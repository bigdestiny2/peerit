# T2 Lane Plan — Browser Writes + Discovery (2026-08-06)

Status: PLAN, grounded in two code recons (relay-side agent-79, client-side agent-80). Claim boundary unchanged until each phase has gate evidence.

## The two halves

A browser comment syncing to another machine requires BOTH:

1. **Write** — the authoring browser gets its signed record into the relay stores (public CELL.PUT).
2. **Discovery** — every other browser learns the new record exists (the 39-cell signed bootstrap is static; nothing enumerates today).

## What the recons established

### Client (peerit) — mostly built
- Identity (Ed25519, non-extractable AES-GCM wrap in IndexedDB), signing, sealing: built, live.
- PoW mint: pure JS + WebCrypto, no WASM/eval (strict-CSP safe). Difficulties post 16 / comment 14 / community 18. App-level, verified by every client on ingest.
- Outbox: journal + flush queue + claim leases + prepare/send split + retry + readback revalidation: built. Currently parked because the signed profile pins `networkPuts: 0` / `ordinaryDelivery: local-only`.
- Relay adapter already composes Cell replicas + PUT bytes; `createAdmissionProvider` injection seam exists, unused.
- Net-new: signed limited Cell-PUT authority profile (+ceremony), browser spend provider, production PUT qualification.

### Relay (hiverelay, live code = `v1-integration/packages/blind-*`)
- Public PUT **transport exists**: edge routes HTTPS CELL.PUT → staged V2 channel (TLS-exporter bound). Gated by topology + daemon readiness, not by missing code.
- PUT admission is `REQUIRED` — no free-write concept in the protocol. No production admission scheme adapter exists (`resolveAdmissionAdapter` is deployer-injected; the live "admission-v5" adapter is deploy-side, not in any checkout). No public issuer (`issuanceUrl`) exists.
- **INBOX READ is cursor enumeration, admission-OPTIONAL (uncharged)**, ≤64 frames/page; WATCH is 30s long-poll. Vendored browser client already ships `createReadInboxRequest`/`createWatchInboxRequest`. INBOX CREATE/APPEND need admission. INBOX runtime self-declares `productionReady:false` blockers — must be reconciled before use.
- CORE is an upstream stub — excluded from this lane.
- Relay has NO PoW concept; admission is token-based only. Peerit PoW stays app-level (client-verified spam friction).

## Decisions (owner, 2026-08-06)

### D1 — Storage/discovery model: **cells for content, INBOX for discovery (hybrid)**
Writers CELL.PUT sealed records (hash-addressed, same pipeline as the seed), then APPEND a small pointer frame (record CID + replica hints) to the per-board INBOX topic. Readers poll INBOX READ from their persisted floor → CELL.GET new records → full client-side verification (signature, PoW, content-id, moderation overlay) → render.
- Why not INBOX-frames-as-content: preserves the verified cell pipeline, hash-addressed caching, lease model, and the existing ingest verifier; INBOX carries only tiny pointers.
- CORE replication stays out of scope.

### D2 — Admission shape: **PoW-issued one-use tokens ("pow-issuance-v1")**
Permissionless writes without host keys:
1. Issuer (small public service per relay, operator-run) hands a fresh random challenge.
2. Browser mints PoW over `challenge ‖ recordCommitment` at write difficulty (reuses the existing pure-JS minter; challenge-bound so record PoW can't be replayed).
3. Issuer verifies, returns a one-use HMAC-signed token.
4. Daemon admission adapter verifies the token locally and enforces one-use (spend marker bound to requestCommitment — already enforced generically).
- Why not full oblivious blind credits (spec `open-admission-v1`): the right end-state, but the entire credential scheme is net-new crypto; PoW-issuance gets permissionless writes live with a fraction of the surface and upgrades cleanly later (same adapter contract, swap token crypto).
- Honesty note: issuer and relay are operator-run; unlinkability is operator-trust at v1, same boundary as the relays today. Disclosed in the decision record.
- Peerit's in-record PoW stays as the second, client-verified spam gate (comment 14 / post 16).

### D3 — Sequencing: relay-side first (long pole), client phases build against local fixtures in parallel
- **T2-A (relay, hiverelay v1-integration)**: admission adapter + issuer service + OPEN profile in descriptors + edge topology with CELL.PUT + INBOX APPEND bits + reconcile stale readiness flags + INBOX production blockers. Drills: good-token PUT, double-spend rejected, bad-PoW rejected, INBOX append/read.
- **T2-B (peerit write)**: browser spend provider (challenge→PoW→token via `createAdmissionProvider`), limited Cell-PUT authority profile + ceremony (GET profile as template), outbox flush wired to PUT-qualified adapters, INBOX.APPEND pointer after receipt. Gate: stock browser posts a record both relays receipt.
- **T2-C (peerit discovery)**: INBOX READ composition from persisted floor → CELL.GET + ingest verification → feed render; optional WATCH for live updates. Gate: fresh reader (no new bootstrap) sees a comment written from a second browser, on both relays.
- **T2-D (hardening)**: abuse policy + quotas + monitoring + decision records + claim-boundary update. Browser-smoke first-comment flake gets fixed here for real (it gates B/C).

Local fixture path exists (`scripts/local-blind-browser-standup.mjs`) so B/C need not wait for A's fleet deploy; live drills follow on syd-1 then dal-1.

## Interactions
- Seq-26 (UX copy) and seq-27 (re-seed) land first; T2 builds on feature branches off the merged result. No ceremony collision: each T2 phase gets its own decision record + release sequence when it ships.
- The peerit INBOX usage means relays must advertise INBOX families in descriptors with the append admission tuple — rides in T2-A descriptor/edge work.
- GA gate unchanged (22 blockers disclosed-open); T2 clears none of them by itself — each phase's claim boundary is recorded in its decision.
