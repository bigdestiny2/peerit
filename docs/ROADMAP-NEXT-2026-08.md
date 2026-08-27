# Roadmap — post-cutover: self-hosted serving + the unsolved list

> **Status: Historical roadmap snapshot (Sequence 20 era).** Retained for its
> problem statements and decision history; unchecked items are not the current
> roadmap and checked prose is not a Sequence 29 release claim. See
> [`CURRENT-STATUS.md`](./CURRENT-STATUS.md) for the present boundary.

**Status:** drafted 2026-07-31, after the vNext cutover went live (peerit.site on the seq-20 bundle, 34 seed records on both blind relays, Chromium gate PASS ×3).
**Claim boundary:** LIVE_PUBLIC_TEST_ONLY — two owner-operated relays, GA gate closed (22 blockers disclosed-open).

This roadmap has three tracks: (1) owning the serving layer, (2) the genuinely-unsolved scale + client items, (3) launch operations. Each item has an owner lane and a done-criterion. Nothing here contradicts the evidence ledger; deferred items stay labelled deferred until proven.

---

## Track 1 — Own the serving layer (Render → our server → mirrors)

**Why:** one less external dependency; deploys, headers, logs, cadence are ours. The bundle is signed and static, so serving is a commodity — but the entry point is the honest-acknowledged chokepoint, and owning it is step one.

### 1.1 Provision + static origin (P0, this week)
- [ ] Provision a small third VPS (do **not** co-locate on relay boxes — blind edge owns 443 there, and site+relay must not share a failure domain). Owner: fleet lane.
- [ ] Caddy or nginx with automatic Let's Encrypt TLS for `peerit.site`.
- [ ] Serve `web/` with the **exact** header policy from `deploy/render-security-headers.json` (CSP is load-bearing — byte-match required).
- **Done when:** site serves over TLS with `asset-manifest.json` == `a0978b9f…`, bootstrap == `0a386975…`, CSP header match, and `scripts/verify-live-readonly.mjs` passes against it.

### 1.2 Deploy pipeline (P0)
- [ ] On-box cron: `git pull` on `main` → `node scripts/web-release.mjs --verify-only --strict --canary-limited-public-test-v1` (the identical command Render runs today) → rsync `web/` to webroot. Fail-closed: a failed verify keeps the previous deploy.
- **Done when:** a merge to main is live on our origin within ~5 min with zero manual steps, proven by a test merge.

### 1.3 DNS cut + parity window (P0)
- [ ] Repoint `peerit.site` A record to the new box (owner action, TTL lowered ahead).
- [ ] Keep Render as fallback for one deploy cycle; verify parity on every deploy (live-bytes check + CSP diff).
- **Done when:** DNS resolves to our origin, full verify passes, and one real deploy cycles through both hosts cleanly before Render is retired.

### 1.4 Mirrors — kill the chokepoint properly (P1)
- [ ] Second static mirror on a separate box (failover or round-robin), same signed bytes.
- [ ] Restore `hyper://` drive delivery for the bundle (peerit's original canonical form) + IPFS pinning per `docs/WEB-DEPLOYMENT.md` censorship-resistance design.
- **Done when:** the bundle is fetchable+verifiable from ≥3 independent origins and the client treats any of them as equivalent (signature/hash verification is what makes mirrors trustless).

---

## Track 2 — The genuinely unsolved list (scale + client)

These are the items named as deferred at cutover. Each stays labelled until it has evidence.

### 2.1 Bootstrap sharding for cold-start at high content volume (P1)
- **Problem:** today's bootstrap names every record (fine at 34; untenable at thousands).
- **Shape:** per-community checkpoint artifacts chained via `prevHash` + incremental sync (head census per outbox) for catch-up. Reader cold-starts on the communities it follows, not the forum.
- **Done when:** a synthetic 1k-post board cold-starts a fresh reader with < N MB of bootstrap+cells and correct feed assembly, measured and evidenced.

### 2.2 INBOX discovery composition (P1)
- **Problem:** the relays and vendored browser client now expose INBOX READ/WATCH constructors, but Peerit does not yet compose them into discovery; cold-start still requires the signed bootstrap. CORE remains an upstream stub and is excluded from this lane.
- **Shape:** keep content in verified cells and use INBOX only for small record pointers. Readers persist an INBOX floor, fetch new pointers with READ (optionally WATCH), resolve them through CELL.GET, and run the existing signature/PoW/content-id/moderation checks. The bootstrap then becomes an optimization, not the only enumeration path.
- **Done when:** a fresh reader with **no** new bootstrap can enumerate and read a board correctly through INBOX → CELL.GET on both relays in the gate environment.

### 2.3 Browser write path (P1–P2)
- **Problem:** posting is native-only today (welcome pin says so); stock-browser readers remain verified GET-only and queue no network writes.
- **Shape:** follow the accepted T2 lane in `docs/T2-BROWSER-WRITES-LANE-PLAN-2026-08-06.md`: browser-side identity + in-browser record PoW, a challenge-bound PoW issuance service that returns one-use admission tokens, CELL.PUT for content, and INBOX.APPEND for discovery pointers. Peerit's existing outbox/claim/retry/readback pipeline stays fail-closed until the limited write authority is signed and qualified.
- **Done when:** a stock browser posts a record that both relays receipt and a fresh second browser discovers and renders — under the same Chromium gate discipline.

### 2.4 Seeder/mirror durability tier (P2, roadmap anchor)
- **Shape:** author-outbox replication as system of record; relays as availability, not the only copy. Lease model becomes an availability detail, not a lifetime dependency.
- **Done when:** killing any one relay (or letting every lease lapse on it) loses no readable content, proven by drill.

### 2.5 Smaller open items (P1–P2)
- [ ] **seq-19 reassessment** — apply the vendor CSP fix to the accepted seq-19 line and close the ledger entry (`disclosed-finding-seq19-browser-recovery-never-browser-proven-20260731.json`).
- [ ] **Push canonical CSP fix** `b177e1f2` to origin (vendor lane) — the WASM-safe blake2b belongs in canonical hiverelay, not just our branch.
- [ ] **Placeholder profile-hash rotation** (DAL1-IAR-P2-1) — rotate descriptor build tuples 0x01/0x02/0x03 to real profile hashes on both relays, then fresh re-probe.
- [ ] **Atomic-ingress** — either productize a minimal outboxlog-ingress entry point (the soak composition as a real service) or record formally that blind CELL is the accepted write path and close the item with evidence.
- [ ] **Storage budget policy** — enforce per-service caps + disk monitoring on all fleet boxes (lesson from the syd 100 %-disk incident; archive `47 G` already at `/root/syd-classic-archive` on dal).

### 2.6 GA gate (P3, boundary)
- [ ] Independent operators (non-owner failure domains).
- [ ] The 22 disclosed GA blockers, worked through the release line.
- **Done when:** the gate itself, not us, says GA.

---

## Track 3 — Launch operations (imminent)

### 3.1 Telegram bounty campaign (P0, this week)
- [ ] Creatives using the existing UTM machinery (`launch/reports/utm-links.*`), leading with the BTC bounty + anti-scam mechanics (hash-committed seed keys, public adjudication).
- [ ] Land traffic on the 9 empty boards; measure with the UTM links.
- **Done when:** first external (non-seed) signed posts visible on any board.

### 3.2 Bounty adjudication machinery (P1, needed by day 14)
- [ ] The distinct-author counting script over signed records (recomputable by anyone — publish it in the adjudication thread).
- [ ] Day-14 adjudication post: scores, method, the five winning pubkeys; 48 h comment window; signed-claim payout flow (BTC); public receipts.
- **Done when:** the counting script runs against live boards and its output is independently recomputable.

### 3.3 Monitoring (P0, continuous)
- [ ] Relay health + `ok_head_fresh` rotation logs on both boxes.
- [ ] Disk usage alerts at 80 % on all fleet boxes.
- [ ] Scheduled checkpoints: bootstrap expiry (cron `e0ff09d2`, Aug 25), renewal (cron `7413ebe8`, Sep 23).
- **Done when:** all four signal classes flow to one reviewed place (run evidence or fleet log) and a missed checkpoint pages the owner.

### 3.4 Explainer collateral (P0, completed in source)
- [x] Add `docs/BROWSER-ZERO-TRUST-PROOF-EXPLAINER.html` and `docs/VNEXT-CUTOVER-REPORT-2026-07-31.html` to the 2026-08-06 documentation sync.
- [ ] Link the report from the in-app About page.

---

## Sequencing (honest)

1. **This week:** 1.1–1.3 (own origin + DNS), 3.1 (Telegram), 3.3 (monitoring), 3.4 (docs commit).
2. **Next 2–4 weeks:** 1.4 (mirrors), 2.1 (bootstrap sharding), 2.2 (INBOX/CORE), 3.2 (bounty machinery), 2.5 (open items).
3. **1–2 months:** 2.3 (browser writes), 2.4 (durability tier).
4. **GA:** whenever the 22 blockers + independent operators are real — gate stays closed until then.

**Standing rule (unchanged from the cutover):** nothing ships that only passes static gates. Browser-affecting work passes a real browser gate; relay-affecting work passes a live two-relay probe; every claim is either evidenced or labelled deferred.
