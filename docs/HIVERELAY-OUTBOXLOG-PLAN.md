# OutboxLog — a first-class blind append-log + live-gossip service on HiveRelay

**For:** peerit owner · **Date:** 2026-07-01 · **Lenses:** mafintosh (small composable primitives) + DMC (performance-first, runtime-portable) + the brain's P2P audit framework (threat modeling, blindness, relay-backed availability, crypto guarantees).

Goal: if the *mutable append-log + live-gossip* pattern becomes the default shape for P2P web apps, HiveRelay should provide it as a first-class, blind, decentralized **service** — so peerit (and any app) is **scalable, censorship-resistant, and bears minimal operator liability by design** — instead of every app running a bespoke relay.

The good news up front: **this is a bounded extension, not a ground-up HiveRelay redesign.** It generalizes an already-proven HiveRelay pattern (the poker `SignedLog`) and peerit's browser already speaks the exact wire, so an *unmodified* peerit build can converge through a native HiveRelay running the service.

**Status update — 2026-07-01:** the local Phase 2 convergence proof is now executable as `npm run proof:hiverelay-outboxlog -- --out reports/hiverelay-outboxlog-convergence-2026-07-01.json`. It runs the generated Peerit `web/js` modules against a sibling HiveRelay `RelayAPI` with the real `OutboxLogApp` and verifies create/post/vote/comment/edit/reload convergence. This closes the local in-memory Phase 2 proof; Phase 3 durability, per-key gossip, and bench gates remain separate.

**Status update — 2026-07-02:** the app-layer group-membership boundary is now executable as `npm run proof:app-membership`. The proof uses Peerit's merge validator hook to compose PoW with an app-owned closed-group membership map; valid member private records are admitted, valid outsider private post/comment records are rejected, and public outsider records still work. No HiveRelay change is required for membership policy.

**Status update — 2026-07-02:** the signed relay roster drift gate is now green as `npm run proof:relay-roster -- --out .deploy/relay-roster-evidence-2026-07-02.json --json`. The current roster covers both configured relays (`https://153-75-89-206.sslip.io` and `https://peerit-relay.onrender.com`) and verifies with the pinned roster key. The entry-point blocking caveat still applies: multi-relay improves relay seizure/rollback resistance, not bundle-origin blocking.

---

## 1. Recommended architecture — `OutboxLog`

An app-agnostic HiveRelay `ServiceProvider` that generalizes the poker `SignedLog` from a fixed-writer-allowlist table into a **single-writer-per-pubkey outbox**, serving the exact `/api/sync/*` + SSE contract peerit's browser already speaks, with **one blind store behind two front-ends**.

**Resolved: HTTP+SSE is primary; WS-DHT is an upgrade layered on top — not the reverse.** The HTTP path is real and browser-proven today; the WS-DHT path is currently a fail-closed stub (`js/dht-bundle.js` throws; the real `js/dht-transport.js` is not in `publish.mjs` SITE_FILES). So ship HTTP+SSE first for reachability on locked-down networks; add WS-DHT for peer diversity once it's actually built + CI-tested.

```
                     BROWSER (peerit / p2pbuilders / pear-exchange)
         encrypt-before-append (private ns) · client re-verify · merge/PoW
            │  fetch /api/sync/*        │  EventSource /api/swarm/events
            │  (CRUD, primary)          │  (live gossip, primary)
   ┌────────┴───────────────────────────┴─────────┐   ┌──── WS-DHT (Phase 4+, upgrade)
   ▼                                               ▼   ▼
 ┌──────────────────────── HiveRelay node ───────────────────────┐
 │  http-adapter (/api/sync/*)     feed-adapter (SSE + WS)        │
 │        ▼                             ▼  per-key pubsub topics  │
 │   OutboxLogApp ── extends ServiceProvider ── app-registry (ns) │
 │        ▼  append/get/list/range/count/heads/directory         │
 │   OutboxLog (writer=appId, +1 seq, 60s skew, 64KiB,           │
 │             Ed25519 verify, OPAQUE payload bytes)             │
 │        ▼  one Hypercore per outbox ─→ existing seeder/custody │
 └───────────────────────────────────────────────────────────────┘
    signed multi-relay roster (pinned Ed25519) ← relay untrusted; client reconciles across pool
```

**Grafts (which idea, which lens):**
- **mafintosh:** store treats keys/values as opaque bytes, adds nothing to transport; one Hypercore per outbox reusing the existing seeder/custody/federation pipeline. Smallest composable primitive.
- **DMC:** one long-lived SSE/WS connection *per relay* (not per outbox) multiplexing per-key pubsub topics; a fixed bench gate (append p50/p99, publish→SSE latency, range rows/s, RSS per 1k outboxes) so scale is measured, not asserted.
- **service-architect:** an app-registry (`namespace → {caps, quotas, blind}`) so peerit is *consumer #1*, not a special case.
- **adversary/zero-liability:** encrypt-before-append for private namespaces + a signable-field allow-list rejecting any op carrying `dataKey`/`plaintext` + the honest reframe below.

---

## 2. How it meets the three goals

### Scalable
- One Hypercore per `(namespace, appId)`; the existing seeder/custody/federation pipeline treats each core independently → a new app adds **zero central index**, a new author adds one small core. Append is O(1). Reads never allocate. Bounded by caps that already exist (`maxValueBytes` 64KiB, `maxRowsPerGroup`, `maxTotalBytes`, `maxGroups`).
- Live gossip fan-out is per-relay (one SSE/WS stream multiplexing per-key topics), not per-outbox.
- **Correction (critique):** `directory()` and `heads()` are currently **O(all outboxes)** and on the browser boot hot path (`_bootstrapFloor → directory`), and `directory`'s `limit: 5000` < `maxGroups: 20000` silently truncates the rollback floor at scale — a *correctness* cliff, not just perf. Must make `directory` paginated/delta and bench-gate it before claiming O(bytes-written) scaling.

### Censorship-resistant
- The mechanism **already exists and is correct** — `js/relay-roster.js` verifies an untrusted roster against a **pinned Ed25519 key** (removes DNS/TLS/BGP/rogue-host from trust), and `js/relay-pool.js` does cross-relay highest-**verified**-head reconciliation (defeats rollback + strip). As of the 2026-07-02 roster proof, the current signed roster carries the owner VPS plus Render; keep the proof gate green whenever the fleet changes.
- **Honest chokepoint the plan must name (critique):** the pinned key removes the *trust* chokepoint, not the *availability* one — the roster URL and the static JS bundle are still single-origin. Block that origin and the pool is unreachable regardless of how many relays it lists. Mitigation: **inline the signed roster + pin into `index.html` at build time** (a cached/pinned bundle needs zero network to know its relays) + a bundle-distribution story (IPFS/mirrors/extension). Multi-relay resists *relay seizure*, not *entry-point blocking* — ship that limit in the threat-model doc.

### Operator liability — reframed honestly to **"content-blind," not "zero-liability"**
This is the most important correction the stress tests forced, and it's a **product decision you must make**:
- **A public forum cannot be operator-blind.** Public communities must broadcast the read key so anyone can read — which hands it to the operator too. So **blind mode protects PRIVATE/access-controlled groups only; public peerit content is pseudonymous-plaintext-to-the-relay by necessity.** You cannot market "the operator can't read your posts" for public communities.
- **Even blind, the relay is a social-graph oracle.** `op.data.id` is required in cleartext, keys are `type!id`, and `/api/directory` exposes the author roster — so record type, per-record ids, per-author outbox membership, and the activity graph leak regardless of body encryption. For many threat models the *metadata is the liability*.
- **The correct claim:** *"no plaintext-content liability for private namespaces; residual metadata/association liability remains."* The mechanism (private namespaces): the browser seals each body with a 32-byte `dataKey` (XChaCha20-Poly1305) **before** append; only `{v, alg, nonce, ct, sig, keybinding}` travels; the relay stores opaque bytes (exactly as `SignedLog` treats `payload` — "card-blind by construction"); a signable-field allow-list rejects any append carrying `dataKey`/`plaintext`; `/api/identity` stays 410; blind-namespace directory exposes only commitments. Also add **encryption-at-rest** — today the memory core's `snapshot()` writes `op.data` verbatim to disk, so a seized disk has plaintext for non-blind namespaces.

---

## 3. App-agnostic registration — how ANY app uses it

`OutboxLog` is the generic form of `SignedLog` (the poker file itself flags the lift). The one generalization: a namespace keyed by **writer pubkey = appId** (single-writer) with the app's `type!id` as opaque keys.

Operator declares (config, no relay fork):
```
config.plugins: ['outboxlog']
outboxlog.namespaces: {
  peerit:      { blind: false, caps: {...} },
  privchat:    { blind: true,  caps: {...} },
  p2pbuilders: { blind: false, caps: {...} }
}
```
The app supplies **client-side only**: record schema, key derivation (`type!id`), a deterministic merge/winner rule, and an optional per-record validator (PoW). The relay owns transport + availability; the app owns meaning.

The stable API is **byte-identical to what `js/pear-api.js` already emits**: `create`, `join`, `append`, `get`/`list`/`range`/`count`, `heads`, `directory`, `events` (SSE). **Correction (critique):** that wire-compat claim is the linchpin and must be backed by a **golden-transcript conformance test** (record peerit-relay responses, replay against OutboxLog) as the Phase 2 gate — not asserted. And the per-app merge/schema/PoW logic is a real **client SDK deliverable**, not "a config line."

---

## 4. Net-new work vs what already exists

**Reuse near-verbatim:** `ServiceProvider`/`PluginLoader`/`ServiceRegistry`; the dynamic-import + 503-when-absent HTTP mount (`api.js:694-697`, clone the poker hook); `SignedLog` discipline (+1 seq / 60s skew / 64KiB / canonical Ed25519 / opaque payload); `HypercorePersistence` (one core/log + seeder pickup + size-pad); `router.pubsub` + WS feed; the `dht-relay-ws` transport; the client-side signed roster + cross-relay head.

**Net-new deltas:**
1. `outboxlog/outbox-log.js` — **port peerit-relay's `core-memory` KV/range/heads/directory engine** into a ServiceProvider (poker's flat `getLog(from)` array is *not* enough — poker contributes verification discipline, core-memory contributes the query engine). Budget ~1–2 wks, not a 3-line fork.
2. **Write-time single-writer Ed25519 verification** — `core-memory.append()` does **zero** signature/writer checks today (stores any bytes any token-holder POSTs to any appId). Net-new server-side, kept compatible with opaque payload (verify envelope fields, never the ciphertext).
3. `http-adapter.js` (prefix-dispatch `/api/sync/*`), `feed-adapter.js` (SSE + WS, per-key topics + heads/directory — poker lacks these), `app-registry.js` (the one genuinely new concept), blind guard + encrypt-before-append, and ~6 lines wiring (`BUILTIN_MAP.outboxlog` + poker-style mount).

**Not touched:** `custody-signing.js` (separate; imitate its allow-list discipline, don't extend), the Core→services boundary, the seeder/federation pipeline (adopts cores automatically).

---

## 5. Phased roadmap — smallest first step first

> Verification gate: `test/gossip.mjs`/`test/smoke.mjs` run against in-memory fakes (client merge logic, never the wire). The real gate is the relay wire suite (`peerit-relay/test/`). Gate every phase on the wire suite.

| Phase | Build | Repo | Effort | Unlocks |
|---|---|---|---|---|
| **1. Close cold-start censorship gap** | Deploy peerit-relay to the **owner's VPS as PRIMARY**; add Render as #2; put both in the signed roster; wire the roster into the publish/deploy path + inline a bundled roster fallback into `index.html`; add health-gated primary reselection. | peerit | ~1–2 days | Roster of two independent origins → cross-relay rollback/strip defenses go live; single-host chokepoint removed. **See critique #1 — not quite "no code."** |
| **2. Port `core-memory` → `OutboxLogApp`** | Lift the KV/range/heads/directory engine into `packages/services/builtin/outboxlog/`; clone the poker mount; add write-time single-writer verification. Gate on a **golden wire-conformance test**. | hiverelay | ~1–2 wks | Native HiveRelay serves peerit's wire; an unmodified peerit build converges through it. Peerit = consumer #1. |
| **3. Durability + per-key live gossip** | Swap backend Map→`HypercorePersistence` (one core/outbox, seeder pickup, size-pad); add per-key `router.pubsub` topics + SSE `from=N` replay. Ship the DMC bench gate. | hiverelay | ~1 wk | Durable, size-blinded, federated storage via the existing pipeline; live *updates* become 1-connection. |
| **4. Blind mode + WS-DHT upgrade** | Client XChaCha20 encrypt-before-append + key-binding; relay signable-field allow-list + blind-ns 403 gateway + commitments-only directory + **snapshot encryption-at-rest**. Build the real `dht-transport` bundle (replace the throwing stub), CI-test, add to SITE_FILES. Ship the honest threat-model doc. | both | ~2–3 wks | Content-blind private groups; WS-DHT peer diversity. |
| **5. Second consumer proves app-agnostic** | p2pbuilders / pear-exchange register their own namespace + client SDK (schema/merge/PoW). Optionally re-express poker as an `OutboxLog` namespace. | both | ~1 wk/app | Proves the primitive is app-agnostic; HiveRelay ships `outboxlog` as a first-class builtin. |

---

## 6. Open decisions the owner must make

1. **Blind vs public forum is a genuine contradiction — choose peerit's product identity.** Public content can't be operator-blind. Either accept peerit is pseudonymous-plaintext for public content and reserve blind mode for private groups/DMs (honest, shippable), or pivot private-group-first. Decide before any blindness marketing.
2. **Even blind, the relay is a metadata/social-graph oracle** (ids, keys, author roster in cleartext). Truly hiding who-did-what needs encrypting keys, which destroys the range-query feed model — a ground-up key-scheme redesign. Disclose and live with it, or fund the redesign.
3. **The relay verifies nothing on write today** (forged-bytes DoS bounded only by caps). Phase 2 fixes it; accept status-quo until then or prioritize.
4. **Censorship resistance is "detectable and expensive," not impossible** — the roster URL + JS bundle are single-origin. Inline the roster + distribute the bundle; never claim impunity.
5. **WS-DHT is real work, not a flag** — the shipped bundle throws by design; the dep is do-not-use-in-production; the `random-access-web` truncate gap is unresolved. Fund Phase 4 properly or stand honestly on HTTP+SSE + multi-relay diversity.
6. **Durability = signed quorum receipt, not "a relay says it has it."** `fanoutAppend` is fire-and-forget to non-primary relays (`.catch(()=>{})`), so cross-relay durability is best-effort-async, not acknowledged. MVP = best-effort seeding (honest), or fund custody receipts.

---

## Bottom line

The transport + storage substrate is largely already built; the generalization to `OutboxLog` is a **bounded, low-risk port** of peerit-relay's `core-memory` engine into a HiveRelay ServiceProvider using the proven poker mount. The three headline properties are *achievable* but not *shipped* — and **blindness is fundamentally scoped to private content**. Start with **Phase 1** (VPS as primary + a real 2-relay roster wired into deploy), which converts the biggest overclaim — "censorship-resistant" — into deployed reality before writing a line of HiveRelay code.
