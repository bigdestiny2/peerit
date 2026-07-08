# Handover spec — build `OutboxLog`, a first-class blind append-log service on HiveRelay

**To:** the HiveRelay agent · **From:** the peerit side · **Date:** 2026-07-01
**Companion design doc:** `02-apps/peerit/docs/HIVERELAY-OUTBOXLOG-PLAN.md` (read it first for the full rationale + threat model). This spec is the executable brief.

> ⚠ **The hiverelay repo is mid-heavy-refactor** (many uncommitted core files on `main`). Land the ADDITIVE work (`packages/services/builtin/outboxlog/`, tests) freely, but **coordinate before editing the churning mount files** (`relay-node/api.js`, `plugin-loader.js`, `core/index.js`). Rebase the mount wiring onto the settled refactor.

---

## 1. Mission

Generalize peerit-relay's proven `core-memory` engine into **`OutboxLog`** — an app-agnostic HiveRelay `ServiceProvider` that serves the mutable **single-writer-per-pubkey append log + live gossip** data plane that browser P2P apps need, so any app (peerit is consumer #1) gets a scalable, censorship-resistant, blind relay **without running its own bespoke relay**.

**Product framing (decided):** peerit is a **public** forum — public content is plaintext-to-the-relay by necessity; the liability posture rests on **decentralization + pseudonymity**, not content-blindness. Blind mode (client-side encrypt-before-append) is a later phase, scoped to **private namespaces only**.

---

## 2. Acceptance criteria (definition of done for Phase 2)

1. **Wire-conformance gate is green.** Port `runWireConformance(sync)` from
   `02-apps/peerit-relay/test/wire-conformance.mjs` (26 golden assertions) into a
   hiverelay test and run it against `OutboxLog`'s `sync` surface. It must pass
   **byte-for-byte** — that function is the contract, not prose.
2. **The single-writer verification delta is enforced** (the whole reason this
   isn't a copy — see §5). Add tests: a record not signed by the outbox's writer
   key (`appId`) is rejected; a correctly-signed one is accepted; an opaque body is
   never inspected.
3. **An UNMODIFIED peerit web build converges through it.** Point a peerit web
   build's relay at a HiveRelay node running `outboxlog`; create a community, post,
   vote, comment, reload — all work. (peerit's client emits exactly the `/api/sync/*`
   + SSE calls this service answers.)

**Evidence update — 2026-07-01:** `npm run proof:hiverelay-outboxlog -- --out reports/hiverelay-outboxlog-convergence-2026-07-01.json` now exercises the generated Peerit `web/js` modules against a local HiveRelay `RelayAPI` running the real `OutboxLogApp`. The report passed 13 checks covering bridge readiness, two distinct writer keys, community/post/vote/comment/edit convergence, and reload recovery.

**Evidence update — 2026-07-02:** `npm run proof:app-membership` now covers the first app-layer private/group policy proof. It runs Peerit's signed gossip merge path with the existing PoW validator plus an app-owned membership map, admits member-signed closed-group content, rejects outsider-signed closed-group post/comment rows even with valid signatures and PoW, and leaves public outsider records valid. This confirms group membership belongs in Peerit/app policy, not inside `OutboxLog`.

---

## 3. The engine to port (the reference implementation)

`02-apps/peerit-relay/lib/core-memory.mjs` — the `sync` object is the exact API. Reproduce every method + response shape:

| method | returns | notes |
|---|---|---|
| `create(appId)` | `{appId, inviteKey:<64hex>, writerPublicKey:appId}` | single-writer: writer == appId |
| `join(appId, inviteKey)` | same, or throws 404/400 | **never creates** (read-side griefing can't grow the store) |
| `append(appId, op)` | `{ok:true, key}` | `key = op.type.replace(':','!') + '!' + String(op.data.id)`; bumps per-outbox `version`; validates shape/id-len/size |
| `get(appId, key)` | record body or `null` | |
| `list(appId, prefix, {limit})` | `[{key,value}]` sorted | prefix scan |
| `range(appId, {gt,gte,lt,lte,prefix,reverse,limit})` | `[{key,value}]` | limit clamped **1..1000** |
| `count(appId, prefix?)` | `{count}` | |
| `status(appId)` | `{appId, inviteKey, writerCount, viewLength}` | |
| `heads(appIds[])` | `{heads:{appId:version}}` | batched change-markers; `0` for unknown outbox |
| `directory({limit})` | `{heads:{appId:headRecord}, count}` | every outbox's signed `head!<appId>` record |

Hard bounds to preserve (DoS): `maxValueBytes` 64 KiB (→413), `maxRowsPerGroup`, `maxTotalBytes` (→503), `maxGroups` (→503), `maxAppIdLength` 128, `maxIdLength` 256. **Reads never create a group.**

**The HTTP wire** that maps onto this engine lives in `02-apps/peerit-relay/lib/server.mjs` — mirror those routes + status codes exactly: `POST /api/token`, `POST /api/sync/{create,join,append,heads}`, `GET /api/sync/{get,list,range,count,status}`, `GET /api/sync/directory` (a.k.a. `/api/directory`), `GET /api/swarm/events` (SSE, token via `?token=` since EventSource can't set headers), `GET /api/bridge/status`. CORS allowlist + per-IP rate-limit + SSE-per-IP cap are part of the contract.

---

## 4. HiveRelay integration (reuse — do not reinvent)

- **`ServiceProvider` base** — `packages/core/core/services/provider.js` (manifest/start/stop). `OutboxLogApp extends ServiceProvider`.
- **The mount pattern** — clone the **poker** dynamic-import + 503-when-absent HTTP hook (find the current `isPokerHttpRoute` / `resolvePokerServiceProvider` path in `packages/core/core/relay-node/api.js`; **don't trust old line numbers — the file is being refactored**). Core must never import services directly.
- **`plugin-loader.js` `BUILTIN_MAP`** — add `outboxlog`.
- **Discipline to graft** — `packages/services/builtin/poker/signed-log.js`: per-writer monotonic `seq` (no gaps/rewinds), 60s ts skew, `MAX_ENTRY_BYTES` 64 KiB, canonical Ed25519 over non-signature fields, **opaque payload** ("blind by construction — never inspects payload"), `subscribe(fn)` for live push. **But:** OutboxLog is single-writer-**per-pubkey** (`writer == appId`), not a fixed writer-allowlist table; and it needs KV/range/heads/directory (from core-memory), which poker's flat `getLog(from)` lacks. So: **engine = core-memory, discipline = signed-log.**
- **Durability (Phase 3)** — `packages/services/builtin/poker/persistence-hypercore.js`: one Hypercore per log, seeder/custody pickup, size-pad ladder. Swap the in-memory Map for this.
- **Live gossip** — `router.pubsub` + the poker WS/SSE feed adapter. Add **per-key topics** (`outbox/<appId>`) so one relay connection multiplexes many outboxes (poker's is one-socket-per-table).

---

## 5. The DELTA to add: write-time single-writer verification

`core-memory.append()` does **zero** verification — it stores whatever bytes any token-holder sends to any `appId` (safe there only because peerit's *client* re-verifies at merge; `test/wire-conformance.mjs` demonstrates the gap). As a shared multi-tenant service, OutboxLog **must** verify server-side:

- Reject any append whose record is **not signed by the outbox's writer key** (`appId` == the Ed25519 pubkey that signed it).
- **Verify only the signable envelope fields; never inspect the body** (it may be opaque/ciphertext in blind namespaces). Match peerit's canonicalization + signed-field set exactly — see `02-apps/peerit/js/canon.js` (canonical serialization), `02-apps/peerit/js/verify.js` (`verifyRecord`), `02-apps/peerit/js/model.js` (record types + which fields are signed) so the server check agrees with the client.
- Preserve every read/heads/directory shape from §3 (the conformance gate enforces this).

---

## 6. App-agnostic registration (so it isn't peerit-specific)

Operator-declared, config-driven, no relay fork:
```
config.plugins: ['outboxlog']
outboxlog.namespaces: {
  peerit:      { blind: false, caps: {maxOutboxes, maxEntriesPerOutbox, bytesPerDay} },
  privchat:    { blind: true,  caps: {...} }
}
```
The app supplies **client-side only**: record schema, key derivation (`type!id`), a deterministic merge/winner rule, an optional per-record validator (PoW). The relay owns transport + availability; the app owns meaning. A namespace is keyed by **writer pubkey = appId**.

---

## 7. Known gotchas (from the decentralization audit — fix, don't inherit)

- **`directory()` is O(all outboxes)** and every fresh visitor calls it at boot; its `limit:5000` < `maxGroups:20000` **silently truncates** the rollback-floor/author-discovery — a correctness cliff, not just perf. Make it **paginated/delta** (return heads changed since a client cursor) and bench-gate `directory` p99 + payload vs group count.
- **Snapshot writes plaintext at rest** (`core-memory.snapshot()` serializes `op.data` verbatim). For blind namespaces (Phase 4) add **encryption-at-rest**; for public ones it's the accepted tradeoff.
- **Metadata is not blind even in blind mode** — `op.data.id` is required in the clear and keys are `type!id`; the directory exposes the author roster. Document it; never claim anonymity.

---

## 8. Engineering lenses to apply (the brain)

`00-brain/compiled-vault-brain-2026-06-23/` — apply both:
- **mafintosh / Small Composable P2P Primitives**: smallest primitive, opaque bytes, tiny stable API, explicit teardown/backpressure, README-explainable, lifecycle/failure tests.
- **DMC / Performance-First**: hot paths boring + measurable (ship a **bench gate**: append p50/p99, publish→SSE latency, range rows/s, RSS per 1k outboxes), narrow API, runtime-portable (Node/Bare/Pear), package metadata as architecture, dependency cost.

---

## 9. Phasing + do-not-touch

- **Phase 2 (this handover):** engine port + write-verification + mount + conformance gate green + peerit converges. In-memory backend is fine.
- **Phase 3:** `HypercorePersistence` + per-key pubsub gossip + bench gate.
- **Phase 4:** blind mode (client encrypt-before-append for private ns) + at-rest encryption.
- **Phase 5:** a second app registers a namespace.
- **Do NOT touch:** `custody-signing.js` (a separate storage-custody signed-log — imitate its allow-list discipline, don't extend it); the Core→services boundary (Core never imports services); the seeder/federation pipeline (adopts cores automatically).

---

## 10. Reference files (absolute)

- Gate: `/Users/localllm/Projects/pear-ecosystem/02-apps/peerit-relay/test/wire-conformance.mjs` (`runWireConformance`)
- Engine: `/Users/localllm/Projects/pear-ecosystem/02-apps/peerit-relay/lib/core-memory.mjs`
- Wire/HTTP: `/Users/localllm/Projects/pear-ecosystem/02-apps/peerit-relay/lib/server.mjs`
- Client canon/verify/model: `…/02-apps/peerit/js/canon.js`, `…/js/verify.js`, `…/js/model.js`, `…/js/pear-api.js`
- HiveRelay reuse: `…/00-core/hiverelay/packages/core/core/services/provider.js`, `…/relay-node/api.js` (locate the current poker mount), `…/core/plugin-loader.js`, `…/packages/services/builtin/poker/{signed-log.js,persistence-hypercore.js,http-adapter.js}`
- Plan + threat model: `/Users/localllm/Projects/pear-ecosystem/02-apps/peerit/docs/HIVERELAY-OUTBOXLOG-PLAN.md`
