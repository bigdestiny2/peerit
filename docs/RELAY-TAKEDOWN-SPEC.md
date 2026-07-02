# Relay-Side DO-NOT-SERVE / Takedown-Compliance Layer

**Status:** design, implementation-ready. **Target:** `02-apps/peerit-relay` (the `core-memory` backend + HTTP/SSE surface), consumed by unmodified peerit web clients.
**Companions:** [`OPERATOR-LIABILITY.md`](OPERATOR-LIABILITY.md) (§3.3 "drop-by-opaque-id" — the identifier-keyed takedown concept this doc makes real on the relay) and [`BLINDSHARD-DESIGN.md`](BLINDSHARD-DESIGN.md) (the `blob!<blobId>` content-addressed body surface a suppression can target).

> **Not legal advice.** US framing (DMCA §512) with EU/DSA notes. This is a set of design invariants and a build plan for a *responsive-conduit* mechanism, not a legal opinion.

---

## 0. Motivation — the #1 operator-liability lever

Intermediary safe harbors (DMCA §512(c) storage; EU/DSA hosting) are **conditioned on the ability to respond to a valid takedown notice**. "Expeditiously remove or disable access upon notice" is a *precondition* of the protection, not an optional courtesy. An operator who **cannot** comply is not a protected conduit — they are a host that chose to keep serving after notice.

**Today peerit's relay can HOLD everything but REMOVE nothing.** Concretely:

- The store is **append-only**. `core-memory.mjs` `append()` (lib/core-memory.mjs:119) only ever `g.rows.set(key, op.data)` — there is no relay-side delete, and reads (`get`/`list`/`range`/`count`/`status`/`heads`/`directory`, lib/core-memory.mjs:138–173) return whatever is in `g.rows`.
- The **only** way a record is retracted today is a client-authored **tombstone**: peerit's `deletePost`/`deleteComment` (peerit `js/data.js`) re-sign the record with a `deleted` flag. That write is gated by the record's Ed25519 signature and is authored by the **original author only** — the relay holds no signing key (lib/core-memory.mjs:10–12) and *cannot* author one. `join`/`append` never mint a key; `/api/identity` is a hard `410` (lib/server.mjs:115).

So an operator served a valid notice for a post whose author is unreachable, uncooperative, or anonymous **has no mechanism to comply on their own relay**. That is the gap this spec closes.

This layer makes the relay a **responsive conduit**: it keeps holding the bytes (append-only + signed-head census math untouched, so nothing forks and no client audit breaks in an unexpected way) but **stops serving** a named record or outbox on every read path, and stops re-advertising it to new peers. It is the single highest-leverage liability change available, because it converts "structurally cannot comply" into "can comply on my relay in seconds, without a key, without reading content."

**What it is not:** it is *not* global erasure and does not claim to be (§5, §7). Other relays, seeders, and PearBrowser peers may still carry the content. That is the correct conduit posture — an operator can only be asked to act on **their own** service.

---

## 1. Design overview

A **suppression list** — a persisted set of opaque identifiers — is consulted at **serve time** on every read path. A suppressed identifier's bytes stay on disk (append-only invariant intact; the signed-head census the client audits is computed over stored rows, unchanged) but are **filtered out of every response** and **never replayed** to new swarm joiners. An authenticated, non-public operator control surface adds and removes entries. The list rides the existing disk snapshot so it survives restart.

Two suppression granularities:

1. **Record key** — a single row, e.g.
   - `post!<community>!<cid>`
   - `comment!<community>!<postCid>!<cid>`
   - `blob!<blobId>` (a BlindShard boxed body — suppressing it blanks the body while the post row may remain, see §5)
   Keyed by the **exact storage key** as produced by `append()` (`op.type.replace(':','!') + '!' + id`, lib/core-memory.mjs:127).
2. **Entire outbox appId** — every row in one author's outbox (the appId is the author's writer pubkey; lib/core-memory.mjs:112). Used when a notice targets an account rather than one item.

Both are stored as **opaque strings**. The relay never parses, reads, or interprets the suppressed content — it matches identifiers. This preserves the "cannot read / cannot select by meaning" posture: a takedown operates on identifiers a notice names, exactly the drop-by-opaque-id shape in [`OPERATOR-LIABILITY.md` §3.3](OPERATOR-LIABILITY.md).

---

## 2. Design — data structure

Add to `createMemoryCore` (lib/core-memory.mjs) two in-memory sets, populated at boot and mutated only through the control surface (§5):

```js
const suppressedKeys   = new Set() // exact storage keys: "post!c!cid", "blob!<id>", ...
const suppressedAppIds = new Set() // whole outboxes (author pubkeys)
```

Central predicates (define once, near `getGroup`):

```js
// True if a specific stored row must not be served.
const isKeySuppressed = (appId, key) =>
  suppressedAppIds.has(appId) || suppressedKeys.has(key)

// True if an entire outbox is suppressed (used by heads/directory/status/swarm).
const isAppSuppressed = (appId) => suppressedAppIds.has(appId)
```

Notes:
- **Sets, not arrays** — O(1) membership on the hot read path. `suppressedKeys` can hold tens of thousands of entries without changing read complexity (each read already iterates or map-gets rows; the added check is a single `Set.has`).
- **Bytes are retained.** Nothing in `append()` or the census/`head!` machinery changes. `totalBytes`, `g.rows`, `g.version`, and the `head!<appId>` census record are all computed and stored exactly as today — the record still counts in the signed head, so the client's own producer/auditor math stays symmetric (§6). Suppression is a *serve-time veil*, not a delete.
- **Bounded.** Cap the sets (e.g. `maxSuppressedKeys = 100000`, `maxSuppressedAppIds = 20000`) and reject additions past the cap with a `503`, mirroring the existing capacity guards in `ensureGroup`/`append` (lib/core-memory.mjs:87, 130–131).

---

## 3. Design — exact serve-path filter points (with file refs)

Every path that returns record bytes or advertises an outbox gets the filter. Named precisely so an engineer edits exactly these functions.

### 3.1 `core.sync.get` — lib/core-memory.mjs:138
Single-key fetch. Return `null` for a suppressed key (identical to a genuinely absent row, which `get` already returns as `null`):
```js
get (appId, key) {
  if (isKeySuppressed(appId, key)) return null
  const g = getGroup(appId); return g ? (g.rows.get(key) ?? null) : null
}
```

### 3.2 `rangeRows` — lib/core-memory.mjs:96 (backs `list` **and** `range`)
Both `list` (lib/core-memory.mjs:139) and `range` (lib/core-memory.mjs:140) funnel through `rangeRows`. Filter **inside** `rangeRows`, after the key-range/prefix filters and **before** `limit` slicing, so a suppressed row does not consume a limit slot (otherwise suppression would silently shrink page sizes and clients would over-page). This requires `rangeRows` to know the `appId`; pass it in:

```js
function rangeRows (appId, g, opts = {}) {
  let rows = sortedRows(g)
  // ...existing prefix / gt / gte / lt / lte / reverse filters unchanged...
  if (suppressedAppIds.has(appId)) rows = []
  else if (suppressedKeys.size) rows = rows.filter((r) => !suppressedKeys.has(r.key))
  // ...existing limit clamp + slice unchanged...
}
```
Update the two call sites:
```js
list (appId, prefix, opts = {}) { return rangeRows(appId, getGroup(appId) || EMPTY, { prefix, limit: opts.limit }) },
range (appId, opts = {}) { return rangeRows(appId, getGroup(appId) || EMPTY, opts) },
```

### 3.3 `core.sync.count` — lib/core-memory.mjs:141
`count` must not leak the existence of suppressed rows via an inflated tally. Subtract suppressed matches (or return 0 for a suppressed appId):
```js
count (appId, prefix) {
  if (isAppSuppressed(appId)) return { count: 0 }
  const g = getGroup(appId); if (!g) return { count: 0 }
  let n = 0
  for (const k of g.rows.keys()) {
    if (suppressedKeys.has(k)) continue
    if (!prefix || (k >= prefix && k < prefix + '\xff')) n++
  }
  return { count: n }
}
```

### 3.4 `core.sync.status` — lib/core-memory.mjs:149
`status` reports `viewLength` (= `g.rows.size`) and the `inviteKey`. For a suppressed appId, report it as empty so the outbox is not discoverable/joinable via status:
```js
status (appId) {
  if (isAppSuppressed(appId)) return { appId, inviteKey: null, writerCount: 0, viewLength: 0 }
  const g = getGroup(appId); return g ? { appId, inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size } : { appId, inviteKey: null, writerCount: 0, viewLength: 0 }
}
```
(Per-key suppression does **not** alter `viewLength` here — that count is the raw stored size and is used only for status display; the load-bearing count is the signed `head.count` the client audits, which stays symmetric per §6. Zeroing only whole-appId status is sufficient and avoids an O(rows) scan on a status ping.)

### 3.5 `core.sync.heads` — lib/core-memory.mjs:153
`heads` returns per-outbox `version` change-markers for batch polling. For a suppressed appId, report version `0` (== "no such outbox / no changes"), so a client polling heads is never told to re-read a suppressed outbox:
```js
heads (appIds) {
  const out = {}
  if (Array.isArray(appIds)) for (const a of appIds) {
    if (typeof a !== 'string' || a.length > maxAppIdLength) continue
    if (isAppSuppressed(a)) { out[a] = 0; continue }
    const g = getGroup(a); out[a] = g ? g.version : 0
  }
  return { heads: out }
}
```
(Per-key suppression is not reflected in `heads` — `heads` is outbox-granular by design; a client that re-reads the outbox on a version bump simply won't receive the suppressed row from `range`/`get` per §3.2/§3.1.)

### 3.6 `core.sync.directory` — lib/core-memory.mjs:164
The durable directory hands a fresh visitor the signed `head!<appId>` of every outbox for rollback-floor + author bootstrap (peerit `js/gossip.js` `_bootstrapFloor`). A suppressed **appId** must not appear (or the outbox is re-discovered and its floor re-seeded, re-pulling it):
```js
directory ({ limit = 5000 } = {}) {
  const heads = {}; let n = 0
  for (const [appId, g] of groups) {
    if (n >= limit) break
    if (isAppSuppressed(appId)) continue
    const h = g.rows.get('head!' + appId)
    if (h && !suppressedKeys.has('head!' + appId)) { heads[appId] = h; n++ }
  }
  return { heads, count: n }
}
```
(Also skip a directly-suppressed `head!<appId>` key, though suppressing a whole account normally targets the appId form.)

### 3.7 Swarm replay + descriptor memory — lib/swarm-hub.mjs
The swarm hub re-advertises stored signed descriptors to every new joiner (`replay`, lib/swarm-hub.mjs:43), which is how a visitor discovers an outbox whose author is offline. A suppressed outbox must **not** be replayed, or suppression is defeated at the discovery layer.

The hub keys descriptors by opaque `data` string per topic (lib/swarm-hub.mjs:21, 30). It does not today parse the appId out of a descriptor. Two implementable options — the spec mandates **(a)**, with **(b)** as an optimization:

**(a) Suppress-aware replay via an injected predicate (mandated).** `createSwarmHub` already takes an options bag (lib/swarm-hub.mjs:19) and an `onChange` callback wired from the core. Add an injected `isDescriptorSuppressed(data)` callback and consult it in **both** `replay` (before emitting each cached descriptor, lib/swarm-hub.mjs:48–52) and `remember` (to avoid caching a newly-arriving descriptor for an already-suppressed target, lib/swarm-hub.mjs:30–38):
```js
// core-memory.mjs, where the hub is created (lib/core-memory.mjs:35):
const swarm = createSwarmHub({
  onChange: () => { dirty = true },
  isDescriptorSuppressed: (data) => {
    if (!suppressedAppIds.size && !suppressedKeys.size) return false
    try {
      // peerit outbox descriptors carry the author appId (writer pubkey).
      const d = JSON.parse(data)
      const appId = d.appId || d.writerPublicKey || d.author
      return appId ? isAppSuppressed(appId) : false
    } catch { return false }
  }
})
```
```js
// swarm-hub.mjs replay (lib/swarm-hub.mjs:48):
for (const data of m.keys()) {
  if (isDescriptorSuppressed && isDescriptorSuppressed(data)) continue
  const pid = 'cache-' + (++synth)
  deliver(channelId, { type: 'peer', peerId: pid, pubkey: null })
  deliver(channelId, { type: 'message', peerId: pid, data })
}
```
Descriptor shape is verified against what peerit publishes on the swarm before shipping (grep the client's descriptor/announce payload). If a descriptor does not carry an appId in a parseable field, fall back to per-appId suppression having no descriptor effect and rely on the read-path filters (§3.1–§3.6) — discovery may still surface the outbox, but every data read returns nothing, so the visible result is an empty outbox. Document that residual.

**(b) Purge-on-suppress (optimization).** When an appId is suppressed via the control surface, also drop its cached descriptors from `descriptors` immediately (a `swarm._forgetDescriptorsFor(pred)` helper mirroring `_loadDescriptors`), so already-cached entries stop replaying without a per-replay parse. Combine with (a) to also block *future* descriptors.

### 3.8 Not a filter point
`create`, `join`, `append` (lib/core-memory.mjs:112–137) are **writes** and are intentionally left unfiltered: the append-only + census invariant must hold (a suppressed post that the author later edits still lands on disk and still counts in the head census, keeping the client audit symmetric per §6). Suppression is serve-time only. `/api/token` (lib/server.mjs:107) is unaffected.

---

## 4. Design — persistence (survives restart)

Fold the two sets into the existing snapshot, reusing the **exact same discipline** already in `core-memory.mjs`: `dirty` flag → debounced `setInterval(flush, intervalMs)` (lib/core-memory.mjs:78) → atomic `writeFileSync(tmp)` + `renameSync` (lib/core-memory.mjs:72–76) → SIGTERM/SIGINT `core.flush()` on shutdown (relay.mjs:54).

- **`snapshot()`** (lib/core-memory.mjs:67): add the sets to the serialized object.
  ```js
  return JSON.stringify({
    v: 1, totalBytes, groups: out,
    descriptors: swarm._snapshotDescriptors(),
    suppressedKeys: [...suppressedKeys],
    suppressedAppIds: [...suppressedAppIds]
  })
  ```
- **`loadSnapshot()`** (lib/core-memory.mjs:41): after loading groups/descriptors, rehydrate the sets defensively (string-only, length-bounded, cap-bounded — same defensive style as descriptor load, lib/swarm-hub.mjs:104–108):
  ```js
  if (Array.isArray(snap.suppressedKeys))
    for (const k of snap.suppressedKeys) if (typeof k === 'string' && k.length <= 512 && suppressedKeys.size < maxSuppressedKeys) suppressedKeys.add(k)
  if (Array.isArray(snap.suppressedAppIds))
    for (const a of snap.suppressedAppIds) if (typeof a === 'string' && a.length <= maxAppIdLength && suppressedAppIds.size < maxSuppressedAppIds) suppressedAppIds.add(a)
  ```
- **Mutation sets `dirty = true`** (via the control surface, §5) so the change is snapshotted on the next debounce tick and on SIGTERM — identical to how `append()` schedules a snapshot (lib/core-memory.mjs:135).
- **Corrupt/absent snapshot** is already handled (start empty, never crash — lib/core-memory.mjs:44, 65); the new fields inherit that behavior for free.
- **Persistence off** (`persist: null`, the default) → suppression is in-memory only and resets on restart, exactly like the store itself. Document that a compliance-serious deployment MUST set `PEERIT_RELAY_PERSIST` (relay.mjs:47) — otherwise a takedown does not survive a redeploy.

Expose mutators on the core so the server layer can call them without reaching into internals:
```js
return {
  sync: { /* ...unchanged... */ },
  swarm,
  flush,
  suppress: {
    addKey (key)     { if (typeof key !== 'string' || !key || key.length > 512) throw fail('bad key', 400); if (suppressedKeys.size >= maxSuppressedKeys) throw fail('suppression list full', 503); suppressedKeys.add(key); dirty = true; return { ok: true, size: suppressedKeys.size } },
    removeKey (key)  { const had = suppressedKeys.delete(key); if (had) dirty = true; return { ok: true, removed: had } },
    addAppId (a)     { if (typeof a !== 'string' || !a || a.length > maxAppIdLength) throw fail('bad appId', 400); if (suppressedAppIds.size >= maxSuppressedAppIds) throw fail('suppression list full', 503); suppressedAppIds.add(a); swarm._forgetDescriptorsFor && swarm._forgetDescriptorsFor(a); dirty = true; return { ok: true, size: suppressedAppIds.size } },
    removeAppId (a)  { const had = suppressedAppIds.delete(a); if (had) dirty = true; return { ok: true, removed: had } },
    list ()          { return { keys: [...suppressedKeys], appIds: [...suppressedAppIds] } }
  },
  _stats () { /* ... */ }
}
```

---

## 5. Design — operator control surface (authenticated, NON-public)

The suppression list is operator-only. It must never be mutable by an ordinary client token — `auth.verify` (lib/token.mjs:21) accepts **any** issued token (anyone can `POST /api/token`, lib/server.mjs:107; the token only scopes rate limiting). So the admin surface needs a **separate secret**, distinct from `PEERIT_RELAY_SECRET`.

### 5.1 Admin secret + auth (reuse the HMAC/timing-safe discipline in token.mjs)
Add `PEERIT_RELAY_ADMIN_SECRET` (env). If **unset**, the admin endpoints return `404` (the layer is inert and the surface does not exist — never a soft-fail-open). Auth is a constant-time compare of a caller-supplied `x-pear-admin` header against the configured secret, using `crypto.timingSafeEqual` exactly as `token.mjs` verify does (lib/token.mjs:29):
```js
// server.mjs: inject adminSecret into createRelayHandler
function adminOk (req) {
  if (!adminSecret) return false
  const got = req.headers['x-pear-admin']
  if (typeof got !== 'string' || got.length !== adminSecret.length) return false
  try { return timingSafeEqual(Buffer.from(got), Buffer.from(adminSecret)) } catch { return false }
}
```
`createRelayHandler` gains `adminSecret` in its options (default from `process.env.PEERIT_RELAY_ADMIN_SECRET`), wired in relay.mjs alongside the other env reads (relay.mjs:56–63). Optionally sign admin requests HMAC-style (payload+timestamp) to prevent replay if the header could be logged; a raw shared secret over the TLS-terminated proxy is the minimum acceptable bar and matches the existing token trust model.

### 5.2 Endpoints (routed BEFORE the ordinary `auth.verify` gate, gated by `adminOk`)
Place these in the handler (lib/server.mjs) immediately after the `/api/token` route (lib/server.mjs:107) and **before** the `auth.verify` line (lib/server.mjs:109), each guarded by `adminOk(req)` returning `401` on failure and `404` when `adminSecret` is unset:

```
POST /api/admin/suppress        { key?: "post!c!cid", appId?: "<pub>" }   → core.suppress.addKey / addAppId
POST /api/admin/unsuppress      { key?: ..., appId?: ... }                → core.suppress.removeKey / removeAppId
GET  /api/admin/suppress        → core.suppress.list()   (audit / transparency export)
```
Rules:
- **Not public.** `adminOk` is checked first; a normal client token grants nothing here. When `adminSecret` is unset, `/api/admin/*` is `404` (indistinguishable from a relay without the feature).
- Bind the admin routes to the same handler but recommend the reverse proxy additionally restrict `/api/admin/*` by source IP / basic-auth as defense in depth (documented in the relay README, not code).
- Mutations flow through `core.suppress.*` (§4), which sets `dirty = true` → snapshotted on the next flush and on SIGTERM. A takedown is durable within one debounce interval (default 5s, relay.mjs:47) and guaranteed durable on graceful shutdown.

### 5.3 Config-file alternative (boot-time)
Additionally support a boot-loaded list for operators who prefer declarative config over live API calls: `PEERIT_RELAY_SUPPRESS_FILE` → a JSON file `{ "keys": [...], "appIds": [...] }` read in `loadSnapshot()`/constructor and merged into the sets (same defensive parse as §4). The API-managed set and the file-managed set union; the file is re-read only on boot (a SIGHUP re-read is an optional extra). This gives a git-tracked, reviewable takedown ledger for operators who want the paper trail in version control.

---

## 6. Composition with the client withholding-audit (BY DESIGN)

peerit clients run a **signed-head-floor withholding audit** (peerit `js/gossip.js`): `auditOutbox(rows, head, owner)` (js/gossip.js:176) checks that the rows a relay served match the author's signed `head.count`/`head.root` census, and `_reconcile` maintains a **durable monotonic head floor** (`this._floor`, js/gossip.js:371, persisted js/gossip.js:503) plus a `this._withholding` set (js/gossip.js:369) of outboxes that fail their audit on **every reachable relay**.

**A suppressed record therefore looks exactly like withholding to the client — and that is the intended, correct behavior:**

- The signed `head!<appId>` census (authored by the client, counting the record) is **still served** unless the operator also suppresses that outbox/head. So the client sees `head.count = N` but `range`/`get` returns `N−1` rows → `auditOutbox` reports `countSufficient: false` and/or `matches: false` (js/gossip.js:180–183). The client marks the outbox as **withholding** (js/gossip.js:834) and — critically — **routes the read to another relay in the pool** (`recoverRows`/cross-relay recovery, js/gossip.js:788, 828–829).
- **A takedown IS withholding.** This is the honest framing: suppression on relay R makes R decline to serve a record; a client that also talks to relay S (which has not suppressed it) transparently recovers it. **Suppression on one relay ≠ global erasure** — it is one conduit declining to carry one item, which is precisely what a per-service takedown is and all a per-service takedown can be.
- **No false forks, no census corruption.** Because the bytes and the `head!` census stay on disk untouched (§3.8), the client's producer-side `_maintainHead` and auditor-side `auditOutbox` remain **symmetric** — the relay is not fabricating a lower count, it is declining to serve rows against an honest count. The audit fires as "this relay is withholding," not "the log is corrupt," which is the accurate description.
- **Rollback-floor interaction.** If an operator suppresses the whole appId (including its `head!` record via §3.6/§3.4), the client that already learned a higher floor for that author (js/gossip.js:807–811) will log a rollback-below-floor warning and flag withholding — again the correct signal ("this relay stopped serving an author I've seen"), and again recoverable from another relay.

State plainly in the relay README and operator docs: **the withholding audit is not defeated or deceived by suppression; it correctly reports it.** A takedown is a visible, auditable act of one conduit, not a silent rewrite of history. This is a feature — it is what lets the network remain censorship-*evident* while letting an individual operator comply.

### Interaction with content-addressed blobs (BlindShard)
Per [`BLINDSHARD-DESIGN.md` Phase 2](BLINDSHARD-DESIGN.md), a long post body is stored as an opaque `blob!<blobId>` row and the post row carries a signed manifest referencing it. Two suppression targets:
- **Suppress `blob!<blobId>`** → the body ciphertext stops being served; the post row (title/metadata/manifest) may remain. peerit's blob hydration already tolerates a missing blob and surfaces `_blobMissing` (peerit `js/blob-store.js`/`js/data.js` `getPost` hydration) rather than crashing. Result: the post appears with its body blanked/unavailable — a clean, minimal takedown that removes the offending *content* while leaving the thread structure intact.
- **Suppress the `post!<community>!<cid>` row** → the whole post (and its manifest) stops being served; the orphaned `blob!<blobId>` becomes unreferenced. Both are valid; a notice targeting a specific body prefers the `blob!` form, a notice targeting the whole post prefers the `post!` form.

Note the blob's self-certification gate (`SHA-256(ct)==blobId` in `admit()`, per BlindShard Phase 2 "AS BUILT") is a **client-side merge** rule and is unaffected — suppression happens at serve time on the relay, downstream of nothing the client signs.

---

## 7. Test plan (peerit-relay/test)

New file `test/relay-suppress.mjs`, matching the existing harness style (plain `node:assert`, `ok(cond, msg)` counter, run with `node test/relay-suppress.mjs`) as in `test/relay-persist.mjs` and `test/relay-hardening.mjs`. Drive the core directly for unit coverage and the HTTP handler for the admin-auth cases.

**Core-level suppression (drive `createMemoryCore`):**
1. **Seed:** `create(A)`; `append` several `post!c!*` rows and one `blob!<id>` row; also `append` a `head!A` census row.
2. **`get` hides a suppressed key:** `suppress.addKey('post!c!cid1')` → `sync.get(A, 'post!c!cid1') === null`, while a sibling `post!c!cid2` is still returned. (Covers §3.1.)
3. **`range`/`list` omit the suppressed key AND do not shrink the page:** a `range` over the prefix returns every row **except** the suppressed one, and returns the full expected count of the *unsuppressed* rows (proving the filter runs before `limit` slicing, §3.2).
4. **`count` excludes suppressed:** `sync.count(A, 'post!c!')` drops by exactly one after suppressing one `post!c!*` key. (§3.3.)
5. **`blob!` suppression blanks the body:** `suppress.addKey('blob!<id>')` → `get(A,'blob!<id>') === null`; the referencing post row still returns. (§6 / §3.1.)
6. **Whole-appId suppression:** `suppress.addAppId(A)` → `range`/`list`/`get` return empty/null for every key in A; `status(A).viewLength === 0`; `heads([A]).heads[A] === 0`; `directory()` omits A. (§3.2–§3.6.)
7. **`directory` omits a suppressed appId AND a suppressed `head!` key.** (§3.6.)
8. **`heads` reports 0 for a suppressed appId** even though `append` bumped its version, so a polling client is not told to re-read it. (§3.5.)
9. **Bytes retained (append-only intact):** after suppression, `_stats().totalBytes` is unchanged and re-`append` of an edit to the suppressed row still succeeds and still bumps `version` (proving suppression is serve-time only, §3.8).
10. **Unsuppress restores:** `suppress.removeKey(...)` / `removeAppId(...)` → the row/outbox is served again from `get`/`range`/`count`/`status`/`heads`/`directory`. Round-trips cleanly.

**Persistence (mirror `relay-persist.mjs`):**
11. **Survives restart:** with `persist: { path, intervalMs: 1e9 }`, suppress a key + an appId, `core.flush()`, construct a **new** core over the same path → the suppressed key/appId are still suppressed (served as absent) without re-issuing any admin call. (§4.)
12. **SIGTERM discipline:** `flush()` writes the suppression sets into the snapshot atomically (assert the tmp file does not linger and the final file parses with `suppressedKeys`/`suppressedAppIds` arrays). (§4.)
13. **Corrupt snapshot:** a garbage file still starts empty and does not crash (inherits the existing guard; assert no throw). (§4.)

**Swarm replay (drive the hub or the core's swarm):**
14. **Suppressed appId is not replayed to new joiners:** remember a descriptor whose `appId === A`, suppress A, subscribe a fresh channel → the synthetic replay does **not** emit A's descriptor; a non-suppressed descriptor on the same topic still replays. (§3.7.)

**Admin auth (drive `createRelayHandler`):**
15. **Admin required:** `POST /api/admin/suppress` with a normal client token (or no admin header) → `401`; the row remains served. (§5.)
16. **Admin secret unset → 404:** build a handler with no `adminSecret` → `/api/admin/suppress` is `404` (feature inert, not fail-open). (§5.1.)
17. **Valid admin call suppresses end-to-end:** with the correct `x-pear-admin` header, `POST /api/admin/suppress {key}` returns `{ok:true}` and a subsequent `GET /api/sync/get?...` for that key (with a valid client token) returns `null`. (§5.2.)
18. **Timing-safe / length-mismatch reject:** a wrong-length admin header is rejected without throwing (exercises the `timingSafeEqual` guard). (§5.1.)
19. **`GET /api/admin/suppress` audit export** returns the current keys/appIds for a valid admin caller. (§5.2.)

Wire `test/relay-suppress.mjs` into `package.json`'s test script alongside the existing relay tests.

---

## 8. Honest framing & limits

**This makes the operator a responsive conduit — it does NOT and CANNOT globally erase content.**

- **What it achieves (the correct safe-harbor posture):** an operator served a valid notice can, in seconds and without a signing key and without reading the content, **stop serving** the named record or outbox on **their** relay, satisfying the "expeditiously remove or disable access upon notice" condition that safe harbors are conditioned on. It converts "structurally cannot comply" into "compliant conduit." This is the intended and defensible claim.
- **What it does NOT do:** it does not remove content from the **network**. peerit is P2P: other relays in the roster, user-device seeders (the durable localStorage floor + full author copy, js/gossip.js `_loadCache`/`_loadFloor`), and PearBrowser-native peers may still carry and serve the same record. A suppression on relay R is one conduit declining to carry one item. **This is not a defect — it is the conduit shape.** An operator can only be asked to act on the service they run.
- **It is censorship-*evident*, not silent.** Per §6, a suppressed record surfaces to clients as **withholding**, which they detect and route around. The takedown is auditable and non-deceptive: the relay declines to serve against an honest, unchanged signed census — it does not fabricate history or fork the log.
- **Metadata / graph unaffected by design.** Suppression removes serve-time availability of named items; it is not a privacy mechanism. Who-posted-what associations for *non-suppressed* records remain cleartext as before ([`BLINDSHARD-DESIGN.md` §6.3](BLINDSHARD-DESIGN.md)).
- **Persistence is a deployment requirement, not a default.** With `PEERIT_RELAY_PERSIST` unset (relay.mjs:47) the suppression list is memory-only and lost on redeploy. A compliance-serious operator MUST enable persistence; document this as a hard operational prerequisite.
- **Blindness composition (BlindShard).** On a boxed-body relay, suppressing `blob!<blobId>` removes the ciphertext body an operator was never able to read; the post may remain with `_blobMissing`. Takedown-by-opaque-id and blindness are **not in tension** — the operator drops an identifier a notice names, never reads content, exactly as [`OPERATOR-LIABILITY.md` §3.3](OPERATOR-LIABILITY.md) prescribes.

### Non-code companions (name + ship alongside the mechanism)
The mechanism is necessary but not sufficient for the safe-harbor posture. Ship these operator-side, non-code pieces (brief, in the relay README / operator agreement):
1. **A notice channel.** A published contact — a `abuse@`/`dmca@` email or a form — where a notice can be received. A relay with no way to *receive* a notice cannot be "responsive."
2. **A designated agent.** For US DMCA §512, a designated agent on record (register with the Copyright Office for the formal safe harbor). Name it in the ToS.
3. **A minimal ToS / acceptable-use policy.** States the service is a neutral availability relay, that the operator does not select or endorse content, that valid notices are actioned via the drop-by-id path, and how to submit one.
4. **A repeat-infringer posture.** §512(i) conditions the safe harbor on a policy for terminating repeat infringers "in appropriate circumstances." On peerit that maps to **whole-appId suppression** (§3, §5) of an account that is the repeated subject of valid notices — the mechanism to enforce such a policy already exists in this layer; the *policy* must be written down.

These are positioning/paperwork, not code — but per [`OPERATOR-LIABILITY.md` §4–§5](OPERATOR-LIABILITY.md) they are load-bearing: the code lets an operator comply; the paperwork is what puts "neutral, responsive conduit" on the record.

---

## 9. Summary of concrete edits

| File | Function / location | Change |
|---|---|---|
| `lib/core-memory.mjs` | new sets + `isKeySuppressed`/`isAppSuppressed` near `getGroup` (:82) | data structure (§2) |
| `lib/core-memory.mjs` | `get` (:138) | return `null` for suppressed key (§3.1) |
| `lib/core-memory.mjs` | `rangeRows` (:96) + `list`/`range` (:139–140) | filter suppressed rows before `limit` (§3.2) |
| `lib/core-memory.mjs` | `count` (:141) | exclude suppressed from tally (§3.3) |
| `lib/core-memory.mjs` | `status` (:149) | empty for suppressed appId (§3.4) |
| `lib/core-memory.mjs` | `heads` (:153) | `0` for suppressed appId (§3.5) |
| `lib/core-memory.mjs` | `directory` (:164) | omit suppressed appId / head key (§3.6) |
| `lib/core-memory.mjs` | `snapshot` (:67) / `loadSnapshot` (:41) | persist + rehydrate the sets (§4) |
| `lib/core-memory.mjs` | return object (:110) | expose `suppress.{addKey,removeKey,addAppId,removeAppId,list}` (§4) |
| `lib/swarm-hub.mjs` | `createSwarmHub` opts (:19), `replay` (:43), `remember` (:30) | `isDescriptorSuppressed` predicate + optional `_forgetDescriptorsFor` (§3.7) |
| `lib/server.mjs` | `createRelayHandler` opts (:39), after `/api/token` (:107), before `auth.verify` (:109) | `adminOk` + `/api/admin/(un)suppress` routes (§5) |
| `relay.mjs` | env reads + `createRelayHandler` call (:56–63) | `PEERIT_RELAY_ADMIN_SECRET`, `PEERIT_RELAY_SUPPRESS_FILE` (§5) |
| `test/relay-suppress.mjs` | new | full test plan (§7) |
| `package.json` | test script | run the new test |
| `README.md` | operator docs | env vars, notice channel, ToS/agent/repeat-infringer posture (§5, §8) |
