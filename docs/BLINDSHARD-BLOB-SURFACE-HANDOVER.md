# HiveRelay Handover Spec — Phase 3 BLIND BLOB SURFACE (BlindShard)

**Audience:** HiveRelay agents (the `00-core/hiverelay` fleet).
**Consumer:** peerit `feat/web-deployment` client (`js/box.js`, `js/shard.js` — already built).
**Status:** buildable. This is the ONE net-new relay capability BlindShard needs; every other piece is client-side and done.
**Design source:** `/Users/localllm/Desktop/Faceless/BLINDSHARD-DESIGN.md` §3a, §4 net-new #5, §5 Phase 3, §6 risks 2/8.

> **Thesis (do not overclaim — design §2 "HONEST LIMIT", §6.1):** this surface makes a relay hold, at rest, only opaque content-hash-addressed ciphertext fragments — fewer than K of any item, no key, no manifest, no author linkage. It is **non-readability-in-isolation + deniability**, NOT confidentiality. A relay that ALSO mirrors the outbox and crawls shards defeats blindness (§6.2). Keep manifests OFF this tier.

---

## 0. What already exists (verified — reuse, do not rebuild)

| Asset | File:line | What it gives us |
|---|---|---|
| Custody attestation protocol: `custody-intent` / `custody-receipt` / `custody-commit`, over `blindContentId` (64-hex), `ciphertextRoot` (64-hex), `shardIds`, `requiredReplicas`, `storageCommitment` | `packages/core/core/custody-signing.js:56-176`, `:205-267` | The signed, replicated placement/replication contract. `custodyMode: 'blind'` is enforced (`:427-429`). Do NOT re-derive a weaker one. |
| `FORBIDDEN_KEYS` reject (recursive, on every signed entry) | `custody-signing.js:10-32`, enforced at `:411` / `:932-939 containsForbiddenSecret` | Any op carrying `dataKey`/`decryptionKey`/`plaintext` is refused → proves key never co-locates with shards. |
| Blind seed ingestion: `seedApp(appKey, { blind:true, blindContentId, ciphertextRoot, shardIds, retainUntil, requiredReplicas })` | `packages/core/core/relay-node/app-lifecycle.js:149-247`; publisher-signed builder `packages/core/core/seed-request-builder.js:159-360` | Publisher-signed, replay-protected, lease-gated write path that binds bytes (an `appKey`-addressed Hypercore) to custody anchors. `blind:true` → `storageClass:'temporary'`, `availabilityClass:'atomic-handoff'`, redacted metadata. |
| `dht-relay-ws` Noise-tunneled WSS transport | `packages/core/transports/dht-relay-ws/index.js:186-264` | Browser reaches the swarm over WSS; block contents are **end-to-end Noise-tunneled, relay-blind** (`:19-27`). This is how a browser PUTs/GETs shard bytes without the relay reading them. |
| Per-IP token-bucket rate limit on that transport | `dht-relay-ws/index.js:137-167` | Connection-level DoS floor. NOT sufficient alone for write-DoS — see §5 PoW. |
| OutboxLog single-writer contract (the thing we must NOT reuse for shards) | `packages/services/builtin/outboxlog/outbox-log.js:72-109`, gate `:236-255` | `verifyOutboxRecordSignature` hard-requires `data._k === appId` (`:246`) and namespace `'peerit'` (`:248`). Structurally cannot express an anonymous blob. This is *why* the new surface exists. |
| Publisher-signed seed replay cache + lease gate | `seed-request-builder.js:121-143`, `api-seed-publish.js:393-411` | Reuse verbatim for write authorization economics. |

**Load-bearing discovery:** the custody pipeline is an **attestation + swarm-seeding** layer over `appKey`-addressed Hypercores. It signs *claims about* content (`blindContentId`/`ciphertextRoot`/`shardIds`) and replicates it over the DHT swarm; it does **not** today expose a `GET blob-by-content-hash` read plane. So "the net-new surface" = a thin **content-addressed store+read plane** that the existing custody protocol **attests over** — not a parallel custody scheme. That is the entire scope below.

**Field-name reconciliation (critical — the two systems use `shardIds` differently):**
- peerit `shard.js` `shardId` = **`SHA-256(shard bytes)` as 64-hex** — the content address of one erasure shard (`js/shard.js:97,304`).
- custody `shardIds` (`custody-signing.js:825 normalizeIntegerArray`) = **array of non-negative integers** — Hypercore *block indices* within one custodied core.
- **These are not the same field. Do not conflate them.** The mapping in §2 puts peerit's hex shard address into `blindContentId`/`ciphertextRoot` (each shard is its own tiny custodied item) and lets custody `shardIds` stay the block-index array (0 for a single-block shard core).

---

## 1. Mission

Build a **content-addressed `shard:<hash>` PUT/GET blob surface, DECOUPLED from author identity**, reachable over WSS, so a shard is an anonymous opaque blob — the thing the OutboxLog single-writer contract (`outbox-log.js:246`, `_k === appId`) structurally cannot express.

**Hard requirements:**
1. **Address = content hash, not author.** A shard is stored and retrieved by `shardId = SHA-256(bytes)` (peerit `js/shard.js:97`). There is **no** `appId`/`_k` gate, no author pubkey in the address, no per-author outbox. Two authors uploading the same shard bytes hit the same address (convergent dedup — design §2).
2. **Server-side self-verification on PUT.** On write, the relay MUST recompute `SHA-256(bytes)` and reject if it ≠ the claimed `shardId` (a relay/attacker cannot store bytes under a wrong address). This is the ONLY thing the relay validates about shard *content* — it is otherwise opaque.
3. **`< K` shards of any one item per relay** is a client-enforced placement invariant (peerit `js/shard.js:362 place()`), but the relay MUST expose enough for a reader to audit it (§4 placement contract). The relay does not itself know K; it just stores what it's given, addressed by hash.
4. **Blindness posture (design §2, §6.1/§6.2):** at rest under `shard:*` the relay holds ciphertext with no `contentKey`, no manifest, no shard→post linkage. `shardId` reveals nothing (it's a hash of ciphertext). The relay CANNOT read a shard, attribute it to a post, or reassemble an item (holds `< K`). It CAN act as a reader if it also fetches the public manifest from the outbox tier — disclosed, not hidden.

---

## 2. Wire into the EXISTING custody pipeline (STRONGLY preferred over a parallel store)

Map peerit's per-shard manifest fields onto the custody protocol so the surface is *the existing pipeline with a content-addressed read plane bolted on*, reusing `custody-signing.js` verbatim.

### 2.1 One shard = one blind custody item

Each erasure shard is treated as its own minimal blind-custody unit. Per shard `i`:

| peerit client value (`js/shard.js`, `js/box.js`) | custody field (`custody-signing.js`) | notes |
|---|---|---|
| `shardId_i = SHA-256(shard_i)` (64-hex) | `blindContentId` | the anonymous content address. `hexField` validated (`:437,972`). |
| `SHA-256(shard_i)` again, or the shard-core Hypercore tree root | `ciphertextRoot` | for a single-block shard core these coincide; either is a 64-hex root binding the stored bytes. `normalizeCustodyEntry:432` requires it for intent/receipt/commit. |
| `[0]` (single block) | `shardIds` (custody sense = block indices, `:825`) | integer array; a one-block shard core is `[0]`. Distinct from peerit's `shardId`. |
| roster replica count for this shard (peerit `place({replicas})`, `shard.js:362`) | `requiredReplicas` | `positiveInteger` (`:751`). Client sets to `place()`'s `replicas`. |
| derived on receipt | `storageCommitment` | auto-derived `hashHex({intentId, blindContentId, ciphertextRoot, contentVersion, relayPubkey, shardIds, anchored})` (`:253-263`) — no client action. |

The **manifest** peerit publishes to its outbox — `{blobId, contentKey, iv, k, n, shardIds[]}` (peerit `js/box.js:85`, `js/shard.js`) — stays entirely on the OutboxLog tier and NEVER enters a custody entry. `contentKey` and the manifest are public *there* by design (§3).

### 2.2 Write path — reuse `seedApp` blind ingestion

A shard PUT is a **publisher-signed blind seed** through the existing builder, one custody item per shard:

- Client calls the publisher-seed route (`api-seed-publish.js:374 runPublisherSeedAction` → `seed-request-builder.js:159 buildPublisherSignedSeedOpts`) with `blind: true`, `blindContentId = shardId_i`, `ciphertextRoot`, `contentVersion`, `retainUntil`, and `requiredReplicas` via the intent.
- `seedApp` (`app-lifecycle.js:149`) with `blind:true` already forces `storageClass:'temporary'`, `availabilityClass:'atomic-handoff'`, `metadataVisibility:'redacted'`, and runs `policyGuard.check(..., 'replicate-encrypted-data')` (`:191-201`). Reuse all of it.
- The relay signs a `custody-receipt` (`custody-signing.js:240`) attesting it holds this `blindContentId`/`ciphertextRoot` — this is the placement acknowledgement (Phase 4 quorum, but the receipt is emitted now).

**One net-new store operation:** the relay must additionally index the raw shard bytes by `SHA-256(bytes)` so they're retrievable by hash *without* the `appKey`. Concretely: on a blind seed whose `blindContentId` equals `SHA-256(the single stored block)`, register a `shard:<blindContentId> → coreKey@blockIndex` lookup entry in a new content-address index (§3.2). Nothing about the custody signing changes.

### 2.3 What stays untouched

- `custody-signing.js` — **zero edits.** All fields already exist; `shardIds` (integer) and `blindContentId`/`ciphertextRoot` (hex) carry the mapping.
- The publisher-signature, replay-nonce, and lease gates (`seed-request-builder.js`, `api-seed-publish.js:393-411`) — reused verbatim as the write-authorization spine.

---

## 3. FORBIDDEN_KEYS — what the relay rejects, and what it must NOT reject

### 3.1 On the shard/custody tier — REJECT (already enforced)

`containsForbiddenSecret` (`custody-signing.js:411,932-939`) recursively refuses any entry carrying `contentKey`, `plaintext`, `dataKey`, `decryptionKey` (extend the set with **`contentKey`** — see below). Any shard-PUT op or custody entry carrying a decryption key is refused with the existing error. This is the structural proof that key and blob never co-locate.

**Action item (small, real):** the current `FORBIDDEN_KEYS` (`custody-signing.js:10-32`, mirrored in `packages/client/custody.js:36-58`) lists `dataKey`/`decryptionKey`/`plaintext` but **not `contentKey`**. peerit's key field is named exactly `contentKey` (`js/box.js:85,92`). **Add `'contentKey'` to `FORBIDDEN_KEYS` in BOTH copies** (core + client — they are byte-identical duplicates pinned by `test/unit/client-custody-crossimpl.test.js`, see `packages/client/custody.js:1-25`). This guarantees a shard-tier op carrying the convergent key is refused.

### 3.2 On the manifest/outbox tier — MUST NOT reject

`contentKey` and `shardIds` (the hex address list) are **PUBLIC by design** in the client manifest (design §4 #3, §1 "contentKey PUBLIC by design"). They live on the OutboxLog surface as ordinary signed record fields. The OutboxLog verifier (`outbox-log.js:236`) already treats the record body as opaque and only checks the envelope — it does **not** apply `FORBIDDEN_KEYS`. **Do not add any FORBIDDEN_KEYS-style filter to the OutboxLog path.** The manifest MUST be publishable with `contentKey` in the clear, or readers can't decrypt. The separation is exactly: `FORBIDDEN_KEYS` on the shard tier, no key-filter on the manifest tier.

---

## 4. Interface peerit's client needs

peerit's `js/shard.js` is written against an **injected `backend`** (`js/shard.js:16-24`): "encode/place hand it `(id → bytes)` pairs, decode consumes gathered bytes." The relay must provide exactly this backend over WSS. Two operations:

### 4.1 `putShard(shardId, bytes)` → receipt

- **Address:** `shardId` = 64-hex `SHA-256(bytes)`. Relay recomputes and **rejects on mismatch** (§1.2).
- **Auth:** publisher-signed blind seed (§2.2) + PoW (§5). No `appId`/author gate.
- **Idempotent:** identical bytes → same address → dedup (design §2, §4 #storage).
- **Returns:** the `custody-receipt` (`custody-signing.js:240`) — `{blindContentId, ciphertextRoot, relayPubkey, storageCommitment, retainUntil, anchored}` — so the client can collect a placement quorum (Phase 4).
- **Size:** shard bytes are raw over the DHT-relay replication stream (NOT the OutboxLog 64 KiB / base64-×1.33 path — design §3b, §6.4). The 64 KiB cap (`outbox-log.js:20`) applies to the *manifest*, not shards.

### 4.2 `getShard(shardId)` → bytes | null

- **Lookup:** `shard:<shardId>` content-address index → `coreKey@blockIndex` → serve the block over the Noise-tunneled DHT-relay stream (`dht-relay-ws/index.js:241`). Relay serves opaque bytes it cannot read.
- **Self-verifying:** client re-checks `SHA-256(bytes) === shardId` (`js/shard.js:97`) → a relay cannot substitute. Relay MAY also verify before serving.
- **Miss:** return null/404 so the reader routes to the next-ranked relay (generalizes peerit `relay-pool.js recoverRows`, design §1 "route to next K candidates").

### 4.3 Placement / replication contract (client-computed, relay-auditable)

- **Placement is deterministic and client-side:** peerit `place(shardIds, roster, {replicas, k})` (`js/shard.js:362`) ranks relays by `SHA-256(relayPub ‖ shardId)` (HRW) and assigns the top `replicas`, enforcing **`< K` shards per relay** (`js/shard.js:377-402`). The relay does NOT decide placement; it stores what it's handed at its hash address.
- **Relay's contract:** (a) store any validly-addressed, PoW-gated, publisher-signed shard within `retainUntil`; (b) emit a `custody-receipt` so placement is acknowledgeable (not fire-and-forget — design §3 "honest durability caveat", §6.7); (c) serve or 404 on GET.
- **Auditability (design §3a, §6.2):** because placement is a pure function of the signed roster + `shardId`, any reader recomputes the assignment and can detect a relay that accepted `≥ K` shards of one item. Expose per-relay held-shard membership queryable enough to audit this (a relay listing which `blindContentId`s it holds is already implied by the custody catalog). **The relay must not be the enforcer of `< K`; it must be auditable against it.**

### 4.4 The honest invariant — keep manifests OFF this tier (design §6.2, mission #4)

A single relay that mirrors outboxes (holds the manifest → `contentKey` + shard address list) **and** crawls its own `shard:*` store (holds ≥ K shards) defeats blindness for that item. Mitigation, in priority order:

1. **Never co-serve.** A relay SHOULD run either the OutboxLog manifest tier OR the shard tier, or keep them in isolated stores with no join key. The `shard:<hash>` address deliberately carries **no** `appId`/manifest linkage, so a shard-only relay has no index from shard → post (design §2 "cannot tell which post a `shard:<hash>` belongs to").
2. **Placement disjointness.** peerit's `place()` already keeps `< K` per relay; extend the client roster policy so manifest-holding relays are down-weighted as shard holders (design §1 "manifest/shard-disjoint invariant"). Relay-side: expose enough for the client to see which relays serve OutboxLog so it can exclude them from shard placement.
3. **Disclose the ceiling.** A fully colluding roster reconstructs everything (design §6.2). Blindness holds against **independent** relays only. State this in the relay's threat-model doc; do not let UI copy claim operator-blindness (design §2 "forbidden").

---

## 5. PoW-gated writes (open-write DoS defense)

The shard surface is **not** `appId`-gated, so it is open-write — it needs a cost gate beyond the per-IP token bucket (`dht-relay-ws/index.js:137`, which is connection-level only).

- **Gate:** require a hashcash/PoW stamp on every `putShard`, mirroring peerit's per-post `2^16` proof-of-work (design §4 #reuse `pow.js:80-87`, §3b "dwarfed by existing PoW"). The stamp binds `shardId` + publisherPubkey + a relay-supplied challenge/timestamp so it can't be precomputed or replayed.
- **Reuse the replay cache** (`seed-request-builder.js:121-143`) keyed on the PoW nonce to reject replays.
- **Difficulty** is an operator config knob; default to match peerit's post PoW so a shard write costs ~one post's work. The lease gate (`api-seed-publish.js:393-411`) remains available for durable/paid retention on top.
- **Layering:** PoW (per-op cost) + token bucket (per-IP rate, `dht-relay-ws`) + `SHA-256` address self-check (no wasted store on garbage) + `retainUntil`/`temporary` storage class (bounded lifetime, `app-lifecycle.js:154-166`).

---

## 6. Acceptance test (the round-trip that gates Phase 3)

A peerit `shard.js` **encode → disperse → gather-K-from-distinct-relays → decode** round-trip passes through the REAL surface:

1. **Fixture:** a body ≥ `SHARD_MIN_BYTES` (8 KiB, `js/shard.js` `SHARD_MIN_BYTES`) so `shouldErasure()` is true. Client `box(body)` → `{C, contentKey, iv, blobId}` (`js/box.js:85`); `encode(C, k, n)` → N shards with `shardId_i = SHA-256(shard_i)` (`js/shard.js:97,304`).
2. **Roster:** ≥ N-capable roster of **distinct** relays (design Phase 0 prerequisite — the real fleet, ≥3 independent HiveRelay nodes), so `place(shardIds, roster, {replicas, k})` (`js/shard.js:362`) yields an assignment with **`< K` shards per relay** (assert the invariant, design §5 "servers-of-happiness").
3. **Disperse:** for each `(relay, shardId)` in the placement, `putShard(shardId, bytes)` over WSS through this surface. Assert: (a) each PUT returns a valid `custody-receipt` (`verifyCustodyEntry`, `custody-signing.js:381`); (b) a PUT with bytes whose `SHA-256 ≠ shardId` is **rejected**; (c) a PUT/entry carrying `contentKey`/`plaintext` is **rejected** by `FORBIDDEN_KEYS` (§3.1); (d) a PUT without a valid PoW stamp is rejected (§5).
4. **Gather K from distinct relays:** kill/withhold `N−K` relays. `getShard` the surviving K from **K distinct relays**; assert each returned blob satisfies `SHA-256(bytes) === shardId` (`js/shard.js:97`).
5. **Decode + unbox:** `decode(gatheredShards, k, n) → C`; assert `SHA-256(C) === blobId`; `unbox(C, contentKey, iv) → body` with the mandatory content-key gate (`js/box.js` unbox `SHA-256(plaintext) === contentKey`). Assert `body` equals the original byte-for-byte.
6. **Blindness assertions (design §2, §6):** (a) no single relay's `shard:*` store held ≥ K shards of the item; (b) no relay's shard store contained `contentKey` or the manifest; (c) a `shard:<hash>` on any relay carries no author/post linkage. (d) Negative control: a relay that ALSO holds the manifest CAN reconstruct — assert this is possible (proves the honest ceiling is not overclaimed).

**Bench gate (design §5 Phase 3, §6.5 — DMC discipline):** record K-shard fan-out p50/p95, encode/decode ms per size bucket, and the placement-invariant assertion. Do **not** claim O(bytes) scaling without the transcript.

---

## 7. Build checklist for HiveRelay agents

1. **`FORBIDDEN_KEYS` += `'contentKey'`** in `custody-signing.js:10-32` AND `packages/client/custody.js:36-58` (byte-identical; cross-impl test `test/unit/client-custody-crossimpl.test.js` must still pass). No other custody-signing edits.
2. **Content-address index + read plane:** new `shard:<shardId> → coreKey@blockIndex` lookup, populated on blind seed where `blindContentId === SHA-256(stored block)`; served over the `dht-relay-ws` stream (`dht-relay-ws/index.js:241`). This is the only genuinely net-new store surface (design §4 #5, §6.8 — "real net-new infra, not verbatim reuse").
3. **`putShard`/`getShard` route** decoupled from `_k`/`appId`: address by hash, recompute-and-reject on PUT, 404-on-miss on GET. Wire PUT through the existing publisher-signed blind-seed builder (`seed-request-builder.js:159`) + `seedApp(blind:true)` (`app-lifecycle.js:149`), emitting a `custody-receipt`.
4. **PoW gate** on `putShard` (§5), reusing the replay cache; difficulty configurable, defaulting to peerit's post PoW.
5. **Do NOT** route shards through OutboxLog (`outbox-log.js:246` would reject them) and do NOT apply any key-filter to the OutboxLog manifest path (§3.2).
6. **Threat-model doc:** disclose the colluding-roster ceiling (§4.4, design §6.2) and forbid operator-blindness UI copy (design §2).

**Net diff shape:** ~1 line in two `FORBIDDEN_KEYS` sets; one content-address index + two WSS routes (`putShard`/`getShard`) layered on the *existing* blind-seed + custody-receipt spine; one PoW hook. Custody signing, the DHT-relay transport, the publisher-seed builder, and the lease/replay gates are reused unchanged.

---

## Cited files

- Design: `/Users/localllm/Desktop/Faceless/BLINDSHARD-DESIGN.md` §2, §3a, §4 (#3, #5, #6, #8), §5 Phase 3, §6 (risks 1/2/4/5/7/8).
- `packages/core/core/custody-signing.js:10-32` (FORBIDDEN_KEYS), `:56-176` (signable fields), `:205-267` (intent/receipt), `:411,932-939` (secret reject), `:437,751,825` (field types).
- `packages/client/custody.js:1-25,36-58` (client duplicate of FORBIDDEN_KEYS — must mirror).
- `packages/core/core/relay-node/app-lifecycle.js:149-247` (`seedApp` blind ingestion).
- `packages/core/core/seed-request-builder.js:159-360` (publisher-signed seed builder + custody anchors), `:121-143` (replay cache).
- `packages/core/core/relay-node/api-seed-publish.js:374-422` (publisher-seed route + lease gate).
- `packages/core/transports/dht-relay-ws/index.js:19-27` (relay-blind Noise tunnel), `:137-167` (rate limit), `:241` (stream handoff).
- `packages/services/builtin/outboxlog/outbox-log.js:20` (64 KiB cap), `:236-255` (`_k===appId` + `peerit` namespace gate — the contract shards must NOT use).
- peerit client (already built): `02-apps/peerit/js/box.js` (`box`/`unbox`, `contentKey`/`blobId`/`iv`), `02-apps/peerit/js/shard.js:97,304` (`shardId=SHA-256(bytes)`), `:362-407` (`place()` HRW + `< K` invariant), `:16-24` (injected `backend` interface this surface must implement).