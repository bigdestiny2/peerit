# BlindShard Record-Wiring Spec — dispersal manifest on the live post record

**Status:** DESIGN / hand-off. Written by the BlindShard session for the data-model
session. **No `js/data.js` edits are made by this spec** — it defines exactly what to
change so the two sessions don't collide.

**Prereqs proven before this spec (do not re-litigate):**
- The dealer speaks the shipped HiveRelay #159 custody contract byte-for-byte, validated
  live against a real 3-relay shard-store cohort (`scripts/blind-dispersal-live.mjs`).
- peerit's **real** curated seed bodies disperse + reconstruct across that cohort with a
  full 2-of-3 truth table (`scripts/seed-disperse.mjs`, commit `601c99c`): every single
  relay fail-closes, every pair reconstructs.
- Addressing is **blake2b-256** (client `shardAddressOf`), never SHA-256.

This spec wires that proven dealer into the record model **without** breaking today's
browser, and lays out the cutover to a keyless-on-the-VPS read path.

---

## 0. TL;DR for the implementer

1. Add ONE optional top-level field to the post/comment record: **`dispersal`** = the
   dealer's manifest object. It rides the record exactly like the existing optional
   `blob` field. **No `canon.js` or `gossip.js` change is required** (proven in §2).
2. Store the ciphertext as an ordinary peerit **`blob!<blindContentId>`** record. Because
   `blindContentId = SHA-256(ciphertext)` and the existing `verifyBlobRecord` gate checks
   `SHA-256(ct) === blobId`, the dealer's ciphertext is admit-clean on the **existing**
   blob transport — no new relay endpoint for the interim.
3. The manifest carries **no content key** (unlike `blob`, which ships `contentKey` in the
   clear). The AES key is PVSS-split across the HiveRelay cohort. → **the key leaves the
   VPS.** The VPS holds only opaque ciphertext + a keyless manifest.
4. Roll out additively: keep writing today's body form first (browser unaffected), attach
   `dispersal` alongside, then flip the read path, then move the ciphertext blob off the
   VPS with the OutboxLog migration.

---

## 1. The `dispersal` field

`data.submitPost` (and `submitComment`) gains an optional `dispersal` field, populated by
a node dealer at write time. It is the object `disperseBody()` already returns as
`manifest` ([js/blind-dealer.mjs:231](../js/blind-dealer.mjs)):

```jsonc
{
  "version": 2,
  "scheme": "pvss-secp256k1-v1",
  "threshold": 2,                       // k
  "count": 3,                           // n
  "blindContentId": "<64-hex>",         // = SHA-256(ciphertext); the blob address
  "ciphertextRoot": "<64-hex>",         // = SHA-256(ciphertext)
  "commitmentRoot": "<64-hex>",         // Feldman commitment root (blake2b)
  "shareBundleKey": "<hex>",            // blake2b-256 of commitmentRoot bytes
  "shareManifest": [                    // length n
    { "shareIndex": 1, "shard": "shard:<64-hex>", "shareCommitment": "<66-hex secp256k1 point>" },
    { "shareIndex": 2, "shard": "shard:<64-hex>", "shareCommitment": "<66-hex>" },
    { "shareIndex": 3, "shard": "shard:<64-hex>", "shareCommitment": "<66-hex>" }
  ],
  "iv": "<24-hex>",                     // AES-256-GCM IV (12 bytes)
  "alg": "AES-256-GCM"
  // NOTE: NO contentKey. That is the whole point — the key is dispersed, not shipped.
}
```

**Size:** for n=3 this is ~500 bytes of JSON. No length cap in `admit()` trips (§2.4);
comfortably under the ~64 KiB per-value relay cap.

**Roster reference:** `shareManifest` binds each share to a `shard:<addr>` but not to a
relay URL. The reader supplies `relayBaseUrls` out of band (the pinned cohort roster, same
trust anchor as `relay-roster.json`). Keep the roster resolution in the app layer, not the
record — a record that pinned URLs would rot when the cohort rotates.

---

## 2. Why this needs NO canon/gossip change (the green light)

From the admission map (grounded in code):

**2.1 — The storage key is unaffected.** `expectedKey(TYPE.POST, data)` derives the key
from **only** `community` + `cid` ([canon.js:22-34](../js/canon.js)): `keys.post(community, cid)`.
`dispersal` is never read in key derivation, so
`expectedKey({community, cid, dispersal}) === expectedKey({community, cid})`. The
anti-eviction key-binding check in `admit()` still passes.

**2.2 — The signature covers it, correctly.** `canonical(type, data)` signs a
deterministic key-sorted JSON of **all** fields except `SIG_FIELDS`
([canon.js:43-52](../js/canon.js)). So `dispersal` **is** covered by the author signature
**as long as it is present before signing** — which it is, because the dealer attaches it
at write time and `_sign()` runs after. There is no "forgot to sign" gap. (The only way to
break the signature is to bolt `dispersal` onto an already-signed record — don't; build it
into the record the author signs.)

**2.3 — No unknown-field rejection.** `admit()` is a pure AND of {key-binding, signature,
owner-binding, PoW, blob-cert} ([gossip.js:95-136](../js/gossip.js)). There is no field
allowlist. The reducer stores `op.data` verbatim ([sync.js:24-30](../js/sync.js)). A fresh
record carrying `dispersal`, signed over the full record, **admits**.

**2.4 — No length cap in admission.** `admit()` enforces no per-record size limit; the
~500-byte manifest is a non-issue.

> **Implementer takeaway:** touching `data.js` (write + read paths) is sufficient.
> `canon.js`, `gossip.js`, `verify.js`, `model.js` need **no** change for `dispersal`.
> This is what keeps the two sessions from colliding.

---

## 3. Ciphertext storage — interim (VPS, opaque) → target (off-VPS)

### 3.1 Interim: reuse the existing `blob!<blobId>` record

Today a boxed v1 body writes a `blob!<blobId>` record `{ id, blobId, ct: base64(C), author }`
and the gossip gate admits it iff `SHA-256(base64decode(ct)) === blobId`
([blob-store.js:59-65](../js/blob-store.js), [gossip.js admit blob branch](../js/gossip.js)).

The dealer's ciphertext slots into that machinery unchanged:
- `blindContentId = SHA-256(ciphertext)` (dealer default), so set `blobId = blindContentId`.
- Write `{ id: blindContentId, blobId: blindContentId, ct: base64(ciphertext), author }`.
- `verifyBlobRecord` holds by construction. **No new endpoint, no new gate.**

**What the VPS now holds for a dispersed post:** an opaque ciphertext blob + a keyless
`dispersal` manifest. It **cannot** decrypt — the AES key exists only as PVSS shares on the
HiveRelay cohort. Compare to today's v1 boxing, where `contentKey` ships in the clear on
the post and the VPS can trivially decrypt. **Dispersal moves the key off the VPS.**

Honest caveat (GATE 2): blindness holds against a VPS operator who controls **fewer than k**
cohort relays. A party controlling the VPS **and** ≥k cohort relays reconstructs. That is
the independent-operators property, unchanged by this wiring.

### 3.2 Target: ciphertext off the VPS entirely

The pure-pipe end state stores the ciphertext on HiveRelay too (as an (n+1)-th "ciphertext
blob" or via a shard-store blob PUT), so the VPS holds **nothing** — only a noise pipe for
normal browsers. This depends on a HiveRelay blob-GET surface for arbitrary ciphertext (the
custody contract today is shard-scoped) and is sequenced with the OutboxLog migration
(spec #2). Until then, §3.1 keeps the ciphertext on the VPS but keyless.

---

## 4. Write path (node dealer)

The dealer is node-only today (needs `sodium` for signing custody intents). So dispersal is
authored by node writers — `test/seed-author.mjs` and any server-side authoring — **not** by
in-browser users yet (that is the #115 gate, §6). Sketch, at the `_boxBody` seam in
`data.js`:

```js
// pseudo — data.submitPost, when dispersal is enabled for this write
const { ciphertext, manifest } = await disperseBody(body, {
  threshold: k, relays: cohortRoster, publisher, fetch
})
// 1) ciphertext as an ordinary blob record (interim: on the VPS, opaque)
await sync.append({ type: 'blob', data: signBlob({
  id: manifest.blindContentId, blobId: manifest.blindContentId,
  ct: b64(ciphertext), author: me.pubkey
}) })
// 2) attach the keyless manifest; the author signs the whole record incl. dispersal
record.dispersal = manifest
// (Phase A) ALSO keep the normal body form so today's browser still reads it — see §7
```

Note the publisher: `scripts/seed-disperse.mjs` proved the dealer identity can be derived
from the author's own seed (peerit Ed25519 == sodium `crypto_sign_seed_keypair`), so custody
intents are signed by the content-authoring key. Reuse that derivation.

---

## 5. Read path

A reader with the post record + its `dispersal` manifest reconstructs with:

```js
const body = await recoverBody(manifest, {
  relayBaseUrls: cohortRoster.map(r => r.baseUrl),   // pinned cohort
  fetchCiphertext: async (blindContentId) =>
    base64decode((await sync.get(keys.blob(blindContentId))).ct),  // interim: from the VPS blob
  fetchImpl: fetch
})
```

`recoverBody` gathers k shares from the cohort, verifies each shard's blake2b address +
Feldman commitment, Lagrange-reconstructs the key, then AES-GCM-decrypts via WebCrypto
([blind-dealer.mjs:249-256](../js/blind-dealer.mjs)).

**Node reader:** works today.

**Browser reader — buildable NOW, not #115-gated (corrected finding):** the recover path
uses `@noble/secp256k1` + `@noble/hashes` (pure JS) + `sodium.crypto_generichash` (blake2b)
+ WebCrypto (`crypto.subtle` AES-GCM) + `fetch`. It does **not** use `crypto_sign` or
`randombytes_buf` (those are dealer-only). blake2b already has a browser bundle
(`web/js/blake2b-bundle.js`, verified byte-identical to sodium). So a **recover-only browser
module** — one that imports `{ recoverSecret, shardAddressOf }` + the blake2b shim + WebCrypto,
and deliberately does **not** import the sodium-signing surface of `blind-dealer.mjs` — is a
pure build task. Concretely:
- Factor a `js/blind-reader.mjs` that re-exports only `recoverKey`/`recoverBody`/`decryptBody`
  and pulls blake2b from the browser shim instead of `sodium-universal`.
- Add it to `SITE_FILES`/`publish.mjs` + the esbuild bundle (mirror the blake2b bundle build).
- No relay change, no #115.

---

## 6. What #115 actually gates (corrected)

| Capability | Gated on #115? | Why |
|---|---|---|
| Node dealer writes dispersed posts | ❌ no | works today (`scripts/seed-disperse.mjs`) |
| Node reader reconstructs | ❌ no | works today |
| **Browser reader** reconstructs | ❌ **no** | @noble + blake2b-shim + WebCrypto + fetch; §5 |
| **Browser dealer** authors dispersed posts | ✅ **yes** | Bare client can't emit manifest-bearing v2 custody intents until #115 ([custody-signing.js parity note](../js/vendor/blind-shards/custody-signing.js)) |

So: until #115, **in-browser users keep authoring the normal (v2-sealed) body**, and a node
writer (seeder, or a server-side "disperse recent posts" job) produces the dispersed copies.
The **read** cutover has no such gate.

---

## 7. Phased rollout (additive → cutover)

- **Phase A — attach, don't replace (browser-safe, ship first).** Node writers store the
  normal body form (v2-sealed today) **and** attach `dispersal` + the ciphertext blob. The
  browser reads the body exactly as it does now; node readers can exercise the dispersed
  path. Zero user-visible change; the manifest starts flowing into real records.
- **Phase B — browser reader.** Build + ship `js/blind-reader.mjs` (§5). The browser prefers
  `dispersal` when present, falls back to the sealed body. Still dual-stored.
- **Phase C — read cutover.** Once the browser reader is proven live, stop dual-storing the
  sealed body for dispersed posts; `dispersal` becomes the sole body store. The VPS now holds
  only keyless ciphertext + manifest for those posts.
- **Phase D — ciphertext off the VPS.** With the OutboxLog migration (spec #2), move the
  ciphertext blob onto HiveRelay. VPS holds nothing readable → pure pipe.

Each phase is independently revertible and independently testable. Phase A is the only one
that touches `data.js` write; Phase B touches the read path + bundle; C/D are policy flips.

---

## 8. Concrete change list for the data-model session

**Touch:**
- `js/data.js` — `submitPost`/`submitComment`: an opt-in dispersal branch at the `_boxBody`
  seam (write ciphertext blob + attach `dispersal`), and a read branch that prefers
  `recoverBody` when `record.dispersal` is present. Gate behind a flag (mirror the `v2` flag).
- `test/seed-author.mjs` — call the dealer when the flag is set (Phase A).
- `js/blind-reader.mjs` (new) + `publish.mjs`/bundle — the browser recover module (Phase B).
- A dispersal **policy** knob: which bodies get dispersed (all, or ≥ some size). Dispersal
  overhead is per-post (n shards + one custody intent), heavier than boxing — make it tunable.

**Do NOT touch (proven unnecessary):** `js/canon.js`, `js/gossip.js`, `js/verify.js`,
`js/model.js`. The `dispersal` field is admit-clean as-is (§2).

**Coordinate:** the ciphertext-off-VPS step (Phase D) is sequenced with spec #2 — don't
build a bespoke HiveRelay blob path here; reuse the migration's.

---

## 9. Test plan

- **Unit (offline):** extend the offline suite with a `dispersal`-bearing record → assert
  `expectedKey` unchanged, signature verifies, `admit()` accepts (mock cohort). Proves §2 in CI.
- **Live (node):** `scripts/seed-disperse.mjs` already proves disperse+recover of the real
  seed bodies against the cohort. Add a variant that also writes the ciphertext blob +
  `dispersal` onto a dev outbox and reads it back through the `data.js` read branch.
- **Browser reader:** a headless harness that loads `js/blind-reader.mjs`, points at the live
  cohort + a ciphertext blob, and reconstructs a seed body — the Phase-B gate.
- **Negative:** k-1 relays → read fails closed; tampered shard → rejected on content address;
  manifest stripped of a share → `INSUFFICIENT_SHARDS`.

---

## 10. Open questions for the data-model session

1. Dispersal policy: disperse **all** posts, or only bodies above a size threshold (like the
   `BOX_MIN_BYTES`=2048 gate)? Trade-off: per-post custody-intent overhead vs. uniform blindness.
2. Comments: same `dispersal` field on comment records (identical mechanics) — in scope for
   Phase A, or posts-first?
3. Interaction with the existing v2 seal: for a dispersed post, is the sealed body dropped at
   Phase C, or kept as a browser fallback indefinitely? (Recommend drop, once the browser
   reader is load-bearing.)
4. Roster pinning: where does the cohort roster live for the reader — extend `relay-roster.json`
   with a `shardCohort` block, or a separate pinned file? (Same Ed25519 trust anchor either way.)
