# BlindShard — Content-Blind, Erasure-Dispersed Bodies for a Public P2P Forum

**Status:** design, buildable. **Target:** peerit on `feat/web-deployment`, HiveRelay fleet.
**Author lens:** mafintosh smallest-primitive shape + DMC measurable/browser-portable surface, grafting Freenet (Clarke), Tahoe (Zooko), Storj, and Krawczyk-CSS/AONT-RS (Shamir/Rabin *composition*, not literal secret-sharing).

> **One-line honest thesis.** For a *public* forum the read key must reach every reader, so "blind" can never mean confidentiality. It means: **no single relay, at rest, holds anything readable, complete, or linkable to a post** — opaque AEAD ciphertext shards, no key, no manifest, fewer than K shards of any item. Reconstruction is possible only by a party who deliberately gathers K shards *plus* the public manifest — i.e. does exactly what a reader does. That is **non-readability-in-isolation + plausible deniability + "not the sole authoritative host,"** not cryptographic impossibility.

---

## 0. What the five lenses agreed on (and where they were wrong)

All five schemes (mafintosh/BlindShard, Zooko/Tahoe, Clarke/CHAFF, DMC, Shamir/Rabin) converged on the **same crypto pipeline** — convergent AEAD + K-of-N Reed-Solomon + off-relay signed manifest — and all five stress tests independently found the **same fatal architectural gap**:

- **`hiverelay/.../outbox-log.js:72,88` + `:62/:69`** — every append is signature-gated (`verifyOutboxRecordSignature`) and every group is `writerPublicKey: appId`. A shard **cannot** be an anonymous content-addressed blob dropped on an arbitrary relay; on the *current* surface it would have to be an author-signed record in the author's single outbox.
- **`js/gossip.js:664` + `:382`** — every write goes to `_myAppId() = getMe()` (author pubkey). **One outbox per author.** So manifest + key + all N shards land in the *same* group, replicated wholesale to every relay by `fanoutAppend`.
- **`js/relay-pool.js:118-122`** — `fanoutAppend` mirrors **every** op to **every** relay (`apis[i].sync.append(...).catch(()=>{})`). There is no per-shard placement primitive.
- **`js/gossip.js:95` + `js/canon.js:30`** — `admit()` rejects any row whose `expectedKey(type,val) !== key`, and `expectedKey` returns `null` for unknown types. "Zero canon changes" is false.

**Verdict inherited from the stress tests:** the *boxing* step (AEAD-encrypt the body, content-address the ciphertext, key in a signed manifest) composes cleanly and ships today. The *dispersal* step is real and worth doing but **requires one net-new relay surface** — a blind, content-addressed blob store decoupled from author identity — because the OutboxLog contract structurally cannot express "one shard per relay, no key co-located." This design does not paper over that: it isolates the new surface as the smallest possible primitive and ships value at every phase *before* it lands.

---

## 1. Recommended scheme — BlindShard

**Shape (winning pick):** Clarke/CHAFF's honest ceiling + Zooko/Tahoe's convergent-AEAD-then-erasure-code + Storj's repair-on-ciphertext + DMC's size-gate and bench discipline + mafintosh's "smallest composable primitive, opaque bytes, explicit teardown." The Shamir/Rabin contribution is the **Krawczyk-CSS/AONT-RS composition theorem** — *encrypt once, then disperse the ciphertext with an erasure code* — which is the formal license for using cheap Reed-Solomon (≈1.5×) instead of Shamir's `n/k` blowup that buys secrecy we don't need for public content.

### Grafts, by god/lens
| Idea | From |
|---|---|
| "Store content-hash-addressed blocks a node can't read; key/manifest live off the storing node" = plausible deniability | **Clarke / Freenet CHK** |
| Client-side convergent encryption; storage-index = hash-of-ciphertext; provider-independent security; dedup on a public corpus | **Zooko / Tahoe-LAFS** |
| Low-rate K-of-N Reed-Solomon (zfec GF(2⁸)); audit + **repair on ciphertext, never decrypt** | **Storj / Tahoe** |
| "Encrypt-once-then-erasure-code" is a *named, sound* construction; don't Shamir-split bulk data | **Krawczyk-CSS / AONT-RS (Shamir/Rabin composition)** |
| Smallest primitive, opaque bytes, one core per outbox, explicit `destroy()`/`unref()`, size-gate erasure to sizeable bodies only, **bench gate before any O(bytes) claim** | **mafintosh + DMC** |

### Pipeline (one paragraph)
On write, the client takes the post **body** (only bodies over a threshold — small votes/comments stay inline as today), derives `contentKey = SHA-256(body)` (convergent → free dedup, key needs no escrow), AEAD-encrypts to ciphertext `C = AES-256-GCM(body, contentKey, iv=SHA-256("bs-iv"‖contentKey)[:12])`, computes `blobId = SHA-256(C)`, Reed-Solomon-encodes `C` into **N shards (any K reconstruct)**, seeds the **full `C` to its own device cache first** (the durable authoritative copy), disperses shards to opted-in relays via the new blind blob surface (Phase 3) — or, pre-dispersal, plain-replicates `C` as one blob (Phase 2) — then publishes a **signed manifest** `{blobId, contentKey, k, n, shardIds[], digest, alg}` into its normal outbox record (covered by the existing Ed25519 signature, `canon.js` `stable()`). A reader range-scans the feed (manifests are cleartext, so the feed still works), verifies the manifest signature (`verify.js`), gathers **K shards by content hash across the pool**, checks each shard's `SHA-256 == shardId` (self-verifying — a relay can't substitute), RS-reconstructs `C`, checks `SHA-256(C) == blobId`, AES-GCM-decrypts with `contentKey`, and finally checks `SHA-256(plaintext) == contentKey` (convergent self-check — closes any substitution gap for free). Missing/withholding relay → route to the next K candidates via the existing `recoverRows` failover.

### ASCII sketch
```
AUTHOR (browser)                                    OPTED-IN RELAY POOL              READER (browser)
───────────────                                     ───────────────────              ────────────────
body P
  │  contentKey = SHA-256(P)          [convergent, Tahoe]
  │  C = AES-256-GCM(P, contentKey)   [SubtleCrypto, native]
  │  blobId = SHA-256(C)              [Freenet CHK content-addr]
  ├──► seed FULL C to own device cache  ◄── PRIMARY SEEDER, survives relay wipe (gossip.js floor)
  │
  │  RS-encode C ─► shard[0..N-1], shardId_i = SHA-256(shard_i)   [zfec GF(2^8), Storj]
  │        │
  │        └─ disperse ─►  Relay A: {shard 0, 3}   ┐  each relay holds < K shards,
  │                        Relay B: {shard 1, 4}   ├─ NO key, NO manifest, NO linkage
  │                        Relay C: {shard 2, 5}   ┘  = opaque bytes, indistinguishable from random
  │
  └─ publish SIGNED MANIFEST into OUTBOX (Ed25519, canon.js) ─────────────────────►  range-scan feed
        {blobId, contentKey, k, n, shardIds[], digest}   ▲                             │ verify sig (verify.js)
        contentKey PUBLIC by design ── never on a storage relay's blob surface        │ gather ANY K shards
                                                          │                            │ hash-check each shard
                                                          └────── K shards ────────────┤ RS-reconstruct C
                                                                                       │ blobId == SHA-256(C)?
                                                                                       │ AES-GCM decrypt
                                                                                       └ SHA-256(P)==contentKey?
```
**Key separation invariant (load-bearing):** the manifest (which carries `contentKey` + `shardIds`) lives on the **outbox surface**; the shards live on the **blob surface**. A relay that stores blobs holds ciphertext with no key and no linkage; a relay that mirrors the outbox holds the manifest but no shards. **If the same relay holds both the manifest AND ≥K shards of an item, blindness collapses for that item** — so placement must keep manifest-holders and shard-holders separated, and cap any relay at `< K` shards. This invariant is client-enforced and auditable; a fully colluding roster defeats it (§6).

---

## 2. What it changes for the owner's liability

### Today (baseline)
The VPS stores **readable signed JSON** — `post!<community>!<cid> = { body: "<plaintext markdown>", ... }`. A `grep` over the OutboxLog groups yields every post body in the clear, linked to author pubkey, community, and timestamp. The operator is the sole authoritative host of readable content on one seizable box. Maximum personal liability.

### With BlindShard (Phase 2 boxing → Phase 3 dispersal)
**What the VPS ends up holding:**
- **Phase 2 (boxing):** opaque AEAD ciphertext blobs `blob!<blobId> = <random-looking bytes>` instead of readable JSON bodies. No plaintext in the keyspace. The relay still co-holds the manifest (with the key) in the author outbox, so a *motivated* operator decrypts trivially — but a `grep` no longer yields plaintext, and dedup shrinks the corpus.
- **Phase 3 (dispersal, new blob surface):** a bag of `shard:<shardId> → opaque ciphertext`, **fewer than K shards of any item**, **no `contentKey`, no manifest, no shard→post linkage** (the shard surface is keyed by hash-of-ciphertext and is *decoupled from author identity*, so it is not in any author's enumerable outbox).

**What the operator CAN do (disclosed, honestly):**
- Read the cleartext **manifest metadata** if it also mirrors outboxes: record type, per-record `id`, **author pubkey**, community, timestamps → the **who-posted-what social graph still leaks** (`gossip.js` keys are `type!id`, `op.data.id` is cleartext by construction). BlindShard hides **bodies**, not associations.
- See shard sizes, request timing, peer pubkeys. **No anonymity** is claimed (`CRYPTO-GUARANTEES.md:262-274`).
- **Act as a reader** — fetch the public manifest and gather K shards from across the pool and reconstruct. This is the honest ceiling (below).

**What the operator CANNOT do passively, at rest, holding only its blob disk:**
- Read a shard (AES-GCM ciphertext, no key on the blob surface).
- Tell which post a `shard:<hash>` belongs to (linkage lives only in the off-surface manifest; `shardId = SHA-256(ciphertext)` reveals nothing).
- Reassemble an item (holds `< K` shards).
- Forge/substitute/silently corrupt (content-addressing + the author's Ed25519 manifest make tampering self-detecting client-side — a bad shard fails its `shardId` hash and the reader routes around it, reusing `relay-pool.js:82-91 recoverRows`).

**Plausible-deniability story (defensible, non-magical):** *"I run an opt-in availability relay. Under `shard:*` I hold content-hash-addressed opaque bytes I cannot decrypt (no keys), cannot attribute to any post or user (no manifest; the id is a hash of the bytes), and cannot reassemble alone (I never hold enough fragments of any one item). Reconstructing anything requires deliberately fetching the public manifest AND collecting K fragments from OTHER operators — an affirmative act against the whole network, not something my disk does at rest."* This is the **Freenet-CHK grade** posture: liability shrinks from *"I host this user's readable post"* to *"I host meaningless, incomplete, encrypted fragments,"* and selective censorship-by-meaning is impossible because the relay has no content index.

### The HONEST LIMIT — do not market this away
- **Public content is reconstructable by a determined party.** `contentKey` is published in the manifest to every reader, and the operator is a reader. This is **non-readability-in-isolation + deniability + "not the sole/authoritative host,"** **NOT** cryptographic secrecy. Any UI copy saying "the operator can't read your posts" is a **lie** and is forbidden (`HIVERELAY-OUTBOXLOG-PLAN.md:56-59`: *"A public forum cannot be operator-blind."*).
- **Convergent encryption leaks equality / confirmation-of-file.** An adversary who guesses a body can confirm it's stored by matching `blobId`. Acceptable for a *public* forum (content is world-readable anyway) but stated plainly.
- **Metadata/social graph is fully visible** regardless of sharding.
- **In Phase 2, before the new blob surface exists, a single relay co-holds the manifest+key+blob** and is a full reader — Phase 2's honest win is only "ciphertext-at-rest, not casually grep-able," not dispersal.

---

## 3. How it meets the three goals

### (a) Dispersed — no single relay has readable/complete content
Achieved **only in Phase 3** and **only on the new blob surface**. K-of-N Reed-Solomon + HRW/rendezvous placement (`place(shardId) = roster.sortBy(r => SHA-256(r.pub‖shardId)).slice(0,R)`) so each relay is assigned `< K` shards of any item, deterministically recomputable by any reader with the signed roster. **The blob surface must be author-decoupled** (a content-addressed `shard:<hash>` namespace, *not* gated by `data._k === appId`) — this is the one net-new relay capability, because the current OutboxLog surface (`outbox-log.js:88`) rejects anonymous blobs and forces everything into the author's single outbox. Until Phase 3, Phase 2 gives "no plaintext at rest" but **not** dispersal (single relay still co-holds a whole boxed body + the key).

### (b) Browser-feasible — crypto, lib, costs
- **AEAD + hashing:** `AES-256-GCM` + `SHA-256` via **SubtleCrypto** — already proven in-tree (`js/identity-export.js:97` ships AES-GCM with a random 12-byte IV; `js/crypto.js` ships SubtleCrypto SHA-256/Ed25519). Hardware-accelerated (AES-NI). Encrypting/hashing a ≤40 KB body is **sub-millisecond**, dwarfed by the existing per-post `2^16` proof-of-work (`js/pow.js`). **No new crypto dependency** for boxing.
  - *Two real gaps to close (from stress tests):* `js/crypto.js:20` `hashHex` is UTF-8/**string-only** — content-addressing needs a **bytes-in** SHA-256 path (small new function). And `identity-export.js:97` uses a **random** IV; BlindShard's convergent `iv=SHA-256("bs-iv"‖contentKey)[:12]` is deterministic AES-GCM — safe *only because* key==f(P) and nonce==f(P) so a fixed key never encrypts two plaintexts, but it is a **new construction**, not the proven one; unit-test it against vectors.
- **Erasure code:** the **only new dependency** — a small WASM Reed-Solomon GF(2⁸) module (`reed-solomon-erasure`/zfec-style, ~30–60 KB gz). For ≤40 KB bodies at K=6/N=9 encode/decode is **single-digit ms**. **Systematic RS** means the happy path (all K data shards present) is a **concat, no Galois-field math**. **Gate erasure to sizeable bodies only** (≥ ~8 KB); votes/short comments/manifests stay inline. Run media-sized encodes in a **Web Worker**, off the render loop (DMC).
  - CSP: WASM needs `wasm-unsafe-eval` and `ws:/wss:` in `connect-src` — **already required** by the Holepunch DHT path (`build-web.mjs` CSP), so **no new CSP surface**.
- **Transport encoding cost:** OutboxLog caps values at **64 KiB** (`outbox-log.js:20 DEFAULT_MAX_VALUE_BYTES = 64*1024`) and `pear-api` JSON-stringifies ops, so binary must be **base64 (×1.33)** — the real plain-blob ceiling is ~48 KiB, forcing chunking/coding earlier than a naive "64 KiB plain band."
- **Latency shape:** feed render needs **zero** shard fetches (bodies hydrate lazily on open) → boot/scroll hot path unchanged. A cold body read is up to **K parallel gets** + optional decode. Re-reads are free from the durable device cache.

### (c) Survives churn — K-of-N + device seeding floor + repair
- **User devices are the primary seeders**, relays are best-effort amplifiers. The durable localStorage cache + **monotonic signed-head floor** already survive relay wipes and all-relay collusion (`js/gossip.js:438 _loadCache`, `:476 _loadFloor`, `:579`). The author's device holds the **full plaintext** and can re-encode all N shards deterministically (convergent). This is the **true durability floor** — 1× on the author's device — independent of relays.
- **K-of-N math:** K=6/N=9 → ~1.5× blowup, tolerates **3 shard losses**; **servers-of-happiness** (Tahoe's lesson) is the correct unit — the K shards must land on **K distinct relays**, not merely K shard-slots, or the fault tolerance is illusory.
- **Repair (Storj/Tahoe pattern, client-driven, relay stays blind):** a reader that gathers K shards re-encodes the missing `N−K` and re-uploads them — operating on **ciphertext**, never decrypting to repair. Triggered by the existing shortfall detection in `recoverRows`.
- **Honest durability caveat:** `fanoutAppend` is **fire-and-forget** (`relay-pool.js:120 .catch(()=>{})`), so placement is **unacknowledged** and survival is **probabilistic** until **signed custody receipts** (Phase 4) make "relay holds shard i" acknowledged rather than assumed. Until then the device cache is the real backstop.

---

## 4. Reuse vs net-new

### Rides on existing infra (reuse — mafintosh "store adds nothing to transport")
| Existing asset | Role in BlindShard | Evidence |
|---|---|---|
| Ed25519 signed-envelope + `canon.js stable()` auto-signs every data field | Manifest `{blobId, contentKey, k, n, shardIds}` rides the **existing** signature — no new signing path | `js/canon.js:41-51`, `js/data.js:664` |
| `verify.js verifyRecord` (signer==author, domain-pinned) | Manifest authenticity; relay has **zero** write authority over shards | `js/verify.js:24-36` |
| `relay-pool.js recoverRows/crossRows/crossHead` | Gather-across-untrusted-pool + route-around-withholder → generalize census-root-match to **shard-hash-match** | `js/relay-pool.js:82-91` |
| `relay-pool.js fanoutAppend` | Mirrors manifest + (Phase 2) plain blobs to every relay | `js/relay-pool.js:118-122` |
| `crypto.js` SubtleCrypto SHA-256/Ed25519 + `identity-export.js` AES-GCM | Boxing crypto, **no new dep** | `js/crypto.js`, `js/identity-export.js:97` |
| `gossip.js` durable cache + monotonic head-floor | User devices as primary seeders; source for client-driven repair | `js/gossip.js:438,476,579` |
| HiveRelay OutboxLog opaque-value + 64 KiB caps | Manifest is a normal single-writer outbox record; (Phase 2) boxed body is an opaque value | `outbox-log.js:20,72` |
| HiveRelay `custody-signing.js` `FORBIDDEN_KEYS` allow-list | Relay-side reject of any append carrying `plaintext/contentKey/dataKey/decryptionKey` — proves key and blob never co-located | `custody-signing.js:10-32` |
| HiveRelay `dht-relay-ws` Noise transport | Shard seeding peer-to-peer over the browser-reachable WSS DHT pipe | `dht-relay-ws/index.js` |
| `pow.js` validate-hook | Gate shard/blob writes with the same hashcash to prevent open-write DoS | `js/pow.js:80-87` |

### Net-new pieces (kept as small as possible)
1. **`js/box.js`** (Phase 2, pure SubtleCrypto, ~40 LOC): `box(P) → {C, contentKey, iv, blobId}`, `unbox(C, contentKey, iv) → P`; convergent AES-GCM + **bytes-in** SHA-256. Unit-tested against vectors. **No dep.**
2. **`hashBytes()`** in `crypto.js`: the bytes-in SHA-256 the string-only `hashHex` lacks (`crypto.js:20`).
3. **Manifest record type** + canon wiring: new `expectedKey`/`ownerOf` cases so `admit()` accepts it (`gossip.js:95`, `canon.js:30`) — **this contradicts "zero canon changes"; it is a small, real change.** `contentKey`/`shardIds` are **public by design** and must **NOT** be added to relay `FORBIDDEN_KEYS`.
4. **`js/shard.js`** (Phase 3): thin wrapper over the WASM RS module — `encode(C,k,n)→shards`, `decode(shards,k,n)→C`, `shardId=SHA-256(shard)`. **The one new dependency.**
5. **New blind blob surface on HiveRelay** (Phase 3, the heavy net-new): a content-addressed `shard:<hash>` PUT/GET route **decoupled from `data._k===appId`**, reachable over WSS, so shards are anonymous blobs not gated into an author outbox. *This is the piece every stress test flagged as impossible on the current OutboxLog contract.* Optionally reuse HiveRelay's existing **native-swarm Hypercore custody/seeding pipeline** (`custody-signing.js` already defines `blindContentId`, `ciphertextRoot`, `shardIds`, `requiredReplicas`, `storageCommitment`) rather than re-deriving a weaker one — **prefer routing large/durable content through the existing blind-custody protocol over building a parallel one.**
6. **`place()` HRW placement helper** (Phase 3, pure, unit-testable): deterministic shard→relay assignment with the `< K per relay` + manifest/shard-disjoint invariant.
7. **`repair()` pass** (Phase 4): probe shortfall, re-encode from cached plaintext/K shards, re-place missing shards.
8. **Signed custody-receipt quorum** (Phase 4): reuse HiveRelay `custody-intent/custody-receipt` so placement is acknowledged, not fire-and-forget (`relay-pool.js:120`).

---

## 5. Phased roadmap (smallest first step first)

Each phase is independently shippable and independently valuable. **Ship the honest, modest win first; treat dispersal as the phase that needs new relay infra.**

### 5.0 Revised sequencing (2026-07-02, after a multi-model review)

A strategic review (Opus + a Fable panel: strategist / red-team / dmc-revisit) reached one blunt conclusion: **boxing bodies (Phase 2) has ~zero standalone liability value** — the same relay co-holds the key, so a court sees "possession + ability to control," and the size gate is *anti-correlated* with risk (short-form defamation/threats/links/comments stay plaintext while long essays get boxed). Phase 2 is correct **engineering scaffolding for Phase 3**, not a G1/G2 win, and must not be marketed as one. The highest-leverage moves are cheaper and mostly unblocked, so the post-Phase-2 order is:

| # | Move | Why it beats more crypto | Status |
|---|---|---|---|
| **2a** | **Relay-side DO-NOT-SERVE / takedown** ([`RELAY-TAKEDOWN-SPEC.md`](RELAY-TAKEDOWN-SPEC.md)) | Safe harbor is *conditioned* on responding to notice; today the relay holds everything but can remove nothing (append-only, author-only tombstones). Serve-time suppression + notice channel + agent + ToS is the single biggest G1 lever. Unblocked (own relay). Composes with the withholding audit (a takedown *is* visible withholding — route to another relay). | SPEC — needs greenlight to touch the live relay |
| **2b** | **Signed-release trust chain** (dmc-adapt) — `js/release-verify.js`, `scripts/sign-release.mjs`, `pinnedReleaseKey`, verify.html signature check | Ed25519-sign `asset-manifest.json` with an OFFLINE key so mirrors/auditors/verify.html confirm a bundle is authentic **without trusting the origin**. Adapts dmc's real intent (verify code against a pinned key). Honest ceiling: web self-verification is circular (origin serves the verifier); the durable win is EXTERNAL verification + trustworthy self-host/mirror. | **BUILT (2026-07-02)** |
| **2c** | **Recruit ONE arms-length independent relay operator** ([`RELAY-OPERATOR-RECRUITMENT.md`](RELAY-OPERATOR-RECRUITMENT.md)) | Both roster relays are one legal person → every collusion-threshold / `<K`-per-relay / paid-fleet claim is **vacuous** ("one subpoena covers both"). Social, not code; has lead time → start now. Phase 3 dispersal needs ≥3 (ideally ≥6, per K=6/N=9) independent operators. | TODO (social) |
| **2d** | **Box coverage**: lower floor + box comments; name titles+graph as permanent plaintext | Moves the content classes that actually carry risk into ciphertext-at-rest — but still **scaffolding, not a standalone win** (relay co-holds the key until Phase 3). | Deferred (cheap follow-up) |
| **2e** | **Entry-point hardening**: verify the IPFS/ENS static-JS mirror is actually live; multi-home the roster URL | Cheapest G4 win; today these are checklist claims, not facts. | TODO |

**Reframes:** Phase 3 dispersal stays HELD and is now explicitly **gated on ≥3 independent relays** (dispersal before independence is theater). Phase 5's "north star" is **reframed, not built**: `hyper://` in PearBrowser already serves nothing (content-addressed, zero origin) — push it as the recommended trust tier rather than sinking effort into the do-not-use-in-prod `dht-relay-ws`. **dmc's `data:` URL is DROPPED as a product** (its intent is absorbed by 2b); the scope doc remains the decision record.

**Do NOT:** market Phase 2 as blindness; claim "the operator can't read your posts" (forbidden — inducement trap); promise graph privacy (titles + `type!id` + author pubkeys are cleartext by construction — hiding them is a ground-up key-scheme redesign, out of scope); or count two same-owner relays as a fleet.

### Phase 0 — Populate the roster (prerequisite, no crypto)
The censorship-resistance machinery already exists but is **dormant**: `relay-roster.js` verifies an untrusted roster against a pinned Ed25519 key, and `relay-pool.js` does cross-relay reconciliation — but the roster lists **one** relay today, so every cross-relay defense (and any dispersal) is inert. **Populate a real 2–3 relay roster** (VPS primary + opted-in HiveRelay #2/#3), inline the signed roster+pin into `index.html` at build time. *No dispersal is possible without ≥N independent relays.* (`HIVERELAY-OUTBOXLOG-PLAN.md:52-53`.)

### Phase 1 — Deploy OutboxLog write-time verification
Land OutboxLog (`outbox-log.js`, already ported + tested) on the fleet so the relay verifies the **signed envelope** on write (`verifyOutboxRecordSignature:88`) — it verifies envelope fields, **never the (encrypted) body**, preserving the opaque-payload property. Gate: golden-transcript conformance test (unmodified peerit reader converges through OutboxLog).

### Phase 2 — SMALLEST FIRST STEP: box-before-store (relay stops holding plaintext) — **BUILT (2026-07-02)**
Ship **`js/box.js`** (pure SubtleCrypto, no new dep, no erasure, no new relay surface) and wire **one** record type (long post bodies over ~2 KB):
- **Write:** if `body > threshold`, replace inline `body` with the opaque ciphertext `C` stored as `blob!<blobId>` via the **existing** `fanoutAppend`, and put `{blobId, contentKey, iv, digest}` in the **signed** manifest field (spanned by `canon.js stable()` — no new signing path). Add `hashBytes()` and the manifest `expectedKey`/`ownerOf` cases.
- **Read:** fetch `blob!<blobId>`, assert `SHA-256(C)==blobId`, AES-GCM-decrypt, assert `SHA-256(P)==contentKey`.
- **Value delivered:** the relay's keyspace no longer contains grep-able plaintext bodies; dedup for free; end-to-end proof of the box→append→fetch→unbox loop through the real relay. **Honestly scoped:** "ciphertext-at-rest, not casually readable" — **NOT** dispersal, **NOT** operator-blind (single relay still co-holds manifest+key+blob).
- **Gate:** golden-transcript roundtrip test; bench encrypt/decrypt latency on representative bodies.
- **AS BUILT:** `js/blob-store.js` (glue + `verifyBlobRecord`), boxing in `data.js` submit/edit/delete, transparent hydration in `getPost`/`listPostsIn`, `blob` type in `model.js`/`canon.js`, band `[2048, 34000]` bytes (base64 stays under the ~64 KiB value cap), `canBox()` degrades to inline plaintext without SubtleCrypto. Blobs are **first-class signed records** (own PoW tier `blob:12`) admitted through the real merge — with a **self-certification gate in `gossip.js admit()`** (`SHA-256(ct)==blobId`) so a foreign record cannot win the LWW collision at the content-addressed key and suppress a body. Tests: `test/blob-integration.mjs`.
- **KNOWN LIMIT (orphan blobs, LOW):** the append-only log has no delete and blob rows are content-addressed + convergent, so a deleted/shrunk post's `blob!<blobId>` row persists and stays counted in the signed-head census; `head.count` grows monotonically. This is **amplification-only** — counted symmetrically by the producer (`_maintainHead`) and auditor (`auditOutbox`), so it can never cause a false or masked withholding flag. A future GC pass (or a `deleted`-blob carve-out in the ct gate) could reclaim orphaned bodies; deferred.

### Phase 3 — Dispersal (the net-new relay surface + erasure)
1. Add the **blind blob surface** to HiveRelay: content-addressed `shard:<hash>` PUT/GET over WSS, **decoupled from `data._k===appId`**, with the `FORBIDDEN_KEYS` reject on any op carrying `contentKey`/plaintext. *Prefer wiring into the existing native-swarm custody pipeline (`custody-signing.js`) over a parallel store.*
2. Ship **`js/shard.js`** (WASM RS) + **`place()`** HRW placement. Swap Phase 2's "store 1 blob" for "RS-encode to N shards, disperse `< K` per relay across the roster." Manifest gains `{k, n, shardIds[]}`.
3. **Read:** gather any K shards by hash across the pool (generalize `recoverRows`), hash-check, RS-decode, decrypt, self-check.
4. **Value delivered:** true dispersal — no single relay holds a readable/complete/linkable item. **Gate:** bench K-shard fan-out p50/p95, encode/decode ms per size bucket, servers-of-happiness placement assertion, memory ceiling; do **not** claim O(bytes) scaling without the transcript (DMC).

### Phase 4 — Durability teeth: repair + custody receipts + incentives
- **`repair()`** pass: client-driven re-encode-and-re-place of missing shards on ciphertext (never decrypt).
- **Signed custody-receipt quorum** (reuse `custody-intent/custody-receipt`): author treats a body durable only once a threshold of independent, roster-verified receipts is collected — turns fire-and-forget (`relay-pool.js:120`) into acknowledged placement.
- **Optional custody-proof** (challenge-response PoR) to detect a lying relay, extending peerit's signed-head withholding detection to shards.
- **Incentives:** opted-in HiveRelay operators are volunteers; the receipt/PoR layer is what lets a "durable" claim be honest and lets the roster prune non-serving relays. **The moment operators are *paid*, the payout model itself becomes load-bearing for their liability** — content-neutral metering, drop-by-opaque-id takedown, and the `< K`-per-relay cap as a legal invariant. See [`OPERATOR-LIABILITY.md`](OPERATOR-LIABILITY.md).

### Phase 5 — NORTH STAR: your box serves nothing (pure-pipe + reader-side aggregation)
The end state that answers *"am I still aggregating and serving content?"* with **no**. The interim phases keep an `/api` relay that aggregates every outbox and answers feed queries — BlindShard blinds the *bodies* but that relay is still a content-serving index. Two moves dissolve that role entirely:
1. **Move your box from an `/api` relay to a pure `dht-relay-ws` byte-pipe.** On the in-browser DHT path (`js/dht-transport.js` + `deploy/dht-relay/`), the *reader's browser* runs a **real HyperDHT node** and does its **own** aggregation — discovering authors, pulling K shards from the blind-seeder fleet, reassembling locally. The relay carries only Noise-encrypted frames; it **stores nothing and serves nothing at rest**. The server-side "aggregate every outbox + answer feed queries" job moves *into each reader's device* (which is just reading, not hosting).
2. **Durable storage lives on the opt-in HiveRelay blind-seeder fleet + user devices**, holding blind erasure shards (Phase 3) — never on your box. Your VPS becomes *one optional pure pipe among many*, or you run none and lean on the fleet's `dht-relay-ws` endpoints.

**Result: no operator — including you — aggregates or serves readable or complete content.** The only thing anyone holds at rest is blind, incomplete, content-hashed fragments; the only thing your box does is transport ciphertext frames between peers who chose to be online. This is "use the HiveRelay network as *relays, not standalones*" taken to its logical end.

**The ladder:** Phase 2 (store ciphertext) → Phase 3 (store blind fragments) → **Phase 5 (store/serve nothing — pure pipe)**. Each rung strictly shrinks what your box holds and can be blamed for.

**Honest cost:** you trade self-hosted durability *control* for *dependence on the fleet being populated* (enough independent blind-seeders + `dht-relay-ws` endpoints, per Phase 4's custody receipts to make "durable" honest). Until that fleet is real, the `/api`-relay + boxing (Phases 2–3) is the interim that ships value on infra you control.

---

## 6. Open risks / honest limits (from the stress tests — not blended away)

1. **Public-content deniability ceiling (permanent).** `contentKey` ships to every reader; the operator is a reader. BlindShard delivers **non-readability-in-isolation + deniability + "not the sole authoritative host,"** never confidentiality. A determined operator-as-collector fetches the manifest + K shards and reconstructs, exactly as any reader does. **Market it as such or it overclaims.** (`HIVERELAY-OUTBOXLOG-PLAN.md:56-59`, `CRYPTO-GUARANTEES.md:262-274`.)
2. **Relay-collusion threshold.** The `< K per relay` and manifest/shard-disjoint invariants are **client-enforced at write** and auditable, but a **fully colluding roster** (or one relay mis-assigned ≥K shards + the manifest) reconstructs everything. Blindness holds against **independent** relays, not a colluding pool. Placement must be independently auditable; report this in the threat-model doc.
3. **Metadata / social-graph leak (structural).** Keys are `type!id`; `op.data.id` + author pubkey are cleartext by construction (`canon.js`, `gossip.js`). Sharding hides **bodies only**. Hiding who-posted-what needs encrypted keys, which breaks the range-query feed — an **out-of-scope ground-up redesign**.
4. **Storage blowup + transport inflation.** K=6/N=9 ≈ **1.5×** for sharded bodies; convergent dedup claws some back on reposts. Base64-in-JSON adds **×1.33** on top and drops the real per-value ceiling to ~48 KiB (`outbox-log.js:20`), forcing chunking earlier than the naive plan. Small records pay **0×** (stay inline) — deliberate, to keep the hot path free.
5. **Retrieval latency + request amplification.** A write is N shard-writes + 1 manifest; a cold body read is up to K parallel gets + optional decode, vs one get today. Mitigated by lazy body hydration (feed untouched), systematic RS (no decode on the happy path), device cache, and the ≥8 KB size gate — but it is strictly more chatter and **must be bench-gated** (DMC).
6. **Browser CPU / new dependency / CSP.** AES-GCM+SHA-256 are free; the WASM RS module adds bundle weight + relies on `wasm-unsafe-eval` (already in CSP for the DHT path). Media-sized encode must run in a Web Worker, never on the render loop. New failure mode: RS-wasm blocked → fall back to Phase-2 plain-boxed bodies (lose dispersal, keep at-rest opacity).
7. **Durability is probabilistic until Phase 4.** `fanoutAppend` fire-and-forget (`relay-pool.js:120`) gives no quorum receipt; K-of-N only helps if ≥K shards on **independent** providers actually persist. The user-device seeding floor is the true backstop until custody receipts land. "Durable" before Phase 4 is an overclaim.
8. **The new blob surface is real net-new infra, not verbatim reuse.** Every stress test found that the browser-facing OutboxLog surface **structurally rejects** anonymous content-addressed shards (`outbox-log.js:88`, single-writer `_k===appId`), and `fanoutAppend` fans everything to everyone (`relay-pool.js:118-122`). Phase 3 requires a genuinely new blind blob endpoint (or routing through HiveRelay's existing native-swarm custody pipeline). **Do not frame Phase 3 as low-cost reuse.**
9. **Entry-point blocking is unaddressed by any of this.** Sharding resists relay **seizure/reading**, not **blocking** of the single-origin roster URL + JS bundle. Needs the inlined signed roster/pin (Phase 0) plus a bundle-distribution story (IPFS/mirrors/extension). **Never claim impunity.**
10. **Two crypto-surface fixes are prerequisites, not free reuse.** `hashHex` is string-only → need `hashBytes()`; the convergent deterministic-IV AES-GCM is a **new construction** vs the proven random-IV path (`identity-export.js:97`) — safe under convergent keying but must be vector-tested.

---

## TL;DR for the owner
- **Today:** your VPS holds every post as readable plaintext on one seizable box. Maximum liability.
- **Phase 2 (ship first, ~days, no new deps/infra):** the relay holds AES-GCM ciphertext blobs instead of readable JSON. A grep yields nothing; dedup shrinks storage. **Honest claim: "encrypted at rest, not casually readable"** — not yet dispersal.
- **Phase 3 (needs one new blind blob surface on your HiveRelay fleet):** content is erasure-coded so **no single relay holds a readable, complete, or linkable item** — opaque incomplete fragments, no keys, no manifest. **Honest claim: "I store meaningless incomplete encrypted fragments I can't read, link, or reassemble alone."**
- **⭐ Phase 5 (north star): your box serves *nothing*.** It becomes a pure `dht-relay-ws` byte-pipe; the reader's browser aggregates for itself over a real in-browser DHT; the blind-seeder fleet + user devices hold the fragments. **Honest claim: "I transport ciphertext frames between online peers; I store and serve no content at rest — the network's blind seeders do, in fragments none can read."**
- **The permanent limit you must say out loud:** because the forum is *public*, a determined party (including you acting as a reader) can still fetch the public manifest and gather K fragments and reconstruct. This shrinks your **passive, at-rest, sole-host** liability and gives **plausible deniability** — it does **not** make public posts secret, and it does **not** hide who-posted-what.
