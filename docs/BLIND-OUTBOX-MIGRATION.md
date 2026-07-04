# BLIND-OUTBOX-MIGRATION — Opaque-Log v2 for peerit

**Status:** implementation **LIVE** — the Opaque-Log v2 write/read paths are wired in `js/data.js`,
`js/seal.js` + `js/canon.js` provide the blind-key primitives (`okey` + sealed envelope), and the
live seed outbox on peerit-relay is already opaque (verified by `test/live-v2-decrypt.mjs`). This
document is retained as the design record and migration notes; the phased-migration decisions
above (D1–D7) have been executed.

> **RESOLVED DECISIONS (2026-07-03) — these OVERRIDE the §9 recommendations where they differ:**
> - **D1 → app-wide read key.** One bundled `PEERIT_READ_KEY`; all content public; private groups are a later additive layer.
> - **D4 → CLEAN CUTOVER + reseed (NOT dual-read).** Live content is sparse + already-wiped + reseedable, so we orphan v1 and rebuild v2 clean rather than carry a dual-read admit branch. This SIMPLIFIES §7 (no v1/v2 coexistence, no census union/tombstone (D6), no v2-capable fleet gating) — at the cost of abandoning any un-reseeded historical record.
> - **D7 → move to HiveRelay OutboxLog transport.** **KEY FINDING (contract map): OutboxLog does NOT itself blind anything** — it is a wire-compat KV port that PRESERVES plaintext keys; it merely PERMITS opaque ones. Its *blind namespace is FORBIDDEN for public content* (read key reaches every reader) and requires a `{sealed}` body shape, so peerit uses the **non-blind `peerit` namespace** and seals client-side. Moving to it BUYS server-side Ed25519 verification (closes a forged-writer gap) + it's the ecosystem direction + peerit's envelope is already byte-identical. **The blindness is 100% the client v2 change below; the transport swap is additive.** A takedown-by-opaque-id primitive is NOT shipped by OutboxLog and must be added (D8).
> - Engineering calls made (not user-facing): D2 keep `crk` as a private-group hook; D3 keep the ≥2 KiB body-box threshold; D5 ship the `members` roster with the write phase.

**Goal.** Today peerit stores each record under a **plaintext semantic key** — `post!<community>!<cid>`, `vote!<targetCid>!<author>`, `comment!<community>!<postCid>!<cid>`, `profile!<author>`, `community!<slug>`, `modaction!<community>!<actionId>`, `head!<author>` — and the relay answers **prefix/range** queries on them. So an operator can passively `grep` the entire who-posted-what-voted-where social graph *and* short bodies at rest. This is the "readable host = maximum liability" position (`docs/OPERATOR-LIABILITY.md`, `docs/BLINDSHARD-DESIGN.md` §2). This spec **kills the plaintext keys**: the relay holds opaque bytes under opaque keys, and feed/thread/tally aggregation moves into the browser.

---

## 1. The honest ceiling (FORBIDDEN to overclaim)

A **public** forum's read material must reach *every* reader. The network read key ships to every client — **including any client the operator runs**. Therefore:

> **It is FORBIDDEN to claim "the operator can't read your posts."** The operator IS a reader. It holds the network read key and the convergent content keys and can affirmatively decrypt and reconstruct any public post.

**What v2 actually delivers** (and the only things it delivers):

| Win | Precise statement |
|---|---|
| No passive grep of bodies at rest | Bodies are ciphertext (`blob!<blobId>`); the operator holds no plaintext body in the ordinary course of storage. |
| No semantic index / no passive enumeration | Keys are opaque 64-hex; the relay cannot answer "list all posts in r/x" or "who voted on Y across unknown voters" by prefix/range. It must pull every outbox and run the *client* pipeline. |
| Content-neutral storage | The relay stores and prices opaque cells; nothing at rest is content-derived or content-selected. |
| Drop-by-opaque-id takedown | An operator can drop `v2!<okey>` by exact opaque id without reading it (content-neutral removal). |

Together these break the **knowledge / control / attributable-benefit** liability prongs (`OPERATOR-LIABILITY.md` §1–2): *in the ordinary course of storage the operator perceives nothing and must take affirmative, non-ordinary steps (run the client, derive keys) to read or index.*

**What v2 does NOT deliver — write these words, not softer ones:**

- **NOT secrecy / confidentiality.** Public content is world-readable by design.
- **NOT anonymity.** The author pubkey set is permanently enumerable via `/api/directory` (`appId === author pubkey`).
- **NOT metadata-blindness.** Per-author record **count**, append **cadence/version**, per-record **byte size** (type-mix), community **names** (dictionary-reversible slugs), and **read-side pull patterns + IP** all leak. See §6.
- **NOT infeasible targeted confirmation.** Because the read key is public and semantic ids are guessable, an operator CAN answer "did Alice vote on known-post P?" with an O(1) point lookup. The no-index win is about **enumeration**, not **confirmation**. See §6.

Doctrinal anchor phrase (use verbatim in product copy): *"In the ordinary course, the operator holds and serves nothing readable and must affirmatively reconstruct to read."* Never "the index does not exist" or "the operator cannot build the graph."

---

## 2. The blind record model

### 2.1 Two opacity layers

1. **KEY-opacity (primary liability win, on every record).** The storage key becomes `v2!<okey>`, a `v2!` version prefix + an opaque 64-hex `okey`. No semantic scope survives, so prefix/range yields nothing.
2. **VALUE-opacity for bodies (reuses the shipped convergent AEAD `box.js`).** Every user-text field is boxed under `contentKey = SHA-256(plaintext)` with the derived IV (`box.js`, KAT-pinned) and stored as `blob!<blobId>` (`blobId = SHA-256(ct)`), self-certified by the already-wired `verifyBlobRecord`.

**Structural fields stay in a signed cleartext envelope.** Fields the client needs *before* a body decrypt — `_t` (type), `createdAt`, `ts`, vote `value`, `deleted`, `parentCid`, `community`, `targetCid`, `slug`, `author` — live in the value **in cleartext**, signed but not body-encrypted. Keeping them **out of the key** is what kills the semantic index while letting ranking/threading/tally run without a body decrypt. They still leak to a reader (and the operator-as-reader); the win is only that they are not passively greppable/prefix-indexable.

> **DECISION on body-boxing threshold (see §9-D3).** The synthesis originally proposed "box ALL text." The stress-test refuted this: for short/low-entropy bodies, convergent encryption is trivially confirmable-by-guess (identical short comments → identical `blobId`), it adds a `_blobMissing` failure surface, and it kills search-for-free — for **zero** liability benefit (KEY-opacity already covers short bodies; their key is opaque regardless). **This spec keeps the shipped `[2 KiB, ~34 KB]` boxing band** (`blob-store.js:25`) unless the user chooses otherwise in §9. Short bodies stay inline plaintext-in-value (not plaintext-in-key), documented as "confirmable-by-guess, cleartext-structural-adjacent."

### 2.2 The opaque key scheme (deterministic HMAC, two families)

A single bundled network constant `PEERIT_READ_KEY` (`RK`) keys all okeys. `RK` is a network constant with **no rotation path in v2** (rotation = a fresh v1→v2-scale migration).

**Family A — per-author records** (post, comment, vote, profile, mod, head, blob-manifest owner):

```
okey = HMAC-SHA256(RK, author ‖ 0x00 ‖ typeTag ‖ 0x00 ‖ semanticId)  [first 64 hex]
```

where `semanticId` is the **same tuple** `id.*` builds today:
- post → `community ‖ cid`
- vote → `targetCid ‖ author`
- comment → `community ‖ postCid ‖ cid`
- profile → `author`
- mod → `community ‖ actionId`
- head → `author`

Because the derivation is deterministic, a re-vote/edit recomputes the **same** okey and **overwrites the same slot** — so vote/edit LWW **self-compacts at the storage layer exactly as today** (this is the property pure content-addressing sacrifices and the reason we do not go blob-only for votes). The `author` in the HMAC input pins per-author records to their author's namespace, so a peer can't park a record under a victim's okey.

**Family B — the ONE cross-author shared key** (`community!<slug>` only):

```
okey_community = HMAC-SHA256(RK, 'community' ‖ 0x00 ‖ normalizeSlug(slug))  [first 64 hex]
```

Author-**independent**, so rival creators for the same slug still **collide at one slot** → `communityWins()` + `claimed[slug]` stickiness fire unchanged. `slug` stays a signed cleartext-structural field (dictionary-reversible over known slugs — community **names are not hidden**, acknowledged).

**Body blobs stay `blob!<blobId>`** unchanged (content-addressed, self-certifying via `verifyBlobRecord`; `blob!` needs no `v2!` prefix — it is already opaque and author-independent by design).

### 2.3 How readers decrypt public content

1. Pull a peer's outbox (opaque `v2!<okey>` rows + `blob!<blobId>` rows + a `head!` manifest).
2. Verify each record's Ed25519 signature (`verifyRecord`, unchanged) and recompute its okey from its own signed fields (§4).
3. Read structural fields directly from the (cleartext) envelope; build in-memory inverted indices (§3).
4. On render, hydrate a body lazily: fetch `blob!<blobId>`, run the two content-address gates (`unboxToBody`), decrypt. The `contentKey` rides in the record's signed manifest — every reader (and the operator) holds it. This is deniability + non-readability-in-isolation, **never** secrecy.

### 2.4 `_t` (type) is load-bearing — thread it ONCE

`type` moves from the key into a signed cleartext enum `_t`. A single `typeOf(val)` helper replaces `typeFromKey` at **every** call site (§4, §8-S1). **INVARIANT (fixes stress-test S1 type-confusion):** derive `t = val._t` **once** at the top of `admit`, reject unknown `_t` before any branch, and thread that **same** `t` through okey-recompute, `ownerOf`, `canonical`, and `edVerify`. Because `_t` is a non-SIG field it is covered by the signature (`canon.js` `stable()`), so flipping `_t` breaks BOTH the sig AND the okey-recompute (different slot). Never derive type from the key or accept a caller-supplied type.

---

## 3. Client-side aggregation and how it scales

### 3.1 The reframe (already 80% done)

peerit's relay is **already per-outbox**: every read takes `appId` (= author pubkey) first, and every `data.js` query already runs against the **merged local view** (`gossip.js:897–900` `rangeFromView` over `this._cache`), never the relay. Search is **already 100% client-side** (`data.js:473`). So "move aggregation into the browser" is mostly a matter of replacing 7 semantic-prefix scans with client-built inverted indices — over data the client already pulls.

### 3.2 The manifest index (`head!` evolves)

`head!<author>` evolves from a bare census into a **signed manifest log**: snapshot + delta-appended entries with a `prevRoot` chain. Each entry is a `{ okey, tag }` where `tag` is a small structural descriptor with **inline** values: `_t`, `createdAt`/`ts`, vote `value`, `parentCid`, `community`, `postCid`, `targetCid`, `deleted`. The entry set is sealed under `crk = HKDF(readRoot ‖ slug)` (`readRoot` a bundled constant — see the DECISION in §9-D2 on whether crk is worth keeping for public communities).

On pull, for each **changed** author (gated by the existing `_sig` change-token / heads-version), the client: verifies the manifest Ed25519 sig, decrypts tags, and folds entries into in-memory inverted indices alongside `this._cache`:

- `byCommunity[slug] → [okey…]` (feed)
- `byThread[community/postCid] → [okey…]` (comment tree)
- `byTarget[targetCid] → [voteEntry…]` (tally)
- `byModCommunity[slug] → [okey…]` (mod overlay)
- `byAuthorProfile[author] → okey` (profile)
- `communities → okey_community` set (directory)

The 7 `data.js` prefix scans become index lookups. **Because vote value + createdAt + parentCid ride in the tag, feed ranking, vote tallies, comment counts, and thread skeletons need ZERO body-blob fetches and ZERO body decrypts** — only one manifest decrypt per changed author. Bodies hydrate lazily on render via the shipped `_hydrate` + content-addressed `_bodyCache`. `ranking.js`, `buildCommentTree`, `tally()`, and search run **unchanged**.

### 3.3 Manifest tags are ADVISORY-ONLY (fixes stress-test S4 poisoning)

**INVARIANT:** a tag is an **index hint** only. Every ranking-, tally-, or thread-affecting value is derived from the **referenced record's own signed fields after admit** — never from an inline tag value. On hydrating a tagged okey, require the record's signed `community`/`targetCid`/`parentCid`/`createdAt`/`value`/`deleted` to **equal** the tag; on mismatch, **drop the tag, keep the record**. `tally()`'s by-author dedup (`ranking.js:48`) stays authoritative; never surface a tag-derived pre-tally a Sybil could inflate. This bounds tag-poisoning to self-authored data an author could already lie about via a normal record.

### 3.4 Manifest size / chain (fixes stress-test scalability H "delta-chain vs 64 KiB cap")

The relay caps a value at 64 KiB. A `{okey(64) + tag}` entry sealed+base64 is ~240 B, so a single manifest record snapshots only ~250–450 entries. A prolific author blows the cap. **Therefore:**

- **Snapshots are MANDATORY and self-contained.** Each snapshot is a complete index of the author's **current live** records (post-LWW-compaction, so dead votes/edits drop out), signed, version-continuous.
- **Cap entries per segment** well under the byte limit (~300) and store snapshot/delta segments **content-addressed** (`blob!<segId>`) so they self-certify and dedup.
- **Publish the segment count in the signed head** so withholding a middle segment is auditable via the census/head path.
- The client fetches the **latest snapshot + only deltas since it** (usually 0–1 segments given heads-gating). Re-characterize the headline claim honestly as **"one snapshot + short delta-tail decrypt per changed author,"** and state the per-author record ceiling.

### 3.5 Discovery — which logs to pull (fixes stress-test scalability H #1/#2 and feature BLOCKER)

**This is the load-bearing scalability answer.** Two honest facts first:

1. **The O(authors) cold-pull ceiling is PRE-EXISTING, not created by v2.** Today a fresh visitor to r/x already must pull every outbox in `/api/directory` and filter client-side — the relay has no cross-author `postsIn` index. v2 changes the key string and adds a manifest decrypt; it does **not** change this shape. v2 is a **liability win, NEUTRAL on scalability** — state this, do not imply v2 improves cold-load.
2. **Manifest indices are exactly as complete as `_peers` is today.** They add **no new blindness**: a feature only sees authors the client has discovered, identical to today.

**The bounding mechanism (ships WITH v2, not deferred — see §9-D5):** a **cross-author, author-INDEPENDENT community member roster**, keyed like `community!<slug>` so it is one directly-fetchable relay slot:

```
okey_members = HMAC(RK, 'members' ‖ 0x00 ‖ normalizeSlug(slug))   (author-INDEPENDENT, ONE slot)
```

sealed under crk, each member LWW-appends their own pubkey to a merged set (self-signed entry, owner-bound). A fresh r/x visitor then does: **1 relay get(okey_members) → decrypt → author list → pull ONLY those N outboxes**, bounding discovery to O(members-of-x) instead of O(all-authors). Residual leak: member **count** per opaque slot, and the roster is **relay-enumerable by recomputation** (the operator holds RK) — so do **not** claim membership indistinguishability (fixes stress-test S7). For public communities, membership is relay-enumerable; document it as another metadata leak.

**Supporting relay change (content-blind, additive):** add `POST /api/sync/ranges` (N appIds → rows) to collapse thousands of round-trips into a few. It stays content-blind (the relay already serves these per-outbox; batching leaks nothing new). Without batching, a 5000-author cold boot is thousands of sequential HTTP requests.

**Moderation pull is a DEPENDENCY CLOSURE, not best-effort (fixes stress-test feature H "moderation"):** before rendering a community, always pull the founder's outbox (referenced by the community record) **and** every currently-resolved mod's outbox transitively. Have the community record / founder manifest list the current mod-set appIds so they are prioritized. Surface a "moderation may be incomplete" state when a resolved mod's outbox is unpulled, rather than silently under-enforcing bans.

### 3.6 Memory + reconcile (fixes stress-test scalability H "RAM/re-verify blowup")

At 5000 authors × 40 records the full merged view (~200k JS objects) plus a `RECONCILE_EVERY=30` full re-verify is over the mobile-Safari budget and periodically freezes the tab. v2 adds a per-author manifest decrypt to that path. Mitigations (ship as part of the scalability slice):

- **Bound resident authors:** cap the merged view to subscribed-community members + recently-viewed threads; LRU-evict cold outboxes' views to **IndexedDB**, not RAM.
- **Sampled reconcile:** instead of clearing ALL sigs every 30 polls (`gossip.js:753`), re-verify a rotating 1/30th of outboxes each poll — constant amortized verify load, no single-tick stall.
- **Persist verified manifest indices** to IndexedDB keyed by `(author, manifestVersion)`; an unchanged manifest version **skips** the decrypt+rebuild entirely.
- **Persist per-author `{manifestVersion, okeySet, index}`** so a re-open with a matching heads/manifest-version does **zero** re-fetch; add a relay "rows since key K" cursor so a moved outbox transfers only its delta.

### 3.7 Live-updates fast path (fixes stress-test feature H "live-updates" + migration M4)

`patchVotesInPlace` (`app.js:1495`) and `cacheClassForChangedKeys` (`data.js:589`) parse `k.startsWith('vote!')` and slice the key to recover `targetCid`. Under opaque keys these silently degrade to full re-renders. **The `onChange` contract emits bare KEYS today (`diffViews` returns keys, `gossip.js:196`).** **REQUIRED change (not optional):** rework `onChange` to emit `{ key, _t, targetCid, value }` projections (or resolve `val = merged[key]` before classifying), so both classify by `_t` and locate the vote box by `targetCid` without parsing the opaque key. Ship this in the **same slice** as the key rename or vote UX degrades to full re-render the moment v2 writes begin.

### 3.8 Honest note on tallies (fixes stress-test scalability M)

A tally for a popular post is inherently O(voters) in a per-author-log model (no shared aggregate exists) — this is a **fundamental property of killing the relay index**, not a v2 regression. The inline tag saves the **body** fetch, not the author-log fetch. Document: *tallies and karma cost what discovery costs — they are complete only over pulled voter outboxes* (same as today).

---

## 4. Preserving unforgeability / owner-binding / anti-squat / head-census

peerit's trust model is **key-scheme-independent everywhere except the single `expectedKey`/`admit` gate** (`gossip.js:96`) and the prefix/range read model. The signature already covers all fields (`canon.js` `stable()`), never the storage key.

| Invariant | Today | v2 | Verdict |
|---|---|---|---|
| **Ed25519 authenticity** | `verifyRecord` over `canonical(type,data)` | identical (type = `val._t`) | UNCHANGED |
| **Owner-binding** | `_k === ownerOf(type,data)` | identical (type = `val._t`) | UNCHANGED |
| **Key-binding (anti-eviction)** | `expectedKey(type,val) === key` | v2 branch: recompute okey from signed fields (family A: `HMAC(RK, author‖_t‖semanticId)`; family B: `HMAC(RK, slug)`), compare to `v2!<okey>` | STRONGER-EQUAL: same check over an HMAC not a readable string. **okey-recompute is DEFENSE-IN-DEPTH, not the anti-eviction root** — `ownerOf(_k===author)` + Ed25519 is what prevents eviction (fixes stress-test S3). |
| **Blob self-cert** | `SHA-256(ct)===blobId` in admit | unchanged | UNCHANGED |
| **PoW** | hashes fields (`pow.js`), never key | unchanged | UNCHANGED |
| **LWW / conflict** | `laterRecord`/`communityWins` on signed fields | unchanged; per-author okey deterministic so re-writes still collide at one slot | UNCHANGED |
| **Anti-squat stickiness** | `claimed[slug]` keyed on `val.slug`; community rows found by `typeFromKey==='community'` | `claimed[normalizeSlug(slug)]`; community rows found by `val._t==='community'`; `okey_community` author-independent so rivals still collide | PRESERVED (see S2 below) |
| **Head census** | `outboxCensus` hashes `key\x00sig`, key-agnostic | producer + auditor both hash opaque okeys; `_sig` stays in cleartext envelope | UNCHANGED (see below) |

**Anti-squat conversion is load-bearing — DO NOT undercount call sites (fixes stress-test S2).** There are **10** `typeFromKey` sites (grep-verified): `canon.js:72`; `gossip.js:146, 158, 216, 226, 298, 305, 692, 784, 834, 912`. Convert **each** to `val._t` explicitly — both lock-loops (`gossip.js:158, 226`) and both claimed-checks (`gossip.js:150, 219`) are load-bearing across BOTH merge paths (`mergeOutboxes` AND the incremental `combineAdmitted`). A missed path silently disables stickiness → an established r/x becomes re-squattable. Add a test that established-community stickiness survives across **both** paths.

**okey-recompute needs `RK` at ingest.** Anti-eviction now depends on a shared secret every client holds — fine for the honest-ceiling threat model (the operator is a reader anyway). **Fail-CLOSED but LOUD (fixes stress-test S3):** if `RK` is missing/misprovisioned, **throw at boot**, do not silently reject every row as unadmitted (a self-inflicted total-withholding). The dual-read admit branch selects v1-vs-v2 by **key prefix (`v2!`)**, never by RK-presence, so a missing RK can't misroute a v2 record into the v1 branch.

**Head-census self-reference (fixes stress-test feature-M "census churn").** Manifest-delta records are **CENSUS-EXCLUDED** exactly as `head!` is today (`outboxCensus` skips `_t===HEAD`, `canon.js:72`), so appending a manifest delta never perturbs the root it commits to. Keep monotonic version continuation (`prev.version+1`, never reset).

**MIGRATION FLOOR HAZARD (verified real — the sharpest census edge, fixes stress-test S5 + migration M3).** Two rules:

1. A v2 manifest MUST continue the monotonic head version (`prev.version+1`, never reset) or the durable floor (`gossip.js:818`) raises a **false network-wide rollback** flag. Before its first v2 head append, the migrated client MUST load the existing `head!<me>` (from `/api/directory` / `crossHead`) and continue from its version — never trust a possibly-wiped local cache for the baseline. Enforce version monotonicity **at `_maintainHead`** (reject/repair a computed `version <= prev.version`), not just in docs.
2. **Census scope during dual-read must be symmetric.** During Phase 1 an outbox transiently holds BOTH a v1 plaintext row and its v2 okey row for the same logical record (LWW does **not** dedup across different keys). If a v2-only auditor censuses a **different** row set than the producer, `auditOutbox` mismatches → false withholding flag for every migrating author. **DECISION (§9-D6):** either (a) all clients census the **union** of v1+v2 rows identically (a v2-only reader still counts v1 rows it can't fully index), OR (b) the seed re-emission **tombstones** the v1 row so only one census member survives per logical record. Add a migration test: an author mid-migration must NOT trip `auditOutbox` on either a dual-read or a v2-only auditor.

---

## 5. Per-feature adaptation table

| Feature | Today (relay/prefix) | v2 (client index) | Notes / stress-test fix |
|---|---|---|---|
| **Community feed** (Hot/New/Top/Rising) | `list(post!<c>!)` | `byCommunity[slug]` → records; `ranking.js` unchanged | ranking is pure client math already |
| **Threaded comments** | `list(comment!<c>!<p>!)` | `byThread[c/p]` → `buildCommentTree` unchanged; skeleton from tags | mark `_orphaned` when `parentCid` absent instead of silently promoting to root (feature-H) |
| **Votes + tally** | `list(vote!<cid>!)`; author-in-key LWW dedup | `byTarget[targetCid]`; deterministic per-`(author,target)` okey self-compacts; `tally()` dedups by author | **manifest replay MUST collapse entries to latest per okey by ts (tombstone-wins ties) BEFORE building byTarget** — storage-slot compaction dedups the RECORD, not the manifest DELTA (feature-H "double-count on vote-flip") |
| **Karma / userActivity** | cross-community post+comment scans | compute the target's OWN post/comment okeys from THEIR manifest; tally via `byTarget` | best-effort over pulled outboxes; **do not claim exact** (feature-M) |
| **Profiles** | `get(profile!<pub>)` | `byAuthorProfile[pub]` / pull pub's one outbox | most natural per-author op |
| **Moderation overlay** | `list(modaction!<c>!)` | `byModCommunity[slug]`; `resolveMods`/`modOverlay` unchanged | **dependency-closure pull** of founder + mods (feature-H, §3.5) |
| **Search** | client-side, hydrates boxed bodies | iterate manifests instead of `commentPrefix()`; **keep 2 KiB box threshold** so short bodies stay searchable-for-free | do NOT box all text (feature-H "search regression"); withheld-blob records flagged unsearchable |
| **Sticky community claim** | `community!<slug>` collision + `claimed[slug]` | `okey_community` collision + `claimed[normalizeSlug(slug)]`; `communityWins` unchanged | normalize slug BEFORE the HMAC on both sign and verify (feature-M "case race") |
| **Saved/hidden/subs/follows** | 100% localStorage | unchanged | prioritize pulling followed authors at boot (feature-L) |
| **Live-updates** | `heads(appIds)` version int (content-blind) + `patchVotesInPlace` | heads unchanged; **`onChange` emits `{key,_t,targetCid,value}`** | REQUIRED plumbing change (§3.7, feature-H/M4) |
| **Edit / delete** | re-sign at same key | re-sign → same okey (semanticId immutable) overwrites slot; **manifest delta MUST set `deleted:true` tag** so indices drop it | test: post→delete → `byCommunity` no longer yields it AND tombstone occupies okey slot (feature-M "delete") |
| **Head census / floor / directory** | `head!<pub>` + version; `outboxCensus` hashes key | manifest evolves head!; census key-agnostic over opaque okeys | monotonic version continuity (S5); manifest-delta census-excluded |

---

## 6. Residual leaks (exhaustive — the honest ceiling in detail)

State ALL of these in product copy. Rounding any of them up to "blind" is the forbidden overclaim.

**A. Author-partition leak (dominant, structural, un-fixed by v2 keys).** `/api/directory` enumerates the **complete author-pubkey set** (`appId === pub`) with zero decryption. Per-author outbox reads expose per-author record **count**, append **cadence/version** (`/api/sync/heads`), and per-record **byte size** (a 32-byte vote vs a manifest vs a blob-ref are size-distinguishable → coarse type-mix). This is a passive, index-free per-author activity-volume readout. Scope the four wins to BODIES + the cross-author/target/community index only.

**B. Read-side graph (who-reads-whom) + IP.** A client pulls by requesting an author's appId-partition and refreshes gated by per-appId `/api/sync/heads` over its joined appId list. The relay observes, per connection/IP, the exact set of authors a reader follows and re-pulls — a read-side interest graph no key-opacity touches. Real mitigation is out-of-scope transport work (cover traffic, pool routing, PIR-style batching). "Blind" never covered read-side metadata.

**C. Community membership + names.** `slug` is a signed cleartext-structural field and dictionary-reversible over known slugs (community **names are not hidden**). `okey_community` and `okey_members` are deterministic over guessable inputs, so an RK-holder (every reader, incl. the operator) can **enumerate** membership by recomputation. The member roster (§3.5) is relay-enumerable — do not claim indistinguishability.

**D. Targeted confirmation is O(1) for the operator (ceiling-honesty defect if not stated).** `okey = HMAC(RK, author‖_t‖semanticId)`, RK is public, and semanticId is often low-entropy/enumerable (pubkeys public; slugs dictionary-reversible). So "did Alice vote on known-post P?" is `HMAC(RK, Alice‖'vote'‖P‖Alice)` → one point lookup. The no-index win applies to **ENUMERATION** (list-all-in-r/x, who-voted-on-Y across unknown voters), **NOT to CONFIRMATION** of a specific known-author/known-target pair. Correct any copy that says "who-voted-on-Y is infeasible for the operator."

**E. Convergent-body confirmation + equality.** `contentKey = SHA-256(body)` and `blobId = SHA-256(ct)` are deterministic → identical bodies produce identical `blobId`. Anyone who guesses a body confirms its presence and can enumerate "who else posted this exact text." Acceptable for a public forum (content is world-readable by design); keeping the 2 KiB threshold means short low-entropy text is not needlessly boxed into cheap confirmability.

**F. crk is not a confidentiality mechanism for public content.** `readRoot` ships to every client, so crk provides **zero** confidentiality against the operator or the public. Its only honest functions are (1) the migration hook to genuinely-private groups (crk withheld from non-members) and (2) a marginal "must run an HKDF + decrypt to index" step. Do not let any doc imply crk hides the graph from the operator (see §9-D2 on whether to keep it for public communities at all).

**G. `_t`, per-record structural fields, timestamps, sizes** are cleartext-in-value (not in-key). A reader sees them; a passive operator does not grep/prefix them but reconstructs them by running the client.

---

## 7. Phased migration on the LIVE system

**Non-negotiable constraints.** Existing user records are signed over their plaintext-keyed canonical form and are **un-re-signable by anyone but their author** — so a hard cutover orphans all live content. Migration is **dual-read / write-forward**, not a rewrite. Preserve: the deterministic drive key / peerit.site origin (installs auto-update to it), each user's `peerit:my-outboxes` history, and monotonic head-version continuity.

### Phase 0 — READ-ONLY dual-read (smallest first slice)

**Ship the v2 read path with WRITE_V2=false.** Scope of the smallest correct slice:
- v2 codec: `okey` HMAC builder (families A/B) + `typeOf(val)` helper.
- Dual-read `admit` branch: `v2!<okey>` → okey-recompute + `verifyBlobRecord`-style path + decrypt/index; legacy key → existing plaintext `expectedKey` + prefix.
- Convert **all 10** `typeFromKey` sites to `val._t` with a **legacy fallback** (`val._t || typeFromKey(key)`) so both schemes route.
- Census/floor version-continuity guard at `_maintainHead`.
- **No** write path, **no** manifest index, **no** body-box-threshold change yet (those are later slices).
- Keep `id.*` builders as the **semanticId source** (they feed okey-recompute); stop using their output as the storage key.
- Deploy to peerit.site **and** a new `hyper://` drive revision on the **same deterministic drive key**, so installs auto-update to READ v2 before any client WRITES it.
- Fork the 8 golden-key tests to assert BOTH v1 (legacy rows) AND v2 (okey-recompute) admit paths — they are the dual-read regression guard.

**Enforce read-before-write with a network gate, NOT a timing assumption (fixes stress-test migration H "old install drops v2").** An old install computes `expectedKey('v2', val) → null`, `admit` rejects, and the row is **silently discarded** (no error). Bake a `v2-capable` marker into the signed head; gate the WRITE_V2 flip on an observed-fleet signal (fraction of `/api/directory` heads advertising v2-capable), not a client config flag. Emit a loud client-side warning when a peer's head advertises a version this build can't parse.

### Phase 1 — flip WRITE_V2=true (write-forward)

New records emit v2 (opaque okey + manifest); old v1 rows keep rendering via dual-read; stale v1 orphans harmlessly (LWW per-key). Ship the coupled required changes **in this slice**: the `onChange` `{key,_t,targetCid,value}` plumbing (§3.7) and the census-symmetry decision (§4 / §9-D6). Handle `community!<slug>` as a dual-key special case: during Phase 1 a v1 `community!<slug>` and a v2 `okey_community` for the same slug are **different keys** and both render — de-dupe by slug in the **client** `byCommunity` index so a duplicate community doesn't show.

### Phase 2 — reseed under v2

Run `test/seed-author.mjs` **AFTER** Phase 1 (it runs the same client code, so it inherits the v2 write path) to re-emit r/p2p + r/worldcup idempotently under v2 (deterministic cids → LWW-supersede v1 for dual-readers). **The seed author MUST replicate its current head and carry `prev.version+1` forward** (read it from `/api/directory` at startup or persist the last-emitted head version alongside the seed store) — a reseed that resets version to 1 over an author the directory floor already pins high trips a false rollback (migration H "floor").

### Phase 3 (optional, later) — scalability slice

Member roster (§3.5), `POST /api/sync/ranges` batch endpoint, IndexedDB persistence of indices, sampled reconcile, bounded resident authors. (Per §9-D5 the user may choose to pull the roster **into Phase 1** if popular-community feeds must be viable at launch.)

### Phase 4 (optional, later) — OutboxLog transport upgrade

Cut over to HiveRelay's blind OutboxLog on a `blind:FALSE` namespace as a defense-in-depth transport upgrade (server-side Ed25519 envelope verification). **Not a prerequisite.** The blind namespace **rejects** peerit's non-`{sealed}` envelope today and would force `_k`/`_ns`/`_dk` cleartext — the wrong surface if author-graph hiding were ever wanted (it is out of scope). peerit-relay needs **zero** code change to store opaque rows in the meantime (it already treats `data.id` as an opaque string and `value` as opaque JSON).

### Rollback

`WRITE_V2 → false` stops new v2 writes **instantly, no data loss** (v1 rows never mutated). **Rollback rule: stop writing, KEEP dual-read** — never revert the read branch, or already-written v2 rows silently drop. Sequence the manifest-root re-base as its own gated step and always regenerate the manifest snapshot + head census **together in one append**, never split across a rollback boundary, so an auditor never sees a root computed over a mixed basis.

### What happens to existing data / claims / installs / reseed

- **Existing user records:** immutable, keep rendering via dual-read forever; a user who never returns keeps v1 rows.
- **Sticky claims (`peerit:claimed`):** keyed on slug already → survive; keep keyed on `normalizeSlug(slug)`.
- **PearBrowser installs:** auto-update to the new drive revision on the same deterministic key; Phase 0 lands READ support before any WRITE_V2 flip.
- **Reseed:** inherits the v2 write path; must carry head-version forward (Phase 2).

---

## 8. Blocker + high issues folded in (traceability)

| # | Issue (stress-test) | Severity | Mitigation location |
|---|---|---|---|
| S1 | Type-confusion via `_t` (owner-binding bypass) | high | §2.4 — derive `t=val._t` once; thread identically through okey/ownerOf/canonical/edVerify; reject unknown `_t`; test that altering `_t` fails BOTH sig and okey |
| S2 | Anti-squat loses its trigger under opaque keys; undercounted call sites | high | §4 — all **10** `typeFromKey` sites enumerated; convert both lock-loops + both claimed-checks across BOTH merge paths; test stickiness on both paths |
| S3 | okey-recompute needs RK at ingest; weakens anti-eviction; bootstrap total-withholding | medium | §4 — okey is defense-in-depth; `ownerOf`+Ed25519 is the root; fail-CLOSED+LOUD on missing RK; route by `v2!` prefix not RK-presence; RK immutable in v2 |
| S4 | Manifest poisoning / DoS surface | medium | §3.3 — tags advisory-only; cross-check against signed record, drop tag on mismatch; §3.4 — bound tags/segment, mandatory snapshots |
| S5 | Migration floor / census rollback under opaque transition | medium | §4 (floor hazard) + §7 Phase 2 — monotonic version at `_maintainHead`; census-symmetry decision; mid-migration audit test |
| S6 | Semantic-id preimage: targeted confirmation is O(1), not infeasible | medium | §6-D — correct copy: no-index = enumeration only, NOT confirmation |
| S7 | Deterministic okey → relay membership enumeration | low | §3.5 + §6-C — do not claim membership indistinguishability; document relay-enumerability |
| Scale-H1 | Cold-start already O(authors); v2 framing misleading | high | §3.5 — v2 is liability-win, NEUTRAL on scale; member roster + `/api/sync/ranges` |
| Scale-H2 | New-visitor r/x discovery has no index | high | §3.5 — author-INDEPENDENT `okey_members` roster = one fetchable slot |
| Scale-H3 | Manifest delta-chain vs 64 KiB cap; full-chain replay | high | §3.4 — mandatory self-contained snapshots, content-addressed segments, cap per segment |
| Scale-H4 | RAM + reconcile blowup; v2 adds decrypt to that path | high | §3.6 — bound resident authors (IDB LRU), sampled reconcile, persist indices |
| Feat-BLOCKER | Cross-author aggregation completeness | blocker | §3.5 — manifest indices are exactly as complete as `_peers` today, add NO new blindness; dependency-closure pull for mods; membership roster bounds the pull; **stated in writing** |
| Feat-H (votes) | Manifest replay double-counts a flipped vote | high | §5 votes row — replay collapses to latest per okey by ts BEFORE byTarget |
| Feat-H (threads) | Orphan-at-root silent mis-shape | high | §5 comments row — mark `_orphaned`, don't promote to root |
| Feat-H (mods) | Missing mod outbox → silent under-enforcement | high | §3.5 — moderation pull is a dependency closure + "incomplete" UI state |
| Feat-H (search) | Boxing all text breaks search-for-free | high | §2.1 + §5 search — keep 2 KiB threshold; iterate manifests |
| Feat-H (live) / M4 | `onChange` emits keys, not values | high/med | §3.7 — rework onChange to `{key,_t,targetCid,value}`, same slice as key rename |
| Mig-H (old install) | Silent drop of v2 by pre-Phase-0 install | high | §7 Phase 0 — network gate on v2-capable head marker, not timing |
| Mig-H (floor) | False rollback on head re-init / reseed | high | §4 + §7 Phase 2 — load prior head before first v2 append; version monotonic; reseed carries version |

---

## 9. Open decisions (genuine forks the user must make)

- **D1 — App-wide vs community-scoped read key.** This spec uses a single bundled `PEERIT_READ_KEY` for all okeys. Alternative: a per-community read key so a community's okeys/tags are only recomputable by holders of that community's key (enables genuinely-private communities). Cost: cross-community feeds and global search need every community key; discovery gets harder. **Fork:** one network key (simple, all-public) vs per-community keys (private-group capable, more key distribution).

- **D2 — Keep crk (manifest-tag AEAD) for PUBLIC communities, or drop it.** crk gives **no** confidentiality for public content (readRoot is public). Keeping it buys a marginal "must decrypt to index" step + a clean migration hook to private groups. Dropping it (seal tags with the same convergent scheme, or leave them structural) removes crypto that a reviewer reads as privacy theater. **Fork:** keep crk as a private-group hook vs drop it for public communities and reserve a real read key only for private groups.

- **D3 — Body-box threshold: keep 2 KiB band vs box ALL text.** Boxing all text closes the "short body inline" gap but is confirmable-by-guess for short/low-entropy content, kills search-for-free, and adds a `_blobMissing` surface for zero liability gain. This spec **recommends keeping the 2 KiB band**. **Fork:** keep band (recommended) vs box-all (uniform ciphertext-at-rest, real cost, no real gain).

- **D4 — Hard cutover vs dual-read.** Hard cutover orphans all un-re-signable live user content and is not viable on a LIVE system. This spec mandates **dual-read / write-forward**. **Fork exists only if** the user accepts losing historical content — otherwise dual-read is forced.

- **D5 — Ship membership roster + batch endpoint WITH v2 (Phase 1) or defer.** The roster is the ONLY thing bounding the O(authors) pull; without it, popular-community feeds are cold-infeasible past ~1–2k authors. **Fork:** ship in Phase 1 (feed viable at launch, more surface) vs defer to Phase 3 (smaller first diff, feeds degrade at scale until then).

- **D6 — Census scope during dual-read: union vs tombstone.** Either all clients census the union of v1+v2 rows identically (a v2-only reader counts v1 rows it can't fully index), OR reseed/edit tombstones the v1 row so one census member survives per logical record. **Fork:** union (no producer change, v2-only readers carry dead weight) vs tombstone (clean census, requires the author to actively supersede each v1 row — only possible for the author's own records).

- **D7 — Retire peerit-relay vs keep it / add OutboxLog blind proxy.** peerit-relay needs zero change to store opaque rows today. HiveRelay OutboxLog (blind:FALSE) adds server-side envelope verification but is otherwise wire-identical; its blind namespace is the wrong surface (forces `_k` cleartext, out of scope). **Fork:** keep bespoke peerit-relay (simplest) vs cut over to OutboxLog blind:FALSE as defense-in-depth (Phase 4) vs run OutboxLog as a proxy in front of the current core.

- **D8 — Add a drop-by-opaque-id takedown primitive.** The liability claim includes "drop-by-opaque-id takedown," but neither peerit-relay's admin suppress-by-key nor OutboxLog ships a first-class per-record operator delete that survives pool re-seeding. **Fork:** rely on the existing admin suppress-by-exact-key (opaque key is a fine target) vs add a signed-tombstone / operator-scoped `delete(appId,okey)` primitive across the pool.

---

## 10. Summary

Kill the plaintext keys by re-keying every record under an opaque `v2!<okey>` (deterministic HMAC over the same signed semantic tuple — author-bound for per-author records, author-independent for the one shared `community` slot), box bodies with the shipped convergent AEAD (keeping the 2 KiB threshold), and move feed/thread/tally aggregation into a client-built inverted index materialized from a signed, sealed **manifest** (evolved `head!`) whose tags are **advisory-only**. Unforgeability, owner-binding, LWW self-compaction, anti-squat stickiness, and the head census all survive because the signature already covers fields not keys and okey-recompute is a structural pre-filter, not the anti-eviction root. Discovery is bounded by an author-independent per-community member roster + a content-blind batch endpoint. Migrate write-forward with dual-read on the same deterministic drive key, gate the WRITE_V2 flip on an observed v2-capable fleet, keep the head version monotonic, and roll back by stopping writes while keeping dual-read. The **honest ceiling holds throughout**: no passive grep, no semantic enumeration, content-neutral, drop-by-opaque-id — **NOT** secrecy, **NOT** anonymity, **NOT** metadata-blindness, and **NOT** infeasible targeted confirmation for an operator that holds the public read key.
