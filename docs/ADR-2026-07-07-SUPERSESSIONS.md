# ADR 2026-07-07 — Accepted supersessions (shipped design > documented design)

**Status:** ACCEPTED by the owner. Where the shipped code diverged from the original design
docs and the shipped construction is superior, the divergence is hereby ratified as the
intended architecture. Docs already carry SUPERSEDED banners; this ADR is the decision record.

| # | Original design (docs) | Shipped (ratified) | Why the shipped one wins |
|---|---|---|---|
| 1 | Reed-Solomon erasure of the ciphertext; `contentKey` PUBLIC in the manifest | **PVSS-secp256k1 split of the AES key**; key never published; whole ciphertext as a cohort shard | Below threshold, a held share is *computationally* blind — the original let any single relay decrypt by fetching k shards + the public key. Strictly stronger per-operator blindness. |
| 2 | SHA-256 shard addressing | **blake2b-256** (`shardAddressOf`) | Byte-identical to the deployed HiveRelay `/api/v1/shard` contract; SHA-256 PUTs would fail as address mismatches. Equal cryptographic strength. |
| 3 | Client-side HRW placement + `<K`-shards-per-relay convention | **Signed custody intent, fixed 1 share/relay, relay-enforced resolver** | The `<K` invariant holds *by construction* (1 < k) and is enforced by the relay (orphan-intent + wrong-assignment rejection), not by client etiquette. |
| 4 | New HiveRelay blob-GET surface for the body ciphertext (PURE-PIPE §5.1) | **Ciphertext-as-shard** (`shareIndex: 0`) on the existing shard contract | Closes the gap with zero net-new relay surface; same custody/retention model as the shares. |
| 5 | Plaintext semantic storage keys (`post!<community>!<cid>` …) | **v2 opaque keys** (`v2!<okey>`, HMAC) + sealed graph fields, default-on | Kills graph-by-key-prefix enumeration — the core graph-blindness property. Docs (EXPLAINER) corrected. |
| 6 | Browser reading of dispersed bodies assumed gated on HiveRelay #115 | **Browser reader shipped** (`js/reader-bundle.js`; `data.js` `_hydrate` uses it) | #115 gates only in-browser *authoring* (Bare dealer). Read cutover needs no external dependency. |
| 7 | "Only new dependency = WASM Reed-Solomon" | `sodium-universal` + vendored, pinned `@noble` PVSS client (`js/vendor/blind-shards/`) | Accepted cost of #1; vendored with provenance manifest + sync script rather than reimplemented crypto. |

**Explicitly NOT superseded (ruled the other way):**
- **Device durability floor.** Cohort-only ciphertext (commit `23dc04a`) is *not* accepted as final:
  it makes a dispersed post less durable than a plain v2 post and dies with the (currently
  single-operator) cohort. Ruling: restore device-as-floor — the author's device persistently
  retains the body key (device-local, never synced) plus a local ciphertext replica, enabling
  decrypt + re-disperse after total cohort loss. Phase-4 `repair()` builds on this.

**Standing gaps this ADR does not touch:** production shard cohort (independent operators,
GATE 2) before enabling dispersal; release-signature verification wiring (`pinnedReleaseKey`);
custody-receipt quorum + `repair()`; signed/unified shard roster (PURE-PIPE §5.2).
