# BlindShard Adversarial Review — Production Readiness

**Scope:** peerit `feat/web-deployment` BlindShard dispersal path (v2 opaque log + PVSS shard cohort).  
**Date:** 2026-07-05.  
**Status:** code-complete, tests green, **blocked on production relay pubkeys/API keys** before the live cohort can be activated.  
**Review lenses:** Red Team / Operator-Liability / Browser-Runtime / Crypto / Performance / Fleet-Independence.

> This review treats the honest ceiling from `docs/BLINDSHARD-DESIGN.md` as non-negotiable: for a **public** forum the read key reaches every reader, so BlindShard delivers **non-readability-in-isolation + plausible deniability + "not the sole authoritative host"**, never cryptographic secrecy, never anonymity, never metadata-blindness.

---

## 1. Executive summary

| Axis | Verdict | Blocking? |
|---|---|---|
| Client crypto/dealer | ✅ Sound. PVSS key split, HKDF body-key binding, intent-signature verification, ciphertext content-address gates all present. | No |
| Node dealer + browser reader bundle | ✅ Wired and passing (`blind-dealer.mjs`, `reader-src.mjs` → 95 KB minified bundle). | No |
| v2 + dispersal composition | ✅ Fixed and tested (`data.js` no longer skips `_boxBody()` in v2 mode). | No |
| Local mechanism proof | ✅ 3-relay cohort + reader-bundle-live both pass. | No |
| HiveRelay `shareIndex` routing bug | ✅ Fixed and pushed to `feat/local-shard-cohort` (`91093c3`). | No |
| Production relay pubkeys/API keys | ❌ Unknown. Cannot build a functional production release without them. | **Yes** |
| Public relay shard-store surface | ⚠️ Mounted (`/api/v1/shard` returns 401, not 404), but functionality cannot be verified without keys. | Indirectly |
| PearBrowser bridge shard transport | ⚠️ Theoretical gap: webview reader bundle uses `fetch`; real PearBrowser webview network access to shard relays is unverified. | Maybe |
| Independent operator roster | ❌ Both public relays are same legal entity. Collusion threshold is theater until ≥3 independent operators. | Social |
| Bundle size / CSP | ⚠️ Reader bundle +95 KB; CSP already permits `wasm-unsafe-eval` for DHT path, so no new CSP surface. | No |
| Performance | ⚠️ Cold body read is `k+1` sequential HTTP GETs; lazy hydration keeps feed render unaffected. | No |

**Honest bottom line:** the *mechanism* is ready. The *live deployment* is gated on (a) relay credentials, (b) confirming the public relays run the fixed `feat/local-shard-cohort` branch, and (c) recruiting at least one independent operator so the collusion claim is not vacuous.

---

## 2. Red Team — attack surfaces and mitigations

### 2.1 Relay impersonation / rogue shard relay

**Surface:** A reader fetches shards from base URLs in the public roster. An attacker who controls DNS, TLS, or a mirror can serve bogus shards.

**Mitigations in code:**
- `blind-dealer.mjs:368-375` `recoverKey()` verifies the publisher-signed custody intent (`verifyCustodyIntent`) before reconstruction.
- `js/vendor/blind-shards/blind-shards.js:200+` `recoverSecret()` verifies each fetched share against the committed `shareCommitment` and the DLEQ proof.
- `shard-transport.js:96-104` reader fetches by content hash and the crypto layer re-hashes; a substituted shard fails `recoverSecret`.
- `data.js:343-391` falls back to `_blobMissing` on any recovery failure; no forged body is rendered.

**Gap:** the roster itself is fetched by URL and pinned only by SHA-256 in `asset-manifest.json` / Service Worker. If the origin serving the bundle is compromised, it can serve a roster pointing at attacker relays. This is mitigated by the signed release chain (`release-verify.js`, `pinnedReleaseKey`) and the `hyper://` PearBrowser path, but a normal-browser visitor who does not independently verify the release key is vulnerable to origin compromise. **Not a BlindShard-specific gap, but it bounds the dispersal threat model.**

### 2.2 Withholding / erasure attack

**Surface:** A relay accepts a shard PUT but later 404s it; or `k-1` relays collude to withhold.

**Mitigations:**
- `k-of-n` threshold: reader needs only `k` of `n` shards.
- Ciphertext is replicated to **every** relay (`putCiphertextToRelays` writes shareIndex 0 to all relays), so ciphertext withholding requires all relays to collude.
- `data.js:_hydrate()` degrades to `_blobMissing` rather than crash.

**Gap:** there is **no custody-receipt quorum** yet. The dealer fire-and-forget PUTs shards and trusts they persisted. A relay could accept then delete. The durable floor is the author's device cache + the fact that ciphertext is replicated to all relays. Phase 4 receipts are needed for an honest "durable" claim.

### 2.3 Manifest substitution / wrong key

**Surface:** An attacker publishes a post with a manifest whose `shareCommitments` were not produced by the real dealer.

**Mitigations:**
- `verifyCustodyIntent()` (`blind-dealer.mjs:347-366`) checks the intent signature, then checks every manifest field against the signed intent (`publisherPubkey`, `blindContentId`, `ciphertextRoot`, `commitmentRoot`, `shareBundleKey`, `shareScheme`, `threshold`, `shareManifest`, `plaintextHash`).
- The post record itself is signed by the author (`data.js:_emit()` → `canonical()` + Ed25519), so the manifest cannot be attached to a different author's post.
- `_publisherForDispersal()` enforces that the PVSS publisher pubkey equals the post author pubkey (`data.js:304-308`).

**Verdict:** manifest integrity is well-bound.

### 2.4 Convergent-encryption confirmation attack

**Surface:** `contentKey`/PVSS secret is derived from the body via HKDF; an adversary who guesses a body can re-derive the key and confirm the ciphertext matches.

**Status:** acknowledged in `BLINDSHARD-DESIGN.md` §2 / §6.1. For a **public** forum this is acceptable — the content is world-readable anyway — but marketing must not claim confidentiality.

### 2.5 Custody-intent replay / pin reuse

**Surface:** A shard pin includes `hash`, `custodyIntentId`, `shareIndex`, `retainUntil`, `nonce`. The nonce is freshly random per pin (`freshNonce()`). The intent ID binds the pin to one manifest. `retainUntil` limits temporal replay.

**Verdict:** pin design resists replay and cross-intent reuse.

### 2.6 Size / DoS on shard store

**Surface:** Open write surface on `/api/v1/shard` could be spammed.

**Mitigations:**
- PUT requires a valid custody pin signed by the publisher (`Authorization: Bearer apiKey` also used for intent publish).
- Intent publication is authenticated with per-relay `apiKey`.
- Peerit bodies are gated by `shouldBox()` / `shouldDisperse()` thresholds, so small records never become shards.

**Gap:** there is no hashcash/PoW on shard PUTs in the current implementation. The design doc (§5) contemplated PoW-gated shard writes, but the live surface relies on the relay API key for write authorization. This is acceptable for a closed cohort but should be revisited if opening shard-store writes to untrusted publishers.

### 2.7 Metadata / social graph leak

**Surface:** v2 seals the graph fields, but cleartext LWW fields (`createdAt`, `ts`, `editedAt`, `deleted`, `slug`) and the author pubkey remain exposed. Titles are cleartext unless separately boxed.

**Verdict:** structural, acknowledged, out of scope for BlindShard. Do not market graph privacy.

---

## 3. Operator liability

### 3.1 What a single shard-store relay holds at rest

- PVSS key shares: opaque blobs, fewer than `k` of any item, no key, no manifest, no author→shard linkage.
- Body ciphertext (shareIndex 0): replicated to every relay; content-addressed, no key on the shard tier.
- Custody intents: only if the relay also runs the outbox tier and mirrors the author's outbox.

### 3.2 Honest posture for a single relay operator

> "I run an opt-in availability relay. Under `shard:*` I hold content-hash-addressed opaque bytes I cannot decrypt, cannot attribute to any post or user, and cannot reassemble alone. Reconstructing anything requires deliberately fetching the public manifest AND collecting k fragments from other operators — an affirmative act."

This is defensible **only if**:
1. The relay does **not** also mirror the outbox tier (or, if it does, it does not join shard addresses to posts).
2. The relay never holds `≥ k` shards of one item.
3. The relay roster has **independent** operators; same-owner relays collapse the collusion threshold to one subpoena.

### 3.3 Current liability reality

- The two public relays (`153-75-89-206.sslip.io`, `peerit-relay.onrender.com`) are operated by the same entity.
- A court order to that one entity covers **both** relays.
- With `k=2` and `n=2`, the operator holds exactly the threshold across their own boxes. This is **not** dispersal in a liability-reducing sense; it is merely two copies.

**Recommendation:** do not claim "no single operator can read bodies" until there is at least one independent operator. The mechanism still provides ciphertext-at-rest and non-grep-ability, which is real but weaker.

### 3.4 Takedown / notice-and-takedown

**Gap:** the current relay has no serve-time suppression for a specific `shard:<hash>`. Because shards are content-addressed and no relay knows which post they belong to, a DMCA-style notice cannot identify a shard. A notice must target the **manifest** on the outbox tier (signed by the author, deletable only by the author via tombstone). This is a feature for operator liability but a gap for safe-harbor compliance. `docs/RELAY-TAKEDOWN-SPEC.md` is the place to resolve this.

---

## 4. Browser / PearBrowser runtime

### 4.1 Normal browser (peerit.site)

- `resolveRuntime()` detects no `window.pear` and enters `web` mode.
- `build-web.mjs` injects `<meta name="peerit-shard-roster" content="config/shard-roster.public.json">`.
- `app.js:67` resolves the shard cohort; `data.js` uses `reader-bundle.js` (HTTP `fetch`) for recovery.
- **CSP:** the bundle needs `connect-src` to the shard relay origins. The current `index.html` CSP already permits `connect-src 'self' http: https: hyper: pear:`, so cross-origin HTTPS shard fetches are allowed. No build change needed unless the CSP is tightened later.

### 4.2 PearBrowser (desktop / mobile host bridge)

- `resolveRuntime()` sees `window.pear` and enters `pearbrowser` mode, ignoring all relay `<meta>`.
- The shard cohort config is still read from `<meta>` in the loaded hyper drive, so a PearBrowser build can still enable dispersal if the meta is present.
- **Critical gap:** `data.js:_getRecoverBody()` checks `typeof process !== 'undefined'` to choose between Node (`blind-dealer.mjs`) and browser (`reader-bundle.js`). Inside a PearBrowser webview, `process` is undefined, so it imports the browser bundle, which uses `fetch`.

**Question:** does the PearBrowser webview have unrestricted HTTPS fetch access to arbitrary shard relay origins?

- If **yes**, the current path works.
- If **no** (common in app webviews), the host bridge must expose a shard-fetch API, or the app cannot recover dispersed bodies.

**Recommendation:** test this immediately. If the webview is restricted, add a `pear.bridge.fetchShard` API to the host and a corresponding adapter in `data.js` / `pear-api.js`.

### 4.3 PearBrowser authoring

- `data.js:_publisherForDispersal()` requires `identity.currentSeedEntry()` to return `{seed, pubkey}`. The host-held `BridgeIdentity` does not expose a seed.
- Therefore **PearBrowser authors cannot disperse**; they fall back to single-blob boxing (`data.js:229-237`).
- This means: Node/web authors put bodies off-VPS; PearBrowser authors leave bodies in the peerit sync group as blobs.

**Honest claim:** "Dispersal authoring works from Node/web runtimes; PearBrowser readers can recover dispersed bodies; PearBrowser authoring falls back to ciphertext blobs in the sync group."

---

## 5. Crypto review

### 5.1 Key derivation

- PVSS secret is a secp256k1 scalar.
- `deriveBodyKey()` runs HKDF-SHA-256 with salt = `commitmentRoot` and info = `"peerit-blindshard-body-key-v1"`.
- This binds the AES key to the public manifest and prevents cross-manifest key reuse.

**Verdict:** correct.

### 5.2 AEAD

- AES-256-GCM with random 12-byte IV per encryption.
- `plaintextHash` is SHA-256(body) and checked on decrypt.

**Verdict:** standard.

### 5.3 PVSS

- Vendored from HiveRelay `packages/client/blind-shards.js`.
- Uses secp256k1 Feldman commitments + DLEQ proofs.
- `recoverSecret` verifies each share against `shareCommitment`.

**Verdict:** appropriate for the public-content threat model.

### 5.4 Custody intent verification

- `verifyCustodyIntent()` is comprehensive but is **not called automatically inside `recoverKey()` for a bare manifest** — it is called in `recoverKey()` at `blind-dealer.mjs:370`.
- Wait: `recoverKey()` does call `verifyCustodyIntent(manifest)` before reconstruction. Good.

**Gap:** `data.js:_hydrate()` calls `recoverBody(m, opts)` which calls `recoverKey()` which calls `verifyCustodyIntent()`. The path is covered.

### 5.5 Pin signing byte-identical to relay verifier

- `blind-dealer.mjs:112-118` signs over `shardPinSignable(pin)` from `js/shard-store-adapter.js`.
- `test/shard-store-adapter.mjs` proves byte-identicality with the relay verifier.

**Verdict:** critical integration is tested.

---

## 6. Performance

### 6.1 Write path

- Body encryption: sub-ms for ≤40 KB (SubtleCrypto AES-GCM).
- PVSS split: depends on secp256k1 scalar math; small constant.
- Network: 1 intent POST per relay + 1 shard PUT per relay + 1 ciphertext PUT per relay.
- For `n=2` current production roster: 2 intent POSTs + 2 share PUTs + 2 ciphertext PUTs = 6 HTTP round-trips per long body.
- With `n=3`: 9 round-trips.

**Impact:** write latency is noticeable for long bodies but does not block UI if run asynchronously. The post record is appended after dispersal completes, so a slow relay slows publishing.

**Mitigation:** fire intent POSTs and ciphertext PUTs in parallel; shares are already parallel. Could add a timeout and fall back to single-blob if the cohort is slow.

### 6.2 Read path

- Feed render: **zero** shard fetches. Bodies hydrate lazily on `getPost` / `listPostsIn` with `hydrate=true`.
- Cold body open: `k` share GETs + 1 ciphertext GET. For `k=2`: 3 sequential-or-parallel HTTP fetches.
- Re-reads: content-addressed body cache (`_bodyCache`) makes repeated opens free.

**Impact:** acceptable for a forum where users open a minority of posts. Hot feeds with many expanded posts could generate many shard fetches; consider hydrating only visible viewport posts.

### 6.3 Bundle size

- `web/js/reader-bundle.js`: 95 KB minified, 178 KB unminified.
- Includes `@noble` secp256k1, blake2b WASM, custody signing, PVSS, HTTP transport.
- Loaded dynamically; does not block initial page load.

**Verdict:** acceptable for the security property. Could be split further if needed.

### 6.4 Storage blowup

- PVSS share shards are roughly the size of the secret (32 bytes each) plus encoding overhead.
- Ciphertext is the same size as the body (AES-GCM overhead ~16 bytes).
- With `n` relays, total storage across the cohort is `n × ciphertext + n × share`. For `n=3`, ~3× body size plus tiny shares.
- This is less than the original Reed-Solomon design (~1.5×) because ciphertext is replicated whole to every relay. The trade-off is durability vs. storage efficiency.

**Honest framing:** "ciphertext is replicated to every relay for durability; PVSS shares are split so no relay holds the key."

---

## 7. Fleet and deployment

### 7.1 Current public relays

| URL | Shard route | Pubkey known? | apiKey known? | Branch? |
|---|---|---|---|---|
| `https://153-75-89-206.sslip.io` | 401 (mounted) | ❌ | ❌ | unknown |
| `https://peerit-relay.onrender.com` | 401 (mounted) | ❌ | ❌ | unknown |

**Required next steps:**
1. SSH to each host or run `deploy/shard-cohort/extract-pubkey.mjs <storage> <url> [apiKey]`.
2. Confirm each host is on `feat/local-shard-cohort` at or after commit `91093c3` (the `shareIndex` fix).
3. Add `RELAY_API_KEY` to each host's `.env` and restart.
4. Paste pubkeys into `config/shard-roster.public.json`.
5. Write `~/.hiverelay-shard-cohort/roster.json` with `apiKey`s.
6. Run `node scripts/reader-bundle-live.mjs ~/.hiverelay-shard-cohort/roster.json`.

### 7.2 Need for a third relay

- The current roster has only 2 relays.
- `blind-dealer.mjs:160` and `data.js:_rosterForDispersal():259` require **at least 3 relays** for dispersal.
- With only 2 relays, `_tryDispersalBox()` returns `null` and falls back to single-blob boxing.

**This is a hard blocker for live dispersal.** Even if we had pubkeys for both relays, dispersal would not activate with `n=2`. A third relay must be added to `config/shard-roster.public.json` and `deploy/web-release.json`.

### 7.3 Independence

- Two same-owner relays + one independent operator is **better** than two same-owner relays, but still not ideal.
- For a credible collusion-resistance claim, the roster should have ≥3 independent legal entities.
- Social/operator recruitment is the long pole; do not block code ship on it, but do not overclaim.

---

## 8. Recommendations (prioritized)

### P0 — must do before live dispersal
1. **Get relay pubkeys and API keys** and fill `config/shard-roster.public.json` / `~/.hiverelay-shard-cohort/roster.json`.
2. **Add a third relay** to the roster; `n=2` cannot disperse.
3. **Confirm public relays run the fixed branch** (`feat/local-shard-cohort` ≥ `91093c3`).
4. **Run `reader-bundle-live.mjs` against the production cohort** and capture evidence in `reports/`.

### P1 — before calling it production-ready
5. **Test PearBrowser shard recovery** in a real webview; if `fetch` is blocked, build a bridge transport.
6. **Add a build gate** that fails if `deploy/web-release.json` `shardRoster` is set but pubkeys are missing — **already done** in this session (`assertShardRoster`).
7. **Add a timeout + fallback** in `_tryDispersalBox()` so a slow/unavailable cohort degrades to single-blob instead of hanging the post publish.

### P2 — hardening
9. **Signed custody-receipt quorum** (Phase 4): collect receipts from relays and treat placement as acknowledged, not fire-and-forget.
10. **Repair pass:** a reader that notices missing shards re-encodes and re-uploads them.
11. **Hashcash/PoW on shard PUTs** if opening writes to untrusted publishers.
12. **Independent operator recruitment:** replace same-owner relays one-by-one.

### P3 — docs / marketing guardrails
13. Update `BLINDSHARD-DESIGN.md` to reflect the shipped PVSS/blake2b/HTTP surface.
14. Add explicit UI copy guardrails: never say "operator can't read" or "encrypted"; say "ciphertext-at-rest", "dispersed across independent relays", "no single relay holds a readable body".

---

## 9. Conclusion

The BlindShard code path is **mechanically complete and tested**. The remaining work is **operational, not cryptographic**: obtain relay credentials, deploy the fixed branch, add a third relay, verify cross-runtime behavior, and recruit independent operators. Until then, peerit should ship with dispersal **disabled in production** (the current fail-closed build behavior) and continue to benefit from v2 opaque logs + single-blob boxing.
