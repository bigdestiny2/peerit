# Peerit ↔ HiveRelay blind-cell public-test canary evidence

**Date:** 2026-07-26 · **Branch:** `codex/peerit-blind-cell-bind-20260726` · **Source:** `1f2a971` (codex/rc1-consolidated-reference-20260721 tip)
**Claim boundary:** `LIVE_PUBLIC_TEST_ONLY` — bounded public-test canary on two **owner-operated** failure domains. **NOT GA**, not independent operators, no T1, no multi-hop (FORWARD bits zero), direct credential-free HTTPS only.

> Signing note: every artifact this document cites (profile pin, catalogue, pin-history, release config, signing request, `web/asset-manifest.sig`) is Ed25519-signed with the offline release key `d6633dea…`. This document itself is unsigned — the keyvault agent's idle timeout expired after the last artifact signature; re-sign with `scripts/blind-public-test-sign.mjs` when the vault is next unlocked.

## 1. What this bind is

Peerit (the reference app) is bound to the two live, independently accepted blind-cell relays as its app-agnostic backend:

| FD | Edge | Relay key | Store | Descriptor head |
|----|------|-----------|-------|-----------------|
| syd-1 | `https://relay-syd.p2phiverelay.xyz:443` | `52f4d783…` | `5193f588…` | seq-4 `2d46ac68…` |
| dal-1 | `https://relay-dal.p2phiverelay.xyz:443` | `8b3f4161…` | `744a7e97…` | seq-2 `4325b15a…` |

Both relays run the boot-restore-fixed entry-4 build: edge amd64 `sha256:ae95c673…`, daemon amd64 `sha256:1903df25…` (superseded pre-fix digests retained in the catalogue for continuity). The relays stay generic and plaintext-blind; **all app logic (moderation, feeds, votes, identity) stays client-side**; no Peerit namespace, schema, or config was added to any relay.

## 2. Re-probed tuple: **WIRE_TUPLE_DRIFT, recorded — not silently accepted**

`scripts/blind-public-test-probe.mjs` → `reports/blind-public-test-describe-probe-20260726.json` (exit 2 = drift-recorded; every verification check passed on both relays):

- **Vendored client artifact** `vendor/hiverelay-blind-client-v1/` exact-verified against its own `authority.json` before any network use (artifact `967cbc42…`, 248195 bytes).
- **Descriptor verification passes on both relays** through the authenticated vendored client (signature, chain continuity, validity window, admission binding) under exact advertised protocol/transport pins.
- **Independent crypto check passes** (second implementation in `scripts/lib/blind-descriptor-parse.mjs` + `@noble` BLAKE2b-256 + `node:crypto` Ed25519): `descriptorHash = BLAKE2b-256("hiverelay.blind.descriptor-hash.v1" ‖ canonical signed descriptor)` recomputed exactly; head signature verifies over `"hiverelay.blind.descriptor.v1" ‖ len64 ‖ unsigned descriptor` under each pinned relay key.
- **The drift:** the vendored v1 artifact pins wire tuple `470a48af…/aaf29c82…/09bd04c8…` (2026-07-16). The deployed relays run the 2026-07-24 wire build whose authority pins `c9ddd235…/199ba15d…/fa54012c…` (wire-authority-v1; the v2 authority only adds FORWARD turn schemas the relays do not enable). All three components differ.
- **Descriptor-advertised build tuple is a placeholder** (0x01/0x02/0x03 repeating patterns + `evidence.example` URLs on both relays) — the disclosed relay-side finding DAL1-IAR-P2-1, routed for the next material rotation.
- **Re-pin honestly impossible:** the relay release's matching browser artifact (`blind-client-control-v3.mjs`) declares `runtimeReady: false`, `realBrowserEvidenceAccepted: false`, `authorizesRelease: false`, and Peerit's substrate verification chain (profile registry external-authority bindings) is built against the v1 artifact. The vendored artifact was therefore **not** re-pinned; compatibility is instead **proven empirically** (§3, §4).

## 3. Two-relay CELL write/readback — PASS

`scripts/blind-public-test-cell-drill.mjs` → `reports/blind-public-test-cell-drill-20260726.json`, through the Peerit substrate client only (`qualifyPermissionlessRelayCandidates` + `createBlindCellRelay`):

- Live genesis→head chain walk (syd 5, dal 3 descriptors), each content-hash fetched and client-verified, accepted into a fresh trust store.
- Qualification with signed admission parameters verified against each descriptor pin (profile 7 / scheme 9 / open, per-relay parameterHash syd `8a796071…` / dal `75bde3f8…`).
- Bounded cell write (65536 B padded PUT) → signed receipt verified → byte-exact readback verified **under each relay's own key**, vault stage `readback-verified`.
- **Boundary proof:** zero occurrences of the app plaintext marker or any app schema vocabulary in every relay-visible request byte on both relays.

## 4. Production-profile drills — PASS (A/B), INBOX/CORE deferred (C)

`scripts/blind-public-test-production-drills.mjs` → `reports/blind-public-test-production-drills-20260726.json`:

- **A — write/readback/recovery:** deliver, then simulated client restart (fresh vault instance + freshly qualified adapter over the same persisted kv) → `revalidateReadback` performs **exactly one new capability-bound GET and zero PUTs**, stage `readback-verified`, byte-exact, on both relays. The lost-response-after-commit reconcile (GET-only, never resend) is proven in fixture `test/peerit-hiverelay-real-e2e.mjs`; live fault injection on shared relays is not consented → deferred.
- **B — client-side moderation/feed/vote:** real signed `post` + `vote` records in one inner operation batch, delivered as one opaque cell per relay, read back byte-exact, then decoded and processed **entirely client-side**: `ranking.tally` (score 1), `rankPostsWindow`, `eligibleCommunityAuthors` + `aggregateReports` + `applyModerationPolicy` (visibility `visible`). Wire capture again shows zero app vocabulary. Report/modaction ops require PoW and were not written to shared relays (scope note in the report).
- **C — INBOX/CORE unary:** relays advertise families 3/4 and price them in the signed admission parameters, but the vendored v1 control surface exports no INBOX/CORE request constructors — the app's own code paths cannot compose them today. **Deferred, not faked.** Relay-side INBOX/CORE surface is covered by relay-side acceptance evidence.

## 5. Signed app artifact (canary, not deployed)

- `npm run build-web` with substrate profile `blind-v1` + both relay hints (relayBackend = substrate blind path, **no outbox**): 85 files in `web/`, releaseSequence **12** (advances past 11).
- Offline-signed via keyvault injection (`peerit/release/signing-seed`, never printed): `web/asset-manifest.sig`, Ed25519 key `d6633dea…` (matches `deploy/web-release.json` pin).
- `verifyReleaseManifest` VALID (sequence 12); `verifyPeeritSubstrateRuntimeArtifactV1` VALID — appArtifactHash `b34628cb7580e8de…`, canonical WebAssetManifestV1 hash `fb79fd6c8ec4bd62…`, 81 assets.
- `deploy/web-release-pin-history.json` records 11 → 12 continuity; pin-history, release config, and signing request are each signed (`*.sig.json`, key `d6633dea…`).
- Built `index.html` CSP `connect-src` carries exactly `'self' hyper: pear: https://relay-syd.p2phiverelay.xyz https://relay-dal.p2phiverelay.xyz`; `render.yaml` + `deploy/render-security-headers.json` updated to match (`verify-render-blueprint` PASS). `scripts/csp.mjs` needed no edit — substrate build derives origins from the signed hints.
- **Not deployed.** peerit.site, its Render config, DNS, and channels untouched.
- The GA product gate (`assertPeeritBlindProductReleaseReady`) remains honestly blocked; the canary signing request is produced by `scripts/blind-public-test-signing-request.mjs` with the sequence-progression assertion retained.

## 6. Blockers closed for this bind (and what stays open)

Closed, bind-scoped, with signed artifacts:

- **Signed Peerit profile pin:** `config/blind-public-test-profile-pin.json` (+`.sig.json`) — SubstrateTupleV1 + both relay identities + operation/admission profile + drift disclosure, release-key signed. (The production `PeeritHiveRelayProfilePinV1` cannot exist yet — the production release authority root is intentionally null.)
- **Authenticated runtime authority:** the signed catalogue `config/blind-public-test-bind.scaffold.json` (+`.sig.json`) — descriptor heads/chains, store ids, admission hashes, image digests, `bound: true` on both relays, `seed_publish: false` kept.
- **Permissionless relay CSP:** both relay origins in the built artifact + static headers.
- **Capability recovery:** device-local restart recovery proven (§4A); portable cross-device bundle format exists (`js/substrate/peerit-recovery-bundle-v1.mjs`) but its consumer wiring remains unassembled — recorded deferred.

Still open (unchanged, GA-scope, honestly not claimed): the full `PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS` / product-gate list (production authority, permissionless candidate feeds, first-visit verifier distribution, external codec decoders, portable capability recovery wiring).

## 7. Consumer gaps found by this bind (for the substrate backlog)

- `PEERIT-BIND-GAP-FIRST-CONTACT` — first-contact qualification of a non-genesis relay fails closed (`UNTRUSTED_RELAY_IDENTITY`) without a chain-seeded trust store; drills seed by live chain walk.
- `PEERIT-BIND-GAP-LEASE-CLASS` — `createBlindCellRelay` defaults `leaseClass 4`; the deployed admission offers CELL PUT only at leaseClass 1 (10 units). Drills redeem the advertised class 1; the adapter should negotiate from verified admission parameters.
- `PEERIT-BIND-GAP-PROFILE-HASH-PLACEHOLDERS` — relay descriptors advertise placeholder protocol/transport profileHash values, so contradiction pins are currently vacuous (relay-side follow-up DAL1-IAR-P2-1).

## 8. Reproduce

```sh
cd 02-apps/peerit-release-bind
npm ci
node scripts/blind-public-test-probe.mjs                 # exit 2 = drift recorded, all checks pass
node scripts/blind-public-test-cell-drill.mjs            # exit 0 = two-relay write/readback PASS
node scripts/blind-public-test-production-drills.mjs     # exit 0 = A/B PASS on both relays
node scripts/blind-public-test-sign.mjs verify \
  config/blind-public-test-profile-pin.json \
  config/blind-public-test-bind.scaffold.json \
  deploy/web-release-pin-history.json
node scripts/verify-render-blueprint.mjs
```

## 9. What remains before any wider claim

1. **Owner decision on the recorded WIRE_TUPLE_DRIFT** — re-vendor an accepted v3-class browser artifact (requires upstream `authorizesRelease: true`) and re-run the substrate verification chain, or formally accept the v1 artifact under the canary boundary.
2. Relay-side rotation replacing the placeholder descriptor build/profile hashes (DAL1-IAR-P2-1), then a fresh re-probe.
3. INBOX/CORE client composition in the app control surface (or an explicit substrate decision that Peerit v1 ships CELL-only).
4. Seed-publish owner review (still `seed_publish: false`); independent third-party relay operators before any "independent failure domains" claim; GA product gate.
