// release-verify.mjs — the signed-release trust chain (js/release-verify.js +
// scripts/sign-release.mjs). Proves: an offline-key signature over asset-manifest.json
// verifies against the pinned key; any tamper of a file hash / driveKey / relay config
// fails; a wrong pinned key is rejected; and the seed→pubkey derivation matches what
// crypto.js verify expects (so sign-release output is verifiable in-browser). Run:
//   node test/release-verify.mjs

import assert from 'node:assert'
import { createPrivateKey, createPublicKey, sign as nodeSign, randomBytes } from 'node:crypto'
import {
  advanceReleaseFloor,
  assertReleaseSequenceProgression,
  releaseManifestIdentity,
  releaseSigningMessage,
  verifyReleaseManifest,
  verifyReleaseManifestWithFloor,
  RELEASE_ALG,
  RELEASE_MSG_VERSION
} from '../js/release-verify.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, m) { try { await fn() } catch { ok(true, m); return } assert.fail('expected throw: ' + m) }

const PKCS8_PREFIX = '302e020100300506032b657004220420'

// Sign a manifest exactly the way scripts/sign-release.mjs does (raw seed → pkcs8 →
// raw pubkey + Ed25519 sig over releaseSigningMessage).
function signManifest (manifest, seedHex) {
  const priv = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seedHex, 'hex'), format: 'der', type: 'pkcs8' })
  const key = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  const sig = nodeSign(null, Buffer.from(releaseSigningMessage(manifest), 'utf8'), priv).toString('hex')
  return { alg: RELEASE_ALG, key, sig, msgVersion: RELEASE_MSG_VERSION }
}

const MANIFEST = {
  releaseSequence: 2,
  files: { 'index.html': 'a'.repeat(64), 'js/app.js': 'b'.repeat(64), 'js/crypto.js': 'c'.repeat(64) },
  controls: { 'sw.js': '1'.repeat(64), 'verify.html': '2'.repeat(64) },
  driveKey: 'd'.repeat(64),
  webRelease: { releaseSequence: 2, relay: 'https://relay.example', readonly: false, releaseKey: '' },
  note: 'cosmetic — excluded from the signed message'
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend available (Ed25519)')

  const seed = randomBytes(32).toString('hex')
  // build-web pins releaseKey into the manifest FIRST, then sign-release signs that
  // manifest — so derive the pubkey and pin it before signing (else webRelease changes
  // after signing and the signature legitimately won't match).
  const pub = createPublicKey(createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seed, 'hex'), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  MANIFEST.webRelease.releaseKey = pub
  const signature = signManifest(MANIFEST, seed)

  // ---- happy path ----
  const r = await verifyReleaseManifest({ manifest: MANIFEST, signature, expectedKey: signature.key })
  ok(r.ok && r.key === signature.key, 'valid signature verifies against the pinned key')

  // ---- durable anti-rollback floor ----
  const floored = await verifyReleaseManifestWithFloor({ manifest: MANIFEST, signature, expectedKey: signature.key })
  ok(floored.releaseSequence === 2 && /^[0-9a-f]{64}$/.test(floored.manifestIdentity), 'valid signed manifest establishes sequence 2 and a SHA-256 identity floor')
  ok(advanceReleaseFloor({ releaseSequence: 2, manifestIdentity: floored.manifestIdentity, floor: floored.floor }).releaseSequence === 2, 'same sequence and same signed identity is idempotent')

  const lower = { ...MANIFEST, releaseSequence: 1, webRelease: { ...MANIFEST.webRelease, releaseSequence: 1 } }
  const lowerSignature = signManifest(lower, seed)
  await throwsAsync(
    () => verifyReleaseManifestWithFloor({ manifest: lower, signature: lowerSignature, expectedKey: signature.key, floor: floored.floor }),
    'a valid older signed release is rejected below the durable sequence floor'
  )

  const fork = { ...MANIFEST, files: { ...MANIFEST.files, 'js/app.js': '9'.repeat(64) } }
  const forkSignature = signManifest(fork, seed)
  await throwsAsync(
    () => verifyReleaseManifestWithFloor({ manifest: fork, signature: forkSignature, expectedKey: signature.key, floor: floored.floor }),
    'a valid different manifest reusing sequence 2 is rejected as a fork'
  )

  const higher = { ...fork, releaseSequence: 3, webRelease: { ...fork.webRelease, releaseSequence: 3 } }
  const higherSignature = signManifest(higher, seed)
  const advanced = await verifyReleaseManifestWithFloor({ manifest: higher, signature: higherSignature, expectedKey: signature.key, floor: floored.floor })
  ok(advanced.floor.releaseSequence === 3, 'a valid changed manifest with a higher sequence advances the floor')
  await throwsAsync(
    () => verifyReleaseManifest({ manifest: MANIFEST, signature, expectedKey: signature.key, expectedSequence: 3 }),
    'page meta and signed manifest sequence must agree'
  )
  await throwsAsync(
    () => verifyReleaseManifest({ manifest: { ...MANIFEST, webRelease: { ...MANIFEST.webRelease, releaseSequence: 1 } }, signature, expectedKey: signature.key }),
    'top-level and webRelease sequence must agree'
  )

  assertReleaseSequenceProgression({ releaseSequence: 2, manifestIdentity: floored.manifestIdentity, priorRecord: { releaseSequence: 2, signingMessageSha256: floored.manifestIdentity } })
  ok(true, 'prepare may reproduce the identical tracked sequence idempotently')
  assert.throws(() => assertReleaseSequenceProgression({ releaseSequence: 2, manifestIdentity: '8'.repeat(64), priorRecord: { releaseSequence: 2, signingMessageSha256: floored.manifestIdentity } }), /already used/)
  ok(true, 'prepare rejects a changed signed artifact reusing a tracked sequence')
  assert.throws(() => assertReleaseSequenceProgression({ releaseSequence: 1, manifestIdentity: '8'.repeat(64), priorRecord: { releaseSequence: 2, signingMessageSha256: floored.manifestIdentity } }), /below the tracked/)
  ok(true, 'prepare rejects a sequence below the tracked release record')
  ok((await releaseManifestIdentity(MANIFEST)) === floored.manifestIdentity, 'browser and build progression use the same signing-message identity')

  // cosmetic `note` is NOT part of the signed message → changing it must not break verification
  const withNote = { ...MANIFEST, note: 'totally different note' }
  ok((await verifyReleaseManifest({ manifest: withNote, signature, expectedKey: signature.key })).ok, 'cosmetic note change does not affect the signature')

  // ---- tamper: a file hash changed → verification MUST fail ----
  const tamperedFiles = { ...MANIFEST, files: { ...MANIFEST.files, 'js/app.js': 'e'.repeat(64) } }
  await throwsAsync(() => verifyReleaseManifest({ manifest: tamperedFiles, signature, expectedKey: signature.key }), 'a swapped file hash fails the signature')

  // ---- tamper: a generated control hash changed → verification MUST fail ----
  const tamperedControls = { ...MANIFEST, controls: { ...MANIFEST.controls, 'verify.html': '3'.repeat(64) } }
  await throwsAsync(() => verifyReleaseManifest({ manifest: tamperedControls, signature, expectedKey: signature.key }), 'a swapped control-file hash fails the signature')

  // ---- tamper: driveKey changed ----
  await throwsAsync(() => verifyReleaseManifest({ manifest: { ...MANIFEST, driveKey: 'f'.repeat(64) }, signature, expectedKey: signature.key }), 'a swapped driveKey fails the signature')

  // ---- tamper: relay config changed (webRelease is signed) ----
  await throwsAsync(() => verifyReleaseManifest({ manifest: { ...MANIFEST, webRelease: { ...MANIFEST.webRelease, relay: 'https://evil.example' } }, signature, expectedKey: signature.key }), 'a swapped relay in webRelease fails the signature')

  // ---- wrong pinned key rejected even with an otherwise-valid signature ----
  await throwsAsync(() => verifyReleaseManifest({ manifest: MANIFEST, signature, expectedKey: 'a'.repeat(64) }), 'signature by an unexpected key is rejected against the pinned key')

  // ---- a signature from a DIFFERENT seed does not verify ----
  const other = signManifest(MANIFEST, randomBytes(32).toString('hex'))
  await throwsAsync(() => verifyReleaseManifest({ manifest: MANIFEST, signature: { ...other, key: signature.key }, expectedKey: signature.key }), 'a foreign signature under the pinned key does not verify')

  // ---- malformed inputs ----
  await throwsAsync(() => verifyReleaseManifest({ manifest: MANIFEST, signature: { alg: 'RSA', key: signature.key, sig: signature.sig } }), 'non-Ed25519 alg rejected')
  await throwsAsync(() => verifyReleaseManifest({ manifest: MANIFEST, signature: { ...signature, msgVersion: 'peerit-release-v1' } }), 'legacy signing message version rejected')
  await throwsAsync(() => verifyReleaseManifest({ manifest: MANIFEST, signature: { alg: RELEASE_ALG, key: 'zz', sig: signature.sig } }), 'malformed key rejected')

  console.log(`\n✅ all ${passed} release-verify checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
