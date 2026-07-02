// release-verify.mjs — the signed-release trust chain (js/release-verify.js +
// scripts/sign-release.mjs). Proves: an offline-key signature over asset-manifest.json
// verifies against the pinned key; any tamper of a file hash / driveKey / relay config
// fails; a wrong pinned key is rejected; and the seed→pubkey derivation matches what
// crypto.js verify expects (so sign-release output is verifiable in-browser). Run:
//   node test/release-verify.mjs

import assert from 'node:assert'
import { createPrivateKey, createPublicKey, sign as nodeSign, randomBytes } from 'node:crypto'
import { releaseSigningMessage, verifyReleaseManifest, RELEASE_ALG } from '../js/release-verify.js'
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
  return { alg: RELEASE_ALG, key, sig, msgVersion: 'peerit-release-v1' }
}

const MANIFEST = {
  files: { 'index.html': 'a'.repeat(64), 'js/app.js': 'b'.repeat(64), 'js/crypto.js': 'c'.repeat(64) },
  driveKey: 'd'.repeat(64),
  webRelease: { relay: 'https://relay.example', readonly: false, releaseKey: '' },
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

  // cosmetic `note` is NOT part of the signed message → changing it must not break verification
  const withNote = { ...MANIFEST, note: 'totally different note' }
  ok((await verifyReleaseManifest({ manifest: withNote, signature, expectedKey: signature.key })).ok, 'cosmetic note change does not affect the signature')

  // ---- tamper: a file hash changed → verification MUST fail ----
  const tamperedFiles = { ...MANIFEST, files: { ...MANIFEST.files, 'js/app.js': 'e'.repeat(64) } }
  await throwsAsync(() => verifyReleaseManifest({ manifest: tamperedFiles, signature, expectedKey: signature.key }), 'a swapped file hash fails the signature')

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
  await throwsAsync(() => verifyReleaseManifest({ manifest: MANIFEST, signature: { alg: RELEASE_ALG, key: 'zz', sig: signature.sig } }), 'malformed key rejected')

  console.log(`\n✅ all ${passed} release-verify checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
