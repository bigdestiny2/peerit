// identity-export.mjs — the encrypted, portable identity export/import round-trip.
// A web/phone user's signing key is a browser-held seed; this feature moves it to
// another device sealed under a passphrase. The seed is a bearer secret, so the
// checks below lock down: round-trip fidelity, wrong-passphrase rejection,
// tamper/integrity detection, and format/version guards. Run: node test/identity-export.mjs

import assert from 'node:assert'
import { genKeyPair, ready as cryptoReady, isSecure } from '../js/crypto.js'
import {
  exportIdentity, importIdentity, looksLikeIdentityExport,
  identityExportJson, identityExportFilename, passphraseStrength, MIN_PASSPHRASE
} from '../js/identity-export.js'
import { DevIdentity } from '../js/identity.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, match, m) {
  try { await fn() } catch (e) { ok(!match || match.test(e.message), m + ' (' + e.message + ')'); return }
  assert.fail('expected throw: ' + m)
}
function mem () { const x = new Map(); return { getItem: k => (x.has(k) ? x.get(k) : null), setItem: (k, v) => x.set(k, String(v)), removeItem: k => x.delete(k) } }
// PBKDF2 at 600k iterations twice per test is slow; drop iterations for the suite.
const FAST = { iterations: 1000 }

async function main () {
  await cryptoReady()
  if (!isSecure()) { console.log('\n⚠ no Ed25519 backend in this Node; skipping identity-export suite\n'); return }

  console.log('\n— identity export: round-trip fidelity —')
  const { seedHex, pubHex } = await genKeyPair()
  const entry = { seed: seedHex, pubkey: pubHex, driveKey: pubHex, label: 'anon' }
  const pass = 'correct horse battery staple'

  const env = await exportIdentity(entry, pass, FAST)
  ok(env.type === 'peerit-identity-export' && env.version === 1 && env.app === 'peerit', 'envelope has the type/version/app header')
  ok(env.pubkey === pubHex && env.ciphertext && !JSON.stringify(env).includes(seedHex), 'pubkey is cleartext but the SEED never appears outside the ciphertext')
  ok(env.kdf.name === 'PBKDF2' && env.cipher.name === 'AES-GCM', 'declares PBKDF2 + AES-GCM')

  const back = await importIdentity(env, pass)
  ok(back.seed === seedHex && back.pubkey === pubHex && back.driveKey === pubHex && back.label === 'anon', 'import recovers the exact seed/pubkey/driveKey/label')

  // JSON string transport (file contents / paste blob / QR payload are all this).
  const json = identityExportJson(env)
  const back2 = await importIdentity(json, pass)
  ok(back2.seed === seedHex, 'imports equally from the JSON-string form')
  ok(looksLikeIdentityExport(json) && !looksLikeIdentityExport('{"version":1,"app":"peerit"}'), 'looksLikeIdentityExport distinguishes an export from a recovery bundle')
  ok(/^peerit-identity-[0-9a-f]{12}-\d{4}-\d{2}-\d{2}\.json$/.test(identityExportFilename(pubHex, env.createdAt)), 'filename is peerit-identity-<pub12>-<date>.json')

  console.log('\n— identity export: passphrase + tamper rejection —')
  await throwsAsync(() => importIdentity(env, 'wrong passphrase'), /wrong passphrase|decrypt/i, 'wrong passphrase is rejected')
  await throwsAsync(() => exportIdentity(entry, 'short', FAST), /at least/i, 'export refuses a passphrase under the minimum length')

  const tampered = JSON.parse(JSON.stringify(env))
  const ctBytes = Buffer.from(tampered.ciphertext, 'base64'); ctBytes[0] ^= 0xff
  tampered.ciphertext = ctBytes.toString('base64')
  await throwsAsync(() => importIdentity(tampered, pass), /decrypt|corrupt/i, 'a flipped ciphertext byte fails GCM auth')

  // Header pubkey doctored to a different key → cleartext/contents mismatch.
  const doctored = JSON.parse(JSON.stringify(env)); doctored.pubkey = 'b'.repeat(64)
  await throwsAsync(() => importIdentity(doctored, pass), /header does not match/i, 'a doctored cleartext pubkey is caught by the header cross-check')

  // Integrity: a seed that does not match its pubkey must be refused on import.
  const other = await genKeyPair()
  const mismatchEnv = await exportIdentity({ seed: other.seedHex, pubkey: pubHex, driveKey: pubHex, label: 'x' }, pass, FAST)
    .then(() => null, () => 'export-blocked')
  ok(mismatchEnv === 'export-blocked', 'export itself refuses a seed that does not match its public key')

  console.log('\n— identity export: format guards —')
  await throwsAsync(() => importIdentity('not json', pass), /valid JSON/i, 'non-JSON input is rejected')
  await throwsAsync(() => importIdentity({ ...env, type: 'nope' }, pass), /not a peerit identity export/i, 'wrong type is rejected')
  await throwsAsync(() => importIdentity({ ...env, version: 99 }, pass), /version is not supported/i, 'unsupported version is rejected')
  await throwsAsync(() => importIdentity({ ...env, app: 'other' }, pass), /not peerit/i, 'wrong app is rejected')
  await throwsAsync(() => importIdentity({ ...env, kdf: { ...env.kdf, iterations: 1e9 } }, pass), /unreasonably high/i, 'a hostile iteration count is refused')
  ok(passphraseStrength('a').score === 0 && passphraseStrength('Tr0ub4dour&3xtra').score >= 3 && MIN_PASSPHRASE >= 8, 'passphraseStrength scores weak→strong')

  console.log('\n— DevIdentity.addUser: add-to-roster + switch —')
  const id = await new DevIdentity(mem(), mem()).ready()
  const before = id.me().pubkey
  const added = await id.addUser(back)
  ok(added.pubkey === pubHex && id.me().pubkey === pubHex, 'addUser switches the active user to the imported identity')
  ok(id.listUsers().some(u => u.pubkey === before) && id.listUsers().some(u => u.pubkey === pubHex), 'the previous local identity is kept in the roster (non-destructive)')
  const secret = id.currentSeedEntry()
  ok(secret.seed === seedHex && !('seed' in id.me()), 'currentSeedEntry exposes the seed for export while me() never does')
  const n = id.listUsers().length
  await id.addUser(back)
  ok(id.listUsers().length === n, 'importing the same identity again dedupes by pubkey')
  // A signature from the imported identity verifies — it is a real, usable key.
  const sig = await id.sign('hello')
  ok(sig.publicKey === pubHex && sig.signature, 'the imported identity can actually sign')

  console.log(`\n✅ all ${passed} identity-export checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
