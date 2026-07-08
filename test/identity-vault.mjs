// identity-vault.mjs — the passphrase-unlock durable identity vault.
//
// A1 (test/identity-key-at-rest.mjs) proved the web/production seed is NEVER
// written to cleartext storage — which, correctly, means a plain reload mints a
// fresh in-memory identity. This vault is the UX follow-up: a user opts into
// durability by choosing a passphrase, and ONLY a PBKDF2 + AES-256-GCM envelope
// (the same one identity-export.js ships) lands in localStorage under
// 'peerit:vault:v1'. This test locks the four contract points:
//
//   1. round-trip: create identity → set passphrase → persist → simulate reload
//      → unlock with the correct passphrase → the SAME pubkey signs and verifies;
//   2. wrong passphrase → decrypt fails, NO identity restored, seed never exposed;
//   3. write-spy: no persisted value EVER contains the raw seed (ciphertext only);
//   4. no-vault path still mints a fresh in-memory identity (A1 behavior preserved).
//
// Run: node test/identity-vault.mjs

import assert from 'node:assert'
import { ready as cryptoReady, isSecure, verify as edVerify } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import {
  VAULT_KEY, hasVault, vaultPubkey, saveVault, unlockVault, clearVault, isVaultEnvelope
} from '../js/identity-vault.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, match, m) {
  try { await fn() } catch (e) { ok(!match || match.test(e.message), m + ' (' + e.message + ')'); return }
  assert.fail('expected throw: ' + m)
}

const ROSTER_KEY = 'peerit:dev:users'
const HEX64 = /^[0-9a-f]{64}$/i
// PBKDF2 at 600k iterations is slow; drop it for the suite exactly like the
// identity-export test does. The at-rest / round-trip guarantees are unaffected.
const FAST = { iterations: 1000 }

// A localStorage stand-in that records EVERY write, so we can assert exactly what
// (if anything) touched disk — the same spy shape as identity-key-at-rest.mjs.
function spyStorage () {
  const m = new Map()
  return {
    _map: m,
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    dump: () => JSON.stringify([...m.entries()])
  }
}
function mem () { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) } }

// Build a fresh web/production (forceDev) identity against explicit storage —
// exactly resolveRuntime's web opts minus the relay transport fields DevIdentity
// ignores. This is the same construction the A1 test pins.
async function freshWebIdentity (storage, session) {
  const id = createIdentity({ pear: null, forceDev: true, storage, session })
  await id.ready()
  return id
}

async function main () {
  await cryptoReady()
  if (!isSecure()) {
    console.log('\n⚠ no Ed25519 backend in this Node; skipping identity-vault suite (needs real signatures)\n')
    return
  }

  console.log('\n— 1. round-trip: set passphrase → persist → reload → unlock → same key signs —')
  {
    const disk = spyStorage() // localStorage that survives the "reload"
    const id1 = await freshWebIdentity(disk, mem())
    const before = id1.me().pubkey
    const secret = id1.currentSeedEntry()
    ok(HEX64.test(before) && HEX64.test(secret.seed), 'a fresh web identity has a real pubkey + in-memory seed')

    // User opts into durability: seal the seed under a passphrase into VAULT_KEY.
    const pass = 'correct horse battery staple'
    const env = await saveVault(disk, secret, pass, FAST)
    ok(isVaultEnvelope(env) && env.pubkey === before, 'saveVault returns a vault envelope anchored to the pubkey')
    ok(disk.getItem(VAULT_KEY) !== null && hasVault(disk), `the encrypted vault is persisted under '${VAULT_KEY}'`)
    ok(vaultPubkey(disk) === before, 'the unlock UI can read the vault pubkey WITHOUT the passphrase')

    // Simulate a RELOAD: a brand-new in-memory identity is minted (A1), unaware of
    // the old seed. Same disk (the vault survives), fresh session + memory roster.
    const id2 = await freshWebIdentity(disk, mem())
    ok(id2.me().pubkey !== before, 'after reload, A1 mints a DIFFERENT fresh in-memory identity by default')

    // Unlock the vault and restore the original identity into the in-memory path.
    const entry = await unlockVault(disk, pass)
    ok(entry.pubkey === before && entry.seed === secret.seed, 'unlock with the correct passphrase recovers the exact seed + pubkey')
    await id2.restoreFromVault(entry)
    ok(id2.me().pubkey === before, 'the restored identity is now the active one — SAME pubkey survives reload')

    // The restored identity actually signs, and the signature verifies.
    const sig = await id2.sign('durable hello')
    ok(sig.publicKey === before, 'the restored in-memory identity produces a signature under the original key')
    ok(await edVerify(sig.publicKey, `pear.app.${sig.driveKey}:peerit:durable hello`, sig.signature), 'that signature verifies against the original public key')
  }

  console.log('\n— 2. wrong passphrase → clean failure, nothing restored, seed never exposed —')
  {
    const disk = spyStorage()
    const id = await freshWebIdentity(disk, mem())
    const secret = id.currentSeedEntry()
    await saveVault(disk, secret, 'the right passphrase', FAST)

    // Reload, then attempt to unlock with the WRONG passphrase.
    const id2 = await freshWebIdentity(disk, mem())
    const mintedAfterReload = id2.me().pubkey
    await throwsAsync(() => unlockVault(disk, 'the WRONG passphrase'), /decrypt|wrong passphrase/i, 'wrong passphrase fails to decrypt')
    // No partial state: nothing was restored, the fresh identity is untouched, and
    // the vault is still intact on disk for a retry (no lockout, no wipe).
    ok(id2.me().pubkey === mintedAfterReload, 'no identity was restored — the fresh in-memory identity is unchanged')
    ok(hasVault(disk), 'the vault is still present after a wrong attempt (retry, not lockout)')
    // The plaintext seed appears NOWHERE in persisted storage.
    ok(!disk.dump().includes(secret.seed), 'the raw seed is not exposed anywhere in storage after a failed unlock')
  }

  console.log('\n— 3. write-spy: only AES-GCM ciphertext is persisted, never the raw seed —')
  {
    const disk = spyStorage()
    const id = await freshWebIdentity(disk, mem())
    const secret = id.currentSeedEntry()
    await saveVault(disk, secret, 'a good long passphrase', FAST)

    const dumped = disk.dump()
    // The seed must never appear in ANY persisted value — the whole point of A1.
    ok(!dumped.includes(secret.seed), 'the raw seed does NOT appear anywhere in persisted storage')
    // The A1 cleartext roster key must remain absent — the vault does not resurrect it.
    ok(disk.getItem(ROSTER_KEY) === null, `the A1 cleartext roster key '${ROSTER_KEY}' is still never written`)
    // The ONLY persisted key is the vault, and it is a valid ciphertext envelope.
    const keys = [...disk._map.keys()]
    ok(keys.length === 1 && keys[0] === VAULT_KEY, 'the vault is the only thing on disk')
    const env = JSON.parse(disk.getItem(VAULT_KEY))
    ok(env.cipher && env.cipher.name === 'AES-GCM' && typeof env.ciphertext === 'string' && env.ciphertext.length > 0, 'the persisted value is an AES-256-GCM ciphertext envelope')
    ok(env.kdf && env.kdf.name === 'PBKDF2' && env.kdf.hash === 'SHA-256', 'sealed with the reused PBKDF2-SHA256 KDF (no bespoke crypto)')
    // The pubkey is the only cleartext identity field — by design, as an anchor.
    ok(env.pubkey === id.me().pubkey && !HEX64.test(String(env.seed || '')), 'only the pubkey is cleartext; there is no cleartext seed field')

    // saveVault refuses to persist if a raw seed would ever leak into the string.
    await throwsAsync(() => saveVault(disk, { seed: 'nothex', pubkey: id.me().pubkey }, 'a good long passphrase', FAST), /no exportable seed|nothing to export|invalid/i, 'saveVault rejects a non-hex seed rather than persisting garbage')
  }

  console.log('\n— 4. no-vault path preserves A1: a fresh in-memory identity, nothing on disk —')
  {
    const disk = spyStorage()
    ok(!hasVault(disk) && vaultPubkey(disk) === null, 'a clean device reports no vault')
    const id = await freshWebIdentity(disk, mem())
    ok(HEX64.test(id.me().pubkey), 'with no vault, boot still mints a working fresh in-memory identity (A1 behavior)')
    ok(disk.getItem(ROSTER_KEY) === null && disk.getItem(VAULT_KEY) === null, 'and nothing at all is persisted — not the roster, not a vault')
    const sig = await id.sign('anon hello')
    ok(await edVerify(sig.publicKey, `pear.app.${sig.driveKey}:peerit:anon hello`, sig.signature), 'the fresh in-memory identity signs and verifies')

    // unlockVault on a device with no vault fails clearly (nothing to unlock).
    await throwsAsync(() => unlockVault(disk, 'whatever'), /no saved identity/i, 'unlockVault on a vault-less device reports there is nothing to unlock')
  }

  console.log('\n— 5. clearVault forgets durability without touching the in-memory identity —')
  {
    const disk = spyStorage()
    const id = await freshWebIdentity(disk, mem())
    const pub = id.me().pubkey
    await saveVault(disk, id.currentSeedEntry(), 'a good long passphrase', FAST)
    ok(hasVault(disk), 'vault present before forget')
    clearVault(disk)
    ok(!hasVault(disk) && disk.getItem(VAULT_KEY) === null, 'clearVault removes the ciphertext from disk')
    ok(id.me().pubkey === pub, 'the live in-memory identity keeps working after forgetting the vault')
  }

  console.log('\n— 6. isVaultEnvelope guards against malformed / foreign blobs —')
  {
    ok(isVaultEnvelope({ type: 'peerit-identity-export', ciphertext: 'x' }) === true, 'accepts a well-formed export/vault envelope')
    ok(isVaultEnvelope({ type: 'something-else', ciphertext: 'x' }) === false, 'rejects a foreign type')
    ok(isVaultEnvelope(null) === false && isVaultEnvelope('nope') === false && isVaultEnvelope([]) === false, 'rejects null / string / array')
    // A corrupt stored blob is treated as "no vault", so boot degrades to A1's mint path.
    const disk = spyStorage()
    disk.setItem(VAULT_KEY, '{ not valid json')
    ok(hasVault(disk) === false && vaultPubkey(disk) === null, 'a corrupt vault blob reads as no vault (boot falls back to a fresh identity)')
  }

  console.log(`\n✅ all ${passed} identity-vault checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
