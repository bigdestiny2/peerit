// test/identity-device-store.mjs — the DEVICE tier of web identity durability.
// Run: node test/identity-device-store.mjs
//
// Contract (panel-verified 2026-07-08): the identity minted on the first write
// survives reloads with no passphrase; the seed at rest is AES-256-GCM ciphertext
// under a NON-EXTRACTABLE CryptoKey; the multi-tab first-write race resolves by
// ADOPTION (never a fork); clear() kills the tier; no storage value ever contains
// the seed in cleartext. Node ≥20 has webcrypto but no IndexedDB, so the store's
// kv adapter is injectable — memoryKv() here exercises ALL logic except the
// ~30-line IDB adapter itself (covered by browser smoke).

import assert from 'node:assert'
import { createIdentityStore, memoryKv } from '../js/identity-store.js'
import { DevIdentity } from '../js/identity.js'
import { genKeyPair, ready as cryptoReady } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const HEX64 = /^[0-9a-f]{64}$/i

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

async function main () {
  await cryptoReady()
  const { seedHex, pubHex } = await genKeyPair()
  const entry = { pubkey: pubHex, seed: seedHex, driveKey: pubHex, label: 'anon' }

  console.log('\n— availability + graceful degradation —')
  const noKv = createIdentityStore({ kv: null })
  ok(await noKv.available() === false, 'store without a kv backend reports unavailable')
  ok(await noKv.load() === null, 'load() degrades to null (never throws) when unavailable')
  await noKv.clear() // must not throw
  passed++; console.log('  ✓ clear() is safe when unavailable')
  await assert.rejects(() => noKv.saveOrAdopt(entry), /unavailable/, 'saveOrAdopt refuses loudly when unavailable')
  passed++; console.log('  ✓ saveOrAdopt refuses loudly when unavailable')

  console.log('\n— wrap → persist → reload round-trip —')
  const kv = memoryKv()
  const store = createIdentityStore({ kv })
  ok(await store.available() === true, 'store with kv + webcrypto is available')
  const saved = await store.saveOrAdopt(entry)
  ok(saved.adopted === false && saved.entry.pubkey === pubHex, 'first save inserts our identity (not adopted)')
  const reloaded = await createIdentityStore({ kv }).load() // fresh store instance = a page reload
  ok(reloaded && reloaded.pubkey === pubHex && reloaded.seed === seedHex, 'reload restores the SAME identity (seed round-trips)')
  ok(reloaded.driveKey === pubHex && reloaded.label === 'anon', 'driveKey + label survive')

  console.log('\n— at-rest hygiene: no cleartext seed, non-extractable key —')
  const rec = await kv.get('identity:v1')
  const dump = JSON.stringify({ ...rec, key: undefined, iv: [...rec.iv], ct: [...new Uint8Array(rec.ct)] })
  ok(!dump.includes(seedHex), 'the stored record NEVER contains the seed hex in cleartext')
  ok(rec.key && rec.key.extractable === false, 'wrap CryptoKey is non-extractable (exportKey is impossible via JS)')
  ok(Array.isArray([...rec.iv]) && rec.iv.length === 12, 'AES-GCM iv present (12 bytes)')
  await assert.rejects(
    () => globalThis.crypto.subtle.exportKey('raw', rec.key),
    (e) => /not extractable|InvalidAccessError|non-extractable/i.test(String(e && (e.name + e.message))),
    'exportKey on the wrap key throws')
  passed++; console.log('  ✓ exportKey on the wrap key throws (API-level protection verified)')

  console.log('\n— multi-tab race: LOAD-OR-ADOPT, never a fork —')
  const { seedHex: seed2, pubHex: pub2 } = await genKeyPair()
  const raced = await store.saveOrAdopt({ pubkey: pub2, seed: seed2, driveKey: pub2, label: 'anon' })
  ok(raced.adopted === true && raced.entry.pubkey === pubHex, 'second tab ADOPTS the first identity (its own mint is discarded)')
  ok(raced.entry.seed === seedHex, 'adopted entry carries the WINNING seed (usable for signing immediately)')

  console.log('\n— corrupt record self-heals (ATOMICALLY, review fix 2026-07-08) —')
  const kv2 = memoryKv()
  await kv2.putIfAbsent('identity:v1', { v: 1, garbage: true }) // shape-invalid -> replace in ONE txn
  const store2 = createIdentityStore({ kv: kv2 })
  ok(await store2.load() === null, 'corrupt record loads as null (lurker boot, no crash)')
  const healed = await store2.saveOrAdopt(entry)
  ok(healed.adopted === false && (await store2.load()).pubkey === pubHex, 'saveOrAdopt replaces a shape-corrupt record IN the atomic putIfAbsent (no delete+put window)')
  // Shape-VALID but undecryptable (key/ct mismatch): must NOT be racily replaced —
  // another tab may be signing with it. saveOrAdopt refuses; identity stays session-only.
  const kvBad = memoryKv()
  const alien = await (async () => {
    const k = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new Uint8Array(7))) // wrong length -> unwrap fails HEX64
    return { v: 1, pubkey: 'e'.repeat(64), driveKey: 'e'.repeat(64), label: 'x', key: k, iv, ct }
  })()
  await kvBad.putIfAbsent('identity:v1', alien)
  const storeBad = createIdentityStore({ kv: kvBad })
  await assert.rejects(() => storeBad.saveOrAdopt(entry), /undecryptable/, 'shape-valid-but-undecryptable record is refused, never racily replaced')
  passed++; console.log('  ✓ shape-valid-but-undecryptable record is refused, never racily replaced')

  console.log('\n— clear() kills the tier, FAIL-CLOSED (review fix 2026-07-08) —')
  ok(await store.clear() === true, 'clear() returns true only after a read-back confirms deletion')
  ok(await store.load() === null, 'after clear(), load() is null (next boot is a lurker)')
  // delete rejects -> record survives -> clear() must report FAILURE (a shared
  // machine must never be told "forgotten" while the seed is still restorable).
  const kvStuck = memoryKv()
  await kvStuck.putIfAbsent('identity:v1', { v: 1, garbage: true })
  const stuck = createIdentityStore({ kv: { ...kvStuck, delete: async () => { throw new Error('quota') } } })
  ok(await stuck.clear() === false, 'clear() returns false when the delete fails and the record survives')
  const lying = createIdentityStore({ kv: { ...kvStuck, delete: async () => true } }) // resolves but does not delete
  ok(await lying.clear() === false, 'clear() read-back catches a delete that lied')

  console.log('\n— end-to-end with DevIdentity (the ensureWriterIdentity flow) —')
  const kv3 = memoryKv()
  const store3 = createIdentityStore({ kv: kv3 })
  const idA = new DevIdentity(mem(), mem(), { lazy: true }); await idA.ready()
  await idA.ensureActive('anon') // first write mints…
  const resA = await store3.saveOrAdopt(idA.currentSeedEntry()) // …app.js persists
  ok(resA.adopted === false, 'tab A persisted its fresh mint')
  // "reload": a new lazy identity boots, restores from the device store
  const idB = new DevIdentity(mem(), mem(), { lazy: true }); await idB.ready()
  ok(idB.me().pubkey === null, 'fresh boot starts as a lurker')
  const restored = await store3.load()
  await idB.addUser(restored)
  ok(idB.me().pubkey === idA.me().pubkey, 'reload restores the SAME pseudonym (the "new user every refresh" bug is dead)')
  const sig = await idB.sign('peerit-test')
  ok(HEX64.test(idB.me().pubkey) && sig && sig.publicKey === idA.me().pubkey, 'restored identity SIGNS as the original')

  console.log(`\nidentity-device-store: ${passed} checks passed.`)
}

main().catch((e) => { console.error('❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
