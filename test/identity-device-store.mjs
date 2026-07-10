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
import {
  activateDurableIdentity,
  assertDurableIdentity,
  beginIdentityForget,
  createIdentityStore,
  ensureDurableIdentityForWrite,
  finishIdentityForget,
  hasIdentityForgetTombstone,
  memoryKv,
  resetCorruptDurableIdentity
} from '../js/identity-store.js'
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

  const unavailableId = new DevIdentity(mem(), mem(), { lazy: true }); await unavailableId.ready()
  await assert.rejects(() => activateDurableIdentity(unavailableId, noKv), /unavailable/, 'public writer activation fails closed without durable storage')
  ok(unavailableId.me().pubkey === null, 'failed durable activation remains a lurker (no session-only key)')

  const failingKv = { ...memoryKv(), putIfAbsent: async () => { throw new Error('quota exceeded') } }
  const failingStore = createIdentityStore({ kv: failingKv })
  const failingId = new DevIdentity(mem(), mem(), { lazy: true }); await failingId.ready()
  await assert.rejects(() => activateDurableIdentity(failingId, failingStore), /quota exceeded/, 'public writer activation propagates persistence failure')
  ok(failingId.me().pubkey === null, 'persistence failure never activates the unpersisted candidate')

  console.log('\n— wrap → persist → reload round-trip —')
  const kv = memoryKv()
  const store = createIdentityStore({ kv })
  ok(await store.available() === true, 'store with kv + webcrypto is available')
  const saved = await store.saveOrAdopt(entry)
  ok(saved.adopted === false && saved.entry.pubkey === pubHex, 'first save inserts our identity (not adopted)')
  const reloaded = await createIdentityStore({ kv }).load() // fresh store instance = a page reload
  ok(reloaded && reloaded.pubkey === pubHex && reloaded.seed === seedHex, 'reload restores the SAME identity (seed round-trips)')
  ok(reloaded.driveKey === pubHex && reloaded.label === 'anon', 'driveKey + label survive')

  console.log('\n— decrypted entry integrity is cryptographic, not shape-only —')
  const other = await genKeyPair()
  await assert.rejects(
    () => createIdentityStore({ kv: memoryKv() }).saveOrAdopt({ ...entry, pubkey: other.pubHex }),
    /seed does not match public key/,
    'store refuses a seed paired with another public key')
  passed++; console.log('  ✓ store refuses a seed paired with another public key')
  await assert.rejects(
    () => createIdentityStore({ kv: memoryKv() }).saveOrAdopt({ ...entry, driveKey: 'not-a-drive-key' }),
    /invalid drive key/,
    'store refuses a malformed drive key')
  passed++; console.log('  ✓ store refuses a malformed drive key')
  const tamperKv = memoryKv(); const tamperStore = createIdentityStore({ kv: tamperKv })
  await tamperStore.saveOrAdopt(entry)
  const tamperedHeader = await tamperKv.get('identity:v1'); tamperedHeader.pubkey = other.pubHex
  ok(await tamperStore.load() === null, 'load rejects decrypted seed when the durable pubkey header was swapped')
  const driveKv = memoryKv(); const driveStore = createIdentityStore({ kv: driveKv })
  await driveStore.saveOrAdopt(entry)
  const malformedDrive = await driveKv.get('identity:v1'); malformedDrive.driveKey = 'bad'
  ok(await driveStore.load() === null, 'load rejects a decrypted record with malformed driveKey')

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

  console.log('\n— deliberate replacement is an atomic pubkey CAS —')
  const replaced = await store.replace({ pubkey: pub2, seed: seed2, driveKey: pub2, label: 'imported B' }, { expectedPubkey: pubHex })
  ok(replaced.replaced && (await store.load()).pubkey === pub2, 'import B atomically replaces the observed durable A record')
  const third = await genKeyPair()
  await assert.rejects(
    () => store.replace({ pubkey: third.pubHex, seed: third.seedHex, driveKey: third.pubHex }, { expectedPubkey: pubHex }),
    /changed in another tab/,
    'stale A→C CAS cannot overwrite B')
  passed++; console.log('  ✓ stale A→C CAS cannot overwrite B')
  ok((await store.load()).pubkey === pub2, 'failed stale CAS leaves B durable')

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

  console.log('\n— explicit corrupt-record recovery is exact-token CAS —')
  const corruptState = await storeBad.inspect()
  ok(corruptState.status === 'corrupt' && corruptState.reason === 'undecryptable' && !!corruptState.token, 'inspection surfaces hidden undecryptable state with an exact reset token')
  const alien2 = { ...alien, createdAt: Date.now() + 1, iv: globalThis.crypto.getRandomValues(new Uint8Array(12)) }
  await kvBad.delete('identity:v1')
  await kvBad.putIfAbsent('identity:v1', alien2)
  await assert.rejects(() => storeBad.resetCorrupt({ expectedToken: corruptState.token }), /changed in another tab/, 'a stale corrupt-state token cannot delete a replacement')
  passed++; console.log('  ✓ a stale corrupt-state token cannot delete a replacement')
  const currentCorrupt = await storeBad.inspect()
  ok(await storeBad.resetCorrupt({ expectedToken: currentCorrupt.token }), 'explicit reset deletes exactly the currently inspected corrupt record')
  ok((await storeBad.inspect()).status === 'empty', 'reset leaves an empty device tier that can mint again')
  await storeBad.saveOrAdopt(entry)
  ok((await storeBad.load()).pubkey === pubHex, 'a new durable writer can be saved after explicit corrupt reset')

  const importKv = memoryKv()
  await importKv.putIfAbsent('identity:v1', alien)
  const importStore = createIdentityStore({ kv: importKv })
  const importCorrupt = await importStore.inspect()
  const importedOverCorrupt = await importStore.replace(entry, { expectedToken: importCorrupt.token })
  ok(importedOverCorrupt.replaced && (await importStore.load()).pubkey === pubHex, 'deliberate import atomically replaces the exact corrupt record without delete+insert')
  await assert.rejects(() => importStore.replace({ pubkey: pub2, seed: seed2, driveKey: pub2 }, { expectedToken: importCorrupt.token }), /changed in another tab/, 'the consumed corrupt token cannot overwrite the imported valid identity')
  passed++; console.log('  ✓ the consumed corrupt token cannot overwrite the imported valid identity')

  console.log('\n— arbitrary legacy corruption receives an exact generation token —')
  const collisionKv = memoryKv()
  const normalizedCollisionA = { v: 1, key: { broken: 'key-a' }, iv: { malformed: 'iv-a' }, ct: { malformed: 'ct-a' }, createdAt: 0, extra: 'generation-a' }
  const normalizedCollisionB = { v: 1, key: { broken: 'key-b' }, iv: { malformed: 'iv-b' }, ct: { malformed: 'ct-b' }, createdAt: 0, extra: 'generation-b' }
  await collisionKv.putIfAbsent('identity:v1', normalizedCollisionA)
  const collisionStore = createIdentityStore({ kv: collisionKv })
  const collisionA = await collisionStore.inspect()
  ok(collisionA.status === 'corrupt' && !!collisionA.token, 'first arbitrary structured-clone corruption is atomically tagged for exact observation')
  await collisionKv.delete('identity:v1')
  await collisionKv.putIfAbsent('identity:v1', normalizedCollisionB)
  const collisionB = await collisionStore.inspect()
  ok(collisionB.status === 'corrupt' && collisionB.token !== collisionA.token, 'a distinct corrupt replacement gets a distinct token even when old normalized fields would collide')
  await assert.rejects(() => collisionStore.resetCorrupt({ expectedToken: collisionA.token }), /changed in another tab/, 'stale corrupt observation cannot delete the distinct replacement')
  passed++; console.log('  ✓ stale corrupt observation cannot delete the distinct replacement')
  await assert.rejects(() => collisionStore.replace(entry, { expectedToken: collisionA.token }), /changed in another tab/, 'stale corrupt observation cannot replace the distinct replacement during import')
  passed++; console.log('  ✓ stale corrupt observation cannot replace the distinct replacement during import')

  const unavailableInspectKv = { ...memoryKv(), getOrTag: async () => { throw new Error('idb temporarily unreadable') } }
  const unavailableInspectStore = createIdentityStore({ kv: unavailableInspectKv })
  ok((await unavailableInspectStore.inspect()).status === 'unavailable', 'inspect distinguishes unavailable storage from an empty device tier')
  await assert.rejects(() => unavailableInspectStore.resetCorrupt({ expectedToken: collisionB.token }), /no longer corrupt|unavailable/i, 'reset fails closed when the exact device generation cannot be inspected')
  passed++; console.log('  ✓ reset fails closed when the exact device generation cannot be inspected')
  await assert.rejects(() => unavailableInspectStore.replace(entry), /exact inspected record|verified empty state/i, 'import replacement cannot treat unavailable inspection as verified empty storage')
  passed++; console.log('  ✓ import replacement cannot treat unavailable inspection as verified empty storage')

  console.log('\n— corrupt reset always discards the active session signer —')
  const resetKv = memoryKv()
  await resetKv.putIfAbsent('identity:v1', { v: 1, key: { broken: true }, iv: { malformed: true }, ct: { malformed: true }, pubkey: null })
  const resetStore = createIdentityStore({ kv: resetKv })
  const resetObserved = await resetStore.inspect()
  const resetIdentity = new DevIdentity(mem(), mem(), { lazy: true }); await resetIdentity.ready(); await resetIdentity.ensureActive('session-only-before-reset')
  const sessionSigner = resetIdentity.me().pubkey
  ok(HEX64.test(sessionSigner) && resetObserved.pubkey === null, 'adversarial reset starts with an active signer that the corrupt header cannot identify')
  await resetCorruptDurableIdentity(resetIdentity, resetStore, { expectedToken: resetObserved.token })
  ok(resetIdentity.me().pubkey === null && (await resetStore.inspect()).status === 'empty', 'reset deactivates every in-memory signer while deleting the exact corrupt generation')
  await ensureDurableIdentityForWrite(resetIdentity, resetStore)
  ok(resetIdentity.me().pubkey !== sessionSigner && (await resetStore.load()).pubkey === resetIdentity.me().pubkey, 'the next write gate mints and persists a new signer instead of retaining the session-only key')

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

  console.log('\n— forget tombstone survives every cross-store failure window —')
  let unreadableDeactivated = false
  let unreadableDeviceDeletes = 0
  let unreadableWrites = 0
  const unreadableStorage = {
    getItem: () => { throw new Error('localStorage read denied') },
    setItem: () => { unreadableWrites++ },
    removeItem: () => {}
  }
  ok(hasIdentityForgetTombstone(unreadableStorage), 'an unreadable tombstone store is fail-closed, never mistaken for an absent marker')
  await assert.rejects(
    () => finishIdentityForget({
      storage: unreadableStorage,
      deviceStore: { clear: async () => { unreadableDeviceDeletes++; return true } },
      deactivate: () => { unreadableDeactivated = true },
      vaultPresent: () => false,
      removeVault: () => {}
    }),
    /cannot verify.*forget marker/i,
    'cleanup cannot declare success while marker storage is unreadable'
  )
  passed++; console.log('  ✓ cleanup cannot declare success while marker storage is unreadable')
  ok(unreadableDeactivated && unreadableDeviceDeletes === 0, 'unreadable marker storage deactivates the session but performs no unverifiable key deletion')
  await assert.rejects(async () => beginIdentityForget(unreadableStorage, pubHex), /cannot verify durable identity-forget storage/i, 'a new forget transaction refuses before deleting when its marker cannot be read')
  passed++; console.log('  ✓ a new forget transaction refuses before deleting when its marker cannot be read')
  ok(unreadableWrites === 0, 'unreadable-marker refusal does not overwrite unknown durable state')

  const forgetStorage = mem()
  let devicePresent = true
  let vaultPresent = true
  let active = true
  const order = []
  beginIdentityForget(forgetStorage, pubHex)
  ok(hasIdentityForgetTombstone(forgetStorage), 'forget intent is durable before either identity tier is deleted')
  // A crash at this point leaves both tiers intact, but boot sees the marker and
  // must not restore either one. Resume the exact same transaction below.
  await finishIdentityForget({
    storage: forgetStorage,
    deviceStore: { clear: async () => { order.push('device'); devicePresent = false; return true } },
    deactivate: () => { order.push('deactivate'); active = false },
    vaultPresent: () => vaultPresent,
    removeVault: () => { order.push('vault'); vaultPresent = false }
  })
  ok(order.join(',') === 'deactivate,device,vault', 'resume deactivates, deletes the device tier first, then deletes the vault')
  ok(!active && !devicePresent && !vaultPresent && !hasIdentityForgetTombstone(forgetStorage), 'tombstone clears only after both tiers are confirmed absent')

  const interruptedStorage = mem()
  let interruptedDevice = true
  let interruptedVault = true
  beginIdentityForget(interruptedStorage, pubHex)
  await assert.rejects(
    () => finishIdentityForget({
      storage: interruptedStorage,
      deviceStore: { clear: async () => { interruptedDevice = false; return true } },
      deactivate: () => {},
      vaultPresent: () => interruptedVault,
      removeVault: () => { throw new Error('simulated tab death before vault delete') }
    }),
    /simulated tab death/,
    'failure after device deletion leaves the do-not-restore tombstone durable'
  )
  passed++; console.log('  ✓ failure after device deletion leaves the do-not-restore tombstone durable')
  ok(!interruptedDevice && interruptedVault && hasIdentityForgetTombstone(interruptedStorage), 'interrupted state cannot silently restore the remaining vault/device combination')
  await finishIdentityForget({
    storage: interruptedStorage,
    deviceStore: { clear: async () => true },
    deactivate: () => {},
    vaultPresent: () => interruptedVault,
    removeVault: () => { interruptedVault = false }
  })
  ok(!interruptedVault && !hasIdentityForgetTombstone(interruptedStorage), 'later boot/retry finishes an interrupted forget and clears its marker')

  console.log('\n— end-to-end with DevIdentity (the ensureWriterIdentity flow) —')
  const kv3 = memoryKv()
  const store3 = createIdentityStore({ kv: kv3 })
  const idA = new DevIdentity(mem(), mem(), { lazy: true }); await idA.ready()
  const resA = await activateDurableIdentity(idA, store3) // mint -> persist/adopt -> activate
  ok(resA.adopted === false, 'tab A persisted its fresh mint')
  // "reload": a new lazy identity boots, restores from the device store
  const idB = new DevIdentity(mem(), mem(), { lazy: true }); await idB.ready()
  ok(idB.me().pubkey === null, 'fresh boot starts as a lurker')
  const restored = await store3.load()
  await idB.addUser(restored)
  ok(idB.me().pubkey === idA.me().pubkey, 'reload restores the SAME pseudonym (the "new user every refresh" bug is dead)')
  const sig = await idB.sign('peerit-test')
  ok(HEX64.test(idB.me().pubkey) && sig && sig.publicKey === idA.me().pubkey, 'restored identity SIGNS as the original')

  console.log('\n— every public write requires a matching durable tier —')
  ok((await assertDurableIdentity(idB, store3)).pubkey === idB.me().pubkey, 'active restored signer matches its verified device record')
  const sessionOnly = new DevIdentity(mem(), mem(), { lazy: true }); await sessionOnly.ready(); await sessionOnly.ensureActive('session-only')
  await assert.rejects(
    () => ensureDurableIdentityForWrite(sessionOnly, createIdentityStore({ kv: memoryKv() })),
    /not backed|session-only/,
    'an already-active session-only signer is refused instead of silently persisted after signing')
  passed++; console.log('  ✓ an already-active session-only signer is refused instead of silently persisted after signing')
  const oldPub = idB.me().pubkey
  ok(await store3.clear(), 'forget clears the durable device tier')
  idB.deactivate()
  ok(idB.me().pubkey === null, 'forget removes the in-memory signer immediately')
  await ensureDurableIdentityForWrite(idB, store3)
  ok(idB.me().pubkey && idB.me().pubkey !== oldPub, 'the next write gate creates a new durable identity, never reuses the forgotten signer')
  ok((await store3.load()).pubkey === idB.me().pubkey, 'new post identity is durable before signing resumes')

  console.log(`\nidentity-device-store: ${passed} checks passed.`)
}

main().catch((e) => { console.error('❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
