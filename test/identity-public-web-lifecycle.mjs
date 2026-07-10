// Public-web identity durability lifecycle: import replacement, reload, forget,
// and the first publication after forgetting.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { ready as cryptoReady, genKeyPair } from '../js/crypto.js'
import { createData } from '../js/data.js'
import { DevIdentity } from '../js/identity.js'
import { exportIdentity, importIdentity } from '../js/identity-export.js'
import {
  assertDurableIdentity,
  createIdentityStore,
  ensureDurableIdentityForWrite,
  memoryKv,
  replaceDurableIdentity
} from '../js/identity-store.js'
import { VAULT_KEY, clearVault, saveVault, unlockVault, vaultPubkey } from '../js/identity-vault.js'
import { DevSync, memoryStorage } from '../js/sync.js'

const FAST = { iterations: 1000 }
const BITS = { community: 3, post: 3, comment: 3 }
const mem = () => {
  const m = new Map()
  return { getItem: k => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}
let passed = 0
function ok (value, message) { assert.ok(value, message); passed++; console.log('  ✓ ' + message) }

await cryptoReady()
const localStorage = mem()
const kv = memoryKv()
const deviceStore = createIdentityStore({ kv })
const identity = new DevIdentity(mem(), mem(), { lazy: true })
await identity.ready()
const ensureWriter = () => ensureDurableIdentityForWrite(identity, deviceStore, { vaultPubkey: vaultPubkey(localStorage) })
const sync = new DevSync(memoryStorage(), 'identity-public-web-lifecycle')
await sync.ready()
const data = createData(sync, identity, { minBits: BITS, ensureWriter })

console.log('\n— first post-capable identity is durable before use —')
await data.createCommunity({ slug: 'durable', title: 'Durable identity' })
const pubA = identity.me().pubkey
ok(pubA && (await deviceStore.load()).pubkey === pubA, 'first write minted A only after A was durable')
await saveVault(localStorage, identity.currentSeedEntry(), 'identity A passphrase', FAST)
ok(vaultPubkey(localStorage) === pubA, 'A also has a matching encrypted vault')

console.log('\n— import B replaces A in both durable tiers before activation —')
const b = await genKeyPair()
const entryB = { seed: b.seedHex, pubkey: b.pubHex, driveKey: b.pubHex, label: 'B' }
const exportedB = await exportIdentity(entryB, 'identity B passphrase', FAST)
const importedB = await importIdentity(exportedB, 'identity B passphrase')
const previousVault = localStorage.getItem(VAULT_KEY)
let activeDuringVaultPersist = null
await replaceDurableIdentity(identity, deviceStore, importedB, {
  expectedPubkey: pubA,
  persistVault: async (verified) => {
    activeDuringVaultPersist = identity.me().pubkey
    await saveVault(localStorage, verified, 'identity B passphrase', FAST)
  },
  rollbackVault: () => localStorage.setItem(VAULT_KEY, previousVault)
})
ok(activeDuringVaultPersist === pubA, 'B vault was stored while A was still active')
ok(identity.me().pubkey === b.pubHex && identity.listUsers().length === 1, 'B activates only after durability commits and replaces A in memory')
ok((await deviceStore.load()).pubkey === b.pubHex, 'device CAS now contains B')
ok(vaultPubkey(localStorage) === b.pubHex && (await unlockVault(localStorage, 'identity B passphrase')).pubkey === b.pubHex, 'entered passphrase now unlocks a matching B vault')
ok((await assertDurableIdentity(identity, deviceStore, { vaultPubkey: vaultPubkey(localStorage) })).pubkey === b.pubHex, 'write gate accepts imported B')

const vaultOnly = new DevIdentity(mem(), mem(), { lazy: true }); await vaultOnly.ready()
await vaultOnly.restoreFromVault(await unlockVault(localStorage, 'identity B passphrase'))
ok((await assertDurableIdentity(vaultOnly, createIdentityStore({ kv: memoryKv() }), { vaultPubkey: b.pubHex })).kind === 'vault', 'an actually decrypted matching vault can back a writer without a device record')
const headerOnly = new DevIdentity(mem(), mem(), { lazy: true }); await headerOnly.ready(); await headerOnly.addUser(entryB)
await assert.rejects(
  () => assertDurableIdentity(headerOnly, createIdentityStore({ kv: memoryKv() }), { vaultPubkey: b.pubHex }),
  /not backed|session-only/,
  'a matching cleartext vault header alone cannot authorize a session-only signer')
passed++; console.log('  ✓ a matching cleartext vault header alone cannot authorize a session-only signer')

console.log('\n— reload restores B, not A —')
const reloaded = new DevIdentity(mem(), mem(), { lazy: true })
await reloaded.ready()
await reloaded.restoreFromDevice(await createIdentityStore({ kv }).load())
ok(reloaded.me().pubkey === b.pubHex, 'reload silently restores B from the replaced device record')
const reloadSig = await reloaded.sign('after reload')
ok(reloadSig.publicKey === b.pubHex, 'reloaded signer is B')

console.log('\n— forget deactivates now; next post uses a new durable key —')
clearVault(localStorage)
ok(await deviceStore.clear(), 'both durability tiers clear successfully')
identity.deactivate()
ok(identity.me().pubkey === null && identity.currentSeedEntry() === null, 'B seed is removed from memory immediately')
await assert.rejects(() => identity.sign('must fail'), /no active identity/, 'forgotten B cannot sign in the current page')
passed++; console.log('  ✓ forgotten B cannot sign in the current page')
const post = await data.submitPost({ community: 'durable', kind: 'text', title: 'After forget', body: 'new durable author' })
ok(post.author && post.author !== b.pubHex, 'the next post is authored by a newly minted identity C, not forgotten B')
ok((await deviceStore.load()).pubkey === post.author, 'C was durable before the post was signed')
ok(!vaultPubkey(localStorage), 'forget did not silently recreate a vault')

console.log('\n— app lifecycle wiring —')
const appSource = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8')
ok(appSource.includes('await assertDurableIdentity(identity, deviceIdStore'), 'app write gate rechecks durable identity on active writers')
ok(appSource.includes('await replaceDurableIdentity(identity, deviceIdStore, candidate'), 'app import uses atomic durable replacement before activation')
ok(appSource.includes('identity.deactivate()'), 'app forget path removes the in-memory signer immediately')
const writerStart = appSource.indexOf('async function ensureWriterIdentity')
const writerEnd = appSource.indexOf('\nfunction isBridgeMode', writerStart)
ok(writerStart >= 0 && writerEnd > writerStart && !appSource.slice(writerStart, writerEnd).includes('migrateLocalGraph'), 'first-write gate does not start local graph migration before the user publication')
ok(!appSource.includes('data.migrateLocalGraph('), 'returning browse does not auto-publish local graph preferences')

console.log(`\nidentity-public-web-lifecycle: ${passed} checks passed`)
