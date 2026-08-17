// Host-backed identity for the blind-substrate runtime: when Pear Browser
// exposes window.pear.identity, peerit signs with the host per-app identity
// (_dk = site drive key, _k = per-app subkey) instead of a browser-local key.
// Run: node --test test/peerit-host-identity.mjs

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { genKeyPair, sign as edSign } from '../js/crypto.js'
import { Data } from '../js/data.js'
import { TYPE } from '../js/model.js'
import { verifyRecord } from '../js/verify.js'
import { createPeeritLocalIdentityV1 } from '../js/substrate/local-identity.js'
import { createPeeritHostIdentityV1 } from '../js/substrate/host-identity.js'

// signForApp semantics (scripts/browser-smoke.mjs): the host signs
// pear.app.<driveKey>:<namespace>:<payload> with the per-app subkey and returns
// only { signature, publicKey } — driveKey and namespace stay on the host side.
function fakePearIdentity ({ seedHex, pubHex, driveKey, signPublicKey }) {
  const calls = { getPublicKey: 0, sign: 0 }
  return {
    calls,
    async getPublicKey () {
      calls.getPublicKey++
      return { publicKey: pubHex, driveKey, algorithm: 'ed25519' }
    },
    async sign (payload, namespace) {
      calls.sign++
      const signature = await edSign(seedHex, `pear.app.${driveKey}:${namespace}:${payload}`)
      return { signature, publicKey: signPublicKey || pubHex, algorithm: 'ed25519' }
    }
  }
}

const stubSync = { onChange () { return () => {} } }

async function hostKeyMaterial () {
  const app = await genKeyPair()
  const site = await genKeyPair()
  return { seedHex: app.seedHex, pubHex: app.pubHex, driveKey: site.pubHex }
}

test('host sign() output passes verifyRecord through a real Data._sign round-trip (_dk !== _k)', async () => {
  const material = await hostKeyMaterial()
  const host = createPeeritHostIdentityV1(fakePearIdentity(material))
  assert.equal(host.isDev, false)
  assert.equal(host.isHost, true)
  assert.equal(host.me().pubkey, null, 'a fresh host identity is a lurker until ready')
  assert.equal(host.durableSource(), null)

  await host.ready()
  const data = new Data(stubSync, host, {})
  const record = { author: material.pubHex, name: 'Pear Host Author', bio: 'signed by the browser', createdAt: 1 }
  Object.assign(record, await data._sign(TYPE.PROFILE, record, material.pubHex))

  assert.equal(record._k, material.pubHex)
  assert.equal(record._dk, material.driveKey)
  assert.notEqual(record._dk, record._k, 'host records carry the site drive key, not the signer key')
  assert.equal(record._ns, 'peerit')
  assert.equal(record._alg, 'ed25519')
  assert.equal(await verifyRecord(TYPE.PROFILE, record), 'ok',
    'a host-signed record verifies unchanged from record fields only')

  const me = await host.ensureActive()
  assert.equal(me.pubkey, material.pubHex)
  assert.equal(me.driveKey, material.driveKey)
  assert.equal(me.label, 'pear host')
  assert.deepEqual(host.durableSource(), { kind: 'host', pubkey: material.pubHex })
  assert.deepEqual(host.listUsers(), [host.me()])
  assert.equal(host.switchUser(material.pubHex), false)
})

test('host sign() returns a frozen envelope supplying driveKey and namespace from cache + request', async () => {
  const material = await hostKeyMaterial()
  const bridge = fakePearIdentity(material)
  const host = createPeeritHostIdentityV1(bridge)
  const signed = await host.sign('payload')
  assert.equal(Object.isFrozen(signed), true)
  assert.equal(signed.publicKey, material.pubHex)
  assert.equal(signed.driveKey, material.driveKey)
  assert.equal(signed.namespace, 'peerit')
  assert.equal(signed.algorithm, 'ed25519')
  assert.equal(bridge.calls.getPublicKey, 1, 'getPublicKey is cached after ready')
  const again = await host.sign('payload')
  assert.equal(bridge.calls.getPublicKey, 1)
  assert.deepEqual(again, signed)
})

test('host sign() refuses a foreign namespace with a coded error', async () => {
  const material = await hostKeyMaterial()
  const host = createPeeritHostIdentityV1(fakePearIdentity(material))
  await assert.rejects(host.sign('payload', 'other-app'),
    error => error.code === 'PEERIT_SIGNING_NAMESPACE_INVALID')
})

test('a mid-sign host pubkey change fails closed with PEERIT_WRITER_IDENTITY_CHANGED', async () => {
  const material = await hostKeyMaterial()
  const rotated = await genKeyPair()
  const host = createPeeritHostIdentityV1(fakePearIdentity({ ...material, signPublicKey: rotated.pubHex }))
  await assert.rejects(host.sign('payload'),
    error => error.code === 'PEERIT_WRITER_IDENTITY_CHANGED')
})

test('a host seed never crosses the bridge', async () => {
  const material = await hostKeyMaterial()
  const host = createPeeritHostIdentityV1(fakePearIdentity(material))
  await host.ready()
  assert.equal(host.currentSeedEntry(), null)
})

test('key-lifecycle methods are unsupported on a host identity', async () => {
  const material = await hostKeyMaterial()
  const host = createPeeritHostIdentityV1(fakePearIdentity(material))
  for (const method of [
    'mintEntry', 'createUser', 'addUser',
    'restoreFromDevice', 'restoreFromVault', 'restoreFromDurableImport',
    'deactivate', 'signAuthorBindV1'
  ]) {
    assert.throws(() => host[method](),
      error => error.code === 'PEERIT_HOST_IDENTITY_UNSUPPORTED',
      `${method} throws coded`)
  }
})

test('a malformed host getPublicKey fails closed with a coded error', async () => {
  const drive = (await genKeyPair()).pubHex
  for (const malformed of [
    { publicKey: 'not-hex', driveKey: drive },
    { publicKey: drive.toUpperCase(), driveKey: drive },
    { publicKey: drive, driveKey: drive.slice(1) },
    {}
  ]) {
    const host = createPeeritHostIdentityV1({
      async getPublicKey () { return malformed },
      async sign () { return { signature: 'ab'.repeat(64), publicKey: malformed.publicKey } }
    })
    await assert.rejects(host.ready(),
      error => error.code === 'PEERIT_HOST_IDENTITY_INVALID')
    await assert.rejects(host.ensureActive(),
      error => error.code === 'PEERIT_HOST_IDENTITY_INVALID')
  }
})

test('seq29-style local record (_dk === _k) and host record (_dk !== _k) both pass verifyRecord', async () => {
  // The pre-host wire shape: browser-local key, drive key equals signer key.
  const local = createPeeritLocalIdentityV1()
  const entry = await local.mintEntry('seq29')
  await local.restoreFromDevice(entry)
  const localData = new Data(stubSync, local, {})
  const localRecord = { author: entry.pubkey, name: 'Local Author', createdAt: 2 }
  Object.assign(localRecord, await localData._sign(TYPE.PROFILE, localRecord, entry.pubkey))
  assert.equal(localRecord._dk, localRecord._k, 'seq29-style records sign with _dk === _k')
  assert.equal(await verifyRecord(TYPE.PROFILE, localRecord), 'ok',
    'the historical local-key shape still verifies')

  const material = await hostKeyMaterial()
  const host = createPeeritHostIdentityV1(fakePearIdentity(material))
  await host.ready()
  const hostData = new Data(stubSync, host, {})
  const hostRecord = { author: material.pubHex, name: 'Host Author', createdAt: 3 }
  Object.assign(hostRecord, await hostData._sign(TYPE.PROFILE, hostRecord, material.pubHex))
  assert.notEqual(hostRecord._dk, hostRecord._k)
  assert.equal(await verifyRecord(TYPE.PROFILE, hostRecord), 'ok',
    'the host-key shape verifies under the same recomputed envelope')
})
