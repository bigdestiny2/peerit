import assert from 'node:assert/strict'
import {
  createPeeritDescriptorTrustBackend,
  memoryDescriptorTrustKv,
  PEERIT_DESCRIPTOR_TRUST_BACKEND_STATUS
} from '../js/substrate/descriptor-trust-backend.js'

const crypto = globalThis.crypto
assert.ok(crypto && crypto.subtle, 'WebCrypto is required')

const encoder = new TextEncoder()

function hex (value) {
  return Buffer.from(value).toString('hex')
}

function descriptorKey (root, store) {
  return `descriptor:${hex(root)}:${hex(store)}`
}

function descriptorBytes (label) {
  return encoder.encode(`peerit-sensitive-signed-descriptor-${label}`)
}

function state (root, store, labels = ['zero'], overrides = {}) {
  const history = labels.map(descriptorBytes)
  return {
    rootRelayPublicKey: new Uint8Array(root),
    storeId: new Uint8Array(store),
    currentBytes: new Uint8Array(history[history.length - 1]),
    currentHash: new Uint8Array(32).fill(0x30 + labels.length),
    sequence: BigInt(history.length - 1),
    identitySequence: BigInt(history.length - 1),
    relayPublicKey: new Uint8Array(32).fill(0x40 + labels.length),
    durabilityProfileId: 1,
    durabilityContinuityHash: new Uint8Array(32).fill(0x50 + labels.length),
    history,
    quarantined: false,
    ...overrides
  }
}

function jsonRecord (record) {
  return JSON.stringify(record, (_key, value) => value instanceof Uint8Array
    ? Buffer.from(value).toString('hex')
    : value)
}

const root = new Uint8Array(32).fill(0x11)
const store = new Uint8Array(32).fill(0x22)
const key = descriptorKey(root, store)

{
  const kv = memoryDescriptorTrustKv()
  const backend = createPeeritDescriptorTrustBackend({ kv, crypto })
  assert.deepEqual(await backend.read(key), { version: 0, value: null })

  const first = state(root, store)
  assert.equal(await backend.compareAndSwap(key, 0, first), true)
  const loaded = await backend.read(key)
  assert.equal(loaded.version, 1)
  assert.deepEqual(loaded.value, first)

  loaded.value.currentBytes[0] ^= 0xff
  loaded.value.history[0][0] ^= 0xff
  assert.deepEqual((await backend.read(key)).value, first, 'reads return private state copies')

  const [raw] = kv.records.values()
  assert.equal(raw.wrapKey.extractable, false)
  await assert.rejects(crypto.subtle.exportKey('raw', raw.wrapKey))
  const serialized = jsonRecord(raw)
  assert.doesNotMatch(serialized, new RegExp(hex(root), 'i'), 'continuity root must not appear in the clear record')
  assert.doesNotMatch(serialized, new RegExp(hex(store), 'i'), 'store id must not appear in the clear record')
  assert.doesNotMatch(serialized, new RegExp(hex(first.currentBytes), 'i'), 'signed descriptor bytes must be encrypted')

  assert.equal(await backend.compareAndSwap(key, 0, first), false, 'insert CAS cannot overwrite existing trust')
  assert.equal(await backend.compareAndSwap(key, 7, first), false, 'wrong CAS version cannot overwrite trust')

  const quarantined = state(root, store, ['zero', 'one'], { quarantined: true })
  assert.equal(await backend.compareAndSwap(key, 1, quarantined), true)
  const second = await backend.read(key)
  assert.equal(second.version, 2)
  assert.equal(second.value.quarantined, true)
  assert.deepEqual(second.value.history, quarantined.history)
}

{
  const kv = memoryDescriptorTrustKv()
  const first = createPeeritDescriptorTrustBackend({ kv, crypto })
  const second = createPeeritDescriptorTrustBackend({ kv, crypto })
  const results = await Promise.all([
    first.compareAndSwap(key, 0, state(root, store, ['race-a'])),
    second.compareAndSwap(key, 0, state(root, store, ['race-b']))
  ])
  assert.deepEqual(results.sort(), [false, true], 'cross-tab insert race has exactly one winner')
  assert.equal((await first.read(key)).version, 1)
}

{
  const kv = memoryDescriptorTrustKv()
  const backend = createPeeritDescriptorTrustBackend({ kv, crypto })
  await backend.compareAndSwap(key, 0, state(root, store))
  const [recordKey, raw] = kv.records.entries().next().value
  const corrupt = structuredClone(raw)
  corrupt.ciphertext[0] ^= 0xff
  kv.records.set(recordKey, corrupt)
  await assert.rejects(backend.read(key), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(
    backend.compareAndSwap(key, 1, state(root, store, ['zero', 'one'])),
    error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT',
    'corrupt trust cannot silently reset or advance'
  )
}

{
  const otherRoot = new Uint8Array(32).fill(0x61)
  const otherStore = new Uint8Array(32).fill(0x62)
  const otherKey = descriptorKey(otherRoot, otherStore)
  const kv = memoryDescriptorTrustKv()
  const backend = createPeeritDescriptorTrustBackend({ kv, crypto })
  await backend.compareAndSwap(key, 0, state(root, store))
  await backend.compareAndSwap(otherKey, 0, state(otherRoot, otherStore, ['other']))
  const entries = [...kv.records.entries()]
  const [firstKey, firstRecord] = entries[0]
  const [secondKey, secondRecord] = entries[1]

  kv.records.set(firstKey, structuredClone(secondRecord))
  await assert.rejects(backend.read(key), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT',
    'an encrypted record cannot be substituted across descriptor identities')

  const rebound = structuredClone(secondRecord)
  rebound.recordKey = firstRecord.recordKey
  kv.records.set(firstKey, rebound)
  await assert.rejects(backend.read(key), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT',
    'rewriting a clear lookup key cannot rebind authenticated ciphertext')
  assert.ok(secondKey !== firstKey)
}

{
  const backend = createPeeritDescriptorTrustBackend({ kv: memoryDescriptorTrustKv(), crypto })
  const valid = state(root, store)
  await assert.rejects(backend.compareAndSwap(key, -1, valid), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.compareAndSwap(key, 0, { ...valid, history: null }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.compareAndSwap(key, 0, { ...valid, sequence: 1n }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.compareAndSwap(key, 0, { ...valid, currentBytes: descriptorBytes('different') }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.compareAndSwap(key, 0, { ...valid, rootRelayPublicKey: new Uint8Array(32).fill(0x71) }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.compareAndSwap(key, 0, { ...valid, history: Array.from({ length: 4097 }, () => descriptorBytes('x')) }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.compareAndSwap(key, 0, { ...valid, quarantined: 0 }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.compareAndSwap(key, 0, { ...valid, extra: true }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  const sparseHistory = []
  sparseHistory[1] = descriptorBytes('hole')
  await assert.rejects(backend.compareAndSwap(key, 0, {
    ...valid,
    history: sparseHistory,
    sequence: 1n,
    currentBytes: sparseHistory[1]
  }), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  const accessor = { ...valid }
  Object.defineProperty(accessor, 'currentBytes', {
    enumerable: true,
    get () { throw new Error('descriptor state getter must not execute') }
  })
  await assert.rejects(backend.compareAndSwap(key, 0, accessor), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
  await assert.rejects(backend.read(`descriptor:${'AA'.repeat(32)}:${hex(store)}`), error => error.code === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT')
}

assert.deepEqual(PEERIT_DESCRIPTOR_TRUST_BACKEND_STATUS, {
  encryptedAtRest: true,
  nonExtractableDeviceKey: true,
  atomicCrossTabCas: true,
  corruptionFailsClosed: true,
  silentTofuResetForbidden: true,
  browserIndexedDbIntegrationTested: true
})

console.log('peerit-descriptor-trust-backend: encrypted continuity CAS, quarantine, tamper, and substitution checks passed')
