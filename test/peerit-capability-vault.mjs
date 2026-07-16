import assert from 'node:assert/strict'
import {
  createPeeritCapabilityVault,
  memoryCapabilityVaultKv,
  PEERIT_CAPABILITY_VAULT_STATUS
} from '../js/substrate/capability-vault.js'

const crypto = globalThis.crypto
assert.ok(crypto && crypto.subtle, 'WebCrypto is required')

function packet (suffix = 1) {
  return {
    intentId: `intent-${suffix}`,
    logicalId: `logical-${suffix}`,
    // The vault persists the exact Cell envelope identity beside the encrypted
    // capability.  These are deliberately stable for a fixture instance so a
    // retry proves byte-bound idempotence rather than relying on legacy JSON.
    innerCodec: 334,
    innerLength: 8 + suffix,
    sizeClass: 1,
    logicalHash: new Uint8Array(32).fill(0x80 + suffix),
    encodingCommitment: new Uint8Array(32).fill(0xa0 + suffix),
    targetId: `cell-v1:relay-${suffix}:store-${suffix}`,
    targetContext: {
      relayPublicKey: new Uint8Array(32).fill(0x10 + suffix),
      storeId: new Uint8Array(32).fill(0x20 + suffix),
      endpointId: suffix,
      descriptorSequence: BigInt(suffix)
    },
    prepared: {
      requestBytes: new Uint8Array([0x53, 0x45, 0x43, 0x52, 0x45, 0x54, suffix]),
      requestCommitment: new Uint8Array(32).fill(0x30 + suffix),
      readCap: { cellKey: new Uint8Array(32).fill(0x40 + suffix) },
      writeCap: {
        createPrivateKey: new Uint8Array(32).fill(0x50 + suffix),
        renewPrivateKey: new Uint8Array(32).fill(0x60 + suffix),
        dropPrivateKey: new Uint8Array(32).fill(0x70 + suffix)
      }
    }
  }
}

function jsonRecord (record) {
  return JSON.stringify(record, (_key, value) => value instanceof Uint8Array
    ? Buffer.from(value).toString('hex')
    : value)
}

{
  const kv = memoryCapabilityVaultKv()
  const vault = createPeeritCapabilityVault({ kv, crypto, now: () => 100 })
  const input = packet(1)
  const prepared = await vault.persistPreparedReplica(input)
  assert.equal(prepared.stage, 'prepared')
  assert.equal(prepared.revision, 1)
  assert.match(prepared.evidenceRef, /^peerit-capability-v1:[0-9a-f]{64}:1$/)

  const [raw] = kv.records.values()
  assert.equal(raw.wrapKey.extractable, false)
  await assert.rejects(crypto.subtle.exportKey('raw', raw.wrapKey))
  const serialized = jsonRecord(raw)
  assert.doesNotMatch(serialized, /intent-1|logical-1|cell-v1:relay-1/,
    'the clear record header must not expose application or relay identities')
  assert.doesNotMatch(serialized, /53454352455401/i, 'request plaintext must not appear in the stored record')
  assert.doesNotMatch(serialized, new RegExp('51'.repeat(32), 'i'), 'management private key must not appear in the stored record')

  const loaded = await vault.load(input.intentId, input.targetId)
  assert.equal(loaded.payload.targetContext.descriptorSequence, 1n)
  assert.deepEqual(loaded.payload.prepared.requestBytes, input.prepared.requestBytes)
  loaded.payload.prepared.requestBytes[0] ^= 0xff
  assert.deepEqual((await vault.load(input.intentId, input.targetId)).payload.prepared.requestBytes,
    input.prepared.requestBytes, 'load returns a private copy')

  const duplicate = await vault.persistPreparedReplica(input)
  assert.equal(duplicate.evidenceRef, prepared.evidenceRef, 'same prepared request is idempotent')
  await assert.rejects(vault.persistPreparedReplica({
    ...input,
    prepared: { ...input.prepared, requestBytes: new Uint8Array([9, 9, 9]) }
  }), /different prepared capability/)

  const verifiedInput = {
    ...input,
    resultBytes: new Uint8Array([1, 2, 3, 4]),
    readCapability: input.prepared.readCap
  }
  const verified = await vault.persistVerifiedResult(verifiedInput)
  assert.equal(verified.stage, 'verified')
  assert.equal(verified.revision, 2)
  assert.notEqual(verified.evidenceRef, prepared.evidenceRef)
  assert.deepEqual(verified.payload.resultBytes, verifiedInput.resultBytes)
  assert.deepEqual(verified.payload.readCapability, verifiedInput.readCapability)
  assert.equal((await vault.persistVerifiedResult(verifiedInput)).evidenceRef, verified.evidenceRef,
    'same verified result is idempotent')
  await assert.rejects(vault.persistVerifiedResult({
    ...verifiedInput,
    resultBytes: new Uint8Array([4, 3, 2, 1])
  }), /conflicting verified result/)

  assert.equal(await vault.deleteExact(input.intentId, input.targetId, prepared.evidenceRef), false,
    'a stale evidence reference cannot delete a newer record')
  assert.equal(await vault.deleteExact(input.intentId, input.targetId, verified.evidenceRef), true)
  assert.equal(await vault.load(input.intentId, input.targetId), null)
}

{
  const kv = memoryCapabilityVaultKv()
  const first = createPeeritCapabilityVault({ kv, crypto, now: () => 200 })
  const second = createPeeritCapabilityVault({ kv, crypto, now: () => 200 })
  const input = packet(2)
  const other = {
    ...input,
    prepared: { ...input.prepared, requestBytes: new Uint8Array([8, 8, 8]) }
  }
  const settled = await Promise.allSettled([
    first.persistPreparedReplica(input),
    second.persistPreparedReplica(other)
  ])
  assert.equal(settled.filter(value => value.status === 'fulfilled').length, 1)
  assert.equal(settled.filter(value => value.status === 'rejected').length, 1)
  assert.equal(kv.records.size, 1, 'cross-tab race commits exactly one prepared owner')
}

{
  const kv = memoryCapabilityVaultKv()
  let now = 300
  const vault = createPeeritCapabilityVault({ kv, crypto, now: () => now })
  const input = packet(3)
  await vault.persistPreparedReplica(input)
  now = 299
  const corrected = await vault.persistVerifiedResult({
    ...input,
    resultBytes: new Uint8Array([1]),
    readCapability: input.prepared.readCap
  })
  assert.equal(corrected.stage, 'verified',
    'backward wall-clock correction cannot strand an already verified relay result')
  assert.equal([...kv.records.values()][0].updatedAt, 300,
    'authenticated diagnostic time clamps monotonically while CAS revision advances')

  const [key, raw] = kv.records.entries().next().value
  const corrupt = structuredClone(raw)
  corrupt.ciphertext[0] ^= 0xff
  kv.records.set(key, corrupt)
  assert.equal((await vault.inspect(input.intentId, input.targetId)).status, 'corrupt')
  await assert.rejects(vault.load(input.intentId, input.targetId), /authentication failed/)
}

{
  const kv = memoryCapabilityVaultKv()
  const vault = createPeeritCapabilityVault({ kv, crypto })
  const input = packet(4)
  await assert.rejects(vault.persistPreparedReplica({
    ...input,
    prepared: { ...input.prepared, unsafe: () => true }
  }), /unsupported value/)
  assert.equal(kv.records.size, 0, 'invalid secret material fails before a durable write')
  await assert.rejects(vault.persistVerifiedResult({
    ...input,
    resultBytes: new Uint8Array([1]),
    readCapability: input.prepared.readCap
  }), /no durable prepared/)
}

{
  const kv = memoryCapabilityVaultKv()
  const vault = createPeeritCapabilityVault({ kv, crypto })
  const base = packet(5)
  const prototypeNamed = {}
  Object.defineProperty(prototypeNamed, '__proto__', {
    configurable: true,
    enumerable: true,
    writable: true,
    value: { marker: 'ordinary-data' }
  })
  await vault.persistPreparedReplica({
    ...base,
    prepared: { ...base.prepared, prototypeNamed }
  })
  const loaded = await vault.load(base.intentId, base.targetId)
  assert.equal(Object.getPrototypeOf(loaded.payload.prepared.prototypeNamed), Object.prototype)
  assert.equal(Object.hasOwn(loaded.payload.prepared.prototypeNamed, '__proto__'), true)
  assert.deepEqual(Object.getOwnPropertyDescriptor(
    loaded.payload.prepared.prototypeNamed, '__proto__').value, { marker: 'ordinary-data' })
}

const invalidPayloads = [
  ['sparse array', (() => { const value = []; value[1] = 'secret'; return value })()],
  ['array property', Object.assign([], { extra: 'secret' })],
  ['symbol property', (() => { const value = {}; value[Symbol('secret')] = 'secret'; return value })()],
  ['hidden property', (() => { const value = {}; Object.defineProperty(value, 'secret', { value: 'secret' }); return value })()],
  ['accessor property', (() => {
    const value = {}
    Object.defineProperty(value, 'secret', { enumerable: true, get () { throw new Error('getter must not run') } })
    return value
  })()]
]

for (let index = 0; index < invalidPayloads.length; index++) {
  const [label, unsafe] = invalidPayloads[index]
  const kv = memoryCapabilityVaultKv()
  const vault = createPeeritCapabilityVault({ kv, crypto })
  const input = packet(10 + index)
  await assert.rejects(vault.persistPreparedReplica({
    ...input,
    prepared: { ...input.prepared, unsafe }
  }), /capability payload/)
  assert.equal(kv.records.size, 0, `${label} fails before a durable write`)
}

assert.equal(PEERIT_CAPABILITY_VAULT_STATUS.browserIndexedDbIntegrationTested, true)

console.log('peerit-capability-vault: encrypted CAS persistence, tamper rejection, and acknowledgement ordering passed')
