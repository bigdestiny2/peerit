import assert from 'node:assert/strict'
import { createBlindCellRelay } from '../js/substrate/blind-client-relay.js'
import {
  createPeeritCapabilityVault,
  memoryCapabilityVaultKv
} from '../js/substrate/capability-vault.js'

const fill = (value, length = 32) => new Uint8Array(length).fill(value)
const hex = value => Buffer.from(value).toString('hex')

function persistedContext (context) {
  return Object.freeze({
    ...context,
    relayPublicKey: hex(context.relayPublicKey),
    storeId: hex(context.storeId),
    continuityRoot: hex(context.continuityRoot),
    durabilityContinuityHash: hex(context.durabilityContinuityHash),
    descriptorHash: hex(context.descriptorHash)
  })
}

function publication (suffix = 1) {
  const innerBytes = new Uint8Array([0x01, 0x4e, 0x01, 0, 0, 0, 1, suffix])
  return Object.freeze({
    intentId: `intent-${suffix}`,
    logicalId: `logical-${suffix}`,
    innerCodec: 334,
    innerBytes,
    innerLength: innerBytes.byteLength,
    sizeClass: 1,
    logicalHash: fill(0x20 + suffix),
    encodingCommitment: fill(0x40 + suffix)
  })
}

function contexts () {
  const common = {
    relayPublicKey: fill(0x11),
    storeId: fill(0x12),
    continuityRoot: fill(0x13),
    durabilityContinuityHash: fill(0x14),
    descriptorHash: fill(0x15),
    endpointId: 1,
    familyId: 2,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1,
    durabilityProfileId: 1
  }
  return {
    put: Object.freeze({ ...common, operationId: 1 }),
    get: Object.freeze({ ...common, operationId: 2 })
  }
}

function harness ({
  ambiguousPut = false,
  mismatch = false,
  tamper = false,
  notFoundAfter = Infinity,
  remoteErrorAfter = Infinity,
  remoteRetryable = 0
} = {}) {
  const kv = memoryCapabilityVaultKv()
  const vault = createPeeritCapabilityVault({ kv, crypto: globalThis.crypto, now: () => 100 })
  const endpointContexts = contexts()
  const putEndpoint = Object.freeze({ kind: 'put' })
  const getEndpoint = Object.freeze({ kind: 'get' })
  const calls = []
  let committedInner = null
  let losePutResponse = ambiguousPut
  let getRequests = 0

  const readCap = Object.freeze({
    version: 1,
    relayPublicKey: fill(0x11),
    storageSlot: fill(0x31),
    cellKey: fill(0x32),
    sizeClass: 1,
    expectedCellBlobHash: fill(0x33)
  })
  const base = Object.freeze({
    maximumCellContentBytes: () => 4063,
    async createCellReplica (options) {
      committedInner = new Uint8Array(options.structuredContent)
      return Object.freeze({
        request: Object.freeze({ version: 1, storageSlot: readCap.storageSlot }),
        requestBytes: new Uint8Array([0x50, 0x55, 0x54]),
        requestCommitment: fill(0x41),
        wire: Object.freeze({ familyId: 2, operationId: 1, expectedResultBodyBytes: 1 }),
        readCap,
        writeCap: Object.freeze({ createPrivateKey: fill(0x42) })
      })
    }
  })
  const control = Object.freeze({
    verifiedEndpointContext (endpoint) {
      if (endpoint === putEndpoint) return endpointContexts.put
      if (endpoint === getEndpoint) return endpointContexts.get
      throw new Error('unverified endpoint')
    },
    async createGetCellRequest ({ readCap: attemptedReadCap }) {
      assert.deepEqual(attemptedReadCap.storageSlot, readCap.storageSlot)
      getRequests++
      return Object.freeze({
        request: Object.freeze({ version: 1, storageSlot: attemptedReadCap.storageSlot }),
        requestBytes: new Uint8Array([0x47, 0x45, 0x54, getRequests]),
        requestCommitment: fill(0x50 + getRequests),
        wire: Object.freeze({ familyId: 2, operationId: 2, expectedResultBodyBytes: 1 })
      })
    },
    verifyOperationResult ({ endpoint, resultBytes }) {
      if (endpoint === putEndpoint) {
        assert.deepEqual(resultBytes, new Uint8Array([0x70]))
        return Object.freeze({ snapshotBytes: () => new Uint8Array([0x71]) })
      }
      assert.equal(endpoint, getEndpoint)
      if (tamper || resultBytes[0] !== 0x80) throw new Error('tampered readback result')
      return Object.freeze({
        opened: mismatch
          ? new Uint8Array([...committedInner.slice(0, -1), committedInner.at(-1) ^ 1])
          : new Uint8Array(committedInner),
        snapshotBytes: () => new Uint8Array([0x81])
      })
    },
    async openVerifiedCellGetResult ({ verifiedResult, readCap: attemptedReadCap }) {
      assert.deepEqual(attemptedReadCap.expectedCellBlobHash, readCap.expectedCellBlobHash)
      return new Uint8Array(verifiedResult.opened)
    }
  })
  const httpClient = Object.freeze({
    async request ({ endpoint }) {
      if (endpoint === putEndpoint) {
        calls.push('PUT')
        if (losePutResponse) {
          losePutResponse = false
          throw new Error('response lost after commit')
        }
        return Object.freeze({ ok: true, body: new Uint8Array([0x70]) })
      }
      assert.equal(endpoint, getEndpoint)
      calls.push('GET')
      if (getRequests > notFoundAfter) {
        return Object.freeze({ ok: false, error: Object.freeze({ code: 13, retryable: 0 }) })
      }
      if (getRequests > remoteErrorAfter) {
        return Object.freeze({ ok: false, error: Object.freeze({ code: 6, retryable: remoteRetryable }) })
      }
      return Object.freeze({ ok: true, body: new Uint8Array([0x80]) })
    }
  })
  const createRelay = () => createBlindCellRelay({
    blindClient: base,
    control,
    runtime: Object.freeze({}),
    relayPublicKey: fill(0x11),
    endpoint: putEndpoint,
    endpointContext: endpointContexts.put,
    readEndpoint: getEndpoint,
    readEndpointContext: endpointContexts.get,
    httpClient,
    persistPreparedReplica: vault.persistPreparedReplica,
    persistVerifiedResult: vault.persistVerifiedResult,
    persistVerifiedReadback: vault.persistVerifiedReadback,
    loadPersistedReplica: vault.load
  })
  const seedLegacyPrepared = async value => {
    const prepared = await base.createCellReplica({ structuredContent: value.innerBytes })
    const relay = createRelay()
    await vault.persistPreparedReplica({
      ...value,
      targetId: relay.id,
      targetContext: persistedContext(endpointContexts.put),
      prepared
    })
  }
  const rotateDescriptor = value => {
    endpointContexts.put = Object.freeze({ ...endpointContexts.put, descriptorHash: fill(value) })
    endpointContexts.get = Object.freeze({ ...endpointContexts.get, descriptorHash: fill(value) })
  }
  return { calls, createRelay, endpointContexts, kv, rotateDescriptor, seedLegacyPrepared, vault }
}

{
  const value = publication(1)
  const test = harness()
  const result = await test.createRelay().deliver(value)
  assert.equal(result.readbackVerified, true)
  assert.equal(result.readbackRevalidated, true)
  assert.deepEqual(test.calls, ['PUT', 'GET'])

  const stored = await test.vault.load(value.intentId, test.createRelay().id)
  assert.equal(stored.stage, 'readback-verified')
  assert.equal(stored.revision, 3)
  assert.deepEqual(stored.payload.readbackInnerBytes, value.innerBytes)
  assert.deepEqual(stored.payload.logicalHash, value.logicalHash)
  assert.deepEqual(stored.payload.encodingCommitment, value.encodingCommitment)

  const recovered = await test.createRelay().reconcile(value)
  assert.equal(recovered.readbackVerified, true)
  assert.notEqual(recovered.readbackRevalidated, true,
    'a cached stage-3 acknowledgement is historical and carries no live-GET marker')
  assert.deepEqual(test.calls, ['PUT', 'GET'], 'durable readback evidence avoids every later network request')

  const refreshed = await test.createRelay().revalidateReadback(value)
  assert.equal(refreshed.readbackRevalidated, true)
  assert.deepEqual(test.calls, ['PUT', 'GET', 'GET'],
    'forced revalidation bypasses the cached receipt and performs a new capability-bound GET')
  const refreshedRecord = await test.vault.load(value.intentId, test.createRelay().id)
  assert.equal(refreshedRecord.revision, 4)
  assert.equal(refreshedRecord.payload.readbackVerifiedAt, 101,
    'fresh nonce/result evidence advances the encrypted stage-3 CAS monotonically')
}

{
  const value = publication(6)
  const test = harness()
  await assert.rejects(test.createRelay().revalidateReadback(value), error =>
    error && error.code === 'PEERIT_SUBSTRATE_READ_CAPABILITY_MISSING' && error.terminal === true)
  assert.deepEqual(test.calls, [], 'missing persisted capability fails before any GET')
}

{
  const value = publication(11)
  const test = harness()
  const relay = test.createRelay()
  await relay.deliver(value)
  const stored = await test.vault.load(value.intentId, relay.id)
  const recovered = await relay.readCellCapability({
    targetId: relay.id,
    innerLength: value.innerLength,
    sizeClass: value.sizeClass,
    readCapability: stored.payload.readCapability
  })
  assert.deepEqual(recovered.innerBytes, value.innerBytes)
  assert.match(recovered.evidenceRef, /^blind-cell-get:[0-9a-f]{64}$/)
  assert.deepEqual(test.calls, ['PUT', 'GET', 'GET'],
    'public reader-capability recovery performs a fresh authenticated GET without a PUT')
}

{
  const value = publication(7)
  const test = harness({ notFoundAfter: 1 })
  await test.createRelay().deliver(value)
  await assert.rejects(test.createRelay().revalidateReadback(value), error =>
    error && error.code === 'HIVERELAY_READBACK_NOT_FOUND' &&
      error.definitiveAbsence === true && error.remote.code === 13)
  assert.deepEqual(test.calls, ['PUT', 'GET', 'GET'],
    'frozen BlindErrorV1 NOT_FOUND=13 is surfaced as definitive authenticated absence')
}

{
  const value = publication(8)
  const test = harness({ remoteErrorAfter: 1, remoteRetryable: 0 })
  await test.createRelay().deliver(value)
  await assert.rejects(test.createRelay().revalidateReadback(value), error =>
    error && error.code === 'HIVERELAY_READBACK_TERMINAL' &&
      error.terminal === true && error.definitiveAbsence === false)
}

{
  const value = publication(9)
  const test = harness({ remoteErrorAfter: 1, remoteRetryable: 1 })
  await test.createRelay().deliver(value)
  await assert.rejects(test.createRelay().revalidateReadback(value), error =>
    error && error.code === 'HIVERELAY_READBACK_PENDING' && error.terminal !== true)
}

{
  const value = publication(10)
  const test = harness()
  const first = test.createRelay()
  await first.deliver(value)
  test.rotateDescriptor(0x25)
  const refreshed = test.createRelay()
  assert.equal(refreshed.id, first.id,
    'a linked descriptor refresh retains the same relay/store target identity')
  const result = await refreshed.revalidateReadback(value)
  assert.equal(result.readbackRevalidated, true)
  assert.deepEqual(test.calls, ['PUT', 'GET', 'GET'],
    'same-target descriptor refresh upgrades contexts through GET without another PUT')
  const stored = await test.vault.load(value.intentId, refreshed.id)
  assert.equal(stored.payload.targetContext.descriptorHash, hex(fill(0x25)))
  assert.equal(stored.payload.readTargetContext.descriptorHash, hex(fill(0x25)))
}

{
  const value = publication(2)
  const test = harness({ ambiguousPut: true })
  await assert.rejects(test.createRelay().deliver(value), /response lost after commit/)
  assert.deepEqual(test.calls, ['PUT'])

  const recovered = await test.createRelay().reconcile(value)
  assert.equal(recovered.readbackVerified, true)
  assert.deepEqual(test.calls, ['PUT', 'GET'],
    'ambiguous commit-response loss is reconciled by GET without resending PUT')
  const stored = await test.vault.load(value.intentId, test.createRelay().id)
  assert.equal(stored.stage, 'readback-verified')
  assert.equal(stored.revision, 2, 'readback can advance directly from prepared ambiguity without inventing a PUT receipt')
}

{
  const value = publication(5)
  const test = harness()
  await test.seedLegacyPrepared(value)
  const recovered = await test.createRelay().reconcile(value)
  assert.equal(recovered.readbackVerified, true)
  assert.deepEqual(test.calls, ['GET'], 'legacy ambiguous vault records upgrade in place without a PUT resend')
  const stored = await test.vault.load(value.intentId, test.createRelay().id)
  assert.equal(stored.stage, 'readback-verified')
  assert.deepEqual(stored.payload.readTargetContext, persistedContext(test.endpointContexts.get))
}

{
  const value = publication(3)
  const test = harness({ mismatch: true })
  await assert.rejects(test.createRelay().deliver(value), error =>
    error && error.code === 'PEERIT_SUBSTRATE_READBACK_ENVELOPE_MISMATCH' && error.terminal === true)
  assert.deepEqual(test.calls, ['PUT', 'GET'])
  const stored = await test.vault.load(value.intentId, test.createRelay().id)
  assert.equal(stored.stage, 'verified', 'mismatched plaintext can never become readback evidence')
}

{
  const value = publication(4)
  const test = harness({ tamper: true })
  await assert.rejects(test.createRelay().deliver(value), error =>
    error && error.code === 'PEERIT_SUBSTRATE_READBACK_AUTHENTICATION_FAILED' && error.terminal === true)
  const stored = await test.vault.load(value.intentId, test.createRelay().id)
  assert.equal(stored.stage, 'verified', 'tampered GET result can never become readback evidence')
}

{
  const test = harness()
  assert.throws(() => createBlindCellRelay({
    blindClient: Object.freeze({ createCellReplica: async () => {}, BlindDirectHttpClient: class {} }),
    relayPublicKey: fill(0x11),
    endpoint: Object.freeze({}),
    endpointContext: test.endpointContexts.put,
    readEndpoint: Object.freeze({}),
    readEndpointContext: Object.freeze({ ...test.endpointContexts.get, storeId: fill(0xff) }),
    httpClient: Object.freeze({ request: async () => {} }),
    persistPreparedReplica: async () => {},
    persistVerifiedResult: async () => {},
    persistVerifiedReadback: async () => {},
    loadPersistedReplica: async () => null
  }), /read endpoint storeId does not match/)
}

console.log('peerit-blind-cell-readback: authenticated exact-envelope recovery and no-resend ambiguity passed')
