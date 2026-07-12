import assert from 'node:assert/strict'
import {
  createPrivateKey,
  createPublicKey,
  sign
} from 'node:crypto'
import {
  checkpointSignaturePayload,
  encodePeeritHiveRelayProfilePinV1,
  encodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryCheckpointV1,
  pinHistoryCheckpointHash,
  profilePinHash,
  profilePinSignaturePayload,
  releaseAuthorityKeyId
} from '../js/substrate/release-control-codec.mjs'
import {
  createPeeritPinHistoryWitnessBackend,
  memoryPinHistoryWitnessKv,
  peeritPinHistoryProfileScopeV1,
  PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS
} from '../js/substrate/pin-history-witness-backend.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  concatBytes,
  hexToBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  encodePeeritReleaseAuthorityTransitionV1,
  releaseAuthorityTransitionHash,
  releaseAuthorityTransitionSignatureCommitment
} from '../js/substrate/release-authority-transition.mjs'
import {
  getVerifiedPinHistoryTerminalSnapshotV1,
  verifyPeeritPinHistoryBundleV1,
  verifyPeeritPinHistoryContinuationV1
} from '../js/substrate/release-control-verifier.mjs'
import {
  buildReleaseControlFixture,
  createNodeReleaseControlCrypto
} from '../scripts/release-control-fixture.mjs'

const webCrypto = globalThis.crypto
assert.ok(webCrypto && webCrypto.subtle, 'WebCrypto is required')
const verifierCrypto = createNodeReleaseControlCrypto()
const fixture = buildReleaseControlFixture()
const scope = peeritPinHistoryProfileScopeV1()
const PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420')

function hash (label) {
  return blake2b256(asciiBytes(`peerit.pin-history-witness.test:${label}`))
}

function rotationPrivateKey () {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => 0x70 + index)
  return createPrivateKey({
    key: Buffer.from(concatBytes(PKCS8_PREFIX, seed)),
    format: 'der',
    type: 'pkcs8'
  })
}

function rawPublicKey (privateKey) {
  const encoded = new Uint8Array(createPublicKey(privateKey).export({
    format: 'der',
    type: 'spki'
  }))
  return encoded.slice(-32)
}

function signPinWith (value, privateKey) {
  return {
    ...value,
    signature: new Uint8Array(sign(
      null, Buffer.from(profilePinSignaturePayload(value)), privateKey))
  }
}

function signCheckpointWith (value, privateKey) {
  return {
    ...value,
    signature: new Uint8Array(sign(
      null, Buffer.from(checkpointSignaturePayload(value)), privateKey))
  }
}

function rotationFixture () {
  const nextPrivateKey = rotationPrivateKey()
  const nextPublicKey = rawPublicKey(nextPrivateKey)
  const unsignedTransition = {
    version: 1,
    previousSequence: 0n,
    nextSequence: 1n,
    previousPublicKey: fixture.releasePublicKey,
    nextPublicKey,
    validFromRelease: 2n,
    previousKeySignature: new Uint8Array(64),
    nextKeySignature: new Uint8Array(64)
  }
  const commitment = releaseAuthorityTransitionSignatureCommitment(
    unsignedTransition)
  const transition = {
    ...unsignedTransition,
    previousKeySignature: new Uint8Array(sign(
      null, Buffer.from(commitment), fixture.releasePrivateKey)),
    nextKeySignature: new Uint8Array(sign(
      null, Buffer.from(commitment), nextPrivateKey))
  }
  const transitionBytes = encodePeeritReleaseAuthorityTransitionV1(transition)
  const pin = signPinWith({
    ...fixture.pins[1],
    releaseSequence: 2n,
    previousPinHash: profilePinHash(fixture.pinBytes[1]),
    appArtifactHash: hash('rotation-app'),
    webAssetManifestHash: hash('rotation-web'),
    migrationTransitionEvidenceHash: null,
    releaseAuthoritySequence: 1n,
    releaseAuthorityPublicKey: nextPublicKey,
    releaseAuthorityKeyId: releaseAuthorityKeyId(nextPublicKey),
    authorityTransitionHash: releaseAuthorityTransitionHash(transitionBytes),
    signature: undefined
  }, nextPrivateKey)
  const pinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  const checkpointValue = {
    version: 1,
    checkpointSequence: 2n,
    previousCheckpointHash: pinHistoryCheckpointHash(
      fixture.checkpointBytes[1]),
    pinHash: profilePinHash(pinBytes),
    previousPinHash: pin.previousPinHash,
    issuedUnixMillis: 1700000002000n,
    releaseAuthoritySequence: 1n,
    releaseAuthorityKeyId: pin.releaseAuthorityKeyId
  }
  const checkpoint = signCheckpointWith(checkpointValue, nextPrivateKey)
  const checkpointBytes = encodePeeritPinHistoryCheckpointV1(checkpoint)
  const bundleBytes = encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [pinBytes],
    checkpoints: [checkpointBytes]
  })
  return { transitionBytes, bundleBytes }
}

function makePin (previousPinBytes, sequence, label) {
  return fixture.signPin({
    ...fixture.pins[1],
    releaseSequence: sequence,
    previousPinHash: profilePinHash(previousPinBytes),
    appArtifactHash: hash(`app:${label}`),
    webAssetManifestHash: hash(`web:${label}`),
    migrationTransitionEvidenceHash: null,
    authorityTransitionHash: null,
    signature: undefined
  })
}

function makeCheckpoint (pin, pinBytes, previousCheckpointBytes) {
  const unsigned = {
    version: 1,
    checkpointSequence: pin.releaseSequence,
    previousCheckpointHash: pinHistoryCheckpointHash(previousCheckpointBytes),
    pinHash: profilePinHash(pinBytes),
    previousPinHash: pin.previousPinHash,
    issuedUnixMillis: 1700000000000n + pin.releaseSequence * 1000n,
    releaseAuthoritySequence: pin.releaseAuthoritySequence,
    releaseAuthorityKeyId: pin.releaseAuthorityKeyId
  }
  return fixture.signCheckpoint({
    ...unsigned,
    signature: undefined
  })
}

function makeContinuation (previousPinBytes, previousCheckpointBytes, sequence, label) {
  const pin = makePin(previousPinBytes, sequence, label)
  const pinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  const checkpoint = makeCheckpoint(pin, pinBytes, previousCheckpointBytes)
  const checkpointBytes = encodePeeritPinHistoryCheckpointV1(checkpoint)
  const bundleBytes = encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [pinBytes],
    checkpoints: [checkpointBytes]
  })
  return { pin, pinBytes, checkpoint, checkpointBytes, bundleBytes }
}

function makeTwoPinContinuation (first, second) {
  return encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [first.pinBytes, second.pinBytes],
    checkpoints: [first.checkpointBytes, second.checkpointBytes]
  })
}

async function verifiedFixtures () {
  const base = await verifyPeeritPinHistoryBundleV1(fixture.bundleBytes, {
    crypto: verifierCrypto,
    expectedPins: fixture.expectedPins
  })
  const second = makeContinuation(
    fixture.pinBytes[1], fixture.checkpointBytes[1], 2n, 'two')
  const terminal2 = await verifyPeeritPinHistoryContinuationV1(
    second.bundleBytes, { crypto: verifierCrypto, anchor: base })
  const third = makeContinuation(
    second.pinBytes, second.checkpointBytes, 3n, 'three')
  const terminal3 = await verifyPeeritPinHistoryContinuationV1(
    third.bundleBytes, { crypto: verifierCrypto, anchor: terminal2 })
  const fork = makeContinuation(
    fixture.pinBytes[1], fixture.checkpointBytes[1], 2n, 'fork-two')
  const fork2 = await verifyPeeritPinHistoryContinuationV1(
    fork.bundleBytes, { crypto: verifierCrypto, anchor: base })
  return { base, second, terminal2, third, terminal3, fork, fork2 }
}

function createBackend (kv) {
  return createPeeritPinHistoryWitnessBackend({
    kv,
    crypto: webCrypto,
    verifierCrypto
  })
}

function rawJson (value) {
  return JSON.stringify(value, (_key, entry) =>
    entry instanceof Uint8Array ? Buffer.from(entry).toString('hex') : entry)
}

function directReadKv (value) {
  return {
    async get () { return value },
    async putIfAbsent () { throw new Error('not used') },
    async compareAndSwap () { throw new Error('not used') }
  }
}

const verified = await verifiedFixtures()

// A lurker read is a pure miss: no identity is requested and the storage
// adapter receives no write.
{
  const kv = memoryPinHistoryWitnessKv()
  const backend = createBackend(kv)
  assert.deepEqual(await backend.read(scope), { version: 0, value: null })
  assert.equal(kv.records.size, 0)
}

// If an IndexedDB open reports blocked and later resumes, the abandoned
// upgrade is aborted and an eventual connection is closed.
{
  let aborted = false
  let closed = false
  const fakeIndexedDb = {
    async databases () { return [{ name: 'peerit-pin-history-witness-v1' }] },
    open () {
      const request = {
        result: {
          objectStoreNames: { contains: () => false },
          close () { closed = true }
        },
        transaction: { abort () { aborted = true } }
      }
      queueMicrotask(() => {
        request.onblocked()
        request.onupgradeneeded()
        request.onsuccess()
      })
      return request
    }
  }
  const backend = createPeeritPinHistoryWitnessBackend({
    indexedDB: fakeIndexedDb,
    crypto: webCrypto,
    verifierCrypto
  })
  await assert.rejects(backend.read(scope), /open was blocked/)
  await new Promise(resolve => queueMicrotask(resolve))
  assert.equal(aborted, true)
  assert.equal(closed, true)
}

// A currently authenticated app base can establish its floor immediately,
// without waiting for another network release.
{
  const kv = memoryPinHistoryWitnessKv()
  const backend = createBackend(kv)
  assert.equal(await backend.initialize(scope, 0, verified.base), true)
  assert.equal(await backend.initialize(scope, 0, verified.base), false)
  const loaded = await backend.read(scope)
  assert.equal(loaded.version, 1)
  assert.equal(loaded.value.baseSequence, 1n)
  assert.equal(loaded.value.terminalSequence, 1n)
  assert.equal(loaded.value.segmentCount, 0)

  const restarted = createBackend(kv)
  const afterRestart = await restarted.read(scope)
  assert.equal(afterRestart.value.terminalSequence, 1n)
  assert.equal(await restarted.rehydrate(scope, verified.base), verified.base)

  const [recordKey, raw] = kv.records.entries().next().value
  assert.match(recordKey, /^pin-history-witness:v1:[0-9a-f]{64}$/)
  assert.equal(raw.wrapKey.extractable, false)
  await assert.rejects(webCrypto.subtle.exportKey('raw', raw.wrapKey))
  const serialized = rawJson(raw)
  assert.doesNotMatch(serialized, /@peerit\/hiverelay-profile-v1/)
  assert.doesNotMatch(serialized, new RegExp(Buffer.from(
    verified.second.bundleBytes).toString('hex'), 'i'))
}

// Exact append, restart replay, witnessed floors, rollback/fork rejection, and
// authenticated boundary-only compaction.
{
  const kv = memoryPinHistoryWitnessKv()
  const backend = createBackend(kv)
  await backend.initialize(scope, 0, verified.base)
  assert.equal(await backend.append(scope, 1, {
    anchor: verified.base,
    authorityTransitions: [],
    completeBundle: verified.second.bundleBytes,
    verifiedResult: verified.terminal2
  }), true)
  assert.equal((await backend.read(scope)).value.terminalSequence, 2n)
  const rawAfterAppend = [...kv.records.values()][0]
  const serializedAfterAppend = rawJson(rawAfterAppend)
  assert.doesNotMatch(serializedAfterAppend, new RegExp(
    Buffer.from(verified.second.bundleBytes).toString('hex'), 'i'))
  assert.doesNotMatch(serializedAfterAppend, new RegExp(
    Buffer.from(scope.profileScopeHash).toString('hex'), 'i'))

  const restarted = createBackend(kv)
  const rehydrated2 = await restarted.rehydrate(scope, verified.base)
  assert.notEqual(rehydrated2, verified.terminal2)
  assert.equal(getVerifiedPinHistoryTerminalSnapshotV1(
    rehydrated2).terminalSequence, 2n)

  assert.equal(await backend.append(scope, 2, {
    anchor: verified.terminal2,
    authorityTransitions: [],
    completeBundle: verified.third.bundleBytes,
    verifiedResult: verified.terminal3
  }), true)
  const rehydrated3 = await createBackend(kv).rehydrate(
    scope, verified.base)
  assert.equal(getVerifiedPinHistoryTerminalSnapshotV1(
    rehydrated3).terminalSequence, 3n)

  await assert.rejects(backend.append(scope, 3, {
    anchor: verified.base,
    authorityTransitions: [],
    completeBundle: verified.fork.bundleBytes,
    verifiedResult: verified.fork2
  }), error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_ROLLBACK')
  await assert.rejects(backend.append(scope, 3, {
    anchor: verified.base,
    authorityTransitions: [],
    completeBundle: verified.third.bundleBytes,
    verifiedResult: verified.terminal3
  }), error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')

  assert.equal(await backend.compact(scope, 3, {
    authenticatedBase: verified.terminal2
  }), true)
  const compacted = await backend.read(scope)
  assert.equal(compacted.version, 4)
  assert.equal(compacted.value.baseSequence, 2n)
  assert.equal(compacted.value.terminalSequence, 3n)
  assert.equal(compacted.value.segmentCount, 1)
  assert.equal(getVerifiedPinHistoryTerminalSnapshotV1(
    await createBackend(kv).rehydrate(scope, verified.terminal2)
  ).terminalSequence, 3n)
  await assert.rejects(
    createBackend(kv).rehydrate(scope, verified.base),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BASE_TOO_OLD')
  assert.equal(await backend.compact(scope, 4, {
    authenticatedBase: verified.terminal3
  }), true)
  assert.equal((await backend.read(scope)).value.segmentCount, 0)
}

// An authenticated base inside a persisted multi-pin segment is not silently
// treated as a compaction boundary; a base ahead of the witness also requires
// exact bridge material.
{
  const second = verified.second
  const third = verified.third
  const combinedBytes = makeTwoPinContinuation(second, third)
  const combined = await verifyPeeritPinHistoryContinuationV1(combinedBytes, {
    crypto: verifierCrypto,
    anchor: verified.base
  })
  const kv = memoryPinHistoryWitnessKv()
  const backend = createBackend(kv)
  await backend.initialize(scope, 0, verified.base)
  await backend.append(scope, 1, {
    anchor: verified.base,
    authorityTransitions: [],
    completeBundle: combinedBytes,
    verifiedResult: combined
  })
  await assert.rejects(
    backend.rehydrate(scope, verified.terminal2),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BASE_FORK')
  await assert.rejects(
    backend.compact(scope, 2, { authenticatedBase: verified.terminal2 }),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_COMPACTION')

  const shortKv = memoryPinHistoryWitnessKv()
  const short = createBackend(shortKv)
  await short.initialize(scope, 0, verified.base)
  await short.append(scope, 1, {
    anchor: verified.base,
    authorityTransitions: [],
    completeBundle: verified.second.bundleBytes,
    verifiedResult: verified.terminal2
  })
  await assert.rejects(
    short.rehydrate(scope, verified.terminal3),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BASE_AHEAD')
}

// Competing tabs cannot both initialize or append the same CAS generation.
{
  const kv = memoryPinHistoryWitnessKv()
  const left = createBackend(kv)
  const right = createBackend(kv)
  assert.deepEqual((await Promise.all([
    left.initialize(scope, 0, verified.base),
    right.initialize(scope, 0, verified.base)
  ])).sort(), [false, true])
  assert.deepEqual((await Promise.all([
    left.append(scope, 1, {
      anchor: verified.base,
      authorityTransitions: [],
      completeBundle: verified.second.bundleBytes,
      verifiedResult: verified.terminal2
    }),
    right.append(scope, 1, {
      anchor: verified.base,
      authorityTransitions: [],
      completeBundle: verified.second.bundleBytes,
      verifiedResult: verified.terminal2
    })
  ])).sort(), [false, true])
  assert.equal((await left.read(scope)).version, 2)
}

// The brand, bundle, and exact dual-signed transition bytes are rebound inside
// append. Preserving transition count and canonical shape while changing one
// signature cannot poison durable replay state.
{
  const rotation = rotationFixture()
  const terminal = await verifyPeeritPinHistoryContinuationV1(
    rotation.bundleBytes, {
      crypto: verifierCrypto,
      anchor: verified.base,
      authorityTransitions: [rotation.transitionBytes]
    })
  const changedSignature = new Uint8Array(rotation.transitionBytes)
  changedSignature[changedSignature.length - 1] ^= 0x01
  const kv = memoryPinHistoryWitnessKv()
  const backend = createBackend(kv)
  await backend.initialize(scope, 0, verified.base)
  await assert.rejects(backend.append(scope, 1, {
    anchor: verified.base,
    authorityTransitions: [changedSignature],
    completeBundle: rotation.bundleBytes,
    verifiedResult: terminal
  }), error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
  assert.equal((await backend.read(scope)).version, 1)
  assert.equal(await backend.append(scope, 1, {
    anchor: verified.base,
    authorityTransitions: [rotation.transitionBytes],
    completeBundle: rotation.bundleBytes,
    verifiedResult: terminal
  }), true)
}

// A valid older whole record and a missing observed record are rejected during
// one runtime. A new runtime still needs the separately gated portable witness
// to detect raw rollback or eviction.
{
  const kv = memoryPinHistoryWitnessKv()
  const backend = createBackend(kv)
  await backend.initialize(scope, 0, verified.base)
  const [key, first] = kv.records.entries().next().value
  await backend.append(scope, 1, {
    anchor: verified.base,
    authorityTransitions: [],
    completeBundle: verified.second.bundleBytes,
    verifiedResult: verified.terminal2
  })
  kv.records.set(key, structuredClone(first))
  await assert.rejects(
    backend.read(scope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_ROLLBACK')

  kv.records.delete(key)
  await assert.rejects(
    backend.read(scope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_SILENT_RESET')
}

// Ciphertext, authenticated header, lookup substitution, and clear-record
// structure attacks fail closed before state can reset.
{
  const kv = memoryPinHistoryWitnessKv()
  const backend = createBackend(kv)
  await backend.initialize(scope, 0, verified.base)
  const [key, original] = kv.records.entries().next().value

  const ciphertext = structuredClone(original)
  ciphertext.ciphertext[0] ^= 0xff
  await assert.rejects(
    createBackend(directReadKv(ciphertext)).read(scope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT')

  const aad = structuredClone(original)
  aad.generation = 'ab'.repeat(32)
  await assert.rejects(
    createBackend(directReadKv(aad)).read(scope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT')

  const substitutedKey = structuredClone(original)
  substitutedKey.recordKey = `pin-history-witness:v1:${'00'.repeat(32)}`
  await assert.rejects(
    createBackend(directReadKv(substitutedKey)).read(scope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT')

  for (const evil of [
    Object.assign(structuredClone(original), { extra: true }),
    Object.assign(Object.create({ inherited: true }), structuredClone(original)),
    Object.assign(structuredClone(original), { [Symbol('hidden')]: true })
  ]) {
    await assert.rejects(
      createBackend(directReadKv(evil)).read(scope),
      error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  const accessor = structuredClone(original)
  let getterRan = false
  Object.defineProperty(accessor, 'ciphertext', {
    enumerable: true,
    get () { getterRan = true; throw new Error('must not run') }
  })
  await assert.rejects(
    createBackend(directReadKv(accessor)).read(scope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  assert.equal(getterRan, false)
  const hostileGeneration = structuredClone(original)
  let generationCoercionRan = false
  hostileGeneration.generation = {
    toString () {
      generationCoercionRan = true
      return 'ab'.repeat(32)
    }
  }
  await assert.rejects(
    createBackend(directReadKv(hostileGeneration)).read(scope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT')
  assert.equal(generationCoercionRan, false)
  assert.ok(key)
}

// A record encrypted for the fixed scope cannot be rebound to another lookup,
// and callers cannot create a parallel empty scope.
{
  const kv = memoryPinHistoryWitnessKv()
  await createBackend(kv).initialize(scope, 0, verified.base)
  const wrongScope = {
    ...scope,
    profileScopeHash: hash('attacker-selected-scope')
  }
  await assert.rejects(
    createBackend(kv).read(wrongScope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_SCOPE_MISMATCH')
}

// Plain-data exactness rejects prototype, symbol, extra, sparse, and accessor
// attacks without invoking hostile getters.
{
  const backend = createBackend(memoryPinHistoryWitnessKv())
  await assert.rejects(
    backend.initialize({ ...scope, extra: true }, 0, verified.base),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  const symbolScope = { ...scope }
  symbolScope[Symbol('hidden')] = true
  await assert.rejects(
    backend.read(symbolScope),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  const scopeAccessor = { ...scope }
  let scopeGetterRan = false
  Object.defineProperty(scopeAccessor, 'profileScopeHash', {
    enumerable: true,
    get () { scopeGetterRan = true; throw new Error('must not run') }
  })
  await assert.rejects(
    backend.read(scopeAccessor),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  assert.equal(scopeGetterRan, false)
  await assert.rejects(
    backend.initialize(Object.assign(Object.create({}), scope), 0, verified.base),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  await assert.rejects(
    backend.initialize(scope, 0, { ...verified.base }),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')

  await backend.initialize(scope, 0, verified.base)
  const sparseTransitions = []
  sparseTransitions.length = 1
  await assert.rejects(backend.append(scope, 1, {
    anchor: verified.base,
    authorityTransitions: sparseTransitions,
    completeBundle: verified.second.bundleBytes,
    verifiedResult: verified.terminal2
  }), error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  const appendAccessor = {
    anchor: verified.base,
    authorityTransitions: [],
    completeBundle: verified.second.bundleBytes,
    verifiedResult: verified.terminal2
  }
  let appendGetterRan = false
  Object.defineProperty(appendAccessor, 'completeBundle', {
    enumerable: true,
    get () { appendGetterRan = true; throw new Error('must not run') }
  })
  await assert.rejects(
    backend.append(scope, 1, appendAccessor),
    error => error.code === 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  assert.equal(appendGetterRan, false)
}

assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.moduleFixedProfileScope, true)
assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.encryptedAtRest, true)
assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.nonExtractablePerStoreKey, true)
assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.atomicCrossContextCas, true)
assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.authenticatedBaseCanInitializeImmediately, true)
assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.exactAuthorityTransitionBytesReverifiedBeforePersist, true)
assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.portableExternalRollbackRecoveryReady, false)
assert.equal(PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.postEvictionContinuityRecoveryReady, false)
assert.equal(bytesEqual(scope.profileScopeHash,
  peeritPinHistoryProfileScopeV1().profileScopeHash), true)

console.log('peerit-pin-history-witness-backend: encrypted branded floors, replay, CAS, compaction, tamper, and rollback checks passed')
