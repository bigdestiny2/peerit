import assert from 'node:assert/strict'
import fs from 'node:fs'
import {
  createPrivateKey,
  createPublicKey,
  sign
} from 'node:crypto'
import {
  checkpointSignaturePayload,
  decodePeeritPinHistoryBundleV1,
  encodePeeritHiveRelayProfilePinV1,
  encodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryCheckpointV1,
  pinHistoryCheckpointHash,
  PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX,
  profilePinHash,
  profilePinSignaturePayload,
  releaseAuthorityKeyId
} from '../js/substrate/release-control-codec.mjs'
import { decodePeeritProfileRegistry } from '../js/substrate/profile-artifact-codec.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  concatBytes,
  hexToBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  decodePeeritReleaseAuthorityTransitionV1,
  encodePeeritReleaseAuthorityTransitionV1,
  PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES,
  PEERIT_RELEASE_AUTHORITY_TRANSITION_TAG,
  releaseAuthorityTransitionHash,
  releaseAuthorityTransitionSignatureCommitment,
  verifyPeeritReleaseAuthorityTransitionV1
} from '../js/substrate/release-authority-transition.mjs'
import {
  canonicalExpectedPinProjection,
  getVerifiedPinHistoryTerminalSnapshotV1,
  verifyPeeritPinHistoryBundleV1,
  verifyPeeritPinHistoryContinuationV1,
  verifyPeeritProfilePinV1
} from '../js/substrate/release-control-verifier.mjs'
import {
  buildReleaseControlFixture,
  createNodeReleaseControlCrypto
} from '../scripts/release-control-fixture.mjs'

const PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420')
const fixture = buildReleaseControlFixture()
const crypto = createNodeReleaseControlCrypto()

function privateKey (offset) {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => (offset + index) & 0xff)
  return createPrivateKey({
    key: Buffer.from(concatBytes(PKCS8_PREFIX, seed)),
    format: 'der',
    type: 'pkcs8'
  })
}

function publicKey (privateKey) {
  const encoded = new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }))
  return encoded.slice(-32)
}

function hash (label) {
  return blake2b256(asciiBytes(`peerit.release-authority-transition.test:${label}`))
}

function transition (fields, previousPrivateKey, nextPrivateKey) {
  const unsigned = {
    ...fields,
    version: 1,
    previousKeySignature: new Uint8Array(64),
    nextKeySignature: new Uint8Array(64)
  }
  const commitment = releaseAuthorityTransitionSignatureCommitment(unsigned)
  return {
    ...unsigned,
    previousKeySignature: new Uint8Array(sign(null, Buffer.from(commitment), previousPrivateKey)),
    nextKeySignature: new Uint8Array(sign(null, Buffer.from(commitment), nextPrivateKey))
  }
}

function signedPin (value, key) {
  return {
    ...value,
    signature: new Uint8Array(sign(null, Buffer.from(profilePinSignaturePayload(value)), key))
  }
}

function nextPin (previousBytes, releaseSequence, key, authoritySequence, authorityTransitionHash, overrides = {}) {
  const base = fixture.pins[1]
  return signedPin({
    ...base,
    releaseSequence,
    previousPinHash: profilePinHash(previousBytes),
    appArtifactHash: hash(`app-${releaseSequence}`),
    webAssetManifestHash: hash(`web-${releaseSequence}`),
    migrationTransitionEvidenceHash: null,
    releaseAuthoritySequence: authoritySequence,
    releaseAuthorityPublicKey: publicKey(key),
    releaseAuthorityKeyId: releaseAuthorityKeyId(publicKey(key)),
    authorityTransitionHash,
    signature: undefined,
    ...overrides
  }, key)
}

function checkpoint (pin, pinBytes, previousBytes, key) {
  const value = {
    version: 1,
    checkpointSequence: pin.releaseSequence,
    previousCheckpointHash: pinHistoryCheckpointHash(previousBytes),
    pinHash: profilePinHash(pinBytes),
    previousPinHash: pin.previousPinHash,
    issuedUnixMillis: 1700000000000n + pin.releaseSequence * 1000n,
    releaseAuthoritySequence: pin.releaseAuthoritySequence,
    releaseAuthorityKeyId: pin.releaseAuthorityKeyId
  }
  return {
    ...value,
    signature: new Uint8Array(sign(null, Buffer.from(checkpointSignaturePayload(value)), key))
  }
}

function bundle (pin, pinBytes, checkpointValue) {
  return encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [pinBytes],
    checkpoints: [encodePeeritPinHistoryCheckpointV1(checkpointValue)]
  })
}

function multiRotationBundle (count) {
  const pins = []
  const checkpoints = []
  const transitions = []
  let previousPinBytes = fixture.pinBytes[1]
  let previousCheckpointBytes = fixture.checkpointBytes[1]
  let previousKey = fixture.releasePrivateKey
  let previousPublicKey = fixture.releasePublicKey
  for (let authoritySequence = 1; authoritySequence <= count; authoritySequence++) {
    const nextKey = privateKey(0x60 + authoritySequence * 3)
    const nextPublicKey = publicKey(nextKey)
    const releaseSequence = 1n + BigInt(authoritySequence)
    const value = transition({
      previousSequence: BigInt(authoritySequence - 1),
      nextSequence: BigInt(authoritySequence),
      previousPublicKey,
      nextPublicKey,
      validFromRelease: releaseSequence
    }, previousKey, nextKey)
    const transitionBytes = encodePeeritReleaseAuthorityTransitionV1(value)
    const pin = nextPin(previousPinBytes, releaseSequence, nextKey,
      BigInt(authoritySequence), releaseAuthorityTransitionHash(transitionBytes))
    const pinBytes = encodePeeritHiveRelayProfilePinV1(pin)
    const checkpointValue = checkpoint(
      pin, pinBytes, previousCheckpointBytes, nextKey)
    const checkpointBytes = encodePeeritPinHistoryCheckpointV1(checkpointValue)
    transitions.push(transitionBytes)
    pins.push(pinBytes)
    checkpoints.push(checkpointBytes)
    previousPinBytes = pinBytes
    previousCheckpointBytes = checkpointBytes
    previousKey = nextKey
    previousPublicKey = nextPublicKey
  }
  return {
    bytes: encodePeeritPinHistoryBundleV1({ version: 1, pins, checkpoints }),
    transitions
  }
}

const newPrivateKey = privateKey(0x50)
const newPublicKey = publicKey(newPrivateKey)
const transitionValue = transition({
  previousSequence: 0n,
  nextSequence: 1n,
  previousPublicKey: fixture.releasePublicKey,
  nextPublicKey: newPublicKey,
  validFromRelease: 2n
}, fixture.releasePrivateKey, newPrivateKey)
const transitionBytes = encodePeeritReleaseAuthorityTransitionV1(transitionValue)
const transitionHash = releaseAuthorityTransitionHash(transitionBytes)
const pin2 = nextPin(fixture.pinBytes[1], 2n, newPrivateKey, 1n, transitionHash)
const pin2Bytes = encodePeeritHiveRelayProfilePinV1(pin2)
const checkpoint2 = checkpoint(pin2, pin2Bytes, fixture.checkpointBytes[1], newPrivateKey)
const bundle2 = bundle(pin2, pin2Bytes, checkpoint2)

const exactAnchor = await verifyPeeritPinHistoryBundleV1(fixture.bundleBytes, {
  crypto,
  expectedPins: fixture.expectedPins
})

assert.deepEqual(decodePeeritReleaseAuthorityTransitionV1(transitionBytes), transitionValue)
assert.equal(transitionBytes.byteLength, PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES)
assert.equal(transitionBytes[0] * 0x100 + transitionBytes[1],
  PEERIT_RELEASE_AUTHORITY_TRANSITION_TAG)
const profileRegistry = decodePeeritProfileRegistry(new Uint8Array(fs.readFileSync(
  new URL('../protocol/peerit-profile-v1.cenc', import.meta.url))))
assert.equal(profileRegistry.schemas.find(
  entry => entry.name === 'PeeritReleaseAuthorityTransitionV1').tag,
PEERIT_RELEASE_AUTHORITY_TRANSITION_TAG)
const verifiedTransition = await verifyPeeritReleaseAuthorityTransitionV1(transitionBytes, {
  crypto,
  previousPin: fixture.pins[1],
  nextPin: pin2
})
assert.equal(bytesEqual(verifiedTransition.transitionHash, transitionHash), true)

const rotated = await verifyPeeritPinHistoryContinuationV1(bundle2, {
  crypto,
  anchor: exactAnchor,
  authorityTransitions: [transitionBytes]
})
assert.equal(rotated.terminalSequence, 2n)
assert.equal(rotated.authorityTransitionCount, 1)

const pin3 = nextPin(pin2Bytes, 3n, newPrivateKey, 1n, null)
const pin3Bytes = encodePeeritHiveRelayProfilePinV1(pin3)
const checkpoint2Bytes = encodePeeritPinHistoryCheckpointV1(checkpoint2)
const checkpoint3 = checkpoint(pin3, pin3Bytes, checkpoint2Bytes, newPrivateKey)
const continued = await verifyPeeritPinHistoryContinuationV1(bundle(pin3, pin3Bytes, checkpoint3), {
  crypto,
  anchor: rotated
})
assert.equal(continued.terminalSequence, 3n)
assert.equal(continued.authorityTransitionCount, 0)

await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle2, {
  crypto,
  anchor: { ...exactAnchor },
  authorityTransitions: [transitionBytes]
}), error => error.code === 'VERIFIED_PIN_HISTORY_ANCHOR_REQUIRED')
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle2, {
  crypto,
  anchor: exactAnchor
}), error => error.code === 'AUTHORITY_TRANSITION_REQUIRED')

const wrongOldSignature = transition({
  previousSequence: 0n,
  nextSequence: 1n,
  previousPublicKey: fixture.releasePublicKey,
  nextPublicKey: newPublicKey,
  validFromRelease: 2n
}, newPrivateKey, newPrivateKey)
const wrongOldBytes = encodePeeritReleaseAuthorityTransitionV1(wrongOldSignature)
const wrongOldPin = nextPin(fixture.pinBytes[1], 2n, newPrivateKey, 1n,
  releaseAuthorityTransitionHash(wrongOldBytes))
const wrongOldPinBytes = encodePeeritHiveRelayProfilePinV1(wrongOldPin)
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  wrongOldPin,
  wrongOldPinBytes,
  checkpoint(wrongOldPin, wrongOldPinBytes, fixture.checkpointBytes[1], newPrivateKey)
), {
  crypto,
  anchor: exactAnchor,
  authorityTransitions: [wrongOldBytes]
}), error => error.code === 'BAD_AUTHORITY_TRANSITION_SIGNATURE')

const wrongActivation = transition({
  previousSequence: 0n,
  nextSequence: 1n,
  previousPublicKey: fixture.releasePublicKey,
  nextPublicKey: newPublicKey,
  validFromRelease: 3n
}, fixture.releasePrivateKey, newPrivateKey)
const wrongActivationBytes = encodePeeritReleaseAuthorityTransitionV1(wrongActivation)
const wrongActivationPin = nextPin(fixture.pinBytes[1], 2n, newPrivateKey, 1n,
  releaseAuthorityTransitionHash(wrongActivationBytes))
const wrongActivationPinBytes = encodePeeritHiveRelayProfilePinV1(wrongActivationPin)
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  wrongActivationPin,
  wrongActivationPinBytes,
  checkpoint(wrongActivationPin, wrongActivationPinBytes, fixture.checkpointBytes[1], newPrivateKey)
), {
  crypto,
  anchor: exactAnchor,
  authorityTransitions: [wrongActivationBytes]
}), error => error.code === 'AUTHORITY_TRANSITION_BINDING_MISMATCH')

const noTransitionPin = nextPin(fixture.pinBytes[1], 2n, newPrivateKey, 1n, null)
const noTransitionPinBytes = encodePeeritHiveRelayProfilePinV1(noTransitionPin)
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  noTransitionPin,
  noTransitionPinBytes,
  checkpoint(noTransitionPin, noTransitionPinBytes, fixture.checkpointBytes[1], newPrivateKey)
), { crypto, anchor: exactAnchor }), error => error.code === 'AUTHORITY_TRANSITION_REQUIRED')

const unexpectedPin = nextPin(pin2Bytes, 3n, newPrivateKey, 1n, transitionHash)
const unexpectedPinBytes = encodePeeritHiveRelayProfilePinV1(unexpectedPin)
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  unexpectedPin,
  unexpectedPinBytes,
  checkpoint(unexpectedPin, unexpectedPinBytes, checkpoint2Bytes, newPrivateKey)
), {
  crypto,
  anchor: rotated,
  authorityTransitions: [transitionBytes]
}), error => error.code === 'UNEXPECTED_AUTHORITY_TRANSITION')

await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(pin3, pin3Bytes, checkpoint3), {
  crypto,
  anchor: rotated,
  authorityTransitions: [transitionBytes]
}), error => error.code === 'BAD_AUTHORITY_TRANSITION_SET')

const forkedPin = nextPin(pin2Bytes, 3n, newPrivateKey, 1n, null)
const forkedPinBytes = encodePeeritHiveRelayProfilePinV1(forkedPin)
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  forkedPin,
  forkedPinBytes,
  checkpoint(forkedPin, forkedPinBytes, checkpoint2Bytes, newPrivateKey)
), {
  crypto,
  anchor: rotated,
  witnessedPinHashes: { 3: hash('witnessed-other-pin') }
}), error => error.code === 'PIN_HISTORY_FORK')

await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  pin3,
  pin3Bytes,
  checkpoint3
), {
  crypto,
  anchor: rotated,
  witnessedCheckpointHashes: { 3: hash('witnessed-other-checkpoint') }
}), error => error.code === 'CHECKPOINT_HISTORY_FORK')

const ambiguousWitnesses = new Map([
  [3n, profilePinHash(pin3Bytes)],
  ['3', hash('conflicting-string-witness')]
])
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  pin3,
  pin3Bytes,
  checkpoint3
), {
  crypto,
  anchor: rotated,
  witnessedPinHashes: ambiguousWitnesses
}), error => error.code === 'AMBIGUOUS_WITNESSED_HASH')

const accessorWitnesses = {}
Object.defineProperty(accessorWitnesses, '3', {
  enumerable: true,
  get () { return profilePinHash(pin3Bytes) }
})
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  pin3,
  pin3Bytes,
  checkpoint3
), {
  crypto,
  anchor: rotated,
  witnessedPinHashes: accessorWitnesses
}), error => error.code === 'BAD_WITNESSED_HASH_SET')
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  pin3,
  pin3Bytes,
  checkpoint3
), {
  crypto,
  anchor: rotated,
  witnessedPinHashes: { 3: null }
}), error => error.code === 'BAD_RELEASE_CONTROL_ENCODING')

const deferredCrypto = {
  async verifyEd25519 (...arguments_) {
    await Promise.resolve()
    return crypto.verifyEd25519(...arguments_)
  }
}
const wrongAuthorityPin = fixture.signPinWithWrongKey({
  ...fixture.pins[0],
  releaseAuthorityPublicKey: fixture.wrongPublicKey,
  releaseAuthorityKeyId: releaseAuthorityKeyId(fixture.wrongPublicKey),
  signature: undefined
})
const mutableExpectedPin = canonicalExpectedPinProjection(fixture.pins[0])
const expectedMutationVerification = verifyPeeritProfilePinV1(
  encodePeeritHiveRelayProfilePinV1(wrongAuthorityPin), {
    crypto: deferredCrypto,
    expected: mutableExpectedPin
  })
Object.assign(mutableExpectedPin, canonicalExpectedPinProjection(wrongAuthorityPin))
await assert.rejects(expectedMutationVerification,
  error => error.code === 'PROFILE_PIN_EXPECTATION_MISMATCH')
const extraExpectedField = canonicalExpectedPinProjection(fixture.pins[0])
extraExpectedField.extra = true
await assert.rejects(verifyPeeritProfilePinV1(fixture.pinBytes[0], {
  crypto,
  expected: extraExpectedField
}), error => error.code === 'INCOMPLETE_EXPECTED_PROFILE_PIN')
const copiedExpected = canonicalExpectedPinProjection(fixture.pins[0])
copiedExpected.profileSpecHash.fill(0)
assert.equal(fixture.pins[0].profileSpecHash.some(value => value !== 0), true)
const bufferedTransition = Buffer.from(transitionBytes)
const bufferedVerification = verifyPeeritReleaseAuthorityTransitionV1(
  bufferedTransition, {
    crypto: deferredCrypto,
    previousPin: fixture.pins[1],
    nextPin: pin2
  })
bufferedTransition.fill(0)
const immutableTransition = await bufferedVerification
assert.equal(bytesEqual(immutableTransition.bytes, transitionBytes), true)
const exposedTransitionBytes = immutableTransition.bytes
const exposedTransition = immutableTransition.transition
exposedTransitionBytes.fill(0)
exposedTransition.nextPublicKey.fill(0)
assert.equal(bytesEqual(immutableTransition.bytes, transitionBytes), true)
assert.equal(bytesEqual(immutableTransition.transition.nextPublicKey, newPublicKey), true)

const bufferedDecodeInput = Buffer.from(transitionBytes)
const bufferedDecoded = decodePeeritReleaseAuthorityTransitionV1(bufferedDecodeInput)
bufferedDecodeInput.fill(0)
assert.equal(bytesEqual(bufferedDecoded.nextPublicKey, newPublicKey), true)

const stableWitness = { 3: profilePinHash(pin3Bytes) }
const stableWitnessVerification = verifyPeeritPinHistoryContinuationV1(bundle(
  pin3,
  pin3Bytes,
  checkpoint3
), {
  crypto: deferredCrypto,
  anchor: rotated,
  witnessedPinHashes: stableWitness
})
stableWitness[3].fill(0)
assert.equal((await stableWitnessVerification).terminalSequence, 3n)

const initiallyForkedWitness = { 3: hash('initially-forked') }
const initiallyForkedVerification = verifyPeeritPinHistoryContinuationV1(bundle(
  pin3,
  pin3Bytes,
  checkpoint3
), {
  crypto: deferredCrypto,
  anchor: rotated,
  witnessedPinHashes: initiallyForkedWitness
})
initiallyForkedWitness[3].set(profilePinHash(pin3Bytes))
await assert.rejects(initiallyForkedVerification,
  error => error.code === 'PIN_HISTORY_FORK')

const pin4 = nextPin(pin3Bytes, 4n, newPrivateKey, 1n, null)
const validPin4Bytes = encodePeeritHiveRelayProfilePinV1(pin4)
const invalidPin4Bytes = new Uint8Array(validPin4Bytes)
invalidPin4Bytes[invalidPin4Bytes.byteLength - 1] ^= 1
const checkpoint4Value = checkpoint(
  pin4, invalidPin4Bytes, encodePeeritPinHistoryCheckpointV1(checkpoint3),
  newPrivateKey)
const mutableCryptoRuntime = {}
let releaseFirstVerification
let firstVerification = true
mutableCryptoRuntime.verifyEd25519 = async function (...arguments_) {
  if (firstVerification) {
    firstVerification = false
    await new Promise(resolve => { releaseFirstVerification = resolve })
  }
  return crypto.verifyEd25519(...arguments_)
}
const mutableRuntimeVerification = verifyPeeritPinHistoryContinuationV1(
  encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [pin3Bytes, invalidPin4Bytes],
    checkpoints: [encodePeeritPinHistoryCheckpointV1(checkpoint3),
      encodePeeritPinHistoryCheckpointV1(checkpoint4Value)]
  }), {
    crypto: mutableCryptoRuntime,
    anchor: rotated
  })
mutableCryptoRuntime.verifyEd25519 = async () => true
releaseFirstVerification()
await assert.rejects(mutableRuntimeVerification,
  error => error.code === 'BAD_PROFILE_PIN_SIGNATURE')

const terminalSnapshot = getVerifiedPinHistoryTerminalSnapshotV1(rotated)
assert.equal(terminalSnapshot.terminalSequence, 2n)
assert.equal(bytesEqual(terminalSnapshot.terminalPinBytes, pin2Bytes), true)
assert.equal(bytesEqual(terminalSnapshot.terminalPinHash, profilePinHash(pin2Bytes)), true)
assert.equal(bytesEqual(
  terminalSnapshot.terminalCheckpointHash,
  pinHistoryCheckpointHash(encodePeeritPinHistoryCheckpointV1(checkpoint2))), true)
const mutatedSnapshotBytes = terminalSnapshot.terminalPinBytes
mutatedSnapshotBytes.fill(0)
assert.equal(bytesEqual(terminalSnapshot.terminalPinBytes, pin2Bytes), true)
const recopiedSnapshot = getVerifiedPinHistoryTerminalSnapshotV1(terminalSnapshot)
assert.equal(bytesEqual(recopiedSnapshot.terminalPinBytes, pin2Bytes), true)
assert.throws(() => getVerifiedPinHistoryTerminalSnapshotV1({ ...terminalSnapshot }),
  error => error.code === 'VERIFIED_PIN_HISTORY_TERMINAL_REQUIRED')
await assert.rejects(verifyPeeritPinHistoryContinuationV1(bundle(
  pin3,
  pin3Bytes,
  checkpoint3
), {
  crypto,
  anchor: terminalSnapshot
}), error => error.code === 'VERIFIED_PIN_HISTORY_ANCHOR_REQUIRED')

const seventeenRotations = multiRotationBundle(17)
const manyRotations = await verifyPeeritPinHistoryContinuationV1(
  seventeenRotations.bytes, {
    crypto,
    anchor: exactAnchor,
    authorityTransitions: [...seventeenRotations.transitions].reverse()
  })
assert.equal(manyRotations.terminalSequence, 18n)
assert.equal(manyRotations.authorityTransitionCount, 17)

const gapPin = nextPin(pin2Bytes, 4n, newPrivateKey, 1n, null)
const gapPinBytes = encodePeeritHiveRelayProfilePinV1(gapPin)
const gapCheckpoint = checkpoint(
  gapPin, gapPinBytes, checkpoint2Bytes, newPrivateKey)
const gapCheckpointBytes = encodePeeritPinHistoryCheckpointV1(gapCheckpoint)
const afterGapPin = nextPin(gapPinBytes, 5n, newPrivateKey, 1n, null)
const afterGapPinBytes = encodePeeritHiveRelayProfilePinV1(afterGapPin)
const afterGapCheckpoint = checkpoint(
  afterGapPin, afterGapPinBytes, gapCheckpointBytes, newPrivateKey)
const gapBundle = encodePeeritPinHistoryBundleV1({
  version: 1,
  pins: [gapPinBytes, afterGapPinBytes],
  checkpoints: [gapCheckpointBytes,
    encodePeeritPinHistoryCheckpointV1(afterGapCheckpoint)]
})
let verificationCount = 0
const countingCrypto = {
  async verifyEd25519 (...arguments_) {
    verificationCount++
    return crypto.verifyEd25519(...arguments_)
  }
}
await assert.rejects(verifyPeeritPinHistoryContinuationV1(gapBundle, {
  crypto: countingCrypto,
  anchor: rotated
}), error => error.code === 'PIN_HISTORY_GAP_OR_FORK')
assert.equal(verificationCount, 2)

assert.throws(() => decodePeeritPinHistoryBundleV1(
  new Uint8Array(PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX + 1)),
error => error.code === 'BAD_PIN_HISTORY_BUNDLE')

assert.throws(() => encodePeeritReleaseAuthorityTransitionV1({
  ...transitionValue,
  nextSequence: 2n
}), error => error.code === 'BAD_AUTHORITY_TRANSITION')
assert.throws(() => decodePeeritReleaseAuthorityTransitionV1(
  new Uint8Array([...transitionBytes, 0])))
assert.throws(() => encodePeeritReleaseAuthorityTransitionV1({
  ...transitionValue,
  extra: true
}), error => error.code === 'BAD_AUTHORITY_TRANSITION')

const accessorTransition = { ...transitionValue }
Object.defineProperty(accessorTransition, 'nextSequence', {
  enumerable: true,
  get () { return 1n }
})
assert.throws(() => encodePeeritReleaseAuthorityTransitionV1(accessorTransition),
  error => error.code === 'BAD_AUTHORITY_TRANSITION')
assert.throws(() => encodePeeritReleaseAuthorityTransitionV1({
  ...transitionValue,
  [Symbol('hidden')]: true
}), error => error.code === 'BAD_AUTHORITY_TRANSITION')
const nonenumerableTransition = { ...transitionValue }
Object.defineProperty(nonenumerableTransition, 'version', {
  value: 1,
  enumerable: false
})
assert.throws(() => encodePeeritReleaseAuthorityTransitionV1(nonenumerableTransition),
  error => error.code === 'BAD_AUTHORITY_TRANSITION')
const nullPrototypeTransition = Object.assign(Object.create(null), transitionValue)
assert.equal(bytesEqual(
  encodePeeritReleaseAuthorityTransitionV1(nullPrototypeTransition), transitionBytes), true)

for (let index = 0; index < transitionBytes.byteLength; index++) {
  const changed = new Uint8Array(transitionBytes)
  changed[index] ^= 1
  await assert.rejects(verifyPeeritReleaseAuthorityTransitionV1(changed, {
    crypto,
    previousPin: fixture.pins[1],
    nextPin: pin2
  }))
}
const wrongNewSignatureBytes = new Uint8Array(transitionBytes)
wrongNewSignatureBytes[wrongNewSignatureBytes.byteLength - 1] ^= 1
const wrongNewSignaturePin = {
  ...pin2,
  authorityTransitionHash: releaseAuthorityTransitionHash(wrongNewSignatureBytes)
}
await assert.rejects(verifyPeeritReleaseAuthorityTransitionV1(
  wrongNewSignatureBytes, {
    crypto,
    previousPin: fixture.pins[1],
    nextPin: wrongNewSignaturePin
  }), error => error.code === 'BAD_AUTHORITY_TRANSITION_SIGNATURE')

await assert.rejects(verifyPeeritReleaseAuthorityTransitionV1(transitionBytes, {
  crypto,
  previousPin: {},
  nextPin: pin2
}), error => error.code === 'AUTHORITY_TRANSITION_BINDING_MISMATCH')

assert.deepEqual(canonicalExpectedPinProjection(fixture.pins[1]).releaseAuthoritySequence, 0n)
console.log('peerit-release-authority-transition: dual-signature rotation and unknown-newer continuity passed')
