import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify
} from 'node:crypto'
import {
  checkpointSignaturePayload,
  compareSubstrateTuples,
  encodePeeritHiveRelayProfilePinV1,
  encodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryCheckpointV1,
  encodeSubstrateTupleV1,
  pinHistoryCheckpointHash,
  profilePinHash,
  profilePinSignaturePayload,
  releaseAuthorityKeyId
} from '../js/substrate/release-control-codec.mjs'
import {
  asciiBytes,
  blake2b256,
  concatBytes,
  hexToBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  PEERIT_MIGRATION_STAGE,
  PEERIT_PROFILE_ID,
  RELEASE_CONTROL_LIMIT
} from '../js/substrate/release-control-registry.mjs'
import { canonicalExpectedPinProjection } from '../js/substrate/release-control-verifier.mjs'

const ED25519_PKCS8_PREFIX = hexToBytes('302e020100300506032b657004220420')
const ED25519_SPKI_PREFIX = hexToBytes('302a300506032b6570032100')

function fixtureSeed (offset) {
  return Uint8Array.from({ length: 32 }, (_, index) => (offset + index) & 0xff)
}

function privateKeyFromSeed (seed) {
  return createPrivateKey({ key: Buffer.from(concatBytes(ED25519_PKCS8_PREFIX, seed)), format: 'der', type: 'pkcs8' })
}

function rawPublicKey (privateKey) {
  const spki = new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }))
  return spki.slice(spki.byteLength - 32)
}

function fixtureHash (label) {
  return blake2b256(asciiBytes(`peerit.release-control.fixture-only.v1:${label}`))
}

function signedPin (value, privateKey) {
  const signature = new Uint8Array(sign(null, Buffer.from(profilePinSignaturePayload(value)), privateKey))
  return { ...value, signature }
}

function signedCheckpoint (value, privateKey) {
  const signature = new Uint8Array(sign(null, Buffer.from(checkpointSignaturePayload(value)), privateKey))
  return { ...value, signature }
}

export function createNodeReleaseControlCrypto () {
  return {
    verifyEd25519 (publicKey, message, signature) {
      const key = createPublicKey({
        key: Buffer.from(concatBytes(ED25519_SPKI_PREFIX, publicKey)),
        format: 'der',
        type: 'spki'
      })
      return verify(null, Buffer.from(message), key, Buffer.from(signature))
    }
  }
}

export function buildReleaseControlFixture () {
  const releasePrivateKey = privateKeyFromSeed(fixtureSeed(0x10))
  const wrongPrivateKey = privateKeyFromSeed(fixtureSeed(0x90))
  const releasePublicKey = rawPublicKey(releasePrivateKey)
  const wrongPublicKey = rawPublicKey(wrongPrivateKey)
  const authorityKeyId = releaseAuthorityKeyId(releasePublicKey)

  const tupleA = {
    specHash: fixtureHash('tuple-a-spec'),
    abiHash: fixtureHash('tuple-a-abi'),
    vectorSetHash: fixtureHash('tuple-a-vectors')
  }
  const tupleB = {
    specHash: fixtureHash('tuple-b-spec'),
    abiHash: fixtureHash('tuple-b-abi'),
    vectorSetHash: fixtureHash('tuple-b-vectors')
  }
  const readSubstrates = [tupleA, tupleB].sort(compareSubstrateTuples)
  const common = {
    version: 1,
    profileId: PEERIT_PROFILE_ID,
    emitSubstrate: tupleB,
    readSubstrates,
    profileSpecHash: fixtureHash('full-profile-spec-placeholder'),
    profileAbiHash: fixtureHash('full-profile-abi-placeholder'),
    profileVectorSetHash: fixtureHash('full-profile-vectors-placeholder'),
    validatorArtifactHash: fixtureHash('validator-placeholder'),
    validatorVectorSetHash: fixtureHash('validator-vectors-placeholder'),
    availabilityPolicyHash: fixtureHash('availability-policy-placeholder'),
    recommendedBootstrapHashes: [fixtureHash('bootstrap-a'), fixtureHash('bootstrap-b')].sort((left, right) => {
      for (let i = 0; i < left.byteLength; i++) if (left[i] !== right[i]) return left[i] - right[i]
      return 0
    }),
    pinHistoryRetentionDays: RELEASE_CONTROL_LIMIT.PIN_HISTORY_RETENTION_DAYS,
    legacySourceSetHash: fixtureHash('legacy-source-set-placeholder'),
    releaseAuthoritySequence: 0n,
    releaseAuthorityPublicKey: releasePublicKey,
    releaseAuthorityKeyId: authorityKeyId,
    authorityTransitionHash: null
  }

  const pin0 = signedPin({
    ...common,
    releaseSequence: 0n,
    previousPinHash: null,
    appArtifactHash: fixtureHash('app-sequence-0'),
    webAssetManifestHash: fixtureHash('web-sequence-0'),
    migrationStage: PEERIT_MIGRATION_STAGE.LIVE_DUAL_READ,
    migrationTransitionEvidenceHash: null,
    legacyImportMode: 0,
    legacyReadMode: 0,
    legacyCutoffHash: null,
    migrationGenesisRecordId: null,
    cutoffActivationReleaseSequence: null,
    legacyRetirementEvidenceHash: null,
    legacyRetirementActivationReleaseSequence: null
  }, releasePrivateKey)
  const pin0Bytes = encodePeeritHiveRelayProfilePinV1(pin0)
  const pin0Hash = profilePinHash(pin0Bytes)

  const pin1 = signedPin({
    ...common,
    releaseSequence: 1n,
    previousPinHash: pin0Hash,
    appArtifactHash: fixtureHash('app-sequence-1'),
    webAssetManifestHash: fixtureHash('web-sequence-1'),
    migrationStage: PEERIT_MIGRATION_STAGE.FROZEN_CUTOFF,
    migrationTransitionEvidenceHash: fixtureHash('migration-transition-0-to-1'),
    legacyImportMode: 1,
    legacyReadMode: 0,
    legacyCutoffHash: fixtureHash('legacy-cutoff'),
    migrationGenesisRecordId: fixtureHash('migration-genesis'),
    cutoffActivationReleaseSequence: 1n,
    legacyRetirementEvidenceHash: null,
    legacyRetirementActivationReleaseSequence: null
  }, releasePrivateKey)
  const pin1Bytes = encodePeeritHiveRelayProfilePinV1(pin1)

  const checkpoint0 = signedCheckpoint({
    version: 1,
    checkpointSequence: 0n,
    previousCheckpointHash: null,
    pinHash: pin0Hash,
    previousPinHash: null,
    issuedUnixMillis: 1700000000000n,
    releaseAuthoritySequence: 0n,
    releaseAuthorityKeyId: authorityKeyId
  }, releasePrivateKey)
  const checkpoint0Bytes = encodePeeritPinHistoryCheckpointV1(checkpoint0)
  const checkpoint0Hash = pinHistoryCheckpointHash(checkpoint0Bytes)

  const checkpoint1 = signedCheckpoint({
    version: 1,
    checkpointSequence: 1n,
    previousCheckpointHash: checkpoint0Hash,
    pinHash: profilePinHash(pin1Bytes),
    previousPinHash: pin0Hash,
    issuedUnixMillis: 1700000001000n,
    releaseAuthoritySequence: 0n,
    releaseAuthorityKeyId: authorityKeyId
  }, releasePrivateKey)
  const checkpoint1Bytes = encodePeeritPinHistoryCheckpointV1(checkpoint1)
  const bundleBytes = encodePeeritPinHistoryBundleV1({
    version: 1,
    checkpoints: [checkpoint0Bytes, checkpoint1Bytes],
    pins: [pin0Bytes, pin1Bytes]
  })

  return {
    fixtureOnly: true,
    releasePrivateKey,
    wrongPrivateKey,
    releasePublicKey,
    wrongPublicKey,
    tuples: { tupleA, tupleB },
    pins: [pin0, pin1],
    pinBytes: [pin0Bytes, pin1Bytes],
    checkpoints: [checkpoint0, checkpoint1],
    checkpointBytes: [checkpoint0Bytes, checkpoint1Bytes],
    bundleBytes,
    expectedPins: [canonicalExpectedPinProjection(pin0), canonicalExpectedPinProjection(pin1)],
    signPin: value => signedPin(value, releasePrivateKey),
    signCheckpoint: value => signedCheckpoint(value, releasePrivateKey),
    signPinWithWrongKey: value => signedPin(value, wrongPrivateKey),
    tupleBytes: [encodeSubstrateTupleV1(tupleA), encodeSubstrateTupleV1(tupleB)]
  }
}
