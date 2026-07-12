import {
  checkpointSignaturePayload,
  checkpointSignaturePayloadHash,
  compareSubstrateTuples,
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  decodePeeritPinHistoryCheckpointV1,
  encodeSubstrateTupleV1,
  PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX,
  pinHistoryBundleHash,
  pinHistoryCheckpointHash,
  profilePinHash,
  profilePinSignaturePayload,
  profilePinSignaturePayloadHash,
  releaseAuthorityKeyId
} from './release-control-codec.mjs'
import {
  asBytes,
  asU64,
  bytesEqual,
  failReleaseControl,
  fixedBytesValue,
  isAllZero
} from './release-control-primitives.mjs'
import {
  PEERIT_MIGRATION_STAGE,
  RELEASE_CONTROL_LIMIT
} from './release-control-registry.mjs'
import {
  releaseAuthorityTransitionHash,
  verifyPeeritReleaseAuthorityTransitionV1
} from './release-authority-transition.mjs'

const EXPECTED_BYTES_FIELDS = Object.freeze([
  'previousPinHash',
  'profileSpecHash',
  'profileAbiHash',
  'profileVectorSetHash',
  'validatorArtifactHash',
  'validatorVectorSetHash',
  'availabilityPolicyHash',
  'appArtifactHash',
  'webAssetManifestHash',
  'legacySourceSetHash',
  'migrationTransitionEvidenceHash',
  'legacyCutoffHash',
  'migrationGenesisRecordId',
  'legacyRetirementEvidenceHash',
  'releaseAuthorityPublicKey',
  'releaseAuthorityKeyId',
  'authorityTransitionHash'
])

const EXPECTED_SCALAR_FIELDS = Object.freeze([
  'releaseSequence',
  'pinHistoryRetentionDays',
  'migrationStage',
  'legacyImportMode',
  'legacyReadMode',
  'cutoffActivationReleaseSequence',
  'legacyRetirementActivationReleaseSequence',
  'releaseAuthoritySequence'
])

const EXPECTED_NULLABLE_BYTES_FIELDS = new Set([
  'previousPinHash',
  'migrationTransitionEvidenceHash',
  'legacyCutoffHash',
  'migrationGenesisRecordId',
  'legacyRetirementEvidenceHash',
  'authorityTransitionHash'
])

const EXPECTED_PIN_FIELDS = Object.freeze([
  'emitSubstrate',
  'readSubstrates',
  'recommendedBootstrapHashes',
  ...EXPECTED_BYTES_FIELDS,
  ...EXPECTED_SCALAR_FIELDS
])

const VERIFIED_TERMINALS = new WeakMap()
const VERIFIED_TERMINAL_SNAPSHOTS = new WeakMap()
const NO_WITNESS = Symbol('NO_WITNESS')

function snapshotBoundedBytes (input, field, minimum, maximum, code, message) {
  const value = asBytes(input, field)
  if (value.byteLength < minimum || value.byteLength > maximum) {
    failReleaseControl(code, message)
  }
  // Buffer#slice aliases its source and SharedArrayBuffer views can change from
  // another agent. A plain Uint8Array construction is an actual byte snapshot.
  return new Uint8Array(value)
}

function snapshotPinBytes (input) {
  return snapshotBoundedBytes(input, 'complete signed pin', 1,
    RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX, 'BAD_PROFILE_PIN_SIZE',
    'profile pin must be bytes[1..8192]')
}

function snapshotCheckpointBytes (input) {
  return snapshotBoundedBytes(input, 'complete signed checkpoint', 1,
    RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MAX, 'BAD_CHECKPOINT_SIZE',
    'checkpoint must be bytes[1..1024]')
}

function snapshotBundleBytes (input, field) {
  return snapshotBoundedBytes(input, field, 1,
    PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX, 'BAD_PIN_HISTORY_BUNDLE',
    `pin history bundle must be bytes[1..${PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX}]`)
}

export function getVerifiedPinHistoryTerminalSnapshotV1 (value) {
  const source = VERIFIED_TERMINALS.get(value) || VERIFIED_TERMINAL_SNAPSHOTS.get(value)
  if (!source) {
    failReleaseControl('VERIFIED_PIN_HISTORY_TERMINAL_REQUIRED',
      'a module-branded verified pin-history result or terminal snapshot is required')
  }
  const terminal = {
    sequence: source.sequence,
    pinBytes: new Uint8Array(source.pinBytes),
    pinHash: new Uint8Array(source.pinHash),
    checkpointHash: new Uint8Array(source.checkpointHash)
  }
  const snapshot = Object.freeze({
    version: 1,
    terminalSequence: terminal.sequence,
    get terminalPinBytes () { return new Uint8Array(terminal.pinBytes) },
    get terminalPinHash () { return new Uint8Array(terminal.pinHash) },
    get terminalCheckpointHash () { return new Uint8Array(terminal.checkpointHash) }
  })
  // Deliberately use a separate brand. A terminal snapshot can be validated and
  // recopied by this getter, but it is never accepted as a continuation anchor.
  VERIFIED_TERMINAL_SNAPSHOTS.set(snapshot, terminal)
  return snapshot
}

function snapshotCryptoRuntime (cryptoRuntime) {
  if (!cryptoRuntime || typeof cryptoRuntime.verifyEd25519 !== 'function') {
    failReleaseControl('RELEASE_CONTROL_CRYPTO_UNAVAILABLE', 'verifyEd25519 runtime is required')
  }
  const verifyEd25519 = cryptoRuntime.verifyEd25519.bind(cryptoRuntime)
  return Object.freeze({ verifyEd25519 })
}

function nullableBytesEqual (left, right) {
  if (left == null || right == null) return left == null && right == null
  return bytesEqual(left, right)
}

function scalarEqual (left, right) {
  if (typeof left === 'bigint' || typeof right === 'bigint') {
    try {
      return BigInt(left) === BigInt(right)
    } catch {
      return false
    }
  }
  return left === right
}

function exactExpectedPinFields (expected) {
  if (!expected || typeof expected !== 'object' || Array.isArray(expected) ||
      (Object.getPrototypeOf(expected) !== Object.prototype &&
       Object.getPrototypeOf(expected) !== null)) {
    failReleaseControl('EXPECTED_PROFILE_PIN_REQUIRED',
      'an authenticated expected pin projection must be a plain object')
  }
  const keys = Reflect.ownKeys(expected)
  if (keys.length !== EXPECTED_PIN_FIELDS.length ||
      keys.some(key => typeof key !== 'string') ||
      EXPECTED_PIN_FIELDS.some(field => !Object.prototype.hasOwnProperty.call(expected, field))) {
    failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
      'expected pin projection fields are missing or unexpected')
  }
  const descriptors = Object.getOwnPropertyDescriptors(expected)
  const snapshot = Object.create(null)
  for (const field of EXPECTED_PIN_FIELDS) {
    if (!descriptors[field] || !descriptors[field].enumerable ||
        !Object.prototype.hasOwnProperty.call(descriptors[field], 'value')) {
      failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
        `expected pin ${field} must be an enumerable data field`)
    }
    snapshot[field] = descriptors[field].value
  }
  return snapshot
}

function snapshotExpectedTuple (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype &&
       Object.getPrototypeOf(value) !== null)) {
    failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
      `expected pin ${field} must be a complete SubstrateTupleV1`)
  }
  const fields = ['specHash', 'abiHash', 'vectorSetHash']
  const keys = Reflect.ownKeys(value)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string') ||
      fields.some(key => !descriptors[key] || !descriptors[key].enumerable ||
        !Object.prototype.hasOwnProperty.call(descriptors[key], 'value'))) {
    failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
      `expected pin ${field} must be an exact SubstrateTupleV1`)
  }
  return {
    specHash: new Uint8Array(fixedBytesValue(
      descriptors.specHash.value, 32, `${field}.specHash`)),
    abiHash: new Uint8Array(fixedBytesValue(
      descriptors.abiHash.value, 32, `${field}.abiHash`)),
    vectorSetHash: new Uint8Array(fixedBytesValue(
      descriptors.vectorSetHash.value, 32, `${field}.vectorSetHash`))
  }
}

function snapshotExpectedPinProjection (input) {
  const expected = exactExpectedPinFields(input)
  const output = Object.create(null)
  output.emitSubstrate = snapshotExpectedTuple(expected.emitSubstrate, 'emitSubstrate')
  if (!Array.isArray(expected.readSubstrates) ||
      expected.readSubstrates.length < RELEASE_CONTROL_LIMIT.READ_SUBSTRATES_MIN ||
      expected.readSubstrates.length > RELEASE_CONTROL_LIMIT.READ_SUBSTRATES_MAX) {
    failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
      'expected pin readSubstrates must contain 1..3 tuples')
  }
  output.readSubstrates = []
  for (let index = 0; index < expected.readSubstrates.length; index++) {
    if (!Object.prototype.hasOwnProperty.call(expected.readSubstrates, index)) {
      failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
        'expected pin readSubstrates must not be sparse')
    }
    output.readSubstrates.push(snapshotExpectedTuple(
      expected.readSubstrates[index], `readSubstrates[${index}]`))
  }
  if (!Array.isArray(expected.recommendedBootstrapHashes) ||
      expected.recommendedBootstrapHashes.length >
      RELEASE_CONTROL_LIMIT.RECOMMENDED_BOOTSTRAPS_MAX) {
    failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
      'expected pin recommendedBootstrapHashes must contain at most 16 hashes')
  }
  output.recommendedBootstrapHashes = []
  for (let index = 0; index < expected.recommendedBootstrapHashes.length; index++) {
    if (!Object.prototype.hasOwnProperty.call(expected.recommendedBootstrapHashes, index)) {
      failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
        'expected pin recommendedBootstrapHashes must not be sparse')
    }
    output.recommendedBootstrapHashes.push(new Uint8Array(fixedBytesValue(
      expected.recommendedBootstrapHashes[index], 32,
      `expected.recommendedBootstrapHashes[${index}]`)))
  }
  for (const field of EXPECTED_BYTES_FIELDS) {
    if (expected[field] === null && EXPECTED_NULLABLE_BYTES_FIELDS.has(field)) {
      output[field] = null
    } else {
      output[field] = new Uint8Array(fixedBytesValue(
        expected[field], 32, `expected.${field}`))
    }
  }
  for (const field of EXPECTED_SCALAR_FIELDS) output[field] = expected[field]
  for (const field of [
    'releaseSequence',
    'releaseAuthoritySequence'
  ]) output[field] = asU64(output[field], `expected.${field}`)
  for (const field of [
    'cutoffActivationReleaseSequence',
    'legacyRetirementActivationReleaseSequence'
  ]) {
    if (output[field] !== null) output[field] = asU64(output[field], `expected.${field}`)
  }
  for (const field of [
    'pinHistoryRetentionDays',
    'migrationStage',
    'legacyImportMode',
    'legacyReadMode'
  ]) {
    if (!Number.isSafeInteger(output[field])) {
      failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN',
        `expected pin ${field} must be an integer`)
    }
  }
  return output
}

function requireExpectedField (expected, field) {
  if (!Object.prototype.hasOwnProperty.call(expected, field)) {
    failReleaseControl('INCOMPLETE_EXPECTED_PROFILE_PIN', `expected pin is missing ${field}`)
  }
}

function assertTupleEqual (actual, expected, field) {
  if (!expected || !bytesEqual(encodeSubstrateTupleV1(actual), encodeSubstrateTupleV1(expected))) {
    failReleaseControl('PROFILE_PIN_EXPECTATION_MISMATCH', `${field} does not match the authenticated build expectation`)
  }
}

function assertBytesArrayEqual (actual, expected, field) {
  if (!Array.isArray(expected) || actual.length !== expected.length) {
    failReleaseControl('PROFILE_PIN_EXPECTATION_MISMATCH', `${field} length does not match the authenticated build expectation`)
  }
  for (let i = 0; i < actual.length; i++) {
    if (!bytesEqual(actual[i], expected[i])) {
      failReleaseControl('PROFILE_PIN_EXPECTATION_MISMATCH', `${field}[${i}] does not match the authenticated build expectation`)
    }
  }
}

function assertProfilePinMatchesExpectedSnapshot (pin, expected) {
  requireExpectedField(expected, 'emitSubstrate')
  assertTupleEqual(pin.emitSubstrate, expected.emitSubstrate, 'emitSubstrate')
  requireExpectedField(expected, 'readSubstrates')
  if (!Array.isArray(expected.readSubstrates) || pin.readSubstrates.length !== expected.readSubstrates.length) {
    failReleaseControl('PROFILE_PIN_EXPECTATION_MISMATCH', 'readSubstrates length does not match the authenticated build expectation')
  }
  for (let i = 0; i < pin.readSubstrates.length; i++) assertTupleEqual(pin.readSubstrates[i], expected.readSubstrates[i], `readSubstrates[${i}]`)

  requireExpectedField(expected, 'recommendedBootstrapHashes')
  assertBytesArrayEqual(pin.recommendedBootstrapHashes, expected.recommendedBootstrapHashes, 'recommendedBootstrapHashes')
  for (const field of EXPECTED_BYTES_FIELDS) {
    requireExpectedField(expected, field)
    if (!nullableBytesEqual(pin[field], expected[field])) {
      failReleaseControl('PROFILE_PIN_EXPECTATION_MISMATCH', `${field} does not match the authenticated build expectation`)
    }
  }
  for (const field of EXPECTED_SCALAR_FIELDS) {
    requireExpectedField(expected, field)
    if (!scalarEqual(pin[field], expected[field])) {
      failReleaseControl('PROFILE_PIN_EXPECTATION_MISMATCH', `${field} does not match the authenticated build expectation`)
    }
  }
  return true
}

export function assertProfilePinMatchesExpected (pin, expected) {
  return assertProfilePinMatchesExpectedSnapshot(
    pin, snapshotExpectedPinProjection(expected))
}

function assertNonzero (value, field, code = 'BAD_PROFILE_PIN_SECURITY_FIELD') {
  if (value == null || isAllZero(fixedBytesValue(value, 32, field))) {
    failReleaseControl(code, `${field} must be nonzero`)
  }
}

function migrationProjection (pin) {
  return [
    pin.migrationStage,
    pin.legacyImportMode,
    pin.legacyReadMode,
    pin.legacyCutoffHash,
    pin.migrationGenesisRecordId,
    pin.cutoffActivationReleaseSequence,
    pin.legacyRetirementEvidenceHash,
    pin.legacyRetirementActivationReleaseSequence
  ]
}

function migrationProjectionEqual (left, right) {
  const a = migrationProjection(left)
  const b = migrationProjection(right)
  for (let i = 0; i < a.length; i++) {
    if (a[i] instanceof Uint8Array || b[i] instanceof Uint8Array) {
      if (!nullableBytesEqual(a[i], b[i])) return false
    } else if (!scalarEqual(a[i], b[i])) return false
  }
  return true
}

export function assertMigrationState (pin, previousPin = null) {
  const cutoffFields = [pin.legacyCutoffHash, pin.migrationGenesisRecordId, pin.cutoffActivationReleaseSequence]
  const cutoffPresent = cutoffFields.map(value => value != null)
  if (!cutoffPresent.every(value => value === cutoffPresent[0])) {
    failReleaseControl('BAD_MIGRATION_CUTOFF_STATE', 'cutoff hash, genesis ID, and activation sequence must be jointly absent or present')
  }
  if (pin.legacyCutoffHash != null) assertNonzero(pin.legacyCutoffHash, 'legacyCutoffHash', 'BAD_MIGRATION_CUTOFF_STATE')
  if (pin.migrationGenesisRecordId != null) assertNonzero(pin.migrationGenesisRecordId, 'migrationGenesisRecordId', 'BAD_MIGRATION_CUTOFF_STATE')

  if (pin.migrationStage === PEERIT_MIGRATION_STAGE.LIVE_DUAL_READ) {
    if (pin.legacyImportMode !== 0 || pin.legacyReadMode !== 0 || cutoffPresent[0]) {
      failReleaseControl('BAD_MIGRATION_STAGE_STATE', 'LIVE_DUAL_READ requires import mode 0, read mode 0, and no cutoff')
    }
  } else if (pin.migrationStage === PEERIT_MIGRATION_STAGE.FROZEN_CUTOFF) {
    if (pin.legacyImportMode !== 1 || pin.legacyReadMode !== 0 || !cutoffPresent[0]) {
      failReleaseControl('BAD_MIGRATION_STAGE_STATE', 'FROZEN_CUTOFF requires import mode 1, read mode 0, and a complete cutoff binding')
    }
  } else if (pin.migrationStage === PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY) {
    if (pin.legacyImportMode !== 2 || pin.legacyReadMode !== 1 || !cutoffPresent[0]) {
      failReleaseControl('BAD_MIGRATION_STAGE_STATE', 'ARCHIVE_ONLY requires import mode 2, read mode 1, and a complete cutoff binding')
    }
  }

  const retirementPresent = pin.legacyRetirementEvidenceHash != null || pin.legacyRetirementActivationReleaseSequence != null
  if (pin.migrationStage === PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY) {
    if (pin.legacyRetirementEvidenceHash == null || pin.legacyRetirementActivationReleaseSequence == null) {
      failReleaseControl('BAD_MIGRATION_RETIREMENT_STATE', 'ARCHIVE_ONLY requires retirement evidence and its activation sequence')
    }
    assertNonzero(pin.legacyRetirementEvidenceHash, 'legacyRetirementEvidenceHash', 'BAD_MIGRATION_RETIREMENT_STATE')
  } else if (retirementPresent) {
    failReleaseControl('BAD_MIGRATION_RETIREMENT_STATE', 'retirement fields are forbidden before ARCHIVE_ONLY')
  }

  if (!previousPin) {
    if (pin.migrationStage !== PEERIT_MIGRATION_STAGE.LIVE_DUAL_READ || pin.migrationTransitionEvidenceHash != null) {
      failReleaseControl('BAD_MIGRATION_GENESIS_STATE', 'the sequence-zero migration state must start LIVE_DUAL_READ without transition evidence')
    }
    return true
  }

  for (const field of ['migrationStage', 'legacyImportMode', 'legacyReadMode']) {
    const delta = pin[field] - previousPin[field]
    if (delta < 0) failReleaseControl('MIGRATION_DOWNGRADE', `${field} cannot downgrade`)
    if (delta > 1) failReleaseControl('MIGRATION_GAP', `${field} cannot skip a state`)
  }

  const changed = !migrationProjectionEqual(pin, previousPin)
  if (changed !== (pin.migrationTransitionEvidenceHash != null)) {
    failReleaseControl('BAD_MIGRATION_TRANSITION_EVIDENCE', 'transition evidence must be present exactly when migration state changes')
  }
  if (pin.migrationTransitionEvidenceHash != null) assertNonzero(pin.migrationTransitionEvidenceHash, 'migrationTransitionEvidenceHash', 'BAD_MIGRATION_TRANSITION_EVIDENCE')

  if (previousPin.legacyImportMode === 0 && pin.legacyImportMode === 1) {
    if (!bytesEqual(pin.legacySourceSetHash, previousPin.legacySourceSetHash)) {
      failReleaseControl('MIGRATION_LEGACY_SOURCE_SET_FORK', 'first frozen pin must retain the final LIVE_DUAL_READ legacySourceSetHash')
    }
    if (pin.cutoffActivationReleaseSequence !== pin.releaseSequence) {
      failReleaseControl('BAD_MIGRATION_CUTOFF_ACTIVATION', 'first frozen cutoff activation must equal the current release sequence')
    }
  } else if (pin.legacyImportMode >= 1) {
    if (!bytesEqual(pin.legacySourceSetHash, previousPin.legacySourceSetHash)) {
      failReleaseControl('MIGRATION_LEGACY_SOURCE_SET_FORK', 'legacySourceSetHash must remain frozen after cutoff')
    }
    for (const field of ['legacyCutoffHash', 'migrationGenesisRecordId']) {
      if (!bytesEqual(pin[field], previousPin[field])) failReleaseControl('MIGRATION_CUTOFF_FORK', `${field} must remain frozen`)
    }
    if (pin.cutoffActivationReleaseSequence !== previousPin.cutoffActivationReleaseSequence) {
      failReleaseControl('MIGRATION_CUTOFF_FORK', 'cutoff activation sequence must remain frozen')
    }
  }

  if (previousPin.migrationStage !== PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY && pin.migrationStage === PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY) {
    if (pin.legacyRetirementActivationReleaseSequence !== pin.releaseSequence) {
      failReleaseControl('BAD_MIGRATION_RETIREMENT_ACTIVATION', 'first archive-only activation must equal the current release sequence')
    }
  } else if (previousPin.migrationStage === PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY) {
    if (!bytesEqual(pin.legacyRetirementEvidenceHash, previousPin.legacyRetirementEvidenceHash) || pin.legacyRetirementActivationReleaseSequence !== previousPin.legacyRetirementActivationReleaseSequence) {
      failReleaseControl('MIGRATION_RETIREMENT_FORK', 'retirement evidence and activation sequence must remain frozen')
    }
  }
  return true
}

async function verifyProfilePinCryptographic (completeSignedPin, options = {}) {
  const cryptoRuntime = snapshotCryptoRuntime(options.crypto)
  const bytes = snapshotPinBytes(completeSignedPin)
  const pin = decodePeeritHiveRelayProfilePinV1(bytes)
  assertNonzero(pin.releaseAuthorityPublicKey, 'releaseAuthorityPublicKey')
  assertNonzero(pin.releaseAuthorityKeyId, 'releaseAuthorityKeyId')
  for (const [field, value] of [
    ['previousPinHash', pin.previousPinHash],
    ['profileSpecHash', pin.profileSpecHash],
    ['profileAbiHash', pin.profileAbiHash],
    ['profileVectorSetHash', pin.profileVectorSetHash],
    ['validatorArtifactHash', pin.validatorArtifactHash],
    ['validatorVectorSetHash', pin.validatorVectorSetHash],
    ['availabilityPolicyHash', pin.availabilityPolicyHash],
    ['appArtifactHash', pin.appArtifactHash],
    ['webAssetManifestHash', pin.webAssetManifestHash],
    ['legacySourceSetHash', pin.legacySourceSetHash],
    ['authorityTransitionHash', pin.authorityTransitionHash]
  ]) {
    if (value != null) assertNonzero(value, field)
  }
  for (const [index, tuple] of pin.readSubstrates.entries()) {
    assertNonzero(tuple.specHash, `readSubstrates[${index}].specHash`)
    assertNonzero(tuple.abiHash, `readSubstrates[${index}].abiHash`)
    assertNonzero(tuple.vectorSetHash, `readSubstrates[${index}].vectorSetHash`)
  }
  for (const [index, hash] of pin.recommendedBootstrapHashes.entries()) assertNonzero(hash, `recommendedBootstrapHashes[${index}]`)
  const computedKeyId = releaseAuthorityKeyId(pin.releaseAuthorityPublicKey)
  if (!bytesEqual(computedKeyId, pin.releaseAuthorityKeyId)) {
    failReleaseControl('BAD_RELEASE_AUTHORITY_KEY_ID', 'releaseAuthorityKeyId does not match releaseAuthorityPublicKey')
  }
  const signatureValid = await cryptoRuntime.verifyEd25519(
    pin.releaseAuthorityPublicKey,
    profilePinSignaturePayload(pin),
    pin.signature
  )
  if (signatureValid !== true) failReleaseControl('BAD_PROFILE_PIN_SIGNATURE', 'profile pin Ed25519 signature is invalid')
  return {
    pin,
    bytes,
    pinHash: profilePinHash(bytes),
    signaturePayloadHash: profilePinSignaturePayloadHash(pin)
  }
}

export async function verifyPeeritProfilePinV1 (completeSignedPin, options = {}) {
  const expected = snapshotExpectedPinProjection(options.expected)
  const verified = await verifyProfilePinCryptographic(completeSignedPin, options)
  if (verified.pin.authorityTransitionHash != null) {
    failReleaseControl('AUTHORITY_TRANSITION_OUTSIDE_SLICE',
      'standalone exact-pin verification cannot authenticate an authority transition')
  }
  assertProfilePinMatchesExpectedSnapshot(verified.pin, expected)
  return verified
}

async function verifyCheckpoint (completeSignedCheckpoint, verifiedPin, options) {
  const cryptoRuntime = snapshotCryptoRuntime(options.crypto)
  const bytes = snapshotCheckpointBytes(completeSignedCheckpoint)
  const checkpoint = decodePeeritPinHistoryCheckpointV1(bytes)
  if (checkpoint.checkpointSequence !== verifiedPin.pin.releaseSequence) {
    failReleaseControl('CHECKPOINT_PIN_SEQUENCE_MISMATCH', 'checkpointSequence must equal its pin releaseSequence')
  }
  if (!bytesEqual(checkpoint.pinHash, verifiedPin.pinHash)) {
    failReleaseControl('CHECKPOINT_PIN_HASH_MISMATCH', 'checkpoint pinHash does not match the complete signed pin')
  }
  if (!nullableBytesEqual(checkpoint.previousPinHash, verifiedPin.pin.previousPinHash)) {
    failReleaseControl('CHECKPOINT_PREVIOUS_PIN_MISMATCH', 'checkpoint previousPinHash does not match its pin')
  }
  if (checkpoint.releaseAuthoritySequence !== verifiedPin.pin.releaseAuthoritySequence || !bytesEqual(checkpoint.releaseAuthorityKeyId, verifiedPin.pin.releaseAuthorityKeyId)) {
    failReleaseControl('CHECKPOINT_AUTHORITY_MISMATCH', 'checkpoint authority does not match its pin')
  }
  const signatureValid = await cryptoRuntime.verifyEd25519(
    verifiedPin.pin.releaseAuthorityPublicKey,
    checkpointSignaturePayload(checkpoint),
    checkpoint.signature
  )
  if (signatureValid !== true) failReleaseControl('BAD_CHECKPOINT_SIGNATURE', 'checkpoint Ed25519 signature is invalid')
  return {
    checkpoint,
    bytes,
    checkpointHash: pinHistoryCheckpointHash(bytes),
    signaturePayloadHash: checkpointSignaturePayloadHash(checkpoint)
  }
}

function witnessedHashValue (witnessed, sequence, field) {
  if (witnessed == null) return NO_WITNESS
  if (witnessed instanceof Map) {
    let hasBigInt
    let hasString
    try {
      hasBigInt = Map.prototype.has.call(witnessed, sequence)
      hasString = Map.prototype.has.call(witnessed, sequence.toString())
    } catch {
      failReleaseControl('BAD_WITNESSED_HASH_SET', `${field} must be a genuine Map or plain object`)
    }
    if (!hasBigInt && !hasString) return NO_WITNESS
    const bigIntValue = hasBigInt ? Map.prototype.get.call(witnessed, sequence) : null
    const stringValue = hasString ? Map.prototype.get.call(witnessed, sequence.toString()) : null
    if (hasBigInt && hasString && !bytesEqual(
      fixedBytesValue(bigIntValue, 32, `${field}[${sequence}]`),
      fixedBytesValue(stringValue, 32, `${field}[${sequence.toString()}]`))) {
      failReleaseControl('AMBIGUOUS_WITNESSED_HASH',
        `${field} has conflicting bigint and string witnesses for sequence ${sequence}`)
    }
    return hasBigInt ? bigIntValue : stringValue
  }
  if (typeof witnessed !== 'object' || Array.isArray(witnessed) ||
      (Object.getPrototypeOf(witnessed) !== Object.prototype &&
       Object.getPrototypeOf(witnessed) !== null)) {
    failReleaseControl('BAD_WITNESSED_HASH_SET', `${field} must be a genuine Map or plain object`)
  }
  const descriptor = Object.getOwnPropertyDescriptor(witnessed, sequence.toString())
  if (!descriptor) return NO_WITNESS
  if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
    failReleaseControl('BAD_WITNESSED_HASH_SET', `${field} witnesses must be data fields`)
  }
  return descriptor.value
}

function snapshotWitnessedHashes (witnessed, sequences, field) {
  const output = new Map()
  for (const sequence of sequences) {
    const value = witnessedHashValue(witnessed, sequence, field)
    if (value !== NO_WITNESS) {
      output.set(sequence.toString(), new Uint8Array(fixedBytesValue(
        value, 32, `${field}[${sequence}]`)))
    }
  }
  return output
}

export async function verifyPeeritPinHistoryBundleV1 (completeBundle, options = {}) {
  const cryptoRuntime = snapshotCryptoRuntime(options.crypto)
  const bytes = snapshotBundleBytes(completeBundle, 'complete pin history bundle')
  const bundle = decodePeeritPinHistoryBundleV1(bytes)
  if (!Array.isArray(options.expectedPins) || options.expectedPins.length !== bundle.pins.length) {
    failReleaseControl('EXPECTED_PROFILE_PIN_SET_REQUIRED', 'expectedPins must authenticate every pin in the bundle')
  }
  const expectedPins = options.expectedPins.map(snapshotExpectedPinProjection)
  const pinSequences = bundle.pins.map(entry =>
    decodePeeritHiveRelayProfilePinV1(entry).releaseSequence)
  const witnessedPinHashes = snapshotWitnessedHashes(
    options.witnessedPinHashes, pinSequences, 'witnessedPinHashes')
  const witnessedCheckpointHashes = snapshotWitnessedHashes(
    options.witnessedCheckpointHashes, pinSequences, 'witnessedCheckpointHashes')

  const verifiedPins = []
  const verifiedCheckpoints = []

  let previousPin = null
  let previousPinHash = null
  let previousCheckpointHash = null
  let previousSequence = null
  if (pinSequences[0] > 0n) {
    const anchor = VERIFIED_TERMINALS.get(options.anchor)
    if (!anchor) {
      failReleaseControl('VERIFIED_PIN_HISTORY_ANCHOR_REQUIRED', 'a nonzero bundle suffix requires a module-branded prior verified terminal result')
    }
    previousPin = decodePeeritHiveRelayProfilePinV1(anchor.pinBytes)
    previousPinHash = new Uint8Array(anchor.pinHash)
    previousCheckpointHash = new Uint8Array(anchor.checkpointHash)
    previousSequence = anchor.sequence
  }

  // Authenticate and chain-check one pair at a time. An invalid first pair must
  // not force verification of all 256 possible pin/checkpoint signatures.
  for (let i = 0; i < bundle.pins.length; i++) {
    const verifiedPin = await verifyPeeritProfilePinV1(bundle.pins[i], {
      crypto: cryptoRuntime,
      expected: expectedPins[i]
    })
    const verifiedCheckpoint = await verifyCheckpoint(
      bundle.checkpoints[i], verifiedPin, { crypto: cryptoRuntime })
    const pin = verifiedPin.pin
    const checkpoint = verifiedCheckpoint.checkpoint

    if (previousSequence == null) {
      if (pin.releaseSequence !== 0n || pin.previousPinHash != null || checkpoint.previousCheckpointHash != null || checkpoint.previousPinHash != null) {
        failReleaseControl('BAD_PIN_HISTORY_GENESIS', 'sequence zero alone must omit every predecessor hash')
      }
    } else {
      if (pin.releaseSequence !== previousSequence + 1n) failReleaseControl('PIN_HISTORY_GAP_OR_FORK', 'pin sequence must advance exactly +1')
      if (!bytesEqual(pin.previousPinHash, previousPinHash)) failReleaseControl('PIN_HISTORY_PREDECESSOR_MISMATCH', 'pin does not name the previous complete signed pin')
      if (!bytesEqual(checkpoint.previousPinHash, previousPinHash)) failReleaseControl('CHECKPOINT_PREDECESSOR_MISMATCH', 'checkpoint does not name the previous pin')
      if (!bytesEqual(checkpoint.previousCheckpointHash, previousCheckpointHash)) failReleaseControl('CHECKPOINT_PREDECESSOR_MISMATCH', 'checkpoint does not name the previous checkpoint')
      if (pin.releaseAuthoritySequence !== previousPin.releaseAuthoritySequence || !bytesEqual(pin.releaseAuthorityPublicKey, previousPin.releaseAuthorityPublicKey)) {
        failReleaseControl('AUTHORITY_TRANSITION_OUTSIDE_SLICE', 'release authority changed without the out-of-slice dual-signed transition verifier')
      }
    }

    assertMigrationState(pin, previousPin)
    const witnessedPinHash = witnessedPinHashes.get(pin.releaseSequence.toString())
    if (witnessedPinHash != null && !bytesEqual(witnessedPinHash, verifiedPin.pinHash)) {
      failReleaseControl('PIN_HISTORY_FORK', `release sequence ${pin.releaseSequence} conflicts with a witnessed pin hash`)
    }
    const witnessedCheckpointHash = witnessedCheckpointHashes.get(pin.releaseSequence.toString())
    if (witnessedCheckpointHash != null && !bytesEqual(witnessedCheckpointHash, verifiedCheckpoint.checkpointHash)) {
      failReleaseControl('CHECKPOINT_HISTORY_FORK', `release sequence ${pin.releaseSequence} conflicts with a witnessed checkpoint hash`)
    }

    verifiedPins.push(verifiedPin)
    verifiedCheckpoints.push(verifiedCheckpoint)
    previousPin = pin
    previousPinHash = verifiedPin.pinHash
    previousCheckpointHash = verifiedCheckpoint.checkpointHash
    previousSequence = pin.releaseSequence
  }

  const exactBundleHash = pinHistoryBundleHash(bytes)
  const publicPins = Object.freeze(verifiedPins.map(entry => {
    const exactPinHash = entry.pinHash.slice()
    const exactPayloadHash = entry.signaturePayloadHash.slice()
    return Object.freeze({
      releaseSequence: entry.pin.releaseSequence,
      get pinHash () { return exactPinHash.slice() },
      get signaturePayloadHash () { return exactPayloadHash.slice() }
    })
  }))
  const publicCheckpoints = Object.freeze(verifiedCheckpoints.map(entry => {
    const exactCheckpointHash = entry.checkpointHash.slice()
    const exactPayloadHash = entry.signaturePayloadHash.slice()
    return Object.freeze({
      checkpointSequence: entry.checkpoint.checkpointSequence,
      get checkpointHash () { return exactCheckpointHash.slice() },
      get signaturePayloadHash () { return exactPayloadHash.slice() }
    })
  }))
  const result = Object.freeze({
    version: bundle.version,
    pinCount: verifiedPins.length,
    checkpointCount: verifiedCheckpoints.length,
    get bytes () { return new Uint8Array(bytes) },
    get bundleHash () { return new Uint8Array(exactBundleHash) },
    pins: publicPins,
    checkpoints: publicCheckpoints,
    terminalSequence: previousSequence,
    get terminalPinHash () { return previousPinHash.slice() },
    get terminalCheckpointHash () { return previousCheckpointHash.slice() }
  })
  VERIFIED_TERMINALS.set(result, {
    sequence: previousSequence,
    pinBytes: new Uint8Array(verifiedPins[verifiedPins.length - 1].bytes),
    pinHash: new Uint8Array(previousPinHash),
    checkpointHash: new Uint8Array(previousCheckpointHash)
  })
  return result
}

function transitionMap (values, maximum) {
  if (values == null) return new Map()
  if (!Array.isArray(values) || values.length > maximum) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION_SET',
      `authorityTransitions must contain at most ${maximum} complete transitions for this continuation`)
  }
  const output = new Map()
  for (const value of values) {
    const bytes = new Uint8Array(asBytes(value, 'complete release authority transition'))
    const hash = releaseAuthorityTransitionHash(bytes)
    let key = ''
    for (const byte of hash) key += byte.toString(16).padStart(2, '0')
    if (output.has(key)) {
      failReleaseControl('BAD_AUTHORITY_TRANSITION_SET',
        'authorityTransitions contains a duplicate transition hash')
    }
    output.set(key, bytes)
  }
  return output
}

function hashKey (value) {
  let output = ''
  for (const byte of fixedBytesValue(value, 32, 'authorityTransitionHash')) {
    output += byte.toString(16).padStart(2, '0')
  }
  return output
}

export async function verifyPeeritPinHistoryContinuationV1 (completeBundle, options = {}) {
  const cryptoRuntime = snapshotCryptoRuntime(options.crypto)
  const anchor = VERIFIED_TERMINALS.get(options.anchor)
  if (!anchor) {
    failReleaseControl('VERIFIED_PIN_HISTORY_ANCHOR_REQUIRED',
      'unknown newer pin history requires a module-branded exact prior terminal')
  }
  const bytes = snapshotBundleBytes(completeBundle, 'complete pin history continuation')
  const bundle = decodePeeritPinHistoryBundleV1(bytes)
  const pinSequences = bundle.pins.map(entry =>
    decodePeeritHiveRelayProfilePinV1(entry).releaseSequence)
  const witnessedPinHashes = snapshotWitnessedHashes(
    options.witnessedPinHashes, pinSequences, 'witnessedPinHashes')
  const witnessedCheckpointHashes = snapshotWitnessedHashes(
    options.witnessedCheckpointHashes, pinSequences, 'witnessedCheckpointHashes')
  const transitions = transitionMap(options.authorityTransitions, bundle.pins.length)
  const consumedTransitions = new Set()
  const verifiedPins = []
  const verifiedCheckpoints = []

  let previousPin = decodePeeritHiveRelayProfilePinV1(anchor.pinBytes)
  let previousPinHash = new Uint8Array(anchor.pinHash)
  let previousCheckpointHash = new Uint8Array(anchor.checkpointHash)
  let previousSequence = anchor.sequence
  for (let index = 0; index < bundle.pins.length; index++) {
    const verifiedPin = await verifyProfilePinCryptographic(
      bundle.pins[index], { crypto: cryptoRuntime })
    const verifiedCheckpoint = await verifyCheckpoint(
      bundle.checkpoints[index], verifiedPin, { crypto: cryptoRuntime })
    const pin = verifiedPin.pin
    const checkpoint = verifiedCheckpoint.checkpoint
    if (pin.releaseSequence !== previousSequence + 1n) {
      failReleaseControl('PIN_HISTORY_GAP_OR_FORK', 'pin continuation must advance exactly +1')
    }
    if (!bytesEqual(pin.previousPinHash, previousPinHash)) {
      failReleaseControl('PIN_HISTORY_PREDECESSOR_MISMATCH',
        'pin continuation does not name the prior complete signed pin')
    }
    if (!bytesEqual(checkpoint.previousPinHash, previousPinHash) ||
        !bytesEqual(checkpoint.previousCheckpointHash, previousCheckpointHash)) {
      failReleaseControl('CHECKPOINT_PREDECESSOR_MISMATCH',
        'checkpoint continuation does not name the prior pin and checkpoint')
    }

    const sameAuthoritySequence = pin.releaseAuthoritySequence === previousPin.releaseAuthoritySequence
    const sameAuthorityKey = bytesEqual(pin.releaseAuthorityPublicKey, previousPin.releaseAuthorityPublicKey)
    if (sameAuthoritySequence && sameAuthorityKey) {
      if (pin.authorityTransitionHash != null) {
        failReleaseControl('UNEXPECTED_AUTHORITY_TRANSITION',
          'authorityTransitionHash is allowed only on the first pin under a new key')
      }
    } else {
      if (pin.authorityTransitionHash == null ||
          pin.releaseAuthoritySequence !== previousPin.releaseAuthoritySequence + 1n) {
        failReleaseControl('AUTHORITY_TRANSITION_REQUIRED',
          'release authority changes require an exact +1 dual-signed transition')
      }
      const key = hashKey(pin.authorityTransitionHash)
      const transitionBytes = transitions.get(key)
      if (!transitionBytes) {
        failReleaseControl('AUTHORITY_TRANSITION_REQUIRED',
          'the first pin under a new authority is missing its complete transition')
      }
      await verifyPeeritReleaseAuthorityTransitionV1(transitionBytes, {
        crypto: cryptoRuntime,
        previousPin,
        nextPin: pin
      })
      consumedTransitions.add(key)
    }

    assertMigrationState(pin, previousPin)
    const witnessedPinHash = witnessedPinHashes.get(pin.releaseSequence.toString())
    if (witnessedPinHash != null && !bytesEqual(witnessedPinHash, verifiedPin.pinHash)) {
      failReleaseControl('PIN_HISTORY_FORK',
        `release sequence ${pin.releaseSequence} conflicts with a witnessed pin hash`)
    }
    const witnessedCheckpointHash = witnessedCheckpointHashes.get(
      pin.releaseSequence.toString())
    if (witnessedCheckpointHash != null &&
        !bytesEqual(witnessedCheckpointHash, verifiedCheckpoint.checkpointHash)) {
      failReleaseControl('CHECKPOINT_HISTORY_FORK',
        `release sequence ${pin.releaseSequence} conflicts with a witnessed checkpoint hash`)
    }

    verifiedPins.push(verifiedPin)
    verifiedCheckpoints.push(verifiedCheckpoint)
    previousPin = pin
    previousPinHash = verifiedPin.pinHash
    previousCheckpointHash = verifiedCheckpoint.checkpointHash
    previousSequence = pin.releaseSequence
  }
  if (consumedTransitions.size !== transitions.size) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION_SET',
      'authorityTransitions contains an unreferenced complete transition')
  }

  const exactBundleHash = pinHistoryBundleHash(bytes)
  const publicPins = Object.freeze(verifiedPins.map(entry => Object.freeze({
    releaseSequence: entry.pin.releaseSequence,
    get pinHash () { return entry.pinHash.slice() },
    get signaturePayloadHash () { return entry.signaturePayloadHash.slice() }
  })))
  const publicCheckpoints = Object.freeze(verifiedCheckpoints.map(entry => Object.freeze({
    checkpointSequence: entry.checkpoint.checkpointSequence,
    get checkpointHash () { return entry.checkpointHash.slice() },
    get signaturePayloadHash () { return entry.signaturePayloadHash.slice() }
  })))
  const result = Object.freeze({
    version: bundle.version,
    pinCount: verifiedPins.length,
    checkpointCount: verifiedCheckpoints.length,
    get bytes () { return new Uint8Array(bytes) },
    get bundleHash () { return new Uint8Array(exactBundleHash) },
    pins: publicPins,
    checkpoints: publicCheckpoints,
    terminalSequence: previousSequence,
    get terminalPinHash () { return previousPinHash.slice() },
    get terminalCheckpointHash () { return previousCheckpointHash.slice() },
    authorityTransitionCount: consumedTransitions.size
  })
  VERIFIED_TERMINALS.set(result, {
    sequence: previousSequence,
    pinBytes: new Uint8Array(verifiedPins[verifiedPins.length - 1].bytes),
    pinHash: new Uint8Array(previousPinHash),
    checkpointHash: new Uint8Array(previousCheckpointHash)
  })
  return result
}

export function canonicalExpectedPinProjection (pin) {
  const output = {
    emitSubstrate: pin.emitSubstrate,
    readSubstrates: pin.readSubstrates,
    recommendedBootstrapHashes: pin.recommendedBootstrapHashes
  }
  for (const field of EXPECTED_BYTES_FIELDS) output[field] = pin[field]
  for (const field of EXPECTED_SCALAR_FIELDS) output[field] = pin[field]
  return snapshotExpectedPinProjection(output)
}

export function assertReadSubstrateOrder (pin) {
  for (let i = 1; i < pin.readSubstrates.length; i++) {
    if (compareSubstrateTuples(pin.readSubstrates[i - 1], pin.readSubstrates[i]) >= 0) {
      failReleaseControl('NONCANONICAL_RELEASE_CONTROL_ORDER', 'readSubstrates are not strictly sorted')
    }
  }
  return true
}
