import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  asciiBytes,
  blake2b256,
  bytesEqual,
  compareBytes,
  concatBytes,
  domainHash,
  domainLengthHash,
  failReleaseControl,
  fixedBytesValue
} from './release-control-primitives.mjs'
import {
  PEERIT_MIGRATION_STAGE,
  PEERIT_PROFILE_ID,
  RELEASE_CONTROL_DOMAIN,
  RELEASE_CONTROL_LIMIT,
  RELEASE_CONTROL_TAG,
  assertMigrationStage
} from './release-control-registry.mjs'

const SUBSTRATE_TUPLE_BYTES = 98
export const PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX =
  2 + 1 + 2 +
  RELEASE_CONTROL_LIMIT.BUNDLE_ITEMS_MAX * (2 + RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MAX) +
  2 +
  RELEASE_CONTROL_LIMIT.BUNDLE_ITEMS_MAX * (2 + RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX)

function expectTag (reader, expected, field) {
  const actual = reader.u16(`${field} tag`)
  if (actual !== expected) {
    failReleaseControl('BAD_RELEASE_CONTROL_TAG', `${field} tag ${actual} does not equal ${expected}`)
  }
}

function writeTag (writer, tag, field) {
  writer.u16(tag, `${field} tag`)
}

function assertVersionOne (value, field) {
  if (value !== 1) failReleaseControl('BAD_RELEASE_CONTROL_VERSION', `${field} version must be 1`)
}

function assertU8Range (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be in [${minimum}..${maximum}]`)
  }
  return value
}

function assertStrictSorted (encoded, field) {
  for (let i = 1; i < encoded.length; i++) {
    if (compareBytes(encoded[i - 1], encoded[i]) >= 0) {
      failReleaseControl('NONCANONICAL_RELEASE_CONTROL_ORDER', `${field} must be strictly sorted and unique`)
    }
  }
}

function writeTuple (writer, value, field = 'SubstrateTupleV1') {
  writeTag(writer, RELEASE_CONTROL_TAG.SUBSTRATE_TUPLE_V1, field)
  writer.fixed(value.specHash, 32, `${field}.specHash`)
  writer.fixed(value.abiHash, 32, `${field}.abiHash`)
  writer.fixed(value.vectorSetHash, 32, `${field}.vectorSetHash`)
}

function readTuple (reader, field = 'SubstrateTupleV1') {
  expectTag(reader, RELEASE_CONTROL_TAG.SUBSTRATE_TUPLE_V1, field)
  return {
    specHash: reader.fixed(32, `${field}.specHash`),
    abiHash: reader.fixed(32, `${field}.abiHash`),
    vectorSetHash: reader.fixed(32, `${field}.vectorSetHash`)
  }
}

export function encodeSubstrateTupleV1 (value) {
  const writer = new CanonicalWriter()
  writeTuple(writer, value)
  return writer.finish()
}

export function decodeSubstrateTupleV1 (value) {
  const input = asBytes(value, 'SubstrateTupleV1 bytes')
  if (input.byteLength !== SUBSTRATE_TUPLE_BYTES) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING',
      `SubstrateTupleV1 must be exactly ${SUBSTRATE_TUPLE_BYTES} bytes`)
  }
  const reader = new CanonicalReader(new Uint8Array(input))
  const decoded = readTuple(reader)
  reader.expectEnd('SubstrateTupleV1')
  return decoded
}

export function compareSubstrateTuples (left, right) {
  return compareBytes(encodeSubstrateTupleV1(left), encodeSubstrateTupleV1(right))
}

function writeProfilePinFields (writer, value) {
  assertVersionOne(value.version, 'PeeritHiveRelayProfilePinV1')
  if (value.profileId !== PEERIT_PROFILE_ID) {
    failReleaseControl('BAD_PROFILE_ID', `profileId must be ${PEERIT_PROFILE_ID}`)
  }
  writeTag(writer, RELEASE_CONTROL_TAG.PROFILE_PIN_V1, 'PeeritHiveRelayProfilePinV1')
  writer.u8(1, 'profile pin version')
  writer.literalAscii(PEERIT_PROFILE_ID, 'profileId')
  writer.u64(value.releaseSequence, 'releaseSequence')
  writer.optionalFixed(value.previousPinHash, 32, 'previousPinHash')

  const emitBytes = encodeSubstrateTupleV1(value.emitSubstrate)
  writer.fixed(emitBytes, SUBSTRATE_TUPLE_BYTES, 'emitSubstrate')
  if (!Array.isArray(value.readSubstrates) || value.readSubstrates.length < RELEASE_CONTROL_LIMIT.READ_SUBSTRATES_MIN || value.readSubstrates.length > RELEASE_CONTROL_LIMIT.READ_SUBSTRATES_MAX) {
    failReleaseControl('BAD_READ_SUBSTRATES', 'readSubstrates must contain 1..3 tuples')
  }
  const readBytes = value.readSubstrates.map(encodeSubstrateTupleV1)
  assertStrictSorted(readBytes, 'readSubstrates')
  const emitOccurrences = readBytes.filter(entry => bytesEqual(entry, emitBytes)).length
  if (emitOccurrences !== 1) {
    failReleaseControl('BAD_EMIT_SUBSTRATE', 'emitSubstrate must occur exactly once in readSubstrates')
  }
  writer.u8(readBytes.length, 'readSubstrates count')
  for (const entry of readBytes) writer.fixed(entry, SUBSTRATE_TUPLE_BYTES, 'readSubstrates entry')

  for (const field of [
    'profileSpecHash',
    'profileAbiHash',
    'profileVectorSetHash',
    'validatorArtifactHash',
    'validatorVectorSetHash',
    'availabilityPolicyHash'
  ]) writer.fixed(value[field], 32, field)

  if (!Array.isArray(value.recommendedBootstrapHashes) || value.recommendedBootstrapHashes.length > RELEASE_CONTROL_LIMIT.RECOMMENDED_BOOTSTRAPS_MAX) {
    failReleaseControl('BAD_RECOMMENDED_BOOTSTRAPS', 'recommendedBootstrapHashes must contain 0..16 hashes')
  }
  const bootstrapHashes = value.recommendedBootstrapHashes.map((entry, index) => fixedBytesValue(entry, 32, `recommendedBootstrapHashes[${index}]`))
  assertStrictSorted(bootstrapHashes, 'recommendedBootstrapHashes')
  writer.u8(bootstrapHashes.length, 'recommendedBootstrapHashes count')
  for (const entry of bootstrapHashes) writer.fixed(entry, 32, 'recommendedBootstrapHash')

  if (value.pinHistoryRetentionDays !== RELEASE_CONTROL_LIMIT.PIN_HISTORY_RETENTION_DAYS) {
    failReleaseControl('BAD_PIN_RETENTION', `pinHistoryRetentionDays must be ${RELEASE_CONTROL_LIMIT.PIN_HISTORY_RETENTION_DAYS}`)
  }
  writer.u16(value.pinHistoryRetentionDays, 'pinHistoryRetentionDays')
  writer.fixed(value.appArtifactHash, 32, 'appArtifactHash')
  writer.fixed(value.webAssetManifestHash, 32, 'webAssetManifestHash')
  writer.fixed(value.legacySourceSetHash, 32, 'legacySourceSetHash')
  writer.u8(assertMigrationStage(value.migrationStage), 'migrationStage')
  writer.optionalFixed(value.migrationTransitionEvidenceHash, 32, 'migrationTransitionEvidenceHash')
  writer.u8(assertU8Range(value.legacyImportMode, 0, 2, 'legacyImportMode'), 'legacyImportMode')
  writer.u8(assertU8Range(value.legacyReadMode, 0, 1, 'legacyReadMode'), 'legacyReadMode')
  writer.optionalFixed(value.legacyCutoffHash, 32, 'legacyCutoffHash')
  writer.optionalFixed(value.migrationGenesisRecordId, 32, 'migrationGenesisRecordId')
  writer.optionalU64(value.cutoffActivationReleaseSequence, 'cutoffActivationReleaseSequence')
  writer.optionalFixed(value.legacyRetirementEvidenceHash, 32, 'legacyRetirementEvidenceHash')
  writer.optionalU64(value.legacyRetirementActivationReleaseSequence, 'legacyRetirementActivationReleaseSequence')
  writer.u64(value.releaseAuthoritySequence, 'releaseAuthoritySequence')
  writer.fixed(value.releaseAuthorityPublicKey, 32, 'releaseAuthorityPublicKey')
  writer.fixed(value.releaseAuthorityKeyId, 32, 'releaseAuthorityKeyId')
  writer.optionalFixed(value.authorityTransitionHash, 32, 'authorityTransitionHash')
}

export function encodePeeritHiveRelayProfilePinV1Unsigned (value) {
  const writer = new CanonicalWriter()
  writeProfilePinFields(writer, value)
  const output = writer.finish()
  if (output.byteLength + 64 > RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX) {
    failReleaseControl('BAD_PROFILE_PIN_SIZE', 'complete profile pin exceeds 8192 bytes')
  }
  return output
}

export function encodePeeritHiveRelayProfilePinV1 (value) {
  const writer = new CanonicalWriter()
  writeProfilePinFields(writer, value)
  writer.fixed(value.signature, 64, 'signature')
  const output = writer.finish()
  if (output.byteLength > RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX) {
    failReleaseControl('BAD_PROFILE_PIN_SIZE', 'complete profile pin exceeds 8192 bytes')
  }
  return output
}

export function decodePeeritHiveRelayProfilePinV1 (value) {
  const input = asBytes(value, 'profile pin bytes')
  if (input.byteLength < 1 || input.byteLength > RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX) {
    failReleaseControl('BAD_PROFILE_PIN_SIZE', 'profile pin must be bytes[1..8192]')
  }
  value = new Uint8Array(input)
  const reader = new CanonicalReader(value)
  expectTag(reader, RELEASE_CONTROL_TAG.PROFILE_PIN_V1, 'PeeritHiveRelayProfilePinV1')
  const version = reader.u8('profile pin version')
  assertVersionOne(version, 'PeeritHiveRelayProfilePinV1')
  const profileId = reader.expectLiteralAscii(PEERIT_PROFILE_ID, 'profileId')
  const releaseSequence = reader.u64('releaseSequence')
  const previousPinHash = reader.optionalFixed(32, 'previousPinHash')
  const emitSubstrate = decodeSubstrateTupleV1(reader.fixed(SUBSTRATE_TUPLE_BYTES, 'emitSubstrate'))
  const readCount = reader.u8('readSubstrates count')
  if (readCount < RELEASE_CONTROL_LIMIT.READ_SUBSTRATES_MIN || readCount > RELEASE_CONTROL_LIMIT.READ_SUBSTRATES_MAX) {
    failReleaseControl('BAD_READ_SUBSTRATES', 'readSubstrates must contain 1..3 tuples')
  }
  const readSubstrates = []
  const readBytes = []
  for (let i = 0; i < readCount; i++) {
    const bytes = reader.fixed(SUBSTRATE_TUPLE_BYTES, `readSubstrates[${i}]`)
    readBytes.push(bytes)
    readSubstrates.push(decodeSubstrateTupleV1(bytes))
  }
  assertStrictSorted(readBytes, 'readSubstrates')
  const emitBytes = encodeSubstrateTupleV1(emitSubstrate)
  if (readBytes.filter(entry => bytesEqual(entry, emitBytes)).length !== 1) {
    failReleaseControl('BAD_EMIT_SUBSTRATE', 'emitSubstrate must occur exactly once in readSubstrates')
  }

  const decoded = {
    version,
    profileId,
    releaseSequence,
    previousPinHash,
    emitSubstrate,
    readSubstrates,
    profileSpecHash: reader.fixed(32, 'profileSpecHash'),
    profileAbiHash: reader.fixed(32, 'profileAbiHash'),
    profileVectorSetHash: reader.fixed(32, 'profileVectorSetHash'),
    validatorArtifactHash: reader.fixed(32, 'validatorArtifactHash'),
    validatorVectorSetHash: reader.fixed(32, 'validatorVectorSetHash'),
    availabilityPolicyHash: reader.fixed(32, 'availabilityPolicyHash')
  }
  const bootstrapCount = reader.u8('recommendedBootstrapHashes count')
  if (bootstrapCount > RELEASE_CONTROL_LIMIT.RECOMMENDED_BOOTSTRAPS_MAX) {
    failReleaseControl('BAD_RECOMMENDED_BOOTSTRAPS', 'recommendedBootstrapHashes must contain 0..16 hashes')
  }
  decoded.recommendedBootstrapHashes = []
  for (let i = 0; i < bootstrapCount; i++) decoded.recommendedBootstrapHashes.push(reader.fixed(32, `recommendedBootstrapHashes[${i}]`))
  assertStrictSorted(decoded.recommendedBootstrapHashes, 'recommendedBootstrapHashes')
  decoded.pinHistoryRetentionDays = reader.u16('pinHistoryRetentionDays')
  if (decoded.pinHistoryRetentionDays !== RELEASE_CONTROL_LIMIT.PIN_HISTORY_RETENTION_DAYS) {
    failReleaseControl('BAD_PIN_RETENTION', `pinHistoryRetentionDays must be ${RELEASE_CONTROL_LIMIT.PIN_HISTORY_RETENTION_DAYS}`)
  }
  decoded.appArtifactHash = reader.fixed(32, 'appArtifactHash')
  decoded.webAssetManifestHash = reader.fixed(32, 'webAssetManifestHash')
  decoded.legacySourceSetHash = reader.fixed(32, 'legacySourceSetHash')
  decoded.migrationStage = assertMigrationStage(reader.u8('migrationStage'))
  decoded.migrationTransitionEvidenceHash = reader.optionalFixed(32, 'migrationTransitionEvidenceHash')
  decoded.legacyImportMode = assertU8Range(reader.u8('legacyImportMode'), 0, 2, 'legacyImportMode')
  decoded.legacyReadMode = assertU8Range(reader.u8('legacyReadMode'), 0, 1, 'legacyReadMode')
  decoded.legacyCutoffHash = reader.optionalFixed(32, 'legacyCutoffHash')
  decoded.migrationGenesisRecordId = reader.optionalFixed(32, 'migrationGenesisRecordId')
  decoded.cutoffActivationReleaseSequence = reader.optionalU64('cutoffActivationReleaseSequence')
  decoded.legacyRetirementEvidenceHash = reader.optionalFixed(32, 'legacyRetirementEvidenceHash')
  decoded.legacyRetirementActivationReleaseSequence = reader.optionalU64('legacyRetirementActivationReleaseSequence')
  decoded.releaseAuthoritySequence = reader.u64('releaseAuthoritySequence')
  decoded.releaseAuthorityPublicKey = reader.fixed(32, 'releaseAuthorityPublicKey')
  decoded.releaseAuthorityKeyId = reader.fixed(32, 'releaseAuthorityKeyId')
  decoded.authorityTransitionHash = reader.optionalFixed(32, 'authorityTransitionHash')
  decoded.signature = reader.fixed(64, 'signature')
  reader.expectEnd('PeeritHiveRelayProfilePinV1')
  if (!bytesEqual(encodePeeritHiveRelayProfilePinV1(decoded), value)) {
    failReleaseControl('NONCANONICAL_PROFILE_PIN', 'profile pin does not round-trip canonically')
  }
  return decoded
}

function writeCheckpointFields (writer, value) {
  assertVersionOne(value.version, 'PeeritPinHistoryCheckpointV1')
  writeTag(writer, RELEASE_CONTROL_TAG.PIN_HISTORY_CHECKPOINT_V1, 'PeeritPinHistoryCheckpointV1')
  writer.u8(1, 'checkpoint version')
  writer.u64(value.checkpointSequence, 'checkpointSequence')
  writer.optionalFixed(value.previousCheckpointHash, 32, 'previousCheckpointHash')
  writer.fixed(value.pinHash, 32, 'pinHash')
  writer.optionalFixed(value.previousPinHash, 32, 'previousPinHash')
  writer.u64(value.issuedUnixMillis, 'issuedUnixMillis')
  writer.u64(value.releaseAuthoritySequence, 'releaseAuthoritySequence')
  writer.fixed(value.releaseAuthorityKeyId, 32, 'releaseAuthorityKeyId')
}

export function encodePeeritPinHistoryCheckpointV1Unsigned (value) {
  const writer = new CanonicalWriter()
  writeCheckpointFields(writer, value)
  return writer.finish()
}

export function encodePeeritPinHistoryCheckpointV1 (value) {
  const writer = new CanonicalWriter()
  writeCheckpointFields(writer, value)
  writer.fixed(value.signature, 64, 'signature')
  const output = writer.finish()
  if (output.byteLength > RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MAX) {
    failReleaseControl('BAD_CHECKPOINT_SIZE', 'checkpoint exceeds 1024 bytes')
  }
  return output
}

export function decodePeeritPinHistoryCheckpointV1 (value) {
  const input = asBytes(value, 'checkpoint bytes')
  if (input.byteLength < 1 || input.byteLength > RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MAX) {
    failReleaseControl('BAD_CHECKPOINT_SIZE', 'checkpoint must be bytes[1..1024]')
  }
  value = new Uint8Array(input)
  const reader = new CanonicalReader(value)
  expectTag(reader, RELEASE_CONTROL_TAG.PIN_HISTORY_CHECKPOINT_V1, 'PeeritPinHistoryCheckpointV1')
  const decoded = {
    version: reader.u8('checkpoint version'),
    checkpointSequence: reader.u64('checkpointSequence'),
    previousCheckpointHash: reader.optionalFixed(32, 'previousCheckpointHash'),
    pinHash: reader.fixed(32, 'pinHash'),
    previousPinHash: reader.optionalFixed(32, 'previousPinHash'),
    issuedUnixMillis: reader.u64('issuedUnixMillis'),
    releaseAuthoritySequence: reader.u64('releaseAuthoritySequence'),
    releaseAuthorityKeyId: reader.fixed(32, 'releaseAuthorityKeyId'),
    signature: reader.fixed(64, 'signature')
  }
  assertVersionOne(decoded.version, 'PeeritPinHistoryCheckpointV1')
  reader.expectEnd('PeeritPinHistoryCheckpointV1')
  if (!bytesEqual(encodePeeritPinHistoryCheckpointV1(decoded), value)) {
    failReleaseControl('NONCANONICAL_CHECKPOINT', 'checkpoint does not round-trip canonically')
  }
  return decoded
}

export function encodePeeritPinHistoryBundleV1 (value) {
  assertVersionOne(value.version, 'PeeritPinHistoryBundleV1')
  if (!Array.isArray(value.checkpoints) || !Array.isArray(value.pins) || value.checkpoints.length !== value.pins.length || value.pins.length < RELEASE_CONTROL_LIMIT.BUNDLE_ITEMS_MIN || value.pins.length > RELEASE_CONTROL_LIMIT.BUNDLE_ITEMS_MAX) {
    failReleaseControl('BAD_PIN_HISTORY_BUNDLE', 'bundle must contain one-to-one checkpoint/pin arrays of length 1..256')
  }
  const writer = new CanonicalWriter()
  writeTag(writer, RELEASE_CONTROL_TAG.PIN_HISTORY_BUNDLE_V1, 'PeeritPinHistoryBundleV1')
  writer.u8(1, 'bundle version')
  writer.u16(value.checkpoints.length, 'checkpoint count')
  for (const [index, entry] of value.checkpoints.entries()) {
    const bytes = asBytes(entry, `checkpoints[${index}]`)
    decodePeeritPinHistoryCheckpointV1(bytes)
    writer.bytesU16(bytes, RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MIN, RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MAX, `checkpoints[${index}]`)
  }
  writer.u16(value.pins.length, 'pin count')
  for (const [index, entry] of value.pins.entries()) {
    const bytes = asBytes(entry, `pins[${index}]`)
    decodePeeritHiveRelayProfilePinV1(bytes)
    writer.bytesU16(bytes, RELEASE_CONTROL_LIMIT.PIN_BYTES_MIN, RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX, `pins[${index}]`)
  }
  const output = writer.finish()
  if (output.byteLength > PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX) {
    failReleaseControl('BAD_PIN_HISTORY_BUNDLE',
      `pin history bundle exceeds ${PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX} bytes`)
  }
  return output
}

export function decodePeeritPinHistoryBundleV1 (value) {
  const input = asBytes(value, 'pin history bundle bytes')
  if (input.byteLength < 1 || input.byteLength > PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX) {
    failReleaseControl('BAD_PIN_HISTORY_BUNDLE',
      `pin history bundle must be bytes[1..${PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX}]`)
  }
  value = new Uint8Array(input)
  const reader = new CanonicalReader(value)
  expectTag(reader, RELEASE_CONTROL_TAG.PIN_HISTORY_BUNDLE_V1, 'PeeritPinHistoryBundleV1')
  const version = reader.u8('bundle version')
  assertVersionOne(version, 'PeeritPinHistoryBundleV1')
  const checkpointCount = reader.u16('checkpoint count')
  if (checkpointCount < RELEASE_CONTROL_LIMIT.BUNDLE_ITEMS_MIN || checkpointCount > RELEASE_CONTROL_LIMIT.BUNDLE_ITEMS_MAX) {
    failReleaseControl('BAD_PIN_HISTORY_BUNDLE', 'checkpoint count must be in [1..256]')
  }
  const checkpoints = []
  for (let i = 0; i < checkpointCount; i++) {
    const bytes = reader.bytesU16(RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MIN, RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MAX, `checkpoints[${i}]`)
    decodePeeritPinHistoryCheckpointV1(bytes)
    checkpoints.push(bytes)
  }
  const pinCount = reader.u16('pin count')
  if (pinCount !== checkpointCount) {
    failReleaseControl('BAD_PIN_HISTORY_BUNDLE', 'checkpoint and pin counts must match')
  }
  const pins = []
  for (let i = 0; i < pinCount; i++) {
    const bytes = reader.bytesU16(RELEASE_CONTROL_LIMIT.PIN_BYTES_MIN, RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX, `pins[${i}]`)
    decodePeeritHiveRelayProfilePinV1(bytes)
    pins.push(bytes)
  }
  reader.expectEnd('PeeritPinHistoryBundleV1')
  const decoded = { version, checkpoints, pins }
  if (!bytesEqual(encodePeeritPinHistoryBundleV1(decoded), value)) {
    failReleaseControl('NONCANONICAL_PIN_HISTORY_BUNDLE', 'bundle does not round-trip canonically')
  }
  return decoded
}

export function profilePinSignaturePayload (pin) {
  return concatBytes(asciiBytes(RELEASE_CONTROL_DOMAIN.PROFILE_PIN_SIGNATURE), encodePeeritHiveRelayProfilePinV1Unsigned(pin))
}

export function checkpointSignaturePayload (checkpoint) {
  return concatBytes(asciiBytes(RELEASE_CONTROL_DOMAIN.PIN_HISTORY_CHECKPOINT_SIGNATURE), encodePeeritPinHistoryCheckpointV1Unsigned(checkpoint))
}

export function profilePinSignaturePayloadHash (pin) {
  return blake2b256(profilePinSignaturePayload(pin))
}

export function checkpointSignaturePayloadHash (checkpoint) {
  return blake2b256(checkpointSignaturePayload(checkpoint))
}

export function releaseAuthorityKeyId (publicKey) {
  return domainHash(RELEASE_CONTROL_DOMAIN.RELEASE_AUTHORITY_KEY_ID, fixedBytesValue(publicKey, 32, 'releaseAuthorityPublicKey'))
}

export function profilePinHash (completeSignedPin) {
  return domainLengthHash(RELEASE_CONTROL_DOMAIN.PROFILE_PIN_HASH, completeSignedPin)
}

export function pinHistoryCheckpointHash (completeSignedCheckpoint) {
  return domainLengthHash(RELEASE_CONTROL_DOMAIN.PIN_HISTORY_CHECKPOINT_HASH, completeSignedCheckpoint)
}

export function pinHistoryBundleHash (completeBundle) {
  return domainLengthHash(RELEASE_CONTROL_DOMAIN.PIN_HISTORY_BUNDLE_HASH, completeBundle)
}

function validateVectorPath (path) {
  if (typeof path !== 'string' || path.length === 0 || path !== path.normalize('NFC')) {
    failReleaseControl('BAD_VECTOR_PATH', 'vector path must be non-empty NFC text')
  }
  if (path.startsWith('/') || path.includes('\\')) failReleaseControl('BAD_VECTOR_PATH', 'vector path must be relative and use slash separators')
  if (path.split('/').some(component => component === '' || component === '.' || component === '..')) {
    failReleaseControl('BAD_VECTOR_PATH', 'vector path contains a forbidden component')
  }
  const bytes = new TextEncoder().encode(path)
  if (bytes.byteLength > 0xffff) failReleaseControl('BAD_VECTOR_PATH', 'vector path exceeds u16')
  return bytes
}

export function encodeReleaseControlVectorManifest (entries) {
  if (!Array.isArray(entries) || entries.length === 0) failReleaseControl('BAD_VECTOR_MANIFEST', 'vector manifest cannot be empty')
  const normalized = entries.map(entry => {
    const pathBytes = validateVectorPath(entry.path)
    const bytes = asBytes(entry.bytes, `${entry.path} bytes`)
    return { path: entry.path, pathBytes, length: bytes.byteLength, hash: blake2b256(bytes) }
  }).sort((left, right) => compareBytes(left.pathBytes, right.pathBytes))
  assertStrictSorted(normalized.map(entry => entry.pathBytes), 'vector paths')
  const writer = new CanonicalWriter()
  writer.u32(normalized.length, 'vector count')
  for (const entry of normalized) {
    writer.u16(entry.pathBytes.byteLength, 'vector path length')
    writer.fixed(entry.pathBytes, entry.pathBytes.byteLength, 'vector path')
    writer.u64(entry.length, 'vector byte length')
    writer.fixed(entry.hash, 32, 'vector hash')
  }
  return writer.finish()
}

export function decodeReleaseControlVectorManifest (value) {
  const reader = new CanonicalReader(value)
  const count = reader.u32('vector count')
  if (count < 1) failReleaseControl('BAD_VECTOR_MANIFEST', 'vector manifest cannot be empty')
  const entries = []
  const pathBytes = []
  for (let i = 0; i < count; i++) {
    const pathLength = reader.u16('vector path length')
    if (pathLength < 1) failReleaseControl('BAD_VECTOR_PATH', 'vector path cannot be empty')
    const rawPath = reader.fixed(pathLength, 'vector path')
    const path = new TextDecoder('utf-8', { fatal: true }).decode(rawPath)
    if (!bytesEqual(validateVectorPath(path), rawPath)) failReleaseControl('BAD_VECTOR_PATH', 'vector path is not canonical UTF-8')
    pathBytes.push(rawPath)
    entries.push({ path, length: reader.u64('vector byte length'), hash: reader.fixed(32, 'vector hash') })
  }
  assertStrictSorted(pathBytes, 'vector paths')
  reader.expectEnd('vector manifest')
  return entries
}

export function migrationStageName (value) {
  assertMigrationStage(value)
  return Object.entries(PEERIT_MIGRATION_STAGE).find(([, id]) => id === value)[0]
}
