import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  bytesEqual,
  compareBytes,
  concatBytes,
  domainLengthHash,
  failReleaseControl,
  fixedBytesValue,
  isAllZero,
  utf8Bytes
} from './release-control-primitives.mjs'
import {
  verifyPeeritPortablePinHistoryV1
} from './portable-pin-history.mjs'

export const PEERIT_RECOVERY_BUNDLE_MAGIC_V1 = 'PEERITRB'
export const PEERIT_RECOVERY_PAYLOAD_MAGIC_V1 = 'PEERITRP'
export const PEERIT_RECOVERY_CRYPTO_SUITE_V1 =
  'argon2id-v1.3+xchacha20poly1305-ietf'
export const PEERIT_RECOVERY_KDF_V1 = Object.freeze({
  id: 1,
  version: 0x13,
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
  keyBytes: 32,
  saltBytes: 16,
  nonceBytes: 24,
  tagBytes: 16
})
export const PEERIT_RECOVERY_LIMITS_V1 = Object.freeze({
  maximumPassphraseBytes: 1024,
  maximumCiphertextBytes: 16777216,
  maximumRowsPerSection: 4096,
  maximumRowBytes: 1048576
})
export const PEERIT_RECOVERY_CAPABILITY_KIND_V1 = Object.freeze({
  PUBLIC_READ: 1,
  CELL_MANAGEMENT: 2,
  CORE_READ: 3
})
export const PEERIT_RECOVERY_FLOOR_KIND_V1 = Object.freeze({
  AUTHOR: 1,
  CORE: 2,
  RELEASE: 3,
  ROOT: 4,
  HEAD: 5,
  DISCOVERY: 6
})

const PAYLOAD_FIELDS = Object.freeze([
  'version',
  'accountSeed',
  'pinHistoryRecord',
  'capabilities',
  'pendingCellIntents',
  'publishedLogicalIds',
  'receipts',
  'witnessedFloors',
  'discoveryFloors',
  'verifiedIndexRoots',
  'authenticatedCursors',
  'repairBacklog',
  'retiredDeviceChainIds'
])
const BUNDLE_FIELDS = Object.freeze([
  'magic',
  'version',
  'kdfId',
  'memoryKiB',
  'iterations',
  'parallelism',
  'salt',
  'accountPublicKey',
  'ciphertextLength',
  'nonce',
  'sealed'
])
const CONTRACT = [
  'PeeritRecoveryBundleV1',
  'magic=PEERITRB',
  'version=1',
  'kdf=Argon2id-v1.3,m=65536KiB,t=3,p=1,key=32',
  'aead=XChaCha20-Poly1305-IETF,nonce=24,tag=16',
  'aad=header-through-ciphertextLength',
  'passphrase=NFC-valid-Unicode,UTF8[1..1024]',
  'ciphertextLength=plaintext[1..16777216]',
  'payload=PeeritRecoveryPayloadV1',
  'payload-excludes=deviceTransportSeed,CoreTransportWriterSeed,originCredential,bearerToken,cookie',
  'restore=fresh-device-writer-and-chain,monotonic-floors,verified-portable-pin-history'
].join('\n') + '\n'

function fail (code, message) {
  failReleaseControl(code, message)
}

function exactObject (input, fields, name) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype &&
       Object.getPrototypeOf(input) !== null)) {
    fail('BAD_RECOVERY_BUNDLE', `${name} must be a plain data object`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(input)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string') ||
      fields.some(field => !Object.hasOwn(descriptors, field))) {
    fail('BAD_RECOVERY_BUNDLE', `${name} fields are missing or unexpected`)
  }
  const output = Object.create(null)
  for (const field of fields) {
    const descriptor = descriptors[field]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('BAD_RECOVERY_BUNDLE', `${name}.${field} must be an enumerable data field`)
    }
    output[field] = descriptor.value
  }
  return output
}

function fixed (input, length, field, nonzero = true) {
  const value = new Uint8Array(fixedBytesValue(input, length, field))
  if (nonzero && isAllZero(value)) fail('BAD_RECOVERY_BUNDLE', `${field} must be nonzero`)
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_RECOVERY_BUNDLE', `${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    fail('BAD_RECOVERY_BUNDLE', `${field} is outside u64`)
  }
  return value
}

function boundedBytes (input, field, minimum = 1) {
  const value = new Uint8Array(asBytes(input, field))
  if (value.byteLength < minimum ||
      value.byteLength > PEERIT_RECOVERY_LIMITS_V1.maximumRowBytes) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} has an invalid byte length`)
  }
  return value
}

function assertSorted (values, projection, field) {
  for (let index = 1; index < values.length; index++) {
    if (compareBytes(projection(values[index - 1]), projection(values[index])) >= 0) {
      fail('NONCANONICAL_RECOVERY_PAYLOAD', `${field} must be strictly sorted and unique`)
    }
  }
}

function rows (input, field, withKind = false) {
  if (!Array.isArray(input) ||
      input.length > PEERIT_RECOVERY_LIMITS_V1.maximumRowsPerSection) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} count is invalid`)
  }
  const fields = withKind ? ['kind', 'id', 'bytes'] : ['id', 'bytes']
  const output = input.map((entry, index) => {
    const value = exactObject(entry, fields, `${field}[${index}]`)
    const row = {
      id: fixed(value.id, 32, `${field}[${index}].id`),
      bytes: boundedBytes(value.bytes, `${field}[${index}].bytes`)
    }
    if (withKind) {
      if (!Number.isSafeInteger(value.kind) || value.kind < 1 || value.kind > 3) {
        fail('BAD_RECOVERY_PAYLOAD',
          `${field}[${index}].kind must be public-read, CELL-management, or Core-read`)
      }
      row.kind = value.kind
    }
    return row
  })
  assertSorted(output, entry => withKind
    ? concatBytes(Uint8Array.of(entry.kind), entry.id)
    : entry.id, field)
  return output
}

function floors (input, field = 'witnessedFloors') {
  if (!Array.isArray(input) ||
      input.length > PEERIT_RECOVERY_LIMITS_V1.maximumRowsPerSection) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} count is invalid`)
  }
  const output = input.map((entry, index) => {
    const value = exactObject(entry, ['kind', 'scopeId', 'sequence', 'hash'],
      `${field}[${index}]`)
    if (!Number.isSafeInteger(value.kind) || value.kind < 1 || value.kind > 6) {
      fail('BAD_RECOVERY_PAYLOAD', `${field}[${index}].kind is invalid`)
    }
    return {
      kind: value.kind,
      scopeId: fixed(value.scopeId, 32, `${field}[${index}].scopeId`),
      sequence: u64(value.sequence, `${field}[${index}].sequence`),
      hash: fixed(value.hash, 32, `${field}[${index}].hash`)
    }
  })
  assertSorted(output, entry => concatBytes(Uint8Array.of(entry.kind), entry.scopeId), field)
  return output
}

function identifiers (input, field) {
  if (!Array.isArray(input) ||
      input.length > PEERIT_RECOVERY_LIMITS_V1.maximumRowsPerSection) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} count is invalid`)
  }
  const output = input.map((entry, index) => fixed(entry, 32, `${field}[${index}]`))
  assertSorted(output, entry => entry, field)
  return output
}

function canonicalPayload (input) {
  const value = exactObject(input, PAYLOAD_FIELDS, 'PeeritRecoveryPayloadV1')
  if (value.version !== 1) fail('BAD_RECOVERY_PAYLOAD', 'PeeritRecoveryPayloadV1 version must be 1')
  const pinHistoryRecord = new Uint8Array(asBytes(
    value.pinHistoryRecord, 'pinHistoryRecord'))
  if (pinHistoryRecord.byteLength < 1 ||
      pinHistoryRecord.byteLength > PEERIT_RECOVERY_LIMITS_V1.maximumCiphertextBytes) {
    fail('BAD_RECOVERY_PAYLOAD', 'pinHistoryRecord size is invalid')
  }
  return {
    version: 1,
    accountSeed: fixed(value.accountSeed, 32, 'accountSeed'),
    pinHistoryRecord,
    capabilities: rows(value.capabilities, 'capabilities', true),
    pendingCellIntents: rows(value.pendingCellIntents, 'pendingCellIntents'),
    publishedLogicalIds: identifiers(value.publishedLogicalIds, 'publishedLogicalIds'),
    receipts: rows(value.receipts, 'receipts'),
    witnessedFloors: floors(value.witnessedFloors),
    discoveryFloors: rows(value.discoveryFloors, 'discoveryFloors'),
    verifiedIndexRoots: rows(value.verifiedIndexRoots, 'verifiedIndexRoots'),
    authenticatedCursors: rows(value.authenticatedCursors, 'authenticatedCursors'),
    repairBacklog: rows(value.repairBacklog, 'repairBacklog'),
    retiredDeviceChainIds: identifiers(
      value.retiredDeviceChainIds, 'retiredDeviceChainIds')
  }
}

function writeByteRows (writer, values, field, withKind = false) {
  writer.u16(values.length, `${field} count`)
  for (const row of values) {
    if (withKind) writer.u8(row.kind, `${field} kind`)
    writer.fixed(row.id, 32, `${field} id`)
    writer.u32(row.bytes.byteLength, `${field} bytes length`)
    writer.fixed(row.bytes, row.bytes.byteLength, `${field} bytes`)
  }
}

function writePayload (value) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_RECOVERY_PAYLOAD_MAGIC_V1,
    'PeeritRecoveryPayloadV1 magic')
  writer.u8(1, 'PeeritRecoveryPayloadV1 version')
  writer.fixed(value.accountSeed, 32, 'accountSeed')
  writer.u32(value.pinHistoryRecord.byteLength, 'pinHistoryRecord length')
  writer.fixed(value.pinHistoryRecord, value.pinHistoryRecord.byteLength,
    'pinHistoryRecord')
  writeByteRows(writer, value.capabilities, 'capabilities', true)
  writeByteRows(writer, value.pendingCellIntents, 'pendingCellIntents')
  writer.u16(value.publishedLogicalIds.length, 'publishedLogicalIds count')
  for (const id of value.publishedLogicalIds) {
    writer.fixed(id, 32, 'publishedLogicalId')
  }
  writeByteRows(writer, value.receipts, 'receipts')
  writer.u16(value.witnessedFloors.length, 'witnessedFloors count')
  for (const floor of value.witnessedFloors) {
    writer.u8(floor.kind, 'witnessed floor kind')
    writer.fixed(floor.scopeId, 32, 'witnessed floor scopeId')
    writer.u64(floor.sequence, 'witnessed floor sequence')
    writer.fixed(floor.hash, 32, 'witnessed floor hash')
  }
  writeByteRows(writer, value.discoveryFloors, 'discoveryFloors')
  writeByteRows(writer, value.verifiedIndexRoots, 'verifiedIndexRoots')
  writeByteRows(writer, value.authenticatedCursors, 'authenticatedCursors')
  writeByteRows(writer, value.repairBacklog, 'repairBacklog')
  writer.u16(value.retiredDeviceChainIds.length, 'retiredDeviceChainIds count')
  for (const id of value.retiredDeviceChainIds) {
    writer.fixed(id, 32, 'retiredDeviceChainId')
  }
  const output = writer.finish()
  if (output.byteLength < 1 ||
      output.byteLength > PEERIT_RECOVERY_LIMITS_V1.maximumCiphertextBytes) {
    fail('BAD_RECOVERY_PAYLOAD', 'PeeritRecoveryPayloadV1 exceeds the ciphertext bound')
  }
  return output
}

export function encodePeeritRecoveryPayloadV1 (input) {
  return writePayload(canonicalPayload(input))
}

function readByteRows (reader, field, withKind = false) {
  const count = reader.u16(`${field} count`)
  if (count > PEERIT_RECOVERY_LIMITS_V1.maximumRowsPerSection) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} count is invalid`)
  }
  const output = []
  for (let index = 0; index < count; index++) {
    const row = {}
    if (withKind) row.kind = reader.u8(`${field}[${index}].kind`)
    row.id = reader.fixed(32, `${field}[${index}].id`)
    const length = reader.u32(`${field}[${index}].bytes length`)
    if (length < 1 || length > PEERIT_RECOVERY_LIMITS_V1.maximumRowBytes) {
      fail('BAD_RECOVERY_PAYLOAD', `${field}[${index}].bytes length is invalid`)
    }
    row.bytes = reader.fixed(length, `${field}[${index}].bytes`)
    output.push(row)
  }
  return output
}

export function decodePeeritRecoveryPayloadV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritRecoveryPayloadV1 bytes'))
  if (bytes.byteLength < 1 ||
      bytes.byteLength > PEERIT_RECOVERY_LIMITS_V1.maximumCiphertextBytes) {
    fail('BAD_RECOVERY_PAYLOAD', 'PeeritRecoveryPayloadV1 size is invalid')
  }
  const reader = new CanonicalReader(bytes)
  reader.expectLiteralAscii(PEERIT_RECOVERY_PAYLOAD_MAGIC_V1,
    'PeeritRecoveryPayloadV1 magic')
  const version = reader.u8('PeeritRecoveryPayloadV1 version')
  const accountSeed = reader.fixed(32, 'accountSeed')
  const pinHistoryLength = reader.u32('pinHistoryRecord length')
  if (pinHistoryLength < 1 ||
      pinHistoryLength > PEERIT_RECOVERY_LIMITS_V1.maximumCiphertextBytes) {
    fail('BAD_RECOVERY_PAYLOAD', 'pinHistoryRecord length is invalid')
  }
  const pinHistoryRecord = reader.fixed(pinHistoryLength, 'pinHistoryRecord')
  const capabilities = readByteRows(reader, 'capabilities', true)
  const pendingCellIntents = readByteRows(reader, 'pendingCellIntents')
  const publishedCount = reader.u16('publishedLogicalIds count')
  const publishedLogicalIds = []
  for (let index = 0; index < publishedCount; index++) {
    publishedLogicalIds.push(reader.fixed(32, `publishedLogicalIds[${index}]`))
  }
  const receipts = readByteRows(reader, 'receipts')
  const floorCount = reader.u16('witnessedFloors count')
  const witnessedFloors = []
  for (let index = 0; index < floorCount; index++) {
    witnessedFloors.push({
      kind: reader.u8(`witnessedFloors[${index}].kind`),
      scopeId: reader.fixed(32, `witnessedFloors[${index}].scopeId`),
      sequence: reader.u64(`witnessedFloors[${index}].sequence`),
      hash: reader.fixed(32, `witnessedFloors[${index}].hash`)
    })
  }
  const discoveryFloors = readByteRows(reader, 'discoveryFloors')
  const verifiedIndexRoots = readByteRows(reader, 'verifiedIndexRoots')
  const authenticatedCursors = readByteRows(reader, 'authenticatedCursors')
  const repairBacklog = readByteRows(reader, 'repairBacklog')
  const retiredCount = reader.u16('retiredDeviceChainIds count')
  const retiredDeviceChainIds = []
  for (let index = 0; index < retiredCount; index++) {
    retiredDeviceChainIds.push(reader.fixed(32, `retiredDeviceChainIds[${index}]`))
  }
  reader.expectEnd('PeeritRecoveryPayloadV1')
  const value = canonicalPayload({
    version,
    accountSeed,
    pinHistoryRecord,
    capabilities,
    pendingCellIntents,
    publishedLogicalIds,
    receipts,
    witnessedFloors,
    discoveryFloors,
    verifiedIndexRoots,
    authenticatedCursors,
    repairBacklog,
    retiredDeviceChainIds
  })
  if (!bytesEqual(writePayload(value), bytes)) {
    fail('NONCANONICAL_RECOVERY_PAYLOAD', 'PeeritRecoveryPayloadV1 is noncanonical')
  }
  return freezePayload(value)
}

function freezeRows (values, withKind = false) {
  return Object.freeze(values.map(row => Object.freeze({
    ...(withKind ? { kind: row.kind } : {}),
    id: new Uint8Array(row.id),
    bytes: new Uint8Array(row.bytes)
  })))
}

function freezePayload (value) {
  return Object.freeze({
    version: 1,
    accountSeed: new Uint8Array(value.accountSeed),
    pinHistoryRecord: new Uint8Array(value.pinHistoryRecord),
    capabilities: freezeRows(value.capabilities, true),
    pendingCellIntents: freezeRows(value.pendingCellIntents),
    publishedLogicalIds: Object.freeze(value.publishedLogicalIds.map(
      entry => new Uint8Array(entry))),
    receipts: freezeRows(value.receipts),
    witnessedFloors: Object.freeze(value.witnessedFloors.map(entry => Object.freeze({
      kind: entry.kind,
      scopeId: new Uint8Array(entry.scopeId),
      sequence: entry.sequence,
      hash: new Uint8Array(entry.hash)
    }))),
    discoveryFloors: freezeRows(value.discoveryFloors),
    verifiedIndexRoots: freezeRows(value.verifiedIndexRoots),
    authenticatedCursors: freezeRows(value.authenticatedCursors),
    repairBacklog: freezeRows(value.repairBacklog),
    retiredDeviceChainIds: Object.freeze(value.retiredDeviceChainIds.map(
      entry => new Uint8Array(entry)))
  })
}

function canonicalBundle (input) {
  const value = exactObject(input, BUNDLE_FIELDS, 'PeeritRecoveryBundleV1')
  const kdf = PEERIT_RECOVERY_KDF_V1
  if (value.magic !== PEERIT_RECOVERY_BUNDLE_MAGIC_V1 || value.version !== 1 ||
      value.kdfId !== kdf.id || value.memoryKiB !== kdf.memoryKiB ||
      value.iterations !== kdf.iterations || value.parallelism !== kdf.parallelism) {
    fail('BAD_RECOVERY_BUNDLE_PARAMETERS',
      'PeeritRecoveryBundleV1 has an unregistered version or KDF parameter set')
  }
  const ciphertextLength = u64(value.ciphertextLength, 'ciphertextLength')
  if (ciphertextLength < 1n ||
      ciphertextLength > BigInt(PEERIT_RECOVERY_LIMITS_V1.maximumCiphertextBytes)) {
    fail('BAD_RECOVERY_BUNDLE', 'ciphertextLength is outside the registered bound')
  }
  const sealed = new Uint8Array(asBytes(value.sealed, 'sealed'))
  if (BigInt(sealed.byteLength) !== ciphertextLength + BigInt(kdf.tagBytes)) {
    fail('BAD_RECOVERY_BUNDLE', 'sealed length does not equal ciphertextLength plus tag')
  }
  return {
    magic: PEERIT_RECOVERY_BUNDLE_MAGIC_V1,
    version: 1,
    kdfId: kdf.id,
    memoryKiB: kdf.memoryKiB,
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
    salt: fixed(value.salt, kdf.saltBytes, 'salt'),
    accountPublicKey: fixed(value.accountPublicKey, 32, 'accountPublicKey'),
    ciphertextLength,
    nonce: fixed(value.nonce, kdf.nonceBytes, 'nonce'),
    sealed
  }
}

function writeHeader (value) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_RECOVERY_BUNDLE_MAGIC_V1,
    'PeeritRecoveryBundleV1 magic')
  writer.u8(1, 'PeeritRecoveryBundleV1 version')
  writer.u8(PEERIT_RECOVERY_KDF_V1.id, 'kdfId')
  writer.u32(PEERIT_RECOVERY_KDF_V1.memoryKiB, 'memoryKiB')
  writer.u32(PEERIT_RECOVERY_KDF_V1.iterations, 'iterations')
  writer.u8(PEERIT_RECOVERY_KDF_V1.parallelism, 'parallelism')
  writer.fixed(value.salt, PEERIT_RECOVERY_KDF_V1.saltBytes, 'salt')
  writer.fixed(value.accountPublicKey, 32, 'accountPublicKey')
  writer.u64(value.ciphertextLength, 'ciphertextLength')
  return writer.finish()
}

function writeBundle (value) {
  const writer = new CanonicalWriter()
  writer.fixed(writeHeader(value), 75, 'PeeritRecoveryBundleV1 header')
  writer.fixed(value.nonce, PEERIT_RECOVERY_KDF_V1.nonceBytes, 'nonce')
  writer.fixed(value.sealed, value.sealed.byteLength, 'sealed')
  return writer.finish()
}

export function encodePeeritRecoveryBundleV1 (input) {
  return writeBundle(canonicalBundle(input))
}

export function decodePeeritRecoveryBundleV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritRecoveryBundleV1 bytes'))
  const maximum = 75 + PEERIT_RECOVERY_KDF_V1.nonceBytes +
    PEERIT_RECOVERY_LIMITS_V1.maximumCiphertextBytes + PEERIT_RECOVERY_KDF_V1.tagBytes
  if (bytes.byteLength < 75 + PEERIT_RECOVERY_KDF_V1.nonceBytes + 17 ||
      bytes.byteLength > maximum) {
    fail('BAD_RECOVERY_BUNDLE', 'PeeritRecoveryBundleV1 size is invalid')
  }
  const reader = new CanonicalReader(bytes)
  const magic = reader.expectLiteralAscii(PEERIT_RECOVERY_BUNDLE_MAGIC_V1,
    'PeeritRecoveryBundleV1 magic')
  const version = reader.u8('version')
  const kdfId = reader.u8('kdfId')
  const memoryKiB = reader.u32('memoryKiB')
  const iterations = reader.u32('iterations')
  const parallelism = reader.u8('parallelism')
  const salt = reader.fixed(16, 'salt')
  const accountPublicKey = reader.fixed(32, 'accountPublicKey')
  const ciphertextLength = reader.u64('ciphertextLength')
  const nonce = reader.fixed(24, 'nonce')
  if (ciphertextLength < 1n ||
      ciphertextLength > BigInt(PEERIT_RECOVERY_LIMITS_V1.maximumCiphertextBytes)) {
    fail('BAD_RECOVERY_BUNDLE', 'ciphertextLength is invalid')
  }
  const sealed = reader.fixed(Number(ciphertextLength) + 16, 'sealed')
  reader.expectEnd('PeeritRecoveryBundleV1')
  const value = canonicalBundle({
    magic,
    version,
    kdfId,
    memoryKiB,
    iterations,
    parallelism,
    salt,
    accountPublicKey,
    ciphertextLength,
    nonce,
    sealed
  })
  if (!bytesEqual(writeBundle(value), bytes)) {
    fail('BAD_RECOVERY_BUNDLE', 'PeeritRecoveryBundleV1 is noncanonical')
  }
  return Object.freeze(value)
}

function validUnicodeScalarString (value) {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++index)
      if (next < 0xdc00 || next > 0xdfff) return false
    } else if (code >= 0xdc00 && code <= 0xdfff) return false
  }
  return true
}

export function peeritRecoveryPassphraseBytesV1 (input) {
  if (typeof input !== 'string' || input.length < 1 ||
      !validUnicodeScalarString(input) || input !== input.normalize('NFC')) {
    fail('BAD_RECOVERY_PASSPHRASE',
      'recovery passphrase must be a nonempty NFC Unicode scalar string')
  }
  const bytes = new TextEncoder().encode(input)
  if (bytes.byteLength < 1 ||
      bytes.byteLength > PEERIT_RECOVERY_LIMITS_V1.maximumPassphraseBytes) {
    fail('BAD_RECOVERY_PASSPHRASE', 'recovery passphrase UTF-8 length is invalid')
  }
  return bytes
}

function cryptoRuntime (input) {
  if (!input || input.recoveryAlgorithm !== PEERIT_RECOVERY_CRYPTO_SUITE_V1 ||
      typeof input.randomBytes !== 'function' ||
      typeof input.deriveArgon2id !== 'function' ||
      typeof input.encryptXChaCha20Poly1305Ietf !== 'function' ||
      typeof input.decryptXChaCha20Poly1305Ietf !== 'function' ||
      typeof input.deriveEd25519PublicKey !== 'function' ||
      typeof input.verifyEd25519 !== 'function') {
    fail('RECOVERY_CRYPTO_UNAVAILABLE',
      'the exact bundled Argon2id/XChaCha/Ed25519 recovery runtime is required')
  }
  return input
}

async function deriveKey (runtime, passphraseBytes, salt) {
  const key = new Uint8Array(await runtime.deriveArgon2id({
    version: PEERIT_RECOVERY_KDF_V1.version,
    passphrase: new Uint8Array(passphraseBytes),
    salt: new Uint8Array(salt),
    memoryKiB: PEERIT_RECOVERY_KDF_V1.memoryKiB,
    iterations: PEERIT_RECOVERY_KDF_V1.iterations,
    parallelism: PEERIT_RECOVERY_KDF_V1.parallelism,
    outputBytes: PEERIT_RECOVERY_KDF_V1.keyBytes
  }))
  if (key.byteLength !== PEERIT_RECOVERY_KDF_V1.keyBytes) {
    key.fill(0)
    fail('RECOVERY_CRYPTO_UNAVAILABLE', 'Argon2id runtime returned the wrong key length')
  }
  return key
}

async function random (runtime, length, field) {
  const value = new Uint8Array(await runtime.randomBytes(length))
  if (value.byteLength !== length || isAllZero(value)) {
    fail('RECOVERY_RANDOMNESS_FAILURE', `${field} randomness is invalid`)
  }
  return value
}

async function decryptPayload (bundle, passphrase, runtime) {
  const passphraseBytes = peeritRecoveryPassphraseBytesV1(passphrase)
  const key = await deriveKey(runtime, passphraseBytes, bundle.salt)
  passphraseBytes.fill(0)
  try {
    let plaintext
    try {
      plaintext = new Uint8Array(await runtime.decryptXChaCha20Poly1305Ietf({
        key: new Uint8Array(key),
        nonce: new Uint8Array(bundle.nonce),
        sealed: new Uint8Array(bundle.sealed),
        aad: writeHeader(bundle)
      }))
    } catch (cause) {
      const error = new Error('recovery bundle authentication failed')
      error.code = 'RECOVERY_AUTHENTICATION_FAILED'
      error.cause = cause
      throw error
    }
    if (BigInt(plaintext.byteLength) !== bundle.ciphertextLength) {
      plaintext.fill(0)
      fail('RECOVERY_AUTHENTICATION_FAILED',
        'authenticated recovery plaintext has the wrong length')
    }
    return plaintext
  } finally {
    key.fill(0)
  }
}

async function assertAccountPublicKey (payload, expected, runtime) {
  const derived = new Uint8Array(await runtime.deriveEd25519PublicKey(
    new Uint8Array(payload.accountSeed)))
  try {
    if (derived.byteLength !== 32 || !bytesEqual(derived, expected)) {
      fail('RECOVERY_ACCOUNT_IDENTITY_MISMATCH',
        'recovered account seed does not reproduce the bundle public key')
    }
  } finally {
    derived.fill(0)
  }
}

export async function exportPeeritRecoveryBundleV1 (payloadInput, passphrase, options = {}) {
  const runtime = cryptoRuntime(options.crypto)
  const payloadBytes = encodePeeritRecoveryPayloadV1(payloadInput)
  const payload = decodePeeritRecoveryPayloadV1(payloadBytes)
  await verifyPeeritPortablePinHistoryV1(payload.pinHistoryRecord, {
    crypto: runtime,
    trustRoot: options.trustRoot,
    minimumWitness: options.minimumPinHistoryWitness
  })
  const accountPublicKey = new Uint8Array(await runtime.deriveEd25519PublicKey(
    new Uint8Array(payload.accountSeed)))
  if (accountPublicKey.byteLength !== 32 || isAllZero(accountPublicKey)) {
    accountPublicKey.fill(0)
    fail('RECOVERY_ACCOUNT_IDENTITY_MISMATCH', 'account seed produced an invalid public key')
  }
  const salt = await random(runtime, 16, 'recovery salt')
  const nonce = await random(runtime, 24, 'recovery nonce')
  const passphraseBytes = peeritRecoveryPassphraseBytesV1(passphrase)
  const key = await deriveKey(runtime, passphraseBytes, salt)
  passphraseBytes.fill(0)
  try {
    const provisional = {
      magic: PEERIT_RECOVERY_BUNDLE_MAGIC_V1,
      version: 1,
      kdfId: 1,
      memoryKiB: 65536,
      iterations: 3,
      parallelism: 1,
      salt,
      accountPublicKey,
      ciphertextLength: BigInt(payloadBytes.byteLength),
      nonce,
      sealed: new Uint8Array(payloadBytes.byteLength + 16)
    }
    const sealed = new Uint8Array(await runtime.encryptXChaCha20Poly1305Ietf({
      key: new Uint8Array(key),
      nonce: new Uint8Array(nonce),
      plaintext: new Uint8Array(payloadBytes),
      aad: writeHeader(provisional)
    }))
    if (sealed.byteLength !== payloadBytes.byteLength + 16) {
      sealed.fill(0)
      fail('RECOVERY_CRYPTO_UNAVAILABLE', 'XChaCha runtime returned the wrong sealed length')
    }
    const bytes = encodePeeritRecoveryBundleV1({ ...provisional, sealed })
    // Success is reported only after the exact emitted bytes authenticate and
    // reproduce the account identity through an immediate test import.
    const testBundle = decodePeeritRecoveryBundleV1(bytes)
    const testPlaintext = await decryptPayload(testBundle, passphrase, runtime)
    try {
      const testPayload = decodePeeritRecoveryPayloadV1(testPlaintext)
      await assertAccountPublicKey(testPayload, testBundle.accountPublicKey, runtime)
      if (!bytesEqual(testPlaintext, payloadBytes)) {
        fail('RECOVERY_EXPORT_SELF_TEST_FAILED', 'recovery export did not round-trip exactly')
      }
    } finally {
      testPlaintext.fill(0)
    }
    return bytes
  } finally {
    key.fill(0)
    payloadBytes.fill(0)
    accountPublicKey.fill(0)
  }
}

function floorKey (value) {
  return `${value.kind}:${hex(value.scopeId)}`
}

function hex (input) {
  let output = ''
  for (const byte of input) output += byte.toString(16).padStart(2, '0')
  return output
}

export function mergePeeritRecoveryFloorsV1 (localInput, recoveredInput) {
  const local = floors(localInput, 'local witnessed floors')
  const recovered = floors(recoveredInput, 'recovered witnessed floors')
  const merged = new Map()
  for (const value of [...local, ...recovered]) {
    const key = floorKey(value)
    const prior = merged.get(key)
    if (prior == null || value.sequence > prior.sequence) {
      merged.set(key, value)
    } else if (value.sequence === prior.sequence && !bytesEqual(value.hash, prior.hash)) {
      fail('RECOVERY_FLOOR_FORK',
        'same-sequence recovery floors contain different witnessed hashes')
    }
  }
  return Object.freeze([...merged.values()]
    .sort((left, right) => compareBytes(
      concatBytes(Uint8Array.of(left.kind), left.scopeId),
      concatBytes(Uint8Array.of(right.kind), right.scopeId)))
    .map(value => Object.freeze({
      kind: value.kind,
      scopeId: new Uint8Array(value.scopeId),
      sequence: value.sequence,
      hash: new Uint8Array(value.hash)
    })))
}

function containsId (values, candidate) {
  return values.some(value => bytesEqual(value, candidate))
}

export async function importPeeritRecoveryBundleV1 (input, passphrase, options = {}) {
  const runtime = cryptoRuntime(options.crypto)
  const bundle = decodePeeritRecoveryBundleV1(input)
  const plaintext = await decryptPayload(bundle, passphrase, runtime)
  try {
    const payload = decodePeeritRecoveryPayloadV1(plaintext)
    await assertAccountPublicKey(payload, bundle.accountPublicKey, runtime)
    const verifiedPinHistory = await verifyPeeritPortablePinHistoryV1(
      payload.pinHistoryRecord,
      {
        crypto: runtime,
        trustRoot: options.trustRoot,
        minimumWitness: options.minimumPinHistoryWitness
      }
    )
    const mergedFloors = mergePeeritRecoveryFloorsV1(
      options.localWitnessedFloors || [],
      payload.witnessedFloors
    )
    const deviceTransportSeed = await random(runtime, 32, 'fresh device transport seed')
    const deviceChainId = await random(runtime, 32, 'fresh device chain ID')
    const currentSeed = options.currentDeviceTransportSeed == null
      ? null
      : fixed(options.currentDeviceTransportSeed, 32, 'currentDeviceTransportSeed')
    const currentChainId = options.currentDeviceChainId == null
      ? null
      : fixed(options.currentDeviceChainId, 32, 'currentDeviceChainId')
    if (bytesEqual(deviceTransportSeed, payload.accountSeed) ||
        (currentSeed != null && bytesEqual(deviceTransportSeed, currentSeed)) ||
        (currentChainId != null && bytesEqual(deviceChainId, currentChainId)) ||
        containsId(payload.retiredDeviceChainIds, deviceChainId)) {
      deviceTransportSeed.fill(0)
      deviceChainId.fill(0)
      fail('RECOVERY_CLONED_WRITER_REJECTED',
        'restore randomness would clone an account or device writer identity')
    }
    return Object.freeze({
      version: 1,
      accountPublicKey: new Uint8Array(bundle.accountPublicKey),
      payload,
      verifiedPinHistory,
      mergedWitnessedFloors: mergedFloors,
      deviceTransportSeed,
      deviceChainId
    })
  } finally {
    plaintext.fill(0)
  }
}

export function peeritRecoveryBundleContractBytesV1 () {
  return utf8Bytes(CONTRACT, 'PeeritRecoveryBundleV1 contract')
}

export function peeritRecoveryBundleContractHashV1 () {
  return domainLengthHash(
    'peerit.recovery-bundle-contract.v1',
    peeritRecoveryBundleContractBytesV1()
  )
}
