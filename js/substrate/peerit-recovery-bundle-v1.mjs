import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  asciiBytes,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  domainLengthHash,
  failReleaseControl,
  fixedBytesValue,
  hexToBytes,
  isAllZero,
  utf8Bytes
} from './release-control-primitives.mjs'
import { verifyPeeritPortablePinHistoryV1 } from './portable-pin-history.mjs'

// The frozen profile owns PeeritRecoveryBundleV1. Its authenticated plaintext
// and portable release contract intentionally advance to V2: V1 plaintext must
// fail instead of inheriting stronger semantics it never encoded.
export const PEERIT_RECOVERY_BUNDLE_MAGIC_V1 = 'PEERITRB'
export const PEERIT_RECOVERY_PAYLOAD_MAGIC_V2 = 'PEERITR2'
export const PEERIT_RECOVERY_RECORD_MAGIC_V2 = 'PEERITRR'
export const PEERIT_RECOVERY_COLLISION_SET_MAGIC_V1 = 'PEERITCS'
export const PEERIT_RECOVERY_CRYPTO_SUITE_V1 =
  'argon2id-v1.3+xchacha20poly1305-ietf'
export const PEERIT_DEVICE_CHAIN_START_SIGNATURE_DOMAIN_V1 =
  'peerit.hiverelay.device-chain-start.v1'

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

export const PEERIT_RECOVERY_LIMITS_V2 = Object.freeze({
  maximumPassphraseBytes: 1024,
  maximumCiphertextBytes: 16777216,
  maximumRecordsPerSection: 4096,
  maximumRecordBytes: 4194304,
  maximumOperationalBytes: 1048576,
  maximumCoreSignedHeadBytes: 4096
})

export const PEERIT_RECOVERY_RECORD_TYPE_V2 = Object.freeze({
  PUBLIC_READ_CAPABILITY: 1,
  CELL_MANAGEMENT_CAPABILITY: 2,
  CORE_READ_CAPABILITY: 3,
  PENDING_CELL_INTENT: 16,
  RECEIPT: 17,
  DISCOVERY_FLOOR: 18,
  VERIFIED_INDEX_ROOT: 19,
  AUTHENTICATED_CURSOR: 20,
  REPAIR_BACKLOG: 21,
  WITNESSED_FLOOR: 22
})

export const PEERIT_RECOVERY_FLOOR_KIND_V1 = Object.freeze({
  AUTHOR: 1,
  CORE: 2,
  RELEASE: 3,
  ROOT: 4,
  HEAD: 5,
  DISCOVERY: 6
})

export const PEERIT_RECOVERY_PROFILE_BINDING_V2 = Object.freeze({
  profileId: '@peerit/hiverelay-profile-v1',
  profileSpecHash:
    '931a85e29eb3767d8d2a1920d7e127cf20d708cce6975d967522fd07f475f473',
  inventoryCommitment:
    '68bf44c0933e01f6eb208c65a2de486e6b7aca371b51b7022797d4ab9fad0fcc',
  schemaCount: 78,
  deviceChainStartTag: 332,
  deviceChainStartMaximumBytes: 208,
  deviceChainStartSourceSha256:
    'c0bf52a841e40d6a6378b39a5324dd637afb86053253dd7c5b98a38f1356b914',
  validatorArtifactHash:
    '9e4c2e57769d005bee92a227751e559144824553b202401fb89c06d4bca55b2a',
  validatorVectorSetHash:
    'b0cfcbe4deebd25632edb53c570ca9b05a1e0544532af4091ca8c43249994f9b'
})

const TYPES = PEERIT_RECOVERY_RECORD_TYPE_V2
const RECORD_FIELDS = Object.freeze({
  [TYPES.PUBLIC_READ_CAPABILITY]: Object.freeze({
    name: 'PublicReadCapabilityV2',
    fields: Object.freeze([
      Object.freeze({ name: 'relayPublicKey', kind: 'fixed32' }),
      Object.freeze({ name: 'storageSlot', kind: 'fixed32' }),
      Object.freeze({ name: 'cellKey', kind: 'fixed32' }),
      Object.freeze({ name: 'sizeClass', kind: 'u8', minimum: 1, maximum: 5 }),
      Object.freeze({ name: 'expectedCellBlobHash', kind: 'optional32' })
    ])
  }),
  [TYPES.CELL_MANAGEMENT_CAPABILITY]: Object.freeze({
    name: 'CellManagementCapabilityV2',
    fields: Object.freeze([
      Object.freeze({ name: 'relayPublicKey', kind: 'fixed32' }),
      Object.freeze({ name: 'storageSlot', kind: 'fixed32' }),
      Object.freeze({ name: 'cellKey', kind: 'fixed32' }),
      Object.freeze({ name: 'sizeClass', kind: 'u8', minimum: 1, maximum: 5 }),
      Object.freeze({ name: 'expectedCellBlobHash', kind: 'optional32' }),
      Object.freeze({ name: 'allocationEpoch', kind: 'u32' }),
      Object.freeze({ name: 'createPrivateKey', kind: 'fixed32' }),
      Object.freeze({ name: 'renewPrivateKey', kind: 'fixed32' }),
      Object.freeze({ name: 'dropPrivateKey', kind: 'fixed32' })
    ])
  }),
  [TYPES.CORE_READ_CAPABILITY]: Object.freeze({
    name: 'CoreReadCapabilityV2',
    fields: Object.freeze([
      Object.freeze({ name: 'corePublicKey', kind: 'fixed32' }),
      Object.freeze({ name: 'blockEncryptionKey', kind: 'fixed32' }),
      Object.freeze({ name: 'witnessedFork', kind: 'u64' }),
      Object.freeze({ name: 'witnessedLength', kind: 'u64' }),
      Object.freeze({
        name: 'witnessedSignedHead',
        kind: 'bytesU16',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumCoreSignedHeadBytes
      })
    ])
  }),
  [TYPES.PENDING_CELL_INTENT]: Object.freeze({
    name: 'PendingCellIntentV2',
    fields: Object.freeze([
      Object.freeze({ name: 'logicalIntentId', kind: 'fixed32' }),
      Object.freeze({ name: 'createdUnixMillis', kind: 'u64' }),
      Object.freeze({ name: 'operationKind', kind: 'u8', minimum: 1, maximum: 4 }),
      Object.freeze({ name: 'targetId', kind: 'fixed32' }),
      Object.freeze({ name: 'relayPublicKey', kind: 'fixed32' }),
      Object.freeze({ name: 'storeId', kind: 'fixed32' }),
      Object.freeze({ name: 'durabilityContinuityHash', kind: 'fixed32' }),
      Object.freeze({ name: 'endpointRole', kind: 'u8', minimum: 1, maximum: 8 }),
      Object.freeze({ name: 'locatorHash', kind: 'fixed32' }),
      Object.freeze({ name: 'managementCapabilityRecordId', kind: 'fixed32' }),
      Object.freeze({
        name: 'innerEnvelopeBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'innerEnvelopeHash', kind: 'fixed32' }),
      Object.freeze({
        name: 'replicaBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'replicaHash', kind: 'fixed32' }),
      Object.freeze({
        name: 'requestBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'requestBytesHash', kind: 'fixed32' }),
      Object.freeze({ name: 'requestCommitment', kind: 'fixed32' }),
      Object.freeze({ name: 'spendBindingHash', kind: 'optional32' }),
      Object.freeze({ name: 'expectedRevision', kind: 'u64' })
    ])
  }),
  [TYPES.RECEIPT]: Object.freeze({
    name: 'RecoveryReceiptV2',
    fields: Object.freeze([
      Object.freeze({ name: 'intentRecordId', kind: 'fixed32' }),
      Object.freeze({ name: 'requestCommitment', kind: 'fixed32' }),
      Object.freeze({ name: 'issuerPublicKey', kind: 'fixed32' }),
      Object.freeze({ name: 'status', kind: 'u8', minimum: 1, maximum: 3 }),
      Object.freeze({ name: 'commitSequence', kind: 'u64' }),
      Object.freeze({ name: 'commitDescriptorSequence', kind: 'u64' }),
      Object.freeze({ name: 'commitDescriptorHash', kind: 'fixed32' }),
      Object.freeze({ name: 'durabilityProfileHash', kind: 'fixed32' }),
      Object.freeze({
        name: 'resultBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'resultBytesHash', kind: 'fixed32' })
    ])
  }),
  [TYPES.DISCOVERY_FLOOR]: Object.freeze({
    name: 'RecoveryDiscoveryFloorV2',
    fields: Object.freeze([
      Object.freeze({ name: 'sourceId', kind: 'fixed32' }),
      Object.freeze({ name: 'checkpointSequence', kind: 'u64' }),
      Object.freeze({ name: 'checkpointHash', kind: 'fixed32' }),
      Object.freeze({
        name: 'recentBucketTupleBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'recentBucketTupleHash', kind: 'fixed32' })
    ])
  }),
  [TYPES.VERIFIED_INDEX_ROOT]: Object.freeze({
    name: 'VerifiedIndexRootV2',
    fields: Object.freeze([
      Object.freeze({ name: 'indexId', kind: 'fixed32' }),
      Object.freeze({ name: 'rootSequence', kind: 'u64' }),
      Object.freeze({ name: 'rootHash', kind: 'fixed32' }),
      Object.freeze({
        name: 'rootRecordBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'rootRecordBytesHash', kind: 'fixed32' })
    ])
  }),
  [TYPES.AUTHENTICATED_CURSOR]: Object.freeze({
    name: 'AuthenticatedCursorV2',
    fields: Object.freeze([
      Object.freeze({ name: 'cursorKind', kind: 'u8', minimum: 1, maximum: 4 }),
      Object.freeze({ name: 'cursorId', kind: 'fixed32' }),
      Object.freeze({ name: 'sourcePublicKey', kind: 'fixed32' }),
      Object.freeze({ name: 'sequence', kind: 'u64' }),
      Object.freeze({ name: 'entryHash', kind: 'fixed32' }),
      Object.freeze({
        name: 'authenticatedCursorBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'authenticatedCursorBytesHash', kind: 'fixed32' })
    ])
  }),
  [TYPES.REPAIR_BACKLOG]: Object.freeze({
    name: 'RepairBacklogEntryV2',
    fields: Object.freeze([
      Object.freeze({ name: 'targetId', kind: 'fixed32' }),
      Object.freeze({ name: 'reason', kind: 'u8', minimum: 1, maximum: 8 }),
      Object.freeze({ name: 'floorSequence', kind: 'u64' }),
      Object.freeze({ name: 'expectedHash', kind: 'fixed32' }),
      Object.freeze({ name: 'destinationHash', kind: 'fixed32' }),
      Object.freeze({ name: 'capabilityRecordId', kind: 'fixed32' }),
      Object.freeze({
        name: 'repairRequestBytes',
        kind: 'bytesU32',
        minimum: 1,
        maximum: PEERIT_RECOVERY_LIMITS_V2.maximumOperationalBytes
      }),
      Object.freeze({ name: 'repairRequestBytesHash', kind: 'fixed32' })
    ])
  }),
  [TYPES.WITNESSED_FLOOR]: Object.freeze({
    name: 'WitnessedFloorV2',
    fields: Object.freeze([
      Object.freeze({ name: 'floorKind', kind: 'u8', minimum: 1, maximum: 6 }),
      Object.freeze({ name: 'scopeId', kind: 'fixed32' }),
      Object.freeze({ name: 'sequence', kind: 'u64' }),
      Object.freeze({ name: 'witnessHash', kind: 'fixed32' })
    ])
  })
})

const PAYLOAD_FIELDS_V2 = Object.freeze([
  'version',
  'accountSeed',
  'pinHistoryRecord',
  'capabilityRecords',
  'pendingCellIntentRecords',
  'publishedLogicalIds',
  'receiptRecords',
  'witnessedFloorRecords',
  'discoveryFloorRecords',
  'verifiedIndexRootRecords',
  'authenticatedCursorRecords',
  'repairBacklogRecords',
  'retiredDeviceChainIds'
])

const PAYLOAD_SECTIONS_V2 = Object.freeze([
  Object.freeze({
    field: 'capabilityRecords',
    allowedTypes: Object.freeze([
      TYPES.PUBLIC_READ_CAPABILITY,
      TYPES.CELL_MANAGEMENT_CAPABILITY,
      TYPES.CORE_READ_CAPABILITY
    ]),
    sort: 'type+recordId'
  }),
  Object.freeze({
    field: 'pendingCellIntentRecords',
    allowedTypes: Object.freeze([TYPES.PENDING_CELL_INTENT]),
    sort: 'recordId'
  }),
  Object.freeze({
    field: 'receiptRecords',
    allowedTypes: Object.freeze([TYPES.RECEIPT]),
    sort: 'recordId'
  }),
  Object.freeze({
    field: 'witnessedFloorRecords',
    allowedTypes: Object.freeze([TYPES.WITNESSED_FLOOR]),
    sort: 'floorKind+scopeId'
  }),
  Object.freeze({
    field: 'discoveryFloorRecords',
    allowedTypes: Object.freeze([TYPES.DISCOVERY_FLOOR]),
    sort: 'recordId'
  }),
  Object.freeze({
    field: 'verifiedIndexRootRecords',
    allowedTypes: Object.freeze([TYPES.VERIFIED_INDEX_ROOT]),
    sort: 'recordId'
  }),
  Object.freeze({
    field: 'authenticatedCursorRecords',
    allowedTypes: Object.freeze([TYPES.AUTHENTICATED_CURSOR]),
    sort: 'recordId'
  }),
  Object.freeze({
    field: 'repairBacklogRecords',
    allowedTypes: Object.freeze([TYPES.REPAIR_BACKLOG]),
    sort: 'recordId'
  })
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

const COLLISION_SET_INPUT_FIELDS = Object.freeze([
  'version',
  'complete',
  'activeTransportPublicKeys',
  'retiredTransportPublicKeys',
  'activeDeviceChainIds',
  'retiredDeviceChainIds',
  'localWitnessedFloors',
  'previousAuthorSequence',
  'previousAuthorRecordId',
  'createdLeaseEpoch'
])

const RECORD_HASH_DOMAIN_V2 = 'peerit.recovery-record-content.v2'
const RECORD_ID_DOMAIN_V2 = 'peerit.recovery-record-id.v2'
const OPERATIONAL_BYTES_HASH_DOMAIN_V2 =
  'peerit.recovery-operational-bytes.v2'
const COLLISION_SET_HASH_DOMAIN_V1 = 'peerit.recovery-collision-set.v1'
const PROFILE_AUTHORITIES = new WeakMap()
const COLLISION_SETS = new WeakMap()

function fail (code, message) {
  failReleaseControl(code, message)
}

function wipe (input, seen = new Set()) {
  if (input == null || (typeof input !== 'object' && typeof input !== 'function') ||
      seen.has(input)) return
  seen.add(input)
  if (input instanceof Uint8Array) {
    try {
      input.fill(0)
    } catch {}
    return
  }
  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(input)
  )) {
    if (Object.hasOwn(descriptor, 'value')) wipe(descriptor.value, seen)
  }
}

function exactObject (input, fields, name, code = 'BAD_RECOVERY_PAYLOAD') {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype &&
       Object.getPrototypeOf(input) !== null)) {
    fail(code, `${name} must be a plain data object`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(input)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string') ||
      fields.some(field => !Object.hasOwn(descriptors, field))) {
    fail(code, `${name} fields are missing or unexpected`)
  }
  const output = Object.create(null)
  for (const field of fields) {
    const descriptor = descriptors[field]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(code, `${name}.${field} must be an enumerable data field`)
    }
    output[field] = descriptor.value
  }
  return output
}

function arrayValues (input, field, maximum, minimum = 0) {
  if (!Array.isArray(input) || input.length < minimum || input.length > maximum) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} count is invalid`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(input)
  const keys = Reflect.ownKeys(descriptors)
  const expected = new Set(['length'])
  for (let index = 0; index < input.length; index++) expected.add(String(index))
  if (keys.length !== expected.size ||
      keys.some(key => typeof key !== 'string' || !expected.has(key))) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} must be a dense data array`)
  }
  const output = []
  for (let index = 0; index < input.length; index++) {
    const descriptor = descriptors[index]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('BAD_RECOVERY_PAYLOAD', `${field}[${index}] must be a data element`)
    }
    output.push(descriptor.value)
  }
  return output
}

function fixed (input, length, field, nonzero = true) {
  const value = new Uint8Array(fixedBytesValue(input, length, field))
  if (nonzero && isAllZero(value)) {
    wipe(value)
    fail('BAD_RECOVERY_PAYLOAD', `${field} must be nonzero`)
  }
  return value
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail('BAD_RECOVERY_PAYLOAD', `${field} is outside u64`)
    }
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n ||
      value > ((1n << 64n) - 1n)) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} is outside u64`)
  }
  return value
}

function asU32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} is outside u32`)
  }
  return value
}

function boundedInteger (value, descriptor, field) {
  if (!Number.isSafeInteger(value) ||
      value < descriptor.minimum || value > descriptor.maximum) {
    fail('BAD_RECOVERY_RECORD', `${field} is outside its closed registry`)
  }
  return value
}

function canonicalField (value, descriptor, field) {
  switch (descriptor.kind) {
    case 'fixed32':
      return fixed(value, 32, field)
    case 'optional32':
      return value == null ? null : fixed(value, 32, field)
    case 'u8':
    case 'u16':
      return boundedInteger(value, descriptor, field)
    case 'u32':
      return asU32(value, field)
    case 'u64':
      return asU64(value, field)
    case 'bytesU16':
    case 'bytesU32': {
      const bytes = new Uint8Array(asBytes(value, field))
      if (bytes.byteLength < descriptor.minimum ||
          bytes.byteLength > descriptor.maximum) {
        wipe(bytes)
        fail('BAD_RECOVERY_RECORD', `${field} byte length is invalid`)
      }
      return bytes
    }
    default:
      fail('BAD_RECOVERY_RECORD', `${field} has an unknown field codec`)
  }
}

function writeField (writer, value, descriptor, field) {
  switch (descriptor.kind) {
    case 'fixed32':
      writer.fixed(value, 32, field)
      break
    case 'optional32':
      writer.optionalFixed(value, 32, field)
      break
    case 'u8':
      writer.u8(value, field)
      break
    case 'u16':
      writer.u16(value, field)
      break
    case 'u32':
      writer.u32(value, field)
      break
    case 'u64':
      writer.u64(value, field)
      break
    case 'bytesU16':
      writer.bytesU16(value, descriptor.minimum, descriptor.maximum, field)
      break
    case 'bytesU32':
      writer.u32(value.byteLength, `${field} length`)
      writer.fixed(value, value.byteLength, field)
      break
  }
}

function readField (reader, descriptor, field) {
  switch (descriptor.kind) {
    case 'fixed32':
      return reader.fixed(32, field)
    case 'optional32':
      return reader.optionalFixed(32, field)
    case 'u8':
      return reader.u8(field)
    case 'u16':
      return reader.u16(field)
    case 'u32':
      return reader.u32(field)
    case 'u64':
      return reader.u64(field)
    case 'bytesU16':
      return reader.bytesU16(descriptor.minimum, descriptor.maximum, field)
    case 'bytesU32': {
      const length = reader.u32(`${field} length`)
      if (length < descriptor.minimum || length > descriptor.maximum) {
        fail('BAD_RECOVERY_RECORD', `${field} byte length is invalid`)
      }
      return reader.fixed(length, field)
    }
    default:
      fail('BAD_RECOVERY_RECORD', `${field} has an unknown field codec`)
  }
}

function canonicalRecord (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('BAD_RECOVERY_RECORD', 'PeeritRecoveryRecordV2 must be a plain object')
  }
  const typeDescriptor = Object.getOwnPropertyDescriptor(input, 'type')
  if (!typeDescriptor || !Object.hasOwn(typeDescriptor, 'value') ||
      !Number.isSafeInteger(typeDescriptor.value) ||
      RECORD_FIELDS[typeDescriptor.value] == null) {
    fail('RECOVERY_RECORD_TYPE_FORBIDDEN',
      'recovery records admit only the closed read/management/state type registry')
  }
  const definition = RECORD_FIELDS[typeDescriptor.value]
  const fields = ['type', 'version', ...definition.fields.map(field => field.name)]
  const value = exactObject(
    input,
    fields,
    definition.name,
    'BAD_RECOVERY_RECORD'
  )
  if (value.version !== 2) {
    fail('BAD_RECOVERY_RECORD', `${definition.name} version must be 2`)
  }
  const output = { type: value.type, version: 2 }
  try {
    for (const descriptor of definition.fields) {
      output[descriptor.name] = canonicalField(
        value[descriptor.name],
        descriptor,
        `${definition.name}.${descriptor.name}`
      )
    }
    if (value.type === TYPES.CELL_MANAGEMENT_CAPABILITY) {
      const keys = [
        output.createPrivateKey,
        output.renewPrivateKey,
        output.dropPrivateKey
      ]
      for (let left = 0; left < keys.length; left++) {
        for (let right = left + 1; right < keys.length; right++) {
          if (bytesEqual(keys[left], keys[right])) {
            fail('BAD_RECOVERY_RECORD',
              'CELL management private keys must be pairwise distinct')
          }
        }
      }
    }
    const operationalPairs = {
      [TYPES.PENDING_CELL_INTENT]: [
        ['innerEnvelopeBytes', 'innerEnvelopeHash'],
        ['replicaBytes', 'replicaHash'],
        ['requestBytes', 'requestBytesHash']
      ],
      [TYPES.RECEIPT]: [
        ['resultBytes', 'resultBytesHash']
      ],
      [TYPES.DISCOVERY_FLOOR]: [
        ['recentBucketTupleBytes', 'recentBucketTupleHash']
      ],
      [TYPES.VERIFIED_INDEX_ROOT]: [
        ['rootRecordBytes', 'rootRecordBytesHash']
      ],
      [TYPES.AUTHENTICATED_CURSOR]: [
        ['authenticatedCursorBytes', 'authenticatedCursorBytesHash']
      ],
      [TYPES.REPAIR_BACKLOG]: [
        ['repairRequestBytes', 'repairRequestBytesHash']
      ]
    }[value.type] || []
    for (const [bytesField, hashField] of operationalPairs) {
      const expected = domainLengthHash(
        OPERATIONAL_BYTES_HASH_DOMAIN_V2,
        concatBytes(asciiBytes(bytesField), output[bytesField])
      )
      if (!bytesEqual(expected, output[hashField])) {
        wipe(expected)
        fail('RECOVERY_OPERATIONAL_BYTES_HASH_MISMATCH',
          `${definition.name}.${hashField} does not bind ${bytesField}`)
      }
      wipe(expected)
    }
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

function writeRecordPrefix (value) {
  const definition = RECORD_FIELDS[value.type]
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_RECOVERY_RECORD_MAGIC_V2,
    'PeeritRecoveryRecordV2 magic')
  writer.u8(value.type, 'PeeritRecoveryRecordV2 type')
  writer.u8(2, 'PeeritRecoveryRecordV2 version')
  for (const descriptor of definition.fields) {
    writeField(writer, value[descriptor.name], descriptor,
      `${definition.name}.${descriptor.name}`)
  }
  return writer.finish()
}

function writeRecord (value) {
  let prefix = null
  let recordHash = null
  let recordIdInput = null
  let recordId = null
  try {
    prefix = writeRecordPrefix(value)
    recordHash = domainLengthHash(RECORD_HASH_DOMAIN_V2, prefix)
    recordIdInput = concatBytes(
      Uint8Array.of(value.type, 2),
      recordHash
    )
    recordId = domainLengthHash(RECORD_ID_DOMAIN_V2, recordIdInput)
    const writer = new CanonicalWriter()
    writer.fixed(prefix, prefix.byteLength, 'PeeritRecoveryRecordV2 prefix')
    writer.fixed(recordHash, 32, 'recordHash')
    writer.fixed(recordId, 32, 'recordId')
    return writer.finish()
  } finally {
    wipe(prefix)
    wipe(recordHash)
    wipe(recordIdInput)
    wipe(recordId)
  }
}

export function encodePeeritRecoveryRecordV2 (input) {
  let value = null
  try {
    value = canonicalRecord(input)
    const output = writeRecord(value)
    if (output.byteLength > PEERIT_RECOVERY_LIMITS_V2.maximumRecordBytes) {
      wipe(output)
      fail('BAD_RECOVERY_RECORD', 'PeeritRecoveryRecordV2 exceeds its bound')
    }
    return output
  } finally {
    wipe(value)
  }
}

function freezeRecord (value, recordHash, recordId) {
  const definition = RECORD_FIELDS[value.type]
  const output = {
    type: value.type,
    typeName: definition.name,
    version: 2
  }
  for (const descriptor of definition.fields) {
    const field = value[descriptor.name]
    output[descriptor.name] = field instanceof Uint8Array
      ? new Uint8Array(field)
      : field
  }
  output.recordHash = new Uint8Array(recordHash)
  output.recordId = new Uint8Array(recordId)
  return Object.freeze(output)
}

export function decodePeeritRecoveryRecordV2 (input) {
  let bytes = null
  let raw = null
  let value = null
  let prefix = null
  let expectedHash = null
  let expectedIdInput = null
  let expectedId = null
  let canonicalBytes = null
  try {
    bytes = new Uint8Array(asBytes(input, 'PeeritRecoveryRecordV2 bytes'))
    if (bytes.byteLength < 74 ||
        bytes.byteLength > PEERIT_RECOVERY_LIMITS_V2.maximumRecordBytes) {
      fail('BAD_RECOVERY_RECORD', 'PeeritRecoveryRecordV2 size is invalid')
    }
    const reader = new CanonicalReader(bytes)
    reader.expectLiteralAscii(PEERIT_RECOVERY_RECORD_MAGIC_V2,
      'PeeritRecoveryRecordV2 magic')
    const type = reader.u8('PeeritRecoveryRecordV2 type')
    const version = reader.u8('PeeritRecoveryRecordV2 version')
    const definition = RECORD_FIELDS[type]
    if (definition == null) {
      fail('RECOVERY_RECORD_TYPE_FORBIDDEN',
        'unknown writer/admin/credential recovery record type is forbidden')
    }
    raw = { type, version }
    for (const descriptor of definition.fields) {
      raw[descriptor.name] = readField(
        reader,
        descriptor,
        `${definition.name}.${descriptor.name}`
      )
    }
    const recordHash = reader.fixed(32, 'recordHash')
    const recordId = reader.fixed(32, 'recordId')
    reader.expectEnd('PeeritRecoveryRecordV2')
    value = canonicalRecord(raw)
    prefix = writeRecordPrefix(value)
    expectedHash = domainLengthHash(RECORD_HASH_DOMAIN_V2, prefix)
    expectedIdInput = concatBytes(
      Uint8Array.of(type, 2),
      expectedHash
    )
    expectedId = domainLengthHash(RECORD_ID_DOMAIN_V2, expectedIdInput)
    if (!bytesEqual(recordHash, expectedHash)) {
      fail('RECOVERY_RECORD_HASH_MISMATCH',
        `${definition.name} content hash does not match its canonical fields`)
    }
    if (!bytesEqual(recordId, expectedId)) {
      fail('RECOVERY_RECORD_ID_MISMATCH',
        `${definition.name} ID does not bind its type and content hash`)
    }
    canonicalBytes = writeRecord(value)
    if (!bytesEqual(canonicalBytes, bytes)) {
      fail('NONCANONICAL_RECOVERY_RECORD',
        `${definition.name} bytes are not canonical`)
    }
    return freezeRecord(value, recordHash, recordId)
  } finally {
    wipe(bytes)
    wipe(raw)
    wipe(value)
    wipe(prefix)
    wipe(expectedHash)
    wipe(expectedIdInput)
    wipe(expectedId)
    wipe(canonicalBytes)
  }
}

function recordSortKey (record, sort) {
  if (sort === 'type+recordId') {
    return concatBytes(Uint8Array.of(record.type), record.recordId)
  }
  if (sort === 'floorKind+scopeId') {
    return concatBytes(Uint8Array.of(record.floorKind), record.scopeId)
  }
  return new Uint8Array(record.recordId)
}

function typedRecords (input, section) {
  const values = arrayValues(
    input,
    section.field,
    PEERIT_RECOVERY_LIMITS_V2.maximumRecordsPerSection
  )
  const output = []
  try {
    for (let index = 0; index < values.length; index++) {
      const bytes = new Uint8Array(asBytes(
        values[index],
        `${section.field}[${index}]`
      ))
      if (bytes.byteLength < 1 ||
          bytes.byteLength > PEERIT_RECOVERY_LIMITS_V2.maximumRecordBytes) {
        wipe(bytes)
        fail('BAD_RECOVERY_PAYLOAD',
          `${section.field}[${index}] byte length is invalid`)
      }
      let record = null
      try {
        record = decodePeeritRecoveryRecordV2(bytes)
        if (!section.allowedTypes.includes(record.type)) {
          fail('RECOVERY_RECORD_TYPE_CONFUSION',
            `${record.typeName} cannot appear in ${section.field}`)
        }
        output.push({
          bytes,
          sortKey: recordSortKey(record, section.sort)
        })
      } finally {
        wipe(record)
      }
    }
    for (let index = 1; index < output.length; index++) {
      if (compareBytes(output[index - 1].sortKey, output[index].sortKey) >= 0) {
        fail('NONCANONICAL_RECOVERY_PAYLOAD',
          `${section.field} must be strictly sorted and unique`)
      }
    }
    const result = output.map(row => row.bytes)
    for (const row of output) wipe(row.sortKey)
    return result
  } catch (error) {
    wipe(output)
    throw error
  }
}

function identifiers (input, field, minimum = 0) {
  const values = arrayValues(
    input,
    field,
    PEERIT_RECOVERY_LIMITS_V2.maximumRecordsPerSection,
    minimum
  )
  const output = []
  try {
    for (let index = 0; index < values.length; index++) {
      output.push(fixed(values[index], 32, `${field}[${index}]`))
    }
    for (let index = 1; index < output.length; index++) {
      if (compareBytes(output[index - 1], output[index]) >= 0) {
        fail('NONCANONICAL_RECOVERY_PAYLOAD',
          `${field} must be strictly sorted and unique`)
      }
    }
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

function canonicalPayload (input) {
  const value = exactObject(input, PAYLOAD_FIELDS_V2, 'PeeritRecoveryPayloadV2')
  if (value.version !== 2) {
    fail('BAD_RECOVERY_PAYLOAD', 'PeeritRecoveryPayloadV2 version must be 2')
  }
  const output = { version: 2 }
  try {
    output.accountSeed = fixed(value.accountSeed, 32, 'accountSeed')
    output.pinHistoryRecord = new Uint8Array(asBytes(
      value.pinHistoryRecord,
      'pinHistoryRecord'
    ))
    if (output.pinHistoryRecord.byteLength < 1 ||
        output.pinHistoryRecord.byteLength >
          PEERIT_RECOVERY_LIMITS_V2.maximumCiphertextBytes) {
      fail('BAD_RECOVERY_PAYLOAD', 'pinHistoryRecord size is invalid')
    }
    for (const section of PAYLOAD_SECTIONS_V2) {
      output[section.field] = typedRecords(value[section.field], section)
    }
    output.publishedLogicalIds = identifiers(
      value.publishedLogicalIds,
      'publishedLogicalIds'
    )
    output.retiredDeviceChainIds = identifiers(
      value.retiredDeviceChainIds,
      'retiredDeviceChainIds'
    )
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

function writeRecordSection (writer, values, field) {
  writer.u16(values.length, `${field} count`)
  for (const bytes of values) {
    writer.u32(bytes.byteLength, `${field} record length`)
    writer.fixed(bytes, bytes.byteLength, `${field} record`)
  }
}

function writeIdentifiers (writer, values, field) {
  writer.u16(values.length, `${field} count`)
  for (const value of values) writer.fixed(value, 32, field)
}

function writePayload (value) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_RECOVERY_PAYLOAD_MAGIC_V2,
    'PeeritRecoveryPayloadV2 magic')
  writer.u8(2, 'PeeritRecoveryPayloadV2 version')
  writer.fixed(value.accountSeed, 32, 'accountSeed')
  writer.u32(value.pinHistoryRecord.byteLength, 'pinHistoryRecord length')
  writer.fixed(value.pinHistoryRecord, value.pinHistoryRecord.byteLength,
    'pinHistoryRecord')
  writeRecordSection(writer, value.capabilityRecords, 'capabilityRecords')
  writeRecordSection(writer, value.pendingCellIntentRecords,
    'pendingCellIntentRecords')
  writeIdentifiers(writer, value.publishedLogicalIds, 'publishedLogicalId')
  writeRecordSection(writer, value.receiptRecords, 'receiptRecords')
  writeRecordSection(writer, value.witnessedFloorRecords,
    'witnessedFloorRecords')
  writeRecordSection(writer, value.discoveryFloorRecords,
    'discoveryFloorRecords')
  writeRecordSection(writer, value.verifiedIndexRootRecords,
    'verifiedIndexRootRecords')
  writeRecordSection(writer, value.authenticatedCursorRecords,
    'authenticatedCursorRecords')
  writeRecordSection(writer, value.repairBacklogRecords,
    'repairBacklogRecords')
  writeIdentifiers(writer, value.retiredDeviceChainIds, 'retiredDeviceChainId')
  const output = writer.finish()
  if (output.byteLength < 1 ||
      output.byteLength > PEERIT_RECOVERY_LIMITS_V2.maximumCiphertextBytes) {
    wipe(output)
    fail('BAD_RECOVERY_PAYLOAD',
      'PeeritRecoveryPayloadV2 exceeds the ciphertext bound')
  }
  return output
}

export function encodePeeritRecoveryPayloadV2 (input) {
  let value = null
  try {
    value = canonicalPayload(input)
    return writePayload(value)
  } finally {
    wipe(value)
  }
}

function readRecordSection (reader, field) {
  const count = reader.u16(`${field} count`)
  if (count > PEERIT_RECOVERY_LIMITS_V2.maximumRecordsPerSection) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} count is invalid`)
  }
  const output = []
  try {
    for (let index = 0; index < count; index++) {
      const length = reader.u32(`${field}[${index}] record length`)
      if (length < 1 ||
          length > PEERIT_RECOVERY_LIMITS_V2.maximumRecordBytes) {
        fail('BAD_RECOVERY_PAYLOAD',
          `${field}[${index}] record length is invalid`)
      }
      output.push(reader.fixed(length, `${field}[${index}] record`))
    }
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

function readIdentifiers (reader, field) {
  const count = reader.u16(`${field} count`)
  if (count > PEERIT_RECOVERY_LIMITS_V2.maximumRecordsPerSection) {
    fail('BAD_RECOVERY_PAYLOAD', `${field} count is invalid`)
  }
  const output = []
  try {
    for (let index = 0; index < count; index++) {
      output.push(reader.fixed(32, `${field}[${index}]`))
    }
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

function freezePayload (value) {
  const output = {
    version: 2,
    accountSeed: new Uint8Array(value.accountSeed),
    pinHistoryRecord: new Uint8Array(value.pinHistoryRecord)
  }
  for (const section of PAYLOAD_SECTIONS_V2) {
    output[section.field] = Object.freeze(
      value[section.field].map(bytes => new Uint8Array(bytes))
    )
  }
  output.publishedLogicalIds = Object.freeze(
    value.publishedLogicalIds.map(id => new Uint8Array(id))
  )
  output.retiredDeviceChainIds = Object.freeze(
    value.retiredDeviceChainIds.map(id => new Uint8Array(id))
  )
  return Object.freeze(output)
}

export function decodePeeritRecoveryPayloadV2 (input) {
  let bytes = null
  let raw = null
  let value = null
  let canonicalBytes = null
  try {
    bytes = new Uint8Array(asBytes(input, 'PeeritRecoveryPayloadV2 bytes'))
    if (bytes.byteLength < 1 ||
        bytes.byteLength > PEERIT_RECOVERY_LIMITS_V2.maximumCiphertextBytes) {
      fail('BAD_RECOVERY_PAYLOAD', 'PeeritRecoveryPayloadV2 size is invalid')
    }
    const reader = new CanonicalReader(bytes)
    reader.expectLiteralAscii(PEERIT_RECOVERY_PAYLOAD_MAGIC_V2,
      'PeeritRecoveryPayloadV2 magic')
    raw = {
      version: reader.u8('PeeritRecoveryPayloadV2 version'),
      accountSeed: reader.fixed(32, 'accountSeed')
    }
    const pinHistoryLength = reader.u32('pinHistoryRecord length')
    if (pinHistoryLength < 1 ||
        pinHistoryLength >
          PEERIT_RECOVERY_LIMITS_V2.maximumCiphertextBytes) {
      fail('BAD_RECOVERY_PAYLOAD', 'pinHistoryRecord length is invalid')
    }
    raw.pinHistoryRecord = reader.fixed(pinHistoryLength, 'pinHistoryRecord')
    raw.capabilityRecords = readRecordSection(reader, 'capabilityRecords')
    raw.pendingCellIntentRecords = readRecordSection(
      reader,
      'pendingCellIntentRecords'
    )
    raw.publishedLogicalIds = readIdentifiers(reader, 'publishedLogicalIds')
    raw.receiptRecords = readRecordSection(reader, 'receiptRecords')
    raw.witnessedFloorRecords = readRecordSection(
      reader,
      'witnessedFloorRecords'
    )
    raw.discoveryFloorRecords = readRecordSection(
      reader,
      'discoveryFloorRecords'
    )
    raw.verifiedIndexRootRecords = readRecordSection(
      reader,
      'verifiedIndexRootRecords'
    )
    raw.authenticatedCursorRecords = readRecordSection(
      reader,
      'authenticatedCursorRecords'
    )
    raw.repairBacklogRecords = readRecordSection(
      reader,
      'repairBacklogRecords'
    )
    raw.retiredDeviceChainIds = readIdentifiers(reader, 'retiredDeviceChainIds')
    reader.expectEnd('PeeritRecoveryPayloadV2')
    value = canonicalPayload(raw)
    canonicalBytes = writePayload(value)
    if (!bytesEqual(canonicalBytes, bytes)) {
      fail('NONCANONICAL_RECOVERY_PAYLOAD',
        'PeeritRecoveryPayloadV2 is noncanonical')
    }
    return freezePayload(value)
  } finally {
    wipe(bytes)
    wipe(raw)
    wipe(value)
    wipe(canonicalBytes)
  }
}

export function zeroizePeeritRecoveryPayloadV2 (payload) {
  wipe(payload)
}

function canonicalBundle (input) {
  const value = exactObject(
    input,
    BUNDLE_FIELDS,
    'PeeritRecoveryBundleV1',
    'BAD_RECOVERY_BUNDLE'
  )
  const kdf = PEERIT_RECOVERY_KDF_V1
  if (value.magic !== PEERIT_RECOVERY_BUNDLE_MAGIC_V1 ||
      value.version !== 1 || value.kdfId !== kdf.id ||
      value.memoryKiB !== kdf.memoryKiB ||
      value.iterations !== kdf.iterations ||
      value.parallelism !== kdf.parallelism) {
    fail('BAD_RECOVERY_BUNDLE_PARAMETERS',
      'PeeritRecoveryBundleV1 has an unregistered parameter set')
  }
  const ciphertextLength = asU64(value.ciphertextLength, 'ciphertextLength')
  if (ciphertextLength < 1n ||
      ciphertextLength >
        BigInt(PEERIT_RECOVERY_LIMITS_V2.maximumCiphertextBytes)) {
    fail('BAD_RECOVERY_BUNDLE',
      'ciphertextLength is outside the registered bound')
  }
  const sealed = new Uint8Array(asBytes(value.sealed, 'sealed'))
  if (BigInt(sealed.byteLength) !==
      ciphertextLength + BigInt(kdf.tagBytes)) {
    wipe(sealed)
    fail('BAD_RECOVERY_BUNDLE',
      'sealed length does not equal ciphertextLength plus tag')
  }
  const output = {
    magic: PEERIT_RECOVERY_BUNDLE_MAGIC_V1,
    version: 1,
    kdfId: kdf.id,
    memoryKiB: kdf.memoryKiB,
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
    salt: null,
    accountPublicKey: null,
    ciphertextLength,
    nonce: null,
    sealed
  }
  try {
    output.salt = fixed(value.salt, kdf.saltBytes, 'salt')
    output.accountPublicKey = fixed(value.accountPublicKey, 32,
      'accountPublicKey')
    output.nonce = fixed(value.nonce, kdf.nonceBytes, 'nonce')
    return output
  } catch (error) {
    wipe(output)
    throw error
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
  let value = null
  try {
    value = canonicalBundle(input)
    return writeBundle(value)
  } finally {
    wipe(value)
  }
}

export function decodePeeritRecoveryBundleV1 (input) {
  let bytes = null
  let raw = null
  let value = null
  try {
    bytes = new Uint8Array(asBytes(input, 'PeeritRecoveryBundleV1 bytes'))
    const maximum = 75 + PEERIT_RECOVERY_KDF_V1.nonceBytes +
      PEERIT_RECOVERY_LIMITS_V2.maximumCiphertextBytes +
      PEERIT_RECOVERY_KDF_V1.tagBytes
    if (bytes.byteLength < 75 + PEERIT_RECOVERY_KDF_V1.nonceBytes + 17 ||
        bytes.byteLength > maximum) {
      fail('BAD_RECOVERY_BUNDLE', 'PeeritRecoveryBundleV1 size is invalid')
    }
    const reader = new CanonicalReader(bytes)
    raw = {
      magic: reader.expectLiteralAscii(PEERIT_RECOVERY_BUNDLE_MAGIC_V1,
        'PeeritRecoveryBundleV1 magic'),
      version: reader.u8('version'),
      kdfId: reader.u8('kdfId'),
      memoryKiB: reader.u32('memoryKiB'),
      iterations: reader.u32('iterations'),
      parallelism: reader.u8('parallelism'),
      salt: reader.fixed(16, 'salt'),
      accountPublicKey: reader.fixed(32, 'accountPublicKey'),
      ciphertextLength: reader.u64('ciphertextLength')
    }
    raw.nonce = reader.fixed(24, 'nonce')
    if (raw.ciphertextLength < 1n ||
        raw.ciphertextLength >
          BigInt(PEERIT_RECOVERY_LIMITS_V2.maximumCiphertextBytes)) {
      fail('BAD_RECOVERY_BUNDLE', 'ciphertextLength is invalid')
    }
    raw.sealed = reader.fixed(Number(raw.ciphertextLength) + 16, 'sealed')
    reader.expectEnd('PeeritRecoveryBundleV1')
    value = canonicalBundle(raw)
    if (!bytesEqual(writeBundle(value), bytes)) {
      fail('BAD_RECOVERY_BUNDLE', 'PeeritRecoveryBundleV1 is noncanonical')
    }
    return Object.freeze({
      ...value,
      salt: new Uint8Array(value.salt),
      accountPublicKey: new Uint8Array(value.accountPublicKey),
      nonce: new Uint8Array(value.nonce),
      sealed: new Uint8Array(value.sealed)
    })
  } finally {
    wipe(bytes)
    wipe(raw)
    wipe(value)
  }
}

function validUnicodeScalarString (value) {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return false
      const next = value.charCodeAt(++index)
      if (next < 0xdc00 || next > 0xdfff) return false
    } else if (code >= 0xdc00 && code <= 0xdfff) return false
  }
  return true
}

export function peeritRecoveryPassphraseBytesV1 (input) {
  if (typeof input !== 'string' || input.length < 1 ||
      !validUnicodeScalarString(input) ||
      input !== input.normalize('NFC')) {
    fail('BAD_RECOVERY_PASSPHRASE',
      'recovery passphrase must be a nonempty NFC Unicode scalar string')
  }
  const bytes = new TextEncoder().encode(input)
  if (bytes.byteLength < 1 ||
      bytes.byteLength > PEERIT_RECOVERY_LIMITS_V2.maximumPassphraseBytes) {
    wipe(bytes)
    fail('BAD_RECOVERY_PASSPHRASE',
      'recovery passphrase UTF-8 length is invalid')
  }
  return bytes
}

function cryptoRuntime (input) {
  if (!input ||
      input.recoveryAlgorithm !== PEERIT_RECOVERY_CRYPTO_SUITE_V1 ||
      typeof input.randomBytes !== 'function' ||
      typeof input.deriveArgon2id !== 'function' ||
      typeof input.encryptXChaCha20Poly1305Ietf !== 'function' ||
      typeof input.decryptXChaCha20Poly1305Ietf !== 'function' ||
      typeof input.deriveEd25519PublicKey !== 'function' ||
      typeof input.signEd25519 !== 'function' ||
      typeof input.verifyEd25519 !== 'function') {
    fail('RECOVERY_CRYPTO_UNAVAILABLE',
      'the exact signed Argon2id/XChaCha/Ed25519 recovery provider is required')
  }
  return input
}

function visibleProviderBytes (value) {
  try {
    if (value instanceof Uint8Array) return value
    if (value instanceof ArrayBuffer) return new Uint8Array(value)
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    }
  } catch {}
  return null
}

function ownedProviderBytes (value, length, field, borrowed = []) {
  const visible = visibleProviderBytes(value)
  const exact = value instanceof Uint8Array &&
    Object.getPrototypeOf(value) === Uint8Array.prototype &&
    value.buffer instanceof ArrayBuffer &&
    value.byteOffset === 0 &&
    value.byteLength === value.buffer.byteLength &&
    value.byteLength === length
  const aliases = exact && borrowed.some(input =>
    input instanceof Uint8Array && input.buffer === value.buffer)
  if (!exact || aliases) {
    wipe(visible)
    fail('RECOVERY_CRYPTO_PROVIDER_ABI_VIOLATION',
      `${field} must transfer a fresh unaliased whole-buffer Uint8Array(${length})`)
  }
  return value
}

async function random (runtime, length, field) {
  let output = null
  try {
    output = ownedProviderBytes(
      await runtime.randomBytes(length),
      length,
      field
    )
    if (isAllZero(output)) {
      fail('RECOVERY_RANDOMNESS_FAILURE', `${field} randomness is all zero`)
    }
    const transferred = output
    output = null
    return transferred
  } finally {
    wipe(output)
  }
}

async function deriveKey (runtime, passphrase, salt) {
  let passphraseBytes = null
  let providerPassphrase = null
  let providerSalt = null
  let output = null
  try {
    passphraseBytes = peeritRecoveryPassphraseBytesV1(passphrase)
    providerPassphrase = new Uint8Array(passphraseBytes)
    providerSalt = new Uint8Array(salt)
    output = ownedProviderBytes(
      await runtime.deriveArgon2id({
        version: PEERIT_RECOVERY_KDF_V1.version,
        passphrase: providerPassphrase,
        salt: providerSalt,
        memoryKiB: PEERIT_RECOVERY_KDF_V1.memoryKiB,
        iterations: PEERIT_RECOVERY_KDF_V1.iterations,
        parallelism: PEERIT_RECOVERY_KDF_V1.parallelism,
        outputBytes: PEERIT_RECOVERY_KDF_V1.keyBytes
      }),
      PEERIT_RECOVERY_KDF_V1.keyBytes,
      'Argon2id key',
      [providerPassphrase, providerSalt]
    )
    const transferred = output
    output = null
    return transferred
  } finally {
    wipe(passphraseBytes)
    wipe(providerPassphrase)
    wipe(providerSalt)
    wipe(output)
  }
}

async function derivePublicKey (runtime, seed, field) {
  let providerSeed = null
  let output = null
  try {
    providerSeed = new Uint8Array(seed)
    output = ownedProviderBytes(
      await runtime.deriveEd25519PublicKey(providerSeed),
      32,
      field,
      [providerSeed]
    )
    if (isAllZero(output)) {
      fail('RECOVERY_ACCOUNT_IDENTITY_MISMATCH',
        `${field} provider output is all zero`)
    }
    const transferred = output
    output = null
    return transferred
  } finally {
    wipe(providerSeed)
    wipe(output)
  }
}

async function signWithSeed (runtime, seed, message) {
  let providerSeed = null
  let providerMessage = null
  let output = null
  try {
    providerSeed = new Uint8Array(seed)
    providerMessage = new Uint8Array(message)
    output = ownedProviderBytes(
      await runtime.signEd25519(providerSeed, providerMessage),
      64,
      'Ed25519 signature',
      [providerSeed, providerMessage]
    )
    const transferred = output
    output = null
    return transferred
  } finally {
    wipe(providerSeed)
    wipe(providerMessage)
    wipe(output)
  }
}

async function verifySignature (runtime, publicKey, message, signature) {
  let providerKey = null
  let providerMessage = null
  let providerSignature = null
  try {
    providerKey = new Uint8Array(publicKey)
    providerMessage = new Uint8Array(message)
    providerSignature = new Uint8Array(signature)
    if (await runtime.verifyEd25519(
      providerKey,
      providerMessage,
      providerSignature
    ) !== true) {
      fail('RECOVERY_DEVICE_CHAIN_START_INVALID',
        'DeviceChainStartV1 signature did not verify')
    }
  } finally {
    wipe(providerKey)
    wipe(providerMessage)
    wipe(providerSignature)
  }
}

async function encryptPayload (runtime, key, nonce, plaintext, aad) {
  let providerKey = null
  let providerNonce = null
  let providerPlaintext = null
  let providerAad = null
  let output = null
  try {
    providerKey = new Uint8Array(key)
    providerNonce = new Uint8Array(nonce)
    providerPlaintext = new Uint8Array(plaintext)
    providerAad = new Uint8Array(aad)
    output = ownedProviderBytes(
      await runtime.encryptXChaCha20Poly1305Ietf({
        key: providerKey,
        nonce: providerNonce,
        plaintext: providerPlaintext,
        aad: providerAad
      }),
      plaintext.byteLength + PEERIT_RECOVERY_KDF_V1.tagBytes,
      'XChaCha20-Poly1305 sealed bytes',
      [providerKey, providerNonce, providerPlaintext, providerAad]
    )
    const transferred = output
    output = null
    return transferred
  } finally {
    wipe(providerKey)
    wipe(providerNonce)
    wipe(providerPlaintext)
    wipe(providerAad)
    wipe(output)
  }
}

async function decryptPayload (bundle, passphrase, runtime) {
  let key = null
  let providerKey = null
  let providerNonce = null
  let providerSealed = null
  let providerAad = null
  let plaintext = null
  try {
    key = await deriveKey(runtime, passphrase, bundle.salt)
    providerKey = new Uint8Array(key)
    providerNonce = new Uint8Array(bundle.nonce)
    providerSealed = new Uint8Array(bundle.sealed)
    providerAad = writeHeader(bundle)
    try {
      plaintext = ownedProviderBytes(
        await runtime.decryptXChaCha20Poly1305Ietf({
          key: providerKey,
          nonce: providerNonce,
          sealed: providerSealed,
          aad: providerAad
        }),
        Number(bundle.ciphertextLength),
        'XChaCha20-Poly1305 plaintext',
        [providerKey, providerNonce, providerSealed, providerAad]
      )
    } catch (cause) {
      if (cause?.code === 'RECOVERY_CRYPTO_PROVIDER_ABI_VIOLATION') throw cause
      const error = new Error('recovery bundle authentication failed')
      error.code = 'RECOVERY_AUTHENTICATION_FAILED'
      error.cause = cause
      throw error
    }
    const transferred = plaintext
    plaintext = null
    return transferred
  } finally {
    wipe(key)
    wipe(providerKey)
    wipe(providerNonce)
    wipe(providerSealed)
    wipe(providerAad)
    wipe(plaintext)
  }
}

async function assertAccountPublicKey (payload, expected, runtime) {
  let derived = null
  try {
    derived = await derivePublicKey(
      runtime,
      payload.accountSeed,
      'account public key'
    )
    if (!bytesEqual(derived, expected)) {
      fail('RECOVERY_ACCOUNT_IDENTITY_MISMATCH',
        'recovered account seed does not reproduce the bundle public key')
    }
  } finally {
    wipe(derived)
  }
}

function asExpectedHash (input, expectedHex, field) {
  const value = fixed(input, 32, field)
  if (!bytesEqual(value, hexToBytes(expectedHex, 32, `${field} expected`))) {
    wipe(value)
    fail('RECOVERY_PROFILE_AUTHORITY_MISMATCH',
      `${field} does not match the pinned recovery profile authority`)
  }
  return value
}

function profileBindingSnapshot (input) {
  const value = exactObject(
    input,
    [
      'profileId',
      'profileSpecHash',
      'inventoryCommitment',
      'schemaCount',
      'capabilities'
    ],
    'recovery profile binding',
    'RECOVERY_PROFILE_AUTHORITY_MISMATCH'
  )
  if (value.profileId !== PEERIT_RECOVERY_PROFILE_BINDING_V2.profileId ||
      value.schemaCount !== PEERIT_RECOVERY_PROFILE_BINDING_V2.schemaCount) {
    fail('RECOVERY_PROFILE_AUTHORITY_MISMATCH',
      'recovery profile identity or schema count is not pinned')
  }
  const capabilities = value.capabilities
  if (!capabilities || capabilities.strictCanonicalEncodeDecode !== true ||
      capabilities.boundedDecodeBeforeAllocation !== true ||
      capabilities.localCrossFieldValidation !== true ||
      capabilities.embeddedEd25519Verification !== true ||
      capabilities.externalCodecAuthorityRequired !== true) {
    fail('RECOVERY_PROFILE_AUTHORITY_MISMATCH',
      'recovery profile validator capabilities are incomplete')
  }
  return {
    profileSpecHash: asExpectedHash(
      value.profileSpecHash,
      PEERIT_RECOVERY_PROFILE_BINDING_V2.profileSpecHash,
      'profileSpecHash'
    ),
    inventoryCommitment: asExpectedHash(
      value.inventoryCommitment,
      PEERIT_RECOVERY_PROFILE_BINDING_V2.inventoryCommitment,
      'inventoryCommitment'
    )
  }
}

export function createPeeritRecoveryProfileAuthorityV2 (input) {
  const value = exactObject(
    input,
    [
      'profileBinding',
      'validatorArtifactHash',
      'validatorVectorSetHash',
      'validator'
    ],
    'PeeritRecoveryProfileAuthorityV2',
    'RECOVERY_PROFILE_AUTHORITY_MISMATCH'
  )
  let binding = null
  let artifactHash = null
  let vectorHash = null
  let absentBytes = null
  let presentBytes = null
  try {
    binding = profileBindingSnapshot(value.profileBinding)
    artifactHash = asExpectedHash(
      value.validatorArtifactHash,
      PEERIT_RECOVERY_PROFILE_BINDING_V2.validatorArtifactHash,
      'validatorArtifactHash'
    )
    vectorHash = asExpectedHash(
      value.validatorVectorSetHash,
      PEERIT_RECOVERY_PROFILE_BINDING_V2.validatorVectorSetHash,
      'validatorVectorSetHash'
    )
    if (!value.validator || typeof value.validator !== 'object' ||
        typeof value.validator.validate !== 'function' ||
        !value.validator.catalog ||
        typeof value.validator.catalog !== 'object') {
      fail('RECOVERY_PROFILE_AUTHORITY_MISMATCH',
        'exact authenticated profile validator is required')
    }
    const codec = value.validator.catalog.DeviceChainStartV1
    if (!codec ||
        codec.tag !== PEERIT_RECOVERY_PROFILE_BINDING_V2.deviceChainStartTag ||
        codec.maximumCompleteBytes !==
          BigInt(PEERIT_RECOVERY_PROFILE_BINDING_V2.deviceChainStartMaximumBytes) ||
        typeof codec.encode !== 'function' ||
        typeof codec.decode !== 'function') {
      fail('RECOVERY_PROFILE_AUTHORITY_MISMATCH',
        'DeviceChainStartV1 codec identity is not exact')
    }
    const fixedValue = present => ({
      version: 1,
      accountPublicKey: new Uint8Array(32).fill(1),
      deviceChainId: new Uint8Array(32).fill(2),
      newTransportCorePublicKey: new Uint8Array(32).fill(3),
      previousAuthorSequence: present ? 1n : 0n,
      previousAuthorRecordId: present ? new Uint8Array(32).fill(4) : null,
      createdLeaseEpoch: 1,
      signature: new Uint8Array(64).fill(5)
    })
    absentBytes = codec.encode(fixedValue(false))
    presentBytes = codec.encode(fixedValue(true))
    if (absentBytes.byteLength !== 176 || presentBytes.byteLength !== 208 ||
        !bytesEqual(codec.encode(codec.decode(absentBytes)), absentBytes) ||
        !bytesEqual(codec.encode(codec.decode(presentBytes)), presentBytes)) {
      fail('RECOVERY_PROFILE_AUTHORITY_MISMATCH',
        'DeviceChainStartV1 structural self-test failed')
    }
    let trailingRejected = false
    try {
      codec.decode(concatBytes(absentBytes, Uint8Array.of(0)))
    } catch {
      trailingRejected = true
    }
    if (!trailingRejected) {
      fail('RECOVERY_PROFILE_AUTHORITY_MISMATCH',
        'DeviceChainStartV1 codec accepted trailing bytes')
    }
    const authority = Object.freeze({
      version: 2,
      profileId: PEERIT_RECOVERY_PROFILE_BINDING_V2.profileId,
      profileSpecHash: new Uint8Array(binding.profileSpecHash),
      inventoryCommitment: new Uint8Array(binding.inventoryCommitment),
      validatorArtifactHash: new Uint8Array(artifactHash),
      validatorVectorSetHash: new Uint8Array(vectorHash),
      deviceChainStartTag:
        PEERIT_RECOVERY_PROFILE_BINDING_V2.deviceChainStartTag
    })
    PROFILE_AUTHORITIES.set(authority, Object.freeze({
      encode: codec.encode.bind(codec),
      decode: codec.decode.bind(codec),
      validate: value.validator.validate.bind(value.validator)
    }))
    return authority
  } finally {
    wipe(binding)
    wipe(artifactHash)
    wipe(vectorHash)
    wipe(absentBytes)
    wipe(presentBytes)
  }
}

function requireProfileAuthority (input) {
  const value = PROFILE_AUTHORITIES.get(input)
  if (value == null) {
    fail('RECOVERY_PROFILE_AUTHORITY_REQUIRED',
      'a module-branded exact recovery profile authority is required')
  }
  return value
}

function floors (input, field, minimum = 0) {
  const values = arrayValues(
    input,
    field,
    PEERIT_RECOVERY_LIMITS_V2.maximumRecordsPerSection,
    minimum
  )
  const output = []
  try {
    for (let index = 0; index < values.length; index++) {
      const value = exactObject(
        values[index],
        ['kind', 'scopeId', 'sequence', 'hash'],
        `${field}[${index}]`
      )
      if (!Number.isSafeInteger(value.kind) ||
          value.kind < 1 || value.kind > 6) {
        fail('BAD_RECOVERY_PAYLOAD',
          `${field}[${index}].kind is invalid`)
      }
      output.push({
        kind: value.kind,
        scopeId: fixed(value.scopeId, 32, `${field}[${index}].scopeId`),
        sequence: asU64(value.sequence, `${field}[${index}].sequence`),
        hash: fixed(value.hash, 32, `${field}[${index}].hash`)
      })
    }
    for (let index = 1; index < output.length; index++) {
      const left = concatBytes(
        Uint8Array.of(output[index - 1].kind),
        output[index - 1].scopeId
      )
      const right = concatBytes(
        Uint8Array.of(output[index].kind),
        output[index].scopeId
      )
      const order = compareBytes(left, right)
      wipe(left)
      wipe(right)
      if (order >= 0) {
        fail('NONCANONICAL_RECOVERY_PAYLOAD',
          `${field} must be strictly sorted and unique`)
      }
    }
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

function containsId (values, candidate) {
  return values.some(value => bytesEqual(value, candidate))
}

function rejectOverlap (left, right, field) {
  for (const value of left) {
    if (containsId(right, value)) {
      fail('BAD_RECOVERY_COLLISION_SET',
        `${field} active and retired sets overlap`)
    }
  }
}

function canonicalCollisionSet (input) {
  const value = exactObject(
    input,
    COLLISION_SET_INPUT_FIELDS,
    'PeeritRecoveryCollisionSetV1',
    'BAD_RECOVERY_COLLISION_SET'
  )
  if (value.version !== 1 || value.complete !== true) {
    fail('BAD_RECOVERY_COLLISION_SET',
      'collision set must explicitly declare complete version 1 state')
  }
  const output = { version: 1, complete: true }
  try {
    output.activeTransportPublicKeys = identifiers(
      value.activeTransportPublicKeys,
      'activeTransportPublicKeys',
      1
    )
    output.retiredTransportPublicKeys = identifiers(
      value.retiredTransportPublicKeys,
      'retiredTransportPublicKeys'
    )
    output.activeDeviceChainIds = identifiers(
      value.activeDeviceChainIds,
      'activeDeviceChainIds',
      1
    )
    output.retiredDeviceChainIds = identifiers(
      value.retiredDeviceChainIds,
      'retiredDeviceChainIds'
    )
    output.localWitnessedFloors = floors(
      value.localWitnessedFloors,
      'localWitnessedFloors'
    )
    output.previousAuthorSequence = asU64(
      value.previousAuthorSequence,
      'previousAuthorSequence'
    )
    output.previousAuthorRecordId = value.previousAuthorRecordId == null
      ? null
      : fixed(value.previousAuthorRecordId, 32, 'previousAuthorRecordId')
    if ((output.previousAuthorSequence === 0n) !==
        (output.previousAuthorRecordId == null)) {
      fail('BAD_RECOVERY_COLLISION_SET',
        'author predecessor is absent exactly at sequence zero')
    }
    output.createdLeaseEpoch = asU32(
      value.createdLeaseEpoch,
      'createdLeaseEpoch'
    )
    rejectOverlap(output.activeTransportPublicKeys,
      output.retiredTransportPublicKeys, 'transport public key')
    rejectOverlap(output.activeDeviceChainIds,
      output.retiredDeviceChainIds, 'device chain ID')
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

function cloneFloors (values) {
  return values.map(value => ({
    kind: value.kind,
    scopeId: new Uint8Array(value.scopeId),
    sequence: value.sequence,
    hash: new Uint8Array(value.hash)
  }))
}

function cloneCollisionSet (value) {
  return {
    version: 1,
    complete: true,
    activeTransportPublicKeys: value.activeTransportPublicKeys.map(
      key => new Uint8Array(key)
    ),
    retiredTransportPublicKeys: value.retiredTransportPublicKeys.map(
      key => new Uint8Array(key)
    ),
    activeDeviceChainIds: value.activeDeviceChainIds.map(
      id => new Uint8Array(id)
    ),
    retiredDeviceChainIds: value.retiredDeviceChainIds.map(
      id => new Uint8Array(id)
    ),
    localWitnessedFloors: cloneFloors(value.localWitnessedFloors),
    previousAuthorSequence: value.previousAuthorSequence,
    previousAuthorRecordId: value.previousAuthorRecordId == null
      ? null
      : new Uint8Array(value.previousAuthorRecordId),
    createdLeaseEpoch: value.createdLeaseEpoch
  }
}

function writeCollisionSet (value) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_RECOVERY_COLLISION_SET_MAGIC_V1,
    'PeeritRecoveryCollisionSetV1 magic')
  writer.u8(1, 'PeeritRecoveryCollisionSetV1 version')
  writer.u8(1, 'PeeritRecoveryCollisionSetV1 complete')
  writeIdentifiers(writer, value.activeTransportPublicKeys,
    'activeTransportPublicKey')
  writeIdentifiers(writer, value.retiredTransportPublicKeys,
    'retiredTransportPublicKey')
  writeIdentifiers(writer, value.activeDeviceChainIds, 'activeDeviceChainId')
  writeIdentifiers(writer, value.retiredDeviceChainIds, 'retiredDeviceChainId')
  writer.u16(value.localWitnessedFloors.length, 'localWitnessedFloors count')
  for (const floor of value.localWitnessedFloors) {
    writer.u8(floor.kind, 'local witnessed floor kind')
    writer.fixed(floor.scopeId, 32, 'local witnessed floor scopeId')
    writer.u64(floor.sequence, 'local witnessed floor sequence')
    writer.fixed(floor.hash, 32, 'local witnessed floor hash')
  }
  writer.u64(value.previousAuthorSequence, 'previousAuthorSequence')
  writer.optionalFixed(value.previousAuthorRecordId, 32,
    'previousAuthorRecordId')
  writer.u32(value.createdLeaseEpoch, 'createdLeaseEpoch')
  return writer.finish()
}

export function createPeeritRecoveryCollisionSetV1 (input) {
  let value = null
  let bytes = null
  try {
    value = canonicalCollisionSet(input)
    bytes = writeCollisionSet(value)
    const collisionSetHash = domainLengthHash(
      COLLISION_SET_HASH_DOMAIN_V1,
      bytes
    )
    const output = Object.freeze({
      version: 1,
      complete: true,
      activeTransportPublicKeys: Object.freeze(
        value.activeTransportPublicKeys.map(key => new Uint8Array(key))
      ),
      retiredTransportPublicKeys: Object.freeze(
        value.retiredTransportPublicKeys.map(key => new Uint8Array(key))
      ),
      activeDeviceChainIds: Object.freeze(
        value.activeDeviceChainIds.map(id => new Uint8Array(id))
      ),
      retiredDeviceChainIds: Object.freeze(
        value.retiredDeviceChainIds.map(id => new Uint8Array(id))
      ),
      localWitnessedFloors: Object.freeze(
        value.localWitnessedFloors.map(floor => Object.freeze({
          kind: floor.kind,
          scopeId: new Uint8Array(floor.scopeId),
          sequence: floor.sequence,
          hash: new Uint8Array(floor.hash)
        }))
      ),
      previousAuthorSequence: value.previousAuthorSequence,
      previousAuthorRecordId: value.previousAuthorRecordId == null
        ? null
        : new Uint8Array(value.previousAuthorRecordId),
      createdLeaseEpoch: value.createdLeaseEpoch,
      collisionSetHash: new Uint8Array(collisionSetHash)
    })
    COLLISION_SETS.set(output, Object.freeze({
      snapshot: cloneCollisionSet(value),
      collisionSetHash: new Uint8Array(collisionSetHash)
    }))
    return output
  } finally {
    wipe(value)
    wipe(bytes)
  }
}

function requireCollisionSet (input) {
  const branded = COLLISION_SETS.get(input)
  if (branded == null) {
    fail('RECOVERY_COLLISION_SET_REQUIRED',
      'a complete module-branded local writer/chain collision set is required')
  }
  return {
    snapshot: cloneCollisionSet(branded.snapshot),
    collisionSetHash: new Uint8Array(branded.collisionSetHash)
  }
}

export function mergePeeritRecoveryFloorsV1 (localInput, recoveredInput) {
  let local = null
  let recovered = null
  try {
    local = floors(localInput, 'local witnessed floors')
    recovered = floors(recoveredInput, 'recovered witnessed floors')
    const merged = new Map()
    for (const value of [...local, ...recovered]) {
      const key = `${value.kind}:${bytesToHex(value.scopeId)}`
      const prior = merged.get(key)
      if (prior == null || value.sequence > prior.sequence) {
        merged.set(key, value)
      } else if (value.sequence === prior.sequence &&
          !bytesEqual(value.hash, prior.hash)) {
        fail('RECOVERY_FLOOR_FORK',
          'same-sequence recovery floors contain different witnessed hashes')
      }
    }
    return Object.freeze(
      [...merged.values()]
        .sort((left, right) => compareBytes(
          concatBytes(Uint8Array.of(left.kind), left.scopeId),
          concatBytes(Uint8Array.of(right.kind), right.scopeId)
        ))
        .map(value => Object.freeze({
          kind: value.kind,
          scopeId: new Uint8Array(value.scopeId),
          sequence: value.sequence,
          hash: new Uint8Array(value.hash)
        }))
    )
  } finally {
    wipe(local)
    wipe(recovered)
  }
}

function recoveredWitnessedFloors (payload) {
  const output = []
  try {
    for (const bytes of payload.witnessedFloorRecords) {
      let record = null
      try {
        record = decodePeeritRecoveryRecordV2(bytes)
        output.push({
          kind: record.floorKind,
          scopeId: new Uint8Array(record.scopeId),
          sequence: record.sequence,
          hash: new Uint8Array(record.witnessHash)
        })
      } finally {
        wipe(record)
      }
    }
    return output
  } catch (error) {
    wipe(output)
    throw error
  }
}

async function createDeviceChainStart (
  profileAuthority,
  runtime,
  accountSeed,
  accountPublicKey,
  deviceChainId,
  newTransportPublicKey,
  collision
) {
  let placeholder = null
  let prefix = null
  let message = null
  let signature = null
  let finalBytes = null
  let validated = null
  try {
    const base = {
      version: 1,
      accountPublicKey: new Uint8Array(accountPublicKey),
      deviceChainId: new Uint8Array(deviceChainId),
      newTransportCorePublicKey: new Uint8Array(newTransportPublicKey),
      previousAuthorSequence: collision.previousAuthorSequence,
      previousAuthorRecordId: collision.previousAuthorRecordId == null
        ? null
        : new Uint8Array(collision.previousAuthorRecordId),
      createdLeaseEpoch: collision.createdLeaseEpoch,
      signature: new Uint8Array(64)
    }
    try {
      placeholder = profileAuthority.encode(base)
    } finally {
      wipe(base)
    }
    const expectedLength = collision.previousAuthorRecordId == null ? 176 : 208
    if (!(placeholder instanceof Uint8Array) ||
        placeholder.byteLength !== expectedLength ||
        !isAllZero(placeholder.slice(-64))) {
      fail('RECOVERY_DEVICE_CHAIN_START_INVALID',
        'DeviceChainStartV1 codec did not place the exact signature suffix')
    }
    prefix = placeholder.slice(0, -64)
    message = concatBytes(
      asciiBytes(PEERIT_DEVICE_CHAIN_START_SIGNATURE_DOMAIN_V1),
      prefix
    )
    signature = await signWithSeed(runtime, accountSeed, message)
    const complete = {
      version: 1,
      accountPublicKey: new Uint8Array(accountPublicKey),
      deviceChainId: new Uint8Array(deviceChainId),
      newTransportCorePublicKey: new Uint8Array(newTransportPublicKey),
      previousAuthorSequence: collision.previousAuthorSequence,
      previousAuthorRecordId: collision.previousAuthorRecordId == null
        ? null
        : new Uint8Array(collision.previousAuthorRecordId),
      createdLeaseEpoch: collision.createdLeaseEpoch,
      signature: new Uint8Array(signature)
    }
    try {
      finalBytes = profileAuthority.encode(complete)
    } finally {
      wipe(complete)
    }
    validated = profileAuthority.validate('DeviceChainStartV1', finalBytes)
    const value = validated?.value
    if (!value ||
        !bytesEqual(value.accountPublicKey, accountPublicKey) ||
        !bytesEqual(value.deviceChainId, deviceChainId) ||
        !bytesEqual(value.newTransportCorePublicKey, newTransportPublicKey) ||
        value.previousAuthorSequence !== collision.previousAuthorSequence ||
        ((value.previousAuthorRecordId == null) !==
          (collision.previousAuthorRecordId == null)) ||
        (value.previousAuthorRecordId != null &&
          !bytesEqual(value.previousAuthorRecordId,
            collision.previousAuthorRecordId)) ||
        value.createdLeaseEpoch !== collision.createdLeaseEpoch ||
        !bytesEqual(value.signature, signature)) {
      fail('RECOVERY_DEVICE_CHAIN_START_INVALID',
        'validated DeviceChainStartV1 fields do not match restore state')
    }
    await verifySignature(runtime, accountPublicKey, message, signature)
    const transferred = finalBytes
    finalBytes = null
    return transferred
  } finally {
    wipe(placeholder)
    wipe(prefix)
    wipe(message)
    wipe(signature)
    wipe(finalBytes)
    wipe(validated)
  }
}

export async function exportPeeritRecoveryBundleV1 (
  payloadInput,
  passphrase,
  options = {}
) {
  const runtime = cryptoRuntime(options.crypto)
  let payloadBytes = null
  let payload = null
  let accountPublicKey = null
  let salt = null
  let nonce = null
  let key = null
  let header = null
  let sealed = null
  let testPlaintext = null
  let testPayload = null
  try {
    payloadBytes = encodePeeritRecoveryPayloadV2(payloadInput)
    payload = decodePeeritRecoveryPayloadV2(payloadBytes)
    await verifyPeeritPortablePinHistoryV1(payload.pinHistoryRecord, {
      crypto: runtime,
      trustRoot: options.trustRoot,
      minimumWitness: options.minimumPinHistoryWitness
    })
    accountPublicKey = await derivePublicKey(
      runtime,
      payload.accountSeed,
      'account public key'
    )
    salt = await random(runtime, PEERIT_RECOVERY_KDF_V1.saltBytes,
      'recovery salt')
    nonce = await random(runtime, PEERIT_RECOVERY_KDF_V1.nonceBytes,
      'recovery nonce')
    key = await deriveKey(runtime, passphrase, salt)
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
      sealed: new Uint8Array(
        payloadBytes.byteLength + PEERIT_RECOVERY_KDF_V1.tagBytes
      )
    }
    try {
      header = writeHeader(provisional)
      sealed = await encryptPayload(
        runtime,
        key,
        nonce,
        payloadBytes,
        header
      )
      provisional.sealed = sealed
      const bytes = encodePeeritRecoveryBundleV1(provisional)
      const testBundle = decodePeeritRecoveryBundleV1(bytes)
      testPlaintext = await decryptPayload(testBundle, passphrase, runtime)
      testPayload = decodePeeritRecoveryPayloadV2(testPlaintext)
      await assertAccountPublicKey(
        testPayload,
        testBundle.accountPublicKey,
        runtime
      )
      if (!bytesEqual(testPlaintext, payloadBytes)) {
        fail('RECOVERY_EXPORT_SELF_TEST_FAILED',
          'recovery export did not round-trip exactly')
      }
      return bytes
    } finally {
      wipe(provisional)
    }
  } finally {
    wipe(payloadBytes)
    wipe(payload)
    wipe(accountPublicKey)
    wipe(salt)
    wipe(nonce)
    wipe(key)
    wipe(header)
    wipe(sealed)
    wipe(testPlaintext)
    wipe(testPayload)
  }
}

export async function importPeeritRecoveryBundleV1 (
  input,
  passphrase,
  options = {}
) {
  const runtime = cryptoRuntime(options.crypto)
  const profileAuthority = requireProfileAuthority(options.profileAuthority)
  let collision = null
  let collisionSetHash = null
  let plaintext = null
  let payload = null
  let accountPublicKey = null
  let recoveredFloors = null
  let mergedFloors = null
  let deviceTransportSeed = null
  let newTransportPublicKey = null
  let deviceChainId = null
  let deviceChainStartBytes = null
  try {
    const collisionBrand = requireCollisionSet(options.collisionSet)
    collision = collisionBrand.snapshot
    collisionSetHash = collisionBrand.collisionSetHash
    const bundle = decodePeeritRecoveryBundleV1(input)
    plaintext = await decryptPayload(bundle, passphrase, runtime)
    payload = decodePeeritRecoveryPayloadV2(plaintext)
    await assertAccountPublicKey(payload, bundle.accountPublicKey, runtime)
    accountPublicKey = new Uint8Array(bundle.accountPublicKey)
    const verifiedPinHistory = await verifyPeeritPortablePinHistoryV1(
      payload.pinHistoryRecord,
      {
        crypto: runtime,
        trustRoot: options.trustRoot,
        minimumWitness: options.minimumPinHistoryWitness
      }
    )
    recoveredFloors = recoveredWitnessedFloors(payload)
    mergedFloors = mergePeeritRecoveryFloorsV1(
      collision.localWitnessedFloors,
      recoveredFloors
    )
    deviceTransportSeed = await random(
      runtime,
      32,
      'fresh device transport seed'
    )
    newTransportPublicKey = await derivePublicKey(
      runtime,
      deviceTransportSeed,
      'fresh transport public key'
    )
    if (bytesEqual(newTransportPublicKey, accountPublicKey) ||
        containsId(collision.activeTransportPublicKeys,
          newTransportPublicKey) ||
        containsId(collision.retiredTransportPublicKeys,
          newTransportPublicKey)) {
      fail('RECOVERY_CLONED_WRITER_REJECTED',
        'restore transport identity collides with account or local writer history')
    }
    deviceChainId = await random(runtime, 32, 'fresh device chain ID')
    if (containsId(collision.activeDeviceChainIds, deviceChainId) ||
        containsId(collision.retiredDeviceChainIds, deviceChainId) ||
        containsId(payload.retiredDeviceChainIds, deviceChainId)) {
      fail('RECOVERY_CLONED_CHAIN_REJECTED',
        'restore chain ID collides with active or retired local history')
    }
    deviceChainStartBytes = await createDeviceChainStart(
      profileAuthority,
      runtime,
      payload.accountSeed,
      accountPublicKey,
      deviceChainId,
      newTransportPublicKey,
      collision
    )
    const result = Object.freeze({
      version: 2,
      accountPublicKey,
      payload,
      verifiedPinHistory,
      mergedWitnessedFloors: mergedFloors,
      collisionSetHash,
      deviceTransportSeed,
      newTransportCorePublicKey: newTransportPublicKey,
      deviceChainId,
      deviceChainStartBytes,
      persistenceStatus: 'UNCOMMITTED_SIGNED_CANDIDATE'
    })
    accountPublicKey = null
    payload = null
    mergedFloors = null
    collisionSetHash = null
    deviceTransportSeed = null
    newTransportPublicKey = null
    deviceChainId = null
    deviceChainStartBytes = null
    return result
  } finally {
    wipe(collision)
    wipe(collisionSetHash)
    wipe(plaintext)
    wipe(payload)
    wipe(accountPublicKey)
    wipe(recoveredFloors)
    wipe(mergedFloors)
    wipe(deviceTransportSeed)
    wipe(newTransportPublicKey)
    wipe(deviceChainId)
    wipe(deviceChainStartBytes)
  }
}

function deepFreeze (value) {
  if (value == null || typeof value !== 'object' ||
      value instanceof Uint8Array || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

const CONTRACT_ABI_V2 = deepFreeze({
  contract: 'PeeritRecoveryContractV2',
  compatibility: {
    outerRecord: 'PeeritRecoveryBundleV1',
    authenticatedPlaintext: 'PeeritRecoveryPayloadV2',
    priorPayloadAccepted: false
  },
  outer: {
    magic: PEERIT_RECOVERY_BUNDLE_MAGIC_V1,
    version: 1,
    fields: BUNDLE_FIELDS,
    kdf: PEERIT_RECOVERY_KDF_V1,
    aead: 'XChaCha20-Poly1305-IETF',
    aadFieldsThrough: 'ciphertextLength',
    passphrase: 'NFC Unicode scalar UTF-8 bytes[1..1024]'
  },
  payload: {
    magic: PEERIT_RECOVERY_PAYLOAD_MAGIC_V2,
    version: 2,
    fields: PAYLOAD_FIELDS_V2,
    sections: PAYLOAD_SECTIONS_V2,
    publishedLogicalIds: 'strict sorted unique nonzero bytes[32]',
    retiredDeviceChainIds: 'strict sorted unique nonzero bytes[32]'
  },
  recordEnvelope: {
    magic: PEERIT_RECOVERY_RECORD_MAGIC_V2,
    version: 2,
    layout: [
      'magic[8]',
      'type:u8',
      'version:u8',
      'exact-type-fields',
      'recordHash[32]',
      'recordId[32]'
    ],
    recordHashDomain: RECORD_HASH_DOMAIN_V2,
    recordHashRecipe: 'domainLengthHash(canonical-prefix)',
    recordIdDomain: RECORD_ID_DOMAIN_V2,
    recordIdRecipe: 'domainLengthHash(type:u8||version:u8||recordHash)',
    operationalBytesHashDomain: OPERATIONAL_BYTES_HASH_DOMAIN_V2,
    operationalBytesHashRecipe:
      'domainLengthHash(ASCII(fieldName)||exactOperationalBytes)',
    unknownTypes: 'forbidden',
    types: Object.entries(RECORD_FIELDS).map(([type, definition]) => ({
      type: Number(type),
      name: definition.name,
      fields: definition.fields
    }))
  },
  excludedShapes: [
    'CoreTransportWriterSeed',
    'deviceTransportSeed',
    'originCredential',
    'bearerToken',
    'cookie',
    'admissionIssuerAccount',
    'unknown-writer/admin/credential-record-type',
    'opaque-extension-or-trailing-bytes'
  ],
  cryptoProvider: {
    suite: PEERIT_RECOVERY_CRYPTO_SUITE_V1,
    methods: [
      'randomBytes(length)->Uint8Array',
      'deriveArgon2id(options)->Uint8Array(32)',
      'encryptXChaCha20Poly1305Ietf(options)->Uint8Array(plaintext+16)',
      'decryptXChaCha20Poly1305Ietf(options)->Uint8Array(ciphertext)',
      'deriveEd25519PublicKey(seed)->Uint8Array(32)',
      'signEd25519(seed,message)->Uint8Array(64)',
      'verifyEd25519(publicKey,message,signature)->true'
    ],
    outputOwnership:
      'fresh unaliased exact-prototype whole-buffer Uint8Array transfers to caller',
    inputOwnership:
      'provider borrows caller copies only for the awaited call',
    cleanup:
      'all caller passphrase/key/plaintext/seed/message copies wipe in immediate finally; invalid outputs wipe before throw'
  },
  collisionSet: {
    magic: PEERIT_RECOVERY_COLLISION_SET_MAGIC_V1,
    version: 1,
    brandRequired: true,
    completeRequired: true,
    activeSetsMayBeEmpty: false,
    fields: COLLISION_SET_INPUT_FIELDS,
    hashDomain: COLLISION_SET_HASH_DOMAIN_V1
  },
  freshChain: {
    profileBinding: PEERIT_RECOVERY_PROFILE_BINDING_V2,
    profileAuthorityBrandRequired: true,
    signatureDomain: PEERIT_DEVICE_CHAIN_START_SIGNATURE_DOMAIN_V1,
    collisionIdentity: 'derived Ed25519 transport public key',
    result: [
      'accountPublicKey[32]',
      'PeeritRecoveryPayloadV2',
      'verified portable pin history brand',
      'merged witnessed floors',
      'collisionSetHash[32]',
      'deviceTransportSeed[32]',
      'newTransportCorePublicKey[32]',
      'deviceChainId[32]',
      'exact signed DeviceChainStartV1 bytes',
      'persistenceStatus=UNCOMMITTED_SIGNED_CANDIDATE'
    ],
    claimBoundary:
      'candidate is signed and validated but not claimed durable, journaled, or published'
  },
  limits: PEERIT_RECOVERY_LIMITS_V2
})

export const PEERIT_RECOVERY_GOLDEN_VECTOR_MANIFEST_V2 = deepFreeze({
  vectorSet: 'PeeritRecoveryContractV2/2026-07-19',
  fixtureHashDomains: {
    typedRecordSetHash: 'peerit.recovery-golden-record-set.v2',
    payloadHash: 'peerit.recovery-golden-payload.v2',
    outerBundleHash: 'peerit.recovery-golden-outer-bundle.v2',
    collisionSetHash: COLLISION_SET_HASH_DOMAIN_V1,
    deviceChainStartHash: 'peerit.recovery-golden-device-chain-start.v2'
  },
  fixtures: {
    typedRecordSetHash:
      '7a51a6642e8861a58d3e6d49de1c032f3c1be824131ead5d2b825b58fd6dcb4b',
    payloadHash:
      '856db5dc15f2d7b37fc270f18f9f8b58cf2340a87eb07ca29b7b75cf6819959a',
    outerBundleHash:
      '43f1e7f1a77ed95be77d35fa81fb7ef7251ec5207b905bbb6185e6c9e41d3ebd',
    collisionSetHash:
      '3372a4569321ee31aee8755433f3690fb82dc00a07a2d0a3aaea1535cd0048ac',
    deviceChainStartHash:
      'd0c7e219ea54021bc938bcd2f5206b88d389d5c03839151c042c88e58ae6cf1c'
  },
  requiredPositiveCases: [
    'all-ten-record-types-round-trip',
    'payload-v2-round-trip',
    'outer-v1-authenticates-payload-v2',
    'portable-pin-history-node-and-browser',
    'complete-collision-set-fresh-chain-start',
    'two-generation-service-worker-trust'
  ],
  requiredNegativeCases: [
    'payload-v1-cross-decode',
    'unknown-writer-record-type',
    'extra-secret-field',
    'section-type-confusion',
    'record-trailing-byte',
    'record-wrong-hash',
    'record-wrong-id',
    'record-noncanonical-sort',
    'collision-set-omitted',
    'collision-set-shape-copy',
    'collision-set-empty-active-writer',
    'active-writer-collision',
    'retired-writer-collision',
    'active-chain-collision',
    'retired-chain-collision',
    'profile-authority-omitted',
    'device-chain-start-binding',
    'passphrase-empty-invalid-unicode-nonnfc-overbound',
    'provider-output-type-length-alias',
    'portable-history-trailing-root-terminal-transition-order'
  ],
  requiredCleanupCases: [
    'success-export-and-self-test',
    'success-import',
    'random-failure',
    'kdf-failure',
    'public-key-failure',
    'encrypt-failure',
    'decrypt-failure',
    'pin-history-validation-failure',
    'collision-validation-failure',
    'sign-failure',
    'profile-validation-failure'
  ]
})

export function peeritRecoveryBundleContractBytesV2 () {
  return utf8Bytes(
    `${JSON.stringify(CONTRACT_ABI_V2)}\n`,
    'PeeritRecoveryContractV2 ABI'
  )
}

export function peeritRecoveryGoldenVectorManifestBytesV2 () {
  return utf8Bytes(
    `${JSON.stringify(PEERIT_RECOVERY_GOLDEN_VECTOR_MANIFEST_V2)}\n`,
    'PeeritRecoveryContractV2 golden vector manifest'
  )
}

export function peeritRecoveryBundleContractHashV2 () {
  return domainLengthHash(
    'peerit.recovery-bundle-contract.v2',
    concatBytes(
      peeritRecoveryBundleContractBytesV2(),
      peeritRecoveryGoldenVectorManifestBytesV2()
    )
  )
}
