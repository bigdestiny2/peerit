// Structural VNext intent construction shared by journal-only scale and fault
// laboratories. Signed-operation authority is tested separately; these labs
// measure the journal with the exact current envelope, identifiers, and
// commitments instead of the retired raw-JSON intent shape.

import {
  PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1
} from '../../js/substrate/peerit-journal.js'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  PEERIT_OPERATION_TYPES_V1,
  hashPeeritInnerCellEncodingCommitmentV1,
  hashPeeritInnerLogicalHashV1,
  hashPeeritInnerOperationIntentIdV1
} from '../../js/substrate/peerit-operation-authority-v1.js'
import {
  peeritAuthorBindCellSizeClassForInnerLengthV1
} from '../../js/substrate/author-bind-inner-envelope-policy.mjs'

export {
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1
}

export const PEERIT_LAB_OPERATION_SHAPE_V2 = 'peerit-unsigned-structural-operation-records-v2'
export const PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2 = 'peerit-inner-operation-batch-v1-derived-journal-intent-v2'

const encoder = new TextEncoder()
const operationTypes = new Set(PEERIT_OPERATION_TYPES_V1)
const hex64 = /^[0-9a-f]{64}$/
const inspectionChecks = Object.freeze([
  'wireFormat',
  'innerCodec',
  'codecBytes',
  'version',
  'payloadLength',
  'innerLength',
  'smallestSizeClass',
  'logicalHash',
  'encodingCommitment',
  'intentId',
  'logicalId'
])

function canonicalJson (value, arrayElement = false) {
  if (value === undefined) {
    if (arrayElement) return 'null'
    throw new TypeError('structural VNext intent contains undefined outside an array')
  }
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('structural VNext intent contains a non-finite number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(child => canonicalJson(child, true)).join(',')}]`
  if (!value || typeof value !== 'object') {
    throw new TypeError(`structural VNext intent contains unsupported ${typeof value}`)
  }
  return `{${Object.keys(value)
    .filter(key => value[key] !== undefined)
    .sort()
    .map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`
}

function hex (value) {
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('')
}

function sameBytes (left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.byteLength !== right.byteLength) return false
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) return false
  }
  return true
}

function readU32BigEndian (bytes, offset) {
  return (bytes[offset] * 0x1000000) +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]
}

function validateOperations (operations) {
  if (!Array.isArray(operations) || operations.length < 1 || operations.length > 64) {
    throw new TypeError('structural VNext intent operations must contain 1..64 entries')
  }
  for (const [index, operation] of operations.entries()) {
    const keys = operation && typeof operation === 'object' && !Array.isArray(operation)
      ? Object.keys(operation).sort()
      : []
    if (keys.length !== 2 || keys[0] !== 'data' || keys[1] !== 'type' ||
        !operationTypes.has(operation.type) || !operation.data ||
        typeof operation.data !== 'object' || Array.isArray(operation.data) ||
        typeof operation.data.id !== 'string' || !operation.data.id) {
      throw new TypeError(`structural VNext intent operation ${index} is not an exact Peerit {type,data} record shape`)
    }
  }
}

export function createStructuralPeeritVnextJournalIntent ({ operations, records, createdAt }) {
  validateOperations(operations)
  const payloadBytes = encoder.encode(canonicalJson({ version: 1, operations }))
  const innerBytes = new Uint8Array(7 + payloadBytes.byteLength)
  innerBytes[0] = (PEERIT_INNER_OPERATION_BATCH_V1_CODEC >>> 8) & 0xff
  innerBytes[1] = PEERIT_INNER_OPERATION_BATCH_V1_CODEC & 0xff
  innerBytes[2] = 1
  innerBytes[3] = (payloadBytes.byteLength >>> 24) & 0xff
  innerBytes[4] = (payloadBytes.byteLength >>> 16) & 0xff
  innerBytes[5] = (payloadBytes.byteLength >>> 8) & 0xff
  innerBytes[6] = payloadBytes.byteLength & 0xff
  innerBytes.set(payloadBytes, 7)

  const innerLength = innerBytes.byteLength
  const sizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(BigInt(innerLength))
  const logicalHash = hashPeeritInnerLogicalHashV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)
  const intent = {
    wireFormat: PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
    innerCodec: PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
    innerBytes,
    innerLength,
    sizeClass,
    logicalHash,
    encodingCommitment: hashPeeritInnerCellEncodingCommitmentV1(
      PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
      innerBytes,
      logicalHash,
      sizeClass
    ),
    intentId: hex(hashPeeritInnerOperationIntentIdV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)),
    logicalId: hex(logicalHash)
  }
  if (records !== undefined) intent.records = records
  if (createdAt !== undefined) intent.createdAt = createdAt
  return intent
}

export function inspectStructuralPeeritVnextJournalIntent (intent) {
  const innerBytes = intent?.innerBytes instanceof Uint8Array ? intent.innerBytes : null
  const logicalHash = intent?.logicalHash instanceof Uint8Array ? intent.logicalHash : null
  const innerLength = innerBytes?.byteLength ?? null
  const codecBytesHex = innerBytes && innerLength >= 2 ? hex(innerBytes.subarray(0, 2)) : null
  const version = innerBytes && innerLength >= 3 ? innerBytes[2] : null
  const declaredPayloadLength = innerBytes && innerLength >= 7 ? readU32BigEndian(innerBytes, 3) : null
  const payloadLength = innerBytes && innerLength >= 7 ? innerLength - 7 : null

  let smallestSizeClass = null
  let recomputedLogicalHash = null
  let recomputedEncodingCommitment = null
  let recomputedIntentId = null
  try {
    if (innerBytes) {
      smallestSizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(BigInt(innerLength))
      recomputedLogicalHash = hashPeeritInnerLogicalHashV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)
      recomputedEncodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
        PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
        innerBytes,
        recomputedLogicalHash,
        smallestSizeClass
      )
      recomputedIntentId = hashPeeritInnerOperationIntentIdV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)
    }
  } catch {}

  const checks = {
    wireFormat: intent?.wireFormat === PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
    innerCodec: intent?.innerCodec === PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
    codecBytes: codecBytesHex === '014e',
    version: version === 1,
    payloadLength: declaredPayloadLength !== null && declaredPayloadLength === payloadLength,
    innerLength: Number.isSafeInteger(intent?.innerLength) && intent.innerLength === innerLength,
    smallestSizeClass: smallestSizeClass !== null && intent?.sizeClass === smallestSizeClass,
    logicalHash: recomputedLogicalHash !== null && sameBytes(logicalHash, recomputedLogicalHash),
    encodingCommitment: recomputedEncodingCommitment !== null && sameBytes(intent?.encodingCommitment, recomputedEncodingCommitment),
    intentId: recomputedIntentId !== null && intent?.intentId === hex(recomputedIntentId),
    logicalId: recomputedLogicalHash !== null && intent?.logicalId === hex(recomputedLogicalHash)
  }

  return {
    operationShape: PEERIT_LAB_OPERATION_SHAPE_V2,
    journalIntentShape: PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2,
    wireFormat: intent?.wireFormat ?? null,
    innerCodec: intent?.innerCodec ?? null,
    codecBytesHex,
    version,
    declaredPayloadLength,
    payloadLength,
    innerLength,
    sizeClass: intent?.sizeClass ?? null,
    smallestSizeClass,
    logicalHashHex: logicalHash ? hex(logicalHash) : null,
    recomputedLogicalHashHex: recomputedLogicalHash ? hex(recomputedLogicalHash) : null,
    encodingCommitmentHex: intent?.encodingCommitment instanceof Uint8Array ? hex(intent.encodingCommitment) : null,
    recomputedEncodingCommitmentHex: recomputedEncodingCommitment ? hex(recomputedEncodingCommitment) : null,
    intentId: intent?.intentId ?? null,
    recomputedIntentId: recomputedIntentId ? hex(recomputedIntentId) : null,
    logicalId: intent?.logicalId ?? null,
    checks,
    verified: Object.values(checks).every(Boolean)
  }
}

export function isStructuralPeeritVnextJournalInspectionEvidence (evidence) {
  const checks = evidence && evidence.checks
  return evidence != null &&
    evidence.operationShape === PEERIT_LAB_OPERATION_SHAPE_V2 &&
    evidence.journalIntentShape === PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2 &&
    evidence.wireFormat === PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1 &&
    evidence.innerCodec === PEERIT_INNER_OPERATION_BATCH_V1_CODEC &&
    evidence.codecBytesHex === '014e' && evidence.version === 1 &&
    Number.isSafeInteger(evidence.declaredPayloadLength) && evidence.declaredPayloadLength >= 1 &&
    evidence.declaredPayloadLength === evidence.payloadLength &&
    evidence.innerLength === evidence.payloadLength + 7 &&
    evidence.sizeClass === evidence.smallestSizeClass &&
    hex64.test(evidence.logicalHashHex || '') &&
    evidence.recomputedLogicalHashHex === evidence.logicalHashHex &&
    hex64.test(evidence.encodingCommitmentHex || '') &&
    evidence.recomputedEncodingCommitmentHex === evidence.encodingCommitmentHex &&
    hex64.test(evidence.intentId || '') && evidence.recomputedIntentId === evidence.intentId &&
    evidence.logicalId === evidence.logicalHashHex && evidence.verified === true &&
    checks != null && inspectionChecks.every(key => checks[key] === true)
}
