// Narrow VNext authority for the bytes placed in a Cell before an AuthorBindV1
// can ever be considered. This module deliberately owns the operation batch
// grammar, signature checks, envelope framing, and portable commitments. It does
// not issue an AuthorBind or treat a relay receipt as readback proof.

import { expectedKey, expectedKeyV2 } from '../canon.js'
import { verifyBlobRecord } from '../blob-store.js'
import { unseal } from '../seal.js'
import { verifyRecord } from '../verify.js'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  PEERIT_INNER_OPERATION_BATCH_V1_MAX_BYTES,
  PEERIT_INNER_OPERATION_BATCH_V1_MIN_BYTES,
  peeritAuthorBindCellSizeClassForInnerLengthV1
} from './author-bind-inner-envelope-policy.mjs'
import {
  asciiBytes,
  asBytes,
  blake2b256,
  bytesEqual,
  concatBytes,
  u16Bytes,
  u32Bytes,
  u64Bytes
} from './release-control-primitives.mjs'

export { PEERIT_INNER_OPERATION_BATCH_V1_CODEC }

export const PEERIT_INNER_OPERATION_BATCH_V1_VERSION = 1
export const PEERIT_INNER_OPERATION_BATCH_V1_HEADER_BYTES = 7
export const PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATION_BYTES = 1048512
export const PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATIONS = 64
export const PEERIT_INNER_OPERATION_BATCH_V1_MAX_CANONICAL_DEPTH = 64
export const PEERIT_INNER_OPERATION_BATCH_V1_MAX_CANONICAL_NODES = 16384
export const PEERIT_INNER_OPERATION_BATCH_V1_DEFAULT_MAX_RECORD_KEY_BYTES = 4096

// Keep the VNext surface deliberately closed. Adding an application type must
// be an explicit profile/runtime change rather than an accidental bypass via a
// caller-provided semantic type.
export const PEERIT_OPERATION_TYPES_V1 = Object.freeze([
  'blob',
  'comment',
  'community',
  'follow',
  'member',
  'modaction',
  'post',
  'profile',
  'vote'
])

const OPERATION_TYPES = new Set(PEERIT_OPERATION_TYPES_V1)
const V2_SEMANTIC_TYPES = new Set(PEERIT_OPERATION_TYPES_V1.filter(type => type !== 'blob'))
const HEX_64_LOWER = /^[0-9a-f]{64}$/
const HEX_128_LOWER = /^[0-9a-f]{128}$/
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: true })

function fail (code, message, cause = undefined) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

function isPlainObject (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function canonicalBudget (byteLimit = PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATION_BYTES) {
  return { byteLimit, bytes: 0, nodes: 0 }
}

function chargeCanonicalBytes (budget, text, field) {
  const length = textEncoder.encode(text).byteLength
  if (budget.bytes + length > budget.byteLimit) {
    fail('PEERIT_OPERATION_BATCH_RESOURCE_LIMIT', `${field} exceeds the bounded canonical operation batch size`)
  }
  budget.bytes += length
}

function countCanonicalNode (budget, field, depth) {
  if (depth > PEERIT_INNER_OPERATION_BATCH_V1_MAX_CANONICAL_DEPTH) {
    fail('PEERIT_OPERATION_BATCH_RESOURCE_LIMIT', `${field} exceeds the canonical nesting-depth limit`)
  }
  budget.nodes++
  if (budget.nodes > PEERIT_INNER_OPERATION_BATCH_V1_MAX_CANONICAL_NODES) {
    fail('PEERIT_OPERATION_BATCH_RESOURCE_LIMIT', `${field} exceeds the canonical node-count limit`)
  }
}

function canonicalString (value, field, budget) {
  if (typeof value !== 'string') fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must be text`)
  // Existing Peerit signatures preserve user-provided Unicode verbatim. Do not
  // normalize after signing: JSON.stringify gives this envelope one exact UTF-8
  // spelling while preserving valid legacy NFD content and escaped surrogates.
  const text = JSON.stringify(value)
  chargeCanonicalBytes(budget, text, field)
  return text
}

function ownDataKeys (value, field) {
  if (!isPlainObject(value)) fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must be a plain object`)
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must not contain symbol properties`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable || descriptor.get || descriptor.set) {
      fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field}.${key} must be an enumerable data property`)
    }
  }
  return descriptors
}

function arrayDataDescriptors (value, field) {
  if (!Array.isArray(value)) fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must be an array`)
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must not contain symbol properties`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const names = Object.keys(descriptors)
  const lengthDescriptor = descriptors.length
  const length = lengthDescriptor && lengthDescriptor.value
  if (!lengthDescriptor || lengthDescriptor.get || lengthDescriptor.set ||
      !Number.isSafeInteger(length) || length < 0 || names.length !== length + 1) {
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must be a dense data array without extra properties`)
  }
  for (let index = 0; index < length; index++) {
    const key = String(index)
    const descriptor = descriptors[key]
    if (!descriptor || !descriptor.enumerable || descriptor.get || descriptor.set) {
      fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field}[${index}] must be an enumerable data property`)
    }
  }
  return Object.freeze({ descriptors, length })
}

function canonicalArray (value, field, budget, depth) {
  const { descriptors, length } = arrayDataDescriptors(value, field)
  const parts = []
  chargeCanonicalBytes(budget, '[', field)
  for (let index = 0; index < length; index++) {
    if (index) chargeCanonicalBytes(budget, ',', field)
    parts.push(canonicalValue(descriptors[String(index)].value, `${field}[${index}]`, budget, depth + 1, true))
  }
  chargeCanonicalBytes(budget, ']', field)
  return '[' + parts.join(',') + ']'
}

function canonicalValue (value, field, budget, depth = 0, arrayElement = false) {
  countCanonicalNode(budget, field, depth)
  if (value === undefined) {
    if (arrayElement) {
      chargeCanonicalBytes(budget, 'null', field)
      return 'null'
    }
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must not be undefined`)
  }
  if (value === null) {
    chargeCanonicalBytes(budget, 'null', field)
    return 'null'
  }
  if (typeof value === 'string') return canonicalString(value, field, budget)
  if (typeof value === 'boolean') {
    const text = value ? 'true' : 'false'
    chargeCanonicalBytes(budget, text, field)
    return text
  }
  if (typeof value === 'number') {
    // JSON's one canonical spelling for both numeric zero values is `0`. The
    // legacy signed-operation serializer already used JSON.stringify(), so
    // accepting -0 here preserves those valid records while the envelope still
    // has one exact byte representation.
    if (!Number.isFinite(value)) {
      fail('PEERIT_OPERATION_BATCH_NONCANONICAL', `${field} must be a finite JSON number`)
    }
    const text = JSON.stringify(value)
    chargeCanonicalBytes(budget, text, field)
    return text
  }
  if (Array.isArray(value)) return canonicalArray(value, field, budget, depth)
  const descriptors = ownDataKeys(value, field)
  const keys = Object.keys(descriptors).filter(key => descriptors[key].value !== undefined).sort()
  const parts = []
  chargeCanonicalBytes(budget, '{', field)
  for (let index = 0; index < keys.length; index++) {
    const key = keys[index]
    if (index) chargeCanonicalBytes(budget, ',', field)
    const keyText = JSON.stringify(key)
    chargeCanonicalBytes(budget, keyText, `${field} key`)
    chargeCanonicalBytes(budget, ':', field)
    parts.push(`${keyText}:${canonicalValue(descriptors[key].value, `${field}.${key}`, budget, depth + 1)}`)
  }
  chargeCanonicalBytes(budget, '}', field)
  return '{' + parts.join(',') + '}'
}

function exactObject (value, field, expectedKeys) {
  const descriptors = ownDataKeys(value, field)
  const keys = Object.keys(descriptors).sort()
  const expected = [...expectedKeys].sort()
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `${field} must contain exactly ${expected.join(', ')}`)
  }
  return descriptors
}

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function snapshotOperation (input, field, budget) {
  const descriptors = exactObject(input, field, ['type', 'data'])
  const text = canonicalValue({ type: descriptors.type.value, data: descriptors.data.value }, field, budget)
  try {
    return JSON.parse(text)
  } catch (cause) {
    fail('PEERIT_OPERATION_BATCH_NONCANONICAL', `${field} cannot be reconstructed from canonical JSON`, cause)
  }
}

function snapshotOperationInputs (operations) {
  const { descriptors, length } = arrayDataDescriptors(operations, 'operations')
  if (length < 1 || length > PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATIONS) {
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', `operations must contain 1..${PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATIONS} entries`)
  }
  return Object.freeze(Array.from({ length }, (_, index) => descriptors[String(index)].value))
}

function assertExpectedAuthor (value, field = 'expectedAuthorPublicKey') {
  if (!HEX_64_LOWER.test(value || '')) {
    fail('PEERIT_OPERATION_BATCH_METADATA', `${field} must be a lowercase 32-byte Ed25519 public key`)
  }
  return value
}

function normalizeAuthorityOptions (options) {
  if (options == null) {
    return Object.freeze({
      expectedAuthorPublicKey: null,
      maxRecordKeyBytes: PEERIT_INNER_OPERATION_BATCH_V1_DEFAULT_MAX_RECORD_KEY_BYTES
    })
  }
  const descriptors = ownDataKeys(options, 'operation authority options')
  const keys = Object.keys(descriptors).sort()
  const allowed = new Set(['expectedAuthorPublicKey', 'maxRecordKeyBytes'])
  if (keys.some(key => !allowed.has(key))) {
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', 'operation authority options has an unknown field')
  }
  const expectedDescriptor = descriptors.expectedAuthorPublicKey
  const expectedAuthorPublicKey = expectedDescriptor == null || expectedDescriptor.value == null
    ? null
    : assertExpectedAuthor(expectedDescriptor.value)
  const maxRecordKeyDescriptor = descriptors.maxRecordKeyBytes
  const maxRecordKeyBytes = maxRecordKeyDescriptor == null || maxRecordKeyDescriptor.value == null
    ? PEERIT_INNER_OPERATION_BATCH_V1_DEFAULT_MAX_RECORD_KEY_BYTES
    : maxRecordKeyDescriptor.value
  if (!Number.isSafeInteger(maxRecordKeyBytes) || maxRecordKeyBytes < 1 ||
      maxRecordKeyBytes > PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATION_BYTES) {
    fail('PEERIT_OPERATION_BATCH_BAD_INPUT', 'maxRecordKeyBytes must be a bounded positive safe integer')
  }
  return Object.freeze({ expectedAuthorPublicKey, maxRecordKeyBytes })
}

function semanticTypeFor (operation) {
  const type = operation.type
  if (typeof type !== 'string' || type.length < 1 || type.length > 64) {
    fail('PEERIT_OPERATION_BATCH_BAD_OPERATION', 'operation type must be a bounded string')
  }
  if (!operation.data || typeof operation.data !== 'object' || Array.isArray(operation.data)) {
    fail('PEERIT_OPERATION_BATCH_BAD_OPERATION', 'operation data must be an object')
  }
  if (type === 'v2') {
    if (!V2_SEMANTIC_TYPES.has(operation.data._t)) {
      fail('PEERIT_OPERATION_BATCH_UNSUPPORTED_TYPE', 'v2 operation _t is outside the closed Peerit V1 type set')
    }
    return operation.data._t
  }
  if (!OPERATION_TYPES.has(type)) {
    fail('PEERIT_OPERATION_BATCH_UNSUPPORTED_TYPE', 'operation type is outside the closed Peerit V1 type set')
  }
  if (Object.hasOwn(operation.data, '_t')) {
    fail('PEERIT_OPERATION_BATCH_BAD_OPERATION', 'non-v2 operations must not carry a semantic _t override')
  }
  return type
}

function assertOperationMetadata (operation) {
  const data = operation.data
  if (typeof data.id !== 'string' || !data.id) {
    fail('PEERIT_OPERATION_BATCH_METADATA', 'operation data.id must be non-empty text')
  }
  if (!HEX_64_LOWER.test(data._k || '') || !HEX_128_LOWER.test(data._sig || '') ||
      !HEX_64_LOWER.test(data._dk || '') || data._ns !== 'peerit' || data._alg !== 'ed25519') {
    fail('PEERIT_OPERATION_BATCH_METADATA', 'operation signature metadata is not the exact Peerit Ed25519 shape')
  }
}

export function peeritOperationWireKeyV1 (operation) {
  if (!operation || typeof operation !== 'object' || typeof operation.type !== 'string' ||
      !operation.data || typeof operation.data !== 'object' || typeof operation.data.id !== 'string' ||
      !operation.data.id) {
    fail('PEERIT_OPERATION_BATCH_BAD_OPERATION', 'operation has no stable local reduction key')
  }
  return `${operation.type.replace(':', '!')}!${operation.data.id}`
}

function assertWireKeyBound (key, maximum) {
  if (textEncoder.encode(key).byteLength > maximum) {
    fail('PEERIT_OPERATION_BATCH_KEY_BOUND', 'operation wire key exceeds the active journal bound')
  }
}

async function assertOperationKeyBinding (operation, semanticType, key) {
  let expected
  try {
    if (operation.type === 'v2') {
      const opened = await unseal(operation.data.sealed)
      if (!isPlainObject(opened)) {
        fail('PEERIT_OPERATION_BATCH_KEY_BINDING', 'v2 operation sealed graph is not a plain object')
      }
      const record = {
        ...opened,
        _t: semanticType,
        author: operation.data._k,
        creator: operation.data._k,
        by: operation.data._k,
        slug: operation.data.slug != null ? operation.data.slug : opened.slug
      }
      expected = await expectedKeyV2(record)
    } else {
      expected = expectedKey(semanticType, operation.data)
      if (semanticType === 'blob' && !(await verifyBlobRecord(operation.data))) {
        fail('PEERIT_OPERATION_BATCH_KEY_BINDING', 'blob operation does not reproduce its content-addressed blob key')
      }
    }
  } catch (cause) {
    if (cause && cause.code === 'PEERIT_OPERATION_BATCH_KEY_BINDING') throw cause
    fail('PEERIT_OPERATION_BATCH_KEY_BINDING', 'operation cannot reproduce its signed storage key', cause)
  }
  if (typeof expected !== 'string' || expected !== key) {
    fail('PEERIT_OPERATION_BATCH_KEY_BINDING', 'operation wire key does not match its signed semantic fields')
  }
}

async function normalizeOperation (input, index, authorityOptions, seenKeys, budget) {
  const operation = snapshotOperation(input, `operations[${index}]`, budget)
  const semanticType = semanticTypeFor(operation)
  assertOperationMetadata(operation)
  const authorPublicKey = operation.data._k
  if (authorityOptions.expectedAuthorPublicKey != null && authorPublicKey !== authorityOptions.expectedAuthorPublicKey) {
    fail('PEERIT_OPERATION_BATCH_MIXED_AUTHOR', 'operation author does not equal the required author key')
  }
  const key = peeritOperationWireKeyV1(operation)
  assertWireKeyBound(key, authorityOptions.maxRecordKeyBytes)
  if (seenKeys.has(key)) fail('PEERIT_OPERATION_BATCH_DUPLICATE_VIEW_KEY', 'operation batch contains a duplicate local reduction key')
  let verified
  try {
    verified = await verifyRecord(operation.type, operation.data, semanticType)
  } catch (cause) {
    fail('PEERIT_OPERATION_BATCH_SIGNATURE', 'operation signature verification failed unexpectedly', cause)
  }
  if (verified !== 'ok') {
    fail('PEERIT_OPERATION_BATCH_SIGNATURE', 'operation is unsigned, forged, owner-mismatched, or unverifiable')
  }
  await assertOperationKeyBinding(operation, semanticType, key)
  seenKeys.add(key)
  return Object.freeze({ operation: deepFreeze(operation), authorPublicKey, key })
}

export async function normalizePeeritSignedOperationBatchV1 (operations, options = undefined) {
  const authorityOptions = normalizeAuthorityOptions(options)
  const inputs = snapshotOperationInputs(operations)
  const seenKeys = new Set()
  const normalized = []
  let authorPublicKey = authorityOptions.expectedAuthorPublicKey
  const snapshotBudget = canonicalBudget()
  for (let index = 0; index < inputs.length; index++) {
    const entry = await normalizeOperation(inputs[index], index, {
      ...authorityOptions,
      expectedAuthorPublicKey: authorPublicKey
    }, seenKeys, snapshotBudget)
    if (authorPublicKey == null) authorPublicKey = entry.authorPublicKey
    normalized.push(entry)
  }
  const cleanOperations = normalized.map(entry => entry.operation)
  const canonicalOperationBatch = canonicalValue(
    { version: 1, operations: cleanOperations },
    'operation batch',
    canonicalBudget()
  )
  const payloadBytes = textEncoder.encode(canonicalOperationBatch)
  if (payloadBytes.byteLength < 1 || payloadBytes.byteLength > PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATION_BYTES) {
    fail('PEERIT_OPERATION_BATCH_LENGTH', 'canonical operation batch is outside the VNext Cell payload range')
  }
  return Object.freeze({
    version: 1,
    authorPublicKey,
    canonicalOperationBatch,
    operations: Object.freeze(cleanOperations),
    operationWireKeys: Object.freeze(normalized.map(entry => entry.key))
  })
}

function assertEnvelopeHeader (innerCodec, value) {
  if (innerCodec !== PEERIT_INNER_OPERATION_BATCH_V1_CODEC) {
    fail('PEERIT_OPERATION_ENVELOPE_CODEC', 'inner codec is not PeeritInnerOperationBatchV1')
  }
  const bytes = new Uint8Array(asBytes(value, 'inner operation envelope'))
  if (bytes.byteLength < Number(PEERIT_INNER_OPERATION_BATCH_V1_MIN_BYTES) ||
      bytes.byteLength > Number(PEERIT_INNER_OPERATION_BATCH_V1_MAX_BYTES)) {
    fail('PEERIT_OPERATION_ENVELOPE_LENGTH', 'inner operation envelope is outside the VNext Cell range')
  }
  const tag = (bytes[0] << 8) | bytes[1]
  if (tag !== PEERIT_INNER_OPERATION_BATCH_V1_CODEC || bytes[2] !== PEERIT_INNER_OPERATION_BATCH_V1_VERSION) {
    fail('PEERIT_OPERATION_ENVELOPE_CODEC', 'inner operation envelope tag or version is invalid')
  }
  const payloadLength = (bytes[3] * 0x1000000) + (bytes[4] << 16) + (bytes[5] << 8) + bytes[6]
  if (payloadLength < 1 || payloadLength > PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATION_BYTES ||
      bytes.byteLength !== PEERIT_INNER_OPERATION_BATCH_V1_HEADER_BYTES + payloadLength) {
    fail('PEERIT_OPERATION_ENVELOPE_LENGTH', 'inner operation envelope length framing is invalid')
  }
  return Object.freeze({ bytes, payloadBytes: bytes.slice(PEERIT_INNER_OPERATION_BATCH_V1_HEADER_BYTES) })
}

export function hashPeeritInnerLogicalHashV1 (innerCodec, innerBytes) {
  const { bytes } = assertEnvelopeHeader(innerCodec, innerBytes)
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.logical-hash.v1'),
    u16Bytes(innerCodec),
    u64Bytes(bytes.byteLength),
    bytes
  ))
}

export function hashPeeritInnerCellEncodingCommitmentV1 (innerCodec, innerBytes, logicalHash, sizeClass) {
  const { bytes } = assertEnvelopeHeader(innerCodec, innerBytes)
  const expectedLogicalHash = hashPeeritInnerLogicalHashV1(innerCodec, bytes)
  const suppliedLogicalHash = new Uint8Array(asBytes(logicalHash, 'logicalHash'))
  if (suppliedLogicalHash.byteLength !== 32 || !bytesEqual(suppliedLogicalHash, expectedLogicalHash)) {
    fail('PEERIT_OPERATION_ENVELOPE_COMMITMENT', 'logical hash does not reproduce the exact inner operation envelope')
  }
  const expectedSizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(BigInt(bytes.byteLength))
  if (sizeClass !== expectedSizeClass) {
    fail('PEERIT_OPERATION_ENVELOPE_COMMITMENT', 'Cell size class is not the smallest class for the exact inner envelope')
  }
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.encoding.v1'),
    Uint8Array.of(1),
    expectedLogicalHash,
    u16Bytes(innerCodec),
    u64Bytes(bytes.byteLength),
    u32Bytes(1),
    blake2b256(bytes),
    Uint8Array.of(sizeClass)
  ))
}

function immutableEnvelope (normalized, innerBytes) {
  const canonicalBytes = new Uint8Array(innerBytes)
  const innerLength = BigInt(canonicalBytes.byteLength)
  const sizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(innerLength)
  const logicalHash = hashPeeritInnerLogicalHashV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, canonicalBytes)
  const encodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
    PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
    canonicalBytes,
    logicalHash,
    sizeClass
  )
  return Object.freeze({
    version: PEERIT_INNER_OPERATION_BATCH_V1_VERSION,
    innerCodec: PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
    innerLength,
    sizeClass,
    authorPublicKey: normalized.authorPublicKey,
    canonicalOperationBatch: normalized.canonicalOperationBatch,
    operations: normalized.operations,
    operationWireKeys: normalized.operationWireKeys,
    get innerBytes () { return new Uint8Array(canonicalBytes) },
    get logicalHash () { return new Uint8Array(logicalHash) },
    get encodingCommitment () { return new Uint8Array(encodingCommitment) }
  })
}

export async function createPeeritInnerOperationBatchV1 (operations, options = undefined) {
  const normalized = await normalizePeeritSignedOperationBatchV1(operations, options)
  const payloadBytes = textEncoder.encode(normalized.canonicalOperationBatch)
  const innerBytes = concatBytes(
    u16Bytes(PEERIT_INNER_OPERATION_BATCH_V1_CODEC),
    Uint8Array.of(PEERIT_INNER_OPERATION_BATCH_V1_VERSION),
    u32Bytes(payloadBytes.byteLength),
    payloadBytes
  )
  return immutableEnvelope(normalized, innerBytes)
}

export async function decodePeeritInnerOperationBatchV1 (innerCodec, innerBytes, options = undefined) {
  const { bytes, payloadBytes } = assertEnvelopeHeader(innerCodec, innerBytes)
  let canonicalOperationBatch
  try { canonicalOperationBatch = textDecoder.decode(payloadBytes) } catch (cause) {
    fail('PEERIT_OPERATION_ENVELOPE_UTF8', 'inner operation batch payload is not valid UTF-8', cause)
  }
  let parsed
  try {
    parsed = JSON.parse(canonicalOperationBatch)
  } catch (cause) {
    fail('PEERIT_OPERATION_BATCH_NONCANONICAL', 'inner operation batch payload is not JSON', cause)
  }
  if (!isPlainObject(parsed) || parsed.version !== 1 || !Array.isArray(parsed.operations)) {
    fail('PEERIT_OPERATION_BATCH_NONCANONICAL', 'inner operation batch payload has an unsupported shape')
  }
  const normalized = await normalizePeeritSignedOperationBatchV1(parsed.operations, options)
  if (normalized.canonicalOperationBatch !== canonicalOperationBatch) {
    fail('PEERIT_OPERATION_BATCH_NONCANONICAL', 'inner operation batch payload is not the exact canonical operation encoding')
  }
  return immutableEnvelope(normalized, bytes)
}
