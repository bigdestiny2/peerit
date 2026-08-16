// Bounded transactional journal for Peerit's local-first blind-substrate path.
// All mutation methods are single backend transactions, so IndexedDB provides
// cross-tab CAS even where navigator.locks is absent. The deterministic memory
// backend runs the exact same journal logic in tests.

import { hashHex } from '../crypto.js'
import { verifyRecord } from '../verify.js'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  hashPeeritInnerCellEncodingCommitmentV1,
  hashPeeritInnerLogicalHashV1,
  hashPeeritInnerOperationIntentIdV1
} from './peerit-operation-authority-v1.js'
import { asBytes, bytesEqual } from './release-control-primitives.mjs'
import {
  IndexedDbJournalBackend,
  JOURNAL_MARKER_KEY,
  JOURNAL_STORES,
  MemoryJournalBackend,
  createMemoryJournalState
} from './peerit-journal-backend.js'

export const PEERIT_JOURNAL_SCHEMA_VERSION = 3
export const LEGACY_SUBSTRATE_STATE_KEY = 'peerit:substrate-sync:v1'
export const PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1 = 'peerit-inner-operation-batch-v1'
export const PEERIT_LEGACY_JSON_QUARANTINE_FORMAT_V1 = 'legacy-json-v1-quarantined'

export const JOURNAL_LIMITS = Object.freeze({
  maxIntentBytes: 1_048_519,
  maxIntentBytesTotal: 64 * 1024 * 1024,
  maxIntents: 10_000,
  maxViewRecords: 100_000,
  maxRecordsPerIntent: 64,
  maxTargetsPerIntent: 16,
  maxRecordKeyBytes: 4096,
  maxTargetIdBytes: 4096,
  maxEvidenceRefBytes: 1024,
  maxDedupeRecords: 50_000,
  deliveryBatch: 256,
  compactionBatch: 256,
  acknowledgedRetentionMs: 30 * 24 * 60 * 60 * 1000,
  dedupeRetentionMs: 365 * 24 * 60 * 60 * 1000
})

const META_KEY = 'state'
const PREVIOUS_JOURNAL_SCHEMA_VERSION = 2
const ACKNOWLEDGED = new Set(['acknowledged', 'readback-verified'])
const RETRY_DUE_STATES = new Set(['retryable', 'pending-unknown'])
const TARGET_STATES = Object.freeze([
  'preparing', 'delivering', 'pending-unknown', 'retryable',
  'terminal', 'acknowledged', 'readback-verified'
])
const HEX64 = /^[0-9a-f]{64}$/
const DISCOVERY_FLOOR_PREFIX = 'discovery-floor:v1:'
const SEQ29_PUBLIC_INBOX_BOOTSTRAP_FLOOR_PREFIX = 'seq29-public-inbox-bootstrap-floor:v1:'
const SEQ29_PUBLIC_INBOX_STATE_PREFIX = 'seq29-public-inbox-state:v1:'
const SEQ29_PUBLICATION_AUTHOR_HEAD_PREFIX = 'seq29-publication-author-head:v1:'
const SEQ29_PUBLICATION_INTENT_PREFIX = 'seq29-publication-intent:v1:'
const SEQ29_PUBLIC_INBOX_RELEASE_SEQUENCE = 29

function clone (value) {
  if (value == null) return value
  if (value instanceof Uint8Array) return new Uint8Array(value)
  if (value instanceof ArrayBuffer) return value.slice(0)
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength))
  }
  if (typeof structuredClone === 'function') return structuredClone(value)
  if (Array.isArray(value)) return value.map(clone)
  if (typeof value === 'object') {
    const output = {}
    for (const [key, child] of Object.entries(value)) output[key] = clone(child)
    return output
  }
  return value
}

function byteLength (value) { return new TextEncoder().encode(String(value)).byteLength }

function bytesCopy (value, field) {
  try { return new Uint8Array(asBytes(value, field)) } catch (cause) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} must be bytes.`, cause)
  }
}

function bytesToHex (value) {
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

function intentPayloadByteLength (intent) {
  if (intent && intent.wireFormat === PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1) {
    return Number(intent.innerLength)
  }
  if (intent && intent.wireFormat === PEERIT_LEGACY_JSON_QUARANTINE_FORMAT_V1) {
    return byteLength(intent.legacyOperationBytes)
  }
  return byteLength(intent && intent.operationBytes)
}

function journalError (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause) error.cause = cause
  return error
}

function mapStorageError (error, context) {
  if (error && error.code && String(error.code).startsWith('PEERIT_JOURNAL_')) return error
  if (error && (error.name === 'QuotaExceededError' || error.code === 22 || error.code === 1014)) {
    return journalError('PEERIT_JOURNAL_QUOTA', `Peerit local journal quota was exceeded during ${context}.`, error)
  }
  if (error && (error.name === 'UnknownError' || error.name === 'InvalidStateError' || error.name === 'VersionError')) {
    return journalError('PEERIT_JOURNAL_STORAGE_UNAVAILABLE', `Peerit IndexedDB failed during ${context}.`, error)
  }
  return journalError('PEERIT_JOURNAL_TRANSACTION_FAILED', `Peerit local journal transaction failed during ${context}.`, error)
}

function emptyTargetCounts () {
  return Object.fromEntries(TARGET_STATES.map(state => [state, 0]))
}

function emptyMeta () {
  return {
    key: META_KEY,
    schemaVersion: PEERIT_JOURNAL_SCHEMA_VERSION,
    revision: 0,
    viewRevision: 0,
    viewRecordCount: 0,
    intentCount: 0,
    pendingIntentCount: 0,
    dedupeCount: 0,
    intentBytes: 0,
    quarantinedIntentCount: 0,
    quarantinedIntentBytes: 0,
    latestIntentId: null,
    latestCreatedAt: 0,
    targetStateCounts: emptyTargetCounts(),
    legacyImportHash: null,
    legacyImportSource: null,
    createdAt: 0,
    updatedAt: 0
  }
}

function validateMeta (value) {
  if (value == null) return emptyMeta()
  const integers = [
    'revision', 'viewRevision', 'viewRecordCount', 'intentCount',
    'pendingIntentCount', 'dedupeCount', 'intentBytes', 'quarantinedIntentCount',
    'quarantinedIntentBytes', 'latestCreatedAt'
  ]
  if (!value || value.key !== META_KEY || value.schemaVersion !== PEERIT_JOURNAL_SCHEMA_VERSION ||
    integers.some(field => !Number.isSafeInteger(value[field]) || value[field] < 0) ||
    !value.targetStateCounts || typeof value.targetStateCounts !== 'object') {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit journal metadata is corrupt or from an unsupported schema.')
  }
  for (const state of TARGET_STATES) {
    if (!Number.isSafeInteger(value.targetStateCounts[state]) || value.targetStateCounts[state] < 0) {
      throw journalError('PEERIT_JOURNAL_CORRUPT', `Peerit journal target counter ${state} is corrupt.`)
    }
  }
  if (value.quarantinedIntentCount > value.intentCount) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit journal quarantine counters are inconsistent.')
  }
  if (value.quarantinedIntentBytes > value.intentBytes) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit journal quarantine byte counters are inconsistent.')
  }
  return clone(value)
}

// Schema V2 carried raw JSON operation strings. It remains recognizable only
// long enough for an atomic, fail-closed conversion to the local quarantine
// format below; it is never accepted by ordinary journal mutation paths.
function validatePreviousMetaForMigration (value) {
  const integers = [
    'revision', 'viewRevision', 'viewRecordCount', 'intentCount',
    'pendingIntentCount', 'dedupeCount', 'intentBytes', 'latestCreatedAt',
    'createdAt', 'updatedAt'
  ]
  if (!value || value.key !== META_KEY || value.schemaVersion !== PREVIOUS_JOURNAL_SCHEMA_VERSION ||
      integers.some(field => !Number.isSafeInteger(value[field]) || value[field] < 0) ||
      !value.targetStateCounts || typeof value.targetStateCounts !== 'object') {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit journal metadata is corrupt or from an unsupported schema.')
  }
  for (const state of TARGET_STATES) {
    if (!Number.isSafeInteger(value.targetStateCounts[state]) || value.targetStateCounts[state] < 0) {
      throw journalError('PEERIT_JOURNAL_CORRUPT', `Peerit journal target counter ${state} is corrupt.`)
    }
  }
  return clone(value)
}

function validateIntentId (value, field = 'intentId') {
  const normalized = String(value || '').toLowerCase()
  if (!HEX64.test(normalized)) throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} must be 32-byte lowercase hex.`)
  return normalized
}

function boundedString (value, field, maximum, { allowEmpty = false } = {}) {
  const normalized = String(value == null ? '' : value)
  if ((!allowEmpty && !normalized) || byteLength(normalized) > maximum) {
    throw journalError('PEERIT_JOURNAL_LIMIT', `${field} exceeds its journal bound.`)
  }
  return normalized
}

function discoveredRecordTimestamp (value) {
  const candidates = [value && value.editedAt, value && value.updatedAt, value && value.ts, value && value.createdAt]
  for (const candidate of candidates) {
    if (Number.isSafeInteger(candidate) && candidate >= 0) return candidate
  }
  return 0
}

function discoveredRecordWins (incoming, current) {
  if (!current) return true
  if (incoming && current && incoming._sig === current._sig) return false
  // Community ownership is sticky once a signed row has been admitted locally.
  if (incoming && current && incoming._t === 'community' && current._t === 'community' &&
      (incoming.creator || incoming._k) !== (current.creator || current._k)) return false
  const left = discoveredRecordTimestamp(incoming)
  const right = discoveredRecordTimestamp(current)
  if (left !== right) return left > right
  return String((incoming && incoming._sig) || '') > String((current && current._sig) || '')
}

function discoveryFloorKey (sourceId) {
  return DISCOVERY_FLOOR_PREFIX + validateIntentId(sourceId, 'discovery sourceId')
}

function seq29PublicInboxHex (value, field) {
  const normalized = String(value || '')
  if (!HEX64.test(normalized)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} must be 32-byte lowercase hex.`)
  }
  return normalized
}

function seq29PublicInboxDecimal (value, field) {
  let parsed
  try { parsed = typeof value === 'bigint' ? value : BigInt(value) } catch (cause) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} must be an unsigned integer.`, cause)
  }
  if (parsed < 0n || parsed > ((1n << 64n) - 1n)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} must fit unsigned 64-bit storage.`)
  }
  return parsed
}

function seq29PublicInboxRelayId (value) {
  const relayId = String(value || '')
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(relayId)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 public INBOX relayId is invalid.')
  }
  return relayId
}

function seq29PublicInboxBootstrapFloorKey (authorityPublicKey) {
  return SEQ29_PUBLIC_INBOX_BOOTSTRAP_FLOOR_PREFIX +
    seq29PublicInboxHex(authorityPublicKey, 'Seq29 public INBOX authorityPublicKey')
}

function seq29PublicInboxStateKey (authorityPublicKey, completeSignedWrapperHash) {
  return SEQ29_PUBLIC_INBOX_STATE_PREFIX +
    seq29PublicInboxHex(authorityPublicKey, 'Seq29 public INBOX authorityPublicKey') + ':' +
    seq29PublicInboxHex(completeSignedWrapperHash, 'Seq29 public INBOX completeSignedWrapperHash')
}

function normalizeSeq29PublicInboxBootstrap (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      input.releaseSequence !== SEQ29_PUBLIC_INBOX_RELEASE_SEQUENCE) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 public INBOX bootstrap identity is invalid.')
  }
  const authorityPublicKey = seq29PublicInboxHex(
    input.authorityPublicKey, 'Seq29 public INBOX authorityPublicKey')
  const completeSignedWrapperHash = seq29PublicInboxHex(
    input.completeSignedWrapperHash, 'Seq29 public INBOX completeSignedWrapperHash')
  const bootstrapSequence = seq29PublicInboxDecimal(
    input.bootstrapSequence, 'Seq29 public INBOX bootstrapSequence')
  if (!Array.isArray(input.relayIds) || input.relayIds.length !== 2) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 public INBOX bootstrap must bind exactly two relays.')
  }
  const relayIds = input.relayIds.map(seq29PublicInboxRelayId).sort()
  if (relayIds[0] === relayIds[1]) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 public INBOX relay IDs must be distinct.')
  }
  return Object.freeze({
    releaseSequence: SEQ29_PUBLIC_INBOX_RELEASE_SEQUENCE,
    authorityPublicKey,
    completeSignedWrapperHash,
    bootstrapSequence,
    relayIds: Object.freeze(relayIds)
  })
}

function validateSeq29PublicInboxBootstrapFloor (value, authorityPublicKey) {
  if (!value || value.schema !== 'PeeritSeq29PublicInboxBootstrapFloorV1' || value.version !== 1 ||
      value.authorityPublicKey !== authorityPublicKey ||
      !/^(0|[1-9][0-9]*)$/.test(value.highestAcceptedBootstrapSequence || '') ||
      !HEX64.test(value.completeSignedWrapperHash || '')) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 public INBOX bootstrap floor is corrupt.')
  }
  return value
}

function validateSeq29PublicInboxState (value, bootstrap) {
  if (!value || value.schema !== 'PeeritSeq29PublicInboxStateV1' || value.version !== 1 ||
      value.releaseSequence !== SEQ29_PUBLIC_INBOX_RELEASE_SEQUENCE ||
      value.authorityPublicKey !== bootstrap.authorityPublicKey ||
      value.completeSignedWrapperHash !== bootstrap.completeSignedWrapperHash ||
      value.bootstrapSequence !== String(bootstrap.bootstrapSequence) ||
      !Array.isArray(value.relays) || value.relays.length !== 2) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 public INBOX append-floor state is corrupt.')
  }
  const relayIds = []
  for (const relay of value.relays) {
    const relayId = seq29PublicInboxRelayId(relay && relay.relayId)
    if (!/^(0|[1-9][0-9]*)$/.test(relay.appendRevision || '') ||
        !/^(0|[1-9][0-9]*)$/.test(relay.previousAppendRevision || '') ||
        (relay.observationHash != null && !HEX64.test(relay.observationHash))) {
      throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 public INBOX relay append floor is corrupt.')
    }
    if (BigInt(relay.previousAppendRevision) > BigInt(relay.appendRevision) ||
        (BigInt(relay.appendRevision) === 0n && relay.observationHash != null)) {
      throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 public INBOX relay transition is inconsistent.')
    }
    relayIds.push(relayId)
  }
  relayIds.sort()
  if (relayIds[0] === relayIds[1] ||
      relayIds.some((relayId, index) => relayId !== bootstrap.relayIds[index])) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 public INBOX relay set differs from its signed bootstrap.')
  }
  return clone(value)
}

function seq29PublicInboxBootstrapFloorValue (floor) {
  return Object.freeze({
    schema: 'PeeritLimitedPublicInboxBootstrapFloorV1',
    version: 1,
    highestAcceptedBootstrapSequence: floor.highestAcceptedBootstrapSequence,
    completeSignedWrapperHash: floor.completeSignedWrapperHash
  })
}

function seq29PublicationScope (input) {
  const bootstrap = normalizeSeq29PublicInboxBootstrap(input)
  const authorPublicKey = seq29PublicInboxHex(
    input.authorPublicKey, 'Seq29 publication authorPublicKey')
  return Object.freeze({ ...bootstrap, authorPublicKey })
}

function seq29PublicationAuthorHeadKey (scope) {
  return SEQ29_PUBLICATION_AUTHOR_HEAD_PREFIX + scope.authorityPublicKey + ':' +
    scope.completeSignedWrapperHash + ':' + scope.authorPublicKey
}

function seq29PublicationIntentKey (scope, logicalHash) {
  return SEQ29_PUBLICATION_INTENT_PREFIX + scope.authorityPublicKey + ':' +
    scope.completeSignedWrapperHash + ':' + scope.authorPublicKey + ':' +
    seq29PublicInboxHex(logicalHash, 'Seq29 publication logicalHash')
}

function validateSeq29PublicationHead (value, scope) {
  if (value == null) {
    return Object.freeze({
      nextAuthorSequence: 0n,
      previousAuthorRecordId: null
    })
  }
  if (value.schema !== 'PeeritSeq29PublicationAuthorHeadV1' || value.version !== 1 ||
      value.authorityPublicKey !== scope.authorityPublicKey ||
      value.completeSignedWrapperHash !== scope.completeSignedWrapperHash ||
      value.authorPublicKey !== scope.authorPublicKey ||
      !/^(0|[1-9][0-9]*)$/.test(value.nextAuthorSequence || '') ||
      (value.previousAuthorRecordId != null && !HEX64.test(value.previousAuthorRecordId))) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication author head is corrupt.')
  }
  const nextAuthorSequence = BigInt(value.nextAuthorSequence)
  if ((nextAuthorSequence === 0n) !== (value.previousAuthorRecordId == null)) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication author head continuity is corrupt.')
  }
  return Object.freeze({
    nextAuthorSequence,
    previousAuthorRecordId: value.previousAuthorRecordId
  })
}

function seq29PublicationBytes (value, field, minimum, maximum) {
  const output = bytesCopy(value, field)
  if (output.byteLength < minimum || output.byteLength > maximum) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} is outside its byte bound.`)
  }
  return output
}

function normalizeSeq29PreparedRelay (value, relayIds, field) {
  const relayId = seq29PublicInboxRelayId(value && value.relayId)
  if (!relayIds.includes(relayId)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} relay is absent from the signed bootstrap.`)
  }
  if (!value.request || typeof value.request !== 'object' || Array.isArray(value.request)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', `${field} exact APPEND request is required.`)
  }
  return {
    relayId,
    frame: seq29PublicationBytes(value.frame, `${field} frame`, 4096, 4096),
    request: clone(value.request),
    requestBytes: seq29PublicationBytes(
      value.requestBytes, `${field} requestBytes`, 1, 32 * 1024),
    requestCommitment: seq29PublicationBytes(
      value.requestCommitment, `${field} requestCommitment`, 32, 32),
    stage: 'prepared',
    attemptToken: null,
    leaseUntil: 0,
    attempts: 0,
    result: null,
    lastError: null,
    updatedAt: 0
  }
}

function seq29PublicationValueEqual (left, right) {
  if (left instanceof Uint8Array || right instanceof Uint8Array) {
    return left instanceof Uint8Array && right instanceof Uint8Array && bytesEqual(left, right)
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((value, index) => seq29PublicationValueEqual(value, right[index]))
  }
  if (left && right && typeof left === 'object' && typeof right === 'object') {
    const leftKeys = Object.keys(left).sort()
    const rightKeys = Object.keys(right).sort()
    return leftKeys.length === rightKeys.length &&
      leftKeys.every((key, index) => key === rightKeys[index] &&
        seq29PublicationValueEqual(left[key], right[key]))
  }
  return Object.is(left, right)
}

function seq29PreparedRelayConflict (left, right) {
  if (left.relayId !== right.relayId) return 'relayId'
  if (!bytesEqual(left.frame, right.frame)) return 'frame'
  if (!seq29PublicationValueEqual(left.request, right.request)) return 'request'
  if (!bytesEqual(left.requestBytes, right.requestBytes)) return 'requestBytes'
  if (!bytesEqual(left.requestCommitment, right.requestCommitment)) return 'requestCommitment'
  return null
}

function validateSeq29PublicationIntent (value, scope = null) {
  if (!value || value.schema !== 'PeeritSeq29PublicationIntentV1' || value.version !== 1 ||
      value.releaseSequence !== SEQ29_PUBLIC_INBOX_RELEASE_SEQUENCE ||
      !HEX64.test(value.authorityPublicKey || '') ||
      !HEX64.test(value.completeSignedWrapperHash || '') ||
      !HEX64.test(value.authorPublicKey || '') || !HEX64.test(value.logicalHash || '') ||
      !HEX64.test(value.authorRecordId || '') ||
      !/^(0|[1-9][0-9]*)$/.test(value.authorSequence || '') ||
      (value.previousAuthorRecordId != null && !HEX64.test(value.previousAuthorRecordId)) ||
      !Array.isArray(value.relays) || value.relays.length !== 2 ||
      !(value.announcementBytes instanceof Uint8Array) ||
      value.announcementBytes.byteLength < 1 || value.announcementBytes.byteLength > 12288 ||
      !Number.isSafeInteger(value.createdAt) || value.createdAt < 0 ||
      !Number.isSafeInteger(value.updatedAt) || value.updatedAt < 0 ||
      !Number.isSafeInteger(value.completedAt) || value.completedAt < 0) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication intent is corrupt.')
  }
  if (scope && (value.authorityPublicKey !== scope.authorityPublicKey ||
      value.completeSignedWrapperHash !== scope.completeSignedWrapperHash ||
      value.authorPublicKey !== scope.authorPublicKey)) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication intent crossed its authority scope.')
  }
  const sequence = BigInt(value.authorSequence)
  if ((sequence === 0n) !== (value.previousAuthorRecordId == null)) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication author continuity is corrupt.')
  }
  const seen = new Set()
  for (const relay of value.relays) {
    const relayId = seq29PublicInboxRelayId(relay && relay.relayId)
    if (seen.has(relayId) || !['prepared', 'sending', 'reconciling', 'pending-unknown', 'succeeded'].includes(relay.stage) ||
        !(relay.frame instanceof Uint8Array) || relay.frame.byteLength !== 4096 ||
        !relay.request || typeof relay.request !== 'object' ||
        !(relay.requestBytes instanceof Uint8Array) || relay.requestBytes.byteLength < 1 ||
        !(relay.requestCommitment instanceof Uint8Array) || relay.requestCommitment.byteLength !== 32 ||
        (relay.attemptToken != null && typeof relay.attemptToken !== 'string') ||
        !Number.isSafeInteger(relay.leaseUntil) || relay.leaseUntil < 0 ||
        !Number.isSafeInteger(relay.attempts) || relay.attempts < 0) {
      throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication relay intent is corrupt.')
    }
    if ((relay.stage === 'succeeded') !== (relay.result != null)) {
      throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication relay outcome is inconsistent.')
    }
    seen.add(relayId)
  }
  if ((value.completedAt > 0) !== value.relays.every(relay => relay.stage === 'succeeded')) {
    throw journalError('PEERIT_JOURNAL_CORRUPT', 'Seq29 publication completion is inconsistent.')
  }
  return clone(value)
}

function normalizedInnerIntent (input, limits) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'VNext intent must be an object.')
  }
  if (input.wireFormat != null && input.wireFormat !== PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'VNext intent wire format is unsupported.')
  }
  if (input.innerCodec !== PEERIT_INNER_OPERATION_BATCH_V1_CODEC) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'VNext intent must use PeeritInnerOperationBatchV1.')
  }
  const innerBytes = bytesCopy(input.innerBytes, 'innerBytes')
  const innerLength = typeof input.innerLength === 'bigint' ? Number(input.innerLength) : input.innerLength
  if (!Number.isSafeInteger(innerLength) || innerLength < 1 || innerLength !== innerBytes.byteLength ||
      innerLength > limits.maxIntentBytes) {
    throw journalError('PEERIT_JOURNAL_LIMIT', 'VNext exact inner envelope is outside the active journal bound.')
  }
  const logicalHash = bytesCopy(input.logicalHash, 'logicalHash')
  const encodingCommitment = bytesCopy(input.encodingCommitment, 'encodingCommitment')
  if (logicalHash.byteLength !== 32 || encodingCommitment.byteLength !== 32 ||
      !Number.isSafeInteger(input.sizeClass) || input.sizeClass < 1 || input.sizeClass > 5) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'VNext intent commitment metadata has an invalid shape.')
  }
  let expectedLogicalHash
  let expectedEncodingCommitment
  let expectedIntentHash
  try {
    expectedLogicalHash = hashPeeritInnerLogicalHashV1(input.innerCodec, innerBytes)
    expectedEncodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
      input.innerCodec,
      innerBytes,
      expectedLogicalHash,
      input.sizeClass
    )
    expectedIntentHash = hashPeeritInnerOperationIntentIdV1(input.innerCodec, innerBytes)
  } catch (cause) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'VNext inner envelope or commitments are malformed.', cause)
  }
  if (!bytesEqual(logicalHash, expectedLogicalHash) || !bytesEqual(encodingCommitment, expectedEncodingCommitment)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'VNext intent commitments do not reproduce the exact inner envelope.')
  }
  const intentId = validateIntentId(input.intentId)
  const logicalId = validateIntentId(input.logicalId, 'logicalId')
  if (intentId !== bytesToHex(expectedIntentHash) || logicalId !== bytesToHex(expectedLogicalHash)) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'VNext intent identifiers do not reproduce its exact envelope.')
  }
  return Object.freeze({
    wireFormat: PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
    innerCodec: input.innerCodec,
    innerBytes,
    innerLength,
    logicalHash,
    encodingCommitment,
    sizeClass: input.sizeClass,
    intentId,
    logicalId
  })
}

function sameInnerIntent (stored, input) {
  return !!(stored && stored.wireFormat === PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1 &&
    stored.innerCodec === input.innerCodec && stored.innerLength === input.innerLength &&
    stored.sizeClass === input.sizeClass &&
    bytesEqual(stored.innerBytes, input.innerBytes) &&
    bytesEqual(stored.logicalHash, input.logicalHash) &&
    bytesEqual(stored.encodingCommitment, input.encodingCommitment))
}

function sameInnerDedupe (stored, input) {
  return !!(stored && stored.wireFormat === PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1 &&
    stored.innerCodec === input.innerCodec && stored.innerLength === input.innerLength &&
    stored.sizeClass === input.sizeClass &&
    bytesEqual(stored.logicalHash, input.logicalHash) &&
    bytesEqual(stored.encodingCommitment, input.encodingCommitment))
}

function targetKey (intentId, targetId) { return `${intentId}\u0000${targetId}` }

const MAX_INDEX_NUMBER = Number.MAX_SAFE_INTEGER
const MAX_INDEX_STRING = '\uffff'

function targetStateDueBounds (targetId, state, upperDue = MAX_INDEX_NUMBER) {
  return {
    lower: [targetId, state, 0, 0, 0, ''],
    upper: [targetId, state, upperDue, MAX_INDEX_NUMBER, MAX_INDEX_NUMBER, MAX_INDEX_STRING]
  }
}

function targetStateLeaseBounds (targetId, state) {
  return {
    lower: [targetId, state, 0, ''],
    upper: [targetId, state, MAX_INDEX_NUMBER, MAX_INDEX_STRING]
  }
}

function stateLeaseBounds (state, upperLease) {
  return {
    lower: [state, 0, '', ''],
    upper: [state, upperLease, MAX_INDEX_STRING, MAX_INDEX_STRING]
  }
}

function pendingOrderKey (createdAt, intentId) {
  if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'createdAt must be a non-negative safe integer.')
  }
  return `${String(createdAt).padStart(16, '0')}!${intentId}`
}

function nonNegativeInteger (value, fallback = 0) {
  return Number.isSafeInteger(value) && value >= 0 ? value : fallback
}

function normalizedAttempts (value) {
  return Number.isSafeInteger(value) && value >= 1 ? value : 1
}

function retryDueAt (options, attempts) {
  if (options.nextAttemptAt != null) {
    if (!Number.isSafeInteger(options.nextAttemptAt) || options.nextAttemptAt < 0) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'nextAttemptAt must be a non-negative safe integer.')
    }
    return options.nextAttemptAt
  }
  if (!Number.isSafeInteger(options.now) || options.now < 0) {
    throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'retry scheduling requires a non-negative now timestamp.')
  }
  const base = Number.isSafeInteger(options.retryBaseMs) && options.retryBaseMs > 0 ? options.retryBaseMs : 1000
  const maximum = Number.isSafeInteger(options.retryMaxMs) && options.retryMaxMs >= base ? options.retryMaxMs : Math.max(base, 60_000)
  const exponent = Math.max(0, Math.min(16, normalizedAttempts(attempts) - 1))
  const delay = Math.min(maximum, base * (2 ** exponent))
  return Math.min(MAX_INDEX_NUMBER, options.now + delay)
}

function bumpTargetCount (meta, before, after) {
  if (before && TARGET_STATES.includes(before)) meta.targetStateCounts[before]--
  if (after && TARGET_STATES.includes(after)) meta.targetStateCounts[after]++
  for (const state of TARGET_STATES) {
    if (meta.targetStateCounts[state] < 0) throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit target-state counters underflowed.')
  }
}

function legacyState (raw) {
  let state
  try { state = typeof raw === 'string' ? JSON.parse(raw) : clone(raw) } catch (error) {
    throw journalError('PEERIT_JOURNAL_LEGACY_CORRUPT', 'Legacy Peerit publication state is not valid JSON.', error)
  }
  if (!state || state.version !== 1 || !Number.isSafeInteger(state.revision) ||
    !state.view || typeof state.view !== 'object' || Array.isArray(state.view) ||
    !state.intents || typeof state.intents !== 'object' || Array.isArray(state.intents)) {
    throw journalError('PEERIT_JOURNAL_LEGACY_CORRUPT', 'Legacy Peerit publication state has an unsupported shape.')
  }
  return state
}

function stableLegacyValue (value) {
  if (value === null) return 'null'
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw journalError('PEERIT_JOURNAL_LEGACY_UNVERIFIED', 'Legacy operation contains a non-finite number.')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return '[' + value.map(stableLegacyValue).join(',') + ']'
  if (!value || typeof value !== 'object') {
    throw journalError('PEERIT_JOURNAL_LEGACY_UNVERIFIED', 'Legacy operation contains an unsupported value.')
  }
  const keys = Object.keys(value).filter(key => value[key] !== undefined).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stableLegacyValue(value[key])).join(',') + '}'
}

function legacyViewKey (operation) {
  if (!operation || typeof operation.type !== 'string' || !operation.type ||
      !operation.data || typeof operation.data !== 'object' || operation.data.id == null) {
    throw journalError('PEERIT_JOURNAL_LEGACY_UNVERIFIED', 'Legacy operation shape is not a signed Peerit record.')
  }
  return operation.type.replace(':', '!') + '!' + operation.data.id
}

function legacyUnverified (message, cause) {
  return journalError('PEERIT_JOURNAL_LEGACY_UNVERIFIED', message, cause)
}

async function verifyLegacyIntentForQuarantine (sourceIntentId, legacy, limits, now) {
  if (!legacy || typeof legacy !== 'object' || Array.isArray(legacy)) {
    throw legacyUnverified('Legacy intent is not an object.')
  }
  const operationBytes = boundedString(legacy.operationBytes, 'legacy operationBytes', limits.maxIntentBytes)
  let decoded
  try { decoded = JSON.parse(operationBytes) } catch (error) {
    throw legacyUnverified('Legacy intent bytes are not valid JSON.', error)
  }
  if (!decoded || decoded.version !== 1 || !Array.isArray(decoded.operations) ||
      decoded.operations.length < 1 || decoded.operations.length > limits.maxRecordsPerIntent ||
      stableLegacyValue(decoded) !== operationBytes) {
    throw legacyUnverified('Legacy intent bytes are noncanonical or outside the signed operation bounds.')
  }
  const expectedIntentId = await hashHex('peerit.substrate.intent.v1|' + operationBytes)
  const expectedLogicalId = await hashHex('peerit.substrate.logical.v1|' + operationBytes)
  const intentId = validateIntentId(legacy.intentId)
  const logicalId = validateIntentId(legacy.logicalId, 'logicalId')
  if (String(sourceIntentId).toLowerCase() !== intentId || intentId !== expectedIntentId || logicalId !== expectedLogicalId) {
    throw legacyUnverified('Legacy intent identifiers do not match the exact signed operation bytes.')
  }
  const recordKeys = []
  const records = []
  const seen = new Set()
  for (const operation of decoded.operations) {
    const key = boundedString(legacyViewKey(operation), 'legacy reduced view key', limits.maxRecordKeyBytes)
    if (seen.has(key)) throw legacyUnverified('Legacy intent contains duplicate reduced view keys.')
    seen.add(key)
    const semanticType = operation.type === 'v2' ? operation.data._t : operation.type
    if ((await verifyRecord(operation.type, operation.data, semanticType)) !== 'ok') {
      throw legacyUnverified('Legacy intent contains an unsigned, forged, or owner-mismatched record.')
    }
    recordKeys.push(key)
    records.push({ key, value: clone(operation.data) })
  }
  const claimedKeys = Array.isArray(legacy.recordKeys) ? legacy.recordKeys.map(String) : []
  if (claimedKeys.length !== recordKeys.length || claimedKeys.some((key, index) => key !== recordKeys[index])) {
    throw legacyUnverified('Legacy intent record keys do not match its verified operation reduction.')
  }
  return Object.freeze({
    intentId,
    logicalId,
    operationBytes,
    recordKeys: Object.freeze(recordKeys),
    records: Object.freeze(records),
    createdAt: nonNegativeInteger(legacy.createdAt, now),
    updatedAt: nonNegativeInteger(legacy.updatedAt, nonNegativeInteger(legacy.createdAt, now))
  })
}

function quarantinedLegacyIntent (verified, now) {
  return {
    intentId: verified.intentId,
    logicalId: verified.logicalId,
    wireFormat: PEERIT_LEGACY_JSON_QUARANTINE_FORMAT_V1,
    legacyOperationBytes: verified.operationBytes,
    recordKeys: [...verified.recordKeys],
    createdAt: verified.createdAt,
    updatedAt: verified.updatedAt,
    discoveryState: 'legacy-quarantined',
    targetCount: 0,
    acknowledgedTargets: 0,
    readbackVerified: 0,
    policyDurable: false,
    completedAt: 0,
    quarantinedAt: now
  }
}

async function validateLegacyForImport (state, limits, now) {
  const sourceView = Object.entries(state.view)
  const sourceIntents = Object.entries(state.intents)
  if (sourceView.length > limits.maxViewRecords || sourceIntents.length > limits.maxIntents) {
    throw journalError('PEERIT_JOURNAL_LIMIT', 'Legacy Peerit journal exceeds bounded migration limits.')
  }
  for (const [key] of sourceView) boundedString(key, 'legacy view key', limits.maxRecordKeyBytes)
  const reducedView = new Map()
  const intents = []
  let intentBytes = 0
  const sorted = sourceIntents.sort(([, left], [, right]) => {
    const created = nonNegativeInteger(left && left.createdAt, now) - nonNegativeInteger(right && right.createdAt, now)
    return created || String(left && left.intentId).localeCompare(String(right && right.intentId))
  })
  for (const [sourceIntentId, legacy] of sorted) {
    const verified = await verifyLegacyIntentForQuarantine(sourceIntentId, legacy, limits, now)
    for (const record of verified.records) {
      reducedView.set(record.key, { key: record.key, value: clone(record.value), intentId: verified.intentId })
    }
    intentBytes += byteLength(verified.operationBytes)
    if (intentBytes > limits.maxIntentBytesTotal) throw journalError('PEERIT_JOURNAL_LIMIT', 'Legacy intent bytes exceed the journal bound.')
    intents.push(quarantinedLegacyIntent(verified, now))
  }
  if (reducedView.size > limits.maxViewRecords) throw journalError('PEERIT_JOURNAL_LIMIT', 'Verified legacy view exceeds its record bound.')
  if (sourceView.length !== reducedView.size || sourceView.some(([key, value]) => {
    const reduced = reducedView.get(key)
    return !reduced || stableLegacyValue(value) !== stableLegacyValue(reduced.value)
  })) {
    throw legacyUnverified('Legacy materialized view does not exactly equal the verified signed-operation reduction.')
  }
  return { intents, view: [...reducedView.values()], intentBytes }
}

function migrationCorrupt (message, cause) {
  return journalError('PEERIT_JOURNAL_CORRUPT', message, cause)
}

function migrationField (operation, message) {
  try { return operation() } catch (cause) { throw migrationCorrupt(message, cause) }
}

function migrationRowsFingerprint (rows) {
  try {
    return rows.map(row => `${String(row.key)}\u0000${stableLegacyValue(row.value)}`).join('\n')
  } catch (cause) {
    throw migrationCorrupt('Peerit previous journal contains an unserializable stored row.', cause)
  }
}

function legacyViewOperation (key, value, limits) {
  const normalizedKey = migrationField(
    () => boundedString(key, 'stored legacy view key', limits.maxRecordKeyBytes),
    'Peerit previous journal has an invalid materialized-view key.'
  )
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.id == null) {
    throw migrationCorrupt('Peerit previous journal has an invalid materialized-view value.')
  }
  const suffix = '!' + String(value.id)
  if (!normalizedKey.endsWith(suffix)) {
    throw migrationCorrupt('Peerit previous journal materialized-view key does not bind its signed record id.')
  }
  const encodedType = normalizedKey.slice(0, -suffix.length)
  const type = encodedType.replace('!', ':')
  const operation = { type, data: value }
  if (legacyViewKey(operation) !== normalizedKey) {
    throw migrationCorrupt('Peerit previous journal materialized-view key is not canonical.')
  }
  return operation
}

async function validatePreviousViewRows (rows, verifiedByIntentRecord, limits) {
  if (rows.length > limits.maxViewRecords) {
    throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit previous journal view exceeds its bounded migration limit.')
  }
  for (const row of rows) {
    const value = row && row.value
    if (!value || value.key !== row.key || !Number.isSafeInteger(value.updatedAt) || value.updatedAt < 0) {
      throw migrationCorrupt('Peerit previous journal has a malformed materialized-view row.')
    }
    const intentId = migrationField(() => validateIntentId(value.intentId), 'Peerit previous journal view has an invalid intent id.')
    const operation = legacyViewOperation(row.key, value.value, limits)
    const semanticType = operation.type === 'v2' ? operation.data._t : operation.type
    if ((await verifyRecord(operation.type, operation.data, semanticType)) !== 'ok') {
      throw legacyUnverified('Previous journal materialized view contains an unsigned or forged record.')
    }
    const expected = verifiedByIntentRecord.get(`${intentId}\u0000${row.key}`)
    if (expected && stableLegacyValue(expected) !== stableLegacyValue(value.value)) {
      throw migrationCorrupt('Peerit previous journal materialized view disagrees with its exact signed operation bytes.')
    }
  }
}

function validatePreviousTargetRows (rows, knownIntentIds, limits) {
  const counts = emptyTargetCounts()
  const byIntent = new Map()
  if (rows.length > limits.maxIntents * limits.maxTargetsPerIntent) {
    throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit previous journal target rows exceed their bounded migration limit.')
  }
  for (const row of rows) {
    const target = row && row.value
    if (!target || typeof target !== 'object' || Array.isArray(target)) {
      throw migrationCorrupt('Peerit previous journal has a malformed target row.')
    }
    const intentId = migrationField(() => validateIntentId(target.intentId), 'Peerit previous journal target has an invalid intent id.')
    const targetId = migrationField(
      () => boundedString(target.targetId, 'stored targetId', limits.maxTargetIdBytes),
      'Peerit previous journal target has an invalid relay id.'
    )
    if (!knownIntentIds.has(intentId) || target.key !== row.key || target.key !== targetKey(intentId, targetId) ||
        !TARGET_STATES.includes(target.state) || !Number.isSafeInteger(target.attempts) || target.attempts < 1 ||
        !Number.isSafeInteger(target.updatedAt) || target.updatedAt < 0 ||
        !Number.isSafeInteger(target.nextAttemptAt) || target.nextAttemptAt < 0 ||
        !Number.isSafeInteger(target.leaseUntil) || target.leaseUntil < 0 ||
        typeof target.readbackVerified !== 'boolean' || typeof target.policyDurable !== 'boolean' ||
        (target.attemptToken != null && typeof target.attemptToken !== 'string') ||
        (target.lastError != null && typeof target.lastError !== 'string') ||
        (target.evidenceRef != null && typeof target.evidenceRef !== 'string')) {
      throw migrationCorrupt('Peerit previous journal target row is internally inconsistent.')
    }
    const entries = byIntent.get(intentId) || []
    if (entries.length >= limits.maxTargetsPerIntent) {
      throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit previous journal intent exceeds its target bound.')
    }
    entries.push(target)
    byIntent.set(intentId, entries)
    counts[target.state]++
  }
  return { counts, byIntent }
}

function validatePreviousDedupeRows (rows) {
  for (const row of rows) {
    const dedupe = row && row.value
    if (!dedupe || typeof dedupe !== 'object' || Array.isArray(dedupe) || dedupe.intentId !== row.key) {
      throw migrationCorrupt('Peerit previous journal has a malformed dedupe row.')
    }
    migrationField(() => validateIntentId(dedupe.intentId), 'Peerit previous journal dedupe has an invalid intent id.')
    migrationField(() => validateIntentId(dedupe.logicalId, 'logicalId'), 'Peerit previous journal dedupe has an invalid logical id.')
    if (!Number.isSafeInteger(dedupe.expiresAt) || dedupe.expiresAt < 0) {
      throw migrationCorrupt('Peerit previous journal dedupe expiry is invalid.')
    }
  }
}

async function preparePreviousJournalMigration (snapshot, limits, now) {
  const previous = validatePreviousMetaForMigration(snapshot.meta)
  const intentRows = snapshot.intents
  const viewRows = snapshot.view
  const targetRows = snapshot.targets
  const dedupeRows = snapshot.dedupe
  if (intentRows.length > limits.maxIntents) {
    throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit previous journal exceeds its bounded intent migration limit.')
  }
  const sorted = [...intentRows].sort((left, right) => {
    const created = nonNegativeInteger(left.value && left.value.createdAt, now) - nonNegativeInteger(right.value && right.value.createdAt, now)
    return created || String(left.key).localeCompare(String(right.key))
  })
  const verified = []
  const verifiedByIntentRecord = new Map()
  let intentBytes = 0
  for (const row of sorted) {
    if (!row || !row.value || row.key !== row.value.intentId) {
      throw migrationCorrupt('Peerit previous journal intent primary key is inconsistent.')
    }
    const item = await verifyLegacyIntentForQuarantine(row.key, row.value, limits, now)
    verified.push({ row, item })
    for (const record of item.records) verifiedByIntentRecord.set(`${item.intentId}\u0000${record.key}`, record.value)
    intentBytes += byteLength(item.operationBytes)
    if (intentBytes > limits.maxIntentBytesTotal) {
      throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit previous journal exact bytes exceed the quarantine bound.')
    }
  }
  const knownIntentIds = new Set(verified.map(({ item }) => item.intentId))
  const targets = validatePreviousTargetRows(targetRows, knownIntentIds, limits)
  await validatePreviousViewRows(viewRows, verifiedByIntentRecord, limits)
  validatePreviousDedupeRows(dedupeRows)
  if (previous.intentCount !== verified.length || previous.viewRecordCount !== viewRows.length ||
      previous.dedupeCount !== dedupeRows.length || previous.intentBytes !== intentBytes) {
    throw migrationCorrupt('Peerit previous journal metadata counters disagree with stored rows.')
  }
  if ((previous.latestIntentId != null && (!knownIntentIds.has(previous.latestIntentId) ||
      !HEX64.test(previous.latestIntentId))) ||
      (previous.legacyImportHash != null && typeof previous.legacyImportHash !== 'string') ||
      (previous.legacyImportSource != null && typeof previous.legacyImportSource !== 'string')) {
    throw migrationCorrupt('Peerit previous journal metadata has an invalid retained identity field.')
  }
  const pending = verified.filter(({ row }) => {
    const count = row.value.acknowledgedTargets
    return !Number.isSafeInteger(count) || count < 0 || count === 0
  }).length
  if (previous.pendingIntentCount !== pending) {
    throw migrationCorrupt('Peerit previous journal pending-intent counter disagrees with stored rows.')
  }
  for (const state of TARGET_STATES) {
    if (previous.targetStateCounts[state] !== targets.counts[state]) {
      throw migrationCorrupt('Peerit previous journal target-state counters disagree with stored rows.')
    }
  }
  for (const { row, item } of verified) {
    const targetRowsForIntent = targets.byIntent.get(item.intentId) || []
    const acknowledged = targetRowsForIntent.filter(target => ACKNOWLEDGED.has(target.state)).length
    const readback = targetRowsForIntent.filter(target => target.state === 'readback-verified').length
    const durable = targetRowsForIntent.some(target => target.policyDurable === true)
    if (!Number.isSafeInteger(row.value.targetCount) || row.value.targetCount !== targetRowsForIntent.length ||
        !Number.isSafeInteger(row.value.acknowledgedTargets) || row.value.acknowledgedTargets !== acknowledged ||
        !Number.isSafeInteger(row.value.readbackVerified) || row.value.readbackVerified !== readback ||
        row.value.policyDurable !== durable || !Number.isSafeInteger(row.value.completedAt) || row.value.completedAt < 0) {
      throw migrationCorrupt('Peerit previous journal intent counters disagree with its target rows.')
    }
  }
  const latest = verified.reduce((current, candidate) => {
    if (!current || candidate.item.createdAt > current.item.createdAt ||
        (candidate.item.createdAt === current.item.createdAt && candidate.item.intentId > current.item.intentId)) return candidate
    return current
  }, null)
  if (previous.revision >= Number.MAX_SAFE_INTEGER) throw migrationCorrupt('Peerit previous journal revision cannot be migrated safely.')
  const meta = emptyMeta()
  meta.revision = previous.revision + 1
  meta.viewRevision = previous.viewRevision
  meta.viewRecordCount = viewRows.length
  meta.intentCount = verified.length
  meta.pendingIntentCount = 0
  meta.dedupeCount = 0
  meta.intentBytes = intentBytes
  meta.quarantinedIntentCount = verified.length
  meta.quarantinedIntentBytes = intentBytes
  meta.latestIntentId = latest ? latest.item.intentId : null
  meta.latestCreatedAt = latest ? latest.item.createdAt : 0
  meta.legacyImportHash = typeof previous.legacyImportHash === 'string' ? previous.legacyImportHash : null
  meta.legacyImportSource = typeof previous.legacyImportSource === 'string' ? previous.legacyImportSource : null
  meta.createdAt = previous.createdAt
  meta.updatedAt = now
  return Object.freeze({
    meta,
    intents: Object.freeze(verified.map(({ item }) => quarantinedLegacyIntent(item, now))),
    targetKeys: Object.freeze(targetRows.map(row => row.key)),
    dedupeKeys: Object.freeze(dedupeRows.map(row => row.key)),
    fingerprints: Object.freeze({
      meta: stableLegacyValue(snapshot.meta),
      intents: migrationRowsFingerprint(intentRows),
      view: migrationRowsFingerprint(viewRows),
      targets: migrationRowsFingerprint(targetRows),
      dedupe: migrationRowsFingerprint(dedupeRows)
    })
  })
}

function readLegacyStorage (storage) {
  if (!storage) return null
  try { return storage.getItem(LEGACY_SUBSTRATE_STATE_KEY) } catch (error) {
    throw journalError('PEERIT_JOURNAL_LEGACY_UNREADABLE', 'Peerit cannot inspect its legacy local publication journal.', error)
  }
}

function clearLegacyStorage (storage) {
  if (!storage) return true
  try {
    storage.removeItem(LEGACY_SUBSTRATE_STATE_KEY)
    return storage.getItem(LEGACY_SUBSTRATE_STATE_KEY) == null
  } catch { return false }
}

export class PeeritJournal {
  constructor (options = {}) {
    if (!options.backend || typeof options.backend.transaction !== 'function') {
      throw new TypeError('PeeritJournal requires a transactional backend')
    }
    this.backend = options.backend
    this.legacyStorage = options.legacyStorage || null
    this.clock = typeof options.clock === 'function' ? options.clock : Date.now
    this.limits = Object.freeze({ ...JOURNAL_LIMITS, ...(options.limits || {}) })
    this.dormant = false
    this.failure = null
    this._ready = null
  }

  async ready () {
    if (this._ready) return this._ready
    this._ready = this._readyInternal().catch(error => {
      this.failure = mapStorageError(error, 'ready')
      throw this.failure
    })
    return this._ready
  }

  async _readyInternal () {
    const legacyRaw = readLegacyStorage(this.legacyStorage)
    const opened = await this.backend.ready({ legacyPresent: legacyRaw != null })
    this.dormant = opened && opened.dormant === true
    if (opened && opened.unavailable) {
      throw journalError('PEERIT_JOURNAL_STORAGE_UNAVAILABLE', 'IndexedDB is unavailable; Peerit will not downgrade signed intents to memory.')
    }
    const migrated = !this.dormant && await this._migratePreviousJournal()
    let schemaRaw = null
    if (!this.dormant && this.backend.hasStore('state')) {
      schemaRaw = await this.backend.transaction(['state'], 'readonly', async tx => {
        if (!tx) return null
        return (await tx.get('state', LEGACY_SUBSTRATE_STATE_KEY)) || (await tx.get('state', 'root'))
      })
    }
    if (legacyRaw != null && schemaRaw != null) {
      const left = typeof legacyRaw === 'string' ? legacyRaw : JSON.stringify(legacyRaw)
      const right = typeof schemaRaw === 'string' ? schemaRaw : JSON.stringify(schemaRaw)
      if (left !== right) throw journalError('PEERIT_JOURNAL_LEGACY_CONFLICT', 'Two different legacy Peerit journals require explicit recovery.')
    }
    const source = legacyRaw != null ? legacyRaw : schemaRaw
    if (source != null) {
      await this.importLegacy(source, legacyRaw != null ? 'localStorage-v1' : 'indexeddb-v1')
      let cleanupFailed = legacyRaw != null && !clearLegacyStorage(this.legacyStorage)
      if (schemaRaw != null) {
        try {
          const cleared = await this.backend.transaction(['state'], 'readwrite', async tx => {
            await tx.delete('state', LEGACY_SUBSTRATE_STATE_KEY)
            await tx.delete('state', 'root')
            return (await tx.get('state', LEGACY_SUBSTRATE_STATE_KEY)) == null &&
              (await tx.get('state', 'root')) == null
          })
          cleanupFailed = cleanupFailed || !cleared
        } catch { cleanupFailed = true }
      }
      if (cleanupFailed) {
        // The atomic import is complete and hash-pinned. Retaining the source is
        // safe and idempotent, but the failed delete must remain visible.
        this.failure = journalError('PEERIT_JOURNAL_LEGACY_CLEANUP', 'Legacy Peerit journal imported, but its source could not be removed.')
      }
    }
    if (!this.dormant) await this.summary()
    return { dormant: this.dormant, imported: source != null, migrated, cleanupWarning: this.failure }
  }

  async _migratePreviousJournal () {
    const stores = Object.values(JOURNAL_STORES)
    const snapshot = await this.backend.transaction(stores, 'readonly', async tx => {
      const meta = await tx.get(JOURNAL_STORES.META, META_KEY)
      if (meta == null || meta.schemaVersion === PEERIT_JOURNAL_SCHEMA_VERSION) return { meta }
      return {
        meta,
        intents: await tx.scan(JOURNAL_STORES.INTENTS),
        view: await tx.scan(JOURNAL_STORES.VIEW),
        targets: await tx.scan(JOURNAL_STORES.TARGETS),
        dedupe: await tx.scan(JOURNAL_STORES.DEDUPE)
      }
    })
    if (snapshot.meta == null) return false
    if (snapshot.meta.schemaVersion === PEERIT_JOURNAL_SCHEMA_VERSION) {
      validateMeta(snapshot.meta)
      return false
    }
    const plan = await preparePreviousJournalMigration(snapshot, this.limits, this.clock())
    return this._transaction(stores, 'readwrite', 'previous journal quarantine migration', async tx => {
      const currentMeta = await tx.get(JOURNAL_STORES.META, META_KEY)
      if (currentMeta && currentMeta.schemaVersion === PEERIT_JOURNAL_SCHEMA_VERSION) {
        validateMeta(currentMeta)
        return false
      }
      validatePreviousMetaForMigration(currentMeta)
      const current = {
        meta: currentMeta,
        intents: await tx.scan(JOURNAL_STORES.INTENTS),
        view: await tx.scan(JOURNAL_STORES.VIEW),
        targets: await tx.scan(JOURNAL_STORES.TARGETS),
        dedupe: await tx.scan(JOURNAL_STORES.DEDUPE)
      }
      if (stableLegacyValue(current.meta) !== plan.fingerprints.meta ||
          migrationRowsFingerprint(current.intents) !== plan.fingerprints.intents ||
          migrationRowsFingerprint(current.view) !== plan.fingerprints.view ||
          migrationRowsFingerprint(current.targets) !== plan.fingerprints.targets ||
          migrationRowsFingerprint(current.dedupe) !== plan.fingerprints.dedupe) {
        throw migrationCorrupt('Peerit previous journal changed during its fail-closed quarantine migration.')
      }
      for (const intent of plan.intents) await tx.put(JOURNAL_STORES.INTENTS, intent)
      for (const key of plan.targetKeys) await tx.delete(JOURNAL_STORES.TARGETS, key)
      for (const key of plan.dedupeKeys) await tx.delete(JOURNAL_STORES.DEDUPE, key)
      await tx.put(JOURNAL_STORES.META, plan.meta)
      return true
    })
  }

  async _transaction (stores, mode, context, operation) {
    if (this.failure && this.failure.code !== 'PEERIT_JOURNAL_LEGACY_CLEANUP') throw this.failure
    try {
      if (mode === 'readwrite' && this.dormant) {
        await this.backend.ready({ create: true })
        this.dormant = false
      }
      if (this.dormant && mode === 'readonly') return operation(null)
      return await this.backend.transaction(stores, mode, operation)
    } catch (error) {
      const mapped = mapStorageError(error, context)
      if (mapped.code === 'PEERIT_JOURNAL_CORRUPT' || mapped.code === 'PEERIT_JOURNAL_STORAGE_UNAVAILABLE') this.failure = mapped
      throw mapped
    }
  }

  async importLegacy (raw, source) {
    const state = legacyState(raw)
    const canonicalRaw = typeof raw === 'string' ? raw : JSON.stringify(raw)
    const importHash = await hashHex(canonicalRaw)
    const now = this.clock()
    const verified = await validateLegacyForImport(state, this.limits, now)
    return this._transaction(Object.values(JOURNAL_STORES), 'readwrite', 'legacy import', async tx => {
      const current = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      if (current.legacyImportHash) {
        if (current.legacyImportHash !== importHash) {
          throw journalError('PEERIT_JOURNAL_LEGACY_CONFLICT', 'A different legacy journal was already imported.')
        }
        return { imported: false, duplicate: true, hash: importHash }
      }
      if (current.intentCount || current.viewRecordCount || current.dedupeCount) {
        throw journalError('PEERIT_JOURNAL_LEGACY_CONFLICT', 'Legacy import cannot merge into an already-authored journal.')
      }
      const meta = emptyMeta()
      meta.createdAt = now
      meta.updatedAt = now
      meta.legacyImportHash = importHash
      meta.legacyImportSource = source
      meta.revision = Math.max(1, verified.intents.length)
      meta.viewRevision = verified.intents.length
      for (const record of verified.view) {
        await tx.put(JOURNAL_STORES.VIEW, { ...record, updatedAt: now })
        meta.viewRecordCount++
      }
      for (const verifiedIntent of verified.intents) {
        await tx.put(JOURNAL_STORES.INTENTS, verifiedIntent)
        meta.intentCount++
        meta.quarantinedIntentCount++
        meta.quarantinedIntentBytes += byteLength(verifiedIntent.legacyOperationBytes)
        if (verifiedIntent.createdAt >= meta.latestCreatedAt) {
          meta.latestCreatedAt = verifiedIntent.createdAt
          meta.latestIntentId = verifiedIntent.intentId
        }
      }
      meta.intentBytes = verified.intentBytes
      await tx.put(JOURNAL_STORES.META, meta)
      return { imported: true, duplicate: false, hash: importHash }
    })
  }

  async commitIntent (input) {
    const payload = normalizedInnerIntent(input, this.limits)
    const { intentId } = payload
    const records = Array.isArray(input.records) ? input.records : []
    if (!records.length || records.length > this.limits.maxRecordsPerIntent) {
      throw journalError('PEERIT_JOURNAL_LIMIT', 'Intent record count is outside journal bounds.')
    }
    const seen = new Set()
    const normalizedRecords = records.map(record => {
      const key = boundedString(record && record.key, 'record key', this.limits.maxRecordKeyBytes)
      if (seen.has(key)) throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Intent contains a duplicate record key.')
      seen.add(key)
      return { key, value: clone(record.value) }
    })
    const createdAt = Number.isSafeInteger(input.createdAt) ? input.createdAt : this.clock()
    const orderKey = pendingOrderKey(createdAt, intentId)
    return this._transaction([
      JOURNAL_STORES.META, JOURNAL_STORES.VIEW, JOURNAL_STORES.INTENTS, JOURNAL_STORES.DEDUPE
    ], 'readwrite', 'local intent commit', async tx => {
      const existing = await tx.get(JOURNAL_STORES.INTENTS, intentId)
      if (existing) {
        if (!sameInnerIntent(existing, payload)) {
          throw journalError('PEERIT_JOURNAL_CORRUPT', 'Intent hash collision or journal corruption.')
        }
        return { duplicate: true, compacted: false, queued: existing.acknowledgedTargets === 0, viewRevision: null }
      }
      const dedupe = await tx.get(JOURNAL_STORES.DEDUPE, intentId)
      if (dedupe) {
        if (!sameInnerDedupe(dedupe, payload)) {
          throw journalError('PEERIT_JOURNAL_CORRUPT', 'Compacted intent identity does not match the exact VNext envelope.')
        }
        return { duplicate: true, compacted: true, queued: false, viewRevision: null }
      }
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      if (meta.intentCount - meta.quarantinedIntentCount >= this.limits.maxIntents) {
        throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit has reached its bounded active-intent limit.')
      }
      // Historical raw-JSON rows are held in a distinct, bounded quarantine so
      // a prior release cannot strand an otherwise valid VNext author behind
      // its old relay queue. The new active envelope budget is independent.
      const activeIntentBytes = meta.intentBytes - meta.quarantinedIntentBytes
      if (activeIntentBytes < 0) throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit active-intent byte counters underflowed.')
      if (activeIntentBytes + payload.innerLength > this.limits.maxIntentBytesTotal) {
        throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit has reached its bounded exact-intent byte limit.')
      }
      let newViewRecords = 0
      for (const record of normalizedRecords) if (!(await tx.get(JOURNAL_STORES.VIEW, record.key))) newViewRecords++
      if (meta.viewRecordCount + newViewRecords > this.limits.maxViewRecords) {
        throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit has reached its bounded materialized-view record limit.')
      }
      const now = this.clock()
      const intent = {
        ...payload,
        recordKeys: normalizedRecords.map(record => record.key),
        createdAt,
        updatedAt: now,
        discoveryState: input.discoveryState || 'queued',
        targetCount: 0,
        acknowledgedTargets: 0,
        readbackVerified: 0,
        policyDurable: false,
        completedAt: 0,
        pendingOrderKey: orderKey
      }
      await tx.put(JOURNAL_STORES.INTENTS, intent)
      for (const record of normalizedRecords) {
        await tx.put(JOURNAL_STORES.VIEW, { ...record, intentId, updatedAt: now })
      }
      meta.revision++
      meta.viewRevision++
      meta.viewRecordCount += newViewRecords
      meta.intentCount++
      meta.pendingIntentCount++
      meta.intentBytes += payload.innerLength
      if (createdAt >= meta.latestCreatedAt) {
        meta.latestCreatedAt = createdAt
        meta.latestIntentId = intentId
      }
      if (!meta.createdAt) meta.createdAt = now
      meta.updatedAt = now
      await tx.put(JOURNAL_STORES.META, meta)
      return { duplicate: false, compacted: false, queued: true, viewRevision: meta.viewRevision }
    })
  }

  // Persists the signed Seq29 bootstrap before any public-INBOX transport is
  // attempted. The authority-wide row is the monotonic anti-rollback/fork
  // floor; append floors live in a second row keyed by that exact authority and
  // complete signed-wrapper hash. Both rows share the same backend transaction.
  async acceptSeq29PublicInboxBootstrap (input) {
    const bootstrap = normalizeSeq29PublicInboxBootstrap(input)
    const floorKey = seq29PublicInboxBootstrapFloorKey(bootstrap.authorityPublicKey)
    const stateKey = seq29PublicInboxStateKey(
      bootstrap.authorityPublicKey, bootstrap.completeSignedWrapperHash)
    const now = Number.isSafeInteger(input.observedAt) && input.observedAt >= 0
      ? input.observedAt
      : this.clock()
    return this._transaction([JOURNAL_STORES.META], 'readwrite', 'Seq29 public INBOX bootstrap commit', async tx => {
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      const rawFloor = await tx.get(JOURNAL_STORES.META, floorKey)
      let duplicate = false
      let previousStateKey = null
      if (rawFloor) {
        const floor = validateSeq29PublicInboxBootstrapFloor(
          rawFloor, bootstrap.authorityPublicKey)
        previousStateKey = seq29PublicInboxStateKey(
          bootstrap.authorityPublicKey, floor.completeSignedWrapperHash)
        const previousSequence = BigInt(floor.highestAcceptedBootstrapSequence)
        if (bootstrap.bootstrapSequence < previousSequence) {
          throw journalError('PEERIT_JOURNAL_SEQ29_BOOTSTRAP_ROLLBACK',
            'Seq29 public INBOX bootstrap is below the durable authority floor.')
        }
        if (bootstrap.bootstrapSequence === previousSequence &&
            bootstrap.completeSignedWrapperHash !== floor.completeSignedWrapperHash) {
          throw journalError('PEERIT_JOURNAL_SEQ29_BOOTSTRAP_FORK',
            'Seq29 public INBOX bootstrap conflicts at the durable authority sequence.')
        }
        duplicate = bootstrap.bootstrapSequence === previousSequence
      }

      const rawState = await tx.get(JOURNAL_STORES.META, stateKey)
      let state
      if (rawState) {
        state = validateSeq29PublicInboxState(rawState, bootstrap)
      } else {
        if (duplicate) {
          throw journalError('PEERIT_JOURNAL_CORRUPT',
            'Seq29 public INBOX bootstrap floor has no exact append-floor state.')
        }
        state = {
          key: stateKey,
          schema: 'PeeritSeq29PublicInboxStateV1',
          version: 1,
          releaseSequence: SEQ29_PUBLIC_INBOX_RELEASE_SEQUENCE,
          authorityPublicKey: bootstrap.authorityPublicKey,
          completeSignedWrapperHash: bootstrap.completeSignedWrapperHash,
          bootstrapSequence: String(bootstrap.bootstrapSequence),
          relays: bootstrap.relayIds.map(relayId => ({
            relayId,
            previousAppendRevision: '0',
            appendRevision: '0',
            observationHash: null
          })),
          observedAt: now,
          updatedAt: now
        }
        await tx.put(JOURNAL_STORES.META, state)
      }

      if (!duplicate) {
        await tx.put(JOURNAL_STORES.META, {
          key: floorKey,
          schema: 'PeeritSeq29PublicInboxBootstrapFloorV1',
          version: 1,
          authorityPublicKey: bootstrap.authorityPublicKey,
          highestAcceptedBootstrapSequence: String(bootstrap.bootstrapSequence),
          completeSignedWrapperHash: bootstrap.completeSignedWrapperHash,
          observedAt: now,
          updatedAt: now
        })
        if (previousStateKey != null && previousStateKey !== stateKey) {
          await tx.delete(JOURNAL_STORES.META, previousStateKey)
        }
        meta.revision++
        if (!meta.createdAt) meta.createdAt = now
        meta.updatedAt = Math.max(meta.updatedAt, now)
        await tx.put(JOURNAL_STORES.META, meta)
      }
      return Object.freeze({
        duplicate,
        bootstrapFloor: Object.freeze({
          schema: 'PeeritLimitedPublicInboxBootstrapFloorV1',
          version: 1,
          highestAcceptedBootstrapSequence: String(bootstrap.bootstrapSequence),
          completeSignedWrapperHash: bootstrap.completeSignedWrapperHash
        }),
        appendFloors: Object.freeze(Object.fromEntries(state.relays.map(relay =>
          [relay.relayId, BigInt(relay.appendRevision)])))
      })
    })
  }

  async getSeq29PublicInboxBootstrapFloor (authorityPublicKey) {
    const normalizedAuthority = seq29PublicInboxHex(
      authorityPublicKey, 'Seq29 public INBOX authorityPublicKey')
    const key = seq29PublicInboxBootstrapFloorKey(normalizedAuthority)
    return this._transaction([JOURNAL_STORES.META], 'readonly', 'Seq29 public INBOX bootstrap floor read', async tx => {
      if (!tx) return null
      const raw = await tx.get(JOURNAL_STORES.META, key)
      if (!raw) return null
      return seq29PublicInboxBootstrapFloorValue(
        validateSeq29PublicInboxBootstrapFloor(raw, normalizedAuthority))
    })
  }

  async getSeq29PublicInboxAppendFloors (input) {
    const bootstrap = normalizeSeq29PublicInboxBootstrap(input)
    const floorKey = seq29PublicInboxBootstrapFloorKey(bootstrap.authorityPublicKey)
    const stateKey = seq29PublicInboxStateKey(
      bootstrap.authorityPublicKey, bootstrap.completeSignedWrapperHash)
    return this._transaction([JOURNAL_STORES.META], 'readonly', 'Seq29 public INBOX append-floor read', async tx => {
      if (!tx) return null
      const rawFloor = await tx.get(JOURNAL_STORES.META, floorKey)
      if (!rawFloor) return null
      const floor = validateSeq29PublicInboxBootstrapFloor(
        rawFloor, bootstrap.authorityPublicKey)
      const sequence = BigInt(floor.highestAcceptedBootstrapSequence)
      if (bootstrap.bootstrapSequence < sequence) {
        throw journalError('PEERIT_JOURNAL_SEQ29_BOOTSTRAP_ROLLBACK',
          'Seq29 public INBOX bootstrap is below the durable authority floor.')
      }
      if (bootstrap.bootstrapSequence !== sequence ||
          bootstrap.completeSignedWrapperHash !== floor.completeSignedWrapperHash) {
        throw journalError('PEERIT_JOURNAL_SEQ29_BOOTSTRAP_FORK',
          'Seq29 public INBOX bootstrap differs from the exact durable authority state.')
      }
      const state = validateSeq29PublicInboxState(
        await tx.get(JOURNAL_STORES.META, stateKey), bootstrap)
      return Object.freeze(Object.fromEntries(state.relays.map(relay =>
        [relay.relayId, BigInt(relay.appendRevision)])))
    })
  }

  async getSeq29PublicationAuthorHead (input) {
    const scope = seq29PublicationScope(input)
    return this._transaction([JOURNAL_STORES.META], 'readonly', 'Seq29 publication author-head read', async tx => {
      if (!tx) return Object.freeze({ nextAuthorSequence: 0n, previousAuthorRecordId: null })
      return validateSeq29PublicationHead(
        await tx.get(JOURNAL_STORES.META, seq29PublicationAuthorHeadKey(scope)), scope)
    })
  }

  async getSeq29PublicationIntent (input) {
    const scope = seq29PublicationScope(input)
    const key = seq29PublicationIntentKey(scope, input.logicalHash)
    return this._transaction([JOURNAL_STORES.META], 'readonly', 'Seq29 publication intent read', async tx => {
      if (!tx) return null
      const value = await tx.get(JOURNAL_STORES.META, key)
      return value == null ? null : validateSeq29PublicationIntent(value, scope)
    })
  }

  async listSeq29PublicationIntents (input) {
    const scope = seq29PublicationScope(input)
    const prefix = SEQ29_PUBLICATION_INTENT_PREFIX + scope.authorityPublicKey + ':' +
      scope.completeSignedWrapperHash + ':' + scope.authorPublicKey + ':'
    const limit = Math.max(1, Math.min(64, Number(input.limit) || 32))
    return this._transaction([JOURNAL_STORES.META], 'readonly', 'Seq29 publication intent scan', async tx => {
      if (!tx) return []
      const rows = await tx.scan(JOURNAL_STORES.META, { prefix, limit: limit + 1 })
      if (rows.length > limit) {
        throw journalError('PEERIT_JOURNAL_LIMIT', 'Seq29 publication recovery scan exceeds its bound.')
      }
      return rows.map(row => validateSeq29PublicationIntent(row.value, scope))
    })
  }

  // The exact two APPEND frames and requests become durable in the same
  // transaction that advances the local AuthorBind chain head. No network
  // APPEND is permitted before this commit returns.
  async commitSeq29PublicationIntent (input) {
    const scope = seq29PublicationScope(input)
    const logicalHash = seq29PublicInboxHex(input.logicalHash, 'Seq29 publication logicalHash')
    const intentId = validateIntentId(input.intentId)
    const authorSequence = seq29PublicInboxDecimal(
      input.authorSequence, 'Seq29 publication authorSequence')
    const previousAuthorRecordId = input.previousAuthorRecordId == null
      ? null
      : seq29PublicInboxHex(input.previousAuthorRecordId,
        'Seq29 publication previousAuthorRecordId')
    const authorRecordId = seq29PublicInboxHex(
      input.authorRecordId, 'Seq29 publication authorRecordId')
    const announcementBytes = seq29PublicationBytes(
      input.announcementBytes, 'Seq29 publication announcementBytes', 1, 12288)
    if (!Array.isArray(input.relays) || input.relays.length !== 2) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 publication requires two prepared APPEND relays.')
    }
    const relays = input.relays.map((value, index) => normalizeSeq29PreparedRelay(
      value, scope.relayIds, `Seq29 publication relays[${index}]`))
      .sort((left, right) => left.relayId.localeCompare(right.relayId))
    if (relays[0].relayId === relays[1].relayId ||
        relays.some((relay, index) => relay.relayId !== scope.relayIds[index])) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 publication relay set differs from its signed bootstrap.')
    }
    const key = seq29PublicationIntentKey(scope, logicalHash)
    const headKey = seq29PublicationAuthorHeadKey(scope)
    const floorKey = seq29PublicInboxBootstrapFloorKey(scope.authorityPublicKey)
    const now = Number.isSafeInteger(input.createdAt) && input.createdAt >= 0
      ? input.createdAt
      : this.clock()
    return this._transaction([
      JOURNAL_STORES.META, JOURNAL_STORES.INTENTS
    ], 'readwrite', 'Seq29 publication intent commit', async tx => {
      const floor = validateSeq29PublicInboxBootstrapFloor(
        await tx.get(JOURNAL_STORES.META, floorKey), scope.authorityPublicKey)
      if (floor.completeSignedWrapperHash !== scope.completeSignedWrapperHash ||
          BigInt(floor.highestAcceptedBootstrapSequence) !== scope.bootstrapSequence) {
        throw journalError('PEERIT_JOURNAL_SEQ29_BOOTSTRAP_ROLLBACK',
          'Seq29 publication is not bound to the current durable bootstrap.')
      }
      const authored = await tx.get(JOURNAL_STORES.INTENTS, intentId)
      if (!authored || authored.logicalId !== logicalHash ||
          authored.wireFormat !== PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1) {
        throw journalError('PEERIT_JOURNAL_BAD_INPUT',
          'Seq29 publication does not name an exact ordinary authored intent.')
      }
      const existing = await tx.get(JOURNAL_STORES.META, key)
      if (existing) {
        const value = validateSeq29PublicationIntent(existing, scope)
        const relayConflicts = value.relays.map((relay, index) =>
          seq29PreparedRelayConflict(relay, relays[index]))
        const relayConflict = relayConflicts.findIndex(Boolean)
        if (value.intentId !== intentId || value.authorRecordId !== authorRecordId ||
            !bytesEqual(value.announcementBytes, announcementBytes) ||
            relayConflict !== -1) {
          throw journalError('PEERIT_JOURNAL_CORRUPT',
            `Seq29 publication logical identity conflicts with durable bytes${
              relayConflict === -1
                ? ''
                : ` for ${value.relays[relayConflict].relayId} ${relayConflicts[relayConflict]}`}.`)
        }
        return Object.freeze({ duplicate: true, intent: value })
      }
      const head = validateSeq29PublicationHead(
        await tx.get(JOURNAL_STORES.META, headKey), scope)
      if (authorSequence !== head.nextAuthorSequence ||
          previousAuthorRecordId !== head.previousAuthorRecordId) {
        throw journalError('PEERIT_JOURNAL_SEQ29_AUTHOR_HEAD_STALE',
          'Seq29 publication AuthorBind head changed before its durable commit.')
      }
      for (const relay of relays) relay.updatedAt = now
      const value = {
        key,
        schema: 'PeeritSeq29PublicationIntentV1',
        version: 1,
        releaseSequence: SEQ29_PUBLIC_INBOX_RELEASE_SEQUENCE,
        authorityPublicKey: scope.authorityPublicKey,
        completeSignedWrapperHash: scope.completeSignedWrapperHash,
        bootstrapSequence: String(scope.bootstrapSequence),
        authorPublicKey: scope.authorPublicKey,
        intentId,
        logicalHash,
        authorSequence: String(authorSequence),
        previousAuthorRecordId,
        authorRecordId,
        announcementBytes,
        relays,
        createdAt: now,
        updatedAt: now,
        completedAt: 0
      }
      validateSeq29PublicationIntent(value, scope)
      await tx.put(JOURNAL_STORES.META, value)
      await tx.put(JOURNAL_STORES.META, {
        key: headKey,
        schema: 'PeeritSeq29PublicationAuthorHeadV1',
        version: 1,
        authorityPublicKey: scope.authorityPublicKey,
        completeSignedWrapperHash: scope.completeSignedWrapperHash,
        authorPublicKey: scope.authorPublicKey,
        nextAuthorSequence: String(authorSequence + 1n),
        previousAuthorRecordId: authorRecordId,
        updatedAt: now
      })
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      meta.revision++
      if (!meta.createdAt) meta.createdAt = now
      meta.updatedAt = Math.max(meta.updatedAt, now)
      await tx.put(JOURNAL_STORES.META, meta)
      return Object.freeze({ duplicate: false, intent: clone(value) })
    })
  }

  async claimSeq29PublicationRelay (input) {
    const scope = seq29PublicationScope(input)
    const key = seq29PublicationIntentKey(scope, input.logicalHash)
    const relayId = seq29PublicInboxRelayId(input.relayId)
    const attemptToken = boundedString(input.attemptToken, 'Seq29 publication attemptToken', 256)
    const now = Number.isSafeInteger(input.now) && input.now >= 0 ? input.now : this.clock()
    const leaseUntil = Number.isSafeInteger(input.leaseUntil) && input.leaseUntil > now
      ? input.leaseUntil
      : now + 60_000
    return this._transaction([JOURNAL_STORES.META], 'readwrite', 'Seq29 publication relay claim', async tx => {
      const value = validateSeq29PublicationIntent(
        await tx.get(JOURNAL_STORES.META, key), scope)
      const relay = value.relays.find(row => row.relayId === relayId)
      if (!relay) throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 publication relay is absent.')
      if (relay.stage === 'succeeded') return Object.freeze({ claimed: false, intent: value })
      if (relay.attemptToken != null && relay.leaseUntil > now) {
        return Object.freeze({ claimed: false, intent: value })
      }
      relay.stage = relay.stage === 'prepared' ? 'sending' : 'reconciling'
      relay.attemptToken = attemptToken
      relay.leaseUntil = leaseUntil
      relay.attempts++
      relay.updatedAt = now
      value.updatedAt = now
      await tx.put(JOURNAL_STORES.META, value)
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      meta.revision++
      meta.updatedAt = Math.max(meta.updatedAt, now)
      await tx.put(JOURNAL_STORES.META, meta)
      return Object.freeze({ claimed: true, action: relay.stage, intent: clone(value) })
    })
  }

  async markSeq29PublicationRelayAbsent (input) {
    return this._mutateSeq29PublicationRelay(input, 'Seq29 publication authenticated absence',
      (value, relay, now) => {
        if (relay.stage !== 'reconciling') {
          throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 publication relay is not reconciling.')
        }
        relay.stage = 'sending'
        relay.updatedAt = now
        value.updatedAt = now
      })
  }

  async completeSeq29PublicationRelay (input) {
    return this._mutateSeq29PublicationRelay(input, 'Seq29 publication relay completion',
      (value, relay, now) => {
        relay.stage = 'succeeded'
        relay.result = clone(input.result)
        relay.attemptToken = null
        relay.leaseUntil = 0
        relay.lastError = null
        relay.updatedAt = now
        value.updatedAt = now
        if (value.relays.every(row => row.stage === 'succeeded')) value.completedAt = now || 1
      })
  }

  async failSeq29PublicationRelay (input) {
    return this._mutateSeq29PublicationRelay(input, 'Seq29 publication relay ambiguous outcome',
      (value, relay, now) => {
        relay.stage = 'pending-unknown'
        relay.attemptToken = null
        relay.leaseUntil = 0
        relay.lastError = String(input.errorCode || 'PEERIT_SEQ29_APPEND_AMBIGUOUS').slice(0, 128)
        relay.updatedAt = now
        value.updatedAt = now
      })
  }

  async _mutateSeq29PublicationRelay (input, context, mutation) {
    const scope = seq29PublicationScope(input)
    const key = seq29PublicationIntentKey(scope, input.logicalHash)
    const relayId = seq29PublicInboxRelayId(input.relayId)
    const attemptToken = boundedString(input.attemptToken, 'Seq29 publication attemptToken', 256)
    const now = Number.isSafeInteger(input.now) && input.now >= 0 ? input.now : this.clock()
    return this._transaction([JOURNAL_STORES.META], 'readwrite', context, async tx => {
      const value = validateSeq29PublicationIntent(
        await tx.get(JOURNAL_STORES.META, key), scope)
      const relay = value.relays.find(row => row.relayId === relayId)
      if (!relay || relay.attemptToken !== attemptToken || relay.leaseUntil < now) {
        throw journalError('PEERIT_JOURNAL_SEQ29_APPEND_CLAIM_STALE',
          'Seq29 publication relay claim is absent or expired.')
      }
      mutation(value, relay, now)
      validateSeq29PublicationIntent(value, scope)
      await tx.put(JOURNAL_STORES.META, value)
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      meta.revision++
      meta.updatedAt = Math.max(meta.updatedAt, now)
      await tx.put(JOURNAL_STORES.META, meta)
      return clone(value)
    })
  }

  // Commits one complete dual-relay poll. The transaction deliberately opens
  // only META and VIEW: remote discovery cannot create authored intents,
  // targets, dedupe queue rows, or outbound work. A concurrent tab that won the
  // same prior->next transition must reproduce its observation hash; a tab with
  // any other stale prior is forced to re-poll from the newly durable floor.
  async commitSeq29PublicInboxPoll (input) {
    const bootstrap = normalizeSeq29PublicInboxBootstrap(input)
    if (!Array.isArray(input.relayPolls) || input.relayPolls.length !== 2) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Seq29 public INBOX poll must cover exactly two relays.')
    }
    const relayPolls = input.relayPolls.map(raw => {
      const relayId = seq29PublicInboxRelayId(raw && raw.relayId)
      const previousAppendRevision = seq29PublicInboxDecimal(
        raw && raw.previousAppendRevision, `${relayId} previous append revision`)
      const newAppendRevision = seq29PublicInboxDecimal(
        raw && raw.newAppendRevision, `${relayId} new append revision`)
      const observationHash = seq29PublicInboxHex(
        raw && raw.observationHash, `${relayId} observationHash`)
      if (newAppendRevision < previousAppendRevision) {
        throw journalError('PEERIT_JOURNAL_SEQ29_APPEND_ROLLBACK',
          `${relayId} authenticated append observation is below its requested floor.`)
      }
      return Object.freeze({ relayId, previousAppendRevision, newAppendRevision, observationHash })
    }).sort((left, right) => left.relayId.localeCompare(right.relayId))
    if (relayPolls[0].relayId === relayPolls[1].relayId ||
        relayPolls.some((poll, index) => poll.relayId !== bootstrap.relayIds[index])) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT',
        'Seq29 public INBOX poll relay set differs from its signed bootstrap.')
    }

    const records = Array.isArray(input.records) ? input.records : []
    if (records.length > this.limits.maxRecordsPerIntent * 64) {
      throw journalError('PEERIT_JOURNAL_LIMIT',
        'Seq29 public INBOX remote record count exceeds its atomic ingest bound.')
    }
    const normalizedByKey = new Map()
    for (const record of records) {
      const key = boundedString(record && record.key,
        'Seq29 public INBOX record key', this.limits.maxRecordKeyBytes)
      if (!record.value || typeof record.value !== 'object' || Array.isArray(record.value) ||
          typeof record.value._sig !== 'string' || typeof record.value._k !== 'string') {
        throw journalError('PEERIT_JOURNAL_BAD_INPUT',
          'Seq29 public INBOX record is not an intrinsically authenticated Peerit row.')
      }
      const normalized = { key, value: clone(record.value) }
      const prior = normalizedByKey.get(key)
      if (!prior || discoveredRecordWins(normalized.value, prior.value)) normalizedByKey.set(key, normalized)
    }
    const normalizedRecords = [...normalizedByKey.values()]
    const observedAt = Number.isSafeInteger(input.observedAt) && input.observedAt >= 0
      ? input.observedAt
      : this.clock()
    const floorKey = seq29PublicInboxBootstrapFloorKey(bootstrap.authorityPublicKey)
    const stateKey = seq29PublicInboxStateKey(
      bootstrap.authorityPublicKey, bootstrap.completeSignedWrapperHash)
    return this._transaction([JOURNAL_STORES.META, JOURNAL_STORES.VIEW], 'readwrite', 'Seq29 public INBOX atomic poll commit', async tx => {
      const floor = validateSeq29PublicInboxBootstrapFloor(
        await tx.get(JOURNAL_STORES.META, floorKey), bootstrap.authorityPublicKey)
      if (BigInt(floor.highestAcceptedBootstrapSequence) !== bootstrap.bootstrapSequence ||
          floor.completeSignedWrapperHash !== bootstrap.completeSignedWrapperHash) {
        throw journalError('PEERIT_JOURNAL_SEQ29_BOOTSTRAP_ROLLBACK',
          'Seq29 public INBOX poll is not bound to the current durable bootstrap.')
      }
      const state = validateSeq29PublicInboxState(
        await tx.get(JOURNAL_STORES.META, stateKey), bootstrap)
      const byRelay = new Map(state.relays.map(relay => [relay.relayId, relay]))
      let advances = 0
      let duplicates = 0
      for (const poll of relayPolls) {
        const relay = byRelay.get(poll.relayId)
        const current = BigInt(relay.appendRevision)
        const previousTransition = BigInt(relay.previousAppendRevision)
        if (poll.newAppendRevision < current) {
          throw journalError('PEERIT_JOURNAL_SEQ29_APPEND_ROLLBACK',
            `${poll.relayId} authenticated append observation is below the durable floor.`)
        }
        if (poll.previousAppendRevision === current) {
          if (poll.newAppendRevision === current) continue
          relay.previousAppendRevision = String(current)
          relay.appendRevision = String(poll.newAppendRevision)
          relay.observationHash = poll.observationHash
          advances++
          continue
        }
        if (poll.previousAppendRevision === previousTransition &&
            poll.newAppendRevision === current) {
          if (relay.observationHash !== poll.observationHash) {
            throw journalError('PEERIT_JOURNAL_SEQ29_APPEND_FORK',
              `${poll.relayId} conflicts with the concurrently committed append transition.`)
          }
          duplicates++
          continue
        }
        throw journalError('PEERIT_JOURNAL_SEQ29_APPEND_FLOOR_STALE',
          `${poll.relayId} poll did not begin at the current durable append floor.`)
      }
      if (advances === 0) {
        return Object.freeze({
          duplicate: true,
          changedKeys: Object.freeze([]),
          appendFloors: Object.freeze(Object.fromEntries(state.relays.map(relay =>
            [relay.relayId, BigInt(relay.appendRevision)]))),
          duplicateTransitionCount: duplicates
        })
      }

      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      let newViewRecords = 0
      const changedKeys = []
      for (const record of normalizedRecords) {
        const existing = await tx.get(JOURNAL_STORES.VIEW, record.key)
        if (!discoveredRecordWins(record.value, existing && existing.value)) continue
        if (!existing) newViewRecords++
        await tx.put(JOURNAL_STORES.VIEW, {
          ...record,
          intentId: null,
          seq29PublicInboxAuthorityPublicKey: bootstrap.authorityPublicKey,
          seq29PublicInboxCompleteSignedWrapperHash: bootstrap.completeSignedWrapperHash,
          seq29PublicInboxBootstrapSequence: String(bootstrap.bootstrapSequence),
          updatedAt: observedAt
        })
        changedKeys.push(record.key)
      }
      if (meta.viewRecordCount + newViewRecords > this.limits.maxViewRecords) {
        throw journalError('PEERIT_JOURNAL_LIMIT',
          'Seq29 public INBOX ingest exceeds the materialized-view record limit.')
      }
      state.updatedAt = observedAt
      await tx.put(JOURNAL_STORES.META, state)
      meta.revision++
      if (changedKeys.length) meta.viewRevision++
      meta.viewRecordCount += newViewRecords
      if (!meta.createdAt) meta.createdAt = observedAt
      meta.updatedAt = Math.max(meta.updatedAt, observedAt)
      await tx.put(JOURNAL_STORES.META, meta)
      return Object.freeze({
        duplicate: false,
        changedKeys: Object.freeze(changedKeys),
        appendFloors: Object.freeze(Object.fromEntries(state.relays.map(relay =>
          [relay.relayId, BigInt(relay.appendRevision)]))),
        duplicateTransitionCount: duplicates
      })
    })
  }

  // Atomically imports an already-authenticated remote batch into the read view
  // and advances one source-scoped discovery floor. This transaction never opens
  // INTENTS, TARGETS or DEDUPE, so downloaded rows cannot become publication
  // work or relay targets even if the process crashes at any boundary.
  async commitDiscoveredBatch (input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'discovered batch must be an object.')
    }
    const sourceId = validateIntentId(input.sourceId, 'discovery sourceId')
    const checkpointHash = validateIntentId(input.checkpointHash, 'discovery checkpointHash')
    const previousCheckpointHash = input.previousCheckpointHash == null
      ? null
      : validateIntentId(input.previousCheckpointHash, 'discovery previousCheckpointHash')
    const checkpointSequence = input.checkpointSequence
    if (!Number.isSafeInteger(checkpointSequence) || checkpointSequence < 0) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'discovery checkpointSequence must be a non-negative safe integer.')
    }
    const records = Array.isArray(input.records) ? input.records : []
    if (records.length < 1 || records.length > this.limits.maxRecordsPerIntent * 64) {
      throw journalError('PEERIT_JOURNAL_LIMIT', 'discovered record count is outside its bounded batch limit.')
    }
    const seen = new Set()
    const normalizedRecords = records.map(record => {
      const key = boundedString(record && record.key, 'discovered record key', this.limits.maxRecordKeyBytes)
      if (seen.has(key)) throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'discovered batch contains a duplicate record key.')
      seen.add(key)
      if (!record.value || typeof record.value !== 'object' || Array.isArray(record.value) ||
          typeof record.value._sig !== 'string' || typeof record.value._k !== 'string') {
        throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'discovered record is not an authenticated Peerit row.')
      }
      return { key, value: clone(record.value) }
    })
    const observedAt = Number.isSafeInteger(input.observedAt) && input.observedAt >= 0
      ? input.observedAt
      : this.clock()
    const floorKey = discoveryFloorKey(sourceId)
    return this._transaction([JOURNAL_STORES.META, JOURNAL_STORES.VIEW], 'readwrite', 'verified remote batch commit', async tx => {
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      const previous = await tx.get(JOURNAL_STORES.META, floorKey)
      if (previous) {
        if (!Number.isSafeInteger(previous.checkpointSequence) || !HEX64.test(previous.checkpointHash || '')) {
          throw journalError('PEERIT_JOURNAL_CORRUPT', 'discovery floor is corrupt.')
        }
        if (checkpointSequence < previous.checkpointSequence) {
          throw journalError('PEERIT_JOURNAL_DISCOVERY_ROLLBACK', 'discovery checkpoint is below the persisted source floor.')
        }
        if (checkpointSequence === previous.checkpointSequence) {
          if (checkpointHash !== previous.checkpointHash) {
            throw journalError('PEERIT_JOURNAL_DISCOVERY_FORK', 'discovery checkpoint conflicts at the persisted sequence.')
          }
          return { duplicate: true, changedKeys: [], checkpointSequence, checkpointHash }
        }
        if (previousCheckpointHash !== previous.checkpointHash) {
          throw journalError('PEERIT_JOURNAL_DISCOVERY_GAP', 'discovery checkpoint does not extend the persisted source floor.')
        }
      } else if (checkpointSequence !== 0 || previousCheckpointHash != null) {
        throw journalError('PEERIT_JOURNAL_DISCOVERY_GAP', 'first discovery checkpoint must be sequence zero with no predecessor.')
      }

      let newViewRecords = 0
      const changedKeys = []
      for (const record of normalizedRecords) {
        const existing = await tx.get(JOURNAL_STORES.VIEW, record.key)
        if (!discoveredRecordWins(record.value, existing && existing.value)) continue
        if (!existing) newViewRecords++
        await tx.put(JOURNAL_STORES.VIEW, {
          ...record,
          intentId: null,
          discoverySourceId: sourceId,
          discoveryCheckpointSequence: checkpointSequence,
          discoveryCheckpointHash: checkpointHash,
          updatedAt: observedAt
        })
        changedKeys.push(record.key)
      }
      if (meta.viewRecordCount + newViewRecords > this.limits.maxViewRecords) {
        throw journalError('PEERIT_JOURNAL_LIMIT', 'discovered batch exceeds the materialized-view record limit.')
      }
      await tx.put(JOURNAL_STORES.META, {
        key: floorKey,
        sourceId,
        checkpointSequence,
        checkpointHash,
        previousCheckpointHash,
        observedAt
      })
      meta.revision++
      if (changedKeys.length) meta.viewRevision++
      meta.viewRecordCount += newViewRecords
      if (!meta.createdAt) meta.createdAt = observedAt
      meta.updatedAt = Math.max(meta.updatedAt, observedAt)
      await tx.put(JOURNAL_STORES.META, meta)
      return { duplicate: false, changedKeys, checkpointSequence, checkpointHash }
    })
  }

  async getDiscoveryFloor (sourceId) {
    const key = discoveryFloorKey(sourceId)
    return this._transaction([JOURNAL_STORES.META], 'readonly', 'discovery floor read', async tx => {
      if (!tx) return null
      const value = await tx.get(JOURNAL_STORES.META, key)
      return value == null ? null : clone(value)
    })
  }

  async getView (key) {
    return this._transaction([JOURNAL_STORES.VIEW], 'readonly', 'view read', async tx => {
      if (!tx) return null
      const row = await tx.get(JOURNAL_STORES.VIEW, String(key))
      return row ? clone(row.value) : null
    })
  }

  async rangeView (options = {}) {
    const limit = Math.max(1, Math.min(1000, Number(options.limit) || 100))
    const query = { limit, direction: options.reverse ? 'prev' : 'next' }
    if (options.gte != null) query.lower = String(options.gte)
    if (options.gt != null) { query.lower = String(options.gt); query.lowerOpen = true }
    if (options.lte != null) query.upper = String(options.lte)
    if (options.lt != null) { query.upper = String(options.lt); query.upperOpen = true }
    return this._transaction([JOURNAL_STORES.VIEW], 'readonly', 'view range', async tx => {
      if (!tx) return []
      const rows = await tx.scan(JOURNAL_STORES.VIEW, query)
      return rows.map(row => ({ key: row.value.key, value: clone(row.value.value) }))
    })
  }

  async countView (prefix = '') {
    const query = prefix ? { prefix: String(prefix) } : {}
    return this._transaction([JOURNAL_STORES.VIEW], 'readonly', 'view count', async tx => tx ? tx.count(JOURNAL_STORES.VIEW, query) : 0)
  }

  async getIntent (rawIntentId) {
    const intentId = validateIntentId(rawIntentId)
    return this._transaction([JOURNAL_STORES.INTENTS, JOURNAL_STORES.TARGETS], 'readonly', 'intent read', async tx => {
      if (!tx) return null
      const intent = await tx.get(JOURNAL_STORES.INTENTS, intentId)
      if (!intent) return null
      const rows = await tx.scan(JOURNAL_STORES.TARGETS, { index: 'intentId', eq: intentId, limit: this.limits.maxTargetsPerIntent + 1 })
      if (rows.length > this.limits.maxTargetsPerIntent) throw journalError('PEERIT_JOURNAL_CORRUPT', 'Intent target count exceeds its schema bound.')
      intent.targets = Object.fromEntries(rows.map(row => [row.value.targetId, row.value]))
      return intent
    })
  }

  async listIntentIds (options = {}) {
    const limit = Math.max(1, Math.min(this.limits.deliveryBatch, Number(options.limit) || this.limits.deliveryBatch))
    return this._transaction([JOURNAL_STORES.INTENTS], 'readonly', 'intent index scan', async tx => {
      if (!tx) return { intentIds: [], hasMore: false }
      const query = { index: 'pendingOrderKey', limit: limit + 1 }
      if (options.after) { query.lower = String(options.after); query.lowerOpen = true }
      const rows = await tx.scan(JOURNAL_STORES.INTENTS, query)
      const page = rows.slice(0, limit)
      return {
        intentIds: page.map(row => row.value.intentId),
        cursor: page.length ? page[page.length - 1].value.pendingOrderKey : null,
        hasMore: rows.length > limit
      }
    })
  }

  async listRetryIntentIds (options = {}) {
    const limit = Math.max(1, Math.min(this.limits.deliveryBatch, Number(options.limit) || this.limits.deliveryBatch))
    const eligible = [...new Set(Array.isArray(options.targetIds) ? options.targetIds.map(String) : [])].sort()
    const reconcile = new Set(Array.isArray(options.reconcileTargetIds) ? options.reconcileTargetIds.map(String) : [])
    const now = Number.isSafeInteger(options.now) && options.now >= 0 ? options.now : this.clock()
    if (!eligible.length) return { intentIds: [], truncated: false }
    return this._transaction([JOURNAL_STORES.TARGETS], 'readonly', 'retry target scan', async tx => {
      if (!tx) return { intentIds: [], truncated: false }
      const lanes = []
      for (const targetId of eligible) {
        lanes.push({ targetId, state: 'retryable' })
        if (reconcile.has(targetId)) lanes.push({ targetId, state: 'pending-unknown' })
      }
      let truncated = false
      const pages = []
      for (const lane of lanes) {
        const bounds = targetStateDueBounds(lane.targetId, lane.state, now)
        const rows = await tx.scan(JOURNAL_STORES.TARGETS, {
          index: 'targetStateDueOrder',
          ...bounds,
          limit: limit + 1
        })
        if (rows.length > limit) truncated = true
        pages.push(rows.slice(0, limit))
      }
      const intentIds = new Set()
      for (let position = 0; intentIds.size < limit; position++) {
        let advanced = false
        for (const rows of pages) {
          const row = rows[position]
          if (!row) continue
          advanced = true
          intentIds.add(row.value.intentId)
          if (intentIds.size >= limit) break
        }
        if (!advanced) break
      }
      if (pages.reduce((total, rows) => total + rows.length, 0) > intentIds.size) truncated = true
      return { intentIds: [...intentIds], truncated }
    })
  }

  async claimTarget (options) {
    const intentId = validateIntentId(options.intentId)
    const targetId = boundedString(options.targetId, 'targetId', this.limits.maxTargetIdBytes)
    const nextState = TARGET_STATES.includes(options.state) ? options.state : null
    if (nextState !== 'preparing' && nextState !== 'delivering') throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Target claim state is invalid.')
    return this._transaction([JOURNAL_STORES.META, JOURNAL_STORES.INTENTS, JOURNAL_STORES.TARGETS], 'readwrite', 'target claim', async tx => {
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      const intent = await tx.get(JOURNAL_STORES.INTENTS, intentId)
      if (!intent) return null
      const key = targetKey(intentId, targetId)
      const before = await tx.get(JOURNAL_STORES.TARGETS, key)
      if (options.expectedState) {
        if (!before || before.state !== options.expectedState) return null
      } else if (before && (ACKNOWLEDGED.has(before.state) || ['preparing', 'delivering', 'pending-unknown', 'terminal'].includes(before.state))) {
        return null
      }
      if (!before && intent.targetCount >= this.limits.maxTargetsPerIntent) {
        // Target history is audit evidence and is never silently deleted to make
        // room for a rotating relay. Exhaustion is an ordinary non-claim result:
        // callers surface it as a bounded repair blocker while local authoring
        // and future intents remain live. This check is inside the transaction,
        // so a cross-tab last-slot race is also nonfatal.
        return null
      }
      if (before && RETRY_DUE_STATES.has(before.state) &&
          nonNegativeInteger(before.nextAttemptAt, 0) > options.now) return null
      const attemptToken = options.expectedState && before.attemptToken ? before.attemptToken : boundedString(options.attemptToken, 'attemptToken', 512)
      const target = {
        key,
        intentId,
        targetId,
        state: nextState,
        attempts: before ? Math.min(MAX_INDEX_NUMBER, normalizedAttempts(before.attempts) + 1) : 1,
        attemptToken,
        leaseUntil: options.leaseUntil,
        updatedAt: options.now,
        nextAttemptAt: 0,
        lastError: null,
        readbackVerified: before && before.readbackVerified === true,
        lastReadbackVerifiedAt: before && Number.isSafeInteger(before.lastReadbackVerifiedAt)
          ? before.lastReadbackVerifiedAt
          : null,
        lastReadbackEvidenceRef: (before && before.lastReadbackEvidenceRef) || null,
        lastReadbackEvidenceRevision: before && Number.isSafeInteger(before.lastReadbackEvidenceRevision)
          ? before.lastReadbackEvidenceRevision
          : 0,
        readbackCurrentInvalidated: before && before.readbackCurrentInvalidated === true,
        readbackRepairNeeded: before && before.readbackRepairNeeded === true,
        readbackRevalidationAttempts: before && Number.isSafeInteger(before.readbackRevalidationAttempts)
          ? before.readbackRevalidationAttempts
          : 0,
        readbackRevalidationNextAttemptAt: before && Number.isSafeInteger(before.readbackRevalidationNextAttemptAt)
          ? before.readbackRevalidationNextAttemptAt
          : 0,
        lastReadbackError: (before && before.lastReadbackError) || null,
        policyDurable: before && before.policyDurable === true,
        evidenceRef: (before && before.evidenceRef) || null
      }
      bumpTargetCount(meta, before && before.state, nextState)
      await tx.put(JOURNAL_STORES.TARGETS, target)
      if (!before) intent.targetCount++
      intent.updatedAt = options.now
      meta.revision++
      meta.updatedAt = options.now
      await tx.put(JOURNAL_STORES.INTENTS, intent)
      await tx.put(JOURNAL_STORES.META, meta)
      return attemptToken
    })
  }

  async transitionTarget (options) {
    return this._mutateTarget('target transition', options, async ({ target, intent, meta, tx }) => {
      if (target.attemptToken !== options.attemptToken || target.state !== options.from) return false
      bumpTargetCount(meta, target.state, options.to)
      target.state = options.to
      target.leaseUntil = options.leaseUntil
      target.updatedAt = options.now
      target.nextAttemptAt = 0
      await tx.put(JOURNAL_STORES.TARGETS, target)
      intent.updatedAt = options.now
      return true
    })
  }

  async completeTarget (options) {
    const evidenceRef = boundedString(options.evidenceRef, 'evidenceRef', this.limits.maxEvidenceRefBytes)
    return this._mutateTarget('target acknowledgement', options, async ({ target, intent, meta, tx }) => {
      if (target.attemptToken !== options.attemptToken || !['delivering', 'pending-unknown'].includes(target.state)) return false
      const nextState = options.readbackVerified === true ? 'readback-verified' : 'acknowledged'
      bumpTargetCount(meta, target.state, nextState)
      target.state = nextState
      target.leaseUntil = 0
      target.updatedAt = options.now
      target.nextAttemptAt = 0
      target.lastError = null
      target.readbackVerified = options.readbackVerified === true
      target.lastReadbackVerifiedAt = target.readbackVerified &&
        Number.isSafeInteger(options.readbackVerifiedAt) && options.readbackVerifiedAt >= 0
        ? options.readbackVerifiedAt
        : null
      target.lastReadbackEvidenceRef = target.lastReadbackVerifiedAt != null ? evidenceRef : null
      target.lastReadbackEvidenceRevision = target.lastReadbackVerifiedAt != null &&
        Number.isSafeInteger(options.readbackEvidenceRevision) && options.readbackEvidenceRevision >= 1
        ? options.readbackEvidenceRevision
        : 0
      target.readbackCurrentInvalidated = false
      target.readbackRepairNeeded = false
      target.readbackRevalidationAttempts = 0
      target.readbackRevalidationNextAttemptAt = 0
      target.lastReadbackError = null
      target.policyDurable = options.policyDurable === true
      target.evidenceRef = evidenceRef
      await tx.put(JOURNAL_STORES.TARGETS, target)
      const wasPending = intent.acknowledgedTargets === 0
      intent.acknowledgedTargets++
      if (target.readbackVerified) intent.readbackVerified++
      if (target.policyDurable) intent.policyDurable = true
      if (wasPending) {
        if (meta.pendingIntentCount < 1) throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit pending-intent counter underflowed.')
        meta.pendingIntentCount--
        intent.completedAt = options.now
        delete intent.pendingOrderKey
      }
      if (typeof options.discoveryState === 'string' && options.discoveryState) {
        intent.discoveryState = options.discoveryState.slice(0, 128)
      }
      intent.updatedAt = options.now
      return true
    })
  }

  // A historical verified GET remains an auditable receipt, but current
  // retrievability is a separate, expiring fact. Revalidation updates only that
  // fact in the same transaction as its repair/backoff marker; it never rewrites
  // the acknowledgement state and cannot authorize another PUT.
  async recordReadbackRevalidation (options) {
    const now = Number.isSafeInteger(options.now) && options.now >= 0
      ? options.now
      : null
    if (now == null) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'readback revalidation requires a non-negative now timestamp.')
    }
    const success = options.success === true
    const evidenceRef = success
      ? boundedString(options.evidenceRef, 'readback evidenceRef', this.limits.maxEvidenceRefBytes)
      : null
    const evidenceRevision = success && Number.isSafeInteger(options.evidenceRevision) && options.evidenceRevision >= 1
      ? options.evidenceRevision
      : null
    if (success && evidenceRevision == null) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'readback revalidation requires a positive evidence revision.')
    }
    return this._mutateTarget('readback revalidation', options, async ({ target, intent, tx }) => {
      if (target.state !== 'readback-verified' || target.readbackVerified !== true) return false
      if (success) {
        const currentRevision = nonNegativeInteger(target.lastReadbackEvidenceRevision, 0)
        if (evidenceRevision <= currentRevision) return false
        target.lastReadbackVerifiedAt = now
        target.lastReadbackEvidenceRef = evidenceRef
        target.lastReadbackEvidenceRevision = evidenceRevision
        target.readbackCurrentInvalidated = false
        target.readbackRepairNeeded = false
        target.readbackRevalidationAttempts = 0
        target.readbackRevalidationNextAttemptAt = 0
        target.lastReadbackError = null
      } else {
        const expectedEvidenceRevision = Number.isSafeInteger(options.expectedEvidenceRevision) &&
          options.expectedEvidenceRevision >= 0
          ? options.expectedEvidenceRevision
          : null
        if (expectedEvidenceRevision == null ||
            nonNegativeInteger(target.lastReadbackEvidenceRevision, 0) !== expectedEvidenceRevision) return false
        const attempts = Math.min(
          MAX_INDEX_NUMBER,
          nonNegativeInteger(target.readbackRevalidationAttempts, 0) + 1
        )
        target.readbackCurrentInvalidated = true
        target.readbackRepairNeeded = options.repairNeeded === true
        target.readbackRevalidationAttempts = attempts
        target.readbackRevalidationNextAttemptAt = target.readbackRepairNeeded
          ? 0
          : retryDueAt(options, attempts)
        target.lastReadbackError = String(options.lastError || 'readback-revalidation-failed').slice(0, 160)
      }
      target.updatedAt = now
      intent.updatedAt = now
      await tx.put(JOURNAL_STORES.TARGETS, target)
      return true
    })
  }

  async failTarget (options) {
    if (!TARGET_STATES.includes(options.state) || ACKNOWLEDGED.has(options.state)) {
      throw journalError('PEERIT_JOURNAL_BAD_INPUT', 'Target failure state is invalid.')
    }
    return this._mutateTarget('target failure', options, async ({ target, intent, meta, tx }) => {
      if (target.attemptToken !== options.attemptToken || !['preparing', 'delivering', 'pending-unknown'].includes(target.state)) return false
      bumpTargetCount(meta, target.state, options.state)
      target.state = options.state
      target.leaseUntil = 0
      target.updatedAt = options.now
      target.nextAttemptAt = RETRY_DUE_STATES.has(options.state)
        ? retryDueAt(options, target.attempts)
        : 0
      target.lastError = String(options.lastError || '').slice(0, 160)
      await tx.put(JOURNAL_STORES.TARGETS, target)
      intent.updatedAt = options.now
      return true
    })
  }

  async _mutateTarget (context, options, mutate) {
    const intentId = validateIntentId(options.intentId)
    const targetId = boundedString(options.targetId, 'targetId', this.limits.maxTargetIdBytes)
    return this._transaction([JOURNAL_STORES.META, JOURNAL_STORES.INTENTS, JOURNAL_STORES.TARGETS], 'readwrite', context, async tx => {
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      const intent = await tx.get(JOURNAL_STORES.INTENTS, intentId)
      const target = await tx.get(JOURNAL_STORES.TARGETS, targetKey(intentId, targetId))
      if (!intent || !target) return false
      const changed = await mutate({ target, intent, meta, tx })
      if (!changed) return false
      meta.revision++
      meta.updatedAt = options.now
      await tx.put(JOURNAL_STORES.INTENTS, intent)
      await tx.put(JOURNAL_STORES.META, meta)
      return true
    })
  }

  async recoverExpiredClaims (now = this.clock()) {
    return this._transaction([JOURNAL_STORES.META, JOURNAL_STORES.INTENTS, JOURNAL_STORES.TARGETS], 'readwrite', 'expired claim recovery', async tx => {
      const states = ['preparing', 'delivering']
      const perState = Math.max(1, Math.ceil(this.limits.deliveryBatch / states.length))
      const pages = []
      for (const state of states) {
        const bounds = stateLeaseBounds(state, now)
        pages.push(await tx.scan(JOURNAL_STORES.TARGETS, {
          index: 'stateLeaseOrder',
          ...bounds,
          limit: perState
        }))
      }
      if (pages.every(rows => rows.length === 0)) return 0
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      let changed = 0
      for (let position = 0; changed < this.limits.deliveryBatch; position++) {
        let advanced = false
        for (const rows of pages) {
          const row = rows[position]
          if (!row) continue
          advanced = true
          const target = row.value
          if (!['preparing', 'delivering'].includes(target.state) || target.leaseUntil > now) continue
          const nextState = target.state === 'preparing' ? 'retryable' : 'pending-unknown'
          bumpTargetCount(meta, target.state, nextState)
          target.state = nextState
          target.leaseUntil = 0
          target.updatedAt = now
          target.nextAttemptAt = now
          await tx.put(JOURNAL_STORES.TARGETS, target)
          const intent = await tx.get(JOURNAL_STORES.INTENTS, target.intentId)
          if (intent) { intent.updatedAt = now; await tx.put(JOURNAL_STORES.INTENTS, intent) }
          changed++
          if (changed >= this.limits.deliveryBatch) break
        }
        if (!advanced) break
      }
      if (!changed) return 0
      meta.revision++
      meta.updatedAt = now
      await tx.put(JOURNAL_STORES.META, meta)
      return changed
    })
  }

  async summary () {
    return this._transaction([JOURNAL_STORES.META, JOURNAL_STORES.INTENTS], 'readonly', 'status summary', async tx => {
      if (!tx) return { ...emptyMeta(), dormant: true, latest: null }
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      const latest = meta.latestIntentId ? await tx.get(JOURNAL_STORES.INTENTS, meta.latestIntentId) : null
      if (meta.latestIntentId && !latest) throw journalError('PEERIT_JOURNAL_CORRUPT', 'Latest intent index points to a missing record.')
      return { ...meta, dormant: false, latest }
    })
  }

  async nextWake (options = {}) {
    const now = Number.isSafeInteger(options.now) ? options.now : this.clock()
    const reconcile = new Set(options.reconcileTargetIds || [])
    const eligible = [...new Set(options.targetIds || [])].map(String).sort()
    if (!eligible.length) return null
    return this._transaction([JOURNAL_STORES.TARGETS], 'readonly', 'retry index scan', async tx => {
      if (!tx) return null
      let delay = Infinity
      for (const targetId of eligible) {
        for (const state of ['retryable', 'pending-unknown']) {
          if (state === 'pending-unknown' && !reconcile.has(targetId)) continue
          const rows = await tx.scan(JOURNAL_STORES.TARGETS, {
            index: 'targetStateDueOrder',
            ...targetStateDueBounds(targetId, state),
            limit: 1
          })
          if (!rows.length) continue
          delay = Math.min(delay, Math.max(0, nonNegativeInteger(rows[0].value.nextAttemptAt, now) - now))
        }
        for (const state of ['preparing', 'delivering']) {
          const rows = await tx.scan(JOURNAL_STORES.TARGETS, {
            index: 'targetStateLeaseOrder',
            ...targetStateLeaseBounds(targetId, state),
            limit: 1
          })
          if (!rows.length) continue
          delay = Math.min(delay, Math.max(0, (rows[0].value.leaseUntil || now) - now))
        }
      }
      return Number.isFinite(delay) ? delay : null
    })
  }

  async compact (options = {}) {
    const now = Number.isSafeInteger(options.now) ? options.now : this.clock()
    const ackRetention = Number.isSafeInteger(options.acknowledgedRetentionMs)
      ? options.acknowledgedRetentionMs
      : this.limits.acknowledgedRetentionMs
    const dedupeRetention = Number.isSafeInteger(options.dedupeRetentionMs)
      ? options.dedupeRetentionMs
      : this.limits.dedupeRetentionMs
    const cutoff = now - ackRetention
    return this._transaction(Object.values(JOURNAL_STORES), 'readwrite', 'journal compaction', async tx => {
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      const candidates = await tx.scan(JOURNAL_STORES.INTENTS, { index: 'completedAt', upper: cutoff, limit: this.limits.compactionBatch })
      let compacted = 0
      let pruned = 0
      for (const { value: intent } of candidates) {
        if (!intent.completedAt || intent.acknowledgedTargets < 1 || intent.intentId === meta.latestIntentId) continue
        const targets = await tx.scan(JOURNAL_STORES.TARGETS, { index: 'intentId', eq: intent.intentId, limit: this.limits.maxTargetsPerIntent + 1 })
        for (const { value: target } of targets) {
          bumpTargetCount(meta, target.state, null)
          await tx.delete(JOURNAL_STORES.TARGETS, target.key)
        }
        await tx.put(JOURNAL_STORES.DEDUPE, {
          intentId: intent.intentId,
          logicalId: intent.logicalId,
          wireFormat: intent.wireFormat,
          innerCodec: intent.innerCodec,
          innerLength: intent.innerLength,
          logicalHash: clone(intent.logicalHash),
          encodingCommitment: clone(intent.encodingCommitment),
          sizeClass: intent.sizeClass,
          completedAt: intent.completedAt,
          expiresAt: now + dedupeRetention
        })
        await tx.delete(JOURNAL_STORES.INTENTS, intent.intentId)
        meta.intentCount--
        meta.intentBytes -= intentPayloadByteLength(intent)
        if (meta.intentBytes < 0) throw journalError('PEERIT_JOURNAL_CORRUPT', 'Peerit exact-intent byte counter underflowed.')
        meta.dedupeCount++
        compacted++
      }
      const expired = await tx.scan(JOURNAL_STORES.DEDUPE, { index: 'expiresAt', upper: now, limit: this.limits.compactionBatch })
      for (const row of expired) {
        await tx.delete(JOURNAL_STORES.DEDUPE, row.value.intentId)
        meta.dedupeCount--
        pruned++
      }
      if (meta.dedupeCount > this.limits.maxDedupeRecords) {
        const excess = meta.dedupeCount - this.limits.maxDedupeRecords
        const oldest = await tx.scan(JOURNAL_STORES.DEDUPE, { index: 'completedAt', limit: Math.min(excess, this.limits.compactionBatch) })
        for (const row of oldest) {
          await tx.delete(JOURNAL_STORES.DEDUPE, row.value.intentId)
          meta.dedupeCount--
          pruned++
        }
      }
      if (compacted || pruned) {
        meta.revision++
        meta.updatedAt = now
        await tx.put(JOURNAL_STORES.META, meta)
      }
      return { compacted, pruned, remainingIntents: meta.intentCount, dedupeCount: meta.dedupeCount }
    })
  }

  async close () { await this.backend.close() }
}

export function createMemoryPeeritJournal (options = {}) {
  const shared = options.shared || createMemoryJournalState(options)
  const backend = options.backend || new MemoryJournalBackend({ ...options, shared })
  return new PeeritJournal({ ...options, backend })
}

export function createIndexedDbPeeritJournal (options = {}) {
  const backend = options.backend || new IndexedDbJournalBackend({
    ...options,
    markerStorage: options.markerStorage || options.legacyStorage || null
  })
  return new PeeritJournal({ ...options, backend })
}

export { JOURNAL_MARKER_KEY, JOURNAL_STORES, MemoryJournalBackend, createMemoryJournalState }
