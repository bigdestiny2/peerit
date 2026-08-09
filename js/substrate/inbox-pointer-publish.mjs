// peerit INBOX pointer publish v1 — after a record's CELL.PUT verifies on a
// relay, append the board-topic pointer frame to that relay's inbox so fresh
// readers can discover the record. Pure-JS only (strict-CSP safe: no
// node:crypto, no Buffer, no eval, no WASM).
//
// Spend discipline (the pow-issuance-v1 binding): ONE two-slot token per relay
// per record — slot 0 binds the CELL.PUT requestCommitment, slot 1 binds the
// INBOX.APPEND requestCommitment (beginOperationRecord's declared order). The
// mint can only happen once BOTH commitments exist, and the PUT embeds slot
// 0's presentation, so the append must be PREBUILT (and the token minted)
// before the PUT completes. This module therefore splits the flow:
//
//   preparePeeritInboxPointerV1  — build the frame, derive the deterministic
//     board topic, prebuild the APPEND request (fixed per-record+relay
//     clientNonce → byte-identical retry replays the original ack). Run
//     CONCURRENTLY with the caller's control.createCellReplica: the two
//     admission providers rendezvous inside the shared operation record and
//     ONE mint covers both. No relay traffic happens here at all.
//
//   publishPeeritInboxPointerV1  — gated on the completed, verified CELL.PUT
//     (receiptVerified + readbackVerified, bound byte-exactly to the session's
//     slot-0 commitment; NO inbox traffic happens before that assertion).
//     Probe READ (uncharged, limit 1): if the topic is absent, CREATE it first
//     with a FRESH one-slot token over the create requestCommitment (the only
//     create mint; a topic that already exists never re-mints). Then send the
//     prebuilt APPEND and verify the ack through the vendored control. Every
//     result is authenticated with control.verifyOperationResult; fields are
//     read off the authenticated snapshot with the strict local decoder.
//
// Replay: the append clientNonce is blake2b256("peerit/inbox-append-nonce/v1"
// ‖ recordCid ‖ relayPublicKey) — fixed per logical record+relay. A
// byte-identical resend (same frame, same nonce, same presentation) replays
// the original ack with the original appendRevision (exactly-once). Callers
// that may retry a publish must pin `now` so the frame is byte-identical.
import {
  asBytes,
  asciiBytes,
  blake2b256,
  bytesEqual,
  concatBytes,
  fixedBytesValue,
  hexToBytes
} from './release-control-primitives.mjs'
import { derivePeeritInboxTopicV1, validatePeeritInboxBoardSlugV1 } from './inbox-topic-v1.mjs'
import { encodePeeritInboxPointerFrameV1 } from './inbox-pointer-frame-v1.mjs'
import {
  decodePeeritInboxAppendAckSnapshotV1,
  decodePeeritInboxReceiptSnapshotV1
} from './inbox-read-result-decode.mjs'

export const PEERIT_INBOX_APPEND_NONCE_DOMAIN_V1 = 'peerit/inbox-append-nonce/v1'
export const PEERIT_INBOX_POINTER_PROFILE_ID_V1 = 8
export const PEERIT_INBOX_POINTER_SCHEME_ID_V1 = 1

// Canonical relay error codes (00-core/hiverelay blind-protocol registry.js).
const RELAY_ERROR = Object.freeze({ CONFLICT: 8, SPEND_INVALID: 10, NOT_FOUND: 13, EXPIRED: 14 })

const PREPARED_POINTERS = new WeakSet()

function fail (code, message, extra = undefined) {
  const error = new Error(message)
  error.code = code
  if (extra) Object.assign(error, extra)
  throw error
}

function relayFailure (operation, response) {
  const relayCode = response && response.error && Number.isSafeInteger(response.error.code)
    ? response.error.code
    : null
  const code = relayCode === RELAY_ERROR.NOT_FOUND
    ? 'PEERIT_INBOX_PUBLISH_NOT_FOUND'
    : relayCode === RELAY_ERROR.CONFLICT
      ? 'PEERIT_INBOX_PUBLISH_CONFLICT'
      : relayCode === RELAY_ERROR.SPEND_INVALID
        ? 'PEERIT_INBOX_PUBLISH_SPEND_INVALID'
        : relayCode === RELAY_ERROR.EXPIRED
          ? 'PEERIT_INBOX_PUBLISH_EXPIRED'
          : 'PEERIT_INBOX_PUBLISH_RELAY_ERROR'
  fail(code, `INBOX.${operation} was rejected by the relay`, {
    relayCode,
    relayRetryable: response && response.error ? response.error.retryable === 1 : null
  })
}

function normalizeRecord (value) {
  if (!value || typeof value !== 'object') {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'record is required')
  }
  const recordCid = hexToBytes(value.cid, 32, 'record.cid')
  const authorPubKey = fixedBytesValue(value.authorPubKey, 32, 'record.authorPubKey')
  if (!Number.isSafeInteger(value.sizeClass) || value.sizeClass < 1 || value.sizeClass > 5) {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'record.sizeClass is outside 1..5')
  }
  if (!Number.isSafeInteger(value.leaseClass) || value.leaseClass < 1 || value.leaseClass > 4) {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'record.leaseClass is outside 1..4')
  }
  if (value.boardSlug != null) validatePeeritInboxBoardSlugV1(value.boardSlug)
  return Object.freeze({
    recordCid,
    authorPubKey,
    sizeClass: value.sizeClass,
    leaseClass: value.leaseClass,
    boardSlug: value.boardSlug == null ? null : value.boardSlug
  })
}

function admissionFrom (spent, profileId, schemeId, parameterHash) {
  return Object.freeze({
    profileId,
    schemeId,
    parameterHash,
    token: spent.presentation
  })
}

// Phase 1: build the pointer frame and the admission-bearing APPEND request.
// `operationRecord` is the caller-opened beginOperationRecord session for
// [{relayPublicKey, kind:'put'}, {relayPublicKey, kind:'append'}]; this phase
// consumes its 'append' slot. Runs concurrently with the CELL.PUT replica
// construction so ONE mint covers both slots.
export async function preparePeeritInboxPointerV1 ({
  control,
  baseRuntime,
  relayPublicKey,
  boardSlug,
  record,
  hints,
  operationRecord,
  parameterHash,
  profileId = PEERIT_INBOX_POINTER_PROFILE_ID_V1,
  schemeId = PEERIT_INBOX_POINTER_SCHEME_ID_V1,
  now
} = {}) {
  validatePeeritInboxBoardSlugV1(boardSlug)
  if (typeof control?.createAppendInboxRequest !== 'function') {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'the vendored blind client control surface is required')
  }
  if (!operationRecord || typeof operationRecord.spend !== 'function') {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'an open pow-issuance operation record is required')
  }
  const relayKey = fixedBytesValue(relayPublicKey, 32, 'relayPublicKey')
  const parameterHashBytes = fixedBytesValue(parameterHash, 32, 'parameterHash')
  const normalized = normalizeRecord(record)
  if (normalized.boardSlug != null && normalized.boardSlug !== boardSlug) {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'record.boardSlug does not match the publish board')
  }
  const appendedAtUnixMillis = typeof now === 'function' ? now() : Date.now()
  const frame = encodePeeritInboxPointerFrameV1({
    boardSlug,
    recordCid: normalized.recordCid,
    authorPubKey: normalized.authorPubKey,
    sizeClass: normalized.sizeClass,
    leaseClass: normalized.leaseClass,
    appendedAtUnixMillis,
    hints: hints == null ? [] : hints
  })
  const topic = await derivePeeritInboxTopicV1({ boardSlug, relayPublicKey: relayKey, control, baseRuntime })
  const clientNonce = blake2b256(concatBytes(
    asciiBytes(PEERIT_INBOX_APPEND_NONCE_DOMAIN_V1),
    normalized.recordCid,
    relayKey))
  const append = await control.createAppendInboxRequest({
    runtime: baseRuntime,
    writeCap: topic.writeCap,
    frame,
    frameClass: 1,
    clientNonce,
    admissionProvider: async context => admissionFrom(
      await operationRecord.spend(context), profileId, schemeId, parameterHashBytes)
  })
  const appendRequestCommitment = asBytes(append.requestCommitment, 'append requestCommitment').slice()
  const registered = operationRecord.slotCommitment('append', relayKey)
  if (!registered || !bytesEqual(registered, appendRequestCommitment)) {
    fail('PEERIT_INBOX_PUBLISH_COMMITMENT_DRIFT',
      'the operation record append slot does not bind the prebuilt append requestCommitment')
  }
  const result = Object.freeze({
    boardSlug,
    relayPublicKey: relayKey.slice(),
    recordCid: normalized.recordCid.slice(),
    authorPubKey: normalized.authorPubKey.slice(),
    sizeClass: normalized.sizeClass,
    leaseClass: normalized.leaseClass,
    appendedAtUnixMillis: BigInt(appendedAtUnixMillis),
    frame,
    readCap: topic.readCap,
    physicalTopic: topic.physicalTopic,
    topic: topic.topic,
    append: Object.freeze({
      request: append.request,
      requestBytes: asBytes(append.requestBytes, 'append requestBytes').slice(),
      requestCommitment: appendRequestCommitment,
      wire: append.wire
    })
  })
  PREPARED_POINTERS.add(result)
  return result
}

// Phase 2: probe → (CREATE only when absent) → APPEND → verified evidence.
export async function publishPeeritInboxPointerV1 ({
  control,
  baseRuntime,
  endpoints,
  httpClient,
  relayPublicKey,
  boardSlug,
  record,
  cellPut,
  prepared,
  operationRecord,
  spendFactory,
  parameterHash,
  profileId = PEERIT_INBOX_POINTER_PROFILE_ID_V1,
  schemeId = PEERIT_INBOX_POINTER_SCHEME_ID_V1,
  timeoutMillis,
  signal,
  onEvent
} = {}) {
  validatePeeritInboxBoardSlugV1(boardSlug)
  if (!prepared || !PREPARED_POINTERS.has(prepared)) {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'a preparePeeritInboxPointerV1 output is required')
  }
  if (prepared.boardSlug !== boardSlug) {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'prepared pointer is for a different board')
  }
  const relayKey = fixedBytesValue(relayPublicKey, 32, 'relayPublicKey')
  if (!bytesEqual(prepared.relayPublicKey, relayKey)) {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'prepared pointer is for a different relay')
  }
  if (record != null) {
    const normalized = normalizeRecord(record)
    if (!bytesEqual(normalized.recordCid, prepared.recordCid)) {
      fail('PEERIT_INBOX_PUBLISH_INVALID', 'record.cid does not match the prepared pointer')
    }
  }
  const parameterHashBytes = fixedBytesValue(parameterHash, 32, 'parameterHash')
  if (!endpoints || !endpoints.read || !endpoints.create || !endpoints.append) {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'verified read/create/append endpoints are required')
  }
  const client = httpClient || new control.BlindDirectHttpClient({ runtime: baseRuntime })
  if (typeof control.verifyOperationResult !== 'function' || !client ||
      typeof client.request !== 'function') {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'the vendored control surface and a direct http client are required')
  }
  const event = value => {
    if (typeof onEvent === 'function') onEvent(Object.freeze(value))
  }

  // Gate: NO inbox traffic before the CELL.PUT on THIS relay is complete and
  // verified, and the cell put is bound byte-exactly to slot 0 of the same
  // operation record whose slot 1 admitted this append.
  if (!cellPut || typeof cellPut !== 'object' ||
      cellPut.receiptVerified !== true || cellPut.readbackVerified !== true) {
    fail('PEERIT_INBOX_PUBLISH_PUT_UNVERIFIED',
      'the record\'s CELL.PUT receipt and byte-exact readback must be verified before any INBOX traffic')
  }
  const putCommitment = fixedBytesValue(cellPut.requestCommitment, 32, 'cellPut.requestCommitment')
  if (!operationRecord || typeof operationRecord.slotCommitment !== 'function') {
    fail('PEERIT_INBOX_PUBLISH_INVALID', 'the publish operation record is required')
  }
  if (!bytesEqual(operationRecord.slotCommitment('put', relayKey) || new Uint8Array(0), putCommitment)) {
    fail('PEERIT_INBOX_PUBLISH_COMMITMENT_DRIFT',
      'cellPut.requestCommitment is not the operation record\'s slot-0 (put) commitment')
  }
  if (!bytesEqual(operationRecord.slotCommitment('append', relayKey) || new Uint8Array(0),
      prepared.append.requestCommitment)) {
    fail('PEERIT_INBOX_PUBLISH_COMMITMENT_DRIFT',
      'the prepared append is not the operation record\'s slot-1 (append) commitment')
  }
  operationRecord.close()

  // Probe: uncharged READ, limit 1, no cursor. NOT_FOUND means the board topic
  // does not exist on this relay yet; anything else is a relay failure.
  event({ phase: 'probe', topic: prepared.topic })
  const probe = await control.createReadInboxRequest({
    runtime: baseRuntime,
    readCap: prepared.readCap,
    limit: 1
  })
  const probeResponse = await client.request({
    endpoint: endpoints.read,
    familyId: probe.wire.familyId,
    operationId: probe.wire.operationId,
    expectedResultBodyBytes: probe.wire.expectedResultBodyBytes,
    body: probe.requestBytes,
    timeoutMillis,
    signal
  })
  let topicExists
  if (probeResponse && probeResponse.ok === true) {
    control.verifyOperationResult({
      endpoint: endpoints.read,
      request: probe.request,
      requestCommitment: probe.requestCommitment,
      resultBytes: probeResponse.body
    })
    topicExists = true
  } else if (probeResponse && probeResponse.error && probeResponse.error.code === RELAY_ERROR.NOT_FOUND) {
    topicExists = false
  } else {
    relayFailure('READ(probe)', probeResponse)
  }

  // CREATE only when the topic is absent: a FRESH one-slot token over the
  // create requestCommitment (the deterministic derivation makes the request
  // byte-identical across publishers and re-creations).
  let created = false
  let createEvidence = null
  let createRequest = null
  let createRequestBytes = null
  let createRequestCommitment = null
  let createWire = null
  if (!topicExists) {
    const createRecord = spendFactory.beginOperationRecord({
      operations: [{ relayPublicKey: relayKey, kind: 'create' }]
    })
    try {
      const derived = await derivePeeritInboxTopicV1({
        boardSlug,
        relayPublicKey: relayKey,
        control,
        baseRuntime,
        admissionProvider: async context => admissionFrom(
          await createRecord.spend(context), profileId, schemeId, parameterHashBytes)
      })
      if (!bytesEqual(derived.physicalTopic, prepared.physicalTopic)) {
        fail('PEERIT_INBOX_PUBLISH_TOPIC_DRIFT',
          'the charged CREATE derivation does not reproduce the prepared topic')
      }
      event({ phase: 'create', topic: prepared.topic })
      const response = await client.request({
        endpoint: endpoints.create,
        familyId: derived.wire.familyId,
        operationId: derived.wire.operationId,
        expectedResultBodyBytes: derived.wire.expectedResultBodyBytes,
        body: derived.requestBytes,
        timeoutMillis,
        signal
      })
      if (!response || response.ok !== true) relayFailure('CREATE', response)
      const verified = control.verifyOperationResult({
        endpoint: endpoints.create,
        request: derived.request,
        requestCommitment: derived.requestCommitment,
        resultBytes: response.body
      })
      const receipt = decodePeeritInboxReceiptSnapshotV1(verified.snapshotBytes())
      created = true
      createEvidence = verified.snapshotBytes()
      createRequest = derived.request
      createRequestBytes = derived.requestBytes
      createRequestCommitment = derived.requestCommitment
      createWire = derived.wire
      event({ phase: 'created', topic: prepared.topic, stateRevision: receipt.stateRevision })
    } finally {
      createRecord.close()
    }
  }

  // APPEND the prebuilt pointer frame; the fixed clientNonce makes a
  // byte-identical retry replay the original ack (exactly-once).
  event({ phase: 'append', topic: prepared.topic })
  const appendResponse = await client.request({
    endpoint: endpoints.append,
    familyId: prepared.append.wire.familyId,
    operationId: prepared.append.wire.operationId,
    expectedResultBodyBytes: prepared.append.wire.expectedResultBodyBytes,
    body: prepared.append.requestBytes,
    timeoutMillis,
    signal
  })
  if (!appendResponse || appendResponse.ok !== true) relayFailure('APPEND', appendResponse)
  const appendVerified = control.verifyOperationResult({
    endpoint: endpoints.append,
    request: prepared.append.request,
    requestCommitment: prepared.append.requestCommitment,
    resultBytes: appendResponse.body
  })
  const ack = decodePeeritInboxAppendAckSnapshotV1(appendVerified.snapshotBytes())
  if (!bytesEqual(ack.frameHash, blake2b256(prepared.frame))) {
    fail('PEERIT_INBOX_PUBLISH_RELAY_DRIFT', 'the append ack frameHash does not match the published frame')
  }
  const appendEvidence = appendVerified.snapshotBytes()
  event({ phase: 'done', topic: prepared.topic, appendRevision: ack.appendRevision, created })
  return Object.freeze({
    topic: prepared.topic,
    physicalTopic: prepared.physicalTopic.slice(),
    appendRevision: ack.appendRevision,
    appendStoredAtEpoch: ack.storedAtEpoch,
    appendExpiresAtEpoch: ack.expiresAtEpoch,
    appendEvidence,
    appendRequestBytes: prepared.append.requestBytes.slice(),
    appendRequestCommitment: prepared.append.requestCommitment.slice(),
    appendWire: prepared.append.wire,
    created,
    createEvidence,
    createRequest,
    createRequestBytes,
    createRequestCommitment,
    createWire
  })
}
