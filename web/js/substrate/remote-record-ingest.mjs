// Verification and one-way ingest for Peerit records recovered from generic
// Blind Cells. This module accepts only a branded signed seed bootstrap, then
// re-runs the existing intrinsic operation authority over every exact envelope.

import {
  decodePeeritInnerOperationBatchV1,
  hashPeeritInnerCellEncodingCommitmentV1,
  hashPeeritInnerLogicalHashV1,
  hashPeeritInnerOperationIntentIdV1
} from './peerit-operation-authority-v1.js'
import { assertVerifiedPeeritSeedBootstrapV1 } from './seed-bootstrap-v1.mjs'

const VERIFIED_BATCHES = new WeakSet()

function fail (code, message, cause = undefined) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

function hex (value) {
  const bytes = value instanceof Uint8Array
    ? value
    : value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : ArrayBuffer.isView(value)
        ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        : fail('PEERIT_REMOTE_INGEST_BAD_BYTES', 'remote Cell result must contain bytes')
  let output = ''
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0')
  return output
}

function exactResult (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('PEERIT_REMOTE_INGEST_BAD_RESULT', 'remote Cell result must be an object')
  }
  const fields = ['evidenceRef', 'innerBytes', 'recordId', 'relayId', 'targetId', 'verified']
  const keys = Object.keys(input).sort()
  if (keys.length !== fields.length || keys.some((key, index) => key !== fields[index])) {
    fail('PEERIT_REMOTE_INGEST_BAD_RESULT', 'remote Cell result fields are missing or unexpected')
  }
  for (const field of ['recordId', 'relayId', 'targetId', 'innerBytes', 'evidenceRef']) {
    if (input[field] == null) fail('PEERIT_REMOTE_INGEST_BAD_RESULT', `remote Cell result is missing ${field}`)
  }
  if (!(input.innerBytes instanceof Uint8Array) && !(input.innerBytes instanceof ArrayBuffer) &&
      !ArrayBuffer.isView(input.innerBytes)) {
    fail('PEERIT_REMOTE_INGEST_BAD_BYTES', 'remote Cell result innerBytes must be binary')
  }
  if (input.verified !== true) {
    fail('PEERIT_REMOTE_INGEST_UNSIGNED_RESULT', 'remote Cell result lacks authenticated relay verification')
  }
  return input
}

function freeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) freeze(child)
  return Object.freeze(value)
}

export async function verifyPeeritRemoteSeedBatchV1 (bootstrapInput, resultInputs) {
  const bootstrap = assertVerifiedPeeritSeedBootstrapV1(bootstrapInput)
  if (!Array.isArray(resultInputs) || resultInputs.length !== bootstrap.payload.records.length) {
    fail('PEERIT_REMOTE_INGEST_INCOMPLETE', 'remote result set does not cover every signed bootstrap record exactly once')
  }
  const expected = new Map(bootstrap.payload.records.map(record => [record.recordId, record]))
  const observed = new Set()
  const wireKeys = new Set()
  const records = []
  const evidence = []

  for (const raw of resultInputs) {
    const result = exactResult(raw)
    const record = expected.get(result.recordId)
    if (!record || observed.has(result.recordId)) {
      fail('PEERIT_REMOTE_INGEST_UNDECLARED_RECORD', 'remote result is undeclared or duplicated')
    }
    observed.add(result.recordId)
    const replica = record.replicas.find(value => value.relayId === result.relayId)
    if (!replica || replica.targetId !== result.targetId) {
      fail('PEERIT_REMOTE_INGEST_REPLICA_MISMATCH', 'remote result is not bound to a declared record replica')
    }
    const innerBytes = result.innerBytes instanceof Uint8Array
      ? new Uint8Array(result.innerBytes)
      : new Uint8Array(result.innerBytes)
    if (innerBytes.byteLength !== record.innerLength) {
      fail('PEERIT_REMOTE_INGEST_ENVELOPE_MISMATCH', 'remote envelope length does not match the signed bootstrap')
    }
    let decoded
    try {
      decoded = await decodePeeritInnerOperationBatchV1(record.innerCodec, innerBytes, {
        expectedAuthorPublicKey: record.authorPublicKey
      })
    } catch (cause) {
      fail('PEERIT_REMOTE_INGEST_ENVELOPE_MISMATCH', 'remote envelope failed intrinsic Peerit operation authority', cause)
    }
    const intentId = hex(hashPeeritInnerOperationIntentIdV1(record.innerCodec, innerBytes))
    const logicalHash = hashPeeritInnerLogicalHashV1(record.innerCodec, innerBytes)
    const encodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
      record.innerCodec,
      innerBytes,
      logicalHash,
      decoded.sizeClass
    )
    if (intentId !== record.recordId || hex(logicalHash) !== record.logicalHash ||
        hex(encodingCommitment) !== record.encodingCommitment || decoded.sizeClass !== record.sizeClass ||
        decoded.operationWireKeys.length !== record.wireKeys.length ||
        decoded.operationWireKeys.some((key, index) => key !== record.wireKeys[index])) {
      fail('PEERIT_REMOTE_INGEST_ENVELOPE_MISMATCH', 'remote envelope does not reproduce its signed identity and wire-key commitments')
    }
    for (let index = 0; index < decoded.operations.length; index++) {
      const key = decoded.operationWireKeys[index]
      if (wireKeys.has(key)) {
        fail('PEERIT_REMOTE_INGEST_DUPLICATE_WIRE_KEY', 'two discovered Cells reduce to the same view key')
      }
      wireKeys.add(key)
      records.push({ key, value: decoded.operations[index].data })
    }
    const evidenceRef = String(result.evidenceRef)
    if (!evidenceRef || evidenceRef.length > 1024) {
      fail('PEERIT_REMOTE_INGEST_BAD_RESULT', 'remote Cell result evidence reference is invalid')
    }
    evidence.push({ recordId: record.recordId, relayId: result.relayId, targetId: result.targetId, evidenceRef })
  }

  const verified = freeze({
    version: 1,
    sourceId: bootstrap.sourceId,
    checkpointSequence: bootstrap.payload.bootstrapSequence,
    checkpointHash: bootstrap.artifactHash,
    previousCheckpointHash: bootstrap.payload.previousBootstrapHash,
    releaseSequence: bootstrap.payload.releaseSequence,
    releaseBoundBootstrapHash: bootstrap.artifactHash,
    records,
    evidence
  })
  VERIFIED_BATCHES.add(verified)
  return verified
}

export function assertVerifiedPeeritRemoteBatchV1 (value) {
  if (!value || typeof value !== 'object' || !VERIFIED_BATCHES.has(value)) {
    fail('PEERIT_REMOTE_INGEST_UNVERIFIED_BATCH', 'a verified Peerit remote batch is required')
  }
  return value
}

export async function ingestVerifiedPeeritRemoteBatchV1 (sync, batchInput, options = {}) {
  const batch = assertVerifiedPeeritRemoteBatchV1(batchInput)
  if (!sync || typeof sync.ingestVerifiedRemoteBatch !== 'function') {
    throw new TypeError('Peerit substrate sync remote-ingest boundary is required')
  }
  return sync.ingestVerifiedRemoteBatch(batch, options)
}
