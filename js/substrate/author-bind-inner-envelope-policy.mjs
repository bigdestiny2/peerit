import { bytesEqual } from './release-control-primitives.mjs'

// These values are part of the Peerit consumer profile, not HiveRelay's wire
// protocol. Keeping them here gives the local writer and structural validator one
// narrow source of truth without importing a generated browser artifact.
export const PEERIT_INNER_OPERATION_BATCH_V1_CODEC = 334
export const PEERIT_INNER_OPERATION_BATCH_V1_VERSION = 1
export const PEERIT_INNER_OPERATION_BATCH_V1_MIN_BYTES = 8n
export const PEERIT_INNER_OPERATION_BATCH_V1_MAX_BYTES = 1048519n
export const PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MIN = 1
export const PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MAX = 5

// These are the authenticated V1 Cell classes (4 KiB through 1 MiB) less the
// frozen cell wrapper overhead: version (1), nonce (12), GCM tag (16), and
// structured-content length (4). The browser client currently does not export
// this calculation, so the profile pins the resulting values rather than
// guessing from an application-provided capacity callback.
export const PEERIT_AUTHOR_BIND_CELL_CONTENT_CAPACITY_V1 = Object.freeze({
  1: 4063n,
  2: 16351n,
  3: 65503n,
  4: 262111n,
  5: 1048543n
})

function failure (message) {
  const error = new Error(message)
  error.code = 'BAD_AUTHOR_BIND'
  throw error
}

function equalBytes (left, right) {
  try {
    return bytesEqual(left, right)
  } catch {
    return false
  }
}

export function peeritAuthorBindCellSizeClassForInnerLengthV1 (innerLength) {
  if (typeof innerLength !== 'bigint' ||
      innerLength < PEERIT_INNER_OPERATION_BATCH_V1_MIN_BYTES ||
      innerLength > PEERIT_INNER_OPERATION_BATCH_V1_MAX_BYTES) {
    failure('author bind inner envelope length is outside the V1 Cell range')
  }
  for (let sizeClass = PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MIN;
    sizeClass <= PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MAX;
    sizeClass++) {
    if (innerLength <= PEERIT_AUTHOR_BIND_CELL_CONTENT_CAPACITY_V1[sizeClass]) return sizeClass
  }
  failure('author bind inner envelope has no supported Cell size class')
}

// V1 deliberately limits initial author bindings to Cell replicas. A Cell is
// the only representation for which the current protocol requires a
// capability-bound decrypting readback before the author head can advance. Core
// support belongs in a future profile revision with proof parity, not in a
// permissive fallback here.
export function assertPeeritAuthorBindInnerEnvelopeV1 (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    failure('author bind must be a decoded record object')
  }
  if (value.innerCodec !== PEERIT_INNER_OPERATION_BATCH_V1_CODEC) {
    failure('author bind does not name PeeritInnerOperationBatchV1')
  }
  if (typeof value.innerLength !== 'bigint' ||
      value.innerLength < PEERIT_INNER_OPERATION_BATCH_V1_MIN_BYTES ||
      value.innerLength > PEERIT_INNER_OPERATION_BATCH_V1_MAX_BYTES) {
    failure('author bind inner envelope length is outside the V1 Cell range')
  }
  const requiredSizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(value.innerLength)
  if (!Array.isArray(value.initialReplicas) || value.initialReplicas.length < 1 || value.initialReplicas.length > 16) {
    failure('author bind must contain one to sixteen initial Cell replicas')
  }

  const first = value.initialReplicas[0]
  if (!first || typeof first !== 'object' ||
      !Number.isSafeInteger(first.sizeClass) ||
      first.sizeClass < PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MIN ||
      first.sizeClass > PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MAX) {
    failure('author bind first Cell replica has an unsupported size class')
  }
  if (first.sizeClass !== requiredSizeClass) {
    failure('author bind Cell size class is not the smallest class that contains its inner envelope')
  }

  for (const replica of value.initialReplicas) {
    if (!replica || typeof replica !== 'object') failure('author bind contains a malformed Cell replica')
    if (!Number.isSafeInteger(replica.sizeClass) ||
        replica.sizeClass < PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MIN ||
        replica.sizeClass > PEERIT_AUTHOR_BIND_CELL_SIZE_CLASS_MAX) {
      failure('author bind contains a Cell replica with an unsupported size class')
    }
    if (!equalBytes(replica.logicalHash, value.logicalHash)) {
      failure('author bind Cell replica logical hash does not match the envelope')
    }
    if (replica.sizeClass !== first.sizeClass ||
        !equalBytes(replica.encodingCommitment, first.encodingCommitment)) {
      failure('author bind Cell replicas must share one size class and encoding commitment')
    }
  }

  return Object.freeze({
    innerCodec: value.innerCodec,
    innerLength: value.innerLength,
    sizeClass: first.sizeClass,
    encodingCommitment: new Uint8Array(first.encodingCommitment)
  })
}
