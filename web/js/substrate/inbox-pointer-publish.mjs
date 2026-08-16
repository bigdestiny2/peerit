// Sequence-29 global public-INBOX publisher. Topic lifecycle is deliberately
// absent: the signed release bootstrap supplies the two already-created
// OPEN_APPEND capabilities, and browsers can only seal + APPEND an INLINE
// signed announcement.
import { asBytes, blake2b256, bytesEqual } from './release-control-primitives.mjs'
import {
  isVerifiedPeeritLimitedPublicInboxBootstrapV1
} from './inbox-topic-v1.mjs'
import {
  PEERIT_INBOX_ANNOUNCEMENT_FRAME_CLASS_V1,
  sealPeeritInboxAnnouncementFrameV1
} from './inbox-pointer-frame-v1.mjs'
import {
  decodePeeritInboxAppendAckSnapshotV1,
  decodePeeritInboxReadResultSnapshotV1
} from './inbox-read-result-decode.mjs'

const PREPARED = new WeakSet()

function fail (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

export async function preparePeeritPublicInboxAnnouncementV1 (input = {}) {
  const { authority, binding, control, runtime } = input
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(authority) ||
      !authority.bindings.includes(binding)) {
    fail('PEERIT_PUBLIC_INBOX_APPEND_INVALID', 'verified bootstrap binding is required')
  }
  if (typeof control?.createAppendInboxRequest !== 'function') {
    fail('PEERIT_PUBLIC_INBOX_APPEND_INVALID', 'public browser APPEND control is required')
  }
  const frame = await sealPeeritInboxAnnouncementFrameV1({
    authority,
    binding,
    announcementBytes: input.announcementBytes
  })
  const append = await control.createAppendInboxRequest({
    runtime,
    readCap: binding.readCap,
    frame,
    frameClass: PEERIT_INBOX_ANNOUNCEMENT_FRAME_CLASS_V1,
    admission: input.admission,
    admissionProvider: input.admissionProvider,
    clientNonce: input.clientNonce
  })
  const prepared = Object.freeze({
    authority,
    binding,
    frame,
    request: append.request,
    requestBytes: asBytes(append.requestBytes, 'APPEND request bytes').slice(),
    requestCommitment: asBytes(append.requestCommitment, 'APPEND request commitment').slice(),
    wire: append.wire
  })
  PREPARED.add(prepared)
  return prepared
}

// Rebuilds the module brand after reload from the exact durable request. The
// authenticated client must reproduce the byte-identical frame, request and
// commitment from the stored nonce/admission; otherwise recovery stops before
// any transport call.
export async function restorePeeritPublicInboxAnnouncementV1 (input = {}) {
  const { authority, binding, control, runtime } = input
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(authority) ||
      !authority.bindings.includes(binding) || !input.request ||
      typeof input.request !== 'object') {
    fail('PEERIT_PUBLIC_INBOX_APPEND_RECOVERY_INVALID',
      'verified bootstrap binding and exact durable APPEND request are required')
  }
  const frame = asBytes(input.frame, 'durable APPEND frame').slice()
  const recreated = await control.createAppendInboxRequest({
    runtime,
    readCap: binding.readCap,
    frame,
    frameClass: PEERIT_INBOX_ANNOUNCEMENT_FRAME_CLASS_V1,
    admission: input.request.admission,
    clientNonce: input.request.clientNonce
  })
  const requestBytes = asBytes(input.requestBytes, 'durable APPEND request bytes')
  const requestCommitment = asBytes(
    input.requestCommitment, 'durable APPEND request commitment')
  if (!bytesEqual(recreated.requestBytes, requestBytes) ||
      !bytesEqual(recreated.requestCommitment, requestCommitment)) {
    fail('PEERIT_PUBLIC_INBOX_APPEND_RECOVERY_INVALID',
      'durable APPEND request cannot be reproduced byte-for-byte')
  }
  const prepared = Object.freeze({
    authority,
    binding,
    frame,
    request: recreated.request,
    requestBytes: requestBytes.slice(),
    requestCommitment: requestCommitment.slice(),
    wire: recreated.wire
  })
  PREPARED.add(prepared)
  return prepared
}

// After an ambiguous send/reload, authenticate the relay's complete bounded
// READ snapshot and look for the exact frame before deciding whether the same
// prepared request may be sent again. A matching hash with different bytes is
// treated as corruption, never as success.
export async function reconcilePeeritPublicInboxAnnouncementV1 (input = {}) {
  const { prepared, control, endpoint, signal, timeoutMillis } = input
  if (!PREPARED.has(prepared) || typeof control?.createReadInboxRequest !== 'function' ||
      typeof control?.verifyOperationResult !== 'function') {
    fail('PEERIT_PUBLIC_INBOX_APPEND_RECOVERY_INVALID',
      'module-restored APPEND and authenticated READ control are required')
  }
  const client = input.httpClient || new control.BlindDirectHttpClient({ runtime: input.runtime })
  const expectedHash = blake2b256(prepared.frame)
  let cursor = null
  let pages = 0
  let snapshotRevision = 0n
  for (;;) {
    const read = await control.createReadInboxRequest({
      runtime: input.runtime,
      readCap: prepared.binding.readCap,
      cursor,
      limit: 64
    })
    const response = await client.request({
      endpoint,
      ...read.wire,
      body: read.requestBytes,
      signal,
      timeoutMillis
    })
    if (!response || response.ok !== true) {
      fail('PEERIT_PUBLIC_INBOX_APPEND_RECONCILE_REJECTED',
        'authenticated public INBOX READ reconciliation was rejected', response?.error)
    }
    let decoded
    try {
      const verified = await control.verifyOperationResult({
        endpoint,
        request: read.request,
        requestCommitment: read.requestCommitment,
        resultBytes: response.body
      })
      decoded = decodePeeritInboxReadResultSnapshotV1(verified.snapshotBytes())
    } catch (cause) {
      fail('PEERIT_PUBLIC_INBOX_APPEND_RECONCILE_INVALID',
        'public INBOX READ reconciliation failed result authentication', cause)
    }
    pages++
    snapshotRevision = decoded.snapshotRevision
    for (const entry of decoded.entries) {
      if (!bytesEqual(entry.frameHash, expectedHash)) continue
      if (!bytesEqual(entry.frame, prepared.frame)) {
        fail('PEERIT_PUBLIC_INBOX_APPEND_RECONCILE_INVALID',
          'authenticated READ returned a frame-hash collision')
      }
      return Object.freeze({
        present: true,
        appendRevision: entry.appendRevision,
        snapshotRevision,
        pagesRead: pages,
        requestCommitment: prepared.requestCommitment.slice()
      })
    }
    if (decoded.nextCursor == null) break
    if (pages >= 64) {
      fail('PEERIT_PUBLIC_INBOX_APPEND_RECONCILE_INVALID',
        'public INBOX reconciliation exceeded its bounded history')
    }
    cursor = decoded.nextCursor
  }
  return Object.freeze({
    present: false,
    snapshotRevision,
    pagesRead: pages,
    requestCommitment: prepared.requestCommitment.slice()
  })
}

export async function publishPeeritPublicInboxAnnouncementV1 (input = {}) {
  const { prepared, control, endpoint, signal, timeoutMillis } = input
  if (!PREPARED.has(prepared)) {
    fail('PEERIT_PUBLIC_INBOX_APPEND_INVALID', 'prepared public INBOX APPEND is required')
  }
  if (typeof control?.verifyOperationResult !== 'function') {
    fail('PEERIT_PUBLIC_INBOX_APPEND_INVALID', 'public browser result verifier is required')
  }
  const client = input.httpClient || new control.BlindDirectHttpClient({ runtime: input.runtime })
  if (!client || typeof client.request !== 'function') {
    fail('PEERIT_PUBLIC_INBOX_APPEND_INVALID', 'direct HTTP client is required')
  }
  const response = await client.request({
    endpoint,
    ...prepared.wire,
    body: prepared.requestBytes,
    signal,
    timeoutMillis
  })
  if (!response || response.ok !== true) {
    const error = response?.error
    fail('PEERIT_PUBLIC_INBOX_APPEND_REJECTED', 'public INBOX APPEND was rejected', error)
  }
  let verified
  let decoded
  try {
    verified = await control.verifyOperationResult({
      endpoint,
      request: prepared.request,
      requestCommitment: prepared.requestCommitment,
      resultBytes: response.body
    })
    decoded = decodePeeritInboxAppendAckSnapshotV1(verified.snapshotBytes())
  } catch (cause) {
    fail('PEERIT_PUBLIC_INBOX_APPEND_RESULT_INVALID',
      'public INBOX APPEND result authentication failed', cause)
  }
  if (!bytesEqual(decoded.frameHash, blake2b256(prepared.frame))) {
    fail('PEERIT_PUBLIC_INBOX_APPEND_RESULT_INVALID', 'APPEND ack does not bind the sealed frame')
  }
  return Object.freeze({
    appendRevision: decoded.appendRevision,
    storedAtEpoch: decoded.storedAtEpoch,
    expiresAtEpoch: decoded.expiresAtEpoch,
    requestCommitment: prepared.requestCommitment.slice()
  })
}
