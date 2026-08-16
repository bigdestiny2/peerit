// Sequence-29 public-INBOX discovery. Every accepted record crosses the exact
// chain: verified bootstrap binding -> authenticated READ -> encrypted INLINE
// signed announcement -> signed AuthorBind -> same-relay public ReadCellCap ->
// authenticated CELL.GET -> intrinsic tag-334 operation-authority validation.
import {
  asBytes,
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  concatBytes,
  u16Bytes,
  u64Bytes
} from './release-control-primitives.mjs'
import {
  isVerifiedPeeritLimitedPublicInboxBootstrapV1
} from './inbox-topic-v1.mjs'
import { openPeeritInboxAnnouncementFrameV1 } from './inbox-pointer-frame-v1.mjs'
import { decodePeeritInboxReadResultSnapshotV1 } from './inbox-read-result-decode.mjs'
import { decodePeeritInnerOperationBatchV1 } from './peerit-operation-authority-v1.js'

const MAX_READ_PAGES = 64
const LEASE_EPOCH_MILLIS = 21600000n
const VERIFIED_POLL_RESULTS = new WeakMap()
const VERIFIED_ANNOUNCEMENT_READBACKS = new WeakMap()
const ADVANCEABLE_ENTRY_REJECTIONS = new WeakSet()

function fail (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

// Only deterministic invalid content from an already authenticated READ entry
// may be skipped while advancing its append floor. Network rejection, abort,
// timeout, missing runtime authority, or local crypto setup failure must abort
// the whole poll so the durable floor remains unchanged and the entry retries.
function authenticatedEntryRejectionMayAdvance (error) {
  return error != null && typeof error === 'object' &&
    ADVANCEABLE_ENTRY_REJECTIONS.has(error)
}

function rejectAuthenticatedEntry (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  ADVANCEABLE_ENTRY_REJECTIONS.add(error)
  throw error
}

function sameRelay (left, right) {
  return bytesEqual(left, right)
}

async function openAuthenticatedAnnouncement (input) {
  try {
    return await openPeeritInboxAnnouncementFrameV1(input)
  } catch (cause) {
    const message = String(cause?.message || '')
    if (cause?.code === 'PEERIT_INBOX_ANNOUNCEMENT_FRAME_INVALID' &&
        (/must be exactly 4096 bytes/.test(message) ||
          /frame authentication failed/.test(message) ||
          /decrypted (?:frame plaintext|announcement) length is invalid/.test(message))) {
      rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_FRAME_INVALID',
        'authenticated READ entry carries a deterministically invalid announcement frame', cause)
    }
    throw cause
  }
}

function validateAnnouncement (profileValidator, announcementBytes, binding, nowUnixMillis) {
  if (!profileValidator || typeof profileValidator.validate !== 'function') {
    fail('PEERIT_PUBLIC_INBOX_PROFILE_VALIDATOR_REQUIRED',
      'authenticated Peerit profile validator is required')
  }
  let announcement
  let authorBind
  try {
    announcement = profileValidator.validate(
      'PeeritAnnouncementV1', announcementBytes).value
    if (announcement.version !== 1 || announcement.manifestTag !== 3 ||
        announcement.manifestMode !== 1 || announcement.manifestReadCaps.length !== 0) {
      rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_ANNOUNCEMENT_INVALID',
        'announcement is not the accepted INLINE AuthorBind form')
    }
    authorBind = profileValidator.validate(
      'AuthorBindV1', announcement.manifestRecord).value
  } catch (cause) {
    if (authenticatedEntryRejectionMayAdvance(cause)) throw cause
    fail('PEERIT_PUBLIC_INBOX_PROFILE_VALIDATION_FAILED',
      'signed announcement or AuthorBind validator execution failed', cause)
  }
  const manifestRecordId = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.manifest-record-id.v1'),
    u16Bytes(3),
    u64Bytes(announcement.manifestRecord.byteLength),
    announcement.manifestRecord
  ))
  const currentLeaseEpoch = Number(nowUnixMillis / LEASE_EPOCH_MILLIS)
  if (!bytesEqual(announcement.manifestRecordId, manifestRecordId) ||
      announcement.publishedLeaseEpoch > currentLeaseEpoch + 1 ||
      authorBind.innerCodec !== 334 ||
      authorBind.innerLength < 8n ||
      authorBind.innerLength > 1048519n) {
    rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_ANNOUNCEMENT_INVALID',
      'announcement record ID, time, or inner envelope bounds are invalid')
  }
  const replica = authorBind.initialReplicas.find(value =>
    sameRelay(value.relayPublicKey, binding.relayPublicKey))
  if (!replica) {
    rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_SAME_RELAY_CAP_REQUIRED',
      'AuthorBind has no public Cell read capability for the announcing relay')
  }
  if (!bytesEqual(replica.logicalHash, authorBind.logicalHash)) {
    rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_AUTHOR_BIND_INVALID',
      'same-relay replica does not bind the AuthorBind logical hash')
  }
  return Object.freeze({ announcement, authorBind, replica })
}

async function getSameRelayInner ({
  control, runtime, profile, binding, cellEndpoint, httpClient, timeoutMillis, signal
}) {
  let readCap
  try {
    readCap = control.decodeBlindExternalProfileValueV1(
      'ReadCellCapV1', profile.replica.readCapability)
  } catch (cause) {
    fail('PEERIT_PUBLIC_INBOX_READ_CAP_DECODE_FAILED',
      'same-relay ReadCellCapV1 decoder execution failed', cause)
  }
  if (!sameRelay(readCap.relayPublicKey, binding.relayPublicKey) ||
      !sameRelay(profile.replica.relayPublicKey, readCap.relayPublicKey) ||
      readCap.sizeClass !== profile.replica.sizeClass ||
      !bytesEqual(readCap.expectedCellBlobHash, profile.replica.cellBlobHash)) {
    rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_READ_CAP_INVALID',
      'same-relay ReadCellCapV1 differs from its signed replica binding')
  }
  const get = await control.createGetCellRequest({ runtime, readCap })
  const response = await httpClient.request({
    endpoint: cellEndpoint,
    ...get.wire,
    body: get.requestBytes,
    timeoutMillis,
    signal
  })
  if (!response || response.ok !== true) {
    fail('PEERIT_PUBLIC_INBOX_CELL_GET_REJECTED',
      'same-relay CELL.GET was rejected', response?.error)
  }
  let verified
  try {
    verified = await control.verifyOperationResult({
      endpoint: cellEndpoint,
      request: get.request,
      requestCommitment: get.requestCommitment,
      resultBytes: response.body
    })
  } catch (cause) {
    fail('PEERIT_PUBLIC_INBOX_CELL_GET_RESULT_INVALID',
      'same-relay CELL.GET result authentication failed', cause)
  }
  let inner
  try {
    inner = await control.openVerifiedCellGetResult({
      verifiedResult: verified,
      runtime,
      readCap
    })
  } catch (cause) {
    fail('PEERIT_PUBLIC_INBOX_CELL_GET_OPEN_INVALID',
      'same-relay CELL.GET capability opening failed', cause)
  }
  let operationBatch
  try {
    operationBatch = await decodePeeritInnerOperationBatchV1(
      profile.authorBind.innerCodec,
      inner,
      { expectedAuthorPublicKey: bytesToHex(profile.authorBind.authorPublicKey) }
    )
  } catch (cause) {
    // The intrinsic decoder is locally implemented and emits stable protocol
    // validation codes. Unknown exceptions are local/runtime failures and must
    // retry rather than becoming permanent append-floor skips.
    if (typeof cause?.code === 'string' && cause.code.startsWith('PEERIT_OPERATION_BATCH_')) {
      rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_INTRINSIC_AUTHORITY_INVALID',
        'discovered inner operation batch lacks intrinsic author authority', cause)
    }
    fail('PEERIT_PUBLIC_INBOX_INTRINSIC_DECODER_FAILED',
      'intrinsic operation decoder execution failed', cause)
  }
  if (operationBatch.innerLength !== profile.authorBind.innerLength ||
      !bytesEqual(operationBatch.logicalHash, profile.authorBind.logicalHash) ||
      !bytesEqual(operationBatch.logicalHash, profile.replica.logicalHash) ||
      !bytesEqual(operationBatch.encodingCommitment, profile.replica.encodingCommitment)) {
    rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_INTRINSIC_AUTHORITY_INVALID',
      'opened inner bytes differ from signed AuthorBind commitments')
  }
  return Object.freeze({ readCap, operationBatch })
}

// This is intentionally a lower-level verifier, not an authority minter. The
// caller must supply the profile validator obtained from its authenticated app
// runtime. The returned batch has already crossed signed announcement,
// signed AuthorBind, same-relay capability, authenticated GET, and intrinsic
// operation-authority checks.
export async function verifyPeeritPublicInboxAnnouncementReadbackV1 (input = {}) {
  const {
    authority, binding, control, runtime, cellEndpoint, announcementBytes,
    timeoutMillis, signal
  } = input
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(authority) ||
      !authority.bindings.includes(binding)) {
    fail('PEERIT_PUBLIC_INBOX_DISCOVERY_INVALID', 'verified bootstrap binding is required')
  }
  const nowUnixMillis = typeof input.nowUnixMillis === 'bigint'
    ? input.nowUnixMillis
    : BigInt(input.nowUnixMillis == null ? Date.now() : input.nowUnixMillis)
  const client = input.httpClient || new control.BlindDirectHttpClient({ runtime })
  if (!client || typeof client.request !== 'function') {
    fail('PEERIT_PUBLIC_INBOX_DISCOVERY_INVALID', 'direct HTTP client is required')
  }
  const profile = validateAnnouncement(
    input.profileValidator, announcementBytes, binding, nowUnixMillis)
  const readback = await getSameRelayInner({
    control,
    runtime,
    profile,
    binding,
    cellEndpoint,
    httpClient: client,
    timeoutMillis,
    signal
  })
  const result = Object.freeze({
    announcement: profile.announcement,
    authorBind: profile.authorBind,
    replica: profile.replica,
    readCap: readback.readCap,
    operationBatch: readback.operationBatch
  })
  VERIFIED_ANNOUNCEMENT_READBACKS.set(result, Object.freeze({
    authority,
    binding,
    control
  }))
  return result
}

export function assertVerifiedPeeritPublicInboxAnnouncementReadbackV1 (
  value, expected = {}) {
  const state = VERIFIED_ANNOUNCEMENT_READBACKS.get(value)
  if (!state || (expected.authority != null && state.authority !== expected.authority) ||
      (expected.binding != null && state.binding !== expected.binding) ||
      (expected.control != null && state.control !== expected.control)) {
    fail('PEERIT_PUBLIC_INBOX_READBACK_AUTHORITY_REQUIRED',
      'a matching intrinsically verified AuthorBind CELL.GET readback is required')
  }
  return value
}

export async function pollPeeritPublicInboxBindingV1 (input = {}) {
  const {
    authority, binding, control, runtime, readEndpoint, cellEndpoint,
    timeoutMillis, signal
  } = input
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(authority) ||
      !authority.bindings.includes(binding)) {
    fail('PEERIT_PUBLIC_INBOX_DISCOVERY_INVALID', 'verified bootstrap binding is required')
  }
  for (const name of [
    'createReadInboxRequest', 'createGetCellRequest', 'verifyOperationResult',
    'openVerifiedCellGetResult', 'decodeBlindExternalProfileValueV1'
  ]) {
    if (typeof control?.[name] !== 'function') {
      fail('PEERIT_PUBLIC_INBOX_DISCOVERY_INVALID', `public browser control lacks ${name}`)
    }
  }
  const floor = input.floor == null ? 0n : input.floor
  if (typeof floor !== 'bigint' || floor < 0n) {
    fail('PEERIT_PUBLIC_INBOX_DISCOVERY_INVALID', 'append floor must be an unsigned bigint')
  }
  const limit = input.limit == null ? 64 : input.limit
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 64) {
    fail('PEERIT_PUBLIC_INBOX_DISCOVERY_INVALID', 'READ limit is outside 1..64')
  }
  const nowUnixMillis = typeof input.nowUnixMillis === 'bigint'
    ? input.nowUnixMillis
    : BigInt(input.nowUnixMillis == null ? Date.now() : input.nowUnixMillis)
  const client = input.httpClient || new control.BlindDirectHttpClient({ runtime })
  if (!client || typeof client.request !== 'function') {
    fail('PEERIT_PUBLIC_INBOX_DISCOVERY_INVALID', 'direct HTTP client is required')
  }
  const records = []
  const rejections = []
  let cursor = null
  let pagesRead = 0
  let newFloor = floor
  let snapshotRevision = 0n
  for (;;) {
    const read = await control.createReadInboxRequest({
      runtime,
      readCap: binding.readCap,
      cursor,
      limit
    })
    const response = await client.request({
      endpoint: readEndpoint,
      ...read.wire,
      body: read.requestBytes,
      timeoutMillis,
      signal
    })
    if (!response || response.ok !== true) {
      fail('PEERIT_PUBLIC_INBOX_READ_REJECTED',
        'pre-created public INBOX READ was rejected', response?.error)
    }
    let decoded
    try {
      const verified = await control.verifyOperationResult({
        endpoint: readEndpoint,
        request: read.request,
        requestCommitment: read.requestCommitment,
        resultBytes: response.body
      })
      decoded = decodePeeritInboxReadResultSnapshotV1(verified.snapshotBytes())
    } catch (cause) {
      fail('PEERIT_PUBLIC_INBOX_READ_INVALID',
        'public INBOX READ result authentication failed', cause)
    }
    pagesRead += 1
    snapshotRevision = decoded.snapshotRevision
    for (const entry of decoded.entries) {
      if (entry.appendRevision > newFloor) newFloor = entry.appendRevision
      if (entry.appendRevision <= floor) continue
      try {
        if (entry.frameClass !== 1) {
          rejectAuthenticatedEntry('PEERIT_PUBLIC_INBOX_FRAME_CLASS_INVALID',
            'seq29 announcement must use the smallest frame class')
        }
        const announcementBytes = await openAuthenticatedAnnouncement({
          authority,
          binding,
          frame: entry.frame
        })
        const readback = await verifyPeeritPublicInboxAnnouncementReadbackV1({
          authority,
          announcementBytes,
          control,
          runtime,
          binding,
          cellEndpoint,
          httpClient: client,
          profileValidator: input.profileValidator,
          nowUnixMillis,
          timeoutMillis,
          signal
        })
        records.push(Object.freeze({
          appendRevision: entry.appendRevision,
          signedAnnouncementId: blake2b256(concatBytes(
            asciiBytes('peerit.hiverelay.signed-announcement-id.v1'),
            u64Bytes(announcementBytes.byteLength),
            announcementBytes
          )),
          publisherPublicKey: readback.announcement.publisherPublicKey.slice(),
          authorPublicKey: readback.authorBind.authorPublicKey.slice(),
          operationBatch: readback.operationBatch
        }))
      } catch (error) {
        if (!authenticatedEntryRejectionMayAdvance(error)) throw error
        rejections.push(Object.freeze({
          appendRevision: entry.appendRevision,
          frameHash: bytesToHex(entry.frameHash),
          rejection: error?.code || 'PEERIT_PUBLIC_INBOX_ENTRY_INVALID'
        }))
      }
    }
    if (decoded.nextCursor == null) break
    if (pagesRead >= MAX_READ_PAGES) {
      fail('PEERIT_PUBLIC_INBOX_PAGES_EXCEEDED', 'public INBOX pagination exceeded its bound')
    }
    cursor = asBytes(decoded.nextCursor, 'nextCursor').slice()
  }
  const result = Object.freeze({
    relayId: binding.relayId,
    previousFloor: floor,
    records: Object.freeze(records),
    rejections: Object.freeze(rejections),
    snapshotRevision,
    newFloor,
    pagesRead
  })
  VERIFIED_POLL_RESULTS.set(result, Object.freeze({ authority, binding, control }))
  return result
}

export function isVerifiedPeeritPublicInboxPollResultV1 (value) {
  return value != null && typeof value === 'object' && VERIFIED_POLL_RESULTS.has(value)
}

export function assertVerifiedPeeritPublicInboxPollResultV1 (value, expected = {}) {
  const state = VERIFIED_POLL_RESULTS.get(value)
  if (!state || (expected.authority != null && state.authority !== expected.authority) ||
      (expected.binding != null && state.binding !== expected.binding) ||
      (expected.control != null && state.control !== expected.control)) {
    fail('PEERIT_PUBLIC_INBOX_POLL_AUTHORITY_REQUIRED',
      'a matching intrinsically verified public INBOX poll result is required')
  }
  return value
}
