// peerit INBOX discovery v1 — fresh-reader polling of a board's inbox topic.
// INBOX-truth only: this module enumerates and decodes pointer frames; the
// CELL.GET + ingest + merge of any discovered record is the CALLER's job.
// Pure-JS only (strict-CSP safe: no node:crypto, no Buffer, no eval, no WASM).
//
// The uncharged READ has no afterRevision parameter: readers re-enumerate from
// an empty cursor and filter by appendRevision locally (`floor`). Pages are
// authenticated with the vendored control's verifyOperationResult (endpoint
// binding + relay signature + request correlation), then decoded with the
// strict local snapshot decoder. Entries at or below the floor are skipped;
// entries above it are pointer-frame decoded — a tampered/poison frame is
// recorded as rejection evidence and the walk CONTINUES past it (the floor
// still advances, so one poisoned entry can never wedge a reader).
//
// Pagination: while a page carries nextCursor, continue with that cursor. A
// cursor is snapshot-pinned and short-lived (15 minutes); if the relay answers
// EXPIRED on a continuation, the poll restarts ONCE from an empty cursor and
// re-filters. An absent topic (NOT_FOUND on the first probe) is not an error:
// the board simply has no inbox on this relay yet.
import {
  asBytes,
  bytesToHex,
  fixedBytesValue
} from './release-control-primitives.mjs'
import { derivePeeritInboxTopicV1, validatePeeritInboxBoardSlugV1 } from './inbox-topic-v1.mjs'
import { decodePeeritInboxPointerFrameV1 } from './inbox-pointer-frame-v1.mjs'
import { decodePeeritInboxReadResultSnapshotV1 } from './inbox-read-result-decode.mjs'

// Canonical relay error codes (00-core/hiverelay blind-protocol registry.js).
const RELAY_ERROR = Object.freeze({ NOT_FOUND: 13, EXPIRED: 14 })

// A hostile or stuck relay could otherwise keep a poll paging forever; the
// bound is far above any real board's depth (64 entries per page).
const MAX_READ_PAGES = 64

function fail (code, message, extra = undefined) {
  const error = new Error(message)
  error.code = code
  if (extra) Object.assign(error, extra)
  throw error
}

export async function pollPeeritInboxTopicV1 ({
  control,
  baseRuntime,
  endpoint,
  httpClient,
  relayPublicKey,
  boardSlug,
  floor,
  limit,
  timeoutMillis,
  signal
} = {}) {
  validatePeeritInboxBoardSlugV1(boardSlug)
  if (typeof control?.createReadInboxRequest !== 'function' ||
      typeof control?.verifyOperationResult !== 'function') {
    fail('PEERIT_INBOX_DISCOVERY_INVALID', 'the vendored blind client control surface is required')
  }
  const relayKey = fixedBytesValue(relayPublicKey, 32, 'relayPublicKey')
  const client = httpClient || new control.BlindDirectHttpClient({ runtime: baseRuntime })
  if (!client || typeof client.request !== 'function') {
    fail('PEERIT_INBOX_DISCOVERY_INVALID', 'a direct http client is required')
  }
  const floorValue = floor == null ? 0n : floor
  if (typeof floorValue !== 'bigint' || floorValue < 0n) {
    fail('PEERIT_INBOX_DISCOVERY_INVALID', 'floor must be an unsigned bigint appendRevision')
  }
  const pageLimit = limit == null ? 64 : limit
  if (!Number.isSafeInteger(pageLimit) || pageLimit < 1 || pageLimit > 64) {
    fail('PEERIT_INBOX_DISCOVERY_INVALID', 'limit is outside 1..64')
  }
  const topic = await derivePeeritInboxTopicV1({ boardSlug, relayPublicKey: relayKey, control, baseRuntime })

  const pointers = []
  const rejections = []
  let snapshotRevision = 0n
  let newFloor = floorValue
  let pagesRead = 0
  let cursor = null
  let restartedAfterExpiry = false

  for (;;) {
    const prepared = await control.createReadInboxRequest({
      runtime: baseRuntime,
      readCap: topic.readCap,
      cursor,
      limit: pageLimit
    })
    const response = await client.request({
      endpoint,
      familyId: prepared.wire.familyId,
      operationId: prepared.wire.operationId,
      expectedResultBodyBytes: prepared.wire.expectedResultBodyBytes,
      body: prepared.requestBytes,
      timeoutMillis,
      signal
    })
    if (!response || response.ok !== true) {
      const relayCode = response && response.error && Number.isSafeInteger(response.error.code)
        ? response.error.code
        : null
      if (relayCode === RELAY_ERROR.NOT_FOUND && pagesRead === 0 && cursor == null) {
        // Absent topic: the board has no inbox on this relay (no traffic
        // beyond this probe).
        return Object.freeze({
          topic: topic.topic,
          physicalTopic: topic.physicalTopic,
          pointers: Object.freeze([]),
          rejections: Object.freeze([]),
          snapshotRevision: 0n,
          newFloor: floorValue,
          pagesRead: 1
        })
      }
      if (relayCode === RELAY_ERROR.EXPIRED && cursor != null && !restartedAfterExpiry) {
        // The continuation cursor died (15-minute snapshot pin): restart from
        // an empty cursor ONCE and re-filter against the original floor.
        restartedAfterExpiry = true
        cursor = null
        snapshotRevision = 0n
        newFloor = floorValue
        pointers.length = 0
        rejections.length = 0
        continue
      }
      fail('PEERIT_INBOX_DISCOVERY_RELAY_ERROR', 'INBOX.READ was rejected by the relay', {
        relayCode,
        relayRetryable: response && response.error ? response.error.retryable === 1 : null
      })
    }
    const verified = control.verifyOperationResult({
      endpoint,
      request: prepared.request,
      requestCommitment: prepared.requestCommitment,
      resultBytes: response.body
    })
    const decoded = decodePeeritInboxReadResultSnapshotV1(verified.snapshotBytes())
    pagesRead += 1
    snapshotRevision = decoded.snapshotRevision
    for (const entry of decoded.entries) {
      if (entry.appendRevision > newFloor) newFloor = entry.appendRevision
      if (entry.appendRevision <= floorValue) continue
      try {
        const pointer = decodePeeritInboxPointerFrameV1(entry.frame)
        if (pointer.boardSlug !== boardSlug) {
          const error = new Error('frame board does not match the polled topic')
          error.code = 'PEERIT_INBOX_POINTER_FRAME_INVALID'
          throw error
        }
        pointers.push(Object.freeze({
          appendRevision: entry.appendRevision,
          recordCid: pointer.recordCid,
          authorPubKey: pointer.authorPubKey,
          sizeClass: pointer.sizeClass,
          leaseClass: pointer.leaseClass,
          appendedAtUnixMillis: pointer.appendedAtUnixMillis,
          hints: pointer.hints
        }))
      } catch (error) {
        // Poison frames (and cross-board frames, which cannot legitimately
        // exist on this topic) are evidence, not failure: record and advance.
        rejections.push(Object.freeze({
          appendRevision: entry.appendRevision,
          rejection: error && typeof error.code === 'string' ? error.code : 'PEERIT_INBOX_POINTER_FRAME_INVALID',
          frameHash: bytesToHex(entry.frameHash)
        }))
      }
    }
    if (decoded.nextCursor == null) break
    if (pagesRead >= MAX_READ_PAGES) {
      fail('PEERIT_INBOX_DISCOVERY_PAGES_EXCEEDED', 'INBOX.READ pagination exceeded its bound')
    }
    cursor = asBytes(decoded.nextCursor, 'nextCursor').slice()
  }

  return Object.freeze({
    topic: topic.topic,
    physicalTopic: topic.physicalTopic,
    pointers: Object.freeze(pointers),
    rejections: Object.freeze(rejections),
    snapshotRevision,
    newFloor,
    pagesRead
  })
}
