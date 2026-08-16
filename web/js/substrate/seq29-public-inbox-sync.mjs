// Sequence-29 public-INBOX read-side sync authority.
//
// This helper is imported only by the non-activated Seq29 coordinator. It keeps
// Seq29 authority imports out of the always-shipped generic sync core while
// ensuring no shape-only bootstrap or prepared record batch can cross into its
// journal. An opaque authority is bound to one exact verified signed bootstrap
// and one exact substrate sync instance; every poll is independently checked
// against the discovery brand and intrinsically re-decoded here.
import { hashBytes } from '../crypto.js'
import {
  assertVerifiedPeeritPublicInboxPollResultV1
} from './inbox-discovery.mjs'
import {
  isVerifiedPeeritLimitedPublicInboxBootstrapV1
} from './inbox-topic-v1.mjs'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_DEFAULT_MAX_RECORD_KEY_BYTES,
  decodePeeritInnerOperationBatchV1
} from './peerit-operation-authority-v1.js'
import { assertPeeritSubstrateSyncV1 } from './peerit-substrate-sync.js'
import { bytesEqual, bytesToHex } from './release-control-primitives.mjs'

const SYNC_AUTHORITIES = new WeakMap()

function fail (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

function bootstrapIdentity (authority) {
  return Object.freeze({
    releaseSequence: authority.releaseSequence,
    authorityPublicKey: authority.authorityPublicKey,
    completeSignedWrapperHash: authority.completeSignedWrapperHash,
    bootstrapSequence: authority.bootstrapSequence,
    relayIds: Object.freeze(authority.bindings.map(binding => binding.relayId))
  })
}

function authorityState (value) {
  const state = SYNC_AUTHORITIES.get(value)
  if (!state) {
    fail('PEERIT_SUBSTRATE_SEQ29_COORDINATOR_AUTHORITY_REQUIRED',
      'the exact branded Seq29 coordinator sync authority is required')
  }
  return state
}

function assertWritable (state, code, message) {
  if (!state.sync._localFailure) return
  fail(code, message, state.sync._localFailure)
}

function retainStorageFailure (state, error) {
  if (error && (error.code === 'PEERIT_JOURNAL_CORRUPT' ||
    error.code === 'PEERIT_JOURNAL_STORAGE_UNAVAILABLE')) state.sync._localFailure = error
}

function compareObservationEntry (left, right) {
  const leftRevision = BigInt(left.appendRevision)
  const rightRevision = BigInt(right.appendRevision)
  if (leftRevision < rightRevision) return -1
  if (leftRevision > rightRevision) return 1
  return String(left.identity).localeCompare(String(right.identity))
}

async function pollObservationHash (result) {
  const records = result.records.map(record => ({
    appendRevision: String(record.appendRevision),
    identity: bytesToHex(record.signedAnnouncementId),
    publisherPublicKey: bytesToHex(record.publisherPublicKey),
    authorPublicKey: bytesToHex(record.authorPublicKey),
    logicalHash: bytesToHex(record.operationBatch.logicalHash)
  })).sort(compareObservationEntry)
  const rejections = result.rejections.map(rejection => ({
    appendRevision: String(rejection.appendRevision),
    identity: String(rejection.frameHash),
    rejection: String(rejection.rejection)
  })).sort(compareObservationEntry)
  return hashBytes(new TextEncoder().encode(JSON.stringify({
    domain: 'peerit.seq29.public-inbox-poll-observation.v1',
    relayId: result.relayId,
    previousFloor: String(result.previousFloor),
    newFloor: String(result.newFloor),
    records,
    rejections
  })))
}

async function prepareAuthenticatedPoll (state, results) {
  if (!Array.isArray(results) || results.length !== 2) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_AUTHORITY_REQUIRED',
      'two intrinsically verified public INBOX poll results are required')
  }
  const expectedRelayIds = [...state.bootstrap.relayIds].sort()
  const observedRelayIds = []
  for (const result of results) {
    const binding = state.authority.bindings.find(value => value.relayId === result?.relayId)
    if (!binding) {
      fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_RELAY_MISMATCH',
        'poll result relay is absent from the exact signed bootstrap')
    }
    try {
      assertVerifiedPeeritPublicInboxPollResultV1(result, {
        authority: state.authority,
        binding
      })
    } catch (cause) {
      fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_AUTHORITY_REQUIRED',
        'two exact-authority public INBOX poll results are required', cause)
    }
    observedRelayIds.push(result.relayId)
  }
  observedRelayIds.sort()
  if (observedRelayIds[0] === observedRelayIds[1] ||
      observedRelayIds.some((relayId, index) => relayId !== expectedRelayIds[index])) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_RELAY_MISMATCH',
      'poll results differ from the signed bootstrap relay set')
  }

  const journalKeyLimit = state.sync.journal?.limits?.maxRecordKeyBytes
  const maxRecordKeyBytes = Number.isSafeInteger(journalKeyLimit) && journalKeyLimit > 0
    ? journalKeyLimit
    : PEERIT_INNER_OPERATION_BATCH_V1_DEFAULT_MAX_RECORD_KEY_BYTES
  const uniqueBatches = new Map()
  const records = []
  for (const result of results) {
    if (typeof result.previousFloor !== 'bigint' || result.previousFloor < 0n ||
        typeof result.newFloor !== 'bigint' || result.newFloor < result.previousFloor) {
      fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_FLOOR_INVALID',
        `${result.relayId} poll has an invalid append-floor transition`)
    }
    for (const record of result.records) {
      const authorPublicKey = bytesToHex(record.authorPublicKey)
      const supplied = record.operationBatch
      let decoded
      try {
        decoded = await decodePeeritInnerOperationBatchV1(
          supplied.innerCodec,
          supplied.innerBytes,
          { expectedAuthorPublicKey: authorPublicKey, maxRecordKeyBytes }
        )
      } catch (cause) {
        fail('PEERIT_SEQ29_INTRINSIC_INGEST_INVALID',
          'public INBOX batch failed intrinsic exact-author revalidation', cause)
      }
      if (decoded.innerLength !== supplied.innerLength || decoded.sizeClass !== supplied.sizeClass ||
          !bytesEqual(decoded.logicalHash, supplied.logicalHash) ||
          !bytesEqual(decoded.encodingCommitment, supplied.encodingCommitment)) {
        fail('PEERIT_SEQ29_INTRINSIC_INGEST_MISMATCH',
          'public INBOX batch changed after intrinsic discovery validation')
      }
      const batchId = `${authorPublicKey}:${bytesToHex(decoded.logicalHash)}`
      const previous = uniqueBatches.get(batchId)
      if (previous) {
        if (!bytesEqual(previous.innerBytes, decoded.innerBytes)) {
          fail('PEERIT_SEQ29_INTRINSIC_INGEST_FORK',
            'two public INBOX announcements conflict at one author/logical identity')
        }
        continue
      }
      uniqueBatches.set(batchId, decoded)
      for (let index = 0; index < decoded.operations.length; index++) {
        records.push(Object.freeze({
          key: decoded.operationWireKeys[index],
          value: decoded.operations[index].data
        }))
      }
    }
  }
  const relayPolls = await Promise.all(results.map(async result => Object.freeze({
    relayId: result.relayId,
    previousAppendRevision: result.previousFloor,
    newAppendRevision: result.newFloor,
    observationHash: await pollObservationHash(result)
  })))
  return Object.freeze({
    relayPolls: Object.freeze(relayPolls),
    records: Object.freeze(records),
    ingestedBatchCount: uniqueBatches.size
  })
}

export function createPeeritSeq29PublicInboxSyncAuthorityV1 (input = {}) {
  const sync = assertPeeritSubstrateSyncV1(input.substrateSync)
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(input.authority)) {
    fail('PEERIT_SUBSTRATE_SEQ29_COORDINATOR_AUTHORITY_REQUIRED',
      'a verified signed Seq29 public INBOX bootstrap authority is required')
  }
  const value = Object.freeze({ version: 1 })
  SYNC_AUTHORITIES.set(value, Object.freeze({
    sync,
    authority: input.authority,
    bootstrap: bootstrapIdentity(input.authority)
  }))
  return value
}

export async function getPeeritSeq29PublicInboxBootstrapFloorV1 (
  substrateSync, authorityPublicKey) {
  const sync = assertPeeritSubstrateSyncV1(substrateSync)
  return sync.journal.getSeq29PublicInboxBootstrapFloor(authorityPublicKey)
}

export async function acceptPeeritSeq29PublicInboxBootstrapV1 (
  syncAuthority, options = {}) {
  const state = authorityState(syncAuthority)
  assertWritable(state, 'PEERIT_SUBSTRATE_SEQ29_BOOTSTRAP_PERSIST_BLOCKED',
    'Peerit cannot durably bind the Seq29 public INBOX bootstrap on this device.')
  try {
    const result = await state.sync.journal.acceptSeq29PublicInboxBootstrap({
      ...state.bootstrap,
      observedAt: Number.isSafeInteger(options.observedAt)
        ? options.observedAt
        : state.sync.clock()
    })
    if (!result.duplicate) {
      await state.sync._refreshAfterMutation(false, [], { publicationWork: false })
    }
    return result
  } catch (error) {
    retainStorageFailure(state, error)
    throw error
  }
}

export async function getPeeritSeq29PublicInboxAppendFloorsV1 (syncAuthority) {
  const state = authorityState(syncAuthority)
  return state.sync.journal.getSeq29PublicInboxAppendFloors(state.bootstrap)
}

export async function commitPeeritSeq29PublicInboxPollV1 (
  syncAuthority, results, options = {}) {
  const state = authorityState(syncAuthority)
  assertWritable(state, 'PEERIT_SUBSTRATE_SEQ29_REMOTE_INGEST_BLOCKED',
    'Peerit cannot safely ingest Seq29 public INBOX records on this device.')
  const prepared = await prepareAuthenticatedPoll(state, results)
  try {
    const committed = await state.sync.journal.commitSeq29PublicInboxPoll({
      ...state.bootstrap,
      relayPolls: prepared.relayPolls,
      records: prepared.records,
      observedAt: Number.isSafeInteger(options.observedAt)
        ? options.observedAt
        : state.sync.clock()
    })
    if (!committed.duplicate) {
      await state.sync._refreshAfterMutation(
        committed.changedKeys.length > 0,
        committed.changedKeys,
        { publicationWork: false }
      )
    }
    return Object.freeze({
      ok: true,
      remote: true,
      duplicate: committed.duplicate,
      ingestedBatchCount: prepared.ingestedBatchCount,
      changedKeys: Object.freeze([...committed.changedKeys]),
      appendFloors: committed.appendFloors,
      queued: false,
      pendingIntentsCreated: 0,
      relayTargetsCreated: 0
    })
  } catch (error) {
    retainStorageFailure(state, error)
    throw error
  }
}

function publicationScope (state, authorPublicKey) {
  return Object.freeze({
    ...state.bootstrap,
    authorPublicKey: typeof authorPublicKey === 'string'
      ? authorPublicKey
      : bytesToHex(authorPublicKey)
  })
}

export async function listPeeritSeq29LocalAuthoredPublicationsV1 (
  syncAuthority, options = {}) {
  const state = authorityState(syncAuthority)
  const limit = Math.max(1, Math.min(32, Number(options.limit) || 16))
  const page = await state.sync.journal.listIntentIds({ limit })
  const values = []
  for (const intentId of page.intentIds) {
    const intent = await state.sync.journal.getIntent(intentId)
    if (!intent || intent.wireFormat !== 'peerit-inner-operation-batch-v1' ||
        intent.innerCodec !== 334 || !(intent.innerBytes instanceof Uint8Array)) continue
    values.push(Object.freeze({
      intentId: intent.intentId,
      logicalId: intent.logicalId,
      innerCodec: intent.innerCodec,
      innerBytes: intent.innerBytes.slice(),
      innerLength: intent.innerLength,
      logicalHash: intent.logicalHash.slice(),
      encodingCommitment: intent.encodingCommitment.slice(),
      sizeClass: intent.sizeClass
    }))
  }
  return Object.freeze(values)
}

export async function getPeeritSeq29LocalAuthoredPublicationV1 (
  syncAuthority, intentId) {
  const state = authorityState(syncAuthority)
  const intent = await state.sync.journal.getIntent(intentId)
  if (!intent || intent.wireFormat !== 'peerit-inner-operation-batch-v1' ||
      intent.innerCodec !== 334 || !(intent.innerBytes instanceof Uint8Array)) {
    fail('PEERIT_SEQ29_LOCAL_AUTHORED_INTENT_INVALID',
      'the exact ordinary locally authored intent is unavailable')
  }
  return Object.freeze({
    intentId: intent.intentId,
    logicalId: intent.logicalId,
    innerCodec: intent.innerCodec,
    innerBytes: intent.innerBytes.slice(),
    innerLength: intent.innerLength,
    logicalHash: intent.logicalHash.slice(),
    encodingCommitment: intent.encodingCommitment.slice(),
    sizeClass: intent.sizeClass
  })
}

export async function getPeeritSeq29PublicationAuthorHeadV1 (
  syncAuthority, authorPublicKey) {
  const state = authorityState(syncAuthority)
  return state.sync.journal.getSeq29PublicationAuthorHead(
    publicationScope(state, authorPublicKey))
}

export async function getPeeritSeq29PublicationIntentV1 (
  syncAuthority, authorPublicKey, logicalHash) {
  const state = authorityState(syncAuthority)
  return state.sync.journal.getSeq29PublicationIntent({
    ...publicationScope(state, authorPublicKey),
    logicalHash: typeof logicalHash === 'string' ? logicalHash : bytesToHex(logicalHash)
  })
}

export async function listPeeritSeq29PublicationIntentsV1 (
  syncAuthority, authorPublicKey, options = {}) {
  const state = authorityState(syncAuthority)
  return state.sync.journal.listSeq29PublicationIntents({
    ...publicationScope(state, authorPublicKey),
    limit: options.limit
  })
}

async function mutatePublication (syncAuthority, input, method) {
  const state = authorityState(syncAuthority)
  assertWritable(state, 'PEERIT_SUBSTRATE_SEQ29_PUBLICATION_BLOCKED',
    'Peerit cannot durably advance a Seq29 authored publication on this device.')
  try {
    const result = await state.sync.journal[method]({
      ...input,
      ...publicationScope(state, input.authorPublicKey)
    })
    await state.sync._refreshAfterMutation(false, [], { publicationWork: false })
    return result
  } catch (error) {
    retainStorageFailure(state, error)
    throw error
  }
}

export function commitPeeritSeq29PublicationIntentV1 (
  syncAuthority, input) {
  return mutatePublication(syncAuthority, input, 'commitSeq29PublicationIntent')
}

export function claimPeeritSeq29PublicationRelayV1 (
  syncAuthority, input) {
  return mutatePublication(syncAuthority, input, 'claimSeq29PublicationRelay')
}

export function markPeeritSeq29PublicationRelayAbsentV1 (
  syncAuthority, input) {
  return mutatePublication(syncAuthority, input, 'markSeq29PublicationRelayAbsent')
}

export function completePeeritSeq29PublicationRelayV1 (
  syncAuthority, input) {
  return mutatePublication(syncAuthority, input, 'completeSeq29PublicationRelay')
}

export function failPeeritSeq29PublicationRelayV1 (
  syncAuthority, input) {
  return mutatePublication(syncAuthority, input, 'failSeq29PublicationRelay')
}
