// peerit-substrate-sync.js — local-first Peerit sync boundary for the generic
// HiveRelay blind substrate.
//
// The load-bearing order is:
//   signed operation -> one durable journal transaction -> local notification
//   -> optional, independent relay attempts.
//
// The injected journal owns IndexedDB transactions and cross-tab CAS. Web Locks
// are used only to fence identity lifecycle sessions; publication correctness
// does not depend on navigator.locks being present.

import {
  LEGACY_SUBSTRATE_STATE_KEY,
  PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
  PeeritJournal,
  createIndexedDbPeeritJournal
} from './peerit-journal.js'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_DEFAULT_MAX_RECORD_KEY_BYTES,
  createPeeritInnerOperationBatchV1,
  decodePeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from './peerit-operation-authority-v1.js'
import { bytesEqual } from './release-control-primitives.mjs'
import { isPeeritVerifiedRelayAdapter } from './relay-consumer.js'

export const SUBSTRATE_STATE_KEY = LEGACY_SUBSTRATE_STATE_KEY
// AvailabilityPolicyVNext fixes proofFreshnessEpochs=4 and the substrate lease
// epoch at six hours. A shorter value remains injectable for deterministic tests.
export const PEERIT_CELL_READBACK_FRESHNESS_TTL_MS = 4 * 6 * 60 * 60 * 1000

const MAX_RELAY_TARGETS = 3
const MAX_DELIVERY_INTENT_CONCURRENCY = 32
const MAX_READBACK_FRESHNESS_TTL_MS = PEERIT_CELL_READBACK_FRESHNESS_TTL_MS
const ACKNOWLEDGED = new Set(['acknowledged', 'readback-verified'])

function clone (value) {
  if (value == null) return value
  if (typeof structuredClone === 'function') return structuredClone(value)
  return JSON.parse(JSON.stringify(value))
}

async function normalizePublicationBatch (operations, options = undefined) {
  try {
    return await createPeeritInnerOperationBatchV1(operations, options)
  } catch (cause) {
    // Retain the public sync-boundary error vocabulary for callers that already
    // distinguish malformed/unsigned records from a cryptographically bad
    // record, while preserving the narrower authority reason as the cause.
    if (cause && cause.code === 'PEERIT_OPERATION_BATCH_METADATA') {
      const error = new Error('Peerit substrate append refuses an unsigned or malformed author event.')
      error.code = 'PEERIT_SUBSTRATE_UNSIGNED_EVENT'
      error.cause = cause
      throw error
    }
    if (cause && cause.code === 'PEERIT_OPERATION_BATCH_SIGNATURE') {
      const error = new Error('Peerit substrate append refuses a forged, tampered, or owner-mismatched event.')
      error.code = 'PEERIT_SUBSTRATE_INVALID_SIGNATURE'
      error.cause = cause
      throw error
    }
    throw cause
  }
}

function hex (value) {
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

function emptySummary () {
  return {
    revision: 0,
    viewRevision: 0,
    viewRecordCount: 0,
    intentCount: 0,
    pendingIntentCount: 0,
    targetStateCounts: {},
    latestIntentId: null,
    latest: null,
    dormant: true
  }
}

function viewKey (operation) {
  return operation.type.replace(':', '!') + '!' + operation.data.id
}

function relayId (relay, index) {
  const value = relay && (relay.id || relay.relayPublicKey || relay.url || relay.baseUrl)
  return String(value || `relay-${index + 1}`).toLowerCase()
}

function usableRelay (relay) {
  return !!(relay && relay.compatible !== false &&
    (typeof relay.deliver === 'function' ||
      (typeof relay.prepare === 'function' && typeof relay.send === 'function')))
}

function normalizeRelay (relay, index) {
  if (!relay || typeof relay !== 'object') return { id: relayId(relay, index), compatible: false }
  const bind = name => typeof relay[name] === 'function' ? relay[name].bind(relay) : undefined
  return Object.freeze({
    id: relayId(relay, index),
    compatible: relay.compatible !== false,
    deliver: bind('deliver'),
    prepare: bind('prepare'),
    send: bind('send'),
    reconcile: bind('reconcile'),
    revalidateReadback: bind('revalidateReadback')
  })
}

function normalizeRelayQualificationStatus (status) {
  if (!status || typeof status !== 'object') return null
  const strings = (value, maximum) => Object.freeze((Array.isArray(value) ? value : [])
    .slice(0, maximum)
    .map(item => String(item).slice(0, 128)))
  return Object.freeze({
    state: String(status.state || 'unknown').slice(0, 64),
    active: status.active === true,
    candidateHintCount: Number.isSafeInteger(status.candidateHintCount) ? Math.max(0, status.candidateHintCount) : 0,
    descriptorPinnedCandidateCount: Number.isSafeInteger(status.descriptorPinnedCandidateCount)
      ? Math.max(0, status.descriptorPinnedCandidateCount)
      : 0,
    rawUrlHintCount: Number.isSafeInteger(status.rawUrlHintCount) ? Math.max(0, status.rawUrlHintCount) : 0,
    candidateSources: strings(status.candidateSources, 4),
    pinnedAttemptCount: Number.isSafeInteger(status.pinnedAttemptCount) ? Math.max(0, status.pinnedAttemptCount) : 0,
    qualificationFailureCount: Number.isSafeInteger(status.qualificationFailureCount)
      ? Math.max(0, status.qualificationFailureCount)
      : 0,
    qualificationDeadlineMillis: Number.isSafeInteger(status.qualificationDeadlineMillis)
      ? Math.max(0, status.qualificationDeadlineMillis)
      : 0,
    qualificationTimedOut: status.qualificationTimedOut === true,
    deduplicatedCandidateCount: Number.isSafeInteger(status.deduplicatedCandidateCount)
      ? Math.max(0, status.deduplicatedCandidateCount)
      : 0,
    continuityDiversityDeduplicatedCount: Number.isSafeInteger(status.continuityDiversityDeduplicatedCount)
      ? Math.max(0, status.continuityDiversityDeduplicatedCount)
      : 0,
    quarantinedIdentityCount: Number.isSafeInteger(status.quarantinedIdentityCount)
      ? Math.max(0, status.quarantinedIdentityCount)
      : 0,
    qualifiedRelayCount: Number.isSafeInteger(status.qualifiedRelayCount) ? Math.max(0, status.qualifiedRelayCount) : 0,
    releaseBlockers: strings(status.releaseBlockers, 32),
    rawUrlAuthorizesOrdinaryOperations: status.rawUrlAuthorizesOrdinaryOperations === true,
    descriptorPinRequired: status.descriptorPinRequired === true,
    descriptorSignatureRequired: status.descriptorSignatureRequired === true,
    admissionParametersVerified: status.admissionParametersVerified === true,
    qualificationLeaseMillis: Number.isSafeInteger(status.qualificationLeaseMillis)
      ? Math.max(0, status.qualificationLeaseMillis)
      : 0,
    endpointBoundHealthRequired: status.endpointBoundHealthRequired === true,
    sharedContinuityTrustStoreRequired: status.sharedContinuityTrustStoreRequired === true,
    sameContinuityDeduplicationRequired: status.sameContinuityDeduplicationRequired === true,
    descriptorForkQuarantineRequired: status.descriptorForkQuarantineRequired === true,
    oneRelayEnablesDelivery: status.oneRelayEnablesDelivery === true,
    zeroRelayBehavior: String(status.zeroRelayBehavior || '').slice(0, 64)
  })
}

function targetSnapshot (entry, id) {
  return entry && entry.targets && entry.targets[id] ? entry.targets[id] : null
}

function readbackEvidence (latest, relays, validatedTargetIds, requiredTargetIds, now, freshnessTtlMs, maxTargetsPerIntent) {
  const active = new Set(relays.map(relay => relay.id))
  const targets = latest && latest.targets ? Object.values(latest.targets) : []
  const knownTargets = new Set(targets.map(target => target && target.targetId).filter(Boolean))
  const targetBudgetExhausted = !!(latest && Number.isSafeInteger(latest.targetCount) &&
    Number.isSafeInteger(maxTargetsPerIntent) && latest.targetCount >= maxTargetsPerIntent &&
    [...active].some(targetId => !knownTargets.has(targetId)))
  let current = 0
  let repairNeeded = 0
  let revalidationPending = 0
  let activeAcknowledged = 0
  let lastReadbackVerifiedAt = null
  let freshUntil = null
  for (const target of targets) {
    if (!target || !active.has(target.targetId)) continue
    if (ACKNOWLEDGED.has(target.state)) activeAcknowledged++
    if (target.state !== 'readback-verified' || target.readbackVerified !== true) continue
    const verifiedAt = Number.isSafeInteger(target.lastReadbackVerifiedAt) && target.lastReadbackVerifiedAt >= 0
      ? target.lastReadbackVerifiedAt
      : null
    if (verifiedAt != null && (lastReadbackVerifiedAt == null || verifiedAt > lastReadbackVerifiedAt)) {
      lastReadbackVerifiedAt = verifiedAt
    }
    if (target.readbackRepairNeeded === true) {
      repairNeeded++
      continue
    }
    const fresh = verifiedAt != null && now >= verifiedAt && now - verifiedAt < freshnessTtlMs &&
      target.readbackCurrentInvalidated !== true && validatedTargetIds.has(target.targetId)
    if (fresh) {
      current++
      const expiresAt = verifiedAt + freshnessTtlMs
      if (freshUntil == null || expiresAt > freshUntil) freshUntil = expiresAt
    } else if (requiredTargetIds.has(target.targetId) || target.readbackCurrentInvalidated === true || verifiedAt == null ||
        now < verifiedAt || now - verifiedAt >= freshnessTtlMs) {
      revalidationPending++
    }
  }
  return Object.freeze({
    current,
    repairNeeded,
    revalidationPending,
    lastReadbackVerifiedAt,
    freshUntil,
    targetBudgetExhausted,
    activeAcknowledged
  })
}

function publicationStatus (summary, relays, relayHints, evidence, freshnessTtlMs, localState = 'ready', localWarning = null, localFailure = null) {
  const latest = summary.latest || null
  const counts = summary.targetStateCounts || {}
  const usableTargets = relays.filter(usableRelay).length
  const pendingUnknown = (counts['pending-unknown'] || 0) > 0
  const preparing = (counts.preparing || 0) > 0
  const delivering = (counts.delivering || 0) > 0
  const retryable = (counts.retryable || 0) > 0
  const terminal = (counts.terminal || 0) > 0
  const pendingIntents = summary.pendingIntentCount || 0
  const acknowledgedTargets = latest ? latest.acknowledgedTargets || 0 : 0

  let relayState = 'idle'
  if (pendingUnknown) relayState = 'pending-unknown'
  else if (preparing || delivering) relayState = 'delivering'
  else if (pendingIntents > 0 && usableTargets === 0) relayState = 'queued-no-relay'
  else if (pendingIntents > 0 && terminal && !retryable) relayState = 'target-rejected'
  else if (pendingIntents > 0 || retryable) relayState = 'queued'
  else if (evidence.targetBudgetExhausted) relayState = 'target-budget-exhausted'
  else if (evidence.repairNeeded > 0) relayState = 'repair-needed'
  else if (evidence.revalidationPending > 0) relayState = 'revalidation-pending'
  else if (evidence.activeAcknowledged > 0) relayState = 'relay-acknowledged'
  else if (acknowledgedTargets > 0) relayState = 'historically-acknowledged'

  const policyDurable = !!(latest && latest.policyDurable)
  const historicalReadbackVerified = latest ? latest.readbackVerified || 0 : 0
  const readbackVerified = evidence.current
  let durabilityState = 'local-only'
  if (policyDurable && readbackVerified > 0) durabilityState = 'policy-durable'
  else if (readbackVerified > 0) durabilityState = 'recently-retrievable'
  else if (evidence.targetBudgetExhausted) durabilityState = 'target-budget-exhausted'
  else if (evidence.repairNeeded > 0) durabilityState = 'repair-needed'
  else if (historicalReadbackVerified > 0) durabilityState = 'remote-evidence-stale'
  else if (evidence.activeAcknowledged > 0) durabilityState = 'remote-single'
  else if (acknowledgedTargets > 0) durabilityState = 'remote-evidence-stale'

  const discoveryState = latest ? (latest.discoveryState || 'queued') : 'idle'
  return Object.freeze({
    local: Object.freeze({
      state: localState,
      visibleRecords: summary.viewRecordCount || 0,
      warningCode: (localWarning && localWarning.code) || null,
      failureCode: (localFailure && localFailure.code) || null
    }),
    relay: Object.freeze({
      state: relayState,
      usableTargets,
      configuredHints: relayHints.length,
      acknowledgedTargets,
      activeAcknowledgedTargets: evidence.activeAcknowledged,
      pendingIntents,
      targetBudgetExhausted: evidence.targetBudgetExhausted
    }),
    durability: Object.freeze({
      state: durabilityState,
      acknowledgedReplicas: evidence.activeAcknowledged,
      historicalAcknowledgedReplicas: acknowledgedTargets,
      readbackVerified,
      historicalReadbackVerified,
      lastReadbackVerifiedAt: evidence.lastReadbackVerifiedAt,
      freshUntil: evidence.freshUntil,
      freshnessTtlMs,
      repairNeeded: evidence.repairNeeded,
      revalidationPending: evidence.revalidationPending,
      targetBudgetExhausted: evidence.targetBudgetExhausted
    }),
    discovery: Object.freeze({ state: discoveryState }),
    intentCount: summary.intentCount || 0,
    latestIntentId: summary.latestIntentId || null
  })
}

function definitelyNotProcessed (error) {
  return !!(error && (error.definitelyNotProcessed === true || error.safeToRetry === true || error.code === 'RETRYABLE_NOT_SENT'))
}

function readbackNeedsRepair (error) {
  return !!(error && (error.definitiveAbsence === true || error.terminal === true || [
    'HIVERELAY_READBACK_NOT_FOUND',
    'HIVERELAY_PERSISTED_REPLICA_MISMATCH',
    'HIVERELAY_PERSISTED_READBACK_MISMATCH',
    'PEERIT_SUBSTRATE_READ_CAPABILITY_MISSING',
    'PEERIT_SUBSTRATE_READBACK_AUTHENTICATION_FAILED',
    'PEERIT_SUBSTRATE_READBACK_ENVELOPE_MISMATCH',
    'HIVERELAY_READ_TARGET_CONTEXT_DRIFT'
  ].includes(error.code)))
}

async function runBounded (values, concurrency, worker) {
  if (!values.length) return
  let cursor = 0
  const runners = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (cursor < values.length) {
      const index = cursor++
      await worker(values[index], index)
    }
  })
  await Promise.all(runners)
}

async function withDeadline (milliseconds, operation) {
  const controller = typeof AbortController === 'function' ? new AbortController() : null
  let timer
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      const error = new Error('relay delivery attempt exceeded its bounded deadline')
      error.code = 'PEERIT_SUBSTRATE_DELIVERY_TIMEOUT'
      reject(error)
      // Reject the deadline first. An untrusted adapter may synchronously resolve
      // from its abort handler; it must not win the Promise.race after expiry.
      if (controller) controller.abort()
    }, milliseconds)
  })
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(Object.freeze({
        signal: controller ? controller.signal : undefined,
        timeoutMs: milliseconds
      }))),
      timeout
    ])
  } finally {
    clearTimeout(timer)
  }
}

function attemptOwnerId () {
  const bytes = new Uint8Array(8)
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    const error = new Error('secure randomness is required for durable publication claim ownership')
    error.code = 'PEERIT_SUBSTRATE_SECURE_RANDOM_REQUIRED'
    throw error
  }
  globalThis.crypto.getRandomValues(bytes)
  return [...bytes].map(value => value.toString(16).padStart(2, '0')).join('')
}

async function publicationPayload (entry, targetId) {
  const terminal = (code, message, cause = undefined) => {
    const error = new Error(message)
    error.code = code
    error.terminal = true
    if (cause !== undefined) error.cause = cause
    throw error
  }
  if (!entry || entry.wireFormat !== PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1) {
    terminal('PEERIT_SUBSTRATE_LEGACY_INTENT_QUARANTINED', 'A retired raw-JSON intent cannot be sent through the VNext Cell path.')
  }
  let decoded
  try {
    decoded = await decodePeeritInnerOperationBatchV1(entry.innerCodec, entry.innerBytes)
  } catch (cause) {
    terminal('PEERIT_SUBSTRATE_INTENT_CORRUPT', 'Peerit VNext intent bytes are corrupt or unverifiable.', cause)
  }
  const expectedIntentId = hex(hashPeeritInnerOperationIntentIdV1(decoded.innerCodec, decoded.innerBytes))
  let exactMetadata
  try {
    exactMetadata = entry.intentId === expectedIntentId && entry.logicalId === hex(decoded.logicalHash) &&
      Number.isSafeInteger(entry.innerLength) && entry.innerLength === Number(decoded.innerLength) &&
      entry.innerCodec === decoded.innerCodec && entry.sizeClass === decoded.sizeClass &&
      bytesEqual(entry.innerBytes, decoded.innerBytes) &&
      bytesEqual(entry.logicalHash, decoded.logicalHash) &&
      bytesEqual(entry.encodingCommitment, decoded.encodingCommitment) &&
      Array.isArray(entry.recordKeys) && entry.recordKeys.length === decoded.operationWireKeys.length &&
      entry.recordKeys.every((key, index) => key === decoded.operationWireKeys[index])
  } catch (cause) {
    terminal('PEERIT_SUBSTRATE_INTENT_CORRUPT', 'Peerit VNext intent metadata is not a valid exact-envelope value.', cause)
  }
  if (!exactMetadata) {
    terminal('PEERIT_SUBSTRATE_INTENT_CORRUPT', 'Peerit VNext intent metadata does not reproduce its exact Cell envelope.')
  }
  return Object.freeze({
    intentId: entry.intentId,
    logicalId: entry.logicalId,
    innerCodec: decoded.innerCodec,
    innerBytes: decoded.innerBytes,
    innerLength: Number(decoded.innerLength),
    sizeClass: decoded.sizeClass,
    logicalHash: decoded.logicalHash,
    encodingCommitment: decoded.encodingCommitment,
    operations: clone(decoded.operations),
    recordKeys: [...entry.recordKeys],
    targetId
  })
}

export class PeeritSubstrateSync {
  constructor (options = {}) {
    if (!options.journal || typeof options.journal.commitIntent !== 'function') {
      throw new TypeError('PeeritSubstrateSync requires a transactional journal')
    }
    this.mode = 'peerit-substrate'
    this.journal = options.journal
    this.clock = typeof options.clock === 'function' ? options.clock : Date.now
    this.autoFlush = options.autoFlush !== false
    this.requireVerifiedRelayAdapters = options.requireVerifiedRelayAdapters === true
    this.maxRelayTargets = Number.isSafeInteger(options.maxRelayTargets)
      ? Math.max(1, Math.min(MAX_RELAY_TARGETS, options.maxRelayTargets))
      : MAX_RELAY_TARGETS
    this.deliveryIntentConcurrency = Number.isSafeInteger(options.deliveryIntentConcurrency)
      ? Math.max(1, Math.min(MAX_DELIVERY_INTENT_CONCURRENCY, options.deliveryIntentConcurrency))
      : 4
    this.deliveryRelayConcurrency = Number.isSafeInteger(options.deliveryRelayConcurrency)
      ? Math.max(1, Math.min(this.maxRelayTargets, options.deliveryRelayConcurrency))
      : this.maxRelayTargets
    this.relayHints = Array.isArray(options.relayHints) ? [...new Set(options.relayHints.map(String))] : []
    this.relays = []
    this._listeners = new Set()
    this._summary = emptySummary()
    this._tail = Promise.resolve()
    this._activeWriterSession = null
    this._flush = null
    this._flushTimer = null
    this._flushDueAt = 0
    this._flushRequested = false
    this._deliveryCursor = null
    this._destroyed = false
    this._readyComplete = false
    this._localFailure = null
    this._localWarning = null
    this._relayQualificationStatus = null
    this._channel = null
    this._channelName = options.channelName || 'peerit-substrate-journal-v2'
    this._lockManager = options.lockManager || (globalThis.navigator && globalThis.navigator.locks)
    this._lockName = options.lockName || 'peerit-substrate-writer-v2'
    this._attemptOwner = options.attemptOwner || attemptOwnerId()
    this._attemptCounter = 0
    this.deliveryLeaseMs = Number.isSafeInteger(options.deliveryLeaseMs)
      ? Math.max(1000, options.deliveryLeaseMs)
      : 60_000
    this.deliveryAttemptTimeoutMs = Number.isSafeInteger(options.deliveryAttemptTimeoutMs)
      ? Math.max(10, Math.min(this.deliveryLeaseMs, options.deliveryAttemptTimeoutMs))
      : Math.min(this.deliveryLeaseMs, 15_000)
    this.retryBaseMs = Number.isSafeInteger(options.retryBaseMs) ? Math.max(10, options.retryBaseMs) : 1000
    this.retryMaxMs = Number.isSafeInteger(options.retryMaxMs) ? Math.max(this.retryBaseMs, options.retryMaxMs) : 60_000
    this.readbackFreshnessTtlMs = Number.isSafeInteger(options.readbackFreshnessTtlMs)
      ? Math.max(1, Math.min(MAX_READBACK_FRESHNESS_TTL_MS, options.readbackFreshnessTtlMs))
      : PEERIT_CELL_READBACK_FRESHNESS_TTL_MS
    this.compaction = options.compaction || {}
    this._readbackValidatedTargets = new Set()
    this._readbackRevalidationRequired = new Set()
    this.viewEpoch = 0
    this.setRelays(options.relays || [])
  }

  async ready () {
    try {
      const readiness = await this.journal.ready()
      this._localWarning = (readiness && readiness.cleanupWarning) || null
      let summary = await this.journal.summary()
      if (!summary.dormant && ((summary.targetStateCounts.preparing || 0) > 0 ||
        (summary.targetStateCounts.delivering || 0) > 0)) {
        const recovered = await this.journal.recoverExpiredClaims(this.clock())
        if (recovered) summary = await this.journal.summary()
      }
      this._adoptSummary(summary)
    } catch (error) {
      this._localFailure = error
      this._adoptSummary(emptySummary())
    }
    this._readyComplete = true
    this._startChannel()
    this._scheduleFlush()
    return this
  }

  _startChannel () {
    if (typeof BroadcastChannel === 'undefined' || this._channel || this._destroyed) return
    try {
      this._channel = new BroadcastChannel(this._channelName)
      if (this._channel.unref) this._channel.unref()
      this._channel.onmessage = event => {
        if (!event || !event.data || event.data.key !== 'peerit-journal-v2') return
        this._reloadFromExternal(event.data.viewChanged === true).catch(error => {
          this._localFailure = error
          console.error(error)
        })
      }
    } catch {}
  }

  async _reloadFromExternal (viewChangedHint) {
    const previous = this._summary
    const next = await this.journal.summary()
    if (previous && next.revision <= previous.revision) return
    const viewChanged = viewChangedHint || !previous || next.viewRevision !== previous.viewRevision
    this._adoptSummary(next)
    this._emit(viewChanged ? undefined : [])
    this._scheduleFlush()
  }

  _adoptSummary (summary) {
    this._summary = summary || emptySummary()
    this.viewEpoch = this._summary.viewRevision || 0
  }

  async _withLock (operation) {
    if (this._lockManager && typeof this._lockManager.request === 'function') {
      return this._lockManager.request(this._lockName, { mode: 'exclusive' }, operation)
    }
    const run = this._tail.then(operation, operation)
    this._tail = run.then(() => undefined, () => undefined)
    return run
  }

  async withLocalWriterSession (operation) {
    if (typeof operation !== 'function') throw new TypeError('writer session callback is required')
    return this._withLock(async () => {
      const token = Object.freeze({ owner: this })
      this._activeWriterSession = token
      try { return await operation(token) } finally { this._activeWriterSession = null }
    })
  }

  withAtomicWriterSession (operation) { return this.withLocalWriterSession(operation) }

  async append (operation, writerSession = null) {
    return this._appendOperations([operation], writerSession)
  }

  async appendBatch (operations, writerSession = null) {
    if (!Array.isArray(operations) || operations.length === 0) throw new TypeError('non-empty operation batch required')
    return this._appendOperations(operations, writerSession)
  }

  async _appendOperations (operations, writerSession) {
    if (this._localFailure) {
      const error = new Error('Peerit cannot safely journal a signed publication on this device.')
      error.code = 'PEERIT_SUBSTRATE_LOCAL_AUTHORING_BLOCKED'
      error.cause = this._localFailure
      throw error
    }
    // VNext validates and snapshots the exact tag-334 bytes before anything
    // enters the journal. The relay path receives these bytes verbatim; it is
    // never allowed to reconstruct a Cell payload from raw operation JSON.
    const journalKeyLimit = this.journal && this.journal.limits && this.journal.limits.maxRecordKeyBytes
    const batch = await normalizePublicationBatch(operations, {
      maxRecordKeyBytes: Number.isSafeInteger(journalKeyLimit) && journalKeyLimit > 0
        ? journalKeyLimit
        : PEERIT_INNER_OPERATION_BATCH_V1_DEFAULT_MAX_RECORD_KEY_BYTES
    })
    const normalized = batch.operations
    const journalIntentLimit = this.journal && this.journal.limits && this.journal.limits.maxIntentBytes
    if (Number.isSafeInteger(journalIntentLimit) && journalIntentLimit > 0 &&
        Number(batch.innerLength) > journalIntentLimit) {
      const error = new Error('Peerit signed publication exceeds the active exact-intent journal bound.')
      error.code = 'PEERIT_SUBSTRATE_INTENT_TOO_LARGE'
      throw error
    }
    const intentId = hex(hashPeeritInnerOperationIntentIdV1(batch.innerCodec, batch.innerBytes))
    const logicalId = hex(batch.logicalHash)
    const keys = normalized.map(viewKey)
    const commit = () => this.journal.commitIntent({
      intentId,
      logicalId,
      wireFormat: PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
      innerCodec: batch.innerCodec,
      innerBytes: batch.innerBytes,
      innerLength: Number(batch.innerLength),
      logicalHash: batch.logicalHash,
      encodingCommitment: batch.encodingCommitment,
      sizeClass: batch.sizeClass,
      records: normalized.map((operation, index) => ({ key: keys[index], value: operation.data })),
      createdAt: this.clock(),
      discoveryState: 'queued'
    })
    let result
    try {
      result = writerSession && writerSession === this._activeWriterSession
        ? await commit()
        : await this._withLock(commit)
      await this._refreshAfterMutation(!result.duplicate, result.duplicate ? [] : keys)
    } catch (error) {
      this._localFailure = error
      throw error
    }
    this._scheduleFlush()
    return Object.freeze({
      ok: true,
      local: true,
      duplicate: result.duplicate,
      intentId,
      logicalId,
      queued: result.queued
    })
  }

  async get (key) { return this.journal.getView(key) }

  async list (prefix, options = {}) {
    return this.range(prefix
      ? { gte: prefix, lt: prefix + '\xff', limit: options.limit }
      : { limit: options.limit })
  }

  async range (options = {}) { return this.journal.rangeView(options) }

  async count (prefix) { return this.journal.countView(prefix) }

  async status () {
    let latest = null
    try {
      this._adoptSummary(await this.journal.summary())
      if (this._summary.latestIntentId) latest = await this.journal.getIntent(this._summary.latestIntentId)
    } catch (error) { this._localFailure = error }
    const summary = this._summary || emptySummary()
    const activeRelays = this._activeRelays()
    const evidence = readbackEvidence(
      latest,
      activeRelays,
      this._readbackValidatedTargets,
      this._readbackRevalidationRequired,
      this.clock(),
      this.readbackFreshnessTtlMs,
      this.journal && this.journal.limits && this.journal.limits.maxTargetsPerIntent
    )
    return Object.freeze({
      appId: 'peerit',
      mode: this.mode,
      secure: true,
      readOnly: false,
      peers: activeRelays.length,
      viewLength: summary.viewRecordCount || 0,
      relayQualification: this._relayQualificationStatus,
      publication: publicationStatus(
        summary,
        activeRelays,
        this.relayHints,
        evidence,
        this.readbackFreshnessTtlMs,
        this._localFailure ? 'blocked' : 'ready',
        this._localWarning,
        this._localFailure
      )
    })
  }

  setRelays (relays) {
    this.relays = (Array.isArray(relays) ? relays : [])
      .filter(relay => !this.requireVerifiedRelayAdapters || isPeeritVerifiedRelayAdapter(relay))
      .map(normalizeRelay)
      .filter((relay, index, all) => all.findIndex(candidate => candidate.id === relay.id) === index)
    this._readbackValidatedTargets.clear()
    this._readbackRevalidationRequired = new Set(this.relays.filter(usableRelay).map(relay => relay.id))
    if (this._listeners) this._emit([])
    this._scheduleFlush()
  }

  _activeRelays () {
    return this.relays.filter(usableRelay).slice(0, this.maxRelayTargets)
  }

  setRelayQualificationStatus (status) {
    this._relayQualificationStatus = normalizeRelayQualificationStatus(status)
    if (this._listeners) this._emit([])
  }

  async flushPublicationQueue () {
    if (this._localFailure) return this.status()
    if (this._flush) {
      this._flushRequested = true
      return this._flush
    }
    this._flushRequested = false
    const run = (async () => {
      let summary = await this.journal.summary()
      if ((summary.targetStateCounts.preparing || 0) > 0 || (summary.targetStateCounts.delivering || 0) > 0) {
        const recovered = await this.journal.recoverExpiredClaims(this.clock())
        if (recovered) {
          await this._refreshAfterMutation(false, [])
          summary = await this.journal.summary()
        }
      }
      const activeRelays = this._activeRelays()
      const latestVNextIntentId = summary.latest &&
        summary.latest.wireFormat === PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1
        ? summary.latest.intentId
        : null
      if (latestVNextIntentId && activeRelays.length) {
        await this._revalidateLatestReadback(latestVNextIntentId, activeRelays)
        summary = await this.journal.summary()
      }
      const page = await this.journal.listIntentIds({ after: this._deliveryCursor })
      const targetIds = activeRelays.map(relay => relay.id)
      const reconcileTargetIds = activeRelays
        .filter(relay => typeof relay.reconcile === 'function')
        .map(relay => relay.id)
      const retries = typeof this.journal.listRetryIntentIds === 'function'
        ? await this.journal.listRetryIntentIds({ now: this.clock(), targetIds, reconcileTargetIds })
        : { intentIds: [] }
      // Including exactly the latest active intent is bounded and lets a newly
      // qualified, protocol-compliant target identity receive one fresh replica.
      // Existing acknowledged targets still short-circuit and are never resent.
      const intentIds = [...new Set([
        ...page.intentIds,
        ...retries.intentIds,
        ...(latestVNextIntentId ? [latestVNextIntentId] : [])
      ])]
      await runBounded(intentIds, this.deliveryIntentConcurrency, intentId =>
        this._deliverIntent(intentId, activeRelays, intentId === latestVNextIntentId))
      this._deliveryCursor = page.hasMore ? page.cursor : null
      await this.journal.compact({ now: this.clock(), ...this.compaction })
      this._adoptSummary(await this.journal.summary())
      if (page.hasMore && activeRelays.length) this._flushRequested = true
      return this.status()
    })()
    this._flush = run
    try {
      return await run
    } catch (error) {
      this._localFailure = error
      throw error
    } finally {
      if (this._flush === run) this._flush = null
      if (this._flushRequested) {
        this._flushRequested = false
        this._scheduleFlush()
      } else {
        this._scheduleNextAttempt()
      }
    }
  }

  async _deliverIntent (intentId, activeRelays = this._activeRelays(), isLatestIntent = false) {
    const entry = await this.journal.getIntent(intentId)
    if (!entry) return
    const known = new Set(Object.keys(entry.targets || {}))
    const existing = activeRelays.filter(relay => known.has(relay.id))
    const allowUnknownTargets = isLatestIntent || entry.acknowledgedTargets === 0
    const unknown = (allowUnknownTargets ? activeRelays : []).filter(relay => !known.has(relay.id))
      .sort((left, right) => left.id.localeCompare(right.id))
    const targetLimit = this.journal && this.journal.limits && this.journal.limits.maxTargetsPerIntent
    const available = Number.isSafeInteger(targetLimit)
      ? Math.max(0, targetLimit - entry.targetCount)
      : unknown.length
    const selected = [...existing, ...unknown.slice(0, available)]
    await runBounded(selected, this.deliveryRelayConcurrency, relay => this._deliverIntentToRelay(intentId, relay))
  }

  async _revalidateLatestReadback (intentId, activeRelays) {
    await runBounded(activeRelays, this.deliveryRelayConcurrency, relay =>
      this._revalidateIntentReadback(intentId, relay))
  }

  async _revalidateIntentReadback (intentId, relay) {
    const entry = await this.journal.getIntent(intentId)
    if (!entry) return
    const target = targetSnapshot(entry, relay.id)
    if (!target || target.state !== 'readback-verified' || target.readbackVerified !== true) return
    if (target.readbackRepairNeeded === true) {
      this._readbackValidatedTargets.delete(relay.id)
      this._readbackRevalidationRequired.delete(relay.id)
      return
    }
    const now = this.clock()
    const retryAt = Number.isSafeInteger(target.readbackRevalidationNextAttemptAt)
      ? target.readbackRevalidationNextAttemptAt
      : 0
    if (retryAt > now) return
    const verifiedAt = Number.isSafeInteger(target.lastReadbackVerifiedAt) && target.lastReadbackVerifiedAt >= 0
      ? target.lastReadbackVerifiedAt
      : null
    const observedEvidenceRevision = Number.isSafeInteger(target.lastReadbackEvidenceRevision) &&
      target.lastReadbackEvidenceRevision >= 0
      ? target.lastReadbackEvidenceRevision
      : 0
    const fresh = verifiedAt != null && now >= verifiedAt && now - verifiedAt < this.readbackFreshnessTtlMs &&
      target.readbackCurrentInvalidated !== true && this._readbackValidatedTargets.has(relay.id)
    if (fresh && !this._readbackRevalidationRequired.has(relay.id)) return

    let result
    try {
      if (typeof relay.revalidateReadback !== 'function') {
        const error = new Error('qualified relay adapter cannot force an authenticated Cell GET revalidation')
        error.code = 'PEERIT_SUBSTRATE_READBACK_REVALIDATION_UNAVAILABLE'
        error.terminal = true
        throw error
      }
      const payload = await publicationPayload(entry, relay.id)
      result = await withDeadline(this.deliveryAttemptTimeoutMs, context => relay.revalidateReadback(payload, context))
      if (!this.relays.includes(relay)) return
      if (!result || result.ok !== true || result.acknowledged !== true || result.readbackVerified !== true ||
          result.readbackRevalidated !== true ||
          !Number.isSafeInteger(result.readbackEvidenceRevision) || result.readbackEvidenceRevision < 1 ||
          typeof result.evidenceRef !== 'string' || !result.evidenceRef) {
        const error = new Error('relay readback revalidation did not return authenticated durable evidence')
        error.code = 'PEERIT_SUBSTRATE_UNVERIFIED_READBACK'
        error.terminal = true
        throw error
      }
      const recorded = await this.journal.recordReadbackRevalidation({
        intentId,
        targetId: relay.id,
        success: true,
        evidenceRef: result.evidenceRef,
        evidenceRevision: result.readbackEvidenceRevision,
        now: this.clock()
      })
      if (!recorded) return
      this._readbackValidatedTargets.add(relay.id)
      this._readbackRevalidationRequired.delete(relay.id)
      await this._refreshAfterMutation(false, [])
    } catch (error) {
      // A replaced adapter no longer owns current status for this installation.
      // Its late failure must not poison a same-ID replacement that may already
      // have completed a newer authenticated GET.
      if (!this.relays.includes(relay)) return
      const repairNeeded = readbackNeedsRepair(error)
      const recorded = await this.journal.recordReadbackRevalidation({
        intentId,
        targetId: relay.id,
        success: false,
        repairNeeded,
        expectedEvidenceRevision: observedEvidenceRevision,
        lastError: String((error && (error.code || error.message)) || 'readback-revalidation-failed'),
        now: this.clock(),
        retryBaseMs: this.retryBaseMs,
        retryMaxMs: this.retryMaxMs
      })
      this._readbackValidatedTargets.delete(relay.id)
      if (repairNeeded) this._readbackRevalidationRequired.delete(relay.id)
      if (recorded) await this._refreshAfterMutation(false, [])
    }
  }

  async _deliverIntentToRelay (intentId, relay) {
    const entry = await this.journal.getIntent(intentId)
    if (!entry) return
    const previous = targetSnapshot(entry, relay.id)
    const targetLimit = this.journal && this.journal.limits && this.journal.limits.maxTargetsPerIntent
    if (!previous && Number.isSafeInteger(targetLimit) && entry.targetCount >= targetLimit) return
    if (previous && ACKNOWLEDGED.has(previous.state)) return
    if (previous && (previous.state === 'preparing' || previous.state === 'delivering')) return
    if (previous && previous.state === 'pending-unknown' && typeof relay.reconcile !== 'function') return
    if (previous && ['retryable', 'pending-unknown'].includes(previous.state) &&
        Number.isSafeInteger(previous.nextAttemptAt) && previous.nextAttemptAt > this.clock()) return
    const reconcile = !!(previous && previous.state === 'pending-unknown' && typeof relay.reconcile === 'function')
    const split = !reconcile && typeof relay.prepare === 'function' && typeof relay.send === 'function'
    const claimedState = split ? 'preparing' : 'delivering'
    const now = this.clock()
    const proposedToken = `${this._attemptOwner}:${++this._attemptCounter}:${now}`
    const attemptToken = await this.journal.claimTarget({
      intentId,
      targetId: relay.id,
      state: claimedState,
      expectedState: reconcile ? 'pending-unknown' : null,
      attemptToken: proposedToken,
      leaseUntil: now + this.deliveryLeaseMs,
      now
    })
    if (!attemptToken) return
    await this._refreshAfterMutation(false, [])
    let networkMayHaveStarted = reconcile || !split
    try {
      const current = await this.journal.getIntent(intentId)
      if (!current) throw new Error('Peerit publication intent disappeared from its local journal')
      const payload = await publicationPayload(current, relay.id)
      let result
      if (reconcile) {
        result = await withDeadline(this.deliveryAttemptTimeoutMs, context => relay.reconcile(payload, context))
      } else if (split) {
        const prepared = await withDeadline(this.deliveryAttemptTimeoutMs, context => relay.prepare(payload, context))
        const transitionAt = this.clock()
        const advanced = await this.journal.transitionTarget({
          intentId,
          targetId: relay.id,
          attemptToken,
          from: 'preparing',
          to: 'delivering',
          leaseUntil: transitionAt + this.deliveryLeaseMs,
          now: transitionAt
        })
        if (!advanced) return
        await this._refreshAfterMutation(false, [])
        networkMayHaveStarted = true
        result = await withDeadline(this.deliveryAttemptTimeoutMs, context => relay.send({ ...payload, prepared }, context))
      } else {
        result = await withDeadline(this.deliveryAttemptTimeoutMs, context => relay.deliver(payload, context))
      }
      if (!result || (result.ok !== true && result.acknowledged !== true) ||
          typeof result.evidenceRef !== 'string' || !result.evidenceRef) {
        const error = new Error('relay did not return a verified acknowledgement')
        error.code = 'PEERIT_SUBSTRATE_UNVERIFIED_ACK'
        throw error
      }
      const completedAt = this.clock()
      const relayStillQualified = this.relays.includes(relay)
      const liveReadback = result.readbackVerified === true && result.readbackRevalidated === true &&
        Number.isSafeInteger(result.readbackEvidenceRevision) && result.readbackEvidenceRevision >= 1 &&
        relayStillQualified
      const completed = await this.journal.completeTarget({
        intentId,
        targetId: relay.id,
        attemptToken,
        evidenceRef: result.evidenceRef,
        readbackVerified: result.readbackVerified === true,
        readbackVerifiedAt: liveReadback ? completedAt : null,
        readbackEvidenceRevision: liveReadback ? result.readbackEvidenceRevision : null,
        policyDurable: result.policyDurable === true,
        discoveryState: result.discoveryState,
        now: completedAt
      })
      if (completed) {
        if (liveReadback) {
          this._readbackValidatedTargets.add(relay.id)
          this._readbackRevalidationRequired.delete(relay.id)
        }
        await this._refreshAfterMutation(false, [])
      }
    } catch (error) {
      const failedAt = this.clock()
      const failureState = error && error.terminal === true
        ? 'terminal'
        : !networkMayHaveStarted || definitelyNotProcessed(error) ? 'retryable' : 'pending-unknown'
      const failure = {
        intentId,
        targetId: relay.id,
        attemptToken,
        state: failureState,
        lastError: String((error && (error.code || error.message)) || 'delivery-failed'),
        now: failedAt,
        retryBaseMs: this.retryBaseMs,
        retryMaxMs: this.retryMaxMs
      }
      // A first ambiguous send may be reconciled immediately if a capable
      // adapter appears. Failed reconciliation attempts still back off.
      if (failureState === 'pending-unknown' && !reconcile) failure.nextAttemptAt = failedAt
      const failed = await this.journal.failTarget(failure)
      if (failed) await this._refreshAfterMutation(false, [])
    }
  }

  async _refreshAfterMutation (viewChanged, changedKeys) {
    this._adoptSummary(await this.journal.summary())
    this._broadcast(viewChanged)
    this._emit(changedKeys)
  }

  _scheduleFlush (delay = 0) {
    if (!this.autoFlush || this._destroyed || !this._readyComplete || this._localFailure) return
    if (this._flush) {
      this._flushRequested = true
      return
    }
    delay = Math.max(0, Number(delay) || 0)
    const dueAt = this.clock() + delay
    if (this._flushTimer) {
      if (dueAt >= this._flushDueAt) return
      clearTimeout(this._flushTimer)
      this._flushTimer = null
    }
    this._flushDueAt = dueAt
    this._flushTimer = setTimeout(() => {
      this._flushTimer = null
      this._flushDueAt = 0
      this.flushPublicationQueue().catch(error => console.error(error))
    }, delay)
  }

  async _nextReadbackWake (activeRelays) {
    if (!activeRelays.length) return null
    const summary = await this.journal.summary()
    if (!summary.latestIntentId || !summary.latest ||
        summary.latest.wireFormat !== PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1) return null
    const entry = await this.journal.getIntent(summary.latestIntentId)
    if (!entry) return null
    const now = this.clock()
    let delay = Infinity
    for (const relay of activeRelays) {
      const target = targetSnapshot(entry, relay.id)
      if (!target || target.state !== 'readback-verified' || target.readbackVerified !== true ||
          target.readbackRepairNeeded === true) continue
      const retryAt = Number.isSafeInteger(target.readbackRevalidationNextAttemptAt)
        ? target.readbackRevalidationNextAttemptAt
        : 0
      if (retryAt > now) {
        delay = Math.min(delay, retryAt - now)
        continue
      }
      const verifiedAt = Number.isSafeInteger(target.lastReadbackVerifiedAt) && target.lastReadbackVerifiedAt >= 0
        ? target.lastReadbackVerifiedAt
        : null
      if (this._readbackRevalidationRequired.has(relay.id) ||
          !this._readbackValidatedTargets.has(relay.id) ||
          target.readbackCurrentInvalidated === true || verifiedAt == null || now < verifiedAt) return 0
      delay = Math.min(delay, Math.max(0, verifiedAt + this.readbackFreshnessTtlMs - now))
    }
    return Number.isFinite(delay) ? delay : null
  }

  _scheduleNextAttempt () {
    if (!this.autoFlush || this._destroyed || !this._readyComplete || this._localFailure) return
    const activeRelays = this._activeRelays()
    const reconcileTargetIds = activeRelays
      .filter(relay => typeof relay.reconcile === 'function')
      .map(relay => relay.id)
    const targetIds = activeRelays.map(relay => relay.id)
    Promise.all([
      this.journal.nextWake({
        now: this.clock(),
        targetIds,
        reconcileTargetIds,
        retryBaseMs: this.retryBaseMs,
        retryMaxMs: this.retryMaxMs
      }),
      this._nextReadbackWake(activeRelays)
    ]).then(delays => {
      const eligible = delays.filter(delay => delay != null)
      if (eligible.length) this._scheduleFlush(Math.min(...eligible))
    }).catch(error => {
      this._localFailure = error
      console.error(error)
    })
  }

  onChange (listener) {
    if (typeof listener !== 'function') throw new TypeError('change listener must be a function')
    this._listeners.add(listener)
    return () => this._listeners.delete(listener)
  }

  _emit (changed) {
    for (const listener of this._listeners) {
      try { listener(changed) } catch (error) { console.error(error) }
    }
  }

  _broadcast (viewChanged) {
    if (!this._channel) return
    try {
      this._channel.postMessage({
        key: 'peerit-journal-v2',
        revision: this._summary.revision,
        viewRevision: this._summary.viewRevision,
        viewChanged
      })
    } catch {}
  }

  destroy () {
    this._destroyed = true
    if (this._flushTimer) clearTimeout(this._flushTimer)
    this._flushTimer = null
    this._flushDueAt = 0
    if (this._channel) {
      try { this._channel.close() } catch {}
      this._channel = null
    }
    this._listeners.clear()
    Promise.resolve(this.journal.close()).catch(error => console.error(error))
  }
}

export function createPeeritSubstrateSync (options = {}) {
  const legacyStorage = options.legacyStorage || options.storage ||
    globalThis.localStorage || null
  let journal = options.journal
  if (!journal && options.journalBackend) {
    journal = new PeeritJournal({
      backend: options.journalBackend,
      legacyStorage,
      clock: options.clock,
      limits: options.journalLimits
    })
  } else if (!journal) {
    journal = createIndexedDbPeeritJournal({
      indexedDB: options.indexedDB || globalThis.indexedDB,
      IDBKeyRange: options.IDBKeyRange || globalThis.IDBKeyRange,
      dbName: options.journalDbName,
      legacyStorage,
      markerStorage: options.markerStorage || legacyStorage,
      clock: options.clock,
      limits: options.journalLimits
    })
  }
  return new PeeritSubstrateSync({ ...options, journal })
}
