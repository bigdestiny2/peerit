// Bounded transactional journal for Peerit's local-first blind-substrate path.
// All mutation methods are single backend transactions, so IndexedDB provides
// cross-tab CAS even where navigator.locks is absent. The deterministic memory
// backend runs the exact same journal logic in tests.

import { hashHex } from '../crypto.js'
import { verifyRecord } from '../verify.js'
import {
  IndexedDbJournalBackend,
  JOURNAL_MARKER_KEY,
  JOURNAL_STORES,
  MemoryJournalBackend,
  createMemoryJournalState
} from './peerit-journal-backend.js'

export const PEERIT_JOURNAL_SCHEMA_VERSION = 2
export const LEGACY_SUBSTRATE_STATE_KEY = 'peerit:substrate-sync:v1'

export const JOURNAL_LIMITS = Object.freeze({
  maxIntentBytes: 1_100_000,
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
const ACKNOWLEDGED = new Set(['acknowledged', 'readback-verified'])
const RETRY_DUE_STATES = new Set(['retryable', 'pending-unknown'])
const TARGET_STATES = Object.freeze([
  'preparing', 'delivering', 'pending-unknown', 'retryable',
  'terminal', 'acknowledged', 'readback-verified'
])
const HEX64 = /^[0-9a-f]{64}$/

function clone (value) {
  if (value == null) return value
  if (typeof structuredClone === 'function') return structuredClone(value)
  return JSON.parse(JSON.stringify(value))
}

function byteLength (value) { return new TextEncoder().encode(String(value)).byteLength }

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
    'pendingIntentCount', 'dedupeCount', 'intentBytes', 'latestCreatedAt'
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
    if (sourceIntentId !== intentId || intentId !== expectedIntentId || logicalId !== expectedLogicalId) {
      throw legacyUnverified('Legacy intent identifiers do not match the exact signed operation bytes.')
    }
    const recordKeys = []
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
      reducedView.set(key, { key, value: clone(operation.data), intentId })
    }
    const claimedKeys = Array.isArray(legacy.recordKeys) ? legacy.recordKeys.map(String) : []
    if (claimedKeys.length !== recordKeys.length || claimedKeys.some((key, index) => key !== recordKeys[index])) {
      throw legacyUnverified('Legacy intent record keys do not match its verified operation reduction.')
    }
    const createdAt = nonNegativeInteger(legacy.createdAt, now)
    const updatedAt = nonNegativeInteger(legacy.updatedAt, createdAt)
    const targets = Object.entries(legacy.targets || {})
    if (targets.length > limits.maxTargetsPerIntent) throw journalError('PEERIT_JOURNAL_LIMIT', 'Legacy intent has too many targets.')
    const normalizedTargets = targets.map(([rawTargetId, rawTarget]) => {
      if (!rawTarget || typeof rawTarget !== 'object' || Array.isArray(rawTarget)) {
        throw legacyUnverified('Legacy target state is malformed.')
      }
      const targetId = boundedString(rawTargetId, 'legacy targetId', limits.maxTargetIdBytes)
      const targetUpdatedAt = nonNegativeInteger(rawTarget.updatedAt, updatedAt)
      return {
        key: targetKey(intentId, targetId),
        intentId,
        targetId,
        state: 'pending-unknown',
        attempts: normalizedAttempts(rawTarget.attempts),
        attemptToken: null,
        updatedAt: targetUpdatedAt,
        nextAttemptAt: targetUpdatedAt,
        leaseUntil: 0,
        lastError: 'legacy-evidence-quarantined',
        readbackVerified: false,
        policyDurable: false,
        evidenceRef: null
      }
    })
    intentBytes += byteLength(operationBytes)
    if (intentBytes > limits.maxIntentBytesTotal) throw journalError('PEERIT_JOURNAL_LIMIT', 'Legacy intent bytes exceed the journal bound.')
    intents.push({
      intentId,
      logicalId,
      operationBytes,
      recordKeys,
      createdAt,
      updatedAt,
      discoveryState: 'queued',
      targetCount: normalizedTargets.length,
      acknowledgedTargets: 0,
      readbackVerified: 0,
      policyDurable: false,
      completedAt: 0,
      pendingOrderKey: pendingOrderKey(createdAt, intentId),
      targets: normalizedTargets
    })
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
    return { dormant: this.dormant, imported: source != null, cleanupWarning: this.failure }
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
        const { targets, ...intent } = verifiedIntent
        for (const target of targets) {
          await tx.put(JOURNAL_STORES.TARGETS, target)
          bumpTargetCount(meta, null, target.state)
        }
        await tx.put(JOURNAL_STORES.INTENTS, intent)
        meta.intentCount++
        meta.pendingIntentCount++
        if (intent.createdAt >= meta.latestCreatedAt) {
          meta.latestCreatedAt = intent.createdAt
          meta.latestIntentId = intent.intentId
        }
      }
      meta.intentBytes = verified.intentBytes
      await tx.put(JOURNAL_STORES.META, meta)
      return { imported: true, duplicate: false, hash: importHash }
    })
  }

  async commitIntent (input) {
    const intentId = validateIntentId(input.intentId)
    const logicalId = validateIntentId(input.logicalId, 'logicalId')
    const operationBytes = boundedString(input.operationBytes, 'operationBytes', this.limits.maxIntentBytes)
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
        if (existing.operationBytes !== operationBytes) throw journalError('PEERIT_JOURNAL_CORRUPT', 'Intent hash collision or journal corruption.')
        return { duplicate: true, compacted: false, queued: existing.acknowledgedTargets === 0, viewRevision: null }
      }
      const dedupe = await tx.get(JOURNAL_STORES.DEDUPE, intentId)
      if (dedupe) return { duplicate: true, compacted: true, queued: false, viewRevision: null }
      const meta = validateMeta(await tx.get(JOURNAL_STORES.META, META_KEY))
      if (meta.intentCount >= this.limits.maxIntents) throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit has reached its bounded active-intent limit.')
      if (meta.intentBytes + byteLength(operationBytes) > this.limits.maxIntentBytesTotal) {
        throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit has reached its bounded exact-intent byte limit.')
      }
      let newViewRecords = 0
      for (const record of normalizedRecords) if (!(await tx.get(JOURNAL_STORES.VIEW, record.key))) newViewRecords++
      if (meta.viewRecordCount + newViewRecords > this.limits.maxViewRecords) {
        throw journalError('PEERIT_JOURNAL_LIMIT', 'Peerit has reached its bounded materialized-view record limit.')
      }
      const now = this.clock()
      const intent = {
        intentId,
        logicalId,
        operationBytes,
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
      meta.intentBytes += byteLength(operationBytes)
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
        throw journalError('PEERIT_JOURNAL_LIMIT', 'Intent target count reached its bound.')
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
          completedAt: intent.completedAt,
          expiresAt: now + dedupeRetention
        })
        await tx.delete(JOURNAL_STORES.INTENTS, intent.intentId)
        meta.intentCount--
        meta.intentBytes -= byteLength(intent.operationBytes)
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
