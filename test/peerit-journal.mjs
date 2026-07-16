// Deterministic adversarial checks for the production Peerit journal contract.
// Run: node test/peerit-journal.mjs

import assert from 'node:assert/strict'
import { canonical } from '../js/canon.js'
import { genKeyPair, hashHex, ready as cryptoReady, sign } from '../js/crypto.js'
import {
  LEGACY_SUBSTRATE_STATE_KEY,
  JOURNAL_STORES,
  PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
  PEERIT_LEGACY_JSON_QUARANTINE_FORMAT_V1,
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  hashPeeritInnerCellEncodingCommitmentV1,
  hashPeeritInnerLogicalHashV1,
  hashPeeritInnerOperationIntentIdV1
} from '../js/substrate/peerit-operation-authority-v1.js'
import { peeritAuthorBindCellSizeClassForInnerLengthV1 } from '../js/substrate/author-bind-inner-envelope-policy.mjs'

let passed = 0
function ok (condition, message) {
  assert.ok(condition, message)
  passed++
  console.log('  ✓ ' + message)
}

const textEncoder = new TextEncoder()

function hex (value) {
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('')
}

function stable (value) {
  if (value === null) return 'null'
  if (typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  const keys = Object.keys(value).filter(key => value[key] !== undefined).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}

function fixtureEnvelope (number, options = {}) {
  // The journal owns durable exact-byte identity and commitments, while the
  // sync authority owns the signed operation validation before these bytes can
  // reach it. Keep journal fixtures deliberately structural, but use the real
  // tag-334 VNext frame and commitment functions so they cannot accidentally
  // exercise the retired raw-JSON path.
  const payload = options.innerPayload == null
    ? stable({ version: 1, operations: [{ type: 'post', data: { id: String(number) } }] })
    : options.innerPayload
  const payloadBytes = typeof payload === 'string'
    ? textEncoder.encode(payload)
    : new Uint8Array(payload)
  const innerBytes = new Uint8Array(7 + payloadBytes.byteLength)
  innerBytes[0] = (PEERIT_INNER_OPERATION_BATCH_V1_CODEC >>> 8) & 0xff
  innerBytes[1] = PEERIT_INNER_OPERATION_BATCH_V1_CODEC & 0xff
  innerBytes[2] = 1
  innerBytes[3] = (payloadBytes.byteLength >>> 24) & 0xff
  innerBytes[4] = (payloadBytes.byteLength >>> 16) & 0xff
  innerBytes[5] = (payloadBytes.byteLength >>> 8) & 0xff
  innerBytes[6] = payloadBytes.byteLength & 0xff
  innerBytes.set(payloadBytes, 7)
  const innerLength = innerBytes.byteLength
  const sizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(BigInt(innerLength))
  const logicalHash = hashPeeritInnerLogicalHashV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)
  const encodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
    PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
    innerBytes,
    logicalHash,
    sizeClass
  )
  return {
    wireFormat: PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
    innerCodec: PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
    innerBytes,
    innerLength,
    logicalHash,
    encodingCommitment,
    sizeClass,
    intentId: hex(hashPeeritInnerOperationIntentIdV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)),
    logicalId: hex(logicalHash)
  }
}

function id (number) { return fixtureEnvelope(number).intentId }

function intent (number, options = {}) {
  const key = options.key || `post!${number}`
  return {
    ...fixtureEnvelope(number, options),
    records: options.records || [{ key, value: { id: String(number), body: options.body || `record ${number}` } }],
    createdAt: options.createdAt == null ? number : options.createdAt,
    discoveryState: 'queued'
  }
}

function storage (initial = {}) {
  const values = new Map(Object.entries(initial))
  return {
    values,
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
  }
}

async function acknowledge (journal, number, targetId = 'relay-a', now = 100) {
  const token = await journal.claimTarget({
    intentId: id(number),
    targetId,
    state: 'delivering',
    attemptToken: `attempt-${number}`,
    leaseUntil: now + 1000,
    now
  })
  assert.ok(token)
  assert.equal(await journal.completeTarget({
    intentId: id(number),
    targetId,
    attemptToken: token,
    evidenceRef: `receipt:${number}`,
    readbackVerified: false,
    policyDurable: false,
    now: now + 1
  }), true)
}

async function main () {
  await cryptoReady()
  console.log('\n— dormant/fresh behavior and transactional persistence —')
  const shared = createMemoryJournalState()
  const journal = createMemoryPeeritJournal({ shared })
  await journal.ready()
  ok(shared.writeTransactions === 0 && (await journal.summary()).intentCount === 0,
    'fresh journal readiness and status perform no write transaction')

  const firstIntent = intent(1)
  const firstEnvelope = new Uint8Array(firstIntent.innerBytes)
  await journal.commitIntent(firstIntent)
  firstIntent.innerBytes[7] ^= 0xff
  const reloaded = createMemoryPeeritJournal({ shared })
  await reloaded.ready()
  ok((await reloaded.getView('post!1')).body === 'record 1' && (await reloaded.summary()).intentCount === 1,
    'an atomic intent/view commit survives a new journal instance')
  const persistedFirst = await reloaded.getIntent(id(1))
  ok(persistedFirst.wireFormat === PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1 &&
    persistedFirst.innerCodec === PEERIT_INNER_OPERATION_BATCH_V1_CODEC &&
    persistedFirst.innerLength === firstEnvelope.byteLength &&
    Buffer.from(persistedFirst.innerBytes).equals(Buffer.from(firstEnvelope)) &&
    persistedFirst.sizeClass === peeritAuthorBindCellSizeClassForInnerLengthV1(BigInt(firstEnvelope.byteLength)),
  'the journal preserves and defensively copies the exact VNext tag-334 envelope bytes')

  const beforeCrash = await reloaded.summary()
  shared.failNextCommit = Object.assign(new Error('simulated process loss before commit'), { code: 'SIMULATED_CRASH' })
  await assert.rejects(() => reloaded.commitIntent(intent(2)), error => error && error.code === 'PEERIT_JOURNAL_TRANSACTION_FAILED')
  passed++
  const afterCrash = await reloaded.summary()
  ok(afterCrash.revision === beforeCrash.revision && afterCrash.intentCount === 1 && await reloaded.getView('post!2') == null,
    'a crash before transaction commit leaves neither the intent nor its materialized record')

  console.log('\n— cross-instance CAS without Web Locks —')
  const concurrentState = createMemoryJournalState()
  const concurrentA = createMemoryPeeritJournal({ shared: concurrentState })
  const concurrentB = createMemoryPeeritJournal({ shared: concurrentState })
  await Promise.all([concurrentA.ready(), concurrentB.ready()])
  await Promise.all([concurrentA.commitIntent(intent(10)), concurrentB.commitIntent(intent(11))])
  ok((await concurrentA.summary()).intentCount === 2 && await concurrentB.getView('post!10') && await concurrentA.getView('post!11'),
    'concurrent commits from independent instances do not lose metadata or view records')

  const duplicateResults = await Promise.all([
    concurrentA.commitIntent(intent(12)),
    concurrentB.commitIntent(intent(12))
  ])
  ok(duplicateResults.filter(result => result.duplicate).length === 1 &&
    duplicateResults.filter(result => !result.duplicate).length === 1,
  'the exact same concurrent intent commits once and deterministically deduplicates once')

  const claims = await Promise.all([
    concurrentA.claimTarget({ intentId: id(10), targetId: 'same-relay', state: 'delivering', attemptToken: 'owner-a', leaseUntil: 1000, now: 0 }),
    concurrentB.claimTarget({ intentId: id(10), targetId: 'same-relay', state: 'delivering', attemptToken: 'owner-b', leaseUntil: 1000, now: 0 })
  ])
  ok(claims.filter(Boolean).length === 1,
    'transactional target CAS admits exactly one cross-instance delivery owner without navigator.locks')
  const winningToken = claims.find(Boolean)
  ok(await concurrentA.transitionTarget({ intentId: id(10), targetId: 'same-relay', attemptToken: 'wrong-owner', from: 'delivering', to: 'delivering', leaseUntil: 2000, now: 1 }) === false,
    'a stale or foreign attempt token cannot mutate the winning claim')
  await concurrentB.completeTarget({
    intentId: id(10),
    targetId: 'same-relay',
    attemptToken: winningToken,
    evidenceRef: 'verified:cross-instance',
    readbackVerified: true,
    policyDurable: false,
    now: 2
  })
  ok((await concurrentA.getIntent(id(10))).targets['same-relay'].evidenceRef === 'verified:cross-instance',
    'verified acknowledgement evidence is durable and visible to another instance')

  for (let index = 1; index < 15; index++) {
    assert.ok(await concurrentA.claimTarget({
      intentId: id(10),
      targetId: `prefill-relay-${index}`,
      state: 'delivering',
      attemptToken: `prefill-owner-${index}`,
      leaseUntil: 3000,
      now: 3
    }))
  }
  const lastSlotClaims = await Promise.all([
    concurrentA.claimTarget({ intentId: id(10), targetId: 'last-slot-relay-a', state: 'delivering', attemptToken: 'last-slot-owner-a', leaseUntil: 3000, now: 3 }),
    concurrentB.claimTarget({ intentId: id(10), targetId: 'last-slot-relay-b', state: 'delivering', attemptToken: 'last-slot-owner-b', leaseUntil: 3000, now: 3 })
  ])
  const cappedIntent = await concurrentA.getIntent(id(10))
  ok(lastSlotClaims.filter(Boolean).length === 1 &&
    cappedIntent.targetCount === 16 &&
    Number(Boolean(cappedIntent.targets['last-slot-relay-a'])) + Number(Boolean(cappedIntent.targets['last-slot-relay-b'])) === 1,
  'different-target cross-instance claims contend transactionally for the final bounded audit slot')

  console.log('\n— quota, corruption, and explicit bounds —')
  const quotaState = createMemoryJournalState()
  const quotaJournal = createMemoryPeeritJournal({ shared: quotaState })
  await quotaJournal.ready()
  await quotaJournal.commitIntent(intent(20))
  quotaState.quotaBytes = 1
  await assert.rejects(() => quotaJournal.commitIntent(intent(21)), error => error && error.code === 'PEERIT_JOURNAL_QUOTA')
  passed++
  ok((await quotaJournal.getView('post!20')).body === 'record 20' && await quotaJournal.getView('post!21') == null,
    'quota exhaustion is explicit and preserves every previously committed row')
  quotaState.quotaBytes = Infinity
  await quotaJournal.commitIntent(intent(21))
  ok((await quotaJournal.summary()).intentCount === 2,
    'the journal itself remains readable and recoverable after quota pressure clears')

  const bounded = createMemoryPeeritJournal({
    shared: createMemoryJournalState(),
    limits: { maxRecordsPerIntent: 1, maxIntentBytes: 128 }
  })
  await bounded.ready()
  await assert.rejects(
    () => bounded.commitIntent(intent(30, { records: [{ key: 'a', value: 1 }, { key: 'b', value: 2 }] })),
    error => error && error.code === 'PEERIT_JOURNAL_LIMIT'
  )
  passed++
  await assert.rejects(
    () => bounded.commitIntent(intent(31, { innerPayload: 'x'.repeat(129) })),
    error => error && error.code === 'PEERIT_JOURNAL_LIMIT'
  )
  passed++
  const tamperedCommitment = intent(32)
  tamperedCommitment.encodingCommitment[0] ^= 0xff
  await assert.rejects(
    () => bounded.commitIntent(tamperedCommitment),
    error => error && error.code === 'PEERIT_JOURNAL_BAD_INPUT'
  )
  passed++
  const retiredRaw = fixtureEnvelope(33)
  await assert.rejects(
    () => bounded.commitIntent({
      intentId: retiredRaw.intentId,
      logicalId: retiredRaw.logicalId,
      operationBytes: stable({ version: 1, operations: [{ type: 'post', data: { id: '33' } }] }),
      records: [{ key: 'post!33', value: { id: '33' } }]
    }),
    error => error && error.code === 'PEERIT_JOURNAL_BAD_INPUT'
  )
  passed++
  ok((await bounded.summary()).intentCount === 0,
    'record-count, exact-byte, commitment, and retired raw-JSON inputs reject before any commit')

  const corruptState = createMemoryJournalState()
  const corrupt = createMemoryPeeritJournal({ shared: corruptState })
  await corrupt.ready()
  await corrupt.commitIntent(intent(40))
  corrupt.backend.corrupt(JOURNAL_STORES.META, 'state', { key: 'state', schemaVersion: 999 })
  await assert.rejects(() => corrupt.summary(), error => error && error.code === 'PEERIT_JOURNAL_CORRUPT')
  passed++
  ok(await corrupt.getView('post!40').then(() => false, error => error.code === 'PEERIT_JOURNAL_CORRUPT'),
    'schema corruption fails closed instead of silently rebuilding or downgrading storage')

  console.log('\n— bounded compaction preserves every unresolved state —')
  let now = 100
  const compactState = createMemoryJournalState()
  const compact = createMemoryPeeritJournal({ shared: compactState, clock: () => now })
  await compact.ready()
  await compact.commitIntent(intent(50, { createdAt: 1 }))
  await acknowledge(compact, 50, 'relay-a', 10)
  await compact.commitIntent(intent(51, { createdAt: 2 }))
  await acknowledge(compact, 51, 'relay-a', 20)
  await compact.commitIntent(intent(52, { createdAt: 3 }))
  const ambiguousToken = await compact.claimTarget({
    intentId: id(52), targetId: 'relay-a', state: 'delivering', attemptToken: 'ambiguous', leaseUntil: 1000, now: 30
  })
  await compact.failTarget({
    intentId: id(52),
    targetId: 'relay-a',
    attemptToken: ambiguousToken,
    state: 'pending-unknown',
    lastError: 'response-lost',
    now: 31
  })
  await compact.commitIntent(intent(53, { createdAt: 4 }))
  await compact.claimTarget({
    intentId: id(53), targetId: 'relay-a', state: 'preparing', attemptToken: 'prepared', leaseUntil: 1000, now: 32
  })
  now = 10_000
  const compacted = await compact.compact({ now, acknowledgedRetentionMs: 0, dedupeRetentionMs: 100_000 })
  ok(compacted.compacted === 2 && await compact.getIntent(id(50)) == null && await compact.getIntent(id(51)) == null,
    'compaction removes only old completed non-latest intents and leaves active history untouched')
  const ambiguous = await compact.getIntent(id(52))
  const preparing = await compact.getIntent(id(53))
  ok(ambiguous.targets['relay-a'].state === 'pending-unknown' && ambiguous.targets['relay-a'].attemptToken === 'ambiguous' &&
    preparing.targets['relay-a'].state === 'preparing',
  'compaction never deletes queued, preparing, sent/ambiguous, or reconciliation state')
  const compactedDuplicate = await compact.commitIntent(intent(50, { createdAt: 1 }))
  ok(compactedDuplicate.duplicate === true && compactedDuplicate.compacted === true && compactedDuplicate.queued === false,
    'bounded tombstones retain exact idempotency after acknowledged payload compaction')

  console.log('\n— persisted due scheduling and online-arrival fairness —')
  const scheduleState = createMemoryJournalState()
  const scheduled = createMemoryPeeritJournal({ shared: scheduleState, clock: () => 101 })
  await scheduled.ready()
  await scheduled.commitIntent(intent(70))
  const scheduledToken = await scheduled.claimTarget({
    intentId: id(70),
    targetId: 'scheduled-relay',
    state: 'delivering',
    attemptToken: 'scheduled-attempt',
    leaseUntil: 200,
    now: 100
  })
  await scheduled.failTarget({
    intentId: id(70),
    targetId: 'scheduled-relay',
    attemptToken: scheduledToken,
    state: 'retryable',
    lastError: 'safe-retry',
    now: 101,
    retryBaseMs: 10,
    retryMaxMs: 40
  })
  const scheduledIntent = await scheduled.getIntent(id(70))
  ok(scheduledIntent.targets['scheduled-relay'].nextAttemptAt === 111 &&
    (await scheduled.listRetryIntentIds({ now: 110, targetIds: ['scheduled-relay'] })).intentIds.length === 0 &&
    (await scheduled.nextWake({ now: 101, targetIds: ['scheduled-relay'] })) === 10,
  'retry due time is persisted and neither scans nor wake scheduling recompute it')
  const scheduledReload = createMemoryPeeritJournal({ shared: scheduleState, clock: () => 102 })
  await scheduledReload.ready()
  ok(await scheduledReload.claimTarget({
    intentId: id(70),
    targetId: 'scheduled-relay',
    state: 'delivering',
    attemptToken: 'too-early',
    leaseUntil: 200,
    now: 110
  }) == null &&
    (await scheduledReload.listRetryIntentIds({ now: 111, targetIds: ['scheduled-relay'] })).intentIds[0] === id(70),
  'a reload preserves the exact due boundary and transactional claims reject early retry')

  const fairness = createMemoryPeeritJournal({ shared: createMemoryJournalState() })
  await fairness.ready()
  const oldCount = 48
  const queueRetry = async (number, updatedAt) => {
    await fairness.commitIntent(intent(number))
    const token = await fairness.claimTarget({
      intentId: id(number),
      targetId: 'fair-relay',
      state: 'delivering',
      attemptToken: `fair:${number}`,
      leaseUntil: updatedAt + 1,
      now: updatedAt
    })
    await fairness.failTarget({
      intentId: id(number),
      targetId: 'fair-relay',
      attemptToken: token,
      state: 'retryable',
      lastError: 'queued',
      now: updatedAt,
      nextAttemptAt: 0
    })
  }
  for (let number = 100; number < 100 + oldCount; number++) await queueRetry(number, 1)
  const oldIntentIds = new Set(Array.from({ length: oldCount }, (_, index) => id(100 + index)))
  const seenOld = new Set()
  for (let round = 0; round < 4; round++) {
    for (let arrival = 0; arrival < 4; arrival++) await queueRetry(200 + round * 4 + arrival, 10 + round)
    const page = await fairness.listRetryIntentIds({ now: 100, targetIds: ['fair-relay'], limit: 12 })
    for (const intentId of page.intentIds) {
      if (oldIntentIds.has(intentId)) seenOld.add(intentId)
      const token = await fairness.claimTarget({
        intentId,
        targetId: 'fair-relay',
        state: 'delivering',
        expectedState: 'retryable',
        attemptToken: `consume:${round}:${intentId}`,
        leaseUntil: 201 + round,
        now: 200 + round
      })
      await fairness.failTarget({
        intentId,
        targetId: 'fair-relay',
        attemptToken: token,
        state: 'terminal',
        lastError: 'consumed',
        now: 200 + round
      })
    }
  }
  ok(seenOld.size === oldCount,
    'older due retries cannot be starved by a continuing stream of newly arrived due work')

  console.log('\n— memory scan indexes stay ordered and invalidate on writes —')
  const cachedState = createMemoryJournalState()
  const cached = createMemoryPeeritJournal({ shared: cachedState })
  await cached.ready()
  await cached.commitIntent(intent(500, { key: 'post!a', createdAt: 10 }))
  await cached.commitIntent(intent(502, { key: 'post!c', createdAt: 30 }))
  const beforeCacheWrite = await cached.rangeView({ limit: 10 })
  const beforeIntentWrite = await cached.listIntentIds({ limit: 10 })
  assert.deepEqual(beforeCacheWrite.map(row => row.key), ['post!a', 'post!c'])
  assert.deepEqual(beforeIntentWrite.intentIds, [id(500), id(502)])
  await cached.commitIntent(intent(501, { key: 'post!b', createdAt: 20 }))
  const afterCacheWrite = await cached.rangeView({ limit: 10 })
  const reverseCacheWrite = await cached.rangeView({ lt: 'post!d', reverse: true, limit: 10 })
  const afterIntentWrite = await cached.listIntentIds({ limit: 10 })
  ok(JSON.stringify(afterCacheWrite.map(row => row.key)) === JSON.stringify(['post!a', 'post!b', 'post!c']) &&
    JSON.stringify(reverseCacheWrite.map(row => row.key)) === JSON.stringify(['post!c', 'post!b', 'post!a']) &&
    JSON.stringify(afterIntentWrite.intentIds) === JSON.stringify([id(500), id(501), id(502)]),
  'cached forward, reverse, and compound-index scans invalidate without stale rows')

  console.log('\n— one-time legacy import is atomic and fail-closed —')
  const legacyKeys = await genKeyPair()
  const legacyDriveKey = 'd'.repeat(64)
  const legacyRecord = {
    id: legacyKeys.pubHex,
    author: legacyKeys.pubHex,
    name: 'migrated in browser',
    _k: legacyKeys.pubHex,
    _dk: legacyDriveKey,
    _ns: 'peerit',
    _alg: 'ed25519'
  }
  legacyRecord._sig = await sign(
    legacyKeys.seedHex,
    `pear.app.${legacyDriveKey}:peerit:` + canonical('profile', legacyRecord)
  )
  const legacyOperationBytes = stable({
    version: 1,
    operations: [{ type: 'profile', data: legacyRecord }]
  })
  const legacyIntentId = await hashHex('peerit.substrate.intent.v1|' + legacyOperationBytes)
  const legacyLogicalId = await hashHex('peerit.substrate.logical.v1|' + legacyOperationBytes)
  const legacyViewKey = `profile!${legacyKeys.pubHex}`
  const legacy = {
    version: 1,
    revision: 7,
    viewRevision: 3,
    view: { [legacyViewKey]: legacyRecord },
    intents: {
      [legacyIntentId]: {
        intentId: legacyIntentId,
        logicalId: legacyLogicalId,
        operationBytes: legacyOperationBytes,
        recordKeys: [legacyViewKey],
        createdAt: 5,
        updatedAt: 6,
        discoveryState: 'queued',
        targets: {
          'old-relay': {
            state: 'acknowledged',
            attempts: -1,
            attemptToken: 'old-attempt',
            updatedAt: -1,
            nextAttemptAt: 'not-a-time',
            evidenceRef: 'fabricated:receipt',
            readbackVerified: true,
            policyDurable: true
          }
        }
      }
    }
  }
  const legacyRaw = JSON.stringify(legacy)
  const legacyStorage = storage({ [LEGACY_SUBSTRATE_STATE_KEY]: legacyRaw })
  const importedState = createMemoryJournalState()
  const imported = createMemoryPeeritJournal({ shared: importedState, legacyStorage })
  const importResult = await imported.ready()
  const importedIntent = await imported.getIntent(legacyIntentId)
  ok(importResult.imported === true && legacyStorage.getItem(LEGACY_SUBSTRATE_STATE_KEY) == null &&
    (await imported.getView(legacyViewKey)).name === 'migrated in browser',
  'a cryptographically verified legacy reduction imports once and its source is removed only after success')
  const importedSummary = await imported.summary()
  ok(importedIntent.wireFormat === PEERIT_LEGACY_JSON_QUARANTINE_FORMAT_V1 &&
    importedIntent.legacyOperationBytes === legacyOperationBytes &&
    importedIntent.discoveryState === 'legacy-quarantined' &&
    importedIntent.targetCount === 0 && importedIntent.acknowledgedTargets === 0 &&
    importedIntent.policyDurable === false && importedIntent.pendingOrderKey == null &&
    Object.keys(importedIntent.targets).length === 0 &&
    importedSummary.pendingIntentCount === 0 && importedSummary.quarantinedIntentCount === 1 &&
    importedSummary.quarantinedIntentBytes === textEncoder.encode(legacyOperationBytes).byteLength &&
    !(await imported.listIntentIds({ limit: 10 })).intentIds.includes(legacyIntentId),
  'legacy raw bytes are retained only as quarantined local history, never as relay-deliverable work')
  const importedReload = createMemoryPeeritJournal({ shared: importedState, legacyStorage })
  await importedReload.ready()
  ok((await importedReload.summary()).intentCount === 1,
    'reload after migration cannot duplicate imported intents or view records')

  const storedV2State = createMemoryJournalState()
  const storedV2 = createMemoryPeeritJournal({ shared: storedV2State })
  const storedV2TargetId = 'retired-relay'
  storedV2.backend.corrupt(JOURNAL_STORES.META, 'state', {
    key: 'state',
    schemaVersion: 2,
    revision: 7,
    viewRevision: 3,
    viewRecordCount: 1,
    intentCount: 1,
    pendingIntentCount: 1,
    dedupeCount: 1,
    intentBytes: textEncoder.encode(legacyOperationBytes).byteLength,
    latestIntentId: legacyIntentId,
    latestCreatedAt: 5,
    targetStateCounts: {
      preparing: 0,
      delivering: 0,
      'pending-unknown': 1,
      retryable: 0,
      terminal: 0,
      acknowledged: 0,
      'readback-verified': 0
    },
    legacyImportHash: null,
    legacyImportSource: null,
    createdAt: 5,
    updatedAt: 6
  })
  storedV2.backend.corrupt(JOURNAL_STORES.VIEW, legacyViewKey, {
    key: legacyViewKey,
    value: legacyRecord,
    intentId: legacyIntentId,
    updatedAt: 6
  })
  storedV2.backend.corrupt(JOURNAL_STORES.INTENTS, legacyIntentId, {
    intentId: legacyIntentId,
    logicalId: legacyLogicalId,
    operationBytes: legacyOperationBytes,
    recordKeys: [legacyViewKey],
    createdAt: 5,
    updatedAt: 6,
    discoveryState: 'queued',
    targetCount: 1,
    acknowledgedTargets: 0,
    readbackVerified: 0,
    policyDurable: false,
    completedAt: 0,
    pendingOrderKey: `0000000000000005!${legacyIntentId}`
  })
  storedV2.backend.corrupt(JOURNAL_STORES.TARGETS, `${legacyIntentId}\u0000${storedV2TargetId}`, {
    key: `${legacyIntentId}\u0000${storedV2TargetId}`,
    intentId: legacyIntentId,
    targetId: storedV2TargetId,
    state: 'pending-unknown',
    attempts: 1,
    attemptToken: null,
    updatedAt: 6,
    nextAttemptAt: 6,
    leaseUntil: 0,
    lastError: 'old raw delivery',
    readbackVerified: false,
    policyDurable: false,
    evidenceRef: null
  })
  storedV2.backend.corrupt(JOURNAL_STORES.DEDUPE, legacyIntentId, {
    intentId: legacyIntentId,
    logicalId: legacyLogicalId,
    operationBytes: legacyOperationBytes,
    compactedAt: 6,
    expiresAt: 9_999
  })
  const v2Migrated = createMemoryPeeritJournal({ shared: storedV2State, clock: () => 1234 })
  await v2Migrated.ready()
  const v2MigratedIntent = await v2Migrated.getIntent(legacyIntentId)
  const v2MigratedSummary = await v2Migrated.summary()
  ok(v2MigratedIntent.wireFormat === PEERIT_LEGACY_JSON_QUARANTINE_FORMAT_V1 &&
    v2MigratedIntent.legacyOperationBytes === legacyOperationBytes &&
    v2MigratedIntent.quarantinedAt === 1234 && v2MigratedIntent.pendingOrderKey == null &&
    Object.keys(v2MigratedIntent.targets).length === 0 &&
    (await v2Migrated.getView(legacyViewKey)).name === 'migrated in browser' &&
    v2MigratedSummary.schemaVersion === 3 && v2MigratedSummary.intentCount === 1 &&
    v2MigratedSummary.pendingIntentCount === 0 && v2MigratedSummary.dedupeCount === 0 &&
    v2MigratedSummary.quarantinedIntentCount === 1 &&
    v2MigratedSummary.quarantinedIntentBytes === textEncoder.encode(legacyOperationBytes).byteLength &&
    (await v2Migrated.listIntentIds({ limit: 10 })).intentIds.length === 0 &&
    (await v2Migrated.listRetryIntentIds({ now: 1234, targetIds: [storedV2TargetId], reconcileTargetIds: [storedV2TargetId] })).intentIds.length === 0,
  'stored V2 raw work is atomically quarantined, while validated local view history remains readable')

  const forgedView = structuredClone(legacy)
  forgedView.view['profile!forged'] = { id: 'forged', author: legacyKeys.pubHex, name: 'unsigned injection' }
  const forgedViewRaw = JSON.stringify(forgedView)
  const forgedViewStorage = storage({ [LEGACY_SUBSTRATE_STATE_KEY]: forgedViewRaw })
  const forgedViewJournal = createMemoryPeeritJournal({ shared: createMemoryJournalState(), legacyStorage: forgedViewStorage })
  await assert.rejects(
    () => forgedViewJournal.ready(),
    error => error && error.code === 'PEERIT_JOURNAL_LEGACY_UNVERIFIED'
  )
  passed++
  ok(forgedViewStorage.getItem(LEGACY_SUBSTRATE_STATE_KEY) === forgedViewRaw &&
    (await forgedViewJournal.getView('profile!forged').catch(() => null)) == null,
  'a forged legacy view row fails closed, remains invisible, and preserves the source for explicit recovery')

  const forgedIds = structuredClone(legacy)
  const forgedId = id(999)
  forgedIds.intents[forgedId] = { ...forgedIds.intents[legacyIntentId], intentId: forgedId }
  delete forgedIds.intents[legacyIntentId]
  const forgedIdsRaw = JSON.stringify(forgedIds)
  const forgedIdsStorage = storage({ [LEGACY_SUBSTRATE_STATE_KEY]: forgedIdsRaw })
  const forgedIdsJournal = createMemoryPeeritJournal({ shared: createMemoryJournalState(), legacyStorage: forgedIdsStorage })
  await assert.rejects(
    () => forgedIdsJournal.ready(),
    error => error && error.code === 'PEERIT_JOURNAL_LEGACY_UNVERIFIED'
  )
  passed++
  ok(forgedIdsStorage.getItem(LEGACY_SUBSTRATE_STATE_KEY) === forgedIdsRaw,
    'fabricated legacy intent identifiers cannot relabel signed operation bytes or trigger source cleanup')

  const schemaState = createMemoryJournalState({ includeLegacyStore: true, schemaVersion: 1 })
  schemaState.stores.get('state').set('root', legacyRaw)
  const schemaImport = createMemoryPeeritJournal({ shared: schemaState })
  await schemaImport.ready()
  ok(schemaState.stores.get('state').get('root') == null && (await schemaImport.summary()).intentCount === 1,
    'legacy IndexedDB state records are cleared only after their atomic import is hash-pinned')

  const conflictStorage = storage({ [LEGACY_SUBSTRATE_STATE_KEY]: legacyRaw })
  const conflictState = createMemoryJournalState()
  const conflictJournal = createMemoryPeeritJournal({ shared: conflictState })
  await conflictJournal.ready()
  await conflictJournal.commitIntent(intent(61))
  const conflictingImport = createMemoryPeeritJournal({ shared: conflictState, legacyStorage: conflictStorage })
  await assert.rejects(() => conflictingImport.ready(), error => error && error.code === 'PEERIT_JOURNAL_LEGACY_CONFLICT')
  passed++
  ok(conflictStorage.getItem(LEGACY_SUBSTRATE_STATE_KEY) === legacyRaw && (await conflictJournal.summary()).intentCount === 1,
    'a conflicting migration preserves both the source and existing journal for explicit recovery')

  const brokenRaw = '{not-json'
  const brokenStorage = storage({ [LEGACY_SUBSTRATE_STATE_KEY]: brokenRaw })
  const broken = createMemoryPeeritJournal({ shared: createMemoryJournalState(), legacyStorage: brokenStorage })
  await assert.rejects(() => broken.ready(), error => error && error.code === 'PEERIT_JOURNAL_LEGACY_CORRUPT')
  passed++
  ok(brokenStorage.getItem(LEGACY_SUBSTRATE_STATE_KEY) === brokenRaw,
    'corrupt legacy bytes remain untouched and never trigger a silent empty-journal downgrade')

  console.log(`\n✅ all ${passed} adversarial Peerit journal checks passed`)
}

main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
