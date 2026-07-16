#!/usr/bin/env node

// Measured local proof for Peerit's retry-target compound indexes. A logical
// monotonic clock moves completed selections behind untouched due work.
// This is a Node memory-backend result, never browser/IndexedDB or crash proof.

import { createHash } from 'node:crypto'
import { writeFile } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  JOURNAL_LIMITS,
  JOURNAL_STORES,
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import {
  PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2,
  PEERIT_LAB_OPERATION_SHAPE_V2,
  createStructuralPeeritVnextJournalIntent,
  inspectStructuralPeeritVnextJournalIntent,
  isStructuralPeeritVnextJournalInspectionEvidence
} from '../test/fixtures/peerit-vnext-journal-fixture.mjs'

export const RETRY_FAIRNESS_FULL_TARGETS = JOURNAL_LIMITS.maxIntents

const DEFAULTS = Object.freeze({
  targets: RETRY_FAIRNESS_FULL_TARGETS,
  batchSize: JOURNAL_LIMITS.deliveryBatch,
  maxElapsedMs: 30_000,
  out: '',
  assert: false
})

function positiveInteger (value, fallback, maximum) {
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= maximum ? parsed : fallback
}

function nonNegativeNumber (value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback
}

function parseArgs (argv) {
  const options = { ...DEFAULTS }
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    if (argument === '--targets') options.targets = positiveInteger(argv[++index], 0, RETRY_FAIRNESS_FULL_TARGETS)
    else if (argument === '--batch-size') options.batchSize = positiveInteger(argv[++index], 0, JOURNAL_LIMITS.deliveryBatch)
    else if (argument === '--max-elapsed-ms') options.maxElapsedMs = nonNegativeNumber(argv[++index], -1)
    else if (argument === '--out') options.out = String(argv[++index] || '')
    else if (argument === '--assert') options.assert = true
    else if (argument === '--help' || argument === '-h') {
      process.stdout.write('usage: node scripts/peerit-retry-fairness-lab.mjs [options]\n\n' +
        `  --targets <n>         eligible retry targets, max ${RETRY_FAIRNESS_FULL_TARGETS}\n` +
        `  --batch-size <n>      retry page size, max ${JOURNAL_LIMITS.deliveryBatch}\n` +
        '  --max-elapsed-ms <n>  local memory-backend wall-time ceiling\n' +
        '  --assert              exit nonzero when a local gate fails\n' +
        '  --out <file>          write JSON evidence\n')
      return null
    } else {
      throw new Error(`unknown option: ${argument}`)
    }
  }
  if (!options.targets || !options.batchSize || options.maxElapsedMs < 0) {
    throw new Error('retry-fairness counts must be positive and the elapsed ceiling must be non-negative')
  }
  return options
}

function fairnessFixture (targets) {
  const shared = createMemoryJournalState()
  const intents = shared.stores.get(JOURNAL_STORES.INTENTS)
  const targetRows = shared.stores.get(JOURNAL_STORES.TARGETS)
  const targetByIntent = new Map()
  const intentIds = []
  let intentBytes = 0
  let verifiedVnextEnvelopeCount = 0
  let firstGeneratedEnvelope = null
  let lastGeneratedEnvelope = null
  for (let index = 0; index < targets; index++) {
    const envelope = createStructuralPeeritVnextJournalIntent({
      operations: [{ type: 'post', data: { id: `retry!${index}`, index } }],
      createdAt: index + 1
    })
    const envelopeInspection = inspectStructuralPeeritVnextJournalIntent(envelope)
    if (envelopeInspection.verified) verifiedVnextEnvelopeCount++
    if (index === 0) firstGeneratedEnvelope = envelopeInspection
    lastGeneratedEnvelope = envelopeInspection
    const { intentId } = envelope
    const retryTarget = index % 2 === 0 ? 'retry-a' : 'retry-b'
    intentIds.push(intentId)
    targetByIntent.set(intentId, retryTarget)
    intents.set(intentId, {
      ...envelope,
      recordKeys: [],
      createdAt: index + 1,
      updatedAt: 1,
      discoveryState: 'queued',
      targetCount: 2,
      acknowledgedTargets: 1,
      readbackVerified: 0,
      policyDurable: false,
      completedAt: 1
    })
    targetRows.set(`${intentId}\u0000durable-a`, {
      key: `${intentId}\u0000durable-a`,
      intentId,
      targetId: 'durable-a',
      state: 'acknowledged',
      attempts: 1,
      attemptToken: `durable:${index}`,
      evidenceRef: `receipt:${index}`,
      updatedAt: 1,
      nextAttemptAt: 0,
      leaseUntil: 0,
      readbackVerified: false,
      policyDurable: false,
      lastError: null
    })
    targetRows.set(`${intentId}\u0000${retryTarget}`, {
      key: `${intentId}\u0000${retryTarget}`,
      intentId,
      targetId: retryTarget,
      state: 'pending-unknown',
      attempts: 1,
      attemptToken: `ambiguous:${index}`,
      evidenceRef: null,
      updatedAt: 1,
      nextAttemptAt: 1,
      leaseUntil: 0,
      readbackVerified: false,
      policyDurable: false,
      lastError: 'fairness-fixture'
    })
    intentBytes += envelope.innerLength
  }
  shared.stores.get(JOURNAL_STORES.META).set('state', {
    key: 'state',
    schemaVersion: 3,
    revision: 1,
    viewRevision: 0,
    viewRecordCount: 0,
    intentCount: targets,
    pendingIntentCount: 0,
    dedupeCount: 0,
    intentBytes,
    quarantinedIntentCount: 0,
    quarantinedIntentBytes: 0,
    latestIntentId: intentIds[intentIds.length - 1],
    latestCreatedAt: targets,
    targetStateCounts: {
      preparing: 0,
      delivering: 0,
      'pending-unknown': targets,
      retryable: 0,
      terminal: 0,
      acknowledged: targets,
      'readback-verified': 0
    },
    legacyImportHash: null,
    legacyImportSource: null,
    createdAt: 1,
    updatedAt: 1
  })
  shared.encodedBytes = null
  return {
    shared,
    targetByIntent,
    intentIds,
    envelopeEvidence: {
      verifiedVnextEnvelopeCount,
      firstGeneratedEnvelope,
      lastGeneratedEnvelope,
      firstStoredEnvelope: null,
      lastStoredEnvelope: null
    }
  }
}

function percentile (values, quantile) {
  if (!values.length) return 0
  const sorted = [...values].sort((left, right) => left - right)
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * quantile) - 1))]
}

function timing (values) {
  const total = values.reduce((sum, value) => sum + value, 0)
  return {
    count: values.length,
    meanMs: values.length ? total / values.length : 0,
    p50Ms: percentile(values, 0.5),
    p95Ms: percentile(values, 0.95),
    p99Ms: percentile(values, 0.99),
    maxMs: values.length ? Math.max(...values) : 0
  }
}

function errorText (error) {
  return String((error && (error.stack || error.message)) || error)
}

export function isRetryTargetIndex10kFairnessProven (report) {
  return !!(report &&
    report.schema === 'peerit-retry-fairness-lab-v1' &&
    report.evidenceClass === 'MEASURED_LOCAL_NODE_MEMORY_BACKEND' &&
    report.operationShape === PEERIT_LAB_OPERATION_SHAPE_V2 &&
    report.journalIntentShape === PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2 &&
    report.workloadDefinition && report.workloadDefinition.schema === 'peerit-retry-fairness-workload-v2' &&
    report.workloadDefinition.generator === 'direct-bounded-vnext-journal-state-alternating-pending-unknown-v2' &&
    report.workload && report.workload.targets === RETRY_FAIRNESS_FULL_TARGETS &&
    Number.isSafeInteger(report.workload.batchSize) && report.workload.batchSize > 0 &&
    report.workload.batchSize <= JOURNAL_LIMITS.deliveryBatch &&
    report.summary && report.summary.uniqueTargetsSeen === RETRY_FAIRNESS_FULL_TARGETS &&
    report.summary.claimsSucceeded === report.summary.selectedRows &&
    report.summary.selectedRows >= RETRY_FAIRNESS_FULL_TARGETS &&
    report.summary.selectedRows <= Math.ceil(RETRY_FAIRNESS_FULL_TARGETS / report.workload.batchSize) * report.workload.batchSize &&
    report.envelopeEvidence && report.envelopeEvidence.verifiedVnextEnvelopeCount === RETRY_FAIRNESS_FULL_TARGETS &&
    ['firstGeneratedEnvelope', 'lastGeneratedEnvelope', 'firstStoredEnvelope', 'lastStoredEnvelope']
      .every(key => isStructuralPeeritVnextJournalInspectionEvidence(report.envelopeEvidence[key])) &&
    report.localGateReady === true &&
    Array.isArray(report.gates) && report.gates.length > 0 && report.gates.every(gate => gate && gate.passed === true) &&
    Array.isArray(report.blockers) && report.blockers.length === 0)
}

export async function runPeeritRetryFairnessLab (rawOptions = {}) {
  const options = { ...DEFAULTS, ...rawOptions }
  if (!Number.isSafeInteger(options.targets) || options.targets < 1 || options.targets > RETRY_FAIRNESS_FULL_TARGETS) {
    throw new Error(`targets must be an integer in 1..${RETRY_FAIRNESS_FULL_TARGETS}`)
  }
  if (!Number.isSafeInteger(options.batchSize) || options.batchSize < 1 || options.batchSize > JOURNAL_LIMITS.deliveryBatch) {
    throw new Error(`batchSize must be an integer in 1..${JOURNAL_LIMITS.deliveryBatch}`)
  }
  if (!Number.isFinite(options.maxElapsedMs) || options.maxElapsedMs < 0) {
    throw new Error('maxElapsedMs must be a non-negative finite number')
  }

  let logicalClock = 1
  const workloadDefinition = {
    schema: 'peerit-retry-fairness-workload-v2',
    targets: options.targets,
    lanes: ['retry-a', 'retry-b'],
    batchSize: options.batchSize,
    clock: 'monotonic-logical-v1',
    operationShape: PEERIT_LAB_OPERATION_SHAPE_V2,
    journalIntentShape: PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2,
    generator: 'direct-bounded-vnext-journal-state-alternating-pending-unknown-v2'
  }
  const workloadSha256 = createHash('sha256').update(JSON.stringify(workloadDefinition)).digest('hex')
  const startedAt = performance.now()
  const memoryBefore = process.memoryUsage()
  let journal = null
  let fixture = null
  let fixtureBuildMs = 0
  let readyMs = 0
  let initialSummary = null
  let executionError = null
  const seen = new Set()
  const pageTimes = []
  const maximumRounds = Math.ceil(options.targets / options.batchSize) + 2
  let rounds = 0
  let selectedRows = 0
  let claimsSucceeded = 0
  let claimsFailed = 0
  let stateResetsSucceeded = 0
  let unknownIntentIds = 0
  let laneFairnessViolations = 0
  let fullPagesChecked = 0
  let truncatedPages = 0
  let mutationWallMs = 0
  let expiredClaimsRecovered = 0
  let expiredTargetState = null

  try {
    const fixtureStarted = performance.now()
    fixture = fairnessFixture(options.targets)
    fixtureBuildMs = performance.now() - fixtureStarted
    journal = createMemoryPeeritJournal({
      shared: fixture.shared,
      clock: () => logicalClock
    })
    const readyStarted = performance.now()
    await journal.ready()
    readyMs = performance.now() - readyStarted
    initialSummary = await journal.summary()
    fixture.envelopeEvidence.firstStoredEnvelope = inspectStructuralPeeritVnextJournalIntent(
      await journal.getIntent(fixture.intentIds[0])
    )
    fixture.envelopeEvidence.lastStoredEnvelope = inspectStructuralPeeritVnextJournalIntent(
      await journal.getIntent(fixture.intentIds[fixture.intentIds.length - 1])
    )

    while (seen.size < options.targets && rounds < maximumRounds) {
      rounds++
      const pageStarted = performance.now()
      const page = await journal.listRetryIntentIds({
        targetIds: ['retry-a', 'retry-b'],
        reconcileTargetIds: ['retry-a', 'retry-b'],
        now: logicalClock,
        limit: options.batchSize
      })
      pageTimes.push(performance.now() - pageStarted)
      if (page.truncated) truncatedPages++
      if (!page.intentIds.length) break
      const laneCounts = { 'retry-a': 0, 'retry-b': 0 }
      const mutationStarted = performance.now()
      for (const intentId of page.intentIds) {
        selectedRows++
        const targetId = fixture.targetByIntent.get(intentId)
        if (!targetId) {
          unknownIntentIds++
          continue
        }
        laneCounts[targetId]++
        seen.add(intentId)
        const claimAt = ++logicalClock
        const attemptToken = await journal.claimTarget({
          intentId,
          targetId,
          state: 'delivering',
          expectedState: 'pending-unknown',
          attemptToken: `reconcile:${rounds}:${intentId}`,
          leaseUntil: claimAt + 1,
          now: claimAt
        })
        if (!attemptToken) {
          claimsFailed++
          continue
        }
        claimsSucceeded++
        const reset = await journal.failTarget({
          intentId,
          targetId,
          attemptToken,
          state: 'pending-unknown',
          lastError: 'still-ambiguous',
          now: ++logicalClock,
          nextAttemptAt: 1
        })
        if (reset) stateResetsSucceeded++
      }
      mutationWallMs += performance.now() - mutationStarted
      if (page.intentIds.length === options.batchSize && seen.size < options.targets) {
        fullPagesChecked++
        if (laneCounts['retry-a'] === 0 || laneCounts['retry-b'] === 0) laneFairnessViolations++
      }
    }

    const finalIntentId = fixture.intentIds[fixture.intentIds.length - 1]
    const finalTargetId = fixture.targetByIntent.get(finalIntentId)
    const finalClaimAt = ++logicalClock
    const finalToken = await journal.claimTarget({
      intentId: finalIntentId,
      targetId: finalTargetId,
      state: 'delivering',
      expectedState: 'pending-unknown',
      attemptToken: 'expired-active-claim',
      leaseUntil: finalClaimAt + 1,
      now: finalClaimAt
    })
    if (finalToken) expiredClaimsRecovered = await journal.recoverExpiredClaims(finalClaimAt + 1)
    const finalIntent = await journal.getIntent(finalIntentId)
    expiredTargetState = finalIntent && finalIntent.targets[finalTargetId] && finalIntent.targets[finalTargetId].state
  } catch (error) {
    executionError = errorText(error)
  } finally {
    if (journal) await journal.close().catch(() => {})
  }

  const elapsedMs = performance.now() - startedAt
  const memoryAfter = process.memoryUsage()
  const gates = [
    { id: 'HARNESS_EXECUTION', passed: executionError == null, observed: executionError },
    {
      id: 'FIXTURE_INTENT_COUNT_EXACT',
      passed: initialSummary != null && initialSummary.intentCount === options.targets,
      observed: initialSummary && initialSummary.intentCount,
      expected: options.targets
    },
    {
      id: 'VNEXT_INTENT_ENVELOPES_EXACT',
      passed: fixture != null &&
        fixture.envelopeEvidence.verifiedVnextEnvelopeCount === options.targets &&
        ['firstGeneratedEnvelope', 'lastGeneratedEnvelope', 'firstStoredEnvelope', 'lastStoredEnvelope']
          .every(key => isStructuralPeeritVnextJournalInspectionEvidence(fixture.envelopeEvidence[key])),
      observed: fixture && {
        verifiedVnextEnvelopeCount: fixture.envelopeEvidence.verifiedVnextEnvelopeCount,
        firstGeneratedVerified: fixture.envelopeEvidence.firstGeneratedEnvelope?.verified === true,
        lastGeneratedVerified: fixture.envelopeEvidence.lastGeneratedEnvelope?.verified === true,
        firstStoredVerified: fixture.envelopeEvidence.firstStoredEnvelope?.verified === true,
        lastStoredVerified: fixture.envelopeEvidence.lastStoredEnvelope?.verified === true
      },
      expected: { verifiedVnextEnvelopeCount: options.targets, allBoundaryEnvelopesVerified: true }
    },
    {
      id: 'COMPLETED_INTENT_COUNT_EXACT',
      passed: initialSummary != null && initialSummary.pendingIntentCount === 0,
      observed: initialSummary && initialSummary.pendingIntentCount,
      expected: 0
    },
    {
      id: 'RETRY_TARGET_COVERAGE_EXACT',
      passed: seen.size === options.targets,
      observed: seen.size,
      expected: options.targets
    },
    {
      id: 'RETRY_TARGET_CLAIMS_EXACT',
      passed: claimsSucceeded === selectedRows && claimsFailed === 0 && stateResetsSucceeded === selectedRows && unknownIntentIds === 0 &&
        selectedRows >= options.targets && selectedRows <= Math.ceil(options.targets / options.batchSize) * options.batchSize,
      observed: { claimsSucceeded, claimsFailed, stateResetsSucceeded, unknownIntentIds },
      expected: {
        uniqueTargets: options.targets,
        maximumPageGranularitySelections: Math.ceil(options.targets / options.batchSize) * options.batchSize
      }
    },
    {
      id: 'RETRY_BATCH_CONVERGENCE',
      passed: rounds <= maximumRounds && seen.size === options.targets,
      observed: rounds,
      ceiling: maximumRounds
    },
    {
      id: 'RETRY_LANE_FAIRNESS',
      passed: laneFairnessViolations === 0,
      observed: { fullPagesChecked, laneFairnessViolations }
    },
    {
      id: 'RETRY_TRUNCATION_SIGNAL',
      passed: options.targets <= options.batchSize || truncatedPages > 0,
      observed: truncatedPages
    },
    {
      id: 'EXPIRED_ACTIVE_CLAIM_RECOVERY',
      passed: expiredClaimsRecovered >= 1 && expiredTargetState === 'pending-unknown',
      observed: { expiredClaimsRecovered, expiredTargetState }
    },
    {
      id: 'LOCAL_MEMORY_WALL_TIME',
      passed: elapsedMs <= options.maxElapsedMs,
      observedMs: elapsedMs,
      ceilingMs: options.maxElapsedMs
    }
  ]
  const blockers = gates.filter(gate => !gate.passed).map(gate => gate.id)
  const report = {
    schema: 'peerit-retry-fairness-lab-v1',
    evidenceClass: 'MEASURED_LOCAL_NODE_MEMORY_BACKEND',
    operationShape: PEERIT_LAB_OPERATION_SHAPE_V2,
    journalIntentShape: PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2,
    claimBoundary: 'Local Node memory-backend compound-index evidence only; not browser/IndexedDB, disk, crash, multi-process, network, or production evidence.',
    environment: {
      runtime: 'node',
      node: process.version,
      platform: process.platform,
      arch: process.arch
    },
    workloadDefinition,
    workloadSha256,
    workload: {
      targets: options.targets,
      batchSize: options.batchSize,
      maximumRounds,
      maxElapsedMs: options.maxElapsedMs
    },
    envelopeEvidence: fixture?.envelopeEvidence ?? {
      verifiedVnextEnvelopeCount: 0,
      firstGeneratedEnvelope: null,
      lastGeneratedEnvelope: null,
      firstStoredEnvelope: null,
      lastStoredEnvelope: null
    },
    summary: {
      uniqueTargetsSeen: seen.size,
      selectedRows,
      claimsSucceeded,
      claimsFailed,
      stateResetsSucceeded,
      unknownIntentIds,
      rounds,
      fullPagesChecked,
      truncatedPages,
      laneFairnessViolations,
      expiredClaimsRecovered,
      expiredTargetState
    },
    timing: {
      fixtureBuildMs,
      readyMs,
      retryPage: timing(pageTimes),
      mutationWallMs,
      elapsedMs
    },
    memory: {
      rssBeforeBytes: memoryBefore.rss,
      rssAfterBytes: memoryAfter.rss,
      rssDeltaBytes: memoryAfter.rss - memoryBefore.rss,
      heapUsedBeforeBytes: memoryBefore.heapUsed,
      heapUsedAfterBytes: memoryAfter.heapUsed,
      heapUsedDeltaBytes: memoryAfter.heapUsed - memoryBefore.heapUsed
    },
    gates,
    blockers,
    localGateReady: blockers.length === 0,
    fullCeilingReady: false,
    releaseReady: false,
    releaseBlockers: []
  }
  report.fullCeilingReady = isRetryTargetIndex10kFairnessProven(report)
  report.releaseBlockers = [
    ...(report.fullCeilingReady ? [] : ['RETRY_TARGET_INDEX_10K_FAIRNESS_UNPROVEN']),
    'BROWSER_INDEXEDDB_RETRY_FAIRNESS_UNRUN',
    'BROWSER_CRASH_RETRY_RECOVERY_UNRUN'
  ]
  return report
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (!options) return
  const report = await runPeeritRetryFairnessLab(options)
  const encoded = JSON.stringify(report, null, 2) + '\n'
  if (options.out) await writeFile(resolve(options.out), encoded)
  process.stdout.write(encoded)
  if (options.assert && !report.localGateReady) process.exitCode = 1
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : ''
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error)
    process.exitCode = 1
  })
}
