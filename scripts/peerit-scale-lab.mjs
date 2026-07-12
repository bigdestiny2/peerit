#!/usr/bin/env node

// Measured local scale laboratory for Peerit's replacement runtime.
//
// This intentionally does not pretend that a Node memory-backend result is a
// browser/IndexedDB result. It exercises the same journal and materialized-index
// logic, records the environment and workload, and emits blockers instead of
// converting synthetic timings into production claims.

import { createHash } from 'node:crypto'
import { writeFile } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MaterializedIndex } from '../js/materialized-index.js'
import {
  JOURNAL_LIMITS,
  createMemoryPeeritJournal,
  createMemoryJournalState
} from '../js/substrate/peerit-journal.js'
import {
  isRetryTargetIndex10kFairnessProven,
  runPeeritRetryFairnessLab
} from './peerit-retry-fairness-lab.mjs'

const DEFAULTS = Object.freeze({
  intents: 500,
  viewRecords: 5_000,
  communities: 50,
  pageSize: 256,
  maxCommitP99Ms: 25,
  maxIndexBuildMsPer100k: 4_000,
  maxFeedReadP99Ms: 50,
  maxViewPageP99Ms: 250,
  maxRssDeltaMiB: 768,
  maxRetryFairnessElapsedMs: 30_000,
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
    const arg = argv[index]
    if (arg === '--intents') options.intents = positiveInteger(argv[++index], 0, JOURNAL_LIMITS.maxIntents)
    else if (arg === '--view-records') options.viewRecords = positiveInteger(argv[++index], 0, JOURNAL_LIMITS.maxViewRecords)
    else if (arg === '--communities') options.communities = positiveInteger(argv[++index], 0, 10_000)
    else if (arg === '--page-size') options.pageSize = positiveInteger(argv[++index], 0, JOURNAL_LIMITS.deliveryBatch)
    else if (arg === '--max-commit-p99-ms') options.maxCommitP99Ms = nonNegativeNumber(argv[++index], -1)
    else if (arg === '--max-index-build-ms-per-100k') options.maxIndexBuildMsPer100k = nonNegativeNumber(argv[++index], -1)
    else if (arg === '--max-feed-read-p99-ms') options.maxFeedReadP99Ms = nonNegativeNumber(argv[++index], -1)
    else if (arg === '--max-view-page-p99-ms') options.maxViewPageP99Ms = nonNegativeNumber(argv[++index], -1)
    else if (arg === '--max-rss-delta-mib') options.maxRssDeltaMiB = nonNegativeNumber(argv[++index], -1)
    else if (arg === '--max-retry-fairness-elapsed-ms') options.maxRetryFairnessElapsedMs = nonNegativeNumber(argv[++index], -1)
    else if (arg === '--out') options.out = String(argv[++index] || '')
    else if (arg === '--assert') options.assert = true
    else if (arg === '--full') {
      options.intents = JOURNAL_LIMITS.maxIntents
      options.viewRecords = JOURNAL_LIMITS.maxViewRecords
      options.communities = 1_000
    } else if (arg === '--help' || arg === '-h') {
      process.stdout.write('usage: node scripts/peerit-scale-lab.mjs [options]\n\n' +
        `  --intents <n>                     active intents, max ${JOURNAL_LIMITS.maxIntents}\n` +
        `  --view-records <n>                local records, max ${JOURNAL_LIMITS.maxViewRecords}\n` +
        '  --communities <n>                 feed partitions\n' +
        `  --page-size <n>                   pending-intent page, max ${JOURNAL_LIMITS.deliveryBatch}\n` +
        '  --max-commit-p99-ms <n>           measured release ceiling\n' +
        '  --max-index-build-ms-per-100k <n> measured release ceiling\n' +
        '  --max-feed-read-p99-ms <n>        measured release ceiling\n' +
        '  --max-view-page-p99-ms <n>        memory-backend page ceiling\n' +
        '  --max-rss-delta-mib <n>           memory-backend RSS ceiling\n' +
        '  --max-retry-fairness-elapsed-ms <n> retry-index wall-time ceiling\n' +
        '  --full                            10k intents / 100k records\n' +
        '  --assert                          exit nonzero when a release gate fails\n' +
        '  --out <file>                      write JSON evidence\n')
      return null
    } else {
      throw new Error(`unknown option: ${arg}`)
    }
  }
  if (!options.intents || !options.viewRecords || !options.communities || !options.pageSize ||
    options.maxCommitP99Ms < 0 || options.maxIndexBuildMsPer100k < 0 || options.maxFeedReadP99Ms < 0 ||
    options.maxViewPageP99Ms < 0 || options.maxRssDeltaMiB < 0 || options.maxRetryFairnessElapsedMs < 0) {
    throw new Error('scale-lab counts must be positive and latency ceilings must be non-negative')
  }
  const recordsPerIntent = Math.ceil(options.viewRecords / options.intents)
  if (recordsPerIntent > JOURNAL_LIMITS.maxRecordsPerIntent) {
    throw new Error(`workload needs ${recordsPerIntent} records per intent; journal maximum is ${JOURNAL_LIMITS.maxRecordsPerIntent}`)
  }
  return options
}

function deterministicId (domain, value) {
  return createHash('sha256').update(`${domain}:${value}`).digest('hex')
}

function percentile (values, quantile) {
  if (!values.length) return 0
  const sorted = [...values].sort((left, right) => left - right)
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * quantile) - 1))]
}

function timingSummary (values) {
  const sum = values.reduce((total, value) => total + value, 0)
  return Object.freeze({
    count: values.length,
    meanMs: values.length ? sum / values.length : 0,
    p50Ms: percentile(values, 0.5),
    p95Ms: percentile(values, 0.95),
    p99Ms: percentile(values, 0.99),
    maxMs: values.length ? Math.max(...values) : 0
  })
}

async function timed (operation) {
  const started = performance.now()
  const value = await operation()
  return { value, elapsedMs: performance.now() - started }
}

function recordFor (index, communities) {
  const community = `c-${index % communities}`
  const cid = deterministicId('record', index)
  const author = deterministicId('author', index % 1_000)
  return {
    key: `post!${community}!${cid}`,
    value: {
      cid,
      community,
      author,
      title: `synthetic post ${index}`,
      createdAt: index
    }
  }
}

async function exerciseJournal (options) {
  const shared = createMemoryJournalState()
  let now = 1_800_000_000_000
  const journal = createMemoryPeeritJournal({ shared, clock: () => now++ })
  const recordsPerIntent = Math.ceil(options.viewRecords / options.intents)
  const commitTimes = []
  let recordIndex = 0
  for (let intentIndex = 0; intentIndex < options.intents; intentIndex++) {
    const records = []
    while (records.length < recordsPerIntent && recordIndex < options.viewRecords) {
      records.push(recordFor(recordIndex++, options.communities))
    }
    const intentId = deterministicId('intent', intentIndex)
    const operationBytes = JSON.stringify({
      version: 1,
      operations: [{ type: 'synthetic-scale-records', first: intentIndex * recordsPerIntent, count: records.length }]
    })
    const result = await timed(() => journal.commitIntent({
      intentId,
      logicalId: deterministicId('logical', intentIndex),
      operationBytes,
      records,
      createdAt: intentIndex + 1
    }))
    commitTimes.push(result.elapsedMs)
  }

  const scanTimes = []
  let cursor = null
  let scanned = 0
  do {
    const result = await timed(() => journal.listIntentIds({ after: cursor, limit: options.pageSize }))
    scanTimes.push(result.elapsedMs)
    scanned += result.value.intentIds.length
    cursor = result.value.hasMore ? result.value.cursor : null
  } while (cursor)

  const rangeTimes = []
  let ranged = 0
  let after = null
  do {
    const query = { limit: 1_000 }
    if (after) query.gt = after
    const result = await timed(() => journal.rangeView(query))
    rangeTimes.push(result.elapsedMs)
    if (!result.value.length) break
    ranged += result.value.length
    after = result.value[result.value.length - 1].key
  } while (ranged < options.viewRecords)

  const summary = await journal.summary()
  const wake = await journal.nextWake({
    now,
    reconcileTargetIds: [],
    retryBaseMs: 1_000,
    retryMaxMs: 60_000
  })
  await journal.close()
  return {
    backend: 'deterministic-node-memory',
    writeTransactions: shared.writeTransactions,
    summary,
    scannedIntentIds: scanned,
    rangedViewRecords: ranged,
    nextWakeWithoutTargets: wake,
    commit: timingSummary(commitTimes),
    pendingIndexPage: timingSummary(scanTimes),
    viewRangePage: timingSummary(rangeTimes)
  }
}

function exerciseMaterializedIndex (options) {
  const index = new MaterializedIndex()
  const started = performance.now()
  for (let recordIndex = 0; recordIndex < options.viewRecords; recordIndex++) {
    const record = recordFor(recordIndex, options.communities)
    index.upsert(record.key, record.value)
  }
  const buildMs = performance.now() - started
  const feedTimes = []
  let totalFeedRows = 0
  for (let communityIndex = 0; communityIndex < options.communities; communityIndex++) {
    const feedStarted = performance.now()
    const feed = index.listPostsIn(`c-${communityIndex}`)
    feedTimes.push(performance.now() - feedStarted)
    totalFeedRows += feed.length
  }
  return {
    records: index.records.size,
    totalFeedRows,
    buildMs,
    projectedBuildMsPer100k: buildMs * (100_000 / options.viewRecords),
    feedRead: timingSummary(feedTimes)
  }
}

function localGates (options, journal, index, retryFairness, memory) {
  const checks = [
    {
      id: 'JOURNAL_COUNT_EXACT',
      passed: journal.summary.intentCount === options.intents &&
        journal.summary.viewRecordCount === options.viewRecords &&
        journal.scannedIntentIds === options.intents &&
        journal.rangedViewRecords === options.viewRecords,
      observed: {
        intents: journal.summary.intentCount,
        viewRecords: journal.summary.viewRecordCount,
        scannedIntentIds: journal.scannedIntentIds,
        rangedViewRecords: journal.rangedViewRecords
      }
    },
    {
      id: 'INDEX_COUNT_EXACT',
      passed: index.records === options.viewRecords && index.totalFeedRows === options.viewRecords,
      observed: { records: index.records, totalFeedRows: index.totalFeedRows }
    },
    {
      id: 'JOURNAL_COMMIT_P99',
      passed: journal.commit.p99Ms <= options.maxCommitP99Ms,
      ceilingMs: options.maxCommitP99Ms,
      observedMs: journal.commit.p99Ms
    },
    {
      id: 'INDEX_BUILD_PROJECTED_100K',
      passed: index.projectedBuildMsPer100k <= options.maxIndexBuildMsPer100k,
      ceilingMs: options.maxIndexBuildMsPer100k,
      observedMs: index.projectedBuildMsPer100k
    },
    {
      id: 'FEED_READ_P99',
      passed: index.feedRead.p99Ms <= options.maxFeedReadP99Ms,
      ceilingMs: options.maxFeedReadP99Ms,
      observedMs: index.feedRead.p99Ms
    },
    {
      id: 'JOURNAL_VIEW_RANGE_PAGE_P99',
      passed: journal.viewRangePage.p99Ms <= options.maxViewPageP99Ms,
      ceilingMs: options.maxViewPageP99Ms,
      observedMs: journal.viewRangePage.p99Ms
    },
    {
      id: 'RETRY_TARGET_INDEX_LOCAL_FAIRNESS',
      passed: retryFairness.localGateReady === true,
      observed: {
        targets: retryFairness.workload.targets,
        uniqueTargetsSeen: retryFairness.summary.uniqueTargetsSeen,
        rounds: retryFairness.summary.rounds,
        elapsedMs: retryFairness.timing.elapsedMs,
        blockers: retryFairness.blockers
      }
    },
    {
      id: 'NODE_MEMORY_RSS_DELTA',
      passed: memory.rssDeltaBytes <= options.maxRssDeltaMiB * 1024 * 1024,
      ceilingMiB: options.maxRssDeltaMiB,
      observedMiB: memory.rssDeltaBytes / (1024 * 1024)
    }
  ]
  return checks
}

export async function runPeeritScaleLab (rawOptions = {}) {
  const options = { ...DEFAULTS, ...rawOptions }
  const before = process.memoryUsage()
  const journal = await exerciseJournal(options)
  const index = exerciseMaterializedIndex(options)
  const retryFairness = await runPeeritRetryFairnessLab({
    targets: options.intents,
    batchSize: JOURNAL_LIMITS.deliveryBatch,
    maxElapsedMs: options.maxRetryFairnessElapsedMs
  })
  const after = process.memoryUsage()
  const memory = {
    rssBeforeBytes: before.rss,
    rssAfterBytes: after.rss,
    rssDeltaBytes: after.rss - before.rss,
    heapUsedBeforeBytes: before.heapUsed,
    heapUsedAfterBytes: after.heapUsed,
    heapUsedDeltaBytes: after.heapUsed - before.heapUsed
  }
  const gates = localGates(options, journal, index, retryFairness, memory)
  const blockers = gates.filter(gate => !gate.passed).map(gate => gate.id)
  const retryFairness10kProven = isRetryTargetIndex10kFairnessProven(retryFairness)
  const requiredNextEvidence = [
    'Chromium, Firefox, and WebKit IndexedDB run at 10k intents and 100k records',
    'verified browser relay adapters repeat bounded hung/ambiguous-target delivery',
    ...(retryFairness10kProven ? [] : ['10,000 eligible retry targets rotate fairly beyond every 256-row scan window']),
    'mobile memory/long-task/render/pagination measurements',
    'crash/reload/quota-pressure evidence on persistent browser storage'
  ]
  const releaseBlockers = [
    ...blockers,
    'BROWSER_INDEXEDDB_SCALE_EVIDENCE_UNRUN',
    'CROSS_BROWSER_RELAY_DELIVERY_SCALE_EVIDENCE_UNRUN',
    ...(retryFairness10kProven ? [] : ['RETRY_TARGET_INDEX_10K_FAIRNESS_UNPROVEN']),
    'MOBILE_RENDER_SCALE_EVIDENCE_UNRUN',
    'BROWSER_PERSISTENCE_CRASH_MATRIX_UNRUN'
  ]
  return {
    schema: 'peerit-scale-lab-v1',
    evidenceClass: 'MEASURED_LOCAL_NODE_MEMORY_BACKEND',
    claimBoundary: 'Not browser/IndexedDB, network, disk, multi-process, or production capacity evidence.',
    environment: {
      runtime: 'node',
      node: process.version,
      platform: process.platform,
      arch: process.arch
    },
    workload: {
      intents: options.intents,
      viewRecords: options.viewRecords,
      communities: options.communities,
      pageSize: options.pageSize,
      recordsPerIntent: Math.ceil(options.viewRecords / options.intents),
      retryTargets: retryFairness.workload.targets
    },
    journal,
    materializedIndex: index,
    retryFairness,
    memory,
    gates,
    blockers,
    localGateReady: blockers.length === 0,
    releaseBlockers,
    releaseReady: false,
    requiredNextEvidence
  }
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (!options) return
  const report = await runPeeritScaleLab(options)
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
