import assert from 'node:assert/strict'
import { runPeeritScaleLab } from '../scripts/peerit-scale-lab.mjs'

const report = await runPeeritScaleLab({
  intents: 80,
  viewRecords: 800,
  communities: 20,
  pageSize: 31,
  maxCommitP99Ms: 1_000,
  maxIndexBuildMsPer100k: 60_000,
  maxFeedReadP99Ms: 1_000,
  maxViewPageP99Ms: 1_000,
  maxRssDeltaMiB: 1_024
})

assert.equal(report.schema, 'peerit-scale-lab-v1')
assert.equal(report.evidenceClass, 'MEASURED_LOCAL_NODE_MEMORY_BACKEND')
assert.equal(report.workload.recordsPerIntent, 10)
assert.equal(report.journal.summary.intentCount, 80)
assert.equal(report.journal.summary.viewRecordCount, 800)
assert.equal(report.journal.scannedIntentIds, 80)
assert.equal(report.journal.rangedViewRecords, 800)
assert.equal(report.materializedIndex.records, 800)
assert.equal(report.materializedIndex.totalFeedRows, 800)
assert.equal(report.retryFairness.evidenceClass, 'MEASURED_LOCAL_NODE_MEMORY_BACKEND')
assert.equal(report.retryFairness.workload.targets, 80)
assert.equal(report.retryFairness.summary.uniqueTargetsSeen, 80)
assert.equal(report.retryFairness.localGateReady, true)
assert.equal(report.retryFairness.fullCeilingReady, false)
assert.equal(report.localGateReady, true)
assert.equal(report.releaseReady, false)
assert.deepEqual(report.blockers, [])
assert.ok(report.releaseBlockers.includes('BROWSER_INDEXEDDB_SCALE_EVIDENCE_UNRUN'))
assert.ok(report.releaseBlockers.includes('RETRY_TARGET_INDEX_10K_FAIRNESS_UNPROVEN'))
assert.match(report.claimBoundary, /Not browser\/IndexedDB/)
assert.ok(report.requiredNextEvidence.some(item => /hung\/ambiguous-target/.test(item)))

console.log('peerit-scale-lab: bounded journal/index evidence and claim boundary passed')
