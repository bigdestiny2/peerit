import assert from 'node:assert/strict'
import {
  RETRY_FAIRNESS_FULL_TARGETS,
  isRetryTargetIndex10kFairnessProven,
  runPeeritRetryFairnessLab
} from '../scripts/peerit-retry-fairness-lab.mjs'

const report = await runPeeritRetryFairnessLab()

assert.equal(report.schema, 'peerit-retry-fairness-lab-v1')
assert.equal(report.evidenceClass, 'MEASURED_LOCAL_NODE_MEMORY_BACKEND')
assert.match(report.claimBoundary, /not browser\/IndexedDB, disk, crash, multi-process, network, or production/i)
assert.equal(report.workload.targets, RETRY_FAIRNESS_FULL_TARGETS)
assert.equal(report.workload.batchSize, 256)
assert.equal(report.summary.uniqueTargetsSeen, RETRY_FAIRNESS_FULL_TARGETS)
assert.equal(report.summary.claimsSucceeded, report.summary.selectedRows)
assert.ok(report.summary.selectedRows >= RETRY_FAIRNESS_FULL_TARGETS)
assert.ok(report.summary.selectedRows <= Math.ceil(RETRY_FAIRNESS_FULL_TARGETS / report.workload.batchSize) * report.workload.batchSize)
assert.equal(report.summary.claimsFailed, 0)
assert.equal(report.summary.stateResetsSucceeded, report.summary.selectedRows)
assert.equal(report.summary.unknownIntentIds, 0)
assert.equal(report.summary.laneFairnessViolations, 0)
assert.ok(report.summary.fullPagesChecked > 0)
assert.ok(report.summary.truncatedPages > 0)
assert.ok(report.summary.expiredClaimsRecovered >= 1)
assert.equal(report.summary.expiredTargetState, 'pending-unknown')
assert.equal(report.timing.retryPage.count, report.summary.rounds)
assert.equal(report.localGateReady, true)
assert.equal(report.fullCeilingReady, true)
assert.equal(report.releaseReady, false)
assert.deepEqual(report.blockers, [])
assert.equal(report.releaseBlockers.includes('RETRY_TARGET_INDEX_10K_FAIRNESS_UNPROVEN'), false)
assert.equal(isRetryTargetIndex10kFairnessProven(report), true)

const undersized = structuredClone(report)
undersized.workload.targets--
assert.equal(isRetryTargetIndex10kFairnessProven(undersized), false,
  'a sub-ceiling result cannot clear the 10k release blocker')

console.log(`peerit-retry-fairness: ${report.summary.uniqueTargetsSeen} targets, ${report.summary.rounds} pages, ${report.timing.elapsedMs.toFixed(1)}ms`)
