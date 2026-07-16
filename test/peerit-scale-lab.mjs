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
assert.equal(report.operationShape, 'peerit-unsigned-structural-operation-records-v2')
assert.equal(report.journalIntentShape, 'peerit-inner-operation-batch-v1-derived-journal-intent-v2')
assert.equal(report.workloadDefinition.schema, 'peerit-node-scale-workload-v2')
assert.equal(report.workloadDefinition.generator, 'sequential-vnext-journal-intents-round-robin-communities-v2')
assert.equal(report.workload.recordsPerIntent, 10)
assert.equal(report.journal.intentEnvelope.operationShape, report.operationShape)
assert.equal(report.journal.intentEnvelope.journalIntentShape, report.journalIntentShape)
assert.equal(report.journal.intentEnvelope.verifiedVnextEnvelopeCount, 80)
for (const boundary of [
  'firstGeneratedEnvelope',
  'lastGeneratedEnvelope',
  'firstBeforeReopen',
  'lastBeforeReopen',
  'firstAfterReopen',
  'lastAfterReopen'
]) {
  assert.equal(report.journal.intentEnvelope[boundary].verified, true)
  assert.equal(report.journal.intentEnvelope[boundary].codecBytesHex, '014e')
  assert.equal(report.journal.intentEnvelope[boundary].version, 1)
  assert.equal(report.journal.intentEnvelope[boundary].declaredPayloadLength,
    report.journal.intentEnvelope[boundary].payloadLength)
  assert.equal(report.journal.intentEnvelope[boundary].sizeClass,
    report.journal.intentEnvelope[boundary].smallestSizeClass)
}
assert.equal(report.gates.find(gate => gate.id === 'JOURNAL_VNEXT_INTENT_ENVELOPE').passed, true)
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
