import assert from 'node:assert/strict'
import {
  BROWSER_SCALE_PROFILES,
  browserScaleEvidenceDigest,
  buildTargetUrl,
  classifyBrowserScaleReadiness,
  parseArgs,
  validatePageReport,
  verifyBrowserScaleEvidence
} from '../scripts/browser-peerit-scale-matrix.mjs'

const smoke = BROWSER_SCALE_PROFILES.smoke

assert.deepEqual(parseArgs([]), {
  engines: ['chromium', 'firefox', 'webkit'],
  profile: 'smoke',
  url: null,
  out: null,
  timeoutMs: null,
  help: false
})
assert.deepEqual(parseArgs(['--browser=webkit', '--profile', 'full', '--timeout-ms', '12345']).engines, ['webkit'])
assert.equal(parseArgs(['--browser=webkit', '--profile', 'full', '--timeout-ms', '12345']).profile, 'full')
assert.equal(parseArgs(['--browser=webkit', '--profile', 'full', '--timeout-ms', '12345']).timeoutMs, 12345)
assert.throws(() => parseArgs(['--browser', 'mobile']), /chromium, firefox, webkit, or all/)
assert.throws(() => parseArgs(['--profile', 'production']), /smoke or full/)
assert.throws(() => parseArgs(['--url', 'file:///tmp/gate.html']), /http or https/)
assert.throws(() => parseArgs(['--timeout-ms', '999']), /1000\.\.900000/)
assert.throws(() => parseArgs(['--mystery']), /unknown argument/)

const target = new URL(buildTargetUrl('http://127.0.0.1:8777/base', smoke, {
  profile: 'smoke',
  engine: 'firefox'
}))
assert.equal(target.pathname, '/base/journal-scale-browser-gate.html')
assert.equal(target.searchParams.get('intents'), '100')
assert.equal(target.searchParams.get('records'), '1000')
assert.equal(target.searchParams.get('communities'), '20')
assert.equal(target.searchParams.get('page'), '100')
assert.equal(target.searchParams.get('profile'), 'smoke')
assert.equal(target.searchParams.get('run'), 'smoke-firefox')

const fixture = {
  schema: 'peerit-browser-scale-gate-v1',
  evidenceClass: 'MEASURED_LOCAL_BROWSER_INDEXEDDB',
  claimBoundary: 'One local desktop browser build; not other engines, mobile, crash recovery, quota exhaustion, network, or mainnet evidence.',
  profile: 'smoke',
  operationShape: 'exact-generated-record-operations-v1',
  workload: {
    intents: smoke.intents,
    records: smoke.records,
    communities: smoke.communities,
    pageSize: smoke.pageSize
  },
  summary: {
    intents: smoke.intents,
    records: smoke.records,
    countedRecords: smoke.records,
    indexedRecords: smoke.records,
    reopenedIntents: smoke.intents,
    reopenedRecords: smoke.records,
    reopenedCountedRecords: smoke.records,
    reopenedScannedRecords: smoke.records,
    initialViewSha256: 'a'.repeat(64),
    reopenedViewSha256: 'a'.repeat(64),
    lastRecordRecovered: true
  },
  timing: {
    commit: { count: smoke.intents, p99Ms: 1 },
    rangePage: { count: Math.ceil(smoke.records / smoke.pageSize), p99Ms: 2 },
    indexWallMs: 3,
    longTask: { count: 0, maxMs: 4 }
  },
  gates: [
    'EXACT_COUNTS',
    'REOPEN_PERSISTENCE',
    'REOPEN_RECOUNT_DIGEST',
    'INDEX_REBUILD_COUNT',
    'COMMIT_P99',
    'RANGE_PAGE_P99',
    'INDEX_REBUILD_WALL',
    'LONG_TASK_OBSERVATION',
    'LONG_TASK_MAX'
  ].map(id => ({ id, passed: true })),
  blockers: [],
  localBrowserRunReady: true,
  localBrowserGateReady: false,
  releaseReady: false
}

const passed = validatePageReport({ report: fixture, workload: smoke, bodyStatus: 'passed' })
assert.equal(passed.passed, true)
assert.deepEqual(passed.blockers, [])

assert.deepEqual(classifyBrowserScaleReadiness({
  profile: 'smoke',
  requestedEngines: ['chromium', 'firefox', 'webkit'],
  passedEngines: ['chromium', 'firefox', 'webkit']
}), {
  selectedRunPassed: true,
  selectedBrowserGateReady: false,
  localDesktopMatrixReady: false,
  fullProfileEnginesPassed: []
}, 'a smoke run may pass diagnostics but cannot become desktop scale evidence')
assert.equal(classifyBrowserScaleReadiness({
  profile: 'full',
  requestedEngines: ['chromium', 'firefox', 'webkit'],
  passedEngines: ['chromium', 'firefox', 'webkit']
}).localDesktopMatrixReady, true)

const countMismatch = structuredClone(fixture)
countMismatch.summary.reopenedRecords--
const countFailure = validatePageReport({ report: countMismatch, workload: smoke, bodyStatus: 'passed' })
assert.equal(countFailure.passed, false)
assert.ok(countFailure.blockers.includes('EXACT_COUNTS'))

const slow = structuredClone(fixture)
slow.timing.commit.p99Ms = 50.01
const thresholdFailure = validatePageReport({ report: slow, workload: smoke, bodyStatus: 'passed' })
assert.equal(thresholdFailure.passed, false)
assert.ok(thresholdFailure.blockers.includes('THRESHOLDS_PASS'))

const pageFailure = validatePageReport({
  report: fixture,
  workload: smoke,
  bodyStatus: 'failed',
  diagnostics: {
    consoleErrors: ['console boom'],
    pageErrors: ['page boom'],
    requestFailures: ['GET module.js: failed'],
    httpErrors: ['500 module.js']
  }
})
assert.equal(pageFailure.passed, false)
assert.ok(pageFailure.blockers.includes('BODY_STATUS_PASSED'))
assert.ok(pageFailure.blockers.includes('NO_CONSOLE_ERRORS'))
assert.ok(pageFailure.blockers.includes('NO_PAGE_ERRORS'))
assert.ok(pageFailure.blockers.includes('NO_REQUEST_FAILURES'))
assert.ok(pageFailure.blockers.includes('NO_HTTP_ERRORS'))

const missingObserver = structuredClone(fixture)
missingObserver.gates.find(item => item.id === 'LONG_TASK_OBSERVATION').passed = false
const observerFailure = validatePageReport({ report: missingObserver, workload: smoke, bodyStatus: 'passed' })
assert.equal(observerFailure.passed, false)
assert.ok(observerFailure.blockers.includes('EXPECTED_PAGE_GATES_PASS'))

const inconsistentBlockers = structuredClone(fixture)
inconsistentBlockers.blockers.push('HIDDEN_FAILURE')
const blockerFailure = validatePageReport({ report: inconsistentBlockers, workload: smoke, bodyStatus: 'passed' })
assert.equal(blockerFailure.passed, false)
assert.ok(blockerFailure.blockers.includes('PAGE_BLOCKERS_EMPTY'))

const missingSamples = structuredClone(fixture)
missingSamples.timing.commit.count--
const sampleFailure = validatePageReport({ report: missingSamples, workload: smoke, bodyStatus: 'passed' })
assert.equal(sampleFailure.passed, false)
assert.ok(sampleFailure.blockers.includes('METRIC_SAMPLE_COUNTS'))

const evidenceBody = {
  schema: 'peerit-browser-scale-matrix-v1',
  evidenceClass: 'MEASURED_LOCAL_DESKTOP_BROWSER_INDEXEDDB_PLAYWRIGHT',
  evidenceDigestAlgorithm: 'sha256-canonical-json-v1',
  startedAt: '2026-07-12T00:00:00.000Z',
  results: [{ engine: 'chromium', status: 'passed', metrics: { records: 1000 } }],
  releaseReady: false
}
const sealedEvidence = { ...evidenceBody, evidenceDigest: browserScaleEvidenceDigest(evidenceBody) }
assert.equal(verifyBrowserScaleEvidence(sealedEvidence).verified, true)
assert.equal(verifyBrowserScaleEvidence(sealedEvidence).checksumVerified, true)
assert.equal(verifyBrowserScaleEvidence(sealedEvidence).verificationClass, 'CONTENT_CHECKSUM_ONLY')
assert.equal(verifyBrowserScaleEvidence(sealedEvidence).authentic, false)
assert.equal(verifyBrowserScaleEvidence(sealedEvidence).authorizesRelease, false)

const reorderedEvidence = {
  evidenceDigest: sealedEvidence.evidenceDigest,
  releaseReady: sealedEvidence.releaseReady,
  results: sealedEvidence.results,
  startedAt: sealedEvidence.startedAt,
  evidenceDigestAlgorithm: sealedEvidence.evidenceDigestAlgorithm,
  evidenceClass: sealedEvidence.evidenceClass,
  schema: sealedEvidence.schema
}
assert.equal(verifyBrowserScaleEvidence(reorderedEvidence).verified, true,
  'canonical hashing must not depend on object key insertion order')

const mutatedEvidence = structuredClone(sealedEvidence)
mutatedEvidence.results[0].metrics.records++
const mutationCheck = verifyBrowserScaleEvidence(mutatedEvidence)
assert.equal(mutationCheck.verified, false)
assert.ok(mutationCheck.blockers.includes('EVIDENCE_DIGEST_MISMATCH'))

const missingDigest = structuredClone(sealedEvidence)
delete missingDigest.evidenceDigest
assert.equal(verifyBrowserScaleEvidence(missingDigest).verified, false)
assert.ok(verifyBrowserScaleEvidence(missingDigest).blockers.includes('EVIDENCE_DIGEST_MISSING_OR_MALFORMED'))

assert.equal(fixture.releaseReady, false)
console.log('browser-peerit-scale-matrix: CLI, evidence boundary, counts, diagnostics, and threshold fail-closed checks passed')
