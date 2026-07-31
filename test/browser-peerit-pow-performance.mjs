import assert from 'node:assert/strict'
import { MIN_BITS, POW_VERSION } from '../js/pow-current.js'
import {
  LOCAL_POW_SOURCE_SHA256,
  POW_ACTIONS,
  POW_BENCHMARK_BITS,
  POW_CLAIM_BOUNDARY,
  POW_DESKTOP_ENGINES,
  POW_EVIDENCE_GAPS_BASE,
  POW_PROGRESS_GRANULARITY,
  POW_REPORT_SCHEMA,
  browserPowEvidenceDigest,
  buildPowLatencyModel,
  buildPowRateDispersion,
  geometricQuantileAttempts,
  parseArgs,
  sealBrowserPowEvidence,
  verifyBrowserPowEvidence
} from '../scripts/browser-peerit-pow-performance.mjs'
import { parseArgs as parseVerifierArgs } from '../scripts/verify-browser-peerit-pow-report.mjs'

assert.deepEqual(parseArgs([]), {
  engines: ['chromium', 'firefox', 'webkit'],
  warmupHashes: 4096,
  sampleHashes: 16_384,
  samplesPerAction: 6,
  sampleTimeoutMs: 30_000,
  requireAll: false,
  out: null,
  help: false
})
assert.deepEqual(parseArgs([
  '--browser=firefox',
  '--warmup-hashes', '2048',
  '--sample-hashes=8192',
  '--samples', '5',
  '--timeout-ms', '12000',
  '--require-all',
  '--out', '/tmp/pow.json'
]), {
  engines: ['firefox'],
  warmupHashes: 2048,
  sampleHashes: 8192,
  samplesPerAction: 5,
  sampleTimeoutMs: 12_000,
  requireAll: true,
  out: '/tmp/pow.json',
  help: false
})
assert.throws(() => parseArgs(['--browser', 'mobile']), /chromium, firefox, webkit, or all/)
assert.throws(() => parseArgs(['--sample-hashes', '2049']), /multiple of 1024/)
assert.throws(() => parseArgs(['--warmup-hashes', '0']), /1024\.\.1048576/)
assert.throws(() => parseArgs(['--samples', '26']), /1\.\.25/)
assert.throws(() => parseArgs(['--timeout-ms', '999']), /1000\.\.120000/)
assert.throws(() => parseArgs(['--threshold-ms', '10']), /unknown argument/)
assert.deepEqual(parseVerifierArgs(['--in=/tmp/report.json']), { input: '/tmp/report.json', help: false })
assert.throws(() => parseVerifierArgs(['--release-ready']), /unknown argument/)

assert.equal(geometricQuantileAttempts(14, 0.50), 11_357)
assert.equal(geometricQuantileAttempts(14, 0.95), 49_081)
assert.equal(geometricQuantileAttempts(14, 0.99), 75_449)
assert.equal(geometricQuantileAttempts(16, 0.50), 45_426)
assert.equal(geometricQuantileAttempts(16, 0.95), 196_327)
assert.equal(geometricQuantileAttempts(16, 0.99), 301_803)
assert.equal(geometricQuantileAttempts(18, 0.50), 181_705)
assert.equal(geometricQuantileAttempts(18, 0.95), 785_312)
assert.equal(geometricQuantileAttempts(18, 0.99), 1_207_216)
assert.throws(() => geometricQuantileAttempts(0, 0.5), /bits/)
assert.throws(() => geometricQuantileAttempts(16, 1), /quantile/)

const model = buildPowLatencyModel({ bits: 16, candidateHashesPerSecond: 2048 })
assert.equal(model.expectedAttempts, 65_536)
assert.equal(model.latencyMs.expected, 32_000)
assert.equal(model.latencyMs.p50, 22_180.664063)
assert.equal(model.latencyMs.p95, 95_862.792969)
assert.equal(model.latencyMs.p99, 147_364.746094)
assert.equal(model.assumptions.includes('no-relay-network-or-admission-cost'), true)
assert.equal(model.assumptions.includes('latency-uses-minimum-observed-sample-rate'), true)
assert.equal(model.rateBasis, 'minimum-observed-sample-effective-rate-v1')

assert.deepEqual(buildPowRateDispersion([
  { candidateHashesPerSecond: 100 },
  { candidateHashesPerSecond: 200 },
  { candidateHashesPerSecond: 300 },
  { candidateHashesPerSecond: 400 }
]), {
  sampleCount: 4,
  min: 100,
  median: 250,
  max: 400,
  mean: 250,
  standardDeviation: 111.803399,
  coefficientOfVariation: 0.447214
})

const configuration = {
  benchmarkBits: POW_BENCHMARK_BITS,
  progressGranularity: POW_PROGRESS_GRANULARITY,
  warmupHashes: 1024,
  sampleHashes: 4096,
  samplesPerAction: 2,
  sampleTimeoutMs: 30_000,
  requireAll: false,
  actionOrder: [...POW_ACTIONS],
  sampleSchedule: 'rotating-action-round-robin-v1'
}

function actionFixture (action) {
  const candidateHashesPerSecond = 2048
  const samples = [
    { candidateHashes: 4096, elapsedMs: 2000, candidateHashesPerSecond },
    { candidateHashes: 4096, elapsedMs: 2000, candidateHashesPerSecond }
  ]
  const dispersion = buildPowRateDispersion(samples)
  return {
    action,
    productionBits: MIN_BITS[action],
    benchmarkBits: POW_BENCHMARK_BITS,
    throughputUnit: 'effective-candidate-sha256-attempts-per-second',
    measurementMethod: 'production-mint-abort-on-progress-boundary-v1',
    warmup: {
      candidateHashes: 1024,
      elapsedMs: 500,
      candidateHashesPerSecond
    },
    samples,
    aggregate: {
      candidateHashes: 8192,
      elapsedMs: 4000,
      candidateHashesPerSecond,
      sampleCount: 2
    },
    dispersion,
    sanity: {
      bits: 4,
      nonce: 12,
      targetHash: 'a'.repeat(64),
      v: POW_VERSION,
      verified: true
    },
    model: buildPowLatencyModel({ bits: MIN_BITS[action], candidateHashesPerSecond: dispersion.min })
  }
}

const result = {
  engine: 'chromium',
  status: 'passed',
  browserVersion: 'fixture-1',
  evidenceClass: 'MEASURED_LOCAL_HEADLESS_CHROMIUM_PRODUCTION_POW_MINT_LOOP',
  sourceSha256: LOCAL_POW_SOURCE_SHA256,
  error: null,
  diagnostics: {
    consoleErrors: [],
    pageErrors: [],
    requestFailures: [],
    httpErrors: []
  },
  actions: POW_ACTIONS.map(actionFixture)
}

const body = {
  schema: POW_REPORT_SCHEMA,
  evidenceClass: 'MEASURED_LOCAL_DESKTOP_BROWSER_PRODUCTION_POW_MINT_LOOP',
  evidenceDigestAlgorithm: 'sha256-canonical-json-v1',
  evidenceDigestPurpose: 'content-checksum-only-not-authenticity-difficulty-or-release-authorization',
  claimBoundary: POW_CLAIM_BOUNDARY,
  startedAt: '2026-07-12T00:00:00.000Z',
  finishedAt: '2026-07-12T00:00:05.000Z',
  environment: {
    platform: 'fixture',
    arch: 'fixture',
    nodeVersion: 'fixture',
    playwrightVersion: 'fixture',
    logicalCpuCount: 1,
    cpuModel: 'fixture',
    totalMemoryBytes: 1,
    headless: true,
    executionOrder: 'sequential-engines-warmup-actions-rotating-sample-rounds'
  },
  productionAuthority: {
    sourcePath: 'js/pow-current.js',
    sourceSha256: LOCAL_POW_SOURCE_SHA256,
    powVersion: POW_VERSION,
    minBits: Object.fromEntries(Object.entries(MIN_BITS))
  },
  configuration,
  requestedEngines: ['chromium'],
  coverage: {
    passedEngines: ['chromium'],
    unavailableEngines: [],
    failedEngines: [],
    desktopEngines: [...POW_DESKTOP_ENGINES],
    desktopMatrixComplete: false,
    mobile: false,
    relayAdmission: false,
    relayEnforcement: false,
    productionFleet: false
  },
  results: [result],
  labExecutionPassed: true,
  requestedCoverageComplete: true,
  desktopMatrixComplete: false,
  releaseReady: false,
  difficultyChangeAuthorized: false,
  authentic: false,
  evidenceGaps: [...POW_EVIDENCE_GAPS_BASE]
}

const sealed = sealBrowserPowEvidence(body)
const valid = verifyBrowserPowEvidence(sealed)
assert.equal(valid.verified, true)
assert.equal(valid.checksumVerified, true)
assert.equal(valid.verificationClass, 'CONTENT_CHECKSUM_AND_INTERNAL_CONSISTENCY_ONLY')
assert.equal(valid.authentic, false)
assert.equal(valid.authorizesDifficultyChange, false)
assert.equal(valid.authorizesRelease, false)

const reordered = {
  ...Object.fromEntries(Object.entries(sealed).reverse())
}
assert.equal(verifyBrowserPowEvidence(reordered).verified, true, 'canonical digest is independent of key insertion order')

const unsealedMutation = structuredClone(sealed)
unsealedMutation.results[0].actions[0].samples[0].elapsedMs++
assert.equal(verifyBrowserPowEvidence(unsealedMutation).checksumVerified, false)
assert.ok(verifyBrowserPowEvidence(unsealedMutation).blockers.includes('EVIDENCE_DIGEST_INVALID'))

const difficultyMutation = structuredClone(sealed)
difficultyMutation.productionAuthority.minBits.post++
const resealedDifficultyMutation = sealBrowserPowEvidence(difficultyMutation)
assert.equal(verifyBrowserPowEvidence(resealedDifficultyMutation).verified, false)
assert.ok(verifyBrowserPowEvidence(resealedDifficultyMutation).blockers.includes('PRODUCTION_AUTHORITY_INVALID'))

const modelMutation = structuredClone(sealed)
modelMutation.results[0].actions[1].model.latencyMs.p99++
const resealedModelMutation = sealBrowserPowEvidence(modelMutation)
assert.equal(verifyBrowserPowEvidence(resealedModelMutation).verified, false)
assert.ok(verifyBrowserPowEvidence(resealedModelMutation).blockers.includes('CHROMIUM_POST_MODEL_INVALID'))

const claimMutation = structuredClone(sealed)
claimMutation.claimBoundary.authorizesDifficultyChange = true
const resealedClaimMutation = sealBrowserPowEvidence(claimMutation)
assert.equal(verifyBrowserPowEvidence(resealedClaimMutation).verified, false)
assert.ok(verifyBrowserPowEvidence(resealedClaimMutation).blockers.includes('CLAIM_BOUNDARY_INVALID'))

const theatreMutation = structuredClone(sealed)
theatreMutation.latencyThresholds = { ready: true }
const resealedTheatreMutation = sealBrowserPowEvidence(theatreMutation)
assert.equal(verifyBrowserPowEvidence(resealedTheatreMutation).verified, false)
assert.ok(verifyBrowserPowEvidence(resealedTheatreMutation).blockers.includes('EVIDENCE_SHAPE_INVALID'))

const malformed = structuredClone(sealed)
delete malformed.configuration
assert.doesNotThrow(() => verifyBrowserPowEvidence(malformed))
assert.equal(verifyBrowserPowEvidence(malformed).verified, false)

assert.equal(browserPowEvidenceDigest(sealed), sealed.evidenceDigest)
console.log('browser-peerit-pow-performance: CLI, production authority, geometric model, claim boundary, and fail-closed evidence checks passed')
