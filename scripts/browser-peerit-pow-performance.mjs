#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, rename, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { arch, availableParallelism, cpus, platform, totalmem } from 'node:os'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MIN_BITS, POW_VERSION } from '../js/pow-current.js'

const HOST = '127.0.0.1'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const POW_SOURCE_PATH = resolve(ROOT, 'js/pow-current.js')
const POW_SOURCE_BYTES = readFileSync(POW_SOURCE_PATH)

export const POW_REPORT_SCHEMA = 'peerit-browser-pow-performance-v1'
export const POW_DESKTOP_ENGINES = Object.freeze(['chromium', 'firefox', 'webkit'])
export const POW_ACTIONS = Object.freeze(['community', 'post', 'comment'])
export const POW_PROGRESS_GRANULARITY = 1024
export const POW_BENCHMARK_BITS = 256
export const LOCAL_POW_SOURCE_SHA256 = createHash('sha256').update(POW_SOURCE_BYTES).digest('hex')

export const POW_CLAIM_BOUNDARY = Object.freeze({
  measurement: 'Fixed abort-bounded candidate batches executed by the production js/pow-current.js mint() loop in local headless desktop browsers.',
  model: 'Geometric first-success latency derived from each action-specific measured candidate rate, assuming independent uniformly distributed SHA-256 outputs and constant throughput.',
  clientSpamFrictionOnly: true,
  relayAdmissionMeasured: false,
  relayAdmissionSecurityClaim: false,
  relayEnforcementMeasured: false,
  adversarialResistanceMeasured: false,
  mobileMeasured: false,
  productionFleetMeasured: false,
  authentic: false,
  authorizesDifficultyChange: false,
  authorizesRelease: false
})

export const POW_EVIDENCE_GAPS_BASE = Object.freeze([
  'CLIENT_BENCHMARK_NOT_RELAY_ADMISSION_EVIDENCE',
  'RELAY_ENFORCEMENT_UNMEASURED',
  'ADVERSARIAL_RESISTANCE_UNMEASURED',
  'MOBILE_DEVICE_PERFORMANCE_UNMEASURED',
  'PRODUCTION_DEVICE_DISTRIBUTION_UNMEASURED',
  'REPORT_NOT_AUTHENTICATED'
])

const DEFAULTS = Object.freeze({
  warmupHashes: 4096,
  sampleHashes: 16_384,
  samplesPerAction: 6,
  sampleTimeoutMs: 30_000
})

function canonicalJson (value) {
  if (value === null) return 'null'
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('PoW evidence contains a non-finite number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .filter(key => value[key] !== undefined)
      .sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`
  }
  throw new TypeError(`PoW evidence contains unsupported ${typeof value}`)
}

function roundMetric (value) {
  return Number(Number(value).toFixed(6))
}

function rateFor (candidateHashes, elapsedMs) {
  return roundMetric(candidateHashes * 1000 / elapsedMs)
}

function exactKeys (value, expected, blocker, blockers) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    blockers.push(blocker)
    return false
  }
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    blockers.push(blocker)
    return false
  }
  return true
}

function sameCanonical (left, right) {
  try {
    return canonicalJson(left) === canonicalJson(right)
  } catch {
    return false
  }
}

function isFinitePositive (value) {
  return Number.isFinite(value) && value > 0
}

function isSafePositiveInteger (value) {
  return Number.isSafeInteger(value) && value > 0
}

function validIsoTimestamp (value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value))
}

function validateBatch (batch, candidateHashes, blocker, blockers) {
  if (!exactKeys(batch, ['candidateHashes', 'elapsedMs', 'candidateHashesPerSecond'], blocker, blockers)) return
  if (batch.candidateHashes !== candidateHashes || !isFinitePositive(batch.elapsedMs) ||
      batch.candidateHashesPerSecond !== rateFor(candidateHashes, batch.elapsedMs)) {
    blockers.push(blocker)
  }
}

export function geometricQuantileAttempts (bits, quantile) {
  if (!Number.isSafeInteger(bits) || bits < 1 || bits > 52) throw new RangeError('bits must be an integer in 1..52')
  if (!Number.isFinite(quantile) || quantile <= 0 || quantile >= 1) throw new RangeError('quantile must be between zero and one')
  const probability = 2 ** -bits
  return Math.ceil(Math.log1p(-quantile) / Math.log1p(-probability))
}

export function buildPowLatencyModel ({ bits, candidateHashesPerSecond }) {
  if (!Number.isSafeInteger(bits) || bits < 1 || bits > 52) throw new RangeError('bits must be an integer in 1..52')
  if (!isFinitePositive(candidateHashesPerSecond)) throw new RangeError('candidateHashesPerSecond must be positive and finite')
  const attempts = {
    p50: geometricQuantileAttempts(bits, 0.50),
    p95: geometricQuantileAttempts(bits, 0.95),
    p99: geometricQuantileAttempts(bits, 0.99)
  }
  const expectedAttempts = 2 ** bits
  const latency = count => roundMetric(count * 1000 / candidateHashesPerSecond)
  return {
    distribution: 'geometric-first-success-v1',
    rateBasis: 'minimum-observed-sample-effective-rate-v1',
    assumptions: [
      'independent-uniform-sha256-outputs',
      'constant-measured-effective-candidate-rate',
      'one-client-one-sequential-production-mint-loop',
      'no-relay-network-or-admission-cost',
      'latency-uses-minimum-observed-sample-rate'
    ],
    successProbabilityPerCandidate: `1/${expectedAttempts}`,
    expectedAttempts,
    quantileAttempts: attempts,
    latencyMs: {
      effectiveCandidateHashesPerSecond: candidateHashesPerSecond,
      expected: latency(expectedAttempts),
      p50: latency(attempts.p50),
      p95: latency(attempts.p95),
      p99: latency(attempts.p99)
    }
  }
}

export function buildPowRateDispersion (samples) {
  if (!Array.isArray(samples) || samples.length === 0) throw new TypeError('samples must be a non-empty array')
  const rates = samples.map(sample => Number(sample && sample.candidateHashesPerSecond))
  if (rates.some(rate => !isFinitePositive(rate))) throw new TypeError('every sample rate must be positive and finite')
  const sorted = [...rates].sort((left, right) => left - right)
  const mean = rates.reduce((sum, rate) => sum + rate, 0) / rates.length
  const middle = Math.floor(sorted.length / 2)
  const median = sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle]
  const variance = rates.reduce((sum, rate) => sum + ((rate - mean) ** 2), 0) / rates.length
  const standardDeviation = Math.sqrt(variance)
  return {
    sampleCount: rates.length,
    min: roundMetric(sorted[0]),
    median: roundMetric(median),
    max: roundMetric(sorted[sorted.length - 1]),
    mean: roundMetric(mean),
    standardDeviation: roundMetric(standardDeviation),
    coefficientOfVariation: roundMetric(standardDeviation / mean)
  }
}

export function browserPowEvidenceDigest (report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new TypeError('PoW evidence must be an object')
  }
  const body = { ...report }
  delete body.evidenceDigest
  return createHash('sha256').update(canonicalJson(body)).digest('hex')
}

export function sealBrowserPowEvidence (report) {
  const body = { ...report }
  delete body.evidenceDigest
  return { ...body, evidenceDigest: browserPowEvidenceDigest(body) }
}

export function expectedPowEvidenceGaps (results) {
  const gaps = [...POW_EVIDENCE_GAPS_BASE]
  for (const result of results) {
    if (!result || typeof result !== 'object') continue
    const engine = typeof result.engine === 'string' && result.engine ? result.engine.toUpperCase() : 'UNKNOWN'
    if (result.status === 'unavailable') gaps.push(`${engine}_BROWSER_UNAVAILABLE`)
    if (result.status === 'failed') gaps.push(`${engine}_MEASUREMENT_FAILED`)
  }
  return gaps
}

function validateModel (model, bits, candidateHashesPerSecond, blocker, blockers) {
  if (!exactKeys(model, [
    'distribution',
    'rateBasis',
    'assumptions',
    'successProbabilityPerCandidate',
    'expectedAttempts',
    'quantileAttempts',
    'latencyMs'
  ], blocker, blockers)) return
  const expected = buildPowLatencyModel({ bits, candidateHashesPerSecond })
  if (!sameCanonical(model, expected)) blockers.push(blocker)
}

function validateActionMeasurement (action, expectedAction, configuration, blockerPrefix, blockers) {
  if (!exactKeys(action, [
    'action',
    'productionBits',
    'benchmarkBits',
    'throughputUnit',
    'measurementMethod',
    'warmup',
    'samples',
    'aggregate',
    'dispersion',
    'sanity',
    'model'
  ], `${blockerPrefix}_SHAPE_INVALID`, blockers)) return
  const expectedBits = MIN_BITS[expectedAction]
  if (action.action !== expectedAction || action.productionBits !== expectedBits ||
      action.benchmarkBits !== POW_BENCHMARK_BITS ||
      action.throughputUnit !== 'effective-candidate-sha256-attempts-per-second' ||
      action.measurementMethod !== 'production-mint-abort-on-progress-boundary-v1') {
    blockers.push(`${blockerPrefix}_AUTHORITY_INVALID`)
  }
  validateBatch(action.warmup, configuration.warmupHashes, `${blockerPrefix}_WARMUP_INVALID`, blockers)
  if (!Array.isArray(action.samples) || action.samples.length !== configuration.samplesPerAction) {
    blockers.push(`${blockerPrefix}_SAMPLES_INVALID`)
  } else {
    for (const sample of action.samples) {
      validateBatch(sample, configuration.sampleHashes, `${blockerPrefix}_SAMPLES_INVALID`, blockers)
    }
  }
  let expectedDispersion = null
  try {
    expectedDispersion = buildPowRateDispersion(action.samples)
  } catch {
    blockers.push(`${blockerPrefix}_DISPERSION_INVALID`)
  }
  if (!expectedDispersion || !sameCanonical(action.dispersion, expectedDispersion)) {
    blockers.push(`${blockerPrefix}_DISPERSION_INVALID`)
  }
  if (!exactKeys(action.aggregate, [
    'candidateHashes',
    'elapsedMs',
    'candidateHashesPerSecond',
    'sampleCount'
  ], `${blockerPrefix}_AGGREGATE_INVALID`, blockers)) return
  const samples = Array.isArray(action.samples) ? action.samples : []
  const expectedCandidateHashes = configuration.sampleHashes * configuration.samplesPerAction
  const expectedElapsedMs = roundMetric(samples.reduce((sum, sample) => sum + Number(sample && sample.elapsedMs), 0))
  const expectedRate = isFinitePositive(expectedElapsedMs) ? rateFor(expectedCandidateHashes, expectedElapsedMs) : null
  if (action.aggregate.candidateHashes !== expectedCandidateHashes ||
      action.aggregate.elapsedMs !== expectedElapsedMs ||
      action.aggregate.candidateHashesPerSecond !== expectedRate ||
      action.aggregate.sampleCount !== configuration.samplesPerAction) {
    blockers.push(`${blockerPrefix}_AGGREGATE_INVALID`)
  }
  if (!exactKeys(action.sanity, ['bits', 'nonce', 'targetHash', 'v', 'verified'], `${blockerPrefix}_SANITY_INVALID`, blockers) ||
      action.sanity.bits !== 4 || !Number.isSafeInteger(action.sanity.nonce) || action.sanity.nonce < 0 ||
      typeof action.sanity.targetHash !== 'string' || !/^[0-9a-f]{64}$/.test(action.sanity.targetHash) ||
      action.sanity.v !== POW_VERSION || action.sanity.verified !== true) {
    blockers.push(`${blockerPrefix}_SANITY_INVALID`)
  }
  if (expectedDispersion && isFinitePositive(expectedDispersion.min)) {
    validateModel(action.model, expectedBits, expectedDispersion.min, `${blockerPrefix}_MODEL_INVALID`, blockers)
  } else {
    blockers.push(`${blockerPrefix}_MODEL_INVALID`)
  }
}

function validateResult (result, engine, configuration, blockers) {
  const prefix = engine.toUpperCase()
  if (!exactKeys(result, [
    'engine',
    'status',
    'browserVersion',
    'evidenceClass',
    'sourceSha256',
    'error',
    'diagnostics',
    'actions'
  ], `${prefix}_RESULT_SHAPE_INVALID`, blockers)) return
  if (result.engine !== engine || !['passed', 'unavailable', 'failed'].includes(result.status) ||
      result.evidenceClass !== `MEASURED_LOCAL_HEADLESS_${prefix}_PRODUCTION_POW_MINT_LOOP`) {
    blockers.push(`${prefix}_RESULT_IDENTITY_INVALID`)
  }
  const diagnostics = result.diagnostics && typeof result.diagnostics === 'object' ? result.diagnostics : {}
  if (!exactKeys(diagnostics, ['consoleErrors', 'pageErrors', 'requestFailures', 'httpErrors'], `${prefix}_DIAGNOSTICS_INVALID`, blockers) ||
      !['consoleErrors', 'pageErrors', 'requestFailures', 'httpErrors'].every(key => Array.isArray(diagnostics[key]))) {
    blockers.push(`${prefix}_DIAGNOSTICS_INVALID`)
  }
  if (result.status === 'passed') {
    if (typeof result.browserVersion !== 'string' || result.browserVersion.length === 0 ||
        result.sourceSha256 !== LOCAL_POW_SOURCE_SHA256 || result.error !== null ||
        !Array.isArray(result.actions) || result.actions.length !== POW_ACTIONS.length ||
        !['consoleErrors', 'pageErrors', 'requestFailures', 'httpErrors'].every(key => Array.isArray(diagnostics[key]) && diagnostics[key].length === 0)) {
      blockers.push(`${prefix}_PASSED_RESULT_INVALID`)
      return
    }
    POW_ACTIONS.forEach((action, index) => {
      validateActionMeasurement(result.actions[index], action, configuration, `${prefix}_${action.toUpperCase()}`, blockers)
    })
  } else if (result.status === 'unavailable' || result.status === 'failed') {
    if (result.browserVersion !== null || result.sourceSha256 !== null ||
      typeof result.error !== 'string' || result.error.length === 0 ||
      !Array.isArray(result.actions) || result.actions.length !== 0) {
      blockers.push(`${prefix}_${result.status.toUpperCase()}_RESULT_INVALID`)
    }
  }
}

export function verifyBrowserPowEvidence (report) {
  const blockers = []
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    return {
      verified: false,
      checksumVerified: false,
      verificationClass: 'CONTENT_CHECKSUM_AND_INTERNAL_CONSISTENCY_ONLY',
      authentic: false,
      authorizesDifficultyChange: false,
      authorizesRelease: false,
      expectedDigest: null,
      observedDigest: null,
      blockers: ['EVIDENCE_NOT_OBJECT']
    }
  }
  exactKeys(report, [
    'schema',
    'evidenceClass',
    'evidenceDigestAlgorithm',
    'evidenceDigestPurpose',
    'claimBoundary',
    'startedAt',
    'finishedAt',
    'environment',
    'productionAuthority',
    'configuration',
    'requestedEngines',
    'coverage',
    'results',
    'labExecutionPassed',
    'requestedCoverageComplete',
    'desktopMatrixComplete',
    'releaseReady',
    'difficultyChangeAuthorized',
    'authentic',
    'evidenceGaps',
    'evidenceDigest'
  ], 'EVIDENCE_SHAPE_INVALID', blockers)
  if (report.schema !== POW_REPORT_SCHEMA) blockers.push('EVIDENCE_SCHEMA_INVALID')
  if (report.evidenceClass !== 'MEASURED_LOCAL_DESKTOP_BROWSER_PRODUCTION_POW_MINT_LOOP') blockers.push('EVIDENCE_CLASS_INVALID')
  if (report.evidenceDigestAlgorithm !== 'sha256-canonical-json-v1' ||
      report.evidenceDigestPurpose !== 'content-checksum-only-not-authenticity-difficulty-or-release-authorization') {
    blockers.push('EVIDENCE_DIGEST_AUTHORITY_INVALID')
  }
  if (!sameCanonical(report.claimBoundary, POW_CLAIM_BOUNDARY)) blockers.push('CLAIM_BOUNDARY_INVALID')
  if (!validIsoTimestamp(report.startedAt) || !validIsoTimestamp(report.finishedAt) || Date.parse(report.finishedAt) < Date.parse(report.startedAt)) {
    blockers.push('TIMESTAMPS_INVALID')
  }
  const environment = report.environment && typeof report.environment === 'object' ? report.environment : {}
  if (!exactKeys(environment, [
    'platform',
    'arch',
    'nodeVersion',
    'playwrightVersion',
    'logicalCpuCount',
    'cpuModel',
    'totalMemoryBytes',
    'headless',
    'executionOrder'
  ], 'ENVIRONMENT_INVALID', blockers) ||
      typeof environment.platform !== 'string' || typeof environment.arch !== 'string' ||
      typeof environment.nodeVersion !== 'string' || typeof environment.playwrightVersion !== 'string' ||
      !isSafePositiveInteger(environment.logicalCpuCount) || typeof environment.cpuModel !== 'string' ||
      !isSafePositiveInteger(environment.totalMemoryBytes) || environment.headless !== true ||
      environment.executionOrder !== 'sequential-engines-warmup-actions-rotating-sample-rounds') {
    blockers.push('ENVIRONMENT_INVALID')
  }
  const expectedMinBits = Object.fromEntries(Object.entries(MIN_BITS))
  const productionAuthority = report.productionAuthority && typeof report.productionAuthority === 'object' ? report.productionAuthority : {}
  if (!exactKeys(productionAuthority, ['sourcePath', 'sourceSha256', 'powVersion', 'minBits'], 'PRODUCTION_AUTHORITY_INVALID', blockers) ||
      productionAuthority.sourcePath !== 'js/pow-current.js' ||
      productionAuthority.sourceSha256 !== LOCAL_POW_SOURCE_SHA256 ||
      productionAuthority.powVersion !== POW_VERSION ||
      !sameCanonical(productionAuthority.minBits, expectedMinBits)) {
    blockers.push('PRODUCTION_AUTHORITY_INVALID')
  }
  const configuration = report.configuration && typeof report.configuration === 'object' ? report.configuration : {}
  if (!exactKeys(configuration, [
    'benchmarkBits',
    'progressGranularity',
    'warmupHashes',
    'sampleHashes',
    'samplesPerAction',
    'sampleTimeoutMs',
    'requireAll',
    'actionOrder',
    'sampleSchedule'
  ], 'CONFIGURATION_INVALID', blockers) ||
      configuration.benchmarkBits !== POW_BENCHMARK_BITS ||
      configuration.progressGranularity !== POW_PROGRESS_GRANULARITY ||
      !isSafePositiveInteger(configuration.warmupHashes) || configuration.warmupHashes % POW_PROGRESS_GRANULARITY !== 0 ||
      !isSafePositiveInteger(configuration.sampleHashes) || configuration.sampleHashes % POW_PROGRESS_GRANULARITY !== 0 ||
      !Number.isSafeInteger(configuration.samplesPerAction) || configuration.samplesPerAction < 1 || configuration.samplesPerAction > 25 ||
      !Number.isSafeInteger(configuration.sampleTimeoutMs) || configuration.sampleTimeoutMs < 1000 || configuration.sampleTimeoutMs > 120_000 ||
      typeof configuration.requireAll !== 'boolean' || !sameCanonical(configuration.actionOrder, POW_ACTIONS) ||
      configuration.sampleSchedule !== 'rotating-action-round-robin-v1') {
    blockers.push('CONFIGURATION_INVALID')
  }
  const requested = report.requestedEngines
  if (!Array.isArray(requested) || requested.length === 0 || new Set(requested).size !== requested.length ||
      requested.some(engine => !POW_DESKTOP_ENGINES.includes(engine))) {
    blockers.push('REQUESTED_ENGINES_INVALID')
  }
  if (!Array.isArray(report.results) || !Array.isArray(requested) || report.results.length !== requested.length) {
    blockers.push('RESULT_SET_INVALID')
  } else {
    requested.forEach((engine, index) => validateResult(report.results[index], engine, configuration, blockers))
  }
  const results = Array.isArray(report.results) ? report.results : []
  const passed = results.filter(result => result && result.status === 'passed').map(result => result.engine)
  const unavailable = results.filter(result => result && result.status === 'unavailable').map(result => result.engine)
  const failed = results.filter(result => result && result.status === 'failed').map(result => result.engine)
  const desktopMatrixComplete = POW_DESKTOP_ENGINES.every(engine => passed.includes(engine))
  const requestedCoverageComplete = Array.isArray(requested) && requested.length > 0 && requested.every(engine => passed.includes(engine))
  const labExecutionPassed = passed.length > 0 && failed.length === 0
  const expectedCoverage = {
    passedEngines: passed,
    unavailableEngines: unavailable,
    failedEngines: failed,
    desktopEngines: [...POW_DESKTOP_ENGINES],
    desktopMatrixComplete,
    mobile: false,
    relayAdmission: false,
    relayEnforcement: false,
    productionFleet: false
  }
  if (!sameCanonical(report.coverage, expectedCoverage)) blockers.push('COVERAGE_INVALID')
  if (report.labExecutionPassed !== labExecutionPassed || report.requestedCoverageComplete !== requestedCoverageComplete ||
      report.desktopMatrixComplete !== desktopMatrixComplete) {
    blockers.push('EXECUTION_CLASSIFICATION_INVALID')
  }
  if (report.releaseReady !== false || report.difficultyChangeAuthorized !== false || report.authentic !== false) {
    blockers.push('SECURITY_BOUNDARY_INVALID')
  }
  if (!sameCanonical(report.evidenceGaps, expectedPowEvidenceGaps(results))) blockers.push('EVIDENCE_GAPS_INVALID')
  const observedDigest = typeof report.evidenceDigest === 'string' ? report.evidenceDigest : null
  let expectedDigest = null
  try {
    expectedDigest = browserPowEvidenceDigest(report)
  } catch {
    blockers.push('EVIDENCE_BODY_NOT_CANONICALIZABLE')
  }
  const checksumVerified = observedDigest != null && /^[0-9a-f]{64}$/.test(observedDigest) && expectedDigest === observedDigest
  if (!checksumVerified) blockers.push('EVIDENCE_DIGEST_INVALID')
  return {
    verified: blockers.length === 0,
    checksumVerified,
    verificationClass: 'CONTENT_CHECKSUM_AND_INTERNAL_CONSISTENCY_ONLY',
    authentic: false,
    authorizesDifficultyChange: false,
    authorizesRelease: false,
    expectedDigest,
    observedDigest,
    blockers: [...new Set(blockers)]
  }
}

function usage () {
  return [
    'Usage: node scripts/browser-peerit-pow-performance.mjs [options]',
    '',
    '  --browser chromium|firefox|webkit|all  desktop engine(s), default all',
    '  --warmup-hashes INTEGER                multiple of 1024, default 4096',
    '  --sample-hashes INTEGER                multiple of 1024, default 16384',
    '  --samples INTEGER                      samples per action, default 6',
    '  --timeout-ms INTEGER                   timeout per bounded batch, default 30000',
    '  --require-all                          fail if any requested engine is unavailable',
    '  --out FILE                             atomically write the JSON report',
    '  --help                                 show this help',
    '',
    'The lab measures client-side spam-friction work only. It does not test or authorize relay admission, relay security, difficulty changes, or a release.'
  ].join('\n')
}

function takeValue (args, index, name) {
  const equals = args[index].indexOf('=')
  if (equals !== -1) return { value: args[index].slice(equals + 1), consumed: 0 }
  if (index + 1 >= args.length || args[index + 1].startsWith('--')) throw new Error(`${name} requires a value`)
  return { value: args[index + 1], consumed: 1 }
}

function parseBoundedInteger (value, name, minimum, maximum) {
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer in ${minimum}..${maximum}`)
  }
  return parsed
}

export function parseArgs (args) {
  const options = {
    engines: [...POW_DESKTOP_ENGINES],
    warmupHashes: DEFAULTS.warmupHashes,
    sampleHashes: DEFAULTS.sampleHashes,
    samplesPerAction: DEFAULTS.samplesPerAction,
    sampleTimeoutMs: DEFAULTS.sampleTimeoutMs,
    requireAll: false,
    out: null,
    help: false
  }
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]
    if (argument === '--help') {
      options.help = true
      continue
    }
    if (argument === '--require-all') {
      options.requireAll = true
      continue
    }
    const name = argument.split('=', 1)[0]
    if (!['--browser', '--warmup-hashes', '--sample-hashes', '--samples', '--timeout-ms', '--out'].includes(name)) {
      throw new Error(`unknown argument ${argument}`)
    }
    const { value, consumed } = takeValue(args, index, name)
    index += consumed
    if (!value) throw new Error(`${name} requires a non-empty value`)
    if (name === '--browser') {
      if (value === 'all') options.engines = [...POW_DESKTOP_ENGINES]
      else if (POW_DESKTOP_ENGINES.includes(value)) options.engines = [value]
      else throw new Error(`--browser must be chromium, firefox, webkit, or all (received ${value})`)
    } else if (name === '--warmup-hashes') {
      options.warmupHashes = parseBoundedInteger(value, name, POW_PROGRESS_GRANULARITY, 1_048_576)
      if (options.warmupHashes % POW_PROGRESS_GRANULARITY !== 0) throw new Error(`${name} must be a multiple of 1024`)
    } else if (name === '--sample-hashes') {
      options.sampleHashes = parseBoundedInteger(value, name, POW_PROGRESS_GRANULARITY, 1_048_576)
      if (options.sampleHashes % POW_PROGRESS_GRANULARITY !== 0) throw new Error(`${name} must be a multiple of 1024`)
    } else if (name === '--samples') {
      options.samplesPerAction = parseBoundedInteger(value, name, 1, 25)
    } else if (name === '--timeout-ms') {
      options.sampleTimeoutMs = parseBoundedInteger(value, name, 1000, 120_000)
    } else if (name === '--out') {
      options.out = value
    }
  }
  return options
}

async function startSourceServer () {
  const server = createServer((request, response) => {
    const url = new URL(request.url || '/', `http://${HOST}`)
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('X-Content-Type-Options', 'nosniff')
    if (url.pathname === '/' || url.pathname === '/index.html') {
      response.statusCode = 200
      response.setHeader('Content-Type', 'text/html; charset=utf-8')
      response.end('<!doctype html><meta charset="utf-8"><title>Peerit PoW performance lab</title>')
      return
    }
    if (url.pathname === '/js/pow-current.js') {
      response.statusCode = 200
      response.setHeader('Content-Type', 'text/javascript; charset=utf-8')
      response.end(POW_SOURCE_BYTES)
      return
    }
    response.statusCode = 404
    response.setHeader('Content-Type', 'text/plain; charset=utf-8')
    response.end('not found')
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, HOST, resolve)
  })
  const address = server.address()
  return {
    origin: `http://${HOST}:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
  }
}

function diagnosticsRecorder (page) {
  const diagnostics = { consoleErrors: [], pageErrors: [], requestFailures: [], httpErrors: [] }
  page.on('console', message => {
    if (message.type() === 'error') diagnostics.consoleErrors.push(message.text())
  })
  page.on('pageerror', error => diagnostics.pageErrors.push(String((error && (error.stack || error.message)) || error)))
  page.on('requestfailed', request => {
    const failure = request.failure()
    diagnostics.requestFailures.push(`${request.method()} ${request.url()}: ${failure ? failure.errorText : 'unknown failure'}`)
  })
  page.on('response', response => {
    if (response.status() >= 400) diagnostics.httpErrors.push(`${response.status()} ${response.url()}`)
  })
  return diagnostics
}

function errorText (error) {
  return String((error && (error.stack || error.message)) || error)
}

function browserUnavailable (error) {
  const text = errorText(error)
  return /executable (doesn't exist|not found)|playwright install|failed to launch.*executable/i.test(text)
}

function normalizeBatch (batch) {
  const candidateHashes = Number(batch.candidateHashes)
  const elapsedMs = roundMetric(batch.elapsedMs)
  return { candidateHashes, elapsedMs, candidateHashesPerSecond: rateFor(candidateHashes, elapsedMs) }
}

function normalizeAction (raw, action, options) {
  const warmup = normalizeBatch(raw.warmup)
  const samples = raw.samples.map(normalizeBatch)
  const dispersion = buildPowRateDispersion(samples)
  const candidateHashes = options.sampleHashes * options.samplesPerAction
  const elapsedMs = roundMetric(samples.reduce((sum, sample) => sum + sample.elapsedMs, 0))
  const candidateHashesPerSecond = rateFor(candidateHashes, elapsedMs)
  return {
    action,
    productionBits: MIN_BITS[action],
    benchmarkBits: POW_BENCHMARK_BITS,
    throughputUnit: 'effective-candidate-sha256-attempts-per-second',
    measurementMethod: 'production-mint-abort-on-progress-boundary-v1',
    warmup,
    samples,
    aggregate: {
      candidateHashes,
      elapsedMs,
      candidateHashesPerSecond,
      sampleCount: options.samplesPerAction
    },
    dispersion,
    sanity: raw.sanity,
    model: buildPowLatencyModel({ bits: MIN_BITS[action], candidateHashesPerSecond: dispersion.min })
  }
}

async function runEngine ({ playwright, engine, origin, options }) {
  let browser = null
  let browserVersion = null
  let diagnostics = { consoleErrors: [], pageErrors: [], requestFailures: [], httpErrors: [] }
  try {
    browser = await playwright[engine].launch({ headless: true, timeout: options.sampleTimeoutMs })
    browserVersion = browser.version()
    const context = await browser.newContext()
    const page = await context.newPage()
    diagnostics = diagnosticsRecorder(page)
    await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded', timeout: options.sampleTimeoutMs })
    const moduleUrl = `${origin}/js/pow-current.js?sha256=${LOCAL_POW_SOURCE_SHA256}`
    const evaluationTimeoutMs = options.sampleTimeoutMs * (POW_ACTIONS.length * (options.samplesPerAction + 2))
    const evaluation = page.evaluate(async ({
      moduleUrl,
      sourceSha256,
      actionOrder,
      warmupHashes,
      sampleHashes,
      samplesPerAction,
      sampleTimeoutMs,
      benchmarkBits
    }) => {
      if (!globalThis.isSecureContext || !globalThis.crypto || !globalThis.crypto.subtle) {
        throw new Error('secure browser Web Crypto is unavailable')
      }
      const sourceResponse = await fetch(moduleUrl, { cache: 'no-store' })
      if (!sourceResponse.ok) throw new Error(`production PoW source returned HTTP ${sourceResponse.status}`)
      const sourceBytes = new Uint8Array(await sourceResponse.arrayBuffer())
      const observedDigest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', sourceBytes))
      const observedSourceSha256 = [...observedDigest].map(byte => byte.toString(16).padStart(2, '0')).join('')
      if (observedSourceSha256 !== sourceSha256) throw new Error('browser-observed production PoW source digest mismatch')
      const production = await import(moduleUrl)
      const expectedBits = { community: 18, post: 16, comment: 14, blob: 12 }
      const observedBitKeys = Object.keys(production.MIN_BITS).sort()
      const expectedBitKeys = Object.keys(expectedBits).sort()
      const bitsMatch = observedBitKeys.length === expectedBitKeys.length &&
        observedBitKeys.every((key, index) => key === expectedBitKeys[index] && production.MIN_BITS[key] === expectedBits[key])
      if (production.POW_VERSION !== 2 || !bitsMatch) {
        throw new Error('production PoW exports do not match the benchmark authority')
      }
      let sequence = 0
      const dataFor = action => ({
        id: String(++sequence).padStart(64, '0'),
        createdAt: 1780000000000 + sequence,
        community: 'pow-lab',
        cid: `pow-lab-${sequence}`,
        postCid: `pow-lab-post-${sequence}`,
        author: '1'.repeat(64),
        creator: '1'.repeat(64),
        slug: `pow-lab-${sequence}`
      })
      const boundedBatch = async (action, candidateHashes) => {
        const controller = new AbortController()
        let reachedBoundary = false
        let timedOut = false
        let lastProgress = 0
        const timer = setTimeout(() => {
          timedOut = true
          controller.abort()
        }, sampleTimeoutMs)
        const started = performance.now()
        try {
          await production.mint(action, dataFor(action), benchmarkBits, {
            signal: controller.signal,
            onProgress (nonce) {
              lastProgress = nonce
              if (nonce >= candidateHashes) {
                reachedBoundary = true
                controller.abort()
              }
            }
          })
          throw new Error('the 256-bit bounded benchmark unexpectedly found a proof')
        } catch (error) {
          if (!reachedBoundary) {
            if (timedOut) throw new Error(`${action} bounded batch timed out after progress ${lastProgress}/${candidateHashes}`)
            throw error
          }
        } finally {
          clearTimeout(timer)
        }
        const elapsedMs = performance.now() - started
        if (lastProgress !== candidateHashes) throw new Error(`${action} bounded batch stopped at ${lastProgress}/${candidateHashes}`)
        return { candidateHashes, elapsedMs }
      }
      const measurements = Object.fromEntries(actionOrder.map(action => [action, {
        action,
        warmup: null,
        samples: [],
        sanity: null
      }]))
      for (const action of actionOrder) {
        measurements[action].warmup = await boundedBatch(action, warmupHashes)
      }
      for (let sample = 0; sample < samplesPerAction; sample++) {
        for (let offset = 0; offset < actionOrder.length; offset++) {
          const action = actionOrder[(sample + offset) % actionOrder.length]
          measurements[action].samples.push(await boundedBatch(action, sampleHashes))
        }
      }
      for (const action of actionOrder) {
        const sanityData = dataFor(action)
        const sanityProof = await production.mint(action, sanityData, 4)
        const verified = await production.verify(action, { ...sanityData, pow: sanityProof }, 4)
        if (!verified) throw new Error(`${action} low-cost production mint/verify sanity failed`)
        measurements[action].sanity = { ...sanityProof, verified }
      }
      return { observedSourceSha256, actions: actionOrder.map(action => measurements[action]) }
    }, {
      moduleUrl,
      sourceSha256: LOCAL_POW_SOURCE_SHA256,
      actionOrder: POW_ACTIONS,
      warmupHashes: options.warmupHashes,
      sampleHashes: options.sampleHashes,
      samplesPerAction: options.samplesPerAction,
      sampleTimeoutMs: options.sampleTimeoutMs,
      benchmarkBits: POW_BENCHMARK_BITS
    })
    let timeout
    const raw = await Promise.race([
      evaluation,
      new Promise((resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(`browser evaluation exceeded ${evaluationTimeoutMs}ms`)), evaluationTimeoutMs)
      })
    ]).finally(() => clearTimeout(timeout))
    if (raw.observedSourceSha256 !== LOCAL_POW_SOURCE_SHA256) throw new Error('browser source digest mismatch')
    if (diagnostics.consoleErrors.length || diagnostics.pageErrors.length || diagnostics.requestFailures.length || diagnostics.httpErrors.length) {
      throw new Error('browser diagnostics were not clean')
    }
    return {
      engine,
      status: 'passed',
      browserVersion,
      evidenceClass: `MEASURED_LOCAL_HEADLESS_${engine.toUpperCase()}_PRODUCTION_POW_MINT_LOOP`,
      sourceSha256: raw.observedSourceSha256,
      error: null,
      diagnostics,
      actions: POW_ACTIONS.map((action, index) => normalizeAction(raw.actions[index], action, options))
    }
  } catch (error) {
    const unavailable = browser == null && browserUnavailable(error)
    return {
      engine,
      status: unavailable ? 'unavailable' : 'failed',
      browserVersion: null,
      evidenceClass: `MEASURED_LOCAL_HEADLESS_${engine.toUpperCase()}_PRODUCTION_POW_MINT_LOOP`,
      sourceSha256: null,
      error: errorText(error),
      diagnostics,
      actions: []
    }
  } finally {
    if (browser) await browser.close().catch(() => {})
  }
}

function playwrightVersion () {
  try {
    return JSON.parse(readFileSync(resolve(ROOT, 'node_modules/playwright/package.json'), 'utf8')).version
  } catch {
    return 'unknown'
  }
}

export async function runBrowserPowPerformanceLab (options) {
  const startedAt = new Date().toISOString()
  const playwright = await import('playwright')
  const sourceServer = await startSourceServer()
  const results = []
  try {
    for (const engine of options.engines) {
      results.push(await runEngine({ playwright, engine, origin: sourceServer.origin, options }))
    }
  } finally {
    await sourceServer.close()
  }
  const passed = results.filter(result => result.status === 'passed').map(result => result.engine)
  const unavailable = results.filter(result => result.status === 'unavailable').map(result => result.engine)
  const failed = results.filter(result => result.status === 'failed').map(result => result.engine)
  const desktopMatrixComplete = POW_DESKTOP_ENGINES.every(engine => passed.includes(engine))
  const requestedCoverageComplete = options.engines.every(engine => passed.includes(engine))
  const labExecutionPassed = passed.length > 0 && failed.length === 0
  const cpuList = cpus()
  const report = {
    schema: POW_REPORT_SCHEMA,
    evidenceClass: 'MEASURED_LOCAL_DESKTOP_BROWSER_PRODUCTION_POW_MINT_LOOP',
    evidenceDigestAlgorithm: 'sha256-canonical-json-v1',
    evidenceDigestPurpose: 'content-checksum-only-not-authenticity-difficulty-or-release-authorization',
    claimBoundary: POW_CLAIM_BOUNDARY,
    startedAt,
    finishedAt: new Date().toISOString(),
    environment: {
      platform: platform(),
      arch: arch(),
      nodeVersion: process.version,
      playwrightVersion: playwrightVersion(),
      logicalCpuCount: availableParallelism(),
      cpuModel: cpuList[0] ? cpuList[0].model : 'unknown',
      totalMemoryBytes: totalmem(),
      headless: true,
      executionOrder: 'sequential-engines-warmup-actions-rotating-sample-rounds'
    },
    productionAuthority: {
      sourcePath: 'js/pow-current.js',
      sourceSha256: LOCAL_POW_SOURCE_SHA256,
      powVersion: POW_VERSION,
      minBits: Object.fromEntries(Object.entries(MIN_BITS))
    },
    configuration: {
      benchmarkBits: POW_BENCHMARK_BITS,
      progressGranularity: POW_PROGRESS_GRANULARITY,
      warmupHashes: options.warmupHashes,
      sampleHashes: options.sampleHashes,
      samplesPerAction: options.samplesPerAction,
      sampleTimeoutMs: options.sampleTimeoutMs,
      requireAll: options.requireAll,
      actionOrder: [...POW_ACTIONS],
      sampleSchedule: 'rotating-action-round-robin-v1'
    },
    requestedEngines: [...options.engines],
    coverage: {
      passedEngines: passed,
      unavailableEngines: unavailable,
      failedEngines: failed,
      desktopEngines: [...POW_DESKTOP_ENGINES],
      desktopMatrixComplete,
      mobile: false,
      relayAdmission: false,
      relayEnforcement: false,
      productionFleet: false
    },
    results,
    labExecutionPassed,
    requestedCoverageComplete,
    desktopMatrixComplete,
    releaseReady: false,
    difficultyChangeAuthorized: false,
    authentic: false,
    evidenceGaps: expectedPowEvidenceGaps(results)
  }
  return sealBrowserPowEvidence(report)
}

async function atomicWriteJson (file, report) {
  const destination = resolve(file)
  const temporary = `${destination}.${process.pid}.tmp`
  await mkdir(dirname(destination), { recursive: true })
  await writeFile(temporary, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 })
  await rename(temporary, destination)
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  const report = await runBrowserPowPerformanceLab(options)
  const verification = verifyBrowserPowEvidence(report)
  if (options.out) await atomicWriteJson(options.out, report)
  process.stdout.write(`${JSON.stringify(report)}\n`)
  if (!verification.verified || !report.labExecutionPassed || (options.requireAll && !report.requestedCoverageComplete)) {
    process.exitCode = 1
  }
}

const invokedPath = process.argv[1] && resolve(process.argv[1])
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`[browser-peerit-pow-performance] FAIL ${errorText(error)}\n`)
    process.exitCode = 1
  })
}
