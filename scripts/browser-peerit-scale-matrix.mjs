#!/usr/bin/env node

import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, rename, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { dirname, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const HOST = '127.0.0.1'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ALL_ENGINES = Object.freeze(['chromium', 'firefox', 'webkit'])
const EXPECTED_PAGE_GATES = Object.freeze([
  'EXACT_COUNTS',
  'REOPEN_PERSISTENCE',
  'REOPEN_RECOUNT_DIGEST',
  'INDEX_REBUILD_COUNT',
  'COMMIT_P99',
  'RANGE_PAGE_P99',
  'INDEX_REBUILD_WALL',
  'LONG_TASK_OBSERVATION',
  'LONG_TASK_MAX'
])

export const BROWSER_SCALE_PROFILES = Object.freeze({
  smoke: Object.freeze({
    intents: 100,
    records: 1000,
    communities: 20,
    pageSize: 100,
    timeoutMs: 60_000
  }),
  full: Object.freeze({
    intents: 10_000,
    records: 100_000,
    communities: 100,
    // Keep rebuild reads aligned with the journal/delivery batch. WebKit shows
    // repeatable multi-hundred-millisecond allocation stalls at 1,000 rows,
    // while 256-row pages still scan the exact 100k corpus and keep the full
    // rebuild comfortably inside the unchanged 10s wall-time gate.
    pageSize: 256,
    timeoutMs: 300_000
  })
})

function canonicalJson (value) {
  if (value === null) return 'null'
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('browser scale evidence contains a non-finite number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object') {
    const entries = Object.keys(value)
      .filter(key => value[key] !== undefined)
      .sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    return `{${entries.join(',')}}`
  }
  throw new TypeError(`browser scale evidence contains unsupported ${typeof value}`)
}

export function browserScaleEvidenceDigest (report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new TypeError('browser scale evidence must be an object')
  }
  const body = { ...report }
  delete body.evidenceDigest
  return createHash('sha256').update(canonicalJson(body)).digest('hex')
}

export function verifyBrowserScaleEvidence (report) {
  const blockers = []
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    return {
      verified: false,
      checksumVerified: false,
      verificationClass: 'CONTENT_CHECKSUM_ONLY',
      authentic: false,
      authorizesRelease: false,
      expectedDigest: null,
      observedDigest: null,
      blockers: ['EVIDENCE_NOT_OBJECT']
    }
  }
  if (report.schema !== 'peerit-browser-scale-matrix-v1') blockers.push('EVIDENCE_SCHEMA_INVALID')
  if (report.evidenceDigestAlgorithm !== 'sha256-canonical-json-v1') blockers.push('EVIDENCE_DIGEST_ALGORITHM_INVALID')
  const observedDigest = typeof report.evidenceDigest === 'string' ? report.evidenceDigest : null
  if (!observedDigest || !/^[0-9a-f]{64}$/.test(observedDigest)) blockers.push('EVIDENCE_DIGEST_MISSING_OR_MALFORMED')
  let expectedDigest = null
  try {
    expectedDigest = browserScaleEvidenceDigest(report)
  } catch {
    blockers.push('EVIDENCE_BODY_NOT_CANONICALIZABLE')
  }
  if (expectedDigest && observedDigest && expectedDigest !== observedDigest) blockers.push('EVIDENCE_DIGEST_MISMATCH')
  return {
    verified: blockers.length === 0,
    checksumVerified: blockers.length === 0,
    verificationClass: 'CONTENT_CHECKSUM_ONLY',
    authentic: false,
    authorizesRelease: false,
    expectedDigest,
    observedDigest,
    blockers
  }
}

export function classifyBrowserScaleReadiness ({ profile, requestedEngines, passedEngines }) {
  const passed = new Set(passedEngines)
  const selectedRunPassed = requestedEngines.length > 0 && requestedEngines.every(engine => passed.has(engine))
  const fullProfile = profile === 'full'
  const fullProfileEnginesPassed = fullProfile ? [...passed] : []
  return {
    selectedRunPassed,
    selectedBrowserGateReady: fullProfile && selectedRunPassed,
    localDesktopMatrixReady: fullProfile && ALL_ENGINES.every(engine => passed.has(engine)),
    fullProfileEnginesPassed
  }
}

const activeBrowsers = new Set()
let activeServerChild = null

function usage () {
  return [
    'Usage: node scripts/browser-peerit-scale-matrix.mjs [options]',
    '',
    '  --browser chromium|firefox|webkit|all  desktop engine(s), default all',
    '  --profile smoke|full                    deterministic workload, default smoke',
    '  --url URL                               use an existing server instead of starting dev-server.mjs',
    '  --out FILE                              atomically write the JSON report',
    '  --timeout-ms INTEGER                    override the per-engine timeout',
    '  --help                                  show this help',
    '',
    'This gate never represents mobile, crash-recovery, quota-exhaustion, network, or production evidence.'
  ].join('\n')
}

function takeValue (args, index, name) {
  const argument = args[index]
  const equals = argument.indexOf('=')
  if (equals !== -1) return { value: argument.slice(equals + 1), consumed: 0 }
  if (index + 1 >= args.length || args[index + 1].startsWith('--')) {
    throw new Error(`${name} requires a value`)
  }
  return { value: args[index + 1], consumed: 1 }
}

export function parseArgs (args) {
  const options = {
    engines: [...ALL_ENGINES],
    profile: 'smoke',
    url: null,
    out: null,
    timeoutMs: null,
    help: false
  }
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]
    if (argument === '--help') {
      options.help = true
      continue
    }
    const name = argument.split('=', 1)[0]
    if (!['--browser', '--profile', '--url', '--out', '--timeout-ms'].includes(name)) {
      throw new Error(`unknown argument ${argument}`)
    }
    const { value, consumed } = takeValue(args, index, name)
    index += consumed
    if (!value) throw new Error(`${name} requires a non-empty value`)
    if (name === '--browser') {
      if (value === 'all') options.engines = [...ALL_ENGINES]
      else if (ALL_ENGINES.includes(value)) options.engines = [value]
      else throw new Error(`--browser must be chromium, firefox, webkit, or all (received ${value})`)
    } else if (name === '--profile') {
      if (!Object.hasOwn(BROWSER_SCALE_PROFILES, value)) {
        throw new Error(`--profile must be smoke or full (received ${value})`)
      }
      options.profile = value
    } else if (name === '--url') {
      const parsed = new URL(value)
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('--url must use http or https')
      options.url = parsed.toString()
    } else if (name === '--out') {
      options.out = value
    } else if (name === '--timeout-ms') {
      const timeoutMs = Number(value)
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 900_000) {
        throw new Error('--timeout-ms must be an integer in 1000..900000')
      }
      options.timeoutMs = timeoutMs
    }
  }
  return options
}

export function buildTargetUrl (baseUrl, workload, { profile, engine }) {
  const parsed = new URL(baseUrl)
  if (!parsed.pathname.endsWith('.html')) {
    if (!parsed.pathname.endsWith('/')) parsed.pathname += '/'
    parsed.pathname += 'journal-scale-browser-gate.html'
  }
  parsed.hash = ''
  parsed.searchParams.set('intents', String(workload.intents))
  parsed.searchParams.set('records', String(workload.records))
  parsed.searchParams.set('communities', String(workload.communities))
  parsed.searchParams.set('page', String(workload.pageSize))
  parsed.searchParams.set('profile', profile)
  parsed.searchParams.set('run', `${profile}-${engine}`)
  return parsed.toString()
}

function gate (id, passed, detail = undefined) {
  return detail === undefined ? { id, passed } : { id, passed, detail }
}

function sameWorkload (actual, expected) {
  return actual != null &&
    actual.intents === expected.intents &&
    actual.records === expected.records &&
    actual.communities === expected.communities &&
    actual.pageSize === expected.pageSize
}

function finiteAtMost (value, ceiling) {
  return Number.isFinite(value) && value >= 0 && value <= ceiling
}

export function validatePageReport ({ report, workload, profile = 'smoke', diagnostics = {}, bodyStatus = null }) {
  const consoleErrors = diagnostics.consoleErrors || []
  const pageErrors = diagnostics.pageErrors || []
  const requestFailures = diagnostics.requestFailures || []
  const httpErrors = diagnostics.httpErrors || []
  const pageGates = new Map(Array.isArray(report && report.gates)
    ? report.gates.map(item => [item && item.id, item])
    : [])
  const summary = report && report.summary
  const timing = report && report.timing
  const exactCounts = summary != null &&
    summary.intents === workload.intents &&
    summary.records === workload.records &&
    summary.countedRecords === workload.records &&
    summary.indexedRecords === workload.records &&
    summary.reopenedIntents === workload.intents &&
    summary.reopenedRecords === workload.records &&
    summary.reopenedCountedRecords === workload.records &&
    summary.reopenedScannedRecords === workload.records &&
    typeof summary.initialViewSha256 === 'string' && /^[0-9a-f]{64}$/.test(summary.initialViewSha256) &&
    summary.reopenedViewSha256 === summary.initialViewSha256 &&
    summary.lastRecordRecovered === true
  const pageThresholds = timing != null &&
    finiteAtMost(timing.commit && timing.commit.p99Ms, 50) &&
    finiteAtMost(timing.rangePage && timing.rangePage.p99Ms, 100) &&
    finiteAtMost(timing.indexWallMs, 10_000) &&
    finiteAtMost(timing.longTask && timing.longTask.maxMs, 250)
  const metricSampleCounts = timing != null &&
    timing.commit && timing.commit.count === workload.intents &&
    timing.rangePage && timing.rangePage.count === Math.ceil(workload.records / workload.pageSize) &&
    timing.longTask && Number.isSafeInteger(timing.longTask.count) && timing.longTask.count >= 0
  const expectedPageGatesPass = EXPECTED_PAGE_GATES.every(id => pageGates.get(id) && pageGates.get(id).passed === true)
  const claimBoundary = report && report.claimBoundary
  const pageClaimBoundary = typeof claimBoundary === 'string' &&
    ['mobile', 'crash recovery', 'quota exhaustion', 'network', 'mainnet'].every(term => claimBoundary.includes(term))
  const gates = [
    gate('PAGE_REPORT_PRESENT', report != null),
    gate('PAGE_SCHEMA', report && report.schema === 'peerit-browser-scale-gate-v1', report && report.schema),
    gate('PAGE_EVIDENCE_CLASS', report && report.evidenceClass === 'MEASURED_LOCAL_BROWSER_INDEXEDDB', report && report.evidenceClass),
    gate('PAGE_CLAIM_BOUNDARY', pageClaimBoundary, claimBoundary),
    gate('PAGE_PROFILE', report && report.profile === profile, report && report.profile),
    gate('PAGE_OPERATION_SHAPE', report && report.operationShape === 'exact-generated-record-operations-v1', report && report.operationShape),
    gate('WORKLOAD_MATCH', sameWorkload(report && report.workload, workload)),
    gate('EXACT_COUNTS', exactCounts, summary || null),
    gate('METRIC_SAMPLE_COUNTS', metricSampleCounts),
    gate('EXPECTED_PAGE_GATES_PASS', expectedPageGatesPass),
    gate('THRESHOLDS_PASS', pageThresholds),
    gate('PAGE_BLOCKERS_EMPTY', Array.isArray(report && report.blockers) && report.blockers.length === 0, report && report.blockers),
    gate('PAGE_LOCAL_RUN_READY', report && report.localBrowserRunReady === true),
    gate('PAGE_FULL_GATE_BOUNDARY', report && report.localBrowserGateReady === (profile === 'full')),
    gate('PAGE_RELEASE_BOUNDARY', report && report.releaseReady === false),
    gate('BODY_STATUS_PASSED', bodyStatus === 'passed', bodyStatus),
    gate('NO_CONSOLE_ERRORS', consoleErrors.length === 0, consoleErrors),
    gate('NO_PAGE_ERRORS', pageErrors.length === 0, pageErrors),
    gate('NO_REQUEST_FAILURES', requestFailures.length === 0, requestFailures),
    gate('NO_HTTP_ERRORS', httpErrors.length === 0, httpErrors)
  ]
  const blockers = gates.filter(item => !item.passed).map(item => item.id)
  return { gates, blockers, passed: blockers.length === 0 }
}

async function freePort () {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.once('error', reject)
    server.listen(0, HOST, () => {
      const address = server.address()
      server.close(error => error ? reject(error) : resolve(address.port))
    })
  })
}

async function waitForHttp (url, child, output) {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    if (child.exitCode != null) throw new Error(`dev server exited ${child.exitCode}: ${output()}`)
    try {
      const response = await fetch(url, { cache: 'no-store' })
      if (response.ok) return
    } catch {}
    await sleep(50)
  }
  throw new Error(`dev server did not start at ${url}: ${output()}`)
}

async function startDevServer () {
  const port = await freePort()
  let captured = ''
  const child = spawn(process.execPath, ['dev-server.mjs'], {
    cwd: ROOT,
    env: { ...process.env, HOST, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  activeServerChild = child
  const capture = chunk => {
    captured = (captured + String(chunk)).slice(-65_536)
  }
  child.stdout.on('data', capture)
  child.stderr.on('data', capture)
  const baseUrl = `http://${HOST}:${port}/`
  try {
    await waitForHttp(`${baseUrl}journal-scale-browser-gate.html`, child, () => captured)
  } catch (error) {
    await stopDevServer(child)
    throw error
  }
  return { child, baseUrl, output: () => captured }
}

async function stopDevServer (child) {
  if (!child || child.exitCode != null || child.signalCode != null) {
    if (activeServerChild === child) activeServerChild = null
    return
  }
  const exited = new Promise(resolve => child.once('exit', resolve))
  child.kill('SIGTERM')
  await Promise.race([
    exited,
    sleep(1500).then(() => {
      if (child.exitCode == null && child.signalCode == null) child.kill('SIGKILL')
    })
  ])
  if (child.exitCode == null && child.signalCode == null) await exited
  if (activeServerChild === child) activeServerChild = null
}

function errorText (error) {
  return String((error && (error.stack || error.message)) || error)
}

async function runEngine ({ playwright, engine, baseUrl, workload, profile, timeoutMs }) {
  const diagnostics = { consoleErrors: [], pageErrors: [], requestFailures: [], httpErrors: [] }
  const targetUrl = buildTargetUrl(baseUrl, workload, { profile, engine })
  let browser = null
  let context = null
  let pageReport = null
  let bodyStatus = null
  let browserVersion = null
  let executionError = null
  try {
    browser = await playwright[engine].launch({ headless: true })
    activeBrowsers.add(browser)
    browserVersion = browser.version()
    context = await browser.newContext()
    const page = await context.newPage()
    page.on('console', message => {
      if (message.type() === 'error') diagnostics.consoleErrors.push(message.text())
    })
    page.on('pageerror', error => diagnostics.pageErrors.push(errorText(error)))
    page.on('requestfailed', request => {
      const failure = request.failure()
      diagnostics.requestFailures.push(`${request.method()} ${request.url()}: ${failure ? failure.errorText : 'unknown failure'}`)
    })
    page.on('response', response => {
      if (response.status() >= 400) diagnostics.httpErrors.push(`${response.status()} ${response.url()}`)
    })
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs })
    await page.waitForFunction(() => globalThis.__PEERIT_BROWSER_SCALE_GATE__ != null, null, { timeout: timeoutMs })
    const result = await page.evaluate(() => ({
      report: globalThis.__PEERIT_BROWSER_SCALE_GATE__,
      bodyStatus: document.body.dataset.status || null
    }))
    pageReport = result.report
    bodyStatus = result.bodyStatus
  } catch (error) {
    executionError = errorText(error)
  } finally {
    if (context) await context.close().catch(() => {})
    if (browser) {
      activeBrowsers.delete(browser)
      await browser.close().catch(() => {})
    }
  }
  const validation = validatePageReport({ report: pageReport, workload, profile, diagnostics, bodyStatus })
  const harnessGates = [
    gate('HARNESS_EXECUTION', executionError == null, executionError),
    ...validation.gates
  ]
  const blockers = harnessGates.filter(item => !item.passed).map(item => item.id)
  return {
    engine,
    browserVersion,
    evidenceClass: `MEASURED_LOCAL_DESKTOP_${engine.toUpperCase()}_INDEXEDDB_PLAYWRIGHT`,
    claimBoundary: `One local desktop ${engine} build on one machine; not mobile, crash recovery, quota exhaustion, network, or production evidence.`,
    status: blockers.length === 0 ? 'passed' : 'failed',
    target: new URL(targetUrl).origin + new URL(targetUrl).pathname,
    executionError,
    diagnostics,
    harnessGates,
    blockers,
    metrics: pageReport
      ? {
          workload: pageReport.workload,
          summary: pageReport.summary,
          timing: pageReport.timing,
          storage: pageReport.storage,
          memory: pageReport.memory,
          observability: pageReport.observability
        }
      : null,
    pageReport
  }
}

export async function runBrowserScaleMatrix (options) {
  const workload = BROWSER_SCALE_PROFILES[options.profile]
  if (!workload) throw new Error(`unknown profile ${options.profile}`)
  const playwright = await import('playwright')
  let devServer = null
  const baseUrl = options.url || (devServer = await startDevServer()).baseUrl
  const timeoutMs = options.timeoutMs || workload.timeoutMs
  const startedAt = new Date().toISOString()
  const results = []
  try {
    for (const engine of options.engines) {
      results.push(await runEngine({ playwright, engine, baseUrl, workload, profile: options.profile, timeoutMs }))
    }
  } finally {
    if (devServer) await stopDevServer(devServer.child)
  }
  const passedEngines = results.filter(result => result.status === 'passed').map(result => result.engine)
  const readiness = classifyBrowserScaleReadiness({
    profile: options.profile,
    requestedEngines: options.engines,
    passedEngines
  })
  const releaseBlockers = [
    ...(options.profile === 'full' ? [] : ['FULL_BROWSER_SCALE_PROFILE_UNRUN']),
    ...ALL_ENGINES.filter(engine => !readiness.fullProfileEnginesPassed.includes(engine))
      .map(engine => `${engine.toUpperCase()}_INDEXEDDB_SCALE_UNPROVEN`),
    'MOBILE_BROWSER_SCALE_UNRUN',
    'BROWSER_CRASH_RECOVERY_UNRUN',
    'BROWSER_QUOTA_EXHAUSTION_UNRUN',
    'PRODUCTION_BROWSER_SCALE_UNRUN'
  ]
  const workloadDefinition = {
    schema: 'peerit-browser-scale-workload-v1',
    profile: options.profile,
    intents: workload.intents,
    records: workload.records,
    communities: workload.communities,
    pageSize: workload.pageSize,
    generator: 'sequential-intents-round-robin-communities-v1'
  }
  const workloadSha256 = createHash('sha256').update(JSON.stringify(workloadDefinition)).digest('hex')
  const report = {
    schema: 'peerit-browser-scale-matrix-v1',
    evidenceClass: 'MEASURED_LOCAL_DESKTOP_BROWSER_INDEXEDDB_PLAYWRIGHT',
    evidenceDigestAlgorithm: 'sha256-canonical-json-v1',
    evidenceDigestPurpose: 'content-address-only-not-authenticity-or-release-authorization',
    claimBoundary: 'Local headless desktop Playwright engines on one machine only; not mobile, crash recovery, quota exhaustion, network, multi-host, or production evidence.',
    startedAt,
    finishedAt: new Date().toISOString(),
    profile: options.profile,
    workloadDefinition,
    workloadSha256,
    workload: {
      intents: workload.intents,
      records: workload.records,
      communities: workload.communities,
      pageSize: workload.pageSize
    },
    timeoutMs,
    usedOwnedDevServer: options.url == null,
    requestedEngines: [...options.engines],
    coverage: {
      desktopEnginesPassed: passedEngines,
      desktopFullProfileEnginesPassed: readiness.fullProfileEnginesPassed,
      desktopEnginesRequired: [...ALL_ENGINES],
      mobile: false,
      crashRecovery: false,
      quotaExhaustion: false,
      network: false,
      production: false
    },
    results,
    selectedRunPassed: readiness.selectedRunPassed,
    selectedBrowserGateReady: readiness.selectedBrowserGateReady,
    localDesktopMatrixReady: readiness.localDesktopMatrixReady,
    releaseReady: false,
    releaseBlockers
  }
  return { ...report, evidenceDigest: browserScaleEvidenceDigest(report) }
}

async function atomicWriteJson (file, report) {
  const destination = resolve(file)
  const temporary = `${destination}.${process.pid}.tmp`
  await mkdir(dirname(destination), { recursive: true })
  await writeFile(temporary, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 })
  await rename(temporary, destination)
}

async function cleanupActive () {
  const browsers = [...activeBrowsers]
  activeBrowsers.clear()
  await Promise.allSettled(browsers.map(browser => browser.close()))
  if (activeServerChild) await stopDevServer(activeServerChild)
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  let shuttingDown = false
  const shutdown = exitCode => {
    if (shuttingDown) return
    shuttingDown = true
    cleanupActive().then(
      () => process.exit(exitCode),
      () => process.exit(exitCode)
    )
  }
  const onSigint = () => shutdown(130)
  const onSigterm = () => shutdown(143)
  process.once('SIGINT', onSigint)
  process.once('SIGTERM', onSigterm)
  try {
    const report = await runBrowserScaleMatrix(options)
    if (options.out) await atomicWriteJson(options.out, report)
    process.stdout.write(`${JSON.stringify(report)}\n`)
    if (!report.selectedRunPassed) process.exitCode = 1
  } finally {
    process.removeListener('SIGINT', onSigint)
    process.removeListener('SIGTERM', onSigterm)
    await cleanupActive()
  }
}

const invokedPath = process.argv[1] && resolve(process.argv[1])
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch(async error => {
    await cleanupActive()
    process.stderr.write(`[browser-peerit-scale-matrix] FAIL ${errorText(error)}\n`)
    process.exitCode = 1
  })
}
