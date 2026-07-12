#!/usr/bin/env node

// Measured Chromium fault gate for Peerit's production IndexedDB journal.
// This deliberately kills an externally launched browser process while a real
// IDB put is outstanding, then reopens the same profile. It also uses Chromium's
// test-only CDP quota override to prove transaction rollback and recovery.

import { execFile, spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const HOST = '127.0.0.1'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PAGE_PATH = '/journal-persistence-fault-gate.html'
const execFileAsync = promisify(execFile)
const EXPECTED_GATE_IDS = Object.freeze([
  'OWNED_SOURCE_MODULES',
  'REAL_BROWSER_PROCESS_SIGKILL',
  'IDB_WRITE_OBSERVED_BEFORE_KILL',
  'COMMITTED_PREFIX_ATOMIC',
  'REOPEN_RECOUNT_AND_DIGEST',
  'CONTINUE_AFTER_CRASH',
  'CDP_QUOTA_OVERRIDE_OBSERVED',
  'INJECTED_QUOTA_ERROR_MAPPED',
  'INJECTED_QUOTA_TRANSACTION_ROLLED_BACK',
  'COMMITTED_ROWS_SURVIVE_INJECTED_QUOTA',
  'CONTINUE_AFTER_INJECTED_QUOTA'
])

export const PERSISTENCE_FAULT_PROFILES = Object.freeze({
  smoke: Object.freeze({
    baselineIntents: 12,
    crashRecords: 16,
    quotaPayloadBytes: 850_000,
    timeoutMs: 90_000
  }),
  full: Object.freeze({
    baselineIntents: 256,
    crashRecords: 64,
    quotaPayloadBytes: 1_000_000,
    timeoutMs: 180_000
  })
})

function canonicalJson (value) {
  if (value === null) return 'null'
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('fault evidence contains a non-finite number')
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
  throw new TypeError(`fault evidence contains unsupported ${typeof value}`)
}

export function persistenceFaultContentChecksum (report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new TypeError('fault evidence must be an object')
  }
  const body = { ...report }
  delete body.contentChecksum
  return createHash('sha256').update(canonicalJson(body)).digest('hex')
}

export function verifyPersistenceFaultEvidence (report) {
  const blockers = []
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    return { verified: false, expectedChecksum: null, observedChecksum: null, blockers: ['EVIDENCE_NOT_OBJECT'] }
  }
  if (report.schema !== 'peerit-browser-persistence-fault-v1') blockers.push('EVIDENCE_SCHEMA_INVALID')
  if (report.evidenceClass !== 'MEASURED_LOCAL_CHROMIUM_PROCESS_CRASH_AND_INJECTED_QUOTA') blockers.push('EVIDENCE_CLASS_INVALID')
  if (report.checksumAlgorithm !== 'sha256-canonical-json-v1') blockers.push('CHECKSUM_ALGORITHM_INVALID')
  if (!Object.hasOwn(PERSISTENCE_FAULT_PROFILES, report.profile)) blockers.push('PROFILE_INVALID')
  if (report.authenticityProven !== false) blockers.push('AUTHENTICITY_BOUNDARY_INVALID')
  if (report.releaseReady !== false) blockers.push('RELEASE_BOUNDARY_INVALID')
  const observedChecksum = typeof report.contentChecksum === 'string' ? report.contentChecksum : null
  if (!observedChecksum || !/^[0-9a-f]{64}$/.test(observedChecksum)) blockers.push('CHECKSUM_MISSING_OR_MALFORMED')
  let expectedChecksum = null
  try { expectedChecksum = persistenceFaultContentChecksum(report) } catch { blockers.push('EVIDENCE_NOT_CANONICALIZABLE') }
  if (expectedChecksum && observedChecksum && expectedChecksum !== observedChecksum) blockers.push('CHECKSUM_MISMATCH')

  const gates = Array.isArray(report.gates) ? report.gates : []
  const ids = gates.map(value => value && value.id)
  if (ids.length !== EXPECTED_GATE_IDS.length || ids.some((id, index) => id !== EXPECTED_GATE_IDS[index])) {
    blockers.push('GATE_SET_INVALID')
  }
  const allGatesPass = gates.length === EXPECTED_GATE_IDS.length && gates.every(value => value && value.passed === true)
  if (report.localFaultGateReady !== allGatesPass) blockers.push('LOCAL_GATE_INCONSISTENT')
  const expectedFull = report.profile === 'full' && allGatesPass
  if (report.fullProfileGateReady !== expectedFull) blockers.push('FULL_GATE_INCONSISTENT')
  if (!report.coverage || report.coverage.browserEngine !== 'chromium' ||
      report.coverage.realProcessSigkill !== true || report.coverage.realIndexedDb !== true ||
      report.coverage.cdpQuotaOverrideObserved !== true || report.coverage.injectedQuotaFault !== true ||
      report.coverage.realQuotaExhaustion !== false || report.coverage.otherDesktopEngines !== false ||
      report.coverage.mobile !== false || report.coverage.production !== false) {
    blockers.push('COVERAGE_BOUNDARY_INVALID')
  }
  const boundary = report.claimBoundary
  if (typeof boundary !== 'string' ||
      !['one local Chromium build', 'two isolated local filesystem profiles', 'not Firefox', 'not WebKit', 'not mobile', 'not production', 'not real quota exhaustion', 'not authenticity']
        .every(term => boundary.includes(term))) {
    blockers.push('CLAIM_BOUNDARY_INVALID')
  }
  return { verified: blockers.length === 0, expectedChecksum, observedChecksum, blockers }
}

function usage () {
  return [
    'Usage: node scripts/browser-peerit-persistence-fault.mjs [options]',
    '',
    '  --profile smoke|full       bounded fault workload, default smoke',
    '  --out FILE                 atomically write the JSON report',
    '  --timeout-ms INTEGER       override the phase timeout',
    '  --help                     show this help',
    '',
    'This is local Chromium crash/quota evidence, not cross-browser, mobile, production, or authenticity evidence.'
  ].join('\n')
}

function takeValue (args, index, name) {
  const argument = args[index]
  const equals = argument.indexOf('=')
  if (equals !== -1) return { value: argument.slice(equals + 1), consumed: 0 }
  if (index + 1 >= args.length || args[index + 1].startsWith('--')) throw new Error(`${name} requires a value`)
  return { value: args[index + 1], consumed: 1 }
}

export function parseArgs (args) {
  const options = { profile: 'smoke', out: null, timeoutMs: null, help: false }
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]
    if (argument === '--help') { options.help = true; continue }
    const name = argument.split('=', 1)[0]
    if (!['--profile', '--out', '--timeout-ms'].includes(name)) throw new Error(`unknown argument ${argument}`)
    const { value, consumed } = takeValue(args, index, name)
    index += consumed
    if (!value) throw new Error(`${name} requires a non-empty value`)
    if (name === '--profile') {
      if (!Object.hasOwn(PERSISTENCE_FAULT_PROFILES, value)) throw new Error(`--profile must be smoke or full (received ${value})`)
      options.profile = value
    } else if (name === '--out') {
      options.out = value
    } else {
      const timeoutMs = Number(value)
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10_000 || timeoutMs > 900_000) {
        throw new Error('--timeout-ms must be an integer in 10000..900000')
      }
      options.timeoutMs = timeoutMs
    }
  }
  return options
}

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => { resolve = _resolve; reject = _reject })
  return { promise, resolve, reject }
}

async function withTimeout (promise, timeoutMs, message) {
  let timer = null
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs)
    if (typeof timer.unref === 'function') timer.unref()
  })
  try { return await Promise.race([promise, timeout]) } finally { clearTimeout(timer) }
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

async function waitForHttp (url, child, output, timeoutMs) {
  const deadline = Date.now() + Math.min(timeoutMs, 15_000)
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

async function startDevServer (timeoutMs) {
  const port = await freePort()
  let captured = ''
  const child = spawn(process.execPath, ['dev-server.mjs'], {
    cwd: ROOT,
    env: { ...process.env, HOST, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const capture = chunk => { captured = (captured + String(chunk)).slice(-65_536) }
  child.stdout.on('data', capture)
  child.stderr.on('data', capture)
  const baseUrl = `http://${HOST}:${port}/`
  try { await waitForHttp(`${baseUrl}${PAGE_PATH.slice(1)}`, child, () => captured, timeoutMs) } catch (error) {
    child.kill('SIGKILL')
    throw error
  }
  return { child, baseUrl, output: () => captured }
}

async function stopChild (child, signal = 'SIGTERM') {
  if (!child || child.exitCode != null || child.signalCode != null) return
  const exited = new Promise(resolve => child.once('exit', (code, exitSignal) => resolve({ code, signal: exitSignal })))
  child.kill(signal)
  await Promise.race([
    exited,
    sleep(2000).then(() => {
      if (child.exitCode == null && child.signalCode == null) child.kill('SIGKILL')
    })
  ])
}

async function browserProcesses (userDataDir) {
  const { stdout } = await execFileAsync('ps', ['-axo', 'pid=,ppid=,command='], {
    timeout: 5000,
    maxBuffer: 4 * 1024 * 1024
  })
  return String(stdout).split('\n').flatMap(line => {
    const match = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line)
    if (!match || !match[3].includes(userDataDir)) return []
    return [{ pid: Number(match[1]), ppid: Number(match[2]), command: match[3] }]
  })
}

async function startChromium ({ playwright, userDataDir, timeoutMs }) {
  const context = await playwright.chromium.launchPersistentContext(userDataDir, {
    headless: true,
    timeout: timeoutMs
  })
  const browser = context.browser()
  if (!browser) throw new Error('persistent Chromium context has no browser owner')
  const page = context.pages()[0] || await context.newPage()
  const processes = await browserProcesses(userDataDir)
  const main = processes.find(value => !value.command.includes('--type='))
  if (!main) {
    await context.close().catch(() => {})
    throw new Error('could not identify the unique persistent Chromium process')
  }
  return { browser, context, page, main, processes, userDataDir }
}

async function closeChromium (instance) {
  if (!instance) return
  await instance.context.close().catch(() => {})
  const remaining = await browserProcesses(instance.userDataDir).catch(() => [])
  for (const processInfo of remaining) {
    try { process.kill(processInfo.pid, 'SIGKILL') } catch {}
  }
}

function processExists (pid) {
  try { process.kill(pid, 0); return true } catch { return false }
}

async function killChromiumProcess (instance, timeoutMs) {
  const closed = new Promise(resolve => instance.context.once('close', resolve))
  process.kill(instance.main.pid, 'SIGKILL')
  await withTimeout(closed, timeoutMs, 'SIGKILLed Chromium context did not close')
  const deadline = Date.now() + Math.min(timeoutMs, 5000)
  while (processExists(instance.main.pid) && Date.now() < deadline) await sleep(20)
  const remaining = await browserProcesses(instance.userDataDir).catch(() => [])
  for (const processInfo of remaining) {
    try { process.kill(processInfo.pid, 'SIGKILL') } catch {}
  }
  return { pid: instance.main.pid, signal: 'SIGKILL', exited: !processExists(instance.main.pid) }
}

async function verifyGatePage (page, baseUrl, timeoutMs) {
  await page.goto(new URL(PAGE_PATH, baseUrl).href, { waitUntil: 'domcontentloaded', timeout: timeoutMs })
  const marker = await page.evaluate(() => globalThis.__PEERIT_PERSISTENCE_FAULT_PAGE__ || null)
  if (!marker || marker.schema !== 'peerit-persistence-fault-page-v1' ||
      marker.productionJournalModule !== '/js/substrate/peerit-journal.js') {
    throw new Error('persistence fault page marker does not bind the production journal module')
  }
  return marker
}

async function sourceBindings (baseUrl) {
  const files = [
    'journal-persistence-fault-gate.html',
    'js/substrate/peerit-journal.js',
    'js/substrate/peerit-journal-backend.js'
  ]
  const bindings = []
  for (const file of files) {
    const local = await readFile(join(ROOT, file))
    const response = await fetch(new URL(file, baseUrl), { cache: 'no-store' })
    if (!response.ok) throw new Error(`fault source ${file} returned HTTP ${response.status}`)
    const served = Buffer.from(await response.arrayBuffer())
    const localSha256 = createHash('sha256').update(local).digest('hex')
    const servedSha256 = createHash('sha256').update(served).digest('hex')
    bindings.push({ file, bytes: served.byteLength, localSha256, servedSha256, exact: localSha256 === servedSha256 })
  }
  return bindings
}

async function runCrashPhase ({ playwright, baseUrl, userDataDir, workload, timeoutMs }) {
  const first = await startChromium({ playwright, userDataDir, timeoutMs })
  const baseline = deferred()
  const putIssued = deferred()
  let commitResolvedBeforeKill = false
  let killIssued = false
  let exitResult = null
  try {
    await verifyGatePage(first.page, baseUrl, timeoutMs)
    await first.page.exposeFunction('__peeritFaultEvent', event => {
      if (event && event.phase === 'baseline-ready') baseline.resolve(event)
      if (event && event.phase === 'commit-resolved') commitResolvedBeforeKill = true
      if (event && event.phase === 'idb-put-issued' && !killIssued) {
        killIssued = true
        putIssued.resolve(event)
      }
    })
    const evaluation = first.page.evaluate(async options => {
      const modulePath = '/js/substrate/peerit-journal.js'
      const { createIndexedDbPeeritJournal } = await import(modulePath)
      const id = number => Number(number).toString(16).padStart(64, '0')
      const deleteDatabase = name => new Promise((resolve, reject) => {
        const request = globalThis.indexedDB.deleteDatabase(name)
        request.onsuccess = () => resolve()
        request.onerror = () => reject(request.error)
        request.onblocked = () => reject(new Error(`delete blocked for ${name}`))
      })
      const inputFor = (intentNumber, recordCount) => {
        const records = Array.from({ length: recordCount }, (_, recordNumber) => ({
          key: `fault!${intentNumber}!${recordNumber}`,
          value: { intentNumber, recordNumber, body: `committed-${intentNumber}-${recordNumber}` }
        }))
        return {
          intentId: id(intentNumber),
          logicalId: id(intentNumber + 100000),
          operationBytes: JSON.stringify({ version: 1, operations: records.map(record => ({ type: 'fault-record', data: record.value })) }),
          records,
          createdAt: intentNumber
        }
      }
      const scan = async journal => {
        const rows = []
        let after = null
        for (;;) {
          const page = await journal.rangeView({ gt: after || undefined, limit: 1000 })
          if (!page.length) break
          rows.push(...page)
          after = page[page.length - 1].key
        }
        const bytes = new TextEncoder().encode(JSON.stringify(rows))
        const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
          .map(value => value.toString(16).padStart(2, '0')).join('')
        return { count: rows.length, digest }
      }
      const compactSummary = value => ({
        revision: value.revision,
        viewRevision: value.viewRevision,
        viewRecordCount: value.viewRecordCount,
        intentCount: value.intentCount,
        pendingIntentCount: value.pendingIntentCount,
        intentBytes: value.intentBytes,
        latestIntentId: value.latestIntentId
      })
      await deleteDatabase(options.dbName)
      const journal = createIndexedDbPeeritJournal({
        indexedDB: globalThis.indexedDB,
        IDBKeyRange: globalThis.IDBKeyRange,
        dbName: options.dbName
      })
      await journal.ready()
      for (let intentNumber = 1; intentNumber <= options.baselineIntents; intentNumber++) {
        await journal.commitIntent(inputFor(intentNumber, 1))
      }
      const summary = await journal.summary()
      const scanned = await scan(journal)
      await globalThis.__peeritFaultEvent({ phase: 'baseline-ready', summary: compactSummary(summary), scanned })

      const originalPut = globalThis.IDBObjectStore.prototype.put
      let armed = true
      globalThis.IDBObjectStore.prototype.put = function (...args) {
        const request = Reflect.apply(originalPut, this, args)
        if (armed) {
          armed = false
          queueMicrotask(() => {
            globalThis.__peeritFaultEvent({ phase: 'idb-put-issued', store: this.name }).catch(() => {})
          })
        }
        return request
      }
      const crashInput = inputFor(options.baselineIntents + 1, options.crashRecords)
      journal.commitIntent(crashInput).then(
        () => globalThis.__peeritFaultEvent({ phase: 'commit-resolved' }),
        error => globalThis.__peeritFaultEvent({ phase: 'commit-rejected', error: String(error) })
      )
      await new Promise(() => {})
    }, { dbName: workload.dbName, baselineIntents: workload.baselineIntents, crashRecords: workload.crashRecords })
      .catch(error => String((error && (error.stack || error.message)) || error))

    const baselineEvent = await withTimeout(baseline.promise, timeoutMs, 'baseline commit phase timed out')
    const putEvent = await withTimeout(putIssued.promise, timeoutMs, 'no IndexedDB put was observed before the crash timeout')
    exitResult = await killChromiumProcess(first, timeoutMs)
    await evaluation

    const second = await startChromium({ playwright, userDataDir, timeoutMs })
    try {
      await verifyGatePage(second.page, baseUrl, timeoutMs)
      const recovered = await second.page.evaluate(async options => {
        const modulePath = '/js/substrate/peerit-journal.js'
        const { createIndexedDbPeeritJournal } = await import(modulePath)
        const id = number => Number(number).toString(16).padStart(64, '0')
        const inputFor = (intentNumber, recordCount) => {
          const records = Array.from({ length: recordCount }, (_, recordNumber) => ({
            key: `fault!${intentNumber}!${recordNumber}`,
            value: { intentNumber, recordNumber, body: `committed-${intentNumber}-${recordNumber}` }
          }))
          return {
            intentId: id(intentNumber),
            logicalId: id(intentNumber + 100000),
            operationBytes: JSON.stringify({ version: 1, operations: records.map(record => ({ type: 'fault-record', data: record.value })) }),
            records,
            createdAt: intentNumber
          }
        }
        const scan = async journal => {
          const rows = []
          let after = null
          for (;;) {
            const page = await journal.rangeView({ gt: after || undefined, limit: 1000 })
            if (!page.length) break
            rows.push(...page)
            after = page[page.length - 1].key
          }
          const bytes = new TextEncoder().encode(JSON.stringify(rows))
          const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
            .map(value => value.toString(16).padStart(2, '0')).join('')
          return { rows, digest }
        }
        const compactSummary = value => ({
          revision: value.revision,
          viewRevision: value.viewRevision,
          viewRecordCount: value.viewRecordCount,
          intentCount: value.intentCount,
          pendingIntentCount: value.pendingIntentCount,
          intentBytes: value.intentBytes,
          latestIntentId: value.latestIntentId
        })
        const journal = createIndexedDbPeeritJournal({
          indexedDB: globalThis.indexedDB,
          IDBKeyRange: globalThis.IDBKeyRange,
          dbName: options.dbName
        })
        await journal.ready()
        const crashNumber = options.baselineIntents + 1
        const crashIntent = await journal.getIntent(id(crashNumber))
        const outcome = crashIntent ? 'committed' : 'rolled-back'
        const expectedIntentCount = options.baselineIntents + (crashIntent ? 1 : 0)
        const expectedViewCount = options.baselineIntents + (crashIntent ? options.crashRecords : 0)
        let prefixExact = true
        for (let number = 1; number <= options.baselineIntents; number++) {
          const intent = await journal.getIntent(id(number))
          const row = await journal.getView(`fault!${number}!0`)
          if (!intent || !row || row.intentNumber !== number) prefixExact = false
        }
        let crashRowsPresent = 0
        for (let recordNumber = 0; recordNumber < options.crashRecords; recordNumber++) {
          const row = await journal.getView(`fault!${crashNumber}!${recordNumber}`)
          if (row && row.intentNumber === crashNumber && row.recordNumber === recordNumber) crashRowsPresent++
        }
        const summary = await journal.summary()
        const scanned = await scan(journal)
        const atomic = summary.intentCount === expectedIntentCount &&
          summary.viewRecordCount === expectedViewCount && scanned.rows.length === expectedViewCount &&
          crashRowsPresent === (crashIntent ? options.crashRecords : 0)
        const continuationNumber = crashIntent ? crashNumber + 1 : crashNumber
        await journal.commitIntent(inputFor(continuationNumber, crashIntent ? 1 : options.crashRecords))
        const continued = await journal.getIntent(id(continuationNumber))
        const afterContinue = await journal.summary()
        await journal.close()
        return {
          outcome,
          expectedIntentCount,
          expectedViewCount,
          summary: compactSummary(summary),
          scannedCount: scanned.rows.length,
          scannedDigest: scanned.digest,
          prefixExact,
          crashRowsPresent,
          atomic,
          continuationNumber,
          continued: !!continued,
          afterContinue: compactSummary(afterContinue)
        }
      }, { dbName: workload.dbName, baselineIntents: workload.baselineIntents, crashRecords: workload.crashRecords })
      return {
        baseline: baselineEvent,
        putEvent,
        killIssued,
        exit: exitResult,
        commitResolvedBeforeKill,
        recovered,
        browserVersion: second.browser.version(),
        product: `Chromium/${second.browser.version()}`
      }
    } finally {
      await closeChromium(second)
    }
  } finally {
    if (processExists(first.main.pid)) await closeChromium(first)
  }
}

async function runQuotaPhase ({ playwright, baseUrl, userDataDir, workload, timeoutMs }) {
  const instance = await startChromium({ playwright, userDataDir, timeoutMs })
  const origin = new URL(baseUrl).origin
  try {
    await verifyGatePage(instance.page, baseUrl, timeoutMs)
    const baseline = await instance.page.evaluate(async dbName => {
      const modulePath = '/js/substrate/peerit-journal.js'
      const { createIndexedDbPeeritJournal } = await import(modulePath)
      const id = number => Number(number).toString(16).padStart(64, '0')
      const deleteDatabase = name => new Promise((resolve, reject) => {
        const request = globalThis.indexedDB.deleteDatabase(name)
        request.onsuccess = () => resolve()
        request.onerror = () => reject(request.error)
        request.onblocked = () => reject(new Error(`delete blocked for ${name}`))
      })
      await deleteDatabase(dbName)
      const journal = createIndexedDbPeeritJournal({
        indexedDB: globalThis.indexedDB,
        IDBKeyRange: globalThis.IDBKeyRange,
        dbName
      })
      await journal.ready()
      await journal.commitIntent({
        intentId: id(800001),
        logicalId: id(900001),
        operationBytes: JSON.stringify({ version: 1, operations: [{ type: 'quota-baseline' }] }),
        records: [{ key: 'quota!baseline', value: { durable: true } }],
        createdAt: 1
      })
      const summary = await journal.summary()
      await journal.close()
      return {
        revision: summary.revision,
        viewRevision: summary.viewRevision,
        viewRecordCount: summary.viewRecordCount,
        intentCount: summary.intentCount,
        pendingIntentCount: summary.pendingIntentCount,
        intentBytes: summary.intentBytes,
        latestIntentId: summary.latestIntentId
      }
    }, workload.quotaDbName)

    const session = await instance.context.newCDPSession(instance.page)
    const before = await session.send('Storage.getUsageAndQuota', { origin })
    // Put the origin below its already-committed usage. Existing reads remain
    // available, while every allocating transaction must fail closed.
    const overrideBytes = 1
    await session.send('Storage.overrideQuotaForOrigin', { origin, quotaSize: overrideBytes })
    const overridden = await session.send('Storage.getUsageAndQuota', { origin })
    const attempted = await instance.page.evaluate(async options => {
      const modulePath = '/js/substrate/peerit-journal.js'
      const { createIndexedDbPeeritJournal } = await import(modulePath)
      const id = number => Number(number).toString(16).padStart(64, '0')
      const journal = createIndexedDbPeeritJournal({
        indexedDB: globalThis.indexedDB,
        IDBKeyRange: globalThis.IDBKeyRange,
        dbName: options.dbName
      })
      await journal.ready()
      const randomBytes = new Uint8Array(Math.ceil(options.payloadBytes * 0.75))
      for (let offset = 0; offset < randomBytes.length; offset += 65536) {
        crypto.getRandomValues(randomBytes.subarray(offset, Math.min(offset + 65536, randomBytes.length)))
      }
      let binary = ''
      for (let offset = 0; offset < randomBytes.length; offset += 32768) {
        binary += String.fromCharCode(...randomBytes.subarray(offset, Math.min(offset + 32768, randomBytes.length)))
      }
      const payload = btoa(binary).slice(0, options.payloadBytes)
      let error = null
      const originalPut = globalThis.IDBObjectStore.prototype.put
      let putCount = 0
      globalThis.IDBObjectStore.prototype.put = function (...args) {
        putCount++
        if (putCount === 2) throw new DOMException('injected browser quota boundary', 'QuotaExceededError')
        return Reflect.apply(originalPut, this, args)
      }
      try {
        await journal.commitIntent({
          intentId: id(800002),
          logicalId: id(900002),
          operationBytes: JSON.stringify({ version: 1, operations: [{ type: 'quota-pressure', payload }] }),
          records: Array.from({ length: 16 }, (_, number) => ({
            key: `quota!failed!${number}`,
            value: { number, payload: payload.slice(number * 256, number * 256 + 256) }
          })),
          createdAt: 2
        })
      } catch (caught) {
        error = {
          code: (caught && caught.code) || null,
          name: (caught && caught.name) || null,
          message: String((caught && caught.message) || caught)
        }
      } finally {
        globalThis.IDBObjectStore.prototype.put = originalPut
      }
      const summary = await journal.summary()
      const intent = await journal.getIntent(id(800002))
      const baselineRow = await journal.getView('quota!baseline')
      const failedRow = await journal.getView('quota!failed!0')
      await journal.close()
      return {
        error,
        summary: {
          revision: summary.revision,
          viewRevision: summary.viewRevision,
          viewRecordCount: summary.viewRecordCount,
          intentCount: summary.intentCount,
          pendingIntentCount: summary.pendingIntentCount,
          intentBytes: summary.intentBytes,
          latestIntentId: summary.latestIntentId
        },
        intentPresent: !!intent,
        baselinePresent: !!baselineRow,
        failedRowPresent: !!failedRow
      }
    }, { dbName: workload.quotaDbName, payloadBytes: workload.quotaPayloadBytes })

    await session.send('Storage.overrideQuotaForOrigin', { origin })
    const restored = await session.send('Storage.getUsageAndQuota', { origin })
    await session.detach()
    const continued = await instance.page.evaluate(async dbName => {
      const modulePath = '/js/substrate/peerit-journal.js'
      const { createIndexedDbPeeritJournal } = await import(modulePath)
      const id = number => Number(number).toString(16).padStart(64, '0')
      const journal = createIndexedDbPeeritJournal({
        indexedDB: globalThis.indexedDB,
        IDBKeyRange: globalThis.IDBKeyRange,
        dbName
      })
      await journal.ready()
      await journal.commitIntent({
        intentId: id(800003),
        logicalId: id(900003),
        operationBytes: JSON.stringify({ version: 1, operations: [{ type: 'quota-continued' }] }),
        records: [{ key: 'quota!continued', value: { durable: true } }],
        createdAt: 3
      })
      const summary = await journal.summary()
      const row = await journal.getView('quota!continued')
      const baselineRow = await journal.getView('quota!baseline')
      await journal.close()
      return {
        summary: {
          revision: summary.revision,
          viewRevision: summary.viewRevision,
          viewRecordCount: summary.viewRecordCount,
          intentCount: summary.intentCount,
          pendingIntentCount: summary.pendingIntentCount,
          intentBytes: summary.intentBytes,
          latestIntentId: summary.latestIntentId
        },
        continuedPresent: !!row,
        baselinePresent: !!baselineRow
      }
    }, workload.quotaDbName)
    return { baseline, before, overrideBytes, overridden, attempted, restored, continued }
  } finally {
    await closeChromium(instance)
  }
}

function gate (id, passed, detail) {
  return detail === undefined ? { id, passed: passed === true } : { id, passed: passed === true, detail }
}

export async function runBrowserPersistenceFaultLab (rawOptions = {}) {
  const profile = rawOptions.profile || 'smoke'
  const definition = PERSISTENCE_FAULT_PROFILES[profile]
  if (!definition) throw new Error(`unknown persistence fault profile ${profile}`)
  const timeoutMs = rawOptions.timeoutMs || definition.timeoutMs
  const playwright = await import('playwright')
  const root = await mkdtemp(join(tmpdir(), 'peerit-persistence-fault-'))
  const crashUserDataDir = join(root, 'chromium-crash-profile')
  const quotaUserDataDir = join(root, 'chromium-quota-profile')
  await Promise.all([
    mkdir(crashUserDataDir, { recursive: true, mode: 0o700 }),
    mkdir(quotaUserDataDir, { recursive: true, mode: 0o700 })
  ])
  const runId = `${Date.now()}-${process.pid}`
  const workload = {
    ...definition,
    dbName: `peerit-fault-crash-${runId}`,
    quotaDbName: `peerit-fault-quota-${runId}`
  }
  const server = await startDevServer(timeoutMs)
  try {
    const sources = await sourceBindings(server.baseUrl)
    const startedAt = new Date().toISOString()
    const crash = await runCrashPhase({
      playwright,
      baseUrl: server.baseUrl,
      userDataDir: crashUserDataDir,
      workload,
      timeoutMs
    })
    const quota = await runQuotaPhase({
      playwright,
      baseUrl: server.baseUrl,
      userDataDir: quotaUserDataDir,
      workload,
      timeoutMs
    })
    const quotaRolledBack = quota.attempted.summary.intentCount === quota.baseline.intentCount &&
      quota.attempted.summary.viewRecordCount === quota.baseline.viewRecordCount &&
      quota.attempted.intentPresent === false && quota.attempted.failedRowPresent === false
    const gates = [
      gate('OWNED_SOURCE_MODULES', sources.every(value => value.exact), sources),
      gate('REAL_BROWSER_PROCESS_SIGKILL', crash.killIssued && crash.exit.signal === 'SIGKILL' && crash.exit.exited, crash.exit),
      gate('IDB_WRITE_OBSERVED_BEFORE_KILL', crash.putEvent && crash.putEvent.store && !crash.commitResolvedBeforeKill, {
        putEvent: crash.putEvent,
        commitResolvedBeforeKill: crash.commitResolvedBeforeKill
      }),
      gate('COMMITTED_PREFIX_ATOMIC', crash.recovered.atomic && crash.recovered.prefixExact, crash.recovered),
      gate('REOPEN_RECOUNT_AND_DIGEST', crash.recovered.scannedCount === crash.recovered.expectedViewCount &&
        /^[0-9a-f]{64}$/.test(crash.recovered.scannedDigest), {
        count: crash.recovered.scannedCount,
        digest: crash.recovered.scannedDigest
      }),
      gate('CONTINUE_AFTER_CRASH', crash.recovered.continued === true, crash.recovered.afterContinue),
      gate('CDP_QUOTA_OVERRIDE_OBSERVED', quota.overridden.overrideActive === true && quota.overridden.quota === quota.overrideBytes, {
        before: quota.before,
        overridden: quota.overridden
      }),
      gate('INJECTED_QUOTA_ERROR_MAPPED', quota.attempted.error && quota.attempted.error.code === 'PEERIT_JOURNAL_QUOTA', quota.attempted.error),
      gate('INJECTED_QUOTA_TRANSACTION_ROLLED_BACK', quotaRolledBack, quota.attempted),
      gate('COMMITTED_ROWS_SURVIVE_INJECTED_QUOTA', quota.attempted.baselinePresent === true && quota.continued.baselinePresent === true),
      gate('CONTINUE_AFTER_INJECTED_QUOTA', quota.restored.overrideActive === false &&
        quota.continued.continuedPresent === true && quota.continued.summary.intentCount === quota.baseline.intentCount + 1,
      { restored: quota.restored, continued: quota.continued })
    ]
    const blockers = gates.filter(value => !value.passed).map(value => value.id)
    const body = {
      schema: 'peerit-browser-persistence-fault-v1',
      evidenceClass: 'MEASURED_LOCAL_CHROMIUM_PROCESS_CRASH_AND_INJECTED_QUOTA',
      checksumAlgorithm: 'sha256-canonical-json-v1',
      authenticityProven: false,
      claimBoundary: 'Measured on one local Chromium build and two isolated local filesystem profiles; not Firefox, not WebKit, not mobile, not production, not real quota exhaustion, not physical power loss, and not authenticity evidence.',
      startedAt,
      finishedAt: new Date().toISOString(),
      profile,
      workload: {
        baselineIntents: workload.baselineIntents,
        crashRecords: workload.crashRecords,
        quotaPayloadBytes: workload.quotaPayloadBytes
      },
      environment: {
        node: process.version,
        platform: process.platform,
        arch: process.arch,
        chromiumVersion: crash.browserVersion,
        chromiumProduct: crash.product,
        chromiumExecutable: playwright.chromium.executablePath()
      },
      sources,
      coverage: {
        browserEngine: 'chromium',
        realProcessSigkill: true,
        realIndexedDb: true,
        cdpQuotaOverrideObserved: true,
        injectedQuotaFault: true,
        realQuotaExhaustion: false,
        otherDesktopEngines: false,
        mobile: false,
        physicalPowerLoss: false,
        filesystemCorruption: false,
        production: false
      },
      crash,
      quota,
      gates,
      blockers,
      localFaultGateReady: blockers.length === 0,
      fullProfileGateReady: profile === 'full' && blockers.length === 0,
      releaseReady: false,
      releaseBlockers: [
        'FIREFOX_PROCESS_CRASH_UNRUN',
        'WEBKIT_PROCESS_CRASH_UNRUN',
        'MOBILE_PROCESS_CRASH_UNRUN',
        'REAL_BROWSER_QUOTA_EXHAUSTION_UNRUN',
        'PHYSICAL_POWER_LOSS_UNRUN',
        'FILESYSTEM_CORRUPTION_UNRUN',
        'PRODUCTION_PERSISTENCE_FAULT_UNRUN',
        'SIGNED_RELEASE_ATTESTATION_UNASSEMBLED'
      ]
    }
    return { ...body, contentChecksum: persistenceFaultContentChecksum(body) }
  } finally {
    await stopChild(server.child)
    await rm(root, { recursive: true, force: true })
  }
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
  if (options.help) { process.stdout.write(`${usage()}\n`); return }
  const report = await runBrowserPersistenceFaultLab(options)
  if (options.out) await atomicWriteJson(options.out, report)
  process.stdout.write(`${JSON.stringify(report)}\n`)
  if (!report.localFaultGateReady) process.exitCode = 1
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`[browser-peerit-persistence-fault] FAIL ${String((error && (error.stack || error.message)) || error)}\n`)
    process.exitCode = 1
  })
}
