#!/usr/bin/env node

// First-visit seed-recovery soak harness. Boots the REAL limited Cell-GET
// seed-recovery path (exactly as js/substrate/app-entry.js calls it — no
// timeoutMillis, no concurrency overrides) against the LIVE production
// relays, N times, each time in a FRESH Playwright browser context with a
// sync stub that never persists a discovery floor, so every boot is a true
// cold first visit (recovery.cached === false, full head->genesis walk).
// Optional --describe-delay-ms adds a fixed artificial delay to every
// /api/blind/v1/describe POST (only describes — cell GETs are untouched) to
// simulate a slow long-haul link on the sequential descriptor walk.
//
// Read-only diagnostic: it changes nothing in the repo and installs nothing.
// Exits non-zero when any boot blocks, so it can gate on the reproduction.

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import http from 'node:http'
import path from 'node:path'
import { performance } from 'node:perf_hooks'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const EXPECTED_HEADER_POLICY_SHA256 = 'e672153d1c396e617491fce64ed5472635314e20c45864e959b48e5f1b52b312'
const EXPECTED_CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; " +
  "connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz " +
  "https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'"
const RELAYS = Object.freeze({
  dallas: 'https://relay-dal.p2phiverelay.xyz',
  sydney: 'https://relay-syd.p2phiverelay.xyz'
})
const CELL_PATH = '/api/blind/v1/cell'
const DESCRIBE_PATH = '/api/blind/v1/describe'
const BOOT_RESULT_GLOBAL = '__peeritFirstVisitSoakResult'
const BOOT_TIMEOUT_MS = 480000

function fail (message) {
  throw new Error(message)
}

function argValue (name, fallback = null) {
  const inline = process.argv.find(value => value.startsWith(`${name}=`))
  if (inline != null) return inline.slice(name.length + 1)
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

function optionalNonNegativeInteger (name, fallback) {
  const raw = argValue(name)
  if (raw == null) return fallback
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < 0) fail(`${name} must be a non-negative safe integer`)
  return value
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function exactMeta (html, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const patterns = [
    new RegExp(`<meta\\s+[^>]*name=["']${escaped}["'][^>]*content=["']([^"']*)["'][^>]*>`, 'i'),
    new RegExp(`<meta\\s+[^>]*content=["']([^"']*)["'][^>]*name=["']${escaped}["'][^>]*>`, 'i')
  ]
  const matches = patterns.map(pattern => pattern.exec(html)).filter(Boolean)
  if (matches.length !== 1) fail(`candidate index must contain exactly one ${name} meta value`)
  return matches[0][1]
}

function htmlAttribute (value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function contentType (file) {
  if (file.endsWith('.html')) return 'text/html; charset=utf-8'
  if (file.endsWith('.mjs') || file.endsWith('.js')) return 'text/javascript; charset=utf-8'
  if (file.endsWith('.json')) return 'application/json; charset=utf-8'
  if (file.endsWith('.md')) return 'text/markdown; charset=utf-8'
  if (file.endsWith('.css')) return 'text/css; charset=utf-8'
  if (file.endsWith('.svg')) return 'image/svg+xml'
  if (file.endsWith('.png')) return 'image/png'
  if (file.endsWith('.ico')) return 'image/x-icon'
  return 'application/octet-stream'
}

function send (response, status, type, body, csp) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body)
  response.writeHead(status, {
    'Content-Type': type,
    'Content-Length': bytes.byteLength,
    'Content-Security-Policy': csp,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  })
  response.end(bytes)
}

function median (values) {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  const middle = sorted.length >> 1
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
}

function controllerSource ({ expectedSequence }) {
  return `
import { loadPeeritProductionPinHistoryTerminalV1 } from '/js/substrate/pin-history-bootstrap.mjs';
import { loadPeeritBrowserRuntimeAuthorityV1 } from '/js/substrate/browser-runtime-authority.mjs';
import { recoverPeeritSeedWithLimitedCellGetAuthorityV1 } from '/js/substrate/relay-consumer.js';

const EXPECTED_SEQUENCE=${JSON.stringify(expectedSequence)};
const RELAY_ORIGINS=new Set(${JSON.stringify(Object.values(RELAYS))});
const requests=[];
const violations=[];
let phase='controller-start';
let capturedBatch=null;
let setRelayCalls=0;
const t0=performance.now();

document.addEventListener('securitypolicyviolation', event => {
  violations.push({
    blockedURI:String(event.blockedURI||''),
    effectiveDirective:String(event.effectiveDirective||''),
    violatedDirective:String(event.violatedDirective||'')
  });
});

function cleanError(error){
  return {
    name:String(error&&error.name||'Error'),
    code:error&&typeof error.code==='string'?error.code:null,
    message:String(error&&error.message||error)
  };
}

function nowMs(){return Math.round((performance.now()-t0)*1000)/1000;}

function setPhase(value){phase=value;}

// First-visit sync stub: NEVER persists a floor, so discoveryFloor() always
// returns null and every boot performs the full cold head->genesis walk.
const sync=Object.freeze({
  async discoveryFloor(){return null;},
  async ingestVerifiedRemoteBatch(batch){
    capturedBatch=batch;
    return Object.freeze({captured:true,recordCount:batch.records.length});
  },
  setRelays(){setRelayCalls++;throw new Error('soak forbids relay installation');}
});

async function tracedFetch(input,init={}){
  const requestUrl=new URL(input instanceof Request?input.url:String(input),location.href);
  const external=RELAY_ORIGINS.has(requestUrl.origin);
  let row=null;
  let start=0;
  if(external){
    start=performance.now();
    row={
      atMs:Math.round((start-t0)*1000)/1000,
      phase,
      kind:requestUrl.pathname==='/api/blind/v1/describe'?'describe':(requestUrl.pathname==='/api/blind/v1/cell'?'cell':'other'),
      url:requestUrl.href,
      origin:requestUrl.origin,
      path:requestUrl.pathname,
      method:String((init&&init.method)||(input instanceof Request&&input.method)||'GET').toUpperCase(),
      status:null,
      durationMs:null,
      error:null
    };
    requests.push(row);
    if(phase!=='authority-active')throw new Error('relay request attempted before authenticated authority became active');
  }
  try{
    const response=await fetch(input,init);
    if(row){
      row.status=response.status;
      row.durationMs=Math.round((performance.now()-start)*1000)/1000;
    }
    return response;
  }catch(error){
    if(row){
      row.error=cleanError(error);
      row.durationMs=Math.round((performance.now()-start)*1000)/1000;
    }
    throw error;
  }
}

async function run(){
  setPhase('pin-history-loading');
  const pinHistory=await loadPeeritProductionPinHistoryTerminalV1({document});
  if(!pinHistory.active)throw Object.assign(new Error(pinHistory.message||'pin history inactive'),{code:pinHistory.releaseBlockers&&pinHistory.releaseBlockers[0]});
  const terminalSequence=Number(pinHistory.terminal.terminalSequence);
  if(terminalSequence!==EXPECTED_SEQUENCE)throw new Error('pin-history terminal sequence mismatch');

  setPhase('runtime-authority-loading');
  const authority=await loadPeeritBrowserRuntimeAuthorityV1({
    document,
    pinHistoryTerminal:pinHistory.terminal
  });
  if(!authority.active)throw Object.assign(new Error(authority.message||'browser runtime authority inactive'),{code:authority.releaseBlockers&&authority.releaseBlockers[0]});
  setPhase('authority-active');

  const abort=new AbortController();
  const recoveryStartMs=nowMs();
  // Faithful to js/substrate/app-entry.js: { sync, releaseAuthority, signal }
  // plus a traced fetch for observability. NO timeoutMillis, NO concurrency.
  const recovery=await recoverPeeritSeedWithLimitedCellGetAuthorityV1({
    releaseAuthority:authority.authority,
    sync,
    signal:abort.signal,
    fetch:tracedFetch
  });
  const recoveryWallMs=Math.round((nowMs()-recoveryStartMs)*1000)/1000;
  setPhase('recovery-complete');
  globalThis.${BOOT_RESULT_GLOBAL}={
    ok:recovery.ok===true,
    blocked:false,
    error:null,
    phase,
    terminalSequence,
    recoveryStartMs,
    recoveryWallMs,
    recovery:{
      ok:recovery.ok,
      cached:recovery.cached,
      qualifiedRelayCount:recovery.qualifiedRelayCount,
      networkGets:recovery.networkGets,
      networkPuts:recovery.networkPuts,
      fallbackCount:recovery.fallbackCount,
      ordinaryDelivery:recovery.ordinaryDelivery,
      recordCount:recovery.recordCount
    },
    capturedBatchRecordCount:capturedBatch?capturedBatch.records.length:null,
    requests,
    violations,
    setRelayCalls
  };
}

run().catch(error=>{
  globalThis.${BOOT_RESULT_GLOBAL}={
    ok:false,
    blocked:true,
    error:cleanError(error),
    phase,
    recoveryWallMs:nowMs(),
    requests,
    violations,
    setRelayCalls
  };
});
`
}

const boots = optionalNonNegativeInteger('--boots', 10)
if (boots < 1) fail('--boots must be a positive safe integer')
const describeDelayMs = optionalNonNegativeInteger('--describe-delay-ms', 0)
const describeAbortEvery = optionalNonNegativeInteger('--describe-abort-every', 0)
const describeOutageMs = optionalNonNegativeInteger('--describe-outage-ms', 0)

const candidate = path.resolve(ROOT, argValue('--candidate', 'web'))
const indexBytes = await readFile(path.join(candidate, 'index.html'))
const indexHtml = indexBytes.toString('utf8')
const expectedSequence = Number(exactMeta(indexHtml, 'peerit-release-sequence'))
const meta = {
  pinHistory: exactMeta(indexHtml, 'peerit-production-pin-history'),
  webManifest: exactMeta(indexHtml, 'peerit-production-web-asset-manifest'),
  releaseSequence: String(expectedSequence)
}

const headerPolicyBytes = await readFile(path.join(ROOT, 'deploy/render-security-headers.json'))
const headerPolicySha256 = sha256(headerPolicyBytes)
if (headerPolicySha256 !== EXPECTED_HEADER_POLICY_SHA256) {
  fail(`production header policy hash drifted: ${headerPolicySha256}`)
}
const headers = JSON.parse(headerPolicyBytes.toString('utf8'))
const cspRows = (headers.headers || []).filter(row => row.name === 'Content-Security-Policy')
if (cspRows.length !== 1 || typeof cspRows[0].value !== 'string') fail('render security policy has no unique CSP')
const csp = cspRows[0].value
if (csp !== EXPECTED_CSP) fail(`production CSP bytes drifted: ${sha256(Buffer.from(csp, 'utf8'))}`)
if (/\b(?:wasm-unsafe-eval|unsafe-eval)\b/.test(csp)) fail('production CSP unexpectedly permits dynamic evaluation')

const harness = Buffer.from('<!doctype html><html><head><meta charset="utf-8">' +
  `<meta name="peerit-production-pin-history" content="${htmlAttribute(meta.pinHistory)}">` +
  `<meta name="peerit-production-web-asset-manifest" content="${htmlAttribute(meta.webManifest)}">` +
  `<meta name="peerit-release-sequence" content="${htmlAttribute(meta.releaseSequence)}">` +
  '<script type="module" src="/__peerit_first_visit_soak__.mjs"></script></head><body></body></html>')
const controller = Buffer.from(controllerSource({ expectedSequence }))

const server = http.createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname)
    if (pathname === '/') return send(response, 200, 'text/html; charset=utf-8', harness, csp)
    if (pathname === '/__peerit_first_visit_soak__.mjs') {
      return send(response, 200, 'text/javascript; charset=utf-8', controller, csp)
    }
    const file = path.resolve(candidate, `.${pathname}`)
    if (file !== candidate && !file.startsWith(`${candidate}${path.sep}`)) {
      return send(response, 403, 'text/plain; charset=utf-8', 'forbidden', csp)
    }
    const bytes = await readFile(file)
    send(response, 200, contentType(file), bytes, csp)
  } catch (error) {
    const status = error && error.code === 'ENOENT' ? 404 : 500
    send(response, status, 'text/plain; charset=utf-8', status === 404 ? 'not found' : 'server error', csp)
  }
})

await new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(0, '127.0.0.1', resolve)
})

function summarizeBootRequests (requests) {
  const describes = requests.filter(row => row.path === DESCRIBE_PATH)
  const cells = requests.filter(row => row.path === CELL_PATH)
  const abortedDescribes = describes.filter(row => row.error)
  const abortedCells = cells.filter(row => row.error)
  const failed = requests
    .filter(row => row.error)
    .map(row => ({ row, failedAtMs: Math.round(((row.atMs || 0) + (row.durationMs || 0)) * 1000) / 1000 }))
    .sort((a, b) => a.failedAtMs - b.failedAtMs)
  const first = failed[0] || null
  const httpStatuses = {}
  for (const row of requests) {
    if (row.status == null) continue
    const key = row.kind
    httpStatuses[key] = httpStatuses[key] || {}
    httpStatuses[key][row.status] = (httpStatuses[key][row.status] || 0) + 1
  }
  const durations = rows => rows.length ? Math.max(...rows.map(row => row.durationMs || 0)) : null
  return {
    totalDescribes: describes.length,
    abortedDescribes: abortedDescribes.length,
    totalCellGets: cells.length,
    abortedCellGets: abortedCells.length,
    maxDescribeDurationMs: durations(describes),
    maxCellGetDurationMs: durations(cells),
    httpStatuses,
    firstAbort: first
      ? {
          atMs: first.row.atMs,
          failedAtMs: first.failedAtMs,
          phase: first.row.phase,
          kind: first.row.kind,
          origin: first.row.origin,
          path: first.row.path,
          method: first.row.method,
          durationMs: first.row.durationMs,
          error: first.row.error
        }
      : null
  }
}

async function runBoot (browser, bootIndex) {
  const boot = {
    boot: bootIndex,
    ok: false,
    blocked: true,
    error: null,
    phase: null,
    wallMs: null,
    recoveryStartMs: null,
    recoveryWallMs: null,
    recovery: null,
    totalDescribes: 0,
    abortedDescribes: 0,
    totalCellGets: 0,
    abortedCellGets: 0,
    maxDescribeDurationMs: null,
    maxCellGetDurationMs: null,
    httpStatuses: {},
    firstAbort: null,
    requests: null,
    pageErrors: [],
    consoleErrors: [],
    violations: 0
  }
  const started = performance.now()
  // Fresh context per boot: no shared storage/IndexedDB — a true cold first visit.
  const context = await browser.newContext({ serviceWorkers: 'block' })
  try {
    let describeSeen = 0
    let outageStart = null
    if (describeDelayMs > 0 || describeAbortEvery > 0 || describeOutageMs > 0) {
      for (const origin of Object.values(RELAYS)) {
        await context.route(`${origin}${DESCRIBE_PATH}`, async route => {
          try {
            if (route.request().method() === 'POST') {
              describeSeen++
              // Sustained-outage injection: abort every describe that starts within
              // the first describeOutageMs of the walk (a network-change / handoff
              // blackout window), to prove the bounded retry's ~12s window survives
              // a sustained burst rather than just an isolated abort.
              if (describeOutageMs > 0) {
                if (outageStart === null) outageStart = performance.now()
                if (performance.now() - outageStart < describeOutageMs) {
                  await route.abort('failed')
                  return
                }
              }
              // Deterministically inject a transient transport abort every Nth
              // describe (simulates a dropped connection / network change) to
              // prove the bounded retry absorbs it rather than blocking recovery.
              if (describeAbortEvery > 0 && describeSeen % describeAbortEvery === 0) {
                await route.abort('failed')
                return
              }
              if (describeDelayMs > 0) {
                await new Promise(resolve => setTimeout(resolve, describeDelayMs))
              }
            }
            await route.continue()
          } catch {
            // The page aborted the fetch while the artificial delay was pending
            // (per-request 15s describe timeout); nothing left to continue.
          }
        })
      }
    }
    const page = await context.newPage()
    page.on('pageerror', error => boot.pageErrors.push({ name: error.name, message: error.message }))
    page.on('console', message => {
      if (message.type() === 'error') boot.consoleErrors.push(message.text())
    })
    let result = null
    try {
      await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'load', timeout: 30000 })
      await page.waitForFunction(
        globalName => globalThis[globalName] != null,
        BOOT_RESULT_GLOBAL,
        { timeout: BOOT_TIMEOUT_MS }
      )
      result = await page.evaluate(globalName => globalThis[globalName], BOOT_RESULT_GLOBAL)
    } catch (error) {
      boot.error = {
        name: 'HarnessBootError',
        code: null,
        message: String((error && error.message) || error).split('\n')[0]
      }
      try {
        result = await page.evaluate(globalName => globalThis[globalName], BOOT_RESULT_GLOBAL)
      } catch { /* page already gone */ }
    }
    boot.wallMs = Math.round(performance.now() - started)
    if (result) {
      const summary = summarizeBootRequests(Array.isArray(result.requests) ? result.requests : [])
      Object.assign(boot, summary)
      boot.phase = result.phase || null
      boot.recoveryStartMs = result.recoveryStartMs != null ? result.recoveryStartMs : null
      boot.recoveryWallMs = result.recoveryWallMs != null ? result.recoveryWallMs : null
      boot.recovery = result.recovery || null
      boot.violations = Array.isArray(result.violations) ? result.violations.length : 0
      if (!boot.error) {
        boot.ok = result.ok === true && result.blocked !== true
        boot.blocked = !boot.ok
        boot.error = boot.ok ? null : (result.error || { name: 'Error', code: null, message: 'recovery not ok' })
      }
      if (boot.blocked) boot.requests = result.requests || []
    }
    return boot
  } finally {
    await context.close().catch(() => {})
  }
}

const summary = {
  schema: 'peerit-first-visit-recovery-soak-v1',
  checkedAt: new Date().toISOString(),
  candidate,
  expectedSequence,
  describeDelayMs,
  describeAbortEvery,
  describeOutageMs,
  relays: { ...RELAYS },
  boots: [],
  totals: null
}

const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.PEERIT_GATE_CHROMIUM_EXECUTABLE || undefined
})
try {
  for (let index = 1; index <= boots; index++) {
    const boot = await runBoot(browser, index)
    summary.boots.push(boot)
    process.stderr.write(
      `boot ${index}/${boots} ${boot.ok ? 'ok' : 'BLOCKED'} wall=${boot.wallMs}ms ` +
      `describes=${boot.totalDescribes}(aborted ${boot.abortedDescribes}) ` +
      `cells=${boot.totalCellGets}(aborted ${boot.abortedCellGets})` +
      `${boot.error ? ` error=${JSON.stringify(boot.error)}` : ''}\n`
    )
  }
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}

const blocked = summary.boots.filter(boot => boot.blocked)
const walls = summary.boots.map(boot => boot.wallMs).filter(value => typeof value === 'number')
summary.totals = {
  boots: summary.boots.length,
  ok: summary.boots.length - blocked.length,
  blocks: blocked.length,
  blockedBoots: blocked.map(boot => ({
    boot: boot.boot,
    error: boot.error,
    phase: boot.phase,
    firstAbort: boot.firstAbort,
    wallMs: boot.wallMs,
    recoveryWallMs: boot.recoveryWallMs,
    totalDescribes: boot.totalDescribes,
    abortedDescribes: boot.abortedDescribes,
    totalCellGets: boot.totalCellGets,
    abortedCellGets: boot.abortedCellGets
  })),
  totalDescribes: summary.boots.reduce((sum, boot) => sum + boot.totalDescribes, 0),
  totalAbortedDescribes: summary.boots.reduce((sum, boot) => sum + boot.abortedDescribes, 0),
  totalCellGets: summary.boots.reduce((sum, boot) => sum + boot.totalCellGets, 0),
  totalAbortedCellGets: summary.boots.reduce((sum, boot) => sum + boot.abortedCellGets, 0),
  wallMs: {
    min: walls.length ? Math.min(...walls) : null,
    median: median(walls),
    max: walls.length ? Math.max(...walls) : null
  }
}

process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`)
if (blocked.length > 0) process.exitCode = 1
