#!/usr/bin/env node

// Release-only Chromium gate for the exact signed Peerit Web candidate. This
// deliberately stays out of test:ship because live-two-relay performs bounded
// DESCRIBE/health/CELL.GET requests against the signed production relays.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const EXPECTED_HEADER_POLICY_SHA256 = 'e672153d1c396e617491fce64ed5472635314e20c45864e959b48e5f1b52b312'
const EXPECTED_CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; " +
  "connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz " +
  "https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'"
const MODES = new Set(['live-two-relay', 'rollback-preio'])
const RELAYS = Object.freeze({
  dallas: 'https://relay-dal.p2phiverelay.xyz',
  sydney: 'https://relay-syd.p2phiverelay.xyz'
})
const CELL_PATH = '/api/blind/v1/cell'
const DESCRIBE_PATH = '/api/blind/v1/describe'
const VALIDATOR_PATH = '/protocol/validator/peerit-validator-v1.bare.mjs'
const HEX_32 = /^[0-9a-f]{64}$/

function fail (message) {
  throw new Error(message)
}

function argument (name, fallback = null) {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

function requiredInteger (name) {
  const value = Number(argument(name))
  if (!Number.isSafeInteger(value) || value < 1) fail(`${name} must be a positive safe integer`)
  return value
}

function optionalHex32 (name) {
  const value = String(argument(name, '')).trim().toLowerCase()
  if (value && !HEX_32.test(value)) fail(`${name} must be 32-byte lowercase hexadecimal`)
  return value || null
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

function controllerSource ({ mode, expectedSequence }) {
  return `
import { loadPeeritProductionPinHistoryTerminalV1 } from '/js/substrate/pin-history-bootstrap.mjs';
import { loadPeeritBrowserRuntimeAuthorityV1 } from '/js/substrate/browser-runtime-authority.mjs';
import { recoverPeeritSeedWithLimitedCellGetAuthorityV1 } from '/js/substrate/relay-consumer.js';

const MODE=${JSON.stringify(mode)};
const EXPECTED_SEQUENCE=${JSON.stringify(expectedSequence)};
const RELAY_ORIGINS=new Set(${JSON.stringify(Object.values(RELAYS))});
const requests=[];
const violations=[];
let phase='controller-start';
let capturedBatch=null;
let setRelayCalls=0;

globalThis.__peeritPg10Phase=phase;
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

function setPhase(value){phase=value;globalThis.__peeritPg10Phase=value;}

const sync=Object.freeze({
  async discoveryFloor(){return null;},
  async ingestVerifiedRemoteBatch(batch){
    capturedBatch=batch;
    return Object.freeze({captured:true,recordCount:batch.records.length});
  },
  setRelays(){setRelayCalls++;throw new Error('release gate forbids relay installation');}
});

async function tracedFetch(input,init={}){
  const requestUrl=new URL(input instanceof Request?input.url:String(input),location.href);
  const external=RELAY_ORIGINS.has(requestUrl.origin);
  let row=null;
  if(external){
    row={
      phase,
      url:requestUrl.href,
      origin:requestUrl.origin,
      path:requestUrl.pathname,
      method:String((init&&init.method)||(input instanceof Request&&input.method)||'GET').toUpperCase(),
      status:null,
      responseBytes:null,
      error:null
    };
    requests.push(row);
    if(phase!=='authority-active')throw new Error('relay request attempted before authenticated authority became active');
  }
  try{
    const response=await fetch(input,init);
    if(row){
      row.status=response.status;
      if(requestUrl.pathname==='/api/blind/v1/cell'&&response.ok){
        row.responseBytes=(await response.clone().arrayBuffer()).byteLength;
      }
    }
    return response;
  }catch(error){
    if(row)row.error=cleanError(error);
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

  if(MODE==='rollback-preio'){
    let rollbackError=null;
    try{
      await recoverPeeritSeedWithLimitedCellGetAuthorityV1({
        releaseAuthority:authority.authority,
        sync,
        fetch:tracedFetch
      });
    }catch(error){rollbackError=cleanError(error);}
    if(!rollbackError||rollbackError.code!=='PEERIT_LIMITED_CELL_GET_CONTROL_INVALID'){
      throw new Error('rollback recovery did not fail with PEERIT_LIMITED_CELL_GET_CONTROL_INVALID');
    }
    globalThis.__peeritPg10Result={
      mode:MODE,
      expectedSequence:EXPECTED_SEQUENCE,
      terminalSequence,
      authorityActive:true,
      rollbackError,
      requests,
      setRelayCalls,
      violations
    };
    return;
  }

  const recovery=await recoverPeeritSeedWithLimitedCellGetAuthorityV1({
    releaseAuthority:authority.authority,
    sync,
    fetch:tracedFetch,
    timeoutMillis:15000,
    concurrency:4
  });
  if(!capturedBatch)throw new Error('verified remote batch was not presented to the read-only ingest seam');
  globalThis.__peeritPg10Result={
    mode:MODE,
    expectedSequence:EXPECTED_SEQUENCE,
    terminalSequence,
    authorityActive:true,
    recovery:{
      ok:recovery.ok,
      cached:recovery.cached,
      qualifiedRelayCount:recovery.qualifiedRelayCount,
      networkGets:recovery.networkGets,
      networkPuts:recovery.networkPuts,
      fallbackCount:recovery.fallbackCount,
      ordinaryDelivery:recovery.ordinaryDelivery,
      recordCount:recovery.recordCount,
      descriptorHeads:recovery.descriptorHeads.map(row=>({
        relayId:row.relayId,
        descriptorSequence:String(row.descriptorSequence),
        descriptorHeadHash:row.descriptorHeadHash
      }))
    },
    verifiedBatch:{
      releaseSequence:capturedBatch.releaseSequence,
      recordCount:capturedBatch.records.length,
      evidence:capturedBatch.evidence.map(row=>({...row}))
    },
    requests,
    setRelayCalls,
    violations
  };
}

run().catch(error=>{
  globalThis.__peeritPg10Result={
    mode:MODE,
    expectedSequence:EXPECTED_SEQUENCE,
    phase,
    fatal:cleanError(error),
    requests,
    setRelayCalls,
    violations
  };
});
`
}

function assertLiveResult (result, expectedHeads) {
  assert.equal(result.fatal, undefined, `browser runtime gate failed: ${JSON.stringify(result.fatal)}`)
  assert.equal(result.authorityActive, true)
  assert.equal(result.terminalSequence, result.expectedSequence)
  assert.equal(result.recovery.ok, true)
  assert.equal(result.recovery.cached, false)
  assert.equal(result.recovery.qualifiedRelayCount, 2)
  assert.equal(result.recovery.networkGets, 40)
  assert.equal(result.recovery.networkPuts, 0)
  assert.equal(result.recovery.fallbackCount, 1)
  assert.equal(result.recovery.ordinaryDelivery, 'local-only')
  assert.equal(result.recovery.recordCount, 39)
  assert.equal(result.verifiedBatch.releaseSequence, result.expectedSequence)
  assert.equal(result.verifiedBatch.recordCount, 39)
  assert.equal(result.verifiedBatch.evidence.length, 39)
  assert.equal(result.setRelayCalls, 0)
  assert.deepEqual(result.violations, [])

  const heads = new Map(result.recovery.descriptorHeads.map(row => [row.relayId, row]))
  assert.equal(heads.size, 2)
  assert.equal(heads.get('dal-1')?.descriptorHeadHash, expectedHeads.dallas,
    'dal-1 descriptor head does not match the Dallas context lock')
  assert.equal(heads.get('syd-1')?.descriptorHeadHash, expectedHeads.sydney,
    'syd-1 descriptor head does not match the Sydney context lock')

  assert.equal(result.requests.length > 0, true)
  assert.equal(result.requests.every(row => row.phase === 'authority-active'), true,
    'a relay request occurred before authority.active=true')
  assert.equal(result.requests.every(row =>
    Object.values(RELAYS).includes(row.origin) &&
    (row.path === DESCRIBE_PATH || row.path === CELL_PATH)), true,
  'recovery used an undeclared origin or operation route')
  assert.equal(result.requests.some(row => row.url.includes('evidence.example')), false,
    'the signed admission parameter URL was fetched')
  for (const origin of Object.values(RELAYS)) {
    assert.equal(result.requests.some(row => row.origin === origin && row.path === DESCRIBE_PATH), true,
      `${origin} did not complete descriptor/health traffic`)
  }

  const cell = result.requests.filter(row => row.path === CELL_PATH)
  assert.equal(cell.length, 40)
  const successes = cell.filter(row => row.status >= 200 && row.status < 300)
  assert.equal(successes.length, 39)
  const sizeClass1 = successes.filter(row => row.responseBytes === 16384)
  const sizeClass2 = successes.filter(row => row.responseBytes === 65536)
  assert.equal(sizeClass1.length, 36,
    `expected 36 sizeClass-1 Cell GET responses of exactly 16,384 bytes, got ${sizeClass1.length}`)
  assert.equal(sizeClass2.length, 3,
    `expected 3 sizeClass-2 Cell GET responses of exactly 65,536 bytes, got ${sizeClass2.length}`)
  assert.equal(successes.filter(row => row.origin === RELAYS.dallas).length, 38)
  assert.equal(successes.filter(row => row.origin === RELAYS.sydney).length, 1)
  assert.equal(cell.filter(row => row.origin === RELAYS.dallas && row.error).length, 1)

  const evidenceByRelay = new Map()
  for (const row of result.verifiedBatch.evidence) {
    evidenceByRelay.set(row.relayId, (evidenceByRelay.get(row.relayId) || 0) + 1)
  }
  assert.equal(evidenceByRelay.size, 2)
  assert.equal(evidenceByRelay.get('dal-1'), 38,
    'verified readback evidence did not bind 38 records to Dallas')
  assert.equal(evidenceByRelay.get('syd-1'), 1,
    'verified readback evidence did not bind the forced fallback record to Sydney')
}

function assertRollbackResult (result) {
  assert.equal(result.fatal, undefined, `rollback browser gate failed: ${JSON.stringify(result.fatal)}`)
  assert.equal(result.authorityActive, true)
  assert.equal(result.terminalSequence, result.expectedSequence)
  assert.equal(result.rollbackError.code, 'PEERIT_LIMITED_CELL_GET_CONTROL_INVALID')
  assert.deepEqual(result.requests, [])
  assert.equal(result.setRelayCalls, 0)
  assert.deepEqual(result.violations, [])
}

const mode = String(argument('--mode', ''))
if (!MODES.has(mode)) fail('--mode must be live-two-relay or rollback-preio')
const expectedSequence = requiredInteger('--expected-sequence')
// Owner decisions 2026-07-31/08-01: sequence 20 was the LIVE bounded-public-test
// launch slot, 21 its content-type unblock successor, and 22 its compression-tolerant
// successor (limited Cell-GET authority exposed at sequence 22). live-two-relay
// proves the exact signed candidate recovers the 39-record launch seed at
// sequence 22.
// rollback-preio asserts the fail-closed posture everywhere else: the limited
// Cell-GET authority is inert at any sequence != 21, so a candidate built at
// such a sequence must refuse recovery with PEERIT_LIMITED_CELL_GET_CONTROL_INVALID
// before any relay I/O.
if (mode === 'live-two-relay' && expectedSequence !== 28) fail('live-two-relay is authorized only for sequence 28')
if (mode === 'rollback-preio' && expectedSequence === 28) fail('rollback-preio targets only sequences without the limited Cell-GET authority (!= 28)')
const expectedHeads = {
  dallas: optionalHex32('--expected-dallas-head'),
  sydney: optionalHex32('--expected-sydney-head')
}
if (mode === 'live-two-relay' && (!expectedHeads.dallas || !expectedHeads.sydney)) {
  fail('live-two-relay requires --expected-dallas-head and --expected-sydney-head')
}

const candidate = path.resolve(ROOT, argument('--candidate', 'web'))
const indexBytes = await readFile(path.join(candidate, 'index.html'))
const indexHtml = indexBytes.toString('utf8')
const indexSequence = Number(exactMeta(indexHtml, 'peerit-release-sequence'))
if (indexSequence !== expectedSequence) fail(`candidate index sequence ${indexSequence} is not ${expectedSequence}`)
const meta = {
  pinHistory: exactMeta(indexHtml, 'peerit-production-pin-history'),
  webManifest: exactMeta(indexHtml, 'peerit-production-web-asset-manifest'),
  releaseSequence: String(indexSequence)
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
const cspSha256 = sha256(Buffer.from(csp, 'utf8'))
if (csp !== EXPECTED_CSP) fail(`production CSP bytes drifted: ${cspSha256}`)
if (/\b(?:wasm-unsafe-eval|unsafe-eval)\b/.test(csp)) fail('production CSP unexpectedly permits dynamic evaluation')

const harness = Buffer.from('<!doctype html><html><head><meta charset="utf-8">' +
  `<meta name="peerit-production-pin-history" content="${htmlAttribute(meta.pinHistory)}">` +
  `<meta name="peerit-production-web-asset-manifest" content="${htmlAttribute(meta.webManifest)}">` +
  `<meta name="peerit-release-sequence" content="${htmlAttribute(meta.releaseSequence)}">` +
  '<script type="module" src="/__peerit_pg10_gate__.mjs"></script></head><body></body></html>')
const controller = Buffer.from(controllerSource({ mode, expectedSequence }))
const validatorServes = []

const server = http.createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname)
    if (pathname === '/') return send(response, 200, 'text/html; charset=utf-8', harness, csp)
    if (pathname === '/__peerit_pg10_gate__.mjs') {
      return send(response, 200, 'text/javascript; charset=utf-8', controller, csp)
    }
    const file = path.resolve(candidate, `.${pathname}`)
    if (file !== candidate && !file.startsWith(`${candidate}${path.sep}`)) {
      return send(response, 403, 'text/plain; charset=utf-8', 'forbidden', csp)
    }
    const bytes = await readFile(file)
    if (pathname === VALIDATOR_PATH) validatorServes.push(sha256(bytes))
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

const browser = await chromium.launch({
  headless: true,
  // Optional explicit Chromium binary for multi-version gate sweeps (the
  // default remains Playwright's bundled newest build).
  executablePath: process.env.PEERIT_GATE_CHROMIUM_EXECUTABLE || undefined
})
const context = await browser.newContext({ serviceWorkers: 'block' })
const page = await context.newPage()
const pageErrors = []
const consoleErrors = []
let dallasFaults = 0
page.on('pageerror', error => pageErrors.push({ name: error.name, message: error.message }))
page.on('console', message => {
  if (message.type() === 'error') consoleErrors.push(message.text())
})
if (mode === 'live-two-relay') {
  await context.route(`${RELAYS.dallas}${CELL_PATH}`, async route => {
    if (route.request().method() === 'POST' && dallasFaults === 0) {
      dallasFaults++
      await route.abort('failed')
      return
    }
    await route.continue()
  })
}

let result
try {
  await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'load', timeout: 30000 })
  await page.waitForFunction(() => globalThis.__peeritPg10Result != null, null, { timeout: 180000 })
  result = await page.evaluate(() => globalThis.__peeritPg10Result)
  if (mode === 'live-two-relay') assertLiveResult(result, expectedHeads)
  else assertRollbackResult(result)
  assert.deepEqual(pageErrors, [])
  assert.equal(consoleErrors.some(value => /content security policy|refused to|wasm/i.test(value)), false,
    `browser emitted a CSP/runtime console error: ${JSON.stringify(consoleErrors)}`)
  assert.equal(validatorServes.length, 2,
    `validator canonical path was served ${validatorServes.length} times instead of signed-content + SRI exactly twice`)
  assert.equal(new Set(validatorServes).size, 1, 'validator responses were not byte-identical')
  if (mode === 'live-two-relay') assert.equal(dallasFaults, 1)

  const evidence = {
    schema: 'peerit-production-runtime-chromium-gate-v1',
    mode,
    candidate,
    expectedSequence,
    checkedAt: new Date().toISOString(),
    csp,
    cspSha256,
    headerPolicySha256,
    indexSha256: sha256(indexBytes),
    validatorSha256: validatorServes[0],
    validatorCanonicalServes: validatorServes.length,
    dallasFaults,
    pageErrors,
    consoleErrors,
    result
  }
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`)
} finally {
  await page.close()
  await context.close()
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
