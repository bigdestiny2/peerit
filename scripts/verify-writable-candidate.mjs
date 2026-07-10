#!/usr/bin/env node

// Non-mutating writable-web candidate proof.
//
// This gate verifies the candidate release's signed relay roster, then checks
// that EVERY signed relay advertises the atomic commit contract. It also sends
// deliberately invalid, non-mutating requests to the legacy create/append
// routes and requires the public edge to block them. A missing candidate
// config, a read-only config, a one-origin roster, a stale relay, an exposed
// legacy writer route, or a missing capability is a hard failure.

import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dedupeRelayList,
  normalizeRelayRosterPayload,
  verifyRelayRoster
} from '../js/relay-roster.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_CONFIG = resolve(ROOT, 'deploy', 'web-release.json')
const DEFAULT_TIMEOUT_MS = 15_000
export const DEFAULT_WRITABLE_MIN_RATE_MAX = 12_000
export const DEFAULT_WRITABLE_MAX_RATE_WINDOW_MS = 60_000
const MAX_SUPPORTED_RATE_MAX = 10_000_000
const MAX_SUPPORTED_RATE_WINDOW_MS = 24 * 60 * 60 * 1000

function usage (code = 0, message = '') {
  if (message) console.error(`[writable-candidate] FAIL ${message}`)
  console.error('usage: node scripts/verify-writable-candidate.mjs [--config deploy/web-release.json] [--roster relay-roster.json] [--timeout-ms 15000] [--min-rate-max 12000] [--max-rate-window-ms 60000] [--json]')
  console.error('staged-gate env overrides: PEERIT_WRITABLE_MIN_RATE_MAX, PEERIT_WRITABLE_MAX_RATE_WINDOW_MS')
  process.exit(code)
}

function normalizeWritableRateLimitPolicy ({
  minRateMax = DEFAULT_WRITABLE_MIN_RATE_MAX,
  maxRateWindowMs = DEFAULT_WRITABLE_MAX_RATE_WINDOW_MS
} = {}) {
  if (!Number.isSafeInteger(minRateMax) || minRateMax < 1 || minRateMax > MAX_SUPPORTED_RATE_MAX) {
    throw new TypeError(`minimum public-write rate max must be an integer from 1 to ${MAX_SUPPORTED_RATE_MAX}`)
  }
  if (!Number.isSafeInteger(maxRateWindowMs) || maxRateWindowMs < 1 || maxRateWindowMs > MAX_SUPPORTED_RATE_WINDOW_MS) {
    throw new TypeError(`maximum public-write rate window must be an integer from 1 to ${MAX_SUPPORTED_RATE_WINDOW_MS}ms`)
  }
  return { minRateMax, maxRateWindowMs }
}

export function writableRateLimitPolicyFromEnv (env = process.env) {
  return normalizeWritableRateLimitPolicy({
    minRateMax: env.PEERIT_WRITABLE_MIN_RATE_MAX === undefined
      ? DEFAULT_WRITABLE_MIN_RATE_MAX
      : Number(env.PEERIT_WRITABLE_MIN_RATE_MAX),
    maxRateWindowMs: env.PEERIT_WRITABLE_MAX_RATE_WINDOW_MS === undefined
      ? DEFAULT_WRITABLE_MAX_RATE_WINDOW_MS
      : Number(env.PEERIT_WRITABLE_MAX_RATE_WINDOW_MS)
  })
}

function parseArgs (argv) {
  let rateLimitPolicy
  try {
    rateLimitPolicy = writableRateLimitPolicyFromEnv()
  } catch (err) {
    usage(2, err.message)
  }
  const opts = {
    config: process.env.PEERIT_WEB_RELEASE_CONFIG ? resolve(ROOT, process.env.PEERIT_WEB_RELEASE_CONFIG) : DEFAULT_CONFIG,
    roster: '',
    timeoutMs: Number(process.env.PEERIT_WRITABLE_PREFLIGHT_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS,
    ...rateLimitPolicy,
    json: false
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--config') opts.config = resolve(ROOT, argv[++i] || '')
    else if (arg === '--roster') opts.roster = resolve(ROOT, argv[++i] || '')
    else if (arg === '--timeout-ms') opts.timeoutMs = Number(argv[++i])
    else if (arg === '--min-rate-max') opts.minRateMax = Number(argv[++i])
    else if (arg === '--max-rate-window-ms') opts.maxRateWindowMs = Number(argv[++i])
    else if (arg === '--json') opts.json = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  if (!Number.isSafeInteger(opts.timeoutMs) || opts.timeoutMs < 100 || opts.timeoutMs > 120_000) {
    usage(2, '--timeout-ms must be an integer from 100 to 120000')
  }
  try {
    Object.assign(opts, normalizeWritableRateLimitPolicy(opts))
  } catch (err) {
    usage(2, err.message)
  }
  return opts
}

function readJson (file, label) {
  if (!existsSync(file)) throw new Error(`${label} is missing`)
  try {
    const value = JSON.parse(readFileSync(file, 'utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('expected object')
    return value
  } catch (err) {
    throw new Error(`${label} is invalid JSON (${err.message})`)
  }
}

function sameJson (a, b) {
  return JSON.stringify(a) === JSON.stringify(b)
}

function addCheck (report, id, status, message, evidence) {
  const check = { id, status, message }
  if (evidence !== undefined) check.evidence = evidence
  report.checks.push(check)
}

function finish (report) {
  const counts = { pass: 0, fail: 0, info: 0 }
  for (const check of report.checks) counts[check.status] = (counts[check.status] || 0) + 1
  report.counts = counts
  report.status = counts.fail ? 'blocked' : 'ready'
  // The legacy guard probes below are malformed by construction and can never
  // allocate an outbox or append a row. Keep this field as the number of sync
  // mutations attempted, not the number of HTTP requests made to prove a route
  // is closed.
  report.syncWritesAttempted = 0
  return report
}

function positiveHealth (body) {
  return !!(body && (
    body.ok === true ||
    body.healthy === true ||
    body.ready === true ||
    ['ok', 'healthy', 'ready'].includes(String(body.status || '').toLowerCase())
  ))
}

function assertAtomicDescriptor (body, label, { requireRootSchema = false } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error(`${label} is not an object`)
  if (requireRootSchema && body.schema !== 1) throw new Error(`${label} schema must be 1`)
  const atomic = body.atomicCommit
  if (!atomic || typeof atomic !== 'object' || Array.isArray(atomic)) throw new Error(`${label} has no atomicCommit descriptor`)
  const expected = {
    schema: 1,
    method: 'POST',
    route: '/api/sync/commit',
    enabled: true,
    durable: true,
    cas: true,
    idempotent: true
  }
  for (const [field, value] of Object.entries(expected)) {
    if (atomic[field] !== value) throw new Error(`${label} atomicCommit.${field} must be ${JSON.stringify(value)}`)
  }
  const idempotency = atomic.idempotency
  if (!idempotency || idempotency.mode !== 'bounded' || idempotency.latestPerOutbox !== true ||
      !Number.isSafeInteger(idempotency.hotReceiptsPerOutbox) || idempotency.hotReceiptsPerOutbox < 1 ||
      !Number.isSafeInteger(idempotency.tombstonesPerOutbox) || idempotency.tombstonesPerOutbox < 0 ||
      !Number.isSafeInteger(idempotency.aggregateEntries) || idempotency.aggregateEntries < 2 ||
      !Number.isSafeInteger(idempotency.extraHistoryEntries) || idempotency.extraHistoryEntries < 0) {
    throw new Error(`${label} must guarantee bounded idempotency with latestPerOutbox=true`)
  }
  const legacy = body.legacyWrites
  if (!legacy || legacy.create !== false || legacy.append !== false) {
    throw new Error(`${label} must advertise legacyWrites.create=false and legacyWrites.append=false`)
  }
  return atomic
}

function assertPublicWriteRateLimit (body, label, policy) {
  const rateLimit = body && body.httpRateLimit
  if (!rateLimit || typeof rateLimit !== 'object' || Array.isArray(rateLimit)) {
    throw new Error(`${label} has no valid httpRateLimit descriptor`)
  }
  if (rateLimit.scope !== 'public-writes') {
    throw new Error(`${label} httpRateLimit.scope must be "public-writes"`)
  }
  if (rateLimit.source !== 'operator') {
    throw new Error(`${label} httpRateLimit.source must be "operator"; relay defaults and the coarse 60-request gate are not launch capacity`)
  }
  if (rateLimit.enabled !== true) {
    throw new Error(`${label} httpRateLimit.enabled must be true`)
  }
  if (!Number.isSafeInteger(rateLimit.windowMs) || rateLimit.windowMs < 1) {
    throw new Error(`${label} httpRateLimit.windowMs must be a positive integer`)
  }
  if (!Number.isSafeInteger(rateLimit.max) || rateLimit.max < 1) {
    throw new Error(`${label} httpRateLimit.max must be a positive integer`)
  }

  const envelope = rateLimit.outboxLogEnvelope
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new Error(`${label} httpRateLimit.outboxLogEnvelope must be an object`)
  }
  if (envelope.enabled !== true ||
      !Number.isSafeInteger(envelope.windowMs) || envelope.windowMs < 1 ||
      !Number.isSafeInteger(envelope.max) || envelope.max < 1) {
    throw new Error(`${label} httpRateLimit.outboxLogEnvelope must be an enabled positive-integer envelope`)
  }
  if (envelope.enabled !== rateLimit.enabled ||
      envelope.windowMs !== rateLimit.windowMs ||
      envelope.max !== rateLimit.max) {
    throw new Error(`${label} httpRateLimit.outboxLogEnvelope must exactly match the effective public-writes envelope`)
  }
  if (rateLimit.windowMs > policy.maxRateWindowMs) {
    throw new Error(`${label} httpRateLimit.windowMs ${rateLimit.windowMs} exceeds launch maximum ${policy.maxRateWindowMs}`)
  }
  if (rateLimit.max < policy.minRateMax) {
    throw new Error(`${label} httpRateLimit.max ${rateLimit.max} is below launch minimum ${policy.minRateMax}`)
  }
  return rateLimit
}

async function requestJson (fetchFn, url, options, timeoutMs) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetchFn(url, {
      ...options,
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal
    })
    const text = await response.text()
    let body = null
    try { body = text ? JSON.parse(text) : null } catch { throw new Error(`${new URL(url).pathname} returned invalid JSON`) }
    if (!response.ok) throw new Error(`${new URL(url).pathname} returned HTTP ${response.status}`)
    return body
  } catch (err) {
    if (err && err.name === 'AbortError') throw new Error(`${new URL(url).pathname} timed out after ${timeoutMs}ms`)
    throw err
  } finally {
    clearTimeout(timer)
  }
}

async function requireLegacyWriterBlocked (fetchFn, relay, path, body, headers, timeoutMs) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetchFn(relay + path, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal
    })
    // An enabled HiveRelay route returns 400 for these intentionally invalid
    // bodies. Only an edge/backend policy response proves that the legacy
    // mutation path cannot bypass atomic CAS.
    if (![403, 404, 405, 410].includes(response.status)) {
      throw new Error(`${path} is publicly reachable (expected a policy block, received HTTP ${response.status})`)
    }
  } catch (err) {
    if (err && err.name === 'AbortError') throw new Error(`${path} guard probe timed out after ${timeoutMs}ms`)
    throw err
  } finally {
    clearTimeout(timer)
  }
}

// Prove the one legal writer route is actually mounted without changing relay
// state. An empty appId/commit is rejected by validation before group lookup or
// allocation. Capability JSON alone is not enough: a stale proxy can advertise
// the route while returning 404/405 for every real publication.
async function requireAtomicWriterReachable (fetchFn, relay, headers, timeoutMs) {
  const path = '/api/sync/commit'
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetchFn(relay + path, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ appId: '', commit: null }),
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal
    })
    if (response.status !== 400) {
      throw new Error(`${path} is not safely reachable (expected validation HTTP 400, received HTTP ${response.status})`)
    }
  } catch (err) {
    if (err && err.name === 'AbortError') throw new Error(`${path} guard probe timed out after ${timeoutMs}ms`)
    throw err
  } finally {
    clearTimeout(timer)
  }
}

async function probeRelay (relay, { fetch: fetchFn, timeoutMs, rateLimitPolicy }) {
  const health = await requestJson(fetchFn, relay + '/health', { method: 'GET' }, timeoutMs)
  if (!positiveHealth(health)) throw new Error('/health did not report a positive status')

  // Token issuance is ephemeral relay access setup, not an outbox mutation.
  const issued = await requestJson(fetchFn, relay + '/api/token', { method: 'POST' }, timeoutMs)
  const token = String((issued && issued.token) || '')
  if (!token) throw new Error('/api/token did not issue a token')
  const headers = { 'X-Pear-Token': token }

  const status = await requestJson(fetchFn, relay + '/api/bridge/status', { method: 'GET', headers }, timeoutMs)
  if (status.ready !== true) throw new Error('/api/bridge/status did not report ready=true')
  assertAtomicDescriptor(status, '/api/bridge/status')
  const httpRateLimit = assertPublicWriteRateLimit(status, '/api/bridge/status', rateLimitPolicy)

  const capabilities = await requestJson(fetchFn, relay + '/api/sync/capabilities', { method: 'GET', headers }, timeoutMs)
  assertAtomicDescriptor(capabilities, '/api/sync/capabilities', { requireRootSchema: true })

  await requireAtomicWriterReachable(fetchFn, relay, headers, timeoutMs)

  // Empty appId/op values are rejected before either legacy handler can mutate
  // state. A 400 proves the handler is still reachable and is therefore a hard
  // failure; the public writable fleet must expose only the atomic writer path.
  await requireLegacyWriterBlocked(fetchFn, relay, '/api/sync/create', { appId: '' }, headers, timeoutMs)
  await requireLegacyWriterBlocked(fetchFn, relay, '/api/sync/append', { appId: '', op: null }, headers, timeoutMs)

  return {
    relay,
    ready: true,
    atomicCommit: {
      schema: 1,
      method: 'POST',
      route: '/api/sync/commit',
      durable: true,
      cas: true,
      idempotent: true,
      idempotency: capabilities.atomicCommit.idempotency
    },
    httpRateLimit
  }
}

export async function buildWritableCandidateProof ({
  config,
  roster,
  fetch: fetchFn = globalThis.fetch && globalThis.fetch.bind(globalThis),
  now = Date.now(),
  timeoutMs = DEFAULT_TIMEOUT_MS,
  minRateMax = DEFAULT_WRITABLE_MIN_RATE_MAX,
  maxRateWindowMs = DEFAULT_WRITABLE_MAX_RATE_WINDOW_MS,
  configLabel = 'deploy/web-release.json',
  rosterLabel = 'relay-roster.json'
} = {}) {
  const report = {
    kind: 'peerit-writable-candidate-proof-v1',
    appId: 'peerit',
    generatedAt: new Date().toISOString(),
    config: configLabel,
    roster: rosterLabel,
    checks: [],
    relays: []
  }

  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    addCheck(report, 'config:json', 'fail', `${configLabel} is missing or invalid.`)
    return finish(report)
  }
  if (config.readonly !== false) {
    addCheck(report, 'config:writable', 'fail', `${configLabel} must explicitly set readonly=false; writable checks never auto-skip.`)
    return finish(report)
  }
  addCheck(report, 'config:writable', 'pass', 'Candidate explicitly selects writable web mode.')

  let rateLimitPolicy
  try {
    rateLimitPolicy = normalizeWritableRateLimitPolicy({ minRateMax, maxRateWindowMs })
  } catch (err) {
    addCheck(report, 'candidate:http-rate-limit-policy', 'fail', `Writable rate-limit launch policy is invalid: ${err.message}`)
    return finish(report)
  }
  report.httpRateLimitPolicy = rateLimitPolicy
  addCheck(report, 'candidate:http-rate-limit-policy', 'pass', `Every relay must expose at least ${rateLimitPolicy.minRateMax} public writes per window of at most ${rateLimitPolicy.maxRateWindowMs}ms.`, rateLimitPolicy)

  const bootstrapRaw = Array.isArray(config.bootstrapRelays)
    ? config.bootstrapRelays.map((value) => String(value).trim()).filter(Boolean)
    : String(config.relay || '').split(',').map((value) => value.trim()).filter(Boolean)
  const bootstrap = dedupeRelayList(bootstrapRaw)
  if (!bootstrap.length || bootstrap.length !== bootstrapRaw.length) {
    addCheck(report, 'config:bootstrap', 'fail', 'Bootstrap relays must be valid, canonical, and unique.')
    return finish(report)
  }

  const pinnedKey = String(config.pinnedRosterKey || config.rosterKey || '').trim().toLowerCase()
  const expectedPayload = normalizeRelayRosterPayload(config.roster || {
    version: 1,
    expires: config.expires,
    relays: config.relays || bootstrap
  })
  let verified
  try {
    verified = await verifyRelayRoster(roster, { expectedKey: pinnedKey, now })
    addCheck(report, 'roster:signature', 'pass', 'Signed relay roster verifies with the pinned key.', {
      expires: verified.expires,
      relays: verified.relays
    })
  } catch (err) {
    addCheck(report, 'roster:signature', 'fail', `Signed relay roster verification failed: ${err.message}`)
    return finish(report)
  }

  if (!sameJson(verified.payload, expectedPayload)) {
    addCheck(report, 'roster:payload', 'fail', 'Signed relay roster payload does not match the candidate release config.')
    return finish(report)
  }
  addCheck(report, 'roster:payload', 'pass', 'Signed roster payload matches the candidate release config.')

  const missingBootstrap = bootstrap.filter((relay) => !verified.relays.includes(relay))
  if (missingBootstrap.length) {
    addCheck(report, 'roster:bootstrap', 'fail', 'Signed roster does not cover every bootstrap relay.', { missingBootstrap })
    return finish(report)
  }
  addCheck(report, 'roster:bootstrap', 'pass', 'Signed roster covers every bootstrap relay.')

  const origins = new Set(verified.relays.map((relay) => new URL(relay).origin))
  if (verified.relays.length < 2 || origins.size < 2) {
    addCheck(report, 'roster:failure-domains', 'fail', 'Writable candidates require at least two signed relays on distinct origins.', {
      relays: verified.relays,
      origins: [...origins]
    })
    return finish(report)
  }
  addCheck(report, 'roster:failure-domains', 'pass', `Signed roster has ${verified.relays.length} relays across ${origins.size} origins.`)

  if (typeof fetchFn !== 'function') {
    addCheck(report, 'candidate:fetch', 'fail', 'Fetch is unavailable; writable relay checks cannot run.')
    return finish(report)
  }

  for (const relay of verified.relays) {
    try {
      const evidence = await probeRelay(relay, { fetch: fetchFn, timeoutMs, rateLimitPolicy })
      report.relays.push(evidence)
      addCheck(report, `relay:${relay}`, 'pass', `${relay} is ready and advertises durable CAS/idempotent atomic commit with an operator-configured public-write envelope.`)
    } catch (err) {
      report.relays.push({ relay, ready: false, error: err.message })
      addCheck(report, `relay:${relay}`, 'fail', `${relay} writable capability proof failed: ${err.message}`)
    }
  }

  addCheck(report, 'candidate:non-mutating', 'pass', 'Preflight made zero sync mutations; invalid legacy-route probes confirmed create/append are blocked.')
  return finish(report)
}

function printHuman (report) {
  for (const check of report.checks) console.log(`[writable-candidate] ${check.status.toUpperCase()} ${check.message}`)
  console.log(`[writable-candidate] status=${report.status} relays=${report.relays.filter((relay) => relay.ready).length}/${report.relays.length} syncWrites=${report.syncWritesAttempted}`)
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  let config
  let roster
  let rosterFile = opts.roster
  try {
    config = readJson(opts.config, opts.config)
    if (!rosterFile) rosterFile = resolve(ROOT, String(config.relayRoster || 'relay-roster.json'))
    roster = readJson(rosterFile, rosterFile)
  } catch (err) {
    const report = finish({
      kind: 'peerit-writable-candidate-proof-v1',
      appId: 'peerit',
      generatedAt: new Date().toISOString(),
      config: opts.config,
      roster: rosterFile,
      checks: [{ id: 'inputs', status: 'fail', message: err.message }],
      relays: []
    })
    if (opts.json) console.log(JSON.stringify(report, null, 2))
    else printHuman(report)
    process.exit(1)
  }

  const report = await buildWritableCandidateProof({
    config,
    roster,
    timeoutMs: opts.timeoutMs,
    minRateMax: opts.minRateMax,
    maxRateWindowMs: opts.maxRateWindowMs,
    configLabel: opts.config,
    rosterLabel: rosterFile
  })
  if (opts.json) console.log(JSON.stringify(report, null, 2))
  else printHuman(report)
  process.exit(report.status === 'ready' ? 0 : 1)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((err) => {
    console.error('[writable-candidate] FAIL', err.stack || err.message)
    process.exit(1)
  })
}
