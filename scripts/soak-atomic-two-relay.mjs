#!/usr/bin/env node

// Bounded release-candidate exercise for Peerit's public writer path.
//
// This is deliberately different from soak-outboxlog.mjs: it runs two real
// HiveRelay RelayAPI + OutboxLog instances with fsynced JSONL journals, disables
// legacy create/append, uses Peerit's signed-roster relay pool and atomic client,
// loses a real HTTP response after one relay has committed, recreates both
// relays without flushing their engines, and then verifies recovery from disk.

import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { createData } from '../js/data.js'
import { DevIdentity } from '../js/identity.js'
import { outboxCensus, censusString } from '../js/canon.js'
import { ready as cryptoReady, hashHex, isSecure } from '../js/crypto.js'
import { keys, TYPE } from '../js/model.js'
import { makeValidator } from '../js/pow.js'
import { createRelayPool } from '../js/relay-pool.js'
import { createSync } from '../js/sync.js'
import { verifyRecord } from '../js/verify.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_HIVERELAY_ROOT = resolve(ROOT, '../../00-core/hiverelay')
const BITS = { community: 4, post: 4, comment: 4, profile: 0, blob: 0 }

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error(`usage: node scripts/soak-atomic-two-relay.mjs [options]

Options:
  --hiverelay-root <dir>  HiveRelay checkout containing atomic OutboxLog
  --clients <n>           Concurrent writers (default: 6)
  --iterations <n>        Posts per writer (default: 3)
  --restarts <n>          Unflushed relay recreation cycles (default: 2)
  --commit-timeout-ms <n> Per-relay atomic commit deadline (default: 5000)
  --traffic-profile <p>   shared-nat or distributed (default: shared-nat)
  --rate-limit-max <n>    Fixture requests per IP/window (default: 1200)
  --rate-limit-window-ms <n> Fixture rate window (default: 60000)
  --disable-rate-limit    Distributed engine isolation only
  --out <file>            Write JSON evidence report
  --keep-temp             Preserve journals for inspection
  -h, --help              Show this help
`)
  process.exit(code)
}

function positiveInt (value, fallback, max = 1000) {
  const n = Number(value)
  return Number.isSafeInteger(n) && n > 0 && n <= max ? n : fallback
}

function parseArgs (argv) {
  const opts = {
    hiverelayRoot: process.env.HIVERELAY_ROOT || DEFAULT_HIVERELAY_ROOT,
    clients: positiveInt(process.env.PEERIT_ATOMIC_SOAK_CLIENTS, 6, 200),
    iterations: positiveInt(process.env.PEERIT_ATOMIC_SOAK_ITERATIONS, 3, 1000),
    restarts: positiveInt(process.env.PEERIT_ATOMIC_SOAK_RESTARTS, 2, 100),
    commitTimeoutMs: positiveInt(process.env.PEERIT_ATOMIC_SOAK_COMMIT_TIMEOUT_MS, 5000, 120000),
    trafficProfile: process.env.PEERIT_ATOMIC_SOAK_TRAFFIC_PROFILE || 'shared-nat',
    rateLimitMax: positiveInt(process.env.PEERIT_ATOMIC_SOAK_RATE_LIMIT_MAX, 1200, 10_000_000),
    rateLimitWindowMs: positiveInt(process.env.PEERIT_ATOMIC_SOAK_RATE_LIMIT_WINDOW_MS, 60_000, 24 * 60 * 60 * 1000),
    disableRateLimit: process.env.PEERIT_ATOMIC_SOAK_DISABLE_RATE_LIMIT === '1',
    out: process.env.PEERIT_ATOMIC_SOAK_REPORT || '',
    keepTemp: false
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--hiverelay-root') opts.hiverelayRoot = argv[++i] || ''
    else if (arg === '--clients') opts.clients = positiveInt(argv[++i], 0, 200)
    else if (arg === '--iterations') opts.iterations = positiveInt(argv[++i], 0, 1000)
    else if (arg === '--restarts') opts.restarts = positiveInt(argv[++i], 0, 100)
    else if (arg === '--commit-timeout-ms') opts.commitTimeoutMs = positiveInt(argv[++i], 0, 120000)
    else if (arg === '--traffic-profile') opts.trafficProfile = argv[++i] || ''
    else if (arg === '--rate-limit-max') opts.rateLimitMax = positiveInt(argv[++i], 0, 10_000_000)
    else if (arg === '--rate-limit-window-ms') opts.rateLimitWindowMs = positiveInt(argv[++i], 0, 24 * 60 * 60 * 1000)
    else if (arg === '--disable-rate-limit') opts.disableRateLimit = true
    else if (arg === '--out') opts.out = argv[++i] || ''
    else if (arg === '--keep-temp') opts.keepTemp = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  if (!opts.clients || !opts.iterations || !opts.restarts || !opts.commitTimeoutMs || !opts.rateLimitMax || !opts.rateLimitWindowMs) usage(2, 'numeric load, timeout, and rate-limit options must be positive integers')
  if (!['shared-nat', 'distributed'].includes(opts.trafficProfile)) usage(2, 'traffic-profile must be shared-nat or distributed')
  if (opts.disableRateLimit && opts.trafficProfile !== 'distributed') usage(2, 'disable-rate-limit is permitted only with traffic-profile=distributed')
  opts.hiverelayRoot = resolve(ROOT, opts.hiverelayRoot || DEFAULT_HIVERELAY_ROOT)
  if (opts.out) opts.out = resolve(ROOT, opts.out)
  return opts
}

function memoryStore () {
  const values = new Map()
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
    clear: () => values.clear()
  }
}

function percentile (values, p) {
  if (!values.length) return 0
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * p) - 1))]
}

function fixtureRateLimitConfig (opts) {
  return opts.disableRateLimit
    ? false
    : { enabled: true, windowMs: opts.rateLimitWindowMs, max: opts.rateLimitMax }
}

function expectedHttpRateLimit (opts) {
  const enabled = !opts.disableRateLimit
  return {
    scope: 'public-writes',
    source: 'operator',
    enabled,
    windowMs: opts.rateLimitWindowMs,
    max: enabled ? opts.rateLimitMax : null,
    outboxLogEnvelope: {
      enabled,
      windowMs: opts.rateLimitWindowMs,
      max: enabled ? opts.rateLimitMax : null
    }
  }
}

function assertHttpRateLimit (status, expected, label) {
  const actual = status && status.httpRateLimit
  const same = actual &&
    actual.scope === expected.scope &&
    actual.source === expected.source &&
    actual.enabled === expected.enabled &&
    actual.windowMs === expected.windowMs &&
    actual.max === expected.max &&
    actual.outboxLogEnvelope &&
    actual.outboxLogEnvelope.enabled === expected.outboxLogEnvelope.enabled &&
    actual.outboxLogEnvelope.windowMs === expected.outboxLogEnvelope.windowMs &&
    actual.outboxLogEnvelope.max === expected.outboxLogEnvelope.max
  if (!same) throw new Error(`${label}: advertised HTTP rate envelope mismatch (expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)})`)
}

function resourceSnapshot (phase) {
  const memory = process.memoryUsage()
  const usage = typeof process.resourceUsage === 'function' ? process.resourceUsage() : null
  return {
    phase,
    at: new Date().toISOString(),
    memoryBytes: {
      rss: memory.rss,
      heapTotal: memory.heapTotal,
      heapUsed: memory.heapUsed,
      external: memory.external,
      arrayBuffers: memory.arrayBuffers
    },
    usage
  }
}

function resourceSummary (samples) {
  const last = samples[samples.length - 1] || null
  return {
    peakObservedRssBytes: Math.max(0, ...samples.map(sample => sample.memoryBytes.rss)),
    peakObservedHeapUsedBytes: Math.max(0, ...samples.map(sample => sample.memoryBytes.heapUsed)),
    processMaxRssKilobytes: last && last.usage ? last.usage.maxRSS : null,
    final: last
  }
}

function tail (value, max = 4000) {
  const text = String(value || '')
  return text.length > max ? text.slice(-max) : text
}

function diagnosticValue (value, depth = 0, seen = new Set()) {
  if (value == null || typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'string') return tail(value, 2000)
  if (typeof value !== 'object') return String(value)
  if (depth >= 5) return '[depth-limited]'
  if (seen.has(value)) return '[circular]'
  seen.add(value)
  if (Array.isArray(value)) return value.slice(0, 50).map(item => diagnosticValue(item, depth + 1, seen))
  const out = {}
  for (const [key, item] of Object.entries(value).slice(0, 80)) {
    if (/^(?:apiToken|token|inviteKey)$/i.test(key)) out[key] = '[redacted]'
    else out[key] = diagnosticValue(item, depth + 1, seen)
  }
  return out
}

function errorReport (error, depth = 0, seen = new Set()) {
  if (!error || depth >= 8) return null
  if (seen.has(error)) return { message: '[circular error cause]' }
  seen.add(error)
  const report = {
    name: error.name || 'Error',
    message: tail(error.message || error, 4000)
  }
  for (const key of ['code', 'status', 'stale', 'operation', 'client', 'clientIndex', 'iteration']) {
    if (error[key] !== undefined) report[key] = error[key]
  }
  if (error.failures !== undefined) report.failures = diagnosticValue(error.failures)
  if (error.receipts !== undefined) report.receipts = diagnosticValue(error.receipts)
  if (error.response !== undefined) report.response = diagnosticValue(error.response)
  if (error.stack) report.stack = tail(error.stack, 10000)
  if (error.cause) report.cause = errorReport(error.cause, depth + 1, seen)
  if (Array.isArray(error.errors)) report.errors = error.errors.slice(0, 100).map(item => errorReport(item, depth + 1, seen))
  return report
}

function contextualError (error, context) {
  const label = [context.client, context.operation, context.iteration == null ? '' : `iteration=${context.iteration}`].filter(Boolean).join(' ')
  const wrapped = new Error(`${label}: ${error && error.message ? error.message : error}`, { cause: error })
  Object.assign(wrapped, context)
  if (error && error.code !== undefined) wrapped.code = error.code
  if (error && error.status !== undefined) wrapped.status = error.status
  return wrapped
}

function createFetchTelemetry (realFetch = fetch) {
  const rows = new Map()
  let total = 0
  const wrapped = async (input, init = {}) => {
    const startedAt = Date.now()
    const url = new URL(String(input))
    const method = String(init.method || 'GET').toUpperCase()
    let status = 'transport-error'
    try {
      const response = await realFetch(input, init)
      status = String(response.status)
      return response
    } catch (error) {
      status = error && error.name === 'AbortError' ? 'aborted' : 'transport-error'
      throw error
    } finally {
      total++
      const key = [url.origin, method, url.pathname, status].join(' ')
      const elapsed = Date.now() - startedAt
      const row = rows.get(key) || { origin: url.origin, method, path: url.pathname, status, count: 0, totalMs: 0, maxMs: 0 }
      row.count++
      row.totalMs += elapsed
      row.maxMs = Math.max(row.maxMs, elapsed)
      rows.set(key, row)
    }
  }
  wrapped.report = () => ({
    total,
    rows: [...rows.values()].map(row => ({
      ...row,
      averageMs: Number((row.totalMs / row.count).toFixed(2))
    })).sort((a, b) => a.origin.localeCompare(b.origin) || a.path.localeCompare(b.path) || String(a.status).localeCompare(String(b.status)))
  })
  return wrapped
}

function withForwardedIp (fetchImpl, ip) {
  return (input, init = {}) => {
    const headers = new Headers(init.headers || {})
    headers.set('X-Forwarded-For', ip)
    return fetchImpl(input, { ...init, headers })
  }
}

function simulatedClientIp (index) {
  if (index < 0) return '203.0.113.1'
  return `198.51.100.${index + 1}`
}

async function importFrom (root, relative) {
  return import(pathToFileURL(join(root, relative)).href)
}

class SilentEventSource {
  constructor (url) {
    this.url = String(url)
    this.onmessage = null
    this.onerror = null
  }

  close () {}
}

class DurableRelay {
  constructor ({ label, journalPath, modules, trustProxy = false, rateLimitConfig }) {
    this.label = label
    this.journalPath = journalPath
    this.modules = modules
    this.trustProxy = trustProxy
    this.rateLimitConfig = rateLimitConfig
    this.port = 0
    this.base = ''
    this.provider = null
    this.api = null
  }

  async start () {
    const { RelayAPI, OutboxLogApp } = this.modules
    const provider = new OutboxLogApp()
    const manifest = provider.manifest()
    const node = new EventEmitter()
    Object.assign(node, {
      running: true,
      config: {
        storage: null,
        plugins: ['outboxlog'],
        trustProxy: false,
        outboxlog: {
          namespace: 'peerit',
          legacyWrites: false,
          journalPath: this.journalPath,
          sweep: false,
          http: { rateLimit: this.rateLimitConfig }
        }
      },
      store: null,
      seededApps: new Map(),
      appRegistry: {
        apps: new Map(),
        catalog () { return [] },
        catalogForBroadcast () { return [] }
      },
      metrics: { getSummary () { return { uptime: 1 } } },
      getStats () { return { running: true } },
      getHealthStatus () { return { healthy: true } },
      async start () {},
      async stop () {}
    })
    node.serviceRegistry = {
      services: new Map([['outboxlog', {
        name: manifest.name,
        version: manifest.version,
        status: 'running',
        capabilities: manifest.capabilities,
        provider
      }]])
    }

    await provider.start({ node, config: node.config })
    const api = new RelayAPI(node, {
      apiPort: this.port,
      apiHost: '127.0.0.1',
      apiKey: `peerit-atomic-soak-${this.label}-${randomBytes(8).toString('hex')}`,
      trustProxy: this.trustProxy
    })
    await api.start()
    this.port = api.server.address().port
    this.base = `http://127.0.0.1:${this.port}`
    this.provider = provider
    this.api = api
    return this
  }

  // Stop only the HTTP surface. Deliberately do not call provider.stop()/flush():
  // the replacement engine must recover solely from already-fsynced journal data.
  // close() releases only the exclusive writer-owner record; it does not create
  // a checkpoint. A real killed process loses that ownership with its dead pid,
  // while this same-process harness must release it explicitly.
  async crash () {
    if (this.api) await this.api.stop()
    if (this.provider && this.provider.engine && typeof this.provider.engine.close === 'function') this.provider.engine.close()
    this.api = null
    this.provider = null
  }

  async stop () {
    if (this.api) await this.api.stop()
    if (this.provider) await this.provider.stop()
    this.api = null
    this.provider = null
  }

  stats () {
    const engine = this.provider && this.provider.engine && this.provider.engine._stats
      ? this.provider.engine._stats()
      : null
    const state = this.api && this.api._outboxLogHttpState
    const buckets = state && state.buckets instanceof Map
      ? [...state.buckets.entries()].map(([ip, bucket]) => ({ ip, count: bucket.count, start: bucket.start }))
      : []
    return {
      engine,
      http: {
        rateBuckets: buckets,
        sseTotal: state && Number.isFinite(state.sseTotal) ? state.sseTotal : null
      }
    }
  }
}

async function jsonRequest (url, { token, method = 'GET', body, fetchImpl = fetch } = {}) {
  const headers = {}
  if (token) headers['X-Pear-Token'] = token
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let response
  try {
    response = await fetchImpl(url, {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    })
  } catch (error) {
    const detail = error && error.cause && (error.cause.code || error.cause.message)
    throw new Error(`${method} ${url} transport failed${detail ? `: ${detail}` : ''}`, { cause: error })
  }
  const payload = await response.json().catch(() => null)
  if (!response.ok) {
    const error = new Error(`${method} ${url} failed: ${response.status} ${tail(JSON.stringify(payload))}`)
    error.status = response.status
    error.response = payload
    throw error
  }
  return payload
}

async function retryTransport (fn, attempts = 3) {
  let lastError
  for (let attempt = 0; attempt < attempts; attempt++) {
    try { return await fn() } catch (error) {
      lastError = error
      if (!/transport failed/.test(String(error && error.message))) throw error
      if (attempt + 1 < attempts) await new Promise(resolve => setTimeout(resolve, 50 * (attempt + 1)))
    }
  }
  throw lastError
}

async function relayDescriptor (relay, expectedRateLimit) {
  // A recreated local server can invalidate an undici keep-alive socket even
  // though listen() has completed. Retry that transport-only condition; HTTP
  // failures and malformed capabilities still fail immediately.
  const tokenBody = await retryTransport(() => jsonRequest(relay.base + '/api/token', { method: 'POST' }))
  if (!tokenBody || typeof tokenBody.token !== 'string') throw new Error(`${relay.label}: token missing`)
  const status = await jsonRequest(relay.base + '/api/bridge/status', { token: tokenBody.token })
  const atomic = status && status.atomicCommit
  if (!(status && status.ready === true && status.service === 'outboxlog' && atomic && atomic.durable === true && atomic.ready === true && status.legacyWrites && status.legacyWrites.create === false && status.legacyWrites.append === false)) {
    throw new Error(`${relay.label}: durable atomic-only capability unavailable`)
  }
  assertHttpRateLimit(status, expectedRateLimit, relay.label)
  return {
    relay,
    apiBase: relay.base,
    apiToken: tokenBody.token,
    ready: true,
    atomicCommit: true,
    capabilities: { atomicCommit: status.atomicCommit, legacyWrites: status.legacyWrites },
    tokenExpiresAt: tokenBody.expiresAt,
    status
  }
}

async function describeFleet (relays, expectedRateLimit) {
  const descriptors = await Promise.all(relays.map(relay => relayDescriptor(relay, expectedRateLimit)))
  const origins = descriptors.map(entry => new URL(entry.apiBase).origin)
  const topologyId = 'peerit-local-atomic-soak-v1|' + origins.join('|')
  const topology = {
    schema: 1,
    verified: true,
    stable: true,
    id: topologyId,
    size: origins.length,
    origins,
    validWriterTopology: origins.length >= 2 && new Set(origins).size === origins.length
  }
  const entries = descriptors.map((entry, rosterIndex) => ({
    ...entry,
    canonicalOrigin: origins[rosterIndex],
    rosterVerified: true,
    rosterStable: true,
    rosterIndex,
    topologyId,
    rosterOrigins: origins,
    rosterSize: origins.length
  }))
  return { descriptors, entries, topology }
}

function oneLostCommitResponse (realFetch = fetch) {
  let armed = true
  let dropped = null
  const wrapped = async (input, init = {}) => {
    const response = await realFetch(input, init)
    const url = new URL(String(input))
    if (armed && init.method === 'POST' && url.pathname === '/api/sync/commit') {
      armed = false
      dropped = url.origin
      await response.arrayBuffer()
      throw new Error('injected response loss after durable relay commit')
    }
    return response
  }
  wrapped.droppedOrigin = () => dropped
  wrapped.wasTriggered = () => !armed
  return wrapped
}

async function makeClient ({ name, fleet, state = null, fetchImpl = fetch, createUser = true, commitTimeoutMs = 5000 }) {
  const local = state ? state.local : memoryStore()
  const session = state ? state.session : memoryStore()
  const storage = state ? state.storage : memoryStore()
  const identity = new DevIdentity(local, session, { persistSeed: true })
  await identity.ready()
  if (createUser && !identity.me().pubkey) await identity.createUser(name)
  if (!identity.me().pubkey) throw new Error(`${name}: durable identity did not restore`)

  const pool = createRelayPool({
    relays: fleet.entries,
    topology: fleet.topology,
    fetch: fetchImpl,
    EventSource: SilentEventSource,
    commitTimeoutMs,
    evidenceTimeoutMs: commitTimeoutMs
  })
  if (!pool || pool._atomicCommit !== true) throw new Error(`${name}: exact two-relay writer capability was not established`)
  const sync = createSync({
    pear: pool,
    getMe: () => identity.me().pubkey,
    identity,
    storage,
    validate: makeValidator(BITS),
    pollMs: 0,
    writeHead: true,
    readOnly: false,
    requireAtomicWrites: true
  })
  await sync.ready()
  return {
    name,
    local,
    session,
    storage,
    identity,
    pub: identity.me().pubkey,
    pool,
    sync,
    data: createData(sync, identity, { minBits: BITS, v2: true }),
    destroy () { try { sync.destroy() } catch {} }
  }
}

async function readAllRows (descriptor, appId, fetchImpl = fetch) {
  const rows = []
  let gt = ''
  while (rows.length <= 50000) {
    const url = new URL('/api/sync/range', descriptor.apiBase)
    url.searchParams.set('appId', appId)
    url.searchParams.set('gt', gt)
    url.searchParams.set('limit', '1000')
    const batch = await jsonRequest(url, { token: descriptor.apiToken, fetchImpl })
    if (!Array.isArray(batch)) throw new Error(`${descriptor.relay.label}: malformed range response`)
    if (!batch.length) break
    for (const row of batch) {
      if (!row || typeof row.key !== 'string' || (gt && row.key <= gt)) throw new Error(`${descriptor.relay.label}: non-advancing range`)
      rows.push(row)
      gt = row.key
    }
    if (batch.length < 1000) break
  }
  if (rows.length > 50000) throw new Error(`${descriptor.relay.label}: audit row bound exceeded`)
  return rows
}

async function auditAuthor (fleet, appId, fetchImpl = fetch) {
  const copies = []
  for (const descriptor of fleet.descriptors) {
    const rows = await readAllRows(descriptor, appId, fetchImpl)
    const headRow = rows.find(row => row.key === keys.head(appId))
    const head = headRow && headRow.value
    if (!head || (await verifyRecord(TYPE.HEAD, head)) !== 'ok') throw new Error(`${descriptor.relay.label}: invalid signed head for ${appId}`)
    const census = outboxCensus(rows, appId)
    const root = await hashHex(censusString(census))
    if (head.author !== appId || head.id !== appId || head.count !== census.length || head.root !== root) {
      throw new Error(`${descriptor.relay.label}: head census mismatch for ${appId}`)
    }
    copies.push({
      relay: descriptor.relay.label,
      origin: new URL(descriptor.apiBase).origin,
      version: head.version,
      count: head.count,
      root: head.root,
      signature: head._sig,
      rows,
      census
    })
  }
  const first = copies[0]
  for (const copy of copies.slice(1)) {
    if (copy.version !== first.version || copy.count !== first.count || copy.root !== first.root || copy.signature !== first.signature || JSON.stringify(copy.census) !== JSON.stringify(first.census)) {
      throw new Error(`relay divergence for ${appId}`)
    }
  }
  return copies.map(({ rows, census, ...copy }) => copy)
}

async function auditFleet (fleet, authors, fetchImpl = fetch) {
  const out = {}
  for (const appId of authors) out[appId] = await auditAuthor(fleet, appId, fetchImpl)
  return out
}

async function crashAndRestart (relays, expectedRateLimit) {
  await Promise.all(relays.map(relay => relay.crash()))
  await Promise.all(relays.map(relay => relay.start()))
  return describeFleet(relays, expectedRateLimit)
}

async function run (opts) {
  if (!existsSync(opts.hiverelayRoot)) throw new Error('HiveRelay checkout not found: ' + opts.hiverelayRoot)
  const [{ RelayAPI }, { OutboxLogApp }] = await Promise.all([
    importFrom(opts.hiverelayRoot, 'packages/core/core/relay-node/api.js'),
    importFrom(opts.hiverelayRoot, 'packages/services/builtin/outboxlog/index.js')
  ])
  const tempRoot = mkdtempSync(join(tmpdir(), 'peerit-atomic-two-relay-'))
  const trustProxy = opts.trafficProfile === 'distributed'
  const rateLimitConfig = fixtureRateLimitConfig(opts)
  const advertisedRateLimit = expectedHttpRateLimit(opts)
  const relays = [
    new DurableRelay({ label: 'relay-a', journalPath: join(tempRoot, 'relay-a', 'outboxlog.jsonl'), modules: { RelayAPI, OutboxLogApp }, trustProxy, rateLimitConfig }),
    new DurableRelay({ label: 'relay-b', journalPath: join(tempRoot, 'relay-b', 'outboxlog.jsonl'), modules: { RelayAPI, OutboxLogApp }, trustProxy, rateLimitConfig })
  ]
  const telemetryFetch = createFetchTelemetry(fetch)
  const clientFetch = (index) => opts.trafficProfile === 'distributed'
    ? withForwardedIp(telemetryFetch, simulatedClientIp(index))
    : telemetryFetch
  const auditFetch = opts.trafficProfile === 'distributed'
    ? withForwardedIp(telemetryFetch, '203.0.113.2')
    : telemetryFetch
  const report = {
    kind: 'peerit-two-relay-atomic-soak',
    version: 1,
    generatedAt: new Date().toISOString(),
    options: {
      clients: opts.clients,
      iterations: opts.iterations,
      restarts: opts.restarts,
      commitTimeoutMs: opts.commitTimeoutMs,
      trafficProfile: opts.trafficProfile,
      httpRateLimit: advertisedRateLimit,
      hiverelayRoot: opts.hiverelayRoot
    },
    tempRoot,
    status: 'fail',
    phase: 'setup',
    checks: [],
    metrics: {}
  }
  const clients = []
  const operationAttempts = []
  const resourceSamples = [resourceSnapshot('start')]
  const check = (id, pass, detail = null) => {
    report.checks.push({ id, status: pass ? 'pass' : 'fail', ...(detail == null ? {} : { detail }) })
    if (!pass) throw new Error(id)
    console.log('[pass] ' + id)
  }
  const operation = async (context, fn) => {
    const startedAt = Date.now()
    const attempt = { ...context, startedAt: new Date(startedAt).toISOString(), status: 'fail', latencyMs: null }
    operationAttempts.push(attempt)
    try {
      const value = await fn()
      attempt.status = 'pass'
      attempt.latencyMs = Date.now() - startedAt
      return value
    } catch (error) {
      attempt.latencyMs = Date.now() - startedAt
      attempt.error = errorReport(error)
      throw contextualError(error, context)
    }
  }

  try {
    await cryptoReady()
    console.log(`[soak] traffic=${opts.trafficProfile} commit-timeout=${opts.commitTimeoutMs}ms rate=${opts.disableRateLimit ? 'disabled' : `${opts.rateLimitMax}/${opts.rateLimitWindowMs}ms/IP`}`)
    check('secure Ed25519 backend', isSecure())
    await Promise.all(relays.map(relay => relay.start()))
    let fleet = await describeFleet(relays, advertisedRateLimit)
    check('two independent atomic-only relay origins', fleet.topology.validWriterTopology && fleet.entries.length === 2, fleet.topology.origins)
    check('relays advertise the configured HTTP rate envelope', fleet.descriptors.every(descriptor => descriptor.status.httpRateLimit.source === 'operator'), advertisedRateLimit)

    // Lost response after the relay has fsynced: the client must retain its exact
    // pending envelope; recreating both engines without flush must restore the
    // leader receipt/state and let the same commit reach the mirror once.
    report.phase = 'response-loss-recovery'
    const lossyFetch = oneLostCommitResponse(clientFetch(-1))
    let recovery = await makeClient({ name: 'recovery-writer', fleet, fetchImpl: lossyFetch, commitTimeoutMs: opts.commitTimeoutMs })
    await recovery.data.setProfile({ name: 'recovery-writer', bio: 'response-loss probe', color: '#123456' }).then(
      () => { throw new Error('injected lost response unexpectedly reported success') },
      () => {}
    )
    check('durable response-loss injection triggered', lossyFetch.wasTriggered(), lossyFetch.droppedOrigin())
    check('ambiguous commit persisted before restart', !!recovery.storage.getItem('peerit:pending-commit:v1'))
    const recoveryState = { local: recovery.local, session: recovery.session, storage: recovery.storage }
    const recoveryPub = recovery.pub
    recovery.destroy()
    recovery = null

    fleet = await crashAndRestart(relays, advertisedRateLimit)
    recovery = await makeClient({ name: 'recovery-writer', fleet, state: recoveryState, fetchImpl: clientFetch(-1), createUser: false, commitTimeoutMs: opts.commitTimeoutMs })
    check('writer identity survives relay recreation', recovery.pub === recoveryPub)
    check('exact pending commit reaches quorum after restart', !recovery.storage.getItem('peerit:pending-commit:v1'))
    const recoveredAudit = await auditAuthor(fleet, recoveryPub, auditFetch)
    check('response-loss commit is identical on both recovered relays', recoveredAudit.length === 2 && recoveredAudit[0].version === 1 && recoveredAudit[0].count === 1, recoveredAudit)
    clients.push(recovery)

    report.phase = 'writer-setup'
    for (let i = 0; i < opts.clients; i++) clients.push(await makeClient({ name: `soak-writer-${i}`, fleet, fetchImpl: clientFetch(i), commitTimeoutMs: opts.commitTimeoutMs }))
    resourceSamples.push(resourceSnapshot('writers-ready'))
    const latencies = []
    const startedAt = Date.now()
    report.phase = 'writer-operations'
    const writers = await Promise.allSettled(clients.slice(1).map(async (client, index) => {
      let slug = `soak-${index}-${Date.now().toString(36)}`
      let firstPost = null
      let start = Date.now()
      const community = await operation({ client: client.name, clientIndex: index, operation: 'community', iteration: null }, () => (
        client.data.createCommunity({ slug, title: `Soak ${index}`, description: 'two-relay atomic soak' })
      ))
      slug = community.slug // createCommunity applies the same public slug normalization as the UI.
      latencies.push(Date.now() - start)
      for (let iteration = 0; iteration < opts.iterations; iteration++) {
        start = Date.now()
        const post = await operation({ client: client.name, clientIndex: index, operation: 'post', iteration }, () => (
          client.data.submitPost({
            community: slug,
            kind: 'text',
            title: `writer ${index} post ${iteration}`,
            body: iteration === 0 && index === 0 ? 'atomic boxed body '.repeat(400) : `payload ${index}/${iteration}`,
            seed: `soak-${index}-${iteration}`
          })
        ))
        if (!firstPost) firstPost = post
        latencies.push(Date.now() - start)
      }
      start = Date.now()
      await operation({ client: client.name, clientIndex: index, operation: 'vote', iteration: null }, () => (
        client.data.vote(firstPost.cid, slug, TYPE.POST, 1)
      ))
      latencies.push(Date.now() - start)
      start = Date.now()
      await operation({ client: client.name, clientIndex: index, operation: 'comment', iteration: null }, () => (
        client.data.addComment({
          community: slug,
          postCid: firstPost.cid,
          body: `protocol-v3 bound comment ${index}`,
          seed: `soak-comment-${index}`
        })
      ))
      latencies.push(Date.now() - start)
    }))
    const writerFailures = writers
      .map((result, index) => result.status === 'rejected' ? contextualError(result.reason, { client: `soak-writer-${index}`, clientIndex: index, operation: 'writer-sequence', iteration: null }) : null)
      .filter(Boolean)
    if (writerFailures.length) throw new AggregateError(writerFailures, `${writerFailures.length} writer sequence(s) failed`)
    const durationMs = Date.now() - startedAt
    resourceSamples.push(resourceSnapshot('writer-operations-complete'))
    const authors = clients.map(client => client.pub)
    report.phase = 'initial-census-audit'
    let audit = await auditFleet(fleet, authors, auditFetch)
    check('all acknowledged writers converge on two exact signed censuses', Object.keys(audit).length === authors.length)
    resourceSamples.push(resourceSnapshot('initial-census-audit-complete'))

    for (let cycle = 1; cycle <= opts.restarts; cycle++) {
      report.phase = `restart-${cycle}`
      const states = clients.map(client => ({
        name: client.name,
        pub: client.pub,
        local: client.local,
        session: client.session,
        storage: client.storage
      }))
      for (const client of clients.splice(0)) client.destroy()
      fleet = await crashAndRestart(relays, advertisedRateLimit)
      for (const state of states) {
        const writerIndex = state.name === 'recovery-writer' ? -1 : Number(state.name.replace('soak-writer-', ''))
        const restored = await makeClient({ name: state.name, fleet, state, fetchImpl: clientFetch(writerIndex), createUser: false, commitTimeoutMs: opts.commitTimeoutMs })
        if (restored.pub !== state.pub) throw new Error(`${state.name}: identity changed after restart ${cycle}`)
        clients.push(restored)
      }
      audit = await auditFleet(fleet, authors, auditFetch)
      check(`restart ${cycle}: no loss, fork, or census mismatch`, Object.keys(audit).length === authors.length)
      const canary = clients[cycle % clients.length]
      await operation({ client: canary.name, clientIndex: cycle % clients.length, operation: 'restart-canary', iteration: cycle }, () => (
        canary.data.setProfile({ name: canary.name, bio: `post-restart canary ${cycle}`, color: '#abcdef' })
      ))
      await auditAuthor(fleet, canary.pub, auditFetch)
      check(`restart ${cycle}: new quorum commit succeeds`, true)
      resourceSamples.push(resourceSnapshot(`restart-${cycle}-complete`))
    }

    const commits = opts.clients * (opts.iterations + 3)
    report.metrics = {
      measuredConcurrentCommits: commits,
      durationMs,
      throughputPerSecond: Number((commits / Math.max(0.001, durationMs / 1000)).toFixed(2)),
      latencyMs: {
        min: Math.min(...latencies),
        p50: percentile(latencies, 0.50),
        p95: percentile(latencies, 0.95),
        p99: percentile(latencies, 0.99),
        max: Math.max(...latencies)
      },
      relays: relays.map(relay => ({ label: relay.label, stats: relay.stats() })),
      resources: resourceSummary(resourceSamples)
    }
    report.phase = 'final-census-audit'
    report.finalAudit = await auditFleet(fleet, authors, auditFetch)
    report.status = 'pass'
    report.phase = 'complete'
    console.log(`[soak] pass commits=${commits} restarts=${opts.restarts} p99=${report.metrics.latencyMs.p99}ms throughput=${report.metrics.throughputPerSecond}/s`)
    return report
  } catch (error) {
    report.error = errorReport(error)
    throw error
  } finally {
    resourceSamples.push(resourceSnapshot(report.status === 'pass' ? 'final' : `failure:${report.phase}`))
    report.metrics.resources = resourceSummary(resourceSamples)
    const operationCounts = {}
    for (const attempt of operationAttempts) {
      const key = `${attempt.operation}:${attempt.status}`
      operationCounts[key] = (operationCounts[key] || 0) + 1
    }
    const http = telemetryFetch.report()
    const httpStatusCounts = {}
    for (const row of http.rows) httpStatusCounts[row.status] = (httpStatusCounts[row.status] || 0) + row.count
    report.diagnostics = {
      operations: operationAttempts,
      operationCounts,
      http: { ...http, statusCounts: httpStatusCounts, rateLimitedRequests: httpStatusCounts['429'] || 0 },
      resources: resourceSamples,
      relays: relays.map(relay => ({ label: relay.label, origin: relay.base || null, stats: relay.stats() })),
      pendingClients: clients
        .filter(client => client.storage.getItem('peerit:pending-commit:v1'))
        .map(client => ({ name: client.name, pub: client.pub }))
    }
    for (const client of clients) client.destroy()
    await Promise.all(relays.map(relay => relay.stop().catch(() => {})))
    if (opts.out) {
      mkdirSync(dirname(opts.out), { recursive: true })
      writeFileSync(opts.out, JSON.stringify(report, null, 2) + '\n')
    }
    if (!opts.keepTemp) rmSync(tempRoot, { recursive: true, force: true })
    else console.log('[soak] kept ' + tempRoot)
  }
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  try {
    await run(opts)
    if (opts.out) console.log('[soak] wrote ' + opts.out)
  } catch (error) {
    if (opts.out) console.error('[soak] wrote failed report ' + opts.out)
    console.error('[soak] failed: ' + error.message)
    process.exitCode = 1
  }
}

await main()
