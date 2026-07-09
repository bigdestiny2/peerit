#!/usr/bin/env node
/**
 * soak-outboxlog.mjs — capacity instrument for Peerit ↔ local OutboxLog.
 *
 * NEVER points at production by default. Spawns M concurrent clients that each
 * boot → token → write a community/post → read directory/heads against a LOCAL
 * HiveRelay OutboxLog (or --relay http://localhost:...).
 *
 * Emits a JSON report with p50/p99/max latency, error rate, 429 count, peak RSS,
 * final group total, and optional static-asset fan-in metrics.
 *
 * Usage:
 *   node scripts/soak-outboxlog.mjs --clients 50 --out report.json
 *   node scripts/soak-outboxlog.mjs --clients 20 --relay http://127.0.0.1:PORT
 */

import { EventEmitter } from 'node:events'
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { randomBytes } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { createSync } from '../web/js/sync.js'
import { DevIdentity } from '../web/js/identity.js'
import { createData } from '../web/js/data.js'
import { ready as cryptoReady, isSecure } from '../web/js/crypto.js'
import { makeValidator } from '../web/js/pow.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_HIVERELAY_ROOT = resolve(ROOT, '../../00-core/hiverelay')
const BITS = { community: 6, post: 5, comment: 4 }

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error(`usage: node scripts/soak-outboxlog.mjs [options]

Options:
  --clients <n>           Concurrent clients (default: 20)
  --ramp-s <n>            Seconds to ramp clients (default: 5)
  --loops <n>             Write loops per client after boot (default: 1)
  --hiverelay-root <dir>  HiveRelay checkout
  --relay <url>           Already-running local OutboxLog relay (never production)
  --out <file>            Write JSON report
  --static-origin <url>   Also hammer static assets (roster/snapshot/manifest)
  --allow-remote          Permit non-loopback --relay (default: refuse)
  -h, --help
`)
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    clients: 20,
    rampS: 5,
    loops: 1,
    hiverelayRoot: process.env.HIVERELAY_ROOT || DEFAULT_HIVERELAY_ROOT,
    relay: '',
    out: '',
    staticOrigin: '',
    allowRemote: false
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--clients') opts.clients = Number(argv[++i] || 0)
    else if (arg === '--ramp-s') opts.rampS = Number(argv[++i] || 0)
    else if (arg === '--loops') opts.loops = Number(argv[++i] || 0)
    else if (arg === '--hiverelay-root') opts.hiverelayRoot = argv[++i] || ''
    else if (arg === '--relay') opts.relay = argv[++i] || ''
    else if (arg === '--out') opts.out = argv[++i] || ''
    else if (arg === '--static-origin') opts.staticOrigin = argv[++i] || ''
    else if (arg === '--allow-remote') opts.allowRemote = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, 'unknown option: ' + arg)
  }
  opts.hiverelayRoot = resolve(ROOT, opts.hiverelayRoot || DEFAULT_HIVERELAY_ROOT)
  if (opts.out) opts.out = resolve(process.cwd(), opts.out)
  if (!Number.isFinite(opts.clients) || opts.clients < 1) opts.clients = 20
  if (!Number.isFinite(opts.rampS) || opts.rampS < 0) opts.rampS = 5
  if (!Number.isFinite(opts.loops) || opts.loops < 1) opts.loops = 1
  opts.clients = Math.min(opts.clients, 5000)
  return opts
}

function mem () {
  const m = new Map()
  return {
    getItem: (key) => (m.has(key) ? m.get(key) : null),
    setItem: (key, value) => m.set(key, String(value)),
    removeItem: (key) => m.delete(key),
    clear: () => m.clear()
  }
}

function delay (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function percentile (sorted, p) {
  if (!sorted.length) return null
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))
  return sorted[idx]
}

function isLoopbackUrl (url) {
  try {
    const u = new URL(url)
    return u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '::1'
  } catch {
    return false
  }
}

class NodeEventSource {
  constructor (url) {
    this.url = String(url)
    this.onmessage = null
    this.onerror = null
    this._closed = false
    this._buf = ''
    const parsed = new URL(this.url)
    const transport = parsed.protocol === 'https:' ? https : http
    this._req = transport.get(this.url, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume()
        if (!this._closed && this.onerror) this.onerror(new Error('EventSource HTTP ' + res.statusCode))
        return
      }
      res.setEncoding('utf8')
      res.on('data', (chunk) => this._feed(chunk))
      res.on('end', () => {
        if (!this._closed && this.onerror) this.onerror(new Error('EventSource ended'))
      })
    })
    this._req.on('error', (err) => {
      if (!this._closed && this.onerror) this.onerror(err)
    })
  }

  _feed (chunk) {
    this._buf += chunk
    let idx
    while ((idx = this._buf.indexOf('\n\n')) >= 0) {
      const raw = this._buf.slice(0, idx)
      this._buf = this._buf.slice(idx + 2)
      let data = ''
      for (const line of raw.split('\n')) {
        if (line.startsWith('data:')) data += line.slice(5).replace(/^ /, '')
      }
      if (data && this.onmessage) {
        try { this.onmessage({ data }) } catch {}
      }
    }
  }

  close () {
    this._closed = true
    try { this._req.destroy() } catch {}
  }
}

async function importFrom (root, path) {
  return import(pathToFileURL(join(root, path)).href)
}

async function startLocalHiveRelayOutboxLog (hiverelayRoot) {
  if (!existsSync(hiverelayRoot)) throw new Error('HiveRelay checkout not found: ' + hiverelayRoot)
  const [{ RelayAPI }, { OutboxLogApp }] = await Promise.all([
    importFrom(hiverelayRoot, 'packages/core/core/relay-node/api.js'),
    importFrom(hiverelayRoot, 'packages/services/builtin/outboxlog/index.js')
  ])
  const provider = new OutboxLogApp()
  const manifest = provider.manifest()
  const node = new EventEmitter()
  Object.assign(node, {
    running: true,
    // Peerit stamps _ns:'peerit' on every signed record; OutboxLog must register that
    // namespace or append returns 400 unknown namespace.
    config: {
      storage: null,
      plugins: ['outboxlog'],
      trustProxy: false,
      outboxlog: { namespace: 'peerit' }
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
    services: new Map([[
      'outboxlog',
      {
        name: manifest.name,
        version: manifest.version,
        status: 'running',
        capabilities: manifest.capabilities,
        provider
      }
    ]])
  }
  await provider.start({ node, config: node.config })
  const api = new RelayAPI(node, {
    apiPort: 0,
    apiHost: '127.0.0.1',
    apiKey: 'peerit-soak-' + randomBytes(8).toString('hex')
  })
  // Soak needs headroom; production limits remain untouched.
  api._checkRateLimit = () => true
  api._checkEndpointRateLimit = () => true
  await api.start()
  const port = api.server.address().port
  return {
    base: `http://127.0.0.1:${port}`,
    mode: 'local-hiverelay-relayapi',
    provider,
    async stop () {
      await api.stop()
      await provider.stop()
    },
    groupCount () {
      try {
        const s = provider.engine && provider.engine._stats ? provider.engine._stats() : null
        if (s && typeof s.groups === 'number') return s.groups
        if (s && typeof s.groupCount === 'number') return s.groupCount
      } catch {}
      return null
    }
  }
}

async function getToken (base) {
  const res = await fetch(base + '/api/token', { method: 'POST' })
  const body = await res.json().catch(() => null)
  if (!res.ok || !body || !body.token) {
    const err = new Error('/api/token failed: ' + res.status)
    err.status = res.status
    throw err
  }
  return body.token
}

async function timed (fn) {
  const t0 = performance.now()
  try {
    const value = await fn()
    return { ok: true, ms: performance.now() - t0, value }
  } catch (err) {
    return {
      ok: false,
      ms: performance.now() - t0,
      error: err && err.message ? err.message : String(err),
      status: err && err.status
    }
  }
}

async function runClient (base, clientId, loops, metrics) {
  const local = mem()
  const session = mem()
  const tokenRes = await timed(() => getToken(base))
  metrics.latencies.token.push(tokenRes.ms)
  if (!tokenRes.ok) {
    metrics.errors++
    if (tokenRes.status === 429) metrics.rateLimited++
    metrics.clientResults.push({ clientId, ok: false, stage: 'token', error: tokenRes.error, ms: tokenRes.ms })
    return
  }

  const id = new DevIdentity(local, session)
  await id.ready()
  await id.createUser('soak-' + clientId)
  const sync = createSync({
    apiToken: tokenRes.value,
    apiBase: base,
    fetch: (...args) => fetch(...args),
    EventSource: NodeEventSource,
    storage: local,
    getMe: () => id.me().pubkey,
    identity: id,
    validate: makeValidator(BITS),
    pollMs: 500,
    writeHead: true
  })
  await sync.ready()
  const data = createData(sync, id, { minBits: BITS })

  try {
    for (let i = 0; i < loops; i++) {
      const slug = ('s' + clientId + 'x' + i + Date.now().toString(36)).slice(0, 20)
      const writeRes = await timed(async () => {
        await data.createCommunity({ slug, title: 'soak ' + clientId, description: 'soak' })
        return data.submitPost({
          community: slug,
          kind: 'text',
          title: 'soak post ' + clientId,
          body: 'soak body ' + clientId + ' loop ' + i
        })
      })
      metrics.latencies.write.push(writeRes.ms)
      if (!writeRes.ok) {
        metrics.errors++
        if (writeRes.status === 429) metrics.rateLimited++
        metrics.clientResults.push({ clientId, ok: false, stage: 'write', error: writeRes.error, ms: writeRes.ms })
        return
      }

      const dirRes = await timed(async () => {
        const tok = await getToken(base)
        const res = await fetch(base + '/api/directory', { headers: { 'X-Pear-Token': tok } })
        if (res.status === 429) {
          const e = new Error('directory 429'); e.status = 429; throw e
        }
        if (!res.ok) {
          const e = new Error('directory ' + res.status); e.status = res.status; throw e
        }
        return res.json()
      })
      metrics.latencies.directory.push(dirRes.ms)
      if (!dirRes.ok) {
        metrics.errors++
        if (dirRes.status === 429) metrics.rateLimited++
      }
    }
    metrics.clientResults.push({ clientId, ok: true })
    metrics.successClients++
  } finally {
    try { sync.destroy() } catch {}
  }
}

async function hammerStatic (origin, clients, metrics) {
  const paths = ['/relay-roster.json', '/seed-snapshot.json', '/asset-manifest.json']
  const base = origin.replace(/\/+$/, '')
  const jobs = []
  for (let i = 0; i < clients; i++) {
    for (const p of paths) {
      jobs.push(timed(async () => {
        const res = await fetch(base + p, { cache: 'no-store' })
        if (!res.ok) {
          const e = new Error(p + ' ' + res.status)
          e.status = res.status
          throw e
        }
        await res.arrayBuffer()
        return p
      }).then((r) => {
        metrics.latencies.static.push(r.ms)
        if (!r.ok) {
          metrics.staticErrors++
          if (r.status === 429) metrics.rateLimited++
        }
      }))
    }
  }
  await Promise.all(jobs)
}

function summarize (arr) {
  const sorted = [...arr].filter((n) => Number.isFinite(n)).sort((a, b) => a - b)
  return {
    count: sorted.length,
    p50: percentile(sorted, 50),
    p99: percentile(sorted, 99),
    max: sorted.length ? sorted[sorted.length - 1] : null,
    mean: sorted.length ? sorted.reduce((a, b) => a + b, 0) / sorted.length : null
  }
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  if (opts.relay) {
    if (!opts.allowRemote && !isLoopbackUrl(opts.relay)) {
      console.error('refusing non-loopback --relay without --allow-remote (never soak production)')
      process.exit(2)
    }
  }

  await cryptoReady()
  if (!isSecure()) {
    console.error('no secure Ed25519 backend')
    process.exit(1)
  }

  let relay = null
  const metrics = {
    latencies: { token: [], write: [], directory: [], static: [] },
    errors: 0,
    staticErrors: 0,
    rateLimited: 0,
    successClients: 0,
    clientResults: [],
    peakRss: 0
  }
  const rssTimer = setInterval(() => {
    const rss = process.memoryUsage().rss
    if (rss > metrics.peakRss) metrics.peakRss = rss
  }, 200)

  const t0 = performance.now()
  try {
    relay = opts.relay
      ? {
          base: opts.relay.replace(/\/+$/, ''),
          mode: 'external-relay',
          stop: async () => {},
          groupCount: () => null
        }
      : await startLocalHiveRelayOutboxLog(opts.hiverelayRoot)

    console.log('[soak] target=' + relay.base + ' clients=' + opts.clients + ' ramp-s=' + opts.rampS)

    if (opts.staticOrigin) {
      console.log('[soak] static fan-in against ' + opts.staticOrigin)
      await hammerStatic(opts.staticOrigin, Math.min(opts.clients, 100), metrics)
    }

    const gap = opts.clients > 1 ? (opts.rampS * 1000) / opts.clients : 0
    const runners = []
    for (let i = 0; i < opts.clients; i++) {
      runners.push((async () => {
        if (gap > 0) await delay(i * gap)
        await runClient(relay.base, i, opts.loops, metrics)
      })())
    }
    await Promise.all(runners)

    const durationMs = performance.now() - t0
    const groups = relay.groupCount ? relay.groupCount() : null
    let directoryTotal = null
    try {
      const tok = await getToken(relay.base)
      const dir = await fetch(relay.base + '/api/directory', { headers: { 'X-Pear-Token': tok } }).then((r) => r.json())
      directoryTotal = dir && (dir.total != null ? dir.total : dir.count)
    } catch {}

    const sampleErrors = metrics.clientResults
      .filter((r) => !r.ok)
      .slice(0, 10)
      .map((r) => ({ stage: r.stage, error: r.error, ms: r.ms }))

    const report = {
      kind: 'peerit-outboxlog-soak',
      version: 1,
      generatedAt: new Date().toISOString(),
      target: relay.base,
      mode: relay.mode || (opts.relay ? 'external-relay' : 'local-hiverelay-relayapi'),
      clients: opts.clients,
      loops: opts.loops,
      rampS: opts.rampS,
      durationMs,
      peakRssBytes: metrics.peakRss,
      peakRssMb: Math.round(metrics.peakRss / (1024 * 1024) * 10) / 10,
      errors: metrics.errors,
      staticErrors: metrics.staticErrors,
      rateLimited429: metrics.rateLimited,
      successClients: metrics.successClients,
      errorRate: opts.clients ? (opts.clients - metrics.successClients) / opts.clients : 0,
      groups,
      directoryTotal,
      // authors-until-cap heuristic: one group per writing author under default OutboxLog
      authorsUntilCapEstimate: 20000,
      sampleErrors,
      latencyMs: {
        token: summarize(metrics.latencies.token),
        write: summarize(metrics.latencies.write),
        directory: summarize(metrics.latencies.directory),
        static: summarize(metrics.latencies.static)
      },
      thresholds: {
        p99WriteMs: 2000,
        errorRateMax: 0.01,
        note: 'Pass when write p99 < 2000ms and errorRate < 1% at the committed client count'
      },
      status: null
    }

    const writeP99 = report.latencyMs.write.p99
    const passP99 = writeP99 == null || writeP99 < report.thresholds.p99WriteMs
    const passErr = report.errorRate <= report.thresholds.errorRateMax
    report.status = (passP99 && passErr && metrics.successClients > 0) ? 'pass' : 'fail'

    if (opts.out) {
      mkdirSync(dirname(opts.out), { recursive: true })
      writeFileSync(opts.out, JSON.stringify(report, null, 2) + '\n')
      console.log('[soak] wrote ' + opts.out)
    }
    console.log('[soak] status=' + report.status +
      ' success=' + metrics.successClients + '/' + opts.clients +
      ' write_p99=' + writeP99 +
      ' errors=' + metrics.errors +
      ' 429=' + metrics.rateLimited +
      ' rssMb=' + report.peakRssMb +
      ' directoryTotal=' + directoryTotal)
    if (report.status !== 'pass') process.exitCode = 1
  } finally {
    clearInterval(rssTimer)
    if (relay) await relay.stop()
  }
}

main().catch((err) => {
  console.error('[soak] failed:', err)
  process.exit(1)
})
