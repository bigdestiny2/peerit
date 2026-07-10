#!/usr/bin/env node

// Local-only writable Peerit browser fixture.
//
// Starts two real HiveRelay RelayAPI + atomic-only OutboxLog instances on
// loopback, prepares an isolated copy of the current Peerit source shell, signs a
// short-lived two-origin roster, and serves that temporary tree with writer mode
// enabled. Nothing here contacts or mutates production.

import http from 'node:http'
import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, extname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { genKeyPair, ready as cryptoReady, sign } from '../js/crypto.js'
import { createRelayPool } from '../js/relay-pool.js'
import {
  hasDurableAtomicCommit,
  normalizeRelayRosterPayload,
  resolveRelayCandidates,
  rosterSigningMessage,
  selectRelaysResilient,
  verifyRelayRoster
} from '../js/relay-roster.js'
import { cspConnectOrigin, patchCspForWeb } from './csp.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_HIVERELAY_ROOT = resolve(ROOT, '../../00-core/hiverelay')
const HOST = '127.0.0.1'
const WRITABLE_RATE_LIMIT = Object.freeze({ enabled: true, windowMs: 60_000, max: 12_000 })
const MIME = Object.freeze({
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml'
})

function usage (code = 0, message = '') {
  if (message) console.error('error: ' + message)
  console.error(`usage: node scripts/local-writable-two-relay.mjs [options]

Options:
  --hiverelay-root <p>  HiveRelay checkout with the atomic OutboxLog candidate
  --port <n>       App port (default: an available loopback port)
  --state-dir <p>  Reuse a journal directory instead of a fresh temp directory
  --keep-temp      Keep the generated web tree and journals after shutdown
  -h, --help       Show this help
`)
  process.exitCode = code
}

function parseArgs (argv) {
  const opts = { hiverelayRoot: process.env.HIVERELAY_ROOT || DEFAULT_HIVERELAY_ROOT, port: 0, stateDir: '', keepTemp: false, help: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--hiverelay-root') {
      const value = argv[++i]
      if (!value) throw new Error('--hiverelay-root requires a path')
      opts.hiverelayRoot = resolve(value)
    } else if (arg === '--port') {
      const port = Number(argv[++i])
      if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new Error('--port must be 0-65535')
      opts.port = port
    } else if (arg === '--state-dir') {
      const value = argv[++i]
      if (!value) throw new Error('--state-dir requires a path')
      opts.stateDir = resolve(value)
    } else if (arg === '--keep-temp') opts.keepTemp = true
    else if (arg === '-h' || arg === '--help') opts.help = true
    else throw new Error('unknown option: ' + arg)
  }
  return opts
}

function attr (value) {
  return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')
}

function loopbackOrigin (value) {
  const url = new URL(String(value))
  if (url.protocol !== 'http:' || url.hostname !== HOST) throw new Error('fixture refused a non-loopback origin: ' + url.origin)
  return url.origin
}

function importFromHiveRelay (root, relativePath) {
  return import(pathToFileURL(join(root, relativePath)).href)
}

function makeRelayNode (provider, config) {
  const manifest = provider.manifest()
  const node = new EventEmitter()
  Object.assign(node, {
    running: true,
    config,
    store: null,
    seededApps: new Map(),
    appRegistry: {
      apps: new Map(),
      catalog () { return [] },
      catalogForBroadcast () { return [] }
    },
    metrics: { getSummary () { return { uptime: 1 } } },
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true, status: 'healthy' } },
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
  return node
}

class LocalRelay {
  constructor ({ label, journalPath, appOrigin, modules }) {
    this.label = label
    this.journalPath = journalPath
    this.appOrigin = appOrigin
    this.modules = modules
    this.api = null
    this.provider = null
    this.port = 0
    this.base = ''
  }

  async start () {
    if (this.api || this.provider) return this
    const { RelayAPI, OutboxLogApp } = this.modules
    const config = {
      storage: null,
      plugins: ['outboxlog'],
      trustProxy: false,
      outboxlog: {
        namespace: 'peerit',
        legacyWrites: false,
        journalPath: this.journalPath,
        seedReaffirmMs: 0,
        sweep: false,
        http: { rateLimit: { ...WRITABLE_RATE_LIMIT } }
      }
    }
    const provider = new OutboxLogApp()
    const node = makeRelayNode(provider, config)
    await provider.start({ node, config, store: null })
    const api = new RelayAPI(node, {
      apiPort: this.port,
      apiHost: HOST,
      apiKey: `peerit-local-${this.label}-${randomBytes(12).toString('hex')}`,
      corsOrigins: [this.appOrigin]
    })
    await api.start()
    this.api = api
    this.provider = provider
    this.port = api.server.address().port
    this.base = loopbackOrigin(`http://${HOST}:${this.port}`)
    return this
  }

  async stop () {
    const api = this.api
    const provider = this.provider
    this.api = null
    this.provider = null
    if (api) await api.stop().catch(() => {})
    if (provider) await provider.stop().catch(() => {})
  }
}

function listen (server, port = 0) {
  return new Promise((resolve, reject) => {
    const onError = (error) => { server.off('listening', onListening); reject(error) }
    const onListening = () => { server.off('error', onError); resolve() }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(port, HOST)
  })
}

function closeServer (server) {
  if (!server || !server.listening) return Promise.resolve()
  if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections()
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections()
  return new Promise((resolve) => server.close(() => resolve()))
}

function prepareWebTree (webRoot) {
  rmSync(webRoot, { recursive: true, force: true })
  mkdirSync(webRoot, { recursive: true, mode: 0o700 })
  for (const file of ['index.html', 'styles.css', 'icon.svg', 'manifest.json']) {
    cpSync(join(ROOT, file), join(webRoot, file))
  }
  cpSync(join(ROOT, 'js'), join(webRoot, 'js'), { recursive: true })
  if (existsSync(join(ROOT, 'config'))) cpSync(join(ROOT, 'config'), join(webRoot, 'config'), { recursive: true })
  // Use the current locally built reader when available, but never modify or
  // serve the signed web/ tree itself.
  const builtReader = join(ROOT, 'web', 'js', 'reader-bundle.js')
  if (existsSync(builtReader)) cpSync(builtReader, join(webRoot, 'js', 'reader-bundle.js'))
}

function prepareIndex ({ webRoot, relays, rosterKey }) {
  let html = readFileSync(join(ROOT, 'index.html'), 'utf8')
  html = html.replace(/\s*<meta\s+name="peerit-shard-(?:roster|relays|threshold)"[^>]*>/gi, '')
  const connectOrigins = relays.map(cspConnectOrigin).filter(Boolean)
  html = patchCspForWeb(html, { connectOrigins })
  const metas = [
    `<meta name="peerit-relay" content="${attr(relays.join(','))}">`,
    '<meta name="peerit-relay-backend" content="hiverelay-outbox">',
    '<meta name="peerit-relay-readonly" content="false">',
    '<meta name="peerit-relay-roster" content="relay-roster.json">',
    `<meta name="peerit-relay-roster-key" content="${attr(rosterKey)}">`,
    '<meta name="peerit-local-demo" content="two-relay-atomic">'
  ].join('\n  ')
  html = html.replace('</head>', `  ${metas}\n</head>`)
  writeFileSync(join(webRoot, 'index.html'), html)
  return html
}

function safeStaticPath (pathname) {
  return pathname === '/index.html' || pathname === '/styles.css' || pathname === '/icon.svg' || pathname === '/manifest.json' ||
    /^\/js\/[a-z0-9-]+\.(?:js|mjs)$/i.test(pathname) || /^\/config\/[a-z0-9._-]+\.json$/i.test(pathname)
}

function createAppServer ({ webRoot, state }) {
  return http.createServer((req, res) => {
    let pathname
    try { pathname = decodeURIComponent(new URL(req.url || '/', 'http://local.invalid').pathname) } catch {
      res.writeHead(400); res.end('bad request'); return
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' }); res.end('method not allowed'); return
    }
    if (pathname === '/healthz') {
      const body = JSON.stringify({ ready: state.ready, relays: state.relays || [] }) + '\n'
      res.writeHead(state.ready ? 200 : 503, { 'Content-Type': MIME['.json'], 'Cache-Control': 'no-store' })
      if (req.method === 'GET') res.end(body); else res.end()
      return
    }
    if (pathname === '/') pathname = '/index.html'
    if (pathname === '/relay-roster.json') {
      if (!state.ready || !state.roster) { res.writeHead(503); res.end('fixture starting'); return }
      const body = JSON.stringify(state.roster, null, 2) + '\n'
      res.writeHead(200, { 'Content-Type': MIME['.json'], 'Cache-Control': 'no-store, max-age=0', 'X-Content-Type-Options': 'nosniff' })
      if (req.method === 'GET') res.end(body); else res.end()
      return
    }
    if (!state.ready) { res.writeHead(503); res.end('fixture starting'); return }
    if (!safeStaticPath(pathname) || pathname.includes('\0')) { res.writeHead(404); res.end('not found'); return }
    const file = resolve(webRoot, '.' + pathname)
    const rel = relative(webRoot, file)
    if (rel.startsWith('..') || isAbsolute(rel)) { res.writeHead(403); res.end('forbidden'); return }
    try {
      if (!statSync(file).isFile()) throw new Error('not a file')
      const body = readFileSync(file)
      res.writeHead(200, {
        'Content-Type': MIME[extname(file)] || 'application/octet-stream',
        'Cache-Control': 'no-store, max-age=0',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'X-Content-Type-Options': 'nosniff'
      })
      if (req.method === 'GET') res.end(body); else res.end()
    } catch {
      res.writeHead(404); res.end('not found')
    }
  })
}

async function requestJson (url, { method = 'GET', token = '', body, origin = '' } = {}) {
  loopbackOrigin(url)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 5000)
  try {
    const headers = {}
    if (token) headers['X-Pear-Token'] = token
    if (origin) headers.Origin = origin
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const response = await fetch(url, {
      method,
      headers,
      signal: controller.signal,
      redirect: 'error',
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    })
    const text = await response.text()
    let value = null
    try { value = text ? JSON.parse(text) : null } catch { value = text }
    return { response, value }
  } finally {
    clearTimeout(timer)
  }
}

async function validateRelay (relay, appOrigin) {
  if (!existsSync(relay.journalPath)) throw new Error(`${relay.label}: JSONL journal was not created`)
  const health = await requestJson(relay.base + '/health', { origin: appOrigin })
  if (!health.response.ok) throw new Error(`${relay.label}: /health failed (${health.response.status})`)
  const tokenResult = await requestJson(relay.base + '/api/token', { method: 'POST', origin: appOrigin })
  const token = tokenResult.value && tokenResult.value.token
  if (!tokenResult.response.ok || typeof token !== 'string' || !token) throw new Error(`${relay.label}: browser token unavailable`)
  const allowOrigin = tokenResult.response.headers.get('access-control-allow-origin')
  if (allowOrigin !== '*' && allowOrigin !== appOrigin) throw new Error(`${relay.label}: browser CORS was not enabled`)
  const status = await requestJson(relay.base + '/api/bridge/status', { token, origin: appOrigin })
  if (!status.response.ok || !hasDurableAtomicCommit(status.value)) throw new Error(`${relay.label}: exact durable atomic capability unavailable`)
  const rate = status.value && status.value.httpRateLimit
  const nestedRate = rate && rate.outboxLogEnvelope
  if (!rate || rate.scope !== 'public-writes' || rate.source !== 'operator' ||
      rate.enabled !== WRITABLE_RATE_LIMIT.enabled || rate.windowMs !== WRITABLE_RATE_LIMIT.windowMs || rate.max !== WRITABLE_RATE_LIMIT.max ||
      !nestedRate || nestedRate.enabled !== WRITABLE_RATE_LIMIT.enabled || nestedRate.windowMs !== WRITABLE_RATE_LIMIT.windowMs || nestedRate.max !== WRITABLE_RATE_LIMIT.max) {
    throw new Error(`${relay.label}: explicit public-writer rate envelope unavailable or mismatched`)
  }
  const capabilities = await requestJson(relay.base + '/api/sync/capabilities', { token, origin: appOrigin })
  if (!capabilities.response.ok || !hasDurableAtomicCommit({ ready: true, ...capabilities.value })) throw new Error(`${relay.label}: capability endpoint is not atomic-only`)
  for (const route of ['/api/sync/create', '/api/sync/append']) {
    const legacy = await requestJson(relay.base + route, {
      method: 'POST',
      token,
      origin: appOrigin,
      body: route.endsWith('/create')
        ? { appId: '0'.repeat(64) }
        : { appId: '0'.repeat(64), op: { type: 'profile', data: {} } }
    })
    if (legacy.response.status !== 403) throw new Error(`${relay.label}: ${route} was not blocked`)
  }
  return { apiBase: relay.base, apiToken: token, status: status.value }
}

async function validatePreparedApp ({ appUrl, relays, roster, rosterKey }) {
  const indexResponse = await fetch(appUrl, { cache: 'no-store', redirect: 'error' })
  const html = await indexResponse.text()
  if (!indexResponse.ok || !html.includes('name="peerit-relay-readonly" content="false"')) throw new Error('prepared app is not writable')
  if (!html.includes(`name="peerit-relay-roster-key" content="${rosterKey}"`)) throw new Error('prepared app does not pin the local roster key')
  for (const origin of relays) if (!html.includes(origin)) throw new Error('prepared app CSP/config omitted ' + origin)

  const rosterUrl = new URL('relay-roster.json', appUrl).href
  const candidates = await resolveRelayCandidates({
    relays,
    roster: { url: rosterUrl, urls: [rosterUrl], key: rosterKey },
    fetch,
    timeoutMs: 5000
  })
  if (!candidates.rosterVerified || !candidates.topology || candidates.topology.stable !== true || candidates.topology.validWriterTopology !== true) {
    throw new Error('real runtime roster verification did not produce a stable two-origin topology')
  }
  const selected = await selectRelaysResilient(candidates.relays, {
    fetch,
    topology: candidates.topology,
    tries: 1,
    timeoutMs: 5000
  })
  const pool = createRelayPool({ relays: selected, topology: candidates.topology, fetch })
  if (!pool || pool._atomicCommit !== true || pool._writerRelayCount !== 2) throw new Error('real runtime selection did not establish atomic writer quorum')
  const verified = await verifyRelayRoster(roster, { expectedKey: rosterKey })
  if (verified.relays.length !== 2) throw new Error('local roster self-verification failed')
}

async function main () {
  let opts
  try { opts = parseArgs(process.argv.slice(2)) } catch (error) { usage(2, error.message); return }
  if (opts.help) { usage(0); return }
  if (!existsSync(opts.hiverelayRoot)) throw new Error('required HiveRelay worktree is missing: ' + opts.hiverelayRoot)

  const tempRoot = opts.stateDir || mkdtempSync(join(tmpdir(), 'peerit-local-writable-'))
  const removeOnStop = !opts.keepTemp && !opts.stateDir
  mkdirSync(tempRoot, { recursive: true, mode: 0o700 })
  const webRoot = join(tempRoot, 'web')
  prepareWebTree(webRoot)

  const state = { ready: false, roster: null, relays: [] }
  const appServer = createAppServer({ webRoot, state })
  const relays = []
  let stopping = null
  let relayTransition = Promise.resolve()
  const relaySignalHandlers = new Map()
  const stop = async (reason = 'shutdown') => {
    if (stopping) return stopping
    stopping = (async () => {
      console.log(`\n[local-demo] ${reason}; stopping app and relays...`)
      state.ready = false
      for (const [signal, handler] of relaySignalHandlers) process.off(signal, handler)
      await closeServer(appServer).catch(() => {})
      await relayTransition.catch(() => {})
      await Promise.all(relays.map(relay => relay.stop()))
      if (removeOnStop) rmSync(tempRoot, { recursive: true, force: true })
      else console.log('[local-demo] kept state at ' + tempRoot)
      console.log('[local-demo] stopped cleanly')
    })()
    return stopping
  }

  try {
    await listen(appServer, opts.port)
    const appOrigin = loopbackOrigin(`http://${HOST}:${appServer.address().port}`)
    const [{ RelayAPI }, { OutboxLogApp }] = await Promise.all([
      importFromHiveRelay(opts.hiverelayRoot, 'packages/core/core/relay-node/api.js'),
      importFromHiveRelay(opts.hiverelayRoot, 'packages/services/builtin/outboxlog/index.js')
    ])
    const modules = { RelayAPI, OutboxLogApp }
    relays.push(
      new LocalRelay({ label: 'relay-a', journalPath: join(tempRoot, 'relay-a', 'outboxlog.jsonl'), appOrigin, modules }),
      new LocalRelay({ label: 'relay-b', journalPath: join(tempRoot, 'relay-b', 'outboxlog.jsonl'), appOrigin, modules })
    )
    await Promise.all(relays.map(relay => relay.start()))
    const relayOrigins = relays.map(relay => loopbackOrigin(relay.base))
    if (new Set(relayOrigins).size !== 2) throw new Error('relay origins are not independent')

    await cryptoReady()
    const rosterKeypair = await genKeyPair()
    const payload = normalizeRelayRosterPayload({
      version: 1,
      expires: new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(),
      relays: relayOrigins
    })
    const roster = {
      payload,
      signature: {
        alg: 'Ed25519',
        key: rosterKeypair.pubHex,
        sig: await sign(rosterKeypair.seedHex, rosterSigningMessage(payload))
      }
    }
    await verifyRelayRoster(roster, { expectedKey: rosterKeypair.pubHex })
    writeFileSync(join(webRoot, 'relay-roster.json'), JSON.stringify(roster, null, 2) + '\n')
    prepareIndex({ webRoot, relays: relayOrigins, rosterKey: rosterKeypair.pubHex })
    state.roster = roster
    state.relays = relayOrigins
    state.ready = true

    const relayChecks = await Promise.all(relays.map(relay => validateRelay(relay, appOrigin)))
    if (new Set(relays.map(relay => relay.journalPath)).size !== 2 || relayChecks.length !== 2) throw new Error('separate relay journal validation failed')
    const appUrl = appOrigin + '/'
    await validatePreparedApp({ appUrl, relays: relayOrigins, roster, rosterKey: rosterKeypair.pubHex })

    const toggleRelay = (index) => {
      relayTransition = relayTransition.then(async () => {
        if (stopping) return
        const relay = relays[index]
        if (!relay) return
        if (relay.api || relay.provider) {
          console.log(`[local-demo] stopping ${relay.label} (${relay.base})`)
          await relay.stop()
          console.log(`[local-demo] ${relay.label} is offline; send the same signal to restart it`)
        } else {
          console.log(`[local-demo] restarting ${relay.label} on ${relay.base}`)
          await relay.start()
          if (relay.base !== relayOrigins[index]) throw new Error(`${relay.label}: restart changed its signed-roster origin`)
          await validateRelay(relay, appOrigin)
          console.log(`[local-demo] ${relay.label} recovered from its journal at ${relay.base}`)
        }
      }).catch((error) => console.error('[local-demo] relay toggle failed: ' + error.message))
    }
    relaySignalHandlers.set('SIGUSR1', () => toggleRelay(0))
    relaySignalHandlers.set('SIGUSR2', () => toggleRelay(1))
    for (const [signal, handler] of relaySignalHandlers) process.on(signal, handler)

    console.log('\nPeerit local writable demo is ready.')
    console.log('App:      ' + appUrl)
    console.log('Relay A:  ' + relayOrigins[0])
    console.log('Relay B:  ' + relayOrigins[1])
    console.log('Journal A:' + ' ' + relays[0].journalPath)
    console.log('Journal B:' + ' ' + relays[1].journalPath)
    console.log('Roster:   verified Ed25519, stable two-origin topology, readonly=false')
    console.log('Process:  ' + process.pid + ' (SIGUSR1 toggles relay A; SIGUSR2 toggles relay B)')
    console.log('Press Ctrl-C to stop cleanly.')

    await new Promise((resolve, reject) => {
      const shutdown = (signal) => {
        stop(signal).then(resolve, reject)
      }
      process.once('SIGINT', shutdown)
      process.once('SIGTERM', shutdown)
    })
  } catch (error) {
    await stop('startup failure')
    throw error
  }
}

main().catch((error) => {
  console.error('[local-demo] ' + ((error && error.stack) || error))
  process.exitCode = 1
})
