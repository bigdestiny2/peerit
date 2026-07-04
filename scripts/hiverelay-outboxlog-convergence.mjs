#!/usr/bin/env node
import { EventEmitter } from 'node:events'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { randomBytes } from 'node:crypto'
import { createSync } from '../web/js/sync.js'
import { DevIdentity } from '../web/js/identity.js'
import { createData } from '../web/js/data.js'
import { ready as cryptoReady, isSecure } from '../web/js/crypto.js'
import { makeValidator } from '../web/js/pow.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_HIVERELAY_ROOT = resolve(ROOT, '../../00-core/hiverelay')
const PROOF_KIND = 'peerit-hiverelay-outboxlog-convergence'
const BITS = { community: 7, post: 6, comment: 5 }

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error(`usage: node scripts/hiverelay-outboxlog-convergence.mjs [options]

Options:
  --hiverelay-root <dir>  HiveRelay checkout (default: ../../00-core/hiverelay)
  --relay <url>           Use an already-running HiveRelay OutboxLog relay
  --out <file>            Write JSON evidence report
  --poll-ms <n>           Peerit bridge poll interval (default: 200)
  -h, --help              Show this help
`)
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    hiverelayRoot: process.env.HIVERELAY_ROOT || DEFAULT_HIVERELAY_ROOT,
    relay: process.env.PEERIT_HIVERELAY_OUTBOXLOG_RELAY || '',
    out: process.env.PEERIT_HIVERELAY_OUTBOXLOG_REPORT || '',
    pollMs: Number(process.env.PEERIT_HIVERELAY_OUTBOXLOG_POLL_MS || 200)
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--hiverelay-root') opts.hiverelayRoot = argv[++i] || ''
    else if (arg === '--relay') opts.relay = argv[++i] || ''
    else if (arg === '--out') opts.out = argv[++i] || ''
    else if (arg === '--poll-ms') opts.pollMs = Number(argv[++i] || 0)
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  opts.hiverelayRoot = resolve(ROOT, opts.hiverelayRoot || DEFAULT_HIVERELAY_ROOT)
  if (opts.out) opts.out = resolve(ROOT, opts.out)
  if (!Number.isFinite(opts.pollMs) || opts.pollMs < 0) opts.pollMs = 200
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
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function until (fn, { tries = 220, gap = 100 } = {}) {
  for (let i = 0; i < tries; i++) {
    try {
      if (await fn()) return true
    } catch {}
    await delay(gap)
  }
  return false
}

function tail (text, max = 4000) {
  text = String(text || '')
  return text.length > max ? text.slice(text.length - max) : text
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
      res.on('data', chunk => this._feed(chunk))
      res.on('end', () => {
        if (!this._closed && this.onerror) this.onerror(new Error('EventSource ended'))
      })
    })
    this._req.on('error', err => {
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
        try {
          this.onmessage({ data })
        } catch {}
      }
    }
  }

  close () {
    this._closed = true
    try {
      this._req.destroy()
    } catch {}
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
    config: {
      storage: null,
      plugins: ['outboxlog'],
      trustProxy: false
    },
    store: null,
    seededApps: new Map(),
    appRegistry: {
      apps: new Map(),
      catalog () { return [] },
      catalogForBroadcast () { return [] }
    },
    metrics: {
      getSummary () { return { uptime: 1 } }
    },
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

  await provider.start({ node })
  const api = new RelayAPI(node, {
    apiPort: 0,
    apiHost: '127.0.0.1',
    apiKey: 'peerit-proof-' + randomBytes(8).toString('hex')
  })
  // This proof deliberately compresses many browser polls/writes into seconds.
  // Keep production limits untouched; only widen the in-process proof API.
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
    stats () {
      return provider.engine && provider.engine._stats ? provider.engine._stats() : null
    }
  }
}

async function getToken (base) {
  const res = await fetch(base + '/api/token', { method: 'POST' })
  const body = await res.json().catch(() => null)
  if (!res.ok || !body || !body.token) {
    throw new Error('/api/token failed: ' + res.status + ' ' + tail(JSON.stringify(body)))
  }
  return body.token
}

async function makeClient ({ base, name, local = mem(), session = mem(), pollMs, createUser = true }) {
  const token = await getToken(base)
  const id = new DevIdentity(local, session)
  await id.ready()
  if (createUser) await id.createUser(name)
  const sync = createSync({
    apiToken: token,
    apiBase: base,
    fetch: (...args) => fetch(...args),
    EventSource: NodeEventSource,
    storage: local,
    getMe: () => id.me().pubkey,
    identity: id,
    validate: makeValidator(BITS),
    pollMs,
    writeHead: true
  })
  await sync.ready()
  return {
    id,
    sync,
    data: createData(sync, id, { minBits: BITS }),
    local,
    session,
    pub: id.me().pubkey,
    name
  }
}

function writeReport (file, report) {
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, JSON.stringify(report, null, 2) + '\n')
}

function makeReporter () {
  const checks = []
  return {
    checks,
    ok (id, pass, message, detail = null) {
      checks.push({
        id,
        status: pass ? 'pass' : 'fail',
        message,
        ...(detail ? { detail } : {})
      })
      if (!pass) throw new Error(message)
      console.log('[pass] ' + message)
    }
  }
}

async function runProof (opts) {
  const report = {
    kind: PROOF_KIND,
    version: 1,
    generatedAt: new Date().toISOString(),
    peerit: {
      modules: 'web/js',
      unmodifiedWebBuildModules: true
    },
    hiverelay: {
      root: opts.relay ? null : opts.hiverelayRoot,
      mode: opts.relay ? 'external-relay' : 'local-hiverelay-relayapi',
      relay: null
    },
    checks: [],
    status: 'fail'
  }
  const r = makeReporter()
  report.checks = r.checks
  let relay = null
  let alice = null
  let bob = null
  let bobReload = null

  try {
    await cryptoReady()
    r.ok('crypto:ed25519', isSecure(), 'Peerit web build has a secure Ed25519 backend')

    relay = opts.relay
      ? { base: opts.relay.replace(/\/+$/, ''), mode: 'external-relay', stop: async () => {}, stats: () => null }
      : await startLocalHiveRelayOutboxLog(opts.hiverelayRoot)
    report.hiverelay.relay = relay.base
    console.log('[proof] target=' + relay.base)

    const bridgeStatusToken = await getToken(relay.base)
    const bridgeStatus = await fetch(relay.base + '/api/bridge/status', {
      headers: { 'X-Pear-Token': bridgeStatusToken }
    }).then(res => res.json())
    r.ok('hiverelay:bridge-status', bridgeStatus && bridgeStatus.ready === true && bridgeStatus.service === 'outboxlog', 'HiveRelay OutboxLog bridge reports ready', bridgeStatus)

    alice = await makeClient({ base: relay.base, name: 'alice-hiverelay', pollMs: opts.pollMs })
    bob = await makeClient({ base: relay.base, name: 'bob-hiverelay', pollMs: opts.pollMs })

    r.ok('peerit:gossip-bridge-mode', alice.sync.mode === 'gossip-bridge' && bob.sync.mode === 'gossip-bridge', 'Both Peerit web clients run in gossip-bridge mode')
    r.ok('peerit:distinct-writers', alice.pub !== bob.pub, 'Peerit clients use distinct writer keys', { alice: alice.pub, bob: bob.pub })
    r.ok('peerit:peer-discovery', await until(async () => {
      const [a, b] = await Promise.all([alice.sync.status(), bob.sync.status()])
      return a.peers >= 2 && b.peers >= 2
    }), 'Both clients discover at least two OutboxLog-backed outboxes')

    const slug = 'hrol' + Date.now().toString(36).slice(-6)
    await alice.data.createCommunity({
      slug,
      title: 'HiveRelay OutboxLog',
      description: 'Peerit convergence proof through HiveRelay OutboxLog'
    })
    const alicePost = await alice.data.submitPost({
      community: slug,
      kind: 'text',
      title: 'alice through hiverelay',
      body: 'created by alice through HiveRelay OutboxLog'
    })
    r.ok('peerit:community-visible', await until(() => bob.data.getCommunity(slug)), 'Bob sees Alice-created community through HiveRelay OutboxLog')
    r.ok('peerit:alice-post-visible', await until(() => bob.data.getPost(slug, alicePost.cid)), 'Bob sees Alice post through HiveRelay OutboxLog')

    const bobPost = await bob.data.submitPost({
      community: slug,
      kind: 'text',
      title: 'bob through hiverelay',
      body: 'created by bob through HiveRelay OutboxLog'
    })
    r.ok('peerit:bob-post-visible', await until(() => alice.data.getPost(slug, bobPost.cid)), 'Alice sees Bob post through HiveRelay OutboxLog')

    await alice.data.vote(alicePost.cid, slug, 'post', 1)
    await bob.data.vote(alicePost.cid, slug, 'post', 1)
    r.ok('peerit:votes-converge', await until(async () => {
      const tally = await bob.data.tallyFor(alicePost.cid)
      return tally.score === 2
    }), 'Two writer-local votes aggregate to score 2 through HiveRelay OutboxLog')

    const comment = await bob.data.addComment({
      community: slug,
      postCid: alicePost.cid,
      body: 'comment created by bob through HiveRelay OutboxLog'
    })
    r.ok('peerit:comment-visible', await until(() => alice.data.listComments(slug, alicePost.cid).then(comments => comments.some(c => c.cid === comment.cid))), 'Alice sees Bob comment through HiveRelay OutboxLog')

    await alice.data.editPost(slug, alicePost.cid, 'edited by alice through HiveRelay OutboxLog')
    r.ok('peerit:edit-visible', await until(() => bob.data.getPost(slug, alicePost.cid).then(post => post && post.body === 'edited by alice through HiveRelay OutboxLog')), 'Bob sees Alice signed edit through HiveRelay OutboxLog')

    bob.sync.destroy()
    bobReload = await makeClient({
      base: relay.base,
      name: 'bob-hiverelay',
      local: bob.local,
      session: bob.session,
      pollMs: opts.pollMs,
      createUser: false
    })
    r.ok('peerit:reload-same-writer', bobReload.pub === bob.pub, 'Reloaded Bob keeps the same writer key')
    r.ok('peerit:reload-sees-thread', await until(async () => {
      const post = await bobReload.data.getPost(slug, alicePost.cid)
      const comments = await bobReload.data.listComments(slug, alicePost.cid)
      const tally = await bobReload.data.tallyFor(alicePost.cid)
      return post && post.body === 'edited by alice through HiveRelay OutboxLog' &&
        comments.some(c => c.cid === comment.cid) &&
        tally.score === 2
    }), 'Reloaded Peerit client recovers community, post, vote tally, and comment through HiveRelay OutboxLog')

    const [aliceStatus, bobStatus] = await Promise.all([alice.sync.status(), bobReload.sync.status()])
    report.proof = {
      community: slug,
      alice: { writer: alice.pub, status: aliceStatus },
      bob: { writer: bob.pub, status: bobStatus },
      records: {
        alicePost: alicePost.cid,
        bobPost: bobPost.cid,
        comment: comment.cid
      },
      outboxlogStats: relay.stats()
    }
    report.status = 'pass'
    console.log('[proof] status=pass checks=' + report.checks.length)
    return report
  } catch (err) {
    report.error = { message: err.message, stack: tail(err.stack, 8000) }
    report.status = 'fail'
    throw err
  } finally {
    for (const client of [alice, bobReload, bob]) {
      if (client && client.sync) {
        try {
          client.sync.destroy()
        } catch {}
      }
    }
    if (relay) await relay.stop()
    if (opts.out) writeReport(opts.out, report)
  }
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  try {
    const report = await runProof(opts)
    if (opts.out) console.log('[proof] wrote ' + opts.out)
    console.log('[proof] completed ' + report.kind)
  } catch (err) {
    if (opts.out) console.error('[proof] wrote failed report ' + opts.out)
    console.error('[proof] failed: ' + err.message)
    process.exit(1)
  }
}

main()
