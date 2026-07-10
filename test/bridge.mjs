// bridge.mjs — host bridge contract checks for PearBrowser mobile/desktop.
// Verifies that token-gated `/api/*` routes can back Peerit's bridge mode and
// that partial bridge injection fails closed instead of downgrading to dev.

import assert from 'node:assert'
import { createPearApi, hasAnyPearBridgeSurface, hasGossipPearSurface, resolvePear } from '../js/pear-api.js'
import { createIdentity } from '../js/identity.js'
import { createSync } from '../js/sync.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

const PUB = 'a'.repeat(64)
const DRIVE = 'b'.repeat(64)
const INVITE = 'c'.repeat(64)
const SIG = 'd'.repeat(128)

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

function response (value, status = 200, extra = {}) {
  return {
    ...extra,
    ok: status >= 200 && status < 300,
    status,
    statusText: status >= 200 && status < 300 ? 'OK' : 'API error',
    text: async () => JSON.stringify(value)
  }
}

function makeApiHost () {
  const calls = []
  const groups = new Map()
  const ensure = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { inviteKey: INVITE, rows: new Map() })
    return groups.get(appId)
  }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))

  async function fetch (url, opts = {}) {
    const u = new URL(String(url))
    const body = opts.body ? JSON.parse(opts.body) : null
    calls.push({
      method: opts.method || 'GET',
      path: u.pathname + u.search,
      token: opts.headers && opts.headers['X-Pear-Token'],
      body
    })

    try {
      if (u.pathname === '/api/identity') return response({ publicKey: PUB, driveKey: DRIVE, algorithm: 'ed25519' })
      if (u.pathname === '/api/identity/sign') return response({ signature: SIG, publicKey: PUB, algorithm: 'ed25519', tag: `pear.app.${DRIVE}:${body.namespace || ''}:${body.payload}` })

      if (u.pathname === '/api/sync/create') {
        ensure(body.appId)
        return response({ appId: body.appId, inviteKey: INVITE, writerPublicKey: PUB })
      }
      if (u.pathname === '/api/sync/join') {
        const g = ensure(body.appId)
        if (body.inviteKey !== g.inviteKey) return response({ error: 'bad invite' }, 400)
        return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: PUB })
      }
      if (u.pathname === '/api/sync/append') {
        const g = ensure(body.appId)
        const op = body.op
        const key = op.type.replace(':', '!') + '!' + op.data.id
        g.rows.set(key, op.data)
        return response({ ok: true, key })
      }
      if (u.pathname === '/api/sync/get') {
        const g = ensure(u.searchParams.get('appId'))
        return response(g.rows.get(u.searchParams.get('key')) || null)
      }
      if (u.pathname === '/api/sync/list' || u.pathname === '/api/sync/range') {
        const g = ensure(u.searchParams.get('appId'))
        const limit = Number(u.searchParams.get('limit')) || 100
        const prefix = u.searchParams.get('prefix') || ''
        let rows = sortedRows(g)
        if (prefix) rows = rows.filter(r => r.key >= prefix && r.key < prefix + '\xff')
        for (const bound of ['gte', 'gt', 'lte', 'lt']) {
          const v = u.searchParams.get(bound)
          if (!v) continue
          if (bound === 'gte') rows = rows.filter(r => r.key >= v)
          if (bound === 'gt') rows = rows.filter(r => r.key > v)
          if (bound === 'lte') rows = rows.filter(r => r.key <= v)
          if (bound === 'lt') rows = rows.filter(r => r.key < v)
        }
        return response(rows.slice(0, limit))
      }
      if (u.pathname === '/api/sync/ranges') {
        const requests = Array.isArray(body && body.requests) ? body.requests : []
        const ranges = requests.map((request) => {
          const g = ensure(request.appId)
          let rows = sortedRows(g)
          if (request.gt) rows = rows.filter((row) => row.key > request.gt)
          return { appId: request.appId, rows: rows.slice(0, Number(request.limit) || 100) }
        })
        return response({ ranges })
      }
      if (u.pathname === '/api/sync/count') {
        const g = ensure(u.searchParams.get('appId'))
        return response({ count: sortedRows(g).length })
      }
      if (u.pathname === '/api/sync/status') {
        const appId = u.searchParams.get('appId')
        const g = ensure(appId)
        return response({ appId, inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size })
      }

      if (u.pathname === '/api/swarm/join') {
        return response({
          channelId: 'channel-1',
          topicHex: body.topicHex || '0'.repeat(64),
          protocol: body.protocol,
          version: body.version,
          tier: 'A'
        })
      }
      if (u.pathname === '/api/swarm/send' || u.pathname === '/api/swarm/leave') return response({ ok: true })
      if (u.pathname === '/api/bridge/status') return response({ ready: true, port: 12345 })
      return response({ error: 'not found' }, 404)
    } catch (err) {
      return response({ error: err.message }, 500)
    }
  }

  return { base: 'https://peerit.test', calls, fetch, groups }
}

class FakeEventSource {
  static instances = []
  constructor (url) {
    this.url = url
    this.closed = false
    FakeEventSource.instances.push(this)
  }

  close () { this.closed = true }
}

async function main () {
  console.log('\n— mobile /api bridge fallback —')
  const host = makeApiHost()
  const pear = createPearApi({ apiToken: 'token-1', apiBase: host.base, fetch: host.fetch, EventSource: FakeEventSource })
  ok(hasGossipPearSurface(pear), 'token-gated /api wrapper exposes sync, identity, and swarm.v1')
  ok(typeof pear.sync.ranges === 'undefined', 'batch ranges are absent until a relay explicitly advertises them')
  const batchPear = createPearApi({ apiToken: 'token-1', apiBase: host.base, fetch: host.fetch, EventSource: FakeEventSource, batchRanges: true })
  const batchRows = await batchPear.sync.ranges([{ appId: PUB, gt: '', limit: 10 }])
  ok(Array.isArray(batchRows.ranges) && batchRows.ranges[0].appId === PUB, 'advertised batch ranges use one authenticated POST request')
  const metaPear = createPearApi({
    document: { querySelector: () => ({ getAttribute: () => 'token-1' }) },
    apiBase: host.base,
    fetch: host.fetch,
    EventSource: FakeEventSource
  })
  ok(hasGossipPearSurface(metaPear), 'bridge token can be discovered from injected pear-api-token meta tag')
  ok(createPearApi({ apiBase: host.base, fetch: host.fetch, EventSource: FakeEventSource }) === null, 'missing bridge token does not create an ambient /api surface')

  const redirectedPear = createPearApi({
    apiToken: 'token-1',
    apiBase: 'https://front.example',
    fetch: async () => response({ ok: true }, 200, { redirected: true, url: 'https://backend.example/api/sync/get' }),
    requestTimeoutMs: 30
  })
  await assert.rejects(() => redirectedPear.sync.get(PUB, 'profile!' + PUB), (error) => error && error.code === 'PEAR_API_REDIRECT')
  ok(true, 'post-admission API calls reject detectable redirects instead of following an alias')

  const hangingPear = createPearApi({ apiToken: 'token-1', apiBase: host.base, fetch: async () => new Promise(() => {}), requestTimeoutMs: 25 })
  const hangingStarted = Date.now()
  await assert.rejects(() => hangingPear.sync.get(PUB, 'profile!' + PUB), (error) => error && error.code === 'PEAR_API_TIMEOUT')
  ok(Date.now() - hangingStarted < 500, 'every token-gated API request has a finite timeout even when fetch ignores abort')
  const hangingBodyPear = createPearApi({
    apiToken: 'token-1',
    apiBase: host.base,
    requestTimeoutMs: 25,
    fetch: async () => ({ ok: true, status: 200, statusText: 'OK', text: async () => new Promise(() => {}) })
  })
  await assert.rejects(() => hangingBodyPear.sync.get(PUB, 'profile!' + PUB), (error) => error && error.code === 'PEAR_API_TIMEOUT')
  ok(true, 'request timeout also bounds a relay that sends headers then stalls its JSON body')

  const identity = createIdentity({ apiToken: 'token-1', apiBase: host.base, fetch: host.fetch, EventSource: FakeEventSource })
  await identity.ready()
  ok(identity.isDev === false && identity.me().pubkey === PUB && identity.me().driveKey === DRIVE, 'identity factory uses host signing identity from /api')
  const signed = await identity.sign('payload', 'peerit')
  ok(signed.signature === SIG && signed.driveKey === DRIVE && signed.namespace === 'peerit', 'host signature response is normalized for Peerit records')

  const sync = createSync({
    apiToken: 'token-1',
    apiBase: host.base,
    fetch: host.fetch,
    EventSource: FakeEventSource,
    storage: mem(),
    getMe: () => identity.me().pubkey,
    identity
  })
  await sync.ready()
  ok(sync.mode === 'gossip-bridge', 'sync factory enters gossip-bridge over /api fallback')
  ok(FakeEventSource.instances.some(es => es.url.includes('/api/swarm/events') && es.url.includes('token=token-1')), 'swarm event stream carries the bridge token')
  await sync.append({ type: 'profile', data: { id: PUB, author: PUB, updatedAt: Date.now() } })
  const stored = host.groups.get(PUB).rows.get('profile!' + PUB)
  ok(stored && stored.author === PUB, 'bridge append writes through /api sync, not localStorage')
  ok(host.calls.every(c => c.token === 'token-1' || c.path.startsWith('/api/swarm/events')), 'all HTTP bridge calls carry X-Pear-Token')

  const appendCallsBeforeReadOnly = host.calls.filter(c => c.path.startsWith('/api/sync/append')).length
  const readOnlySync = createSync({
    apiToken: 'token-1',
    apiBase: host.base,
    fetch: host.fetch,
    EventSource: FakeEventSource,
    storage: mem(),
    getMe: () => identity.me().pubkey,
    identity,
    readOnly: true
  })
  await readOnlySync.ready()
  await assert.rejects(
    () => readOnlySync.append({ type: 'profile', data: { id: PUB, author: PUB, updatedAt: Date.now() } }),
    /read-only/
  )
  ok(host.calls.filter(c => c.path.startsWith('/api/sync/append')).length === appendCallsBeforeReadOnly, 'read-only bridge rejects appends before touching /api sync')

  console.log('\n— partial bridge fail-closed behavior —')
  const merged = resolvePear({ pear: { swarm: { v1: { join: async () => ({ peers: [], on: () => {} }) } } }, apiToken: 'token-1', apiBase: host.base, fetch: host.fetch, EventSource: FakeEventSource })
  ok(hasGossipPearSurface(merged), 'partial window.pear can be completed by token-gated /api fallback')
  const partialSyncMerged = resolvePear({
    pear: { sync: { create: async () => ({}) }, identity: { getPublicKey: async () => ({ publicKey: 'e'.repeat(64), driveKey: 'f'.repeat(64) }) } },
    apiToken: 'token-1',
    apiBase: host.base,
    fetch: host.fetch,
    EventSource: FakeEventSource
  })
  ok(hasGossipPearSurface(partialSyncMerged), 'partial injected sync/identity cannot mask a complete token-gated /api bridge')
  const partialIdentity = createIdentity({
    pear: { identity: { getPublicKey: async () => ({ publicKey: 'e'.repeat(64), driveKey: 'f'.repeat(64) }) } },
    apiToken: 'token-1',
    apiBase: host.base,
    fetch: host.fetch,
    EventSource: FakeEventSource
  })
  await partialIdentity.ready()
  ok(partialIdentity.me().pubkey === PUB, 'incomplete injected identity is replaced by the complete /api identity surface')
  ok(hasAnyPearBridgeSurface({ drive: {} }), 'non-sync PearBrowser host surfaces still count as bridge presence')
  assert.throws(
    () => createIdentity({ pear: { drive: {} } }),
    /identity signing is unavailable/
  )
  ok(true, 'non-sync PearBrowser host surface cannot downgrade to dev identity')
  assert.throws(
    () => createIdentity({ pear: { swarm: { v1: { join: async () => ({}) } } } }),
    /identity signing is unavailable/
  )
  ok(true, 'partial Pear bridge without host identity cannot downgrade to dev identity')
  assert.throws(
    () => createSync({ pear: { identity: pear.identity }, getMe: () => PUB, identity }),
    /refusing to fall back to local dev sync/
  )
  ok(true, 'partial Pear bridge without sync/swarm cannot downgrade to dev sync')
  const devSync = createSync({ storage: mem(), getMe: () => PUB, identity })
  ok(devSync.mode === 'gossip-dev', 'plain browsers with no bridge still get explicit dev fallback')

  console.log(`\n✅ all ${passed} bridge checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
