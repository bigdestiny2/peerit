// Browser-shaped writable-web lifecycle, without Playwright or live writes.
// Run: node test/writable-web-lurker.mjs
//
// Drives the real normal-web runtime, lazy identity, encrypted device identity
// store, Data post path, BridgeGossipSync atomic commit path, and two-relay pool.

import assert from 'node:assert/strict'
import { DevIdentity } from '../js/identity.js'
import { createIdentityStore, memoryKv } from '../js/identity-store.js'
import { createData } from '../js/data.js'
import { BridgeGossipSync } from '../js/gossip.js'
import { createRelayPool } from '../js/relay-pool.js'
import { resolveRuntime } from '../js/runtime.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'

const RELAYS = ['https://canary-a.example', 'https://canary-b.example']
const BITS = { post: 1, comment: 1, community: 1, blob: 1 }

function mem () {
  const values = new Map()
  return {
    getItem: (key) => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    clear: () => values.clear()
  }
}

function metaDocument (values) {
  return {
    querySelector (selector) {
      const match = selector.match(/^meta\[name="([^"]+)"\]$/)
      const name = match && match[1]
      return name && Object.hasOwn(values, name)
        ? { getAttribute: () => values[name] }
        : null
    }
  }
}

function response (value, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status >= 200 && status < 300 ? 'OK' : 'Error',
    text: async () => JSON.stringify(value)
  }
}

function makeRelayFleet () {
  const calls = []
  const stores = new Map(RELAYS.map((origin) => [origin, new Map()]))
  const versions = new Map(RELAYS.map((origin) => [origin, new Map()]))

  const rows = (origin, appId) => {
    const byApp = stores.get(origin)
    if (!byApp.has(appId)) byApp.set(appId, new Map())
    return byApp.get(appId)
  }
  const version = (origin, appId) => versions.get(origin).get(appId) || 0
  const setVersion = (origin, appId, value) => versions.get(origin).set(appId, value)
  const sortedRows = (origin, appId) => [...rows(origin, appId)]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => ({ key, value }))

  const fetch = async (input, options = {}) => {
    const url = new URL(String(input))
    const method = options.method || 'GET'
    const body = options.body ? JSON.parse(options.body) : null
    calls.push({ origin: url.origin, path: url.pathname, method, body })

    if (url.pathname === '/api/sync/create' || url.pathname === '/api/sync/append') {
      return response({ error: 'legacy write route forbidden in writable-web smoke' }, 500)
    }
    if (url.pathname === '/api/sync/commit') {
      const { appId, commit } = body
      const target = rows(url.origin, appId)
      for (const mutation of commit.mutations) {
        const key = mutation.type.replace(':', '!') + '!' + mutation.data.id
        target.set(key, mutation.data)
      }
      target.set('head!' + appId, commit.head.data)
      const relayVersion = version(url.origin, appId) + 1
      setVersion(url.origin, appId, relayVersion)
      return response({
        ok: true,
        durable: true,
        commitId: commit.commitId,
        appId,
        inviteKey: appId,
        head: {
          version: commit.head.data.version,
          count: commit.head.data.count,
          root: commit.head.data.root
        },
        relayVersion
      })
    }
    if (url.pathname === '/api/sync/heads') {
      return response({
        heads: Object.fromEntries((body.appIds || []).map((appId) => [appId, version(url.origin, appId)]))
      })
    }
    if (url.pathname === '/api/sync/get') {
      return response(rows(url.origin, url.searchParams.get('appId')).get(url.searchParams.get('key')) || null)
    }
    if (url.pathname === '/api/sync/list' || url.pathname === '/api/sync/range') {
      let result = sortedRows(url.origin, url.searchParams.get('appId'))
      const prefix = url.searchParams.get('prefix') || ''
      if (prefix) result = result.filter((row) => row.key >= prefix && row.key < prefix + '\xff')
      for (const [name, compare] of [
        ['gte', (key, bound) => key >= bound],
        ['gt', (key, bound) => key > bound],
        ['lte', (key, bound) => key <= bound],
        ['lt', (key, bound) => key < bound]
      ]) {
        const bound = url.searchParams.get(name)
        if (bound != null && bound !== '') result = result.filter((row) => compare(row.key, bound))
      }
      return response(result.slice(0, Number(url.searchParams.get('limit')) || 1000))
    }
    if (url.pathname === '/api/sync/count') {
      return response({ count: sortedRows(url.origin, url.searchParams.get('appId')).length })
    }
    if (url.pathname === '/api/sync/status') {
      const appId = url.searchParams.get('appId')
      return response({ appId, inviteKey: appId, writerCount: 1, viewLength: rows(url.origin, appId).size })
    }
    if (url.pathname === '/api/directory') return response({ heads: {}, hasMore: false, nextCursor: null })
    if (url.pathname === '/api/swarm/join') {
      return response({ channelId: 'writable-smoke', topicHex: body.topicHex, protocol: body.protocol, version: body.version, tier: 'A' })
    }
    if (url.pathname === '/api/swarm/send' || url.pathname === '/api/swarm/leave') return response({ ok: true })
    return response({ error: 'not found' }, 404)
  }

  class EventSource {
    constructor (url) { this.url = String(url); this.readyState = 1 }
    close () { this.readyState = 2 }
  }

  return { calls, stores, fetch, EventSource }
}

function makeSync ({ identity, storage, fleet }) {
  const origins = RELAYS.map((apiBase) => new URL(apiBase).origin)
  const capabilities = { atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: { mode: 'bounded', latestPerOutbox: true, hotReceiptsPerOutbox: 16, tombstonesPerOutbox: 64, aggregateEntries: 1024, extraHistoryEntries: 1000 } }, legacyWrites: { create: false, append: false } }
  const pear = createRelayPool({
    relays: RELAYS.map((apiBase, rosterIndex) => ({ apiBase, apiToken: `candidate-token-${rosterIndex}`, ready: true, atomicCommit: true, capabilities, canonicalOrigin: origins[rosterIndex], rosterVerified: true, rosterStable: true, rosterIndex, topologyId: 'test-writable-roster', rosterOrigins: origins, rosterSize: origins.length })),
    fetch: fleet.fetch,
    EventSource: fleet.EventSource
  })
  return new BridgeGossipSync({
    pear,
    getMe: () => identity.me().pubkey,
    identity,
    storage,
    validate: makeValidator(BITS),
    pollMs: 0,
    writeHead: true,
    readOnly: false,
    requireAtomicWrites: true,
    discover: false
  })
}

async function main () {
  await cryptoReady()

  const runtime = resolveRuntime({
    rawPear: null,
    doc: metaDocument({
      'peerit-relay': RELAYS.join(','),
      'peerit-relay-readonly': 'false'
    })
  })
  assert.equal(runtime.mode, 'web')
  assert.equal(runtime.readOnly, false)
  assert.equal(runtime.identityOpts.lazy, true)

  const fleet = makeRelayFleet()
  const syncStorage = mem()
  const identityKv = memoryKv()
  const deviceStore = createIdentityStore({ kv: identityKv })
  const identityA = new DevIdentity(mem(), mem(), { lazy: true })
  await identityA.ready()
  const syncA = makeSync({ identity: identityA, storage: syncStorage, fleet })
  await syncA.ready()

  assert.equal(identityA.me().pubkey, null, 'normal writable web boots as browsing/lurking')
  assert.equal(identityA.listUsers().length, 0, 'lurker boot mints no identity')
  assert.equal(fleet.calls.filter((call) => ['/api/sync/create', '/api/sync/append', '/api/sync/commit'].includes(call.path)).length, 0, 'boot makes zero write calls')

  let activations = 0
  let ensuring = null
  const ensureWriter = async () => {
    if (identityA.me().pubkey) return
    if (ensuring) return ensuring
    ensuring = (async () => {
      activations++
      const candidate = await identityA.mintEntry('anon')
      const saved = await deviceStore.saveOrAdopt(candidate)
      await identityA.addUser(saved.entry)
    })().finally(() => { ensuring = null })
    return ensuring
  }

  const dataA = createData(syncA, identityA, { ensureWriter, minBits: BITS })
  // The route already selected an existing community. Keeping this lookup local
  // isolates the lifecycle under test: explicit post intent -> writer activation.
  dataA.getCommunity = async (slug) => ({ slug, creator: 'e'.repeat(64), createdAt: 1 })
  dataA.overlay = async () => ({ banned: new Set(), mods: new Set() })

  const post = await dataA.submitPost({
    community: 'welcome',
    kind: 'text',
    title: 'First explicit writable-web post',
    body: 'The lurker chose to publish.'
  })
  const writer = identityA.me().pubkey
  assert.match(writer, /^[0-9a-f]{64}$/)
  assert.equal(post.author, writer)
  assert.equal(activations, 1, 'the explicit post is the only identity activation trigger')
  assert.equal(identityA.listUsers().length, 1, 'first post mints exactly one identity')

  const createCalls = fleet.calls.filter((call) => call.path === '/api/sync/create')
  const appendCalls = fleet.calls.filter((call) => call.path === '/api/sync/append')
  const commitCalls = fleet.calls.filter((call) => call.path === '/api/sync/commit')
  assert.equal(createCalls.length, 0)
  assert.equal(appendCalls.length, 0)
  assert.equal(commitCalls.length, 2, 'one identical atomic commit is sent to each selected relay')
  assert.equal(commitCalls[0].body.appId, writer)
  assert.deepEqual(commitCalls[0].body.commit, commitCalls[1].body.commit)
  assert.equal(commitCalls[0].body.commit.mutations.length, 1)
  assert.equal(commitCalls[0].body.commit.mutations[0].data.title, post.title)
  assert.equal(commitCalls[0].body.commit.head.data.version, 1)
  assert.equal(syncStorage.getItem('peerit:pending-commit:v1'), null, 'matching durable quorum clears the pending marker')

  const durable = await deviceStore.load()
  assert.equal(durable.pubkey, writer, 'identity is durable before publication returns')

  // Simulated reload: fresh JS identity/sync objects, same browser device stores.
  syncA.destroy()
  const identityB = new DevIdentity(mem(), mem(), { lazy: true })
  await identityB.ready()
  assert.equal(identityB.me().pubkey, null, 'fresh runtime starts identity-less before device restore')
  await identityB.addUser(await deviceStore.load())
  assert.equal(identityB.me().pubkey, writer, 'reload restores the same writer identity')

  const commitsBeforeReload = commitCalls.length
  const syncB = makeSync({ identity: identityB, storage: syncStorage, fleet })
  await syncB.ready()
  assert.equal(fleet.calls.filter((call) => call.path === '/api/sync/commit').length, commitsBeforeReload, 'clean reload does not replay or create another commit')
  assert.equal(fleet.calls.filter((call) => call.path === '/api/sync/create').length, 0, 'restored writer boot still never uses create')
  assert.equal(fleet.calls.filter((call) => call.path === '/api/sync/append').length, 0, 'restored writer boot still never uses append')
  syncB.destroy()

  console.log('writable-web-lurker: lurker boot, explicit post activation, atomic quorum, and identity reload passed')
}

main().catch((err) => {
  console.error('writable-web-lurker: FAILED', err.stack || err.message)
  process.exit(1)
})
