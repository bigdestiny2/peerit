// directory.mjs — Phase D of the P2P durability spec: the durable signed
// directory. The relay serves every outbox's SIGNED head in one /api/directory
// call, and a verified-roster pool uses the deterministic writer leader's
// VERIFIED head (or matching mirror evidence). A client bootstraps its rollback
// floor from it at boot — so even a
// FRESH visitor has a cross-relay floor for every author immediately, instead of
// accumulating floors as it browses. Relay can't forge: every head re-verified.
//   node test/directory.mjs   (part of `npm test`)

import assert from 'node:assert'
import { randomBytes } from 'node:crypto'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { createSync } from '../js/sync.js'
import { createRelayPool } from '../js/relay-pool.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { keys } from '../js/model.js'
import { makeValidator } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const BITS = { community: 7, post: 6, comment: 5 }
function mem () { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
async function until (fn, { tries = 200, gap = 60 } = {}) { for (let i = 0; i < tries; i++) { if (await fn()) return true; await delay(gap) } return false }

function makeMultiWorld (bases) {
  const relays = new Map(bases.map((b) => [new URL(b).host, { groups: new Map() }]))
  const channels = new Map(); let chanSeq = 0
  const ensureGroup = (store, appId) => { if (!store.has(appId)) store.set(appId, { inviteKey: randomBytes(32).toString('hex'), rows: new Map(), version: 0, commits: new Map() }); return store.get(appId) }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  const deliver = (id, msg) => { const c = channels.get(id); if (!c || !c.es || !c.es.onmessage) return; setTimeout(() => { try { c.es.onmessage({ data: JSON.stringify(msg) }) } catch {} }, 0) }
  const linkPeers = (id) => { const c = channels.get(id); if (!c || !c.es) return; for (const [o, ot] of channels) { if (o === id || ot.topic !== c.topic || !ot.es || c.linked.has(o)) continue; c.linked.add(o); ot.linked.add(id); deliver(id, { type: 'peer', peerId: o, pubkey: null }); deliver(o, { type: 'peer', peerId: id, pubkey: null }) } }
  const resp = (v, s = 200) => ({ ok: s >= 200 && s < 300, status: s, statusText: 'OK', text: async () => JSON.stringify(v) })
  async function fetch (url, opts = {}) {
    const u = new URL(String(url)); const p = u.pathname; const body = opts.body ? JSON.parse(opts.body) : null
    const relay = relays.get(u.host); const store = relay ? relay.groups : new Map()
    if (p === '/api/token') return resp({ token: 't' })
    if (p === '/api/sync/create' || p === '/api/sync/join') { const g = ensureGroup(store, body.appId); return resp({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
    if (p === '/api/sync/append') { const g = ensureGroup(store, body.appId); const op = body.op; g.rows.set(op.type.replace(':', '!') + '!' + op.data.id, op.data); g.version++; return resp({ ok: true }) }
    if (p === '/api/sync/commit') {
      const commit = body.commit
      const g = ensureGroup(store, body.appId)
      const duplicate = g.commits.get(commit.commitId)
      if (duplicate) return resp(duplicate)
      const current = g.rows.get(keys.head(body.appId))
      const currentVersion = current ? (current.version | 0) : 0
      const currentRoot = current ? current.root : commit.expected.root
      if (commit.expected.version !== currentVersion || commit.expected.root !== currentRoot) return resp({ error: 'stale compare-and-swap', code: 'COMMIT_CAS_MISMATCH' }, 409)
      for (const op of commit.mutations) g.rows.set(op.type.replace(':', '!') + '!' + op.data.id, op.data)
      g.rows.set(keys.head(body.appId), commit.head.data)
      g.version++
      const receipt = { ok: true, durable: true, commitId: commit.commitId, appId: body.appId, inviteKey: g.inviteKey, head: { version: commit.head.data.version, count: commit.head.data.count, root: commit.head.data.root }, relayVersion: g.version }
      g.commits.set(commit.commitId, receipt)
      return resp(receipt)
    }
    if (p === '/api/sync/heads') { const out = {}; for (const a of (body.appIds || [])) { const g = store.get(a); out[a] = g ? g.version : 0 }; return resp({ heads: out }) }
    if (p === '/api/sync/get') { const g = ensureGroup(store, u.searchParams.get('appId')); return resp(g.rows.get(u.searchParams.get('key')) || null) }
    if (p === '/api/sync/list' || p === '/api/sync/range') {
      const g = ensureGroup(store, u.searchParams.get('appId')); let rows = sortedRows(g)
      const pre = u.searchParams.get('prefix'); if (pre) rows = rows.filter((r) => r.key >= pre && r.key < pre + '\xff')
      for (const [b, cmp] of [['gte', (k, v) => k >= v], ['gt', (k, v) => k > v], ['lte', (k, v) => k <= v], ['lt', (k, v) => k < v]]) { const v = u.searchParams.get(b); if (v != null && v !== '') rows = rows.filter((r) => cmp(r.key, v)) }
      return resp(rows.slice(0, Number(u.searchParams.get('limit')) || 100))
    }
    if (p === '/api/directory') { const heads = {}; for (const [appId, g] of store) { const h = g.rows.get('head!' + appId); if (h) heads[appId] = h }; return resp({ heads }) }
    if (p === '/api/sync/status') { const g = ensureGroup(store, u.searchParams.get('appId')); return resp({ appId: u.searchParams.get('appId'), inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size }) }
    if (p === '/api/swarm/join') { const id = 'ch-' + (++chanSeq); channels.set(id, { topic: body.topicHex || 'd', es: null, linked: new Set() }); return resp({ channelId: id, topicHex: body.topicHex || 'd', protocol: body.protocol, version: body.version, tier: 'A' }) }
    if (p === '/api/swarm/send') { deliver(body.peerId, { type: 'message', peerId: body.channelId, data: body.data }); return resp({ ok: true }) }
    if (p === '/api/swarm/leave') { channels.delete(body.channelId); return resp({ ok: true }) }
    if (p === '/api/bridge/status') return resp({ ready: true })
    return resp({ error: 'nf' }, 404)
  }
  class ES { constructor (url) { this.url = String(url); this.onmessage = null; this.onerror = null; const id = new URL(this.url).searchParams.get('channelId'); const c = channels.get(id); if (c) { c.es = this; setTimeout(() => linkPeers(id), 0) } } close () {} }
  return { fetch, EventSource: ES, relays }
}
const storeOf = (world, base, pub) => world.relays.get(new URL(base).host).groups.get(pub)

async function makeClient (world, bases, name, { writeHead = false, storage = mem(), pollMs = 250 } = {}) {
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const origins = bases.map((base) => new URL(base).origin)
  const capabilities = { atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: { mode: 'bounded', latestPerOutbox: true, hotReceiptsPerOutbox: 16, tombstonesPerOutbox: 64, aggregateEntries: 1024, extraHistoryEntries: 1000 } }, legacyWrites: { create: false, append: false } }
  const relays = bases.map((apiBase, rosterIndex) => ({ apiBase, apiToken: 't', ready: true, atomicCommit: true, capabilities, canonicalOrigin: origins[rosterIndex], rosterVerified: true, rosterStable: true, rosterIndex, topologyId: 'test-directory-roster', rosterOrigins: origins, rosterSize: origins.length }))
  const pool = createRelayPool({ relays, fetch: world.fetch, EventSource: world.EventSource })
  const sync = createSync({ getMe: () => id.me().pubkey, identity: id, pear: pool, validate: makeValidator(BITS), pollMs, writeHead, storage })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, storage, pool }
}
const floorOf = (storage) => JSON.parse(storage.getItem('peerit:head-floor') || '{}')

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available')
  const A = 'https://a.peerit.test'; const B = 'https://b.peerit.test'
  const world = makeMultiWorld([A, B])

  console.log('\n— the relay directory serves every outbox\'s signed head —')
  const alice = await makeClient(world, [A, B], 'alice', { writeHead: true })
  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'x' })
  const v1Head = storeOf(world, A, alice.pub).rows.get(keys.head(alice.pub)) // a validly-signed v1 head to replay later
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'first', body: '1' })
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'second', body: '2' })
  const dir = JSON.parse(await (await world.fetch(A + '/api/directory')).text())
  ok(dir.heads[alice.pub] && dir.heads[alice.pub].version === 3, 'GET /api/directory returns alice\'s signed head at version 3')

  console.log('\n— a FRESH visitor bootstraps its floor from the directory (no browsing yet) —')
  const bob = await makeClient(world, [A, B], 'bob')
  ok(floorOf(bob.storage)[alice.pub] && floorOf(bob.storage)[alice.pub].v === 3, 'bob has a durable floor of v3 for alice immediately after boot — from the directory, before reading her outbox')
  const bobFloor = floorOf(bob.storage)[alice.pub]
  ok(/^[0-9a-f]{64}$/i.test(String((bobFloor && bobFloor.root) || '')), 'the directory bootstrap also pins alice\'s signed head root')

  console.log('\n— cross-relay: a stale mirror cannot override the roster leader —')
  const aliceLeader = alice.pool._leaderFor(alice.pub).origin
  const staleMirror = [A, B].find((base) => new URL(base).origin !== aliceLeader)
  storeOf(world, staleMirror, alice.pub).rows.set(keys.head(alice.pub), v1Head)
  const carol = await makeClient(world, [A, B], 'carol')
  ok(floorOf(carol.storage)[alice.pub] && floorOf(carol.storage)[alice.pub].v === 3, 'carol bootstraps the leader\'s v3 floor; a stale signed mirror does not override it')

  console.log('\n— the bootstrapped floor arms rollback detection from the first read —')
  for (const base of [A, B]) storeOf(world, base, alice.pub).rows.set(keys.head(alice.pub), v1Head)
  storeOf(world, A, alice.pub).version += 5; storeOf(world, B, alice.pub).version += 5
  const dave = await makeClient(world, [A, B], 'dave') // floor bootstrapped to v3, but every relay serves v1
  const flagged = await until(async () => (await dave.sync.status()).withholding.includes(alice.pub), { tries: 80 })
  ok(flagged, 'a fresh visitor whose floor was directory-seeded to v3 FLAGS the all-relays rollback to v1 on first read')

  for (const c of [alice, bob, carol, dave]) c.sync.destroy && c.sync.destroy()
  console.log(`\n✅ all ${passed} directory checks passed\n`)
}
main().catch((e) => { console.error('❌', (e && e.stack) || e); process.exit(1) })
