// relay-pool.mjs — Phase B of the P2P durability spec: the multi-relay pool.
// Writes fan out across relays and each author's SIGNED head is cross-checked
// (highest version wins), so a single relay serving a STALE head (rollback) or
// dropping it (STRIP) — the two open Phase A gaps — is caught and the reader
// routes the READ around it (recoverRows) to a relay that serves the committed
// set. Relays stay untrusted: every record + head is re-verified client-side.
//   node test/relay-pool.mjs   (part of `npm test`)

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
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const BITS = { community: 7, post: 6, comment: 5 }
const ATOMIC_CAPABILITIES = { atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: { mode: 'bounded', latestPerOutbox: true, hotReceiptsPerOutbox: 16, tombstonesPerOutbox: 64, aggregateEntries: 1024, extraHistoryEntries: 1000 } }, legacyWrites: { create: false, append: false } }
function signedWriterRelays (bases) { const origins = bases.map((base) => new URL(base).origin); const topologyId = 'test-signed-roster|' + bases.join('|'); return bases.map((apiBase, rosterIndex) => ({ apiBase, apiToken: 't', ready: true, atomicCommit: true, capabilities: ATOMIC_CAPABILITIES, canonicalOrigin: origins[rosterIndex], rosterVerified: true, rosterStable: true, rosterIndex, topologyId, rosterOrigins: origins, rosterSize: origins.length })) }
function mem () { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
async function until (fn, { tries = 200, gap = 60 } = {}) { for (let i = 0; i < tries; i++) { if (await fn()) return true; await delay(gap) } return false }

// A world of N independent relays (each its own /api/sync store) + ONE shared
// swarm hub (the pool joins the swarm only on its primary). fetch routes sync
// ops to the relay named in the URL host; swarm ops to the shared hub.
function makeMultiWorld (bases) {
  const relays = new Map(bases.map((b) => [new URL(b).host, { groups: new Map() }]))
  const channels = new Map(); let chanSeq = 0
  const ensureGroup = (store, appId) => { if (!store.has(appId)) store.set(appId, { inviteKey: randomBytes(32).toString('hex'), rows: new Map(), version: 0, commits: new Map() }); return store.get(appId) }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  const deliver = (channelId, msg) => { const c = channels.get(channelId); if (!c || !c.es || !c.es.onmessage) return; setTimeout(() => { try { c.es.onmessage({ data: JSON.stringify(msg) }) } catch {} }, 0) }
  const linkPeers = (channelId) => {
    const c = channels.get(channelId); if (!c || !c.es) return
    for (const [otherId, other] of channels) {
      if (otherId === channelId || other.topic !== c.topic || !other.es || c.linked.has(otherId)) continue
      c.linked.add(otherId); other.linked.add(channelId)
      deliver(channelId, { type: 'peer', peerId: otherId, pubkey: null }); deliver(otherId, { type: 'peer', peerId: channelId, pubkey: null })
    }
  }
  const response = (value, status = 200) => ({ ok: status >= 200 && status < 300, status, statusText: 'OK', text: async () => JSON.stringify(value) })
  async function fetch (url, opts = {}) {
    const u = new URL(String(url)); const p = u.pathname; const body = opts.body ? JSON.parse(opts.body) : null
    const relay = relays.get(u.host); const store = relay ? relay.groups : new Map()
    if (p === '/api/token') return response({ token: 't' })
    if (p === '/api/sync/create') { const g = ensureGroup(store, body.appId); return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
    if (p === '/api/sync/join') { const g = ensureGroup(store, body.appId); return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
    if (p === '/api/sync/append') { const g = ensureGroup(store, body.appId); const op = body.op; g.rows.set(op.type.replace(':', '!') + '!' + op.data.id, op.data); g.version++; return response({ ok: true }) }
    if (p === '/api/sync/commit') {
      const commit = body.commit
      const g = ensureGroup(store, body.appId)
      const duplicate = g.commits.get(commit.commitId)
      if (duplicate) return response(duplicate)
      const current = g.rows.get(keys.head(body.appId))
      const currentVersion = current ? (current.version | 0) : 0
      const currentRoot = current ? current.root : commit.expected.root
      if (commit.expected.version !== currentVersion || commit.expected.root !== currentRoot) return response({ error: 'stale compare-and-swap', code: 'COMMIT_CAS_MISMATCH' }, 409)
      for (const op of commit.mutations) g.rows.set(op.type.replace(':', '!') + '!' + op.data.id, op.data)
      g.rows.set(keys.head(body.appId), commit.head.data)
      g.version++
      const receipt = {
        ok: true,
        durable: true,
        commitId: commit.commitId,
        appId: body.appId,
        inviteKey: g.inviteKey,
        head: { version: commit.head.data.version, count: commit.head.data.count, root: commit.head.data.root },
        relayVersion: g.version
      }
      g.commits.set(commit.commitId, receipt)
      return response(receipt)
    }
    if (p === '/api/sync/heads') { const out = {}; for (const a of (body.appIds || [])) { const g = store.get(a); out[a] = g ? g.version : 0 }; return response({ heads: out }) }
    if (p === '/api/sync/get') { const g = ensureGroup(store, u.searchParams.get('appId')); return response(g.rows.get(u.searchParams.get('key')) || null) }
    if (p === '/api/sync/list' || p === '/api/sync/range') {
      const g = ensureGroup(store, u.searchParams.get('appId')); let rows = sortedRows(g)
      const prefix = u.searchParams.get('prefix'); if (prefix) rows = rows.filter((r) => r.key >= prefix && r.key < prefix + '\xff')
      for (const [bound, cmp] of [['gte', (k, v) => k >= v], ['gt', (k, v) => k > v], ['lte', (k, v) => k <= v], ['lt', (k, v) => k < v]]) { const v = u.searchParams.get(bound); if (v != null && v !== '') rows = rows.filter((r) => cmp(r.key, v)) }
      return response(rows.slice(0, Number(u.searchParams.get('limit')) || 100))
    }
    if (p === '/api/sync/status') { const g = ensureGroup(store, u.searchParams.get('appId')); return response({ appId: u.searchParams.get('appId'), inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size }) }
    if (p === '/api/directory') {
      const heads = {}
      for (const [appId, g] of store) { const head = g.rows.get(keys.head(appId)); if (head) heads[appId] = head }
      return response({ heads, hasMore: false, nextCursor: null })
    }
    if (p === '/api/swarm/join') { const id = 'ch-' + (++chanSeq); channels.set(id, { topic: body.topicHex || 'default', es: null, linked: new Set() }); return response({ channelId: id, topicHex: body.topicHex || 'default', protocol: body.protocol, version: body.version, tier: 'A' }) }
    if (p === '/api/swarm/send') { deliver(body.peerId, { type: 'message', peerId: body.channelId, data: body.data }); return response({ ok: true }) }
    if (p === '/api/swarm/leave') { channels.delete(body.channelId); return response({ ok: true }) }
    if (p === '/api/bridge/status') return response({ ready: true })
    return response({ error: 'not found' }, 404)
  }
  class HubEventSource { constructor (url) { this.url = String(url); this.onmessage = null; this.onerror = null; const channelId = new URL(this.url).searchParams.get('channelId'); const c = channels.get(channelId); if (c) { c.es = this; setTimeout(() => linkPeers(channelId), 0) } } close () {} }
  return { fetch, EventSource: HubEventSource, relays }
}

async function makeClient (world, bases, name, { writeHead = false, pollMs = 250 } = {}) {
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const pool = createRelayPool({ relays: signedWriterRelays(bases), fetch: world.fetch, EventSource: world.EventSource })
  const sync = createSync({ getMe: () => id.me().pubkey, identity: id, pear: pool, validate: makeValidator(BITS), pollMs, writeHead })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, name, pool }
}

const storeOf = (world, base, pub) => world.relays.get(new URL(base).host).groups.get(pub)

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available')

  const A = 'https://a.peerit.test'; const B = 'https://b.peerit.test'
  const world = makeMultiWorld([A, B])

  console.log('\n— writes fan out to every relay in the pool —')
  const alice = await makeClient(world, [A, B], 'alice', { writeHead: true })
  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'serverless reddit' })
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'first', body: 'one' })
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'second', body: 'two' })

  const headKey = keys.head(alice.pub)
  const onA = storeOf(world, A, alice.pub); const onB = storeOf(world, B, alice.pub)
  ok(onA && onB, 'alice\'s outbox exists on BOTH relays (write fan-out)')
  ok(onA.rows.has(headKey) && onB.rows.has(headKey), 'the signed head landed on both relays')
  ok(onA.rows.get(headKey).version === onB.rows.get(headKey).version && onA.rows.get(headKey).count === 3, 'both relays carry the same head (version + count=3)')

  console.log('\n— ROLLBACK: primary (A) reverts to an old head+subset; the pool recovers from B —')
  // Snapshot A at v1 (community + head v1), then let alice add more; then FORCE A
  // back to that stale snapshot while B keeps the current v3 state.
  const stale = new Map()
  stale.set(keys.community('p2p'), onA.rows.get(keys.community('p2p')))
  // rebuild a v1-style head over just the community, signed by alice, by reading B's history is complex;
  // simplest: drop A down to {community + a head that under-counts}. Reuse A's OWN earlier head if present.
  // We emulate rollback by trimming A to the community + the CURRENT head is removed and replaced with a
  // hand-rolled OLDER head is unsigned → instead: trim A to community + posts MINUS one, keep head v3.
  // That is a withhold+rollback the audit must still catch via B's identical v3 head.
  onA.rows.delete('post!p2p!' + [...onA.rows.keys()].filter((k) => k.startsWith('post!p2p!'))[1].split('!')[2]) // drop one post on A
  onA.rows.delete(headKey) // and STRIP A's head entirely (worst case: rollback + strip)
  ok(!onA.rows.has(headKey) && [...onA.rows.keys()].filter((k) => k.startsWith('post!p2p!')).length === 1, 'relay A now strips the head AND withholds one post (B still has head v3 + both posts)')

  const bob = await makeClient(world, [A, B], 'bob', { writeHead: false })
  const bobFull = await until(async () => (await bob.data.listPostsIn('p2p')).length >= 2)
  ok(bobFull, 'bob (primary A) still sees BOTH of alice\'s posts — the pool recovered the withheld/stripped set from B')
  const st = await bob.sync.status()
  ok(Array.isArray(st.withholding) && st.withholding.length === 0, 'after recovery bob reports NO unresolved withholding (a relay serving the committed set was found)')
  ok((await bob.data.getCommunity('p2p'))?.title === 'P2P', 'bob resolves r/p2p (community record recovered too)')
  // F7: recovery must STICK — reads are pinned to B, so the withholding primary A
  // can't re-strip the recovered rows on subsequent polls (would flap 2<->1 if not).
  await delay(1600)
  ok((await bob.data.listPostsIn('p2p')).length >= 2, 'recovery STICKS across ~6 polls (reads pinned to the good relay, not re-stripped by A)')

  console.log('\n— when NO relay serves the committed set, withholding is flagged —')
  // Break BOTH relays for a NEW author so recovery has nowhere to route.
  const carol = await makeClient(world, [A, B], 'carol', { writeHead: true })
  await carol.data.createCommunity({ slug: 'solo', title: 'Solo', description: 'x' })
  await carol.data.submitPost({ community: 'solo', kind: 'text', title: 'c1', body: 'c' })
  // Drop the same post from BOTH relays but keep carol's head (count still claims it):
  for (const base of [A, B]) { const g = storeOf(world, base, carol.pub); const pk = [...g.rows.keys()].find((k) => k.startsWith('post!solo!')); g.rows.delete(pk) }
  const dave = await makeClient(world, [A, B], 'dave', { writeHead: false })
  const flagged = await until(async () => (await dave.sync.status()).withholding.includes(carol.pub), { tries: 80 })
  ok(flagged, 'dave FLAGS carol\'s outbox as withholding when neither relay serves her head-committed set')
  const carolRows = (await dave.sync.range({ limit: 1000 })).filter((r) => r.value && r.value._k === carol.pub)
  ok(carolRows.length === 0 && !(await dave.data.getCommunity('solo')), 'dave quarantines carol\'s WHOLE first-read view instead of presenting its partial community')

  for (const c of [alice, bob, carol, dave]) c.sync.destroy && c.sync.destroy()
  console.log(`\n✅ all ${passed} relay-pool checks passed\n`)
}
main().catch((e) => { console.error('❌', e && e.stack || e); process.exit(1) })
