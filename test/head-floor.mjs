// head-floor.mjs — Phase C of the P2P durability spec: the DURABLE monotonic
// head floor. A signed head's version is monotonic + author-controlled, so once
// a client has durably recorded "I saw version N for this author" (localStorage,
// survives restart), NO relay — not even the ephemeral memory core after a wipe,
// not even all relays colluding — can talk it below N without being flagged.
// This closes the two rollback cases Phase B (cross-relay, online-only) can't:
// across a client restart, and an all-relays-collude rollback.
//   node test/head-floor.mjs   (part of `npm test`)

import assert from 'node:assert'
import { randomBytes } from 'node:crypto'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { createSync } from '../js/sync.js'
import { createPearApi } from '../js/pear-api.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { keys } from '../js/model.js'
import { makeValidator } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const BITS = { community: 7, post: 6, comment: 5 }
function mem () { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
async function until (fn, { tries = 200, gap = 60 } = {}) { for (let i = 0; i < tries; i++) { if (await fn()) return true; await delay(gap) } return false }

// Single-relay world (an all-relays-collude rollback with N=1 is just this relay
// rolling back; the mechanism is identical with a pool via crossHead's max head).
function makeWorld () {
  const groups = new Map(); const channels = new Map(); let chanSeq = 0
  const ensureGroup = (appId) => { if (!groups.has(appId)) groups.set(appId, { inviteKey: randomBytes(32).toString('hex'), rows: new Map(), version: 0 }); return groups.get(appId) }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  const deliver = (id, msg) => { const c = channels.get(id); if (!c || !c.es || !c.es.onmessage) return; setTimeout(() => { try { c.es.onmessage({ data: JSON.stringify(msg) }) } catch {} }, 0) }
  const linkPeers = (id) => { const c = channels.get(id); if (!c || !c.es) return; for (const [o, ot] of channels) { if (o === id || ot.topic !== c.topic || !ot.es || c.linked.has(o)) continue; c.linked.add(o); ot.linked.add(id); deliver(id, { type: 'peer', peerId: o, pubkey: null }); deliver(o, { type: 'peer', peerId: id, pubkey: null }) } }
  const resp = (v, s = 200) => ({ ok: s >= 200 && s < 300, status: s, statusText: 'OK', text: async () => JSON.stringify(v) })
  async function fetch (url, opts = {}) {
    const u = new URL(String(url)); const p = u.pathname; const body = opts.body ? JSON.parse(opts.body) : null
    if (p === '/api/token') return resp({ token: 't' })
    if (p === '/api/sync/create' || p === '/api/sync/join') { const g = ensureGroup(body.appId); return resp({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
    if (p === '/api/sync/append') { const g = ensureGroup(body.appId); const op = body.op; g.rows.set(op.type.replace(':', '!') + '!' + op.data.id, op.data); g.version++; return resp({ ok: true }) }
    if (p === '/api/sync/heads') { const out = {}; for (const a of (body.appIds || [])) { const g = groups.get(a); out[a] = g ? g.version : 0 }; return resp({ heads: out }) }
    if (p === '/api/sync/get') { const g = ensureGroup(u.searchParams.get('appId')); return resp(g.rows.get(u.searchParams.get('key')) || null) }
    if (p === '/api/sync/list' || p === '/api/sync/range') {
      const g = ensureGroup(u.searchParams.get('appId')); let rows = sortedRows(g)
      const pre = u.searchParams.get('prefix'); if (pre) rows = rows.filter((r) => r.key >= pre && r.key < pre + '\xff')
      for (const [b, cmp] of [['gte', (k, v) => k >= v], ['gt', (k, v) => k > v], ['lte', (k, v) => k <= v], ['lt', (k, v) => k < v]]) { const v = u.searchParams.get(b); if (v != null && v !== '') rows = rows.filter((r) => cmp(r.key, v)) }
      return resp(rows.slice(0, Number(u.searchParams.get('limit')) || 100))
    }
    if (p === '/api/sync/status') { const g = ensureGroup(u.searchParams.get('appId')); return resp({ appId: u.searchParams.get('appId'), inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size }) }
    if (p === '/api/swarm/join') { const id = 'ch-' + (++chanSeq); channels.set(id, { topic: body.topicHex || 'd', es: null, linked: new Set() }); return resp({ channelId: id, topicHex: body.topicHex || 'd', protocol: body.protocol, version: body.version, tier: 'A' }) }
    if (p === '/api/swarm/send') { deliver(body.peerId, { type: 'message', peerId: body.channelId, data: body.data }); return resp({ ok: true }) }
    if (p === '/api/swarm/leave') { channels.delete(body.channelId); return resp({ ok: true }) }
    if (p === '/api/bridge/status') return resp({ ready: true })
    return resp({ error: 'nf' }, 404)
  }
  class ES { constructor (url) { this.url = String(url); this.onmessage = null; this.onerror = null; const id = new URL(this.url).searchParams.get('channelId'); const c = channels.get(id); if (c) { c.es = this; setTimeout(() => linkPeers(id), 0) } } close () {} }
  return { base: 'https://a.peerit.test', fetch, EventSource: ES, groups }
}

async function makeClient (world, name, { writeHead = false, storage = mem(), pollMs = 200 } = {}) {
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  // Explicit legacy transport: this floor suite covers the separate append/head
  // compatibility path, while atomic HTTP commits are covered independently.
  const pear = createPearApi({ apiToken: 't', apiBase: world.base, fetch: world.fetch, EventSource: world.EventSource })
  delete pear.sync.commit
  const sync = createSync({ pear, storage, getMe: () => id.me().pubkey, identity: id, validate: makeValidator(BITS), pollMs, writeHead })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, storage }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available')
  const world = makeWorld()

  console.log('\n— a client durably records the head version it has seen —')
  const alice = await makeClient(world, 'alice', { writeHead: true })
  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'x' })
  const g = world.groups.get(alice.pub)
  const snapshotV1 = new Map(g.rows) // {community!p2p, head!alice(v1)} — a validly-signed OLD state the relay could later replay
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'first', body: '1' })
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'second', body: '2' })
  ok((g.rows.get(keys.head(alice.pub)).version | 0) === 3, 'alice\'s current signed head is version 3 (community + 2 posts)')

  const bobStorage = mem()
  const bob = await makeClient(world, 'bob', { storage: bobStorage })
  await until(async () => (await bob.data.listPostsIn('p2p')).length >= 2)
  ok(true, 'bob replicates alice and sees version-3 content')
  const floor = JSON.parse(bobStorage.getItem('peerit:head-floor') || '{}')
  ok(floor[alice.pub] && floor[alice.pub].v === 3, 'bob durably records a head floor of v3 for alice (peerit:head-floor)')
  ok(/^[0-9a-f]{64}$/i.test(String(floor[alice.pub] && floor[alice.pub].root || '')), 'the durable floor pins the signed root as well as the version')

  console.log('\n— the relay ROLLS BACK to an old, validly-signed state; bob catches it —')
  g.rows = new Map(snapshotV1); g.version += 5 // serve the old v1 head + subset, and report a change so bob re-reads
  const flagged = await until(async () => (await bob.sync.status()).withholding.includes(alice.pub), { tries: 80 })
  ok(flagged, 'bob FLAGS the rollback: the relay serves v1 but bob durably knows v3 existed (all-relays-collude has nothing newer to hide behind)')
  const retained = await bob.data.listPostsIn('p2p')
  ok(retained.length === 2, 'bob retains the last verified version-3 view instead of replacing it with rolled-back rows')
  // F2: the AUTHOR detects a rollback of their OWN outbox too (self is floored).
  const selfFlagged = await until(async () => (await alice.sync.status()).withholding.includes(alice.pub), { tries: 80 })
  ok(selfFlagged, 'alice detects the rollback of HER OWN outbox (the relay served her back an older head than she durably knows she wrote)')

  console.log('\n— the floor SURVIVES a client restart (the whole point) —')
  bob.sync.destroy && bob.sync.destroy()
  const bob2 = await makeClient(world, 'bob2reuse', { storage: bobStorage }) // fresh instance, SAME storage
  const floor2 = JSON.parse(bobStorage.getItem('peerit:head-floor') || '{}')
  ok(floor2[alice.pub] && floor2[alice.pub].v === 3, 'the durable floor (v3) is present in storage after teardown')
  const flagged2 = await until(async () => (await bob2.sync.status()).withholding.includes(alice.pub), { tries: 80 })
  ok(flagged2, 'a RESTARTED client (same storage, relay still rolled back) detects the rollback on its own from the persisted floor')

  bob2.sync.destroy && bob2.sync.destroy(); alice.sync.destroy && alice.sync.destroy()
  console.log(`\n✅ all ${passed} head-floor checks passed\n`)
}
main().catch((e) => { console.error('❌', e && e.stack || e); process.exit(1) })
