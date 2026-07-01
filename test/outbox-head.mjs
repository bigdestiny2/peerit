// outbox-head.mjs — Phase A of the P2P durability spec: the signed outbox HEAD
// (the "merkle root"). After each write, an author commits head!<author> — a
// census { author, version, count, root } of their OWN records, Ed25519-signed
// with the same envelope as every record. Because a relay/seeder can only DROP
// signed rows (never forge new ones), a reader comparing what it received to the
// signed count/root reliably DETECTS withholding and can fail over. Off by
// default (writeHead:false) so existing count-based tests are untouched; app.js
// turns it on in production.
//   node test/outbox-head.mjs   (part of `npm test`)

import assert from 'node:assert'
import { randomBytes } from 'node:crypto'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { createSync } from '../js/sync.js'
import { ready as cryptoReady, isSecure, hashHex } from '../js/crypto.js'
import { verifyRecord } from '../js/verify.js'
import { auditOutbox } from '../js/gossip.js'
import { outboxCensus, censusString } from '../js/canon.js'
import { keys, TYPE } from '../js/model.js'
import { makeValidator } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const BITS = { community: 7, post: 6, comment: 5 } // fast PoW; real app uses pow.MIN_BITS
function mem () { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
async function until (fn, { tries = 160, gap = 60 } = {}) { for (let i = 0; i < tries; i++) { if (await fn()) return true; await delay(gap) } return false }

// Minimal shared bridge world (same shape as bridge-convergence.mjs): /api/sync
// groups keyed by appId + a live /api/swarm hub linking EventSources on a topic.
function makeBridgeWorld () {
  const groups = new Map()
  const channels = new Map()
  let chanSeq = 0
  const ensureGroup = (appId) => { if (!groups.has(appId)) groups.set(appId, { inviteKey: randomBytes(32).toString('hex'), rows: new Map(), version: 0 }); return groups.get(appId) }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  const deliver = (channelId, msg) => { const c = channels.get(channelId); if (!c || !c.es || !c.es.onmessage) return; setTimeout(() => { try { c.es.onmessage({ data: JSON.stringify(msg) }) } catch {} }, 0) }
  const linkPeers = (channelId) => {
    const c = channels.get(channelId); if (!c || !c.es) return
    for (const [otherId, other] of channels) {
      if (otherId === channelId || other.topic !== c.topic || !other.es || c.linked.has(otherId)) continue
      c.linked.add(otherId); other.linked.add(channelId)
      deliver(channelId, { type: 'peer', peerId: otherId, pubkey: null })
      deliver(otherId, { type: 'peer', peerId: channelId, pubkey: null })
    }
  }
  const response = (value, status = 200) => ({ ok: status >= 200 && status < 300, status, statusText: 'OK', text: async () => JSON.stringify(value) })
  async function fetch (url, opts = {}) {
    const u = new URL(String(url)); const p = u.pathname; const body = opts.body ? JSON.parse(opts.body) : null
    if (p === '/api/token') return response({ token: 't' })
    if (p === '/api/sync/create') { const g = ensureGroup(body.appId); return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
    if (p === '/api/sync/join') { const g = ensureGroup(body.appId); if (body.inviteKey !== g.inviteKey) return response({ error: 'bad invite' }, 400); return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
    if (p === '/api/sync/append') { const g = ensureGroup(body.appId); const op = body.op; g.rows.set(op.type.replace(':', '!') + '!' + op.data.id, op.data); g.version++; return response({ ok: true }) }
    if (p === '/api/sync/heads') { const out = {}; for (const a of (body.appIds || [])) { const g = groups.get(a); out[a] = g ? g.version : 0 }; return response({ heads: out }) }
    if (p === '/api/sync/get') { const g = ensureGroup(u.searchParams.get('appId')); return response(g.rows.get(u.searchParams.get('key')) || null) }
    if (p === '/api/sync/list' || p === '/api/sync/range') {
      const g = ensureGroup(u.searchParams.get('appId')); let rows = sortedRows(g)
      const prefix = u.searchParams.get('prefix'); if (prefix) rows = rows.filter((r) => r.key >= prefix && r.key < prefix + '\xff')
      for (const [bound, cmp] of [['gte', (k, v) => k >= v], ['gt', (k, v) => k > v], ['lte', (k, v) => k <= v], ['lt', (k, v) => k < v]]) { const v = u.searchParams.get(bound); if (v != null && v !== '') rows = rows.filter((r) => cmp(r.key, v)) }
      return response(rows.slice(0, Number(u.searchParams.get('limit')) || 100))
    }
    if (p === '/api/sync/status') { const g = ensureGroup(u.searchParams.get('appId')); return response({ appId: u.searchParams.get('appId'), inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size }) }
    if (p === '/api/swarm/join') { const id = 'ch-' + (++chanSeq); channels.set(id, { topic: body.topicHex || 'default', es: null, linked: new Set() }); return response({ channelId: id, topicHex: body.topicHex || 'default', protocol: body.protocol, version: body.version, tier: 'A' }) }
    if (p === '/api/swarm/send') { deliver(body.peerId, { type: 'message', peerId: body.channelId, data: body.data }); return response({ ok: true }) }
    if (p === '/api/swarm/leave') { channels.delete(body.channelId); return response({ ok: true }) }
    if (p === '/api/bridge/status') return response({ ready: true })
    return response({ error: 'not found' }, 404)
  }
  class HubEventSource {
    constructor (url) { this.url = String(url); this.onmessage = null; this.onerror = null; const channelId = new URL(this.url).searchParams.get('channelId'); const c = channels.get(channelId); if (c) { c.es = this; setTimeout(() => linkPeers(channelId), 0) } }
    close () {}
  }
  return { base: 'https://peerit.test', fetch, EventSource: HubEventSource, groups }
}

async function makeClient (world, token, name, { writeHead = false, pollMs = 300 } = {}) {
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const sync = createSync({ apiToken: token, apiBase: world.base, fetch: world.fetch, EventSource: world.EventSource, storage: mem(), getMe: () => id.me().pubkey, identity: id, validate: makeValidator(BITS), pollMs, writeHead })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, name }
}

// Alice's OWN outbox rows as the relay stores them: [{key,value}].
const outboxRowsOf = (world, pub) => [...world.groups.get(pub).rows.entries()].map(([key, value]) => ({ key, value }))

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available (head signatures are enforced)')

  const world = makeBridgeWorld()

  console.log('\n— an author commits a signed head after each write —')
  const alice = await makeClient(world, 'tok-a', 'alice', { writeHead: true })
  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'serverless reddit' })
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'first', body: 'one' })
  await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'second', body: 'two' })

  const rows = outboxRowsOf(world, alice.pub)
  const headKey = keys.head(alice.pub)
  const head = world.groups.get(alice.pub).rows.get(headKey)
  ok(!!head, 'head!<author> exists in the outbox after writes')
  ok(head._k === alice.pub && head.author === alice.pub, 'the head is authored (and _k-bound) by the outbox owner')

  const nonHead = rows.filter((r) => r.key !== headKey)
  ok(head.count === nonHead.length && head.count === 3, 'head.count equals the number of non-head records (community + 2 posts = 3)')
  const expectedRoot = await hashHex(censusString(outboxCensus(rows)))
  ok(head.root === expectedRoot, 'head.root is the hash of the sorted key\\nsig census of the author\'s records')

  console.log('\n— the head verifies like any record, and rejects tampering —')
  ok((await verifyRecord(TYPE.HEAD, head)) === 'ok', 'verifyRecord(head) === "ok" (valid Ed25519 over the canonical head)')
  ok((await verifyRecord(TYPE.HEAD, { ...head, count: head.count + 5 })) === 'bad', 'a head with a bumped count but stale signature is rejected ("bad")')
  ok((await verifyRecord(TYPE.HEAD, { ...head, root: 'deadbeef'.repeat(8) })) === 'bad', 'a head with a swapped root but stale signature is rejected ("bad")')
  ok((await verifyRecord(TYPE.HEAD, { ...head, _k: 'a'.repeat(64) })) === 'bad', 'a head whose signer _k != author is rejected ("bad") — no signing as someone else')

  console.log('\n— a WITHHOLDING source is detected; a complete source passes —')
  const full = await auditOutbox(rows, head)
  ok(full.complete && full.exact && full.rootMatch, 'auditing the FULL outbox against its head → complete + exact')
  ok(full.expected === 3 && full.got === 3, 'audit reports expected=3, got=3 for the full set')

  const withheld = rows.filter((r) => r.key !== nonHead[0].key) // relay drops one signed record
  const audit = await auditOutbox(withheld, head)
  ok(!audit.complete, 'auditing an outbox MISSING one record → NOT complete (withholding detected)')
  ok(audit.got === 2 && audit.expected === 3 && !audit.rootMatch, 'audit reports got=2 < expected=3 and a root mismatch')

  const noHead = await auditOutbox(rows, null)
  ok(noHead.hasHead === false && noHead.complete === true, 'an author with no head yet is un-auditable (complete=true, hasHead=false) — backward compatible')

  console.log('\n— end to end: a second peer replicates the outbox and audits it —')
  const bob = await makeClient(world, 'tok-b', 'bob', { writeHead: false })
  const bobSaw = await until(async () => (await bob.data.getPost('p2p', (await bob.data.listPostsIn('p2p'))[0]?.cid))?.title === 'first' || (await bob.data.listPostsIn('p2p')).length >= 2)
  ok(bobSaw, 'bob discovers alice via signed swarm descriptors and replicates her posts')
  const bobHead = await bob.sync.get(headKey)
  ok(!!bobHead && (await verifyRecord(TYPE.HEAD, bobHead)) === 'ok', 'bob replicated alice\'s head and it verifies on his side')
  const bobRowsOfAlice = (await bob.sync.list('', { limit: 1000 })).filter((r) => (r.value && r.value._k) === alice.pub)
  const bobAudit = await auditOutbox(bobRowsOfAlice, bobHead)
  ok(bobAudit.complete && bobAudit.exact, 'bob audits alice\'s replicated outbox against her head → complete + exact (no withholding on this path)')

  alice.sync.destroy && alice.sync.destroy(); bob.sync.destroy && bob.sync.destroy()
  console.log(`\n✅ all ${passed} outbox-head checks passed\n`)
}
main().catch((e) => { console.error('❌', e && e.stack || e); process.exit(1) })
