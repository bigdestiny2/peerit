// bridge-convergence.mjs — automated two-writer proof over the PearBrowser
// mobile/desktop `/api/*` transport.
//
// gossip.mjs proves multi-writer convergence in DEV mode (in-memory bus); it
// never exercises two BridgeGossipSync writers discovering each other over the
// swarm. bridge.mjs proves the `/api` contract with a SINGLE writer. Neither
// covers the seam the user actually cares about for mobile: two distinct
// identities, each writing their own outbox, finding each other via SIGNED
// descriptors over the `/api/swarm/*` transport, and merging into one view.
//
// This harness wires up a shared "bridge world": one host whose `/api/sync/*`
// groups are shared across both clients (so a join reads the other's rows) and
// a LIVE `/api/swarm/*` hub with a push-capable EventSource — the same code
// path js/pear-api.js uses on real mobile. Signing uses real Ed25519
// (DevIdentity), so the descriptor signatures actually verify through
// _onDescriptor → edVerify. The result: a genuine, fast, repeatable proof that
// peerit converges across two peers in `gossip-bridge` mode.
//
// Run: node test/bridge-convergence.mjs   (also part of `npm test`)

import assert from 'node:assert'
import { createPearApi, hasGossipPearSurface } from '../js/pear-api.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { createSync } from '../js/sync.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { mergeOutboxes } from '../js/gossip.js'
import { makeValidator } from '../js/pow.js'
import { randomBytes } from 'node:crypto'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))

// Fast PoW bits so the proof runs in well under a second (gossip.mjs uses the
// same trick); the real app uses pow.MIN_BITS.
const BITS = { community: 7, post: 6, comment: 5 }

function mem () {
  const m = new Map()
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() }
}

async function until (fn, { tries = 120, gap = 75 } = {}) {
  for (let i = 0; i < tries; i++) {
    if (await fn()) return true
    await delay(gap)
  }
  return false
}

// ---- shared bridge world ----------------------------------------------------
// Single host, shared across every client. Sync groups are keyed by appId (the
// writer's pubkey) and are visible to anyone who joins with the right inviteKey.
// The swarm hub links every EventSource on the same topic as mutual peers and
// routes `/api/swarm/send` to the recipient's event stream.
function makeBridgeWorld () {
  const groups = new Map()        // appId -> { inviteKey, rows: Map, version }
  const channels = new Map()      // channelId -> { topic, es, linked:Set }
  let chanSeq = 0
  let reads = 0                   // count of full outbox reads (list/range) — proves heads-gating cuts them

  const ensureGroup = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { inviteKey: randomBytes(32).toString('hex'), rows: new Map(), version: 0 })
    return groups.get(appId)
  }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))

  function deliver (channelId, msg) {
    const c = channels.get(channelId)
    if (!c || !c.es || !c.es.onmessage) return
    setTimeout(() => { try { c.es.onmessage({ data: JSON.stringify(msg) }) } catch {} }, 0)
  }

  // Link a freshly-subscribed channel to every other live channel on its topic,
  // emitting reciprocal `peer` events (deferred, so pear-api has attached its
  // onmessage handler by the time they fire).
  function linkPeers (channelId) {
    const c = channels.get(channelId)
    if (!c || !c.es) return
    for (const [otherId, other] of channels) {
      if (otherId === channelId || other.topic !== c.topic || !other.es) continue
      if (c.linked.has(otherId)) continue
      c.linked.add(otherId); other.linked.add(channelId)
      deliver(channelId, { type: 'peer', peerId: otherId, pubkey: null })
      deliver(otherId, { type: 'peer', peerId: channelId, pubkey: null })
    }
  }

  function response (value, status = 200) {
    return { ok: status >= 200 && status < 300, status, statusText: status >= 200 && status < 300 ? 'OK' : 'API error', text: async () => JSON.stringify(value) }
  }

  async function fetch (url, opts = {}) {
    const u = new URL(String(url))
    const p = u.pathname
    const body = opts.body ? JSON.parse(opts.body) : null
    try {
      if (p === '/api/sync/create') { const g = ensureGroup(body.appId); return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
      if (p === '/api/sync/join') { const g = ensureGroup(body.appId); if (body.inviteKey !== g.inviteKey) return response({ error: 'bad invite' }, 400); return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId }) }
      if (p === '/api/sync/append') { const g = ensureGroup(body.appId); const op = body.op; g.rows.set(op.type.replace(':', '!') + '!' + op.data.id, op.data); g.version++; return response({ ok: true }) }
      if (p === '/api/sync/heads') { const out = {}; for (const a of (body.appIds || [])) { const g = groups.get(a); out[a] = g ? g.version : 0 }; return response({ heads: out }) }
      if (p === '/api/sync/get') { const g = ensureGroup(u.searchParams.get('appId')); return response(g.rows.get(u.searchParams.get('key')) || null) }
      if (p === '/api/sync/list' || p === '/api/sync/range') {
        reads++
        const g = ensureGroup(u.searchParams.get('appId'))
        let rows = sortedRows(g)
        const prefix = u.searchParams.get('prefix')
        if (prefix) rows = rows.filter((r) => r.key >= prefix && r.key < prefix + '\xff')
        for (const [bound, cmp] of [['gte', (k, v) => k >= v], ['gt', (k, v) => k > v], ['lte', (k, v) => k <= v], ['lt', (k, v) => k < v]]) {
          const v = u.searchParams.get(bound)
          if (v != null && v !== '') rows = rows.filter((r) => cmp(r.key, v))
        }
        return response(rows.slice(0, Number(u.searchParams.get('limit')) || 100))
      }
      if (p === '/api/sync/count') { const g = ensureGroup(u.searchParams.get('appId')); return response({ count: g.rows.size }) }
      if (p === '/api/sync/status') { const g = ensureGroup(u.searchParams.get('appId')); return response({ appId: u.searchParams.get('appId'), inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size }) }
      if (p === '/api/swarm/join') { const id = 'ch-' + (++chanSeq); channels.set(id, { topic: body.topicHex || 'default', es: null, linked: new Set() }); return response({ channelId: id, topicHex: body.topicHex || 'default', protocol: body.protocol, version: body.version, tier: 'A' }) }
      if (p === '/api/swarm/send') { deliver(body.peerId, { type: 'message', peerId: body.channelId, data: body.data }); return response({ ok: true }) }
      if (p === '/api/swarm/leave') { channels.delete(body.channelId); return response({ ok: true }) }
      if (p === '/api/bridge/status') return response({ ready: true })
      if (p === '/api/identity') return response({ publicKey: '0'.repeat(64), driveKey: '0'.repeat(64), algorithm: 'ed25519' })
      return response({ error: 'not found' }, 404)
    } catch (err) { return response({ error: err.message }, 500) }
  }

  // Push-capable EventSource: registers itself with the hub by channelId, then
  // (deferred) links to peers already on its topic.
  class HubEventSource {
    constructor (url) {
      this.url = String(url)
      this.onmessage = null
      this.onerror = null
      const channelId = new URL(this.url).searchParams.get('channelId')
      const c = channels.get(channelId)
      if (c) { c.es = this; setTimeout(() => linkPeers(channelId), 0) }
    }
    close () {}
  }

  return { base: 'https://peerit.test', fetch, EventSource: HubEventSource, groups, getReads: () => reads }
}

// A client is a real Ed25519 identity whose sync + swarm transport runs entirely
// over the shared `/api` host.
async function makeClient (world, token, name, pollMs = 4000) {
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  const sync = createSync({
    apiToken: token,
    apiBase: world.base,
    fetch: world.fetch,
    EventSource: world.EventSource,
    storage: mem(),
    getMe: () => id.me().pubkey,
    identity: id,
    validate: makeValidator(BITS),
    pollMs
  })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, name }
}

// The full from-scratch merge of every outbox in a world — the oracle the
// incremental BridgeGossipSync delta must always agree with.
async function fullMergeOf (world) {
  const boxes = []
  for (const [appId, g] of world.groups) {
    const view = {}
    for (const [k, v] of g.rows) view[k] = v
    boxes.push({ pub: appId, view })
  }
  return mergeOutboxes(boxes, {}, makeValidator(BITS))
}
async function viewOf (sync) {
  const rows = await sync.list('', { limit: 1000 })
  const v = {}
  for (const r of rows) v[r.key] = r.value
  return v
}
function sameView (a, b) {
  const ka = Object.keys(a).sort(), kb = Object.keys(b).sort()
  if (ka.length !== kb.length || ka.join(' ') !== kb.join(' ')) return false
  for (const k of ka) if ((a[k] && a[k]._sig) !== (b[k] && b[k]._sig)) return false
  return true
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available (descriptor signatures are enforced)')

  const world = makeBridgeWorld()

  // Sanity: the /api wrapper presents a complete gossip-capable bridge surface.
  const probe = createPearApi({ apiToken: 't-probe', apiBase: world.base, fetch: world.fetch, EventSource: world.EventSource })
  ok(hasGossipPearSurface(probe), 'token-gated /api wrapper exposes sync + identity + swarm.v1')

  console.log('\n— two writers enter gossip-bridge over /api —')
  const alice = await makeClient(world, 'tok-alice', 'alice')
  const bob = await makeClient(world, 'tok-bob', 'bob')
  ok(alice.sync.mode === 'gossip-bridge' && bob.sync.mode === 'gossip-bridge', 'both peers run in gossip-bridge mode (the chip would read "gossip-bridge")')
  ok(alice.pub !== bob.pub, 'the two writers have distinct identities (distinct outboxes)')

  console.log('\n— alice → bob replication via signed swarm descriptors —')
  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'serverless reddit' })
  const aPost = await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'alice posts', body: 'hello from alice' })

  const bobSawCommunity = await until(() => bob.data.getCommunity('p2p'))
  ok(bobSawCommunity, "bob discovered alice's outbox over the /api swarm and sees r/p2p")
  ok(await until(() => bob.data.listPostsIn('p2p').then((ps) => ps.some((p) => p.cid === aPost.cid))), "bob sees alice's post (cross-writer merge over the bridge)")

  // Both peers must have discovered each other (self + 1 remote).
  const aStatus = await alice.sync.status()
  const bStatus = await bob.sync.status()
  ok(aStatus.peers >= 2 && bStatus.peers >= 2, `both peers report >=2 outboxes in the merged view (alice=${aStatus.peers}, bob=${bStatus.peers})`)
  ok(aStatus.mode.includes('bridge') && bStatus.mode.includes('bridge'), 'status.mode includes "bridge" on both peers (drives the chip class)')

  console.log('\n— bob → alice replication (reverse direction) —')
  const bPost = await bob.data.submitPost({ community: 'p2p', kind: 'text', title: 'bob replies', body: 'hello back from bob' })
  const aliceSawBob = await until(() => alice.data.getPost('p2p', bPost.cid))
  ok(aliceSawBob, "alice sees bob's post (reverse-direction convergence; exercises the background re-merge poll)")

  console.log('\n— cross-writer votes & comments aggregate —')
  await alice.data.vote(aPost.cid, 'p2p', 'post', 1)
  await bob.data.vote(aPost.cid, 'p2p', 'post', 1)
  const tallyConverged = await until(async () => (await bob.data.tallyFor(aPost.cid)).score === 2)
  ok(tallyConverged, 'two upvotes from two outboxes aggregate to score 2 in the merged view')
  const cm = await bob.data.addComment({ community: 'p2p', postCid: aPost.cid, body: 'nice post' })
  ok(await until(() => alice.data.listComments('p2p', aPost.cid).then((cs) => cs.some((c) => c.cid === cm.cid))), "alice sees bob's comment")

  console.log('\n— signed edits propagate; tamper does not —')
  await alice.data.editPost('p2p', aPost.cid, 'hello from alice (edited)')
  ok(await until(() => bob.data.getPost('p2p', aPost.cid).then((p) => p && p.body === 'hello from alice (edited)')), "alice's re-signed edit propagates and verifies on bob")

  console.log('\n— incremental merge: equals full merge + catches overwrites —')
  // Two poll-free clients so every refresh is driven explicitly and deterministically.
  const w2 = makeBridgeWorld()
  const carol = await makeClient(w2, 'tok-carol', 'carol', 0)
  const dave = await makeClient(w2, 'tok-dave', 'dave', 0)
  ok(await until(() => Promise.all([carol.sync.status(), dave.sync.status()]).then(([c, d]) => c.peers >= 2 && d.peers >= 2)), 'carol + dave discover each other (poll-free)')

  await carol.data.createCommunity({ slug: 'inc', title: 'Inc', description: '' })
  const cp = await carol.data.submitPost({ community: 'inc', kind: 'text', title: 'carol post', body: 'hi' })
  await dave.sync._refresh() // dave pulls carol's new rows
  ok(await dave.data.getPost('inc', cp.cid), 'dave sees carol post after an explicit refresh')
  ok(sameView(await viewOf(carol.sync), await fullMergeOf(w2)) && sameView(await viewOf(dave.sync), await fullMergeOf(w2)), 'incremental view on BOTH peers equals the full from-scratch mergeOutboxes')

  // Idle refresh must report NO change (and not churn the cache).
  const idle = await carol.sync._refresh()
  ok(Array.isArray(idle) && idle.length === 0, 'a refresh with no new rows reports zero changed keys (idle poll = no re-render)')

  // NEW row (dave votes) → carol's refresh reports exactly that key.
  await dave.data.vote(cp.cid, 'inc', 'post', 1)
  const afterVote = await carol.sync._refresh()
  ok(afterVote.includes('vote!' + cp.cid + '!' + dave.pub), 'a peer\'s new vote shows up as a single changed key')
  ok((await carol.data.tallyFor(cp.cid)).score === 1, 'carol\'s tally reflects dave\'s upvote')

  // OVERWRITE (dave flips his vote) → same key, new _sig. A key-watermark would
  // MISS this; the _sig change-token must catch it.
  await dave.data.vote(cp.cid, 'inc', 'post', -1)
  const afterFlip = await carol.sync._refresh()
  ok(afterFlip.includes('vote!' + cp.cid + '!' + dave.pub), 'a peer flipping an EXISTING vote (key overwrite) is detected by the _sig change-token')
  ok((await carol.data.tallyFor(cp.cid)).score === -1, 'carol\'s tally reflects the flipped vote (overwrite applied, not missed)')
  ok(sameView(await viewOf(carol.sync), await fullMergeOf(w2)), 'after edits + overwrites, incremental view still equals the full merge')

  console.log('\n— heads-gating: idle polls stop re-reading every outbox —')
  await carol.sync._refresh() // settle the heads baseline
  const readsBefore = w2.getReads()
  await carol.sync._refresh(); await carol.sync._refresh() // two IDLE polls
  ok(w2.getReads() === readsBefore, `idle polls re-read ZERO outboxes — /api/sync/heads gated them (reads stayed ${readsBefore})`)
  await dave.data.vote(cp.cid, 'inc', 'post', 1) // dave's outbox version moves
  await carol.sync._refresh()
  ok(w2.getReads() > readsBefore, 'a peer whose outbox version moved IS re-read (only the changed one, not all peers)')

  console.log('\n— persistent cache: a reload renders instantly with the relay OFFLINE —')
  const sharedStore = mem()
  const gid = new DevIdentity(sharedStore, mem()); await gid.ready(); await gid.createUser('grace')
  const mkGrace = (f) => createSync({ apiToken: 'tok-grace', apiBase: w2.base, fetch: f, EventSource: w2.EventSource, storage: sharedStore, getMe: () => gid.me().pubkey, identity: gid, validate: makeValidator(BITS), pollMs: 0 })
  const grace1 = mkGrace(w2.fetch); await grace1.ready()
  ok(await until(() => grace1.list('community!', { limit: 100 }).then((r) => r.some((x) => x.key.includes('inc')))), 'grace discovers r/inc and persists the verified view to local cache')
  grace1.destroy()
  // Reload with the SAME storage but a fetch that always throws: any content shown
  // now can only have come from the persisted cache, not the network.
  const grace2 = mkGrace(async () => { throw new Error('relay offline') }); await grace2.ready()
  ok((await grace2.list('', { limit: 1000 })).some((x) => x.key.includes('inc')), 'after reload with NO relay, the feed renders instantly from cache (no blank screen)')
  grace2.destroy()
  carol.sync.destroy(); dave.sync.destroy(); alice.sync.destroy(); bob.sync.destroy()

  console.log(`\n✅ all ${passed} bridge-convergence checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
