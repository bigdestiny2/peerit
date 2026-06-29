// dht-adapter.mjs — rigorous test of the Phase 3 DHT adapter (js/dht-adapter.js)
// WITHOUT the real network. In-memory fakes mimic the corestore / hyperbee /
// hyperswarm / protomux APIs the adapter consumes; two REAL BridgeGossipSync
// peers (real Ed25519 DevIdentity) run on top and must converge — proving the
// peerit-specific glue (hypercore stack → pear.sync/swarm.v1) is correct.
//
// What this proves: the adapter's outbox CRUD, the swarm.v1 channel semantics
// (peer/message/send over a protomux channel), and end-to-end multi-writer
// convergence. What it does NOT prove (needs a live DHT): real Noise/replication
// timing, dht-relay behavior, protomux-on-the-wire. Replication is modelled as a
// shared core-data registry; peer linking as a shared topic hub.
// Run: node test/dht-adapter.mjs

import assert from 'node:assert'
import { randomBytes } from 'node:crypto'
import { createHyperPearSurface } from '../js/dht-adapter.js'
import { BridgeGossipSync } from '../js/gossip.js'
import { createSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const BITS = { community: 7, post: 6, comment: 5 }
function mem () { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
async function until (fn, { tries = 160, gap = 60 } = {}) { for (let i = 0; i < tries; i++) { if (await fn()) return true; await delay(gap) } return false }

// b4a-like (Buffer-backed)
const b4a = { from: (v, enc) => (typeof v === 'string' ? Buffer.from(v, enc || 'utf8') : Buffer.from(v)), toString: (b, enc) => Buffer.from(b).toString(enc || 'utf8') }
async function sha256 (str) { const { createHash } = await import('node:crypto'); return new Uint8Array(createHash('sha256').update(String(str)).digest()) }

// ---- fakes ------------------------------------------------------------------
class FakeHyperbee {
  constructor (core) { this.core = core }
  async ready () {}
  async put (k, v) { this.core._backing.set(k, v) }
  async get (k) { return this.core._backing.has(k) ? { key: k, value: this.core._backing.get(k) } : null }
  async * createReadStream (opts = {}) {
    let keys = [...this.core._backing.keys()].sort()
    if (opts.gte != null) keys = keys.filter((k) => k >= opts.gte)
    if (opts.gt != null) keys = keys.filter((k) => k > opts.gt)
    if (opts.lte != null) keys = keys.filter((k) => k <= opts.lte)
    if (opts.lt != null) keys = keys.filter((k) => k < opts.lt)
    if (opts.reverse) keys.reverse()
    const lim = Number(opts.limit) || keys.length
    let n = 0
    for (const k of keys) { if (n++ >= lim) break; yield { key: k, value: this.core._backing.get(k) } }
  }
}

// Shared registry models the DHT replicating cores: a core opened by KEY anywhere
// shares the same backing data as the writer who created it by NAME.
function makeStore (registry) {
  return {
    get ({ name, key }) {
      let keyHex
      if (key) keyHex = b4a.toString(key, 'hex')
      else { keyHex = registry.nameKeys.get(name); if (!keyHex) { keyHex = randomBytes(32).toString('hex'); registry.nameKeys.set(name, keyHex) } }
      if (!registry.data.has(keyHex)) registry.data.set(keyHex, new Map())
      const backing = registry.data.get(keyHex)
      return { key: Buffer.from(keyHex, 'hex'), discoveryKey: Buffer.from(keyHex, 'hex'), get length () { return backing.size }, ready: async () => {}, _backing: backing }
    },
    replicate () {}, // data sharing modelled via the registry
    close: async () => {}
  }
}

// Protomux fake: per-connection named channels; send routes to the paired end.
const Protomux = {
  from (conn) {
    return {
      createChannel ({ protocol }) {
        return {
          addMessage ({ onmessage }) {
            conn._channels.set(protocol, { onmessage })
            ;(conn._pending.get(protocol) || []).forEach((d) => onmessage(d)); conn._pending.delete(protocol)
            return { send (data) { conn._deliver(protocol, data) } }
          },
          open () {}
        }
      }
    }
  }
}
function makeConn (remotePubHex) {
  return {
    remotePublicKey: Buffer.from(remotePubHex, 'hex'),
    _channels: new Map(), _pending: new Map(), _peer: null, _close: [],
    on (ev, fn) { if (ev === 'close') this._close.push(fn) },
    _deliver (protocol, data) {
      const peer = this._peer
      setTimeout(() => { const ch = peer._channels.get(protocol); if (ch) ch.onmessage(data); else { const q = peer._pending.get(protocol) || []; q.push(data); peer._pending.set(protocol, q) } }, 0)
    }
  }
}

// Shared topic hub: one connection per peer-pair (mimics Hyperswarm dedup),
// established when two swarms first share any topic.
function makeHub () {
  const members = []
  const connected = new Set()
  return {
    register (topicHex, rec) {
      rec.topics.add(topicHex)
      if (!members.includes(rec)) members.push(rec)
      for (const other of members) {
        if (other === rec || !other.topics.has(topicHex)) continue
        const pk = [rec.pub, other.pub].sort().join('|')
        if (connected.has(pk)) continue
        connected.add(pk)
        const a = makeConn(other.pub), b = makeConn(rec.pub)
        a._peer = b; b._peer = a
        rec.fire(a); other.fire(b)
      }
    },
    unregister (topicHex, rec) { rec.topics.delete(topicHex) }
  }
}
function makeSwarm (hub, pubHex) {
  const cbs = []
  const rec = { topics: new Set(), pub: pubHex, fire: (conn) => { for (const cb of cbs) cb(conn) } }
  return {
    on (ev, cb) { if (ev === 'connection') cbs.push(cb) },
    join (topic, opts) { hub.register(b4a.toString(topic, 'hex'), rec); return { flushed: async () => {} } },
    leave (topic) { hub.unregister(b4a.toString(topic, 'hex'), rec) },
    destroy: async () => {}
  }
}

async function makePeer (registry, hub, name) {
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const surface = createHyperPearSurface({ store: makeStore(registry), swarm: makeSwarm(hub, randomBytes(32).toString('hex')), Hyperbee: FakeHyperbee, Protomux, b4a, sha256, identity: id })
  const sync = new BridgeGossipSync({ pear: surface, getMe: () => id.me().pubkey, identity: id, storage: mem(), validate: makeValidator(BITS), pollMs: 300 })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, name }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available')

  console.log('\n— boot integration: createSync selects BridgeGossipSync over the adapter —')
  const probeId = new DevIdentity(mem(), mem()); await probeId.ready(); await probeId.createUser('probe')
  const probeSurface = createHyperPearSurface({ store: makeStore({ data: new Map(), nameKeys: new Map() }), swarm: makeSwarm(makeHub(), randomBytes(32).toString('hex')), Hyperbee: FakeHyperbee, Protomux, b4a, sha256, identity: probeId })
  const probeSync = createSync({ pear: probeSurface, identity: probeId, getMe: () => probeId.me().pubkey, storage: mem(), validate: makeValidator(BITS), pollMs: 0 })
  ok(probeSync.mode === 'gossip-bridge', 'createSync selects BridgeGossipSync over the DHT adapter surface (the boot wiring path, no downgrade)')

  console.log('\n— two peers converge through the in-browser DHT adapter —')
  const registry = { data: new Map(), nameKeys: new Map() }
  const hub = makeHub()
  const alice = await makePeer(registry, hub, 'alice')
  const bob = await makePeer(registry, hub, 'bob')
  ok(alice.sync.mode === 'gossip-bridge' && bob.sync.mode === 'gossip-bridge', 'both peers run gossip-bridge on the DHT adapter surface')

  await alice.data.createCommunity({ slug: 'dht', title: 'DHT', description: 'over the in-browser DHT' })
  const aPost = await alice.data.submitPost({ community: 'dht', kind: 'text', title: 'hello over DHT', body: 'noise end to end' })
  ok(await until(() => bob.data.getCommunity('dht')), 'bob discovers alice via the swarm.v1 descriptor channel and sees r/dht')
  ok(await until(() => bob.data.listPostsIn('dht').then((ps) => ps.some((p) => p.cid === aPost.cid))), "bob replicates alice's outbox and sees her post")

  const bPost = await bob.data.submitPost({ community: 'dht', kind: 'text', title: 'bob replies', body: 'hi' })
  ok(await until(() => alice.data.getPost('dht', bPost.cid)), "alice sees bob's reply (bidirectional convergence)")

  await alice.data.vote(aPost.cid, 'dht', 'post', 1)
  await bob.data.vote(aPost.cid, 'dht', 'post', 1)
  ok(await until(async () => (await bob.data.tallyFor(aPost.cid)).score === 2), 'cross-writer votes aggregate to score 2 across the DHT adapter')

  const cm = await bob.data.addComment({ community: 'dht', postCid: aPost.cid, body: 'nice' })
  ok(await until(() => alice.data.listComments('dht', aPost.cid).then((cs) => cs.some((c) => c.cid === cm.cid))), "alice sees bob's comment")

  alice.sync.destroy(); bob.sync.destroy()
  console.log(`\n✅ all ${passed} dht-adapter checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
