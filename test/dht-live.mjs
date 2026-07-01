// dht-live.mjs — LIVE-WIRE validation of the Phase E in-browser DHT path
// (js/dht-adapter.js), the thing the fake test (dht-adapter.mjs) explicitly can't
// prove. Two REAL BridgeGossipSync peers run over the REAL Holepunch stack —
// corestore + hyperbee + hyperswarm + protomux + hypercore replication — on a
// LOCAL testnet DHT (@hyperswarm/testnet, no public network). This exercises the
// genuine Noise handshake, protomux muxing (corestore replication + the descriptor
// channel sharing one muxer), and the compact-encoding.raw wire codec (the fix for
// the pass-through fake). If alice's post reaches bob here, the wire is real.
//
// Not part of `npm test`: needs the heavy DHT deps (corestore@6 hypercore@10
// hyperbee@2 hyperswarm@4 protomux b4a compact-encoding @hyperswarm/testnet
// random-access-memory). Skips cleanly (exit 0) if they're absent.
//   node test/dht-live.mjs

import assert from 'node:assert'
import { createHash } from 'node:crypto'

let deps
try {
  const [Corestore, Hyperswarm, Hyperbee, Protomux, b4a, cenc, RAM, createTestnet] = await Promise.all([
    import('corestore'), import('hyperswarm'), import('hyperbee'), import('protomux'),
    import('b4a'), import('compact-encoding'), import('random-access-memory'), import('@hyperswarm/testnet')
  ]).then((m) => m.map((x) => x.default || x))
  deps = { Corestore, Hyperswarm, Hyperbee, Protomux, b4a, cenc, RAM, createTestnet }
} catch (e) {
  console.log('SKIP dht-live: DHT deps not installed (' + (e && e.message) + ')')
  process.exit(0)
}

const { createHyperPearSurface } = await import('../js/dht-adapter.js')
const { BridgeGossipSync } = await import('../js/gossip.js')
const { DevIdentity } = await import('../js/identity.js')
const { createData } = await import('../js/data.js')
const { ready: cryptoReady, isSecure } = await import('../js/crypto.js')
const { makeValidator } = await import('../js/pow.js')

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const BITS = { community: 7, post: 6, comment: 5 }
function mem () { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
async function until (fn, { tries = 300, gap = 100 } = {}) { for (let i = 0; i < tries; i++) { if (await fn()) return true; await delay(gap) } return false }
async function sha256 (str) { return new Uint8Array(createHash('sha256').update(String(str)).digest()) }

async function makePeer (bootstrap, name) {
  const { Corestore, Hyperswarm, Hyperbee, Protomux, b4a, cenc, RAM } = deps
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const store = new Corestore(RAM)
  await store.ready()
  const swarm = new Hyperswarm({ bootstrap })
  // The REAL adapter with the REAL protomux codec (compact-encoding raw) — the fix.
  const surface = createHyperPearSurface({ store, swarm, Hyperbee, Protomux, b4a, sha256, identity: id, codec: cenc.raw })
  const sync = new BridgeGossipSync({ pear: surface, getMe: () => id.me().pubkey, identity: id, storage: mem(), validate: makeValidator(BITS), pollMs: 500 })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, swarm, store }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available')

  console.log('\n— spin a local testnet DHT (no public network) —')
  const testnet = await deps.createTestnet(3)
  ok(testnet.nodes.length === 3, 'local testnet DHT is up (3 nodes)')

  console.log('\n— two REAL peers converge over the REAL wire (Noise + protomux + compact-encoding.raw) —')
  const alice = await makePeer(testnet.bootstrap, 'alice')
  const bob = await makePeer(testnet.bootstrap, 'bob')
  ok(alice.sync.mode === 'gossip-bridge' && bob.sync.mode === 'gossip-bridge', 'both peers run gossip-bridge on the DHT adapter over hyperswarm')

  await alice.data.createCommunity({ slug: 'dht', title: 'DHT', description: 'over a real testnet DHT' })
  const aPost = await alice.data.submitPost({ community: 'dht', kind: 'text', title: 'hello over the real wire', body: 'noise end to end' })
  ok(await until(() => bob.data.getCommunity('dht')), 'bob discovers alice via the protomux descriptor channel (compact-encoding.raw frames it correctly)')
  ok(await until(() => bob.data.listPostsIn('dht').then((ps) => ps.some((p) => p.cid === aPost.cid))), "bob REPLICATES alice's outbox hypercore over Noise and sees her post")

  const bPost = await bob.data.submitPost({ community: 'dht', kind: 'text', title: 'bob replies', body: 'hi' })
  ok(await until(() => alice.data.getPost('dht', bPost.cid)), "alice sees bob's reply — bidirectional replication over the real DHT")

  await alice.data.vote(aPost.cid, 'dht', 'post', 1)
  await bob.data.vote(aPost.cid, 'dht', 'post', 1)
  ok(await until(async () => (await bob.data.tallyFor(aPost.cid)).score === 2), 'cross-writer votes aggregate to score 2 across the real wire')

  try { alice.sync.destroy(); bob.sync.destroy() } catch {}
  await Promise.all([alice.swarm.destroy(), bob.swarm.destroy()]).catch(() => {})
  await testnet.destroy().catch(() => {})
  console.log(`\n✅ all ${passed} dht-live checks passed — the in-browser DHT path works on the real wire\n`)
  process.exit(0)
}
main().catch((e) => { console.error('\n❌ dht-live FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
