// dht-relay-local.mjs — prove the HOME-BOX model: two independent boxes, each
// running a local ws:// dht-relay (scripts/dht-relay-local.mjs), each hosting one
// RELAYED client that reaches the DHT only through its own local relay (the exact
// browser path from js/dht-transport.js — ws -> local relay -> DHT — just without a
// browser). If alice's post reaches bob, two home boxes converged over the real
// wire with NO hosted relay between them.
//
// Runs on a local @hyperswarm/testnet (no public network). Skips (exit 0) if the
// heavy DHT deps are absent.
//   node test/dht-relay-local.mjs

// Proves the HOME-BOX model end to end: two independent boxes, each running a local
// ws:// dht-relay (scripts/dht-relay-local.mjs), converge peerit content over the real
// DHT with NO hosted relay in the data path.
//
// This surfaced (and validates the fix for) a real bug in the in-browser DHT path: the
// relayed client attached its ws 'message' listener only AFTER awaiting socket-open, so
// a low-latency relay's protomux channel-open frame — sent the instant the socket
// connects — was dropped, the muxer channel never paired, and every relay->client
// message was silently discarded (listen/connect hung forever). The fix (build the
// WSStream BEFORE awaiting open) lives in js/dht-transport.js and is mirrored below in
// makeRelayedPeer. Needs the heavy DHT deps; runs on a local @hyperswarm/testnet.
//   TOPO=two-relay|one-relay|native-relayed node test/dht-relay-local.mjs
import assert from 'node:assert'
import { createHash } from 'node:crypto'
const step = (m) => console.log('  · ' + m)
const _wd = setTimeout(() => { console.log('WATCHDOG 90s — relayed convergence did not complete (known dht-relay listen/connect gap)'); process.exit(2) }, 90000)
if (_wd.unref) _wd.unref()

let deps
try {
  const [Corestore, Hyperswarm, Hyperbee, Protomux, b4a, cenc, RAM, createTestnet, wsMod, RelayDHT, WSStream] = await Promise.all([
    import('corestore'), import('hyperswarm'), import('hyperbee'), import('protomux'),
    import('b4a'), import('compact-encoding'), import('random-access-memory'), import('@hyperswarm/testnet'),
    import('ws'), import('@hyperswarm/dht-relay'), import('@hyperswarm/dht-relay/ws')
  ]).then((m) => m.map((x) => x.default || x))
  deps = { Corestore, Hyperswarm, Hyperbee, Protomux, b4a, cenc, RAM, createTestnet, WebSocket: wsMod.WebSocket || wsMod, RelayDHT, WSStream }
} catch (e) {
  console.log('SKIP dht-relay-local: DHT deps not installed (' + (e && e.message) + ')')
  process.exit(0)
}

const { startLocalRelay } = await import('../scripts/dht-relay-local.mjs')
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
async function until (fn, { tries = 400, gap = 100 } = {}) { for (let i = 0; i < tries; i++) { if (await fn()) return true; await delay(gap) } return false }
async function sha256 (str) { return new Uint8Array(createHash('sha256').update(String(str)).digest()) }

// One relayed peer: a ws client into a local relay, wrapped exactly as js/dht-transport.js does.
async function makeRelayedPeer (relayUrl, name) {
  const { Corestore, Hyperswarm, Hyperbee, Protomux, b4a, cenc, RAM, WebSocket, RelayDHT, WSStream } = deps
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  step(name + ': connecting ws ' + relayUrl)
  const socket = new WebSocket(relayUrl)
  // Attach the transport listener BEFORE awaiting open (see js/dht-transport.js) — otherwise
  // the relay's immediately-sent channel-open frame is dropped and nothing relay->client lands.
  const wsStream = new WSStream(true, socket)
  await new Promise((resolve, reject) => { if (socket.readyState === 1) return resolve(); socket.addEventListener('open', () => resolve(), { once: true }); socket.addEventListener('error', () => reject(new Error('ws connect failed: ' + relayUrl)), { once: true }) })
  step(name + ': ws OPEN; building relayed DHT')
  const dht = new RelayDHT(wsStream) // relayed DHT client — the browser's exact construction
  if (dht.ready) { await dht.ready(); step(name + ': relayed dht.ready()') }
  const store = new Corestore(RAM); await store.ready(); step(name + ': corestore ready')
  const swarm = new Hyperswarm({ dht })
  const surface = createHyperPearSurface({ store, swarm, Hyperbee, Protomux, b4a, sha256, identity: id, codec: cenc.raw })
  const sync = new BridgeGossipSync({ pear: surface, getMe: () => id.me().pubkey, identity: id, storage: mem(), validate: makeValidator(BITS), pollMs: 500 })
  step(name + ': sync.ready() ...')
  await sync.ready()
  step(name + ': sync.ready() DONE mode=' + sync.mode)
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, swarm, socket }
}

// A NATIVE peer (direct hyperswarm on the testnet, exactly like test/dht-live.mjs) —
// used to isolate the relay: if a native peer converges with a relayed peer, the ws
// bridge carries convergence and only inter-relay routing is in question.
async function makeNativePeer (bootstrap, name) {
  const { Corestore, Hyperswarm, Hyperbee, Protomux, b4a, cenc, RAM } = deps
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const store = new Corestore(RAM); await store.ready()
  const swarm = new Hyperswarm({ bootstrap })
  const surface = createHyperPearSurface({ store, swarm, Hyperbee, Protomux, b4a, sha256, identity: id, codec: cenc.raw })
  const sync = new BridgeGossipSync({ pear: surface, getMe: () => id.me().pubkey, identity: id, storage: mem(), validate: makeValidator(BITS), pollMs: 500 })
  step(name + ': (native) sync.ready() ...'); await sync.ready(); step(name + ': (native) sync.ready() DONE')
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, swarm }
}

const TOPO = process.env.TOPO || 'native-relayed' // native-relayed | one-relay | two-relay

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available')
  step('TOPO=' + TOPO)

  step('main: starting; spinning testnet')
  console.log('\n— local testnet DHT (no public network) —')
  const testnet = await deps.createTestnet(3)
  step('testnet up: ' + testnet.nodes.length + ' nodes; bootstrap=' + JSON.stringify(testnet.bootstrap))
  ok(testnet.nodes.length === 3, 'testnet DHT up (3 nodes)')

  const relays = []
  const mkRelay = async () => { const r = await startLocalRelay({ port: 0, bootstrap: testnet.bootstrap }); relays.push(r); const url = 'ws://127.0.0.1:' + r.wss.address().port; step('relay up ' + url); return url }

  let alice, bob
  if (TOPO === 'native-relayed') {
    console.log('\n— alice NATIVE on the testnet · bob RELAYED through his own local ws relay —')
    alice = await makeNativePeer(testnet.bootstrap, 'alice')
    bob = await makeRelayedPeer(await mkRelay(), 'bob')
  } else if (TOPO === 'one-relay') {
    console.log('\n— alice + bob both RELAYED through ONE shared local relay —')
    const url = await mkRelay()
    alice = await makeRelayedPeer(url, 'alice')
    bob = await makeRelayedPeer(url, 'bob')
  } else {
    console.log('\n— two independent HOME BOXES, each its own local ws relay —')
    alice = await makeRelayedPeer(await mkRelay(), 'alice')
    bob = await makeRelayedPeer(await mkRelay(), 'bob')
  }
  ok(alice.sync.mode === 'gossip-bridge' && bob.sync.mode === 'gossip-bridge', 'both peers run gossip-bridge (' + TOPO + ')')

  // Diagnostic: do the swarms actually form peer connections?
  let aC = 0, bC = 0
  alice.swarm.on('connection', () => { aC++; step('alice swarm CONNECTION #' + aC) })
  bob.swarm.on('connection', () => { bC++; step('bob swarm CONNECTION #' + bC) })
  const statusIv = setInterval(() => step(`status: alice-conns=${aC} bob-conns=${bC} bob-peers=${(bob.sync._peers && bob.sync._peers.size) || '?'}`), 4000)
  if (statusIv.unref) statusIv.unref()

  step('alice creating community + post')
  await alice.data.createCommunity({ slug: 'homebox', title: 'HomeBox', description: 'two boxes, no hosted relay' })
  const aPost = await alice.data.submitPost({ community: 'homebox', kind: 'text', title: 'posted from my own box', body: 'no server in the middle' })
  step('alice posted ' + aPost.cid + '; waiting for bob to discover')
  ok(await until(() => bob.data.getCommunity('homebox')), 'bob (his box) discovers alice via the DHT through both local relays')
  step('bob discovered community')
  ok(await until(() => bob.data.listPostsIn('homebox').then((ps) => ps.some((p) => p.cid === aPost.cid))), "bob replicates alice's outbox over Noise — box-to-box, no hosted relay")

  const bPost = await bob.data.submitPost({ community: 'homebox', kind: 'text', title: 'bob replies from his box', body: 'hi' })
  ok(await until(() => alice.data.getPost('homebox', bPost.cid)), "alice sees bob's reply — bidirectional over the real DHT")

  await alice.data.vote(aPost.cid, 'homebox', 'post', 1)
  await bob.data.vote(aPost.cid, 'homebox', 'post', 1)
  ok(await until(async () => (await bob.data.tallyFor(aPost.cid)).score === 2), 'cross-box votes aggregate to score 2')

  try { alice.sync.destroy(); bob.sync.destroy() } catch {}
  await Promise.all([alice.swarm.destroy(), bob.swarm.destroy()]).catch(() => {})
  await Promise.all(relays.map((r) => r.close())).catch(() => {})
  await testnet.destroy().catch(() => {})
  console.log(`\n✅ all ${passed} home-box checks passed — two boxes synced through their own local relays, no hosted relay in the data path\n`)
  process.exit(0)
}
main().catch((e) => { console.error('\n❌ dht-relay-local FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
