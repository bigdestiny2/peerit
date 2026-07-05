// pearbrowser-dispersal-convergence.mjs — two bridge-mode peers read a dispersed post.
//
// Proves the PearBrowser BlindShard path end-to-end without a real PearBrowser
// host. Peer A (bridge-mode, but with a seed-exposing identity for this test)
// authors a dispersed post to a shared mock HiveRelay shard cohort over HTTP.
// The post record replicates through the shared window.pear.sync surface; the
// shards and ciphertext do NOT live in the sync group. Peer B joins A's outbox
// and recovers the body by fetching shards + ciphertext from the cohort.

import assert from 'node:assert'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { createSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))

const BITS = { community: 7, post: 6, comment: 5, blob: 4 }

function mem () {
  const m = new Map()
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() }
}

function shardHash (bytes) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(bytes))
  return 'shard:' + b4a.toString(out, 'hex')
}

function getHeader (headers, name) {
  if (!headers) return undefined
  if (typeof headers.get === 'function') return headers.get(name)
  return headers[name]
}

// Shared mock HiveRelay shard cohort. Both peers read/write shards here; the
// peerit sync group only carries the sealed post records + heads.
function makeShardStore () {
  const intents = new Map()
  const shards = new Map()
  const relayPubs = new Map([
    ['https://relay-a.example', 'a'.repeat(64)],
    ['https://relay-b.example', 'b'.repeat(64)],
    ['https://relay-c.example', 'c'.repeat(64)]
  ])
  return {
    shards,
    fetch: async (url, init = {}) => {
      const u = new URL(url)
      const base = u.origin
      const path = u.pathname
      if (path === '/api/custody/intent' && init.method === 'POST') {
        intents.set(base, JSON.parse(init.body))
        return { ok: true, status: 201, text: async () => 'ok' }
      }
      if (path === '/api/v1/shard' && init.method === 'POST') {
        const bytes = new Uint8Array(await init.body)
        const addr = shardHash(bytes)
        const pinRaw = getHeader(init.headers, 'X-Shard-Pin')
        const pin = pinRaw ? JSON.parse(pinRaw) : {}
        if (pin.hash && shardHash(bytes) !== 'shard:' + String(pin.hash).toLowerCase()) {
          return { ok: false, status: 400, text: async () => 'hash mismatch' }
        }
        const intent = intents.get(base)
        if (!intent) return { ok: false, status: 401, text: async () => 'orphan intent' }
        if (pin.shareIndex === 0) {
          const ctAssign = (intent.ciphertextAssignments || []).find(a => a.relayPubkey.toLowerCase() === relayPubs.get(base))
          if (!ctAssign || addr !== intent.ciphertextShard) return { ok: false, status: 401, text: async () => 'bad ciphertext assignment' }
        } else {
          const assign = intent.shareAssignments.find(a => a.relayPubkey.toLowerCase() === relayPubs.get(base))
          if (!assign || assign.shareIndex !== pin.shareIndex) return { ok: false, status: 401, text: async () => 'bad assignment' }
          const bound = intent.shareManifest.find(m => m.shareIndex === pin.shareIndex)
          if (!bound || addr !== bound.shard) return { ok: false, status: 401, text: async () => 'manifest mismatch' }
        }
        shards.set(addr, bytes)
        return { ok: true, status: 201, json: async () => ({ shard: addr }) }
      }
      const getMatch = path.match(/\/api\/v1\/shard\/([0-9a-f]{64})$/i)
      if (getMatch) {
        const addr = 'shard:' + getMatch[1].toLowerCase()
        const bytes = shards.get(addr)
        if (!bytes) return { ok: false, status: 404, text: async () => 'not found' }
        return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) }
      }
      throw new Error('unexpected fetch: ' + url)
    }
  }
}

// Shared fake PearBrowser sync surface. Both peers operate on the same groups.
function makeSharedPearSync () {
  const groups = new Map() // appId -> { inviteKey, rows: Map, version }
  const listeners = new Set()

  const ensure = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { inviteKey: Math.random().toString(36).slice(2), rows: new Map(), version: 0 })
    return groups.get(appId)
  }
  const sorted = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))

  const sync = {
    create: async (appId) => { ensure(appId); return { appId, inviteKey: groups.get(appId).inviteKey, writerPublicKey: appId } },
    join: async (appId, inviteKey) => {
      const g = ensure(appId)
      if (g.inviteKey !== inviteKey) throw new Error('bad invite')
      return { appId, inviteKey, writerPublicKey: appId }
    },
    append: async (appId, op) => {
      const g = ensure(appId)
      const key = op.type.replace(':', '!') + '!' + op.data.id
      g.rows.set(key, op.data)
      g.version++
      for (const fn of listeners) { try { fn() } catch (e) { console.error(e) } }
      return { ok: true, key }
    },
    get: async (appId, key) => { const g = groups.get(appId); return g ? (g.rows.get(key) || null) : null },
    list: async (appId, prefix, listOpts = {}) => {
      const g = ensure(appId)
      const limit = Number(listOpts.limit) || 100
      return sorted(g).filter(r => r.key >= prefix && r.key < prefix + '\xff').slice(0, limit)
    },
    range: async (appId, opts = {}) => {
      const g = ensure(appId)
      let rows = sorted(g)
      for (const [bound, cmp] of [['gte', (k, v) => k >= v], ['gt', (k, v) => k > v], ['lte', (k, v) => k <= v], ['lt', (k, v) => k < v]]) {
        const v = opts[bound]
        if (v != null && v !== '') rows = rows.filter(r => cmp(r.key, v))
      }
      if (opts.reverse) rows.reverse()
      return rows.slice(0, Number(opts.limit) || 100)
    },
    count: async (appId, prefix) => {
      const g = ensure(appId)
      return { count: sorted(g).filter(r => r.key >= prefix && r.key < prefix + '\xff').length }
    },
    status: async (appId) => {
      const g = ensure(appId)
      return { appId, inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size }
    }
  }

  return { sync, groups, onChange: (fn) => { listeners.add(fn); return () => listeners.delete(fn) } }
}

async function makePeer (world, shardFetch, name, knownOutboxes = []) {
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  const storage = mem()
  const sync = createSync({ pear: { sync: world.sync }, storage, mode: 'shared', getMe: () => id.me().pubkey, identity: id, validate: makeValidator(BITS), pollMs: 100 })
  await sync.ready()
  const data = createData(sync, id, {
    minBits: BITS,
    dispersal: true,
    shardRelays: [
      { url: 'https://relay-a.example', pubkey: 'a'.repeat(64) },
      { url: 'https://relay-b.example', pubkey: 'b'.repeat(64) },
      { url: 'https://relay-c.example', pubkey: 'c'.repeat(64) }
    ],
    fetch: shardFetch
  })
  // Seed known outboxes so peer B merges A's data without waiting for swarm discovery.
  for (const appId of knownOutboxes) {
    try { await sync.join(appId, world.groups.get(appId).inviteKey) } catch {}
  }
  return { id, sync, data, pub: id.me().pubkey }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 backend available')

  const world = makeSharedPearSync()
  const shardStore = makeShardStore()

  console.log('\n— peer A authors a dispersed post over bridge sync —')
  const peerA = await makePeer(world, shardStore.fetch, 'alice')
  ok(peerA.sync.mode === 'bridge', 'peer A runs in bridge mode')

  await peerA.data.createCommunity({ slug: 'p2p', title: 'P2P' })
  const body = 'x'.repeat(3000) // above dispersal threshold
  const post = await peerA.data.submitPost({ community: 'p2p', kind: 'text', title: 'Bridge dispersed post', body })
  ok(post.body === '', 'stored post body is empty placeholder')
  ok(post.dispersal && post.dispersal.scheme === 'pvss-secp256k1-v1', 'post carries a PVSS dispersal manifest')
  ok(post.dispersal.threshold === 2 && post.dispersal.count === 3, 'manifest names a 2-of-3 scheme')

  const localBlob = await peerA.sync.get('blob!' + post.dispersal.blindContentId)
  ok(!localBlob, 'ciphertext is NOT stored as a local blob in bridge mode')
  ok(!!shardStore.shards.get(post.dispersal.ciphertextShard), 'ciphertext shard was placed on the mock cohort')
  ok(post.dispersal.shareManifest.every(s => shardStore.shards.has(s.shard)), 'all key shards were placed on the mock cohort')

  const aStatus = await peerA.sync.status()
  ok(aStatus.viewLength >= 2, 'peer A outbox contains community + post + head (no shard records in sync)')

  console.log('\n— peer B joins peer A outbox and recovers the dispersed body —')
  const peerB = await makePeer(world, shardStore.fetch, 'bob', [peerA.pub])
  ok(peerB.sync.mode === 'bridge', 'peer B runs in bridge mode')

  // Wait for the merge to converge.
  let recovered = null
  for (let i = 0; i < 50; i++) {
    recovered = await peerB.data.getPost('p2p', post.cid)
    if (recovered && recovered.body === body) break
    await delay(50)
  }
  ok(recovered && recovered.body === body, "peer B recovers peer A's exact body from the shard cohort")
  ok(!recovered._blobMissing, 'hydration did not flag blob missing')

  console.log('\n— tampered shards on the cohort fail recovery —')
  // Corrupt 2 of 3 shards so fewer than k=2 valid shards remain.
  for (let i = 0; i < 2; i++) {
    const addr = post.dispersal.shareManifest[i].shard
    const original = shardStore.shards.get(addr)
    ok(!!original, `cohort holds shard ${i + 1}`)
    const corrupted = new Uint8Array(original)
    corrupted[0] ^= 0xff
    shardStore.shards.set(addr, corrupted)
  }
  peerB.data._bodyCache.clear()
  const tampered = await peerB.data.getPost('p2p', post.cid)
  ok(tampered && tampered._blobMissing, 'corrupted shards cause recovery to fail closed (_blobMissing)')

  console.log('\n✅ all ' + passed + ' pearbrowser dispersal convergence checks passed')
  peerA.sync.destroy()
  peerB.sync.destroy()
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
