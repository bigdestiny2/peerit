// test/instant-boot.mjs — normal-website boot: content renders with ZERO relay.
//
// Proves the Tier-1 reliability work:
//  1. instantBoot ready() returns in milliseconds against a DEAD relay and serves
//     the cached view (returning visitor = instant content, stale-not-empty).
//  2. wake() reconciles once a relay pool is plugged in late (lazy pool path).
//  3. A first-ever visitor renders the baked seed snapshot — every row passes the
//     SAME admit() verification as live gossip; a tampered row is dropped.
//  4. Writes while offline fail politely (and work after wake()).

import assert from 'node:assert'
import { BridgeGossipSync } from '../js/gossip.js'
import { DevIdentity } from '../js/identity.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { canonical } from '../js/canon.js'
import { makeValidator, mint } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const BITS = { community: 6, post: 5 }
const legacyContentSignatures = new Set()
const fixtureValidator = () => makeValidator(BITS, { legacyContentSignatures })

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

// Same in-memory relay world as test/gossip.mjs.
function rememberingPear () {
  const groups = new Map()
  const channel = { peers: [], on: () => {} }
  const ensure = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { inviteKey: 'a'.repeat(64), rows: new Map() })
    return groups.get(appId)
  }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  return {
    groups,
    sync: {
      create: async (appId) => ({ appId, inviteKey: ensure(appId).inviteKey, writerPublicKey: 'b'.repeat(64) }),
      join: async (appId, inviteKey) => {
        const g = ensure(appId)
        if (inviteKey !== g.inviteKey) throw new Error('bad invite')
        return { appId, inviteKey, writerPublicKey: 'b'.repeat(64) }
      },
      append: async (appId, op) => {
        const key = op.type.replace(':', '!') + '!' + op.data.id
        ensure(appId).rows.set(key, op.data)
        return { ok: true, key }
      },
      range: async (appId, opts = {}) => {
        let rows = sortedRows(ensure(appId))
        if (opts.gt != null) rows = rows.filter(r => r.key > opts.gt)
        if (opts.gte != null) rows = rows.filter(r => r.key >= opts.gte)
        if (opts.lt != null) rows = rows.filter(r => r.key < opts.lt)
        if (opts.lte != null) rows = rows.filter(r => r.key <= opts.lte)
        return rows.slice(0, Number(opts.limit) || 100)
      },
      list: async (appId, prefix = '', opts = {}) => {
        let rows = sortedRows(ensure(appId))
        if (prefix) rows = rows.filter(r => r.key >= prefix && r.key < prefix + '\xff')
        return rows.slice(0, Number(opts.limit) || 100)
      },
      status: async (appId) => ({ appId, inviteKey: ensure(appId).inviteKey, viewLength: ensure(appId).rows.size })
    },
    swarm: { v1: { join: async () => channel } }
  }
}

// A relay that is DOWN: every call rejects (like the lazy pool before selection).
function deadPear () {
  const boom = async () => { throw new Error('relay not connected yet') }
  const pear = { sync: {}, swarm: { v1: { join: boom } } }
  for (const m of ['create', 'join', 'append', 'get', 'list', 'range', 'count', 'heads', 'directory', 'crossHead', 'crossRows', 'recoverRows']) pear.sync[m] = boom
  return pear
}

// A lazy facade like app.js's createLazyPearPool.
function lazyPear () {
  let target = null
  const call = (ns, m) => async (...a) => { if (!target) throw new Error('relay not connected yet'); return ns === 'swarm' ? target.swarm.v1.join(...a) : target.sync[m](...a) }
  const pear = { sync: {}, swarm: { v1: { join: call('swarm') } } }
  for (const m of ['create', 'join', 'append', 'get', 'list', 'range', 'count', 'heads', 'directory', 'crossHead', 'crossRows', 'recoverRows']) pear.sync[m] = call('sync', m)
  return { pear, setTarget: (t) => { target = t } }
}

async function sign (id, type, data) {
  const s = await id.sign(canonical(type, data))
  if (type === 'post' || type === 'comment') legacyContentSignatures.add(s.signature)
  return { ...data, _sig: s.signature, _k: s.publicKey, _dk: s.driveKey, _ns: s.namespace, _alg: s.algorithm }
}
async function powSign (id, type, data) {
  data.pow = await mint(type, data, BITS[type] || 0)
  return sign(id, type, data)
}

async function main () {
  await cryptoReady()

  // ---- world: an author with real signed + PoW'd content on the live relay ----
  const world = rememberingPear()
  const authorId = new DevIdentity(mem(), mem()); await authorId.ready(); await authorId.createUser('author')
  const authorPub = authorId.me().pubkey
  const author = new BridgeGossipSync({ pear: world, getMe: () => authorPub, identity: authorId, storage: mem(), validate: fixtureValidator(), pollMs: 0 })
  await author.ready()
  const comm = await powSign(authorId, 'community', { id: 'p2p', slug: 'p2p', title: 'P2P', description: 'd', creator: authorPub, author: authorPub, createdAt: 1, updatedAt: 1 })
  const post = await powSign(authorId, 'post', { id: 'p2p!hello', cid: 'hello', community: 'p2p', kind: 'text', title: 'hello world', body: 'instant boot works', url: '', author: authorPub, createdAt: 2, editedAt: 0, deleted: false })
  await author.append({ type: 'community', data: comm })
  await author.append({ type: 'post', data: post })

  // ---- returning visitor: sync once against the live relay to build the cache ----
  const readerId = new DevIdentity(mem(), mem()); await readerId.ready(); await readerId.createUser('reader')
  const readerStore = mem()
  const seedOutboxes = [{ appId: authorPub, inviteKey: 'a'.repeat(64) }]
  const live = new BridgeGossipSync({ pear: world, getMe: () => readerId.me().pubkey, identity: readerId, storage: readerStore, validate: fixtureValidator(), pollMs: 0, seedOutboxes })
  await live.ready()
  await live._refresh()
  const liveRows = await live.list('post!')
  ok(liveRows.length === 1 && liveRows[0].value.title === 'hello world', 'live sync reads the author post (cache primed)')
  ok(!!readerStore.getItem('peerit:gossip-view'), 'verified view persisted to the device')

  // ---- 1. INSTANT boot on a DEAD relay: cached content in milliseconds ----
  const t0 = Date.now()
  const offline = new BridgeGossipSync({ pear: deadPear(), getMe: () => readerId.me().pubkey, identity: readerId, storage: readerStore, validate: fixtureValidator(), pollMs: 0, seedOutboxes, instantBoot: true })
  await offline.ready()
  const bootMs = Date.now() - t0
  ok(bootMs < 300, 'instantBoot ready() returns in ' + bootMs + 'ms against a DEAD relay')
  const offRows = await offline.list('post!')
  ok(offRows.length === 1 && offRows[0].value.body === 'instant boot works', 'cached post renders with ZERO relay round-trips (stale, not empty)')
  await assert.rejects(() => offline.append({ type: 'post', data: post }), /outbox is unavailable|read-only/i, '')
  passed++; console.log('  ✓ offline write fails politely (relay unavailable), never silently')

  // ---- 2. lazy pool + wake(): relay appears late, view reconciles ----
  const lazy = lazyPear()
  const lateStore = readerStore // same device
  const late = new BridgeGossipSync({ pear: lazy.pear, getMe: () => readerId.me().pubkey, identity: readerId, storage: lateStore, validate: fixtureValidator(), pollMs: 0, seedOutboxes, instantBoot: true })
  await late.ready()
  ok((await late.list('post!')).length === 1, 'lazy-pool boot renders the cache before any relay exists')
  // author posts something NEW while we were "offline"
  const post2 = await powSign(authorId, 'post', { id: 'p2p!again', cid: 'again', community: 'p2p', kind: 'text', title: 'after reconnect', body: 'fresh row', url: '', author: authorPub, createdAt: 3, editedAt: 0, deleted: false })
  await author.append({ type: 'post', data: post2 })
  lazy.setTarget(world)
  await late.wake()
  const woke = await late.list('post!')
  ok(woke.length === 2 && woke.some(r => r.value.title === 'after reconnect'), 'wake() after late connect pulls the new post (stale view reconciled)')

  // ---- 3. first-ever visitor: baked seed snapshot, admit()-verified ----
  const snapRows = [...world.groups.get(authorPub).rows.entries()].map(([key, value]) => ({ key, value }))
  const snapshot = { v: 1, authors: [{ pub: authorPub, rows: snapRows }] }
  const freshId = new DevIdentity(mem(), mem()); await freshId.ready(); await freshId.createUser('fresh')
  const fresh = new BridgeGossipSync({ pear: deadPear(), getMe: () => freshId.me().pubkey, identity: freshId, storage: mem(), validate: fixtureValidator(), pollMs: 0, instantBoot: true, seedSnapshot: snapshot })
  await fresh.ready()
  const freshRows = await fresh.list('post!')
  ok(freshRows.length === 2, 'first visit renders the seed snapshot with ZERO relay (' + freshRows.length + ' posts)')

  // tampered snapshot row (body swapped, signature stale) must be dropped
  const tampered = JSON.parse(JSON.stringify(snapshot))
  for (const r of tampered.authors[0].rows) if (r.key === 'post!p2p!hello') r.value.body = 'EVIL EDIT'
  const fresh2 = new BridgeGossipSync({ pear: deadPear(), getMe: () => freshId.me().pubkey, identity: freshId, storage: mem(), validate: fixtureValidator(), pollMs: 0, instantBoot: true, seedSnapshot: tampered })
  await fresh2.ready()
  const rows2 = await fresh2.list('post!')
  ok(rows2.length === 1 && rows2[0].value.title === 'after reconnect', 'tampered snapshot row is REJECTED by admit() (1 valid row survives)')

  // ---- 4. non-instant boot unchanged (seeder/tests contract) ----
  const classic = new BridgeGossipSync({ pear: world, getMe: () => readerId.me().pubkey, identity: readerId, storage: mem(), validate: fixtureValidator(), pollMs: 0, seedOutboxes })
  await classic.ready()
  ok((await classic._refresh(), (await classic.list('post!')).length === 2), 'default (non-instant) boot still does the network work in ready()')

  console.log('\ninstant-boot: ' + passed + ' checks passed')
  process.exit(0)
}
main().catch((e) => { console.error('✗ FAIL:', e.message, '\n', e.stack); process.exit(1) })
