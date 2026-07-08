// test/cache-poisoning.mjs — a relay wipe must never poison the cached view.
// Run: node test/cache-poisoning.mjs
//
// THE BUG: the production relay can restart/wipe and then answers 200-with-EMPTY-
// rows (and version-0 heads) for outboxes it forgot. The client's reconcile
// deletes every cached row, and _saveCache used to persist that EMPTY view over a
// good one. Because the seed snapshot is only used when there is NO cache, every
// later boot skipped the snapshot floor and rendered an empty feed forever —
// "posts loaded first time but went away" (live incident 2026-07-08).
//
// THE CONTRACT (stale-never-empty, at the persistence layer):
//  1. _saveCache never overwrites a non-empty cached view with a rowless one.
//  2. _loadCache treats a rowless cache as NO cache (so the snapshot floor applies).
//  3. cachedViewHasRows (used by app.js to gate the snapshot fetch) agrees — which
//     HEALS devices already poisoned by older builds.

import assert from 'node:assert'
import { BridgeGossipSync, cachedViewHasRows } from '../js/gossip.js'
import { DevIdentity } from '../js/identity.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { canonical } from '../js/canon.js'
import { makeValidator, mint } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const BITS = { community: 6, post: 5 }
const CACHE_KEY = 'peerit:gossip-view'

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

// Same in-memory relay world as test/gossip.mjs / test/instant-boot.mjs. ensure()
// auto-creates an EMPTY group for any unknown appId — exactly how the real relay
// behaves after a wipe, which is what makes the poisoning reproducible here.
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

async function powSign (id, type, data) {
  data.pow = await mint(type, data, BITS[type] || 0)
  const s = await id.sign(canonical(type, data))
  return { ...data, _sig: s.signature, _k: s.publicKey, _dk: s.driveKey, _ns: s.namespace, _alg: s.algorithm }
}

async function main () {
  await cryptoReady()

  // ---- world: an author with signed + PoW'd content on the live relay ----
  const world = rememberingPear()
  const authorId = new DevIdentity(mem(), mem()); await authorId.ready(); await authorId.createUser('author')
  const authorPub = authorId.me().pubkey
  const author = new BridgeGossipSync({ pear: world, getMe: () => authorPub, identity: authorId, storage: mem(), validate: makeValidator(BITS), pollMs: 0 })
  await author.ready()
  const comm = await powSign(authorId, 'community', { id: 'p2p', slug: 'p2p', title: 'P2P', description: 'd', creator: authorPub, author: authorPub, createdAt: 1, updatedAt: 1 })
  const post = await powSign(authorId, 'post', { id: 'p2p!hello', cid: 'hello', community: 'p2p', kind: 'text', title: 'hello world', body: 'still here after the wipe', url: '', author: authorPub, createdAt: 2, editedAt: 0, deleted: false })
  await author.append({ type: 'community', data: comm })
  await author.append({ type: 'post', data: post })
  const seedOutboxes = [{ appId: authorPub, inviteKey: 'a'.repeat(64) }]

  // ---- prime a reader's device cache from the healthy relay ----
  const readerId = new DevIdentity(mem(), mem()); await readerId.ready(); await readerId.createUser('reader')
  const device = mem() // the phone
  const live = new BridgeGossipSync({ pear: world, getMe: () => readerId.me().pubkey, identity: readerId, storage: device, validate: makeValidator(BITS), pollMs: 0, seedOutboxes })
  await live.ready()
  await live._refresh()
  ok((await live.list('post!')).length === 1, 'reader synced the post from the healthy relay')
  ok(cachedViewHasRows(device), 'device cache is primed and has rows')
  const goodBlob = device.getItem(CACHE_KEY)

  // ---- 1. THE WIPE: same device reconciles against a relay that forgot everything ----
  const wiped = rememberingPear() // ensure() serves 200-with-empty-rows for every appId
  const afterWipe = new BridgeGossipSync({ pear: wiped, getMe: () => readerId.me().pubkey, identity: readerId, storage: device, validate: makeValidator(BITS), pollMs: 0, seedOutboxes })
  await afterWipe.ready()
  await afterWipe._refresh()
  ok(cachedViewHasRows(device), 'wipe reconcile did NOT poison the persisted cache (rows kept)')
  ok(device.getItem(CACHE_KEY) === goodBlob, 'persisted blob is byte-identical to the pre-wipe view (empty never overwrites non-empty)')

  // ---- 2. next boot on the same device (relay still empty): stale, never empty ----
  const nextBoot = new BridgeGossipSync({ pear: wiped, getMe: () => readerId.me().pubkey, identity: readerId, storage: device, validate: makeValidator(BITS), pollMs: 0, seedOutboxes, instantBoot: true })
  await nextBoot.ready()
  const rows = await nextBoot.list('post!')
  ok(rows.length === 1 && rows[0].value.body === 'still here after the wipe', 'next boot renders the STALE view, not an empty feed')

  // ---- 3. white-box: _saveCache with all-empty views must refuse to persist ----
  for (const [pub] of nextBoot._peerViews) nextBoot._peerViews.set(pub, Object.create(null))
  nextBoot._saveCache()
  ok(device.getItem(CACHE_KEY) === goodBlob, '_saveCache(empty views) is a no-op (guard fired, blob untouched)')

  // ---- 4. ALREADY-poisoned device (older build wrote the empty blob): heals via snapshot ----
  const poisoned = mem()
  poisoned.setItem(CACHE_KEY, JSON.stringify({ v: 1, peers: [{ pub: authorPub, appId: authorPub, inviteKey: 'a'.repeat(64) }], views: { [authorPub]: {} }, heads: {} }))
  ok(!cachedViewHasRows(poisoned), 'cachedViewHasRows treats the poisoned (rowless) blob as NO cache — app.js will fetch the snapshot')
  const snapshot = { authors: [{ pub: authorPub, rows: world.groups.get(authorPub) ? [...world.groups.get(authorPub).rows.entries()].map(([key, value]) => ({ key, value })) : [] }] }
  const victimId = new DevIdentity(mem(), mem()); await victimId.ready(); await victimId.createUser('victim')
  const healed = new BridgeGossipSync({ pear: wiped, getMe: () => victimId.me().pubkey, identity: victimId, storage: poisoned, validate: makeValidator(BITS), pollMs: 0, seedOutboxes, instantBoot: true, seedSnapshot: snapshot })
  await healed.ready()
  const healedRows = await healed.list('post!')
  ok(healedRows.length === 1 && healedRows[0].value.title === 'hello world', 'poisoned device renders the seed snapshot (empty cache did not suppress the floor)')

  // ---- 5. helper contract edges ----
  ok(!cachedViewHasRows(mem()), 'no cache at all -> false')
  const junk = mem(); junk.setItem(CACHE_KEY, 'not json')
  ok(!cachedViewHasRows(junk), 'corrupt cache -> false (never throws)')
  const good = mem(); good.setItem(CACHE_KEY, goodBlob)
  ok(cachedViewHasRows(good), 'non-empty cache -> true')

  console.log(`\ncache-poisoning: ${passed} checks passed.`)
}

main().catch((e) => { console.error('❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
