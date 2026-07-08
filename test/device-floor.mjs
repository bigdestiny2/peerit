// test/device-floor.mjs — the device durability floor (ADR-2026-07-07).
//
// Proves the ruling that dispersal must NOT make a post less durable than a
// plain v2 post: the AUTHOR's device keeps {key, iv, ciphertext} device-local
// (never synced), so after TOTAL cohort loss the author still reads their body
// (floor decrypt), probeDispersal reports the outage, and repairDispersal
// re-disperses from the floor so ordinary readers recover too. A reader with no
// floor proves the counterfactual (body gone without it). Floor entries are
// dropped on delete so a deleted post keeps no local copy.

import assert from 'node:assert'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { createSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const BITS = { community: 7, post: 6, comment: 5, blob: 4 }

function mem () {
  const m = new Map()
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    clear: () => m.clear(),
    keys: () => [...m.keys()]
  }
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

// Mock HiveRelay shard cohort (same wire shapes as the live surface).
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

// Shared fake PearBrowser sync surface (records replicate; shards do not).
function makeSharedPearSync () {
  const groups = new Map()
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
      return sorted(g).filter(r => r.key >= prefix && r.key < prefix + '\xff').slice(0, Number(listOpts.limit) || 100)
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
    count: async (appId, prefix) => ({ count: sorted(ensure(appId)).filter(r => r.key >= prefix && r.key < prefix + '\xff').length }),
    status: async (appId) => { const g = ensure(appId); return { appId, inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size } }
  }
  return { sync, groups, onChange: (fn) => { listeners.add(fn); return () => listeners.delete(fn) } }
}

const COHORT = [
  { url: 'https://relay-a.example', pubkey: 'a'.repeat(64) },
  { url: 'https://relay-b.example', pubkey: 'b'.repeat(64) },
  { url: 'https://relay-c.example', pubkey: 'c'.repeat(64) }
]

async function makePeer (world, shardFetch, name, { deviceStore = null, knownOutboxes = [] } = {}) {
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  const sync = createSync({ pear: { sync: world.sync }, storage: mem(), mode: 'shared', getMe: () => id.me().pubkey, identity: id, validate: makeValidator(BITS), pollMs: 100 })
  await sync.ready()
  const data = createData(sync, id, { minBits: BITS, dispersal: true, shardRelays: COHORT, fetch: shardFetch, deviceStore })
  for (const appId of knownOutboxes) {
    try { await sync.join(appId, world.groups.get(appId).inviteKey) } catch {}
  }
  return { id, sync, data, pub: id.me().pubkey }
}

async function main () {
  await cryptoReady()
  const world = makeSharedPearSync()
  const store = makeShardStore()
  const floorStore = mem()

  const author = await makePeer(world, store.fetch, 'author', { deviceStore: floorStore })
  const body = ('the device floor survives total cohort loss. ').repeat(64) // > BOX_MIN_BYTES => dispersal path

  await author.data.createCommunity({ slug: 'floor', title: 'Floor', description: 'd' })
  const post = await author.data.submitPost({ community: 'floor', kind: 'text', title: 'floored', body })
  const raw = await author.sync.get('post!floor!' + post.cid) || post
  const m = (await author.data._rawPost('floor', post.cid)).dispersal
  ok(m && m.blindContentId, 'post is dispersed (manifest on the record)')

  // 1. The floor entry exists, device-local only (never a synced record).
  const floorKeys = floorStore.keys().filter(k => k.startsWith('peerit:floor:'))
  ok(floorKeys.length === 1 && floorKeys[0] === 'peerit:floor:' + m.blindContentId, 'floor entry saved under peerit:floor:<blindContentId>')
  const entry = JSON.parse(floorStore.getItem(floorKeys[0]))
  ok(entry.v === 1 && /^[0-9a-f]{64}$/.test(entry.key) && entry.ct.length > 0, 'floor holds {key, iv, ct}')
  const syncedKeys = [...world.groups.values()].flatMap((g) => [...g.rows.keys()])
  ok(!syncedKeys.some(k => k.includes('floor:') || k.includes(entry.key)), 'floor never rides the sync group (key stays off every relay)')

  // 2. TOTAL cohort loss: every shard (shares + ciphertext) is gone.
  const shardCount = store.shards.size
  store.shards.clear()
  ok(shardCount >= 4 && store.shards.size === 0, 'cohort wiped (' + shardCount + ' shards destroyed)')

  // 3. The author still reads their own body — from the device floor.
  author.data._bodyCache.clear()
  const mine = await author.data.getPost('floor', post.cid)
  ok(mine && mine.body === body, 'author recovers the body from the device floor at ZERO cohort')

  // 4. Counterfactual: a floor-less reader cannot.
  const reader = await makePeer(world, store.fetch, 'reader', { knownOutboxes: [author.pub] })
  await delay(250)
  const theirs = await reader.data.getPost('floor', post.cid)
  ok(theirs && theirs._blobMissing === true && theirs.body === '', 'reader with no floor loses the body (the floor is load-bearing)')

  // 5. probeDispersal reports the outage.
  const status = await author.data.probeDispersal(m)
  ok(status.available === 0 && !status.recoverable && status.needsRepair, 'probeDispersal: 0 shares available -> needsRepair')

  // 6. repairDispersal re-disperses from the floor; the cohort holds shards again.
  const rep = await author.data.repairDispersal('floor', post.cid)
  ok(rep.repaired === true, 'repairDispersal re-disperses from the floor')
  ok(store.shards.size >= 4, 'cohort re-populated (' + store.shards.size + ' shards)')
  const repaired = await author.data._rawPost('floor', post.cid)
  ok(repaired.dispersal && repaired.dispersal.intentId !== m.intentId, 'repaired record carries a FRESH custody intent')
  const probe2 = await author.data.probeDispersal(repaired.dispersal)
  ok(probe2.recoverable && !probe2.needsRepair, 'probe after repair: recoverable, no repair needed')

  // 7. Ordinary readers recover again through the repaired cohort.
  await delay(250)
  reader.data._bodyCache.clear()
  reader.data.invalidateViewCaches()
  const theirs2 = await reader.data.getPost('floor', post.cid)
  ok(theirs2 && theirs2.body === body, 'floor-less reader reads the body again after repair')

  // 8. Healthy posts are not churned: repair without force is a no-op.
  const rep2 = await author.data.repairDispersal('floor', post.cid)
  ok(rep2.repaired === false, 'repairDispersal is a no-op while the cohort is healthy')

  // 9. Delete drops the floor entry — a deleted post keeps no local copy.
  await author.data.deletePost('floor', post.cid)
  ok(floorStore.keys().filter(k => k.startsWith('peerit:floor:')).length === 0, 'delete drops the floor entry')

  console.log('\ndevice-floor: ' + passed + ' checks passed')
  process.exit(0) // sync poll timers keep node alive; the run is done
}

main().catch((e) => { console.error('✗ FAIL:', e.message, '\n', e.stack); process.exit(1) })
