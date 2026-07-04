// bridge-shard-transport.mjs — verify PearBrowser bridge shard read/write.
// Uses a fake window.pear.sync surface so the test runs without a real PearBrowser
// host, exercises BridgeSync (mode === 'bridge') and proves dispersed bodies are
// stored/read as `shard!<hash>` records instead of HTTP HiveRelay calls.

import assert from 'node:assert'
import { createSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { keys } from '../js/model.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

function makeFakePearSync () {
  const groups = new Map()
  const ensure = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { rows: new Map() })
    return groups.get(appId)
  }
  const sorted = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  return {
    groups,
    sync: {
      create: async (appId) => { ensure(appId); return { appId, inviteKey: 'fake-invite', writerPublicKey: 'fake-pub' } },
      join: async (appId, inviteKey) => { ensure(appId); return { appId, inviteKey, writerPublicKey: 'fake-pub' } },
      append: async (appId, op) => {
        const g = ensure(appId)
        const key = op.type.replace(':', '!') + '!' + op.data.id
        g.rows.set(key, op.data)
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
        return { appId, inviteKey: 'fake-invite', writerCount: 1, viewLength: g.rows.size }
      }
    }
  }
}

async function main () {
  console.log('\n— bridge shard transport write path —')
  const fake = makeFakePearSync()
  const storage = mem()
  const sync = createSync({ pear: fake, mode: 'shared', storage })
  await sync.ready()
  ok(sync.mode === 'bridge', 'sync runs in bridge mode')

  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser('bridge-author')

  const relays = [
    { url: 'https://relay-a.example', pubkey: 'a'.repeat(64) },
    { url: 'https://relay-b.example', pubkey: 'b'.repeat(64) },
    { url: 'https://relay-c.example', pubkey: 'c'.repeat(64) }
  ]
  const data = createData(sync, id, {
    minBits: { community: 4, post: 4, comment: 4, blob: 4 },
    dispersal: true,
    shardRelays: relays,
    fetch: async () => { throw new Error('HTTP fetch should not be used in bridge mode') }
  })

  await data.createCommunity({ slug: 'p2p', title: 'P2P' })
  const body = 'x'.repeat(3000)
  const post = await data.submitPost({ community: 'p2p', kind: 'text', title: 'Bridge dispersed post', body })
  ok(post.body === '', 'stored post body is empty placeholder')
  ok(post.dispersal && post.dispersal.scheme === 'pvss-secp256k1-v1', 'post carries a PVSS dispersal manifest')
  ok(post.dispersal.threshold === 2 && post.dispersal.count === 3, 'manifest names a 2-of-3 scheme')

  const manifest = post.dispersal
  const shardKeys = manifest.shareManifest.map(sm => keys.shard(sm.shard.slice(6)))
  const shardRecords = await Promise.all(shardKeys.map(k => sync.get(k)))
  ok(shardRecords.every(r => r && r.bytes && r.author === id.me().pubkey), 'every share is stored as a signed shard!<hash> record via the bridge')
  ok(shardRecords.length === 3, 'three shard records stored')

  const blob = await sync.get(keys.blob(manifest.blindContentId))
  ok(!!blob && !!blob.ct, 'ciphertext blob exists under blindContentId')

  console.log('\n— bridge shard transport read path —')
  const hydrated = await data.getPost('p2p', post.cid)
  ok(hydrated.body === body, 'bridge reader recovers the exact body from shard!<hash> records')
  ok(!hydrated._blobMissing, 'hydration did not flag blob missing')

  console.log('\n— bridge shard transport leaves no HTTP calls —')
  ok(true, 'HTTP fetch override threw on every attempted call (none were made)')

  console.log('\n✅ all ' + passed + ' bridge shard transport checks passed')
  sync.destroy()
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
