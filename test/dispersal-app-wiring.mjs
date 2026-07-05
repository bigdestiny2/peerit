// dispersal-app-wiring.mjs — verify app.js/runtime.js/data.js wiring for BlindShard.
// Covers the runtime-config detection path and the fallback behaviors declared in
// the m1-dispersal-app-wiring feature.

import assert from 'node:assert'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { DevSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { resolveRuntime, fetchShardRoster } from '../js/runtime.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

function doc (metas = {}) {
  return {
    querySelector: (sel) => {
      const m = sel.match(/meta\[name="([^"]+)"\]/)
      const name = m && m[1]
      return name && Object.prototype.hasOwnProperty.call(metas, name) ? { getAttribute: () => metas[name] } : null
    }
  }
}

function makeShardStore () {
  const shards = new Map()
  return {
    shards,
    fetch: async (url, init = {}) => {
      const u = String(url)
      if (u.endsWith('/api/custody/intent')) {
        return { ok: true, status: 200, text: async () => '', json: async () => ({ ok: true }) }
      }
      if (u.includes('/api/v1/shard') && init.method === 'POST') {
        const bytes = new Uint8Array(await init.body)
        const out = b4a.alloc(32)
        sodium.crypto_generichash(out, b4a.from(bytes))
        const addr = 'shard:' + b4a.toString(out, 'hex')
        shards.set(addr, bytes)
        return { ok: true, status: 200, text: async () => '', json: async () => ({ shard: addr }) }
      }
      const getMatch = u.match(/\/api\/v1\/shard\/([0-9a-f]{64})$/i)
      if (getMatch) {
        const hash = 'shard:' + getMatch[1].toLowerCase()
        const bytes = shards.get(hash)
        if (!bytes) return { ok: false, status: 404, text: async () => 'not found', json: async () => ({ error: 'not found' }) }
        return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) }
      }
      throw new Error('unexpected fetch: ' + u)
    }
  }
}

async function setup (opts = {}) {
  const sync = new DevSync(mem(), 'wiring-test')
  await sync.ready()
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  return { sync, id }
}

async function main () {
  console.log('\n— runtime config detection wires shard cohort —')
  const rt = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-shard-roster': 'config/shard-roster.json' }) })
  ok(rt.mode === 'dev' && rt.shardCohort && rt.shardCohort.rosterUrl === 'config/shard-roster.json',
    'resolveRuntime exposes shard cohort config from meta tag')

  const fetched = await fetchShardRoster({ url: 'config/shard-roster.json', fetch: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ threshold: 2, relays: ['http://127.0.0.1:8801', 'http://127.0.0.1:8802', 'http://127.0.0.1:8803'] }) }) })
  ok(fetched && fetched.threshold === 2 && fetched.relays.length === 3,
    'fetchShardRoster normalizes a 2-of-3 local cohort')

  console.log('\n— createData receives dispersal opts when cohort is available —')
  const { sync: sync1, id: id1 } = await setup()
  const data1 = createData(sync1, id1, { dispersal: true, shardRelays: ['http://127.0.0.1:8801', 'http://127.0.0.1:8802'], fetch: makeShardStore().fetch })
  ok(data1.dispersal === true && data1.shardRelays.length === 2, 'createData enables dispersal and stores shardRelays')

  console.log('\n— dispersed post carries PVSS manifest and stores ciphertext blob —')
  const shardStore = makeShardStore()
  const { sync: sync2, id: id2 } = await setup()
  const data2 = createData(sync2, id2, {
    minBits: { community: 4, post: 4, comment: 4, blob: 4 },
    dispersal: true,
    shardRelays: [
      { url: 'https://relay-a.example', pubkey: 'a'.repeat(64) },
      { url: 'https://relay-b.example', pubkey: 'b'.repeat(64) },
      { url: 'https://relay-c.example', pubkey: 'c'.repeat(64) }
    ],
    fetch: shardStore.fetch
  })
  await data2.createCommunity({ slug: 'p2p', title: 'P2P' })
  const body = 'x'.repeat(3000)
  const post = await data2.submitPost({ community: 'p2p', kind: 'text', title: 'Wired post', body })
  ok(post.body === '' && !!post.dispersal && post.dispersal.scheme === 'pvss-secp256k1-v1',
    'dispersed post carries a PVSS manifest and an empty body placeholder')
  ok(!!post.dispersal.blindContentId, 'manifest names a blindContentId')

  const localBlob = await sync2.get('blob!' + post.dispersal.blindContentId)
  ok(!localBlob, 'ciphertext is NOT stored as a local blob (off-VPS)')
  const ctBytes = shardStore.shards.get(post.dispersal.ciphertextShard)
  ok(!!ctBytes && ctBytes.length > 0, 'ciphertext shard exists on the mock cohort')

  const hydrated = await data2.getPost('p2p', post.cid)
  ok(hydrated.body === body && !hydrated._blobMissing, 'reader recovers the exact body from dispersed shards')

  console.log('\n— graceful fallback when shard relays are unavailable —')
  const { sync: sync3, id: id3 } = await setup()
  const data3 = createData(sync3, id3, {
    minBits: { community: 4, post: 4, comment: 4, blob: 4 },
    dispersal: true,
    shardRelays: [
      { url: 'https://relay-a.example', pubkey: 'a'.repeat(64) },
      { url: 'https://relay-b.example', pubkey: 'b'.repeat(64) },
      { url: 'https://relay-c.example', pubkey: 'c'.repeat(64) }
    ],
    fetch: async () => { throw new Error('relay down') }
  })
  await data3.createCommunity({ slug: 'p2p', title: 'P2P' })
  const fallbackBody = 'y'.repeat(3000)
  const fallbackPost = await data3.submitPost({ community: 'p2p', kind: 'text', title: 'Fallback post', body: fallbackBody })
  ok(!fallbackPost.dispersal && !!fallbackPost.blob, 'unavailable shard relays fall back to single v2 blob manifest')

  const fallbackHydrated = await data3.getPost('p2p', fallbackPost.cid)
  ok(fallbackHydrated.body === fallbackBody && !fallbackHydrated._blobMissing, 'fallback blob body is recovered')

  console.log('\n✅ all ' + passed + ' dispersal-app-wiring checks passed')
}

main().catch((e) => { console.error(e); process.exit(1) })
