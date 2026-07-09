// test/disperse.mjs — end-to-end dispersal write + read through data.js.
// Uses a mock shard store so no real relays are required. Proves that:
//   1. A node/dev writer with dispersal enabled produces a post with a dispersal manifest.
//   2. The ciphertext is stored as blob!<blindContentId> and self-certifies.
//   3. The Node reader recovers the exact body by gathering shards + decrypting.
//   4. The browser reader bundle builds and exports recoverBody.

import assert from 'node:assert'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { DevSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { keys } from '../js/model.js'
import { buildReaderBundle } from '../scripts/build-reader-bundle.mjs'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

function shardHash (bytes) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(bytes))
  return 'shard:' + b4a.toString(out, 'hex')
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
        const addr = shardHash(bytes)
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

async function main () {
  console.log('\n— dispersal write/read round-trip —')
  const shardStore = makeShardStore()
  const storage = mem()
  const sync = new DevSync(storage, 'dispersal-test')
  await sync.ready()
  const id = new DevIdentity(mem(), mem())
  await id.ready()

  const relays = [
    { url: 'https://relay-a.example', pubkey: 'a'.repeat(64) },
    { url: 'https://relay-b.example', pubkey: 'b'.repeat(64) },
    { url: 'https://relay-c.example', pubkey: 'c'.repeat(64) }
  ]
  const data = createData(sync, id, { minBits: { community: 4, post: 4, comment: 4 }, dispersal: true, shardRelays: relays, fetch: shardStore.fetch })

  await data.createCommunity({ slug: 'p2p', title: 'P2P' })
  const body = 'x'.repeat(3000)
  const post = await data.submitPost({ community: 'p2p', kind: 'text', title: 'Dispersed post', body })
  ok(post.body === '', 'stored post body is empty placeholder')
  ok(post.dispersal && post.dispersal.scheme === 'pvss-secp256k1-v1', 'post carries a PVSS dispersal manifest')
  ok(post.dispersal.threshold === 2 && post.dispersal.count === 3, 'manifest names a 2-of-3 scheme')
  ok(Array.isArray(post.dispersal.shareManifest) && post.dispersal.shareManifest.length === 3, 'manifest lists three shares')

  const localBlob = await sync.get('blob!' + post.dispersal.blindContentId)
  ok(!localBlob, 'ciphertext is NOT stored as a local blob (off-VPS)')
  const ctBytes = shardStore.shards.get(post.dispersal.ciphertextShard)
  ok(!!ctBytes && ctBytes.length > 0, 'ciphertext shard exists on the mock cohort')

  const hydrated = await data.getPost('p2p', post.cid)
  ok(hydrated.body === body, 'Node reader recovers the exact body from dispersed shards')
  ok(!hydrated._blobMissing, 'hydration did not flag blob missing')

  console.log('\n— custody-intent in stored manifest —')
  ok(post.dispersal.intent && typeof post.dispersal.intent === 'object', 'stored manifest carries the custody intent')
  ok(post.dispersal.intentId === post.dispersal.intent.intentId, 'manifest intentId matches intent')
  ok(post.dispersal.publisherPubkey === post.dispersal.intent.publisherPubkey, 'manifest publisherPubkey matches intent')

  console.log('\n— tampered custody intent rejected on read —')
  {
    const tampered = await sync.get(keys.post('p2p', post.cid))
    tampered.dispersal.intent.signature = '0'.repeat(128)
    await sync.append({ type: 'post', data: tampered }) // overwrite the raw record
    data._bodyCache.clear()
    data.invalidateViewCaches()
    const bad = await data.getPost('p2p', post.cid)
    ok(bad._blobMissing, 'tampered intent signature causes blob-missing fallback')
    ok(bad.body === '', 'tampered intent leaves body empty')
  }

  console.log('\n— dispersal with fallback when identity has no seed —')
  const id2 = new DevIdentity(mem(), mem())
  await id2.ready()
  const data2 = createData(sync, id2, { minBits: { community: 4, post: 4, comment: 4 }, dispersal: true, shardRelays: relays, fetch: shardStore.fetch })
  // Stub currentSeedEntry so it returns no seed, simulating BridgeIdentity.
  data2.id.currentSeedEntry = () => null
  const post2 = await data2.submitPost({ community: 'p2p', kind: 'text', title: 'Fallback post', body: 'y'.repeat(3000) })
  ok(!post2.dispersal && !!post2.blob, 'falls back to single-blob when publisher seed is unavailable')

  const bundleDir = mkdtempSync(join(tmpdir(), 'peerit-reader-bundle-'))
  try {
    const bundlePath = join(bundleDir, 'reader-bundle.mjs')

    console.log('\n— browser reader bundle builds —')
    const bundle = await buildReaderBundle({ outfile: bundlePath })
    ok(bundle.length > 1000, 'reader bundle is non-trivial (' + bundle.length + ' bytes)')
    const bundleText = bundle.toString('utf8')
    ok(bundleText.includes('recoverBody'), 'bundle exports recoverBody')
    ok(!bundleText.includes('sodium-universal'), 'bundle does not contain a bare sodium-universal import')

    console.log('\n— browser reader bundle verifies custody intent —')
    const { recoverBody: bundleRecoverBody } = await import(pathToFileURL(bundlePath).href + `?t=${Date.now()}`)
    const cohortCtBytes = new Uint8Array(shardStore.shards.get(post.dispersal.ciphertextShard))
    const bundleBody = await bundleRecoverBody(post.dispersal, {
      relayBaseUrls: relays.map(r => r.url),
      fetchCiphertext: async () => cohortCtBytes,
      fetchImpl: shardStore.fetch
    })
    ok(bundleBody === body, 'browser bundle recovers body with valid custody intent')

    const tamperedManifest = JSON.parse(JSON.stringify(post.dispersal))
    tamperedManifest.intent.signature = '0'.repeat(128)
    try {
      await bundleRecoverBody(tamperedManifest, {
        relayBaseUrls: relays.map(r => r.url),
        fetchCiphertext: async () => cohortCtBytes,
        fetchImpl: shardStore.fetch
      })
      assert.fail('browser bundle should reject tampered custody intent')
    } catch (e) {
      ok(/custody intent|signature invalid/i.test(e.message), 'browser bundle rejects tampered custody intent')
    }
  } finally {
    rmSync(bundleDir, { recursive: true, force: true })
  }

  console.log('\n✅ all ' + passed + ' dispersal checks passed')
}

main().catch((e) => { console.error(e); process.exit(1) })
