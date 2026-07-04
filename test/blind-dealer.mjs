// test/blind-dealer.mjs — unit test for js/blind-dealer.mjs.
//
// Mocks the HiveRelay v0.24.0 shard-store surface in-memory so the test runs
// without a live relay fleet, while exercising the exact PVSS + custody-intent
// + custody-pin wire shapes. Proves: encrypt → disperse → publish → PUT →
// recover round-trips, k-of-n threshold holds, and k-1 fails.

import assert from 'node:assert'
import crypto from 'node:crypto'
import sodium from 'sodium-universal'
import { shardAddressOf } from '../js/vendor/blind-shards/blind-shards.js'
import {
  disperseBody, recoverBody, recoverKey, makeHiverelayKeypair, verifyCustodyIntent,
  encryptBody, decryptBody, normalizeRoster
} from '../js/blind-dealer.mjs'
import { genKeyPair, ready as cryptoReady } from '../js/crypto.js'

function blake2b256Hex (buf) {
  return shardAddressOf(buf).slice('shard:'.length)
}

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

// Build a deterministic mock relay fleet.
function makeMockFleet (n) {
  const intents = new Map()   // relay url -> intent
  const shards = new Map()    // relay url -> Map('shard:<hash>' -> bytes)
  const relays = []
  for (let i = 0; i < n; i++) {
    const seed = crypto.createHash('sha256').update('mock-relay-' + i).digest()
    const kp = crypto.generateKeyPairSync('ed25519', { privateKeyEncoding: { type: 'pkcs8', format: 'der' }, publicKeyEncoding: { type: 'spki', format: 'der' } })
    const pub = new Uint8Array(kp.publicKey).slice(-32)
    relays.push({
      pubkey: Buffer.from(pub).toString('hex'),
      url: 'https://mock-relay-' + i + '.test',
      apiKey: 'key-' + i
    })
  }

  const baseToPubkey = new Map()
  for (const r of relays) baseToPubkey.set(r.url, r.pubkey.toLowerCase())

  async function mockFetch (url, opts = {}) {
    const u = new URL(url)
    const base = u.origin
    const path = u.pathname
    if (path === '/api/custody/intent' && opts.method === 'POST') {
      const intent = JSON.parse(opts.body)
      intents.set(base, intent)
      return { ok: true, status: 201, text: async () => 'ok' }
    }
    if (path === '/api/v1/shard' && opts.method === 'POST') {
      const buf = Buffer.from(opts.body)
      const pin = JSON.parse(opts.headers['X-Shard-Pin'])
      const hash = pin.hash.toLowerCase()
      const addr = 'shard:' + hash
      const computed = blake2b256Hex(buf)
      if (computed !== hash) {
        return { ok: false, status: 400, text: async () => 'hash mismatch' }
      }
      // Verify custody pin against the published intent for this relay.
      const intent = intents.get(base)
      if (!intent) return { ok: false, status: 401, text: async () => 'orphan intent' }
      const relayPub = baseToPubkey.get(base)
      const assign = intent.shareAssignments.find(a => a.relayPubkey.toLowerCase() === relayPub)
      if (!assign || assign.shareIndex !== pin.shareIndex) {
        return { ok: false, status: 401, text: async () => 'bad assignment' }
      }
      const manifestEntry = intent.shareManifest.find(m => m.shareIndex === pin.shareIndex)
      if (!manifestEntry || ('shard:' + manifestEntry.shard.slice('shard:'.length).toLowerCase()) !== addr) {
        return { ok: false, status: 401, text: async () => 'manifest mismatch' }
      }
      if (!shards.has(base)) shards.set(base, new Map())
      shards.get(base).set(addr, new Uint8Array(buf))
      return {
        ok: true, status: 201,
        json: async () => ({ ok: true, shard: addr, byteLength: buf.length })
      }
    }
    if (path.startsWith('/api/v1/shard/') && (!opts.method || opts.method === 'GET')) {
      const hash = path.slice('/api/v1/shard/'.length)
      const addr = 'shard:' + hash
      const store = shards.get(base)
      const bytes = store ? store.get(addr) : null
      if (!bytes) return { ok: false, status: 404, text: async () => 'not held' }
      return {
        ok: true, status: 200,
        arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
      }
    }
    return { ok: false, status: 404, text: async () => 'not found' }
  }

  return { relays, shards, intents, fetch: mockFetch }
}

async function main () {
  await cryptoReady()
  const N = 4
  const K = 3
  const fleet = makeMockFleet(N)
  const cfg = {
    threshold: K,
    retainMs: 30 * 24 * 60 * 60 * 1000,
    relays: fleet.relays
  }

  console.log('\n— encrypt/decrypt sanity —')
  {
    const { ciphertext, iv, keyHex } = await encryptBody('hello pvss')
    ok(ciphertext.length > 0, 'ciphertext produced')
    ok(/^[0-9a-f]{64}$/i.test(keyHex), 'key is 64-hex')
    const back = await decryptBody(ciphertext, iv, keyHex)
    ok(back === 'hello pvss', 'decrypt recovers plaintext')
  }

  console.log('\n— full disperse → recover round-trip —')
  const body = 'The quick brown fox jumps over the lazy dog.'
  const { seedHex: publisherSeed, pubHex: publisherPub } = await genKeyPair()

  const { ciphertext, manifest, intent, placed } = await disperseBody(body, {
    threshold: K,
    relays: cfg.relays,
    publisher: makeHiverelayKeypair({ seedHex: publisherSeed, pubHex: publisherPub }),
    retainMs: cfg.retainMs,
    fetch: fleet.fetch
  })

  ok(manifest.threshold === K, 'manifest threshold matches K')
  ok(manifest.count === N, 'manifest count matches N')
  ok(manifest.scheme === 'pvss-secp256k1-v1', 'manifest scheme is pvss-secp256k1-v1')
  ok(manifest.version === 2, 'manifest version is 2')
  ok(manifest.shareManifest.length === N, 'manifest has N shard entries')
  ok(placed.length === N, 'all N shards placed')
  ok(intent.version === 2, 'custody intent is v2')
  ok(intent.shareAssignments.length === N, 'intent has N share assignments')
  ok(intent.shareManifest.length === N, 'intent has N share manifest entries')

  // Recover using the first K relays.
  const recovered = await recoverBody(manifest, {
    relayBaseUrls: cfg.relays.slice(0, K).map(r => r.url),
    fetchCiphertext: async () => ciphertext,
    fetchImpl: fleet.fetch
  })
  ok(recovered === body, 'recoverBody reproduces the exact body')

  console.log('\n— threshold enforcement: k-1 fails —')
  try {
    await recoverBody(manifest, {
      relayBaseUrls: cfg.relays.slice(0, K - 1).map(r => r.url),
      fetchCiphertext: async () => ciphertext,
      fetchImpl: fleet.fetch
    })
    assert.fail('k-1 recovery should have failed')
  } catch (e) {
    ok(/recover failed|INSUFFICIENT_SHARDS/i.test(e.message), 'k-1 relays cannot reconstruct')
  }

  console.log('\n— custody-intent verification —')
  ok(verifyCustodyIntent(manifest), 'valid custody intent verifies')

  {
    const missing = { ...manifest }
    delete missing.intent
    try {
      await recoverKey(missing, cfg.relays.slice(0, K).map(r => r.url), fleet.fetch)
      assert.fail('missing intent should be rejected')
    } catch (e) {
      ok(/custody intent missing/i.test(e.message), 'manifest without intent is rejected')
    }
  }

  {
    const tamperedSig = { ...manifest, intent: { ...manifest.intent, signature: '0'.repeat(128) } }
    try {
      await recoverKey(tamperedSig, cfg.relays.slice(0, K).map(r => r.url), fleet.fetch)
      assert.fail('tampered intent signature should be rejected')
    } catch (e) {
      ok(/signature invalid/i.test(e.message), 'tampered intent signature is rejected')
    }
  }

  {
    const mismatched = { ...manifest, blindContentId: '0'.repeat(64) }
    try {
      await recoverKey(mismatched, cfg.relays.slice(0, K).map(r => r.url), fleet.fetch)
      assert.fail('mismatched intent binding should be rejected')
    } catch (e) {
      ok(/blindContentId mismatch/i.test(e.message), 'mismatched manifest blindContentId is rejected')
    }
  }

  console.log('\n— orphan-intent rejection —')
  {
    // The mockFetch rejects POST /api/v1/shard when no intent was published to
    // that relay's base URL. disperseBody publishes before PUTting, so a normal
    // flow never orphans. We verify the mock itself rejects an orphan by
    // sending bytes whose hash matches the pin so we reach the intent check.
    const orphanFleet = makeMockFleet(N)
    ok(!orphanFleet.intents.has(orphanFleet.relays[0].url), 'fresh mock fleet has no published intent')
    const orphanBytes = Buffer.from('orphan')
    const orphanHash = blake2b256Hex(orphanBytes)
    const orphanRes = await orphanFleet.fetch(orphanFleet.relays[0].url + '/api/v1/shard', {
      method: 'POST',
      headers: { 'X-Shard-Pin': JSON.stringify({ hash: orphanHash }) },
      body: orphanBytes
    })
    ok(!orphanRes.ok && orphanRes.status === 401, 'orphan PUT is rejected with 401')
  }

  console.log('\n— roster validation —')
  assert.throws(() => normalizeRoster({ threshold: 0, relays: cfg.relays }), /threshold/)
  assert.throws(() => normalizeRoster({ threshold: 2, relays: [{ pubkey: 'bad', url: 'https://x' }] }), /pubkey|relay/)
  ok(true, 'roster validation rejects bad thresholds and pubkeys')

  console.log(`\n✅ all ${passed} blind-dealer checks passed`)
}

main().catch((e) => { console.error('\n❌ blind-dealer test FAILED:', e.message, '\n', e.stack); process.exit(1) })
