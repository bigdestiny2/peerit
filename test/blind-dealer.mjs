// blind-dealer.mjs — the peerit BlindShard dealer (js/blind-dealer.js) end-to-end against
// an in-process fleet running the REAL shard-store authorization (test/fixtures/shard-store,
// verbatim from hiverelay): a v2 custody intent per relay, authorizeShardPin →
// resolveCustodyAssignment on every PUT (the exact #159 acceptance rule), k-of-n reconstruct,
// k-1 refused, orphan-intent rejected. Mirrors P2P-Hiverelay's blind-dispersal-fleet-e2e.
//   node test/blind-dealer.mjs
import assert from 'node:assert'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { makeBlindDealer } from '../js/blind-dealer.js'
import { authorizeShardPin } from './fixtures/shard-store/shard-pin.js'
import { shardHash } from './fixtures/shard-store/shard-engine.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

const jsonRes = (value, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => value, text: async () => JSON.stringify(value) })
const bytesRes = (bytes) => { const u8 = new Uint8Array(bytes); return { ok: true, status: 200, arrayBuffer: async () => u8.buffer } }

// One in-process relay: its own shard store + custody-intent registry + the exact
// resolveCustodyAssignment rule authorizeShardPin calls.
function makeRelay (pubkey) {
  const shards = new Map() // hash -> bytes
  const intents = new Map() // intentId -> intent
  const resolveCustodyAssignment = async (intentId, thisRelay) => {
    const intent = intents.get(intentId)
    if (!intent) return null // orphan intent
    const a = (intent.shareAssignments || []).find((x) => x.relayPubkey === thisRelay)
    if (!a) return null // not assigned to this relay
    const m = (intent.shareManifest || []).find((x) => x.shareIndex === a.shareIndex)
    if (!m) return null
    return { shareIndex: a.shareIndex, shard: m.shard }
  }
  return { pubkey, baseUrl: 'http://relay-' + pubkey.slice(0, 8) + '.local', shards, intents, resolveCustodyAssignment }
}

async function main () {
  const N = 4, K = 3
  const relays = Array.from({ length: N }, (_, i) => makeRelay(i.toString(16).padStart(2, '0').repeat(32))) // distinct 64-hex pubkey per relay
  const byBase = new Map(relays.map((r) => [r.baseUrl, r]))

  const fetchShim = async (url, opts = {}) => {
    const u = new URL(String(url))
    const relay = byBase.get(u.origin)
    if (!relay) return jsonRes({ error: 'no such relay' }, 502)
    const p = u.pathname
    const method = (opts.method || 'GET').toUpperCase()
    if (p === '/api/custody/intent' && method === 'POST') {
      const intent = JSON.parse(opts.body)
      relay.intents.set(intent.intentId, intent)
      return jsonRes({ ok: true, intentId: intent.intentId }, 201)
    }
    if (p === '/api/v1/shard' && method === 'POST') {
      const pin = JSON.parse((opts.headers || {})['X-Shard-Pin'])
      const bytes = opts.body
      const hash = shardHash(bytes)
      try {
        await authorizeShardPin(pin, { hash, byteLength: bytes.length, relayPubkey: relay.pubkey, allowedReasons: ['custody'], resolveCustodyAssignment: relay.resolveCustodyAssignment })
      } catch (e) { return jsonRes({ error: e.code || e.message }, 403) }
      relay.shards.set(hash, bytes)
      return jsonRes({ ok: true, shard: 'shard:' + hash, byteLength: bytes.length }, 201)
    }
    if (p.startsWith('/api/v1/shard/') && method === 'GET') {
      const bytes = relay.shards.get(p.slice('/api/v1/shard/'.length).toLowerCase())
      return bytes ? bytesRes(bytes) : jsonRes({ error: 'NOT_HELD' }, 404)
    }
    return jsonRes({ error: 'not found' }, 404)
  }

  // publisher seed
  const seed = b4a.alloc(32); sodium.randombytes_buf(seed)
  const roster = relays.map((r) => ({ baseUrl: r.baseUrl, pubkey: r.pubkey, apiKey: 'admin-' + r.pubkey.slice(0, 6) }))
  const dealer = makeBlindDealer({ seed: b4a.toString(seed, 'hex'), roster, threshold: K, fetchImpl: fetchShim })

  console.log('— disperse across a', N, 'relay fleet, k =', K, '—')
  const d = await dealer.disperse()
  ok(d.intent && d.intent.version === 2 && d.intent.shareScheme === 'pvss-secp256k1-v1', 'built + published a signed v2 custody intent')
  ok(d.refs.length === N, `PUT all ${N} shares (one per relay)`)
  const held = relays.map((r) => r.shards.size)
  ok(held.every((h) => h === 1), `each relay holds exactly ONE share (${held.join(',')}) — no operator has >= k`)
  ok(relays.every((r) => r.intents.has(d.intent.intentId)), 'every relay indexed the custody intent before its PUT authorized')

  console.log('— reconstruct from ANY k, k-1 refused —')
  const anyK = await dealer.recover(d.shareManifest, { readRelays: roster.slice(0, K) })
  ok(anyK.ok && anyK.key === d.key, `recovered the secret from the first ${K} relays (key matches)`)
  const anyKOther = await dealer.recover(d.shareManifest, { readRelays: roster.slice(N - K) })
  ok(anyKOther.ok && anyKOther.key === d.key, `recovered from a DIFFERENT k-subset (relays ${N - K}..${N - 1})`)
  const underK = await dealer.recover(d.shareManifest, { readRelays: roster.slice(0, K - 1) })
  ok(!underK.ok, `k-1 (${K - 1}) relays CANNOT reconstruct — fail-closed`)

  console.log('— orphan-intent + misassignment rejected at the relay —')
  // a custody pin naming an intentId no relay has indexed → rejected
  const relay0 = relays[0]
  const share0hash = d.shareManifest.find((m) => m.shareIndex === 1).shard.slice('shard:'.length)
  const bytes0 = relay0.shards.get(share0hash) || b4a.from('x')
  const orphanPin = { reason: 'custody', hash: share0hash, pinner: dealer.publisherPubkey, custodyIntentId: 'f'.repeat(64), shareIndex: 1, retainUntil: Date.now() + 1000, nonce: 'n1' }
  // sign it validly so ONLY the orphan-intent rule (not the signature) can reject it
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES), sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  const { shardPinSignable } = await import('../js/shard-store-adapter.js')
  sodium.crypto_sign_detached(sig, b4a.from(shardPinSignable(orphanPin), 'utf8'), sk)
  orphanPin.sig = b4a.toString(sig, 'hex')
  const orphanRes = await fetchShim(relay0.baseUrl + '/api/v1/shard', { method: 'POST', headers: { 'X-Shard-Pin': JSON.stringify(orphanPin) }, body: bytes0 })
  ok(!orphanRes.ok, 'a PUT citing an UNKNOWN custody intent is rejected (orphan-intent)')

  console.log(`\n✅ all ${passed} blind-dealer checks passed — peerit's dealer speaks the #159 custody contract`)
  process.exit(0)
}
main().catch((e) => { console.error('❌', e.message, '\n', e.stack); process.exit(1) })
