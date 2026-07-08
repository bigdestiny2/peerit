// shard-store-adapter.mjs — validate peerit's client shard adapter
// (js/shard-store-adapter.js) against the REAL shipped HiveRelay shard-store
// contract, not a hand-rolled fake. The vendored server files
// (test/fixtures/shard-store/{http-adapter,shard-pin}.js, verbatim from hiverelay
// origin/main 26c02eb) run the ACTUAL request parsing + pin authorization; an
// in-process fetch shim wires the adapter's HTTP calls to handleShardHttp over a
// per-relay in-memory store that addresses by REAL blake2b-256.
//
// Proves: (1) the adapter's replicated pin envelope is BYTE-IDENTICAL to the real
// shardPinSignable; (2) a pin signed with peerit's own Ed25519 (crypto.js) is
// accepted by the real verifyShardPin (cross-library interop); (3) putShard speaks
// the exact wire (POST raw octet + X-Shard-Pin -> 201 shard:<hash>), self-verify
// rejects a mis-addressed shard, quota rejection surfaces; (4) getShard maps
// 200->bytes / 404->null; (5) full disperseBody->reassembleBody round-trip + K-of-N
// tolerance through the adapter with blake2b addressing.
//
// This validates CLIENT LOGIC + WIRE CONFORMANCE only. It does NOT test blindness
// (which needs >=3 INDEPENDENT operators — not met; see docs/BLINDSHARD-DESIGN.md §5)
// and it is NOT a live-store test (0.22.0 is source-only; the HTTP adapter is
// unmounted on the live fleet). Run: node test/shard-store-adapter.mjs

import assert from 'node:assert'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { ready as cryptoReady, isSecure, genKeyPair, sign as edSign } from '../js/crypto.js'
import {
  createShardStoreAdapter, buildPaymentPin, makeBlake2b256Hex,
  shardPinSignable as mySignable, SHARD_PIN_DOMAIN
} from '../js/shard-store-adapter.js'
import { disperseBody, reassembleBody } from '../js/blob-disperse.js'
// REAL server code (vendored verbatim) + the pure-function engine stub:
import { resolveShardRoute, handleShardHttp, createShardHttpState } from './fixtures/shard-store/http-adapter.js'
import { shardPinSignable as realSignable, verifyShardPin, shardPinRef, SHARD_PIN_DOMAIN as REAL_DOMAIN } from './fixtures/shard-store/shard-pin.js'
import { authorizeShardPin } from './fixtures/shard-store/shard-pin.js'
import { shardHash, shardError, DEFAULT_MAX_SHARD_BYTES } from './fixtures/shard-store/shard-engine.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, m, re) { try { await fn() } catch (e) { if (re && !re.test(e.message)) return assert.fail('threw wrong reason: ' + e.message + ' (want ' + re + ') for: ' + m); ok(true, m); return } assert.fail('expected throw: ' + m) }

// --- a minimal ShardStoreService (put/get/has) backed by a Map, running the REAL
//     authorizeShardPin + shardHash. One instance PER relay endpoint. ------------
function makeService ({ checkPaymentQuota = () => true, allowedReasons = ['custody', 'payment'], relayPubkey = 'r'.repeat(64) } = {}) {
  const store = new Map() // hash -> { bytes, pins: Map(pinRef->pin) }
  return {
    maxShardBytes: DEFAULT_MAX_SHARD_BYTES,
    async put ({ ciphertext, pin }) {
      const bytes = b4a.from(ciphertext, 'base64')
      const hash = shardHash(bytes)
      await authorizeShardPin(pin, { hash, byteLength: bytes.length, relayPubkey, allowedReasons, checkPaymentQuota })
      let rec = store.get(hash); const deduped = !!rec
      if (!rec) { rec = { bytes, pins: new Map() }; store.set(hash, rec) }
      rec.pins.set(shardPinRef(pin), pin)
      return { ok: true, shard: 'shard:' + hash, byteLength: bytes.length, deduped, pinRef: shardPinRef(pin), refs: rec.pins.size, retainUntil: pin.retainUntil }
    },
    async get ({ hash }) {
      const rec = store.get(hash)
      if (!rec) throw shardError('NOT_HELD', 'shard not held')
      return { ok: true, shard: 'shard:' + hash, byteLength: rec.bytes.length, encoding: 'base64', ciphertext: b4a.toString(rec.bytes, 'base64') }
    },
    async has ({ hash }) { const rec = store.get(hash); return rec ? { present: true, byteLength: rec.bytes.length } : { present: false } },
    _drop (hash) { store.delete(hash) },
    _corrupt (hash) { const rec = store.get(hash); if (rec) rec.bytes = b4a.from([1, 2, 3, 4]) },
    _count () { return store.size }
  }
}

// --- in-process fetch that routes to the REAL handleShardHttp per endpoint --------
function makeFleetFetch (byUrl) {
  const rateState = createShardHttpState()
  return async function fetchShim (url, init = {}) {
    const u = new URL(url)
    const service = byUrl.get(u.origin) || byUrl.get(u.protocol + '//' + u.host)
    const method = (init.method || 'GET').toUpperCase()
    const route = resolveShardRoute(method, u.pathname)
    const headers = {}
    for (const [k, v] of Object.entries(init.headers || {})) headers[k.toLowerCase()] = v
    const bodyBytes = init.body != null ? b4a.from(init.body) : b4a.alloc(0)
    const res = fakeRes()
    if (!service) { res.writeHead(502, {}); res.end(b4a.from(JSON.stringify({ error: 'NO_SERVICE' }))); return res.response() }
    if (!route) { res.writeHead(404, {}); res.end(b4a.from(JSON.stringify({ error: 'not found' }))); return res.response() }
    await handleShardHttp(service, route, fakeReq(method, u.pathname + u.search, headers, bodyBytes), res, { url: u, state: rateState })
    return res.response()
  }
}
function fakeReq (method, url, headers, bodyBytes) {
  const L = {}
  const req = { method, url, headers, socket: { remoteAddress: '127.0.0.1' }, destroy () {}, on (ev, cb) { L[ev] = cb; return req } }
  setTimeout(() => { if (bodyBytes && bodyBytes.length && L.data) L.data(bodyBytes); if (L.end) L.end() }, 0)
  return req
}
function fakeRes () {
  let status = 200; let headers = {}; const chunks = []
  return {
    writeHead (s, h) { status = s; if (h) headers = h; return this },
    end (data) { if (data != null) chunks.push(b4a.from(data)) },
    response () {
      const body = b4a.concat(chunks)
      const hmap = {}; for (const k of Object.keys(headers)) hmap[k.toLowerCase()] = headers[k]
      return {
        status,
        headers: { get: (k) => (k.toLowerCase() in hmap ? hmap[k.toLowerCase()] : null) },
        async json () { return JSON.parse(b4a.toString(body, 'utf8')) },
        async text () { return b4a.toString(body, 'utf8') },
        async arrayBuffer () { return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) }
      }
    }
  }
}

const K = 6; const N = 9
const BODY = 'BlindShard dispersed body via the real shard-store contract. '.repeat(400) + 'end' // ~24 KB -> erasure

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')
  const blake2b256Hex = makeBlake2b256Hex(sodium, b4a)

  // an author identity to sign pins with
  const { seedHex, pubHex } = await genKeyPair()
  const signRaw = (msg) => edSign(seedHex, msg)

  // ---- 1. pin envelope is byte-identical to the REAL server serialization ----
  console.log('\n— pin envelope conformance —')
  ok(SHARD_PIN_DOMAIN === REAL_DOMAIN, 'adapter SHARD_PIN_DOMAIN matches the shipped constant')
  const samplePin = { reason: 'payment', hash: 'a'.repeat(64), pinner: 'b'.repeat(64), custodyIntentId: null, shareIndex: null, retainUntil: 1234, nonce: 'cc' }
  ok(mySignable(samplePin) === 'hiverelay.shard-pin.v1\0{"custodyIntentId":null,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"cc","pinner":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","reason":"payment","retainUntil":1234,"shareIndex":null}',
    'stable() serialization matches the hand-computed golden (sorted keys, NUL sep)')
  ok(b4a.from(mySignable(samplePin), 'utf8').equals(realSignable(samplePin)), "adapter's replicated signable is BYTE-IDENTICAL to the vendored real shardPinSignable")

  // ---- 2. a peerit-signed pin is accepted by the REAL verifyShardPin ----
  console.log('\n— cross-library Ed25519 interop (peerit sign -> sodium verify) —')
  const realHash = await blake2b256Hex(b4a.from('some ciphertext bytes'))
  const pin = await buildPaymentPin({ hash: realHash, pinner: pubHex, retainUntil: 999999, nonce: 'ab'.repeat(8), signRaw })
  ok(verifyShardPin(pin), 'REAL verifyShardPin accepts a pin signed by peerit crypto.js (raw Ed25519 interops with sodium)')
  ok(!verifyShardPin({ ...pin, hash: 'f'.repeat(64) }), 'tampering a signed field (hash) breaks the real verify — the cross-check has teeth')
  ok(!verifyShardPin({ ...pin, sig: pin.sig.replace(/^../, '00') }), 'a corrupted signature is rejected by the real verify')

  // ---- 3/4. putShard/getShard over the REAL handleShardHttp ----
  console.log('\n— putShard / getShard wire conformance —')
  const relays = ['aa', 'bb', 'cc', 'dd', 'ee'].map((c, i) => ({ pub: c.repeat(32), url: `https://relay${i}.example` }))
  const services = new Map(relays.map(r => [r.url, makeService({ relayPubkey: r.pub })]))
  const byUrl = new Map(relays.map(r => [new URL(r.url).origin, services.get(r.url)]))
  const fetchImpl = makeFleetFetch(byUrl)
  const adapter = createShardStoreAdapter({ roster: relays, pinner: pubHex, signRaw, fetchImpl, token: 'test-token' })

  const bytes = b4a.from('an opaque shard payload — ' + 'x'.repeat(200))
  const sid = await blake2b256Hex(bytes)
  const receipt = await adapter.putShard(relays[0].pub, sid, bytes)
  ok(receipt.ok && receipt.shard === 'shard:' + sid, 'putShard -> 201 with shard:<blake2b(bytes)> (server self-verified the address)')
  ok(receipt.pinRef && Number.isInteger(receipt.refs), 'receipt carries pinRef + refs from the real service')
  ok(services.get(relays[0].url)._count() === 1, 'the shard is actually held by the targeted relay')

  const got = await adapter.getShard(relays[0].pub, sid)
  ok(got && b4a.from(got).equals(bytes), 'getShard -> the exact stored bytes')
  ok(await adapter.getShard(relays[1].pub, sid) === null, 'getShard on a relay that never received it -> null (404)')
  ok(await adapter.getShard(relays[0].pub, 'd'.repeat(64)) === null, 'getShard of an unknown hash -> null')

  // self-verify: a mis-addressed shard (claimed id != blake2b(bytes)) is rejected
  await throwsAsync(() => adapter.putShard(relays[0].pub, 'e'.repeat(64), bytes), 'putShard with a wrong shardId is rejected by the server self-verify (403 UNAUTHORIZED_PIN)', /403|UNAUTHORIZED_PIN/)

  // quota rejection surfaces as a throw
  const paywalled = new Map([[new URL(relays[0].url).origin, makeService({ checkPaymentQuota: () => false })]])
  const payAdapter = createShardStoreAdapter({ roster: [relays[0]], pinner: pubHex, signRaw, fetchImpl: makeFleetFetch(paywalled) })
  await throwsAsync(() => payAdapter.putShard(relays[0].pub, sid, bytes), 'putShard surfaces QUOTA_EXHAUSTED (429) as a throw', /429|QUOTA_EXHAUSTED/)

  // ---- 5. full disperse -> reassemble round-trip + K-of-N through the adapter ----
  console.log('\n— disperseBody -> reassembleBody round-trip (blake2b addressing) —')
  const fresh = new Map(relays.map(r => [r.url, makeService({ relayPubkey: r.pub })]))
  const freshByUrl = new Map(relays.map(r => [new URL(r.url).origin, fresh.get(r.url)]))
  const rtAdapter = createShardStoreAdapter({ roster: relays, pinner: pubHex, signRaw, fetchImpl: makeFleetFetch(freshByUrl) })
  const rosterPubs = relays.map(r => r.pub)

  const { manifest } = await disperseBody(BODY, { backend: rtAdapter, roster: rosterPubs, k: K, n: N, replicas: 1, hashShard: blake2b256Hex })
  ok(manifest.shardIds.length === N && manifest.shardIds.every(id => /^[0-9a-f]{64}$/.test(id)), 'disperse produced N blake2b-addressed shardIds')
  const heldTotal = [...fresh.values()].reduce((a, s) => a + s._count(), 0)
  ok(heldTotal === N, `all N shards are stored across the fleet (held ${heldTotal})`)
  ok([...fresh.values()].every(s => s._count() < K), 'no single relay holds >= K shards (place() <K cap held on the wire)')

  ok(await reassembleBody({ manifest, backend: rtAdapter, roster: rosterPubs, hashShard: blake2b256Hex }) === BODY, 'gather -> content-address gate -> RS-decode -> unbox reconstructs the exact body')

  // a lying relay: one shard's stored bytes are corrupted (blake2b(bytes) != shardId).
  // The content-address gate (blob-disperse.js:118) must REJECT it and route around via
  // K-of-N — proving the gate FIRES on the real adapter path (delete the gate and this
  // reconstruction returns garbage / throws). Complements test/blob-disperse.mjs's tamper.
  for (const s of fresh.values()) s._corrupt(manifest.shardIds[0])
  ok(await reassembleBody({ manifest, backend: rtAdapter, roster: rosterPubs, hashShard: blake2b256Hex }) === BODY, 'a forged/corrupted shard fails the content-address gate and is routed around (gate is load-bearing on the adapter path)')

  // K-of-N: lose N-K shards entirely, still reconstruct; one more -> fail
  const dropAll = (hash) => { for (const s of fresh.values()) s._drop(hash) }
  for (let i = 0; i < N - K; i++) dropAll(manifest.shardIds[i])
  ok(await reassembleBody({ manifest, backend: rtAdapter, roster: rosterPubs, hashShard: blake2b256Hex }) === BODY, `survives losing N-K (${N - K}) shards`)
  dropAll(manifest.shardIds[N - K])
  await throwsAsync(() => reassembleBody({ manifest, backend: rtAdapter, roster: rosterPubs, hashShard: blake2b256Hex }), 'fails once fewer than K shards remain')

  // ---- 6. a WRONG hashShard (SHA-256 default) cannot address the blake2b store ----
  console.log('\n— addressing must be blake2b (SHA-256 default fails against the store) —')
  const wrong = new Map(relays.map(r => [r.url, makeService({ relayPubkey: r.pub })]))
  const wrongByUrl = new Map(relays.map(r => [new URL(r.url).origin, wrong.get(r.url)]))
  const wrongAdapter = createShardStoreAdapter({ roster: relays, pinner: pubHex, signRaw, fetchImpl: makeFleetFetch(wrongByUrl) })
  await throwsAsync(() => disperseBody(BODY, { backend: wrongAdapter, roster: rosterPubs, k: K, n: N, replicas: 1 /* hashShard defaults to SHA-256 */ }),
    'dispersing with the default SHA-256 hashShard is rejected by the blake2b store (proves blake2b injection is load-bearing)', /403|UNAUTHORIZED_PIN/)

  console.log(`\n✅ all ${passed} shard-store-adapter checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
