// blob-disperse.mjs — BlindShard Phase 3 dispersal glue (js/blob-disperse.js),
// dependency-injected against a FAKE shard blob surface modeling the HiveRelay
// handover (docs/BLINDSHARD-BLOB-SURFACE-HANDOVER.md): server-side self-verify on
// PUT, content-addressed GET. Proves: box→erasure→disperse→gather→decode→unbox
// round-trips; K-of-N tolerance; a tampered shard is rejected and routed around;
// and no single relay holds >=K shards (blindness invariant). This validates the
// CLIENT LOGIC only — not a live HiveRelay blob surface (which is net-new).
//   node test/blob-disperse.mjs

import assert from 'node:assert'
import { disperseBody, reassembleBody, shouldDisperse } from '../js/blob-disperse.js'
import { hashBytes, ready as cryptoReady, isSecure } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, m) { try { await fn() } catch { ok(true, m); return } assert.fail('expected throw: ' + m) }

// A fake fleet: one opaque content-addressed store per relay. putShard recomputes
// SHA-256(bytes) and rejects a wrong address (the relay's only content check, §1.2).
function fakeFleet (hashFn = hashBytes) {
  const store = new Map() // `${relayPub}\x00${shardId}` -> Uint8Array
  const K = (relayPub, sid) => relayPub + '\x00' + sid
  return {
    async putShard (relayPub, sid, bytes) {
      const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
      if ((await hashFn(u8)).toLowerCase() !== String(sid).toLowerCase()) throw new Error('shard address mismatch (server self-verify)')
      store.set(K(relayPub, sid), u8.slice())
      return { blindContentId: sid, relayPub, anchored: true }
    },
    async getShard (relayPub, sid) { return store.get(K(relayPub, sid)) || null },
    // test helpers
    heldBy (relayPub) { let n = 0; for (const k of store.keys()) if (k.startsWith(relayPub + '\x00')) n++; return n },
    dropShard (sid) { for (const k of [...store.keys()]) if (k.endsWith('\x00' + sid)) store.delete(k) },
    corruptShard (sid) { for (const k of [...store.keys()]) if (k.endsWith('\x00' + sid)) store.set(k, new Uint8Array([1, 2, 3, 4])) }
  }
}

const roster = ['a', 'b', 'c', 'd', 'e'].map((c) => c.repeat(64)) // 5 independent relays
const K = 6, N = 9, REPLICAS = 2
const BODY = 'BlindShard dispersed body. '.repeat(800) + 'end' // ~21 KB → erasure

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend available')
  ok(shouldDisperse(BODY) && !shouldDisperse('tiny'), 'shouldDisperse gates on the erasure size threshold')

  // ---- disperse ----
  console.log('\n— disperse —')
  const backend = fakeFleet()
  const { manifest, receipts, assignment } = await disperseBody(BODY, { backend, roster, k: K, n: N, replicas: REPLICAS })
  ok(manifest.k === K && manifest.n === N && manifest.replicas === REPLICAS, 'manifest carries k/n/replicas')
  ok(manifest.shardIds.length === N && /^[0-9a-f]{64}$/.test(manifest.blobId) && /^[0-9a-f]{64}$/.test(manifest.contentKey), 'manifest has N shardIds + blobId + contentKey')
  ok(receipts.length === N * REPLICAS, 'a placement receipt per shard-replica (N*replicas)')

  // blindness invariant: no relay holds >= K shards (can't reconstruct alone), and place() honored < K
  const held = roster.map((r) => backend.heldBy(r))
  ok(held.every((n) => n < K), `no single relay holds >= K shards (max held ${Math.max(...held)} < ${K})`)
  ok(held.reduce((a, b) => a + b, 0) === N * REPLICAS, 'total placements = N*replicas across the fleet')

  // ---- full round-trip ----
  console.log('\n— reassemble —')
  ok(await reassembleBody({ manifest, backend, roster }) === BODY, 'gather+decode+unbox reconstructs the exact body')

  // ---- K-of-N tolerance ----
  console.log('\n— K-of-N tolerance —')
  const b2 = fakeFleet()
  const r2 = await disperseBody(BODY, { backend: b2, roster, k: K, n: N, replicas: REPLICAS })
  for (let i = 0; i < N - K; i++) b2.dropShard(r2.manifest.shardIds[i]) // lose exactly N-K shards entirely
  ok(await reassembleBody({ manifest: r2.manifest, backend: b2, roster }) === BODY, `survives losing N-K (${N - K}) shards — any K reconstruct`)
  b2.dropShard(r2.manifest.shardIds[N - K]) // one more → only K-1 left
  await throwsAsync(() => reassembleBody({ manifest: r2.manifest, backend: b2, roster }), 'fails when fewer than K shards remain')

  // ---- tampered shard: content-address check rejects it, routes around ----
  console.log('\n— tamper resistance —')
  const b3 = fakeFleet()
  const r3 = await disperseBody(BODY, { backend: b3, roster, k: K, n: N, replicas: REPLICAS })
  b3.corruptShard(r3.manifest.shardIds[0]) // corrupt every copy of ONE shard
  let tampered = null
  for (const rp of roster) { const b = await b3.getShard(rp, r3.manifest.shardIds[0]); if (b) { tampered = b; break } }
  ok(tampered && (await hashBytes(tampered)).toLowerCase() !== r3.manifest.shardIds[0], 'a corrupted shard fails its content-address check')
  ok(await reassembleBody({ manifest: r3.manifest, backend: b3, roster }) === BODY, 'one fully-corrupted shard is skipped; the other N-1 still reconstruct')

  // ---- server-side self-verification on PUT ----
  console.log('\n— server self-verify on PUT —')
  await throwsAsync(() => backend.putShard(roster[0], 'f'.repeat(64), new Uint8Array([9, 9, 9])), 'putShard rejects bytes whose SHA-256 != claimed shardId')

  // ---- roster churn: read-time roster != write-time roster (review HIGH fix) ----
  console.log('\n— roster churn resilience —')
  const bChurn = fakeFleet()
  const writeRoster = ['a', 'b', 'c'].map((c) => c.repeat(64))
  const rC = await disperseBody(BODY, { backend: bChurn, roster: writeRoster, k: 4, n: 6, replicas: 1 })
  const readRoster = ['a', 'b', 'c', 'x', 'y', 'z', 'w', 'v'].map((c) => c.repeat(64)) // 5 relays ADDED since write → HRW re-ranks
  ok(await reassembleBody({ manifest: rC.manifest, backend: bChurn, roster: readRoster }) === BODY,
    'reconstructs when the read roster differs from write (fan-out fallback finds shards HRW would no longer point at)')
  await throwsAsync(() => reassembleBody({ manifest: rC.manifest, backend: fakeFleet(), roster: readRoster }),
    'still fails when the shards are genuinely gone (empty fleet)')
  await throwsAsync(() => reassembleBody({ manifest: rC.manifest, backend: bChurn, roster: [] }),
    'reassembleBody guards an empty roster (symmetric with disperseBody)')

  // ---- placement <K cap actually binds (not vacuous) ----
  console.log('\n— placement <K cap binds —')
  const tinyRoster = ['p', 'q'].map((c) => c.repeat(64)) // 2 relays, 9 shards → uncapped a relay would take >= K
  const tiny = fakeFleet()
  const rTiny = await disperseBody(BODY, { backend: tiny, roster: tinyRoster, k: 6, n: 9, replicas: 1 })
  ok(tinyRoster.every((rp) => tiny.heldBy(rp) <= 6 - 1) && tinyRoster.reduce((a, rp) => a + tiny.heldBy(rp), 0) === 9,
    'place() caps each relay at < K even on a 2-relay roster (cap binds: 9 shards would exceed K uncapped)')
  ok(await reassembleBody({ manifest: rTiny.manifest, backend: tiny, roster: tinyRoster }) === BODY, 'tiny-roster dispersal still round-trips')
  await throwsAsync(() => disperseBody(BODY, { backend: fakeFleet(), roster: ['z'.repeat(64)], k: 6, n: 9, replicas: 1 }),
    'place() throws when the roster is too small to honor < K (9 shards, 1 relay)')

  // ---- injectable shard hash: matches the store's addressing (blake2b-ready) ----
  // The real HiveRelay shard store addresses by blake2b-256; peerit's default is
  // SHA-256. Prove the module is hash-AGNOSTIC by injecting a distinct hash and
  // round-tripping — blake2b (from the DHT bundle's sodium) will slot in unchanged.
  console.log('\n— injectable shard content-address (store uses blake2b-256) —')
  const altHash = async (bytes) => hashBytes(Uint8Array.from([0xAA, ...bytes])) // a DISTINCT stand-in for blake2b
  const bAlt = fakeFleet(altHash) // the fake store self-verifies with the SAME injected hash
  const rAlt = await disperseBody(BODY, { backend: bAlt, roster, k: K, n: N, replicas: REPLICAS, hashShard: altHash })
  ok(rAlt.manifest.shardIds.every((id) => /^[0-9a-f]{64}$/.test(id)), 'shards are addressed with the injected hash')
  const rDef = await disperseBody(BODY, { backend: fakeFleet(), roster, k: K, n: N, replicas: REPLICAS })
  ok(rAlt.manifest.shardIds.join() !== rDef.manifest.shardIds.join(), 'a different injected hash yields different shard addresses (the hash is actually used, not shard.js’s built-in)')
  ok(await reassembleBody({ manifest: rAlt.manifest, backend: bAlt, roster, hashShard: altHash }) === BODY, 'round-trips through the injected-hash store (blake2b slots in with no logic change)')
  await throwsAsync(() => reassembleBody({ manifest: rAlt.manifest, backend: bAlt, roster, hashShard: hashBytes }), 'a WRONG read hash fails the content-address gate (recovers nothing)')

  console.log(`\n✅ all ${passed} blob-disperse checks passed`)
}

main().catch((e) => { console.error(e); process.exit(1) })
