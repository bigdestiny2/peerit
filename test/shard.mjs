// shard.mjs — verifies the BlindShard erasure + placement primitive (js/shard.js).
//
// Asserts (per the build brief):
//   1. encode -> drop any N-K shards -> decode recovers the ciphertext EXACTLY,
//      across several drop patterns (all-parity-dropped, all-data-dropped,
//      random, and exhaustive small-case) — proves any-K-of-N reconstruct.
//   2. shardId self-verification: recomputed SHA-256 matches; a substituted
//      shard is detectable (its bytes no longer hash to its id) AND, when fed to
//      decode in place of the real shard, yields wrong bytes -> caught by the
//      caller's blobId self-check (we assert the substitution is detectable).
//   3. place(): < k shards per relay (blindness invariant), deterministic, and
//      re-derivable by an independent reader from the same roster.
//   4. bench: encode/decode ms across a few size buckets.
//
// Run: node test/shard.mjs

import assert from 'node:assert'
import crypto from 'node:crypto'
import {
  encode, decode, shardId, place, referenceCodec, destroyCodec,
  shouldErasure, SHARD_MIN_BYTES, _internal
} from '../js/shard.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

const rnd = (n) => new Uint8Array(crypto.randomBytes(n))
const eqBytes = (a, b) => a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0

// all C(n,drop) index combinations of size `drop` from 0..n-1
function combos (n, drop) {
  const res = []
  const idx = [...Array(n).keys()]
  const rec = (start, chosen) => {
    if (chosen.length === drop) { res.push(chosen.slice()); return }
    for (let i = start; i < n; i++) { chosen.push(idx[i]); rec(i + 1, chosen); chosen.pop() }
  }
  rec(0, [])
  return res
}

async function main () {
  console.log('\n— GF(2^8) field sanity —')
  ok(_internal.gfMul(0, 123) === 0 && _internal.gfMul(123, 0) === 0, 'gfMul by 0 is 0')
  ok(_internal.gfMul(1, 200) === 200, 'gfMul identity')
  ok(_internal.gfDiv(_internal.gfMul(57, 99), 99) === 57, 'gfDiv inverts gfMul')

  console.log('\n— shardId self-verification —')
  {
    const bytes = rnd(1000)
    const id = await shardId(bytes)
    const recomputed = await shardId(bytes)
    ok(id === recomputed && id.length === 64, `shardId is SHA-256 hex (${id.slice(0, 12)}…)`)
    // Substitute one byte -> id must change (relay cannot silently substitute).
    const tampered = Uint8Array.from(bytes); tampered[0] ^= 0xff
    const tamperedId = await shardId(tampered)
    ok(tamperedId !== id, 'a substituted shard hashes to a different id (detectable)')
  }

  console.log('\n— encode/decode round-trip: exhaustive drop of any N-K (k=6,n=9) —')
  {
    const k = 6, n = 9
    const C = rnd(20 * 1024) // 20 KiB ciphertext, above the 8 KiB gate
    const shards = await encode(C, { k, n })
    ok(shards.length === n, `encode produced ${n} shards`)
    // every shard's id verifies
    let allIdsOk = true
    for (const s of shards) if (await shardId(s.bytes) !== s.id) allIdsOk = false
    ok(allIdsOk, `all ${n} shard ids self-verify (SHA-256(bytes) === id)`)
    // exhaustively drop every possible set of exactly N-K = 3 shards
    const dropSets = combos(n, n - k)
    let checked = 0
    for (const drop of dropSets) {
      const kept = shards.filter(s => !drop.includes(s.index))
      const out = await decode(kept, { k, n })
      assert.ok(eqBytes(out, C), `drop ${JSON.stringify(drop)} must recover exactly`)
      checked++
    }
    ok(checked === dropSets.length, `all ${dropSets.length} drop-of-3 patterns recover the ciphertext EXACTLY`)

    // named patterns for readability
    const dropAllParity = shards.filter(s => s.index < k) // keep only data
    ok(eqBytes(await decode(dropAllParity, { k, n }), C), 'drop ALL parity (systematic happy path) recovers')
    const dropAllData = shards.filter(s => s.index >= k - (n - k)) // keep last k incl parity
    ok(eqBytes(await decode(dropAllData, { k, n }), C), 'drop leading data shards (parity-heavy set) recovers')
  }

  console.log('\n— substituted shard is caught at decode/verify time —')
  {
    const k = 4, n = 7
    const C = rnd(9 * 1024)
    const shards = await encode(C, { k, n })
    // Corrupt one shard's bytes but keep its (now-wrong) id claim.
    const bad = shards.map(s => ({ ...s, bytes: Uint8Array.from(s.bytes) }))
    bad[2].bytes[10] ^= 0x01
    // A reader verifies shardId(bytes) === id BEFORE using it -> this catches it.
    ok(await shardId(bad[2].bytes) !== bad[2].id, 'corrupted shard fails its shardId check (reader rejects it)')
    // If the reader instead drops the bad shard, remaining k good shards recover.
    const good = bad.filter((_, i) => i !== 2)
    ok(eqBytes(await decode(good, { k, n }), C), 'routing around the bad shard still recovers exactly')
  }

  console.log('\n— varied k/n and sizes —')
  {
    const cases = [
      { k: 1, n: 3, size: 100 },      // trivial replicate-ish
      { k: 3, n: 5, size: 8 * 1024 },
      { k: 6, n: 9, size: 40 * 1024 },
      { k: 10, n: 16, size: 48 * 1024 },
      { k: 8, n: 12, size: 1 }        // 1-byte edge case
    ]
    for (const { k, n, size } of cases) {
      const C = rnd(size)
      const shards = await encode(C, { k, n })
      // drop a random N-K subset
      const drop = [...Array(n).keys()].sort(() => Math.random() - 0.5).slice(0, n - k)
      const kept = shards.filter(s => !drop.includes(s.index))
      ok(eqBytes(await decode(kept, { k, n }), C), `k=${k} n=${n} size=${size}B: random drop-of-${n - k} recovers`)
    }
  }

  console.log('\n— size gate —')
  ok(shouldErasure(SHARD_MIN_BYTES) && !shouldErasure(SHARD_MIN_BYTES - 1), `size gate at ${SHARD_MIN_BYTES} bytes (~8 KiB)`)

  console.log('\n— injected codec parity (production WASM RS swaps in here) —')
  {
    // Wrap the reference codec to prove encode/decode only touch the interface.
    let encCalls = 0, recCalls = 0, destroyed = false
    const injected = {
      name: 'injected-wrapper',
      encode: (d, p) => { encCalls++; return referenceCodec.encode(d, p) },
      reconstruct: (present, k) => { recCalls++; return referenceCodec.reconstruct(present, k) },
      destroy: () => { destroyed = true }
    }
    const k = 5, n = 8
    const C = rnd(12 * 1024)
    const shards = await encode(C, { k, n, codec: injected })
    const kept = shards.filter(s => s.index !== 1 && s.index !== 6 && s.index !== 7) // drop 3
    const out = await decode(kept, { k, n, codec: injected })
    ok(eqBytes(out, C) && encCalls === 1 && recCalls === 1, 'injected codec drives encode+decode via the interface only')
    ok(destroyCodec(injected) === true && destroyed === true, 'destroyCodec() releases an injected codec (explicit teardown)')
    ok(destroyCodec(referenceCodec) === false, 'reference codec needs no teardown')
  }

  console.log('\n— place(): < k invariant, deterministic, re-derivable —')
  {
    const k = 6, n = 9
    const roster = Array.from({ length: 5 }, () => crypto.randomBytes(32).toString('hex')) // 5 relays
    const C = rnd(16 * 1024)
    const shards = await encode(C, { k, n })
    const ids = shards.map(s => s.id)

    const asg = await place(ids, roster, { replicas: 1, k })
    // invariant: no relay holds >= k shards
    let maxPerRelay = 0
    let totalPlaced = 0
    for (const [, list] of asg) { maxPerRelay = Math.max(maxPerRelay, list.length); totalPlaced += list.length }
    ok(maxPerRelay < k, `no relay holds >= k shards (max=${maxPerRelay}, k=${k}) — blindness invariant holds`)
    ok(totalPlaced === n * 1, `every shard placed once (replicas=1): ${totalPlaced}/${n}`)

    // deterministic: same inputs -> identical assignment
    const asg2 = await place(ids, roster, { replicas: 1, k })
    const norm = (m) => JSON.stringify([...m.entries()].map(([r, l]) => [r, [...l].sort()]).sort())
    ok(norm(asg) === norm(asg2), 'placement is deterministic (identical on re-run)')

    // re-derivable by an independent reader from the SAME roster in different order
    const shuffled = [...roster].reverse()
    const asgReader = await place(ids, shuffled, { replicas: 1, k })
    ok(norm(asg) === norm(asgReader), 'a reader re-derives the identical placement (order-independent HRW)')

    // replicas: 2 -> each shard on 2 relays, still < k per relay
    const asgR2 = await place(ids, roster, { replicas: 2, k })
    let max2 = 0, total2 = 0
    for (const [, list] of asgR2) { max2 = Math.max(max2, list.length); total2 += list.length }
    ok(max2 < k, `replicas=2: still < k per relay (max=${max2})`)
    ok(total2 === n * 2, `replicas=2: ${total2} placements = ${n} shards x 2`)

    // auditability: reader recomputes a specific shard's relay set and it matches
    const sid = ids[0]
    const holdersActual = new Set()
    for (const [r, list] of asgR2) if (list.includes(sid)) holdersActual.add(r)
    // independently recompute top-2 HRW relays for sid, honoring the cap is
    // trivial here since it's the first shard placed -> top-2 by weight.
    const ranked = []
    for (const r of roster) {
      const h = crypto.createHash('sha256').update(Buffer.concat([Buffer.from(r, 'hex'), Buffer.from(sid, 'hex')])).digest('hex')
      ranked.push({ r, h })
    }
    ranked.sort((a, b) => (a.h < b.h ? -1 : a.h > b.h ? 1 : 0))
    const expectTop2 = new Set([ranked[0].r, ranked[1].r])
    ok([...expectTop2].every(r => holdersActual.has(r)) && holdersActual.size === 2,
      'reader independently recomputes the HRW holder set for a shard (auditable)')
  }

  console.log('\n— place(): roster-too-small is rejected (fault-tolerance honesty) —')
  {
    const k = 3, n = 9
    const roster = [crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')] // 2 relays
    const ids = Array.from({ length: n }, (_, i) => crypto.createHash('sha256').update('s' + i).digest('hex'))
    // 9 shards x 1 replica needs > 2 relays x (k-1)=2 = 4 capacity -> must throw
    await assert.rejects(() => place(ids, roster, { replicas: 1, k }), /roster too small/)
    ok(true, 'place() throws when roster cannot satisfy the < k cap for all shards')
  }

  // -------------------------------------------------------------------------
  console.log('\n— BENCH (encode/decode ms per size bucket, reference codec) —')
  {
    const buckets = [8 * 1024, 16 * 1024, 40 * 1024, 64 * 1024, 128 * 1024]
    const k = 6, n = 9
    const iters = 30
    console.log(`  codec=${referenceCodec.name}  k=${k} n=${n}  (median of ${iters} iters)`)
    console.log('  size      encode(ms)  decode-worst(ms)  shards')
    for (const size of buckets) {
      const C = rnd(size)
      // warm
      await encode(C, { k, n })
      const encTimes = []
      let shards
      for (let i = 0; i < iters; i++) {
        const t0 = performance.now()
        shards = await encode(C, { k, n })
        encTimes.push(performance.now() - t0)
      }
      // worst-case decode: drop the 3 parity-inducing data shards so GF math runs
      const drop = [0, 1, 2]
      const kept = shards.filter(s => !drop.includes(s.index))
      const decTimes = []
      for (let i = 0; i < iters; i++) {
        const t0 = performance.now()
        const out = await decode(kept, { k, n })
        decTimes.push(performance.now() - t0)
        if (i === 0) assert.ok(eqBytes(out, C), 'bench decode correctness')
      }
      const med = (a) => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)] }
      const kib = (size / 1024).toFixed(0).padStart(4)
      console.log(`  ${kib} KiB   ${med(encTimes).toFixed(3).padStart(8)}   ${med(decTimes).toFixed(3).padStart(12)}       ${n}`)
    }
    ok(true, 'bench completed across size buckets')
  }

  console.log(`\n✅ all ${passed} shard checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
