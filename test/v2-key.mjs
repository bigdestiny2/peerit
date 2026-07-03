// v2-key.mjs — the blind key-scheme codec (canon.js expectedKeyV2 + model.js
// semanticId + seal.js okey). Proves the anti-eviction + type-binding invariants
// that the Opaque-Log v2 admit gate will rest on (docs/BLIND-OUTBOX-MIGRATION.md §4,
// stress-test S1/S3): a record's opaque slot `v2!<okey>` is recomputable ONLY from
// its own signed fields; flipping `_t` breaks BOTH the okey recompute AND the Ed25519
// signature; author-binding stops parking under a victim's slot; the community slot is
// author-INDEPENDENT so rival creators collide (anti-squat sticky-claim survives).
//   node test/v2-key.mjs

import assert from 'node:assert'
import { ready as cryptoReady, isSecure, genKeyPair, sign, verify } from '../js/crypto.js'
import { canonical, expectedKeyV2, typeOf } from '../js/canon.js'
import { okey, communityOkey } from '../js/seal.js'
import { semanticId } from '../js/model.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')
  const { seedHex, pubHex } = await genKeyPair()

  // A v2 post record: its id IS its own okey; signed over canonical('v2', data).
  console.log('\n— per-author record (family A) —')
  const rec = { _t: 'post', author: pubHex, community: 'p2p', cid: 'x1', createdAt: 1, deleted: false }
  const wantKey = await expectedKeyV2(rec) // 'v2!<okey>'
  rec.id = wantKey.slice(3)
  const sig = await sign(seedHex, canonical('v2', rec))

  ok(/^v2![0-9a-f]{64}$/.test(wantKey), 'expectedKeyV2 → v2!<64-hex opaque> (no semantic scope in the wire key)')
  ok(wantKey === 'v2!' + await okey('post', semanticId('post', rec), pubHex), 'okey recompute == a direct seal.okey over (author, _t, semanticId)')
  ok('v2!' + rec.id === await expectedKeyV2(rec), 'the record’s id IS its recomputed okey → admit key-binding holds')
  ok(await verify(pubHex, canonical('v2', rec), sig), 'the signature verifies over canonical(v2, data)')

  // flip _t → BOTH the okey slot AND the signature must reject
  console.log('\n— type integrity (_t) —')
  const flipT = { ...rec, _t: 'vote', targetCid: 'p2p!x1' }
  ok(await expectedKeyV2(flipT) !== wantKey, 'flipping _t → a DIFFERENT okey slot (admit rejects the relocation)')
  ok(!(await verify(pubHex, canonical('v2', flipT), sig)), 'flipping _t → the signature no longer verifies (canonical covers _t) — both gates catch it')
  ok(typeOf(rec) === 'post' && typeOf({}) === undefined, 'typeOf reads the signed _t field, never the key')

  // anti-parking: author + semantic fields are load-bearing in the slot
  console.log('\n— anti-eviction / anti-parking —')
  ok(await expectedKeyV2({ ...rec, author: 'b'.repeat(64) }) !== wantKey, 'a different author → a different slot (author-bound; a peer can’t park under a victim)')
  ok(await expectedKeyV2({ ...rec, community: 'evil' }) !== wantKey, 'a different community → a different slot')
  ok(await expectedKeyV2({ ...rec, cid: 'x2' }) !== wantKey, 'a different cid → a different slot')

  // vote uses author-in-semanticId (one slot per voter → LWW self-compaction survives)
  console.log('\n— vote slot (LWW self-compaction) —')
  const v1 = { _t: 'vote', author: pubHex, targetCid: 'p2p!x1', value: 1, ts: 5 }
  const v2 = { _t: 'vote', author: pubHex, targetCid: 'p2p!x1', value: -1, ts: 9 } // same voter re-votes
  ok(await expectedKeyV2(v1) === await expectedKeyV2(v2), 'a re-vote by the same voter hits the SAME okey slot → LWW overwrites (self-compaction as today)')
  ok(await expectedKeyV2({ ...v1, author: 'c'.repeat(64) }) !== await expectedKeyV2(v1), 'a different voter → a different vote slot')

  // community: the ONE author-INDEPENDENT slot (anti-squat collision)
  console.log('\n— community slot (family B, author-independent) —')
  const cA = { _t: 'community', slug: 'worldcup', creator: 'a'.repeat(64) }
  const cB = { _t: 'community', slug: 'worldcup', creator: 'b'.repeat(64) }
  ok(await expectedKeyV2(cA) === await expectedKeyV2(cB), 'community slot is AUTHOR-INDEPENDENT — rival creators collide at one slot (sticky-claim fires unchanged)')
  ok(await expectedKeyV2(cA) === 'v2!' + await communityOkey('worldcup'), 'community slot == v2!communityOkey(slug)')
  ok(await expectedKeyV2({ _t: 'community', slug: 'p2p', creator: cA.creator }) !== await expectedKeyV2(cA), 'a different slug → a different community slot')

  console.log(`\n✅ all ${passed} v2-key checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
