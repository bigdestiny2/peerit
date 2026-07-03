// gossip-v2.mjs — the Opaque-Log v2 admit path in gossip.js (slice 3). Builds REAL
// v2 records (opaque key v2!<okey>, semantic type in signed _t, signed over
// canonical('v2', data), PoW over the semantic type) and drives them through the
// REAL mergeOutboxes/admit. Proves: a valid v2 record admits; the anti-eviction +
// owner-binding + sig gates all reject tampering; anti-squat sticky-claim + vote LWW
// self-compaction survive opaque keys; and v1 + v2 rows coexist (dual-read).
//   node test/gossip-v2.mjs

import assert from 'node:assert'
import { ready as cryptoReady, isSecure, genKeyPair, sign } from '../js/crypto.js'
import { mergeOutboxes } from '../js/gossip.js'
import { canonical, expectedKeyV2 } from '../js/canon.js'
import { mint, makeValidator } from '../js/pow.js'
import { keys } from '../js/model.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const BITS = { community: 4, post: 4, vote: 4, comment: 4, profile: 4, modaction: 4, head: 4 }
const validate = makeValidator(BITS)

// Build a signed v2 record exactly as data.js's v2 write path will (slice 4).
async function mkV2 (t, fields, kp, opts = {}) {
  const data = { _t: t, ...fields }
  const wireKey = await expectedKeyV2(data)      // v2!<okey> — from _t/owner/semanticId, not id/pow/sig
  data.id = wireKey.slice(3)
  data.pow = await mint(t, data, BITS[t] || 0)    // PoW keyed by the semantic type
  const msg = `pear.app.${kp.pubHex}:peerit:` + canonical('v2', data) // sign over the CONSTANT wire type
  data._sig = opts.badSig ? '00'.repeat(32) : await sign(kp.seedHex, msg)
  data._k = opts.k || kp.pubHex
  data._dk = kp.pubHex; data._ns = 'peerit'; data._alg = 'ed25519'
  return { key: opts.key || wireKey, val: data }
}
// A minimal legacy v1 record (plaintext key) for the dual-read check.
async function mkV1 (t, fields, kp) {
  const data = { id: null, ...fields }
  data.id = t === 'post' ? `${fields.community}!${fields.cid}` : fields.author
  data.pow = await mint(t, data, BITS[t] || 0)
  data._sig = await sign(kp.seedHex, `pear.app.${kp.pubHex}:peerit:` + canonical(t, data))
  data._k = kp.pubHex; data._dk = kp.pubHex; data._ns = 'peerit'; data._alg = 'ed25519'
  return { key: t === 'post' ? keys.post(fields.community, fields.cid) : keys.profile(fields.author), val: data }
}
const box = (kp, ...recs) => ({ pub: kp.pubHex, view: Object.fromEntries(recs.map(r => [r.key, r.val])) })

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')
  const A = await genKeyPair(); const B = await genKeyPair()

  // ---- valid v2 records admit ----
  console.log('\n— valid v2 admit —')
  const post = await mkV2('post', { author: A.pubHex, community: 'p2p', cid: 'x1', title: 'hi', createdAt: 1, deleted: false }, A)
  const vote = await mkV2('vote', { author: B.pubHex, targetCid: 'p2p!x1', value: 1, ts: 3 }, B)
  const merged = await mergeOutboxes([box(A, post), box(B, vote)], {}, validate)
  ok(merged[post.key] && merged[post.key].title === 'hi', 'a valid v2 post admits under its opaque key')
  ok(merged[vote.key] && merged[vote.key].value === 1, 'a valid v2 vote (different author) admits')
  ok(/^v2![0-9a-f]{64}$/.test(post.key) && post.key.indexOf('p2p') === -1, 'the wire key is opaque — no community/cid/type in it')

  // ---- tamper: every gate rejects ----
  console.log('\n— tamper rejection —')
  const flipT = { key: post.key, val: { ...post.val, _t: 'vote' } } // relabel type, keep key+sig
  ok(!(await mergeOutboxes([box(A, flipT)], {}, validate))[post.key], 'flipping _t → okey-recompute mismatch → rejected (anti-relabel)')

  const parked = { key: 'v2!' + 'f'.repeat(64), val: post.val } // valid record parked under a foreign okey
  ok(!(await mergeOutboxes([box(A, parked)], {}, validate))['v2!' + 'f'.repeat(64)], 'a valid record parked under a foreign okey → rejected (anti-eviction)')

  const foreignK = await mkV2('post', { author: A.pubHex, community: 'p2p', cid: 'x9', createdAt: 1 }, B, { k: B.pubHex }) // author A, signed by B
  ok(!(await mergeOutboxes([box(B, foreignK)], {}, validate))[foreignK.key], 'author=A but signed by B (_k≠owner) → rejected (owner-binding via semantic _t)')

  const badSig = await mkV2('post', { author: A.pubHex, community: 'p2p', cid: 'x8', createdAt: 1 }, A, { badSig: true })
  ok(!(await mergeOutboxes([box(A, badSig)], {}, validate))[badSig.key], 'a broken signature → rejected')

  // ---- anti-squat sticky community claim (author-INDEPENDENT slot) ----
  console.log('\n— anti-squat sticky claim —')
  const cA = await mkV2('community', { slug: 'worldcup', creator: A.pubHex, title: 'A', createdAt: 10 }, A)
  const cB = await mkV2('community', { slug: 'worldcup', creator: B.pubHex, title: 'B', createdAt: 20 }, B)
  ok(cA.key === cB.key, 'rival creators for a slug land on the SAME opaque community slot (author-independent)')
  const claimed = {}
  const m1 = await mergeOutboxes([box(A, cA), box(B, cB)], claimed, validate)
  ok(m1[cA.key].creator === A.pubHex, 'earliest-createdAt creator wins the community slot (communityWins)')
  ok(claimed.worldcup === A.pubHex, 'the winning creator is locked in `claimed`')
  const m2 = await mergeOutboxes([box(B, cB)], claimed, validate) // B tries again with the lock set
  ok(!m2[cB.key] || m2[cB.key].creator === A.pubHex, 'a later different-creator claim is rejected by the sticky lock')

  // ---- vote LWW self-compaction at the opaque slot ----
  console.log('\n— vote LWW self-compaction —')
  const up = await mkV2('vote', { author: A.pubHex, targetCid: 'p2p!x1', value: 1, ts: 5 }, A)
  const down = await mkV2('vote', { author: A.pubHex, targetCid: 'p2p!x1', value: -1, ts: 9 }, A) // same voter re-votes
  ok(up.key === down.key, 'a re-vote by the same voter hits the SAME opaque slot')
  const mv = await mergeOutboxes([box(A, up), box(A, down)], {}, validate)
  ok(mv[up.key].value === -1, 'later vote wins the slot (LWW) — table self-compacts as v1 did')

  // ---- dual-read: v1 + v2 coexist ----
  console.log('\n— dual-read (v1 + v2) —')
  const v1post = await mkV1('post', { author: A.pubHex, community: 'p2p', cid: 'legacy1', title: 'old', createdAt: 1 }, A)
  const mix = await mergeOutboxes([box(A, v1post, post)], {}, validate)
  ok(mix[v1post.key] && mix[v1post.key].title === 'old', 'a legacy v1 plaintext-key row still admits alongside v2')
  ok(mix[post.key] && mix[post.key].title === 'hi', 'the v2 opaque-key row admits in the same merge')

  console.log(`\n✅ all ${passed} gossip-v2 checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
