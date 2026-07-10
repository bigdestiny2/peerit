// gossip-v2.mjs — the Opaque-Log v2 admit path in gossip.js with SEALED records
// (slice 3 opaque keys + slice 4a sealed graph fields). Builds REAL v2 records the way
// data.js's v2 write path will: graph fields (community, cid, targetCid, …) SEALED under
// the read key; LWW/sticky fields (createdAt, ts, deleted, slug) cleartext; opaque key
// v2!<okey> where okey = HMAC(RK, _k‖_t‖semanticId); signed over canonical('v2', stored).
// Drives them through the REAL mergeOutboxes/admit. Proves: a valid sealed record admits;
// the graph field does NOT leak in the stored value; anti-eviction (okey recomputed from
// DECRYPTED fields) + owner-binding (okey is _k-bound) + sig all reject tampering; sticky
// anti-squat + vote LWW survive; v1 + v2 coexist (dual-read).
//   node test/gossip-v2.mjs

import assert from 'node:assert'
import { ready as cryptoReady, isSecure, genKeyPair, sign } from '../js/crypto.js'
import { mergeOutboxes } from '../js/gossip.js'
import { canonical, expectedKeyV2 } from '../js/canon.js'
import { seal } from '../js/seal.js'
import { mint, makeValidator } from '../js/pow.js'
import { keys } from '../js/model.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const BITS = { community: 4, post: 4, vote: 4, comment: 4, profile: 4, modaction: 4, head: 4 }
// This suite intentionally exercises historical record shapes. Grandfather
// only the exact locally signed fixture bytes, mirroring production's frozen set.
const legacyContentSignatures = new Set()
const legacyActionSignatures = { comment: new Set(), vote: new Set(), modaction: new Set() }
const validate = makeValidator(BITS, { legacyContentSignatures, legacyActionSignatures })
const CLEAR = new Set(['createdAt', 'ts', 'editedAt', 'deleted', 'slug']) // stay cleartext (LWW + name, leak anyway)

// Build a signed SEALED v2 record exactly as data.js's v2 write path will.
async function mkV2 (t, fields, kp, opts = {}) {
  const logical = { _t: t, author: kp.pubHex, creator: kp.pubHex, by: kp.pubHex, ...fields }
  const wireKey = await expectedKeyV2(logical) // v2!<okey> — from _k + _t + semanticId
  const clear = {}, sealedFields = {}
  for (const [k, v] of Object.entries(fields)) (CLEAR.has(k) ? clear : sealedFields)[k] = v
  const data = { _t: t, id: wireKey.slice(3), ...clear, sealed: await seal(sealedFields) }
  data.pow = await mint(t, data, BITS[t] || 0)
  data._sig = opts.badSig ? '00'.repeat(32) : await sign(kp.seedHex, `pear.app.${kp.pubHex}:peerit:` + canonical('v2', data))
  data._k = opts.k || kp.pubHex; data._dk = kp.pubHex; data._ns = 'peerit'; data._alg = 'ed25519'
  if (!opts.badSig && (t === 'post' || t === 'comment')) legacyContentSignatures.add(data._sig)
  if (!opts.badSig && legacyActionSignatures[t]) legacyActionSignatures[t].add(data._sig)
  return { key: opts.key || wireKey, val: data }
}
async function mkV1 (t, fields, kp) { // minimal legacy record for the dual-read check
  const data = { id: t === 'post' ? `${fields.community}!${fields.cid}` : fields.author, ...fields }
  data.pow = await mint(t, data, BITS[t] || 0)
  data._sig = await sign(kp.seedHex, `pear.app.${kp.pubHex}:peerit:` + canonical(t, data))
  data._k = kp.pubHex; data._dk = kp.pubHex; data._ns = 'peerit'; data._alg = 'ed25519'
  if (t === 'post' || t === 'comment') legacyContentSignatures.add(data._sig)
  return { key: t === 'post' ? keys.post(fields.community, fields.cid) : keys.profile(fields.author), val: data }
}
const box = (kp, ...recs) => ({ pub: kp.pubHex, view: Object.fromEntries(recs.map(r => [r.key, r.val])) })

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')
  const A = await genKeyPair(); const B = await genKeyPair()

  // ---- valid sealed v2 records admit + the graph does NOT leak ----
  console.log('\n— valid sealed admit + no graph leak —')
  const post = await mkV2('post', { community: 'p2p', cid: 'x1', title: 'hi', createdAt: 1, deleted: false }, A)
  const vote = await mkV2('vote', { targetCid: 'p2p!x1', value: 1, ts: 3 }, B)
  const merged = await mergeOutboxes([box(A, post), box(B, vote)], {}, validate)
  ok(merged[post.key] && merged[post.key]._t === 'post', 'a valid sealed v2 post admits under its opaque key')
  ok(merged[vote.key] && merged[vote.key].sealed, 'a valid sealed v2 vote (different author) admits')
  ok(/^v2![0-9a-f]{64}$/.test(post.key) && !JSON.stringify(post.val).includes('p2p'), 'the community/target NEVER appears in the stored value — sealed, not greppable')
  ok(post.val.community === undefined && post.val.cid === undefined && post.val.sealed, 'graph fields are gone from the top level; only { iv, ct } remains')

  // ---- anti-eviction: okey recomputed from DECRYPTED fields ----
  console.log('\n— anti-eviction / anti-impersonation —')
  const parked = { key: 'v2!' + 'f'.repeat(64), val: post.val }
  ok(!(await mergeOutboxes([box(A, parked)], {}, validate))['v2!' + 'f'.repeat(64)], 'a valid record parked under a foreign okey → rejected (okey recomputed from its own sealed fields)')

  const imp = await mkV2('post', { community: 'p2p', cid: 'imp', createdAt: 1 }, A)
  imp.val._k = B.pubHex; imp.val._dk = B.pubHex
  imp.val._sig = await sign(B.seedHex, `pear.app.${B.pubHex}:peerit:` + canonical('v2', imp.val)) // B validly re-signs A's slot
  ok(!(await mergeOutboxes([box(B, imp)], {}, validate))[imp.key], 'a record at A’s okey but signed by B → rejected (okey is bound to the signer _k)')

  const flipT = { key: post.key, val: { ...post.val, _t: 'vote' } }
  ok(!(await mergeOutboxes([box(A, flipT)], {}, validate))[post.key], 'relabelling _t → okey no longer recomputes (and the sig breaks) → rejected')

  const tampered = { key: post.key, val: { ...post.val, sealed: { ...post.val.sealed, ct: post.val.sealed.ct.slice(0, -6) + 'AAAAAA' } } }
  ok(!(await mergeOutboxes([box(A, tampered)], {}, validate))[post.key], 'tampering the sealed ciphertext → the signature breaks → rejected')

  const badSig = await mkV2('post', { community: 'p2p', cid: 'x8', createdAt: 1 }, A, { badSig: true })
  ok(!(await mergeOutboxes([box(A, badSig)], {}, validate))[badSig.key], 'a broken signature → rejected')

  // ---- anti-squat sticky claim (slug cleartext, one author-independent slot) ----
  console.log('\n— anti-squat sticky claim —')
  const cA = await mkV2('community', { slug: 'worldcup', title: 'A', createdAt: 10 }, A)
  const cB = await mkV2('community', { slug: 'worldcup', title: 'B', createdAt: 20 }, B)
  ok(cA.key === cB.key, 'rival creators for a slug land on the SAME opaque community slot')
  const claimed = {}
  const m1 = await mergeOutboxes([box(A, cA), box(B, cB)], claimed, validate)
  ok(m1[cA.key]._k === A.pubHex, 'earliest-createdAt creator wins the community slot')
  ok(claimed.worldcup === A.pubHex, 'the winning creator is locked in `claimed` (keyed on cleartext slug + _k)')
  const m2 = await mergeOutboxes([box(B, cB)], claimed, validate)
  ok(!m2[cB.key] || m2[cB.key]._k === A.pubHex, 'a later different-creator claim is rejected by the sticky lock')

  // ---- vote LWW self-compaction at the opaque slot ----
  console.log('\n— vote LWW self-compaction —')
  const up = await mkV2('vote', { targetCid: 'p2p!x1', value: 1, ts: 5 }, A)
  const down = await mkV2('vote', { targetCid: 'p2p!x1', value: -1, ts: 9 }, A) // same voter re-votes
  ok(up.key === down.key, 'a re-vote by the same voter hits the SAME opaque slot (ts cleartext for LWW)')
  const mv = await mergeOutboxes([box(A, up), box(A, down)], {}, validate)
  ok(await (async () => { const f = await import('../js/seal.js').then(m => m.unseal(mv[up.key].sealed)); return f.value })() === -1, 'later vote wins the slot (LWW); its sealed value decrypts to -1')

  // ---- dual-read: v1 + v2 coexist ----
  console.log('\n— dual-read (v1 + v2) —')
  const v1post = await mkV1('post', { author: A.pubHex, community: 'p2p', cid: 'legacy1', title: 'old', createdAt: 1 }, A)
  const mix = await mergeOutboxes([box(A, v1post, post)], {}, validate)
  ok(mix[v1post.key] && mix[v1post.key].title === 'old', 'a legacy v1 plaintext-key row still admits alongside v2')
  ok(mix[post.key] && mix[post.key].sealed, 'the v2 sealed opaque-key row admits in the same merge')

  console.log(`\n✅ all ${passed} gossip-v2 checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
