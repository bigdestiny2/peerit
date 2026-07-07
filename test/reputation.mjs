// reputation.mjs — Slice 3: reputation-weighted votes (ported from p2pbuilders).
// A vote's influence scales with the VOTER's age + upvotes received, so Sybil
// ballot-stuffing barely moves rankings while established voters carry weight.
// Proves: the weight curve, that raw score is preserved for DISPLAY while
// `weighted` drives RANKING, that a real voter outweighs many fresh keys, and that
// weighted karma discounts low-weight approval.
//   node test/reputation.mjs

import assert from 'node:assert'
import { weight, tally } from '../js/ranking.js'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'

const BITS = { community: 4, post: 4, comment: 4, vote: 4, profile: 4, modaction: 4 }
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const fresh = (u) => u.data.invalidateViewCaches('content')

function pureChecks () {
  console.log('— weight curve —')
  ok(weight(0, 0) === 0.02, 'a brand-new key with no reputation floors at 0.02 (counts, barely)')
  ok(weight(1e6, 1e6) === 1, 'weight is clamped to a 1.0 ceiling')
  ok(weight(90, 50) > weight(30, 10) && weight(30, 10) > weight(0, 0), 'weight increases with age + upvotes received')

  console.log('\n— tally: raw score for display, weighted for ranking —')
  const votes = [{ author: 'a', value: 1 }, { author: 'b', value: 1 }, { author: 'c', value: -1 }]
  const unweighted = tally(votes, null)
  ok(unweighted.score === 1 && unweighted.weighted === 1, 'unweighted callers get weighted == raw score (backward compatible)')
  const weightOf = (pub) => pub === 'a' ? [30, 10] : [0, 0] // a is mid-reputation (~0.33), b/c are fresh (~0.02)
  const weighted = tally(votes, null, weightOf)
  ok(weighted.up === 2 && weighted.down === 1 && weighted.score === 1, 'raw up/down/score are UNCHANGED by weighting (display integrity)')
  ok(weighted.weighted === (1 * weight(30, 10)) + (1 * weight(0, 0)) + (-1 * weight(0, 0)), 'weighted score sums per-voter weights')
  ok(Math.abs(weighted.weighted - weighted.score) > 0.1, 'the weighted score (~0.33) diverges from the raw score (1) once voters are weighted')
}

async function liveChecks () {
  const store = memoryStorage()
  const users = {}
  const mk = async (name) => {
    const sync = new DevSync(store, 'rep'); await sync.ready()
    const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
    users[name] = { sync, id, data: createData(sync, id, { minBits: BITS, v2: true }), me: id.me().pubkey }
    return users[name]
  }
  const alice = await mk('alice')   // will be the established voter (gets upvoted)
  const author = await mk('author')
  const sybils = []
  for (let i = 0; i < 8; i++) sybils.push(await mk('sybil' + i))

  await author.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'rep' })
  Object.values(users).forEach(fresh)
  // Backdate alice's history ~400 days so she has real ACCOUNT AGE (weight is
  // age-dominant: a brand-new key floors at 0.02 no matter its upvotes — reputation
  // is earned over calendar time). We mock Date.now ONLY while she writes that post.
  const realNow = Date.now
  const OLD = realNow() - 400 * 86400000
  Date.now = () => OLD
  const aliceOldPost = await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'alice history', body: 'x' })
  Date.now = realNow
  const P = await author.data.submitPost({ community: 'p2p', kind: 'text', title: 'the sybil target', body: 'x' })
  const Q = await author.data.submitPost({ community: 'p2p', kind: 'text', title: 'the honest target', body: 'y' })
  // alice accrues received-upvotes (reputation) from several accounts on her old post
  for (const s of sybils.slice(0, 6)) { fresh(s); await s.data.vote(aliceOldPost.cid, 'p2p', 'post', 1) }

  console.log('\n— a real voter outweighs a Sybil swarm —')
  fresh(alice); await alice.data.vote(Q.cid, 'p2p', 'post', 1)                 // 1 reputable upvote on Q
  for (const s of sybils) { fresh(s); await s.data.vote(P.cid, 'p2p', 'post', 1) } // 8 fresh upvotes on P
  fresh(author)
  const [tp, tq] = [await author.data.tallyFor(P.cid), await author.data.tallyFor(Q.cid)]
  ok(tp.score === 8 && tq.score === 1, 'raw score: P=8 (sybils), Q=1 (alice) — display shows the real counts')
  ok(tq.weighted > tp.weighted, 'WEIGHTED: alice\'s single reputable vote outranks 8 fresh Sybil votes')
  ok(tp.weighted < 8 * weight(0, 0) + 0.001 && tp.weighted > 0, 'the Sybil swarm is discounted toward the 0.02 floor per vote')

  console.log('\n— feed ranking reflects weight, not raw count —')
  const ranked = (await import('../js/ranking.js')).sortPosts(await author.data.withTallies([{ ...P, createdAt: P.createdAt }, { ...Q, createdAt: Q.createdAt }]), 'top')
  ok(ranked[0].cid === Q.cid, 'top sort puts the reputably-upvoted post FIRST despite its lower raw score')

  console.log('\n— weighted karma discounts low-weight approval —')
  const k = await author.data.karmaFor(author.me)
  ok(k.total === 9, 'raw karma = 9 (8 + 1, unchanged)')
  ok(k.weighted < k.total, 'weighted karma is lower than raw karma (Sybil approval is discounted)')

  console.log('\n— vote-weight inputs surface for the profile —')
  const [ageDays, received] = await author.data.weightInputsFor(alice.me)
  ok(received === 6, 'alice\'s received-upvotes (6) feed her vote weight')
  ok(ageDays >= 0, 'age-in-days is computed from earliest activity')
}

async function main () {
  await cryptoReady()
  pureChecks()
  await liveChecks()
  console.log(`\n✅ all ${passed} reputation checks passed`)
  process.exit(0)
}
main().catch((e) => { console.error('\n❌ reputation FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
