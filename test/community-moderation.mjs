// Signed community moderation + interchangeable feed algorithms.

import assert from 'node:assert/strict'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { FEED_ALGORITHMS, rankFeedWindow } from '../js/feed-algorithms.js'
import {
  MODERATION_VIEW,
  VISIBILITY,
  aggregateReports,
  applyModerationPolicy,
  eligibleCommunityAuthors
} from '../js/moderation.js'
import { REPORT_VERDICT, TYPE } from '../js/model.js'

const BITS = { community: 4, post: 4, comment: 4, blob: 4, report: 4 }
const mem = () => {
  const values = new Map()
  return {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
    clear: () => values.clear()
  }
}
let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }

async function identity (name) {
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  return id
}

function report (author, verdict = REPORT_VERDICT.BURY, ts = 1, deleted = false) {
  return { author, verdict, reason: 'spam', note: '', ts, deleted }
}

await cryptoReady()

console.log('\n— pure consensus thresholds and reader choice —')
const eligible = new Set(Array.from({ length: 10 }, (_, i) => 'p' + i))
let consensus = aggregateReports(['p0', 'p1', 'p2'].map(author => report(author)), { eligible })
ok(consensus.state === VISIBILITY.DOWNRANKED, 'three eligible bury votes downrank')
consensus = aggregateReports(['p0', 'p1', 'p2', 'p3', 'p4'].map(author => report(author)), { eligible })
ok(consensus.state === VISIBILITY.COLLAPSED, 'five eligible supermajority votes collapse')
consensus = aggregateReports(['p0', 'p1', 'p2', 'p3', 'p4', 'p5', 'p6'].map(author => report(author)), { eligible })
ok(consensus.state === VISIBILITY.BURIED, 'seven eligible supermajority votes bury')
const split = aggregateReports([
  ...['p0', 'p1', 'p2', 'p3', 'p4', 'p5', 'p6'].map(author => report(author)),
  report('p7', REPORT_VERDICT.KEEP),
  report('p8', REPORT_VERDICT.KEEP),
  report('p9', REPORT_VERDICT.KEEP)
], { eligible })
ok(split.state === VISIBILITY.COLLAPSED, 'keep votes reduce support and prevent a bury threshold')
ok(applyModerationPolicy(consensus, { view: MODERATION_VIEW.OPEN }).visibility === VISIBILITY.VISIBLE,
  'Open view displays content even when consensus says buried')
ok(applyModerationPolicy(aggregateReports([]), { view: MODERATION_VIEW.COMMUNITY, moderatorRemoved: true }).visibility === VISIBILITY.COLLAPSED,
  'Community view applies the moderator overlay')
ok(applyModerationPolicy(aggregateReports([]), { view: MODERATION_VIEW.CONSENSUS, moderatorRemoved: true }).visibility === VISIBILITY.VISIBLE,
  'Consensus-only view labels but does not apply moderator removal')
const permutedA = aggregateReports([
  report('p0', REPORT_VERDICT.BURY, 1),
  report('p0', REPORT_VERDICT.KEEP, 1),
  report('p1', REPORT_VERDICT.BURY, 2)
], { eligible })
const permutedB = aggregateReports([
  report('p1', REPORT_VERDICT.BURY, 2),
  report('p0', REPORT_VERDICT.KEEP, 1),
  report('p0', REPORT_VERDICT.BURY, 1)
], { eligible })
ok(JSON.stringify(permutedA) === JSON.stringify(permutedB), 'report aggregation converges across input permutations and timestamp ties')

console.log('\n— trust-connected eligibility has no self-timestamp age shortcut —')
const roots = eligibleCommunityAuthors({
  creator: 'founder',
  memberships: [{ author: 'newcomer' }],
  posts: [{ cid: 'new-post', author: 'newcomer', createdAt: -999999999999 }],
  votes: []
})
ok(!roots.has('newcomer'), 'a backdated contribution alone does not grant moderation authority')
const endorsed = eligibleCommunityAuthors({
  creator: 'founder',
  memberships: [{ author: 'newcomer' }],
  posts: [{ cid: 'new-post', author: 'newcomer', createdAt: -999999999999 }],
  votes: [{ targetCid: 'new-post', author: 'founder', value: 1 }]
})
ok(endorsed.has('newcomer'), 'an active member joins after an eligible participant endorses their community contribution')
const noRecursiveSybil = eligibleCommunityAuthors({
  creator: 'founder',
  memberships: [{ author: 'newcomer' }, { author: 'sybil' }],
  posts: [{ cid: 'new-post', author: 'newcomer' }, { cid: 'sybil-post', author: 'sybil' }],
  votes: [
    { targetCid: 'new-post', author: 'founder', value: 1 },
    { targetCid: 'sybil-post', author: 'newcomer', value: 1 }
  ]
})
ok(noRecursiveSybil.has('newcomer') && !noRecursiveSybil.has('sybil'),
  'raw upvote trust does not recurse into an endorsed participant’s Sybil chain')
const bannedParticipant = eligibleCommunityAuthors({
  creator: 'founder',
  banned: ['newcomer'],
  memberships: [{ author: 'newcomer' }],
  posts: [{ cid: 'new-post', author: 'newcomer' }],
  votes: [{ targetCid: 'new-post', author: 'founder', value: 1 }]
})
ok(!bannedParticipant.has('newcomer'), 'an active community ban removes moderation eligibility')

console.log('\n— sealed report lifecycle over the generic cell substrate —')
const sync = new DevSync(memoryStorage(), 'community-moderation')
await sync.ready()
const aliceId = await identity('alice')
const bobId = await identity('bob')
const alice = createData(sync, aliceId, { minBits: BITS, v2: true })
const bob = createData(sync, bobId, { minBits: BITS, v2: true })
await alice.createCommunity({ slug: 'commons', title: 'Commons' })
const target = await alice.submitPost({ community: 'commons', kind: 'text', title: 'Target', body: 'inspect me' })
await bob.setMembership('commons')
const contribution = await bob.submitPost({ community: 'commons', kind: 'text', title: 'Hello', body: 'community participation' })
await bob.reportContent('commons', {
  targetCid: target.cid,
  targetType: TYPE.POST,
  verdict: REPORT_VERDICT.BURY,
  reason: 'spam',
  note: 'repeated promotion'
})

const storedReports = (await sync.list('v2!', { limit: 1000 })).filter(row => row.value?._t === TYPE.REPORT)
ok(storedReports.length === 1 && storedReports[0].key.startsWith('v2!'), 'report is a normal opaque v2 cell')
const wire = JSON.stringify(storedReports[0])
ok(!wire.includes(target.cid) && !wire.includes('commons') && !wire.includes('repeated promotion') && !wire.includes('spam'),
  'blind relay cell exposes neither target, community, reason, nor note')
let annotated = (await alice.moderationMany([target], { view: MODERATION_VIEW.COMMUNITY }))[0]
ok(annotated.moderation.raw === 1 && annotated.moderation.eligible === 0,
  'an unendorsed member flag is retained but has no visibility authority')

await alice.vote(contribution.cid, 'commons', TYPE.POST, 1)
annotated = (await alice.moderationMany([target], { view: MODERATION_VIEW.COMMUNITY }))[0]
ok(annotated.moderation.eligible === 1 && annotated.moderation.bury === 1,
  'the same signed flag counts after its author becomes trust-connected')

await bob.reportContent('commons', {
  targetCid: target.cid,
  targetType: TYPE.POST,
  verdict: REPORT_VERDICT.KEEP,
  reason: 'other'
})
let reports = await alice.listReportsFor('commons', target.cid)
ok(reports.length === 1 && reports[0].verdict === REPORT_VERDICT.KEEP,
  'one author/target slot gives deterministic LWW bury-to-keep replacement')
await bob.withdrawReport('commons', target.cid)
reports = await alice.listReportsFor('commons', target.cid)
ok(reports.length === 1 && reports[0].deleted === true, 'withdrawal is a signed tombstone in the same slot')
annotated = (await alice.moderationMany([target], { view: MODERATION_VIEW.COMMUNITY }))[0]
ok(annotated.moderation.raw === 0 && annotated.moderation.eligible === 0, 'withdrawn reports no longer affect consensus')

console.log('\n— open algorithm registry and host-enforced downranking —')
ok(FEED_ALGORITHMS.length === 5 && FEED_ALGORITHMS.every(item => item.license === 'MIT' && item.source === './ranking.js'),
  'all built-in algorithms publish stable ids, versions, source modules, and license')
const ranked = rankFeedWindow([
  { cid: 'flagged', createdAt: 20, tally: { score: 100, weighted: 100 }, moderation: { visibility: VISIBILITY.DOWNRANKED } },
  { cid: 'normal', createdAt: 10, tally: { score: 1, weighted: 1 }, moderation: { visibility: VISIBILITY.VISIBLE } }
], 'top', 'all', 1, 25, 100)
ok(ranked.items.map(row => row.cid).join(',') === 'normal,flagged', 'host policy downranks before the selected algorithm orders its tier')
ok(ranked.algorithm.id === 'peerit.top.v1', 'rank result discloses the exact interchangeable algorithm manifest')

console.log(`\ncommunity-moderation: ${passed} checks passed`)
