// smoke.mjs — headless verification of peerit's core logic against the dev
// sync backend (which reimplements the bridge reducer). Exercises the full
// Reddit flow: communities, posts, threaded comments, votes, ranking, profiles,
// karma, and moderation (remove + ban). Run: node test/smoke.mjs

import assert from 'node:assert'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { Prefs } from '../js/prefs.js'
import { STARTER_COMMUNITIES, STARTER_POSTS, WELCOME_COMMUNITY, starterCommunity } from '../js/onboarding.js'
import { renderMarkdown, excerpt } from '../js/markdown.js'
import { sortPosts, hotScore, wilsonScore, controversyScore, tally } from '../js/ranking.js'
import { buildCommentTree, sortCommentTree, annotateDescendants, countDescendants, modOverlay, resolveMods } from '../js/model.js'
import { parseRoute, safeUserUrl } from '../js/util.js'
import { verify as verifyPow } from '../js/pow.js'
import {
  COPY as RECOVERY_COPY,
  assertRecoveryBundleMatches,
  buildRecoveryBundle,
  cleanOutboxes,
  compareRecoveryBundle,
  peeritSeederCommand,
  recoveryBundleFilename,
  recoveryBundleJson,
  shellArg
} from '../js/recovery.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }
const BITS = { community: 7, post: 6, comment: 5 }

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

async function main () {
  console.log('\n— pure logic —')
  ok(typeof hotScore(100, Date.now()) === 'number', 'hotScore returns a number')
  ok(wilsonScore(10, 0) > wilsonScore(1, 0), 'wilson rewards confident ratios')
  ok(controversyScore(50, 50) > controversyScore(100, 1), 'controversy peaks when balanced')
  const t = tally([{ author: 'a', value: 1 }, { author: 'b', value: 1 }, { author: 'a', value: -1 }], 'a')
  ok(t.score === 0 && t.up === 1 && t.down === 1 && t.myVote === -1, 'tally dedups last-write-per-author')
  const md = renderMarkdown('# Hi\n\n**bold** and <script>alert(1)</script> and [x](javascript:evil)')
  ok(!md.includes('<script>') && !md.includes('javascript:'), 'markdown escapes HTML + blocks unsafe links')
  ok(md.includes('<strong>bold</strong>'), 'markdown renders bold')
  ok(!renderMarkdown('[x](//evil.example)').includes('href="//evil.example"'), 'markdown blocks protocol-relative links')
  ok(renderMarkdown('[r](#/r/p2p)').includes('href="#/r/p2p"'), 'markdown allows in-app hash routes')
  ok(excerpt('## Heading\n\nsome **text** here', 10).length <= 11, 'excerpt strips + truncates')
  ok(safeUserUrl('https://holepunch.to') && !safeUserUrl('javascript:alert(1)') && !safeUserUrl('//evil.example'), 'safeUserUrl allows only intended schemes')
  ok(parseRoute('#/%E0%A4%A').path[0] === '%E0%A4%A', 'malformed hash routes do not throw')
  ok(WELCOME_COMMUNITY.slug === 'welcome' && starterCommunity('welcome') === WELCOME_COMMUNITY, 'onboarding exposes a welcome community')
  ok(new Set(STARTER_COMMUNITIES.map(c => c.slug)).size === STARTER_COMMUNITIES.length, 'starter community slugs are unique')
  ok(STARTER_COMMUNITIES.every(c => /^[a-z0-9_]{2,24}$/.test(c.slug)), 'starter community slugs are valid')
  ok(STARTER_POSTS.every(p => starterCommunity(p.community)), 'starter posts point at starter communities')

  console.log('\n— recovery bundle helpers —')
  const pub = 'a'.repeat(64)
  const drive = 'b'.repeat(64)
  const invite = 'c'.repeat(64)
  const outboxes = cleanOutboxes([{ appId: pub, inviteKey: invite }, { appId: 'bad', inviteKey: invite }])
  const bundle = buildRecoveryBundle({ publicKey: pub, driveKey: drive, outboxes, createdAt: '2026-06-23T00:00:00.000Z' })
  ok(bundle.version === 1 && bundle.app === 'peerit' && bundle.outboxes.length === 1, 'recovery bundle has the documented shape')
  ok(compareRecoveryBundle(bundle, { publicKey: pub, driveKey: drive }).ok, 'recovery bundle comparison accepts matching app identity')
  assert.throws(() => assertRecoveryBundleMatches({ ...bundle, driveKey: 'e'.repeat(64) }, { publicKey: pub, driveKey: drive }), /different app drive key/)
  ok(true, 'recovery bundle comparison rejects a different drive key')
  assert.throws(() => assertRecoveryBundleMatches({ ...bundle, publicKey: 'd'.repeat(64) }, { publicKey: pub, driveKey: drive }), /different app identity/)
  ok(true, 'recovery bundle comparison rejects a different public key')
  ok(recoveryBundleJson(bundle).includes('"outboxes"') && recoveryBundleFilename(bundle).startsWith('peerit-app-data-recovery-aaaaaaaaaaaa-2026-06-23'), 'recovery bundle serializes with a stable filename')
  ok(peeritSeederCommand(outboxes) === `cd ../peerit-seeder\nnode seeder.mjs ${invite}`, 'seeder command is ready for peerit-seeder')
  ok(shellArg("abc def'ghi") === "'abc def'\"'\"'ghi'", 'shellArg quotes unusual command arguments')
  ok(RECOVERY_COPY.identityBackup === 'Your identity lives in PearBrowser. Back up your 12-word PearBrowser recovery phrase. peerit/p2pbuilders only see an app-specific public key and cannot recover this phrase for you.', 'identity backup warning copy matches protocol')

  console.log('\n— data layer (dev backend) —')
  const storage = mem()
  const sync = new DevSync(storage, 'test')
  await sync.ready()
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  const data = createData(sync, id, { minBits: BITS })
  const alice = data.me().pubkey

  // community
  const c = await data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'serverless' })
  ok(c.slug === 'p2p' && c.creator === alice, 'alice creates r/p2p as founder')
  ok(await verifyPow('community', c, BITS.community), 'community creation includes valid proof-of-work')
  await assert.rejects(() => data.createCommunity({ slug: 'p2p' }), /already exists/)
  ok(true, 'duplicate community rejected')
  await assert.rejects(() => data.createCommunity({ slug: 'a' }), /2–24/)
  ok(true, 'invalid slug rejected')

  // posts
  const p1 = await data.submitPost({ community: 'p2p', kind: 'text', title: 'First post', body: 'hello **world**' })
  const p2 = await data.submitPost({ community: 'p2p', kind: 'link', title: 'A link', url: 'https://holepunch.to' })
  ok(await verifyPow('post', p1, BITS.post), 'post creation includes valid proof-of-work')
  await assert.rejects(() => data.submitPost({ community: 'p2p', kind: 'link', title: 'Bad link', url: 'javascript:alert(1)' }), /URL must start/)
  ok(true, 'unsafe post URLs are rejected at creation')
  ok((await data.listPostsIn('p2p')).length === 2, 'two posts listed in r/p2p')
  const got = await data.getPost('p2p', p1.cid)
  ok(got && got.title === 'First post', 'getPost round-trips')

  // comments (threaded)
  const cm1 = await data.addComment({ community: 'p2p', postCid: p1.cid, body: 'top-level' })
  const cm2 = await data.addComment({ community: 'p2p', postCid: p1.cid, parentCid: cm1.cid, body: 'reply to top' })
  ok(await verifyPow('comment', cm1, BITS.comment), 'comment creation includes valid proof-of-work')
  await data.addComment({ community: 'p2p', postCid: p1.cid, body: 'another top-level' })
  const comments = await data.listComments('p2p', p1.cid)
  ok(comments.length === 3, 'three comments stored')
  const { roots } = buildCommentTree(comments)
  ok(roots.length === 2 && roots.find(r => r.cid === cm1.cid).children.length === 1, 'comment tree nests replies')

  // votes (LWW per identity)
  await data.vote(p1.cid, 'p2p', 'post', 1)
  let tp = await data.tallyFor(p1.cid)
  ok(tp.score === 1 && tp.myVote === 1, 'alice upvote counts once')
  await data.vote(p1.cid, 'p2p', 'post', 1) // toggling same dir again still 1 record
  tp = await data.tallyFor(p1.cid)
  ok(tp.score === 1, 're-upvoting is idempotent (one vote per user)')
  await data.vote(p1.cid, 'p2p', 'post', -1)
  tp = await data.tallyFor(p1.cid)
  ok(tp.score === -1 && tp.myVote === -1, 'switching vote overwrites previous')

  // second user
  const bob = (await id.createUser('bob')).pubkey
  ok(data.me().pubkey === bob && bob !== alice, 'switched to bob')
  await data.vote(p1.cid, 'p2p', 'post', 1)
  tp = await data.tallyFor(p1.cid)
  ok(tp.score === 0 && tp.up === 1 && tp.down === 1, 'bob upvote + alice downvote => score 0')
  const bc = await data.addComment({ community: 'p2p', postCid: p1.cid, body: 'bob was here' })

  // ranking
  await data.vote(p2.cid, 'p2p', 'post', 1)
  let posts = await data.withTallies(await data.listPostsIn('p2p'))
  const top = sortPosts(posts, 'top')
  ok(top[0].cid === p2.cid, 'top sort puts higher score first')

  // profiles + karma
  id.switchUser(alice)
  await data.setProfile({ name: 'alice', bio: 'builds p2p things' })
  ok((await data.displayName(alice)) === 'alice', 'display name resolves from profile')
  const karma = await data.karmaFor(alice)
  ok(typeof karma.total === 'number' && karma.postCount === 2, 'karma counts alice posts')

  // moderation: alice (founder) removes bob's comment
  const mods = await data.getMods('p2p')
  ok(mods.has(alice) && !mods.has(bob), 'founder is the sole mod')
  await data.removePost('p2p', bc.cid, 'spam')
  const ov = await data.overlay('p2p')
  ok(ov.removed.has(bc.cid), 'mod removal recorded in overlay')

  // mod chain: alice adds bob as mod, bob can then act
  await data.addMod('p2p', bob)
  const mods2 = await data.getMods('p2p')
  ok(mods2.has(bob), 'added mod appears in mod set')
  id.switchUser(bob)
  await data.toggleLock('p2p', p1.cid, false) // bob locks the thread
  const ov2 = await data.overlay('p2p')
  ok(ov2.locked.has(p1.cid), 'newly-added mod can lock a thread')
  await assert.rejects(() => data.addComment({ community: 'p2p', postCid: p1.cid, body: 'x' }), /locked/)
  ok(true, 'commenting on a locked thread is blocked')

  // ban enforcement
  id.switchUser(alice)
  const carol = (await id.createUser('carol')).pubkey
  id.switchUser(alice)
  await data.banUser('p2p', carol, 'rule 1')
  id.switchUser(carol)
  await assert.rejects(() => data.submitPost({ community: 'p2p', kind: 'text', title: 'hi' }), /banned/)
  ok(true, 'banned user cannot post')

  // overlay honors only real mods (forged mod action by non-mod ignored)
  const forged = modOverlay(c, [{ action: 'remove', targetCid: p2.cid, by: carol, ts: Date.now() }])
  ok(!forged.removed.has(p2.cid), 'mod action by non-moderator is ignored')

  console.log('\n— edits, deletes, profile, sort, prefs —')
  // author edit/delete
  id.switchUser(alice)
  await data.editPost('p2p', p1.cid, 'edited body **bold**')
  const ep = await data.getPost('p2p', p1.cid)
  ok(ep.body.includes('edited body') && ep.editedAt > 0, 'author can edit own post')
  id.switchUser(bob)
  await assert.rejects(() => data.editPost('p2p', p1.cid, 'hax'), /your own/)
  ok(true, 'non-author cannot edit a post')
  await data.deleteComment('p2p', p1.cid, bc.cid)
  const delc = await sync.get(`comment!p2p!${p1.cid}!${bc.cid}`)
  ok(delc.deleted === true && delc.body === '', 'author soft-deletes own comment (body cleared)')

  // mod approve clears removal; unban restores posting
  id.switchUser(alice)
  await data.approvePost('p2p', bc.cid)
  const ov3 = await data.overlay('p2p')
  ok(!ov3.removed.has(bc.cid), 'mod approve clears a removal')
  await data.unbanUser('p2p', carol)
  id.switchUser(carol)
  const cp = await data.submitPost({ community: 'p2p', kind: 'text', title: 'carol is back' })
  ok(cp && !cp.deleted, 'unbanned user can post again')

  // profile activity
  id.switchUser(alice)
  const act = await data.userActivity(alice)
  ok(act.posts.length >= 2 && Array.isArray(act.comments), 'userActivity returns posts + comments')

  // sort correctness
  const ps = await data.withTallies(await data.listPostsIn('p2p'))
  const byNew = sortPosts(ps, 'new')
  ok(byNew.every((p, i, a) => i === 0 || a[i - 1].createdAt >= p.createdAt), 'new sort is reverse-chronological')
  const byTop = sortPosts(ps, 'top')
  ok(byTop.every((p, i, a) => i === 0 || a[i - 1].tally.score >= p.tally.score), 'top sort is by descending score')

  // dev reducer key parity with the bridge generic fallback (type!data.id)
  await sync.append({ type: 'post', data: { id: 'kk!zz', cid: 'zz', community: 'kk', title: 't' } })
  const direct = await sync.get('post!kk!zz')
  ok(direct && direct.cid === 'zz', 'dev reducer keys op at type!data.id (bridge parity)')

  // local prefs
  const pf = new Prefs(mem(), 'tester')
  pf.subscribe('p2p'); ok(pf.isSubscribed('p2p') && !pf.isSubscribed('nope'), 'prefs: subscribe')
  pf.toggleSaved('p2p/abc'); ok(pf.isSaved('p2p/abc'), 'prefs: save')
  pf.toggleHidden('p2p/xyz'); ok(pf.isHidden('p2p/xyz'), 'prefs: hide')
  pf.toggleSaved('p2p/abc'); ok(!pf.isSaved('p2p/abc'), 'prefs: toggle off')
  pf.markWelcomeSeen(); ok(pf.seenWelcome, 'prefs: welcome can be dismissed')
  pf.markWelcomeUnseen(); ok(!pf.seenWelcome, 'prefs: welcome can be shown again')
  pf.acknowledgeIdentityBackup(); ok(pf.identityBackupAcked, 'prefs: identity backup acknowledgement persists')

  // markdown extras
  const md2 = renderMarkdown('```\ncode\n```\n\n- a\n- b\n\n> quote\n\n[hp](https://holepunch.to)')
  ok(md2.includes('<pre><code>') && md2.includes('<ul>') && md2.includes('<blockquote>') && md2.includes('href="https://holepunch.to"'), 'markdown renders code/list/quote/link')

  console.log('\n— optimization invariants: comment tree —')
  const flatCids = (roots) => { const out = []; const walk = n => { out.push(n.cid); n.children.forEach(walk) }; roots.forEach(walk); return out }
  // A malicious parentCid cycle (A<->B) must not drop nodes or recurse forever.
  const cyc = buildCommentTree([
    { cid: 'A', parentCid: 'B', community: 'x' },
    { cid: 'B', parentCid: 'A', community: 'x' }
  ])
  const cf = flatCids(cyc.roots)
  ok(cf.length === 2 && new Set(cf).size === 2, 'comment tree with a parentCid cycle keeps every node exactly once (no loss)')
  const csorted = sortCommentTree(cyc.roots, (n) => n.slice())
  annotateDescendants(csorted)
  ok(csorted.reduce((s, n) => s + 1 + n._descendants, 0) === 2, 'sort + descendant annotation terminate on cyclic input')
  // Deep linear chain builds, counts correctly, and the memoized count matches.
  const N = 500
  const chain = []
  for (let i = 0; i < N; i++) chain.push({ cid: 'n' + i, parentCid: i ? 'n' + (i - 1) : null, community: 'x' })
  const deep = buildCommentTree(chain)
  const dsorted = sortCommentTree(deep.roots, (n) => n.slice())
  annotateDescendants(dsorted)
  ok(deep.roots.length === 1 && dsorted[0]._descendants === N - 1, `deep ${N}-level chain builds with one root + ${N - 1} descendants`)
  ok(countDescendants(dsorted[0]) === dsorted[0]._descendants, 'annotateDescendants matches countDescendants exactly')

  console.log('\n— optimization invariants: ranking determinism —')
  const nowR = Date.now()
  // Both posts are >24h old → risingScore is -Infinity for both → comparator
  // would be NaN without the createdAt tiebreaker; assert newest-first order.
  const agedOut = sortPosts([
    { cid: 'old', createdAt: nowR - 48 * 3600000, tally: { score: 3, up: 3, down: 0 }, stickied: false },
    { cid: 'new', createdAt: nowR - 25 * 3600000, tally: { score: 3, up: 3, down: 0 }, stickied: false }
  ], 'rising', 'all', nowR)
  ok(agedOut[0].cid === 'new', 'rising deterministically orders aged-out (-Infinity) posts newest-first via tiebreaker')

  console.log('\n— optimization invariants: targeted scans + cache decoupling —')
  {
    const s2 = new DevSync(mem(), 'opt'); await s2.ready()
    const id2 = new DevIdentity(mem(), mem()); await id2.ready()
    const d2 = createData(s2, id2, { minBits: BITS })
    await d2.createCommunity({ slug: 'opt', title: 'Opt', description: '' })
    const pa = await d2.submitPost({ community: 'opt', kind: 'text', title: 'Alpha', body: 'a' })
    const pb = await d2.submitPost({ community: 'opt', kind: 'text', title: 'Beta', body: 'b' })
    await d2.vote(pa.cid, 'opt', 'post', 1)
    await d2.vote(pb.cid, 'opt', 'post', -1)
    await d2.addComment({ community: 'opt', postCid: pa.cid, body: 'c1' })
    await d2.addComment({ community: 'opt', postCid: pa.cid, body: 'c2' })
    // tallyMany (per-target prefix scan) matches per-target tallyFor.
    const many = await d2.tallyMany([pa.cid, pb.cid])
    const ta = await d2.tallyFor(pa.cid), tb = await d2.tallyFor(pb.cid)
    ok(many.get(pa.cid).score === ta.score && many.get(pb.cid).score === tb.score && ta.score === 1 && tb.score === -1, 'tallyMany (per-target scan) matches tallyFor on every target')
    // commentCountsFor (per-post prefix scan) matches listComments length.
    const counts = await d2.commentCountsFor(await d2.listPostsIn('opt'))
    ok(counts.get(pa.cid) === (await d2.listComments('opt', pa.cid)).length && counts.get(pa.cid) === 2, 'commentCountsFor (per-post scan) matches listComments length')
    ok(counts.get(pb.cid) === 0, 'commentCountsFor returns 0 for a post with no comments')
    // search index is decoupled from vote churn.
    ok((await d2.search('Alpha')).posts.some(p => p.cid === pa.cid), 'search finds post by title')
    const idxBefore = d2._searchIndex
    await d2.vote(pa.cid, 'opt', 'post', -1)
    ok(d2._searchIndex === idxBefore && idxBefore !== null, 'a vote does NOT rebuild the search index (content unchanged)')
    ok((await d2.tallyFor(pa.cid)).score === -1, 'the vote still updated the tally (cache correctly invalidated)')
    await d2.submitPost({ community: 'opt', kind: 'text', title: 'Gamma', body: 'g' })
    ok(d2._searchIndex === null, 'a new post DOES invalidate the search index')
  }

  console.log('\n— status —')
  const st = await sync.status()
  ok(st.viewLength > 0, 'view has records (' + st.viewLength + ')')

  console.log(`\n✅ all ${passed} checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
