// smoke.mjs — headless verification of peerit's core logic against the dev
// sync backend (which reimplements the bridge reducer). Exercises the full
// Reddit flow: communities, posts, threaded comments, votes, ranking, profiles,
// karma, and moderation (remove + ban). Run: node test/smoke.mjs

import assert from 'node:assert'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { Prefs } from '../js/prefs.js'
import { renderMarkdown, excerpt } from '../js/markdown.js'
import { sortPosts, hotScore, wilsonScore, controversyScore, tally } from '../js/ranking.js'
import { buildCommentTree, sortCommentTree, modOverlay, resolveMods } from '../js/model.js'
import { parseRoute, safeUserUrl } from '../js/util.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

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

  console.log('\n— data layer (dev backend) —')
  const storage = mem()
  const sync = new DevSync(storage, 'test')
  await sync.ready()
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  const data = createData(sync, id)
  const alice = data.me().pubkey

  // community
  const c = await data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'serverless' })
  ok(c.slug === 'p2p' && c.creator === alice, 'alice creates r/p2p as founder')
  await assert.rejects(() => data.createCommunity({ slug: 'p2p' }), /already exists/)
  ok(true, 'duplicate community rejected')
  await assert.rejects(() => data.createCommunity({ slug: 'a' }), /2–24/)
  ok(true, 'invalid slug rejected')

  // posts
  const p1 = await data.submitPost({ community: 'p2p', kind: 'text', title: 'First post', body: 'hello **world**' })
  const p2 = await data.submitPost({ community: 'p2p', kind: 'link', title: 'A link', url: 'https://holepunch.to' })
  await assert.rejects(() => data.submitPost({ community: 'p2p', kind: 'link', title: 'Bad link', url: 'javascript:alert(1)' }), /URL must start/)
  ok(true, 'unsafe post URLs are rejected at creation')
  ok((await data.listPostsIn('p2p')).length === 2, 'two posts listed in r/p2p')
  const got = await data.getPost('p2p', p1.cid)
  ok(got && got.title === 'First post', 'getPost round-trips')

  // comments (threaded)
  const cm1 = await data.addComment({ community: 'p2p', postCid: p1.cid, body: 'top-level' })
  const cm2 = await data.addComment({ community: 'p2p', postCid: p1.cid, parentCid: cm1.cid, body: 'reply to top' })
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

  // markdown extras
  const md2 = renderMarkdown('```\ncode\n```\n\n- a\n- b\n\n> quote\n\n[hp](https://holepunch.to)')
  ok(md2.includes('<pre><code>') && md2.includes('<ul>') && md2.includes('<blockquote>') && md2.includes('href="https://holepunch.to"'), 'markdown renders code/list/quote/link')

  console.log('\n— status —')
  const st = await sync.status()
  ok(st.viewLength > 0, 'view has records (' + st.viewLength + ')')

  console.log(`\n✅ all ${passed} checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
