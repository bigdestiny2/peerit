// materialized-index.mjs — local graph/feed index regression coverage.
// Proves the index is rebuildable from Peerit's normal v2 view, preserves the
// dual-direction social graph, and serves repeated reads without another source
// range scan during the same view epoch.

import assert from 'node:assert'
import { MaterializedIndex } from '../js/materialized-index.js'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'

const BITS = { community: 4, post: 4, comment: 4, vote: 4, profile: 4, modaction: 4 }
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }

async function identity (name) {
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  return id
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')

  console.log('\n— pure index: bidirectional edges + LWW replacement —')
  const index = new MaterializedIndex()
  index.upsert('follow!alice!bob', { _t: 'follow', target: 'alice', author: 'bob', ts: 1 })
  index.upsert('member!p2p!bob', { _t: 'member', community: 'p2p', author: 'bob', ts: 1 })
  ok(index.followersOf('alice').join() === 'bob' && index.followingOf('bob').join() === 'alice', 'follow edge is available in both directions')
  ok(index.membersOf('p2p').join() === 'bob' && index.membershipsOf('bob').join() === 'p2p', 'membership edge is available in both directions')
  index.upsert('follow!alice!bob', { _t: 'follow', target: 'alice', author: 'bob', deleted: true, ts: 2 })
  index.upsert('member!p2p!bob', { _t: 'member', community: 'p2p', author: 'bob', deleted: true, ts: 2 })
  ok(index.followersOf('alice').length === 0 && index.followingOf('bob').length === 0, 'follow tombstone removes both derived edges')
  ok(index.membersOf('p2p').length === 0 && index.membershipsOf('bob').length === 0, 'membership tombstone removes both derived edges')
  index.upsert('post!p2p!legacy', { _t: 'follow', community: 'p2p', cid: 'legacy', author: 'bob' })
  ok(index.listPostsIn('p2p').some(row => row.cid === 'legacy') && index.followersOf('alice').length === 0,
    'the semantic storage key, not an arbitrary legacy _t field, determines index type')

  console.log('\n— Data integration: one source build, many indexed reads —')
  const sync = new DevSync(memoryStorage(), 'materialized-index')
  await sync.ready()
  let rangeReads = 0
  const originalRange = sync.range.bind(sync)
  sync.range = async (opts) => { rangeReads++; return originalRange(opts) }
  const alice = await identity('alice')
  const bob = await identity('bob')
  const data = createData(sync, alice, { minBits: BITS, v2: true })

  await data.createCommunity({ slug: 'p2p', title: 'P2P' })
  const post = await data.submitPost({ community: 'p2p', kind: 'text', title: 'Indexed', body: 'source of truth stays signed' })
  await data.addComment({ community: 'p2p', postCid: post.cid, body: 'thread edge' })

  // A second author writes graph edges into the same test world. Data's v2 reader
  // indexes the resulting merged view rather than trusting this local index as a
  // transport source.
  const bobData = createData(sync, bob, { minBits: BITS, v2: true })
  await bobData.setFollow(alice.me().pubkey)
  await bobData.setMembership('p2p')
  data.invalidateViewCaches()

  const posts = await data.listPostsIn('p2p', { hydrate: false })
  const readsAfterBuild = rangeReads
  ok(posts.length === 1 && posts[0].cid === post.cid, 'community feed rebuilds from opaque signed records')
  ok((await data.listComments('p2p', post.cid, { hydrate: false })).length === 1, 'thread uses the derived post adjacency')
  ok((await data.followersOf(alice.me().pubkey)).includes(bob.me().pubkey), 'inbound social lookup uses the derived edge')
  ok((await data.followingOf(bob.me().pubkey)).includes(alice.me().pubkey), 'outbound social lookup uses the reverse derived edge')
  ok((await data.membersOf('p2p')).includes(bob.me().pubkey), 'community membership lookup uses the derived edge')
  ok(rangeReads === readsAfterBuild, 'repeated graph/feed reads reuse one materialized source epoch')
  ok((await bobData.myMemberships()).includes('p2p'), 'author membership lookup uses the reverse derived edge')

  console.log('\n— local writes patch the existing derived view —')
  await data.vote(post.cid, 'p2p', 'post', 1)
  const readsAfterVote = rangeReads
  ok((await data.tallyFor(post.cid)).score === 1, 'local vote is visible through the patched vote adjacency')
  ok(rangeReads === readsAfterVote, 'local vote advances the index epoch without a global source rebuild')
  const second = await data.submitPost({ community: 'p2p', kind: 'text', title: 'Second indexed post', body: 'still signed at source' })
  const readsAfterPost = rangeReads
  ok((await data.listPostsIn('p2p', { hydrate: false })).some(row => row.cid === second.cid), 'local post is visible through the patched feed adjacency')
  ok(rangeReads === readsAfterPost, 'local post advances the index epoch without a global source rebuild')

  console.log(`\n✅ all ${passed} materialized-index checks passed`)
}

main().catch(error => { console.error(error); process.exit(1) })
