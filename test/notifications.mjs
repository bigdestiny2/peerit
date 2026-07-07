// notifications.mjs — the inbox (Slice 2): a PURE client-side scan for replies to
// your posts + comments. No new record type, no relay change. Proves the scan
// picks up top-level replies to your posts and nested replies to your comments,
// ignores your own / deleted / unrelated comments, hydrates the reply body (v2
// sealed), sorts newest-first, and that unreadCount respects the device-local
// read marker.
//   node test/notifications.mjs

import assert from 'node:assert'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'

const BITS = { community: 4, post: 4, comment: 4, vote: 4, profile: 4, modaction: 4 }
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const fresh = (u) => u.data.invalidateViewCaches('content') // what sync.onChange does in the app

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend available')
  const store = memoryStorage()
  const mk = async (name) => {
    const sync = new DevSync(store, 'notif'); await sync.ready()
    const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
    return { sync, id, data: createData(sync, id, { minBits: BITS, v2: true }), me: id.me().pubkey }
  }
  const alice = await mk('alice'); const bob = await mk('bob'); const carol = await mk('carol')

  // Alice creates a community + a post + a comment of her own.
  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'inbox test' })
  fresh(bob); fresh(carol)
  const aPost = await alice.data.submitPost({ community: 'p2p', kind: 'text', title: 'my post', body: 'hi' })
  const aComment = await alice.data.addComment({ community: 'p2p', postCid: aPost.cid, body: 'my own comment' })

  console.log('\n— replies generate notifications —')
  fresh(bob)
  const bReply = await bob.data.addComment({ community: 'p2p', postCid: aPost.cid, body: 'nice post!' }) // top-level → reply to alice POST
  const bNested = await bob.data.addComment({ community: 'p2p', postCid: aPost.cid, parentCid: aComment.cid, body: 'good point' }) // → reply to alice COMMENT
  fresh(alice)
  const notes = await alice.data.notificationsFor()
  ok(notes.length === 2, `alice has 2 notifications (got ${notes.length})`)
  const post = notes.find(n => n.on === 'post'); const comment = notes.find(n => n.on === 'comment')
  ok(post && post.from === bob.me && post.cid === bReply.cid, 'a top-level comment on alice\'s POST notifies her (on:post)')
  ok(comment && comment.from === bob.me && comment.cid === bNested.cid, 'a nested reply to alice\'s COMMENT notifies her (on:comment)')
  ok(post.body === 'nice post!' && comment.body === 'good point', 'the reply body is hydrated (decrypted from the sealed v2 record)')
  ok(post.postTitle === 'my post', 'the notification carries the post title for context')

  console.log('\n— the scan does not over-notify —')
  ok((await alice.data.notificationsFor()).every(n => n.from !== alice.me), 'alice is never notified about her own comments')
  // carol replies to BOB's top-level comment — that notifies BOB, not alice.
  fresh(carol)
  await carol.data.addComment({ community: 'p2p', postCid: aPost.cid, parentCid: bReply.cid, body: 'i agree' })
  fresh(alice); fresh(bob)
  ok((await alice.data.notificationsFor()).length === 2, 'a reply to BOB\'s comment does NOT notify alice')
  ok((await bob.data.notificationsFor()).some(n => n.from === carol.me), 'it DOES notify bob (whose comment was replied to)')

  console.log('\n— deletion + ordering + unread marker —')
  ok(notes[0].ts >= notes[1].ts, 'notifications are sorted newest-first')
  fresh(bob)
  await bob.data.deleteComment('p2p', aPost.cid, bReply.cid) // soft-delete bob's reply-to-post
  fresh(alice)
  ok((await alice.data.notificationsFor()).length === 1, 'a deleted reply drops out of the inbox')
  const remaining = await alice.data.notificationsFor()
  const marker = remaining[0].ts
  ok((await alice.data.unreadCount(0)) === 1, 'unreadCount(0) = 1 (all unread)')
  ok((await alice.data.unreadCount(marker)) === 0, 'unreadCount(marker) = 0 once the newest is marked seen')

  console.log(`\n✅ all ${passed} notification checks passed`)
  process.exit(0)
}
main().catch((e) => { console.error('\n❌ notifications FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
