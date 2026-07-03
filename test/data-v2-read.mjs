// data-v2-read.mjs — slice 4c: the Opaque-Log v2 READ model in data.js. Writes a
// full community/post/comment/vote set through a { v2:true } Data instance (so the
// outbox holds only opaque sealed records) and reads it ALL back through the normal
// domain API — feed, thread, vote tally, community list — proving aggregation happens
// entirely in the client by decrypting + reconstructing each record. This is the
// "no relay-side index" property working end-to-end.
//   node test/data-v2-read.mjs

import assert from 'node:assert'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'

const BITS = { community: 4, post: 4, comment: 4, vote: 4, profile: 4, modaction: 4 }
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

async function newUser (v2) {
  const sync = new DevSync(memoryStorage(), 'v2-read'); await sync.ready()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser('alice')
  return { data: createData(sync, id, { minBits: BITS, v2 }), sync, me: id.me().pubkey }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')
  const { data, sync } = await newUser(true)

  await data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'the peer stack' })
  const p1 = await data.submitPost({ community: 'p2p', kind: 'text', title: 'First', body: 'hello world' })
  const p2 = await data.submitPost({ community: 'p2p', kind: 'text', title: 'Second', body: 'another body' })

  // sanity: the outbox really is opaque (no plaintext keys, no greppable content)
  const raw = await sync.list('', { limit: 100 })
  ok(raw.every(r => r.key.startsWith('v2!')) && raw.length >= 3, 'every stored row is an opaque v2!<okey> record')
  ok(!JSON.stringify(raw).includes('hello world'), 'no post body is greppable anywhere in the raw outbox')

  console.log('\n— feed (client-aggregated) —')
  const posts = await data.listPostsIn('p2p')
  ok(posts.length === 2, 'listPostsIn aggregates BOTH posts out of opaque records')
  ok(posts.some(p => p.title === 'First' && p.body === 'hello world'), 'a listed post carries its decrypted title + body')
  const got = await data.getPost('p2p', p1.cid)
  ok(got && got.title === 'First' && got.body === 'hello world' && got.community === 'p2p', 'getPost returns the fully decrypted post')

  console.log('\n— thread (spans records) —')
  const c1 = await data.addComment({ community: 'p2p', postCid: p1.cid, body: 'nice post' })
  await data.addComment({ community: 'p2p', postCid: p1.cid, parentCid: c1.cid, body: 'agreed' })
  const comments = await data.listComments('p2p', p1.cid)
  ok(comments.length === 2, 'listComments aggregates the thread from opaque records')
  ok(comments.some(c => c.body === 'nice post') && comments.some(c => c.body === 'agreed' && c.parentCid === c1.cid), 'comments decrypt with body + parentCid (thread structure preserved)')

  console.log('\n— votes (tally) —')
  await data.vote(p1.cid, 'p2p', 'post', 1)
  const t = await data.tallyFor(p1.cid)
  ok(t && t.score === 1, 'tallyFor aggregates the upvote from the opaque vote record (score 1)')

  console.log('\n— community list —')
  const comms = await data.listCommunities()
  ok(comms.some(c => c.slug === 'p2p' && c.title === 'P2P'), 'listCommunities returns the community (slug cleartext, title decrypted)')

  console.log(`\n✅ all ${passed} data-v2-read checks passed`)
}
main().catch(e => { console.error(e); process.exit(1) })
