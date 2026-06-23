// gossip.mjs — verifies the post-audit gossip layer: signature is the sole
// authority, the transport label carries none. Covers convergence, cross-outbox
// votes/moderation, edit propagation, and — critically — that forged/tampered
// records are rejected EVEN when relayed under a victim's outbox label.
// Run: node test/gossip.mjs

import assert from 'node:assert'
import { GossipSync, makeHub, mergeOutboxes } from '../js/gossip.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { canonical } from '../js/canon.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}
// Attach a real signature from `id` to a record (mirrors data._sign).
async function sign (id, type, data) {
  const s = await id.sign(canonical(type, data))
  return { ...data, _sig: s.signature, _k: s.publicKey, _dk: s.driveKey, _ns: s.namespace, _alg: s.algorithm }
}
async function makePeer (hub, name) {
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const sync = new GossipSync({ storage: mem(), bus: hub.connect(), getMe: () => id.me().pubkey })
  await sync.ready()
  return { id, sync, data: createData(sync, id), pub: id.me().pubkey, name }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'real crypto backend available (signatures are enforced)')

  console.log('\n— merge: signature is the authority —')
  const aid = new DevIdentity(mem(), mem()); await aid.ready(); const A = aid.me().pubkey
  const mal = new DevIdentity(mem(), mem()); await mal.ready(); const M = mal.me().pubkey

  const comm = await sign(aid, 'community', { id: 'p2p', slug: 'p2p', creator: A, createdAt: 1000, title: 'P2P', description: '' })
  ok((await mergeOutboxes([{ pub: A, view: { 'community!p2p': comm } }]))['community!p2p'], 'legit signed record is honored')

  // The exact bypass the audit found: relay a forged record under the victim's label.
  let forged = await sign(mal, 'post', { id: 'p2p!x', cid: 'x', community: 'p2p', kind: 'text', title: 'FAKE', author: A, createdAt: 1, editedAt: 0, deleted: false })
  ok(!(await mergeOutboxes([{ pub: A, view: { 'post!p2p!x': forged } }]))['post!p2p!x'], 'forged post (author=A, signed by attacker), relayed as pub=A, is REJECTED')
  // Attacker also lies about the signer key:
  const forged2 = { ...forged, _k: A }
  ok(!(await mergeOutboxes([{ pub: A, view: { 'post!p2p!x': forged2 } }]))['post!p2p!x'], 'forged post claiming _k=A but with an invalid signature is REJECTED')

  // Tamper after signing.
  const tampered = { ...comm, title: 'HIJACK' }
  ok(!(await mergeOutboxes([{ pub: A, view: { 'community!p2p': tampered } }]))['community!p2p'], 'tampered record (content changed post-sign) is rejected')

  // Key binding: a valid record parked under the wrong key.
  ok(!(await mergeOutboxes([{ pub: A, view: { 'community!evil': comm } }]))['community!evil'], 'record under a mismatched storage key is rejected (key binding)')

  // Relaying someone ELSE's validly-signed record is fine (you can't forge it).
  ok((await mergeOutboxes([{ pub: M, view: { 'community!p2p': comm } }]))['community!p2p'], "a peer relaying A's validly-signed record is honored (transport label is not authority)")

  // Deterministic community winner (earliest createdAt), order-independent.
  const bid = new DevIdentity(mem(), mem()); await bid.ready(); const B = bid.me().pubkey
  const cA = await sign(aid, 'community', { id: 'dup', slug: 'dup', creator: A, createdAt: 500, title: 'A', description: '' })
  const cB = await sign(bid, 'community', { id: 'dup', slug: 'dup', creator: B, createdAt: 200, title: 'B', description: '' })
  const w1 = (await mergeOutboxes([{ pub: A, view: { 'community!dup': cA } }, { pub: B, view: { 'community!dup': cB } }]))['community!dup']
  const w2 = (await mergeOutboxes([{ pub: B, view: { 'community!dup': cB } }, { pub: A, view: { 'community!dup': cA } }]))['community!dup']
  ok(w1.creator === B && w2.creator === B, 'earliest-createdAt community wins, regardless of merge order')

  // Robustness: malformed records and prototype-pollution keys do not crash/poison.
  const junk = await mergeOutboxes([{ pub: A, view: { 'post!p2p!n': null, '__proto__': { x: 1 }, 'community!p2p': comm } }])
  ok(junk['community!p2p'] && !({}).x, 'null records + __proto__ key are skipped safely')

  console.log('\n— community ownership is sticky (no hijack) —')
  const claimed = {}
  const own = await sign(aid, 'community', { id: 'own', slug: 'own', creator: A, createdAt: 5000, title: 'A owns', description: '' })
  let mm = await mergeOutboxes([{ pub: A, view: { 'community!own': own } }], claimed)
  ok(mm['community!own'].creator === A && claimed.own === A, 'first claim locks r/own to creator A')
  const hijack = await sign(bid, 'community', { id: 'own', slug: 'own', creator: B, createdAt: 0, title: 'B HIJACK', description: '' })
  mm = await mergeOutboxes([{ pub: A, view: { 'community!own': own } }, { pub: B, view: { 'community!own': hijack } }], claimed)
  ok(mm['community!own'].creator === A, 'attacker with createdAt:0 cannot hijack an established community (sticky)')

  console.log('\n— tombstones: deletes are not resurrected —')
  const live = await sign(aid, 'post', { id: 'p2p!t', cid: 't', community: 'p2p', kind: 'text', title: 'T', body: 'live', url: '', author: A, createdAt: 100, editedAt: 0, deleted: false })
  const dead = await sign(aid, 'post', { id: 'p2p!t', cid: 't', community: 'p2p', kind: 'text', title: 'T', body: '', url: '', author: A, createdAt: 100, editedAt: 0, deleted: true })
  const r1 = await mergeOutboxes([{ pub: A, view: { 'post!p2p!t': live } }, { pub: A, view: { 'post!p2p!t': dead } }])
  const r2 = await mergeOutboxes([{ pub: A, view: { 'post!p2p!t': dead } }, { pub: A, view: { 'post!p2p!t': live } }])
  ok(r1['post!p2p!t'].deleted === true && r2['post!p2p!t'].deleted === true, 'tombstone wins an equal-timestamp tie regardless of order')

  console.log('\n— 3-peer convergence —')
  const hub = makeHub()
  const alice = await makePeer(hub, 'alice')
  const bob = await makePeer(hub, 'bob')
  const carol = await makePeer(hub, 'carol')

  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'serverless' })
  ok(await bob.data.getCommunity('p2p'), 'bob sees the community alice created')
  ok(await carol.data.getCommunity('p2p'), 'carol sees it too (gossip convergence)')

  const post = await bob.data.submitPost({ community: 'p2p', kind: 'text', title: 'bob posts', body: 'hi' })
  ok((await alice.data.listPostsIn('p2p')).some(p => p.cid === post.cid), "alice sees bob's post")
  const cm = await carol.data.addComment({ community: 'p2p', postCid: post.cid, body: 'nice' })
  ok((await alice.data.listComments('p2p', post.cid)).some(c => c.cid === cm.cid), "alice sees carol's comment")

  console.log('\n— cross-outbox votes & moderation —')
  await alice.data.vote(post.cid, 'p2p', 'post', 1)
  await bob.data.vote(post.cid, 'p2p', 'post', 1)
  await carol.data.vote(post.cid, 'p2p', 'post', 1)
  ok((await carol.data.tallyFor(post.cid)).score === 3, 'three peers upvote -> score 3 aggregated across outboxes')
  await alice.data.removePost('p2p', post.cid, 'x')
  ok((await carol.data.overlay('p2p')).removed.has(post.cid), "carol honors founder's removal")

  console.log('\n— forgery rejection over the live transport —')
  // mallory relays an outbox LABELLED as alice, full of fabricated records.
  const mallory = await makePeer(hub, 'mallory')
  const fakeMod = { id: 'p2p!f', actionId: 'f', community: 'p2p', action: 'remove', targetCid: cm.cid, by: alice.pub, ts: Date.now() } // unsigned / wrong signer
  const fakePost = { id: 'p2p!f2', cid: 'f2', community: 'p2p', kind: 'text', title: 'FAKE', author: alice.pub, createdAt: Date.now(), editedAt: 0, deleted: false }
  await mallory.sync.bus.send({ t: 'outbox', pub: alice.pub, view: { 'modaction!p2p!f': fakeMod, 'post!p2p!f2': fakePost } })
  ok(!(await carol.data.overlay('p2p')).removed.has(cm.cid), "forged mod action relayed as alice is ignored (carol's comment stays)")
  ok(!(await carol.data.getPost('p2p', 'f2')), 'forged post relayed as alice is dropped on carol')
  // and it did not evict alice's real community/post from carol's replica
  ok(await carol.data.getCommunity('p2p'), "alice's real records survived the forged relay (no eviction)")

  console.log('\n— edit propagation —')
  await bob.data.editPost('p2p', post.cid, 'edited by bob')
  const fromAlice = await alice.data.getPost('p2p', post.cid)
  ok(fromAlice && fromAlice.body === 'edited by bob', "bob's signed edit propagates and verifies on alice")

  console.log('\n— status —')
  const st = await carol.sync.status()
  ok(st.secure === true && st.viewLength > 0, `secure=${st.secure}, ${st.viewLength} merged records, ${st.peers} peers`)

  console.log(`\n✅ all ${passed} gossip checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
