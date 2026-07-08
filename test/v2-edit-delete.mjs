// test/v2-edit-delete.mjs — editing/deleting your own content must survive the
// wire on the opaque-log v2 path. Run: node test/v2-edit-delete.mjs
//
// THE BUG (live incident 2026-07-08): edit/delete of a v2 comment OR post landed
// "bad signature" on the relay and would have been rejected by every peer. Root
// cause: canonical() (canon.js stable) kept undefined-valued keys, serializing
// them as null — but JSON (the sync store, the relay wire, gossip replication)
// DROPS undefined keys. The v2 read-model reconstruction sets ts/slug to
// undefined for records that lack them (a comment has neither); edit/delete
// re-emit that reconstructed record, so the signer covered `"slug":null,"ts":null`
// that the wire stripped → the verifier recomputed a shorter canonical → reject.
// Fresh records never carry those keys, so only re-emits (edit/delete) broke.
//
// THE INVARIANT: canonical() MUST be identical before and after a JSON round-trip,
// because a record is ALWAYS JSON-serialized between signing and verification.
// The existing v2 suites missed this because (a) they never exercised edit/delete
// and (b) they verified in-process objects, not wire-serialized copies.

import assert from 'node:assert'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { verifyRecord } from '../js/verify.js'
import { canonical } from '../js/canon.js'
import { mergeOutboxes } from '../js/gossip.js'
import { makeValidator } from '../js/pow.js'
import { ready as cryptoReady } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const BITS = { community: 4, post: 4, comment: 4, vote: 4, profile: 4, modaction: 4 }
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
const wire = (r) => JSON.parse(JSON.stringify(r)) // exactly what the sync store / relay / gossip do

async function main () {
  await cryptoReady()

  console.log('\n— canonical() is invariant across a JSON round-trip —')
  // The core contract. undefined-valued keys must not change the canonical, or a
  // signature can never survive serialization.
  const withUndef = { a: 1, b: undefined, c: 'x', nested: { d: undefined, e: 2 } }
  ok(canonical('t', withUndef) === canonical('t', wire(withUndef)),
    'canonical() ignores undefined-valued keys (matches JSON.stringify)')
  ok(canonical('t', { a: 1, c: 'x', nested: { e: 2 } }) === canonical('t', withUndef),
    'a key set to undefined is identical to the key being absent')

  console.log('\n— v2 edit/delete records verify AFTER the wire —')
  const sync = new DevSync(memoryStorage(), 'v2ed'); await sync.ready()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser('alice')
  const alice = id.me().pubkey
  const data = createData(sync, id, { minBits: BITS, v2: true })

  await data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'd' })
  const post = await data.submitPost({ community: 'p2p', kind: 'text', title: 'hi', body: 'the original body' })
  const c = await data.addComment({ community: 'p2p', postCid: post.cid, body: 'first version' })

  const rawOf = async (t) => wire((await sync.list('v2!', { limit: 500 })).map(x => x.value).find(v => v && v._t === t))

  // fresh (regression guard: the fix must not break the already-working path)
  ok(await verifyRecord('v2', await rawOf('comment')) === 'ok', 'fresh comment verifies over the wire (unchanged)')
  ok(await verifyRecord('v2', await rawOf('post')) === 'ok', 'fresh post verifies over the wire (unchanged)')

  await data.editComment('p2p', post.cid, c.cid, 'edited version — longer than before')
  ok(await verifyRecord('v2', await rawOf('comment')) === 'ok', 'EDITED comment verifies over the wire (the bug)')

  await data.deleteComment('p2p', post.cid, c.cid)
  const delC = await rawOf('comment')
  ok(await verifyRecord('v2', delC) === 'ok', 'DELETED comment verifies over the wire')

  await data.editPost('p2p', post.cid, 'edited post body')
  ok(await verifyRecord('v2', await rawOf('post')) === 'ok', 'EDITED post verifies over the wire')

  await data.deletePost('p2p', post.cid)
  ok(await verifyRecord('v2', await rawOf('post')) === 'ok', 'DELETED post verifies over the wire')

  await data.updateCommunity('p2p', { description: 'a new description' })
  ok(await verifyRecord('v2', await rawOf('community')) === 'ok', 'EDITED community verifies over the wire')

  console.log('\n— edited/deleted records ADMIT through the real gossip merge —')
  // The end-to-end proof: another peer receiving these records (wire-serialized)
  // through mergeOutboxes/admit() accepts them, so edits actually propagate.
  const boxes = [{ pub: alice, view: {} }]
  for (const r of (await sync.list('v2!', { limit: 500 }))) boxes[0].view[r.key] = wire(r.value)
  const merged = await mergeOutboxes(boxes, {}, makeValidator(BITS))
  const admittedKeys = Object.keys(merged)
  ok(admittedKeys.length > 0, 'merge admitted the wire-serialized v2 records')
  // every admitted row is one a verifier accepted — a bad-signature edit would be dropped
  const commentRows = admittedKeys.filter(k => merged[k] && merged[k]._t === 'comment')
  ok(commentRows.length === 1 && merged[commentRows[0]].deleted === true,
    'the deleted comment is the admitted state (edit+delete propagated, not rejected)')

  console.log('\n— the PoW fix repairs v1 edit/delete too —')
  // The missing-PoW half of the bug was type-agnostic: v1 edit/delete also
  // re-emitted without a fresh proof and were rejected by admit().
  const s1 = new DevSync(memoryStorage(), 'v1ed'); await s1.ready()
  const i1 = new DevIdentity(mem(), mem()); await i1.ready(); await i1.createUser('bob')
  const bob = i1.me().pubkey
  const d1 = createData(s1, i1, { minBits: BITS }) // v2 OFF
  await d1.createCommunity({ slug: 'help', title: 'Help', description: 'd' })
  const p1 = await d1.submitPost({ community: 'help', kind: 'text', title: 't', body: 'b' })
  const cm1 = await d1.addComment({ community: 'help', postCid: p1.cid, body: 'hi' })
  await d1.editComment('help', p1.cid, cm1.cid, 'edited')
  const b1 = { pub: bob, view: {} }
  for (const r of (await s1.list('', { limit: 500 }))) b1.view[r.key] = wire(r.value)
  const m1 = await mergeOutboxes([b1], {}, makeValidator(BITS))
  const editedComment = Object.entries(m1).find(([k, v]) => k.startsWith('comment!') && v && v.author === bob)
  ok(editedComment && editedComment[1].body === 'edited' && editedComment[1].editedAt > 0,
    'v1 edited comment admits with its new body (PoW re-minted)')

  console.log(`\nv2-edit-delete: ${passed} checks passed.`)
}

main().catch((e) => { console.error('❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
