// gossip.mjs — verifies the post-audit gossip layer: signature is the sole
// authority, the transport label carries none. Covers convergence, cross-outbox
// votes/moderation, edit propagation, and — critically — that forged/tampered
// records are rejected EVEN when relayed under a victim's outbox label.
// Run: node test/gossip.mjs

import assert from 'node:assert'
import { BridgeGossipSync, GossipSync, makeHub, mergeOutboxes } from '../js/gossip.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { canonical } from '../js/canon.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { makeValidator, mint, verify as verifyPow } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const BITS = { community: 7, post: 6, comment: 5 }
function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}
function rememberingPear () {
  const groups = new Map()
  const channel = { peers: [], on: () => {} }
  const ensure = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { inviteKey: 'a'.repeat(64), rows: new Map() })
    return groups.get(appId)
  }
  const sortedRows = (g) => [...g.rows.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  return {
    sync: {
      create: async (appId) => ({ appId, inviteKey: ensure(appId).inviteKey, writerPublicKey: 'b'.repeat(64) }),
      join: async (appId, inviteKey) => {
        const g = ensure(appId)
        if (inviteKey !== g.inviteKey) throw new Error('bad invite')
        return { appId, inviteKey, writerPublicKey: 'b'.repeat(64) }
      },
      append: async (appId, op) => {
        const key = op.type.replace(':', '!') + '!' + op.data.id
        ensure(appId).rows.set(key, op.data)
        return { ok: true, key }
      },
      range: async (appId, opts = {}) => {
        let rows = sortedRows(ensure(appId))
        if (opts.gt != null) rows = rows.filter(r => r.key > opts.gt)
        if (opts.gte != null) rows = rows.filter(r => r.key >= opts.gte)
        if (opts.lt != null) rows = rows.filter(r => r.key < opts.lt)
        if (opts.lte != null) rows = rows.filter(r => r.key <= opts.lte)
        return rows.slice(0, Number(opts.limit) || 100)
      },
      list: async (appId, prefix = '', opts = {}) => {
        let rows = sortedRows(ensure(appId))
        if (prefix) rows = rows.filter(r => r.key >= prefix && r.key < prefix + '\xff')
        return rows.slice(0, Number(opts.limit) || 100)
      },
      status: async (appId) => {
        const g = ensure(appId)
        return { appId, inviteKey: g.inviteKey, viewLength: g.rows.size }
      }
    },
    swarm: { v1: { join: async () => channel } }
  }
}
// Attach a real signature from `id` to a record (mirrors data._sign).
async function sign (id, type, data) {
  const s = await id.sign(canonical(type, data))
  return { ...data, _sig: s.signature, _k: s.publicKey, _dk: s.driveKey, _ns: s.namespace, _alg: s.algorithm }
}
async function powSign (id, type, data) {
  data.pow = await mint(type, data, BITS[type] || 0)
  return sign(id, type, data)
}
async function makePeer (hub, name) {
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const sync = new GossipSync({ storage: mem(), bus: hub.connect(), getMe: () => id.me().pubkey, validate: makeValidator(BITS) })
  await sync.ready()
  return { id, sync, data: createData(sync, id, { minBits: BITS }), pub: id.me().pubkey, name }
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
  const forged = await sign(mal, 'post', { id: 'p2p!x', cid: 'x', community: 'p2p', kind: 'text', title: 'FAKE', author: A, createdAt: 1, editedAt: 0, deleted: false })
  ok(!(await mergeOutboxes([{ pub: A, view: { 'post!p2p!x': forged } }]))['post!p2p!x'], 'forged post (author=A, signed by attacker), relayed as pub=A, is REJECTED')
  // Attacker also lies about the signer key:
  const forged2 = { ...forged, _k: A }
  ok(!(await mergeOutboxes([{ pub: A, view: { 'post!p2p!x': forged2 } }]))['post!p2p!x'], 'forged post claiming _k=A but with an invalid signature is REJECTED')

  // Author binding holds for comments and votes too, not just posts.
  const forgedComment = await sign(mal, 'comment', { id: 'p2p!x!y', cid: 'y', community: 'p2p', postCid: 'x', parentCid: null, body: 'FAKE', author: A, createdAt: 1, editedAt: 0, deleted: false })
  ok(!(await mergeOutboxes([{ pub: A, view: { 'comment!p2p!x!y': forgedComment } }]))['comment!p2p!x!y'], 'forged comment (author=A, signed by attacker) is REJECTED')
  const forgedVote = await sign(mal, 'vote', { id: 'x!' + A, targetCid: 'x', targetType: 'post', community: 'p2p', value: 1, author: A, ts: 1 })
  ok(!(await mergeOutboxes([{ pub: A, view: { ['vote!x!' + A]: forgedVote } }]))['vote!x!' + A], 'forged vote (author=A, signed by attacker) is REJECTED')

  // Tamper after signing.
  const tampered = { ...comm, title: 'HIJACK' }
  ok(!(await mergeOutboxes([{ pub: A, view: { 'community!p2p': tampered } }]))['community!p2p'], 'tampered record (content changed post-sign) is rejected')

  // Key binding: a valid record parked under the wrong key.
  ok(!(await mergeOutboxes([{ pub: A, view: { 'community!evil': comm } }]))['community!evil'], 'record under a mismatched storage key is rejected (key binding)')

  // Relaying someone ELSE's validly-signed record is fine (you can't forge it).
  ok((await mergeOutboxes([{ pub: M, view: { 'community!p2p': comm } }]))['community!p2p'], "a peer relaying A's validly-signed record is honored (transport label is not authority)")

  console.log('\n— proof-of-work spam gate —')
  const validator = makeValidator(BITS)
  const noPow = await sign(aid, 'post', { id: 'p2p!nopow', cid: 'nopow', community: 'p2p', kind: 'text', title: 'No PoW', body: '', url: '', author: A, createdAt: 10, editedAt: 0, deleted: false })
  ok(!(await mergeOutboxes([{ pub: A, view: { 'post!p2p!nopow': noPow } }], {}, validator))['post!p2p!nopow'], 'signed post without proof-of-work is rejected by the validate hook')
  const worked = await powSign(aid, 'post', { id: 'p2p!worked', cid: 'worked', community: 'p2p', kind: 'text', title: 'Worked', body: '', url: '', author: A, createdAt: 11, editedAt: 0, deleted: false })
  ok(await verifyPow('post', worked, BITS.post), 'minted post proof verifies')
  ok((await mergeOutboxes([{ pub: A, view: { 'post!p2p!worked': worked } }], {}, validator))['post!p2p!worked'], 'signed post with valid proof-of-work is admitted')
  const powTampered = { ...worked, cid: 'moved', id: 'p2p!moved' }
  ok(!(await mergeOutboxes([{ pub: A, view: { 'post!p2p!moved': powTampered } }], {}, validator))['post!p2p!moved'], 'proof-of-work target binding rejects identity tampering')

  console.log('\n— app-level group membership gate —')
  const memberId = new DevIdentity(mem(), mem()); await memberId.ready(); const MEMBER = memberId.me().pubkey
  const outsiderId = new DevIdentity(mem(), mem()); await outsiderId.ready(); const OUTSIDER = outsiderId.me().pubkey
  const groupMembers = new Map([['closed', new Set([A, MEMBER])]])
  const membershipValidator = async (type, val) => {
    if (!(await validator(type, val))) return false
    const community = type === 'community' ? val.slug : val.community
    const author = type === 'community' ? val.creator : (type === 'modaction' ? val.by : val.author)
    return !groupMembers.has(community) || groupMembers.get(community).has(author)
  }
  const closedCommunity = await powSign(aid, 'community', { id: 'closed', slug: 'closed', creator: A, createdAt: 20, title: 'Closed', description: 'members only' })
  const memberPost = await powSign(memberId, 'post', { id: 'closed!member', cid: 'member', community: 'closed', kind: 'text', title: 'Member', body: '', url: '', author: MEMBER, createdAt: 21, editedAt: 0, deleted: false })
  const outsiderPost = await powSign(outsiderId, 'post', { id: 'closed!outsider', cid: 'outsider', community: 'closed', kind: 'text', title: 'Outsider', body: '', url: '', author: OUTSIDER, createdAt: 22, editedAt: 0, deleted: false })
  const outsiderComment = await powSign(outsiderId, 'comment', { id: 'closed!member!outsider-comment', cid: 'outsider-comment', community: 'closed', postCid: 'member', parentCid: null, body: 'let me in', author: OUTSIDER, createdAt: 23, editedAt: 0, deleted: false })
  const publicPost = await powSign(outsiderId, 'post', { id: 'public!outsider', cid: 'outsider', community: 'public', kind: 'text', title: 'Public', body: '', url: '', author: OUTSIDER, createdAt: 24, editedAt: 0, deleted: false })
  const gated = await mergeOutboxes([
    { pub: A, view: { 'community!closed': closedCommunity } },
    { pub: MEMBER, view: { 'post!closed!member': memberPost } },
    { pub: OUTSIDER, view: { 'post!closed!outsider': outsiderPost, 'comment!closed!member!outsider-comment': outsiderComment, 'post!public!outsider': publicPost } }
  ], {}, membershipValidator)
  ok(gated['community!closed'], 'closed group descriptor is admitted when signed by a member')
  ok(gated['post!closed!member'], 'closed group member post is admitted by the app validator')
  ok(!gated['post!closed!outsider'], 'closed group outsider post is rejected even with a valid signature and PoW')
  ok(!gated['comment!closed!member!outsider-comment'], 'closed group outsider comment is rejected at the app layer')
  ok(gated['post!public!outsider'], 'the same outsider can still publish public records')

  // Deterministic community winner (earliest createdAt), order-independent.
  const bid = new DevIdentity(mem(), mem()); await bid.ready(); const B = bid.me().pubkey
  const cA = await sign(aid, 'community', { id: 'dup', slug: 'dup', creator: A, createdAt: 500, title: 'A', description: '' })
  const cB = await sign(bid, 'community', { id: 'dup', slug: 'dup', creator: B, createdAt: 200, title: 'B', description: '' })
  const w1 = (await mergeOutboxes([{ pub: A, view: { 'community!dup': cA } }, { pub: B, view: { 'community!dup': cB } }]))['community!dup']
  const w2 = (await mergeOutboxes([{ pub: B, view: { 'community!dup': cB } }, { pub: A, view: { 'community!dup': cA } }]))['community!dup']
  ok(w1.creator === B && w2.creator === B, 'earliest-createdAt community wins, regardless of merge order')

  // Robustness: malformed records and prototype-pollution keys do not crash/poison.
  const protoPollutionKey = '__proto__'
  const pollutionView = Object.create(null)
  pollutionView['post!p2p!n'] = null
  pollutionView[protoPollutionKey] = { x: 1 }
  pollutionView['community!p2p'] = comm
  const junk = await mergeOutboxes([{ pub: A, view: pollutionView }])
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

  console.log('\n— bridge restart without page-local outbox key —')
  const pear = rememberingPear()
  const rid = new DevIdentity(mem(), mem()); await rid.ready(); await rid.createUser('restart')
  const restart1 = new BridgeGossipSync({ pear, getMe: () => rid.me().pubkey, identity: rid, validate: makeValidator(BITS) }); await restart1.ready()
  const d1 = createData(restart1, rid, { minBits: BITS })
  await d1.createCommunity({ slug: 'persist', title: 'Persists', description: '' })
  const persisted = await d1.submitPost({ community: 'persist', kind: 'text', title: 'survives restart', body: 'no localStorage key' })
  ok(await d1.getPost('persist', persisted.cid), 'first bridge launch wrote a signed post')
  const restart2 = new BridgeGossipSync({ pear, getMe: () => rid.me().pubkey, identity: rid, validate: makeValidator(BITS) }); await restart2.ready()
  const d2 = createData(restart2, rid, { minBits: BITS })
  ok(await d2.getPost('persist', persisted.cid), 'second bridge launch reopens browser-remembered outbox without localStorage')
  const rst = await restart2.status()
  ok(rst.outboxAppId === rid.me().pubkey && rst.outboxes.some(o => o.appId === rst.outboxAppId && o.inviteKey === rst.inviteKey), 'bridge status exposes the current outbox for seeding/export')

  console.log('\n— bridge lifecycle: configurable poll + destroy —')
  const pid = new DevIdentity(mem(), mem()); await pid.ready(); await pid.createUser('poll')
  const noPoll = new BridgeGossipSync({ pear: rememberingPear(), getMe: () => pid.me().pubkey, identity: pid, validate: makeValidator(BITS), pollMs: 0 }); await noPoll.ready()
  ok(noPoll._pollTimer === null, 'pollMs:0 disables the background re-merge timer')
  noPoll.onChange(() => {})
  noPoll.destroy()
  ok(noPoll._pollTimer === null && noPoll._listeners.size === 0, 'destroy() clears timers and listeners')
  ok(noPoll._destroyed === true && (await noPoll._refresh()).length === 0, 'after destroy() a refresh is a no-op (returns [], cannot mutate a discarded instance)')
  const polled = new BridgeGossipSync({ pear: rememberingPear(), getMe: () => pid.me().pubkey, identity: pid, validate: makeValidator(BITS) }); await polled.ready()
  ok(polled._pollTimer !== null, 'default pollMs starts a jittered re-merge timer')
  polled.destroy()
  ok(polled._pollTimer === null, 'destroy() stops the default re-merge timer')

  console.log('\n— bridge UX change signals —')
  const uxPear = rememberingPear()
  const uxId = new DevIdentity(mem(), mem()); await uxId.ready(); await uxId.createUser('ux')
  const uxSync = new BridgeGossipSync({ pear: uxPear, getMe: () => uxId.me().pubkey, identity: uxId, validate: makeValidator(BITS), pollMs: 0 }); await uxSync.ready()
  const uxData = createData(uxSync, uxId, { minBits: BITS })
  const events = []
  uxSync.onChange((changed) => events.push(changed))
  await uxData.createCommunity({ slug: 'signals', title: 'Signals', description: '' })
  ok(events.some(keys => Array.isArray(keys) && keys.includes('community!signals')), 'bridge emits the precise community key for a visible local append')
  events.length = 0
  const uxPost = await uxData.submitPost({ community: 'signals', kind: 'text', title: 'vote patch target', body: 'hi' })
  ok(events.some(keys => Array.isArray(keys) && keys.includes('post!signals!' + uxPost.cid)), 'bridge emits the precise post key for a structural feed update')
  events.length = 0
  await uxData.vote(uxPost.cid, 'signals', 'post', 1)
  ok(events.some(keys => Array.isArray(keys) && keys.length === 1 && keys[0] === 'vote!' + uxPost.cid + '!' + uxId.me().pubkey), 'bridge emits a single vote key so the UI can patch vote widgets in place')
  events.length = 0
  ok((await uxSync._refresh()).length === 0, 'idle bridge refresh returns no visible change keys')
  const unsigned = { id: 'signals!bad', cid: 'bad', community: 'signals', kind: 'text', title: 'unsigned', author: uxId.me().pubkey, createdAt: Date.now(), editedAt: 0, deleted: false }
  await uxPear.sync.append(uxId.me().pubkey, { type: 'post', data: unsigned })
  ok((await uxSync._refresh()).length === 0, 'rejected bridge rows do not create spurious UI change keys')
  uxSync.destroy()

  console.log('\n— app recovery bundle import —')
  const recoveryStore = mem()
  const exportSync = new BridgeGossipSync({ pear, getMe: () => rid.me().pubkey, identity: rid, storage: recoveryStore, validate: makeValidator(BITS) }); await exportSync.ready()
  const exportData = createData(exportSync, rid, { minBits: BITS })
  const bundle = await exportData.recoveryBundle()
  ok(bundle.driveKey === rid.me().driveKey && bundle.publicKey === rid.me().pubkey && bundle.outboxes.length >= 1, 'bridge recovery export includes current drive/public keys and outbox')
  const importStore = mem()
  const importSync = new BridgeGossipSync({ pear, getMe: () => rid.me().pubkey, identity: rid, storage: importStore, validate: makeValidator(BITS) }); await importSync.ready()
  const importData = createData(importSync, rid, { minBits: BITS })
  const imported = await importData.importRecoveryBundle(bundle)
  ok(imported.joined === bundle.outboxes.length && imported.failures.length === 0, 'matching recovery bundle imports and joins every outbox')
  ok(JSON.parse(importStore.getItem('peerit:my-outboxes') || '[]').length >= 1, 'import persists known outboxes locally')
  await assert.rejects(() => importData.importRecoveryBundle({ ...bundle, publicKey: 'f'.repeat(64) }), /different app identity/)
  ok(true, 'recovery import rejects a bundle for another app public key')

  console.log('\n— status —')
  const st = await carol.sync.status()
  ok(st.secure === true && st.viewLength > 0, `secure=${st.secure}, ${st.viewLength} merged records, ${st.peers} peers`)

  console.log(`\n✅ all ${passed} gossip checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
