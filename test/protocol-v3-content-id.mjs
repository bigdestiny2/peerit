// Protocol-v3 adversarial identity tests.
// Two authors deliberately choose the same deterministic nonce (the old design
// would have let them choose the same CID). Their posts/comments, votes, and
// reply targets must remain disjoint. Fresh legacy-shaped records are rejected
// even with valid Ed25519 + PoW; historical compatibility is exact-signature only.

import assert from 'node:assert/strict'
import { canonical, expectedKeyV2 } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { createData } from '../js/data.js'
import { mergeOutboxes } from '../js/gossip.js'
import { DevIdentity } from '../js/identity.js'
import { CONTENT_PROTOCOL, TYPE, contentId, hasValidContentId, hasValidContentRef, keys } from '../js/model.js'
import { makeValidator, mint } from '../js/pow.js'
import { seal } from '../js/seal.js'
import { DevSync, memoryStorage } from '../js/sync.js'

const BITS = { community: 4, post: 4, comment: 4, blob: 4 }
const mem = () => {
  const m = new Map()
  return { getItem: k => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}
const wire = value => JSON.parse(JSON.stringify(value))
let passed = 0
function ok (condition, message) { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }

async function identity (name) {
  const id = new DevIdentity(mem(), mem())
  await id.ready(); await id.createUser(name)
  return id
}

async function signLogical (identity, type, data) {
  data.pow = await mint(type, data, BITS[type] || 0)
  const sig = await identity.sign(canonical(type, data))
  return { ...data, _sig: sig.signature, _k: sig.publicKey, _dk: sig.driveKey, _ns: sig.namespace, _alg: sig.algorithm }
}

async function maliciousSealedLegacyPost (identity, victimCid) {
  const author = identity.me().pubkey
  const logical = { _t: TYPE.POST, author, community: 'collision', cid: victimCid, kind: 'text', title: 'redirect', body: 'attacker', url: '', createdAt: 50, editedAt: 0, deleted: false }
  const key = await expectedKeyV2(logical)
  const stored = {
    id: key.slice(3), _t: TYPE.POST, createdAt: logical.createdAt, editedAt: 0, deleted: false,
    sealed: await seal({ community: logical.community, cid: logical.cid, kind: logical.kind, title: logical.title, body: logical.body, url: logical.url })
  }
  stored.pow = await mint(TYPE.POST, stored, BITS.post)
  const sig = await identity.sign(canonical('v2', stored))
  Object.assign(stored, { _sig: sig.signature, _k: sig.publicKey, _dk: sig.driveKey, _ns: sig.namespace, _alg: sig.algorithm })
  return { key, value: stored }
}

await cryptoReady()
const alice = await identity('alice')
const mallory = await identity('mallory')
const sync = new DevSync(memoryStorage(), 'protocol-v3-collision')
await sync.ready()
const a = createData(sync, alice, { minBits: BITS, v2: true })

await a.createCommunity({ slug: 'collision', title: 'Collision lab' })
const b = createData(sync, mallory, { minBits: BITS, v2: true })

console.log('\n— author-bound post and comment identities —')
const sharedPostNonce = 'both-authors-deliberately-chose-this'
const pa = await a.submitPost({ community: 'collision', kind: 'text', title: 'Alice', body: 'a', nonce: sharedPostNonce })
const pb = await b.submitPost({ community: 'collision', kind: 'text', title: 'Mallory', body: 'b', nonce: sharedPostNonce })
ok(pa.protocol === CONTENT_PROTOCOL && pb.protocol === CONTENT_PROTOCOL, 'new posts explicitly stamp protocol 3')
ok(pa.contentNonce === pb.contentNonce && pa.cid !== pb.cid, 'the same nonce under different authors yields different post CIDs')
ok(pa.cid === await contentId(TYPE.POST, alice.me().pubkey, sharedPostNonce), 'Alice post CID is independently recomputable')
ok(pb.cid === await contentId(TYPE.POST, mallory.me().pubkey, sharedPostNonce), 'Mallory post CID is independently recomputable')
ok(await hasValidContentId(TYPE.POST, pa) && await hasValidContentId(TYPE.POST, pb), 'both post identities pass the protocol verifier')

const sharedCommentNonce = 'same-comment-nonce'
const ca = await a.addComment({ community: 'collision', postCid: pa.cid, body: 'on Alice', nonce: sharedCommentNonce })
const cb = await b.addComment({ community: 'collision', postCid: pb.cid, body: 'on Mallory', nonce: sharedCommentNonce })
ok(ca.cid !== cb.cid && ca.postCid !== cb.postCid, 'same-nonce comments and their parent post references stay disjoint')
ok(await hasValidContentId(TYPE.COMMENT, ca) && await hasValidContentId(TYPE.COMMENT, cb), 'both comment identities are recomputable from type + author + nonce')
ok(await hasValidContentRef(ca.targetRef, TYPE.POST) && ca.targetRef.cid === pa.cid && ca.parentRef === null, 'Data stamps a recomputable post ref and explicit null parent ref')

console.log('\n— votes/replies cannot cross the collision boundary —')
await a.vote(pa.cid, 'collision', 'post', 1)
await b.vote(pb.cid, 'collision', 'post', -1)
const reader = createData(sync, alice, { minBits: BITS, v2: true })
ok((await reader.tallyFor(pa.cid)).score === 1, 'vote for Alice CID stays on Alice post')
ok((await reader.tallyFor(pb.cid)).score === -1, 'vote for Mallory CID stays on Mallory post')
ok((await reader.listComments('collision', pa.cid)).some(c => c.cid === ca.cid) && !(await reader.listComments('collision', pa.cid)).some(c => c.cid === cb.cid), 'Alice thread cannot absorb Mallory comment')
ok((await reader.listComments('collision', pb.cid)).some(c => c.cid === cb.cid) && !(await reader.listComments('collision', pb.cid)).some(c => c.cid === ca.cid), 'Mallory thread cannot absorb Alice comment')

let directLookupKey = null
let directVoteOp = null
const directVote = createData(sync, alice, { minBits: BITS, v2: true })
directVote._get = async (key) => { directLookupKey = key; return ca }
directVote._listPrefix = async () => { throw new Error('full comment scan forbidden when post context is present') }
directVote._emit = async (type, data) => { directVoteOp = { type, data }; return data }
await directVote.vote(ca.cid, 'collision', TYPE.COMMENT, 1, { postCid: pa.cid })
ok(directLookupKey === keys.comment('collision', pa.cid, ca.cid) && directVoteOp?.data?.targetCid === ca.cid, 'comment vote context performs one direct parent-scoped lookup instead of a global comment scan')

console.log('\n— edits preserve identity —')
const editedPost = await a.editPost('collision', pa.cid, 'edited')
const editedComment = await a.editComment('collision', pa.cid, ca.cid, 'edited reply')
ok(editedPost.cid === pa.cid && editedPost.contentNonce === pa.contentNonce && await hasValidContentId(TYPE.POST, editedPost), 'post edit preserves and re-verifies CID/nonce')
ok(editedComment.cid === ca.cid && editedComment.contentNonce === ca.contentNonce && await hasValidContentId(TYPE.COMMENT, editedComment), 'comment edit preserves and re-verifies CID/nonce')

console.log('\n— sealed v3 wire records admit —')
const raw = await sync.list('v2!', { limit: 1000 })
const boxes = new Map()
for (const row of raw) {
  const pub = row.value && row.value._k
  if (!boxes.has(pub)) boxes.set(pub, Object.create(null))
  boxes.get(pub)[row.key] = wire(row.value)
}
const merged = await mergeOutboxes([...boxes].map(([pub, view]) => ({ pub, view })), {}, makeValidator(BITS))
const admittedPosts = Object.values(merged).filter(v => v && v._t === TYPE.POST)
const admittedComments = Object.values(merged).filter(v => v && v._t === TYPE.COMMENT)
const admittedVotes = Object.values(merged).filter(v => v && v._t === TYPE.VOTE)
ok(admittedPosts.length === 2, 'both authors’ sealed v3 posts admit simultaneously')
ok(admittedComments.length === 2 && admittedVotes.length === 2, 'Data-generated sealed comments and votes pass target-ref admission')

console.log('\n— fresh legacy shape is closed —')
const legacyCid = 'attacker-selected-collision'
const legacyA = await signLogical(alice, TYPE.POST, { id: `collision!${legacyCid}`, cid: legacyCid, community: 'collision', kind: 'text', title: 'A legacy', body: '', url: '', author: alice.me().pubkey, createdAt: 10, editedAt: 0, deleted: false })
const legacyB = await signLogical(mallory, TYPE.POST, { id: `collision!${legacyCid}`, cid: legacyCid, community: 'collision', kind: 'text', title: 'B legacy', body: '', url: '', author: mallory.me().pubkey, createdAt: 11, editedAt: 0, deleted: false })
ok(keys.post('collision', legacyA.cid) === keys.post('collision', legacyB.cid), 'the old design would place both authors at the same plaintext key')
const legacyMerged = await mergeOutboxes([
  { pub: alice.me().pubkey, view: { [keys.post('collision', legacyCid)]: legacyA } },
  { pub: mallory.me().pubkey, view: { [keys.post('collision', legacyCid)]: legacyB } }
], {}, makeValidator(BITS))
ok(!legacyMerged[keys.post('collision', legacyCid)], 'two newly signed legacy-shaped posts are rejected despite valid signatures and PoW')

await sync.append({ type: TYPE.POST, data: legacyA })
const legacyWriter = createData(sync, alice, { minBits: BITS, v2: true })
await assert.rejects(
  () => legacyWriter.addComment({ community: 'collision', postCid: legacyCid, body: 'must not redirect' }),
  /Legacy threads are read-only/
)
passed++; console.log('  ✓ a new reply cannot attach to an ambiguous historical CID')
await assert.rejects(
  () => legacyWriter.vote(legacyCid, 'collision', TYPE.POST, 1),
  /Legacy posts are read-only/
)
passed++; console.log('  ✓ a new vote cannot attach to an ambiguous historical CID')

const redirect = await maliciousSealedLegacyPost(mallory, pa.cid)
const redirected = await mergeOutboxes([{ pub: mallory.me().pubkey, view: { [redirect.key]: redirect.value } }], {}, makeValidator(BITS))
ok(!redirected[redirect.key], 'a newly signed sealed legacy post cannot select a victim v3 CID')

console.log(`\nprotocol-v3-content-id: ${passed} checks passed`)
