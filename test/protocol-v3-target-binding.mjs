// Adversarial admission tests for protocol-v3 target references.
// These records are signed exactly like a custom client could sign them; the
// real merge/admit path must reject legacy/ambiguous targets even when Ed25519,
// storage-key binding, and PoW are all otherwise valid.

import assert from 'node:assert/strict'
import { canonical, expectedKey, expectedKeyV2 } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { mergeOutboxes } from '../js/gossip.js'
import { DevIdentity } from '../js/identity.js'
import {
  CONTENT_PROTOCOL,
  MOD,
  REPORT_VERDICT,
  TYPE,
  contentId,
  hasValidContentRef,
  makeContentRef
} from '../js/model.js'
import { makeValidator, mint } from '../js/pow.js'
import { seal } from '../js/seal.js'

const BITS = { community: 4, post: 4, comment: 4, blob: 4, report: 4 }
const CLEAR = new Set(['createdAt', 'ts', 'editedAt', 'deleted', 'slug'])
const DROP = new Set(['id', '_t', 'author', 'creator', 'by', 'pow', '_sig', '_k', '_dk', '_ns', '_alg'])
let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }

function mem () {
  const values = new Map()
  return { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key), clear: () => values.clear() }
}

async function identity (name) {
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  return id
}

async function content (type, identity, nonce, extra = {}) {
  const author = identity.me().pubkey
  return {
    protocol: CONTENT_PROTOCOL,
    contentNonce: nonce,
    cid: await contentId(type, author, nonce),
    author,
    ...extra
  }
}

async function signedPlain (identity, type, logical, { proof = type === TYPE.COMMENT || type === TYPE.POST } = {}) {
  const data = { ...logical }
  if (proof) data.pow = await mint(type, data, BITS[type] || 0)
  const sig = await identity.sign(canonical(type, data))
  return { ...data, _sig: sig.signature, _k: sig.publicKey, _dk: sig.driveKey, _ns: sig.namespace, _alg: sig.algorithm }
}

async function signedSealed (identity, type, logical, { proof = type === TYPE.COMMENT || type === TYPE.POST } = {}) {
  const key = await expectedKeyV2({ ...logical, _t: type })
  const clear = {}
  const graph = {}
  for (const [field, value] of Object.entries(logical)) {
    if (value === undefined || DROP.has(field)) continue
    if (CLEAR.has(field)) clear[field] = value
    else graph[field] = value
  }
  const data = { id: key.slice(3), _t: type, ...clear, sealed: await seal(graph) }
  if (proof) data.pow = await mint(type, data, BITS[type] || 0)
  const sig = await identity.sign(canonical('v2', data))
  Object.assign(data, { _sig: sig.signature, _k: sig.publicKey, _dk: sig.driveKey, _ns: sig.namespace, _alg: sig.algorithm })
  return { key, value: data }
}

async function admits (identity, type, value, validator = makeValidator(BITS), key = expectedKey(type, value)) {
  const merged = await mergeOutboxes([{ pub: identity.me().pubkey, view: { [key]: value } }], {}, validator)
  return !!merged[key]
}

await cryptoReady()
const alice = await identity('target-alice')
const bob = await identity('target-bob')
const community = 'target_lab'
const targetPost = await content(TYPE.POST, alice, 'target-post', {
  id: '', community, kind: 'text', title: 'target', body: '', url: '', createdAt: 1, editedAt: 0, deleted: false
})
targetPost.id = `${community}!${targetPost.cid}`
const postRef = await makeContentRef(TYPE.POST, targetPost)

console.log('\n— target refs are exact and independently recomputable —')
ok(await hasValidContentRef(postRef, TYPE.POST), 'a canonical post ref independently reproduces its CID')
ok(!(await hasValidContentRef({ ...postRef, ignored: true }, TYPE.POST)), 'a ref with unrecognized fields is rejected')
ok(!(await hasValidContentRef({ ...postRef, type: TYPE.COMMENT }, TYPE.POST)), 'a ref cannot be relabelled across content types')
ok(!(await hasValidContentRef({ ...postRef, cid: '0'.repeat(64) }, TYPE.POST)), 'a ref with a substituted CID is rejected')

console.log('\n— comments bind both post and parent —')
const topLogical = await content(TYPE.COMMENT, bob, 'top-comment', {
  id: '', community, postCid: targetPost.cid, targetRef: postRef,
  parentCid: null, parentRef: null, body: 'top', createdAt: 2, editedAt: 0, deleted: false
})
topLogical.id = `${community}!${targetPost.cid}!${topLogical.cid}`
const top = await signedPlain(bob, TYPE.COMMENT, topLogical)
ok(await admits(bob, TYPE.COMMENT, top), 'a signed v3 top-level comment with a valid post ref admits')

const parentRef = await makeContentRef(TYPE.COMMENT, topLogical)
const nestedLogical = await content(TYPE.COMMENT, alice, 'nested-comment', {
  id: '', community, postCid: targetPost.cid, targetRef: postRef,
  parentCid: topLogical.cid, parentRef, body: 'nested', createdAt: 3, editedAt: 0, deleted: false
})
nestedLogical.id = `${community}!${targetPost.cid}!${nestedLogical.cid}`
const nested = await signedPlain(alice, TYPE.COMMENT, nestedLogical)
ok(await admits(alice, TYPE.COMMENT, nested), 'a nested reply admits only with a recomputable parent comment ref')

const noPostRef = await signedPlain(bob, TYPE.COMMENT, { ...topLogical, targetRef: undefined })
ok(!(await admits(bob, TYPE.COMMENT, noPostRef)), 'a validly signed/PoW comment with only a CID cannot target a legacy thread')
const movedPost = await signedPlain(bob, TYPE.COMMENT, { ...topLogical, postCid: 'legacy-caller-selected' })
ok(!(await admits(bob, TYPE.COMMENT, movedPost)), 'a custom client cannot staple a valid post ref onto a different legacy postCid')
const noParentRef = await signedPlain(alice, TYPE.COMMENT, { ...nestedLogical, parentRef: null })
ok(!(await admits(alice, TYPE.COMMENT, noParentRef)), 'a nested reply with a bare parentCid is rejected')
const wrongParent = await signedPlain(alice, TYPE.COMMENT, { ...nestedLogical, parentCid: targetPost.cid, parentRef: postRef })
ok(!(await admits(alice, TYPE.COMMENT, wrongParent)), 'a post ref cannot masquerade as a parent-comment ref')

console.log('\n— votes bind target type and identity —')
const votePost = await signedPlain(bob, TYPE.VOTE, {
  id: `${targetPost.cid}!${bob.me().pubkey}`,
  protocol: CONTENT_PROTOCOL,
  targetCid: targetPost.cid,
  targetType: TYPE.POST,
  targetRef: postRef,
  community,
  value: 1,
  author: bob.me().pubkey,
  ts: 4
}, { proof: false })
ok(await admits(bob, TYPE.VOTE, votePost), 'a v3 vote with a matching recomputable post ref admits')
const legacyVote = await signedPlain(bob, TYPE.VOTE, { ...votePost, id: `legacy-cid!${bob.me().pubkey}`, targetCid: 'legacy-cid', targetRef: null, ts: 5 }, { proof: false })
ok(!(await admits(bob, TYPE.VOTE, legacyVote)), 'a newly signed CID-only vote is rejected')
const relabelledVote = await signedPlain(bob, TYPE.VOTE, { ...votePost, targetType: TYPE.COMMENT, ts: 6 }, { proof: false })
ok(!(await admits(bob, TYPE.VOTE, relabelledVote)), 'a vote target type must match its signed ref type')

// Exercise the explicit deny-set with a syntactically valid v3 hash. This covers
// a deliberately v3-looking CID selected by a malicious pre-cutover author.
const denyValidator = makeValidator(BITS, { legacyTargetCids: new Set([targetPost.cid]) })
ok(!(await admits(bob, TYPE.VOTE, votePost, denyValidator)), 'an inventoried legacy CID is rejected even when it can reproduce a v3-looking ref')

console.log('\n— moderation action shapes are closed —')
const removeComment = await signedPlain(alice, TYPE.MOD, {
  id: `${community}!remove-comment`, actionId: 'remove-comment', community,
  protocol: CONTENT_PROTOCOL, action: MOD.REMOVE,
  targetCid: topLogical.cid, targetType: TYPE.COMMENT, targetRef: parentRef, targetUser: null,
  reason: 'spam', by: alice.me().pubkey, ts: 7
}, { proof: false })
ok(await admits(alice, TYPE.MOD, removeComment), 'remove/approve may bind a protocol-v3 comment ref')
const lockComment = await signedPlain(alice, TYPE.MOD, { ...removeComment, id: `${community}!lock-comment`, actionId: 'lock-comment', action: MOD.LOCK, ts: 8 }, { proof: false })
ok(!(await admits(alice, TYPE.MOD, lockComment)), 'lock/sticky actions reject comment targets')
const lockPost = await signedPlain(alice, TYPE.MOD, {
  ...removeComment, id: `${community}!lock-post`, actionId: 'lock-post', action: MOD.LOCK,
  targetCid: targetPost.cid, targetType: TYPE.POST, targetRef: postRef, ts: 9
}, { proof: false })
ok(await admits(alice, TYPE.MOD, lockPost), 'lock/sticky actions accept a bound protocol-v3 post ref')
const legacyRemove = await signedPlain(alice, TYPE.MOD, {
  ...removeComment, id: `${community}!legacy-remove`, actionId: 'legacy-remove',
  targetCid: 'legacy-cid', targetType: TYPE.POST, targetRef: null, ts: 10
}, { proof: false })
ok(!(await admits(alice, TYPE.MOD, legacyRemove)), 'a newly signed content-mod action cannot carry a bare legacy CID')
const ban = await signedPlain(alice, TYPE.MOD, {
  id: `${community}!ban-user`, actionId: 'ban-user', community,
  protocol: CONTENT_PROTOCOL, action: MOD.BAN,
  targetCid: null, targetType: null, targetRef: null, targetUser: bob.me().pubkey,
  reason: '', by: alice.me().pubkey, ts: 11
}, { proof: false })
ok(await admits(alice, TYPE.MOD, ban), 'a user action admits with one canonical lowercase user target and no content target')
const ambiguousBan = await signedPlain(alice, TYPE.MOD, { ...ban, id: `${community}!ambiguous-ban`, actionId: 'ambiguous-ban', targetCid: targetPost.cid, targetType: TYPE.POST, targetRef: postRef, ts: 12 }, { proof: false })
ok(!(await admits(alice, TYPE.MOD, ambiguousBan)), 'a user action carrying both user and content targets is rejected')
const uppercaseBan = await signedPlain(alice, TYPE.MOD, { ...ban, id: `${community}!uppercase-ban`, actionId: 'uppercase-ban', targetUser: bob.me().pubkey.toUpperCase(), ts: 13 }, { proof: false })
ok(!(await admits(alice, TYPE.MOD, uppercaseBan)), 'a user action rejects a non-canonical public-key target')
const unknown = await signedPlain(alice, TYPE.MOD, { ...ban, id: `${community}!unknown`, actionId: 'unknown', action: 'shadowban', ts: 14 }, { proof: false })
ok(!(await admits(alice, TYPE.MOD, unknown)), 'an unknown mod action is rejected instead of acquiring client-specific semantics')

console.log('\n— community reports bind verdict and target identity —')
const buryReport = await signedPlain(bob, TYPE.REPORT, {
  id: `${community}!${targetPost.cid}!${bob.me().pubkey}`,
  protocol: CONTENT_PROTOCOL,
  community,
  targetCid: targetPost.cid,
  targetType: TYPE.POST,
  targetRef: postRef,
  verdict: REPORT_VERDICT.BURY,
  reason: 'spam',
  note: '',
  author: bob.me().pubkey,
  ts: 15,
  deleted: false
}, { proof: true })
ok(await admits(bob, TYPE.REPORT, buryReport), 'a signed PoW report with an exact protocol-v3 target admits')
const bareReport = await signedPlain(bob, TYPE.REPORT, {
  ...buryReport,
  targetRef: null,
  ts: 16
}, { proof: true })
ok(!(await admits(bob, TYPE.REPORT, bareReport)), 'a freshly signed report cannot target a bare legacy CID')
const inventedVerdict = await signedPlain(bob, TYPE.REPORT, {
  ...buryReport,
  verdict: 'shadowban',
  ts: 17
}, { proof: true })
ok(!(await admits(bob, TYPE.REPORT, inventedVerdict)), 'unknown report verdicts cannot acquire client-specific semantics')

console.log('\n— sealed v2 validates decrypted logical targets —')
const sealedComment = await signedSealed(bob, TYPE.COMMENT, topLogical)
ok(await admits(bob, TYPE.COMMENT, sealedComment.value, makeValidator(BITS), sealedComment.key), 'a sealed comment with valid decrypted refs admits')
const sealedVote = await signedSealed(bob, TYPE.VOTE, { ...votePost })
ok(await admits(bob, TYPE.VOTE, sealedVote.value, makeValidator(BITS), sealedVote.key), 'a sealed vote with a valid decrypted ref admits')
const sealedMod = await signedSealed(alice, TYPE.MOD, { ...lockPost })
ok(await admits(alice, TYPE.MOD, sealedMod.value, makeValidator(BITS), sealedMod.key), 'a sealed content-mod action with a valid decrypted ref admits')
const sealedReport = await signedSealed(bob, TYPE.REPORT, { ...buryReport }, { proof: true })
ok(await admits(bob, TYPE.REPORT, sealedReport.value, makeValidator(BITS), sealedReport.key), 'a sealed report validates its decrypted target and PoW')
const sealedAttack = await signedSealed(bob, TYPE.VOTE, { ...votePost, targetCid: 'legacy-cid', targetRef: null, id: `legacy-cid!${bob.me().pubkey}`, ts: 15 })
ok(!(await admits(bob, TYPE.VOTE, sealedAttack.value, makeValidator(BITS), sealedAttack.key)), 'sealed fields are unsealed before a legacy-targeted vote is rejected')

console.log('\n— compatibility is exact-signature only —')
const oldLogical = {
  id: `${community}!old-post!old-comment`, cid: 'old-comment', community, postCid: 'old-post', parentCid: null,
  body: 'historical', author: bob.me().pubkey, createdAt: 20, editedAt: 0, deleted: false
}
const oldComment = await signedPlain(bob, TYPE.COMMENT, oldLogical)
const fixtureInventory = { comment: new Set([oldComment._sig]), vote: new Set(), modaction: new Set() }
const fixtureValidator = makeValidator(BITS, { legacyActionSignatures: fixtureInventory, legacyTargetCids: new Set() })
ok(await admits(bob, TYPE.COMMENT, oldComment, fixtureValidator), 'one exact inventoried legacy comment signature remains readable')
const freshLegacy = await signedPlain(bob, TYPE.COMMENT, { ...oldLogical, body: 'newly signed replay', createdAt: 21 })
ok(!(await admits(bob, TYPE.COMMENT, freshLegacy, fixtureValidator)), 'a fresh signature over a legacy comment shape is rejected despite valid Ed25519 and PoW')

console.log(`\nprotocol-v3-target-binding: ${passed} checks passed`)
