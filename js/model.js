// model.js — the peerit data model expressed in terms of the PearBrowser sync
// bridge's GENERIC REDUCER. The bridge applies an op { type, data } by storing
// `data` at Hyperbee key `type + '!' + data.id` (last-write-wins). We use
// colon-free type names so every op hits that generic path, and we encode
// scope + identity into `data.id` to get cheap prefix/range queries.
//
//   community   community!<slug>
//   post        post!<community>!<cid>
//   comment     comment!<community>!<postCid>!<cid>
//   vote        vote!<targetCid>!<authorPub>     (one per voter -> LWW dedup)
//   profile     profile!<authorPub>
//   modaction   modaction!<community>!<actionId>
//
// All record fields live INSIDE `data` (the reducer stores only data, not the
// op envelope). Edits/deletes are re-writes of the full record (soft delete via
// `deleted:true`) — correct for an append-only P2P log.

import { hashHex } from './crypto.js'

export const TYPE = {
  COMMUNITY: 'community',
  POST: 'post',
  COMMENT: 'comment',
  VOTE: 'vote',
  PROFILE: 'profile',
  MOD: 'modaction',
  // A per-outbox signed census (the "merkle root"): head!<authorPub> commits to
  // the complete set of that author's records, so a reader can detect a relay
  // that withholds records and no relay is the authoritative source of truth.
  HEAD: 'head',
  // BlindShard Phase 2: an opaque, content-addressed ciphertext body. blob!<blobId>
  // (blobId = SHA-256(ciphertext)) holds a long post body the relay never sees in
  // plaintext; the owning post carries the signed {blobId, contentKey, iv} manifest.
  // Convergent → identical bodies share one blob (dedup). See blob-store.js / box.js.
  BLOB: 'blob',
  // BlindShard bridge transport: opaque PVSS share shards stored in the PearBrowser
  // sync bridge instead of HTTP HiveRelay. shard!<hash> holds one encrypted share;
  // the dispersal manifest lists the set of shard addresses needed to reconstruct.
  SHARD: 'shard',
  // Signed social graph (replaces device-local prefs, which die with localStorage
  // and are invisible to the network). One record per edge, LWW like vote:
  //   follow!<targetPub>!<authorPub>   (unfollow = deleted:true tombstone)
  //   member!<community>!<authorPub>   (leave    = deleted:true tombstone)
  // NOTE the member field is `community`, NOT `slug` — V2_CLEAR keeps `slug`
  // cleartext (community LWW needs it), so naming it `community` is what gets the
  // membership edge SEALED in the v2 opaque form, exactly like a vote's targetCid.
  FOLLOW: 'follow',
  MEMBER: 'member'
}

// Protocol v3 gives every new post/comment a globally author-bound identity.
// The nonce is signed with the record, while the cid is independently
// recomputable by every reader. Including the type prevents a comment identity
// from being re-used as a post identity; including the author prevents two
// authors choosing the same nonce from colliding in the decrypted read model.
export const CONTENT_PROTOCOL = 3
const CONTENT_ID_DOMAIN = 'peerit.content-id.v3'
const HEX64 = /^[0-9a-f]{64}$/
const CONTENT_TYPES = new Set([TYPE.POST, TYPE.COMMENT])
const CONTENT_REF_FIELDS = Object.freeze(['author', 'cid', 'contentNonce', 'type'])

export function validContentNonce (nonce) {
  return typeof nonce === 'string' && nonce.length >= 1 && nonce.length <= 128 &&
    !/[\u0000-\u001f\u007f]/.test(nonce)
}

export async function contentId (type, author, nonce) {
  if (!CONTENT_TYPES.has(type)) throw new Error('Content identities are only defined for posts and comments')
  const owner = String(author || '').toLowerCase()
  if (!HEX64.test(owner)) throw new Error('Content identity requires a 32-byte author public key')
  if (!validContentNonce(nonce)) throw new Error('Content identity nonce must be 1-128 printable characters')
  // JSON array framing is unambiguous even when a deterministic nonce contains
  // punctuation. The fixed prefix is the protocol/domain separator.
  return hashHex(CONTENT_ID_DOMAIN + '\x00' + JSON.stringify([type, owner, nonce]))
}

export async function hasValidContentId (type, data) {
  if (!CONTENT_TYPES.has(type) || !data || data.protocol !== CONTENT_PROTOCOL) return false
  const author = String(data.author || '').toLowerCase()
  // New identities are canonical lowercase on the wire. Accepting uppercase
  // aliases would make two signed ref shapes describe the same hash input.
  if (data.author !== author || !HEX64.test(author) || !validContentNonce(data.contentNonce)) return false
  if (!HEX64.test(String(data.cid || '')) || data.cid !== String(data.cid).toLowerCase()) return false
  return data.cid === await contentId(type, author, data.contentNonce)
}

// A target-bearing record cannot safely carry only a CID: pre-v3 CIDs were
// caller-selected and may be ambiguous. Protocol-v3 actions instead sign this
// complete, self-certifying identity tuple. Readers independently recompute the
// CID without trusting the action author or looking at a mutable local winner.
// Keep the shape exact so an ignored/unsigned-looking extension cannot acquire
// conflicting semantics in another client implementation.
export async function hasValidContentRef (ref, expectedType) {
  if (!ref || typeof ref !== 'object' || Array.isArray(ref)) return false
  const fields = Object.keys(ref).sort()
  if (fields.length !== CONTENT_REF_FIELDS.length || fields.some((field, i) => field !== CONTENT_REF_FIELDS[i])) return false
  if (!CONTENT_TYPES.has(ref.type) || (expectedType && ref.type !== expectedType)) return false
  const author = String(ref.author || '').toLowerCase()
  if (ref.author !== author || !HEX64.test(author)) return false
  if (!validContentNonce(ref.contentNonce)) return false
  if (!HEX64.test(String(ref.cid || '')) || ref.cid !== String(ref.cid).toLowerCase()) return false
  return ref.cid === await contentId(ref.type, author, ref.contentNonce)
}

// Construct a ref only from a record that already proves its own protocol-v3
// identity. This is async because the same independent hash check used by
// admission runs before the ref is returned to a writer.
export async function makeContentRef (type, data) {
  if (!(await hasValidContentId(type, data))) throw new Error('Target must have a valid protocol v3 content identity')
  return { type, author: data.author, contentNonce: data.contentNonce, cid: data.cid }
}

export const CONTENT_MOD_ACTIONS = new Set([
  'remove', 'approve', 'lock', 'unlock', 'sticky', 'unsticky'
])
export const USER_MOD_ACTIONS = new Set([
  'ban', 'unban', 'addmod', 'removemod'
])

export function validCommunitySlug (slug) {
  return typeof slug === 'string' && /^[a-z0-9_]{2,24}$/.test(slug)
}

export function validUserTarget (target) {
  return typeof target === 'string' && HEX64.test(target) && target === target.toLowerCase()
}

// Validate the signed semantic fields of a NEW mod action. Historical actions
// are handled only by the exact-signature inventory in pow.js. Content actions
// bind the legacy scalar fields to a recomputable targetRef; user actions must
// carry no content target at all. Locking/pinning is post-only, while remove and
// approve may address a post or a comment.
export async function hasValidModAction (data) {
  if (!data || typeof data !== 'object' || data.protocol !== CONTENT_PROTOCOL) return false
  if (!validCommunitySlug(data.community)) return false
  if (typeof data.actionId !== 'string' || data.actionId.length < 1 || data.actionId.length > 128 || /[\u0000-\u001f\u007f]/.test(data.actionId)) return false
  if (typeof data.reason !== 'string' || data.reason.length > 300) return false
  if (!validUserTarget(data.by) || !Number.isFinite(data.ts) || data.ts < 0) return false

  if (CONTENT_MOD_ACTIONS.has(data.action)) {
    if (data.targetUser !== null) return false
    if (data.targetType !== TYPE.POST && data.targetType !== TYPE.COMMENT) return false
    if ((data.action === 'lock' || data.action === 'unlock' || data.action === 'sticky' || data.action === 'unsticky') && data.targetType !== TYPE.POST) return false
    if (data.targetCid !== data.targetRef?.cid || data.targetType !== data.targetRef?.type) return false
    return hasValidContentRef(data.targetRef, data.targetType)
  }

  if (USER_MOD_ACTIONS.has(data.action)) {
    return validUserTarget(data.targetUser) && data.targetCid === null && data.targetType === null && data.targetRef === null
  }

  return false
}

export const keys = {
  community: (slug) => `${TYPE.COMMUNITY}!${slug}`,
  communityPrefix: () => `${TYPE.COMMUNITY}!`,

  post: (community, cid) => `${TYPE.POST}!${community}!${cid}`,
  postsIn: (community) => `${TYPE.POST}!${community}!`,

  comment: (community, postCid, cid) => `${TYPE.COMMENT}!${community}!${postCid}!${cid}`,
  commentPrefix: () => `${TYPE.COMMENT}!`,
  commentsOn: (community, postCid) => `${TYPE.COMMENT}!${community}!${postCid}!`,

  vote: (targetCid, author) => `${TYPE.VOTE}!${targetCid}!${author}`,
  voteAll: () => `${TYPE.VOTE}!`,
  votesFor: (targetCid) => `${TYPE.VOTE}!${targetCid}!`,

  profile: (author) => `${TYPE.PROFILE}!${author}`,

  mod: (community, actionId) => `${TYPE.MOD}!${community}!${actionId}`,
  modsIn: (community) => `${TYPE.MOD}!${community}!`,

  head: (author) => `${TYPE.HEAD}!${author}`,
  headPrefix: () => `${TYPE.HEAD}!`,

  blob: (blobId) => `${TYPE.BLOB}!${blobId}`,
  blobPrefix: () => `${TYPE.BLOB}!`,

  shard: (hash) => `${TYPE.SHARD}!${hash}`,
  shardPrefix: () => `${TYPE.SHARD}!`,

  follow: (targetPub, author) => `${TYPE.FOLLOW}!${targetPub}!${author}`,
  followAll: () => `${TYPE.FOLLOW}!`,
  followersOf: (targetPub) => `${TYPE.FOLLOW}!${targetPub}!`,

  member: (community, author) => `${TYPE.MEMBER}!${community}!${author}`,
  memberAll: () => `${TYPE.MEMBER}!`,
  membersOf: (community) => `${TYPE.MEMBER}!${community}!`
}

// data.id builders (the part after `type!`). These determine the storage key
// because the reducer does k(type, data.id).
export const id = {
  community: (slug) => slug,
  post: (community, cid) => `${community}!${cid}`,
  comment: (community, postCid, cid) => `${community}!${postCid}!${cid}`,
  vote: (targetCid, author) => `${targetCid}!${author}`,
  profile: (author) => author,
  mod: (community, actionId) => `${community}!${actionId}`,
  head: (author) => author,
  blob: (blobId) => blobId,
  shard: (hash) => hash,
  follow: (targetPub, author) => `${targetPub}!${author}`,
  member: (community, author) => `${community}!${author}`
}

// The v2 blind key scheme (docs/BLIND-OUTBOX-MIGRATION.md) folds this SAME semantic
// tuple — not the plaintext key — into an opaque okey (js/seal.js): okey =
// HMAC(READ_KEY, author‖_t‖semanticId). Dispatches by type exactly like id.* /
// expectedKey, so a record's opaque slot is recomputable from its own signed fields.
export function semanticId (type, data) {
  switch (type) {
    case TYPE.COMMUNITY: return data.slug != null ? id.community(data.slug) : null
    case TYPE.POST: return data.community != null && data.cid != null ? id.post(data.community, data.cid) : null
    case TYPE.COMMENT: return data.community != null && data.postCid != null && data.cid != null ? id.comment(data.community, data.postCid, data.cid) : null
    case TYPE.VOTE: return data.targetCid != null && data.author != null ? id.vote(data.targetCid, data.author) : null
    case TYPE.PROFILE: return data.author != null ? id.profile(data.author) : null
    case TYPE.MOD: return data.community != null && data.actionId != null ? id.mod(data.community, data.actionId) : null
    case TYPE.HEAD: return data.author != null ? id.head(data.author) : null
    case TYPE.FOLLOW: return data.target != null && data.author != null ? id.follow(data.target, data.author) : null
    case TYPE.MEMBER: return data.community != null && data.author != null ? id.member(data.community, data.author) : null
    default: return null
  }
}

// MOD actions a community moderator may perform.
export const MOD = {
  REMOVE: 'remove', APPROVE: 'approve',
  LOCK: 'lock', UNLOCK: 'unlock',
  STICKY: 'sticky', UNSTICKY: 'unsticky',
  BAN: 'ban', UNBAN: 'unban',
  ADD_MOD: 'addmod', REMOVE_MOD: 'removemod'
}

// Build a threaded comment tree from a flat list. Each node carries `children`.
// Orphaned replies (missing parent) are attached at root so nothing is lost.
//
// Cycle-safe: records arrive signed but a malicious peer can sign comments whose
// parentCid chain loops (A→B→A). Such records pass the merge's per-record
// validation (each is individually well-formed), so the tree builder must reject
// the back-edge itself — otherwise the looped nodes never become roots (they
// vanish from the rendered thread) and sortCommentTree/countDescendants recurse
// forever. We attach a node under its parent only when doing so can't form a
// cycle; every node ends up exactly once, either under a parent or at root.
export function buildCommentTree (comments) {
  const byCid = new Map()
  for (const c of comments) byCid.set(c.cid, { ...c, children: [] })
  const roots = []
  const wouldCycle = (node, parent) => {
    let cur = parent
    let hops = 0
    while (cur && hops++ <= byCid.size) {
      if (cur === node) return true
      cur = cur.parentCid ? byCid.get(cur.parentCid) : null
    }
    return false
  }
  for (const node of byCid.values()) {
    const parent = node.parentCid && byCid.get(node.parentCid)
    if (parent && parent !== node && !wouldCycle(node, parent)) parent.children.push(node)
    else roots.push(node)
  }
  return { roots, index: byCid }
}

// Recursively sort a comment tree using a node comparator (from ranking).
export function sortCommentTree (roots, sorter) {
  const sorted = sorter(roots)
  for (const n of sorted) if (n.children.length) n.children = sortCommentTree(n.children, sorter)
  return sorted
}

// Count all descendants of a node (for "N replies" / collapse labels).
export function countDescendants (node) {
  let n = 0
  for (const c of node.children) n += 1 + countDescendants(c)
  return n
}

// Annotate every node with `_descendants` (total nodes beneath it) in ONE
// bottom-up pass, so a renderer can read node._descendants in O(1) instead of
// calling countDescendants() per node (which re-walks each subtree — O(n²) over
// a full tree). Call after the tree is built/sorted. Returns `roots` for chaining.
export function annotateDescendants (roots) {
  const visit = (node) => {
    let n = 0
    for (const c of node.children) n += 1 + visit(c)
    node._descendants = n
    return n
  }
  for (const r of roots) visit(r)
  return roots
}

// Resolve the effective moderator set for a community: creator is always a mod;
// addmod/removemod actions by an existing mod mutate the set (creator's actions
// always trusted; a mod can add others). Returns a Set of author pubkeys.
export function resolveMods (community, modActions) {
  const mods = new Set()
  if (community && community.creator) mods.add(community.creator)
  // Apply addmod/removemod in timestamp order; only honor actions by current mods.
  const actions = (modActions || [])
    .filter(a => a.action === MOD.ADD_MOD || a.action === MOD.REMOVE_MOD)
    .sort((a, b) => a.ts - b.ts)
  for (const a of actions) {
    if (!mods.has(a.by)) continue // action author must already be a mod
    if (a.action === MOD.ADD_MOD && a.targetUser) mods.add(a.targetUser)
    if (a.action === MOD.REMOVE_MOD && a.targetUser && a.targetUser !== community.creator) mods.delete(a.targetUser)
  }
  return mods
}

// Reduce mod actions into an overlay of effective states, honoring only actions
// authored by a current moderator. Returns:
//   { removed:Set<cid>, locked:Set<postCid>, stickied:Set<cid>, banned:Set<user> }
export function modOverlay (community, modActions) {
  const mods = resolveMods(community, modActions)
  const removed = new Map()   // cid -> bool (last write wins)
  const locked = new Map()    // postCid -> bool
  const stickied = new Map()  // cid -> bool
  const banned = new Map()    // user -> bool
  const actions = (modActions || []).slice().sort((a, b) => a.ts - b.ts)
  for (const a of actions) {
    if (!mods.has(a.by)) continue
    switch (a.action) {
      case MOD.REMOVE: if (a.targetCid) removed.set(a.targetCid, true); break
      case MOD.APPROVE: if (a.targetCid) removed.set(a.targetCid, false); break
      case MOD.LOCK: if (a.targetCid) locked.set(a.targetCid, true); break
      case MOD.UNLOCK: if (a.targetCid) locked.set(a.targetCid, false); break
      case MOD.STICKY: if (a.targetCid) stickied.set(a.targetCid, true); break
      case MOD.UNSTICKY: if (a.targetCid) stickied.set(a.targetCid, false); break
      case MOD.BAN: if (a.targetUser) banned.set(a.targetUser, true); break
      case MOD.UNBAN: if (a.targetUser) banned.set(a.targetUser, false); break
    }
  }
  const toSet = (m) => new Set([...m.entries()].filter(([, v]) => v).map(([k]) => k))
  return { mods, removed: toSet(removed), locked: toSet(locked), stickied: toSet(stickied), banned: toSet(banned) }
}
