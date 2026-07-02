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
  BLOB: 'blob'
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
  blobPrefix: () => `${TYPE.BLOB}!`
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
  blob: (blobId) => blobId
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
