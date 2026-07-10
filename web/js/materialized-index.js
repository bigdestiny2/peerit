// materialized-index.js — a rebuildable, device-local read index over Peerit's
// already-admitted signed records. It is deliberately NOT another source of
// truth: Data rebuilds it from the merged record view whenever that view changes.
//
// The storage model remains signed per-author records. This class simply keeps
// both directions of graph edges plus the feed/thread adjacency maps that a
// graph database would normally provide. Keeping it local preserves v2's wire
// privacy property: relays still see only opaque `v2!<okey>` cells.

import { TYPE } from './model.js'

function typeOf (key) {
  // Data only gives this index semantic (v1-style) keys, including reconstructed
  // v2 rows. The key is therefore the type authority, matching gossip's treatment
  // of legacy rows; an arbitrary legacy `_t` extension must never retag a record.
  const bang = String(key || '').indexOf('!')
  return bang < 0 ? '' : String(key).slice(0, bang)
}

function scopeMap (root, scope) {
  let bucket = root.get(scope)
  if (!bucket) {
    bucket = { rows: new Map(), keys: null }
    root.set(scope, bucket)
  }
  return bucket
}

function put (root, scope, key, value) {
  const bucket = scopeMap(root, scope)
  bucket.rows.set(key, value)
  bucket.keys = null
}

function del (root, scope, key) {
  const bucket = root.get(scope)
  if (!bucket) return
  bucket.rows.delete(key)
  bucket.keys = null
  if (bucket.rows.size === 0) root.delete(scope)
}

function values (root, scope) {
  const bucket = root.get(scope)
  if (!bucket) return []
  if (!bucket.keys) bucket.keys = [...bucket.rows.keys()].sort()
  return bucket.keys.map(key => bucket.rows.get(key))
}

function count (root, scope) {
  const bucket = root.get(scope)
  return bucket ? bucket.rows.size : 0
}

const ALL = '*'
const threadScope = (community, postCid) => String(community) + '\u0000' + String(postCid)

export class MaterializedIndex {
  constructor () {
    this.records = new Map()
    this.communities = new Map()
    this.postsByCommunity = new Map()
    this.postsByAuthor = new Map()
    this.commentsByThread = new Map()
    this.commentsByAuthor = new Map()
    this.commentsAll = new Map()
    this.votesByTarget = new Map()
    this.votesAll = new Map()
    this.modsByCommunity = new Map()
    this.followersByTarget = new Map()
    this.followingByAuthor = new Map()
    this.membersByCommunity = new Map()
    this.membershipsByAuthor = new Map()
  }

  clear () {
    this.records.clear()
    this.communities.clear()
    this.postsByCommunity.clear()
    this.postsByAuthor.clear()
    this.commentsByThread.clear()
    this.commentsByAuthor.clear()
    this.commentsAll.clear()
    this.votesByTarget.clear()
    this.votesAll.clear()
    this.modsByCommunity.clear()
    this.followersByTarget.clear()
    this.followingByAuthor.clear()
    this.membersByCommunity.clear()
    this.membershipsByAuthor.clear()
  }

  upsert (key, record) {
    if (typeof key !== 'string' || !key || !record || typeof record !== 'object') return
    this.remove(key)
    this.records.set(key, record)
    this._add(key, record)
  }

  remove (key) {
    const previous = this.records.get(key)
    if (!previous) return
    this._remove(key, previous)
    this.records.delete(key)
  }

  get (key) { return this.records.get(key) || null }

  listCommunities () { return values(this.communities, ALL) }
  listPostsIn (community) { return values(this.postsByCommunity, community) }
  listPostsByAuthor (author) { return values(this.postsByAuthor, author) }
  listComments (community, postCid) { return values(this.commentsByThread, threadScope(community, postCid)) }
  listCommentsByAuthor (author) { return values(this.commentsByAuthor, author) }
  listAllComments () { return values(this.commentsAll, ALL) }
  listVotesFor (targetCid) { return values(this.votesByTarget, targetCid) }
  listAllVotes () { return values(this.votesAll, ALL) }
  listModActions (community) { return values(this.modsByCommunity, community) }
  followersOf (target) { return values(this.followersByTarget, target).map(row => row.author) }
  followingOf (author) { return values(this.followingByAuthor, author).map(row => row.target) }
  membersOf (community) { return values(this.membersByCommunity, community).map(row => row.author) }
  membershipsOf (author) { return values(this.membershipsByAuthor, author).map(row => row.community) }
  postCount (community) { return count(this.postsByCommunity, community) }
  memberCount (community) { return count(this.membersByCommunity, community) }

  _add (key, record) {
    switch (typeOf(key)) {
      case TYPE.COMMUNITY:
        if (record.slug != null) put(this.communities, ALL, key, record)
        break
      case TYPE.POST:
        if (record.community != null) put(this.postsByCommunity, record.community, key, record)
        if (record.author != null) put(this.postsByAuthor, record.author, key, record)
        break
      case TYPE.COMMENT:
        if (record.community != null && record.postCid != null) put(this.commentsByThread, threadScope(record.community, record.postCid), key, record)
        if (record.author != null) put(this.commentsByAuthor, record.author, key, record)
        put(this.commentsAll, ALL, key, record)
        break
      case TYPE.VOTE:
        if (record.targetCid != null) put(this.votesByTarget, record.targetCid, key, record)
        put(this.votesAll, ALL, key, record)
        break
      case TYPE.MOD:
        if (record.community != null) put(this.modsByCommunity, record.community, key, record)
        break
      case TYPE.FOLLOW:
        if (!record.deleted && record.target != null && record.author != null) {
          put(this.followersByTarget, record.target, key, record)
          put(this.followingByAuthor, record.author, key, record)
        }
        break
      case TYPE.MEMBER:
        if (!record.deleted && record.community != null && record.author != null) {
          put(this.membersByCommunity, record.community, key, record)
          put(this.membershipsByAuthor, record.author, key, record)
        }
        break
    }
  }

  _remove (key, record) {
    switch (typeOf(key)) {
      case TYPE.COMMUNITY:
        del(this.communities, ALL, key)
        break
      case TYPE.POST:
        del(this.postsByCommunity, record.community, key)
        del(this.postsByAuthor, record.author, key)
        break
      case TYPE.COMMENT:
        del(this.commentsByThread, threadScope(record.community, record.postCid), key)
        del(this.commentsByAuthor, record.author, key)
        del(this.commentsAll, ALL, key)
        break
      case TYPE.VOTE:
        del(this.votesByTarget, record.targetCid, key)
        del(this.votesAll, ALL, key)
        break
      case TYPE.MOD:
        del(this.modsByCommunity, record.community, key)
        break
      case TYPE.FOLLOW:
        del(this.followersByTarget, record.target, key)
        del(this.followingByAuthor, record.author, key)
        break
      case TYPE.MEMBER:
        del(this.membersByCommunity, record.community, key)
        del(this.membershipsByAuthor, record.author, key)
        break
    }
  }
}
