// data.js — the peerit domain API. Turns user intentions (create community,
// submit post, vote, moderate…) into signed ops on the sync layer, and reads
// the materialized view back into typed records. Ranking/threading live in
// ranking.js / model.js; this module is CRUD + queries + vote tallies.

import { keys, id as mkid, TYPE, MOD, modOverlay, resolveMods } from './model.js'
import { tally as tallyVotes } from './ranking.js'
import { canonical } from './canon.js'
import { uid, isValidSlug, normalizeSlug, safeUserUrl } from './util.js'
import { mint, MIN_BITS } from './pow.js'
import { assertRecoveryBundleMatches, buildRecoveryBundle, isHex64 } from './recovery.js'
import { boxBody, unboxToBody, shouldBox, canBox } from './blob-store.js'

// Decrypted-body cache is keyed by blobId (a content hash), so it is immutable
// and never goes stale — a bounded FIFO is all it needs.
const BODY_CACHE_MAX = 500

export class Data {
  constructor (sync, identity, opts = {}) {
    this.sync = sync
    this.id = identity
    this.minBits = opts.minBits || MIN_BITS
    this._profileCache = new Map() // pub -> { rec, at }
    this._tallyCache = new Map()   // `${viewer}:${cid}` -> { val, epoch }
    this._commentCountCache = new Map() // `${community}/${postCid}` -> { val, contentEpoch }
    this._searchIndex = null
    this._epoch = 0          // bumped on EVERY write; gates vote tallies
    this._contentEpoch = 0   // bumped only when searchable content changes; gates comment-count + search caches
    this._bodyCache = new Map() // blobId -> decrypted body (content-addressed → never stale)
  }

  me () { return this.id.me() }

  // `opClass === 'vote'` means only vote tallies changed — comment counts and the
  // search index (which votes never touch) survive, so a vote no longer forces a
  // full search-index rebuild on the next search.
  invalidateViewCaches (opClass) {
    if (opClass === 'none') return
    this._epoch++
    this._tallyCache.clear()
    if (opClass !== 'vote') {
      this._contentEpoch++
      this._commentCountCache.clear()
      this._searchIndex = null
    }
  }

  async _listPrefix (prefix, { limit = 1000 } = {}) {
    const rows = []
    let gt = null
    while (true) {
      const opts = gt
        ? { gt, lt: prefix + '\xff', limit }
        : { gte: prefix, lt: prefix + '\xff', limit }
      const batch = await this.sync.range(opts)
      rows.push(...batch)
      const last = batch[batch.length - 1] && batch[batch.length - 1].key
      if (!last || batch.length < limit) break
      gt = last
    }
    return rows
  }

  // Sign a record's canonical form and attach verification metadata. MUST be
  // called on every create AND every edit/delete — the gossip merge recomputes
  // the canonical form and rejects records whose signature no longer matches
  // (a stale sig from a spread `...prev` would otherwise look forged).
  async _sign (type, data) {
    // Fail CLOSED: if signing fails, the calling op throws before append — never
    // write an unsigned record (which secure peers would reject as untrusted).
    const s = await this.id.sign(canonical(type, data))
    return { _sig: s.signature, _k: s.publicKey, _dk: s.driveKey, _ns: s.namespace, _alg: s.algorithm }
  }

  async _powSign (type, data, onProgress) {
    data.pow = await mint(type, data, this.minBits[type] || 0, { onProgress })
    Object.assign(data, await this._sign(type, data))
    return data
  }

  // ---- BlindShard Phase 2: box-before-store --------------------------------
  // Replace a long plaintext `data.body` with an opaque, content-addressed
  // ciphertext record (blob!<blobId>) + a signed manifest on the record. Mutates
  // `data` in place (body -> '', adds `data.blob`). Call BEFORE signing so the
  // manifest is covered by the record's signature; the blob itself is a separate
  // signed record so it flows through the normal admit/verify/merge path.
  async _boxBody (data) {
    const { manifest, ct } = await boxBody(data.body)
    const blobData = { id: manifest.blobId, blobId: manifest.blobId, ct, author: this.me().pubkey }
    await this._powSign(TYPE.BLOB, blobData) // small PoW so blobs aren't a free large-append flood vector
    await this.sync.append({ type: TYPE.BLOB, data: blobData })
    data.body = ''
    data.blob = manifest
  }

  // Return a render-ready copy of a post: if it carries a blob manifest, fetch
  // blob!<blobId>, verify the two content-address gates, and decrypt the body.
  // Never mutates the stored record; on a missing/withheld/tampered blob it
  // degrades gracefully to an empty body flagged `_blobMissing` (a relay can
  // withhold a blob but can never forge one past the gates in unboxToBody).
  async _hydrate (rec) {
    if (!rec || !rec.blob || !rec.blob.blobId) return rec
    const m = rec.blob
    const cached = this._bodyCache.get(m.blobId)
    if (cached != null) return { ...rec, body: cached }
    try {
      const blob = await this.sync.get(keys.blob(m.blobId))
      if (!blob || !blob.ct) return { ...rec, body: '', _blobMissing: true }
      const body = await unboxToBody(blob.ct, m)
      if (this._bodyCache.size >= BODY_CACHE_MAX) this._bodyCache.delete(this._bodyCache.keys().next().value)
      this._bodyCache.set(m.blobId, body)
      return { ...rec, body }
    } catch {
      return { ...rec, body: '', _blobMissing: true }
    }
  }

  // Raw stored post (no hydration) — used by edit/delete so a re-signed record is
  // never built from a decrypted-and-annotated copy.
  async _rawPost (community, cid) { return this.sync.get(keys.post(community, cid)) }

  // ---- Communities ----------------------------------------------------------
  async createCommunity ({ slug, title, description, rules, onProgress }) {
    slug = normalizeSlug(slug)
    if (!isValidSlug(slug)) throw new Error('Community name must be 2–24 chars: a–z, 0–9, _')
    const existing = await this.getCommunity(slug)
    if (existing) throw new Error('r/' + slug + ' already exists')
    const me = this.me()
    const now = Date.now()
    const data = {
      id: mkid.community(slug), slug, title: (title || slug).slice(0, 100),
      description: (description || '').slice(0, 500),
      rules: Array.isArray(rules) ? rules.slice(0, 20) : [],
      creator: me.pubkey, createdAt: now, updatedAt: now, author: me.pubkey
    }
    await this._powSign(TYPE.COMMUNITY, data, onProgress)
    await this.sync.append({ type: TYPE.COMMUNITY, data })
    this.invalidateViewCaches()
    return data
  }

  async getCommunity (slug) { return this.sync.get(keys.community(slug)) }

  async listCommunities () {
    const rows = await this.sync.list(keys.communityPrefix(), { limit: 1000 })
    return rows.map(r => r.value).filter(Boolean)
  }

  async updateCommunity (slug, patch) {
    const c = await this.getCommunity(slug)
    if (!c) throw new Error('No such community')
    const me = this.me()
    // Owner binding: only the founder's outbox holds the canonical community
    // record, so only the founder can change its metadata and have it propagate.
    if (c.creator !== me.pubkey) throw new Error('Only the founder can edit community details')
    const now = Date.now()
    const data = { ...c, ...patch, id: mkid.community(slug), slug, creator: c.creator, createdAt: c.createdAt, updatedAt: now }
    Object.assign(data, await this._sign(TYPE.COMMUNITY, data))
    await this.sync.append({ type: TYPE.COMMUNITY, data })
    this.invalidateViewCaches()
    return data
  }

  // ---- Posts ----------------------------------------------------------------
  async submitPost ({ community, kind, title, body, url, onProgress }) {
    const c = await this.getCommunity(community)
    if (!c) throw new Error('No such community')
    const me = this.me()
    const banned = (await this.overlay(community)).banned
    if (banned.has(me.pubkey)) throw new Error('You are banned from r/' + community)
    if (!title || !title.trim()) throw new Error('A title is required')
    kind = ['text', 'link', 'image'].includes(kind) ? kind : 'text'
    let postUrl = ''
    if (kind !== 'text') {
      postUrl = String(url || '').trim().slice(0, 2000)
      if (!safeUserUrl(postUrl)) throw new Error('URL must start with http://, https://, hyper://, or pear://')
    }
    const cid = uid()
    const now = Date.now()
    const data = {
      id: mkid.post(community, cid), cid, community, kind,
      title: title.trim().slice(0, 300),
      body: kind === 'text' ? String(body || '').slice(0, 40000) : '',
      url: kind !== 'text' ? postUrl : '',
      author: me.pubkey, createdAt: now, editedAt: 0, deleted: false
    }
    // Box a long text body into an opaque blob before signing (design §5 Phase 2).
    if (kind === 'text' && canBox() && shouldBox(data.body)) await this._boxBody(data)
    await this._powSign(TYPE.POST, data, onProgress)
    await this.sync.append({ type: TYPE.POST, data })
    this.invalidateViewCaches()
    return data
  }

  async getPost (community, cid) {
    const p = await this._rawPost(community, cid)
    return p ? this._hydrate(p) : p
  }

  // Body-free callers (karma, activity) pass { hydrate: false } to skip fetching +
  // decrypting every boxed blob they would only discard (review FIX 4).
  async listPostsIn (community, { hydrate = true } = {}) {
    const rows = await this.sync.list(keys.postsIn(community), { limit: 1000 })
    const recs = rows.map(r => r.value).filter(Boolean)
    return hydrate ? Promise.all(recs.map(r => this._hydrate(r))) : recs
  }

  async editPost (community, cid, body) {
    const p = await this._rawPost(community, cid)
    if (!p) throw new Error('Post not found')
    if (p.author !== this.me().pubkey) throw new Error('You can only edit your own post')
    const data = { ...p, body: String(body || '').slice(0, 40000), editedAt: Date.now() }
    delete data.blob // drop any prior manifest; re-box below if the new body is still long
    if (data.kind === 'text' && canBox() && shouldBox(data.body)) await this._boxBody(data)
    Object.assign(data, await this._sign(TYPE.POST, data))
    await this.sync.append({ type: TYPE.POST, data })
    this.invalidateViewCaches()
    return data
  }

  async deletePost (community, cid) {
    const p = await this._rawPost(community, cid)
    if (!p) return
    if (p.author !== this.me().pubkey) throw new Error('You can only delete your own post')
    const data = { ...p, deleted: true, body: '', url: '', title: p.title, editedAt: Date.now() }
    delete data.blob // a deleted post references no blob
    Object.assign(data, await this._sign(TYPE.POST, data))
    await this.sync.append({ type: TYPE.POST, data })
    this.invalidateViewCaches()
  }

  // Aggregate posts across communities (for home/all feeds).
  async listAllPosts (communities) {
    let slugs = communities
    if (!slugs) slugs = (await this.listCommunities()).map(c => c.slug)
    const lists = await Promise.all(slugs.map(s => this.listPostsIn(s).catch(() => [])))
    return lists.flat()
  }

  // ---- Comments -------------------------------------------------------------
  async addComment ({ community, postCid, parentCid, body, onProgress }) {
    if (!body || !body.trim()) throw new Error('Comment cannot be empty')
    const me = this.me()
    const ov = await this.overlay(community)
    if (ov.banned.has(me.pubkey)) throw new Error('You are banned from r/' + community)
    if (ov.locked.has(postCid)) throw new Error('This thread is locked')
    const cid = uid()
    const now = Date.now()
    const data = {
      id: mkid.comment(community, postCid, cid), cid, community, postCid,
      parentCid: parentCid || null, body: body.trim().slice(0, 10000),
      author: me.pubkey, createdAt: now, editedAt: 0, deleted: false
    }
    await this._powSign(TYPE.COMMENT, data, onProgress)
    await this.sync.append({ type: TYPE.COMMENT, data })
    this.invalidateViewCaches()
    return data
  }

  async listComments (community, postCid) {
    const rows = await this.sync.list(keys.commentsOn(community, postCid), { limit: 1000 })
    return rows.map(r => r.value).filter(Boolean)
  }

  async editComment (community, postCid, cid, body) {
    const c = await this.sync.get(keys.comment(community, postCid, cid))
    if (!c) throw new Error('Comment not found')
    if (c.author !== this.me().pubkey) throw new Error('You can only edit your own comment')
    const data = { ...c, body: String(body || '').slice(0, 10000), editedAt: Date.now() }
    Object.assign(data, await this._sign(TYPE.COMMENT, data))
    await this.sync.append({ type: TYPE.COMMENT, data })
    this.invalidateViewCaches()
    return data
  }

  async deleteComment (community, postCid, cid) {
    const c = await this.sync.get(keys.comment(community, postCid, cid))
    if (!c) return
    if (c.author !== this.me().pubkey) throw new Error('You can only delete your own comment')
    const data = { ...c, deleted: true, body: '', editedAt: Date.now() }
    Object.assign(data, await this._sign(TYPE.COMMENT, data))
    await this.sync.append({ type: TYPE.COMMENT, data })
    this.invalidateViewCaches()
  }

  // ---- Votes ----------------------------------------------------------------
  async vote (targetCid, community, targetType, value) {
    const me = this.me()
    value = value === 1 ? 1 : value === -1 ? -1 : 0
    const now = Date.now()
    const data = {
      id: mkid.vote(targetCid, me.pubkey), targetCid, targetType, community,
      value, author: me.pubkey, ts: now
    }
    Object.assign(data, await this._sign(TYPE.VOTE, data))
    await this.sync.append({ type: TYPE.VOTE, data })
    this.invalidateViewCaches('vote')
    return data
  }

  async rawVotes (targetCid) {
    const rows = await this.sync.list(keys.votesFor(targetCid), { limit: 1000 })
    return rows.map(r => r.value).filter(Boolean)
  }

  async tallyFor (targetCid) {
    const me = this.me().pubkey
    const votes = await this.rawVotes(targetCid)
    return tallyVotes(votes, me)
  }

  // Tally many targets at once (used to enrich a feed). Returns Map cid->tally.
  async tallyMany (cids) {
    const me = this.me().pubkey
    const uniq = [...new Set(cids)]
    const out = new Map()
    const missing = []
    for (const cid of uniq) {
      const key = me + ':' + cid
      const cached = this._tallyCache.get(key)
      if (cached && cached.epoch === this._epoch) out.set(cid, cached.val)
      else missing.push(cid)
    }
    if (missing.length) {
      // Scan only the votes for each missing target (vote!<cid>!…) instead of the
      // whole vote table — turns a feed render from O(all votes) into O(votes on
      // the visible posts). Same prefix scheme rawVotes uses.
      const lists = await Promise.all(missing.map(cid => this._listPrefix(keys.votesFor(cid))))
      for (let i = 0; i < missing.length; i++) {
        const cid = missing[i]
        const votes = lists[i].map(r => r.value).filter(Boolean)
        const val = tallyVotes(votes, me)
        this._tallyCache.set(me + ':' + cid, { val, epoch: this._epoch })
        out.set(cid, val)
      }
    }
    return out
  }

  // Attach `.tally` to each post/comment record.
  async withTallies (records) {
    const map = await this.tallyMany(records.map(r => r.cid))
    return records.map(r => ({ ...r, tally: map.get(r.cid) || { up: 0, down: 0, score: 0, myVote: 0, total: 0 } }))
  }

  async commentCountsFor (posts) {
    const out = new Map()
    const missing = []
    for (const p of posts) {
      const key = p.community + '/' + p.cid
      const cached = this._commentCountCache.get(key)
      if (cached && cached.epoch === this._contentEpoch) out.set(p.cid, cached.val)
      else missing.push(p)
    }
    if (missing.length) {
      // Count per post via the comment!<community>!<postCid>! prefix instead of
      // scanning the entire comment table on every feed render. Deleted comments
      // are still counted (truthy value), matching the prior behaviour.
      const lists = await Promise.all(missing.map(p => this._listPrefix(keys.commentsOn(p.community, p.cid))))
      for (let i = 0; i < missing.length; i++) {
        const p = missing[i]
        const key = p.community + '/' + p.cid
        const val = lists[i].reduce((n, r) => n + (r.value ? 1 : 0), 0)
        this._commentCountCache.set(key, { val, epoch: this._contentEpoch })
        out.set(p.cid, val)
      }
    }
    return out
  }

  // ---- Profiles -------------------------------------------------------------
  async setProfile ({ name, bio, color }) {
    const me = this.me()
    const now = Date.now()
    const prev = await this.getProfile(me.pubkey)
    const data = {
      id: mkid.profile(me.pubkey), author: me.pubkey,
      name: (name != null ? name : prev && prev.name || '').slice(0, 32),
      bio: (bio != null ? bio : prev && prev.bio || '').slice(0, 500),
      color: color || (prev && prev.color) || '',
      createdAt: prev ? prev.createdAt : now, updatedAt: now
    }
    Object.assign(data, await this._sign(TYPE.PROFILE, data))
    await this.sync.append({ type: TYPE.PROFILE, data })
    this._profileCache.set(me.pubkey, { rec: data, at: Date.now() })
    this.invalidateViewCaches()
    return data
  }

  async getProfile (pub) {
    const cached = this._profileCache.get(pub)
    if (cached && Date.now() - cached.at < 15000) return cached.rec
    const rec = await this.sync.get(keys.profile(pub))
    this._profileCache.set(pub, { rec, at: Date.now() })
    return rec
  }

  async displayName (pub) {
    if (!pub) return 'unknown'
    const p = await this.getProfile(pub)
    if (p && p.name) return p.name
    return 'u/' + pub.slice(0, 8)
  }

  invalidateProfile (pub) { this._profileCache.delete(pub) }

  // Karma: sum of vote scores on a user's posts + comments across all
  // communities. Lazy + capped — only called on a profile page.
  async karmaFor (pub) {
    const communities = (await this.listCommunities()).map(c => c.slug)
    let postKarma = 0, commentKarma = 0, postCount = 0, commentCount = 0
    for (const slug of communities) {
      // List each community's posts ONCE and reuse for both the author's own
      // posts (post karma) and the per-post comment scan (comment karma).
      const allPosts = await this.listPostsIn(slug, { hydrate: false }) // karma never reads bodies
      const mine = allPosts.filter(p => p.author === pub && !p.deleted)
      postCount += mine.length
      if (mine.length) {
        const postTallies = await this.tallyMany(mine.map(p => p.cid))
        for (const p of mine) postKarma += (postTallies.get(p.cid) || { score: 0 }).score
      }
      // Comments aren't prefix-listable by author cheaply; scan per community post.
      for (const p of allPosts) {
        const cs = (await this.listComments(slug, p.cid)).filter(c => c.author === pub && !c.deleted)
        commentCount += cs.length
        if (cs.length) {
          const t = await this.tallyMany(cs.map(c => c.cid))
          for (const c of cs) commentKarma += (t.get(c.cid) || { score: 0 }).score
        }
      }
    }
    return { postKarma, commentKarma, total: postKarma + commentKarma, postCount, commentCount }
  }

  // Gather a user's posts + comments across communities (for profile page).
  async userActivity (pub, { limit = 100 } = {}) {
    const communities = (await this.listCommunities()).map(c => c.slug)
    const posts = []
    const comments = []
    for (const slug of communities) {
      const slugPosts = await this.listPostsIn(slug, { hydrate: false }) // activity lists titles, not bodies
      for (const p of slugPosts) {
        if (p.author === pub && !p.deleted) posts.push(p)
      }
      for (const p of slugPosts) {
        for (const c of await this.listComments(slug, p.cid)) {
          if (c.author === pub && !c.deleted) comments.push({ ...c, postTitle: p.title })
        }
      }
    }
    return { posts: posts.slice(0, limit), comments: comments.slice(0, limit) }
  }

  async _ensureSearchIndex () {
    if (this._searchIndex && this._searchIndex.epoch === this._contentEpoch) return this._searchIndex
    const communities = await this.listCommunities()
    const posts = await this.listAllPosts(communities.map(c => c.slug))
    const postTitle = new Map(posts.map(p => [p.community + '/' + p.cid, p.title]))
    const comments = (await this._listPrefix(keys.commentPrefix()))
      .map(r => r.value)
      .filter(c => c && !c.deleted)
      .map(c => ({ ...c, postTitle: postTitle.get(c.community + '/' + c.postCid) || '' }))
    const index = {
      epoch: this._contentEpoch,
      communities: communities.map(c => ({
        record: c,
        text: (c.slug + ' ' + (c.title || '') + ' ' + (c.description || '')).toLowerCase()
      })),
      posts: posts.filter(p => !p.deleted).map(p => ({
        record: p,
        text: (p.title + ' ' + (p.body || '') + ' ' + (p.url || '')).toLowerCase()
      })),
      comments: comments.map(c => ({
        record: c,
        text: ((c.body || '') + ' ' + (c.postTitle || '')).toLowerCase()
      }))
    }
    this._searchIndex = index
    return index
  }

  async search (query, { limit = 50 } = {}) {
    const needle = String(query || '').trim().toLowerCase()
    if (!needle) return { communities: [], posts: [], comments: [] }
    const index = await this._ensureSearchIndex()
    return {
      communities: index.communities.filter(it => it.text.includes(needle)).map(it => it.record),
      posts: index.posts.filter(it => it.text.includes(needle)).slice(0, limit).map(it => it.record),
      comments: index.comments.filter(it => it.text.includes(needle)).slice(0, limit).map(it => it.record)
    }
  }

  // ---- Moderation -----------------------------------------------------------
  async listModActions (community) {
    const rows = await this.sync.list(keys.modsIn(community), { limit: 1000 })
    return rows.map(r => r.value).filter(Boolean)
  }

  async getMods (community) {
    const c = await this.getCommunity(community)
    const actions = await this.listModActions(community)
    return resolveMods(c, actions)
  }

  async overlay (community) {
    const c = await this.getCommunity(community)
    const actions = await this.listModActions(community)
    return modOverlay(c, actions)
  }

  async modAction (community, { action, targetCid, targetUser, reason }) {
    const me = this.me()
    const mods = await this.getMods(community)
    if (!mods.has(me.pubkey)) throw new Error('Only moderators can do that')
    const actionId = uid()
    const now = Date.now()
    const data = {
      id: mkid.mod(community, actionId), actionId, community, action,
      targetCid: targetCid || null, targetUser: targetUser || null,
      reason: (reason || '').slice(0, 300), by: me.pubkey, ts: now
    }
    Object.assign(data, await this._sign(TYPE.MOD, data))
    await this.sync.append({ type: TYPE.MOD, data })
    this.invalidateViewCaches()
    return data
  }

  // Convenience wrappers
  removePost (community, cid, reason) { return this.modAction(community, { action: MOD.REMOVE, targetCid: cid, reason }) }
  approvePost (community, cid) { return this.modAction(community, { action: MOD.APPROVE, targetCid: cid }) }
  toggleLock (community, cid, locked) { return this.modAction(community, { action: locked ? MOD.UNLOCK : MOD.LOCK, targetCid: cid }) }
  toggleSticky (community, cid, stuck) { return this.modAction(community, { action: stuck ? MOD.UNSTICKY : MOD.STICKY, targetCid: cid }) }
  banUser (community, user, reason) { return this.modAction(community, { action: MOD.BAN, targetUser: user, reason }) }
  unbanUser (community, user) { return this.modAction(community, { action: MOD.UNBAN, targetUser: user }) }
  addMod (community, user) { return this.modAction(community, { action: MOD.ADD_MOD, targetUser: user }) }

  async status () { return this.sync.status() }

  async recoveryOutboxes () {
    if (this.sync.recoveryOutboxes) return this.sync.recoveryOutboxes()
    const s = await this.status()
    return isHex64(s.inviteKey) ? [{ appId: this.me().pubkey, inviteKey: s.inviteKey }] : []
  }

  async recoveryBundle () {
    const me = this.me()
    return buildRecoveryBundle({
      driveKey: me.driveKey,
      publicKey: me.pubkey,
      outboxes: await this.recoveryOutboxes()
    })
  }

  async importRecoveryBundle (bundle) {
    const me = this.me()
    const accepted = assertRecoveryBundleMatches(bundle, { driveKey: me.driveKey, publicKey: me.pubkey })
    if (!this.sync.importRecoveryBundle) throw new Error('This backend cannot import app recovery bundles.')
    const result = await this.sync.importRecoveryBundle(accepted)
    this.invalidateViewCaches()
    return result
  }
}

export function createData (sync, identity, opts) { return new Data(sync, identity, opts) }

export function cacheClassForChangedKeys (changed) {
  if (Array.isArray(changed)) {
    if (changed.length === 0) return 'none'
    return changed.every(k => String(k).startsWith(keys.voteAll())) ? 'vote' : 'content'
  }
  return 'content'
}
