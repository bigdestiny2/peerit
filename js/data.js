// data.js — the peerit domain API. Turns user intentions (create community,
// submit post, vote, moderate…) into signed ops on the sync layer, and reads
// the materialized view back into typed records. Ranking/threading live in
// ranking.js / model.js; this module is CRUD + queries + vote tallies.

import { keys, id as mkid, TYPE, MOD, modOverlay, resolveMods } from './model.js'
import { tally as tallyVotes } from './ranking.js'
import { canonical } from './canon.js'
import { uid, isValidSlug, normalizeSlug, safeUserUrl } from './util.js'

export class Data {
  constructor (sync, identity) {
    this.sync = sync
    this.id = identity
    this._profileCache = new Map() // pub -> { rec, at }
    this._tallyCache = new Map()   // cid -> { val, at }
  }

  me () { return this.id.me() }

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

  // ---- Communities ----------------------------------------------------------
  async createCommunity ({ slug, title, description, rules }) {
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
    Object.assign(data, await this._sign(TYPE.COMMUNITY, data))
    await this.sync.append({ type: TYPE.COMMUNITY, data })
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
    return data
  }

  // ---- Posts ----------------------------------------------------------------
  async submitPost ({ community, kind, title, body, url }) {
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
    Object.assign(data, await this._sign(TYPE.POST, data))
    await this.sync.append({ type: TYPE.POST, data })
    return data
  }

  async getPost (community, cid) { return this.sync.get(keys.post(community, cid)) }

  async listPostsIn (community) {
    const rows = await this.sync.list(keys.postsIn(community), { limit: 1000 })
    return rows.map(r => r.value).filter(Boolean)
  }

  async editPost (community, cid, body) {
    const p = await this.getPost(community, cid)
    if (!p) throw new Error('Post not found')
    if (p.author !== this.me().pubkey) throw new Error('You can only edit your own post')
    const data = { ...p, body: String(body || '').slice(0, 40000), editedAt: Date.now() }
    Object.assign(data, await this._sign(TYPE.POST, data))
    await this.sync.append({ type: TYPE.POST, data })
    return data
  }

  async deletePost (community, cid) {
    const p = await this.getPost(community, cid)
    if (!p) return
    if (p.author !== this.me().pubkey) throw new Error('You can only delete your own post')
    const data = { ...p, deleted: true, body: '', url: '', title: p.title, editedAt: Date.now() }
    Object.assign(data, await this._sign(TYPE.POST, data))
    await this.sync.append({ type: TYPE.POST, data })
  }

  // Aggregate posts across communities (for home/all feeds).
  async listAllPosts (communities) {
    let slugs = communities
    if (!slugs) slugs = (await this.listCommunities()).map(c => c.slug)
    const lists = await Promise.all(slugs.map(s => this.listPostsIn(s).catch(() => [])))
    return lists.flat()
  }

  // ---- Comments -------------------------------------------------------------
  async addComment ({ community, postCid, parentCid, body }) {
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
    Object.assign(data, await this._sign(TYPE.COMMENT, data))
    await this.sync.append({ type: TYPE.COMMENT, data })
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
    return data
  }

  async deleteComment (community, postCid, cid) {
    const c = await this.sync.get(keys.comment(community, postCid, cid))
    if (!c) return
    if (c.author !== this.me().pubkey) throw new Error('You can only delete your own comment')
    const data = { ...c, deleted: true, body: '', editedAt: Date.now() }
    Object.assign(data, await this._sign(TYPE.COMMENT, data))
    await this.sync.append({ type: TYPE.COMMENT, data })
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
    this._tallyCache.delete(targetCid)
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
    const results = await Promise.all(uniq.map(async cid => [cid, tallyVotes(await this.rawVotes(cid), me)]))
    return new Map(results)
  }

  // Attach `.tally` to each post/comment record.
  async withTallies (records) {
    const map = await this.tallyMany(records.map(r => r.cid))
    return records.map(r => ({ ...r, tally: map.get(r.cid) || { up: 0, down: 0, score: 0, myVote: 0, total: 0 } }))
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
      const posts = (await this.listPostsIn(slug)).filter(p => p.author === pub && !p.deleted)
      postCount += posts.length
      const postTallies = await this.tallyMany(posts.map(p => p.cid))
      for (const p of posts) postKarma += (postTallies.get(p.cid) || { score: 0 }).score
    }
    // Comments aren't prefix-listable by author cheaply; scan per community post.
    for (const slug of communities) {
      const posts = await this.listPostsIn(slug)
      for (const p of posts) {
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
      for (const p of await this.listPostsIn(slug)) {
        if (p.author === pub && !p.deleted) posts.push(p)
      }
      for (const p of await this.listPostsIn(slug)) {
        for (const c of await this.listComments(slug, p.cid)) {
          if (c.author === pub && !c.deleted) comments.push({ ...c, postTitle: p.title })
        }
      }
    }
    return { posts: posts.slice(0, limit), comments: comments.slice(0, limit) }
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
}

export function createData (sync, identity) { return new Data(sync, identity) }
