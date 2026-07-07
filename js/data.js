// data.js — the peerit domain API. Turns user intentions (create community,
// submit post, vote, moderate…) into signed ops on the sync layer, and reads
// the materialized view back into typed records. Ranking/threading live in
// ranking.js / model.js; this module is CRUD + queries + vote tallies.

import { keys, id as mkid, TYPE, MOD, modOverlay, resolveMods } from './model.js'
import { tally as tallyVotes } from './ranking.js'
import { canonical, expectedKey, expectedKeyV2 } from './canon.js'
import { seal, unseal } from './seal.js'
import { uid, isValidSlug, normalizeSlug, safeUserUrl } from './util.js'
import { mint, MIN_BITS } from './pow.js'
import { assertRecoveryBundleMatches, buildRecoveryBundle, isHex64 } from './recovery.js'
import { boxBody, unboxToBody, shouldBox, canBox } from './blob-store.js'

// Decrypted-body cache is keyed by blobId (a content hash), so it is immutable
// and never goes stale — a bounded FIFO is all it needs.
const BODY_CACHE_MAX = 500
const BLIND_DEALER_MODULE = './blind-dealer.mjs'
// Node-only (browser takes the reader-bundle branch below); a computed specifier
// keeps this out of the web publish graph + the ship SITE_FILES import check,
// exactly like BLIND_DEALER_MODULE. The raw vendor files are never served to browsers.
const SHARD_TRANSPORT_MODULE = './vendor/blind-shards/shard-transport.js'
const DISPERSAL_TIMEOUT_MS = 15000 // cap slow/unavailable cohort; fall back to single-blob

async function loadBlindDealer () {
  return import(BLIND_DEALER_MODULE)
}

// Small base64 helpers for the dispersal path (ciphertext stored as blob!<blindContentId>).
function b64Encode (u8) {
  if (typeof btoa === 'function') { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s) }
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64')
  throw new Error('base64 encoder unavailable')
}
function b64Decode (s) {
  if (typeof atob === 'function') { const bin = atob(String(s)); const u = new Uint8Array(bin.length); for (let i = 0; i < u.length; i++) u[i] = bin.charCodeAt(i); return u }
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(String(s), 'base64'))
  throw new Error('base64 decoder unavailable')
}

export class Data {
  constructor (sync, identity, opts = {}) {
    this.sync = sync
    this.id = identity
    this.minBits = opts.minBits || MIN_BITS
    this.v2 = !!opts.v2 // Opaque-Log v2 write path (sealed graph fields + okey keys). OFF by default until cutover.
    this.dispersal = !!opts.dispersal // BlindShard dispersal: node writer attaches PVSS manifest; browser/Node reader recovers.
    this.shardRelays = Array.isArray(opts.shardRelays) ? opts.shardRelays : [] // [{url,pubkey}] or [url] for shard fetch
    this.fetch = opts.fetch || globalThis.fetch // injected for tests; defaults to global fetch
    this._profileCache = new Map() // pub -> { rec, at }
    this._tallyCache = new Map()   // `${viewer}:${cid}` -> { val, epoch }
    this._repIndex = null          // reputation index (voter age + upvotes received), gated by _epoch
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
    this._repIndex = null // voter reputation shifts as content/votes change; rebuild lazily
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
      const batch = await this._rangeRead(opts)
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

  // ---- Opaque-Log v2 write path (docs/BLIND-OUTBOX-MIGRATION.md) --------------
  // Fields that MUST stay cleartext at the top level: LWW/sticky needs them without
  // a decrypt, and they leak nothing the honest ceiling doesn't already concede
  // (timestamps, a deleted flag, and the community name — dictionary-reversible anyway).
  static V2_CLEAR = new Set(['createdAt', 'ts', 'editedAt', 'deleted', 'slug'])
  // Dropped entirely: id (→ okey), the owner fields (the owner IS the signer _k), and
  // any sig/pow metadata (re-added below).
  static V2_DROP = new Set(['id', 'author', 'creator', 'by', 'pow', '_sig', '_k', '_dk', '_ns', '_alg'])

  // Turn a plaintext logical record into the sealed v2 stored form:
  //   { id:<okey>, _t, <cleartext LWW fields>, sealed:{iv,ct} of the GRAPH fields }
  async _toV2 (semType, logical) {
    const wk = await expectedKeyV2({ ...logical, _t: semType }) // okey = HMAC(RK, owner‖_t‖semanticId)
    if (!wk) throw new Error('v2: cannot derive key for ' + semType)
    const clear = {}, graph = {}
    for (const [k, v] of Object.entries(logical)) {
      if (Data.V2_DROP.has(k)) continue
      if (Data.V2_CLEAR.has(k)) clear[k] = v
      else graph[k] = v
    }
    return { id: wk.slice(3), _t: semType, ...clear, sealed: await seal(graph) }
  }

  // The single write chokepoint. v1 (flag off) behaves exactly as before; v2 emits the
  // sealed opaque record but RETURNS the plaintext logical record so the caller can
  // render optimistically (the author already knows what it wrote). Blobs stay v1.
  async _emit (semType, data, { pow = false, onProgress } = {}) {
    if (this.v2 && semType !== TYPE.BLOB) {
      const stored = await this._toV2(semType, data)
      if (pow) stored.pow = await mint(semType, stored, this.minBits[semType] || 0, { onProgress })
      Object.assign(stored, await this._sign('v2', stored)) // sign over canonical('v2', stored)
      await this.sync.append({ type: 'v2', data: stored })
      return data
    }
    if (pow) await this._powSign(semType, data, onProgress)
    else Object.assign(data, await this._sign(semType, data))
    await this.sync.append({ type: semType, data })
    return data
  }

  // ---- Opaque-Log v2 read model --------------------------------------------
  // The relay holds opaque v2!<okey> records; the CLIENT (holding the read key)
  // decrypts every one and reconstructs it under its plaintext v1-style semantic key
  // (post!<community>!<cid>, vote!<targetCid>!<author>, …). Every existing read/query
  // then works unchanged over `_get/_list/_range/_count`, which merge the reconstructed
  // v2 view with any legacy v1 rows (v2 wins a key collision). Built once per write
  // epoch. This is what "aggregation moves into the browser" means in code.
  async _buildV2View () {
    const rows = await this.sync.list('v2!', { limit: 5000 }).catch(() => [])
    const view = Object.create(null)
    for (const r of (rows || [])) {
      const s = r && r.value
      if (!s || !s.sealed || !s._t) continue
      let g; try { g = await unseal(s.sealed) } catch { continue }
      if (!g || typeof g !== 'object') continue
      const plain = {
        ...g, _t: s._t, author: s._k, creator: s._k, by: s._k,
        createdAt: s.createdAt, ts: s.ts, editedAt: s.editedAt, deleted: s.deleted,
        slug: s.slug != null ? s.slug : g.slug,
        _sig: s._sig, _k: s._k, _dk: s._dk, _ns: s._ns, _alg: s._alg, pow: s.pow
      }
      const k = expectedKey(s._t, plain) // reconstruct the plaintext semantic key
      if (!k) continue
      plain.id = k.slice(k.indexOf('!') + 1) // the v1-style data.id
      view[k] = plain
    }
    return view
  }

  async _v2v () {
    if (!this._v2View || this._v2Epoch !== this._epoch) { this._v2View = await this._buildV2View(); this._v2Epoch = this._epoch }
    return this._v2View
  }

  // Read helpers — v1 pass through to sync; v2 answers from the reconstructed view
  // (falling back to / merging with any legacy v1 rows so dual-read is transparent).
  async _get (k) {
    if (!this.v2) return this.sync.get(k)
    const v = await this._v2v()
    return v[k] != null ? v[k] : this.sync.get(k)
  }
  async _mergedRows (prefix) { // v1 rows + reconstructed v2 rows; v2 wins a key collision
    const v1 = await this.sync.list(prefix, { limit: 5000 }).catch(() => [])
    const m = new Map((v1 || []).map(r => [r.key, r.value]))
    const v = await this._v2v()
    for (const k of Object.keys(v)) if (k.startsWith(prefix)) m.set(k, v[k])
    return [...m.entries()].map(([key, value]) => ({ key, value }))
  }
  async _list (prefix, { limit = 1000 } = {}) {
    if (!this.v2) return this.sync.list(prefix, { limit })
    return (await this._mergedRows(prefix)).slice(0, limit)
  }
  async _count (prefix) {
    if (!this.v2) return this.sync.count(prefix)
    return (await this._mergedRows(prefix)).length
  }
  async _rangeRead (opts = {}) {
    if (!this.v2) return this.sync.range(opts)
    const { gte, gt, lte, lt, limit = 1000, reverse } = opts
    const v = await this._v2v()
    let ks = Object.keys(v).filter(x => (gte == null || x >= gte) && (gt == null || x > gt) && (lte == null || x <= lte) && (lt == null || x < lt))
    // include legacy v1 rows in the range too
    const pfx = typeof gte === 'string' ? gte : (typeof gt === 'string' ? gt : '')
    const v1 = pfx ? await this.sync.range(opts).catch(() => []) : []
    const m = new Map((v1 || []).map(r => [r.key, r.value]))
    for (const k of ks) m.set(k, v[k])
    let out = [...m.entries()].map(([key, value]) => ({ key, value }))
    out.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
    if (reverse) out.reverse()
    return out.slice(0, limit)
  }

  // ---- BlindShard Phase 2/3: box-before-store + dispersal ------------------
  // Replace a long plaintext `data.body` with an opaque, content-addressed
  // ciphertext record (blob!<blobId>) + a signed manifest on the record. Mutates
  // `data` in place (body -> '', adds `data.blob`). Call BEFORE signing so the
  // manifest is covered by the record's signature; the blob itself is a separate
  // signed record so it flows through the normal admit/verify/merge path.
  //
  // When `this.dispersal` is enabled and the identity exposes a signing seed
  // (Node/dev path), the AES key is PVSS-split across `this.shardRelays` and the
  // ciphertext is still stored as blob!<blindContentId>. The record carries the
  // dispersal manifest; the reader gathers >=threshold shards to reconstruct the
  // key at the edge. Browser authoring remains blocked on #115, so this path is
  // Node-only; the read path works in both Node and browser.
  async _boxBody (data) {
    if (this.dispersal) {
      const dispersal = await this._tryDispersalBox(data.body)
      if (dispersal) {
        data.body = ''
        data.dispersal = dispersal
        return
      }
      // Fall through to single-blob boxing if dispersal is not viable here.
    }
    const { manifest, ct } = await boxBody(data.body)
    const blobData = { id: manifest.blobId, blobId: manifest.blobId, ct, author: this.me().pubkey }
    await this._powSign(TYPE.BLOB, blobData) // small PoW so blobs aren't a free large-append flood vector
    await this.sync.append({ type: TYPE.BLOB, data: blobData })
    data.body = ''
    data.blob = manifest
  }

  // Build a publisher keypair from the current identity, if it exposes a seed.
  // BridgeIdentity (PearBrowser host) does not, so dispersal authoring falls back
  // to single-blob in that runtime.
  async _publisherForDispersal () {
    if (!this.id || typeof this.id.currentSeedEntry !== 'function') return null
    const entry = this.id.currentSeedEntry()
    if (!entry || !entry.seed || !entry.pubkey) return null
    const { makeHiverelayKeypair } = await loadBlindDealer()
    return makeHiverelayKeypair({ seedHex: entry.seed, pubHex: entry.pubkey })
  }

  _rosterForDispersal () {
    const relays = this.shardRelays
    if (!relays || relays.length < 3) return null
    const normalized = relays.map((r) => {
      if (typeof r === 'string') return { url: r }
      return { url: String(r.url || r.baseUrl || ''), pubkey: String(r.pubkey || r.publicKey || '').toLowerCase() }
    }).filter((r) => r.url)
    if (normalized.length < 3) return null
    const uniquePubs = new Set(normalized.map(r => r.pubkey).filter(Boolean))
    if (uniquePubs.size < normalized.length) {
      if (typeof console !== 'undefined' && console.warn) console.warn('[peerit] shard roster contains duplicate pubkeys; refusing dispersal')
      return null
    }
    const threshold = Math.max(2, Math.min(normalized.length - 1, Math.ceil(normalized.length / 2)))
    return { threshold, relays: normalized, retainMs: 30 * 24 * 60 * 60 * 1000 }
  }

  _relayBaseUrls () {
    return (this.shardRelays || []).map((r) => typeof r === 'string' ? r : (r.url || r.baseUrl || '')).filter(Boolean)
  }

  async _getRecoverBody () {
    const node = typeof process !== 'undefined' && !!process.versions && !!process.versions.node
    if (node) {
      const { recoverBody } = await loadBlindDealer()
      return recoverBody
    }
    const { recoverBody } = await import('./reader-bundle.js')
    return recoverBody
  }

  async _getCreateHttpShardFetch () {
    const node = typeof process !== 'undefined' && !!process.versions && !!process.versions.node
    if (node) {
      const { createHttpShardFetch } = await import(SHARD_TRANSPORT_MODULE)
      return createHttpShardFetch
    }
    const { createHttpShardFetch } = await import('./reader-bundle.js')
    return createHttpShardFetch
  }

  async _tryDispersalBox (bodyText) {
    const publisher = await this._publisherForDispersal()
    const roster = this._rosterForDispersal()
    if (!publisher || !roster) return null
    // Bind the post author to the PVSS publisher so a signed post cannot
    // smuggle another party's dispersal manifest.
    const mePubkey = this.me().pubkey
    if (publisher.pubkeyHex.toLowerCase() !== mePubkey.toLowerCase()) {
      if (typeof console !== 'undefined' && console.warn) console.warn('[peerit] dispersal publisher does not match post author; falling back')
      return null
    }
    try {
      const { disperseBody } = await loadBlindDealer()
      // Shards and ciphertext are always placed on the remote HiveRelay shard cohort.
      // Storing PVSS shares inside the peerit sync group would collapse the blind
      // invariant (one operator/outbox would hold manifest + ciphertext + shares),
      // so this path never falls back to local shard records.
      const dispersal = await Promise.race([
        disperseBody(bodyText, {
          publisher,
          threshold: roster.threshold,
          relays: roster.relays,
          retainMs: roster.retainMs,
          fetch: this.fetch
        }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('dispersal timeout')), DISPERSAL_TIMEOUT_MS))
      ])
      const { ciphertext, manifest } = dispersal
      // Keep a local blob replica only for legacy manifests without a ciphertextShard.
      // Modern manifests put the ciphertext on the shard cohort, so the VPS/outbox
      // holds only the keyless dispersal manifest.
      if (!manifest.ciphertextShard) {
        const ct = b64Encode(ciphertext)
        const blobData = { id: manifest.blindContentId, blobId: manifest.blindContentId, ct, author: this.me().pubkey }
        await this._powSign(TYPE.BLOB, blobData)
        await this.sync.append({ type: TYPE.BLOB, data: blobData })
      }
      return manifest
    } catch (err) {
      if (typeof console !== 'undefined' && console.warn) console.warn('[peerit] dispersal box failed, falling back:', err.message)
      return null
    }
  }

  // Return a render-ready copy of a post: if it carries a blob manifest, fetch
  // blob!<blobId>, verify the two content-address gates, and decrypt the body.
  // Never mutates the stored record; on a missing/withheld/tampered blob it
  // degrades gracefully to an empty body flagged `_blobMissing` (a relay can
  // withhold a blob but can never forge one past the gates in unboxToBody).
  async _hydrate (rec) {
    if (!rec) return rec
    if (rec.dispersal) {
      const m = rec.dispersal
      const cached = this._bodyCache.get(m.blindContentId)
      if (cached != null) return { ...rec, body: cached }
      try {
        const recoverBody = await this._getRecoverBody()
        const opts = {
          relayBaseUrls: this._relayBaseUrls(),
          fetchImpl: this.fetch
        }
        if (m.ciphertextShard) {
          const createHttpShardFetch = await this._getCreateHttpShardFetch()
          const fetchShard = createHttpShardFetch({ baseUrls: this._relayBaseUrls(), fetch: this.fetch })
          opts.fetchCiphertext = async () => {
            const bytes = await fetchShard(m.ciphertextShard)
            if (!bytes) throw new Error('ciphertext shard not found on cohort')
            return bytes
          }
        } else {
          // Legacy dispersal manifest: ciphertext was kept as a local blob.
          const blob = await this.sync.get(keys.blob(m.blindContentId))
          if (!blob || !blob.ct) return { ...rec, body: '', _blobMissing: true }
          opts.fetchCiphertext = () => b64Decode(blob.ct)
        }
        const body = await recoverBody(m, opts)
        if (this._bodyCache.size >= BODY_CACHE_MAX) this._bodyCache.delete(this._bodyCache.keys().next().value)
        this._bodyCache.set(m.blindContentId, body)
        return { ...rec, body }
      } catch {
        return { ...rec, body: '', _blobMissing: true }
      }
    }
    if (!rec.blob || !rec.blob.blobId) return rec
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
  async _rawPost (community, cid) { return this._get(keys.post(community, cid)) }

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
    await this._emit(TYPE.COMMUNITY, data, { pow: true, onProgress })
    this.invalidateViewCaches()
    return data
  }

  async getCommunity (slug) { return this._get(keys.community(slug)) }

  async listCommunities () {
    const rows = await this._list(keys.communityPrefix(), { limit: 1000 })
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
    await this._emit(TYPE.COMMUNITY, data)
    this.invalidateViewCaches()
    return data
  }

  // ---- Posts ----------------------------------------------------------------
  async submitPost ({ community, kind, title, body, url, cid, onProgress }) {
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
    // Optional caller-supplied cid (safe charset only) for idempotent/deterministic
    // posts (e.g. seeding — same cid overwrites the same key rather than duplicating).
    // The post is author+sig-bound, so pinning a cid can only affect your own posts.
    cid = (typeof cid === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(cid)) ? cid : uid()
    const now = Date.now()
    const data = {
      id: mkid.post(community, cid), cid, community, kind,
      title: title.trim().slice(0, 300),
      body: kind === 'text' ? String(body || '').slice(0, 40000) : '',
      url: kind !== 'text' ? postUrl : '',
      author: me.pubkey, createdAt: now, editedAt: 0, deleted: false
    }
    // Box a long text body into an opaque blob/dispersal manifest before signing
    // (design §5 Phase 2). In v2 mode the manifest is sealed inside the graph fields.
    if (kind === 'text' && canBox() && shouldBox(data.body)) await this._boxBody(data)
    await this._emit(TYPE.POST, data, { pow: true, onProgress })
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
    const rows = await this._list(keys.postsIn(community), { limit: 1000 })
    const recs = rows.map(r => r.value).filter(Boolean)
    return hydrate ? Promise.all(recs.map(r => this._hydrate(r))) : recs
  }

  // Post count for a community sidebar/card. Routes through _count so it works for
  // both v1 (relay prefix count) and v2 (the client-reconstructed view) — the UI must
  // never call sync.count directly, since v2 keys are opaque.
  async postCount (community) { return this._count(keys.postsIn(community)) }

  async editPost (community, cid, body) {
    const p = await this._rawPost(community, cid)
    if (!p) throw new Error('Post not found')
    if (p.author !== this.me().pubkey) throw new Error('You can only edit your own post')
    const data = { ...p, body: String(body || '').slice(0, 40000), editedAt: Date.now() }
    delete data.blob // drop any prior manifest; re-box below if the new body is still long
    delete data.dispersal
    if (data.kind === 'text' && canBox() && shouldBox(data.body)) await this._boxBody(data)
    await this._emit(TYPE.POST, data)
    this.invalidateViewCaches()
    return data
  }

  async deletePost (community, cid) {
    const p = await this._rawPost(community, cid)
    if (!p) return
    if (p.author !== this.me().pubkey) throw new Error('You can only delete your own post')
    const data = { ...p, deleted: true, body: '', url: '', title: p.title, editedAt: Date.now() }
    delete data.blob // a deleted post references no blob
    delete data.dispersal
    await this._emit(TYPE.POST, data)
    this.invalidateViewCaches()
  }

  // Aggregate posts across communities (for home/all feeds).
  async listAllPosts (communities, { hydrate = true } = {}) {
    let slugs = communities
    if (!slugs) slugs = (await this.listCommunities()).map(c => c.slug)
    const lists = await Promise.all(slugs.map(s => this.listPostsIn(s, { hydrate }).catch(() => [])))
    return lists.flat()
  }

  // ---- inbox: replies to your posts + comments (Slice 2) ----------------------
  // A PURE client-side scan of records already in the log — no new record type, no
  // relay change. A "reply" is a comment whose parent you authored: a top-level
  // comment (parentCid null) on YOUR post, or a nested reply whose parentCid is one
  // of YOUR comment cids. Read state lives device-local (prefs.notifSeen).
  async notificationsFor (pub = this.me().pubkey, { limit = 100, hydrate = true } = {}) {
    const [allPosts, allComments] = await Promise.all([
      this.listAllPosts(undefined, { hydrate: false }), // titles + author only; bodies not needed
      this._listPrefix(keys.commentPrefix()).then(rows => rows.map(r => r.value).filter(Boolean))
    ])
    const postTitle = new Map(allPosts.map(p => [p.cid, p.title]))
    const myPostCids = new Set(allPosts.filter(p => p.author === pub && !p.deleted).map(p => p.cid))
    const myCommentCids = new Set(allComments.filter(c => c.author === pub && !c.deleted).map(c => c.cid))

    const matches = []
    for (const c of allComments) {
      if (c.deleted || c.author === pub) continue
      let on = null
      if (c.parentCid && myCommentCids.has(c.parentCid)) on = 'comment'
      else if (!c.parentCid && myPostCids.has(c.postCid)) on = 'post'
      if (!on) continue
      matches.push({ kind: 'reply', on, community: c.community, postCid: c.postCid, cid: c.cid, from: c.author, ts: c.createdAt || 0, postTitle: postTitle.get(c.postCid) || '', _raw: c })
    }
    matches.sort((a, b) => b.ts - a.ts)
    const top = matches.slice(0, limit)
    if (hydrate) await Promise.all(top.map(async (n) => { try { n.body = (await this._hydrate(n._raw)).body } catch { n.body = '' } }))
    for (const n of top) delete n._raw
    return top
  }

  // Unread reply count since a device-local marker ts (for the header badge).
  // No body hydration — a count never needs to decrypt.
  async unreadCount (since = 0, pub = this.me().pubkey) {
    const notes = await this.notificationsFor(pub, { limit: 500, hydrate: false })
    return notes.reduce((n, x) => n + (x.ts > since ? 1 : 0), 0)
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
    // Box a long comment body too (same band as posts) — a long comment is as
    // sensitive as a long post body. Short comments stay inline (below threshold).
    // In v2 mode the blob/dispersal manifest is sealed inside the graph fields.
    if (canBox() && shouldBox(data.body)) await this._boxBody(data)
    await this._emit(TYPE.COMMENT, data, { pow: true, onProgress })
    this.invalidateViewCaches()
    return data
  }

  // Body-free callers (karma) pass { hydrate: false } to skip fetching+decrypting
  // boxed comment bodies they only discard — mirrors listPostsIn (review FIX 4).
  async listComments (community, postCid, { hydrate = true } = {}) {
    const rows = await this._list(keys.commentsOn(community, postCid), { limit: 1000 })
    const recs = rows.map(r => r.value).filter(Boolean)
    return hydrate ? Promise.all(recs.map(r => this._hydrate(r))) : recs
  }

  // Hydrated single comment (decrypts a boxed body) — used to seed the edit prompt
  // so editing a boxed comment shows its real body, not the stored empty placeholder.
  async getComment (community, postCid, cid) {
    const c = await this._get(keys.comment(community, postCid, cid))
    return c ? this._hydrate(c) : c
  }

  async editComment (community, postCid, cid, body) {
    const c = await this._get(keys.comment(community, postCid, cid)) // raw (never a hydrated copy)
    if (!c) throw new Error('Comment not found')
    if (c.author !== this.me().pubkey) throw new Error('You can only edit your own comment')
    const data = { ...c, body: String(body || '').slice(0, 10000), editedAt: Date.now() }
    delete data.blob // drop any prior manifest; re-box below if still long
    delete data.dispersal
    if (canBox() && shouldBox(data.body)) await this._boxBody(data)
    await this._emit(TYPE.COMMENT, data)
    this.invalidateViewCaches()
    return data
  }

  async deleteComment (community, postCid, cid) {
    const c = await this._get(keys.comment(community, postCid, cid))
    if (!c) return
    if (c.author !== this.me().pubkey) throw new Error('You can only delete your own comment')
    const data = { ...c, deleted: true, body: '', editedAt: Date.now() }
    delete data.blob // a deleted comment references no blob
    delete data.dispersal
    await this._emit(TYPE.COMMENT, data)
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
    await this._emit(TYPE.VOTE, data)
    this.invalidateViewCaches('vote')
    return data
  }

  async rawVotes (targetCid) {
    const rows = await this._list(keys.votesFor(targetCid), { limit: 1000 })
    return rows.map(r => r.value).filter(Boolean)
  }

  // ---- reputation index (Slice 3) -------------------------------------------
  // Per-author inputs to the vote weight: earliest activity (age) + upvotes their
  // content has received. Built once per write-epoch from a full scan (same cost
  // class as the search index) and reused by every weighted tally on a feed render.
  async _reputation () {
    if (this._repIndex && this._repIndex.epoch === this._epoch) return this._repIndex
    const earliest = new Map() // pub -> earliest activity ms
    const received = new Map() // pub -> upvotes received on their content
    const cidAuthor = new Map() // cid -> author (to attribute an upvote to a content owner)
    const seen = (pub, ts) => { if (!pub) return; const e = earliest.get(pub); if (e == null || ts < e) earliest.set(pub, ts) }
    const posts = await this.listAllPosts(undefined, { hydrate: false })
    for (const p of posts) { cidAuthor.set(p.cid, p.author); seen(p.author, p.createdAt || 0) }
    const comments = (await this._listPrefix(keys.commentPrefix())).map(r => r.value).filter(Boolean)
    for (const c of comments) { cidAuthor.set(c.cid, c.author); seen(c.author, c.createdAt || 0) }
    const allVotes = await this._listPrefix(keys.voteAll())
    for (const { value: v } of allVotes) {
      if (v && v.value === 1) { const a = cidAuthor.get(v.targetCid); if (a) received.set(a, (received.get(a) || 0) + 1) }
    }
    this._repIndex = { epoch: this._epoch, earliest, received, cidAuthor }
    return this._repIndex
  }

  // [ageDays, receivedUpvotes] for a pub — the inputs to ranking.weight(). Used by
  // the weighted tallies and surfaced on the profile ("your vote weight").
  async weightInputsFor (pub, idx) {
    idx = idx || await this._reputation()
    const e = idx.earliest.get(pub)
    return [e ? Math.max(0, (Date.now() - e) / 86400000) : 0, idx.received.get(pub) || 0]
  }

  async tallyFor (targetCid) {
    const me = this.me().pubkey
    const idx = await this._reputation()
    const weightOf = (pub) => { const e = idx.earliest.get(pub); return [e ? Math.max(0, (Date.now() - e) / 86400000) : 0, idx.received.get(pub) || 0] }
    return tallyVotes(await this.rawVotes(targetCid), me, weightOf)
  }

  // Tally many targets at once (used to enrich a feed). Returns Map cid->tally, each
  // carrying a reputation-weighted score for ranking. Cached per (viewer,cid,epoch).
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
      const idx = await this._reputation()
      const weightOf = (pub) => { const e = idx.earliest.get(pub); return [e ? Math.max(0, (Date.now() - e) / 86400000) : 0, idx.received.get(pub) || 0] }
      // Scan only the votes for each missing target (vote!<cid>!…) instead of the
      // whole vote table — turns a feed render from O(all votes) into O(votes on
      // the visible posts). Same prefix scheme rawVotes uses.
      const lists = await Promise.all(missing.map(cid => this._listPrefix(keys.votesFor(cid))))
      for (let i = 0; i < missing.length; i++) {
        const cid = missing[i]
        const votes = lists[i].map(r => r.value).filter(Boolean)
        const val = tallyVotes(votes, me, weightOf)
        this._tallyCache.set(me + ':' + cid, { val, epoch: this._epoch })
        out.set(cid, val)
      }
    }
    return out
  }

  // Attach `.tally` to each post/comment record.
  async withTallies (records) {
    const map = await this.tallyMany(records.map(r => r.cid))
    return records.map(r => ({ ...r, tally: map.get(r.cid) || { up: 0, down: 0, score: 0, weighted: 0, myVote: 0, total: 0 } }))
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
    await this._emit(TYPE.PROFILE, data)
    this._profileCache.set(me.pubkey, { rec: data, at: Date.now() })
    this.invalidateViewCaches()
    return data
  }

  async getProfile (pub) {
    const cached = this._profileCache.get(pub)
    if (cached && Date.now() - cached.at < 15000) return cached.rec
    const rec = await this._get(keys.profile(pub))
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
    let postKarma = 0, commentKarma = 0, postCount = 0, commentCount = 0, weighted = 0
    for (const slug of communities) {
      // List each community's posts ONCE and reuse for both the author's own
      // posts (post karma) and the per-post comment scan (comment karma).
      const allPosts = await this.listPostsIn(slug, { hydrate: false }) // karma never reads bodies
      const mine = allPosts.filter(p => p.author === pub && !p.deleted)
      postCount += mine.length
      if (mine.length) {
        const postTallies = await this.tallyMany(mine.map(p => p.cid))
        for (const p of mine) { const t = postTallies.get(p.cid) || { score: 0, weighted: 0 }; postKarma += t.score; weighted += t.weighted }
      }
      // Comments aren't prefix-listable by author cheaply; scan per community post.
      for (const p of allPosts) {
        const cs = (await this.listComments(slug, p.cid, { hydrate: false })).filter(c => c.author === pub && !c.deleted) // karma tallies by cid, never reads body
        commentCount += cs.length
        if (cs.length) {
          const t = await this.tallyMany(cs.map(c => c.cid))
          for (const c of cs) { const tt = t.get(c.cid) || { score: 0, weighted: 0 }; commentKarma += tt.score; weighted += tt.weighted }
        }
      }
    }
    // total = raw karma (what users expect); weighted = reputation-weighted karma.
    return { postKarma, commentKarma, total: postKarma + commentKarma, weighted: Math.round(weighted), postCount, commentCount }
  }

  // ---- signed social graph (follow! / member!) --------------------------------
  // One LWW record per edge, exactly the vote! pattern: unfollow/leave is a
  // deleted:true tombstone re-write of the SAME id (a later re-follow wins by ts).
  // In v2 the edge (target / community) is a SEALED graph field — the relay stores
  // an opaque cell and cannot enumerate who follows whom or who joined what.

  async setFollow (targetPub, on = true) {
    const me = this.me()
    if (!targetPub || targetPub === me.pubkey) throw new Error(on ? 'Cannot follow yourself.' : 'Bad target.')
    const now = Date.now()
    const data = {
      id: mkid.follow(targetPub, me.pubkey), target: targetPub,
      author: me.pubkey, ts: now, ...(on ? {} : { deleted: true })
    }
    await this._emit(TYPE.FOLLOW, data)
    this.invalidateViewCaches('vote') // graph edges don't touch comments/search; bump the view epoch only
    return data
  }

  async isFollowing (targetPub, viewer = this.me().pubkey) {
    const r = await this._get(keys.follow(targetPub, viewer))
    return !!(r && !r.deleted)
  }

  // Everyone WHO FOLLOWS pub — cheap prefix read (follow!<pub>!).
  async followersOf (pub) {
    const rows = await this._list(keys.followersOf(pub), { limit: 5000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted).map(v => v.author)
  }

  // Everyone pub FOLLOWS — a scan of the follow! range filtered by author (client-
  // side aggregation, same cost model as karmaFor).
  async followingOf (pub) {
    const rows = await this._list(keys.followAll(), { limit: 5000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted && v.author === pub).map(v => v.target)
  }

  async followCounts (pub) {
    const [followers, following] = await Promise.all([this.followersOf(pub), this.followingOf(pub)])
    return { followers: followers.length, following: following.length }
  }

  async setMembership (community, on = true) {
    const me = this.me()
    const c = await this.getCommunity(community)
    if (!c) throw new Error('No such community: r/' + community)
    const now = Date.now()
    const data = {
      id: mkid.member(community, me.pubkey), community,
      author: me.pubkey, ts: now, ...(on ? {} : { deleted: true })
    }
    await this._emit(TYPE.MEMBER, data)
    this.invalidateViewCaches('vote')
    return data
  }

  async membersOf (community) {
    const rows = await this._list(keys.membersOf(community), { limit: 5000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted).map(v => v.author)
  }

  async memberCount (community) { return (await this.membersOf(community)).length }

  async myMemberships () {
    const me = this.me().pubkey
    const rows = await this._list(keys.memberAll(), { limit: 5000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted && v.author === me).map(v => v.community)
  }

  // One-time migration: device-local prefs (which die with localStorage and are
  // invisible to peers) become signed records. Idempotent per identity — guarded
  // by a per-pubkey flag AND skipped for edges that already have a record. The
  // flag is only set when every edge landed, so a partial run retries next boot.
  async migrateLocalGraph ({ follows = [], subs = [], storage } = {}) {
    const me = this.me().pubkey
    const flagKey = 'peerit:graph-migrated:' + me
    try { if (storage && storage.getItem(flagKey)) return { migrated: 0, skipped: true } } catch {}
    let migrated = 0; let failed = 0
    for (const pub of follows) {
      try { if (pub && pub !== me && !(await this.isFollowing(pub))) { await this.setFollow(pub, true); migrated++ } } catch { failed++ }
    }
    for (const slug of subs) {
      try {
        const mine = await this._get(keys.member(slug, me))
        if (!mine || mine.deleted) { await this.setMembership(slug, true); migrated++ }
      } catch { failed++ } // e.g. community not replicated yet — retried next boot
    }
    if (!failed) { try { if (storage) storage.setItem(flagKey, String(Date.now())) } catch {} }
    return { migrated, failed, skipped: false }
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
    // Hydrate boxed comment bodies so they remain searchable (the client can
    // decrypt; only the relay can't). Content-addressed body cache amortizes it.
    const rawComments = (await this._listPrefix(keys.commentPrefix())).map(r => r.value).filter(c => c && !c.deleted)
    const comments = (await Promise.all(rawComments.map(c => this._hydrate(c))))
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
    const rows = await this._list(keys.modsIn(community), { limit: 1000 })
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
    await this._emit(TYPE.MOD, data)
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
