// data.js — the peerit domain API. Turns user intentions (create community,
// submit post, vote, moderate…) into signed ops on the sync layer, and reads
// the materialized view back into typed records. Ranking/threading live in
// ranking.js / model.js; this module is CRUD + queries + vote tallies.

import {
  keys, id as mkid, TYPE, MOD, modOverlay, resolveMods,
  CONTENT_PROTOCOL, CONTENT_MOD_ACTIONS, USER_MOD_ACTIONS,
  contentId, hasValidContentId, makeContentRef, validContentNonce
} from './model.js'
import { tally as tallyVotes } from './ranking.js'
import { canonical, expectedKey, expectedKeyV2, ownerOf } from './canon.js'
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

// Public methods that can eventually publish an owner-signed mutation. Tracking
// the whole intent (not just the final network request) lets the app refuse an
// import/forget while a write is reading its target, boxing a body, minting PoW,
// signing, or awaiting durable receipts.
const WRITE_INTENT_METHODS = Object.freeze([
  'createCommunity', 'updateCommunity',
  'submitPost', 'editPost', 'deletePost', 'repairDispersal',
  'addComment', 'editComment', 'deleteComment', 'vote',
  'setProfile', 'setFollow', 'setMembership', 'migrateLocalGraph',
  'modAction', 'addMod', 'removeMod'
])

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
    this.mintProof = typeof opts.mint === 'function' ? opts.mint : mint
    this.withWriterSession = typeof opts.withWriterSession === 'function' ? opts.withWriterSession : null
    this.assertWriterStart = typeof opts.assertWriterStart === 'function' ? opts.assertWriterStart : null
    // Mint-on-first-write (lazy web identity): app.js injects a callback that
    // checks read-only mode FIRST and then ensures an active identity. It runs at
    // the TOP of every write path, strictly BEFORE anything is signed — a key
    // minted/adopted mid-append would leave the in-flight record signed by a
    // discarded key (uneditable, failing its own head census).
    this.ensureWriter = typeof opts.ensureWriter === 'function' ? opts.ensureWriter : null
    // Device durability floor (ADR-2026-07-07): a localStorage-like store where the
    // AUTHOR keeps {bodyKey, iv, ciphertext} for their own dispersed posts — device-
    // local, NEVER synced/appended, so no relay ever co-locates key + ciphertext.
    // With it, the author can decrypt + re-disperse after total cohort loss; without
    // it a dispersed post would be LESS durable than a plain v2 post.
    this.deviceStore = opts.deviceStore || null
    this._profileCache = new Map() // pub -> { rec, at }
    this._tallyCache = new Map()   // `${viewer}:${cid}` -> { val, epoch }
    this._repIndex = null          // reputation index (voter age + upvotes received), gated by _epoch
    this._commentCountCache = new Map() // `${community}/${postCid}` -> { val, contentEpoch }
    this._searchIndex = null
    this._epoch = 0          // bumped on EVERY write; gates vote tallies
    this._contentEpoch = 0   // bumped only when searchable content changes; gates comment-count + search caches
    this._bodyCache = new Map() // blobId -> decrypted body (content-addressed → never stale)
    this._writeIntents = 0
    this._writeSessionTail = Promise.resolve()
    this._writerSession = null
    this._trackWriteIntents()
  }

  me () { return this.id.me() }

  _trackWriteIntents () {
    for (const name of WRITE_INTENT_METHODS) {
      const original = this[name]
      if (typeof original !== 'function') continue
      this[name] = (...args) => {
        if (this.assertWriterStart) this.assertWriterStart()
        this._writeIntents++
        const invoke = async (writerSession = null) => {
          const previous = this._writerSession
          this._writerSession = writerSession
          try { return await original.apply(this, args) } finally { this._writerSession = previous }
        }
        let result = null
        if (this.withWriterSession) {
          // Serialize this Data instance before asking the sync layer for its
          // cross-tab writer session. This prevents two concurrent UI actions
          // from being mistaken for reentrant work by the session owner.
          const run = () => this.withWriterSession(invoke)
          result = this._writeSessionTail.then(run, run)
          this._writeSessionTail = result.then(() => undefined, () => undefined)
        } else {
          try { result = invoke() } catch (error) {
            this._writeIntents--
            throw error
          }
        }
        return Promise.resolve(result).finally(() => { this._writeIntents-- })
      }
    }
  }

  hasWriteInFlight () { return this._writeIntents > 0 }

  _identityRace (stage) {
    const error = new Error(`Writer identity changed ${stage}; this publication was stopped before it could be sent.`)
    error.code = 'PEERIT_WRITER_IDENTITY_CHANGED'
    return error
  }

  _assertCurrentOwner (expectedOwner, stage) {
    const current = this.me() && this.me().pubkey
    if (!expectedOwner || current !== expectedOwner) throw this._identityRace(stage)
    return current
  }

  _semanticOwner (type, data) {
    const expectedOwner = ownerOf(type, data || {})
    if (!expectedOwner) throw new Error('Cannot publish a record without a semantic owner.')
    return expectedOwner
  }

  _assertSignedOpsOwner (ops, expectedOwner) {
    for (const op of ops) {
      // V2 deliberately seals author/creator/by; its semantic owner is the
      // signer baked into the opaque key. V1 retains the clear owner field.
      const semanticOwner = op && op.type === 'v2'
        ? op.data && op.data._k
        : op && op.data && ownerOf(op.type, op.data)
      if (!op || !op.data || !op.data._sig || op.data._k !== expectedOwner || semanticOwner !== expectedOwner) {
        throw this._identityRace('while assembling its signed mutation batch')
      }
    }
  }

  // Writer-identity gate for every public WRITE method. MUST run BEFORE the
  // record is built: owner fields (author/creator) and owner-derived ids
  // (mkid.vote/profile/follow/member bake the pubkey in) are stamped from me()
  // at construction time — a lurker's record built pre-mint would carry
  // author:null, which v2 rejects at key derivation and v1 verifiers reject at
  // admit() (owner !== signer). The _emit/_boxBody calls remain as an idempotent
  // backstop (ensureWriter single-flights in app.js, so the double call is free).
  async _writer () {
    if (this.ensureWriter) await this.ensureWriter()
    const me = this.me()
    if (!me || !me.pubkey) throw new Error('No active writer identity')
    return { ...me }
  }

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
    // Hard cap: never let a relay backend whose range/cursor semantics differ from
    // ours grow `rows` without bound. Mirrors relay-pool.js readAll()'s MAX_ROWS.
    const MAX_ROWS = 200000
    while (rows.length < MAX_ROWS) {
      const opts = gt
        ? { gt, lt: prefix + '\xff', limit }
        : { gte: prefix, lt: prefix + '\xff', limit }
      const batch = await this._rangeRead(opts)
      rows.push(...batch)
      const last = batch[batch.length - 1] && batch[batch.length - 1].key
      // Stop on: no rows, a short final page, OR a NON-ADVANCING cursor
      // (last === gt). Without the last===gt guard, a backend that returns a full
      // batch whose last key equals the cursor we passed (different gt-inclusivity
      // or a stalled cursor) makes this while-loop spin forever, allocating `limit`
      // rows per turn until the tab OOMs — the returning-visitor crash on the
      // repointed relay. This mirrors the guard in relay-pool.js readAll().
      if (!last || last === gt || batch.length < limit) break
      gt = last
    }
    return rows
  }

  // Read the backend's raw range with a cursor. This is intentionally separate
  // from _rangeRead: the v2 view itself is built from raw `v2!` rows, so routing
  // that call through _rangeRead would recurse through _v2v forever.
  async _rawListPrefix (prefix, { limit = 1000 } = {}) {
    const rows = []
    let gt = null
    const MAX_ROWS = 200000
    while (rows.length < MAX_ROWS) {
      const opts = gt ? { gt, lt: prefix + '\xff', limit } : { gte: prefix, lt: prefix + '\xff', limit }
      const batch = await this.sync.range(opts).catch(() => [])
      if (!Array.isArray(batch) || !batch.length) break
      rows.push(...batch)
      const last = batch[batch.length - 1] && batch[batch.length - 1].key
      if (!last || last === gt || batch.length < limit) break
      gt = last
    }
    return rows
  }

  // Sign a record's canonical form and attach verification metadata. MUST be
  // called on every create AND every edit/delete — the gossip merge recomputes
  // the canonical form and rejects records whose signature no longer matches
  // (a stale sig from a spread `...prev` would otherwise look forged).
  async _sign (type, data, expectedOwner = this._semanticOwner(type, data)) {
    // Fail CLOSED: if signing fails, the calling op throws before append — never
    // write an unsigned record (which secure peers would reject as untrusted).
    this._assertCurrentOwner(expectedOwner, 'before signing')
    const s = await this.id.sign(canonical(type, data))
    if (!s || s.publicKey !== expectedOwner) throw this._identityRace('while signing')
    this._assertCurrentOwner(expectedOwner, 'after signing')
    return { _sig: s.signature, _k: s.publicKey, _dk: s.driveKey, _ns: s.namespace, _alg: s.algorithm }
  }

  async _powSign (type, data, onProgress, expectedOwner = this._semanticOwner(type, data)) {
    this._assertCurrentOwner(expectedOwner, 'before proof-of-work')
    data.pow = await this.mintProof(type, data, this.minBits[type] || 0, { onProgress })
    this._assertCurrentOwner(expectedOwner, 'after proof-of-work')
    Object.assign(data, await this._sign(type, data, expectedOwner))
    return data
  }

  // ---- Opaque-Log v2 write path (docs/BLIND-OUTBOX-MIGRATION.md) --------------
  // Fields that MUST stay cleartext at the top level: LWW/sticky needs them without
  // a decrypt, and they leak nothing the honest ceiling doesn't already concede
  // (timestamps, a deleted flag, and the community name — dictionary-reversible anyway).
  static V2_CLEAR = new Set(['createdAt', 'ts', 'editedAt', 'deleted', 'slug'])
  // Dropped entirely: id (→ okey), the owner fields (the owner IS the signer _k),
  // any sig/pow metadata (re-added below), and _t (always re-added from semType).
  // Dropping an inbound _t matters for re-emits (edit/delete build from the
  // RECONSTRUCTED record, which carries _t): without it _t would seal into the
  // graph, so an edited record's sealed blob would differ in shape from a fresh
  // one's for no reason.
  static V2_DROP = new Set(['id', '_t', 'author', 'creator', 'by', 'pow', '_sig', '_k', '_dk', '_ns', '_alg'])

  // Turn a plaintext logical record into the sealed v2 stored form:
  //   { id:<okey>, _t, <cleartext LWW fields>, sealed:{iv,ct} of the GRAPH fields }
  async _toV2 (semType, logical) {
    const wk = await expectedKeyV2({ ...logical, _t: semType }) // okey = HMAC(RK, owner‖_t‖semanticId)
    if (!wk) throw new Error('v2: cannot derive key for ' + semType)
    const clear = {}, graph = {}
    for (const [k, v] of Object.entries(logical)) {
      // undefined never enters the stored/signed form: JSON (storage + wire)
      // drops undefined keys, so signing over them yields a canonical no verifier
      // can reproduce (canon.js stable() now drops them too — this is belt-and-
      // suspenders so an undefined graph field also never seals). The v2
      // reconstruction sets ts/slug to undefined for records that lack them.
      if (v === undefined) continue
      if (Data.V2_DROP.has(k)) continue
      if (Data.V2_CLEAR.has(k)) clear[k] = v
      else graph[k] = v
    }
    return { id: wk.slice(3), _t: semType, ...clear, sealed: await seal(graph) }
  }

  // The single write chokepoint. v1 (flag off) behaves exactly as before; v2 emits the
  // sealed opaque record but RETURNS the plaintext logical record so the caller can
  // render optimistically (the author already knows what it wrote). Blobs stay v1.
  async _emit (semType, data, { pow = false, onProgress, batch = [] } = {}) {
    const expectedOwner = this._semanticOwner(semType, data)
    if (this.ensureWriter) await this.ensureWriter() // read-only gate + lazy mint, BEFORE any signing
    this._assertCurrentOwner(expectedOwner, 'before record construction')
    let op
    if (this.v2 && semType !== TYPE.BLOB) {
      const stored = await this._toV2(semType, data)
      this._assertCurrentOwner(expectedOwner, 'while sealing the record')
      if (pow) {
        this._assertCurrentOwner(expectedOwner, 'before proof-of-work')
        stored.pow = await this.mintProof(semType, stored, this.minBits[semType] || 0, { onProgress })
        this._assertCurrentOwner(expectedOwner, 'after proof-of-work')
      }
      Object.assign(stored, await this._sign('v2', stored, expectedOwner)) // sign over canonical('v2', stored)
      op = { type: 'v2', data: stored }
    } else {
      if (pow) await this._powSign(semType, data, onProgress, expectedOwner)
      else Object.assign(data, await this._sign(semType, data, expectedOwner))
      op = { type: semType, data }
    }
    const staged = Array.isArray(batch) ? batch : []
    const ops = [...staged, op]
    // Public web's ensureWriter also re-reads encrypted device durability and
    // pending/recovery status. Repeat it after all async PoW/sign work so a
    // cross-tab durable identity replacement is caught as late as possible.
    if (this.ensureWriter) await this.ensureWriter()
    this._assertCurrentOwner(expectedOwner, 'immediately before publication')
    this._assertSignedOpsOwner(ops, expectedOwner)
    if (staged.length && typeof this.sync.appendBatch === 'function') await this.sync.appendBatch(ops, this._writerSession)
    else {
      // DevSync and old PearBrowser transports retain their historical sequential
      // compatibility. Writable web exposes appendBatch and takes the atomic path.
      for (const pending of staged) {
        this._assertCurrentOwner(expectedOwner, 'between publication batch records')
        await this.sync.append(pending, this._writerSession)
      }
      this._assertCurrentOwner(expectedOwner, 'immediately before publication')
      await this.sync.append(op, this._writerSession)
    }
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
    const rows = await this._rawListPrefix('v2!', { limit: 1000 })
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
    const v1 = await this._rawListPrefix(prefix, { limit: 1000 })
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
  async _boxBody (data, { batch = null } = {}) {
    const expectedOwner = this._semanticOwner(data._t || (data.postCid ? TYPE.COMMENT : TYPE.POST), data)
    if (this.ensureWriter) await this.ensureWriter() // blob appends happen BEFORE the parent record's _emit
    this._assertCurrentOwner(expectedOwner, 'before boxing the body')
    if (this.dispersal) {
      const dispersal = await this._tryDispersalBox(data.body, { batch, expectedOwner })
      this._assertCurrentOwner(expectedOwner, 'after dispersing the body')
      if (dispersal) {
        data.body = ''
        data.dispersal = dispersal
        return
      }
      // Fall through to single-blob boxing if dispersal is not viable here.
    }
    const { manifest, ct } = await boxBody(data.body)
    this._assertCurrentOwner(expectedOwner, 'after encrypting the body')
    const blobData = { id: manifest.blobId, blobId: manifest.blobId, ct, author: expectedOwner }
    await this._powSign(TYPE.BLOB, blobData, undefined, expectedOwner) // small PoW so blobs aren't a free large-append flood vector
    const blobOp = { type: TYPE.BLOB, data: blobData }
    if (Array.isArray(batch) && typeof this.sync.appendBatch === 'function') batch.push(blobOp)
    else {
      if (this.ensureWriter) await this.ensureWriter()
      this._assertCurrentOwner(expectedOwner, 'immediately before blob publication')
      this._assertSignedOpsOwner([blobOp], expectedOwner)
      await this.sync.append(blobOp, this._writerSession)
    }
    data.body = ''
    data.blob = manifest
  }

  // Build a publisher keypair from the current identity, if it exposes a seed.
  // BridgeIdentity (PearBrowser host) does not, so dispersal authoring falls back
  // to single-blob in that runtime.
  async _publisherForDispersal (expectedOwner) {
    this._assertCurrentOwner(expectedOwner, 'before loading the dispersal signer')
    if (!this.id || typeof this.id.currentSeedEntry !== 'function') return null
    const entry = this.id.currentSeedEntry()
    if (!entry || !entry.seed || !entry.pubkey) return null
    if (entry.pubkey !== expectedOwner) throw this._identityRace('while loading the dispersal signer')
    const { makeHiverelayKeypair } = await loadBlindDealer()
    this._assertCurrentOwner(expectedOwner, 'after loading the dispersal signer')
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

  async _getDecryptBody () {
    const node = typeof process !== 'undefined' && !!process.versions && !!process.versions.node
    if (node) {
      const { decryptBody } = await loadBlindDealer()
      return decryptBody
    }
    const { decryptBody } = await import('./reader-bundle.js')
    return decryptBody
  }

  // ---- device durability floor (ADR-2026-07-07) -----------------------------
  // The floor entry holds everything the author needs to reproduce the body with
  // ZERO cohort relays: the HKDF-derived AES key, IV, ciphertext, and the
  // plaintext-hash commitment (so a corrupted floor fails closed in decryptBody).
  // Best-effort by design: quota errors or a missing store must never fail a write.
  _floorKey (blindContentId) { return 'peerit:floor:' + String(blindContentId || '').toLowerCase() }

  _saveFloor (blindContentId, entry) {
    if (!this.deviceStore || !blindContentId) return
    try { this.deviceStore.setItem(this._floorKey(blindContentId), JSON.stringify(entry)) } catch {}
  }

  _loadFloor (blindContentId) {
    if (!this.deviceStore || !blindContentId) return null
    try {
      const raw = this.deviceStore.getItem(this._floorKey(blindContentId))
      if (!raw) return null
      const f = JSON.parse(raw)
      return (f && f.v === 1 && f.key && f.iv && f.ct) ? f : null
    } catch { return null }
  }

  _dropFloor (blindContentId) {
    if (!this.deviceStore || !blindContentId) return
    try { this.deviceStore.removeItem(this._floorKey(blindContentId)) } catch {}
  }

  async _tryDispersalBox (bodyText, { batch = null, expectedOwner } = {}) {
    const publisher = await this._publisherForDispersal(expectedOwner)
    const roster = this._rosterForDispersal()
    if (!publisher || !roster) return null
    // Bind the post author to the PVSS publisher so a signed post cannot
    // smuggle another party's dispersal manifest.
    if (publisher.pubkeyHex.toLowerCase() !== expectedOwner.toLowerCase()) {
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
      this._assertCurrentOwner(expectedOwner, 'after dispersing the body')
      const { ciphertext, manifest, bodyKeyHex } = dispersal
      // Keep a local blob replica only for legacy manifests without a ciphertextShard.
      // Modern manifests put the ciphertext on the shard cohort, so the VPS/outbox
      // holds only the keyless dispersal manifest.
      if (!manifest.ciphertextShard) {
        const ct = b64Encode(ciphertext)
        const blobData = { id: manifest.blindContentId, blobId: manifest.blindContentId, ct, author: expectedOwner }
        await this._powSign(TYPE.BLOB, blobData, undefined, expectedOwner)
        const blobOp = { type: TYPE.BLOB, data: blobData }
        if (Array.isArray(batch) && typeof this.sync.appendBatch === 'function') batch.push(blobOp)
        else {
          if (this.ensureWriter) await this.ensureWriter()
          this._assertCurrentOwner(expectedOwner, 'immediately before dispersed blob publication')
          this._assertSignedOpsOwner([blobOp], expectedOwner)
          await this.sync.append(blobOp, this._writerSession)
        }
      }
      // Device durability floor (ADR-2026-07-07): the author keeps key+iv+ciphertext
      // DEVICE-LOCAL (never synced). Blindness is unchanged — no relay sees the key —
      // while the author regains the "1x on my own device" floor: decrypt and
      // re-disperse (repairDispersal) even after total cohort loss.
      if (bodyKeyHex) {
        this._saveFloor(manifest.blindContentId, {
          v: 1, key: bodyKeyHex, iv: manifest.iv, ct: b64Encode(ciphertext), ph: manifest.plaintextHash || ''
        })
      }
      return manifest
    } catch (err) {
      if (err && err.code === 'PEERIT_WRITER_IDENTITY_CHANGED') throw err
      if (typeof console !== 'undefined' && console.warn) console.warn('[peerit] dispersal box failed, falling back:', err.message)
      return null
    }
  }

  // ---- Phase-4 durability teeth: probe + repair ------------------------------
  // probeDispersal: ask the cohort which pieces of a dispersal manifest are still
  // retrievable. Returns { total, available, threshold, ciphertextAvailable,
  // recoverable, needsRepair }. "recoverable" = a reader could still reconstruct;
  // "needsRepair" = the body is at/below the cliff (cohort alone can no longer
  // reconstruct, or the ciphertext shard is gone) and only the device floor can
  // restore it. (The write-time quorum is already enforced by the dealer: intent +
  // every share PUT + ciphertext PUT must all ACK or the write falls back.)
  async probeDispersal (manifest) {
    const m = manifest && manifest.dispersal ? manifest.dispersal : manifest
    if (!m || !Array.isArray(m.shareManifest)) throw new Error('probeDispersal: dispersal manifest required')
    const createHttpShardFetch = await this._getCreateHttpShardFetch()
    const fetchShard = createHttpShardFetch({ baseUrls: this._relayBaseUrls(), fetch: this.fetch })
    const probe = async (addr) => { try { return !!(addr && await fetchShard(addr)) } catch { return false } }
    const shares = await Promise.all(m.shareManifest.map((s) => probe(s.shard)))
    const available = shares.filter(Boolean).length
    const ciphertextAvailable = m.ciphertextShard ? await probe(m.ciphertextShard) : true
    const threshold = Number(m.threshold) || 0
    const recoverable = ciphertextAvailable && available >= threshold
    return {
      total: m.shareManifest.length,
      available,
      threshold,
      ciphertextAvailable,
      recoverable,
      needsRepair: !recoverable || available < threshold + 1 // no margin left => repair now
    }
  }

  // repairDispersal: re-establish full cohort redundancy for the author's own post
  // from the device floor (or from the cohort itself while it can still serve).
  // Reuses the normal edit path, so the repaired record gets a FRESH dispersal
  // (new PVSS split, new custody intent, new floor entry) and replicates through
  // the ordinary signed-record flow. Author-only by construction (editPost checks).
  async repairDispersal (community, cid, { force = false } = {}) {
    const p = await this._rawPost(community, cid)
    if (!p) throw new Error('Post not found')
    if (!p.dispersal) throw new Error('Post is not dispersed')
    const m = p.dispersal
    const status = await this.probeDispersal(m).catch(() => null)
    if (!force && status && !status.needsRepair) return { repaired: false, status }
    // Body source: device floor first (works at zero cohort), else the cohort
    // while it is still above threshold.
    let body = null
    const floor = this._loadFloor(m.blindContentId)
    if (floor) {
      try {
        const decryptBody = await this._getDecryptBody()
        body = await decryptBody(b64Decode(floor.ct), floor.iv, floor.key, m.plaintextHash || floor.ph || undefined)
      } catch {}
    }
    if (body == null) {
      const hydrated = await this._hydrate(p)
      if (hydrated && !hydrated._blobMissing && hydrated.body) body = hydrated.body
    }
    if (body == null) throw new Error('repairDispersal: body unrecoverable (no device floor and cohort below threshold)')
    const data = await this._editPost(community, cid, body) // already inside the outer writer session; do not reacquire it
    return { repaired: true, status, record: data }
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
      // Device floor first (author's own posts): decrypt locally with zero cohort
      // round-trips. The plaintext-hash gate inside decryptBody keeps a corrupted
      // floor entry from serving a wrong body — on any failure fall through to the
      // normal cohort reconstruction below.
      const floor = this._loadFloor(m.blindContentId)
      if (floor) {
        try {
          const decryptBody = await this._getDecryptBody()
          const body = await decryptBody(b64Decode(floor.ct), floor.iv, floor.key, m.plaintextHash || floor.ph || undefined)
          if (this._bodyCache.size >= BODY_CACHE_MAX) this._bodyCache.delete(this._bodyCache.keys().next().value)
          this._bodyCache.set(m.blindContentId, body)
          return { ...rec, body }
        } catch {}
      }
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
    const me = await this._writer() // mint BEFORE stamping creator/author
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
    const rows = await this._listPrefix(keys.communityPrefix(), { limit: 1000 })
    return rows.map(r => r.value).filter(Boolean)
  }

  async updateCommunity (slug, patch) {
    const c = await this.getCommunity(slug)
    if (!c) throw new Error('No such community')
    const me = await this._writer() // mint BEFORE the owner check reads me()
    // Owner binding: only the founder's outbox holds the canonical community
    // record, so only the founder can change its metadata and have it propagate.
    if (c.creator !== me.pubkey) throw new Error('Only the founder can edit community details')
    const now = Date.now()
    const data = { ...c, ...patch, id: mkid.community(slug), slug, creator: c.creator, createdAt: c.createdAt, updatedAt: now }
    await this._emit(TYPE.COMMUNITY, data, { pow: true }) // re-mint: _toV2 strips the reconstructed record's pow (V2_DROP); community requires PoW, so without this the edit reaches the wire with NO proof and admit() drops it
    this.invalidateViewCaches()
    return data
  }

  // ---- Posts ----------------------------------------------------------------
  async submitPost ({ community, kind, title, body, url, cid: callerCid, nonce, seed, onProgress }) {
    const c = await this.getCommunity(community)
    if (!c) throw new Error('No such community')
    const me = await this._writer() // mint BEFORE stamping author
    const banned = (await this.overlay(community)).banned
    if (banned.has(me.pubkey)) throw new Error('You are banned from r/' + community)
    if (!title || !title.trim()) throw new Error('A title is required')
    kind = ['text', 'link', 'image'].includes(kind) ? kind : 'text'
    let postUrl = ''
    if (kind !== 'text') {
      postUrl = String(url || '').trim().slice(0, 2000)
      if (!safeUserUrl(postUrl)) throw new Error('URL must start with http://, https://, hyper://, or pear://')
    }
    // Protocol v3 never accepts a caller-selected CID. A CID is recomputed from
    // {type, author, nonce}; callers that need idempotency (seed scripts) provide
    // an explicit deterministic nonce/seed instead. Treating a legacy `cid`
    // argument as the result would reopen the cross-author collision vector.
    if (callerCid != null) throw new Error('Caller-selected post cid is no longer supported; use nonce or seed')
    if (nonce != null && seed != null && nonce !== seed) throw new Error('Post nonce and seed must match when both are provided')
    const contentNonce = nonce != null ? nonce : (seed != null ? seed : uid())
    if (!validContentNonce(contentNonce)) throw new Error('Post nonce must be 1-128 printable characters')
    const cid = await contentId(TYPE.POST, me.pubkey, contentNonce)
    const now = Date.now()
    const data = {
      id: mkid.post(community, cid), cid, community, kind,
      protocol: CONTENT_PROTOCOL, contentNonce,
      title: title.trim().slice(0, 300),
      body: kind === 'text' ? String(body || '').slice(0, 40000) : '',
      url: kind !== 'text' ? postUrl : '',
      author: me.pubkey, createdAt: now, editedAt: 0, deleted: false
    }
    // Box a long text body into an opaque blob/dispersal manifest before signing
    // (design §5 Phase 2). In v2 mode the manifest is sealed inside the graph fields.
    const batch = []
    if (kind === 'text' && canBox() && shouldBox(data.body)) await this._boxBody(data, { batch })
    await this._emit(TYPE.POST, data, { pow: true, onProgress, batch })
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
    const rows = await this._listPrefix(keys.postsIn(community), { limit: 1000 })
    const recs = rows.map(r => r.value).filter(Boolean)
    return hydrate ? Promise.all(recs.map(r => this._hydrate(r))) : recs
  }

  // Post count for a community sidebar/card. Routes through _count so it works for
  // both v1 (relay prefix count) and v2 (the client-reconstructed view) — the UI must
  // never call sync.count directly, since v2 keys are opaque.
  async postCount (community) { return this._count(keys.postsIn(community)) }

  async editPost (community, cid, body) { return this._editPost(community, cid, body) }

  async _editPost (community, cid, body) {
    const p = await this._rawPost(community, cid)
    if (!p) throw new Error('Post not found')
    if (p.author !== this.me().pubkey) throw new Error('You can only edit your own post')
    if (!(await hasValidContentId(TYPE.POST, p))) throw new Error('Legacy posts are read-only after the protocol v3 identity cutover')
    const data = { ...p, body: String(body || '').slice(0, 40000), editedAt: Date.now() }
    if (p.dispersal) this._dropFloor(p.dispersal.blindContentId) // stale floor entry for the replaced body
    delete data.blob // drop any prior manifest; re-box below if the new body is still long
    delete data.dispersal
    const batch = []
    if (data.kind === 'text' && canBox() && shouldBox(data.body)) await this._boxBody(data, { batch })
    await this._emit(TYPE.POST, data, { pow: true, batch }) // re-mint: _toV2 strips the reconstructed record's pow (V2_DROP), so without this the re-emit hits the wire with NO proof and admit()→verify() drops it. (v2 powTarget is content-independent, so this restores a present proof; it does not re-bind to the edit.)
    this.invalidateViewCaches()
    return data
  }

  async deletePost (community, cid) {
    const p = await this._rawPost(community, cid)
    if (!p) return
    if (p.author !== this.me().pubkey) throw new Error('You can only delete your own post')
    if (!(await hasValidContentId(TYPE.POST, p))) throw new Error('Legacy posts are read-only after the protocol v3 identity cutover')
    const data = { ...p, deleted: true, body: '', url: '', title: p.title, editedAt: Date.now() }
    if (p.dispersal) this._dropFloor(p.dispersal.blindContentId) // deleted post keeps no floor copy
    delete data.blob // a deleted post references no blob
    delete data.dispersal
    await this._emit(TYPE.POST, data, { pow: true }) // re-mint: _toV2 strips the reconstructed record's pow (V2_DROP), so without this the re-emit hits the wire with NO proof and admit()→verify() drops it. (v2 powTarget is content-independent, so this restores a present proof; it does not re-bind to the edit.)
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
  async addComment ({ community, postCid, parentCid, body, nonce, seed, onProgress }) {
    if (!body || !body.trim()) throw new Error('Comment cannot be empty')
    const targetPost = await this._rawPost(community, postCid)
    if (!targetPost) throw new Error('Post not found')
    // Historical CIDs were caller-selected and can already be ambiguous across
    // authors. They stay readable, but accepting a new reply would let an old
    // collision redirect it. Only protocol-v3 targets are writable.
    if (!(await hasValidContentId(TYPE.POST, targetPost))) throw new Error('Legacy threads are read-only after the protocol v3 identity cutover')
    const targetRef = await makeContentRef(TYPE.POST, targetPost)
    let parentRef = null
    if (parentCid) {
      const parent = await this._get(keys.comment(community, postCid, parentCid))
      if (!parent || !(await hasValidContentId(TYPE.COMMENT, parent))) throw new Error('Replies require a protocol v3 parent comment in this thread')
      parentRef = await makeContentRef(TYPE.COMMENT, parent)
    }
    const me = await this._writer() // validate target before mint; then stamp author from the active writer
    const ov = await this.overlay(community)
    if (ov.banned.has(me.pubkey)) throw new Error('You are banned from r/' + community)
    if (ov.locked.has(postCid)) throw new Error('This thread is locked')
    if (nonce != null && seed != null && nonce !== seed) throw new Error('Comment nonce and seed must match when both are provided')
    const contentNonce = nonce != null ? nonce : (seed != null ? seed : uid())
    if (!validContentNonce(contentNonce)) throw new Error('Comment nonce must be 1-128 printable characters')
    const cid = await contentId(TYPE.COMMENT, me.pubkey, contentNonce)
    const now = Date.now()
    const data = {
      id: mkid.comment(community, postCid, cid), cid, community, postCid,
      protocol: CONTENT_PROTOCOL, contentNonce,
      targetRef, parentCid: parentCid || null, parentRef,
      body: body.trim().slice(0, 10000),
      author: me.pubkey, createdAt: now, editedAt: 0, deleted: false
    }
    // Box a long comment body too (same band as posts) — a long comment is as
    // sensitive as a long post body. Short comments stay inline (below threshold).
    // In v2 mode the blob/dispersal manifest is sealed inside the graph fields.
    const batch = []
    if (canBox() && shouldBox(data.body)) await this._boxBody(data, { batch })
    await this._emit(TYPE.COMMENT, data, { pow: true, onProgress, batch })
    this.invalidateViewCaches()
    return data
  }

  // Body-free callers (karma) pass { hydrate: false } to skip fetching+decrypting
  // boxed comment bodies they only discard — mirrors listPostsIn (review FIX 4).
  async listComments (community, postCid, { hydrate = true } = {}) {
    const rows = await this._listPrefix(keys.commentsOn(community, postCid), { limit: 1000 })
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
    if (!(await hasValidContentId(TYPE.COMMENT, c))) throw new Error('Legacy comments are read-only after the protocol v3 identity cutover')
    const targetPost = await this._rawPost(community, postCid)
    if (!targetPost || !(await hasValidContentId(TYPE.POST, targetPost))) throw new Error('Legacy threads are read-only after the protocol v3 identity cutover')
    const targetRef = await makeContentRef(TYPE.POST, targetPost)
    let parentRef = null
    if (c.parentCid) {
      const parent = await this._get(keys.comment(community, postCid, c.parentCid))
      if (!parent || !(await hasValidContentId(TYPE.COMMENT, parent))) throw new Error('Replies require a protocol v3 parent comment in this thread')
      parentRef = await makeContentRef(TYPE.COMMENT, parent)
    }
    const data = { ...c, targetRef, parentRef, body: String(body || '').slice(0, 10000), editedAt: Date.now() }
    if (c.dispersal) this._dropFloor(c.dispersal.blindContentId) // stale floor entry for the replaced body
    delete data.blob // drop any prior manifest; re-box below if still long
    delete data.dispersal
    const batch = []
    if (canBox() && shouldBox(data.body)) await this._boxBody(data, { batch })
    await this._emit(TYPE.COMMENT, data, { pow: true, batch }) // re-mint: _toV2 strips the reconstructed record's pow (V2_DROP), so without this the re-emit hits the wire with NO proof and admit()→verify() drops it. (v2 powTarget is content-independent, so this restores a present proof; it does not re-bind to the edit.)
    this.invalidateViewCaches()
    return data
  }

  async deleteComment (community, postCid, cid) {
    const c = await this._get(keys.comment(community, postCid, cid))
    if (!c) return
    if (c.author !== this.me().pubkey) throw new Error('You can only delete your own comment')
    if (!(await hasValidContentId(TYPE.COMMENT, c))) throw new Error('Legacy comments are read-only after the protocol v3 identity cutover')
    const targetPost = await this._rawPost(community, postCid)
    if (!targetPost || !(await hasValidContentId(TYPE.POST, targetPost))) throw new Error('Legacy threads are read-only after the protocol v3 identity cutover')
    const targetRef = await makeContentRef(TYPE.POST, targetPost)
    let parentRef = null
    if (c.parentCid) {
      const parent = await this._get(keys.comment(community, postCid, c.parentCid))
      if (!parent || !(await hasValidContentId(TYPE.COMMENT, parent))) throw new Error('Replies require a protocol v3 parent comment in this thread')
      parentRef = await makeContentRef(TYPE.COMMENT, parent)
    }
    const data = { ...c, targetRef, parentRef, deleted: true, body: '', editedAt: Date.now() }
    if (c.dispersal) this._dropFloor(c.dispersal.blindContentId) // deleted comment keeps no floor copy
    delete data.blob // a deleted comment references no blob
    delete data.dispersal
    await this._emit(TYPE.COMMENT, data, { pow: true }) // re-mint: _toV2 strips the reconstructed record's pow (V2_DROP), so without this the re-emit hits the wire with NO proof and admit()→verify() drops it. (v2 powTarget is content-independent, so this restores a present proof; it does not re-bind to the edit.)
    this.invalidateViewCaches()
  }

  // ---- Votes ----------------------------------------------------------------
  async vote (targetCid, community, targetType, value, context = {}) {
    let target = null
    if (targetType === TYPE.POST || targetType === 'post') {
      targetType = TYPE.POST
      target = await this._rawPost(community, targetCid)
      if (!target) throw new Error('Post not found')
      if (!(await hasValidContentId(TYPE.POST, target))) throw new Error('Legacy posts are read-only after the protocol v3 identity cutover')
    } else if (targetType === TYPE.COMMENT || targetType === 'comment') {
      targetType = TYPE.COMMENT
      let valid = null
      const postCid = typeof context === 'string' ? context : (context && context.postCid)
      if (postCid) {
        // Normal UI path: direct key lookup is O(1), even on forums with hundreds
        // of thousands of comments. App wiring supplies the enclosing postCid.
        const candidate = await this._get(keys.comment(community, postCid, targetCid))
        if (candidate && candidate.cid === targetCid && await hasValidContentId(TYPE.COMMENT, candidate)) valid = candidate
      } else {
        // Backwards-compatible API fallback for older callers that omitted the
        // enclosing post. The globally author-bound v3 CID prevents redirection,
        // but this scan is intentionally not the normal browser path.
        const rows = await this._listPrefix(keys.commentPrefix(), { limit: 1000 })
        const candidates = rows.map(r => r.value).filter(c => c && c.community === community && c.cid === targetCid)
        for (const candidate of candidates) if (await hasValidContentId(TYPE.COMMENT, candidate)) { valid = candidate; break }
      }
      if (!valid) throw new Error('Legacy comments are read-only after the protocol v3 identity cutover')
      target = valid
    } else {
      throw new Error('Vote target must be a post or comment')
    }
    const targetRef = await makeContentRef(targetType, target)
    const me = await this._writer() // validate target before mint; then bake the active pubkey into vote id
    value = value === 1 ? 1 : value === -1 ? -1 : 0
    const now = Date.now()
    const data = {
      id: mkid.vote(targetCid, me.pubkey), targetCid, targetType, community,
      protocol: CONTENT_PROTOCOL, targetRef,
      value, author: me.pubkey, ts: now
    }
    await this._emit(TYPE.VOTE, data)
    this.invalidateViewCaches('vote')
    return data
  }

  async rawVotes (targetCid) {
    const rows = await this._listPrefix(keys.votesFor(targetCid), { limit: 1000 })
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
    // Lurkers (me === null) are a valid viewer state: tallies render with
    // myVote 0; cache them under an explicit 'anon' viewer key rather than a
    // stringified null. After the first-write mint the viewer key changes, so
    // no stale lurker tally can collide with the new identity's.
    const viewerKey = me || 'anon'
    const uniq = [...new Set(cids)]
    const out = new Map()
    const missing = []
    for (const cid of uniq) {
      const key = viewerKey + ':' + cid
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
        this._tallyCache.set(viewerKey + ':' + cid, { val, epoch: this._epoch })
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
    const me = await this._writer() // mint BEFORE mkid.profile bakes the pubkey into the id
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

  async setFollow (targetPub, on = true) { return this._setFollow(targetPub, on) }

  async _setFollow (targetPub, on = true) {
    const me = await this._writer() // mint BEFORE mkid.follow bakes the pubkey into the id
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
    const rows = await this._listPrefix(keys.followersOf(pub), { limit: 1000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted).map(v => v.author)
  }

  // Everyone pub FOLLOWS — a scan of the follow! range filtered by author (client-
  // side aggregation, same cost model as karmaFor).
  async followingOf (pub) {
    const rows = await this._listPrefix(keys.followAll(), { limit: 1000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted && v.author === pub).map(v => v.target)
  }

  async followCounts (pub) {
    const [followers, following] = await Promise.all([this.followersOf(pub), this.followingOf(pub)])
    return { followers: followers.length, following: following.length }
  }

  async setMembership (community, on = true) { return this._setMembership(community, on) }

  async _setMembership (community, on = true) {
    const me = await this._writer() // mint BEFORE mkid.member bakes the pubkey into the id
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
    const rows = await this._listPrefix(keys.membersOf(community), { limit: 1000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted).map(v => v.author)
  }

  async memberCount (community) { return (await this.membersOf(community)).length }

  async myMemberships () {
    const me = this.me().pubkey
    const rows = await this._listPrefix(keys.memberAll(), { limit: 1000 })
    return rows.map(r => r.value).filter(v => v && !v.deleted && v.author === me).map(v => v.community)
  }

  // One-time migration: device-local prefs (which die with localStorage and are
  // invisible to peers) become signed records. Idempotent per identity — guarded
  // by a per-pubkey flag AND skipped for edges that already have a record. The
  // flag is only set when every edge landed, so a partial run retries next boot.
  async migrateLocalGraph ({ follows = [], subs = [], storage } = {}) {
    const me = this.me().pubkey
    // Lurker (lazy web identity): nothing to migrate INTO yet — running would
    // trigger ensureWriter and mint at boot. app.js re-kicks this after the
    // first write's mint; the flag key stays per-pubkey (never 'null').
    if (!me) return { migrated: 0, skipped: true }
    const flagKey = 'peerit:graph-migrated:' + me
    try { if (storage && storage.getItem(flagKey)) return { migrated: 0, skipped: true } } catch {}
    let migrated = 0; let failed = 0
    for (const pub of follows) {
      try { if (pub && pub !== me && !(await this.isFollowing(pub))) { await this._setFollow(pub, true); migrated++ } } catch { failed++ }
    }
    for (const slug of subs) {
      try {
        const mine = await this._get(keys.member(slug, me))
        if (!mine || mine.deleted) { await this._setMembership(slug, true); migrated++ }
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
    const rows = await this._listPrefix(keys.modsIn(community), { limit: 1000 })
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

  async modAction (community, args) { return this._modAction(community, args) }

  async _modContentTarget (community, targetCid, targetType, postCid) {
    if (targetType != null && targetType !== TYPE.POST && targetType !== TYPE.COMMENT) throw new Error('Moderation target must be a post or comment')

    if (targetType == null || targetType === TYPE.POST) {
      const post = await this._rawPost(community, targetCid)
      if (post) {
        if (!(await hasValidContentId(TYPE.POST, post))) throw new Error('Legacy posts are read-only after the protocol v3 identity cutover')
        return { targetType: TYPE.POST, target: post, targetRef: await makeContentRef(TYPE.POST, post) }
      }
      if (targetType === TYPE.POST) throw new Error('Post not found')
    }

    let comment = null
    if (postCid) {
      const candidate = await this._get(keys.comment(community, postCid, targetCid))
      if (candidate?.cid === targetCid) comment = candidate
    } else {
      // Compatibility for older API callers. The browser supplies postCid and
      // takes the direct O(1) path; a bounded scan keeps legacy tests/tools usable.
      const rows = await this._listPrefix(keys.commentPrefix(), { limit: 1000 })
      comment = rows.map(row => row.value).find(value => value?.community === community && value.cid === targetCid) || null
    }
    if (!comment) throw new Error('Comment not found')
    if (!(await hasValidContentId(TYPE.COMMENT, comment))) throw new Error('Legacy comments are read-only after the protocol v3 identity cutover')
    return { targetType: TYPE.COMMENT, target: comment, targetRef: await makeContentRef(TYPE.COMMENT, comment) }
  }

  async _modAction (community, { action, targetCid, targetType, postCid, targetUser, reason }) {
    const me = await this._writer() // mint BEFORE stamping the acting mod
    const mods = await this.getMods(community)
    if (!mods.has(me.pubkey)) throw new Error('Only moderators can do that')
    let boundCid = null
    let boundType = null
    let targetRef = null
    let boundUser = null

    if (CONTENT_MOD_ACTIONS.has(action)) {
      if (targetUser != null) throw new Error('Content moderation actions cannot target a user')
      const bound = await this._modContentTarget(community, targetCid, targetType, postCid)
      boundCid = bound.target.cid
      boundType = bound.targetType
      targetRef = bound.targetRef
      if ((action === MOD.LOCK || action === MOD.UNLOCK || action === MOD.STICKY || action === MOD.UNSTICKY) && boundType !== TYPE.POST) {
        throw new Error('Lock and sticky actions require a post target')
      }
    } else if (USER_MOD_ACTIONS.has(action)) {
      if (targetCid != null || targetType != null) throw new Error('User moderation actions cannot target content')
      boundUser = String(targetUser || '').toLowerCase()
      if (!isHex64(boundUser)) throw new Error('User moderation target must be a full 64-character public key.')
    } else {
      throw new Error('Unknown moderation action')
    }

    const actionId = uid()
    const now = Date.now()
    const data = {
      id: mkid.mod(community, actionId), actionId, community, action,
      protocol: CONTENT_PROTOCOL,
      targetCid: boundCid, targetType: boundType, targetRef, targetUser: boundUser,
      reason: (reason || '').slice(0, 300), by: me.pubkey, ts: now
    }
    await this._emit(TYPE.MOD, data)
    this.invalidateViewCaches()
    return data
  }

  // Convenience wrappers
  removePost (community, cid, reason) { return this.modAction(community, { action: MOD.REMOVE, targetCid: cid, reason }) }
  approvePost (community, cid) { return this.modAction(community, { action: MOD.APPROVE, targetCid: cid }) }
  toggleLock (community, cid, locked) { return this.modAction(community, { action: locked ? MOD.UNLOCK : MOD.LOCK, targetCid: cid, targetType: TYPE.POST }) }
  toggleSticky (community, cid, stuck) { return this.modAction(community, { action: stuck ? MOD.UNSTICKY : MOD.STICKY, targetCid: cid, targetType: TYPE.POST }) }
  banUser (community, user, reason) { return this.modAction(community, { action: MOD.BAN, targetUser: user, reason }) }
  unbanUser (community, user) { return this.modAction(community, { action: MOD.UNBAN, targetUser: user }) }

  // Mod management. resolveMods (model.js) is the network truth: any CURRENT mod
  // can add/remove, actions apply in timestamp order, and the founder can never
  // be removed. Validate the pubkey shape here so a typo becomes an error
  // instead of a signed mod record binding a key nobody holds.
  async addMod (community, user) {
    const pub = String(user || '').toLowerCase()
    if (!isHex64(pub)) throw new Error('Moderator must be a full 64-character public key.')
    return this._modAction(community, { action: MOD.ADD_MOD, targetUser: pub })
  }

  async removeMod (community, user) {
    // New admission accepts canonical lowercase user targets only. Historical
    // malformed entries (none exist in the frozen live inventory) stay visible
    // but cannot be extended with another malformed action.
    const lower = String(user || '').toLowerCase()
    if (!isHex64(lower)) throw new Error('Moderator must be a full 64-character public key.')
    return this._modAction(community, { action: MOD.REMOVE_MOD, targetUser: lower })
  }

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
