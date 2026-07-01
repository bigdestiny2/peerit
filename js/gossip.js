// gossip.js — the multi-writer layer. Each user writes ONLY their own outbox;
// peers replicate each other's outboxes and merge them into one view.
//
// SECURITY MODEL (post-audit): authenticity comes from the Ed25519 SIGNATURE,
// never from which outbox relayed a record. A record is admitted iff:
//   1. its storage key === the key recomputed from its own fields (key binding),
//   2. its signer (_k) === its claimed author (ownerOf), and
//   3. in secure mode its Ed25519 signature verifies.
// So relaying a victim-labelled outbox full of fabricated records gains nothing.
// Records are verified at INGEST too, so a forgery can't evict a real record.
//
// Community names: ownership is sticky — once a replica has admitted r/<slug>
// for some creator, a different creator can never replace it (no hijack of an
// established community). Genesis races for a brand-new slug resolve
// deterministically; pure-gossip unique naming can still be squatted at genesis
// (see README) — that is a naming limitation, NOT a content-forgery one.
//
// Without a crypto backend (a browser lacking SubtleCrypto Ed25519) this degrades
// to cooperative owner-binding (NOT secure — local simulation only).

import { TYPE, keys } from './model.js'
import { ownerOf, expectedKey, typeFromKey, recordTs, canonical, outboxCensus, censusString } from './canon.js'
import { verifyRecord } from './verify.js'
import { verify as edVerify, isSecure, ready as cryptoReady, hashHex } from './crypto.js'
import { makeValidator } from './pow.js'

const PEERS_KEY = 'peerit:peers'
const CLAIMED_KEY = 'peerit:claimed'
const outboxKey = (pub) => 'peerit:outbox:' + pub
const TOPIC = 'peerit-gossip-v1'
const PROTO_KEYS = new Set(['__proto__', 'prototype', 'constructor'])
const MAX_PEERS = 4096
const MAX_DESCRIPTOR_BYTES = 8192
const MAX_ROWS_PER_PEER = 50000
const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i
// Persisted verified view, so a reload renders instantly instead of blanking
// while it re-discovers. Plus per-outbox change-markers (heads) so each poll
// only re-reads outboxes that actually changed.
const CACHE_KEY = 'peerit:gossip-view'
const MAX_CACHE_BYTES = 3 * 1024 * 1024 // skip persisting if the view is huge (graceful)
const RECONCILE_EVERY = 30 // every N polls, ignore heads + re-verify everything (defends against a stale/lying relay or a tampered local cache)

// ---- local reducer + range over a {key:value} view --------------------------
function applyOp (view, op) {
  if (!op || typeof op !== 'object' || !op.type) return
  if (op.data && op.data.id != null) view[op.type.replace(':', '!') + '!' + op.data.id] = op.data
}
// `keys` (optional) is a pre-sorted key array for `view` — pass the cached one
// so a stable merged view isn't re-sorted on every list/range query. Filters
// return fresh arrays and reverse copies first, so the cached array is never
// mutated.
function rangeFromView (view, opts, keys) {
  let ks = keys || Object.keys(view).sort()
  if (opts.gte != null) ks = ks.filter(k => k >= opts.gte)
  if (opts.gt != null) ks = ks.filter(k => k > opts.gt)
  if (opts.lte != null) ks = ks.filter(k => k <= opts.lte)
  if (opts.lt != null) ks = ks.filter(k => k < opts.lt)
  if (opts.reverse) ks = ks.slice().reverse()
  let limit = Number(opts.limit) || 100
  if (limit < 1) limit = 100
  if (limit > 1000) limit = 1000
  const out = []
  for (const k of ks) { if (out.length >= limit) break; out.push({ key: k, value: view[k] }) }
  return out
}

// Sorted keys of a merged view, cached by view-object identity. A new merge
// produces a fresh view object, so the cache auto-refreshes without explicit
// invalidation.
function cachedSortedKeys (self, view) {
  if (self._sortedFor !== view) { self._sortedFor = view; self._sortedKeysCache = Object.keys(view).sort() }
  return self._sortedKeysCache
}

// ---- authenticity (cache only positive verdicts; key binds sig TO content) --
const _verdict = new Map()
const VERDICT_CACHE_MAX = 50000
async function honored (type, val) {
  if (!val || !val._sig) return verifyRecord(type, val)
  const ck = JSON.stringify([val._sig, val._k || '', val._dk || '', val._ns || '', canonical(type, val)])
  if (_verdict.has(ck)) return _verdict.get(ck)
  const v = await verifyRecord(type, val)
  if (v === 'ok') { // never cache 'bad' (cheap to recompute; avoids unbounded growth from rejected forgeries)
    if (_verdict.size >= VERDICT_CACHE_MAX) _verdict.delete(_verdict.keys().next().value) // bounded FIFO eviction
    _verdict.set(ck, v)
  }
  return v
}

async function admit (type, val, key, pub, secure, validate) {
  if (!val || typeof val !== 'object') return false
  if (!type || expectedKey(type, val) !== key) return false // key binding
  const owner = ownerOf(type, val)
  if (!owner) return false
  const v = await honored(type, val)
  if (secure) {
    if (v !== 'ok') return false // signature is the authority
  } else if (!(owner === pub && v !== 'bad')) return false // cooperative dev fallback only
  if (validate) {
    try {
      if (!(await validate(type, val))) return false
    } catch {
      return false
    }
  }
  return true
}

// deterministic, order-independent conflict winners
function laterRecord (a, b) {
  const ta = recordTs(a), tb = recordTs(b)
  if (ta !== tb) return ta > tb
  const da = a.deleted ? 1 : 0, db = b.deleted ? 1 : 0
  if (da !== db) return da > db                       // a tombstone wins ties (no resurrection)
  return String(a._sig || '') > String(b._sig || '')  // total order
}
function communityWins (a, b) {
  const ca = a.createdAt || 0, cb = b.createdAt || 0
  if (ca !== cb) return ca < cb
  const ka = a.creator || '', kb = b.creator || ''
  if (ka !== kb) return ka < kb
  return String(a._sig || '') < String(b._sig || '')
}
function winner (type, a, b) { return type === 'community' ? communityWins(a, b) : laterRecord(a, b) }

// THE merge. `claimed` (slug -> creator) makes community ownership sticky across
// calls; pass a persistent object to lock established names. async (verifies sigs).
export async function mergeOutboxes (boxes, claimed, validate) {
  await cryptoReady()
  const secure = isSecure()
  claimed = claimed || {}
  const out = Object.create(null)
  for (const { pub, view } of boxes) {
    if (!view || typeof view !== 'object') continue
    for (const key in view) {
      if (PROTO_KEYS.has(key)) continue
      const val = view[key]
      const type = typeFromKey(key)
      if (!(await admit(type, val, key, pub, secure, validate))) continue
      if (type === 'community') {
        const slug = val.slug
        if (claimed[slug] && claimed[slug] !== val.creator) continue // sticky: name owned by another creator
      }
      const ex = out[key]
      if (!ex || winner(type, val, ex)) out[key] = val
    }
  }
  // Lock the resolved community owners so a later different-creator claim can't take them.
  for (const key in out) {
    if (typeFromKey(key) === 'community') { const s = out[key].slug; if (s && !claimed[s]) claimed[s] = out[key].creator }
  }
  return out
}

// Audit an author's replicated rows against their SIGNED head (verify the head
// itself with verifyRecord first — this only compares the census). Pass `owner`
// (the outbox pubkey) so a foreign validly-signed row a relay injects can't pad
// the census. The SOUND "this source is not serving the author's committed set"
// signal is `hasHead && !matches`: a root mismatch means rows were withheld,
// reordered, or substituted. `countSufficient` (got >= count) is NOT sound on
// its own — a relay can hold cardinality constant while dropping a committed key
// — so never fail over on count alone. `hasHead:false` means UN-AUDITABLE
// (fail-OPEN), NOT healthy: a relay can strip the head to disable auditing.
// Detection only; ACTING on it needs an independent head + an alternate source
// (Phase B cross-relay comparison), and rollback/strip resistance across restart
// needs the Phase C durable signed directory.
//   { hasHead, matches, countSufficient, expected, got }
export async function auditOutbox (rows, head, owner) {
  const auditOwner = owner || (head && (head.author || head.id || head._k))
  const census = outboxCensus(rows, auditOwner)
  const got = census.length
  if (!head || typeof head.count !== 'number') return { hasHead: false, matches: null, countSufficient: true, expected: null, got }
  const expected = head.count | 0
  const matches = head.root === await hashHex(censusString(census))
  return { hasHead: true, matches, countSufficient: got >= expected, expected, got }
}

// ---- incremental merge primitives (BridgeGossipSync delta path) -------------
// A record's Ed25519 signature changes iff its signed content changes (every
// edit/delete/vote-flip re-signs), so `_sig` is a perfect, cheap "did this row
// change since last time?" token — letting the bridge skip re-verifying and
// re-merging rows that haven't moved.
function changeToken (val) { return val && val._sig ? val._sig : JSON.stringify(val) }

// Keys whose WINNING value differs between two merged views (added / removed /
// replaced). Lets the bridge poll notify listeners only when the visible view
// actually changed, and tells the UI exactly which records to repaint.
function diffViews (prev, next) {
  const changed = []
  for (const k in next) { if (!prev || !(k in prev) || changeToken(prev[k]) !== changeToken(next[k])) changed.push(k) }
  if (prev) for (const k in prev) { if (!(k in next)) changed.push(k) }
  return changed
}

// Combine ALREADY-ADMITTED per-peer views into one merged view using the SAME
// deterministic winner() + sticky-community rules as mergeOutboxes, but WITHOUT
// re-verifying signatures. The incremental path admits each row once (when its
// signature first appears) and keeps the admitted value per peer, so the result
// here is identical to mergeOutboxes over the same raw outboxes. (Only
// `community!<slug>` keys ever collide across peers; every other key lives in
// exactly one writer's outbox, so winner() is trivial for them.)
function combineAdmitted (boxes, claimed) {
  const out = Object.create(null)
  for (const { view } of boxes) {
    for (const key in view) {
      if (PROTO_KEYS.has(key)) continue
      const val = view[key]
      const type = typeFromKey(key)
      if (type === 'community') {
        const slug = val.slug
        if (claimed[slug] && claimed[slug] !== val.creator) continue // sticky: owned by another creator
      }
      const ex = out[key]
      if (!ex || winner(type, val, ex)) out[key] = val
    }
  }
  for (const key in out) {
    if (typeFromKey(key) === 'community') { const s = out[key].slug; if (s && !claimed[s]) claimed[s] = out[key].creator }
  }
  return out
}

// ---- dev / Node gossip ------------------------------------------------------
class GossipSync {
  constructor ({ storage, bus, getMe, validate = makeValidator() }) {
    this.mode = 'gossip-dev'
    this.storage = storage
    this.bus = bus
    this.getMe = getMe
    this._listeners = new Set()
    this._cache = null
    this._inflight = null
    this._epoch = 0
    this.validate = validate
  }

  async ready () {
    await cryptoReady()
    this.mode = isSecure() ? 'gossip-dev' : 'gossip-dev-insecure'
    this._addPeer(this.getMe())
    if (this.bus) {
      this.bus.onMessage((m) => this._onBus(m))
      await this.bus.send({ t: 'hello', pub: this.getMe() })
      await this._broadcastMine()
      this._helloRetry()
    }
    return this
  }

  _read (k) { try { const s = this.storage.getItem(k); return s ? JSON.parse(s) : null } catch { return null } }
  _write (k, v) { this.storage.setItem(k, JSON.stringify(v)) }
  _outbox (pub) { return this._read(outboxKey(pub)) || {} }
  _peers () { return this._read(PEERS_KEY) || [] }
  _addPeer (pub) { if (!pub) return; const p = this._peers(); if (!p.includes(pub) && p.length < MAX_PEERS) { p.push(pub); this._write(PEERS_KEY, p) } }

  _helloRetry () {
    let n = 0
    const tick = () => {
      if (n++ >= 3 || !this.bus) return
      try { this.bus.send({ t: 'hello', pub: this.getMe() }) } catch {}
      const t = setTimeout(tick, 300); if (t && t.unref) t.unref()
    }
    const t = setTimeout(tick, 300); if (t && t.unref) t.unref()
  }

  async _onBus (m) {
    if (!m || !m.t) return
    const me = this.getMe()
    if (m.t === 'hello' && m.pub && m.pub !== me) {
      this._addPeer(m.pub); await this._broadcastMine(); this._invalidate(); this._emit()
    } else if (m.t === 'outbox' && m.pub && m.pub !== me) {
      this._addPeer(m.pub)
      const incoming = m.view || {}
      const secure = isSecure()
      // Verify everything FIRST (await), into a clean admitted map — so a forged
      // record can never be written into the replica (no eviction of real data).
      const admitted = {}
      for (const k in incoming) {
        if (PROTO_KEYS.has(k)) continue
        const iv = incoming[k]
        if (await admit(typeFromKey(k), iv, k, m.pub, secure, this.validate)) admitted[k] = iv
      }
      // Re-read AFTER the awaits, then a single write — minimises the RMW window.
      const cur = this._outbox(m.pub)
      let changed = false
      for (const k in admitted) {
        const iv = admitted[k]
        if (!cur[k] || winner(typeFromKey(k), iv, cur[k])) { cur[k] = iv; changed = true }
      }
      if (changed) { this._write(outboxKey(m.pub), cur); this._invalidate() }
      this._emit()
    }
  }

  _broadcastMine () { return this.bus ? this.bus.send({ t: 'outbox', pub: this.getMe(), view: this._outbox(this.getMe()) }) : undefined }
  async announce () { this._addPeer(this.getMe()); await this._broadcastMine(); this._invalidate(); this._emit() }

  async append (op) {
    const me = this.getMe()
    this._addPeer(me)
    const box = this._outbox(me)
    applyOp(box, { type: op.type, data: op.data })
    this._write(outboxKey(me), box)
    this._invalidate()
    await this._broadcastMine()
    this._emit()
    return { ok: true }
  }

  async _merged () {
    if (this._cache) return this._cache
    if (this._inflight) return this._inflight
    const epoch = this._epoch
    this._inflight = (async () => {
      const boxes = this._peers().map(pub => ({ pub, view: this._outbox(pub) }))
      const claimed = this._read(CLAIMED_KEY) || {}
      const merged = await mergeOutboxes(boxes, claimed, this.validate)
      this._write(CLAIMED_KEY, claimed)
      if (this._epoch === epoch) this._cache = merged // discard if invalidated mid-flight
      this._inflight = null
      return merged
    })()
    return this._inflight
  }
  _invalidate () { this._cache = null; this._inflight = null; this._epoch++ }

  async get (key) { const v = await this._merged(); return Object.prototype.hasOwnProperty.call(v, key) ? v[key] : null }
  async list (prefix, opts = {}) { const v = await this._merged(); return rangeFromView(v, prefix ? { gte: prefix, lt: prefix + '\xff', limit: opts.limit } : { limit: opts.limit }, cachedSortedKeys(this, v)) }
  async range (opts = {}) { const v = await this._merged(); return rangeFromView(v, opts, cachedSortedKeys(this, v)) }
  async count (prefix) { const v = await this._merged(); if (!prefix) return Object.keys(v).length; let n = 0; for (const k in v) if (k >= prefix && k < prefix + '\xff') n++; return n }
  async status () { const v = await this._merged(); return { appId: 'peerit', mode: this.mode, secure: isSecure(), peers: this._peers().length, viewLength: Object.keys(v).length } }

  onChange (fn) { this._listeners.add(fn); return () => this._listeners.delete(fn) }
  _emit () { for (const fn of this._listeners) { try { fn() } catch (e) { console.error(e) } } }
}

// ---- real PearBrowser gossip ------------------------------------------------
class BridgeGossipSync {
  constructor ({ pear, getMe, identity, storage, validate = makeValidator(), pollMs = 4000, writeHead = false, readOnly = false }) {
    this.mode = 'gossip-bridge'
    this.pear = pear
    this.getMe = getMe
    this.identity = identity
    this.storage = storage
    // Fail-closed write gate: in read-only web mode NO outbox write (post, vote,
    // community, mod, …) may reach the relay. Guarding here (the single append
    // chokepoint) can't be bypassed by a UI handler that forgot an isReadOnly()
    // check, and it also prevents a stray head! append.
    this._readOnly = readOnly
    // When on, maintain a signed head!<me> record after each of my writes (the
    // outbox "merkle root": a census of my own records so a reader can detect a
    // relay withholding rows). Off by default so existing count-based tests are
    // untouched; app.js turns it on in production.
    this._writeHead = writeHead
    this._listeners = new Set()
    this._peers = new Map() // pub -> { appId, inviteKey }
    this._cache = null            // current merged view (maintained incrementally)
    this._peerViews = new Map()   // pub -> admitted {key:value} view (verified rows only)
    this._peerSigs = new Map()    // pub -> Map(key -> changeToken) seen last refresh
    this._peerHeads = new Map()   // pub -> last-seen outbox version (from /api/sync/heads)
    this._withholding = new Set()  // pubs whose replicated rows failed their signed-head audit (detection only)
    this._claimed = null          // sticky community owners (slug -> creator), persisted
    this._refreshing = null       // in-flight refresh promise (serialises concurrent merges)
    this._destroyed = false
    this._poll = null
    this._pollTimer = null
    this._refreshCount = 0
    this._myInviteAppId = null
    this._pollMs = pollMs // remote writes don't notify us; a periodic re-merge surfaces peers' new rows (tunable/testable)
    this.validate = validate
  }

  // Full pubkey as appId (64 hex == bridge's max appId length) so two distinct
  // users can never collide onto the same sync group.
  _myAppId () { return this.getMe() }

  // Every outbox this user has ever written, persisted locally. Re-merging ALL
  // of them on boot makes posts survive even if PearBrowser hands back a
  // different per-app identity key on reopen (which would otherwise orphan the
  // prior outbox and make posts "vanish" though they're still on disk).
  _store () { return this.storage || (typeof localStorage !== 'undefined' ? localStorage : null) }
  _getLocal (key) { try { const s = this._store(); return s ? s.getItem(key) : null } catch { return null } }
  _setLocal (key, value) { try { const s = this._store(); if (s) s.setItem(key, value) } catch {} }
  _outboxKeyName (appId) { return `peerit:my-outbox-key:${appId}` }
  _getOutboxKey (appId) {
    if (!HEX64.test(appId || '')) return null
    return this._getLocal(this._outboxKeyName(appId)) || this._getLocal('peerit:my-outbox-key')
  }
  _setOutboxKey (appId, inviteKey) {
    if (!HEX64.test(appId || '') || !HEX64.test(inviteKey || '')) return
    this._setLocal(this._outboxKeyName(appId), inviteKey)
    this._setLocal('peerit:my-outbox-key', inviteKey)
  }
  _knownOutboxes () {
    try {
      const list = JSON.parse(this._getLocal('peerit:my-outboxes') || '[]')
      return Array.isArray(list)
        ? list.filter(o => o && HEX64.test(o.appId || '') && HEX64.test(o.inviteKey || ''))
        : []
    } catch { return [] }
  }
  _rememberOutbox (appId, inviteKey) {
    if (!HEX64.test(appId || '') || !HEX64.test(inviteKey || '')) return
    const list = this._knownOutboxes()
    if (!list.find(o => o.appId === appId && o.inviteKey === inviteKey)) {
      list.push({ appId, inviteKey })
      this._setLocal('peerit:my-outboxes', JSON.stringify(list))
    }
  }

  // Persist the VERIFIED merged state (discovered peers + their admitted rows +
  // last-seen heads) so a reload renders instantly instead of blanking while it
  // re-discovers. Only the final winning view is user-visible; cached rows are a
  // render hint that the next refresh re-checks (and a periodic full reconcile
  // re-verifies), so a tampered cache self-heals and can never forge for anyone.
  _saveCache () {
    try {
      const peers = []; const views = {}; const heads = {}
      for (const [pub, info] of this._peers) { if (!info.self && HEX64.test(pub) && info.appId === pub && typeof info.inviteKey === 'string') peers.push({ pub, appId: info.appId, inviteKey: info.inviteKey }) }
      for (const [pub, view] of this._peerViews) { const o = {}; for (const k in view) o[k] = view[k]; views[pub] = o }
      for (const [pub, v] of this._peerHeads) heads[pub] = v
      const blob = JSON.stringify({ v: 1, peers, views, heads })
      if (blob.length > MAX_CACHE_BYTES) { this._setLocal(CACHE_KEY, ''); return } // too large → skip (graceful, just slower first paint)
      this._setLocal(CACHE_KEY, blob)
    } catch {}
  }

  // Restore the cached view BEFORE any network, so list()/get() return content on
  // the very first paint. Discovered peers go back into _peers so the first poll
  // re-reads them (heads-gated). Returns true if a view was restored.
  _loadCache () {
    try {
      const raw = this._getLocal(CACHE_KEY)
      if (!raw) return false
      const c = JSON.parse(raw)
      if (!c || typeof c !== 'object') return false
      if (Array.isArray(c.peers)) for (const p of c.peers) {
        if (p && HEX64.test(p.pub || '') && p.appId === p.pub && p.pub !== this.getMe() && typeof p.inviteKey === 'string' && !this._peers.has(p.pub) && this._peers.size < MAX_PEERS) {
          this._peers.set(p.pub, { appId: p.appId, inviteKey: p.inviteKey })
        }
      }
      if (c.views && typeof c.views === 'object') for (const pub in c.views) {
        if (PROTO_KEYS.has(pub) || !this._peers.has(pub)) continue
        const v = c.views[pub]; if (!v || typeof v !== 'object') continue
        const view = Object.create(null); const sig = new Map()
        for (const k in v) { if (PROTO_KEYS.has(k)) continue; view[k] = v[k]; sig.set(k, changeToken(v[k])) }
        this._peerViews.set(pub, view)
        this._peerSigs.set(pub, sig)
      }
      // Deliberately do NOT restore cached heads: the production relay is the
      // EPHEMERAL memory core whose per-outbox version resets to 0 on restart, so a
      // cached version could coincidentally match a different post-restart state and
      // suppress a real change. Leaving _peerHeads empty forces the first poll to
      // re-read (and thus re-validate) every cached peer against the live relay;
      // heads-gating then kicks in for subsequent polls.
      if (!this._claimed) { try { this._claimed = JSON.parse(this._getLocal(CLAIMED_KEY) || '{}') } catch { this._claimed = {} } }
      const boxes = []; for (const [pub, view] of this._peerViews) boxes.push({ pub, view })
      if (boxes.length) { this._cache = combineAdmitted(boxes, this._claimed); this._sortedFor = null; return true }
      return false
    } catch { return false }
  }

  async _openMyOutbox () {
    const appId = this._myAppId()
    let key = null
    key = this._getOutboxKey(appId)
    try {
      // If localStorage was stranded under an old random proxy origin, key is
      // null. In modern PearBrowser create(appId) is open-or-create: it reopens
      // the browser-remembered group for this appId instead of minting a fresh
      // empty outbox.
      return key ? await this.pear.sync.join(appId, key) : await this.pear.sync.create(appId)
    } catch {
      return this.pear.sync.create(appId)
    }
  }

  // Idempotent: open the writable outbox if we haven't yet. Tolerates a network
  // failure (returns false) so boot/posting degrade gracefully and self-heal when
  // the relay comes back.
  async _ensureMyOutbox () {
    const appId = this._myAppId()
    if (this._myInvite && this._myInviteAppId === appId) return true
    try {
      const r = await this._openMyOutbox()
      this._myInvite = r.inviteKey
      this._myInviteAppId = appId
      this._setOutboxKey(appId, r.inviteKey)
      this._peers.set(appId, { appId, inviteKey: r.inviteKey, self: true })
      this._rememberOutbox(appId, r.inviteKey)
      return true
    } catch (e) { console.warn('[gossip] outbox open deferred (offline?):', e && e.message); return false }
  }

  async ready () {
    await cryptoReady()
    // Register our own outbox FIRST (with the locally-remembered key) so a reload
    // renders our content from cache even if the relay is unreachable at boot.
    const appId = this._myAppId()
    const myKey = this._getOutboxKey(appId)
    this._peers.set(appId, { appId, inviteKey: myKey || null, self: true })
    if (HEX64.test(myKey || '')) this._rememberOutbox(appId, myKey)
    // Open (or create) the WRITABLE outbox so we can post. A network failure here
    // is non-fatal — reads + the cached render still work, and the poll retries.
    await this._ensureMyOutbox()
    // Re-join EVERY outbox we've ever owned, so a changed identity key can't
    // strand earlier posts. (Best-effort; offline-tolerant.)
    for (const o of this._knownOutboxes()) {
      if (this._peers.has(o.appId)) continue
      try { await this.pear.sync.join(o.appId, o.inviteKey); this._peers.set(o.appId, { appId: o.appId, inviteKey: o.inviteKey, self: true }) } catch {}
    }
    // Restore last session's verified view (+ discovered peers + heads) so the
    // first list()/get() paints instantly instead of blanking; the poll below then
    // re-reads only what changed and a periodic reconcile re-verifies everything.
    this._loadCache()
    try { console.log('[peerit persist] me=' + (this.getMe() || '').slice(0, 12) + ' outbox=' + (this._myInvite || '').slice(0, 12) + ' knownOutboxes=' + this._knownOutboxes().length + ' cachedPeers=' + this._peers.size) } catch {}
    try {
      this._channel = await this.pear.swarm.v1.join(TOPIC, { server: true, client: true, appName: 'peerit', reason: 'Discover other peerit users' })
      this._channel.on('peer', () => this._announce())
      this._channel.on('message', (peer, data) => this._onDescriptor(data))
      await this._announce()
    } catch (e) { console.warn('[gossip] swarm unavailable:', e && e.message) }
    if (this._pollMs > 0) {
      // Re-merge incrementally and notify ONLY when a peer's rows actually
      // changed. Self-scheduling with ±15% jitter so many clients don't hit the
      // relay in lockstep; each tick is now a single cheap heads call plus reads
      // of only the outboxes that moved.
      const jittered = () => this._pollMs * (0.85 + Math.random() * 0.3)
      const tick = async () => {
        if (this._destroyed) return
        if (!this._myInvite) { try { if (await this._ensureMyOutbox()) await this._announce() } catch {} } // relay came back → resume writing/discovery
        try { const changed = await this._refresh(); if (changed.length) this._emit(changed) } catch (e) { console.warn('[gossip poll]', e && e.message) }
        if (this._destroyed) return
        this._pollTimer = setTimeout(tick, jittered())
        if (this._pollTimer && this._pollTimer.unref) this._pollTimer.unref()
      }
      this._pollTimer = setTimeout(tick, jittered())
      if (this._pollTimer && this._pollTimer.unref) this._pollTimer.unref()
    }
    return this
  }

  // Tear down timers, the swarm channel, and listeners. Call on tab/SPA teardown
  // so a navigated-away page doesn't leak an EventSource + interval.
  destroy () {
    this._destroyed = true
    if (this._poll) { clearInterval(this._poll); this._poll = null }
    if (this._pollTimer) { clearTimeout(this._pollTimer); this._pollTimer = null }
    if (this._channel && this._channel.destroy) { try { this._channel.destroy() } catch {} }
    if (this._refreshing) this._refreshing.catch(() => {}) // don't leave the in-flight refresh's rejection unhandled
    this._channel = null
    this._listeners.clear()
  }

  async _announce () {
    if (!this._channel) return
    const pub = this.getMe(), appId = this._myAppId(), inviteKey = this._myInvite
    let sig = null
    try { sig = await this.identity.sign(`peerit-desc|${pub}|${appId}|${inviteKey}`) } catch {}
    const desc = JSON.stringify({ t: 'outbox-desc', pub, appId, inviteKey, sig: sig && sig.signature, dk: sig && sig.driveKey, ns: sig && sig.namespace })
    const bytes = new TextEncoder().encode(desc)
    for (const p of this._channel.peers) { try { p.send(bytes) } catch {} }
  }

  async _onDescriptor (data) {
    if (data && data.byteLength != null && data.byteLength > MAX_DESCRIPTOR_BYTES) return
    let d
    try {
      const text = new TextDecoder().decode(data)
      if (text.length > MAX_DESCRIPTOR_BYTES) return
      d = JSON.parse(text)
    } catch { return }
    if (!d || d.t !== 'outbox-desc' || !d.pub || d.pub === this.getMe()) return
    if (this._peers.size >= MAX_PEERS) return
    if (!HEX64.test(d.pub) || !HEX64.test(d.appId) || d.appId !== d.pub) return // appId must be the pubkey itself
    if (typeof d.inviteKey !== 'string' || d.inviteKey.length < 16 || d.inviteKey.length > 4096) return
    if (d.ns !== 'peerit' || !HEX128.test(d.sig || '') || !HEX64.test(d.dk || '')) return
    // The descriptor (pub, appId, inviteKey) must be signed by `pub`, binding the
    // invite key to the identity — a peer can't redirect a victim's pub to a
    // Hyperbee it controls.
    const ok = await edVerify(d.pub, `pear.app.${d.dk}:peerit:peerit-desc|${d.pub}|${d.appId}|${d.inviteKey}`, d.sig).catch(() => false)
    if (!ok) return
    if (this._peers.has(d.pub)) return
    try {
      await this.pear.sync.join(d.appId, d.inviteKey) // only commit the peer AFTER a successful join
      this._peers.set(d.pub, { appId: d.appId, inviteKey: d.inviteKey })
      const changed = await this._refresh(); this._emit(changed); this._announce()
    } catch (e) { console.warn('[gossip] join failed', e && e.message) }
  }

  async announce () {
    if (!await this._ensureMyOutbox()) return
    return this._announce()
  }

  async append (op) {
    if (this._readOnly) throw new Error('This peerit is read-only.')
    if (!await this._ensureMyOutbox()) throw new Error('Peerit outbox is unavailable; check relay connectivity and try again.')
    const r = await this.pear.sync.append(this._myAppId(), { type: op.type, data: op.data, timestamp: new Date().toISOString() })
    const changed = await this._refresh()
    // Re-commit my signed head so it always reflects my full record set. It's a
    // low-level append (no re-entry into append()), and we UNION its change set
    // with the record's so the UI still sees the record it just wrote (the head
    // key itself is inert to the UI).
    if (this._writeHead && this.identity && op.type !== TYPE.HEAD) {
      try {
        const headChanged = await this._maintainHead()
        if (headChanged) for (const k of headChanged) if (!changed.includes(k)) changed.push(k)
      } catch (e) { console.warn('[gossip] head update failed:', e && e.message) }
    }
    // head! keys are inert to the UI; strip them so a write's change-set doesn't
    // defeat the vote fast-paths (cacheClassForChangedKeys / patchVotesInPlace).
    this._emit(changed.filter((k) => typeFromKey(k) !== TYPE.HEAD))
    return r
  }

  // Compute + sign + append the outbox head (the "merkle root" census over my own
  // records). Returns the refresh change-set. No PoW (makeValidator passes the
  // 'head' type); signed with the same Ed25519 envelope as every record, so a
  // reader verifies it with the identical verifyRecord() path.
  async _maintainHead () {
    if (this._destroyed) return null // torn down mid-write — don't append after destroy()
    const me = this.getMe()
    if (!HEX64.test(me || '')) return null // no real key -> no meaningful head
    const view = this._peerViews.get(me) || {}
    const rows = []
    for (const k in view) rows.push({ key: k, value: view[k] })
    const census = outboxCensus(rows, me)
    const root = await hashHex(censusString(census))
    const prev = view[keys.head(me)]
    const data = {
      id: me, author: me,
      version: (((prev && prev.version) | 0)) + 1,
      count: census.length, root, updatedAt: Date.now()
    }
    const s = await this.identity.sign(canonical(TYPE.HEAD, data))
    data._sig = s.signature; data._k = s.publicKey; data._dk = s.driveKey; data._ns = s.namespace; data._alg = s.algorithm
    await this.pear.sync.append(this._myAppId(), { type: TYPE.HEAD, data, timestamp: new Date().toISOString() })
    return this._refresh()
  }

  // Incremental re-merge. Re-reads each peer's replicated outbox (the bridge has
  // no since-diff, and edits/votes OVERWRITE existing keys under the LWW reducer,
  // so a key-watermark would miss them), but skips the expensive part — Ed25519 +
  // proof-of-work verification and canonical serialisation — for every row whose
  // signature is unchanged. Rows that DID change are re-verified; the merged view
  // is then rebuilt from the cached per-peer admitted views with cheap winner()
  // comparisons only. Returns the list of merged keys whose winning value changed.
  async _doRefresh () {
    if (this._destroyed) return [] // torn down (e.g. pagehide) — don't touch a discarded instance
    const secure = isSecure()
    if (!this._claimed) { try { this._claimed = JSON.parse(this._getLocal(CLAIMED_KEY) || '{}') } catch { this._claimed = {} } }
    this._refreshCount++

    // Pick which outboxes to re-read. Cheap path: ONE /api/sync/heads call returns
    // a version per outbox; only the ones whose version moved get re-read — so an
    // idle network costs a single request instead of one-read-per-peer. Every
    // RECONCILE_EVERY rounds (or when the relay has no heads endpoint) we read
    // everyone, dropping cached signatures so rows are genuinely RE-VERIFIED — this
    // self-heals against a stale/lying relay or a tampered local cache.
    const reconcile = (this._refreshCount % RECONCILE_EVERY) === 0
    let heads = null
    let headsErrored = false
    const headsFn = this.pear.sync && this.pear.sync.heads
    if (headsFn && this._peers.size) {
      try {
        const appIds = []; for (const [, info] of this._peers) appIds.push(info.appId)
        const resp = await headsFn(appIds)
        heads = resp && resp.heads && typeof resp.heads === 'object' ? resp.heads : null
      } catch { headsErrored = true } // rate-limited/transient
    }
    let toRead
    if (reconcile) {
      this._peerSigs.clear()                 // periodic full RE-VERIFY (relay is untrusted)
      toRead = [...this._peers.keys()]
    } else if (heads) {
      toRead = []                            // cheap path: only outboxes whose version moved
      for (const [pub, info] of this._peers) {
        const v = heads[info.appId]
        if (v === undefined || this._peerHeads.get(pub) !== v) toRead.push(pub)
      }
    } else if (headsErrored) {
      toRead = []                            // transient heads failure → skip this round, don't pile load on a throttled relay
    } else {
      toRead = [...this._peers.keys()]       // relay has no heads endpoint → read everyone (old/dev fallback)
    }

    let anyRowChanged = false
    for (const pub of toRead) {
      const info = this._peers.get(pub); if (!info) continue
      let rows
      try { rows = await this._rowsForPeer(info) } catch { continue }
      const prevSig = this._peerSigs.get(pub) || new Map()
      const view = this._peerViews.get(pub) || Object.create(null)
      const newSig = new Map()
      for (const r of rows) {
        const key = r.key
        if (PROTO_KEYS.has(key)) continue
        const val = r.value
        const tok = changeToken(val)
        newSig.set(key, tok)
        if (prevSig.get(key) === tok) continue // unchanged since last refresh — verdict still holds
        anyRowChanged = true
        if (await admit(typeFromKey(key), val, key, pub, secure, this.validate)) view[key] = val
        else if (key in view) delete view[key] // an edit turned a once-admitted row invalid
      }
      for (const key of prevSig.keys()) { if (!newSig.has(key)) { if (key in view) delete view[key]; anyRowChanged = true } } // key removed (rare)
      this._peerViews.set(pub, view)
      this._peerSigs.set(pub, newSig)
      if (heads && heads[info.appId] !== undefined) this._peerHeads.set(pub, heads[info.appId]) // baseline for next round's gating
    }

    // Withholding / ROLLBACK / STRIP detection + FAILOVER (Phase B). For each
    // re-read peer, take the highest-version SIGNED head across ALL pool relays
    // (crossHead) — a relay serving a stale head (rollback) or none (strip) loses
    // to a relay that has the newer one. Audit the rows we got against that head;
    // on a shortfall, route the READ around the withholding relay (recoverRows
    // finds a relay serving the head-matching set) and re-admit. Degrades to the
    // primary's own head + detection-only surfacing on a single-relay transport.
    const localWriter = this._writeHead && typeof this.getMe === 'function' ? this.getMe() : null
    const multi = this.pear.sync && (this.pear._relayCount || 1) > 1
    const crossHeadFn = multi && this.pear.sync.crossHead
    const recoverFn = multi && this.pear.sync.recoverRows
    for (const pub of toRead) {
      if (localWriter && pub === localWriter) continue // own head can lag briefly between append() and _maintainHead()
      let view = this._peerViews.get(pub); if (!view) continue
      let head = view[keys.head(pub)]
      if (crossHeadFn) { try { const ch = await this.pear.sync.crossHead(pub); if (ch && ch.head && (!head || (ch.head.version | 0) > (head.version | 0))) head = ch.head } catch {} }
      if (!head) continue
      let rows = []; for (const k in view) rows.push({ key: k, value: view[k] })
      let a; try { a = await auditOutbox(rows, head, pub) } catch { continue }
      if (a.hasHead && a.matches === false && recoverFn) {
        try {
          const rec = await this.pear.sync.recoverRows(pub, head)
          if (rec && rec.rows) {
            const view2 = Object.create(null); const newSig = new Map()
            for (const r of rec.rows) { if (PROTO_KEYS.has(r.key)) continue; if (await admit(typeFromKey(r.key), r.value, r.key, pub, secure, this.validate)) { view2[r.key] = r.value; newSig.set(r.key, changeToken(r.value)) } }
            this._peerViews.set(pub, view2); this._peerSigs.set(pub, newSig); view = view2; anyRowChanged = true
            rows = []; for (const k in view2) rows.push({ key: k, value: view2[k] })
            a = await auditOutbox(rows, head, pub)
          }
        } catch {}
      }
      const bad = a.hasHead && a.matches === false
      if (bad) { if (!this._withholding.has(pub)) console.warn('[gossip] outbox ' + pub.slice(0, 12) + '… fails its signed-head audit on every reachable relay (rows withheld/tampered)'); this._withholding.add(pub) } else this._withholding.delete(pub)
    }

    if (this._cache && !anyRowChanged) return [] // nothing moved anywhere — keep cache (and its sorted-key cache)
    const boxes = []
    for (const [pub, view] of this._peerViews) boxes.push({ pub, view })
    const merged = combineAdmitted(boxes, this._claimed)
    this._setLocal(CLAIMED_KEY, JSON.stringify(this._claimed))
    const changed = diffViews(this._cache, merged)
    if (this._cache && changed.length === 0) { /* winning view identical — keep object identity */ }
    else { this._cache = merged; this._sortedFor = null }
    if (changed.length || (anyRowChanged && !reconcile)) this._saveCache() // persist the latest verified view for an instant reload
    return changed
  }

  _refresh () {
    if (this._refreshing) return this._refreshing
    this._refreshing = (async () => { try { return await this._doRefresh() } finally { this._refreshing = null } })()
    return this._refreshing
  }

  async _rowsForPeer (info) {
    if (this.pear.sync.range) {
      const rows = []
      let gt = ''
      while (rows.length < MAX_ROWS_PER_PEER) {
        const limit = Math.min(1000, MAX_ROWS_PER_PEER - rows.length)
        const batch = await this.pear.sync.range(info.appId, { gt, limit })
        if (!Array.isArray(batch) || !batch.length) break
        rows.push(...batch)
        const last = batch[batch.length - 1] && batch[batch.length - 1].key
        if (!last || last === gt || batch.length < limit) break
        gt = last
      }
      return rows
    }
    return this.pear.sync.list(info.appId, '', { limit: 1000 })
  }
  async _merged () {
    if (this._cache) return this._cache
    await this._refresh()
    return this._cache || Object.create(null)
  }
  // Hard reset: drop the merged view AND the incremental state so the next read
  // re-verifies every row from scratch. Internal mutations use _refresh (a cheap
  // delta); this is the escape hatch if the incremental state must be rebuilt.
  _invalidate () { this._cache = null; this._peerViews.clear(); this._peerSigs.clear(); this._claimed = null; this._sortedFor = null }

  async get (key) { const v = await this._merged(); return Object.prototype.hasOwnProperty.call(v, key) ? v[key] : null }
  async list (prefix, opts = {}) { const v = await this._merged(); return rangeFromView(v, prefix ? { gte: prefix, lt: prefix + '\xff', limit: opts.limit } : { limit: opts.limit }, cachedSortedKeys(this, v)) }
  async range (opts = {}) { const v = await this._merged(); return rangeFromView(v, opts, cachedSortedKeys(this, v)) }
  async count (prefix) { const v = await this._merged(); if (!prefix) return Object.keys(v).length; let n = 0; for (const k in v) if (k >= prefix && k < prefix + '\xff') n++; return n }
  _statusOutboxes () {
    const byApp = new Map()
    for (const o of this._knownOutboxes()) {
      if (o && o.appId && o.inviteKey) byApp.set(o.appId, { appId: o.appId, inviteKey: o.inviteKey, current: o.appId === this._myAppId() })
    }
    if (this._myInvite) byApp.set(this._myAppId(), { appId: this._myAppId(), inviteKey: this._myInvite, current: true })
    return [...byApp.values()]
  }
  async status () {
    const v = await this._merged()
    let viewLength = 0
    for (const k in v) if (typeFromKey(k) !== TYPE.HEAD) viewLength++ // head! is an internal census, not a "record"
    return {
      appId: 'peerit',
      mode: this.mode,
      secure: isSecure(),
      peers: this._peers.size,
      viewLength,
      relays: (this.pear && this.pear._relayCount) || 1, // Phase B: how many relays writes fan out across + heads are cross-checked on
      withholding: [...this._withholding], // outboxes still failing their signed-head audit after cross-relay recovery
      inviteKey: this._myInvite,
      outboxAppId: this._myAppId(),
      outboxes: this._statusOutboxes()
    }
  }

  recoveryOutboxes () {
    const out = []
    const seen = new Set()
    const add = (appId, inviteKey) => {
      if (!HEX64.test(appId || '') || !HEX64.test(inviteKey || '')) return
      const key = appId + ':' + inviteKey
      if (seen.has(key)) return
      seen.add(key)
      out.push({ appId, inviteKey })
    }
    add(this._myAppId(), this._myInvite)
    for (const o of this._knownOutboxes()) add(o.appId, o.inviteKey)
    return out
  }

  async importRecoveryBundle (bundle) {
    const failures = []
    let joined = 0
    let currentOutboxRestored = false
    for (const o of bundle.outboxes || []) {
      this._rememberOutbox(o.appId, o.inviteKey)
      try {
        await this.pear.sync.join(o.appId, o.inviteKey)
        joined++
        const self = o.appId === this._myAppId()
        this._peers.set(o.appId, { appId: o.appId, inviteKey: o.inviteKey, self })
        if (self && !currentOutboxRestored) {
          this._myInvite = o.inviteKey
          this._setLocal('peerit:my-outbox-key', o.inviteKey)
          currentOutboxRestored = true
        }
      } catch (err) {
        failures.push({ appId: o.appId, message: err && err.message || 'join failed' })
      }
    }
    this._invalidate() // hard reset: new outboxes joined; rebuild from scratch
    const changed = await this._refresh()
    this._emit(changed)
    await this._announce()
    return { imported: (bundle.outboxes || []).length, joined, failures, currentOutboxRestored }
  }

  onChange (fn) { this._listeners.add(fn); return () => this._listeners.delete(fn) }
  // Listeners receive the list of merged keys whose winning value changed, so the
  // UI can repaint just those records instead of re-rendering the whole page.
  _emit (changed) { for (const fn of this._listeners) { try { fn(changed) } catch (e) { console.error(e) } } }
}

// ---- bus adapters -----------------------------------------------------------
export function makeHub () {
  const peers = []
  return {
    connect () {
      const self = { fn: null }
      peers.push(self)
      return {
        send: async (m) => { const c = JSON.parse(JSON.stringify(m)); for (const p of peers) if (p !== self && p.fn) await p.fn(c) },
        onMessage: (fn) => { self.fn = fn }
      }
    }
  }
}

function browserBus (name) {
  const bc = new BroadcastChannel(name)
  if (bc.unref) bc.unref()
  return { send: (m) => { bc.postMessage(m) }, onMessage: (fn) => { bc.onmessage = (e) => fn(e.data) } }
}

export function createGossip ({ storage, pear, getMe, identity, channelName, forceDev, bus, validate, pollMs, writeHead, readOnly } = {}) {
  if (pear && pear.sync && pear.swarm && !forceDev) return new BridgeGossipSync({ pear, getMe, identity, storage, validate, pollMs, writeHead, readOnly })
  const theBus = bus || (typeof BroadcastChannel !== 'undefined' ? browserBus(channelName || 'peerit-gossip') : null)
  return new GossipSync({ storage, bus: theBus, getMe, validate })
}

export { GossipSync, BridgeGossipSync, applyOp as gossipApplyOp }
