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
import { ownerOf, expectedKey, expectedKeyV2, typeFromKey, typeForRow, recordTs, canonical, outboxCensus, censusString } from './canon.js'
import { unseal } from './seal.js'
import { verifyRecord } from './verify.js'
import { verifyBlobRecord } from './blob-store.js'
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
// A batch is capped on both dimensions. `ranges` is only a round-trip
// optimisation: every returned outbox remains complete-paginated and audited
// against its owner's signed head below.
const RANGE_PAGE_ROWS = 1000
const BATCH_RANGE_OUTBOXES = 32
const FALLBACK_READ_CONCURRENCY = 6
const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i
// Persisted verified view, so a reload renders instantly instead of blanking
// while it re-discovers. Plus per-outbox change-markers (heads) so each poll
// only re-reads outboxes that actually changed.
const CACHE_KEY = 'peerit:gossip-view'
const MAX_CACHE_BYTES = 3 * 1024 * 1024 // skip persisting if the view is huge (graceful)
const FLOOR_KEY = 'peerit:head-floor'   // Phase C durable monotonic head floor (author -> max signed head version)
// Exactly one owner-signed atomic commit may be in flight per device. Persisting
// the complete envelope before the first network call makes response-loss retry
// byte-for-byte idempotent across wake/reload; later writes remain blocked until
// two relays return matching durable receipts.
const PENDING_COMMIT_KEY = 'peerit:pending-commit:v1'
const ATOMIC_LOCKS = new Map() // same-realm fallback for Node/tests; browsers use Web Locks
const PENDING_RETRY_MIN_MS = 1000
const PENDING_RETRY_MAX_MS = 30000
// Synthetic change key used when transport integrity changes without any accepted
// content changing. UI listeners can repaint the status warning without treating a
// rejected rollback/withholding candidate as a real record mutation.
export const SYNC_INTEGRITY_STATUS_KEY = 'peerit:status:integrity'

// A floor applies to the signed author head INSIDE a candidate view. Missing heads
// are below every persisted floor; an equal-version candidate must reproduce the
// pinned root exactly. Keep this predicate shared by the pre-boot cache gate, cache
// restore, snapshot restore, and live reads so no path can render what another path
// would quarantine.
function authorHeadPosition (view, pub) {
  const head = view && view[keys.head(pub)]
  const version = head && Number.isFinite(Number(head.version)) ? (head.version | 0) : -1
  const root = head && typeof head.root === 'string' ? head.root.toLowerCase() : ''
  return { head, version, root }
}

function violatesHeadFloor (view, pub, floor) {
  if (!floor || typeof floor.v !== 'number') return false
  const { version, root } = authorHeadPosition(view, pub)
  return version < (floor.v | 0) || (version === (floor.v | 0) && !!floor.root && root !== String(floor.root).toLowerCase())
}

// True when the persisted gossip view holds at least one row. "Empty cache is NO
// cache": a blob whose views were all emptied (a relay wipe answered 200-with-
// empty-rows under builds predating _saveCache's rowCount guard) must not count as
// a usable cached view. This helper is intentionally shape/floor-only; async
// `_loadCache` performs the cryptographic admission that a sync helper cannot.
export function cachedViewHasRows (storage) {
  try {
    const raw = storage && storage.getItem(CACHE_KEY)
    if (!raw) return false
    const c = JSON.parse(raw)
    const views = (c && typeof c === 'object' && c.views && typeof c.views === 'object') ? c.views : {}
    // Count ONLY rows _loadCache can actually RESTORE: views whose pub appears in
    // the cached peers list (same admission test as _loadCache). _saveCache
    // persists the SELF view but excludes self from `peers`, so a cache holding
    // only one's own rows would otherwise report "has rows" while a later
    // identity-less boot (forget-on-device, lost IDB record) restores nothing —
    // suppressing the seed-snapshot floor and booting to a blank feed.
    const restorable = new Set()
    if (Array.isArray(c.peers)) {
      for (const p of c.peers) {
        if (p && HEX64.test(p.pub || '') && p.appId === p.pub && typeof p.inviteKey === 'string') restorable.add(p.pub)
      }
    }
    let floors = {}
    try {
      const parsed = JSON.parse(storage.getItem(FLOOR_KEY) || '{}')
      if (parsed && typeof parsed === 'object') floors = parsed
    } catch {}
    let hasRows = false
    for (const pub in views) {
      if (PROTO_KEYS.has(pub) || !restorable.has(pub)) continue
      const v = views[pub]
      if (!v || typeof v !== 'object') continue
      let nonEmpty = false
      for (const k in v) { if (!PROTO_KEYS.has(k)) { nonEmpty = true; break } }
      if (!nonEmpty) continue
      const f = floors[pub]
      const floor = f && typeof f.v === 'number'
        ? { v: f.v | 0, root: typeof f.root === 'string' && HEX64.test(f.root) ? f.root.toLowerCase() : '' }
        : null
      // Report the cache unusable if any rowful author violates its floor. The web
      // path always fetches the signed snapshot; this helper remains a synchronous
      // shape/floor diagnostic for callers and tests.
      if (violatesHeadFloor(v, pub, floor)) return false
      hasRows = true
    }
    return hasRows
  } catch { return false }
}
const MAX_FLOOR = 5000                  // cap tracked authors (drop lowest-version on overflow)
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
async function honored (type, val, semType) {
  if (!val || !val._sig) return verifyRecord(type, val, semType)
  const ck = JSON.stringify([val._sig, val._k || '', val._dk || '', val._ns || '', canonical(type, val)])
  if (_verdict.has(ck)) return _verdict.get(ck)
  const v = await verifyRecord(type, val, semType)
  if (v === 'ok') { // never cache 'bad' (cheap to recompute; avoids unbounded growth from rejected forgeries)
    if (_verdict.size >= VERDICT_CACHE_MAX) _verdict.delete(_verdict.keys().next().value) // bounded FIFO eviction
    _verdict.set(ck, v)
  }
  return v
}

async function admit (type, val, key, pub, secure, validate) {
  if (!val || typeof val !== 'object') return false
  // KEY BINDING — recompute the storage key from the record's OWN signed fields and
  // reject a mismatch (anti-eviction). v2 opaque rows (key `v2!<okey>`) recompute the
  // HMAC okey; the SEMANTIC type is the signed `_t` (the key is opaque). Legacy v1 rows
  // recompute the plaintext key. v2 records sign over canonical('v2', …) — a CONSTANT
  // wire type so the type never leaks in the key — so the signature is verified with
  // 'v2' while ownerOf / PoW / winner use the semantic type.
  const v2 = String(key).startsWith('v2!')
  if (v2) {
    if (!val._t || !val.sealed) return false
    // The graph-bearing fields (community, cid, targetCid, …) are SEALED, so recompute
    // the opaque okey from the DECRYPTED fields + the owner (_k, baked into the okey).
    // A record parked under a victim's okey fails here: its own (_k, fields) can't
    // reproduce that slot. LWW/sticky fields (createdAt/ts/deleted/slug) stay cleartext,
    // so only this anti-eviction check needs the read key.
    let f
    try { f = await unseal(val.sealed) } catch { return false }
    if (!f || typeof f !== 'object') return false
    const rec = { ...f, _t: val._t, author: val._k, creator: val._k, by: val._k, slug: val.slug != null ? val.slug : f.slug }
    if ((await expectedKeyV2(rec)) !== key) return false
    type = val._t // semantic type (blob / PoW below)
  } else if (!type || expectedKey(type, val) !== key) return false
  // Content-addressed blobs must self-certify (SHA-256(ct)===blobId): the blob! key
  // is not author-scoped, so without this a foreign validly-signed record could win
  // the LWW collision and suppress a boxed body. See blob-store.js verifyBlobRecord.
  if (type === TYPE.BLOB && !(await verifyBlobRecord(val))) return false
  const owner = v2 ? val._k : ownerOf(type, val) // v2: the owner IS the signer (baked into the okey)
  if (!owner) return false
  const v = await honored(v2 ? 'v2' : type, val, type) // sig covers canonical(wire type); owner-binding uses the semantic type
  if (secure) {
    if (v !== 'ok') return false // signature is the authority
  } else if (!(owner === pub && v !== 'bad')) return false // cooperative dev fallback only
  if (validate) {
    try {
      if (!(await validate(type, val))) return false // PoW keyed by the semantic type
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
  const ka = a.creator || a._k || '', kb = b.creator || b._k || '' // v2: owner is _k (no creator field)
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
      const type = typeForRow(key, val)
      if (!(await admit(type, val, key, pub, secure, validate))) continue
      if (type === 'community') {
        const slug = val.slug
        if (claimed[slug] && claimed[slug] !== (val.creator || val._k)) continue // sticky: name owned by another creator
      }
      const ex = out[key]
      if (!ex || winner(type, val, ex)) out[key] = val
    }
  }
  // Lock the resolved community owners so a later different-creator claim can't take them.
  for (const key in out) {
    if (typeForRow(key, out[key]) === 'community') { const s = out[key].slug; if (s && !claimed[s]) claimed[s] = out[key].creator || out[key]._k }
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
      const type = typeForRow(key, val)
      if (type === 'community') {
        const slug = val.slug
        if (claimed[slug] && claimed[slug] !== (val.creator || val._k)) continue // sticky: owned by another creator
      }
      const ex = out[key]
      if (!ex || winner(type, val, ex)) out[key] = val
    }
  }
  for (const key in out) {
    if (typeForRow(key, out[key]) === 'community') { const s = out[key].slug; if (s && !claimed[s]) claimed[s] = out[key].creator || out[key]._k }
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
    if (typeof globalThis.addEventListener === 'function') {
      globalThis.addEventListener('storage', (e) => {
        if (!e || !e.key) return
        if (e.key === PEERS_KEY || e.key.startsWith('peerit:outbox:')) {
          this._invalidate()
          this._emit()
        }
      })
    }
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
        if (await admit(typeForRow(k, iv), iv, k, m.pub, secure, this.validate)) admitted[k] = iv
      }
      // Re-read AFTER the awaits, then a single write — minimises the RMW window.
      const cur = this._outbox(m.pub)
      let changed = false
      for (const k in admitted) {
        const iv = admitted[k]
        if (!cur[k] || winner(typeForRow(k, iv), iv, cur[k])) { cur[k] = iv; changed = true }
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
  get viewEpoch () { return this._epoch }

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
  constructor ({ pear, getMe, identity, storage, validate = makeValidator(), pollMs = 4000, writeHead = false, readOnly = false, requireAtomicWrites = false, discover = true, seedOutboxes = [], instantBoot = false, seedSnapshot = null }) {
    this.mode = 'gossip-bridge'
    this.pear = pear
    // instantBoot: ready() returns after the LOCAL restore (cached view / verified
    // seed snapshot) and runs every network step in the background — so the web app
    // paints last-known content in milliseconds like a normal website, instead of
    // blocking first render on relay round-trips. Default OFF: the seeder and tests
    // rely on ready() meaning "network attempted". app.js turns it on for web boot.
    this._instantBoot = !!instantBoot
    // seedSnapshot: signed rows baked into the static bundle ({authors:[{pub,rows}]}).
    // Used when there is no cached view, or when the durable floor quarantines one
    // or more cached authors: every row passes the SAME admit() verification as live
    // gossip (mergeOutboxes), so the snapshot can go stale but can never forge.
    this._seedSnapshot = seedSnapshot
    this.getMe = getMe
    this.identity = identity
    this.storage = storage
    // Fail-closed write gate: in read-only web mode NO outbox write (post, vote,
    // community, mod, …) may reach the relay. Guarding here (the single append
    // chokepoint) can't be bypassed by a UI handler that forgot an isReadOnly()
    // check, and it also prevents a stray head! append.
    this._readOnly = readOnly
    // Normal-browser writable releases must never silently downgrade to the
    // legacy record/head append sequence. PearBrowser retains that legacy/P2P
    // path; web writer mode sets this fail-closed requirement in app.js.
    this._requireAtomicWrites = !!requireAtomicWrites
    // When on, maintain a signed head!<me> record after each of my writes (the
    // outbox "merkle root": a census of my own records so a reader can detect a
    // relay withholding rows). Off by default so existing count-based tests are
    // untouched; app.js turns it on in production.
    this._writeHead = writeHead
    this._discover = discover // false = announce-only (findable, doesn't join others) — used by the write-only seeder
    // Pinned outboxes baked into the build (curated launch content). Joined directly at
    // boot so a fresh visitor renders them without waiting on flaky swarm discovery.
    this._seedOutboxes = (Array.isArray(seedOutboxes) ? seedOutboxes : []).filter(o => o && HEX64.test(o.appId || '') && HEX64.test(o.inviteKey || ''))
    this._listeners = new Set()
    this._peers = new Map() // pub -> { appId, inviteKey }
    this._cache = null            // current merged view (maintained incrementally)
    // Public, monotonically advancing source revision for consumers that cache
    // derived views. It also changes when a caller drives _refresh() directly
    // (without going through onChange), which is useful for embedders/tests.
    this.viewEpoch = 0
    this._peerViews = new Map()   // pub -> admitted {key:value} view (verified rows only)
    this._peerSigs = new Map()    // pub -> Map(key -> changeToken) seen last refresh
    this._peerHeads = new Map()   // pub -> last-seen outbox version (from /api/sync/heads)
    this._withholding = new Set()  // pubs whose replicated rows failed their signed-head audit (detection only)
    this._readFrom = new Map()     // pub -> relay base to read that outbox from (set on recovery so it sticks; cleared at reconcile)
    this._floor = new Map()        // pub -> {v:maxVersion, t:tick} DURABLE monotonic head floor (Phase C: rollback across restart + all-relays-collude)
    this._floorDirty = false
    this._floorTick = 0            // monotonic recency stamp for floor eviction (LRU, not version)
    this._claimed = null          // sticky community owners (slug -> creator), persisted
    this._refreshing = null       // in-flight refresh promise (serialises concurrent merges)
    this._forceReadPub = null     // explicit stable-state audit; bypasses transport-head gating once
    this._localWriteTransition = null // narrowly-scoped record -> signed-head two-append window
    this._unconfirmedLocalHead = null // final audit must quarantine a headless/partial local publication
    this._unconfirmedRecordAppend = null // ambiguous low-level record ACK; blocks writes until a signed head confirms it
    this._pendingCommit = null // persisted atomic HTTP commit awaiting quorum
    this._retryingPending = null // single-flight boot/wake retry of that exact commit
    this._pendingRetryAt = 0
    this._pendingRetryDelay = PENDING_RETRY_MIN_MS
    this._pendingRecoveryNeeded = false
    this._activeAtomicWriterSessions = new WeakSet()
    this._appendTail = Promise.resolve() // serialize local record/head pairs
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
  _atomicCommitEnabled () {
    if (this._requireAtomicWrites && (!this.pear || this.pear._atomicCommit !== true)) return false
    return !!(this.pear && this.pear.sync && typeof this.pear.sync.commit === 'function' && this.identity)
  }

  _loadPendingCommit () {
    const store = this._store()
    if (!store || typeof store.getItem !== 'function') {
      // Legacy PearBrowser/P2P transports historically run without localStorage
      // and do not use the HTTP atomic marker at all. Preserve that compatibility;
      // an atomic-capable writer still fails closed because safe response-loss
      // recovery is impossible without durable marker storage.
      if (!this._requireAtomicWrites && !this._atomicCommitEnabled()) {
        this._pendingCommit = null
        this._pendingRecoveryNeeded = false
        return null
      }
      this._pendingCommit = { invalid: true, unreadable: true }
      return this._pendingCommit
    }
    try {
      const raw = store.getItem(PENDING_COMMIT_KEY)
      if (!raw) {
        this._pendingCommit = null
        this._pendingRecoveryNeeded = false
        this._pendingRetryAt = 0
        this._pendingRetryDelay = PENDING_RETRY_MIN_MS
        return null
      }
      const pending = JSON.parse(raw)
      if (!pending || pending.v !== 1 || !HEX64.test(pending.appId || '') || !pending.commit || pending.commit.schema !== 1 || !HEX64.test(pending.commit.commitId || '')) {
        // Never overwrite an unrecognized durable marker. It might be a newer
        // client schema or local corruption that needs operator recovery.
        this._pendingCommit = { invalid: true }
        return this._pendingCommit
      }
      const previousId = this._pendingCommit && this._pendingCommit.commit && this._pendingCommit.commit.commitId
      if (previousId !== pending.commit.commitId) {
        this._pendingRecoveryNeeded = false
        this._pendingRetryAt = 0
        this._pendingRetryDelay = PENDING_RETRY_MIN_MS
      }
      this._pendingCommit = pending
      // A pending commit is a writer state even if the in-memory identity has not
      // yet been restored from its encrypted vault. Its signed envelope is enough
      // to retry; never mint a replacement identity or allocate an empty outbox.
      this._peers.set(pending.appId, { appId: pending.appId, inviteKey: pending.appId, self: true, dir: true })
      return pending
    } catch {
      // A read/parse failure is not evidence that the marker is absent. Preserve a
      // fail-closed sentinel so a transient storage fault can never authorize a
      // second publication over an unknown in-flight commit.
      this._pendingCommit = { invalid: true, unreadable: true }
      return this._pendingCommit
    }
  }

  _persistPendingCommit (pending) {
    const store = this._store()
    if (!store || typeof store.setItem !== 'function' || typeof store.getItem !== 'function') throw new Error('Cannot publish safely: durable pending-commit storage is unavailable.')
    const blob = JSON.stringify(pending)
    const existing = store.getItem(PENDING_COMMIT_KEY)
    if (existing) {
      let existingId = null
      try { existingId = JSON.parse(existing).commit.commitId } catch {}
      if (existingId !== pending.commit.commitId) throw new Error('Another tab already has a different pending Peerit commit; refusing to overwrite it.')
    }
    store.setItem(PENDING_COMMIT_KEY, blob)
    if (store.getItem(PENDING_COMMIT_KEY) !== blob) throw new Error('Cannot publish safely: the pending commit was not durably persisted.')
    this._pendingCommit = pending
  }

  _replacePendingCommit (previous, pending) {
    const store = this._store()
    if (!store || typeof store.setItem !== 'function' || typeof store.getItem !== 'function') throw new Error('Cannot rebase safely: durable pending-commit storage is unavailable.')
    const raw = store.getItem(PENDING_COMMIT_KEY)
    let storedId = null
    try { storedId = raw && JSON.parse(raw).commit.commitId } catch {}
    if (!previous || storedId !== previous.commit.commitId) throw new Error('Cannot rebase safely: another tab changed the pending Peerit commit.')
    const blob = JSON.stringify(pending)
    store.setItem(PENDING_COMMIT_KEY, blob)
    if (store.getItem(PENDING_COMMIT_KEY) !== blob) throw new Error('Cannot rebase safely: the replacement pending commit was not durably persisted.')
    this._pendingCommit = pending
    this._pendingRecoveryNeeded = false
    this._pendingRetryAt = 0
    this._pendingRetryDelay = PENDING_RETRY_MIN_MS
  }

  _pendingMarkerMatches (pending) {
    const store = this._store()
    if (!store || typeof store.getItem !== 'function' || !pending || !pending.commit) return false
    try {
      const raw = store.getItem(PENDING_COMMIT_KEY)
      return !!raw && JSON.parse(raw).commit.commitId === pending.commit.commitId
    } catch { return false }
  }

  _clearPendingCommit (pending) {
    const store = this._store()
    if (!store || typeof store.getItem !== 'function') throw new Error('Commit reached quorum, but local pending-commit storage is unavailable.')
    const raw = store.getItem(PENDING_COMMIT_KEY)
    let storedId = null
    try { storedId = raw && JSON.parse(raw).commit.commitId } catch {}
    if (!pending || storedId !== pending.commit.commitId) throw new Error('Commit reached quorum, but another tab owns or cleared the current pending marker; it was not cleared.')
    if (typeof store.removeItem === 'function') store.removeItem(PENDING_COMMIT_KEY)
    else if (typeof store.setItem === 'function') store.setItem(PENDING_COMMIT_KEY, '')
    if (typeof store.getItem === 'function' && store.getItem(PENDING_COMMIT_KEY)) throw new Error('Commit reached quorum, but its local pending marker could not be cleared.')
    this._pendingCommit = null
    this._pendingRecoveryNeeded = false
    this._pendingRetryAt = 0
    this._pendingRetryDelay = PENDING_RETRY_MIN_MS
  }

  async _withCrossTabLock (name, fn) {
    const locks = typeof navigator !== 'undefined' && navigator && navigator.locks
    if (locks && typeof locks.request === 'function') {
      // The pending marker is intentionally device-global, so the lock must be
      // global too: two tabs using different identities must not race separate
      // per-author locks and overwrite the same durable slot.
      return locks.request(name, { mode: 'exclusive' }, fn)
    }
    // A web page without Web Locks cannot make refresh→persist atomic across
    // tabs. Refuse explicitly instead of relying on a racy localStorage lease.
    // Node/test environments have no `window`; serialize instances in-realm.
    if (typeof window !== 'undefined') throw new Error('This browser cannot safely coordinate Peerit publishing across tabs (Web Locks unavailable).')
    const key = name
    const previous = ATOMIC_LOCKS.get(key) || Promise.resolve()
    let release
    const held = new Promise((resolve) => { release = resolve })
    const tail = previous.catch(() => {}).then(() => held)
    ATOMIC_LOCKS.set(key, tail)
    await previous.catch(() => {})
    try { return await fn() } finally {
      release()
      if (ATOMIC_LOCKS.get(key) === tail) ATOMIC_LOCKS.delete(key)
    }
  }

  async _withAtomicWriterLock (fn) {
    if (typeof fn !== 'function') throw new TypeError('Atomic writer session requires a function.')
    return this._withCrossTabLock('peerit:atomic-commit', async () => {
      // Reentrancy is an explicit unforgeable capability passed only to the same
      // Data write stack. An instance-global depth counter is unsafe: unrelated
      // async work (including poll retry) can observe it and enter concurrently.
      const session = Object.freeze({})
      this._activeAtomicWriterSessions.add(session)
      try { return await fn(session) } finally { this._activeAtomicWriterSessions.delete(session) }
    })
  }

  // Public lifecycle/write-intent hook. Identity import/forget and Data's
  // outermost write both use the same lock as pending-commit creation. Reload the
  // device-global marker only after acquiring it: no tab may replace an identity
  // while another tab has an ambiguous publication, and no writer can mint/sign
  // across an import or forget transition.
  withAtomicWriterSession (fn) {
    return this._withAtomicWriterLock(async (session) => {
      const pending = this._loadPendingCommit()
      if (pending || this._pendingRecoveryNeeded) {
        const error = new Error('Peerit identity/write state is locked while a publication is awaiting durable quorum recovery.')
        error.code = 'PEERIT_PENDING_WRITER_LOCK'
        throw error
      }
      return fn(session)
    })
  }

  // Narrow recovery escape hatch for a vault/device key that matches the author of
  // the ALREADY-SIGNED pending envelope. Ordinary withAtomicWriterSession remains
  // closed, so import/forget/arbitrary identity switches cannot cross a pending
  // publication. This callback may only activate the exact pending appId; while the
  // same cross-tab lock is held we retry/rebase that envelope before returning.
  recoverPendingWithIdentity (expectedAppId, activateMatchingIdentity) {
    if (!HEX64.test(String(expectedAppId || '')) || typeof activateMatchingIdentity !== 'function') {
      return Promise.reject(new Error('Pending publication recovery requires its exact writer identity.'))
    }
    expectedAppId = String(expectedAppId).toLowerCase()
    return this._withAtomicWriterLock(async () => {
      const pending = this._loadPendingCommit()
      if (!pending) return null // another tab completed it before this lock was acquired
      if (pending.invalid || !pending.commit) throw new Error('The durable Peerit pending marker is unreadable and cannot activate an identity automatically.')
      if (pending.appId !== expectedAppId) throw new Error('The available identity does not match the pending publication author.')
      await activateMatchingIdentity({ appId: pending.appId, commitId: pending.commit.commitId })
      if (this._myAppId() !== pending.appId) throw new Error('Pending publication recovery refused an identity that does not match its signed author.')
      if (!this._pendingMarkerMatches(pending)) throw new Error('The pending publication changed while its writer identity was being unlocked.')
      try {
        return await this._sendPendingCommitLocked(pending)
      } catch (error) {
        this._notePendingFailure(error)
        throw error
      }
    })
  }

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
      let rowCount = 0
      for (const [pub, info] of this._peers) { if (!info.self && HEX64.test(pub) && info.appId === pub && typeof info.inviteKey === 'string') peers.push({ pub, appId: info.appId, inviteKey: info.inviteKey }) }
      for (const [pub, view] of this._peerViews) { const o = {}; for (const k in view) { o[k] = view[k]; rowCount++ } views[pub] = o }
      for (const [pub, v] of this._peerHeads) heads[pub] = v
      // STALE-NEVER-EMPTY at the persistence layer: a relay restart/wipe answers
      // 200-with-empty-rows for outboxes it forgot, which empties the in-memory
      // views — persisting that would poison the cache (and, since the snapshot is
      // only used when there is NO cache, suppress the seed-snapshot floor on every
      // later boot). Keep the last non-empty view instead; the next reconcile that
      // actually returns rows overwrites it with fresher content.
      if (rowCount === 0) return
      const blob = JSON.stringify({ v: 1, peers, views, heads })
      if (blob.length > MAX_CACHE_BYTES) { this._setLocal(CACHE_KEY, ''); return } // too large → skip (graceful, just slower first paint)
      this._setLocal(CACHE_KEY, blob)
    } catch {}
  }

  // Restore the cached view BEFORE any network, so list()/get() return content on
  // the very first paint. The cache is untrusted local input: every row goes back
  // through mergeOutboxes -> admit (signature, key binding, blob integrity, PoW)
  // before it can render or capture a claim. Returns true if a view was restored.
  async _loadCache () {
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
      let restoredRows = 0
      const accepted = []
      if (c.views && typeof c.views === 'object') for (const pub in c.views) {
        if (PROTO_KEYS.has(pub) || !this._peers.has(pub)) continue
        const v = c.views[pub]; if (!v || typeof v !== 'object') continue
        const view = Object.create(null)
        let viewRows = 0
        for (const k in v) { if (PROTO_KEYS.has(k)) continue; view[k] = v[k]; viewRows++ }
        if (!viewRows) continue
        if (violatesHeadFloor(view, pub, this._floor.get(pub))) {
          // Keep peer metadata so the first live pass can recover it, but do not let
          // a stale cached author become visible or capture a sticky community name.
          this._withholding.add(pub)
          continue
        }
        // Verify one author at a time with an empty temporary claim map. Live
        // ingest stores every authentic row in that author's per-peer view even
        // when a sticky/global community winner hides it from the merged view;
        // cache restore must preserve the same census symmetry.
        const verified = await mergeOutboxes([{ pub, view }], {}, this.validate)
        const admitted = Object.create(null); const sig = new Map()
        for (const k in verified) { admitted[k] = verified[k]; sig.set(k, changeToken(verified[k])) }
        const admittedRows = Object.keys(admitted).length
        if (!admittedRows) continue

        // If an authentic cached head exists, require the re-admitted rows to
        // reproduce its exact census. A forged/tampered row removed above must not
        // leave a partial author view that still suppresses the seed fallback.
        const head = admitted[keys.head(pub)]
        if (head) {
          const rows = []; for (const k in admitted) rows.push({ key: k, value: admitted[k] })
          const audit = await auditOutbox(rows, head, pub)
          if (audit.hasHead && audit.matches === false) {
            this._withholding.add(pub)
            continue
          }
          // A fully re-admitted, census-matching cached head is durable evidence in
          // its own right. Ratchet before comparing the bundled snapshot so a newer
          // cache can never be downgraded by an older release baseline.
          const { version, root } = authorHeadPosition(admitted, pub)
          const floor = this._floor.get(pub)
          if (!floor || version > floor.v || (version === floor.v && !floor.root && root)) {
            this._floor.set(pub, { v: version, root, t: ++this._floorTick })
            this._floorDirty = true
          }
        }
        accepted.push({ pub, view: admitted, sig })
        restoredRows += admittedRows
      }
      // An empty cache is NO cache: a poisoned blob (all views emptied by a relay
      // wipe — written by builds that predate the rowCount guard in _saveCache)
      // must not count as "restored", or ready() skips the seed-snapshot floor and
      // the app renders an empty feed forever. Restored peers stay registered so
      // the first poll still re-reads them.
      if (restoredRows === 0) return false
      // Deliberately do NOT restore cached heads: the production relay is the
      // EPHEMERAL memory core whose per-outbox version resets to 0 on restart, so a
      // cached version could coincidentally match a different post-restart state and
      // suppress a real change. Leaving _peerHeads empty forces the first poll to
      // re-read (and thus re-validate) every cached peer against the live relay;
      // heads-gating then kicks in for subsequent polls.
      if (!this._claimed) { try { this._claimed = JSON.parse(this._getLocal(CLAIMED_KEY) || '{}') } catch { this._claimed = {} } }
      // Combine through a temporary claim map, then commit it only after every
      // floor-rejected author has already been removed from `accepted`.
      const nextClaimed = { ...this._claimed }
      if (accepted.length) {
        this._cache = combineAdmitted(accepted, nextClaimed)
        for (const { pub, view, sig } of accepted) { this._peerViews.set(pub, view); this._peerSigs.set(pub, sig) }
        this._claimed = nextClaimed
        if (this._floorDirty) await this._saveFloor()
        this._sortedFor = null
        return true
      }
      return false
    } catch { return false }
  }

  // Phase C durable head floor. UNLIKE cached heads (deliberately not restored,
  // see above), the floor IS restored across restart — it is the whole point: a
  // signed head's version is monotonic and author-controlled, so "I have durably
  // seen version N for this author" is a sound rollback baseline that a relay
  // (even the ephemeral memory core after a wipe, even all relays colluding)
  // cannot talk us below. Stores (v, root) so an equal-version fork is pinned too.
  _loadFloor () {
    try {
      const o = JSON.parse(this._getLocal(FLOOR_KEY) || '{}')
      if (!o || typeof o !== 'object') return
      for (const pub in o) {
        if (PROTO_KEYS.has(pub) || !HEX64.test(pub)) continue
        const e = o[pub]; if (!e || typeof e.v !== 'number') continue
        const t = typeof e.t === 'number' ? e.t : 0
        const root = typeof e.root === 'string' && HEX64.test(e.root) ? e.root.toLowerCase() : ''
        this._floor.set(pub, { v: e.v | 0, root, t })
        if (t > this._floorTick) this._floorTick = t
      }
    } catch {}
  }

  async _saveFloor ({ required = false, requiredHead = null } = {}) {
    const persist = async () => {
      const store = this._store()
      if (!store || typeof store.getItem !== 'function' || typeof store.setItem !== 'function') throw new Error('head-floor storage unavailable')
      let disk = {}
      const raw = store.getItem(FLOOR_KEY)
      if (raw) {
        disk = JSON.parse(raw)
        if (!disk || typeof disk !== 'object' || Array.isArray(disk)) throw new Error('head-floor storage is corrupt')
      }

      const merged = new Map()
      const add = (pub, value) => {
        if (PROTO_KEYS.has(pub) || !HEX64.test(pub) || !value || !Number.isInteger(Number(value.v)) || Number(value.v) < 0) return
        const next = {
          v: Number(value.v),
          root: typeof value.root === 'string' && HEX64.test(value.root) ? value.root.toLowerCase() : '',
          t: Number.isFinite(Number(value.t)) ? Number(value.t) : 0
        }
        // A different tab may have advanced the recency clock since this instance
        // loaded. Merge that clock before allocating a required publication tick so
        // the new floor cannot look older and become the first entry evicted.
        if (next.t > this._floorTick) this._floorTick = next.t
        const prior = merged.get(pub)
        if (!prior || next.v > prior.v) { merged.set(pub, next); return }
        if (next.v < prior.v) return
        if (prior.root && next.root && prior.root !== next.root) throw new Error('equal-version signed head fork for ' + pub)
        merged.set(pub, { v: prior.v, root: prior.root || next.root, t: Math.max(prior.t, next.t) })
      }
      for (const pub in disk) add(pub, disk[pub])
      for (const [pub, value] of this._floor) add(pub, value)
      if (requiredHead) {
        const pub = requiredHead.appId
        const next = { v: Number(requiredHead.version), root: String(requiredHead.root || '').toLowerCase(), t: ++this._floorTick }
        if (!HEX64.test(pub || '') || !Number.isInteger(next.v) || next.v < 0 || !HEX64.test(next.root)) throw new Error('invalid required head floor')
        add(pub, next)
      }

      let entries = [...merged.entries()]
      // Evict by RECENCY (tick), not author-controlled version — a Sybil minting a
      // high-version head must not be able to push a followed author out of the cap.
      if (entries.length > MAX_FLOOR) entries = entries.sort((a, b) => b[1].t - a[1].t).slice(0, MAX_FLOOR)
      const o = {}
      for (const [pub, e] of entries) o[pub] = { v: e.v, root: e.root || '', t: Math.trunc(e.t) }
      const blob = JSON.stringify(o)
      store.setItem(FLOOR_KEY, blob)
      if (store.getItem(FLOOR_KEY) !== blob) throw new Error('head-floor write did not survive read-back')
      if (requiredHead) {
        const saved = o[requiredHead.appId]
        if (!saved || saved.v !== Number(requiredHead.version) || saved.root !== String(requiredHead.root).toLowerCase()) throw new Error('required head floor was not persisted')
      }
      this._floor = new Map(entries)
      this._floorDirty = false
      return true
    }
    try {
      return await this._withCrossTabLock('peerit:head-floor', persist)
    } catch (error) {
      this._floorDirty = true
      if (required) throw error
      console.warn('[gossip] head-floor persist failed (rollback protection not durable this round):', error && error.message)
      return false
    }
  }

  // Phase D: seed the durable floor from the relay directory at boot. One call
  // returns every outbox's signed head (the pool merges to the highest verified
  // version across relays), so even a FRESH visitor has a rollback floor for every
  // author immediately — instead of accumulating floors as it browses. Every head
  // is re-verified here; the floor is only ever ratcheted UP, so a relay serving a
  // stale directory can't lower it. Offline-tolerant.
  async _bootstrapFloor () {
    const dirFn = this.pear.sync && this.pear.sync.directory
    if (!dirFn) return
    const me = this.getMe()
    // PAGINATE the directory: the relay caps each page (default 5000 heads) and returns a
    // cursor. Follow nextCursor until exhausted so author #5001+ is actually discovered —
    // otherwise a large forum silently truncates. Bounded (MAX_PAGES) so a hostile relay
    // can't spin us forever; the 429/503 backoff in pear-api paces us under the rate limit.
    // Degrades gracefully against an OLD relay that ignores `after` + omits hasMore (one page).
    const PAGE = 2000, MAX_PAGES = 50
    let after = null
    for (let page = 0; page < MAX_PAGES; page++) {
      let dir
      try { dir = await dirFn({ limit: PAGE, after }) } catch { break }
      const heads = dir && dir.heads ? dir.heads : dir
      if (!heads || typeof heads !== 'object') break
      for (const appId in heads) {
        if (PROTO_KEYS.has(appId) || !HEX64.test(appId) || appId === me) continue
        const h = heads[appId]
        if (!h || h._k !== appId) continue
        if ((await verifyRecord(TYPE.HEAD, h)) !== 'ok') continue // never seed the floor from an unverified head
        const v = h.version | 0
        const root = typeof h.root === 'string' && HEX64.test(h.root) ? h.root.toLowerCase() : ''
        const fl = this._floor.get(appId)
        if (!fl || v > fl.v || (v === fl.v && !fl.root && root)) { this._floor.set(appId, { v, root, t: ++this._floorTick }); this._floorDirty = true }
        // RELIABLE READ DISCOVERY: the relay serves any outbox's rows by appId (range takes
        // no inviteKey — the drive read-cap only gates P2P replication, which the relay does
        // on our behalf). A VERIFIED directory head is therefore enough to READ that author's
        // content directly, without waiting on flaky swarm-descriptor gossip. Add as a content
        // peer (inviteKey unused for relay reads; admit re-verifies every row's signature, so a
        // lying relay still can't forge). Directory is a relay-only surface, so this never runs
        // under PearBrowser's P2P sync (which needs the real read-cap). Skip empties + self.
        if (this._discover && (h.count | 0) > 0 && !this._peers.has(appId) && this._peers.size < MAX_PEERS) {
          this._peers.set(appId, { appId, inviteKey: appId, dir: true }) // inviteKey placeholder: relay range is keyed by appId
        }
      }
      if (!dir.hasMore || !dir.nextCursor || this._peers.size >= MAX_PEERS) break
      after = dir.nextCursor
    }
    if (this._floorDirty) await this._saveFloor()
  }

  async _openMyOutbox () {
    const appId = this._myAppId()
    // Defensive: callers gate on identity presence (_ensureMyOutbox), but creating
    // a relay group keyed "null" would mint exactly the ghost outbox the lazy
    // lurker tier exists to prevent — fail loudly if a new call path slips through.
    if (!appId) throw new Error('no writer identity yet')
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
    // Read-only is a transport capability boundary, not merely an append UI gate.
    // An existing identity must not cause boot, wake, poll, or announce to create a
    // writable relay group. Those paths all converge here; reads/discovery continue.
    if (this._readOnly) return false
    const appId = this._myAppId()
    // Lurker (lazy web identity, pre-first-write): no identity → no outbox to
    // open. Quiet false, NOT a warning — this is the designed steady state for
    // readers. The first write mints an identity and the very next call (append
    // does one inline) opens the outbox.
    if (!appId) return false
    if (this._requireAtomicWrites && !this._atomicCommitEnabled()) return false
    // Atomic HTTP relays allocate writer state only inside the first valid,
    // owner-signed commit. Register the public appId as a read/self placeholder,
    // but make ZERO unsigned create/join calls. A durable quorum receipt later
    // supplies the invite key (or appId remains the public read handle).
    if (this._atomicCommitEnabled()) {
      if (!this._peers.has(appId)) this._peers.set(appId, { appId, inviteKey: appId, self: true, dir: true })
      return true
    }
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
    // Skipped for lurkers (lazy web identity, me() === null): a null appId in
    // _peers would ride into the heads-poll payload and the persisted peer cache.
    const appId = this._myAppId()
    if (appId) {
      const myKey = this._getOutboxKey(appId)
      this._peers.set(appId, { appId, inviteKey: myKey || null, self: true })
      if (HEX64.test(myKey || '')) this._rememberOutbox(appId, myKey)
    }
    // Load the durable monotonic floor BEFORE accepting any cache/snapshot rows.
    // A previously observed newer head must be able to reject an older bundled
    // snapshot just as it rejects an older relay response.
    this._loadFloor()
    this._loadPendingCommit()
    // Restore last session's view after full re-admission so the first list()/get()
    // paints authenticated content; the poll later reconciles against live relays.
    await this._loadCache()
    // The signed bundle is also a recovery baseline for returning clients. Always
    // compare it with the verified cache: a newer bundled head repairs a stale
    // cache, while a newer cache remains authoritative and is never downgraded.
    if (this._seedSnapshot) await this._loadSnapshot(this._seedSnapshot)
    if (this._instantBoot) {
      // Normal-website boot: paint from the local restore NOW; do every network
      // step in the background. Callers that need the network done (seeder,
      // tests) leave instantBoot off or await netReady()/wake().
      this._netReady = this._connectNet().catch((e) => { console.warn('[gossip] background connect failed (will retry on poll/wake):', e && e.message) })
      return this
    }
    await this._connectNet()
    return this
  }

  // Every network step of boot, extracted so instantBoot can run it in the
  // background and wake() can re-run the idempotent parts after a relay pool is
  // plugged in late. Each step is individually offline-tolerant.
  async _connectNet () {
    // Open (or create) the WRITABLE outbox so we can post. A network failure here
    // is non-fatal — reads + the cached render still work, and the poll retries.
    await this._ensureMyOutbox()
    // A crash/refresh after transmit but before receipt must replay the exact
    // persisted commitId and signatures. Read-only deployments deliberately keep
    // the marker without transmitting it; re-enabling writes resumes the retry.
    if (!this._readOnly) {
      try { await this._retryPendingCommit({ force: true }) } catch (e) { console.warn('[gossip] pending atomic commit still awaiting quorum:', e && e.message) }
    }
    // Re-join EVERY outbox we've ever owned, so a changed identity key can't
    // strand earlier posts. (Best-effort; offline-tolerant.) Gated on identity
    // PRESENCE only — never on pubkey match, because recovering outboxes owned
    // under a DIFFERENT prior key is this loop's whole purpose (PearBrowser can
    // hand back a new per-app key on reopen). Lurkers skip it: with no writer
    // identity there is nothing of "mine" to recover, and web devices from the
    // churn era carry long ghost lists that would burn one join each per boot.
    if (this.getMe()) {
      for (const o of this._knownOutboxes()) {
        if (this._peers.has(o.appId)) continue
        try { await this.pear.sync.join(o.appId, o.inviteKey); this._peers.set(o.appId, { appId: o.appId, inviteKey: o.inviteKey, self: true }) } catch {}
      }
    }
    // Pinned/seed outboxes (curated launch content baked into the build): join them as
    // regular CONTENT peers (NOT self) so a fresh visitor renders them immediately,
    // independent of the flaky swarm-descriptor discovery. Read-only capability; the
    // records still pass full signature/PoW admit like any other peer's.
    for (const o of this._seedOutboxes) {
      if (this._peers.has(o.appId) || o.appId === this.getMe()) continue
      try { await this.pear.sync.join(o.appId, o.inviteKey); this._peers.set(o.appId, { appId: o.appId, inviteKey: o.inviteKey }) } catch {}
    }
    await this._bootstrapFloor() // Phase D: seed the floor from the durable directory (fresh visitor gets a cross-relay floor immediately)
    try { console.log('[peerit persist] me=' + (this.getMe() || '').slice(0, 12) + ' outbox=' + (this._myInvite || '').slice(0, 12) + ' knownOutboxes=' + this._knownOutboxes().length + ' cachedPeers=' + this._peers.size) } catch {}
    try {
      if (!this._channel) {
        this._channel = await this.pear.swarm.v1.join(TOPIC, { server: true, client: true, appName: 'peerit', reason: 'Discover other peerit users' })
        // Send our descriptor only to the newly-connected peer (O(1)); never re-broadcast
        // to every peer on each 'peer' event — that is the O(N²) /api/swarm/send storm that
        // exhausts the browser socket pool and wedges cold-start boot.
        this._channel.on('peer', (peer) => { if (peer && typeof peer.send === 'function') this._announceTo(peer); else this._scheduleAnnounce() })
        this._channel.on('message', (peer, data) => this._onDescriptor(data))
        await this._announce()
      }
    } catch (e) { console.warn('[gossip] swarm unavailable:', e && e.message) }
    this._startPoll()
  }

  // Re-kick the idempotent connect steps after connectivity appears (app.js plugs
  // a live relay pool into a lazy facade, then calls wake()). Safe to call any
  // time: every step no-ops when already done and tolerates a dead relay.
  async wake () {
    try { if (this._netReady) await this._netReady } catch {}
    if (this._destroyed) return
    await this._ensureMyOutbox()
    if (!this._readOnly) {
      try { await this._retryPendingCommit({ force: true }) } catch (e) { console.warn('[gossip] pending atomic commit still awaiting quorum:', e && e.message) }
    }
    for (const o of this._seedOutboxes) {
      if (this._peers.has(o.appId) || o.appId === this.getMe()) continue
      try { await this.pear.sync.join(o.appId, o.inviteKey); this._peers.set(o.appId, { appId: o.appId, inviteKey: o.inviteKey }) } catch {}
    }
    try { await this._bootstrapFloor() } catch {}
    try {
      if (!this._channel) {
        this._channel = await this.pear.swarm.v1.join(TOPIC, { server: true, client: true, appName: 'peerit', reason: 'Discover other peerit users' })
        this._channel.on('peer', (peer) => { if (peer && typeof peer.send === 'function') this._announceTo(peer); else this._scheduleAnnounce() })
        this._channel.on('message', (peer, data) => this._onDescriptor(data))
        await this._announce()
      }
    } catch {}
    // Force the first post-connect refresh to be a FULL reconcile: ignore the
    // heads gate (a throttled/absent heads endpoint must not defer the catch-up)
    // and re-verify every cached row against the live relay.
    this._refreshCount = RECONCILE_EVERY - 1
    try { const changed = await this._refresh(); if (changed.length) this._emit(changed) } catch (e) { console.warn('[gossip wake]', e && e.message) }
  }

  // Verify + load the baked seed snapshot ({authors:[{pub, rows:[{key,value}]}]}).
  // Rows go through mergeOutboxes -> admit(): full signature/key-binding/PoW checks,
  // exactly like live gossip — the snapshot is a render floor, never a trust bypass.
  async _loadSnapshot (snap) {
    try {
      const authors = (snap && Array.isArray(snap.authors)) ? snap.authors : []
      const boxes = []
      for (const a of authors) {
        if (!a || !HEX64.test(a.pub || '') || !Array.isArray(a.rows)) continue
        const view = Object.create(null)
        for (const r of a.rows) { if (r && typeof r.key === 'string' && !PROTO_KEYS.has(r.key) && r.value) view[r.key] = r.value }
        boxes.push({ pub: a.pub, view })
      }
      if (!boxes.length) return false
      if (!this._claimed) { try { this._claimed = JSON.parse(this._getLocal(CLAIMED_KEY) || '{}') } catch { this._claimed = {} } }
      // Re-admit and compare each author independently. This preserves the exact
      // author census (global sticky-community winners are applied only after the
      // winning per-author version is selected) and prevents a rejected snapshot
      // candidate from capturing a claim.
      for (const { pub, view } of boxes) {
        if (!this._peers.has(pub) && this._peers.size < MAX_PEERS) this._peers.set(pub, { appId: pub, inviteKey: pub, dir: true })
        const verified = await mergeOutboxes([{ pub, view }], {}, this.validate)
        const admitted = Object.create(null); const sig = new Map()
        for (const k in verified) { admitted[k] = verified[k]; sig.set(k, changeToken(verified[k])) }
        if (!Object.keys(admitted).length) continue

        const existing = this._peerViews.get(pub) || null
        const candidate = authorHeadPosition(admitted, pub)
        const current = authorHeadPosition(existing, pub)

        // A headed snapshot must be internally complete before it participates in
        // version selection. Headless legacy snapshots remain row-by-row compatible.
        if (candidate.head) {
          const rows = []; for (const k in admitted) rows.push({ key: k, value: admitted[k] })
          const audit = await auditOutbox(rows, candidate.head, pub)
          if (audit.hasHead && audit.matches === false) {
            if (!existing) this._withholding.add(pub)
            continue
          }
        }

        if (existing) {
          if (current.head && candidate.head) {
            // Same version with different roots is an author-signed fork. Neither
            // local source may win by arrival order: quarantine until live recovery
            // reproduces the durable floor.
            if (candidate.version === current.version && candidate.root !== current.root) {
              this._peerViews.delete(pub)
              this._peerSigs.delete(pub)
              this._withholding.add(pub)
              continue
            }
            if (candidate.version <= current.version) continue // same root or older snapshot: never downgrade
          } else if (current.head && !candidate.head) continue // auditable cache beats a headless snapshot
          else if (!current.head && !candidate.head) continue // no ordering proof: retain the returning client's cache
          // candidate.head && !current.head falls through: prefer the auditable snapshot
        }

        const floor = this._floor.get(pub)
        if (violatesHeadFloor(admitted, pub, floor)) {
          if (!existing) this._withholding.add(pub)
          continue
        }
        if (candidate.head && (!floor || candidate.version > floor.v || (candidate.version === floor.v && !floor.root && candidate.root))) {
          this._floor.set(pub, { v: candidate.version, root: candidate.root, t: ++this._floorTick })
          this._floorDirty = true
        }
        this._peerViews.set(pub, admitted)
        this._peerSigs.set(pub, sig)
        this._withholding.delete(pub)
      }
      if (this._floorDirty) await this._saveFloor()
      // Apply global winners/claims only after every author has been authenticated,
      // audited, and monotonically selected.
      const allAccepted = []
      for (const [pub, view] of this._peerViews) allAccepted.push({ pub, view })
      this._cache = combineAdmitted(allAccepted, this._claimed)
      if (!Object.keys(this._cache).length) { this._cache = null; return false }
      this._sortedFor = null
      console.log('[gossip] reconciled ' + Object.keys(this._cache).length + ' verified rows with the signed seed snapshot')
      return true
    } catch (e) { console.warn('[gossip] seed snapshot rejected:', e && e.message); return false }
  }

  _startPoll () {
    if (this._pollStarted || this._destroyed) return
    this._pollStarted = true
    if (this._pollMs > 0) {
      // Re-merge incrementally and notify ONLY when a peer's rows actually
      // changed. Self-scheduling with ±15% jitter so many clients don't hit the
      // relay in lockstep; each tick is now a single cheap heads call plus reads
      // of only the outboxes that moved.
      const jittered = () => this._pollMs * (0.85 + Math.random() * 0.3)
      const tick = async () => {
        if (this._destroyed) return
        if (!this._myInvite) { try { if (await this._ensureMyOutbox()) await this._announce() } catch {} } // relay came back → resume writing/discovery
        // Periodically re-scan the directory so authors who first post AFTER we booted get
        // discovered (adds them to _peers; the next refresh reads their content by appId).
        try { if ((this._refreshCount % 5) === 0) await this._bootstrapFloor() } catch {}
        try { const changed = await this._refresh(); if (changed.length) this._emit(changed) } catch (e) { console.warn('[gossip poll]', e && e.message) }
        try { await this._maybeRetryPendingCommit() } catch (e) { console.warn('[gossip] pending atomic commit retry deferred:', e && e.message) }
        if (this._destroyed) return
        this._pollTimer = setTimeout(tick, jittered())
        if (this._pollTimer && this._pollTimer.unref) this._pollTimer.unref()
      }
      this._pollTimer = setTimeout(tick, jittered())
      if (this._pollTimer && this._pollTimer.unref) this._pollTimer.unref()
    }
  }

  // Tear down timers, the swarm channel, and listeners. Call on tab/SPA teardown
  // so a navigated-away page doesn't leak an EventSource + interval.
  destroy () {
    this._destroyed = true
    if (this._poll) { clearInterval(this._poll); this._poll = null }
    if (this._pollTimer) { clearTimeout(this._pollTimer); this._pollTimer = null }
    if (this._refreshScheduled) { clearTimeout(this._refreshScheduled); this._refreshScheduled = null }
    if (this._announceScheduled) { clearTimeout(this._announceScheduled); this._announceScheduled = null }
    if (this._channel && this._channel.destroy) { try { this._channel.destroy() } catch {} }
    if (this._refreshing) this._refreshing.catch(() => {}) // don't leave the in-flight refresh's rejection unhandled
    this._channel = null
    this._listeners.clear()
  }

  // Build our signed outbox descriptor once, reused by broadcast + per-peer sends.
  async _descBytes () {
    if (!this._channel) return null
    const pub = this.getMe(), appId = this._myAppId(), inviteKey = this._myInvite
    // LURKERS ARE SILENT: no identity (lazy web mode, pre-first-write) or no open
    // outbox → there is nothing announceable. Returning null here no-ops EVERY
    // announce path at once (_announce, _announceTo, scheduled + post-refresh
    // announces) — a null descriptor would be rejected by receivers anyway, but
    // sending it still burns one /api/swarm/send per replayed peer against the
    // relay's per-IP budget.
    if (!pub || !inviteKey) return null
    let sig = null
    try { sig = await this.identity.sign(`peerit-desc|${pub}|${appId}|${inviteKey}`) } catch {}
    const desc = JSON.stringify({ t: 'outbox-desc', pub, appId, inviteKey, sig: sig && sig.signature, dk: sig && sig.driveKey, ns: sig && sig.namespace })
    return new TextEncoder().encode(desc)
  }

  // Broadcast our descriptor to every current peer (used at boot / after our outbox
  // opens / on re-announce). One send per peer — O(N), not the O(N²) of re-broadcasting
  // on every peer connection.
  async _announce () {
    const bytes = await this._descBytes()
    if (!bytes || !this._channel) return
    for (const p of this._channel.peers) { try { p.send(bytes) } catch {} }
  }

  // Send our descriptor to a single newly-connected peer — the ONLY peer that needs it.
  // The relay replays every remembered peer on join, so re-broadcasting to all peers on
  // each 'peer' event is O(N²) /api/swarm/send POSTs that exhaust the browser socket pool
  // (net::ERR_INSUFFICIENT_RESOURCES) and wedge boot into "no relay reachable".
  async _announceTo (peer) {
    const bytes = await this._descBytes()
    if (bytes) { try { peer.send(bytes) } catch {} }
  }

  // Coalesce a burst of peer connections into ONE broadcast (fallback when the swarm
  // 'peer' event doesn't hand us the peer to target directly).
  _scheduleAnnounce () {
    if (this._announceScheduled || this._destroyed) return
    this._announceScheduled = setTimeout(() => { this._announceScheduled = null; this._announce().catch(() => {}) }, 500)
    if (this._announceScheduled && this._announceScheduled.unref) this._announceScheduled.unref()
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
    if (!this._discover) return // announce-only client (e.g. the seeder): stays findable, but never joins others
    if (this._peers.size >= MAX_PEERS) return
    if (!HEX64.test(d.pub) || !HEX64.test(d.appId) || d.appId !== d.pub) return // appId must be the pubkey itself
    if (typeof d.inviteKey !== 'string' || d.inviteKey.length < 16 || d.inviteKey.length > 4096) return
    if (d.ns !== 'peerit' || !HEX128.test(d.sig || '') || !HEX64.test(d.dk || '')) return
    // The descriptor (pub, appId, inviteKey) must be signed by `pub`, binding the
    // invite key to the identity — a peer can't redirect a victim's pub to a
    // Hyperbee it controls.
    const ok = await edVerify(d.pub, `pear.app.${d.dk}:peerit:peerit-desc|${d.pub}|${d.appId}|${d.inviteKey}`, d.sig).catch(() => false)
    if (!ok) return
    if (this._peers.has(d.pub) || (this._joinSeen && this._joinSeen.has(d.pub))) return
    // The relay replays EVERY remembered descriptor when we join the topic, so a boot
    // can surface dozens at once. Joining them all immediately hammers the relay's
    // per-IP rate limit (and can fetch-fail a small relay). Enqueue + drain them at a
    // throttled rate, then refresh ONCE for the whole burst.
    ;(this._joinSeen || (this._joinSeen = new Set())).add(d.pub)
    ;(this._joinQueue || (this._joinQueue = [])).push(d)
    this._pumpJoins()
  }

  async _pumpJoins () {
    if (this._joinPumping || this._destroyed) return
    this._joinPumping = true
    try {
      while (this._joinQueue && this._joinQueue.length && !this._destroyed) {
        const d = this._joinQueue.shift()
        if (this._peers.has(d.pub) || this._peers.size >= MAX_PEERS) continue
        try {
          await this.pear.sync.join(d.appId, d.inviteKey)
          this._peers.set(d.pub, { appId: d.appId, inviteKey: d.inviteKey })
        } catch { /* transient (rate limit / fetch) — the poll re-discovers later */ }
        await new Promise((r) => setTimeout(r, 280)) // ~3.5 joins/s — comfortably under the per-IP limit
      }
    } finally {
      this._joinPumping = false
      this._scheduleRefresh() // one coalesced refresh once the burst drains
    }
  }

  // Debounced re-merge — many descriptors arriving in a boot burst collapse into a
  // single refresh + emit, keeping the client well under the relay's per-IP rate limit.
  _scheduleRefresh () {
    if (this._refreshScheduled || this._destroyed) return
    this._refreshScheduled = setTimeout(async () => {
      this._refreshScheduled = null
      if (this._destroyed) return
      try { const changed = await this._refresh(); if (changed.length) this._emit(changed) } catch (e) { console.warn('[gossip refresh]', e && e.message) }
      try { await this._announce() } catch {}
    }, 700)
    if (this._refreshScheduled && this._refreshScheduled.unref) this._refreshScheduled.unref()
  }

  async announce () {
    if (!await this._ensureMyOutbox()) return
    return this._announce()
  }

  append (op, writerSession = null) {
    // Required-atomic web mode has no legal standalone head operation: the head
    // must be derived and committed in the same transaction as one or more
    // owner-signed mutations. Reject before any legacy endpoint can be touched.
    if (this._requireAtomicWrites) {
      if (!op || op.type === TYPE.HEAD) return Promise.reject(new Error('Peerit web publishing rejects standalone heads and legacy append fallthrough.'))
      return this.appendBatch([op], writerSession)
    }
    if (this._atomicCommitEnabled() && op && op.type !== TYPE.HEAD) return this._appendAtomic([op], writerSession)
    const run = () => this._appendOne(op)
    // A record and the signed head that commits it are one local integrity
    // transition. Serialize those pairs so concurrent UI writes cannot derive two
    // heads from the same prior version.
    if (this._writeHead && this.identity && op && op.type !== TYPE.HEAD) {
      const queued = this._appendTail.then(run, run)
      this._appendTail = queued.then(() => undefined, () => undefined)
      return queued
    }
    return run()
  }

  appendBatch (ops, writerSession = null) {
    if (!Array.isArray(ops) || !ops.length) return Promise.reject(new Error('Peerit publication batch must contain at least one mutation.'))
    const list = ops.slice()
    if (list.some(op => !op || typeof op.type !== 'string' || op.type === TYPE.HEAD)) {
      return Promise.reject(new Error('Peerit publication batches accept owner mutations only; the signed head is derived atomically.'))
    }
    if (!this._atomicCommitEnabled()) {
      if (this._requireAtomicWrites) return Promise.reject(new Error('Peerit web publishing requires two relays advertising durable atomic commits; the current relay pool is read-only.'))
      // Compatibility for legacy/PearBrowser transports: preserve the historical
      // sequential record+head behavior when atomic commit is not advertised.
      return list.reduce((tail, op) => tail.then(() => this.append(op)), Promise.resolve()).then(() => ({ ok: true, sequential: true }))
    }
    // The atomic writer lock itself serializes refresh→sign→persist→quorum. Do
    // not put this behind _appendTail: a Data stack already holding the writer
    // lock could otherwise wait on a direct append that is queued waiting for
    // that same lock.
    return this._appendAtomic(list, writerSession)
  }

  async _appendOne (op) {
    if (this._readOnly) throw new Error('This peerit is read-only.')
    if (this._pendingCommit) throw new Error('A previous Peerit publication is still awaiting two durable relay receipts. No later writes are allowed until it reaches quorum or is reconciled.')
    if (this._requireAtomicWrites) throw new Error('Peerit web publishing refuses every legacy append path.')
    if (!await this._ensureMyOutbox()) throw new Error('Peerit outbox is unavailable; check relay connectivity and try again.')
    const me = this._myAppId()
    const maintainsHead = this._writeHead && this.identity && op.type !== TYPE.HEAD

    if (maintainsHead) {
      // Stable-state preflight: force a fresh self read and census audit even when
      // `/heads` claims nothing changed. A replayed old self-signed row must be
      // detected BEFORE this client can sign a new head over it.
      await this._refreshPeerNow(me)
    }
    if (this._withholding.has(me) || (this._unconfirmedRecordAppend && this._unconfirmedRecordAppend.pub === me)) throw new Error('Peerit outbox integrity check failed; refusing to append until the relay recovers the newer signed state.')

    let r
    let recordError = null
    let headError = null
    const recordKey = op.type.replace(':', '!') + '!' + op.data.id
    const transition = maintainsHead ? { pub: me, key: recordKey } : null
    if (transition) {
      // While the relay has accepted the record but not its new head, background
      // polls retain the last audited self view. The producer computes the new
      // census from that trusted view plus this exact local op; no relay candidate
      // is trusted during the two-append window.
      this._localWriteTransition = transition
    }
    try {
      try { r = await this.pear.sync.append(me, { type: op.type, data: op.data, timestamp: new Date().toISOString() }) } catch (error) { recordError = error }
      // Never derive or append a confirming head after an ambiguous record error:
      // the relay may have committed the row before losing the response.
      if (!recordError && maintainsHead) { try { await this._maintainHead(op) } catch (e) { headError = e } }
    } finally {
      if (transition && this._localWriteTransition === transition) this._localWriteTransition = null
    }

    if (recordError) {
      this._unconfirmedRecordAppend = { pub: me, key: recordKey, token: changeToken(op.data) }
      this._withholding.add(me)
    }
    // A record without its confirming head is an unconfirmed partial publication.
    // Quarantine before the stable audit so even a first-ever (headless) write
    // cannot look healthy after both bounded head attempts fail.
    if (headError) { this._withholding.add(me); this._unconfirmedLocalHead = me }
    // Audit the now-stable record+head pair. This is forced past transport-head
    // gating and cannot coalesce into a refresh that began before the head append.
    let changed = []
    try { changed = (maintainsHead || recordError) ? await this._refreshPeerNow(me) : await this._refresh() } catch (error) {
      // If the write itself was ambiguous, preserve that explicit failure instead
      // of replacing it with a secondary reconciliation/network error.
      if (!recordError && !headError) throw error
      console.warn('[gossip] post-write integrity reconciliation failed:', error && error.message)
      changed = [SYNC_INTEGRITY_STATUS_KEY]
    } finally {
      if (this._unconfirmedLocalHead === me) this._unconfirmedLocalHead = null
    }
    const unconfirmedHead = !!headError && this._withholding.has(me)
    if (unconfirmedHead) console.warn('[gossip] head confirmation failed:', headError && headError.message)
    // head! keys are inert to the UI; strip them so a write's change-set doesn't
    // defeat the vote fast-paths (cacheClassForChangedKeys / patchVotesInPlace).
    this._emit(changed.filter((k) => typeFromKey(k) !== TYPE.HEAD))
    if (recordError) {
      const unconfirmed = new Error('Peerit publication is unconfirmed: the relay did not acknowledge the record append, so it may have committed without a confirming signed head. No further writes are allowed until integrity recovers.')
      unconfirmed.cause = recordError
      throw unconfirmed
    }
    if (unconfirmedHead) {
      const unconfirmed = new Error('Peerit publication is unconfirmed: the record reached the relay, but its signed outbox head could not be confirmed. No further writes are allowed until integrity recovers.')
      unconfirmed.cause = headError
      throw unconfirmed
    }
    return r
  }

  async _buildAtomicCommit (ops) {
    const appId = this._myAppId()
    if (!HEX64.test(appId || '')) throw new Error('Cannot publish without a valid writer identity.')
    if (!Array.isArray(ops) || !ops.length) throw new Error('Cannot publish an empty atomic mutation batch.')
    for (const op of ops) {
      if (!op || typeof op.type !== 'string' || op.type === TYPE.HEAD || !op.data || op.data._k !== appId || !HEX128.test(op.data._sig || '')) throw new Error('Cannot publish an unsigned, standalone-head, or cross-owner mutation.')
    }

    const current = Object.assign(Object.create(null), this._peerViews.get(appId) || {})
    const previousHead = current[keys.head(appId)]
    const expected = previousHead
      ? { version: previousHead.version | 0, root: String(previousHead.root || '').toLowerCase() }
      : { version: 0, root: await hashHex('') }
    if (!Number.isInteger(expected.version) || expected.version < 0 || !HEX64.test(expected.root)) throw new Error('Cannot derive a valid prior outbox head for atomic commit.')

    const now = Date.now()
    const timestamp = new Date(now).toISOString()
    const mutations = ops.map(op => ({ type: op.type, data: op.data, timestamp }))
    for (const mutation of mutations) applyOp(current, mutation)
    const rows = []
    for (const key in current) rows.push({ key, value: current[key] })
    const census = outboxCensus(rows, appId)
    const headData = {
      id: appId,
      author: appId,
      version: expected.version + 1,
      count: census.length,
      root: await hashHex(censusString(census)),
      updatedAt: now
    }
    const headSig = await this.identity.sign(canonical(TYPE.HEAD, headData))
    if (!headSig || headSig.publicKey !== appId || !HEX128.test(headSig.signature || '')) throw new Error('Cannot sign the next atomic outbox head with the active writer.')
    Object.assign(headData, { _sig: headSig.signature, _k: headSig.publicKey, _dk: headSig.driveKey, _ns: headSig.namespace, _alg: headSig.algorithm })
    const head = { type: TYPE.HEAD, data: headData, timestamp }

    const authFields = {
      appId,
      expectedVersion: expected.version,
      expectedRoot: expected.root,
      mutationSigs: mutations.map(mutation => mutation.data._sig),
      headSig: headData._sig,
      createdAt: now
    }
    // The id is a deterministic digest of every signed object referenced by the
    // authorization plus its CAS position. Retrying cannot derive a new id, and
    // changing any mutation/head signature necessarily changes it.
    const commitId = await hashHex(canonical('commit-id', authFields))
    const authorization = { id: commitId, ...authFields }
    const authSig = await this.identity.sign(canonical('commit', authorization))
    if (!authSig || authSig.publicKey !== appId || !HEX128.test(authSig.signature || '')) throw new Error('Cannot authorize the atomic commit with the active writer.')
    Object.assign(authorization, { _sig: authSig.signature, _k: authSig.publicKey, _dk: authSig.driveKey, _ns: authSig.namespace, _alg: authSig.algorithm })

    return {
      v: 1,
      appId,
      commit: { schema: 1, commitId, expected, mutations, head, authorization }
    }
  }

  async _validatePendingCommit (pending) {
    const commit = pending && pending.commit
    const auth = commit && commit.authorization
    const expected = commit && commit.expected
    const head = commit && commit.head
    const mutations = commit && commit.mutations
    if (!pending || pending.v !== 1 || !HEX64.test(pending.appId || '') || !commit || commit.schema !== 1 || !HEX64.test(commit.commitId || '')) return false
    if (!expected || !Number.isInteger(expected.version) || expected.version < 0 || !HEX64.test(expected.root || '')) return false
    if (!Array.isArray(mutations) || mutations.length < 1 || !head || head.type !== TYPE.HEAD || !head.data || !auth) return false
    const sigs = []
    for (const mutation of mutations) {
      if (!mutation || typeof mutation.type !== 'string' || !mutation.data || mutation.data._k !== pending.appId || !HEX128.test(mutation.data._sig || '')) return false
      const semType = mutation.type === 'v2' ? mutation.data._t : mutation.type
      if ((await verifyRecord(mutation.type, mutation.data, semType)) !== 'ok') return false
      sigs.push(mutation.data._sig)
    }
    const next = head.data
    if (next._k !== pending.appId || next.author !== pending.appId || next.version !== expected.version + 1 || !Number.isInteger(next.count) || next.count < 0 || !HEX64.test(next.root || '')) return false
    if ((await verifyRecord(TYPE.HEAD, next)) !== 'ok') return false
    if (auth.id !== commit.commitId || auth.appId !== pending.appId || auth.expectedVersion !== expected.version || auth.expectedRoot !== expected.root || auth.headSig !== next._sig) return false
    if (!Array.isArray(auth.mutationSigs) || JSON.stringify(auth.mutationSigs) !== JSON.stringify(sigs)) return false
    const authFields = {
      appId: auth.appId,
      expectedVersion: auth.expectedVersion,
      expectedRoot: auth.expectedRoot,
      mutationSigs: auth.mutationSigs,
      headSig: auth.headSig,
      createdAt: auth.createdAt
    }
    if ((await hashHex(canonical('commit-id', authFields))) !== commit.commitId) return false
    if (auth._k !== pending.appId || auth._ns !== 'peerit' || !HEX64.test(auth._dk || '') || !HEX128.test(auth._sig || '')) return false
    return edVerify(auth._k, `pear.app.${auth._dk}:peerit:` + canonical('commit', auth), auth._sig)
  }

  _receiptMatchesPending (receipt, pending) {
    const expectedHead = pending && pending.commit && pending.commit.head && pending.commit.head.data
    const head = receipt && receipt.head
    const topMatches = !!(
      receipt && receipt.ok === true && receipt.durable === true &&
      receipt.commitId === pending.commit.commitId && receipt.appId === pending.appId &&
      head && expectedHead && Number(head.version) === Number(expectedHead.version) &&
      Number(head.count) === Number(expectedHead.count) &&
      String(head.root || '').toLowerCase() === String(expectedHead.root || '').toLowerCase()
    )
    if (!topMatches || Number(receipt.quorum) < 2 || !Array.isArray(receipt.receipts)) return false
    const origins = new Set()
    for (const evidence of receipt.receipts) {
      const evidenceHead = evidence && evidence.head
      if (!(
        evidence && evidence.ok === true && evidence.durable === true &&
        evidence.commitId === pending.commit.commitId && evidence.appId === pending.appId &&
        evidenceHead && Number(evidenceHead.version) === Number(expectedHead.version) &&
        Number(evidenceHead.count) === Number(expectedHead.count) &&
        String(evidenceHead.root || '').toLowerCase() === String(expectedHead.root || '').toLowerCase()
      )) return false
      let origin = ''
      try { origin = new URL(String(evidence.origin || '')).origin } catch { return false }
      if (origin !== evidence.origin) return false
      origins.add(origin)
    }
    return origins.size >= 2 && origins.size >= Number(receipt.quorum)
  }

  async _adoptAtomicCommit (pending, receipt) {
    if (!this._pendingMarkerMatches(pending)) throw new Error('A stale Peerit receipt arrived after the pending marker changed; refusing to adopt it.')
    const appId = pending.appId
    const nextHead = pending.commit.head.data
    // The durable floor is part of publication completion, not best-effort cache.
    // Persist it before clearing the retry envelope, and refuse an older/equal-fork
    // receipt even if another tab produced it with a once-valid commitId.
    await this._saveFloor({
      required: true,
      requiredHead: { appId, version: nextHead.version, root: nextHead.root }
    })
    const inviteKey = HEX64.test((receipt && receipt.inviteKey) || '') ? receipt.inviteKey : appId
    this._peers.set(appId, { appId, inviteKey, self: true, dir: inviteKey === appId })
    this._setOutboxKey(appId, inviteKey)
    this._rememberOutbox(appId, inviteKey)
    if (this._myAppId() === appId) { this._myInvite = inviteKey; this._myInviteAppId = appId }

    const view = Object.assign(Object.create(null), this._peerViews.get(appId) || {})
    for (const mutation of pending.commit.mutations) applyOp(view, mutation)
    applyOp(view, pending.commit.head)
    const sig = new Map()
    for (const key in view) sig.set(key, changeToken(view[key]))
    this._peerViews.set(appId, view)
    this._peerSigs.set(appId, sig)
    if (Number.isFinite(Number(receipt.relayVersion))) this._peerHeads.set(appId, Number(receipt.relayVersion))

    this._withholding.delete(appId)
    if (!this._claimed) { try { this._claimed = JSON.parse(this._getLocal(CLAIMED_KEY) || '{}') } catch { this._claimed = {} } }
    const boxes = []
    for (const [pub, admitted] of this._peerViews) boxes.push({ pub, view: admitted })
    const merged = combineAdmitted(boxes, this._claimed)
    const changed = diffViews(this._cache, merged)
    this._cache = merged
    this._sortedFor = null
    this._saveCache()
    return changed
  }

  _isStaleCommitError (error) {
    return !!(error && (error.stale || error.status === 409 || error.code === 'COMMIT_CAS_MISMATCH' || error.code === 'STALE_CAS'))
  }

  _pendingMutationState (pending) {
    const view = pending && this._peerViews.get(pending.appId)
    const mutations = pending && pending.commit && pending.commit.mutations
    if (!view || !Array.isArray(mutations)) return []
    return mutations.map((mutation, index) => {
      const key = mutation.type.replace(':', '!') + '!' + mutation.data.id
      const value = view[key]
      const exact = !!(value && value._sig === mutation.data._sig)
      const semType = value && typeForRow(key, value)
      const sameType = !!(value && semType && semType === (mutation.type === 'v2' ? mutation.data._t : mutation.type))
      const dominates = !!(!exact && sameType && winner(semType, value, mutation.data) && !winner(semType, mutation.data, value))
      return { index, key, value, exact, dominates }
    })
  }

  // Turn independently audited relay censuses into per-mutation durability
  // evidence. A mutation is resolved only when two distinct canonical roster
  // origins serve the SAME current signature at its exact key and that value is
  // either the pending record itself or strictly wins under the real reducer.
  // This lets a later edit/delete/vote supersede an ambiguous older intent without
  // ever rebasing the old record over it.
  async _pendingResolutionFromEvidence (pending, transportProof) {
    const none = { resolved: new Set(), resolutions: [], complete: false, proof: null }
    if (!transportProof || transportProof.appId !== pending.appId || transportProof.commitId !== pending.commit.commitId) return none
    const evidence = Array.isArray(transportProof.censusEvidence)
      ? transportProof.censusEvidence
      : (Array.isArray(transportProof.evidence) ? transportProof.evidence : [])
    if (new Set(evidence.map((item) => item && item.origin).filter(Boolean)).size < 2) return none

    const resolved = new Set()
    const resolutions = []
    const usedOrigins = new Set()
    const mutations = pending.commit.mutations
    for (let index = 0; index < mutations.length; index++) {
      const mutation = mutations[index]
      const key = mutation.type.replace(':', '!') + '!' + mutation.data.id
      const expectedType = mutation.type === 'v2' ? mutation.data._t : mutation.type
      const groups = new Map()
      for (const relayEvidence of evidence) {
        let origin = ''
        try { origin = new URL(String((relayEvidence && relayEvidence.origin) || '')).origin } catch { continue }
        if (origin !== relayEvidence.origin || !Array.isArray(relayEvidence.mutations)) continue
        const state = relayEvidence.mutations.find((item) => item && item.key === key)
        const value = state && state.value
        if (!state || state.expectedSignature !== mutation.data._sig || state.currentSignature !== (value && value._sig) || !value || value._k !== pending.appId) continue
        const semType = typeForRow(key, value)
        if (!semType || semType !== expectedType || (await verifyRecord(mutation.type, value, semType)) !== 'ok') continue
        let kind = null
        if (value._sig === mutation.data._sig) kind = 'exact'
        else if (winner(semType, value, mutation.data) && !winner(semType, mutation.data, value)) kind = 'superseded'
        if (!kind) continue
        const groupKey = kind + '\x00' + value._sig
        let group = groups.get(groupKey)
        if (!group) { group = { kind, signature: value._sig, value, origins: new Set() }; groups.set(groupKey, group) }
        group.origins.add(origin)
      }
      const candidates = [...groups.values()].filter((group) => group.origins.size >= 2)
      candidates.sort((a, b) => (a.kind === 'exact' ? -1 : 1) - (b.kind === 'exact' ? -1 : 1) || String(a.signature).localeCompare(String(b.signature)))
      const selected = candidates[0]
      if (!selected) continue
      resolved.add(index)
      for (const origin of selected.origins) usedOrigins.add(origin)
      resolutions.push({ index, key, kind: selected.kind, signature: selected.signature, origins: [...selected.origins] })
    }
    const complete = resolved.size === mutations.length
    const selectedEvidence = evidence.filter((item) => item && usedOrigins.has(item.origin))
    return {
      resolved,
      resolutions,
      complete,
      proof: complete
        ? {
            ok: true,
            durable: true,
            resolved: true,
            superseded: resolutions.some((item) => item.kind === 'superseded'),
            appId: pending.appId,
            commitId: pending.commit.commitId,
            quorum: Math.min(...resolutions.map((item) => item.origins.length)),
            evidence: selectedEvidence,
            resolutions
          }
        : null
    }
  }

  async _finishReconciledPendingLocked (pending, changed, proof) {
    if (!this._pendingMarkerMatches(pending)) throw new Error('Pending Peerit commit changed during reconciliation.')
    const evidence = proof && Array.isArray(proof.evidence) ? proof.evidence : []
    const origins = new Set(evidence.map((item) => item && item.origin).filter(Boolean))
    if (!proof || proof.ok !== true || proof.durable !== true || proof.appId !== pending.appId || proof.commitId !== pending.commit.commitId || Number(proof.quorum) < 2 || origins.size < 2) {
      throw new Error('Reconciliation did not produce two distinct signed-roster relay proofs.')
    }
    const position = authorHeadPosition(this._peerViews.get(pending.appId), pending.appId)
    if (!position.head || position.version < 1 || !HEX64.test(position.root)) throw new Error('Reconciliation found no verified current outbox head.')
    await this._saveFloor({ required: true, requiredHead: { appId: pending.appId, version: position.version, root: position.root } })
    this._withholding.delete(pending.appId)
    this._clearPendingCommit(pending)
    if (changed && changed.length) this._emit(changed.filter((key) => typeFromKey(key) !== TYPE.HEAD))
    return {
      ok: true,
      durable: true,
      reconciled: true,
      commitId: pending.commit.commitId,
      appId: pending.appId,
      head: { version: position.version, count: position.head.count, root: position.root },
      quorum: origins.size,
      evidence,
      superseded: proof.superseded === true,
      resolutions: Array.isArray(proof.resolutions) ? proof.resolutions : []
    }
  }

  async _reconcileStalePendingLocked (pending) {
    if (!this._pendingMarkerMatches(pending)) throw new Error('Pending Peerit commit changed before stale reconciliation.')
    const changed = await this._refreshPeerNow(pending.appId)
    if (this._withholding.has(pending.appId)) {
      this._pendingRecoveryNeeded = true
      const error = new Error('Peerit stale publication needs recovery: the current signed outbox cannot be audited to one head.')
      error.code = 'COMMIT_RECOVERY_NEEDED'
      throw error
    }
    let transportProof = null
    try {
      if (this.pear && this.pear.sync && typeof this.pear.sync.proveCommitQuorum === 'function') {
        transportProof = await this.pear.sync.proveCommitQuorum(pending.appId, pending.commit)
      }
    } catch {}
    const resolution = await this._pendingResolutionFromEvidence(pending, transportProof)
    const currentStates = this._pendingMutationState(pending)
    const resolutionByIndex = new Map(resolution.resolutions.map((item) => [item.index, item]))
    const resolutionMissingFromView = currentStates.some((state) => {
      const item = resolutionByIndex.get(state.index)
      if (!item) return false
      return item.kind === 'superseded' ? !state.dominates : (!state.exact && !state.dominates)
    })
    if (resolution.complete && !resolutionMissingFromView) return this._finishReconciledPendingLocked(pending, changed, resolution.proof)

    if (resolutionMissingFromView) {
      this._withholding.add(pending.appId)
      this._pendingRecoveryNeeded = true
      const error = new Error('Peerit relay evidence resolved a mutation that is absent from the selected audited view; refusing to derive a new head.')
      error.code = 'COMMIT_RECOVERY_NEEDED'
      throw error
    }
    const unsafeToReplay = currentStates.some((state) => !resolution.resolved.has(state.index) && (state.exact || state.dominates))
    if (unsafeToReplay) {
      // A merged view can still be only one relay's copy. Exact or newer same-key
      // state is never replayed until it has two-origin proof: exact replay would
      // invent durability, while replaying a dominated old value would regress a
      // later edit/delete/vote.
      this._withholding.add(pending.appId)
      this._pendingRecoveryNeeded = true
      const error = new Error('Peerit stale publication still needs two-origin durable relay evidence before same-key state can be completed.')
      error.code = 'COMMIT_RECOVERY_NEEDED'
      throw error
    }

    // Leader advanced first with another valid commit. When this device still has
    // the matching writer key, retain the exact signed mutations but derive a new
    // owner-signed head/authorization over the freshly audited position.
    const position = authorHeadPosition(this._peerViews.get(pending.appId), pending.appId)
    if (!position.head || position.version < 1 || !HEX64.test(position.root)) {
      this._pendingRecoveryNeeded = true
      const error = new Error('Peerit stale publication needs recovery: no verified current signed head is available for a safe rebase.')
      error.code = 'COMMIT_RECOVERY_NEEDED'
      throw error
    }
    if (this._myAppId() !== pending.appId || !this.identity || typeof this.identity.sign !== 'function') {
      this._pendingRecoveryNeeded = true
      const error = new Error('Peerit stale publication needs the matching writer identity before it can be safely rebased.')
      error.code = 'COMMIT_RECOVERY_NEEDED'
      throw error
    }
    const ops = pending.commit.mutations
      .filter((mutation, index) => !resolution.resolved.has(index))
      .map(mutation => ({ type: mutation.type, data: mutation.data }))
    if (!ops.length) {
      this._pendingRecoveryNeeded = true
      const error = new Error('Peerit stale publication has no mutation that is safe to replay without stronger relay evidence.')
      error.code = 'COMMIT_RECOVERY_NEEDED'
      throw error
    }
    const rebased = await this._buildAtomicCommit(ops)
    this._replacePendingCommit(pending, rebased)
    try {
      return await this._sendPendingCommitLocked(rebased, { reconcileStale: false })
    } catch (error) {
      if (this._isStaleCommitError(error)) this._pendingRecoveryNeeded = true
      throw error
    }
  }

  async _sendPendingCommitLocked (pending, { reconcileStale = true } = {}) {
    if (!(await this._validatePendingCommit(pending))) {
      this._withholding.add(pending && pending.appId)
      throw new Error('The persisted Peerit commit failed local signature or schema validation; refusing to transmit it.')
    }
    let receipt
    try {
      receipt = await this.pear.sync.commit(pending.appId, pending.commit)
    } catch (error) {
      if (this._isStaleCommitError(error)) {
        this._withholding.add(pending.appId)
        if (reconcileStale) return this._reconcileStalePendingLocked(pending)
      }
      throw error
    }
    if (!this._receiptMatchesPending(receipt, pending)) {
      const error = new Error('Peerit relay quorum returned a mismatched or non-durable atomic commit receipt.')
      error.code = 'INVALID_COMMIT_RECEIPT'
      throw error
    }
    const changed = await this._adoptAtomicCommit(pending, receipt)
    // This is the only clear site: no receipt, one receipt, or mismatched
    // receipts leave the exact envelope durable and block every later write.
    try {
      this._clearPendingCommit(pending)
    } catch (error) {
      // Quorum already made this publication durable. A retained marker is safe
      // because commitId is idempotent; do not misreport the published record as
      // failed merely because local cleanup needs a later retry.
      console.warn('[gossip] atomic commit reached quorum but its local marker remains:', error && error.message)
    }
    this._emit(changed.filter((key) => typeFromKey(key) !== TYPE.HEAD))
    try { await this._announce() } catch {}
    return receipt
  }

  _notePendingFailure () {
    this._pendingRetryAt = Date.now() + this._pendingRetryDelay
    this._pendingRetryDelay = Math.min(PENDING_RETRY_MAX_MS, this._pendingRetryDelay * 2)
  }

  async _retryPendingCommit ({ force = false } = {}) {
    if (this._readOnly || !this._atomicCommitEnabled()) return null
    if (this._retryingPending) return this._retryingPending
    if (!force && (this._pendingRecoveryNeeded || Date.now() < this._pendingRetryAt)) return null
    this._retryingPending = this._withAtomicWriterLock(async () => {
      const pending = this._loadPendingCommit()
      if (!pending) return null
      if (pending.invalid) throw new Error('The durable Peerit pending marker is unreadable or uses an unsupported schema.')
      return this._sendPendingCommitLocked(pending)
    }).then((receipt) => {
      if (receipt) {
        this._pendingRetryAt = 0
        this._pendingRetryDelay = PENDING_RETRY_MIN_MS
      }
      return receipt
    }, (error) => {
      this._notePendingFailure(error)
      throw error
    }).finally(() => { this._retryingPending = null })
    return this._retryingPending
  }

  _maybeRetryPendingCommit () {
    // Do not trust the instance-local marker here. Another tab can create or clear
    // the device-global marker between poll ticks; _retryPendingCommit reloads it
    // under the writer lock before deciding whether there is work to do.
    if (this._readOnly || !this._atomicCommitEnabled() || this._pendingRecoveryNeeded || Date.now() < this._pendingRetryAt) return null
    return this._retryPendingCommit()
  }

  async _appendAtomic (ops, writerSession = null) {
    const publishLocked = async () => {
      const me = this._myAppId()
      // Re-read the global marker *inside* the cross-tab lock. An instance whose
      // in-memory state predates another tab's failed publication must block,
      // never overwrite that tab's durable retry envelope.
      this._loadPendingCommit()
      if (this._pendingCommit) throw new Error('A previous Peerit publication is still awaiting two durable relay receipts. No later writes are allowed until it reaches quorum or is reconciled.')
      // Fresh self replay prevents signing a new CAS position over stale cached
      // rows. The relay independently rechecks expected version/root and census.
      await this._refreshPeerNow(me)
      if (this._withholding.has(me)) throw new Error('Peerit outbox integrity check failed; refusing to commit until the relay recovers the newer signed state.')
      const pending = await this._buildAtomicCommit(ops)
      this._persistPendingCommit(pending) // MUST happen before the first POST
      try {
        return await this._sendPendingCommitLocked(pending)
      } catch (cause) {
        this._notePendingFailure(cause)
        const error = new Error(this._pendingRecoveryNeeded
          ? 'Peerit stale publication needs verified recovery before another write can proceed.'
          : 'Peerit publication is pending: fewer than two relays returned matching durable receipts. It will retry automatically; no later writes are allowed meanwhile.')
        error.code = cause && cause.code
        error.cause = cause
        throw error
      }
    }
    // Only the opaque capability issued to this exact active write stack may
    // bypass reacquiring the non-reentrant Web Lock. Concurrent same-instance
    // append/retry calls have no token and therefore queue normally.
    if (writerSession && this._activeAtomicWriterSessions.has(writerSession)) return publishLocked()
    return this.withAtomicWriterSession(() => publishLocked())
  }

  // Compute + sign + append the outbox head (the "merkle root" census over the
  // last audited self view plus `pendingOp`). No PoW (makeValidator passes the
  // 'head' type); signed with the same Ed25519 envelope as every record. The
  // caller performs one stable-state refresh after both low-level appends.
  async _maintainHead (pendingOp = null) {
    if (this._destroyed) return null // torn down mid-write — don't append after destroy()
    const me = this.getMe()
    if (!HEX64.test(me || '')) return null // no real key -> no meaningful head
    const view = Object.assign(Object.create(null), this._peerViews.get(me) || {})
    if (pendingOp) applyOp(view, pendingOp)
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
    // Repeating this exact signed reducer overwrite is idempotent. One bounded
    // retry covers a transient response loss without deriving another head/version.
    let lastError = null
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await this.pear.sync.append(this._myAppId(), { type: TYPE.HEAD, data, timestamp: new Date().toISOString() })
        return data
      } catch (error) { lastError = error }
    }
    throw lastError || new Error('signed outbox head append failed')
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
      this._readFrom.clear()                 // re-evaluate recovery routing (a withholding primary may have healed)
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
    // An integrity-sensitive caller can force one author past the cheap `/heads`
    // gate (including a transient heads error). Conversely, the only time self is
    // skipped is the explicit local record -> head transition: that candidate is
    // intentionally incomplete and the last audited self view remains authoritative.
    const forcedPub = this._forceReadPub
    if (forcedPub && this._peers.has(forcedPub) && !toRead.includes(forcedPub)) toRead.push(forcedPub)
    const transitionPub = this._localWriteTransition && this._localWriteTransition.pub
    if (transitionPub) toRead = toRead.filter((pub) => pub !== transitionPub)

    // Read candidate outboxes with an explicitly advertised batch endpoint when
    // available. This changes neither the bytes accepted nor the audit below;
    // it only removes per-outbox HTTP round trips. A malformed/failed batch is
    // discarded wholesale and re-read through the established range endpoint.
    const readInfos = toRead.map((pub) => ({ pub, info: this._peers.get(pub) })).filter(({ info }) => !!info)
    const fetchedRows = await this._rowsForPeers(readInfos)

    let anyRowChanged = false
    const previous = new Map()
    for (const pub of toRead) {
      const info = this._peers.get(pub); if (!info) continue
      if (!fetchedRows.has(pub)) continue
      const rows = fetchedRows.get(pub)
      const prevSig = this._peerSigs.get(pub) || new Map()
      const priorView = this._peerViews.get(pub) || null
      const priorHead = this._peerHeads.has(pub) ? this._peerHeads.get(pub) : undefined
      previous.set(pub, { view: priorView, sig: prevSig, head: priorHead })
      // Stage into a fresh object. Never mutate the last-known-good view in place;
      // a stale/withheld candidate must be discardable after the signed-head audit.
      const view = Object.assign(Object.create(null), priorView || {})
      const newSig = new Map()
      for (const r of rows) {
        const key = r.key
        if (PROTO_KEYS.has(key)) continue
        const val = r.value
        const tok = changeToken(val)
        newSig.set(key, tok)
        if (prevSig.get(key) === tok) continue // unchanged since last refresh — verdict still holds
        anyRowChanged = true
        let admitted = false
        try { admitted = await admit(typeForRow(key, val), val, key, pub, secure, this.validate) } catch { admitted = false }
        if (admitted) view[key] = val
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
    const multi = this.pear.sync && (this.pear._relayCount || 1) > 1
    const crossHeadFn = multi && this.pear.sync.crossHead
    const recoverFn = multi && this.pear.sync.recoverRows
    for (const pub of toRead) {
      let view = this._peerViews.get(pub); if (!view) continue
      let head = view[keys.head(pub)]
      if (crossHeadFn) { try { const ch = await this.pear.sync.crossHead(pub); if (ch && ch.head && (!head || (ch.head.version | 0) > (head.version | 0))) head = ch.head } catch {} }
      // Phase C: durable monotonic head floor. `head` is the max VERIFIED head
      // across every reachable relay. If it REGRESSES below a version this client
      // durably recorded (localStorage, survives restart) — for a PEER or the
      // author's OWN outbox — then all relays are serving older content than we
      // know existed: an all-relays-collude / across-restart rollback Phase B
      // can't see. Flag it; else ratchet the floor up and TOUCH it, so eviction
      // is by recency, NOT version (a Sybil can't evict a followed author by
      // minting a high-version head). Floor is only set from a verified head.
      const fl = this._floor.get(pub)
      const hv = head ? (head.version | 0) : -1
      const root = head && typeof head.root === 'string' ? head.root.toLowerCase() : ''
      const rootConflict = fl && hv === fl.v && fl.root && fl.root !== root
      if (fl && (hv < fl.v || rootConflict)) {
        if (!this._withholding.has(pub)) console.warn('[gossip] outbox ' + pub.slice(0, 12) + '… ROLLED BACK below the durable head floor (serving v' + (hv < 0 ? '∅' : hv) + ' < known v' + fl.v + ')')
        this._withholding.add(pub)
        const prior = previous.get(pub)
        this._restorePeerCandidate(pub, prior)
        continue // no relay has the newer head — can't recover; flag it (detection, not content-recovery)
      }
      if (head && (!fl || hv > fl.v || (hv === fl.v && !fl.root && root))) { this._floor.set(pub, { v: hv, root, t: ++this._floorTick }); this._floorDirty = true }
      else if (fl) { fl.t = ++this._floorTick } // recently-relevant → survives eviction
      if (!head) {
        if (this._unconfirmedLocalHead === pub || (this._unconfirmedRecordAppend && this._unconfirmedRecordAppend.pub === pub)) {
          this._withholding.add(pub)
          this._restorePeerCandidate(pub, previous.get(pub))
        }
        continue
      }
      let rows = []; for (const k in view) rows.push({ key: k, value: view[k] })
      let a
      try { a = await auditOutbox(rows, head, pub) } catch {
        if (this._unconfirmedLocalHead === pub || (this._unconfirmedRecordAppend && this._unconfirmedRecordAppend.pub === pub)) this._restorePeerCandidate(pub, previous.get(pub))
        continue
      }
      if (a.hasHead && a.matches === false && recoverFn) {
        try {
          const rec = await this.pear.sync.recoverRows(pub, head)
          if (rec && rec.rows) {
            const view2 = Object.create(null); const newSig = new Map()
            for (const r of rec.rows) {
              if (PROTO_KEYS.has(r.key)) continue
              if (!(r.value && r.value._k === pub)) continue
              let admitted = false
              try { admitted = await admit(typeForRow(r.key, r.value), r.value, r.key, pub, secure, this.validate) } catch { admitted = false }
              if (admitted) { view2[r.key] = r.value; newSig.set(r.key, changeToken(r.value)) }
            } // re-admit ONLY pub's own rows (a relay can't smuggle foreign-signed rows through recovery)
            this._peerViews.set(pub, view2); this._peerSigs.set(pub, newSig); view = view2; anyRowChanged = true
            if (rec.base) this._readFrom.set(pub, rec.base) // pin future reads of this outbox to the relay that serves it, so the recovery STICKS (re-evaluated at reconcile)
            rows = []; for (const k in view2) rows.push({ key: k, value: view2[k] })
            a = await auditOutbox(rows, head, pub)
          }
        } catch {}
      }
      const bad = a.hasHead && a.matches === false
      if (bad) {
        if (!this._withholding.has(pub)) console.warn('[gossip] outbox ' + pub.slice(0, 12) + '… fails its signed-head audit on every reachable relay (rows withheld/tampered)')
        this._withholding.add(pub)
        const prior = previous.get(pub)
        this._restorePeerCandidate(pub, prior)
      } else {
        const pending = this._unconfirmedRecordAppend
        if (pending && pending.pub === pub) {
          // Only an exact attempted row covered by a census-matching signed head
          // resolves an ambiguous append. A healthy alternate relay that simply
          // lacks the row is not enough to prove the primary never committed it.
          if (view[pending.key] && changeToken(view[pending.key]) === pending.token) {
            this._unconfirmedRecordAppend = null
            this._withholding.delete(pub)
          } else this._withholding.add(pub)
        } else this._withholding.delete(pub)
      }
    }

    if (this._floorDirty) await this._saveFloor() // persist BEFORE the early return: a crossHead-only ratchet leaves anyRowChanged false
    const integrityBefore = this._integritySnapshot || ''
    const integrityAfter = [...this._withholding].sort().join(',')
    this._integritySnapshot = integrityAfter
    if (this._cache && !anyRowChanged && integrityAfter === integrityBefore) return [] // nothing moved anywhere — keep cache (and its sorted-key cache)
    const boxes = []
    for (const [pub, view] of this._peerViews) boxes.push({ pub, view })
    const merged = combineAdmitted(boxes, this._claimed)
    this._setLocal(CLAIMED_KEY, JSON.stringify(this._claimed))
    const changed = diffViews(this._cache, merged)
    if (integrityAfter !== integrityBefore && !changed.includes(SYNC_INTEGRITY_STATUS_KEY)) changed.push(SYNC_INTEGRITY_STATUS_KEY)
    if (this._cache && changed.length === 0) { /* winning view identical — keep object identity */ }
    else { this._cache = merged; this._sortedFor = null }
    if (changed.length || (anyRowChanged && !reconcile)) this._saveCache() // persist the latest verified view for an instant reload
    if (changed.length) this.viewEpoch++
    return changed
  }

  _refresh () {
    if (this._refreshing) return this._refreshing
    this._refreshing = (async () => { try { return await this._doRefresh() } finally { this._refreshing = null } })()
    return this._refreshing
  }

  // Restore the last audited author view after rejecting a staged candidate. On
  // a first read there is no prior view: delete the stage entirely so a partial
  // census cannot render, persist, or capture a sticky community claim.
  _restorePeerCandidate (pub, prior) {
    if (prior && prior.view !== null) {
      this._peerViews.set(pub, prior.view)
      this._peerSigs.set(pub, prior.sig || new Map())
    } else {
      this._peerViews.delete(pub)
      this._peerSigs.delete(pub)
    }
    if (prior && prior.head !== undefined) this._peerHeads.set(pub, prior.head)
    else this._peerHeads.delete(pub)
  }

  // Force a distinct stable-state audit for one author. Await an existing merge
  // first so a preflight cannot accidentally coalesce into a pass that selected
  // `toRead` before the force flag was installed.
  async _refreshPeerNow (pub) {
    if (this._refreshing) await this._refreshing
    this._forceReadPub = pub
    try { return await this._refresh() } finally { if (this._forceReadPub === pub) this._forceReadPub = null }
  }

  async _rowsForPeer (info) {
    // If a prior cross-relay audit recovered this outbox from a specific relay,
    // keep reading it from THERE (paginated) so the recovery sticks instead of
    // being re-stripped by the withholding primary each round.
    const from = this._readFrom.get(info.appId)
    if (from && this.pear.sync.crossRows) { try { return await this.pear.sync.crossRows(info.appId, from) } catch {} }
    if (this.pear.sync.range) {
      const rows = []
      let gt = ''
      while (rows.length < MAX_ROWS_PER_PEER) {
        const limit = Math.min(RANGE_PAGE_ROWS, MAX_ROWS_PER_PEER - rows.length)
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

  // Returns `pub -> complete rows`. Failures are isolated per outbox on the
  // legacy path. On the batch path, any malformed response makes us abandon the
  // entire optimisation and use the established per-outbox reader instead — it
  // is never safe to blend a partial batch response into an audited candidate.
  async _rowsForPeers (entries) {
    const result = new Map()
    const pending = []
    const batchable = []
    for (const entry of entries || []) {
      if (!entry || !entry.pub || !entry.info) continue
      if (this._readFrom.get(entry.info.appId) || !this.pear.sync.ranges) pending.push(entry)
      else batchable.push(entry)
    }

    if (batchable.length) {
      try {
        const batched = await this._batchRowsForPeers(batchable)
        for (const [pub, rows] of batched) result.set(pub, rows)
      } catch {
        // The capability can disappear while a stale roster is cached, and a
        // relay can return an invalid page. Both are availability failures, not
        // grounds to weaken the audited read path.
        pending.push(...batchable)
      }
    }

    // Even unchanged relays benefit from bounded parallel reads on the old
    // endpoint. Do not fan thousands of cold-start requests at once: the relay
    // already advertises rate limits and the backoff layer needs room to work.
    let next = 0
    const workers = Array.from({ length: Math.min(FALLBACK_READ_CONCURRENCY, pending.length) }, async () => {
      while (next < pending.length) {
        const entry = pending[next++]
        try { result.set(entry.pub, await this._rowsForPeer(entry.info)) } catch {}
      }
    })
    await Promise.all(workers)
    return result
  }

  async _batchRowsForPeers (entries) {
    const state = new Map()
    for (const entry of entries) {
      if (state.has(entry.info.appId)) throw new Error('duplicate appId in batched range request')
      state.set(entry.info.appId, { pub: entry.pub, appId: entry.info.appId, gt: '', rows: [], complete: false })
    }
    while (true) {
      const active = [...state.values()].filter((row) => !row.complete)
      if (!active.length) break
      for (let start = 0; start < active.length; start += BATCH_RANGE_OUTBOXES) {
        const page = active.slice(start, start + BATCH_RANGE_OUTBOXES)
        if (page.some((row) => row.rows.length >= MAX_ROWS_PER_PEER)) throw new Error('batched range outbox reaches row bound')
        const requests = page.map((row) => ({ appId: row.appId, gt: row.gt, limit: Math.min(RANGE_PAGE_ROWS, MAX_ROWS_PER_PEER - row.rows.length) }))
        const response = await this.pear.sync.ranges(requests)
        const replies = Array.isArray(response) ? response : (response && response.ranges)
        if (!Array.isArray(replies) || replies.length !== requests.length) throw new Error('invalid batched range response shape')
        const byApp = new Map()
        for (const reply of replies) {
          if (!reply || typeof reply.appId !== 'string' || !Array.isArray(reply.rows) || byApp.has(reply.appId)) throw new Error('invalid batched range response entry')
          byApp.set(reply.appId, reply.rows)
        }
        for (const row of page) {
          const request = requests.find((item) => item.appId === row.appId)
          const rows = byApp.get(row.appId)
          if (!rows || rows.length > request.limit) throw new Error('batched range response exceeds requested page')
          let previous = row.gt
          for (const entry of rows) {
            if (!entry || typeof entry.key !== 'string' || !entry.key || !entry.value || typeof entry.value !== 'object' || entry.key <= previous) throw new Error('batched range pagination is not strictly ordered')
            previous = entry.key
            row.rows.push(entry)
            if (row.rows.length > MAX_ROWS_PER_PEER) throw new Error('batched range outbox exceeds row bound')
          }
          if (rows.length < request.limit) row.complete = true
          else row.gt = previous
        }
      }
    }
    const out = new Map()
    for (const row of state.values()) out.set(row.pub, row.rows)
    return out
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
    if (this._requireAtomicWrites || this._atomicCommitEnabled() || this._pendingCommit) this._loadPendingCommit()
    let viewLength = 0
    for (const k in v) { const t = typeForRow(k, v[k]); if (t !== TYPE.HEAD && t !== TYPE.BLOB) viewLength++ } // head!/blob! are internal (census / opaque body storage), not "records"
    return {
      appId: 'peerit',
      mode: this.mode,
      secure: isSecure(),
      peers: this._peers.size,
      viewLength,
      relays: (this.pear && this.pear._relayCount) || 1, // Phase B: how many relays writes fan out across + heads are cross-checked on
      atomicCommit: {
        required: this._requireAtomicWrites,
        available: this._atomicCommitEnabled(),
        pending: !!this._pendingCommit,
        pendingCommitId: this._pendingCommit && this._pendingCommit.commit ? this._pendingCommit.commit.commitId : null,
        pendingAppId: this._pendingCommit && this._pendingCommit.appId ? this._pendingCommit.appId : null,
        recoveryNeeded: this._pendingRecoveryNeeded,
        nextRetryAt: this._pendingRetryAt || 0
      },
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

export function createGossip ({ storage, pear, getMe, identity, channelName, forceDev, bus, validate, pollMs, writeHead, readOnly, requireAtomicWrites, discover, seedOutboxes, instantBoot, seedSnapshot } = {}) {
  if (pear && pear.sync && pear.swarm && !forceDev) return new BridgeGossipSync({ pear, getMe, identity, storage, validate, pollMs, writeHead, readOnly, requireAtomicWrites, discover, seedOutboxes, instantBoot, seedSnapshot })
  const theBus = bus || (typeof BroadcastChannel !== 'undefined' ? browserBus(channelName || 'peerit-gossip') : null)
  return new GossipSync({ storage, bus: theBus, getMe, validate })
}

export { GossipSync, BridgeGossipSync, applyOp as gossipApplyOp }
