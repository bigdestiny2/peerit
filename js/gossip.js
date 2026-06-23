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

import { ownerOf, expectedKey, typeFromKey, recordTs, canonical } from './canon.js'
import { verifyRecord } from './verify.js'
import { verify as edVerify, isSecure, ready as cryptoReady } from './crypto.js'

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

// ---- local reducer + range over a {key:value} view --------------------------
function applyOp (view, op) {
  if (!op || typeof op !== 'object' || !op.type) return
  if (op.data && op.data.id != null) view[op.type.replace(':', '!') + '!' + op.data.id] = op.data
}
function rangeFromView (view, opts) {
  let ks = Object.keys(view).sort()
  if (opts.gte != null) ks = ks.filter(k => k >= opts.gte)
  if (opts.gt != null) ks = ks.filter(k => k > opts.gt)
  if (opts.lte != null) ks = ks.filter(k => k <= opts.lte)
  if (opts.lt != null) ks = ks.filter(k => k < opts.lt)
  if (opts.reverse) ks.reverse()
  let limit = Number(opts.limit) || 100
  if (limit < 1) limit = 100
  if (limit > 1000) limit = 1000
  const out = []
  for (const k of ks) { if (out.length >= limit) break; out.push({ key: k, value: view[k] }) }
  return out
}

// ---- authenticity (cache only positive verdicts; key binds sig TO content) --
const _verdict = new Map()
async function honored (type, val) {
  if (!val || !val._sig) return verifyRecord(type, val)
  const ck = JSON.stringify([val._sig, val._k || '', val._dk || '', val._ns || '', canonical(type, val)])
  if (_verdict.has(ck)) return _verdict.get(ck)
  const v = await verifyRecord(type, val)
  if (v === 'ok') _verdict.set(ck, v) // never cache 'bad' (cheap to recompute; avoids unbounded growth from rejected forgeries)
  return v
}

async function admit (type, val, key, pub, secure) {
  if (!val || typeof val !== 'object') return false
  if (!type || expectedKey(type, val) !== key) return false // key binding
  const owner = ownerOf(type, val)
  if (!owner) return false
  const v = await honored(type, val)
  if (secure) return v === 'ok'              // signature is the authority
  return owner === pub && v !== 'bad'         // cooperative dev fallback only
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
export async function mergeOutboxes (boxes, claimed) {
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
      if (!(await admit(type, val, key, pub, secure))) continue
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

// ---- dev / Node gossip ------------------------------------------------------
class GossipSync {
  constructor ({ storage, bus, getMe }) {
    this.mode = 'gossip-dev'
    this.storage = storage
    this.bus = bus
    this.getMe = getMe
    this._listeners = new Set()
    this._cache = null
    this._inflight = null
    this._epoch = 0
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
        if (await admit(typeFromKey(k), iv, k, m.pub, secure)) admitted[k] = iv
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
      const merged = await mergeOutboxes(boxes, claimed)
      this._write(CLAIMED_KEY, claimed)
      if (this._epoch === epoch) this._cache = merged // discard if invalidated mid-flight
      this._inflight = null
      return merged
    })()
    return this._inflight
  }
  _invalidate () { this._cache = null; this._inflight = null; this._epoch++ }

  async get (key) { const v = await this._merged(); return Object.prototype.hasOwnProperty.call(v, key) ? v[key] : null }
  async list (prefix, opts = {}) { return rangeFromView(await this._merged(), prefix ? { gte: prefix, lt: prefix + '\xff', limit: opts.limit } : { limit: opts.limit }) }
  async range (opts = {}) { return rangeFromView(await this._merged(), opts) }
  async count (prefix) { const v = await this._merged(); if (!prefix) return Object.keys(v).length; let n = 0; for (const k in v) if (k >= prefix && k < prefix + '\xff') n++; return n }
  async status () { const v = await this._merged(); return { appId: 'peerit', mode: this.mode, secure: isSecure(), peers: this._peers().length, viewLength: Object.keys(v).length } }

  onChange (fn) { this._listeners.add(fn); return () => this._listeners.delete(fn) }
  _emit () { for (const fn of this._listeners) { try { fn() } catch (e) { console.error(e) } } }
}

// ---- real PearBrowser gossip ------------------------------------------------
class BridgeGossipSync {
  constructor ({ pear, getMe, identity }) {
    this.mode = 'gossip-bridge'
    this.pear = pear
    this.getMe = getMe
    this.identity = identity
    this._listeners = new Set()
    this._peers = new Map() // pub -> { appId, inviteKey }
    this._cache = null
    this._inflight = null
    this._epoch = 0
    this._poll = null
  }

  // Full pubkey as appId (64 hex == bridge's max appId length) so two distinct
  // users can never collide onto the same sync group.
  _myAppId () { return this.getMe() }

  // Every outbox this user has ever written, persisted locally. Re-merging ALL
  // of them on boot makes posts survive even if PearBrowser hands back a
  // different per-app identity key on reopen (which would otherwise orphan the
  // prior outbox and make posts "vanish" though they're still on disk).
  _knownOutboxes () { try { return JSON.parse(localStorage.getItem('peerit:my-outboxes') || '[]') } catch { return [] } }
  _rememberOutbox (appId, inviteKey) {
    const list = this._knownOutboxes()
    if (!list.find(o => o.appId === appId)) { list.push({ appId, inviteKey }); try { localStorage.setItem('peerit:my-outboxes', JSON.stringify(list)) } catch {} }
  }

  async ready () {
    await cryptoReady()
    let key = null
    try { key = localStorage.getItem('peerit:my-outbox-key') } catch {}
    try {
      const r = key ? await this.pear.sync.join(this._myAppId(), key) : await this.pear.sync.create(this._myAppId())
      this._myInvite = r.inviteKey
      try { localStorage.setItem('peerit:my-outbox-key', r.inviteKey) } catch {}
    } catch {
      const r = await this.pear.sync.create(this._myAppId()); this._myInvite = r.inviteKey
    }
    this._peers.set(this.getMe(), { appId: this._myAppId(), inviteKey: this._myInvite, self: true })
    this._rememberOutbox(this._myAppId(), this._myInvite)
    // Re-join + merge EVERY outbox we've ever owned, so a changed identity key
    // can't strand earlier posts.
    for (const o of this._knownOutboxes()) {
      if (this._peers.has(o.appId)) continue
      try { await this.pear.sync.join(o.appId, o.inviteKey); this._peers.set(o.appId, { appId: o.appId, inviteKey: o.inviteKey, self: true }) } catch {}
    }
    try { console.log('[peerit persist] me=' + (this.getMe() || '').slice(0, 12) + ' outbox=' + (this._myInvite || '').slice(0, 12) + ' knownOutboxes=' + this._knownOutboxes().length) } catch {}
    try {
      this._channel = await this.pear.swarm.v1.join(TOPIC, { server: true, client: true, appName: 'peerit', reason: 'Discover other peerit users' })
      this._channel.on('peer', () => this._announce())
      this._channel.on('message', (peer, data) => this._onDescriptor(data))
      await this._announce()
    } catch (e) { console.warn('[gossip] swarm unavailable:', e && e.message) }
    this._poll = setInterval(() => { this._invalidate(); this._emit() }, 4000)
    if (this._poll && this._poll.unref) this._poll.unref()
    return this
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
      this._invalidate(); this._emit(); this._announce()
    } catch (e) { console.warn('[gossip] join failed', e && e.message) }
  }

  announce () { return this._announce() }

  async append (op) {
    const r = await this.pear.sync.append(this._myAppId(), { type: op.type, data: op.data, timestamp: new Date().toISOString() })
    this._invalidate(); this._emit()
    return r
  }

  async _mergedAsync () {
    const boxes = []
    for (const [pub, info] of this._peers) {
      try {
        const rows = await this._rowsForPeer(info)
        const view = {}
        for (const r of rows) view[r.key] = r.value
        boxes.push({ pub, view })
      } catch {}
    }
    let claimed = {}
    try { claimed = JSON.parse(localStorage.getItem(CLAIMED_KEY) || '{}') } catch {}
    const merged = await mergeOutboxes(boxes, claimed)
    try { localStorage.setItem(CLAIMED_KEY, JSON.stringify(claimed)) } catch {}
    return merged
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
    if (this._inflight) return this._inflight
    const epoch = this._epoch
    this._inflight = (async () => { const m = await this._mergedAsync(); if (this._epoch === epoch) this._cache = m; this._inflight = null; return m })()
    return this._inflight
  }
  _invalidate () { this._cache = null; this._inflight = null; this._epoch++ }

  async get (key) { const v = await this._merged(); return Object.prototype.hasOwnProperty.call(v, key) ? v[key] : null }
  async list (prefix, opts = {}) { return rangeFromView(await this._merged(), prefix ? { gte: prefix, lt: prefix + '\xff', limit: opts.limit } : { limit: opts.limit }) }
  async range (opts = {}) { return rangeFromView(await this._merged(), opts) }
  async count (prefix) { const v = await this._merged(); if (!prefix) return Object.keys(v).length; let n = 0; for (const k in v) if (k >= prefix && k < prefix + '\xff') n++; return n }
  async status () { const v = await this._merged(); return { appId: 'peerit', mode: this.mode, secure: isSecure(), peers: this._peers.size, viewLength: Object.keys(v).length, inviteKey: this._myInvite } }

  onChange (fn) { this._listeners.add(fn); return () => this._listeners.delete(fn) }
  _emit () { for (const fn of this._listeners) { try { fn() } catch (e) { console.error(e) } } }
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

export function createGossip ({ storage, pear, getMe, identity, channelName, forceDev, bus } = {}) {
  if (pear && pear.sync && pear.swarm && !forceDev) return new BridgeGossipSync({ pear, getMe, identity })
  const theBus = bus || (typeof BroadcastChannel !== 'undefined' ? browserBus(channelName || 'peerit-gossip') : null)
  return new GossipSync({ storage, bus: theBus, getMe })
}

export { GossipSync, BridgeGossipSync, applyOp as gossipApplyOp }
