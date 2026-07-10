// identity-store.js — the DEVICE tier of web identity durability.
//
// Tiers (panel-ratified 2026-07-08):
//   0. lurker  — no identity at all until the first write (js/identity.js lazy).
//   1. DEVICE  — this module: the seed minted on first write survives reloads on
//                THIS device with no passphrase, stored as AES-256-GCM ciphertext
//                whose wrapping CryptoKey is generated NON-EXTRACTABLE and kept in
//                IndexedDB next to it.
//   2. vault   — passphrase envelope (identity-vault.js): portable/backup tier and
//                the recovery story; export-to-file for cross-device/offline.
//
// HONEST THREAT MODEL — read before relying on this:
//   * "Non-extractable" is a WebCrypto API property, NOT disk encryption. The wrap
//     key's raw bytes live in the browser profile's IDB backing store; an attacker
//     with filesystem/disk/backup access recovers the seed. Only the passphrase
//     vault (tier 2) defends at rest — recommend OS disk encryption in UI copy.
//   * What tier 1 DOES defend: passive same-origin storage READS (a
//     localStorage/IDB dump via JS APIs yields ciphertext + an unexportable key
//     handle, not a bearer seed) and storage-sync/backup-file leaks of values.
//   * Same-origin XSS while the app runs can still USE the key (decrypt/sign) —
//     as it can with an unlocked vault session. Nothing here changes that.
//   * While the app runs, the decrypted seed lives in page memory (same exposure
//     class as an unlocked vault session today).
//   * iOS ITP purges IndexedDB (and localStorage, so the vault too) after ~7 days
//     without a visit, regardless of navigator.storage.persist(). The durable
//     recovery is the EXPORT file, not this store — say so in UI copy.
//
// Storage layout: ONE record under a fixed key holding { wrap CryptoKey, iv, ct,
// pubkey, driveKey, label }. Key and ciphertext share the record so there is a
// single atomicity domain: the multi-tab first-write race is settled by an atomic
// put-if-absent — the loser ADOPTS the winner's identity (identity forking is the
// exact churn bug this design kills). Crypto runs BEFORE the transaction (awaiting
// inside an IDB txn auto-commits it), so the txn is a pure get→put.
//
// The kv adapter is injectable: Node tests pass a Map-backed adapter (Node has
// webcrypto but no IndexedDB); the browser uses the IDB adapter below.

import { verifiedIdentityEntry } from './identity.js'

const DB_NAME = 'peerit-identity'
const DB_STORE = 'device'
const RECORD_KEY = 'identity:v1'
export const IDENTITY_FORGET_TOMBSTONE_KEY = 'peerit:identity-forget:v1'
const HEX64 = /^[0-9a-f]{64}$/i

function subtle () {
  return (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) || null
}

function hexToBytes (hex) {
  const u = new Uint8Array(hex.length / 2)
  for (let i = 0; i < u.length; i++) u[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return u
}
function bytesToHex (buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function tokenBytes (value) {
  try { return bytesToHex(value) } catch { return String(value == null ? '' : value) }
}

// Exact, synchronous identity-record token used inside IndexedDB transactions.
// CryptoKey objects cannot be compared after structured cloning, so bind the CAS
// to every stable record field plus the complete IV/ciphertext. This is not an
// authentication token and never leaves the browser; it only prevents a deliberate
// reset/import from deleting a different record that another tab installed first.
function deviceRecordToken (rec) {
  if (!rec || typeof rec !== 'object') return 'none'
  return JSON.stringify({
    v: rec.v,
    pubkey: String(rec.pubkey || '').toLowerCase(),
    driveKey: String(rec.driveKey || '').toLowerCase(),
    createdAt: Number(rec.createdAt) || 0,
    iv: tokenBytes(rec.iv),
    ct: tokenBytes(rec.ct)
  })
}

function storageValue (storage, key) {
  try { return storage && typeof storage.getItem === 'function' ? storage.getItem(key) : null } catch { return null }
}

// Forget is a two-store transaction (IndexedDB device key + localStorage vault),
// which browsers cannot commit atomically. A synchronous, read-back-verified
// tombstone is therefore written BEFORE either delete. Boot and every write honor
// any value at this key, including a malformed one, until both tiers are gone.
export function hasIdentityForgetTombstone (storage) {
  return storageValue(storage, IDENTITY_FORGET_TOMBSTONE_KEY) != null
}

export function beginIdentityForget (storage, pubkey = null) {
  if (!storage || typeof storage.setItem !== 'function' || typeof storage.getItem !== 'function') {
    throw new Error('Cannot forget this identity safely because durable browser storage is unavailable.')
  }
  const existing = storageValue(storage, IDENTITY_FORGET_TOMBSTONE_KEY)
  if (existing != null) return existing
  const marker = JSON.stringify({
    v: 1,
    pubkey: HEX64.test(String(pubkey || '')) ? String(pubkey).toLowerCase() : null,
    startedAt: Date.now()
  })
  storage.setItem(IDENTITY_FORGET_TOMBSTONE_KEY, marker)
  if (storage.getItem(IDENTITY_FORGET_TOMBSTONE_KEY) !== marker) {
    throw new Error('Could not durably record the identity forget request; nothing was deleted.')
  }
  return marker
}

export function clearIdentityForgetTombstone (storage) {
  if (!storage || typeof storage.getItem !== 'function') return false
  try {
    if (typeof storage.removeItem !== 'function') return false
    storage.removeItem(IDENTITY_FORGET_TOMBSTONE_KEY)
    return storage.getItem(IDENTITY_FORGET_TOMBSTONE_KEY) == null
  } catch { return false }
}

// Complete the cross-store forget transaction. Dependency injection keeps this
// module independent of the vault implementation while making crash/failure order
// executable in tests: tombstone -> deactivate -> device delete -> vault delete ->
// tombstone clear. Any throw leaves the tombstone in place, which boot treats as a
// hard do-not-restore instruction.
export async function finishIdentityForget ({ storage, deviceStore, deactivate, vaultPresent, removeVault } = {}) {
  if (!hasIdentityForgetTombstone(storage)) return true
  try { if (typeof deactivate === 'function') deactivate() } catch {}
  if (!deviceStore || typeof deviceStore.clear !== 'function' || !(await deviceStore.clear())) {
    throw new Error('Could not remove the encrypted device identity from this browser.')
  }
  if (typeof vaultPresent === 'function' && vaultPresent()) {
    if (typeof removeVault !== 'function') throw new Error('Could not remove the encrypted identity vault from this browser.')
    removeVault()
    if (vaultPresent()) throw new Error('Could not remove the encrypted identity vault from this browser.')
  }
  if (!clearIdentityForgetTombstone(storage)) {
    throw new Error('The identity keys were removed, but the browser could not finish their durable forget marker. Reload to retry cleanup before publishing again.')
  }
  return true
}

// ---- IndexedDB kv adapter (browser) -----------------------------------------
// Minimal surface: get / atomic insert / atomic compare-and-swap / delete.
function idbAdapter () {
  if (typeof indexedDB === 'undefined') return null
  const open = () => new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => { req.result.createObjectStore(DB_STORE) }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error || new Error('indexedDB open failed'))
  })
  const withStore = async (mode, fn) => {
    const db = await open()
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(DB_STORE, mode)
        const store = tx.objectStore(DB_STORE)
        let result
        fn(store, (v) => { result = v })
        tx.oncomplete = () => resolve(result)
        tx.onabort = () => reject(tx.error || new Error('transaction aborted'))
        tx.onerror = () => reject(tx.error || new Error('transaction failed'))
      })
    } finally { db.close() }
  }
  return {
    get: (key) => withStore('readonly', (store, done) => {
      const req = store.get(key)
      req.onsuccess = () => done(req.result === undefined ? null : req.result)
    }),
    // Atomic: the get and the conditional put run in the SAME readwrite
    // transaction — IDB serializes readwrite txns on a store, so two tabs racing
    // here cannot both insert. Returns the value that WON (existing or ours).
    // isUsable (optional, SYNCHRONOUS — an await inside an IDB txn auto-commits
    // it) lets a corrupt existing record be replaced atomically: without it, a
    // separate delete + putIfAbsent lets two tabs interleave and silently
    // un-persist an identity the other tab already signed with.
    putIfAbsent: (key, value, isUsable) => withStore('readwrite', (store, done) => {
      const req = store.get(key)
      req.onsuccess = () => {
        const existing = (req.result === undefined) ? null : req.result
        if (existing !== null && (!isUsable || isUsable(existing))) { done({ value: existing, inserted: false }); return }
        store.put(value, key)
        done({ value, inserted: true })
      }
    }),
    compareAndSwap: (key, expectedPubkey, value) => withStore('readwrite', (store, done) => {
      const req = store.get(key)
      req.onsuccess = () => {
        const existing = (req.result === undefined) ? null : req.result
        const actual = existing && HEX64.test(String(existing.pubkey || '')) ? String(existing.pubkey).toLowerCase() : null
        const expected = expectedPubkey == null ? null : String(expectedPubkey).toLowerCase()
        if (actual !== expected) { done({ swapped: false, value: existing }); return }
        store.put(value, key)
        done({ swapped: true, value })
      }
    }),
    compareAndSwapToken: (key, expectedToken, value) => withStore('readwrite', (store, done) => {
      const req = store.get(key)
      req.onsuccess = () => {
        const existing = (req.result === undefined) ? null : req.result
        if (deviceRecordToken(existing) !== expectedToken) { done({ swapped: false, value: existing }); return }
        store.put(value, key)
        done({ swapped: true, value })
      }
    }),
    compareAndDelete: (key, expectedToken) => withStore('readwrite', (store, done) => {
      const req = store.get(key)
      req.onsuccess = () => {
        const existing = (req.result === undefined) ? null : req.result
        if (deviceRecordToken(existing) !== expectedToken) { done({ deleted: false, value: existing }); return }
        store.delete(key)
        done({ deleted: true, value: existing })
      }
    }),
    delete: (key) => withStore('readwrite', (store, done) => { store.delete(key); done(true) })
  }
}

// Synchronous shape check for a device record — the exact condition under which
// unwrapRecord() would return null. Used INSIDE the atomic putIfAbsent txn (so it
// must not await): a record failing this is unreadable garbage and is replaced.
function usableRecord (rec) {
  return !!(rec && rec.v === 1 && rec.key && rec.iv && rec.ct)
}

// ---- the store ---------------------------------------------------------------
export function createIdentityStore ({ kv } = {}) {
  const backing = kv === undefined ? idbAdapter() : kv
  const sub = subtle()

  async function available () {
    return !!(backing && sub)
  }

  // Wrap an identity entry {pubkey, seed, driveKey, label} into a device record.
  async function wrapEntry (entry) {
    const { seed, pubkey, driveKey, label } = await verifiedIdentityEntry(entry, 'device store')
    const key = await sub.generateKey({ name: 'AES-GCM', length: 256 }, false /* NON-extractable */, ['encrypt', 'decrypt'])
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await sub.encrypt({ name: 'AES-GCM', iv }, key, hexToBytes(seed)))
    return {
      v: 1,
      pubkey,
      driveKey,
      label,
      key, // non-extractable CryptoKey — structured-cloned into IDB, never exportable via JS
      iv,
      ct,
      createdAt: Date.now()
    }
  }

  async function unwrapRecord (rec) {
    if (!rec || rec.v !== 1 || !rec.key || !rec.iv || !rec.ct) return null
    const seedBuf = await sub.decrypt({ name: 'AES-GCM', iv: rec.iv }, rec.key, rec.ct)
    const seed = bytesToHex(seedBuf)
    if (!HEX64.test(seed)) return null
    return verifiedIdentityEntry({ seed, pubkey: rec.pubkey, driveKey: rec.driveKey, label: rec.label }, 'device store')
  }

  return {
    available,

    // Inspect without hiding corruption. `load()` intentionally degrades corrupt
    // state to null for boot compatibility; Settings/import need this stronger
    // surface so the user can deliberately recover instead of being trapped as a
    // permanent lurker. The exact token is consumed by reset/replace CAS methods.
    async inspect () {
      if (!await available()) return { status: 'unavailable', pubkey: null, token: null, entry: null }
      let rec
      try { rec = await backing.get(RECORD_KEY) } catch { return { status: 'unavailable', pubkey: null, token: null, entry: null } }
      if (rec == null) return { status: 'empty', pubkey: null, token: deviceRecordToken(null), entry: null }
      const pubkey = HEX64.test(String(rec.pubkey || '')) ? String(rec.pubkey).toLowerCase() : null
      const token = deviceRecordToken(rec)
      if (!usableRecord(rec)) return { status: 'corrupt', reason: 'malformed', pubkey, token, entry: null }
      try {
        const entry = await unwrapRecord(rec)
        return entry
          ? { status: 'valid', pubkey: entry.pubkey, token, entry }
          : { status: 'corrupt', reason: 'undecryptable', pubkey, token, entry: null }
      } catch {
        return { status: 'corrupt', reason: 'undecryptable', pubkey, token, entry: null }
      }
    },

    // Boot-time restore: the saved device identity (seed decrypted into memory —
    // same in-page exposure as an unlocked vault session), or null. Never throws:
    // a corrupt/undecryptable record degrades to "no device identity".
    async load () {
      try {
        const state = await this.inspect()
        return state.status === 'valid' ? state.entry : null
      } catch { return null }
    },

    // First-write persist with LOAD-OR-ADOPT semantics: wraps OUR entry, then
    // atomically inserts it unless another tab already saved one — in which case
    // the existing identity is returned and the caller must ADOPT it (switch to
    // it BEFORE signing anything). A shape-corrupt existing record is replaced
    // IN THE SAME transaction (usableRecord predicate) — a separate delete+put
    // would let two racing tabs silently un-persist each other's inserts.
    // Returns { entry, adopted }.
    async saveOrAdopt (entry) {
      if (!await available()) throw new Error('device identity store unavailable')
      const candidate = await wrapEntry(entry) // crypto BEFORE the txn (an await inside an IDB txn auto-commits it)
      const res = await backing.putIfAbsent(RECORD_KEY, candidate, usableRecord)
      if (res.inserted) return { entry: { seed: entry.seed, pubkey: candidate.pubkey, driveKey: candidate.driveKey, label: candidate.label }, adopted: false }
      const existing = await unwrapRecord(res.value)
      if (existing) return { entry: existing, adopted: existing.pubkey !== candidate.pubkey }
      // Shape-valid but UNDECRYPTABLE (key/data mismatch): unrecoverable either
      // way. Never racily replace a record another tab may be about to sign
      // with; the public web caller fails closed and remains a lurker.
      throw new Error('device identity store record is undecryptable')
    },

    // Deliberate durable switch/import. Replace exactly the pubkey observed by
    // the caller; another tab changing it first makes this CAS fail closed.
    async replace (entry, { expectedPubkey = null, expectedToken = null } = {}) {
      if (!await available()) throw new Error('device identity store unavailable')
      const candidate = await wrapEntry(entry)
      let result
      if (expectedToken != null) {
        if (!backing || typeof backing.compareAndSwapToken !== 'function') throw new Error('device identity store does not support token-bound atomic replacement')
        result = await backing.compareAndSwapToken(RECORD_KEY, expectedToken, candidate)
      } else {
        if (!backing || typeof backing.compareAndSwap !== 'function') throw new Error('device identity store does not support atomic replacement')
        result = await backing.compareAndSwap(RECORD_KEY, expectedPubkey, candidate)
      }
      if (!result || !result.swapped) throw new Error('device identity changed in another tab; import was not activated')
      const stored = await unwrapRecord(result.value)
      if (!stored || stored.pubkey !== candidate.pubkey) throw new Error('device identity replacement failed verification')
      return { entry: stored, replaced: expectedPubkey != null || expectedToken != null }
    },

    // User-confirmed recovery for a record whose clear header exists but whose
    // encrypted seed cannot be opened. Never deletes a valid record, and the exact
    // token CAS prevents a tab that inspected stale corruption from deleting a
    // replacement installed by another tab before it acquired the writer lock.
    async resetCorrupt ({ expectedToken } = {}) {
      if (!await available()) throw new Error('device identity store unavailable')
      if (!expectedToken || !backing || typeof backing.compareAndDelete !== 'function') throw new Error('device identity store does not support safe corrupt-record reset')
      const state = await this.inspect()
      if (state.status !== 'corrupt') throw new Error('The device identity is no longer corrupt; refusing to reset it.')
      if (state.token !== expectedToken) throw new Error('The device identity changed in another tab; it was not reset.')
      const result = await backing.compareAndDelete(RECORD_KEY, expectedToken)
      if (!result || !result.deleted) throw new Error('The device identity changed in another tab; it was not reset.')
      try {
        if ((await backing.get(RECORD_KEY)) != null) throw new Error('The corrupt device identity could not be removed.')
      } catch (error) {
        if (/could not be removed/.test(String(error && error.message))) throw error
        throw new Error('The corrupt device identity reset could not be verified.')
      }
      return true
    },

    // Sign-out / forget-this-device: BOTH tiers' forget paths call this (a device
    // record surviving a vault clear would silently resurrect the identity).
    // FAIL-CLOSED for key destruction: returns true only when a read-back
    // confirms the record is gone — callers must not report "forgotten" on a
    // swallowed delete failure (the next visitor on a shared machine would be
    // silently signed in as the identity the user explicitly destroyed).
    async clear () {
      if (!backing) return true
      try { await backing.delete(RECORD_KEY) } catch {}
      try { return (await backing.get(RECORD_KEY)) == null } catch { return false }
    }
  }
}

// Mint without activation, durably save-or-adopt, then activate exactly the
// persisted winner. This ordering is the public web writer safety boundary: a
// key that has not survived durable storage is never allowed to sign or publish.
export async function activateDurableIdentity (identity, store, label = 'anon') {
  if (!identity || typeof identity.mintEntry !== 'function' || typeof identity.restoreFromDevice !== 'function') {
    throw new Error('durable identity activation is unsupported')
  }
  if (!store || typeof store.available !== 'function' || !await store.available()) {
    throw new Error('device identity store unavailable')
  }
  const candidate = await identity.mintEntry(label)
  const saved = await store.saveOrAdopt(candidate)
  if (!saved || !saved.entry) throw new Error('device identity was not persisted')
  await identity.restoreFromDevice(saved.entry)
  const active = identity.me && identity.me().pubkey
  if (!active || active !== saved.entry.pubkey) throw new Error('persisted device identity was not activated')
  return saved
}

// Verify the active public-web signer is still backed before EVERY write. A
// decrypted device record is proof on its own. A vault header is accepted only
// when this page actually activated the signer from a decrypted vault/import;
// a forged/corrupt cleartext header cannot bless a session-only key.
export async function assertDurableIdentity (identity, store, { vaultPubkey = null } = {}) {
  const active = identity && identity.me && identity.me().pubkey
  if (!active) throw new Error('No active writer identity')
  let device = null
  try { device = store && typeof store.load === 'function' ? await store.load() : null } catch {}
  if (device && device.pubkey === active) return { kind: 'device', pubkey: active }
  const source = identity && typeof identity.durableSource === 'function' ? identity.durableSource() : null
  const vault = HEX64.test(String(vaultPubkey || '')) ? String(vaultPubkey).toLowerCase() : null
  if (vault === active && source && source.pubkey === active && /vault/.test(source.kind)) return { kind: 'vault', pubkey: active }
  throw new Error('Active identity is not backed by this device or an unlocked matching vault; refusing a session-only write')
}

export async function ensureDurableIdentityForWrite (identity, store, { vaultPubkey = null, label = 'anon' } = {}) {
  if (!identity || !identity.me) throw new Error('durable identity activation is unsupported')
  if (!identity.me().pubkey) await activateDurableIdentity(identity, store, label)
  await assertDurableIdentity(identity, store, { vaultPubkey })
  return identity.me()
}

// Durable import/switch coordinator. The matching vault is persisted first, the
// device tier is replaced with an atomic pubkey CAS, and only then is the new
// signer activated. If the CAS loses a multi-tab race, restore the prior vault
// bytes so the two durability tiers never intentionally diverge.
export async function replaceDurableIdentity (identity, store, entry, { expectedPubkey = null, expectedToken = null, persistVault, rollbackVault } = {}) {
  if (!identity || typeof identity.restoreFromDurableImport !== 'function') throw new Error('durable identity import is unsupported')
  if (typeof persistVault !== 'function') throw new Error('durable identity import requires a matching vault')
  const verified = await verifiedIdentityEntry(entry, 'identity import')
  await persistVault(verified)
  let replaced
  try {
    replaced = await store.replace(verified, { expectedPubkey, expectedToken })
  } catch (error) {
    try { if (typeof rollbackVault === 'function') await rollbackVault() } catch {}
    throw error
  }
  await identity.restoreFromDurableImport(replaced.entry)
  await assertDurableIdentity(identity, store, { vaultPubkey: replaced.entry.pubkey })
  return replaced
}

// Map-backed kv for Node tests (Node ≥20 has webcrypto but no IndexedDB). Kept
// here so tests and any future runtime share one reference implementation —
// including the isUsable replace-in-place semantics of the IDB adapter.
export function memoryKv () {
  const m = new Map()
  return {
    get: async (k) => (m.has(k) ? m.get(k) : null),
    putIfAbsent: async (k, v, isUsable) => {
      const existing = m.has(k) ? m.get(k) : null
      if (existing != null && (!isUsable || isUsable(existing))) return { value: existing, inserted: false }
      m.set(k, v)
      return { value: v, inserted: true }
    },
    compareAndSwap: async (k, expectedPubkey, v) => {
      const existing = m.has(k) ? m.get(k) : null
      const actual = existing && HEX64.test(String(existing.pubkey || '')) ? String(existing.pubkey).toLowerCase() : null
      const expected = expectedPubkey == null ? null : String(expectedPubkey).toLowerCase()
      if (actual !== expected) return { swapped: false, value: existing }
      m.set(k, v)
      return { swapped: true, value: v }
    },
    compareAndSwapToken: async (k, expectedToken, v) => {
      const existing = m.has(k) ? m.get(k) : null
      if (deviceRecordToken(existing) !== expectedToken) return { swapped: false, value: existing }
      m.set(k, v)
      return { swapped: true, value: v }
    },
    compareAndDelete: async (k, expectedToken) => {
      const existing = m.has(k) ? m.get(k) : null
      if (deviceRecordToken(existing) !== expectedToken) return { deleted: false, value: existing }
      m.delete(k)
      return { deleted: true, value: existing }
    },
    delete: async (k) => m.delete(k)
  }
}
