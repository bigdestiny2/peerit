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

const DB_NAME = 'peerit-identity'
const DB_STORE = 'device'
const RECORD_KEY = 'identity:v1'
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

// ---- IndexedDB kv adapter (browser) -----------------------------------------
// Minimal surface: get / putIfAbsent (atomic within one readwrite txn) / delete.
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
    putIfAbsent: (key, value) => withStore('readwrite', (store, done) => {
      const req = store.get(key)
      req.onsuccess = () => {
        if (req.result !== undefined && req.result !== null) { done({ value: req.result, inserted: false }); return }
        store.put(value, key)
        done({ value, inserted: true })
      }
    }),
    delete: (key) => withStore('readwrite', (store, done) => { store.delete(key); done(true) })
  }
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
    const seed = String((entry && entry.seed) || '').toLowerCase()
    const pubkey = String((entry && entry.pubkey) || '').toLowerCase()
    if (!HEX64.test(seed) || !HEX64.test(pubkey)) throw new Error('device store: invalid identity entry')
    const key = await sub.generateKey({ name: 'AES-GCM', length: 256 }, false /* NON-extractable */, ['encrypt', 'decrypt'])
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await sub.encrypt({ name: 'AES-GCM', iv }, key, hexToBytes(seed)))
    return {
      v: 1,
      pubkey,
      driveKey: String((entry && entry.driveKey) || pubkey).toLowerCase(),
      label: (entry && entry.label) ? String(entry.label) : 'anon',
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
    return { seed, pubkey: rec.pubkey, driveKey: rec.driveKey, label: rec.label }
  }

  return {
    available,

    // Boot-time restore: the saved device identity (seed decrypted into memory —
    // same in-page exposure as an unlocked vault session), or null. Never throws:
    // a corrupt/undecryptable record degrades to "no device identity".
    async load () {
      try {
        if (!await available()) return null
        const rec = await backing.get(RECORD_KEY)
        return rec ? await unwrapRecord(rec) : null
      } catch { return null }
    },

    // First-write persist with LOAD-OR-ADOPT semantics: wraps OUR entry, then
    // atomically inserts it unless another tab already saved one — in which case
    // the existing identity is returned and the caller must ADOPT it (switch to
    // it BEFORE signing anything). Returns { entry, adopted }.
    async saveOrAdopt (entry) {
      if (!await available()) throw new Error('device identity store unavailable')
      const candidate = await wrapEntry(entry) // crypto BEFORE the txn (awaits inside an IDB txn auto-commit it)
      const res = await backing.putIfAbsent(RECORD_KEY, candidate)
      if (res.inserted) return { entry: { seed: entry.seed, pubkey: candidate.pubkey, driveKey: candidate.driveKey, label: candidate.label }, adopted: false }
      const existing = await unwrapRecord(res.value)
      if (existing) return { entry: existing, adopted: existing.pubkey !== candidate.pubkey }
      // Existing record is corrupt/undecryptable: replace it with ours.
      await backing.delete(RECORD_KEY)
      const retry = await backing.putIfAbsent(RECORD_KEY, candidate)
      if (retry.inserted) return { entry: { seed: entry.seed, pubkey: candidate.pubkey, driveKey: candidate.driveKey, label: candidate.label }, adopted: false }
      const winner = await unwrapRecord(retry.value)
      if (!winner) throw new Error('device identity store is corrupt')
      return { entry: winner, adopted: winner.pubkey !== candidate.pubkey }
    },

    // Sign-out / forget-this-device: BOTH tiers' forget paths call this (a device
    // record surviving a vault clear would silently resurrect the identity).
    async clear () {
      try { if (backing) await backing.delete(RECORD_KEY) } catch {}
    }
  }
}

// Map-backed kv for Node tests (Node ≥20 has webcrypto but no IndexedDB). Kept
// here so tests and any future runtime share one reference implementation.
export function memoryKv () {
  const m = new Map()
  return {
    get: async (k) => (m.has(k) ? m.get(k) : null),
    putIfAbsent: async (k, v) => {
      if (m.has(k) && m.get(k) != null) return { value: m.get(k), inserted: false }
      m.set(k, v)
      return { value: v, inserted: true }
    },
    delete: async (k) => m.delete(k)
  }
}
