// identity.js — who the user is and how they sign.
//
//   BridgeIdentity — window.pear.identity: a stable per-app ed25519 sub-key and
//                    real signatures over pear.app.<driveKey>:<ns>:<payload>.
//   DevIdentity    — a roster of simulated users, each with a REAL ed25519 keypair
//                    (via crypto.js). The active user is per-tab (sessionStorage)
//                    so two tabs are two people. Seeds are kept in localStorage —
//                    fine for local simulation; they are the user's secret key.
//
//   ready(), me() -> { pubkey, driveKey, label },
//   sign(payload, namespace) -> { signature, publicKey, driveKey, namespace, algorithm },
//   isDev, listUsers(), switchUser(pub), createUser(name)  (createUser is async)

import { genKeyPair, sign as edSign } from './crypto.js'
import { hasAnyPearBridgeSurface, hasIdentityPearSurface, resolvePear } from './pear-api.js'

const NS = 'peerit'
const HEX64 = /^[0-9a-f]{64}$/i

class DevIdentity {
  // persistSeed: whether the raw Ed25519 SEED is allowed to be written to disk
  // (localStorage) in CLEARTEXT. This is a bearer secret — anyone who reads it can
  // sign as the user forever, unrevocably. So it defaults to FALSE: the roster
  // (pubkey/driveKey/label) and the seeds are held in memory only, per browsing
  // session. On peerit.site (web mode) DevIdentity is the PRODUCTION signing path,
  // so a persisted cleartext seed there is directly XSS-/shared-machine-exfiltrable;
  // in-memory-only keeps a same-origin read from yielding a permanent signing key.
  // The durable, safe way to move a key across reloads/devices is the
  // passphrase-encrypted envelope in identity-export.js — never cleartext at rest.
  // Only opt in (persistSeed:true) for a genuinely local dev fallback.
  constructor (storage, session, opts = {}) {
    this.isDev = true
    this.storage = storage
    this.session = session
    this.persistSeed = opts.persistSeed === true
    // lazy: do NOT mint a keypair at ready() — web visitors are LURKERS until
    // their first write. A reader needs no identity, and eager minting is what
    // turned every refresh into a new "user" plus a ghost outbox and a permanent
    // swarm descriptor on the relay (the request amplification behind the per-IP
    // 429 starvation). ensureActive() mints on the first write instead.
    this.lazy = opts.lazy === true
    this.ROSTER = 'peerit:dev:users'
    // In-memory roster + seed store, used whenever persistSeed is false so that no
    // seed (and, to avoid unusable ghost entries, no roster) is written to disk.
    this._memRoster = null
    this._ensuring = null
  }

  async ready () {
    let roster = this._roster()
    if (!roster.length && !this.lazy) { roster = [await this._mint('anon')]; this._saveRoster(roster) }
    let active = this.session && this.session.getItem('peerit:dev:active')
    if (!active || !roster.find(u => u.pubkey === active)) {
      // Lazy + empty roster → stay identity-less (me().pubkey === null). The
      // sessionStorage pointer may name a pubkey from a previous page's in-memory
      // roster; without its seed it is unusable, so it never becomes active.
      active = roster.length ? roster[0].pubkey : null
      if (this.session && active) this.session.setItem('peerit:dev:active', active)
    }
    this._active = active
    return this
  }

  // Mint-on-first-write: idempotent and SINGLE-FLIGHT — two concurrent writes
  // must not mint two identities (that would recreate the churn this exists to
  // kill). Callers check read-only mode BEFORE calling (fail-closed: a read-only
  // deployment never mints). Returns me().
  async ensureActive (label = 'anon') {
    if (this._meEntry()) return this.me()
    if (!this._ensuring) {
      this._ensuring = this.createUser(label).finally(() => { this._ensuring = null })
    }
    await this._ensuring
    return this.me()
  }

  _roster () {
    if (!this.persistSeed) return this._memRoster ? this._memRoster.map(u => ({ ...u })) : []
    try { const s = this.storage.getItem(this.ROSTER); return s ? JSON.parse(s) : [] } catch { return [] }
  }

  _saveRoster (r) {
    if (!this.persistSeed) {
      // Hold the full roster (INCLUDING seeds) in memory only; never touch disk.
      // Also proactively clear any legacy cleartext roster a prior build left behind.
      this._memRoster = r.map(u => ({ ...u }))
      try { if (this.storage.getItem(this.ROSTER) != null && typeof this.storage.removeItem === 'function') this.storage.removeItem(this.ROSTER) } catch {}
      return
    }
    this.storage.setItem(this.ROSTER, JSON.stringify(r))
  }

  async _mint (name) {
    const { seedHex, pubHex } = await genKeyPair()
    return { pubkey: pubHex, seed: seedHex, driveKey: pubHex, label: name }
  }

  _meEntry () { return this._roster().find(x => x.pubkey === this._active) || null }
  me () {
    const u = this._meEntry() || { pubkey: this._active, driveKey: this._active, label: 'anon' }
    return { pubkey: u.pubkey, driveKey: u.driveKey, label: u.label }
  }

  async sign (payload, namespace = NS) {
    const u = this._meEntry()
    if (!u) throw new Error('no active identity')
    const tag = `pear.app.${u.driveKey}:${namespace}:`
    const signature = await edSign(u.seed, tag + payload)
    return { signature, publicKey: u.pubkey, driveKey: u.driveKey, namespace, algorithm: 'ed25519' }
  }

  listUsers () { return this._roster().map(u => ({ pubkey: u.pubkey, driveKey: u.driveKey, label: u.label })) }
  switchUser (pub) {
    if (this._roster().find(u => u.pubkey === pub)) {
      this._active = pub
      if (this.session) this.session.setItem('peerit:dev:active', pub)
      return true
    }
    return false
  }
  async createUser (name) {
    const u = await this._mint(name || 'anon')
    const roster = this._roster(); roster.push(u); this._saveRoster(roster)
    this._active = u.pubkey
    if (this.session) this.session.setItem('peerit:dev:active', u.pubkey)
    return { pubkey: u.pubkey, driveKey: u.driveKey, label: u.label }
  }

  // The active user's full secret entry (INCLUDING the seed), for identity export
  // only. me() never exposes the seed; callers must treat this as a bearer secret.
  currentSeedEntry () {
    const u = this._meEntry()
    return u ? { seed: u.seed, pubkey: u.pubkey, driveKey: u.driveKey, label: u.label } : null
  }

  // Restore a durable identity decrypted from the passphrase vault
  // (identity-vault.js) into the IN-MEMORY roster and make it active. This is the
  // A1 in-memory path — the seed is injected into _memRoster (when persistSeed is
  // false, i.e. the web/production case) and never re-touches disk; the ciphertext
  // vault on disk stays the only at-rest copy. Semantically identical to addUser,
  // named separately so the boot/unlock flow reads clearly.
  async restoreFromVault (entry) { return this.addUser(entry) }

  // Add an externally-provided identity (from importIdentity) to the roster and
  // switch to it — the "add to roster + switch" import model. Dedupes by pubkey.
  async addUser (entry) {
    const seed = String(entry && entry.seed || '').toLowerCase()
    const pubkey = String(entry && entry.pubkey || '').toLowerCase()
    if (!HEX64.test(seed) || !HEX64.test(pubkey)) throw new Error('Cannot add identity: invalid seed or public key.')
    const driveKey = String(entry && entry.driveKey || pubkey).toLowerCase()
    const label = entry && entry.label ? String(entry.label) : 'imported'
    const roster = this._roster()
    const existing = roster.find(u => u.pubkey === pubkey)
    if (existing) {
      existing.seed = seed
      existing.driveKey = driveKey
      if (entry && entry.label) existing.label = label
    } else {
      roster.push({ pubkey, seed, driveKey, label })
    }
    this._saveRoster(roster)
    this._active = pubkey
    if (this.session) this.session.setItem('peerit:dev:active', pubkey)
    return this.me()
  }
}

class BridgeIdentity {
  constructor (pearIdentity) { this.isDev = false; this.identity = pearIdentity }
  async ready () {
    const r = await this.identity.getPublicKey()
    this._pub = r.publicKey
    this._driveKey = r.driveKey
    return this
  }
  me () { return { pubkey: this._pub, driveKey: this._driveKey, label: null } }
  async sign (payload, namespace = NS) {
    const r = await this.identity.sign(String(payload), namespace)
    return { signature: r.signature, publicKey: r.publicKey || this._pub, driveKey: this._driveKey, namespace, algorithm: r.algorithm || 'ed25519' }
  }
  listUsers () { return [this.me()] }
  switchUser () { return false }
  async createUser () { return this.me() }
  // The bridge identity always exists (PearBrowser provisions it); ensureActive is
  // a no-op for API parity with DevIdentity's lazy mint-on-first-write.
  async ensureActive () { return this.me() }
}

export function createIdentity (opts = {}) {
  const pear = resolvePear(opts)
  if (hasIdentityPearSurface(pear) && !opts.forceDev) return new BridgeIdentity(pear.identity)
  if (hasAnyPearBridgeSurface(pear) && !opts.forceDev) {
    throw new Error('PearBrowser bridge is present but identity signing is unavailable; refusing to fall back to dev identity.')
  }
  const storage = opts.storage || (typeof localStorage !== 'undefined' ? localStorage : memShim())
  const session = opts.session || (typeof sessionStorage !== 'undefined' ? sessionStorage : memShim())
  // persistSeed is OFF unless a caller explicitly opts in (local dev fallback). The
  // web/production path (forceDev) must never enable it: a persisted cleartext seed
  // is a permanent, unrevocable sign-as-victim key on same-origin read/XSS.
  // lazy (web mode): no keypair until the first write — see DevIdentity.ensureActive.
  return new DevIdentity(storage, session, { persistSeed: opts.persistSeed === true, lazy: opts.lazy === true })
}

function memShim () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }
}

export { DevIdentity, BridgeIdentity }
