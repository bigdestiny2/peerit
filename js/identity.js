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
  constructor (storage, session) {
    this.isDev = true
    this.storage = storage
    this.session = session
    this.ROSTER = 'peerit:dev:users'
  }

  async ready () {
    let roster = this._roster()
    if (!roster.length) { roster = [await this._mint('anon')]; this._saveRoster(roster) }
    let active = this.session && this.session.getItem('peerit:dev:active')
    if (!active || !roster.find(u => u.pubkey === active)) {
      active = roster[0].pubkey
      if (this.session) this.session.setItem('peerit:dev:active', active)
    }
    this._active = active
    return this
  }

  _roster () { try { const s = this.storage.getItem(this.ROSTER); return s ? JSON.parse(s) : [] } catch { return [] } }
  _saveRoster (r) { this.storage.setItem(this.ROSTER, JSON.stringify(r)) }

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
}

export function createIdentity (opts = {}) {
  const pear = resolvePear(opts)
  if (hasIdentityPearSurface(pear) && !opts.forceDev) return new BridgeIdentity(pear.identity)
  if (hasAnyPearBridgeSurface(pear) && !opts.forceDev) {
    throw new Error('PearBrowser bridge is present but identity signing is unavailable; refusing to fall back to dev identity.')
  }
  const storage = opts.storage || (typeof localStorage !== 'undefined' ? localStorage : memShim())
  const session = opts.session || (typeof sessionStorage !== 'undefined' ? sessionStorage : memShim())
  return new DevIdentity(storage, session)
}

function memShim () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }
}

export { DevIdentity, BridgeIdentity }
