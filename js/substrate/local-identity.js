// Replacement-browser signing identity.
//
// This runtime is intentionally smaller than identity.js: it never probes a
// Pear host bridge, never writes a cleartext seed, and never selects a network
// backend. A fresh instance is an identity-less lurker. The first explicit
// write is coordinated by identity-store.js, which persists-or-adopts one
// encrypted device identity before this object is allowed to sign.

import {
  genKeyPair,
  isSecure,
  ready as cryptoReady,
  sign as edSign,
  signBytes
} from '../crypto.js'
import { verifiedIdentityEntry } from '../identity-primitives.js'

const NAMESPACE = 'peerit'
const AUTHOR_BIND_DOMAIN = new TextEncoder().encode('peerit.hiverelay.author-bind.v1')
const MAX_AUTHOR_BIND_PREFIX_BYTES = 2 * 1024 * 1024

function authorBindPrefix (value) {
  if (!(value instanceof Uint8Array)) {
    const error = new TypeError('AuthorBindV1 signing prefix must be a Uint8Array')
    error.code = 'PEERIT_AUTHOR_BIND_PREFIX_INVALID'
    throw error
  }
  if (value.byteLength < 1 || value.byteLength > MAX_AUTHOR_BIND_PREFIX_BYTES) {
    const error = new RangeError('AuthorBindV1 signing prefix is outside the bounded protocol range')
    error.code = 'PEERIT_AUTHOR_BIND_PREFIX_INVALID'
    throw error
  }
  const output = new Uint8Array(AUTHOR_BIND_DOMAIN.byteLength + value.byteLength)
  output.set(AUTHOR_BIND_DOMAIN)
  output.set(value, AUTHOR_BIND_DOMAIN.byteLength)
  return output
}

function publicIdentity (entry) {
  return Object.freeze({
    pubkey: entry ? entry.pubkey : null,
    driveKey: entry ? entry.driveKey : null,
    label: entry ? entry.label : 'lurker'
  })
}

export class PeeritLocalIdentityV1 {
  constructor () {
    this.isDev = false
    this._entry = null
    this._durableSource = null
    this._ready = null
  }

  async ready () {
    if (!this._ready) {
      this._ready = cryptoReady().then(() => {
        if (!isSecure()) {
          const error = new Error('Secure Ed25519 is unavailable; local authoring remains blocked.')
          error.code = 'PEERIT_LOCAL_CRYPTO_UNAVAILABLE'
          throw error
        }
        return this
      })
    }
    return this._ready
  }

  me () { return publicIdentity(this._entry) }

  listUsers () { return this._entry ? [publicIdentity(this._entry)] : [] }

  switchUser (pubkey) {
    return !!(this._entry && this._entry.pubkey === pubkey)
  }

  async mintEntry (label = 'anon') {
    await this.ready()
    const { seedHex, pubHex } = await genKeyPair()
    return Object.freeze({
      seed: seedHex,
      pubkey: pubHex,
      driveKey: pubHex,
      label: String(label || 'anon').slice(0, 32)
    })
  }

  async _replace (entry, source) {
    const verified = await verifiedIdentityEntry(entry, 'replacement browser identity')
    this._entry = Object.freeze({ ...verified })
    this._durableSource = source
      ? Object.freeze({ kind: source, pubkey: verified.pubkey })
      : null
    return this.me()
  }

  restoreFromDevice (entry) { return this._replace(entry, 'device') }

  restoreFromVault (entry) { return this._replace(entry, 'vault') }

  restoreFromDurableImport (entry) { return this._replace(entry, 'device+vault') }

  async addUser (entry) { return this._replace(entry, null) }

  async createUser () {
    const error = new Error('Replacement browser identities must be persisted before activation.')
    error.code = 'PEERIT_DURABLE_IDENTITY_REQUIRED'
    throw error
  }

  async ensureActive () {
    if (!this._entry) {
      const error = new Error('Replacement browser identities must be activated through the durable device store.')
      error.code = 'PEERIT_DURABLE_IDENTITY_REQUIRED'
      throw error
    }
    return this.me()
  }

  durableSource () {
    return this._durableSource ? Object.freeze({ ...this._durableSource }) : null
  }

  currentSeedEntry () {
    return this._entry ? Object.freeze({ ...this._entry }) : null
  }

  deactivate () {
    this._entry = null
    this._durableSource = null
    return this.me()
  }

  async sign (payload, namespace = NAMESPACE) {
    await this.ready()
    const entry = this._entry
    if (!entry) {
      const error = new Error('No active durable identity')
      error.code = 'PEERIT_DURABLE_IDENTITY_REQUIRED'
      throw error
    }
    if (namespace !== NAMESPACE) {
      const error = new Error('Replacement browser identity refuses a foreign signing namespace.')
      error.code = 'PEERIT_SIGNING_NAMESPACE_INVALID'
      throw error
    }
    const envelope = `pear.app.${entry.driveKey}:${NAMESPACE}:${String(payload)}`
    return Object.freeze({
      signature: await edSign(entry.seed, envelope),
      publicKey: entry.pubkey,
      driveKey: entry.driveKey,
      namespace: NAMESPACE,
      algorithm: 'ed25519'
    })
  }

  // Fixed-domain binary signing for the AuthorBindV1 authority only.  This is
  // intentionally not a generic signing escape hatch: callers cannot choose a
  // domain or pass an app-envelope string in place of canonical record bytes.
  async signAuthorBindV1 (prefix) {
    await this.ready()
    const entry = this._entry
    if (!entry) {
      const error = new Error('No active durable identity')
      error.code = 'PEERIT_DURABLE_IDENTITY_REQUIRED'
      throw error
    }
    const signature = await signBytes(entry.seed, authorBindPrefix(prefix))
    if (this._entry !== entry || this._entry.pubkey !== entry.pubkey) {
      const error = new Error('Active durable identity changed while AuthorBindV1 was signing')
      error.code = 'PEERIT_AUTHOR_BIND_IDENTITY_CHANGED'
      throw error
    }
    return new Uint8Array(signature)
  }
}

export function createPeeritLocalIdentityV1 () {
  return new PeeritLocalIdentityV1()
}
