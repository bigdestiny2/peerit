// Host-backed signing identity for the replacement browser runtime.
//
// When peerit runs inside Pear Browser, the browser provisions a per-app
// identity behind window.pear.identity. This adapter signs with that host
// identity instead of minting a browser-local key. No seed ever crosses the
// bridge: the host returns { publicKey, driveKey } once and then only
// signatures. Records verify unchanged everywhere — verifyRecord recomputes
// pear.app.<driveKey>:peerit:<canonical> from record fields only, and _dk is
// the site drive key rather than the signer key (_dk !== _k).

const NAMESPACE = 'peerit'
const HEX64 = /^[0-9a-f]{64}$/

function coded (code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function unsupported () {
  return coded('PEERIT_HOST_IDENTITY_UNSUPPORTED',
    'The Pear host identity owns key lifecycle; peerit cannot mint, import, restore, or deactivate it.')
}

export class PeeritHostIdentityV1 {
  constructor (pearIdentity) {
    this.isDev = false
    this.isHost = true
    this._identity = pearIdentity
    this._pubkey = null
    this._driveKey = null
    this._ready = null
  }

  async ready () {
    if (!this._ready) {
      this._ready = (async () => {
        const result = await this._identity.getPublicKey()
        const publicKey = result && result.publicKey
        const driveKey = result && result.driveKey
        if (!HEX64.test(publicKey || '') || !HEX64.test(driveKey || '')) {
          throw coded('PEERIT_HOST_IDENTITY_INVALID',
            'Pear host returned a malformed identity; signing remains blocked.')
        }
        this._pubkey = publicKey
        this._driveKey = driveKey
        return this
      })()
      this._ready.catch(() => { this._ready = null })
    }
    return this._ready
  }

  me () {
    return Object.freeze({
      pubkey: this._pubkey,
      driveKey: this._driveKey,
      label: 'pear host'
    })
  }

  listUsers () { return this._pubkey ? [this.me()] : [] }

  switchUser () { return false }

  // The host identity already exists (Pear Browser provisions it per app), so
  // activation is a readiness check rather than a durable-store write.
  async ensureActive () {
    await this.ready()
    const me = this.me()
    if (!me.pubkey) {
      throw coded('PEERIT_HOST_IDENTITY_UNAVAILABLE',
        'Pear host identity is unavailable; authoring remains blocked.')
    }
    return me
  }

  durableSource () {
    return this._pubkey ? Object.freeze({ kind: 'host', pubkey: this._pubkey }) : null
  }

  // A seed never crosses the bridge; there is no local seed entry to expose.
  currentSeedEntry () { return null }

  mintEntry () { throw unsupported() }

  createUser () { throw unsupported() }

  addUser () { throw unsupported() }

  restoreFromDevice () { throw unsupported() }

  restoreFromVault () { throw unsupported() }

  restoreFromDurableImport () { throw unsupported() }

  deactivate () { throw unsupported() }

  signAuthorBindV1 () { throw unsupported() }

  async sign (payload, namespace = NAMESPACE) {
    if (namespace !== NAMESPACE) {
      throw coded('PEERIT_SIGNING_NAMESPACE_INVALID',
        'Pear host identity refuses a foreign signing namespace.')
    }
    await this.ready()
    const pubkey = this._pubkey
    const result = await this._identity.sign(String(payload), NAMESPACE)
    if (!result || result.publicKey !== pubkey) {
      throw coded('PEERIT_WRITER_IDENTITY_CHANGED',
        'Pear host identity changed while signing; the record was not written.')
    }
    return Object.freeze({
      signature: result.signature,
      publicKey: pubkey,
      driveKey: this._driveKey,
      namespace: NAMESPACE,
      algorithm: 'ed25519'
    })
  }
}

export function createPeeritHostIdentityV1 (pearIdentity) {
  return new PeeritHostIdentityV1(pearIdentity)
}
