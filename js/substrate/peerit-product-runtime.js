// Peerit's replacement-only browser composition.
//
// Local use is sovereign: authenticated relay assembly may add delivery targets,
// but it is never an authoring permission. A fresh boot does not inspect or open
// the identity database. The first explicit mutation enters the journal's
// cross-tab writer fence, atomically persists-or-adopts a device identity, signs
// once, and materializes locally before any relay attempt.

import { createData } from '../data.js'
import {
  createIdentityStore,
  ensureDurableIdentityForWrite,
  hasIdentityForgetTombstone
} from '../identity-store.js'
import { createPeeritLocalIdentityV1 } from './local-identity.js'
import { createPeeritSubstrateSync } from './peerit-substrate-sync.js'
import { publicationUiState } from './publication-status.js'

const PRODUCT_RUNTIME_INSTANCES = new WeakSet()
const PRODUCT_SEQ29_AUTHORITIES = new WeakMap()

function immutableNetworkStatus (value) {
  return Object.freeze({
    state: String((value && value.state) || 'blocked-authenticated-browser-runtime'),
    active: value && value.active === true,
    releaseBlockers: Object.freeze([...(value && value.releaseBlockers ? value.releaseBlockers : [])])
  })
}

function immutableInboxStatus (value) {
  const acceptedRecords = Number(value?.acceptedRecords || 0)
  const rejectedEntries = Number(value?.rejectedEntries || 0)
  return Object.freeze({
    state: String(value?.state || 'blocked-public-inbox-bootstrap'),
    active: value?.active === true,
    acceptedRecords: Number.isSafeInteger(acceptedRecords) && acceptedRecords >= 0
      ? acceptedRecords
      : 0,
    rejectedEntries: Number.isSafeInteger(rejectedEntries) && rejectedEntries >= 0
      ? rejectedEntries
      : 0,
    releaseBlockers: Object.freeze([...(value?.releaseBlockers || [])])
  })
}

function localStorageOrNull () {
  try { return globalThis.localStorage || null } catch { return null }
}

export class PeeritProductRuntimeV1 {
  constructor (options = {}) {
    this.storage = options.storage === undefined ? localStorageOrNull() : options.storage
    this.identity = options.identity || createPeeritLocalIdentityV1()
    this.identityStore = options.identityStore || createIdentityStore(options.identityStoreOptions)
    this.sync = options.sync || createPeeritSubstrateSync({
      relays: [],
      relayHints: [],
      requireVerifiedRelayAdapters: true,
      autoFlush: options.autoFlush,
      legacyStorage: this.storage,
      markerStorage: this.storage,
      indexedDB: options.indexedDB,
      IDBKeyRange: options.IDBKeyRange,
      journalDbName: options.journalDbName
    })
    this._network = immutableNetworkStatus(options.networkStatus)
    this._inbox = immutableInboxStatus(options.inboxStatus)
    this._listeners = new Set()
    this._ready = null
    this._destroyed = false
    this._writerActivation = null
    this._unsubscribe = null
    const ensureWriter = () => this.ensureWriter()
    this.data = options.data || createData(this.sync, this.identity, {
      v2: true,
      dispersal: false,
      ensureWriter,
      withWriterSession: operation => this.sync.withLocalWriterSession(operation),
      minBits: options.minBits,
      mint: options.mint
    })
    PRODUCT_RUNTIME_INSTANCES.add(this)
  }

  async ready () {
    if (this._ready) return this._ready
    this._ready = (async () => {
      await this.identity.ready()
      await this.sync.ready()
      // Deliberately do not call identityStore.inspect/load here. On a pristine
      // browser that would create the identity database during lurker boot. A
      // returning author's first mutation atomically adopts the existing record.
      this._unsubscribe = this.sync.onChange(() => this._emit())
      this._emit()
      return this
    })()
    return this._ready
  }

  async ensureWriter () {
    if (this._destroyed) throw new Error('Peerit product runtime is closed')
    if (hasIdentityForgetTombstone(this.storage)) {
      const error = new Error('Identity forget is incomplete; authoring remains blocked until cleanup finishes.')
      error.code = 'PEERIT_IDENTITY_FORGET_INCOMPLETE'
      throw error
    }
    if (!this._writerActivation) {
      this._writerActivation = ensureDurableIdentityForWrite(
        this.identity,
        this.identityStore,
        { label: 'peerit author' }
      ).finally(() => { this._writerActivation = null })
    }
    const identity = await this._writerActivation
    this._emit()
    return identity
  }

  setNetworkStatus (status) {
    this._network = immutableNetworkStatus(status)
    this._emit()
    return this._network
  }

  setInboxDiscoveryStatus (status) {
    this._inbox = immutableInboxStatus(status)
    this._emit()
    return this._inbox
  }

  // Only already-qualified, branded relay adapters may cross this boundary.
  // Raw URLs and descriptor hints are handled by the authenticated consumer.
  setQualifiedRelays (relays) {
    this.sync.setRelays(Array.isArray(relays) ? relays : [])
    this._emit()
  }

  async status () {
    const syncStatus = await this.sync.status()
    return Object.freeze({
      version: 1,
      mode: 'peerit-product-v1',
      identity: this.identity.me(),
      lurker: !this.identity.me().pubkey,
      network: this._network,
      inbox: this._inbox,
      sync: syncStatus,
      publication: publicationUiState(syncStatus)
    })
  }

  onChange (listener) {
    if (typeof listener !== 'function') throw new TypeError('product change listener must be a function')
    this._listeners.add(listener)
    return () => this._listeners.delete(listener)
  }

  _emit () {
    for (const listener of this._listeners) {
      try { listener() } catch (error) { console.error(error) }
    }
  }

  destroy () {
    if (this._destroyed) return
    this._destroyed = true
    if (this._unsubscribe) this._unsubscribe()
    this._unsubscribe = null
    this._listeners.clear()
    this.sync.destroy()
  }
}

export function createPeeritProductRuntimeV1 (options = {}) {
  return new PeeritProductRuntimeV1(options)
}

// A bounded bridge from shipped product authoring to Seq29 publication. It
// exposes neither a seed nor a generic signer. The coordinator may only obtain
// the exact ordinary sync instance and the two fixed protocol signatures used
// to wrap an already-authored intrinsic operation batch.
export function getPeeritProductSeq29AuthoringAuthorityV1 (value) {
  if (!value || !PRODUCT_RUNTIME_INSTANCES.has(value)) {
    const error = new TypeError('The exact Peerit product runtime is required.')
    error.code = 'PEERIT_PRODUCT_RUNTIME_AUTHORITY_REQUIRED'
    throw error
  }
  let authority = PRODUCT_SEQ29_AUTHORITIES.get(value)
  if (authority) return authority
  authority = Object.freeze({
    version: 1,
    substrateSync: value.sync,
    async authorPublicKey () {
      const identity = await value.ensureWriter()
      if (!identity || !/^[0-9a-f]{64}$/.test(String(identity.pubkey || ''))) {
        const error = new Error('A durable Peerit author identity is required.')
        error.code = 'PEERIT_DURABLE_IDENTITY_REQUIRED'
        throw error
      }
      const output = new Uint8Array(32)
      for (let index = 0; index < 32; index++) {
        output[index] = Number.parseInt(identity.pubkey.slice(index * 2, index * 2 + 2), 16)
      }
      return output
    },
    signAuthorBindV1 (prefix) {
      return value.identity.signAuthorBindV1(prefix)
    },
    signPeeritAnnouncementV1 (prefix) {
      return value.identity.signPeeritAnnouncementV1(prefix)
    },
    withSeq29PublicationSession (operation) {
      if (typeof operation !== 'function') {
        throw new TypeError('Seq29 publication session callback is required')
      }
      return value.sync.withLocalWriterSession(operation)
    }
  })
  PRODUCT_SEQ29_AUTHORITIES.set(value, authority)
  return authority
}
