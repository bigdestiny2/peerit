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

function immutableNetworkStatus (value) {
  return Object.freeze({
    state: String((value && value.state) || 'blocked-authenticated-browser-runtime'),
    active: value && value.active === true,
    releaseBlockers: Object.freeze([...(value && value.releaseBlockers ? value.releaseBlockers : [])])
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
