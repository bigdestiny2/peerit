// Transaction backends for Peerit's local blind-substrate journal.
//
// The journal layer above this file owns schemas and invariants. Backends expose
// one deliberately small transactional API so the same CAS/compaction logic runs
// in deterministic tests and in browser IndexedDB. No application record is
// created by ready(); the IndexedDB backend opens lazily only when an existing DB,
// a durable presence marker, or a legacy import is present.

export const JOURNAL_DB_NAME = 'peerit-substrate-journal'
export const JOURNAL_DB_VERSION = 5
export const JOURNAL_MARKER_KEY = 'peerit:substrate-journal:idb:v5:present'

export const JOURNAL_STORES = Object.freeze({
  META: 'meta',
  VIEW: 'view',
  INTENTS: 'intents',
  TARGETS: 'targets',
  DEDUPE: 'dedupe'
})

function clone (value) {
  if (value == null) return value
  if (typeof structuredClone === 'function') return structuredClone(value)
  return JSON.parse(JSON.stringify(value))
}

function compare (left, right) {
  if (left === right) return 0
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left)) return -1
    if (!Array.isArray(right)) return 1
    const length = Math.min(left.length, right.length)
    for (let index = 0; index < length; index++) {
      const result = compare(left[index], right[index])
      if (result) return result
    }
    return compare(left.length, right.length)
  }
  return left < right ? -1 : 1
}

function inQuery (value, query = {}) {
  if (Object.prototype.hasOwnProperty.call(query, 'eq') && compare(value, query.eq) !== 0) return false
  if (query.lower != null) {
    const result = compare(value, query.lower)
    if (query.lowerOpen ? result <= 0 : result < 0) return false
  }
  if (query.upper != null) {
    const result = compare(value, query.upper)
    if (query.upperOpen ? result >= 0 : result > 0) return false
  }
  if (query.prefix != null && !String(value).startsWith(String(query.prefix))) return false
  return true
}

function encodedSize (stores) {
  let total = 0
  const encoder = new TextEncoder()
  for (const [name, rows] of stores) {
    total += encoder.encode(name).byteLength
    for (const [key, value] of rows) total += encoder.encode(String(key) + JSON.stringify(value)).byteLength
  }
  return total
}

function encodedRowSize (key, value) {
  return new TextEncoder().encode(String(key) + JSON.stringify(value)).byteLength
}

function quotaError () {
  const error = new Error('simulated IndexedDB quota exceeded')
  error.name = 'QuotaExceededError'
  return error
}

export function createMemoryJournalState (options = {}) {
  const stores = new Map()
  for (const name of Object.values(JOURNAL_STORES)) stores.set(name, new Map())
  if (options.includeLegacyStore) stores.set('state', new Map())
  return {
    stores,
    storeVersions: new Map([...stores.keys()].map(name => [name, 0])),
    scanCache: new Map(),
    encodedBytes: encodedSize(stores),
    tail: Promise.resolve(),
    writeTransactions: 0,
    readonlyTransactions: 0,
    quotaBytes: Number.isSafeInteger(options.quotaBytes) ? options.quotaBytes : Infinity,
    failNextCommit: null,
    opened: false,
    schemaVersion: options.schemaVersion || JOURNAL_DB_VERSION
  }
}

const DELETED = Symbol('deleted journal row')

const MEMORY_INDEX_KEY_PATHS = Object.freeze({
  updatedAt: 'updatedAt',
  createdAt: 'createdAt',
  completedAt: 'completedAt',
  pendingOrderKey: 'pendingOrderKey',
  intentId: 'intentId',
  state: 'state',
  leaseUntil: 'leaseUntil',
  expiresAt: 'expiresAt',
  targetStateDueOrder: Object.freeze(['targetId', 'state', 'nextAttemptAt', 'updatedAt', 'attempts', 'intentId']),
  targetStateLeaseOrder: Object.freeze(['targetId', 'state', 'leaseUntil', 'intentId']),
  stateLeaseOrder: Object.freeze(['state', 'leaseUntil', 'intentId', 'targetId'])
})

function indexOrder (value, index) {
  const keyPath = MEMORY_INDEX_KEY_PATHS[index]
  if (keyPath == null) throw new Error(`journal index ${index} does not exist`)
  return Array.isArray(keyPath) ? keyPath.map(field => value[field]) : value[keyPath]
}

function scanCacheKey (name, index) {
  return JSON.stringify([name, index || null])
}

function ensureMemoryScanState (shared) {
  if (!(shared.storeVersions instanceof Map)) {
    shared.storeVersions = new Map([...shared.stores.keys()].map(name => [name, 0]))
  }
  if (!(shared.scanCache instanceof Map)) shared.scanCache = new Map()
}

function cachedMemoryRows (shared, name, index) {
  ensureMemoryScanState(shared)
  const key = scanCacheKey(name, index)
  const version = shared.storeVersions.get(name) || 0
  const cached = shared.scanCache.get(key)
  if (cached && cached.version === version) return cached.rows
  const rows = []
  for (const [primaryKey, value] of shared.stores.get(name)) {
    const order = index ? indexOrder(value, index) : primaryKey
    if (index && (order === undefined || order === null)) continue
    rows.push({ key: primaryKey, value, order })
  }
  rows.sort((left, right) => compare(left.order, right.order) || compare(left.key, right.key))
  shared.scanCache.set(key, { version, rows })
  return rows
}

function forwardStart (rows, query) {
  let target
  let open = false
  if (Object.prototype.hasOwnProperty.call(query, 'eq')) target = query.eq
  else if (query.lower != null) {
    target = query.lower
    open = query.lowerOpen === true
  } else if (query.prefix != null) target = String(query.prefix)
  else return 0
  let lower = 0
  let upper = rows.length
  while (lower < upper) {
    const middle = (lower + upper) >>> 1
    const result = compare(rows[middle].order, target)
    if (result < 0 || (open && result === 0)) lower = middle + 1
    else upper = middle
  }
  return lower
}

function reverseStart (rows, query) {
  let target
  let open = false
  if (Object.prototype.hasOwnProperty.call(query, 'eq')) target = query.eq
  else if (query.upper != null) {
    target = query.upper
    open = query.upperOpen === true
  } else if (query.prefix != null) target = String(query.prefix) + '\uffff'
  else return rows.length - 1
  let lower = 0
  let upper = rows.length
  while (lower < upper) {
    const middle = (lower + upper) >>> 1
    const result = compare(rows[middle].order, target)
    if (result < 0 || (!open && result === 0)) lower = middle + 1
    else upper = middle
  }
  return lower - 1
}

function scanCachedMemoryRows (rows, query, limit) {
  const selected = []
  if (query.direction === 'prev') {
    for (let index = reverseStart(rows, query); index >= 0 && selected.length < limit; index--) {
      const row = rows[index]
      if (inQuery(row.order, query)) selected.push({ key: row.key, value: clone(row.value) })
    }
  } else {
    for (let index = forwardStart(rows, query); index < rows.length && selected.length < limit; index++) {
      const row = rows[index]
      if (inQuery(row.order, query)) selected.push({ key: row.key, value: clone(row.value) })
    }
  }
  return selected
}

class MemoryTransaction {
  constructor (stores, writable = false, shared = null) {
    this.stores = stores
    this.writable = writable
    this.shared = shared
    this.changes = new Map()
  }

  _store (name) {
    const store = this.stores.get(name)
    if (!store) throw new Error(`journal object store ${name} does not exist`)
    return store
  }

  async get (name, key) {
    const changes = this.changes.get(name)
    const value = changes && changes.has(key) ? changes.get(key) : this._store(name).get(key)
    if (value === DELETED) return null
    return value === undefined ? null : clone(value)
  }

  async put (name, value, key) {
    const actualKey = key == null
      ? value && (value.key ?? value.intentId)
      : key
    if (actualKey == null) throw new TypeError(`journal ${name} put requires a key`)
    if (!this.writable) throw new Error('journal readonly transaction cannot write')
    this._store(name)
    let changes = this.changes.get(name)
    if (!changes) { changes = new Map(); this.changes.set(name, changes) }
    changes.set(actualKey, clone(value))
  }

  async delete (name, key) {
    if (!this.writable) throw new Error('journal readonly transaction cannot delete')
    this._store(name)
    let changes = this.changes.get(name)
    if (!changes) { changes = new Map(); this.changes.set(name, changes) }
    changes.set(key, DELETED)
  }

  async count (name, query = {}) {
    return (await this.scan(name, query)).length
  }

  async scan (name, query = {}) {
    this._store(name)
    const index = query.index || null
    const limit = Number.isSafeInteger(query.limit) && query.limit >= 0 ? query.limit : Infinity
    if (this.shared && !this.changes.has(name)) {
      return scanCachedMemoryRows(cachedMemoryRows(this.shared, name, index), query, limit)
    }
    const rows = []
    const source = this._store(name)
    const changes = this.changes.get(name)
    const entries = changes ? new Map(source) : source
    if (changes) {
      for (const [key, value] of changes) {
        if (value === DELETED) entries.delete(key)
        else entries.set(key, value)
      }
    }
    for (const [key, raw] of entries) {
      const value = clone(raw)
      const order = index ? indexOrder(value, index) : key
      if (index && (order === undefined || order === null)) continue
      if (!inQuery(order, query)) continue
      rows.push({ key, value, order })
    }
    rows.sort((left, right) => compare(left.order, right.order) || compare(left.key, right.key))
    if (query.direction === 'prev') rows.reverse()
    const boundedLimit = limit === Infinity ? rows.length : limit
    return rows.slice(0, boundedLimit).map(({ key, value }) => ({ key, value }))
  }

  encodedDelta () {
    let delta = 0
    for (const [name, changes] of this.changes) {
      const store = this._store(name)
      for (const [key, value] of changes) {
        const before = store.get(key)
        if (before !== undefined) delta -= encodedRowSize(key, before)
        if (value !== DELETED) delta += encodedRowSize(key, value)
      }
    }
    return delta
  }

  commit () {
    for (const [name, changes] of this.changes) {
      const store = this._store(name)
      for (const [key, value] of changes) {
        if (value === DELETED) store.delete(key)
        else store.set(key, value)
      }
      if (this.shared) {
        ensureMemoryScanState(this.shared)
        this.shared.storeVersions.set(name, (this.shared.storeVersions.get(name) || 0) + 1)
        for (const key of this.shared.scanCache.keys()) {
          if (key === scanCacheKey(name, null) || key.startsWith(`[${JSON.stringify(name)},`)) {
            this.shared.scanCache.delete(key)
          }
        }
      }
    }
  }
}

export class MemoryJournalBackend {
  constructor (options = {}) {
    this.shared = options.shared || createMemoryJournalState(options)
  }

  async ready () {
    this.shared.opened = true
    return { opened: true, dormant: false, schemaVersion: this.shared.schemaVersion }
  }

  hasStore (name) { return this.shared.stores.has(name) }

  async transaction (storeNames, mode, operation) {
    const run = async () => {
      const writable = mode === 'readwrite'
      if (writable) this.shared.writeTransactions++
      else this.shared.readonlyTransactions++
      const transaction = new MemoryTransaction(this.shared.stores, writable, this.shared)
      const result = await operation(transaction)
      if (writable) {
        if (this.shared.failNextCommit) {
          const error = this.shared.failNextCommit
          this.shared.failNextCommit = null
          throw error
        }
        const currentBytes = Number.isSafeInteger(this.shared.encodedBytes)
          ? this.shared.encodedBytes
          : encodedSize(this.shared.stores)
        const nextBytes = currentBytes + transaction.encodedDelta()
        if (nextBytes > this.shared.quotaBytes) throw quotaError()
        transaction.commit()
        this.shared.encodedBytes = nextBytes
      }
      return result
    }
    const result = this.shared.tail.then(run, run)
    this.shared.tail = result.then(() => undefined, () => undefined)
    return result
  }

  corrupt (store, key, value) {
    this.shared.stores.get(store).set(key, clone(value))
    this.shared.encodedBytes = null
    ensureMemoryScanState(this.shared)
    this.shared.storeVersions.set(store, (this.shared.storeVersions.get(store) || 0) + 1)
    for (const cacheKey of this.shared.scanCache.keys()) {
      if (cacheKey === scanCacheKey(store, null) || cacheKey.startsWith(`[${JSON.stringify(store)},`)) {
        this.shared.scanCache.delete(cacheKey)
      }
    }
  }

  async close () {}
}

function requestResult (request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result === undefined ? null : request.result)
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'))
  })
}

function makeRange (keyRange, query = {}) {
  if (Object.prototype.hasOwnProperty.call(query, 'eq')) return keyRange.only(query.eq)
  if (query.prefix != null) return keyRange.bound(String(query.prefix), String(query.prefix) + '\uffff')
  if (query.lower != null && query.upper != null) {
    return keyRange.bound(query.lower, query.upper, query.lowerOpen === true, query.upperOpen === true)
  }
  if (query.lower != null) return keyRange.lowerBound(query.lower, query.lowerOpen === true)
  if (query.upper != null) return keyRange.upperBound(query.upper, query.upperOpen === true)
  return null
}

class IndexedDbTransaction {
  constructor (tx, keyRange) {
    this.tx = tx
    this.keyRange = keyRange
  }

  _source (name, query = {}) {
    const store = this.tx.objectStore(name)
    return query.index ? store.index(query.index) : store
  }

  async get (name, key) {
    const value = await requestResult(this.tx.objectStore(name).get(key))
    // IndexedDB already returns a structured clone detached from storage. The
    // journal owns this transaction-local value and clones only at its public
    // read boundary, so cloning again here doubles large range allocations.
    return value == null ? null : value
  }

  async put (name, value, key) {
    const request = key == null
      ? this.tx.objectStore(name).put(clone(value))
      : this.tx.objectStore(name).put(clone(value), key)
    await requestResult(request)
  }

  async delete (name, key) { await requestResult(this.tx.objectStore(name).delete(key)) }

  async count (name, query = {}) {
    const request = this._source(name, query).count(makeRange(this.keyRange, query))
    return Number(await requestResult(request))
  }

  async scan (name, query = {}) {
    const source = this._source(name, query)
    const range = makeRange(this.keyRange, query)
    const direction = query.direction === 'prev' ? 'prev' : 'next'
    const limit = Number.isSafeInteger(query.limit) && query.limit >= 0 ? query.limit : Infinity
    return new Promise((resolve, reject) => {
      const rows = []
      const request = source.openCursor(range, direction)
      request.onerror = () => reject(request.error || new Error('IndexedDB cursor failed'))
      request.onsuccess = () => {
        const cursor = request.result
        if (!cursor || rows.length >= limit) return resolve(rows)
        rows.push({ key: cursor.primaryKey, value: cursor.value })
        cursor.continue()
      }
    })
  }
}

const STORE_KEY_PATHS = Object.freeze({
  [JOURNAL_STORES.META]: 'key',
  [JOURNAL_STORES.VIEW]: 'key',
  [JOURNAL_STORES.INTENTS]: 'intentId',
  [JOURNAL_STORES.TARGETS]: 'key',
  [JOURNAL_STORES.DEDUPE]: 'intentId'
})

const STORE_INDEX_KEY_PATHS = Object.freeze({
  [JOURNAL_STORES.META]: Object.freeze({}),
  [JOURNAL_STORES.VIEW]: Object.freeze({ updatedAt: 'updatedAt' }),
  [JOURNAL_STORES.INTENTS]: Object.freeze({
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    completedAt: 'completedAt',
    pendingOrderKey: 'pendingOrderKey'
  }),
  [JOURNAL_STORES.TARGETS]: Object.freeze({
    intentId: 'intentId',
    state: 'state',
    leaseUntil: 'leaseUntil',
    updatedAt: 'updatedAt',
    targetStateDueOrder: Object.freeze(['targetId', 'state', 'nextAttemptAt', 'updatedAt', 'attempts', 'intentId']),
    targetStateLeaseOrder: Object.freeze(['targetId', 'state', 'leaseUntil', 'intentId']),
    stateLeaseOrder: Object.freeze(['state', 'leaseUntil', 'intentId', 'targetId'])
  }),
  [JOURNAL_STORES.DEDUPE]: Object.freeze({
    completedAt: 'completedAt',
    expiresAt: 'expiresAt'
  })
})

function schemaError (message) {
  const error = new Error(message)
  error.code = 'PEERIT_JOURNAL_CORRUPT'
  return error
}

function sameKeyPath (actual, expected) {
  if (Array.isArray(actual) || Array.isArray(expected)) {
    return Array.isArray(actual) && Array.isArray(expected) &&
      actual.length === expected.length && actual.every((value, index) => value === expected[index])
  }
  return actual === expected
}

function ensureStore (db, tx, name, keyPath) {
  if (!db.objectStoreNames.contains(name)) return db.createObjectStore(name, { keyPath })
  const store = tx.objectStore(name)
  if (!sameKeyPath(store.keyPath, keyPath) || store.autoIncrement !== false) {
    throw schemaError(`journal object store ${name} has an incompatible key schema`)
  }
  return store
}

function reconcileIndexes (store, definitions) {
  for (const name of [...store.indexNames]) {
    if (!Object.hasOwn(definitions, name)) store.deleteIndex(name)
  }
  for (const [name, keyPath] of Object.entries(definitions)) {
    if (store.indexNames.contains(name)) {
      const index = store.index(name)
      if (!sameKeyPath(index.keyPath, keyPath) || index.unique !== false || index.multiEntry !== false) {
        store.deleteIndex(name)
      }
    }
    if (!store.indexNames.contains(name)) {
      store.createIndex(name, keyPath, { unique: false, multiEntry: false })
    }
  }
}

function repairLegacyTargetRows (store) {
  const request = store.openCursor()
  request.onsuccess = () => {
    const cursor = request.result
    if (!cursor) return
    const target = cursor.value
    const attempts = Number.isSafeInteger(target.attempts) && target.attempts >= 1 ? target.attempts : 1
    const updatedAt = Number.isSafeInteger(target.updatedAt) && target.updatedAt >= 0 ? target.updatedAt : 0
    const retryState = target.state === 'retryable' || target.state === 'pending-unknown'
    const nextAttemptAt = retryState && Number.isSafeInteger(target.nextAttemptAt) && target.nextAttemptAt >= 0
      ? target.nextAttemptAt
      : retryState ? updatedAt : 0
    cursor.update({ ...target, attempts, updatedAt, nextAttemptAt })
    cursor.continue()
  }
}

function createStores (db, tx, oldVersion) {
  const stores = {}
  for (const [name, keyPath] of Object.entries(STORE_KEY_PATHS)) {
    stores[name] = ensureStore(db, tx, name, keyPath)
    reconcileIndexes(stores[name], STORE_INDEX_KEY_PATHS[name])
  }
  if (oldVersion > 0 && oldVersion < JOURNAL_DB_VERSION) {
    repairLegacyTargetRows(stores[JOURNAL_STORES.TARGETS])
  }
}

function validateDatabaseSchema (db) {
  const names = Object.keys(STORE_KEY_PATHS)
  if (names.some(name => !db.objectStoreNames.contains(name))) {
    throw schemaError('journal database is missing a required object store')
  }
  const tx = db.transaction(names, 'readonly')
  for (const name of names) {
    const store = tx.objectStore(name)
    if (!sameKeyPath(store.keyPath, STORE_KEY_PATHS[name]) || store.autoIncrement !== false) {
      throw schemaError(`journal object store ${name} failed exact schema validation`)
    }
    const expectedIndexes = Object.keys(STORE_INDEX_KEY_PATHS[name]).sort()
    const actualIndexes = [...store.indexNames].sort()
    if (expectedIndexes.length !== actualIndexes.length ||
        expectedIndexes.some((value, index) => value !== actualIndexes[index])) {
      throw schemaError(`journal object store ${name} has an unexpected index set`)
    }
    for (const [indexName, keyPath] of Object.entries(STORE_INDEX_KEY_PATHS[name])) {
      const index = store.index(indexName)
      if (!sameKeyPath(index.keyPath, keyPath) || index.unique !== false || index.multiEntry !== false) {
        throw schemaError(`journal index ${name}.${indexName} failed exact schema validation`)
      }
    }
  }
}

function writeMarker (storage) {
  try {
    if (!storage) return false
    storage.setItem(JOURNAL_MARKER_KEY, String(JOURNAL_DB_VERSION))
    return storage.getItem(JOURNAL_MARKER_KEY) === String(JOURNAL_DB_VERSION)
  } catch { return false }
}

export class IndexedDbJournalBackend {
  constructor (options = {}) {
    this.idb = options.indexedDB || globalThis.indexedDB || null
    this.keyRange = options.IDBKeyRange || globalThis.IDBKeyRange || null
    this.dbName = options.dbName || JOURNAL_DB_NAME
    this.markerStorage = options.markerStorage || null
    this.db = null
    this.dormant = true
    this._opening = null
  }

  async _databaseExists () {
    if (!this.idb) return false
    if (typeof this.idb.databases === 'function') {
      try {
        const databases = await this.idb.databases()
        if (Array.isArray(databases) && databases.some(value => value && value.name === this.dbName)) return true
      } catch {}
    }
    // Safari versions without indexedDB.databases() still need to recover an
    // existing journal when localStorage is unavailable or cleared. Opening a
    // missing database starts a version-zero upgrade; abort that transaction so
    // a fresh lurker leaves no persistent database behind.
    return new Promise((resolve, reject) => {
      let missing = false
      const request = this.idb.open(this.dbName)
      request.onupgradeneeded = event => {
        if (event.oldVersion !== 0) return
        missing = true
        try { request.transaction.abort() } catch {}
      }
      request.onsuccess = () => {
        try { request.result.close() } catch {}
        resolve(!missing)
      }
      request.onerror = () => {
        if (missing || (request.error && request.error.name === 'AbortError')) resolve(false)
        else reject(request.error || new Error('IndexedDB existence probe failed'))
      }
      request.onblocked = () => reject(new Error('IndexedDB existence probe was blocked'))
    })
  }

  async ready (options = {}) {
    if (!this.idb || !this.keyRange) return { opened: false, dormant: true, unavailable: true }
    const shouldOpen = options.create === true || options.legacyPresent === true || await this._databaseExists()
    if (!shouldOpen) return { opened: false, dormant: true, schemaVersion: JOURNAL_DB_VERSION }
    await this._open(true)
    return { opened: true, dormant: false, schemaVersion: JOURNAL_DB_VERSION }
  }

  async _open (create) {
    if (this.db) return this.db
    if (this._opening) return this._opening
    if (!this.idb || !this.keyRange) throw new Error('IndexedDB is unavailable')
    if (!create && !(await this._databaseExists())) return null
    this._opening = new Promise((resolve, reject) => {
      let upgradeError = null
      const request = this.idb.open(this.dbName, JOURNAL_DB_VERSION)
      request.onupgradeneeded = event => {
        try {
          createStores(request.result, request.transaction, event.oldVersion)
        } catch (error) {
          upgradeError = error
          try { request.transaction.abort() } catch {}
        }
      }
      request.onsuccess = () => {
        const db = request.result
        try {
          validateDatabaseSchema(db)
          this.db = db
          this.dormant = false
          this.db.onversionchange = () => { try { this.db.close() } catch {}; this.db = null }
          writeMarker(this.markerStorage)
          resolve(this.db)
        } catch (error) {
          try { db.close() } catch {}
          reject(error)
        }
      }
      request.onerror = () => reject(upgradeError || request.error || new Error('IndexedDB journal open failed'))
      request.onblocked = () => reject(new Error('IndexedDB journal upgrade is blocked by another tab'))
    }).finally(() => { this._opening = null })
    return this._opening
  }

  hasStore (name) { return !!(this.db && this.db.objectStoreNames.contains(name)) }

  async transaction (storeNames, mode, operation) {
    const db = await this._open(mode === 'readwrite')
    if (!db) return operation(null)
    return new Promise((resolve, reject) => {
      let tx
      try { tx = db.transaction(storeNames, mode) } catch (error) { reject(error); return }
      const api = new IndexedDbTransaction(tx, this.keyRange)
      let result
      let operationError = null
      Promise.resolve().then(() => operation(api)).then(value => { result = value }).catch(error => {
        operationError = error
        try { tx.abort() } catch {}
      })
      tx.oncomplete = () => operationError ? reject(operationError) : resolve(result)
      tx.onabort = () => reject(operationError || tx.error || new Error('IndexedDB journal transaction aborted'))
      tx.onerror = () => { /* onabort is the terminal signal */ }
    })
  }

  async close () {
    if (this.db) this.db.close()
    this.db = null
  }
}
