// Durable backend for @hiverelay/blind-client DescriptorTrustStore.
// Continuity floors and quarantine state are encrypted and updated with one
// cross-tab IndexedDB compare-and-swap. Corrupt state is never reset to TOFU.

const DB_NAME = 'peerit-substrate-descriptor-trust'
const DB_STORE = 'records'
const DOMAIN = 'peerit.substrate-descriptor-trust.v1'
const MAGIC = new TextEncoder().encode('PDTRST01')
const HEX64 = /^[0-9a-f]{64}$/
const MAX_HISTORY = 4096
const MAX_DESCRIPTOR_BYTES = 64 * 1024
const MAX_TOTAL_BYTES = 256 * 1024 * 1024
const MAX_U64 = (1n << 64n) - 1n
const STATE_FIELDS = Object.freeze([
  'currentBytes',
  'currentHash',
  'durabilityContinuityHash',
  'durabilityProfileId',
  'history',
  'identitySequence',
  'quarantined',
  'relayPublicKey',
  'rootRelayPublicKey',
  'sequence',
  'storeId'
])

export class PeeritDescriptorTrustIntegrityError extends Error {
  constructor (message) {
    super(message)
    this.name = 'PeeritDescriptorTrustIntegrityError'
    this.code = 'PEERIT_DESCRIPTOR_TRUST_CORRUPT'
  }
}

function fail (message) {
  throw new PeeritDescriptorTrustIntegrityError(message)
}

function runtimeCrypto (value) {
  const runtime = value || globalThis.crypto
  if (!runtime || !runtime.subtle || typeof runtime.getRandomValues !== 'function') {
    throw new Error('secure WebCrypto descriptor trust persistence is unavailable')
  }
  return runtime
}

function bytes (value, field, length = null, nonzero = false) {
  let output
  if (value instanceof Uint8Array) output = new Uint8Array(value)
  else if (value instanceof ArrayBuffer) output = new Uint8Array(value.slice(0))
  else if (ArrayBuffer.isView(value)) {
    output = new Uint8Array(new Uint8Array(value.buffer, value.byteOffset, value.byteLength))
  }
  else fail(`${field} must be bytes`)
  if (length != null && output.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  if (nonzero && output.every(value => value === 0)) fail(`${field} must be nonzero`)
  return output
}

function sameBytes (left, right) {
  if (left.byteLength !== right.byteLength) return false
  for (let index = 0; index < left.byteLength; index++) if (left[index] !== right[index]) return false
  return true
}

function hex (value) {
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

function fromHex (value, field) {
  if (!HEX64.test(String(value || ''))) fail(`${field} must be 32-byte lowercase hexadecimal`)
  const output = new Uint8Array(32)
  for (let index = 0; index < output.length; index++) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  return output
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  return value
}

function descriptorKey (value) {
  if (typeof value !== 'string') fail('descriptor trust key must be text')
  const matched = /^descriptor:([0-9a-f]{64}):([0-9a-f]{64})$/.exec(value)
  if (!matched) fail('descriptor trust key is not canonical')
  return {
    key: value,
    rootRelayPublicKey: fromHex(matched[1], 'descriptor root key'),
    storeId: fromHex(matched[2], 'descriptor store id')
  }
}

function exactStateValues (state) {
  if (!state || typeof state !== 'object' || Array.isArray(state) ||
      (Object.getPrototypeOf(state) !== Object.prototype && Object.getPrototypeOf(state) !== null) ||
      Object.getOwnPropertySymbols(state).length !== 0 ||
      Object.getOwnPropertyNames(state).sort().join('\0') !== STATE_FIELDS.join('\0')) {
    fail('descriptor trust state must be an exact plain state object')
  }
  const output = Object.create(null)
  for (const field of STATE_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(state, field)
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
      fail('descriptor trust state cannot contain accessors or hidden fields')
    }
    output[field] = descriptor.value
  }
  return output
}

function exactHistoryValues (history) {
  if (!Array.isArray(history) || Object.getOwnPropertySymbols(history).length !== 0) {
    fail('descriptor history must be a dense array')
  }
  const names = Object.getOwnPropertyNames(history)
  if (names.length !== history.length + 1 || names[names.length - 1] !== 'length') {
    fail('descriptor history must be dense and cannot contain extra fields')
  }
  const output = new Array(history.length)
  for (let index = 0; index < history.length; index++) {
    if (names[index] !== String(index)) fail('descriptor history must be dense and canonical')
    const descriptor = Object.getOwnPropertyDescriptor(history, String(index))
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
      fail('descriptor history cannot contain accessors or hidden entries')
    }
    output[index] = descriptor.value
  }
  return output
}

function cloneState (state) {
  if (state == null) return null
  const source = exactStateValues(state)
  const history = exactHistoryValues(source.history)
  if (typeof source.quarantined !== 'boolean') fail('quarantined must be boolean')
  return {
    rootRelayPublicKey: bytes(source.rootRelayPublicKey, 'rootRelayPublicKey'),
    storeId: bytes(source.storeId, 'storeId'),
    currentBytes: bytes(source.currentBytes, 'currentBytes'),
    currentHash: bytes(source.currentHash, 'currentHash'),
    sequence: source.sequence,
    identitySequence: source.identitySequence,
    relayPublicKey: bytes(source.relayPublicKey, 'relayPublicKey'),
    durabilityProfileId: source.durabilityProfileId,
    durabilityContinuityHash: bytes(source.durabilityContinuityHash, 'durabilityContinuityHash'),
    history: history.map(value => bytes(value, 'history entry')),
    quarantined: source.quarantined
  }
}

function validateState (state, expected = null) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) fail('descriptor trust state must be an object')
  const output = cloneState(state)
  output.rootRelayPublicKey = bytes(output.rootRelayPublicKey, 'rootRelayPublicKey', 32, true)
  output.storeId = bytes(output.storeId, 'storeId', 32, true)
  output.currentHash = bytes(output.currentHash, 'currentHash', 32, true)
  output.relayPublicKey = bytes(output.relayPublicKey, 'relayPublicKey', 32, true)
  output.durabilityContinuityHash = bytes(output.durabilityContinuityHash, 'durabilityContinuityHash', 32, true)
  output.sequence = u64(output.sequence, 'sequence')
  output.identitySequence = u64(output.identitySequence, 'identitySequence')
  if (!Number.isSafeInteger(output.durabilityProfileId) || output.durabilityProfileId < 1 || output.durabilityProfileId > 0xffff) {
    fail('durabilityProfileId is outside u16')
  }
  if (output.currentBytes.byteLength < 1 || output.currentBytes.byteLength > MAX_DESCRIPTOR_BYTES) {
    fail('current descriptor bytes exceed their bound')
  }
  if (!Array.isArray(output.history) || output.history.length < 1 || output.history.length > MAX_HISTORY) {
    fail('descriptor history count is outside 1..4096')
  }
  let total = output.currentBytes.byteLength
  output.history = output.history.map((value, index) => {
    const entry = bytes(value, `history[${index}]`)
    if (entry.byteLength < 1 || entry.byteLength > MAX_DESCRIPTOR_BYTES) fail(`history[${index}] exceeds its byte bound`)
    total += entry.byteLength
    if (total > MAX_TOTAL_BYTES) fail('descriptor history exceeds its total byte bound')
    return entry
  })
  if (!sameBytes(output.currentBytes, output.history[output.history.length - 1])) {
    fail('current descriptor bytes must equal the final history entry')
  }
  if (output.sequence + 1n !== BigInt(output.history.length)) {
    fail('descriptor sequence does not match the complete retained history')
  }
  if (expected && (!sameBytes(output.rootRelayPublicKey, expected.rootRelayPublicKey) ||
      !sameBytes(output.storeId, expected.storeId))) {
    fail('descriptor trust state does not match its continuity/store key')
  }
  return output
}

function u16Bytes (value) {
  return new Uint8Array([value >>> 8, value])
}

function u32Bytes (value) {
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value])
}

function u64Bytes (value) {
  value = u64(value, 'u64')
  const output = new Uint8Array(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function concat (parts) {
  const length = parts.reduce((total, value) => total + value.byteLength, 0)
  if (length > MAX_TOTAL_BYTES) fail('descriptor trust serialization exceeds its byte bound')
  const output = new Uint8Array(length)
  let offset = 0
  for (const value of parts) {
    output.set(value, offset)
    offset += value.byteLength
  }
  return output
}

function encodeState (input, expected = null) {
  const state = validateState(input, expected)
  const parts = [
    MAGIC,
    new Uint8Array([1]),
    state.rootRelayPublicKey,
    state.storeId,
    state.currentHash,
    u64Bytes(state.sequence),
    u64Bytes(state.identitySequence),
    state.relayPublicKey,
    u16Bytes(state.durabilityProfileId),
    state.durabilityContinuityHash,
    new Uint8Array([state.quarantined ? 1 : 0]),
    u32Bytes(state.currentBytes.byteLength),
    state.currentBytes,
    u16Bytes(state.history.length)
  ]
  for (const entry of state.history) parts.push(u32Bytes(entry.byteLength), entry)
  return concat(parts)
}

class Reader {
  constructor (value) { this.value = value; this.offset = 0 }

  take (length, field) {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.value.byteLength) fail(`${field} is truncated`)
    const output = this.value.subarray(this.offset, this.offset + length)
    this.offset += length
    return output
  }

  u8 (field) { return this.take(1, field)[0] }

  u16 (field) { const value = this.take(2, field); return value[0] * 0x100 + value[1] }

  u32 (field) { const value = this.take(4, field); return value[0] * 0x1000000 + value[1] * 0x10000 + value[2] * 0x100 + value[3] }

  u64 (field) { let output = 0n; for (const byte of this.take(8, field)) output = (output << 8n) | BigInt(byte); return output }
}

function decodeState (input, expected) {
  const encoded = bytes(input, 'descriptor trust plaintext')
  if (encoded.byteLength < 1 || encoded.byteLength > MAX_TOTAL_BYTES) fail('descriptor trust plaintext length is invalid')
  const reader = new Reader(encoded)
  if (!sameBytes(reader.take(8, 'magic'), MAGIC) || reader.u8('version') !== 1) fail('descriptor trust plaintext header is invalid')
  const state = {
    rootRelayPublicKey: bytes(reader.take(32, 'rootRelayPublicKey'), 'rootRelayPublicKey'),
    storeId: bytes(reader.take(32, 'storeId'), 'storeId'),
    currentHash: bytes(reader.take(32, 'currentHash'), 'currentHash'),
    sequence: reader.u64('sequence'),
    identitySequence: reader.u64('identitySequence'),
    relayPublicKey: bytes(reader.take(32, 'relayPublicKey'), 'relayPublicKey'),
    durabilityProfileId: reader.u16('durabilityProfileId'),
    durabilityContinuityHash: bytes(reader.take(32, 'durabilityContinuityHash'), 'durabilityContinuityHash'),
    quarantined: reader.u8('quarantined') === 1,
    currentBytes: null,
    history: []
  }
  const currentLength = reader.u32('current descriptor length')
  state.currentBytes = bytes(reader.take(currentLength, 'current descriptor'), 'current descriptor')
  const count = reader.u16('history count')
  for (let index = 0; index < count; index++) {
    const length = reader.u32(`history[${index}] length`)
    state.history.push(bytes(reader.take(length, `history[${index}]`), `history[${index}]`))
  }
  if (reader.offset !== encoded.byteLength) fail('descriptor trust plaintext has trailing bytes')
  const validated = validateState(state, expected)
  if (!sameBytes(encodeState(validated, expected), encoded)) fail('descriptor trust plaintext is noncanonical')
  return validated
}

function assertWrapKey (key) {
  if (!key || key.type !== 'secret' || key.extractable !== false || !key.algorithm ||
      key.algorithm.name !== 'AES-GCM' || key.algorithm.length !== 256 ||
      !Array.isArray(key.usages) || !key.usages.includes('encrypt') || !key.usages.includes('decrypt')) {
    fail('descriptor trust wrapping key is invalid or extractable')
  }
  return key
}

function assertRecord (record, expectedRecordKey) {
  if (!record || typeof record !== 'object' || record.version !== 1 ||
      record.recordKey !== expectedRecordKey || !HEX64.test(String(record.generation || '')) ||
      !Number.isSafeInteger(record.casVersion) || record.casVersion < 1) {
    fail('descriptor trust encrypted record header is malformed')
  }
  assertWrapKey(record.wrapKey)
  const iv = bytes(record.iv, 'descriptor trust iv')
  const ciphertext = bytes(record.ciphertext, 'descriptor trust ciphertext')
  if (iv.byteLength !== 12 || ciphertext.byteLength < 17 || ciphertext.byteLength > MAX_TOTAL_BYTES + 16) {
    fail('descriptor trust ciphertext is malformed')
  }
  return record
}

function aad (record) {
  return new TextEncoder().encode(JSON.stringify([DOMAIN, record.recordKey, record.generation, record.casVersion]))
}

async function recordKeyFor (runtime, key) {
  const material = new TextEncoder().encode(JSON.stringify([DOMAIN, key]))
  return `descriptor-trust:v1:${hex(new Uint8Array(await runtime.subtle.digest('SHA-256', material)))}`
}

async function seal (runtime, recordKey, casVersion, state, expected, wrapKey = null) {
  const clear = encodeState(state, expected)
  const record = {
    version: 1,
    recordKey,
    generation: hex(runtime.getRandomValues(new Uint8Array(32))),
    casVersion,
    wrapKey: wrapKey || await runtime.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    iv: runtime.getRandomValues(new Uint8Array(12)),
    ciphertext: null
  }
  assertWrapKey(record.wrapKey)
  try {
    record.ciphertext = new Uint8Array(await runtime.subtle.encrypt({
      name: 'AES-GCM',
      iv: record.iv,
      additionalData: aad(record),
      tagLength: 128
    }, record.wrapKey, clear))
  } finally { clear.fill(0) }
  return assertRecord(record, recordKey)
}

async function openRecord (runtime, record, recordKey, expected) {
  assertRecord(record, recordKey)
  let clear
  try {
    clear = new Uint8Array(await runtime.subtle.decrypt({
      name: 'AES-GCM',
      iv: record.iv,
      additionalData: aad(record),
      tagLength: 128
    }, record.wrapKey, record.ciphertext))
  } catch { fail('descriptor trust record authentication failed') }
  try { return decodeState(clear, expected) } finally { clear.fill(0) }
}

function clone (value) {
  return typeof structuredClone === 'function' ? structuredClone(value) : value
}

function indexedDbKv (idb = globalThis.indexedDB) {
  if (!idb) return null
  const open = () => new Promise((resolve, reject) => {
    const request = idb.open(DB_NAME, 1)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(DB_STORE)) request.result.createObjectStore(DB_STORE)
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('descriptor trust IndexedDB open failed'))
    request.onblocked = () => reject(new Error('descriptor trust IndexedDB open was blocked'))
  })
  const withStore = async (mode, operation) => {
    const db = await open()
    try {
      return await new Promise((resolve, reject) => {
        const transaction = db.transaction(DB_STORE, mode)
        const store = transaction.objectStore(DB_STORE)
        let result
        operation(store, value => { result = value })
        transaction.oncomplete = () => resolve(result)
        transaction.onabort = () => reject(transaction.error || new Error('descriptor trust transaction aborted'))
        transaction.onerror = () => {}
      })
    } finally { db.close() }
  }
  return {
    get: key => withStore('readonly', (store, done) => {
      const request = store.get(key)
      request.onsuccess = () => done(request.result == null ? null : request.result)
    }),
    putIfAbsent: (key, value) => withStore('readwrite', (store, done) => {
      const request = store.get(key)
      request.onsuccess = () => {
        if (request.result != null) return done({ inserted: false, value: request.result })
        store.put(value, key)
        done({ inserted: true, value })
      }
    }),
    compareAndSwap: (key, generation, casVersion, value) => withStore('readwrite', (store, done) => {
      const request = store.get(key)
      request.onsuccess = () => {
        const current = request.result == null ? null : request.result
        if (!current || current.generation !== generation || current.casVersion !== casVersion) {
          return done({ swapped: false, value: current })
        }
        store.put(value, key)
        done({ swapped: true, value })
      }
    })
  }
}

export function memoryDescriptorTrustKv () {
  const records = new Map()
  return {
    records,
    async get (key) { return records.has(key) ? clone(records.get(key)) : null },
    async putIfAbsent (key, value) {
      if (records.has(key)) return { inserted: false, value: clone(records.get(key)) }
      records.set(key, clone(value))
      return { inserted: true, value: clone(value) }
    },
    async compareAndSwap (key, generation, casVersion, value) {
      const current = records.get(key)
      if (!current || current.generation !== generation || current.casVersion !== casVersion) {
        return { swapped: false, value: current == null ? null : clone(current) }
      }
      records.set(key, clone(value))
      return { swapped: true, value: clone(value) }
    }
  }
}

export function createPeeritDescriptorTrustBackend (options = {}) {
  const runtime = runtimeCrypto(options.crypto)
  const kv = options.kv === undefined ? indexedDbKv(options.indexedDB) : options.kv
  if (!kv || typeof kv.get !== 'function' || typeof kv.putIfAbsent !== 'function' ||
      typeof kv.compareAndSwap !== 'function') {
    throw new Error('atomic descriptor trust persistence is unavailable')
  }

  return Object.freeze({
    async read (key) {
      const expected = descriptorKey(key)
      const recordKey = await recordKeyFor(runtime, expected.key)
      const record = await kv.get(recordKey)
      if (!record) return Object.freeze({ version: 0, value: null })
      const state = await openRecord(runtime, record, recordKey, expected)
      return Object.freeze({ version: record.casVersion, value: cloneState(state) })
    },

    async compareAndSwap (key, expectedVersion, value) {
      const expected = descriptorKey(key)
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) fail('expected descriptor trust version is invalid')
      const state = validateState(value, expected)
      const recordKey = await recordKeyFor(runtime, expected.key)
      if (expectedVersion === 0) {
        const candidate = await seal(runtime, recordKey, 1, state, expected)
        const result = await kv.putIfAbsent(recordKey, candidate)
        if (result.inserted) return true
        await openRecord(runtime, result.value, recordKey, expected)
        return false
      }
      const current = await kv.get(recordKey)
      if (!current) return false
      await openRecord(runtime, current, recordKey, expected)
      if (current.casVersion !== expectedVersion) return false
      if (expectedVersion >= Number.MAX_SAFE_INTEGER) fail('descriptor trust CAS version is exhausted')
      const candidate = await seal(runtime, recordKey, expectedVersion + 1, state, expected, current.wrapKey)
      const result = await kv.compareAndSwap(recordKey, current.generation, expectedVersion, candidate)
      if (result.swapped) return true
      if (result.value != null) await openRecord(runtime, result.value, recordKey, expected)
      return false
    }
  })
}

export const PEERIT_DESCRIPTOR_TRUST_BACKEND_STATUS = Object.freeze({
  encryptedAtRest: true,
  nonExtractableDeviceKey: true,
  atomicCrossTabCas: true,
  corruptionFailsClosed: true,
  silentTofuResetForbidden: true,
  browserIndexedDbIntegrationTested: true
})
