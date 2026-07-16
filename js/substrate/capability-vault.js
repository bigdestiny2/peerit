// Encrypted device-local persistence for blind Cell management capabilities and
// exact request/result material. A relay acknowledgement cannot count until its
// verified result and read capability have committed here.

const DB_NAME = 'peerit-substrate-capabilities'
const DB_STORE = 'records'
const DOMAIN = 'peerit.substrate-capability-record.v1'
const MAX_SECRET_BYTES = 8 * 1024 * 1024
const MAX_NODES = 100000
const HEX64 = /^[0-9a-f]{64}$/

function cryptoRuntime (value) {
  const runtime = value || globalThis.crypto
  if (!runtime || !runtime.subtle || typeof runtime.getRandomValues !== 'function') {
    throw new Error('secure WebCrypto capability persistence is unavailable')
  }
  return runtime
}

function text (value, field, maximum = 4096) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum ||
      value.includes('\0') || value !== value.normalize('NFC')) {
    throw new TypeError(`${field} must be bounded nonempty NFC text`)
  }
  return value
}

function bytes (value, field) {
  if (value instanceof Uint8Array) return new Uint8Array(value)
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0))
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(new Uint8Array(value.buffer, value.byteOffset, value.byteLength))
  }
  throw new TypeError(`${field} must be bytes`)
}

function hex (value) {
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

function fromHex (value, field) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) {
    throw new TypeError(`${field} must be lowercase hexadecimal`)
  }
  const output = new Uint8Array(value.length / 2)
  for (let index = 0; index < output.length; index++) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  return output
}

function sameBytes (left, right) {
  if (left.byteLength !== right.byteLength) return false
  for (let index = 0; index < left.byteLength; index++) if (left[index] !== right[index]) return false
  return true
}

function randomId (runtime) {
  return hex(runtime.getRandomValues(new Uint8Array(32)))
}

function plainObject (value) {
  if (!value || typeof value !== 'object') return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function canonicalArrayValues (value) {
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new TypeError('capability payload array contains a symbol property')
  }
  const names = Object.getOwnPropertyNames(value)
  if (names.length !== value.length + 1 || names[names.length - 1] !== 'length') {
    throw new TypeError('capability payload array must be dense and cannot contain extra properties')
  }
  const output = new Array(value.length)
  for (let index = 0; index < value.length; index++) {
    if (names[index] !== String(index)) {
      throw new TypeError('capability payload array must be dense and canonical')
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index))
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('capability payload array cannot contain accessors or hidden entries')
    }
    output[index] = descriptor.value
  }
  return output
}

function canonicalObjectEntries (value) {
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new TypeError('capability payload object contains a symbol property')
  }
  const output = []
  for (const key of Object.getOwnPropertyNames(value).sort()) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('capability payload object cannot contain accessors or hidden properties')
    }
    output.push([key, descriptor.value])
  }
  return output
}

function canonicalNode (value, state, depth = 0) {
  if (depth > 32 || ++state.nodes > MAX_NODES) throw new TypeError('capability payload exceeds its structural bound')
  if (value === null) return ['null']
  if (typeof value === 'boolean') return ['bool', value]
  if (typeof value === 'string') {
    if (value.length > MAX_SECRET_BYTES || value.includes('\0') || value !== value.normalize('NFC')) {
      throw new TypeError('capability payload string is invalid')
    }
    return ['text', value]
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('capability payload number must be a safe integer')
    return ['number', value]
  }
  if (typeof value === 'bigint') {
    if (value < 0n || value > ((1n << 64n) - 1n)) throw new TypeError('capability payload bigint is outside u64')
    return ['u64', String(value)]
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return ['bytes', hex(bytes(value, 'capability payload bytes'))]
  if (Array.isArray(value)) {
    return ['array', canonicalArrayValues(value).map(child => canonicalNode(child, state, depth + 1))]
  }
  if (!plainObject(value)) throw new TypeError('capability payload contains a non-plain value')
  const rows = []
  for (const [key, child] of canonicalObjectEntries(value)) {
    if (key.length < 1 || key.length > 512 || key.includes('\0') || key !== key.normalize('NFC')) {
      throw new TypeError('capability payload object key is invalid')
    }
    if (child === undefined || typeof child === 'function' || typeof child === 'symbol') {
      throw new TypeError('capability payload contains an unsupported value')
    }
    rows.push([key, canonicalNode(child, state, depth + 1)])
  }
  return ['object', rows]
}

function valueFromNode (node, state, depth = 0) {
  if (depth > 32 || ++state.nodes > MAX_NODES || !Array.isArray(node) || typeof node[0] !== 'string') {
    throw new Error('encrypted capability payload is malformed')
  }
  const [tag, value] = node
  if (tag === 'null' && node.length === 1) return null
  if (tag === 'bool' && node.length === 2 && typeof value === 'boolean') return value
  if (tag === 'text' && node.length === 2 && typeof value === 'string' && value.length <= MAX_SECRET_BYTES &&
      !value.includes('\0') && value === value.normalize('NFC')) return value
  if (tag === 'number' && node.length === 2 && Number.isSafeInteger(value)) return value
  if (tag === 'u64' && node.length === 2 && typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value)) {
    const output = BigInt(value)
    if (output <= ((1n << 64n) - 1n)) return output
  }
  if (tag === 'bytes' && node.length === 2) return fromHex(value, 'encrypted capability bytes')
  if (tag === 'array' && node.length === 2 && Array.isArray(value)) {
    return value.map(child => valueFromNode(child, state, depth + 1))
  }
  if (tag === 'object' && node.length === 2 && Array.isArray(value)) {
    const output = {}
    let previous = null
    for (const row of value) {
      if (!Array.isArray(row) || row.length !== 2 || typeof row[0] !== 'string' ||
          row[0].length < 1 || row[0].length > 512 || row[0].includes('\0') ||
          row[0] !== row[0].normalize('NFC') || (previous != null && previous >= row[0])) {
        throw new Error('encrypted capability object is noncanonical')
      }
      previous = row[0]
      // Keep "__proto__" as ordinary data instead of invoking the legacy
      // Object.prototype setter while decoding encrypted application input.
      Object.defineProperty(output, row[0], {
        configurable: true,
        enumerable: true,
        writable: true,
        value: valueFromNode(row[1], state, depth + 1)
      })
    }
    return output
  }
  throw new Error('encrypted capability payload has an unknown or invalid value')
}

function encodeSecret (value) {
  const encoded = new TextEncoder().encode(JSON.stringify({ version: 1, value: canonicalNode(value, { nodes: 0 }) }))
  if (encoded.byteLength < 1 || encoded.byteLength > MAX_SECRET_BYTES) throw new TypeError('capability payload exceeds 8 MiB')
  return encoded
}

function decodeSecret (value) {
  value = bytes(value, 'decrypted capability payload')
  if (value.byteLength < 1 || value.byteLength > MAX_SECRET_BYTES) throw new Error('encrypted capability payload length is invalid')
  let parsed
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(value)) } catch { throw new Error('encrypted capability payload is not canonical UTF-8 JSON') }
  if (!plainObject(parsed) || parsed.version !== 1 || Object.keys(parsed).sort().join(',') !== 'value,version') {
    throw new Error('encrypted capability payload envelope is invalid')
  }
  const output = valueFromNode(parsed.value, { nodes: 0 })
  const canonical = encodeSecret(output)
  try {
    if (!sameBytes(canonical, value)) throw new Error('encrypted capability payload is noncanonical')
  } finally {
    canonical.fill(0)
  }
  return output
}

function sameEncodedSecret (value, expected) {
  const encoded = encodeSecret(value)
  try { return sameBytes(encoded, expected) } finally { encoded.fill(0) }
}

function sameSecretValues (left, right) {
  const leftBytes = encodeSecret(left)
  const rightBytes = encodeSecret(right)
  try { return sameBytes(leftBytes, rightBytes) } finally {
    leftBytes.fill(0)
    rightBytes.fill(0)
  }
}

function clone (value) {
  if (typeof structuredClone === 'function') return structuredClone(value)
  return value
}

function assertWrapKey (key) {
  if (!key || key.type !== 'secret' || key.extractable !== false ||
      !key.algorithm || key.algorithm.name !== 'AES-GCM' || key.algorithm.length !== 256 ||
      !Array.isArray(key.usages) || !key.usages.includes('encrypt') || !key.usages.includes('decrypt')) {
    throw new Error('capability record wrapping key is invalid or extractable')
  }
  return key
}

function headerBytes (record) {
  return new TextEncoder().encode(JSON.stringify([
    DOMAIN,
    record.recordKey,
    record.recordId,
    record.revision,
    record.stage,
    record.createdAt,
    record.updatedAt
  ]))
}

function assertRecord (record, expectedKey = null) {
  if (!plainObject(record) || record.version !== 1 || !HEX64.test(String(record.recordId || '')) ||
      typeof record.recordKey !== 'string' || (expectedKey != null && record.recordKey !== expectedKey) ||
      !Number.isSafeInteger(record.revision) || record.revision < 1 ||
      (record.stage !== 1 && record.stage !== 2 && record.stage !== 3) ||
      !Number.isSafeInteger(record.createdAt) ||
      !Number.isSafeInteger(record.updatedAt) || record.updatedAt < record.createdAt) {
    throw new Error('capability record header is malformed')
  }
  assertWrapKey(record.wrapKey)
  const iv = bytes(record.iv, 'record iv')
  const ciphertext = bytes(record.ciphertext, 'record ciphertext')
  if (iv.byteLength !== 12 || ciphertext.byteLength < 17 || ciphertext.byteLength > MAX_SECRET_BYTES + 16) {
    throw new Error('capability record ciphertext is malformed')
  }
  return record
}

async function recordKeyFor (runtime, intentId, targetId) {
  const material = new TextEncoder().encode(JSON.stringify([DOMAIN, intentId, targetId]))
  return `capability:v1:${hex(new Uint8Array(await runtime.subtle.digest('SHA-256', material)))}`
}

async function sealRecord (runtime, header, payload, wrapKey = null) {
  const record = {
    ...header,
    wrapKey: wrapKey || await runtime.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    iv: runtime.getRandomValues(new Uint8Array(12))
  }
  assertWrapKey(record.wrapKey)
  const clear = encodeSecret(payload)
  try {
    record.ciphertext = new Uint8Array(await runtime.subtle.encrypt({
      name: 'AES-GCM',
      iv: record.iv,
      additionalData: headerBytes(record),
      tagLength: 128
    }, record.wrapKey, clear))
  } finally {
    clear.fill(0)
  }
  return assertRecord(record, header.recordKey)
}

async function openRecord (runtime, record, expectedKey) {
  assertRecord(record, expectedKey)
  let clear
  try {
    clear = new Uint8Array(await runtime.subtle.decrypt({
      name: 'AES-GCM',
      iv: record.iv,
      additionalData: headerBytes(record),
      tagLength: 128
    }, record.wrapKey, record.ciphertext))
  } catch { throw new Error('capability record authentication failed') }
  try {
    const payload = decodeSecret(clear)
    if (!plainObject(payload) || payload.version !== 1 || payload.stage !== record.stage) {
      throw new Error('capability record payload does not match its authenticated header')
    }
    return payload
  } finally {
    clear.fill(0)
  }
}

function evidenceRef (record) {
  return `peerit-capability-v1:${record.recordId}:${record.revision}`
}

function publicRecord (record, payload) {
  return Object.freeze({
    intentId: payload.intentId,
    logicalId: payload.logicalId,
    targetId: payload.targetId,
    revision: record.revision,
    stage: record.stage === 1
      ? 'prepared'
      : record.stage === 2 ? 'verified' : 'readback-verified',
    evidenceRef: evidenceRef(record),
    payload: clone(payload)
  })
}

function preparedProjection (payload) {
  const comparable = { ...payload, stage: 1 }
  delete comparable.resultBytes
  delete comparable.readCapability
  delete comparable.readbackRequestBytes
  delete comparable.readbackRequestCommitment
  delete comparable.readbackResultBytes
  delete comparable.readbackInnerBytes
  return comparable
}

function matchesPreparedWithReadContextUpgrade (comparable, expected) {
  if (sameSecretValues(comparable, expected)) return true
  if (comparable.readTargetContext != null || expected.readTargetContext == null) return false
  return sameSecretValues({ ...comparable, readTargetContext: expected.readTargetContext }, expected)
}

function indexedDbKv (idb = globalThis.indexedDB) {
  if (!idb) return null
  const open = () => new Promise((resolve, reject) => {
    const request = idb.open(DB_NAME, 1)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(DB_STORE)) request.result.createObjectStore(DB_STORE)
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('capability IndexedDB open failed'))
    request.onblocked = () => reject(new Error('capability IndexedDB open was blocked'))
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
        transaction.onabort = () => reject(transaction.error || new Error('capability transaction aborted'))
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
    compareAndSwap: (key, expectedRecordId, expectedRevision, value) => withStore('readwrite', (store, done) => {
      const request = store.get(key)
      request.onsuccess = () => {
        const current = request.result == null ? null : request.result
        if (!current || current.recordId !== expectedRecordId || current.revision !== expectedRevision) {
          return done({ swapped: false, value: current })
        }
        store.put(value, key)
        done({ swapped: true, value })
      }
    }),
    compareAndDelete: (key, expectedRecordId, expectedRevision) => withStore('readwrite', (store, done) => {
      const request = store.get(key)
      request.onsuccess = () => {
        const current = request.result == null ? null : request.result
        if (!current || current.recordId !== expectedRecordId || current.revision !== expectedRevision) {
          return done({ deleted: false, value: current })
        }
        store.delete(key)
        done({ deleted: true, value: current })
      }
    })
  }
}

export function memoryCapabilityVaultKv () {
  const records = new Map()
  return {
    records,
    async get (key) { return records.has(key) ? clone(records.get(key)) : null },
    async putIfAbsent (key, value) {
      if (records.has(key)) return { inserted: false, value: clone(records.get(key)) }
      records.set(key, clone(value))
      return { inserted: true, value: clone(value) }
    },
    async compareAndSwap (key, expectedRecordId, expectedRevision, value) {
      const current = records.get(key)
      if (!current || current.recordId !== expectedRecordId || current.revision !== expectedRevision) {
        return { swapped: false, value: current == null ? null : clone(current) }
      }
      records.set(key, clone(value))
      return { swapped: true, value: clone(value) }
    },
    async compareAndDelete (key, expectedRecordId, expectedRevision) {
      const current = records.get(key)
      if (!current || current.recordId !== expectedRecordId || current.revision !== expectedRevision) {
        return { deleted: false, value: current == null ? null : clone(current) }
      }
      records.delete(key)
      return { deleted: true, value: clone(current) }
    }
  }
}

export function createPeeritCapabilityVault (options = {}) {
  if (!plainObject(options)) throw new TypeError('capability vault options must be an object')
  const runtime = cryptoRuntime(options.crypto)
  const kv = options.kv === undefined ? indexedDbKv(options.indexedDB) : options.kv
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  if (!kv || typeof kv.get !== 'function' || typeof kv.putIfAbsent !== 'function' ||
      typeof kv.compareAndSwap !== 'function' || typeof kv.compareAndDelete !== 'function') {
    throw new Error('atomic capability persistence is unavailable')
  }

  function inputFields (input) {
    if (!plainObject(input)) throw new TypeError('capability persistence input must be an object')
    return {
      intentId: text(input.intentId, 'intentId', 512),
      logicalId: text(input.logicalId, 'logicalId', 512),
      targetId: text(input.targetId, 'targetId', 4096)
    }
  }

  function envelopeFields (input) {
    if (!Number.isSafeInteger(input.innerCodec) || input.innerCodec !== 334 ||
        !Number.isSafeInteger(input.innerLength) || input.innerLength < 8 || input.innerLength > 1_048_519 ||
        !Number.isSafeInteger(input.sizeClass) || input.sizeClass < 1 || input.sizeClass > 5) {
      throw new TypeError('capability persistence requires exact VNext envelope metadata')
    }
    const logicalHash = bytes(input.logicalHash, 'logicalHash')
    const encodingCommitment = bytes(input.encodingCommitment, 'encodingCommitment')
    if (logicalHash.byteLength !== 32 || encodingCommitment.byteLength !== 32) {
      throw new TypeError('capability persistence requires 32-byte VNext commitments')
    }
    return {
      innerCodec: input.innerCodec,
      innerLength: input.innerLength,
      sizeClass: input.sizeClass,
      logicalHash,
      encodingCommitment
    }
  }

  async function loadRecord (fields) {
    const recordKey = await recordKeyFor(runtime, fields.intentId, fields.targetId)
    const record = await kv.get(recordKey)
    if (!record) return { recordKey, record: null, payload: null }
    const payload = await openRecord(runtime, record, recordKey)
    if (payload.intentId !== fields.intentId || payload.targetId !== fields.targetId ||
        payload.logicalId !== fields.logicalId) throw new Error('capability record logical identity conflicts')
    return { recordKey, record, payload }
  }

  async function persistPreparedReplica (input) {
    const fields = inputFields(input)
    const envelope = envelopeFields(input)
    if (!plainObject(input.targetContext) || !plainObject(input.prepared) ||
        (input.readTargetContext != null && !plainObject(input.readTargetContext))) {
      throw new TypeError('prepared capability persistence requires targetContext and prepared objects')
    }
    const recordKey = await recordKeyFor(runtime, fields.intentId, fields.targetId)
    const payload = {
      version: 1,
      stage: 1,
      ...fields,
      ...envelope,
      targetContext: input.targetContext,
      readTargetContext: input.readTargetContext || null,
      prepared: input.prepared
    }
    const preparedBytes = encodeSecret(payload)
    try {
      const timestamp = now()
      if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error('capability vault clock is invalid')
      const candidate = await sealRecord(runtime, {
        version: 1,
        recordKey,
        recordId: randomId(runtime),
        revision: 1,
        stage: 1,
        createdAt: timestamp,
        updatedAt: timestamp
      }, payload)
      const result = await kv.putIfAbsent(recordKey, candidate)
      const winner = assertRecord(result.value, recordKey)
      const winnerPayload = await openRecord(runtime, winner, recordKey)
      if (winner.stage === 1 && sameEncodedSecret(winnerPayload, preparedBytes)) {
        return publicRecord(winner, winnerPayload)
      }
      if (winner.stage === 2 || winner.stage === 3) {
        const comparable = preparedProjection(winnerPayload)
        if (sameEncodedSecret(comparable, preparedBytes)) return publicRecord(winner, winnerPayload)
      }
      throw new Error('a different prepared capability record already owns this intent target')
    } finally {
      preparedBytes.fill(0)
    }
  }

  async function persistVerifiedResult (input) {
    const fields = inputFields(input)
    const envelope = envelopeFields(input)
    if (!plainObject(input.targetContext) || !plainObject(input.prepared) ||
        (input.readTargetContext != null && !plainObject(input.readTargetContext))) {
      throw new TypeError('verified capability persistence requires targetContext and prepared objects')
    }
    const resultBytes = bytes(input.resultBytes, 'resultBytes')
    if (resultBytes.byteLength < 1) throw new TypeError('resultBytes must be nonempty')
    if (!plainObject(input.readCapability)) throw new TypeError('readCapability must be an object')
    for (let attempt = 0; attempt < 8; attempt++) {
      const current = await loadRecord(fields)
      if (!current.record) throw new Error('verified result has no durable prepared capability record')
      const expectedPrepared = {
        version: 1,
        stage: 1,
        ...fields,
        ...envelope,
        targetContext: input.targetContext,
        readTargetContext: input.readTargetContext || null,
        prepared: input.prepared
      }
      const comparable = preparedProjection(current.payload)
      if (!matchesPreparedWithReadContextUpgrade(comparable, expectedPrepared)) {
        throw new Error('verified result does not match the durable prepared capability record')
      }
      const payload = {
        ...comparable,
        stage: 2,
        readTargetContext: input.readTargetContext || null,
        resultBytes,
        readCapability: input.readCapability
      }
      if (current.record.stage === 2) {
        if (sameSecretValues(current.payload, payload)) return publicRecord(current.record, current.payload)
        throw new Error('a conflicting verified result already owns this intent target')
      }
      if (current.record.stage === 3) {
        if (!sameSecretValues(current.payload.readCapability, input.readCapability)) {
          throw new Error('verified result read capability conflicts with authenticated readback evidence')
        }
        return publicRecord(current.record, current.payload)
      }
      if (current.record.revision >= Number.MAX_SAFE_INTEGER) throw new Error('capability record revision is exhausted')
      const observedTimestamp = now()
      if (!Number.isSafeInteger(observedTimestamp) || observedTimestamp < 0) {
        throw new Error('capability vault clock is invalid')
      }
      // Wall-clock correction after a request was sent must not strand its
      // verified result. CAS revision/generation order the record; clamp only
      // the diagnostic timestamp so the authenticated header stays monotonic.
      const timestamp = Math.max(observedTimestamp, current.record.updatedAt)
      const candidate = await sealRecord(runtime, {
        version: 1,
        recordKey: current.recordKey,
        recordId: randomId(runtime),
        revision: current.record.revision + 1,
        stage: 2,
        createdAt: current.record.createdAt,
        updatedAt: timestamp
      }, payload, current.record.wrapKey)
      const swapped = await kv.compareAndSwap(current.recordKey, current.record.recordId, current.record.revision, candidate)
      if (swapped.swapped) return publicRecord(candidate, payload)
    }
    throw new Error('capability record changed too many times during verified-result persistence')
  }

  async function persistVerifiedReadback (input) {
    const fields = inputFields(input)
    const envelope = envelopeFields(input)
    if (!plainObject(input.targetContext) || !plainObject(input.readTargetContext) ||
        !plainObject(input.prepared) || !plainObject(input.readCapability)) {
      throw new TypeError('readback persistence requires PUT/GET contexts, prepared request, and read capability')
    }
    if (!sameSecretValues(input.prepared.readCap, input.readCapability)) {
      throw new Error('readback capability does not match the durable prepared Cell')
    }
    const readbackRequestBytes = bytes(input.readbackRequestBytes, 'readbackRequestBytes')
    const readbackRequestCommitment = bytes(input.readbackRequestCommitment, 'readbackRequestCommitment')
    const readbackResultBytes = bytes(input.readbackResultBytes, 'readbackResultBytes')
    const readbackInnerBytes = bytes(input.readbackInnerBytes, 'readbackInnerBytes')
    if (readbackRequestBytes.byteLength < 1 || readbackRequestCommitment.byteLength !== 32 ||
        readbackResultBytes.byteLength < 1 || readbackInnerBytes.byteLength !== envelope.innerLength) {
      throw new TypeError('readback evidence has invalid request, commitment, result, or exact-envelope length')
    }

    for (let attempt = 0; attempt < 8; attempt++) {
      const current = await loadRecord(fields)
      if (!current.record) throw new Error('authenticated readback has no durable prepared capability record')
      const expectedPrepared = {
        version: 1,
        stage: 1,
        ...fields,
        ...envelope,
        targetContext: input.targetContext,
        readTargetContext: input.readTargetContext,
        prepared: input.prepared
      }
      const comparable = preparedProjection(current.payload)
      if (!matchesPreparedWithReadContextUpgrade(comparable, expectedPrepared)) {
        throw new Error('authenticated readback does not match the durable prepared capability record')
      }
      if (current.payload.readCapability &&
          !sameSecretValues(current.payload.readCapability, input.readCapability)) {
        throw new Error('authenticated readback conflicts with the persisted Cell read capability')
      }
      const payload = {
        ...comparable,
        stage: 3,
        readTargetContext: input.readTargetContext,
        readCapability: input.readCapability,
        readbackRequestBytes,
        readbackRequestCommitment,
        readbackResultBytes,
        readbackInnerBytes
      }
      if (current.payload.resultBytes) payload.resultBytes = current.payload.resultBytes
      if (current.record.stage === 3) {
        if (sameSecretValues(current.payload, payload)) return publicRecord(current.record, current.payload)
        throw new Error('conflicting authenticated readback evidence already owns this intent target')
      }
      if (current.record.revision >= Number.MAX_SAFE_INTEGER) throw new Error('capability record revision is exhausted')
      const observedTimestamp = now()
      if (!Number.isSafeInteger(observedTimestamp) || observedTimestamp < 0) {
        throw new Error('capability vault clock is invalid')
      }
      const timestamp = Math.max(observedTimestamp, current.record.updatedAt)
      const candidate = await sealRecord(runtime, {
        version: 1,
        recordKey: current.recordKey,
        recordId: randomId(runtime),
        revision: current.record.revision + 1,
        stage: 3,
        createdAt: current.record.createdAt,
        updatedAt: timestamp
      }, payload, current.record.wrapKey)
      const swapped = await kv.compareAndSwap(
        current.recordKey, current.record.recordId, current.record.revision, candidate)
      if (swapped.swapped) return publicRecord(candidate, payload)
    }
    throw new Error('capability record changed too many times during readback persistence')
  }

  async function load (intentId, targetId) {
    const fields = {
      intentId: text(intentId, 'intentId', 512),
      targetId: text(targetId, 'targetId', 4096),
      logicalId: ''
    }
    const recordKey = await recordKeyFor(runtime, fields.intentId, fields.targetId)
    const record = await kv.get(recordKey)
    if (!record) return null
    const payload = await openRecord(runtime, record, recordKey)
    if (payload.intentId !== fields.intentId || payload.targetId !== fields.targetId) {
      throw new Error('capability record lookup identity conflicts')
    }
    return publicRecord(record, payload)
  }

  async function inspect (intentId, targetId) {
    try {
      const value = await load(intentId, targetId)
      return value == null ? Object.freeze({ status: 'empty' }) : Object.freeze({ status: 'valid', value })
    } catch (error) {
      return Object.freeze({ status: 'corrupt', error: String(error && error.message ? error.message : error) })
    }
  }

  async function deleteExact (intentId, targetId, expectedEvidenceRef) {
    const value = await load(intentId, targetId)
    if (!value || value.evidenceRef !== expectedEvidenceRef) return false
    const recordKey = await recordKeyFor(runtime, value.intentId, value.targetId)
    const record = await kv.get(recordKey)
    if (!record || evidenceRef(record) !== expectedEvidenceRef) return false
    const deleted = await kv.compareAndDelete(recordKey, record.recordId, record.revision)
    if (!deleted.deleted) return false
    return (await kv.get(recordKey)) == null
  }

  return Object.freeze({
    available: () => true,
    persistPreparedReplica,
    persistVerifiedResult,
    persistVerifiedReadback,
    load,
    inspect,
    deleteExact
  })
}

export const PEERIT_CAPABILITY_VAULT_STATUS = Object.freeze({
  encryptedAtRest: true,
  nonExtractableDeviceKey: true,
  exactPreparedBeforeSend: true,
  verifiedResultBeforeAcknowledgement: true,
  authenticatedReadbackBeforeAuthorBinding: true,
  atomicMultiTabCas: true,
  browserIndexedDbIntegrationTested: true,
  portableRecoveryBundleIntegrated: false,
  runtimeConsumerIntegrated: false
})
