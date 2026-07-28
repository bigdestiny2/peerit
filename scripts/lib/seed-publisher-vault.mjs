// Encrypted, restart-safe publisher state for the reviewed Peerit seed corpus.
// Secrets and Cell capabilities are authenticated at rest; public receipt
// manifests are derived projections that never include read/write/management
// capability bytes.

import fs from 'node:fs/promises'
import path from 'node:path'
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync
} from 'node:crypto'

export const PEERIT_SEED_PUBLISHER_VAULT_SCHEMA_V1 = 'peerit-seed-publisher-vault-v1'
export const PEERIT_SEED_RECEIPT_MANIFEST_SCHEMA_V1 = 'peerit-seed-receipts-v1'

const KDF = Object.freeze({ name: 'scrypt', N: 32768, r: 8, p: 1, keyLength: 32 })
const MAX_BYTES = 16 * 1024 * 1024
const HEX32 = /^[0-9a-f]{64}$/

function fail (code, message, exitCode = null) {
  const error = new Error(message)
  error.code = code
  if (exitCode != null) error.exitCode = exitCode
  throw error
}

function plain (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    fail('PEERIT_SEED_VAULT_BAD_INPUT', `${field} must be a plain object`)
  }
  return value
}

function text (value, field, maximum = 4096) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum ||
      value.includes('\0') || value !== value.normalize('NFC')) {
    fail('PEERIT_SEED_VAULT_BAD_INPUT', `${field} must be bounded nonempty NFC text`)
  }
  return value
}

function encodeNode (value, depth = 0) {
  if (depth > 48) fail('PEERIT_SEED_VAULT_LIMIT', 'publisher state nesting exceeds its bound')
  if (value === null) return ['null']
  if (typeof value === 'boolean') return ['bool', value]
  if (typeof value === 'string') return ['text', value]
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('PEERIT_SEED_VAULT_BAD_INPUT', 'publisher state numbers must be safe integers')
    return ['number', value]
  }
  if (typeof value === 'bigint') return ['bigint', String(value)]
  if (value instanceof Uint8Array || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    const bytes = value instanceof Uint8Array
      ? value
      : new Uint8Array(value.buffer || value, value.byteOffset || 0, value.byteLength)
    return ['bytes', Buffer.from(bytes).toString('hex')]
  }
  if (Array.isArray(value)) return ['array', value.map(child => encodeNode(child, depth + 1))]
  plain(value, 'publisher state value')
  return ['object', Object.keys(value).sort().map(key => [key, encodeNode(value[key], depth + 1)])]
}

function decodeNode (node, depth = 0) {
  if (depth > 48 || !Array.isArray(node) || typeof node[0] !== 'string') {
    fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher state node is malformed')
  }
  if (node[0] === 'null' && node.length === 1) return null
  if (node[0] === 'bool' && node.length === 2 && typeof node[1] === 'boolean') return node[1]
  if (node[0] === 'text' && node.length === 2 && typeof node[1] === 'string') return node[1]
  if (node[0] === 'number' && node.length === 2 && Number.isSafeInteger(node[1])) return node[1]
  if (node[0] === 'bigint' && node.length === 2 && /^-?[0-9]+$/.test(node[1])) return BigInt(node[1])
  if (node[0] === 'bytes' && node.length === 2 && typeof node[1] === 'string' && /^[0-9a-f]*$/.test(node[1]) && node[1].length % 2 === 0) {
    return new Uint8Array(Buffer.from(node[1], 'hex'))
  }
  if (node[0] === 'array' && node.length === 2 && Array.isArray(node[1])) {
    return node[1].map(child => decodeNode(child, depth + 1))
  }
  if (node[0] === 'object' && node.length === 2 && Array.isArray(node[1])) {
    const output = Object.create(null)
    let previous = null
    for (const row of node[1]) {
      if (!Array.isArray(row) || row.length !== 2 || typeof row[0] !== 'string' ||
          (previous != null && previous >= row[0])) fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher state object is noncanonical')
      previous = row[0]
      output[row[0]] = decodeNode(row[1], depth + 1)
    }
    return output
  }
  fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher state node has an unknown type')
}

function encodeState (state) {
  const bytes = Buffer.from(JSON.stringify({ version: 1, value: encodeNode(state) }))
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_BYTES) fail('PEERIT_SEED_VAULT_LIMIT', 'publisher state exceeds 16 MiB')
  return bytes
}

function decodeState (bytes) {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_BYTES) fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher state length is invalid')
  let parsed
  try { parsed = JSON.parse(bytes.toString('utf8')) } catch { fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher state plaintext is malformed') }
  if (!parsed || parsed.version !== 1 || Object.keys(parsed).sort().join(',') !== 'value,version') {
    fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher state plaintext envelope is unsupported')
  }
  const state = decodeNode(parsed.value)
  const canonical = encodeState(state)
  if (!canonical.equals(bytes)) fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher state plaintext is noncanonical')
  canonical.fill(0)
  return state
}

function passphraseBytes (value) {
  const bytes = value instanceof Uint8Array ? Buffer.from(value) : null
  if (!bytes || bytes.byteLength < 16 || bytes.byteLength > 1024) {
    fail('PEERIT_SEED_VAULT_PASSPHRASE_REQUIRED', 'publisher vault passphrase must be supplied as 16..1024 owned bytes')
  }
  return bytes
}

function aad (envelope) {
  return Buffer.from(JSON.stringify([
    envelope.schema, envelope.version, envelope.kdf, envelope.N,
    envelope.r, envelope.p, envelope.salt, envelope.nonce
  ]))
}

function seal (state, passphrase) {
  const salt = randomBytes(16)
  const nonce = randomBytes(12)
  const envelope = {
    schema: PEERIT_SEED_PUBLISHER_VAULT_SCHEMA_V1,
    version: 1,
    kdf: KDF.name,
    N: KDF.N,
    r: KDF.r,
    p: KDF.p,
    salt: salt.toString('hex'),
    nonce: nonce.toString('hex')
  }
  const key = scryptSync(passphrase, salt, KDF.keyLength, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: 64 * 1024 * 1024 })
  const clear = encodeState(state)
  try {
    const cipher = createCipheriv('aes-256-gcm', key, nonce)
    cipher.setAAD(aad(envelope))
    const ciphertext = Buffer.concat([cipher.update(clear), cipher.final()])
    envelope.ciphertext = ciphertext.toString('hex')
    envelope.tag = cipher.getAuthTag().toString('hex')
    return Buffer.from(JSON.stringify(envelope) + '\n')
  } finally {
    key.fill(0)
    clear.fill(0)
  }
}

function open (bytes, passphrase) {
  let envelope
  try { envelope = JSON.parse(bytes.toString('utf8')) } catch { fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher vault envelope is malformed') }
  if (!envelope || envelope.schema !== PEERIT_SEED_PUBLISHER_VAULT_SCHEMA_V1 || envelope.version !== 1 ||
      envelope.kdf !== KDF.name || envelope.N !== KDF.N || envelope.r !== KDF.r || envelope.p !== KDF.p ||
      !/^[0-9a-f]{32}$/.test(envelope.salt || '') || !/^[0-9a-f]{24}$/.test(envelope.nonce || '') ||
      !/^[0-9a-f]+$/.test(envelope.ciphertext || '') || !/^[0-9a-f]{32}$/.test(envelope.tag || '')) {
    fail('PEERIT_SEED_VAULT_CORRUPT', 'publisher vault envelope fields are invalid')
  }
  const key = scryptSync(passphrase, Buffer.from(envelope.salt, 'hex'), KDF.keyLength,
    { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: 64 * 1024 * 1024 })
  let clear = null
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.nonce, 'hex'))
    decipher.setAAD(aad(envelope))
    decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'))
    clear = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'hex')), decipher.final()])
    return decodeState(clear)
  } catch (cause) {
    fail('PEERIT_SEED_VAULT_AUTHENTICATION_FAILED', 'publisher vault authentication failed')
  } finally {
    key.fill(0)
    if (clear) clear.fill(0)
  }
}

function emptyState () {
  return {
    schema: PEERIT_SEED_PUBLISHER_VAULT_SCHEMA_V1,
    version: 1,
    revision: 0,
    manifestSha256: null,
    records: Object.create(null),
    updatedAt: 0
  }
}

function complete (record) {
  return record.plannedRelays.every(relayId => record.replicas[relayId] && record.replicas[relayId].verified === true)
}

async function writeAtomic (filePath, bytes) {
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 })
  const temporary = `${filePath}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`
  const handle = await fs.open(temporary, 'wx', 0o600)
  try {
    await handle.writeFile(bytes)
    await handle.sync()
  } finally { await handle.close() }
  await fs.rename(temporary, filePath)
  await fs.chmod(filePath, 0o600)
  const directory = await fs.open(path.dirname(filePath), 'r')
  try { await directory.sync() } finally { await directory.close() }
}

export function createPeeritSeedPublisherVaultV1 (options = {}) {
  const filePath = path.resolve(text(options.filePath, 'filePath'))
  const passphrase = passphraseBytes(options.passphrase)
  const lockPath = `${filePath}.lock`
  const now = typeof options.now === 'function' ? options.now : Date.now

  async function load () {
    try { return open(await fs.readFile(filePath), passphrase) } catch (error) {
      if (error && error.code === 'ENOENT') return emptyState()
      throw error
    }
  }

  async function transaction (mutate) {
    let lock
    await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 })
    try { lock = await fs.open(lockPath, 'wx', 0o600) } catch (cause) {
      fail('PEERIT_SEED_VAULT_LOCKED', 'publisher vault is already locked by another process')
    }
    try {
      const state = await load()
      const result = await mutate(state)
      state.revision++
      state.updatedAt = now()
      await writeAtomic(filePath, seal(state, passphrase))
      return result
    } finally {
      await lock.close()
      await fs.unlink(lockPath).catch(() => {})
    }
  }

  async function bindPlan ({ manifestSha256, records }) {
    if (!HEX32.test(String(manifestSha256 || '')) || !Array.isArray(records) || !records.length) {
      fail('PEERIT_SEED_VAULT_BAD_INPUT', 'publisher plan requires an exact manifest hash and records')
    }
    return transaction(state => {
      if (state.manifestSha256 && state.manifestSha256 !== manifestSha256) {
        fail('PEERIT_SEED_VAULT_MANIFEST_CONFLICT', 'publisher vault is already bound to a different seed manifest')
      }
      state.manifestSha256 = manifestSha256
      for (const input of records) {
        plain(input, 'publisher plan record')
        const recordId = text(input.recordId, 'recordId', 512)
        const plannedRelays = [...new Set((input.plannedRelays || []).map(String))].sort()
        if (plannedRelays.length !== 2) fail('PEERIT_SEED_VAULT_BAD_INPUT', 'each seed record requires exactly two planned relays')
        const candidate = {
          recordId,
          parentRecordId: input.parentRecordId == null ? null : text(input.parentRecordId, 'parentRecordId', 512),
          minimumParentAgeMs: Number.isSafeInteger(input.minimumParentAgeMs) && input.minimumParentAgeMs >= 0 ? input.minimumParentAgeMs : 0,
          plannedRelays,
          replicas: Object.create(null),
          putAttempts: Object.create(null),
          recoveryGets: Object.create(null),
          completedAt: 0
        }
        const existing = state.records[recordId]
        if (existing) {
          if (JSON.stringify([existing.parentRecordId, existing.minimumParentAgeMs, existing.plannedRelays]) !==
              JSON.stringify([candidate.parentRecordId, candidate.minimumParentAgeMs, candidate.plannedRelays])) {
            fail('PEERIT_SEED_VAULT_PLAN_CONFLICT', `record ${recordId} conflicts with the durable plan`)
          }
          continue
        }
        state.records[recordId] = candidate
      }
      return { manifestSha256, recordCount: Object.keys(state.records).length }
    })
  }

  async function resumePlan (recordIds, at = now()) {
    const state = await load()
    const output = []
    for (const recordId of recordIds) {
      const record = state.records[recordId]
      if (!record) fail('PEERIT_SEED_VAULT_UNKNOWN_RECORD', `record ${recordId} is not in the durable plan`)
      let eligibleAt = 0
      if (record.parentRecordId) {
        const parent = state.records[record.parentRecordId]
        if (!parent || !complete(parent)) {
          output.push({ recordId, eligible: false, reason: 'parent-incomplete', actions: [] })
          continue
        }
        eligibleAt = parent.completedAt + record.minimumParentAgeMs
        if (at < eligibleAt) {
          output.push({ recordId, eligible: false, reason: 'parent-age-gate', eligibleAt, actions: [] })
          continue
        }
      }
      output.push({
        recordId,
        eligible: true,
        eligibleAt,
        actions: record.plannedRelays.map(relayId => ({
          relayId,
          action: record.replicas[relayId] && record.replicas[relayId].verified === true
            ? 'get-only-revalidate'
            : 'put'
        }))
      })
    }
    return output
  }

  async function recordPutAttempt (recordId, relayId) {
    return transaction(state => {
      const record = state.records[recordId]
      if (!record || !record.plannedRelays.includes(relayId)) fail('PEERIT_SEED_VAULT_UNKNOWN_RECORD', 'PUT attempt is outside the durable plan')
      record.putAttempts[relayId] = (record.putAttempts[relayId] || 0) + 1
      return record.putAttempts[relayId]
    })
  }

  async function recordVerifiedReplica (input) {
    plain(input, 'verified replica')
    return transaction(state => {
      const record = state.records[input.recordId]
      if (!record || !record.plannedRelays.includes(input.relayId)) fail('PEERIT_SEED_VAULT_UNKNOWN_RECORD', 'verified replica is outside the durable plan')
      const next = {
        verified: true,
        verifiedAt: Number.isSafeInteger(input.verifiedAt) ? input.verifiedAt : now(),
        evidenceRef: text(input.evidenceRef, 'evidenceRef', 1024),
        readbackHash: text(input.readbackHash, 'readbackHash', 128),
        readerCapability: plain(input.readerCapability, 'readerCapability'),
        managementCapability: input.managementCapability == null ? null : plain(input.managementCapability, 'managementCapability')
      }
      const existing = record.replicas[input.relayId]
      if (existing && JSON.stringify(encodeNode(existing)) !== JSON.stringify(encodeNode(next))) {
        fail('PEERIT_SEED_VAULT_RECEIPT_CONFLICT', 'a different verified replica already owns this record/relay')
      }
      record.replicas[input.relayId] = existing || next
      if (complete(record) && !record.completedAt) {
        record.completedAt = Math.max(...record.plannedRelays.map(relayId => record.replicas[relayId].verifiedAt))
      }
      return { recordId: record.recordId, complete: complete(record), completedAt: record.completedAt }
    })
  }

  async function recordRecoveryGet (recordId, relayId, evidenceRef, verifiedAt = now()) {
    return transaction(state => {
      const record = state.records[recordId]
      if (!record || !record.replicas[relayId] || record.replicas[relayId].verified !== true) {
        fail('PEERIT_SEED_VAULT_RECOVERY_WITHOUT_CAP', 'GET-only recovery requires a durable verified reader capability')
      }
      record.recoveryGets[relayId] = {
        count: ((record.recoveryGets[relayId] && record.recoveryGets[relayId].count) || 0) + 1,
        evidenceRef: text(evidenceRef, 'recovery evidenceRef', 1024),
        verifiedAt
      }
      return { recordId, relayId, putAttempts: record.putAttempts[relayId] || 0, recoveryGets: record.recoveryGets[relayId].count }
    })
  }

  async function sanitizedReceiptManifest () {
    const state = await load()
    const records = Object.values(state.records).sort((a, b) => a.recordId.localeCompare(b.recordId)).map(record => ({
      recordId: record.recordId,
      parentRecordId: record.parentRecordId,
      minimumParentAgeMs: record.minimumParentAgeMs,
      completed: complete(record),
      completedAt: record.completedAt,
      replicas: record.plannedRelays.map(relayId => {
        const replica = record.replicas[relayId]
        return {
          relayId,
          verified: replica && replica.verified === true,
          verifiedAt: replica ? replica.verifiedAt : 0,
          evidenceRef: replica ? replica.evidenceRef : null,
          readbackHash: replica ? replica.readbackHash : null,
          putAttempts: record.putAttempts[relayId] || 0,
          recoveryGets: (record.recoveryGets[relayId] && record.recoveryGets[relayId].count) || 0
        }
      })
    }))
    return {
      schema: PEERIT_SEED_RECEIPT_MANIFEST_SCHEMA_V1,
      version: 1,
      manifestSha256: state.manifestSha256,
      vaultRevision: state.revision,
      complete: records.length > 0 && records.every(record => record.completed),
      records
    }
  }

  async function assertComplete (requiredRecordIds) {
    const state = await load()
    const missing = requiredRecordIds.filter(recordId => !state.records[recordId] || !complete(state.records[recordId]))
    if (missing.length) fail('PEERIT_SEED_PUBLISH_PARTIAL', `required seed records remain incomplete: ${missing.join(', ')}`, 2)
    return true
  }

  function close () { passphrase.fill(0) }

  return Object.freeze({
    bindPlan,
    resumePlan,
    recordPutAttempt,
    recordVerifiedReplica,
    recordRecoveryGet,
    sanitizedReceiptManifest,
    assertComplete,
    close
  })
}
