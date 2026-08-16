import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  randomBytes
} from 'node:crypto'
import {
  constants as fsConstants,
  closeSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, parse, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  arch,
  hostname,
  networkInterfaces,
  platform,
  release
} from 'node:os'
import { xchacha20poly1305 } from '../../js/vendor/noble-ciphers/chacha.js'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  isAllZero,
  u16Bytes,
  u32Bytes,
  u64Bytes
} from '../../js/substrate/release-control-primitives.mjs'
import {
  canonicalPeeritLimitedPublicInboxJsonV1
} from '../../js/substrate/inbox-topic-v1.mjs'
import {
  hashPeeritLimitedPublicInboxSignedWrapperV1,
  validatePeeritLimitedPublicInboxSignedWrapperV1,
  validatePeeritLimitedPublicInboxSigningPackageV1
} from '../sign-limited-public-inbox-bootstrap.mjs'
import {
  loadPeeritSeq29AcceptedHiveRelayOperatorV1
} from './seq29-accepted-hiverelay-operator.mjs'

const {
  decodeBlindExternalProfileValueV1
} = (await loadPeeritSeq29AcceptedHiveRelayOperatorV1()).control

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const PROFILE_PIN_SHA256 = '74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd'
const LIMITED_CUSTODY_CONTRACT_SHA256 = 'c3ca211165d962b74951ad699104071e899cf8b811b37ecfe0b6062c8c9f3fae'
const LIMITED_BUNDLE_DOMAIN = 'peerit.hiverelay.limited-public-inbox-management-bundle.v1'
const LIMITED_BUNDLE_KIND = 2
const LIMITED_PLAINTEXT_CODEC = 3
const PREPARED_FILE = '0001-prepared.cenc'
const BOUND_FILE = '0002-public-binding.cenc'
const FINAL_FILE = '0003-management-custody-codec3.cenc'
const QUARANTINE_FILE = '0002-quarantined.json'
const IDENTITY_FILE = 'identity.json'
const HEX64 = /^[0-9a-f]{64}$/
const RELAY_ID = /^[a-z][a-z0-9-]{0,31}$/
const TRANSACTION_ID = /^seq29-[0-9a-f]{64}$/
const X25519_FIELD_PRIME_LE = new Uint8Array([
  0xed, ...Array(30).fill(0xff), 0x7f
])
const TRANSITION_LOCK = '.peerit-seq29-transition.lock'
const TRANSITION_LOCK_STAGE = /^\.peerit-seq29-transition\.lock\.([1-9][0-9]*)\.([0-9a-f]{32})\.stage$/
const LOW_ORDER_X25519_PUBLIC_KEYS = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
])
const PRIVATE_STAGES = Object.freeze({ PREPARED: 1, PUBLIC_BOUND: 2 })
const ACTIVE_TRANSACTION_GUARDS = new Set()
const LOCAL_CUSTODY_TRANSITIONS = new WeakMap()
let protocolAuthorityChecked = false

function localBootFilesystemIdentity () {
  for (const candidate of ['/private/var/run', '/run']) {
    try {
      const metadata = lstatSync(candidate)
      if (metadata.isDirectory()) {
        return {
          path: candidate,
          dev: metadata.dev,
          ino: metadata.ino,
          birthtimeMs: metadata.birthtimeMs
        }
      }
    } catch {}
  }
  fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
    'a local boot-scoped runtime directory is required for lock recovery')
}

const LOCAL_HOST_BOOT_IDENTITY = createHash('sha256').update(JSON.stringify({
  hostname: hostname(),
  platform: platform(),
  arch: arch(),
  release: release(),
  bootFilesystem: localBootFilesystemIdentity(),
  macs: [...new Set(Object.values(networkInterfaces()).flat()
    .filter(value => value != null && !value.internal &&
      value.mac !== '00:00:00:00:00:00')
    .map(value => value.mac.toLowerCase()))].sort()
})).digest('hex')

function fail (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details !== undefined) error.details = details
  throw error
}

function exact (value, fields, field) {
  if (value == null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} must be a plain data object`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string') ||
      fields.some(key => !Object.hasOwn(descriptors, key))) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} has missing or unexpected fields`)
  }
  for (const key of fields) {
    if (!descriptors[key].enumerable || !Object.hasOwn(descriptors[key], 'value')) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field}.${key} must be an enumerable data property`)
    }
  }
  return value
}

function denseArray (value, length, field) {
  if (!Array.isArray(value) || value.length !== length ||
      Object.keys(value).join('\0') !== Array.from({ length }, (_, index) => String(index)).join('\0')) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} must be a dense ${length}-element array`)
  }
  return value
}

function bytes (value, length, field, { nonzero = true } = {}) {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} must be ${length} bytes`)
  }
  const output = new Uint8Array(value)
  if (nonzero && isAllZero(output)) {
    output.fill(0)
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} must be nonzero`)
  }
  return output
}

function hex32 (value, field) {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} must be lowercase 32-byte hexadecimal`)
  }
  return new Uint8Array(Buffer.from(value, 'hex'))
}

function opaqueId (value, field) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256 ||
      !/^[A-Za-z0-9._:-]+$/.test(value)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} is not a bounded opaque identifier`)
  }
  return value
}

function u32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} is outside u32`)
  }
  return value
}

function u8 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} is outside u8`)
  }
  return value
}

function u64 (value, field) {
  try {
    value = BigInt(value)
  } catch {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} is outside u64`)
  }
  if (value < 0n || value > (1n << 64n) - 1n) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', `${field} is outside u64`)
  }
  return value
}

function sha256Hex (value) {
  return createHash('sha256').update(value).digest('hex')
}

function objectDigest (value) {
  return sha256Hex(canonicalPeeritLimitedPublicInboxJsonV1(value))
}

function protocolSignedBootstrapHash (signedBootstrap) {
  return objectDigest({
    payload: signedBootstrap.payload,
    signature: signedBootstrap.signature
  })
}

function randomNonzero (length) {
  for (;;) {
    const value = new Uint8Array(randomBytes(length))
    if (!isAllZero(value)) return value
    value.fill(0)
  }
}

function uniqueRandomNonzero (length, used) {
  for (;;) {
    const value = randomNonzero(length)
    const encoded = bytesToHex(value)
    if (!used.has(encoded)) {
      used.add(encoded)
      return value
    }
    value.fill(0)
  }
}

function destroyPrivateStageValue (value) {
  for (const entry of value?.entries || []) {
    entry.createPrivateSeed?.fill(0)
    entry.renewPrivateSeed?.fill(0)
    entry.closePrivateSeed?.fill(0)
  }
  value?.signingPackageBytes?.fill(0)
}

function destroyManagementValidation (value) {
  for (const entry of value?.entries || []) {
    entry.createPrivateSeed?.fill(0)
    entry.renewPrivateSeed?.fill(0)
    entry.closePrivateSeed?.fill(0)
  }
}

function observeSecretTransient (observer, event, value) {
  if (observer == null) return
  observer(Object.freeze({
    schema: 'peerit-seq29-local-custody-secret-transient-v1',
    event,
    bytes: value
  }))
}

function wipeSecretTransient (value, observer, event) {
  if (value == null) return
  value.fill(0)
  observeSecretTransient(observer, event, value)
}

function assertDistinct (values, field) {
  for (let left = 0; left < values.length; left++) {
    for (let right = left + 1; right < values.length; right++) {
      if (bytesEqual(values[left], values[right])) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE',
          `${field} must be pairwise distinct`)
      }
    }
  }
}

function assertNonzero (value, field) {
  if (isAllZero(value)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_CORRUPT', `${field} must be nonzero`)
  }
  return value
}

function assertX25519PublicKey (value, field) {
  value = bytes(value, 32, field, { nonzero: false })
  if ((value[31] & 0x80) !== 0 || compareLittleEndian(value, X25519_FIELD_PRIME_LE) >= 0) {
    value.fill(0)
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_NONCANONICAL_KEY',
      `${field} is not a canonical X25519 u-coordinate`)
  }
  if (LOW_ORDER_X25519_PUBLIC_KEYS.has(bytesToHex(value))) {
    value.fill(0)
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_LOW_ORDER_KEY', `${field} is a known low-order X25519 point`)
  }
  return value
}

function compareLittleEndian (left, right) {
  for (let index = left.byteLength - 1; index >= 0; index--) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1
  }
  return 0
}

function x25519PrivateKey (raw) {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(raw)
  ])
  try {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  } finally {
    der.fill(0)
  }
}

function x25519PublicKey (raw) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(raw)
    ]),
    format: 'der',
    type: 'spki'
  })
}

function x25519PublicFromPrivate (raw) {
  return new Uint8Array(createPublicKey(x25519PrivateKey(raw))
    .export({ format: 'der', type: 'spki' }).subarray(-32))
}

function ed25519PublicFromSeed (seed) {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed)
  ])
  try {
    return new Uint8Array(createPublicKey(createPrivateKey({
      key: der,
      format: 'der',
      type: 'pkcs8'
    })).export({ format: 'der', type: 'spki' }).subarray(-32))
  } finally {
    der.fill(0)
  }
}

function generateX25519Pair (usedPublicKeys) {
  for (;;) {
    const privateKey = randomNonzero(32)
    let publicKey
    try {
      publicKey = x25519PublicFromPrivate(privateKey)
      const encoded = bytesToHex(publicKey)
      if (!LOW_ORDER_X25519_PUBLIC_KEYS.has(encoded) && !usedPublicKeys.has(encoded)) {
        usedPublicKeys.add(encoded)
        return { privateKey, publicKey }
      }
    } catch {}
    privateKey.fill(0)
    publicKey?.fill(0)
  }
}

function gfMultiply (left, right) {
  let a = left
  let b = right
  let output = 0
  for (let bit = 0; bit < 8; bit++) {
    if (b & 1) output ^= a
    const high = a & 0x80
    a = (a << 1) & 0xff
    if (high) a ^= 0x1b
    b >>>= 1
  }
  return output
}

function gfPower (value, exponent) {
  let output = 1
  let base = value
  let power = exponent
  while (power > 0) {
    if (power & 1) output = gfMultiply(output, base)
    base = gfMultiply(base, base)
    power >>>= 1
  }
  return output
}

function interpolatePair (leftIndex, left, rightIndex, right) {
  if (leftIndex === rightIndex || left.byteLength !== 32 || right.byteLength !== 32) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE', 'Shamir shares have invalid or duplicate coordinates')
  }
  const inverse = gfPower(leftIndex ^ rightIndex, 254)
  const output = new Uint8Array(32)
  for (let index = 0; index < 32; index++) {
    const coefficient = gfMultiply(left[index] ^ right[index], inverse)
    output[index] = left[index] ^ gfMultiply(coefficient, leftIndex)
  }
  return output
}

function seal (plaintext, aad, nonce, key) {
  try {
    return xchacha20poly1305(key, nonce, aad).encrypt(plaintext)
  } catch (cause) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_CRYPTO_FAILED', 'XChaCha20-Poly1305 sealing failed', {
      cause: cause?.message || String(cause)
    })
  }
}

function open (sealed, aad, nonce, key) {
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(sealed)
  } catch {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED', 'XChaCha20-Poly1305 authentication failed')
  }
}

function fsyncDirectory (path) {
  const descriptor = openSync(path, 'r')
  try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
}

function assertOwned (metadata, field) {
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS', `${field} is not owned by the current operator`)
  }
}

function metadataIdentity (metadata) {
  return Object.freeze({ dev: metadata.dev, ino: metadata.ino })
}

function sameIdentity (metadata, expected) {
  return metadata.dev === expected.dev && metadata.ino === expected.ino
}

function lstatIfPresent (path) {
  try {
    return lstatSync(path)
  } catch (cause) {
    if (cause?.code === 'ENOENT') return null
    throw cause
  }
}

function assertNoSymlinkParents (path) {
  const absolute = resolve(path)
  const root = parse(absolute).root
  const suffix = relative(root, absolute)
  let cursor = root
  for (const component of suffix === '' ? [] : suffix.split(sep)) {
    cursor = join(cursor, component)
    const metadata = lstatIfPresent(cursor)
    if (metadata == null) break
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS', `${cursor} is not a real directory`)
    }
  }
}

function assertPrivateDirectory (path, field, expectedIdentity) {
  assertNoSymlinkParents(path)
  const metadata = lstatIfPresent(path)
  if (metadata == null || metadata.isSymbolicLink() || !metadata.isDirectory() ||
      (metadata.mode & 0o777) !== 0o700) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      `${field} must be an owned real directory with exact mode 0700`)
  }
  assertOwned(metadata, field)
  if (expectedIdentity != null && !sameIdentity(metadata, expectedIdentity)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED', `${field} was replaced`)
  }
  return metadata
}

function ensurePrivateDirectory (path, field = basename(path)) {
  assertNoSymlinkParents(dirname(path))
  if (lstatIfPresent(path) == null) {
    try {
      mkdirSync(path, { mode: 0o700 })
      fsyncDirectory(dirname(path))
    } catch (cause) {
      if (cause?.code !== 'EEXIST') throw cause
    }
  }
  return assertPrivateDirectory(path, field)
}

function assertPrivateFileMetadata (metadata, field) {
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1 ||
      (metadata.mode & 0o777) !== 0o600) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      `${field} must be a single-link regular file with exact mode 0600`)
  }
  assertOwned(metadata, field)
}

function validateTransactionBoundary (boundary) {
  const rootBefore = assertPrivateDirectory(
    boundary.root, 'custody root', boundary.rootIdentity
  )
  if (dirname(boundary.directory) !== boundary.root ||
      basename(boundary.directory) !== boundary.transactionId) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      'custody transaction directory escaped its private root')
  }
  const transaction = assertPrivateDirectory(
    boundary.directory, 'custody transaction directory', boundary.transactionIdentity
  )
  const rootAfter = assertPrivateDirectory(
    boundary.root, 'custody root', boundary.rootIdentity
  )
  if (!sameIdentity(rootBefore, rootAfter)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
      'custody root changed during boundary validation')
  }
  return transaction
}

function privateFilePresent (path, boundary) {
  validateTransactionBoundary(boundary)
  if (dirname(path) !== boundary.directory) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      'custody file escaped its transaction directory')
  }
  const metadata = lstatIfPresent(path)
  if (metadata != null) assertPrivateFileMetadata(metadata, basename(path))
  validateTransactionBoundary(boundary)
  return metadata != null
}

function atomicCreate (target, value, boundary, beforeLink) {
  validateTransactionBoundary(boundary)
  const parent = dirname(target)
  if (parent !== boundary.directory) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      'durable custody target escaped its transaction directory')
  }
  const temporary = join(parent,
    `.${basename(target)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  let descriptor
  let temporaryIdentity
  try {
    descriptor = openSync(temporary, 'wx', 0o600)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_IO_FAILED', 'temporary custody file is not private')
    }
    assertOwned(opened, 'temporary custody file')
    temporaryIdentity = metadataIdentity(opened)
    fchmodSync(descriptor, 0o600)
    writeFileSync(descriptor, value)
    fsyncSync(descriptor)
    validateTransactionBoundary(boundary)
    const temporaryMetadata = lstatSync(temporary)
    assertPrivateFileMetadata(temporaryMetadata, 'temporary custody file')
    if (!sameIdentity(temporaryMetadata, temporaryIdentity)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
        'temporary custody file was replaced before commit')
    }
    beforeLink?.()
    validateTransactionBoundary(boundary)
    linkSync(temporary, target)
    unlinkSync(temporary)
    closeSync(descriptor)
    descriptor = undefined
    validateTransactionBoundary(boundary)
    fsyncDirectory(parent)
    const readback = readPrivateFile(target, boundary)
    if (!Buffer.from(value).equals(readback)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_IO_FAILED',
        `${basename(target)} did not read back byte-identically`)
    }
    return readback
  } catch (cause) {
    if (cause?.code === 'EEXIST') {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_ALREADY_SEALED',
        `${basename(target)} is already sealed`)
    }
    if (cause?.code?.startsWith('PEERIT_')) throw cause
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_IO_FAILED',
      `could not durably create ${basename(target)}`, {
        cause: cause?.message || String(cause)
      })
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor) } catch {}
    }
    try {
      validateTransactionBoundary(boundary)
      const leftover = lstatIfPresent(temporary)
      if (leftover != null && temporaryIdentity != null &&
          sameIdentity(leftover, temporaryIdentity)) unlinkSync(temporary)
    } catch {}
    try {
      validateTransactionBoundary(boundary)
      fsyncDirectory(parent)
    } catch {}
  }
}

function readPrivateFile (path, boundary) {
  validateTransactionBoundary(boundary)
  if (dirname(path) !== boundary.directory) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      'custody read escaped its transaction directory')
  }
  if (!Number.isInteger(fsConstants.O_NOFOLLOW) || fsConstants.O_NOFOLLOW === 0) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      'this custody backend requires O_NOFOLLOW file support')
  }
  let descriptor
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const before = fstatSync(descriptor)
    assertPrivateFileMetadata(before, basename(path))
    const value = readFileSync(descriptor)
    const after = fstatSync(descriptor)
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_IO_FAILED', `${basename(path)} changed during readback`)
    }
    validateTransactionBoundary(boundary)
    return new Uint8Array(value)
  } catch (cause) {
    if (cause?.code?.startsWith('PEERIT_')) throw cause
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_IO_FAILED',
      `could not privately read ${basename(path)}`, {
        cause: cause?.message || String(cause)
      })
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}

function canonicalPrettyBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8')
}

function writeIdentity (boundary, identity, beforeLink) {
  const path = join(boundary.directory, IDENTITY_FILE)
  const value = canonicalPrettyBytes(identity)
  if (privateFilePresent(path, boundary)) {
    const existing = readPrivateFile(path, boundary)
    if (!bytesEqual(existing, value)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
        'custody transaction identity or recipient pins changed')
    }
    return
  }
  atomicCreate(path, value, boundary, beforeLink)
}

function stageCommitment (state, value) {
  return `seq29-custody:${state.toLowerCase()}:${sha256Hex(value)}`
}

function transactionIdFor (planHash, attemptId) {
  const attempt = asciiBytes(opaqueId(attemptId, 'attemptId'))
  return `seq29-${sha256Hex(concatBytes(
    asciiBytes('peerit.seq29.local-management-custody-transaction.v1'),
    hex32(planHash, 'planHash'), u16Bytes(attempt.byteLength), attempt
  ))}`
}

function snapshotPrivateEntries (input) {
  const entries = denseArray(input, 2, 'custody entries')
  const output = []
  try {
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index]
      exact(entry, [
        'relayId', 'allocationEpoch', 'createPrivateSeed', 'renewPrivateSeed',
        'closePrivateSeed'
      ], `custody entry ${index}`)
      let createPrivateSeed
      let renewPrivateSeed
      let closePrivateSeed
      try {
        createPrivateSeed = bytes(entry.createPrivateSeed, 32, `entry ${index} CREATE seed`)
        renewPrivateSeed = bytes(entry.renewPrivateSeed, 32, `entry ${index} RENEW seed`)
        closePrivateSeed = bytes(entry.closePrivateSeed, 32, `entry ${index} CLOSE seed`)
        output.push({
          relayId: entry.relayId,
          allocationEpoch: entry.allocationEpoch,
          createPrivateSeed,
          renewPrivateSeed,
          closePrivateSeed
        })
        createPrivateSeed = undefined
        renewPrivateSeed = undefined
        closePrivateSeed = undefined
      } finally {
        createPrivateSeed?.fill(0)
        renewPrivateSeed?.fill(0)
        closePrivateSeed?.fill(0)
      }
    }
    return output
  } catch (cause) {
    destroyPrivateStageValue({ entries: output })
    throw cause
  }
}

function privateStagePayload (stage, value) {
  const planHash = hex32(value.planHash, 'planHash')
  const attemptId = asciiBytes(opaqueId(value.attemptId, 'attemptId'))
  const entries = denseArray(value.entries, 2, 'private stage entries')
  const entryBytes = []
  let base
  try {
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index]
      exact(entry, [
        'relayId', 'allocationEpoch', 'createPrivateSeed', 'renewPrivateSeed',
        'closePrivateSeed'
      ], `private stage entry ${index}`)
      if (!RELAY_ID.test(entry.relayId)) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
          `private stage entry ${index}.relayId is invalid`)
      }
      const relayId = asciiBytes(entry.relayId)
      const create = bytes(entry.createPrivateSeed, 32, `entry ${index} CREATE seed`)
      const renew = bytes(entry.renewPrivateSeed, 32, `entry ${index} RENEW seed`)
      const close = bytes(entry.closePrivateSeed, 32, `entry ${index} CLOSE seed`)
      try {
        entryBytes.push(concatBytes(
          Uint8Array.of(relayId.byteLength), relayId,
          u32Bytes(u32(entry.allocationEpoch, `entry ${index} allocationEpoch`)),
          create, renew, close
        ))
      } finally {
        create.fill(0)
        renew.fill(0)
        close.fill(0)
      }
    }
    base = concatBytes(
      asciiBytes(stage === PRIVATE_STAGES.PREPARED ? 'P29CSTP1' : 'P29CSTB1'),
      Uint8Array.of(1), planHash, u16Bytes(attemptId.byteLength), attemptId,
      u64Bytes(u64(value.preparedUnixMillis, 'preparedUnixMillis')),
      Uint8Array.of(2), entryBytes
    )
    if (stage === PRIVATE_STAGES.PREPARED) {
      const output = base
      base = undefined
      return output
    }
    const signingPackageBytes = value.signingPackageBytes
    if (!(signingPackageBytes instanceof Uint8Array) || signingPackageBytes.byteLength < 1 ||
        signingPackageBytes.byteLength > 1048576) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', 'signing package bytes are out of bounds')
    }
    return concatBytes(base, u32Bytes(signingPackageBytes.byteLength), signingPackageBytes,
      hex32(value.signingPackageSha256, 'signingPackageSha256'),
      hex32(value.publicBindingDigest, 'publicBindingDigest'))
  } finally {
    base?.fill(0)
    for (const encodedEntry of entryBytes) encodedEntry.fill(0)
  }
}

class Reader {
  constructor (value, code = 'PEERIT_SEQ29_LOCAL_CUSTODY_CORRUPT') {
    this.value = value instanceof Uint8Array ? value : new Uint8Array(value)
    this.offset = 0
    this.code = code
  }

  view (length, field) {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.value.byteLength) {
      fail(this.code, `truncated ${field}`)
    }
    const output = this.value.subarray(this.offset, this.offset + length)
    this.offset += length
    return output
  }

  take (length, field) { return new Uint8Array(this.view(length, field)) }

  u8 (field) { return this.take(1, field)[0] }

  u16 (field) {
    const value = this.take(2, field)
    return value[0] * 256 + value[1]
  }

  u32 (field) {
    const value = this.take(4, field)
    return value[0] * 0x1000000 + value[1] * 0x10000 + value[2] * 0x100 + value[3]
  }

  u64 (field) {
    let output = 0n
    for (const byte of this.take(8, field)) output = (output << 8n) | BigInt(byte)
    return output
  }

  ascii (length, expected, field) {
    const value = this.take(length, field)
    if (!bytesEqual(value, asciiBytes(expected))) fail(this.code, `${field} is invalid`)
  }

  end (field) {
    if (this.offset !== this.value.byteLength) fail(this.code, `${field} has trailing bytes`)
  }
}

function parsePrivateStagePayload (stage, plaintext) {
  const reader = new Reader(plaintext)
  const entries = []
  let value
  try {
    reader.ascii(8, stage === PRIVATE_STAGES.PREPARED ? 'P29CSTP1' : 'P29CSTB1', 'stage magic')
    if (reader.u8('stage version') !== 1) fail(reader.code, 'private stage version is invalid')
    const planHash = bytesToHex(reader.take(32, 'plan hash'))
    const attemptId = Buffer.from(reader.take(reader.u16('attempt ID length'), 'attempt ID')).toString('ascii')
    opaqueId(attemptId, 'attemptId')
    const preparedUnixMillis = reader.u64('prepared Unix millis')
    if (reader.u8('entry count') !== 2) fail(reader.code, 'private stage must contain exactly two entries')
    for (let index = 0; index < 2; index++) {
      const relayId = Buffer.from(reader.take(reader.u8('relay ID length'), 'relay ID')).toString('ascii')
      if (!RELAY_ID.test(relayId)) fail(reader.code, 'private stage relay ID is invalid')
      const entry = {
        relayId,
        allocationEpoch: reader.u32('allocation epoch')
      }
      entries.push(entry)
      entry.createPrivateSeed = reader.take(32, 'CREATE seed')
      entry.renewPrivateSeed = reader.take(32, 'RENEW seed')
      entry.closePrivateSeed = reader.take(32, 'CLOSE seed')
    }
    value = { planHash, attemptId, preparedUnixMillis, entries }
    if (stage === PRIVATE_STAGES.PUBLIC_BOUND) {
      value.signingPackageBytes = reader.take(reader.u32('signing package length'), 'signing package')
      value.signingPackageSha256 = bytesToHex(reader.take(32, 'signing package hash'))
      value.publicBindingDigest = bytesToHex(reader.take(32, 'public binding digest'))
    }
    reader.end('private custody stage')
    return value
  } catch (cause) {
    destroyPrivateStageValue(value || { entries })
    throw cause
  }
}

function shareKey (privateKey, publicKey, custodySetId, bundleKind, shareIndex,
  custodianPublicKey, ephemeralPublicKey) {
  let shared
  try {
    shared = new Uint8Array(diffieHellman({
      privateKey: x25519PrivateKey(privateKey),
      publicKey: x25519PublicKey(publicKey)
    }))
  } catch (cause) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_LOW_ORDER_KEY', 'X25519 exchange failed', {
      cause: cause?.message || String(cause)
    })
  }
  try {
    if (isAllZero(shared)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_LOW_ORDER_KEY', 'X25519 produced an all-zero secret')
    }
    return new Uint8Array(hkdfSync('sha256', shared, custodySetId, concatBytes(
      asciiBytes('peerit.hiverelay.custody-share-key.v1'),
      Uint8Array.of(bundleKind), Uint8Array.of(shareIndex),
      custodianPublicKey, ephemeralPublicKey
    ), 32))
  } finally {
    shared.fill(0)
  }
}

function privateStageEnvelopePrefix (value) {
  return concatBytes(
    asciiBytes('P29LSE01'), Uint8Array.of(1), Uint8Array.of(value.stage),
    value.custodySetId, u32Bytes(value.plaintextLength), value.plaintextHash,
    value.keyCommitment, u32Bytes(value.sealedPayloadLength)
  )
}

function privateStageSharePrefix (value) {
  return concatBytes(
    asciiBytes('P29LSS01'), Uint8Array.of(1), Uint8Array.of(value.stage),
    value.custodySetId, Uint8Array.of(value.shareIndex), Uint8Array.of(2),
    Uint8Array.of(3), value.keyCommitment, value.sealedPayloadHash,
    value.custodianPublicKey, value.ephemeralPublicKey, value.nonce
  )
}

function sealPrivateStage (stage, plaintext, custodianPublicKeys) {
  const custodySetId = randomNonzero(32)
  const dataKey = randomNonzero(32)
  const coefficient = new Uint8Array(randomBytes(32))
  const payloadNonce = randomNonzero(24)
  const plaintextHash = blake2b256(concatBytes(
    asciiBytes('peerit.seq29.local-management-custody-stage-plaintext.v1'),
    Uint8Array.of(stage), u64Bytes(plaintext.byteLength), plaintext
  ))
  const keyCommitment = blake2b256(concatBytes(
    asciiBytes('peerit.seq29.local-management-custody-stage-key.v1'),
    custodySetId, dataKey
  ))
  const envelope = {
    stage,
    custodySetId,
    plaintextLength: plaintext.byteLength,
    plaintextHash,
    keyCommitment,
    sealedPayloadLength: plaintext.byteLength + 16
  }
  const payloadAad = privateStageEnvelopePrefix(envelope)
  const sealedPayload = seal(plaintext, payloadAad, payloadNonce, dataKey)
  const sealedPayloadHash = blake2b256(concatBytes(
    asciiBytes('peerit.seq29.local-management-custody-stage-sealed-payload.v1'),
    u64Bytes(sealedPayload.byteLength), sealedPayload
  ))
  const usedEphemerals = new Set()
  const usedNonces = new Set([bytesToHex(payloadNonce)])
  const shares = []
  try {
    for (let index = 0; index < 3; index++) {
      const ephemeral = generateX25519Pair(usedEphemerals)
      const sharePlaintext = new Uint8Array(32)
      for (let offset = 0; offset < 32; offset++) {
        sharePlaintext[offset] = dataKey[offset] ^ gfMultiply(coefficient[offset], index + 1)
      }
      const nonce = uniqueRandomNonzero(24, usedNonces)
      const value = {
        stage,
        custodySetId,
        shareIndex: index + 1,
        keyCommitment,
        sealedPayloadHash,
        custodianPublicKey: custodianPublicKeys[index],
        ephemeralPublicKey: ephemeral.publicKey,
        nonce
      }
      const key = shareKey(ephemeral.privateKey, custodianPublicKeys[index], custodySetId,
        stage, index + 1, custodianPublicKeys[index], ephemeral.publicKey)
      try {
        shares.push({
          ...value,
          sealedShare: seal(
            sharePlaintext, privateStageSharePrefix(value), nonce, key
          )
        })
      } finally {
        key.fill(0)
        sharePlaintext.fill(0)
        ephemeral.privateKey.fill(0)
      }
    }
    assertDistinct(shares.map(value => value.ephemeralPublicKey), 'private ephemeral keys')
    assertDistinct(shares.map(value => value.nonce), 'private share nonces')
    assertDistinct(shares.map(value => value.sealedShare), 'private sealed shares')
    return concatBytes(
      payloadAad, payloadNonce, sealedPayload, Uint8Array.of(3),
      shares.map(value => concatBytes(privateStageSharePrefix(value), value.sealedShare))
    )
  } finally {
    dataKey.fill(0)
    coefficient.fill(0)
  }
}

function parsePrivateStageEnvelope (input, custodianPublicKeys) {
  const reader = new Reader(input)
  const start = reader.offset
  reader.ascii(8, 'P29LSE01', 'private envelope magic')
  if (reader.u8('private envelope version') !== 1) fail(reader.code, 'private envelope version is invalid')
  const stage = reader.u8('private stage')
  if (![PRIVATE_STAGES.PREPARED, PRIVATE_STAGES.PUBLIC_BOUND].includes(stage)) {
    fail(reader.code, 'private envelope stage is invalid')
  }
  const custodySetId = assertNonzero(reader.take(32, 'custody set ID'), 'custody set ID')
  const plaintextLength = reader.u32('plaintext length')
  if (plaintextLength < 1 || plaintextLength > 1048576) fail(reader.code, 'private plaintext length is invalid')
  const plaintextHash = assertNonzero(reader.take(32, 'plaintext hash'), 'plaintext hash')
  const keyCommitment = assertNonzero(reader.take(32, 'key commitment'), 'key commitment')
  const sealedPayloadLength = reader.u32('sealed payload length')
  if (sealedPayloadLength !== plaintextLength + 16) fail(reader.code, 'sealed payload length is invalid')
  const payloadAad = input.slice(start, reader.offset)
  const payloadNonce = assertNonzero(reader.take(24, 'payload nonce'), 'payload nonce')
  const sealedPayload = assertNonzero(reader.take(sealedPayloadLength, 'sealed payload'),
    'sealed payload')
  const sealedPayloadHash = blake2b256(concatBytes(
    asciiBytes('peerit.seq29.local-management-custody-stage-sealed-payload.v1'),
    u64Bytes(sealedPayload.byteLength), sealedPayload
  ))
  if (reader.u8('share count') !== 3) fail(reader.code, 'private envelope must contain three shares')
  const shares = []
  for (let index = 0; index < 3; index++) {
    const shareStart = reader.offset
    reader.ascii(8, 'P29LSS01', 'private share magic')
    if (reader.u8('share version') !== 1 || reader.u8('share stage') !== stage ||
        !bytesEqual(reader.take(32, 'share custody set ID'), custodySetId) ||
        reader.u8('share index') !== index + 1 || reader.u8('share threshold') !== 2 ||
        reader.u8('share total') !== 3 ||
        !bytesEqual(reader.take(32, 'share key commitment'), keyCommitment) ||
        !bytesEqual(reader.take(32, 'share payload hash'), sealedPayloadHash)) {
      fail(reader.code, 'private encrypted share does not bind its envelope')
    }
    const custodianPublicKey = assertX25519PublicKey(reader.take(32, 'custodian public key'),
      `private share ${index + 1} recipient`)
    const ephemeralPublicKey = assertX25519PublicKey(reader.take(32, 'ephemeral public key'),
      `private share ${index + 1} ephemeral`)
    const nonce = assertNonzero(reader.take(24, 'share nonce'), `private share ${index + 1} nonce`)
    const aad = input.slice(shareStart, reader.offset)
    const sealedShare = assertNonzero(reader.take(48, 'sealed share'),
      `private share ${index + 1} ciphertext`)
    if (!bytesEqual(custodianPublicKey, custodianPublicKeys[index])) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_WRONG_RECIPIENT',
        `private share ${index + 1} differs from its pinned custodian`)
    }
    shares.push({ index: index + 1, custodianPublicKey, ephemeralPublicKey, nonce, aad, sealedShare })
  }
  reader.end('private stage envelope')
  assertDistinct(shares.map(value => value.custodianPublicKey), 'private custodian keys')
  assertDistinct(shares.map(value => value.ephemeralPublicKey), 'private ephemeral keys')
  assertDistinct(shares.map(value => value.nonce), 'private share nonces')
  assertDistinct(shares.map(value => value.sealedShare), 'private sealed shares')
  return {
    stage,
    custodySetId,
    plaintextLength,
    plaintextHash,
    keyCommitment,
    payloadAad,
    payloadNonce,
    sealedPayload,
    shares
  }
}

async function suppliedPrivateKeys (provider) {
  let supplied
  try { supplied = await provider() } catch (cause) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_KEYS_UNAVAILABLE', 'custodian key provider failed', {
      cause: cause?.message || String(cause)
    })
  }
  if (!Array.isArray(supplied) || supplied.length < 2 || supplied.length > 3) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_THRESHOLD',
      'custodian key provider must supply two or three private keys')
  }
  const output = []
  try {
    for (let index = 0; index < supplied.length; index++) {
      output.push(bytes(supplied[index], 32, `custodian private key ${index + 1}`))
    }
    return output
  } catch (cause) {
    for (const key of output) key.fill(0)
    throw cause
  } finally {
    for (const key of supplied) {
      if (key instanceof Uint8Array) key.fill(0)
    }
  }
}

async function recoverPrivateStage (envelopeBytes, custodianPublicKeys, provider) {
  const parsed = parsePrivateStageEnvelope(envelopeBytes, custodianPublicKeys)
  const privateKeys = await suppliedPrivateKeys(provider)
  const opened = []
  const candidates = []
  try {
    const seen = new Set()
    for (const privateKey of privateKeys) {
      const publicKey = assertX25519PublicKey(x25519PublicFromPrivate(privateKey),
        'derived custodian public key')
      const encoded = bytesToHex(publicKey)
      if (seen.has(encoded)) fail('PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE', 'duplicate custodian private key')
      seen.add(encoded)
      const share = parsed.shares.find(value => bytesEqual(value.custodianPublicKey, publicKey))
      if (share == null) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_WRONG_RECIPIENT',
          'custodian private key does not match a pinned recipient')
      }
      const key = shareKey(privateKey, share.ephemeralPublicKey, parsed.custodySetId,
        parsed.stage, share.index, share.custodianPublicKey, share.ephemeralPublicKey)
      try {
        opened.push({ index: share.index, bytes: open(share.sealedShare, share.aad, share.nonce, key) })
      } finally {
        key.fill(0)
        publicKey.fill(0)
      }
    }
    if (opened.length < 2) fail('PEERIT_SEQ29_LOCAL_CUSTODY_THRESHOLD', 'two shares are required')
    for (let left = 0; left < opened.length; left++) {
      for (let right = left + 1; right < opened.length; right++) {
        const dataKey = interpolatePair(opened[left].index, opened[left].bytes,
          opened[right].index, opened[right].bytes)
        let plaintext
        try {
          const commitment = blake2b256(concatBytes(
            asciiBytes('peerit.seq29.local-management-custody-stage-key.v1'),
            parsed.custodySetId, dataKey
          ))
          if (!bytesEqual(commitment, parsed.keyCommitment)) continue
          plaintext = open(parsed.sealedPayload, parsed.payloadAad, parsed.payloadNonce, dataKey)
          if (plaintext.byteLength !== parsed.plaintextLength || !bytesEqual(
            blake2b256(concatBytes(
              asciiBytes('peerit.seq29.local-management-custody-stage-plaintext.v1'),
              Uint8Array.of(parsed.stage), u64Bytes(plaintext.byteLength), plaintext
            )), parsed.plaintextHash)) continue
          candidates.push(new Uint8Array(plaintext))
        } catch (error) {
          if (error?.code !== 'PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED') throw error
        } finally {
          dataKey.fill(0)
          plaintext?.fill(0)
        }
      }
    }
    if (candidates.length === 0) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_RECONSTRUCTION_FAILED',
        'no two-share pair reconstructed the private custody stage')
    }
    for (let index = 1; index < candidates.length; index++) {
      if (!bytesEqual(candidates[0], candidates[index])) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_RECONSTRUCTION_AMBIGUOUS',
          'passing private-stage reconstructions disagree')
      }
    }
    const output = new Uint8Array(candidates[0])
    for (const candidate of candidates) candidate.fill(0)
    return { parsed, plaintext: output }
  } finally {
    for (const candidate of candidates) candidate.fill(0)
    for (const privateKey of privateKeys) privateKey.fill(0)
    for (const share of opened) share.bytes.fill(0)
  }
}

function applyGeneratedEnvelopeFixtureHook (stage, envelope, fixtureHooks) {
  if (typeof fixtureHooks?.corruptGeneratedEnvelope !== 'function') return envelope
  const candidate = new Uint8Array(envelope)
  envelope.fill(0)
  fixtureHooks.corruptGeneratedEnvelope(stage, candidate)
  if (!(candidate instanceof Uint8Array) || candidate.byteLength < 1) {
    candidate?.fill?.(0)
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_FIXTURE_INVALID',
      'generated-envelope fixture hook returned invalid bytes')
  }
  return candidate
}

function maybeCrashLocalCustodyFixture (fixtureHooks, stage) {
  if (fixtureHooks?.crashStage === stage) process.kill(process.pid, 'SIGKILL')
}

async function selfVerifyPrivateStageEnvelope (stage, envelope, plaintext,
  custodianPublicKeys, provider) {
  const recovered = await recoverPrivateStage(envelope, custodianPublicKeys, provider)
  try {
    if (recovered.parsed.stage !== stage || !bytesEqual(recovered.plaintext, plaintext)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_SELF_VERIFY_FAILED',
        'generated private custody stage did not reconstruct byte-identically')
    }
  } finally {
    recovered.plaintext.fill(0)
  }
}

async function selfVerifyFinalEnvelope (envelope, plaintext, signedBootstrap,
  custodianPublicKeys, provider) {
  const privateKeys = await suppliedPrivateKeys(provider)
  const pairs = privateKeys.length === 3
    ? [[0, 1], [0, 2], [1, 2]]
    : [[0, 1]]
  try {
    for (const pair of pairs) {
      const pairKeys = pair.map(index => new Uint8Array(privateKeys[index]))
      let recovered
      try {
        recovered = await recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
          envelope,
          custodianPublicKeys,
          custodianPrivateKeys: pairKeys,
          signedBootstrap
        })
        if (!bytesEqual(recovered.plaintext, plaintext)) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_SELF_VERIFY_FAILED',
            `generated final custody pair ${pair.join('+')} did not reconstruct exactly`)
        }
      } finally {
        recovered?.destroy()
        for (const key of pairKeys) key.fill(0)
      }
    }
  } finally {
    for (const key of privateKeys) key.fill(0)
  }
}

function assertProtocolAuthority () {
  if (protocolAuthorityChecked) return
  const profilePath = join(ROOT, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md')
  const profileBytes = readFileSync(profilePath)
  if (sha256Hex(profileBytes) !== PROFILE_PIN_SHA256) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PROFILE_DRIFT',
      'the admitted canonical Peerit profile source changed')
  }
  const protocolPath = join(ROOT,
    'protocol/seq29-limited-public-test/limited-management-custody-v1.json')
  const protocolBytes = readFileSync(protocolPath)
  if (sha256Hex(protocolBytes) !== LIMITED_CUSTODY_CONTRACT_SHA256) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PROFILE_DRIFT',
      'the exact limited management custody contract bytes changed')
  }
  const protocol = JSON.parse(protocolBytes)
  if (protocol?.schema !== 'peerit-seq29-limited-public-inbox-management-custody-v1' ||
      protocol?.bundle?.profilePinSha256 !== PROFILE_PIN_SHA256 ||
      protocol?.envelope?.bundleKind !== LIMITED_BUNDLE_KIND ||
      protocol?.envelope?.plaintextCodec !== LIMITED_PLAINTEXT_CODEC ||
      protocol?.envelope?.threshold !== 2 || protocol?.envelope?.totalShares !== 3) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PROFILE_DRIFT',
      'the limited management custody contract changed')
  }
  protocolAuthorityChecked = true
}

// These are the two exact profile child codecs named by the Seq29 contract.
// Receipt validation is delegated to the same authenticated captured-bytes
// control module used by qualification and ceremony; these local wrappers
// preserve the contract's canonical tags, field order, widths and bounds.
function encodeInboxStripeBindingV1 (value) {
  if (!(value?.createReceipt instanceof Uint8Array)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'InboxStripeBindingV1.createReceipt must be bytes')
  }
  const receipt = bytes(value.createReceipt, value.createReceipt.byteLength,
    'InboxStripeBindingV1.createReceipt')
  if (receipt.byteLength < 1 || receipt.byteLength > 16384) {
    receipt.fill(0)
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', 'InboxStripeBindingV1 receipt is out of bounds')
  }
  decodeBlindExternalProfileValueV1('InboxReceiptV1', receipt)
  return concatBytes(
    u16Bytes(282), u32Bytes(u32(value.inboxEpoch, 'binding inboxEpoch')),
    Uint8Array.of(u8(value.stripeIndex, 'binding stripeIndex')),
    bytes(value.relayPublicKey, 32, 'binding relayPublicKey'),
    u32Bytes(u32(value.allocationEpoch, 'binding allocationEpoch')),
    bytes(value.createPublicKey, 32, 'binding createPublicKey'),
    bytes(value.physicalTopic, 32, 'binding physicalTopic'), Uint8Array.of(3, 0, 3, 4),
    u16Bytes(receipt.byteLength), receipt
  )
}

function decodeInboxStripeBindingV1 (input) {
  const reader = new Reader(input)
  if (reader.u16('InboxStripeBindingV1 tag') !== 282) {
    fail(reader.code, 'InboxStripeBindingV1 tag is invalid')
  }
  const value = {
    inboxEpoch: reader.u32('binding inboxEpoch'),
    stripeIndex: reader.u8('binding stripeIndex'),
    relayPublicKey: reader.take(32, 'binding relayPublicKey'),
    allocationEpoch: reader.u32('binding allocationEpoch'),
    createPublicKey: reader.take(32, 'binding createPublicKey'),
    physicalTopic: reader.take(32, 'binding physicalTopic'),
    frameClassBits: reader.u8('binding frameClassBits'),
    appendAuthMode: reader.u8('binding appendAuthMode'),
    retentionClass: reader.u8('binding retentionClass'),
    leaseClass: reader.u8('binding leaseClass')
  }
  const receiptLength = reader.u16('binding receipt length')
  if (receiptLength < 1 || receiptLength > 16384) {
    fail(reader.code, 'binding receipt is out of bounds')
  }
  value.createReceipt = reader.take(receiptLength, 'binding receipt')
  reader.end('InboxStripeBindingV1')
  if (value.frameClassBits !== 3 || value.appendAuthMode !== 0 ||
      value.retentionClass !== 3 || value.leaseClass !== 4) {
    fail(reader.code, 'InboxStripeBindingV1 constants are invalid')
  }
  decodeBlindExternalProfileValueV1('InboxReceiptV1', value.createReceipt)
  if (!bytesEqual(encodeInboxStripeBindingV1(value), input)) {
    fail(reader.code, 'InboxStripeBindingV1 does not re-encode byte-identically')
  }
  return value
}

function encodeInboxManagementEntryV1 (value) {
  if (!(value?.bindingBytes instanceof Uint8Array) ||
      !(value?.latestReceipt instanceof Uint8Array)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'InboxManagementEntryV1 bounded child fields must be bytes')
  }
  const bindingBytes = bytes(value.bindingBytes, value.bindingBytes.byteLength,
    'InboxManagementEntryV1.bindingBytes')
  const receipt = bytes(value.latestReceipt, value.latestReceipt.byteLength,
    'InboxManagementEntryV1.latestReceipt')
  if (bindingBytes.byteLength < 1 || bindingBytes.byteLength > 8192 ||
      receipt.byteLength < 1 || receipt.byteLength > 16384) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'InboxManagementEntryV1 bounded bytes are out of range')
  }
  decodeInboxStripeBindingV1(bindingBytes)
  decodeBlindExternalProfileValueV1('InboxReceiptV1', receipt)
  let createPrivateSeed
  let renewPrivateSeed
  let closePrivateSeed
  try {
    createPrivateSeed = bytes(value.createPrivateSeed, 32, 'entry CREATE seed')
    renewPrivateSeed = bytes(value.renewPrivateSeed, 32, 'entry RENEW seed')
    closePrivateSeed = bytes(value.closePrivateSeed, 32, 'entry CLOSE seed')
    return concatBytes(
      u16Bytes(263), Uint8Array.of(1), u32Bytes(u32(value.inboxEpoch, 'entry inboxEpoch')),
      Uint8Array.of(u8(value.stripeIndex, 'entry stripeIndex')),
      bytes(value.relayPublicKey, 32, 'entry relayPublicKey'),
      bytes(value.bindingHash, 32, 'entry bindingHash'),
      u16Bytes(bindingBytes.byteLength), bindingBytes,
      createPrivateSeed, renewPrivateSeed, closePrivateSeed,
      bytes(value.renewPublicKey, 32, 'entry RENEW public key'),
      bytes(value.closePublicKey, 32, 'entry CLOSE public key'),
      u16Bytes(receipt.byteLength), receipt,
      u64Bytes(u64(value.latestRevision, 'entry latestRevision')),
      u32Bytes(u32(value.leaseEpoch, 'entry leaseEpoch'))
    )
  } finally {
    createPrivateSeed?.fill(0)
    renewPrivateSeed?.fill(0)
    closePrivateSeed?.fill(0)
  }
}

function decodeInboxManagementEntryV1 (input, transientObserver) {
  const reader = new Reader(input)
  const value = {}
  let canonicalReencode
  try {
    if (reader.u16('InboxManagementEntryV1 tag') !== 263 ||
        reader.u8('entry version') !== 1) {
      fail(reader.code, 'InboxManagementEntryV1 identity is invalid')
    }
    value.version = 1
    value.inboxEpoch = reader.u32('entry inboxEpoch')
    value.stripeIndex = reader.u8('entry stripeIndex')
    value.relayPublicKey = reader.take(32, 'entry relayPublicKey')
    value.bindingHash = reader.take(32, 'entry bindingHash')
    const bindingLength = reader.u16('entry binding length')
    if (bindingLength < 1 || bindingLength > 8192) fail(reader.code, 'entry binding is out of bounds')
    value.bindingBytes = reader.take(bindingLength, 'entry binding')
    value.createPrivateSeed = reader.take(32, 'entry CREATE seed')
    value.renewPrivateSeed = reader.take(32, 'entry RENEW seed')
    value.closePrivateSeed = reader.take(32, 'entry CLOSE seed')
    value.renewPublicKey = reader.take(32, 'entry RENEW public key')
    value.closePublicKey = reader.take(32, 'entry CLOSE public key')
    const receiptLength = reader.u16('entry receipt length')
    if (receiptLength < 1 || receiptLength > 16384) fail(reader.code, 'entry receipt is out of bounds')
    value.latestReceipt = reader.take(receiptLength, 'entry receipt')
    value.latestRevision = reader.u64('entry latestRevision')
    value.leaseEpoch = reader.u32('entry leaseEpoch')
    reader.end('InboxManagementEntryV1')
    decodeInboxStripeBindingV1(value.bindingBytes)
    decodeBlindExternalProfileValueV1('InboxReceiptV1', value.latestReceipt)
    canonicalReencode = encodeInboxManagementEntryV1(value)
    if (!bytesEqual(canonicalReencode, input)) {
      fail(reader.code, 'InboxManagementEntryV1 does not re-encode byte-identically')
    }
    return value
  } catch (cause) {
    destroyManagementValidation({ entries: [value] })
    throw cause
  } finally {
    wipeSecretTransient(canonicalReencode, transientObserver,
      'ZEROIZED_DECODE_ENTRY_CANONICAL_REENCODE')
  }
}

function allowFixture () {
  return process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST === '1'
}

function validateSigningPackage (input) {
  return validatePeeritLimitedPublicInboxSigningPackageV1(input, { allowFixture: allowFixture() })
}

function validatePreparedAgainstSigningPackage (prepared, signingPackage) {
  const set = signingPackage.payload.inboxEpochSets[0]
  if (prepared.entries.length !== 2 || set.bindings.length !== 2 ||
      signingPackage.createRequests.length !== 2) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
      'prepared custody and signing package do not contain exactly two topics')
  }
  const seeds = []
  const authorities = []
  try {
    for (const entry of prepared.entries) {
      const binding = set.bindings.find(value => value.relayId === entry.relayId)
      const request = signingPackage.createRequests.find(value => value.relayId === entry.relayId)
      if (binding == null || request == null || entry.allocationEpoch !== binding.allocationEpoch ||
          request.allocationEpoch !== binding.allocationEpoch) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
          `${entry.relayId} does not match its signed public binding`)
      }
      const createPublicKey = ed25519PublicFromSeed(entry.createPrivateSeed)
      const renewPublicKey = ed25519PublicFromSeed(entry.renewPrivateSeed)
      const closePublicKey = ed25519PublicFromSeed(entry.closePrivateSeed)
      if (bytesToHex(createPublicKey) !== binding.createPublicKey ||
          bytesToHex(createPublicKey) !== request.createPublicKey ||
          bytesToHex(renewPublicKey) !== request.renewPublicKey ||
          bytesToHex(closePublicKey) !== request.closePublicKey) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
          `${entry.relayId} management seeds do not derive its public authorities`)
      }
      seeds.push(entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed)
      authorities.push(createPublicKey, renewPublicKey, closePublicKey)
    }
    assertDistinct(seeds, 'all six management seeds')
    assertDistinct(authorities, 'all six management authorities')
  } finally {
    for (const authority of authorities) authority.fill(0)
  }
}

function buildManagementBundle (bound, signedBootstrapHash) {
  assertProtocolAuthority()
  const signingPackage = validateSigningPackage(bound.signingPackageBytes)
  validatePreparedAgainstSigningPackage(bound, signingPackage)
  const set = signingPackage.payload.inboxEpochSets[0]
  const entries = []
  let prefix
  try {
    for (const entry of bound.entries) {
      const binding = set.bindings.find(value => value.relayId === entry.relayId)
      const request = signingPackage.createRequests.find(value => value.relayId === entry.relayId)
      const receiptBytes = new Uint8Array(Buffer.from(binding.createReceiptCanonicalHex, 'hex'))
      const receipt = decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes)
      const bindingValue = {
        inboxEpoch: binding.inboxEpoch,
        stripeIndex: binding.stripeIndex,
        relayPublicKey: new Uint8Array(Buffer.from(binding.relayPublicKey, 'hex')),
        allocationEpoch: binding.allocationEpoch,
        createPublicKey: new Uint8Array(Buffer.from(binding.createPublicKey, 'hex')),
        physicalTopic: new Uint8Array(Buffer.from(binding.physicalTopic, 'hex')),
        frameClassBits: binding.frameClassBits,
        appendAuthMode: binding.appendAuthMode,
        retentionClass: binding.retentionClass,
        leaseClass: binding.leaseClass,
        createReceipt: receiptBytes
      }
      const bindingBytes = encodeInboxStripeBindingV1(bindingValue)
      const bindingHash = blake2b256(concatBytes(
        asciiBytes('peerit.hiverelay.inbox-management-binding.v1'),
        u64Bytes(bindingBytes.byteLength), bindingBytes
      ))
      const value = {
        version: 1,
        inboxEpoch: binding.inboxEpoch,
        stripeIndex: binding.stripeIndex,
        relayPublicKey: bindingValue.relayPublicKey,
        bindingHash,
        bindingBytes,
        createPrivateSeed: entry.createPrivateSeed,
        renewPrivateSeed: entry.renewPrivateSeed,
        closePrivateSeed: entry.closePrivateSeed,
        renewPublicKey: new Uint8Array(Buffer.from(request.renewPublicKey, 'hex')),
        closePublicKey: new Uint8Array(Buffer.from(request.closePublicKey, 'hex')),
        latestReceipt: receiptBytes,
        latestRevision: receipt.stateRevision,
        leaseEpoch: receipt.leaseEpoch
      }
      entries.push({
        bytes: encodeInboxManagementEntryV1(value),
        projection: concatBytes(bindingValue.relayPublicKey, bindingValue.physicalTopic)
      })
    }
    entries.sort((left, right) => compareBytes(left.projection, right.projection))
    prefix = concatBytes(
      Uint8Array.of(1), u64Bytes(29n), new Uint8Array(Buffer.from(PROFILE_PIN_SHA256, 'hex')),
      new Uint8Array(Buffer.from(signedBootstrapHash, 'hex')),
      u64Bytes(BigInt(signingPackage.payload.bootstrapSequence)),
      u32Bytes(set.inboxEpoch), Uint8Array.of(entries.length),
      entries.map(entry => concatBytes(u16Bytes(entry.bytes.byteLength), entry.bytes)),
      u64Bytes(bound.preparedUnixMillis)
    )
    const commitment = blake2b256(concatBytes(
      asciiBytes(LIMITED_BUNDLE_DOMAIN), u64Bytes(prefix.byteLength), prefix
    ))
    return { plaintext: concatBytes(prefix, commitment), signingPackage }
  } finally {
    prefix?.fill(0)
    for (const entry of entries) entry.bytes.fill(0)
  }
}

function finalEnvelopePrefix (value) {
  return concatBytes(
    Uint8Array.of(1), value.custodySetId, Uint8Array.of(LIMITED_BUNDLE_KIND),
    u16Bytes(LIMITED_PLAINTEXT_CODEC), u64Bytes(value.plaintextLength),
    value.plaintextHash, value.keyCommitment, u32Bytes(value.sealedPayloadLength)
  )
}

function finalSharePrefix (value) {
  return concatBytes(
    Uint8Array.of(1), value.custodySetId, Uint8Array.of(LIMITED_BUNDLE_KIND),
    Uint8Array.of(value.shareIndex), Uint8Array.of(2), Uint8Array.of(3),
    value.keyCommitment, value.sealedPayloadHash, value.custodianPublicKey,
    value.ephemeralPublicKey, value.nonce
  )
}

function sealFinalEnvelope (plaintext, custodianPublicKeys) {
  const custodySetId = randomNonzero(32)
  const dataKey = randomNonzero(32)
  const coefficient = new Uint8Array(randomBytes(32))
  const payloadNonce = randomNonzero(24)
  const keyCommitment = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-key.v1'), custodySetId, dataKey
  ))
  const plaintextHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-plaintext.v1'),
    Uint8Array.of(LIMITED_BUNDLE_KIND), u16Bytes(LIMITED_PLAINTEXT_CODEC),
    u64Bytes(plaintext.byteLength), plaintext
  ))
  const envelope = {
    custodySetId,
    plaintextLength: plaintext.byteLength,
    plaintextHash,
    keyCommitment,
    sealedPayloadLength: plaintext.byteLength + 16
  }
  const payloadAad = finalEnvelopePrefix(envelope)
  const sealedPayload = seal(plaintext, payloadAad, payloadNonce, dataKey)
  const sealedPayloadHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-sealed-payload.v1'),
    u64Bytes(sealedPayload.byteLength), sealedPayload
  ))
  const usedEphemerals = new Set()
  const usedNonces = new Set([bytesToHex(payloadNonce)])
  const shares = []
  try {
    for (let index = 0; index < 3; index++) {
      const ephemeral = generateX25519Pair(usedEphemerals)
      const sharePlaintext = new Uint8Array(32)
      for (let offset = 0; offset < 32; offset++) {
        sharePlaintext[offset] = dataKey[offset] ^ gfMultiply(coefficient[offset], index + 1)
      }
      const nonce = uniqueRandomNonzero(24, usedNonces)
      const value = {
        custodySetId,
        shareIndex: index + 1,
        keyCommitment,
        sealedPayloadHash,
        custodianPublicKey: custodianPublicKeys[index],
        ephemeralPublicKey: ephemeral.publicKey,
        nonce
      }
      const key = shareKey(ephemeral.privateKey, custodianPublicKeys[index], custodySetId,
        LIMITED_BUNDLE_KIND, index + 1, custodianPublicKeys[index], ephemeral.publicKey)
      try {
        shares.push({
          ...value,
          sealedShare: seal(
            sharePlaintext, finalSharePrefix(value), nonce, key
          )
        })
      } finally {
        key.fill(0)
        sharePlaintext.fill(0)
        ephemeral.privateKey.fill(0)
      }
    }
    assertDistinct(shares.map(value => value.ephemeralPublicKey), 'ephemeral keys')
    assertDistinct(shares.map(value => value.nonce), 'share nonces')
    assertDistinct(shares.map(value => value.sealedShare), 'sealed shares')
    return concatBytes(
      payloadAad, payloadNonce, sealedPayload, Uint8Array.of(3),
      shares.map(value => concatBytes(finalSharePrefix(value), value.sealedShare))
    )
  } finally {
    dataKey.fill(0)
    coefficient.fill(0)
  }
}

function parseFinalEnvelope (input, custodianPublicKeys) {
  const reader = new Reader(input)
  const prefixStart = reader.offset
  if (reader.u8('envelope version') !== 1) fail(reader.code, 'limited envelope version is invalid')
  const custodySetId = reader.take(32, 'custody set ID')
  if (isAllZero(custodySetId) || reader.u8('bundle kind') !== LIMITED_BUNDLE_KIND ||
      reader.u16('plaintext codec') !== LIMITED_PLAINTEXT_CODEC) {
    fail(reader.code, 'limited envelope identity is invalid')
  }
  const plaintextLength = reader.u64('plaintext length')
  if (plaintextLength < 1n || plaintextLength > 16777216n) {
    fail(reader.code, 'limited envelope plaintext length is invalid')
  }
  const plaintextHash = assertNonzero(reader.take(32, 'plaintext hash'), 'plaintext hash')
  const keyCommitment = assertNonzero(reader.take(32, 'key commitment'), 'key commitment')
  const sealedPayloadLength = reader.u32('sealed payload length')
  if (BigInt(sealedPayloadLength) !== plaintextLength + 16n) {
    fail(reader.code, 'limited envelope sealed payload length is invalid')
  }
  const payloadAad = input.slice(prefixStart, reader.offset)
  const payloadNonce = assertNonzero(reader.take(24, 'payload nonce'), 'payload nonce')
  const sealedPayload = assertNonzero(reader.take(sealedPayloadLength, 'sealed payload'),
    'sealed payload')
  const sealedPayloadHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-sealed-payload.v1'),
    u64Bytes(sealedPayload.byteLength), sealedPayload
  ))
  if (reader.u8('share count') !== 3) fail(reader.code, 'limited envelope must contain three shares')
  const shares = []
  for (let index = 0; index < 3; index++) {
    const shareStart = reader.offset
    if (reader.u8('share version') !== 1 ||
        !bytesEqual(reader.take(32, 'share custody set ID'), custodySetId) ||
        reader.u8('share bundle kind') !== LIMITED_BUNDLE_KIND ||
        reader.u8('share index') !== index + 1 || reader.u8('share threshold') !== 2 ||
        reader.u8('share total') !== 3 ||
        !bytesEqual(reader.take(32, 'share key commitment'), keyCommitment) ||
        !bytesEqual(reader.take(32, 'share payload hash'), sealedPayloadHash)) {
      fail(reader.code, 'limited encrypted share does not bind its envelope')
    }
    const custodianPublicKey = assertX25519PublicKey(reader.take(32, 'custodian public key'),
      `share ${index + 1} recipient`)
    const ephemeralPublicKey = assertX25519PublicKey(reader.take(32, 'ephemeral public key'),
      `share ${index + 1} ephemeral`)
    const nonce = assertNonzero(reader.take(24, 'share nonce'), `share ${index + 1} nonce`)
    const aad = input.slice(shareStart, reader.offset)
    const sealedShare = assertNonzero(reader.take(48, 'sealed share'),
      `share ${index + 1} ciphertext`)
    if (!bytesEqual(custodianPublicKey, custodianPublicKeys[index])) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_WRONG_RECIPIENT',
        `share ${index + 1} differs from its pinned custodian`)
    }
    shares.push({ index: index + 1, custodianPublicKey, ephemeralPublicKey, nonce, aad, sealedShare })
  }
  reader.end('PeeritLimitedPublicInboxCustodyEnvelopeV1')
  assertDistinct(shares.map(value => value.custodianPublicKey), 'custodian keys')
  assertDistinct(shares.map(value => value.ephemeralPublicKey), 'ephemeral keys')
  assertDistinct(shares.map(value => value.nonce), 'share nonces')
  assertDistinct(shares.map(value => value.sealedShare), 'sealed shares')
  return {
    custodySetId,
    plaintextLength,
    plaintextHash,
    keyCommitment,
    payloadAad,
    payloadNonce,
    sealedPayload,
    shares
  }
}

function validateManagementPlaintext (plaintext, signedBootstrap, transientObserver) {
  assertProtocolAuthority()
  const signed = validatePeeritLimitedPublicInboxSignedWrapperV1(signedBootstrap, {
    allowFixture: allowFixture()
  })
  const reader = new Reader(plaintext)
  if (reader.u8('bundle version') !== 1 || reader.u64('release sequence') !== 29n ||
      !bytesEqual(reader.take(32, 'profile pin hash'), Buffer.from(PROFILE_PIN_SHA256, 'hex'))) {
    fail(reader.code, 'limited management bundle identity is invalid')
  }
  const signedBootstrapHash = reader.take(32, 'signed bootstrap hash')
  if (bytesToHex(signedBootstrapHash) !== protocolSignedBootstrapHash(signed)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
      'limited management bundle names the wrong signed bootstrap')
  }
  if (reader.u64('bootstrap sequence') !== BigInt(signed.payload.bootstrapSequence) ||
      reader.u32('current inbox epoch') !== signed.payload.inboxEpochSets[0].inboxEpoch) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
      'limited management bundle names the wrong bootstrap sequence or epoch')
  }
  const count = reader.u8('entry count')
  if (count !== 2) fail(reader.code, 'initial Seq29 custody must contain exactly two entries')
  const encodedEntries = []
  for (let index = 0; index < count; index++) {
    const length = reader.u16('entry length')
    if (length < 1 || length > 8192) fail(reader.code, 'management entry length is invalid')
    const encodedEntry = reader.view(length, 'management entry')
    encodedEntries.push(encodedEntry)
    observeSecretTransient(transientObserver, 'PARENT_PLAINTEXT_ENTRY_VIEW', encodedEntry)
  }
  const createdUnixMillis = reader.u64('created Unix millis')
  const prefix = plaintext.subarray(0, reader.offset)
  observeSecretTransient(transientObserver, 'PARENT_PLAINTEXT_PREFIX_VIEW', prefix)
  const commitment = reader.take(32, 'bundle commitment')
  let commitmentPreimage
  let expectedCommitment
  try {
    commitmentPreimage = concatBytes(
      asciiBytes(LIMITED_BUNDLE_DOMAIN), u64Bytes(prefix.byteLength), prefix
    )
    expectedCommitment = blake2b256(commitmentPreimage)
    if (!bytesEqual(commitment, expectedCommitment)) {
      fail(reader.code, 'limited management bundle commitment is invalid')
    }
  } finally {
    wipeSecretTransient(commitmentPreimage, transientObserver,
      'ZEROIZED_BUNDLE_COMMITMENT_PREIMAGE')
    expectedCommitment?.fill(0)
  }
  reader.end('PeeritLimitedPublicInboxManagementBundleV1')
  const expectedBindings = [...signed.payload.inboxEpochSets[0].bindings]
    .sort((left, right) => compareBytes(
      Buffer.from(left.relayPublicKey + left.physicalTopic, 'hex'),
      Buffer.from(right.relayPublicKey + right.physicalTopic, 'hex')
    ))
  const decodedForCleanup = []
  try {
    const entries = encodedEntries.map((entryBytes, index) => {
      let entry
      let binding
      let entryReencode
      try {
        entry = decodeInboxManagementEntryV1(entryBytes, transientObserver)
        decodedForCleanup.push(entry)
        entryReencode = encodeInboxManagementEntryV1(entry)
        if (!bytesEqual(entryReencode, entryBytes)) throw new Error('entry re-encode drift')
        binding = decodeInboxStripeBindingV1(entry.bindingBytes)
        if (!bytesEqual(encodeInboxStripeBindingV1(binding), entry.bindingBytes)) throw new Error('binding re-encode drift')
      } catch (cause) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
          `management entry is not canonical: ${cause?.message || String(cause)}`)
      } finally {
        wipeSecretTransient(entryReencode, transientObserver,
          'ZEROIZED_OUTER_ENTRY_CANONICAL_REENCODE')
      }
      const expected = expectedBindings[index]
      const expectedReceipt = new Uint8Array(Buffer.from(expected.createReceiptCanonicalHex, 'hex'))
      const receipt = decodeBlindExternalProfileValueV1('InboxReceiptV1', entry.latestReceipt)
      const createPublicKey = ed25519PublicFromSeed(entry.createPrivateSeed)
      const renewPublicKey = ed25519PublicFromSeed(entry.renewPrivateSeed)
      const closePublicKey = ed25519PublicFromSeed(entry.closePrivateSeed)
      try {
        if (!bytesEqual(entry.bindingHash, blake2b256(concatBytes(
          asciiBytes('peerit.hiverelay.inbox-management-binding.v1'),
          u64Bytes(entry.bindingBytes.byteLength), entry.bindingBytes
        ))) || entry.inboxEpoch !== expected.inboxEpoch || entry.stripeIndex !== expected.stripeIndex ||
            binding.inboxEpoch !== expected.inboxEpoch || binding.inboxEpoch !== entry.inboxEpoch ||
            binding.stripeIndex !== expected.stripeIndex || binding.stripeIndex !== entry.stripeIndex ||
            binding.allocationEpoch !== expected.allocationEpoch ||
            !bytesEqual(entry.relayPublicKey, Buffer.from(expected.relayPublicKey, 'hex')) ||
            !bytesEqual(binding.relayPublicKey, entry.relayPublicKey) ||
            !bytesEqual(binding.createPublicKey, createPublicKey) ||
            !bytesEqual(entry.renewPublicKey, renewPublicKey) ||
            !bytesEqual(entry.closePublicKey, closePublicKey) ||
            !bytesEqual(binding.physicalTopic, Buffer.from(expected.physicalTopic, 'hex')) ||
            !bytesEqual(binding.createReceipt, expectedReceipt) ||
            !bytesEqual(entry.latestReceipt, expectedReceipt) || entry.latestRevision !== receipt.stateRevision ||
            entry.leaseEpoch !== receipt.leaseEpoch) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
            `management entry ${index} does not reproduce its bootstrap binding`)
        }
      } finally {
        createPublicKey.fill(0)
        renewPublicKey.fill(0)
        closePublicKey.fill(0)
      }
      return entry
    })
    const allSeeds = entries.flatMap(entry => [
      entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed
    ])
    assertDistinct(allSeeds, 'recovered management seeds')
    return { entries, createdUnixMillis, signedBootstrapHash: bytesToHex(signedBootstrapHash) }
  } catch (cause) {
    destroyManagementValidation({ entries: decodedForCleanup })
    throw cause
  }
}

function custodyReceipt (state, transactionId, commitment, extra = {}) {
  return Object.freeze({
    accepted: true,
    durable: true,
    state,
    transactionId,
    ...extra,
    commitment
  })
}

export function peeritSeq29LocalManagementCustodyTransactionIdV1 (input = {}) {
  exact(input, ['planHash', 'attemptId'], 'transaction identity input')
  return transactionIdFor(input.planHash, input.attemptId)
}

export function peeritSeq29LocalManagementCustodyPathsV1 (input = {}) {
  exact(input, ['directory', 'transactionId'], 'custody path input')
  if (typeof input.directory !== 'string' || input.directory.length < 1) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', 'custody directory is required')
  }
  if (typeof input.transactionId !== 'string' || !TRANSACTION_ID.test(input.transactionId)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'transactionId must be the canonical derived Seq29 custody identifier')
  }
  const transactionId = input.transactionId
  const directory = resolve(input.directory, transactionId)
  return Object.freeze({
    directory,
    identity: join(directory, IDENTITY_FILE),
    prepared: join(directory, PREPARED_FILE),
    publicBinding: join(directory, BOUND_FILE),
    finalEnvelope: join(directory, FINAL_FILE),
    quarantine: join(directory, QUARANTINE_FILE)
  })
}

function expectedTransactionIdentity (transactionId, planHash, attemptId,
  custodianPublicKeys) {
  return {
    schema: 'peerit-seq29-local-management-custody-transaction-v1',
    version: 1,
    transactionId,
    planHash,
    attemptId,
    custodianPublicKeys: custodianPublicKeys.map(bytesToHex),
    finalBundleKind: LIMITED_BUNDLE_KIND,
    finalPlaintextCodec: LIMITED_PLAINTEXT_CODEC
  }
}

function inspectTransactionState (paths, boundary) {
  const present = {
    identity: privateFilePresent(paths.identity, boundary),
    prepared: privateFilePresent(paths.prepared, boundary),
    publicBinding: privateFilePresent(paths.publicBinding, boundary),
    finalEnvelope: privateFilePresent(paths.finalEnvelope, boundary),
    quarantine: privateFilePresent(paths.quarantine, boundary)
  }
  let state
  if (!present.identity && !present.prepared && !present.publicBinding &&
      !present.finalEnvelope && !present.quarantine) state = 'EMPTY'
  else if (present.identity && !present.prepared && !present.publicBinding &&
      !present.finalEnvelope && !present.quarantine) state = 'IDENTIFIED'
  else if (present.identity && present.prepared && !present.publicBinding &&
      !present.finalEnvelope && !present.quarantine) state = 'PREPARED'
  else if (present.identity && present.prepared && present.publicBinding &&
      !present.finalEnvelope && !present.quarantine) state = 'PUBLIC_BOUND'
  else if (present.identity && present.prepared && present.publicBinding &&
      present.finalEnvelope && !present.quarantine) state = 'COMMITTED'
  else if (present.identity && present.prepared && !present.publicBinding &&
      !present.finalEnvelope && present.quarantine) state = 'QUARANTINED'
  else {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_STATE_CONFLICT',
      'custody transaction files do not form a monotonic state')
  }
  validateTransactionBoundary(boundary)
  return state
}

function requireTransactionState (paths, boundary, allowed, operation) {
  const state = inspectTransactionState(paths, boundary)
  if (!allowed.includes(state)) {
    if (state === 'QUARANTINED') {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_QUARANTINED',
        `quarantined custody is terminal and cannot ${operation}`)
    }
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_STATE_CONFLICT',
      `${operation} is invalid from custody state ${state}`)
  }
  return state
}

function verifyTransactionIdentity (boundary, expected) {
  const bytes = canonicalPrettyBytes(expected)
  const existing = readPrivateFile(join(boundary.directory, IDENTITY_FILE), boundary)
  if (!bytesEqual(existing, bytes)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
      'custody transaction identity or recipient pins changed')
  }
}

function createTransactionBoundary (root, rootIdentity, transactionId,
  transactionIdentities, create) {
  assertPrivateDirectory(root, 'custody root', rootIdentity)
  const directory = resolve(root, transactionId)
  if (dirname(directory) !== root || basename(directory) !== transactionId) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      'custody transaction escaped its private root')
  }
  let metadata
  if (create) metadata = ensurePrivateDirectory(directory, 'custody transaction directory')
  else metadata = assertPrivateDirectory(directory, 'custody transaction directory')
  assertPrivateDirectory(root, 'custody root', rootIdentity)
  const remembered = transactionIdentities.get(transactionId)
  if (remembered != null && !sameIdentity(metadata, remembered)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
      'custody transaction directory was replaced')
  }
  const transactionIdentity = remembered || metadataIdentity(metadata)
  transactionIdentities.set(transactionId, transactionIdentity)
  const boundary = Object.freeze({
    root,
    rootIdentity,
    directory,
    transactionIdentity,
    transactionId
  })
  validateTransactionBoundary(boundary)
  return boundary
}

function transitionFileIdentity (metadata) {
  return [
    metadata.dev, metadata.ino, metadata.mode, metadata.nlink, metadata.uid,
    metadata.size, metadata.mtimeMs, metadata.ctimeMs
  ].join(':')
}

function assertTransitionLockMetadata (metadata, links, field) {
  if (metadata.isSymbolicLink() || !metadata.isFile() ||
      !links.includes(metadata.nlink) || (metadata.mode & 0o777) !== 0o600 ||
      metadata.size < 1 || metadata.size > 4096) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      `${field} is not an exact private transition-lock file`)
  }
  assertOwned(metadata, field)
}

function readTransitionLock (path, boundary, links, field) {
  validateTransactionBoundary(boundary)
  if (dirname(path) !== boundary.directory) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      `${field} escaped the custody transaction directory`)
  }
  const before = lstatSync(path)
  assertTransitionLockMetadata(before, links, field)
  let descriptor
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const opened = fstatSync(descriptor)
    if (transitionFileIdentity(opened) !== transitionFileIdentity(before)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
        `${field} changed during open`)
    }
    const bytes = Buffer.alloc(before.size)
    let offset = 0
    while (offset < bytes.byteLength) {
      const count = readSync(descriptor, bytes, offset,
        bytes.byteLength - offset, offset)
      if (count === 0) break
      offset += count
    }
    const extra = Buffer.alloc(1)
    const after = fstatSync(descriptor)
    const durable = lstatSync(path)
    if (offset !== bytes.byteLength ||
        readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        transitionFileIdentity(after) !== transitionFileIdentity(before) ||
        transitionFileIdentity(durable) !== transitionFileIdentity(before)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
        `${field} changed during exact read`)
    }
    validateTransactionBoundary(boundary)
    let owner
    try { owner = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
        `${field} is not canonical UTF-8 JSON`)
    }
    exact(owner, [
      'schema', 'version', 'hostBootIdentity', 'pid', 'nonce', 'stage'
    ], field)
    if (owner.schema !== 'peerit-seq29-local-custody-transition-lock-v1' ||
        owner.version !== 1 || typeof owner.hostBootIdentity !== 'string' ||
        !HEX64.test(owner.hostBootIdentity) ||
        !Number.isSafeInteger(owner.pid) || owner.pid < 1 ||
        typeof owner.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(owner.nonce) ||
        typeof owner.stage !== 'string' ||
        !TRANSITION_LOCK_STAGE.test(owner.stage) ||
        !bytesEqual(bytes, canonicalPrettyBytes(owner))) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
        `${field} identity is invalid`)
    }
    return Object.freeze({ metadata: before, owner: Object.freeze(owner), bytes })
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}

function transitionOwnerAlive (owner) {
  // This recovery seam is deliberately single-host/local-filesystem only.
  // A lock from a different host or boot is conservatively live forever here;
  // it requires operator custody rather than PID-namespace inference.
  if (owner.hostBootIdentity !== LOCAL_HOST_BOOT_IDENTITY) return true
  try {
    process.kill(owner.pid, 0)
    return true
  } catch (cause) {
    if (cause?.code === 'ESRCH') return false
    return true
  }
}

function verifiedUnlinkTransition (path, boundary, expected, field) {
  validateTransactionBoundary(boundary)
  const current = lstatSync(path)
  if (transitionFileIdentity(current) !== transitionFileIdentity(expected)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
      `${field} changed before verified unlink`)
  }
  unlinkSync(path)
  validateTransactionBoundary(boundary)
}

function validateTransitionStageOwner (record, name, field) {
  const match = TRANSITION_LOCK_STAGE.exec(name)
  if (match == null || record.owner.pid !== Number(match[1]) ||
      record.owner.nonce !== match[2] || record.owner.stage !== name) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
      `${field} does not bind its exact staging path`)
  }
}

function reclaimStaleTransactionGuard (boundary) {
  validateTransactionBoundary(boundary)
  const lockPath = join(boundary.directory, TRANSITION_LOCK)
  const existing = lstatIfPresent(lockPath)
  if (existing != null) {
    const lock = readTransitionLock(lockPath, boundary, [1, 2],
      'custody transition guard')
    validateTransitionStageOwner(lock, lock.owner.stage,
      'custody transition guard')
    if (transitionOwnerAlive(lock.owner)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY',
        'another live process holds the custody transition guard')
    }
    if (lock.metadata.nlink === 2) {
      const stagePath = join(boundary.directory, lock.owner.stage)
      if (lstatIfPresent(stagePath) == null) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
          'stale transition guard has an unowned hard-link alias')
      }
      const stage = readTransitionLock(stagePath, boundary, [2],
        'stale custody transition guard stage')
      validateTransitionStageOwner(stage, lock.owner.stage,
        'stale custody transition guard stage')
      if (!sameIdentity(stage.metadata, metadataIdentity(lock.metadata)) ||
          !bytesEqual(stage.bytes, lock.bytes)) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
          'stale transition guard alias is not the exact owned stage')
      }
      verifiedUnlinkTransition(stagePath, boundary, stage.metadata,
        'stale custody transition guard stage')
      const single = readTransitionLock(lockPath, boundary, [1],
        'stale custody transition guard')
      if (!sameIdentity(single.metadata, metadataIdentity(lock.metadata)) ||
          !bytesEqual(single.bytes, lock.bytes)) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
          'stale transition guard changed after alias removal')
      }
      verifiedUnlinkTransition(lockPath, boundary, single.metadata,
        'stale custody transition guard')
    } else {
      verifiedUnlinkTransition(lockPath, boundary, lock.metadata,
        'stale custody transition guard')
    }
    fsyncDirectory(boundary.directory)
  }

  let removed = false
  for (const name of readdirSync(boundary.directory).sort()) {
    if (!name.startsWith(`${TRANSITION_LOCK}.`)) continue
    if (!TRANSITION_LOCK_STAGE.test(name)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
        'custody transition stage has a hostile path identity')
    }
    const stagePath = join(boundary.directory, name)
    const stage = readTransitionLock(stagePath, boundary, [1],
      'orphan custody transition guard stage')
    validateTransitionStageOwner(stage, name,
      'orphan custody transition guard stage')
    if (transitionOwnerAlive(stage.owner)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY',
        'another live process is acquiring the custody transition guard')
    }
    verifiedUnlinkTransition(stagePath, boundary, stage.metadata,
      'orphan custody transition guard stage')
    removed = true
  }
  if (removed) fsyncDirectory(boundary.directory)
}

function acquireTransactionGuard (boundary) {
  reclaimStaleTransactionGuard(boundary)
  const lockPath = join(boundary.directory, TRANSITION_LOCK)
  const nonce = randomBytes(16).toString('hex')
  const stageName = `${TRANSITION_LOCK}.${process.pid}.${nonce}.stage`
  const stagePath = join(boundary.directory, stageName)
  const owner = Object.freeze({
    schema: 'peerit-seq29-local-custody-transition-lock-v1',
    version: 1,
    hostBootIdentity: LOCAL_HOST_BOOT_IDENTITY,
    pid: process.pid,
    nonce,
    stage: stageName
  })
  const ownerBytes = canonicalPrettyBytes(owner)
  let descriptor
  let stageMetadata
  try {
    descriptor = openSync(stagePath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY |
      fsConstants.O_NOFOLLOW, 0o600)
    fchmodSync(descriptor, 0o600)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== 0 ||
        (opened.mode & 0o777) !== 0o600) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
        'new custody transition guard stage is not private and empty')
    }
    assertOwned(opened, 'new custody transition guard stage')
    const openedIdentity = metadataIdentity(opened)
    writeFileSync(descriptor, ownerBytes)
    fsyncSync(descriptor)
    stageMetadata = fstatSync(descriptor)
    assertTransitionLockMetadata(stageMetadata, [1],
      'new custody transition guard stage')
    if (!sameIdentity(stageMetadata, openedIdentity) ||
        stageMetadata.size !== ownerBytes.byteLength) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
        'custody transition guard stage changed during write')
    }
    closeSync(descriptor)
    descriptor = undefined
    const ready = readTransitionLock(stagePath, boundary, [1],
      'new custody transition guard stage')
    validateTransitionStageOwner(ready, stageName,
      'new custody transition guard stage')
    if (!bytesEqual(ready.bytes, ownerBytes)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
        'custody transition guard stage changed before link')
    }
    try { linkSync(stagePath, lockPath) } catch (cause) {
      if (cause?.code === 'EEXIST') {
        verifiedUnlinkTransition(stagePath, boundary, ready.metadata,
          'uncommitted custody transition guard stage')
        fsyncDirectory(boundary.directory)
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY',
          'another process acquired the custody transition guard')
      }
      throw cause
    }
    const alias = readTransitionLock(stagePath, boundary, [2],
      'linked custody transition guard stage')
    const lock = readTransitionLock(lockPath, boundary, [2],
      'linked custody transition guard')
    if (!sameIdentity(alias.metadata, metadataIdentity(lock.metadata)) ||
        !bytesEqual(alias.bytes, ownerBytes) || !bytesEqual(lock.bytes, ownerBytes)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
        'custody transition guard link handoff changed')
    }
    verifiedUnlinkTransition(stagePath, boundary, alias.metadata,
      'linked custody transition guard stage')
    fsyncDirectory(boundary.directory)
    const durable = readTransitionLock(lockPath, boundary, [1],
      'custody transition guard')
    if (!sameIdentity(durable.metadata, metadataIdentity(lock.metadata)) ||
        !bytesEqual(durable.bytes, ownerBytes)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
        'custody transition guard changed after durable handoff')
    }
    return Object.freeze({
      path: lockPath,
      identity: metadataIdentity(durable.metadata),
      ownerBytes
    })
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor) } catch {}
    }
    if (lstatIfPresent(lockPath) == null && stageMetadata != null) {
      try {
        const current = lstatIfPresent(stagePath)
        if (current != null && sameIdentity(current, metadataIdentity(stageMetadata))) {
          unlinkSync(stagePath)
          fsyncDirectory(boundary.directory)
        }
      } catch {}
    }
  }
}

function releaseTransactionGuard (boundary, guard) {
  const record = readTransitionLock(guard.path, boundary, [1],
    'custody transition guard')
  if (!sameIdentity(record.metadata, guard.identity) ||
      !bytesEqual(record.bytes, guard.ownerBytes)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED',
      'custody transition guard was replaced')
  }
  verifiedUnlinkTransition(guard.path, boundary, record.metadata,
    'custody transition guard')
  fsyncDirectory(boundary.directory)
}

async function withTransactionGuard (options, task) {
  const guardKey = `${options.root}\0${options.transactionId}`
  if (ACTIVE_TRANSACTION_GUARDS.has(guardKey)) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY',
      'another in-process custody transition is already active')
  }
  ACTIVE_TRANSACTION_GUARDS.add(guardKey)
  let boundary
  let guard
  try {
    boundary = createTransactionBoundary(
      options.root, options.rootIdentity, options.transactionId,
      options.transactionIdentities, options.create
    )
    guard = acquireTransactionGuard(boundary)
    return await task(boundary)
  } finally {
    try {
      if (guard != null) releaseTransactionGuard(boundary, guard)
    } finally {
      ACTIVE_TRANSACTION_GUARDS.delete(guardKey)
    }
  }
}

export function createPeeritSeq29LocalManagementCustodyV1 (input = {}) {
  exact(input, ['directory', 'custodianPublicKeys', 'custodianPrivateKeyProvider'],
    'local custody adapter input')
  return createLocalManagementCustody(input, null)
}

export function createPeeritSeq29LocalManagementCustodyFixtureV1 (input = {}) {
  exact(input, [
    'directory', 'custodianPublicKeys', 'custodianPrivateKeyProvider',
    'corruptGeneratedEnvelope'
  ], 'local custody fixture adapter input')
  if (!allowFixture() || typeof input.corruptGeneratedEnvelope !== 'function') {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_FIXTURE_FORBIDDEN',
      'generated-envelope corruption hooks are fixture-only')
  }
  return createLocalManagementCustody({
    directory: input.directory,
    custodianPublicKeys: input.custodianPublicKeys,
    custodianPrivateKeyProvider: input.custodianPrivateKeyProvider
  }, Object.freeze({ corruptGeneratedEnvelope: input.corruptGeneratedEnvelope }))
}

export function createPeeritSeq29LocalManagementCustodyCrashFixtureV1 (input = {}) {
  exact(input, [
    'directory', 'custodianPublicKeys', 'custodianPrivateKeyProvider', 'crashStage'
  ], 'local custody crash fixture adapter input')
  if (!allowFixture() ||
      input.crashStage !== 'INNER_AFTER_PREPARED_FSYNC_BEFORE_GUARD_RELEASE') {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_FIXTURE_FORBIDDEN',
      'local custody process-death injection is fixture-only')
  }
  return createLocalManagementCustody({
    directory: input.directory,
    custodianPublicKeys: input.custodianPublicKeys,
    custodianPrivateKeyProvider: input.custodianPrivateKeyProvider
  }, Object.freeze({ crashStage: input.crashStage }))
}

function createLocalManagementCustody (input, fixtureHooks) {
  if (typeof input.directory !== 'string' || input.directory.length < 1 ||
      typeof input.custodianPrivateKeyProvider !== 'function') {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'directory and in-process custodianPrivateKeyProvider are required')
  }
  const root = resolve(input.directory)
  const custodianPublicKeys = denseArray(input.custodianPublicKeys, 3, 'custodian public keys')
    .map((value, index) => assertX25519PublicKey(value, `custodian public key ${index + 1}`))
  assertDistinct(custodianPublicKeys, 'custodian public keys')
  const rootIdentity = metadataIdentity(ensurePrivateDirectory(root, 'custody root'))
  const transactionIdentities = new Map()
  assertProtocolAuthority()

  function guardOptions (transactionId, create) {
    return { root, rootIdentity, transactionId, transactionIdentities, create }
  }

  async function prepare (request) {
    exact(request, ['schema', 'disposition', 'planHash', 'attemptId', 'entries'], 'custody prepare request')
    if (request.schema !== 'peerit-limited-inbox-topic-private-custody-input-v1' ||
        request.disposition !== 'SEALED_PENDING_CREATE') {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', 'custody prepare request identity is invalid')
    }
    const transactionId = transactionIdFor(request.planHash, request.attemptId)
    const paths = peeritSeq29LocalManagementCustodyPathsV1({ directory: root, transactionId })
    return withTransactionGuard(guardOptions(transactionId, true), async boundary => {
      const state = requireTransactionState(paths, boundary, [
        'EMPTY', 'IDENTIFIED', 'PREPARED', 'PUBLIC_BOUND', 'COMMITTED'
      ], 'prepare')
      const identity = expectedTransactionIdentity(
        transactionId, request.planHash, request.attemptId, custodianPublicKeys
      )
      if (state !== 'EMPTY') verifyTransactionIdentity(boundary, identity)
      const snapshot = {
        planHash: request.planHash,
        attemptId: request.attemptId,
        preparedUnixMillis: BigInt(Date.now()),
        entries: snapshotPrivateEntries(request.entries)
      }
      let plaintext
      let envelope
      try {
        plaintext = privateStagePayload(PRIVATE_STAGES.PREPARED, snapshot)
        if (['PREPARED', 'PUBLIC_BOUND', 'COMMITTED'].includes(state)) {
          const recovered = await recoverPrivateStage(
            readPrivateFile(paths.prepared, boundary), custodianPublicKeys,
            input.custodianPrivateKeyProvider
          )
          let existing
          try {
            requireTransactionState(paths, boundary, [state], 'continue prepare')
            existing = parsePrivateStagePayload(PRIVATE_STAGES.PREPARED, recovered.plaintext)
            const expected = privateStagePayload(PRIVATE_STAGES.PREPARED, {
              ...snapshot,
              preparedUnixMillis: existing.preparedUnixMillis
            })
            try {
              if (!bytesEqual(expected, recovered.plaintext)) {
                fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
                  'repeated custody prepare differs from the durable request')
              }
            } finally { expected.fill(0) }
          } finally {
            destroyPrivateStageValue(existing)
            recovered.plaintext.fill(0)
          }
          const durable = readPrivateFile(paths.prepared, boundary)
          try {
            return custodyReceipt('SEALED_PENDING_CREATE', transactionId,
              stageCommitment('PREPARED', durable))
          } finally { durable.fill(0) }
        }
        envelope = applyGeneratedEnvelopeFixtureHook('PREPARED',
          sealPrivateStage(PRIVATE_STAGES.PREPARED, plaintext, custodianPublicKeys),
          fixtureHooks)
        await selfVerifyPrivateStageEnvelope(PRIVATE_STAGES.PREPARED, envelope, plaintext,
          custodianPublicKeys, input.custodianPrivateKeyProvider)
        requireTransactionState(paths, boundary, [state], 'commit prepared custody')
        if (state === 'EMPTY') {
          writeIdentity(boundary, identity, () => {
            requireTransactionState(paths, boundary, ['EMPTY'], 'commit custody identity')
          })
        }
        requireTransactionState(paths, boundary, ['IDENTIFIED'], 'commit prepared custody')
        const created = atomicCreate(paths.prepared, envelope, boundary, () => {
          requireTransactionState(paths, boundary, ['IDENTIFIED'], 'commit prepared custody')
        })
        requireTransactionState(paths, boundary, ['PREPARED'], 'finish prepare')
        maybeCrashLocalCustodyFixture(fixtureHooks,
          'INNER_AFTER_PREPARED_FSYNC_BEFORE_GUARD_RELEASE')
        try {
          return custodyReceipt('SEALED_PENDING_CREATE', transactionId,
            stageCommitment('PREPARED', created))
        } finally { created.fill(0) }
      } finally {
        plaintext?.fill(0)
        envelope?.fill(0)
        destroyPrivateStageValue(snapshot)
      }
    })
  }

  // Narrow recovery seam for an authenticated, already-durable PREPARED
  // transition. Callers must hold the exact module-created custody adapter and
  // the durable envelope commitment. The returned seed copies are explicitly
  // destroyable and are never attached to the public adapter.
  async function recoverPreparedTransition (request) {
    exact(request, ['planHash', 'attemptId', 'commitment'],
      'prepared custody transition request')
    const transactionId = transactionIdFor(request.planHash, request.attemptId)
    const paths = peeritSeq29LocalManagementCustodyPathsV1({ directory: root, transactionId })
    return withTransactionGuard(guardOptions(transactionId, false), async boundary => {
      const state = requireTransactionState(paths, boundary,
        ['PREPARED'], 'recover prepared transition')
      verifyTransactionIdentity(boundary, expectedTransactionIdentity(
        transactionId, request.planHash, request.attemptId, custodianPublicKeys
      ))
      const durable = readPrivateFile(paths.prepared, boundary)
      let recovered
      let prepared
      try {
        if (request.commitment !== stageCommitment('PREPARED', durable)) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
            'prepared transition commitment differs from durable custody')
        }
        recovered = await recoverPrivateStage(
          durable, custodianPublicKeys, input.custodianPrivateKeyProvider)
        requireTransactionState(paths, boundary, [state], 'finish prepared transition recovery')
        prepared = parsePrivateStagePayload(PRIVATE_STAGES.PREPARED, recovered.plaintext)
        if (prepared.planHash !== request.planHash || prepared.attemptId !== request.attemptId) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
            'recovered PREPARED identity differs from the transition request')
        }
        const entries = prepared.entries
        prepared.entries = []
        let destroyed = false
        return Object.freeze({
          schema: 'peerit-seq29-local-management-prepared-transition-v1',
          version: 1,
          planHash: prepared.planHash,
          attemptId: prepared.attemptId,
          transactionId,
          commitment: request.commitment,
          preparedUnixMillis: String(prepared.preparedUnixMillis),
          entries: Object.freeze(entries.map(entry => Object.freeze(entry))),
          destroy () {
            if (destroyed) return
            destroyed = true
            destroyPrivateStageValue({ entries })
          }
        })
      } finally {
        durable.fill(0)
        recovered?.plaintext.fill(0)
        destroyPrivateStageValue(prepared)
      }
    })
  }

  // Return only the durable public receipt for an exact PREPARED transition.
  // This deliberately does not decrypt the envelope or expose any seed
  // material. It exists so a caller can reconstruct a lost outer commitment
  // record after the inner PREPARED envelope itself became durable.
  async function inspectPreparedTransition (request) {
    exact(request, ['planHash', 'attemptId'],
      'prepared custody transition inspection request')
    const transactionId = transactionIdFor(request.planHash, request.attemptId)
    const paths = peeritSeq29LocalManagementCustodyPathsV1({ directory: root, transactionId })
    return withTransactionGuard(guardOptions(transactionId, false), async boundary => {
      requireTransactionState(paths, boundary,
        ['PREPARED'], 'inspect prepared transition')
      verifyTransactionIdentity(boundary, expectedTransactionIdentity(
        transactionId, request.planHash, request.attemptId, custodianPublicKeys
      ))
      const durable = readPrivateFile(paths.prepared, boundary)
      try {
        requireTransactionState(paths, boundary,
          ['PREPARED'], 'finish prepared transition inspection')
        return custodyReceipt('SEALED_PENDING_CREATE', transactionId,
          stageCommitment('PREPARED', durable))
      } finally { durable.fill(0) }
    })
  }

  async function commitPublicBinding (request) {
    exact(request, [
      'transactionId', 'planHash', 'attemptId', 'signingPackage',
      'signingPackageSha256', 'publicBindingDigest'
    ], 'custody public binding request')
    const transactionId = transactionIdFor(request.planHash, request.attemptId)
    if (request.transactionId !== transactionId) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH', 'public binding transaction ID is invalid')
    }
    const paths = peeritSeq29LocalManagementCustodyPathsV1({ directory: root, transactionId })
    return withTransactionGuard(guardOptions(transactionId, false), async boundary => {
      const state = requireTransactionState(paths, boundary,
        ['PREPARED', 'PUBLIC_BOUND', 'COMMITTED'], 'commit public binding')
      verifyTransactionIdentity(boundary, expectedTransactionIdentity(
        transactionId, request.planHash, request.attemptId, custodianPublicKeys
      ))
      const signingPackage = validateSigningPackage(request.signingPackage)
      if (request.signingPackageSha256 !== objectDigest({
        schema: signingPackage.schema,
        version: signingPackage.version,
        offlineOnly: signingPackage.offlineOnly,
        hiverelayCommit: signingPackage.hiverelayCommit,
        createRequests: signingPackage.createRequests,
        payload: signingPackage.payload
      }) || request.publicBindingDigest !== objectDigest({
        schema: 'peerit-seq29-limited-inbox-custody-public-binding-v1',
        planHash: request.planHash,
        signingPackageSha256: request.signingPackageSha256,
        signingPackage: {
          schema: signingPackage.schema,
          version: signingPackage.version,
          offlineOnly: signingPackage.offlineOnly,
          hiverelayCommit: signingPackage.hiverelayCommit,
          createRequests: signingPackage.createRequests,
          payload: signingPackage.payload
        }
      })) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
          'public binding hashes do not bind the exact signing package')
      }
      const recovered = await recoverPrivateStage(
        readPrivateFile(paths.prepared, boundary), custodianPublicKeys,
        input.custodianPrivateKeyProvider
      )
      let boundPlaintext
      let prepared
      let envelope
      try {
        requireTransactionState(paths, boundary, [state], 'continue public binding')
        prepared = parsePrivateStagePayload(PRIVATE_STAGES.PREPARED, recovered.plaintext)
        if (prepared.planHash !== request.planHash || prepared.attemptId !== request.attemptId) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
            'prepared custody differs from the public binding request')
        }
        validatePreparedAgainstSigningPackage(prepared, signingPackage)
        const bound = {
          ...prepared,
          signingPackageBytes: signingPackage.canonicalBytes,
          signingPackageSha256: request.signingPackageSha256,
          publicBindingDigest: request.publicBindingDigest
        }
        boundPlaintext = privateStagePayload(PRIVATE_STAGES.PUBLIC_BOUND, bound)
        if (state !== 'PREPARED') {
          const existing = await recoverPrivateStage(
            readPrivateFile(paths.publicBinding, boundary), custodianPublicKeys,
            input.custodianPrivateKeyProvider
          )
          try {
            requireTransactionState(paths, boundary, [state], 'continue public binding')
            if (!bytesEqual(existing.plaintext, boundPlaintext)) {
              fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
                'repeated public binding differs from the durable binding')
            }
          } finally { existing.plaintext.fill(0) }
        } else {
          envelope = applyGeneratedEnvelopeFixtureHook('PUBLIC_BOUND',
            sealPrivateStage(PRIVATE_STAGES.PUBLIC_BOUND,
              boundPlaintext, custodianPublicKeys), fixtureHooks)
          await selfVerifyPrivateStageEnvelope(PRIVATE_STAGES.PUBLIC_BOUND,
            envelope, boundPlaintext, custodianPublicKeys,
            input.custodianPrivateKeyProvider)
          requireTransactionState(paths, boundary, ['PREPARED'], 'commit public binding')
          atomicCreate(paths.publicBinding, envelope, boundary, () => {
            requireTransactionState(paths, boundary, ['PREPARED'], 'commit public binding')
          }).fill(0)
          requireTransactionState(paths, boundary, ['PUBLIC_BOUND'], 'finish public binding')
        }
        const durable = readPrivateFile(paths.publicBinding, boundary)
        try {
          return custodyReceipt('COMMITTED_AWAITING_SIGNED_BOOTSTRAP', transactionId,
            stageCommitment('PUBLIC_BOUND', durable), {
              signingPackageSha256: request.signingPackageSha256,
              publicBindingDigest: request.publicBindingDigest
            })
        } finally { durable.fill(0) }
      } finally {
        destroyPrivateStageValue(prepared)
        recovered.plaintext.fill(0)
        boundPlaintext?.fill(0)
        envelope?.fill(0)
      }
    })
  }

  async function finalizeSignedBootstrap (request) {
    exact(request, [
      'transactionId', 'planHash', 'attemptId', 'signingPackageSha256',
      'publicBindingDigest', 'signedBootstrap', 'signedBootstrapHash', 'finalizationDigest'
    ], 'custody finalization request')
    const transactionId = transactionIdFor(request.planHash, request.attemptId)
    if (request.transactionId !== transactionId) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH', 'finalization transaction ID is invalid')
    }
    const paths = peeritSeq29LocalManagementCustodyPathsV1({ directory: root, transactionId })
    return withTransactionGuard(guardOptions(transactionId, false), async boundary => {
      const state = requireTransactionState(paths, boundary,
        ['PUBLIC_BOUND', 'COMMITTED'], 'finalize signed bootstrap')
      verifyTransactionIdentity(boundary, expectedTransactionIdentity(
        transactionId, request.planHash, request.attemptId, custodianPublicKeys
      ))
      const recovered = await recoverPrivateStage(
        readPrivateFile(paths.publicBinding, boundary), custodianPublicKeys,
        input.custodianPrivateKeyProvider
      )
      let bundle
      let bound
      let envelope
      try {
        requireTransactionState(paths, boundary, [state], 'continue finalization')
        bound = parsePrivateStagePayload(PRIVATE_STAGES.PUBLIC_BOUND, recovered.plaintext)
        if (bound.planHash !== request.planHash || bound.attemptId !== request.attemptId ||
            bound.signingPackageSha256 !== request.signingPackageSha256 ||
            bound.publicBindingDigest !== request.publicBindingDigest) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
            'finalization differs from the durable public binding')
        }
        const signingPackage = validateSigningPackage(bound.signingPackageBytes)
        const signed = validatePeeritLimitedPublicInboxSignedWrapperV1(request.signedBootstrap, {
          allowFixture: allowFixture(),
          createRequests: signingPackage.createRequests
        })
        if (objectDigest(signed.payload) !== objectDigest(signingPackage.payload)) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
            'signed bootstrap payload differs from the durable signing package')
        }
        const signedBootstrapRequestHash = hashPeeritLimitedPublicInboxSignedWrapperV1(
          signed.canonicalBytes, {
            allowFixture: allowFixture(),
            createRequests: signingPackage.createRequests
          })
        const signedBootstrap = { payload: signed.payload, signature: signed.signature }
        const signedBootstrapHash = protocolSignedBootstrapHash(signedBootstrap)
        if (request.signedBootstrapHash !== signedBootstrapRequestHash ||
            request.finalizationDigest !== objectDigest({
              schema: 'peerit-seq29-limited-inbox-custody-finalization-v1',
              planHash: request.planHash,
              publicBindingDigest: request.publicBindingDigest,
              signedBootstrapHash: signedBootstrapRequestHash,
              signedBootstrap
            })) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
            'finalization hashes do not bind the exact signed bootstrap')
        }
        bundle = buildManagementBundle(bound, signedBootstrapHash)
        const managementBundleDigest = sha256Hex(bundle.plaintext)
        if (state === 'COMMITTED') {
          const existing = readPrivateFile(paths.finalEnvelope, boundary)
          try {
            await selfVerifyFinalEnvelope(existing, bundle.plaintext, signedBootstrap,
              custodianPublicKeys, input.custodianPrivateKeyProvider)
            requireTransactionState(paths, boundary, ['COMMITTED'], 'continue finalization')
          } finally { existing.fill(0) }
        } else {
          envelope = applyGeneratedEnvelopeFixtureHook('FINAL',
            sealFinalEnvelope(bundle.plaintext, custodianPublicKeys), fixtureHooks)
          await selfVerifyFinalEnvelope(envelope, bundle.plaintext, signedBootstrap,
            custodianPublicKeys, input.custodianPrivateKeyProvider)
          requireTransactionState(paths, boundary, ['PUBLIC_BOUND'], 'commit final custody')
          atomicCreate(paths.finalEnvelope, envelope, boundary, () => {
            requireTransactionState(paths, boundary, ['PUBLIC_BOUND'], 'commit final custody')
          }).fill(0)
          requireTransactionState(paths, boundary, ['COMMITTED'], 'finish finalization')
        }
        const finalEnvelope = readPrivateFile(paths.finalEnvelope, boundary)
        try {
          return custodyReceipt('COMMITTED', transactionId,
            stageCommitment('COMMITTED', finalEnvelope), {
              publicBindingDigest: request.publicBindingDigest,
              signedBootstrapHash: signedBootstrapRequestHash,
              finalizationDigest: request.finalizationDigest,
              managementBundleDigest
            })
        } finally { finalEnvelope.fill(0) }
      } finally {
        destroyPrivateStageValue(bound)
        recovered.plaintext.fill(0)
        bundle?.plaintext.fill(0)
        envelope?.fill(0)
      }
    })
  }

  async function quarantine (request) {
    exact(request, ['transactionId', 'planHash', 'attemptId', 'disposition'],
      'custody quarantine request')
    const transactionId = transactionIdFor(request.planHash, request.attemptId)
    if (request.transactionId !== transactionId ||
        !['QUARANTINED_NO_CREATE', 'QUARANTINED_CREATE_OUTCOME'].includes(request.disposition)) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH', 'quarantine identity is invalid')
    }
    const paths = peeritSeq29LocalManagementCustodyPathsV1({ directory: root, transactionId })
    return withTransactionGuard(guardOptions(transactionId, false), async boundary => {
      const state = requireTransactionState(paths, boundary,
        ['PREPARED', 'QUARANTINED'], 'quarantine')
      verifyTransactionIdentity(boundary, expectedTransactionIdentity(
        transactionId, request.planHash, request.attemptId, custodianPublicKeys
      ))
      const prepared = readPrivateFile(paths.prepared, boundary)
      const value = canonicalPrettyBytes({
        schema: 'peerit-seq29-local-management-custody-quarantine-v1',
        version: 1,
        transactionId,
        planHash: request.planHash,
        attemptId: request.attemptId,
        disposition: request.disposition,
        preparedEnvelopeSha256: sha256Hex(prepared)
      })
      prepared.fill(0)
      if (state === 'QUARANTINED') {
        if (!bytesEqual(readPrivateFile(paths.quarantine, boundary), value)) {
          fail('PEERIT_SEQ29_LOCAL_CUSTODY_IDENTITY_MISMATCH',
            'repeated quarantine differs from the durable marker')
        }
      } else {
        atomicCreate(paths.quarantine, value, boundary, () => {
          requireTransactionState(paths, boundary, ['PREPARED'], 'commit quarantine')
        }).fill(0)
        requireTransactionState(paths, boundary, ['QUARANTINED'], 'finish quarantine')
      }
      return custodyReceipt('QUARANTINED', transactionId,
        stageCommitment('QUARANTINED', value))
    })
  }

  const adapter = Object.freeze({ prepare, commitPublicBinding, finalizeSignedBootstrap, quarantine })
  LOCAL_CUSTODY_TRANSITIONS.set(adapter, Object.freeze({
    inspectPreparedTransition,
    recoverPreparedTransition
  }))
  return adapter
}

export async function inspectPeeritSeq29LocalManagementPreparedTransitionV1 (
  input = {}
) {
  exact(input, ['custody', 'planHash', 'attemptId'],
    'prepared custody transition inspection input')
  const state = LOCAL_CUSTODY_TRANSITIONS.get(input.custody)
  if (!state) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'a module-created local custody adapter is required for PREPARED inspection')
  }
  return state.inspectPreparedTransition({
    planHash: input.planHash,
    attemptId: input.attemptId
  })
}

export async function recoverPeeritSeq29LocalManagementPreparedTransitionV1 (
  input = {}
) {
  exact(input, ['custody', 'planHash', 'attemptId', 'commitment'],
    'prepared custody transition input')
  const state = LOCAL_CUSTODY_TRANSITIONS.get(input.custody)
  if (!state) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'a module-created local custody adapter is required for PREPARED recovery')
  }
  return state.recoverPreparedTransition({
    planHash: input.planHash,
    attemptId: input.attemptId,
    commitment: input.commitment
  })
}

export async function recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1 (input = {}) {
  exact(input, [
    'envelope', 'custodianPublicKeys', 'custodianPrivateKeys', 'signedBootstrap'
  ], 'limited management custody recovery input')
  return recoverLimitedManagementCustodyEnvelope(input)
}

export async function recoverPeeritSeq29LimitedManagementCustodyEnvelopeFixtureV1 (input = {}) {
  exact(input, [
    'envelope', 'custodianPublicKeys', 'custodianPrivateKeys', 'signedBootstrap',
    'observeSecretTransient'
  ], 'limited management custody fixture recovery input')
  if (!allowFixture()) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_FIXTURE_FORBIDDEN',
      'secret-transient instrumentation is fixture-only')
  }
  if (typeof input.observeSecretTransient !== 'function') {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
      'observeSecretTransient must be a fixture callback')
  }
  return recoverLimitedManagementCustodyEnvelope({
    envelope: input.envelope,
    custodianPublicKeys: input.custodianPublicKeys,
    custodianPrivateKeys: input.custodianPrivateKeys,
    signedBootstrap: input.signedBootstrap
  }, input.observeSecretTransient)
}

async function recoverLimitedManagementCustodyEnvelope (input, transientObserver) {
  assertProtocolAuthority()
  validatePeeritLimitedPublicInboxSignedWrapperV1(input.signedBootstrap, {
    allowFixture: allowFixture()
  })
  const envelope = input.envelope instanceof Uint8Array
    ? new Uint8Array(input.envelope)
    : (() => { fail('PEERIT_SEQ29_LOCAL_CUSTODY_INVALID', 'envelope must be bytes') })()
  const custodianPublicKeys = denseArray(input.custodianPublicKeys, 3, 'custodian public keys')
    .map((value, index) => assertX25519PublicKey(value, `custodian public key ${index + 1}`))
  assertDistinct(custodianPublicKeys, 'custodian public keys')
  if (!Array.isArray(input.custodianPrivateKeys) || input.custodianPrivateKeys.length < 2 ||
      input.custodianPrivateKeys.length > 3) {
    fail('PEERIT_SEQ29_LOCAL_CUSTODY_THRESHOLD', 'recovery requires two or three private keys')
  }
  const privateKeys = []
  let parsed
  try {
    for (let index = 0; index < input.custodianPrivateKeys.length; index++) {
      privateKeys.push(bytes(input.custodianPrivateKeys[index], 32,
        `custodian private key ${index + 1}`))
    }
    parsed = parseFinalEnvelope(envelope, custodianPublicKeys)
  } catch (cause) {
    envelope.fill(0)
    for (const key of privateKeys) key.fill(0)
    throw cause
  }
  const opened = []
  const candidates = []
  try {
    const seen = new Set()
    for (const privateKey of privateKeys) {
      const publicKey = assertX25519PublicKey(x25519PublicFromPrivate(privateKey),
        'derived custodian public key')
      const encoded = bytesToHex(publicKey)
      if (seen.has(encoded)) fail('PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE', 'duplicate custodian private key')
      seen.add(encoded)
      const share = parsed.shares.find(value => bytesEqual(value.custodianPublicKey, publicKey))
      if (share == null) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_WRONG_RECIPIENT',
          'custodian private key does not match a pinned recipient')
      }
      const key = shareKey(privateKey, share.ephemeralPublicKey, parsed.custodySetId,
        LIMITED_BUNDLE_KIND, share.index, share.custodianPublicKey, share.ephemeralPublicKey)
      try {
        opened.push({
          index: share.index,
          bytes: open(share.sealedShare, share.aad, share.nonce, key)
        })
      } finally {
        key.fill(0)
        publicKey.fill(0)
      }
    }
    if (opened.length < 2) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_THRESHOLD', 'fewer than two supplied shares authenticated')
    }
    for (let left = 0; left < opened.length; left++) {
      for (let right = left + 1; right < opened.length; right++) {
        const dataKey = interpolatePair(opened[left].index, opened[left].bytes,
          opened[right].index, opened[right].bytes)
        let plaintext
        let candidateValidation
        try {
          const commitment = blake2b256(concatBytes(
            asciiBytes('peerit.hiverelay.custody-key.v1'), parsed.custodySetId, dataKey
          ))
          if (!bytesEqual(commitment, parsed.keyCommitment)) continue
          plaintext = open(parsed.sealedPayload, parsed.payloadAad, parsed.payloadNonce, dataKey)
          if (BigInt(plaintext.byteLength) !== parsed.plaintextLength || !bytesEqual(
            blake2b256(concatBytes(
              asciiBytes('peerit.hiverelay.custody-plaintext.v1'),
              Uint8Array.of(LIMITED_BUNDLE_KIND), u16Bytes(LIMITED_PLAINTEXT_CODEC),
              u64Bytes(plaintext.byteLength), plaintext
            )), parsed.plaintextHash)) continue
          candidateValidation = validateManagementPlaintext(
            plaintext, input.signedBootstrap, transientObserver
          )
          candidates.push(new Uint8Array(plaintext))
        } catch (error) {
          if (![
            'PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED',
            'PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH',
            'PEERIT_SEQ29_LOCAL_CUSTODY_CORRUPT'
          ].includes(error?.code)) throw error
        } finally {
          destroyManagementValidation(candidateValidation)
          dataKey.fill(0)
          plaintext?.fill(0)
        }
      }
    }
    if (candidates.length === 0) {
      fail('PEERIT_SEQ29_LOCAL_CUSTODY_RECONSTRUCTION_FAILED',
        'no authenticated two-share reconstruction passed complete validation')
    }
    for (let index = 1; index < candidates.length; index++) {
      if (!bytesEqual(candidates[0], candidates[index])) {
        fail('PEERIT_SEQ29_LOCAL_CUSTODY_RECONSTRUCTION_AMBIGUOUS',
          'passing final custody reconstructions disagree')
      }
    }
    const plaintext = new Uint8Array(candidates[0])
    for (const candidate of candidates) candidate.fill(0)
    let validated
    try {
      validated = validateManagementPlaintext(
        plaintext, input.signedBootstrap, transientObserver
      )
    } catch (cause) {
      plaintext.fill(0)
      throw cause
    }
    let destroyed = false
    return Object.freeze({
      schema: 'peerit-seq29-limited-management-custody-recovery-v1',
      plaintext,
      entries: validated.entries,
      signedBootstrapHash: validated.signedBootstrapHash,
      rejectedShares: Object.freeze([]),
      destroy () {
        if (destroyed) return
        destroyed = true
        plaintext.fill(0)
        for (const entry of validated.entries) {
          entry.createPrivateSeed.fill(0)
          entry.renewPrivateSeed.fill(0)
          entry.closePrivateSeed.fill(0)
        }
      }
    })
  } finally {
    for (const candidate of candidates) candidate.fill(0)
    envelope.fill(0)
    for (const key of privateKeys) key.fill(0)
    for (const share of opened) share.bytes.fill(0)
  }
}

export const PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1 = Object.freeze({
  schema: 'PeeritLimitedPublicInboxManagementCustodyV1',
  version: 1,
  bundleName: 'PeeritLimitedPublicInboxManagementBundleV1',
  envelopeName: 'PeeritLimitedPublicInboxCustodyEnvelopeV1',
  profilePinSha256: PROFILE_PIN_SHA256,
  bundleKind: LIMITED_BUNDLE_KIND,
  plaintextCodec: LIMITED_PLAINTEXT_CODEC,
  threshold: 2,
  totalShares: 3,
  lowOrderX25519PublicKeys: Object.freeze([...LOW_ORDER_X25519_PUBLIC_KEYS])
})
