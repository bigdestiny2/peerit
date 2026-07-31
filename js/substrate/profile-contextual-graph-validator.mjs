import sodium from 'sodium-javascript'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  asciiBytes,
  asBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  domainLengthHash,
  isAllZero,
  u16Bytes,
  u32Bytes,
  u64Bytes
} from './release-control-primitives.mjs'
import { encodePeeritProfileRecordPrefixFromIr } from './profile-codec-ir.mjs'
import {
  hashPeeritWebAssetManifestV1,
  verifyPeeritWebAssetContentV1
} from './web-asset-manifest.mjs'

const AUTHORITY_STATE = new WeakMap()
const SUPPORTING_EVIDENCE_STATE = new WeakMap()
const MAX_U64 = (1n << 64n) - 1n
const DEFAULT_BUDGETS = Object.freeze({
  maximumFetchedObjects: 8192,
  maximumFetchedBytes: 268435456,
  maximumGraphDepth: 256,
  maximumEvidenceEntries: 1048576
})

const SINGLE_SIGNATURE = Object.freeze({
  PeeritHiveRelayProfilePinV1: Object.freeze({ domain: 'peerit.hiverelay.profile-pin.v1', field: 'signature' }),
  PeeritPinHistoryCheckpointV1: Object.freeze({ domain: 'peerit.pin-history-checkpoint.v1', field: 'signature' }),
  PeeritMigrationTransitionEvidenceV1: Object.freeze({ domain: 'peerit.migration-transition-evidence.v1', field: 'signature' }),
  AvailabilityRootV1: Object.freeze({ domain: 'peerit.hiverelay.root.v1', field: 'signature' }),
  AvailabilityBootstrapV1: Object.freeze({ domain: 'peerit.hiverelay.bootstrap.v1', field: 'signature' }),
  PeeritAnnouncementV1: Object.freeze({ domain: 'peerit.hiverelay.announcement.v1', field: 'signature' }),
  AuthorBindV1: Object.freeze({ domain: 'peerit.hiverelay.author-bind.v1', field: 'signature' }),
  RepairAddV1: Object.freeze({ domain: 'peerit.hiverelay.repair-add.v1', field: 'signature' }),
  MaintainerIngressBindingV1: Object.freeze({ domain: 'peerit.hiverelay.maintainer-ingress.v1', field: 'signature' }),
  MaintainerObservationV1: Object.freeze({ domain: 'peerit.hiverelay.maintainer-observation.v1', field: 'signature' }),
  MaintainerObservationReceiptV1: Object.freeze({ domain: 'peerit.hiverelay.maintainer-observation-receipt.v1', field: 'signature' }),
  MaintainerObservationHeadV1: Object.freeze({ domain: 'peerit.hiverelay.maintainer-observation-head.v1', field: 'signature' }),
  DiscoveryProposalV1: Object.freeze({ domain: 'peerit.hiverelay.discovery-proposal.v1', field: 'signature' }),
  LegacyCutoffV1: Object.freeze({ domain: 'peerit.hiverelay.legacy-cutoff.v1', field: 'signature' }),
  LegacyArchiveDistributionV1: Object.freeze({ domain: 'peerit.hiverelay.legacy-archive-distribution.v1', field: 'releaseSignature' }),
  LegacyRetirementEvidenceV1: Object.freeze({ domain: 'peerit.legacy-retirement-evidence.v1', field: 'signature' }),
  MigrationGenesisV1: Object.freeze({ domain: 'peerit.hiverelay.migration-genesis.v1', field: 'releaseSignature' }),
  DeviceChainStartV1: Object.freeze({ domain: 'peerit.hiverelay.device-chain-start.v1', field: 'signature' })
})

const LOW_ORDER_X25519_PUBLIC_KEYS = Object.freeze([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3fa1f6f7f3c0a37f7d5b4f47f170bcfdc728d63333f',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8b01f22f4f',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'
])

function failGraph (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details != null) error.details = details
  throw error
}

function safeInteger (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    failGraph('BAD_CONTEXTUAL_GRAPH_CONFIGURATION', `${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function snapshotBytes (value, field) {
  if (!(value instanceof Uint8Array) && !(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) {
    failGraph('BAD_FETCHED_EVIDENCE', `${field} must be bytes`)
  }
  return new Uint8Array(asBytes(value, field))
}

function strictObject (value, field) {
  if (value == null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    failGraph('BAD_CONTEXTUAL_GRAPH_CONFIGURATION', `${field} must be a plain object`)
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') failGraph('BAD_CONTEXTUAL_GRAPH_CONFIGURATION', `${field} contains a symbol key`)
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor == null || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      failGraph('BAD_CONTEXTUAL_GRAPH_CONFIGURATION', `${field}.${key} must be a data property`)
    }
  }
  return value
}

function checkedAdd (...values) {
  let output = 0n
  for (const value of values) {
    output += BigInt(value)
    if (output > MAX_U64) failGraph('CONTEXTUAL_GRAPH_INTEGER_OVERFLOW', 'contextual u64 arithmetic overflowed')
  }
  return output
}

function distinctByteValues (values, field) {
  const sorted = values.map(value => snapshotBytes(value, field)).sort(compareBytes)
  for (let index = 1; index < sorted.length; index++) {
    if (bytesEqual(sorted[index - 1], sorted[index])) failGraph('CONTEXTUAL_GRAPH_DUPLICATE', `${field} contains a duplicate`)
  }
}

function hashWithTag (domain, tag, bytes) {
  bytes = snapshotBytes(bytes, `${domain} bytes`)
  return blake2b256(concatBytes(asciiBytes(domain), u16Bytes(tag), u64Bytes(bytes.byteLength), bytes))
}

export function hashPeeritProfileRecordIdV1 (manifestTag, bytes) {
  return hashWithTag('peerit.hiverelay.manifest-record-id.v1', manifestTag, bytes)
}

export function hashPeeritProfilePinV1 (bytes) {
  return domainLengthHash('peerit.hiverelay.profile-pin-hash.v1', bytes)
}

export function hashPeeritPinHistoryCheckpointV1 (bytes) {
  return domainLengthHash('peerit.pin-history-checkpoint-hash.v1', bytes)
}

export function hashPeeritLegacyCutoffV1 (bytes) {
  return domainLengthHash('peerit.hiverelay.legacy-cutoff-hash.v1', bytes)
}

export function hashPeeritLegacyRetirementEvidenceV1 (bytes) {
  return domainLengthHash('peerit.legacy-retirement-evidence-hash.v1', bytes)
}

function prefixBytes (state, schemaName, value, field) {
  return encodePeeritProfileRecordPrefixFromIr(state.compiled, state.inventory, schemaName, value, field, {
    externalAuthorityByName: state.externalAuthorityByName,
    sortProjection: state.sortProjection
  })
}

function verifyDetached (signature, message, publicKey, code, field) {
  signature = snapshotBytes(signature, `${field} signature`)
  publicKey = snapshotBytes(publicKey, `${field} public key`)
  if (signature.byteLength !== 64 || publicKey.byteLength !== 32 || isAllZero(publicKey) ||
      !sodium.crypto_sign_verify_detached(signature, message, publicKey)) {
    failGraph(code, `${field} signature is invalid`)
  }
}

function verifySingleSignature (state, schemaName, value, publicKey, fieldOverride) {
  const rule = SINGLE_SIGNATURE[schemaName]
  if (rule == null) failGraph('CONTEXTUAL_SIGNATURE_RULE_MISSING', `${schemaName} has no contextual signature rule`)
  const field = fieldOverride || rule.field
  const prefix = prefixBytes(state, schemaName, value, field)
  verifyDetached(value[field], concatBytes(asciiBytes(rule.domain), prefix), publicKey, 'INVALID_CONTEXTUAL_SIGNATURE', schemaName)
}

function normalizeBudgets (input = {}) {
  strictObject(input, 'contextual graph budgets')
  return Object.freeze({
    maximumFetchedObjects: safeInteger(input.maximumFetchedObjects ?? DEFAULT_BUDGETS.maximumFetchedObjects, 1, 1048576, 'maximumFetchedObjects'),
    maximumFetchedBytes: safeInteger(input.maximumFetchedBytes ?? DEFAULT_BUDGETS.maximumFetchedBytes, 1, 1073741824, 'maximumFetchedBytes'),
    maximumGraphDepth: safeInteger(input.maximumGraphDepth ?? DEFAULT_BUDGETS.maximumGraphDepth, 1, 4096, 'maximumGraphDepth'),
    maximumEvidenceEntries: safeInteger(input.maximumEvidenceEntries ?? DEFAULT_BUDGETS.maximumEvidenceEntries, 1, 1048576, 'maximumEvidenceEntries')
  })
}

function createSession (state, context = {}) {
  strictObject(context, 'contextual graph context')
  return {
    state,
    context,
    fetchedObjects: 0,
    fetchedBytes: 0,
    visitedEntries: 0,
    cache: new Map(),
    active: new Set()
  }
}

function chargeEntries (session, count, field) {
  if (!Number.isSafeInteger(count) || count < 0) failGraph('BAD_FETCHED_EVIDENCE', `${field} count is invalid`)
  session.visitedEntries += count
  if (session.visitedEntries > session.state.budgets.maximumEvidenceEntries) {
    failGraph('CONTEXTUAL_GRAPH_BUDGET_EXCEEDED', `${field} exceeds the evidence-entry budget`)
  }
}

function fetchExact (session, expectedHash, descriptor, computeHash, maximumBytes = session.state.budgets.maximumFetchedBytes) {
  expectedHash = snapshotBytes(expectedHash, `${descriptor} expected hash`)
  if (expectedHash.byteLength !== 32 || isAllZero(expectedHash)) failGraph('BAD_FETCHED_EVIDENCE_REFERENCE', `${descriptor} hash must be nonzero 32 bytes`)
  const cacheKey = `${descriptor}:${bytesToHex(expectedHash)}`
  const cached = session.cache.get(cacheKey)
  if (cached != null) return new Uint8Array(cached)
  if (session.fetchedObjects >= session.state.budgets.maximumFetchedObjects) {
    failGraph('CONTEXTUAL_GRAPH_BUDGET_EXCEEDED', 'fetched-object budget exceeded')
  }
  const request = Object.freeze({ descriptor, expectedHash: new Uint8Array(expectedHash) })
  let returned
  try {
    returned = session.state.fetchByHash(request)
  } catch (error) {
    failGraph('FETCHED_EVIDENCE_UNAVAILABLE', `${descriptor} fetch failed`, { cause: String(error && error.message ? error.message : error) })
  }
  if (returned && typeof returned.then === 'function') {
    failGraph('ASYNC_FETCH_NOT_SNAPSHOTTED', `${descriptor} must be prefetched into the synchronous evidence snapshot`)
  }
  const bytes = snapshotBytes(returned, `${descriptor} fetched bytes`)
  if (bytes.byteLength > maximumBytes) failGraph('FETCHED_EVIDENCE_OVERSIZE', `${descriptor} exceeds its byte bound`)
  session.fetchedObjects++
  session.fetchedBytes += bytes.byteLength
  if (session.fetchedBytes > session.state.budgets.maximumFetchedBytes) {
    failGraph('CONTEXTUAL_GRAPH_BUDGET_EXCEEDED', 'fetched-byte budget exceeded')
  }
  const actualHash = computeHash(bytes)
  if (!bytesEqual(actualHash, expectedHash)) {
    failGraph('FETCHED_EVIDENCE_HASH_MISMATCH', `${descriptor} bytes do not reproduce the requested hash`)
  }
  session.cache.set(cacheKey, new Uint8Array(bytes))
  return bytes
}

function readU32LE (bytes, offset) {
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0
}

function writeU32LE (bytes, offset, value) {
  bytes[offset] = value & 0xff
  bytes[offset + 1] = (value >>> 8) & 0xff
  bytes[offset + 2] = (value >>> 16) & 0xff
  bytes[offset + 3] = (value >>> 24) & 0xff
}

function rotateLeft (value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0
}

function quarterRound (state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0
  state[d] = rotateLeft(state[d] ^ state[a], 16)
  state[c] = (state[c] + state[d]) >>> 0
  state[b] = rotateLeft(state[b] ^ state[c], 12)
  state[a] = (state[a] + state[b]) >>> 0
  state[d] = rotateLeft(state[d] ^ state[a], 8)
  state[c] = (state[c] + state[d]) >>> 0
  state[b] = rotateLeft(state[b] ^ state[c], 7)
}

function hchacha20 (key, noncePrefix) {
  key = snapshotBytes(key, 'XChaCha key')
  noncePrefix = snapshotBytes(noncePrefix, 'XChaCha nonce prefix')
  if (key.byteLength !== 32 || noncePrefix.byteLength !== 16) failGraph('BAD_CUSTODY_CRYPTO_INPUT', 'HChaCha20 requires a 32-byte key and 16-byte nonce')
  const constants = asciiBytes('expand 32-byte k')
  const words = new Uint32Array(16)
  for (let index = 0; index < 4; index++) words[index] = readU32LE(constants, index * 4)
  for (let index = 0; index < 8; index++) words[4 + index] = readU32LE(key, index * 4)
  for (let index = 0; index < 4; index++) words[12 + index] = readU32LE(noncePrefix, index * 4)
  for (let round = 0; round < 10; round++) {
    quarterRound(words, 0, 4, 8, 12)
    quarterRound(words, 1, 5, 9, 13)
    quarterRound(words, 2, 6, 10, 14)
    quarterRound(words, 3, 7, 11, 15)
    quarterRound(words, 0, 5, 10, 15)
    quarterRound(words, 1, 6, 11, 12)
    quarterRound(words, 2, 7, 8, 13)
    quarterRound(words, 3, 4, 9, 14)
  }
  const output = new Uint8Array(32)
  for (const [outputIndex, wordIndex] of [0, 1, 2, 3, 12, 13, 14, 15].entries()) {
    writeU32LE(output, outputIndex * 4, words[wordIndex])
  }
  words.fill(0)
  return output
}

function xchachaNonce (nonce) {
  nonce = snapshotBytes(nonce, 'XChaCha nonce')
  if (nonce.byteLength !== 24) failGraph('BAD_CUSTODY_CRYPTO_INPUT', 'XChaCha nonce must be 24 bytes')
  const output = new Uint8Array(12)
  output.set(nonce.slice(16), 4)
  return output
}

function xchachaEncrypt (plaintext, aad, nonce, key) {
  plaintext = snapshotBytes(plaintext, 'XChaCha plaintext')
  aad = snapshotBytes(aad, 'XChaCha AAD')
  nonce = snapshotBytes(nonce, 'XChaCha nonce')
  key = snapshotBytes(key, 'XChaCha key')
  const subkey = hchacha20(key, nonce.slice(0, 16))
  const output = new Uint8Array(plaintext.byteLength + 16)
  try {
    sodium.crypto_aead_chacha20poly1305_ietf_encrypt(output, plaintext, aad, null, xchachaNonce(nonce), subkey)
    return output
  } finally {
    subkey.fill(0)
  }
}

function xchachaDecrypt (ciphertext, aad, nonce, key) {
  ciphertext = snapshotBytes(ciphertext, 'XChaCha ciphertext')
  aad = snapshotBytes(aad, 'XChaCha AAD')
  nonce = snapshotBytes(nonce, 'XChaCha nonce')
  key = snapshotBytes(key, 'XChaCha key')
  if (ciphertext.byteLength < 16) failGraph('CUSTODY_AEAD_FAILED', 'XChaCha ciphertext is truncated')
  const subkey = hchacha20(key, nonce.slice(0, 16))
  const output = new Uint8Array(ciphertext.byteLength - 16)
  try {
    sodium.crypto_aead_chacha20poly1305_ietf_decrypt(output, null, ciphertext, aad, xchachaNonce(nonce), subkey)
    return output
  } catch {
    output.fill(0)
    failGraph('CUSTODY_AEAD_FAILED', 'XChaCha20-Poly1305 authentication failed')
  } finally {
    subkey.fill(0)
  }
}

function gfMultiply (left, right) {
  let a = left
  let b = right
  let output = 0
  for (let bit = 0; bit < 8; bit++) {
    if ((b & 1) !== 0) output ^= a
    const high = a & 0x80
    a = (a << 1) & 0xff
    if (high !== 0) a ^= 0x1b
    b >>>= 1
  }
  return output
}

function gfPower (value, exponent) {
  let output = 1
  let base = value
  while (exponent > 0) {
    if ((exponent & 1) !== 0) output = gfMultiply(output, base)
    base = gfMultiply(base, base)
    exponent >>>= 1
  }
  return output
}

function gfDivide (left, right) {
  if (right === 0) failGraph('BAD_CUSTODY_SHARE', 'GF(2^8) division by zero')
  return gfMultiply(left, gfPower(right, 254))
}

function interpolatePair (leftIndex, left, rightIndex, right) {
  if (leftIndex === rightIndex) failGraph('BAD_CUSTODY_SHARE', 'duplicate Shamir coordinates')
  const denominator = leftIndex ^ rightIndex
  const leftWeight = gfDivide(rightIndex, denominator)
  const rightWeight = gfDivide(leftIndex, denominator)
  const output = new Uint8Array(32)
  for (let index = 0; index < output.byteLength; index++) {
    output[index] = gfMultiply(left[index], leftWeight) ^ gfMultiply(right[index], rightWeight)
  }
  return output
}

function deriveEd25519PublicKey (seed) {
  seed = snapshotBytes(seed, 'Ed25519 seed')
  if (seed.byteLength !== 32) failGraph('BAD_CUSTODY_PLAINTEXT', 'Ed25519 seed must be 32 bytes')
  const publicKey = new Uint8Array(32)
  const secretKey = new Uint8Array(64)
  try {
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
    return publicKey
  } finally {
    secretKey.fill(0)
  }
}

function assertX25519PublicKey (publicKey, field) {
  publicKey = snapshotBytes(publicKey, field)
  if (publicKey.byteLength !== 32 || LOW_ORDER_X25519_PUBLIC_KEYS.includes(bytesToHex(publicKey))) {
    failGraph('CUSTODY_LOW_ORDER_PUBLIC_KEY', `${field} is a known low-order X25519 point`)
  }
  return publicKey
}

function shareKey (share, privateKey) {
  privateKey = snapshotBytes(privateKey, 'custodian private key')
  if (privateKey.byteLength !== 32 || isAllZero(privateKey)) failGraph('BAD_CUSTODY_PRIVATE_KEY', 'custodian private key must be nonzero 32 bytes')
  const expectedPublicKey = new Uint8Array(32)
  sodium.crypto_scalarmult_base(expectedPublicKey, privateKey)
  if (!bytesEqual(expectedPublicKey, share.custodianPublicKey)) failGraph('CUSTODY_WRONG_RECIPIENT', 'custodian private key does not match the pinned public key')
  const shared = new Uint8Array(32)
  try {
    sodium.crypto_scalarmult(shared, privateKey, assertX25519PublicKey(share.ephemeralPublicKey, 'ephemeralPublicKey'))
    if (isAllZero(shared)) failGraph('CUSTODY_LOW_ORDER_PUBLIC_KEY', 'X25519 produced an all-zero shared secret')
    return hkdf(sha256, shared, share.custodySetId, concatBytes(
      asciiBytes('peerit.hiverelay.custody-share-key.v1'),
      Uint8Array.of(share.bundleKind),
      Uint8Array.of(share.shareIndex),
      share.custodianPublicKey,
      share.ephemeralPublicKey
    ), 32)
  } finally {
    shared.fill(0)
    expectedPublicKey.fill(0)
    privateKey.fill(0)
  }
}

function custodyEnvelopeAad (state, envelope) {
  return concatBytes(prefixBytes(state, 'PeeritCustodyEnvelopeV1', envelope, 'payloadNonce').slice(2), u32Bytes(envelope.sealedPayload.byteLength))
}

function custodyShareAad (state, share) {
  return prefixBytes(state, 'PeeritCustodyEncryptedShareV1', share, 'sealedShare').slice(2)
}

function validateCustodyPlaintext (state, envelope, plaintext, context) {
  const expectedHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-plaintext.v1'),
    Uint8Array.of(envelope.bundleKind),
    u16Bytes(envelope.plaintextCodec),
    u64Bytes(plaintext.byteLength),
    plaintext
  ))
  if (!bytesEqual(expectedHash, envelope.plaintextHash) || BigInt(plaintext.byteLength) !== envelope.plaintextLength) {
    failGraph('CUSTODY_PLAINTEXT_MISMATCH', 'custody plaintext length or hash is invalid')
  }
  let value
  if (envelope.bundleKind === 1 && envelope.plaintextCodec === 1) {
    value = state.catalog.PeeritCustodySeedPayloadV1.decode(plaintext)
    if (value.secretKind < 1 || value.secretKind > 3 || !bytesEqual(deriveEd25519PublicKey(value.secretSeed), value.derivedPublicKey)) {
      failGraph('BAD_CUSTODY_SEED_PAYLOAD', 'custody seed kind or derived public key is invalid')
    }
    if (context.expectedProfilePinHash != null && !bytesEqual(value.profilePinHash, context.expectedProfilePinHash)) {
      failGraph('BAD_CUSTODY_SEED_PAYLOAD', 'custody seed payload names the wrong profile pin')
    }
  } else if (envelope.bundleKind === 2 && envelope.plaintextCodec === 2) {
    value = state.catalog.PeeritInboxManagementBundleV1.decode(plaintext)
    validateInboxManagementBundle(state, value, context)
  } else {
    failGraph('BAD_CUSTODY_CODEC_RELATION', 'custody bundle kind and plaintext codec do not match')
  }
  return value
}

function validateInboxManagementBundle (state, bundle, context) {
  const prefix = prefixBytes(state, 'PeeritInboxManagementBundleV1', bundle, 'bundleCommitment').slice(2)
  if (!bytesEqual(bundle.bundleCommitment, blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.inbox-management-bundle.v1'),
    u64Bytes(prefix.byteLength),
    prefix
  )))) failGraph('BAD_INBOX_MANAGEMENT_COMMITMENT', 'Inbox management bundle commitment is invalid')
  const expectedCount = bundle.entries.length === 24 ? 24 : 48
  if (bundle.entries.length !== expectedCount) failGraph('BAD_INBOX_MANAGEMENT_SHAPE', 'Inbox management bundle must contain 24 or 48 entries')
  const seenTopics = []
  const seenAuthorities = []
  const epochCounts = new Map()
  for (const entry of bundle.entries) {
    const binding = state.catalog.InboxStripeBindingV1.decode(entry.bindingBytes)
    const bindingHash = domainLengthHash('peerit.hiverelay.inbox-management-binding.v1', entry.bindingBytes)
    if (!bytesEqual(bindingHash, entry.bindingHash) || binding.inboxEpoch !== entry.inboxEpoch || binding.stripeIndex !== entry.stripeIndex ||
        !bytesEqual(binding.relayPublicKey, entry.relayPublicKey) || !bytesEqual(binding.createPublicKey, deriveEd25519PublicKey(entry.createPrivateSeed)) ||
        !bytesEqual(entry.renewPublicKey, deriveEd25519PublicKey(entry.renewPrivateSeed)) ||
        !bytesEqual(entry.closePublicKey, deriveEd25519PublicKey(entry.closePrivateSeed))) {
      failGraph('BAD_INBOX_MANAGEMENT_BINDING', 'Inbox management entry does not reproduce its binding or management keys')
    }
    distinctByteValues([entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed], 'Inbox management private seeds')
    seenTopics.push(binding.physicalTopic)
    seenAuthorities.push(binding.createPublicKey, entry.renewPublicKey, entry.closePublicKey)
    epochCounts.set(entry.inboxEpoch, (epochCounts.get(entry.inboxEpoch) || 0) + 1)
  }
  distinctByteValues(seenTopics, 'Inbox management topics')
  distinctByteValues(seenAuthorities, 'Inbox management authorities')
  if (epochCounts.get(bundle.currentInboxEpoch) !== 24 || epochCounts.size > 2 ||
      (epochCounts.size === 2 && epochCounts.get(bundle.currentInboxEpoch - 1) !== 24)) {
    failGraph('BAD_INBOX_MANAGEMENT_EPOCHS', 'Inbox management entries do not contain the current and optional immediately previous epoch')
  }
  if (context.expectedProfilePinHash != null && !bytesEqual(bundle.profilePinHash, context.expectedProfilePinHash)) {
    failGraph('BAD_INBOX_MANAGEMENT_CONTEXT', 'Inbox management bundle names the wrong profile pin')
  }
}

function recoverCustodyEnvelope (state, envelopeBytes, custodianPrivateKeys, context = {}) {
  const envelope = state.catalog.PeeritCustodyEnvelopeV1.decode(snapshotBytes(envelopeBytes, 'custody envelope'))
  if (!Array.isArray(custodianPrivateKeys) || custodianPrivateKeys.length < 2 || custodianPrivateKeys.length > 3) {
    failGraph('CUSTODY_THRESHOLD_NOT_MET', 'custody recovery requires two or three private keys')
  }
  if (envelope.plaintextLength < 1n || envelope.plaintextLength > 16777216n ||
      BigInt(envelope.sealedPayload.byteLength) !== envelope.plaintextLength + 16n) {
    failGraph('BAD_CUSTODY_ENVELOPE', 'custody envelope payload length is invalid')
  }
  const payloadHash = domainLengthHash('peerit.hiverelay.custody-sealed-payload.v1', envelope.sealedPayload)
  const decryptedShares = []
  const rejectedShares = []
  for (let index = 0; index < envelope.encryptedShares.length; index++) {
    const share = envelope.encryptedShares[index]
    if (share.shareIndex !== index + 1 || share.threshold !== 2 || share.totalShares !== 3 ||
        !bytesEqual(share.custodySetId, envelope.custodySetId) || share.bundleKind !== envelope.bundleKind ||
        !bytesEqual(share.keyCommitment, envelope.keyCommitment) || !bytesEqual(share.sealedPayloadHash, payloadHash)) {
      failGraph('BAD_CUSTODY_ENVELOPE', 'encrypted share does not bind its envelope')
    }
  }
  distinctByteValues(envelope.encryptedShares.map(share => share.custodianPublicKey), 'custodian public keys')
  distinctByteValues(envelope.encryptedShares.map(share => share.ephemeralPublicKey), 'ephemeral public keys')
  distinctByteValues(envelope.encryptedShares.map(share => share.nonce), 'share nonces')
  distinctByteValues(envelope.encryptedShares.map(share => share.sealedShare), 'sealed shares')
  try {
    for (const suppliedPrivateKey of custodianPrivateKeys) {
      const privateKey = snapshotBytes(suppliedPrivateKey, 'custodian private key')
      const publicKey = new Uint8Array(32)
      sodium.crypto_scalarmult_base(publicKey, privateKey)
      const share = envelope.encryptedShares.find(candidate => bytesEqual(candidate.custodianPublicKey, publicKey))
      if (share == null) failGraph('CUSTODY_WRONG_RECIPIENT', 'custodian key is not present in the envelope')
      if (decryptedShares.some(candidate => candidate.index === share.shareIndex)) failGraph('CONTEXTUAL_GRAPH_DUPLICATE', 'duplicate custodian private key')
      const key = shareKey(share, privateKey)
      try {
        try {
          decryptedShares.push(Object.freeze({
            index: share.shareIndex,
            bytes: xchachaDecrypt(share.sealedShare, custodyShareAad(state, share), share.nonce, key)
          }))
        } catch (error) {
          if (error && error.code === 'CUSTODY_AEAD_FAILED') rejectedShares.push(error)
          else throw error
        }
      } finally {
        key.fill(0)
        privateKey.fill(0)
        publicKey.fill(0)
      }
    }
    if (decryptedShares.length < 2) {
      if (rejectedShares.length > 0) throw rejectedShares[0]
      failGraph('CUSTODY_THRESHOLD_NOT_MET', 'fewer than two authenticated custody shares remain')
    }
    const accepted = []
    for (let left = 0; left < decryptedShares.length; left++) {
      for (let right = left + 1; right < decryptedShares.length; right++) {
        const dataKey = interpolatePair(decryptedShares[left].index, decryptedShares[left].bytes, decryptedShares[right].index, decryptedShares[right].bytes)
        let plaintext
        try {
          const commitment = blake2b256(concatBytes(asciiBytes('peerit.hiverelay.custody-key.v1'), envelope.custodySetId, dataKey))
          if (!bytesEqual(commitment, envelope.keyCommitment)) continue
          plaintext = xchachaDecrypt(envelope.sealedPayload, custodyEnvelopeAad(state, envelope), envelope.payloadNonce, dataKey)
          validateCustodyPlaintext(state, envelope, plaintext, context)
          accepted.push(new Uint8Array(plaintext))
        } catch (error) {
          if (error && ['BAD_CUSTODY_SEED_PAYLOAD', 'BAD_CUSTODY_CODEC_RELATION', 'BAD_INBOX_MANAGEMENT_COMMITMENT', 'BAD_INBOX_MANAGEMENT_BINDING', 'BAD_INBOX_MANAGEMENT_EPOCHS', 'BAD_INBOX_MANAGEMENT_CONTEXT'].includes(error.code)) throw error
        } finally {
          dataKey.fill(0)
          if (plaintext != null) plaintext.fill(0)
        }
      }
    }
    if (accepted.length === 0) failGraph('CUSTODY_RECONSTRUCTION_FAILED', 'no authenticated two-share reconstruction passed')
    for (let index = 1; index < accepted.length; index++) {
      if (!bytesEqual(accepted[0], accepted[index])) failGraph('CUSTODY_RECONSTRUCTION_AMBIGUOUS', 'passing custody reconstructions disagree')
    }
    const plaintext = new Uint8Array(accepted[0])
    const value = validateCustodyPlaintext(state, envelope, plaintext, context)
    for (const candidate of accepted) candidate.fill(0)
    return Object.freeze({ envelope, plaintext, value })
  } finally {
    for (const share of decryptedShares) share.bytes.fill(0)
  }
}

export const PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1 = Object.freeze({
  xchacha20poly1305Encrypt: xchachaEncrypt,
  xchacha20poly1305Decrypt: xchachaDecrypt,
  gfMultiply,
  interpolatePair
})

export function createPeeritSupportingEvidenceAuditAuthorityV1 (verifiers) {
  strictObject(verifiers, 'supporting-evidence verifiers')
  const rows = new Map()
  for (let kind = 1; kind <= 6; kind++) {
    const verifier = verifiers[kind]
    if (typeof verifier !== 'function') {
      failGraph('SUPPORTING_EVIDENCE_AUTHORITY_INCOMPLETE', `supporting-evidence kind ${kind} has no verifier`)
    }
    rows.set(kind, verifier)
  }
  for (const key of Object.keys(verifiers)) {
    if (!/^[1-6]$/.test(key)) failGraph('SUPPORTING_EVIDENCE_AUTHORITY_INCOMPLETE', `unknown supporting-evidence verifier ${key}`)
  }
  const authority = Object.freeze({
    authorityId: '@peerit/supporting-evidence-audit-authority-v1',
    auditOnly: true,
    evidenceKinds: Object.freeze([1, 2, 3, 4, 5, 6])
  })
  SUPPORTING_EVIDENCE_STATE.set(authority, rows)
  return authority
}

function supportingEvidenceState (authority) {
  const state = SUPPORTING_EVIDENCE_STATE.get(authority)
  if (state == null) failGraph('SUPPORTING_EVIDENCE_AUTHORITY_REQUIRED', 'a branded six-kind supporting-evidence authority is required')
  return state
}

function verifySupportingArtifact (authority, row, bytes) {
  const verifier = supportingEvidenceState(authority).get(row.evidenceKind)
  let output
  try {
    output = verifier(Object.freeze({
      evidenceKind: row.evidenceKind,
      supportingEvidenceHash: new Uint8Array(row.supportingEvidenceHash),
      bytes: new Uint8Array(bytes)
    }))
  } catch (error) {
    failGraph('SUPPORTING_EVIDENCE_INVALID', `supporting-evidence kind ${row.evidenceKind} verifier rejected the artifact`, {
      cause: String(error && error.message ? error.message : error)
    })
  }
  if (output && typeof output.then === 'function') failGraph('ASYNC_FETCH_NOT_SNAPSHOTTED', 'supporting evidence must be verified in the synchronous snapshot')
  strictObject(output, 'supporting-evidence facts')
  if (output.valid !== true) failGraph('SUPPORTING_EVIDENCE_INVALID', 'supporting-evidence verifier did not return valid=true')
  const facts = { valid: true }
  for (const field of ['logicalIntentEvidenceId', 'runtimeEvidenceKeyHash']) {
    if (output[field] != null) {
      const value = snapshotBytes(output[field], `supporting-evidence ${field}`)
      if (value.byteLength !== 32) failGraph('SUPPORTING_EVIDENCE_INVALID', `${field} must be 32 bytes`)
      facts[field] = value
    }
  }
  for (const field of ['terminalClass', 'failureBits', 'runtimeClass']) {
    if (output[field] != null) facts[field] = safeInteger(output[field], 0, 255, `supporting-evidence ${field}`)
  }
  return Object.freeze(facts)
}

function evidenceLeafHash (catalog, entry) {
  const bytes = catalog.PeeritWriteOperationEvidenceV1.encode(entry)
  return domainLengthHash('peerit.write-operation-evidence-leaf.v1', bytes)
}

function merkleRoot (leaves, nodeDomain, emptyDomain, levelIncluded) {
  if (leaves.length === 0) return blake2b256(asciiBytes(emptyDomain))
  let level = leaves.map((leaf, index) => {
    const bytes = snapshotBytes(leaf, `Merkle leaf ${index}`)
    if (bytes.byteLength !== 32) failGraph('BAD_CONTEXTUAL_MERKLE_TREE', 'Merkle leaves must be 32 bytes')
    return bytes
  })
  let treeLevel = 1
  while (level.length > 1) {
    const next = []
    for (let index = 0; index < level.length; index += 2) {
      if (index + 1 === level.length) {
        next.push(level[index])
      } else {
        next.push(blake2b256(concatBytes(
          asciiBytes(nodeDomain),
          levelIncluded ? u32Bytes(treeLevel) : [],
          level[index],
          level[index + 1]
        )))
      }
    }
    level = next
    treeLevel++
  }
  return level[0]
}

function operationEvidenceRoot (catalog, entries) {
  return merkleRoot(
    entries.map(entry => evidenceLeafHash(catalog, entry)),
    'peerit.write-operation-evidence-node.v1',
    'peerit.write-operation-evidence-empty.v1',
    true
  )
}

function qualificationSubjectHash (state, bundle) {
  const substrate = state.catalog.SubstrateTupleV1.encode(bundle.substrate)
  return blake2b256(concatBytes(
    asciiBytes('peerit.release-qualification-subject.v1'),
    bundle.appArtifactHash,
    bundle.validatorArtifactHash,
    bundle.profileSpecHash,
    bundle.profileAbiHash,
    bundle.profileVectorSetHash,
    bundle.availabilityPolicyHash,
    bundle.recommendedBootstrapSetHash,
    bundle.webAssetManifestHash,
    u64Bytes(substrate.byteLength),
    substrate,
    Uint8Array.of(bundle.measuredMigrationStage)
  ))
}

function countFailureBits (entries) {
  const output = new Array(6).fill(0n)
  for (const entry of entries) {
    for (let bit = 0; bit < output.length; bit++) if ((entry.failureBits & (1 << bit)) !== 0) output[bit]++
  }
  return output
}

function countTerminalClasses (entries) {
  const output = [0n, 0n, 0n]
  for (const entry of entries) {
    if (entry.terminalClass < 0 || entry.terminalClass > 2) failGraph('BAD_OPERATION_EVIDENCE_TERMINAL_CLASS', 'operation terminal class is not closed')
    output[entry.terminalClass]++
  }
  return output
}

function artifactMapKey (hash) {
  return bytesToHex(hash)
}

function validateOperationSupportingFacts (entry, artifactsByHash) {
  const rows = entry.supportingEvidenceHashes.map(hash => artifactsByHash.get(artifactMapKey(hash)))
  if (rows.some(row => row == null)) failGraph('SUPPORTING_EVIDENCE_REFERENCE_MISSING', 'operation references evidence absent from the supporting manifest')
  const ledgers = rows.filter(row => row.row.evidenceKind === 4)
  if (ledgers.length !== 1 || ledgers[0].facts.logicalIntentEvidenceId == null ||
      !bytesEqual(ledgers[0].facts.logicalIntentEvidenceId, entry.logicalIntentEvidenceId)) {
    failGraph('SUPPORTING_EVIDENCE_ATTEMPT_LEDGER_INVALID', 'operation must reference exactly one matching durable attempt-ledger proof')
  }
  if (entry.terminalClass === 1 && rows.every(row => row.row.evidenceKind !== 1)) {
    failGraph('SUPPORTING_EVIDENCE_RESULT_REQUIRED', 'successful operation has no result/receipt evidence')
  }
  if (entry.terminalClass !== 1 && rows.every(row => ![2, 3, 6].includes(row.row.evidenceKind))) {
    failGraph('SUPPORTING_EVIDENCE_TERMINAL_REQUIRED', 'failed or pending operation has no terminal/reconciliation evidence')
  }
  const terminalFacts = rows.filter(row => row.facts.logicalIntentEvidenceId != null &&
    bytesEqual(row.facts.logicalIntentEvidenceId, entry.logicalIntentEvidenceId) &&
    row.facts.terminalClass != null && row.facts.failureBits != null)
  if (terminalFacts.length === 0 || terminalFacts.some(row => row.facts.terminalClass !== entry.terminalClass || row.facts.failureBits !== entry.failureBits)) {
    failGraph('SUPPORTING_EVIDENCE_SUMMARY_MISMATCH', 'typed supporting evidence does not derive the operation terminal class and failure bits')
  }
}

function validateQualificationEvidenceBundle (state, session, bundle, bundleBytes) {
  if (!bytesEqual(bundle.qualificationSubjectHash, qualificationSubjectHash(state, bundle))) {
    failGraph('BAD_QUALIFICATION_SUBJECT_HASH', 'qualification subject hash does not reproduce the immutable release subject')
  }
  if (bundle.windowStartedUnixMillis >= bundle.windowEndedUnixMillis) failGraph('BAD_EVIDENCE_WINDOW', 'qualification evidence window is empty or inverted')
  const manifestBytes = fetchExact(
    session,
    bundle.operationEvidenceManifestHash,
    'operation evidence manifest',
    bytes => domainLengthHash('peerit.write-operation-evidence-manifest.v1', bytes),
    1048576
  )
  const manifest = state.catalog.PeeritWriteOperationEvidenceManifestV1.decode(manifestBytes)
  if (!bytesEqual(manifest.qualificationSubjectHash, bundle.qualificationSubjectHash) ||
      manifest.windowStartedUnixMillis !== bundle.windowStartedUnixMillis || manifest.windowEndedUnixMillis !== bundle.windowEndedUnixMillis ||
      manifest.totalEntryCount !== bundle.operationEvidenceCount || !bytesEqual(manifest.operationEvidenceRoot, bundle.operationEvidenceRoot)) {
    failGraph('BAD_OPERATION_EVIDENCE_MANIFEST_BINDING', 'operation manifest does not equal the qualification bundle')
  }
  chargeEntries(session, manifest.shards.length, 'operation shard references')
  const entries = []
  for (const reference of manifest.shards) {
    const shardBytes = fetchExact(
      session,
      reference.shardArtifactHash,
      'operation evidence shard',
      bytes => domainLengthHash('peerit.write-operation-evidence-shard.v1', bytes),
      16777216
    )
    const shard = state.catalog.PeeritWriteOperationEvidenceShardV1.decode(shardBytes)
    chargeEntries(session, shard.entries.length, 'operation evidence entries')
    if (!bytesEqual(shard.qualificationSubjectHash, manifest.qualificationSubjectHash) ||
        shard.windowStartedUnixMillis !== manifest.windowStartedUnixMillis || shard.windowEndedUnixMillis !== manifest.windowEndedUnixMillis ||
        BigInt(shard.entries.length) !== reference.entryCount || shard.entries.length === 0 ||
        !bytesEqual(shard.entries[0].logicalIntentEvidenceId, reference.firstLogicalIntentEvidenceId) ||
        !bytesEqual(shard.entries[shard.entries.length - 1].logicalIntentEvidenceId, reference.lastLogicalIntentEvidenceId) ||
        !bytesEqual(operationEvidenceRoot(state.catalog, shard.entries), reference.entryMerkleRoot)) {
      failGraph('BAD_OPERATION_EVIDENCE_SHARD_BINDING', 'operation shard does not reproduce its manifest reference')
    }
    for (const entry of shard.entries) {
      if (entry.attemptedUnixMillis < manifest.windowStartedUnixMillis || entry.attemptedUnixMillis >= manifest.windowEndedUnixMillis ||
          (entry.terminalClass === 0) !== (entry.terminalUnixMillis == null) ||
          (entry.terminalUnixMillis != null && (entry.terminalUnixMillis < entry.attemptedUnixMillis || entry.terminalUnixMillis > manifest.windowEndedUnixMillis)) ||
          entry.failureBits > 0x3f) {
        failGraph('BAD_OPERATION_EVIDENCE_ENTRY', 'operation entry is outside its window or has an invalid terminal summary')
      }
      const previous = entries[entries.length - 1]
      if (previous != null && compareBytes(previous.logicalIntentEvidenceId, entry.logicalIntentEvidenceId) >= 0) {
        failGraph('OPERATION_EVIDENCE_FORK_OR_DUPLICATE', 'global operation entry stream is not strictly increasing')
      }
      entries.push(entry)
    }
  }
  if (BigInt(entries.length) !== manifest.totalEntryCount || !bytesEqual(operationEvidenceRoot(state.catalog, entries), manifest.operationEvidenceRoot)) {
    failGraph('BAD_OPERATION_EVIDENCE_GLOBAL_ROOT', 'reconstructed operation stream does not reproduce manifest count/root')
  }
  if (entries.length === 0 && manifest.shards.length !== 0) failGraph('BAD_OPERATION_EVIDENCE_EMPTY_SHAPE', 'empty operation stream must have no shards')

  const supportingManifestBytes = fetchExact(
    session,
    bundle.supportingEvidenceManifestHash,
    'supporting evidence manifest',
    bytes => domainLengthHash('peerit.write-supporting-evidence-manifest.v1', bytes),
    67108864
  )
  const supportingManifest = state.catalog.PeeritWriteSupportingEvidenceManifestV1.decode(supportingManifestBytes)
  if (!bytesEqual(supportingManifest.qualificationSubjectHash, bundle.qualificationSubjectHash) ||
      supportingManifest.windowStartedUnixMillis !== bundle.windowStartedUnixMillis ||
      supportingManifest.windowEndedUnixMillis !== bundle.windowEndedUnixMillis) {
    failGraph('BAD_SUPPORTING_EVIDENCE_MANIFEST_BINDING', 'supporting manifest does not equal the qualification subject/window')
  }
  chargeEntries(session, supportingManifest.artifacts.length, 'supporting evidence artifacts')
  const artifactsByHash = new Map()
  for (const row of supportingManifest.artifacts) {
    const key = artifactMapKey(row.supportingEvidenceHash)
    if (artifactsByHash.has(key)) failGraph('CONTEXTUAL_GRAPH_DUPLICATE', 'supporting manifest repeats a hash')
    const bytes = fetchExact(
      session,
      row.supportingEvidenceHash,
      `supporting evidence artifact kind ${row.evidenceKind}`,
      artifactBytes => blake2b256(concatBytes(
        asciiBytes('peerit.write-supporting-evidence.v1'),
        Uint8Array.of(row.evidenceKind),
        u64Bytes(artifactBytes.byteLength),
        artifactBytes
      )),
      state.budgets.maximumFetchedBytes
    )
    if (BigInt(bytes.byteLength) !== row.byteLength) failGraph('SUPPORTING_EVIDENCE_LENGTH_MISMATCH', 'supporting artifact length does not match its manifest row')
    artifactsByHash.set(key, { row, bytes, facts: verifySupportingArtifact(state.supportingEvidenceAuthority, row, bytes), references: 0 })
  }
  const reference = hash => {
    const artifact = artifactsByHash.get(artifactMapKey(hash))
    if (artifact == null) failGraph('SUPPORTING_EVIDENCE_REFERENCE_MISSING', 'referenced supporting artifact is absent')
    artifact.references++
    return artifact
  }
  for (const entry of entries) {
    for (const hash of entry.supportingEvidenceHashes) reference(hash)
    validateOperationSupportingFacts(entry, artifactsByHash)
  }
  for (const row of bundle.runtimeEvidence) {
    const version = reference(row.runtimeVersionHash)
    const platform = reference(row.platformConfigurationHash)
    const capture = reference(row.captureEvidenceHash)
    const expectedRuntimeKey = blake2b256(concatBytes(
      asciiBytes('peerit.write-runtime-evidence-key.v1'),
      Uint8Array.of(row.runtimeClass),
      row.runtimeVersionHash,
      row.platformConfigurationHash,
      row.captureEvidenceHash
    ))
    if (row.runtimeClass < 1 || row.runtimeClass > 6 || !bytesEqual(expectedRuntimeKey, row.runtimeEvidenceKeyHash) ||
        version.row.evidenceKind !== 5 || platform.row.evidenceKind !== 5 ||
        ![2, 6].includes(capture.row.evidenceKind) ||
        (capture.facts.runtimeClass != null && capture.facts.runtimeClass !== row.runtimeClass) ||
        (capture.facts.runtimeEvidenceKeyHash != null && !bytesEqual(capture.facts.runtimeEvidenceKeyHash, row.runtimeEvidenceKeyHash))) {
      failGraph('BAD_RUNTIME_CAPTURE_EVIDENCE', 'runtime capture does not prove its runtime class')
    }
  }
  for (const hash of bundle.reconstructionEvidenceHashes) {
    if (reference(hash).row.evidenceKind !== 3) failGraph('BAD_RECONSTRUCTION_EVIDENCE_KIND', 'reconstruction evidence must use supporting-evidence kind 3')
  }
  for (const artifact of artifactsByHash.values()) {
    if (artifact.references === 0) failGraph('UNREFERENCED_SUPPORTING_EVIDENCE', 'supporting manifest contains an unreferenced artifact')
  }

  const runtimeRows = new Map(bundle.runtimeEvidence.map(row => [artifactMapKey(row.runtimeEvidenceKeyHash), row]))
  if (runtimeRows.size !== bundle.runtimeEvidence.length) failGraph('CONTEXTUAL_GRAPH_DUPLICATE', 'runtime evidence keys are not unique')
  const observedRuntimeKeys = new Set()
  for (const entry of entries) {
    const key = artifactMapKey(entry.runtimeEvidenceKeyHash)
    if (!runtimeRows.has(key)) failGraph('RUNTIME_EVIDENCE_ROW_MISSING', 'operation entry has no runtime evidence row')
    observedRuntimeKeys.add(key)
  }
  if (observedRuntimeKeys.size !== runtimeRows.size) failGraph('UNREFERENCED_RUNTIME_EVIDENCE', 'runtime evidence contains an unreferenced row')
  for (const [key, row] of runtimeRows) {
    const selected = entries.filter(entry => artifactMapKey(entry.runtimeEvidenceKeyHash) === key)
    const terminal = countTerminalClasses(selected)
    if (row.operationEvidenceCount !== BigInt(selected.length) || row.attemptedLogicalWrites !== BigInt(selected.length) ||
        row.pendingOrUnknownWrites !== terminal[0] || row.terminalSuccessfulWrites !== terminal[1] || row.terminalFailedWrites !== terminal[2] ||
        !bytesEqual(row.operationEvidenceRoot, operationEvidenceRoot(state.catalog, selected))) {
      failGraph('BAD_RUNTIME_EVIDENCE_AGGREGATE', 'runtime evidence row does not reproduce its filtered operation stream')
    }
  }
  const terminal = countTerminalClasses(entries)
  const failure = countFailureBits(entries)
  if (bundle.attemptedLogicalWrites !== BigInt(entries.length) || bundle.operationEvidenceCount !== BigInt(entries.length) ||
      bundle.pendingOrUnknownWrites !== terminal[0] || bundle.terminalSuccessfulWrites !== terminal[1] || bundle.terminalFailedWrites !== terminal[2] ||
      bundle.acknowledgedWriteLosses !== failure[0] || bundle.unresolvedLegacyOnlyWrites !== failure[1] ||
      bundle.forbiddenLegacyWrites !== failure[2] || bundle.signatureOrCodecDisagreements !== failure[3] ||
      bundle.floorRollbacks !== failure[4] || bundle.hiddenPrivacyDowngrades !== failure[5] ||
      checkedAdd(bundle.pendingOrUnknownWrites, bundle.terminalSuccessfulWrites, bundle.terminalFailedWrites) !== bundle.attemptedLogicalWrites) {
    failGraph('BAD_QUALIFICATION_EVIDENCE_AGGREGATE', 'qualification counters do not reproduce the complete operation stream')
  }
  return Object.freeze({
    bundleBytes: new Uint8Array(bundleBytes),
    operationManifestBytes: manifestBytes,
    supportingManifestBytes,
    operationCount: entries.length,
    fetchedObjects: session.fetchedObjects,
    fetchedBytes: session.fetchedBytes
  })
}

function fetchRecord (session, schemaName, expectedHash, descriptor, computeHash, depth, maximumBytes) {
  if (depth > session.state.budgets.maximumGraphDepth) failGraph('CONTEXTUAL_GRAPH_BUDGET_EXCEEDED', 'graph depth budget exceeded')
  const bytes = fetchExact(session, expectedHash, descriptor, computeHash, maximumBytes)
  const codec = session.state.catalog[schemaName]
  if (codec == null) failGraph('CONTEXTUAL_SCHEMA_UNKNOWN', `contextual graph references unknown schema ${schemaName}`)
  return Object.freeze({ schemaName, bytes, value: codec.decode(bytes) })
}

function sameOptionalBytes (left, right) {
  if (left == null || right == null) return left == null && right == null
  return bytesEqual(left, right)
}

function migrationStateChanged (left, right) {
  if (left == null) return false
  return left.migrationStage !== right.migrationStage || left.legacyImportMode !== right.legacyImportMode ||
    left.legacyReadMode !== right.legacyReadMode || !sameOptionalBytes(left.legacyCutoffHash, right.legacyCutoffHash) ||
    !sameOptionalBytes(left.migrationGenesisRecordId, right.migrationGenesisRecordId) ||
    left.cutoffActivationReleaseSequence !== right.cutoffActivationReleaseSequence ||
    !sameOptionalBytes(left.legacyRetirementEvidenceHash, right.legacyRetirementEvidenceHash) ||
    left.legacyRetirementActivationReleaseSequence !== right.legacyRetirementActivationReleaseSequence
}

function verifyAuthorityTransition (state, session, previousPin, nextPin, depth) {
  if (nextPin.authorityTransitionHash == null) failGraph('RELEASE_AUTHORITY_TRANSITION_REQUIRED', 'first pin under a new release key has no authority transition')
  const fetched = fetchRecord(
    session,
    'PeeritReleaseAuthorityTransitionV1',
    nextPin.authorityTransitionHash,
    'release authority transition',
    bytes => domainLengthHash('peerit.release-authority-transition-hash.v1', bytes),
    depth,
    4096
  )
  const transition = fetched.value
  if (transition.previousSequence !== previousPin.releaseAuthoritySequence || transition.nextSequence !== nextPin.releaseAuthoritySequence ||
      transition.nextSequence !== transition.previousSequence + 1n || !bytesEqual(transition.previousPublicKey, previousPin.releaseAuthorityPublicKey) ||
      !bytesEqual(transition.nextPublicKey, nextPin.releaseAuthorityPublicKey) || transition.validFromRelease > nextPin.releaseSequence ||
      transition.validFromRelease <= previousPin.releaseSequence) {
    failGraph('BAD_RELEASE_AUTHORITY_TRANSITION', 'release authority transition does not bridge the adjacent pins')
  }
  const fields = prefixBytes(state, 'PeeritReleaseAuthorityTransitionV1', transition, 'previousKeySignature').slice(2)
  const commitment = blake2b256(concatBytes(asciiBytes('peerit.release-authority-transition.v1'), fields))
  verifyDetached(transition.previousKeySignature, commitment, transition.previousPublicKey, 'INVALID_RELEASE_AUTHORITY_TRANSITION_SIGNATURE', 'previous release key')
  verifyDetached(transition.nextKeySignature, commitment, transition.nextPublicKey, 'INVALID_RELEASE_AUTHORITY_TRANSITION_SIGNATURE', 'next release key')
  return fetched
}

function validatePinPair (state, session, previous, current, depth) {
  const previousHash = hashPeeritProfilePinV1(previous.bytes)
  if (current.value.releaseSequence !== previous.value.releaseSequence + 1n ||
      current.value.previousPinHash == null || !bytesEqual(current.value.previousPinHash, previousHash)) {
    failGraph('PROFILE_PIN_CHAIN_GAP_OR_FORK', 'profile pin is not the exact +1 successor of its fetched predecessor')
  }
  const sameAuthority = current.value.releaseAuthoritySequence === previous.value.releaseAuthoritySequence &&
    bytesEqual(current.value.releaseAuthorityPublicKey, previous.value.releaseAuthorityPublicKey)
  if (sameAuthority) {
    if (current.value.authorityTransitionHash != null) failGraph('UNEXPECTED_RELEASE_AUTHORITY_TRANSITION', 'unchanged release key has an authority transition')
  } else {
    verifyAuthorityTransition(state, session, previous.value, current.value, depth + 1)
  }
  if (current.value.migrationStage < previous.value.migrationStage || current.value.migrationStage > previous.value.migrationStage + 1 ||
      current.value.legacyImportMode < previous.value.legacyImportMode || current.value.legacyImportMode > previous.value.legacyImportMode + 1 ||
      current.value.legacyReadMode < previous.value.legacyReadMode || current.value.legacyReadMode > previous.value.legacyReadMode + 1) {
    failGraph('MIGRATION_STATE_ROLLBACK_OR_SKIP', 'migration state rolls back or skips a stage')
  }
  const changed = migrationStateChanged(previous.value, current.value)
  if (changed !== (current.value.migrationTransitionEvidenceHash != null)) {
    failGraph('MIGRATION_TRANSITION_EVIDENCE_SHAPE', 'migration transition evidence must be present exactly when migration state changes')
  }
  if (previous.value.legacyImportMode > 0 &&
      (!bytesEqual(previous.value.legacyCutoffHash, current.value.legacyCutoffHash) ||
       !bytesEqual(previous.value.migrationGenesisRecordId, current.value.migrationGenesisRecordId) ||
       previous.value.cutoffActivationReleaseSequence !== current.value.cutoffActivationReleaseSequence)) {
    failGraph('MIGRATION_FROZEN_STATE_MUTATED', 'frozen cutoff/genesis/activation state changed')
  }
  if (previous.value.legacyReadMode === 1 &&
      (!bytesEqual(previous.value.legacyRetirementEvidenceHash, current.value.legacyRetirementEvidenceHash) ||
       previous.value.legacyRetirementActivationReleaseSequence !== current.value.legacyRetirementActivationReleaseSequence)) {
    failGraph('MIGRATION_FROZEN_STATE_MUTATED', 'retirement evidence/activation state changed')
  }
  if (previous.value.legacyImportMode === 0 && current.value.legacyImportMode === 1 &&
      current.value.cutoffActivationReleaseSequence !== current.value.releaseSequence) {
    failGraph('BAD_CUTOFF_ACTIVATION_SEQUENCE', 'first frozen-cutoff pin must activate at its own release sequence')
  }
  if (previous.value.legacyReadMode === 0 && current.value.legacyReadMode === 1 &&
      current.value.legacyRetirementActivationReleaseSequence !== current.value.releaseSequence) {
    failGraph('BAD_RETIREMENT_ACTIVATION_SEQUENCE', 'first archive-only pin must activate at its own release sequence')
  }
  if (changed) validateMigrationTransitionEvidence(state, session, previous, current, depth + 1)
}

function validatePinIntrinsic (state, record) {
  const value = record.value
  verifySingleSignature(state, 'PeeritHiveRelayProfilePinV1', value, value.releaseAuthorityPublicKey)
  const keyId = blake2b256(concatBytes(asciiBytes('peerit.release-authority-key-id.v1'), value.releaseAuthorityPublicKey))
  if (!bytesEqual(keyId, value.releaseAuthorityKeyId) || value.migrationStage !== value.legacyImportMode ||
      value.pinHistoryRetentionDays !== 3650) {
    failGraph('BAD_PROFILE_PIN_INTRINSIC_BINDING', 'profile pin key, migration, or retention binding is invalid')
  }
  if ((value.releaseSequence === 0n) !== (value.previousPinHash == null)) {
    failGraph('PROFILE_PIN_CHAIN_GAP_OR_FORK', 'only release sequence zero may omit the previous pin hash')
  }
}

function validatePinChain (state, session, topValue, topBytes, depth = 0) {
  const chain = []
  let current = Object.freeze({ value: topValue, bytes: snapshotBytes(topBytes, 'profile pin') })
  const observedSequences = new Map()
  while (true) {
    if (chain.length >= state.budgets.maximumGraphDepth) failGraph('CONTEXTUAL_GRAPH_BUDGET_EXCEEDED', 'profile pin chain exceeds depth budget')
    validatePinIntrinsic(state, current)
    const currentHashHex = bytesToHex(hashPeeritProfilePinV1(current.bytes))
    const priorHash = observedSequences.get(current.value.releaseSequence.toString())
    if (priorHash != null && priorHash !== currentHashHex) failGraph('PROFILE_PIN_SAME_SEQUENCE_FORK', 'profile pin chain contains a same-sequence fork')
    observedSequences.set(current.value.releaseSequence.toString(), currentHashHex)
    const witnessed = session.context.witnessedPinHashes
    if (witnessed != null) {
      const sequence = current.value.releaseSequence.toString()
      const expected = witnessed instanceof Map ? witnessed.get(sequence) : witnessed[sequence]
      if (expected != null) {
        const expectedHex = typeof expected === 'string' ? expected : bytesToHex(expected)
        if (expectedHex !== currentHashHex) failGraph('PROFILE_PIN_SAME_SEQUENCE_FORK', 'profile pin conflicts with the witnessed hash for its sequence')
      }
    }
    chain.push(current)
    if (current.value.releaseSequence === 0n) break
    const nextHashHex = bytesToHex(current.value.previousPinHash)
    if ([...observedSequences.values()].includes(nextHashHex)) failGraph('CONTEXTUAL_GRAPH_CYCLE', 'profile pin predecessor graph contains a cycle')
    const fetched = fetchRecord(
      session,
      'PeeritHiveRelayProfilePinV1',
      current.value.previousPinHash,
      'profile pin predecessor',
      hashPeeritProfilePinV1,
      depth + chain.length,
      8192
    )
    const previous = Object.freeze({ value: fetched.value, bytes: fetched.bytes })
    validatePinPair(state, session, previous, current, depth + chain.length)
    current = previous
  }
  chain.reverse()
  return Object.freeze(chain)
}

function validateMigrationTransitionEvidence (state, session, previousPin, targetPin, depth) {
  const fetched = fetchRecord(
    session,
    'PeeritMigrationTransitionEvidenceV1',
    targetPin.value.migrationTransitionEvidenceHash,
    'migration transition evidence',
    bytes => domainLengthHash('peerit.migration-transition-evidence-hash.v1', bytes),
    depth,
    16384
  )
  const evidence = fetched.value
  verifySingleSignature(state, 'PeeritMigrationTransitionEvidenceV1', evidence, targetPin.value.releaseAuthorityPublicKey)
  if (!bytesEqual(evidence.previousPinHash, hashPeeritProfilePinV1(previousPin.bytes)) ||
      evidence.targetReleaseSequence !== targetPin.value.releaseSequence || evidence.fromMigrationStage !== previousPin.value.migrationStage ||
      evidence.toMigrationStage !== targetPin.value.migrationStage || evidence.targetLegacyImportMode !== targetPin.value.legacyImportMode ||
      evidence.targetLegacyReadMode !== targetPin.value.legacyReadMode || evidence.releaseAuthoritySequence !== targetPin.value.releaseAuthoritySequence ||
      !bytesEqual(evidence.releaseAuthorityKeyId, targetPin.value.releaseAuthorityKeyId) ||
      !sameOptionalBytes(evidence.legacyCutoffHash, targetPin.value.legacyCutoffHash) ||
      !sameOptionalBytes(evidence.migrationGenesisRecordId, targetPin.value.migrationGenesisRecordId) ||
      evidence.targetCutoffActivationReleaseSequence !== targetPin.value.cutoffActivationReleaseSequence ||
      !sameOptionalBytes(evidence.targetLegacyRetirementEvidenceHash, targetPin.value.legacyRetirementEvidenceHash) ||
      evidence.targetLegacyRetirementActivationReleaseSequence !== targetPin.value.legacyRetirementActivationReleaseSequence) {
    failGraph('BAD_MIGRATION_TRANSITION_BINDING', 'migration transition evidence does not equal the adjacent pins')
  }
  const bundle = fetchRecord(
    session,
    'PeeritReleaseQualificationEvidenceBundleV1',
    evidence.evidenceBundleHash,
    'release qualification evidence bundle',
    bytes => domainLengthHash('peerit.release-qualification-evidence-bundle-hash.v1', bytes),
    depth + 1,
    16777216
  )
  validateQualificationEvidenceBundle(state, session, bundle.value, bundle.bytes)
  const fields = [
    'qualificationSubjectHash', 'windowStartedUnixMillis', 'windowEndedUnixMillis', 'attemptedLogicalWrites',
    'terminalSuccessfulWrites', 'terminalFailedWrites', 'pendingOrUnknownWrites', 'acknowledgedWriteLosses',
    'unresolvedLegacyOnlyWrites', 'forbiddenLegacyWrites', 'signatureOrCodecDisagreements', 'floorRollbacks', 'hiddenPrivacyDowngrades'
  ]
  for (const field of fields) {
    const left = evidence[field]
    const right = bundle.value[field]
    if (left instanceof Uint8Array ? !bytesEqual(left, right) : left !== right) {
      failGraph('BAD_MIGRATION_TRANSITION_SUMMARY', `migration transition ${field} does not equal its evidence bundle`)
    }
  }
  if (evidence.reconstructionEvidenceHashes.length !== bundle.value.reconstructionEvidenceHashes.length ||
      evidence.reconstructionEvidenceHashes.some((hash, index) => !bytesEqual(hash, bundle.value.reconstructionEvidenceHashes[index]))) {
    failGraph('BAD_MIGRATION_TRANSITION_SUMMARY', 'migration transition reconstruction hashes do not equal its evidence bundle')
  }
}

function rootFromContext (state, session, rootRecordId, generation) {
  const rootBytes = session.context.acceptedRootBytes
  if (rootBytes == null) failGraph('ACCEPTED_ROOT_CONTEXT_REQUIRED', 'threshold validation requires acceptedRootBytes')
  const bytes = snapshotBytes(rootBytes, 'accepted root bytes')
  const value = state.catalog.AvailabilityRootV1.decode(bytes)
  if (!bytesEqual(hashPeeritProfileRecordIdV1(1, bytes), rootRecordId) || value.generation !== generation ||
      value.recoveryThreshold !== 2 || value.discoveryMaintainerThreshold !== 3 ||
      value.recoveryKeys.length !== 3 || value.discoveryMaintainerKeys.length !== 4) {
    failGraph('BAD_ACCEPTED_ROOT_CONTEXT', 'accepted root does not match the referenced root/generation/threshold shape')
  }
  verifySingleSignature(state, 'AvailabilityRootV1', value, value.rootVerifyKey)
  return Object.freeze({ bytes, value })
}

function sharedCommitment (state, schemaName, value, signatureField, domain, manifestTag) {
  const fields = prefixBytes(state, schemaName, value, signatureField).slice(2)
  return blake2b256(concatBytes(
    asciiBytes(domain),
    manifestTag == null ? [] : u16Bytes(manifestTag),
    u64Bytes(fields.byteLength),
    fields
  ))
}

function validateMaintainerThreshold (state, root, schemaName, value, signatureField, domain, manifestTag) {
  const signatures = value[signatureField]
  if (!Array.isArray(signatures) || signatures.length < root.discoveryMaintainerThreshold || signatures.length > root.discoveryMaintainerKeys.length) {
    failGraph('DISCOVERY_THRESHOLD_NOT_MET', `${schemaName} does not meet the accepted maintainer threshold`)
  }
  distinctByteValues(signatures.map(row => row.maintainerKey), `${schemaName} maintainer keys`)
  const commitment = sharedCommitment(state, schemaName, value, signatureField, domain, manifestTag)
  for (const row of signatures) {
    if (!root.discoveryMaintainerKeys.some(key => bytesEqual(key, row.maintainerKey))) {
      failGraph('DISCOVERY_SIGNER_NOT_ACCEPTED', `${schemaName} contains a signer outside the accepted root`)
    }
    verifyDetached(row.signature, commitment, row.maintainerKey, 'INVALID_DISCOVERY_THRESHOLD_SIGNATURE', `${schemaName} maintainer`)
  }
  return commitment
}

function validateDiscoveryThresholdRecord (state, session, schemaName, value) {
  const root = rootFromContext(state, session, value.rootRecordId, value.generation).value
  if (schemaName === 'DiscoverySnapshotV1') {
    return validateMaintainerThreshold(state, root, schemaName, value, 'maintainerSignatures', 'peerit.hiverelay.discovery-snapshot.v1', 5)
  }
  if (schemaName === 'DiscoveryCheckpointV1') {
    return validateMaintainerThreshold(state, root, schemaName, value, 'maintainerSignatures', 'peerit.hiverelay.discovery-checkpoint.v1', 7)
  }
  if (schemaName === 'RelayProbeEvidenceSetV1') {
    return validateMaintainerThreshold(state, root, schemaName, value, 'maintainerSignatures', 'peerit.hiverelay.relay-probe-evidence-set.v1', 8)
  }
  failGraph('CONTEXTUAL_SIGNATURE_RULE_MISSING', `${schemaName} is not a threshold-signed discovery record`)
}

function validateRootRotation (state, session, value) {
  const previousRoot = rootFromContext(state, session, value.previousRootRecordId, value.previousGeneration).value
  if (value.nextGeneration !== value.previousGeneration + 1n || value.nextRootReplicas.length !== 3 ||
      value.nextRootReplicas.some(binding => !bytesEqual(binding.value.logicalHash, value.nextRootLogicalHash))) {
    failGraph('BAD_ROOT_ROTATION_BINDING', 'root rotation generation or next-root replica binding is invalid')
  }
  const nextRootBytes = session.context.nextRootBytes
  if (nextRootBytes == null) failGraph('NEXT_ROOT_CONTEXT_REQUIRED', 'root rotation requires nextRootBytes')
  const nextBytes = snapshotBytes(nextRootBytes, 'next root bytes')
  const nextRoot = state.catalog.AvailabilityRootV1.decode(nextBytes)
  if (!bytesEqual(hashPeeritProfileRecordIdV1(1, nextBytes), value.nextRootRecordId) || nextRoot.generation !== value.nextGeneration) {
    failGraph('BAD_ROOT_ROTATION_BINDING', 'next root bytes do not reproduce nextRootRecordId/generation')
  }
  verifySingleSignature(state, 'AvailabilityRootV1', nextRoot, nextRoot.rootVerifyKey)
  const commitment = sharedCommitment(state, 'RootRotateV1', value, 'oldRootSignature', 'peerit.hiverelay.root-rotate.v1')
  const recovery = value.oldRootSignature == null
  if (recovery) {
    if (value.recoverySignatures.length !== previousRoot.recoveryThreshold) failGraph('ROOT_RECOVERY_THRESHOLD_NOT_MET', 'root recovery does not have the exact old threshold')
    distinctByteValues(value.recoverySignatures.map(row => row.recoveryKey), 'root recovery keys')
    for (const row of value.recoverySignatures) {
      if (!previousRoot.recoveryKeys.some(key => bytesEqual(key, row.recoveryKey))) failGraph('ROOT_RECOVERY_SIGNER_NOT_ACCEPTED', 'root recovery signer is not accepted by the old root')
      verifyDetached(row.signature, commitment, row.recoveryKey, 'INVALID_ROOT_RECOVERY_SIGNATURE', 'root recovery')
    }
  } else {
    if (value.recoverySignatures.length !== 0) failGraph('BAD_ROOT_ROTATION_MODE', 'normal root rotation contains recovery signatures')
    verifyDetached(value.oldRootSignature, commitment, previousRoot.rootVerifyKey, 'INVALID_ROOT_ROTATION_SIGNATURE', 'old root')
  }
  verifyDetached(value.newRootSignature, commitment, nextRoot.rootVerifyKey, 'INVALID_ROOT_ROTATION_SIGNATURE', 'new root')
  return Object.freeze({ previousRoot, nextRoot, commitment })
}

function encodeFixedArrayU8 (values) {
  if (values.length > 255) failGraph('BAD_CONTEXTUAL_GRAPH_VALUE', 'u8 array exceeds 255 entries')
  return concatBytes(Uint8Array.of(values.length), values)
}

function witnessStatementMessage (witness) {
  return concatBytes(
    asciiBytes('peerit.hiverelay.operator-group-witness.v1'),
    witness.witnessGroupId,
    witness.witnessKey,
    u32Bytes(witness.issuedLeaseEpoch),
    u32Bytes(witness.expiresLeaseEpoch)
  )
}

function profile1FailureDomainBytes (row) {
  return concatBytes(row.continuityRoot, row.storeId, row.localFailureDomainId, row.chaosEvidenceHash)
}

function groupStatementFields (group) {
  return concatBytes(
    group.groupId,
    group.operatorStatementKey,
    encodeFixedArrayU8(group.continuityRoots),
    encodeFixedArrayU8(group.maintainerKeys),
    encodeFixedArrayU8(group.failureDomainCommitments),
    encodeFixedArrayU8(group.profile1StoreFailureDomains.map(profile1FailureDomainBytes)),
    u32Bytes(group.issuedLeaseEpoch),
    u32Bytes(group.expiresLeaseEpoch)
  )
}

function groupStatementCommitment (group) {
  const fields = groupStatementFields(group)
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.operator-group-statement.v1'),
    u64Bytes(fields.byteLength),
    fields
  ))
}

function validateOperatorGroupRegistry (state, session, value, bytes, depth = 0, seen = new Set()) {
  const currentHash = domainLengthHash('peerit.hiverelay.operator-group-registry-hash.v1', bytes)
  const currentHex = bytesToHex(currentHash)
  if (seen.has(currentHex)) failGraph('CONTEXTUAL_GRAPH_CYCLE', 'operator registry predecessor graph contains a cycle')
  seen.add(currentHex)
  const effectiveLeaseEpoch = session.context.effectiveLeaseEpoch
  if (!Number.isSafeInteger(effectiveLeaseEpoch) || effectiveLeaseEpoch < 0 || effectiveLeaseEpoch > 0xffffffff) {
    failGraph('EFFECTIVE_LEASE_EPOCH_REQUIRED', 'operator registry validation requires an effectiveLeaseEpoch')
  }
  const witnessByKey = new Map()
  const witnessGroupByKey = new Map()
  for (const witness of value.witnesses) {
    const key = bytesToHex(witness.witnessKey)
    if (witnessByKey.has(key) || witness.issuedLeaseEpoch > effectiveLeaseEpoch || witness.expiresLeaseEpoch < effectiveLeaseEpoch) {
      failGraph('BAD_OPERATOR_REGISTRY_WITNESS', 'operator registry witness is duplicate or outside its accepted lease')
    }
    verifyDetached(witness.witnessStatementSignature, witnessStatementMessage(witness), witness.witnessKey, 'INVALID_OPERATOR_REGISTRY_WITNESS_SIGNATURE', 'operator registry witness')
    witnessByKey.set(key, witness)
    witnessGroupByKey.set(key, bytesToHex(witness.witnessGroupId))
  }
  distinctByteValues(value.witnesses.map(witness => witness.witnessGroupId), 'operator registry witness groups')
  const allContinuityRoots = []
  const allMaintainerKeys = []
  const allProfile1Tuples = new Set()
  const allProfile1Domains = new Set()
  for (const group of value.groups) {
    if (group.issuedLeaseEpoch > effectiveLeaseEpoch || group.expiresLeaseEpoch < effectiveLeaseEpoch ||
        bytesEqual(group.groupId, group.operatorStatementKey)) {
      failGraph('BAD_OPERATOR_GROUP_STATEMENT', 'operator group statement is expired, premature, or self-confuses its group/key')
    }
    const commitment = groupStatementCommitment(group)
    verifyDetached(group.operatorSignature, commitment, group.operatorStatementKey, 'INVALID_OPERATOR_GROUP_SIGNATURE', 'operator group')
    const witnessedGroups = new Set()
    const witnessedKeys = new Set()
    for (const signature of group.witnessSignatures) {
      const key = bytesToHex(signature.witnessKey)
      const witness = witnessByKey.get(key)
      if (witness == null || bytesEqual(witness.witnessGroupId, group.groupId) || bytesEqual(signature.witnessKey, group.operatorStatementKey) || witnessedKeys.has(key)) {
        failGraph('BAD_OPERATOR_GROUP_WITNESS_SET', 'operator group witness is unknown, duplicate, or conflicts with the operator')
      }
      verifyDetached(signature.signature, commitment, signature.witnessKey, 'INVALID_OPERATOR_GROUP_WITNESS_SIGNATURE', 'operator group witness')
      witnessedKeys.add(key)
      witnessedGroups.add(witnessGroupByKey.get(key))
    }
    if (witnessedGroups.size < value.witnessThreshold) failGraph('OPERATOR_GROUP_WITNESS_THRESHOLD_NOT_MET', 'operator group statement does not meet distinct witness-group threshold')
    allContinuityRoots.push(...group.continuityRoots)
    allMaintainerKeys.push(...group.maintainerKeys)
    for (const row of group.profile1StoreFailureDomains) {
      if (isAllZero(row.storeId) || isAllZero(row.localFailureDomainId) || isAllZero(row.chaosEvidenceHash)) {
        failGraph('BAD_PROFILE1_FAILURE_DOMAIN_DECLARATION', 'profile-1 failure-domain declaration has a zero security value')
      }
      const tuple = `${bytesToHex(row.continuityRoot)}:${bytesToHex(row.storeId)}`
      const domain = bytesToHex(row.localFailureDomainId)
      if (allProfile1Tuples.has(tuple) || allProfile1Domains.has(domain)) {
        failGraph('DUPLICATE_PROFILE1_FAILURE_DOMAIN_DECLARATION', 'profile-1 store tuple or local failure-domain ID repeats globally')
      }
      allProfile1Tuples.add(tuple)
      allProfile1Domains.add(domain)
    }
  }
  distinctByteValues(allContinuityRoots, 'operator registry continuity roots')
  distinctByteValues(allMaintainerKeys, 'operator registry maintainer keys')
  const registryMessage = concatBytes(
    asciiBytes('peerit.hiverelay.operator-group-registry.v1'),
    prefixBytes(state, 'PeeritOperatorGroupRegistryV1', value, 'registryWitnessSignatures')
  )
  const registryWitnessGroups = new Set()
  const registryWitnessKeys = new Set()
  for (const packed of value.registryWitnessSignatures) {
    const keyBytes = packed.slice(0, 32)
    const signature = packed.slice(32)
    const key = bytesToHex(keyBytes)
    const witness = witnessByKey.get(key)
    if (witness == null || registryWitnessKeys.has(key)) failGraph('BAD_OPERATOR_REGISTRY_WITNESS_SET', 'registry signature key is unknown or duplicate')
    verifyDetached(signature, registryMessage, keyBytes, 'INVALID_OPERATOR_REGISTRY_SIGNATURE', 'operator registry')
    registryWitnessKeys.add(key)
    registryWitnessGroups.add(bytesToHex(witness.witnessGroupId))
  }
  if (registryWitnessGroups.size < value.witnessThreshold) failGraph('OPERATOR_REGISTRY_WITNESS_THRESHOLD_NOT_MET', 'registry does not meet distinct witness-group threshold')
  if (value.registrySequence === 0n) {
    if (value.previousRegistryHash != null) failGraph('OPERATOR_REGISTRY_CHAIN_GAP_OR_FORK', 'registry sequence zero has a predecessor')
  } else {
    if (value.previousRegistryHash == null) failGraph('OPERATOR_REGISTRY_CHAIN_GAP_OR_FORK', 'nonzero registry sequence omits its predecessor')
    const predecessor = fetchRecord(
      session,
      'PeeritOperatorGroupRegistryV1',
      value.previousRegistryHash,
      'operator registry predecessor',
      predecessorBytes => domainLengthHash('peerit.hiverelay.operator-group-registry-hash.v1', predecessorBytes),
      depth + 1,
      1048576
    )
    if (predecessor.value.registrySequence + 1n !== value.registrySequence) failGraph('OPERATOR_REGISTRY_CHAIN_GAP_OR_FORK', 'operator registry predecessor is not exact +1')
    validateOperatorGroupRegistry(state, session, predecessor.value, predecessor.bytes, depth + 1, seen)
  }
  return Object.freeze({ registryHash: currentHash, witnessGroupCount: registryWitnessGroups.size })
}

function validatePinHistoryCheckpoint (state, session, value, bytes, depth = 0, seen = new Set()) {
  const currentHash = hashPeeritPinHistoryCheckpointV1(bytes)
  const currentHex = bytesToHex(currentHash)
  if (seen.has(currentHex)) failGraph('CONTEXTUAL_GRAPH_CYCLE', 'pin checkpoint predecessor graph contains a cycle')
  seen.add(currentHex)
  const pin = fetchRecord(
    session,
    'PeeritHiveRelayProfilePinV1',
    value.pinHash,
    'checkpoint profile pin',
    hashPeeritProfilePinV1,
    depth + 1,
    8192
  )
  validatePinIntrinsic(state, pin)
  if (pin.value.releaseSequence !== value.checkpointSequence || pin.value.releaseAuthoritySequence !== value.releaseAuthoritySequence ||
      !bytesEqual(pin.value.releaseAuthorityKeyId, value.releaseAuthorityKeyId) ||
      !sameOptionalBytes(pin.value.previousPinHash, value.previousPinHash)) {
    failGraph('BAD_PIN_HISTORY_CHECKPOINT_BINDING', 'checkpoint fields do not equal the fetched complete pin')
  }
  verifySingleSignature(state, 'PeeritPinHistoryCheckpointV1', value, pin.value.releaseAuthorityPublicKey)
  if (value.checkpointSequence === 0n) {
    if (value.previousCheckpointHash != null || value.previousPinHash != null) failGraph('PIN_HISTORY_CHAIN_GAP_OR_FORK', 'checkpoint sequence zero has predecessor fields')
  } else {
    if (value.previousCheckpointHash == null || value.previousPinHash == null) failGraph('PIN_HISTORY_CHAIN_GAP_OR_FORK', 'nonzero checkpoint omits predecessor fields')
    const predecessor = fetchRecord(
      session,
      'PeeritPinHistoryCheckpointV1',
      value.previousCheckpointHash,
      'pin history checkpoint predecessor',
      hashPeeritPinHistoryCheckpointV1,
      depth + 1,
      2048
    )
    if (predecessor.value.checkpointSequence + 1n !== value.checkpointSequence || !bytesEqual(predecessor.value.pinHash, value.previousPinHash)) {
      failGraph('PIN_HISTORY_CHAIN_GAP_OR_FORK', 'checkpoint predecessor is not exact +1 or names the wrong prior pin')
    }
    validatePinHistoryCheckpoint(state, session, predecessor.value, predecessor.bytes, depth + 1, seen)
  }
  return Object.freeze({ checkpointHash: currentHash, pinHash: value.pinHash })
}

function validatePinHistoryBundle (state, session, value) {
  if (value.checkpoints.length !== value.pins.length) failGraph('BAD_PIN_HISTORY_BUNDLE', 'pin history bundle arrays have different counts')
  let previousCheckpointHash = null
  let previousPinHash = null
  let previousSequence = null
  const seenCheckpointHashes = new Set()
  const seenPinHashes = new Set()
  for (let index = 0; index < value.pins.length; index++) {
    const pinBytes = snapshotBytes(value.pins[index], `pin history pin ${index}`)
    const checkpointBytes = snapshotBytes(value.checkpoints[index], `pin history checkpoint ${index}`)
    const pin = state.catalog.PeeritHiveRelayProfilePinV1.decode(pinBytes)
    const checkpoint = state.catalog.PeeritPinHistoryCheckpointV1.decode(checkpointBytes)
    const pinHash = hashPeeritProfilePinV1(pinBytes)
    const checkpointHash = hashPeeritPinHistoryCheckpointV1(checkpointBytes)
    if (seenPinHashes.has(bytesToHex(pinHash)) || seenCheckpointHashes.has(bytesToHex(checkpointHash))) {
      failGraph('BAD_PIN_HISTORY_BUNDLE', 'pin history bundle repeats an object')
    }
    seenPinHashes.add(bytesToHex(pinHash))
    seenCheckpointHashes.add(bytesToHex(checkpointHash))
    validatePinIntrinsic(state, { value: pin, bytes: pinBytes })
    verifySingleSignature(state, 'PeeritPinHistoryCheckpointV1', checkpoint, pin.releaseAuthorityPublicKey)
    if (!bytesEqual(checkpoint.pinHash, pinHash) || checkpoint.checkpointSequence !== pin.releaseSequence ||
        checkpoint.releaseAuthoritySequence !== pin.releaseAuthoritySequence || !bytesEqual(checkpoint.releaseAuthorityKeyId, pin.releaseAuthorityKeyId)) {
      failGraph('BAD_PIN_HISTORY_BUNDLE', 'checkpoint does not bind its paired pin')
    }
    if (previousSequence != null && (pin.releaseSequence !== previousSequence + 1n ||
        !bytesEqual(pin.previousPinHash, previousPinHash) || !bytesEqual(checkpoint.previousPinHash, previousPinHash) ||
        !bytesEqual(checkpoint.previousCheckpointHash, previousCheckpointHash))) {
      failGraph('BAD_PIN_HISTORY_BUNDLE', 'pin history bundle is not one contiguous ordered suffix')
    }
    previousSequence = pin.releaseSequence
    previousPinHash = pinHash
    previousCheckpointHash = checkpointHash
  }
  return Object.freeze({ terminalPinHash: previousPinHash, terminalCheckpointHash: previousCheckpointHash, count: value.pins.length })
}

function validateAuthorChain (state, session, value, bytes, depth = 0, seen = new Set()) {
  verifySingleSignature(state, 'AuthorBindV1', value, value.authorPublicKey)
  const currentId = hashPeeritProfileRecordIdV1(3, bytes)
  const currentHex = bytesToHex(currentId)
  if (seen.has(currentHex)) failGraph('CONTEXTUAL_GRAPH_CYCLE', 'author predecessor graph contains a cycle')
  seen.add(currentHex)
  if (value.authorSequence === 0n) {
    if (value.previousAuthorRecordId != null) failGraph('AUTHOR_CHAIN_GAP_OR_FORK', 'author sequence zero has a predecessor')
  } else {
    if (value.previousAuthorRecordId == null) failGraph('AUTHOR_CHAIN_GAP_OR_FORK', 'nonzero author sequence omits a predecessor')
    const predecessor = fetchRecord(
      session,
      'AuthorBindV1',
      value.previousAuthorRecordId,
      'author record predecessor',
      predecessorBytes => hashPeeritProfileRecordIdV1(3, predecessorBytes),
      depth + 1,
      1048576
    )
    if (predecessor.value.authorSequence + 1n !== value.authorSequence ||
        !bytesEqual(predecessor.value.authorPublicKey, value.authorPublicKey)) {
      failGraph('AUTHOR_CHAIN_GAP_OR_FORK', 'author predecessor is not exact +1 under the same authority')
    }
    validateAuthorChain(state, session, predecessor.value, predecessor.bytes, depth + 1, seen)
  }
  return currentId
}

function validateObservationChain (state, session, value, bytes, depth = 0, seen = new Set()) {
  verifySingleSignature(state, 'MaintainerObservationV1', value, value.maintainerKey)
  const currentHash = domainLengthHash('peerit.hiverelay.maintainer-observation-hash.v1', bytes)
  const currentHex = bytesToHex(currentHash)
  if (seen.has(currentHex)) failGraph('CONTEXTUAL_GRAPH_CYCLE', 'maintainer observation graph contains a cycle')
  seen.add(currentHex)
  if (value.observationSequence === 0n) {
    if (value.previousObservationHash != null) failGraph('OBSERVATION_CHAIN_GAP_OR_FORK', 'observation sequence zero has a predecessor')
  } else {
    const predecessor = fetchRecord(
      session,
      'MaintainerObservationV1',
      value.previousObservationHash,
      'maintainer observation predecessor',
      predecessorBytes => domainLengthHash('peerit.hiverelay.maintainer-observation-hash.v1', predecessorBytes),
      depth + 1,
      1048576
    )
    if (predecessor.value.observationSequence + 1n !== value.observationSequence ||
        !bytesEqual(predecessor.value.maintainerKey, value.maintainerKey) ||
        predecessor.value.receivedUnixMillis > value.receivedUnixMillis) {
      failGraph('OBSERVATION_CHAIN_GAP_OR_FORK', 'observation predecessor is not exact +1, same-key, and monotonic')
    }
    validateObservationChain(state, session, predecessor.value, predecessor.bytes, depth + 1, seen)
  }
  return currentHash
}

function legacySourceSetFromCutoff (state, cutoff) {
  return state.catalog.LegacySourceSetV1.encode({
    version: 1,
    sources: cutoff.sources.map(source => ({
      sourceRelayIdentity: new Uint8Array(source.sourceRelayIdentity),
      sourceDescriptorHash: new Uint8Array(source.sourceDescriptorHash),
      legacyServiceId: new Uint8Array(source.legacyServiceId)
    }))
  })
}

function validateLegacyCutoffDeterministic (state, session, value, bytes, depth = 0) {
  if (value.drainEndedUnixMillis !== value.drainStartedUnixMillis + 86400000n) {
    failGraph('BAD_LEGACY_CUTOFF_WINDOW', 'legacy cutoff drain must be exactly 24 hours')
  }
  const pairs = new Set()
  for (const source of value.sources) {
    const pair = `${bytesToHex(source.sourceRelayIdentity)}:${bytesToHex(source.legacyServiceId)}`
    if (pairs.has(pair)) failGraph('DUPLICATE_LEGACY_SOURCE', 'legacy cutoff repeats a relay/service pair')
    pairs.add(pair)
    const absent = source.terminalHeadBytes == null && source.terminalHeadHash == null
    const present = source.terminalHeadBytes != null && source.terminalHeadHash != null
    if (source.snapshotStatus < 1 || source.snapshotStatus > 3 ||
        (source.snapshotStatus === 2 ? !absent : !present) ||
        (present && !bytesEqual(source.terminalHeadHash, blake2b256(source.terminalHeadBytes)))) {
      failGraph('BAD_LEGACY_SOURCE_STATUS', 'legacy cutoff source status/head shape is invalid')
    }
  }
  const sourceSetBytes = legacySourceSetFromCutoff(state, value)
  const sourceSetHash = domainLengthHash('peerit.hiverelay.legacy-source-set-hash.v1', sourceSetBytes)
  if (!bytesEqual(sourceSetHash, value.legacySourceSetHash)) failGraph('BAD_LEGACY_SOURCE_SET_HASH', 'legacy cutoff sources do not reproduce legacySourceSetHash')
  const pendingPin = fetchRecord(
    session,
    'PeeritHiveRelayProfilePinV1',
    value.cutoffPendingPinHash,
    'cutoff pending profile pin',
    hashPeeritProfilePinV1,
    depth + 1,
    8192
  )
  validatePinIntrinsic(state, pendingPin)
  if (pendingPin.value.legacyImportMode !== 0 || pendingPin.value.legacyReadMode !== 0 ||
      pendingPin.value.releaseSequence !== value.legacyWriteCutoffReleaseSequence ||
      pendingPin.value.releaseAuthoritySequence !== value.releaseAuthoritySequence ||
      !bytesEqual(pendingPin.value.releaseAuthorityKeyId, value.releaseAuthorityKeyId) ||
      !bytesEqual(pendingPin.value.legacySourceSetHash, value.legacySourceSetHash)) {
    failGraph('BAD_LEGACY_CUTOFF_PIN_BINDING', 'legacy cutoff does not bind the final LIVE_DUAL_READ pin')
  }
  verifySingleSignature(state, 'LegacyCutoffV1', value, pendingPin.value.releaseAuthorityPublicKey)
  return Object.freeze({
    cutoffHash: hashPeeritLegacyCutoffV1(bytes),
    sourceSetHash,
    pendingPin
  })
}

function taggedLegacyEntryBytes (state, entry) {
  return state.catalog.LegacyArchiveEntryV1.encode(entry)
}

function untaggedLegacyEntryBytes (state, entry) {
  if (entry.variant === 1 || entry.variant === 2) return state.catalog.LegacyValidRecordEntryV1.encode(entry.value)
  if (entry.variant === 3) return state.catalog.LegacyInvalidRecordEntryV1.encode(entry.value)
  if (entry.variant === 4) return state.catalog.LegacyMissingRangeEntryV1.encode(entry.value)
  failGraph('BAD_LEGACY_ARCHIVE_ENTRY', `legacy archive entry has unknown variant ${entry.variant}`)
}

function legacyEntryHash (state, entry) {
  const tagged = taggedLegacyEntryBytes(state, entry)
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.legacy-archive-entry.v1'),
    Uint8Array.of(entry.variant),
    u64Bytes(tagged.byteLength),
    tagged
  ))
}

function exactLegacyCategoryRoot (state, category, entries) {
  if (entries.length === 0) {
    return blake2b256(concatBytes(asciiBytes('peerit.hiverelay.legacy-category-empty.v1'), Uint8Array.of(category)))
  }
  let level = entries.map(entry => {
    const bytes = untaggedLegacyEntryBytes(state, entry)
    return blake2b256(concatBytes(
      asciiBytes('peerit.hiverelay.legacy-category-leaf.v1'),
      Uint8Array.of(category),
      u64Bytes(bytes.byteLength),
      bytes
    ))
  })
  while (level.length > 1) {
    const next = []
    for (let index = 0; index < level.length; index += 2) {
      next.push(index + 1 === level.length
        ? level[index]
        : blake2b256(concatBytes(asciiBytes('peerit.hiverelay.legacy-category-node.v1'), Uint8Array.of(category), level[index], level[index + 1])))
    }
    level = next
  }
  return level[0]
}

function legacyCensusRoot (entries) {
  if (entries.length === 0) failGraph('EMPTY_LEGACY_RETAINED_CENSUS', 'retained legacy census must be nonempty')
  let level = entries.map(entry => blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.census-leaf.v1'),
    entry.value.logicalRecordId,
    entry.value.exactOriginalSignedBytesHash
  )))
  while (level.length > 1) {
    const next = []
    for (let index = 0; index < level.length; index += 2) {
      next.push(index + 1 === level.length
        ? level[index]
        : blake2b256(concatBytes(asciiBytes('peerit.hiverelay.census-node.v1'), level[index], level[index + 1])))
    }
    level = next
  }
  return level[0]
}

function legacyOriginalRecordsLogicalHash (entries) {
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.original-records.v1'),
    entries.map(entry => concatBytes(
      entry.value.logicalRecordId,
      u64Bytes(entry.value.exactOriginalSignedBytes.byteLength),
      entry.value.exactOriginalSignedBytes
    ))
  ))
}

function canonicalProvenanceArray (state, provenances) {
  return concatBytes(Uint8Array.of(provenances.length), provenances.map(value => state.catalog.LegacyProvenanceV1.encode(value)))
}

function optionalFixed (value) {
  return value == null ? Uint8Array.of(0) : concatBytes(Uint8Array.of(1), value)
}

function optionalU64 (value) {
  return value == null ? Uint8Array.of(0) : concatBytes(Uint8Array.of(1), u64Bytes(value))
}

function validateLegacyEvidenceIds (state, entry) {
  if (entry.variant === 3) {
    const value = entry.value
    const expected = blake2b256(concatBytes(
      asciiBytes('peerit.hiverelay.legacy-invalid-evidence.v1'),
      value.exactOriginalSignedBytesHash,
      u64Bytes(canonicalProvenanceArray(state, value.provenances).byteLength),
      canonicalProvenanceArray(state, value.provenances)
    ))
    if (!bytesEqual(expected, value.evidenceId)) failGraph('BAD_LEGACY_EVIDENCE_ID', 'invalid-entry evidence ID does not reproduce its bytes/provenances')
  } else if (entry.variant === 4) {
    const value = entry.value
    const expected = blake2b256(concatBytes(
      asciiBytes('peerit.hiverelay.legacy-missing-evidence.v1'),
      value.sourceRelayIdentity,
      value.sourceDescriptorHash,
      u64Bytes(value.legacyServiceId.byteLength),
      value.legacyServiceId,
      optionalFixed(value.terminalHeadHash),
      u64Bytes(value.rangeStartExclusive.byteLength),
      value.rangeStartExclusive,
      u64Bytes(value.rangeEndInclusive.byteLength),
      value.rangeEndInclusive,
      optionalU64(value.expectedRecordCount),
      u16Bytes(value.missingReasonCode),
      u64Bytes(value.sourceRangeEvidenceBytes.byteLength),
      value.sourceRangeEvidenceBytes
    ))
    if (!bytesEqual(expected, value.evidenceId)) failGraph('BAD_LEGACY_EVIDENCE_ID', 'missing-range evidence ID does not reproduce its range evidence')
  }
}

function legacyIndexProjection (row) {
  return concatBytes(Uint8Array.of(row.category), row.primarySortId, row.secondarySortId, row.entryHash)
}

function validateDeterministicLegacyArchiveBundle (state, session, bundle, bundleBytes, context = {}) {
  if (bundleBytes.byteLength > 251658240) failGraph('BAD_LEGACY_ARCHIVE_BUNDLE_SIZE', 'legacy archive bundle exceeds 240 MiB')
  const archiveBytes = snapshotBytes(bundle.archiveBytes, 'legacy archive bytes')
  const indexBytes = snapshotBytes(bundle.indexBytes, 'legacy archive index bytes')
  const distributionBytes = snapshotBytes(bundle.distributionBytes, 'legacy archive distribution bytes')
  const archive = state.catalog.PeeritLegacyArchiveV1.decode(archiveBytes)
  const index = state.catalog.LegacyArchiveIndexV1.decode(indexBytes)
  const distribution = state.catalog.LegacyArchiveDistributionV1.decode(distributionBytes)
  const cutoff = state.catalog.LegacyCutoffV1.decode(archive.cutoffBytes)
  const cutoffResult = validateLegacyCutoffDeterministic(state, session, cutoff, archive.cutoffBytes)
  const archiveArtifactHash = domainLengthHash('peerit.hiverelay.legacy-archive.v1', archiveBytes)
  const archiveIndexHash = domainLengthHash('peerit.hiverelay.legacy-archive-index.v1', indexBytes)
  const distributionHash = domainLengthHash('peerit.hiverelay.legacy-archive-distribution-hash.v1', distributionBytes)
  const bundleLogicalHash = domainLengthHash('peerit.hiverelay.legacy-archive-bundle.v1', bundleBytes)
  if (!bytesEqual(index.legacyArchiveArtifactHash, archiveArtifactHash) || !bytesEqual(index.legacyCutoffHash, cutoffResult.cutoffHash) ||
      !bytesEqual(distribution.legacyArchiveArtifactHash, archiveArtifactHash) || !bytesEqual(distribution.legacyArchiveIndexHash, archiveIndexHash)) {
    failGraph('BAD_LEGACY_ARCHIVE_CROSS_BINDING', 'archive/index/distribution hashes do not bind the exact nested bytes')
  }
  verifySingleSignature(state, 'LegacyArchiveDistributionV1', distribution, cutoffResult.pendingPin.value.releaseAuthorityPublicKey)
  const distinctGroups = new Set(distribution.copies.map(copy => bytesToHex(copy.operatorGroupId)))
  const distinctKinds = new Set(distribution.copies.map(copy => copy.copyKind))
  const distinctFailureDomains = new Set(distribution.copies.map(copy => bytesToHex(copy.failureDomainCommitment)))
  if (distinctGroups.size < 2 || distinctKinds.size < 2 || distinctFailureDomains.size !== distribution.copies.length ||
      distribution.copies.some(copy => !bytesEqual(copy.artifactHash, archiveArtifactHash) || !bytesEqual(copy.indexHash, archiveIndexHash))) {
    failGraph('BAD_LEGACY_ARCHIVE_DISTRIBUTION', 'archive distribution lacks independent exact artifact/index copies')
  }
  chargeEntries(session, archive.entries.length + index.entries.length, 'legacy archive/index entries')
  if (archive.entries.length !== index.entries.length) failGraph('BAD_LEGACY_ARCHIVE_INDEX', 'archive and index entry counts differ')
  const tagged = archive.entries.map(entry => taggedLegacyEntryBytes(state, entry))
  const entriesByteLength = tagged.reduce((sum, bytes) => sum + bytes.byteLength, 0)
  let expectedOffset = archiveBytes.byteLength - entriesByteLength
  let previousProjection = null
  const categories = { 1: [], 2: [], 3: [], 4: [] }
  for (let position = 0; position < archive.entries.length; position++) {
    const entry = archive.entries[position]
    const row = index.entries[position]
    const value = entry.value
    const hash = legacyEntryHash(state, entry)
    const primary = entry.variant <= 2 ? value.logicalRecordId : value.evidenceId
    const secondary = entry.variant <= 3 ? value.exactOriginalSignedBytesHash : new Uint8Array(32)
    if (row.category !== entry.variant || !bytesEqual(row.primarySortId, primary) || !bytesEqual(row.secondarySortId, secondary) ||
        !bytesEqual(row.entryHash, hash) || row.archiveOffset !== BigInt(expectedOffset) || row.archiveLength !== tagged[position].byteLength) {
      failGraph('BAD_LEGACY_ARCHIVE_INDEX', `legacy index row ${position} does not select/reproduce its exact archive entry`)
    }
    const projection = legacyIndexProjection(row)
    if (previousProjection != null && compareBytes(previousProjection, projection) >= 0) failGraph('BAD_LEGACY_ARCHIVE_ORDER', 'legacy archive/index rows are not strictly ordered')
    previousProjection = projection
    expectedOffset += tagged[position].byteLength
    categories[entry.variant].push(entry)
    validateLegacyEvidenceIds(state, entry)
    if (entry.variant <= 3 && !bytesEqual(value.exactOriginalSignedBytesHash, blake2b256(value.exactOriginalSignedBytes))) {
      failGraph('BAD_LEGACY_ORIGINAL_BYTES_HASH', 'legacy entry does not reproduce its original signed-byte hash')
    }
  }
  if (expectedOffset !== archiveBytes.byteLength) failGraph('BAD_LEGACY_ARCHIVE_INDEX', 'legacy archive entry offsets do not terminate at EOF')
  const retainedIds = new Set()
  for (const entry of categories[1]) {
    const key = bytesToHex(entry.value.logicalRecordId)
    if (retainedIds.has(key)) failGraph('BAD_LEGACY_RETAINED_CENSUS', 'retained category repeats a logical record ID')
    retainedIds.add(key)
  }
  const conflicts = new Map()
  for (const entry of categories[2]) {
    const key = bytesToHex(entry.value.logicalRecordId)
    if (retainedIds.has(key)) failGraph('BAD_LEGACY_CONFLICT_CENSUS', 'logical record ID occurs in both retained and conflict categories')
    const hashes = conflicts.get(key) || new Set()
    hashes.add(bytesToHex(entry.value.exactOriginalSignedBytesHash))
    conflicts.set(key, hashes)
  }
  for (const hashes of conflicts.values()) if (hashes.size < 2) failGraph('BAD_LEGACY_CONFLICT_CENSUS', 'conflict logical ID has fewer than two distinct valid byte strings')
  const retained = [...categories[1]].sort((left, right) => compareBytes(left.value.logicalRecordId, right.value.logicalRecordId))
  if (retained.some((entry, position) => entry !== categories[1][position])) failGraph('BAD_LEGACY_RETAINED_CENSUS', 'retained entries are not ordered by logicalRecordId')
  const roots = {
    retained: exactLegacyCategoryRoot(state, 1, categories[1]),
    conflict: exactLegacyCategoryRoot(state, 2, categories[2]),
    invalid: exactLegacyCategoryRoot(state, 3, categories[3]),
    missing: exactLegacyCategoryRoot(state, 4, categories[4]),
    census: legacyCensusRoot(retained)
  }
  const originalRecordsLogicalHash = legacyOriginalRecordsLogicalHash(retained)
  if (index.retainedRecordCount !== BigInt(retained.length) || index.conflictRecordCount !== BigInt(conflicts.size) ||
      index.invalidRecordCount !== BigInt(categories[3].length) || index.missingRangeCount !== BigInt(categories[4].length) ||
      !bytesEqual(index.retainedCategoryRoot, roots.retained) || !bytesEqual(index.conflictCategoryRoot, roots.conflict) ||
      !bytesEqual(index.invalidCategoryRoot, roots.invalid) || !bytesEqual(index.missingCategoryRoot, roots.missing) ||
      !bytesEqual(index.legacyCensusRoot, roots.census) || !bytesEqual(index.originalRecordsLogicalHash, originalRecordsLogicalHash)) {
    failGraph('BAD_LEGACY_ARCHIVE_SUMMARY', 'legacy index counts/roots do not reproduce the archive')
  }
  return Object.freeze({
    archive,
    index,
    distribution,
    cutoff,
    cutoffResult,
    archiveArtifactHash,
    archiveIndexHash,
    distributionHash,
    bundleLogicalHash,
    originalRecordsLogicalHash,
    roots: Object.freeze(roots),
    counts: Object.freeze({
      retained: BigInt(retained.length),
      conflicts: BigInt(conflicts.size),
      invalid: BigInt(categories[3].length),
      missing: BigInt(categories[4].length)
    })
  })
}

function validateMigrationGenesisDeterministic (state, session, value, bytes, context = {}) {
  const activationPinBytes = context.activationPinBytes
  if (activationPinBytes == null) failGraph('MIGRATION_ACTIVATION_PIN_REQUIRED', 'migration genesis validation requires activationPinBytes')
  const pinBytes = snapshotBytes(activationPinBytes, 'migration activation pin')
  const pin = state.catalog.PeeritHiveRelayProfilePinV1.decode(pinBytes)
  validatePinIntrinsic(state, { value: pin, bytes: pinBytes })
  const recordId = hashPeeritProfileRecordIdV1(6, bytes)
  if (pin.migrationStage !== 1 || pin.legacyImportMode !== 1 || pin.legacyReadMode !== 0 ||
      pin.cutoffActivationReleaseSequence !== pin.releaseSequence ||
      !bytesEqual(pin.migrationGenesisRecordId, recordId) || !bytesEqual(pin.legacyCutoffHash, value.legacyCutoffHash) ||
      !bytesEqual(pin.legacySourceSetHash, value.legacySourceSetHash) || pin.releaseSequence !== value.releaseSequence ||
      !bytesEqual(pin.releaseAuthorityKeyId, value.releaseAuthorityKeyId)) {
    failGraph('BAD_MIGRATION_GENESIS_PIN_BINDING', 'migration genesis does not equal its first frozen-cutoff activation pin')
  }
  verifySingleSignature(state, 'MigrationGenesisV1', value, pin.releaseAuthorityPublicKey)
  const bundleRecord = fetchRecord(
    session,
    'LegacyArchiveBundleV1',
    value.legacyArchiveBundleLogicalHash,
    'legacy archive bundle',
    bundleBytes => domainLengthHash('peerit.hiverelay.legacy-archive-bundle.v1', bundleBytes),
    1,
    251658240
  )
  const archive = validateDeterministicLegacyArchiveBundle(state, session, bundleRecord.value, bundleRecord.bytes, context)
  if (!bytesEqual(value.cutoffPendingPinHash, archive.cutoff.cutoffPendingPinHash) ||
      !bytesEqual(pin.previousPinHash, value.cutoffPendingPinHash) || pin.releaseSequence !== archive.cutoffResult.pendingPin.value.releaseSequence + 1n ||
      !bytesEqual(value.legacySourceSetHash, archive.cutoff.legacySourceSetHash) || !bytesEqual(value.legacyCutoffHash, archive.cutoffResult.cutoffHash) ||
      !bytesEqual(value.legacyCensusRoot, archive.roots.census) || value.retainedRecordCount !== archive.counts.retained ||
      value.invalidRecordCount !== archive.counts.invalid || value.conflictRecordCount !== archive.counts.conflicts ||
      value.missingRangeCount !== archive.counts.missing || !bytesEqual(value.invalidCategoryRoot, archive.roots.invalid) ||
      !bytesEqual(value.conflictCategoryRoot, archive.roots.conflict) || !bytesEqual(value.missingCategoryRoot, archive.roots.missing) ||
      !bytesEqual(value.legacyArchiveArtifactHash, archive.archiveArtifactHash) ||
      !bytesEqual(value.legacyArchiveIndexHash, archive.archiveIndexHash) ||
      !bytesEqual(value.legacyArchiveDistributionHash, archive.distributionHash) ||
      !bytesEqual(value.legacyArchiveBundleLogicalHash, archive.bundleLogicalHash) ||
      !bytesEqual(value.originalRecordsLogicalHash, archive.originalRecordsLogicalHash)) {
    failGraph('BAD_MIGRATION_GENESIS_ARCHIVE_BINDING', 'migration genesis counts/roots/hashes do not reproduce the exact legacy archive bundle')
  }
  if (value.legacyArchiveBundleReplicas.some(binding => !bytesEqual(binding.value.logicalHash, value.legacyArchiveBundleLogicalHash)) ||
      value.originalRecordsReplicas.some(binding => !bytesEqual(binding.value.logicalHash, value.originalRecordsLogicalHash))) {
    failGraph('BAD_MIGRATION_GENESIS_REPLICA_BINDING', 'migration genesis replica logical hashes do not equal the archive/original streams')
  }
  return Object.freeze({ recordId, pin, archive })
}

function validateLegacyRetirementReferences (state, session, value, bytes, context = {}) {
  const targetPinBytes = context.targetPinBytes
  if (targetPinBytes == null) failGraph('RETIREMENT_TARGET_PIN_REQUIRED', 'legacy retirement validation requires targetPinBytes')
  const targetBytes = snapshotBytes(targetPinBytes, 'retirement target pin')
  const target = state.catalog.PeeritHiveRelayProfilePinV1.decode(targetBytes)
  validatePinIntrinsic(state, { value: target, bytes: targetBytes })
  const evidenceHash = hashPeeritLegacyRetirementEvidenceV1(bytes)
  if (target.legacyImportMode !== 2 || target.legacyReadMode !== 1 || target.releaseSequence !== value.targetReleaseSequence ||
      !bytesEqual(target.previousPinHash, value.previousPinHash) || !bytesEqual(target.legacyRetirementEvidenceHash, evidenceHash) ||
      target.legacyRetirementActivationReleaseSequence !== target.releaseSequence ||
      !bytesEqual(target.legacyCutoffHash, value.legacyCutoffHash) || !bytesEqual(target.migrationGenesisRecordId, value.migrationGenesisRecordId) ||
      target.releaseAuthoritySequence !== value.releaseAuthoritySequence || !bytesEqual(target.releaseAuthorityKeyId, value.releaseAuthorityKeyId)) {
    failGraph('BAD_LEGACY_RETIREMENT_PIN_BINDING', 'legacy retirement evidence does not equal its target archive-only pin')
  }
  verifySingleSignature(state, 'LegacyRetirementEvidenceV1', value, target.releaseAuthorityPublicKey)
  if (value.retirementWindowEndedUnixMillis <= value.retirementWindowStartedUnixMillis ||
      value.retirementWindowEndedUnixMillis - value.retirementWindowStartedUnixMillis < 7776000000n ||
      value.unresolvedValidLegacyOnlyCount !== 0n || value.acknowledgedWriteLossCount !== 0n || value.forbiddenLegacyWriteCount !== 0n) {
    failGraph('BAD_LEGACY_RETIREMENT_GATE', 'legacy retirement window is under 90 days or a zero-loss criterion is nonzero')
  }
  const previous = fetchRecord(
    session,
    'PeeritHiveRelayProfilePinV1',
    value.previousPinHash,
    'retirement previous dual-read pin',
    hashPeeritProfilePinV1,
    1,
    8192
  )
  validatePinIntrinsic(state, previous)
  if (previous.value.legacyReadMode !== 0 || !bytesEqual(value.precedingDualReadPinHashes[0], value.previousPinHash) ||
      previous.value.previousPinHash == null || !bytesEqual(previous.value.legacyCutoffHash, value.legacyCutoffHash) ||
      !bytesEqual(previous.value.migrationGenesisRecordId, value.migrationGenesisRecordId)) {
    failGraph('BAD_LEGACY_RETIREMENT_PREDECESSORS', 'retirement evidence does not name its newest dual-read predecessor')
  }
  const older = fetchRecord(
    session,
    'PeeritHiveRelayProfilePinV1',
    previous.value.previousPinHash,
    'retirement older dual-read pin',
    hashPeeritProfilePinV1,
    2,
    8192
  )
  validatePinIntrinsic(state, older)
  if (older.value.legacyReadMode !== 0 || !bytesEqual(older.value.legacyCutoffHash, value.legacyCutoffHash) ||
      !bytesEqual(older.value.migrationGenesisRecordId, value.migrationGenesisRecordId) ||
      !bytesEqual(value.precedingDualReadPinHashes[1], previous.value.previousPinHash) ||
      previous.value.releaseSequence !== older.value.releaseSequence + 1n ||
      bytesEqual(value.precedingDualReadPinHashes[0], value.precedingDualReadPinHashes[1])) {
    failGraph('BAD_LEGACY_RETIREMENT_PREDECESSORS', 'retirement dual-read predecessor pair is not newest-to-oldest contiguous history')
  }
  const genesis = fetchRecord(
    session,
    'MigrationGenesisV1',
    value.migrationGenesisRecordId,
    'retirement migration genesis',
    genesisBytes => hashPeeritProfileRecordIdV1(6, genesisBytes),
    1,
    1048576
  )
  let genesisPublicKey = target.releaseAuthorityPublicKey
  if (!bytesEqual(genesis.value.releaseAuthorityKeyId, target.releaseAuthorityKeyId)) {
    if (context.genesisActivationPinBytes == null) {
      failGraph('GENESIS_ACTIVATION_PIN_REQUIRED', 'a release-key rotation requires genesisActivationPinBytes to verify historical genesis')
    }
    const activationBytes = snapshotBytes(context.genesisActivationPinBytes, 'genesis activation pin')
    const activation = state.catalog.PeeritHiveRelayProfilePinV1.decode(activationBytes)
    validatePinIntrinsic(state, { value: activation, bytes: activationBytes })
    if (activation.releaseSequence !== genesis.value.releaseSequence ||
        !bytesEqual(activation.migrationGenesisRecordId, value.migrationGenesisRecordId) ||
        !bytesEqual(activation.releaseAuthorityKeyId, genesis.value.releaseAuthorityKeyId)) {
      failGraph('BAD_MIGRATION_GENESIS_PIN_BINDING', 'historical genesis activation pin does not bind the fetched genesis')
    }
    genesisPublicKey = activation.releaseAuthorityPublicKey
  }
  verifySingleSignature(state, 'MigrationGenesisV1', genesis.value, genesisPublicKey)
  if (!bytesEqual(genesis.value.legacyCutoffHash, value.legacyCutoffHash) ||
      !bytesEqual(genesis.value.legacyCensusRoot, value.retainedCensusRoot) || genesis.value.retainedRecordCount !== value.retainedRecordCount) {
    failGraph('BAD_LEGACY_RETIREMENT_GENESIS_BINDING', 'retirement census/cutoff does not equal migration genesis')
  }
  const evidenceHashes = [
    ...value.externalCopyRestoreEvidenceHashes,
    ...value.relayRestoreEvidenceHashes,
    value.freshUserExportEvidenceHash,
    ...value.reconstructionRehearsalHashes,
    value.evidenceBundleHash
  ]
  if (evidenceHashes.some(hash => isAllZero(hash))) failGraph('BAD_LEGACY_RETIREMENT_EVIDENCE_REFERENCE', 'retirement evidence contains a zero content hash')
  distinctByteValues(evidenceHashes, 'legacy retirement evidence references')
  return Object.freeze({ evidenceHash, target, previous, older, genesis })
}

function validateWebAssetManifestGraph (state, session, value, bytes, context = {}) {
  if (context.profilePinBytes == null) {
    failGraph('WEB_ASSET_PROFILE_PIN_REQUIRED', 'WebAssetManifestV1 graph validation requires exact signed profilePinBytes')
  }
  if (context.webAssetContentSnapshot == null) {
    failGraph('WEB_ASSET_CONTENT_SNAPSHOT_REQUIRED', 'WebAssetManifestV1 graph validation requires a complete content snapshot')
  }
  const pinBytes = snapshotBytes(context.profilePinBytes, 'web asset profile pin')
  const pin = state.catalog.PeeritHiveRelayProfilePinV1.decode(pinBytes)
  const pinChain = validatePinChain(state, session, pin, pinBytes)
  const manifestHash = hashPeeritWebAssetManifestV1(bytes)
  if (pin.releaseSequence !== value.releaseSequence ||
      !bytesEqual(pin.webAssetManifestHash, manifestHash) ||
      !bytesEqual(pin.appArtifactHash, value.appArtifactHash) ||
      pin.recommendedBootstrapHashes.length !== value.recommendedBootstrapHashes.length ||
      pin.recommendedBootstrapHashes.some((hash, index) =>
        !bytesEqual(hash, value.recommendedBootstrapHashes[index]))) {
    failGraph('BAD_WEB_ASSET_PIN_BINDING', 'WebAssetManifestV1 release, hash, app, or bootstrap fields do not equal its signed profile pin')
  }

  chargeEntries(session, value.assets.length, 'web asset manifest entries')
  if (session.fetchedObjects + value.assets.length > state.budgets.maximumFetchedObjects) {
    failGraph('CONTEXTUAL_GRAPH_BUDGET_EXCEEDED', 'web asset snapshot exceeds the fetched-object budget')
  }
  let declaredBytes = 0n
  for (const asset of value.assets) declaredBytes = checkedAdd(declaredBytes, asset.byteLength)
  const remainingBytes = BigInt(state.budgets.maximumFetchedBytes - session.fetchedBytes)
  if (declaredBytes > remainingBytes || declaredBytes > BigInt(Number.MAX_SAFE_INTEGER)) {
    failGraph('CONTEXTUAL_GRAPH_BUDGET_EXCEEDED', 'web asset snapshot exceeds the fetched-byte budget')
  }
  session.fetchedObjects += value.assets.length
  session.fetchedBytes += Number(declaredBytes)
  const content = verifyPeeritWebAssetContentV1(value, context.webAssetContentSnapshot)
  if (content.verifiedTotalBytes !== Number(declaredBytes)) {
    failGraph('BAD_WEB_ASSET_CONTENT_LENGTH', 'verified web asset bytes do not reproduce the manifest aggregate length')
  }
  return Object.freeze({
    manifestHash,
    pinHash: hashPeeritProfilePinV1(pinBytes),
    pinChainLength: pinChain.length,
    verifiedAssetCount: content.verifiedAssetCount,
    verifiedTotalBytes: content.verifiedTotalBytes,
    recommendedBootstrapCount: content.bootstrapAssets.length,
    complete: content.complete
  })
}

const INCOMPLETE_CONTEXTUAL_SCHEMAS = Object.freeze(new Set([
  'AvailabilityBootstrapV1',
  'InboxEpochSetV1',
  'InboxStripeBindingV1',
  'RootRotateV1',
  'CellReplicaBindingV1',
  'CoreReplicaBindingV1',
  'ReplicaBindingV1',
  'AuthorBindV1',
  'RepairAddV1',
  'ChargedProbeEvidenceV1',
  'RelayProbeEvidenceSetV1',
  'DiscoveryAvailabilityEntryV1',
  'DiscoveryIndexChildV1',
  'DiscoveryIndexBranchV1',
  'DiscoveryMembershipLeafV1',
  'DiscoveryAvailabilityLeafV1',
  'DiscoveryIndexNodeV1',
  'DiscoveryRecentBucketV1',
  'DiscoveryIndexProofV1',
  'MaintainerSubmitV1',
  'MaintainerSubmitResultV1',
  'MaintainerObservationV1',
  'MaintainerObservationReceiptV1',
  'MaintainerObservationHeadV1',
  'DiscoveryProposalV1',
  'DiscoverySnapshotV1',
  'DiscoveryCheckpointV1',
  'DiscoveryRecoveryParentV1',
  'DiscoveryRecoveryMergeV1',
  'MigrationGenesisV1',
  'LegacySourceCutoffV1',
  'LegacyCutoffV1',
  'LegacyArchiveDistributionV1',
  'LegacyValidRecordEntryV1',
  'LegacyInvalidRecordEntryV1',
  'LegacyMissingRangeEntryV1',
  'LegacyArchiveEntryV1',
  'LegacyArchiveIndexV1',
  'PeeritLegacyArchiveV1',
  'LegacyArchiveBundleV1',
  'LegacyRetirementEvidenceV1'
]))

function authorityState (authority) {
  const state = AUTHORITY_STATE.get(authority)
  if (state == null) failGraph('CONTEXTUAL_GRAPH_AUTHORITY_REQUIRED', 'a branded Peerit contextual-graph authority is required')
  return state
}

export function createPeeritContextualGraphAuditAuthorityV1 (options) {
  strictObject(options, 'contextual graph authority options')
  const requiredObjects = ['compiled', 'inventory', 'catalog', 'externalAuthorityByName']
  for (const field of requiredObjects) {
    if (options[field] == null || typeof options[field] !== 'object') failGraph('BAD_CONTEXTUAL_GRAPH_CONFIGURATION', `${field} is required`)
  }
  if (typeof options.sortProjection !== 'function' || typeof options.fetchByHash !== 'function') {
    failGraph('BAD_CONTEXTUAL_GRAPH_CONFIGURATION', 'sortProjection and fetchByHash functions are required')
  }
  supportingEvidenceState(options.supportingEvidenceAuthority)
  const state = Object.freeze({
    compiled: options.compiled,
    inventory: options.inventory,
    catalog: options.catalog,
    externalAuthorityByName: options.externalAuthorityByName,
    sortProjection: options.sortProjection,
    fetchByHash: options.fetchByHash,
    supportingEvidenceAuthority: options.supportingEvidenceAuthority,
    budgets: normalizeBudgets(options.budgets),
    productionTrusted: false
  })
  const authority = Object.freeze({
    authorityId: '@peerit/contextual-graph-audit-authority-v1',
    auditOnly: true,
    budgets: state.budgets,
    incompleteSchemas: Object.freeze([...INCOMPLETE_CONTEXTUAL_SCHEMAS].sort()),
    validateRecord (schemaName, value, bytes, context = {}) {
      const session = createSession(state, context)
      if (schemaName === 'PeeritHiveRelayProfilePinV1') return validatePinChain(state, session, value, bytes)
      if (schemaName === 'PeeritPinHistoryCheckpointV1') return validatePinHistoryCheckpoint(state, session, value, bytes)
      if (schemaName === 'PeeritPinHistoryBundleV1') return validatePinHistoryBundle(state, session, value)
      if (schemaName === 'PeeritCustodyEnvelopeV1') {
        if (context.custodianPrivateKeys == null) failGraph('CUSTODY_PRIVATE_KEYS_REQUIRED', 'custody envelope validation requires custodianPrivateKeys')
        return recoverCustodyEnvelope(state, bytes, context.custodianPrivateKeys, context)
      }
      if (schemaName === 'PeeritReleaseQualificationEvidenceBundleV1') return validateQualificationEvidenceBundle(state, session, value, bytes)
      if (schemaName === 'PeeritOperatorGroupRegistryV1') return validateOperatorGroupRegistry(state, session, value, bytes)
      if (schemaName === 'WebAssetManifestV1') return validateWebAssetManifestGraph(state, session, value, bytes, context)
      if (INCOMPLETE_CONTEXTUAL_SCHEMAS.has(schemaName)) {
        failGraph('CONTEXTUAL_GRAPH_RUNTIME_UNAVAILABLE', `${schemaName} still requires an unassembled external proof or traversal runtime`)
      }
      return Object.freeze({ schemaName, contextualReferences: 0, fetchedObjects: 0, fetchedBytes: 0 })
    },
    validatePinChain (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'profile pin')
      return validatePinChain(state, createSession(state, context), state.catalog.PeeritHiveRelayProfilePinV1.decode(snapshot), snapshot)
    },
    validatePinHistoryCheckpoint (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'pin history checkpoint')
      return validatePinHistoryCheckpoint(state, createSession(state, context), state.catalog.PeeritPinHistoryCheckpointV1.decode(snapshot), snapshot)
    },
    validatePinHistoryBundle (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'pin history bundle')
      return validatePinHistoryBundle(state, createSession(state, context), state.catalog.PeeritPinHistoryBundleV1.decode(snapshot))
    },
    validateOperatorGroupRegistry (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'operator group registry')
      return validateOperatorGroupRegistry(state, createSession(state, context), state.catalog.PeeritOperatorGroupRegistryV1.decode(snapshot), snapshot)
    },
    validateRootRotation (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'root rotation')
      return validateRootRotation(state, createSession(state, context), state.catalog.RootRotateV1.decode(snapshot))
    },
    validateDiscoveryThresholdRecord (schemaName, bytes, context = {}) {
      if (!['DiscoverySnapshotV1', 'DiscoveryCheckpointV1', 'RelayProbeEvidenceSetV1'].includes(schemaName)) {
        failGraph('CONTEXTUAL_SIGNATURE_RULE_MISSING', `${schemaName} is not threshold-signed`)
      }
      const snapshot = snapshotBytes(bytes, `${schemaName} bytes`)
      return validateDiscoveryThresholdRecord(state, createSession(state, context), schemaName, state.catalog[schemaName].decode(snapshot))
    },
    validateQualificationEvidenceBundle (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'qualification evidence bundle')
      return validateQualificationEvidenceBundle(state, createSession(state, context), state.catalog.PeeritReleaseQualificationEvidenceBundleV1.decode(snapshot), snapshot)
    },
    validateLegacyCutoffDeterministic (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'legacy cutoff')
      return validateLegacyCutoffDeterministic(state, createSession(state, context), state.catalog.LegacyCutoffV1.decode(snapshot), snapshot)
    },
    validateDeterministicLegacyArchiveBundle (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'legacy archive bundle')
      return validateDeterministicLegacyArchiveBundle(state, createSession(state, context), state.catalog.LegacyArchiveBundleV1.decode(snapshot), snapshot, context)
    },
    validateMigrationGenesisDeterministic (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'migration genesis')
      return validateMigrationGenesisDeterministic(state, createSession(state, context), state.catalog.MigrationGenesisV1.decode(snapshot), snapshot, context)
    },
    validateLegacyRetirementReferences (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'legacy retirement evidence')
      return validateLegacyRetirementReferences(state, createSession(state, context), state.catalog.LegacyRetirementEvidenceV1.decode(snapshot), snapshot, context)
    },
    validateWebAssetManifest (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'web asset manifest')
      return validateWebAssetManifestGraph(state, createSession(state, context), state.catalog.WebAssetManifestV1.decode(snapshot), snapshot, context)
    },
    recoverCustodyEnvelope (bytes, custodianPrivateKeys, context = {}) {
      return recoverCustodyEnvelope(state, bytes, custodianPrivateKeys, context)
    },
    validateAuthorSignatureChainAudit (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'author binding')
      return validateAuthorChain(state, createSession(state, context), state.catalog.AuthorBindV1.decode(snapshot), snapshot)
    },
    validateAuthorChain () {
      failGraph('CONTEXTUAL_GRAPH_RUNTIME_UNAVAILABLE',
        'AuthorBindV1 requires capability-bound Cell readback and operation authority before contextual acceptance')
    },
    validateObservationChain (bytes, context = {}) {
      const snapshot = snapshotBytes(bytes, 'maintainer observation')
      return validateObservationChain(state, createSession(state, context), state.catalog.MaintainerObservationV1.decode(snapshot), snapshot)
    }
  })
  AUTHORITY_STATE.set(authority, state)
  return authority
}

export function assertPeeritContextualGraphAuthorityV1 (authority, expected = {}) {
  const state = authorityState(authority)
  if ((expected.compiled != null && state.compiled !== expected.compiled) ||
      (expected.inventory != null && state.inventory !== expected.inventory) ||
      (expected.catalog != null && state.catalog !== expected.catalog) ||
      (expected.sortProjection != null && state.sortProjection !== expected.sortProjection)) {
    failGraph('CONTEXTUAL_GRAPH_AUTHORITY_MISMATCH', 'contextual graph authority was built for a different profile runtime')
  }
  if (expected.production === true && state.productionTrusted !== true) {
    failGraph('CONTEXTUAL_GRAPH_PRODUCTION_AUTHORITY_REQUIRED', 'public audit minters cannot produce a trusted production contextual-graph authority')
  }
  return authority
}

export const PEERIT_CONTEXTUAL_GRAPH_VALIDATOR_STATUS_V1 = Object.freeze({
  auditAuthorityReady: true,
  publicMinterProductionTrusted: false,
  fixedProductionAuthorityReady: false,
  boundedFetchSnapshotReady: true,
  exactContentHashSubstitutionRejectionReady: true,
  pinCheckpointAuthorObservationChainReady: true,
  authorSignatureChainAuditReady: true,
  releaseAuthorityTransitionReady: true,
  rootRecoveryThresholdCryptoReady: true,
  discoveryThresholdCryptoReady: true,
  operatorRegistryThresholdCryptoReady: true,
  qualificationEvidenceGraphReady: true,
  custodyReconstructionCryptoReady: true,
  deterministicCutoffArchiveGraphReady: true,
  deterministicMigrationGenesisGraphReady: true,
  retirementReferenceGraphReady: true,
  webAssetManifestGraphReady: true,
  runtimeUnavailableSchemaCount: INCOMPLETE_CONTEXTUAL_SCHEMAS.size,
  runtimeUnavailableSchemas: Object.freeze([...INCOMPLETE_CONTEXTUAL_SCHEMAS].sort()),
  signedValidatorBundleGraphAuthorityFactoryReady: false,
  browserHarnessCompleteGraphReady: false,
  legacyRecordAndRestoreAuthenticityReady: false,
  retirementRestoreEvidenceGraphReady: false,
  externalHiveRelayProofRuntimeReady: false,
  discoveryRadixReplayReady: false,
  legacyRecordValidatorReady: false,
  productionComplete: false
})
