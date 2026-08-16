#!/usr/bin/env node

// Offline-only signer for the Sequence-29 limited public INBOX bootstrap.
// The signing seed is accepted only as an in-memory option or from the
// dedicated environment variable. This module performs no network I/O.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify
} from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  canonicalPeeritLimitedPublicInboxJsonV1,
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1,
  PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  concatBytes,
  hexToBytes,
  u32Bytes,
  u64Bytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  loadPeeritSeq29AcceptedHiveRelayOperatorV1
} from './lib/seq29-accepted-hiverelay-operator.mjs'

const {
  decodeBlindExternalProfileValueV1
} = (await loadPeeritSeq29AcceptedHiveRelayOperatorV1()).control

export const PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1 =
  'peerit-limited-public-inbox-signing-package-v1'
export const PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1 =
  'PEERIT_SEQ29_LIMITED_PUBLIC_INBOX_BOOTSTRAP_AUTHORITY_SEED'
export const PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1 =
  'adeacef07c5de4d17d5ed1389fee7a35095b862f'

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const HEX32 = /^[0-9a-f]{64}$/
const HEX64 = /^[0-9a-f]{128}$/
const DECIMAL_U64 = /^(0|[1-9][0-9]{0,19})$/
const PAYLOAD_FIELDS = Object.freeze([
  'schema', 'version', 'artifactClass', 'claimBoundary', 'operatorBoundary',
  'topicScope', 'profileId', 'releaseSequence', 'bootstrapSequence',
  'previousBootstrapHash', 'issuedUnixMillis', 'expiresUnixMillis',
  'authorityPublicKey', 'relays', 'inboxEpochSets'
])
const RELAY_FIELDS = Object.freeze([
  'relayId', 'canonicalDescribeUrl', 'relayPublicKey', 'storeId',
  'durabilityContinuityHash', 'descriptorFloor'
])
const EPOCH_SET_FIELDS = Object.freeze([
  'inboxEpoch', 'stripeCountLog2', 'stripeSelectionKey',
  'announcementMasterKey', 'bindings'
])
const BINDING_FIELDS = Object.freeze([
  'inboxEpoch', 'stripeIndex', 'relayId', 'relayPublicKey', 'allocationEpoch',
  'createPublicKey', 'physicalTopic', 'frameClassBits', 'appendAuthMode',
  'retentionClass', 'leaseClass', 'createReceiptCanonicalHex'
])
const CREATE_REQUEST_FIELDS = Object.freeze([
  'relayId', 'allocationEpoch', 'physicalTopic', 'frameClassBits',
  'appendAuthMode', 'createPublicKey', 'appendPublicKey', 'renewPublicKey',
  'closePublicKey', 'retentionClass', 'leaseClass', 'clientNonce',
  'createCommitment', 'requestCommitment'
])
const RECEIPT_FIELDS = Object.freeze([
  'version', 'relayBinding', 'topicCommitment', 'stateRevision', 'leaseClass',
  'leaseEpoch', 'requestNonce', 'requestCommitment', 'result', 'signature'
])
const RECEIPT_RELAY_BINDING_FIELDS = Object.freeze([
  'version', 'relayPublicKey', 'storeId', 'descriptorSequence',
  'descriptorHash', 'durabilityProfileId', 'durabilityContinuityHash',
  'durabilityProfileHash', 'restoreEvidenceHeadSequence',
  'restoreEvidenceHeadHash', 'externalCommitWitness'
])

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      `${field} fields are missing or unexpected`)
  }
  return value
}

function noPrivateMaterial (value, path = []) {
  if (value == null || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const lower = key.toLowerCase()
    if (lower.includes('privateseed') || lower.includes('privatekey') ||
        lower === 'secretseed' || lower.includes('managementseed') ||
        lower.includes('managementkey') || lower.includes('appendseed') ||
        lower.includes('renewseed') || lower.includes('closeseed') ||
        lower.includes('createseed') || lower.includes('capabilityseed')) {
      fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_SECRET',
        `signing package carries forbidden private material at ${[...path, key].join('.')}`)
    }
    noPrivateMaterial(child, [...path, key])
  }
}

function deepFreeze (value) {
  if (value == null || typeof value !== 'object' || Object.isFrozen(value) ||
      ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function canonicalDecimal (value, field) {
  if (typeof value !== 'string' || !DECIMAL_U64.test(value) ||
      BigInt(value) > ((1n << 64n) - 1n)) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      `${field} is not canonical u64 decimal`)
  }
  return BigInt(value)
}

function exactHex (value, pattern, field) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      `${field} is not canonical lowercase hexadecimal`)
  }
  return value
}

function exactU32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID', `${field} is outside u32`)
  }
  return value
}

function canonicalHttpsUrl (value, field) {
  if (typeof value !== 'string') {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID', `${field} must be a URL`)
  }
  const match = /^https:\/\/([a-z0-9.-]+):([0-9]+)(\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)$/.exec(value)
  if (!match) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      `${field} must be canonical HTTPS with an explicit port`)
  }
  const port = Number(match[2])
  let parsed
  try { parsed = new URL(value) } catch {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID', `${field} is invalid`)
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535 ||
      parsed.protocol !== 'https:' || parsed.hostname !== match[1] ||
      parsed.username || parsed.password || parsed.search || parsed.hash ||
      parsed.pathname !== match[3] || value.includes('/./') || value.includes('/../') ||
      value.includes('//', 8)) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID', `${field} is not canonical`)
  }
}

function unique (values, field) {
  if (new Set(values).size !== values.length) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID', `${field} contains duplicates`)
  }
}

function exactBytes (value, length, field) {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      `${field} must be exactly ${length} bytes`)
  }
  return value
}

function nonzeroBytes (value, length, field) {
  exactBytes(value, length, field)
  if (value.every(byte => byte === 0)) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      `${field} must not be all-zero`)
  }
  return value
}

function assertCreateReceipt (binding, relay, requestEvidence, allowFixture) {
  if (typeof binding.createReceiptCanonicalHex !== 'string' ||
      !/^[0-9a-f]+$/.test(binding.createReceiptCanonicalHex) ||
      binding.createReceiptCanonicalHex.length % 2 !== 0 ||
      binding.createReceiptCanonicalHex.length > 32768) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'createReceiptCanonicalHex is not bounded canonical hexadecimal')
  }
  const receiptBytes = hexToBytes(
    binding.createReceiptCanonicalHex, undefined, 'createReceiptCanonicalHex')
  if (receiptBytes.byteLength <= 64) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'CREATE receipt is too short to carry an authenticated result')
  }
  let receipt
  try {
    receipt = decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes)
  } catch (cause) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      `CREATE receipt is not canonical InboxReceiptV1: ${cause.message}`)
  }
  exact(receipt, RECEIPT_FIELDS, 'decoded CREATE receipt')
  exact(receipt.relayBinding, RECEIPT_RELAY_BINDING_FIELDS,
    'decoded CREATE receipt relay binding')
  const unsigned = receiptBytes.subarray(0, receiptBytes.byteLength - 64)
  const signature = exactBytes(receipt.signature, 64, 'CREATE receipt signature')
  const signatureMessage = concatBytes(
    asciiBytes('hiverelay.blind.inbox-receipt.v1'),
    u64Bytes(unsigned.byteLength),
    unsigned
  )
  if (!nodeVerify(null, Buffer.from(signatureMessage),
    publicKeyForHex(relay.relayPublicKey), Buffer.from(signature))) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'CREATE receipt relay signature is invalid')
  }
  const relayBinding = receipt.relayBinding
  if (receipt.version !== 1 || relayBinding.version !== 1 || receipt.result !== 1 ||
      receipt.stateRevision !== 0n || receipt.leaseClass !== 4 ||
      !Number.isSafeInteger(receipt.leaseEpoch) ||
      receipt.leaseEpoch < binding.allocationEpoch ||
      receipt.leaseEpoch >= binding.allocationEpoch + 1460 ||
      !bytesEqual(exactBytes(relayBinding.relayPublicKey, 32, 'receipt relayPublicKey'),
        hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey')) ||
      !bytesEqual(exactBytes(relayBinding.storeId, 32, 'receipt storeId'),
        hexToBytes(relay.storeId, 32, 'storeId')) ||
      !bytesEqual(exactBytes(relayBinding.durabilityContinuityHash, 32,
        'receipt durabilityContinuityHash'),
      hexToBytes(relay.durabilityContinuityHash, 32, 'durabilityContinuityHash')) ||
      String(relayBinding.descriptorSequence) !== relay.descriptorFloor.sequence ||
      !bytesEqual(exactBytes(relayBinding.descriptorHash, 32, 'receipt descriptorHash'),
        hexToBytes(relay.descriptorFloor.hash, 32, 'descriptorFloor.hash')) ||
      !bytesEqual(exactBytes(receipt.topicCommitment, 32, 'receipt topicCommitment'),
        blake2b256(hexToBytes(binding.physicalTopic, 32, 'physicalTopic')))) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'CREATE receipt does not bind the exact relay, floor, topic and CREATE result')
  }
  nonzeroBytes(receipt.requestNonce, 32, 'CREATE receipt requestNonce')
  nonzeroBytes(receipt.requestCommitment, 32, 'CREATE receipt requestCommitment')
  if (requestEvidence == null) return
  exact(requestEvidence, CREATE_REQUEST_FIELDS, `CREATE request ${binding.relayId}`)
  if (requestEvidence.relayId !== binding.relayId ||
      requestEvidence.allocationEpoch !== binding.allocationEpoch ||
      requestEvidence.physicalTopic !== binding.physicalTopic ||
      requestEvidence.frameClassBits !== 3 || requestEvidence.appendAuthMode !== 0 ||
      requestEvidence.createPublicKey !== binding.createPublicKey ||
      requestEvidence.appendPublicKey !== null ||
      requestEvidence.retentionClass !== 3 || requestEvidence.leaseClass !== 4) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'CREATE request evidence differs from the advertised OPEN_APPEND binding')
  }
  for (const field of [
    'renewPublicKey', 'closePublicKey', 'clientNonce',
    'createCommitment', 'requestCommitment'
  ]) exactHex(requestEvidence[field], HEX32, `CREATE request ${field}`)
  const createCommitment = blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.inbox-create.v1'),
    hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey'),
    hexToBytes(requestEvidence.physicalTopic, 32, 'physicalTopic'),
    u32Bytes(requestEvidence.allocationEpoch),
    Uint8Array.of(3, 0),
    new Uint8Array(32),
    hexToBytes(requestEvidence.createPublicKey, 32, 'createPublicKey'),
    hexToBytes(requestEvidence.renewPublicKey, 32, 'renewPublicKey'),
    hexToBytes(requestEvidence.closePublicKey, 32, 'closePublicKey'),
    Uint8Array.of(3, 4)
  ))
  const requestCommitment = blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.request.v1inbox-create'),
    createCommitment,
    hexToBytes(requestEvidence.clientNonce, 32, 'clientNonce')
  ))
  if (allowFixture !== true &&
      (!bytesEqual(createCommitment,
        hexToBytes(requestEvidence.createCommitment, 32, 'createCommitment')) ||
      !bytesEqual(requestCommitment,
        hexToBytes(requestEvidence.requestCommitment, 32, 'requestCommitment')) ||
      !bytesEqual(receipt.requestNonce,
        hexToBytes(requestEvidence.clientNonce, 32, 'clientNonce')) ||
      !bytesEqual(receipt.requestCommitment, requestCommitment))) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'CREATE receipt is not bound to the exact canonical CREATE request')
  }
}

function assertPayloadShape (payload, allowFixture, createRequests) {
  exact(payload, PAYLOAD_FIELDS, 'bootstrap payload')
  if (payload.schema !== 'peerit-limited-public-inbox-bootstrap-v1' ||
      payload.version !== 1 ||
      payload.claimBoundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
      payload.operatorBoundary !==
        'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS' ||
      payload.topicScope !== 'GLOBAL_PUBLIC_DISCOVERY' ||
      payload.profileId !== '@peerit/hiverelay-profile-v1' ||
      payload.releaseSequence !== PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      'bootstrap payload contract identity is invalid')
  }
  if (payload.artifactClass !== 'LIMITED_PUBLIC_TEST_RELEASE' &&
      !(allowFixture === true && payload.artifactClass === 'FIXTURE_ONLY')) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_ARTIFACT_CLASS',
      'offline signer accepts only LIMITED_PUBLIC_TEST_RELEASE')
  }
  const sequence = canonicalDecimal(payload.bootstrapSequence, 'bootstrapSequence')
  if ((sequence === 0n) !== (payload.previousBootstrapHash === null)) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      'bootstrap predecessor presence does not match its sequence')
  }
  if (payload.previousBootstrapHash !== null) {
    exactHex(payload.previousBootstrapHash, HEX32, 'previousBootstrapHash')
  }
  const issued = canonicalDecimal(payload.issuedUnixMillis, 'issuedUnixMillis')
  const expires = canonicalDecimal(payload.expiresUnixMillis, 'expiresUnixMillis')
  if (expires <= issued || expires - issued > 2678400000n) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      'bootstrap lifetime must be positive and at most 31 days')
  }
  exactHex(payload.authorityPublicKey, HEX32, 'authorityPublicKey')
  if (!Array.isArray(payload.relays) || payload.relays.length !== 2 ||
      !Array.isArray(payload.inboxEpochSets) || payload.inboxEpochSets.length !== 1) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      'bootstrap must contain exactly two relays and one current epoch set')
  }
  const relayById = new Map()
  for (const [index, relay] of payload.relays.entries()) {
    exact(relay, RELAY_FIELDS, `relays[${index}]`)
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(relay.relayId)) {
      fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID', `relays[${index}].relayId is invalid`)
    }
    canonicalHttpsUrl(relay.canonicalDescribeUrl, `relays[${index}].canonicalDescribeUrl`)
    for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash']) {
      exactHex(relay[field], HEX32, `relays[${index}].${field}`)
    }
    exact(relay.descriptorFloor, ['sequence', 'hash'], `relays[${index}].descriptorFloor`)
    canonicalDecimal(relay.descriptorFloor.sequence, `relays[${index}].descriptorFloor.sequence`)
    exactHex(relay.descriptorFloor.hash, HEX32, `relays[${index}].descriptorFloor.hash`)
    relayById.set(relay.relayId, relay)
  }
  for (const field of ['relayId', 'relayPublicKey', 'storeId']) {
    unique(payload.relays.map(relay => relay[field]), `relay ${field}`)
  }
  const set = exact(payload.inboxEpochSets[0], EPOCH_SET_FIELDS, 'inboxEpochSets[0]')
  exactU32(set.inboxEpoch, 'inboxEpochSets[0].inboxEpoch')
  exactHex(set.stripeSelectionKey, HEX32, 'stripeSelectionKey')
  exactHex(set.announcementMasterKey, HEX32, 'announcementMasterKey')
  const effectiveLeaseEpoch = Number(issued / 21600000n)
  if (set.inboxEpoch !== Math.floor(effectiveLeaseEpoch / 28) ||
      set.stripeCountLog2 !== 0 || !Array.isArray(set.bindings) ||
      set.bindings.length !== 2) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      'bootstrap does not carry the exact two-topic OPEN_APPEND shape')
  }
  if (createRequests != null &&
      (!Array.isArray(createRequests) || createRequests.length !== 2)) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'exactly two canonical CREATE request evidence rows are required')
  }
  if (createRequests != null) {
    unique(createRequests.map(row => row?.relayId), 'CREATE request relayId')
  }
  for (const [index, binding] of set.bindings.entries()) {
    exact(binding, BINDING_FIELDS, `bindings[${index}]`)
    const relay = relayById.get(binding.relayId)
    if (!relay || binding.relayPublicKey !== relay.relayPublicKey ||
        binding.inboxEpoch !== set.inboxEpoch || binding.stripeIndex !== 0 ||
        binding.frameClassBits !== 3 || binding.appendAuthMode !== 0 ||
        binding.retentionClass !== 3 || binding.leaseClass !== 4) {
      fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
        `bindings[${index}] does not match the exact relay OPEN_APPEND shape`)
    }
    exactU32(binding.allocationEpoch, `bindings[${index}].allocationEpoch`)
    exactHex(binding.createPublicKey, HEX32, `bindings[${index}].createPublicKey`)
    exactHex(binding.physicalTopic, HEX32, `bindings[${index}].physicalTopic`)
    if (binding.allocationEpoch > effectiveLeaseEpoch + 1 ||
        effectiveLeaseEpoch >= binding.allocationEpoch + 1460) {
      fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
        `bindings[${index}].allocationEpoch is outside the accepted window`)
    }
    const expectedTopic = blake2b256(concatBytes(
      asciiBytes('hiverelay.blind.inbox-topic.v1'),
      u32Bytes(binding.allocationEpoch),
      hexToBytes(binding.createPublicKey, 32, 'createPublicKey')
    ))
    if (!bytesEqual(expectedTopic, hexToBytes(binding.physicalTopic, 32, 'physicalTopic'))) {
      fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
        `bindings[${index}].physicalTopic is not self-certifying`)
    }
    const requestEvidence = createRequests == null
      ? null
      : createRequests.find(row => row?.relayId === binding.relayId)
    assertCreateReceipt(binding, relay, requestEvidence, allowFixture)
  }
  unique(set.bindings.map(binding => binding.relayId), 'binding relayId')
  unique(set.bindings.map(binding => binding.physicalTopic), 'binding physicalTopic')
}

function canonicalPrettyBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8')
}

function parseCanonicalJson (bytes, field) {
  let value
  const source = Buffer.from(bytes).toString('utf8')
  try { value = JSON.parse(source) } catch {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID', `${field} is not JSON`)
  }
  if (!canonicalPrettyBytes(value).equals(Buffer.from(bytes))) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_NONCANONICAL',
      `${field} is not canonical pretty JSON with one trailing newline`)
  }
  return value
}

export function validatePeeritLimitedPublicInboxSigningPackageV1 (input, options = {}) {
  const value = input instanceof Uint8Array || Buffer.isBuffer(input)
    ? parseCanonicalJson(input, 'signing package')
    : structuredClone(input)
  exact(value, [
    'schema', 'version', 'offlineOnly', 'hiverelayCommit', 'createRequests', 'payload'
  ],
  'signing package')
  if (value.schema !== PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1 ||
      value.version !== 1 || value.offlineOnly !== true ||
      value.hiverelayCommit !== PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID',
      'signing package identity or offline boundary is invalid')
  }
  noPrivateMaterial(value)
  if (!Array.isArray(value.createRequests) || value.createRequests.length !== 2) {
    fail('PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
      'signing package requires exactly two CREATE request evidence rows')
  }
  assertPayloadShape(value.payload, options.allowFixture, value.createRequests)
  return deepFreeze({
    schema: value.schema,
    version: 1,
    offlineOnly: true,
    hiverelayCommit: value.hiverelayCommit,
    createRequests: structuredClone(value.createRequests),
    payload: structuredClone(value.payload),
    canonicalBytes: canonicalPrettyBytes(value)
  })
}

function publicKeyForHex (value) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(exactHex(value, HEX32, 'authorityPublicKey'), 'hex')
    ]),
    format: 'der',
    type: 'spki'
  })
}

export function validatePeeritLimitedPublicInboxSignedWrapperV1 (input, options = {}) {
  const value = input instanceof Uint8Array || Buffer.isBuffer(input)
    ? parseCanonicalJson(input, 'signed wrapper')
    : structuredClone(input)
  noPrivateMaterial(value)
  exact(value, ['payload', 'signature'], 'signed wrapper')
  assertPayloadShape(value.payload, options.allowFixture, options.createRequests || null)
  const signature = Buffer.from(exactHex(value.signature, HEX64, 'signature'), 'hex')
  const message = peeritLimitedPublicInboxSigningMessageV1(value.payload)
  if (!nodeVerify(null, Buffer.from(message), publicKeyForHex(value.payload.authorityPublicKey), signature)) {
    fail('PEERIT_LIMITED_INBOX_SIGNER_SELF_VERIFY_FAILED',
      'signed wrapper signature is invalid')
  }
  return deepFreeze({
    payload: structuredClone(value.payload),
    signature: value.signature,
    canonicalBytes: canonicalPrettyBytes(value)
  })
}

// The protocol bootstrap identity is the SHA-256 of the recursively
// key-sorted compact canonical complete signed wrapper.  It is intentionally
// distinct from the SHA-256 of the pretty-JSON release file: the former binds
// bootstrap floors, predecessor continuity, management custody and bounded
// publication, while the latter is an ordinary release-artifact file digest.
export function hashPeeritLimitedPublicInboxSignedWrapperV1 (input, options = {}) {
  const verified = validatePeeritLimitedPublicInboxSignedWrapperV1(input, options)
  return createHash('sha256').update(
    canonicalPeeritLimitedPublicInboxJsonV1({
      payload: verified.payload,
      signature: verified.signature
    })
  ).digest('hex')
}

export function peeritLimitedPublicInboxSigningMessageV1 (payload) {
  return concatBytes(
    asciiBytes(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1),
    Uint8Array.of(0),
    canonicalPeeritLimitedPublicInboxJsonV1(payload)
  )
}

function privateKeyForSeed (seedHex) {
  const seed = Buffer.from(exactHex(seedHex, HEX32, 'signing seed'), 'hex')
  const der = Buffer.concat([PKCS8_PREFIX, seed])
  try {
    return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  } finally {
    seed.fill(0)
    der.fill(0)
  }
}

export function signPeeritLimitedPublicInboxBootstrapV1 (input = {}) {
  const checked = validatePeeritLimitedPublicInboxSigningPackageV1(
    input.signingPackage, { allowFixture: input.allowFixture })
  const seedHex = input.seedHex == null
    ? String(input.environment?.[PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1] || '').trim()
    : String(input.seedHex).trim()
  if (!seedHex) {
    fail('PEERIT_LIMITED_INBOX_SIGNER_REQUIRED',
      `${PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1} is required`)
  }
  const privateKey = privateKeyForSeed(seedHex)
  const publicKey = createPublicKey(privateKey)
  const publicKeyHex = publicKey.export({ format: 'der', type: 'spki' })
    .subarray(-32).toString('hex')
  if (publicKeyHex !== checked.payload.authorityPublicKey) {
    fail('PEERIT_LIMITED_INBOX_SIGNER_KEY_MISMATCH',
      'signing seed does not derive the payload authorityPublicKey')
  }
  const message = peeritLimitedPublicInboxSigningMessageV1(checked.payload)
  const signature = nodeSign(null, Buffer.from(message), privateKey)
  if (signature.byteLength !== 64 ||
      !nodeVerify(null, Buffer.from(message), publicKey, signature)) {
    fail('PEERIT_LIMITED_INBOX_SIGNER_SELF_VERIFY_FAILED',
      'offline signature did not immediately self-verify')
  }
  const wrapper = {
    payload: checked.payload,
    signature: signature.toString('hex')
  }
  const verifiedWrapper = validatePeeritLimitedPublicInboxSignedWrapperV1(wrapper, {
    allowFixture: input.allowFixture,
    createRequests: checked.createRequests
  })
  return Object.freeze({
    wrapper: deepFreeze({
      payload: structuredClone(verifiedWrapper.payload),
      signature: verifiedWrapper.signature
    }),
    canonicalBytes: verifiedWrapper.canonicalBytes,
    signedBootstrapHash: hashPeeritLimitedPublicInboxSignedWrapperV1(
      verifiedWrapper.canonicalBytes, {
        allowFixture: input.allowFixture,
        createRequests: checked.createRequests
      }),
    authorityPublicKey: publicKeyHex,
    selfVerified: true,
    networkRequests: 0
  })
}

function arg (name) {
  const index = process.argv.indexOf(name)
  return index >= 0 ? process.argv[index + 1] : null
}

function main () {
  const inputPath = arg('--input')
  const outputPath = arg('--out')
  if (!inputPath || !outputPath) {
    fail('PEERIT_LIMITED_INBOX_SIGNER_USAGE',
      'usage: sign-limited-public-inbox-bootstrap.mjs --input <package.json> --out <bootstrap.json>')
  }
  const result = signPeeritLimitedPublicInboxBootstrapV1({
    signingPackage: readFileSync(resolve(inputPath)),
    environment: process.env
  })
  writeFileSync(resolve(outputPath), result.canonicalBytes, { flag: 'wx', mode: 0o600 })
  console.log(JSON.stringify({
    status: 'SIGNED_OFFLINE',
    authorityPublicKey: result.authorityPublicKey,
    selfVerified: true,
    networkRequests: 0
  }))
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { main() } catch (error) {
    console.error(`${error.code || 'PEERIT_LIMITED_INBOX_SIGNER_FAILED'}: ${error.message}`)
    process.exitCode = 1
  }
}
