// Sequence-29 global public INBOX bootstrap authority. Topics are created only
// by the offline release ceremony. Browser publishers and lurkers receive two
// public OPEN_APPEND capabilities and can only APPEND or READ.
import { hashBytes, verifyBytes } from '../crypto.js'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  concatBytes,
  hexToBytes,
  u32Bytes,
  u64Bytes,
  utf8Bytes
} from './release-control-primitives.mjs'

export const PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1 =
  '/peerit-limited-public-inbox-bootstrap-v1.json'
export const PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1 =
  'peerit.limited-public-test.inbox-bootstrap.v1'
export const PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1 = 29
export const PEERIT_LIMITED_PUBLIC_INBOX_FRAME_CLASS_BITS_V1 = 3
export const PEERIT_LIMITED_PUBLIC_INBOX_APPEND_AUTH_MODE_V1 = 0
export const PEERIT_LIMITED_PUBLIC_INBOX_RETENTION_CLASS_V1 = 3
export const PEERIT_LIMITED_PUBLIC_INBOX_LEASE_CLASS_V1 = 4
export const PEERIT_LIMITED_PUBLIC_INBOX_MAX_LIFETIME_MILLIS_V1 = 2678400000n
export const PEERIT_LIMITED_PUBLIC_INBOX_LEASE_EPOCH_MILLIS_V1 = 21600000n

const HEX32 = /^[0-9a-f]{64}$/
const HEX64 = /^[0-9a-f]{128}$/
const DECIMAL_U64 = /^(0|[1-9][0-9]{0,19})$/
const MAX_U64 = (1n << 64n) - 1n
const VERIFIED = new WeakMap()
const FORBIDDEN_LIFECYCLE_EXPORTS = Object.freeze([
  'createInboxReplica',
  'createWatchInboxRequest',
  'createRenewInboxRequest',
  'createCloseInboxRequest',
  'destroyInboxWriteCapability'
])

function fail (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', `${field} fields are missing or unexpected`)
  }
  return value
}

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}

export function canonicalPeeritLimitedPublicInboxJsonV1 (value) {
  return utf8Bytes(stable(value), 'limited public INBOX canonical JSON')
}

function decimal (value, field) {
  if (typeof value !== 'string' || !DECIMAL_U64.test(value)) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', `${field} is not canonical u64 decimal`)
  }
  const parsed = BigInt(value)
  if (parsed > MAX_U64) fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', `${field} exceeds u64`)
  return parsed
}

function hex (value, length, field) {
  const pattern = length === 32 ? HEX32 : length === 64 ? HEX64 : /^[0-9a-f]+$/
  if (typeof value !== 'string' || !pattern.test(value) || value.length % 2 !== 0) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', `${field} is not canonical lowercase hex`)
  }
  return length == null
    ? hexToBytes(value, undefined, field)
    : hexToBytes(value, length, field)
}

function unique (values, field) {
  if (new Set(values).size !== values.length) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', `${field} contains duplicates`)
  }
}

function noPrivateManagementMaterial (value, path = []) {
  if (value == null || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const lower = key.toLowerCase()
    if (lower.includes('privateseed') || lower.includes('privatekey') || lower === 'secretseed' ||
        lower === 'managementkeyderivation' || lower === 'deterministicpublicinputderivation') {
      fail('PEERIT_LIMITED_INBOX_PRIVATE_MANAGEMENT_MATERIAL',
        `public bootstrap carries forbidden management material at ${[...path, key].join('.')}`)
    }
    noPrivateManagementMaterial(child, [...path, key])
  }
}

function canonicalHttpsUrl (value) {
  if (typeof value !== 'string' ||
      !/^https:\/\/[a-z0-9.-]+:[1-9][0-9]{0,4}\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(value)) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'relay describe URL is not canonical HTTPS with an explicit port')
  }
  const port = Number(/^https:\/\/[^/]+:([0-9]+)\//.exec(value)[1])
  if (port > 65535 || value.includes('/./') || value.includes('/../') || value.includes('//', 8)) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'relay describe URL has an invalid port or path')
  }
}

function readCap (binding) {
  const relayPublicKey = hex(binding.relayPublicKey, 32, 'binding relayPublicKey')
  const physicalTopic = hex(binding.physicalTopic, 32, 'binding physicalTopic')
  // A non-empty TypedArray cannot be made element-immutable with
  // Object.freeze. Keep the signed route bytes closure-private and expose a
  // fresh defensive copy on every read; freezing the cap then prevents either
  // accessor replacement or scalar-field mutation.
  return Object.freeze({
    get relayPublicKey () { return relayPublicKey.slice() },
    get physicalTopic () { return physicalTopic.slice() },
    frameClassBits: PEERIT_LIMITED_PUBLIC_INBOX_FRAME_CLASS_BITS_V1,
    appendAuthMode: PEERIT_LIMITED_PUBLIC_INBOX_APPEND_AUTH_MODE_V1,
    appendPublicKey: null
  })
}

function immutableBinding (binding, relay) {
  const cap = readCap(binding)
  const storeId = hex(relay.storeId, 32, 'relay storeId')
  const durabilityContinuityHash = hex(
    relay.durabilityContinuityHash, 32, 'relay durabilityContinuityHash')
  const descriptorFloorHash = hex(
    relay.descriptorFloor.hash, 32, 'descriptor floor hash')
  const createPublicKey = hex(binding.createPublicKey, 32, 'binding createPublicKey')
  return Object.freeze({
    inboxEpoch: binding.inboxEpoch,
    stripeIndex: 0,
    relayId: binding.relayId,
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    allocationEpoch: binding.allocationEpoch,
    get createPublicKey () { return createPublicKey.slice() },
    readCap: cap,
    descriptorFloorSequence: decimal(
      relay.descriptorFloor.sequence, 'descriptor floor sequence'),
    get relayPublicKey () { return cap.relayPublicKey },
    get physicalTopic () { return cap.physicalTopic },
    get storeId () { return storeId.slice() },
    get durabilityContinuityHash () { return durabilityContinuityHash.slice() },
    get descriptorFloorHash () { return descriptorFloorHash.slice() }
  })
}

export function assertPeeritSeq29PublicBrowserControlV1 (control) {
  for (const name of [
    'createAppendInboxRequest', 'createReadInboxRequest', 'createGetCellRequest',
    'openVerifiedCellGetResult', 'verifyOperationResult', 'decodeBlindExternalProfileValueV1'
  ]) {
    if (typeof control?.[name] !== 'function') {
      fail('PEERIT_LIMITED_INBOX_BROWSER_CONTROL_INVALID', `browser control lacks ${name}`)
    }
  }
  for (const name of FORBIDDEN_LIFECYCLE_EXPORTS) {
    if (name in control) {
      fail('PEERIT_LIMITED_INBOX_BROWSER_CREATE_FORBIDDEN',
        `public browser control exposes forbidden INBOX lifecycle constructor ${name}`)
    }
  }
  return control
}

async function verifyReceipt (control, binding, relay) {
  const receiptBytes = hex(binding.createReceiptCanonicalHex, null, 'create receipt')
  let receipt
  try { receipt = control.decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes) } catch (cause) {
    fail('PEERIT_LIMITED_INBOX_RECEIPT_INVALID', 'create receipt is not canonical', cause)
  }
  const unsigned = receiptBytes.subarray(0, receiptBytes.byteLength - 64)
  const signature = receiptBytes.subarray(receiptBytes.byteLength - 64)
  const signatureMessage = concatBytes(
    asciiBytes('hiverelay.blind.inbox-receipt.v1'), u64Bytes(unsigned.byteLength), unsigned)
  if (!await verifyBytes(bytesToHex(receipt.relayBinding.relayPublicKey), signatureMessage, signature)) {
    fail('PEERIT_LIMITED_INBOX_RECEIPT_SIGNATURE_INVALID', 'create receipt relay signature is invalid')
  }
  const topic = hex(binding.physicalTopic, 32, 'binding physicalTopic')
  if (!bytesEqual(receipt.relayBinding.relayPublicKey, hex(relay.relayPublicKey, 32, 'relay publicKey')) ||
      !bytesEqual(receipt.relayBinding.storeId, hex(relay.storeId, 32, 'relay storeId')) ||
      !bytesEqual(receipt.relayBinding.durabilityContinuityHash,
        hex(relay.durabilityContinuityHash, 32, 'relay durabilityContinuityHash')) ||
      String(receipt.relayBinding.descriptorSequence) !== relay.descriptorFloor.sequence ||
      !bytesEqual(receipt.relayBinding.descriptorHash, hex(relay.descriptorFloor.hash, 32, 'descriptor floor hash')) ||
      !bytesEqual(receipt.topicCommitment, blake2b256(topic)) || String(receipt.stateRevision) !== '0' ||
      receipt.leaseClass !== 4 || receipt.result !== 1) {
    fail('PEERIT_LIMITED_INBOX_RECEIPT_BINDING_INVALID', 'create receipt does not bind the advertised topic and relay floor')
  }
}

export async function verifyPeeritLimitedPublicInboxBootstrapV1 (input = {}) {
  const wrapper = input.wrapper
  const control = assertPeeritSeq29PublicBrowserControlV1(input.control)
  const referenceUnixMillis = typeof input.referenceUnixMillis === 'bigint'
    ? input.referenceUnixMillis
    : BigInt(input.referenceUnixMillis == null ? Date.now() : input.referenceUnixMillis)
  noPrivateManagementMaterial(wrapper)
  exact(wrapper, ['payload', 'signature'], 'bootstrap wrapper')
  const payload = exact(wrapper.payload, [
    'schema', 'version', 'artifactClass', 'claimBoundary', 'operatorBoundary', 'topicScope', 'profileId',
    'releaseSequence', 'bootstrapSequence', 'previousBootstrapHash', 'issuedUnixMillis', 'expiresUnixMillis',
    'authorityPublicKey', 'relays', 'inboxEpochSets'
  ], 'bootstrap payload')
  if (payload.schema !== 'peerit-limited-public-inbox-bootstrap-v1' || payload.version !== 1 ||
      payload.claimBoundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
      payload.operatorBoundary !== 'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS' ||
      payload.topicScope !== 'GLOBAL_PUBLIC_DISCOVERY' || payload.profileId !== '@peerit/hiverelay-profile-v1' ||
      payload.releaseSequence !== PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'bootstrap contract identity is invalid')
  }
  if (payload.artifactClass !== 'LIMITED_PUBLIC_TEST_RELEASE' &&
      !(input.allowFixture === true && payload.artifactClass === 'FIXTURE_ONLY')) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_FIXTURE_FORBIDDEN', 'runtime bootstrap is not a limited public test release')
  }
  const sequence = decimal(payload.bootstrapSequence, 'bootstrapSequence')
  if ((sequence === 0n) !== (payload.previousBootstrapHash === null)) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'bootstrap predecessor presence does not match sequence')
  }
  if (payload.previousBootstrapHash !== null) hex(payload.previousBootstrapHash, 32, 'previousBootstrapHash')
  const issued = decimal(payload.issuedUnixMillis, 'issuedUnixMillis')
  const expires = decimal(payload.expiresUnixMillis, 'expiresUnixMillis')
  if (expires <= issued || expires - issued > PEERIT_LIMITED_PUBLIC_INBOX_MAX_LIFETIME_MILLIS_V1 ||
      referenceUnixMillis < issued || referenceUnixMillis >= expires) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_TIME_INVALID', 'trusted local time is outside the bounded bootstrap lifetime')
  }
  const authorityPublicKey = hex(payload.authorityPublicKey, 32, 'authorityPublicKey')
  if (input.expectedAuthorityPublicKey != null &&
      !bytesEqual(authorityPublicKey, hex(input.expectedAuthorityPublicKey, 32, 'expectedAuthorityPublicKey'))) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_AUTHORITY_INVALID', 'bootstrap authority key differs from the release binding')
  }
  const signature = hex(wrapper.signature, 64, 'bootstrap signature')
  const signingPayload = concatBytes(
    asciiBytes(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1), Uint8Array.of(0),
    canonicalPeeritLimitedPublicInboxJsonV1(payload))
  if (!await verifyBytes(bytesToHex(authorityPublicKey), signingPayload, signature)) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_SIGNATURE_INVALID', 'bootstrap signature is invalid')
  }
  if (!Array.isArray(payload.relays) || payload.relays.length !== 2) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'bootstrap must name exactly two relays')
  }
  const relayById = new Map()
  for (const relay of payload.relays) {
    exact(relay, ['relayId', 'canonicalDescribeUrl', 'relayPublicKey', 'storeId', 'durabilityContinuityHash', 'descriptorFloor'], 'relay')
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(relay.relayId)) fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'relayId is invalid')
    canonicalHttpsUrl(relay.canonicalDescribeUrl)
    hex(relay.relayPublicKey, 32, 'relayPublicKey')
    hex(relay.storeId, 32, 'storeId')
    hex(relay.durabilityContinuityHash, 32, 'durabilityContinuityHash')
    exact(relay.descriptorFloor, ['sequence', 'hash'], 'descriptorFloor')
    decimal(relay.descriptorFloor.sequence, 'descriptorFloor.sequence')
    hex(relay.descriptorFloor.hash, 32, 'descriptorFloor.hash')
    relayById.set(relay.relayId, relay)
  }
  unique(payload.relays.map(value => value.relayId), 'relay IDs')
  unique(payload.relays.map(value => value.relayPublicKey), 'relay keys')
  unique(payload.relays.map(value => value.storeId), 'relay stores')
  if (!Array.isArray(payload.inboxEpochSets) || payload.inboxEpochSets.length !== 1) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'bootstrap must carry exactly one current epoch set')
  }
  const set = exact(payload.inboxEpochSets[0],
    ['inboxEpoch', 'stripeCountLog2', 'stripeSelectionKey', 'announcementMasterKey', 'bindings'], 'epoch set')
  const effectiveLeaseEpoch = Number(referenceUnixMillis / PEERIT_LIMITED_PUBLIC_INBOX_LEASE_EPOCH_MILLIS_V1)
  if (!Number.isSafeInteger(set.inboxEpoch) || set.inboxEpoch !== Math.floor(effectiveLeaseEpoch / 28) ||
      set.stripeCountLog2 !== 0 || !Array.isArray(set.bindings) || set.bindings.length !== 2) {
    fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'bootstrap epoch or one-stripe shape is invalid')
  }
  const announcementMasterKey = hex(set.announcementMasterKey, 32, 'announcementMasterKey')
  hex(set.stripeSelectionKey, 32, 'stripeSelectionKey')
  unique(set.bindings.map(value => value.relayId), 'binding relay IDs')
  unique(set.bindings.map(value => value.physicalTopic), 'physical topics')
  const bindings = []
  for (const binding of set.bindings) {
    exact(binding, [
      'inboxEpoch', 'stripeIndex', 'relayId', 'relayPublicKey', 'allocationEpoch', 'createPublicKey',
      'physicalTopic', 'frameClassBits', 'appendAuthMode', 'retentionClass', 'leaseClass', 'createReceiptCanonicalHex'
    ], 'binding')
    const relay = relayById.get(binding.relayId)
    if (!relay || binding.inboxEpoch !== set.inboxEpoch || binding.stripeIndex !== 0 ||
        binding.relayPublicKey !== relay.relayPublicKey || binding.frameClassBits !== 3 ||
        binding.appendAuthMode !== 0 || binding.retentionClass !== 3 || binding.leaseClass !== 4 ||
        !Number.isSafeInteger(binding.allocationEpoch) ||
        binding.allocationEpoch > effectiveLeaseEpoch + 1 || effectiveLeaseEpoch >= binding.allocationEpoch + 1460) {
      fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_INVALID', 'binding does not match the accepted OPEN_APPEND shape')
    }
    const expectedTopic = blake2b256(concatBytes(
      asciiBytes('hiverelay.blind.inbox-topic.v1'), u32Bytes(binding.allocationEpoch),
      hex(binding.createPublicKey, 32, 'createPublicKey')))
    if (!bytesEqual(expectedTopic, hex(binding.physicalTopic, 32, 'physicalTopic'))) {
      fail('PEERIT_LIMITED_INBOX_TOPIC_INVALID', 'physical topic is not self-certifying')
    }
    await verifyReceipt(control, binding, relay)
    bindings.push(immutableBinding(binding, relay))
  }
  const completeSignedWrapperHash = await hashBytes(canonicalPeeritLimitedPublicInboxJsonV1(wrapper))
  if (input.floor != null) {
    exact(input.floor, ['schema', 'version', 'highestAcceptedBootstrapSequence', 'completeSignedWrapperHash'], 'bootstrap floor')
    const floorSequence = decimal(input.floor.highestAcceptedBootstrapSequence, 'floor sequence')
    if (sequence < floorSequence) fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_ROLLBACK', 'bootstrap is below the persisted floor')
    if (sequence === floorSequence && input.floor.completeSignedWrapperHash !== completeSignedWrapperHash) {
      fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_FORK', 'bootstrap forks the persisted same-sequence floor')
    }
  }
  const authority = Object.freeze({
    version: 1,
    releaseSequence: 29,
    artifactClass: payload.artifactClass,
    bootstrapSequence: sequence,
    inboxEpoch: set.inboxEpoch,
    completeSignedWrapperHash,
    authorityPublicKey: bytesToHex(authorityPublicKey),
    get announcementMasterKey () { return announcementMasterKey.slice() },
    bindings: Object.freeze(bindings),
    floor: Object.freeze({
      schema: 'PeeritLimitedPublicInboxBootstrapFloorV1',
      version: 1,
      highestAcceptedBootstrapSequence: String(sequence),
      completeSignedWrapperHash
    })
  })
  VERIFIED.set(authority, true)
  return authority
}

export function isVerifiedPeeritLimitedPublicInboxBootstrapV1 (value) {
  return VERIFIED.has(value)
}

export function peeritLimitedPublicInboxBindingsV1 (value) {
  if (!VERIFIED.has(value)) fail('PEERIT_LIMITED_INBOX_BOOTSTRAP_REQUIRED', 'verified bootstrap authority is required')
  return value.bindings
}
