import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto'
import { patchCspForWeb } from './csp.mjs'
import {
  decodePeeritWebAssetManifestV1,
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1,
  hashPeeritWebAssetManifestV1,
  verifyPeeritWebAssetBytesV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesToHex,
  concatBytes,
  u32Bytes,
  u64Bytes
} from '../js/substrate/release-control-primitives.mjs'
import { PEERIT_PRODUCTION_PIN_HISTORY_PATH } from '../js/substrate/production-release-authority.mjs'
import { normalizePeeritReleaseRelayHintsV1 } from '../js/substrate/release-relay-hints.mjs'
import { encodePeeritSeedBootstrapV1 } from '../js/substrate/seed-bootstrap-v1.mjs'
import { PEERIT_LIMITED_CELL_PUT_ISSUER_ORIGINS_V1 } from '../js/substrate/limited-cell-put-profile.mjs'
import {
  decodeBlindExternalProfileValueV1
} from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'

export const PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE = 7
export const PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE = 13
export const PEERIT_LIMITED_PUBLIC_INBOX_MINIMUM_RELEASE_SEQUENCE = 29
export const PEERIT_APP_ARTIFACT_PATH = 'peerit-app-artifact-v1.json'
export const PEERIT_WEB_ASSET_MANIFEST_PATH = 'peerit-web-assets-v1.cenc'
export const PEERIT_SEED_BOOTSTRAP_PATH = 'peerit-seed-bootstrap-v1.json'
export const PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH =
  'peerit-limited-public-inbox-bootstrap-v1.json'

const HEX_32 = /^[0-9a-f]{64}$/
const HEX_64 = /^[0-9a-f]{128}$/
const DECIMAL_U64 = /^(0|[1-9][0-9]{0,19})$/
const MAX_U64 = (1n << 64n) - 1n
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const LIMITED_INBOX_DOMAIN = 'peerit.limited-public-test.inbox-bootstrap.v1'
const LIMITED_INBOX_MAX_LIFETIME_MILLIS = 2678400000n
const LIMITED_INBOX_LEASE_EPOCH_MILLIS = 21600000n

function sha256 (input) {
  return createHash('sha256').update(input).digest('hex')
}

function sri (input) {
  return 'sha384-' + createHash('sha384').update(input).digest('base64')
}

function attr (value) {
  return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
}

function exactBuffer (value, field) {
  if (Buffer.isBuffer(value)) return Buffer.from(value)
  if (value instanceof Uint8Array) return Buffer.from(value)
  throw new TypeError(`${field} must be bytes`)
}

function sortedObject (entries) {
  return Object.fromEntries([...entries].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0))
}

function stableJson (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']'
  return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + stableJson(value[key])).join(',') + '}'
}

function exactObject (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    throw new Error(`${field} fields are missing or unexpected`)
  }
  return value
}

function decimalU64 (value, field) {
  if (typeof value !== 'string' || !DECIMAL_U64.test(value)) {
    throw new Error(`${field} is not canonical u64 decimal`)
  }
  const parsed = BigInt(value)
  if (parsed > MAX_U64) throw new Error(`${field} exceeds u64`)
  return parsed
}

function exactHex (value, bytes, field) {
  const pattern = bytes === 32 ? HEX_32 : bytes === 64 ? HEX_64 : /^[0-9a-f]+$/
  if (typeof value !== 'string' || !pattern.test(value) || value.length % 2 !== 0) {
    throw new Error(`${field} is not canonical lowercase hex`)
  }
  return Buffer.from(value, 'hex')
}

function uniqueValues (values, field) {
  if (new Set(values).size !== values.length) throw new Error(`${field} contains duplicates`)
}

function noPrivateInboxMaterial (value, path = []) {
  if (value == null || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const lower = key.toLowerCase()
    if (lower.includes('privateseed') || lower.includes('privatekey') ||
        lower === 'secretseed' || lower === 'managementkeyderivation' ||
        lower === 'deterministicpublicinputderivation') {
      throw new Error(`public INBOX bootstrap carries forbidden management material at ${[...path, key].join('.')}`)
    }
    noPrivateInboxMaterial(child, [...path, key])
  }
}

function canonicalInboxDescribeUrl (value) {
  if (typeof value !== 'string' ||
      !/^https:\/\/[a-z0-9.-]+:[1-9][0-9]{0,4}\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(value)) {
    throw new Error('public INBOX relay describe URL is not canonical HTTPS with an explicit port')
  }
  const port = Number(/^https:\/\/[^/]+:([0-9]+)\//.exec(value)[1])
  if (port > 65535 || value.includes('/./') || value.includes('/../') || value.includes('//', 8)) {
    throw new Error('public INBOX relay describe URL has an invalid port or path')
  }
}

function verifyInboxBootstrapSignature (wrapper, authorityPublicKey) {
  const signatureMessage = Buffer.concat([
    Buffer.from(LIMITED_INBOX_DOMAIN, 'ascii'),
    Buffer.from([0]),
    Buffer.from(stableJson(wrapper.payload), 'utf8')
  ])
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(authorityPublicKey, 'hex')]),
    format: 'der',
    type: 'spki'
  })
  return verifySignature(null, signatureMessage, publicKey, Buffer.from(wrapper.signature, 'hex'))
}

function verifyInboxCreateReceipt (binding, relay) {
  const receiptBytes = exactHex(binding.createReceiptCanonicalHex, null, 'public INBOX create receipt')
  let receipt
  try {
    receipt = decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes)
  } catch (cause) {
    throw new Error(`public INBOX create receipt is not canonical: ${cause.message}`)
  }
  const unsigned = receiptBytes.subarray(0, receiptBytes.byteLength - 64)
  const signature = receiptBytes.subarray(receiptBytes.byteLength - 64)
  const signatureMessage = concatBytes(
    asciiBytes('hiverelay.blind.inbox-receipt.v1'), u64Bytes(unsigned.byteLength), unsigned)
  const relayPublicKey = exactHex(relay.relayPublicKey, 32, 'public INBOX relayPublicKey')
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, relayPublicKey]),
    format: 'der',
    type: 'spki'
  })
  if (!verifySignature(null, signatureMessage, publicKey, signature)) {
    throw new Error('public INBOX create receipt relay signature is invalid')
  }
  const topic = exactHex(binding.physicalTopic, 32, 'public INBOX physicalTopic')
  if (!Buffer.from(receipt.relayBinding.relayPublicKey).equals(relayPublicKey) ||
      !Buffer.from(receipt.relayBinding.storeId).equals(
        exactHex(relay.storeId, 32, 'public INBOX relay storeId')) ||
      !Buffer.from(receipt.relayBinding.durabilityContinuityHash).equals(
        exactHex(relay.durabilityContinuityHash, 32, 'public INBOX relay durabilityContinuityHash')) ||
      String(receipt.relayBinding.descriptorSequence) !== relay.descriptorFloor.sequence ||
      !Buffer.from(receipt.relayBinding.descriptorHash).equals(
        exactHex(relay.descriptorFloor.hash, 32, 'public INBOX descriptor floor hash')) ||
      !Buffer.from(receipt.topicCommitment).equals(Buffer.from(blake2b256(topic))) ||
      String(receipt.stateRevision) !== '0' || receipt.leaseClass !== 4 || receipt.result !== 1) {
    throw new Error('public INBOX create receipt does not bind the advertised topic and relay floor')
  }
}

// Synchronous Node-side equivalent of verifyPeeritLimitedPublicInboxBootstrapV1.
// Artifact construction intentionally stays synchronous; this uses Node's
// Ed25519 verifier plus the exact pinned external-profile receipt decoder while
// matching the browser verifier's wrapper, payload, relay, epoch, topic,
// receipt, time, authority, and release checks.
function verifyExactInboxBootstrap (wrapper, expectedAuthorityPublicKey, releaseSequence,
  referenceUnixMillis = BigInt(Date.now())) {
  noPrivateInboxMaterial(wrapper)
  exactObject(wrapper, ['payload', 'signature'], 'public INBOX bootstrap wrapper')
  const payload = exactObject(wrapper.payload, [
    'schema', 'version', 'artifactClass', 'claimBoundary', 'operatorBoundary',
    'topicScope', 'profileId', 'releaseSequence', 'bootstrapSequence',
    'previousBootstrapHash', 'issuedUnixMillis', 'expiresUnixMillis',
    'authorityPublicKey', 'relays', 'inboxEpochSets'
  ], 'public INBOX bootstrap payload')
  if (payload.artifactClass !== 'LIMITED_PUBLIC_TEST_RELEASE') {
    throw new Error('public INBOX bootstrap is not a limited public test release production-test class')
  }
  if (payload.schema !== 'peerit-limited-public-inbox-bootstrap-v1' ||
      payload.version !== 1 ||
      payload.claimBoundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
      payload.operatorBoundary !== 'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS' ||
      payload.topicScope !== 'GLOBAL_PUBLIC_DISCOVERY' ||
      payload.profileId !== '@peerit/hiverelay-profile-v1' ||
      payload.releaseSequence !== PEERIT_LIMITED_PUBLIC_INBOX_MINIMUM_RELEASE_SEQUENCE ||
      payload.releaseSequence !== releaseSequence) {
    throw new Error('public INBOX bootstrap contract identity is invalid')
  }
  const sequence = decimalU64(payload.bootstrapSequence, 'public INBOX bootstrapSequence')
  if ((sequence === 0n) !== (payload.previousBootstrapHash === null)) {
    throw new Error('public INBOX bootstrap predecessor presence does not match sequence')
  }
  if (payload.previousBootstrapHash !== null) {
    exactHex(payload.previousBootstrapHash, 32, 'public INBOX previousBootstrapHash')
  }
  const issued = decimalU64(payload.issuedUnixMillis, 'public INBOX issuedUnixMillis')
  const expires = decimalU64(payload.expiresUnixMillis, 'public INBOX expiresUnixMillis')
  const reference = typeof referenceUnixMillis === 'bigint'
    ? referenceUnixMillis
    : BigInt(referenceUnixMillis)
  if (expires <= issued || expires - issued > LIMITED_INBOX_MAX_LIFETIME_MILLIS ||
      reference < issued || reference >= expires) {
    throw new Error('trusted local time is outside the bounded public INBOX bootstrap lifetime')
  }
  exactHex(payload.authorityPublicKey, 32, 'public INBOX authorityPublicKey')
  if (payload.authorityPublicKey !== expectedAuthorityPublicKey) {
    throw new Error('public INBOX bootstrap authority key differs from the release binding')
  }
  exactHex(wrapper.signature, 64, 'public INBOX bootstrap signature')
  if (!verifyInboxBootstrapSignature(wrapper, payload.authorityPublicKey)) {
    throw new Error('public INBOX bootstrap signature is invalid')
  }
  if (!Array.isArray(payload.relays) || payload.relays.length !== 2) {
    throw new Error('public INBOX bootstrap must name exactly two relays')
  }
  const relayById = new Map()
  for (const relay of payload.relays) {
    exactObject(relay, [
      'relayId', 'canonicalDescribeUrl', 'relayPublicKey', 'storeId',
      'durabilityContinuityHash', 'descriptorFloor'
    ], 'public INBOX relay')
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(relay.relayId)) {
      throw new Error('public INBOX relayId is invalid')
    }
    canonicalInboxDescribeUrl(relay.canonicalDescribeUrl)
    exactHex(relay.relayPublicKey, 32, 'public INBOX relayPublicKey')
    exactHex(relay.storeId, 32, 'public INBOX relay storeId')
    exactHex(relay.durabilityContinuityHash, 32,
      'public INBOX relay durabilityContinuityHash')
    exactObject(relay.descriptorFloor, ['sequence', 'hash'],
      'public INBOX descriptorFloor')
    decimalU64(relay.descriptorFloor.sequence, 'public INBOX descriptorFloor.sequence')
    exactHex(relay.descriptorFloor.hash, 32, 'public INBOX descriptorFloor.hash')
    relayById.set(relay.relayId, relay)
  }
  uniqueValues(payload.relays.map(value => value.relayId), 'public INBOX relay IDs')
  uniqueValues(payload.relays.map(value => value.relayPublicKey), 'public INBOX relay keys')
  uniqueValues(payload.relays.map(value => value.storeId), 'public INBOX relay stores')
  if (!Array.isArray(payload.inboxEpochSets) || payload.inboxEpochSets.length !== 1) {
    throw new Error('public INBOX bootstrap must carry exactly one current epoch set')
  }
  const set = exactObject(payload.inboxEpochSets[0], [
    'inboxEpoch', 'stripeCountLog2', 'stripeSelectionKey',
    'announcementMasterKey', 'bindings'
  ], 'public INBOX epoch set')
  const effectiveLeaseEpoch = Number(reference / LIMITED_INBOX_LEASE_EPOCH_MILLIS)
  if (!Number.isSafeInteger(set.inboxEpoch) ||
      set.inboxEpoch !== Math.floor(effectiveLeaseEpoch / 28) ||
      set.stripeCountLog2 !== 0 || !Array.isArray(set.bindings) ||
      set.bindings.length !== 2) {
    throw new Error('public INBOX bootstrap epoch or one-stripe shape is invalid')
  }
  exactHex(set.stripeSelectionKey, 32, 'public INBOX stripeSelectionKey')
  exactHex(set.announcementMasterKey, 32, 'public INBOX announcementMasterKey')
  uniqueValues(set.bindings.map(value => value.relayId), 'public INBOX binding relay IDs')
  uniqueValues(set.bindings.map(value => value.physicalTopic), 'public INBOX physical topics')
  for (const binding of set.bindings) {
    exactObject(binding, [
      'inboxEpoch', 'stripeIndex', 'relayId', 'relayPublicKey',
      'allocationEpoch', 'createPublicKey', 'physicalTopic', 'frameClassBits',
      'appendAuthMode', 'retentionClass', 'leaseClass', 'createReceiptCanonicalHex'
    ], 'public INBOX binding')
    const relay = relayById.get(binding.relayId)
    if (!relay || binding.inboxEpoch !== set.inboxEpoch || binding.stripeIndex !== 0 ||
        binding.relayPublicKey !== relay.relayPublicKey || binding.frameClassBits !== 3 ||
        binding.appendAuthMode !== 0 || binding.retentionClass !== 3 ||
        binding.leaseClass !== 4 || !Number.isSafeInteger(binding.allocationEpoch) ||
        binding.allocationEpoch > effectiveLeaseEpoch + 1 ||
        effectiveLeaseEpoch >= binding.allocationEpoch + 1460) {
      throw new Error('public INBOX binding does not match the accepted OPEN_APPEND shape')
    }
    const expectedTopic = blake2b256(concatBytes(
      asciiBytes('hiverelay.blind.inbox-topic.v1'), u32Bytes(binding.allocationEpoch),
      exactHex(binding.createPublicKey, 32, 'public INBOX createPublicKey')))
    if (!Buffer.from(expectedTopic).equals(
      exactHex(binding.physicalTopic, 32, 'public INBOX physicalTopic'))) {
      throw new Error('public INBOX physical topic is not self-certifying')
    }
    verifyInboxCreateReceipt(binding, relay)
  }
  return wrapper
}

export function verifyPeeritLimitedPublicInboxBootstrapArtifactV1 (options = {}) {
  const bytes = exactBuffer(options.bytes, 'public INBOX bootstrap')
  if (bytes.byteLength < 1 || bytes.byteLength > 1024 * 1024) {
    throw new Error('public INBOX bootstrap exceeds its fixed byte bound')
  }
  let wrapper
  try { wrapper = JSON.parse(bytes.toString('utf8')) } catch (cause) {
    throw new Error(`public INBOX bootstrap is not JSON: ${cause.message}`)
  }
  if (JSON.stringify(wrapper, null, 2) + '\n' !== bytes.toString('utf8')) {
    throw new Error('public INBOX bootstrap JSON bytes are not canonical')
  }
  const authorityPublicKey = String(options.expectedAuthorityPublicKey || '').toLowerCase()
  const releaseSequence = Number(options.expectedReleaseSequence)
  if (!HEX_32.test(authorityPublicKey) ||
      !Number.isSafeInteger(releaseSequence) ||
      releaseSequence !== PEERIT_LIMITED_PUBLIC_INBOX_MINIMUM_RELEASE_SEQUENCE) {
    throw new Error('public INBOX bootstrap verification requires the exact release authority and sequence')
  }
  const referenceUnixMillis = options.referenceUnixMillis == null
    ? BigInt(Date.now())
    : options.referenceUnixMillis
  verifyExactInboxBootstrap(wrapper, authorityPublicKey, releaseSequence,
    referenceUnixMillis)
  return Object.freeze({
    sha256: sha256(bytes),
    authorityPublicKey: wrapper.payload.authorityPublicKey,
    artifactClass: wrapper.payload.artifactClass,
    releaseSequence: wrapper.payload.releaseSequence,
    bindingCount: wrapper.payload.inboxEpochSets[0].bindings.length
  })
}

function seedReleaseBinding (value) {
  const fields = [
    'peeritSeedBootstrap',
    'peeritSeedBootstrapSha256',
    'peeritSeedDiscoveryAuthorityPublicKey',
    'peeritSeedBootstrapReleaseSequence'
  ]
  const present = fields.filter(field => Object.hasOwn(value, field))
  if (value.releaseSequence < PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE) {
    if (present.length !== 0) throw new Error('pre-sequence-13 app artifact cannot carry a Peerit seed bootstrap binding')
    return null
  }
  if (present.length !== fields.length ||
      value.peeritSeedBootstrap !== `/${PEERIT_SEED_BOOTSTRAP_PATH}` ||
      !HEX_32.test(String(value.peeritSeedBootstrapSha256 || '')) ||
      !HEX_32.test(String(value.peeritSeedDiscoveryAuthorityPublicKey || '')) ||
      value.peeritSeedBootstrapReleaseSequence !== value.releaseSequence) {
    throw new Error('sequence-13+ app artifact must bind one exact Peerit seed bootstrap')
  }
  return Object.freeze({
    path: value.peeritSeedBootstrap,
    sha256: value.peeritSeedBootstrapSha256,
    authorityPublicKey: value.peeritSeedDiscoveryAuthorityPublicKey,
    releaseSequence: value.peeritSeedBootstrapReleaseSequence
  })
}

function seedBuildInput (options, releaseSequence) {
  const supplied = options.seedBootstrapBytes != null ||
    String(options.seedDiscoveryAuthorityPublicKey || '').length > 0
  if (releaseSequence < PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE) {
    if (supplied) throw new Error('Peerit seed bootstrap composition requires releaseSequence 13 or later')
    return null
  }
  const bytes = exactBuffer(options.seedBootstrapBytes, 'Peerit seed bootstrap')
  if (bytes.byteLength < 1 || bytes.byteLength > 16 * 1024 * 1024) {
    throw new Error('Peerit seed bootstrap exceeds its fixed byte bound')
  }
  let canonical
  try { canonical = Buffer.from(encodePeeritSeedBootstrapV1(bytes)) } catch (cause) {
    throw new Error(`Peerit seed bootstrap is not canonical: ${cause.message}`)
  }
  if (!canonical.equals(bytes)) throw new Error('Peerit seed bootstrap bytes are not canonical')
  const authorityPublicKey = String(options.seedDiscoveryAuthorityPublicKey || '').toLowerCase()
  if (!HEX_32.test(authorityPublicKey)) {
    throw new Error('sequence-13+ replacement requires one 32-byte lowercase seed discovery authority key')
  }
  const artifact = JSON.parse(bytes.toString('utf8'))
  if (artifact.payload.releaseSequence !== releaseSequence ||
      artifact.payload.authorityPublicKey !== authorityPublicKey) {
    throw new Error('Peerit seed bootstrap release sequence or discovery authority does not match its build input')
  }
  return Object.freeze({
    bytes,
    path: `/${PEERIT_SEED_BOOTSTRAP_PATH}`,
    sha256: sha256(bytes),
    authorityPublicKey,
    releaseSequence,
    domainHash: hashPeeritBootstrapV1(bytes)
  })
}

function inboxReleaseBinding (value) {
  const fields = [
    'peeritLimitedPublicInboxBootstrap',
    'peeritLimitedPublicInboxBootstrapSha256',
    'peeritLimitedPublicInboxBootstrapAuthorityPublicKey',
    'peeritLimitedPublicInboxBootstrapReleaseSequence'
  ]
  const present = fields.filter(field => Object.hasOwn(value, field))
  if (value.releaseSequence < PEERIT_LIMITED_PUBLIC_INBOX_MINIMUM_RELEASE_SEQUENCE) {
    if (present.length !== 0) throw new Error('pre-sequence-29 app artifact cannot carry a public INBOX bootstrap binding')
    return null
  }
  if (present.length !== fields.length ||
      value.peeritLimitedPublicInboxBootstrap !== `/${PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH}` ||
      !HEX_32.test(String(value.peeritLimitedPublicInboxBootstrapSha256 || '')) ||
      !HEX_32.test(String(value.peeritLimitedPublicInboxBootstrapAuthorityPublicKey || '')) ||
      value.peeritLimitedPublicInboxBootstrapReleaseSequence !== value.releaseSequence) {
    throw new Error('sequence-29+ app artifact must bind one exact public INBOX bootstrap')
  }
  return Object.freeze({
    path: value.peeritLimitedPublicInboxBootstrap,
    sha256: value.peeritLimitedPublicInboxBootstrapSha256,
    authorityPublicKey: value.peeritLimitedPublicInboxBootstrapAuthorityPublicKey,
    releaseSequence: value.peeritLimitedPublicInboxBootstrapReleaseSequence
  })
}

function inboxBuildInput (options, releaseSequence) {
  const supplied = options.limitedPublicInboxBootstrapBytes != null ||
    String(options.limitedPublicInboxBootstrapAuthorityPublicKey || '').length > 0 ||
    options.limitedPublicInboxReferenceUnixMillis != null
  if (releaseSequence < PEERIT_LIMITED_PUBLIC_INBOX_MINIMUM_RELEASE_SEQUENCE) {
    if (supplied) throw new Error('public INBOX bootstrap composition requires releaseSequence 29 or later')
    return null
  }
  const bytes = exactBuffer(options.limitedPublicInboxBootstrapBytes, 'public INBOX bootstrap')
  const authorityPublicKey = String(
    options.limitedPublicInboxBootstrapAuthorityPublicKey || '').toLowerCase()
  if (!HEX_32.test(authorityPublicKey)) {
    throw new Error('public INBOX bootstrap does not match the exact release authority and production-test class')
  }
  const verified = verifyPeeritLimitedPublicInboxBootstrapArtifactV1({
    bytes,
    expectedAuthorityPublicKey: authorityPublicKey,
    expectedReleaseSequence: releaseSequence,
    referenceUnixMillis: options.limitedPublicInboxReferenceUnixMillis
  })
  return Object.freeze({
    bytes,
    path: `/${PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH}`,
    sha256: verified.sha256,
    authorityPublicKey: verified.authorityPublicKey,
    releaseSequence: verified.releaseSequence
  })
}

function normalizedFiles (sourceFiles) {
  const source = sourceFiles instanceof Map ? sourceFiles : new Map(Object.entries(sourceFiles || {}))
  const files = new Map()
  for (const [path, bytes] of source) {
    if (typeof path !== 'string' ||
        !/^(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(path) ||
        path.split('/').some(component => component === '.' || component === '..')) {
      throw new Error(`replacement runtime source path is not canonical: ${path}`)
    }
    files.set(path, exactBuffer(bytes, path))
  }
  for (const path of ['index.html', 'styles.css', 'js/substrate/app-entry.js']) {
    if (!files.has(path)) throw new Error(`replacement runtime source is missing ${path}`)
  }
  return files
}

function decodeAppArtifactV1 (bytes) {
  let value
  try {
    value = JSON.parse(exactBuffer(bytes, PEERIT_APP_ARTIFACT_PATH).toString('utf8'))
  } catch {
    throw new Error(`${PEERIT_APP_ARTIFACT_PATH} is not valid JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      value.schema !== 'peerit-app-artifact-v1' ||
      value.transport !== 'blind-substrate' ||
      value.substrateProfile !== 'blind-v1' ||
      value.entry !== '/index.html' ||
      value.canonicalWebAssetManifest !== `/${PEERIT_WEB_ASSET_MANIFEST_PATH}` ||
      (value.productionPinHistory !== null &&
        value.productionPinHistory !== PEERIT_PRODUCTION_PIN_HISTORY_PATH) ||
      !Number.isSafeInteger(value.releaseSequence) ||
      value.releaseSequence < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE ||
      !HEX_32.test(String(value.releaseKey || '')) ||
      !Array.isArray(value.relayHints) ||
      !value.files || typeof value.files !== 'object' || Array.isArray(value.files)) {
    throw new Error(`${PEERIT_APP_ARTIFACT_PATH} has an invalid replacement release identity`)
  }
  value.relayHints = normalizePeeritReleaseRelayHintsV1(
    value.relayHints, 'app artifact')
  value.seedBootstrap = seedReleaseBinding(value)
  value.inboxBootstrap = inboxReleaseBinding(value)
  return value
}

export function verifyPeeritAppArtifactReleaseBindingsV1 (input) {
  const bytes = exactBuffer(input, PEERIT_APP_ARTIFACT_PATH)
  let source
  try { source = JSON.parse(bytes.toString('utf8')) } catch {
    throw new Error(`${PEERIT_APP_ARTIFACT_PATH} is not valid JSON`)
  }
  if (JSON.stringify(source, null, 2) + '\n' !== bytes.toString('utf8')) {
    throw new Error(`${PEERIT_APP_ARTIFACT_PATH} bytes are not canonical pretty JSON`)
  }
  const artifact = decodeAppArtifactV1(bytes)
  return Object.freeze({
    releaseSequence: artifact.releaseSequence,
    releaseKey: artifact.releaseKey,
    seedBootstrap: artifact.seedBootstrap,
    inboxBootstrap: artifact.inboxBootstrap,
    files: Object.freeze({ ...artifact.files })
  })
}

// Verify a generated replacement closure without trusting either wrapper's JSON
// metadata. Web release tooling, deployment proof, and Hyper tests all call this
// same verifier, so the canonical CENC manifest remains the authority for bytes.
export function verifyPeeritSubstrateRuntimeArtifactV1 (options = {}) {
  const source = options.files instanceof Map
    ? new Map(options.files)
    : new Map(Object.entries(options.files || {}))
  const releaseSequence = Number(options.releaseSequence)
  const releaseKey = String(options.releaseKey || '').toLowerCase()
  if (!Number.isSafeInteger(releaseSequence) ||
      releaseSequence < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE ||
      !HEX_32.test(releaseKey)) {
    throw new Error('replacement runtime verification requires an exact sequence and release key')
  }
  if (!source.has(PEERIT_APP_ARTIFACT_PATH) ||
      !source.has(PEERIT_WEB_ASSET_MANIFEST_PATH)) {
    throw new Error('replacement runtime is missing its app artifact or canonical WebAssetManifestV1')
  }

  const appArtifactBytes = exactBuffer(source.get(PEERIT_APP_ARTIFACT_PATH), PEERIT_APP_ARTIFACT_PATH)
  const webAssetManifestBytes = exactBuffer(
    source.get(PEERIT_WEB_ASSET_MANIFEST_PATH), PEERIT_WEB_ASSET_MANIFEST_PATH)
  const appArtifact = decodeAppArtifactV1(appArtifactBytes)
  const webAssetManifest = decodePeeritWebAssetManifestV1(webAssetManifestBytes)
  if (appArtifact.releaseSequence !== releaseSequence ||
      appArtifact.releaseKey !== releaseKey ||
      webAssetManifest.releaseSequence !== BigInt(releaseSequence)) {
    throw new Error('replacement runtime release identity does not match its wrapper configuration')
  }
  if (webAssetManifest.assets.some(asset => asset.path === `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`)) {
    throw new Error('canonical WebAssetManifestV1 cannot self-list its own bytes')
  }
  const appArtifactHash = hashPeeritAppArtifactV1(appArtifactBytes)
  if (!Buffer.from(webAssetManifest.appArtifactHash).equals(Buffer.from(appArtifactHash))) {
    throw new Error('canonical WebAssetManifestV1 does not bind the exact app artifact')
  }

  const seedBinding = appArtifact.seedBootstrap
  if (seedBinding) {
    const seedPath = seedBinding.path.slice(1)
    if (!source.has(seedPath)) throw new Error('replacement runtime is missing its bound Peerit seed bootstrap')
    const seedBytes = exactBuffer(source.get(seedPath), seedPath)
    let canonicalSeed
    try { canonicalSeed = Buffer.from(encodePeeritSeedBootstrapV1(seedBytes)) } catch (cause) {
      throw new Error(`bound Peerit seed bootstrap is not canonical: ${cause.message}`)
    }
    const seedArtifact = JSON.parse(seedBytes.toString('utf8'))
    if (!canonicalSeed.equals(seedBytes) || sha256(seedBytes) !== seedBinding.sha256 ||
        seedArtifact.payload.releaseSequence !== seedBinding.releaseSequence ||
        seedArtifact.payload.authorityPublicKey !== seedBinding.authorityPublicKey ||
        webAssetManifest.recommendedBootstrapHashes.length !== 1 ||
        !Buffer.from(webAssetManifest.recommendedBootstrapHashes[0]).equals(
          Buffer.from(hashPeeritBootstrapV1(seedBytes)))) {
      throw new Error('Peerit seed bootstrap bytes do not match the app/canonical release bindings')
    }
  } else if (webAssetManifest.recommendedBootstrapHashes.length !== 0 ||
      source.has(PEERIT_SEED_BOOTSTRAP_PATH)) {
    throw new Error('pre-sequence-13 replacement runtime cannot carry recommended seed bootstrap bytes')
  }

  const inboxBinding = appArtifact.inboxBootstrap
  if (inboxBinding) {
    const inboxPath = inboxBinding.path.slice(1)
    if (!source.has(inboxPath)) throw new Error('replacement runtime is missing its bound public INBOX bootstrap')
    const inboxBytes = exactBuffer(source.get(inboxPath), inboxPath)
    if (sha256(inboxBytes) !== inboxBinding.sha256) {
      throw new Error('public INBOX bootstrap bytes do not match the app release binding')
    }
    verifyPeeritLimitedPublicInboxBootstrapArtifactV1({
      bytes: inboxBytes,
      expectedAuthorityPublicKey: inboxBinding.authorityPublicKey,
      expectedReleaseSequence: inboxBinding.releaseSequence,
      referenceUnixMillis: options.limitedPublicInboxReferenceUnixMillis
    })
  } else if (source.has(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH)) {
    throw new Error('pre-sequence-29 replacement runtime cannot carry public INBOX bootstrap bytes')
  }

  const indexHtml = exactBuffer(source.get('index.html'), 'index.html').toString('utf8')
  const exactCount = pattern => (indexHtml.match(pattern) || []).length
  if (exactCount(/<meta\s+name="peerit-substrate"\s+content="blind-v1">/g) !== 1 ||
      exactCount(new RegExp(`<meta\\s+name="peerit-release-key"\\s+content="${releaseKey}">`, 'g')) !== 1 ||
      exactCount(new RegExp(`<meta\\s+name="peerit-release-sequence"\\s+content="${releaseSequence}">`, 'g')) !== 1 ||
      exactCount(new RegExp(`<meta\\s+name="peerit-production-web-asset-manifest"\\s+content="/${PEERIT_WEB_ASSET_MANIFEST_PATH}">`, 'g')) !== 1 ||
      exactCount(/<script\s+type="module"\s+src="js\/substrate\/app-entry\.js"[^>]*><\/script>/g) !== 1 ||
      !/script-src 'self'(?:;|$)/.test(indexHtml)) {
    throw new Error('replacement index transformation did not produce one exact entry, authority metadata set, and strict script CSP')
  }
  const pinMetaCount = exactCount(new RegExp(
    `<meta\\s+name="peerit-production-pin-history"\\s+content="${PEERIT_PRODUCTION_PIN_HISTORY_PATH}">`, 'g'))
  const expectedRelayMeta = appArtifact.relayHints.length
    ? `<meta name="peerit-substrate-relays" content="${attr(appArtifact.relayHints.join(','))}">`
    : null
  const relayMetaCount = exactCount(/<meta\s+name="peerit-substrate-relays"\s+content="[^"]*">/g)
  const canonicalHasPinHistory = webAssetManifest.assets.some(
    asset => asset.path === PEERIT_PRODUCTION_PIN_HISTORY_PATH)
  if ((appArtifact.productionPinHistory ? pinMetaCount !== 1 : pinMetaCount !== 0) ||
      (expectedRelayMeta ? relayMetaCount !== 1 || !indexHtml.includes(expectedRelayMeta) : relayMetaCount !== 0) ||
      Boolean(appArtifact.productionPinHistory) !==
        source.has(PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)) ||
      canonicalHasPinHistory ||
      Object.hasOwn(appArtifact.files, PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1))) {
    throw new Error('replacement pin-history metadata and canonical closure do not agree')
  }

  const canonicalAssets = new Map()
  for (const asset of webAssetManifest.assets) {
    const path = asset.path.slice(1)
    if (!source.has(path)) throw new Error(`canonical replacement asset is missing: ${asset.path}`)
    canonicalAssets.set(asset.path, exactBuffer(source.get(path), path))
  }
  const exactSourcePaths = new Set([
    ...webAssetManifest.assets.map(asset => asset.path.slice(1)),
    PEERIT_WEB_ASSET_MANIFEST_PATH,
    ...(appArtifact.productionPinHistory
      ? [PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)]
      : [])
  ])
  if (source.size !== exactSourcePaths.size ||
      [...source.keys()].some(path => !exactSourcePaths.has(path))) {
    throw new Error('replacement runtime contains bytes outside its exact canonical closure')
  }
  verifyPeeritWebAssetBytesV1(webAssetManifest, canonicalAssets, { requireComplete: true })

  const appPaths = Object.keys(appArtifact.files).sort()
  const expectedAppPaths = webAssetManifest.assets
    .map(asset => asset.path.slice(1))
    .filter(path => path !== PEERIT_APP_ARTIFACT_PATH)
    .sort()
  if (JSON.stringify(appPaths) !== JSON.stringify(expectedAppPaths)) {
    throw new Error('app artifact file closure does not equal the canonical runtime closure')
  }
  for (const path of appPaths) {
    const expectedHash = appArtifact.files[path]
    if (!HEX_32.test(String(expectedHash || '')) || sha256(source.get(path)) !== expectedHash) {
      throw new Error(`app artifact SHA-256 mismatch: ${path}`)
    }
  }

  const webAssetManifestHash = hashPeeritWebAssetManifestV1(webAssetManifestBytes)
  return Object.freeze({
    appArtifact,
    seedBootstrap: seedBinding,
    inboxBootstrap: inboxBinding,
    webAssetManifest,
    appArtifactHash,
    appArtifactHashHex: bytesToHex(appArtifactHash),
    webAssetManifestHash,
    webAssetManifestHashHex: bytesToHex(webAssetManifestHash),
    verifiedAssetCount: canonicalAssets.size
  })
}

export function peeritServiceWorkerRegisterSourceV1 () {
  return `if ('serviceWorker' in navigator) {
  // A new deploy changes the bundle hashes -> a new sw.js. The SW skipWaiting()s +
  // clients.claim()s, so it activates immediately, but the page already loaded with
  // the OLD cached assets. Reload ONCE when the new SW takes control so returning
  // visitors actually run the new audited bundle instead of stale code. Guard with
  // hadController so a brand-new visitor (first install) does not reload.
  // RATE-LIMITED, not once-per-session: the old boolean latch blocked the reload
  // for every deploy AFTER a tab's first, so long-lived tabs silently ran stale
  // builds until a manual refresh. A timestamp latch keeps reload loops harmless.
  var hadController = !!navigator.serviceWorker.controller, refreshing = false;
  var LATCH = 'peerit:sw-reloaded-at', WINDOW_MS = 5 * 60 * 1000;
  navigator.serviceWorker.addEventListener('controllerchange', function () {
    if (refreshing || !hadController) return;
    try {
      var last = Number(sessionStorage.getItem(LATCH) || 0);
      if (Date.now() - last < WINDOW_MS) return;
      sessionStorage.setItem(LATCH, String(Date.now()));
    } catch (e) {}
    refreshing = true; location.reload();
  });
  addEventListener('load', function () {
    navigator.serviceWorker.register('sw.js').then(function (reg) {
      if (reg && reg.update) { try { reg.update(); } catch (e) {} }
    }).catch(function () {});
  });
}
`
}

// Produce the one replacement runtime closure shared by the Web wrapper and
// Hyper publication. The returned bytes never contain a drive key, so the
// content-addressed Hyper identity does not become self-referential.
export function buildPeeritSubstrateRuntimeArtifactV1 (options = {}) {
  const profile = String(options.substrateProfile || '')
  const releaseSequence = Number(options.releaseSequence)
  const releaseKey = String(options.releaseKey || '').toLowerCase()
  const relayHints = normalizePeeritReleaseRelayHintsV1(
    options.relayHints == null ? [] : options.relayHints,
    'replacement runtime')
  if (profile !== 'blind-v1') throw new Error(`unsupported Peerit substrate profile: ${profile}`)
  if (!Number.isSafeInteger(releaseSequence) ||
      releaseSequence < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE) {
    throw new Error(`blind-substrate replacement releaseSequence must be at least ${PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE}; sequence 6 belongs to the retired legacy artifact`)
  }
  if (!HEX_32.test(releaseKey)) throw new Error('blind-substrate replacement requires one 32-byte lowercase release key')

  const files = normalizedFiles(options.sourceFiles)
  const productionPinHistoryBytes = options.productionPinHistoryBytes == null
    ? null
    : exactBuffer(options.productionPinHistoryBytes, 'production pin-history bundle')
  if (productionPinHistoryBytes &&
      (productionPinHistoryBytes.byteLength < 1 || productionPinHistoryBytes.byteLength > 4 * 1024 * 1024)) {
    throw new Error('production pin-history bundle exceeds its fixed byte bound')
  }
  const seedBootstrap = seedBuildInput(options, releaseSequence)
  const inboxBootstrap = inboxBuildInput(options, releaseSequence)
  if (files.has(PEERIT_SEED_BOOTSTRAP_PATH)) {
    throw new Error(`${PEERIT_SEED_BOOTSTRAP_PATH} is generated only from the explicit release seed input`)
  }
  if (seedBootstrap) files.set(PEERIT_SEED_BOOTSTRAP_PATH, seedBootstrap.bytes)
  if (files.has(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH)) {
    throw new Error(`${PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH} is generated only from the explicit release INBOX input`)
  }
  if (inboxBootstrap) files.set(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH, inboxBootstrap.bytes)
  const styleIntegrity = sri(files.get('styles.css'))
  const entryIntegrity = sri(files.get('js/substrate/app-entry.js'))
  let html = files.get('index.html').toString('utf8')
  html = html.replace(/\s*<meta\s+name="peerit-v2"[^>]*>/gi, '')
  html = html.replace(
    /<meta\s+name="description"\s+content="[^"]*">/i,
    '<meta name="description" content="peerit is a local-first community app using authenticated blind relay substrate artifacts.">')
  html = html.replace(/\s*<meta\s+name="peerit-shard-(?:roster|relays|threshold)"[^>]*>/gi, '')
  html = html.replace(/\s*<meta\s+name="peerit-(?:relay(?:-[a-z0-9-]+)?|dht-relay|seed-outboxes|substrate(?:-relays)?|release-key|release-sequence|production-web-asset-manifest|production-pin-history)"[^>]*>/gi, '')
  const head = [
    `<meta name="peerit-substrate" content="${attr(profile)}">`,
    relayHints.length ? `<meta name="peerit-substrate-relays" content="${attr(relayHints.join(','))}">` : '',
    `<meta name="peerit-release-key" content="${releaseKey}">`,
    `<meta name="peerit-release-sequence" content="${releaseSequence}">`,
    `<meta name="peerit-production-web-asset-manifest" content="/${PEERIT_WEB_ASSET_MANIFEST_PATH}">`,
    productionPinHistoryBytes
      ? `<meta name="peerit-production-pin-history" content="${PEERIT_PRODUCTION_PIN_HISTORY_PATH}">`
      : '',
    '<script src="sw-register.js"></script>'
  ].filter(Boolean).join('\n  ')
  html = html.replace('</head>', `  ${head}\n</head>`)
  html = patchCspForWeb(html, {
    dhtRelay: '',
    connectOrigins: [...new Set([
      ...relayHints.map(value => new URL(value).origin),
      ...PEERIT_LIMITED_CELL_PUT_ISSUER_ORIGINS_V1
    ])]
  })
  html = html.replace('<link rel="stylesheet" href="styles.css">',
    `<link rel="stylesheet" href="styles.css" integrity="${styleIntegrity}" crossorigin="anonymous">`)
  html = html.replace(/<script\s+type="module"\s+src="js\/(?:app\.js|substrate\/app-entry\.js)"(?:\s+[^>]*)?><\/script>/,
    `<script type="module" src="js/substrate/app-entry.js" integrity="${entryIntegrity}" crossorigin="anonymous"></script>`)
  files.set('index.html', Buffer.from(html))
  files.set('sw-register.js', Buffer.from(peeritServiceWorkerRegisterSourceV1()))

  const closureHashes = sortedObject([...files].map(([path, bytes]) => [path, sha256(bytes)]))
  const appArtifact = Object.freeze({
    schema: 'peerit-app-artifact-v1',
    releaseSequence,
    transport: 'blind-substrate',
    substrateProfile: profile,
    relayHints,
    releaseKey,
    entry: '/index.html',
    canonicalWebAssetManifest: `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`,
    productionPinHistory: productionPinHistoryBytes
      ? PEERIT_PRODUCTION_PIN_HISTORY_PATH
      : null,
    ...(seedBootstrap
      ? {
          peeritSeedBootstrap: seedBootstrap.path,
          peeritSeedBootstrapSha256: seedBootstrap.sha256,
          peeritSeedDiscoveryAuthorityPublicKey: seedBootstrap.authorityPublicKey,
          peeritSeedBootstrapReleaseSequence: seedBootstrap.releaseSequence
        }
      : {}),
    ...(inboxBootstrap
      ? {
          peeritLimitedPublicInboxBootstrap: inboxBootstrap.path,
          peeritLimitedPublicInboxBootstrapSha256: inboxBootstrap.sha256,
          peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxBootstrap.authorityPublicKey,
          peeritLimitedPublicInboxBootstrapReleaseSequence: inboxBootstrap.releaseSequence
        }
      : {}),
    files: closureHashes
  })
  const appArtifactBytes = Buffer.from(JSON.stringify(appArtifact, null, 2) + '\n')
  files.set(PEERIT_APP_ARTIFACT_PATH, appArtifactBytes)
  const appArtifactHash = hashPeeritAppArtifactV1(appArtifactBytes)

  const assets = [...files]
    .map(([path, bytes]) => ({
      path: new TextEncoder().encode('/' + path),
      byteLength: BigInt(bytes.byteLength),
      assetHash: blake2b256(bytes)
    }))
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
  const webAssetManifestBytes = Buffer.from(encodePeeritWebAssetManifestV1({
    version: 1,
    releaseSequence: BigInt(releaseSequence),
    appArtifactHash,
    recommendedBootstrapHashes: seedBootstrap ? [seedBootstrap.domainHash] : [],
    assets
  }))
  files.set(PEERIT_WEB_ASSET_MANIFEST_PATH, webAssetManifestBytes)
  const webAssetManifestHash = hashPeeritWebAssetManifestV1(webAssetManifestBytes)

  // Detached by design: the terminal profile pin commits to appArtifactHash and
  // webAssetManifestHash. Including pin history in either artifact would create
  // an impossible fixed-point hash cycle. Web signs this detached file in the
  // outer asset manifest; Hyper binds it through the drive content address.
  if (productionPinHistoryBytes) {
    files.set(PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1), productionPinHistoryBytes)
  }

  verifyPeeritSubstrateRuntimeArtifactV1({
    files,
    releaseSequence,
    releaseKey,
    limitedPublicInboxReferenceUnixMillis:
      options.limitedPublicInboxReferenceUnixMillis
  })

  return Object.freeze({
    files,
    appArtifact,
    appArtifactBytes,
    appArtifactHash,
    appArtifactHashHex: bytesToHex(appArtifactHash),
    webAssetManifestBytes,
    webAssetManifestHash,
    webAssetManifestHashHex: bytesToHex(webAssetManifestHash),
    seedBootstrap,
    inboxBootstrap,
    sha256Files: sortedObject([...files].map(([path, bytes]) => [path, sha256(bytes)]))
  })
}
