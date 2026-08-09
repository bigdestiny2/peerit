import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import {
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  verify
} from 'node:crypto'
import { fileURLToPath } from 'node:url'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  concatBytes,
  hexToBytes,
  u16Bytes,
  u32Bytes,
  u64Bytes
} from '../../js/substrate/release-control-primitives.mjs'
import {
  decodeBlindExternalProfileValueV1
} from '../../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'
import {
  compilePeeritProfileCodecIr,
  createPeeritProfileCodecCatalogFromIr
} from '../../js/substrate/profile-codec-ir.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../../js/substrate/profile-inventory.mjs'
import { authenticatePeeritProfileExternalCodecAuthorityV1 } from '../../js/substrate/profile-external-authority.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '../..')
const FIXTURES = path.join(ROOT, 'test/fixtures/peerit-seq29-limited-public-test-v1')
const NEGATIVE = path.join(FIXTURES, 'negative')
const PROFILE_SHA256 = '74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd'
const BOOTSTRAP_DOMAIN = 'peerit.limited-public-test.inbox-bootstrap.v1'
const MAX_BOOTSTRAP_LIFETIME_MILLIS = 2678400000n
const LIMITED_MANAGEMENT_BUNDLE_DOMAIN = 'peerit.hiverelay.limited-public-inbox-management-bundle.v1'
const LIMITED_MANAGEMENT_BUNDLE_KIND = 2
const LIMITED_MANAGEMENT_PLAINTEXT_CODEC = 3
const HEX32 = /^[0-9a-f]{64}$/
const HEX64 = /^[0-9a-f]{128}$/
const U64 = /^(0|[1-9][0-9]{0,19})$/

let assertions = 0
function ok (condition, code, message) {
  assertions++
  if (!condition) {
    const error = new Error(message)
    error.code = code
    throw error
  }
}
function same (actual, expected, code, message) {
  ok(actual === expected, code, `${message}: expected ${String(expected)}, got ${String(actual)}`)
}
function bytesSame (actual, expected, code, message) {
  ok(bytesEqual(actual, expected), code, message)
}
function hex (value, length = null, code = 'BAD_HEX', field = 'hex') {
  const rule = length === 32 ? HEX32 : length === 64 ? HEX64 : /^[0-9a-f]+$/
  ok(typeof value === 'string' && rule.test(value) && value.length % 2 === 0, code, `${field} is not canonical lowercase hex`)
  return hexToBytes(value, length == null ? undefined : length, field)
}
function sha256Hex (value) { return createHash('sha256').update(value).digest('hex') }
function json (value) { return JSON.parse(value) }
async function readJson (file) { return json(await fs.readFile(file, 'utf8')) }

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}
function canonicalJson (value) { return Buffer.from(stable(value), 'utf8') }
function publicKey (raw) {
  return createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]),
    format: 'der',
    type: 'spki'
  })
}
function verifyEd25519 (rawPublicKey, payload, signature) {
  try { return verify(null, payload, publicKey(rawPublicKey), signature) } catch { return false }
}

function ed25519PublicFromSeed (rawSeed) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(rawSeed)]),
    format: 'der',
    type: 'pkcs8'
  })
  return new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32))
}

async function createPinnedProfileCatalog (profileText) {
  const read = relative => fs.readFile(path.join(ROOT, relative)).then(value => new Uint8Array(value))
  const wireArtifacts = {
    specBytes: await read('protocol/external-authority/hiverelay-blind-wire-v1.md'),
    abiBytes: await read('protocol/external-authority/hiverelay-blind-abi-v1.cenc'),
    vectorManifestBytes: await read('protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc')
  }
  const clientArtifacts = {
    formatAuthorityBytes: await read('protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'),
    vectorManifestBytes: await read('protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')
  }
  const externalAuthorities = {}
  for (const row of PEERIT_PROFILE_INVENTORY.externalCodecImports) {
    externalAuthorities[row.name] = authenticatePeeritProfileExternalCodecAuthorityV1({
      name: row.name,
      authorityKind: row.authorityKind,
      authorityBinding: row.tupleBinding,
      artifacts: row.authorityKind === 'WIRE_TUPLE_V1' ? wireArtifacts : clientArtifacts,
      assertCanonical (value, name) {
        if (!(value instanceof Uint8Array) || value.byteLength === 0 || name !== row.name) {
          throw new Error(`invalid checker external value for ${row.name}`)
        }
      }
    })
  }
  const compiled = compilePeeritProfileCodecIr(profileText, PEERIT_PROFILE_INVENTORY)
  return createPeeritProfileCodecCatalogFromIr(compiled, PEERIT_PROFILE_INVENTORY, {
    externalAuthorities: Object.freeze(externalAuthorities)
  })
}

class Reader {
  constructor (bytes, code) {
    this.bytes = bytes
    this.offset = 0
    this.code = code
  }

  take (length, field) {
    ok(Number.isSafeInteger(length) && length >= 0 && this.offset + length <= this.bytes.byteLength,
      this.code, `truncated ${field}`)
    const value = this.bytes.slice(this.offset, this.offset + length)
    this.offset += length
    return value
  }

  u8 (field) { return this.take(1, field)[0] }
  u16 (field) {
    const value = this.take(2, field)
    return (value[0] << 8) | value[1]
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

  compact (field) {
    const marker = this.u8(field)
    if (marker <= 0xfc) return marker
    ok(false, this.code, `${field} uses an unsupported/non-canonical long form`)
  }

  end (field) { same(this.offset, this.bytes.byteLength, this.code, `${field} trailing bytes`) }
}

function exactKeys (value, keys, code, field) {
  ok(value && typeof value === 'object' && !Array.isArray(value), code, `${field} must be an object`)
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  ok(actual.length === expected.length && actual.every((entry, index) => entry === expected[index]), code,
    `${field} keys differ: ${actual.join(',')}`)
}
function unique (values, code, field) {
  ok(new Set(values).size === values.length, code, `${field} contains a duplicate`)
}
function findForbiddenMaterial (value, trail = []) {
  if (value == null || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const lowered = key.toLowerCase()
    if (lowered.includes('privateseed') || lowered.includes('privatekey') || lowered === 'secretseed') {
      const error = new Error(`private management material at ${[...trail, key].join('.')}`)
      error.code = 'SECRET_MATERIAL'
      throw error
    }
    if (lowered === 'managementkeyderivation' || lowered === 'deterministicpublicinputderivation') {
      const error = new Error(`public management derivation at ${[...trail, key].join('.')}`)
      error.code = 'PUBLIC_DERIVATION'
      throw error
    }
    findForbiddenMaterial(child, [...trail, key])
  }
}

function canonicalHttpsUrl (value) {
  ok(typeof value === 'string' && /^https:\/\/[a-z0-9.-]+:[1-9][0-9]{0,4}\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/.test(value),
    'BAD_RELAY_URL', 'relay URL is not canonical HTTPS with explicit port/path')
  const port = Number(/^https:\/\/[^/]+:([0-9]+)\//.exec(value)[1])
  ok(port <= 65535 && !value.includes('/./') && !value.includes('/../') && !value.includes('//', 8),
    'BAD_RELAY_URL', 'relay URL has invalid port or path')
}

function resultSignaturePayload (domain, unsigned) {
  return concatBytes(asciiBytes(domain), u64Bytes(unsigned.byteLength), unsigned)
}
function verifyTrailingResultSignature (canonical, relayPublicKey, domain, code) {
  ok(canonical.byteLength > 64, code, 'signed canonical result is too short')
  const unsigned = canonical.subarray(0, canonical.byteLength - 64)
  const signature = canonical.subarray(canonical.byteLength - 64)
  ok(verifyEd25519(relayPublicKey, resultSignaturePayload(domain, unsigned), signature), code,
    `invalid ${domain} signature`)
}

function validateSchemaAuthority (schema) {
  same(schema.$schema, 'https://json-schema.org/draft/2020-12/schema', 'BAD_JSON_SCHEMA', 'schema dialect')
  same(schema.$id, 'https://peerit.site/schemas/peerit-limited-public-inbox-bootstrap-v1.schema.json', 'BAD_SCHEMA_NAME', 'schema id')
  same(schema.title, 'PeeritLimitedPublicInboxBootstrapV1', 'BAD_SCHEMA_NAME', 'schema title')
  ok(!schema.title.includes('AvailabilityBootstrap'), 'BAD_SCHEMA_NAME', 'schema title makes a production availability claim')
  same(schema.$defs.payload.properties.schema.const, 'peerit-limited-public-inbox-bootstrap-v1', 'BAD_SCHEMA_NAME', 'payload schema constant')
  same(schema.$defs.payload.properties.releaseSequence.const, 29, 'BAD_JSON_SCHEMA', 'release sequence constant')
  same(schema.$defs.epochSet.properties.stripeCountLog2.const, 0, 'BAD_JSON_SCHEMA', 'stripe count constant')
  same(schema.$defs.binding.properties.appendAuthMode.const, 0, 'BAD_JSON_SCHEMA', 'OPEN_APPEND constant')
  same(schema.$defs.binding.properties.frameClassBits.const, 3, 'BAD_JSON_SCHEMA', 'frame bits constant')
}

function validateBootstrap (wrapper, options = {}) {
  findForbiddenMaterial(wrapper)
  exactKeys(wrapper, ['payload', 'signature'], 'BAD_BOOTSTRAP_SCHEMA', 'bootstrap wrapper')
  const payload = wrapper.payload
  exactKeys(payload, [
    'schema', 'version', 'artifactClass', 'claimBoundary', 'operatorBoundary', 'topicScope', 'profileId',
    'releaseSequence', 'bootstrapSequence', 'previousBootstrapHash', 'issuedUnixMillis', 'expiresUnixMillis',
    'authorityPublicKey', 'relays', 'inboxEpochSets'
  ], 'BAD_BOOTSTRAP_SCHEMA', 'bootstrap payload')
  same(payload.schema, 'peerit-limited-public-inbox-bootstrap-v1', 'BAD_SCHEMA_NAME', 'bootstrap schema')
  same(payload.version, 1, 'BAD_BOOTSTRAP_SCHEMA', 'bootstrap version')
  ok(['FIXTURE_ONLY', 'LIMITED_PUBLIC_TEST_RELEASE'].includes(payload.artifactClass), 'BAD_ARTIFACT_CLASS', 'artifact class')
  same(payload.claimBoundary, 'LIVE_PUBLIC_TEST_ONLY', 'CLAIM_BOUNDARY', 'claim boundary')
  same(payload.operatorBoundary, 'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS', 'OPERATOR_BOUNDARY', 'operator boundary')
  same(payload.topicScope, 'GLOBAL_PUBLIC_DISCOVERY', 'TOPIC_SCOPE', 'topic scope')
  same(payload.profileId, '@peerit/hiverelay-profile-v1', 'BAD_PROFILE_ID', 'profile id')
  same(payload.releaseSequence, 29, 'BAD_RELEASE_SEQUENCE', 'release sequence')
  ok(U64.test(payload.bootstrapSequence), 'BOOTSTRAP_SEQUENCE', 'bootstrap sequence is not u64 decimal')
  const sequence = BigInt(payload.bootstrapSequence)
  ok((sequence === 0n) === (payload.previousBootstrapHash === null), 'BOOTSTRAP_SEQUENCE', 'sequence/predecessor presence differs')
  if (payload.previousBootstrapHash !== null) hex(payload.previousBootstrapHash, 32, 'BOOTSTRAP_SEQUENCE', 'previousBootstrapHash')
  ok(U64.test(payload.issuedUnixMillis) && U64.test(payload.expiresUnixMillis) &&
    BigInt(payload.expiresUnixMillis) > BigInt(payload.issuedUnixMillis), 'BOOTSTRAP_TIME', 'bootstrap time bounds are invalid')
  ok(BigInt(payload.expiresUnixMillis) - BigInt(payload.issuedUnixMillis) <= MAX_BOOTSTRAP_LIFETIME_MILLIS,
    'BOOTSTRAP_LIFETIME', 'bootstrap lifetime exceeds 31 days')
  const authorityKey = hex(payload.authorityPublicKey, 32, 'BAD_BOOTSTRAP_KEY', 'authorityPublicKey')
  const signature = hex(wrapper.signature, 64, 'BAD_BOOTSTRAP_SIGNATURE', 'signature')
  const signingPayload = concatBytes(asciiBytes(BOOTSTRAP_DOMAIN), Uint8Array.of(0), canonicalJson(payload))
  if (options.skipSignature !== true) {
    ok(verifyEd25519(authorityKey, signingPayload, signature), 'BAD_BOOTSTRAP_SIGNATURE', 'bootstrap signature is invalid')
  }

  ok(Array.isArray(payload.relays) && payload.relays.length === 2, 'RELAY_COUNT', 'bootstrap must have two relays')
  const relayById = new Map()
  for (const relay of payload.relays) {
    exactKeys(relay, ['relayId', 'canonicalDescribeUrl', 'relayPublicKey', 'storeId', 'durabilityContinuityHash', 'descriptorFloor'],
      'BAD_RELAY', `relay ${relay.relayId}`)
    ok(/^[a-z][a-z0-9-]{0,31}$/.test(relay.relayId), 'BAD_RELAY', 'relayId')
    canonicalHttpsUrl(relay.canonicalDescribeUrl)
    hex(relay.relayPublicKey, 32, 'BAD_RELAY', 'relayPublicKey')
    hex(relay.storeId, 32, 'BAD_RELAY', 'storeId')
    hex(relay.durabilityContinuityHash, 32, 'BAD_RELAY', 'durabilityContinuityHash')
    exactKeys(relay.descriptorFloor, ['sequence', 'hash'], 'BAD_RELAY', 'descriptorFloor')
    ok(U64.test(relay.descriptorFloor.sequence), 'BAD_RELAY', 'descriptor sequence')
    hex(relay.descriptorFloor.hash, 32, 'BAD_RELAY', 'descriptor hash')
    relayById.set(relay.relayId, relay)
  }
  unique(payload.relays.map(value => value.relayId), 'DUPLICATE_RELAY', 'relay IDs')
  unique(payload.relays.map(value => value.relayPublicKey), 'DUPLICATE_RELAY', 'relay keys')
  unique(payload.relays.map(value => value.storeId), 'DUPLICATE_RELAY', 'store IDs')
  unique(payload.relays.map(value => value.durabilityContinuityHash), 'DUPLICATE_RELAY', 'continuity hashes')

  ok(Array.isArray(payload.inboxEpochSets) && payload.inboxEpochSets.length >= 1 && payload.inboxEpochSets.length <= 2,
    'EPOCH_SET_COUNT', 'epoch set count')
  if (payload.inboxEpochSets.length === 2) {
    same(payload.inboxEpochSets[1].inboxEpoch + 1, payload.inboxEpochSets[0].inboxEpoch, 'EPOCH_ORDER', 'epoch overlap')
  }
  for (const set of payload.inboxEpochSets) {
    exactKeys(set, ['inboxEpoch', 'stripeCountLog2', 'stripeSelectionKey', 'announcementMasterKey', 'bindings'],
      'BAD_EPOCH_SET', 'epoch set')
    ok(Number.isSafeInteger(set.inboxEpoch) && set.inboxEpoch >= 0 && set.inboxEpoch <= 0xffffffff,
      'BAD_EPOCH_SET', 'inboxEpoch')
    same(set.stripeCountLog2, 0, 'STRIPE_SHAPE', 'stripeCountLog2')
    hex(set.stripeSelectionKey, 32, 'BAD_EPOCH_SET', 'stripeSelectionKey')
    hex(set.announcementMasterKey, 32, 'BAD_EPOCH_SET', 'announcementMasterKey')
    ok(Array.isArray(set.bindings) && set.bindings.length === 2, 'BINDING_COUNT', 'epoch set requires two bindings')
    unique(set.bindings.map(value => value.relayId), 'DUPLICATE_BINDING', 'binding relay IDs')
    unique(set.bindings.map(value => value.physicalTopic), 'DUPLICATE_TOPIC', 'physical topics')
    for (const binding of set.bindings) {
      exactKeys(binding, [
        'inboxEpoch', 'stripeIndex', 'relayId', 'relayPublicKey', 'allocationEpoch', 'createPublicKey',
        'physicalTopic', 'frameClassBits', 'appendAuthMode', 'retentionClass', 'leaseClass', 'createReceiptCanonicalHex'
      ], 'BAD_BINDING', 'inbox binding')
      same(binding.inboxEpoch, set.inboxEpoch, 'BAD_BINDING_EPOCH', 'binding inbox epoch')
      same(binding.stripeIndex, 0, 'STRIPE_SHAPE', 'stripe index')
      same(binding.frameClassBits, 3, 'INBOX_SHAPE', 'frame class bits')
      same(binding.appendAuthMode, 0, 'INBOX_SHAPE', 'append auth mode')
      same(binding.retentionClass, 3, 'INBOX_SHAPE', 'retention class')
      same(binding.leaseClass, 4, 'INBOX_SHAPE', 'lease class')
      const relay = relayById.get(binding.relayId)
      ok(relay != null, 'BAD_BINDING', 'binding references unknown relay')
      same(binding.relayPublicKey, relay.relayPublicKey, 'BAD_BINDING', 'binding relay public key')
      const createPublicKey = hex(binding.createPublicKey, 32, 'BAD_BINDING', 'createPublicKey')
      const expectedTopic = blake2b256(concatBytes(
        asciiBytes('hiverelay.blind.inbox-topic.v1'), u32Bytes(binding.allocationEpoch), createPublicKey
      ))
      const topic = hex(binding.physicalTopic, 32, 'TOPIC_MISMATCH', 'physicalTopic')
      bytesSame(topic, expectedTopic, 'TOPIC_MISMATCH', 'physical topic is not self-certifying')
      const receiptBytes = hex(binding.createReceiptCanonicalHex, null, 'BAD_RECEIPT', 'create receipt')
      let receipt
      try { receipt = decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes) } catch (cause) {
        const error = new Error(`create receipt is not canonical: ${cause.message}`)
        error.code = 'BAD_RECEIPT'
        throw error
      }
      const receiptRelayKey = receipt.relayBinding.relayPublicKey
      verifyTrailingResultSignature(receiptBytes, receiptRelayKey, 'hiverelay.blind.inbox-receipt.v1', 'BAD_RECEIPT_SIGNATURE')
      bytesSame(receiptRelayKey, hex(relay.relayPublicKey, 32), 'BAD_RECEIPT_BINDING', 'receipt relay key')
      bytesSame(receipt.relayBinding.storeId, hex(relay.storeId, 32), 'BAD_RECEIPT_BINDING', 'receipt store')
      bytesSame(receipt.relayBinding.durabilityContinuityHash, hex(relay.durabilityContinuityHash, 32), 'BAD_RECEIPT_BINDING', 'receipt continuity')
      same(String(receipt.relayBinding.descriptorSequence), relay.descriptorFloor.sequence, 'BAD_RECEIPT_BINDING', 'receipt descriptor sequence')
      bytesSame(receipt.relayBinding.descriptorHash, hex(relay.descriptorFloor.hash, 32), 'BAD_RECEIPT_BINDING', 'receipt descriptor hash')
      bytesSame(receipt.topicCommitment, blake2b256(topic), 'BAD_RECEIPT_BINDING', 'receipt topic commitment')
      same(String(receipt.stateRevision), '0', 'BAD_RECEIPT_BINDING', 'create state revision')
      same(receipt.leaseClass, 4, 'BAD_RECEIPT_BINDING', 'create lease class')
      same(receipt.result, 1, 'BAD_RECEIPT_BINDING', 'create result')
    }
  }
  return wrapper
}

function logicalHash (inner) {
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.logical-hash.v1'), u16Bytes(334), u64Bytes(inner.byteLength), inner
  ))
}
function encodingCommitment (inner, logical, sizeClass) {
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.encoding.v1'), Uint8Array.of(1), logical, u16Bytes(334),
    u64Bytes(inner.byteLength), u32Bytes(1), blake2b256(inner), Uint8Array.of(sizeClass)
  ))
}

function bootstrapWrapperHash (bootstrap) {
  return new Uint8Array(createHash('sha256').update(canonicalJson(bootstrap)).digest())
}

function validateBootstrapFloor (floor, bootstrap) {
  exactKeys(floor, [
    'schema', 'version', 'highestAcceptedBootstrapSequence', 'completeSignedWrapperHash'
  ], 'BAD_BOOTSTRAP_FLOOR', 'bootstrap floor')
  same(floor.schema, 'PeeritLimitedPublicInboxBootstrapFloorV1', 'BAD_BOOTSTRAP_FLOOR', 'floor schema')
  same(floor.version, 1, 'BAD_BOOTSTRAP_FLOOR', 'floor version')
  ok(U64.test(floor.highestAcceptedBootstrapSequence), 'BAD_BOOTSTRAP_FLOOR', 'floor sequence')
  const candidateSequence = BigInt(bootstrap.payload.bootstrapSequence)
  const acceptedSequence = BigInt(floor.highestAcceptedBootstrapSequence)
  ok(candidateSequence >= acceptedSequence, 'BOOTSTRAP_ROLLBACK', 'candidate bootstrap is below the persisted floor')
  if (candidateSequence === acceptedSequence) {
    bytesSame(hex(floor.completeSignedWrapperHash, 32, 'BAD_BOOTSTRAP_FLOOR', 'floor wrapper hash'),
      bootstrapWrapperHash(bootstrap), 'BOOTSTRAP_FORK', 'same-sequence bootstrap fork')
  }
}

function decodeRelayBinding (reader) {
  same(reader.u8('relay binding version'), 1, reader.code, 'relay binding version')
  const value = {
    relayPublicKey: reader.take(32, 'relay public key'),
    storeId: reader.take(32, 'store id'),
    descriptorSequence: reader.u64('descriptor sequence'),
    descriptorHash: reader.take(32, 'descriptor hash'),
    durabilityProfileId: reader.u8('durability profile'),
    durabilityContinuityHash: reader.take(32, 'continuity hash'),
    durabilityProfileHash: reader.take(32, 'durability profile hash'),
    restoreEvidenceHeadSequence: reader.u64('restore evidence sequence'),
    restoreEvidenceHeadHash: reader.take(32, 'restore evidence hash')
  }
  same(reader.u8('external witness presence'), 0, reader.code, 'fixture external witness presence')
  return value
}

function inboxReadRequestCommitment (relayPublicKey, physicalTopic, cursor, limit, clientNonce) {
  return blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.request.v1inbox-read'), relayPublicKey, physicalTopic,
    blake2b256(cursor), u16Bytes(limit), clientNonce
  ))
}

function decodeInboxReadRequest (bytes) {
  const reader = new Reader(bytes, 'READ_REQUEST_BINDING')
  same(reader.u8('read request version'), 1, reader.code, 'read request version')
  const physicalTopic = reader.take(32, 'physical topic')
  const cursorLength = reader.compact('cursor length')
  ok(cursorLength <= 128, reader.code, 'cursor length exceeds 128')
  const cursor = reader.take(cursorLength, 'cursor')
  const limit = reader.u16('limit')
  ok(limit >= 1 && limit <= 64, reader.code, 'read limit')
  const clientNonce = reader.take(32, 'client nonce')
  same(reader.u8('admission presence'), 0, reader.code, 'fixture read admission')
  reader.end('InboxReadV1')
  return { physicalTopic, cursor, limit, clientNonce }
}

function decodeInboxReadResult (bytes, relayKey) {
  ok(bytes.byteLength > 64, 'READ_PAGE_SIGNATURE', 'read result is too short')
  const unsigned = bytes.subarray(0, bytes.byteLength - 64)
  const signature = bytes.subarray(bytes.byteLength - 64)
  const reader = new Reader(unsigned, 'READ_PAGE_BINDING')
  same(reader.u8('read result version'), 1, reader.code, 'read result version')
  const relayBindingStart = reader.offset
  const relayBinding = decodeRelayBinding(reader)
  const relayBindingBytes = unsigned.subarray(relayBindingStart, reader.offset)
  const requestNonce = reader.take(32, 'request nonce')
  const requestCommitment = reader.take(32, 'request commitment')
  const snapshotRevision = reader.u64('snapshot revision')
  const entriesStart = reader.offset
  const count = reader.compact('entry count')
  ok(count <= 64, reader.code, 'read entry count')
  const entries = []
  let previous = -1n
  for (let index = 0; index < count; index++) {
    const appendRevision = reader.u64('append revision')
    const frameHash = reader.take(32, 'frame hash')
    const frameClass = reader.u8('frame class')
    const frameBytes = ({ 1: 4096, 2: 16384, 3: 65536 })[frameClass]
    ok(frameBytes != null, reader.code, 'frame class')
    const frame = reader.take(frameBytes, 'frame')
    bytesSame(blake2b256(frame), frameHash, 'READ_ENTRIES_COMMITMENT', 'read entry frame hash')
    ok(appendRevision > previous && appendRevision <= snapshotRevision,
      'READ_ENTRIES_COMMITMENT', 'read entry revision order/snapshot')
    previous = appendRevision
    entries.push({ appendRevision, frameHash, frameClass, frame })
  }
  const entriesSpan = unsigned.subarray(entriesStart, reader.offset)
  const entriesCommitment = reader.take(32, 'entries commitment')
  bytesSame(entriesCommitment, blake2b256(entriesSpan), 'READ_ENTRIES_COMMITMENT', 'entries commitment')
  const cursorPresence = reader.u8('next cursor presence')
  ok(cursorPresence === 0 || cursorPresence === 1, reader.code, 'next cursor presence')
  let nextCursor = null
  if (cursorPresence === 1) {
    const length = reader.compact('next cursor length')
    ok(length <= 128, reader.code, 'next cursor length')
    nextCursor = reader.take(length, 'next cursor')
  }
  reader.end('InboxReadResultV1 unsigned')
  const encodedNextCursor = nextCursor == null
    ? Uint8Array.of(0)
    : concatBytes(Uint8Array.of(1, nextCursor.byteLength), nextCursor)
  const signaturePayloadBytes = concatBytes(
    Uint8Array.of(1), relayBindingBytes, requestNonce, requestCommitment,
    u64Bytes(snapshotRevision), entriesCommitment, encodedNextCursor
  )
  const compressedSignatureValid = verifyEd25519(relayKey,
    resultSignaturePayload('hiverelay.blind.inbox-read-result.v1', signaturePayloadBytes), signature)
  const fullResultDriftSignatureValid = verifyEd25519(relayKey,
    resultSignaturePayload('hiverelay.blind.inbox-read-result.v1', unsigned), signature)
  ok(compressedSignatureValid,
    fullResultDriftSignatureValid ? 'READ_SIGNATURE_PAYLOAD_DRIFT' : 'READ_PAGE_SIGNATURE',
    'InboxReadResultV1 must sign the compressed signature payload, never the full raw-entry result')
  return { relayBinding, requestNonce, requestCommitment, snapshotRevision, entries, nextCursor }
}

function validateReadPages (pages, bootstrap) {
  ok(Array.isArray(pages) && pages.length === 4, 'READ_PAGE_COUNT', 'two signed pages per relay are required')
  const epochSet = bootstrap.payload.inboxEpochSets[0]
  const relayById = new Map(bootstrap.payload.relays.map(value => [value.relayId, value]))
  const bindingById = new Map(epochSet.bindings.map(value => [value.relayId, value]))
  const authenticatedFrames = new Map()
  for (const relayId of epochSet.bindings.map(value => value.relayId)) {
    const relay = relayById.get(relayId)
    const binding = bindingById.get(relayId)
    const scoped = pages.filter(value => value.relayId === relayId).sort((a, b) => a.pageIndex - b.pageIndex)
    ok(scoped.length === 2, 'READ_PAGE_COUNT', `two pages for ${relayId}`)
    let priorCursor = new Uint8Array(0)
    let snapshot = null
    for (let index = 0; index < scoped.length; index++) {
      const page = scoped[index]
      exactKeys(page, ['relayId', 'pageIndex', 'requestCanonicalHex', 'requestCommitment', 'resultCanonicalHex'],
        'BAD_READ_PAGE', 'read page')
      same(page.pageIndex, index, 'CURSOR_CHAIN', 'page index')
      const requestBytes = hex(page.requestCanonicalHex, null, 'READ_REQUEST_BINDING', 'read request bytes')
      const request = decodeInboxReadRequest(requestBytes)
      bytesSame(request.physicalTopic, hex(binding.physicalTopic, 32), 'READ_REQUEST_BINDING', 'read request topic')
      bytesSame(request.cursor, priorCursor, 'CURSOR_CHAIN', 'read continuation cursor')
      same(request.limit, 1, 'READ_REQUEST_BINDING', 'bounded read limit')
      const expectedCommitment = inboxReadRequestCommitment(
        hex(relay.relayPublicKey, 32), request.physicalTopic, request.cursor, request.limit, request.clientNonce
      )
      bytesSame(hex(page.requestCommitment, 32, 'READ_REQUEST_BINDING', 'read commitment'), expectedCommitment,
        'READ_REQUEST_BINDING', 'read request commitment')
      const result = decodeInboxReadResult(
        hex(page.resultCanonicalHex, null, 'READ_PAGE_SIGNATURE', 'read result bytes'),
        hex(relay.relayPublicKey, 32)
      )
      bytesSame(result.relayBinding.relayPublicKey, hex(relay.relayPublicKey, 32),
        'READ_PAGE_BINDING', 'result relay key')
      bytesSame(result.relayBinding.storeId, hex(relay.storeId, 32), 'READ_PAGE_BINDING', 'result store')
      same(String(result.relayBinding.descriptorSequence), relay.descriptorFloor.sequence,
        'READ_PAGE_BINDING', 'result descriptor sequence')
      bytesSame(result.relayBinding.descriptorHash, hex(relay.descriptorFloor.hash, 32),
        'READ_PAGE_BINDING', 'result descriptor hash')
      bytesSame(result.relayBinding.durabilityContinuityHash, hex(relay.durabilityContinuityHash, 32),
        'READ_PAGE_BINDING', 'result continuity')
      bytesSame(result.requestNonce, request.clientNonce, 'READ_REQUEST_BINDING', 'result nonce correlation')
      bytesSame(result.requestCommitment, expectedCommitment, 'READ_REQUEST_BINDING', 'result commitment correlation')
      if (snapshot == null) snapshot = result.snapshotRevision
      else same(result.snapshotRevision, snapshot, 'CURSOR_CHAIN', 'snapshot-pinned continuation')
      if (index === 0) {
        same(result.entries.length, 1, 'READ_PAGE_COUNT', 'first page entry count')
        ok(result.nextCursor != null && result.nextCursor.byteLength > 0, 'CURSOR_CHAIN', 'first page continuation')
        authenticatedFrames.set(relayId, result.entries[0])
      } else {
        same(result.entries.length, 0, 'READ_PAGE_COUNT', 'continuation page entry count')
        same(result.nextCursor, null, 'CURSOR_CHAIN', 'terminal continuation')
      }
      priorCursor = result.nextCursor == null ? new Uint8Array(0) : result.nextCursor
    }
  }
  same(authenticatedFrames.size, 2, 'READ_PAGE_COUNT', 'authenticated frame sources')
  return authenticatedFrames
}

function openCellResult (cell, cap, inner) {
  const readback = cell.capabilityBoundGet
  ok(readback && typeof readback === 'object' && typeof readback.getResultCanonicalHex === 'string',
    'READBACK_REQUIRED', 'capability-bound GET result is required')
  exactKeys(readback, [
    'familyId', 'operationId', 'requestCanonicalHex', 'requestCommitment', 'getResultCanonicalHex'
  ], 'READBACK_SHORTCUT', 'capability-bound GET evidence')
  same(readback.familyId, 2, 'READ_REQUEST_BINDING', 'CELL family')
  same(readback.operationId, 2, 'READ_REQUEST_BINDING', 'CELL.GET operation')
  const request = hex(readback.requestCanonicalHex, null, 'READ_REQUEST_BINDING', 'GetCellV1')
  same(request.byteLength, 66, 'READ_REQUEST_BINDING', 'GetCellV1 byte length')
  same(request[0], 1, 'READ_REQUEST_BINDING', 'GetCellV1 version')
  bytesSame(request.subarray(1, 33), cap.storageSlot, 'READ_REQUEST_BINDING', 'GetCellV1 slot')
  same(request[65], 0, 'READ_REQUEST_BINDING', 'GetCellV1 admission presence')
  const clientNonce = request.subarray(33, 65)
  const expectedCommitment = blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.request.v1cell-get'), cap.relayPublicKey, cap.storageSlot, clientNonce
  ))
  bytesSame(hex(readback.requestCommitment, 32, 'READ_REQUEST_BINDING', 'CELL.GET commitment'),
    expectedCommitment, 'READ_REQUEST_BINDING', 'CELL.GET commitment')
  const result = hex(readback.getResultCanonicalHex, null, 'READBACK_REQUIRED', 'GetCellResultV1')
  same(result.byteLength, 4098, 'READBACK_REQUIRED', 'GetCellResultV1 byte length')
  same(result[0], 1, 'READBACK_REQUIRED', 'GetCellResultV1 version')
  same(result[1], cap.sizeClass, 'READBACK_REQUIRED', 'GetCellResultV1 size class')
  const blob = result.subarray(2)
  const blobHash = blake2b256(blob)
  bytesSame(blobHash, cap.expectedCellBlobHash, 'CELL_BLOB_HASH', 'GET blob/cap hash')
  bytesSame(blobHash, hex(cell.cellBlobHash, 32), 'CELL_BLOB_HASH', 'GET blob/vector hash')
  same(blob[0], 1, 'CELL_BLOB_FORMAT', 'Cell blob version')
  const nonce = blob.subarray(1, 13)
  const ciphertext = blob.subarray(13, blob.byteLength - 16)
  const tag = blob.subarray(blob.byteLength - 16)
  const aad = concatBytes(asciiBytes('hiverelay.blind.cell.v1'), Uint8Array.of(1, cap.sizeClass), cap.storageSlot)
  let plaintext
  try {
    const decipher = createDecipheriv('aes-256-gcm', cap.cellKey, nonce, { authTagLength: 16 })
    decipher.setAAD(Buffer.from(aad), { plaintextLength: ciphertext.byteLength })
    decipher.setAuthTag(Buffer.from(tag))
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch (cause) {
    const error = new Error(`Cell authentication failed: ${cause.message}`); error.code = 'CELL_AUTHENTICATION'; throw error
  }
  const contentLength = plaintext.readUInt32BE(0)
  ok(contentLength <= plaintext.byteLength - 4, 'CELL_BLOB_FORMAT', 'Cell content length')
  const reconstructed = plaintext.subarray(4, 4 + contentLength)
  bytesSame(reconstructed, inner, 'READBACK_REQUIRED', 'authenticated Cell reconstruction')
  return reconstructed
}

function validateProtocolVector (vector, bootstrap, profileCatalog) {
  same(vector.schema, 'peerit-seq29-limited-public-test-positive-vector-v1', 'BAD_VECTOR_SCHEMA', 'vector schema')
  same(vector.version, 1, 'BAD_VECTOR_SCHEMA', 'vector version')
  same(vector.fixtureOnly, true, 'BAD_VECTOR_SCHEMA', 'fixture-only marker')
  validateBootstrapFloor(vector.bootstrapFloor, bootstrap)
  same(vector.issuance.expectedCellPutCount, 2, 'ISSUANCE_COUNT', 'CELL.PUT count')
  same(vector.issuance.expectedCellGetReadbackCount, 2, 'ISSUANCE_COUNT', 'CELL.GET count')
  same(vector.issuance.expectedInboxAppendCount, 2, 'ISSUANCE_COUNT', 'INBOX.APPEND count')
  same(vector.issuance.emitterMode, 'INLINE_ONLY', 'ANNOUNCEMENT_MODE', 'emitter mode')

  const inner = hex(vector.inner.canonicalHex, null, 'BAD_INNER', 'inner canonical bytes')
  same(vector.inner.codec, 334, 'BAD_INNER', 'inner codec')
  same(inner.byteLength, vector.inner.byteLength, 'BAD_INNER', 'inner byte length')
  ok(inner.byteLength >= 8 && inner.byteLength <= 1048519, 'BAD_INNER', 'inner length range')
  same((inner[0] << 8) | inner[1], 334, 'BAD_INNER', 'inner tag')
  same(inner[2], 1, 'BAD_INNER', 'inner version')
  const payloadLength = inner[3] * 0x1000000 + inner[4] * 0x10000 + inner[5] * 0x100 + inner[6]
  same(payloadLength + 7, inner.byteLength, 'BAD_INNER', 'inner framing length')
  const expectedLogical = logicalHash(inner)
  bytesSame(expectedLogical, hex(vector.inner.logicalHash, 32), 'BAD_INNER', 'logical hash')
  const expectedEncoding = encodingCommitment(inner, expectedLogical, 1)
  bytesSame(expectedEncoding, hex(vector.inner.encodingCommitment, 32), 'BAD_INNER', 'encoding commitment')

  ok(Array.isArray(vector.cells) && vector.cells.length === 2, 'CELL_BINDING_COUNT', 'two Cell bindings required')
  let reconstructed = 0
  for (const cell of vector.cells) {
    bytesSame(hex(cell.logicalHash, 32), expectedLogical, 'CELL_EQUALITY', 'Cell logical hash')
    bytesSame(hex(cell.encodingCommitment, 32), expectedEncoding, 'CELL_EQUALITY', 'Cell encoding commitment')
    same(cell.sizeClass, 1, 'CELL_EQUALITY', 'smallest Cell class')
    const capBytes = hex(cell.readCapabilityCanonicalHex, null, 'BAD_READ_CAP', 'ReadCellCapV1')
    let cap
    try { cap = decodeBlindExternalProfileValueV1('ReadCellCapV1', capBytes) } catch (cause) {
      const error = new Error(`bad ReadCellCapV1: ${cause.message}`); error.code = 'BAD_READ_CAP'; throw error
    }
    bytesSame(cap.relayPublicKey, hex(cell.relayPublicKey, 32), 'CELL_EQUALITY', 'read cap relay')
    bytesSame(cap.expectedCellBlobHash, hex(cell.cellBlobHash, 32), 'CELL_EQUALITY', 'read cap blob hash')
    same(cap.sizeClass, cell.sizeClass, 'CELL_EQUALITY', 'read cap size class')
    const expectedSlot = blake2b256(concatBytes(
      asciiBytes('hiverelay.blind.slot.v1'), u32Bytes(cell.allocationEpoch), hex(cell.createPublicKey, 32)
    ))
    bytesSame(cap.storageSlot, expectedSlot, 'CELL_EQUALITY', 'read cap self-certifying slot')
    const receiptBytes = hex(cell.relayReceiptCanonicalHex, null, 'BAD_CELL_RECEIPT', 'BlindReceiptV1')
    let receipt
    try { receipt = decodeBlindExternalProfileValueV1('BlindReceiptV1', receiptBytes) } catch (cause) {
      const error = new Error(`bad BlindReceiptV1: ${cause.message}`); error.code = 'BAD_CELL_RECEIPT'; throw error
    }
    verifyTrailingResultSignature(receiptBytes, receipt.relayBinding.relayPublicKey,
      'hiverelay.blind.cell-receipt.v1', 'BAD_CELL_RECEIPT_SIGNATURE')
    bytesSame(receipt.relayBinding.relayPublicKey, cap.relayPublicKey, 'CELL_EQUALITY', 'receipt relay')
    bytesSame(receipt.slotCommitment, blake2b256(cap.storageSlot), 'CELL_EQUALITY', 'receipt slot commitment')
    bytesSame(receipt.cellBlobHash, hex(cell.cellBlobHash, 32), 'CELL_EQUALITY', 'receipt blob hash')
    bytesSame(receipt.allocationCommitment, hex(cell.allocationCommitment, 32), 'CELL_EQUALITY', 'allocation commitment')
    same(receipt.sizeClass, cell.sizeClass, 'CELL_EQUALITY', 'receipt size class')
    same(receipt.allocationEpoch, cell.allocationEpoch, 'CELL_EQUALITY', 'receipt allocation epoch')
    same(receipt.leaseEpoch, cell.leaseEpoch, 'CELL_EQUALITY', 'receipt lease epoch')
    same(receipt.result, 1, 'CELL_EQUALITY', 'receipt STORED result')
    openCellResult(cell, cap, inner)
    reconstructed++
  }
  ok(reconstructed >= 1, 'READBACK_REQUIRED', 'at least one replica must reconstruct')
  unique(vector.cells.map(value => value.relayPublicKey), 'DUPLICATE_CELL_RELAY', 'Cell relay keys')

  const author = vector.authorBind
  same(author.manifestTag, 3, 'AUTHOR_BIND_TAG', 'AuthorBind manifest tag')
  ok(U64.test(author.authorSequence), 'AUTHOR_CHAIN', 'author sequence')
  ok((BigInt(author.authorSequence) === 0n) === (author.previousAuthorRecordId === null), 'AUTHOR_CHAIN', 'author predecessor')
  const authorPrefix = hex(author.signingPrefixHex, null, 'BAD_AUTHOR_BIND_BYTES', 'AuthorBind prefix')
  const authorSignature = hex(author.signature, 64, 'BAD_AUTHOR_BIND_SIGNATURE', 'AuthorBind signature')
  const authorBytes = hex(author.canonicalHex, null, 'BAD_AUTHOR_BIND_BYTES', 'AuthorBind canonical')
  bytesSame(authorBytes, concatBytes(authorPrefix, authorSignature), 'BAD_AUTHOR_BIND_BYTES', 'AuthorBind complete bytes')
  same(authorBytes.byteLength, author.byteLength, 'BAD_AUTHOR_BIND_BYTES', 'AuthorBind byte length')
  ok(authorBytes.byteLength <= 10000, 'INLINE_TOO_LARGE', 'AuthorBind exceeds Sequence 29 INLINE cap')
  same(sha256Hex(authorBytes), author.canonicalSha256, 'BAD_AUTHOR_BIND_BYTES', 'AuthorBind SHA-256')
  ok(verifyEd25519(hex(author.authorPublicKey, 32), concatBytes(asciiBytes('peerit.hiverelay.author-bind.v1'), authorPrefix), authorSignature),
    'BAD_AUTHOR_BIND_SIGNATURE', 'AuthorBind signature')
  const manifestId = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.manifest-record-id.v1'), u16Bytes(3), u64Bytes(authorBytes.byteLength), authorBytes
  ))
  bytesSame(manifestId, hex(author.manifestRecordId, 32), 'MANIFEST_ID', 'AuthorBind manifest ID')

  const announcement = vector.announcement
  same(announcement.version, 1, 'BAD_ANNOUNCEMENT', 'announcement version')
  same(announcement.manifestTag, 3, 'BAD_ANNOUNCEMENT', 'announcement tag')
  same(announcement.manifestMode, 1, 'ANNOUNCEMENT_MODE', 'Sequence 29 announcement mode')
  ok(Array.isArray(announcement.manifestReadCaps) && announcement.manifestReadCaps.length === 0,
    'ANNOUNCEMENT_MODE', 'INLINE announcement must have no read caps')
  const inlineRecord = hex(announcement.manifestRecordCanonicalHex, null, 'BAD_ANNOUNCEMENT', 'inline manifest')
  bytesSame(inlineRecord, authorBytes, 'BAD_ANNOUNCEMENT', 'INLINE AuthorBind equality')
  bytesSame(hex(announcement.manifestRecordId, 32), manifestId, 'MANIFEST_ID', 'announcement manifest ID')
  const announcementPrefix = hex(announcement.signingPrefixHex, null, 'BAD_ANNOUNCEMENT_BYTES', 'announcement prefix')
  const announcementSignature = hex(announcement.signature, 64, 'BAD_ANNOUNCEMENT_SIGNATURE', 'announcement signature')
  const announcementBytes = hex(announcement.canonicalHex, null, 'BAD_ANNOUNCEMENT_BYTES', 'announcement canonical')
  bytesSame(announcementBytes, concatBytes(announcementPrefix, announcementSignature), 'BAD_ANNOUNCEMENT_BYTES', 'announcement complete bytes')
  same(announcementBytes.byteLength, announcement.byteLength, 'BAD_ANNOUNCEMENT_BYTES', 'announcement byte length')
  ok(announcementBytes.byteLength <= 12288, 'BAD_ANNOUNCEMENT_BYTES', 'announcement maximum')
  same(sha256Hex(announcementBytes), announcement.canonicalSha256, 'BAD_ANNOUNCEMENT_BYTES', 'announcement SHA-256')
  ok(verifyEd25519(hex(announcement.publisherPublicKey, 32),
    concatBytes(asciiBytes('peerit.hiverelay.announcement.v1'), announcementPrefix), announcementSignature),
  'BAD_ANNOUNCEMENT_SIGNATURE', 'announcement signature')
  const signedId = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.signed-announcement-id.v1'), u64Bytes(announcementBytes.byteLength), announcementBytes
  ))
  bytesSame(signedId, hex(announcement.signedAnnouncementId, 32), 'SIGNED_ANNOUNCEMENT_ID', 'signed announcement ID')

  const authenticatedFrames = validateReadPages(vector.readPages, bootstrap)
  validateFrames(vector.frames, bootstrap, announcementBytes, authenticatedFrames)
  validateCursor(vector.cursor)
  validateManagementCustody(vector.managementCustody, bootstrap, profileCatalog)
  validateRetry(vector.retry)
  validateConsent(vector.consent)
  return vector
}

function rotl32 (value, shift) { return ((value << shift) | (value >>> (32 - shift))) >>> 0 }
function quarterRound (state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl32(state[d] ^ state[a], 16)
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl32(state[b] ^ state[c], 12)
  state[a] = (state[a] + state[b]) >>> 0; state[d] = rotl32(state[d] ^ state[a], 8)
  state[c] = (state[c] + state[d]) >>> 0; state[b] = rotl32(state[b] ^ state[c], 7)
}
function hchacha20 (key, nonce16) {
  const input = Buffer.concat([Buffer.from('expand 32-byte k', 'ascii'), Buffer.from(key), Buffer.from(nonce16)])
  const state = new Uint32Array(16)
  for (let index = 0; index < 16; index++) state[index] = input.readUInt32LE(index * 4)
  for (let round = 0; round < 10; round++) {
    quarterRound(state, 0, 4, 8, 12); quarterRound(state, 1, 5, 9, 13)
    quarterRound(state, 2, 6, 10, 14); quarterRound(state, 3, 7, 11, 15)
    quarterRound(state, 0, 5, 10, 15); quarterRound(state, 1, 6, 11, 12)
    quarterRound(state, 2, 7, 8, 13); quarterRound(state, 3, 4, 9, 14)
  }
  const output = Buffer.alloc(32)
  ;[0, 1, 2, 3, 12, 13, 14, 15].forEach((source, index) => output.writeUInt32LE(state[source], index * 4))
  return output
}
function xchachaOpen (key, nonce, aad, sealed) {
  const subkey = hchacha20(key, nonce.subarray(0, 16))
  const nonce12 = Buffer.concat([Buffer.alloc(4), Buffer.from(nonce.subarray(16))])
  const ciphertext = sealed.subarray(0, sealed.byteLength - 16)
  const tag = sealed.subarray(sealed.byteLength - 16)
  const decipher = createDecipheriv('chacha20-poly1305', subkey, nonce12, { authTagLength: 16 })
  decipher.setAAD(Buffer.from(aad), { plaintextLength: ciphertext.byteLength })
  decipher.setAuthTag(Buffer.from(tag))
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

function x25519PrivateKey (raw) {
  return createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(raw)]),
    format: 'der', type: 'pkcs8'
  })
}
function x25519PublicKey (raw) {
  return createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(raw)]),
    format: 'der', type: 'spki'
  })
}
function gfMultiply (left, right) {
  let a = left
  let b = right
  let out = 0
  for (let bit = 0; bit < 8; bit++) {
    if (b & 1) out ^= a
    const high = a & 0x80
    a = (a << 1) & 0xff
    if (high) a ^= 0x1b
    b >>>= 1
  }
  return out
}
function gfPower (value, exponent) {
  let out = 1
  let base = value
  let power = exponent
  while (power > 0) {
    if (power & 1) out = gfMultiply(out, base)
    base = gfMultiply(base, base)
    power >>>= 1
  }
  return out
}
function reconstructTwoShares (left, right) {
  const denominator = left.index ^ right.index
  ok(denominator !== 0, 'CUSTODY_RECONSTRUCTION', 'duplicate Shamir coordinates')
  const inverse = gfPower(denominator, 254)
  const secret = new Uint8Array(32)
  for (let index = 0; index < 32; index++) {
    const coefficient = gfMultiply(left.bytes[index] ^ right.bytes[index], inverse)
    secret[index] = left.bytes[index] ^ gfMultiply(coefficient, left.index)
  }
  return secret
}

function validateLimitedManagementPlaintext (plaintext, vector, bootstrap, profileCatalog) {
  const reader = new Reader(plaintext, 'CUSTODY_RECONSTRUCTION')
  const prefixStart = reader.offset
  same(reader.u8('limited bundle version'), 1, reader.code, 'limited bundle version')
  same(reader.u64('release sequence'), 29n, reader.code, 'limited bundle release sequence')
  reader.take(32, 'profile pin hash')
  bytesSame(reader.take(32, 'signed bootstrap hash'), bootstrapWrapperHash(bootstrap),
    reader.code, 'custody/signed bootstrap hash')
  same(reader.u64('bootstrap sequence'), BigInt(bootstrap.payload.bootstrapSequence),
    reader.code, 'custody/bootstrap sequence')
  same(reader.u32('current inbox epoch'), bootstrap.payload.inboxEpochSets[0].inboxEpoch,
    reader.code, 'custody current epoch')
  const count = reader.u8('management entry count')
  ok(count === 2 || count === 4, 'CUSTODY_CARDINALITY', 'limited management entries must be 2 or 4')
  same(count, vector.currentEntryCount + vector.previousEntryCount, 'CUSTODY_CARDINALITY', 'declared management counts')
  const entries = []
  for (let index = 0; index < count; index++) {
    const length = reader.u16('management entry length')
    ok(length >= 1 && length <= 8192, reader.code, 'canonical InboxManagementEntryV1 length')
    entries.push(reader.take(length, 'canonical InboxManagementEntryV1'))
  }
  unique(entries.map(value => sha256Hex(value)), 'CUSTODY_CARDINALITY', 'management entries')
  const expectedSets = [bootstrap.payload.inboxEpochSets[0]]
  if (bootstrap.payload.inboxEpochSets.length === 2) expectedSets.push(bootstrap.payload.inboxEpochSets[1])
  same(vector.previousEntryCount, expectedSets.length === 2 ? 2 : 0,
    'CUSTODY_CARDINALITY', 'custody previous entries/bootstrap epoch sets')
  const allSeeds = []
  const allAuthorities = []
  for (let index = 0; index < entries.length; index++) {
    const expectedSet = expectedSets[index < 2 ? 0 : 1]
    ok(expectedSet != null, 'CUSTODY_ENTRY_BINDING', 'management entry has no admitted epoch set')
    let entry
    let binding
    try {
      entry = profileCatalog.InboxManagementEntryV1.decode(entries[index])
      bytesSame(profileCatalog.InboxManagementEntryV1.encode(entry), entries[index],
        'CUSTODY_ENTRY_BINDING', 'management entry canonical decode/re-encode')
      binding = profileCatalog.InboxStripeBindingV1.decode(entry.bindingBytes)
      bytesSame(profileCatalog.InboxStripeBindingV1.encode(binding), entry.bindingBytes,
        'CUSTODY_ENTRY_BINDING', 'management binding canonical decode/re-encode')
    } catch (cause) {
      const error = new Error(`management entry is not canonical: ${cause.message}`)
      error.code = 'CUSTODY_ENTRY_BINDING'
      throw error
    }
    same(entry.inboxEpoch, expectedSet.inboxEpoch, 'CUSTODY_ENTRY_BINDING', 'management entry epoch/order')
    same(entry.stripeIndex, 0, 'CUSTODY_ENTRY_BINDING', 'management entry stripe')
    const orderedBootstrapBindings = [...expectedSet.bindings].sort((left, right) => {
      const leftKey = left.relayPublicKey + left.physicalTopic
      const rightKey = right.relayPublicKey + right.physicalTopic
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
    })
    const expectedBootstrapBinding = orderedBootstrapBindings[index % 2]
    ok(expectedBootstrapBinding != null, 'CUSTODY_ENTRY_BINDING', 'management entry follows canonical relay/topic order')
    bytesSame(entry.bindingHash, blake2b256(concatBytes(
      asciiBytes('peerit.hiverelay.inbox-management-binding.v1'),
      u64Bytes(entry.bindingBytes.byteLength), entry.bindingBytes
    )), 'CUSTODY_ENTRY_BINDING', 'management binding hash')
    same(binding.inboxEpoch, entry.inboxEpoch, 'CUSTODY_ENTRY_BINDING', 'entry/binding epoch')
    same(binding.stripeIndex, entry.stripeIndex, 'CUSTODY_ENTRY_BINDING', 'entry/binding stripe')
    bytesSame(binding.relayPublicKey, entry.relayPublicKey, 'CUSTODY_ENTRY_BINDING', 'entry/binding relay')
    same(binding.inboxEpoch, expectedBootstrapBinding.inboxEpoch, 'CUSTODY_ENTRY_BINDING', 'binding/bootstrap epoch')
    same(binding.stripeIndex, expectedBootstrapBinding.stripeIndex, 'CUSTODY_ENTRY_BINDING', 'binding/bootstrap stripe')
    bytesSame(binding.relayPublicKey, hex(expectedBootstrapBinding.relayPublicKey, 32),
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap relay')
    same(binding.allocationEpoch, expectedBootstrapBinding.allocationEpoch,
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap allocation epoch')
    bytesSame(binding.createPublicKey, hex(expectedBootstrapBinding.createPublicKey, 32),
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap create key')
    bytesSame(binding.physicalTopic, hex(expectedBootstrapBinding.physicalTopic, 32),
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap topic')
    same(binding.frameClassBits, expectedBootstrapBinding.frameClassBits,
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap frame classes')
    same(binding.appendAuthMode, expectedBootstrapBinding.appendAuthMode,
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap append mode')
    same(binding.retentionClass, expectedBootstrapBinding.retentionClass,
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap retention')
    same(binding.leaseClass, expectedBootstrapBinding.leaseClass,
      'CUSTODY_ENTRY_BINDING', 'binding/bootstrap lease')
    const expectedReceipt = hex(expectedBootstrapBinding.createReceiptCanonicalHex, null,
      'CUSTODY_ENTRY_BINDING', 'bootstrap create receipt')
    bytesSame(binding.createReceipt, expectedReceipt, 'CUSTODY_ENTRY_BINDING', 'binding/bootstrap create receipt')
    bytesSame(entry.latestReceipt, expectedReceipt, 'CUSTODY_ENTRY_BINDING', 'entry latest/bootstrap create receipt')
    let latestReceipt
    try { latestReceipt = decodeBlindExternalProfileValueV1('InboxReceiptV1', entry.latestReceipt) } catch (cause) {
      const error = new Error(`management latest receipt is not canonical: ${cause.message}`)
      error.code = 'CUSTODY_ENTRY_BINDING'
      throw error
    }
    same(entry.latestRevision, latestReceipt.stateRevision,
      'CUSTODY_ENTRY_BINDING', 'entry/latest receipt revision')
    same(entry.leaseEpoch, latestReceipt.leaseEpoch,
      'CUSTODY_ENTRY_BINDING', 'entry/latest receipt lease epoch')
    bytesSame(ed25519PublicFromSeed(entry.createPrivateSeed), binding.createPublicKey,
      'CUSTODY_ENTRY_BINDING', 'CREATE seed/public key')
    bytesSame(ed25519PublicFromSeed(entry.renewPrivateSeed), entry.renewPublicKey,
      'CUSTODY_ENTRY_BINDING', 'RENEW seed/public key')
    bytesSame(ed25519PublicFromSeed(entry.closePrivateSeed), entry.closePublicKey,
      'CUSTODY_ENTRY_BINDING', 'CLOSE seed/public key')
    for (const seed of [entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed]) {
      ok(seed.some(value => value !== 0), 'CUSTODY_ENTRY_BINDING', 'management seed must be nonzero')
    }
    unique([entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed].map(bytesToHex),
      'CUSTODY_ENTRY_BINDING', 'entry management seeds')
    allSeeds.push(entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed)
    allAuthorities.push(binding.createPublicKey, entry.renewPublicKey, entry.closePublicKey)
  }
  unique(allSeeds.map(bytesToHex), 'CUSTODY_ENTRY_BINDING', 'all management seeds')
  unique(allAuthorities.map(bytesToHex), 'CUSTODY_ENTRY_BINDING', 'all management authorities')
  reader.u64('created Unix millis')
  const prefix = plaintext.subarray(prefixStart, reader.offset)
  const commitment = reader.take(32, 'bundle commitment')
  bytesSame(commitment, blake2b256(concatBytes(
    asciiBytes(LIMITED_MANAGEMENT_BUNDLE_DOMAIN), u64Bytes(prefix.byteLength), prefix
  )), reader.code, 'limited management bundle commitment')
  reader.end('PeeritLimitedPublicInboxManagementBundleV1')
}

function validateManagementCustody (vector, bootstrap, profileCatalog) {
  exactKeys(vector, [
    'schema', 'version', 'bundleName', 'envelopeName', 'bundleKind', 'plaintextCodec',
    'currentEntryCount', 'previousEntryCount', 'seedRoles', 'appendAuthMode', 'threshold',
    'totalShares', 'envelopeCanonicalHex', 'plaintextSha256', 'fixtureCustodianPrivateKeys',
    'fixtureCustodianPublicKeys'
  ], 'BAD_CUSTODY_CONTRACT', 'management custody vector')
  same(vector.schema, 'PeeritLimitedPublicInboxManagementCustodyV1', 'BAD_CUSTODY_CONTRACT', 'custody schema')
  same(vector.version, 1, 'BAD_CUSTODY_CONTRACT', 'custody version')
  same(vector.bundleName, 'PeeritLimitedPublicInboxManagementBundleV1', 'BAD_CUSTODY_CONTRACT', 'limited bundle name')
  same(vector.envelopeName, 'PeeritLimitedPublicInboxCustodyEnvelopeV1', 'BAD_CUSTODY_CONTRACT', 'limited envelope name')
  same(vector.bundleKind, LIMITED_MANAGEMENT_BUNDLE_KIND, 'BAD_CUSTODY_CONTRACT', 'limited bundle kind')
  same(vector.plaintextCodec, LIMITED_MANAGEMENT_PLAINTEXT_CODEC, 'BAD_CUSTODY_CONTRACT', 'limited plaintext codec')
  same(vector.currentEntryCount, 2, 'CUSTODY_CARDINALITY', 'current management entries')
  ok(vector.previousEntryCount === 0 || vector.previousEntryCount === 2,
    'CUSTODY_CARDINALITY', 'previous management entries')
  same(vector.seedRoles.join(','), 'CREATE,RENEW,CLOSE', 'CUSTODY_APPEND_SEED', 'management seed roles')
  same(vector.appendAuthMode, 'OPEN_APPEND', 'CUSTODY_APPEND_SEED', 'OPEN_APPEND has no append seed')
  same(vector.threshold, 2, 'CUSTODY_THRESHOLD', 'custody threshold')
  same(vector.totalShares, 3, 'CUSTODY_THRESHOLD', 'custody share count')
  ok(Array.isArray(vector.fixtureCustodianPrivateKeys) && vector.fixtureCustodianPrivateKeys.length >= 2,
    'CUSTODY_THRESHOLD', 'two fixture custodian keys are required for reconstruction')
  ok(Array.isArray(vector.fixtureCustodianPublicKeys) && vector.fixtureCustodianPublicKeys.length === 3,
    'CUSTODY_THRESHOLD', 'three custodian public keys are required')

  const bytes = hex(vector.envelopeCanonicalHex, null, 'CUSTODY_RECONSTRUCTION', 'limited custody envelope')
  const reader = new Reader(bytes, 'CUSTODY_RECONSTRUCTION')
  const envelopePrefixStart = reader.offset
  same(reader.u8('envelope version'), 1, reader.code, 'limited envelope version')
  const custodySetId = reader.take(32, 'custody set id')
  same(reader.u8('bundle kind'), LIMITED_MANAGEMENT_BUNDLE_KIND, reader.code, 'limited bundle kind')
  same(reader.u16('plaintext codec'), LIMITED_MANAGEMENT_PLAINTEXT_CODEC, reader.code, 'limited plaintext codec')
  const plaintextLength = reader.u64('plaintext length')
  ok(plaintextLength >= 1n && plaintextLength <= 16777216n, reader.code, 'plaintext length')
  const plaintextHash = reader.take(32, 'plaintext hash')
  const keyCommitment = reader.take(32, 'key commitment')
  const sealedPayloadLength = reader.u32('sealed payload length')
  same(BigInt(sealedPayloadLength), plaintextLength + 16n, reader.code, 'sealed payload length')
  const payloadAad = bytes.subarray(envelopePrefixStart, reader.offset)
  const payloadNonce = reader.take(24, 'payload nonce')
  const sealedPayload = reader.take(sealedPayloadLength, 'sealed payload')
  const sealedPayloadHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-sealed-payload.v1'), u64Bytes(sealedPayload.byteLength), sealedPayload
  ))
  same(reader.u8('share count'), 3, 'CUSTODY_THRESHOLD', 'encrypted share count')
  const shares = []
  for (let index = 0; index < 3; index++) {
    const sharePrefixStart = reader.offset
    same(reader.u8('share version'), 1, reader.code, 'share version')
    bytesSame(reader.take(32, 'share custody set'), custodySetId, reader.code, 'share custody set')
    same(reader.u8('share bundle kind'), LIMITED_MANAGEMENT_BUNDLE_KIND, reader.code, 'share bundle kind')
    const shareIndex = reader.u8('share index')
    same(shareIndex, index + 1, reader.code, 'ordered share index')
    same(reader.u8('share threshold'), 2, 'CUSTODY_THRESHOLD', 'share threshold')
    same(reader.u8('share total'), 3, 'CUSTODY_THRESHOLD', 'share total')
    bytesSame(reader.take(32, 'share key commitment'), keyCommitment, reader.code, 'share key commitment')
    bytesSame(reader.take(32, 'share payload hash'), sealedPayloadHash, reader.code, 'share payload hash')
    const custodianPublicKey = reader.take(32, 'custodian public key')
    const ephemeralPublicKey = reader.take(32, 'ephemeral public key')
    const nonce = reader.take(24, 'share nonce')
    const shareAad = bytes.subarray(sharePrefixStart, reader.offset)
    const sealedShare = reader.take(48, 'sealed share')
    shares.push({ shareIndex, custodianPublicKey, ephemeralPublicKey, nonce, shareAad, sealedShare })
  }
  reader.end('PeeritLimitedPublicInboxCustodyEnvelopeV1')
  unique(shares.map(value => bytesToHex(value.custodianPublicKey)), reader.code, 'custodian keys')
  unique(shares.map(value => bytesToHex(value.ephemeralPublicKey)), reader.code, 'ephemeral keys')

  const openedShares = []
  for (let index = 0; index < 2; index++) {
    const privateRaw = hex(vector.fixtureCustodianPrivateKeys[index], 32, 'CUSTODY_THRESHOLD', 'custodian private key')
    const privateKey = x25519PrivateKey(privateRaw)
    const derivedPublic = new Uint8Array(createPublicKey(privateKey)
      .export({ format: 'der', type: 'spki' }).subarray(-32))
    bytesSame(derivedPublic, shares[index].custodianPublicKey, 'CUSTODY_RECONSTRUCTION', 'custodian recipient')
    bytesSame(derivedPublic, hex(vector.fixtureCustodianPublicKeys[index], 32),
      'CUSTODY_RECONSTRUCTION', 'fixture custodian pin')
    const shared = new Uint8Array(diffieHellman({
      privateKey,
      publicKey: x25519PublicKey(shares[index].ephemeralPublicKey)
    }))
    const shareKey = new Uint8Array(hkdfSync('sha256', shared, custodySetId, concatBytes(
      asciiBytes('peerit.hiverelay.custody-share-key.v1'), Uint8Array.of(LIMITED_MANAGEMENT_BUNDLE_KIND),
      Uint8Array.of(shares[index].shareIndex), shares[index].custodianPublicKey,
      shares[index].ephemeralPublicKey
    ), 32))
    let opened
    try {
      opened = xchachaOpen(shareKey, shares[index].nonce, shares[index].shareAad, shares[index].sealedShare)
    } catch (cause) {
      const error = new Error(`custody share authentication failed: ${cause.message}`)
      error.code = 'CUSTODY_RECONSTRUCTION'
      throw error
    }
    same(opened.byteLength, 32, 'CUSTODY_RECONSTRUCTION', 'opened share length')
    openedShares.push({ index: shares[index].shareIndex, bytes: opened })
  }
  const dataKey = reconstructTwoShares(openedShares[0], openedShares[1])
  bytesSame(blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-key.v1'), custodySetId, dataKey
  )), keyCommitment, 'CUSTODY_RECONSTRUCTION', 'reconstructed custody key commitment')
  let plaintext
  try {
    plaintext = xchachaOpen(dataKey, payloadNonce, payloadAad, sealedPayload)
  } catch (cause) {
    const error = new Error(`custody payload authentication failed: ${cause.message}`)
    error.code = 'CUSTODY_RECONSTRUCTION'
    throw error
  }
  same(BigInt(plaintext.byteLength), plaintextLength, 'CUSTODY_RECONSTRUCTION', 'opened plaintext length')
  bytesSame(blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-plaintext.v1'), Uint8Array.of(LIMITED_MANAGEMENT_BUNDLE_KIND),
    u16Bytes(LIMITED_MANAGEMENT_PLAINTEXT_CODEC), u64Bytes(plaintext.byteLength), plaintext
  )), plaintextHash, 'CUSTODY_RECONSTRUCTION', 'opened plaintext hash')
  same(sha256Hex(plaintext), vector.plaintextSha256, 'CUSTODY_RECONSTRUCTION', 'opened plaintext SHA-256')
  validateLimitedManagementPlaintext(plaintext, vector, bootstrap, profileCatalog)
}

function validateFrames (frames, bootstrap, announcementBytes, authenticatedFrames) {
  ok(Array.isArray(frames) && frames.length === 2, 'FRAME_COUNT', 'two frames required')
  unique(frames.map(frame => frame.frameCanonicalHex), 'FRAME_REUSE', 'frame bytes')
  unique(frames.map(frame => frame.nonceHex), 'FRAME_REUSE', 'frame nonces')
  const set = bootstrap.payload.inboxEpochSets[0]
  const bindingByRelay = new Map(set.bindings.map(binding => [binding.relayId, binding]))
  for (const vector of frames) {
    const binding = bindingByRelay.get(vector.relayId)
    ok(binding != null, 'FRAME_BINDING', 'frame relay binding')
    same(vector.inboxEpoch, set.inboxEpoch, 'FRAME_BINDING', 'frame epoch')
    same(vector.stripeIndex, 0, 'STRIPE_SHAPE', 'frame stripe')
    same(vector.frameClass, 1, 'FRAME_CLASS', 'smallest fitting frame class')
    same(vector.relayPublicKey, binding.relayPublicKey, 'FRAME_BINDING', 'frame relay key')
    same(vector.physicalTopic, binding.physicalTopic, 'FRAME_BINDING', 'frame topic')
    const relayKey = hex(vector.relayPublicKey, 32)
    const topic = hex(vector.physicalTopic, 32)
    const info = concatBytes(
      asciiBytes('peerit.hiverelay.inbox-frame-key.v1'), u32Bytes(set.inboxEpoch), Uint8Array.of(0), relayKey
    )
    const expectedKey = new Uint8Array(hkdfSync('sha256', hex(set.announcementMasterKey, 32), topic, info, 32))
    bytesSame(hex(vector.frameKey, 32), expectedKey, 'FRAME_KEY', 'frame HKDF key')
    const expectedAad = concatBytes(
      asciiBytes('peerit.hiverelay.inbox-frame-aad.v1'), u32Bytes(set.inboxEpoch), Uint8Array.of(0),
      relayKey, topic, Uint8Array.of(vector.frameClass)
    )
    bytesSame(hex(vector.aadHex), expectedAad, 'FRAME_AAD', 'frame AAD')
    const frame = hex(vector.frameCanonicalHex)
    const authenticated = authenticatedFrames.get(vector.relayId)
    ok(authenticated != null, 'READ_PAGE_COUNT', 'frame lacks authenticated relay READ source')
    bytesSame(frame, authenticated.frame, 'READ_PAGE_FRAME', 'frame must come from signed READ result')
    same(vector.frameClass, authenticated.frameClass, 'READ_PAGE_FRAME', 'READ frame class')
    bytesSame(hex(vector.frameHash, 32), authenticated.frameHash, 'READ_PAGE_FRAME', 'READ frame hash')
    same(frame.byteLength, 4096, 'FRAME_CLASS', 'class-1 frame length')
    const nonce = frame.subarray(0, 24)
    bytesSame(nonce, hex(vector.nonceHex, null), 'FRAME_NONCE', 'frame nonce prefix')
    let plaintext
    try { plaintext = xchachaOpen(expectedKey, nonce, expectedAad, frame.subarray(24)) } catch (cause) {
      const error = new Error(`frame AEAD failed: ${cause.message}`); error.code = 'FRAME_AEAD'; throw error
    }
    same(plaintext.byteLength, 4096 - 24 - 16, 'FRAME_CLASS', 'fixed plaintext length')
    same(sha256Hex(plaintext), vector.plaintextSha256, 'FRAME_PLAINTEXT', 'plaintext SHA-256')
    const announcementLength = plaintext.readUInt32BE(0)
    same(announcementLength, announcementBytes.byteLength, 'FRAME_PLAINTEXT', 'announcement length')
    bytesSame(plaintext.subarray(4, 4 + announcementLength), announcementBytes, 'FRAME_PLAINTEXT', 'announcement bytes')
    same(sha256Hex(plaintext.subarray(4 + announcementLength)), vector.paddingSha256, 'FRAME_PADDING', 'padding SHA-256')
    bytesSame(blake2b256(frame), hex(vector.frameHash, 32), 'FRAME_HASH', 'generic frame hash')
  }
}

function validateCursor (cursor) {
  ok(Array.isArray(cursor.scopeFields) && cursor.scopeFields.join(',') === 'inboxEpoch,stripeIndex,relayPublicKey,physicalTopic',
    'CURSOR_SCOPE', 'cursor scope')
  same(cursor.snapshotLifetimeSeconds, 900, 'CURSOR_LIFETIME', 'cursor lifetime')
  same(cursor.maximumCursorBytes, 128, 'CURSOR_SIZE', 'cursor max')
  same(cursor.signedPageVerifiedBeforeUse, true, 'CURSOR_SIGNATURE', 'signed page gate')
  same(cursor.invalidFrameAdvancesVerifiedPage, true, 'CURSOR_POISON', 'poison-frame advance')
  same(cursor.acceptedRecordsAndCursorAtomic, true, 'CURSOR_ATOMICITY', 'cursor atomicity')
  same(cursor.dedupeKey, 'manifestRecordId', 'CURSOR_DEDUPE', 'cursor dedupe')
  same(cursor.orderingClaim, false, 'CURSOR_CLAIM', 'cursor ordering claim')
  same(cursor.completenessClaim, false, 'CURSOR_CLAIM', 'cursor completeness claim')
}
function validateRetry (retry) {
  same(retry.exactRequestPersistedBeforeSend, true, 'RETRY_PERSISTENCE', 'request persistence')
  same(retry.exactSpendPersistedBeforeSend, true, 'RETRY_PERSISTENCE', 'spend persistence')
  same(retry.exactFramePersistedBeforeSend, true, 'RETRY_PERSISTENCE', 'frame persistence')
  same(retry.ambiguousOutcome, 'PENDING_UNKNOWN', 'RETRY_AMBIGUITY', 'ambiguous outcome')
  same(retry.reconcileCell, 'CELL.GET_EXACT_SLOT_AND_BLOB_HASH', 'RETRY_RECONCILE', 'Cell reconciliation')
  same(retry.reconcileInbox, 'INBOX.READ_EXACT_FRAME_HASH', 'RETRY_RECONCILE', 'Inbox reconciliation')
  same(retry.changedTarget, 'NEW_ATTEMPT_FRESH_ALL_MATERIAL', 'RETRY_TARGET', 'changed target')
  same(retry.frameReuseAllowed, false, 'RETRY_FRAME_REUSE', 'frame reuse')
}
function validateConsent (consent) {
  same(consent.boot, 'LURKER_NO_IDENTITY_NO_ADMISSION_NO_WRITE', 'CONSENT_LURKER', 'boot state')
  same(consent.confirmation, 'EXPLICIT', 'CONSENT_CONFIRMATION', 'confirmation')
  same(consent.identityBeforeSignature, 'AUTHENTICATED_ENCRYPTED_DURABLE', 'CONSENT_IDENTITY', 'identity commit')
  same(consent.signedIntentBeforeNetwork, true, 'CONSENT_JOURNAL', 'signed intent order')
  same(consent.localVisibleOffline, true, 'CONSENT_LOCAL', 'offline local visibility')
  ok(consent.propagationOrder.join(',') === 'CELL_ACK,CELL_GET_DECRYPT,AUTHOR_BIND_SIGN,INLINE_ANNOUNCEMENT_SIGN,INBOX_APPEND',
    'CONSENT_PROPAGATION', 'propagation order')
  same(consent.cancelBeforeIdentity, 'PRISTINE_LURKER_DRAFT_RETAINED', 'CONSENT_CANCEL', 'pre-identity cancel')
  same(consent.ambiguousSend, 'PENDING_UNKNOWN_RECONCILE_EXACT', 'CONSENT_AMBIGUITY', 'ambiguous send')
  same(consent.forgetWhilePending, 'REFUSED_WITHOUT_RECONCILIATION_OR_COMPLETE_FRESH_RECOVERY_EXPORT', 'CONSENT_FORGET', 'forget fence')
}

function pointerParts (pointer) {
  ok(typeof pointer === 'string' && pointer.startsWith('/'), 'BAD_MUTATION', 'mutation path')
  return pointer.slice(1).split('/').map(value => value.replaceAll('~1', '/').replaceAll('~0', '~'))
}
function parentAt (root, pointer) {
  const parts = pointerParts(pointer)
  const key = parts.pop()
  let parent = root
  for (const part of parts) parent = parent[Array.isArray(parent) ? Number(part) : part]
  return { parent, key: Array.isArray(parent) ? Number(key) : key }
}
function valueAt (root, pointer) {
  let value = root
  for (const part of pointerParts(pointer)) value = value[Array.isArray(value) ? Number(part) : part]
  return value
}
function applyMutation (base, mutation) {
  const output = structuredClone(base)
  const { parent, key } = parentAt(output, mutation.path)
  if (mutation.op === 'replace' || mutation.op === 'add') parent[key] = structuredClone(mutation.value)
  else if (mutation.op === 'remove') Array.isArray(parent) ? parent.splice(key, 1) : delete parent[key]
  else if (mutation.op === 'copy') parent[key] = structuredClone(valueAt(output, mutation.from))
  else if (mutation.op === 'truncate-array') {
    ok(Array.isArray(parent[key]) && Number.isSafeInteger(mutation.length) && mutation.length >= 0,
      'BAD_MUTATION', 'truncate-array mutation')
    parent[key].length = mutation.length
  }
  else if (mutation.op === 'xor-hex') {
    const value = Buffer.from(parent[key], 'hex')
    const index = mutation.byteIndex < 0 ? value.byteLength + mutation.byteIndex : mutation.byteIndex
    value[index] ^= mutation.mask
    parent[key] = value.toString('hex')
  } else {
    const error = new Error(`unknown mutation ${mutation.op}`); error.code = 'BAD_MUTATION'; throw error
  }
  return output
}

async function validateRegistries () {
  const compatibility = await readJson(path.join(HERE, 'compatibility-v1.json'))
  same(compatibility.status, 'CONTRACT_ONLY_NOT_RELEASE_AUTHORITY', 'BAD_COMPATIBILITY', 'compatibility status')
  same(compatibility.consumerProfile.specSha256, PROFILE_SHA256, 'BAD_COMPATIBILITY', 'profile SHA')
  same(compatibility.boundedIssuance.announcementEmitterMode, 'INLINE_ONLY', 'BAD_COMPATIBILITY', 'emitter')
  same(compatibility.boundedIssuance.maximumInlineAuthorBindBytes, 10000, 'BAD_COMPATIBILITY', 'INLINE limit')
  same(compatibility.boundedIssuance.cellReferenceEmission, 'REJECT_IN_SEQUENCE_29', 'BAD_COMPATIBILITY', 'CELL_REFERENCE emission')
  same(compatibility.releaseAuthorityRequirements.provenanceInputsAreNotTargetPins, true, 'STALE_TARGET_PIN', 'provenance pin boundary')
  same(compatibility.releaseAuthorityRequirements.fixtureHashesAreNotTargetPins, true, 'STALE_TARGET_PIN', 'fixture pin boundary')
  same(compatibility.releaseAuthorityRequirements.inboxReadCompressedSignaturePayloadReconciliationRequired, true,
    'BAD_COMPATIBILITY', 'Inbox READ signature drift gate')
  same(compatibility.inboxShape.initialEpochSetCount, 1, 'BAD_COMPATIBILITY', 'initial epoch set count')
  same(compatibility.inboxShape.appendTargetsRemainCurrentSetOnly, 2, 'BAD_COMPATIBILITY', 'current append targets')
  const encoded = stable(compatibility)
  for (const value of Object.values(compatibility.sourceProvenanceOnly)) {
    ok(encoded.indexOf(`\"target`) === -1 || !encoded.includes(`\"target\":\"${value}\"`), 'STALE_TARGET_PIN', 'provenance promoted to target')
  }
  const registry = await readJson(path.join(HERE, 'codec-registry-v1.json'))
  same(registry.bootstrap.schemaName, 'PeeritLimitedPublicInboxBootstrapV1', 'BAD_SCHEMA_NAME', 'registry bootstrap name')
  same(registry.bootstrap.schemaId, 'peerit-limited-public-inbox-bootstrap-v1', 'BAD_SCHEMA_NAME', 'registry bootstrap id')
  same(registry.peeritProfileAuthority.sourceSha256, PROFILE_SHA256, 'BAD_REGISTRY', 'registry profile hash')
  same(registry.peeritProfileAuthority.schemas.AuthorBindV1.innerCodec, 334, 'BAD_REGISTRY', 'AuthorBind codec')
  same(registry.peeritProfileAuthority.schemas.AuthorBindV1.manifestTag, 3, 'BAD_REGISTRY', 'AuthorBind tag')
  same(registry.hiverelayAuthority.inboxConstants.OPEN_APPEND, 0, 'BAD_REGISTRY', 'OPEN_APPEND')
  same(registry.hiverelayAuthority.inboxConstants.FRAME_CLASS_BITS_1_AND_2, 3, 'BAD_REGISTRY', 'frame bits')
  same(registry.hiverelayAuthority.status, 'REGENERATED_TARGET_TUPLE_REQUIRED_BEFORE_RELEASE', 'BAD_REGISTRY', 'target tuple status')
  same(registry.hiverelayAuthority.wireTypes.InboxReadResultV1.resultSignaturePayloadCodec,
    'InboxReadSignaturePayloadV1', 'BAD_REGISTRY', 'Inbox READ signature payload codec')
  ok(registry.hiverelayAuthority.wireTypes.InboxReadResultV1.targetIntegrationDrift.includes('MUST_BE_RECONCILED'),
    'BAD_REGISTRY', 'Inbox READ implementation drift must remain release blocking')
  same(registry.managementCustody.bundleKind, 2, 'BAD_REGISTRY', 'Inbox management custody bundle kind')
  same(registry.managementCustody.plaintextCodec, 3, 'BAD_REGISTRY', 'limited custody codec')
  const custody = await readJson(path.join(HERE, 'limited-management-custody-v1.json'))
  same(custody.schema, 'peerit-seq29-limited-public-inbox-management-custody-v1', 'BAD_REGISTRY', 'custody policy schema')
  same(custody.bundle.name, 'PeeritLimitedPublicInboxManagementBundleV1', 'BAD_REGISTRY', 'custody bundle name')
  same(custody.bundle.cardinality.current, 2, 'BAD_REGISTRY', 'custody current count')
  same(custody.bundle.cardinality.previous.join(','), '0,2', 'BAD_REGISTRY', 'custody previous count')
  same(custody.bundle.entryOrder,
    'TWO_CURRENT_SORTED_BY_RELAY_PUBLIC_KEY_THEN_PHYSICAL_TOPIC_THEN_OPTIONAL_TWO_PREVIOUS_WITH_SAME_SORT',
    'BAD_REGISTRY', 'custody entry order')
  same(custody.envelope.encryptedShareName, 'PeeritCustodyEncryptedShareV1',
    'BAD_REGISTRY', 'canonical encrypted share child')
  same(custody.bundle.seedRoles.join(','), 'CREATE,RENEW,CLOSE', 'BAD_REGISTRY', 'custody seed roles')
  same(custody.envelope.name, 'PeeritLimitedPublicInboxCustodyEnvelopeV1', 'BAD_REGISTRY', 'custody envelope name')
  same(custody.envelope.threshold, 2, 'BAD_REGISTRY', 'custody threshold')
  same(custody.envelope.totalShares, 3, 'BAD_REGISTRY', 'custody total shares')
  ok(custody.nonAliases.includes('NO_PADDING_TO_24'), 'BAD_REGISTRY', 'custody no-padding boundary')
  return { compatibility, registry, custody }
}

async function validateManifest () {
  const manifest = await readJson(path.join(HERE, 'vector-manifest-v1.json'))
  same(manifest.schema, 'peerit-seq29-limited-public-test-vector-manifest-v1', 'BAD_MANIFEST', 'manifest schema')
  const paths = manifest.artifacts.map(value => value.path)
  same(paths.join('\n'), [...paths].sort().join('\n'), 'BAD_MANIFEST', 'manifest artifact sort order')
  ok(!paths.includes('protocol/seq29-limited-public-test/vector-manifest-v1.json'),
    'BAD_MANIFEST', 'vector manifest must not hash itself')
  unique(paths, 'BAD_MANIFEST', 'manifest artifact paths')
  const aggregate = createHash('sha256')
  for (const artifact of manifest.artifacts) {
    const file = path.join(ROOT, artifact.path)
    const value = await fs.readFile(file)
    same(value.byteLength, artifact.byteLength, 'ARTIFACT_HASH', `${artifact.path} byte length`)
    same(sha256Hex(value), artifact.sha256, 'ARTIFACT_HASH', `${artifact.path} SHA-256`)
    aggregate.update(`${artifact.path}\0${artifact.byteLength}\0${artifact.sha256}\n`, 'utf8')
  }
  same(aggregate.digest('hex'), manifest.artifactAggregateSha256,
    'ARTIFACT_HASH', 'artifact aggregate SHA-256')
  return manifest
}

async function main () {
  const profileBytes = await fs.readFile(path.join(ROOT, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md'))
  same(sha256Hex(profileBytes), PROFILE_SHA256, 'PROFILE_INPUT_DRIFT', 'canonical profile input')
  const profileCatalog = await createPinnedProfileCatalog(profileBytes.toString('utf8'))
  validateSchemaAuthority(await readJson(path.join(ROOT, 'config/peerit-limited-availability-bootstrap-v1.schema.json')))
  await validateRegistries()
  const bootstrap = validateBootstrap(await readJson(path.join(FIXTURES, 'positive-bootstrap.json')))
  const vector = validateProtocolVector(await readJson(path.join(FIXTURES, 'positive-protocol-vector.json')), bootstrap, profileCatalog)
  const manifest = await validateManifest()
  const negativeFiles = (await fs.readdir(NEGATIVE)).filter(name => name.endsWith('.json')).sort()
  same(negativeFiles.length, manifest.negativeFixtureCount, 'BAD_MANIFEST', 'negative fixture count')
  for (const name of negativeFiles) {
    const fixture = await readJson(path.join(NEGATIVE, name))
    same(fixture.schema, 'peerit-seq29-limited-public-test-negative-v1', 'BAD_NEGATIVE_FIXTURE', `${name} schema`)
    const base = fixture.target === 'bootstrap' ? bootstrap : vector
    const mutated = applyMutation(base, fixture.mutation)
    let rejected = null
    try {
      if (fixture.target === 'bootstrap') validateBootstrap(mutated, { skipSignature: fixture.validationStage === 'POST_SIGNATURE' })
      else validateProtocolVector(mutated, bootstrap, profileCatalog)
    } catch (error) {
      rejected = error
    }
    ok(rejected != null, 'NEGATIVE_ACCEPTED', `${name} was accepted`)
    same(rejected.code, fixture.expectedError, 'NEGATIVE_WRONG_ERROR', `${name} rejection code`)
  }
  console.log(JSON.stringify({
    status: 'PASS',
    contract: 'PeeritLimitedPublicInboxBootstrapV1',
    claimBoundary: 'LIVE_PUBLIC_TEST_ONLY',
    positiveFixtures: 2,
    negativeFixtures: negativeFiles.length,
    assertions
  }))
}

await main()
