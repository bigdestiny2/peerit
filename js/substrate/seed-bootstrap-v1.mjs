// Signed direct-share bootstrap for the bounded Peerit Blind canary. Binding is
// deliberately one-way to avoid a manifest/bootstrap hash cycle: this signed
// artifact names its release sequence and authority, while the authenticated
// terminal release/profile reverse-binds the exact artifact hash. The artifact
// is application-owned. HiveRelay receives only generic ReadCellCapV1 material
// and never learns Peerit record semantics.

import { hashBytes, signBytes, verifyBytes } from '../crypto.js'

export const PEERIT_SEED_BOOTSTRAP_SCHEMA_V1 = 'peerit-seed-bootstrap-v1'
export const PEERIT_SEED_BOOTSTRAP_PROFILE_V1 = 'LIMITED_PUBLIC_TEST_V1'
export const PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1 =
  'two-owner-operated-relays-not-independent-operators'
export const PEERIT_SEED_BOOTSTRAP_RELEASE_BINDING_V1 = Object.freeze({
  direction: 'authenticated-terminal-release-profile-to-bootstrap',
  authenticatedReleaseField: 'peeritSeedBootstrapSha256',
  hashAlgorithm: 'sha256',
  verificationOption: 'expectedArtifactHash',
  bootstrapEmbedsTerminalManifestHash: false
})

const SIGN_DOMAIN = 'peerit.seed-bootstrap.v1'
const HEX32 = /^[0-9a-f]{64}$/
const HEX64 = /^[0-9a-f]{128}$/
const MAX_RECORDS = 4096
const MAX_TEXT = 4096
const MAX_LIFETIME_MS = 31 * 24 * 60 * 60 * 1000
const VERIFIED = new WeakSet()
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function plain (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_SHAPE', `${field} must be a plain object`)
  }
  return value
}

function exact (value, fields, field) {
  plain(value, field)
  const keys = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_SHAPE', `${field} fields are missing or unexpected`)
  }
  return value
}

function text (value, field, maximum = MAX_TEXT) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum ||
      value.includes('\0') || value !== value.normalize('NFC')) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_TEXT', `${field} must be bounded nonempty NFC text`)
  }
  return value
}

function hex32 (value, field) {
  if (!HEX32.test(String(value || ''))) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_HASH', `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function integer (value, field, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_INTEGER', `${field} is outside its closed bound`)
  }
  return value
}

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`
}

function canonicalBytes (value) { return encoder.encode(stable(value)) }

function fromHex (value) {
  const output = new Uint8Array(value.length / 2)
  for (let index = 0; index < output.length; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

function signedBytes (payload) {
  const body = canonicalBytes(payload)
  const domain = encoder.encode(SIGN_DOMAIN)
  const output = new Uint8Array(domain.byteLength + 1 + body.byteLength)
  output.set(domain)
  output[domain.byteLength] = 0
  output.set(body, domain.byteLength + 1)
  return output
}

function immutable (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return value
  for (const child of Object.values(value)) immutable(child)
  return Object.freeze(value)
}

function readCapability (input, field) {
  exact(input, [
    'version', 'relayPublicKey', 'storageSlot', 'cellKey', 'sizeClass',
    'expectedCellBlobHash'
  ], field)
  return {
    version: integer(input.version, `${field}.version`, 1, 1),
    relayPublicKey: hex32(input.relayPublicKey, `${field}.relayPublicKey`),
    storageSlot: hex32(input.storageSlot, `${field}.storageSlot`),
    cellKey: hex32(input.cellKey, `${field}.cellKey`),
    sizeClass: integer(input.sizeClass, `${field}.sizeClass`, 1, 5),
    expectedCellBlobHash: input.expectedCellBlobHash == null
      ? null
      : hex32(input.expectedCellBlobHash, `${field}.expectedCellBlobHash`)
  }
}

function relayRoot (input, index) {
  const field = `payload.relays[${index}]`
  exact(input, [
    'relayId', 'canonicalDescribeUrl', 'continuityRootRelayPublicKey', 'storeId',
    'descriptorGenesisHash', 'minimumDescriptorSequence', 'familyId',
    'operationId', 'endpointId', 'transportId', 'transportSupportBit',
    'privacyProfileBit'
  ], field)
  let url
  try { url = new URL(text(input.canonicalDescribeUrl, `${field}.canonicalDescribeUrl`)) } catch {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_URL', `${field}.canonicalDescribeUrl must be an absolute URL`)
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search ||
      url.pathname !== '/api/blind/v1/describe') {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_URL', `${field}.canonicalDescribeUrl is not an exact Blind HTTPS describe URL`)
  }
  return {
    relayId: text(input.relayId, `${field}.relayId`, 128),
    canonicalDescribeUrl: url.href,
    continuityRootRelayPublicKey: hex32(input.continuityRootRelayPublicKey, `${field}.continuityRootRelayPublicKey`),
    storeId: hex32(input.storeId, `${field}.storeId`),
    descriptorGenesisHash: hex32(input.descriptorGenesisHash, `${field}.descriptorGenesisHash`),
    minimumDescriptorSequence: integer(input.minimumDescriptorSequence, `${field}.minimumDescriptorSequence`),
    familyId: integer(input.familyId, `${field}.familyId`, 1, 0xffff),
    operationId: integer(input.operationId, `${field}.operationId`, 1, 0xffff),
    endpointId: integer(input.endpointId, `${field}.endpointId`, 1, 0xffff),
    transportId: integer(input.transportId, `${field}.transportId`, 1, 0xffff),
    transportSupportBit: integer(input.transportSupportBit, `${field}.transportSupportBit`, 1, 0xffff),
    privacyProfileBit: integer(input.privacyProfileBit, `${field}.privacyProfileBit`, 1, 0xffff)
  }
}

function replica (input, record, relays, index) {
  const field = `record ${record.recordId} replica[${index}]`
  exact(input, ['relayId', 'targetId', 'readCapability'], field)
  const relayId = text(input.relayId, `${field}.relayId`, 128)
  const relay = relays.get(relayId)
  if (!relay) fail('PEERIT_SEED_BOOTSTRAP_UNKNOWN_RELAY', `${field} references an undeclared relay`)
  const capability = readCapability(input.readCapability, `${field}.readCapability`)
  if (capability.relayPublicKey !== relay.continuityRootRelayPublicKey) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_READ_CAPABILITY', `${field} read capability relay key is not bound to the signed relay root`)
  }
  if (capability.sizeClass !== record.sizeClass) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_READ_CAPABILITY', `${field} read capability size class disagrees with the record`)
  }
  return {
    relayId,
    targetId: text(input.targetId, `${field}.targetId`),
    readCapability: capability
  }
}

function seedRecord (input, relays, index) {
  const field = `payload.records[${index}]`
  exact(input, [
    'recordId', 'wireKeys', 'authorPublicKey', 'innerCodec', 'innerLength',
    'sizeClass', 'logicalHash', 'encodingCommitment', 'replicas'
  ], field)
  const record = {
    recordId: hex32(input.recordId, `${field}.recordId`),
    wireKeys: Array.isArray(input.wireKeys)
      ? input.wireKeys.map((value, wireIndex) => text(value, `${field}.wireKeys[${wireIndex}]`))
      : fail('PEERIT_SEED_BOOTSTRAP_BAD_SHAPE', `${field}.wireKeys must be an array`),
    authorPublicKey: hex32(input.authorPublicKey, `${field}.authorPublicKey`),
    innerCodec: integer(input.innerCodec, `${field}.innerCodec`, 334, 334),
    innerLength: integer(input.innerLength, `${field}.innerLength`, 8, 1_048_519),
    sizeClass: integer(input.sizeClass, `${field}.sizeClass`, 1, 5),
    logicalHash: hex32(input.logicalHash, `${field}.logicalHash`),
    encodingCommitment: hex32(input.encodingCommitment, `${field}.encodingCommitment`),
    replicas: []
  }
  if (record.wireKeys.length < 1 || record.wireKeys.length > 64 ||
      new Set(record.wireKeys).size !== record.wireKeys.length ||
      [...record.wireKeys].sort().some((key, wireIndex) => key !== record.wireKeys[wireIndex])) {
    fail('PEERIT_SEED_BOOTSTRAP_NONCANONICAL', `${field}.wireKeys must be unique and sorted`)
  }
  if (!Array.isArray(input.replicas) || input.replicas.length !== relays.size) {
    fail('PEERIT_SEED_BOOTSTRAP_REPLICA_FLOOR', `${field} must carry one replica for every declared relay`)
  }
  record.replicas = input.replicas.map((value, replicaIndex) => replica(value, record, relays, replicaIndex))
  const replicaIds = record.replicas.map(value => value.relayId)
  if (new Set(replicaIds).size !== relays.size || [...replicaIds].sort().some((id, relayIndex) => id !== replicaIds[relayIndex])) {
    fail('PEERIT_SEED_BOOTSTRAP_NONCANONICAL', `${field}.replicas must be unique and sorted by relayId`)
  }
  return record
}

function payload (input) {
  exact(input, [
    'schema', 'version', 'profile', 'operatorBoundary', 'bootstrapSequence',
    'previousBootstrapHash', 'releaseSequence', 'authorityPublicKey', 'issuedAt',
    'expiresAt', 'relays', 'records'
  ], 'payload')
  if (input.schema !== PEERIT_SEED_BOOTSTRAP_SCHEMA_V1 || input.version !== 1 ||
      input.profile !== PEERIT_SEED_BOOTSTRAP_PROFILE_V1 ||
      input.operatorBoundary !== PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1) {
    fail('PEERIT_SEED_BOOTSTRAP_PROFILE_MISMATCH', 'bootstrap schema/profile/operator boundary is unsupported')
  }
  const bootstrapSequence = integer(input.bootstrapSequence, 'payload.bootstrapSequence')
  const previousBootstrapHash = input.previousBootstrapHash == null
    ? null
    : hex32(input.previousBootstrapHash, 'payload.previousBootstrapHash')
  if ((bootstrapSequence === 0) !== (previousBootstrapHash == null)) {
    fail('PEERIT_SEED_BOOTSTRAP_CONTINUITY', 'only bootstrap sequence zero may omit its predecessor hash')
  }
  const issuedAt = integer(input.issuedAt, 'payload.issuedAt')
  const expiresAt = integer(input.expiresAt, 'payload.expiresAt')
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_LIFETIME_MS) {
    fail('PEERIT_SEED_BOOTSTRAP_EXPIRY', 'bootstrap validity window is empty or too long')
  }
  if (!Array.isArray(input.relays) || input.relays.length !== 2) {
    fail('PEERIT_SEED_BOOTSTRAP_RELAY_FLOOR', 'the bounded canary requires exactly two declared relays')
  }
  const relayRows = input.relays.map(relayRoot)
  const relayIds = relayRows.map(value => value.relayId)
  if (new Set(relayIds).size !== 2 || [...relayIds].sort().some((id, index) => id !== relayIds[index])) {
    fail('PEERIT_SEED_BOOTSTRAP_NONCANONICAL', 'relays must be unique and sorted by relayId')
  }
  const relayMap = new Map(relayRows.map(value => [value.relayId, value]))
  if (!Array.isArray(input.records) || input.records.length < 1 || input.records.length > MAX_RECORDS) {
    fail('PEERIT_SEED_BOOTSTRAP_RECORD_BOUND', 'bootstrap record count is outside its bound')
  }
  const records = input.records.map((value, index) => seedRecord(value, relayMap, index))
  const recordIds = records.map(value => value.recordId)
  if (new Set(recordIds).size !== records.length || [...recordIds].sort().some((id, index) => id !== recordIds[index])) {
    fail('PEERIT_SEED_BOOTSTRAP_NONCANONICAL', 'records must be unique and sorted by recordId')
  }
  return {
    schema: input.schema,
    version: 1,
    profile: input.profile,
    operatorBoundary: input.operatorBoundary,
    bootstrapSequence,
    previousBootstrapHash,
    releaseSequence: integer(input.releaseSequence, 'payload.releaseSequence', 13),
    authorityPublicKey: hex32(input.authorityPublicKey, 'payload.authorityPublicKey'),
    issuedAt,
    expiresAt,
    relays: relayRows,
    records
  }
}

function parseArtifact (input) {
  let value = input
  if (input instanceof Uint8Array || input instanceof ArrayBuffer || ArrayBuffer.isView(input)) {
    const bytes = input instanceof Uint8Array
      ? new Uint8Array(input)
      : new Uint8Array(input.buffer || input, input.byteOffset || 0, input.byteLength)
    let decoded
    try { decoded = decoder.decode(bytes) } catch {
      fail('PEERIT_SEED_BOOTSTRAP_NONCANONICAL', 'bootstrap is not canonical UTF-8')
    }
    try { value = JSON.parse(decoded) } catch {
      fail('PEERIT_SEED_BOOTSTRAP_NONCANONICAL', 'bootstrap is not JSON')
    }
    if (stable(value) !== decoded) {
      fail('PEERIT_SEED_BOOTSTRAP_NONCANONICAL', 'bootstrap bytes are not the exact canonical JSON encoding')
    }
  }
  exact(value, ['payload', 'signature'], 'artifact')
  const normalizedPayload = payload(value.payload)
  if (!HEX64.test(String(value.signature || ''))) {
    fail('PEERIT_SEED_BOOTSTRAP_BAD_SIGNATURE', 'bootstrap signature must be lowercase 64-byte hexadecimal')
  }
  return { payload: normalizedPayload, signature: value.signature }
}

export async function createPeeritSeedBootstrapV1 (input, options = {}) {
  const normalized = payload(input)
  if (typeof options.seedHex !== 'string' || !HEX32.test(options.seedHex)) {
    fail('PEERIT_SEED_BOOTSTRAP_SIGNER_REQUIRED', 'a 32-byte fixture/offline signing seed is required')
  }
  const signature = await signBytes(options.seedHex, signedBytes(normalized))
  const artifact = { payload: normalized, signature: [...signature].map(value => value.toString(16).padStart(2, '0')).join('') }
  return immutable(artifact)
}

export function encodePeeritSeedBootstrapV1 (input) {
  const artifact = parseArtifact(input)
  return canonicalBytes(artifact)
}

// Offline/release assembly helper. It authenticates no content and grants no
// runtime authority; it only computes the exact reverse-binding value that the
// terminal release/profile must commit before signing.
export async function hashPeeritSeedBootstrapV1 (input) {
  return hashBytes(canonicalBytes(parseArtifact(input)))
}

export async function verifyPeeritSeedBootstrapV1 (input, options = {}) {
  const artifact = parseArtifact(input)
  const expectedAuthority = hex32(options.authorityPublicKey, 'authorityPublicKey')
  if (artifact.payload.authorityPublicKey !== expectedAuthority) {
    fail('PEERIT_SEED_BOOTSTRAP_AUTHORITY_MISMATCH', 'bootstrap signer is not the release-pinned discovery authority')
  }
  const expectedReleaseSequence = integer(options.releaseSequence, 'releaseSequence', 13)
  if (artifact.payload.releaseSequence !== expectedReleaseSequence) {
    fail('PEERIT_SEED_BOOTSTRAP_RELEASE_MISMATCH', 'bootstrap release sequence does not match the authenticated release')
  }
  const expectedArtifactHash = hex32(options.expectedArtifactHash, 'expectedArtifactHash')
  const expectedPrevious = options.previousBootstrapHash == null ? null : hex32(options.previousBootstrapHash, 'previousBootstrapHash')
  if (artifact.payload.previousBootstrapHash !== expectedPrevious) {
    fail('PEERIT_SEED_BOOTSTRAP_CONTINUITY', 'bootstrap predecessor does not match the persisted discovery floor')
  }
  const now = options.now == null ? Date.now() : integer(options.now, 'now')
  if (now < artifact.payload.issuedAt || now >= artifact.payload.expiresAt) {
    fail('PEERIT_SEED_BOOTSTRAP_EXPIRED', 'bootstrap is outside its signed validity window')
  }
  const ok = await verifyBytes(expectedAuthority, signedBytes(artifact.payload), fromHex(artifact.signature))
  if (!ok) fail('PEERIT_SEED_BOOTSTRAP_BAD_SIGNATURE', 'bootstrap signature verification failed')
  const artifactHash = await hashBytes(canonicalBytes(artifact))
  if (artifactHash !== expectedArtifactHash) {
    fail('PEERIT_SEED_BOOTSTRAP_RELEASE_MISMATCH', 'bootstrap hash does not match the authenticated release/profile reverse binding')
  }
  const sourceId = await hashBytes(encoder.encode(
    `${SIGN_DOMAIN}\0${expectedAuthority}\0${expectedReleaseSequence}`))
  const verified = immutable({
    ...artifact,
    artifactHash,
    sourceId
  })
  VERIFIED.add(verified)
  return verified
}

export function assertVerifiedPeeritSeedBootstrapV1 (value) {
  if (!value || typeof value !== 'object' || !VERIFIED.has(value)) {
    fail('PEERIT_SEED_BOOTSTRAP_UNVERIFIED', 'a verified PeeritSeedBootstrapV1 artifact is required')
  }
  return value
}

export function decodePeeritSeedReadCapabilityV1 (value) {
  const normalized = readCapability(value, 'readCapability')
  return Object.freeze({
    version: normalized.version,
    relayPublicKey: fromHex(normalized.relayPublicKey),
    storageSlot: fromHex(normalized.storageSlot),
    cellKey: fromHex(normalized.cellKey),
    sizeClass: normalized.sizeClass,
    expectedCellBlobHash: normalized.expectedCellBlobHash == null
      ? null
      : fromHex(normalized.expectedCellBlobHash)
  })
}
