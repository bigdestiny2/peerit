// Deterministic FIXTURE-ONLY generator for the Sequence 29 contract gate.
//
// Every key below is derived from a public test label. Those keys are therefore
// intentionally unsafe for any live or release use. The generated bootstrap is
// marked FIXTURE_ONLY, and a release ceremony must reject it. Live management
// keys remain independent CSPRNG Ed25519 keypairs created by the offline
// ceremony; this generator cannot emit LIMITED_PUBLIC_TEST_RELEASE.

import fs from 'node:fs/promises'
import path from 'node:path'
import {
  createCipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  sign
} from 'node:crypto'
import { fileURLToPath } from 'node:url'
import {
  asciiBytes,
  blake2b256,
  bytesToHex,
  compareBytes,
  concatBytes,
  u16Bytes,
  u32Bytes,
  u64Bytes
} from '../../js/substrate/release-control-primitives.mjs'
import {
  compilePeeritProfileCodecIr,
  createPeeritProfileCodecCatalogFromIr,
  encodePeeritProfileRecordPrefixFromIr
} from '../../js/substrate/profile-codec-ir.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../../js/substrate/profile-inventory.mjs'
import { authenticatePeeritProfileExternalCodecAuthorityV1 } from '../../js/substrate/profile-external-authority.mjs'
import { decodeBlindExternalProfileValueV1 } from '../../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '../..')
const FIXTURES = path.join(ROOT, 'test/fixtures/peerit-seq29-limited-public-test-v1')
const NEGATIVE = path.join(FIXTURES, 'negative')
const BOOTSTRAP_DOMAIN = 'peerit.limited-public-test.inbox-bootstrap.v1'
const FIXTURE_KDF_DOMAIN = 'peerit.seq29.fixture-only.generator.v1'
const LIMITED_MANAGEMENT_BUNDLE_DOMAIN = 'peerit.hiverelay.limited-public-inbox-management-bundle.v1'
const LIMITED_MANAGEMENT_BUNDLE_KIND = 2
const LIMITED_MANAGEMENT_PLAINTEXT_CODEC = 3
const PROFILE_SPEC_SHA256 = '74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd'
const HIVERELAY_PROVENANCE = 'fa53fb22e5ecd606bf7816575bb723f5a9e87766'
const FIXTURE_REFERENCE_UNIX_MILLIS = 1780000001000n
const FIXTURE_EFFECTIVE_LEASE_EPOCH = Number(FIXTURE_REFERENCE_UNIX_MILLIS / 21600000n)
const FIXTURE_CURRENT_INBOX_EPOCH = Math.floor(FIXTURE_EFFECTIVE_LEASE_EPOCH / 28)
const FIXTURE_L90_EXPIRY_EPOCH = FIXTURE_EFFECTIVE_LEASE_EPOCH + 360
const FIXTURE_SUCCESSOR_EFFECTIVE_LEASE_EPOCH = (FIXTURE_CURRENT_INBOX_EPOCH + 1) * 28
const FIXTURE_SUCCESSOR_REFERENCE_UNIX_MILLIS = BigInt(FIXTURE_SUCCESSOR_EFFECTIVE_LEASE_EPOCH) * 21600000n + 1000n

if (process.env.PEERIT_SEQ29_ARTIFACT_CLASS && process.env.PEERIT_SEQ29_ARTIFACT_CLASS !== 'FIXTURE_ONLY') {
  throw new Error('fixture generator refuses every non-FIXTURE_ONLY artifact class')
}

const hex = bytesToHex
const sha256 = value => createHash('sha256').update(value).digest()
const sha256Hex = value => sha256(value).toString('hex')
const jsonBytes = value => Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8')

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}
function canonicalJson (value) { return Buffer.from(stable(value), 'utf8') }

const PEERIT_SIGNATURE_FIELDS = new Set(['_sig', '_k', '_dk', '_ns', '_alg'])
function stablePeeritRecordValue (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value === undefined ? null : value)
  if (Array.isArray(value)) return '[' + value.map(stablePeeritRecordValue).join(',') + ']'
  const keys = Object.keys(value).filter(key => !PEERIT_SIGNATURE_FIELDS.has(key) && value[key] !== undefined).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stablePeeritRecordValue(value[key])).join(',') + '}'
}
function canonicalPeeritRecordFixture (type, data) {
  return type + '|' + stablePeeritRecordValue(data)
}
function createBoundedPeeritInnerOperationBatchFixtureV1 (operations) {
  const canonicalOperationBatch = stable({ version: 1, operations })
  const payload = Buffer.from(canonicalOperationBatch, 'utf8')
  if (payload.byteLength < 1 || payload.byteLength > 1048512) throw new Error('fixture operation batch payload is out of bounds')
  return {
    innerBytes: concatBytes(u16Bytes(334), u8(1), u32Bytes(payload.byteLength), payload),
    canonicalOperationBatch
  }
}

function fixtureBytes (label, length) {
  const chunks = []
  let count = 0
  let total = 0
  while (total < length) {
    const chunk = sha256(Buffer.concat([
      Buffer.from(FIXTURE_KDF_DOMAIN, 'ascii'),
      Buffer.from([0]),
      Buffer.from(label, 'utf8'),
      Buffer.from(u32Bytes(count++))
    ]))
    chunks.push(chunk)
    total += chunk.byteLength
  }
  return new Uint8Array(Buffer.concat(chunks).subarray(0, length))
}

function keyPair (label) {
  const seed = Buffer.from(fixtureBytes(`ed25519:${label}`, 32))
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8'
  })
  const publicKey = new Uint8Array(createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' }).subarray(-32))
  const privateSeed = new Uint8Array(seed)
  seed.fill(0)
  return { privateKey, privateSeed, publicKey }
}

function u8 (value) { return Uint8Array.of(value) }
function optionalBytes (value) { return value == null ? u8(0) : concatBytes(u8(1), value) }
function compactBytes (value) {
  if (!(value instanceof Uint8Array) || value.byteLength > 0xfc) throw new Error('fixture compact bytes exceed one-byte canonical form')
  return concatBytes(u8(value.byteLength), value)
}

function cellGetRequestCommitment (relayPublicKey, storageSlot, clientNonce) {
  return blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.request.v1cell-get'), relayPublicKey, storageSlot, clientNonce
  ))
}
function cellAllocationCommitment (value) {
  return blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.allocate.v1'), value.relayPublicKey, value.storageSlot,
    u32Bytes(value.allocationEpoch), u8(value.sizeClass), u8(value.leaseClass),
    value.declaredBlobHash, value.createPublicKey, value.renewPublicKey, value.dropPublicKey
  ))
}
function cellPutRequestCommitment (allocationCommitment, clientNonce) {
  return blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.request.v1cell-put'), allocationCommitment, clientNonce
  ))
}
function putCellRequestBytes (value) {
  return concatBytes(
    u8(1), value.storageSlot, u32Bytes(value.allocationEpoch), u8(value.sizeClass), u8(value.leaseClass),
    value.clientNonce, value.createPublicKey, value.renewPublicKey, value.dropPublicKey,
    value.declaredBlobHash, value.createSignature,
    u16Bytes(value.admission.profileId), u16Bytes(value.admission.schemeId),
    value.admission.parameterHash, compactBytes(value.admission.token), value.cellBlob
  )
}
function inboxReadRequestCommitment (relayPublicKey, physicalTopic, cursor, limit, clientNonce) {
  return blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.request.v1inbox-read'), relayPublicKey, physicalTopic,
    blake2b256(cursor), u16Bytes(limit), clientNonce
  ))
}
function getCellRequestBytes (storageSlot, clientNonce) {
  return concatBytes(u8(1), storageSlot, clientNonce, u8(0))
}
function getCellResultBytes (sizeClass, cellBlob) {
  return concatBytes(u8(1), u8(sizeClass), cellBlob)
}
function inboxReadRequestBytes (physicalTopic, cursor, limit, clientNonce) {
  return concatBytes(u8(1), physicalTopic, compactBytes(cursor), u16Bytes(limit), clientNonce, u8(0))
}

function sealCellFixture (storageSlot, cellKey, sizeClass, inner, label) {
  if (sizeClass !== 1) throw new Error('Sequence 29 fixture only emits class-1 Cells')
  const totalBytes = 4096
  const nonce = fixtureBytes(`${label}:nonce`, 12)
  const plaintextBytes = totalBytes - 1 - 12 - 16
  if (inner.byteLength > plaintextBytes - 4) throw new Error('fixture inner exceeds class-1 Cell')
  const padding = fixtureBytes(`${label}:padding`, plaintextBytes - 4 - inner.byteLength)
  const plaintext = concatBytes(u32Bytes(inner.byteLength), inner, padding)
  const aad = concatBytes(asciiBytes('hiverelay.blind.cell.v1'), u8(1), u8(sizeClass), storageSlot)
  const cipher = createCipheriv('aes-256-gcm', cellKey, nonce, { authTagLength: 16 })
  cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.byteLength })
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const cellBlob = concatBytes(u8(1), nonce, ciphertext, cipher.getAuthTag())
  if (cellBlob.byteLength !== totalBytes) throw new Error('fixture Cell blob length drift')
  return { aad, cellBlob, cellBlobHash: blake2b256(cellBlob) }
}

function inboxReadResultBytes (value, pair) {
  if (value.entries.length > 0xfc) throw new Error('fixture read page exceeds compact one-byte count')
  const entriesBytes = concatBytes(
    u8(value.entries.length),
    ...value.entries.map(entry => concatBytes(
      u64Bytes(entry.appendRevision), entry.frameHash, u8(entry.frameClass), entry.frame
    ))
  )
  const relayBytes = relayResultBindingBytes(value.relayBinding)
  const entriesCommitment = blake2b256(entriesBytes)
  const encodedNextCursor = optionalBytes(value.nextCursor == null ? null : compactBytes(value.nextCursor))
  const unsigned = concatBytes(
    u8(1), relayBytes, value.requestNonce, value.requestCommitment,
    u64Bytes(value.snapshotRevision), entriesBytes, entriesCommitment, encodedNextCursor
  )
  const signaturePayloadBytes = concatBytes(
    u8(1), relayBytes, value.requestNonce, value.requestCommitment,
    u64Bytes(value.snapshotRevision), entriesCommitment, encodedNextCursor
  )
  const signature = new Uint8Array(sign(null,
    resultSignaturePayload('hiverelay.blind.inbox-read-result.v1', signaturePayloadBytes), pair.privateKey))
  return concatBytes(unsigned, signature)
}

function x25519Pair (label) {
  const privateBytes = fixtureBytes(`x25519:${label}`, 32)
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(privateBytes)]),
    format: 'der',
    type: 'pkcs8'
  })
  const publicKey = new Uint8Array(createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' }).subarray(-32))
  return { privateBytes, privateKey, publicKey }
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

function encodeLimitedManagementBundle (value) {
  if (![2, 4].includes(value.entryBytes.length)) throw new Error('limited management bundle requires 2 or 4 entries')
  const prefix = concatBytes(
    u8(1), u64Bytes(value.releaseSequence), value.profilePinHash,
    value.signedBootstrapHash, u64Bytes(value.bootstrapSequence),
    u32Bytes(value.currentInboxEpoch), u8(value.entryBytes.length),
    ...value.entryBytes.map(bytes => concatBytes(u16Bytes(bytes.byteLength), bytes)),
    u64Bytes(value.createdUnixMillis)
  )
  const commitment = blake2b256(concatBytes(
    asciiBytes(LIMITED_MANAGEMENT_BUNDLE_DOMAIN), u64Bytes(prefix.byteLength), prefix
  ))
  return concatBytes(prefix, commitment)
}

function limitedCustodyEnvelopePrefix (value) {
  return concatBytes(
    u8(1), value.custodySetId, u8(LIMITED_MANAGEMENT_BUNDLE_KIND),
    u16Bytes(LIMITED_MANAGEMENT_PLAINTEXT_CODEC), u64Bytes(value.plaintextLength),
    value.plaintextHash, value.keyCommitment, u32Bytes(value.sealedPayloadLength)
  )
}
function limitedCustodySharePrefix (value) {
  return concatBytes(
    u8(1), value.custodySetId, u8(LIMITED_MANAGEMENT_BUNDLE_KIND), u8(value.shareIndex),
    u8(2), u8(3), value.keyCommitment, value.sealedPayloadHash,
    value.custodianPublicKey, value.ephemeralPublicKey, value.nonce
  )
}

function makeLimitedManagementCustody (plaintext, options = {}) {
  const custodySetId = fixtureBytes('limited-custody:set-id', 32)
  const dataKey = fixtureBytes('limited-custody:data-key', 32)
  const coefficient = fixtureBytes('limited-custody:shamir-coefficient', 32)
  const payloadNonce = fixtureBytes('limited-custody:payload-nonce', 24)
  const keyCommitment = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-key.v1'), custodySetId, dataKey
  ))
  const plaintextHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-plaintext.v1'), u8(LIMITED_MANAGEMENT_BUNDLE_KIND),
    u16Bytes(LIMITED_MANAGEMENT_PLAINTEXT_CODEC), u64Bytes(plaintext.byteLength), plaintext
  ))
  const envelope = {
    custodySetId,
    plaintextLength: plaintext.byteLength,
    plaintextHash,
    keyCommitment,
    sealedPayloadLength: plaintext.byteLength + 16
  }
  const payloadAad = limitedCustodyEnvelopePrefix(envelope)
  const sealedPayload = xchachaSeal(dataKey, payloadNonce, payloadAad, plaintext)
  const sealedPayloadHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-sealed-payload.v1'),
    u64Bytes(sealedPayload.byteLength), sealedPayload
  ))
  const custodians = [0, 1, 2].map(index => x25519Pair(`limited-custodian-${index}`))
  const ephemerals = [0, 1, 2].map(index => x25519Pair(`limited-ephemeral-${index}`))
  const shares = custodians.map((custodian, index) => {
    const shareIndex = index + 1
    const sharePlaintext = new Uint8Array(32)
    for (let byte = 0; byte < 32; byte++) {
      sharePlaintext[byte] = dataKey[byte] ^ gfMultiply(coefficient[byte], shareIndex)
    }
    if (options.maliciousShareIndex === shareIndex) sharePlaintext[0] ^= 1
    const shared = new Uint8Array(diffieHellman({
      privateKey: ephemerals[index].privateKey,
      publicKey: createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(custodian.publicKey)]),
        format: 'der', type: 'spki'
      })
    }))
    const info = concatBytes(
      asciiBytes('peerit.hiverelay.custody-share-key.v1'), u8(LIMITED_MANAGEMENT_BUNDLE_KIND),
      u8(shareIndex), custodian.publicKey, ephemerals[index].publicKey
    )
    const shareKey = new Uint8Array(hkdfSync('sha256', shared, custodySetId, info, 32))
    const nonceLabel = options.duplicateNonceAt === shareIndex ? 1 : shareIndex
    const nonce = fixtureBytes(`limited-custody:share-${nonceLabel}:nonce`, 24)
    const value = {
      custodySetId,
      shareIndex,
      keyCommitment,
      sealedPayloadHash,
      custodianPublicKey: custodian.publicKey,
      ephemeralPublicKey: ephemerals[index].publicKey,
      nonce
    }
    const sealedShare = xchachaSeal(shareKey, nonce, limitedCustodySharePrefix(value), sharePlaintext)
    return { ...value, sealedShare }
  })
  if (options.tamperShareIndex != null) {
    const share = shares[options.tamperShareIndex - 1]
    share.sealedShare = new Uint8Array(share.sealedShare)
    share.sealedShare[share.sealedShare.byteLength - 1] ^= 1
  }
  if (options.duplicateCiphertextAt != null) {
    shares[options.duplicateCiphertextAt - 1].sealedShare = new Uint8Array(shares[0].sealedShare)
  }
  if (options.duplicateEphemeralAt != null) {
    shares[options.duplicateEphemeralAt - 1].ephemeralPublicKey = new Uint8Array(shares[0].ephemeralPublicKey)
  }
  if (options.lowOrderEphemeralAt != null) {
    shares[options.lowOrderEphemeralAt - 1].ephemeralPublicKey = concatBytes(Uint8Array.of(1), new Uint8Array(31))
  }
  const canonical = concatBytes(
    limitedCustodyEnvelopePrefix(envelope), payloadNonce, sealedPayload, u8(3),
    ...shares.map(share => concatBytes(limitedCustodySharePrefix(share), share.sealedShare))
  )
  return {
    canonical,
    custodians: custodians.map(value => ({ privateKey: value.privateBytes, publicKey: value.publicKey })),
    shares,
    plaintextHash,
    keyCommitment
  }
}

function relayResultBindingBytes (value) {
  if (value.externalCommitWitness != null) throw new Error('fixture relay binding forbids external witness')
  return concatBytes(
    u8(1), value.relayPublicKey, value.storeId, u64Bytes(value.descriptorSequence), value.descriptorHash,
    u8(value.durabilityProfileId), value.durabilityContinuityHash, value.durabilityProfileHash,
    u64Bytes(value.restoreEvidenceHeadSequence), value.restoreEvidenceHeadHash, u8(0)
  )
}

function resultSignaturePayload (domain, unsigned) {
  return concatBytes(asciiBytes(domain), u64Bytes(unsigned.byteLength), unsigned)
}
function signedResultBytes (domain, unsigned, pair) {
  return concatBytes(unsigned, new Uint8Array(sign(null, resultSignaturePayload(domain, unsigned), pair.privateKey)))
}
function inboxReceiptBytes (value, pair) {
  const unsigned = concatBytes(
    u8(1), relayResultBindingBytes(value.relayBinding), value.topicCommitment,
    u64Bytes(value.stateRevision), u8(value.leaseClass), u32Bytes(value.leaseEpoch),
    value.requestNonce, value.requestCommitment, u8(value.result)
  )
  return signedResultBytes('hiverelay.blind.inbox-receipt.v1', unsigned, pair)
}
function readCellCapBytes (value) {
  return concatBytes(
    u8(1), value.relayPublicKey, value.storageSlot, value.cellKey, u8(value.sizeClass),
    optionalBytes(value.expectedCellBlobHash)
  )
}
function blindReceiptBytes (value, pair) {
  const unsigned = concatBytes(
    u8(1), asciiBytes('hiverelay-blind-cell-v1'), relayResultBindingBytes(value.relayBinding),
    value.slotCommitment, value.cellBlobHash, value.allocationCommitment, value.requestCommitment,
    u8(value.sizeClass), u32Bytes(value.allocationEpoch), u8(value.leaseClass),
    u32Bytes(value.leaseEpoch), u64Bytes(value.stateRevision), u32Bytes(value.receiptEpoch),
    value.requestNonce, u8(value.result)
  )
  return signedResultBytes('hiverelay.blind.cell-receipt.v1', unsigned, pair)
}

function signedAuthorBindFixture (value, pair, compiled, runtimeOptions, catalog) {
  const record = { ...value, signature: new Uint8Array(64) }
  const prefix = encodePeeritProfileRecordPrefixFromIr(
    compiled, PEERIT_PROFILE_INVENTORY, 'AuthorBindV1', record, 'signature', runtimeOptions
  )
  record.signature = new Uint8Array(sign(null, concatBytes(
    asciiBytes('peerit.hiverelay.author-bind.v1'), prefix
  ), pair.privateKey))
  const bytes = catalog.AuthorBindV1.encode(record)
  const manifestRecordId = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.manifest-record-id.v1'), u16Bytes(3), u64Bytes(bytes.byteLength), bytes
  ))
  return { record, prefix, bytes, manifestRecordId }
}

function signedAnnouncementFixture (authorBytes, manifestRecordId, publishedLeaseEpoch, pair, compiled, runtimeOptions, catalog) {
  const record = {
    version: 1,
    manifestTag: 3,
    manifestRecordId: new Uint8Array(manifestRecordId),
    manifestMode: 1,
    manifestRecord: new Uint8Array(authorBytes),
    manifestReadCaps: [],
    publishedLeaseEpoch,
    publisherPublicKey: new Uint8Array(pair.publicKey),
    signature: new Uint8Array(64)
  }
  const prefix = encodePeeritProfileRecordPrefixFromIr(
    compiled, PEERIT_PROFILE_INVENTORY, 'PeeritAnnouncementV1', record, 'signature', runtimeOptions
  )
  record.signature = new Uint8Array(sign(null, concatBytes(
    asciiBytes('peerit.hiverelay.announcement.v1'), prefix
  ), pair.privateKey))
  const bytes = catalog.PeeritAnnouncementV1.encode(record)
  const signedAnnouncementId = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.signed-announcement-id.v1'), u64Bytes(bytes.byteLength), bytes
  ))
  return { record, prefix, bytes, signedAnnouncementId }
}

function authorBindVectorValue (signed) {
  return {
    manifestTag: 3,
    authorSequence: String(signed.record.authorSequence),
    previousAuthorRecordId: signed.record.previousAuthorRecordId == null
      ? null
      : hex(signed.record.previousAuthorRecordId),
    authorPublicKey: hex(signed.record.authorPublicKey),
    signature: hex(signed.record.signature),
    signingPrefixHex: hex(signed.prefix),
    canonicalHex: hex(signed.bytes),
    byteLength: signed.bytes.byteLength,
    canonicalSha256: sha256Hex(signed.bytes),
    manifestRecordId: hex(signed.manifestRecordId)
  }
}

function announcementVectorValue (signed) {
  return {
    version: 1,
    manifestTag: 3,
    manifestRecordId: hex(signed.record.manifestRecordId),
    manifestMode: 1,
    manifestRecordCanonicalHex: hex(signed.record.manifestRecord),
    manifestReadCaps: [],
    publishedLeaseEpoch: signed.record.publishedLeaseEpoch,
    publisherPublicKey: hex(signed.record.publisherPublicKey),
    signature: hex(signed.record.signature),
    signingPrefixHex: hex(signed.prefix),
    canonicalHex: hex(signed.bytes),
    byteLength: signed.bytes.byteLength,
    canonicalSha256: sha256Hex(signed.bytes),
    signedAnnouncementId: hex(signed.signedAnnouncementId)
  }
}

function relayBinding (pair, label, sequence) {
  return {
    version: 1,
    relayPublicKey: new Uint8Array(pair.publicKey),
    storeId: fixtureBytes(`${label}:store-id`, 32),
    descriptorSequence: BigInt(sequence),
    descriptorHash: fixtureBytes(`${label}:descriptor-hash`, 32),
    durabilityProfileId: 1,
    durabilityContinuityHash: fixtureBytes(`${label}:continuity`, 32),
    durabilityProfileHash: fixtureBytes(`${label}:durability-profile`, 32),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: new Uint8Array(32),
    externalCommitWitness: null
  }
}

function cellReplicaProjection (value) {
  const projection = concatBytes(
    value.logicalHash, value.encodingCommitment, value.relayPublicKey, value.readCapability,
    value.cellBlobHash, u8(value.sizeClass), u32Bytes(value.allocationEpoch)
  )
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.replica-id.v1'), Uint8Array.of(1),
    u64Bytes(projection.byteLength), projection
  ))
}

function boundedProfileSortProjection (owner, type, value, encoded) {
  if (String(owner).includes('initialReplicas')) return cellReplicaProjection(value)
  return encoded
}

async function externalAuthorities () {
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
  const object = {}
  const map = new Map()
  for (const row of PEERIT_PROFILE_INVENTORY.externalCodecImports) {
    const authority = authenticatePeeritProfileExternalCodecAuthorityV1({
      name: row.name,
      authorityKind: row.authorityKind,
      authorityBinding: row.tupleBinding,
      artifacts: row.authorityKind === 'WIRE_TUPLE_V1' ? wireArtifacts : clientArtifacts,
      assertCanonical (value, name) {
        if (!(value instanceof Uint8Array) || value.byteLength === 0 || name !== row.name) {
          throw new Error(`invalid fixture external value for ${row.name}`)
        }
        decodeBlindExternalProfileValueV1(name, value)
      }
    })
    object[row.name] = authority
    map.set(row.name, authority)
  }
  return { object: Object.freeze(object), map }
}

function logicalHash (inner) {
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.logical-hash.v1'), u16Bytes(334), u64Bytes(inner.byteLength), inner
  ))
}
function encodingCommitment (inner, logical, sizeClass) {
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.encoding.v1'), u8(1), logical, u16Bytes(334),
    u64Bytes(inner.byteLength), u32Bytes(1), blake2b256(inner), u8(sizeClass)
  ))
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
function xchachaSeal (key, nonce, aad, plaintext) {
  const subkey = hchacha20(key, nonce.subarray(0, 16))
  const nonce12 = Buffer.concat([Buffer.alloc(4), Buffer.from(nonce.subarray(16))])
  const cipher = createCipheriv('chacha20-poly1305', subkey, nonce12, { authTagLength: 16 })
  cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.byteLength })
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([ciphertext, cipher.getAuthTag()])
}

const staticNegativeFixtures = Object.freeze([
  ['01-private-management-seed.json', 'bootstrap', null, { op: 'add', path: '/payload/inboxEpochSets/0/bindings/0/createPrivateSeed', value: '00'.repeat(32) }, 'SECRET_MATERIAL'],
  ['02-public-management-derivation.json', 'bootstrap', null, { op: 'add', path: '/payload/managementKeyDerivation', value: 'SHA256(boardSlug || relayPublicKey)' }, 'PUBLIC_DERIVATION'],
  ['03-per-board-topic-scope.json', 'bootstrap', 'POST_SIGNATURE', { op: 'replace', path: '/payload/topicScope', value: 'PER_BOARD' }, 'TOPIC_SCOPE'],
  ['04-topic-formula-mismatch.json', 'bootstrap', 'POST_SIGNATURE', { op: 'xor-hex', path: '/payload/inboxEpochSets/0/bindings/0/physicalTopic', byteIndex: 0, mask: 1 }, 'TOPIC_MISMATCH'],
  ['05-signed-append-mode.json', 'bootstrap', 'POST_SIGNATURE', { op: 'replace', path: '/payload/inboxEpochSets/0/bindings/0/appendAuthMode', value: 1 }, 'INBOX_SHAPE'],
  ['06-production-stripe-count.json', 'bootstrap', 'POST_SIGNATURE', { op: 'replace', path: '/payload/inboxEpochSets/0/stripeCountLog2', value: 3 }, 'STRIPE_SHAPE'],
  ['07-duplicate-relay-key.json', 'bootstrap', 'POST_SIGNATURE', { op: 'copy', from: '/payload/relays/0/relayPublicKey', path: '/payload/relays/1/relayPublicKey' }, 'DUPLICATE_RELAY'],
  ['08-create-receipt-signature.json', 'bootstrap', 'POST_SIGNATURE', { op: 'xor-hex', path: '/payload/inboxEpochSets/0/bindings/0/createReceiptCanonicalHex', byteIndex: -1, mask: 1 }, 'BAD_RECEIPT_SIGNATURE'],
  ['09-bootstrap-signature.json', 'bootstrap', null, { op: 'xor-hex', path: '/signature', byteIndex: -1, mask: 1 }, 'BAD_BOOTSTRAP_SIGNATURE'],
  ['10-receipt-cross-binding.json', 'bootstrap', 'POST_SIGNATURE', { op: 'copy', from: '/payload/inboxEpochSets/0/bindings/0/createReceiptCanonicalHex', path: '/payload/inboxEpochSets/0/bindings/1/createReceiptCanonicalHex' }, 'BAD_RECEIPT_BINDING'],
  ['11-bootstrap-sequence-gap.json', 'bootstrap', 'POST_SIGNATURE', { op: 'replace', path: '/payload/bootstrapSequence', value: '2' }, 'BOOTSTRAP_SEQUENCE'],
  ['12-receipt-only-author-bind.json', 'vector', null, { op: 'remove', path: '/cells/0/capabilityBoundGet/getResultCanonicalHex' }, 'READBACK_REQUIRED'],
  ['13-author-chain-gap.json', 'vector', null, { op: 'replace', path: '/authorBind/authorSequence', value: '2' }, 'AUTHOR_CHAIN'],
  ['14-cell-reference-emission.json', 'vector', null, { op: 'replace', path: '/announcement/manifestMode', value: 2 }, 'ANNOUNCEMENT_MODE'],
  ['15-inline-read-cap.json', 'vector', null, { op: 'replace', path: '/announcement/manifestReadCaps', value: ['00'] }, 'ANNOUNCEMENT_MODE'],
  ['16-manifest-id-substitution.json', 'vector', null, { op: 'replace', path: '/announcement/manifestRecordId', value: '00'.repeat(32) }, 'MANIFEST_ID'],
  ['17-wrong-author-manifest-tag.json', 'vector', null, { op: 'replace', path: '/authorBind/manifestTag', value: 4 }, 'AUTHOR_BIND_TAG'],
  ['18-frame-reuse-across-relays.json', 'vector', null, { op: 'copy', from: '/frames/0/frameCanonicalHex', path: '/frames/1/frameCanonicalHex' }, 'FRAME_REUSE'],
  ['19-frame-aad-substitution.json', 'vector', null, { op: 'xor-hex', path: '/frames/0/aadHex', byteIndex: -1, mask: 1 }, 'FRAME_AAD'],
  ['20-frame-key-cross-relay.json', 'vector', null, { op: 'copy', from: '/frames/0/frameKey', path: '/frames/1/frameKey' }, 'FRAME_KEY'],
  ['21-cursor-cross-binding.json', 'vector', null, { op: 'copy', from: '/readPages/1/requestCanonicalHex', path: '/readPages/3/requestCanonicalHex' }, 'READ_REQUEST_BINDING'],
  ['22-cursor-ordering-claim.json', 'vector', null, { op: 'replace', path: '/cursor/orderingClaim', value: true }, 'CURSOR_CLAIM'],
  ['23-retry-frame-reuse.json', 'vector', null, { op: 'replace', path: '/retry/frameReuseAllowed', value: true }, 'RETRY_FRAME_REUSE'],
  ['24-ambiguous-auto-ack.json', 'vector', null, { op: 'replace', path: '/retry/ambiguousOutcome', value: 'ACKNOWLEDGED' }, 'RETRY_AMBIGUITY'],
  ['25-lurker-creates-identity.json', 'vector', null, { op: 'replace', path: '/consent/boot', value: 'IDENTITY_CREATED' }, 'CONSENT_LURKER'],
  ['26-sign-before-identity-commit.json', 'vector', null, { op: 'replace', path: '/consent/identityBeforeSignature', value: 'VOLATILE_AFTER_SIGNATURE' }, 'CONSENT_IDENTITY'],
  ['27-author-bind-before-readback.json', 'vector', null, { op: 'replace', path: '/consent/propagationOrder', value: ['CELL_ACK', 'AUTHOR_BIND_SIGN', 'CELL_GET_DECRYPT', 'INLINE_ANNOUNCEMENT_SIGN', 'INBOX_APPEND'] }, 'CONSENT_PROPAGATION'],
  ['28-cell-logical-hash-substitution.json', 'vector', null, { op: 'xor-hex', path: '/cells/0/logicalHash', byteIndex: 0, mask: 1 }, 'CELL_EQUALITY'],
  ['29-cell-receipt-signature.json', 'vector', null, { op: 'xor-hex', path: '/cells/0/relayReceiptCanonicalHex', byteIndex: -1, mask: 1 }, 'BAD_CELL_RECEIPT_SIGNATURE'],
  ['30-publisher-decrypted-shortcut.json', 'vector', null, { op: 'add', path: '/cells/0/capabilityBoundGet/decryptedInnerCanonicalHex', value: '00' }, 'READBACK_SHORTCUT'],
  ['31-cell-get-blob-tamper.json', 'vector', null, { op: 'xor-hex', path: '/cells/0/capabilityBoundGet/getResultCanonicalHex', byteIndex: 20, mask: 1 }, 'CELL_BLOB_HASH'],
  ['32-forged-inbox-read-page.json', 'vector', null, { op: 'xor-hex', path: '/readPages/0/resultCanonicalHex', byteIndex: -1, mask: 1 }, 'READ_PAGE_SIGNATURE'],
  ['33-inbox-read-result-cross-binding.json', 'vector', null, { op: 'copy', from: '/readPages/0/resultCanonicalHex', path: '/readPages/2/resultCanonicalHex' }, 'READ_PAGE_SIGNATURE'],
  ['34-cursor-chain-rollback.json', 'vector', null, { op: 'replace', path: '/readPages/1/requestCanonicalHex', value: '' }, 'READ_REQUEST_BINDING'],
  ['35-bootstrap-expiry-over-31-days.json', 'bootstrap', 'POST_SIGNATURE', { op: 'replace', path: '/payload/expiresUnixMillis', value: '1782678400001' }, 'BOOTSTRAP_LIFETIME'],
  ['36-bootstrap-floor-rollback.json', 'vector', null, { op: 'replace', path: '/bootstrapFloor/highestAcceptedBootstrapSequence', value: '1' }, 'BOOTSTRAP_ROLLBACK'],
  ['37-bootstrap-floor-same-sequence-fork.json', 'vector', null, { op: 'xor-hex', path: '/bootstrapFloor/completeSignedWrapperHash', byteIndex: 0, mask: 1 }, 'BOOTSTRAP_FORK'],
  ['38-custody-bundle-cardinality.json', 'vector', null, { op: 'replace', path: '/managementCustody/currentEntryCount', value: 3 }, 'CUSTODY_CARDINALITY'],
  ['39-custody-append-seed.json', 'vector', null, { op: 'replace', path: '/managementCustody/seedRoles', value: ['CREATE', 'RENEW', 'CLOSE', 'APPEND'] }, 'CUSTODY_APPEND_SEED'],
  ['40-custody-threshold.json', 'vector', null, { op: 'replace', path: '/managementCustody/threshold', value: 1 }, 'CUSTODY_THRESHOLD'],
  ['41-custody-envelope-tamper.json', 'vector', null, { op: 'xor-hex', path: '/managementCustody/envelopeCanonicalHex', byteIndex: 140, mask: 1 }, 'CUSTODY_RECONSTRUCTION'],
  ['42-custody-one-share-only.json', 'vector', null, { op: 'truncate-array', path: '/managementCustody/fixtureCustodianPrivateKeys', length: 1 }, 'CUSTODY_THRESHOLD'],
  ['43-cursor-result-page-cross-topic.json', 'vector', null, { op: 'copy', from: '/readPages/0/requestCanonicalHex', path: '/readPages/2/requestCanonicalHex' }, 'READ_REQUEST_BINDING']
])

async function generate () {
  await fs.mkdir(NEGATIVE, { recursive: true })
  const relayPairs = [keyPair('relay-a'), keyPair('relay-b')]
  const relayBindings = relayPairs.map((pair, index) => relayBinding(pair, `relay-${index}`, 7 + index))
  const relayIds = ['fixture-relay-a', 'fixture-relay-b']
  const allocationEpoch = FIXTURE_EFFECTIVE_LEASE_EPOCH
  const inboxEpoch = FIXTURE_CURRENT_INBOX_EPOCH
  const relays = []
  const bootstrapBindings = []
  const inboxManagementPairs = []

  for (let index = 0; index < 2; index++) {
    const create = keyPair(`fixture-only-inbox-create-${index}`)
    const renew = keyPair(`fixture-only-inbox-renew-${index}`)
    const close = keyPair(`fixture-only-inbox-close-${index}`)
    const topic = blake2b256(concatBytes(
      asciiBytes('hiverelay.blind.inbox-topic.v1'), u32Bytes(allocationEpoch), create.publicKey
    ))
    const receiptBytes = inboxReceiptBytes({
      relayBinding: relayBindings[index],
      topicCommitment: blake2b256(topic),
      stateRevision: 0n,
      leaseClass: 4,
      leaseEpoch: FIXTURE_L90_EXPIRY_EPOCH,
      requestNonce: fixtureBytes(`inbox-${index}:request-nonce`, 32),
      requestCommitment: fixtureBytes(`inbox-${index}:request-commitment`, 32),
      result: 1
    }, relayPairs[index])
    decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes)
    relays.push({
      relayId: relayIds[index],
      canonicalDescribeUrl: `https://${relayIds[index]}.invalid:443/blind/v1/describe`,
      relayPublicKey: hex(relayPairs[index].publicKey),
      storeId: hex(relayBindings[index].storeId),
      durabilityContinuityHash: hex(relayBindings[index].durabilityContinuityHash),
      descriptorFloor: {
        sequence: String(relayBindings[index].descriptorSequence),
        hash: hex(relayBindings[index].descriptorHash)
      }
    })
    bootstrapBindings.push({
      inboxEpoch,
      stripeIndex: 0,
      relayId: relayIds[index],
      relayPublicKey: hex(relayPairs[index].publicKey),
      allocationEpoch,
      createPublicKey: hex(create.publicKey),
      physicalTopic: hex(topic),
      frameClassBits: 3,
      appendAuthMode: 0,
      retentionClass: 3,
      leaseClass: 4,
      createReceiptCanonicalHex: hex(receiptBytes)
    })
    inboxManagementPairs.push({ create, renew, close, receiptBytes })
  }

  const bootstrapAuthority = keyPair('bootstrap-authority')
  const bootstrapPayload = {
    schema: 'peerit-limited-public-inbox-bootstrap-v1',
    version: 1,
    artifactClass: 'FIXTURE_ONLY',
    claimBoundary: 'LIVE_PUBLIC_TEST_ONLY',
    operatorBoundary: 'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS',
    topicScope: 'GLOBAL_PUBLIC_DISCOVERY',
    profileId: '@peerit/hiverelay-profile-v1',
    releaseSequence: 29,
    bootstrapSequence: '0',
    previousBootstrapHash: null,
    issuedUnixMillis: '1780000000000',
    expiresUnixMillis: '1780604800000',
    authorityPublicKey: hex(bootstrapAuthority.publicKey),
    relays,
    inboxEpochSets: [{
      inboxEpoch,
      stripeCountLog2: 0,
      stripeSelectionKey: hex(fixtureBytes('stripe-selection-key', 32)),
      announcementMasterKey: hex(fixtureBytes('announcement-master-key', 32)),
      bindings: bootstrapBindings
    }]
  }
  const bootstrap = {
    payload: bootstrapPayload,
    signature: hex(new Uint8Array(sign(null, concatBytes(
      asciiBytes(BOOTSTRAP_DOMAIN), u8(0), canonicalJson(bootstrapPayload)
    ), bootstrapAuthority.privateKey)))
  }
  const bootstrapWrapperBytes = canonicalJson(bootstrap)
  const bootstrapWrapperHash = new Uint8Array(sha256(bootstrapWrapperBytes))

  const successorBindings = []
  for (let index = 0; index < 2; index++) {
    const create = keyPair(`fixture-only-successor-inbox-create-${index}`)
    const successorTopic = blake2b256(concatBytes(
      asciiBytes('hiverelay.blind.inbox-topic.v1'),
      u32Bytes(FIXTURE_SUCCESSOR_EFFECTIVE_LEASE_EPOCH), create.publicKey
    ))
    const receiptBytes = inboxReceiptBytes({
      relayBinding: relayBindings[index],
      topicCommitment: blake2b256(successorTopic),
      stateRevision: 0n,
      leaseClass: 4,
      leaseEpoch: FIXTURE_SUCCESSOR_EFFECTIVE_LEASE_EPOCH + 360,
      requestNonce: fixtureBytes(`successor-inbox-${index}:request-nonce`, 32),
      requestCommitment: fixtureBytes(`successor-inbox-${index}:request-commitment`, 32),
      result: 1
    }, relayPairs[index])
    decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes)
    successorBindings.push({
      inboxEpoch: FIXTURE_CURRENT_INBOX_EPOCH + 1,
      stripeIndex: 0,
      relayId: relayIds[index],
      relayPublicKey: hex(relayPairs[index].publicKey),
      allocationEpoch: FIXTURE_SUCCESSOR_EFFECTIVE_LEASE_EPOCH,
      createPublicKey: hex(create.publicKey),
      physicalTopic: hex(successorTopic),
      frameClassBits: 3,
      appendAuthMode: 0,
      retentionClass: 3,
      leaseClass: 4,
      createReceiptCanonicalHex: hex(receiptBytes)
    })
  }
  const successorPayload = {
    ...bootstrapPayload,
    bootstrapSequence: '1',
    previousBootstrapHash: hex(bootstrapWrapperHash),
    issuedUnixMillis: String(FIXTURE_SUCCESSOR_REFERENCE_UNIX_MILLIS - 1000n),
    expiresUnixMillis: String(FIXTURE_SUCCESSOR_REFERENCE_UNIX_MILLIS + 604800000n),
    inboxEpochSets: [{
      inboxEpoch: FIXTURE_CURRENT_INBOX_EPOCH + 1,
      stripeCountLog2: 0,
      stripeSelectionKey: hex(fixtureBytes('successor-stripe-selection-key', 32)),
      announcementMasterKey: hex(fixtureBytes('successor-announcement-master-key', 32)),
      bindings: successorBindings
    }]
  }
  const successorBootstrap = {
    payload: successorPayload,
    signature: hex(new Uint8Array(sign(null, concatBytes(
      asciiBytes(BOOTSTRAP_DOMAIN), u8(0), canonicalJson(successorPayload)
    ), bootstrapAuthority.privateKey)))
  }

  const authorPair = keyPair('author')
  const publisherPair = keyPair('publisher')
  const authorPublicKeyHex = hex(authorPair.publicKey)
  const operationData = {
    id: 'fixture!fixture-only-seq29',
    author: authorPublicKeyHex,
    body: 'fixture-only',
    cid: 'fixture-only-seq29',
    community: 'fixture',
    createdAt: 1780000000000,
    _k: authorPublicKeyHex,
    _dk: hex(fixtureBytes('fixture-operation-drive-key', 32)),
    _ns: 'peerit',
    _alg: 'ed25519'
  }
  operationData._sig = hex(new Uint8Array(sign(null, Buffer.from(
    `pear.app.${operationData._dk}:peerit:${canonicalPeeritRecordFixture('post', operationData)}`,
    'utf8'
  ), authorPair.privateKey)))
  const innerEnvelope = createBoundedPeeritInnerOperationBatchFixtureV1([{
    type: 'post',
    data: operationData
  }])
  const innerBytes = innerEnvelope.innerBytes
  const logical = logicalHash(innerBytes)
  const sizeClass = 1
  const encoding = encodingCommitment(innerBytes, logical, sizeClass)
  const cellBindings = []
  const cellReadbackByRelay = new Map()
  const cellPutByRelay = new Map()

  for (let index = 0; index < 2; index++) {
    const create = keyPair(`fixture-only-cell-create-${index}`)
    const renew = keyPair(`fixture-only-cell-renew-${index}`)
    const drop = keyPair(`fixture-only-cell-drop-${index}`)
    const cellAllocationEpoch = allocationEpoch
    const slot = blake2b256(concatBytes(
      asciiBytes('hiverelay.blind.slot.v1'), u32Bytes(cellAllocationEpoch), create.publicKey
    ))
    const cellKey = fixtureBytes(`cell-${index}:read-key`, 32)
    const sealedCell = sealCellFixture(slot, cellKey, sizeClass, innerBytes, `cell-${index}`)
    const cellBlobHash = sealedCell.cellBlobHash
    const getClientNonce = fixtureBytes(`cell-${index}:get-client-nonce`, 32)
    const getRequestCommitment = cellGetRequestCommitment(relayPairs[index].publicKey, slot, getClientNonce)
    const readCapability = readCellCapBytes({
      relayPublicKey: relayPairs[index].publicKey,
      storageSlot: slot,
      cellKey,
      sizeClass,
      expectedCellBlobHash: cellBlobHash
    })
    decodeBlindExternalProfileValueV1('ReadCellCapV1', readCapability)
    const putClientNonce = fixtureBytes(`cell-${index}:put-client-nonce`, 32)
    const allocationCommitment = cellAllocationCommitment({
      relayPublicKey: relayPairs[index].publicKey,
      storageSlot: slot,
      allocationEpoch: cellAllocationEpoch,
      sizeClass,
      leaseClass: 4,
      declaredBlobHash: cellBlobHash,
      createPublicKey: create.publicKey,
      renewPublicKey: renew.publicKey,
      dropPublicKey: drop.publicKey
    })
    const putRequestCommitment = cellPutRequestCommitment(allocationCommitment, putClientNonce)
    const putRequest = putCellRequestBytes({
      storageSlot: slot,
      allocationEpoch: cellAllocationEpoch,
      sizeClass,
      leaseClass: 4,
      clientNonce: putClientNonce,
      createPublicKey: create.publicKey,
      renewPublicKey: renew.publicKey,
      dropPublicKey: drop.publicKey,
      declaredBlobHash: cellBlobHash,
      createSignature: new Uint8Array(sign(null, allocationCommitment, create.privateKey)),
      admission: {
        profileId: 8,
        schemeId: 1,
        parameterHash: fixtureBytes(`cell-${index}:put-admission-parameter-hash`, 32),
        token: fixtureBytes(`cell-${index}:put-admission-token`, 32)
      },
      cellBlob: sealedCell.cellBlob
    })
    const receiptBytes = blindReceiptBytes({
      relayBinding: relayBindings[index],
      slotCommitment: blake2b256(slot),
      cellBlobHash,
      allocationCommitment,
      requestCommitment: putRequestCommitment,
      sizeClass,
      allocationEpoch: cellAllocationEpoch,
      leaseClass: 4,
      leaseEpoch: FIXTURE_L90_EXPIRY_EPOCH,
      stateRevision: 0n,
      receiptEpoch: FIXTURE_EFFECTIVE_LEASE_EPOCH,
      requestNonce: putClientNonce,
      result: 1
    }, relayPairs[index])
    decodeBlindExternalProfileValueV1('BlindReceiptV1', receiptBytes)
    cellBindings.push({
      version: 1,
      logicalHash: new Uint8Array(logical),
      encodingCommitment: new Uint8Array(encoding),
      relayPublicKey: new Uint8Array(relayPairs[index].publicKey),
      readCapability,
      cellBlobHash,
      sizeClass,
      allocationEpoch: cellAllocationEpoch,
      leaseEpoch: FIXTURE_L90_EXPIRY_EPOCH,
      createPublicKey: create.publicKey,
      renewPublicKey: renew.publicKey,
      dropPublicKey: drop.publicKey,
      allocationCommitment,
      relayReceipt: receiptBytes
    })
    cellReadbackByRelay.set(hex(relayPairs[index].publicKey), {
      getRequest: getCellRequestBytes(slot, getClientNonce),
      getRequestCommitment,
      getResult: getCellResultBytes(sizeClass, sealedCell.cellBlob)
    })
    cellPutByRelay.set(hex(relayPairs[index].publicKey), {
      putRequest,
      allocationCommitment,
      putRequestCommitment,
      putClientNonce
    })
  }
  cellBindings.sort((left, right) => compareBytes(cellReplicaProjection(left), cellReplicaProjection(right)))

  const profileText = await fs.readFile(path.join(ROOT, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md'), 'utf8')
  if (sha256Hex(Buffer.from(profileText, 'utf8')) !== PROFILE_SPEC_SHA256) throw new Error('profile source drift')
  const compiled = compilePeeritProfileCodecIr(profileText, PEERIT_PROFILE_INVENTORY)
  const authorities = await externalAuthorities()
  const runtimeOptions = Object.freeze({
    externalAuthorityByName: authorities.map,
    sortProjection: boundedProfileSortProjection
  })
  const catalog = createPeeritProfileCodecCatalogFromIr(compiled, PEERIT_PROFILE_INVENTORY, {
    externalAuthorities: authorities.object,
    sortProjection: boundedProfileSortProjection
  })

  const managementEntryBytes = bootstrapBindings.map((binding, index) => {
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
      createReceipt: new Uint8Array(Buffer.from(binding.createReceiptCanonicalHex, 'hex'))
    }
    const bindingBytes = catalog.InboxStripeBindingV1.encode(bindingValue)
    const bindingHash = blake2b256(concatBytes(
      asciiBytes('peerit.hiverelay.inbox-management-binding.v1'),
      u64Bytes(bindingBytes.byteLength), bindingBytes
    ))
    const roles = inboxManagementPairs[index]
    const entry = {
      version: 1,
      inboxEpoch,
      stripeIndex: 0,
      relayPublicKey: new Uint8Array(relayPairs[index].publicKey),
      bindingHash,
      bindingBytes,
      createPrivateSeed: new Uint8Array(roles.create.privateSeed),
      renewPrivateSeed: new Uint8Array(roles.renew.privateSeed),
      closePrivateSeed: new Uint8Array(roles.close.privateSeed),
      renewPublicKey: new Uint8Array(roles.renew.publicKey),
      closePublicKey: new Uint8Array(roles.close.publicKey),
      latestReceipt: new Uint8Array(roles.receiptBytes),
      latestRevision: 0n,
      leaseEpoch: FIXTURE_L90_EXPIRY_EPOCH
    }
    return catalog.InboxManagementEntryV1.encode(entry)
  })
  managementEntryBytes.sort((left, right) => {
    const leftEntry = catalog.InboxManagementEntryV1.decode(left)
    const rightEntry = catalog.InboxManagementEntryV1.decode(right)
    const leftBinding = catalog.InboxStripeBindingV1.decode(leftEntry.bindingBytes)
    const rightBinding = catalog.InboxStripeBindingV1.decode(rightEntry.bindingBytes)
    return compareBytes(
      concatBytes(leftEntry.relayPublicKey, leftBinding.physicalTopic),
      concatBytes(rightEntry.relayPublicKey, rightBinding.physicalTopic)
    )
  })
  const managementPlaintext = encodeLimitedManagementBundle({
    releaseSequence: 29,
    profilePinHash: fixtureBytes('limited-management:profile-pin-hash', 32),
    bootstrapSequence: 0n,
    signedBootstrapHash: bootstrapWrapperHash,
    currentInboxEpoch: inboxEpoch,
    entryBytes: managementEntryBytes,
    createdUnixMillis: 1780000000000n
  })
  const managementCustody = makeLimitedManagementCustody(managementPlaintext)
  const thirdShareTamperedCustody = makeLimitedManagementCustody(managementPlaintext, { maliciousShareIndex: 3 })
  const duplicateNonceCustody = makeLimitedManagementCustody(managementPlaintext, { duplicateNonceAt: 2 })
  const duplicateCiphertextCustody = makeLimitedManagementCustody(managementPlaintext, { duplicateCiphertextAt: 2 })
  const duplicateEphemeralCustody = makeLimitedManagementCustody(managementPlaintext, { duplicateEphemeralAt: 2 })
  const lowOrderEphemeralCustody = makeLimitedManagementCustody(managementPlaintext, { lowOrderEphemeralAt: 2 })
  const invalidManagementEntry = catalog.InboxManagementEntryV1.decode(managementEntryBytes[0])
  const invalidManagementEntryBytes = catalog.InboxManagementEntryV1.encode({
    ...invalidManagementEntry,
    latestRevision: invalidManagementEntry.latestRevision + 1n
  })
  const invalidManagementPlaintext = encodeLimitedManagementBundle({
    releaseSequence: 29,
    profilePinHash: fixtureBytes('limited-management:profile-pin-hash', 32),
    bootstrapSequence: 0n,
    signedBootstrapHash: bootstrapWrapperHash,
    currentInboxEpoch: inboxEpoch,
    entryBytes: [invalidManagementEntryBytes, managementEntryBytes[1]],
    createdUnixMillis: 1780000000000n
  })
  const invalidManagementCustody = makeLimitedManagementCustody(invalidManagementPlaintext)

  const authorBindBase = {
    version: 1,
    authorSequence: 0n,
    previousAuthorRecordId: null,
    logicalHash: new Uint8Array(logical),
    innerCodec: 334,
    innerLength: BigInt(innerBytes.byteLength),
    initialReplicas: cellBindings,
    authorPublicKey: new Uint8Array(authorPair.publicKey)
  }
  const signedAuthor = signedAuthorBindFixture(authorBindBase, authorPair, compiled, runtimeOptions, catalog)
  const authorBind = signedAuthor.record
  const authorPrefix = signedAuthor.prefix
  const authorBindBytes = signedAuthor.bytes
  const manifestRecordId = signedAuthor.manifestRecordId
  if (authorBindBytes.byteLength > 10000) throw new Error('fixture AuthorBind exceeds INLINE cap')
  const signedAnnouncement = signedAnnouncementFixture(
    authorBindBytes, manifestRecordId, FIXTURE_EFFECTIVE_LEASE_EPOCH,
    publisherPair, compiled, runtimeOptions, catalog
  )
  const announcement = signedAnnouncement.record
  const announcementPrefix = signedAnnouncement.prefix
  const announcementBytes = signedAnnouncement.bytes
  const signedAnnouncementId = signedAnnouncement.signedAnnouncementId

  const epochSet = bootstrap.payload.inboxEpochSets[0]
  const frames = []
  for (let index = 0; index < epochSet.bindings.length; index++) {
    const binding = epochSet.bindings[index]
    const relayKey = Buffer.from(binding.relayPublicKey, 'hex')
    const topic = Buffer.from(binding.physicalTopic, 'hex')
    const info = concatBytes(
      asciiBytes('peerit.hiverelay.inbox-frame-key.v1'), u32Bytes(inboxEpoch), u8(0), relayKey
    )
    const frameKey = Buffer.from(hkdfSync(
      'sha256', Buffer.from(epochSet.announcementMasterKey, 'hex'), topic, info, 32
    ))
    const frameClass = 1
    const aad = concatBytes(
      asciiBytes('peerit.hiverelay.inbox-frame-aad.v1'), u32Bytes(inboxEpoch), u8(0),
      relayKey, topic, u8(frameClass)
    )
    const nonce = fixtureBytes(`frame-${index}:nonce`, 24)
    const plaintextLength = 4096 - 24 - 16
    const padding = fixtureBytes(`frame-${index}:padding`, plaintextLength - 4 - announcementBytes.byteLength)
    const plaintext = concatBytes(u32Bytes(announcementBytes.byteLength), announcementBytes, padding)
    const frame = concatBytes(nonce, xchachaSeal(frameKey, nonce, aad, plaintext))
    frames.push({
      relayId: binding.relayId,
      inboxEpoch,
      stripeIndex: 0,
      relayPublicKey: binding.relayPublicKey,
      physicalTopic: binding.physicalTopic,
      frameClass,
      frameKey: frameKey.toString('hex'),
      aadHex: hex(aad),
      nonceHex: hex(nonce),
      paddingSha256: sha256Hex(padding),
      plaintextSha256: sha256Hex(plaintext),
      frameCanonicalHex: hex(frame),
      frameHash: hex(blake2b256(frame))
    })
  }

  const readPages = []
  for (let index = 0; index < frames.length; index++) {
    const binding = epochSet.bindings[index]
    const relayKey = new Uint8Array(Buffer.from(binding.relayPublicKey, 'hex'))
    const topic = new Uint8Array(Buffer.from(binding.physicalTopic, 'hex'))
    const continuation = fixtureBytes(`inbox-read-${index}:next-cursor`, 32)
    const firstNonce = fixtureBytes(`inbox-read-${index}:page-0:nonce`, 32)
    const firstCommitment = inboxReadRequestCommitment(relayKey, topic, new Uint8Array(0), 1, firstNonce)
    const firstRequest = inboxReadRequestBytes(topic, new Uint8Array(0), 1, firstNonce)
    const firstResult = inboxReadResultBytes({
      relayBinding: relayBindings[index],
      requestNonce: firstNonce,
      requestCommitment: firstCommitment,
      snapshotRevision: 1n,
      entries: [{
        appendRevision: 1n,
        frameHash: new Uint8Array(Buffer.from(frames[index].frameHash, 'hex')),
        frameClass: frames[index].frameClass,
        frame: new Uint8Array(Buffer.from(frames[index].frameCanonicalHex, 'hex'))
      }],
      nextCursor: continuation
    }, relayPairs[index])
    readPages.push({
      relayId: binding.relayId,
      pageIndex: 0,
      requestCanonicalHex: hex(firstRequest),
      requestCommitment: hex(firstCommitment),
      resultCanonicalHex: hex(firstResult)
    })

    const secondNonce = fixtureBytes(`inbox-read-${index}:page-1:nonce`, 32)
    const secondCommitment = inboxReadRequestCommitment(relayKey, topic, continuation, 1, secondNonce)
    const secondRequest = inboxReadRequestBytes(topic, continuation, 1, secondNonce)
    const secondResult = inboxReadResultBytes({
      relayBinding: relayBindings[index],
      requestNonce: secondNonce,
      requestCommitment: secondCommitment,
      snapshotRevision: 1n,
      entries: [],
      nextCursor: null
    }, relayPairs[index])
    readPages.push({
      relayId: binding.relayId,
      pageIndex: 1,
      requestCanonicalHex: hex(secondRequest),
      requestCommitment: hex(secondCommitment),
      resultCanonicalHex: hex(secondResult)
    })
  }

  const vector = {
    schema: 'peerit-seq29-limited-public-test-positive-vector-v1',
    version: 1,
    fixtureOnly: true,
    bootstrapFixture: 'positive-bootstrap.json',
    bootstrapFloor: {
      schema: 'PeeritLimitedPublicInboxBootstrapFloorV1',
      version: 1,
      highestAcceptedBootstrapSequence: '0',
      completeSignedWrapperHash: hex(bootstrapWrapperHash)
    },
    issuance: {
      expectedCellPutCount: 2,
      expectedCellGetReadbackCount: 2,
      expectedInboxAppendCount: 2,
      emitterMode: 'INLINE_ONLY'
    },
    inner: {
      codec: 334,
      canonicalHex: hex(innerBytes),
      byteLength: innerBytes.byteLength,
      logicalHash: hex(logical),
      encodingCommitment: hex(encoding),
      oneAuthorPublicKey: hex(authorPair.publicKey),
      authorityNote: 'Fixture operation shape is not an application-validity claim; runtime gate must validate its real signed operation batch.'
    },
    cells: cellBindings.map(binding => {
      const readback = cellReadbackByRelay.get(hex(binding.relayPublicKey))
      const put = cellPutByRelay.get(hex(binding.relayPublicKey))
      return ({
      relayPublicKey: hex(binding.relayPublicKey),
      logicalHash: hex(binding.logicalHash),
      encodingCommitment: hex(binding.encodingCommitment),
      cellReplicaBindingCanonicalHex: hex(catalog.CellReplicaBindingV1.encode(binding)),
      readCapabilityCanonicalHex: hex(binding.readCapability),
      cellBlobHash: hex(binding.cellBlobHash),
      sizeClass: binding.sizeClass,
      allocationEpoch: binding.allocationEpoch,
      leaseEpoch: binding.leaseEpoch,
      createPublicKey: hex(binding.createPublicKey),
      renewPublicKey: hex(binding.renewPublicKey),
      dropPublicKey: hex(binding.dropPublicKey),
      allocationCommitment: hex(binding.allocationCommitment),
      relayReceiptCanonicalHex: hex(binding.relayReceipt),
      capabilityBoundPut: {
        familyId: 2,
        operationId: 1,
        requestCanonicalHex: hex(put.putRequest),
        allocationCommitment: hex(put.allocationCommitment),
        requestCommitment: hex(put.putRequestCommitment),
        clientNonce: hex(put.putClientNonce)
      },
      capabilityBoundGet: {
        familyId: 2,
        operationId: 2,
        requestCanonicalHex: hex(readback.getRequest),
        requestCommitment: hex(readback.getRequestCommitment),
        getResultCanonicalHex: hex(readback.getResult)
      }
      })
    }),
    authorBind: authorBindVectorValue(signedAuthor),
    announcement: announcementVectorValue(signedAnnouncement),
    frames,
    readPages,
    managementCustody: {
      schema: 'PeeritLimitedPublicInboxManagementCustodyV1',
      version: 1,
      bundleName: 'PeeritLimitedPublicInboxManagementBundleV1',
      envelopeName: 'PeeritLimitedPublicInboxCustodyEnvelopeV1',
      bundleKind: LIMITED_MANAGEMENT_BUNDLE_KIND,
      plaintextCodec: LIMITED_MANAGEMENT_PLAINTEXT_CODEC,
      currentEntryCount: 2,
      previousEntryCount: 0,
      seedRoles: ['CREATE', 'RENEW', 'CLOSE'],
      appendAuthMode: 'OPEN_APPEND',
      threshold: 2,
      totalShares: 3,
      envelopeCanonicalHex: hex(managementCustody.canonical),
      plaintextSha256: sha256Hex(managementPlaintext),
      fixtureCustodianPrivateKeys: managementCustody.custodians.map(value => hex(value.privateKey)),
      fixtureCustodianPublicKeys: managementCustody.custodians.map(value => hex(value.publicKey)),
      fixtureRecoveryCases: [
        {
          name: 'PAIR_1_2',
          envelopeCanonicalHex: hex(managementCustody.canonical),
          fixtureCustodianPrivateKeys: [0, 1].map(index => hex(managementCustody.custodians[index].privateKey)),
          expectedPassingPairs: ['1+2'],
          expectedRejectedShares: []
        },
        {
          name: 'PAIR_1_3',
          envelopeCanonicalHex: hex(managementCustody.canonical),
          fixtureCustodianPrivateKeys: [0, 2].map(index => hex(managementCustody.custodians[index].privateKey)),
          expectedPassingPairs: ['1+3'],
          expectedRejectedShares: []
        },
        {
          name: 'PAIR_2_3',
          envelopeCanonicalHex: hex(managementCustody.canonical),
          fixtureCustodianPrivateKeys: [1, 2].map(index => hex(managementCustody.custodians[index].privateKey)),
          expectedPassingPairs: ['2+3'],
          expectedRejectedShares: []
        },
        {
          name: 'THIRD_SHARE_TAMPER_RECOVERY',
          envelopeCanonicalHex: hex(thirdShareTamperedCustody.canonical),
          fixtureCustodianPrivateKeys: managementCustody.custodians.map(value => hex(value.privateKey)),
          expectedPassingPairs: ['1+2'],
          expectedRejectedShares: []
        }
      ]
    },
    cursor: {
      scopeFields: ['inboxEpoch', 'stripeIndex', 'relayPublicKey', 'physicalTopic'],
      snapshotLifetimeSeconds: 900,
      maximumCursorBytes: 128,
      signedPageVerifiedBeforeUse: true,
      invalidFrameAdvancesVerifiedPage: true,
      acceptedRecordsAndCursorAtomic: true,
      dedupeKey: 'manifestRecordId',
      orderingClaim: false,
      completenessClaim: false
    },
    retry: {
      exactRequestPersistedBeforeSend: true,
      exactSpendPersistedBeforeSend: true,
      exactFramePersistedBeforeSend: true,
      ambiguousOutcome: 'PENDING_UNKNOWN',
      reconcileCell: 'CELL.GET_EXACT_SLOT_AND_BLOB_HASH',
      reconcileInbox: 'INBOX.READ_EXACT_FRAME_HASH',
      changedTarget: 'NEW_ATTEMPT_FRESH_ALL_MATERIAL',
      frameReuseAllowed: false
    },
    consent: {
      boot: 'LURKER_NO_IDENTITY_NO_ADMISSION_NO_WRITE',
      confirmation: 'EXPLICIT',
      identityBeforeSignature: 'AUTHENTICATED_ENCRYPTED_DURABLE',
      signedIntentBeforeNetwork: true,
      localVisibleOffline: true,
      propagationOrder: ['CELL_ACK', 'CELL_GET_DECRYPT', 'AUTHOR_BIND_SIGN', 'INLINE_ANNOUNCEMENT_SIGN', 'INBOX_APPEND'],
      cancelBeforeIdentity: 'PRISTINE_LURKER_DRAFT_RETAINED',
      ambiguousSend: 'PENDING_UNKNOWN_RECONCILE_EXACT',
      forgetWhilePending: 'REFUSED_WITHOUT_RECONCILIATION_OR_COMPLETE_FRESH_RECOVERY_EXPORT'
    }
  }

  const wrongAuthorSigned = signedAuthorBindFixture({
    ...authorBindBase,
    authorPublicKey: new Uint8Array(publisherPair.publicKey)
  }, publisherPair, compiled, runtimeOptions, catalog)
  const logicalMismatch = new Uint8Array(logical)
  logicalMismatch[0] ^= 1
  const logicalMismatchSigned = signedAuthorBindFixture({
    ...authorBindBase,
    logicalHash: logicalMismatch
  }, authorPair, compiled, runtimeOptions, catalog)
  const sequenceGapSigned = signedAuthorBindFixture({
    ...authorBindBase,
    authorSequence: 2n,
    previousAuthorRecordId: fixtureBytes('fixture-author-predecessor-gap', 32)
  }, authorPair, compiled, runtimeOptions, catalog)
  const changedAllocation = new Uint8Array(cellBindings[0].allocationCommitment)
  changedAllocation[0] ^= 1
  const mismatchedReplicas = [
    { ...cellBindings[0], allocationCommitment: changedAllocation },
    cellBindings[1]
  ].sort((left, right) => compareBytes(cellReplicaProjection(left), cellReplicaProjection(right)))
  const replicaMismatchSigned = signedAuthorBindFixture({
    ...authorBindBase,
    initialReplicas: mismatchedReplicas
  }, authorPair, compiled, runtimeOptions, catalog)
  const futureAnnouncementSigned = signedAnnouncementFixture(
    authorBindBytes, manifestRecordId, FIXTURE_EFFECTIVE_LEASE_EPOCH + 2,
    publisherPair, compiled, runtimeOptions, catalog
  )
  const firstCell = cellBindings[0]
  const firstRelayIndex = relayPairs.findIndex(value => hex(value.publicKey) === hex(firstCell.relayPublicKey))
  const firstCap = decodeBlindExternalProfileValueV1('ReadCellCapV1', firstCell.readCapability)
  const firstPut = cellPutByRelay.get(hex(firstCell.relayPublicKey))
  const wrongReceiptRequestCommitment = fixtureBytes('cell-signed-wrong-request-commitment', 32)
  const wrongRequestReceipt = blindReceiptBytes({
    relayBinding: relayBindings[firstRelayIndex],
    slotCommitment: blake2b256(firstCap.storageSlot),
    cellBlobHash: firstCell.cellBlobHash,
    allocationCommitment: firstCell.allocationCommitment,
    requestCommitment: wrongReceiptRequestCommitment,
    sizeClass: firstCell.sizeClass,
    allocationEpoch: firstCell.allocationEpoch,
    leaseClass: 4,
    leaseEpoch: firstCell.leaseEpoch,
    stateRevision: 0n,
    receiptEpoch: FIXTURE_EFFECTIVE_LEASE_EPOCH,
    requestNonce: firstPut.putClientNonce,
    result: 1
  }, relayPairs[firstRelayIndex])

  const invalidManagementCustodyVector = {
    ...vector.managementCustody,
    envelopeCanonicalHex: hex(invalidManagementCustody.canonical),
    plaintextSha256: sha256Hex(invalidManagementPlaintext),
    fixtureCustodianPrivateKeys: invalidManagementCustody.custodians.map(value => hex(value.privateKey)),
    fixtureCustodianPublicKeys: invalidManagementCustody.custodians.map(value => hex(value.publicKey))
  }
  const driftResult = Buffer.from(readPages[0].resultCanonicalHex, 'hex')
  const driftUnsigned = driftResult.subarray(0, driftResult.byteLength - 64)
  const fullResultDriftBytes = concatBytes(driftUnsigned, new Uint8Array(sign(null,
    resultSignaturePayload('hiverelay.blind.inbox-read-result.v1', driftUnsigned), relayPairs[0].privateKey)))
  const wrongRecipient = x25519Pair('limited-custody-wrong-recipient')
  const negativeFixtures = Object.freeze([
    ...staticNegativeFixtures,
    ['44-custody-entry-binding.json', 'vector', null, {
      op: 'replace',
      path: '/managementCustody',
      value: invalidManagementCustodyVector
    }, 'CUSTODY_ENTRY_BINDING'],
    ['45-read-signature-payload-drift.json', 'vector', null, {
      op: 'replace',
      path: '/readPages/0/resultCanonicalHex',
      value: hex(fullResultDriftBytes)
    }, 'READ_SIGNATURE_PAYLOAD_DRIFT'],
    ['46-custody-malicious-plus-unavailable.json', 'vector', null, {
      op: 'replace',
      path: '/managementCustody/fixtureRecoveryCases/3/fixtureCustodianPrivateKeys',
      value: [
        hex(managementCustody.custodians[0].privateKey),
        hex(managementCustody.custodians[2].privateKey)
      ]
    }, 'CUSTODY_RECONSTRUCTION'],
    ['47-custody-wrong-recipient.json', 'vector', null, {
      op: 'replace',
      path: '/managementCustody/fixtureRecoveryCases/0/fixtureCustodianPrivateKeys/1',
      value: hex(wrongRecipient.privateBytes)
    }, 'CUSTODY_WRONG_RECIPIENT'],
    ['48-custody-duplicate-public-pin.json', 'vector', null, {
      op: 'copy',
      from: '/managementCustody/fixtureCustodianPublicKeys/0',
      path: '/managementCustody/fixtureCustodianPublicKeys/1'
    }, 'CUSTODY_DUPLICATE'],
    ['49-custody-low-order-public-pin.json', 'vector', null, {
      op: 'replace',
      path: '/managementCustody/fixtureCustodianPublicKeys/0',
      value: '00'.repeat(32)
    }, 'CUSTODY_LOW_ORDER_PUBLIC_KEY'],
    ['50-custody-duplicate-share-nonce.json', 'vector', null, {
      op: 'replace',
      path: '/managementCustody/envelopeCanonicalHex',
      value: hex(duplicateNonceCustody.canonical)
    }, 'CUSTODY_DUPLICATE'],
    ['51-custody-duplicate-share-ciphertext.json', 'vector', null, {
      op: 'replace',
      path: '/managementCustody/envelopeCanonicalHex',
      value: hex(duplicateCiphertextCustody.canonical)
    }, 'CUSTODY_DUPLICATE'],
    ['52-bootstrap-u64-overflow.json', 'bootstrap', 'POST_SIGNATURE', {
      op: 'replace', path: '/payload/bootstrapSequence', value: '18446744073709551616'
    }, 'U64_RANGE'],
    ['53-bootstrap-not-yet-valid.json', 'bootstrap', 'POST_SIGNATURE', {
      op: 'replace', path: '/payload/issuedUnixMillis', value: '1780000002000'
    }, 'BOOTSTRAP_NOT_YET_VALID'],
    ['54-bootstrap-expired.json', 'bootstrap', 'POST_SIGNATURE', {
      op: 'replace', path: '/payload/expiresUnixMillis', value: '1780000001000'
    }, 'BOOTSTRAP_EXPIRED'],
    ['55-initial-second-epoch-set.json', 'bootstrap', 'POST_SIGNATURE', {
      op: 'copy', from: '/payload/inboxEpochSets/0', path: '/payload/inboxEpochSets/1'
    }, 'INITIAL_EPOCH_SET'],
    ['56-bootstrap-noncurrent-epoch.json', 'bootstrap', 'POST_SIGNATURE', {
      op: 'replace', path: '/payload/inboxEpochSets/0/inboxEpoch', value: FIXTURE_CURRENT_INBOX_EPOCH + 1
    }, 'EPOCH_CURRENT'],
    ['57-successor-sequence-gap.json', 'successor', 'POST_SIGNATURE', {
      op: 'replace', path: '/payload/bootstrapSequence', value: '3'
    }, 'BOOTSTRAP_SEQUENCE'],
    ['58-successor-predecessor-fork.json', 'successor', 'POST_SIGNATURE', {
      op: 'xor-hex', path: '/payload/previousBootstrapHash', byteIndex: 0, mask: 1
    }, 'BOOTSTRAP_PREDECESSOR'],
    ['59-successor-epoch-key-reuse.json', 'successor', 'POST_SIGNATURE', {
      op: 'replace', path: '/payload/inboxEpochSets/0/stripeSelectionKey',
      value: bootstrap.payload.inboxEpochSets[0].stripeSelectionKey
    }, 'EPOCH_REUSE'],
    ['60-successor-u64-overflow.json', 'successor', 'POST_SIGNATURE', {
      op: 'replace', path: '/payload/bootstrapSequence', value: '18446744073709551616'
    }, 'U64_RANGE'],
    ['61-valid-signature-wrong-inner-authority.json', 'vector', null, {
      op: 'replace', path: '/authorBind', value: authorBindVectorValue(wrongAuthorSigned)
    }, 'INNER_AUTHORITY'],
    ['62-valid-signature-logical-mismatch.json', 'vector', null, {
      op: 'replace', path: '/authorBind', value: authorBindVectorValue(logicalMismatchSigned)
    }, 'AUTHOR_BIND_SEMANTICS'],
    ['63-valid-signature-author-sequence-gap.json', 'vector', null, {
      op: 'replace', path: '/authorBind', value: authorBindVectorValue(sequenceGapSigned)
    }, 'AUTHOR_CHAIN'],
    ['64-valid-signature-replica-allocation-mismatch.json', 'vector', null, {
      op: 'replace', path: '/authorBind', value: authorBindVectorValue(replicaMismatchSigned)
    }, 'AUTHOR_BIND_SEMANTICS'],
    ['65-valid-signature-future-announcement.json', 'vector', null, {
      op: 'replace', path: '/announcement', value: announcementVectorValue(futureAnnouncementSigned)
    }, 'ANNOUNCEMENT_TIME'],
    ['66-cell-put-allocation-commitment.json', 'vector', null, {
      op: 'xor-hex', path: '/cells/0/capabilityBoundPut/allocationCommitment', byteIndex: 0, mask: 1
    }, 'CELL_PUT_BINDING'],
    ['67-cell-put-request-commitment.json', 'vector', null, {
      op: 'xor-hex', path: '/cells/0/capabilityBoundPut/requestCommitment', byteIndex: 0, mask: 1
    }, 'CELL_PUT_BINDING'],
    ['68-valid-signature-cell-receipt-request-mismatch.json', 'vector', null, {
      op: 'replace', path: '/cells/0/relayReceiptCanonicalHex', value: hex(wrongRequestReceipt)
    }, 'CELL_PUT_BINDING'],
    ['69-cross-relay-create-key-reuse.json', 'vector', null, {
      op: 'copy', from: '/cells/0/createPublicKey', path: '/cells/1/createPublicKey'
    }, 'CELL_EQUALITY'],
    ['70-custody-duplicate-ephemeral-key.json', 'vector', null, {
      op: 'replace', path: '/managementCustody/envelopeCanonicalHex', value: hex(duplicateEphemeralCustody.canonical)
    }, 'CUSTODY_DUPLICATE'],
    ['71-custody-nonzero-low-order-ephemeral.json', 'vector', null, {
      op: 'replace', path: '/managementCustody/envelopeCanonicalHex', value: hex(lowOrderEphemeralCustody.canonical)
    }, 'CUSTODY_LOW_ORDER_PUBLIC_KEY'],
    ['72-cell-put-blob-tamper.json', 'vector', null, {
      op: 'xor-hex', path: '/cells/0/capabilityBoundPut/requestCanonicalHex', byteIndex: -1, mask: 1
    }, 'CELL_PUT_BINDING']
  ])

  await fs.writeFile(path.join(FIXTURES, 'positive-bootstrap.json'), jsonBytes(bootstrap))
  await fs.writeFile(path.join(FIXTURES, 'positive-bootstrap-successor.json'), jsonBytes(successorBootstrap))
  await fs.writeFile(path.join(FIXTURES, 'positive-protocol-vector.json'), jsonBytes(vector))
  for (const [name, target, validationStage, mutation, expectedError] of negativeFixtures) {
    const value = { schema: 'peerit-seq29-limited-public-test-negative-v1', version: 1, target }
    if (validationStage != null) value.validationStage = validationStage
    value.mutation = mutation
    value.expectedError = expectedError
    await fs.writeFile(path.join(NEGATIVE, name), jsonBytes(value))
  }
  const actualNegative = (await fs.readdir(NEGATIVE)).filter(name => name.endsWith('.json')).sort()
  const expectedNegative = negativeFixtures.map(value => value[0]).sort()
  if (actualNegative.join('\n') !== expectedNegative.join('\n')) {
    throw new Error('negative fixture directory contains an unexpected or missing JSON file')
  }

  const artifacts = [
    'config/peerit-limited-availability-bootstrap-v1.schema.json',
    'docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md',
    'protocol/seq29-limited-public-test/canonical-cross-check.mjs',
    'protocol/seq29-limited-public-test/check.mjs',
    'protocol/seq29-limited-public-test/codec-registry-v1.json',
    'protocol/seq29-limited-public-test/compatibility-v1.json',
    'protocol/seq29-limited-public-test/generate-fixtures.mjs',
    'protocol/seq29-limited-public-test/limited-management-custody-v1.json',
    'protocol/validator/peerit-validator-v1.bare.mjs',
    'test/fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json',
    'test/fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap-successor.json',
    'test/fixtures/peerit-seq29-limited-public-test-v1/positive-protocol-vector.json',
    ...expectedNegative.map(name => `test/fixtures/peerit-seq29-limited-public-test-v1/negative/${name}`)
  ].sort()
  const rows = []
  for (const relative of artifacts) {
    const value = await fs.readFile(path.join(ROOT, relative))
    rows.push({ path: relative, byteLength: value.byteLength, sha256: sha256Hex(value) })
  }
  const aggregate = createHash('sha256')
  for (const row of rows) aggregate.update(`${row.path}\0${row.byteLength}\0${row.sha256}\n`, 'utf8')
  const manifest = {
    schema: 'peerit-seq29-limited-public-test-vector-manifest-v1',
    version: 1,
    status: 'FIXTURE_ONLY_NOT_RELEASE_AUTHORITY',
    source: {
      preservedCommit: '4ada838b372360c9b0a7675c0ef190a62edef22f',
      profileSpecSha256: PROFILE_SPEC_SHA256,
      hiverelayCodecProvenanceCommit: HIVERELAY_PROVENANCE
    },
    generator: 'protocol/seq29-limited-public-test/generate-fixtures.mjs',
    generatorCommand: 'node protocol/seq29-limited-public-test/generate-fixtures.mjs',
    checker: 'protocol/seq29-limited-public-test/check.mjs',
    positiveFixtureCount: 3,
    negativeFixtureCount: expectedNegative.length,
    aggregateRecipe: 'SHA-256(path || NUL || decimalByteLength || NUL || lowercaseSha256 || LF), paths sorted lexicographically; vector-manifest-v1.json is excluded',
    artifactAggregateSha256: aggregate.digest('hex'),
    artifacts: rows
  }
  await fs.writeFile(path.join(HERE, 'vector-manifest-v1.json'), jsonBytes(manifest))
  console.log(JSON.stringify({
    status: 'GENERATED',
    artifactClass: 'FIXTURE_ONLY',
    positiveFixtures: 3,
    negativeFixtures: expectedNegative.length,
    artifactAggregateSha256: manifest.artifactAggregateSha256
  }))
}

await generate()
