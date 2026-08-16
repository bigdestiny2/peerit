#!/usr/bin/env node

// Sequence-29's four-write drill. Production construction starts from the
// module-branded browser runtime/app assembly, its authenticated relay
// endpoints and pure publication inputs. This module creates the operation
// driver and owns the only direct HTTP client. The runner never accepts a
// caller control, prepare hook, verifier hook or send callback.

import {
  createDecipheriv,
  createHash,
  createPublicKey,
  verify as verifySignature
} from 'node:crypto'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  canonicalPeeritLimitedPublicInboxJsonV1,
  verifyPeeritLimitedPublicInboxBootstrapV1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  getVerifiedPeeritBrowserRuntimeAssembly
} from '../js/substrate/browser-runtime-authority.mjs'
import {
  verifyPeeritPublicInboxAnnouncementReadbackV1
} from '../js/substrate/inbox-discovery.mjs'
import {
  preparePeeritPublicInboxAnnouncementV1
} from '../js/substrate/inbox-pointer-publish.mjs'
import {
  decodePeeritInboxAppendAckSnapshotV1,
  decodePeeritInboxReadResultSnapshotV1
} from '../js/substrate/inbox-read-result-decode.mjs'
import {
  openPeeritInboxAnnouncementFrameV1
} from '../js/substrate/inbox-pointer-frame-v1.mjs'
import {
  verifyPeeritSeq29CellPutReadbackEvidenceV1,
  verifyPeeritSeq29PublicInboxRelayEndpointsV1
} from '../js/substrate/public-inbox-boot-coordinator.mjs'
import {
  peeritAuthorBindCellSizeClassForInnerLengthV1
} from '../js/substrate/author-bind-inner-envelope-policy.mjs'
import {
  decodePeeritInnerOperationBatchV1,
  hashPeeritInnerCellEncodingCommitmentV1,
  hashPeeritInnerLogicalHashV1
} from '../js/substrate/peerit-operation-authority-v1.js'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  u16Bytes,
  u32Bytes,
  u64Bytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
  hashPeeritLimitedPublicInboxSignedWrapperV1,
  validatePeeritLimitedPublicInboxSignedWrapperV1
} from './sign-limited-public-inbox-bootstrap.mjs'
import {
  decodeBlindExternalProfileValueV1
} from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'

export const PEERIT_SEQ29_BOUNDED_PUBLICATION_DRILL_SCHEMA_V1 =
  'peerit-seq29-bounded-publication-drill-v1'
export const PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1 = createHash('sha256')
  .update('peerit.seq29.limited-public-test.publication-drill.release-slot.v1')
  .digest('hex')

const AUTHORITY = new WeakMap()
const PREPARED = new WeakSet()
const PRODUCTION_PREPARED = new WeakMap()
const PRODUCTION_VERIFIED = new WeakMap()
const PRODUCTION_APPEND_EVIDENCE = new WeakMap()
const PUBLICATION_PREPARATIONS = new WeakMap()
const CONSUMED_PREPARATIONS = new WeakSet()
const TEST_ONLY_FIXTURE_ENV = 'PEERIT_SEQ29_OPERATOR_FIXTURE_TEST'
const AUTHORITY_FIELDS = Object.freeze([
  'prepareCellPut', 'verifyCellPutReadback', 'prepareInboxAppend',
  'verifyInboxAppend', 'freshReadCellGet', 'decodeWireRequest',
  'verifyWriteResult'
])
const FAMILY_OPERATION = Object.freeze({
  'CELL.PUT': Object.freeze({ familyId: 2, operationId: 1 }),
  'INBOX.APPEND': Object.freeze({ familyId: 3, operationId: 4 })
})

function fail (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details !== undefined) error.details = details
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      `${field} fields are missing or unexpected`)
  }
  return value
}

function opaque (value, field, maximum = 4096) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', `${field} is invalid`)
  }
  return value
}

function hex32 (value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', `${field} must be lowercase 32-byte hex`)
  }
  return value
}

function hashObject (value) {
  return createHash('sha256')
    .update(canonicalPeeritLimitedPublicInboxJsonV1(value)).digest('hex')
}

function bytesHash (value, field) {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > 1048576) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', `${field} must be bounded bytes`)
  }
  return createHash('sha256').update(value).digest('hex')
}

function fixedBytes (value, length, field) {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID',
      `${field} must be exactly ${length} bytes`)
  }
  return value
}

function sameReadCap (left, right, field) {
  if (!left || !right || left.version !== 1 || right.version !== 1 ||
      left.sizeClass !== right.sizeClass ||
      !bytesEqual(fixedBytes(left.relayPublicKey, 32, `${field}.left.relayPublicKey`),
        fixedBytes(right.relayPublicKey, 32, `${field}.right.relayPublicKey`)) ||
      !bytesEqual(fixedBytes(left.storageSlot, 32, `${field}.left.storageSlot`),
        fixedBytes(right.storageSlot, 32, `${field}.right.storageSlot`)) ||
      !bytesEqual(fixedBytes(left.cellKey, 32, `${field}.left.cellKey`),
        fixedBytes(right.cellKey, 32, `${field}.right.cellKey`)) ||
      !bytesEqual(fixedBytes(left.expectedCellBlobHash, 32,
        `${field}.left.expectedCellBlobHash`), fixedBytes(right.expectedCellBlobHash, 32,
        `${field}.right.expectedCellBlobHash`))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID',
      `${field} differs from the exact prepared CELL.PUT read capability`)
  }
}

function boundedBigInt (value, field) {
  let output
  try { output = BigInt(value) } catch {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID', `${field} is not an integer`)
  }
  if (output < 0n || output > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID', `${field} is outside the bound`)
  }
  return output
}

// This exact validator is shared by the production branded path and its
// adversarial regression. Branding and authenticated I/O happen before it;
// this function proves that every authenticated object describes one and the
// same prepared PUT, signed AuthorBind and intrinsic operation batch.
export function validatePeeritSeq29PreparedPutReadbackBindingV1 (input = {}) {
  exact(input, [
    'request', 'readCap', 'publication', 'announcementBytes',
    'verifiedAnnouncementBytes', 'readback'
  ], 'prepared PUT readback binding input')
  const { request, readCap, publication, readback } = input
  if (!request || request.version !== 1 || !readCap || readCap.version !== 1 ||
      !publication || !readback || request.sizeClass !== readCap.sizeClass ||
      request.sizeClass !== publication.sizeClass ||
      !bytesEqual(fixedBytes(request.storageSlot, 32, 'PUT request storageSlot'),
        fixedBytes(readCap.storageSlot, 32, 'prepared readCap storageSlot')) ||
      !bytesEqual(fixedBytes(request.declaredBlobHash, 32, 'PUT request declaredBlobHash'),
        fixedBytes(readCap.expectedCellBlobHash, 32, 'prepared readCap expectedCellBlobHash')) ||
      !bytesEqual(fixedBytes(readCap.relayPublicKey, 32, 'prepared readCap relayPublicKey'),
        fixedBytes(readback.replica?.relayPublicKey, 32, 'AuthorBind replica relayPublicKey'))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID',
      'PUT request, prepared read capability and signed replica identity differ')
  }
  sameReadCap(readCap, readback.readCap, 'signed AuthorBind readCap')
  const announcementBytes = fixedBytes(input.announcementBytes,
    input.announcementBytes?.byteLength, 'expected announcementBytes')
  const verifiedAnnouncementBytes = fixedBytes(input.verifiedAnnouncementBytes,
    announcementBytes.byteLength, 'verified announcementBytes')
  if (announcementBytes.byteLength < 1 || announcementBytes.byteLength > 1048576 ||
      !bytesEqual(announcementBytes, verifiedAnnouncementBytes)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID',
      'verified announcement bytes differ from the exact drill announcement')
  }
  const innerBytes = fixedBytes(publication.innerBytes,
    publication.innerBytes?.byteLength, 'prepared publication innerBytes')
  if (innerBytes.byteLength < 1 || innerBytes.byteLength > 1048576 ||
      boundedBigInt(publication.innerLength, 'publication.innerLength') !==
        BigInt(innerBytes.byteLength) ||
      boundedBigInt(readback.authorBind?.innerLength, 'AuthorBind.innerLength') !==
        BigInt(innerBytes.byteLength) ||
      boundedBigInt(readback.operationBatch?.innerLength, 'operationBatch.innerLength') !==
        BigInt(innerBytes.byteLength) ||
      readback.authorBind?.innerCodec !== publication.innerCodec ||
      readback.operationBatch?.innerCodec !== publication.innerCodec ||
      readback.operationBatch?.sizeClass !== publication.sizeClass ||
      readback.replica?.sizeClass !== publication.sizeClass) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID',
      'AuthorBind or opened operation batch differs from the prepared envelope shape')
  }
  const expectedLogicalHash = hashPeeritInnerLogicalHashV1(publication.innerCodec, innerBytes)
  const expectedEncodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
    publication.innerCodec, innerBytes, expectedLogicalHash, publication.sizeClass)
  for (const [value, expected, field] of [
    [publication.logicalHash, expectedLogicalHash, 'publication.logicalHash'],
    [publication.encodingCommitment, expectedEncodingCommitment,
      'publication.encodingCommitment'],
    [readback.authorBind?.logicalHash, expectedLogicalHash, 'AuthorBind.logicalHash'],
    [readback.replica?.logicalHash, expectedLogicalHash, 'replica.logicalHash'],
    [readback.replica?.encodingCommitment, expectedEncodingCommitment,
      'replica.encodingCommitment'],
    [readback.operationBatch?.logicalHash, expectedLogicalHash,
      'operationBatch.logicalHash'],
    [readback.operationBatch?.encodingCommitment, expectedEncodingCommitment,
      'operationBatch.encodingCommitment'],
    [readback.operationBatch?.innerBytes, innerBytes, 'operationBatch.innerBytes']
  ]) {
    if (!(value instanceof Uint8Array) || !bytesEqual(value, expected)) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID',
        `${field} differs from the exact prepared intrinsic publication`)
    }
  }
  return Object.freeze({
    announcementSha256: bytesHash(announcementBytes, 'announcementBytes'),
    innerSha256: bytesHash(innerBytes, 'innerBytes'),
    logicalHash: bytesToHex(expectedLogicalHash),
    cellBlobHash: bytesToHex(readCap.expectedCellBlobHash),
    storageSlot: bytesToHex(readCap.storageSlot)
  })
}

function methods (value, names, field) {
  if (!value || typeof value !== 'object' || names.some(name => typeof value[name] !== 'function')) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', `${field} lacks ${names.join(', ')}`)
  }
  return value
}

function durableReceipt (value, state, fields, field, expected = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0') ||
      value.accepted !== true || value.durable !== true || value.state !== state ||
      Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      `${field} was not durably accepted and correlated in state ${state}`)
  }
  opaque(value.commitment, `${field}.commitment`, 512)
  return value
}

function bindingRows (wrapper) {
  const relayById = new Map(wrapper.payload.relays.map(relay => [relay.relayId, relay]))
  const bindings = wrapper.payload.inboxEpochSets[0].bindings
  const rows = bindings.map(binding => {
    const relay = relayById.get(binding.relayId)
    return Object.freeze({
      relayId: binding.relayId,
      relayPublicKey: binding.relayPublicKey,
      storeId: relay.storeId,
      durabilityContinuityHash: relay.durabilityContinuityHash,
      physicalTopic: binding.physicalTopic,
      allocationEpoch: binding.allocationEpoch
    })
  })
  for (const field of [
    'relayId', 'relayPublicKey', 'storeId', 'physicalTopic'
  ]) {
    if (new Set(rows.map(row => row[field])).size !== 2) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
        `verified bootstrap ${field} identities must be distinct`)
    }
  }
  return Object.freeze(rows)
}

export function createPeeritSeq29BoundedPublicationFixtureAuthorityV1 (input = {}) {
  exact(input, [
    'allowFixture', 'hiverelayCommit', 'signedBootstrap', 'signedBootstrapHash',
    'control', 'send'
  ], 'publication authority input')
  if (process.env[TEST_ONLY_FIXTURE_ENV] !== '1' || input.allowFixture !== true) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'fixture publication authority is disabled outside focused tests')
  }
  if (input.hiverelayCommit !== PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', 'accepted HiveRelay candidate is not pinned')
  }
  const wrapper = validatePeeritLimitedPublicInboxSignedWrapperV1(
    input.signedBootstrap, { allowFixture: true })
  if (wrapper.payload.artifactClass !== 'FIXTURE_ONLY' ||
      wrapper.payload.relays.some(relay => new URL(relay.canonicalDescribeUrl).hostname
        .endsWith('.invalid') !== true)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'fixture publication authority requires a FIXTURE_ONLY .invalid bootstrap')
  }
  const control = exact(input.control, AUTHORITY_FIELDS, 'trusted publication control')
  methods(control, AUTHORITY_FIELDS, 'trusted publication control')
  if (typeof input.send !== 'function') {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'fixture publication authority requires its closed fixture send boundary')
  }
  const bootstrapHash = hashPeeritLimitedPublicInboxSignedWrapperV1(
    wrapper.canonicalBytes, { allowFixture: true })
  if (input.signedBootstrapHash !== bootstrapHash) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'signed bootstrap hash does not match the verified wrapper')
  }
  const rows = bindingRows(wrapper)
  const authority = Object.freeze({
    candidateCommit: PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
    releaseSequence: 29,
    bootstrapHash,
    rows
  })
  AUTHORITY.set(authority, Object.freeze({ control, send: input.send, fixtureOnly: true }))
  return authority
}

function rejectCallables (value, field, seen = new Set()) {
  if (typeof value === 'function') {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      `${field} must not contain caller-supplied functions`)
  }
  if (value == null || typeof value !== 'object' || seen.has(value)) return
  seen.add(value)
  if (value instanceof Map) {
    for (const [key, child] of value) {
      rejectCallables(key, `${field}.mapKey`, seen)
      rejectCallables(child, `${field}.mapValue`, seen)
    }
    return
  }
  for (const [key, child] of Object.entries(value)) {
    rejectCallables(child, `${field}.${key}`, seen)
  }
}

function productionRow (endpointSet) {
  return Object.freeze({
    relayId: endpointSet.relayId,
    relayPublicKey: bytesToHex(endpointSet.binding.relayPublicKey),
    storeId: bytesToHex(endpointSet.binding.storeId),
    durabilityContinuityHash: bytesToHex(endpointSet.binding.durabilityContinuityHash),
    physicalTopic: bytesToHex(endpointSet.binding.physicalTopic),
    allocationEpoch: endpointSet.binding.allocationEpoch
  })
}

function publicationForRow (value, row) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', `${row.relayId} publication is invalid`)
  }
  const required = [
    'intentId', 'logicalId', 'innerCodec', 'innerBytes', 'innerLength',
    'sizeClass', 'logicalHash', 'encodingCommitment'
  ]
  if (Object.keys(value).sort().join('\0') !== required.sort().join('\0') ||
      typeof value.intentId !== 'string' || typeof value.logicalId !== 'string' ||
      !Number.isSafeInteger(value.innerCodec) || !(value.innerBytes instanceof Uint8Array) ||
      value.innerBytes.byteLength < 1 || value.innerBytes.byteLength > 1048576 ||
      value.innerLength !== value.innerBytes.byteLength ||
      !Number.isSafeInteger(value.sizeClass) || value.sizeClass < 1 || value.sizeClass > 5 ||
      !(value.logicalHash instanceof Uint8Array) || value.logicalHash.byteLength !== 32 ||
      !(value.encodingCommitment instanceof Uint8Array) ||
      value.encodingCommitment.byteLength !== 32) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      `${row.relayId} publication does not have the exact bounded Peerit envelope shape`)
  }
  const publication = Object.freeze({
    intentId: value.intentId,
    logicalId: value.logicalId,
    innerCodec: value.innerCodec,
    innerBytes: value.innerBytes.slice(),
    innerLength: value.innerLength,
    sizeClass: value.sizeClass,
    logicalHash: value.logicalHash.slice(),
    encodingCommitment: value.encodingCommitment.slice()
  })
  let expectedLogicalHash
  let expectedEncodingCommitment
  let expectedSizeClass
  try {
    expectedSizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(
      BigInt(publication.innerBytes.byteLength))
    expectedLogicalHash = hashPeeritInnerLogicalHashV1(
      publication.innerCodec, publication.innerBytes)
    expectedEncodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
      publication.innerCodec, publication.innerBytes, expectedLogicalHash, expectedSizeClass)
  } catch (cause) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      `${row.relayId} publication is not an intrinsic Peerit operation envelope`, cause)
  }
  if (publication.sizeClass !== expectedSizeClass ||
      !bytesEqual(publication.logicalHash, expectedLogicalHash) ||
      !bytesEqual(publication.encodingCommitment, expectedEncodingCommitment)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      `${row.relayId} publication logical hash, encoding commitment, or minimum Cell class differs from its exact inner bytes`)
  }
  return publication
}

function publicationRelease (bootstrapHash, rows) {
  const releaseIdentity = Object.freeze({
    schema: 'peerit-seq29-publication-release-identity-v1',
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    candidateCommit: PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
    releaseSequence: 29,
    bootstrapHash,
    rows
  })
  const releaseIdentityDigest = hashObject(releaseIdentity)
  const beginRequest = Object.freeze({
    schema: 'peerit-seq29-bounded-publication-attempt-v1',
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest,
    operationManifest: Object.freeze([
      `CELL.PUT:${rows[0].relayId}`,
      `CELL.PUT:${rows[1].relayId}`,
      `INBOX.APPEND:${rows[0].relayId}`,
      `INBOX.APPEND:${rows[1].relayId}`
    ])
  })
  return Object.freeze({ releaseIdentityDigest, beginRequest })
}

function encodeReadCellCapV1 (value) {
  const expected = fixedBytes(value.expectedCellBlobHash, 32,
    'readCap.expectedCellBlobHash')
  return concatBytes(
    Uint8Array.of(1),
    fixedBytes(value.relayPublicKey, 32, 'readCap.relayPublicKey'),
    fixedBytes(value.storageSlot, 32, 'readCap.storageSlot'),
    fixedBytes(value.cellKey, 32, 'readCap.cellKey'),
    Uint8Array.of(value.sizeClass),
    Uint8Array.of(1),
    expected
  )
}

const CELL_BLOB_BYTES = Object.freeze({
  1: 4096,
  2: 16384,
  3: 65536,
  4: 262144,
  5: 1048576
})

function putReader (input) {
  const bytes = fixedBytes(input, input?.byteLength, 'PutCellV1 bytes')
  let offset = 0
  const take = (length, field) => {
    if (!Number.isSafeInteger(length) || length < 0 || offset + length > bytes.byteLength) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
        `recovered PutCellV1 truncates ${field}`)
    }
    const output = bytes.slice(offset, offset + length)
    offset += length
    return output
  }
  return Object.freeze({
    bytes,
    take,
    u8: field => take(1, field)[0],
    u16: field => {
      const value = take(2, field)
      return value[0] * 0x100 + value[1]
    },
    u32: field => {
      const value = take(4, field)
      return value[0] * 0x1000000 + value[1] * 0x10000 + value[2] * 0x100 + value[3]
    },
    end: () => offset === bytes.byteLength
  })
}

function decodePutCellRequestV1 (requestBytes) {
  const reader = putReader(requestBytes)
  const version = reader.u8('version')
  const storageSlot = reader.take(32, 'storageSlot')
  const allocationEpoch = reader.u32('allocationEpoch')
  const sizeClass = reader.u8('sizeClass')
  const leaseClass = reader.u8('leaseClass')
  const clientNonce = reader.take(32, 'clientNonce')
  const createPublicKey = reader.take(32, 'createPublicKey')
  const renewPublicKey = reader.take(32, 'renewPublicKey')
  const dropPublicKey = reader.take(32, 'dropPublicKey')
  const declaredBlobHash = reader.take(32, 'declaredBlobHash')
  const createSignature = reader.take(64, 'createSignature')
  const profileId = reader.u16('admission.profileId')
  const schemeId = reader.u16('admission.schemeId')
  const parameterHash = reader.take(32, 'admission.parameterHash')
  const tokenLength = reader.u8('admission token length')
  const token = reader.take(tokenLength, 'admission.token')
  const blobLength = CELL_BLOB_BYTES[sizeClass]
  if (version !== 1 || blobLength == null || leaseClass !== 4 || profileId < 1 ||
      schemeId < 1 || tokenLength < 1 || tokenLength > 0xfc) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'recovered PutCellV1 has a non-canonical version, class, lease, or admission')
  }
  const cellBlob = reader.take(blobLength, 'cellBlob')
  if (!reader.end()) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'recovered PutCellV1 has trailing bytes')
  }
  return Object.freeze({
    version,
    storageSlot,
    allocationEpoch,
    sizeClass,
    leaseClass,
    clientNonce,
    createPublicKey,
    renewPublicKey,
    dropPublicKey,
    declaredBlobHash,
    createSignature,
    admission: Object.freeze({ profileId, schemeId, parameterHash, token }),
    cellBlob
  })
}

function encodePutCellRequestV1 (value) {
  return concatBytes(
    Uint8Array.of(value.version), value.storageSlot, u32Bytes(value.allocationEpoch),
    Uint8Array.of(value.sizeClass, value.leaseClass), value.clientNonce,
    value.createPublicKey, value.renewPublicKey, value.dropPublicKey,
    value.declaredBlobHash, value.createSignature,
    u16Bytes(value.admission.profileId), u16Bytes(value.admission.schemeId),
    value.admission.parameterHash, Uint8Array.of(value.admission.token.byteLength),
    value.admission.token, value.cellBlob
  )
}

function cellAllocationCommitmentV1 (relayPublicKey, value) {
  return blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.allocate.v1'), relayPublicKey, value.storageSlot,
    u32Bytes(value.allocationEpoch), Uint8Array.of(value.sizeClass, value.leaseClass),
    value.declaredBlobHash, value.createPublicKey, value.renewPublicKey,
    value.dropPublicKey
  ))
}

function cellPutRequestCommitmentV1 (allocationCommitment, clientNonce) {
  return blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.request.v1cell-put'), allocationCommitment, clientNonce
  ))
}

function rawEd25519PublicKey (bytes) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(fixedBytes(bytes, 32, 'Ed25519 public key'))
    ]),
    format: 'der',
    type: 'spki'
  })
}

function openPreparedCellContentV1 (request, readCap) {
  const blob = request.cellBlob
  if (blob[0] !== 1 || !bytesEqual(blake2b256(blob), readCap.expectedCellBlobHash)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'recovered PUT Cell blob does not match its exact read capability')
  }
  const nonce = blob.subarray(1, 13)
  const ciphertext = blob.subarray(13, blob.byteLength - 16)
  const tag = blob.subarray(blob.byteLength - 16)
  const aad = concatBytes(
    asciiBytes('hiverelay.blind.cell.v1'), Uint8Array.of(1, request.sizeClass),
    request.storageSlot
  )
  let plaintext
  try {
    const decipher = createDecipheriv('aes-256-gcm',
      fixedBytes(readCap.cellKey, 32, 'readCap.cellKey'), nonce, { authTagLength: 16 })
    decipher.setAAD(Buffer.from(aad), { plaintextLength: ciphertext.byteLength })
    decipher.setAuthTag(Buffer.from(tag))
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch (cause) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'recovered PUT Cell cannot be opened by its exact read capability', cause)
  }
  const contentLength = plaintext.readUInt32BE(0)
  if (contentLength < 1 || contentLength > plaintext.byteLength - 4) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'recovered PUT Cell has a non-canonical content length')
  }
  return new Uint8Array(plaintext.subarray(4, 4 + contentLength))
}

function replicaProjection (value) {
  const projection = concatBytes(
    value.logicalHash,
    value.encodingCommitment,
    value.relayPublicKey,
    value.readCapability,
    value.cellBlobHash,
    Uint8Array.of(value.sizeClass),
    u32Bytes(value.allocationEpoch)
  )
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.replica-id.v1'),
    Uint8Array.of(1),
    u64Bytes(projection.byteLength),
    projection
  ))
}

function replicaFromPut (state, verified) {
  const receipt = verified.receipt
  const replica = Object.freeze({
    version: 1,
    logicalHash: state.publication.logicalHash.slice(),
    encodingCommitment: state.publication.encodingCommitment.slice(),
    relayPublicKey: state.readCap.relayPublicKey.slice(),
    readCapability: encodeReadCellCapV1(state.readCap),
    cellBlobHash: state.readCap.expectedCellBlobHash.slice(),
    sizeClass: state.readCap.sizeClass,
    allocationEpoch: state.request.allocationEpoch,
    leaseEpoch: receipt.leaseEpoch,
    createPublicKey: state.request.createPublicKey.slice(),
    renewPublicKey: state.request.renewPublicKey.slice(),
    dropPublicKey: state.request.dropPublicKey.slice(),
    allocationCommitment: state.allocationCommitment.slice(),
    relayReceipt: verified.receiptBytes.slice()
  })
  return Object.freeze({ replica, projection: replicaProjection(replica) })
}

function signingIntent (value, publication) {
  exact(value, [
    'authorSequence', 'previousAuthorRecordId', 'authorPublicKey',
    'publishedLeaseEpoch', 'publisherPublicKey'
  ], 'publication signing intent')
  decimalString(value.authorSequence, 'authorSequence')
  if (value.previousAuthorRecordId !== null) {
    hex32(value.previousAuthorRecordId, 'previousAuthorRecordId')
  }
  if ((value.authorSequence === '0') !== (value.previousAuthorRecordId === null)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'author sequence zero must have no previous AuthorBind record')
  }
  hex32(value.authorPublicKey, 'authorPublicKey')
  hex32(value.publisherPublicKey, 'publisherPublicKey')
  if (!Number.isSafeInteger(value.publishedLeaseEpoch) || value.publishedLeaseEpoch < 0 ||
      value.publishedLeaseEpoch > 0xffffffff) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', 'publishedLeaseEpoch is invalid')
  }
  return Object.freeze({ ...value, innerSha256: bytesHash(publication.innerBytes, 'innerBytes') })
}

function decimalString (value, field) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) > ((1n << 64n) - 1n)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', `${field} is not canonical u64 decimal`)
  }
  return value
}

function signingRequestFor (state) {
  const ordered = [...state.putStates.values()].map(row => Object.freeze({
    ...replicaFromPut(row.state, row.verified),
    put: row
  }))
    .sort((left, right) => compareBytes(left.projection, right.projection))
  const replicas = ordered.map(value => value.replica)
  const publication = state.publications.get(state.rows[0].relayId)
  const request = Object.freeze({
    schema: 'peerit-seq29-publication-signing-request-v1',
    version: 1,
    candidateCommit: PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
    releaseSequence: 29,
    bootstrapHash: state.bootstrapHash,
    releaseIdentityDigest: state.releaseIdentityDigest,
    authorSequence: state.signingIntent.authorSequence,
    previousAuthorRecordId: state.signingIntent.previousAuthorRecordId,
    authorPublicKey: state.signingIntent.authorPublicKey,
    innerCodec: publication.innerCodec,
    innerLength: String(publication.innerLength),
    innerBytesCanonicalHex: bytesToHex(publication.innerBytes),
    innerSha256: bytesHash(publication.innerBytes, 'innerBytes'),
    logicalHash: bytesToHex(publication.logicalHash),
    initialReplicas: Object.freeze(ordered.map(({ replica, put }) => Object.freeze({
      version: replica.version,
      logicalHash: bytesToHex(replica.logicalHash),
      encodingCommitment: bytesToHex(replica.encodingCommitment),
      relayId: put.prepared.relayId,
      relayPublicKey: bytesToHex(replica.relayPublicKey),
      storeId: put.prepared.storeId,
      durabilityContinuityHash: put.prepared.durabilityContinuityHash,
      readCapabilityCanonicalHex: bytesToHex(replica.readCapability),
      cellBlobHash: bytesToHex(replica.cellBlobHash),
      sizeClass: replica.sizeClass,
      allocationEpoch: replica.allocationEpoch,
      leaseEpoch: replica.leaseEpoch,
      createPublicKey: bytesToHex(replica.createPublicKey),
      renewPublicKey: bytesToHex(replica.renewPublicKey),
      dropPublicKey: bytesToHex(replica.dropPublicKey),
      allocationCommitment: bytesToHex(replica.allocationCommitment),
      relayReceiptCanonicalHex: bytesToHex(replica.relayReceipt),
      putClientNonce: bytesToHex(put.state.request.clientNonce),
      putRequestCanonicalHex: bytesToHex(put.prepared.requestBytes),
      putRequestCommitment: bytesToHex(put.state.requestCommitment),
      putResultCanonicalHex: bytesToHex(put.verified.resultBytes)
    }))),
    publishedLeaseEpoch: state.signingIntent.publishedLeaseEpoch,
    publisherPublicKey: state.signingIntent.publisherPublicKey
  })
  const validated = validatePeeritSeq29PublicationSigningRequestV1(request)
  return Object.freeze({ request: validated, requestDigest: hashObject(validated), replicas })
}

function boundedCanonicalHex (value, field, minimumBytes = 1, maximumBytes = 1048576) {
  if (typeof value !== 'string' || value.length % 2 !== 0 ||
      !/^[0-9a-f]+$/.test(value) || value.length < minimumBytes * 2 ||
      value.length > maximumBytes * 2) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      `${field} is not bounded canonical lowercase hexadecimal`)
  }
  return new Uint8Array(Buffer.from(value, 'hex'))
}

function verifyBlindReceiptSignatureV1 (receiptBytes, receipt, field) {
  if (receiptBytes.byteLength <= 64 || !(receipt.signature instanceof Uint8Array) ||
      receipt.signature.byteLength !== 64) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      `${field} is too short or omits its signature`)
  }
  const unsigned = receiptBytes.subarray(0, receiptBytes.byteLength - 64)
  const message = concatBytes(
    asciiBytes('hiverelay.blind.cell-receipt.v1'),
    u64Bytes(unsigned.byteLength),
    unsigned
  )
  if (!verifySignature(null, Buffer.from(message),
    rawEd25519PublicKey(receipt.relayBinding.relayPublicKey),
    Buffer.from(receipt.signature))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      `${field} signature is invalid`)
  }
}

// This is the offline handoff validator.  It deliberately accepts no
// callbacks: a signer can reconstruct both CellReplicaBindingV1 rows and the
// AuthorBind envelope solely from this exact durable request, while proving
// the two relay-signed receipts bind the exact canonical PUT requests.
export function validatePeeritSeq29PublicationSigningRequestV1 (input = {}) {
  exact(input, [
    'schema', 'version', 'candidateCommit', 'releaseSequence', 'bootstrapHash',
    'releaseIdentityDigest', 'authorSequence', 'previousAuthorRecordId',
    'authorPublicKey', 'innerCodec', 'innerLength', 'innerBytesCanonicalHex',
    'innerSha256', 'logicalHash', 'initialReplicas', 'publishedLeaseEpoch',
    'publisherPublicKey'
  ], 'publication signing request')
  if (input.schema !== 'peerit-seq29-publication-signing-request-v1' ||
      input.version !== 1 ||
      input.candidateCommit !== PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1 ||
      input.releaseSequence !== 29 || !Array.isArray(input.initialReplicas) ||
      input.initialReplicas.length !== 2) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      'signing request does not name the exact Seq29 two-replica release')
  }
  hex32(input.bootstrapHash, 'bootstrapHash')
  hex32(input.releaseIdentityDigest, 'releaseIdentityDigest')
  decimalString(input.authorSequence, 'authorSequence')
  if (input.previousAuthorRecordId !== null) {
    hex32(input.previousAuthorRecordId, 'previousAuthorRecordId')
  }
  if ((input.authorSequence === '0') !== (input.previousAuthorRecordId === null)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      'signing request author chain floor is inconsistent')
  }
  hex32(input.authorPublicKey, 'authorPublicKey')
  hex32(input.publisherPublicKey, 'publisherPublicKey')
  hex32(input.innerSha256, 'innerSha256')
  hex32(input.logicalHash, 'logicalHash')
  decimalString(input.innerLength, 'innerLength')
  if (!Number.isSafeInteger(input.innerCodec) ||
      !Number.isSafeInteger(input.publishedLeaseEpoch) || input.publishedLeaseEpoch < 0 ||
      input.publishedLeaseEpoch > 0xffffffff) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      'signing request codec or published lease epoch is invalid')
  }
  const innerBytes = boundedCanonicalHex(
    input.innerBytesCanonicalHex, 'innerBytesCanonicalHex', 8, 1048519)
  if (String(innerBytes.byteLength) !== input.innerLength ||
      bytesHash(innerBytes, 'signing request innerBytes') !== input.innerSha256) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      'signing request inner bytes do not reproduce their length and SHA-256')
  }
  let logicalHash
  let requiredSizeClass
  try {
    logicalHash = hashPeeritInnerLogicalHashV1(input.innerCodec, innerBytes)
    requiredSizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(
      BigInt(innerBytes.byteLength))
  } catch (cause) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      'signing request inner bytes are not the exact intrinsic operation envelope', cause)
  }
  if (bytesToHex(logicalHash) !== input.logicalHash) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      'signing request logicalHash differs from its exact inner bytes')
  }
  const seenRelays = new Set()
  const seenCapabilities = new Set()
  for (const [index, row] of input.initialReplicas.entries()) {
    exact(row, [
      'version', 'logicalHash', 'encodingCommitment', 'relayId',
      'relayPublicKey', 'storeId', 'durabilityContinuityHash',
      'readCapabilityCanonicalHex', 'cellBlobHash', 'sizeClass',
      'allocationEpoch', 'leaseEpoch', 'createPublicKey', 'renewPublicKey',
      'dropPublicKey', 'allocationCommitment', 'relayReceiptCanonicalHex',
      'putClientNonce', 'putRequestCanonicalHex', 'putRequestCommitment',
      'putResultCanonicalHex'
    ], `initialReplicas[${index}]`)
    if (row.version !== 1 || typeof row.relayId !== 'string' || row.relayId.length < 1 ||
        row.sizeClass !== requiredSizeClass ||
        !Number.isSafeInteger(row.allocationEpoch) || row.allocationEpoch < 0 ||
        row.allocationEpoch > 0xffffffff || !Number.isSafeInteger(row.leaseEpoch) ||
        row.leaseEpoch < 0 || row.leaseEpoch > 0xffffffff ||
        row.logicalHash !== input.logicalHash) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
        `initialReplicas[${index}] has an invalid version, identity, epoch, logical hash, or minimum class`)
    }
    for (const field of [
      'relayPublicKey', 'storeId', 'durabilityContinuityHash', 'cellBlobHash',
      'createPublicKey', 'renewPublicKey', 'dropPublicKey', 'allocationCommitment',
      'putClientNonce', 'putRequestCommitment', 'encodingCommitment'
    ]) hex32(row[field], `initialReplicas[${index}].${field}`)
    let expectedEncodingCommitment
    try {
      expectedEncodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
        input.innerCodec, innerBytes, logicalHash, row.sizeClass)
    } catch (cause) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
        `initialReplicas[${index}] encoding commitment cannot be reproduced`, cause)
    }
    if (bytesToHex(expectedEncodingCommitment) !== row.encodingCommitment) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
        `initialReplicas[${index}] encodingCommitment differs from exact inner bytes`)
    }
    const capBytes = boundedCanonicalHex(row.readCapabilityCanonicalHex,
      `initialReplicas[${index}].readCapabilityCanonicalHex`, 99, 131)
    const requestBytes = boundedCanonicalHex(row.putRequestCanonicalHex,
      `initialReplicas[${index}].putRequestCanonicalHex`, 256, 1049000)
    const resultBytes = boundedCanonicalHex(row.putResultCanonicalHex,
      `initialReplicas[${index}].putResultCanonicalHex`, 65, 16384)
    const receiptBytes = boundedCanonicalHex(row.relayReceiptCanonicalHex,
      `initialReplicas[${index}].relayReceiptCanonicalHex`, 65, 16384)
    let cap
    let receipt
    try {
      cap = decodeBlindExternalProfileValueV1('ReadCellCapV1', capBytes)
      receipt = decodeBlindExternalProfileValueV1('BlindReceiptV1', receiptBytes)
    } catch (cause) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
        `initialReplicas[${index}] capability or receipt is not canonical`, cause)
    }
    const request = decodePutCellRequestV1(requestBytes)
    const allocationCommitment = cellAllocationCommitmentV1(cap.relayPublicKey, request)
    const requestCommitment = cellPutRequestCommitmentV1(
      allocationCommitment, request.clientNonce)
    const exactCellContent = openPreparedCellContentV1(request, cap)
    verifyBlindReceiptSignatureV1(receiptBytes, receipt,
      `initialReplicas[${index}].relayReceiptCanonicalHex`)
    if (!bytesEqual(resultBytes, receiptBytes) ||
        !bytesEqual(encodePutCellRequestV1(request), requestBytes) ||
        bytesToHex(cap.relayPublicKey) !== row.relayPublicKey ||
        bytesToHex(cap.expectedCellBlobHash) !== row.cellBlobHash ||
        cap.sizeClass !== row.sizeClass ||
        !bytesEqual(cap.storageSlot, request.storageSlot) ||
        !bytesEqual(cap.expectedCellBlobHash, request.declaredBlobHash) ||
        !bytesEqual(exactCellContent, innerBytes) ||
        bytesToHex(request.clientNonce) !== row.putClientNonce ||
        bytesToHex(requestCommitment) !== row.putRequestCommitment ||
        bytesToHex(allocationCommitment) !== row.allocationCommitment ||
        bytesToHex(request.createPublicKey) !== row.createPublicKey ||
        bytesToHex(request.renewPublicKey) !== row.renewPublicKey ||
        bytesToHex(request.dropPublicKey) !== row.dropPublicKey ||
        request.sizeClass !== row.sizeClass || request.allocationEpoch !== row.allocationEpoch ||
        !bytesEqual(receipt.relayBinding.relayPublicKey, cap.relayPublicKey) ||
        bytesToHex(receipt.relayBinding.storeId) !== row.storeId ||
        bytesToHex(receipt.relayBinding.durabilityContinuityHash) !==
          row.durabilityContinuityHash ||
        !bytesEqual(receipt.requestNonce, request.clientNonce) ||
        !bytesEqual(receipt.requestCommitment, requestCommitment) ||
        !bytesEqual(receipt.allocationCommitment, allocationCommitment) ||
        !bytesEqual(receipt.cellBlobHash, request.declaredBlobHash) ||
        receipt.sizeClass !== row.sizeClass || receipt.allocationEpoch !== row.allocationEpoch ||
        receipt.leaseEpoch !== row.leaseEpoch || receipt.leaseClass !== 4 ||
        receipt.stateRevision !== 0n || receipt.result !== 1) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
        `initialReplicas[${index}] does not bind one exact canonical authenticated PUT`)
    }
    seenRelays.add(row.relayPublicKey)
    seenCapabilities.add(row.readCapabilityCanonicalHex)
  }
  if (seenRelays.size !== 2 || seenCapabilities.size !== 2) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID',
      'signing request requires two distinct physical relay capabilities')
  }
  return Object.freeze(structuredClone(input))
}

// Focused-test seam for the pre-gate, non-authority portion of phase one. It
// proves invalid intrinsic publications fail before a durable slot can be
// consumed. It cannot construct, brand, or execute a production authority.
export function validatePeeritSeq29PublicationInputsBeforeAttemptV1 (input = {}) {
  exact(input, ['rows', 'publications'], 'pre-attempt publication validation input')
  if (!Array.isArray(input.rows) || input.rows.length !== 2) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'pre-attempt validation requires the exact two authenticated rows')
  }
  const publicationInput = input.publications instanceof Map
    ? input.publications
    : new Map(Object.entries(input.publications || {}))
  if (publicationInput.size !== 2 ||
      input.rows.some(row => !publicationInput.has(row.relayId))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'pre-attempt publications must cover exactly the two rows')
  }
  const publications = new Map(input.rows.map(row => [
    row.relayId, publicationForRow(publicationInput.get(row.relayId), row)
  ]))
  const first = publications.get(input.rows[0].relayId)
  const second = publications.get(input.rows[1].relayId)
  if (!bytesEqual(first.innerBytes, second.innerBytes) ||
      !bytesEqual(first.logicalHash, second.logicalHash) ||
      !bytesEqual(first.encodingCommitment, second.encodingCommitment) ||
      first.innerCodec !== second.innerCodec || first.sizeClass !== second.sizeClass) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'both publications must carry one exact intrinsic operation batch')
  }
  return Object.freeze({
    publications,
    publicationDigest: hashObject(input.rows.map(row => ({
      relayId: row.relayId,
      innerSha256: bytesHash(publications.get(row.relayId).innerBytes, 'innerBytes'),
      logicalHash: bytesToHex(publications.get(row.relayId).logicalHash),
      encodingCommitment: bytesToHex(publications.get(row.relayId).encodingCommitment),
      sizeClass: publications.get(row.relayId).sizeClass
    })))
  })
}

async function authenticateProductionInput (input) {
  const assembly = getVerifiedPeeritBrowserRuntimeAssembly(input.runtimeAuthority)
  if (input.runtimeAppBinding !== assembly || assembly.control == null ||
      assembly.validatorInstantiationAuthorized !== true ||
      typeof assembly.profileValidator?.validate !== 'function') {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'the exact module-authenticated browser runtime/app binding is required')
  }
  const control = assembly.control
  const wrapper = validatePeeritLimitedPublicInboxSignedWrapperV1(input.signedBootstrap)
  const bootstrapHash = hashPeeritLimitedPublicInboxSignedWrapperV1(wrapper.canonicalBytes)
  if (input.signedBootstrapHash !== bootstrapHash) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'signed bootstrap hash does not match the verified wrapper')
  }
  const signedWrapper = Object.freeze({ payload: wrapper.payload, signature: wrapper.signature })
  const bootstrapAuthority = await verifyPeeritLimitedPublicInboxBootstrapV1({
    wrapper: signedWrapper,
    control,
    referenceUnixMillis: input.referenceUnixMillis
  })
  const endpointSets = verifyPeeritSeq29PublicInboxRelayEndpointsV1({
    authority: bootstrapAuthority,
    control,
    relayEndpoints: input.relayEndpoints
  })
  const rows = Object.freeze(endpointSets.map(productionRow))
  bindingRows(signedWrapper)
  const publications = validatePeeritSeq29PublicationInputsBeforeAttemptV1({
    rows,
    publications: input.publications
  }).publications
  const first = publications.get(rows[0].relayId)
  const intent = signingIntent(input.signingIntent, first)
  await decodePeeritInnerOperationBatchV1(first.innerCodec, first.innerBytes, {
    expectedAuthorPublicKey: intent.authorPublicKey
  })
  const putAdmissions = input.putAdmissionByRelayId instanceof Map
    ? input.putAdmissionByRelayId
    : new Map(Object.entries(input.putAdmissionByRelayId || {}))
  if (putAdmissions.size !== 2 || rows.some(row => !putAdmissions.has(row.relayId))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'putAdmissionByRelayId must cover exactly the two authenticated relay IDs')
  }
  const runtime = control.createBrowserCryptoRuntime()
  return Object.freeze({
    assembly,
    control,
    bootstrapAuthority,
    endpointSets,
    rows,
    publications,
    signingIntent: intent,
    putAdmissions,
    runtime,
    client: new control.BlindDirectHttpClient({ runtime }),
    bootstrapHash
  })
}

function phaseInputDigest (state) {
  return hashObject({
    schema: 'peerit-seq29-publication-phase-input-v1',
    bootstrapHash: state.bootstrapHash,
    rows: state.rows,
    publications: state.rows.map(row => {
      const value = state.publications.get(row.relayId)
      return {
        relayId: row.relayId,
        innerCodec: value.innerCodec,
        innerSha256: bytesHash(value.innerBytes, 'innerBytes'),
        logicalHash: bytesToHex(value.logicalHash),
        encodingCommitment: bytesToHex(value.encodingCommitment),
        sizeClass: value.sizeClass
      }
    }),
    signingIntent: state.signingIntent
  })
}

function publicPreparedPut (row, created) {
  return Object.freeze({
    relayId: row.relayId,
    relayPublicKey: row.relayPublicKey,
    storeId: row.storeId,
    durabilityContinuityHash: row.durabilityContinuityHash,
    physicalTopic: row.physicalTopic,
    family: 'CELL',
    operation: 'PUT',
    requestBytes: created.requestBytes.slice(),
    requestCommitment: bytesToHex(created.requestCommitment),
    evidenceRef: `authenticated-cell-put:${row.relayId}`
  })
}

function internalPreparedPut (row, created, endpointSet, publication) {
  const request = structuredClone(created.request)
  const readCap = structuredClone(created.readCap)
  if (request.version !== 1 || readCap.version !== 1 ||
      request.sizeClass !== publication.sizeClass ||
      readCap.sizeClass !== publication.sizeClass ||
      !bytesEqual(fixedBytes(request.storageSlot, 32, 'PUT request storageSlot'),
        fixedBytes(readCap.storageSlot, 32, 'PUT readCap storageSlot')) ||
      !bytesEqual(fixedBytes(request.declaredBlobHash, 32, 'PUT declaredBlobHash'),
        fixedBytes(readCap.expectedCellBlobHash, 32, 'PUT expectedCellBlobHash')) ||
      !bytesEqual(fixedBytes(readCap.relayPublicKey, 32, 'PUT readCap relayPublicKey'),
        endpointSet.binding.relayPublicKey)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      `${row.relayId} generated PUT does not bind its exact read capability and blob`)
  }
  return Object.freeze({
    kind: 'CELL.PUT',
    relayId: row.relayId,
    endpoint: endpointSet.putEndpoint,
    request,
    requestCommitment: created.requestCommitment.slice(),
    wire: structuredClone(created.wire),
    readCap,
    allocationCommitment: created.allocationCommitment.slice(),
    declaredBlobHash: request.declaredBlobHash.slice(),
    storageSlot: request.storageSlot.slice(),
    publication
  })
}

function assertPutReceiptCorrelation (state, row, internal, receipt) {
  const endpointSet = state.endpointSets.find(value => value.relayId === row.relayId)
  if (!receipt || receipt.version !== 1 || receipt.result !== 1 ||
      receipt.stateRevision !== 0n || receipt.leaseClass !== 4 ||
      !bytesEqual(receipt.requestCommitment, internal.requestCommitment) ||
      !bytesEqual(receipt.requestNonce, internal.request.clientNonce) ||
      !bytesEqual(receipt.relayBinding.relayPublicKey, endpointSet.binding.relayPublicKey) ||
      !bytesEqual(receipt.relayBinding.storeId, endpointSet.binding.storeId) ||
      !bytesEqual(receipt.relayBinding.durabilityContinuityHash,
        endpointSet.binding.durabilityContinuityHash) ||
      !bytesEqual(receipt.slotCommitment, blake2b256(internal.request.storageSlot)) ||
      !bytesEqual(receipt.cellBlobHash, internal.declaredBlobHash) ||
      !bytesEqual(receipt.allocationCommitment, internal.allocationCommitment) ||
      receipt.allocationEpoch !== internal.request.allocationEpoch ||
      receipt.sizeClass !== internal.request.sizeClass) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_RESULT_INVALID',
      `${row.relayId} PUT receipt differs from its exact request and authenticated relay`)
  }
  return receipt
}

function validateRecoveredPreparedPut (state, row, prepared, internal) {
  const endpointSet = state.endpointSets.find(value => value.relayId === row.relayId)
  const requestBytes = fixedBytes(prepared.requestBytes,
    prepared.requestBytes?.byteLength, 'recovered PUT requestBytes')
  const decoded = decodePutCellRequestV1(requestBytes)
  const request = internal.request
  exact(request, [
    'version', 'storageSlot', 'allocationEpoch', 'sizeClass', 'leaseClass',
    'clientNonce', 'createPublicKey', 'renewPublicKey', 'dropPublicKey',
    'declaredBlobHash', 'createSignature', 'admission', 'cellBlob'
  ], `${row.relayId} recovered PutCellV1`)
  exact(request.admission, ['profileId', 'schemeId', 'parameterHash', 'token'],
    `${row.relayId} recovered PutCellV1 admission`)
  exact(internal.readCap, [
    'version', 'relayPublicKey', 'storageSlot', 'cellKey', 'sizeClass',
    'expectedCellBlobHash'
  ], `${row.relayId} recovered ReadCellCapV1`)
  exact(internal.wire, [
    'familyId', 'operationId', 'expectedResultBodyBytes'
  ], `${row.relayId} recovered PUT wire`)
  const canonicalSavedRequest = encodePutCellRequestV1(request)
  const canonicalDecodedRequest = encodePutCellRequestV1(decoded)
  const allocationCommitment = cellAllocationCommitmentV1(
    endpointSet.binding.relayPublicKey, decoded)
  const requestCommitment = cellPutRequestCommitmentV1(
    allocationCommitment, decoded.clientNonce)
  const expectedStorageSlot = blake2b256(concatBytes(
    asciiBytes('hiverelay.blind.slot.v1'), u32Bytes(decoded.allocationEpoch),
    decoded.createPublicKey
  ))
  const readCapBytes = encodeReadCellCapV1(internal.readCap)
  let decodedReadCap
  try {
    decodedReadCap = state.control.decodeBlindExternalProfileValueV1(
      'ReadCellCapV1', readCapBytes)
  } catch (cause) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      `${row.relayId} recovered read capability is not canonical`, cause)
  }
  const openedContent = openPreparedCellContentV1(decoded, decodedReadCap)
  if (!bytesEqual(requestBytes, canonicalDecodedRequest) ||
      !bytesEqual(requestBytes, canonicalSavedRequest) ||
      internal.wire?.familyId !== 2 || internal.wire?.operationId !== 1 ||
      internal.wire.expectedResultBodyBytes !== 16384 ||
      prepared.requestCommitment !== bytesToHex(requestCommitment) ||
      !bytesEqual(internal.requestCommitment, requestCommitment) ||
      !bytesEqual(internal.allocationCommitment, allocationCommitment) ||
      !bytesEqual(decoded.storageSlot, expectedStorageSlot) ||
      !bytesEqual(decoded.storageSlot, decodedReadCap.storageSlot) ||
      !bytesEqual(decoded.declaredBlobHash, decodedReadCap.expectedCellBlobHash) ||
      !bytesEqual(decodedReadCap.relayPublicKey, endpointSet.binding.relayPublicKey) ||
      decoded.sizeClass !== decodedReadCap.sizeClass ||
      decoded.sizeClass !== internal.publication.sizeClass ||
      decoded.allocationEpoch !== row.allocationEpoch ||
      !bytesEqual(openedContent, internal.publication.innerBytes) ||
      !verifySignature(null, Buffer.from(allocationCommitment),
        rawEd25519PublicKey(decoded.createPublicKey), Buffer.from(decoded.createSignature))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      `${row.relayId} recovered PUT is not the exact canonical capability-bound publication`)
  }
  assertDecodedWire(Object.freeze({
    familyId: internal.wire.familyId,
    operationId: internal.wire.operationId,
    requestCommitment: prepared.requestCommitment,
    relayPublicKey: prepared.relayPublicKey,
    physicalTopic: prepared.physicalTopic
  }), prepared)
  return Object.freeze({ decoded, requestCommitment, allocationCommitment })
}

function clearCellManagementCapability (writeCap) {
  for (const field of ['createPrivateKey', 'renewPrivateKey', 'dropPrivateKey']) {
    try { writeCap?.[field]?.fill(0) } catch {}
  }
}

function phaseRecovery (state, phaseName) {
  return Object.freeze({
    schema: 'peerit-seq29-bounded-publication-recovery-v1',
    phase: phaseName,
    attemptId: state.attemptId,
    releaseIdentityDigest: state.releaseIdentityDigest,
    inputDigest: state.inputDigest,
    signingRequest: state.signingRequest || null,
    signingRequestDigest: state.signingRequestDigest || null,
    puts: Object.freeze(state.rows.map(row => {
      const value = state.putStates.get(row.relayId)
      return Object.freeze({
        relayId: row.relayId,
        prepared: value.prepared,
        internal: Object.freeze({
          request: value.state.request,
          requestCommitment: value.state.requestCommitment,
          wire: value.state.wire,
          readCap: value.state.readCap,
          allocationCommitment: value.state.allocationCommitment
        }),
        resultBytes: value.verified?.resultBytes || null,
        receiptBytes: value.verified?.receiptBytes || null
      })
    }))
  })
}

async function persistPhaseRecovery (journal, state, phaseName) {
  const recovery = phaseRecovery(state, phaseName)
  const request = Object.freeze({
    attemptId: state.attemptId,
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest: state.releaseIdentityDigest,
    recovery,
    recoveryDigest: hashObject(recovery)
  })
  return durableReceipt(await journal.persistRecovery(request),
    'RECOVERY_DURABLE_NO_RESEND', [
      'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
      'releaseIdentityDigest', 'recoveryDigest', 'requestDigest', 'commitment'
    ], `publication ${phaseName} recovery`, {
      attemptId: state.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest: state.releaseIdentityDigest,
      recoveryDigest: request.recoveryDigest,
      requestDigest: hashObject(request)
    })
}

async function restorePhaseRecovery (recovery, state) {
  exact(recovery, [
    'schema', 'phase', 'attemptId', 'releaseIdentityDigest', 'inputDigest',
    'signingRequest', 'signingRequestDigest', 'puts'
  ], 'publication recovery')
  if (recovery.schema !== 'peerit-seq29-bounded-publication-recovery-v1' ||
      !['PUTS_PREPARED', 'PUTS_VERIFIED_AWAITING_SIGNED_ANNOUNCEMENT',
        'SIGNED_ANNOUNCEMENT_ACCEPTED', 'APPENDS_IN_PROGRESS'].includes(recovery.phase) ||
      recovery.attemptId !== state.attemptId ||
      recovery.releaseIdentityDigest !== state.releaseIdentityDigest ||
      recovery.inputDigest !== state.inputDigest || !Array.isArray(recovery.puts) ||
      recovery.puts.length !== 2 ||
      ((recovery.signingRequest == null) !== (recovery.signingRequestDigest == null))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'durable publication recovery differs from the exact release input')
  }
  const endpointById = new Map(state.endpointSets.map(value => [value.relayId, value]))
  for (const row of state.rows) {
    const saved = recovery.puts.find(value => value.relayId === row.relayId)
    exact(saved, ['relayId', 'prepared', 'internal', 'resultBytes', 'receiptBytes'],
      `${row.relayId} recovered PUT`)
    exact(saved.internal, [
      'request', 'requestCommitment', 'wire', 'readCap', 'allocationCommitment'
    ], `${row.relayId} recovered PUT internals`)
    const prepared = Object.freeze(structuredClone(saved.prepared))
    assertPrepared(prepared, row, 'CELL', 'PUT')
    const internal = Object.freeze({
      kind: 'CELL.PUT',
      relayId: row.relayId,
      endpoint: endpointById.get(row.relayId).putEndpoint,
      request: structuredClone(saved.internal.request),
      requestCommitment: saved.internal.requestCommitment.slice(),
      wire: structuredClone(saved.internal.wire),
      readCap: structuredClone(saved.internal.readCap),
      allocationCommitment: saved.internal.allocationCommitment.slice(),
      declaredBlobHash: saved.internal.request.declaredBlobHash.slice(),
      storageSlot: saved.internal.request.storageSlot.slice(),
      publication: state.publications.get(row.relayId)
    })
    validateRecoveredPreparedPut(state, row, prepared, internal)
    if ((saved.resultBytes == null) !== (saved.receiptBytes == null)) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
        `${row.relayId} recovered result and receipt must be present together`)
    }
    let verified = null
    if (saved.resultBytes != null) {
      const resultBytes = fixedBytes(saved.resultBytes,
        saved.resultBytes?.byteLength, `${row.relayId} recovered resultBytes`).slice()
      const receiptBytes = fixedBytes(saved.receiptBytes,
        saved.receiptBytes?.byteLength, `${row.relayId} recovered receiptBytes`).slice()
      let authenticated
      try {
        authenticated = await state.control.verifyOperationResult({
          endpoint: internal.endpoint,
          request: internal.request,
          requestCommitment: internal.requestCommitment,
          resultBytes
        })
      } catch (cause) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
          `${row.relayId} recovered PUT result is not authenticated`, cause)
      }
      const authenticatedReceiptBytes = authenticated.snapshotBytes()
      if (!(authenticatedReceiptBytes instanceof Uint8Array) ||
          !bytesEqual(authenticatedReceiptBytes, receiptBytes) ||
          !bytesEqual(resultBytes, receiptBytes)) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
          `${row.relayId} recovered result snapshot differs from its stored receipt bytes`)
      }
      const receipt = state.control.decodeBlindExternalProfileValueV1(
        'BlindReceiptV1', receiptBytes)
      assertPutReceiptCorrelation(state, row, internal, receipt)
      verified = Object.freeze({ kind: 'CELL.PUT', resultBytes, receiptBytes, receipt })
    }
    PRODUCTION_PREPARED.set(prepared, internal)
    if (verified) PRODUCTION_VERIFIED.set(prepared, verified)
    state.putStates.set(row.relayId, Object.freeze({ prepared, state: internal, verified }))
  }
  if (recovery.signingRequest != null) {
    if ([...state.putStates.values()].some(value => value.verified == null)) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
        'durable signing request exists before both exact PUT results are verified')
    }
    const reproduced = signingRequestFor(state)
    if (recovery.signingRequestDigest !== reproduced.requestDigest ||
        hashObject(recovery.signingRequest) !== reproduced.requestDigest) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
        'durable signing request differs from the authenticated recovered PUT evidence')
    }
    state.signingRequest = reproduced.request
    state.signingRequestDigest = reproduced.requestDigest
    state.replicas = reproduced.replicas
  } else if (recovery.phase === 'PUTS_VERIFIED_AWAITING_SIGNED_ANNOUNCEMENT') {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'awaiting-signature recovery omitted its exact durable signing request')
  }
  return recovery.phase
}

async function dispatchPhaseOnePut (state, row, journal, operationIndex) {
  const value = state.putStates.get(row.relayId)
  const prepared = value.prepared
  const internal = value.state
  const operationKey = `CELL.PUT:${row.relayId}`
  const requestSha256 = bytesHash(prepared.requestBytes, 'PUT requestBytes')
  const claimRequest = Object.freeze({
    attemptId: state.attemptId,
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest: state.releaseIdentityDigest,
    operationIndex,
    operationKey,
    requestSha256,
    requestCommitment: prepared.requestCommitment
  })
  durableReceipt(await journal.claimOperation(claimRequest), 'DISPATCH_CLAIMED', [
    'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
    'releaseIdentityDigest', 'operationKey', 'requestDigest', 'commitment'
  ], `claim ${operationKey}`, {
    attemptId: state.attemptId,
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest: state.releaseIdentityDigest,
    operationKey,
    requestDigest: hashObject(claimRequest)
  })
  let response
  try {
    response = await state.client.request({
      endpoint: internal.endpoint,
      ...internal.wire,
      body: prepared.requestBytes
    })
  } catch (cause) {
    const outcome = Object.freeze({
      attemptId: state.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest: state.releaseIdentityDigest,
      operationKey,
      requestSha256,
      state: 'AMBIGUOUS_TERMINAL'
    })
    durableReceipt(await journal.recordOutcome(outcome), 'AMBIGUOUS_TERMINAL', [
      'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
      'releaseIdentityDigest', 'operationKey', 'requestDigest', 'commitment'
    ], `outcome ${operationKey}`, {
      attemptId: state.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest: state.releaseIdentityDigest,
      operationKey,
      requestDigest: hashObject(outcome)
    })
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_TRANSPORT_AMBIGUOUS',
      `${operationKey} has an ambiguous terminal outcome`, cause)
  }
  if (!response || response.ok !== true || !(response.body instanceof Uint8Array)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_WRITE_REJECTED', `${operationKey} was rejected`)
  }
  const authenticated = await state.control.verifyOperationResult({
    endpoint: internal.endpoint,
    request: internal.request,
    requestCommitment: internal.requestCommitment,
    resultBytes: response.body
  })
  const snapshotBytes = authenticated.snapshotBytes()
  const receiptBytes = fixedBytes(snapshotBytes,
    snapshotBytes?.byteLength, 'PUT receipt').slice()
  if (!bytesEqual(receiptBytes, response.body)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_RESULT_INVALID',
      `${row.relayId} authenticated PUT result bytes differ from its exact receipt snapshot`)
  }
  const receipt = state.control.decodeBlindExternalProfileValueV1('BlindReceiptV1', receiptBytes)
  assertPutReceiptCorrelation(state, row, internal, receipt)
  const verified = Object.freeze({
    kind: 'CELL.PUT',
    resultBytes: response.body.slice(),
    receiptBytes,
    receipt
  })
  PRODUCTION_VERIFIED.set(prepared, verified)
  state.putStates.set(row.relayId, Object.freeze({ prepared, state: internal, verified }))
  const outcome = Object.freeze({
    attemptId: state.attemptId,
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest: state.releaseIdentityDigest,
    operationKey,
    requestSha256,
    resultSha256: bytesHash(response.body, 'PUT result'),
    state: 'VERIFIED_TERMINAL'
  })
  durableReceipt(await journal.recordOutcome(outcome), 'VERIFIED_TERMINAL', [
    'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
    'releaseIdentityDigest', 'operationKey', 'requestDigest', 'commitment'
  ], `outcome ${operationKey}`, {
    attemptId: state.attemptId,
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest: state.releaseIdentityDigest,
    operationKey,
    requestDigest: hashObject(outcome)
  })
}

export async function preparePeeritSeq29BoundedPublicationV1 (input = {}) {
  exact(input, [
    'runtimeAuthority', 'runtimeAppBinding', 'signedBootstrap', 'signedBootstrapHash',
    'referenceUnixMillis', 'relayEndpoints', 'publications', 'putAdmissionByRelayId',
    'signingIntent', 'attemptJournal'
  ], 'production publication phase-one input')
  for (const forbidden of ['control', 'send', 'transport', 'prepare', 'verify', 'signer']) {
    if (forbidden in input) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
        `production publication phase one forbids caller ${forbidden}`)
    }
  }
  rejectCallables(input.relayEndpoints, 'relayEndpoints')
  rejectCallables(input.publications, 'publications')
  rejectCallables(input.putAdmissionByRelayId, 'putAdmissionByRelayId')
  const journal = methods(input.attemptJournal, [
    'beginAttempt', 'claimOperation', 'recordOutcome', 'persistRecovery', 'finishAttempt'
  ], 'durable publication journal')
  const authenticated = await authenticateProductionInput(input)
  const release = publicationRelease(authenticated.bootstrapHash, authenticated.rows)
  const begunValue = await journal.beginAttempt(release.beginRequest)
  const recoveryAvailable = begunValue?.state === 'RECOVERY_AVAILABLE_NO_RESEND'
  const begun = durableReceipt(begunValue,
    recoveryAvailable ? 'RECOVERY_AVAILABLE_NO_RESEND' : 'CONSUMED_NO_MUTATIONS',
    recoveryAvailable
      ? [
          'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
          'releaseIdentityDigest', 'requestDigest', 'recovery', 'commitment'
        ]
      : [
          'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
          'releaseIdentityDigest', 'requestDigest', 'commitment'
        ], recoveryAvailable ? 'publication recovery begin' : 'publication begin', {
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest: release.releaseIdentityDigest,
      requestDigest: hashObject(release.beginRequest)
    })
  const state = {
    ...authenticated,
    referenceUnixMillis: input.referenceUnixMillis,
    releaseIdentityDigest: release.releaseIdentityDigest,
    attemptId: begun.attemptId,
    journal,
    putStates: new Map()
  }
  state.inputDigest = phaseInputDigest(state)
  if (recoveryAvailable) {
    await restorePhaseRecovery(begun.recovery, state)
  } else {
    const endpointById = new Map(state.endpointSets.map(value => [value.relayId, value]))
    for (const row of state.rows) {
      const publication = state.publications.get(row.relayId)
      let created
      try {
        created = await state.control.createCellReplica({
          runtime: state.runtime,
          relayPublicKey: endpointById.get(row.relayId).binding.relayPublicKey,
          allocationEpoch: row.allocationEpoch,
          sizeClass: publication.sizeClass,
          leaseClass: 4,
          structuredContent: publication.innerBytes,
          admission: state.putAdmissions.get(row.relayId)
        })
        const prepared = publicPreparedPut(row, created)
        const internal = internalPreparedPut(
          row, created, endpointById.get(row.relayId), publication)
        assertDecodedWire(Object.freeze({
          familyId: internal.wire.familyId,
          operationId: internal.wire.operationId,
          requestCommitment: prepared.requestCommitment,
          relayPublicKey: prepared.relayPublicKey,
          physicalTopic: prepared.physicalTopic
        }), prepared)
        PRODUCTION_PREPARED.set(prepared, internal)
        state.putStates.set(row.relayId, Object.freeze({ prepared, state: internal, verified: null }))
      } finally {
        clearCellManagementCapability(created?.writeCap)
      }
    }
    await persistPhaseRecovery(journal, state, 'PUTS_PREPARED')
  }
  for (let index = 0; index < state.rows.length; index++) {
    const row = state.rows[index]
    if (state.putStates.get(row.relayId).verified) continue
    await dispatchPhaseOnePut(state, row, journal, index)
    if (index !== state.rows.length - 1) {
      await persistPhaseRecovery(journal, state, 'PUTS_PREPARED')
    }
  }
  const signing = signingRequestFor(state)
  state.signingRequest = signing.request
  state.signingRequestDigest = signing.requestDigest
  state.replicas = signing.replicas
  await persistPhaseRecovery(journal, state,
    'PUTS_VERIFIED_AWAITING_SIGNED_ANNOUNCEMENT')
  const preparation = Object.freeze({
    schema: 'peerit-seq29-bounded-publication-preparation-v1',
    version: 1,
    status: 'AWAITING_SIGNED_ANNOUNCEMENT',
    candidateCommit: PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
    releaseSequence: 29,
    bootstrapHash: state.bootstrapHash,
    releaseIdentityDigest: state.releaseIdentityDigest,
    attemptId: state.attemptId,
    signingRequest: signing.request,
    signingRequestDigest: signing.requestDigest,
    mutationLedger: Object.freeze({ cellPut: 2, inboxAppend: 0 })
  })
  PUBLICATION_PREPARATIONS.set(preparation, Object.freeze({
    ...state,
    signingRequest: signing.request,
    signingRequestDigest: signing.requestDigest,
    replicas: signing.replicas
  }))
  return preparation
}

function replicaSigningRow (replica) {
  return Object.freeze({
    version: replica.version,
    logicalHash: bytesToHex(replica.logicalHash),
    encodingCommitment: bytesToHex(replica.encodingCommitment),
    relayPublicKey: bytesToHex(replica.relayPublicKey),
    readCapabilityCanonicalHex: bytesToHex(replica.readCapability),
    cellBlobHash: bytesToHex(replica.cellBlobHash),
    sizeClass: replica.sizeClass,
    allocationEpoch: replica.allocationEpoch,
    leaseEpoch: replica.leaseEpoch,
    createPublicKey: bytesToHex(replica.createPublicKey),
    renewPublicKey: bytesToHex(replica.renewPublicKey),
    dropPublicKey: bytesToHex(replica.dropPublicKey),
    allocationCommitment: bytesToHex(replica.allocationCommitment),
    relayReceiptCanonicalHex: bytesToHex(replica.relayReceipt)
  })
}

function replicaBindingRowFromSigningRequest (row) {
  return Object.freeze({
    version: row.version,
    logicalHash: row.logicalHash,
    encodingCommitment: row.encodingCommitment,
    relayPublicKey: row.relayPublicKey,
    readCapabilityCanonicalHex: row.readCapabilityCanonicalHex,
    cellBlobHash: row.cellBlobHash,
    sizeClass: row.sizeClass,
    allocationEpoch: row.allocationEpoch,
    leaseEpoch: row.leaseEpoch,
    createPublicKey: row.createPublicKey,
    renewPublicKey: row.renewPublicKey,
    dropPublicKey: row.dropPublicKey,
    allocationCommitment: row.allocationCommitment,
    relayReceiptCanonicalHex: row.relayReceiptCanonicalHex
  })
}

export async function createPeeritSeq29BoundedPublicationAuthorityV1 (input = {}) {
  exact(input, [
    'preparation', 'signedAnnouncementBytes', 'appendAdmissionByRelayId', 'attemptJournal'
  ], 'production publication phase-two input')
  for (const forbidden of ['control', 'send', 'transport', 'prepare', 'verify', 'signer']) {
    if (forbidden in input) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
        `production publication phase two forbids caller ${forbidden}`)
    }
  }
  const state = PUBLICATION_PREPARATIONS.get(input.preparation)
  if (!state || CONSUMED_PREPARATIONS.has(input.preparation) ||
      input.attemptJournal !== state.journal) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'one-use module-created phase-one preparation and its exact journal are required')
  }
  const announcementBytes = fixedBytes(input.signedAnnouncementBytes,
    input.signedAnnouncementBytes?.byteLength, 'signed announcement bytes').slice()
  if (announcementBytes.byteLength < 1 || announcementBytes.byteLength > 12288) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'signed announcement bytes are outside the protocol bound')
  }
  rejectCallables(input.appendAdmissionByRelayId, 'appendAdmissionByRelayId')
  const appendAdmissions = input.appendAdmissionByRelayId instanceof Map
    ? input.appendAdmissionByRelayId
    : new Map(Object.entries(input.appendAdmissionByRelayId || {}))
  if (appendAdmissions.size !== 2 || state.rows.some(row => !appendAdmissions.has(row.relayId))) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'appendAdmissionByRelayId must cover exactly the two authenticated relay IDs')
  }
  let announcement
  let authorBind
  try {
    announcement = state.assembly.profileValidator.validate(
      'PeeritAnnouncementV1', announcementBytes).value
    authorBind = state.assembly.profileValidator.validate(
      'AuthorBindV1', announcement.manifestRecord).value
  } catch (cause) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNED_ANNOUNCEMENT_INVALID',
      'signed announcement or AuthorBind failed authenticated runtime validation', cause)
  }
  const intent = state.signingIntent
  const durableSigningRequest = validatePeeritSeq29PublicationSigningRequestV1(
    state.signingRequest)
  if (hashObject(durableSigningRequest) !== state.signingRequestDigest) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNED_ANNOUNCEMENT_INVALID',
      'durable signing request digest changed before phase two')
  }
  const expectedEvidenceRows = durableSigningRequest.initialReplicas
  const expectedRows = expectedEvidenceRows.map(replicaBindingRowFromSigningRequest)
  const actualRows = authorBind.initialReplicas.map(replicaSigningRow)
  const publication = state.publications.get(state.rows[0].relayId)
  const signedInnerBytes = Buffer.from(
    durableSigningRequest.innerBytesCanonicalHex, 'hex')
  if (signedInnerBytes.byteLength !== Number(durableSigningRequest.innerLength) ||
      bytesHash(signedInnerBytes, 'signing-request innerBytes') !==
        durableSigningRequest.innerSha256 ||
      !bytesEqual(signedInnerBytes, publication.innerBytes) ||
      bytesToHex(hashPeeritInnerLogicalHashV1(
        durableSigningRequest.innerCodec, signedInnerBytes)) !==
        durableSigningRequest.logicalHash ||
      bytesToHex(hashPeeritInnerCellEncodingCommitmentV1(
        durableSigningRequest.innerCodec,
        signedInnerBytes,
        publication.logicalHash,
        publication.sizeClass)) !== expectedRows[0].encodingCommitment ||
      expectedRows.some(row => row.version !== 1 ||
        row.logicalHash !== durableSigningRequest.logicalHash ||
        row.encodingCommitment !== expectedRows[0].encodingCommitment)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNED_ANNOUNCEMENT_INVALID',
      'durable signing request no longer reproduces its exact intrinsic envelope')
  }
  if (announcement.manifestTag !== 3 || announcement.manifestMode !== 1 ||
      announcement.manifestReadCaps.length !== 0 ||
      announcement.publishedLeaseEpoch !== intent.publishedLeaseEpoch ||
      bytesToHex(announcement.publisherPublicKey) !== intent.publisherPublicKey ||
      String(authorBind.authorSequence) !== intent.authorSequence ||
      (authorBind.previousAuthorRecordId == null
        ? null
        : bytesToHex(authorBind.previousAuthorRecordId)) !== intent.previousAuthorRecordId ||
      bytesToHex(authorBind.authorPublicKey) !== intent.authorPublicKey ||
      authorBind.innerCodec !== durableSigningRequest.innerCodec ||
      String(authorBind.innerLength) !== durableSigningRequest.innerLength ||
      bytesToHex(authorBind.logicalHash) !== durableSigningRequest.logicalHash ||
      hashObject(actualRows) !== hashObject(expectedRows)) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNED_ANNOUNCEMENT_INVALID',
      'signed announcement differs from the exact durable phase-one signing request')
  }
  const endpointById = new Map(state.endpointSets.map(value => [value.relayId, value]))
  const readbacks = new Map()
  const preparedPuts = new Map()
  for (const row of state.rows) {
    const saved = state.putStates.get(row.relayId)
    const signedReplica = authorBind.initialReplicas.find(replica =>
      bytesToHex(replica.relayPublicKey) === row.relayPublicKey)
    const evidenceRow = expectedEvidenceRows.find(value =>
      value.relayPublicKey === row.relayPublicKey)
    if (!signedReplica || !evidenceRow ||
        !bytesEqual(saved.verified.receiptBytes, signedReplica.relayReceipt) ||
        bytesToHex(saved.verified.resultBytes) !== evidenceRow.putResultCanonicalHex ||
        bytesToHex(saved.state.request.clientNonce) !== evidenceRow.putClientNonce ||
        bytesToHex(saved.prepared.requestBytes) !== evidenceRow.putRequestCanonicalHex ||
        bytesToHex(saved.state.requestCommitment) !== evidenceRow.putRequestCommitment) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_SIGNED_ANNOUNCEMENT_INVALID',
        `${row.relayId} signed replica differs from the exact authenticated phase-one PUT evidence`)
    }
    const endpointSet = endpointById.get(row.relayId)
    const readback = await verifyPeeritPublicInboxAnnouncementReadbackV1({
      authority: state.bootstrapAuthority,
      binding: endpointSet.binding,
      control: state.control,
      runtime: state.runtime,
      cellEndpoint: endpointSet.cellGetEndpoint,
      announcementBytes,
      httpClient: state.client,
      profileValidator: state.assembly.profileValidator,
      nowUnixMillis: state.referenceUnixMillis
    })
    await verifyPeeritSeq29CellPutReadbackEvidenceV1({
      authority: state.bootstrapAuthority,
      binding: endpointSet.binding,
      control: state.control,
      putEndpoint: endpointSet.putEndpoint,
      evidence: Object.freeze({
        request: saved.state.request,
        requestCommitment: saved.state.requestCommitment,
        resultBytes: saved.verified.resultBytes
      }),
      readback
    })
    validatePeeritSeq29PreparedPutReadbackBindingV1({
      request: saved.state.request,
      readCap: saved.state.readCap,
      publication: saved.state.publication,
      announcementBytes,
      verifiedAnnouncementBytes: announcementBytes,
      readback
    })
    readbacks.set(row.relayId, readback)
    preparedPuts.set(row.relayId, saved.prepared)
  }
  CONSUMED_PREPARATIONS.add(input.preparation)
  return createProductionPublicationAuthority(Object.freeze({
    ...state,
    announcementBytes,
    preparedPuts,
    readbacks
  }), announcementBytes, appendAdmissions)
}

function createProductionPublicationAuthority (phase, announcementBytes, appendAdmissions) {
  const {
    assembly, control, bootstrapAuthority, endpointSets, rows,
    runtime, client, bootstrapHash, referenceUnixMillis, preparedPuts, readbacks
  } = phase
  const endpointById = new Map(endpointSets.map(value => [value.relayId, value]))
  const authority = Object.freeze({
    candidateCommit: PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
    releaseSequence: 29,
    bootstrapHash,
    rows
  })
  const controlAdapter = Object.freeze({
    async prepareCellPut (row) {
      const prepared = preparedPuts.get(row.relayId)
      if (!prepared) fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', 'frozen PUT is missing')
      return prepared
    },
    async verifyCellPutReadback ({ row, prepared }) {
      const state = PRODUCTION_PREPARED.get(prepared)
      const putResult = PRODUCTION_VERIFIED.get(prepared)
      if (!state || state.kind !== 'CELL.PUT' || state.relayId !== row.relayId ||
          !putResult || putResult.kind !== 'CELL.PUT') {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', 'unbranded CELL.PUT readback request')
      }
      const endpointSet = endpointById.get(row.relayId)
      const readback = readbacks.get(row.relayId)
      if (!readback) fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', 'frozen readback is missing')
      await verifyPeeritSeq29CellPutReadbackEvidenceV1({
        authority: bootstrapAuthority,
        binding: endpointSet.binding,
        control,
        putEndpoint: endpointSet.putEndpoint,
        evidence: Object.freeze({
          request: state.request,
          requestCommitment: state.requestCommitment,
          resultBytes: putResult.resultBytes
        }),
        readback
      })
      const binding = validatePeeritSeq29PreparedPutReadbackBindingV1({
        request: state.request,
        readCap: state.readCap,
        publication: state.publication,
        announcementBytes,
        verifiedAnnouncementBytes: announcementBytes,
        readback
      })
      return Object.freeze({
        relayId: row.relayId,
        cellGetVerified: true,
        authorBindVerified: true,
        announcementBytes: announcementBytes.slice(),
        evidenceRef: `authenticated-put-readback:${row.relayId}:${binding.innerSha256}`
      })
    },
    async prepareInboxAppend ({ row, announcementBytes }) {
      const endpointSet = endpointById.get(row.relayId)
      const created = await preparePeeritPublicInboxAnnouncementV1({
        authority: bootstrapAuthority,
        binding: endpointSet.binding,
        control,
        runtime,
        announcementBytes,
        admission: appendAdmissions.get(row.relayId)
      })
      const prepared = Object.freeze({
        relayId: row.relayId,
        relayPublicKey: row.relayPublicKey,
        storeId: row.storeId,
        durabilityContinuityHash: row.durabilityContinuityHash,
        physicalTopic: row.physicalTopic,
        family: 'INBOX',
        operation: 'APPEND',
        requestBytes: created.requestBytes,
        requestCommitment: bytesToHex(created.requestCommitment),
        evidenceRef: `authenticated-inbox-append:${row.relayId}`
      })
      PRODUCTION_PREPARED.set(prepared, Object.freeze({
        kind: 'INBOX.APPEND',
        relayId: row.relayId,
        endpoint: endpointSet.appendEndpoint,
        request: created.request,
        requestCommitment: created.requestCommitment,
        wire: created.wire,
        frame: created.frame
      }))
      return prepared
    },
    async verifyInboxAppend ({ row, prepared }) {
      const state = PRODUCTION_PREPARED.get(prepared)
      const result = PRODUCTION_VERIFIED.get(prepared)
      if (!state || state.kind !== 'INBOX.APPEND' || !result ||
          result.kind !== 'INBOX.APPEND') {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID', 'unbranded INBOX.APPEND result')
      }
      const ack = decodePeeritInboxAppendAckSnapshotV1(result.verified.snapshotBytes())
      if (!bytesEqual(ack.frameHash, blake2b256(state.frame))) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_RESULT_INVALID',
          `${row.relayId} APPEND result does not bind the sealed frame`)
      }
      const evidence = Object.freeze({
        relayId: row.relayId,
        acknowledged: true,
        evidenceRef: `authenticated-append:${row.relayId}:${ack.appendRevision}`
      })
      PRODUCTION_APPEND_EVIDENCE.set(evidence, Object.freeze({ prepared, state, ack }))
      return evidence
    },
    async freshReadCellGet ({ row, put, append }) {
      const endpointSet = endpointById.get(row.relayId)
      const putState = PRODUCTION_PREPARED.get(put)
      const appendEvidence = PRODUCTION_APPEND_EVIDENCE.get(append)
      if (!putState || putState.kind !== 'CELL.PUT' || putState.relayId !== row.relayId ||
          !appendEvidence || appendEvidence.state.relayId !== row.relayId) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_FRESH_PROOF_INVALID',
          `${row.relayId} fresh proof lacks the exact branded PUT and APPEND`)
      }
      let cursor = null
      let exactEntry = null
      for (let page = 0; page < 64; page++) {
        const read = await control.createReadInboxRequest({
          runtime,
          readCap: endpointSet.binding.readCap,
          cursor,
          limit: 64
        })
        const response = await client.request({
          endpoint: endpointSet.readEndpoint,
          ...read.wire,
          body: read.requestBytes
        })
        if (!response || response.ok !== true) {
          fail('PEERIT_SEQ29_PUBLICATION_DRILL_FRESH_PROOF_INVALID',
            `${row.relayId} fresh INBOX.READ was rejected`)
        }
        const verified = await control.verifyOperationResult({
          endpoint: endpointSet.readEndpoint,
          request: read.request,
          requestCommitment: read.requestCommitment,
          resultBytes: response.body
        })
        const decoded = decodePeeritInboxReadResultSnapshotV1(verified.snapshotBytes())
        for (const entry of decoded.entries) {
          if (entry.appendRevision === appendEvidence.ack.appendRevision &&
              bytesEqual(entry.frameHash, appendEvidence.ack.frameHash)) {
            if (exactEntry) {
              fail('PEERIT_SEQ29_PUBLICATION_DRILL_FRESH_PROOF_INVALID',
                `${row.relayId} fresh READ duplicated the exact append revision`)
            }
            exactEntry = entry
          }
        }
        if (exactEntry || decoded.nextCursor == null) break
        cursor = decoded.nextCursor
      }
      if (!exactEntry || exactEntry.frameClass !== 1 ||
          !bytesEqual(exactEntry.frame, appendEvidence.state.frame) ||
          !bytesEqual(blake2b256(exactEntry.frame), appendEvidence.ack.frameHash)) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_FRESH_PROOF_INVALID',
          `${row.relayId} fresh READ did not recover the exact acknowledged frame`)
      }
      const announcementBytes = await openPeeritInboxAnnouncementFrameV1({
        authority: bootstrapAuthority,
        binding: endpointSet.binding,
        frame: exactEntry.frame
      })
      if (!bytesEqual(announcementBytes, phase.announcementBytes)) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_FRESH_PROOF_INVALID',
          `${row.relayId} fresh READ recovered a different announcement`)
      }
      const readback = await verifyPeeritPublicInboxAnnouncementReadbackV1({
        authority: bootstrapAuthority,
        binding: endpointSet.binding,
        control,
        runtime,
        cellEndpoint: endpointSet.cellGetEndpoint,
        announcementBytes,
        httpClient: client,
        profileValidator: assembly.profileValidator,
        nowUnixMillis: referenceUnixMillis
      })
      const putResult = PRODUCTION_VERIFIED.get(put)
      if (!putResult || putResult.kind !== 'CELL.PUT') {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_FRESH_PROOF_INVALID',
          `${row.relayId} fresh proof lacks the exact authenticated PUT receipt`)
      }
      await verifyPeeritSeq29CellPutReadbackEvidenceV1({
        authority: bootstrapAuthority,
        binding: endpointSet.binding,
        control,
        putEndpoint: endpointSet.putEndpoint,
        evidence: Object.freeze({
          request: putState.request,
          requestCommitment: putState.requestCommitment,
          resultBytes: putResult.resultBytes
        }),
        readback
      })
      const binding = validatePeeritSeq29PreparedPutReadbackBindingV1({
        request: putState.request,
        readCap: putState.readCap,
        publication: putState.publication,
        announcementBytes: phase.announcementBytes,
        verifiedAnnouncementBytes: announcementBytes,
        readback
      })
      return Object.freeze({
        relayId: row.relayId,
        inboxReadVerified: true,
        cellGetVerified: true,
        announcementMatched: true,
        evidenceRef: `authenticated-fresh-read:${row.relayId}:${binding.innerSha256}`
      })
    },
    async decodeWireRequest (_requestBytes, prepared) {
      const state = PRODUCTION_PREPARED.get(prepared)
      if (!state) fail('PEERIT_SEQ29_PUBLICATION_DRILL_WIRE_INVALID', 'unbranded request')
      return Object.freeze({
        familyId: state.wire.familyId,
        operationId: state.wire.operationId,
        requestCommitment: prepared.requestCommitment,
        relayPublicKey: prepared.relayPublicKey,
        physicalTopic: prepared.physicalTopic
      })
    },
    async verifyWriteResult ({ row, prepared, response }) {
      const state = PRODUCTION_PREPARED.get(prepared)
      if (!state || !(response.body instanceof Uint8Array)) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_RESULT_INVALID', 'unbranded write result')
      }
      const verified = await control.verifyOperationResult({
        endpoint: state.endpoint,
        request: state.request,
        requestCommitment: state.requestCommitment,
        resultBytes: response.body
      })
      if (state.kind === 'CELL.PUT') {
        const receipt = control.decodeBlindExternalProfileValueV1(
          'BlindReceiptV1', verified.snapshotBytes())
        if (receipt.result !== 1 ||
            !bytesEqual(receipt.requestCommitment, state.requestCommitment) ||
            !bytesEqual(receipt.relayBinding.relayPublicKey,
              endpointById.get(row.relayId).binding.relayPublicKey) ||
            !bytesEqual(receipt.relayBinding.storeId,
              endpointById.get(row.relayId).binding.storeId) ||
            !bytesEqual(receipt.relayBinding.durabilityContinuityHash,
              endpointById.get(row.relayId).binding.durabilityContinuityHash) ||
            !bytesEqual(receipt.cellBlobHash, state.declaredBlobHash)) {
          fail('PEERIT_SEQ29_PUBLICATION_DRILL_RESULT_INVALID',
            `${row.relayId} PUT receipt differs from the exact request/read capability`)
        }
      }
      PRODUCTION_VERIFIED.set(prepared, Object.freeze({
        kind: state.kind,
        verified,
        resultBytes: response.body.slice()
      }))
      return Object.freeze({
        relayId: row.relayId,
        relayPublicKey: row.relayPublicKey,
        storeId: row.storeId,
        durabilityContinuityHash: row.durabilityContinuityHash,
        physicalTopic: row.physicalTopic,
        familyId: state.wire.familyId,
        operationId: state.wire.operationId,
        requestCommitment: prepared.requestCommitment,
        resultSha256: bytesHash(response.body, 'write result bytes'),
        evidenceRef: `authenticated-write-result:${prepared.family}.${prepared.operation}:${row.relayId}`
      })
    }
  })
  AUTHORITY.set(authority, Object.freeze({
    control: controlAdapter,
    async send ({ prepared }) {
      const state = PRODUCTION_PREPARED.get(prepared)
      if (!state) fail('PEERIT_SEQ29_PUBLICATION_DRILL_WIRE_INVALID', 'unbranded request send')
      return client.request({ endpoint: state.endpoint, ...state.wire, body: prepared.requestBytes })
    },
    fixtureOnly: false,
    phaseSplit: true,
    attemptId: phase.attemptId,
    releaseIdentityDigest: phase.releaseIdentityDigest,
    phaseOneDispatches: Object.freeze(rows.map(row => {
      const prepared = preparedPuts.get(row.relayId)
      return Object.freeze({
        family: 'CELL',
        operation: 'PUT',
        relayId: row.relayId,
        operationKey: `CELL.PUT:${row.relayId}`,
        requestSha256: bytesHash(prepared.requestBytes, 'PUT requestBytes'),
        requestCommitment: prepared.requestCommitment
      })
    }))
  }))
  return authority
}

function assertPrepared (value, row, family, operation) {
  exact(value, [
    'relayId', 'relayPublicKey', 'storeId', 'durabilityContinuityHash',
    'physicalTopic', 'family', 'operation', 'requestBytes', 'requestCommitment',
    'evidenceRef'
  ], `${family}.${operation} prepared envelope`)
  if (value.relayId !== row.relayId || value.relayPublicKey !== row.relayPublicKey ||
      value.storeId !== row.storeId ||
      value.durabilityContinuityHash !== row.durabilityContinuityHash ||
      value.physicalTopic !== row.physicalTopic || value.family !== family ||
      value.operation !== operation) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      `${family}.${operation} envelope does not bind its authenticated relay and topic`)
  }
  hex32(value.requestCommitment, 'requestCommitment')
  opaque(value.evidenceRef, 'prepared evidenceRef')
  bytesHash(value.requestBytes, 'requestBytes')
  return value
}

function assertDecodedWire (decoded, prepared) {
  exact(decoded, [
    'familyId', 'operationId', 'requestCommitment', 'relayPublicKey', 'physicalTopic'
  ], 'decoded wire request')
  const expected = FAMILY_OPERATION[`${prepared.family}.${prepared.operation}`]
  if (!expected || decoded.familyId !== expected.familyId ||
      decoded.operationId !== expected.operationId ||
      decoded.requestCommitment !== prepared.requestCommitment ||
      decoded.relayPublicKey !== prepared.relayPublicKey ||
      decoded.physicalTopic !== prepared.physicalTopic) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_WIRE_INVALID',
      'prepared labels differ from the decoded authenticated request bytes')
  }
}

function operationLedger (dispatches) {
  const ledger = { cellPut: 0, inboxAppend: 0, inboxCreate: 0, inboxRenew: 0, inboxClose: 0, other: 0 }
  for (const row of dispatches) {
    if (row.family === 'CELL' && row.operation === 'PUT') ledger.cellPut++
    else if (row.family === 'INBOX' && row.operation === 'APPEND') ledger.inboxAppend++
    else if (row.family === 'INBOX' && row.operation === 'CREATE') ledger.inboxCreate++
    else if (row.family === 'INBOX' && row.operation === 'RENEW') ledger.inboxRenew++
    else if (row.family === 'INBOX' && row.operation === 'CLOSE') ledger.inboxClose++
    else ledger.other++
  }
  return ledger
}

export async function runPeeritSeq29BoundedPublicationDrillV1 (input = {}) {
  exact(input, ['authority', 'attemptJournal'], 'publication drill input')
  const authority = input.authority
  const authorityState = AUTHORITY.get(authority)
  if (!authorityState) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
      'module-created verified Seq29 publication authority is required')
  }
  const control = authorityState.control
  const journal = methods(input.attemptJournal,
    ['beginAttempt', 'claimOperation', 'recordOutcome', 'finishAttempt'],
    'durable publication journal')
  const releaseIdentity = Object.freeze({
    schema: 'peerit-seq29-publication-release-identity-v1',
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    candidateCommit: authority.candidateCommit,
    releaseSequence: authority.releaseSequence,
    bootstrapHash: authority.bootstrapHash,
    rows: authority.rows
  })
  const releaseIdentityDigest = hashObject(releaseIdentity)
  const beginRequest = Object.freeze({
    schema: 'peerit-seq29-bounded-publication-attempt-v1',
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest,
    operationManifest: Object.freeze([
      'CELL.PUT:' + authority.rows[0].relayId,
      'CELL.PUT:' + authority.rows[1].relayId,
      'INBOX.APPEND:' + authority.rows[0].relayId,
      'INBOX.APPEND:' + authority.rows[1].relayId
    ])
  })
  const begunValue = await journal.beginAttempt(beginRequest)
  const begun = durableReceipt(begunValue,
    authorityState.phaseSplit ? 'RECOVERY_AVAILABLE_NO_RESEND' : 'CONSUMED_NO_MUTATIONS',
    authorityState.phaseSplit
      ? [
          'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
          'releaseIdentityDigest', 'requestDigest', 'recovery', 'commitment'
        ]
      : [
          'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
          'releaseIdentityDigest', 'requestDigest', 'commitment'
        ], 'attempt begin', {
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest,
      requestDigest: hashObject(beginRequest)
    })
  const attemptId = opaque(begun.attemptId, 'attemptId', 512)
  if (authorityState.phaseSplit && attemptId !== authorityState.attemptId) {
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
      'phase-two recovery returned a different durable attempt identity')
  }
  const dispatches = authorityState.phaseSplit
    ? [...authorityState.phaseOneDispatches]
    : []
  const puts = []
  const readbacks = []
  const appends = []
  const freshProofs = []
  let journalFinished = false

  const dispatchOnce = async (prepared, operationIndex) => {
    if (!PREPARED.has(prepared)) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
        'only an envelope branded after trusted-control decoding may be sent')
    }
    const operationKey = `${prepared.family}.${prepared.operation}:${prepared.relayId}`
    const requestSha256 = bytesHash(prepared.requestBytes, 'requestBytes')
    const claimRequest = Object.freeze({
      attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest,
      operationIndex,
      operationKey,
      requestSha256,
      requestCommitment: prepared.requestCommitment
    })
    durableReceipt(await journal.claimOperation(claimRequest), 'DISPATCH_CLAIMED', [
      'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
      'releaseIdentityDigest', 'operationKey', 'requestDigest', 'commitment'
    ], `claim ${operationKey}`, {
      attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest,
      operationKey,
      requestDigest: hashObject(claimRequest)
    })
    const dispatch = Object.freeze({
      family: prepared.family,
      operation: prepared.operation,
      relayId: prepared.relayId,
      operationKey,
      requestSha256,
      requestCommitment: prepared.requestCommitment
    })
    dispatches.push(dispatch)
    let response
    try {
      response = await authorityState.send(Object.freeze({
        attemptId,
        operationKey,
        relayId: prepared.relayId,
        requestBytes: prepared.requestBytes,
        prepared
      }))
    } catch (cause) {
      const outcomeRequest = Object.freeze({
        attemptId,
        releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
        releaseIdentityDigest,
        operationKey,
        requestSha256,
        state: 'AMBIGUOUS_TERMINAL'
      })
      durableReceipt(await journal.recordOutcome(outcomeRequest), 'AMBIGUOUS_TERMINAL', [
        'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
        'releaseIdentityDigest', 'operationKey', 'requestDigest', 'commitment'
      ], `outcome ${operationKey}`, {
        attemptId,
        releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
        releaseIdentityDigest,
        operationKey,
        requestDigest: hashObject(outcomeRequest)
      })
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_TRANSPORT_AMBIGUOUS',
        `${operationKey} has an ambiguous terminal outcome`, cause)
    }
    if (!response || response.ok !== true || !(response.body instanceof Uint8Array)) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_WRITE_REJECTED', `${operationKey} was rejected`)
    }
    const verified = await control.verifyWriteResult({
      row: authority.rows[operationIndex % 2],
      prepared,
      response
    })
    exact(verified, [
      'relayId', 'relayPublicKey', 'storeId', 'durabilityContinuityHash',
      'physicalTopic', 'familyId', 'operationId', 'requestCommitment',
      'resultSha256', 'evidenceRef'
    ], 'authenticated write result')
    const expected = FAMILY_OPERATION[`${prepared.family}.${prepared.operation}`]
    if (verified.relayId !== prepared.relayId ||
        verified.relayPublicKey !== prepared.relayPublicKey ||
        verified.storeId !== prepared.storeId ||
        verified.durabilityContinuityHash !== prepared.durabilityContinuityHash ||
        verified.physicalTopic !== prepared.physicalTopic ||
        verified.familyId !== expected.familyId || verified.operationId !== expected.operationId ||
        verified.requestCommitment !== prepared.requestCommitment ||
        verified.resultSha256 !== bytesHash(response.body, 'write result bytes')) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_RESULT_INVALID',
        `${operationKey} result is not authenticated and request-correlated`)
    }
    opaque(verified.evidenceRef, 'write evidenceRef')
    const outcomeRequest = Object.freeze({
      attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest,
      operationKey,
      requestSha256,
      resultSha256: verified.resultSha256,
      state: 'VERIFIED_TERMINAL'
    })
    durableReceipt(await journal.recordOutcome(outcomeRequest), 'VERIFIED_TERMINAL', [
      'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
      'releaseIdentityDigest', 'operationKey', 'requestDigest', 'commitment'
    ], `outcome ${operationKey}`, {
      attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest,
      operationKey,
      requestDigest: hashObject(outcomeRequest)
    })
    return verified
  }

  try {
    for (let index = 0; index < 2; index++) {
      const row = authority.rows[index]
      const prepared = assertPrepared(await control.prepareCellPut(row), row, 'CELL', 'PUT')
      assertDecodedWire(await control.decodeWireRequest(prepared.requestBytes, prepared), prepared)
      PREPARED.add(prepared)
      puts.push(prepared)
      if (!authorityState.phaseSplit) await dispatchOnce(prepared, index)
      const proof = await control.verifyCellPutReadback({ row, prepared })
      exact(proof, ['relayId', 'cellGetVerified', 'authorBindVerified', 'announcementBytes', 'evidenceRef'],
        'CELL.PUT readback')
      if (proof.relayId !== row.relayId || proof.cellGetVerified !== true ||
          proof.authorBindVerified !== true || !(proof.announcementBytes instanceof Uint8Array)) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID', 'PUT readback is incomplete')
      }
      opaque(proof.evidenceRef, 'PUT readback evidenceRef')
      readbacks.push(proof)
    }
    for (let index = 0; index < 2; index++) {
      const row = authority.rows[index]
      const prepared = assertPrepared(await control.prepareInboxAppend({
        row,
        put: puts[index],
        announcementBytes: readbacks[index].announcementBytes
      }), row, 'INBOX', 'APPEND')
      assertDecodedWire(await control.decodeWireRequest(prepared.requestBytes, prepared), prepared)
      PREPARED.add(prepared)
      const verified = await dispatchOnce(prepared, index + 2)
      const append = await control.verifyInboxAppend({ row, prepared, verified })
      exact(append, ['relayId', 'acknowledged', 'evidenceRef'], 'INBOX.APPEND evidence')
      if (append.relayId !== row.relayId || append.acknowledged !== true) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_APPEND_INVALID', 'APPEND evidence is incomplete')
      }
      opaque(append.evidenceRef, 'APPEND evidenceRef')
      appends.push(append)
    }
    for (let index = 0; index < 2; index++) {
      const proof = await control.freshReadCellGet({
        row: authority.rows[index], put: puts[index], append: appends[index]
      })
      exact(proof, [
        'relayId', 'inboxReadVerified', 'cellGetVerified',
        'announcementMatched', 'evidenceRef'
      ], 'fresh READ/CELL.GET proof')
      if (proof.relayId !== authority.rows[index].relayId ||
          proof.inboxReadVerified !== true || proof.cellGetVerified !== true ||
          proof.announcementMatched !== true) {
        fail('PEERIT_SEQ29_PUBLICATION_DRILL_FRESH_PROOF_INVALID',
          'fresh READ/CELL.GET proof is incomplete')
      }
      opaque(proof.evidenceRef, 'fresh proof evidenceRef')
      freshProofs.push(proof)
    }
    const ledger = operationLedger(dispatches)
    if (ledger.cellPut !== 2 || ledger.inboxAppend !== 2 ||
        ['inboxCreate', 'inboxRenew', 'inboxClose', 'other'].some(field => ledger[field] !== 0)) {
      fail('PEERIT_SEQ29_PUBLICATION_DRILL_BUDGET_EXCEEDED',
        'measured sends differ from exactly two PUT and two APPEND')
    }
    const executionDigest = hashObject({ releaseIdentityDigest, dispatches, ledger })
    const finishRequest = Object.freeze({
      attemptId,
      releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
      releaseIdentityDigest,
      executionDigest,
      state: 'COMMITTED_EXACT_BUDGET',
      dispatches: Object.freeze([...dispatches])
    })
    const finished = durableReceipt(await journal.finishAttempt(finishRequest),
      'COMMITTED_EXACT_BUDGET', [
        'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
        'releaseIdentityDigest', 'executionDigest', 'requestDigest', 'commitment'
      ], 'attempt finish', {
        attemptId,
        releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
        releaseIdentityDigest,
        executionDigest,
        requestDigest: hashObject(finishRequest)
      })
    journalFinished = true
    return Object.freeze({
      schema: PEERIT_SEQ29_BOUNDED_PUBLICATION_DRILL_SCHEMA_V1,
      version: 1,
      status: 'PASS',
      candidateCommit: authority.candidateCommit,
      releaseSequence: 29,
      bootstrapHash: authority.bootstrapHash,
      releaseIdentityDigest,
      relayIdentities: authority.rows,
      writeSequence: Object.freeze([...dispatches]),
      mutationLedger: Object.freeze(ledger),
      readProofLedger: Object.freeze({
        putReceiptAndCellGet: readbacks.length,
        freshInboxReadAndCellGet: freshProofs.length
      }),
      executionAttestation: Object.freeze({
        attemptId,
        executionDigest,
        journalCommitment: finished.commitment
      })
    })
  } catch (cause) {
    if (!journalFinished) {
      try {
        const executionDigest = hashObject({ releaseIdentityDigest, dispatches })
        const finishRequest = Object.freeze({
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
          releaseIdentityDigest,
          executionDigest,
          state: 'TERMINAL_NO_RETRY',
          dispatches: Object.freeze([...dispatches])
        })
        durableReceipt(await journal.finishAttempt(finishRequest), 'TERMINAL_NO_RETRY', [
          'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
          'releaseIdentityDigest', 'executionDigest', 'requestDigest', 'commitment'
        ], 'terminal attempt finish', {
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
          releaseIdentityDigest,
          executionDigest,
          requestDigest: hashObject(finishRequest)
        })
      } catch {}
    }
    fail('PEERIT_SEQ29_PUBLICATION_DRILL_ABORTED',
      'bounded publication drill stopped terminally without retry or lifecycle compensation', {
        attemptId,
        causeCode: cause?.code || null,
        actualDispatches: dispatches,
        retries: 0,
        lifecycleCompensationWrites: 0
      })
  }
}

function main () {
  fail('PEERIT_SEQ29_PUBLICATION_DRILL_USAGE',
    'no CLI execution or caller-authored PASS validation is available; import the branded authority and bounded executor')
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { main() } catch (error) {
    console.error(`${error.code || 'PEERIT_SEQ29_PUBLICATION_DRILL_FAILED'}: ${error.message}`)
    process.exitCode = 1
  }
}
