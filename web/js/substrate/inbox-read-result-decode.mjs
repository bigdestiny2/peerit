// Minimal, strict, bounds-checked decoder for the AUTHENTICATED result
// snapshots (VerifiedOperationResult.snapshotBytes()) of the three INBOX
// operations peerit uses: CREATE receipt, APPEND ack, READ result. The
// vendored blind client authenticates these bytes end-to-end (endpoint
// binding, relay signature, request correlation) but deliberately does not
// decode their fields; this module mirrors the canonical layouts EXACTLY from
// 00-core/hiverelay/packages/blind-protocol/schemas.js (inboxReceiptV1,
// inboxAppendAckV1, inboxReadResultV1) and result-binding.js
// (relayResultBindingV1 ‖ optional blindExternalCommitWitnessV1) so the
// publish/discovery flows can read appendRevision / snapshotRevision / frames.
// Decode-only peerit code: every offset is checked, trailing bytes must be
// exact, compactUint must be canonical, unknown result constants fail, and the
// drill asserts byte-parity with decodeCanonical from @hiverelay/blind-protocol
// on relay-produced bytes. Any deviation → PEERIT_INBOX_RESULT_DECODE_INVALID.
import { asBytes, blake2b256, bytesEqual } from './release-control-primitives.mjs'

const INBOX_FRAME_CLASS_BYTES = Object.freeze({ 1: 4096, 2: 16384, 3: 65536 })
const INBOX_RECEIPT_RESULT_VALUES = Object.freeze({ CREATED: 1, RENEWED: 2, CLOSED: 3 })
const INBOX_APPEND_RESULT_STORED = 1
const MAX_READ_ENTRIES = 64
const MAX_CURSOR_BYTES = 128

function fail (message) {
  const error = new Error(message)
  error.code = 'PEERIT_INBOX_RESULT_DECODE_INVALID'
  throw error
}

class Cursor {
  constructor (bytes) {
    this.bytes = bytes
    this.offset = 0
  }

  get remaining () {
    return this.bytes.byteLength - this.offset
  }

  take (length, field) {
    if (!Number.isSafeInteger(length) || length < 0 || this.remaining < length) {
      fail(`truncated ${field}`)
    }
    const value = this.bytes.slice(this.offset, this.offset + length)
    this.offset += length
    return value
  }

  u8 (field) {
    return this.take(1, field)[0]
  }

  u32 (field) {
    const bytes = this.take(4, field)
    return bytes[0] * 0x1000000 + bytes[1] * 0x10000 + bytes[2] * 0x100 + bytes[3]
  }

  u64 (field) {
    const bytes = this.take(8, field)
    let value = 0n
    for (const byte of bytes) value = (value << 8n) | BigInt(byte)
    return value
  }

  // compact-encoding's canonical unsigned prefix: marker byte, then
  // little-endian payload; overlong forms are non-canonical and invalid.
  compactUint (field) {
    const marker = this.u8(field)
    if (marker <= 0xfc) return marker
    if (marker === 0xfd) {
      const bytes = this.take(2, field)
      const value = bytes[0] | (bytes[1] << 8)
      if (value <= 0xfc) fail(`non-canonical compact uint for ${field}`)
      return value
    }
    if (marker === 0xfe) {
      const bytes = this.take(4, field)
      const value = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0
      if (value <= 0xffff) fail(`non-canonical compact uint for ${field}`)
      return value
    }
    const bytes = this.take(8, field)
    let value = 0n
    for (let index = 7; index >= 0; index--) value = (value << 8n) | BigInt(bytes[index])
    if (value <= 0xffffffffn || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(`non-canonical or unsupported compact uint for ${field}`)
    }
    return Number(value)
  }

  presence (field) {
    const tag = this.u8(`${field} presence`)
    if (tag !== 0 && tag !== 1) fail(`${field} presence must be 0 or 1`)
    return tag === 1
  }

  expectEnd (field) {
    if (this.remaining !== 0) fail(`${field} has trailing bytes`)
  }
}

// relayResultBindingV1 — walked exactly (the offsets of every following field
// depend on it); the decoded binding fields are not part of the returned
// surface because the vendored verifier already bound them to the qualified
// descriptor. durabilityProfileId must be 1..2; the external commit witness,
// when present, is the fixed 539-byte blindExternalCommitWitnessV1:
//   version:u8 ‖ relayPublicKey ‖ storeId ‖ externalJournalId ‖
//   durabilityContinuityHash ‖ durabilityProfileHash ‖
//   restoreEvidenceHeadSequence:u64 ‖ restoreEvidenceHeadHash ‖ familyId:u8 ‖
//   operationId:u8 ‖ requestCommitment ‖ resultCommitment ‖
//   commitWalSequence:u64 ‖ commitWalHash ‖ coveringFloorRevision:u64 ‖
//   coveringFloorHash ‖ coveringFloorWalSequence:u64 ‖ coveringFloorWalHash ‖
//   writerEpoch:u64 ‖ writerFenceTokenHash ‖ externalLeaseRevision:u64 ‖
//   witnessedUnixMillis:u64 ‖ witnessPublicKey ‖ signature(64)
// (13 × 32-byte fields, 7 × u64, 3 × u8, 64-byte signature)
const EXTERNAL_COMMIT_WITNESS_BYTES = 13 * 32 + 7 * 8 + 3 + 64

function walkRelayResultBindingV1 (cursor) {
  if (cursor.u8('relayBinding version') !== 1) fail('relayBinding version is unsupported')
  cursor.take(32, 'relayBinding relayPublicKey')
  cursor.take(32, 'relayBinding storeId')
  cursor.u64('relayBinding descriptorSequence')
  cursor.take(32, 'relayBinding descriptorHash')
  const durabilityProfileId = cursor.u8('relayBinding durabilityProfileId')
  if (durabilityProfileId < 1 || durabilityProfileId > 2) {
    fail('relayBinding durabilityProfileId is outside 1..2')
  }
  cursor.take(32, 'relayBinding durabilityContinuityHash')
  cursor.take(32, 'relayBinding durabilityProfileHash')
  cursor.u64('relayBinding restoreEvidenceHeadSequence')
  cursor.take(32, 'relayBinding restoreEvidenceHeadHash')
  if (cursor.presence('externalCommitWitness')) {
    const witness = cursor.take(EXTERNAL_COMMIT_WITNESS_BYTES, 'externalCommitWitness')
    if (witness[0] !== 1) fail('externalCommitWitness version is unsupported')
  }
}

function decodeSnapshot (bytes, field) {
  const value = asBytes(bytes, field)
  const cursor = new Cursor(value)
  if (cursor.u8('result version') !== 1) fail('result version is unsupported')
  walkRelayResultBindingV1(cursor)
  return cursor
}

// inboxReceiptV1: version ‖ relayBinding ‖ topicCommitment ‖ stateRevision:u64
// ‖ leaseClass:u8(0..4) ‖ leaseEpoch:u32 ‖ requestNonce ‖ requestCommitment ‖
// result:u8(1..3) ‖ signature(64). A CLOSED receipt carries leaseClass 0;
// CREATED/RENEWED must not.
export function decodePeeritInboxReceiptSnapshotV1 (bytes) {
  const cursor = decodeSnapshot(bytes, 'inbox receipt snapshot')
  cursor.take(32, 'topicCommitment')
  const stateRevision = cursor.u64('stateRevision')
  const leaseClass = cursor.u8('leaseClass')
  if (leaseClass > 4) fail('leaseClass is outside 0..4')
  const leaseEpoch = cursor.u32('leaseEpoch')
  cursor.take(32, 'requestNonce')
  cursor.take(32, 'requestCommitment')
  const result = cursor.u8('receipt result')
  if (result !== INBOX_RECEIPT_RESULT_VALUES.CREATED &&
      result !== INBOX_RECEIPT_RESULT_VALUES.RENEWED &&
      result !== INBOX_RECEIPT_RESULT_VALUES.CLOSED) {
    fail('inbox receipt result is unknown')
  }
  if ((result === INBOX_RECEIPT_RESULT_VALUES.CLOSED) !== (leaseClass === 0)) {
    fail('inbox receipt result/lease mismatch')
  }
  cursor.take(64, 'signature')
  cursor.expectEnd('inbox receipt')
  return Object.freeze({ result, stateRevision, leaseClass, leaseEpoch })
}

// inboxAppendAckV1: version ‖ relayBinding ‖ topicCommitment ‖ frameHash ‖
// appendRevision:u64 ‖ storedAtEpoch:u32 ‖ expiresAtEpoch:u32 ‖ requestNonce ‖
// requestCommitment ‖ result:u8(=STORED) ‖ signature(64).
export function decodePeeritInboxAppendAckSnapshotV1 (bytes) {
  const cursor = decodeSnapshot(bytes, 'inbox append ack snapshot')
  cursor.take(32, 'topicCommitment')
  const frameHash = cursor.take(32, 'frameHash')
  const appendRevision = cursor.u64('appendRevision')
  const storedAtEpoch = cursor.u32('storedAtEpoch')
  const expiresAtEpoch = cursor.u32('expiresAtEpoch')
  if (expiresAtEpoch <= storedAtEpoch) fail('expiresAtEpoch must be after storedAtEpoch')
  cursor.take(32, 'requestNonce')
  cursor.take(32, 'requestCommitment')
  if (cursor.u8('append result') !== INBOX_APPEND_RESULT_STORED) {
    fail('inbox append ack result is unknown')
  }
  cursor.take(64, 'signature')
  cursor.expectEnd('inbox append ack')
  return Object.freeze({
    result: INBOX_APPEND_RESULT_STORED,
    appendRevision,
    frameHash,
    storedAtEpoch,
    expiresAtEpoch
  })
}

// inboxReadResultV1: version ‖ relayBinding ‖ requestNonce ‖
// requestCommitment ‖ snapshotRevision:u64 ‖ compactUint count(0..64) ‖
// count × entry{appendRevision:u64 ‖ frameHash ‖ frameClass:u8(1..3) ‖
// frame(class bytes)} ‖ entriesCommitment ‖ nextCursor:?bounded(0..128) ‖
// signature(64). Entries are strictly increasing in appendRevision and pinned
// at or below snapshotRevision; entriesCommitment is blake2b256 of the exact
// canonical entries span (count prefix included), mirrored byte-for-byte.
export function decodePeeritInboxReadResultSnapshotV1 (bytes) {
  const cursor = decodeSnapshot(bytes, 'inbox read result snapshot')
  cursor.take(32, 'requestNonce')
  cursor.take(32, 'requestCommitment')
  const snapshotRevision = cursor.u64('snapshotRevision')
  const entriesStart = cursor.offset
  const count = cursor.compactUint('inbox read entries count')
  if (count > MAX_READ_ENTRIES) fail('inbox read entries count exceeds 64')
  const entries = []
  let previous = -1n
  for (let index = 0; index < count; index++) {
    const appendRevision = cursor.u64(`entries[${index}].appendRevision`)
    const frameHash = cursor.take(32, `entries[${index}].frameHash`)
    const frameClass = cursor.u8(`entries[${index}].frameClass`)
    const frameBytes = INBOX_FRAME_CLASS_BYTES[frameClass]
    if (frameBytes == null) fail(`entries[${index}].frameClass is outside 1..3`)
    const frame = cursor.take(frameBytes, `entries[${index}].frame`)
    if (!bytesEqual(blake2b256(frame), frameHash)) {
      fail(`entries[${index}].frameHash does not match frame`)
    }
    if (appendRevision <= previous) fail('inbox entries must have strictly increasing appendRevision')
    if (appendRevision > snapshotRevision) fail('inbox entry revision exceeds snapshotRevision')
    previous = appendRevision
    entries.push(Object.freeze({ appendRevision, frameHash, frameClass, frame }))
  }
  const entriesSpan = cursor.bytes.slice(entriesStart, cursor.offset)
  const entriesCommitment = cursor.take(32, 'entriesCommitment')
  if (!bytesEqual(blake2b256(entriesSpan), entriesCommitment)) {
    fail('inbox entriesCommitment does not match entries')
  }
  let nextCursor = null
  if (cursor.presence('nextCursor')) {
    const length = cursor.compactUint('nextCursor length')
    if (length > MAX_CURSOR_BYTES) fail('nextCursor exceeds 128 bytes')
    nextCursor = cursor.take(length, 'nextCursor')
  }
  cursor.take(64, 'signature')
  cursor.expectEnd('inbox read result')
  return Object.freeze({
    snapshotRevision,
    entries: Object.freeze(entries),
    nextCursor
  })
}
