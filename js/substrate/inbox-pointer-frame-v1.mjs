// peerit INBOX pointer frame codec v1 — the 4096-byte frameClass-1 frame a
// publisher appends to a board's inbox topic after its record's CELL.PUT
// verifies. Pure-JS only (strict-CSP safe: no node:crypto, no Buffer).
//
// Layout (exactly 4096 bytes, zero-padded):
//   magic "peerit/inbox-pointer/v1" (23 bytes, printable ASCII)
//   u8 version = 1
//   u8 boardSlugLen (1..64)
//   boardSlug utf8 ([a-z0-9-], boardSlugLen bytes)
//   recordCid (32 bytes — the record's protocol-v3 content id)
//   authorPubKey (32 bytes — the record author's ed25519 public key)
//   u8 sizeClass (1..5 — the CELL.PUT size class the record blob lives in)
//   u8 leaseClass (1..4 — the CELL.PUT lease class)
//   u64be appendedAtUnixMillis (publisher-declared append time)
//   u8 hintCount (0..2), then hintCount × 32-byte relayPublicKeys (replica
//     hints: relays where the same record is also expected to be stored)
//   zero padding to exactly 4096 bytes
//
// The frame is self-describing but NOT self-authenticating: the relay stores
// opaque bytes. Readers authenticate the ENVELOPE (the vendored control's
// verifyOperationResult binds the signed read result to the qualified
// descriptor), then treat any frame that fails this codec as poison: the
// discovery module records the rejection and advances past it. ANY deviation
// — magic, version, lengths, ranges, or a single nonzero trailing byte —
// fails closed with PEERIT_INBOX_POINTER_FRAME_INVALID.
import {
  asciiBytes,
  asBytes,
  bytesEqual,
  decodeUtf8,
  fixedBytesValue,
  isAllZero,
  utf8Bytes
} from './release-control-primitives.mjs'
import { PEERIT_INBOX_BOARD_SLUG_PATTERN_V1 } from './inbox-topic-v1.mjs'

export const PEERIT_INBOX_POINTER_FRAME_MAGIC_V1 = 'peerit/inbox-pointer/v1'
export const PEERIT_INBOX_POINTER_FRAME_VERSION_V1 = 1
export const PEERIT_INBOX_POINTER_FRAME_BYTES_V1 = 4096
export const PEERIT_INBOX_POINTER_MAX_HINTS_V1 = 2

const MAGIC = asciiBytes(PEERIT_INBOX_POINTER_FRAME_MAGIC_V1) // 23 bytes
const HEADER_BYTES = MAGIC.byteLength + 2 // magic ‖ version ‖ boardSlugLen
const FIXED_TAIL_BYTES = 32 + 32 + 1 + 1 + 8 + 1 // cid ‖ author ‖ classes ‖ millis ‖ hintCount

function fail (message) {
  const error = new Error(message)
  error.code = 'PEERIT_INBOX_POINTER_FRAME_INVALID'
  throw error
}

function classInteger (value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function millisU64 (value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('appendedAtUnixMillis must be an unsigned safe integer or bigint')
    return BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    fail('appendedAtUnixMillis is outside u64')
  }
  return value
}

export function encodePeeritInboxPointerFrameV1 (fields) {
  if (!fields || typeof fields !== 'object') fail('pointer frame fields are required')
  if (typeof fields.boardSlug !== 'string' || !PEERIT_INBOX_BOARD_SLUG_PATTERN_V1.test(fields.boardSlug)) {
    fail('boardSlug must be lowercase [a-z0-9-]{1,64}')
  }
  const slug = utf8Bytes(fields.boardSlug, 'boardSlug')
  const recordCid = fixedBytesValue(fields.recordCid, 32, 'recordCid')
  const authorPubKey = fixedBytesValue(fields.authorPubKey, 32, 'authorPubKey')
  const sizeClass = classInteger(fields.sizeClass, 'sizeClass', 1, 5)
  const leaseClass = classInteger(fields.leaseClass, 'leaseClass', 1, 4)
  const appendedAtUnixMillis = millisU64(fields.appendedAtUnixMillis)
  const hints = fields.hints == null ? [] : fields.hints
  if (!Array.isArray(hints) || hints.length > PEERIT_INBOX_POINTER_MAX_HINTS_V1) {
    fail(`hints must be 0..${PEERIT_INBOX_POINTER_MAX_HINTS_V1} relay public keys`)
  }
  const hintBytes = hints.map((hint, index) => fixedBytesValue(hint, 32, `hints[${index}]`))
  for (const [index, hint] of hintBytes.entries()) {
    if (hintBytes.findIndex(candidate => bytesEqual(candidate, hint)) !== index) {
      fail('hints must not repeat a relay public key')
    }
  }
  const contentBytes = HEADER_BYTES + slug.byteLength + FIXED_TAIL_BYTES +
    hintBytes.length * 32
  if (contentBytes > PEERIT_INBOX_POINTER_FRAME_BYTES_V1) {
    fail('pointer frame content exceeds the frameClass-1 frame')
  }
  const frame = new Uint8Array(PEERIT_INBOX_POINTER_FRAME_BYTES_V1)
  let offset = 0
  frame.set(MAGIC, offset)
  offset += MAGIC.byteLength
  frame[offset] = PEERIT_INBOX_POINTER_FRAME_VERSION_V1
  offset += 1
  frame[offset] = slug.byteLength
  offset += 1
  frame.set(slug, offset)
  offset += slug.byteLength
  frame.set(recordCid, offset)
  offset += 32
  frame.set(authorPubKey, offset)
  offset += 32
  frame[offset] = sizeClass
  offset += 1
  frame[offset] = leaseClass
  offset += 1
  let millis = appendedAtUnixMillis
  for (let index = 7; index >= 0; index--) {
    frame[offset + index] = Number(millis & 0xffn)
    millis >>= 8n
  }
  offset += 8
  frame[offset] = hintBytes.length
  offset += 1
  for (const hint of hintBytes) {
    frame.set(hint, offset)
    offset += 32
  }
  return frame
}

function decodeFrame (frame) {
  const bytes = asBytes(frame, 'pointer frame')
  if (bytes.byteLength !== PEERIT_INBOX_POINTER_FRAME_BYTES_V1) {
    fail(`pointer frame must be exactly ${PEERIT_INBOX_POINTER_FRAME_BYTES_V1} bytes`)
  }
  let offset = 0
  if (!bytesEqual(bytes.subarray(offset, offset + MAGIC.byteLength), MAGIC)) {
    fail('pointer frame magic mismatch')
  }
  offset += MAGIC.byteLength
  if (bytes[offset] !== PEERIT_INBOX_POINTER_FRAME_VERSION_V1) {
    fail('pointer frame version is unsupported')
  }
  offset += 1
  const slugLength = bytes[offset]
  offset += 1
  if (slugLength < 1 || slugLength > 64) fail('boardSlugLen is outside 1..64')
  if (offset + slugLength + FIXED_TAIL_BYTES > bytes.byteLength) fail('pointer frame header overruns the frame')
  const boardSlug = decodeUtf8(bytes.subarray(offset, offset + slugLength), 'boardSlug')
  if (!PEERIT_INBOX_BOARD_SLUG_PATTERN_V1.test(boardSlug)) fail('boardSlug is not lowercase [a-z0-9-]{1,64}')
  offset += slugLength
  const recordCid = bytes.slice(offset, offset + 32)
  offset += 32
  const authorPubKey = bytes.slice(offset, offset + 32)
  offset += 32
  const sizeClass = bytes[offset]
  offset += 1
  if (sizeClass < 1 || sizeClass > 5) fail('sizeClass is outside 1..5')
  const leaseClass = bytes[offset]
  offset += 1
  if (leaseClass < 1 || leaseClass > 4) fail('leaseClass is outside 1..4')
  let appendedAtUnixMillis = 0n
  for (let index = 0; index < 8; index++) {
    appendedAtUnixMillis = (appendedAtUnixMillis << 8n) | BigInt(bytes[offset + index])
  }
  offset += 8
  const hintCount = bytes[offset]
  offset += 1
  if (hintCount > PEERIT_INBOX_POINTER_MAX_HINTS_V1) {
    fail(`hintCount exceeds ${PEERIT_INBOX_POINTER_MAX_HINTS_V1}`)
  }
  const hints = []
  for (let index = 0; index < hintCount; index++) {
    hints.push(bytes.slice(offset, offset + 32))
    offset += 32
  }
  if (!isAllZero(bytes.subarray(offset))) {
    fail('pointer frame trailing bytes must be zero')
  }
  return Object.freeze({
    version: PEERIT_INBOX_POINTER_FRAME_VERSION_V1,
    boardSlug,
    recordCid,
    authorPubKey,
    sizeClass,
    leaseClass,
    appendedAtUnixMillis,
    hints: Object.freeze(hints)
  })
}

// Strict decode: ANY deviation from the v1 layout — byte type, magic, version,
// lengths, ranges, or a single nonzero trailing byte — is the SAME coded
// failure; poison frames never carry a distinguishable shape.
export function decodePeeritInboxPointerFrameV1 (frame) {
  try {
    return decodeFrame(frame)
  } catch (error) {
    if (error && error.code === 'PEERIT_INBOX_POINTER_FRAME_INVALID') throw error
    fail('pointer frame is not decodable')
  }
}
