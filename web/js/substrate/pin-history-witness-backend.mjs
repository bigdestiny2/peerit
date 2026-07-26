// Encrypted device-local continuity witness for Peerit's signed release-pin
// history. This store is deliberately append-only except for authenticated
// prefix compaction: it cannot manufacture a verifier brand or silently reset
// continuity after corruption.

import {
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  decodePeeritPinHistoryCheckpointV1,
  PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX,
  pinHistoryCheckpointHash,
  profilePinHash
} from './release-control-codec.mjs'
import {
  decodePeeritReleaseAuthorityTransitionV1,
  PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES,
  releaseAuthorityTransitionHash
} from './release-authority-transition.mjs'
import {
  getVerifiedPinHistoryTerminalSnapshotV1,
  verifyPeeritPinHistoryContinuationV1
} from './release-control-verifier.mjs'
import {
  asciiBytes,
  domainHash
} from './release-control-primitives.mjs'
import { PEERIT_PROFILE_ID } from './release-control-registry.mjs'

const DB_NAME = 'peerit-pin-history-witness-v1'
const DB_STORE = 'records'
const DOMAIN = 'peerit.pin-history-witness-record.v1'
const MAGIC = new TextEncoder().encode('PPHWIT01')
const RECORD_FIELDS = Object.freeze([
  'casVersion',
  'ciphertext',
  'generation',
  'iv',
  'recordKey',
  'version',
  'wrapKey'
])
const SCOPE_FIELDS = Object.freeze(['profileId', 'profileScopeHash'])
const APPEND_FIELDS = Object.freeze([
  'anchor',
  'authorityTransitions',
  'completeBundle',
  'verifiedResult'
])
const COMPACT_FIELDS = Object.freeze(['authenticatedBase'])
const PROFILE_SCOPE_DOMAIN = 'peerit.pin-history-witness-profile-scope.v1'
const FIXED_PROFILE_SCOPE_HASH = domainHash(
  PROFILE_SCOPE_DOMAIN, asciiBytes(PEERIT_PROFILE_ID))
const HEX64 = /^[0-9a-f]{64}$/
const MAX_U64 = (1n << 64n) - 1n
const MAX_PROFILE_ID_BYTES = 256
const MAX_SEGMENTS = 512
const MAX_TRANSITIONS_PER_SEGMENT = 256
const MAX_TOTAL_BYTES = 64 * 1024 * 1024

export class PeeritPinHistoryWitnessIntegrityError extends Error {
  constructor (message, code = 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT') {
    super(message)
    this.name = 'PeeritPinHistoryWitnessIntegrityError'
    this.code = code
  }
}

function fail (message, code) {
  throw new PeeritPinHistoryWitnessIntegrityError(message, code)
}

function runtimeCrypto (value) {
  const runtime = value || globalThis.crypto
  if (!runtime || !runtime.subtle || typeof runtime.getRandomValues !== 'function') {
    throw new Error('secure WebCrypto pin-history witness persistence is unavailable')
  }
  return runtime
}

function exactPlainValues (value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype &&
       Object.getPrototypeOf(value) !== null) ||
      Object.getOwnPropertySymbols(value).length !== 0 ||
      Object.getOwnPropertyNames(value).sort().join('\0') !== fields.join('\0')) {
    fail(`${label} must be an exact plain object`, 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  const output = Object.create(null)
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field)
    if (!descriptor || descriptor.enumerable !== true ||
        !Object.hasOwn(descriptor, 'value')) {
      fail(`${label}.${field} must be an enumerable data field`,
        'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
    }
    output[field] = descriptor.value
  }
  return output
}

function bytes (value, field, length = null, nonzero = false) {
  let output
  try {
    if (value instanceof Uint8Array) output = new Uint8Array(value)
    else if (value instanceof ArrayBuffer) output = new Uint8Array(value.slice(0))
    else if (ArrayBuffer.isView(value)) {
      output = new Uint8Array(new Uint8Array(
        value.buffer, value.byteOffset, value.byteLength))
    } else fail(`${field} must be bytes`, 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  } catch (error) {
    if (error instanceof PeeritPinHistoryWitnessIntegrityError) throw error
    fail(`${field} must be ordinary bytes`, 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  if (length != null && output.byteLength !== length) {
    fail(`${field} must be exactly ${length} bytes`,
      'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  if (nonzero && output.every(value => value === 0)) {
    fail(`${field} must be nonzero`, 'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  return output
}

function sameBytes (left, right) {
  if (left.byteLength !== right.byteLength) return false
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) return false
  }
  return true
}

function hex (value) {
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(`${field} must be an unsigned safe integer or bigint`)
    }
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    fail(`${field} is outside u64`)
  }
  return value
}

function canonicalProfileId (value) {
  if (typeof value !== 'string' || value.length < 1 || value.includes('\0') ||
      value !== value.normalize('NFC')) {
    fail('profileId must be bounded nonempty NFC text',
      'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  const encoded = new TextEncoder().encode(value)
  if (encoded.byteLength > MAX_PROFILE_ID_BYTES) {
    fail('profileId exceeds 256 UTF-8 bytes',
      'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  return { value, encoded }
}

function snapshotScope (input) {
  const source = exactPlainValues(input, SCOPE_FIELDS, 'pin-history profile scope')
  const profile = canonicalProfileId(source.profileId)
  const profileScopeHash = bytes(
    source.profileScopeHash, 'profileScopeHash', 32, true)
  if (profile.value !== PEERIT_PROFILE_ID ||
      !sameBytes(profileScopeHash, FIXED_PROFILE_SCOPE_HASH)) {
    fail('pin-history witness scope is fixed by this module and cannot be caller-selected',
      'PEERIT_PIN_HISTORY_WITNESS_SCOPE_MISMATCH')
  }
  return Object.freeze({
    profileId: profile.value,
    profileIdBytes: profile.encoded,
    profileScopeHash
  })
}

export function peeritPinHistoryProfileScopeV1 () {
  return {
    profileId: PEERIT_PROFILE_ID,
    profileScopeHash: new Uint8Array(FIXED_PROFILE_SCOPE_HASH)
  }
}

function denseBytesArray (input, field, maximum) {
  if (!Array.isArray(input) || Object.getOwnPropertySymbols(input).length !== 0 ||
      input.length > maximum) {
    fail(`${field} must be a bounded dense array`,
      'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  const names = Object.getOwnPropertyNames(input)
  if (names.length !== input.length + 1 || names[names.length - 1] !== 'length') {
    fail(`${field} must be dense and cannot contain extra properties`,
      'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  const output = new Array(input.length)
  for (let index = 0; index < input.length; index++) {
    if (names[index] !== String(index)) {
      fail(`${field} must be dense and canonical`,
        'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
    }
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index))
    if (!descriptor || descriptor.enumerable !== true ||
        !Object.hasOwn(descriptor, 'value')) {
      fail(`${field}[${index}] must be an enumerable data entry`,
        'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
    }
    output[index] = bytes(descriptor.value, `${field}[${index}]`)
  }
  return output
}

function snapshotBrand (value, field) {
  let snapshot
  try {
    snapshot = getVerifiedPinHistoryTerminalSnapshotV1(value)
  } catch {
    fail(`${field} must be a module-branded verified pin-history result`,
      'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
  }
  return Object.freeze({
    sequence: u64(snapshot.terminalSequence, `${field}.terminalSequence`),
    pinBytes: bytes(snapshot.terminalPinBytes, `${field}.terminalPinBytes`),
    pinHash: bytes(snapshot.terminalPinHash, `${field}.terminalPinHash`, 32, true),
    checkpointHash: bytes(
      snapshot.terminalCheckpointHash, `${field}.terminalCheckpointHash`, 32, true)
  })
}

function sameTerminal (left, right, includePinBytes = true) {
  return left.sequence === right.sequence &&
    sameBytes(left.pinHash, right.pinHash) &&
    sameBytes(left.checkpointHash, right.checkpointHash) &&
    (!includePinBytes || sameBytes(left.pinBytes, right.pinBytes))
}

function transitionKey (value) {
  return hex(releaseAuthorityTransitionHash(value))
}

function snapshotTransitions (values) {
  const output = denseBytesArray(
    values, 'authorityTransitions', MAX_TRANSITIONS_PER_SEGMENT)
  const seen = new Set()
  for (let index = 0; index < output.length; index++) {
    if (output[index].byteLength !== PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES) {
      fail(`authorityTransitions[${index}] has the wrong length`,
        'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
    }
    try { decodePeeritReleaseAuthorityTransitionV1(output[index]) } catch {
      fail(`authorityTransitions[${index}] is not canonical`,
        'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
    }
    const key = transitionKey(output[index])
    if (seen.has(key)) {
      fail('authorityTransitions contains a duplicate complete transition',
        'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
    }
    seen.add(key)
  }
  return output
}

function decodeBundle (value, field) {
  const completeBundle = bytes(value, field)
  if (completeBundle.byteLength < 1 ||
      completeBundle.byteLength > PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX) {
    fail(`${field} exceeds the canonical bundle bound`,
      'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  let bundle
  try { bundle = decodePeeritPinHistoryBundleV1(completeBundle) } catch {
    fail(`${field} is not a canonical pin-history bundle`,
      'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
  }
  if (bundle.pins.length < 1 || bundle.pins.length !== bundle.checkpoints.length) {
    fail(`${field} must contain paired nonempty pin and checkpoint arrays`)
  }
  return { bytes: completeBundle, bundle }
}

function analyzeSegment (anchor, completeBundle, authorityTransitions) {
  const decoded = decodeBundle(completeBundle, 'persisted continuation bundle')
  const transitionBytes = snapshotTransitions(authorityTransitions)
  if (transitionBytes.length > decoded.bundle.pins.length) {
    fail('continuation has more transitions than pins')
  }
  const transitions = new Map(transitionBytes.map(value => [transitionKey(value), value]))
  const consumed = new Set()
  const witnesses = []
  let previousSequence = anchor.sequence
  let previousPinBytes = bytes(anchor.pinBytes, 'anchor pin bytes')
  let previousPin
  try { previousPin = decodePeeritHiveRelayProfilePinV1(previousPinBytes) } catch {
    fail('authenticated anchor pin bytes are malformed')
  }
  if (previousPin.releaseSequence !== previousSequence ||
      !sameBytes(profilePinHash(previousPinBytes), anchor.pinHash)) {
    fail('authenticated anchor pin does not match its terminal floor')
  }
  let previousPinHash = bytes(anchor.pinHash, 'anchor pin hash', 32, true)
  let previousCheckpointHash = bytes(
    anchor.checkpointHash, 'anchor checkpoint hash', 32, true)

  for (let index = 0; index < decoded.bundle.pins.length; index++) {
    const pinBytes = bytes(decoded.bundle.pins[index], `pin[${index}]`)
    const checkpointBytes = bytes(
      decoded.bundle.checkpoints[index], `checkpoint[${index}]`)
    const pin = decodePeeritHiveRelayProfilePinV1(pinBytes)
    const checkpoint = decodePeeritPinHistoryCheckpointV1(checkpointBytes)
    const pinHash = profilePinHash(pinBytes)
    const checkpointHash = pinHistoryCheckpointHash(checkpointBytes)
    if (pin.releaseSequence !== previousSequence + 1n) {
      fail('persisted continuation contains a gap, replay, or rollback')
    }
    if (!sameBytes(pin.previousPinHash || new Uint8Array(), previousPinHash)) {
      fail('persisted continuation pin predecessor does not match its floor')
    }
    if (checkpoint.checkpointSequence !== pin.releaseSequence ||
        !sameBytes(checkpoint.pinHash, pinHash) ||
        !sameBytes(checkpoint.previousPinHash || new Uint8Array(), previousPinHash) ||
        !sameBytes(checkpoint.previousCheckpointHash || new Uint8Array(),
          previousCheckpointHash)) {
      fail('persisted continuation checkpoint does not match its pin and floors')
    }

    const sameAuthority =
      pin.releaseAuthoritySequence === previousPin.releaseAuthoritySequence &&
      sameBytes(pin.releaseAuthorityPublicKey, previousPin.releaseAuthorityPublicKey)
    if (sameAuthority) {
      if (pin.authorityTransitionHash != null) {
        fail('persisted continuation has an unexpected authority transition')
      }
    } else {
      if (pin.releaseAuthoritySequence !== previousPin.releaseAuthoritySequence + 1n ||
          pin.authorityTransitionHash == null) {
        fail('persisted continuation authority change is not exact +1')
      }
      const key = hex(pin.authorityTransitionHash)
      const exactTransition = transitions.get(key)
      if (!exactTransition) fail('persisted continuation is missing an authority transition')
      const transition = decodePeeritReleaseAuthorityTransitionV1(exactTransition)
      if (transition.previousSequence !== previousPin.releaseAuthoritySequence ||
          transition.nextSequence !== pin.releaseAuthoritySequence ||
          !sameBytes(transition.previousPublicKey,
            previousPin.releaseAuthorityPublicKey) ||
          !sameBytes(transition.nextPublicKey, pin.releaseAuthorityPublicKey) ||
          transition.validFromRelease !== pin.releaseSequence) {
        fail('persisted authority transition does not bind its adjacent pins')
      }
      consumed.add(key)
    }

    witnesses.push(Object.freeze({
      sequence: pin.releaseSequence,
      pinHash: new Uint8Array(pinHash),
      checkpointHash: new Uint8Array(checkpointHash)
    }))
    previousSequence = pin.releaseSequence
    previousPinBytes = pinBytes
    previousPin = pin
    previousPinHash = pinHash
    previousCheckpointHash = checkpointHash
  }
  if (consumed.size !== transitions.size) {
    fail('persisted continuation contains an unreferenced authority transition')
  }
  return Object.freeze({
    bundleBytes: decoded.bytes,
    transitionBytes,
    witnesses,
    terminal: Object.freeze({
      sequence: previousSequence,
      pinBytes: previousPinBytes,
      pinHash: previousPinHash,
      checkpointHash: previousCheckpointHash
    })
  })
}

function assertScopeMatchesPin (scope, pinBytes) {
  let pin
  try { pin = decodePeeritHiveRelayProfilePinV1(pinBytes) } catch {
    fail('witness base pin is not canonical')
  }
  if (pin.profileId !== scope.profileId) {
    fail('witness profile scope does not match its authenticated base pin',
      'PEERIT_PIN_HISTORY_WITNESS_SCOPE_MISMATCH')
  }
}

function cloneSegment (value) {
  return {
    bundleBytes: new Uint8Array(value.bundleBytes),
    authorityTransitions: value.authorityTransitions.map(entry => new Uint8Array(entry))
  }
}

function analyzeState (input, expectedScope) {
  if (!input || typeof input !== 'object') fail('pin-history witness state is missing')
  const scope = snapshotScope({
    profileId: input.profileId,
    profileScopeHash: input.profileScopeHash
  })
  if (scope.profileId !== expectedScope.profileId ||
      !sameBytes(scope.profileScopeHash, expectedScope.profileScopeHash)) {
    fail('encrypted pin-history witness was substituted across profile scopes')
  }
  const base = {
    sequence: u64(input.baseSequence, 'baseSequence'),
    pinBytes: bytes(input.basePinBytes, 'basePinBytes'),
    pinHash: bytes(input.basePinHash, 'basePinHash', 32, true),
    checkpointHash: bytes(
      input.baseCheckpointHash, 'baseCheckpointHash', 32, true)
  }
  assertScopeMatchesPin(scope, base.pinBytes)
  const basePin = decodePeeritHiveRelayProfilePinV1(base.pinBytes)
  if (basePin.releaseSequence !== base.sequence ||
      !sameBytes(profilePinHash(base.pinBytes), base.pinHash)) {
    fail('pin-history witness base floor is internally inconsistent')
  }
  const segments = denseBytesArrayLikeSegments(input.segments)
  if (segments.length > MAX_SEGMENTS) fail('pin-history witness segment count exceeds 512')
  let terminal = base
  const analyzed = []
  for (const segment of segments) {
    const exact = analyzeSegment(
      terminal, segment.bundleBytes, segment.authorityTransitions)
    analyzed.push({
      bundleBytes: exact.bundleBytes,
      authorityTransitions: exact.transitionBytes
    })
    terminal = exact.terminal
  }
  const claimed = {
    sequence: u64(input.terminalSequence, 'terminalSequence'),
    pinHash: bytes(input.terminalPinHash, 'terminalPinHash', 32, true),
    checkpointHash: bytes(
      input.terminalCheckpointHash, 'terminalCheckpointHash', 32, true)
  }
  if (!sameTerminal(terminal, claimed, false)) {
    fail('pin-history witness terminal floor is internally inconsistent')
  }
  return {
    profileId: scope.profileId,
    profileScopeHash: new Uint8Array(scope.profileScopeHash),
    baseSequence: base.sequence,
    basePinBytes: new Uint8Array(base.pinBytes),
    basePinHash: new Uint8Array(base.pinHash),
    baseCheckpointHash: new Uint8Array(base.checkpointHash),
    terminalSequence: terminal.sequence,
    terminalPinHash: new Uint8Array(terminal.pinHash),
    terminalCheckpointHash: new Uint8Array(terminal.checkpointHash),
    segments: analyzed.map(cloneSegment)
  }
}

function denseBytesArrayLikeSegments (value) {
  if (!Array.isArray(value) || value.length > MAX_SEGMENTS) {
    fail('pin-history witness segments must be a bounded array')
  }
  const output = []
  for (let index = 0; index < value.length; index++) {
    if (!Object.hasOwn(value, index)) fail('pin-history witness segments are sparse')
    const segment = value[index]
    if (!segment || typeof segment !== 'object') fail('pin-history witness segment is malformed')
    output.push({
      bundleBytes: bytes(segment.bundleBytes, `segments[${index}].bundleBytes`),
      authorityTransitions: denseBytesArray(
        segment.authorityTransitions,
        `segments[${index}].authorityTransitions`,
        MAX_TRANSITIONS_PER_SEGMENT)
    })
  }
  return output
}

class Writer {
  constructor () { this.parts = []; this.length = 0 }

  push (value) {
    value = bytes(value, 'encoded witness part')
    this.parts.push(value)
    this.length += value.byteLength
    if (this.length > MAX_TOTAL_BYTES) fail('pin-history witness exceeds 64 MiB')
  }

  u8 (value) { this.push(Uint8Array.of(value)) }

  u16 (value) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) fail('u16 overflow')
    this.push(Uint8Array.of(value >>> 8, value))
  }

  u32 (value) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail('u32 overflow')
    this.push(Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value))
  }

  u64 (value) {
    value = u64(value, 'encoded u64')
    const output = new Uint8Array(8)
    for (let index = 7; index >= 0; index--) {
      output[index] = Number(value & 0xffn)
      value >>= 8n
    }
    this.push(output)
  }

  variable16 (value) { this.u16(value.byteLength); this.push(value) }

  variable32 (value) { this.u32(value.byteLength); this.push(value) }

  finish () {
    const output = new Uint8Array(this.length)
    let offset = 0
    for (const part of this.parts) { output.set(part, offset); offset += part.byteLength }
    return output
  }
}

class Reader {
  constructor (value) { this.value = value; this.offset = 0 }

  take (length, field) {
    if (!Number.isSafeInteger(length) || length < 0 ||
        this.offset + length > this.value.byteLength) {
      fail(`truncated pin-history witness ${field}`)
    }
    const output = this.value.slice(this.offset, this.offset + length)
    this.offset += length
    return output
  }

  u8 (field) { return this.take(1, field)[0] }

  u16 (field) {
    const value = this.take(2, field)
    return value[0] * 0x100 + value[1]
  }

  u32 (field) {
    const value = this.take(4, field)
    return value[0] * 0x1000000 + value[1] * 0x10000 +
      value[2] * 0x100 + value[3]
  }

  u64 (field) {
    let output = 0n
    for (const byte of this.take(8, field)) output = (output << 8n) | BigInt(byte)
    return output
  }
}

function encodeState (input, expectedScope) {
  const state = analyzeState(input, expectedScope)
  const profileId = new TextEncoder().encode(state.profileId)
  const writer = new Writer()
  writer.push(MAGIC)
  writer.u8(1)
  writer.variable16(profileId)
  writer.push(state.profileScopeHash)
  writer.u64(state.baseSequence)
  writer.variable32(state.basePinBytes)
  writer.push(state.basePinHash)
  writer.push(state.baseCheckpointHash)
  writer.u64(state.terminalSequence)
  writer.push(state.terminalPinHash)
  writer.push(state.terminalCheckpointHash)
  writer.u16(state.segments.length)
  for (const segment of state.segments) {
    writer.variable32(segment.bundleBytes)
    writer.u16(segment.authorityTransitions.length)
    for (const transition of segment.authorityTransitions) writer.variable16(transition)
  }
  return writer.finish()
}

function decodeState (input, expectedScope) {
  const encoded = bytes(input, 'pin-history witness plaintext')
  if (encoded.byteLength < 1 || encoded.byteLength > MAX_TOTAL_BYTES) {
    fail('pin-history witness plaintext length is invalid')
  }
  const reader = new Reader(encoded)
  if (!sameBytes(reader.take(8, 'magic'), MAGIC) || reader.u8('version') !== 1) {
    fail('pin-history witness plaintext header is invalid')
  }
  const profileIdLength = reader.u16('profileId length')
  if (profileIdLength < 1 || profileIdLength > MAX_PROFILE_ID_BYTES) {
    fail('pin-history witness profileId length is invalid')
  }
  let profileId
  try {
    profileId = new TextDecoder('utf-8', { fatal: true }).decode(
      reader.take(profileIdLength, 'profileId'))
  } catch { fail('pin-history witness profileId is not UTF-8') }
  const state = {
    profileId,
    profileScopeHash: reader.take(32, 'profileScopeHash'),
    baseSequence: reader.u64('baseSequence'),
    basePinBytes: null,
    basePinHash: null,
    baseCheckpointHash: null,
    terminalSequence: null,
    terminalPinHash: null,
    terminalCheckpointHash: null,
    segments: []
  }
  const basePinLength = reader.u32('basePinBytes length')
  if (basePinLength < 1 || basePinLength > 8192) {
    fail('pin-history witness base pin length is invalid')
  }
  state.basePinBytes = reader.take(basePinLength, 'basePinBytes')
  state.basePinHash = reader.take(32, 'basePinHash')
  state.baseCheckpointHash = reader.take(32, 'baseCheckpointHash')
  state.terminalSequence = reader.u64('terminalSequence')
  state.terminalPinHash = reader.take(32, 'terminalPinHash')
  state.terminalCheckpointHash = reader.take(32, 'terminalCheckpointHash')
  const segmentCount = reader.u16('segment count')
  if (segmentCount > MAX_SEGMENTS) fail('pin-history witness segment count exceeds 512')
  for (let index = 0; index < segmentCount; index++) {
    const bundleLength = reader.u32(`segments[${index}] bundle length`)
    if (bundleLength < 1 || bundleLength > PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX) {
      fail(`segments[${index}] bundle length is invalid`)
    }
    const bundleBytes = reader.take(bundleLength, `segments[${index}] bundle`)
    const transitionCount = reader.u16(`segments[${index}] transition count`)
    if (transitionCount > MAX_TRANSITIONS_PER_SEGMENT) {
      fail(`segments[${index}] transition count exceeds 256`)
    }
    const authorityTransitions = []
    for (let transitionIndex = 0; transitionIndex < transitionCount; transitionIndex++) {
      const length = reader.u16(
        `segments[${index}] transitions[${transitionIndex}] length`)
      if (length !== PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES) {
        fail(`segments[${index}] transition length is invalid`)
      }
      authorityTransitions.push(reader.take(
        length, `segments[${index}] transitions[${transitionIndex}]`))
    }
    state.segments.push({ bundleBytes, authorityTransitions })
  }
  if (reader.offset !== encoded.byteLength) {
    fail('pin-history witness plaintext has trailing bytes')
  }
  const validated = analyzeState(state, expectedScope)
  const canonical = encodeState(validated, expectedScope)
  if (!sameBytes(canonical, encoded)) fail('pin-history witness plaintext is noncanonical')
  return validated
}

function assertWrapKey (key) {
  if (!key || key.type !== 'secret' || key.extractable !== false ||
      !key.algorithm || key.algorithm.name !== 'AES-GCM' ||
      key.algorithm.length !== 256 || !Array.isArray(key.usages) ||
      key.usages.length !== 2 || !key.usages.includes('encrypt') ||
      !key.usages.includes('decrypt')) {
    fail('pin-history witness wrapping key is invalid or extractable')
  }
  return key
}

function exactRecord (input, expectedRecordKey) {
  const record = exactPlainValues(input, RECORD_FIELDS, 'encrypted witness record')
  if (record.version !== 1 || record.recordKey !== expectedRecordKey ||
      typeof record.generation !== 'string' || !HEX64.test(record.generation) ||
      !Number.isSafeInteger(record.casVersion) || record.casVersion < 1) {
    fail('encrypted pin-history witness header is malformed')
  }
  assertWrapKey(record.wrapKey)
  record.iv = bytes(record.iv, 'encrypted witness iv')
  record.ciphertext = bytes(record.ciphertext, 'encrypted witness ciphertext')
  if (record.iv.byteLength !== 12 || record.ciphertext.byteLength < 17 ||
      record.ciphertext.byteLength > MAX_TOTAL_BYTES + 16) {
    fail('encrypted pin-history witness ciphertext is malformed')
  }
  return record
}

function aad (record) {
  return new TextEncoder().encode(JSON.stringify([
    DOMAIN,
    record.recordKey,
    record.generation,
    record.casVersion
  ]))
}

async function recordKeyFor (runtime, scope) {
  const profile = new TextEncoder().encode(scope.profileId)
  const material = new Uint8Array(
    DOMAIN.length + 1 + 2 + profile.byteLength + 32)
  let offset = 0
  material.set(new TextEncoder().encode(DOMAIN), offset)
  offset += DOMAIN.length
  material[offset++] = 0
  material[offset++] = profile.byteLength >>> 8
  material[offset++] = profile.byteLength
  material.set(profile, offset)
  offset += profile.byteLength
  material.set(scope.profileScopeHash, offset)
  const digest = new Uint8Array(await runtime.subtle.digest('SHA-256', material))
  return `pin-history-witness:v1:${hex(digest)}`
}

async function seal (runtime, recordKey, casVersion, state, scope, wrapKey = null) {
  const clear = encodeState(state, scope)
  const record = {
    version: 1,
    recordKey,
    generation: hex(runtime.getRandomValues(new Uint8Array(32))),
    casVersion,
    wrapKey: wrapKey || await runtime.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    iv: runtime.getRandomValues(new Uint8Array(12)),
    ciphertext: null
  }
  assertWrapKey(record.wrapKey)
  try {
    record.ciphertext = new Uint8Array(await runtime.subtle.encrypt({
      name: 'AES-GCM',
      iv: record.iv,
      additionalData: aad(record),
      tagLength: 128
    }, record.wrapKey, clear))
  } finally { clear.fill(0) }
  return exactRecord(record, recordKey)
}

async function openRecord (runtime, input, recordKey, scope) {
  const record = exactRecord(input, recordKey)
  let clear
  try {
    clear = new Uint8Array(await runtime.subtle.decrypt({
      name: 'AES-GCM',
      iv: record.iv,
      additionalData: aad(record),
      tagLength: 128
    }, record.wrapKey, record.ciphertext))
  } catch { fail('pin-history witness record authentication failed') }
  try { return decodeState(clear, scope) } finally { clear.fill(0) }
}

function clone (value) {
  return typeof structuredClone === 'function' ? structuredClone(value) : value
}

function indexedDbKv (idb = globalThis.indexedDB) {
  if (!idb) return null
  const databaseExists = async () => {
    if (typeof idb.databases !== 'function') return null
    const databases = await idb.databases()
    return databases.some(entry => entry && entry.name === DB_NAME)
  }
  const open = () => new Promise((resolve, reject) => {
    const request = idb.open(DB_NAME, 1)
    let settled = false
    request.onupgradeneeded = () => {
      if (settled) {
        request.transaction.abort()
        return
      }
      if (!request.result.objectStoreNames.contains(DB_STORE)) {
        request.result.createObjectStore(DB_STORE)
      }
    }
    request.onsuccess = () => {
      if (settled) {
        request.result.close()
        return
      }
      if (!request.result.objectStoreNames.contains(DB_STORE)) {
        settled = true
        request.result.close()
        return reject(new Error('pin-history witness object store is missing'))
      }
      settled = true
      resolve(request.result)
    }
    request.onerror = () => {
      if (settled) return
      settled = true
      reject(request.error || new Error('pin-history witness IndexedDB open failed'))
    }
    request.onblocked = () => {
      if (settled) return
      settled = true
      reject(new Error('pin-history witness IndexedDB open was blocked'))
    }
  })
  const withStore = async (mode, operation) => {
    const db = await open()
    try {
      return await new Promise((resolve, reject) => {
        const transaction = db.transaction(DB_STORE, mode)
        const store = transaction.objectStore(DB_STORE)
        let result
        operation(store, value => { result = value })
        transaction.oncomplete = () => resolve(result)
        transaction.onabort = () => reject(
          transaction.error || new Error('pin-history witness transaction aborted'))
        transaction.onerror = () => {}
      })
    } finally { db.close() }
  }
  return {
    async get (key) {
      const exists = await databaseExists()
      if (exists === false) return null
      return withStore('readonly', (store, done) => {
        const request = store.get(key)
        request.onsuccess = () => done(
          request.result == null ? null : request.result)
      })
    },
    putIfAbsent: (key, value) => withStore('readwrite', (store, done) => {
      const request = store.get(key)
      request.onsuccess = () => {
        if (request.result != null) {
          return done({ inserted: false, value: request.result })
        }
        store.put(value, key)
        done({ inserted: true, value })
      }
    }),
    compareAndSwap: (key, generation, casVersion, value) =>
      withStore('readwrite', (store, done) => {
        const request = store.get(key)
        request.onsuccess = () => {
          const current = request.result == null ? null : request.result
          if (!current || current.generation !== generation ||
              current.casVersion !== casVersion) {
            return done({ swapped: false, value: current })
          }
          store.put(value, key)
          done({ swapped: true, value })
        }
      })
  }
}

export function memoryPinHistoryWitnessKv () {
  const records = new Map()
  return {
    records,
    async get (key) { return records.has(key) ? clone(records.get(key)) : null },
    async putIfAbsent (key, value) {
      if (records.has(key)) {
        return { inserted: false, value: clone(records.get(key)) }
      }
      records.set(key, clone(value))
      return { inserted: true, value: clone(value) }
    },
    async compareAndSwap (key, generation, casVersion, value) {
      const current = records.get(key)
      if (!current || current.generation !== generation ||
          current.casVersion !== casVersion) {
        return {
          swapped: false,
          value: current == null ? null : clone(current)
        }
      }
      records.set(key, clone(value))
      return { swapped: true, value: clone(value) }
    }
  }
}

function publicSummary (version, state) {
  if (state == null) return Object.freeze({ version: 0, value: null })
  const pinHash = new Uint8Array(state.terminalPinHash)
  const checkpointHash = new Uint8Array(state.terminalCheckpointHash)
  return Object.freeze({
    version,
    value: Object.freeze({
      baseSequence: state.baseSequence,
      terminalSequence: state.terminalSequence,
      segmentCount: state.segments.length,
      get terminalPinHash () { return new Uint8Array(pinHash) },
      get terminalCheckpointHash () { return new Uint8Array(checkpointHash) }
    })
  })
}

function stateTerminal (state) {
  let pinBytes = state.basePinBytes
  if (state.segments.length > 0) {
    const last = decodePeeritPinHistoryBundleV1(
      state.segments[state.segments.length - 1].bundleBytes)
    pinBytes = last.pins[last.pins.length - 1]
  }
  return {
    sequence: state.terminalSequence,
    pinBytes: new Uint8Array(pinBytes),
    pinHash: new Uint8Array(state.terminalPinHash),
    checkpointHash: new Uint8Array(state.terminalCheckpointHash)
  }
}

export function createPeeritPinHistoryWitnessBackend (options = {}) {
  const runtime = runtimeCrypto(options.crypto)
  const verificationCrypto = options.verifierCrypto || null
  const kv = options.kv === undefined ? indexedDbKv(options.indexedDB) : options.kv
  if (!kv || typeof kv.get !== 'function' ||
      typeof kv.putIfAbsent !== 'function' ||
      typeof kv.compareAndSwap !== 'function') {
    throw new Error('atomic pin-history witness persistence is unavailable')
  }
  const observed = new Map()

  function observe (recordKey, record, state) {
    const prior = observed.get(recordKey)
    if (prior) {
      const sameCasChanged = record.casVersion === prior.casVersion &&
        (record.generation !== prior.generation ||
         state.terminalSequence !== prior.terminalSequence ||
         !sameBytes(state.terminalPinHash, prior.terminalPinHash) ||
         !sameBytes(state.terminalCheckpointHash,
           prior.terminalCheckpointHash))
      if (record.casVersion < prior.casVersion ||
          state.terminalSequence < prior.terminalSequence ||
          sameCasChanged ||
          (state.terminalSequence === prior.terminalSequence &&
           (!sameBytes(state.terminalPinHash, prior.terminalPinHash) ||
            !sameBytes(state.terminalCheckpointHash,
              prior.terminalCheckpointHash)))) {
        fail('pin-history witness rolled back or forked during this runtime',
          'PEERIT_PIN_HISTORY_WITNESS_ROLLBACK')
      }
    }
    observed.set(recordKey, {
      casVersion: record.casVersion,
      generation: record.generation,
      terminalSequence: state.terminalSequence,
      terminalPinHash: new Uint8Array(state.terminalPinHash),
      terminalCheckpointHash: new Uint8Array(state.terminalCheckpointHash)
    })
  }

  async function load (scope) {
    const recordKey = await recordKeyFor(runtime, scope)
    const input = await kv.get(recordKey)
    if (!input) {
      if (observed.has(recordKey)) {
        fail('an observed pin-history witness disappeared without authorization',
          'PEERIT_PIN_HISTORY_WITNESS_SILENT_RESET')
      }
      return { recordKey, record: null, state: null }
    }
    const record = exactRecord(input, recordKey)
    const state = await openRecord(runtime, record, recordKey, scope)
    observe(recordKey, record, state)
    return { recordKey, record, state }
  }

  async function commit (scope, loaded, expectedVersion, state) {
    if (expectedVersion === 0) {
      if (loaded.record != null) return false
      const candidate = await seal(runtime, loaded.recordKey, 1, state, scope)
      const result = await kv.putIfAbsent(loaded.recordKey, candidate)
      if (result.inserted) {
        const committedState = await openRecord(
          runtime, result.value, loaded.recordKey, scope)
        observe(loaded.recordKey, exactRecord(result.value, loaded.recordKey),
          committedState)
        return true
      }
      const currentRecord = exactRecord(result.value, loaded.recordKey)
      const currentState = await openRecord(
        runtime, currentRecord, loaded.recordKey, scope)
      observe(loaded.recordKey, currentRecord, currentState)
      return false
    }
    if (!loaded.record || loaded.record.casVersion !== expectedVersion) return false
    if (expectedVersion >= Number.MAX_SAFE_INTEGER) {
      fail('pin-history witness CAS version is exhausted')
    }
    const candidate = await seal(
      runtime, loaded.recordKey, expectedVersion + 1, state, scope,
      loaded.record.wrapKey)
    const result = await kv.compareAndSwap(
      loaded.recordKey, loaded.record.generation, expectedVersion, candidate)
    if (result.swapped) {
      const committedRecord = exactRecord(result.value, loaded.recordKey)
      const committedState = await openRecord(
        runtime, committedRecord, loaded.recordKey, scope)
      observe(loaded.recordKey, committedRecord, committedState)
      return true
    }
    if (result.value != null) {
      const currentRecord = exactRecord(result.value, loaded.recordKey)
      const currentState = await openRecord(
        runtime, currentRecord, loaded.recordKey, scope)
      observe(loaded.recordKey, currentRecord, currentState)
    }
    return false
  }

  return Object.freeze({
    async read (profileScope) {
      const scope = snapshotScope(profileScope)
      const loaded = await load(scope)
      return publicSummary(
        loaded.record == null ? 0 : loaded.record.casVersion, loaded.state)
    },

    async initialize (profileScope, expectedVersion, authenticatedBase) {
      const scope = snapshotScope(profileScope)
      if (expectedVersion !== 0) {
        fail('pin-history witness initialization requires expected version zero',
          'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
      }
      const base = snapshotBrand(authenticatedBase, 'authenticatedBase')
      assertScopeMatchesPin(scope, base.pinBytes)
      const loaded = await load(scope)
      if (loaded.record != null) return false
      const state = {
        profileId: scope.profileId,
        profileScopeHash: scope.profileScopeHash,
        baseSequence: base.sequence,
        basePinBytes: base.pinBytes,
        basePinHash: base.pinHash,
        baseCheckpointHash: base.checkpointHash,
        terminalSequence: base.sequence,
        terminalPinHash: base.pinHash,
        terminalCheckpointHash: base.checkpointHash,
        segments: []
      }
      analyzeState(state, scope)
      return commit(scope, loaded, 0, state)
    },

    async append (profileScope, expectedVersion, input) {
      const scope = snapshotScope(profileScope)
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
        fail('expected pin-history witness version is invalid',
          'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
      }
      const request = exactPlainValues(
        input, APPEND_FIELDS, 'pin-history witness append')
      const anchor = snapshotBrand(request.anchor, 'append.anchor')
      const verified = snapshotBrand(
        request.verifiedResult, 'append.verifiedResult')
      const authorityTransitions = snapshotTransitions(request.authorityTransitions)
      const decoded = decodeBundle(request.completeBundle, 'completeBundle')
      const resultDescriptor = Object.getOwnPropertyDescriptor(
        request.verifiedResult, 'authorityTransitionCount')
      if (!resultDescriptor || !Object.hasOwn(resultDescriptor, 'value') ||
          resultDescriptor.value !== authorityTransitions.length) {
        fail('verifiedResult is not the exact continuation result for its transition set',
          'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
      }
      let verifiedBytes
      try { verifiedBytes = bytes(request.verifiedResult.bytes, 'verifiedResult.bytes') } catch {
        fail('verifiedResult does not expose exact authenticated continuation bytes',
          'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
      }
      if (!sameBytes(decoded.bytes, verifiedBytes)) {
        fail('completeBundle does not match the branded verifiedResult',
          'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
      }
      let segment
      try {
        segment = analyzeSegment(anchor, decoded.bytes, authorityTransitions)
      } catch {
        fail('completeBundle is not bound to the exact supplied authority transition bytes',
          'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
      }
      if (!sameTerminal(segment.terminal, verified)) {
        fail('branded verifiedResult terminal does not match completeBundle',
          'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
      }
      let rebound
      try {
        rebound = await verifyPeeritPinHistoryContinuationV1(decoded.bytes, {
          crypto: verificationCrypto,
          anchor: request.anchor,
          authorityTransitions
        })
      } catch {
        fail('completeBundle and exact authority transition bytes did not reverify together',
          'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
      }
      if (!sameTerminal(
        snapshotBrand(rebound, 'append cryptographic re-verification'), verified)) {
        fail('append cryptographic re-verification changed its terminal',
          'PEERIT_PIN_HISTORY_WITNESS_UNVERIFIED')
      }
      assertScopeMatchesPin(scope, anchor.pinBytes)

      const loaded = await load(scope)
      if ((loaded.record == null ? 0 : loaded.record.casVersion) !== expectedVersion) {
        return false
      }
      let state
      if (!loaded.state) {
        if (expectedVersion !== 0) return false
        state = {
          profileId: scope.profileId,
          profileScopeHash: scope.profileScopeHash,
          baseSequence: anchor.sequence,
          basePinBytes: anchor.pinBytes,
          basePinHash: anchor.pinHash,
          baseCheckpointHash: anchor.checkpointHash,
          terminalSequence: verified.sequence,
          terminalPinHash: verified.pinHash,
          terminalCheckpointHash: verified.checkpointHash,
          segments: [{
            bundleBytes: segment.bundleBytes,
            authorityTransitions: segment.transitionBytes
          }]
        }
      } else {
        const currentTerminal = stateTerminal(loaded.state)
        if (!sameTerminal(currentTerminal, anchor)) {
          fail('append anchor is behind, forked from, or ahead of the witnessed terminal',
            'PEERIT_PIN_HISTORY_WITNESS_ROLLBACK')
        }
        if (loaded.state.segments.length >= MAX_SEGMENTS) {
          fail('pin-history witness requires authenticated base compaction before append',
            'PEERIT_PIN_HISTORY_WITNESS_COMPACTION_REQUIRED')
        }
        state = {
          ...loaded.state,
          terminalSequence: verified.sequence,
          terminalPinHash: verified.pinHash,
          terminalCheckpointHash: verified.checkpointHash,
          segments: [...loaded.state.segments, {
            bundleBytes: segment.bundleBytes,
            authorityTransitions: segment.transitionBytes
          }]
        }
      }
      analyzeState(state, scope)
      return commit(scope, loaded, expectedVersion, state)
    },

    async rehydrate (profileScope, authenticatedBase, verifierCrypto) {
      const scope = snapshotScope(profileScope)
      const base = snapshotBrand(authenticatedBase, 'authenticatedBase')
      assertScopeMatchesPin(scope, base.pinBytes)
      const loaded = await load(scope)
      if (!loaded.state) return authenticatedBase
      if (base.sequence < loaded.state.baseSequence) {
        fail('authenticated app base is older than the compacted witness base',
          'PEERIT_PIN_HISTORY_WITNESS_BASE_TOO_OLD')
      }
      if (base.sequence > loaded.state.terminalSequence) {
        fail('authenticated app base is newer than the witness; an exact bridging continuation is required',
          'PEERIT_PIN_HISTORY_WITNESS_BASE_AHEAD')
      }

      const boundaries = [{
        terminal: {
          sequence: loaded.state.baseSequence,
          pinBytes: loaded.state.basePinBytes,
          pinHash: loaded.state.basePinHash,
          checkpointHash: loaded.state.baseCheckpointHash
        },
        nextSegment: 0
      }]
      let boundaryAnchor = boundaries[0].terminal
      for (let index = 0; index < loaded.state.segments.length; index++) {
        const analyzed = analyzeSegment(
          boundaryAnchor,
          loaded.state.segments[index].bundleBytes,
          loaded.state.segments[index].authorityTransitions)
        boundaries.push({ terminal: analyzed.terminal, nextSegment: index + 1 })
        boundaryAnchor = analyzed.terminal
      }
      const boundary = boundaries.find(value =>
        value.terminal.sequence === base.sequence)
      if (!boundary || !sameTerminal(boundary.terminal, base)) {
        fail('authenticated app base conflicts with or falls inside a witness segment',
          'PEERIT_PIN_HISTORY_WITNESS_BASE_FORK')
      }

      let current = authenticatedBase
      let currentAnchor = base
      for (let index = boundary.nextSegment;
        index < loaded.state.segments.length; index++) {
        const segment = loaded.state.segments[index]
        const analyzed = analyzeSegment(
          currentAnchor, segment.bundleBytes, segment.authorityTransitions)
        const witnessedPinHashes = new Map()
        const witnessedCheckpointHashes = new Map()
        for (const witness of analyzed.witnesses) {
          witnessedPinHashes.set(witness.sequence.toString(), witness.pinHash)
          witnessedCheckpointHashes.set(
            witness.sequence.toString(), witness.checkpointHash)
        }
        current = await verifyPeeritPinHistoryContinuationV1(
          segment.bundleBytes, {
            crypto: verifierCrypto || verificationCrypto,
            anchor: current,
            authorityTransitions: segment.authorityTransitions,
            witnessedPinHashes,
            witnessedCheckpointHashes
          })
        currentAnchor = snapshotBrand(current, 'rehydrated continuation')
        if (!sameTerminal(currentAnchor, analyzed.terminal)) {
          fail('rehydrated continuation does not restore its witnessed floor')
        }
      }
      if (!sameTerminal(currentAnchor, stateTerminal(loaded.state))) {
        fail('rehydrated terminal does not match the durable witness floor')
      }
      return current
    },

    async compact (profileScope, expectedVersion, input) {
      const scope = snapshotScope(profileScope)
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
        fail('expected compaction version must be positive',
          'PEERIT_PIN_HISTORY_WITNESS_BAD_INPUT')
      }
      const request = exactPlainValues(
        input, COMPACT_FIELDS, 'pin-history witness compaction')
      const authenticatedBase = snapshotBrand(
        request.authenticatedBase, 'compact.authenticatedBase')
      assertScopeMatchesPin(scope, authenticatedBase.pinBytes)
      const loaded = await load(scope)
      if (!loaded.record || loaded.record.casVersion !== expectedVersion) return false
      if (authenticatedBase.sequence <= loaded.state.baseSequence) {
        fail('compaction base must advance beyond the current authenticated base',
          'PEERIT_PIN_HISTORY_WITNESS_BAD_COMPACTION')
      }

      let anchor = {
        sequence: loaded.state.baseSequence,
        pinBytes: loaded.state.basePinBytes,
        pinHash: loaded.state.basePinHash,
        checkpointHash: loaded.state.baseCheckpointHash
      }
      let matched = -1
      for (let index = 0; index < loaded.state.segments.length; index++) {
        const analyzed = analyzeSegment(
          anchor,
          loaded.state.segments[index].bundleBytes,
          loaded.state.segments[index].authorityTransitions)
        anchor = analyzed.terminal
        if (anchor.sequence === authenticatedBase.sequence) {
          if (!sameTerminal(anchor, authenticatedBase)) {
            fail('authenticated compaction base forks from the witnessed boundary',
              'PEERIT_PIN_HISTORY_WITNESS_BAD_COMPACTION')
          }
          matched = index
          break
        }
      }
      if (matched < 0) {
        fail('compaction is allowed only at an authenticated segment boundary',
          'PEERIT_PIN_HISTORY_WITNESS_BAD_COMPACTION')
      }
      const state = {
        ...loaded.state,
        baseSequence: authenticatedBase.sequence,
        basePinBytes: authenticatedBase.pinBytes,
        basePinHash: authenticatedBase.pinHash,
        baseCheckpointHash: authenticatedBase.checkpointHash,
        segments: loaded.state.segments.slice(matched + 1)
      }
      analyzeState(state, scope)
      return commit(scope, loaded, expectedVersion, state)
    }
  })
}

export const PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS = Object.freeze({
  moduleFixedProfileScope: true,
  encryptedAtRest: true,
  nonExtractablePerStoreKey: true,
  atomicCrossContextCas: true,
  exactContinuationBytesPersisted: true,
  exactAuthorityTransitionBytesReverifiedBeforePersist: true,
  authenticatedBaseCanInitializeImmediately: true,
  brandedVerificationRequiredBeforePersist: true,
  witnessedPinAndCheckpointFloorsRehydrated: true,
  authenticatedBoundaryCompactionOnly: true,
  freshReadAvoidsIndexedDbCreationWhenEnumerationAvailable: true,
  blockedIndexedDbOpenIsAbortedOrClosed: true,
  inProcessWholeRecordRollbackDetected: true,
  corruptionAndObservedSilentResetFailClosed: true,
  portableExternalRollbackRecoveryReady: false,
  postEvictionContinuityRecoveryReady: false
})
