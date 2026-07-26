import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  bytesEqual,
  domainLengthHash,
  failReleaseControl,
  fixedBytesValue,
  isAllZero
} from './release-control-primitives.mjs'
import {
  PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX,
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryBundleV1,
  pinHistoryCheckpointHash,
  profilePinHash
} from './release-control-codec.mjs'
import {
  PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES,
  decodePeeritReleaseAuthorityTransitionV1,
  releaseAuthorityTransitionHash
} from './release-authority-transition.mjs'
import {
  canonicalExpectedPinProjection,
  getVerifiedPinHistoryTerminalSnapshotV1,
  verifyPeeritPinHistoryBundleV1,
  verifyPeeritPinHistoryContinuationV1
} from './release-control-verifier.mjs'

export const PEERIT_PORTABLE_PIN_HISTORY_MAGIC_V1 = 'PEERITPH'
export const PEERIT_PORTABLE_PIN_HISTORY_HASH_DOMAIN_V1 =
  'peerit.portable-pin-history.v1'
export const PEERIT_PORTABLE_PIN_HISTORY_TRANSITIONS_HASH_DOMAIN_V1 =
  'peerit.portable-pin-history-transitions.v1'
export const PEERIT_PORTABLE_PIN_HISTORY_MAX_TRANSITIONS_V1 = 256

const RECORD_FIELDS = Object.freeze([
  'version',
  'trustRootPublicKey',
  'genesisPinHash',
  'bundleBytes',
  'authorityTransitions',
  'terminalSequence',
  'terminalPinHash',
  'terminalCheckpointHash'
])
const VERIFIED = new WeakMap()

function exactDataObject (input, fields, name) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype &&
       Object.getPrototypeOf(input) !== null)) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', `${name} must be a plain data object`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(input)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string') ||
      fields.some(field => !Object.hasOwn(descriptors, field))) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', `${name} fields are missing or unexpected`)
  }
  const output = Object.create(null)
  for (const field of fields) {
    const descriptor = descriptors[field]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      failReleaseControl('BAD_PORTABLE_PIN_HISTORY', `${name}.${field} must be an enumerable data field`)
    }
    output[field] = descriptor.value
  }
  return output
}
function rootSnapshot (input, name = 'pin-history trust root') {
  const value = exactDataObject(input, ['publicKey', 'genesisPinHash'], name)
  const publicKey = new Uint8Array(fixedBytesValue(value.publicKey, 32, `${name}.publicKey`))
  const genesisPinHash = new Uint8Array(fixedBytesValue(
    value.genesisPinHash, 32, `${name}.genesisPinHash`))
  if (isAllZero(publicKey) || isAllZero(genesisPinHash)) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY_ROOT', `${name} values must be nonzero`)
  }
  return { publicKey, genesisPinHash }
}

function bundleSnapshot (input) {
  const bytes = new Uint8Array(asBytes(input, 'portable pin-history bundle'))
  if (bytes.byteLength < 1 || bytes.byteLength > PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', 'portable pin-history bundle size is invalid')
  }
  decodePeeritPinHistoryBundleV1(bytes)
  return bytes
}

function transitionsSnapshot (input) {
  if (!Array.isArray(input) || input.length > PEERIT_PORTABLE_PIN_HISTORY_MAX_TRANSITIONS_V1) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY_TRANSITIONS',
      `authorityTransitions must contain 0..${PEERIT_PORTABLE_PIN_HISTORY_MAX_TRANSITIONS_V1} records`)
  }
  const output = []
  const hashes = new Set()
  for (let index = 0; index < input.length; index++) {
    const bytes = new Uint8Array(fixedBytesValue(input[index],
      PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES, `authorityTransitions[${index}]`))
    decodePeeritReleaseAuthorityTransitionV1(bytes)
    const key = hex(releaseAuthorityTransitionHash(bytes))
    if (hashes.has(key)) {
      failReleaseControl('BAD_PORTABLE_PIN_HISTORY_TRANSITIONS',
        'authorityTransitions contains a duplicate complete transition')
    }
    hashes.add(key)
    output.push(bytes)
  }
  return output
}

function terminalFromBundle (bundleBytes) {
  const bundle = decodePeeritPinHistoryBundleV1(bundleBytes)
  const index = bundle.pins.length - 1
  const pin = decodePeeritHiveRelayProfilePinV1(bundle.pins[index])
  return {
    bundle,
    terminalSequence: pin.releaseSequence,
    terminalPinHash: profilePinHash(bundle.pins[index]),
    terminalCheckpointHash: pinHistoryCheckpointHash(bundle.checkpoints[index])
  }
}

function canonicalRecord (input) {
  const value = exactDataObject(input, RECORD_FIELDS, 'PeeritPortablePinHistoryV1')
  if (value.version !== 1) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', 'PeeritPortablePinHistoryV1 version must be 1')
  }
  const root = rootSnapshot({
    publicKey: value.trustRootPublicKey,
    genesisPinHash: value.genesisPinHash
  }, 'portable pin-history embedded trust root')
  const bundleBytes = bundleSnapshot(value.bundleBytes)
  const authorityTransitions = transitionsSnapshot(value.authorityTransitions)
  const terminal = terminalFromBundle(bundleBytes)
  const terminalSequence = typeof value.terminalSequence === 'number'
    ? BigInt(value.terminalSequence)
    : value.terminalSequence
  if (typeof terminalSequence !== 'bigint' || terminalSequence < 0n ||
      terminalSequence > ((1n << 64n) - 1n)) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', 'terminalSequence is outside u64')
  }
  const terminalPinHash = new Uint8Array(fixedBytesValue(
    value.terminalPinHash, 32, 'terminalPinHash'))
  const terminalCheckpointHash = new Uint8Array(fixedBytesValue(
    value.terminalCheckpointHash, 32, 'terminalCheckpointHash'))
  if (terminalSequence !== terminal.terminalSequence ||
      !bytesEqual(terminalPinHash, terminal.terminalPinHash) ||
      !bytesEqual(terminalCheckpointHash, terminal.terminalCheckpointHash)) {
    failReleaseControl('PORTABLE_PIN_HISTORY_TERMINAL_MISMATCH',
      'portable record terminal does not reproduce the exact embedded history')
  }
  return {
    version: 1,
    trustRootPublicKey: root.publicKey,
    genesisPinHash: root.genesisPinHash,
    bundleBytes,
    authorityTransitions,
    terminalSequence,
    terminalPinHash,
    terminalCheckpointHash
  }
}

function writeRecord (value) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_PORTABLE_PIN_HISTORY_MAGIC_V1,
    'PeeritPortablePinHistoryV1 magic')
  writer.u8(1, 'PeeritPortablePinHistoryV1 version')
  writer.fixed(value.trustRootPublicKey, 32, 'trustRootPublicKey')
  writer.fixed(value.genesisPinHash, 32, 'genesisPinHash')
  writer.u32(value.bundleBytes.byteLength, 'bundleBytes length')
  writer.fixed(value.bundleBytes, value.bundleBytes.byteLength, 'bundleBytes')
  writer.u16(value.authorityTransitions.length, 'authorityTransitions count')
  for (const transition of value.authorityTransitions) {
    writer.fixed(transition, PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES,
      'complete PeeritReleaseAuthorityTransitionV1')
  }
  writer.u64(value.terminalSequence, 'terminalSequence')
  writer.fixed(value.terminalPinHash, 32, 'terminalPinHash')
  writer.fixed(value.terminalCheckpointHash, 32, 'terminalCheckpointHash')
  return writer.finish()
}

export function encodePeeritPortablePinHistoryV1 (input) {
  return writeRecord(canonicalRecord(input))
}

export function createPeeritPortablePinHistoryV1 (input) {
  const value = exactDataObject(input,
    ['trustRootPublicKey', 'genesisPinHash', 'bundleBytes', 'authorityTransitions'],
    'portable pin-history creation input')
  const bundleBytes = bundleSnapshot(value.bundleBytes)
  const terminal = terminalFromBundle(bundleBytes)
  return encodePeeritPortablePinHistoryV1({
    version: 1,
    trustRootPublicKey: value.trustRootPublicKey,
    genesisPinHash: value.genesisPinHash,
    bundleBytes,
    authorityTransitions: value.authorityTransitions,
    terminalSequence: terminal.terminalSequence,
    terminalPinHash: terminal.terminalPinHash,
    terminalCheckpointHash: terminal.terminalCheckpointHash
  })
}

export function decodePeeritPortablePinHistoryV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritPortablePinHistoryV1 bytes'))
  const maximum = PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX +
    PEERIT_PORTABLE_PIN_HISTORY_MAX_TRANSITIONS_V1 *
      PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES + 256
  if (bytes.byteLength < 1 || bytes.byteLength > maximum) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', 'PeeritPortablePinHistoryV1 size is invalid')
  }
  const reader = new CanonicalReader(bytes)
  reader.expectLiteralAscii(PEERIT_PORTABLE_PIN_HISTORY_MAGIC_V1,
    'PeeritPortablePinHistoryV1 magic')
  const version = reader.u8('PeeritPortablePinHistoryV1 version')
  if (version !== 1) failReleaseControl('BAD_PORTABLE_PIN_HISTORY', 'unsupported portable pin-history version')
  const trustRootPublicKey = reader.fixed(32, 'trustRootPublicKey')
  const genesisPinHash = reader.fixed(32, 'genesisPinHash')
  const bundleLength = reader.u32('bundleBytes length')
  if (bundleLength < 1 || bundleLength > PEERIT_PIN_HISTORY_BUNDLE_BYTES_MAX) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', 'bundleBytes length is invalid')
  }
  const bundleBytes = reader.fixed(bundleLength, 'bundleBytes')
  const transitionCount = reader.u16('authorityTransitions count')
  if (transitionCount > PEERIT_PORTABLE_PIN_HISTORY_MAX_TRANSITIONS_V1) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY_TRANSITIONS', 'too many authority transitions')
  }
  const authorityTransitions = []
  for (let index = 0; index < transitionCount; index++) {
    authorityTransitions.push(reader.fixed(
      PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES,
      `authorityTransitions[${index}]`))
  }
  const terminalSequence = reader.u64('terminalSequence')
  const terminalPinHash = reader.fixed(32, 'terminalPinHash')
  const terminalCheckpointHash = reader.fixed(32, 'terminalCheckpointHash')
  reader.expectEnd('PeeritPortablePinHistoryV1')
  const value = canonicalRecord({
    version,
    trustRootPublicKey,
    genesisPinHash,
    bundleBytes,
    authorityTransitions,
    terminalSequence,
    terminalPinHash,
    terminalCheckpointHash
  })
  if (!bytesEqual(writeRecord(value), bytes)) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY', 'PeeritPortablePinHistoryV1 is noncanonical')
  }
  return Object.freeze({
    version: 1,
    trustRootPublicKey: new Uint8Array(value.trustRootPublicKey),
    genesisPinHash: new Uint8Array(value.genesisPinHash),
    bundleBytes: new Uint8Array(value.bundleBytes),
    authorityTransitions: Object.freeze(value.authorityTransitions.map(entry => new Uint8Array(entry))),
    terminalSequence: value.terminalSequence,
    terminalPinHash: new Uint8Array(value.terminalPinHash),
    terminalCheckpointHash: new Uint8Array(value.terminalCheckpointHash)
  })
}

export function hashPeeritPortablePinHistoryV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritPortablePinHistoryV1 bytes'))
  decodePeeritPortablePinHistoryV1(bytes)
  return domainLengthHash(PEERIT_PORTABLE_PIN_HISTORY_HASH_DOMAIN_V1, bytes)
}

export function hashPeeritPortablePinHistoryTransitionsV1 (transitions) {
  const values = transitionsSnapshot(transitions)
  const writer = new CanonicalWriter()
  writer.u16(values.length, 'authorityTransitions count')
  for (const value of values) {
    writer.fixed(value, PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES,
      'complete PeeritReleaseAuthorityTransitionV1')
  }
  return domainLengthHash(
    PEERIT_PORTABLE_PIN_HISTORY_TRANSITIONS_HASH_DOMAIN_V1,
    writer.finish()
  )
}

function hex (input) {
  let output = ''
  for (const byte of input) output += byte.toString(16).padStart(2, '0')
  return output
}

function authorityChanged (left, right) {
  return left.releaseAuthoritySequence !== right.releaseAuthoritySequence ||
    !bytesEqual(left.releaseAuthorityPublicKey, right.releaseAuthorityPublicKey)
}

function subBundle (bundle, start, end) {
  return encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: bundle.pins.slice(start, end),
    checkpoints: bundle.checkpoints.slice(start, end)
  })
}

function assertLineage (candidate, floor) {
  if (!bytesEqual(candidate.root.publicKey, floor.root.publicKey) ||
      !bytesEqual(candidate.root.genesisPinHash, floor.root.genesisPinHash)) {
    failReleaseControl('PORTABLE_PIN_HISTORY_ROOT_FORK',
      'portable pin-history records use different immutable roots')
  }
  if (candidate.terminalSequence < floor.terminalSequence) {
    failReleaseControl('PORTABLE_PIN_HISTORY_ROLLBACK',
      'portable pin-history candidate is below the witnessed terminal')
  }
  const index = Number(floor.terminalSequence)
  if (index >= candidate.pins.length ||
      !bytesEqual(profilePinHash(candidate.pins[index]), floor.terminalPinHash) ||
      !bytesEqual(pinHistoryCheckpointHash(candidate.checkpoints[index]),
        floor.terminalCheckpointHash)) {
    failReleaseControl('PORTABLE_PIN_HISTORY_FORK',
      'portable pin-history candidate does not contain the witnessed terminal')
  }
}

export async function verifyPeeritPortablePinHistoryV1 (input, options = {}) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritPortablePinHistoryV1 bytes'))
  const record = decodePeeritPortablePinHistoryV1(bytes)
  const root = rootSnapshot(options.trustRoot)
  if (!bytesEqual(root.publicKey, record.trustRootPublicKey) ||
      !bytesEqual(root.genesisPinHash, record.genesisPinHash)) {
    failReleaseControl('PORTABLE_PIN_HISTORY_ROOT_FORK',
      'portable record does not match the externally trusted release root')
  }

  const bundle = decodePeeritPinHistoryBundleV1(record.bundleBytes)
  const pins = bundle.pins.map(entry => decodePeeritHiveRelayProfilePinV1(entry))
  if (pins[0].releaseSequence !== 0n || pins[0].releaseAuthoritySequence !== 0n ||
      pins[0].authorityTransitionHash != null ||
      !bytesEqual(pins[0].releaseAuthorityPublicKey, root.publicKey) ||
      !bytesEqual(profilePinHash(bundle.pins[0]), root.genesisPinHash)) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY_GENESIS',
      'portable history does not start at the externally trusted sequence-zero pin')
  }

  const boundaries = [0]
  const expectedTransitionHashes = []
  for (let index = 1; index < pins.length; index++) {
    const changed = authorityChanged(pins[index - 1], pins[index])
    if (changed) {
      if (pins[index].authorityTransitionHash == null) {
        failReleaseControl('AUTHORITY_TRANSITION_REQUIRED',
          'a changed authority is missing its complete transition hash')
      }
      boundaries.push(index)
      expectedTransitionHashes.push(pins[index].authorityTransitionHash)
    } else if (pins[index].authorityTransitionHash != null) {
      failReleaseControl('UNEXPECTED_AUTHORITY_TRANSITION',
        'an unchanged authority must not name a transition')
    }
  }
  boundaries.push(pins.length)
  if (record.authorityTransitions.length !== expectedTransitionHashes.length) {
    failReleaseControl('BAD_PORTABLE_PIN_HISTORY_TRANSITIONS',
      'portable history must carry every and only referenced authority transition')
  }
  for (let index = 0; index < record.authorityTransitions.length; index++) {
    if (!bytesEqual(releaseAuthorityTransitionHash(record.authorityTransitions[index]),
      expectedTransitionHashes[index])) {
      failReleaseControl('BAD_PORTABLE_PIN_HISTORY_TRANSITIONS',
        'authority transitions are not in exact pin-chain order')
    }
  }

  const firstEnd = boundaries[1]
  let verified = await verifyPeeritPinHistoryBundleV1(
    subBundle(bundle, 0, firstEnd),
    {
      crypto: options.crypto,
      expectedPins: pins.slice(0, firstEnd).map(canonicalExpectedPinProjection)
    }
  )
  for (let segment = 1; segment < boundaries.length - 1; segment++) {
    const start = boundaries[segment]
    const end = boundaries[segment + 1]
    verified = await verifyPeeritPinHistoryContinuationV1(
      subBundle(bundle, start, end),
      {
        crypto: options.crypto,
        anchor: verified,
        authorityTransitions: [record.authorityTransitions[segment - 1]]
      }
    )
  }
  const terminal = getVerifiedPinHistoryTerminalSnapshotV1(verified)
  if (terminal.terminalSequence !== record.terminalSequence ||
      !bytesEqual(terminal.terminalPinHash, record.terminalPinHash) ||
      !bytesEqual(terminal.terminalCheckpointHash, record.terminalCheckpointHash)) {
    failReleaseControl('PORTABLE_PIN_HISTORY_TERMINAL_MISMATCH',
      'cryptographically verified terminal does not equal the portable witness')
  }

  const privateState = {
    bytes,
    root,
    pins: bundle.pins.map(entry => new Uint8Array(entry)),
    checkpoints: bundle.checkpoints.map(entry => new Uint8Array(entry)),
    transitions: record.authorityTransitions.map(entry => new Uint8Array(entry)),
    terminalSequence: record.terminalSequence,
    terminalPinBytes: new Uint8Array(bundle.pins[bundle.pins.length - 1]),
    terminalPinHash: new Uint8Array(record.terminalPinHash),
    terminalCheckpointHash: new Uint8Array(record.terminalCheckpointHash),
    recordHash: hashPeeritPortablePinHistoryV1(bytes),
    transitionSetHash: hashPeeritPortablePinHistoryTransitionsV1(record.authorityTransitions)
  }
  if (options.minimumWitness != null) {
    const floor = VERIFIED.get(options.minimumWitness)
    if (!floor) {
      failReleaseControl('VERIFIED_PORTABLE_PIN_HISTORY_REQUIRED',
        'minimumWitness must be a module-branded verified portable record')
    }
    assertLineage(privateState, floor)
  }
  const result = Object.freeze({
    version: 1,
    terminalSequence: privateState.terminalSequence,
    authorityTransitionCount: privateState.transitions.length,
    get recordHash () { return new Uint8Array(privateState.recordHash) },
    get terminalPinHash () { return new Uint8Array(privateState.terminalPinHash) },
    get terminalCheckpointHash () { return new Uint8Array(privateState.terminalCheckpointHash) }
  })
  VERIFIED.set(result, privateState)
  return result
}

export function getVerifiedPeeritPortablePinHistorySnapshotV1 (value) {
  const state = VERIFIED.get(value)
  if (!state) {
    failReleaseControl('VERIFIED_PORTABLE_PIN_HISTORY_REQUIRED',
      'a module-branded verified portable pin-history result is required')
  }
  return Object.freeze({
    version: 1,
    terminalSequence: state.terminalSequence,
    authorityTransitionCount: state.transitions.length,
    get trustRootPublicKey () { return new Uint8Array(state.root.publicKey) },
    get genesisPinHash () { return new Uint8Array(state.root.genesisPinHash) },
    get recordBytes () { return new Uint8Array(state.bytes) },
    get recordHash () { return new Uint8Array(state.recordHash) },
    get transitionSetHash () { return new Uint8Array(state.transitionSetHash) },
    get terminalPinBytes () { return new Uint8Array(state.terminalPinBytes) },
    get terminalPinHash () { return new Uint8Array(state.terminalPinHash) },
    get terminalCheckpointHash () { return new Uint8Array(state.terminalCheckpointHash) }
  })
}

export function mergeVerifiedPeeritPortablePinHistoryV1 (left, right) {
  const leftState = VERIFIED.get(left)
  const rightState = VERIFIED.get(right)
  if (!leftState || !rightState) {
    failReleaseControl('VERIFIED_PORTABLE_PIN_HISTORY_REQUIRED',
      'portable pin-history merge requires two module-branded verified records')
  }
  if (leftState.terminalSequence === rightState.terminalSequence) {
    assertLineage(leftState, rightState)
    assertLineage(rightState, leftState)
    if (!bytesEqual(leftState.bytes, rightState.bytes)) {
      failReleaseControl('PORTABLE_PIN_HISTORY_FORK',
        'same-terminal portable histories are not byte-identical')
    }
    return left
  }
  if (leftState.terminalSequence > rightState.terminalSequence) {
    assertLineage(leftState, rightState)
    return left
  }
  assertLineage(rightState, leftState)
  return right
}
