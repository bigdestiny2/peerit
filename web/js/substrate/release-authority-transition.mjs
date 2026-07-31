import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  asU64,
  asciiBytes,
  blake2b256,
  bytesEqual,
  concatBytes,
  domainLengthHash,
  failReleaseControl,
  fixedBytesValue,
  isAllZero
} from './release-control-primitives.mjs'

export const PEERIT_RELEASE_AUTHORITY_TRANSITION_TAG = 0x0105
export const PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES = 219

const SIGNATURE_DOMAIN = 'peerit.release-authority-transition.v1'
const HASH_DOMAIN = 'peerit.release-authority-transition-hash.v1'
const FIELDS = Object.freeze([
  'version',
  'previousSequence',
  'nextSequence',
  'previousPublicKey',
  'nextPublicKey',
  'validFromRelease',
  'previousKeySignature',
  'nextKeySignature'
])

function exactObject (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION', 'release authority transition must be a plain object')
  }
  const keys = Reflect.ownKeys(value)
  if (keys.length !== FIELDS.length || keys.some(key => typeof key !== 'string') ||
      FIELDS.some(key => !Object.prototype.hasOwnProperty.call(value, key))) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION', 'release authority transition fields are missing or unexpected')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const snapshot = Object.create(null)
  for (const field of FIELDS) {
    if (!descriptors[field] || !descriptors[field].enumerable ||
        !Object.prototype.hasOwnProperty.call(descriptors[field], 'value')) {
      failReleaseControl('BAD_AUTHORITY_TRANSITION', `release authority transition ${field} must be a data field`)
    }
    snapshot[field] = descriptors[field].value
  }
  return snapshot
}

function snapshotTransitionBytes (input) {
  const value = asBytes(input, 'PeeritReleaseAuthorityTransitionV1 bytes')
  if (value.byteLength !== PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION_SIZE',
      `PeeritReleaseAuthorityTransitionV1 must be exactly ${PEERIT_RELEASE_AUTHORITY_TRANSITION_BYTES} bytes`)
  }
  // Uint8Array#slice is not a copy for Node Buffers. Constructing a plain
  // Uint8Array snapshots Buffer and SharedArrayBuffer-backed inputs alike.
  return new Uint8Array(value)
}

function cloneTransition (value) {
  return Object.freeze({
    version: value.version,
    previousSequence: value.previousSequence,
    nextSequence: value.nextSequence,
    previousPublicKey: new Uint8Array(value.previousPublicKey),
    nextPublicKey: new Uint8Array(value.nextPublicKey),
    validFromRelease: value.validFromRelease,
    previousKeySignature: new Uint8Array(value.previousKeySignature),
    nextKeySignature: new Uint8Array(value.nextKeySignature)
  })
}

function snapshotPinBinding (pin, field, transitionHashRequired) {
  try {
    if (!pin || typeof pin !== 'object') throw new TypeError(`${field} must be an object`)
    const transitionHash = pin.authorityTransitionHash == null
      ? null
      : new Uint8Array(fixedBytesValue(pin.authorityTransitionHash, 32, `${field}.authorityTransitionHash`))
    if (transitionHashRequired && transitionHash == null) throw new TypeError('transition hash is required')
    return {
      releaseSequence: asU64(pin.releaseSequence, `${field}.releaseSequence`),
      releaseAuthoritySequence: asU64(
        pin.releaseAuthoritySequence, `${field}.releaseAuthoritySequence`),
      releaseAuthorityPublicKey: new Uint8Array(fixedBytesValue(
        pin.releaseAuthorityPublicKey, 32, `${field}.releaseAuthorityPublicKey`)),
      authorityTransitionHash: transitionHash
    }
  } catch {
    failReleaseControl('AUTHORITY_TRANSITION_BINDING_MISMATCH',
      'release authority transition requires complete adjacent pin bindings')
  }
}

function validateFields (input) {
  const value = exactObject(input)
  if (value.version !== 1) failReleaseControl('BAD_AUTHORITY_TRANSITION', 'release authority transition version must be 1')
  const previousPublicKey = fixedBytesValue(value.previousPublicKey, 32, 'previousPublicKey')
  const nextPublicKey = fixedBytesValue(value.nextPublicKey, 32, 'nextPublicKey')
  if (isAllZero(previousPublicKey) || isAllZero(nextPublicKey) || bytesEqual(previousPublicKey, nextPublicKey)) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION', 'release authority keys must be distinct and nonzero')
  }
  const writer = new CanonicalWriter()
  writer.u64(value.previousSequence, 'previousSequence')
  writer.u64(value.nextSequence, 'nextSequence')
  writer.u64(value.validFromRelease, 'validFromRelease')
  if (BigInt(value.nextSequence) !== BigInt(value.previousSequence) + 1n) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION', 'release authority sequence must advance exactly +1')
  }
  return {
    version: 1,
    previousSequence: BigInt(value.previousSequence),
    nextSequence: BigInt(value.nextSequence),
    previousPublicKey: new Uint8Array(previousPublicKey),
    nextPublicKey: new Uint8Array(nextPublicKey),
    validFromRelease: BigInt(value.validFromRelease),
    previousKeySignature: new Uint8Array(fixedBytesValue(
      value.previousKeySignature, 64, 'previousKeySignature')),
    nextKeySignature: new Uint8Array(fixedBytesValue(
      value.nextKeySignature, 64, 'nextKeySignature'))
  }
}

function writeUnsigned (writer, value) {
  writer.u16(PEERIT_RELEASE_AUTHORITY_TRANSITION_TAG, 'PeeritReleaseAuthorityTransitionV1 tag')
  writer.u8(1, 'PeeritReleaseAuthorityTransitionV1 version')
  writer.u64(value.previousSequence, 'previousSequence')
  writer.u64(value.nextSequence, 'nextSequence')
  writer.fixed(value.previousPublicKey, 32, 'previousPublicKey')
  writer.fixed(value.nextPublicKey, 32, 'nextPublicKey')
  writer.u64(value.validFromRelease, 'validFromRelease')
}

export function encodePeeritReleaseAuthorityTransitionV1Unsigned (input) {
  const value = validateFields(input)
  const writer = new CanonicalWriter()
  writeUnsigned(writer, value)
  return writer.finish()
}

export function encodePeeritReleaseAuthorityTransitionV1 (input) {
  const value = validateFields(input)
  const writer = new CanonicalWriter()
  writeUnsigned(writer, value)
  writer.fixed(value.previousKeySignature, 64, 'previousKeySignature')
  writer.fixed(value.nextKeySignature, 64, 'nextKeySignature')
  return writer.finish()
}

export function decodePeeritReleaseAuthorityTransitionV1 (input) {
  const bytes = snapshotTransitionBytes(input)
  const reader = new CanonicalReader(bytes)
  if (reader.u16('PeeritReleaseAuthorityTransitionV1 tag') !== PEERIT_RELEASE_AUTHORITY_TRANSITION_TAG) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION_TAG',
      `PeeritReleaseAuthorityTransitionV1 tag must be ${PEERIT_RELEASE_AUTHORITY_TRANSITION_TAG}`)
  }
  const value = {
    version: reader.u8('version'),
    previousSequence: reader.u64('previousSequence'),
    nextSequence: reader.u64('nextSequence'),
    previousPublicKey: reader.fixed(32, 'previousPublicKey'),
    nextPublicKey: reader.fixed(32, 'nextPublicKey'),
    validFromRelease: reader.u64('validFromRelease'),
    previousKeySignature: reader.fixed(64, 'previousKeySignature'),
    nextKeySignature: reader.fixed(64, 'nextKeySignature')
  }
  reader.expectEnd('PeeritReleaseAuthorityTransitionV1')
  const validated = validateFields(value)
  const canonical = encodePeeritReleaseAuthorityTransitionV1(validated)
  if (!bytesEqual(canonical, bytes)) {
    failReleaseControl('NONCANONICAL_AUTHORITY_TRANSITION',
      'PeeritReleaseAuthorityTransitionV1 does not round-trip canonically')
  }
  return Object.freeze(validated)
}

export function releaseAuthorityTransitionSignatureCommitment (input) {
  return blake2b256(concatBytes(
    asciiBytes(SIGNATURE_DOMAIN),
    encodePeeritReleaseAuthorityTransitionV1Unsigned(input)
  ))
}

export function releaseAuthorityTransitionHash (input) {
  const bytes = snapshotTransitionBytes(input)
  decodePeeritReleaseAuthorityTransitionV1(bytes)
  return domainLengthHash(HASH_DOMAIN, bytes)
}

export async function verifyPeeritReleaseAuthorityTransitionV1 (completeTransition, options = {}) {
  if (!options.crypto || typeof options.crypto.verifyEd25519 !== 'function') {
    failReleaseControl('RELEASE_CONTROL_CRYPTO_UNAVAILABLE', 'verifyEd25519 runtime is required')
  }
  const verifyEd25519 = options.crypto.verifyEd25519.bind(options.crypto)
  const bytes = snapshotTransitionBytes(completeTransition)
  const transition = decodePeeritReleaseAuthorityTransitionV1(bytes)
  const previousPin = snapshotPinBinding(options.previousPin, 'previousPin', false)
  const nextPin = snapshotPinBinding(options.nextPin, 'nextPin', true)
  if (transition.previousSequence !== previousPin.releaseAuthoritySequence ||
      transition.nextSequence !== nextPin.releaseAuthoritySequence ||
      !bytesEqual(transition.previousPublicKey, previousPin.releaseAuthorityPublicKey) ||
      !bytesEqual(transition.nextPublicKey, nextPin.releaseAuthorityPublicKey) ||
      transition.validFromRelease !== nextPin.releaseSequence ||
      transition.validFromRelease <= previousPin.releaseSequence) {
    failReleaseControl('AUTHORITY_TRANSITION_BINDING_MISMATCH',
      'release authority transition does not exactly bind adjacent pin authorities')
  }
  const hash = releaseAuthorityTransitionHash(bytes)
  if (!bytesEqual(hash, nextPin.authorityTransitionHash)) {
    failReleaseControl('AUTHORITY_TRANSITION_HASH_MISMATCH',
      'first pin under the new authority does not name the complete transition')
  }
  const commitment = releaseAuthorityTransitionSignatureCommitment(transition)
  const results = await Promise.all([
    verifyEd25519(
      transition.previousPublicKey, commitment, transition.previousKeySignature),
    verifyEd25519(
      transition.nextPublicKey, commitment, transition.nextKeySignature)
  ])
  if (results[0] !== true || results[1] !== true) {
    failReleaseControl('BAD_AUTHORITY_TRANSITION_SIGNATURE',
      'release authority transition requires valid old-key and new-key signatures')
  }
  const publicTransition = cloneTransition(transition)
  return Object.freeze({
    get transition () { return cloneTransition(publicTransition) },
    get bytes () { return new Uint8Array(bytes) },
    get transitionHash () { return new Uint8Array(hash) },
    get signatureCommitment () { return new Uint8Array(commitment) }
  })
}
