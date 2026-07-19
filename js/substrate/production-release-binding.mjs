import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  asciiBytes,
  blake2b256,
  bytesEqual,
  concatBytes,
  domainLengthHash,
  failReleaseControl,
  fixedBytesValue,
  hexToBytes,
  isAllZero
} from './release-control-primitives.mjs'
import {
  decodePeeritHiveRelayProfilePinV1,
  releaseAuthorityKeyId
} from './release-control-codec.mjs'
import {
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
} from './profile-external-authority.mjs'
import { PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 } from './production-release-authority.mjs'
import {
  getVerifiedPeeritPortablePinHistorySnapshotV1,
  verifyPeeritPortablePinHistoryV1
} from './portable-pin-history.mjs'
import { hashPeeritLegacyRkPostureV1 } from './legacy-rk-posture.mjs'
import { peeritRecoveryBundleContractHashV1 } from './peerit-recovery-bundle-v1.mjs'
import {
  decodePeeritWebAssetManifestV1,
  hashPeeritWebAssetManifestV1
} from './web-asset-manifest.mjs'

export const PEERIT_PRODUCTION_RELEASE_BINDING_MAGIC_V1 = 'PEERITPB'
export const PEERIT_PRODUCTION_RELEASE_BINDING_SIGNATURE_DOMAIN_V1 =
  'peerit.production-release-binding.v1'
export const PEERIT_PRODUCTION_RELEASE_BINDING_HASH_DOMAIN_V1 =
  'peerit.production-release-binding-hash.v1'
export const PEERIT_BROWSER_RUNTIME_ARTIFACT_HASH_DOMAIN_V1 =
  'peerit.browser-runtime-artifact.v1'
export const PEERIT_BROWSER_RUNTIME_VECTOR_SET_HASH_DOMAIN_V1 =
  'peerit.browser-runtime-vector-set.v1'
export const PEERIT_SERVICE_WORKER_SOURCE_HASH_DOMAIN_V1 =
  'peerit.service-worker-source.v1'

const FIELDS = Object.freeze([
  'version',
  'releaseSequence',
  'releaseAuthoritySequence',
  'releaseAuthorityPublicKey',
  'releaseAuthorityKeyId',
  'terminalPinHash',
  'terminalCheckpointHash',
  'pinHistoryRecordHash',
  'authorityTransitionSetHash',
  'authorityTransitionCount',
  'appArtifactHash',
  'webAssetManifestHash',
  'browserRuntimeArtifactHash',
  'browserRuntimeVectorSetHash',
  'serviceWorkerSourceHash',
  'recoveryContractHash',
  'legacyRkPostureHash',
  'wireSpecHash',
  'wireAbiHash',
  'wireVectorSetHash',
  'clientFormatHash',
  'clientVectorSetHash',
  'signature'
])
const HASH_FIELDS = Object.freeze([
  'releaseAuthorityPublicKey',
  'releaseAuthorityKeyId',
  'terminalPinHash',
  'terminalCheckpointHash',
  'pinHistoryRecordHash',
  'authorityTransitionSetHash',
  'appArtifactHash',
  'webAssetManifestHash',
  'browserRuntimeArtifactHash',
  'browserRuntimeVectorSetHash',
  'serviceWorkerSourceHash',
  'recoveryContractHash',
  'legacyRkPostureHash',
  'wireSpecHash',
  'wireAbiHash',
  'wireVectorSetHash',
  'clientFormatHash',
  'clientVectorSetHash'
])
const VERIFIED = new WeakMap()

function exactObject (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype &&
       Object.getPrototypeOf(input) !== null)) {
    failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING',
      'PeeritProductionReleaseBindingV1 must be a plain data object')
  }
  const descriptors = Object.getOwnPropertyDescriptors(input)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== FIELDS.length || keys.some(key => typeof key !== 'string') ||
      FIELDS.some(field => !Object.hasOwn(descriptors, field))) {
    failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING',
      'PeeritProductionReleaseBindingV1 fields are missing or unexpected')
  }
  const value = Object.create(null)
  for (const field of FIELDS) {
    const descriptor = descriptors[field]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING',
        `PeeritProductionReleaseBindingV1.${field} must be an enumerable data field`)
    }
    value[field] = descriptor.value
  }
  return value
}

function u64 (input, field) {
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input) || input < 0) {
      failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING', `${field} is outside u64`)
    }
    input = BigInt(input)
  }
  if (typeof input !== 'bigint' || input < 0n || input > ((1n << 64n) - 1n)) {
    failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING', `${field} is outside u64`)
  }
  return input
}

function canonicalBinding (input) {
  const value = exactObject(input)
  if (value.version !== 1) {
    failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING',
      'PeeritProductionReleaseBindingV1 version must be 1')
  }
  const output = {
    version: 1,
    releaseSequence: u64(value.releaseSequence, 'releaseSequence'),
    releaseAuthoritySequence: u64(
      value.releaseAuthoritySequence, 'releaseAuthoritySequence'),
    authorityTransitionCount: value.authorityTransitionCount
  }
  if (!Number.isSafeInteger(output.authorityTransitionCount) ||
      output.authorityTransitionCount < 0 || output.authorityTransitionCount > 0xffff) {
    failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING',
      'authorityTransitionCount is outside u16')
  }
  for (const field of HASH_FIELDS) {
    output[field] = new Uint8Array(fixedBytesValue(value[field], 32, field))
    if (isAllZero(output[field])) {
      failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING', `${field} must be nonzero`)
    }
  }
  output.signature = new Uint8Array(fixedBytesValue(value.signature, 64, 'signature'))
  return output
}

function writeBinding (value, includeSignature) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_PRODUCTION_RELEASE_BINDING_MAGIC_V1,
    'PeeritProductionReleaseBindingV1 magic')
  writer.u8(1, 'PeeritProductionReleaseBindingV1 version')
  writer.u64(value.releaseSequence, 'releaseSequence')
  writer.u64(value.releaseAuthoritySequence, 'releaseAuthoritySequence')
  writer.fixed(value.releaseAuthorityPublicKey, 32, 'releaseAuthorityPublicKey')
  writer.fixed(value.releaseAuthorityKeyId, 32, 'releaseAuthorityKeyId')
  writer.fixed(value.terminalPinHash, 32, 'terminalPinHash')
  writer.fixed(value.terminalCheckpointHash, 32, 'terminalCheckpointHash')
  writer.fixed(value.pinHistoryRecordHash, 32, 'pinHistoryRecordHash')
  writer.fixed(value.authorityTransitionSetHash, 32, 'authorityTransitionSetHash')
  writer.u16(value.authorityTransitionCount, 'authorityTransitionCount')
  for (const field of [
    'appArtifactHash',
    'webAssetManifestHash',
    'browserRuntimeArtifactHash',
    'browserRuntimeVectorSetHash',
    'serviceWorkerSourceHash',
    'recoveryContractHash',
    'legacyRkPostureHash',
    'wireSpecHash',
    'wireAbiHash',
    'wireVectorSetHash',
    'clientFormatHash',
    'clientVectorSetHash'
  ]) writer.fixed(value[field], 32, field)
  if (includeSignature) writer.fixed(value.signature, 64, 'signature')
  return writer.finish()
}

export function encodePeeritProductionReleaseBindingV1Unsigned (input) {
  return writeBinding(canonicalBinding(input), false)
}

export function encodePeeritProductionReleaseBindingV1 (input) {
  return writeBinding(canonicalBinding(input), true)
}

export function decodePeeritProductionReleaseBindingV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritProductionReleaseBindingV1 bytes'))
  const reader = new CanonicalReader(bytes)
  reader.expectLiteralAscii(PEERIT_PRODUCTION_RELEASE_BINDING_MAGIC_V1,
    'PeeritProductionReleaseBindingV1 magic')
  const version = reader.u8('PeeritProductionReleaseBindingV1 version')
  const value = {
    version,
    releaseSequence: reader.u64('releaseSequence'),
    releaseAuthoritySequence: reader.u64('releaseAuthoritySequence'),
    releaseAuthorityPublicKey: reader.fixed(32, 'releaseAuthorityPublicKey'),
    releaseAuthorityKeyId: reader.fixed(32, 'releaseAuthorityKeyId'),
    terminalPinHash: reader.fixed(32, 'terminalPinHash'),
    terminalCheckpointHash: reader.fixed(32, 'terminalCheckpointHash'),
    pinHistoryRecordHash: reader.fixed(32, 'pinHistoryRecordHash'),
    authorityTransitionSetHash: reader.fixed(32, 'authorityTransitionSetHash'),
    authorityTransitionCount: reader.u16('authorityTransitionCount')
  }
  for (const field of [
    'appArtifactHash',
    'webAssetManifestHash',
    'browserRuntimeArtifactHash',
    'browserRuntimeVectorSetHash',
    'serviceWorkerSourceHash',
    'recoveryContractHash',
    'legacyRkPostureHash',
    'wireSpecHash',
    'wireAbiHash',
    'wireVectorSetHash',
    'clientFormatHash',
    'clientVectorSetHash'
  ]) value[field] = reader.fixed(32, field)
  value.signature = reader.fixed(64, 'signature')
  reader.expectEnd('PeeritProductionReleaseBindingV1')
  const canonical = canonicalBinding(value)
  if (!bytesEqual(writeBinding(canonical, true), bytes)) {
    failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING',
      'PeeritProductionReleaseBindingV1 is noncanonical')
  }
  return Object.freeze(canonical)
}

export function peeritProductionReleaseBindingSignatureCommitmentV1 (input) {
  return blake2b256(concatBytes(
    asciiBytes(PEERIT_PRODUCTION_RELEASE_BINDING_SIGNATURE_DOMAIN_V1),
    encodePeeritProductionReleaseBindingV1Unsigned(input)
  ))
}

export function hashPeeritProductionReleaseBindingV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritProductionReleaseBindingV1 bytes'))
  decodePeeritProductionReleaseBindingV1(bytes)
  return domainLengthHash(PEERIT_PRODUCTION_RELEASE_BINDING_HASH_DOMAIN_V1, bytes)
}

export function hashPeeritBrowserRuntimeArtifactV1 (input) {
  return domainLengthHash(PEERIT_BROWSER_RUNTIME_ARTIFACT_HASH_DOMAIN_V1, input)
}

export function hashPeeritBrowserRuntimeVectorSetV1 (input) {
  return domainLengthHash(PEERIT_BROWSER_RUNTIME_VECTOR_SET_HASH_DOMAIN_V1, input)
}

export function hashPeeritServiceWorkerSourceV1 (input) {
  return domainLengthHash(PEERIT_SERVICE_WORKER_SOURCE_HASH_DOMAIN_V1, input)
}

function pinnedHash (value, field) {
  return hexToBytes(value, 32, field)
}

function requireEqual (left, right, code, message) {
  if (!bytesEqual(left, right)) failReleaseControl(code, message)
}

export async function verifyPeeritProductionReleaseBindingV1 (input, options = {}) {
  if (!options.crypto || typeof options.crypto.verifyEd25519 !== 'function') {
    failReleaseControl('RELEASE_CONTROL_CRYPTO_UNAVAILABLE',
      'verifyEd25519 runtime is required for PeeritProductionReleaseBindingV1')
  }
  const bytes = new Uint8Array(asBytes(input, 'PeeritProductionReleaseBindingV1 bytes'))
  const binding = decodePeeritProductionReleaseBindingV1(bytes)
  const history = getVerifiedPeeritPortablePinHistorySnapshotV1(
    options.verifiedPinHistory)
  const terminalPin = decodePeeritHiveRelayProfilePinV1(history.terminalPinBytes)

  if (binding.releaseSequence !== history.terminalSequence ||
      binding.releaseSequence !== terminalPin.releaseSequence ||
      binding.releaseAuthoritySequence !== terminalPin.releaseAuthoritySequence ||
      binding.authorityTransitionCount !== history.authorityTransitionCount) {
    failReleaseControl('PRODUCTION_RELEASE_BINDING_HISTORY_MISMATCH',
      'production binding does not name the verified pin-history terminal')
  }
  for (const [left, right, label] of [
    [binding.releaseAuthorityPublicKey, terminalPin.releaseAuthorityPublicKey, 'release authority key'],
    [binding.releaseAuthorityKeyId, terminalPin.releaseAuthorityKeyId, 'release authority key ID'],
    [binding.terminalPinHash, history.terminalPinHash, 'terminal pin hash'],
    [binding.terminalCheckpointHash, history.terminalCheckpointHash, 'terminal checkpoint hash'],
    [binding.pinHistoryRecordHash, history.recordHash, 'portable pin-history hash'],
    [binding.authorityTransitionSetHash, history.transitionSetHash, 'authority transition set hash'],
    [binding.appArtifactHash, terminalPin.appArtifactHash, 'app artifact hash'],
    [binding.webAssetManifestHash, terminalPin.webAssetManifestHash, 'WebAssetManifestV1 hash']
  ]) {
    requireEqual(left, right, 'PRODUCTION_RELEASE_BINDING_HISTORY_MISMATCH',
      `production binding ${label} is not the verified terminal value`)
  }

  requireEqual(binding.releaseAuthorityKeyId,
    releaseAuthorityKeyId(binding.releaseAuthorityPublicKey),
    'PRODUCTION_RELEASE_BINDING_AUTHORITY_MISMATCH',
    'production binding release authority key ID is invalid')

  const wire = PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
  const client = PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1
  for (const [actual, expected, label] of [
    [binding.wireSpecHash, wire.specHash, 'WIRE spec'],
    [binding.wireAbiHash, wire.abiHash, 'WIRE ABI'],
    [binding.wireVectorSetHash, wire.vectorSetHash, 'WIRE vectors'],
    [binding.clientFormatHash, client.formatHash, 'client-composition format'],
    [binding.clientVectorSetHash, client.vectorSetHash, 'client-composition vectors']
  ]) {
    requireEqual(actual, pinnedHash(expected, label),
      'PRODUCTION_RELEASE_BINDING_SUBSTRATE_MISMATCH',
      `production binding ${label} differs from the frozen external authority`)
  }

  requireEqual(binding.recoveryContractHash, peeritRecoveryBundleContractHashV1(),
    'PRODUCTION_RELEASE_BINDING_RECOVERY_MISMATCH',
    'production binding does not name the exact PeeritRecoveryBundleV1 contract')
  requireEqual(binding.legacyRkPostureHash, hashPeeritLegacyRkPostureV1(),
    'PRODUCTION_RELEASE_BINDING_LEGACY_RK_MISMATCH',
    'production binding does not preserve the public/reachable legacy RK posture')

  const manifestBytes = new Uint8Array(asBytes(
    options.webAssetManifestBytes, 'WebAssetManifestV1 bytes'))
  const manifest = decodePeeritWebAssetManifestV1(manifestBytes)
  requireEqual(binding.webAssetManifestHash,
    hashPeeritWebAssetManifestV1(manifestBytes),
    'PRODUCTION_RELEASE_BINDING_MANIFEST_MISMATCH',
    'production binding WebAssetManifestV1 bytes do not match its signed hash')
  if (manifest.releaseSequence !== binding.releaseSequence ||
      !bytesEqual(manifest.appArtifactHash, binding.appArtifactHash)) {
    failReleaseControl('PRODUCTION_RELEASE_BINDING_MANIFEST_MISMATCH',
      'WebAssetManifestV1 does not bind the same release and app artifact')
  }

  for (const [actual, supplied, hash, label] of [
    [binding.browserRuntimeArtifactHash, options.browserRuntimeArtifactBytes,
      hashPeeritBrowserRuntimeArtifactV1, 'browser runtime artifact'],
    [binding.browserRuntimeVectorSetHash, options.browserRuntimeVectorSetBytes,
      hashPeeritBrowserRuntimeVectorSetV1, 'browser runtime vectors'],
    [binding.serviceWorkerSourceHash, options.serviceWorkerSourceBytes,
      hashPeeritServiceWorkerSourceV1, 'service-worker source']
  ]) {
    requireEqual(actual, hash(new Uint8Array(asBytes(supplied, `${label} bytes`))),
      'PRODUCTION_RELEASE_BINDING_RUNTIME_MISMATCH',
      `production binding ${label} bytes do not match`)
  }

  const signatureOk = await options.crypto.verifyEd25519(
    binding.releaseAuthorityPublicKey,
    peeritProductionReleaseBindingSignatureCommitmentV1(binding),
    binding.signature
  )
  if (signatureOk !== true) {
    failReleaseControl('BAD_PRODUCTION_RELEASE_BINDING_SIGNATURE',
      'PeeritProductionReleaseBindingV1 signature is invalid')
  }
  const state = {
    bytes,
    hash: hashPeeritProductionReleaseBindingV1(bytes),
    binding
  }
  const result = Object.freeze({
    version: 1,
    releaseSequence: binding.releaseSequence,
    get bindingHash () { return new Uint8Array(state.hash) }
  })
  VERIFIED.set(result, state)
  return result
}
// This is the only production-root wrapper. Caller-provided roots are not
// accepted here: until the independent ceremony compiles both values, it fails
// before parsing an origin-supplied binding or history.
export async function verifyPeeritCompiledProductionReleaseBindingV1 (
  input,
  options = {}
) {
  const root = PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1
  if (root.publicKey == null || root.genesisPinHash == null) {
    failReleaseControl('PRODUCTION_PEERIT_RELEASE_AUTHORITY_UNPINNED',
      'production release binding is disabled until authority and genesis are compiled')
  }
  const verifiedPinHistory = await verifyPeeritPortablePinHistoryV1(
    options.pinHistoryRecordBytes,
    {
      crypto: options.crypto,
      trustRoot: root,
      minimumWitness: options.minimumPinHistoryWitness
    }
  )
  return verifyPeeritProductionReleaseBindingV1(input, {
    ...options,
    verifiedPinHistory
  })
}

export function getVerifiedPeeritProductionReleaseBindingSnapshotV1 (value) {
  const state = VERIFIED.get(value)
  if (!state) {
    failReleaseControl('VERIFIED_PRODUCTION_RELEASE_BINDING_REQUIRED',
      'a module-branded verified PeeritProductionReleaseBindingV1 is required')
  }
  const binding = state.binding
  return Object.freeze({
    version: 1,
    releaseSequence: binding.releaseSequence,
    get bindingBytes () { return new Uint8Array(state.bytes) },
    get bindingHash () { return new Uint8Array(state.hash) },
    get appArtifactHash () { return new Uint8Array(binding.appArtifactHash) },
    get webAssetManifestHash () { return new Uint8Array(binding.webAssetManifestHash) },
    get serviceWorkerSourceHash () { return new Uint8Array(binding.serviceWorkerSourceHash) }
  })
}
