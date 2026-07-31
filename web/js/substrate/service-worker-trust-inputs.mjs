import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  bytesEqual,
  concatBytes,
  domainLengthHash,
  failReleaseControl,
  fixedBytesValue,
  u64Bytes
} from './release-control-primitives.mjs'
import {
  getVerifiedPeeritProductionReleaseBindingSnapshotV1
} from './production-release-binding.mjs'

export const PEERIT_SERVICE_WORKER_TRUST_INPUTS_MAGIC_V1 = 'PEERITSW'
export const PEERIT_SERVICE_WORKER_TRUST_INPUTS_HASH_DOMAIN_V1 =
  'peerit.service-worker-trust-inputs.v1'
export const PEERIT_SERVICE_WORKER_GENERATION_ID_DOMAIN_V1 =
  'peerit.service-worker-generation-id.v1'
export const PEERIT_SERVICE_WORKER_RETAINED_GENERATIONS_V1 = 2

const FIELDS = Object.freeze([
  'version',
  'releaseSequence',
  'productionBindingHash',
  'appArtifactHash',
  'webAssetManifestHash',
  'serviceWorkerSourceHash',
  'activeGenerationId',
  'previousReleaseSequence',
  'previousGenerationId',
  'retainedGenerations'
])

function fail (message) {
  failReleaseControl('BAD_SERVICE_WORKER_TRUST_INPUTS', message)
}
function exactObject (input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype &&
       Object.getPrototypeOf(input) !== null)) fail('trust inputs must be a plain object')
  const descriptors = Object.getOwnPropertyDescriptors(input)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== FIELDS.length || keys.some(key => typeof key !== 'string') ||
      FIELDS.some(field => !Object.hasOwn(descriptors, field))) {
    fail('trust input fields are missing or unexpected')
  }
  const output = Object.create(null)
  for (const field of FIELDS) {
    const descriptor = descriptors[field]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(`${field} must be an enumerable data field`)
    }
    output[field] = descriptor.value
  }
  return output
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} is outside u64`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    fail(`${field} is outside u64`)
  }
  return value
}

function canonical (input) {
  const value = exactObject(input)
  if (value.version !== 1 ||
      value.retainedGenerations !== PEERIT_SERVICE_WORKER_RETAINED_GENERATIONS_V1) {
    fail('version or retained-generation policy is invalid')
  }
  const previousReleaseSequence = value.previousReleaseSequence == null
    ? null
    : asU64(value.previousReleaseSequence, 'previousReleaseSequence')
  const previousGenerationId = value.previousGenerationId == null
    ? null
    : new Uint8Array(fixedBytesValue(value.previousGenerationId, 32, 'previousGenerationId'))
  if ((previousReleaseSequence == null) !== (previousGenerationId == null)) {
    fail('previous release sequence and generation ID must be present together')
  }
  const output = {
    version: 1,
    releaseSequence: asU64(value.releaseSequence, 'releaseSequence'),
    previousReleaseSequence,
    previousGenerationId,
    retainedGenerations: PEERIT_SERVICE_WORKER_RETAINED_GENERATIONS_V1
  }
  for (const field of [
    'productionBindingHash',
    'appArtifactHash',
    'webAssetManifestHash',
    'serviceWorkerSourceHash',
    'activeGenerationId'
  ]) output[field] = new Uint8Array(fixedBytesValue(value[field], 32, field))
  if (previousReleaseSequence != null && previousReleaseSequence >= output.releaseSequence) {
    fail('previous release must be older than the active release')
  }
  return output
}

function write (value) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_SERVICE_WORKER_TRUST_INPUTS_MAGIC_V1,
    'PeeritServiceWorkerTrustInputsV1 magic')
  writer.u8(1, 'PeeritServiceWorkerTrustInputsV1 version')
  writer.u64(value.releaseSequence, 'releaseSequence')
  writer.fixed(value.productionBindingHash, 32, 'productionBindingHash')
  writer.fixed(value.appArtifactHash, 32, 'appArtifactHash')
  writer.fixed(value.webAssetManifestHash, 32, 'webAssetManifestHash')
  writer.fixed(value.serviceWorkerSourceHash, 32, 'serviceWorkerSourceHash')
  writer.fixed(value.activeGenerationId, 32, 'activeGenerationId')
  writer.optionalU64(value.previousReleaseSequence, 'previousReleaseSequence')
  writer.optionalFixed(value.previousGenerationId, 32, 'previousGenerationId')
  writer.u8(value.retainedGenerations, 'retainedGenerations')
  return writer.finish()
}

export function peeritServiceWorkerGenerationIdV1 (bindingSnapshot) {
  return domainLengthHash(
    PEERIT_SERVICE_WORKER_GENERATION_ID_DOMAIN_V1,
    concatBytes(
      u64Bytes(bindingSnapshot.releaseSequence),
      bindingSnapshot.bindingHash,
      bindingSnapshot.webAssetManifestHash,
      bindingSnapshot.serviceWorkerSourceHash
    )
  )
}

export function encodePeeritServiceWorkerTrustInputsV1 (input) {
  return write(canonical(input))
}

export function decodePeeritServiceWorkerTrustInputsV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritServiceWorkerTrustInputsV1 bytes'))
  const reader = new CanonicalReader(bytes)
  reader.expectLiteralAscii(PEERIT_SERVICE_WORKER_TRUST_INPUTS_MAGIC_V1,
    'PeeritServiceWorkerTrustInputsV1 magic')
  const value = {
    version: reader.u8('version'),
    releaseSequence: reader.u64('releaseSequence'),
    productionBindingHash: reader.fixed(32, 'productionBindingHash'),
    appArtifactHash: reader.fixed(32, 'appArtifactHash'),
    webAssetManifestHash: reader.fixed(32, 'webAssetManifestHash'),
    serviceWorkerSourceHash: reader.fixed(32, 'serviceWorkerSourceHash'),
    activeGenerationId: reader.fixed(32, 'activeGenerationId'),
    previousReleaseSequence: reader.optionalU64('previousReleaseSequence'),
    previousGenerationId: reader.optionalFixed(32, 'previousGenerationId'),
    retainedGenerations: reader.u8('retainedGenerations')
  }
  reader.expectEnd('PeeritServiceWorkerTrustInputsV1')
  const output = canonical(value)
  if (!bytesEqual(write(output), bytes)) fail('trust inputs are noncanonical')
  return Object.freeze(output)
}

export function hashPeeritServiceWorkerTrustInputsV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'PeeritServiceWorkerTrustInputsV1 bytes'))
  decodePeeritServiceWorkerTrustInputsV1(bytes)
  return domainLengthHash(PEERIT_SERVICE_WORKER_TRUST_INPUTS_HASH_DOMAIN_V1, bytes)
}

export function createPeeritServiceWorkerTrustInputsV1 (
  verifiedBinding,
  previousVerifiedBinding = null
) {
  const current = getVerifiedPeeritProductionReleaseBindingSnapshotV1(verifiedBinding)
  const previous = previousVerifiedBinding == null
    ? null
    : getVerifiedPeeritProductionReleaseBindingSnapshotV1(previousVerifiedBinding)
  return encodePeeritServiceWorkerTrustInputsV1({
    version: 1,
    releaseSequence: current.releaseSequence,
    productionBindingHash: current.bindingHash,
    appArtifactHash: current.appArtifactHash,
    webAssetManifestHash: current.webAssetManifestHash,
    serviceWorkerSourceHash: current.serviceWorkerSourceHash,
    activeGenerationId: peeritServiceWorkerGenerationIdV1(current),
    previousReleaseSequence: previous?.releaseSequence ?? null,
    previousGenerationId: previous == null
      ? null
      : peeritServiceWorkerGenerationIdV1(previous),
    retainedGenerations: PEERIT_SERVICE_WORKER_RETAINED_GENERATIONS_V1
  })
}

export function verifyPeeritServiceWorkerTrustInputsV1 (
  input,
  verifiedBinding,
  previousVerifiedBinding = null
) {
  const value = decodePeeritServiceWorkerTrustInputsV1(input)
  const expected = decodePeeritServiceWorkerTrustInputsV1(
    createPeeritServiceWorkerTrustInputsV1(
      verifiedBinding,
      previousVerifiedBinding
    )
  )
  for (const field of FIELDS) {
    const left = value[field]
    const right = expected[field]
    const equal = left instanceof Uint8Array || right instanceof Uint8Array
      ? left != null && right != null && bytesEqual(left, right)
      : left === right
    if (!equal) fail(`${field} is not derived from the verified signed release binding`)
  }
  return Object.freeze({
    version: 1,
    releaseSequence: value.releaseSequence,
    activeGenerationId: new Uint8Array(value.activeGenerationId),
    previousReleaseSequence: value.previousReleaseSequence,
    previousGenerationId: value.previousGenerationId == null
      ? null
      : new Uint8Array(value.previousGenerationId),
    retainedGenerations: value.retainedGenerations
  })
}
