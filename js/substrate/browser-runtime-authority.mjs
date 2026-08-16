import { availabilityPolicyHash } from './availability-policy.mjs'
import { hashBytes } from '../crypto.js'
import {
  verifyBlindClientBrowserReleaseV1,
  verifyBlindClientCellGetBrowserReleaseV1
} from './blind-client-browser-verifier.mjs'
import {
  PEERIT_LIMITED_CELL_GET_ARTIFACT_PATH_V1,
  PEERIT_LIMITED_CELL_GET_MANIFEST_PATH_V1,
  PEERIT_LIMITED_CELL_GET_PROFILE_PATH_V1,
  verifyPeeritLimitedCellGetProfileV1
} from './limited-cell-get-profile.mjs'
import {
  PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
  PEERIT_LIMITED_CELL_PUT_PROFILE_PATH_V1,
  PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE,
  PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1,
  verifyPeeritLimitedCellPutProfileV1
} from './limited-cell-put-profile.mjs'
import {
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1,
  PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1
} from './inbox-topic-v1.mjs'
import {
  decodePeeritProfileRegistry,
  hashPeeritProfileAbi,
  hashPeeritProfileSpec,
  hashPeeritProfileVectorSet
} from './profile-artifact-codec.mjs'
import {
  decodePeeritHiveRelayProfilePinV1,
  profilePinHash
} from './release-control-codec.mjs'
import {
  asBytes,
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  isAllZero,
  u16Bytes,
  u32Bytes,
  u64Bytes
} from './release-control-primitives.mjs'
import {
  canonicalExpectedPinProjection,
  getVerifiedPinHistoryTerminalSnapshotV1,
  verifyPeeritProfilePinV1
} from './release-control-verifier.mjs'
import {
  hashPeeritValidatorArtifactV1,
  hashPeeritValidatorVectorSetV1
} from './validator-artifact.mjs'
import {
  decodePeeritWebAssetManifestV1,
  encodePeeritWebAssetManifestV1,
  PEERIT_APP_ARTIFACT_PATH_V1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1,
  hashPeeritWebAssetManifestV1,
  verifyPeeritWebAssetContentV1,
  verifyPeeritWebAssetBytesV1
} from './web-asset-manifest.mjs'
import { createBlindCellRelay } from './blind-client-relay.js'
import { preparePeeritPublicInboxAnnouncementV1 } from './inbox-pointer-publish.mjs'
import {
  createPowIssuanceV1AdmissionProviderFactory
} from './pow-issuance-spend-provider.mjs'
import { PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 } from './production-release-authority.mjs'

export { PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 } from './production-release-authority.mjs'

const PEERIT_SEED_BOOTSTRAP_PATH_V1 = '/peerit-seed-bootstrap-v1.json'
const PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE = 13
export const PEERIT_LIMITED_CELL_GET_RELEASE_SEQUENCE = 28
const PEERIT_SEQ29_PUBLIC_INBOX_COORDINATOR_PATH_V1 =
  '/js/substrate/public-inbox-boot-coordinator.mjs'
const HEX_32 = /^[0-9a-f]{64}$/

function browserRuntimeAssetPathsForRelease (releaseSequence) {
  const sequence = BigInt(releaseSequence)
  const limitedCellGet = BigInt(releaseSequence) ===
    BigInt(PEERIT_LIMITED_CELL_GET_RELEASE_SEQUENCE)
  const publicInbox = sequence ===
    BigInt(PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1)
  const paths = Object.entries(PEERIT_BROWSER_RUNTIME_ASSET_PATHS)
    .filter(([name]) => (limitedCellGet ||
      (!name.startsWith('hiveCellGet') && name !== 'limitedCellGetProfile')) &&
      (publicInbox || name !== 'limitedCellPutProfile') &&
      (publicInbox ||
        (!name.startsWith('external') && name !== 'seq29PublicInboxCoordinator')))
    .map(([, path]) => path)
  if (publicInbox) paths.push(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1)
  return paths
}

export const PEERIT_BROWSER_RUNTIME_ASSET_PATHS = Object.freeze({
  appArtifact: PEERIT_APP_ARTIFACT_PATH_V1,
  hiveArtifact: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs',
  hiveManifest: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.manifest.cenc',
  hiveChromiumEvidence: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.chromium-evidence.json',
  hiveCrossHostEvidence: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.cross-host-evidence.json',
  hiveVendorAuthority: '/vendor/hiverelay-blind-client-v1/authority.json',
  limitedCellGetProfile: PEERIT_LIMITED_CELL_GET_PROFILE_PATH_V1,
  hiveCellGetArtifact: PEERIT_LIMITED_CELL_GET_ARTIFACT_PATH_V1,
  hiveCellGetManifest: PEERIT_LIMITED_CELL_GET_MANIFEST_PATH_V1,
  hiveCellGetChromiumEvidence: '/vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.chromium-evidence.json',
  hiveCellGetCrossHostEvidence: '/vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.cross-host-evidence.json',
  hiveCellGetVendorAuthority: '/vendor/hiverelay-blind-cell-get-v1/authority.json',
  limitedCellPutProfile: PEERIT_LIMITED_CELL_PUT_PROFILE_PATH_V1,
  profileSource: '/docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md',
  profileRegistry: '/protocol/peerit-profile-v1.cenc',
  profileVectorManifest: '/protocol/vectors/peerit-profile-v1.manifest.cenc',
  validatorArtifact: '/protocol/validator/peerit-validator-v1.bare.mjs',
  validatorVectorManifest: '/protocol/validator/peerit-validator-v1.manifest.cenc',
  externalWireSpec: '/protocol/external-authority/hiverelay-blind-wire-v1.md',
  externalWireAbi: '/protocol/external-authority/hiverelay-blind-abi-v1.cenc',
  externalWireVectors: '/protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc',
  externalClientFormat: '/protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc',
  externalClientVectors: '/protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc',
  availabilityPolicy: '/protocol/availability-policy-v1.cenc',
  peeritRelayAdapter: '/js/substrate/blind-client-relay.js',
  seq29PublicInboxCoordinator: PEERIT_SEQ29_PUBLIC_INBOX_COORDINATOR_PATH_V1
})

const ASSET_HARD_CAPS = Object.freeze({
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact]: 512 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveArtifact]: 320 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveManifest]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveChromiumEvidence]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCrossHostEvidence]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveVendorAuthority]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.limitedCellGetProfile]: 32 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetArtifact]: 320 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetManifest]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetChromiumEvidence]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetCrossHostEvidence]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetVendorAuthority]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.limitedCellPutProfile]: 32 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileSource]: 512 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry]: 1024 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileVectorManifest]: 128 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact]: 1024 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorVectorManifest]: 256 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalWireSpec]: 512 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalWireAbi]: 1024 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalWireVectors]: 256 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalClientFormat]: 512 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalClientVectors]: 256 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.availabilityPolicy]: 4 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.peeritRelayAdapter]: 128 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.seq29PublicInboxCoordinator]: 128 * 1024,
  [PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1]: 256 * 1024
})
const MAX_RUNTIME_BOOT_BYTES = 4 * 1024 * 1024
const MAX_WEB_ASSET_MANIFEST_BYTES = 2269742
const ASSET_FETCH_DEADLINE_MILLIS = 10000
const RUNTIME_ASSEMBLY_DEADLINE_MILLIS = 30000
const MAX_COMPLETE_WEB_ASSET_BYTES = 64 * 1024 * 1024
const MAX_COMPLETE_WEB_ASSET_BYTES_PER_ASSET = 16 * 1024 * 1024
const MAX_COMPLETE_WEB_ASSET_FETCH_CONCURRENCY = 8

export const PEERIT_BROWSER_RUNTIME_ASSEMBLY_STATUS = Object.freeze({
  deterministicHiveVendoringReady: true,
  hiveArtifactReleaseEvidenceVerifierReady: true,
  signedWebAssetManifestVerifierReady: true,
  completeSignedWebAssetContentFetchReady: true,
  signedProfilePinVerifierReady: true,
  profileArtifactBindingReady: true,
  validatorArtifactBindingReady: true,
  authenticatedLazyModuleImportReady: true,
  cspConstrainedAuthenticatedModuleExecutionReady: true,
  firstVisitExecutingVerifierDistributionReady: false,
  authenticatedProfileExternalCodecDecodersReady: false,
  productionPinAvailable: false,
  productionAppArtifactAvailable: false,
  productionCanonicalWebAssetManifestAvailable: false,
  releaseReady: false,
  releaseBlockers: Object.freeze([
    'PRODUCTION_PEERIT_SIGNED_PROFILE_PIN_UNAVAILABLE',
    'PRODUCTION_APP_DISTRIBUTION_ARTIFACT_UNAVAILABLE',
    'PRODUCTION_CANONICAL_WEB_ASSET_MANIFEST_UNAVAILABLE',
    'AUTHENTICATED_PROFILE_EXTERNAL_CODEC_DECODERS_UNASSEMBLED',
    'FIRST_VISIT_EXECUTING_VERIFIER_ORIGIN_BOOTSTRAP_UNRESOLVED'
  ])
})

const VERIFIED_AUTHORITIES = new WeakMap()
const VERIFIED_SEED_BOOTSTRAPS = new WeakMap()
const VERIFIED_PUBLIC_INBOX_BOOTSTRAPS = new WeakMap()
const LEASE_EPOCH_MILLIS = 21600000n
const REQUIRED_CONTROL_EXPORTS = Object.freeze([
  'BlindDescriptorBootstrapHttpClient',
  'BlindDirectHttpClient',
  'BlindRelayQualifier',
  'DescriptorTrustStore',
  'createAdmissionParametersRequest',
  'createBrowserCryptoRuntime',
  'createAppendInboxRequest',
  'createCellReplica',
  'createDescribeGetRequest',
  'createGetCellRequest',
  'createReadInboxRequest',
  'decodeBlindExternalProfileValueV1',
  'qualifyDescribeControlEndpoint',
  'openVerifiedCellGetResult',
  'trustedAdmissionProfile',
  'trustedDescriptorValidity',
  'verifiedAdmissionParametersValidity',
  'verifiedEndpointContext',
  'verifiedHealthValidity',
  'verifyAdmissionParametersBytes',
  'verifyDescriptorBytes',
  'verifyOperationResult'
])

function fail (code, message, cause = undefined) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

function bytes (value, field, length = null) {
  const output = new Uint8Array(asBytes(value, field))
  if (length != null && output.byteLength !== length) fail('BAD_BROWSER_RUNTIME_AUTHORITY', `${field} must be ${length} bytes`)
  return output
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_BROWSER_RUNTIME_AUTHORITY', `${field} is not an unsigned integer`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    fail('BAD_BROWSER_RUNTIME_AUTHORITY', `${field} is outside u64`)
  }
  return value
}

function sameTuple (left, right) {
  return left && right && ['specHash', 'abiHash', 'vectorSetHash'].every(field =>
    bytesEqual(left[field], right[field]))
}

function exactExternalBindings (registry, hiveManifest) {
  const wire = `wire-v1:${bytesToHex(hiveManifest.specHash)}:${bytesToHex(hiveManifest.abiHash)}:${bytesToHex(hiveManifest.vectorSetHash)}`
  const client = `client-composition-v1:${bytesToHex(hiveManifest.clientCompositionFormatHash)}:${bytesToHex(hiveManifest.clientCompositionVectorSetHash)}`
  const rows = registry.externalCodecImports
  if (!Array.isArray(rows) || rows.length !== 6 ||
      rows.some(row => row.authorityKind === 'WIRE_TUPLE_V1'
        ? row.tupleBinding !== wire
        : row.authorityKind === 'CLIENT_COMPOSITION_V1'
          ? row.tupleBinding !== client
          : true)) {
    fail('BROWSER_RUNTIME_EXTERNAL_AUTHORITY_MISMATCH',
      'profile registry does not import the exact authenticated HiveRelay browser authorities')
  }
}

function requireAsset (assets, path) {
  if (!assets.has(path)) fail('BROWSER_RUNTIME_ASSET_MISSING', `${path} is unavailable`)
  return bytes(assets.get(path), path)
}

function snapshotAssets (value) {
  const source = value instanceof Map ? value : new Map(Object.entries(value || {}))
  const output = new Map()
  for (const [path, value] of source) output.set(path, bytes(value, path))
  return output
}

function assertControlModule (control) {
  if (!control || typeof control !== 'object') fail('BLIND_CLIENT_BROWSER_MODULE_INVALID', 'blind-client browser module is unavailable')
  for (const name of REQUIRED_CONTROL_EXPORTS) {
    if (typeof control[name] !== 'function') {
      fail('BLIND_CLIENT_BROWSER_MODULE_INVALID', `blind-client browser module is missing ${name}`)
    }
  }
  for (const name of [
    'createInboxReplica', 'createWatchInboxRequest', 'createRenewInboxRequest',
    'createCloseInboxRequest', 'destroyInboxWriteCapability'
  ]) {
    if (name in control) {
      fail('BLIND_CLIENT_BROWSER_MODULE_INVALID',
        `public browser module exposes forbidden INBOX lifecycle constructor ${name}`)
    }
  }
}

function assertCellGetControlModule (control) {
  if (!control || typeof control !== 'object' ||
      Object.keys(control).sort().join('\0') !==
        ['createBlindCellGetControl', 'createBrowserCryptoRuntime'].sort().join('\0') ||
      typeof control.createBlindCellGetControl !== 'function' ||
      typeof control.createBrowserCryptoRuntime !== 'function') {
    fail('BLIND_CLIENT_CELL_GET_BROWSER_MODULE_INVALID',
      'limited blind-client browser module is not the exact two-export Cell-GET surface')
  }
}

function exactClock (clock = {}) {
  const unixMillis = clock.unixMillis == null ? Date.now() : Number(clock.unixMillis)
  const monotonicMillis = clock.monotonicMillis == null
    ? (globalThis.performance && typeof globalThis.performance.now === 'function'
        ? globalThis.performance.now()
        : 0)
    : Number(clock.monotonicMillis)
  if (!Number.isSafeInteger(unixMillis) || unixMillis < 0 || !Number.isFinite(monotonicMillis) || monotonicMillis < 0) {
    fail('BROWSER_RUNTIME_CLOCK_INVALID', 'browser runtime clock snapshot is invalid')
  }
  return Object.freeze({ unixMillis, monotonicMillis })
}

function epochDeadline (snapshot, epoch) {
  const epochValue = u64(epoch, 'lease epoch')
  const unixDeadline = epochValue * LEASE_EPOCH_MILLIS
  const delta = Number(unixDeadline - BigInt(snapshot.unixMillis))
  if (!Number.isSafeInteger(delta)) fail('BROWSER_RUNTIME_CLOCK_INVALID', 'lease epoch deadline is outside the browser clock range')
  return snapshot.monotonicMillis + delta
}

function monotonicNow () {
  const value = globalThis.performance &&
    typeof globalThis.performance.now === 'function'
    ? globalThis.performance.now()
    : 0
  if (!Number.isFinite(value) || value < 0) {
    fail('BROWSER_RUNTIME_CLOCK_INVALID', 'browser monotonic clock is invalid')
  }
  return value
}

function authenticatedRuntimeClock (snapshot) {
  return Object.freeze({
    monotonicMillis: monotonicNow,
    unixMillis () {
      const elapsed = monotonicNow() - snapshot.monotonicMillis
      if (!Number.isFinite(elapsed) || elapsed < 0) {
        fail('BROWSER_RUNTIME_CLOCK_INVALID',
          'browser monotonic clock moved behind the authenticated runtime snapshot')
      }
      const value = snapshot.unixMillis + Math.floor(elapsed)
      if (!Number.isSafeInteger(value) || value < 0) {
        fail('BROWSER_RUNTIME_CLOCK_INVALID', 'browser runtime time is outside the safe range')
      }
      return BigInt(value)
    }
  })
}

function expectedProjection (pin, values) {
  const expected = canonicalExpectedPinProjection(pin)
  expected.emitSubstrate = values.emitSubstrate
  expected.profileSpecHash = values.profileSpecHash
  expected.profileAbiHash = values.profileAbiHash
  expected.profileVectorSetHash = values.profileVectorSetHash
  expected.validatorArtifactHash = values.validatorArtifactHash
  expected.validatorVectorSetHash = values.validatorVectorSetHash
  expected.availabilityPolicyHash = values.availabilityPolicyHash
  expected.appArtifactHash = values.appArtifactHash
  expected.webAssetManifestHash = values.webAssetManifestHash
  expected.releaseAuthorityPublicKey = values.releaseAuthorityPublicKey
  expected.releaseSequence = values.releaseSequence
  return expected
}

function base64Bytes (value) {
  if (typeof btoa !== 'function') {
    fail('BROWSER_RUNTIME_IMPORT_UNAVAILABLE', 'browser base64 encoding is unavailable')
  }
  let binary = ''
  for (const byte of value) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function moduleLoadError (code, canonicalPath, cause = null) {
  const error = new Error(`authenticated module import failed for ${canonicalPath}`)
  error.code = code
  if (cause != null) error.cause = cause
  return error
}

// The already authenticated bytes are converted to an SRI digest and executed
// from their canonical same-origin URL. The following import resolves the same
// URL from the browser module map; a second network response is never trusted.
// This works with the production `script-src 'self'` policy and does not need a
// Blob, data URL, unsafe-eval, nonce, or caller-selected importer.
export async function importAuthenticatedSameOriginModuleV1 ({
  bytes: moduleBytes,
  canonicalPath,
  document: moduleDocument = globalThis.document,
  crypto: cryptoRuntime = globalThis.crypto,
  timeoutMillis = ASSET_FETCH_DEADLINE_MILLIS
}) {
  const authenticatedBytes = bytes(moduleBytes, `${canonicalPath} authenticated module bytes`)
  if (!moduleDocument || typeof moduleDocument.createElement !== 'function' ||
      !cryptoRuntime || !cryptoRuntime.subtle || typeof cryptoRuntime.subtle.digest !== 'function' ||
      !Number.isSafeInteger(timeoutMillis) || timeoutMillis < 1) {
    fail('BROWSER_RUNTIME_IMPORT_UNAVAILABLE', 'same-origin SRI module execution is unavailable')
  }
  const target = moduleDocument.head || moduleDocument.documentElement
  if (!target || typeof target.appendChild !== 'function') {
    fail('BROWSER_RUNTIME_IMPORT_UNAVAILABLE', 'document has no module-script insertion target')
  }
  const url = canonicalSameOriginUrl(canonicalPath, moduleDocument, canonicalPath)
  const digest = new Uint8Array(await cryptoRuntime.subtle.digest('SHA-384', authenticatedBytes))
  const script = moduleDocument.createElement('script')
  script.type = 'module'
  script.src = url
  script.integrity = `sha384-${base64Bytes(digest)}`
  script.crossOrigin = 'anonymous'
  script.referrerPolicy = 'no-referrer'

  let timer = null
  try {
    await new Promise((resolve, reject) => {
      let settled = false
      const settle = callback => value => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        script.onload = null
        script.onerror = null
        callback(value)
      }
      script.onload = settle(resolve)
      script.onerror = settle(() => reject(moduleLoadError(
        'BROWSER_RUNTIME_MODULE_INTEGRITY_FAILED', canonicalPath)))
      timer = setTimeout(settle(() => reject(moduleLoadError(
        'BROWSER_RUNTIME_MODULE_IMPORT_TIMEOUT', canonicalPath))), timeoutMillis)
      target.appendChild(script)
    })
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(moduleLoadError(
        'BROWSER_RUNTIME_MODULE_IMPORT_TIMEOUT', canonicalPath)), timeoutMillis)
      import(url).then(resolve, reject)
    })
  } catch (cause) {
    if (cause && typeof cause.code === 'string') throw cause
    throw moduleLoadError('BROWSER_RUNTIME_MODULE_IMPORT_FAILED', canonicalPath, cause)
  } finally {
    clearTimeout(timer)
    if (typeof script.remove === 'function') script.remove()
  }
}

export function isVerifiedPeeritBrowserRuntimeAuthority (value) {
  return VERIFIED_AUTHORITIES.has(value)
}

export function getVerifiedPeeritBrowserRuntimeAssembly (value) {
  const record = VERIFIED_AUTHORITIES.get(value)
  if (!record) fail('PEERIT_AUTHENTICATED_RELAY_RUNTIME_AUTHORITY_REQUIRED', 'verified browser runtime authority is required')
  return record
}

export function getVerifiedPeeritBrowserSeedBootstrapV1 (value) {
  const record = VERIFIED_AUTHORITIES.get(value)
  if (!record) fail('PEERIT_AUTHENTICATED_RELAY_RUNTIME_AUTHORITY_REQUIRED', 'verified browser runtime authority is required')
  const seedBootstrap = VERIFIED_SEED_BOOTSTRAPS.get(value)
  if (!seedBootstrap) {
    fail('PEERIT_AUTHENTICATED_SEED_BOOTSTRAP_REQUIRED', 'verified browser runtime has no release-bound seed bootstrap')
  }
  return Object.freeze({
    artifactBytes: seedBootstrap.artifactBytes.slice(),
    verification: Object.freeze({ ...seedBootstrap.verification })
  })
}

export function getVerifiedPeeritBrowserPublicInboxBootstrapV1 (value) {
  const record = VERIFIED_AUTHORITIES.get(value)
  if (!record) fail('PEERIT_AUTHENTICATED_RELAY_RUNTIME_AUTHORITY_REQUIRED', 'verified browser runtime authority is required')
  const publicInbox = VERIFIED_PUBLIC_INBOX_BOOTSTRAPS.get(value)
  if (!publicInbox) {
    fail('PEERIT_AUTHENTICATED_PUBLIC_INBOX_BOOTSTRAP_REQUIRED',
      'verified browser runtime has no release-bound public INBOX bootstrap')
  }
  return Object.freeze({
    appArtifactBytes: publicInbox.appArtifactBytes.slice(),
    bootstrapBytes: publicInbox.bootstrapBytes.slice(),
    verification: Object.freeze({ ...publicInbox.verification })
  })
}

function authenticatedSeedBootstrap (appArtifactBytes, assets, manifest, releaseSequence) {
  if (Number(releaseSequence) < PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE) {
    if (manifest.recommendedBootstrapHashes.length !== 0 || assets.has(PEERIT_SEED_BOOTSTRAP_PATH_V1)) {
      fail('PRODUCTION_SEED_BOOTSTRAP_UNEXPECTED', 'pre-sequence-13 runtime cannot carry a seed bootstrap')
    }
    return null
  }
  let appArtifact
  try { appArtifact = JSON.parse(new TextDecoder().decode(appArtifactBytes)) } catch {
    fail('PRODUCTION_APP_ARTIFACT_INVALID', 'the exact app-distribution artifact is not valid JSON')
  }
  if (!appArtifact || appArtifact.schema !== 'peerit-app-artifact-v1' ||
      appArtifact.releaseSequence !== Number(releaseSequence)) {
    fail('PRODUCTION_APP_ARTIFACT_INVALID', 'the app-distribution artifact release identity is invalid')
  }
  if (appArtifact.peeritSeedBootstrap !== PEERIT_SEED_BOOTSTRAP_PATH_V1 ||
      !HEX_32.test(String(appArtifact.peeritSeedBootstrapSha256 || '')) ||
      !HEX_32.test(String(appArtifact.peeritSeedDiscoveryAuthorityPublicKey || '')) ||
      appArtifact.peeritSeedBootstrapReleaseSequence !== Number(releaseSequence) ||
      manifest.recommendedBootstrapHashes.length !== 1) {
    fail('PRODUCTION_SEED_BOOTSTRAP_BINDING_INVALID', 'sequence-13+ app artifact does not bind one exact seed bootstrap')
  }
  const artifactBytes = requireAsset(assets, PEERIT_SEED_BOOTSTRAP_PATH_V1)
  return Promise.resolve(hashBytes(artifactBytes)).then(rawHash => {
    if (rawHash !== appArtifact.peeritSeedBootstrapSha256 ||
        !bytesEqual(hashPeeritBootstrapV1(artifactBytes), manifest.recommendedBootstrapHashes[0])) {
      fail('PRODUCTION_SEED_BOOTSTRAP_BINDING_MISMATCH', 'seed bootstrap bytes do not match the app/profile release bindings')
    }
    return Object.freeze({
      artifactBytes: artifactBytes.slice(),
      verification: Object.freeze({
        authorityPublicKey: appArtifact.peeritSeedDiscoveryAuthorityPublicKey,
        releaseSequence: appArtifact.peeritSeedBootstrapReleaseSequence,
        expectedArtifactHash: appArtifact.peeritSeedBootstrapSha256,
        previousBootstrapHash: null
      })
    })
  })
}

async function authenticatedPublicInboxBootstrap (
  appArtifactBytes, assets, releaseSequence) {
  if (Number(releaseSequence) !== PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1) return null
  let appArtifact
  try { appArtifact = JSON.parse(new TextDecoder().decode(appArtifactBytes)) } catch {
    fail('PRODUCTION_APP_ARTIFACT_INVALID', 'the exact app-distribution artifact is not valid JSON')
  }
  const bootstrapPath = PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1
  const coordinatorPath = PEERIT_SEQ29_PUBLIC_INBOX_COORDINATOR_PATH_V1.slice(1)
  const cellPutProfilePath = PEERIT_LIMITED_CELL_PUT_PROFILE_PATH_V1.slice(1)
  if (!appArtifact || appArtifact.schema !== 'peerit-app-artifact-v1' ||
      appArtifact.releaseSequence !== PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1 ||
      appArtifact.peeritLimitedPublicInboxBootstrap !== bootstrapPath ||
      !HEX_32.test(String(appArtifact.peeritLimitedPublicInboxBootstrapSha256 || '')) ||
      !HEX_32.test(String(appArtifact.peeritLimitedPublicInboxBootstrapAuthorityPublicKey || '')) ||
      appArtifact.peeritLimitedPublicInboxBootstrapReleaseSequence !==
        PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1 ||
      !appArtifact.files || typeof appArtifact.files !== 'object' ||
      appArtifact.files[bootstrapPath.slice(1)] !==
        appArtifact.peeritLimitedPublicInboxBootstrapSha256 ||
      !HEX_32.test(String(appArtifact.files[coordinatorPath] || '')) ||
      !HEX_32.test(String(appArtifact.files[cellPutProfilePath] || ''))) {
    fail('PRODUCTION_PUBLIC_INBOX_BOOTSTRAP_BINDING_INVALID',
      'sequence-29 app artifact does not bind one exact public INBOX bootstrap and coordinator')
  }
  const bootstrapBytes = requireAsset(assets, bootstrapPath)
  const coordinatorBytes = requireAsset(
    assets, PEERIT_SEQ29_PUBLIC_INBOX_COORDINATOR_PATH_V1)
  const cellPutProfileBytes = requireAsset(
    assets, PEERIT_LIMITED_CELL_PUT_PROFILE_PATH_V1)
  const [bootstrapSha256, coordinatorSha256, cellPutProfileSha256] = await Promise.all([
    hashBytes(bootstrapBytes),
    hashBytes(coordinatorBytes),
    hashBytes(cellPutProfileBytes)
  ])
  if (bootstrapSha256 !== appArtifact.peeritLimitedPublicInboxBootstrapSha256 ||
      coordinatorSha256 !== appArtifact.files[coordinatorPath] ||
      cellPutProfileSha256 !== appArtifact.files[cellPutProfilePath]) {
    fail('PRODUCTION_PUBLIC_INBOX_BOOTSTRAP_BINDING_MISMATCH',
      'public INBOX bootstrap, coordinator, or frozen Cell-PUT profile differs from the authenticated app binding')
  }
  return Object.freeze({
    appArtifactBytes: appArtifactBytes.slice(),
    bootstrapBytes: bootstrapBytes.slice(),
    verification: Object.freeze({
      authorityPublicKey:
        appArtifact.peeritLimitedPublicInboxBootstrapAuthorityPublicKey,
      releaseSequence: PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
      expectedArtifactHash: bootstrapSha256,
      coordinatorSha256,
      limitedCellPutReleaseSequence: PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE,
      limitedCellPutProfileSha256: cellPutProfileSha256
    })
  })
}

function seq29ReadCellCapabilityBytes (value) {
  const expected = bytes(
    value.expectedCellBlobHash, 'ReadCellCapV1 expected blob hash', 32)
  return concatBytes(
    Uint8Array.of(1),
    bytes(value.relayPublicKey, 'ReadCellCapV1 relay public key', 32),
    bytes(value.storageSlot, 'ReadCellCapV1 storage slot', 32),
    bytes(value.cellKey, 'ReadCellCapV1 cell key', 32),
    Uint8Array.of(value.sizeClass),
    Uint8Array.of(1),
    expected
  )
}

function seq29ReplicaProjection (value) {
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

function seq29RecordId (manifestTag, value) {
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.manifest-record-id.v1'),
    u16Bytes(manifestTag),
    u64Bytes(value.byteLength),
    value
  ))
}

function unsignedRecordPrefix (catalog, schemaName, value) {
  const encoded = catalog[schemaName].encode(value)
  if (encoded.byteLength <= 64 || !isAllZero(encoded.subarray(encoded.byteLength - 64))) {
    fail('PEERIT_SEQ29_SIGNING_PREFIX_INVALID',
      `${schemaName} signature is not the exact final fixed field`)
  }
  return Object.freeze({ encoded, prefix: encoded.slice(0, encoded.byteLength - 64) })
}

async function createSeq29SignedPublication (
  validator, profileValidator, input) {
  const publication = input.publication
  const authorPublicKey = bytes(input.authorPublicKey, 'author public key', 32)
  if (!publication || publication.innerCodec !== 334 ||
      typeof publication.innerLength !== 'number' ||
      publication.innerLength < 8 || publication.innerLength > 1048519 ||
      !Array.isArray(input.replicas) || input.replicas.length !== 2 ||
      typeof input.signAuthorBindV1 !== 'function' ||
      typeof input.signPeeritAnnouncementV1 !== 'function') {
    fail('PEERIT_SEQ29_SIGNED_PUBLICATION_INVALID',
      'an exact intrinsic publication, two replicas, and fixed-domain signers are required')
  }
  const replicas = input.replicas.map((row, index) => {
    const readCap = row && row.readCap
    const request = row && row.request
    const receipt = row && row.receipt
    if (!readCap || !request || !receipt) {
      fail('PEERIT_SEQ29_SIGNED_PUBLICATION_INVALID',
        `replica ${index} lacks its exact PUT request, capability, or receipt`)
    }
    return Object.freeze({
      version: 1,
      logicalHash: bytes(publication.logicalHash, 'logical hash', 32),
      encodingCommitment: bytes(
        publication.encodingCommitment, 'encoding commitment', 32),
      relayPublicKey: bytes(readCap.relayPublicKey, 'relay public key', 32),
      readCapability: seq29ReadCellCapabilityBytes(readCap),
      cellBlobHash: bytes(readCap.expectedCellBlobHash, 'cell blob hash', 32),
      sizeClass: readCap.sizeClass,
      allocationEpoch: request.allocationEpoch,
      leaseEpoch: receipt.leaseEpoch,
      createPublicKey: bytes(request.createPublicKey, 'create public key', 32),
      renewPublicKey: bytes(request.renewPublicKey, 'renew public key', 32),
      dropPublicKey: bytes(request.dropPublicKey, 'drop public key', 32),
      allocationCommitment: bytes(
        row.allocationCommitment, 'allocation commitment', 32),
      relayReceipt: bytes(row.receiptBytes, 'relay receipt')
    })
  }).sort((left, right) => compareBytes(
    seq29ReplicaProjection(left), seq29ReplicaProjection(right)))
  const authorValue = Object.freeze({
    version: 1,
    authorSequence: typeof input.authorSequence === 'bigint'
      ? input.authorSequence
      : BigInt(input.authorSequence),
    previousAuthorRecordId: input.previousAuthorRecordId == null
      ? null
      : bytes(input.previousAuthorRecordId, 'previous AuthorBind record ID', 32),
    logicalHash: bytes(publication.logicalHash, 'logical hash', 32),
    innerCodec: publication.innerCodec,
    innerLength: BigInt(publication.innerLength),
    initialReplicas: replicas,
    authorPublicKey,
    signature: new Uint8Array(64)
  })
  const unsignedAuthor = unsignedRecordPrefix(
    validator.catalog, 'AuthorBindV1', authorValue)
  const authorSignature = bytes(
    await input.signAuthorBindV1(unsignedAuthor.prefix), 'AuthorBindV1 signature', 64)
  const authorBindBytes = validator.catalog.AuthorBindV1.encode(Object.freeze({
    ...authorValue,
    signature: authorSignature
  }))
  profileValidator.validate('AuthorBindV1', authorBindBytes)
  const manifestRecordId = seq29RecordId(3, authorBindBytes)
  const announcementValue = Object.freeze({
    version: 1,
    manifestTag: 3,
    manifestRecordId,
    manifestMode: 1,
    manifestRecord: authorBindBytes,
    manifestReadCaps: Object.freeze([]),
    publishedLeaseEpoch: input.publishedLeaseEpoch,
    publisherPublicKey: authorPublicKey,
    signature: new Uint8Array(64)
  })
  const unsignedAnnouncement = unsignedRecordPrefix(
    validator.catalog, 'PeeritAnnouncementV1', announcementValue)
  const announcementSignature = bytes(
    await input.signPeeritAnnouncementV1(unsignedAnnouncement.prefix),
    'PeeritAnnouncementV1 signature', 64)
  const announcementBytes = validator.catalog.PeeritAnnouncementV1.encode(
    Object.freeze({ ...announcementValue, signature: announcementSignature }))
  profileValidator.validate('PeeritAnnouncementV1', announcementBytes)
  return Object.freeze({
    authorBindBytes,
    authorRecordId: manifestRecordId,
    announcementBytes,
    replicas: Object.freeze(replicas)
  })
}

function runtimeOwnedSeq29ValidationOnlyProfileValidator (
  validatorModule, registry, control, assets) {
  if (typeof validatorModule.authenticatePeeritProfileExternalCodecAuthorityV1 !== 'function') {
    fail('PROFILE_VALIDATOR_RUNTIME_BINDING_MISMATCH',
      'authenticated validator module has no external-codec authority minter')
  }
  const wireArtifacts = Object.freeze({
    specBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalWireSpec),
    abiBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalWireAbi),
    vectorManifestBytes: requireAsset(
      assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalWireVectors)
  })
  const clientArtifacts = Object.freeze({
    formatAuthorityBytes: requireAsset(
      assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalClientFormat),
    vectorManifestBytes: requireAsset(
      assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.externalClientVectors)
  })
  const externalAuthorities = Object.create(null)
  for (const row of registry.externalCodecImports) {
    externalAuthorities[row.name] =
      validatorModule.authenticatePeeritProfileExternalCodecAuthorityV1({
        name: row.name,
        authorityKind: row.authorityKind,
        authorityBinding: row.tupleBinding,
        artifacts: row.authorityKind === 'WIRE_TUPLE_V1'
          ? wireArtifacts
          : clientArtifacts,
        assertCanonical (input, expectedName) {
          if (arguments.length !== 2 || expectedName !== row.name) {
            fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH',
              `${row.name} runtime authority cannot validate another schema`)
          }
          control.decodeBlindExternalProfileValueV1(row.name, input)
        }
      })
  }
  // The generated module's public exact-artifact minter intentionally creates
  // productionTrusted:false codec authorities. That is sufficient only for
  // canonical decode, local semantics, and signature verification. Do not set
  // production:true here: no fixed production contextual-graph authority
  // exists. The wrapper below is a narrow pre-readback validator, and the
  // coordinator must obtain its separate branded CELL.GET/intrinsic readback
  // before any record is accepted or committed.
  const validator = validatorModule.createPeeritValidatorV1({
    externalAuthorities: Object.freeze(externalAuthorities),
    verifySignatures: true
  })
  const acceptedSchemas = new Set(['PeeritAnnouncementV1', 'AuthorBindV1'])
  // The generated validator supplies strict canonical decoding, exact external
  // codec authority and mandatory Ed25519 checks. Contextual acceptance remains
  // deliberately outside this narrow surface: the public-INBOX coordinator
  // requires its separately branded same-relay CELL.GET/intrinsic readback
  // before a decoded record can enter the journal or authorize an APPEND.
  const surface = Object.freeze({
    authorityClass: 'PEERIT_SEQ29_AUTHENTICATED_VALIDATION_ONLY_V1',
    productionValidator: false,
    productionTrustedExternalAuthority: false,
    signatureVerificationRequired: true,
    contextualValidationPerformed: false,
    contextualAcceptanceAuthority: 'peerit-seq29-public-inbox-readback-v1',
    createSignedInlineAuthorBindPublicationV1 (input) {
      if (arguments.length !== 1 || !input || typeof input !== 'object') {
        fail('PEERIT_SEQ29_SIGNED_PUBLICATION_INVALID',
          'one bounded signed-publication input is required')
      }
      return createSeq29SignedPublication(validator, surface, input)
    },
    validate (schemaName, input) {
      if (arguments.length !== 2 || !acceptedSchemas.has(schemaName)) {
        fail('PEERIT_SEQ29_PROFILE_VALIDATOR_SCOPE_INVALID',
          'runtime-owned public INBOX validator is closed to Announcement and AuthorBind')
      }
      const result = validator.validate(schemaName, bytes(input, `${schemaName} bytes`))
      if (result.contextual !== null) {
        fail('PEERIT_SEQ29_PROFILE_VALIDATOR_CONTEXT_INVALID',
          'public INBOX profile validation cannot substitute an unbranded graph result')
      }
      return result
    }
  })
  return surface
}

function sameSeq29AdmissionProfile (actual, expected) {
  return actual && actual.schemeId === expected.schemeId &&
    actual.profileId === expected.profileId &&
    actual.conformanceClass === expected.conformanceClass &&
    actual.roleBits === expected.roleBits &&
    actual.parameterUrl == null && expected.parameterUrl == null
}

function clearCellManagementCapability (writeCap) {
  for (const field of ['createPrivateKey', 'renewPrivateKey', 'dropPrivateKey']) {
    try { writeCap?.[field]?.fill(0) } catch {}
  }
}

function runtimeOwnedSeq29PublicationControl (
  control, profile, trusted) {
  const fetch = trusted.fetch || (typeof globalThis.fetch === 'function'
    ? globalThis.fetch.bind(globalThis)
    : null)
  const subtle = trusted.subtle || globalThis.crypto?.subtle
  let factory = null
  const getFactory = () => {
    if (!factory) {
      factory = createPowIssuanceV1AdmissionProviderFactory({
        profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
        schemeId: PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1,
        issuers: profile.relays.map(relay => Object.freeze({
          relayPublicKey: relay.relayPublicKey,
          issuanceUrl: new TextDecoder('utf-8', { fatal: true }).decode(relay.issuanceUrl)
        })),
        fetch,
        subtle
      })
    }
    return factory
  }
  const relayPin = relayId => profile.relays.find(row => row.relayId === relayId)

  async function verifiedAdmission (input, operation) {
    const relay = relayPin(input.relayId)
    const context = control.verifiedEndpointContext(input.endpoint)
    if (!relay || context.familyId !== operation.familyId ||
        context.operationId !== operation.operationId ||
        !bytesEqual(context.relayPublicKey, relay.relayPublicKey)) {
      fail('PEERIT_SEQ29_ADMISSION_CONTEXT_INVALID',
        `${input.relayId} endpoint is outside the frozen Cell-PUT issuer authority`)
    }
    const advertised = control.trustedAdmissionProfile(
      input.trustedDescriptor, PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1)
    if (!sameSeq29AdmissionProfile(advertised, relay.admissionProfile)) {
      fail('PEERIT_SEQ29_ADMISSION_PROFILE_DRIFT',
        `${input.relayId} descriptor changed the frozen admission profile`)
    }
    const request = control.createAdmissionParametersRequest({
      runtime: input.runtime,
      profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
      schemeId: PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1
    })
    const endpoint = control.qualifyDescribeControlEndpoint({
      trustedDescriptor: input.trustedDescriptor,
      nowEpoch: input.nowEpoch,
      familyId: 1,
      operationId: 3,
      endpointId: 1,
      requiredRoleBits: 49,
      privacyProfileBit: 1,
      transportSupportBit: 1
    })
    const client = input.httpClient || new control.BlindDirectHttpClient({
      runtime: input.runtime,
      fetch
    })
    const response = await client.request({
      endpoint,
      ...request.wire,
      body: request.requestBytes,
      signal: input.signal,
      timeoutMillis: input.timeoutMillis
    })
    if (!response || response.ok !== true) {
      fail('PEERIT_SEQ29_ADMISSION_PARAMETERS_UNAVAILABLE',
        `${input.relayId} did not return signed admission parameters`, response?.error)
    }
    const verified = control.verifyAdmissionParametersBytes(
      response.body, input.trustedDescriptor, advertised, { nowEpoch: input.nowEpoch })
    if (!verified || !bytesEqual(verified.parameterHash, advertised.parameterHash)) {
      fail('PEERIT_SEQ29_ADMISSION_PARAMETERS_UNTRUSTED',
        `${input.relayId} admission parameters differ from the current descriptor`)
    }
    return Object.freeze({ relay, context, verified, advertised })
  }

  async function providerFor (factory, input, operation) {
    const admission = await verifiedAdmission(input, operation)
    return factory.createAdmissionProvider({
      endpointContext: admission.context,
      verifiedAdmissionParameters: admission.verified,
      admissionProfile: admission.advertised,
      signal: input.signal
    })
  }

  return Object.freeze({
    qualificationProfile: Object.freeze({
      supportedProtocolProfiles: profile.supportedProtocolProfiles,
      supportedTransportProfiles: profile.supportedTransportProfiles
    }),

    async createDualCellReplicasV1 (input = {}) {
      if (!Array.isArray(input.rows) || input.rows.length !== 2) {
        fail('PEERIT_SEQ29_CELL_PUT_INVALID',
          'two exact authenticated relay publications are required')
      }
      const relayIds = new Set()
      for (const row of input.rows) {
        const relay = row && relayPin(row.relayId)
        if (!relay || relayIds.has(row.relayId) || !row.binding ||
            !bytesEqual(row.binding.relayPublicKey, relay.relayPublicKey)) {
          fail('PEERIT_SEQ29_CELL_PUT_INVALID',
            'the dual CELL.PUT rows must cover each frozen relay identity exactly once')
        }
        if (!row.publication || !Number.isInteger(row.publication.sizeClass) ||
            row.publication.sizeClass < 1 ||
            row.publication.sizeClass > profile.powIssuance.maximumCellSizeClass) {
          fail('PEERIT_SEQ29_CELL_PUT_INVALID',
            'the authored publication exceeds the frozen Cell-PUT size authority')
        }
        relayIds.add(row.relayId)
      }
      if (relayIds.size !== profile.relays.length ||
          profile.relays.some(relay => !relayIds.has(relay.relayId))) {
        fail('PEERIT_SEQ29_CELL_PUT_INVALID',
          'the dual CELL.PUT rows differ from the frozen two-relay authority')
      }
      const pow = getFactory()
      const providers = await Promise.all(input.rows.map(row => providerFor(
        pow, row, Object.freeze({ familyId: 2, operationId: 1 }))))
      const session = pow.beginRecord({
        relayPublicKeys: input.rows.map(row => row.binding.relayPublicKey)
      })
      try {
        return Object.freeze(await Promise.all(input.rows.map(async (row, index) => {
          let created
          try {
            created = await control.createCellReplica({
              runtime: row.runtime,
              relayPublicKey: row.binding.relayPublicKey,
              allocationEpoch: row.allocationEpoch,
              sizeClass: row.publication.sizeClass,
              leaseClass: profile.powIssuance.maximumCellLeaseClass,
              structuredContent: row.publication.innerBytes,
              admissionProvider: providers[index]
            })
            return Object.freeze({
              relayId: row.relayId,
              request: structuredClone(created.request),
              requestBytes: bytes(created.requestBytes, 'CELL.PUT request bytes').slice(),
              requestCommitment: bytes(
                created.requestCommitment, 'CELL.PUT request commitment', 32).slice(),
              wire: structuredClone(created.wire),
              readCap: structuredClone(created.readCap),
              allocationCommitment: bytes(
                created.allocationCommitment, 'CELL.PUT allocation commitment', 32).slice()
            })
          } finally {
            clearCellManagementCapability(created?.writeCap)
          }
        })))
      } finally {
        session.close()
      }
    },

    async prepareAppendV1 (input = {}) {
      const pow = getFactory()
      const provider = await providerFor(
        pow, input, Object.freeze({ familyId: 3, operationId: 4 }))
      const session = pow.beginOperationRecord({
        operations: [Object.freeze({
          relayPublicKey: input.binding.relayPublicKey,
          kind: 'append'
        })]
      })
      try {
        return await preparePeeritPublicInboxAnnouncementV1({
          authority: input.authority,
          binding: input.binding,
          control,
          runtime: input.runtime,
          announcementBytes: input.announcementBytes,
          admissionProvider: provider
        })
      } finally {
        session.close()
      }
    }
  })
}

async function assemblePeeritBrowserRuntimeAuthorityInternal (input, trusted) {
  const assets = snapshotAssets(input.assets)
  const pinBytes = bytes(trusted.productionPinBytes, 'production profile pin')
  const expectedPinHash = bytes(trusted.expectedPinHash, 'expected production pin hash', 32)
  const expectedReleaseAuthorityPublicKey = bytes(
    trusted.expectedReleaseAuthorityPublicKey, 'expected release authority public key', 32)
  const expectedReleaseSequence = u64(trusted.expectedReleaseSequence, 'expected release sequence')
  if (!bytesEqual(profilePinHash(pinBytes), expectedPinHash)) {
    fail('PRODUCTION_PROFILE_PIN_HASH_MISMATCH', 'production profile pin does not match the externally witnessed expected hash')
  }
  const pin = decodePeeritHiveRelayProfilePinV1(pinBytes)
  if (!bytesEqual(pin.releaseAuthorityPublicKey, expectedReleaseAuthorityPublicKey) ||
      pin.releaseSequence !== expectedReleaseSequence) {
    fail('PRODUCTION_PROFILE_PIN_AUTHORITY_MISMATCH', 'production profile pin key or release sequence is unexpected')
  }

  const webAssetManifestBytes = bytes(input.webAssetManifestBytes, 'WebAssetManifestV1')
  const webAssetManifest = decodePeeritWebAssetManifestV1(webAssetManifestBytes)
  const webAssetManifestHash = hashPeeritWebAssetManifestV1(webAssetManifestBytes)
  if (webAssetManifest.releaseSequence !== pin.releaseSequence ||
      !bytesEqual(webAssetManifest.appArtifactHash, pin.appArtifactHash) ||
      webAssetManifest.recommendedBootstrapHashes.length !== pin.recommendedBootstrapHashes.length ||
      webAssetManifest.recommendedBootstrapHashes.some((hash, index) =>
        !bytesEqual(hash, pin.recommendedBootstrapHashes[index]))) {
    fail('PRODUCTION_WEB_ASSET_MANIFEST_PIN_MISMATCH',
      'WebAssetManifestV1 release, app, or bootstrap binding does not match the production pin')
  }
  verifyPeeritWebAssetBytesV1(webAssetManifest, assets, {
    requiredPaths: browserRuntimeAssetPathsForRelease(pin.releaseSequence),
    requireComplete: false
  })
  const appArtifactBytes = requireAsset(
    assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact)
  if (!bytesEqual(hashPeeritAppArtifactV1(appArtifactBytes), pin.appArtifactHash)) {
    fail('PRODUCTION_APP_ARTIFACT_PIN_MISMATCH',
      'the exact app-distribution artifact does not match the production pin')
  }
  const seedBootstrap = await authenticatedSeedBootstrap(
    appArtifactBytes, assets, webAssetManifest, pin.releaseSequence)
  const publicInboxBootstrap = await authenticatedPublicInboxBootstrap(
    appArtifactBytes, assets, pin.releaseSequence)
  const limitedCellPutProfile = publicInboxBootstrap
    ? verifyPeeritLimitedCellPutProfileV1(
      requireAsset(assets, PEERIT_LIMITED_CELL_PUT_PROFILE_PATH_V1), {
        // The Seq29 app retains the exact frozen Seq28 authority bytes; it does
        // not reinterpret or reissue them under the newer release sequence.
        releaseSequence: PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE
      })
    : null

  const hive = verifyBlindClientBrowserReleaseV1({
    artifactBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveArtifact),
    manifestBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveManifest),
    chromiumEvidenceBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveChromiumEvidence),
    crossHostEvidenceBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCrossHostEvidence),
    authorityBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveVendorAuthority)
  })
  const hiveCellGet = Number(pin.releaseSequence) === PEERIT_LIMITED_CELL_GET_RELEASE_SEQUENCE
    ? verifyBlindClientCellGetBrowserReleaseV1({
      artifactBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetArtifact),
      manifestBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetManifest),
      chromiumEvidenceBytes: requireAsset(
        assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetChromiumEvidence),
      crossHostEvidenceBytes: requireAsset(
        assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetCrossHostEvidence),
      authorityBytes: requireAsset(
        assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetVendorAuthority)
    })
    : null
  if (hiveCellGet && (!sameTuple(hive.manifest, hiveCellGet.manifest) ||
      !bytesEqual(hive.manifest.clientCompositionFormatHash,
        hiveCellGet.manifest.clientCompositionFormatHash) ||
      !bytesEqual(hive.manifest.clientCompositionVectorSetHash,
        hiveCellGet.manifest.clientCompositionVectorSetHash))) {
    fail('PRODUCTION_HIVERELAY_CELL_GET_TUPLE_MISMATCH',
      'limited Cell-GET artifact does not share the authenticated HiveRelay tuple')
  }
  const limitedCellGetProfileBytes = hiveCellGet
    ? requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.limitedCellGetProfile)
    : null
  if (hiveCellGet) {
    verifyPeeritLimitedCellGetProfileV1(
      limitedCellGetProfileBytes, {
        releaseSequence: Number(pin.releaseSequence),
        hive: hiveCellGet
      })
  }
  const emitSubstrate = Object.freeze({
    specHash: hive.manifest.specHash,
    abiHash: hive.manifest.abiHash,
    vectorSetHash: hive.manifest.vectorSetHash
  })
  if (!sameTuple(pin.emitSubstrate, emitSubstrate)) {
    fail('PRODUCTION_HIVERELAY_TUPLE_MISMATCH', 'production pin does not emit the authenticated browser HiveRelay tuple')
  }

  const profileSourceBytes = requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileSource)
  const profileRegistryBytes = requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry)
  const profileVectorManifestBytes = requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileVectorManifest)
  let registry
  try {
    registry = decodePeeritProfileRegistry(profileRegistryBytes)
  } catch (cause) {
    fail('PROFILE_REGISTRY_INVALID', 'profile registry bytes are invalid or non-canonical', cause)
  }
  if (!bytesEqual(registry.profileSourceBytes, profileSourceBytes)) {
    fail('PROFILE_SOURCE_BINDING_MISMATCH', 'profile registry embeds different source bytes')
  }
  const profileSpecHash = hashPeeritProfileSpec(profileSourceBytes)
  const profileAbiHash = hashPeeritProfileAbi(profileRegistryBytes)
  const profileVectorSetHash = hashPeeritProfileVectorSet(profileVectorManifestBytes)
  exactExternalBindings(registry, hive.manifest)

  const validatorArtifactBytes = requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact)
  const validatorVectorManifestBytes = requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorVectorManifest)
  const validatorArtifactHash = hashPeeritValidatorArtifactV1(validatorArtifactBytes)
  const validatorVectorSetHash = hashPeeritValidatorVectorSetV1(validatorVectorManifestBytes)
  const availabilityPolicyHashValue = availabilityPolicyHash(
    requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.availabilityPolicy))

  const expected = expectedProjection(pin, {
    emitSubstrate,
    profileSpecHash,
    profileAbiHash,
    profileVectorSetHash,
    validatorArtifactHash,
    validatorVectorSetHash,
    availabilityPolicyHash: availabilityPolicyHashValue,
    appArtifactHash: pin.appArtifactHash,
    webAssetManifestHash,
    releaseAuthorityPublicKey: expectedReleaseAuthorityPublicKey,
    releaseSequence: expectedReleaseSequence
  })
  const verifiedPin = await verifyPeeritProfilePinV1(pinBytes, {
    crypto: trusted.crypto,
    expected
  })

  const importModule = trusted.importModule
  const validatorModule = await importModule(Object.freeze({
    kind: 'peerit-validator',
    bytes: validatorArtifactBytes.slice(),
    canonicalPath: PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact
  }))
  if (!validatorModule || !validatorModule.PEERIT_VALIDATOR_PROFILE_BINDING_V1 ||
      typeof validatorModule.createPeeritValidatorV1 !== 'function' ||
      typeof validatorModule.authenticatePeeritProfileExternalCodecAuthorityV1 !== 'function' ||
      !bytesEqual(validatorModule.PEERIT_VALIDATOR_PROFILE_BINDING_V1.profileSpecHash, profileSpecHash) ||
      !bytesEqual(validatorModule.PEERIT_VALIDATOR_PROFILE_BINDING_V1.inventoryCommitment, registry.inventoryCommitment) ||
      validatorModule.PEERIT_VALIDATOR_PROFILE_BINDING_V1.schemaCount !== registry.schemas.length) {
    fail('PROFILE_VALIDATOR_RUNTIME_BINDING_MISMATCH', 'imported validator module is not bound to the authenticated profile')
  }
  const control = await importModule(Object.freeze({
    kind: 'hiverelay-blind-client',
    bytes: hive.artifactBytes.slice(),
    canonicalPath: PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveArtifact
  }))
  assertControlModule(control)
  const cellGetControl = hiveCellGet
    ? await importModule(Object.freeze({
      kind: 'hiverelay-blind-cell-get-client',
      bytes: hiveCellGet.artifactBytes.slice(),
      canonicalPath: PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCellGetArtifact
    }))
    : null
  if (cellGetControl) assertCellGetControlModule(cellGetControl)
  const validationOnlyProfileValidator = Number(pin.releaseSequence) ===
    PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1
    ? runtimeOwnedSeq29ValidationOnlyProfileValidator(
      validatorModule, registry, control, assets)
    : null
  const seq29PublicationControl = limitedCellPutProfile
    ? runtimeOwnedSeq29PublicationControl(control, limitedCellPutProfile, trusted)
    : null
  const clock = exactClock(trusted.clock)
  const runtimeClock = authenticatedRuntimeClock(clock)
  const authority = Object.freeze({
    version: 1,
    releaseSequence: pin.releaseSequence,
    get pinHash () { return expectedPinHash.slice() },
    get releaseAuthorityPublicKey () { return expectedReleaseAuthorityPublicKey.slice() },
    get emitSubstrate () {
      return Object.freeze({
        specHash: emitSubstrate.specHash.slice(),
        abiHash: emitSubstrate.abiHash.slice(),
        vectorSetHash: emitSubstrate.vectorSetHash.slice()
      })
    },
    epochDeadlineMonotonicMillis (epoch) { return epochDeadline(clock, epoch) }
  })
  VERIFIED_AUTHORITIES.set(authority, Object.freeze({
    control,
    limitedCellGet: cellGetControl
      ? Object.freeze({
        control: cellGetControl,
        profileSnapshot () {
          return verifyPeeritLimitedCellGetProfileV1(
            limitedCellGetProfileBytes, {
              releaseSequence: Number(pin.releaseSequence),
              hive: hiveCellGet
            })
        }
      })
      : null,
    registry,
    verifiedPin,
    validatorArtifactAuthenticated: true,
    // General/production validator construction remains unavailable because
    // the fixed production contextual graph authority is not release-ready.
    validatorInstantiationAuthorized: false,
    seq29ValidationOnlyValidatorInstantiationAuthorized:
      validationOnlyProfileValidator != null,
    seq29ValidationOnlyProfileValidator: validationOnlyProfileValidator,
    seq29PublicationControl,
    runtimeClock,
    publicInboxContextualAcceptanceAuthority: validationOnlyProfileValidator &&
      validationOnlyProfileValidator.contextualAcceptanceAuthority,
    createRelayAdapter (options) {
      return createBlindCellRelay({
        ...options,
        blindClient: control,
        control
      })
    }
  }))
  if (seedBootstrap) VERIFIED_SEED_BOOTSTRAPS.set(authority, seedBootstrap)
  if (publicInboxBootstrap) {
    VERIFIED_PUBLIC_INBOX_BOOTSTRAPS.set(authority, publicInboxBootstrap)
  }
  return authority
}

const PUBLIC_FORBIDDEN_AUTHORITY_INPUTS = Object.freeze([
  'productionPinBytes',
  'expectedPinHash',
  'expectedReleaseAuthorityPublicKey',
  'expectedReleaseSequence',
  'crypto',
  'subtle',
  'fetch',
  'clock',
  'importModule',
  'appDistributionArtifactBytes',
  'requireCompleteAssetSet'
])

function authenticatedProductionTerminal (value) {
  if (!PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey) {
    fail('PRODUCTION_PEERIT_RELEASE_AUTHORITY_UNPINNED',
      'no production Peerit release authority is compiled into this release')
  }
  const terminal = getVerifiedPinHistoryTerminalSnapshotV1(value)
  const pinBytes = terminal.terminalPinBytes
  const pin = decodePeeritHiveRelayProfilePinV1(pinBytes)
  const productionKey = bytes(
    PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey, 'production release authority', 32)
  if (!bytesEqual(pin.releaseAuthorityPublicKey, productionKey) ||
      terminal.terminalSequence !== pin.releaseSequence ||
      !bytesEqual(terminal.terminalPinHash, profilePinHash(pinBytes))) {
    fail('PRODUCTION_PROFILE_PIN_AUTHORITY_MISMATCH',
      'verified pin-history terminal does not equal the compiled production authority')
  }
  return Object.freeze({ terminal, pin, pinBytes, productionKey })
}

export async function assemblePeeritBrowserRuntimeAuthorityV1 (input = {}) {
  for (const field of PUBLIC_FORBIDDEN_AUTHORITY_INPUTS) {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      fail('BROWSER_RUNTIME_AUTHORITY_INJECTION', `${field} cannot be supplied to the production authority minter`)
    }
  }
  const { terminal, pinBytes, productionKey } = authenticatedProductionTerminal(
    input.pinHistoryTerminal)
  return assemblePeeritBrowserRuntimeAuthorityInternal(input, Object.freeze({
    productionPinBytes: pinBytes,
    expectedPinHash: terminal.terminalPinHash,
    expectedReleaseAuthorityPublicKey: productionKey,
    expectedReleaseSequence: terminal.terminalSequence,
    crypto: browserReleaseCrypto(),
    subtle: globalThis.crypto?.subtle,
    fetch: typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null,
    clock: undefined,
    importModule: importAuthenticatedSameOriginModuleV1
  }))
}

async function importNodeTestModule ({ bytes, canonicalPath }) {
  try {
    return await import(`data:text/javascript;base64,${Buffer.from(bytes).toString('base64')}`)
  } catch (cause) {
    if (cause && typeof cause.code === 'string') throw cause
    throw moduleLoadError('BROWSER_RUNTIME_MODULE_IMPORT_FAILED', canonicalPath, cause)
  }
}

// This harness is unavailable in browsers and requires an explicit test-process
// environment flag. It exists only so Node can exercise post-verification
// module binding; production always uses the non-injectable Blob importer above.
export async function assemblePeeritBrowserRuntimeAuthorityNodeTestV1 (input = {}) {
  let nodeModule
  try { nodeModule = await import('node:module') } catch {}
  const nodeTest = typeof process === 'object' && process?.versions?.node &&
    process.env.PEERIT_BROWSER_RUNTIME_NODE_TEST === '1' &&
    nodeModule && typeof nodeModule.isBuiltin === 'function' && nodeModule.isBuiltin('node:module')
  if (!nodeTest) fail('BROWSER_RUNTIME_TEST_HARNESS_DISABLED', 'Node browser-runtime test harness is disabled')
  return assemblePeeritBrowserRuntimeAuthorityInternal(input, Object.freeze({
    productionPinBytes: input.productionPinBytes,
    expectedPinHash: input.expectedPinHash,
    expectedReleaseAuthorityPublicKey: input.expectedReleaseAuthorityPublicKey,
    expectedReleaseSequence: input.expectedReleaseSequence,
    crypto: input.crypto,
    subtle: input.subtle || globalThis.crypto?.subtle,
    fetch: input.fetch || (typeof globalThis.fetch === 'function'
      ? globalThis.fetch.bind(globalThis)
      : null),
    clock: input.clock,
    importModule: importNodeTestModule
  }))
}

function meta (document, name) {
  try {
    const element = document && document.querySelector &&
      document.querySelector(`meta[name="${name}"]`)
    return element ? String(element.getAttribute('content') || '').trim() : ''
  } catch {
    return ''
  }
}

function containsAsciiControl (value) {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code < 32 || code === 127) return true
  }
  return false
}

function canonicalSameOriginUrl (value, document, field) {
  if (typeof value !== 'string' ||
      !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(value) ||
      value.includes('%') || value.includes('\\') || value.includes('?') || value.includes('#') ||
      containsAsciiControl(value)) {
    fail('BROWSER_RUNTIME_RELEASE_META_INVALID', `${field} must be a canonical same-origin absolute path`)
  }
  const components = value.split('/').slice(1)
  if (components.some(component => component === '' || component === '.' || component === '..')) {
    fail('BROWSER_RUNTIME_RELEASE_META_INVALID', `${field} contains a forbidden path component`)
  }
  const base = document && document.baseURI ? document.baseURI : globalThis.location?.href
  if (!base) fail('BROWSER_RUNTIME_RELEASE_META_INVALID', 'document base URI is unavailable')
  const url = new URL(value, base)
  const origin = new URL(base).origin
  if (url.origin !== origin || url.pathname !== value) {
    fail('BROWSER_RUNTIME_RELEASE_META_INVALID', `${field} is not same-origin canonical`)
  }
  return url.href
}

function acceptedContentType (path, value) {
  const type = String(value || '').split(';')[0].trim().toLowerCase()
  if (path.endsWith('.mjs') || path.endsWith('.js')) {
    return type === 'text/javascript' || type === 'application/javascript'
  }
  if (path.endsWith('.json')) return type === 'application/json'
  if (path.endsWith('.md')) return type === 'text/markdown' || type === 'text/plain'
  if (path.endsWith('.html')) return type === 'text/html'
  if (path.endsWith('.css')) return type === 'text/css'
  if (path.endsWith('.svg')) return type === 'image/svg+xml'
  if (path.endsWith('.png')) return type === 'image/png'
  if (path.endsWith('.jpg') || path.endsWith('.jpeg')) return type === 'image/jpeg'
  if (path.endsWith('.webp')) return type === 'image/webp'
  if (path.endsWith('.wasm')) return type === 'application/wasm'
  // Opaque binary artifacts (the .cenc family and any other unmapped binary
  // asset): static hosts disagree on the label — most serve
  // application/octet-stream, Render's static host (and its Cloudflare-backed
  // edge) serves binary/octet-stream. Both name an opaque binary body, so
  // both are accepted; HTML/error-page responses remain rejected, and the
  // exact Content-Length and hash bindings are unchanged.
  return type === 'application/octet-stream' || type === 'binary/octet-stream'
}

export async function fetchBoundedPeeritBrowserRuntimeAssetV1 ({
  fetch: fetchFunction,
  url,
  path,
  maximumBytes,
  expectedLength = null,
  signal = null,
  timeoutMillis = ASSET_FETCH_DEADLINE_MILLIS
}) {
  if (typeof fetchFunction !== 'function' || !Number.isSafeInteger(maximumBytes) || maximumBytes < 0 ||
      !Number.isSafeInteger(timeoutMillis) || timeoutMillis < 1) {
    fail('BROWSER_RUNTIME_ASSET_FETCH_FAILED', 'bounded browser runtime fetch input is invalid')
  }
  if (typeof AbortController !== 'function') {
    fail('BROWSER_RUNTIME_ASSET_FETCH_FAILED', 'AbortController is required for bounded runtime fetches')
  }
  const deadline = createDeadlineSignal(signal, timeoutMillis,
    'BROWSER_RUNTIME_ASSET_FETCH_TIMEOUT', `${path} exceeded its fetch deadline`)
  let reader = null
  try {
    const response = await fetchFunction(url, {
      cache: 'reload',
      credentials: 'omit',
      redirect: 'error',
      signal: deadline.signal
    })
    if (!response || !response.body || typeof response.body.getReader !== 'function') {
      fail('BROWSER_RUNTIME_ASSET_STREAM_REQUIRED', `${path} did not provide a bounded response stream`)
    }
    reader = response.body.getReader()
    if (response.ok !== true || (response.url && response.url !== url)) {
      fail('BROWSER_RUNTIME_ASSET_FETCH_FAILED', `${path} did not return an exact non-redirect response`)
    }
    if (!acceptedContentType(path, response.headers && response.headers.get('content-type'))) {
      fail('BROWSER_RUNTIME_ASSET_CONTENT_TYPE_INVALID', `${path} has an unexpected content type`)
    }
    const contentEncoding = String(
      (response.headers && response.headers.get('content-encoding')) || '')
      .split(';')[0].trim().toLowerCase()
    const lengthHeader = response.headers && response.headers.get('content-length')
    if (contentEncoding && contentEncoding !== 'identity') {
      // Compressing edge (e.g. Render's Cloudflare-backed static host): the
      // Content-Length header carries the COMPRESSED size or is absent, while
      // the network layer has already delivered the DECOMPRESSED body. The
      // compressed header therefore cannot be compared to the signed
      // uncompressed bound — instead the decompressed payload itself must
      // satisfy that bound exactly (and the caller still verifies the payload
      // hash against the signed manifest). The strict uncompressed path below
      // is unchanged; the header, when present, must still be an integer.
      if (lengthHeader != null && !/^(?:0|[1-9][0-9]*)$/.test(String(lengthHeader))) {
        fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${path} is missing an exact Content-Length`)
      }
      const chunks = []
      let offset = 0
      while (true) {
        const { done, value } = await readStreamWithSignal(reader, deadline.signal)
        if (done) break
        const chunk = new Uint8Array(asBytes(value, `${path} response chunk`))
        offset += chunk.byteLength
        if (offset > maximumBytes) {
          fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${path} decompressed response exceeds its signed bound`)
        }
        chunks.push(chunk)
      }
      if (expectedLength != null && offset !== expectedLength) {
        fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${path} decompressed response length differs from its signed bound`)
      }
      const output = new Uint8Array(offset)
      let position = 0
      for (const chunk of chunks) {
        output.set(chunk, position)
        position += chunk.byteLength
      }
      return output
    }
    if (!/^(?:0|[1-9][0-9]*)$/.test(String(lengthHeader || ''))) {
      fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${path} is missing an exact Content-Length`)
    }
    const declaredLength = Number(lengthHeader)
    if (!Number.isSafeInteger(declaredLength) || declaredLength > maximumBytes ||
        (expectedLength != null && declaredLength !== expectedLength)) {
      fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${path} Content-Length exceeds or differs from its signed bound`)
    }
    const output = new Uint8Array(declaredLength)
    let offset = 0
    while (true) {
      const { done, value } = await readStreamWithSignal(reader, deadline.signal)
      if (done) break
      const chunk = new Uint8Array(asBytes(value, `${path} response chunk`))
      if (offset + chunk.byteLength > declaredLength) {
        fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${path} response exceeds Content-Length`)
      }
      output.set(chunk, offset)
      offset += chunk.byteLength
    }
    if (offset !== declaredLength) {
      fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${path} response is shorter than Content-Length`)
    }
    return output
  } catch (error) {
    if (reader) {
      try { await reader.cancel(error) } catch {}
    }
    if (deadline.signal.aborted) throw deadline.signal.reason || error
    throw error
  } finally {
    if (reader) {
      try { reader.releaseLock() } catch {}
    }
    deadline.dispose()
  }
}

function boundedWebAssetFetchPolicy (value, field, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    fail('WEB_ASSET_FETCH_POLICY_INVALID', `${field} must be an integer from 1 through ${maximum}`)
  }
  return value
}

function canonicalWebAssetManifest (value) {
  return value && typeof value === 'object' && Array.isArray(value.assets)
    ? decodePeeritWebAssetManifestV1(encodePeeritWebAssetManifestV1(value))
    : decodePeeritWebAssetManifestV1(value)
}

export async function fetchAndVerifyPeeritWebAssetContentV1 (options = {}) {
  if (!options || typeof options !== 'object' || typeof options.fetch !== 'function') {
    fail('WEB_ASSET_FETCH_POLICY_INVALID', 'complete web asset validation requires a fetch function')
  }
  const manifest = canonicalWebAssetManifest(options.manifest)
  const maximumTotalBytes = boundedWebAssetFetchPolicy(
    options.maximumTotalBytes == null ? MAX_COMPLETE_WEB_ASSET_BYTES : options.maximumTotalBytes,
    'maximumTotalBytes', MAX_COMPLETE_WEB_ASSET_BYTES)
  const maximumAssetBytes = boundedWebAssetFetchPolicy(
    options.maximumAssetBytes == null ? MAX_COMPLETE_WEB_ASSET_BYTES_PER_ASSET : options.maximumAssetBytes,
    'maximumAssetBytes', MAX_COMPLETE_WEB_ASSET_BYTES_PER_ASSET)
  const maximumConcurrency = boundedWebAssetFetchPolicy(
    options.maximumConcurrency == null
      ? MAX_COMPLETE_WEB_ASSET_FETCH_CONCURRENCY
      : options.maximumConcurrency,
    'maximumConcurrency', MAX_COMPLETE_WEB_ASSET_FETCH_CONCURRENCY)
  const timeoutMillis = boundedWebAssetFetchPolicy(
    options.timeoutMillis == null ? ASSET_FETCH_DEADLINE_MILLIS : options.timeoutMillis,
    'timeoutMillis', ASSET_FETCH_DEADLINE_MILLIS)
  const document = options.document || globalThis.document
  const base = options.baseUrl || (document && document.baseURI) || globalThis.location?.href
  let baseUrl
  try {
    baseUrl = new URL(base)
  } catch {
    fail('WEB_ASSET_FETCH_ORIGIN_INVALID', 'complete web asset validation requires one canonical base URL')
  }
  if (!['https:', 'http:'].includes(baseUrl.protocol) || baseUrl.username || baseUrl.password) {
    fail('WEB_ASSET_FETCH_ORIGIN_INVALID', 'complete web asset validation requires an HTTP(S) origin')
  }

  // This call performs the runtime-path checks before any network request.
  verifyPeeritWebAssetBytesV1(manifest, new Map(), { requiredPaths: [] })
  const appArtifactPath = PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact
  if (!manifest.assets.some(asset => asset.path === appArtifactPath)) {
    fail('WEB_APP_ARTIFACT_MISSING', `${appArtifactPath} is absent from signed WebAssetManifestV1`)
  }

  let totalBytes = 0
  const plan = manifest.assets.map(asset => {
    const length = Number(asset.byteLength)
    if (!Number.isSafeInteger(length) || length > maximumAssetBytes ||
        totalBytes + length > maximumTotalBytes) {
      fail('WEB_ASSET_FETCH_BUDGET_EXCEEDED', `${asset.path} exceeds the complete web asset fetch budget`)
    }
    totalBytes += length
    return Object.freeze({
      asset,
      length,
      url: canonicalSameOriginUrl(asset.path, { baseURI: baseUrl.href }, asset.path)
    })
  })

  const assets = new Map()
  for (let offset = 0; offset < plan.length; offset += maximumConcurrency) {
    const batch = plan.slice(offset, offset + maximumConcurrency)
    const results = await Promise.allSettled(batch.map(async entry => ({
      path: entry.asset.path,
      bytes: await fetchBoundedPeeritBrowserRuntimeAssetV1({
        fetch: options.fetch,
        url: entry.url,
        path: entry.asset.path,
        maximumBytes: Math.min(maximumAssetBytes, entry.length),
        expectedLength: entry.length,
        signal: options.signal || null,
        timeoutMillis
      })
    })))
    const failed = results.find(result => result.status === 'rejected')
    if (failed) throw failed.reason
    for (const result of results) assets.set(result.value.path, result.value.bytes)
  }

  const verified = verifyPeeritWebAssetContentV1(manifest, assets)

  return Object.freeze({
    releaseSequence: manifest.releaseSequence,
    assets,
    verifiedAssetCount: verified.verifiedAssetCount,
    verifiedTotalBytes: verified.verifiedTotalBytes,
    appArtifactVerified: verified.appArtifactVerified,
    bootstrapAssets: verified.bootstrapAssets,
    complete: verified.complete
  })
}

function deadlineError (code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function createDeadlineSignal (parentSignal, timeoutMillis, code, message) {
  const controller = new AbortController()
  const abortFromParent = () => controller.abort(
    parentSignal.reason || deadlineError('BROWSER_RUNTIME_ASSEMBLY_ABORTED', 'browser runtime assembly was aborted'))
  if (parentSignal && parentSignal.aborted) abortFromParent()
  else if (parentSignal && typeof parentSignal.addEventListener === 'function') {
    parentSignal.addEventListener('abort', abortFromParent, { once: true })
  }
  const timer = setTimeout(() => controller.abort(deadlineError(code, message)), timeoutMillis)
  return Object.freeze({
    signal: controller.signal,
    dispose () {
      clearTimeout(timer)
      if (parentSignal && typeof parentSignal.removeEventListener === 'function') {
        parentSignal.removeEventListener('abort', abortFromParent)
      }
    }
  })
}

function readStreamWithSignal (reader, signal) {
  if (signal.aborted) return Promise.reject(signal.reason)
  return new Promise((resolve, reject) => {
    const aborted = () => reject(signal.reason ||
      deadlineError('BROWSER_RUNTIME_ASSET_FETCH_TIMEOUT', 'runtime asset read was aborted'))
    signal.addEventListener('abort', aborted, { once: true })
    reader.read().then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted))
  })
}

function browserReleaseCrypto (runtime = globalThis.crypto) {
  if (!runtime || !runtime.subtle) fail('RELEASE_CONTROL_CRYPTO_UNAVAILABLE', 'browser WebCrypto is unavailable')
  const subtle = runtime.subtle
  return Object.freeze({
    async verifyEd25519 (publicKey, message, signature) {
      const key = await subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify'])
      return subtle.verify({ name: 'Ed25519' }, key, signature, message)
    }
  })
}

function loadBlocked (code, message) {
  return Object.freeze({
    state: 'blocked-authenticated-browser-runtime',
    active: false,
    releaseBlockers: Object.freeze([code]),
    message
  })
}

export async function loadPeeritBrowserRuntimeAuthorityV1 (options = {}) {
  const document = options.document || globalThis.document
  const webManifestPath = meta(document, 'peerit-production-web-asset-manifest')
  if (!options.pinHistoryTerminal) {
    return loadBlocked('PRODUCTION_PEERIT_SIGNED_PROFILE_PIN_UNAVAILABLE',
      'No module-verified production Peerit pin-history terminal is available.')
  }
  if (!webManifestPath) {
    return loadBlocked('PRODUCTION_CANONICAL_WEB_ASSET_MANIFEST_UNAVAILABLE',
      'No canonical production WebAssetManifestV1 is configured.')
  }
  const fetchFunction = options.fetch || globalThis.fetch?.bind(globalThis)
  if (typeof fetchFunction !== 'function') {
    return loadBlocked('BROWSER_RUNTIME_ASSET_FETCH_UNAVAILABLE', 'Browser fetch is unavailable.')
  }
  const assemblyDeadline = createDeadlineSignal(options.signal,
    RUNTIME_ASSEMBLY_DEADLINE_MILLIS, 'BROWSER_RUNTIME_ASSEMBLY_TIMEOUT',
    'authenticated browser runtime assembly exceeded its deadline')
  try {
    const production = authenticatedProductionTerminal(options.pinHistoryTerminal)
    const webManifestUrl = canonicalSameOriginUrl(
      webManifestPath, document, 'production WebAssetManifestV1')
    const webAssetManifestBytes = await fetchBoundedPeeritBrowserRuntimeAssetV1({
      fetch: fetchFunction,
      url: webManifestUrl,
      path: webManifestPath,
      maximumBytes: MAX_WEB_ASSET_MANIFEST_BYTES,
      signal: assemblyDeadline.signal
    })
    const webAssetManifest = decodePeeritWebAssetManifestV1(webAssetManifestBytes)
    if (webAssetManifest.releaseSequence !== production.pin.releaseSequence ||
        !bytesEqual(hashPeeritWebAssetManifestV1(webAssetManifestBytes),
          production.pin.webAssetManifestHash)) {
      fail('PRODUCTION_WEB_ASSET_MANIFEST_PIN_MISMATCH',
        'fetched WebAssetManifestV1 does not match the verified production pin')
    }
    const signedAssets = new Map(webAssetManifest.assets.map(asset => [asset.path, asset]))
    let runtimeBootBytes = 0
    for (const assetPath of browserRuntimeAssetPathsForRelease(
      production.pin.releaseSequence)) {
      const asset = signedAssets.get(assetPath)
      if (!asset) fail('WEB_ASSET_MISSING', `${assetPath} is absent from signed WebAssetManifestV1`)
      const length = Number(asset.byteLength)
      const hardCap = ASSET_HARD_CAPS[assetPath]
      if (!Number.isSafeInteger(length) || length > hardCap ||
          runtimeBootBytes + length > MAX_RUNTIME_BOOT_BYTES) {
        fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${assetPath} exceeds the runtime asset budget`)
      }
      runtimeBootBytes += length
    }
    const content = await fetchAndVerifyPeeritWebAssetContentV1({
      fetch: fetchFunction,
      manifest: webAssetManifest,
      document,
      signal: assemblyDeadline.signal
    })
    const assets = content.assets
    const authority = await assemblePeeritBrowserRuntimeAuthorityV1({
      assets,
      pinHistoryTerminal: options.pinHistoryTerminal,
      webAssetManifestBytes
    })
    return Object.freeze({
      state: 'authenticated-browser-runtime-ready',
      active: true,
      authority,
      releaseBlockers: Object.freeze([])
    })
  } catch (error) {
    return loadBlocked(error && error.code ? error.code : 'BROWSER_RUNTIME_ASSEMBLY_FAILED',
      (error && error.message) || 'Authenticated browser runtime assembly failed.')
  } finally {
    assemblyDeadline.dispose()
  }
}
