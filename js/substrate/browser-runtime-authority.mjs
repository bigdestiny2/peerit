import { availabilityPolicyHash } from './availability-policy.mjs'
import { verifyBlindClientBrowserReleaseV1 } from './blind-client-browser-verifier.mjs'
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
  bytesEqual,
  bytesToHex
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
  hashPeeritAppArtifactV1,
  hashPeeritWebAssetManifestV1,
  verifyPeeritWebAssetBytesV1
} from './web-asset-manifest.mjs'
import { createBlindCellRelay } from './blind-client-relay.js'
import { PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 } from './production-release-authority.mjs'

export { PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 } from './production-release-authority.mjs'

export const PEERIT_BROWSER_RUNTIME_ASSET_PATHS = Object.freeze({
  appArtifact: '/peerit-app-artifact-v1.json',
  hiveArtifact: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs',
  hiveManifest: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.manifest.cenc',
  hiveChromiumEvidence: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.chromium-evidence.json',
  hiveCrossHostEvidence: '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.cross-host-evidence.json',
  hiveVendorAuthority: '/vendor/hiverelay-blind-client-v1/authority.json',
  profileSource: '/docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md',
  profileRegistry: '/protocol/peerit-profile-v1.cenc',
  profileVectorManifest: '/protocol/vectors/peerit-profile-v1.manifest.cenc',
  validatorArtifact: '/protocol/validator/peerit-validator-v1.bare.mjs',
  validatorVectorManifest: '/protocol/validator/peerit-validator-v1.manifest.cenc',
  availabilityPolicy: '/protocol/availability-policy-v1.cenc',
  peeritRelayAdapter: '/js/substrate/blind-client-relay.js'
})

const ASSET_HARD_CAPS = Object.freeze({
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact]: 512 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveArtifact]: 320 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveManifest]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveChromiumEvidence]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCrossHostEvidence]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveVendorAuthority]: 16 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileSource]: 512 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry]: 1024 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileVectorManifest]: 128 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact]: 1024 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorVectorManifest]: 256 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.availabilityPolicy]: 4 * 1024,
  [PEERIT_BROWSER_RUNTIME_ASSET_PATHS.peeritRelayAdapter]: 128 * 1024
})
const MAX_RUNTIME_BOOT_BYTES = 4 * 1024 * 1024
const MAX_WEB_ASSET_MANIFEST_BYTES = 2269742
const ASSET_FETCH_DEADLINE_MILLIS = 10000
const RUNTIME_ASSEMBLY_DEADLINE_MILLIS = 30000

export const PEERIT_BROWSER_RUNTIME_ASSEMBLY_STATUS = Object.freeze({
  deterministicHiveVendoringReady: true,
  hiveArtifactReleaseEvidenceVerifierReady: true,
  signedWebAssetManifestVerifierReady: true,
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
const LEASE_EPOCH_MILLIS = 21600000n
const REQUIRED_CONTROL_EXPORTS = Object.freeze([
  'BlindDescriptorBootstrapHttpClient',
  'BlindDirectHttpClient',
  'BlindRelayQualifier',
  'DescriptorTrustStore',
  'createAdmissionParametersRequest',
  'createBrowserCryptoRuntime',
  'createCellReplica',
  'decodeBlindExternalProfileValueV1',
  'qualifyDescribeControlEndpoint',
  'trustedAdmissionProfile',
  'trustedDescriptorValidity',
  'verifiedAdmissionParametersValidity',
  'verifiedEndpointContext',
  'verifiedHealthValidity',
  'verifyAdmissionParametersBytes',
  'verifyOperationResult'
])

function fail (code, message) {
  const error = new Error(message)
  error.code = code
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
    requiredPaths: Object.values(PEERIT_BROWSER_RUNTIME_ASSET_PATHS),
    requireComplete: false
  })
  const appArtifactBytes = requireAsset(
    assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact)
  if (!bytesEqual(hashPeeritAppArtifactV1(appArtifactBytes), pin.appArtifactHash)) {
    fail('PRODUCTION_APP_ARTIFACT_PIN_MISMATCH',
      'the exact app-distribution artifact does not match the production pin')
  }

  const hive = verifyBlindClientBrowserReleaseV1({
    artifactBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveArtifact),
    manifestBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveManifest),
    chromiumEvidenceBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveChromiumEvidence),
    crossHostEvidenceBytes: requireAsset(assets, PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCrossHostEvidence)
  })
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
  const registry = decodePeeritProfileRegistry(profileRegistryBytes)
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
  const clock = exactClock(trusted.clock)
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
    registry,
    verifiedPin,
    validatorArtifactAuthenticated: true,
    validatorInstantiationAuthorized: false,
    createRelayAdapter (options) {
      return createBlindCellRelay({
        ...options,
        blindClient: control,
        control
      })
    }
  }))
  return authority
}

const PUBLIC_FORBIDDEN_AUTHORITY_INPUTS = Object.freeze([
  'productionPinBytes',
  'expectedPinHash',
  'expectedReleaseAuthorityPublicKey',
  'expectedReleaseSequence',
  'crypto',
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
    clock: undefined,
    importModule: importAuthenticatedSameOriginModuleV1
  }))
}

async function importNodeTestModule ({ bytes }) {
  return import(`data:text/javascript;base64,${Buffer.from(bytes).toString('base64')}`)
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
  return type === 'application/octet-stream'
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
    const lengthHeader = response.headers && response.headers.get('content-length')
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
    const assets = new Map()
    const signedAssets = new Map(webAssetManifest.assets.map(asset => [asset.path, asset]))
    let totalBytes = 0
    for (const assetPath of Object.values(PEERIT_BROWSER_RUNTIME_ASSET_PATHS)) {
      const asset = signedAssets.get(assetPath)
      if (!asset) fail('WEB_ASSET_MISSING', `${assetPath} is absent from signed WebAssetManifestV1`)
      const length = Number(asset.byteLength)
      const hardCap = ASSET_HARD_CAPS[assetPath]
      if (!Number.isSafeInteger(length) || length > hardCap ||
          totalBytes + length > MAX_RUNTIME_BOOT_BYTES) {
        fail('BROWSER_RUNTIME_ASSET_LENGTH_INVALID', `${assetPath} exceeds the runtime asset budget`)
      }
      totalBytes += length
      const assetUrl = canonicalSameOriginUrl(assetPath, document, assetPath)
      assets.set(assetPath, await fetchBoundedPeeritBrowserRuntimeAssetV1({
        fetch: fetchFunction,
        url: assetUrl,
        path: assetPath,
        maximumBytes: hardCap,
        expectedLength: length,
        signal: assemblyDeadline.signal
      }))
    }
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
