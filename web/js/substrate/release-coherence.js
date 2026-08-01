import { hashBytes } from '../crypto.js'
import { verifyReleaseManifestWithFloor } from '../release-verify.js'
import {
  decodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritWebAssetManifestV1,
  verifyPeeritWebAssetBytesV1
} from './web-asset-manifest.mjs'
import {
  bytesEqual,
  bytesToHex
} from './release-control-primitives.mjs'
import {
  PEERIT_PRODUCTION_PIN_HISTORY_META,
  PEERIT_PRODUCTION_PIN_HISTORY_PATH
} from './production-release-authority.mjs'
import { normalizePeeritReleaseRelayHintsV1 } from './release-relay-hints.mjs'

const RELEASE_FLOOR_PREFIX = 'peerit:web-release-floor:v1:'
const APP_ARTIFACT_PATH = '/peerit-app-artifact-v1.json'
const WEB_ASSET_MANIFEST_PATH = '/peerit-web-assets-v1.cenc'
const SEED_BOOTSTRAP_PATH = '/peerit-seed-bootstrap-v1.json'
const SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE = 13
const MAX_RELEASE_CONTROL_BYTES = 4 * 1024 * 1024
const MAX_RELEASE_MANIFEST_BYTES = 2 * 1024 * 1024
const MAX_RELEASE_SIGNATURE_BYTES = 64 * 1024
const RELEASE_FETCH_TIMEOUT_MILLIS = 10000
const HEX_32 = /^[0-9a-f]{64}$/

function meta (document, name) {
  try {
    const element = document && document.querySelector &&
      document.querySelector(`meta[name="${name}"]`)
    return element ? String(element.getAttribute('content') || '').trim() : ''
  } catch {
    return ''
  }
}

function storageOrNull (value) {
  if (value !== undefined) return value
  try { return globalThis.localStorage || null } catch { return null }
}

function readFloor (storage, key) {
  try {
    const value = JSON.parse((storage && storage.getItem(RELEASE_FLOOR_PREFIX + key)) || 'null')
    return value && typeof value === 'object' ? value : null
  } catch {
    return null
  }
}

function persistFloor (storage, key, floor) {
  try {
    if (!storage) return false
    storage.setItem(RELEASE_FLOOR_PREFIX + key, JSON.stringify(floor))
    return true
  } catch {
    return false
  }
}

function status (state, active, releaseBlockers, message, values = {}) {
  return Object.freeze({
    state,
    active,
    releaseBlockers: Object.freeze([...new Set(releaseBlockers || [])]),
    message,
    ...values
  })
}

function failed (code, message) {
  return status('signed-release-coherence-failed', false, [code], message)
}

async function exactResponseBytes (response, label, maximumBytes = MAX_RELEASE_CONTROL_BYTES) {
  if (!response || response.ok !== true) throw new Error(`${label} HTTP ${response && response.status}`)
  const lengthText = response.headers && response.headers.get('content-length')
  const contentEncoding = String(response.headers && response.headers.get('content-encoding') || '')
    .split(';')[0].trim().toLowerCase()
  const compressed = contentEncoding !== '' && contentEncoding !== 'identity'
  if (lengthText && (!/^(?:0|[1-9][0-9]*)$/.test(lengthText) ||
      Number(lengthText) > maximumBytes)) {
    throw new Error(`${label} has an invalid Content-Length`)
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw new Error(`${label} requires a bounded response stream`)
  }
  const reader = response.body.getReader()
  const chunks = []
  let total = 0
  try {
    while (true) {
      const result = await reader.read()
      if (result.done) break
      const chunk = result.value instanceof Uint8Array
        ? result.value
        : new Uint8Array(result.value)
      total += chunk.byteLength
      // Under content-encoding the header carries the COMPRESSED size (or is
      // absent) while the network layer delivers the DECOMPRESSED body, so the
      // header cannot be compared to the payload length — the signed hash
      // bindings downstream still authenticate every payload byte. Without
      // content-encoding the header must equal the payload exactly (unchanged).
      if (total > maximumBytes || (lengthText && !compressed && total > Number(lengthText))) {
        throw new Error(`${label} exceeds its bounded length`)
      }
      chunks.push(chunk)
    }
  } catch (error) {
    try { await reader.cancel(error) } catch {}
    throw error
  } finally {
    try { reader.releaseLock() } catch {}
  }
  if (total < 1 || (lengthText && !compressed && total !== Number(lengthText))) {
    throw new Error(`${label} exceeds or differs from its bounded length`)
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

async function boundedJsonResponse (response, label, maximumBytes) {
  const bytes = await exactResponseBytes(response, label, maximumBytes)
  let value
  try { value = JSON.parse(new TextDecoder().decode(bytes)) } catch {
    throw new Error(`${label} is not valid bounded JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must contain one JSON object`)
  }
  return value
}

function releaseDeadline (parentSignal) {
  const controller = new AbortController()
  const forward = () => controller.abort(parentSignal.reason ||
    new Error('release verification was aborted by the page lifecycle'))
  if (parentSignal && parentSignal.aborted) forward()
  else if (parentSignal && typeof parentSignal.addEventListener === 'function') {
    parentSignal.addEventListener('abort', forward, { once: true })
  }
  const timer = setTimeout(() => controller.abort(
    new Error(`release verification exceeded ${RELEASE_FETCH_TIMEOUT_MILLIS}ms`)),
  RELEASE_FETCH_TIMEOUT_MILLIS)
  return Object.freeze({
    signal: controller.signal,
    dispose () {
      clearTimeout(timer)
      if (parentSignal && typeof parentSignal.removeEventListener === 'function') {
        parentSignal.removeEventListener('abort', forward)
      }
    }
  })
}

function pageRelayHints (document) {
  const value = meta(document, 'peerit-substrate-relays')
  return value ? value.split(',').map(entry => entry.trim()).filter(Boolean) : []
}

function seedBinding (value, label) {
  const fields = [
    'peeritSeedBootstrap',
    'peeritSeedBootstrapSha256',
    'peeritSeedDiscoveryAuthorityPublicKey',
    'peeritSeedBootstrapReleaseSequence'
  ]
  const present = fields.filter(field => Object.hasOwn(value, field))
  if (value.releaseSequence < SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE) {
    if (present.length !== 0) throw new Error(`${label} cannot bind a seed bootstrap before release sequence 13`)
    return null
  }
  if (present.length !== fields.length || value.peeritSeedBootstrap !== SEED_BOOTSTRAP_PATH ||
      !HEX_32.test(String(value.peeritSeedBootstrapSha256 || '')) ||
      !HEX_32.test(String(value.peeritSeedDiscoveryAuthorityPublicKey || '')) ||
      value.peeritSeedBootstrapReleaseSequence !== value.releaseSequence) {
    throw new Error(`${label} does not bind one exact sequence-13+ Peerit seed bootstrap`)
  }
  return Object.freeze({
    path: value.peeritSeedBootstrap,
    sha256: value.peeritSeedBootstrapSha256,
    authorityPublicKey: value.peeritSeedDiscoveryAuthorityPublicKey,
    releaseSequence: value.peeritSeedBootstrapReleaseSequence
  })
}

function decodeAppArtifact (bytes) {
  let value
  try { value = JSON.parse(new TextDecoder().decode(bytes)) } catch {
    throw new Error('peerit app artifact is not valid JSON')
  }
  if (!value || value.schema !== 'peerit-app-artifact-v1' ||
      value.transport !== 'blind-substrate' || value.substrateProfile !== 'blind-v1' ||
      value.entry !== '/index.html' || value.canonicalWebAssetManifest !== WEB_ASSET_MANIFEST_PATH ||
      !Number.isSafeInteger(value.releaseSequence) || value.releaseSequence < 7 ||
      !HEX_32.test(String(value.releaseKey || '')) ||
      !Array.isArray(value.relayHints) ||
      !value.files || typeof value.files !== 'object' || Array.isArray(value.files)) {
    throw new Error('peerit app artifact has an invalid replacement release identity')
  }
  value.relayHints = normalizePeeritReleaseRelayHintsV1(value.relayHints, 'app artifact')
  value.seedBootstrap = seedBinding(value, 'peerit app artifact')
  return value
}

async function verifyCanonicalBindings ({
  canonicalBytes,
  appArtifactBytes,
  expectedSequence,
  expectedReleaseKey,
  expectedRelayHints,
  expectedProductionPinHistory,
  expectedCanonicalHash,
  expectedAppArtifactHash
}) {
  const canonical = decodePeeritWebAssetManifestV1(canonicalBytes)
  const appArtifact = decodeAppArtifact(appArtifactBytes)
  if (canonical.releaseSequence !== BigInt(expectedSequence) ||
      appArtifact.releaseSequence !== expectedSequence ||
      appArtifact.releaseKey !== expectedReleaseKey ||
      JSON.stringify(appArtifact.relayHints) !== JSON.stringify(expectedRelayHints) ||
      appArtifact.productionPinHistory !== expectedProductionPinHistory) {
    throw new Error('canonical release sequence or release key does not match the page')
  }
  const canonicalHash = bytesToHex(hashPeeritWebAssetManifestV1(canonicalBytes))
  const appArtifactHash = bytesToHex(hashPeeritAppArtifactV1(appArtifactBytes))
  if (expectedCanonicalHash && canonicalHash !== expectedCanonicalHash) {
    throw new Error('canonical WebAssetManifestV1 hash does not match the signed JSON manifest')
  }
  if (expectedAppArtifactHash && appArtifactHash !== expectedAppArtifactHash) {
    throw new Error('app artifact hash does not match the signed JSON manifest')
  }
  if (!bytesEqual(canonical.appArtifactHash, hashPeeritAppArtifactV1(appArtifactBytes))) {
    throw new Error('canonical WebAssetManifestV1 does not bind the exact app artifact')
  }
  if (appArtifact.seedBootstrap) {
    if (canonical.recommendedBootstrapHashes.length !== 1 ||
        !canonical.assets.some(asset => asset.path === SEED_BOOTSTRAP_PATH)) {
      throw new Error('canonical WebAssetManifestV1 does not carry the bound Peerit seed bootstrap')
    }
  } else if (canonical.recommendedBootstrapHashes.length !== 0 ||
      canonical.assets.some(asset => asset.path === SEED_BOOTSTRAP_PATH)) {
    throw new Error('pre-sequence-13 canonical release unexpectedly carries a Peerit seed bootstrap')
  }
  const canonicalHasPinHistory = canonical.assets.some(
    asset => asset.path === PEERIT_PRODUCTION_PIN_HISTORY_PATH)
  if (canonicalHasPinHistory) {
    throw new Error('detached production pin history must not appear in canonical WebAssetManifestV1')
  }
  verifyPeeritWebAssetBytesV1(canonical, new Map([
    [APP_ARTIFACT_PATH, appArtifactBytes]
  ]), { requiredPaths: [APP_ARTIFACT_PATH], requireComplete: false })
  return Object.freeze({
    canonical,
    appArtifact,
    canonicalHash,
    appArtifactHash,
    seedBootstrap: appArtifact.seedBootstrap
  })
}

function contentAddressedProtocol (document) {
  try {
    const protocol = new URL(document.baseURI).protocol
    return protocol === 'hyper:' || protocol === 'pear:'
  } catch {
    return false
  }
}

export async function verifyPeeritReleaseCoherenceV1 (options = {}) {
  const document = options.document || globalThis.document
  const fetchFunction = options.fetch || globalThis.fetch?.bind(globalThis)
  const pinnedKey = meta(document, 'peerit-release-key').toLowerCase()
  const expectedSequence = Number(meta(document, 'peerit-release-sequence'))
  const canonicalPath = meta(document, 'peerit-production-web-asset-manifest')
  const productionPinHistory = meta(document, PEERIT_PRODUCTION_PIN_HISTORY_META) || null
  if (!document || typeof fetchFunction !== 'function') {
    return failed('SIGNED_RELEASE_VERIFIER_UNAVAILABLE', 'Signed release verification is unavailable in this runtime.')
  }
  if (typeof AbortController !== 'function') {
    return failed('SIGNED_RELEASE_VERIFIER_UNAVAILABLE',
      'Signed release verification requires lifecycle-aware fetch cancellation.')
  }
  if (!HEX_32.test(pinnedKey) || !Number.isSafeInteger(expectedSequence) || expectedSequence < 7 ||
      canonicalPath !== WEB_ASSET_MANIFEST_PATH) {
    return failed('SIGNED_RELEASE_PAGE_IDENTITY_INVALID',
      'The page does not carry one valid replacement release key, sequence, and canonical manifest path.')
  }
  if (productionPinHistory !== null &&
      productionPinHistory !== PEERIT_PRODUCTION_PIN_HISTORY_PATH) {
    return failed('SIGNED_RELEASE_PAGE_IDENTITY_INVALID',
      'The page carries a noncanonical production pin-history path.')
  }
  let expectedRelayHints
  try {
    expectedRelayHints = normalizePeeritReleaseRelayHintsV1(pageRelayHints(document), 'page')
  } catch (error) {
    return failed('SIGNED_RELEASE_PAGE_RELAY_HINTS_INVALID', error.message)
  }
  const deadline = releaseDeadline(options.signal)
  const fetchOptions = Object.freeze({
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    signal: deadline.signal
  })
  try {
    const [canonicalResponse, appResponse] = await Promise.all([
      fetchFunction(canonicalPath, fetchOptions),
      fetchFunction(APP_ARTIFACT_PATH, fetchOptions)
    ])
    const [canonicalBytes, appArtifactBytes] = await Promise.all([
      exactResponseBytes(canonicalResponse, 'peerit-web-assets-v1.cenc'),
      exactResponseBytes(appResponse, 'peerit-app-artifact-v1.json')
    ])

    if (contentAddressedProtocol(document)) {
      const bound = await verifyCanonicalBindings({
        canonicalBytes,
        appArtifactBytes,
        expectedSequence,
        expectedReleaseKey: pinnedKey,
        expectedRelayHints,
        expectedProductionPinHistory: productionPinHistory
      })
      return status('content-addressed-release-coherent', true, [],
        `Content-addressed replacement release ${expectedSequence} is internally coherent.`, {
          releaseSequence: expectedSequence,
          canonicalWebAssetManifestHash: bound.canonicalHash,
          appArtifactHash: bound.appArtifactHash,
          relayHints: bound.appArtifact.relayHints,
          seedBootstrap: bound.seedBootstrap,
          productionPinHistory,
          floorPersisted: false
        })
    }

    const [manifestResponse, signatureResponse] = await Promise.all([
      fetchFunction('asset-manifest.json', fetchOptions),
      fetchFunction('asset-manifest.sig', fetchOptions)
    ])
    const [manifest, signature] = await Promise.all([
      boundedJsonResponse(manifestResponse, 'asset-manifest.json', MAX_RELEASE_MANIFEST_BYTES),
      boundedJsonResponse(signatureResponse, 'asset-manifest.sig', MAX_RELEASE_SIGNATURE_BYTES)
    ])
    const verified = await verifyReleaseManifestWithFloor({
      manifest,
      signature,
      expectedKey: pinnedKey,
      expectedSequence,
      floor: readFloor(storageOrNull(options.storage), pinnedKey)
    })
    const release = manifest.webRelease || {}
    if (release.transport !== 'blind-substrate' || release.substrateProfile !== 'blind-v1' ||
        release.releaseKey !== pinnedKey || release.releaseSequence !== expectedSequence ||
        release.canonicalWebAssetManifest !== WEB_ASSET_MANIFEST_PATH ||
        release.appArtifact !== APP_ARTIFACT_PATH ||
        release.productionPinHistory !== productionPinHistory ||
        JSON.stringify(normalizePeeritReleaseRelayHintsV1(
          release.relayHints, 'signed manifest')) !==
          JSON.stringify(expectedRelayHints) ||
        !HEX_32.test(String(release.canonicalWebAssetManifestHash || '')) ||
        !HEX_32.test(String(release.appArtifactHash || ''))) {
      throw new Error('signed JSON manifest does not carry the canonical replacement release bindings')
    }
    const outerSeedBootstrap = seedBinding(release, 'signed JSON manifest')
    if (manifest.files?.[WEB_ASSET_MANIFEST_PATH.slice(1)] !== await hashBytes(canonicalBytes) ||
        manifest.files?.[APP_ARTIFACT_PATH.slice(1)] !== await hashBytes(appArtifactBytes)) {
      throw new Error('signed JSON file hashes do not match the fetched canonical release artifacts')
    }
    const bound = await verifyCanonicalBindings({
      canonicalBytes,
      appArtifactBytes,
      expectedSequence,
      expectedReleaseKey: pinnedKey,
      expectedRelayHints,
      expectedProductionPinHistory: productionPinHistory,
      expectedCanonicalHash: release.canonicalWebAssetManifestHash,
      expectedAppArtifactHash: release.appArtifactHash
    })
    if (JSON.stringify(outerSeedBootstrap) !== JSON.stringify(bound.seedBootstrap) ||
        (outerSeedBootstrap && manifest.files?.[outerSeedBootstrap.path.slice(1)] !==
          outerSeedBootstrap.sha256)) {
      throw new Error('signed JSON manifest and app artifact disagree on the Peerit seed bootstrap binding')
    }
    const floorPersisted = persistFloor(storageOrNull(options.storage), pinnedKey, verified.floor)
    return status('signed-release-coherent', true, [],
      `Signed replacement release ${expectedSequence} is coherent.`, {
        releaseSequence: expectedSequence,
        manifestIdentity: verified.manifestIdentity,
        canonicalWebAssetManifestHash: bound.canonicalHash,
        appArtifactHash: bound.appArtifactHash,
        relayHints: bound.appArtifact.relayHints,
        seedBootstrap: bound.seedBootstrap,
        productionPinHistory,
        floorPersisted
      })
  } catch (error) {
    return failed('SIGNED_RELEASE_COHERENCE_FAILED',
      `The signed release failed validation: ${(error && error.message) || 'unknown validation error'}`)
  } finally {
    deadline.dispose()
  }
}

export function renderPeeritReleaseCoherenceStatusV1 (releaseStatus, options = {}) {
  const document = options.document || globalThis.document
  if (!document || !document.body || typeof document.createElement !== 'function') return
  let banner = document.getElementById('release-manifest-warning')
  if (!banner) {
    banner = document.createElement('div')
    banner.id = 'release-manifest-warning'
    document.body.insertBefore(banner, document.body.firstChild)
  }
  const coherent = releaseStatus && releaseStatus.active === true
  banner.className = `release-coherence-banner ${coherent ? 'ok' : 'bad'}`
  banner.setAttribute('role', coherent ? 'status' : 'alert')
  banner.setAttribute('data-release-coherent', coherent ? 'true' : 'false')
  banner.textContent = coherent
    ? releaseStatus.state === 'content-addressed-release-coherent'
      ? `${releaseStatus.message} The content address is the external byte identity.`
      : `${releaseStatus.message} Full served-byte verification remains available at `
    : `⚠ ${releaseStatus && releaseStatus.message ? releaseStatus.message : 'Release verification failed.'} Treat this page as untrusted; verify externally at `
  if (coherent && releaseStatus.state === 'content-addressed-release-coherent') return
  const link = document.createElement('a')
  link.href = 'verify.html'
  link.textContent = 'verify.html'
  banner.appendChild(link)
  banner.appendChild(document.createTextNode(coherent ? '.' : ' or use the content-addressed Pear build.'))
}
