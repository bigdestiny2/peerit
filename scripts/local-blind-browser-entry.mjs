// Browser half of scripts/local-blind-browser-standup.mjs.
//
// This file is deliberately outside Peerit's production browser entry graph.
// It verifies the vendored HiveRelay browser artifact before importing it,
// qualifies one signed loopback fixture descriptor through the ordinary
// permissionless qualification seam, and installs only the resulting branded
// relay adapter into the existing local-first product runtime.

import { createBlindCellRelay } from '../js/substrate/blind-client-relay.js'
import { verifyBlindClientBrowserReleaseV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
import { createPeeritCapabilityVault } from '../js/substrate/capability-vault.js'
import { createPeeritDescriptorTrustBackend } from '../js/substrate/descriptor-trust-backend.js'
import { createPeeritProductRuntimeV1 } from '../js/substrate/peerit-product-runtime.js'
import { mountPeeritProductUiV1 } from '../js/substrate/peerit-product-ui.js'
import {
  collectPermissionlessRelayCandidates,
  qualifyPermissionlessRelayCandidates
} from '../js/substrate/relay-consumer.js'

const VENDOR_ROOT = '/vendor/hiverelay-blind-client-v1'
const VENDOR_ARTIFACT = `${VENDOR_ROOT}/blind-client-control-v1.mjs`
const MAX_VENDOR_BYTES = 8 * 1024 * 1024
const LOCAL_RUN_STORAGE_KEY = 'peerit:local-blind-browser-run:v1'
const LOCAL_NETWORK_DATABASES = Object.freeze([
  'peerit-substrate-capabilities',
  'peerit-substrate-descriptor-trust'
])
const lifecycle = new AbortController()
let fixtureToken = ''

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function hex (value) {
  let output = ''
  for (const byte of new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) {
    output += byte.toString(16).padStart(2, '0')
  }
  return output
}

function fromHex (value) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) {
    fail('LOCAL_FIXTURE_ENCODING_INVALID', 'local fixture byte marker is not canonical lowercase hexadecimal')
  }
  const output = new Uint8Array(value.length / 2)
  for (let index = 0; index < output.byteLength; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

function revive (value) {
  if (Array.isArray(value)) return value.map(revive)
  if (value && typeof value === 'object') {
    const keys = Object.keys(value)
    if (keys.length === 1 && keys[0] === '$bytes') return fromHex(value.$bytes)
    if (keys.length === 1 && keys[0] === '$bigint' && /^(?:0|[1-9][0-9]*)$/.test(value.$bigint)) {
      return BigInt(value.$bigint)
    }
    const output = {}
    for (const [key, child] of Object.entries(value)) output[key] = revive(child)
    return output
  }
  return value
}

async function exactFetchBytes (path, maximumBytes = MAX_VENDOR_BYTES) {
  const response = await fetch(path, {
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: lifecycle.signal
  })
  if (!response.ok) fail('LOCAL_ASSET_FETCH_FAILED', `${path} returned ${response.status}`)
  const length = response.headers.get('content-length')
  if (!/^(?:0|[1-9][0-9]*)$/.test(String(length || ''))) {
    fail('LOCAL_ASSET_LENGTH_INVALID', `${path} omitted an exact Content-Length`)
  }
  const expected = Number(length)
  if (!Number.isSafeInteger(expected) || expected > maximumBytes) {
    fail('LOCAL_ASSET_LENGTH_INVALID', `${path} exceeded its local verification bound`)
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength !== expected) {
    fail('LOCAL_ASSET_LENGTH_INVALID', `${path} did not reproduce its declared length`)
  }
  return bytes
}

async function exactFetchJson (path, maximumBytes = 1024 * 1024) {
  const bytes = await exactFetchBytes(path, maximumBytes)
  let value
  try { value = JSON.parse(new TextDecoder().decode(bytes)) } catch {
    fail('LOCAL_JSON_INVALID', `${path} is not exact JSON`)
  }
  return revive(value)
}

async function verifiedHiveClient () {
  const [artifactBytes, manifestBytes, chromiumEvidenceBytes, crossHostEvidenceBytes, authority] = await Promise.all([
    exactFetchBytes(VENDOR_ARTIFACT),
    exactFetchBytes(`${VENDOR_ROOT}/blind-client-control-v1.manifest.cenc`),
    exactFetchBytes(`${VENDOR_ROOT}/blind-client-control-v1.chromium-evidence.json`),
    exactFetchBytes(`${VENDOR_ROOT}/blind-client-control-v1.cross-host-evidence.json`),
    exactFetchJson(`${VENDOR_ROOT}/authority.json`)
  ])
  const verified = verifyBlindClientBrowserReleaseV1({
    artifactBytes,
    manifestBytes,
    chromiumEvidenceBytes,
    crossHostEvidenceBytes
  })
  const snapshot = Object.freeze({
    artifactHash: hex(verified.artifactHash),
    manifestHash: hex(verified.manifestHash),
    sourceClosureHash: hex(verified.manifest.sourceClosureHash),
    artifactLength: artifactBytes.byteLength
  })
  if (authority.artifactHash !== snapshot.artifactHash ||
      authority.manifestHash !== snapshot.manifestHash ||
      authority.sourceClosureHash !== snapshot.sourceClosureHash ||
      authority.artifactLength !== snapshot.artifactLength) {
    fail('LOCAL_VENDOR_AUTHORITY_MISMATCH', 'vendored HiveRelay client bytes do not match Peerit authority.json')
  }
  // The launcher caches the artifact once at startup and serves this path only
  // when its digest matches. Verification and execution therefore consume the
  // same immutable in-memory bytes even if the checkout changes concurrently.
  const immutablePath = `/__fixture/vendor/${snapshot.artifactHash}.mjs`
  const control = await import(immutablePath)
  return Object.freeze({ control, snapshot })
}

function fixtureHeaders (input) {
  if (!/^[0-9a-f]{64}$/.test(fixtureToken)) {
    fail('LOCAL_FIXTURE_TOKEN_UNAVAILABLE', 'local fixture request token is unavailable')
  }
  const headers = new Headers(input || undefined)
  headers.set('x-peerit-local-fixture-token', fixtureToken)
  return headers
}

function relayProxyFetch (input, init = {}) {
  const raw = typeof input === 'string' || input instanceof URL
    ? String(input)
    : input && typeof input.url === 'string' ? input.url : ''
  let target
  try { target = new URL(raw) } catch {
    fail('LOCAL_PROXY_TARGET_INVALID', 'HiveRelay client supplied an invalid transport URL')
  }
  if (target.protocol !== 'https:' || target.hostname !== '127.0.0.1' ||
      target.username || target.password || target.hash) {
    fail('LOCAL_PROXY_TARGET_INVALID', 'browser fixture transport is restricted to its loopback HTTPS relay')
  }
  const proxy = new URL('/__fixture/proxy', globalThis.location.origin)
  proxy.searchParams.set('target', target.href)
  return fetch(proxy, {
    ...init,
    headers: fixtureHeaders(init.headers),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: init.signal || lifecycle.signal
  })
}

// Admission needs POST while the generic exact JSON helper is intentionally
// GET-only. Keep this mutation path explicit and bounded.
async function fetchAdmission () {
  const response = await fetch('/__fixture/admission', {
    method: 'POST',
    headers: fixtureHeaders(),
    body: new Uint8Array(0),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: lifecycle.signal
  })
  if (!response.ok) fail('LOCAL_ADMISSION_UNAVAILABLE', `synthetic admission returned ${response.status}`)
  const length = Number(response.headers.get('content-length'))
  if (!Number.isSafeInteger(length) || length < 1 || length > 64 * 1024) {
    fail('LOCAL_ADMISSION_INVALID', 'synthetic admission response length is invalid')
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength !== length) fail('LOCAL_ADMISSION_INVALID', 'synthetic admission response was truncated')
  return revive(JSON.parse(new TextDecoder().decode(bytes)))
}

function fixtureProfile (config) {
  const admission = config.advertisedAdmissionProfile
  const admissionRequirement = config.admissionParametersRequirement
  if (!admission || !admissionRequirement) {
    fail('LOCAL_QUALIFICATION_CONFIG_INVALID', 'fixture omitted its exact admission profile')
  }
  return Object.freeze({
    supportedProtocolProfiles: config.supportedProtocolProfiles,
    supportedTransportProfiles: config.supportedTransportProfiles,
    requirement: config.cellPutRequirement,
    readRequirement: config.cellGetRequirement,
    describeFamilyId: admissionRequirement.familyId,
    admissionParametersOperationId: admissionRequirement.operationId,
    admissionProfile: admission
  })
}

function deleteLocalDatabase (name) {
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.deleteDatabase(name)
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      reject(Object.assign(new Error(`timed out resetting ${name}`), {
        code: 'LOCAL_NETWORK_STATE_RESET_TIMEOUT'
      }))
    }, 5000)
    const finish = (callback, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      callback(value)
    }
    request.onsuccess = () => finish(resolve)
    request.onerror = () => finish(reject, request.error)
    request.onblocked = () => finish(reject, Object.assign(
      new Error(`${name} reset is blocked by another local stand-up tab`),
      { code: 'LOCAL_NETWORK_STATE_RESET_BLOCKED' }
    ))
  })
}

async function resetLocalNetworkStateForRun (runId) {
  if (!/^[0-9a-f]{32}$/.test(runId || '') || !globalThis.indexedDB) {
    fail('LOCAL_RUN_ID_INVALID', 'local browser run identity or IndexedDB is unavailable')
  }
  let previous
  try { previous = globalThis.localStorage.getItem(LOCAL_RUN_STORAGE_KEY) } catch {
    fail('LOCAL_RUN_STATE_UNAVAILABLE', 'local browser run marker storage is unavailable')
  }
  if (previous === runId) return false
  await Promise.all(LOCAL_NETWORK_DATABASES.map(deleteLocalDatabase))
  try { globalThis.localStorage.setItem(LOCAL_RUN_STORAGE_KEY, runId) } catch {
    fail('LOCAL_RUN_STATE_UNAVAILABLE', 'local browser run marker could not be persisted')
  }
  return true
}

async function qualifyFixture ({ config, control, capabilityVault }) {
  if (!config || config.localTestOnly !== true ||
      config.schema !== 'HiveRelayRealBlindBrowserQualificationConfigV1') {
    fail('LOCAL_QUALIFICATION_CONFIG_INVALID', 'HiveRelay did not return its branded local-only browser config')
  }
  const runtime = control.createBrowserCryptoRuntime(globalThis.crypto)
  const descriptorBackend = createPeeritDescriptorTrustBackend()
  const root = config.candidate.continuityRootRelayPublicKey
  const storeId = config.candidate.storeId
  if (!(root instanceof Uint8Array) || root.byteLength !== 32 ||
      !(storeId instanceof Uint8Array) || storeId.byteLength !== 32) {
    fail('LOCAL_QUALIFICATION_CONFIG_INVALID', 'fixture relay continuity identity is incomplete')
  }
  const descriptorKey = `descriptor:${hex(root)}:${hex(storeId)}`
  const existing = await descriptorBackend.read(descriptorKey)
  const trustStore = new control.DescriptorTrustStore(descriptorBackend)
  if (existing.version === 0) {
    const genesis = control.verifyDescriptorBytes(config.genesis.descriptorBytes, {
      nowEpoch: config.currentEpoch,
      supportedProtocolProfiles: config.supportedProtocolProfiles,
      supportedTransportProfiles: config.supportedTransportProfiles
    })
    await trustStore.accept(genesis, {
      pinnedDescriptorHash: config.genesis.descriptorHash,
      continuityRootRelayPublicKey: root
    })
  }
  const canonicalUrl = config.candidate.canonicalUrl instanceof Uint8Array
    ? new TextDecoder().decode(config.candidate.canonicalUrl)
    : String(config.candidate.canonicalUrl || '')
  const candidates = collectPermissionlessRelayCandidates({
    user: [{
      ...config.candidate,
      canonicalUrl
    }]
  })
  const qualification = await qualifyPermissionlessRelayCandidates({
    control,
    blindClient: control,
    cryptoRuntime: runtime,
    nowEpoch: () => config.currentEpoch,
    monotonicMillis: () => globalThis.performance.now(),
    profile: fixtureProfile(config),
    candidates,
    trustStore,
    fetch: relayProxyFetch,
    timeoutMillis: 15_000,
    totalQualificationTimeoutMillis: 60_000,
    signal: lifecycle.signal,
    admissionProvider: fetchAdmission,
    persistPreparedReplica: capabilityVault.persistPreparedReplica,
    persistVerifiedResult: capabilityVault.persistVerifiedResult,
    persistVerifiedReadback: capabilityVault.persistVerifiedReadback,
    loadPersistedReplica: capabilityVault.load,
    createRelayAdapter: options => createBlindCellRelay({
      ...options,
      blindClient: control,
      control
    })
  })
  if (qualification.adapters.length !== 1 || qualification.status.state !== 'qualified') {
    const failureCodes = qualification.failures.map(failure => failure.code)
    const code = failureCodes[0]
    fail(
      code || 'LOCAL_RELAY_NOT_QUALIFIED',
      `the real loopback HiveRelay did not qualify exactly once (${failureCodes.join(',') || 'no failure code'})`
    )
  }
  return qualification
}

const state = {
  schema: 'PeeritHiveRelayLocalBlindBrowserRuntimeV1',
  localTestOnly: true,
  phase: 'booting',
  error: null,
  vendor: null,
  config: null,
  qualification: null,
  product: null,
  ui: null,
  banner: null
}

function installLocalFixtureBanner () {
  const header = document.querySelector('.topbar')
  if (!header) return null
  const banner = document.createElement('div')
  banner.className = 'local-fixture-banner'
  banner.setAttribute('role', 'status')
  banner.textContent = 'Local synthetic stand-up — qualifying the real loopback blind-cell relay…'
  header.after(banner)
  return banner
}

function publishPhase (phase, error = null) {
  state.phase = phase
  state.error = error == null
    ? null
    : Object.freeze({
      code: error && error.code ? String(error.code) : 'LOCAL_BROWSER_STANDUP_FAILED',
      message: (error && error.message) || 'local browser stand-up failed'
    })
  document.documentElement.setAttribute('data-peerit-local-blind-state', phase)
  if (state.error) {
    document.documentElement.setAttribute('data-peerit-local-blind-error', state.error.code)
  } else {
    document.documentElement.removeAttribute('data-peerit-local-blind-error')
  }
}

async function postControl (path) {
  const response = await fetch(path, {
    method: 'POST',
    headers: fixtureHeaders(),
    body: new Uint8Array(0),
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: lifecycle.signal
  })
  if (!response.ok) fail('LOCAL_FIXTURE_CONTROL_FAILED', `${path} returned ${response.status}`)
  return revive(await response.json())
}

const publicApi = Object.freeze({
  schema: state.schema,
  localTestOnly: true,
  get phase () { return state.phase },
  get error () { return state.error },
  get vendor () { return state.vendor },
  get config () { return state.config },
  get qualification () { return state.qualification },
  async productStatus () { return state.product ? state.product.status() : null },
  async flush () { return state.product ? state.product.sync.flushPublicationQueue() : null },
  async fixtureEvidence () { return exactFetchJson('/__fixture/evidence') },
  async armDroppedCellPutResponse () { return postControl('/__fixture/drop-next-cell-put-response') },
  async restartRelay () { return postControl('/__fixture/restart') }
})
Object.defineProperty(globalThis, '__peeritLocalBlindStandup', {
  configurable: false,
  enumerable: false,
  writable: false,
  value: publicApi
})

function lifecycleEnded () {
  const error = new Error('local blind-cell browser stand-up ended with the page lifecycle')
  error.code = 'LOCAL_BROWSER_LIFECYCLE_ENDED'
  return error
}

function assertLive () {
  if (lifecycle.signal.aborted) throw lifecycle.signal.reason || lifecycleEnded()
}

function destroyRuntime () {
  if (state.ui) state.ui.destroy()
  state.ui = null
  state.banner = null
  if (state.product) state.product.destroy()
  state.product = null
}

window.addEventListener('pagehide', () => {
  if (!lifecycle.signal.aborted) lifecycle.abort(lifecycleEnded())
  destroyRuntime()
}, { once: true })

async function boot () {
  publishPhase('verifying-vendored-client')
  const [vendor, outerConfig] = await Promise.all([
    verifiedHiveClient(),
    exactFetchJson('/__fixture/config')
  ])
  assertLive()
  state.vendor = vendor.snapshot
  if (!outerConfig || outerConfig.localTestOnly !== true ||
      outerConfig.schema !== 'PeeritHiveRelayLocalBlindBrowserConfigV1') {
    fail('LOCAL_FIXTURE_CONFIG_INVALID', 'Peerit local stand-up config is missing or unbranded')
  }
  if (!/^[0-9a-f]{64}$/.test(outerConfig.fixtureToken || '')) {
    fail('LOCAL_FIXTURE_CONFIG_INVALID', 'Peerit local stand-up request token is missing or invalid')
  }
  fixtureToken = outerConfig.fixtureToken
  const localNetworkStateReset = await resetLocalNetworkStateForRun(outerConfig.runId)
  assertLive()
  state.config = Object.freeze({
    runId: outerConfig.runId,
    localNetworkStateReset,
    peeritCommit: outerConfig.peeritCommit,
    peeritTrackedDirty: outerConfig.peeritTrackedDirty,
    hiveRelayCommit: outerConfig.hiveRelayCommit,
    hiveRelayTrackedDirty: outerConfig.hiveRelayTrackedDirty,
    transport: outerConfig.transport
  })

  const product = createPeeritProductRuntimeV1()
  state.product = product
  await product.ready()
  assertLive()
  state.ui = mountPeeritProductUiV1(product, { document, window })
  state.banner = installLocalFixtureBanner()
  product.setNetworkStatus({
    state: 'local-blind-relay-qualifying',
    active: false,
    releaseBlockers: []
  })

  publishPhase('qualifying-real-relay')
  try {
    const capabilityVault = createPeeritCapabilityVault()
    const qualification = await qualifyFixture({
      config: outerConfig.qualification,
      control: vendor.control,
      capabilityVault
    })
    assertLive()
    state.qualification = qualification.status
    product.sync.setRelayQualificationStatus(qualification.status)
    product.setQualifiedRelays(qualification.adapters)
    product.setNetworkStatus({
      state: 'local-synthetic-blind-relay-qualified',
      active: true,
      releaseBlockers: []
    })
    await product.sync.flushPublicationQueue()
    if (state.banner) {
      state.banner.textContent = 'Local synthetic stand-up — real daemon, edge, and filesystem Cells; synthetic admission and a loopback TLS proxy.'
    }
    publishPhase('ready')
  } catch (error) {
    if (lifecycle.signal.aborted) throw lifecycle.signal.reason || error
    state.qualification = Object.freeze({
      state: 'local-relay-qualification-failed',
      active: false,
      qualifiedRelayCount: 0,
      releaseBlockers: Object.freeze([
        error && error.code ? String(error.code) : 'LOCAL_RELAY_QUALIFICATION_FAILED'
      ])
    })
    product.sync.setRelayQualificationStatus(state.qualification)
    product.setNetworkStatus(state.qualification)
    if (state.banner) {
      state.banner.textContent = 'Local synthetic stand-up — relay qualification failed; local authoring remains available.'
    }
    publishPhase('local-only-network-failed', error)
    console.error('[peerit local blind stand-up] relay qualification failed:', error)
  }
}

boot().catch(error => {
  if (error && error.code === 'LOCAL_BROWSER_LIFECYCLE_ENDED') return
  publishPhase('failed', error)
  const bootNode = document.querySelector('[data-local-blind-boot]')
  if (bootNode) {
    const subtitle = bootNode.querySelector('.boot-sub')
    if (subtitle) subtitle.textContent = `local stand-up failed: ${(error && error.message) || 'unknown error'}`
  }
  console.error('[peerit local blind stand-up] boot failed:', error)
})
