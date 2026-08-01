import {
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryBundleV1,
  profilePinHash
} from './release-control-codec.mjs'
import {
  asBytes,
  bytesEqual
} from './release-control-primitives.mjs'
import {
  canonicalExpectedPinProjection,
  getVerifiedPinHistoryTerminalSnapshotV1,
  verifyPeeritPinHistoryBundleV1,
  verifyPeeritPinHistoryContinuationV1
} from './release-control-verifier.mjs'
import {
  createPeeritPinHistoryWitnessBackend,
  peeritPinHistoryProfileScopeV1
} from './pin-history-witness-backend.mjs'
import {
  PEERIT_PRODUCTION_PIN_HISTORY_META,
  PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1
} from './production-release-authority.mjs'

const MAX_PIN_HISTORY_BYTES = 4 * 1024 * 1024
const FETCH_TIMEOUT_MILLIS = 10000

function blocked (code, message) {
  return Object.freeze({
    state: 'blocked-production-pin-history',
    active: false,
    releaseBlockers: Object.freeze([code]),
    message
  })
}

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function fixed32 (value, field) {
  const output = new Uint8Array(asBytes(value, field))
  if (output.byteLength !== 32) fail('PRODUCTION_PIN_HISTORY_TRUST_ROOT_INVALID', `${field} must be 32 bytes`)
  return output
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

function canonicalSameOriginPath (value, document) {
  if (typeof value !== 'string' ||
      !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(value) ||
      value.includes('%') || value.includes('\\') || value.includes('?') || value.includes('#')) {
    fail('PRODUCTION_PIN_HISTORY_LOCATION_INVALID', 'pin-history location must be a canonical same-origin absolute path')
  }
  const base = document && document.baseURI ? document.baseURI : globalThis.location?.href
  if (!base) fail('PRODUCTION_PIN_HISTORY_LOCATION_INVALID', 'document base URI is unavailable')
  const url = new URL(value, base)
  if (url.origin !== new URL(base).origin || url.pathname !== value) {
    fail('PRODUCTION_PIN_HISTORY_LOCATION_INVALID', 'pin-history location is not same-origin canonical')
  }
  return url.href
}

function browserCrypto (runtime = globalThis.crypto) {
  if (!runtime || !runtime.subtle) {
    fail('RELEASE_CONTROL_CRYPTO_UNAVAILABLE', 'browser WebCrypto is unavailable')
  }
  return Object.freeze({
    async verifyEd25519 (publicKey, message, signature) {
      const key = await runtime.subtle.importKey(
        'raw', publicKey, { name: 'Ed25519' }, false, ['verify'])
      return runtime.subtle.verify({ name: 'Ed25519' }, key, signature, message)
    }
  })
}

async function fetchExactBytes (fetchFunction, url, signal) {
  const response = await fetchFunction(url, {
    cache: 'reload',
    credentials: 'omit',
    redirect: 'error',
    signal
  })
  if (!response || response.ok !== true || (response.url && response.url !== url)) {
    fail('PRODUCTION_PIN_HISTORY_FETCH_FAILED', 'pin-history bundle did not return an exact non-redirect response')
  }
  const type = String(response.headers && response.headers.get('content-type') || '')
    .split(';')[0].trim().toLowerCase()
  // Static hosts disagree on the opaque-binary label for extension-less binary
  // artifacts: most serve application/octet-stream, while Render's static host
  // (and its Cloudflare-backed edge) serves binary/octet-stream. Both labels
  // name an opaque binary body, so both are accepted here; HTML/error-page
  // responses remain rejected, and the exact Content-Length and hash bindings
  // below are unchanged.
  if (type !== 'application/octet-stream' && type !== 'binary/octet-stream') {
    fail('PRODUCTION_PIN_HISTORY_CONTENT_TYPE_INVALID', 'pin-history bundle must use an opaque binary content type (application/octet-stream or binary/octet-stream)')
  }
  const lengthText = response.headers && response.headers.get('content-length')
  if (!/^(?:0|[1-9][0-9]*)$/.test(String(lengthText || ''))) {
    fail('PRODUCTION_PIN_HISTORY_LENGTH_INVALID', 'pin-history bundle is missing an exact Content-Length')
  }
  const length = Number(lengthText)
  if (!Number.isSafeInteger(length) || length < 1 || length > MAX_PIN_HISTORY_BYTES) {
    fail('PRODUCTION_PIN_HISTORY_LENGTH_INVALID', 'pin-history bundle exceeds its fixed byte bound')
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    fail('PRODUCTION_PIN_HISTORY_STREAM_REQUIRED', 'pin-history bundle requires a bounded response stream')
  }
  const reader = response.body.getReader()
  const output = new Uint8Array(length)
  let offset = 0
  try {
    while (true) {
      const result = await reader.read()
      if (result.done) break
      const chunk = new Uint8Array(asBytes(result.value, 'pin-history response chunk'))
      if (offset + chunk.byteLength > length) {
        fail('PRODUCTION_PIN_HISTORY_LENGTH_INVALID', 'pin-history response exceeds Content-Length')
      }
      output.set(chunk, offset)
      offset += chunk.byteLength
    }
  } catch (error) {
    try { await reader.cancel(error) } catch {}
    throw error
  } finally {
    try { reader.releaseLock() } catch {}
  }
  if (offset !== length) {
    fail('PRODUCTION_PIN_HISTORY_LENGTH_INVALID', 'pin-history response is shorter than Content-Length')
  }
  return output
}

function compiledTrustRoot () {
  if (!PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey ||
      !PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.genesisPinHash) {
    fail('PRODUCTION_PEERIT_SIGNED_PROFILE_PIN_UNAVAILABLE',
      'the production release authority and genesis pin hash are not compiled into this build')
  }
  return Object.freeze({
    publicKey: fixed32(PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey,
      'production release authority public key'),
    genesisPinHash: fixed32(PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.genesisPinHash,
      'production genesis pin hash')
  })
}

// The fetched bundle never supplies its own trust root. The compiled genesis
// hash authenticates every field of the first complete pin. Signature and exact
// predecessor checks then authenticate the contiguous suffix under that key.
async function verifyCompleteProductionHistory (completeBundle, cryptoRuntime) {
  const trust = compiledTrustRoot()
  const bundleBytes = new Uint8Array(asBytes(completeBundle, 'production pin-history bundle'))
  const decoded = decodePeeritPinHistoryBundleV1(bundleBytes)
  const pins = decoded.pins.map(value => decodePeeritHiveRelayProfilePinV1(value))
  if (pins.length < 1 || pins[0].releaseSequence !== 0n ||
      !bytesEqual(profilePinHash(decoded.pins[0]), trust.genesisPinHash)) {
    fail('PRODUCTION_PIN_HISTORY_GENESIS_MISMATCH',
      'pin-history bundle does not begin at the compiled production genesis')
  }
  for (const pin of pins) {
    if (!bytesEqual(pin.releaseAuthorityPublicKey, trust.publicKey)) {
      fail('PRODUCTION_PIN_HISTORY_AUTHORITY_MISMATCH',
        'pin-history bundle changed the compiled release authority without an authenticated transition')
    }
  }
  return verifyPeeritPinHistoryBundleV1(bundleBytes, {
    crypto: cryptoRuntime,
    expectedPins: pins.map(canonicalExpectedPinProjection)
  })
}

function suffixBundle (completeBundle, firstSequence) {
  const decoded = decodePeeritPinHistoryBundleV1(completeBundle)
  const start = decoded.pins.findIndex(value =>
    decodePeeritHiveRelayProfilePinV1(value).releaseSequence === firstSequence)
  if (start < 0) {
    fail('PRODUCTION_PIN_HISTORY_GAP_OR_FORK',
      'pin-history bundle does not contain the next witnessed sequence')
  }
  return encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: decoded.pins.slice(start),
    checkpoints: decoded.checkpoints.slice(start)
  })
}

async function persistAndRehydrateTerminal (completeBundle, completeResult, cryptoRuntime, backend) {
  const decoded = decodePeeritPinHistoryBundleV1(completeBundle)
  const genesisBytes = encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: decoded.pins.slice(0, 1),
    checkpoints: decoded.checkpoints.slice(0, 1)
  })
  const genesis = await verifyCompleteProductionHistory(genesisBytes, cryptoRuntime)
  const scope = peeritPinHistoryProfileScopeV1()
  let summary = await backend.read(scope)
  if (summary.version === 0) {
    await backend.initialize(scope, 0, genesis)
    summary = await backend.read(scope)
  }
  let anchor = await backend.rehydrate(scope, genesis, cryptoRuntime)
  const anchorSnapshot = getVerifiedPinHistoryTerminalSnapshotV1(anchor)
  if (anchorSnapshot.terminalSequence > completeResult.terminalSequence) {
    fail('PRODUCTION_PIN_HISTORY_ROLLBACK',
      'fetched pin history is behind the durable witnessed terminal')
  }
  if (anchorSnapshot.terminalSequence < completeResult.terminalSequence) {
    const continuationBytes = suffixBundle(
      completeBundle, anchorSnapshot.terminalSequence + 1n)
    const continuation = await verifyPeeritPinHistoryContinuationV1(continuationBytes, {
      crypto: cryptoRuntime,
      anchor,
      authorityTransitions: []
    })
    const appended = await backend.append(scope, summary.version, {
      anchor,
      completeBundle: continuationBytes,
      verifiedResult: continuation,
      authorityTransitions: []
    })
    if (!appended) {
      fail('PRODUCTION_PIN_HISTORY_CONCURRENT_UPDATE',
        'pin-history witness changed during terminal installation; retry boot')
    }
    anchor = continuation
  }
  const terminal = getVerifiedPinHistoryTerminalSnapshotV1(anchor)
  if (terminal.terminalSequence !== completeResult.terminalSequence ||
      !bytesEqual(terminal.terminalPinHash, completeResult.terminalPinHash)) {
    fail('PRODUCTION_PIN_HISTORY_TERMINAL_MISMATCH',
      'durable witnessed terminal does not equal the verified complete history')
  }
  return terminal
}

export async function loadPeeritProductionPinHistoryTerminalV1 (options = {}) {
  const document = options.document || globalThis.document
  const path = meta(document, PEERIT_PRODUCTION_PIN_HISTORY_META)
  const expectedReleaseSequence = Number(meta(document, 'peerit-release-sequence'))
  if (!PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey ||
      !PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.genesisPinHash) {
    return blocked('PRODUCTION_PEERIT_SIGNED_PROFILE_PIN_UNAVAILABLE',
      'No compiled production release authority and genesis pin are available.')
  }
  if (!path) {
    return blocked('PRODUCTION_PIN_HISTORY_BUNDLE_UNAVAILABLE',
      'No same-origin production pin-history bundle is configured.')
  }
  if (!Number.isSafeInteger(expectedReleaseSequence) || expectedReleaseSequence < 7) {
    return blocked('PRODUCTION_PIN_HISTORY_SEQUENCE_INVALID',
      'The page does not carry a valid replacement release sequence for pin-history binding.')
  }
  const fetchFunction = options.fetch || globalThis.fetch?.bind(globalThis)
  if (typeof fetchFunction !== 'function' || typeof AbortController !== 'function') {
    return blocked('PRODUCTION_PIN_HISTORY_FETCH_UNAVAILABLE',
      'Bounded browser pin-history fetch is unavailable.')
  }
  const controller = new AbortController()
  const abortError = (code, message) => {
    const error = new Error(message)
    error.code = code
    return error
  }
  const forwardAbort = () => controller.abort(
    options.signal.reason || abortError('PRODUCTION_PIN_HISTORY_ABORTED',
      'pin-history verification was aborted by the page lifecycle'))
  if (options.signal && options.signal.aborted) forwardAbort()
  else if (options.signal && typeof options.signal.addEventListener === 'function') {
    options.signal.addEventListener('abort', forwardAbort, { once: true })
  }
  const timer = setTimeout(() => controller.abort(abortError(
    'PRODUCTION_PIN_HISTORY_FETCH_TIMEOUT',
    `pin-history verification exceeded ${FETCH_TIMEOUT_MILLIS}ms`)), FETCH_TIMEOUT_MILLIS)
  const assertActive = () => {
    if (controller.signal.aborted) throw controller.signal.reason ||
      abortError('PRODUCTION_PIN_HISTORY_ABORTED', 'pin-history verification was aborted')
  }
  try {
    const cryptoRuntime = browserCrypto()
    const bytes = await fetchExactBytes(
      fetchFunction, canonicalSameOriginPath(path, document), controller.signal)
    assertActive()
    const verified = await verifyCompleteProductionHistory(bytes, cryptoRuntime)
    assertActive()
    const backend = createPeeritPinHistoryWitnessBackend({ verifierCrypto: cryptoRuntime })
    const terminal = await persistAndRehydrateTerminal(
      bytes, verified, cryptoRuntime, backend)
    assertActive()
    if (terminal.terminalSequence !== BigInt(expectedReleaseSequence)) {
      fail('PRODUCTION_PIN_HISTORY_RELEASE_SEQUENCE_MISMATCH',
        'verified production pin-history terminal does not equal the static release sequence')
    }
    return Object.freeze({
      state: 'verified-production-pin-history',
      active: true,
      terminal,
      releaseBlockers: Object.freeze([])
    })
  } catch (error) {
    return blocked(error && typeof error.code === 'string'
      ? error.code
      : 'PRODUCTION_PIN_HISTORY_FAILED',
      (error && error.message) || 'Production pin history failed verification.')
  } finally {
    clearTimeout(timer)
    if (options.signal && typeof options.signal.removeEventListener === 'function') {
      options.signal.removeEventListener('abort', forwardAbort)
    }
  }
}
