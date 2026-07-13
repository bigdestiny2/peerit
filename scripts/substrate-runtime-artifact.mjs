import { createHash } from 'node:crypto'
import { patchCspForWeb } from './csp.mjs'
import {
  decodePeeritWebAssetManifestV1,
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritWebAssetManifestV1,
  verifyPeeritWebAssetBytesV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  blake2b256,
  bytesToHex
} from '../js/substrate/release-control-primitives.mjs'
import { PEERIT_PRODUCTION_PIN_HISTORY_PATH } from '../js/substrate/production-release-authority.mjs'
import { normalizePeeritReleaseRelayHintsV1 } from '../js/substrate/release-relay-hints.mjs'

export const PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE = 7
export const PEERIT_APP_ARTIFACT_PATH = 'peerit-app-artifact-v1.json'
export const PEERIT_WEB_ASSET_MANIFEST_PATH = 'peerit-web-assets-v1.cenc'

const HEX_32 = /^[0-9a-f]{64}$/

function sha256 (input) {
  return createHash('sha256').update(input).digest('hex')
}

function sri (input) {
  return 'sha384-' + createHash('sha384').update(input).digest('base64')
}

function attr (value) {
  return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
}

function exactBuffer (value, field) {
  if (Buffer.isBuffer(value)) return Buffer.from(value)
  if (value instanceof Uint8Array) return Buffer.from(value)
  throw new TypeError(`${field} must be bytes`)
}

function sortedObject (entries) {
  return Object.fromEntries([...entries].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0))
}

function normalizedFiles (sourceFiles) {
  const source = sourceFiles instanceof Map ? sourceFiles : new Map(Object.entries(sourceFiles || {}))
  const files = new Map()
  for (const [path, bytes] of source) {
    if (typeof path !== 'string' ||
        !/^(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(path) ||
        path.split('/').some(component => component === '.' || component === '..')) {
      throw new Error(`replacement runtime source path is not canonical: ${path}`)
    }
    files.set(path, exactBuffer(bytes, path))
  }
  for (const path of ['index.html', 'styles.css', 'js/substrate/app-entry.js']) {
    if (!files.has(path)) throw new Error(`replacement runtime source is missing ${path}`)
  }
  return files
}

function decodeAppArtifactV1 (bytes) {
  let value
  try {
    value = JSON.parse(exactBuffer(bytes, PEERIT_APP_ARTIFACT_PATH).toString('utf8'))
  } catch {
    throw new Error(`${PEERIT_APP_ARTIFACT_PATH} is not valid JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      value.schema !== 'peerit-app-artifact-v1' ||
      value.transport !== 'blind-substrate' ||
      value.substrateProfile !== 'blind-v1' ||
      value.entry !== '/index.html' ||
      value.canonicalWebAssetManifest !== `/${PEERIT_WEB_ASSET_MANIFEST_PATH}` ||
      (value.productionPinHistory !== null &&
        value.productionPinHistory !== PEERIT_PRODUCTION_PIN_HISTORY_PATH) ||
      !Number.isSafeInteger(value.releaseSequence) ||
      value.releaseSequence < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE ||
      !HEX_32.test(String(value.releaseKey || '')) ||
      !Array.isArray(value.relayHints) ||
      !value.files || typeof value.files !== 'object' || Array.isArray(value.files)) {
    throw new Error(`${PEERIT_APP_ARTIFACT_PATH} has an invalid replacement release identity`)
  }
  value.relayHints = normalizePeeritReleaseRelayHintsV1(
    value.relayHints, 'app artifact')
  return value
}

// Verify a generated replacement closure without trusting either wrapper's JSON
// metadata. Web release tooling, deployment proof, and Hyper tests all call this
// same verifier, so the canonical CENC manifest remains the authority for bytes.
export function verifyPeeritSubstrateRuntimeArtifactV1 (options = {}) {
  const source = options.files instanceof Map
    ? new Map(options.files)
    : new Map(Object.entries(options.files || {}))
  const releaseSequence = Number(options.releaseSequence)
  const releaseKey = String(options.releaseKey || '').toLowerCase()
  if (!Number.isSafeInteger(releaseSequence) ||
      releaseSequence < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE ||
      !HEX_32.test(releaseKey)) {
    throw new Error('replacement runtime verification requires an exact sequence and release key')
  }
  if (!source.has(PEERIT_APP_ARTIFACT_PATH) ||
      !source.has(PEERIT_WEB_ASSET_MANIFEST_PATH)) {
    throw new Error('replacement runtime is missing its app artifact or canonical WebAssetManifestV1')
  }

  const appArtifactBytes = exactBuffer(source.get(PEERIT_APP_ARTIFACT_PATH), PEERIT_APP_ARTIFACT_PATH)
  const webAssetManifestBytes = exactBuffer(
    source.get(PEERIT_WEB_ASSET_MANIFEST_PATH), PEERIT_WEB_ASSET_MANIFEST_PATH)
  const appArtifact = decodeAppArtifactV1(appArtifactBytes)
  const webAssetManifest = decodePeeritWebAssetManifestV1(webAssetManifestBytes)
  if (appArtifact.releaseSequence !== releaseSequence ||
      appArtifact.releaseKey !== releaseKey ||
      webAssetManifest.releaseSequence !== BigInt(releaseSequence)) {
    throw new Error('replacement runtime release identity does not match its wrapper configuration')
  }
  if (webAssetManifest.assets.some(asset => asset.path === `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`)) {
    throw new Error('canonical WebAssetManifestV1 cannot self-list its own bytes')
  }
  const appArtifactHash = hashPeeritAppArtifactV1(appArtifactBytes)
  if (!Buffer.from(webAssetManifest.appArtifactHash).equals(Buffer.from(appArtifactHash))) {
    throw new Error('canonical WebAssetManifestV1 does not bind the exact app artifact')
  }

  const indexHtml = exactBuffer(source.get('index.html'), 'index.html').toString('utf8')
  const exactCount = pattern => (indexHtml.match(pattern) || []).length
  if (exactCount(/<meta\s+name="peerit-substrate"\s+content="blind-v1">/g) !== 1 ||
      exactCount(new RegExp(`<meta\\s+name="peerit-release-key"\\s+content="${releaseKey}">`, 'g')) !== 1 ||
      exactCount(new RegExp(`<meta\\s+name="peerit-release-sequence"\\s+content="${releaseSequence}">`, 'g')) !== 1 ||
      exactCount(new RegExp(`<meta\\s+name="peerit-production-web-asset-manifest"\\s+content="/${PEERIT_WEB_ASSET_MANIFEST_PATH}">`, 'g')) !== 1 ||
      exactCount(/<script\s+type="module"\s+src="js\/substrate\/app-entry\.js"[^>]*><\/script>/g) !== 1 ||
      !/script-src 'self'(?:;|$)/.test(indexHtml)) {
    throw new Error('replacement index transformation did not produce one exact entry, authority metadata set, and strict script CSP')
  }
  const pinMetaCount = exactCount(new RegExp(
    `<meta\\s+name="peerit-production-pin-history"\\s+content="${PEERIT_PRODUCTION_PIN_HISTORY_PATH}">`, 'g'))
  const expectedRelayMeta = appArtifact.relayHints.length
    ? `<meta name="peerit-substrate-relays" content="${attr(appArtifact.relayHints.join(','))}">`
    : null
  const relayMetaCount = exactCount(/<meta\s+name="peerit-substrate-relays"\s+content="[^"]*">/g)
  const canonicalHasPinHistory = webAssetManifest.assets.some(
    asset => asset.path === PEERIT_PRODUCTION_PIN_HISTORY_PATH)
  if ((appArtifact.productionPinHistory ? pinMetaCount !== 1 : pinMetaCount !== 0) ||
      (expectedRelayMeta ? relayMetaCount !== 1 || !indexHtml.includes(expectedRelayMeta) : relayMetaCount !== 0) ||
      Boolean(appArtifact.productionPinHistory) !==
        source.has(PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)) ||
      canonicalHasPinHistory ||
      Object.hasOwn(appArtifact.files, PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1))) {
    throw new Error('replacement pin-history metadata and canonical closure do not agree')
  }

  const canonicalAssets = new Map()
  for (const asset of webAssetManifest.assets) {
    const path = asset.path.slice(1)
    if (!source.has(path)) throw new Error(`canonical replacement asset is missing: ${asset.path}`)
    canonicalAssets.set(asset.path, exactBuffer(source.get(path), path))
  }
  const exactSourcePaths = new Set([
    ...webAssetManifest.assets.map(asset => asset.path.slice(1)),
    PEERIT_WEB_ASSET_MANIFEST_PATH,
    ...(appArtifact.productionPinHistory
      ? [PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)]
      : [])
  ])
  if (source.size !== exactSourcePaths.size ||
      [...source.keys()].some(path => !exactSourcePaths.has(path))) {
    throw new Error('replacement runtime contains bytes outside its exact canonical closure')
  }
  verifyPeeritWebAssetBytesV1(webAssetManifest, canonicalAssets, { requireComplete: true })

  const appPaths = Object.keys(appArtifact.files).sort()
  const expectedAppPaths = webAssetManifest.assets
    .map(asset => asset.path.slice(1))
    .filter(path => path !== PEERIT_APP_ARTIFACT_PATH)
    .sort()
  if (JSON.stringify(appPaths) !== JSON.stringify(expectedAppPaths)) {
    throw new Error('app artifact file closure does not equal the canonical runtime closure')
  }
  for (const path of appPaths) {
    const expectedHash = appArtifact.files[path]
    if (!HEX_32.test(String(expectedHash || '')) || sha256(source.get(path)) !== expectedHash) {
      throw new Error(`app artifact SHA-256 mismatch: ${path}`)
    }
  }

  const webAssetManifestHash = hashPeeritWebAssetManifestV1(webAssetManifestBytes)
  return Object.freeze({
    appArtifact,
    webAssetManifest,
    appArtifactHash,
    appArtifactHashHex: bytesToHex(appArtifactHash),
    webAssetManifestHash,
    webAssetManifestHashHex: bytesToHex(webAssetManifestHash),
    verifiedAssetCount: canonicalAssets.size
  })
}

export function peeritServiceWorkerRegisterSourceV1 () {
  return `if ('serviceWorker' in navigator) {
  // A new deploy changes the bundle hashes -> a new sw.js. The SW skipWaiting()s +
  // clients.claim()s, so it activates immediately, but the page already loaded with
  // the OLD cached assets. Reload ONCE when the new SW takes control so returning
  // visitors actually run the new audited bundle instead of stale code. Guard with
  // hadController so a brand-new visitor (first install) does not reload.
  // RATE-LIMITED, not once-per-session: the old boolean latch blocked the reload
  // for every deploy AFTER a tab's first, so long-lived tabs silently ran stale
  // builds until a manual refresh. A timestamp latch keeps reload loops harmless.
  var hadController = !!navigator.serviceWorker.controller, refreshing = false;
  var LATCH = 'peerit:sw-reloaded-at', WINDOW_MS = 5 * 60 * 1000;
  navigator.serviceWorker.addEventListener('controllerchange', function () {
    if (refreshing || !hadController) return;
    try {
      var last = Number(sessionStorage.getItem(LATCH) || 0);
      if (Date.now() - last < WINDOW_MS) return;
      sessionStorage.setItem(LATCH, String(Date.now()));
    } catch (e) {}
    refreshing = true; location.reload();
  });
  addEventListener('load', function () {
    navigator.serviceWorker.register('sw.js').then(function (reg) {
      if (reg && reg.update) { try { reg.update(); } catch (e) {} }
    }).catch(function () {});
  });
}
`
}

// Produce the one replacement runtime closure shared by the Web wrapper and
// Hyper publication. The returned bytes never contain a drive key, so the
// content-addressed Hyper identity does not become self-referential.
export function buildPeeritSubstrateRuntimeArtifactV1 (options = {}) {
  const profile = String(options.substrateProfile || '')
  const releaseSequence = Number(options.releaseSequence)
  const releaseKey = String(options.releaseKey || '').toLowerCase()
  const relayHints = normalizePeeritReleaseRelayHintsV1(
    options.relayHints == null ? [] : options.relayHints,
    'replacement runtime')
  if (profile !== 'blind-v1') throw new Error(`unsupported Peerit substrate profile: ${profile}`)
  if (!Number.isSafeInteger(releaseSequence) ||
      releaseSequence < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE) {
    throw new Error(`blind-substrate replacement releaseSequence must be at least ${PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE}; sequence 6 belongs to the retired legacy artifact`)
  }
  if (!HEX_32.test(releaseKey)) throw new Error('blind-substrate replacement requires one 32-byte lowercase release key')

  const files = normalizedFiles(options.sourceFiles)
  const productionPinHistoryBytes = options.productionPinHistoryBytes == null
    ? null
    : exactBuffer(options.productionPinHistoryBytes, 'production pin-history bundle')
  if (productionPinHistoryBytes &&
      (productionPinHistoryBytes.byteLength < 1 || productionPinHistoryBytes.byteLength > 4 * 1024 * 1024)) {
    throw new Error('production pin-history bundle exceeds its fixed byte bound')
  }
  const styleIntegrity = sri(files.get('styles.css'))
  const entryIntegrity = sri(files.get('js/substrate/app-entry.js'))
  let html = files.get('index.html').toString('utf8')
  html = html.replace(/\s*<meta\s+name="peerit-v2"[^>]*>/gi, '')
  html = html.replace(
    /<meta\s+name="description"\s+content="[^"]*">/i,
    '<meta name="description" content="peerit is a local-first community app using authenticated blind relay substrate artifacts.">')
  html = html.replace(/\s*<meta\s+name="peerit-shard-(?:roster|relays|threshold)"[^>]*>/gi, '')
  html = html.replace(/\s*<meta\s+name="peerit-(?:relay(?:-[a-z0-9-]+)?|dht-relay|seed-outboxes|substrate(?:-relays)?|release-key|release-sequence|production-web-asset-manifest|production-pin-history)"[^>]*>/gi, '')
  const head = [
    `<meta name="peerit-substrate" content="${attr(profile)}">`,
    relayHints.length ? `<meta name="peerit-substrate-relays" content="${attr(relayHints.join(','))}">` : '',
    `<meta name="peerit-release-key" content="${releaseKey}">`,
    `<meta name="peerit-release-sequence" content="${releaseSequence}">`,
    `<meta name="peerit-production-web-asset-manifest" content="/${PEERIT_WEB_ASSET_MANIFEST_PATH}">`,
    productionPinHistoryBytes
      ? `<meta name="peerit-production-pin-history" content="${PEERIT_PRODUCTION_PIN_HISTORY_PATH}">`
      : '',
    '<script src="sw-register.js"></script>'
  ].filter(Boolean).join('\n  ')
  html = html.replace('</head>', `  ${head}\n</head>`)
  html = patchCspForWeb(html, {
    dhtRelay: '',
    connectOrigins: [...new Set(relayHints.map(value => new URL(value).origin))]
  })
  html = html.replace('<link rel="stylesheet" href="styles.css">',
    `<link rel="stylesheet" href="styles.css" integrity="${styleIntegrity}" crossorigin="anonymous">`)
  html = html.replace(/<script\s+type="module"\s+src="js\/(?:app\.js|substrate\/app-entry\.js)"(?:\s+[^>]*)?><\/script>/,
    `<script type="module" src="js/substrate/app-entry.js" integrity="${entryIntegrity}" crossorigin="anonymous"></script>`)
  files.set('index.html', Buffer.from(html))
  files.set('sw-register.js', Buffer.from(peeritServiceWorkerRegisterSourceV1()))

  const closureHashes = sortedObject([...files].map(([path, bytes]) => [path, sha256(bytes)]))
  const appArtifact = Object.freeze({
    schema: 'peerit-app-artifact-v1',
    releaseSequence,
    transport: 'blind-substrate',
    substrateProfile: profile,
    relayHints,
    releaseKey,
    entry: '/index.html',
    canonicalWebAssetManifest: `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`,
    productionPinHistory: productionPinHistoryBytes
      ? PEERIT_PRODUCTION_PIN_HISTORY_PATH
      : null,
    files: closureHashes
  })
  const appArtifactBytes = Buffer.from(JSON.stringify(appArtifact, null, 2) + '\n')
  files.set(PEERIT_APP_ARTIFACT_PATH, appArtifactBytes)
  const appArtifactHash = hashPeeritAppArtifactV1(appArtifactBytes)

  const assets = [...files]
    .map(([path, bytes]) => ({
      path: new TextEncoder().encode('/' + path),
      byteLength: BigInt(bytes.byteLength),
      assetHash: blake2b256(bytes)
    }))
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
  const webAssetManifestBytes = Buffer.from(encodePeeritWebAssetManifestV1({
    version: 1,
    releaseSequence: BigInt(releaseSequence),
    appArtifactHash,
    recommendedBootstrapHashes: [],
    assets
  }))
  files.set(PEERIT_WEB_ASSET_MANIFEST_PATH, webAssetManifestBytes)
  const webAssetManifestHash = hashPeeritWebAssetManifestV1(webAssetManifestBytes)

  // Detached by design: the terminal profile pin commits to appArtifactHash and
  // webAssetManifestHash. Including pin history in either artifact would create
  // an impossible fixed-point hash cycle. Web signs this detached file in the
  // outer asset manifest; Hyper binds it through the drive content address.
  if (productionPinHistoryBytes) {
    files.set(PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1), productionPinHistoryBytes)
  }

  verifyPeeritSubstrateRuntimeArtifactV1({
    files,
    releaseSequence,
    releaseKey
  })

  return Object.freeze({
    files,
    appArtifact,
    appArtifactBytes,
    appArtifactHash,
    appArtifactHashHex: bytesToHex(appArtifactHash),
    webAssetManifestBytes,
    webAssetManifestHash,
    webAssetManifestHashHex: bytesToHex(webAssetManifestHash),
    sha256Files: sortedObject([...files].map(([path, bytes]) => [path, sha256(bytes)]))
  })
}
