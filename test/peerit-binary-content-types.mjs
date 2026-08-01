// Coverage for the 2026-07-31 live-site content-type fix: static hosts
// disagree on the opaque-binary label for extension-less binary artifacts
// (application/octet-stream vs Render's binary/octet-stream). The pin-history
// bootstrap loader and the bounded runtime asset fetcher must accept BOTH
// opaque binary labels while still rejecting HTML/error-page responses, with
// every other check (exact Content-Length, hash bindings) unchanged.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { loadPeeritProductionPinHistoryTerminalV1 } from '../js/substrate/pin-history-bootstrap.mjs'
import { fetchAndVerifyPeeritWebAssetContentV1 } from '../js/substrate/browser-runtime-authority.mjs'
import {
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1
} from '../js/substrate/release-control-codec.mjs'
import {
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1
} from '../js/substrate/web-asset-manifest.mjs'
import { blake2b256 } from '../js/substrate/release-control-primitives.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const bundleBytes = new Uint8Array(readFileSync(join(root, 'peerit-production-pin-history-v1.cenc')))
const terminalSequence = decodePeeritHiveRelayProfilePinV1(
  decodePeeritPinHistoryBundleV1(bundleBytes).pins.at(-1)).releaseSequence

function pageDocument (releaseSequence) {
  const metas = new Map([
    ['peerit-production-pin-history', '/peerit-production-pin-history-v1.cenc'],
    ['peerit-release-sequence', String(releaseSequence)]
  ])
  return {
    baseURI: 'https://peerit.test/',
    querySelector (selector) {
      const name = selector.match(/^meta\[name="([^"]+)"\]$/)?.[1]
      if (!name || !metas.has(name)) return null
      return { getAttribute: (attribute) => (attribute === 'content' ? metas.get(name) : null) }
    }
  }
}

function stubResponse (bytes, contentType) {
  return new Response(bytes, {
    status: 200,
    headers: {
      'content-length': String(bytes.byteLength),
      'content-type': contentType
    }
  })
}

// ---- pin-history bootstrap loader: both opaque binary labels accepted.
// The content-type check runs before any verification/persistence; in bare
// Node (no IndexedDB) an accepted response fails LATER at witness persistence,
// while a rejected response fails AT the content-type check. Discriminating
// the two failure stages proves the acceptance in Node; the active:true
// end-to-end proof is the Chromium production runtime gate + DOM probe.
for (const contentType of ['application/octet-stream', 'binary/octet-stream']) {
  const result = await loadPeeritProductionPinHistoryTerminalV1({
    document: pageDocument(terminalSequence),
    fetch: async () => stubResponse(bundleBytes, contentType)
  })
  assert.notDeepEqual(
    [...(result.releaseBlockers || [])],
    ['PRODUCTION_PIN_HISTORY_CONTENT_TYPE_INVALID'],
    `pin-history content-type check must accept ${contentType}`)
  assert.equal(result.active, false)
  assert.deepEqual([...result.releaseBlockers], ['PRODUCTION_PIN_HISTORY_FAILED'])
  assert.match(result.message, /witness persistence is unavailable/)
}

// ---- pin-history bootstrap loader: HTML/error responses still rejected
for (const contentType of ['text/html; charset=utf-8', 'text/html', 'application/json', 'text/plain']) {
  const result = await loadPeeritProductionPinHistoryTerminalV1({
    document: pageDocument(terminalSequence),
    fetch: async () => stubResponse(bundleBytes, contentType)
  })
  assert.equal(result.active, false, `pin-history bootstrap must reject ${contentType}`)
  assert.deepEqual([...result.releaseBlockers], ['PRODUCTION_PIN_HISTORY_CONTENT_TYPE_INVALID'])
}

// ---- bounded runtime asset fetcher: both opaque binary labels accepted
const assetBytes = new TextEncoder().encode('signed binary artifact')
const appArtifactBytes = new TextEncoder().encode('{"schema":"peerit-app-artifact-v1"}\n')
const assetManifestBytes = encodePeeritWebAssetManifestV1({
  version: 1,
  releaseSequence: 20n,
  appArtifactHash: hashPeeritAppArtifactV1(appArtifactBytes),
  recommendedBootstrapHashes: [hashPeeritBootstrapV1(assetBytes)],
  assets: [
    { path: '/artifact.cenc', byteLength: BigInt(assetBytes.byteLength), assetHash: blake2b256(assetBytes) },
    { path: '/peerit-app-artifact-v1.json', byteLength: BigInt(appArtifactBytes.byteLength), assetHash: blake2b256(appArtifactBytes) }
  ].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
})
function fetchFor (contentType) {
  return async (input) => {
    const path = new URL(input).pathname
    if (path === '/artifact.cenc') return stubResponse(assetBytes, contentType)
    if (path === '/peerit-app-artifact-v1.json') return stubResponse(appArtifactBytes, 'application/json')
    return new Response('not found', { status: 404 })
  }
}
for (const contentType of ['application/octet-stream', 'binary/octet-stream']) {
  const verified = await fetchAndVerifyPeeritWebAssetContentV1({
    fetch: fetchFor(contentType),
    manifest: assetManifestBytes,
    baseUrl: 'https://peerit.test/'
  })
  assert.ok(verified && typeof verified === 'object', `runtime asset fetch must accept ${contentType} for binary artifacts`)
}
await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
  fetch: fetchFor('text/html'),
  manifest: assetManifestBytes,
  baseUrl: 'https://peerit.test/'
}), error => error.code === 'BROWSER_RUNTIME_ASSET_CONTENT_TYPE_INVALID')
await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
  fetch: fetchFor('application/json'),
  manifest: assetManifestBytes,
  baseUrl: 'https://peerit.test/'
}), error => error.code === 'BROWSER_RUNTIME_ASSET_CONTENT_TYPE_INVALID')

// ---- compression tolerance (2026-08-01 live-site unblock, sequence 22):
// a compressing static edge (Render/Cloudflare) answers browsers with
// content-encoding br/gzip and a Content-Length of the COMPRESSED size (or
// none), while the network layer delivers the DECOMPRESSED body. The
// decompressed payload must satisfy the signed length bound and the signed
// hash exactly; the compressed header must not be required to equal it.
import { brotliCompressSync, gzipSync } from 'node:zlib'

function stubEncodedResponse (bodyBytes, encoding, { headerLength = 'compressed', contentType = 'text/javascript' } = {}) {
  const compressed = encoding === 'br'
    ? brotliCompressSync(Buffer.from(bodyBytes))
    : encoding === 'gzip'
      ? gzipSync(Buffer.from(bodyBytes))
      : null
  const headers = {
    'content-type': contentType,
    'content-encoding': encoding
  }
  if (headerLength === 'compressed') headers['content-length'] = String(compressed.byteLength)
  else if (headerLength === 'uncompressed') headers['content-length'] = String(bodyBytes.byteLength)
  else if (headerLength === 'wrong') headers['content-length'] = String(bodyBytes.byteLength + 7)
  // The browser network layer transparently decompresses: response.body carries
  // the DECOMPRESSED bytes while the header carries the compressed size.
  return new Response(bodyBytes, { status: 200, headers })
}
function encodedFetch (bodyBytes, encoding, options = {}) {
  return async (input) => {
    const path = new URL(input).pathname
    if (path === '/artifact.cenc') {
      return new Response(assetBytes, {
        status: 200,
        headers: { 'content-length': String(assetBytes.byteLength), 'content-type': 'binary/octet-stream' }
      })
    }
    if (path === '/peerit-app-artifact-v1.json') {
      return stubResponse(appArtifactBytes, 'application/json')
    }
    if (path === '/js/app.js') return stubEncodedResponse(bodyBytes, encoding, options)
    return new Response('not found', { status: 404 })
  }
}
const appJsBytes = new TextEncoder().encode('export const peerit = "compress me";\n'.repeat(64))
const compressedManifestBytes = encodePeeritWebAssetManifestV1({
  version: 1,
  releaseSequence: 22n,
  appArtifactHash: hashPeeritAppArtifactV1(appArtifactBytes),
  recommendedBootstrapHashes: [hashPeeritBootstrapV1(assetBytes)],
  assets: [
    { path: '/artifact.cenc', byteLength: BigInt(assetBytes.byteLength), assetHash: blake2b256(assetBytes) },
    { path: '/js/app.js', byteLength: BigInt(appJsBytes.byteLength), assetHash: blake2b256(appJsBytes) },
    { path: '/peerit-app-artifact-v1.json', byteLength: BigInt(appArtifactBytes.byteLength), assetHash: blake2b256(appArtifactBytes) }
  ].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
})

// compressed header length != signed bound (and header absent) but the
// decompressed body is exactly the signed bytes -> MUST pass (br and gzip)
for (const encoding of ['br', 'gzip']) {
  for (const headerLength of ['compressed', 'absent']) {
    const verified = await fetchAndVerifyPeeritWebAssetContentV1({
      fetch: encodedFetch(appJsBytes, encoding, { headerLength }),
      manifest: compressedManifestBytes,
      baseUrl: 'https://peerit.test/'
    })
    assert.equal(verified.verifiedAssetCount, 3,
      `${encoding} with ${headerLength} Content-Length must pass when decompressed bytes match the signed bounds`)
  }
}

// compressed but the decompressed body is SHORTER than the signed bound -> fail
await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
  fetch: encodedFetch(appJsBytes.subarray(0, appJsBytes.byteLength - 5), 'br', { headerLength: 'compressed' }),
  manifest: compressedManifestBytes,
  baseUrl: 'https://peerit.test/'
}), error => error.code === 'BROWSER_RUNTIME_ASSET_LENGTH_INVALID')

// compressed, decompressed length matches, but the bytes are WRONG -> the
// signed hash binding must still fail (no weakening of the byte model)
const tamperedAppJsBytes = new Uint8Array(appJsBytes)
tamperedAppJsBytes[tamperedAppJsBytes.byteLength - 2] ^= 0x01
await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
  fetch: encodedFetch(tamperedAppJsBytes, 'br', { headerLength: 'compressed' }),
  manifest: compressedManifestBytes,
  baseUrl: 'https://peerit.test/'
}), error => error.code !== 'BROWSER_RUNTIME_ASSET_LENGTH_INVALID')

// no content-encoding: the strict header rule is preserved byte-for-byte
await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
  fetch: encodedFetch(appJsBytes, 'identity', { headerLength: 'wrong' }),
  manifest: compressedManifestBytes,
  baseUrl: 'https://peerit.test/'
}), error => error.code === 'BROWSER_RUNTIME_ASSET_LENGTH_INVALID')

// HTML stays rejected even when compressed
await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
  fetch: encodedFetch(appJsBytes, 'br', { headerLength: 'compressed', contentType: 'text/html' }),
  manifest: compressedManifestBytes,
  baseUrl: 'https://peerit.test/'
}), error => error.code === 'BROWSER_RUNTIME_ASSET_CONTENT_TYPE_INVALID')

console.log('peerit binary content types: pin-history bootstrap + runtime asset fetch accept application/octet-stream and binary/octet-stream, reject HTML/error responses — passed')
console.log('peerit compression tolerance: compressed (br/gzip) responses with compressed or absent Content-Length pass on exact decompressed bytes; short or tampered decompressed payloads and uncompressed header drift fail; HTML still rejected — passed')
