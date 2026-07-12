import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  blake2b256,
  bytesEqual,
  compareBytes,
  decodeUtf8,
  domainLengthHash,
  utf8Bytes
} from './release-control-primitives.mjs'

export const PEERIT_WEB_ASSET_MANIFEST_TAG = 333
export const PEERIT_WEB_ASSET_MANIFEST_HASH_DOMAIN =
  'peerit.release-web-asset-manifest-hash.v1'
export const PEERIT_APP_ARTIFACT_HASH_DOMAIN =
  'peerit.release-app-artifact-hash.v1'
export const PEERIT_WEB_ASSET_LIMITS = Object.freeze({
  maximumAssets: 4096,
  maximumPathBytes: 512,
  maximumBootstrapHashes: 16
})

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function u64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail('BAD_WEB_ASSET_MANIFEST', `${field} is not an unsigned integer`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) {
    fail('BAD_WEB_ASSET_MANIFEST', `${field} is outside u64`)
  }
  return value
}

function fixed32 (value, field) {
  const output = new Uint8Array(asBytes(value, field))
  if (output.byteLength !== 32) fail('BAD_WEB_ASSET_MANIFEST', `${field} must be 32 bytes`)
  return output
}

function canonicalPathBytes (value) {
  const path = typeof value === 'string' ? value : decodeUtf8(value, 'web asset path')
  const bytes = utf8Bytes(path, 'web asset path')
  if (bytes.byteLength < 1 || bytes.byteLength > PEERIT_WEB_ASSET_LIMITS.maximumPathBytes ||
      path !== path.normalize('NFC')) {
    fail('BAD_WEB_ASSET_PATH', 'web asset path is not canonical')
  }
  return { path, bytes }
}

function containsAsciiControl (value) {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code < 32 || code === 127) return true
  }
  return false
}

function assertRuntimePath (path) {
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(path) ||
      path.includes('%') || path.includes('\\') || path.includes('?') || path.includes('#') ||
      containsAsciiControl(path)) {
    fail('BAD_WEB_ASSET_PATH', 'web runtime asset path is not absolute and canonical')
  }
  const components = path.split('/').slice(1)
  if (components.some(component => component === '' || component === '.' || component === '..')) {
    fail('BAD_WEB_ASSET_PATH', 'web asset path contains a forbidden component')
  }
}

function canonicalManifestValue (value) {
  if (!value || typeof value !== 'object' || value.version !== 1) {
    fail('BAD_WEB_ASSET_MANIFEST', 'WebAssetManifestV1 is required')
  }
  if (!Array.isArray(value.recommendedBootstrapHashes) ||
      value.recommendedBootstrapHashes.length > PEERIT_WEB_ASSET_LIMITS.maximumBootstrapHashes) {
    fail('BAD_WEB_ASSET_MANIFEST', 'recommended bootstrap hash count is invalid')
  }
  const recommendedBootstrapHashes = value.recommendedBootstrapHashes.map((entry, index) =>
    fixed32(entry, `recommendedBootstrapHashes[${index}]`))
  for (let index = 1; index < recommendedBootstrapHashes.length; index++) {
    if (compareBytes(recommendedBootstrapHashes[index - 1], recommendedBootstrapHashes[index]) >= 0) {
      fail('BAD_WEB_ASSET_MANIFEST', 'recommended bootstrap hashes are not strictly sorted')
    }
  }
  if (!Array.isArray(value.assets) || value.assets.length < 1 ||
      value.assets.length > PEERIT_WEB_ASSET_LIMITS.maximumAssets) {
    fail('BAD_WEB_ASSET_MANIFEST', 'web asset count is invalid')
  }
  const assets = value.assets.map((entry, index) => {
    if (!entry || typeof entry !== 'object') fail('BAD_WEB_ASSET_MANIFEST', `assets[${index}] is invalid`)
    const canonical = canonicalPathBytes(entry.path)
    return Object.freeze({
      path: canonical.path,
      pathBytes: canonical.bytes,
      byteLength: u64(entry.byteLength, `assets[${index}].byteLength`),
      assetHash: fixed32(entry.assetHash, `assets[${index}].assetHash`)
    })
  })
  for (let index = 1; index < assets.length; index++) {
    if (compareBytes(assets[index - 1].pathBytes, assets[index].pathBytes) >= 0) {
      fail('BAD_WEB_ASSET_MANIFEST', 'web asset paths are not strictly sorted')
    }
  }
  return Object.freeze({
    version: 1,
    releaseSequence: u64(value.releaseSequence, 'releaseSequence'),
    appArtifactHash: fixed32(value.appArtifactHash, 'appArtifactHash'),
    recommendedBootstrapHashes: Object.freeze(recommendedBootstrapHashes),
    assets: Object.freeze(assets)
  })
}

export function encodePeeritWebAssetManifestV1 (input) {
  const value = canonicalManifestValue(input)
  const writer = new CanonicalWriter()
  writer.u16(PEERIT_WEB_ASSET_MANIFEST_TAG, 'WebAssetManifestV1 tag')
  writer.u8(1, 'version')
  writer.u64(value.releaseSequence, 'releaseSequence')
  writer.fixed(value.appArtifactHash, 32, 'appArtifactHash')
  writer.u8(value.recommendedBootstrapHashes.length, 'recommended bootstrap count')
  for (const hash of value.recommendedBootstrapHashes) writer.fixed(hash, 32, 'recommended bootstrap hash')
  writer.u16(value.assets.length, 'asset count')
  for (const asset of value.assets) {
    writer.u16(asset.pathBytes.byteLength, 'asset path length')
    writer.fixed(asset.pathBytes, asset.pathBytes.byteLength, 'asset path')
    writer.u64(asset.byteLength, 'asset byte length')
    writer.fixed(asset.assetHash, 32, 'asset hash')
  }
  return writer.finish()
}

export function decodePeeritWebAssetManifestV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'WebAssetManifestV1'))
  const reader = new CanonicalReader(bytes)
  if (reader.u16('WebAssetManifestV1 tag') !== PEERIT_WEB_ASSET_MANIFEST_TAG ||
      reader.u8('version') !== 1) {
    fail('BAD_WEB_ASSET_MANIFEST', 'WebAssetManifestV1 tag or version is invalid')
  }
  const releaseSequence = reader.u64('releaseSequence')
  const appArtifactHash = reader.fixed(32, 'appArtifactHash')
  const bootstrapCount = reader.u8('recommended bootstrap count')
  if (bootstrapCount > PEERIT_WEB_ASSET_LIMITS.maximumBootstrapHashes) {
    fail('BAD_WEB_ASSET_MANIFEST', 'recommended bootstrap hash count is invalid')
  }
  const recommendedBootstrapHashes = []
  for (let index = 0; index < bootstrapCount; index++) {
    recommendedBootstrapHashes.push(reader.fixed(32, `recommendedBootstrapHashes[${index}]`))
  }
  const assetCount = reader.u16('asset count')
  if (assetCount < 1 || assetCount > PEERIT_WEB_ASSET_LIMITS.maximumAssets) {
    fail('BAD_WEB_ASSET_MANIFEST', 'web asset count is invalid')
  }
  const assets = []
  for (let index = 0; index < assetCount; index++) {
    const pathLength = reader.u16(`assets[${index}].path length`)
    if (pathLength < 1 || pathLength > PEERIT_WEB_ASSET_LIMITS.maximumPathBytes) {
      fail('BAD_WEB_ASSET_PATH', 'web asset path length is invalid')
    }
    const pathBytes = reader.fixed(pathLength, `assets[${index}].path`)
    const canonical = canonicalPathBytes(pathBytes)
    if (!bytesEqual(canonical.bytes, pathBytes)) fail('BAD_WEB_ASSET_PATH', 'web asset path bytes are noncanonical')
    assets.push({
      path: canonical.path,
      byteLength: reader.u64(`assets[${index}].byteLength`),
      assetHash: reader.fixed(32, `assets[${index}].assetHash`)
    })
  }
  reader.expectEnd('WebAssetManifestV1')
  const value = canonicalManifestValue({
    version: 1,
    releaseSequence,
    appArtifactHash,
    recommendedBootstrapHashes,
    assets
  })
  if (!bytesEqual(encodePeeritWebAssetManifestV1(value), bytes)) {
    fail('BAD_WEB_ASSET_MANIFEST', 'WebAssetManifestV1 is noncanonical')
  }
  return value
}

export function hashPeeritWebAssetManifestV1 (input) {
  return domainLengthHash(PEERIT_WEB_ASSET_MANIFEST_HASH_DOMAIN, input)
}

export function hashPeeritAppArtifactV1 (input) {
  return domainLengthHash(PEERIT_APP_ARTIFACT_HASH_DOMAIN, input)
}

export function verifyPeeritWebAssetBytesV1 (manifest, suppliedAssets, options = {}) {
  manifest = manifest && manifest.assets ? manifest : decodePeeritWebAssetManifestV1(manifest)
  for (const asset of manifest.assets) assertRuntimePath(asset.path)
  const supplied = suppliedAssets instanceof Map ? new Map(suppliedAssets) : new Map(Object.entries(suppliedAssets || {}))
  const manifestPaths = new Set(manifest.assets.map(asset => asset.path))
  const requiredPaths = options.requiredPaths || manifest.assets.map(asset => asset.path)
  for (const path of requiredPaths) {
    if (!manifestPaths.has(path)) fail('WEB_ASSET_MISSING', `${path} is absent from signed WebAssetManifestV1`)
    if (!supplied.has(path)) fail('WEB_ASSET_MISSING', `${path} bytes are unavailable`)
  }
  if (options.requireComplete === true && supplied.size !== manifest.assets.length) {
    fail('WEB_ASSET_SET_INCOMPLETE', 'supplied web asset set does not equal the signed manifest')
  }
  for (const asset of manifest.assets) {
    if (!supplied.has(asset.path)) continue
    const bytes = new Uint8Array(asBytes(supplied.get(asset.path), asset.path))
    if (BigInt(bytes.byteLength) !== asset.byteLength || !bytesEqual(blake2b256(bytes), asset.assetHash)) {
      fail('WEB_ASSET_DRIFT', `${asset.path} does not match signed WebAssetManifestV1`)
    }
  }
  for (const path of supplied.keys()) {
    if (!manifestPaths.has(path)) fail('WEB_ASSET_UNLISTED', `${path} is not listed by signed WebAssetManifestV1`)
  }
  return Object.freeze({
    releaseSequence: manifest.releaseSequence,
    verifiedAssetCount: supplied.size,
    complete: supplied.size === manifest.assets.length
  })
}
