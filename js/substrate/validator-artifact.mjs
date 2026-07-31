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

export const PEERIT_VALIDATOR_ARTIFACT_PATH = 'protocol/validator/peerit-validator-v1.bundle'
export const PEERIT_VALIDATOR_VECTOR_MANIFEST_PATH = 'protocol/validator/peerit-validator-v1.manifest.cenc'
export const PEERIT_VALIDATOR_ARTIFACT_DOMAIN = 'peerit.hiverelay.validator-artifact-hash.v1'
export const PEERIT_VALIDATOR_VECTOR_SET_DOMAIN = 'peerit.hiverelay.validator-vector-set-hash.v1'

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function canonicalVectorPath (path) {
  if (typeof path !== 'string' || path.length === 0 || path !== path.normalize('NFC') ||
      path.startsWith('/') || path.includes('\\')) fail('BAD_VALIDATOR_VECTOR_PATH', 'validator vector path is not canonical')
  const components = path.split('/')
  if (components.some(component => component === '' || component === '.' || component === '..')) {
    fail('BAD_VALIDATOR_VECTOR_PATH', 'validator vector path contains a forbidden component')
  }
  const bytes = utf8Bytes(path, 'validator vector path')
  if (bytes.byteLength > 0xffff) fail('BAD_VALIDATOR_VECTOR_PATH', 'validator vector path exceeds u16')
  return bytes
}

export function encodePeeritValidatorVectorManifestV1 (entries) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 0xffffffff) {
    fail('BAD_VALIDATOR_VECTOR_MANIFEST', 'validator vector manifest must be a nonempty bounded array')
  }
  const rows = entries.map(entry => {
    const pathBytes = canonicalVectorPath(entry.path)
    const bytes = new Uint8Array(asBytes(entry.bytes, entry.path))
    return { path: entry.path, pathBytes, bytes }
  }).sort((left, right) => compareBytes(left.pathBytes, right.pathBytes))
  for (let index = 1; index < rows.length; index++) {
    if (bytesEqual(rows[index - 1].pathBytes, rows[index].pathBytes)) fail('BAD_VALIDATOR_VECTOR_MANIFEST', 'duplicate vector path')
  }
  const writer = new CanonicalWriter()
  writer.u32(rows.length, 'validator vector count')
  for (const row of rows) {
    writer.u16(row.pathBytes.byteLength, 'validator vector path length')
    writer.fixed(row.pathBytes, row.pathBytes.byteLength, 'validator vector path')
    writer.u64(BigInt(row.bytes.byteLength), 'validator vector byte length')
    writer.fixed(blake2b256(row.bytes), 32, 'validator vector hash')
  }
  return writer.finish()
}

export function decodePeeritValidatorVectorManifestV1 (input) {
  const bytes = new Uint8Array(asBytes(input, 'validator vector manifest'))
  const reader = new CanonicalReader(bytes)
  const count = reader.u32('validator vector count')
  if (count === 0 || count > Math.floor((bytes.byteLength - 4) / 43)) fail('BAD_VALIDATOR_VECTOR_MANIFEST', 'validator vector count is invalid')
  const rows = []
  let previous = null
  for (let index = 0; index < count; index++) {
    const pathLength = reader.u16('validator vector path length')
    if (pathLength === 0) fail('BAD_VALIDATOR_VECTOR_PATH', 'validator vector path is empty')
    const pathBytes = reader.fixed(pathLength, 'validator vector path')
    const path = decodeUtf8(pathBytes, 'validator vector path')
    if (!bytesEqual(pathBytes, canonicalVectorPath(path)) || (previous != null && compareBytes(previous, pathBytes) >= 0)) {
      fail('BAD_VALIDATOR_VECTOR_PATH', 'validator vector paths are noncanonical or unordered')
    }
    previous = pathBytes
    rows.push(Object.freeze({
      path,
      vectorLength: reader.u64('validator vector byte length'),
      vectorHash: reader.fixed(32, 'validator vector hash')
    }))
  }
  reader.expectEnd('validator vector manifest')
  return Object.freeze(rows)
}

export function hashPeeritValidatorArtifactV1 (bytes) {
  return domainLengthHash(PEERIT_VALIDATOR_ARTIFACT_DOMAIN, bytes)
}

export function hashPeeritValidatorVectorSetV1 (bytes) {
  return domainLengthHash(PEERIT_VALIDATOR_VECTOR_SET_DOMAIN, bytes)
}
