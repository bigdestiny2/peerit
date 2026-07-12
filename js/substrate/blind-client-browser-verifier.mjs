import {
  asBytes,
  bytesEqual,
  bytesToHex,
  decodeUtf8,
  domainLengthHash,
  utf8Bytes
} from './release-control-primitives.mjs'

const MAGIC = utf8Bytes('HIVERELAY-BLIND-CLIENT-BROWSER-V1')
const ARTIFACT_PATH = 'browser-artifacts/blind-client-control-v1.mjs'
const MAX_ARTIFACT_BYTES = 320 * 1024
const ARTIFACT_HASH_DOMAIN = 'hiverelay.blind.client-browser-artifact-hash.v1'
const MANIFEST_HASH_DOMAIN = 'hiverelay.blind.client-browser-artifact-manifest-hash.v1'
const CHROMIUM_CHECKS = Object.freeze([
  'STANDALONE_ESM_IMPORT',
  'REQUIRED_CONTROL_EXPORTS',
  'CLOSED_EXTERNAL_PROFILE_DECODER',
  'WEBCRYPTO_AES_256_GCM_ROUNDTRIP',
  'SIGNED_CAPABILITY_CELL_COMPOSITION',
  'PLAINTEXT_SENTINEL_ABSENT_FROM_REQUEST'
])
const CROSS_HOST_CHECKS = Object.freeze([
  'CLEAN_LINUX_DEPENDENCY_INSTALL',
  'FROZEN_GENERATOR_CHECK',
  'ARTIFACT_BYTE_EQUALITY',
  'MANIFEST_BYTE_EQUALITY'
])

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function fixed32 (value, field) {
  const output = new Uint8Array(asBytes(value, field))
  if (output.byteLength !== 32) fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} must be 32 bytes`)
  return output
}

class Reader {
  constructor (input) {
    this.bytes = new Uint8Array(asBytes(input, 'blind-client browser manifest'))
    this.offset = 0
  }

  take (length, field) {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.byteLength) {
      fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `truncated ${field}`)
    }
    const output = this.bytes.slice(this.offset, this.offset + length)
    this.offset += length
    return output
  }

  u8 (field) { return this.take(1, field)[0] }

  u16 (field) {
    const bytes = this.take(2, field)
    return (bytes[0] << 8) | bytes[1]
  }

  u64 (field) {
    let value = 0n
    for (const byte of this.take(8, field)) value = (value << 8n) | BigInt(byte)
    return value
  }

  text (field) {
    const bytes = this.take(this.u16(`${field} length`), field)
    const value = decodeUtf8(bytes, field)
    if (!bytesEqual(utf8Bytes(value), bytes) || bytes.byteLength > 1024 || value.length < 1) {
      fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is noncanonical`)
    }
    return value
  }

  end () {
    if (this.offset !== this.bytes.byteLength) {
      fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'blind-client browser manifest has trailing bytes')
    }
  }
}

export function decodeBlindClientBrowserManifestV1 (input) {
  const reader = new Reader(input)
  if (!bytesEqual(reader.take(MAGIC.byteLength, 'magic'), MAGIC) ||
      reader.u8('version') !== 1 || reader.u8('draft') !== 0) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'blind-client browser manifest is not final v1')
  }
  const value = Object.freeze({
    specHash: fixed32(reader.take(32, 'specHash'), 'specHash'),
    abiHash: fixed32(reader.take(32, 'abiHash'), 'abiHash'),
    vectorSetHash: fixed32(reader.take(32, 'vectorSetHash'), 'vectorSetHash'),
    clientCompositionFormatHash: fixed32(
      reader.take(32, 'clientCompositionFormatHash'), 'clientCompositionFormatHash'),
    clientCompositionVectorSetHash: fixed32(
      reader.take(32, 'clientCompositionVectorSetHash'), 'clientCompositionVectorSetHash'),
    toolchain: reader.text('toolchain'),
    buildProfile: reader.text('buildProfile'),
    sourceClosureHash: fixed32(reader.take(32, 'sourceClosureHash'), 'sourceClosureHash'),
    artifactPath: reader.text('artifactPath'),
    artifactLength: reader.u64('artifactLength'),
    artifactHash: fixed32(reader.take(32, 'artifactHash'), 'artifactHash')
  })
  reader.end()
  if (value.artifactPath !== ARTIFACT_PATH || value.artifactLength < 1n ||
      value.artifactLength > BigInt(MAX_ARTIFACT_BYTES)) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'blind-client browser artifact path or size is invalid')
  }
  return value
}

function canonicalEvidence (input, field) {
  const bytes = new Uint8Array(asBytes(input, field))
  if (bytes.byteLength < 1 || bytes.byteLength > 16 * 1024) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is outside its byte limit`)
  }
  const source = decodeUtf8(bytes, field)
  let parsed
  try { parsed = JSON.parse(source) } catch { fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is invalid JSON`) }
  if (JSON.stringify(parsed, null, 2) + '\n' !== source) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is noncanonical JSON`)
  }
  return parsed
}

function exactKeys (value, keys, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} fields are invalid`)
  }
}

function exactChecks (actual, expected, field) {
  if (!Array.isArray(actual) || actual.length !== expected.length ||
      actual.some((value, index) => value !== expected[index])) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} checks are invalid`)
  }
}

export function verifyBlindClientBrowserReleaseV1 (input) {
  const manifestBytes = new Uint8Array(asBytes(input.manifestBytes, 'blind-client browser manifest'))
  const artifactBytes = new Uint8Array(asBytes(input.artifactBytes, 'blind-client browser artifact'))
  const manifest = decodeBlindClientBrowserManifestV1(manifestBytes)
  const manifestHash = domainLengthHash(MANIFEST_HASH_DOMAIN, manifestBytes)
  const artifactHash = domainLengthHash(ARTIFACT_HASH_DOMAIN, artifactBytes)
  if (BigInt(artifactBytes.byteLength) !== manifest.artifactLength ||
      !bytesEqual(artifactHash, manifest.artifactHash)) {
    fail('BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT', 'blind-client browser artifact does not match its manifest')
  }
  const expected = {
    artifactPath: ARTIFACT_PATH,
    artifactLength: artifactBytes.byteLength,
    artifactHash: bytesToHex(artifactHash),
    manifestHash: bytesToHex(manifestHash),
    sourceClosureHash: bytesToHex(manifest.sourceClosureHash)
  }
  const chromium = canonicalEvidence(input.chromiumEvidenceBytes, 'Chromium evidence')
  exactKeys(chromium, [
    'schema', 'version', 'evidenceClass', 'artifactPath', 'artifactLength',
    'artifactHash', 'manifestHash', 'sourceClosureHash', 'chromium', 'checks', 'passed'
  ], 'Chromium evidence')
  const crossHost = canonicalEvidence(input.crossHostEvidenceBytes, 'cross-host evidence')
  exactKeys(crossHost, [
    'schema', 'version', 'evidenceClass', 'artifactPath', 'artifactLength',
    'artifactHash', 'manifestHash', 'sourceClosureHash', 'platform', 'architecture',
    'containerImageId', 'node', 'toolchain', 'checks', 'passed'
  ], 'cross-host evidence')
  for (const [field, value] of Object.entries(expected)) {
    if (chromium[field] !== value || crossHost[field] !== value) {
      fail('BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE_MISMATCH', `${field} evidence does not bind the artifact`)
    }
  }
  if (chromium.schema !== 'HiveRelayBlindClientBrowserArtifactChromiumEvidenceV1' ||
      chromium.version !== 1 || chromium.evidenceClass !== 'real-chromium' || chromium.passed !== true ||
      typeof chromium.chromium !== 'string') {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', 'Chromium evidence authority is invalid')
  }
  if (crossHost.schema !== 'HiveRelayBlindClientBrowserArtifactCrossHostEvidenceV1' ||
      crossHost.version !== 1 || crossHost.evidenceClass !== 'clean-linux-container' ||
      crossHost.platform !== 'linux' || crossHost.toolchain !== manifest.toolchain ||
      crossHost.passed !== true || !/^sha256:[0-9a-f]{64}$/.test(crossHost.containerImageId)) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', 'cross-host evidence authority is invalid')
  }
  exactChecks(chromium.checks, CHROMIUM_CHECKS, 'Chromium evidence')
  exactChecks(crossHost.checks, CROSS_HOST_CHECKS, 'cross-host evidence')
  return Object.freeze({
    manifest,
    artifactBytes,
    manifestHash,
    artifactHash,
    chromium: chromium.chromium,
    crossHost: Object.freeze({
      platform: crossHost.platform,
      architecture: crossHost.architecture,
      containerImageId: crossHost.containerImageId,
      node: crossHost.node
    })
  })
}
