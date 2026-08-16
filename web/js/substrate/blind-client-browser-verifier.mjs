import {
  asBytes,
  bytesEqual,
  bytesToHex,
  decodeUtf8,
  domainLengthHash,
  hexToBytes
} from './release-control-primitives.mjs'

const MAX_ARTIFACT_BYTES = 320 * 1024
const ACCEPTED = Object.freeze({
  candidateCommit: 'adeacef07c5de4d17d5ed1389fee7a35095b862f',
  candidateTree: '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c',
  acceptedSourceCommit: '1a114f64c97547cab6a18102c2ef4bff930e53ed',
  acceptedSourceTree: '5a341ba17a3d91a750cac94ba51116fe3552a6aa',
  sourceClosureHash: 'a021373afd51e6e80d5c4143ff8b80a3c305f69d45c12f2296ad98e06cd2d461',
  normalizedGraphSetHash: '240dc9762391ab59539da2d01b7858055fb0579d8e9b3f7afe84b9ba369160bd'
})
const FULL = Object.freeze({
  authoritySchema: 'PeeritVendoredHiveRelayBlindClientV2',
  profile: 'hiverelay.blind-client-public-browser.full.v1',
  upstreamPath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-control-v1.mjs',
  vendoredPath: 'vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs',
  artifactDomain: 'hiverelay.blind-client-public-browser.full-artifact-hash.v1',
  manifestDomain: 'hiverelay.blind-client-public-browser.full-manifest-hash.v1',
  graphHash: '5c90ed22f25725ec390974aa53add72465f0948e2fd319506684d575238a5997',
  chromiumSchema: 'HiveRelayBlindClientPublicBrowserArtifactChromiumEvidenceV1'
})
const CELL_GET = Object.freeze({
  authoritySchema: 'PeeritVendoredHiveRelayBlindCellGetClientV2',
  profile: 'hiverelay.blind-client-public-browser.cell-get.v1',
  upstreamPath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-cell-get-v1.mjs',
  vendoredPath: 'vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs',
  artifactDomain: 'hiverelay.blind-client-public-browser.cell-get-artifact-hash.v1',
  manifestDomain: 'hiverelay.blind-client-public-browser.cell-get-manifest-hash.v1',
  graphHash: '867e0227b56336eb7eb4ea2c0aff4874e88c2fdf38261a594b95b15c0c663fff',
  chromiumSchema: 'HiveRelayBlindClientPublicBrowserArtifactChromiumEvidenceV1'
})

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function canonicalJson (input, field, maximum = 128 * 1024) {
  const bytes = new Uint8Array(asBytes(input, field))
  if (bytes.byteLength < 1 || bytes.byteLength > maximum) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is outside its byte bound`)
  }
  const source = decodeUtf8(bytes, field)
  let value
  try { value = JSON.parse(source) } catch {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is invalid JSON`)
  }
  if (JSON.stringify(value, null, 2) + '\n' !== source) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is noncanonical JSON`)
  }
  return value
}

function hex32 (value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} is not 32-byte lowercase hex`)
  }
  return hexToBytes(value, 32, field)
}

function exactArray (left, right, field) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length ||
      left.some((value, index) => value !== right[index])) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', `${field} differs from the accepted release`)
  }
}

function decodeAuthorityManifest (manifestBytes, authorityBytes, profile) {
  const manifest = canonicalJson(manifestBytes, 'blind-client public browser manifest')
  const authority = canonicalJson(authorityBytes, 'Peerit vendored browser authority')
  if (manifest.schema !== 'HiveRelayBlindClientPublicBrowserArtifactManifestV1' ||
      manifest.version !== 1 || manifest.profile !== profile.profile ||
      manifest.artifactPath !== profile.upstreamPath ||
      manifest.artifactHashDomain !== profile.artifactDomain ||
      manifest.manifestHashDomain !== profile.manifestDomain ||
      manifest.acceptedSourceCommit !== ACCEPTED.acceptedSourceCommit ||
      manifest.acceptedSourceTree !== ACCEPTED.acceptedSourceTree ||
      manifest.sourceClosureHash !== ACCEPTED.sourceClosureHash ||
      authority.schema !== profile.authoritySchema || authority.version !== 2 ||
      authority.upstreamPackage !== '@hiverelay/blind-client-public-browser' ||
      authority.candidateCommit !== ACCEPTED.candidateCommit ||
      authority.candidateTree !== ACCEPTED.candidateTree ||
      authority.acceptedSourceCommit !== ACCEPTED.acceptedSourceCommit ||
      authority.acceptedSourceTree !== ACCEPTED.acceptedSourceTree ||
      authority.sourceClosureHash !== ACCEPTED.sourceClosureHash ||
      authority.normalizedGraphHash !== profile.graphHash ||
      authority.normalizedGraphSetHash !== ACCEPTED.normalizedGraphSetHash ||
      authority.upstreamArtifactPath !== profile.upstreamPath ||
      authority.artifactPath !== profile.vendoredPath ||
      authority.artifactLength !== manifest.artifactLength ||
      authority.artifactHash !== manifest.artifactHash ||
      authority.browserTupleHash !== manifest.tupleHash ||
      authority.candidateEvidenceAuthority !== 'external-postcommit-final-sequence' ||
      authority.standaloneAuthority !== false) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'candidate manifest or vendored authority identity is invalid')
  }
  exactArray(manifest.exactSortedExports, authority.exactSortedExports, 'exact export inventory')
  const manifestHash = domainLengthHash(profile.manifestDomain, manifestBytes)
  if (bytesToHex(manifestHash) !== authority.manifestHash) {
    fail('BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT', 'manifest bytes differ from the accepted candidate')
  }
  return Object.freeze({ manifest, authority, manifestHash })
}

export function decodeBlindClientBrowserManifestV1 (input, authorityInput = null) {
  if (authorityInput == null) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'candidate manifest decoding requires its vendored authority')
  }
  return releaseManifest(decodeAuthorityManifest(input, authorityInput, FULL))
}

function releaseManifest ({ manifest, authority }) {
  return Object.freeze({
    specHash: hex32(authority.wireTuple.specHash, 'wire specHash'),
    abiHash: hex32(authority.wireTuple.abiHash, 'wire abiHash'),
    vectorSetHash: hex32(authority.wireTuple.vectorSetHash, 'wire vectorSetHash'),
    clientCompositionFormatHash: hex32(authority.clientComposition.formatHash, 'client composition format hash'),
    clientCompositionVectorSetHash: hex32(authority.clientComposition.vectorSetHash, 'client composition vector-set hash'),
    sourceClosureHash: hex32(manifest.sourceClosureHash, 'sourceClosureHash'),
    artifactPath: manifest.artifactPath,
    artifactLength: BigInt(manifest.artifactLength),
    artifactHash: hex32(manifest.artifactHash, 'artifactHash'),
    exactSortedExports: Object.freeze([...manifest.exactSortedExports]),
    toolchain: Object.freeze({ ...manifest.toolchain }),
    tupleHash: hex32(manifest.tupleHash, 'tupleHash')
  })
}

function evidence (input, field) {
  const value = canonicalJson(input, field)
  if (value.version !== 1 || value.evidenceClass == null || value.passed !== true ||
      value.candidateIdentityBinding !== 'external-postcommit-final-sequence' ||
      value.standaloneAuthority !== false) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', `${field} is not accepted candidate evidence`)
  }
  return value
}

function verifyRelease (input, profile) {
  const artifactBytes = new Uint8Array(asBytes(input.artifactBytes, 'browser artifact'))
  if (artifactBytes.byteLength < 1 || artifactBytes.byteLength > MAX_ARTIFACT_BYTES) {
    fail('BAD_BLIND_CLIENT_BROWSER_ARTIFACT', 'browser artifact is outside its fixed bound')
  }
  const decoded = decodeAuthorityManifest(input.manifestBytes, input.authorityBytes, profile)
  const manifest = releaseManifest(decoded)
  const artifactHash = domainLengthHash(profile.artifactDomain, artifactBytes)
  if (BigInt(artifactBytes.byteLength) !== manifest.artifactLength ||
      !bytesEqual(artifactHash, manifest.artifactHash) ||
      bytesToHex(artifactHash) !== decoded.authority.artifactHash) {
    fail('BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT', 'browser artifact does not match its candidate manifest')
  }
  const chromium = evidence(input.chromiumEvidenceBytes, 'Chromium evidence')
  const crossHost = evidence(input.crossHostEvidenceBytes, 'cross-host evidence')
  for (const value of [chromium, crossHost]) {
    if (value.profile !== profile.profile || value.artifactPath !== profile.upstreamPath ||
        value.artifactLength !== artifactBytes.byteLength || value.artifactHash !== bytesToHex(artifactHash) ||
        value.manifestHash !== bytesToHex(decoded.manifestHash) ||
        value.tupleHash !== decoded.authority.browserTupleHash ||
        value.sourceClosureHash !== ACCEPTED.sourceClosureHash) {
      fail('BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE_MISMATCH', 'candidate evidence does not bind the exact artifact')
    }
  }
  if (chromium.schema !== profile.chromiumSchema || chromium.evidenceClass !== 'real-chromium' ||
      crossHost.schema !== 'HiveRelayBlindClientPublicBrowserArtifactCrossHostEvidenceV1' ||
      crossHost.evidenceClass !== 'clean-linux-container' ||
      crossHost.acceptedSourceCommit !== ACCEPTED.acceptedSourceCommit ||
      crossHost.acceptedSourceTree !== ACCEPTED.acceptedSourceTree ||
      crossHost.normalizedGraphHash !== profile.graphHash ||
      crossHost.normalizedGraphSetHash !== ACCEPTED.normalizedGraphSetHash ||
      crossHost.containerPlatform !== 'linux/arm64' ||
      !/^sha256:[0-9a-f]{64}$/.test(crossHost.containerImageId)) {
    fail('BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE', 'candidate browser evidence identity is invalid')
  }
  return Object.freeze({
    manifest,
    artifactBytes,
    manifestHash: decoded.manifestHash,
    artifactHash,
    chromium: decoded.authority.chromium.version,
    crossHost: Object.freeze({ ...decoded.authority.crossHost })
  })
}

export function verifyBlindClientBrowserReleaseV1 (input) {
  return verifyRelease(input, FULL)
}

export function verifyBlindClientCellGetBrowserReleaseV1 (input) {
  return verifyRelease(input, CELL_GET)
}
