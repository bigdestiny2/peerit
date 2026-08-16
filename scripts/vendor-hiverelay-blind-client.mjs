#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { createHiveRelayExactGitSourceV1 } from './lib/hiverelay-exact-git-source.mjs'
import { verifyBlindClientBrowserReleaseV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
import {
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
} from '../js/substrate/profile-codec-ir.mjs'

const root = path.resolve(new URL('..', import.meta.url).pathname)
const hiveRoot = path.resolve(
  process.argv.find(value => value.startsWith('--hiverelay-root='))?.slice('--hiverelay-root='.length) ||
  process.env.HIVERELAY_BLIND_ROOT ||
  '/Users/localllm/.pear-wt/s29artifact5')
const check = process.argv.includes('--check')
const destination = path.join(root, 'vendor', 'hiverelay-blind-client-v1')
const paths = Object.freeze({
  sourceArtifact: 'blind-client-public-control-v1.mjs',
  sourceManifest: 'blind-client-public-control-v1.manifest.cenc',
  sourceChromiumEvidence: 'blind-client-public-control-v1.chromium-evidence.json',
  sourceCrossHostEvidence: 'blind-client-public-control-v1.cross-host-evidence.json',
  artifact: 'blind-client-control-v1.mjs',
  manifest: 'blind-client-control-v1.manifest.cenc',
  chromiumEvidence: 'blind-client-control-v1.chromium-evidence.json',
  crossHostEvidence: 'blind-client-control-v1.cross-host-evidence.json'
})
const EXPECTED = Object.freeze({
  candidateCommit: 'adeacef07c5de4d17d5ed1389fee7a35095b862f',
  candidateTree: '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c',
  acceptedSourceCommit: '1a114f64c97547cab6a18102c2ef4bff930e53ed',
  acceptedSourceTree: '5a341ba17a3d91a750cac94ba51116fe3552a6aa',
  artifactLength: 234813,
  artifactRawSha256: '88e51864c4a21296e64864523a7d602a1df6e24beed7dbbed45690c05eb1902f',
  manifestRawSha256: '454fb9af836e5fd4e59e0a7c45a02dba1b657b5ceba8a2807ebb656ed58b096f',
  chromiumEvidenceRawSha256: '29ed42c71a83b0c3a7c5a1bfb366e0606fe349ea3a6c8fe7d9e9624c51b9b2c0',
  crossHostEvidenceRawSha256: '5d5bfa8c0d1be2256ff328af6836d120bd4015f975dfed7a1e463b80d27e34cc',
  artifactHash: 'f1d1711f4dd0d96924ee0c86d6c3e7b994af9de878ae4e751062004fa30241eb',
  manifestHash: '720855632e60eb230b3b434e67865231067373ff888edd9c72282fb2ef3982c0',
  tupleHash: 'd6ea9227fb94e987526f857ac10eedd6939010d8fad8792776b77dd53ea2e6af',
  sourceClosureHash: 'a021373afd51e6e80d5c4143ff8b80a3c305f69d45c12f2296ad98e06cd2d461',
  normalizedGraphHash: '5c90ed22f25725ec390974aa53add72465f0948e2fd319506684d575238a5997',
  normalizedGraphSetHash: '240dc9762391ab59539da2d01b7858055fb0579d8e9b3f7afe84b9ba369160bd'
})

const source = createHiveRelayExactGitSourceV1({
  root: hiveRoot,
  commit: EXPECTED.candidateCommit,
  expectedTree: EXPECTED.candidateTree
})
const bytes = name => new Uint8Array(source.read(
  `packages/blind-client-public-browser/browser-artifacts/${name}`))
const sha256 = value => createHash('sha256').update(value).digest('hex')
const candidateCommit = source.commit
const candidateTree = source.tree
const artifactBytes = bytes(paths.sourceArtifact)
const manifestBytes = bytes(paths.sourceManifest)
const chromiumEvidenceBytes = bytes(paths.sourceChromiumEvidence)
const crossHostEvidenceBytes = bytes(paths.sourceCrossHostEvidence)
if (artifactBytes.byteLength !== EXPECTED.artifactLength ||
    sha256(artifactBytes) !== EXPECTED.artifactRawSha256 ||
    sha256(manifestBytes) !== EXPECTED.manifestRawSha256 ||
    sha256(chromiumEvidenceBytes) !== EXPECTED.chromiumEvidenceRawSha256 ||
    sha256(crossHostEvidenceBytes) !== EXPECTED.crossHostEvidenceRawSha256) {
  throw new Error('HiveRelay public-browser full artifact does not equal Peerit\'s frozen external acceptance input')
}
const decoded = JSON.parse(Buffer.from(manifestBytes).toString('utf8'))
const chromiumEvidence = JSON.parse(Buffer.from(chromiumEvidenceBytes).toString('utf8'))
const crossHostEvidence = JSON.parse(Buffer.from(crossHostEvidenceBytes).toString('utf8'))
if (decoded.acceptedSourceCommit !== EXPECTED.acceptedSourceCommit ||
    decoded.acceptedSourceTree !== EXPECTED.acceptedSourceTree) {
  throw new Error('HiveRelay public-browser accepted source identity changed')
}
const chromium = Object.freeze({
  version: chromiumEvidence.chromium,
  executablePath: chromiumEvidence.chromiumExecutablePath,
  executableHash: chromiumEvidence.chromiumExecutableHash,
  contentSecurityPolicyHash: chromiumEvidence.contentSecurityPolicyHash,
  requestInventory: chromiumEvidence.requestInventory,
  securityPolicyViolationCount: chromiumEvidence.securityPolicyViolationCount,
  errorCount: chromiumEvidence.errorCount,
  unhandledRejectionCount: chromiumEvidence.unhandledRejectionCount
})
const crossHost = Object.freeze({
  candidateIdentityBinding: crossHostEvidence.candidateIdentityBinding,
  sourceArchiveIdentity: crossHostEvidence.sourceArchiveIdentity,
  hostNode: crossHostEvidence.hostNode,
  hostModulesAbi: crossHostEvidence.hostModulesAbi,
  hostNapi: crossHostEvidence.hostNapi,
  hostPlatform: crossHostEvidence.hostPlatform,
  hostArchitecture: crossHostEvidence.hostArchitecture,
  nativeAddonHash: crossHostEvidence.nativeAddonHash,
  containerImageId: crossHostEvidence.containerImageId,
  containerPlatform: crossHostEvidence.containerPlatform,
  containerArchitecture: crossHostEvidence.containerArchitecture,
  containerNode: crossHostEvidence.containerNode,
  containerModulesAbi: crossHostEvidence.containerModulesAbi,
  containerNapi: crossHostEvidence.containerNapi,
  normalizedGraphHash: crossHostEvidence.normalizedGraphHash,
  normalizedGraphSetHash: crossHostEvidence.normalizedGraphSetHash
})

const authority = Buffer.from(JSON.stringify({
  schema: 'PeeritVendoredHiveRelayBlindClientV2',
  version: 2,
  upstreamPackage: '@hiverelay/blind-client-public-browser',
  candidateCommit: EXPECTED.candidateCommit,
  candidateTree: EXPECTED.candidateTree,
  acceptedSourceCommit: EXPECTED.acceptedSourceCommit,
  acceptedSourceTree: EXPECTED.acceptedSourceTree,
  upstreamArtifactPath: decoded.artifactPath,
  artifactPath: `vendor/hiverelay-blind-client-v1/${paths.artifact}`,
  artifactLength: EXPECTED.artifactLength,
  artifactRawSha256: EXPECTED.artifactRawSha256,
  manifestRawSha256: EXPECTED.manifestRawSha256,
  artifactHash: EXPECTED.artifactHash,
  manifestHash: EXPECTED.manifestHash,
  browserTupleHash: EXPECTED.tupleHash,
  sourceClosureHash: EXPECTED.sourceClosureHash,
  normalizedGraphHash: EXPECTED.normalizedGraphHash,
  normalizedGraphSetHash: EXPECTED.normalizedGraphSetHash,
  candidateEvidenceAuthority: 'external-postcommit-final-sequence',
  standaloneAuthority: false,
  wireTuple: PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1,
  clientComposition: PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  exactSortedExports: decoded.exactSortedExports,
  chromium,
  crossHost
}, null, 2) + '\n')
verifyBlindClientBrowserReleaseV1({
  artifactBytes,
  manifestBytes,
  chromiumEvidenceBytes,
  crossHostEvidenceBytes,
  authorityBytes: authority
})
const outputs = new Map([
  [paths.artifact, Buffer.from(artifactBytes)],
  [paths.manifest, Buffer.from(manifestBytes)],
  [paths.chromiumEvidence, Buffer.from(chromiumEvidenceBytes)],
  [paths.crossHostEvidence, Buffer.from(crossHostEvidenceBytes)],
  ['authority.json', authority]
])

if (check) {
  for (const [name, expected] of outputs) {
    const file = path.join(destination, name)
    if (!fs.existsSync(file) || !fs.readFileSync(file).equals(expected)) {
      throw new Error(`vendored HiveRelay public-browser artifact drift: ${name}`)
    }
  }
  if (fs.readdirSync(destination).sort().join('\n') !== [...outputs.keys()].sort().join('\n')) {
    throw new Error('vendored HiveRelay public-browser directory contains missing or extra files')
  }
} else {
  fs.mkdirSync(destination, { recursive: true })
  for (const [name, value] of outputs) fs.writeFileSync(path.join(destination, name), value)
}

process.stdout.write(`${JSON.stringify({
  schema: 'PeeritVendoredHiveRelayBlindClientResultV2',
  checked: check,
  candidateCommit,
  candidateTree,
  artifactLength: EXPECTED.artifactLength,
  artifactHash: EXPECTED.artifactHash,
  manifestHash: EXPECTED.manifestHash,
  tupleHash: EXPECTED.tupleHash,
  sourceClosureHash: EXPECTED.sourceClosureHash
}, null, 2)}\n`)
