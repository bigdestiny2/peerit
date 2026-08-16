#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { createHiveRelayExactGitSourceV1 } from './lib/hiverelay-exact-git-source.mjs'
import { verifyBlindClientCellGetBrowserReleaseV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
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
const destination = path.join(root, 'vendor', 'hiverelay-blind-cell-get-v1')
const names = Object.freeze({
  sourceArtifact: 'blind-client-public-cell-get-v1.mjs',
  sourceManifest: 'blind-client-public-cell-get-v1.manifest.cenc',
  sourceChromium: 'blind-client-public-cell-get-v1.chromium-evidence.json',
  sourceCrossHost: 'blind-client-public-cell-get-v1.cross-host-evidence.json',
  artifact: 'blind-client-cell-get-v1.mjs',
  manifest: 'blind-client-cell-get-v1.manifest.cenc',
  chromium: 'blind-client-cell-get-v1.chromium-evidence.json',
  crossHost: 'blind-client-cell-get-v1.cross-host-evidence.json'
})
const EXPECTED = Object.freeze({
  candidateCommit: 'adeacef07c5de4d17d5ed1389fee7a35095b862f',
  candidateTree: '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c',
  acceptedSourceCommit: '1a114f64c97547cab6a18102c2ef4bff930e53ed',
  acceptedSourceTree: '5a341ba17a3d91a750cac94ba51116fe3552a6aa',
  artifactLength: 191474,
  artifactRawSha256: 'c4de3329a35ee0a6514cabfa8763e1217f6ab1fc5650ca794db5e3b9b17a6ebc',
  manifestRawSha256: '94d95bbc2cf2a779562eb8ce4a6207a1354238c8e5f5453fbf2e742687180e12',
  chromiumEvidenceRawSha256: '83be7a5e096e3104ca278417d8691a47894774e5fc4a3c59b7079139f1bed9e0',
  crossHostEvidenceRawSha256: '727f4cc3fc9d12411fec104db37593b7ea0a33e8954fc28346f9b5ab6b6fa642',
  artifactHash: 'ef60c0a45fe093d214cddb17f207675dfdf1df3bb5861bc9ea24542376bffb1c',
  manifestHash: 'b483a8fcd032a378640f7f3a3da28650d6defdd8e9d7d78a01ee313e24ac5efa',
  tupleHash: '30c2c6c4bedfbf8cd77436a82c247490a09de9b46dfc45f28675c8cbb9df3b49',
  sourceClosureHash: 'a021373afd51e6e80d5c4143ff8b80a3c305f69d45c12f2296ad98e06cd2d461',
  normalizedGraphHash: '867e0227b56336eb7eb4ea2c0aff4874e88c2fdf38261a594b95b15c0c663fff',
  normalizedGraphSetHash: '240dc9762391ab59539da2d01b7858055fb0579d8e9b3f7afe84b9ba369160bd'
})
const source = createHiveRelayExactGitSourceV1({
  root: hiveRoot,
  commit: EXPECTED.candidateCommit,
  expectedTree: EXPECTED.candidateTree
})
const read = name => new Uint8Array(source.read(
  `packages/blind-client-public-browser/browser-artifacts/${name}`))
const sha256 = value => createHash('sha256').update(value).digest('hex')
const candidateCommit = source.commit
const candidateTree = source.tree
const artifactBytes = read(names.sourceArtifact)
const manifestBytes = read(names.sourceManifest)
const chromiumEvidenceBytes = read(names.sourceChromium)
const crossHostEvidenceBytes = read(names.sourceCrossHost)
if (artifactBytes.byteLength !== EXPECTED.artifactLength ||
    sha256(artifactBytes) !== EXPECTED.artifactRawSha256 ||
    sha256(manifestBytes) !== EXPECTED.manifestRawSha256 ||
    sha256(chromiumEvidenceBytes) !== EXPECTED.chromiumEvidenceRawSha256 ||
    sha256(crossHostEvidenceBytes) !== EXPECTED.crossHostEvidenceRawSha256) {
  throw new Error('HiveRelay public-browser Cell-GET artifact does not equal Peerit\'s frozen external acceptance input')
}
const decoded = JSON.parse(Buffer.from(manifestBytes).toString('utf8'))
const chromiumEvidence = JSON.parse(Buffer.from(chromiumEvidenceBytes).toString('utf8'))
const crossHostEvidence = JSON.parse(Buffer.from(crossHostEvidenceBytes).toString('utf8'))
if (decoded.acceptedSourceCommit !== EXPECTED.acceptedSourceCommit || decoded.acceptedSourceTree !== EXPECTED.acceptedSourceTree) {
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
  schema: 'PeeritVendoredHiveRelayBlindCellGetClientV2',
  version: 2,
  scope: 'DESCRIBE.GET+DESCRIBE.CHALLENGE+CELL.GET',
  networkPuts: 0,
  upstreamPackage: '@hiverelay/blind-client-public-browser',
  candidateCommit: EXPECTED.candidateCommit,
  candidateTree: EXPECTED.candidateTree,
  acceptedSourceCommit: EXPECTED.acceptedSourceCommit,
  acceptedSourceTree: EXPECTED.acceptedSourceTree,
  upstreamArtifactPath: decoded.artifactPath,
  artifactPath: `vendor/hiverelay-blind-cell-get-v1/${names.artifact}`,
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
verifyBlindClientCellGetBrowserReleaseV1({
  artifactBytes,
  manifestBytes,
  chromiumEvidenceBytes,
  crossHostEvidenceBytes,
  authorityBytes: authority
})
const outputs = new Map([
  [names.artifact, Buffer.from(artifactBytes)], [names.manifest, Buffer.from(manifestBytes)],
  [names.chromium, Buffer.from(chromiumEvidenceBytes)], [names.crossHost, Buffer.from(crossHostEvidenceBytes)],
  ['authority.json', authority]
])
if (check) {
  for (const [name, expected] of outputs) {
    const file = path.join(destination, name)
    if (!fs.existsSync(file) || !fs.readFileSync(file).equals(expected)) {
      throw new Error(`vendored HiveRelay public-browser Cell-GET drift: ${name}`)
    }
  }
  if (fs.readdirSync(destination).sort().join('\n') !== [...outputs.keys()].sort().join('\n')) {
    throw new Error('vendored HiveRelay public-browser Cell-GET directory contains missing or extra files')
  }
} else {
  fs.mkdirSync(destination, { recursive: true })
  for (const [name, value] of outputs) fs.writeFileSync(path.join(destination, name), value)
}
process.stdout.write(`${JSON.stringify({
  schema: 'PeeritVendoredHiveRelayBlindCellGetClientResultV2',
  checked: check,
  candidateCommit,
  candidateTree,
  artifactLength: EXPECTED.artifactLength,
  artifactHash: EXPECTED.artifactHash,
  manifestHash: EXPECTED.manifestHash,
  tupleHash: EXPECTED.tupleHash,
  sourceClosureHash: EXPECTED.sourceClosureHash
}, null, 2)}\n`)
