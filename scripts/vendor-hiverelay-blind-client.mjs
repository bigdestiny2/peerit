#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
} from '../js/substrate/profile-codec-ir.mjs'

const root = path.resolve(new URL('..', import.meta.url).pathname)
const hiveRoot = path.resolve(
  process.argv.find(value => value.startsWith('--hiverelay-root='))?.slice('--hiverelay-root='.length) ||
  process.env.HIVERELAY_BLIND_ROOT ||
  '/private/tmp/hiverelay-blind')
const check = process.argv.includes('--check')
const sourceRoot = path.join(hiveRoot, 'packages', 'blind-client')
const sourceArtifacts = path.join(sourceRoot, 'browser-artifacts')
const destination = path.join(root, 'vendor', 'hiverelay-blind-client-v1')
const paths = Object.freeze({
  artifact: 'blind-client-control-v1.mjs',
  manifest: 'blind-client-control-v1.manifest.cenc',
  chromiumEvidence: 'blind-client-control-v1.chromium-evidence.json',
  crossHostEvidence: 'blind-client-control-v1.cross-host-evidence.json'
})
const EXPECTED = Object.freeze({
  artifactLength: 224014,
  artifactHash: '17a7e06df5fac172204dc64c79b3398e3bef38a1869b92bd4bed85b6ae3e74f7',
  manifestHash: 'bf48196c56f419f02e27427f3b36bac8c8aa2a2eaa3c14475f6aceb85c195c5b',
  sourceClosureHash: '38cb0252e218ce07b616fd2697b14af42d629ce0c98a1278221cc95eb6ab91e0'
})

const bytes = name => new Uint8Array(fs.readFileSync(path.join(sourceArtifacts, name)))
const hex = value => Buffer.from(value).toString('hex')
const fromHex = value => new Uint8Array(Buffer.from(value, 'hex'))
const browserAuthority = await import(pathToFileURL(path.join(sourceRoot, 'browser-artifact.js')).href)
const artifactBytes = bytes(paths.artifact)
const manifestBytes = bytes(paths.manifest)
const chromiumEvidenceBytes = bytes(paths.chromiumEvidence)
const crossHostEvidenceBytes = bytes(paths.crossHostEvidence)
const expectedTuple = Object.freeze({
  ...Object.fromEntries(Object.entries(PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1)
    .map(([key, value]) => [key, fromHex(value)])),
  clientCompositionFormatHash: fromHex(
    PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1.formatHash),
  clientCompositionVectorSetHash: fromHex(
    PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1.vectorSetHash)
})
const verified = browserAuthority.verifyBlindClientBrowserArtifactReleaseEvidenceV1({
  manifestBytes,
  artifactBytes,
  expectedManifestHash: fromHex(EXPECTED.manifestHash),
  expectedTuple,
  chromiumEvidenceBytes,
  crossHostEvidenceBytes
})
if (!verified.releaseReady || artifactBytes.byteLength !== EXPECTED.artifactLength ||
    verified.artifactHash !== EXPECTED.artifactHash ||
    verified.manifestHash !== EXPECTED.manifestHash) {
  throw new Error('final HiveRelay browser artifact does not equal Peerit\'s frozen vendor authority')
}
const decoded = browserAuthority.decodeBlindClientBrowserArtifactManifestV1(manifestBytes)
if (hex(decoded.sourceClosureHash) !== EXPECTED.sourceClosureHash) {
  throw new Error('final HiveRelay browser artifact source closure changed')
}

const authority = Buffer.from(JSON.stringify({
  schema: 'PeeritVendoredHiveRelayBlindClientV1',
  version: 1,
  upstreamPackage: '@hiverelay/blind-client',
  upstreamArtifactPath: browserAuthority.BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.artifactPath,
  artifactPath: `vendor/hiverelay-blind-client-v1/${paths.artifact}`,
  artifactLength: EXPECTED.artifactLength,
  artifactHash: EXPECTED.artifactHash,
  manifestHash: EXPECTED.manifestHash,
  sourceClosureHash: EXPECTED.sourceClosureHash,
  wireTuple: PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1,
  clientComposition: PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  chromium: verified.chromium,
  crossHost: verified.crossHost
}, null, 2) + '\n')
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
      throw new Error(`vendored HiveRelay browser artifact drift: ${name}`)
    }
  }
  const names = fs.readdirSync(destination).sort()
  if (names.join('\n') !== [...outputs.keys()].sort().join('\n')) {
    throw new Error('vendored HiveRelay browser artifact directory contains missing or extra files')
  }
} else {
  fs.mkdirSync(destination, { recursive: true })
  for (const [name, value] of outputs) fs.writeFileSync(path.join(destination, name), value)
}

process.stdout.write(`${JSON.stringify({
  schema: 'PeeritVendoredHiveRelayBlindClientResultV1',
  checked: check,
  hiveRoot,
  destination: path.relative(root, destination),
  artifactLength: EXPECTED.artifactLength,
  artifactHash: EXPECTED.artifactHash,
  manifestHash: EXPECTED.manifestHash,
  sourceClosureHash: EXPECTED.sourceClosureHash
}, null, 2)}\n`)
