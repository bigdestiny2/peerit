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
  '/private/tmp/hiverelay-seed-head-bootstrap')
const check = process.argv.includes('--check')
const sourceRoot = path.join(hiveRoot, 'packages', 'blind-client')
const sourceArtifacts = path.join(sourceRoot, 'browser-artifacts')
const destination = path.join(root, 'vendor', 'hiverelay-blind-cell-get-v1')
const paths = Object.freeze({
  artifact: 'blind-client-cell-get-v1.mjs',
  manifest: 'blind-client-cell-get-v1.manifest.cenc',
  chromiumEvidence: 'blind-client-cell-get-v1.chromium-evidence.json',
  crossHostEvidence: 'blind-client-cell-get-v1.cross-host-evidence.json'
})
const EXPECTED = Object.freeze({
  artifactLength: 173893,
  artifactHash: '2c3400b61daea60670fd1b4003d8cfdc107e8ef78742dc2ba6bbbd443f6c7502',
  manifestHash: 'cf7fa1d6bc231d1c73f65b0abf9bf0818834b2281e08cee3df0f88149e58f92d',
  sourceClosureHash: 'd1cf41a27fe66543d7e6afaccaf09f460b467c8d0751394eabef2853030d3ad5'
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
  throw new Error('final HiveRelay Cell-GET browser artifact does not equal Peerit\'s frozen vendor authority')
}
const decoded = browserAuthority.decodeBlindClientBrowserArtifactManifestV1(manifestBytes)
if (decoded.artifactPath !== browserAuthority.BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS.artifactPath ||
    hex(decoded.sourceClosureHash) !== EXPECTED.sourceClosureHash) {
  throw new Error('final HiveRelay Cell-GET artifact path or source closure changed')
}

const authority = Buffer.from(JSON.stringify({
  schema: 'PeeritVendoredHiveRelayBlindCellGetClientV1',
  version: 1,
  scope: 'DESCRIBE.GET+DESCRIBE.CHALLENGE+CELL.GET',
  networkPuts: 0,
  upstreamPackage: '@hiverelay/blind-client',
  upstreamArtifactPath: browserAuthority.BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS.artifactPath,
  artifactPath: `vendor/hiverelay-blind-cell-get-v1/${paths.artifact}`,
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
      throw new Error(`vendored HiveRelay Cell-GET browser artifact drift: ${name}`)
    }
  }
  const names = fs.readdirSync(destination).sort()
  if (names.join('\n') !== [...outputs.keys()].sort().join('\n')) {
    throw new Error('vendored HiveRelay Cell-GET directory contains missing or extra files')
  }
} else {
  fs.mkdirSync(destination, { recursive: true })
  for (const [name, value] of outputs) fs.writeFileSync(path.join(destination, name), value)
}

process.stdout.write(`${JSON.stringify({
  schema: 'PeeritVendoredHiveRelayBlindCellGetClientResultV1',
  checked: check,
  hiveRoot,
  destination: path.relative(root, destination),
  artifactLength: EXPECTED.artifactLength,
  artifactHash: EXPECTED.artifactHash,
  manifestHash: EXPECTED.manifestHash,
  sourceClosureHash: EXPECTED.sourceClosureHash
}, null, 2)}\n`)
