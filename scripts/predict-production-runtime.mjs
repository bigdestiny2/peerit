#!/usr/bin/env node

// Materialize the exact app/Web bytes that a production profile pin must sign
// before the detached pin-history bundle itself exists. Pin-history bytes are
// deliberately outside both hashes; their authenticated predecessor is still
// verified here and their presence selects the fixed runtime path.

import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync
} from 'node:fs'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  pinHistoryBundleHash,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import { bytesEqual, bytesToHex } from '../js/substrate/release-control-primitives.mjs'
import { normalizePeeritReleaseRelayHintsV1 } from '../js/substrate/release-relay-hints.mjs'
import { PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1, PEERIT_PRODUCTION_PIN_HISTORY_PATH } from '../js/substrate/production-release-authority.mjs'
import {
  encodePeeritSeedBootstrapV1,
  hashPeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import {
  PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE,
  deriveProductionPinBindingsV1
} from './production-pin-history-ceremony.mjs'
import {
  verifyPeeritPinHistoryReleaseBundleV1,
  verifyPeeritProductionPinHistoryReleaseV1
} from './production-pin-history-release.mjs'
import {
  buildPeeritSubstrateRuntimeArtifactV1,
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE,
  PEERIT_WEB_ASSET_MANIFEST_PATH
} from './substrate-runtime-artifact.mjs'

export const PEERIT_PRODUCTION_RUNTIME_PREDICTION_SCHEMA_V1 =
  'peerit-production-runtime-prediction-v1'
export const PEERIT_PRODUCTION_RUNTIME_PREDICTION_FILE =
  'peerit-production-runtime-prediction-v1.json'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HEX_32 = /^[0-9a-f]{64}$/
const OUTPUT_FILES = Object.freeze([
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_WEB_ASSET_MANIFEST_PATH,
  PEERIT_PRODUCTION_RUNTIME_PREDICTION_FILE
])

function fail (message, code = 'PEERIT_PRODUCTION_RUNTIME_PREDICTION_FAILED') {
  const error = new Error(message)
  error.code = code
  throw error
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function hex32 (value, field) {
  const raw = String(value || '')
  const normalized = raw.trim().toLowerCase()
  if (raw !== normalized || !HEX_32.test(normalized)) {
    fail(`${field} must be exact 32-byte lowercase hexadecimal`)
  }
  return normalized
}

function canonicalRepoPath (root, value, field) {
  if (typeof value !== 'string' || !value || isAbsolute(value) || value.includes('\\')) {
    fail(`${field} must be a canonical repository-relative path`)
  }
  const absolute = resolve(root, value)
  const rel = relative(root, absolute)
  if (!rel || rel.startsWith('..') || isAbsolute(rel) || rel.split('/').some(part => !part || part === '.' || part === '..')) {
    fail(`${field} escapes or does not name a repository file`)
  }
  return { relative: rel.replaceAll('\\', '/'), absolute }
}

function configBytes (options, root) {
  if (options.fixtureOnly === true && options.configBytes instanceof Uint8Array) {
    return Buffer.from(options.configBytes)
  }
  const path = resolve(root, options.configPath || 'deploy/web-release.json')
  return readFileSync(path)
}

function normalizeConfig (bytes) {
  let value
  try { value = JSON.parse(Buffer.from(bytes).toString('utf8')) } catch {
    fail('release config is not JSON')
  }
  const releaseSequence = Number(value.releaseSequence)
  if (value.substrateProfile !== 'blind-v1' ||
      !Number.isSafeInteger(releaseSequence) ||
      releaseSequence < PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE ||
      releaseSequence > PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE ||
      !Array.isArray(value.relayHints) ||
      value.productionPinHistoryBundle !== PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)) {
    fail(`release config must select exact blind-v1 sequence ${PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE}..${PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE} with the fixed production pin-history path`)
  }
  const relayHints = normalizePeeritReleaseRelayHintsV1(
    value.relayHints, 'production runtime prediction config')
  return Object.freeze({
    substrateProfile: 'blind-v1',
    relayHints: Object.freeze(relayHints),
    productionPinHistoryBundle: value.productionPinHistoryBundle,
    peeritSeedBootstrapBundle: String(value.peeritSeedBootstrapBundle || ''),
    peeritSeedDiscoveryAuthorityPublicKey: hex32(
      value.peeritSeedDiscoveryAuthorityPublicKey,
      'peeritSeedDiscoveryAuthorityPublicKey'),
    releaseSequence,
    pinnedReleaseKey: hex32(value.pinnedReleaseKey, 'pinnedReleaseKey')
  })
}

function exactSourceFiles (root, options) {
  if (options.fixtureOnly === true && options.sourceFiles instanceof Map) {
    return new Map([...options.sourceFiles].map(([path, bytes]) => [path, Buffer.from(bytes)]))
  }
  return new Map(SUBSTRATE_SITE_FILES.map(path => [path, readFileSync(resolve(root, path))]))
}

function sourceHashes (sourceFiles) {
  return Object.fromEntries([...sourceFiles]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([path, bytes]) => [path, sha256(bytes)]))
}

function assertProductionBindings (terminal, root) {
  const expected = deriveProductionPinBindingsV1(root)
  for (const field of [
    'profileSpecHash', 'profileAbiHash', 'profileVectorSetHash',
    'validatorArtifactHash', 'validatorVectorSetHash', 'availabilityPolicyHash',
    'legacySourceSetHash'
  ]) {
    if (!bytesEqual(terminal[field], expected[field])) fail(`predecessor pin ${field} has drifted from the frozen source`)
  }
  if (!bytesEqual(terminal.emitSubstrate.specHash, expected.emitSubstrate.specHash) ||
      !bytesEqual(terminal.emitSubstrate.abiHash, expected.emitSubstrate.abiHash) ||
      !bytesEqual(terminal.emitSubstrate.vectorSetHash, expected.emitSubstrate.vectorSetHash) ||
      terminal.readSubstrates.length !== 1) {
    fail('predecessor pin HiveRelay substrate tuple has drifted from the frozen source')
  }
}

async function verifyPredecessor (bytes, config, root, fixtureOnly) {
  const decoded = decodePeeritPinHistoryBundleV1(bytes)
  const first = decodePeeritHiveRelayProfilePinV1(decoded.pins[0])
  const terminal = decodePeeritHiveRelayProfilePinV1(decoded.pins[decoded.pins.length - 1])
  const expectedSequence = BigInt(config.releaseSequence - 1)
  if (first.releaseSequence !== 0n || terminal.releaseSequence !== expectedSequence ||
      bytesToHex(first.releaseAuthorityPublicKey) !== config.pinnedReleaseKey) {
    fail(`pin-history input must be an authority-matched 0..${expectedSequence} predecessor`)
  }
  const verifyOptions = {
    bundleBytes: bytes,
    releaseSequence: config.releaseSequence - 1,
    appArtifactHash: terminal.appArtifactHash,
    webAssetManifestHash: terminal.webAssetManifestHash
  }
  if (fixtureOnly) {
    await verifyPeeritPinHistoryReleaseBundleV1({
      ...verifyOptions,
      releaseAuthorityPublicKey: first.releaseAuthorityPublicKey,
      genesisPinHash: profilePinHash(decoded.pins[0])
    })
  } else {
    if (!PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey ||
        !PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.genesisPinHash) {
      fail('production authority/genesis is not compiled', 'PRODUCTION_PEERIT_RELEASE_AUTHORITY_UNPINNED')
    }
    await verifyPeeritProductionPinHistoryReleaseV1(verifyOptions)
    assertProductionBindings(terminal, root)
  }
  return { decoded, terminal }
}

async function seedBytes (options, root, config) {
  if (options.fixtureOnly === true && options.seedBootstrapBytes instanceof Uint8Array) {
    return Buffer.from(options.seedBootstrapBytes)
  }
  const path = canonicalRepoPath(
    root, config.peeritSeedBootstrapBundle, 'peeritSeedBootstrapBundle')
  return readFileSync(path.absolute)
}

async function verifySeed (bytes, config) {
  const canonical = Buffer.from(encodePeeritSeedBootstrapV1(bytes))
  if (!canonical.equals(bytes)) fail('seed bootstrap bytes are not canonical')
  const artifact = JSON.parse(bytes.toString('utf8'))
  if (artifact.payload.releaseSequence !== config.releaseSequence ||
      artifact.payload.bootstrapSequence !== 0 ||
      artifact.payload.previousBootstrapHash !== null ||
      artifact.payload.authorityPublicKey !== config.peeritSeedDiscoveryAuthorityPublicKey) {
    fail('seed bootstrap must be source sequence 0 with no predecessor and match this exact release/config authority')
  }
  const rawHash = await hashPeeritSeedBootstrapV1(bytes)
  await verifyPeeritSeedBootstrapV1(bytes, {
    authorityPublicKey: config.peeritSeedDiscoveryAuthorityPublicKey,
    releaseSequence: config.releaseSequence,
    expectedArtifactHash: rawHash,
    previousBootstrapHash: null,
    now: artifact.payload.issuedAt
  })
  return { rawHash, artifact }
}

function predictionBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

function atomicExactWrite (path, bytes) {
  if (existsSync(path)) {
    if (!readFileSync(path).equals(Buffer.from(bytes))) {
      fail(`refusing to overwrite drifted prediction output ${path}`, 'PEERIT_PRODUCTION_PREDICTION_OUTPUT_DRIFT')
    }
    return
  }
  const temporary = `${path}.tmp-${process.pid}`
  writeFileSync(temporary, bytes)
  renameSync(temporary, path)
}

function materialize (directory, appBytes, webBytes, metadata) {
  directory = resolve(directory)
  mkdirSync(directory, { recursive: true })
  const entries = readdirSync(directory)
  if (entries.some(entry => !OUTPUT_FILES.includes(entry))) {
    fail('prediction output directory contains an unexpected file', 'PEERIT_PRODUCTION_PREDICTION_OUTPUT_DRIFT')
  }
  atomicExactWrite(resolve(directory, PEERIT_APP_ARTIFACT_PATH), appBytes)
  atomicExactWrite(resolve(directory, PEERIT_WEB_ASSET_MANIFEST_PATH), webBytes)
  atomicExactWrite(resolve(directory, PEERIT_PRODUCTION_RUNTIME_PREDICTION_FILE), predictionBytes(metadata))
}

export async function predictPeeritProductionRuntimeV1 (options = {}) {
  const root = resolve(options.root || ROOT)
  const rawConfig = configBytes(options, root)
  const config = normalizeConfig(rawConfig)
  const historyBytes = options.fixtureOnly === true && options.pinHistoryBytes instanceof Uint8Array
    ? Buffer.from(options.pinHistoryBytes)
    : readFileSync(resolve(root, options.pinHistoryPath || config.productionPinHistoryBundle))
  const predecessor = await verifyPredecessor(
    historyBytes, config, root, options.fixtureOnly === true)
  const bootstrapBytes = await seedBytes(options, root, config)
  const seed = await verifySeed(bootstrapBytes, config)
  const sourceFiles = exactSourceFiles(root, options)
  const buildOptions = {
    sourceFiles,
    substrateProfile: config.substrateProfile,
    relayHints: config.relayHints,
    releaseSequence: config.releaseSequence,
    releaseKey: config.pinnedReleaseKey,
    productionPinHistoryBytes: historyBytes,
    seedBootstrapBytes: bootstrapBytes,
    seedDiscoveryAuthorityPublicKey: config.peeritSeedDiscoveryAuthorityPublicKey
  }
  const first = buildPeeritSubstrateRuntimeArtifactV1(buildOptions)
  const second = buildPeeritSubstrateRuntimeArtifactV1(buildOptions)
  if (!Buffer.from(first.appArtifactBytes).equals(Buffer.from(second.appArtifactBytes)) ||
      !Buffer.from(first.webAssetManifestBytes).equals(Buffer.from(second.webAssetManifestBytes))) {
    fail('runtime builder produced nondeterministic app/Web bytes')
  }
  const metadata = Object.freeze({
    schema: PEERIT_PRODUCTION_RUNTIME_PREDICTION_SCHEMA_V1,
    releaseSequence: config.releaseSequence,
    configSha256: sha256(rawConfig),
    pinnedReleaseKey: config.pinnedReleaseKey,
    predecessor: {
      terminalReleaseSequence: Number(predecessor.terminal.releaseSequence),
      terminalPinHash: bytesToHex(profilePinHash(
        predecessor.decoded.pins[predecessor.decoded.pins.length - 1])),
      bundleSha256: sha256(historyBytes),
      bundleHash: bytesToHex(pinHistoryBundleHash(historyBytes))
    },
    seedBootstrap: {
      runtimePath: first.seedBootstrap.path,
      sha256: seed.rawHash,
      domainHash: bytesToHex(first.seedBootstrap.domainHash),
      discoveryAuthorityPublicKey: config.peeritSeedDiscoveryAuthorityPublicKey,
      bootstrapSequence: 0,
      previousBootstrapHash: null
    },
    appArtifactHash: first.appArtifactHashHex,
    webAssetManifestHash: first.webAssetManifestHashHex,
    sourceFilesSha256: sourceHashes(sourceFiles)
  })
  if (options.outputDirectory) {
    materialize(options.outputDirectory, first.appArtifactBytes,
      first.webAssetManifestBytes, metadata)
  }
  return Object.freeze({
    appArtifactBytes: Buffer.from(first.appArtifactBytes),
    webAssetManifestBytes: Buffer.from(first.webAssetManifestBytes),
    metadata
  })
}

function arg (name, fallback = null) {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

async function main () {
  const outputDirectory = arg('--out')
  if (!outputDirectory) fail('usage: predict-production-runtime.mjs --out <directory> [--config <file>] [--pin-history <file>]')
  const prediction = await predictPeeritProductionRuntimeV1({
    configPath: arg('--config', 'deploy/web-release.json'),
    pinHistoryPath: arg('--pin-history'),
    outputDirectory
  })
  console.log(JSON.stringify({
    schema: prediction.metadata.schema,
    releaseSequence: prediction.metadata.releaseSequence,
    appArtifactHash: prediction.metadata.appArtifactHash,
    webAssetManifestHash: prediction.metadata.webAssetManifestHash,
    outputDirectory: resolve(outputDirectory)
  }))
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`predict-production-runtime: ${error.message}`)
    process.exitCode = 1
  })
}
