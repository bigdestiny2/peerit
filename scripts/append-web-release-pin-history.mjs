#!/usr/bin/env node

// Append one exact outer-Web release identity after the deterministic build has
// produced its frozen signing request. This command does not sign: the updated
// byte-exact history is handed to the offline bind signer separately.

import { createHash } from 'node:crypto'
import {
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync
} from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { releaseSigningMessage } from '../js/release-verify.js'
import { normalizePeeritReleaseRelayHintsV1 } from '../js/substrate/release-relay-hints.mjs'
import { PEERIT_PRODUCTION_PIN_HISTORY_PATH } from '../js/substrate/production-release-authority.mjs'
import {
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_SEED_BOOTSTRAP_PATH,
  PEERIT_WEB_ASSET_MANIFEST_PATH
} from './substrate-runtime-artifact.mjs'

export const PEERIT_WEB_RELEASE_PIN_HISTORY_SCHEMA_V1 =
  'peerit-web-release-pin-history/v1'
export const PEERIT_WEB_RELEASE_PIN_HISTORY_NOTE_V1 =
  'App-level signed Web release continuity. Each entry binds a release sequence to the exact outer asset-manifest signing identity. This is distinct from the canonical PeeritHiveRelayProfilePinV1 production history.'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HEX_32 = /^[0-9a-f]{64}$/

function fail (message, code = 'PEERIT_WEB_RELEASE_PIN_HISTORY_APPEND_FAILED') {
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

function parseJson (bytes, field) {
  try {
    const value = JSON.parse(Buffer.from(bytes).toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be a JSON object`)
    return value
  } catch (cause) {
    if (cause.code === 'PEERIT_WEB_RELEASE_PIN_HISTORY_APPEND_FAILED') throw cause
    fail(`${field} is not JSON`)
  }
}

function bytesOrFile (options, key, path) {
  if (options.fixtureOnly === true && options[key] instanceof Uint8Array) {
    return Buffer.from(options[key])
  }
  return readFileSync(path)
}

function normalizedConfig (value) {
  const releaseSequence = Number(value.releaseSequence)
  if (value.substrateProfile !== 'blind-v1' ||
      !Number.isSafeInteger(releaseSequence) || releaseSequence < 13 || releaseSequence > 14 ||
      value.productionPinHistoryBundle !== PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)) {
    fail('release config must select exact blind-v1 sequence 13/14 and the fixed production pin-history path')
  }
  return Object.freeze({
    releaseSequence,
    substrateProfile: 'blind-v1',
    relayHints: normalizePeeritReleaseRelayHintsV1(value.relayHints, 'web release config'),
    pinnedReleaseKey: hex32(value.pinnedReleaseKey, 'release config pinnedReleaseKey'),
    peeritSeedBootstrapBundle: String(value.peeritSeedBootstrapBundle || ''),
    peeritSeedDiscoveryAuthorityPublicKey: hex32(
      value.peeritSeedDiscoveryAuthorityPublicKey,
      'release config peeritSeedDiscoveryAuthorityPublicKey')
  })
}

function assertRequest (request, config, manifestBytes, manifest) {
  if (request.schema !== 'peerit-web-signing-request-v2' ||
      request.manifest !== 'web/asset-manifest.json' ||
      request.signature !== 'web/asset-manifest.sig' ||
      request.releaseSequence !== config.releaseSequence ||
      hex32(request.pinnedReleaseKey, 'signing request pinnedReleaseKey') !== config.pinnedReleaseKey ||
      hex32(request.driveKey, 'signing request driveKey') !== String(manifest.driveKey || '').toLowerCase() ||
      hex32(request.manifestSha256, 'signing request manifestSha256') !== sha256(manifestBytes) ||
      hex32(request.signingMessageSha256, 'signing request signingMessageSha256') !==
        sha256(Buffer.from(releaseSigningMessage(manifest), 'utf8')) ||
      !request.artifactFiles || typeof request.artifactFiles !== 'object' ||
      Array.isArray(request.artifactFiles) ||
      request.artifactFiles['asset-manifest.json'] !== request.manifestSha256) {
    fail('signing request does not bind the exact frozen outer asset manifest and release config')
  }
}

function assertOuterManifest (manifest, config) {
  const release = manifest.webRelease
  if (manifest.releaseSequence !== config.releaseSequence ||
      !release || typeof release !== 'object' ||
      release.releaseSequence !== config.releaseSequence ||
      release.transport !== 'blind-substrate' ||
      release.substrateProfile !== config.substrateProfile ||
      release.networkDelivery !== 'profile-gated' ||
      release.legacyDestination !== null ||
      release.productionPinHistory !== PEERIT_PRODUCTION_PIN_HISTORY_PATH ||
      release.appArtifact !== `/${PEERIT_APP_ARTIFACT_PATH}` ||
      release.canonicalWebAssetManifest !== `/${PEERIT_WEB_ASSET_MANIFEST_PATH}` ||
      release.peeritSeedBootstrap !== `/${PEERIT_SEED_BOOTSTRAP_PATH}` ||
      release.releaseKey !== config.pinnedReleaseKey ||
      release.peeritSeedDiscoveryAuthorityPublicKey !==
        config.peeritSeedDiscoveryAuthorityPublicKey ||
      release.peeritSeedBootstrapReleaseSequence !== config.releaseSequence ||
      JSON.stringify(release.relayHints) !== JSON.stringify(config.relayHints)) {
    fail('outer asset manifest does not reproduce the exact config-selected blind release')
  }
  hex32(manifest.driveKey, 'outer asset manifest driveKey')
  hex32(release.appArtifactHash, 'outer asset manifest app artifact hash')
  hex32(release.canonicalWebAssetManifestHash,
    'outer asset manifest canonical WebAssetManifestV1 hash')
  hex32(release.peeritSeedBootstrapSha256, 'outer asset manifest seed bootstrap SHA-256')
}

function assertHistory (history, nextSequence) {
  if (history.schema !== PEERIT_WEB_RELEASE_PIN_HISTORY_SCHEMA_V1 ||
      !Array.isArray(history.entries) || history.entries.length < 1) {
    fail('web release pin history has an invalid schema or empty entries')
  }
  const sequences = history.entries.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        !Number.isSafeInteger(entry.releaseSequence) || entry.releaseSequence < 0) {
      fail(`web release pin history entry ${index} is invalid`)
    }
    return entry.releaseSequence
  })
  for (let index = 1; index < sequences.length; index++) {
    if (sequences[index] <= sequences[index - 1]) fail('web release pin history is not strictly increasing')
  }
  if (sequences[sequences.length - 1] !== nextSequence - 1) {
    fail(`web release pin history must end at exact predecessor ${nextSequence - 1}`,
      'PEERIT_WEB_RELEASE_PIN_HISTORY_PREDECESSOR_MISMATCH')
  }
}

function outputBytes (history) {
  return Buffer.from(JSON.stringify(history, null, 2) + '\n')
}

function atomicWrite (path, bytes) {
  mkdirSync(dirname(path), { recursive: true })
  const temporary = `${path}.tmp-${process.pid}`
  writeFileSync(temporary, bytes)
  renameSync(temporary, path)
}

export function appendPeeritWebReleasePinHistoryV1 (options = {}) {
  const root = resolve(options.root || ROOT)
  const configPath = resolve(root, options.configPath || 'deploy/web-release.json')
  const requestPath = resolve(root, options.requestPath || 'deploy/web-signing-request.json')
  const manifestPath = resolve(root, options.manifestPath || 'web/asset-manifest.json')
  const historyPath = resolve(root, options.historyPath || 'deploy/web-release-pin-history.json')
  const outputPath = resolve(root, options.outputPath || options.historyPath || 'deploy/web-release-pin-history.json')
  const config = normalizedConfig(parseJson(
    bytesOrFile(options, 'configBytes', configPath), 'release config'))
  const request = parseJson(
    bytesOrFile(options, 'requestBytes', requestPath), 'signing request')
  const manifestBytes = bytesOrFile(options, 'manifestBytes', manifestPath)
  const manifest = parseJson(manifestBytes, 'outer asset manifest')
  const history = parseJson(
    bytesOrFile(options, 'historyBytes', historyPath), 'web release pin history')
  assertOuterManifest(manifest, config)
  assertRequest(request, config, manifestBytes, manifest)
  assertHistory(history, config.releaseSequence)

  const value = {
    schema: PEERIT_WEB_RELEASE_PIN_HISTORY_SCHEMA_V1,
    note: PEERIT_WEB_RELEASE_PIN_HISTORY_NOTE_V1,
    entries: [
      ...history.entries,
      {
        releaseSequence: request.releaseSequence,
        manifestSha256: request.manifestSha256,
        signingMessageSha256: request.signingMessageSha256,
        pinnedReleaseKey: request.pinnedReleaseKey,
        driveKey: request.driveKey,
        transport: 'blind-substrate/blind-v1',
        relayHints: [...config.relayHints],
        claim_boundary: 'LIVE_PUBLIC_TEST_ONLY',
        note: `bounded local public-test release sequence ${request.releaseSequence}; not a GA claim`
      }
    ]
  }
  const bytes = outputBytes(value)
  if (options.write !== false) atomicWrite(outputPath, bytes)
  return Object.freeze({ bytes, value: Object.freeze(value), outputPath })
}

function arg (name, fallback = null) {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

function main () {
  const result = appendPeeritWebReleasePinHistoryV1({
    configPath: arg('--config', 'deploy/web-release.json'),
    requestPath: arg('--request', 'deploy/web-signing-request.json'),
    manifestPath: arg('--manifest', 'web/asset-manifest.json'),
    historyPath: arg('--history', 'deploy/web-release-pin-history.json'),
    outputPath: arg('--out')
  })
  console.log(JSON.stringify({
    schema: result.value.schema,
    releaseSequence: result.value.entries[result.value.entries.length - 1].releaseSequence,
    output: result.outputPath,
    sha256: sha256(result.bytes)
  }))
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { main() } catch (error) {
    console.error(`append-web-release-pin-history: ${error.message}`)
    process.exitCode = 1
  }
}
