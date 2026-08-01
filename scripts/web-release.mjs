#!/usr/bin/env node
import { spawn } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, posix, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dedupeRelayList,
  normalizeRelayRosterPayload,
  rosterSigningMessage,
  verifyRelayRoster
} from '../js/relay-roster.js'
import {
  RELEASE_ALG,
  RELEASE_MSG_VERSION,
  assertReleaseSequenceProgression,
  releaseSigningMessage
} from '../js/release-verify.js'
import { normalizeShardRosterPayload, shardRosterSigningMessage } from '../js/shard-roster.js'
import {
  PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS,
  assertPeeritBlindProductReleaseReady
} from '../js/substrate/product-release-status.mjs'
import { PEERIT_PRODUCTION_PIN_HISTORY_PATH } from '../js/substrate/production-release-authority.mjs'
import { normalizePeeritReleaseRelayHintsV1 } from '../js/substrate/release-relay-hints.mjs'
import {
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE,
  PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE,
  PEERIT_WEB_ASSET_MANIFEST_PATH,
  verifyPeeritSubstrateRuntimeArtifactV1
} from './substrate-runtime-artifact.mjs'
import { verifyPeeritProductionPinHistoryReleaseV1 } from './production-pin-history-release.mjs'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dir, '..')
const DEFAULT_CONFIG = join(ROOT, 'deploy', 'web-release.json')
const DEFAULT_REPORT = join(ROOT, '.deploy', 'last-web-release.json')
const DEFAULT_SIGNING_REQUEST = join(ROOT, 'deploy', 'web-signing-request.json')
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const SPKI_PREFIX = '302a300506032b6570032100'
const HEX64 = /^[0-9a-f]{64}$/i

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error([
    'usage: node scripts/web-release.mjs [--prepare|--verify-only] [--strict] [--drive-key <hex>] [--config deploy/web-release.json]',
    '       [--canary-limited-public-test-v1]',
    '       --prepare builds exactly once and writes deploy/web-signing-request.json',
    '       --verify-only (the default) never builds and requires the returned signature',
    '       --canary-limited-public-test-v1 verifies the frozen canary artifact and discloses',
    '       every GA product blocker as DISCLOSED-OPEN under the recorded owner canary',
    '       decision; without it the unchanged GA product gate applies',
    '       PEERIT_ROSTER_SEED=<32-byte-hex-seed> node scripts/web-release.mjs'
  ].join('\n'))
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    phase: 'verify',
    config: process.env.PEERIT_WEB_RELEASE_CONFIG || DEFAULT_CONFIG,
    report: process.env.WEB_RELEASE_REPORT || DEFAULT_REPORT,
    signingRequest: process.env.WEB_SIGNING_REQUEST || DEFAULT_SIGNING_REQUEST,
    driveKey: process.env.PEERIT_DRIVE_KEY || '',
    strict: false,
    json: false,
    canaryLimitedPublicTestV1: false
  }

  let selectedPhase = ''

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--prepare' || arg === '--build') {
      if (selectedPhase && selectedPhase !== 'prepare') usage(2, '--prepare and --verify-only are mutually exclusive')
      selectedPhase = opts.phase = 'prepare'
    } else if (arg === '--verify-only' || arg === '--no-build') {
      if (selectedPhase && selectedPhase !== 'verify') usage(2, '--prepare and --verify-only are mutually exclusive')
      selectedPhase = opts.phase = 'verify'
    } else if (arg === '--config') opts.config = resolve(ROOT, argv[++i] || '')
    else if (arg === '--report') opts.report = resolve(ROOT, argv[++i] || '')
    else if (arg === '--signing-request') opts.signingRequest = resolve(ROOT, argv[++i] || '')
    else if (arg === '--drive-key') opts.driveKey = argv[++i] || ''
    else if (arg === '--strict') opts.strict = true
    else if (arg === '--canary-limited-public-test-v1') opts.canaryLimitedPublicTestV1 = true
    else if (arg === '--json') opts.json = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  return opts
}

const opts = parseArgs(process.argv.slice(2))
const report = {
  appId: 'peerit',
  mode: opts.phase,
  strict: opts.strict,
  canaryScope: opts.canaryLimitedPublicTestV1 ? 'LIMITED_PUBLIC_TEST_V1' : null,
  generatedAt: new Date().toISOString(),
  config: opts.config,
  report: opts.report,
  checks: [],
  status: 'started',
  summary: ''
}

function addCheck (id, status, message, evidence = undefined) {
  const check = { id, status, message }
  if (evidence !== undefined) check.evidence = evidence
  report.checks.push(check)
  if (!opts.json) {
    const prefix = status === 'pass' ? 'PASS' : status === 'warn' ? 'WARN' : status === 'fail' ? 'FAIL' : 'INFO'
    console.log(`[web-release] ${prefix} ${message}`)
  }
}

function finishReport () {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 }
  for (const check of report.checks) {
    if (counts[check.status] !== undefined) counts[check.status]++
  }
  report.counts = counts
  report.status = counts.fail > 0 || (opts.strict && counts.warn > 0)
    ? 'blocked'
    : opts.phase === 'prepare'
      ? 'awaiting-signature'
      : (counts.warn > 0 ? 'review' : 'ready')
  report.summary = report.status === 'blocked'
    ? opts.strict && counts.fail === 0 && counts.warn > 0
      ? `${counts.warn} web release warning${counts.warn === 1 ? ' is' : 's are'} forbidden in strict mode.`
      : `${counts.fail} web release check${counts.fail === 1 ? '' : 's'} failed.`
    : report.status === 'awaiting-signature'
      ? 'Web artifact built once and frozen; return asset-manifest.sig, then run verify-only.'
      : report.status === 'review'
        ? `${counts.warn} web release warning${counts.warn === 1 ? '' : 's'} to review.`
        : opts.canaryLimitedPublicTestV1
          ? `Web release artifacts are in sync (CANARY ${CANARY_SCOPE}; GA product gate remains DISCLOSED-OPEN, never cleared).`
          : 'Web release artifacts are in sync.'
}

function writeReport () {
  finishReport()
  mkdirSync(dirname(opts.report), { recursive: true })
  writeFileSync(opts.report, JSON.stringify(report, null, 2) + '\n')
  if (opts.json) console.log(JSON.stringify(report, null, 2))
  else console.log(`[web-release] report: ${opts.report}`)
}

function readJson (file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function sha256 (buf) {
  return createHash('sha256').update(buf).digest('hex')
}

function safeManifestPath (file) {
  if (typeof file !== 'string' || !file || file.length > 240) return false
  if (!/^[A-Za-z0-9._/-]+$/.test(file)) return false
  if (file.startsWith('/') || file.includes('\\') || file.includes('//')) return false
  const segments = file.split('/')
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) return false
  return posix.normalize(file) === file
}

function listWebFiles (root, dir = root, prefix = '') {
  const files = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name
    if (!safeManifestPath(rel)) throw new Error(`web/ contains an unsafe path: ${rel}`)
    if (entry.isSymbolicLink()) throw new Error(`web/ must not contain symlinks: ${rel}`)
    if (entry.isDirectory()) files.push(...listWebFiles(root, join(dir, entry.name), rel))
    else if (entry.isFile()) files.push(rel)
    else throw new Error(`web/ contains a non-regular artifact: ${rel}`)
  }
  return files.sort()
}

function verifyManifestFileHashes (assetManifest, { requireSignature = true } = {}) {
  const files = assetManifest && assetManifest.files
  if (!files || typeof files !== 'object' || Array.isArray(files)) throw new Error('asset-manifest.json files must be an object')
  const entries = Object.entries(files)
  if (!entries.length) throw new Error('asset-manifest.json files must not be empty')
  const controls = assetManifest && assetManifest.controls
  if (!controls || typeof controls !== 'object' || Array.isArray(controls)) throw new Error('asset-manifest.json controls must be an object')
  const controlEntries = Object.entries(controls)
  const requiredControls = ['sw.js', 'verify.html']
  if (controlEntries.map(([file]) => file).sort().join('\n') !== requiredControls.join('\n')) {
    throw new Error('asset-manifest.json controls must contain exactly sw.js and verify.html')
  }
  const canonical = new Set()
  const verifyEntries = (rows, kind) => {
    for (const [file, expected] of rows) {
      if (!safeManifestPath(file)) throw new Error(`asset-manifest.json contains an unsafe path: ${file}`)
      const collisionKey = file.toLowerCase()
      if (canonical.has(collisionKey)) throw new Error(`asset-manifest.json contains a duplicate/case-colliding path: ${file}`)
      canonical.add(collisionKey)
      if (!/^[0-9a-f]{64}$/i.test(String(expected || ''))) throw new Error(`asset-manifest.json has an invalid SHA-256 for ${file}`)
      const abs = join(ROOT, 'web', ...file.split('/'))
      if (!existsSync(abs) || !statSync(abs).isFile()) throw new Error(`${kind} web asset is missing: ${file}`)
      const actual = sha256(readFileSync(abs))
      if (actual !== String(expected).toLowerCase()) throw new Error(`${kind} web asset hash mismatch: ${file}`)
    }
  }
  verifyEntries(entries, 'manifested')
  verifyEntries(controlEntries, 'signed control')

  // asset-manifest.json is authenticated by Ed25519 rather than self-hashed;
  // asset-manifest.sig is its response. Every other deploy byte must be covered
  // by the signed `files` or `controls` maps.
  const metadataFiles = new Set(['asset-manifest.json'])
  if (requireSignature) metadataFiles.add('asset-manifest.sig')
  const actualFiles = listWebFiles(join(ROOT, 'web'))
  for (const file of actualFiles) {
    if (!Object.hasOwn(files, file) && !Object.hasOwn(controls, file) && !metadataFiles.has(file)) {
      throw new Error(`web/ contains an unmanifested release file: ${file}`)
    }
  }
  for (const required of ['asset-manifest.json', ...requiredControls]) {
    if (!actualFiles.includes(required)) throw new Error(`required web release file is missing: ${required}`)
  }
  if (requireSignature && !actualFiles.includes('asset-manifest.sig')) throw new Error('required web release file is missing: asset-manifest.sig')

  addCheck('web:file-hashes', 'pass', `Recomputed SHA-256 for ${entries.length} manifested assets and ${controlEntries.length} signed control files.`, {
    files: entries.length,
    controls: controlEntries.length
  })
}

function signingRequestFor (release, driveKey, manifestBytes, assetManifest) {
  const artifactFiles = {}
  for (const file of listWebFiles(join(ROOT, 'web'))) {
    // The signature is the response to this request, so it cannot be part of
    // the request itself. Every other deploy byte, including sw.js and
    // verify.html, is frozen here for build-free Render verification.
    if (file === 'asset-manifest.sig') continue
    artifactFiles[file] = sha256(readFileSync(join(ROOT, 'web', ...file.split('/'))))
  }
  return {
    schema: 'peerit-web-signing-request-v2',
    manifest: 'web/asset-manifest.json',
    signature: 'web/asset-manifest.sig',
    releaseSequence: release.releaseSequence,
    driveKey,
    pinnedReleaseKey: release.pinnedReleaseKey,
    manifestSha256: sha256(manifestBytes),
    signingMessageSha256: sha256(Buffer.from(releaseSigningMessage(assetManifest), 'utf8')),
    artifactFiles
  }
}

function writeSigningRequest (release, driveKey, priorRecord = null) {
  const manifestPath = join(ROOT, 'web', 'asset-manifest.json')
  const manifestBytes = readFileSync(manifestPath)
  const assetManifest = JSON.parse(manifestBytes.toString('utf8'))
  const request = signingRequestFor(release, driveKey, manifestBytes, assetManifest)
  assertReleaseSequenceProgression({
    releaseSequence: request.releaseSequence,
    manifestIdentity: request.signingMessageSha256,
    priorRecord
  })
  mkdirSync(dirname(opts.signingRequest), { recursive: true })
  writeFileSync(opts.signingRequest, JSON.stringify(request, null, 2) + '\n')
  report.signingRequest = { ...request, file: opts.signingRequest }
  addCheck('web:signing-request', 'pass', 'Wrote the immutable offline-signing request.', {
    file: opts.signingRequest,
    manifestSha256: request.manifestSha256
  })
  return request
}

function verifySigningRequest (release, driveKey) {
  const request = readJson(opts.signingRequest)
  if (!request) throw new Error(`${opts.signingRequest} is missing or invalid; prepare the artifact exactly once before signing`)
  const manifestPath = join(ROOT, 'web', 'asset-manifest.json')
  if (!existsSync(manifestPath)) throw new Error('web/asset-manifest.json is missing; verify-only never rebuilds it')
  const manifestBytes = readFileSync(manifestPath)
  const assetManifest = JSON.parse(manifestBytes.toString('utf8'))
  const expected = signingRequestFor(release, driveKey, manifestBytes, assetManifest)
  for (const key of ['schema', 'manifest', 'signature', 'releaseSequence', 'driveKey', 'pinnedReleaseKey', 'manifestSha256', 'signingMessageSha256', 'artifactFiles']) {
    if (JSON.stringify(request[key]) !== JSON.stringify(expected[key])) {
      throw new Error(`offline-signing request no longer matches the prepared artifact (${key}); do not rebuild or edit web/ after signing`)
    }
  }
  report.signingRequest = { ...request, file: opts.signingRequest }
  addCheck('web:signing-request', 'pass', 'Prepared artifact still matches the offline-signing request.', {
    file: opts.signingRequest,
    manifestSha256: request.manifestSha256
  })
  return request
}

function samePayload (a, b) {
  return JSON.stringify(normalizeRelayRosterPayload(a)) === JSON.stringify(normalizeRelayRosterPayload(b))
}

function resolveRoot (file) {
  return resolve(ROOT, file || '')
}

function normalizeConfig (raw) {
  const substrateProfile = String(raw.substrateProfile || '').trim()
  if (substrateProfile) {
    return {
      transport: 'blind-substrate',
      substrateProfile,
      relayHints: normalizePeeritReleaseRelayHintsV1(
        raw.relayHints == null ? [] : raw.relayHints,
        'deploy/web-release.json'),
      productionPinHistoryBundle: String(raw.productionPinHistoryBundle || '').trim(),
      peeritSeedBootstrapBundle: String(raw.peeritSeedBootstrapBundle || '').trim(),
      peeritSeedDiscoveryAuthorityPublicKey: String(
        raw.peeritSeedDiscoveryAuthorityPublicKey || '').trim().toLowerCase(),
      releaseSequence: Number(raw.releaseSequence),
      pinnedReleaseKey: String(raw.pinnedReleaseKey || raw.releaseKey || '').trim().toLowerCase()
    }
  }
  const bootstrapRelays = Array.isArray(raw.bootstrapRelays)
    ? raw.bootstrapRelays.map((v) => String(v).trim()).filter(Boolean)
    : String(raw.relay || '').split(',').map((v) => v.trim()).filter(Boolean)
  return {
    transport: 'legacy-migration-compatibility',
    bootstrapRelays,
    relay: bootstrapRelays.join(','),
    relayBackend: String(raw.relayBackend || '').trim(),
    readonly: (raw.readonly === false || raw.readOnly === false) ? 'false' : 'true',
    releaseSequence: Number(raw.releaseSequence),
    relayRoster: raw.relayRoster || 'relay-roster.json',
    relayRosterMirrors: Array.isArray(raw.relayRosterMirrors) ? raw.relayRosterMirrors.map((value) => String(value).trim()).filter(Boolean) : [],
    pinnedRosterKey: String(raw.pinnedRosterKey || raw.rosterKey || '').trim().toLowerCase(),
    pinnedReleaseKey: String(raw.pinnedReleaseKey || raw.releaseKey || '').trim().toLowerCase(),
    dhtRelay: String(raw.dhtRelay || '').trim(),
    shardRoster: String(raw.shardRoster || '').trim(),
    roster: normalizeRelayRosterPayload(raw.roster || {
      version: 1,
      expires: raw.expires,
      relays: raw.relays || bootstrapRelays
    })
  }
}

function publicKeyFromSeed (seedHex) {
  const privateKey = createPrivateKey({
    key: Buffer.from(PKCS8_PREFIX + seedHex, 'hex'),
    format: 'der',
    type: 'pkcs8'
  })
  const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
  return Buffer.from(spki).subarray(-32).toString('hex')
}

function signWithSeed (seedHex, message) {
  const privateKey = createPrivateKey({
    key: Buffer.from(PKCS8_PREFIX + seedHex, 'hex'),
    format: 'der',
    type: 'pkcs8'
  })
  return nodeSign(null, Buffer.from(message), privateKey).toString('hex')
}

function writeSignedRoster (release, rosterPath, seedHex) {
  const key = publicKeyFromSeed(seedHex)
  if (release.pinnedRosterKey && key !== release.pinnedRosterKey) {
    throw new Error('PEERIT_ROSTER_SEED does not derive the pinned roster key in deploy/web-release.json')
  }
  const payload = normalizeRelayRosterPayload(release.roster)
  const roster = {
    payload,
    signature: {
      alg: 'Ed25519',
      key,
      sig: signWithSeed(seedHex, rosterSigningMessage(payload))
    }
  }
  writeFileSync(rosterPath, JSON.stringify(roster, null, 2) + '\n')
  return roster
}

async function prepareRoster (release) {
  const rosterPath = resolveRoot(release.relayRoster)
  const seed = String(process.env.PEERIT_ROSTER_SEED || '').trim().toLowerCase()
  let roster = null

  if (seed) {
    if (opts.phase !== 'prepare') throw new Error('verify-only refuses PEERIT_ROSTER_SEED because verification must not rewrite relay-roster.json')
    if (!HEX64.test(seed)) throw new Error('PEERIT_ROSTER_SEED must be a 32-byte hex seed')
    roster = writeSignedRoster(release, rosterPath, seed)
    addCheck('roster:signed', 'pass', `Signed ${release.relayRoster} from PEERIT_ROSTER_SEED.`, {
      key: roster.signature.key,
      relays: roster.payload.relays
    })
  } else {
    roster = readJson(rosterPath)
    if (!roster) throw new Error(`${release.relayRoster} is missing or invalid; set PEERIT_ROSTER_SEED to sign it from deploy/web-release.json`)
    addCheck('roster:file', 'pass', `${release.relayRoster} parses.`)
  }

  const signer = String((roster.signature && roster.signature.key) || '').toLowerCase()
  if (!release.pinnedRosterKey) throw new Error('deploy/web-release.json must pin pinnedRosterKey')
  if (signer !== release.pinnedRosterKey) throw new Error(`${release.relayRoster} signer does not match pinnedRosterKey`)
  if (!samePayload(roster.payload, release.roster)) throw new Error(`${release.relayRoster} payload does not match deploy/web-release.json`)

  const verified = await verifyRelayRoster(roster, { expectedKey: release.pinnedRosterKey })
  const expiresMs = Date.parse(verified.expires)
  const daysLeft = Math.floor((expiresMs - Date.now()) / 86400000)
  addCheck('roster:signature', 'pass', `Signed relay roster verifies with pinned key ${release.pinnedRosterKey.slice(0, 12)}...`, {
    expires: verified.expires,
    relays: verified.relays
  })
  if (daysLeft < 14) addCheck('roster:expiry', 'warn', `Relay roster expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}.`, { expires: verified.expires })
  else addCheck('roster:expiry', 'pass', `Relay roster expiry has ${daysLeft} days remaining.`, { expires: verified.expires })

  return {
    path: rosterPath,
    roster,
    sha256: sha256(readFileSync(rosterPath)),
    key: release.pinnedRosterKey
  }
}

function loadManifestDriveKey () {
  const manifest = readJson(join(ROOT, 'manifest.json'))
  return String((manifest && manifest.driveKey) || '')
}

function validateReleaseConfig (release) {
  if (!Number.isSafeInteger(release.releaseSequence) || release.releaseSequence < 1) {
    throw new Error('deploy/web-release.json releaseSequence must be a positive safe integer')
  }
  if (release.transport === 'blind-substrate') {
    if (release.releaseSequence < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE) {
      throw new Error(`blind-substrate replacement releaseSequence must be at least ${PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE}; sequence 6 belongs to the retired legacy artifact`)
    }
    if (release.substrateProfile !== 'blind-v1') throw new Error(`unsupported Peerit substrate profile: ${release.substrateProfile}`)
    if (release.productionPinHistoryBundle &&
        release.productionPinHistoryBundle !== PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)) {
      throw new Error(`productionPinHistoryBundle must equal ${PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)}`)
    }
    if (release.releaseSequence >= PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE &&
        (!release.peeritSeedBootstrapBundle ||
         !HEX64.test(release.peeritSeedDiscoveryAuthorityPublicKey))) {
      throw new Error('sequence-13+ release requires a seed bootstrap bundle and discovery authority key')
    }
    if (!HEX64.test(release.pinnedReleaseKey)) throw new Error('deploy/web-release.json has an invalid pinnedReleaseKey')
    addCheck('config:substrate', 'pass', `Release selects ${release.substrateProfile} with ${release.relayHints.length} untrusted relay hint(s).`, {
      relayHints: release.relayHints,
      legacyDestination: null
    })
    return
  }
  const normalizedBootstrap = dedupeRelayList(release.bootstrapRelays)
  if (!release.bootstrapRelays.length) throw new Error('deploy/web-release.json must configure at least one bootstrap relay')
  if (normalizedBootstrap.length !== release.bootstrapRelays.length) {
    throw new Error('bootstrapRelays must be valid, canonical, and unique relay URLs')
  }
  if (!release.roster.relays.length) throw new Error('deploy/web-release.json roster.relays must include at least one relay')
  const signedNetworkQuorum = release.roster && release.roster.networkQuorum
  const signedSingleIngress = release.roster && release.roster.singleIngressWriter === true
  if (String(release.readonly).toLowerCase() !== 'true' && release.roster.relays.length < 2 && !signedNetworkQuorum && !signedSingleIngress) {
    throw new Error('writable public web releases require at least two signed relay failure domains, a signed network-quorum policy, or a signed single-ingress policy')
  }
  addCheck('config:relay', 'pass', `Bootstrap relay list has ${release.bootstrapRelays.length} entr${release.bootstrapRelays.length === 1 ? 'y' : 'ies'}.`, {
    bootstrapRelays: release.bootstrapRelays
  })
  addCheck('config:roster', 'pass', `Roster config has ${release.roster.relays.length} signed relay entr${release.roster.relays.length === 1 ? 'y' : 'ies'}.`, {
    relays: release.roster.relays,
    networkQuorum: signedNetworkQuorum || null,
    singleIngressWriter: signedSingleIngress
  })
}

function assertDriveKey (driveKey) {
  if (!HEX64.test(String(driveKey || ''))) throw new Error('A current 64-byte drive key is required; run publish first or pass --drive-key')
  addCheck('config:drive-key', 'pass', `Web bundle will pin drive key ${driveKey.slice(0, 12)}...`, { driveKey })
}

function run (cmd, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: ROOT,
      stdio: 'inherit',
      env: options.env || process.env
    })
    child.on('error', reject)
    child.on('exit', (code, signal) => {
      if (code === 0) resolve()
      else reject(new Error(`${cmd} ${args.join(' ')} exited with ${signal || code}`))
    })
  })
}

async function buildWeb (release, driveKey) {
  const args = ['build-web.mjs', '--config', opts.config, '--release-sequence', String(release.releaseSequence), '--drive-key', driveKey]
  if (release.transport === 'blind-substrate') {
    args.push('--substrate-profile', release.substrateProfile)
    if (release.relayHints.length) args.push('--substrate-relay-hints', release.relayHints.join(','))
  } else {
    args.push('--relay', release.relay, '--readonly', release.readonly, '--relay-roster', release.relayRoster, '--relay-roster-key', release.pinnedRosterKey)
  }
  if (release.relayBackend) args.push('--relay-backend', release.relayBackend)
  if (release.relayRosterMirrors && release.relayRosterMirrors.length) args.push('--relay-roster-mirrors', release.relayRosterMirrors.join(','))
  if (release.dhtRelay) args.push('--dht-relay', release.dhtRelay)
  if (release.shardRoster) args.push('--shard-roster', release.shardRoster)
  await run('node', args)
  addCheck('build:web', 'pass', release.transport === 'blind-substrate'
    ? 'Built web/ from the replacement substrate release config.'
    : 'Built the separately selected legacy migration-compatibility artifact.')
}

function metaContent (html, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`<meta\\s+name=["']${escaped}["']\\s+content=["']([^"']*)["']`, 'i')
  const match = html.match(re)
  return match ? match[1] : ''
}

async function verifySubstrateWebBundle (release, driveKey, { requireSignature = true } = {}) {
  const required = [
    'index.html',
    'asset-manifest.json',
    'sw.js',
    'verify.html',
    PEERIT_APP_ARTIFACT_PATH,
    PEERIT_WEB_ASSET_MANIFEST_PATH
  ].map(file => join(ROOT, 'web', file))
  for (const file of required) if (!existsSync(file)) throw new Error(`${file} is missing; run npm run build-web`)
  const html = readFileSync(required[0], 'utf8')
  if (metaContent(html, 'peerit-substrate') !== release.substrateProfile) throw new Error('web/index.html substrate profile meta does not match deploy/web-release.json')
  const hints = release.relayHints.join(',')
  if (metaContent(html, 'peerit-substrate-relays') !== hints) throw new Error('web/index.html substrate relay hints do not match deploy/web-release.json')
  for (const legacy of ['peerit-relay', 'peerit-relay-backend', 'peerit-relay-readonly', 'peerit-relay-roster', 'peerit-relay-roster-key', 'peerit-dht-relay', 'peerit-shard-roster', 'peerit-seed-outboxes']) {
    if (metaContent(html, legacy)) throw new Error(`blind-substrate web artifact must not contain ${legacy}`)
  }
  if (html.includes('outbox.peerit.site')) throw new Error('blind-substrate web artifact contains the retired outbox.peerit.site destination')
  if (metaContent(html, 'peerit-release-key') !== release.pinnedReleaseKey) throw new Error('web/index.html release key meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-release-sequence') !== String(release.releaseSequence)) throw new Error('web/index.html release sequence meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-production-web-asset-manifest') !== `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`) {
    throw new Error('web/index.html canonical WebAssetManifestV1 meta does not match the replacement release')
  }
  const expectedPinHistoryPath = release.productionPinHistoryBundle
    ? PEERIT_PRODUCTION_PIN_HISTORY_PATH
    : ''
  if (metaContent(html, 'peerit-production-pin-history') !== expectedPinHistoryPath) {
    throw new Error('web/index.html production pin-history meta does not match deploy/web-release.json')
  }
  addCheck('web:index-meta', 'pass', 'web/index.html selects only the replacement substrate transport.')

  const manifest = readJson(required[1])
  if (!manifest) throw new Error('web/asset-manifest.json is invalid')
  verifyManifestFileHashes(manifest, { requireSignature })
  if (manifest.releaseSequence !== release.releaseSequence || manifest.driveKey !== driveKey) throw new Error('web/asset-manifest.json release identity does not match the release config')
  const runtimeFiles = new Map(Object.keys(manifest.files).map(file => [
    file,
    readFileSync(join(ROOT, 'web', ...file.split('/')))
  ]))
  const runtime = verifyPeeritSubstrateRuntimeArtifactV1({
    files: runtimeFiles,
    releaseSequence: release.releaseSequence,
    releaseKey: release.pinnedReleaseKey
  })
  if (release.productionPinHistoryBundle) {
    await verifyPeeritProductionPinHistoryReleaseV1({
      bundleBytes: runtimeFiles.get(release.productionPinHistoryBundle),
      releaseSequence: release.releaseSequence,
      appArtifactHash: runtime.appArtifactHash,
      webAssetManifestHash: runtime.webAssetManifestHash
    })
  }
  const expected = {
    releaseSequence: release.releaseSequence,
    transport: 'blind-substrate',
    substrateProfile: release.substrateProfile,
    relayHints: release.relayHints,
    networkDelivery: 'profile-gated',
    legacyDestination: null,
    productionPinHistory: release.productionPinHistoryBundle
      ? PEERIT_PRODUCTION_PIN_HISTORY_PATH
      : null,
    appArtifact: `/${PEERIT_APP_ARTIFACT_PATH}`,
    appArtifactHash: runtime.appArtifactHashHex,
    canonicalWebAssetManifest: `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`,
    canonicalWebAssetManifestHash: runtime.webAssetManifestHashHex,
    ...(runtime.seedBootstrap
      ? {
          peeritSeedBootstrap: runtime.seedBootstrap.path,
          peeritSeedBootstrapSha256: runtime.seedBootstrap.sha256,
          peeritSeedDiscoveryAuthorityPublicKey: runtime.seedBootstrap.authorityPublicKey,
          peeritSeedBootstrapReleaseSequence: runtime.seedBootstrap.releaseSequence
        }
      : {}),
    releaseKey: release.pinnedReleaseKey
  }
  if (!manifest.webRelease || JSON.stringify(manifest.webRelease) !== JSON.stringify(expected)) {
    throw new Error('asset-manifest.json webRelease does not match the replacement substrate release config')
  }
  const verifySource = readFileSync(required[3], 'utf8')
  if (!verifySource.includes(driveKey) || !verifySource.includes(release.pinnedReleaseKey)) throw new Error('verify.html does not include the release pins')
  addCheck('web:asset-manifest', 'pass',
    `asset-manifest.json cross-binds the ${runtime.verifiedAssetCount}-asset canonical replacement closure without a legacy destination.`)

  if (!requireSignature) {
    addCheck('web:release-signature', 'info', 'Artifact is frozen and awaiting an external asset-manifest.sig; no build will run during verification.')
    return
  }
  const sigPath = join(ROOT, 'web', 'asset-manifest.sig')
  if (!existsSync(sigPath)) throw new Error('pinnedReleaseKey is set but web/asset-manifest.sig is missing')
  const sig = readJson(sigPath)
  if (!sig || sig.alg !== RELEASE_ALG || sig.msgVersion !== RELEASE_MSG_VERSION || String(sig.key || '').toLowerCase() !== release.pinnedReleaseKey || !/^[0-9a-f]{128}$/i.test(String(sig.sig || ''))) {
    throw new Error('asset-manifest.sig is invalid for the pinned release key')
  }
  const ok = nodeVerify(null, Buffer.from(releaseSigningMessage(manifest), 'utf8'),
    createPublicKey({ key: Buffer.from(SPKI_PREFIX + release.pinnedReleaseKey, 'hex'), format: 'der', type: 'spki' }),
    Buffer.from(sig.sig, 'hex'))
  if (!ok) throw new Error('asset-manifest.sig does not verify over the built asset-manifest.json')
  addCheck('web:release-signature', 'pass', `asset-manifest.sig verifies with the pinned release key ${release.pinnedReleaseKey.slice(0, 12)}...`)
}

async function verifyWebBundle (release, rosterInfo, driveKey, { requireSignature = true } = {}) {
  if (release.transport === 'blind-substrate') return verifySubstrateWebBundle(release, driveKey, { requireSignature })
  const webIndex = join(ROOT, 'web', 'index.html')
  const webManifest = join(ROOT, 'web', 'asset-manifest.json')
  const webRoster = join(ROOT, 'web', 'relay-roster.json')
  const sw = join(ROOT, 'web', 'sw.js')
  const verify = join(ROOT, 'web', 'verify.html')
  for (const file of [webIndex, webManifest, webRoster, sw, verify]) {
    if (!existsSync(file)) throw new Error(`${file} is missing; run npm run build-web`)
  }

  const html = readFileSync(webIndex, 'utf8')
  const expectedRosterMeta = ['relay-roster.json', ...release.relayRosterMirrors].join(',')
  if (metaContent(html, 'peerit-relay') !== release.relay) throw new Error('web/index.html peerit-relay meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-relay-backend') !== release.relayBackend) throw new Error('web/index.html relay backend meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-relay-readonly') !== release.readonly) throw new Error('web/index.html readonly meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-relay-roster') !== expectedRosterMeta) throw new Error('web/index.html relay roster meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-relay-roster-key') !== release.pinnedRosterKey) throw new Error('web/index.html pinned roster key does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-release-key') !== release.pinnedReleaseKey) throw new Error('web/index.html release key meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-release-sequence') !== String(release.releaseSequence)) throw new Error('web/index.html release sequence meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-dht-relay') !== release.dhtRelay) throw new Error('web/index.html DHT relay meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-shard-roster') !== release.shardRoster) throw new Error('web/index.html shard roster meta does not match deploy/web-release.json')
  addCheck('web:index-meta', 'pass', 'web/index.html contains the expected relay roster meta tags.')

  const rootRosterHash = rosterInfo.sha256
  const webRosterHash = sha256(readFileSync(webRoster))
  if (webRosterHash !== rootRosterHash) throw new Error('web/relay-roster.json differs from root relay-roster.json')
  addCheck('web:roster-copy', 'pass', 'web/relay-roster.json matches root relay-roster.json.', { sha256: rootRosterHash })

  let shardRosterHash = ''
  if (release.shardRoster) {
    const rootShardRoster = resolveRoot(release.shardRoster)
    const webShardRoster = join(ROOT, 'web', release.shardRoster)
    if (!existsSync(webShardRoster)) throw new Error(`${webShardRoster} is missing; run npm run build-web`)
    shardRosterHash = sha256(readFileSync(rootShardRoster))
    const webShardRosterHash = sha256(readFileSync(webShardRoster))
    if (webShardRosterHash !== shardRosterHash) throw new Error(`${release.shardRoster} in web/ differs from root`)
    addCheck('web:shard-roster-copy', 'pass', `${release.shardRoster} in web/ matches root.`, { sha256: shardRosterHash })
    // A shipped shard roster must be the SIGNED envelope, signed by the pinned
    // roster key, with real non-duplicate pubkeys and a sane threshold — the same
    // rules the client's verifyShardRoster enforces at load. Sign it with:
    //   PEERIT_ROSTER_SEED=<keyvault seed> node scripts/sign-shard-roster.mjs
    const env = readJson(rootShardRoster)
    if (!env || !env.payload || !env.signature) throw new Error(release.shardRoster + ' is not a signed roster envelope — run scripts/sign-shard-roster.mjs')
    const srPayload = normalizeShardRosterPayload(env.payload)
    if (String(env.signature.key || '').toLowerCase() !== String(release.pinnedRosterKey).toLowerCase()) {
      throw new Error('shard roster is signed by ' + env.signature.key + ' but deploy/web-release.json pins ' + release.pinnedRosterKey)
    }
    const srOk = nodeVerify(null, Buffer.from(shardRosterSigningMessage(env.payload), 'utf8'),
      createPublicKey({ key: Buffer.from(SPKI_PREFIX + String(env.signature.key).toLowerCase(), 'hex'), format: 'der', type: 'spki' }),
      Buffer.from(String(env.signature.sig || ''), 'hex'))
    if (!srOk) throw new Error('shard roster signature does not verify — re-run scripts/sign-shard-roster.mjs')
    if (!(Date.parse(srPayload.expires) > Date.now())) throw new Error('shard roster is expired — re-sign with a fresh --expires')
    const srPubs = srPayload.relays.map((r) => r.pubkey)
    if (srPubs.some((p) => !HEX64.test(p))) throw new Error('shard roster has relays with missing/invalid pubkeys — a release must not ship placeholder custody targets')
    if (new Set(srPubs).size !== srPubs.length) throw new Error('shard roster contains duplicate relay pubkeys')
    if (!(srPayload.threshold >= 2 && srPayload.threshold <= srPayload.relays.length)) throw new Error('shard roster threshold must satisfy 2 <= k <= relays.length')
    addCheck('shard-roster:signature', 'pass', `Signed shard roster verifies with the pinned roster key (${srPayload.threshold}-of-${srPayload.relays.length}).`, {
      relays: srPayload.relays.map((r) => r.url)
    })
  }

  const assetManifest = readJson(webManifest)
  if (!assetManifest) throw new Error('web/asset-manifest.json is invalid')
  verifyManifestFileHashes(assetManifest, { requireSignature })
  if (assetManifest.releaseSequence !== release.releaseSequence) throw new Error('web/asset-manifest.json releaseSequence does not match deploy/web-release.json')
  if (assetManifest.driveKey !== driveKey) throw new Error('web/asset-manifest.json driveKey does not match the release drive key')
  if (!assetManifest.files || assetManifest.files['relay-roster.json'] !== rootRosterHash) throw new Error('asset-manifest.json does not pin relay-roster.json hash')
  if (release.shardRoster && assetManifest.files[release.shardRoster] !== shardRosterHash) throw new Error('asset-manifest.json does not pin ' + release.shardRoster)
  const expectedWebRelease = {
    releaseSequence: release.releaseSequence,
    relay: release.relay,
    relayBackend: release.relayBackend,
    readonly: release.readonly,
    relayRoster: expectedRosterMeta,
    relayRosterKey: release.pinnedRosterKey,
    relayRosterSha256: rootRosterHash,
    shardRoster: release.shardRoster,
    shardRosterSha256: shardRosterHash,
    releaseKey: release.pinnedReleaseKey
  }
  if (!assetManifest.webRelease || typeof assetManifest.webRelease !== 'object') throw new Error('asset-manifest.json webRelease is missing')
  for (const [field, expected] of Object.entries(expectedWebRelease)) {
    if (assetManifest.webRelease[field] !== expected) throw new Error(`asset-manifest.json webRelease.${field} does not match the release config`)
  }
  addCheck('web:asset-manifest', 'pass', 'asset-manifest.json pins the drive key, roster key, and roster hash.', {
    driveKey,
    relayRosterSha256: rootRosterHash
  })

  if (!readFileSync(sw, 'utf8').includes(`"relay-roster.json":"${rootRosterHash}"`)) throw new Error('sw.js does not pin relay-roster.json')
  if (release.shardRoster && !readFileSync(sw, 'utf8').includes(`"${release.shardRoster}":"${shardRosterHash}"`)) throw new Error('sw.js does not pin ' + release.shardRoster)
  const verifySource = readFileSync(verify, 'utf8')
  if (!verifySource.includes(driveKey)) throw new Error('verify.html does not include the release drive key')
  if (!verifySource.includes(release.pinnedReleaseKey)) throw new Error('verify.html does not include the pinned release key')
  addCheck('web:generated-assets', 'pass', 'sw.js and verify.html carry the same release pins.')

  // A pinned release key makes the signed-release chain LOAD-BEARING: refuse to
  // ship a bundle whose asset-manifest.sig is missing, signed by the wrong key, or
  // stale (signed over a different manifest than the one just built). Sign with:
  //   PEERIT_RELEASE_SEED=<keyvault seed> node scripts/sign-release.mjs
  if (!release.pinnedReleaseKey) {
    throw new Error('No pinnedReleaseKey in deploy/web-release.json — refusing an unsigned public web release. Generate a release key, sign asset-manifest.json, and pin its public key.')
  }
  if (!requireSignature) {
    addCheck('web:release-signature', 'info', 'Artifact is frozen and awaiting an external asset-manifest.sig; no build will run during verification.')
  } else {
    const sigPath = join(ROOT, 'web', 'asset-manifest.sig')
    if (!existsSync(sigPath)) throw new Error('pinnedReleaseKey is set but web/asset-manifest.sig is missing — run scripts/sign-release.mjs after the build')
    const sig = readJson(sigPath)
    if (!sig) throw new Error('web/asset-manifest.sig is invalid JSON')
    if (sig.alg !== RELEASE_ALG) throw new Error(`asset-manifest.sig must use ${RELEASE_ALG}`)
    if (sig.msgVersion !== RELEASE_MSG_VERSION) throw new Error(`asset-manifest.sig must use ${RELEASE_MSG_VERSION}`)
    if (String(sig.key || '').toLowerCase() !== String(release.pinnedReleaseKey).toLowerCase()) {
      throw new Error(`asset-manifest.sig is signed by ${sig.key} but deploy/web-release.json pins ${release.pinnedReleaseKey}`)
    }
    if (!/^[0-9a-f]{128}$/i.test(String(sig.sig || ''))) throw new Error('asset-manifest.sig signature must be 64-byte hex')
    const sigOk = nodeVerify(null, Buffer.from(releaseSigningMessage(assetManifest), 'utf8'),
      createPublicKey({ key: Buffer.from(SPKI_PREFIX + String(sig.key).toLowerCase(), 'hex'), format: 'der', type: 'spki' }),
      Buffer.from(String(sig.sig || ''), 'hex'))
    if (!sigOk) throw new Error('asset-manifest.sig does not verify over the built asset-manifest.json (stale signature? re-run sign-release after the build)')
    addCheck('web:release-signature', 'pass', `asset-manifest.sig verifies with the pinned release key ${String(sig.key).slice(0, 12)}...`)
  }
}

function verifyDocs () {
  const docsPath = join(ROOT, 'docs', 'WEB-DEPLOYMENT.md')
  const docs = readFileSync(docsPath, 'utf8')
  const missing = ['npm run web:release', 'deploy/web-release.json']
    .filter((needle) => !docs.includes(needle))
  if (missing.length) throw new Error(`docs/WEB-DEPLOYMENT.md is missing release-flow references: ${missing.join(', ')}`)
  addCheck('docs:web-release', 'pass', 'WEB-DEPLOYMENT.md documents the web release command and config files.')
}

// ---------------------------------------------------------------------------
// CANARY SCOPE: LIMITED_PUBLIC_TEST_V1
//
// The owner's recorded canary decisions bind two successive bounded releases:
// 13/14 for the original two-relay three-post publication, 15/16 for the rejected
// null-URL recovery attempt and its containment rollback, 17/18 for the exact
// signed parameter-URL correction and its cold rollback, and 19/20 for the
// CSP-safe authenticated browser recovery and its cold rollback. In each pair
// the even sequence is prepared only as the monotonic rollback. By the owner
// decision of 2026-07-31, sequence 20 is then RE-SLOTTED as the LIVE
// bounded-public-test launch release for the 34-record live launch seed
// (limited Cell-GET authority exposed, signed seed recovery enabled),
// superseding the rollback posture for this exact slot. The all-five successor
// remains excluded and the GA product gate remains honestly blocked. This scope verifies everything
// the selected canary actually is — frozen signed artifact bytes, manifest,
// pin-history continuity, substrate profile blind-v1, both relay hints, CSP
// origins, and the byte-pinned owner decision — and reports EVERY GA product
// blocker as DISCLOSED-OPEN. It never clears, skips, or weakens the GA gate.
const CANARY_SCOPE = 'LIMITED_PUBLIC_TEST_V1'
const CANARY_DECISION_FILE = 'deploy/canary-decision-peerit-seq13-three-post-activation-20260729t132650z.json'
const CANARY_DECISION_SHA256 = '86130d0257105aecff2a40fee4656edabbffb531ac94854759138a13c06b59b0'
const CANARY_RECOVERY_DECISION_FILE = 'deploy/canary-decision-peerit-seq15-seed-recovery-20260729t172519z.json'
const CANARY_RECOVERY_DECISION_SHA256 = '11d95b7abd52d7c4d443548089a8dd5455be87ee81ececf50314047a6b10ba50'
const CANARY_EXACT_ADMISSION_URL_DECISION_FILE =
  'deploy/canary-decision-peerit-seq17-exact-admission-url-recovery-20260729.json'
const CANARY_EXACT_ADMISSION_URL_DECISION_SHA256 =
  'd218d4c2ff9c651b96450e5caf85911fe1e715767eecd129c8a7c20ad443297a'
const CANARY_CSP_SAFE_RECOVERY_DECISION_FILE =
  'deploy/canary-decision-peerit-seq19-csp-safe-live-recovery-20260729.json'
const CANARY_CSP_SAFE_RECOVERY_DECISION_SHA256 =
  '1dfbb512cdd306dec903a407831cc3911c5844ded6e29c38d641bf700b4c1605'
const CANARY_SEQ20_LAUNCH_DECISION_FILE =
  'deploy/canary-decision-peerit-seq20-launch-live-recovery-20260731.json'
const CANARY_SEQ20_LAUNCH_DECISION_SHA256 =
  '2af60f84013989987e4f229b49c858eb8be83e45b20dbe521454cf1bc0a96c82'
const CANARY_SEQ21_CONTENT_TYPE_UNBLOCK_DECISION_FILE =
  'deploy/canary-decision-peerit-seq21-live-site-content-type-unblock-20260731.json'
const CANARY_SEQ21_CONTENT_TYPE_UNBLOCK_DECISION_SHA256 =
  '96c0216f4e276595d1099f33537dbc22058a3a6c70d012ccc953225a2a1ba042'
const CANARY_PIN_HISTORY_FILE = 'deploy/web-release-pin-history.json'
const CANARY_PIN_HISTORY_SIG_FILE = 'deploy/web-release-pin-history.json.sig.json'

function readCanaryOwnerDecision (relativePath, expectedHash) {
  const file = join(ROOT, relativePath)
  if (!existsSync(file)) throw new Error(`vendored owner canary decision is missing: ${relativePath}`)
  const bytes = readFileSync(file)
  const actual = sha256(bytes)
  if (actual !== expectedHash) {
    throw new Error(`vendored owner canary decision hash mismatch: ${actual} != pinned ${expectedHash}; the decision record must be the exact recorded bytes`)
  }
  return JSON.parse(bytes.toString('utf8'))
}

function verifyCanaryOwnerDecision (release) {
  const exactPostCids = [
    'f68ae14dcd4fb0764b0c5669a03ebb7d68993b7cddc31f1552b85c2cba67536f',
    'fc80b076becb28c9fbda596def255246cd506fc5ed4e5f4d22499c5cdad95f1b',
    '52f99d16c0ab47bdad025cbd4138549802e552d55835435588887e7ca178e3a6'
  ]
  if (release.releaseSequence === 21) {
    const decision = readCanaryOwnerDecision(
      CANARY_SEQ21_CONTENT_TYPE_UNBLOCK_DECISION_FILE,
      CANARY_SEQ21_CONTENT_TYPE_UNBLOCK_DECISION_SHA256)
    const activation = decision.activation || {}
    const authority = decision.authority || {}
    const launch = activation.launch_seed || {}
    const fix = decision.content_type_fix || {}
    const extension = decision.ceremony_extension || {}
    const bootstrap = decision.seed_bootstrap || {}
    const exactUrl = decision.exact_admission_parameter_url || {}
    const csp = decision.production_csp || {}
    const runtimeGate = decision.production_runtime_gate || {}
    const relays = decision.relay_authority || {}
    const followups = Array.isArray(decision.followups) ? decision.followups.join('\n') : ''
    if (decision.schema_version !== 5 ||
        decision.decision_id !== 'peerit-seq21-live-site-content-type-unblock-20260731' ||
        decision.status !== 'DECIDED' ||
        !String(decision.decision || '').startsWith('ACCEPT Peerit release sequence 21 as the LIVE bounded-public-test launch successor') ||
        !followups.includes('GA product gate remains honestly blocked')) {
      throw new Error('sequence-21 content-type unblock decision is not the recorded owner ACCEPT')
    }
    if (authority.baseline_release_sequence !== 20 ||
        !Array.isArray(authority.cited_prior_decisions) ||
        !authority.cited_prior_decisions.some(row => row.file === CANARY_SEQ20_LAUNCH_DECISION_FILE && row.sha256 === CANARY_SEQ20_LAUNCH_DECISION_SHA256)) {
      throw new Error('sequence-21 decision does not cite the seq-20 launch decision it extends')
    }
    if (activation.functional_release_sequence !== 21 ||
        activation.rollback_release_sequence !== null ||
        activation.rollback_posture !== 'SUPERSEDED_FOR_THIS_SLOT_BY_OWNER_DECISION_2026-07-31' ||
        activation.limited_cell_get_authority_release_sequence !== 21 ||
        activation.limited_cell_get_runtime_authority_exposed !== true ||
        activation.seed_recovery_enabled !== true ||
        activation.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
        JSON.stringify(activation.relays) !== JSON.stringify(['dal-1', 'syd-1']) ||
        JSON.stringify(activation.allowed_browser_operations) !==
          JSON.stringify(['DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET']) ||
        activation.network_puts_during_recovery !== 0 ||
        activation.ordinary_delivery !== 'LOCAL_ONLY' ||
        launch.record_count !== 34 || launch.cell_count_per_relay !== 39 ||
        launch.community_claims !== 11 || launch.original_posts !== 17 ||
        launch.boxed_posts_two_cells_each !== 5 || launch.replies !== 6 ||
        launch.sizeclass_2_cells_per_relay !== 3 ||
        launch.manifest_sha256 !== '36c15537d9e853cfb599cf59568a067e573a87c8de858183e332dfd3eb9192c0' ||
        activation.all_five_successor !== 'EXCLUDED' ||
        activation.ga_product_gate !== 'BLOCKED — 22 blockers DISCLOSED-OPEN, none cleared by this scope') {
      throw new Error('sequence-21 decision does not bind the exact live launch successor scope')
    }
    if (!Array.isArray(fix.patched_files) ||
        !fix.patched_files.includes('js/substrate/pin-history-bootstrap.mjs') ||
        !fix.patched_files.includes('js/substrate/browser-runtime-authority.mjs') ||
        fix.acceptance_rule !== 'accept application/octet-stream AND binary/octet-stream for opaque binary artifacts (both labels name an opaque binary body); HTML/error-page responses remain rejected; exact Content-Length checks, hash bindings, and fail-closed semantics unchanged') {
      throw new Error('sequence-21 decision does not bind the exact binary content-type fix')
    }
    if (!Array.isArray(extension.files) ||
        !extension.files.includes('scripts/production-pin-history-ceremony.mjs') ||
        !extension.files.includes('js/substrate/browser-runtime-authority.mjs') ||
        !extension.files.includes('peerit-limited-cell-get-profile-v1.json')) {
      throw new Error('sequence-21 decision does not record the ceremony extension surface')
    }
    if (bootstrap.path !== 'deploy/peerit-seed-bootstrap-v1-seq21.json' ||
        bootstrap.sha256 !== '9f7fa45eb45dd1c6672dd170c7035aa18c2747a3cd4c351867d59f3b1c605538' ||
        bootstrap.embedded_release_sequence !== 21 ||
        bootstrap.bootstrap_sequence !== 0 ||
        bootstrap.previous_bootstrap_hash !== null ||
        bootstrap.discovery_authority !== '691d524a1c2ac38de86ed592fbae6f9a906770b96fe704d3c63397a23171f6ec' ||
        bootstrap.records !== 39) {
      throw new Error('sequence-21 decision does not bind the exact launch seed bootstrap')
    }
    if (csp.policy_file !== 'deploy/render-security-headers.json' ||
        csp.policy_file_sha256 !== 'dc97c87d08bb773712cc739c37ffd4c62c121f7c92c01b20b3a8bf4a14f95724' ||
        csp.script_src !== "'self'" || csp.unsafe_eval !== 'FORBIDDEN' ||
        csp.wasm_unsafe_eval !== 'FORBIDDEN' || csp.expansion !== 'FORBIDDEN' ||
        csp.parameter_url_origin_addition !== 'FORBIDDEN') {
      throw new Error('sequence-21 decision does not bind the exact unchanged policy')
    }
    if (exactUrl.utf8 !== 'https://evidence.example:443/admission.cenc' ||
        exactUrl.utf8_hex !==
          '68747470733a2f2f65766964656e63652e6578616d706c653a3434332f61646d697373696f6e2e63656e63' ||
        exactUrl.semantics !== 'EVIDENCE_MIRROR_HINT_ONLY' ||
        exactUrl.browser_fetch !== 'FORBIDDEN' ||
        exactUrl.dns_resolution !== 'FORBIDDEN' ||
        exactUrl.url_parsing_or_normalization !== 'FORBIDDEN' ||
        exactUrl.csp_change !== 'FORBIDDEN' ||
        exactUrl.comparison !== 'EXACT_SIGNED_UTF8_BYTES') {
      throw new Error('sequence-21 decision does not bind the exact no-fetch parameterUrl contract')
    }
    const gate21 = runtimeGate.sequence_21 || {}
    if (runtimeGate.script !== 'scripts/browser-peerit-production-runtime-gate.mjs' ||
        runtimeGate.functional_mode !== 'live-two-relay' ||
        runtimeGate.functional_release_sequence !== 21 ||
        runtimeGate.full_authority_loader !== 'loadPeeritBrowserRuntimeAuthorityV1' ||
        runtimeGate.production_pin_history_loader !== 'loadPeeritProductionPinHistoryTerminalV1' ||
        runtimeGate.authority_active_before_relay_io !== true ||
        gate21.expected_network_gets !== 40 || gate21.expected_fallback_count !== 1 ||
        gate21.expected_record_count !== 39 || gate21.expected_cell_get_requests !== 40 ||
        gate21.expected_successful_cell_gets !== 39 ||
        gate21.expected_network_puts !== 0 || gate21.expected_parameter_url_requests !== 0 ||
        gate21.expected_sizeclass_1_responses !== 36 ||
        gate21.expected_sizeclass_2_responses !== 3 ||
        gate21['dal-1']?.origin !== 'https://relay-dal.p2phiverelay.xyz' ||
        gate21['dal-1']?.injected_cell_get_failures !== 1 ||
        gate21['dal-1']?.successful_cell_gets !== 38 ||
        gate21['dal-1']?.verified_readback_evidence_count !== 38 ||
        gate21['syd-1']?.origin !== 'https://relay-syd.p2phiverelay.xyz' ||
        gate21['syd-1']?.injected_cell_get_failures !== 0 ||
        gate21['syd-1']?.successful_cell_gets !== 1 ||
        gate21['syd-1']?.verified_readback_evidence_count !== 1) {
      throw new Error('sequence-21 decision does not bind the named-relay production runtime gate')
    }
    if (relays['dal-1']?.minimum_descriptor_sequence !== 11 ||
        relays['dal-1']?.descriptor_head_sha256 !== '813f8b6ae289f1beb0716b5208e695c03e3451d0ca963d4547d48bffc82f80d1' ||
        relays['dal-1']?.admission_protocol_sha256 !== '7d29e79d20955f14b4553d8517c35a5b548308ff9f44db39590c0ec5c2768ecb' ||
        relays['syd-1']?.minimum_descriptor_sequence !== 14 ||
        relays['syd-1']?.descriptor_head_sha256 !== '96a8fcd63f467067f6ff246d75ef629ad31695fd9a9f42a3873e5eb7e1e35d1b' ||
        relays['syd-1']?.admission_protocol_sha256 !== '108e53b1e93c56e8c37f281234c23035b888615e8cd904d2751aa58b2dcea120') {
      throw new Error('sequence-21 decision does not bind the same-day named relay authorities')
    }
    addCheck('canary:owner-decision', 'pass', `Owner live-site unblock decision verified byte-exact (sha256 ${CANARY_SEQ21_CONTENT_TYPE_UNBLOCK_DECISION_SHA256.slice(0, 12)}...): ACCEPT seq-21 as the LIVE bounded-public-test launch successor — binary content-type compatibility for the pin-history bootstrap and runtime asset fetcher (application/octet-stream AND binary/octet-stream, everything else unchanged), limited Cell-GET exposed, 39-record signed recovery enabled; unchanged CSP, zero PUTs, all-five excluded, GA gate still blocked with 22 blockers DISCLOSED-OPEN.`, {
      file: CANARY_SEQ21_CONTENT_TYPE_UNBLOCK_DECISION_FILE,
      sha256: CANARY_SEQ21_CONTENT_TYPE_UNBLOCK_DECISION_SHA256,
      decidedAt: decision.decided_at,
      functionalReleaseSequence: 21,
      launchRecords: launch.record_count,
      launchCellsPerRelay: launch.cell_count_per_relay
    })
    return
  }
  if (release.releaseSequence === 20) {
    const decision = readCanaryOwnerDecision(
      CANARY_SEQ20_LAUNCH_DECISION_FILE,
      CANARY_SEQ20_LAUNCH_DECISION_SHA256)
    const activation = decision.activation || {}
    const authority = decision.authority || {}
    const launch = activation.launch_seed || {}
    const bootstrap = decision.seed_bootstrap || {}
    const exactUrl = decision.exact_admission_parameter_url || {}
    const csp = decision.production_csp || {}
    const runtimeGate = decision.production_runtime_gate || {}
    const relays = decision.relay_authority || {}
    const patch = decision.runtime_patch || {}
    const followups = Array.isArray(decision.followups) ? decision.followups.join('\n') : ''
    if (decision.schema_version !== 5 ||
        decision.decision_id !== 'peerit-seq20-launch-two-relay-live-recovery-20260731' ||
        decision.status !== 'DECIDED' ||
        !String(decision.decision || '').startsWith('ACCEPT Peerit release sequence 20 as the LIVE bounded-public-test launch slot') ||
        !followups.includes('GA product gate remains honestly blocked')) {
      throw new Error('sequence-20 launch decision is not the recorded owner ACCEPT')
    }
    if (authority.baseline_release_sequence !== 19 ||
        authority.superseded_slot_posture !== 'sequence 20 as COLD_FAIL_CLOSED_BEFORE_RELAY_IO rollback, recorded in the seq-19 CSP-safe decision, is superseded for this exact slot only; the rollback tooling remains for any future rollback slot' ||
        !Array.isArray(authority.cited_prior_decisions) ||
        !authority.cited_prior_decisions.some(row => row.file === CANARY_CSP_SAFE_RECOVERY_DECISION_FILE && row.sha256 === CANARY_CSP_SAFE_RECOVERY_DECISION_SHA256)) {
      throw new Error('sequence-20 launch decision does not cite the superseded seq-19 rollback decision')
    }
    if (activation.functional_release_sequence !== 20 ||
        activation.rollback_release_sequence !== null ||
        activation.rollback_posture !== 'SUPERSEDED_FOR_THIS_SLOT_BY_OWNER_DECISION_2026-07-31' ||
        activation.limited_cell_get_authority_release_sequence !== 20 ||
        activation.limited_cell_get_runtime_authority_exposed !== true ||
        activation.seed_recovery_enabled !== true ||
        activation.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
        JSON.stringify(activation.relays) !== JSON.stringify(['dal-1', 'syd-1']) ||
        JSON.stringify(activation.allowed_browser_operations) !==
          JSON.stringify(['DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET']) ||
        activation.network_puts_during_recovery !== 0 ||
        activation.ordinary_delivery !== 'LOCAL_ONLY' ||
        launch.record_count !== 34 || launch.cell_count_per_relay !== 39 ||
        launch.community_claims !== 11 || launch.original_posts !== 17 ||
        launch.boxed_posts_two_cells_each !== 5 || launch.replies !== 6 ||
        launch.sizeclass_2_cells_per_relay !== 3 ||
        launch.manifest_sha256 !== '36c15537d9e853cfb599cf59568a067e573a87c8de858183e332dfd3eb9192c0' ||
        activation.all_five_successor !== 'EXCLUDED' ||
        activation.ga_product_gate !== 'BLOCKED — 22 blockers DISCLOSED-OPEN, none cleared by this scope') {
      throw new Error('sequence-20 launch decision does not bind the exact live launch slot scope')
    }
    if (bootstrap.path !== 'deploy/peerit-seed-bootstrap-v1-seq20.json' ||
        bootstrap.sha256 !== '0a386975293d01e983c5c64074cdbcc8b34cff40bb5147807959de4903e03e69' ||
        bootstrap.embedded_release_sequence !== 20 ||
        bootstrap.bootstrap_sequence !== 0 ||
        bootstrap.previous_bootstrap_hash !== null ||
        bootstrap.discovery_authority !== '691d524a1c2ac38de86ed592fbae6f9a906770b96fe704d3c63397a23171f6ec' ||
        bootstrap.records !== 39) {
      throw new Error('sequence-20 launch decision does not bind the exact launch seed bootstrap')
    }
    if (!Array.isArray(patch.files) ||
        !patch.files.includes('js/substrate/browser-runtime-authority.mjs') ||
        !patch.files.includes('peerit-limited-cell-get-profile-v1.json') ||
        !patch.files.includes('scripts/browser-peerit-production-runtime-gate.mjs')) {
      throw new Error('sequence-20 launch decision does not record the limited Cell-GET runtime patch surface')
    }
    if (csp.policy_file !== 'deploy/render-security-headers.json' ||
        csp.policy_file_sha256 !== 'dc97c87d08bb773712cc739c37ffd4c62c121f7c92c01b20b3a8bf4a14f95724' ||
        csp.script_src !== "'self'" || csp.unsafe_eval !== 'FORBIDDEN' ||
        csp.wasm_unsafe_eval !== 'FORBIDDEN' || csp.expansion !== 'FORBIDDEN' ||
        csp.parameter_url_origin_addition !== 'FORBIDDEN') {
      throw new Error('sequence-20 launch decision does not bind the exact unchanged policy')
    }
    if (exactUrl.utf8 !== 'https://evidence.example:443/admission.cenc' ||
        exactUrl.utf8_hex !==
          '68747470733a2f2f65766964656e63652e6578616d706c653a3434332f61646d697373696f6e2e63656e63' ||
        exactUrl.semantics !== 'EVIDENCE_MIRROR_HINT_ONLY' ||
        exactUrl.browser_fetch !== 'FORBIDDEN' ||
        exactUrl.dns_resolution !== 'FORBIDDEN' ||
        exactUrl.url_parsing_or_normalization !== 'FORBIDDEN' ||
        exactUrl.csp_change !== 'FORBIDDEN' ||
        exactUrl.comparison !== 'EXACT_SIGNED_UTF8_BYTES') {
      throw new Error('sequence-20 launch decision does not bind the exact no-fetch parameterUrl contract')
    }
    const gate20 = runtimeGate.sequence_20 || {}
    if (runtimeGate.script !== 'scripts/browser-peerit-production-runtime-gate.mjs' ||
        runtimeGate.functional_mode !== 'live-two-relay' ||
        runtimeGate.functional_release_sequence !== 20 ||
        runtimeGate.full_authority_loader !== 'loadPeeritBrowserRuntimeAuthorityV1' ||
        runtimeGate.production_pin_history_loader !== 'loadPeeritProductionPinHistoryTerminalV1' ||
        runtimeGate.authority_active_before_relay_io !== true ||
        gate20.expected_network_gets !== 40 || gate20.expected_fallback_count !== 1 ||
        gate20.expected_record_count !== 39 || gate20.expected_cell_get_requests !== 40 ||
        gate20.expected_successful_cell_gets !== 39 ||
        gate20.expected_network_puts !== 0 || gate20.expected_parameter_url_requests !== 0 ||
        gate20.expected_sizeclass_1_responses !== 36 ||
        gate20.expected_sizeclass_2_responses !== 3 ||
        gate20['dal-1']?.origin !== 'https://relay-dal.p2phiverelay.xyz' ||
        gate20['dal-1']?.injected_cell_get_failures !== 1 ||
        gate20['dal-1']?.successful_cell_gets !== 38 ||
        gate20['dal-1']?.verified_readback_evidence_count !== 38 ||
        gate20['syd-1']?.origin !== 'https://relay-syd.p2phiverelay.xyz' ||
        gate20['syd-1']?.injected_cell_get_failures !== 0 ||
        gate20['syd-1']?.successful_cell_gets !== 1 ||
        gate20['syd-1']?.verified_readback_evidence_count !== 1) {
      throw new Error('sequence-20 launch decision does not bind the named-relay production runtime gate')
    }
    if (relays['dal-1']?.minimum_descriptor_sequence !== 9 ||
        relays['dal-1']?.descriptor_head_sha256 !== 'a36845597379c49f492a0b5a99d476723b6e538e7f73052c029f755c68acbdd6' ||
        relays['dal-1']?.admission_protocol_sha256 !== '5494fe9abfc07536392b3d1a51a6ccec7de75063238198fcbf19729c37baf6f7' ||
        relays['syd-1']?.minimum_descriptor_sequence !== 12 ||
        relays['syd-1']?.descriptor_head_sha256 !== 'e1ca456c7e99294b9fde660dc2d597e9bf5abd6e4530064a8c512c1e2de5a507' ||
        relays['syd-1']?.admission_protocol_sha256 !== '03f920f2102e3984e0885867e51c1d87a8aae6b52ae2e1bf472a0b9284e9a265') {
      throw new Error('sequence-20 launch decision does not bind the same-day named relay authorities')
    }
    addCheck('canary:owner-decision', 'pass', `Owner launch-slot decision verified byte-exact (sha256 ${CANARY_SEQ20_LAUNCH_DECISION_SHA256.slice(0, 12)}...): ACCEPT seq-20 as the LIVE bounded-public-test launch slot for the 34-record launch seed (limited Cell-GET exposed, 39-record signed recovery enabled), superseding the seq-19 rollback posture for this slot; unchanged CSP, zero PUTs, all-five excluded, GA gate still blocked with 22 blockers DISCLOSED-OPEN.`, {
      file: CANARY_SEQ20_LAUNCH_DECISION_FILE,
      sha256: CANARY_SEQ20_LAUNCH_DECISION_SHA256,
      decidedAt: decision.decided_at,
      functionalReleaseSequence: 20,
      launchRecords: launch.record_count,
      launchCellsPerRelay: launch.cell_count_per_relay
    })
    return
  }
  if (release.releaseSequence >= 19 && release.releaseSequence <= 20) {
    const decision = readCanaryOwnerDecision(
      CANARY_CSP_SAFE_RECOVERY_DECISION_FILE,
      CANARY_CSP_SAFE_RECOVERY_DECISION_SHA256)
    const activation = decision.activation || {}
    const authority = decision.authority || {}
    const exactUrl = decision.exact_admission_parameter_url || {}
    const csp = decision.production_csp || {}
    const runtimeGate = decision.production_runtime_gate || {}
    const rootCause = decision.root_cause || {}
    const validator = decision.csp_safe_validator_authority || {}
    const cellGet = decision.fixed_cell_get_authority || {}
    const relays = decision.relay_authority || {}
    const followups = Array.isArray(decision.followups) ? decision.followups.join('\n') : ''
    if (decision.schema_version !== 5 ||
        decision.decision_id !== 'peerit-seq19-csp-safe-two-relay-live-recovery-20260729' ||
        decision.status !== 'DECIDED' ||
        !String(decision.decision || '').startsWith('ACCEPT Peerit release sequence 19') ||
        !followups.includes('GA product gate remains honestly blocked')) {
      throw new Error('sequence-19 CSP-safe recovery decision is not the recorded owner ACCEPT')
    }
    if (authority.baseline_commit !== '9f4cb0d600d5df6ed927b9220ea713dab9a1e49b' ||
        authority.baseline_tree !== '0268f2a59a51db0a7ada73679f2451e5bc6718a2' ||
        authority.baseline_release_sequence !== 18 ||
        authority.failed_sequence_17_deploy_id !== 'dep-d9l6u1b7uimc738lsik0' ||
        authority.containment_sequence_18_deploy_id !== 'dep-d9l6vn2jobas738ogetg' ||
        authority.incident_evidence_sha256 !== '4259c947ba1d1ebf9d9bcd323a015c2a01df051fb2d2c085f42df1e53e879d0e' ||
        authority.incident_handoff_sha256 !== '2661648ba7179f43fc8ee71ac9e5b53d611ceaf802c5bac70ab79016516231d0' ||
        authority.root_cause_diagnostic_sha256 !== 'cd65c0c3080e5b64ad5a79b70b7f8506409c4b49825c8e0dbbaabb6e8ff07eb4' ||
        authority.maintenance_run_id !== 'peerit-seq19-csp-safe-live-recovery-20260729t220328z' ||
        authority.context_lock_digest !== '63cf32c6f6a16b954a793fc87877212f1d2ad8db114d9910507f6033dd059890' ||
        authority.source_acceptance_sha256 !== '0326f1efac7cec332875c6ecf5e1fce78edcd2bfec954fb4b903fb8b72677824') {
      throw new Error('CSP-safe recovery decision does not bind the accepted incident and run authority')
    }
    if (activation.functional_release_sequence !== 19 ||
        activation.rollback_release_sequence !== 20 ||
        activation.rollback_posture !== 'COLD_FAIL_CLOSED_BEFORE_RELAY_IO_AT_SEQUENCE_20' ||
        activation.limited_cell_get_authority_release_sequence !== 19 ||
        activation.rollback_limited_cell_get_runtime_authority_exposed !== false ||
        activation.rollback_generic_limited_get_assets !==
          'PRESENT_BUT_INERT_AND_EXCLUDED_FROM_RUNTIME_AUTHORITY' ||
        activation.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
        JSON.stringify(activation.relays) !== JSON.stringify(['dal-1', 'syd-1']) ||
        JSON.stringify(activation.allowed_browser_operations) !==
          JSON.stringify(['DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET']) ||
        activation.network_puts_during_recovery !== 0 ||
        activation.ordinary_delivery !== 'LOCAL_ONLY' ||
        activation.seed_record_count !== 4 || activation.historical_seed_put_count !== 8 ||
        JSON.stringify(activation.post_cids) !== JSON.stringify(exactPostCids) ||
        activation.all_five_successor !==
          'EXCLUDED_AND_LOCKED_UNTIL_AFTER_SEQUENCE_19_LIVE_ACCEPTANCE') {
      throw new Error('CSP-safe decision does not bind the exact seq19/seq20 two-relay recovery scope')
    }
    if (csp.policy_file !== 'deploy/render-security-headers.json' ||
        csp.policy_file_sha256 !== 'dc97c87d08bb773712cc739c37ffd4c62c121f7c92c01b20b3a8bf4a14f95724' ||
        csp.script_src !== "'self'" || csp.unsafe_eval !== 'FORBIDDEN' ||
        csp.wasm_unsafe_eval !== 'FORBIDDEN' || csp.expansion !== 'FORBIDDEN' ||
        csp.parameter_url_origin_addition !== 'FORBIDDEN' ||
        rootCause.classification !== 'VALIDATOR_WASM_BLOCKED_BY_RELEASE_CSP' ||
        !String(rootCause.exact_exception || '').includes('WebAssembly.Module()') ||
        !String(rootCause.exact_exception || '').includes("script-src 'self'")) {
      throw new Error('CSP-safe decision does not bind the exact unchanged policy and root cause')
    }
    if (exactUrl.utf8 !== 'https://evidence.example:443/admission.cenc' ||
        exactUrl.utf8_hex !==
          '68747470733a2f2f65766964656e63652e6578616d706c653a3434332f61646d697373696f6e2e63656e63' ||
        exactUrl.semantics !== 'EVIDENCE_MIRROR_HINT_ONLY' ||
        exactUrl.browser_fetch !== 'FORBIDDEN' ||
        exactUrl.dns_resolution !== 'FORBIDDEN' ||
        exactUrl.url_parsing_or_normalization !== 'FORBIDDEN' ||
        exactUrl.csp_change !== 'FORBIDDEN' ||
        exactUrl.comparison !== 'EXACT_SIGNED_UTF8_BYTES') {
      throw new Error('CSP-safe decision does not bind the exact no-fetch parameterUrl contract')
    }
    const gate19 = runtimeGate.sequence_19 || {}
    const gate20 = runtimeGate.sequence_20 || {}
    if (runtimeGate.script !== 'scripts/browser-peerit-production-runtime-gate.mjs' ||
        runtimeGate.functional_mode !== 'live-two-relay' ||
        runtimeGate.rollback_mode !== 'rollback-preio' ||
        runtimeGate.full_authority_loader !== 'loadPeeritBrowserRuntimeAuthorityV1' ||
        runtimeGate.production_pin_history_loader !== 'loadPeeritProductionPinHistoryTerminalV1' ||
        runtimeGate.authority_active_before_relay_io !== true ||
        gate19.expected_network_gets !== 5 || gate19.expected_fallback_count !== 1 ||
        gate19.expected_record_count !== 4 || gate19.expected_cell_bytes !== 16384 ||
        gate19.expected_network_puts !== 0 || gate19.expected_parameter_url_requests !== 0 ||
        gate19['dal-1']?.origin !== 'https://relay-dal.p2phiverelay.xyz' ||
        gate19['dal-1']?.descriptor_head_sha256 !== '549fd1df9b5cdba8ca2d97ab842bbda6a4a1433d79a82e230d8807bbd97cfebe' ||
        gate19['dal-1']?.injected_cell_get_failures !== 1 ||
        gate19['dal-1']?.successful_cell_gets !== 3 ||
        gate19['dal-1']?.verified_readback_evidence_count !== 3 ||
        gate19['syd-1']?.origin !== 'https://relay-syd.p2phiverelay.xyz' ||
        gate19['syd-1']?.descriptor_head_sha256 !== 'a4cbfe23176862cf5dbfae962ad3b919063073c4a51abe20ef4ae06c05a32153' ||
        gate19['syd-1']?.injected_cell_get_failures !== 0 ||
        gate19['syd-1']?.successful_cell_gets !== 1 ||
        gate19['syd-1']?.verified_readback_evidence_count !== 1 ||
        gate20.browser_runtime_authority_active !== true ||
        gate20.limited_cell_get_runtime_authority_exposed !== false ||
        gate20.expected_error_code !== 'PEERIT_LIMITED_CELL_GET_CONTROL_INVALID' ||
        gate20.expected_relay_requests !== 0 || gate20.expected_network_puts !== 0) {
      throw new Error('CSP-safe decision does not bind the named-relay production runtime gate')
    }
    if (validator.accepted_source_patch_sha256 !== '123c501f36e6368ddedca089f778abb6ac86047b2236b31af72751a7daf9ef36' ||
        validator.accepted_source_file_closure_sha256 !== '350ab2db0feb497107cb262c900b3adc271bd5afe1efed6eb41e94d1401f73ba' ||
        validator.normalized_metafile_input_closure_sha256 !== '49bba7fd634d4085d74d13b5716491ad66415d3fbf4d1028c60a9b6d7cf628da' ||
        validator.normalized_metafile_input_count !== 53 ||
        validator.third_party_input_allowlist_count !== 25 ||
        validator.validator_artifact_sha256 !== 'e69bf4554720c853e340f212eda4fe7760ae119594f5f136701a71c1b214a809' ||
        validator.validator_project_domain_hash !== 'c92f1b402d745fc5d8235358bc7909a50cb23b230e75de605fd421fc500f9613' ||
        validator.bundle_and_bare_byte_identical !== true) {
      throw new Error('CSP-safe decision does not bind the independently accepted validator closure')
    }
    if (cellGet.hiverelay_commit !== 'c284435c1d075423a8d1bfcea04c3e171c6757ca' ||
        cellGet.hiverelay_tree !== '02b11d448efdef693e49fec3b9d078643d8f4086' ||
        cellGet.artifact_sha256 !== '653cba3c78d3b26b1e4f06a22fff8a5896a5c5158bc24c8b06ad577196429eed' ||
        cellGet.artifact_domain_hash !== 'e04b514a4f828d8b557b833c37cea00fab37046bbc2d108c557924a9302259e1' ||
        cellGet.manifest_sha256 !== '6992ea2f8ab4733aaecdfbb277b818bacb853b8d0141291abcc9386f3342fcc8' ||
        cellGet.manifest_domain_hash !== '80fbff28284f1ef2e369871090be260050482b5b8d62b92b3d38670381f5a17d' ||
        cellGet.source_closure_sha256 !== 'ed40292d9c1154e50607188cff6ffcc7df534b203c4ecf3ebccbd64099b24830' ||
        JSON.stringify(cellGet.public_exports) !==
          JSON.stringify(['createBlindCellGetControl', 'createBrowserCryptoRuntime']) ||
        relays['dal-1']?.minimum_descriptor_sequence !== 5 ||
        relays['dal-1']?.descriptor_head_sha256 !== '549fd1df9b5cdba8ca2d97ab842bbda6a4a1433d79a82e230d8807bbd97cfebe' ||
        relays['dal-1']?.admission_protocol_sha256 !== '8748eaafd273695eb1d22282c8278cd733898f00ff137f238d8d5e300a148cc4' ||
        relays['syd-1']?.minimum_descriptor_sequence !== 8 ||
        relays['syd-1']?.descriptor_head_sha256 !== 'a4cbfe23176862cf5dbfae962ad3b919063073c4a51abe20ef4ae06c05a32153' ||
        relays['syd-1']?.admission_protocol_sha256 !== 'a474226ced549bea08cb1e7af20f4104561a4818482b20815f6c63b632e0762b') {
      throw new Error('CSP-safe decision does not bind the accepted Cell GET and named relay authorities')
    }
    addCheck('canary:owner-decision', 'pass', `Owner CSP-safe recovery decision verified byte-exact (sha256 ${CANARY_CSP_SAFE_RECOVERY_DECISION_SHA256.slice(0, 12)}...): ACCEPT seq-19 authenticated two-relay GET recovery with direct-child seq-20 cold rollback; unchanged CSP, zero PUTs, all-five excluded, GA gate still blocked.`, {
      file: CANARY_CSP_SAFE_RECOVERY_DECISION_FILE,
      sha256: CANARY_CSP_SAFE_RECOVERY_DECISION_SHA256,
      decidedAt: decision.decided_at,
      functionalReleaseSequence: 19,
      rollbackReleaseSequence: 20
    })
    return
  }
  if (release.releaseSequence >= 17 && release.releaseSequence <= 18) {
    const decision = readCanaryOwnerDecision(
      CANARY_EXACT_ADMISSION_URL_DECISION_FILE,
      CANARY_EXACT_ADMISSION_URL_DECISION_SHA256)
    const activation = decision.activation || {}
    const exactUrl = decision.exact_admission_parameter_url || {}
    const authority = decision.fixed_cell_get_authority || {}
    const followups = Array.isArray(decision.followups) ? decision.followups.join('\n') : ''
    if (decision.schema_version !== 4 ||
        decision.decision_id !==
          'peerit-seq17-exact-admission-url-recovery-two-relay-public-test-20260729' ||
        decision.status !== 'DECIDED' ||
        !String(decision.decision || '').startsWith('ACCEPT Peerit release sequence 17') ||
        !followups.includes('GA product gate remains honestly blocked')) {
      throw new Error('sequence-17 corrective decision is not the recorded owner ACCEPT')
    }
    if (activation.functional_release_sequence !== 17 ||
        activation.rollback_release_sequence !== 18 ||
        activation.rollback_posture !== 'COLD_FAIL_CLOSED_BEFORE_RELAY_IO_AT_SEQUENCE_18' ||
        activation.limited_cell_get_authority_release_sequence !== 17 ||
        activation.rollback_requires_limited_cell_get_assets !== false ||
        activation.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
        JSON.stringify(activation.relays) !== JSON.stringify(['syd-1', 'dal-1']) ||
        JSON.stringify(activation.allowed_browser_operations) !==
          JSON.stringify(['DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET']) ||
        activation.network_puts_during_recovery !== 0 ||
        activation.ordinary_delivery !== 'LOCAL_ONLY' ||
        activation.seed_record_count !== 4 || activation.historical_seed_put_count !== 8 ||
        JSON.stringify(activation.post_cids) !== JSON.stringify(exactPostCids) ||
        activation.all_five_successor !==
          'EXCLUDED_AND_LOCKED_UNTIL_AFTER_SEQUENCE_17_LIVE_ACCEPTANCE') {
      throw new Error('corrective decision does not bind the exact seq17/seq18 two-relay recovery scope')
    }
    if (exactUrl.utf8 !== 'https://evidence.example:443/admission.cenc' ||
        exactUrl.utf8_hex !==
          '68747470733a2f2f65766964656e63652e6578616d706c653a3434332f61646d697373696f6e2e63656e63' ||
        exactUrl.semantics !== 'EVIDENCE_MIRROR_HINT_ONLY' ||
        exactUrl.browser_fetch !== 'FORBIDDEN' ||
        exactUrl.dns_resolution !== 'FORBIDDEN' ||
        exactUrl.url_parsing_or_normalization !== 'FORBIDDEN' ||
        exactUrl.csp_change !== 'FORBIDDEN' ||
        exactUrl.comparison !== 'EXACT_SIGNED_UTF8_BYTES') {
      throw new Error('corrective decision does not bind the exact no-fetch parameterUrl contract')
    }
    if (authority.hiverelay_commit !== 'c284435c1d075423a8d1bfcea04c3e171c6757ca' ||
        authority.hiverelay_tree !== '02b11d448efdef693e49fec3b9d078643d8f4086' ||
        authority.artifact_sha256 !== '653cba3c78d3b26b1e4f06a22fff8a5896a5c5158bc24c8b06ad577196429eed' ||
        authority.artifact_domain_hash !== 'e04b514a4f828d8b557b833c37cea00fab37046bbc2d108c557924a9302259e1' ||
        authority.manifest_sha256 !== '6992ea2f8ab4733aaecdfbb277b818bacb853b8d0141291abcc9386f3342fcc8' ||
        authority.manifest_domain_hash !== '80fbff28284f1ef2e369871090be260050482b5b8d62b92b3d38670381f5a17d' ||
        authority.source_closure_sha256 !== 'ed40292d9c1154e50607188cff6ffcc7df534b203c4ecf3ebccbd64099b24830' ||
        JSON.stringify(authority.public_exports) !==
          JSON.stringify(['createBlindCellGetControl', 'createBrowserCryptoRuntime'])) {
      throw new Error('corrective decision does not bind the accepted fixed Cell GET authority')
    }
    addCheck('canary:owner-decision', 'pass', `Owner corrective decision verified byte-exact (sha256 ${CANARY_EXACT_ADMISSION_URL_DECISION_SHA256.slice(0, 12)}...): ACCEPT seq-17 exact parameterUrl GET recovery with direct-child seq-18 cold rollback; no URL fetch/DNS/CSP, zero PUTs, all-five excluded, GA gate still blocked.`, {
      file: CANARY_EXACT_ADMISSION_URL_DECISION_FILE,
      sha256: CANARY_EXACT_ADMISSION_URL_DECISION_SHA256,
      decidedAt: decision.decided_at,
      functionalReleaseSequence: 17,
      rollbackReleaseSequence: 18
    })
    return
  }
  if (release.releaseSequence >= 15 && release.releaseSequence <= 16) {
    const decision = readCanaryOwnerDecision(
      CANARY_RECOVERY_DECISION_FILE, CANARY_RECOVERY_DECISION_SHA256)
    const activation = decision.activation || {}
    const authority = decision.fixed_cell_get_authority || {}
    const followups = Array.isArray(decision.followups) ? decision.followups.join('\n') : ''
    if (decision.schema_version !== 3 ||
        decision.decision_id !== 'peerit-seq15-limited-cell-get-recovery-two-relay-public-test-activation-20260729t172519z' ||
        decision.status !== 'DECIDED' ||
        !String(decision.decision || '').startsWith('ACCEPT Peerit release sequence 15') ||
        !followups.includes('GA product gate remains honestly blocked')) {
      throw new Error('sequence-15 recovery decision is not the recorded owner ACCEPT')
    }
    if (activation.functional_release_sequence !== 15 ||
        activation.rollback_release_sequence !== 16 ||
        activation.rollback_posture !== 'RESTORE_SEQUENCE_14_FAIL_CLOSED_RUNTIME_BEHAVIOR_AT_NEW_SEQUENCE_16' ||
        activation.limited_cell_get_authority_release_sequence !== 15 ||
        activation.rollback_requires_limited_cell_get_assets !== false ||
        activation.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
        JSON.stringify(activation.relays) !== JSON.stringify(['syd-1', 'dal-1']) ||
        JSON.stringify(activation.allowed_browser_operations) !==
          JSON.stringify(['DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET']) ||
        activation.network_puts_during_recovery !== 0 ||
        activation.ordinary_delivery !== 'LOCAL_ONLY' ||
        activation.seed_record_count !== 4 || activation.historical_seed_put_count !== 8 ||
        JSON.stringify(activation.post_cids) !== JSON.stringify(exactPostCids) ||
        activation.all_five_successor !== 'EXCLUDED_UNTIL_AFTER_PEERIT_SITE_SEQUENCE_15_ACTIVATION') {
      throw new Error('canary decision does not bind the exact seq15/seq16 fixed-GET two-relay recovery scope')
    }
    if (authority.hiverelay_commit !== 'c284435c1d075423a8d1bfcea04c3e171c6757ca' ||
        authority.hiverelay_tree !== '02b11d448efdef693e49fec3b9d078643d8f4086' ||
        authority.artifact_sha256 !== '653cba3c78d3b26b1e4f06a22fff8a5896a5c5158bc24c8b06ad577196429eed' ||
        authority.artifact_domain_hash !== 'e04b514a4f828d8b557b833c37cea00fab37046bbc2d108c557924a9302259e1' ||
        authority.manifest_sha256 !== '6992ea2f8ab4733aaecdfbb277b818bacb853b8d0141291abcc9386f3342fcc8' ||
        authority.manifest_domain_hash !== '80fbff28284f1ef2e369871090be260050482b5b8d62b92b3d38670381f5a17d' ||
        authority.source_closure_sha256 !== 'ed40292d9c1154e50607188cff6ffcc7df534b203c4ecf3ebccbd64099b24830' ||
        JSON.stringify(authority.public_exports) !==
          JSON.stringify(['createBlindCellGetControl', 'createBrowserCryptoRuntime'])) {
      throw new Error('sequence-15 recovery decision does not bind the independently accepted fixed Cell GET authority')
    }
    addCheck('canary:owner-decision', 'pass', `Owner canary decision verified byte-exact (sha256 ${CANARY_RECOVERY_DECISION_SHA256.slice(0, 12)}...): ACCEPT seq-15 fixed Cell GET recovery with seq-16 monotonic rollback; zero recovery PUTs, ordinary delivery LOCAL_ONLY, all-five excluded, GA gate still blocked.`, {
      file: CANARY_RECOVERY_DECISION_FILE,
      sha256: CANARY_RECOVERY_DECISION_SHA256,
      decidedAt: decision.decided_at,
      functionalReleaseSequence: 15,
      rollbackReleaseSequence: 16
    })
    return
  }
  if (release.releaseSequence < 13 || release.releaseSequence > 14) {
    throw new Error(`no byte-pinned limited-public-test owner decision covers release sequence ${release.releaseSequence}`)
  }
  const decision = readCanaryOwnerDecision(CANARY_DECISION_FILE, CANARY_DECISION_SHA256)
  if (decision.schema_version !== 2 || decision.decision_id !== 'peerit-seq13-three-post-two-relay-public-test-activation-20260729t132650z') {
    throw new Error('canary decision_id does not match the recorded owner decision')
  }
  if (decision.status !== 'DECIDED' || !String(decision.decision || '').startsWith('ACCEPT Peerit release sequence 13')) {
    throw new Error('canary decision is not the recorded ACCEPT')
  }
  if (!String(decision.decision).includes('WIRE_TUPLE_DRIFT') || !String(decision.decision).includes('disclosed')) {
    throw new Error('canary decision must carry the WIRE_TUPLE_DRIFT disclosure')
  }
  const followups = Array.isArray(decision.followups) ? decision.followups.join('\n') : ''
  if (!followups.includes('GA product gate remains honestly blocked')) {
    throw new Error('canary decision must itself record that the GA product gate remains blocked')
  }
  const activation = decision.activation || {}
  if (activation.functional_release_sequence !== 13 || activation.rollback_release_sequence !== 14 ||
      ![13, 14].includes(release.releaseSequence) ||
      activation.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
      JSON.stringify(activation.relays) !== JSON.stringify(['syd-1', 'dal-1']) ||
      JSON.stringify(activation.post_cids) !== JSON.stringify(exactPostCids) ||
      activation.seed_record_count !== 4 || activation.seed_put_count !== 8 ||
      activation.all_five_successor !== 'EXCLUDED_UNTIL_AFTER_PEERIT_SITE_ACTIVATION') {
    throw new Error('canary decision does not bind the exact seq13/seq14, two-relay, three-post activation scope')
  }
  addCheck('canary:owner-decision', 'pass', `Owner canary decision verified byte-exact (sha256 ${CANARY_DECISION_SHA256.slice(0, 12)}...): ACCEPT seq-13 with seq-14 rollback for the exact two-relay, three-post public test; all-five excluded, WIRE_TUPLE_DRIFT disclosed, GA gate still blocked.`, {
    file: CANARY_DECISION_FILE,
    sha256: CANARY_DECISION_SHA256,
    decidedAt: decision.decided_at
  })
}

function verifyCanaryPinHistoryContinuity (release, driveKey) {
  const historyPath = join(ROOT, CANARY_PIN_HISTORY_FILE)
  const sigPath = join(ROOT, CANARY_PIN_HISTORY_SIG_FILE)
  if (!existsSync(historyPath)) throw new Error(`web release pin-history is missing: ${CANARY_PIN_HISTORY_FILE}`)
  if (!existsSync(sigPath)) throw new Error(`web release pin-history signature is missing: ${CANARY_PIN_HISTORY_SIG_FILE}`)
  const historyBytes = readFileSync(historyPath)
  const history = JSON.parse(historyBytes.toString('utf8'))
  const envelope = JSON.parse(readFileSync(sigPath, 'utf8'))
  if (history.schema !== 'peerit-web-release-pin-history/v1' || !Array.isArray(history.entries)) {
    throw new Error('web release pin-history schema is not peerit-web-release-pin-history/v1 with entries')
  }
  if (envelope.schema !== 'peerit-blind-public-test-artifact-sig/v1' || envelope.alg !== 'ed25519' ||
      String(envelope.key || '').toLowerCase() !== release.pinnedReleaseKey ||
      envelope.signedFile !== CANARY_PIN_HISTORY_FILE ||
      envelope.signedBytesSha256 !== sha256(historyBytes)) {
    throw new Error('web release pin-history signature envelope does not bind the exact current pin-history bytes with the pinned release key')
  }
  const historySigOk = nodeVerify(null, historyBytes,
    createPublicKey({ key: Buffer.from(SPKI_PREFIX + release.pinnedReleaseKey, 'hex'), format: 'der', type: 'spki' }),
    Buffer.from(String(envelope.sig || ''), 'hex'))
  if (!historySigOk) throw new Error('web release pin-history signature does not verify with the pinned release key')

  const sequences = history.entries.map((entry) => entry.releaseSequence)
  const expectedHeadSequence = opts.phase === 'prepare'
    ? release.releaseSequence - 1
    : release.releaseSequence
  if (sequences.length < 1 || sequences[sequences.length - 1] !== expectedHeadSequence ||
      (opts.phase !== 'prepare' &&
       (sequences.length < 2 || sequences[sequences.length - 2] !== release.releaseSequence - 1))) {
    const expected = opts.phase === 'prepare'
      ? `signed predecessor ${release.releaseSequence - 1}`
      : `${release.releaseSequence - 1} -> ${release.releaseSequence}`
    throw new Error(`pin-history continuity broken: expected ${expected}, got ${sequences.join(' -> ')}`)
  }
  for (let i = 1; i < sequences.length; i++) {
    if (sequences[i] <= sequences[i - 1]) throw new Error(`pin-history sequences must strictly increase: ${sequences.join(' -> ')}`)
  }
  const head = history.entries[history.entries.length - 1]
  const manifestSha256 = sha256(readFileSync(join(ROOT, 'web', 'asset-manifest.json')))
  if (head.manifestSha256 !== manifestSha256) throw new Error('pin-history head does not bind the exact frozen web/asset-manifest.json bytes')
  if (head.pinnedReleaseKey !== release.pinnedReleaseKey) throw new Error('pin-history head key does not match the release config')
  if (head.driveKey !== driveKey) throw new Error('pin-history head drive key does not match the release drive key')
  if (head.transport !== 'blind-substrate/blind-v1') throw new Error('pin-history head transport is not blind-substrate/blind-v1')
  if (JSON.stringify(head.relayHints) !== JSON.stringify(release.relayHints)) throw new Error('pin-history head relay hints do not match the release config')
  if (head.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY') throw new Error('pin-history head must carry the LIVE_PUBLIC_TEST_ONLY claim boundary')
  const phaseDescription = opts.phase === 'prepare'
    ? `signed predecessor ${expectedHeadSequence}`
    : `continuity ${sequences[sequences.length - 2]} -> ${sequences[sequences.length - 1]}`
  addCheck('canary:pin-history-continuity', 'pass', `Pin-history ${phaseDescription} verified: head entry binds the exact frozen asset-manifest, both relay hints, and the pinned release key; history signature verifies.`, {
    sequences,
    headManifestSha256: manifestSha256
  })
}

function verifyCanaryCspOrigins (release) {
  const blueprintPath = join(ROOT, 'render.yaml')
  if (!existsSync(blueprintPath)) throw new Error('render.yaml is missing; the canary CSP check requires the source-managed blueprint')
  const blueprint = readFileSync(blueprintPath, 'utf8')
  const cspMatch = blueprint.match(/name: "Content-Security-Policy"\n {8}value: "([^"]+)"/)
  if (!cspMatch) throw new Error('render.yaml does not pin a Content-Security-Policy header')
  const connectSrc = (cspMatch[1].split(';').map((v) => v.trim()).find((v) => v.startsWith('connect-src ')) || '')
  if (!connectSrc) throw new Error('render.yaml CSP has no connect-src directive')
  const expectedTokens = ['connect-src', '\'self\'', 'hyper:', 'pear:',
    ...release.relayHints.map((hint) => new URL(hint).origin)]
  const actualTokens = connectSrc.split(/\s+/)
  if (JSON.stringify(actualTokens) !== JSON.stringify(expectedTokens)) {
    throw new Error(`render.yaml CSP connect-src is not the exact bounded origin set: ${actualTokens.join(' ')}`)
  }
  if (blueprint.includes('evidence.example')) {
    throw new Error('render.yaml must not add the admission evidence hint to CSP')
  }
  const headerPolicy = JSON.parse(readFileSync(join(ROOT, 'deploy', 'render-security-headers.json'), 'utf8'))
  const headerCsp = headerPolicy.headers?.find((header) =>
    String(header.name).toLowerCase() === 'content-security-policy')?.value
  if (headerCsp !== cspMatch[1] || String(headerCsp).includes('evidence.example')) {
    throw new Error('deploy/render-security-headers.json must byte-match the bounded blueprint CSP')
  }
  addCheck('canary:csp-origins', 'pass', `render.yaml CSP connect-src allows exactly the canary relay hint origins (${release.relayHints.map((hint) => new URL(hint).origin).join(', ')}).`)
}

function verifyCanaryLimitedPublicTestV1 (release, driveKey) {
  addCheck('canary:scope', 'info', `CANARY SCOPE ${CANARY_SCOPE}: verifying the frozen bounded-public-test artifact under the recorded owner decision. This is NOT the GA release gate and never substitutes for it.`)
  const gaBlockers = [...PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS]
  addCheck('canary:ga-gate-status', 'info', `GA product gate (assertPeeritBlindProductReleaseReady) output unchanged: ${gaBlockers.length} product blocker(s) remain OPEN. Each is disclosed below and stays open; none is cleared by this scope.`, {
    gaReleaseReady: gaBlockers.length === 0,
    gaBlockerCount: gaBlockers.length
  })
  for (const blocker of gaBlockers) {
    addCheck(`canary:ga-blocker:${blocker}`, 'info', `DISCLOSED-OPEN (GA blocker, not canary-blocking): ${blocker}`)
  }
  verifyCanaryOwnerDecision(release)
  verifyCanaryPinHistoryContinuity(release, driveKey)
  verifyCanaryCspOrigins(release)
  addCheck('canary:verdict', 'pass', `CANARY ${CANARY_SCOPE} verification complete: frozen artifact, owner decision, pin-history continuity, relay hints and CSP origins all bind; ${gaBlockers.length} GA blockers remain DISCLOSED-OPEN.`)
}

async function main () {
  const raw = readJson(opts.config)
  if (!raw) throw new Error(`${opts.config} is missing or invalid JSON`)
  const release = normalizeConfig(raw)
  report.release = release.transport === 'blind-substrate'
    ? {
        transport: release.transport,
        substrateProfile: release.substrateProfile,
        relayHints: release.relayHints,
        releaseSequence: release.releaseSequence,
        pinnedReleaseKey: release.pinnedReleaseKey,
        legacyDestination: null
      }
    : {
        transport: release.transport,
        relay: release.relay,
        relayBackend: release.relayBackend,
        readonly: release.readonly,
        releaseSequence: release.releaseSequence,
        relayRoster: release.relayRoster,
        relayRosterMirrors: release.relayRosterMirrors,
        pinnedRosterKey: release.pinnedRosterKey,
        pinnedReleaseKey: release.pinnedReleaseKey,
        dhtRelay: release.dhtRelay || null,
        shardRoster: release.shardRoster || null
      }
  validateReleaseConfig(release)
  // This is the official web-release boundary. A profile-only green state must
  // never publish an uncomposed browser/daemon/store product. The canary scope
  // below does NOT weaken or replace it: without --canary-limited-public-test-v1
  // the unchanged GA product gate applies; with it, the frozen canary artifact
  // is verified under the recorded owner decision while every GA blocker stays
  // disclosed-open.
  if (release.transport === 'blind-substrate' && !opts.canaryLimitedPublicTestV1) {
    assertPeeritBlindProductReleaseReady(release)
  }
  const rosterInfo = release.transport === 'blind-substrate' ? null : await prepareRoster(release)
  verifyDocs()
  const driveKey = String(opts.driveKey || loadManifestDriveKey()).toLowerCase()
  report.driveKey = driveKey
  assertDriveKey(driveKey)
  if (release.transport === 'blind-substrate' && opts.canaryLimitedPublicTestV1) {
    verifyCanaryLimitedPublicTestV1(release, driveKey)
  }
  if (opts.phase === 'prepare') {
    const priorSigningRequest = readJson(opts.signingRequest)
    await buildWeb(release, driveKey)
    await verifyWebBundle(release, rosterInfo, driveKey, { requireSignature: false })
    writeSigningRequest(release, driveKey, priorSigningRequest)
  } else {
    // Verification is intentionally build-free. The signing request binds this
    // exact manifest to the build phase; a missing or changed artifact is fatal.
    await verifyWebBundle(release, rosterInfo, driveKey, { requireSignature: true })
    verifySigningRequest(release, driveKey)
  }
}

main().catch((err) => {
  addCheck('web-release:error', 'fail', err.message,
    Array.isArray(err.releaseBlockers)
      ? { releaseBlockers: [...err.releaseBlockers], profileOnlyGateAccepted: false }
      : undefined)
}).finally(() => {
  writeReport()
  process.exit(report.status === 'blocked' ? 1 : 0)
})
