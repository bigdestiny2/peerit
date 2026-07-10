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
    '       --prepare builds exactly once and writes deploy/web-signing-request.json',
    '       --verify-only (the default) never builds and requires the returned signature',
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
    json: false
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
  const bootstrapRelays = Array.isArray(raw.bootstrapRelays)
    ? raw.bootstrapRelays.map((v) => String(v).trim()).filter(Boolean)
    : String(raw.relay || '').split(',').map((v) => v.trim()).filter(Boolean)
  return {
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
  const normalizedBootstrap = dedupeRelayList(release.bootstrapRelays)
  if (!release.bootstrapRelays.length) throw new Error('deploy/web-release.json must configure at least one bootstrap relay')
  if (normalizedBootstrap.length !== release.bootstrapRelays.length) {
    throw new Error('bootstrapRelays must be valid, canonical, and unique relay URLs')
  }
  if (!release.roster.relays.length) throw new Error('deploy/web-release.json roster.relays must include at least one relay')
  const signedNetworkQuorum = release.roster && release.roster.networkQuorum
  if (String(release.readonly).toLowerCase() !== 'true' && release.roster.relays.length < 2 && !signedNetworkQuorum) {
    throw new Error('writable public web releases require at least two signed relay failure domains or a signed network-quorum policy; use readonly=true for a single-relay preview')
  }
  addCheck('config:relay', 'pass', `Bootstrap relay list has ${release.bootstrapRelays.length} entr${release.bootstrapRelays.length === 1 ? 'y' : 'ies'}.`, {
    bootstrapRelays: release.bootstrapRelays
  })
  addCheck('config:roster', 'pass', `Roster config has ${release.roster.relays.length} signed relay entr${release.roster.relays.length === 1 ? 'y' : 'ies'}.`, {
    relays: release.roster.relays,
    networkQuorum: signedNetworkQuorum || null
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
  const args = [
    'build-web.mjs',
    '--config', opts.config,
    '--relay', release.relay,
    '--readonly', release.readonly,
    '--release-sequence', String(release.releaseSequence),
    '--relay-roster', release.relayRoster,
    '--relay-roster-key', release.pinnedRosterKey,
    '--drive-key', driveKey
  ]
  if (release.relayBackend) args.push('--relay-backend', release.relayBackend)
  if (release.relayRosterMirrors.length) args.push('--relay-roster-mirrors', release.relayRosterMirrors.join(','))
  if (release.dhtRelay) args.push('--dht-relay', release.dhtRelay)
  if (release.shardRoster) args.push('--shard-roster', release.shardRoster)
  await run('node', args)
  addCheck('build:web', 'pass', 'Built web/ from the signed relay roster release config.')
}

function metaContent (html, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`<meta\\s+name=["']${escaped}["']\\s+content=["']([^"']*)["']`, 'i')
  const match = html.match(re)
  return match ? match[1] : ''
}

function verifyWebBundle (release, rosterInfo, driveKey, { requireSignature = true } = {}) {
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
  const missing = ['npm run web:release', 'deploy/web-release.json', 'relay-roster.json']
    .filter((needle) => !docs.includes(needle))
  if (missing.length) throw new Error(`docs/WEB-DEPLOYMENT.md is missing release-flow references: ${missing.join(', ')}`)
  addCheck('docs:web-release', 'pass', 'WEB-DEPLOYMENT.md documents the web release command and config files.')
}

async function main () {
  const raw = readJson(opts.config)
  if (!raw) throw new Error(`${opts.config} is missing or invalid JSON`)
  const release = normalizeConfig(raw)
  report.release = {
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
  const rosterInfo = await prepareRoster(release)
  verifyDocs()
  const driveKey = String(opts.driveKey || loadManifestDriveKey()).toLowerCase()
  report.driveKey = driveKey
  assertDriveKey(driveKey)
  if (opts.phase === 'prepare') {
    const priorSigningRequest = readJson(opts.signingRequest)
    await buildWeb(release, driveKey)
    verifyWebBundle(release, rosterInfo, driveKey, { requireSignature: false })
    writeSigningRequest(release, driveKey, priorSigningRequest)
  } else {
    // Verification is intentionally build-free. The signing request binds this
    // exact manifest to the build phase; a missing or changed artifact is fatal.
    verifyWebBundle(release, rosterInfo, driveKey, { requireSignature: true })
    verifySigningRequest(release, driveKey)
  }
}

main().catch((err) => {
  addCheck('web-release:error', 'fail', err.message)
}).finally(() => {
  writeReport()
  process.exit(report.status === 'blocked' ? 1 : 0)
})
