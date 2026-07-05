#!/usr/bin/env node
import { spawn } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dedupeRelayList,
  normalizeRelayRosterPayload,
  rosterSigningMessage,
  verifyRelayRoster
} from '../js/relay-roster.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dir, '..')
const DEFAULT_CONFIG = join(ROOT, 'deploy', 'web-release.json')
const DEFAULT_REPORT = join(ROOT, '.deploy', 'last-web-release.json')
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const HEX64 = /^[0-9a-f]{64}$/i

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error([
    'usage: node scripts/web-release.mjs [--no-build] [--drive-key <hex>] [--config deploy/web-release.json]',
    '       PEERIT_ROSTER_SEED=<32-byte-hex-seed> node scripts/web-release.mjs'
  ].join('\n'))
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    build: true,
    config: process.env.PEERIT_WEB_RELEASE_CONFIG || DEFAULT_CONFIG,
    report: process.env.WEB_RELEASE_REPORT || DEFAULT_REPORT,
    driveKey: process.env.PEERIT_DRIVE_KEY || '',
    json: false
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--no-build') opts.build = false
    else if (arg === '--build') opts.build = true
    else if (arg === '--config') opts.config = resolve(ROOT, argv[++i] || '')
    else if (arg === '--report') opts.report = resolve(ROOT, argv[++i] || '')
    else if (arg === '--drive-key') opts.driveKey = argv[++i] || ''
    else if (arg === '--json') opts.json = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  return opts
}

const opts = parseArgs(process.argv.slice(2))
const report = {
  appId: 'peerit',
  mode: opts.build ? 'build' : 'check',
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
  report.status = counts.fail > 0 ? 'blocked' : (counts.warn > 0 ? 'review' : 'ready')
  report.summary = report.status === 'blocked'
    ? `${counts.fail} web release check${counts.fail === 1 ? '' : 's'} failed.`
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
    readonly: (raw.readonly === false || raw.readOnly === false) ? 'false' : 'true',
    relayRoster: raw.relayRoster || 'relay-roster.json',
    pinnedRosterKey: String(raw.pinnedRosterKey || raw.rosterKey || '').trim().toLowerCase(),
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

  const signer = String(roster.signature && roster.signature.key || '').toLowerCase()
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
  return String(manifest && manifest.driveKey || '')
}

function validateReleaseConfig (release) {
  const normalizedBootstrap = dedupeRelayList(release.bootstrapRelays)
  if (!release.bootstrapRelays.length) throw new Error('deploy/web-release.json must configure at least one bootstrap relay')
  if (normalizedBootstrap.length !== release.bootstrapRelays.length) {
    throw new Error('bootstrapRelays must be valid, canonical, and unique relay URLs')
  }
  if (!release.roster.relays.length) throw new Error('deploy/web-release.json roster.relays must include at least one relay')
  addCheck('config:relay', 'pass', `Bootstrap relay list has ${release.bootstrapRelays.length} entr${release.bootstrapRelays.length === 1 ? 'y' : 'ies'}.`, {
    bootstrapRelays: release.bootstrapRelays
  })
  addCheck('config:roster', 'pass', `Roster config has ${release.roster.relays.length} signed relay entr${release.roster.relays.length === 1 ? 'y' : 'ies'}.`, {
    relays: release.roster.relays
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
    '--relay-roster', release.relayRoster,
    '--relay-roster-key', release.pinnedRosterKey,
    '--drive-key', driveKey
  ]
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

function verifyWebBundle (release, rosterInfo, driveKey) {
  const webIndex = join(ROOT, 'web', 'index.html')
  const webManifest = join(ROOT, 'web', 'asset-manifest.json')
  const webRoster = join(ROOT, 'web', 'relay-roster.json')
  const sw = join(ROOT, 'web', 'sw.js')
  const verify = join(ROOT, 'web', 'verify.html')
  for (const file of [webIndex, webManifest, webRoster, sw, verify]) {
    if (!existsSync(file)) throw new Error(`${file} is missing; run npm run build-web`)
  }

  const html = readFileSync(webIndex, 'utf8')
  if (metaContent(html, 'peerit-relay') !== release.relay) throw new Error('web/index.html peerit-relay meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-relay-readonly') !== release.readonly) throw new Error('web/index.html readonly meta does not match deploy/web-release.json')
  if (metaContent(html, 'peerit-relay-roster') !== 'relay-roster.json') throw new Error('web/index.html relay roster meta must point at relay-roster.json')
  if (metaContent(html, 'peerit-relay-roster-key') !== release.pinnedRosterKey) throw new Error('web/index.html pinned roster key does not match deploy/web-release.json')
  if (release.dhtRelay && metaContent(html, 'peerit-dht-relay') !== release.dhtRelay) throw new Error('web/index.html DHT relay meta does not match deploy/web-release.json')
  if (release.shardRoster) {
    if (metaContent(html, 'peerit-shard-roster') !== release.shardRoster) throw new Error('web/index.html shard roster meta does not match deploy/web-release.json')
  }
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
  }

  const assetManifest = readJson(webManifest)
  if (!assetManifest) throw new Error('web/asset-manifest.json is invalid')
  if (assetManifest.driveKey !== driveKey) throw new Error('web/asset-manifest.json driveKey does not match the release drive key')
  if (!assetManifest.files || assetManifest.files['relay-roster.json'] !== rootRosterHash) throw new Error('asset-manifest.json does not pin relay-roster.json hash')
  if (release.shardRoster && assetManifest.files[release.shardRoster] !== shardRosterHash) throw new Error('asset-manifest.json does not pin ' + release.shardRoster)
  if (!assetManifest.webRelease || assetManifest.webRelease.relayRosterKey !== release.pinnedRosterKey) throw new Error('asset-manifest.json webRelease key does not match deploy/web-release.json')
  addCheck('web:asset-manifest', 'pass', 'asset-manifest.json pins the drive key, roster key, and roster hash.', {
    driveKey,
    relayRosterSha256: rootRosterHash
  })

  if (!readFileSync(sw, 'utf8').includes(`"relay-roster.json":"${rootRosterHash}"`)) throw new Error('sw.js does not pin relay-roster.json')
  if (release.shardRoster && !readFileSync(sw, 'utf8').includes(`"${release.shardRoster}":"${shardRosterHash}"`)) throw new Error('sw.js does not pin ' + release.shardRoster)
  if (!readFileSync(verify, 'utf8').includes(driveKey)) throw new Error('verify.html does not include the release drive key')
  addCheck('web:generated-assets', 'pass', 'sw.js and verify.html carry the same release pins.')
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
    readonly: release.readonly,
    relayRoster: release.relayRoster,
    pinnedRosterKey: release.pinnedRosterKey,
    dhtRelay: release.dhtRelay || null,
    shardRoster: release.shardRoster || null
  }
  validateReleaseConfig(release)
  const rosterInfo = await prepareRoster(release)
  verifyDocs()
  const driveKey = String(opts.driveKey || loadManifestDriveKey()).toLowerCase()
  report.driveKey = driveKey
  assertDriveKey(driveKey)
  if (opts.build) await buildWeb(release, driveKey)
  if (opts.build || existsSync(join(ROOT, 'web', 'asset-manifest.json'))) {
    verifyWebBundle(release, rosterInfo, driveKey)
  } else {
    addCheck('web:bundle', 'info', 'web/ was not verified because --no-build was set and no asset manifest exists.')
  }
}

main().catch((err) => {
  addCheck('web-release:error', 'fail', err.message)
}).finally(() => {
  writeReport()
  process.exit(report.status === 'blocked' ? 1 : 0)
})
