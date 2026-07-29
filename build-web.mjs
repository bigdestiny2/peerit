// build-web.mjs — produce the peerit.site STATIC web bundle.
//
// The default build mostly copies the served files into web/ and adds the
// web-only delivery hardening:
//   - <meta name="peerit-substrate"> so Web, Pear, and Bare select the same
//     replacement profile before considering any legacy host bridge.
//   - SRI (sha384) on the entry module + stylesheet.
//   - a Service Worker (sw.js) that PINS the audited bundle by SHA-256 after first
//     load, so the app survives the origin going down and global JS swaps are
//     detectable. (Per-module imports aren't SRI-checked by the browser, so the
//     SW manifest is the comprehensive integrity pin.)
//   - asset-manifest.json + verify.html so anyone can recompute the hashes and
//     cross-check against the published hyper:// drive key.
//   - when --dht-relay is set, a real esbuilt browser DHT transport replaces the
//     checked-in fail-closed js/dht-bundle.js stub in web/.
//
// Usage:
//   node build-web.mjs
//   node build-web.mjs --relay https://relay.peerit.site --readonly false \
//     --relay-roster relay-roster.json --relay-roster-key <pubkey> --drive-key <hyperkey>
//   node build-web.mjs --relay same-origin --no-relay-roster
//   PEERIT_WEB_RELEASE_CONFIG=deploy/web-release.json node build-web.mjs

import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SITE_FILES, SUBSTRATE_SITE_FILES } from './publish.mjs'
import { buildDhtBundle } from './scripts/build-dht-bundle.mjs'
import { buildReaderBundle } from './scripts/build-reader-bundle.mjs'
import { normalizeRelayRosterPayload, verifyRelayRoster } from './js/relay-roster.js'
import { patchCspForWeb, cspConnectOrigin } from './scripts/csp.mjs'
import { serviceWorkerSource } from './scripts/service-worker-source.mjs'
import {
  buildPeeritSubstrateRuntimeArtifactV1,
  peeritServiceWorkerRegisterSourceV1,
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE,
  PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE,
  PEERIT_SEED_BOOTSTRAP_PATH,
  PEERIT_WEB_ASSET_MANIFEST_PATH
} from './scripts/substrate-runtime-artifact.mjs'
import { PEERIT_PRODUCTION_PIN_HISTORY_PATH } from './js/substrate/production-release-authority.mjs'
import { normalizePeeritReleaseRelayHintsV1 } from './js/substrate/release-relay-hints.mjs'
import { verifyPeeritProductionPinHistoryReleaseV1 } from './scripts/production-pin-history-release.mjs'

const __dir = dirname(fileURLToPath(import.meta.url))
const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null }
const hasArg = (name) => process.argv.includes(name)
const OUT = resolve(__dir, arg('--out') || 'web')

const CONFIG_PATH = process.env.PEERIT_WEB_RELEASE_CONFIG || arg('--config') || join('deploy', 'web-release.json')
const releaseConfig = readConfig(CONFIG_PATH)
const SUBSTRATE_PROFILE = String(process.env.PEERIT_SUBSTRATE_PROFILE || arg('--substrate-profile') || releaseConfig.substrateProfile || '')
const SUBSTRATE_RELAY_HINTS = String(process.env.PEERIT_SUBSTRATE_RELAY_HINTS || arg('--substrate-relay-hints') || configSubstrateRelayHints(releaseConfig) || '')
const IS_SUBSTRATE_RELEASE = !!SUBSTRATE_PROFILE
const SUBSTRATE_RELAY_HINT_VALUES = IS_SUBSTRATE_RELEASE
  ? normalizePeeritReleaseRelayHintsV1(
    SUBSTRATE_RELAY_HINTS.split(',').map(value => value.trim()).filter(Boolean),
    'blind-substrate build')
  : []
const PRODUCTION_PIN_HISTORY_BUNDLE = IS_SUBSTRATE_RELEASE
  ? String(releaseConfig.productionPinHistoryBundle || '').trim()
  : ''
if (PRODUCTION_PIN_HISTORY_BUNDLE &&
    PRODUCTION_PIN_HISTORY_BUNDLE !== PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)) {
  throw new Error(`productionPinHistoryBundle must equal ${PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)}`)
}
const PRODUCTION_PIN_HISTORY_BYTES = PRODUCTION_PIN_HISTORY_BUNDLE
  ? readFileSync(join(__dir, PRODUCTION_PIN_HISTORY_BUNDLE))
  : null
const RELEASE_SITE_FILES = IS_SUBSTRATE_RELEASE ? SUBSTRATE_SITE_FILES : SITE_FILES
if (IS_SUBSTRATE_RELEASE) {
  if (SUBSTRATE_PROFILE !== 'blind-v1') throw new Error(`unsupported Peerit substrate profile: ${SUBSTRATE_PROFILE}`)
  const forbiddenConfig = ['relay', 'bootstrapRelays', 'relayBackend', 'readonly', 'readOnly', 'relayRoster', 'relayRosterMirrors', 'pinnedRosterKey', 'roster', 'dhtRelay', 'shardRoster', 'seedOutboxes']
    .filter(key => releaseConfig[key] != null && releaseConfig[key] !== '' && (!Array.isArray(releaseConfig[key]) || releaseConfig[key].length > 0))
  const forbiddenArgs = ['--relay', '--relay-backend', '--readonly', '--relay-roster', '--relay-roster-key', '--dht-relay', '--shard-roster', '--seed-outboxes']
    .filter(hasArg)
  const forbiddenEnv = ['PEERIT_RELAY', 'PEERIT_RELAY_BACKEND', 'PEERIT_RELAY_READONLY', 'PEERIT_RELAY_ROSTER', 'PEERIT_RELAY_ROSTER_KEY', 'PEERIT_DHT_RELAY', 'PEERIT_SHARD_ROSTER', 'PEERIT_SEED_OUTBOXES']
    .filter(key => process.env[key])
  if (forbiddenConfig.length || forbiddenArgs.length || forbiddenEnv.length) {
    throw new Error(`blind-substrate release refuses legacy transport configuration: ${[...forbiddenConfig, ...forbiddenArgs, ...forbiddenEnv].join(', ')}`)
  }
}
// These variables exist only for an explicitly separate compatibility build.
// The official cutover config rejects them instead of silently composing both
// transports or treating an OutboxLog endpoint as a blind-substrate relay.
const RELAY = IS_SUBSTRATE_RELEASE ? '' : (process.env.PEERIT_RELAY || arg('--relay') || configRelay(releaseConfig) || '')
// Optional, explicit relay backend kind. Purely descriptive/verifiable — it does
// NOT change --relay or the CSP connect-origins (the operator still passes the
// HiveRelay URL as --relay, and csp.mjs already pins that origin). Empty = default
// (behaviour byte-identical to before this flag existed). 'hiverelay-outbox' turns
// on a one-shot boot probe of /api/bridge/status (see js/app.js).
const RELAY_BACKEND = IS_SUBSTRATE_RELEASE ? '' : String(process.env.PEERIT_RELAY_BACKEND || arg('--relay-backend') || releaseConfig.relayBackend || '')
assertRelayBackend(RELAY_BACKEND)
const READONLY = IS_SUBSTRATE_RELEASE ? '' : String(process.env.PEERIT_RELAY_READONLY || arg('--readonly') || configReadonly(releaseConfig))
const DRIVE_KEY = process.env.PEERIT_DRIVE_KEY || arg('--drive-key') || configDriveKey(releaseConfig) || ''
const DHT_RELAY = IS_SUBSTRATE_RELEASE ? '' : (process.env.PEERIT_DHT_RELAY || arg('--dht-relay') || releaseConfig.dhtRelay || '') // legacy compatibility only
// Pinned outboxes: curated launch content joined directly at boot so a fresh visitor
// renders it without waiting on flaky swarm discovery. `appId:inviteKey` pairs, comma
// separated (public READ caps only). From config seedOutboxes:[{appId,inviteKey}].
const SEED_OUTBOXES = IS_SUBSTRATE_RELEASE ? '' : (process.env.PEERIT_SEED_OUTBOXES || arg('--seed-outboxes') || configSeedOutboxes(releaseConfig) || '')
// Offline Ed25519 release key: pinned into the bundle so verify.html / mirrors / auditors
// can confirm asset-manifest.sig (produced by scripts/sign-release.mjs) is an authentic
// release the origin could not self-forge. Empty = unsigned dev build (verify.html says so).
const RELEASE_KEY = (process.env.PEERIT_RELEASE_KEY || arg('--release-key') || releaseConfig.pinnedReleaseKey || '').toLowerCase()
const RELEASE_SEQUENCE = Number(process.env.PEERIT_RELEASE_SEQUENCE || arg('--release-sequence') || releaseConfig.releaseSequence || 0)
if (RELEASE_KEY && (!Number.isSafeInteger(RELEASE_SEQUENCE) || RELEASE_SEQUENCE < 1)) {
  throw new Error('a signed web build requires --release-sequence to be a positive safe integer')
}
if (IS_SUBSTRATE_RELEASE && (!Number.isSafeInteger(RELEASE_SEQUENCE) ||
    RELEASE_SEQUENCE < PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE)) {
  throw new Error(`blind-substrate replacement releaseSequence must be at least ${PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE}; sequence 6 belongs to the retired legacy artifact`)
}
const SEED_BOOTSTRAP_BUNDLE = IS_SUBSTRATE_RELEASE
  ? String(releaseConfig.peeritSeedBootstrapBundle || '').trim()
  : ''
const SEED_DISCOVERY_AUTHORITY_PUBLIC_KEY = IS_SUBSTRATE_RELEASE
  ? String(releaseConfig.peeritSeedDiscoveryAuthorityPublicKey || '').trim().toLowerCase()
  : ''
if (IS_SUBSTRATE_RELEASE && RELEASE_SEQUENCE >= PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE &&
    (!SEED_BOOTSTRAP_BUNDLE || !SEED_DISCOVERY_AUTHORITY_PUBLIC_KEY)) {
  throw new Error('sequence-13+ blind-substrate release requires peeritSeedBootstrapBundle and peeritSeedDiscoveryAuthorityPublicKey')
}
if (IS_SUBSTRATE_RELEASE && RELEASE_SEQUENCE < PEERIT_SEED_BOOTSTRAP_MINIMUM_RELEASE_SEQUENCE &&
    (SEED_BOOTSTRAP_BUNDLE || SEED_DISCOVERY_AUTHORITY_PUBLIC_KEY)) {
  throw new Error('Peerit seed bootstrap configuration requires releaseSequence 13 or later')
}
const SEED_BOOTSTRAP_BYTES = SEED_BOOTSTRAP_BUNDLE
  ? readFileSync(resolve(__dir, SEED_BOOTSTRAP_BUNDLE))
  : null
const NO_RELAY_ROSTER = hasArg('--no-relay-roster') || process.env.PEERIT_NO_RELAY_ROSTER === '1'
const RELAY_ROSTER = IS_SUBSTRATE_RELEASE || NO_RELAY_ROSTER ? '' : (process.env.PEERIT_RELAY_ROSTER || arg('--relay-roster') || releaseConfig.relayRoster || '')
let RELAY_ROSTER_KEY = IS_SUBSTRATE_RELEASE || NO_RELAY_ROSTER ? '' : (process.env.PEERIT_RELAY_ROSTER_KEY || arg('--relay-roster-key') || releaseConfig.pinnedRosterKey || '')
const NO_SHARD_ROSTER = hasArg('--no-shard-roster') || process.env.PEERIT_NO_SHARD_ROSTER === '1'
const SHARD_ROSTER = IS_SUBSTRATE_RELEASE || NO_SHARD_ROSTER ? '' : (process.env.PEERIT_SHARD_ROSTER || arg('--shard-roster') || releaseConfig.shardRoster || '')
if (DHT_RELAY) assertDhtRelay(DHT_RELAY)
if (SHARD_ROSTER) assertShardRoster(SHARD_ROSTER)

const sri = (buf) => 'sha384-' + createHash('sha384').update(buf).digest('base64')
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex')
const attr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

let dhtBundle = null
if (DHT_RELAY) dhtBundle = await buildDhtBundle()

// Build the browser reader bundle for dispersed-body recovery whenever we are
// producing a web deployment (RELAY set) or explicitly asked. The bundle is
// loaded dynamically, so it does not block initial page load.
const READER_BUNDLE = !IS_SUBSTRATE_RELEASE &&
  (hasArg('--reader-bundle') || process.env.PEERIT_READER_BUNDLE === '1' || !!RELAY)
let readerBundle = null
if (READER_BUNDLE) readerBundle = await buildReaderBundle({ minify: !hasArg('--no-minify') })

function readConfig (file) {
  const abs = resolve(__dir, file || '')
  if (!existsSync(abs)) return {}
  try {
    return JSON.parse(readFileSync(abs, 'utf8'))
  } catch (err) {
    throw new Error(`could not parse ${file}: ${err.message}`)
  }
}

function configRelay (cfg) {
  if (cfg.relay) return String(cfg.relay)
  if (Array.isArray(cfg.bootstrapRelays)) return cfg.bootstrapRelays.map(String).join(',')
  return ''
}

function configSubstrateRelayHints (cfg) {
  return Array.isArray(cfg.relayHints) ? cfg.relayHints.map(String).join(',') : ''
}

function configReadonly (cfg) {
  if (cfg.readonly !== undefined) return cfg.readonly === false ? 'false' : 'true'
  if (cfg.readOnly !== undefined) return cfg.readOnly === false ? 'false' : 'true'
  return 'true'
}

// seedOutboxes: [{ appId, inviteKey }] -> "appId:inviteKey,appId:inviteKey"
function configSeedOutboxes (cfg) {
  const list = Array.isArray(cfg.seedOutboxes) ? cfg.seedOutboxes : []
  return list.filter(o => o && o.appId && o.inviteKey).map(o => `${o.appId}:${o.inviteKey}`).join(',')
}

function configDriveKey (cfg) {
  if (cfg.driveKey) return String(cfg.driveKey)
  try {
    const manifest = JSON.parse(readFileSync(join(__dir, 'manifest.json'), 'utf8'))
    return String(manifest.driveKey || '')
  } catch {
    return ''
  }
}

function samePayload (a, b) {
  return JSON.stringify(normalizeRelayRosterPayload(a)) === JSON.stringify(normalizeRelayRosterPayload(b))
}

async function prepareRoster () {
  if (!RELAY_ROSTER) {
    if (RELAY_ROSTER_KEY) throw new Error('--relay-roster-key was set without --relay-roster')
    return { meta: '', sha256: '' }
  }

  const rosterFile = resolve(__dir, RELAY_ROSTER)
  if (/^https?:\/\//i.test(RELAY_ROSTER) || !existsSync(rosterFile)) {
    if (!RELAY_ROSTER_KEY) throw new Error('--relay-roster requires --relay-roster-key for remote or missing roster files')
    return { meta: RELAY_ROSTER, sha256: '' }
  }

  const buf = readFileSync(rosterFile)
  let roster
  try {
    roster = JSON.parse(buf.toString('utf8'))
  } catch (err) {
    throw new Error(`relay roster is not valid JSON: ${err.message}`)
  }

  const rosterKey = String((roster.signature && roster.signature.key) || '').toLowerCase()
  if (!RELAY_ROSTER_KEY) RELAY_ROSTER_KEY = rosterKey
  RELAY_ROSTER_KEY = String(RELAY_ROSTER_KEY).toLowerCase()
  if (rosterKey !== RELAY_ROSTER_KEY) throw new Error('relay roster signer does not match the pinned roster key')
  if (releaseConfig.pinnedRosterKey && RELAY_ROSTER_KEY !== String(releaseConfig.pinnedRosterKey).toLowerCase()) {
    throw new Error('relay roster key does not match deploy/web-release.json')
  }
  if (releaseConfig.roster && !samePayload(roster.payload, releaseConfig.roster)) {
    throw new Error('relay roster payload does not match deploy/web-release.json')
  }

  await verifyRelayRoster(roster, { expectedKey: RELAY_ROSTER_KEY })
  files['relay-roster.json'] = buf
  manifest['relay-roster.json'] = sha256(buf)
  return { meta: 'relay-roster.json', sha256: manifest['relay-roster.json'] }
}

// 1. read + hash every served file
const files = {}
const manifest = {}
const sriMap = {}
for (const p of RELEASE_SITE_FILES) {
  let buf
  if (p === 'js/dht-bundle.js' && dhtBundle) buf = dhtBundle
  else if (p === 'js/reader-bundle.js' && readerBundle) buf = readerBundle
  else buf = readFileSync(join(__dir, p))
  files[p] = buf
  manifest[p] = sha256(buf)
  sriMap[p] = sri(buf)
}

// Baked seed snapshot (optional): signed seed rows exported by
// scripts/export-seed-snapshot.mjs so a FIRST-EVER visitor paints real content
// before any relay round-trip. Client-side every row still passes admit()
// (signature/key-binding/PoW), so a stale or tampered snapshot renders nothing
// it shouldn't — it is a floor, not a trust bypass. Hash-pinned like every asset.
if (!IS_SUBSTRATE_RELEASE) {
  const snapPath = join(__dir, 'config', 'seed-snapshot.json')
  if (existsSync(snapPath)) {
    const buf = readFileSync(snapPath)
    try {
      const snap = JSON.parse(buf.toString('utf8'))
      const authors = Array.isArray(snap && snap.authors) ? snap.authors.length : 0
      const rows = (snap.authors || []).reduce((n, a) => n + ((a && a.rows && a.rows.length) || 0), 0)
      files['seed-snapshot.json'] = buf
      manifest['seed-snapshot.json'] = sha256(buf)
      console.log(`[build-web] baked seed snapshot: ${authors} author(s), ${rows} row(s)`)
    } catch (err) {
      throw new Error(`config/seed-snapshot.json is not valid JSON: ${err.message}`)
    }
  }
}

// 2. transform the runtime closure. Blind-substrate Web and Hyper publication
// call the same deterministic builder; the legacy compatibility path stays
// deliberately separate.
const rosterRelease = IS_SUBSTRATE_RELEASE ? { meta: '', sha256: '' } : await prepareRoster()
// Multi-home the roster: same-origin file first, then independent mirror URLs (e.g.
// an IPFS gateway) that serve the SAME signed roster. Each is verified client-side
// against the pinned key, so a mirror can't forge — this only removes the single
// fetch chokepoint. Comma-list via PEERIT_RELAY_ROSTER_MIRRORS / --relay-roster-mirrors.
const ROSTER_MIRRORS = (process.env.PEERIT_RELAY_ROSTER_MIRRORS || arg('--relay-roster-mirrors') || (releaseConfig.relayRosterMirrors || []).join(',') || '')
const relayRosterMeta = [rosterRelease.meta, ...ROSTER_MIRRORS.split(',').map((s) => s.trim())].filter(Boolean).join(',')
const connectOrigins = collectConnectOrigins()
let substrateArtifact = null
if (IS_SUBSTRATE_RELEASE) {
  substrateArtifact = buildPeeritSubstrateRuntimeArtifactV1({
    sourceFiles: files,
    substrateProfile: SUBSTRATE_PROFILE,
    relayHints: SUBSTRATE_RELAY_HINT_VALUES,
    releaseSequence: RELEASE_SEQUENCE,
    releaseKey: RELEASE_KEY,
    productionPinHistoryBytes: PRODUCTION_PIN_HISTORY_BYTES,
    seedBootstrapBytes: SEED_BOOTSTRAP_BYTES,
    seedDiscoveryAuthorityPublicKey: SEED_DISCOVERY_AUTHORITY_PUBLIC_KEY
  })
  if (PRODUCTION_PIN_HISTORY_BYTES) {
    await verifyPeeritProductionPinHistoryReleaseV1({
      bundleBytes: PRODUCTION_PIN_HISTORY_BYTES,
      releaseSequence: RELEASE_SEQUENCE,
      appArtifactHash: substrateArtifact.appArtifactHash,
      webAssetManifestHash: substrateArtifact.webAssetManifestHash
    })
  }
  for (const key of Object.keys(files)) delete files[key]
  for (const key of Object.keys(manifest)) delete manifest[key]
  for (const key of Object.keys(sriMap)) delete sriMap[key]
  for (const [path, bytes] of substrateArtifact.files) {
    files[path] = bytes
    manifest[path] = sha256(bytes)
    sriMap[path] = sri(bytes)
  }
} else {
  let html = files['index.html'].toString('utf8')
  html = html.replace(/\s*<meta\s+name="peerit-shard-(?:roster|relays|threshold)"[^>]*>/gi, '')
  html = html.replace(/\s*<meta\s+name="peerit-(?:relay(?:-[a-z0-9-]+)?|dht-relay|seed-outboxes|substrate(?:-relays)?)"[^>]*>/gi, '')
  const head = [
    RELAY ? `<meta name="peerit-relay" content="${attr(RELAY)}">` : '',
    RELAY && RELAY_BACKEND ? `<meta name="peerit-relay-backend" content="${attr(RELAY_BACKEND)}">` : '',
    RELAY ? `<meta name="peerit-relay-readonly" content="${attr(READONLY)}">` : '',
    relayRosterMeta ? `<meta name="peerit-relay-roster" content="${attr(relayRosterMeta)}">` : '',
    RELAY_ROSTER_KEY ? `<meta name="peerit-relay-roster-key" content="${attr(RELAY_ROSTER_KEY)}">` : '',
    RELEASE_KEY ? `<meta name="peerit-release-key" content="${attr(RELEASE_KEY)}">` : '',
    RELEASE_KEY ? `<meta name="peerit-release-sequence" content="${attr(RELEASE_SEQUENCE)}">` : '',
    DHT_RELAY ? `<meta name="peerit-dht-relay" content="${attr(DHT_RELAY)}">` : '',
    SHARD_ROSTER ? `<meta name="peerit-shard-roster" content="${attr(SHARD_ROSTER)}">` : '',
    SEED_OUTBOXES ? `<meta name="peerit-seed-outboxes" content="${attr(SEED_OUTBOXES)}">` : '',
    '<script src="sw-register.js"></script>'
  ].filter(Boolean).join('\n  ')
  html = html.replace('</head>', '  ' + head + '\n</head>')
  if (connectOrigins.length || DHT_RELAY) {
    html = patchCspForWeb(html, { dhtRelay: DHT_RELAY, connectOrigins })
  }
  html = html.replace('<link rel="stylesheet" href="styles.css">', `<link rel="stylesheet" href="styles.css" integrity="${sriMap['styles.css']}" crossorigin="anonymous">`)
  html = html.replace(/<script\s+type="module"\s+src="js\/(?:app\.js|substrate\/app-entry\.js)"(?:\s+[^>]*)?><\/script>/,
    `<script type="module" src="js/app.js" integrity="${sriMap['js/app.js']}" crossorigin="anonymous"></script>`)
  files['index.html'] = Buffer.from(html)
  manifest['index.html'] = sha256(files['index.html'])
  files['sw-register.js'] = Buffer.from(peeritServiceWorkerRegisterSourceV1())
  manifest['sw-register.js'] = sha256(files['sw-register.js'])
}

// 3. write the bundle
rmSync(OUT, { recursive: true, force: true })
mkdirSync(join(OUT, 'js'), { recursive: true })
for (const p of Object.keys(files)) {
  const outPath = join(OUT, p)
  mkdirSync(dirname(outPath), { recursive: true })
  writeFileSync(outPath, files[p])
}

// Generate control files before the signed manifest. Their source reads the
// manifest at runtime rather than embedding these hashes, so hashing them here
// has no self-reference/circularity. RELEASE_MSG_VERSION v2 signs `controls`.
const swSource = serviceWorkerSource(manifest)
const verifySource = verifyPage(DRIVE_KEY, RELEASE_KEY, RELEASE_SEQUENCE)
const controls = {
  'sw.js': sha256(Buffer.from(swSource)),
  'verify.html': sha256(Buffer.from(verifySource))
}
writeFileSync(join(OUT, 'sw.js'), swSource)
writeFileSync(join(OUT, 'verify.html'), verifySource)

writeFileSync(join(OUT, 'asset-manifest.json'), JSON.stringify({
  releaseSequence: RELEASE_SEQUENCE,
  files: manifest,
  controls,
  driveKey: DRIVE_KEY,
  webRelease: IS_SUBSTRATE_RELEASE
    ? {
        releaseSequence: RELEASE_SEQUENCE,
        transport: 'blind-substrate',
        substrateProfile: SUBSTRATE_PROFILE,
        relayHints: SUBSTRATE_RELAY_HINT_VALUES,
        networkDelivery: 'profile-gated',
        legacyDestination: null,
        productionPinHistory: PRODUCTION_PIN_HISTORY_BYTES
          ? PEERIT_PRODUCTION_PIN_HISTORY_PATH
          : null,
        appArtifact: `/${PEERIT_APP_ARTIFACT_PATH}`,
        appArtifactHash: substrateArtifact.appArtifactHashHex,
        canonicalWebAssetManifest: `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`,
        canonicalWebAssetManifestHash: substrateArtifact.webAssetManifestHashHex,
        ...(substrateArtifact.seedBootstrap
          ? {
              peeritSeedBootstrap: `/${PEERIT_SEED_BOOTSTRAP_PATH}`,
              peeritSeedBootstrapSha256: substrateArtifact.seedBootstrap.sha256,
              peeritSeedDiscoveryAuthorityPublicKey: substrateArtifact.seedBootstrap.authorityPublicKey,
              peeritSeedBootstrapReleaseSequence: substrateArtifact.seedBootstrap.releaseSequence
            }
          : {}),
        releaseKey: RELEASE_KEY
      }
    : {
        releaseSequence: RELEASE_SEQUENCE,
        transport: 'legacy-migration-compatibility',
        relay: RELAY,
        relayBackend: RELAY_BACKEND,
        readonly: READONLY,
        relayRoster: relayRosterMeta,
        relayRosterKey: RELAY_ROSTER_KEY,
        relayRosterSha256: rosterRelease.sha256,
        shardRoster: SHARD_ROSTER,
        shardRosterSha256: SHARD_ROSTER ? manifest[SHARD_ROSTER] : '',
        releaseKey: RELEASE_KEY
      },
  note: 'SHA-256 of every served file. Cross-check driveKey against the published hyper:// drive in PearBrowser. If asset-manifest.sig is present, verify it against releaseKey (see verify.html / js/release-verify.js).'
}, null, 2))

console.log(`[build-web] wrote ${Object.keys(files).length + 3} files to web/`)
console.log(`           transport=${IS_SUBSTRATE_RELEASE ? `blind-substrate/${SUBSTRATE_PROFILE}` : 'legacy-migration-compatibility'} releaseSequence=${RELEASE_SEQUENCE || '(unsigned)'} driveKey=${DRIVE_KEY || '(unset)'}`)
if (IS_SUBSTRATE_RELEASE) console.log(`           relayHints=${SUBSTRATE_RELAY_HINTS || '(none — local queue only until qualified)'}`)
else console.log(`           relay=${RELAY || '(none — local-only)'} readonly=${READONLY} relayRoster=${relayRosterMeta || '(none)'}`)
if (DHT_RELAY) console.log(`           dhtRelay=${DHT_RELAY} dhtBundle=${files['js/dht-bundle.js'].length} bytes`)
if (READER_BUNDLE) console.log(`           readerBundle=${files['js/reader-bundle.js'].length} bytes`)
if (SHARD_ROSTER) console.log(`           shardRoster=${SHARD_ROSTER} sha256=${manifest[SHARD_ROSTER]?.slice(0, 12)}...`)
if (!IS_SUBSTRATE_RELEASE && !RELAY) console.log('           NOTE: no legacy relay → compatibility build stays local-only.')
if (RELAY_ROSTER && !RELAY_ROSTER_KEY) console.log('           NOTE: --relay-roster without --relay-roster-key is ignored by clients (no pinned verification key).')

// ---- generated assets -------------------------------------------------------
function verifyPage (driveKey, releaseKey, releaseSequence) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>verify peerit</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.6}code{background:#eee;padding:1px 5px;border-radius:4px;word-break:break-all}table{border-collapse:collapse;margin-top:1rem}td{border:1px solid #ccc;padding:4px 8px;font-size:13px}.ok{color:#0a7d24}.bad{color:#c02436}</style></head><body>
<h1>Verify peerit</h1>
<p>This recomputes the SHA-256 of every file this site served and compares it to <code>asset-manifest.json</code>, then checks the Ed25519 <b>release signature</b> (<code>asset-manifest.sig</code>) against the pinned release key.</p>
<p>Pinned release key: <code>${releaseKey || '(unsigned build — no release key pinned)'}</code><br>Compare this to peerit's published release key from a channel you trust — <b>not</b> from this page. An in-page PASS only proves the bundle is internally consistent; a malicious origin can serve a tampered verify page <em>and</em> a matching bundle, so real assurance is (a) an EXTERNAL check of this key + signature, or (b) opening the <code>hyper://</code> drive in PearBrowser.</p>
<p>Signed release sequence: <code>${releaseSequence || '(unsigned build)'}</code>. Returning browsers retain a best-effort local floor for this signing key and reject lower sequences or a different signed manifest reusing the same sequence.</p>
<p>Published <code>hyper://</code> drive key: <code>${driveKey || '(set --drive-key at build time)'}</code> — content-addressed; open it in <b>PearBrowser</b> for a trust root the origin does not control.</p>
<div id="out">checking…</div>
<script type="module">
import { verifyReleaseManifest } from './js/release-verify.js';
const sha = async (b) => { const h = await crypto.subtle.digest('SHA-256', b); return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join(''); };
(async () => {
  try {
    const m = await (await fetch('asset-manifest.json', { cache: 'no-store' })).json();
    let rows = '', allok = true;
    for (const [p, want] of Object.entries({ ...(m.files || {}), ...(m.controls || {}) })) {
      const b = await (await fetch(p, { cache: 'no-store' })).arrayBuffer();
      const ok = (await sha(b)) === want; allok = allok && ok;
      rows += '<tr><td>' + p + '</td><td class="' + (ok ? 'ok' : 'bad') + '">' + (ok ? 'ok' : 'MISMATCH') + '</td></tr>';
    }
    let sigLine;
    const expected = ${JSON.stringify(releaseKey || '')} || (m.webRelease && m.webRelease.releaseKey) || '';
    const sres = await fetch('asset-manifest.sig', { cache: 'no-store' });
    if (!sres.ok) sigLine = '<p class="bad"><b>Release signature: UNSIGNED</b> — no asset-manifest.sig (dev build, or the release was not signed with the offline key).</p>';
    else {
      try {
        const r = await verifyReleaseManifest({ manifest: m, signature: await sres.json(), expectedKey: expected, expectedSequence: ${JSON.stringify(releaseSequence || 0)} });
        sigLine = '<p class="ok"><b>Release manifest signature: VALID</b> — sequence ' + r.releaseSequence + ', signed by ' + r.key.slice(0, 16) + '… (compare to the key above). This authenticates the manifest; the table below is the separate served-byte check.</p>';
      } catch (e) { sigLine = '<p class="bad"><b>Release signature: INVALID</b> — ' + (e && e.message) + '</p>'; }
    }
    document.getElementById('out').innerHTML = sigLine + '<p class="' + (allok ? 'ok' : 'bad') + '"><b>' + (allok ? 'All files match the manifest.' : 'MISMATCH — served code differs from the manifest.') + '</b></p><table>' + rows + '</table>';
  } catch (e) { document.getElementById('out').textContent = 'verify failed: ' + (e && e.message); }
})();
</script></body></html>`
}

// Gather every cross-origin endpoint this web build fetches/connects to, so the
// CSP connect-src can be pinned to exactly those origins (no wildcard). Sources:
//   - replacement substrate relay hints (untrusted discovery only)
//   - RELAY (comma-separated failover list) + its roster payload relays
//   - relay-roster mirror URLs (independent hosts serving the same signed roster)
//   - shard cohort relays (BlindShard dispersal/recovery)
// same-origin / relative entries are skipped ('self' already allows them).
function collectConnectOrigins () {
  const origins = new Set()
  const add = (base) => { const o = cspConnectOrigin(base); if (o) origins.add(o) }
  for (const hint of String(SUBSTRATE_RELAY_HINTS || '').split(',')) add(hint.trim())
  for (const r of String(RELAY || '').split(',')) add(r.trim())
  for (const m of ROSTER_MIRRORS.split(',')) add(m.trim())
  // Relay roster payload (the signed set of relays clients may actually reach).
  try {
    if (RELAY_ROSTER) {
      const abs = resolve(__dir, RELAY_ROSTER)
      if (existsSync(abs)) {
        const cfg = JSON.parse(readFileSync(abs, 'utf8'))
        const relays = (cfg && cfg.payload && cfg.payload.relays) || cfg.relays || []
        for (const r of relays) add(typeof r === 'string' ? r : (r && (r.url || r.baseUrl)))
      }
    }
  } catch {}
  // Shard cohort relays.
  try {
    if (SHARD_ROSTER) {
      const abs = resolve(__dir, SHARD_ROSTER)
      if (existsSync(abs)) {
        const cfg = JSON.parse(readFileSync(abs, 'utf8'))
        for (const r of (cfg.relays || [])) add(typeof r === 'string' ? r : (r && (r.baseUrl || r.url)))
      }
    }
  } catch {}
  return [...origins]
}

function assertRelayBackend (kind) {
  const kinds = ['', 'peerit-relay', 'hiverelay-outbox']
  if (!kinds.includes(kind)) {
    throw new Error(`--relay-backend must be one of ${kinds.filter(Boolean).map(k => `'${k}'`).join(', ')} (or unset); got '${kind}'`)
  }
}

function assertDhtRelay (relay) {
  let url
  try {
    url = new URL(relay)
  } catch {
    throw new Error('--dht-relay must be a ws:// or wss:// URL')
  }
  if (url.protocol !== 'ws:' && url.protocol !== 'wss:') {
    throw new Error('--dht-relay must be a ws:// or wss:// URL')
  }
}

function assertShardRoster (rosterPath) {
  const abs = resolve(__dir, rosterPath)
  if (!existsSync(abs)) throw new Error(`--shard-roster file not found: ${rosterPath}`)
  let cfg
  try {
    cfg = JSON.parse(readFileSync(abs, 'utf8'))
  } catch (err) {
    throw new Error(`--shard-roster is not valid JSON (${rosterPath}): ${err.message}`)
  }
  const relays = Array.isArray(cfg.relays) ? cfg.relays : []
  const threshold = Number(cfg.threshold) || 0
  if (relays.length < 3) throw new Error(`--shard-roster must list at least 3 relays for k-of-n dispersal (${rosterPath})`)
  if (!Number.isInteger(threshold) || threshold < 2 || threshold > relays.length) {
    throw new Error(`--shard-roster threshold must satisfy 2 <= threshold <= relays.length (${rosterPath})`)
  }
  const seen = new Set()
  for (let i = 0; i < relays.length; i++) {
    const r = relays[i]
    const url = String(r.url || r.baseUrl || '').trim()
    const pub = String(r.pubkey || r.publicKey || '').trim().toLowerCase()
    if (!url) throw new Error(`--shard-roster relay ${i + 1} missing url/baseUrl (${rosterPath})`)
    if (!/^[0-9a-f]{64}$/.test(pub)) {
      throw new Error(`--shard-roster relay ${i + 1} (${url}) has missing/invalid pubkey. Run deploy/shard-cohort/extract-pubkey.mjs on the host and paste the 64-hex publicKey into ${rosterPath}`)
    }
    if (seen.has(pub)) throw new Error(`--shard-roster relay ${i + 1} (${url}) duplicate pubkey (${rosterPath})`)
    seen.add(pub)
  }
}
