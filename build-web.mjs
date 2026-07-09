// build-web.mjs — produce the peerit.site STATIC web bundle.
//
// The default build mostly copies the served files into web/ and adds the
// web-only delivery hardening:
//   - <meta name="peerit-relay"> so a normal browser enters web mode (ignored by
//     PearBrowser, which uses window.pear — so this never affects the P2P build).
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
import { SITE_FILES } from './publish.mjs'
import { buildDhtBundle } from './scripts/build-dht-bundle.mjs'
import { buildReaderBundle } from './scripts/build-reader-bundle.mjs'
import { normalizeRelayRosterPayload, verifyRelayRoster } from './js/relay-roster.js'
import { patchCspForWeb, cspConnectOrigin } from './scripts/csp.mjs'
import { serviceWorkerSource } from './scripts/service-worker-source.mjs'

const __dir = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dir, 'web')
const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null }
const hasArg = (name) => process.argv.includes(name)

const CONFIG_PATH = process.env.PEERIT_WEB_RELEASE_CONFIG || arg('--config') || join('deploy', 'web-release.json')
const releaseConfig = readConfig(CONFIG_PATH)
const RELAY = process.env.PEERIT_RELAY || arg('--relay') || configRelay(releaseConfig) || ''
// Optional, explicit relay backend kind. Purely descriptive/verifiable — it does
// NOT change --relay or the CSP connect-origins (the operator still passes the
// HiveRelay URL as --relay, and csp.mjs already pins that origin). Empty = default
// (behaviour byte-identical to before this flag existed). 'hiverelay-outbox' turns
// on a one-shot boot probe of /api/bridge/status (see js/app.js).
const RELAY_BACKEND = String(process.env.PEERIT_RELAY_BACKEND || arg('--relay-backend') || releaseConfig.relayBackend || '')
assertRelayBackend(RELAY_BACKEND)
const READONLY = String(process.env.PEERIT_RELAY_READONLY || arg('--readonly') || configReadonly(releaseConfig))
const DRIVE_KEY = process.env.PEERIT_DRIVE_KEY || arg('--drive-key') || configDriveKey(releaseConfig) || ''
const DHT_RELAY = process.env.PEERIT_DHT_RELAY || arg('--dht-relay') || releaseConfig.dhtRelay || '' // Phase 3 (optional)
// Pinned outboxes: curated launch content joined directly at boot so a fresh visitor
// renders it without waiting on flaky swarm discovery. `appId:inviteKey` pairs, comma
// separated (public READ caps only). From config seedOutboxes:[{appId,inviteKey}].
const SEED_OUTBOXES = process.env.PEERIT_SEED_OUTBOXES || arg('--seed-outboxes') || configSeedOutboxes(releaseConfig) || ''
// Offline Ed25519 release key: pinned into the bundle so verify.html / mirrors / auditors
// can confirm asset-manifest.sig (produced by scripts/sign-release.mjs) is an authentic
// release the origin could not self-forge. Empty = unsigned dev build (verify.html says so).
const RELEASE_KEY = (process.env.PEERIT_RELEASE_KEY || arg('--release-key') || releaseConfig.pinnedReleaseKey || '').toLowerCase()
const RELEASE_SEQUENCE = Number(process.env.PEERIT_RELEASE_SEQUENCE || arg('--release-sequence') || releaseConfig.releaseSequence || 0)
if (RELEASE_KEY && (!Number.isSafeInteger(RELEASE_SEQUENCE) || RELEASE_SEQUENCE < 1)) {
  throw new Error('a signed web build requires --release-sequence to be a positive safe integer')
}
const NO_RELAY_ROSTER = hasArg('--no-relay-roster') || process.env.PEERIT_NO_RELAY_ROSTER === '1'
const RELAY_ROSTER = NO_RELAY_ROSTER ? '' : (process.env.PEERIT_RELAY_ROSTER || arg('--relay-roster') || releaseConfig.relayRoster || '')
let RELAY_ROSTER_KEY = NO_RELAY_ROSTER ? '' : (process.env.PEERIT_RELAY_ROSTER_KEY || arg('--relay-roster-key') || releaseConfig.pinnedRosterKey || '')
const NO_SHARD_ROSTER = hasArg('--no-shard-roster') || process.env.PEERIT_NO_SHARD_ROSTER === '1'
const SHARD_ROSTER = NO_SHARD_ROSTER ? '' : (process.env.PEERIT_SHARD_ROSTER || arg('--shard-roster') || releaseConfig.shardRoster || '')
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
const READER_BUNDLE = hasArg('--reader-bundle') || process.env.PEERIT_READER_BUNDLE === '1' || !!RELAY
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
for (const p of SITE_FILES) {
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
{
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

// 2. transform index.html: relay meta + SW registration (external, CSP-safe) + SRI
const rosterRelease = await prepareRoster()
// Multi-home the roster: same-origin file first, then independent mirror URLs (e.g.
// an IPFS gateway) that serve the SAME signed roster. Each is verified client-side
// against the pinned key, so a mirror can't forge — this only removes the single
// fetch chokepoint. Comma-list via PEERIT_RELAY_ROSTER_MIRRORS / --relay-roster-mirrors.
const ROSTER_MIRRORS = (process.env.PEERIT_RELAY_ROSTER_MIRRORS || arg('--relay-roster-mirrors') || (releaseConfig.relayRosterMirrors || []).join(',') || '')
const relayRosterMeta = [rosterRelease.meta, ...ROSTER_MIRRORS.split(',').map((s) => s.trim())].filter(Boolean).join(',')
let html = files['index.html'].toString('utf8')
// The source shell carries the development shard-roster hint so local builds can
// exercise the reader. A production release with no signed shard cohort must not
// ship that stale placeholder meta: it causes every visitor to fetch an unsigned
// roster and report a false dispersal warning.
html = html.replace(/\s*<meta\s+name="peerit-shard-(?:roster|relays|threshold)"[^>]*>/gi, '')
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
// Pin connect-src to exactly the origins this build talks to (relays, roster
// mirrors, shard cohort, DHT relay) — the source CSP carries NO http:/https:
// wildcard, so a same-origin XSS cannot exfiltrate to an arbitrary host (audit
// PT-BRW-002). Same-origin ("same-origin"/"/") needs no entry ('self' covers it).
const connectOrigins = collectConnectOrigins()
if (connectOrigins.length || DHT_RELAY) {
  html = patchCspForWeb(html, { dhtRelay: DHT_RELAY, connectOrigins })
}
html = html.replace('<link rel="stylesheet" href="styles.css">', `<link rel="stylesheet" href="styles.css" integrity="${sriMap['styles.css']}" crossorigin="anonymous">`)
html = html.replace('<script type="module" src="js/app.js"></script>', `<script type="module" src="js/app.js" integrity="${sriMap['js/app.js']}" crossorigin="anonymous"></script>`)
files['index.html'] = Buffer.from(html)
manifest['index.html'] = sha256(files['index.html'])

// 3. write the bundle
rmSync(OUT, { recursive: true, force: true })
mkdirSync(join(OUT, 'js'), { recursive: true })
for (const p of SITE_FILES) {
  const outPath = join(OUT, p)
  mkdirSync(dirname(outPath), { recursive: true })
  writeFileSync(outPath, files[p])
}
if (files['relay-roster.json']) writeFileSync(join(OUT, 'relay-roster.json'), files['relay-roster.json'])
if (files['seed-snapshot.json']) writeFileSync(join(OUT, 'seed-snapshot.json'), files['seed-snapshot.json'])

const swRegister = `if ('serviceWorker' in navigator) {
  // A new deploy changes the bundle hashes -> a new sw.js. The SW skipWaiting()s +
  // clients.claim()s, so it activates immediately, but the page already loaded with
  // the OLD cached assets. Reload ONCE when the new SW takes control so returning
  // visitors actually run the new audited bundle instead of stale code. Guard with
  // hadController so a brand-new visitor (first install) does not reload.
  // RATE-LIMITED, not once-per-session: the old boolean latch blocked the reload
  // for every deploy AFTER a tab's first, so long-lived tabs silently ran stale
  // builds until a manual refresh. A timestamp latch keeps reload loops harmless
  // (two fighting SW versions reload at most once per 5 minutes instead of
  // pinning the CPU) while every real deploy — always minutes+ apart — applies.
  var hadController = !!navigator.serviceWorker.controller, refreshing = false;
  var LATCH = 'peerit:sw-reloaded-at', WINDOW_MS = 5 * 60 * 1000;
  navigator.serviceWorker.addEventListener('controllerchange', function () {
    if (refreshing || !hadController) return;
    try {
      var last = Number(sessionStorage.getItem(LATCH) || 0);
      if (Date.now() - last < WINDOW_MS) return;
      sessionStorage.setItem(LATCH, String(Date.now()));
    } catch (e) {}
    refreshing = true; location.reload();
  });
  addEventListener('load', function () {
    navigator.serviceWorker.register('sw.js').then(function (reg) {
      if (reg && reg.update) { try { reg.update(); } catch (e) {} } // check for a newer bundle each load
    }).catch(function () {});
  });
}
`
writeFileSync(join(OUT, 'sw-register.js'), swRegister)
manifest['sw-register.js'] = sha256(Buffer.from(swRegister))

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
  webRelease: {
    releaseSequence: RELEASE_SEQUENCE,
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

console.log(`[build-web] wrote ${SITE_FILES.length + 4 + (files['relay-roster.json'] ? 1 : 0)} files to web/`)
console.log(`           relay=${RELAY || '(none — local-only)'} readonly=${READONLY} releaseSequence=${RELEASE_SEQUENCE || '(unsigned)'} driveKey=${DRIVE_KEY || '(unset)'}`)
console.log(`           relayRoster=${relayRosterMeta || '(none)'} rosterKey=${RELAY_ROSTER_KEY ? RELAY_ROSTER_KEY.slice(0, 12) + '...' : '(unset)'}`)
if (DHT_RELAY) console.log(`           dhtRelay=${DHT_RELAY} dhtBundle=${files['js/dht-bundle.js'].length} bytes`)
if (READER_BUNDLE) console.log(`           readerBundle=${files['js/reader-bundle.js'].length} bytes`)
if (SHARD_ROSTER) console.log(`           shardRoster=${SHARD_ROSTER} sha256=${manifest[SHARD_ROSTER]?.slice(0, 12)}...`)
if (!RELAY) console.log('           NOTE: no --relay → the bundle loads but stays local-only (gossip-dev) until a relay is configured.')
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
//   - RELAY (comma-separated failover list) + its roster payload relays
//   - relay-roster mirror URLs (independent hosts serving the same signed roster)
//   - shard cohort relays (BlindShard dispersal/recovery)
// same-origin / relative entries are skipped ('self' already allows them).
function collectConnectOrigins () {
  const origins = new Set()
  const add = (base) => { const o = cspConnectOrigin(base); if (o) origins.add(o) }
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
