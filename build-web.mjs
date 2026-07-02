// build-web.mjs — produce the peerit.com STATIC web bundle.
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
//   node build-web.mjs --relay https://relay.peerit.com --readonly false \
//     --relay-roster relay-roster.json --relay-roster-key <pubkey> --drive-key <hyperkey>
//   node build-web.mjs --relay same-origin --no-relay-roster
//   PEERIT_WEB_RELEASE_CONFIG=deploy/web-release.json node build-web.mjs

import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SITE_FILES } from './publish.mjs'
import { buildDhtBundle } from './scripts/build-dht-bundle.mjs'
import { normalizeRelayRosterPayload, verifyRelayRoster } from './js/relay-roster.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dir, 'web')
const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null }
const hasArg = (name) => process.argv.includes(name)

const CONFIG_PATH = process.env.PEERIT_WEB_RELEASE_CONFIG || arg('--config') || join('deploy', 'web-release.json')
const releaseConfig = readConfig(CONFIG_PATH)
const RELAY = process.env.PEERIT_RELAY || arg('--relay') || configRelay(releaseConfig) || ''
const READONLY = String(process.env.PEERIT_RELAY_READONLY || arg('--readonly') || configReadonly(releaseConfig))
const DRIVE_KEY = process.env.PEERIT_DRIVE_KEY || arg('--drive-key') || configDriveKey(releaseConfig) || ''
const DHT_RELAY = process.env.PEERIT_DHT_RELAY || arg('--dht-relay') || releaseConfig.dhtRelay || '' // Phase 3 (optional)
// Offline Ed25519 release key: pinned into the bundle so verify.html / mirrors / auditors
// can confirm asset-manifest.sig (produced by scripts/sign-release.mjs) is an authentic
// release the origin could not self-forge. Empty = unsigned dev build (verify.html says so).
const RELEASE_KEY = (process.env.PEERIT_RELEASE_KEY || arg('--release-key') || releaseConfig.pinnedReleaseKey || '').toLowerCase()
const NO_RELAY_ROSTER = hasArg('--no-relay-roster') || process.env.PEERIT_NO_RELAY_ROSTER === '1'
const RELAY_ROSTER = NO_RELAY_ROSTER ? '' : (process.env.PEERIT_RELAY_ROSTER || arg('--relay-roster') || releaseConfig.relayRoster || '')
let RELAY_ROSTER_KEY = NO_RELAY_ROSTER ? '' : (process.env.PEERIT_RELAY_ROSTER_KEY || arg('--relay-roster-key') || releaseConfig.pinnedRosterKey || '')
if (DHT_RELAY) assertDhtRelay(DHT_RELAY)

const sri = (buf) => 'sha384-' + createHash('sha384').update(buf).digest('base64')
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex')
const attr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

let dhtBundle = null
if (DHT_RELAY) dhtBundle = await buildDhtBundle()

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

  const rosterKey = String(roster.signature && roster.signature.key || '').toLowerCase()
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
  const buf = p === 'js/dht-bundle.js' && dhtBundle ? dhtBundle : readFileSync(join(__dir, p))
  files[p] = buf
  manifest[p] = sha256(buf)
  sriMap[p] = sri(buf)
}

// 2. transform index.html: relay meta + SW registration (external, CSP-safe) + SRI
const rosterRelease = await prepareRoster()
const relayRosterMeta = rosterRelease.meta
let html = files['index.html'].toString('utf8')
const head = [
  RELAY ? `<meta name="peerit-relay" content="${attr(RELAY)}">` : '',
  RELAY ? `<meta name="peerit-relay-readonly" content="${attr(READONLY)}">` : '',
  relayRosterMeta ? `<meta name="peerit-relay-roster" content="${attr(relayRosterMeta)}">` : '',
  RELAY_ROSTER_KEY ? `<meta name="peerit-relay-roster-key" content="${attr(RELAY_ROSTER_KEY)}">` : '',
  RELEASE_KEY ? `<meta name="peerit-release-key" content="${attr(RELEASE_KEY)}">` : '',
  DHT_RELAY ? `<meta name="peerit-dht-relay" content="${attr(DHT_RELAY)}">` : '',
  '<script src="sw-register.js"></script>'
].filter(Boolean).join('\n  ')
html = html.replace('</head>', '  ' + head + '\n</head>')
if (DHT_RELAY) html = relaxCspForDht(html, DHT_RELAY)
html = html.replace('<link rel="stylesheet" href="styles.css">', `<link rel="stylesheet" href="styles.css" integrity="${sriMap['styles.css']}" crossorigin="anonymous">`)
html = html.replace('<script type="module" src="js/app.js"></script>', `<script type="module" src="js/app.js" integrity="${sriMap['js/app.js']}" crossorigin="anonymous"></script>`)
files['index.html'] = Buffer.from(html)
manifest['index.html'] = sha256(files['index.html'])

// 3. write the bundle
rmSync(OUT, { recursive: true, force: true })
mkdirSync(join(OUT, 'js'), { recursive: true })
for (const p of SITE_FILES) writeFileSync(join(OUT, p), files[p])
if (files['relay-roster.json']) writeFileSync(join(OUT, 'relay-roster.json'), files['relay-roster.json'])

const swRegister = `if ('serviceWorker' in navigator) {
  // A new deploy changes the bundle hashes -> a new sw.js. The SW skipWaiting()s +
  // clients.claim()s, so it activates immediately, but the page already loaded with
  // the OLD cached assets. Reload ONCE when the new SW takes control so returning
  // visitors actually run the new audited bundle instead of stale code. Guard with
  // hadController so a brand-new visitor (first install) does not reload.
  var hadController = !!navigator.serviceWorker.controller, refreshing = false;
  navigator.serviceWorker.addEventListener('controllerchange', function () {
    if (refreshing || !hadController) return;
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

writeFileSync(join(OUT, 'asset-manifest.json'), JSON.stringify({
  files: manifest,
  driveKey: DRIVE_KEY,
  webRelease: {
    relay: RELAY,
    readonly: READONLY,
    relayRoster: relayRosterMeta,
    relayRosterKey: RELAY_ROSTER_KEY,
    relayRosterSha256: rosterRelease.sha256,
    releaseKey: RELEASE_KEY
  },
  note: 'SHA-256 of every served file. Cross-check driveKey against the published hyper:// drive in PearBrowser. If asset-manifest.sig is present, verify it against releaseKey (see verify.html / js/release-verify.js).'
}, null, 2))

writeFileSync(join(OUT, 'sw.js'), serviceWorker(manifest))
writeFileSync(join(OUT, 'verify.html'), verifyPage(DRIVE_KEY, RELEASE_KEY))

console.log(`[build-web] wrote ${SITE_FILES.length + 4 + (files['relay-roster.json'] ? 1 : 0)} files to web/`)
console.log(`           relay=${RELAY || '(none — local-only)'} readonly=${READONLY} driveKey=${DRIVE_KEY || '(unset)'}`)
console.log(`           relayRoster=${relayRosterMeta || '(none)'} rosterKey=${RELAY_ROSTER_KEY ? RELAY_ROSTER_KEY.slice(0, 12) + '...' : '(unset)'}`)
if (DHT_RELAY) console.log(`           dhtRelay=${DHT_RELAY} dhtBundle=${files['js/dht-bundle.js'].length} bytes`)
if (!RELAY) console.log('           NOTE: no --relay → the bundle loads but stays local-only (gossip-dev) until a relay is configured.')
if (RELAY_ROSTER && !RELAY_ROSTER_KEY) console.log('           NOTE: --relay-roster without --relay-roster-key is ignored by clients (no pinned verification key).')

// ---- generated assets -------------------------------------------------------
function serviceWorker (man) {
  return `// peerit service worker — pins the audited bundle by SHA-256.
// On install it caches every file whose hash matches the manifest (refusing
// mismatches), then serves same-origin GETs cache-first so the app survives the
// origin going offline. Cross-origin relay traffic is never intercepted.
const MANIFEST = ${JSON.stringify(man)};
const CACHE = 'peerit-' + Object.values(MANIFEST).join('').slice(0, 24);
async function sha256hex (buf) {
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
self.addEventListener('install', (e) => e.waitUntil((async () => {
  const cache = await caches.open(CACHE);
  for (const path of Object.keys(MANIFEST)) {
    try {
      const res = await fetch(path, { cache: 'no-store' });
      const buf = await res.clone().arrayBuffer();
      if (await sha256hex(buf) === MANIFEST[path]) await cache.put(path, res);
      else console.warn('[peerit-sw] hash mismatch, refusing to cache', path);
    } catch (err) { console.warn('[peerit-sw] fetch failed', path, err && err.message); }
  }
  self.skipWaiting();
})()));
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
  await self.clients.claim();
})()));
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return; // never touch relay calls
  let path = url.pathname.replace(/^\\//, '');
  if (path === '') path = 'index.html';
  if (!(path in MANIFEST)) return;
  e.respondWith((async () => { const c = await caches.open(CACHE); return (await c.match(path)) || fetch(e.request); })());
});
`
}

function verifyPage (driveKey, releaseKey) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>verify peerit</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.6}code{background:#eee;padding:1px 5px;border-radius:4px;word-break:break-all}table{border-collapse:collapse;margin-top:1rem}td{border:1px solid #ccc;padding:4px 8px;font-size:13px}.ok{color:#0a7d24}.bad{color:#c02436}</style></head><body>
<h1>Verify peerit</h1>
<p>This recomputes the SHA-256 of every file this site served and compares it to <code>asset-manifest.json</code>, then checks the Ed25519 <b>release signature</b> (<code>asset-manifest.sig</code>) against the pinned release key.</p>
<p>Pinned release key: <code>${releaseKey || '(unsigned build — no release key pinned)'}</code><br>Compare this to peerit's published release key from a channel you trust — <b>not</b> from this page. An in-page PASS only proves the bundle is internally consistent; a malicious origin can serve a tampered verify page <em>and</em> a matching bundle, so real assurance is (a) an EXTERNAL check of this key + signature, or (b) opening the <code>hyper://</code> drive in PearBrowser.</p>
<p>Published <code>hyper://</code> drive key: <code>${driveKey || '(set --drive-key at build time)'}</code> — content-addressed; open it in <b>PearBrowser</b> for a trust root the origin does not control.</p>
<div id="out">checking…</div>
<script type="module">
import { verifyReleaseManifest } from './js/release-verify.js';
const sha = async (b) => { const h = await crypto.subtle.digest('SHA-256', b); return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join(''); };
(async () => {
  try {
    const m = await (await fetch('asset-manifest.json', { cache: 'no-store' })).json();
    let rows = '', allok = true;
    for (const [p, want] of Object.entries(m.files)) {
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
        const r = await verifyReleaseManifest({ manifest: m, signature: await sres.json(), expectedKey: expected });
        sigLine = '<p class="ok"><b>Release signature: VALID</b> — signed by ' + r.key.slice(0, 16) + '… (compare to the key above).</p>';
      } catch (e) { sigLine = '<p class="bad"><b>Release signature: INVALID</b> — ' + (e && e.message) + '</p>'; }
    }
    document.getElementById('out').innerHTML = sigLine + '<p class="' + (allok ? 'ok' : 'bad') + '"><b>' + (allok ? 'All files match the manifest.' : 'MISMATCH — served code differs from the manifest.') + '</b></p><table>' + rows + '</table>';
  } catch (e) { document.getElementById('out').textContent = 'verify failed: ' + (e && e.message); }
})();
</script></body></html>`
}

function relaxCspForDht (html, relay) {
  return html.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(")/, (m, before, policy, after) => {
    return before + patchCsp(policy, relay) + after
  })
}

function patchCsp (policy, relay) {
  const dhtSource = cspSourceForWebSocket(relay)
  const out = []
  let sawScript = false
  let sawConnect = false
  for (const raw of policy.split(';')) {
    const part = raw.trim()
    if (!part) continue
    const [name, ...sources] = part.split(/\s+/)
    if (name === 'script-src') {
      sawScript = true
      addSource(sources, "'wasm-unsafe-eval'")
    } else if (name === 'connect-src') {
      sawConnect = true
      addSource(sources, dhtSource)
    }
    out.push([name, ...sources].join(' '))
  }
  if (!sawScript) out.push("script-src 'self' 'wasm-unsafe-eval'")
  if (!sawConnect) out.push("connect-src 'self' " + dhtSource)
  return out.join('; ')
}

function addSource (sources, source) {
  if (source && !sources.includes(source)) sources.push(source)
}

function cspSourceForWebSocket (relay) {
  const url = new URL(relay)
  return `${url.protocol}//${url.host}`
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
