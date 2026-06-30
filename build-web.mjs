// build-web.mjs — produce the peerit.com STATIC web bundle (Phase 0/2).
//
// peerit has no build step; this just copies the served files into web/ and adds
// the web-only delivery hardening:
//   - <meta name="peerit-relay"> so a normal browser enters web mode (ignored by
//     PearBrowser, which uses window.pear — so this never affects the P2P build).
//   - SRI (sha384) on the entry module + stylesheet.
//   - a Service Worker (sw.js) that PINS the audited bundle by SHA-256 after first
//     load, so the app survives the origin going down and global JS swaps are
//     detectable. (Per-module imports aren't SRI-checked by the browser, so the
//     SW manifest is the comprehensive integrity pin.)
//   - asset-manifest.json + verify.html so anyone can recompute the hashes and
//     cross-check against the published hyper:// drive key.
//
// Usage:
//   node build-web.mjs --relay https://relay.peerit.com --readonly false \
//     --relay-roster relay-roster.json --relay-roster-key <pubkey> --drive-key <hyperkey>
//   PEERIT_RELAY=... PEERIT_RELAY_ROSTER=... PEERIT_RELAY_ROSTER_KEY=... node build-web.mjs

import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SITE_FILES } from './publish.mjs'

const __dir = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dir, 'web')
const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null }

const RELAY = process.env.PEERIT_RELAY || arg('--relay') || ''
const READONLY = String(process.env.PEERIT_RELAY_READONLY || arg('--readonly') || 'true')
const DRIVE_KEY = process.env.PEERIT_DRIVE_KEY || arg('--drive-key') || ''
const DHT_RELAY = process.env.PEERIT_DHT_RELAY || arg('--dht-relay') || '' // Phase 3 (optional)
const RELAY_ROSTER = process.env.PEERIT_RELAY_ROSTER || arg('--relay-roster') || ''
const RELAY_ROSTER_KEY = process.env.PEERIT_RELAY_ROSTER_KEY || arg('--relay-roster-key') || ''

const sri = (buf) => 'sha384-' + createHash('sha384').update(buf).digest('base64')
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex')
const attr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

// 1. read + hash every served file
const files = {}
const manifest = {}
const sriMap = {}
for (const p of SITE_FILES) {
  const buf = readFileSync(join(__dir, p))
  files[p] = buf
  manifest[p] = sha256(buf)
  sriMap[p] = sri(buf)
}

// 2. transform index.html: relay meta + SW registration (external, CSP-safe) + SRI
let relayRosterMeta = RELAY_ROSTER
if (RELAY_ROSTER) {
  const rosterFile = resolve(__dir, RELAY_ROSTER)
  if (!/^https?:\/\//i.test(RELAY_ROSTER) && existsSync(rosterFile)) {
    files['relay-roster.json'] = readFileSync(rosterFile)
    manifest['relay-roster.json'] = sha256(files['relay-roster.json'])
    relayRosterMeta = 'relay-roster.json'
  }
}
let html = files['index.html'].toString('utf8')
const head = [
  RELAY ? `<meta name="peerit-relay" content="${attr(RELAY)}">` : '',
  RELAY ? `<meta name="peerit-relay-readonly" content="${attr(READONLY)}">` : '',
  relayRosterMeta ? `<meta name="peerit-relay-roster" content="${attr(relayRosterMeta)}">` : '',
  RELAY_ROSTER_KEY ? `<meta name="peerit-relay-roster-key" content="${attr(RELAY_ROSTER_KEY)}">` : '',
  DHT_RELAY ? `<meta name="peerit-dht-relay" content="${attr(DHT_RELAY)}">` : '',
  '<script src="sw-register.js"></script>'
].filter(Boolean).join('\n  ')
html = html.replace('</head>', '  ' + head + '\n</head>')
html = html.replace('<link rel="stylesheet" href="styles.css">', `<link rel="stylesheet" href="styles.css" integrity="${sriMap['styles.css']}" crossorigin="anonymous">`)
html = html.replace('<script type="module" src="js/app.js"></script>', `<script type="module" src="js/app.js" integrity="${sriMap['js/app.js']}" crossorigin="anonymous"></script>`)
files['index.html'] = Buffer.from(html)
manifest['index.html'] = sha256(files['index.html'])

// 3. write the bundle
rmSync(OUT, { recursive: true, force: true })
mkdirSync(join(OUT, 'js'), { recursive: true })
for (const p of SITE_FILES) writeFileSync(join(OUT, p), files[p])
if (files['relay-roster.json']) writeFileSync(join(OUT, 'relay-roster.json'), files['relay-roster.json'])

const swRegister = "if ('serviceWorker' in navigator) { addEventListener('load', function () { navigator.serviceWorker.register('sw.js').catch(function () {}) }) }\n"
writeFileSync(join(OUT, 'sw-register.js'), swRegister)
manifest['sw-register.js'] = sha256(Buffer.from(swRegister))

writeFileSync(join(OUT, 'asset-manifest.json'), JSON.stringify({
  files: manifest,
  driveKey: DRIVE_KEY,
  note: 'SHA-256 of every served file. Cross-check driveKey against the published hyper:// drive in PearBrowser.'
}, null, 2))

writeFileSync(join(OUT, 'sw.js'), serviceWorker(manifest))
writeFileSync(join(OUT, 'verify.html'), verifyPage(DRIVE_KEY))

console.log(`[build-web] wrote ${SITE_FILES.length + 4 + (files['relay-roster.json'] ? 1 : 0)} files to web/`)
console.log(`           relay=${RELAY || '(none — local-only)'} readonly=${READONLY} driveKey=${DRIVE_KEY || '(unset)'}`)
console.log(`           relayRoster=${relayRosterMeta || '(none)'} rosterKey=${RELAY_ROSTER_KEY ? RELAY_ROSTER_KEY.slice(0, 12) + '...' : '(unset)'}`)
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

function verifyPage (driveKey) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>verify peerit</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.6}code{background:#eee;padding:1px 5px;border-radius:4px}table{border-collapse:collapse;margin-top:1rem}td{border:1px solid #ccc;padding:4px 8px;font-size:13px}</style></head><body>
<h1>Verify peerit</h1>
<p>This recomputes the SHA-256 of every file this site served and compares it to <code>asset-manifest.json</code>.</p>
<p>Published <code>hyper://</code> drive key: <code>${driveKey || '(set --drive-key at build time)'}</code> — for full assurance, open that drive in <b>PearBrowser</b> (content-addressed) and confirm it matches. A web origin can serve a tampered verify page, so treat this as a convenience check, not proof against a malicious origin.</p>
<div id="out">checking…</div>
<script>
(async () => {
  const sha = async (b) => { const h = await crypto.subtle.digest('SHA-256', b); return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join(''); };
  try {
    const m = await (await fetch('asset-manifest.json', { cache: 'no-store' })).json();
    let rows = '', allok = true;
    for (const [p, want] of Object.entries(m.files)) {
      const b = await (await fetch(p, { cache: 'no-store' })).arrayBuffer();
      const ok = (await sha(b)) === want; allok = allok && ok;
      rows += '<tr><td>' + p + '</td><td>' + (ok ? 'ok' : 'MISMATCH') + '</td></tr>';
    }
    document.getElementById('out').innerHTML = '<p><b>' + (allok ? 'All files match the manifest.' : 'MISMATCH — served code differs from the manifest.') + '</b></p><table>' + rows + '</table>';
  } catch (e) { document.getElementById('out').textContent = 'verify failed: ' + (e && e.message); }
})();
</script></body></html>`
}
