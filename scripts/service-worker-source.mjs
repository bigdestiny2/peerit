import { createHash } from 'node:crypto'

// Cache identity must cover every manifest entry, independent of object insertion
// order. A full SHA-256 keeps a changed non-entry module from sharing the active
// cache with the previous release.
export function canonicalAssetManifest (manifest = {}) {
  const sorted = {}
  for (const key of Object.keys(manifest).sort()) sorted[key] = manifest[key]
  return JSON.stringify(sorted)
}

export function serviceWorkerCacheName (manifest = {}) {
  const digest = createHash('sha256').update(canonicalAssetManifest(manifest)).digest('hex')
  return 'peerit-' + digest
}

export function serviceWorkerSource (manifest = {}) {
  const cacheName = serviceWorkerCacheName(manifest)
  return `// peerit service worker — pins the audited bundle by SHA-256.
// Installation verifies the complete candidate before touching its cache. The
// cache name binds the complete canonical manifest, so a failed update cannot
// partially overwrite the incumbent release cache.
const MANIFEST = ${JSON.stringify(manifest)};
const CACHE = ${JSON.stringify(cacheName)};
const ASSETS = Object.keys(MANIFEST).sort();
const RELEASE_METADATA = ['asset-manifest.json', 'asset-manifest.sig'];
const INSTALL_CONCURRENCY = 6;
async function sha256hex (buf) {
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function matchesAssetManifest (candidate) {
  const files = candidate && candidate.files;
  if (!files || typeof files !== 'object' || Array.isArray(files)) return false;
  const keys = Object.keys(MANIFEST);
  if (Object.keys(files).length !== keys.length) return false;
  return keys.every((path) => files[path] === MANIFEST[path]);
}
self.addEventListener('install', (e) => e.waitUntil((async () => {
  // Stage every verified response in memory first. No Cache API mutation occurs
  // unless the complete candidate has fetched and hash-verified successfully.
  // A bounded worker pool avoids the old one-request-at-a-time handover, which
  // left returning mobile visitors on the previous page for many seconds.
  const verified = new Array(ASSETS.length);
  let next = 0;
  async function verifyOne() {
    for (;;) {
      const index = next++;
      if (index >= ASSETS.length) return;
      const path = ASSETS[index];
      const res = await fetch(path, { cache: 'no-store' });
      if (!res.ok) throw new Error('asset fetch failed: ' + path + ' (' + res.status + ')');
      const buf = await res.clone().arrayBuffer();
      if (await sha256hex(buf) !== MANIFEST[path]) throw new Error('asset hash mismatch: ' + path);
      verified[index] = [path, res];
    }
  }
  await Promise.all(Array.from({ length: Math.min(INSTALL_CONCURRENCY, ASSETS.length) }, verifyOne));
  // Keep the manifest/signature pair in the same generation cache. These bytes
  // are not executable and the page verifies their Ed25519 signature before
  // trusting them; structural matching here makes a CDN deploy skew fail the
  // install rather than associating current code with unrelated metadata.
  const metadata = await Promise.all(RELEASE_METADATA.map(async (path) => {
    const res = await fetch(path, { cache: 'no-store' });
    if (!res.ok) throw new Error('release metadata fetch failed: ' + path + ' (' + res.status + ')');
    return [path, res];
  }));
  let metadataManifest;
  try { metadataManifest = await metadata[0][1].clone().json(); } catch { throw new Error('asset-manifest.json is not valid JSON'); }
  if (!matchesAssetManifest(metadataManifest)) throw new Error('asset-manifest.json does not match this service-worker asset set');
  const cache = await caches.open(CACHE);
  for (const [path, res] of verified) await cache.put(path, res);
  for (const [path, res] of metadata) await cache.put(path, res);
  self.skipWaiting();
})().catch((err) => { console.error('[peerit-sw] refusing activation:', err && err.message); throw err; })));
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
  await self.clients.claim();
})()));
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return; // never touch relay calls
  let path = url.pathname.replace(/^\\//, '');
  if (path === '') path = 'index.html';
  if (!(path in MANIFEST) && !RELEASE_METADATA.includes(path)) return;
  e.respondWith((async () => {
    const c = await caches.open(CACHE);
    const cached = await c.match(path);
    if (cached) return cached;
    if (RELEASE_METADATA.includes(path)) return fetch(e.request, { cache: 'no-store' });
    try {
      const res = await fetch(e.request, { cache: 'no-store' });
      if (!res.ok) throw new Error('asset fetch failed (' + res.status + ')');
      const buf = await res.clone().arrayBuffer();
      if (await sha256hex(buf) !== MANIFEST[path]) throw new Error('asset hash mismatch');
      // Preserve the original response/body encoding. The clone is cached only
      // after its decoded bytes match the release manifest.
      await c.put(path, res.clone());
      return res;
    } catch (err) {
      console.error('[peerit-sw] refusing unverified asset', path, err && err.message);
      return new Response('peerit asset integrity check failed', { status: 503, headers: { 'content-type': 'text/plain' } });
    }
  })());
});
`
}
