// peerit service worker — pins the audited bundle by SHA-256.
// Installation verifies the complete candidate before touching its cache. The
// cache name binds the complete canonical manifest, so a failed update cannot
// partially overwrite the incumbent release cache.
const MANIFEST = {"index.html":"c9f742768de0a4f0ce3d4120b9ba46b380f78d1b90c05008ef38ec875b10ec81","styles.css":"719335a9a4d8053e9d26def2fb8a95d2289a879fd5afb8258a3485b879e951d3","icon.svg":"7925827f718381ddf887d3c5bea9b5b94e6e80de569d6604e384033767914a1c","js/app.js":"80c78ae70d3f8f71f49a98006e91d2c5be858f4a8526284283840c486e3c88c4","js/blob-store.js":"1a947ca86c25a590a73d8a7808476e4ee659604da1f848d6da57a289392bfbc9","js/box.js":"7d4460772ef79358bc57c7cc7bcb820af1a6aa96638f1a98b44e4d00fd5fe947","js/canon.js":"8488f17f6d6965449325543a1d69f8e12ee08c3c37e49f4f344ff6217deb3e9b","js/crypto.js":"a0640977c3334363fcbb9831d209f444254093cc607afff32addc2447cb7cb68","js/data.js":"935808186d08a04479228d89936b94af57e8879f0440c29069a3c07650e28c04","js/dht-bundle.js":"ef35ec7ce2c46f1a9f75bd04cf311377c7d41ad10cc6c52d36ff571ca68fafd9","js/feed-window.js":"b6507956f71e1c53123aff3282cca5bf5b65da152050a8a9b5615698e1bc0758","js/gossip.js":"1d4e01ef3a93b91ab673e6d603c500a25d81d0a7474fe48929138fe3fd03f574","js/materialized-index.js":"a020f886663f9e543438c716082c5dc31bffa291f25faf7b6ce6a6df482afbc4","js/identity.js":"57a4d7f1a29cd6f7ee420dfeae794b5d486350fd3db2dfcd6bd6bf7869dd9e11","js/identity-export.js":"59551ecaf8cc8ab8bc1f78fec9bf43eedb8bc5595d4963cac054152727ec4fff","js/identity-store.js":"4a351324a4fc139ac3eb706afca31a335327f09ea9a7f1143a998fc09bd0e1ff","js/identity-vault.js":"c03fe780ccdc1e8acb3247a7d3ac69df6a05f042d2368d0a09d54353cf72e141","js/lazy-pool.js":"5a10a72b561201979e38fd8e227d6553052148dcbee04cd9438cc6ccd937d5ff","js/live-refresh.js":"2d31ba39a548f7f9b33223575e5ff21c8e93cc6efe9340b2aa0e083f71168199","js/markdown.js":"2320179053150c2280507270b8834571c96108456970899f24c37cabebeae8de","js/model.js":"dcde1d1a708d65b9c9b2c9b312a68867e527eb25e4d17a8086975370a4ea984c","js/onboarding.js":"1a3ccc0b46283e4b19b9d0707fa293d5135362cb1feba86159d56ecce5fb7be7","js/pear-api.js":"6adce1fff60938824fa5a0642e8198976bd6240580bc32fb6f8e1291ae7dcce7","js/qr.js":"4fceabaa0805cba7e55a89291a2a882030fa7d8381b491670faee09aa755002a","js/prefs.js":"f06781e9b30f4e35c1797f1414f6d718aceedc897e8989804dad3ca37753a108","js/pow.js":"7cae1496462745d7cb8c2e47f6ebff3c58198bcb743681a83f029da3022417e4","js/legacy-v2-pow-allowlist.js":"af3d33272e839513cdaa0a47985ce8092665290677b8b97da6de9ba669614dd3","js/legacy-action-allowlist.js":"455a6e019d8743db1e924a78a715ca0f649716e5c0729e426801d23a765ce41c","js/ranking.js":"3de81e31ee1727104b22f0aaaa365859de40b44f518fa0b57352f3f76da40832","js/reader-bundle.js":"13ef24fe9b7307d24ef12a3c1376c8f7ffe346fd898a25f153e90ffd980b3a5a","js/recovery.js":"60c940b0c6b40ab46b229b4597c47cff4b14d512eeb616a8ad8222b41405f42c","js/relay-pool.js":"8ae2092aecedf9448c41da2e888bd924a2dea14c7b89fdc488687dc320ff2067","js/relay-roster.js":"3593d8be3bb066fe379cec10f06b00f5d5d05b0a0027864aa20cbd060b039d26","js/release-verify.js":"217ae2950e45b8ec1acb7391cfb2dbb40846ef6a3bc468d4a15ebea7dd842d53","js/release-update.js":"82d4dc84e0fec472ef6f63fa71378bc61f39d51a671ce52c80a73fb963a12d9a","js/runtime.js":"97e442c7efcd3070437a710ebf062d67a16fca94aed0fe3f9c3df81d12052ef9","js/seal.js":"6f64ce89aee4c886b01d48231d716eb7704c9c0b314cdbad8660d9017907c3df","js/shard-roster.js":"0542dda755f813cfb515097cbc958a9e788e9f9a4424c447a8441ad9fa2357de","js/sync.js":"ba78158bb385bf95b1e822d4a62fb440bc2e48460c99423be7b46a6ffe7988ac","js/util.js":"efd676eb4769cae61e01105cf903f298d9d66339ba060072700684c5db768c39","js/verify.js":"9a838a0576d52b03c43f793726522e0a6932e82284a5e9e3fc0450610f3400ea","config/shard-roster.public.json":"c52ec812e673f3e032e6e22ec196cdc5623260c501e07f4eb8f363ceb9923bad","seed-snapshot.json":"c6488226fd120959493141012ae289f11c5ec971106b920cf40c555f6683ab0b","relay-roster.json":"ee116d647df5b316e06da184f872c969724ed856712bba8bde775cebb090b551","sw-register.js":"91aa30dc3a73b7297ea2662bad5ed09dbec7f530a47ab4fb925a628b3a03fefc"};
const CACHE = "peerit-0cbe772a24530e3bc3fbbd9695e5313d4b311575de1e781690a71e16ea42095a";
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
  let path = url.pathname.replace(/^\//, '');
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
