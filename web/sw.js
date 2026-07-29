// peerit service worker — pins the audited bundle by SHA-256.
// Installation verifies the complete candidate before touching its cache. The
// cache name binds the complete canonical manifest, so a failed update cannot
// partially overwrite the incumbent release cache.
const MANIFEST = {"index.html":"ef7f82df1b964bc4294cc43cef28e184a61ffd0f96c7ee4c3634b49f71771290","styles.css":"a1415e011f39383f0365ed06493ad37249b65fd45c59eaaec3f8f0865c7ae051","icon.svg":"7925827f718381ddf887d3c5bea9b5b94e6e80de569d6604e384033767914a1c","js/blob-store.js":"1a947ca86c25a590a73d8a7808476e4ee659604da1f848d6da57a289392bfbc9","js/box.js":"7d4460772ef79358bc57c7cc7bcb820af1a6aa96638f1a98b44e4d00fd5fe947","js/canon.js":"b3e7f8841771675e0ef2bba59d65a217e46e081669ad36bea9fa6a3f45922599","js/crypto.js":"123309fe38d0523ee348d8cf3f744223484ee51d868b6bae4076da20e4be66cc","js/data.js":"281d12aa0ff3254d1a5a42f2032d9e23fecaa57493c46a0a85dd4669ed5387e7","js/feed-algorithms.js":"edbed245e71ef38ca1679d798eaa1b0b4f323f9a99bee9e91cbd5c49867c4b38","js/feed-window.js":"b6507956f71e1c53123aff3282cca5bf5b65da152050a8a9b5615698e1bc0758","js/identity-primitives.js":"72f3582440200ef309b42b7fa1bcc148b88fbbb5079ebfd32f475bbc0fe509c1","js/identity-store.js":"6706cd067729cc14581b1d12fb26a50105c2e442fbf875ff0a5e08934d52e12a","js/materialized-index.js":"4fef790535311849e6b752e94adaacd7428b3b86277b6b9bc9bb42f4c0ee1e55","js/model.js":"cd124e144fe5114063bce8f089a3e85866b7a9e371bdb38290da10342a4334a4","js/moderation.js":"c98f85fc70e12ed05d7a38e9fbcd7f512ce079d657a2de915907893dacad4c23","js/pow-current.js":"ea966e39ec3313adbe31f08439c7f1ccd382973d63ae7729f2cd1515d7fed580","js/ranking.js":"e1d2ea845afd84a1b0f1d4163bf7a2f5b417a223cb9a03b1de26288994eb88df","js/recovery.js":"60c940b0c6b40ab46b229b4597c47cff4b14d512eeb616a8ad8222b41405f42c","js/release-verify.js":"217ae2950e45b8ec1acb7391cfb2dbb40846ef6a3bc468d4a15ebea7dd842d53","js/seal.js":"6f64ce89aee4c886b01d48231d716eb7704c9c0b314cdbad8660d9017907c3df","js/util.js":"efd676eb4769cae61e01105cf903f298d9d66339ba060072700684c5db768c39","js/verify.js":"9a838a0576d52b03c43f793726522e0a6932e82284a5e9e3fc0450610f3400ea","js/substrate/app-entry.js":"f230ddb990de4e0305a06dd9a73423773857f128dd4fd8f13f785a3c0e3418cd","js/substrate/availability-policy.mjs":"0f72108d1adbab87a1c96b2c9f3b5e902ff85aade7daa0a30d4fb574ca7ec26e","js/substrate/author-bind-inner-envelope-policy.mjs":"559b7c91d96458e295821dac8a2f7efaafe3b1bbb4c6f19d50e98a214f1e12f1","js/substrate/blind-client-browser-verifier.mjs":"e1c6a2d478c090b3477ee473366e77c0a0215f5bd2654732f584cb2c8c6856ba","js/substrate/blind-client-relay.js":"c583d9429e031bbc6cc92068049210a56f04da98e5b9dc1751877829ba29dc24","js/substrate/browser-runtime-authority.mjs":"5c3c658d04ef873a2a3417e4ecab8813b4697f048147d78b2500b17200331c5e","js/substrate/capability-vault.js":"82aa9c629fccfd66b2e89b0172c509d0b2a5efb742e160ca3aa6a841fdf39f5d","js/substrate/cold-reader.mjs":"194e4682ecc9ad7ebc2d205283d4c252f0c873cf90fea465094a16b0e71af0b1","js/substrate/descriptor-trust-backend.js":"f20428b40970dd1e31afb35c0ebbe34543a070f3bd1cf4f93dc7260331471258","js/substrate/local-identity.js":"abd5c76078d2547bd1b8e77bdb1d6e521eaf23a92948f91e25cf747ee9c2fbfa","js/substrate/legacy-rk-posture.mjs":"c8e7e9bae1bcdd67971fa831124e57b0042e1a60c9e914e65a7e21b017825208","js/substrate/limited-cell-get-profile.mjs":"5732be98a6de473ccb7c464531a06e3b857f513e033100e69715ddeb346ece22","js/substrate/portable-pin-history.mjs":"5982d5153efb5b7be91d4ce82804708f4f480f8f9cf7cb9d68443d9dfa024d32","js/substrate/production-release-binding.mjs":"f2a39fc811c59096a14b85c645e69fb6a47ecdf434c940ae3b46a280653c0512","js/substrate/service-worker-trust-inputs.mjs":"e68dbd2ab15b4c33c6a76c968877b0b1fc8575e5f1419828cb965d2b667dbad5","js/substrate/peerit-recovery-bundle-v1.mjs":"41ab0d2eee5f1197d8d5258c437862ce71402beb6557460e39b4a1675dbe18cb","js/substrate/peerit-journal-backend.js":"de48279f7ee8e2eef5f60559c1415aada276e2d6c6373620403c171c30aaac90","js/substrate/peerit-journal.js":"a79e3e33bc4f741e3f094af1bf74fd6ac6cd4fb3082c2c3dcd49eb9243c56842","js/substrate/peerit-operation-authority-v1.js":"fae7940063a907042f8ae21754089170fb9f8c68400e86e3804a4c641258f9bf","js/substrate/peerit-product-runtime.js":"a37644be4b4a0ddacef304620881ac5ea17d9eef3a9a736ba0860fd1cb60f752","js/substrate/peerit-product-ui.js":"06560f23bfbc41727b178aba9a1ec6b5174ffdc5d6be71e1e586b386f222b32c","js/substrate/peerit-substrate-sync.js":"cb2f52b1c15d2821b9d0637e3d30a0b87f8952ac3dc1ed0e2c16f33ea2bd675a","js/substrate/pin-history-bootstrap.mjs":"90c4c3459f8c69a9204150392fac7402393080e451189221866ba1983a0c31a1","js/substrate/pin-history-witness-backend.mjs":"f7428ed50126c419c805c4aa49c818e0b9be5af00172f356489e22d8a00a0605","js/substrate/production-release-authority.mjs":"a2f4128daeace46a174f82fe4c830f97cec882d291dca062a5fb791819ff727b","js/substrate/profile-artifact-codec.mjs":"9dd99779eaa8189316a051d78e946295d2a01ac37db2e2e69f41a6a850cf4b46","js/substrate/profile-codec-ir.mjs":"a521429f4ed1ae60b57fdecc2536e207dcb3f6b20cb4fd5391aebe07a8dbc824","js/substrate/profile-external-authority.mjs":"be5593361de52730b56812ece09107a86dfdbabddf83f5b2e523c2644db7277f","js/substrate/profile-inventory-scan.mjs":"7758fead2380f0eb0938358443216323ad5adcedddef37ae8febeca7e82ce214","js/substrate/profile-inventory.mjs":"c2b5ebb36c257987596798773e9ea31bc62037210041235ee06a5458b610d84a","js/substrate/profile-status.mjs":"d48c52a16ca6b3dd4b06e6d4f1f78611cd584bb31b7b433a6e0624069f68f072","js/substrate/publication-status.js":"1005a7ea3514e8b1464747e5044b9b37cefc51d5d66df27c91af913d192a05c1","js/substrate/relay-consumer.js":"70e260a36878751c0fa4b843b3856a61f5ad84044a589361d551ff432b7284f8","js/substrate/relay-requalification-scheduler.js":"c3287f21717ac466549a8da198ab844d73160afe74160a1899dbdab0f6241f02","js/substrate/remote-record-ingest.mjs":"7c56b4627210e333e2fa76660c81e483326d8e297fdf15d5451b684e74aa9d03","js/substrate/release-coherence.js":"c759199a21cf709c883e283b06574c01b75f9d81ea4d14f2943d2f8731b4f9d4","js/substrate/release-relay-hints.mjs":"7de8ca170e38b0513554f015cfb6ef26b6c68fa7c9e023904f494a91f354e612","js/substrate/release-authority-transition.mjs":"56369b0030b97d47ffe501b7cb0468508eb23c1412a3f633b7f6dc1737cf674b","js/substrate/release-control-codec.mjs":"79d26bcc5b16576d9804aa532e89cbfd1fdbbc062d8d354cf7d98382d56a478e","js/substrate/release-control-primitives.mjs":"9abe800f93a268cc280574e4f34c10329095d55bbfee8379aac685ad966b8727","js/substrate/release-control-registry.mjs":"104c70e38b821a371fc2e0eb85c285be8b3df1a2a523178c0ccdfc86cf2f2294","js/substrate/release-control-verifier.mjs":"b90da65ce43a60a59d551eb7ccc2015e8af75641912c1e811cc26961b1e6c30e","js/substrate/seed-bootstrap-v1.mjs":"2e3458b13ffac8238fcd2e44e385e0c7f56706237a99a229d2d4adbd961cb6d6","js/substrate/validator-artifact.mjs":"14d792422c8b8937f281ab5e0ed35792aaab402493940f5fa43982279e248971","js/substrate/web-asset-manifest.mjs":"e873085145d25cfee26950f6703c2f4f2bcb7c19f04d79919848ecfb2740097e","js/vendor/noble-hashes/sha2.js":"0fb8e3c3f2c73a890be2524ac5d2542aaed4decff69e561231a86131203b3973","js/vendor/noble-hashes/_md.js":"8227b9b5cabf078a9d7f7317f7a1ace6e46627539aa9364667aec724e1636f14","js/vendor/noble-hashes/_u64.js":"766b91a693a798f9d3cde97b25db4a6d0cef66b2ca21153d3d42424d37878870","js/vendor/noble-hashes/utils.js":"e2adfc13c846487feff0410bd5508a1d66f5ebadc3188f3a40a6b55449981e2f","docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md":"74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd","protocol/peerit-profile-v1.cenc":"abfbbd0282497f06a78ed675750806c320003bcfe70708a92bdc5a4be642ff28","protocol/vectors/peerit-profile-v1.manifest.cenc":"f820e853a5644c45829eaec8a9c5f53e8602d44fb8b3d540b542d07d1a191f08","protocol/validator/peerit-validator-v1.bare.mjs":"36d35f403460e43c3d595a3adb8011c362ed7a4916e80ee0e1c65e181ad11625","protocol/validator/peerit-validator-v1.manifest.cenc":"c62063e33a037c58770d66116e34226512880246b9bf03752bcb264539558e17","protocol/availability-policy-v1.cenc":"3d5bcc0547a28779fa30673bff1fbb0b5e15f6b75d56ddcab67b5b7f645645a1","protocol/vectors/peerit-recovery-contract-v2.manifest.json":"5ec246ffa6ee0c2126193e29c4cc64146f77764ec02044bc3fc8b6930b26fb25","peerit-limited-cell-get-profile-v1.json":"5388b707dfc3b5ee828db45d033cef67c463a5a3d6e9b99f94cc648f63e2c563","vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs":"dae10d8b71574709e58e67f1fc3f5ed48e9631b98be0ae6c0354cf0024f771c9","vendor/hiverelay-blind-client-v1/blind-client-control-v1.manifest.cenc":"524b46c796fda421e91153e00b2f87df25b999e7cfa4827dc8336faff4b68e17","vendor/hiverelay-blind-client-v1/blind-client-control-v1.chromium-evidence.json":"1382b24b21cae661392a199b0470a22768b85f62215db6fb943ed17b66859c2e","vendor/hiverelay-blind-client-v1/blind-client-control-v1.cross-host-evidence.json":"3cfd3c12a7664899a0901eff7b613f85da6fd039b930f74ade5bc820d215dcd2","vendor/hiverelay-blind-client-v1/authority.json":"502cd2c98a9c5b168b222841b53425d60245c07c950e9cc289a15d919a9e45c2","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs":"653cba3c78d3b26b1e4f06a22fff8a5896a5c5158bc24c8b06ad577196429eed","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.manifest.cenc":"6992ea2f8ab4733aaecdfbb277b818bacb853b8d0141291abcc9386f3342fcc8","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.chromium-evidence.json":"eed7a80c3fc0e4c1f9763f327f0f5960266ce080257c66fc7448be5cb44e1754","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.cross-host-evidence.json":"a0e75066677c13043942f4cd3fce895d821ffc420a3500c150e9730773352470","vendor/hiverelay-blind-cell-get-v1/authority.json":"d3e813f657aa5c121b2b6d5c17df146ba08fbc49fac4878f2938d546d228e795","peerit-seed-bootstrap-v1.json":"7c0ecb964acf17b005e23c06000d5194ab7abeb05164cd7814aaf43182ef4cea","sw-register.js":"aca6bb8cccf12aa754e24c6fe7fbf74cb087d2209e723d01f939b596225540ea","peerit-app-artifact-v1.json":"17705fb2d44de53d1bcef1210fa09bd924c84f69dddf2069a70e394d8ae92881","peerit-web-assets-v1.cenc":"59b85a51cc0b7651c6c0902cf54409741e8e8eaa3e7ff63084d45ea95fb31f1c","peerit-production-pin-history-v1.cenc":"cb51e2ac627e1091bee2c454bc0bbef1ff618c836223a18336b847af81822a8a"};
const CACHE = "peerit-9deccb2e9c42b06f3b1e3d9e30ccbb00c16267f160c330f6d89ab42e93d2b6f1";
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
