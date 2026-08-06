// peerit service worker — pins the audited bundle by SHA-256.
// Installation verifies the complete candidate before touching its cache. The
// cache name binds the complete canonical manifest, so a failed update cannot
// partially overwrite the incumbent release cache.
const MANIFEST = {"index.html":"c90fa852ed94732b75087056677f10230cf343d9361ac18c72c26b90e19d7c0f","how-it-works.html":"247435e9d6affd57c2bed9a958b659e0ca01b780f9bdf6597e3463cc6bee68de","styles.css":"b2251701c1ccf936f11b0f3523f7efb2b7f5e20f6e9772354fae1ad8f2bd0276","icon.svg":"7925827f718381ddf887d3c5bea9b5b94e6e80de569d6604e384033767914a1c","js/blob-store.js":"1a947ca86c25a590a73d8a7808476e4ee659604da1f848d6da57a289392bfbc9","js/box.js":"7d4460772ef79358bc57c7cc7bcb820af1a6aa96638f1a98b44e4d00fd5fe947","js/canon.js":"b3e7f8841771675e0ef2bba59d65a217e46e081669ad36bea9fa6a3f45922599","js/crypto.js":"123309fe38d0523ee348d8cf3f744223484ee51d868b6bae4076da20e4be66cc","js/data.js":"281d12aa0ff3254d1a5a42f2032d9e23fecaa57493c46a0a85dd4669ed5387e7","js/feed-algorithms.js":"edbed245e71ef38ca1679d798eaa1b0b4f323f9a99bee9e91cbd5c49867c4b38","js/feed-window.js":"b6507956f71e1c53123aff3282cca5bf5b65da152050a8a9b5615698e1bc0758","js/identity-primitives.js":"72f3582440200ef309b42b7fa1bcc148b88fbbb5079ebfd32f475bbc0fe509c1","js/identity-store.js":"6706cd067729cc14581b1d12fb26a50105c2e442fbf875ff0a5e08934d52e12a","js/materialized-index.js":"4fef790535311849e6b752e94adaacd7428b3b86277b6b9bc9bb42f4c0ee1e55","js/model.js":"cd124e144fe5114063bce8f089a3e85866b7a9e371bdb38290da10342a4334a4","js/moderation.js":"c98f85fc70e12ed05d7a38e9fbcd7f512ce079d657a2de915907893dacad4c23","js/pow-current.js":"ea966e39ec3313adbe31f08439c7f1ccd382973d63ae7729f2cd1515d7fed580","js/ranking.js":"e1d2ea845afd84a1b0f1d4163bf7a2f5b417a223cb9a03b1de26288994eb88df","js/recovery.js":"60c940b0c6b40ab46b229b4597c47cff4b14d512eeb616a8ad8222b41405f42c","js/release-verify.js":"217ae2950e45b8ec1acb7391cfb2dbb40846ef6a3bc468d4a15ebea7dd842d53","js/seal.js":"6f64ce89aee4c886b01d48231d716eb7704c9c0b314cdbad8660d9017907c3df","js/util.js":"efd676eb4769cae61e01105cf903f298d9d66339ba060072700684c5db768c39","js/verify.js":"9a838a0576d52b03c43f793726522e0a6932e82284a5e9e3fc0450610f3400ea","js/substrate/app-entry.js":"f230ddb990de4e0305a06dd9a73423773857f128dd4fd8f13f785a3c0e3418cd","js/substrate/availability-policy.mjs":"0f72108d1adbab87a1c96b2c9f3b5e902ff85aade7daa0a30d4fb574ca7ec26e","js/substrate/author-bind-inner-envelope-policy.mjs":"559b7c91d96458e295821dac8a2f7efaafe3b1bbb4c6f19d50e98a214f1e12f1","js/substrate/blind-client-browser-verifier.mjs":"e1c6a2d478c090b3477ee473366e77c0a0215f5bd2654732f584cb2c8c6856ba","js/substrate/blind-client-relay.js":"c583d9429e031bbc6cc92068049210a56f04da98e5b9dc1751877829ba29dc24","js/substrate/browser-runtime-authority.mjs":"d329ebfb1f14e78e482f320e7c85c0b4088807ffe24b6af64aa65c74035a4559","js/substrate/capability-vault.js":"82aa9c629fccfd66b2e89b0172c509d0b2a5efb742e160ca3aa6a841fdf39f5d","js/substrate/cold-reader.mjs":"de3fbcc4efec3049975e8cf4eef86b4e08afbbd317baca47772ae8a748180c5e","js/substrate/descriptor-trust-backend.js":"f20428b40970dd1e31afb35c0ebbe34543a070f3bd1cf4f93dc7260331471258","js/substrate/local-identity.js":"abd5c76078d2547bd1b8e77bdb1d6e521eaf23a92948f91e25cf747ee9c2fbfa","js/substrate/legacy-rk-posture.mjs":"c8e7e9bae1bcdd67971fa831124e57b0042e1a60c9e914e65a7e21b017825208","js/substrate/limited-cell-get-profile.mjs":"276f542f176ea4ccefaead252597dc1ccc2bc956b5e41a8642f11b681ce68fc6","js/substrate/portable-pin-history.mjs":"5982d5153efb5b7be91d4ce82804708f4f480f8f9cf7cb9d68443d9dfa024d32","js/substrate/production-release-binding.mjs":"f2a39fc811c59096a14b85c645e69fb6a47ecdf434c940ae3b46a280653c0512","js/substrate/service-worker-trust-inputs.mjs":"e68dbd2ab15b4c33c6a76c968877b0b1fc8575e5f1419828cb965d2b667dbad5","js/substrate/peerit-recovery-bundle-v1.mjs":"41ab0d2eee5f1197d8d5258c437862ce71402beb6557460e39b4a1675dbe18cb","js/substrate/peerit-journal-backend.js":"de48279f7ee8e2eef5f60559c1415aada276e2d6c6373620403c171c30aaac90","js/substrate/peerit-journal.js":"a79e3e33bc4f741e3f094af1bf74fd6ac6cd4fb3082c2c3dcd49eb9243c56842","js/substrate/peerit-operation-authority-v1.js":"fae7940063a907042f8ae21754089170fb9f8c68400e86e3804a4c641258f9bf","js/substrate/peerit-product-runtime.js":"a37644be4b4a0ddacef304620881ac5ea17d9eef3a9a736ba0860fd1cb60f752","js/substrate/peerit-product-ui.js":"d4cd76fa2267429c5c63f062bf87523db87869fd2c2c4c9f5e425d69615ea7b7","js/substrate/peerit-substrate-sync.js":"cb2f52b1c15d2821b9d0637e3d30a0b87f8952ac3dc1ed0e2c16f33ea2bd675a","js/substrate/pin-history-bootstrap.mjs":"66cef66075743fd1d4eab94ddaa45da0f6f3ee186521b58689d91e40e2ee1e14","js/substrate/pin-history-witness-backend.mjs":"f7428ed50126c419c805c4aa49c818e0b9be5af00172f356489e22d8a00a0605","js/substrate/production-release-authority.mjs":"a2f4128daeace46a174f82fe4c830f97cec882d291dca062a5fb791819ff727b","js/substrate/profile-artifact-codec.mjs":"9dd99779eaa8189316a051d78e946295d2a01ac37db2e2e69f41a6a850cf4b46","js/substrate/profile-codec-ir.mjs":"a521429f4ed1ae60b57fdecc2536e207dcb3f6b20cb4fd5391aebe07a8dbc824","js/substrate/profile-external-authority.mjs":"be5593361de52730b56812ece09107a86dfdbabddf83f5b2e523c2644db7277f","js/substrate/profile-inventory-scan.mjs":"7758fead2380f0eb0938358443216323ad5adcedddef37ae8febeca7e82ce214","js/substrate/profile-inventory.mjs":"c2b5ebb36c257987596798773e9ea31bc62037210041235ee06a5458b610d84a","js/substrate/profile-status.mjs":"ba76dfa94ffa1ab19fbf6b67365a8f512733178c48e4b638384fa2d50d3c7fcd","js/substrate/publication-status.js":"1005a7ea3514e8b1464747e5044b9b37cefc51d5d66df27c91af913d192a05c1","js/substrate/relay-consumer.js":"6ad9abfd58c9568974ed758f588502074853f7bfb70b79e804b3378cfd7acc11","js/substrate/relay-requalification-scheduler.js":"c3287f21717ac466549a8da198ab844d73160afe74160a1899dbdab0f6241f02","js/substrate/remote-record-ingest.mjs":"7c56b4627210e333e2fa76660c81e483326d8e297fdf15d5451b684e74aa9d03","js/substrate/release-coherence.js":"fc6edb860a59faeaa33bbaee142272a290cdac2d8f5780b91e40f0524afb7dfc","js/substrate/release-relay-hints.mjs":"7de8ca170e38b0513554f015cfb6ef26b6c68fa7c9e023904f494a91f354e612","js/substrate/release-authority-transition.mjs":"56369b0030b97d47ffe501b7cb0468508eb23c1412a3f633b7f6dc1737cf674b","js/substrate/release-control-codec.mjs":"79d26bcc5b16576d9804aa532e89cbfd1fdbbc062d8d354cf7d98382d56a478e","js/substrate/release-control-primitives.mjs":"9abe800f93a268cc280574e4f34c10329095d55bbfee8379aac685ad966b8727","js/substrate/release-control-registry.mjs":"104c70e38b821a371fc2e0eb85c285be8b3df1a2a523178c0ccdfc86cf2f2294","js/substrate/release-control-verifier.mjs":"b90da65ce43a60a59d551eb7ccc2015e8af75641912c1e811cc26961b1e6c30e","js/substrate/seed-bootstrap-v1.mjs":"2e3458b13ffac8238fcd2e44e385e0c7f56706237a99a229d2d4adbd961cb6d6","js/substrate/validator-artifact.mjs":"14d792422c8b8937f281ab5e0ed35792aaab402493940f5fa43982279e248971","js/substrate/web-asset-manifest.mjs":"e873085145d25cfee26950f6703c2f4f2bcb7c19f04d79919848ecfb2740097e","js/vendor/noble-hashes/sha2.js":"0fb8e3c3f2c73a890be2524ac5d2542aaed4decff69e561231a86131203b3973","js/vendor/noble-hashes/_md.js":"8227b9b5cabf078a9d7f7317f7a1ace6e46627539aa9364667aec724e1636f14","js/vendor/noble-hashes/_u64.js":"766b91a693a798f9d3cde97b25db4a6d0cef66b2ca21153d3d42424d37878870","js/vendor/noble-hashes/utils.js":"e2adfc13c846487feff0410bd5508a1d66f5ebadc3188f3a40a6b55449981e2f","docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md":"74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd","protocol/peerit-profile-v1.cenc":"abfbbd0282497f06a78ed675750806c320003bcfe70708a92bdc5a4be642ff28","protocol/vectors/peerit-profile-v1.manifest.cenc":"f820e853a5644c45829eaec8a9c5f53e8602d44fb8b3d540b542d07d1a191f08","protocol/validator/peerit-validator-v1.bare.mjs":"e69bf4554720c853e340f212eda4fe7760ae119594f5f136701a71c1b214a809","protocol/validator/peerit-validator-v1.manifest.cenc":"c62063e33a037c58770d66116e34226512880246b9bf03752bcb264539558e17","protocol/availability-policy-v1.cenc":"3d5bcc0547a28779fa30673bff1fbb0b5e15f6b75d56ddcab67b5b7f645645a1","protocol/vectors/peerit-recovery-contract-v2.manifest.json":"5ec246ffa6ee0c2126193e29c4cc64146f77764ec02044bc3fc8b6930b26fb25","peerit-limited-cell-get-profile-v1.json":"e05fef941c059b943c416c6d0066aa673404d0a134bf205b5bb9d349d5c78d75","vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs":"64e50f14cd58c4279aff99ccff478ec6c6fc2f80e860d2d51602b816b6909bb9","vendor/hiverelay-blind-client-v1/blind-client-control-v1.manifest.cenc":"0c7ec86cfd4e8be31f0691012f4cbc2be8ff94abe1620b3014d31ff770fe398d","vendor/hiverelay-blind-client-v1/blind-client-control-v1.chromium-evidence.json":"85750ce8159a56d6eb74dc81724e48edb445d454d829e356ab6c8c85537ff92f","vendor/hiverelay-blind-client-v1/blind-client-control-v1.cross-host-evidence.json":"8d743be8ae2010df69ae5ceed0215330df6f67ff8731832d715105c6bbe5aa8f","vendor/hiverelay-blind-client-v1/authority.json":"5282ef7e10a58fc04dc3e1bdccc44f3ff6dba7c048b9657f388985d0d9b6fae5","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs":"fd72cef570f825b10b63ec2130b35aca84bbea703cbebe9273e6a5ad4c0d96e3","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.manifest.cenc":"8ec7a1bf30770b7fac3cbe3ba49776115dd0fa09731ea3a49381de0ac55747e5","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.chromium-evidence.json":"706fb2f2596358e1975237d7f4fc47533238affdd4ef39368c0d0c7a99b23d86","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.cross-host-evidence.json":"0c333a48b5cc2c3fe83c856f9c896871d8c25fd932c41f88ebc9785ea2288fe0","vendor/hiverelay-blind-cell-get-v1/authority.json":"2fd6e1906d2ed88fa7de671ec3fa4bf7768e327fe87309f05c5bf6b6d62ee216","peerit-seed-bootstrap-v1.json":"cc7ce9a92967f6fdbec5038a612f996810935394b8c91db31c9c3d53ab25b77b","sw-register.js":"aca6bb8cccf12aa754e24c6fe7fbf74cb087d2209e723d01f939b596225540ea","peerit-app-artifact-v1.json":"9438f750d44fba30b7493be52d8cc1567301e59a4ce2511cb67f4726415a5b89","peerit-web-assets-v1.cenc":"bd3c9438c773a3e48cc5e33f0033a14abe5c20707ba32c2ce5c51b1cc5d8bddd","peerit-production-pin-history-v1.cenc":"1109acdc26310da43af796d79818d4d23b795a4f3afed252b6491282005079e0"};
const CACHE = "peerit-44fe69b61ab865adf929749bdead1499654c5cc9a46f2feba17bc88eb003de55";
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
