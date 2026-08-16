// peerit service worker — pins the audited bundle by SHA-256.
// Installation verifies the complete candidate before touching its cache. The
// cache name binds the complete canonical manifest, so a failed update cannot
// partially overwrite the incumbent release cache.
const MANIFEST = {"index.html":"dda952afad534f47ed1f52966d8723f68f6c572b1486930abcfa1f95496c16f3","how-it-works.html":"247435e9d6affd57c2bed9a958b659e0ca01b780f9bdf6597e3463cc6bee68de","styles.css":"b2251701c1ccf936f11b0f3523f7efb2b7f5e20f6e9772354fae1ad8f2bd0276","icon.svg":"7925827f718381ddf887d3c5bea9b5b94e6e80de569d6604e384033767914a1c","js/blob-store.js":"1a947ca86c25a590a73d8a7808476e4ee659604da1f848d6da57a289392bfbc9","js/box.js":"7d4460772ef79358bc57c7cc7bcb820af1a6aa96638f1a98b44e4d00fd5fe947","js/canon.js":"b3e7f8841771675e0ef2bba59d65a217e46e081669ad36bea9fa6a3f45922599","js/crypto.js":"123309fe38d0523ee348d8cf3f744223484ee51d868b6bae4076da20e4be66cc","js/data.js":"82cdcc8f1a8c4bcbbd63710d3834ffa0c4b188e6f9603a82fa3b8dfccb115031","js/feed-algorithms.js":"edbed245e71ef38ca1679d798eaa1b0b4f323f9a99bee9e91cbd5c49867c4b38","js/feed-window.js":"b6507956f71e1c53123aff3282cca5bf5b65da152050a8a9b5615698e1bc0758","js/identity-primitives.js":"72f3582440200ef309b42b7fa1bcc148b88fbbb5079ebfd32f475bbc0fe509c1","js/identity-store.js":"6706cd067729cc14581b1d12fb26a50105c2e442fbf875ff0a5e08934d52e12a","js/materialized-index.js":"4fef790535311849e6b752e94adaacd7428b3b86277b6b9bc9bb42f4c0ee1e55","js/model.js":"cd124e144fe5114063bce8f089a3e85866b7a9e371bdb38290da10342a4334a4","js/moderation.js":"c98f85fc70e12ed05d7a38e9fbcd7f512ce079d657a2de915907893dacad4c23","js/pow-current.js":"ea966e39ec3313adbe31f08439c7f1ccd382973d63ae7729f2cd1515d7fed580","js/ranking.js":"e1d2ea845afd84a1b0f1d4163bf7a2f5b417a223cb9a03b1de26288994eb88df","js/recovery.js":"60c940b0c6b40ab46b229b4597c47cff4b14d512eeb616a8ad8222b41405f42c","js/release-verify.js":"217ae2950e45b8ec1acb7391cfb2dbb40846ef6a3bc468d4a15ebea7dd842d53","js/seal.js":"6f64ce89aee4c886b01d48231d716eb7704c9c0b314cdbad8660d9017907c3df","js/util.js":"efd676eb4769cae61e01105cf903f298d9d66339ba060072700684c5db768c39","js/verify.js":"9a838a0576d52b03c43f793726522e0a6932e82284a5e9e3fc0450610f3400ea","js/substrate/app-entry.js":"ee20c356faa025bec1f28dbdddf8e0bc4867cf7c26b08cecc98b69a0a45a3a07","js/substrate/availability-policy.mjs":"0f72108d1adbab87a1c96b2c9f3b5e902ff85aade7daa0a30d4fb574ca7ec26e","js/substrate/author-bind-inner-envelope-policy.mjs":"559b7c91d96458e295821dac8a2f7efaafe3b1bbb4c6f19d50e98a214f1e12f1","js/substrate/blind-client-browser-verifier.mjs":"2e9bb6524532092abeedd5b657622466df8494154a1dcb09e834a03d816bf17a","js/substrate/blind-client-relay.js":"c583d9429e031bbc6cc92068049210a56f04da98e5b9dc1751877829ba29dc24","js/substrate/browser-runtime-authority.mjs":"6fb711fd948a23301f61c3e3f1c375bc3e0378aad2bb6862914f55cb5cfb53f6","js/substrate/capability-vault.js":"82aa9c629fccfd66b2e89b0172c509d0b2a5efb742e160ca3aa6a841fdf39f5d","js/substrate/cold-reader.mjs":"de3fbcc4efec3049975e8cf4eef86b4e08afbbd317baca47772ae8a748180c5e","js/substrate/inbox-discovery.mjs":"dd000ab44f74e90fc9b050565cc3b37c35a25d5b4ce36c68f3e956795fe5c6eb","js/substrate/inbox-pointer-frame-v1.mjs":"352c16e1ed58015af13fe9c0b33035554559cee215cb8847fe9bfa1f549f7e0d","js/substrate/inbox-pointer-publish.mjs":"cd0bc64bb9ba26d958eecaae538ee1447ec68b0960082168463d3c01e60fb7da","js/substrate/inbox-read-result-decode.mjs":"448871b6106507f665c0b3ae9519dea7e97039e0027712dc9adb6d1830b95393","js/substrate/inbox-topic-v1.mjs":"2e52befcdc19c63ca8605f8a1c714573321d05ec95ab5341305e6fcc65cdc136","js/substrate/public-inbox-boot-coordinator.mjs":"e553fe253a082168e5258918e1608659a1c1572d713f6f6ba4c2d1b7af8690d0","js/substrate/seq29-public-inbox-sync.mjs":"0b23350c4d871d64a3d1ce2b0539e9d730b884500131087ec16fd9c54728a1e8","js/substrate/descriptor-trust-backend.js":"f20428b40970dd1e31afb35c0ebbe34543a070f3bd1cf4f93dc7260331471258","js/substrate/local-identity.js":"48d57cd8f6821203c4b7ec54a41f51509d699df02d91e8318b0fc1a7267fb31c","js/substrate/legacy-rk-posture.mjs":"c8e7e9bae1bcdd67971fa831124e57b0042e1a60c9e914e65a7e21b017825208","js/substrate/limited-cell-get-profile.mjs":"276f542f176ea4ccefaead252597dc1ccc2bc956b5e41a8642f11b681ce68fc6","js/substrate/limited-cell-put-profile.mjs":"9ba720c88fd4b3b71d8afede6f868440d5f83f513c4b4037250479ff8dbf8548","js/substrate/portable-pin-history.mjs":"5982d5153efb5b7be91d4ce82804708f4f480f8f9cf7cb9d68443d9dfa024d32","js/substrate/production-release-binding.mjs":"f2a39fc811c59096a14b85c645e69fb6a47ecdf434c940ae3b46a280653c0512","js/substrate/service-worker-trust-inputs.mjs":"e68dbd2ab15b4c33c6a76c968877b0b1fc8575e5f1419828cb965d2b667dbad5","js/substrate/peerit-recovery-bundle-v1.mjs":"41ab0d2eee5f1197d8d5258c437862ce71402beb6557460e39b4a1675dbe18cb","js/substrate/peerit-journal-backend.js":"de48279f7ee8e2eef5f60559c1415aada276e2d6c6373620403c171c30aaac90","js/substrate/peerit-journal.js":"6a417d749b3bec0cfe69828e48d195c257c7be70b3cdffc76c3524fcedc57e2c","js/substrate/peerit-operation-authority-v1.js":"fae7940063a907042f8ae21754089170fb9f8c68400e86e3804a4c641258f9bf","js/substrate/peerit-product-runtime.js":"26a2ec0d9ce6bfa4b476403fecbea8777fbaba648af7213360f64b3ccb758a11","js/substrate/peerit-product-ui.js":"9e852a0fc8d8bb9b37c5fe2ce2ebaa1fc477c70e5c58dee27225952f67552824","js/substrate/peerit-substrate-sync.js":"d2aadb8e1f414587284ab07db2f455a15e30ae39e05d2bfb78ca82246da0586f","js/substrate/pin-history-bootstrap.mjs":"66cef66075743fd1d4eab94ddaa45da0f6f3ee186521b58689d91e40e2ee1e14","js/substrate/pin-history-witness-backend.mjs":"f7428ed50126c419c805c4aa49c818e0b9be5af00172f356489e22d8a00a0605","js/substrate/production-release-authority.mjs":"a2f4128daeace46a174f82fe4c830f97cec882d291dca062a5fb791819ff727b","js/substrate/pow-issuance-spend-provider.mjs":"870f1eca1971e663fe039d78563977cfeeb14a50d9e724ba016fce0ad3f0011a","js/substrate/profile-artifact-codec.mjs":"9dd99779eaa8189316a051d78e946295d2a01ac37db2e2e69f41a6a850cf4b46","js/substrate/profile-codec-ir.mjs":"a521429f4ed1ae60b57fdecc2536e207dcb3f6b20cb4fd5391aebe07a8dbc824","js/substrate/profile-external-authority.mjs":"be5593361de52730b56812ece09107a86dfdbabddf83f5b2e523c2644db7277f","js/substrate/profile-inventory-scan.mjs":"7758fead2380f0eb0938358443216323ad5adcedddef37ae8febeca7e82ce214","js/substrate/profile-inventory.mjs":"c2b5ebb36c257987596798773e9ea31bc62037210041235ee06a5458b610d84a","js/substrate/profile-status.mjs":"16064a00635057334a295b85e16e6d5cd9d39a979c72d6059e1741ef227ce479","js/substrate/publication-status.js":"1005a7ea3514e8b1464747e5044b9b37cefc51d5d66df27c91af913d192a05c1","js/substrate/relay-consumer.js":"77167b5b41b2a196ebd9ac4c09e6a8fa0900c393ed56c4caf59fbd6fec1f61d9","js/substrate/relay-requalification-scheduler.js":"c3287f21717ac466549a8da198ab844d73160afe74160a1899dbdab0f6241f02","js/substrate/remote-record-ingest.mjs":"7c56b4627210e333e2fa76660c81e483326d8e297fdf15d5451b684e74aa9d03","js/substrate/release-coherence.js":"951e443a07b64cdf56cfe38577779a606fa0b1be4109f5ed95ccffd23ffeb636","js/substrate/release-relay-hints.mjs":"7de8ca170e38b0513554f015cfb6ef26b6c68fa7c9e023904f494a91f354e612","js/substrate/release-authority-transition.mjs":"56369b0030b97d47ffe501b7cb0468508eb23c1412a3f633b7f6dc1737cf674b","js/substrate/release-control-codec.mjs":"79d26bcc5b16576d9804aa532e89cbfd1fdbbc062d8d354cf7d98382d56a478e","js/substrate/release-control-primitives.mjs":"9abe800f93a268cc280574e4f34c10329095d55bbfee8379aac685ad966b8727","js/substrate/release-control-registry.mjs":"104c70e38b821a371fc2e0eb85c285be8b3df1a2a523178c0ccdfc86cf2f2294","js/substrate/release-control-verifier.mjs":"b90da65ce43a60a59d551eb7ccc2015e8af75641912c1e811cc26961b1e6c30e","js/substrate/seed-bootstrap-v1.mjs":"2e3458b13ffac8238fcd2e44e385e0c7f56706237a99a229d2d4adbd961cb6d6","js/substrate/validator-artifact.mjs":"14d792422c8b8937f281ab5e0ed35792aaab402493940f5fa43982279e248971","js/substrate/web-asset-manifest.mjs":"e873085145d25cfee26950f6703c2f4f2bcb7c19f04d79919848ecfb2740097e","js/vendor/noble-hashes/sha2.js":"0fb8e3c3f2c73a890be2524ac5d2542aaed4decff69e561231a86131203b3973","js/vendor/noble-hashes/_md.js":"8227b9b5cabf078a9d7f7317f7a1ace6e46627539aa9364667aec724e1636f14","js/vendor/noble-hashes/_u64.js":"766b91a693a798f9d3cde97b25db4a6d0cef66b2ca21153d3d42424d37878870","js/vendor/noble-hashes/utils.js":"e2adfc13c846487feff0410bd5508a1d66f5ebadc3188f3a40a6b55449981e2f","js/vendor/noble-ciphers/chacha.js":"ad0a9595ab6c083500fbb81c5ea14af4b79f57aa9b1a56b2d3ad738918865a9e","js/vendor/noble-ciphers/_arx.js":"d4c0112267f8b6f7d4de238edf87b19e60e373aa438c5400ebf189ed1e42f95c","js/vendor/noble-ciphers/_poly1305.js":"9c7e5aaa972f03d8ca7fe3aa41340b6d4d1ee1228d414634e25e1beb539ac69f","js/vendor/noble-ciphers/utils.js":"306e36d8c59519a289756f5775e2fc2faed9b02b6b60029a7c8e3e943522e441","js/vendor/noble-ciphers/LICENSE":"f36671a5487c9c5050efacb58011c37c24c55a889803cb036cf9d9a6347c1e2d","docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md":"74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd","protocol/peerit-profile-v1.cenc":"abfbbd0282497f06a78ed675750806c320003bcfe70708a92bdc5a4be642ff28","protocol/vectors/peerit-profile-v1.manifest.cenc":"f820e853a5644c45829eaec8a9c5f53e8602d44fb8b3d540b542d07d1a191f08","protocol/validator/peerit-validator-v1.bare.mjs":"66676fddb0c973dececaf78d4a070d76afb2febf78f967a7f83e57c6fba67628","protocol/validator/peerit-validator-v1.manifest.cenc":"c62063e33a037c58770d66116e34226512880246b9bf03752bcb264539558e17","protocol/availability-policy-v1.cenc":"3d5bcc0547a28779fa30673bff1fbb0b5e15f6b75d56ddcab67b5b7f645645a1","protocol/external-authority/hiverelay-blind-wire-v1.md":"635d482de553aa9ada1c43aa3f8d858a9a5d8425eb748526a0c1c70725e91716","protocol/external-authority/hiverelay-blind-abi-v1.cenc":"19f4d42dea804351a281222fe61c96f5dfaf2d45e4547c76b4e443376277556b","protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc":"8eb7b48422efa366ae414aac3a8bb0c1a753b7dd04fb6e257e1e7aa4cefdd4cc","protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc":"a525dc297bf8771ecb7a9204b5b3c031bd292991b210421f3fa713619e296b60","protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc":"b26ab9a86ccd665255ee17dd742ffc39acceeb670bc01a7f7633460cb9d7cee9","protocol/vectors/peerit-recovery-contract-v2.manifest.json":"5ec246ffa6ee0c2126193e29c4cc64146f77764ec02044bc3fc8b6930b26fb25","peerit-limited-cell-get-profile-v1.json":"6756fa789aa794a3875970f5e5912981c1597f14d16dfa4a79d6dbf539362224","peerit-limited-cell-put-profile-v1.json":"f809a8678b94198324dc0c231f10c677269578aded83a257b2bc58db2f1720f9","vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs":"88e51864c4a21296e64864523a7d602a1df6e24beed7dbbed45690c05eb1902f","vendor/hiverelay-blind-client-v1/blind-client-control-v1.manifest.cenc":"454fb9af836e5fd4e59e0a7c45a02dba1b657b5ceba8a2807ebb656ed58b096f","vendor/hiverelay-blind-client-v1/blind-client-control-v1.chromium-evidence.json":"29ed42c71a83b0c3a7c5a1bfb366e0606fe349ea3a6c8fe7d9e9624c51b9b2c0","vendor/hiverelay-blind-client-v1/blind-client-control-v1.cross-host-evidence.json":"5d5bfa8c0d1be2256ff328af6836d120bd4015f975dfed7a1e463b80d27e34cc","vendor/hiverelay-blind-client-v1/authority.json":"85909a01ac34e5fc374a81a7bc9a95c8b36f96665b6d04e0bf67d6c437017260","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs":"c4de3329a35ee0a6514cabfa8763e1217f6ab1fc5650ca794db5e3b9b17a6ebc","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.manifest.cenc":"94d95bbc2cf2a779562eb8ce4a6207a1354238c8e5f5453fbf2e742687180e12","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.chromium-evidence.json":"83be7a5e096e3104ca278417d8691a47894774e5fc4a3c59b7079139f1bed9e0","vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.cross-host-evidence.json":"727f4cc3fc9d12411fec104db37593b7ea0a33e8954fc28346f9b5ab6b6fa642","vendor/hiverelay-blind-cell-get-v1/authority.json":"ef86070386af789a598805a0218c173963dc3d3a716e5fa3d8f409103372a782","peerit-seed-bootstrap-v1.json":"8eb0c977b84e26c726092bb2ed8de4f531b06d2b0a158bb31d0313dacd07ada1","peerit-limited-public-inbox-bootstrap-v1.json":"03ed9005dced4957f9763087dcd1e000579562ea873a95a5b78734babca6839d","sw-register.js":"aca6bb8cccf12aa754e24c6fe7fbf74cb087d2209e723d01f939b596225540ea","peerit-app-artifact-v1.json":"87cac5da0b2b95dbc18cd84db53dff879b00da96866ad6630d62bf877d404590","peerit-web-assets-v1.cenc":"ece81483d89d7972b9a6032d46f92410aff804f07d29415d051c774d722821f0","peerit-production-pin-history-v1.cenc":"911962b7f8f05bc9181074d7598fc8bcc3222adaa016969b4d8afb793a21fb2b"};
const CACHE = "peerit-7afce4f86a62605d8cab16b8d998b578eaafd378e7e4380237617b98f42aa7f2";
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
