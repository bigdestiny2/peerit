import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join, normalize } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { genKeyPair, ready as cryptoReady } from '../js/crypto.js'
import { createPublishedSiteFilesV1, SUBSTRATE_SITE_FILES } from '../publish.mjs'
import { PEERIT_BROWSER_RUNTIME_ASSET_PATHS } from '../js/substrate/browser-runtime-authority.mjs'
import {
  buildPeeritSubstrateRuntimeArtifactV1,
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_WEB_ASSET_MANIFEST_PATH,
  verifyPeeritSubstrateRuntimeArtifactV1
} from '../scripts/substrate-runtime-artifact.mjs'
import { PEERIT_PRODUCTION_PIN_HISTORY_PATH } from '../js/substrate/production-release-authority.mjs'
import { hashPeeritBootstrapV1 } from '../js/substrate/web-asset-manifest.mjs'
import {
  PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const served = new Set(SUBSTRATE_SITE_FILES)

for (const forbiddenFile of [
  'js/app.js',
  'js/data-dispersal.js',
  'js/legacy-action-allowlist.js',
  'js/legacy-v2-pow-allowlist.js',
  'js/pow.js',
  'js/sync.js',
  'js/gossip.js',
  'js/relay-pool.js',
  'js/lazy-pool.js',
  'js/dht-bundle.js',
  'js/shard-roster.js',
  'test/fixtures/peerit-vnext-journal-fixture.mjs',
  'config/shard-roster.public.json',
  'config/seed-snapshot.json'
]) assert.equal(served.has(forbiddenFile), false, `${forbiddenFile} is outside the replacement artifact`)

for (const requiredProductFile of [
  'js/data.js',
  'js/identity-primitives.js',
  'js/identity-store.js',
  'js/pow-current.js',
  'js/substrate/local-identity.js',
  'js/substrate/author-bind-inner-envelope-policy.mjs',
  'js/substrate/peerit-journal-backend.js',
  'js/substrate/peerit-journal.js',
  'js/substrate/peerit-operation-authority-v1.js',
  'js/substrate/peerit-product-runtime.js',
  'js/substrate/peerit-product-ui.js',
  'js/substrate/peerit-substrate-sync.js',
  'js/substrate/cold-reader.mjs',
  'js/substrate/remote-record-ingest.mjs',
  'js/substrate/seed-bootstrap-v1.mjs'
]) assert.equal(served.has(requiredProductFile), true, `${requiredProductFile} is in the replacement product closure`)

for (const path of Object.values(PEERIT_BROWSER_RUNTIME_ASSET_PATHS)) {
  const generated = path === `/${PEERIT_APP_ARTIFACT_PATH}`
  assert.equal(generated || served.has(path.slice(1)), true,
    `${path} is source-owned or deterministically generated in the authenticated runtime closure`)
}

const forbiddenRuntimeTokens = [
  '/api/sync',
  '/api/bridge/status',
  'createGossip',
  'createRelayPool',
  'createDhtTransport',
  'resolveShardCohort',
  'connectRelaysInBackground',
  'peerit-shard-roster',
  'hiverelay-outbox',
  'outbox.peerit.site'
]
const importPattern = /\b(?:import|export)\s+(?:[^'";]+?\s+from\s*)?['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
const staticRuntimeImportTargets = new Set()

for (const file of SUBSTRATE_SITE_FILES.filter(file => /\.(?:js|mjs)$/.test(file))) {
  const source = readFileSync(join(root, file), 'utf8')
  for (const token of forbiddenRuntimeTokens) {
    if (file === 'js/substrate/release-relay-hints.mjs' &&
        token === 'outbox.peerit.site') continue
    assert.equal(source.includes(token), false, `${file} contains no retired writer token ${token}`)
  }
  for (const match of source.matchAll(importPattern)) {
    const specifier = match[1] || match[2]
    if (!specifier || (!specifier.startsWith('./') && !specifier.startsWith('../'))) continue
    const target = normalize(join(dirname(file), specifier)).replaceAll('\\', '/')
    staticRuntimeImportTargets.add(target)
    assert.equal(served.has(target), true, `${file} import ${specifier} remains inside replacement closure`)
  }
}

const output = mkdtempSync(join(tmpdir(), 'peerit-substrate-build-'))
const build = spawnSync(process.execPath, [
  'build-web.mjs', '--config', 'deploy/web-release.json', '--out', output
], {
  cwd: root,
  encoding: 'utf8'
})
assert.equal(build.status, 0, `${build.stdout}\n${build.stderr}`)

const variantOutput = mkdtempSync(join(tmpdir(), 'peerit-substrate-build-variant-'))
const variantBuild = spawnSync(process.execPath, [
  'build-web.mjs', '--config', 'deploy/web-release.json', '--out', variantOutput
], {
  cwd: root,
  encoding: 'utf8',
  env: {
    ...process.env,
    LANG: 'tr_TR.UTF-8',
    LC_ALL: 'tr_TR.UTF-8',
    PEERIT_RELAY_ROSTER_MIRRORS: 'https://legacy-mirror-must-not-enter.example/'
  }
})
assert.equal(variantBuild.status, 0, `${variantBuild.stdout}\n${variantBuild.stderr}`)

const manifest = JSON.parse(readFileSync(join(output, 'asset-manifest.json'), 'utf8'))
const variantManifest = JSON.parse(readFileSync(
  join(variantOutput, 'asset-manifest.json'), 'utf8'))
assert.deepEqual(variantManifest, manifest,
  'locale and stray legacy mirror environment cannot change replacement release bytes')
for (const file of [...Object.keys(manifest.files), ...Object.keys(manifest.controls)]) {
  assert.deepEqual(readFileSync(join(variantOutput, file)), readFileSync(join(output, file)),
    `${file} is byte-reproducible across locale and ignored legacy mirror state`)
}
assert.equal(manifest.webRelease.transport, 'blind-substrate')
assert.deepEqual(new Set(Object.keys(manifest.files)), new Set([
  ...SUBSTRATE_SITE_FILES,
  'sw-register.js',
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_WEB_ASSET_MANIFEST_PATH
]))

const builtRuntimeFiles = new Map(Object.keys(manifest.files).map(file => [
  file,
  readFileSync(join(output, file))
]))
const officialRelease = JSON.parse(readFileSync(join(root, 'deploy', 'web-release.json'), 'utf8'))
const verifiedRuntime = verifyPeeritSubstrateRuntimeArtifactV1({
  files: builtRuntimeFiles,
  releaseSequence: officialRelease.releaseSequence,
  releaseKey: officialRelease.pinnedReleaseKey
})
assert.equal(verifiedRuntime.appArtifactHashHex, manifest.webRelease.appArtifactHash)
assert.equal(verifiedRuntime.webAssetManifestHashHex,
  manifest.webRelease.canonicalWebAssetManifestHash)
const canonicalRuntimePaths = new Set(verifiedRuntime.webAssetManifest.assets
  .map(asset => asset.path.slice(1)))
for (const target of staticRuntimeImportTargets) {
  assert.equal(Object.hasOwn(verifiedRuntime.appArtifact.files, target), true,
    `${target} static/transitive import bytes are authenticated by the app artifact`)
  assert.equal(canonicalRuntimePaths.has(target), true,
    `${target} static/transitive import bytes are authenticated by WebAssetManifestV1`)
  assert.equal(verifiedRuntime.appArtifact.files[target], manifest.files[target],
    `${target} app-artifact SHA-256 equals the outer deterministic manifest`)
}
assert.equal(manifest.webRelease.productionPinHistory, null)
assert.throws(() => verifyPeeritSubstrateRuntimeArtifactV1({
  files: new Map([...builtRuntimeFiles, ['js/app.js', Buffer.from('legacy writer')]]),
  releaseSequence: officialRelease.releaseSequence,
  releaseKey: officialRelease.pinnedReleaseKey
}), /outside its exact canonical closure/,
'an extra signed legacy writer cannot sit outside canonical WebAssetManifestV1')
assert.throws(() => createPublishedSiteFilesV1({ ...officialRelease, releaseSequence: 6 }),
  /sequence 6 belongs to the retired legacy artifact/)

const sourceRuntimeFiles = new Map(SUBSTRATE_SITE_FILES.map(file => [
  file,
  readFileSync(join(root, file))
]))

await cryptoReady()
const discoveryAuthority = await genKeyPair()
const relayRoot = (relayId, fill) => ({
  relayId,
  canonicalDescribeUrl: `https://${relayId}.example/api/blind/v1/describe`,
  continuityRootRelayPublicKey: fill.repeat(32),
  storeId: (fill === '11' ? '12' : '22').repeat(32),
  descriptorGenesisHash: (fill === '11' ? '13' : '23').repeat(32),
  minimumDescriptorSequence: 1,
  familyId: 2,
  operationId: 2,
  endpointId: 1,
  transportId: 1,
  transportSupportBit: 1,
  privacyProfileBit: 1
})
const seedRelays = [relayRoot('dal', '11'), relayRoot('syd', '21')]
const seedRecord = {
  recordId: '31'.repeat(32),
  wireKeys: ['v2!seed'],
  authorPublicKey: '32'.repeat(32),
  innerCodec: 334,
  innerLength: 8,
  sizeClass: 1,
  logicalHash: '33'.repeat(32),
  encodingCommitment: '34'.repeat(32),
  replicas: seedRelays.map((relay, index) => ({
    relayId: relay.relayId,
    targetId: `cell-v1:${relay.relayId}:seed`,
    readCapability: {
      version: 1,
      relayPublicKey: relay.continuityRootRelayPublicKey,
      storageSlot: (index ? '42' : '41').repeat(32),
      cellKey: (index ? '52' : '51').repeat(32),
      sizeClass: 1,
      expectedCellBlobHash: (index ? '62' : '61').repeat(32)
    }
  }))
}
const seedArtifact = await createPeeritSeedBootstrapV1({
  schema: PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  version: 1,
  profile: PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  operatorBoundary: PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  bootstrapSequence: 0,
  previousBootstrapHash: null,
  releaseSequence: 13,
  authorityPublicKey: discoveryAuthority.pubHex,
  issuedAt: 1,
  expiresAt: 10_000,
  relays: seedRelays,
  records: [seedRecord]
}, { seedHex: discoveryAuthority.seedHex })
const seedBootstrapBytes = Buffer.from(encodePeeritSeedBootstrapV1(seedArtifact))
const sequence13Artifact = buildPeeritSubstrateRuntimeArtifactV1({
  sourceFiles: sourceRuntimeFiles,
  substrateProfile: 'blind-v1',
  relayHints: [
    'https://relay-syd.p2phiverelay.xyz/api/blind/v1/describe',
    'https://relay-dal.p2phiverelay.xyz/api/blind/v1/describe'
  ],
  releaseSequence: 13,
  releaseKey: officialRelease.pinnedReleaseKey,
  seedBootstrapBytes,
  seedDiscoveryAuthorityPublicKey: discoveryAuthority.pubHex
})
assert.deepEqual(sequence13Artifact.files.get('peerit-seed-bootstrap-v1.json'), seedBootstrapBytes)
assert.equal(sequence13Artifact.appArtifact.peeritSeedBootstrap, '/peerit-seed-bootstrap-v1.json')
assert.equal(sequence13Artifact.appArtifact.peeritSeedBootstrapSha256,
  sequence13Artifact.seedBootstrap.sha256)
assert.equal(sequence13Artifact.appArtifact.peeritSeedDiscoveryAuthorityPublicKey,
  discoveryAuthority.pubHex)
assert.equal(sequence13Artifact.appArtifact.peeritSeedBootstrapReleaseSequence, 13)
assert.equal(sequence13Artifact.webAssetManifestBytes != null, true)
const sequence13Verified = verifyPeeritSubstrateRuntimeArtifactV1({
  files: sequence13Artifact.files,
  releaseSequence: 13,
  releaseKey: officialRelease.pinnedReleaseKey
})
assert.equal(sequence13Verified.webAssetManifest.recommendedBootstrapHashes.length, 1)
assert.deepEqual(sequence13Verified.webAssetManifest.recommendedBootstrapHashes[0],
  hashPeeritBootstrapV1(seedBootstrapBytes),
  'the canonical manifest/profile input binds the domain-separated seed hash')
const tamperedSeedFiles = new Map(sequence13Artifact.files)
const tamperedSeed = Buffer.from(seedBootstrapBytes)
tamperedSeed[tamperedSeed.length - 2] = tamperedSeed[tamperedSeed.length - 2] === 0x30 ? 0x31 : 0x30
tamperedSeedFiles.set('peerit-seed-bootstrap-v1.json', tamperedSeed)
assert.throws(() => verifyPeeritSubstrateRuntimeArtifactV1({
  files: tamperedSeedFiles,
  releaseSequence: 13,
  releaseKey: officialRelease.pinnedReleaseKey
}), /seed bootstrap|WEB_ASSET_DRIFT/,
'a seed byte tamper cannot survive the app, canonical, and raw-hash closure')
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1({
  sourceFiles: sourceRuntimeFiles,
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence: 13,
  releaseKey: officialRelease.pinnedReleaseKey
}), /seed bootstrap/i, 'sequence 13 fails closed without exact seed bytes')
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1({
  sourceFiles: sourceRuntimeFiles,
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence: 13,
  releaseKey: officialRelease.pinnedReleaseKey,
  seedBootstrapBytes,
  seedDiscoveryAuthorityPublicKey: 'ff'.repeat(32)
}), /discovery authority/, 'a build-time discovery-key mismatch fails before artifact assembly')

const nonProductionPinHistoryFixture = readFileSync(join(
  root, 'protocol', 'vectors', 'release-control', 'pin-history-bundle.bin'))
const ceremonyArtifact = buildPeeritSubstrateRuntimeArtifactV1({
  sourceFiles: sourceRuntimeFiles,
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence: officialRelease.releaseSequence,
  releaseKey: officialRelease.pinnedReleaseKey,
  productionPinHistoryBytes: nonProductionPinHistoryFixture
})
assert.deepEqual(
  ceremonyArtifact.files.get(PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)),
  nonProductionPinHistoryFixture,
  'a future ceremony can carry exact detached pin-history control bytes')
assert.match(ceremonyArtifact.files.get('index.html').toString('utf8'),
  new RegExp(`name="peerit-production-pin-history" content="${PEERIT_PRODUCTION_PIN_HISTORY_PATH}"`))
assert.equal(ceremonyArtifact.appArtifact.productionPinHistory,
  PEERIT_PRODUCTION_PIN_HISTORY_PATH)
assert.equal(ceremonyArtifact.appArtifact.files[
  PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)], undefined,
'detached pin history is excluded from the app artifact hash closure')
const ceremonyVerified = verifyPeeritSubstrateRuntimeArtifactV1({
  files: ceremonyArtifact.files,
  releaseSequence: officialRelease.releaseSequence,
  releaseKey: officialRelease.pinnedReleaseKey
})
assert.equal(ceremonyVerified.webAssetManifest.assets.some(
  asset => asset.path === PEERIT_PRODUCTION_PIN_HISTORY_PATH), false,
'detached pin history is excluded from WebAssetManifestV1 to avoid a hash cycle')

const publishedRuntimeFiles = new Map(createPublishedSiteFilesV1(officialRelease)
  .map(({ path, content }) => [path.slice(1), Buffer.from(content)]))
assert.deepEqual(new Set(publishedRuntimeFiles.keys()), new Set(builtRuntimeFiles.keys()),
  'Web and Hyper publication contain the same replacement runtime paths')
for (const [file, bytes] of publishedRuntimeFiles) {
  assert.deepEqual(bytes, builtRuntimeFiles.get(file),
    `Web and Hyper publication converge on exact bytes for ${file}`)
}

const builtIndex = readFileSync(join(output, 'index.html'), 'utf8')
assert.match(builtIndex, /src="js\/substrate\/app-entry\.js"/)
assert.doesNotMatch(builtIndex, /src="js\/app\.js"|name="peerit-v2"/)
const csp = builtIndex.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i)?.[1] || ''
const scriptSrc = csp.split(';').map(value => value.trim()).find(value => value.startsWith('script-src')) || ''
assert.equal(scriptSrc, "script-src 'self'")
assert.doesNotMatch(scriptSrc, /data:|'unsafe-inline'|'unsafe-eval'/)
assert.match(builtIndex,
  new RegExp(`name="peerit-production-web-asset-manifest" content="/${PEERIT_WEB_ASSET_MANIFEST_PATH}"`))

for (const file of Object.keys(manifest.files).filter(file => /\.(?:js|mjs)$/.test(file))) {
  const source = readFileSync(join(output, file), 'utf8')
  for (const token of forbiddenRuntimeTokens) {
    if (file === 'js/substrate/release-relay-hints.mjs' &&
        token === 'outbox.peerit.site') continue
    assert.equal(source.includes(token), false, `built ${file} contains no retired writer token ${token}`)
  }
}

assert.equal(existsSync(join(output, 'seed-snapshot.json')), false)
assert.equal(existsSync(join(output, 'js', 'app.js')), false)
assert.equal(existsSync(join(output, 'js', 'sync.js')), false)
assert.equal(existsSync(join(output, 'js', 'pear-api.js')), false)
assert.equal(existsSync(join(output, 'js', 'blind-dealer.mjs')), false)
assert.equal(existsSync(join(output, 'js', 'data-dispersal.js')), false)
assert.equal(existsSync(join(output, 'test', 'fixtures', 'peerit-vnext-journal-fixture.mjs')), false,
  'unsigned structural lab fixture is absent from the production build output')

const productEntry = readFileSync(join(output, 'js', 'substrate', 'app-entry.js'), 'utf8')
assert.match(productEntry, /createPeeritProductRuntimeV1/)
assert.match(productEntry, /mountPeeritProductUiV1/)
assert.match(productEntry, /installPeeritBlindRelayConsumer/)
assert.match(productEntry, /loadPeeritProductionPinHistoryTerminalV1/)
assert.match(productEntry, /verifyPeeritReleaseCoherenceV1/)
assert.doesNotMatch(productEntry, /Read-only —/)

const productRuntime = readFileSync(join(output, 'js', 'substrate', 'peerit-product-runtime.js'), 'utf8')
assert.match(productRuntime, /relays:\s*\[\]/)
assert.match(productRuntime, /v2:\s*true/)
assert.match(productRuntime, /dispersal:\s*false/)
assert.doesNotMatch(productRuntime, /relayHints:\s*\[[^\]]+\]/)

const server = createServer((request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname.replace(/^\//, '') || 'index.html'
  const file = join(output, pathname)
  if (!existsSync(file)) {
    response.writeHead(404)
    response.end('not found')
    return
  }
  response.writeHead(200)
  response.end(readFileSync(file))
})
server.listen(0, '127.0.0.1')
await once(server, 'listening')
try {
  const base = `http://127.0.0.1:${server.address().port}/`
  const verifyResponse = await fetch(new URL('verify.html', base))
  assert.equal(verifyResponse.status, 200, '/verify.html is served')
  const verifyHtml = await verifyResponse.text()
  const verifierImport = verifyHtml.match(/from\s+['"]\.\/([^'"]+)['"]/)?.[1]
  assert.equal(verifierImport, 'js/release-verify.js')
  const verifierResponse = await fetch(new URL(verifierImport, base))
  assert.equal(verifierResponse.status, 200,
    '/verify.html module dependency is present instead of returning 404')
} finally {
  server.close()
  await once(server, 'close')
}

console.log('peerit-substrate-build-closure: Web+Hyper bytes converge, canonical bindings verify, /verify.html has no missing module, and legacy writer routes stay absent')
