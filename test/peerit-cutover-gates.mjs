import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import { releaseConfig, verifyIndexConfig, verifyManifestConfig } from '../scripts/verify-deployed-web.mjs'
import {
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE,
  PEERIT_WEB_ASSET_MANIFEST_PATH
} from '../scripts/substrate-runtime-artifact.mjs'

const key = 'ab'.repeat(32)
const drive = 'cd'.repeat(32)
const release = releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence: 9,
  pinnedReleaseKey: key
})

assert.equal(release.transport, 'blind-substrate')
assert.deepEqual(release.relayHints, [])
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence: 6,
  pinnedReleaseKey: key
}), /sequence 6 belongs to the retired legacy artifact/)
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  bootstrapRelays: ['https://outbox.peerit.site'],
  releaseSequence: 9,
  pinnedReleaseKey: key
}), /refuses legacy transport configuration/)
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: ['https://outbox.peerit.site'],
  releaseSequence: 9,
  pinnedReleaseKey: key
}), /replacement transport policy/)
for (const relayHint of [
  'https://user:secret@relay.example/',
  'https://relay.example/?query=1',
  'https://relay.example/#fragment',
  'https://relay.example/a,b',
  `https://relay.example/${'x'.repeat(2049)}`
]) {
  assert.throws(() => releaseConfig({
    substrateProfile: 'blind-v1',
    relayHints: [relayHint],
    releaseSequence: 9,
    pinnedReleaseKey: key
  }), /relay hint/)
}
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: Array.from({ length: 129 }, (_, index) => `https://relay-${index}.example/`),
  releaseSequence: 9,
  pinnedReleaseKey: key
}), /fixed count bound/)

const html = `<!doctype html><head>
  <meta name="peerit-substrate" content="blind-v1">
  <meta name="peerit-release-key" content="${key}">
  <meta name="peerit-release-sequence" content="9">
  <meta name="peerit-production-web-asset-manifest" content="/${PEERIT_WEB_ASSET_MANIFEST_PATH}">
</head>`
verifyIndexConfig(html, release)
assert.throws(() => verifyIndexConfig(html.replace('</head>', '<meta name="peerit-relay" content="https://legacy.example"></head>'), release), /must not contain peerit-relay meta/)

verifyManifestConfig({
  releaseSequence: 9,
  driveKey: drive,
  files: { 'index.html': 'ef'.repeat(32) },
  webRelease: {
    releaseSequence: 9,
    transport: 'blind-substrate',
    substrateProfile: 'blind-v1',
    relayHints: [],
    networkDelivery: 'profile-gated',
    legacyDestination: null,
    productionPinHistory: null,
    appArtifact: `/${PEERIT_APP_ARTIFACT_PATH}`,
    appArtifactHash: 'ef'.repeat(32),
    canonicalWebAssetManifest: `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`,
    canonicalWebAssetManifestHash: '12'.repeat(32),
    releaseKey: key
  }
}, release, '', '', drive)

const publishSource = readFileSync(new URL('../publish.mjs', import.meta.url), 'utf8')
assert.ok(publishSource.indexOf('assertPeeritBlindProductReleaseReady(release)') < publishSource.indexOf('await loadHiveRelayClient()'),
  'public publish checks composed product readiness before loading or starting a network client')
const shipSource = readFileSync(new URL('../ship.mjs', import.meta.url), 'utf8')
assert.match(shipSource, /assertPeeritBlindProductReleaseReady\(release\)/)
assert.match(shipSource, /await run\('npm', \['run', 'test:ship'\]\)/,
  'ship verification executes the complete substrate/closure/cutover suite')
const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
assert.match(packageJson.scripts['test:ship'], /npm test && npm run test:peerit-substrate/)
assert.match(packageJson.scripts['test:peerit-substrate'], /peerit-app-entry-composition\.mjs/)
assert.ok(SUBSTRATE_SITE_FILES.includes('js/substrate/profile-status.mjs'))
for (const browserReleaseFile of [
  'js/substrate/pin-history-bootstrap.mjs',
  'js/substrate/pin-history-witness-backend.mjs',
  'js/substrate/production-release-authority.mjs',
  'js/substrate/release-coherence.js',
  'js/substrate/release-authority-transition.mjs',
  'js/substrate/release-control-codec.mjs',
  'js/substrate/release-control-primitives.mjs',
  'js/substrate/release-control-registry.mjs',
  'js/substrate/release-control-verifier.mjs'
]) assert.ok(SUBSTRATE_SITE_FILES.includes(browserReleaseFile))

const officialConfig = readFileSync(new URL('../deploy/web-release.json', import.meta.url), 'utf8')
const officialRelease = JSON.parse(officialConfig)
const consumedSigningRequest = JSON.parse(readFileSync(
  new URL('../deploy/web-signing-request.json', import.meta.url), 'utf8'))
const trackedWebManifestBytes = readFileSync(
  new URL('../web/asset-manifest.json', import.meta.url))
const trackedWebManifest = JSON.parse(trackedWebManifestBytes)
assert.ok(officialRelease.releaseSequence >= PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE)
const trackedWebManifestSha256 = createHash('sha256').update(trackedWebManifestBytes).digest('hex')
if (officialRelease.productionPinHistoryBundle) {
  assert.equal(consumedSigningRequest.releaseSequence, officialRelease.releaseSequence,
    'the sealed signing request selects the exact production sequence')
  assert.equal(trackedWebManifest.releaseSequence, officialRelease.releaseSequence,
    'the sealed Web tree selects the exact production sequence')
  assert.equal(consumedSigningRequest.manifestSha256, trackedWebManifestSha256,
    'the sealed signing request authorizes the exact tracked Web manifest bytes')
  assert.equal(trackedWebManifest.webRelease?.transport, 'blind-substrate')
  assert.equal(trackedWebManifest.webRelease?.productionPinHistory,
    `/${officialRelease.productionPinHistoryBundle}`)
} else {
  assert.equal(consumedSigningRequest.releaseSequence, trackedWebManifest.releaseSequence,
    'the consumed prior request remains distinguishable from the unsigned replacement')
  assert.notEqual(consumedSigningRequest.manifestSha256, trackedWebManifestSha256,
    'a superseded request cannot authorize a changed tracked tree')
  assert.ok(trackedWebManifest.releaseSequence < officialRelease.releaseSequence,
    'the tracked prior-release Web directory is never reused as the replacement candidate')
  assert.notEqual(trackedWebManifest.webRelease?.transport, 'blind-substrate',
    'the tracked prior release remains distinguishable from the replacement transport')
}
const render = readFileSync(new URL('../render.yaml', import.meta.url), 'utf8')
const renderHeaderPolicy = readFileSync(new URL('../deploy/render-security-headers.json', import.meta.url), 'utf8')
for (const source of [officialConfig, render, renderHeaderPolicy]) {
  assert.doesNotMatch(source, /outbox\.peerit\.site|peerit-relay|hiverelay-outbox/i)
}

console.log('peerit-cutover-gates: replacement-only unsigned and exact sealed release states fail/verify correctly')
