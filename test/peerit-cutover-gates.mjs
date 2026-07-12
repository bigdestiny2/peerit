import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { SITE_FILES } from '../publish.mjs'
import { releaseConfig, verifyIndexConfig, verifyManifestConfig } from '../scripts/verify-deployed-web.mjs'

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
  bootstrapRelays: ['https://outbox.peerit.site'],
  releaseSequence: 9,
  pinnedReleaseKey: key
}), /refuses legacy transport configuration/)
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: ['https://outbox.peerit.site'],
  releaseSequence: 9,
  pinnedReleaseKey: key
}), /retired outbox\.peerit\.site destination/)

const html = `<!doctype html><head>
  <meta name="peerit-substrate" content="blind-v1">
  <meta name="peerit-release-key" content="${key}">
  <meta name="peerit-release-sequence" content="9">
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
    releaseKey: key
  }
}, release, '', '', drive)

const publishSource = readFileSync(new URL('../publish.mjs', import.meta.url), 'utf8')
assert.ok(publishSource.indexOf('assertPeeritBlindProductReleaseReady(release)') < publishSource.indexOf('await loadHiveRelayClient()'),
  'public publish checks composed product readiness before loading or starting a network client')
const shipSource = readFileSync(new URL('../ship.mjs', import.meta.url), 'utf8')
assert.match(shipSource, /assertPeeritBlindProductReleaseReady\(release\)/)
assert.ok(SITE_FILES.includes('js/substrate/profile-status.mjs'))
assert.ok(SITE_FILES.includes('js/substrate/product-release-status.mjs'))
for (const browserReleaseFile of [
  'js/substrate/pin-history-witness-backend.mjs',
  'js/substrate/release-authority-transition.mjs',
  'js/substrate/release-control-codec.mjs',
  'js/substrate/release-control-primitives.mjs',
  'js/substrate/release-control-registry.mjs',
  'js/substrate/release-control-verifier.mjs'
]) assert.ok(SITE_FILES.includes(browserReleaseFile))

const officialConfig = readFileSync(new URL('../deploy/web-release.json', import.meta.url), 'utf8')
const render = readFileSync(new URL('../render.yaml', import.meta.url), 'utf8')
const renderHeaderPolicy = readFileSync(new URL('../deploy/render-security-headers.json', import.meta.url), 'utf8')
for (const source of [officialConfig, render, renderHeaderPolicy]) {
  assert.doesNotMatch(source, /outbox\.peerit\.site|peerit-relay|hiverelay-outbox/i)
}

console.log('peerit-cutover-gates: official release is replacement-only and fail-closed while local authoring remains available')
