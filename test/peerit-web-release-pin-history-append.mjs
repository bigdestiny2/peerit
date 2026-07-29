import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { releaseSigningMessage } from '../js/release-verify.js'
import {
  PEERIT_WEB_RELEASE_PIN_HISTORY_NOTE_V1,
  appendPeeritWebReleasePinHistoryV1
} from '../scripts/append-web-release-pin-history.mjs'

const hash = value => createHash('sha256').update(value).digest('hex')
const releaseKey = '11'.repeat(32)
const driveKey = '22'.repeat(32)
const discoveryKey = '33'.repeat(32)
const relayHints = [
  'https://relay-syd.example/api/blind/v1/describe',
  'https://relay-dal.example/api/blind/v1/describe'
]
const config = {
  substrateProfile: 'blind-v1',
  relayHints,
  productionPinHistoryBundle: 'peerit-production-pin-history-v1.cenc',
  peeritSeedBootstrapBundle: 'deploy/peerit-seed-bootstrap-v1.json',
  peeritSeedDiscoveryAuthorityPublicKey: discoveryKey,
  releaseSequence: 13,
  pinnedReleaseKey: releaseKey,
  ignoredConfigField: 'must-not-copy'
}
const manifest = {
  releaseSequence: 13,
  files: { 'index.html': '44'.repeat(32) },
  controls: { 'sw.js': '55'.repeat(32) },
  driveKey,
  webRelease: {
    releaseSequence: 13,
    transport: 'blind-substrate',
    substrateProfile: 'blind-v1',
    relayHints,
    networkDelivery: 'profile-gated',
    legacyDestination: null,
    productionPinHistory: '/peerit-production-pin-history-v1.cenc',
    appArtifact: '/peerit-app-artifact-v1.json',
    appArtifactHash: '66'.repeat(32),
    canonicalWebAssetManifest: '/peerit-web-assets-v1.cenc',
    canonicalWebAssetManifestHash: '77'.repeat(32),
    peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
    peeritSeedBootstrapSha256: '88'.repeat(32),
    peeritSeedDiscoveryAuthorityPublicKey: discoveryKey,
    peeritSeedBootstrapReleaseSequence: 13,
    releaseKey
  }
}
const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n')
const manifestSha256 = hash(manifestBytes)
const signingMessageSha256 = hash(Buffer.from(releaseSigningMessage(manifest), 'utf8'))
const request = {
  schema: 'peerit-web-signing-request-v2',
  manifest: 'web/asset-manifest.json',
  signature: 'web/asset-manifest.sig',
  releaseSequence: 13,
  driveKey,
  pinnedReleaseKey: releaseKey,
  manifestSha256,
  signingMessageSha256,
  artifactFiles: {
    'asset-manifest.json': manifestSha256,
    'index.html': '44'.repeat(32)
  },
  ignoredRequestField: 'must-not-copy'
}
const history = {
  schema: 'peerit-web-release-pin-history/v1',
  note: 'stale claim: production authority root is intentionally null',
  entries: [{ releaseSequence: 12, historicalField: 'preserved' }]
}
const bytes = value => Buffer.from(JSON.stringify(value) + '\n')
const options = {
  fixtureOnly: true,
  write: false,
  configBytes: bytes(config),
  requestBytes: bytes(request),
  manifestBytes,
  historyBytes: bytes(history)
}

const first = appendPeeritWebReleasePinHistoryV1(options)
const second = appendPeeritWebReleasePinHistoryV1(options)
assert.deepEqual(first.bytes, second.bytes, 'web pin-history append must be deterministic')
assert.equal(first.value.note, PEERIT_WEB_RELEASE_PIN_HISTORY_NOTE_V1)
assert.equal(first.value.entries[0].historicalField, 'preserved')
const head = first.value.entries[1]
assert.deepEqual(Object.keys(head), [
  'releaseSequence',
  'manifestSha256',
  'signingMessageSha256',
  'pinnedReleaseKey',
  'driveKey',
  'transport',
  'relayHints',
  'claim_boundary',
  'note'
])
assert.deepEqual(head, {
  releaseSequence: 13,
  manifestSha256,
  signingMessageSha256,
  pinnedReleaseKey: releaseKey,
  driveKey,
  transport: 'blind-substrate/blind-v1',
  relayHints,
  claim_boundary: 'LIVE_PUBLIC_TEST_ONLY',
  note: 'bounded local public-test release sequence 13; not a GA claim'
})
assert.equal(JSON.stringify(head).includes('must-not-copy'), false)

assert.throws(() => appendPeeritWebReleasePinHistoryV1({
  ...options,
  historyBytes: bytes({ ...history, entries: [{ releaseSequence: 11 }] })
}), error => error.code === 'PEERIT_WEB_RELEASE_PIN_HISTORY_PREDECESSOR_MISMATCH')
assert.throws(() => appendPeeritWebReleasePinHistoryV1({
  ...options,
  requestBytes: bytes({ ...request, manifestSha256: '99'.repeat(32) })
}), /signing request does not bind/)
assert.throws(() => appendPeeritWebReleasePinHistoryV1({
  ...options,
  configBytes: bytes({ ...config, releaseSequence: 14 })
}), /outer asset manifest does not reproduce/)
assert.throws(() => appendPeeritWebReleasePinHistoryV1({
  ...options,
  manifestBytes: Buffer.from(JSON.stringify({
    ...manifest,
    webRelease: { ...manifest.webRelease, relayHints: [...relayHints].reverse() }
  }))
}), /outer asset manifest does not reproduce/)

console.log('peerit-web-release-pin-history-append: exact request/config copy, contiguous predecessor, stale-note replacement and drift rejection green')
