import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { releaseSigningMessage } from '../js/release-verify.js'
import {
  PEERIT_WEB_RELEASE_PIN_HISTORY_NOTE_V1,
  appendPeeritWebReleasePinHistoryV1
} from '../scripts/append-web-release-pin-history.mjs'
import { PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE } from '../scripts/production-pin-history-ceremony.mjs'

const hash = value => createHash('sha256').update(value).digest('hex')
const releaseKey = '11'.repeat(32)
const driveKey = '22'.repeat(32)
const discoveryKey = '33'.repeat(32)
const inboxAuthorityKey = 'aa'.repeat(32)
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

function successorOptions (releaseSequence, historyValue) {
  const inbox = releaseSequence >= 29
  const successorConfig = {
    ...config,
    releaseSequence,
    ...(inbox
      ? {
          peeritLimitedPublicInboxBootstrapBundle:
            'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
          peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxAuthorityKey
        }
      : {})
  }
  const successorManifest = {
    ...manifest,
    releaseSequence,
    files: {
      ...manifest.files,
      ...(inbox
        ? { 'peerit-limited-public-inbox-bootstrap-v1.json': 'ab'.repeat(32) }
        : {})
    },
    webRelease: {
      ...manifest.webRelease,
      releaseSequence,
      peeritSeedBootstrapReleaseSequence: releaseSequence,
      ...(inbox
        ? {
            peeritLimitedPublicInboxBootstrap:
              '/peerit-limited-public-inbox-bootstrap-v1.json',
            peeritLimitedPublicInboxBootstrapSha256: 'ab'.repeat(32),
            peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxAuthorityKey,
            peeritLimitedPublicInboxBootstrapReleaseSequence: releaseSequence
          }
        : {})
    }
  }
  const successorManifestBytes = Buffer.from(JSON.stringify(successorManifest, null, 2) + '\n')
  const successorManifestSha256 = hash(successorManifestBytes)
  const successorRequest = {
    ...request,
    releaseSequence,
    manifestSha256: successorManifestSha256,
    signingMessageSha256: hash(Buffer.from(releaseSigningMessage(successorManifest), 'utf8')),
    artifactFiles: {
      ...request.artifactFiles,
      'asset-manifest.json': successorManifestSha256
    }
  }
  return {
    fixtureOnly: true,
    write: false,
    configBytes: bytes(successorConfig),
    requestBytes: bytes(successorRequest),
    manifestBytes: successorManifestBytes,
    historyBytes: bytes(historyValue)
  }
}

const sequence15 = appendPeeritWebReleasePinHistoryV1(successorOptions(15, {
  schema: 'peerit-web-release-pin-history/v1',
  note: PEERIT_WEB_RELEASE_PIN_HISTORY_NOTE_V1,
  entries: [{ releaseSequence: 14, historicalField: 'preserved-for-seq15' }]
}))
assert.equal(sequence15.value.entries.at(-1).releaseSequence, 15)
assert.equal(sequence15.value.entries.at(-1).note,
  'bounded local public-test release sequence 15; not a GA claim')
assert.equal(sequence15.value.entries[0].historicalField, 'preserved-for-seq15')

const sequence16 = appendPeeritWebReleasePinHistoryV1(
  successorOptions(16, sequence15.value))
assert.deepEqual(sequence16.value.entries.map(entry => entry.releaseSequence), [14, 15, 16])
assert.equal(sequence16.value.entries.at(-1).note,
  'bounded local public-test release sequence 16; not a GA claim')
const sequence17 = appendPeeritWebReleasePinHistoryV1(
  successorOptions(17, sequence16.value))
const sequence18 = appendPeeritWebReleasePinHistoryV1(
  successorOptions(18, sequence17.value))
const sequence19 = appendPeeritWebReleasePinHistoryV1(
  successorOptions(19, sequence18.value))
const sequence20 = appendPeeritWebReleasePinHistoryV1(
  successorOptions(20, sequence19.value))
assert.deepEqual(sequence20.value.entries.map(entry => entry.releaseSequence),
  [14, 15, 16, 17, 18, 19, 20])
assert.equal(sequence17.value.entries.at(-1).note,
  'bounded local public-test release sequence 17; not a GA claim')
assert.equal(sequence18.value.entries.at(-1).note,
  'bounded local public-test release sequence 18; not a GA claim')
assert.equal(sequence19.value.entries.at(-1).note,
  'bounded local public-test release sequence 19; not a GA claim')
assert.equal(sequence20.value.entries.at(-1).note,
  'bounded local public-test release sequence 20; not a GA claim')
const sequence29Options = successorOptions(29, {
  schema: 'peerit-web-release-pin-history/v1',
  note: PEERIT_WEB_RELEASE_PIN_HISTORY_NOTE_V1,
  entries: [{ releaseSequence: 28, historicalField: 'preserved-for-seq29' }]
})
if (PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE >= 29) {
  const sequence29 = appendPeeritWebReleasePinHistoryV1(sequence29Options)
  assert.equal(sequence29.value.entries.at(-1).releaseSequence, 29)
  assert.equal(sequence29.value.entries[0].historicalField, 'preserved-for-seq29')
  assert.throws(() => appendPeeritWebReleasePinHistoryV1({
    ...successorOptions(29, {
      schema: 'peerit-web-release-pin-history/v1',
      entries: [{ releaseSequence: 28 }]
    }),
    configBytes: bytes({
      ...config,
      releaseSequence: 29
    })
  }), /public INBOX bootstrap config fields/)
  assert.throws(() => appendPeeritWebReleasePinHistoryV1(
    successorOptions(30, sequence29.value)), /sequence 13\.\.29/)
} else {
  assert.throws(() => appendPeeritWebReleasePinHistoryV1(sequence29Options),
    new RegExp(`sequence 13\\.\\.${PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE}`))
}
assert.throws(() => appendPeeritWebReleasePinHistoryV1(successorOptions(12, {
    schema: 'peerit-web-release-pin-history/v1',
  entries: [{ releaseSequence: 11 }]
})), new RegExp(`sequence 13\\.\\.${PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE}`))

console.log(`peerit-web-release-pin-history-append: exact 13..${PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE} request/config copy, conditional Seq29 public-INBOX binding, contiguous predecessor, stale-note replacement and drift rejection green`)
