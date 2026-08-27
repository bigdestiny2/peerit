import assert from 'node:assert/strict'
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign
} from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import { releaseSigningMessage } from '../js/release-verify.js'
import {
  blake2b256,
  bytesToHex
} from '../js/substrate/release-control-primitives.mjs'
import {
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritWebAssetManifestV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  canonicalPeeritLimitedPublicInboxJsonV1,
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1
} from '../js/substrate/inbox-topic-v1.mjs'
import { releaseConfig, verifyIndexConfig, verifyManifestConfig } from '../scripts/verify-deployed-web.mjs'
import {
  PEERIT_SEQ29_DECISION_DRAFT_PATH_V1,
  PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1,
  PEERIT_SEQ29_DECISION_PATH_V1,
  PEERIT_SEQ29_DECISION_SHA256_V1,
  materializePeeritSeq29OwnerDecisionV1,
  peeritSeq29OwnerDecisionPhaseV1,
  verifyPeeritSeq29PinnedReprepareV1,
  verifyPeeritSeq29OwnerDecisionV1,
  verifyPinnedPeeritSeq29OwnerDecisionV1,
  writePeeritSeq29OwnerDecisionCreateOnlyV1
} from '../scripts/seq29-owner-decision.mjs'
import {
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_REPLACEMENT_MINIMUM_RELEASE_SEQUENCE,
  PEERIT_WEB_ASSET_MANIFEST_PATH,
  verifyPeeritLimitedPublicInboxBootstrapArtifactV1
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

const seedAuthority = '34'.repeat(32)
const seedSha256 = '56'.repeat(32)
const seededRelease = releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  productionPinHistoryBundle: 'peerit-production-pin-history-v1.cenc',
  peeritSeedBootstrapBundle: 'deploy/peerit-seed-bootstrap-v1-seq13.json',
  peeritSeedDiscoveryAuthorityPublicKey: seedAuthority,
  releaseSequence: 13,
  pinnedReleaseKey: key
})
const seededManifest = {
  releaseSequence: 13,
  driveKey: drive,
  files: { 'index.html': 'ef'.repeat(32) },
  webRelease: {
    releaseSequence: 13,
    transport: 'blind-substrate',
    substrateProfile: 'blind-v1',
    relayHints: [],
    networkDelivery: 'profile-gated',
    legacyDestination: null,
    productionPinHistory: '/peerit-production-pin-history-v1.cenc',
    appArtifact: `/${PEERIT_APP_ARTIFACT_PATH}`,
    appArtifactHash: 'ef'.repeat(32),
    canonicalWebAssetManifest: `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`,
    canonicalWebAssetManifestHash: '12'.repeat(32),
    peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
    peeritSeedBootstrapSha256: seedSha256,
    peeritSeedDiscoveryAuthorityPublicKey: seedAuthority,
    peeritSeedBootstrapReleaseSequence: 13,
    releaseKey: key
  }
}
verifyManifestConfig(seededManifest, seededRelease, '', '', drive, seedSha256)
assert.throws(
  () => verifyManifestConfig(seededManifest, seededRelease, '', '', drive, '78'.repeat(32)),
  /webRelease does not match/,
  'the deployed manifest must bind the exact local seed bootstrap bytes')
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence: 13,
  pinnedReleaseKey: key
}), /requires a seed bootstrap bundle/)

const inboxAuthority = '78'.repeat(32)
const inboxSha256 = '9a'.repeat(32)
const sequence29Release = releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  productionPinHistoryBundle: 'peerit-production-pin-history-v1.cenc',
  peeritSeedBootstrapBundle: 'deploy/peerit-seed-bootstrap-v1-seq29.json',
  peeritSeedDiscoveryAuthorityPublicKey: seedAuthority,
  peeritLimitedPublicInboxBootstrapBundle:
    'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
  peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxAuthority,
  releaseSequence: 29,
  pinnedReleaseKey: key
})
const sequence29Manifest = structuredClone(seededManifest)
sequence29Manifest.releaseSequence = 29
sequence29Manifest.files['peerit-limited-public-inbox-bootstrap-v1.json'] = inboxSha256
Object.assign(sequence29Manifest.webRelease, {
  releaseSequence: 29,
  peeritSeedBootstrapReleaseSequence: 29,
  peeritLimitedPublicInboxBootstrap:
    '/peerit-limited-public-inbox-bootstrap-v1.json',
  peeritLimitedPublicInboxBootstrapSha256: inboxSha256,
  peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxAuthority,
  peeritLimitedPublicInboxBootstrapReleaseSequence: 29
})
delete sequence29Manifest.webRelease.releaseKey
sequence29Manifest.webRelease.releaseKey = key
verifyManifestConfig(sequence29Manifest, sequence29Release, '', '', drive,
  seedSha256, inboxSha256)
assert.throws(() => verifyManifestConfig(sequence29Manifest, sequence29Release,
  '', '', drive, seedSha256, 'bc'.repeat(32)), /webRelease does not match/,
'the deployed manifest must bind the exact local public INBOX bootstrap bytes')
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  peeritSeedBootstrapBundle: 'deploy/peerit-seed-bootstrap-v1-seq29.json',
  peeritSeedDiscoveryAuthorityPublicKey: seedAuthority,
  releaseSequence: 29,
  pinnedReleaseKey: key
}), /requires a signed public INBOX bootstrap/)
assert.throws(() => releaseConfig({
  substrateProfile: 'blind-v1',
  relayHints: [],
  peeritSeedBootstrapBundle: 'deploy/peerit-seed-bootstrap-v1-seq28.json',
  peeritSeedDiscoveryAuthorityPublicKey: seedAuthority,
  peeritLimitedPublicInboxBootstrapBundle:
    'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
  peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxAuthority,
  releaseSequence: 28,
  pinnedReleaseKey: key
}), /requires releaseSequence 29 or later/)

const publishSource = readFileSync(new URL('../publish.mjs', import.meta.url), 'utf8')
assert.ok(publishSource.indexOf('assertPeeritBlindProductReleaseReady(release)') < publishSource.indexOf('await loadHiveRelayClient()'),
  'public publish checks composed product readiness before loading or starting a network client')
assert.ok(publishSource.indexOf(
  'canaryPublication = verifyPeeritSeq29CanaryPublicationV1') <
  publishSource.indexOf('await loadHiveRelayClient()'),
'public canary publication recomputes the pinned decision and release-config hash before loading a network client')
assert.match(publishSource,
  /if \(!LOCAL && CANARY_LIMITED_PUBLIC_TEST_V1\)[\s\S]*else if \(!LOCAL\) \{\s*assertPeeritBlindProductReleaseReady\(release\)/,
  'publish retains the unchanged GA gate unless the exact canary flag is present')
assert.match(publishSource, /publishOptions\.key = canaryPublication\.driveKey/,
  'canary publication reopens only the exact prepared drive key')
const shipSource = readFileSync(new URL('../ship.mjs', import.meta.url), 'utf8')
assert.match(shipSource, /assertPeeritBlindProductReleaseReady\(release\)/)
assert.match(shipSource,
  /publishArgs\.push\('--canary-limited-public-test-v1'\)/,
  'ship propagates the explicit canary flag to public publication')
assert.match(shipSource,
  /webReleaseArgs\.push\('--canary-limited-public-test-v1'\)/,
  'ship propagates the explicit canary flag to prepare and verify')
assert.doesNotMatch(shipSource, /shell: true/,
  'the release signing handoff never executes a shell command')
assert.match(shipSource, /stdio: \['ignore', 'inherit', 'inherit'\]/,
  'the scoped signing command cannot read interactive stdin')
assert.match(shipSource, /await run\('npm', \['run', 'test:ship'\]\)/,
  'ship verification executes the complete substrate/closure/cutover suite')
const webReleaseSource = readFileSync(new URL('../scripts/web-release.mjs', import.meta.url), 'utf8')
assert.match(webReleaseSource,
  /release\.transport === 'blind-substrate' && !opts\.canaryLimitedPublicTestV1\)[\s\S]*assertPeeritBlindProductReleaseReady\(release\)/,
  'web release retains the unchanged GA gate unless the exact canary flag is present')
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
const renderCsp = /name: "Content-Security-Policy"\n {8}value: "([^"]+)"/.exec(render)?.[1]
const expectedConnectSrc = [
  'connect-src', "'self'", 'hyper:', 'pear:',
  ...officialRelease.relayHints.map(hint => new URL(hint).origin),
  ...officialRelease.relayHints.map(hint => `https://${new URL(hint).hostname}:8443`)
].join(' ')
assert.equal(renderCsp?.split(';').map(value => value.trim())
  .find(value => value.startsWith('connect-src ')), expectedConnectSrc,
'production CSP binds exactly both relay origins and both fixed :8443 issuer origins')
assert.equal(JSON.parse(renderHeaderPolicy).headers.find(header =>
  header.name === 'Content-Security-Policy')?.value, renderCsp,
'render policy JSON remains byte-identical to the source blueprint CSP')

// Sequence-29's owner decision is an external release authorization record,
// not a bag of shape-valid hashes. Its verifier must bind the exact seed,
// INBOX bootstrap, app artifact, canonical WebAssetManifest, outer manifest,
// and offline signing request bytes while the checked-in DRAFT stays blocked.
const decisionDraftBytes = readFileSync(new URL(
  '../deploy/canary-decision-peerit-seq29-limited-public-inbox-DRAFT.json',
  import.meta.url))
assert.equal(PEERIT_SEQ29_DECISION_DRAFT_PATH_V1,
  'deploy/canary-decision-peerit-seq29-limited-public-inbox-DRAFT.json')
assert.equal(PEERIT_SEQ29_DECISION_PATH_V1,
  'deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json')
assert.equal(peeritSeq29OwnerDecisionPhaseV1({
  phase: 'prepare', sourcePin: ''
}), 'DRAFT_PREPARE_ONLY')
assert.throws(() => peeritSeq29OwnerDecisionPhaseV1({
  phase: 'verify', sourcePin: ''
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_PIN_REQUIRED')
assert.equal(peeritSeq29OwnerDecisionPhaseV1({
  phase: 'prepare', sourcePin: 'ab'.repeat(32)
}), 'PINNED_FINAL_REQUIRED')
assert.equal(peeritSeq29OwnerDecisionPhaseV1({
  phase: 'verify', sourcePin: 'ab'.repeat(32)
}), 'PINNED_FINAL_REQUIRED')
assert.throws(() => peeritSeq29OwnerDecisionPhaseV1({
  phase: 'prepare', sourcePin: 'AB'.repeat(32)
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_PIN_INVALID')
if (PEERIT_SEQ29_DECISION_SHA256_V1 === '') {
  assert.throws(() => verifyPinnedPeeritSeq29OwnerDecisionV1({ root: '.' }),
    error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_PIN_REQUIRED',
    'verify/publish fail closed before the mechanically reviewed source-pin step')
} else {
  assert.match(PEERIT_SEQ29_DECISION_SHA256_V1, /^[0-9a-f]{64}$/)
  assert.equal(verifyPinnedPeeritSeq29OwnerDecisionV1({
    root: join(dirname(fileURLToPath(import.meta.url)), '..')
  }).status, 'decided', 'a resolved source pin authenticates the exact final decision')
}
const decisionDraft = JSON.parse(decisionDraftBytes)
assert.equal(decisionDraft.release_artifacts.release_config_sha256, null)
assert.ok(decisionDraft.unresolved.includes(
  'release_artifacts.release_config_sha256'))
assert.equal(verifyPeeritSeq29OwnerDecisionV1({
  decisionBytes: decisionDraftBytes,
  allowDraft: true
}).status, 'draft')
assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
  decisionBytes: Buffer.from(JSON.stringify({ ...decisionDraft, unexpected: true }, null, 2) + '\n'),
  allowDraft: true
}), /fields are missing or unexpected/,
'the owner decision rejects even a canonical unknown top-level field')

const decisionRoot = mkdtempSync(join(tmpdir(), 'peerit-seq29-decision-'))
mkdirSync(join(decisionRoot, 'deploy'), { recursive: true })
mkdirSync(join(decisionRoot, 'web'), { recursive: true })
const decisionTime = '2026-08-13T20:00:00.000Z'
const staleRuntimeTime = '2026-08-27T12:00:00.000Z'
const inboxSigningSeed = '7c'.repeat(32)
const inboxPrivateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(inboxSigningSeed, 'hex')
  ]),
  format: 'der',
  type: 'pkcs8'
})
const decisionInboxAuthority = createPublicKey(inboxPrivateKey)
  .export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
const inboxFixture = JSON.parse(readFileSync(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json',
  import.meta.url)))
const inboxPayload = structuredClone(inboxFixture.payload)
const inboxNow = BigInt(Date.parse(decisionTime))
inboxPayload.artifactClass = 'LIMITED_PUBLIC_TEST_RELEASE'
inboxPayload.authorityPublicKey = decisionInboxAuthority
inboxPayload.issuedUnixMillis = String(inboxNow - 1000n)
inboxPayload.expiresUnixMillis = String(
  inboxNow + (7n * 24n * 60n * 60n * 1000n))
inboxPayload.inboxEpochSets[0].inboxEpoch = Math.floor(
  Number(inboxNow / 21600000n) / 28)
for (const binding of inboxPayload.inboxEpochSets[0].bindings) {
  binding.inboxEpoch = inboxPayload.inboxEpochSets[0].inboxEpoch
}
const inboxSignature = nodeSign(null, Buffer.concat([
  Buffer.from(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1, 'ascii'),
  Buffer.from([0]),
  Buffer.from(canonicalPeeritLimitedPublicInboxJsonV1(inboxPayload))
]), inboxPrivateKey).toString('hex')
const inboxBytes = Buffer.from(JSON.stringify({
  payload: inboxPayload,
  signature: inboxSignature
}, null, 2) + '\n')
assert.equal(verifyPeeritLimitedPublicInboxBootstrapArtifactV1({
  bytes: inboxBytes,
  expectedAuthorityPublicKey: decisionInboxAuthority,
  expectedReleaseSequence: 29,
  referenceUnixMillis: BigInt(Date.parse(decisionTime))
}).releaseSequence, 29,
  'the signed bootstrap authenticates at the canonical historical decision time')
assert.throws(() => verifyPeeritLimitedPublicInboxBootstrapArtifactV1({
  bytes: inboxBytes,
  expectedAuthorityPublicKey: decisionInboxAuthority,
  expectedReleaseSequence: 29,
  referenceUnixMillis: BigInt(Date.parse(staleRuntimeTime))
}), /outside the bounded public INBOX bootstrap lifetime|epoch or one-stripe shape is invalid/,
  'the same signed bootstrap fails closed against a stale runtime wall clock')
const seedBytes = Buffer.from('exact-seed-bootstrap\n')
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const decisionReleasePrivateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from('8d'.repeat(32), 'hex')
  ]),
  format: 'der',
  type: 'pkcs8'
})
const decisionReleaseKey = createPublicKey(decisionReleasePrivateKey)
  .export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
const appValue = {
  schema: 'peerit-app-artifact-v1',
  releaseSequence: 29,
  transport: 'blind-substrate',
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseKey: decisionReleaseKey,
  entry: '/index.html',
  canonicalWebAssetManifest: '/peerit-web-assets-v1.cenc',
  productionPinHistory: null,
  peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
  peeritSeedBootstrapSha256: digest(seedBytes),
  peeritSeedDiscoveryAuthorityPublicKey:
    '691d524a1c2ac38de86ed592fbae6f9a906770b96fe704d3c63397a23171f6ec',
  peeritSeedBootstrapReleaseSequence: 29,
  peeritLimitedPublicInboxBootstrap:
    '/peerit-limited-public-inbox-bootstrap-v1.json',
  peeritLimitedPublicInboxBootstrapSha256: digest(inboxBytes),
  peeritLimitedPublicInboxBootstrapAuthorityPublicKey: decisionInboxAuthority,
  peeritLimitedPublicInboxBootstrapReleaseSequence: 29,
  files: {
    'peerit-limited-public-inbox-bootstrap-v1.json': digest(inboxBytes),
    'peerit-seed-bootstrap-v1.json': digest(seedBytes)
  }
}
const appBytes = Buffer.from(JSON.stringify(appValue, null, 2) + '\n')
const canonicalManifestBytes = Buffer.from(encodePeeritWebAssetManifestV1({
  version: 1,
  releaseSequence: 29n,
  appArtifactHash: hashPeeritAppArtifactV1(appBytes),
  recommendedBootstrapHashes: [],
  assets: [
    ['/peerit-app-artifact-v1.json', appBytes],
    ['/peerit-limited-public-inbox-bootstrap-v1.json', inboxBytes],
    ['/peerit-seed-bootstrap-v1.json', seedBytes]
  ].map(([path, bytes]) => ({
    path,
    byteLength: BigInt(bytes.byteLength),
    assetHash: blake2b256(bytes)
  }))
}))
const releaseConfigBytes = Buffer.from(JSON.stringify({
  substrateProfile: 'blind-v1',
  relayHints: [],
  productionPinHistoryBundle: 'peerit-production-pin-history-v1.cenc',
  releaseSequence: 29,
  pinnedReleaseKey: decisionReleaseKey,
  peeritSeedBootstrapBundle: 'deploy/peerit-seed-bootstrap-v1-seq29.json',
  peeritSeedDiscoveryAuthorityPublicKey:
    '691d524a1c2ac38de86ed592fbae6f9a906770b96fe704d3c63397a23171f6ec',
  peeritLimitedPublicInboxBootstrapBundle:
    'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
  peeritLimitedPublicInboxBootstrapAuthorityPublicKey: decisionInboxAuthority
}, null, 2) + '\n')
const decisionFiles = {
  'deploy/peerit-seed-bootstrap-v1-seq29.json': seedBytes,
  'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json': inboxBytes,
  'deploy/web-release.json': releaseConfigBytes,
  'web/peerit-app-artifact-v1.json': appBytes,
  'web/peerit-web-assets-v1.cenc': canonicalManifestBytes
}
for (const [path, bytes] of Object.entries(decisionFiles)) {
  writeFileSync(join(decisionRoot, path), bytes)
}
const fixtureOuter = {
  releaseSequence: 29,
  driveKey: drive,
  files: {
    'peerit-seed-bootstrap-v1.json':
      digest(decisionFiles['deploy/peerit-seed-bootstrap-v1-seq29.json']),
    'peerit-limited-public-inbox-bootstrap-v1.json':
      digest(decisionFiles['deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json']),
    'peerit-app-artifact-v1.json':
      digest(decisionFiles['web/peerit-app-artifact-v1.json']),
    'peerit-web-assets-v1.cenc':
      digest(decisionFiles['web/peerit-web-assets-v1.cenc'])
  },
  controls: {},
  webRelease: {
    releaseSequence: 29,
    appArtifactHash: bytesToHex(hashPeeritAppArtifactV1(
      decisionFiles['web/peerit-app-artifact-v1.json'])),
    canonicalWebAssetManifestHash: bytesToHex(hashPeeritWebAssetManifestV1(
      decisionFiles['web/peerit-web-assets-v1.cenc'])),
    peeritSeedBootstrapSha256:
      digest(decisionFiles['deploy/peerit-seed-bootstrap-v1-seq29.json']),
    peeritLimitedPublicInboxBootstrap:
      '/peerit-limited-public-inbox-bootstrap-v1.json',
    peeritLimitedPublicInboxBootstrapSha256:
      digest(decisionFiles['deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json']),
    peeritLimitedPublicInboxBootstrapAuthorityPublicKey: decisionInboxAuthority,
    peeritLimitedPublicInboxBootstrapReleaseSequence: 29
  }
}
const fixtureOuterBytes = Buffer.from(JSON.stringify(fixtureOuter, null, 2) + '\n')
decisionFiles['web/asset-manifest.json'] = fixtureOuterBytes
writeFileSync(join(decisionRoot, 'web/asset-manifest.json'), fixtureOuterBytes)
const fixtureSignatureBytes = Buffer.from(JSON.stringify({
  alg: 'Ed25519',
  key: decisionReleaseKey,
  sig: nodeSign(null, Buffer.from(releaseSigningMessage(fixtureOuter), 'utf8'),
    decisionReleasePrivateKey).toString('hex'),
  msgVersion: 'peerit-release-v2'
}, null, 2) + '\n')
decisionFiles['web/asset-manifest.sig'] = fixtureSignatureBytes
writeFileSync(join(decisionRoot, 'web/asset-manifest.sig'), fixtureSignatureBytes)
const fixtureSigningMessageSha256 = digest(Buffer.from(
  releaseSigningMessage(fixtureOuter), 'utf8'))
const fixtureRequest = {
  schema: 'peerit-web-signing-request-v2',
  manifest: 'web/asset-manifest.json',
  signature: 'web/asset-manifest.sig',
  releaseSequence: 29,
  driveKey: drive,
  pinnedReleaseKey: decisionReleaseKey,
  manifestSha256: digest(fixtureOuterBytes),
  signingMessageSha256: fixtureSigningMessageSha256,
  artifactFiles: {
    'asset-manifest.json': digest(fixtureOuterBytes),
    'peerit-seed-bootstrap-v1.json':
      digest(decisionFiles['deploy/peerit-seed-bootstrap-v1-seq29.json']),
    'peerit-limited-public-inbox-bootstrap-v1.json':
      digest(decisionFiles['deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json']),
    'peerit-app-artifact-v1.json':
      digest(decisionFiles['web/peerit-app-artifact-v1.json']),
    'peerit-web-assets-v1.cenc':
      digest(decisionFiles['web/peerit-web-assets-v1.cenc'])
  }
}
const fixtureRequestBytes = Buffer.from(JSON.stringify(fixtureRequest, null, 2) + '\n')
decisionFiles['deploy/web-signing-request.json'] = fixtureRequestBytes
writeFileSync(join(decisionRoot, 'deploy/web-signing-request.json'), fixtureRequestBytes)

const materializationArtifacts = {
  seedBootstrap: decisionFiles['deploy/peerit-seed-bootstrap-v1-seq29.json'],
  publicInboxBootstrap:
    decisionFiles['deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json'],
  appArtifact: decisionFiles['web/peerit-app-artifact-v1.json'],
  canonicalWebAssetManifest: decisionFiles['web/peerit-web-assets-v1.cenc'],
  outerAssetManifest: decisionFiles['web/asset-manifest.json'],
  outerSignature: decisionFiles['web/asset-manifest.sig'],
  signingRequest: decisionFiles['deploy/web-signing-request.json'],
  releaseConfig: decisionFiles['deploy/web-release.json']
}
const materializationInput = {
  root: decisionRoot,
  draftBytes: decisionDraftBytes,
  expectedDraftSha256: digest(decisionDraftBytes),
  explicitConfirmation: PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1,
  decidedAt: decisionTime,
  artifacts: materializationArtifacts
}
assert.throws(() => materializePeeritSeq29OwnerDecisionV1({
  ...materializationInput,
  expectedDraftSha256: materializationInput.expectedDraftSha256.toUpperCase()
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_DRAFT_PIN_INVALID')
assert.throws(() => materializePeeritSeq29OwnerDecisionV1({
  ...materializationInput,
  expectedDraftSha256: 'ab'.repeat(32)
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_DRAFT_PIN_MISMATCH')
assert.throws(() => materializePeeritSeq29OwnerDecisionV1({
  ...materializationInput,
  explicitConfirmation: PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1 + '_DRIFT'
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_CONFIRMATION_REQUIRED')
assert.throws(() => materializePeeritSeq29OwnerDecisionV1({
  ...materializationInput,
  artifacts: {
    ...materializationArtifacts,
    signingRequest: Buffer.concat([fixtureRequestBytes, Buffer.from('drift')])
  }
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_ARTIFACT_DRIFT')
const materialized = materializePeeritSeq29OwnerDecisionV1(materializationInput)
const materializedDecisionBytes = materialized.decisionBytes
const materializedDecisionSha256 = materialized.decisionSha256
const materializedDecision = JSON.parse(materializedDecisionBytes)
assert.equal(materializedDecision.release_artifacts.release_config_sha256,
  digest(releaseConfigBytes))
const uppercaseReleaseConfigDecision = structuredClone(materializedDecision)
uppercaseReleaseConfigDecision.release_artifacts.release_config_sha256 =
  uppercaseReleaseConfigDecision.release_artifacts.release_config_sha256.toUpperCase()
const uppercaseReleaseConfigDecisionBytes = Buffer.from(JSON.stringify(
  uppercaseReleaseConfigDecision, null, 2) + '\n')
assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
  root: decisionRoot,
  decisionBytes: uppercaseReleaseConfigDecisionBytes,
  expectedDecisionSha256: digest(uppercaseReleaseConfigDecisionBytes)
}), /not fully materialized/,
'release_config_sha256 must remain canonical lowercase hex even if substituted decision bytes are repinned')
assert.equal(verifyPeeritSeq29OwnerDecisionV1({
  root: decisionRoot,
  decisionBytes: materializedDecisionBytes,
  expectedDecisionSha256: materializedDecisionSha256
}).status, 'decided')
const staleTimeDecision = structuredClone(materializedDecision)
staleTimeDecision.decided_at = staleRuntimeTime
const staleTimeDecisionBytes = Buffer.from(
  JSON.stringify(staleTimeDecision, null, 2) + '\n')
assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
  root: decisionRoot,
  decisionBytes: staleTimeDecisionBytes,
  expectedDecisionSha256: digest(staleTimeDecisionBytes)
}), /not authenticated/,
  'repinning a substituted current decision time cannot revive a stale bootstrap')
const noncanonicalTimeDecision = structuredClone(materializedDecision)
noncanonicalTimeDecision.decided_at = decisionTime.replace('.000Z', 'Z')
const noncanonicalTimeDecisionBytes = Buffer.from(
  JSON.stringify(noncanonicalTimeDecision, null, 2) + '\n')
assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
  root: decisionRoot,
  decisionBytes: noncanonicalTimeDecisionBytes,
  expectedDecisionSha256: digest(noncanonicalTimeDecisionBytes)
}), /not fully materialized/,
  'an equivalent but noncanonical decision-time spelling is rejected')
assert.deepEqual(writePeeritSeq29OwnerDecisionCreateOnlyV1({
  root: decisionRoot,
  materialized
}), {
  path: PEERIT_SEQ29_DECISION_PATH_V1,
  sha256: materializedDecisionSha256,
  sourcePin: materialized.sourcePin
})
assert.throws(() => writePeeritSeq29OwnerDecisionCreateOnlyV1({
  root: decisionRoot,
  materialized
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_CREATE_ONLY')

const decisionCliRoot = mkdtempSync(join(tmpdir(), 'peerit-seq29-decision-cli-'))
mkdirSync(join(decisionCliRoot, 'deploy'), { recursive: true })
mkdirSync(join(decisionCliRoot, 'web'), { recursive: true })
writeFileSync(join(decisionCliRoot, PEERIT_SEQ29_DECISION_DRAFT_PATH_V1),
  decisionDraftBytes)
for (const [path, fileBytes] of Object.entries(decisionFiles)) {
  writeFileSync(join(decisionCliRoot, path), fileBytes)
}
const decisionCli = spawnSync(process.execPath, [
  fileURLToPath(new URL('../scripts/seq29-owner-decision.mjs', import.meta.url)),
  'materialize',
  '--root', decisionCliRoot,
  '--expected-draft-sha256', digest(decisionDraftBytes),
  '--decided-at', decisionTime,
  '--explicit-confirmation', PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1
], { encoding: 'utf8' })
assert.equal(decisionCli.status, 0, decisionCli.stderr)
const decisionCliReceipt = JSON.parse(decisionCli.stdout)
assert.equal(decisionCliReceipt.sha256, materializedDecisionSha256)
assert.equal(digest(readFileSync(join(decisionCliRoot,
  PEERIT_SEQ29_DECISION_PATH_V1))), materializedDecisionSha256)

const stableOutputs = {
  appArtifact: appBytes,
  canonicalWebAssetManifest: canonicalManifestBytes,
  outerAssetManifest: fixtureOuterBytes,
  outerSignature: fixtureSignatureBytes,
  signingRequest: fixtureRequestBytes
}
assert.equal(verifyPeeritSeq29PinnedReprepareV1({
  sourcePin: materializedDecisionSha256,
  decisionBytes: materializedDecisionBytes,
  before: stableOutputs,
  after: stableOutputs
}).sourcePin, materializedDecisionSha256)
assert.throws(() => verifyPeeritSeq29PinnedReprepareV1({
  sourcePin: 'ab',
  decisionBytes: materializedDecisionBytes,
  before: stableOutputs,
  after: stableOutputs
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_PIN_INVALID')
assert.throws(() => verifyPeeritSeq29PinnedReprepareV1({
  sourcePin: materializedDecisionSha256.toUpperCase(),
  decisionBytes: materializedDecisionBytes,
  before: stableOutputs,
  after: stableOutputs
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_PIN_INVALID')
assert.throws(() => verifyPeeritSeq29PinnedReprepareV1({
  sourcePin: 'ab'.repeat(32),
  decisionBytes: materializedDecisionBytes,
  before: stableOutputs,
  after: stableOutputs
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_PIN_MISMATCH')
assert.throws(() => verifyPeeritSeq29PinnedReprepareV1({
  sourcePin: materializedDecisionSha256,
  decisionBytes: materializedDecisionBytes,
  before: stableOutputs,
  after: {
    ...stableOutputs,
    signingRequest: Buffer.concat([fixtureRequestBytes, Buffer.from('drift')])
  }
}), error => error.code === 'PEERIT_SEQ29_OWNER_DECISION_REPREPARE_DRIFT')

const releaseConfigPath = join(decisionRoot, 'deploy/web-release.json')
for (const [field, mutate] of [
  ['relayHints', config => {
    config.relayHints = ['https://relay-drift.example/api/blind/v1/describe']
  }],
  ['peeritSeedBootstrapBundle', config => {
    config.peeritSeedBootstrapBundle =
      'deploy/peerit-seed-bootstrap-v1-seq29-drift.json'
  }]
]) {
  const driftedReleaseConfig = JSON.parse(releaseConfigBytes)
  mutate(driftedReleaseConfig)
  writeFileSync(releaseConfigPath,
    JSON.stringify(driftedReleaseConfig, null, 2) + '\n')
  assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
    root: decisionRoot,
    decisionBytes: materializedDecisionBytes,
    expectedDecisionSha256: materializedDecisionSha256
  }), /byte-bind/,
  `canonical JSON drift in ${field} fails the exact release-config hash before publication`)
  writeFileSync(releaseConfigPath, releaseConfigBytes)
}

for (const path of Object.keys(decisionFiles)) {
  const original = readFileSync(join(decisionRoot, path))
  writeFileSync(join(decisionRoot, path), Buffer.concat([original, Buffer.from('tamper')]))
  assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
    root: decisionRoot,
    decisionBytes: materializedDecisionBytes,
    expectedDecisionSha256: materializedDecisionSha256
  }), /byte-bind|not JSON|not authenticated|not canonical/,
  `the owner decision rejects exact-byte tamper of ${path}`)
  writeFileSync(join(decisionRoot, path), original)
}
const shapeOnlyDecision = structuredClone(materializedDecision)
shapeOnlyDecision.release_artifacts.seed_bootstrap.sha256 = 'aa'.repeat(32)
const shapeOnlyDecisionBytes = Buffer.from(JSON.stringify(shapeOnlyDecision, null, 2) + '\n')
assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
  root: decisionRoot,
  decisionBytes: shapeOnlyDecisionBytes,
  expectedDecisionSha256: digest(shapeOnlyDecisionBytes)
}), /byte-bind/,
'a shape-valid substituted artifact hash cannot pass the owner decision')
const authorityOnlyDecision = structuredClone(materializedDecision)
authorityOnlyDecision.release_artifacts.public_inbox_bootstrap.authority_public_key =
  'aa'.repeat(32)
const authorityOnlyDecisionBytes = Buffer.from(
  JSON.stringify(authorityOnlyDecision, null, 2) + '\n')
assert.throws(() => verifyPeeritSeq29OwnerDecisionV1({
  root: decisionRoot,
  decisionBytes: authorityOnlyDecisionBytes,
  expectedDecisionSha256: digest(authorityOnlyDecisionBytes)
}), /not authenticated|authority key differs/,
'changing only the decision authority and repinning its bytes cannot override the signed INBOX authority')

console.log('peerit-cutover-gates: replacement-only unsigned and exact sealed release states fail/verify correctly')
