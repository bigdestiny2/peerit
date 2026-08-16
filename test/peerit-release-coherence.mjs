import assert from 'node:assert/strict'
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import {
  RELEASE_ALG,
  RELEASE_MSG_VERSION,
  releaseSigningMessage
} from '../js/release-verify.js'
import {
  renderPeeritReleaseCoherenceStatusV1,
  verifyPeeritReleaseCoherenceV1
} from '../js/substrate/release-coherence.js'
import {
  buildPeeritSubstrateRuntimeArtifactV1,
  PEERIT_APP_ARTIFACT_PATH,
  PEERIT_WEB_ASSET_MANIFEST_PATH
} from '../scripts/substrate-runtime-artifact.mjs'
import {
  PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  encodePeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  canonicalPeeritLimitedPublicInboxJsonV1,
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1
} from '../js/substrate/inbox-topic-v1.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const seed = '42'.repeat(32)
const privateKey = createPrivateKey({
  key: Buffer.from(PKCS8_PREFIX + seed, 'hex'),
  format: 'der',
  type: 'pkcs8'
})
const releaseKey = createPublicKey(privateKey).export({
  type: 'spki',
  format: 'der'
}).subarray(-32).toString('hex')
const inboxPrivateKey = createPrivateKey({
  key: Buffer.from(PKCS8_PREFIX + '51'.repeat(32), 'hex'),
  format: 'der',
  type: 'pkcs8'
})
const inboxAuthorityPublicKey = createPublicKey(inboxPrivateKey).export({
  type: 'spki',
  format: 'der'
}).subarray(-32).toString('hex')
const sourceFiles = new Map(SUBSTRATE_SITE_FILES.map(path => [
  path,
  readFileSync(join(root, path))
]))

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function response (bytes, type = 'application/octet-stream') {
  bytes = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)
  return new Response(bytes, {
    status: 200,
    headers: {
      'content-length': String(bytes.byteLength),
      'content-type': type
    }
  })
}

function pageDocument (releaseSequence, relayHints, baseURI = 'https://peerit.test/') {
  const metas = new Map([
    ['peerit-release-key', releaseKey],
    ['peerit-release-sequence', String(releaseSequence)],
    ['peerit-production-web-asset-manifest', `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`]
  ])
  if (relayHints.length) metas.set('peerit-substrate-relays', relayHints.join(','))
  return {
    baseURI,
    querySelector (selector) {
      const name = selector.match(/^meta\[name="([^"]+)"\]$/)?.[1]
      if (!name || !metas.has(name)) return null
      return { getAttribute: key => key === 'content' ? metas.get(name) : null }
    }
  }
}

const seedAuthorityPublicKey = '43'.repeat(32)
const seedRelays = ['dal', 'syd'].map((relayId, index) => ({
  relayId,
  canonicalDescribeUrl: `https://${relayId}.example/api/blind/v1/describe`,
  continuityRootRelayPublicKey: (index ? '21' : '11').repeat(32),
  storeId: (index ? '22' : '12').repeat(32),
  descriptorGenesisHash: (index ? '23' : '13').repeat(32),
  minimumDescriptorSequence: 1,
  familyId: 2,
  operationId: 2,
  endpointId: 1,
  transportId: 1,
  transportSupportBit: 1,
  privacyProfileBit: 1
}))
const seedBootstrapPayload = {
    schema: PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
    version: 1,
    profile: PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
    operatorBoundary: PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
    bootstrapSequence: 0,
    previousBootstrapHash: null,
    releaseSequence: 13,
    authorityPublicKey: seedAuthorityPublicKey,
    issuedAt: 1,
    expiresAt: 10_000,
    relays: seedRelays,
    records: [{
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
    }]
}

function seedBootstrapBytes (releaseSequence) {
  return Buffer.from(encodePeeritSeedBootstrapV1({
    payload: { ...seedBootstrapPayload, releaseSequence },
    signature: '00'.repeat(64)
  }))
}

const publicInboxFixture = JSON.parse(readFileSync(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json',
  import.meta.url)))
const publicInboxPayload = structuredClone(publicInboxFixture.payload)
const publicInboxReferenceNow = BigInt(Date.now())
publicInboxPayload.artifactClass = 'LIMITED_PUBLIC_TEST_RELEASE'
publicInboxPayload.authorityPublicKey = inboxAuthorityPublicKey
publicInboxPayload.issuedUnixMillis = String(publicInboxReferenceNow - 1000n)
publicInboxPayload.expiresUnixMillis = String(
  publicInboxReferenceNow + (7n * 24n * 60n * 60n * 1000n))
publicInboxPayload.inboxEpochSets[0].inboxEpoch = Math.floor(
  Number(publicInboxReferenceNow / 21600000n) / 28)
for (const binding of publicInboxPayload.inboxEpochSets[0].bindings) {
  binding.inboxEpoch = publicInboxPayload.inboxEpochSets[0].inboxEpoch
}
const publicInboxSignature = nodeSign(null, Buffer.concat([
  Buffer.from(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1, 'ascii'),
  Buffer.from([0]),
  Buffer.from(canonicalPeeritLimitedPublicInboxJsonV1(publicInboxPayload))
]), inboxPrivateKey).toString('hex')
const publicInboxBootstrapBytes = Buffer.from(JSON.stringify({
  payload: publicInboxPayload,
  signature: publicInboxSignature
}, null, 2) + '\n')

function releaseFixture (releaseSequence, relayHints = []) {
  const releaseSeedBootstrapBytes = releaseSequence >= 13
    ? seedBootstrapBytes(releaseSequence)
    : null
  const artifact = buildPeeritSubstrateRuntimeArtifactV1({
    sourceFiles,
    substrateProfile: 'blind-v1',
    relayHints,
    releaseSequence,
    releaseKey,
    ...(releaseSequence >= 13
      ? {
          seedBootstrapBytes: releaseSeedBootstrapBytes,
          seedDiscoveryAuthorityPublicKey: seedAuthorityPublicKey
        }
      : {}),
    ...(releaseSequence >= 29
      ? {
          limitedPublicInboxBootstrapBytes: publicInboxBootstrapBytes,
          limitedPublicInboxBootstrapAuthorityPublicKey: inboxAuthorityPublicKey
        }
      : {})
  })
  const files = Object.fromEntries([...artifact.files].map(([path, bytes]) => [path, sha256(bytes)]))
  const manifest = {
    releaseSequence,
    files,
    controls: {},
    driveKey: 'cd'.repeat(32),
    webRelease: {
      releaseSequence,
      transport: 'blind-substrate',
      substrateProfile: 'blind-v1',
      relayHints,
      networkDelivery: 'profile-gated',
      legacyDestination: null,
      productionPinHistory: null,
      appArtifact: `/${PEERIT_APP_ARTIFACT_PATH}`,
      appArtifactHash: artifact.appArtifactHashHex,
      canonicalWebAssetManifest: `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`,
      canonicalWebAssetManifestHash: artifact.webAssetManifestHashHex,
      ...(artifact.seedBootstrap
        ? {
            peeritSeedBootstrap: artifact.seedBootstrap.path,
            peeritSeedBootstrapSha256: artifact.seedBootstrap.sha256,
            peeritSeedDiscoveryAuthorityPublicKey: artifact.seedBootstrap.authorityPublicKey,
            peeritSeedBootstrapReleaseSequence: artifact.seedBootstrap.releaseSequence
          }
        : {}),
      ...(artifact.inboxBootstrap
        ? {
            peeritLimitedPublicInboxBootstrap: artifact.inboxBootstrap.path,
            peeritLimitedPublicInboxBootstrapSha256: artifact.inboxBootstrap.sha256,
            peeritLimitedPublicInboxBootstrapAuthorityPublicKey:
              artifact.inboxBootstrap.authorityPublicKey,
            peeritLimitedPublicInboxBootstrapReleaseSequence:
              artifact.inboxBootstrap.releaseSequence
          }
        : {}),
      releaseKey
    }
  }
  const signature = {
    alg: RELEASE_ALG,
    msgVersion: RELEASE_MSG_VERSION,
    key: releaseKey,
    sig: nodeSign(null, Buffer.from(releaseSigningMessage(manifest)), privateKey).toString('hex')
  }
  const bodies = new Map([
    [`/${PEERIT_WEB_ASSET_MANIFEST_PATH}`, [artifact.webAssetManifestBytes, 'application/octet-stream']],
    [`/${PEERIT_APP_ARTIFACT_PATH}`, [artifact.appArtifactBytes, 'application/json']],
    ...(artifact.seedBootstrap
      ? [[artifact.seedBootstrap.path, [artifact.seedBootstrap.bytes, 'application/json']]]
      : []),
    ...(artifact.inboxBootstrap
      ? [[artifact.inboxBootstrap.path, [publicInboxBootstrapBytes, 'application/json']]]
      : []),
    ['asset-manifest.json', [Buffer.from(JSON.stringify(manifest)), 'application/json']],
    ['asset-manifest.sig', [Buffer.from(JSON.stringify(signature)), 'application/json']]
  ])
  return {
    artifact,
    manifest,
    document: pageDocument(releaseSequence, relayHints),
    fetch: async input => {
      const body = bodies.get(String(input))
      return body ? response(...body) : new Response('not found', { status: 404 })
    }
  }
}

const values = new Map()
const storage = {
  getItem: key => values.has(key) ? values.get(key) : null,
  setItem: (key, value) => values.set(key, String(value))
}
const hints = ['https://relay-a.example/']
const sequence7 = releaseFixture(7, hints)
const coherent = await verifyPeeritReleaseCoherenceV1({ ...sequence7, storage })
assert.equal(coherent.state, 'signed-release-coherent')
assert.equal(coherent.active, true)
assert.deepEqual([...coherent.relayHints], hints)
assert.equal(coherent.productionPinHistory, null)

const tamperedHints = await verifyPeeritReleaseCoherenceV1({
  ...sequence7,
  document: pageDocument(7, ['https://attacker.example/']),
  storage
})
assert.equal(tamperedHints.active, false,
  'page relay-hint drift fails even though relay URLs are only untrusted candidates')

const tamperedCanonical = await verifyPeeritReleaseCoherenceV1({
  ...sequence7,
  fetch: async input => {
    if (String(input) === `/${PEERIT_WEB_ASSET_MANIFEST_PATH}`) {
      const bytes = Buffer.from(sequence7.artifact.webAssetManifestBytes)
      bytes[bytes.length - 1] ^= 1
      return response(bytes)
    }
    return sequence7.fetch(input)
  },
  storage
})
assert.equal(tamperedCanonical.active, false,
  'canonical WebAssetManifestV1 tamper fails before relay activation')

const sequence8 = releaseFixture(8, hints)
const advanced = await verifyPeeritReleaseCoherenceV1({ ...sequence8, storage })
assert.equal(advanced.active, true)
const rollback = await verifyPeeritReleaseCoherenceV1({ ...sequence7, storage })
assert.equal(rollback.active, false)
assert.match(rollback.message, /rollback rejected/)

const hyper = releaseFixture(7, hints)
hyper.document = pageDocument(7, hints, 'hyper://' + 'ab'.repeat(32) + '/')
const contentAddressed = await verifyPeeritReleaseCoherenceV1(hyper)
assert.equal(contentAddressed.state, 'content-addressed-release-coherent')
const banner = {
  children: [],
  setAttribute () {},
  appendChild (child) { this.children.push(child) }
}
const renderDocument = {
  body: { firstChild: null, insertBefore () {} },
  getElementById: () => banner,
  createElement: () => ({ setAttribute () {}, appendChild () {} }),
  createTextNode: text => ({ textContent: text })
}
renderPeeritReleaseCoherenceStatusV1(contentAddressed, { document: renderDocument })
assert.equal(banner.children.length, 0,
  'content-addressed status does not link to a verify.html surface absent from Hyper publication')

const sequence13 = releaseFixture(13, hints)
const sequence13StorageValues = new Map()
const sequence13Storage = {
  getItem: key => sequence13StorageValues.get(key) || null,
  setItem: (key, value) => sequence13StorageValues.set(key, String(value))
}
const seededCoherent = await verifyPeeritReleaseCoherenceV1({ ...sequence13, storage: sequence13Storage })
assert.equal(seededCoherent.active, true)
assert.deepEqual(seededCoherent.seedBootstrap, {
  path: '/peerit-seed-bootstrap-v1.json',
  sha256: sequence13.artifact.seedBootstrap.sha256,
  authorityPublicKey: seedAuthorityPublicKey,
  releaseSequence: 13
})
const outerTamperManifest = structuredClone(sequence13.manifest)
outerTamperManifest.webRelease.peeritSeedBootstrapSha256 = 'ff'.repeat(32)
const outerTamperSignature = {
  alg: RELEASE_ALG,
  msgVersion: RELEASE_MSG_VERSION,
  key: releaseKey,
  sig: nodeSign(null, Buffer.from(releaseSigningMessage(outerTamperManifest)), privateKey).toString('hex')
}
const outerTampered = await verifyPeeritReleaseCoherenceV1({
  ...sequence13,
  storage: { getItem: () => null, setItem () {} },
  fetch: async input => {
    if (String(input) === 'asset-manifest.json') return response(Buffer.from(JSON.stringify(outerTamperManifest)), 'application/json')
    if (String(input) === 'asset-manifest.sig') return response(Buffer.from(JSON.stringify(outerTamperSignature)), 'application/json')
    return sequence13.fetch(input)
  }
})
assert.equal(outerTampered.active, false,
  'a newly signed outer wrapper cannot drift from the seed hash bound by the app/canonical closure')

const sequence29 = releaseFixture(29, hints)
const sequence29Coherent = await verifyPeeritReleaseCoherenceV1({
  ...sequence29,
  storage: { getItem: () => null, setItem () {} }
})
assert.equal(sequence29Coherent.active, true)
assert.deepEqual(sequence29Coherent.publicInboxBootstrap, {
  path: '/peerit-limited-public-inbox-bootstrap-v1.json',
  sha256: sequence29.artifact.inboxBootstrap.sha256,
  authorityPublicKey: inboxAuthorityPublicKey,
  releaseSequence: 29
})
const inboxOuterTamperManifest = structuredClone(sequence29.manifest)
inboxOuterTamperManifest.webRelease.peeritLimitedPublicInboxBootstrapSha256 =
  'ff'.repeat(32)
const inboxOuterTamperSignature = {
  alg: RELEASE_ALG,
  msgVersion: RELEASE_MSG_VERSION,
  key: releaseKey,
  sig: nodeSign(null,
    Buffer.from(releaseSigningMessage(inboxOuterTamperManifest)),
    privateKey).toString('hex')
}
const inboxOuterTampered = await verifyPeeritReleaseCoherenceV1({
  ...sequence29,
  storage: { getItem: () => null, setItem () {} },
  fetch: async input => {
    if (String(input) === 'asset-manifest.json') {
      return response(Buffer.from(JSON.stringify(inboxOuterTamperManifest)),
        'application/json')
    }
    if (String(input) === 'asset-manifest.sig') {
      return response(Buffer.from(JSON.stringify(inboxOuterTamperSignature)),
        'application/json')
    }
    return sequence29.fetch(input)
  }
})
assert.equal(inboxOuterTampered.active, false,
  'a newly signed outer wrapper cannot drift from the public INBOX hash bound by the app/canonical closure')

console.log('peerit-release-coherence: signed seed + Seq29 public-INBOX bindings, canonical tamper, relay-hint drift, rollback floor, and Hyper status all fail/resolve correctly')
