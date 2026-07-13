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

function releaseFixture (releaseSequence, relayHints = []) {
  const artifact = buildPeeritSubstrateRuntimeArtifactV1({
    sourceFiles,
    substrateProfile: 'blind-v1',
    relayHints,
    releaseSequence,
    releaseKey
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

console.log('peerit-release-coherence: signed bindings, canonical tamper, relay-hint drift, rollback floor, and Hyper status all fail/resolve correctly')
