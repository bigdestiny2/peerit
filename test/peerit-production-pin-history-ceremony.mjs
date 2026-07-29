import assert from 'node:assert/strict'
import {
  createHash,
  createPrivateKey,
  createPublicKey
} from 'node:crypto'
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryBundleV1,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import { blake2b256, bytesEqual, bytesToHex } from '../js/substrate/release-control-primitives.mjs'
import {
  PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1,
  hashPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1,
  hashPeeritWebAssetManifestV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  PEERIT_SEED_BOOTSTRAP_PATH,
  finalizeProductionPinHistoryV1,
  prepareProductionPinHistoryPrefixV1,
  releaseSigningSeedFromEnvironment
} from '../scripts/production-pin-history-ceremony.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const fixtureRoot = mkdtempSync(join(tmpdir(), 'peerit-pin-ceremony-'))
const releaseSeed = '10'.repeat(32)
const wrongReleaseSeed = '90'.repeat(32)
const discoverySeed = '40'.repeat(32)
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

function publicKey (seedHex) {
  const key = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8'
  })
  return createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
}

function put (path, bytes) {
  const target = join(fixtureRoot, path)
  mkdirSync(dirname(target), { recursive: true })
  writeFileSync(target, bytes)
}

for (const path of [
  'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md',
  'protocol/peerit-profile-v1.cenc',
  'protocol/vectors/peerit-profile-v1.manifest.cenc',
  'protocol/validator/peerit-validator-v1.bundle',
  'protocol/validator/peerit-validator-v1.manifest.cenc',
  'protocol/availability-policy-v1.cenc',
  'protocol/external-authority/hiverelay-blind-wire-v1.md',
  'protocol/external-authority/hiverelay-blind-abi-v1.cenc',
  'protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc'
]) {
  const target = join(fixtureRoot, path)
  mkdirSync(dirname(target), { recursive: true })
  copyFileSync(join(root, path), target)
}

const releasePublicKey = publicKey(releaseSeed)
put('deploy/web-release.json', Buffer.from(JSON.stringify({ pinnedReleaseKey: releasePublicKey })))
const sequence12AppBytes = Buffer.from(JSON.stringify({
  schema: 'peerit-app-artifact-v1',
  releaseSequence: 12,
  releaseKey: releasePublicKey,
  productionPinHistory: null
}) + '\n')
const sequence12AppHash = hashPeeritAppArtifactV1(sequence12AppBytes)
const sequence12Asset = Buffer.from('sequence-12-fixture')
const sequence12WebBytes = encodePeeritWebAssetManifestV1({
  version: 1,
  releaseSequence: 12n,
  appArtifactHash: sequence12AppHash,
  recommendedBootstrapHashes: [],
  assets: [{
    path: '/sequence-12-fixture',
    byteLength: BigInt(sequence12Asset.byteLength),
    assetHash: blake2b256(sequence12Asset)
  }]
})
put('web/peerit-app-artifact-v1.json', sequence12AppBytes)
put('web/peerit-web-assets-v1.cenc', sequence12WebBytes)

const prepareOptions = {
  root: fixtureRoot,
  seedHex: releaseSeed,
  fixtureOnly: true,
  acceptedSequence12AppHash: bytesToHex(sequence12AppHash),
  acceptedSequence12WebHash: bytesToHex(hashPeeritWebAssetManifestV1(sequence12WebBytes))
}
const prefixA = await prepareProductionPinHistoryPrefixV1(prepareOptions)
const prefixB = await prepareProductionPinHistoryPrefixV1(prepareOptions)
assert.deepEqual(prefixA.bundleBytes, prefixB.bundleBytes, 'prefix ceremony must be deterministic')
assert.deepEqual(prefixA.metadata, prefixB.metadata)
const prefix = decodePeeritPinHistoryBundleV1(prefixA.bundleBytes)
assert.equal(prefix.pins.length, 13)
assert.equal(decodePeeritHiveRelayProfilePinV1(prefix.pins[12]).releaseSequence, 12n)
assert.match(prefixA.authorityModuleSource, new RegExp(releasePublicKey))
assert.match(prefixA.authorityModuleSource, new RegExp(bytesToHex(profilePinHash(prefix.pins[0]))))
assert.equal(prefixA.authorityModuleSource.includes(releaseSeed), false, 'seed must not enter compiled authority')
assert.equal(JSON.stringify(prefixA.metadata).includes(releaseSeed), false, 'seed must not enter public metadata')

assert.equal(releaseSigningSeedFromEnvironment({ PEERIT_RELEASE_SIGNING_SEED: releaseSeed }), releaseSeed)
assert.equal(releaseSigningSeedFromEnvironment({ PEERIT_RELEASE_SEED: releaseSeed }), releaseSeed)
assert.throws(() => releaseSigningSeedFromEnvironment({
  PEERIT_RELEASE_SIGNING_SEED: releaseSeed,
  PEERIT_RELEASE_SEED: wrongReleaseSeed
}), error => error.code === 'PEERIT_PRODUCTION_CEREMONY_KEY_MISMATCH')
await assert.rejects(prepareProductionPinHistoryPrefixV1({
  ...prepareOptions,
  seedHex: wrongReleaseSeed
}), error => error.code === 'PEERIT_PRODUCTION_CEREMONY_KEY_MISMATCH')

const discoveryPublicKey = publicKey(discoverySeed)
const dalRelayKey = '50'.repeat(32)
const sydRelayKey = '70'.repeat(32)
const bootstrap = await createPeeritSeedBootstrapV1({
  schema: PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  version: 1,
  profile: PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  operatorBoundary: PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  bootstrapSequence: 0,
  previousBootstrapHash: null,
  releaseSequence: 13,
  authorityPublicKey: discoveryPublicKey,
  issuedAt: 1_000,
  expiresAt: 10_000,
  relays: [
    {
      relayId: 'dal-1',
      canonicalDescribeUrl: 'https://dal-1.example/api/blind/v1/describe',
      continuityRootRelayPublicKey: dalRelayKey,
      storeId: '51'.repeat(32),
      descriptorGenesisHash: '52'.repeat(32),
      minimumDescriptorSequence: 0,
      familyId: 2,
      operationId: 2,
      endpointId: 1,
      transportId: 1,
      transportSupportBit: 1,
      privacyProfileBit: 1
    },
    {
      relayId: 'syd-1',
      canonicalDescribeUrl: 'https://syd-1.example/api/blind/v1/describe',
      continuityRootRelayPublicKey: sydRelayKey,
      storeId: '71'.repeat(32),
      descriptorGenesisHash: '72'.repeat(32),
      minimumDescriptorSequence: 0,
      familyId: 2,
      operationId: 2,
      endpointId: 1,
      transportId: 1,
      transportSupportBit: 1,
      privacyProfileBit: 1
    }
  ],
  records: [{
    recordId: '60'.repeat(32),
    wireKeys: ['post:fixture'],
    authorPublicKey: '61'.repeat(32),
    innerCodec: 334,
    innerLength: 8,
    sizeClass: 1,
    logicalHash: '62'.repeat(32),
    encodingCommitment: '63'.repeat(32),
    replicas: [
      {
        relayId: 'dal-1',
        targetId: 'cell-v1:dal-1:fixture',
        readCapability: {
          version: 1,
          relayPublicKey: dalRelayKey,
          storageSlot: '64'.repeat(32),
          cellKey: '65'.repeat(32),
          sizeClass: 1,
          expectedCellBlobHash: '66'.repeat(32)
        }
      },
      {
        relayId: 'syd-1',
        targetId: 'cell-v1:syd-1:fixture',
        readCapability: {
          version: 1,
          relayPublicKey: sydRelayKey,
          storageSlot: '74'.repeat(32),
          cellKey: '75'.repeat(32),
          sizeClass: 1,
          expectedCellBlobHash: '76'.repeat(32)
        }
      }
    ]
  }]
}, { seedHex: discoverySeed })
const bootstrapBytes = encodePeeritSeedBootstrapV1(bootstrap)
const bootstrapSha256 = await hashPeeritSeedBootstrapV1(bootstrapBytes)
const bootstrapDomainHash = hashPeeritBootstrapV1(bootstrapBytes)
const app13Bytes = Buffer.from(JSON.stringify({
  schema: 'peerit-app-artifact-v1',
  releaseSequence: 13,
  releaseKey: releasePublicKey,
  productionPinHistory: '/peerit-production-pin-history-v1.cenc',
  peeritSeedBootstrap: PEERIT_SEED_BOOTSTRAP_PATH,
  peeritSeedBootstrapSha256: bootstrapSha256,
  peeritSeedDiscoveryAuthorityPublicKey: discoveryPublicKey,
  peeritSeedBootstrapReleaseSequence: 13
}) + '\n')
const app13Hash = hashPeeritAppArtifactV1(app13Bytes)
const web13Bytes = encodePeeritWebAssetManifestV1({
  version: 1,
  releaseSequence: 13n,
  appArtifactHash: app13Hash,
  recommendedBootstrapHashes: [bootstrapDomainHash],
  assets: [
    {
      path: '/peerit-app-artifact-v1.json',
      byteLength: BigInt(app13Bytes.byteLength),
      assetHash: blake2b256(app13Bytes)
    },
    {
      path: PEERIT_SEED_BOOTSTRAP_PATH,
      byteLength: BigInt(bootstrapBytes.byteLength),
      assetHash: blake2b256(bootstrapBytes)
    }
  ]
})
const finalizeOptions = {
  root: fixtureRoot,
  seedHex: releaseSeed,
  releaseSequence: 13,
  issuedUnixMillis: 13_000n,
  prefixBundleBytes: prefixA.bundleBytes,
  seedBootstrapBytes: bootstrapBytes,
  appArtifactBytes: app13Bytes,
  webAssetManifestBytes: web13Bytes
}
const finalA = await finalizeProductionPinHistoryV1(finalizeOptions)
const finalB = await finalizeProductionPinHistoryV1(finalizeOptions)
assert.deepEqual(finalA.bundleBytes, finalB.bundleBytes, 'finalization must be deterministic')
const finalBundle = decodePeeritPinHistoryBundleV1(finalA.bundleBytes)
assert.equal(finalBundle.pins.length, 14)
const terminal = decodePeeritHiveRelayProfilePinV1(finalBundle.pins[13])
assert.equal(terminal.releaseSequence, 13n)
assert.equal(bytesEqual(terminal.appArtifactHash, app13Hash), true)
assert.equal(bytesEqual(terminal.webAssetManifestHash, hashPeeritWebAssetManifestV1(web13Bytes)), true)
assert.equal(bytesEqual(terminal.recommendedBootstrapHashes[0], bootstrapDomainHash), true)
assert.equal(finalA.metadata.seedBootstrap.sha256, createHash('sha256').update(bootstrapBytes).digest('hex'))

const bootstrap14 = await createPeeritSeedBootstrapV1({
  ...bootstrap.payload,
  bootstrapSequence: 1,
  previousBootstrapHash: bootstrapSha256,
  releaseSequence: 14,
  issuedAt: 10_000,
  expiresAt: 20_000
}, { seedHex: discoverySeed })
const bootstrap14Bytes = encodePeeritSeedBootstrapV1(bootstrap14)
const bootstrap14Sha256 = await hashPeeritSeedBootstrapV1(bootstrap14Bytes)
const bootstrap14DomainHash = hashPeeritBootstrapV1(bootstrap14Bytes)
const app14Bytes = Buffer.from(JSON.stringify({
  schema: 'peerit-app-artifact-v1',
  releaseSequence: 14,
  releaseKey: releasePublicKey,
  productionPinHistory: '/peerit-production-pin-history-v1.cenc',
  peeritSeedBootstrap: PEERIT_SEED_BOOTSTRAP_PATH,
  peeritSeedBootstrapSha256: bootstrap14Sha256,
  peeritSeedDiscoveryAuthorityPublicKey: discoveryPublicKey,
  peeritSeedBootstrapReleaseSequence: 14
}) + '\n')
const app14Hash = hashPeeritAppArtifactV1(app14Bytes)
const web14Bytes = encodePeeritWebAssetManifestV1({
  version: 1,
  releaseSequence: 14n,
  appArtifactHash: app14Hash,
  recommendedBootstrapHashes: [bootstrap14DomainHash],
  assets: [
    {
      path: '/peerit-app-artifact-v1.json',
      byteLength: BigInt(app14Bytes.byteLength),
      assetHash: blake2b256(app14Bytes)
    },
    {
      path: PEERIT_SEED_BOOTSTRAP_PATH,
      byteLength: BigInt(bootstrap14Bytes.byteLength),
      assetHash: blake2b256(bootstrap14Bytes)
    }
  ]
})
const final14 = await finalizeProductionPinHistoryV1({
  root: fixtureRoot,
  seedHex: releaseSeed,
  releaseSequence: 14,
  issuedUnixMillis: 14_000n,
  prefixBundleBytes: finalA.bundleBytes,
  seedBootstrapBytes: bootstrap14Bytes,
  appArtifactBytes: app14Bytes,
  webAssetManifestBytes: web14Bytes,
  previousBootstrapHash: bootstrapSha256
})
const final14Bundle = decodePeeritPinHistoryBundleV1(final14.bundleBytes)
assert.equal(final14Bundle.pins.length, 15)
assert.equal(decodePeeritHiveRelayProfilePinV1(final14Bundle.pins[14]).releaseSequence, 14n)

const tampered = Buffer.from(prefixA.bundleBytes)
tampered[tampered.length - 1] ^= 1
await assert.rejects(finalizeProductionPinHistoryV1({ ...finalizeOptions, prefixBundleBytes: tampered }))
const disordered = decodePeeritPinHistoryBundleV1(prefixA.bundleBytes)
;[disordered.pins[10], disordered.pins[11]] = [disordered.pins[11], disordered.pins[10]]
await assert.rejects(finalizeProductionPinHistoryV1({
  ...finalizeOptions,
  prefixBundleBytes: encodePeeritPinHistoryBundleV1(disordered)
}))
const wrongBootstrap = Buffer.from(bootstrapBytes)
wrongBootstrap[wrongBootstrap.length - 2] ^= 1
await assert.rejects(finalizeProductionPinHistoryV1({
  ...finalizeOptions,
  seedBootstrapBytes: wrongBootstrap
}))

console.log('peerit-production-pin-history-ceremony: deterministic prefix/finalization, exact bindings, tamper/wrong-key/order rejection green')
