import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { availabilityPolicyHash } from '../js/substrate/availability-policy.mjs'
import { genKeyPair } from '../js/crypto.js'
import { decodeBlindClientBrowserManifestV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
import {
  assemblePeeritBrowserRuntimeAuthorityV1,
  assemblePeeritBrowserRuntimeAuthorityNodeTestV1,
  fetchBoundedPeeritBrowserRuntimeAssetV1,
  getVerifiedPeeritBrowserSeedBootstrapV1,
  getVerifiedPeeritBrowserRuntimeAssembly,
  isVerifiedPeeritBrowserRuntimeAuthority,
  PEERIT_BROWSER_RUNTIME_ASSEMBLY_STATUS,
  PEERIT_BROWSER_RUNTIME_ASSET_PATHS,
  PEERIT_LIMITED_CELL_GET_RELEASE_SEQUENCE
} from '../js/substrate/browser-runtime-authority.mjs'
import {
  decodePeeritProfileRegistry,
  encodePeeritProfileRegistry,
  hashPeeritProfileAbi,
  hashPeeritProfileSpec,
  hashPeeritProfileVectorSet
} from '../js/substrate/profile-artifact-codec.mjs'
import { createPeeritProfileCodecCatalogFromIr } from '../js/substrate/profile-codec-ir.mjs'
import {
  assemblePeeritProfileExternalCodecAuthoritiesV1,
  authenticatePeeritProfileExternalCodecAuthorityV1,
  isProductionTrustedPeeritProfileExternalCodecAuthorityV1
} from '../js/substrate/profile-external-authority.mjs'
import {
  encodePeeritHiveRelayProfilePinV1,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import { blake2b256, bytesEqual } from '../js/substrate/release-control-primitives.mjs'
import {
  hashPeeritValidatorArtifactV1,
  hashPeeritValidatorVectorSetV1
} from '../js/substrate/validator-artifact.mjs'
import {
  decodePeeritWebAssetManifestV1,
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1,
  hashPeeritWebAssetManifestV1,
  verifyPeeritWebAssetBytesV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  recoverPeeritSeedWithLimitedCellGetAuthorityV1
} from '../js/substrate/relay-consumer.js'
import {
  PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  buildReleaseControlFixture,
  createNodeReleaseControlCrypto
} from '../scripts/release-control-fixture.mjs'

process.env.PEERIT_BROWSER_RUNTIME_NODE_TEST = '1'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const fixture = buildReleaseControlFixture()
const crypto = createNodeReleaseControlCrypto()
const appArtifactBytes = new TextEncoder().encode('peerit-browser-runtime-test-app-artifact-v1')

function fileBytes (assetPath) {
  if (assetPath === PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact) {
    return appArtifactBytes.slice()
  }
  return new Uint8Array(fs.readFileSync(path.join(root, assetPath.slice(1))))
}

function originalAssets () {
  return new Map(Object.values(PEERIT_BROWSER_RUNTIME_ASSET_PATHS)
    .map(assetPath => [assetPath, fileBytes(assetPath)]))
}

function withoutLimitedCellGetAssets () {
  const assets = originalAssets()
  for (const [name, assetPath] of Object.entries(
    PEERIT_BROWSER_RUNTIME_ASSET_PATHS)) {
    if (name === 'limitedCellGetProfile' || name.startsWith('hiveCellGet')) {
      assets.delete(assetPath)
    }
  }
  return assets
}

function manifestFor (assets, options = {}) {
  const currentAppArtifactBytes = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact)
  return encodePeeritWebAssetManifestV1({
    version: 1,
    releaseSequence: options.releaseSequence == null ? 0n : options.releaseSequence,
    appArtifactHash: hashPeeritAppArtifactV1(currentAppArtifactBytes),
    recommendedBootstrapHashes: options.recommendedBootstrapHashes || [],
    assets: [...assets].map(([assetPath, bytes]) => ({
      path: new TextEncoder().encode(assetPath),
      byteLength: BigInt(bytes.byteLength),
      assetHash: blake2b256(bytes)
    })).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
  })
}

function signedInputs (assets = originalAssets(), options = {}) {
  const currentAppArtifactBytes = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact)
  const releaseSequence = options.releaseSequence == null ? 0n : options.releaseSequence
  const recommendedBootstrapHashes = options.recommendedBootstrapHashes || []
  const webAssetManifestBytes = manifestFor(assets, { releaseSequence, recommendedBootstrapHashes })
  const hiveManifest = decodeBlindClientBrowserManifestV1(
    assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveManifest))
  const profileSource = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileSource)
  const profileRegistry = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry)
  const profileVectors = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileVectorManifest)
  const validator = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact)
  const validatorVectors = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorVectorManifest)
  const emitSubstrate = {
    specHash: hiveManifest.specHash,
    abiHash: hiveManifest.abiHash,
    vectorSetHash: hiveManifest.vectorSetHash
  }
  const pin = fixture.signPin({
    ...fixture.pins[0],
    emitSubstrate,
    readSubstrates: [emitSubstrate],
    profileSpecHash: hashPeeritProfileSpec(profileSource),
    profileAbiHash: hashPeeritProfileAbi(profileRegistry),
    profileVectorSetHash: hashPeeritProfileVectorSet(profileVectors),
    validatorArtifactHash: hashPeeritValidatorArtifactV1(validator),
    validatorVectorSetHash: hashPeeritValidatorVectorSetV1(validatorVectors),
    availabilityPolicyHash: availabilityPolicyHash(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.availabilityPolicy)),
    releaseSequence,
    recommendedBootstrapHashes,
    appArtifactHash: hashPeeritAppArtifactV1(currentAppArtifactBytes),
    webAssetManifestHash: hashPeeritWebAssetManifestV1(webAssetManifestBytes),
    signature: undefined
  })
  const productionPinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  return {
    assets,
    appDistributionArtifactBytes: currentAppArtifactBytes,
    webAssetManifestBytes,
    productionPinBytes,
    expectedPinHash: profilePinHash(productionPinBytes),
    expectedReleaseAuthorityPublicKey: fixture.releasePublicKey,
    expectedReleaseSequence: releaseSequence,
    crypto,
    clock: { unixMillis: 0, monotonicMillis: 100 },
    requireCompleteAssetSet: true
  }
}

const canonicalVector = new Uint8Array(fs.readFileSync(path.join(
  root, 'protocol/validator/vectors/positive/0077-WebAssetManifestV1.cenc')))
const decodedVector = decodePeeritWebAssetManifestV1(canonicalVector)
assert.equal(bytesEqual(encodePeeritWebAssetManifestV1(decodedVector), canonicalVector), true,
  'dedicated WebAssetManifestV1 codec equals the generated profile codec vector')

const valid = signedInputs(withoutLimitedCellGetAssets())
const authority = await assemblePeeritBrowserRuntimeAuthorityNodeTestV1(valid)
assert.equal(isVerifiedPeeritBrowserRuntimeAuthority(authority), true)
assert.equal(isVerifiedPeeritBrowserRuntimeAuthority({ ...authority }), false,
  'shape-copying an authority cannot copy its module brand')
const assembled = getVerifiedPeeritBrowserRuntimeAssembly(authority)
assert.equal(assembled.limitedCellGet, null,
  'authorities outside sequence 20 do not assemble the limited recovery surface')
assert.equal(typeof assembled.control.createCellReplica, 'function')
assert.equal(typeof assembled.control.decodeBlindExternalProfileValueV1, 'function')
assert.equal(assembled.validatorArtifactAuthenticated, true)
assert.equal(assembled.validatorInstantiationAuthorized, false,
  'caller-selected external codec callbacks never become a profile validator authority')
assert.equal(typeof assembled.createRelayAdapter, 'function')
assert.equal(authority.epochDeadlineMonotonicMillis(1n), 21600100)

const seedAuthorityPublicKey = '43'.repeat(32)
const seedBytes = new Uint8Array(encodePeeritSeedBootstrapV1({
  payload: {
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
    relays: ['dal', 'syd'].map((relayId, index) => ({
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
    })),
    records: [{
      recordId: '31'.repeat(32),
      wireKeys: ['v2!seed'],
      authorPublicKey: '32'.repeat(32),
      innerCodec: 334,
      innerLength: 8,
      sizeClass: 1,
      logicalHash: '33'.repeat(32),
      encodingCommitment: '34'.repeat(32),
      replicas: [
        ['dal', '11', '41', '51', '61'],
        ['syd', '21', '42', '52', '62']
      ].map(([relayId, relayKey, slot, cell, blob]) => ({
        relayId,
        targetId: `cell-v1:${relayId}:seed`,
        readCapability: {
          version: 1,
          relayPublicKey: relayKey.repeat(32),
          storageSlot: slot.repeat(32),
          cellKey: cell.repeat(32),
          sizeClass: 1,
          expectedCellBlobHash: blob.repeat(32)
        }
      }))
    }]
  },
  signature: '00'.repeat(64)
}))
const seedSha256 = createHash('sha256').update(seedBytes).digest('hex')
const seedAppArtifactBytes = new TextEncoder().encode(JSON.stringify({
  schema: 'peerit-app-artifact-v1',
  releaseSequence: 13,
  peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
  peeritSeedBootstrapSha256: seedSha256,
  peeritSeedDiscoveryAuthorityPublicKey: seedAuthorityPublicKey,
  peeritSeedBootstrapReleaseSequence: 13
}) + '\n')
const seedAssets = withoutLimitedCellGetAssets()
seedAssets.set(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact, seedAppArtifactBytes)
seedAssets.set('/peerit-seed-bootstrap-v1.json', seedBytes)
const seedDomainHash = hashPeeritBootstrapV1(seedBytes)
const seededAuthority = await assemblePeeritBrowserRuntimeAuthorityNodeTestV1(
  signedInputs(seedAssets, { releaseSequence: 13n, recommendedBootstrapHashes: [seedDomainHash] }))
const authenticatedSeed = getVerifiedPeeritBrowserSeedBootstrapV1(seededAuthority)
assert.equal(getVerifiedPeeritBrowserRuntimeAssembly(seededAuthority).limitedCellGet, null,
  'sequence 13 remains compatible without the sequence-20 recovery assets')
assert.deepEqual(authenticatedSeed.artifactBytes, seedBytes)
assert.deepEqual(authenticatedSeed.verification, {
  authorityPublicKey: seedAuthorityPublicKey,
  releaseSequence: 13,
  expectedArtifactHash: seedSha256,
  previousBootstrapHash: null
})
const reboundTamperAssets = new Map(seedAssets)
const reboundTamper = seedBytes.slice()
reboundTamper[reboundTamper.length - 2] = reboundTamper[reboundTamper.length - 2] === 0x30 ? 0x31 : 0x30
reboundTamperAssets.set('/peerit-seed-bootstrap-v1.json', reboundTamper)
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityNodeTestV1(signedInputs(
  reboundTamperAssets,
  { releaseSequence: 13n, recommendedBootstrapHashes: [hashPeeritBootstrapV1(reboundTamper)] }
)), error => error.code === 'PRODUCTION_SEED_BOOTSTRAP_BINDING_MISMATCH')

const seed25Value = JSON.parse(new TextDecoder().decode(seedBytes))
const seed25Authority = await genKeyPair()
seed25Value.payload.releaseSequence = 25
seed25Value.payload.authorityPublicKey = seed25Authority.pubHex
seed25Value.payload.issuedAt = 1_000
seed25Value.payload.expiresAt = 10_000
const seed25Artifact = await createPeeritSeedBootstrapV1(
  seed25Value.payload, { seedHex: seed25Authority.seedHex })
const seed25Bytes = new Uint8Array(encodePeeritSeedBootstrapV1(seed25Artifact))
const seed25Sha256 = createHash('sha256').update(seed25Bytes).digest('hex')
const seed25AppArtifactBytes = new TextEncoder().encode(JSON.stringify({
  schema: 'peerit-app-artifact-v1',
  releaseSequence: 25,
  peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
  peeritSeedBootstrapSha256: seed25Sha256,
  peeritSeedDiscoveryAuthorityPublicKey: seed25Authority.pubHex,
  peeritSeedBootstrapReleaseSequence: 25
}) + '\n')
const seed25Assets = originalAssets()
seed25Assets.set(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact, seed25AppArtifactBytes)
seed25Assets.set('/peerit-seed-bootstrap-v1.json', seed25Bytes)
const seed25DomainHash = hashPeeritBootstrapV1(seed25Bytes)
const authority25 = await assemblePeeritBrowserRuntimeAuthorityNodeTestV1(
  signedInputs(seed25Assets, {
    releaseSequence: 25n,
    recommendedBootstrapHashes: [seed25DomainHash]
  }))
const assembled25 = getVerifiedPeeritBrowserRuntimeAssembly(authority25)
assert.equal(PEERIT_LIMITED_CELL_GET_RELEASE_SEQUENCE, 25)
assert.equal(Object.hasOwn(assembled25, 'seedBootstrap'), false,
  'release-bound seed bytes remain outside the exposed runtime assembly')
assert.deepEqual(Object.keys(assembled25.limitedCellGet.control).sort(), [
  'createBlindCellGetControl',
  'createBrowserCryptoRuntime'
])
const limitedProfile25 = assembled25.limitedCellGet.profileSnapshot()
assert.equal(limitedProfile25.releaseSequence, 25)
assert.equal(limitedProfile25.networkPuts, 0)
assert.equal(limitedProfile25.ordinaryDelivery, 'local-only')
assert.equal(limitedProfile25.requirement.familyId, 2)
assert.equal(limitedProfile25.requirement.operationId, 2)
assert.equal(Buffer.from(limitedProfile25.relays[0].admissionProfile.parameterUrl).toString('hex'),
  '68747470733a2f2f65766964656e63652e6578616d706c653a3434332f61646d697373696f6e2e63656e63')
limitedProfile25.supportedProtocolProfiles[0].profileHash[0] ^= 0xff
limitedProfile25.relays[0].admissionProfile.parameterUrl[0] ^= 0xff
limitedProfile25.relays[0].admissionProfile.parameterUrl[0] ^= 0xff
const secondLimitedProfile25 = assembled25.limitedCellGet.profileSnapshot()
assert.equal(secondLimitedProfile25.supportedProtocolProfiles[0].profileHash[0], 0x0a)
assert.equal(secondLimitedProfile25.relays[0].admissionProfile.parameterUrl[0], 0x68)
// The admission parameterHash is descriptor-driven (rotating) and must NOT be
// pinned by the release profile.
assert.equal(secondLimitedProfile25.relays[0].admissionProfile.parameterHash, undefined)
assert.equal(secondLimitedProfile25.relays[0].admissionProfile.profileId, 7)
assert.equal(secondLimitedProfile25.relays[0].admissionProfile.schemeId, 9)
assert.equal(secondLimitedProfile25.relays[0].admissionProfile.conformanceClass, 1)
assert.equal(secondLimitedProfile25.relays[0].admissionProfile.roleBits, 49)

for (const sequence of [17, 18]) {
  const priorPayload = JSON.parse(JSON.stringify(seed25Value.payload))
  priorPayload.releaseSequence = sequence
  const priorArtifact = await createPeeritSeedBootstrapV1(
    priorPayload, { seedHex: seed25Authority.seedHex })
  const priorBytes = new Uint8Array(encodePeeritSeedBootstrapV1(priorArtifact))
  const priorAppArtifactBytes = new TextEncoder().encode(JSON.stringify({
    schema: 'peerit-app-artifact-v1',
    releaseSequence: sequence,
    peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
    peeritSeedBootstrapSha256: createHash('sha256').update(priorBytes).digest('hex'),
    peeritSeedDiscoveryAuthorityPublicKey: seed25Authority.pubHex,
    peeritSeedBootstrapReleaseSequence: sequence
  }) + '\n')
  const priorAssets = withoutLimitedCellGetAssets()
  priorAssets.set(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact, priorAppArtifactBytes)
  priorAssets.set('/peerit-seed-bootstrap-v1.json', priorBytes)
  const priorAuthority = await assemblePeeritBrowserRuntimeAuthorityNodeTestV1(
    signedInputs(priorAssets, {
      releaseSequence: BigInt(sequence),
      recommendedBootstrapHashes: [hashPeeritBootstrapV1(priorBytes)]
    }))
  assert.equal(getVerifiedPeeritBrowserRuntimeAssembly(priorAuthority).limitedCellGet, null,
    `superseded sequence ${sequence} cannot acquire sequence-20 Cell GET authority`)
}

const verifiedSeed25 = await verifyPeeritSeedBootstrapV1(seed25Bytes, {
  authorityPublicKey: seed25Authority.pubHex,
  releaseSequence: 25,
  expectedArtifactHash: seed25Sha256,
  previousBootstrapHash: null,
  now: 5_000
})
const returnedSeed25 = getVerifiedPeeritBrowserSeedBootstrapV1(authority25)
returnedSeed25.artifactBytes[0] ^= 0xff
assert.deepEqual(
  getVerifiedPeeritBrowserSeedBootstrapV1(authority25).artifactBytes,
  seed25Bytes,
  'returned seed bytes cannot mutate the authority-owned recovery input')
let limitedRecoveryFetches = 0
const cachedRecoverySync = {
  async discoveryFloor (sourceId) {
    assert.equal(sourceId, verifiedSeed25.sourceId)
    return {
      checkpointSequence: verifiedSeed25.payload.bootstrapSequence,
      checkpointHash: verifiedSeed25.artifactHash
    }
  },
  async ingestVerifiedRemoteBatch () {
    throw new Error('cached recovery must not ingest')
  },
  setRelays () {
    throw new Error('limited recovery must not install relay targets')
  }
}
const cachedRecovery = await recoverPeeritSeedWithLimitedCellGetAuthorityV1({
  releaseAuthority: authority25,
  sync: cachedRecoverySync,
  now: () => 5_000,
  fetch: async () => {
    limitedRecoveryFetches++
    throw new Error('cached recovery must not fetch')
  }
})
assert.equal(cachedRecovery.cached, true)
assert.equal(cachedRecovery.networkGets, 0)
assert.equal(cachedRecovery.networkPuts, 0)
assert.equal(cachedRecovery.qualifiedRelayCount, 0)
assert.equal(limitedRecoveryFetches, 0)
await assert.rejects(recoverPeeritSeedWithLimitedCellGetAuthorityV1({
  releaseAuthority: authority25,
  sync: cachedRecoverySync,
  artifactBytes: seed25Bytes,
  verification: {},
  fetch: async () => { limitedRecoveryFetches++ }
}), error => error.code === 'PEERIT_LIMITED_SEED_AUTHORITY_INJECTION')
assert.equal(limitedRecoveryFetches, 0,
  'caller seed substitution fails before relay I/O')

for (const rollbackSequence of [24, 26]) {
  const rollbackPayload = JSON.parse(JSON.stringify(seed25Value.payload))
  rollbackPayload.releaseSequence = rollbackSequence
  const rollbackArtifact = await createPeeritSeedBootstrapV1(
    rollbackPayload, { seedHex: seed25Authority.seedHex })
  const rollbackBytes = new Uint8Array(encodePeeritSeedBootstrapV1(rollbackArtifact))
  const rollbackSha256 = createHash('sha256').update(rollbackBytes).digest('hex')
  const rollbackAppArtifactBytes = new TextEncoder().encode(JSON.stringify({
    schema: 'peerit-app-artifact-v1',
    releaseSequence: rollbackSequence,
    peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
    peeritSeedBootstrapSha256: rollbackSha256,
    peeritSeedDiscoveryAuthorityPublicKey: seed25Authority.pubHex,
    peeritSeedBootstrapReleaseSequence: rollbackSequence
  }) + '\n')
  const rollbackAssets = withoutLimitedCellGetAssets()
  rollbackAssets.set(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact, rollbackAppArtifactBytes)
  rollbackAssets.set('/peerit-seed-bootstrap-v1.json', rollbackBytes)
  const rollbackAuthority = await assemblePeeritBrowserRuntimeAuthorityNodeTestV1(
    signedInputs(rollbackAssets, {
      releaseSequence: BigInt(rollbackSequence),
      recommendedBootstrapHashes: [hashPeeritBootstrapV1(rollbackBytes)]
    }))
  assert.equal(getVerifiedPeeritBrowserRuntimeAssembly(rollbackAuthority).limitedCellGet, null,
    `sequence ${rollbackSequence} is a cold fail-closed runtime without GET authority after the seq-20 launch-slot decision`)
  let rollbackFetches = 0
  await assert.rejects(recoverPeeritSeedWithLimitedCellGetAuthorityV1({
    releaseAuthority: rollbackAuthority,
    sync: cachedRecoverySync,
    now: () => 5_000,
    fetch: async () => { rollbackFetches++ }
  }), error => error.code === 'PEERIT_LIMITED_CELL_GET_CONTROL_INVALID')
  assert.equal(rollbackFetches, 0,
    `sequence ${rollbackSequence} fails closed before relay I/O`)
}

const badLimitedProfileAssets = new Map(seed25Assets)
const badLimitedProfilePath = PEERIT_BROWSER_RUNTIME_ASSET_PATHS.limitedCellGetProfile
const badLimitedProfile = JSON.parse(new TextDecoder().decode(
  badLimitedProfileAssets.get(badLimitedProfilePath)))
badLimitedProfile.networkPuts = 1
badLimitedProfileAssets.set(badLimitedProfilePath,
  new TextEncoder().encode(JSON.stringify(badLimitedProfile, null, 2) + '\n'))
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityNodeTestV1(
  signedInputs(badLimitedProfileAssets, {
    releaseSequence: 25n,
    recommendedBootstrapHashes: [seed25DomainHash]
  })), error => error.code === 'PEERIT_LIMITED_CELL_GET_PROFILE_INVALID')

const productionExternalAuthorities = await assemblePeeritProfileExternalCodecAuthoritiesV1(authority)
assert.deepEqual(Object.keys(productionExternalAuthorities).sort(), [
  'BlindCoreAckV1',
  'BlindCoreReadCapV1',
  'BlindReceiptV1',
  'InboxAppendAckV1',
  'InboxReceiptV1',
  'ReadCellCapV1'
])
for (const externalAuthority of Object.values(productionExternalAuthorities)) {
  assert.equal(isProductionTrustedPeeritProfileExternalCodecAuthorityV1(externalAuthority), true)
}
const readCellCapBytes = new Uint8Array(99)
readCellCapBytes[0] = 1
readCellCapBytes.fill(0x11, 1, 33)
readCellCapBytes.fill(0x22, 33, 65)
readCellCapBytes.fill(0x33, 65, 97)
readCellCapBytes[97] = 1
readCellCapBytes[98] = 0
productionExternalAuthorities.ReadCellCapV1.assertCanonical(readCellCapBytes, 'ReadCellCapV1')
assert.throws(
  () => productionExternalAuthorities.ReadCellCapV1.assertCanonical(readCellCapBytes, 'BlindCoreAckV1'),
  error => error.code === 'PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH'
)
assert.throws(
  () => assembled.control.decodeBlindExternalProfileValueV1('UnknownAppRecordV1', readCellCapBytes),
  error => error.code === 'BAD_ENCODING'
)

const productionCompiled = Object.freeze({
  version: 1,
  schemas: Object.freeze(assembled.registry.schemas.map(row => row.codecIr))
})
const productionInventory = Object.freeze({
  schemas: assembled.registry.schemas,
  externalTypes: assembled.registry.externalTypes,
  externalCodecImports: assembled.registry.externalCodecImports,
  profileRegistries: assembled.registry.profileRegistries
})
assert.equal(Object.keys(createPeeritProfileCodecCatalogFromIr(
  productionCompiled,
  productionInventory,
  { externalAuthorities: productionExternalAuthorities, production: true }
)).length, 78)
const clientArtifacts = {
  formatAuthorityBytes: new Uint8Array(fs.readFileSync(path.join(
    root, 'protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'))),
  vectorManifestBytes: new Uint8Array(fs.readFileSync(path.join(
    root, 'protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')))
}
const auditReadCellAuthority = authenticatePeeritProfileExternalCodecAuthorityV1({
  name: 'ReadCellCapV1',
  authorityKind: 'CLIENT_COMPOSITION_V1',
  authorityBinding: assembled.registry.externalCodecImports.find(row => row.name === 'ReadCellCapV1').tupleBinding,
  artifacts: clientArtifacts,
  assertCanonical () {}
})
assert.equal(isProductionTrustedPeeritProfileExternalCodecAuthorityV1(auditReadCellAuthority), false)
assert.throws(() => createPeeritProfileCodecCatalogFromIr(
  productionCompiled,
  productionInventory,
  {
    externalAuthorities: Object.freeze({
      ...productionExternalAuthorities,
      ReadCellCapV1: auditReadCellAuthority
    }),
    production: true
  }
), error => error.code === 'PROFILE_EXTERNAL_CODEC_PRODUCTION_AUTHORITY_REQUIRED')

const missing = signedInputs()
missing.assets.delete(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveCrossHostEvidence)
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityNodeTestV1({
  ...missing
}), error => error.code === 'WEB_ASSET_MISSING')

function changed (value) {
  const output = value.slice()
  output[Math.floor(output.byteLength / 2)] ^= 1
  return output
}

function divergentProfileRegistry (value) {
  const registry = decodePeeritProfileRegistry(value)
  const source = new TextDecoder().decode(registry.profileSourceBytes)
  const divergent = source.replace(
    '### 9.6 VNext inner operation envelope',
    '### 9.6 Browser test divergent VNext inner operation envelope'
  )
  assert.notEqual(divergent, source)
  return encodePeeritProfileRegistry({
    ...registry,
    profileSourceBytes: new TextEncoder().encode(divergent)
  })
}

for (const assetPath of [
  PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveArtifact,
  PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry,
  PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact
]) {
  const substitutedAssets = originalAssets()
  substitutedAssets.set(assetPath,
    assetPath === PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry
      ? divergentProfileRegistry(substitutedAssets.get(assetPath))
      : changed(substitutedAssets.get(assetPath)))
  const substituted = signedInputs(substitutedAssets)
  await assert.rejects(assemblePeeritBrowserRuntimeAuthorityNodeTestV1(substituted), error => [
    'BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT',
    'PROFILE_REGISTRY_INVALID',
    'PROFILE_SOURCE_BINDING_MISMATCH',
    'PROFILE_VALIDATOR_RUNTIME_BINDING_MISMATCH',
    'BROWSER_RUNTIME_MODULE_IMPORT_FAILED'
  ].includes(error.code) || error instanceof SyntaxError)
}

const badEvidenceAssets = originalAssets()
const badEvidencePath = PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveChromiumEvidence
const badEvidence = JSON.parse(new TextDecoder().decode(badEvidenceAssets.get(badEvidencePath)))
badEvidence.passed = false
badEvidenceAssets.set(badEvidencePath,
  new TextEncoder().encode(JSON.stringify(badEvidence, null, 2) + '\n'))
const badEvidenceInput = signedInputs(badEvidenceAssets)
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityNodeTestV1(badEvidenceInput),
  error => error.code === 'BAD_BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE')

const rollback = signedInputs()
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityNodeTestV1({
  ...rollback,
  expectedReleaseSequence: 1n
}), error => error.code === 'PRODUCTION_PROFILE_PIN_AUTHORITY_MISMATCH')
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityNodeTestV1({
  ...rollback,
  expectedPinHash: changed(rollback.expectedPinHash)
}), error => error.code === 'PRODUCTION_PROFILE_PIN_HASH_MISMATCH')

let attackerImporterCalls = 0
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityV1({
  ...valid,
  importModule: async () => { attackerImporterCalls++; return {} }
}), error => error.code === 'BROWSER_RUNTIME_AUTHORITY_INJECTION')
assert.equal(attackerImporterCalls, 0, 'caller module importers cannot reach the production minter')
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityV1({
  ...valid,
  crypto: { verifyEd25519: async () => true }
}), error => error.code === 'BROWSER_RUNTIME_AUTHORITY_INJECTION')
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityV1({
  pinHistoryTerminal: {},
  clock: { unixMillis: 0, monotonicMillis: 0 }
}), error => error.code === 'BROWSER_RUNTIME_AUTHORITY_INJECTION')
await assert.rejects(assemblePeeritBrowserRuntimeAuthorityV1({
  pinHistoryTerminal: {},
  expectedPinHash: valid.expectedPinHash
}), error => error.code === 'BROWSER_RUNTIME_AUTHORITY_INJECTION')

function streamedResponse (payload, options = {}) {
  payload = payload instanceof Uint8Array ? payload : new TextEncoder().encode(payload)
  let cancelled = false
  const chunks = options.chunks || [payload]
  const reader = {
    index: 0,
    async read () {
      if (options.pending) return new Promise(() => {})
      if (this.index >= chunks.length) return { done: true }
      return { done: false, value: chunks[this.index++] }
    },
    async cancel () { cancelled = true },
    releaseLock () {}
  }
  const headers = new Map([
    ['content-type', options.contentType || 'text/javascript'],
    ['content-length', options.contentLength == null ? String(payload.byteLength) : String(options.contentLength)]
  ])
  if (options.missingLength) headers.delete('content-length')
  return {
    response: {
      ok: options.ok !== false,
      url: options.url || '',
      headers: { get: name => headers.get(String(name).toLowerCase()) || null },
      body: options.noStream ? null : { getReader: () => reader },
      arrayBuffer: async () => { throw new Error('unbounded arrayBuffer fallback must never run') }
    },
    wasCancelled: () => cancelled
  }
}

const boundedPayload = new TextEncoder().encode('export const bounded = true\n')
let observedFetchOptions = null
const bounded = streamedResponse(boundedPayload)
assert.deepEqual(await fetchBoundedPeeritBrowserRuntimeAssetV1({
  fetch: async (_url, options) => { observedFetchOptions = options; return bounded.response },
  url: 'https://peerit.test/runtime.mjs',
  path: '/runtime.mjs',
  maximumBytes: 1024,
  expectedLength: boundedPayload.byteLength
}), boundedPayload)
assert.equal(observedFetchOptions.cache, 'reload')
assert.equal(observedFetchOptions.credentials, 'omit')
assert.equal(observedFetchOptions.redirect, 'error')
assert.ok(observedFetchOptions.signal instanceof AbortSignal)

for (const [responseFixture, expectedCode] of [
  [streamedResponse(boundedPayload, { noStream: true }), 'BROWSER_RUNTIME_ASSET_STREAM_REQUIRED'],
  [streamedResponse(boundedPayload, { missingLength: true }), 'BROWSER_RUNTIME_ASSET_LENGTH_INVALID'],
  [streamedResponse(boundedPayload, { contentType: 'text/html' }), 'BROWSER_RUNTIME_ASSET_CONTENT_TYPE_INVALID'],
  [streamedResponse(boundedPayload, { contentLength: boundedPayload.byteLength + 1 }), 'BROWSER_RUNTIME_ASSET_LENGTH_INVALID'],
  [streamedResponse(boundedPayload, { chunks: [boundedPayload, new Uint8Array([1])], contentLength: boundedPayload.byteLength }), 'BROWSER_RUNTIME_ASSET_LENGTH_INVALID'],
  [streamedResponse(boundedPayload, { url: 'https://peerit.test/alias.mjs' }), 'BROWSER_RUNTIME_ASSET_FETCH_FAILED']
]) {
  await assert.rejects(fetchBoundedPeeritBrowserRuntimeAssetV1({
    fetch: async () => responseFixture.response,
    url: 'https://peerit.test/runtime.mjs',
    path: '/runtime.mjs',
    maximumBytes: 1024
  }), error => error.code === expectedCode)
  if (responseFixture.response.body) assert.equal(responseFixture.wasCancelled(), true)
}

const stalled = streamedResponse(boundedPayload, { pending: true })
await assert.rejects(fetchBoundedPeeritBrowserRuntimeAssetV1({
  fetch: async () => stalled.response,
  url: 'https://peerit.test/runtime.mjs',
  path: '/runtime.mjs',
  maximumBytes: 1024,
  timeoutMillis: 10
}), error => error.code === 'BROWSER_RUNTIME_ASSET_FETCH_TIMEOUT')
assert.equal(stalled.wasCancelled(), true, 'deadline cancellation reaches the streaming reader')

for (const unsafePath of [
  '/a/%2e%2e/b.js',
  '/a//b.js',
  '/a/../b.js',
  '/a/:b.js',
  '/a/line\nb.js'
]) {
  const unsafeManifest = {
    version: 1,
    releaseSequence: 0n,
    appArtifactHash: new Uint8Array(32),
    recommendedBootstrapHashes: [],
    assets: [{ path: unsafePath, byteLength: 0n, assetHash: blake2b256(new Uint8Array()) }]
  }
  assert.throws(() => verifyPeeritWebAssetBytesV1(unsafeManifest,
    new Map([[unsafePath, new Uint8Array()]])), error => error.code === 'BAD_WEB_ASSET_PATH')
}

const manifest = decodePeeritWebAssetManifestV1(valid.webAssetManifestBytes)
assert.equal(verifyPeeritWebAssetBytesV1(manifest, valid.assets, { requireComplete: true }).complete, true)
assert.equal(PEERIT_BROWSER_RUNTIME_ASSEMBLY_STATUS.completeSignedWebAssetContentFetchReady, true)
assert.equal(PEERIT_BROWSER_RUNTIME_ASSEMBLY_STATUS.releaseReady, false)
assert.deepEqual(PEERIT_BROWSER_RUNTIME_ASSEMBLY_STATUS.releaseBlockers, [
  'PRODUCTION_PEERIT_SIGNED_PROFILE_PIN_UNAVAILABLE',
  'PRODUCTION_APP_DISTRIBUTION_ARTIFACT_UNAVAILABLE',
  'PRODUCTION_CANONICAL_WEB_ASSET_MANIFEST_UNAVAILABLE',
  'AUTHENTICATED_PROFILE_EXTERNAL_CODEC_DECODERS_UNASSEMBLED',
  'FIRST_VISIT_EXECUTING_VERIFIER_ORIGIN_BOOTSTRAP_UNRESOLVED'
])

console.log('peerit-browser-runtime-authority: signed pin, exact assets/evidence, profile, validator, rollback, and authenticated module assembly passed')
