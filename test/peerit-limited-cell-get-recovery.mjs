import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { canonical } from '../js/canon.js'
import { genKeyPair, ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { createSync, memoryStorage } from '../js/sync.js'
import { availabilityPolicyHash } from '../js/substrate/availability-policy.mjs'
import { decodeBlindClientBrowserManifestV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
import {
  assemblePeeritBrowserRuntimeAuthorityNodeTestV1,
  PEERIT_BROWSER_RUNTIME_ASSET_PATHS
} from '../js/substrate/browser-runtime-authority.mjs'
import {
  hashPeeritProfileAbi,
  hashPeeritProfileSpec,
  hashPeeritProfileVectorSet
} from '../js/substrate/profile-artifact-codec.mjs'
import {
  JOURNAL_STORES,
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import {
  createPeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from '../js/substrate/peerit-operation-authority-v1.js'
import {
  encodePeeritHiveRelayProfilePinV1,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import {
  blake2b256
} from '../js/substrate/release-control-primitives.mjs'
import {
  recoverPeeritSeedWithLimitedCellGetAuthorityV1
} from '../js/substrate/relay-consumer.js'
import {
  PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  hashPeeritValidatorArtifactV1,
  hashPeeritValidatorVectorSetV1
} from '../js/substrate/validator-artifact.mjs'
import {
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1,
  hashPeeritWebAssetManifestV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  buildReleaseControlFixture,
  createNodeReleaseControlCrypto
} from '../scripts/release-control-fixture.mjs'

process.env.PEERIT_BROWSER_RUNTIME_NODE_TEST = '1'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const hiveRoot = process.env.HIVERELAY_BLIND_ROOT ||
  '/private/tmp/hiverelay-seed-head-bootstrap'
const protocolRoot = path.join(hiveRoot, 'packages/blind-protocol')
const clientRoot = path.join(hiveRoot, 'packages/blind-client')

for (const required of [
  path.join(protocolRoot, 'index.js'),
  path.join(clientRoot, 'requests.js'),
  path.join(clientRoot, 'runtime/node.js')
]) {
  assert.equal(fs.existsSync(required), true,
    `accepted HiveRelay fixture source is required: ${required}`)
}

const protocol = await import(pathToFileURL(path.join(protocolRoot, 'index.js')))
const { createCellReplica } = await import(pathToFileURL(path.join(clientRoot, 'requests.js')))
const { createNodeCryptoRuntime } = await import(
  pathToFileURL(path.join(clientRoot, 'runtime/node.js')))
const sodiumModule = await import(pathToFileURL(path.join(
  hiveRoot, 'node_modules/sodium-universal/index.js')))
const sodium = sodiumModule.default || sodiumModule

const TEST_EPOCH = 101
const TEST_NOW = TEST_EPOCH * 21_600_000 + 1_000
const RELEASE_SEQUENCE = 26n
const EXACT_PARAMETER_URL = 'https://evidence.example:443/admission.cenc'
const EXACT_PARAMETER_URL_BYTES = Buffer.from(EXACT_PARAMETER_URL, 'utf8')
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()
const releaseFixture = buildReleaseControlFixture()
const releaseCrypto = createNodeReleaseControlCrypto()
const descriptorVector = new Uint8Array(fs.readFileSync(path.join(
  protocolRoot, 'vectors/draft/describe/service-descriptor.bin')))
const limitedProfile = JSON.parse(fs.readFileSync(path.join(
  root, 'peerit-limited-cell-get-profile-v1.json'), 'utf8'))

function hex (value) {
  return Buffer.from(value).toString('hex')
}

function bytes (value) {
  return new Uint8Array(value)
}

function fill (length, value) {
  return new Uint8Array(length).fill(value)
}

function keyPair (seedByte) {
  const publicKey = Buffer.alloc(32)
  const secretKey = Buffer.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, Buffer.alloc(32, seedByte))
  return Object.freeze({ publicKey, secretKey })
}

function signedValue (encoding, value, domainId, secretKey) {
  value.signature = Buffer.alloc(64)
  const complete = protocol.encodeCanonical(encoding, value)
  const unsigned = complete.subarray(0, complete.byteLength - 64)
  sodium.crypto_sign_detached(
    value.signature,
    protocol.resultSignaturePayload(domainId, unsigned),
    secretKey
  )
  return protocol.encodeCanonical(encoding, value)
}

function durabilityBinding (durability) {
  return {
    version: 1,
    profileId: durability.profileId,
    externalJournalId: durability.externalJournalId,
    externalWitnessPublicKey: durability.externalWitnessPublicKey,
    externalJournalReplicationClass: durability.externalJournalReplicationClass,
    externalJournalFailureGroupId: durability.externalJournalFailureGroupId,
    restoreEvidenceFeedId: durability.restoreEvidenceFeedId
  }
}

function signedDescriptor ({
  keys,
  canonicalDescribeUrl,
  storeId,
  admissionParameterUrl,
  admissionParameterHash,
  descriptorSequence,
  previousDescriptorHash,
  nonceByte
}) {
  const value = protocol.decodeCanonical(
    protocol.blindServiceDescriptorV1,
    descriptorVector,
    { copyBytes: true }
  )
  value.relayPublicKey = Buffer.from(keys.publicKey)
  value.storeId = Buffer.from(storeId)
  value.descriptorSequence = BigInt(descriptorSequence)
  value.previousDescriptorHash = previousDescriptorHash == null
    ? null
    : Buffer.from(previousDescriptorHash)
  value.protocols = [
    {
      protocolId: protocol.FAMILY.DESCRIBE,
      major: 1,
      minor: 0,
      featureBits: 0n,
      profileHash: Buffer.alloc(32, 0x0a)
    },
    {
      protocolId: protocol.FAMILY.CELL,
      major: 1,
      minor: 0,
      featureBits: 0n,
      profileHash: Buffer.alloc(32, 0x0a)
    }
  ]
  value.endpoints = [{
    ...value.endpoints[0],
    endpointId: 1,
    transportId: protocol.TRANSPORT_ID.HTTPS_DIRECT,
    transportProfileHash: Buffer.alloc(32, 0x0b),
    roleBits: 49,
    privacyProfileBits: protocol.PRIVACY_PROFILE.DIRECT,
    canonicalUrl: Buffer.from(canonicalDescribeUrl),
    envelopeClassBits: 0x007e
  }]
  value.admissionProfiles = [{
    profileId: 7,
    schemeId: 9,
    conformanceClass: 1,
    roleBits: 49,
    parameterUrl: Buffer.from(admissionParameterUrl),
    parameterHash: Buffer.from(admissionParameterHash)
  }]
  value.issuedEpoch = TEST_EPOCH - 1
  value.expiresEpoch = TEST_EPOCH + 3
  value.descriptorNonce = Buffer.alloc(32, nonceByte)
  value.durabilityProfileHash = protocol.durabilityProfileHash(
    protocol.encodeCanonical(protocol.durabilityProfileV1, value.durability))
  value.durabilityContinuityHash = protocol.durabilityContinuityHash(
    protocol.encodeCanonical(
      protocol.durabilityContinuityBindingV1,
      durabilityBinding(value.durability)
    ))
  const descriptorBytes = signedValue(
    protocol.blindServiceDescriptorV1,
    value,
    protocol.RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    keys.secretKey
  )
  return Object.freeze({
    bytes: bytes(descriptorBytes),
    value,
    hash: bytes(protocol.serviceDescriptorHash(descriptorBytes))
  })
}

function relayChain (relayId, seedByte, storeByte, admissionParameterHash) {
  const keys = keyPair(seedByte)
  const canonicalDescribeUrl = `https://${relayId}.example:443/api/blind/v1/describe`
  const storeId = fill(32, storeByte)
  const genesis = signedDescriptor({
    keys,
    canonicalDescribeUrl,
    storeId,
    admissionParameterUrl: EXACT_PARAMETER_URL_BYTES,
    admissionParameterHash,
    descriptorSequence: 0,
    previousDescriptorHash: null,
    nonceByte: seedByte + 1
  })
  const head = signedDescriptor({
    keys,
    canonicalDescribeUrl,
    storeId,
    admissionParameterUrl: EXACT_PARAMETER_URL_BYTES,
    admissionParameterHash,
    descriptorSequence: 1,
    previousDescriptorHash: genesis.hash,
    nonceByte: seedByte + 2
  })
  return {
    relayId,
    keys,
    canonicalDescribeUrl,
    storeId,
    admissionParameterUrl: bytes(EXACT_PARAMETER_URL_BYTES),
    admissionParameterHash,
    genesis,
    head,
    replicas: new Map()
  }
}

function signedHealth (relay, descriptor, descriptorHash, challenge) {
  const value = {
    version: 1,
    relayPublicKey: descriptor.relayPublicKey,
    storeId: descriptor.storeId,
    descriptorSequence: descriptor.descriptorSequence,
    descriptorHash,
    endpointId: challenge.endpointId,
    transportSupportBit: challenge.transportSupportBit,
    durabilityContinuityHash: descriptor.durabilityContinuityHash,
    durabilityProfileHash: descriptor.durabilityProfileHash,
    clientNonce: challenge.clientNonce,
    readyRoleBits: challenge.requestedRoleBits,
    readyOperationBits: challenge.requestedOperationBits,
    clockState: 1,
    effectiveEpochFloor: TEST_EPOCH - 1,
    integrityState: 1,
    checkpointAgeBand: 1,
    scrubAgeBand: 1,
    rebalanceState: 0,
    capacityBand: 2,
    challengeEpoch: TEST_EPOCH,
    signature: Buffer.alloc(64)
  }
  return signedValue(
    protocol.blindHealthResultV1,
    value,
    protocol.RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT,
    relay.keys.secretKey
  )
}

function signedProfileOperation (identity, name) {
  return (async () => {
    const me = identity.me()
    const data = { id: me.pubkey, author: me.pubkey, name }
    const signature = await identity.sign(canonical('profile', data))
    Object.assign(data, {
      _sig: signature.signature,
      _k: signature.publicKey,
      _dk: signature.driveKey,
      _ns: signature.namespace,
      _alg: signature.algorithm
    })
    return { type: 'profile', data }
  })()
}

function seedRelay (relay, descriptorGenesisHash = relay.genesis.hash) {
  return {
    relayId: relay.relayId,
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    continuityRootRelayPublicKey: hex(relay.keys.publicKey),
    storeId: hex(relay.storeId),
    descriptorGenesisHash: typeof descriptorGenesisHash === 'string'
      ? descriptorGenesisHash
      : hex(descriptorGenesisHash),
    minimumDescriptorSequence: 1,
    familyId: protocol.FAMILY.CELL,
    operationId: protocol.OPERATION.CELL.GET,
    endpointId: 1,
    transportId: protocol.TRANSPORT_ID.HTTPS_DIRECT,
    transportSupportBit: protocol.TRANSPORT_SUPPORT.DIRECT_HTTP,
    privacyProfileBit: protocol.PRIVACY_PROFILE.DIRECT
  }
}

function seedReplica (relay, replica, suffix) {
  return {
    relayId: relay.relayId,
    targetId: `cell-v1:${relay.relayId}:${suffix}`,
    readCapability: {
      version: 1,
      relayPublicKey: hex(replica.readCap.relayPublicKey),
      storageSlot: hex(replica.readCap.storageSlot),
      cellKey: hex(replica.readCap.cellKey),
      sizeClass: replica.readCap.sizeClass,
      expectedCellBlobHash: hex(replica.readCap.expectedCellBlobHash)
    }
  }
}

function seedRecord (envelope, replicas) {
  return {
    recordId: hex(hashPeeritInnerOperationIntentIdV1(
      envelope.innerCodec, envelope.innerBytes)),
    wireKeys: [...envelope.operationWireKeys],
    authorPublicKey: envelope.authorPublicKey,
    innerCodec: envelope.innerCodec,
    innerLength: Number(envelope.innerLength),
    sizeClass: envelope.sizeClass,
    logicalHash: hex(envelope.logicalHash),
    encodingCommitment: hex(envelope.encodingCommitment),
    replicas
  }
}

function fileBytes (assetPath, appArtifactBytes) {
  if (assetPath === PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact) {
    return appArtifactBytes.slice()
  }
  return new Uint8Array(fs.readFileSync(path.join(root, assetPath.slice(1))))
}

function originalAssets (appArtifactBytes) {
  return new Map(Object.values(PEERIT_BROWSER_RUNTIME_ASSET_PATHS)
    .map(assetPath => [assetPath, fileBytes(assetPath, appArtifactBytes)]))
}

function manifestFor (assets) {
  const appArtifactBytes = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact)
  return encodePeeritWebAssetManifestV1({
    version: 1,
    releaseSequence: RELEASE_SEQUENCE,
    appArtifactHash: hashPeeritAppArtifactV1(appArtifactBytes),
    recommendedBootstrapHashes: [hashPeeritBootstrapV1(
      assets.get('/peerit-seed-bootstrap-v1.json'))],
    assets: [...assets].map(([assetPath, assetBytes]) => ({
      path: textEncoder.encode(assetPath),
      byteLength: BigInt(assetBytes.byteLength),
      assetHash: blake2b256(assetBytes)
    })).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
  })
}

async function releaseAuthorityFor (seedBytes, seedAuthorityPublicKey) {
  const seedSha256 = createHash('sha256').update(seedBytes).digest('hex')
  const appArtifactBytes = textEncoder.encode(JSON.stringify({
    schema: 'peerit-app-artifact-v1',
    releaseSequence: Number(RELEASE_SEQUENCE),
    peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
    peeritSeedBootstrapSha256: seedSha256,
    peeritSeedDiscoveryAuthorityPublicKey: seedAuthorityPublicKey,
    peeritSeedBootstrapReleaseSequence: Number(RELEASE_SEQUENCE)
  }) + '\n')
  const assets = originalAssets(appArtifactBytes)
  assets.set('/peerit-seed-bootstrap-v1.json', seedBytes)
  const webAssetManifestBytes = manifestFor(assets)
  const hiveManifest = decodeBlindClientBrowserManifestV1(
    assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveManifest))
  const emitSubstrate = {
    specHash: hiveManifest.specHash,
    abiHash: hiveManifest.abiHash,
    vectorSetHash: hiveManifest.vectorSetHash
  }
  const pin = releaseFixture.signPin({
    ...releaseFixture.pins[0],
    emitSubstrate,
    readSubstrates: [emitSubstrate],
    profileSpecHash: hashPeeritProfileSpec(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileSource)),
    profileAbiHash: hashPeeritProfileAbi(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry)),
    profileVectorSetHash: hashPeeritProfileVectorSet(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileVectorManifest)),
    validatorArtifactHash: hashPeeritValidatorArtifactV1(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact)),
    validatorVectorSetHash: hashPeeritValidatorVectorSetV1(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorVectorManifest)),
    availabilityPolicyHash: availabilityPolicyHash(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.availabilityPolicy)),
    releaseSequence: RELEASE_SEQUENCE,
    recommendedBootstrapHashes: [hashPeeritBootstrapV1(seedBytes)],
    appArtifactHash: hashPeeritAppArtifactV1(appArtifactBytes),
    webAssetManifestHash: hashPeeritWebAssetManifestV1(webAssetManifestBytes),
    signature: undefined
  })
  const productionPinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  return assemblePeeritBrowserRuntimeAuthorityNodeTestV1({
    assets,
    appDistributionArtifactBytes: appArtifactBytes,
    webAssetManifestBytes,
    productionPinBytes,
    expectedPinHash: profilePinHash(productionPinBytes),
    expectedReleaseAuthorityPublicKey: releaseFixture.releasePublicKey,
    expectedReleaseSequence: RELEASE_SEQUENCE,
    crypto: releaseCrypto,
    clock: { unixMillis: TEST_NOW, monotonicMillis: 1_000 },
    requireCompleteAssetSet: true
  })
}

function protocolResponse (request, body) {
  const encoded = protocol.encodeOuterEnvelope({
    outerClass: request.outerClass,
    innerDispatch: protocol.encodeDispatchFrame({
      frameKind: protocol.FRAME_KIND.RESPONSE,
      familyId: request.frame.familyId,
      operationId: request.frame.operationId,
      requestId: request.frame.requestId,
      body
    })
  })
  return new Response(encoded, {
    status: 200,
    headers: new Headers([
      ['content-type', protocol.PROTOCOL.mediaType],
      ['content-length', String(encoded.byteLength)]
    ])
  })
}

function checkedHeaders (init) {
  assert.equal(init.method, 'POST')
  assert.equal(init.credentials, 'omit')
  assert.equal(init.cache, 'no-store')
  assert.equal(init.redirect, 'error')
  const headers = new Map((init.headers || []).map(([name, value]) => [
    String(name).toLowerCase(), String(value)
  ]))
  assert.equal(headers.get('content-type'), protocol.PROTOCOL.mediaType)
  assert.equal(headers.has('authorization'), false)
  assert.equal(headers.has('cookie'), false)
}

function relayServer ({
  relays,
  heads = new Map(),
  history = new Map(),
  failCellSlots = new Set()
}) {
  const byHost = new Map(relays.map(relay => [
    new URL(relay.canonicalDescribeUrl).host,
    relay
  ]))
  const requests = []
  const fetch = async (url, init) => {
    checkedHeaders(init)
    const parsedUrl = new URL(url)
    assert.notEqual(parsedUrl.origin, 'https://evidence.example:443',
      'admission parameterUrl is an evidence hint and must never be fetched')
    const relay = byHost.get(parsedUrl.host)
    assert.ok(relay, `unknown relay host ${parsedUrl.host}`)
    const request = protocol.decodeOuterEnvelope(init.body, { copyBody: true })
    assert.equal(request.frame.frameKind, protocol.FRAME_KIND.REQUEST)
    requests.push(Object.freeze({
      relayId: relay.relayId,
      origin: parsedUrl.origin,
      path: parsedUrl.pathname,
      familyId: request.frame.familyId,
      operationId: request.frame.operationId
    }))

    if (parsedUrl.pathname === '/api/blind/v1/describe') {
      assert.equal(request.frame.familyId, protocol.FAMILY.DESCRIBE)
      if (request.frame.operationId === protocol.OPERATION.DESCRIBE.GET) {
        const get = protocol.decodeCanonical(
          protocol.blindDescribeGetV1,
          request.frame.body,
          { copyBytes: true }
        )
        const currentHead = heads.get(relay.relayId) || relay.head
        if (get.descriptorHash == null) {
          return protocolResponse(request, currentHead.bytes)
        }
        const wanted = hex(get.descriptorHash)
        const available = history.get(relay.relayId) || new Map([
          [hex(relay.genesis.hash), relay.genesis],
          [hex(currentHead.hash), currentHead]
        ])
        const descriptor = available.get(wanted)
        assert.ok(descriptor, `unknown descriptor history hash ${wanted}`)
        return protocolResponse(request, descriptor.bytes)
      }
      assert.equal(request.frame.operationId, protocol.OPERATION.DESCRIBE.CHALLENGE)
      const challenge = protocol.decodeCanonical(
        protocol.blindHealthChallengeV1,
        request.frame.body,
        { copyBytes: true }
      )
      const currentHead = heads.get(relay.relayId) || relay.head
      return protocolResponse(request, signedHealth(
        relay, currentHead.value, currentHead.hash, challenge))
    }

    assert.equal(parsedUrl.pathname, '/api/blind/v1/cell')
    assert.equal(request.frame.familyId, protocol.FAMILY.CELL)
    assert.equal(request.frame.operationId, protocol.OPERATION.CELL.GET)
    const get = protocol.decodeCanonical(
      protocol.getCellV1,
      request.frame.body,
      { copyBytes: true }
    )
    if (failCellSlots.has(`${relay.relayId}:${hex(get.storageSlot)}`)) {
      throw Object.assign(new Error('deterministic first-replica outage'), {
        code: 'BLIND_CELL_UNAVAILABLE'
      })
    }
    const replica = relay.replicas.get(hex(get.storageSlot))
    assert.ok(replica, 'Cell GET must select a seeded storage slot')
    return protocolResponse(request, protocol.encodeCanonical(
      protocol.getCellResultV1,
      {
        version: 1,
        sizeClass: replica.readCap.sizeClass,
        cellBlob: replica.request.cellBlob
      }
    ))
  }
  return { fetch, requests }
}

function minimalSync () {
  let setRelayCalls = 0
  return {
    sync: {
      async discoveryFloor () { return null },
      async ingestVerifiedRemoteBatch () {
        throw new Error('negative recovery scenario must not ingest')
      },
      setRelays () { setRelayCalls++ }
    },
    setRelayCalls: () => setRelayCalls
  }
}

function substrate (name) {
  const shared = createMemoryJournalState()
  const journal = createMemoryPeeritJournal({ shared, clock: () => TEST_NOW })
  const sync = createSync({
    mode: 'substrate',
    journal,
    relays: [],
    autoFlush: false,
    channelName: name
  })
  let setRelayCalls = 0
  sync.setRelays = () => { setRelayCalls++ }
  return { shared, journal, sync, setRelayCalls: () => setRelayCalls }
}

async function expectRecoveryFailure ({
  authority,
  relays,
  code,
  heads,
  history,
  beforeHealth = false,
  monotonicMillis = () => 1_000
}) {
  const server = relayServer({ relays, heads, history })
  const state = minimalSync()
  await assert.rejects(recoverPeeritSeedWithLimitedCellGetAuthorityV1({
    releaseAuthority: authority,
    sync: state.sync,
    now: () => TEST_NOW,
    monotonicMillis,
    webCrypto: globalThis.crypto,
    fetch: server.fetch,
    timeoutMillis: 1_000
  }), error => error && error.code === code,
  `recovery must fail closed with ${code}`)
  assert.equal(state.setRelayCalls(), 0)
  assert.equal(server.requests.some(request =>
    request.familyId === protocol.FAMILY.CELL), false,
  `${code} must fail before Cell GET`)
  if (beforeHealth) {
    assert.equal(server.requests.some(request =>
      request.familyId === protocol.FAMILY.DESCRIBE &&
      request.operationId === protocol.OPERATION.DESCRIBE.CHALLENGE), false,
    `${code} must fail before signed health challenge`)
  }
}

await cryptoReady()

// Fixture admission bindings: they ride the descriptors (descriptor-driven),
// never the release profile — which pins no parameterHash at all.
const admissionByRelay = new Map([
  ['dal-1', Buffer.alloc(32, 0x51)],
  ['syd-1', Buffer.alloc(32, 0x52)]
])
const dal = relayChain('dal-1', 0x31, 0x32, admissionByRelay.get('dal-1'))
const syd = relayChain('syd-1', 0x41, 0x42, admissionByRelay.get('syd-1'))
const relays = [dal, syd]

const envelopes = []
for (const [index, name] of [
  'Recovered from Dallas with authenticated Cell GET',
  'Recovered from Sydney with authenticated Cell GET'
].entries()) {
  const identity = createIdentity({
    forceDev: true,
    lazy: true,
    storage: memoryStorage(),
    session: memoryStorage()
  })
  await identity.ready()
  await identity.ensureActive(`peerit-limited-cell-get-${index}`)
  envelopes.push(await createPeeritInnerOperationBatchV1([
    await signedProfileOperation(identity, name)
  ]))
}

const nodeRuntime = createNodeCryptoRuntime()
async function makeReplica (relay, envelope, suffix) {
  const replica = await createCellReplica({
    runtime: nodeRuntime,
    relayPublicKey: relay.keys.publicKey,
    allocationEpoch: TEST_EPOCH,
    sizeClass: envelope.sizeClass,
    leaseClass: 1,
    structuredContent: envelope.innerBytes,
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: relay.admissionParameterHash,
      token: Uint8Array.of(1)
    }
  })
  relay.replicas.set(hex(replica.readCap.storageSlot), replica)
  return seedReplica(relay, replica, suffix)
}

const firstDal = await makeReplica(dal, envelopes[0], 'record-a')
const firstSyd = await makeReplica(syd, envelopes[0], 'record-a')
const secondDal = await makeReplica(dal, envelopes[1], 'record-b')
const secondSyd = await makeReplica(syd, envelopes[1], 'record-b')
const seedAuthority = await genKeyPair()

function baseSeedPayload (relayValues = relays.map(relay => seedRelay(relay))) {
  return {
    schema: PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
    version: 1,
    profile: PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
    operatorBoundary: PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
    bootstrapSequence: 0,
    previousBootstrapHash: null,
    releaseSequence: Number(RELEASE_SEQUENCE),
    authorityPublicKey: seedAuthority.pubHex,
    issuedAt: TEST_NOW - 1_000,
    expiresAt: TEST_NOW + 120_000,
    relays: relayValues,
    records: [
      seedRecord(envelopes[0], [firstDal, firstSyd]),
      seedRecord(envelopes[1], [secondDal, secondSyd])
    ].sort((left, right) => left.recordId.localeCompare(right.recordId))
  }
}

async function signedSeedBytes (payload) {
  const artifact = await createPeeritSeedBootstrapV1(payload, {
    seedHex: seedAuthority.seedHex
  })
  return new Uint8Array(encodePeeritSeedBootstrapV1(artifact))
}

const seedBytes = await signedSeedBytes(baseSeedPayload())
const authority = await releaseAuthorityFor(seedBytes, seedAuthority.pubHex)

const successServer = relayServer({
  relays,
  failCellSlots: new Set([
    `${dal.relayId}:${secondDal.readCapability.storageSlot}`
  ])
})
const success = substrate('peerit-limited-cell-get-recovery-success')
await success.sync.ready()
const recovered = await recoverPeeritSeedWithLimitedCellGetAuthorityV1({
  releaseAuthority: authority,
  sync: success.sync,
  now: () => TEST_NOW,
  monotonicMillis: () => 1_000,
  webCrypto: globalThis.crypto,
  fetch: successServer.fetch,
  timeoutMillis: 1_000
})

assert.equal(recovered.ok, true)
assert.equal(recovered.cached, false)
assert.equal(recovered.qualifiedRelayCount, 2)
assert.equal(recovered.networkGets, 3)
assert.equal(recovered.networkPuts, 0)
assert.equal(recovered.fallbackCount, 1)
assert.equal(recovered.ordinaryDelivery, 'local-only')
assert.deepEqual(recovered.descriptorHeads.map(head => [
  head.relayId,
  head.descriptorSequence,
  head.descriptorHeadHash
]), [
  ['dal-1', 1n, hex(dal.head.hash)],
  ['syd-1', 1n, hex(syd.head.hash)]
])
assert.equal(success.setRelayCalls(), 0)
assert.equal((await success.journal.summary()).pendingIntentCount, 0)
assert.equal(success.shared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(success.shared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
for (let index = 0; index < envelopes.length; index++) {
  const profile = await success.sync.get(envelopes[index].operationWireKeys[0])
  assert.equal(profile.name, [
    'Recovered from Dallas with authenticated Cell GET',
    'Recovered from Sydney with authenticated Cell GET'
  ][index])
}

const allowed = new Set([
  `${protocol.FAMILY.DESCRIBE}:${protocol.OPERATION.DESCRIBE.GET}`,
  `${protocol.FAMILY.DESCRIBE}:${protocol.OPERATION.DESCRIBE.CHALLENGE}`,
  `${protocol.FAMILY.CELL}:${protocol.OPERATION.CELL.GET}`
])
assert.equal(successServer.requests.every(request =>
  allowed.has(`${request.familyId}:${request.operationId}`)), true)
assert.equal(successServer.requests.every(request =>
  ['https://dal-1.example', 'https://syd-1.example'].includes(request.origin)), true)
assert.equal(successServer.requests.some(request =>
  request.origin.includes('evidence.example')), false)
assert.equal(successServer.requests.some(request =>
  request.familyId === protocol.FAMILY.CELL &&
  request.operationId === protocol.OPERATION.CELL.PUT), false)
for (const relay of relays) {
  const relayRequests = successServer.requests.filter(request =>
    request.relayId === relay.relayId)
  assert.equal(relayRequests.filter(request =>
    request.familyId === protocol.FAMILY.DESCRIBE &&
    request.operationId === protocol.OPERATION.DESCRIBE.GET).length, 3)
  assert.equal(relayRequests.filter(request =>
    request.familyId === protocol.FAMILY.DESCRIBE &&
    request.operationId === protocol.OPERATION.DESCRIBE.CHALLENGE).length, 1)
  assert.equal(relayRequests.filter(request =>
    request.familyId === protocol.FAMILY.CELL &&
    request.operationId === protocol.OPERATION.CELL.GET).length,
  relay.relayId === 'dal-1' ? 2 : 1)
}
success.sync.destroy()

const gapHeads = new Map(relays.map(relay => [relay.relayId, signedDescriptor({
  keys: relay.keys,
  canonicalDescribeUrl: relay.canonicalDescribeUrl,
  storeId: relay.storeId,
  admissionParameterUrl: relay.admissionParameterUrl,
  admissionParameterHash: relay.admissionParameterHash,
  descriptorSequence: 2,
  previousDescriptorHash: relay.genesis.hash,
  nonceByte: relay.relayId === 'dal-1' ? 0x35 : 0x45
})]))
await expectRecoveryFailure({
  authority,
  relays,
  heads: gapHeads,
  code: 'PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID'
})

const wrongGenesisPayload = baseSeedPayload([
  seedRelay(dal, '99'.repeat(32)),
  seedRelay(syd)
])
const wrongGenesisBytes = await signedSeedBytes(wrongGenesisPayload)
const wrongGenesisAuthority = await releaseAuthorityFor(
  wrongGenesisBytes, seedAuthority.pubHex)
await expectRecoveryFailure({
  authority: wrongGenesisAuthority,
  relays,
  code: 'PEERIT_LIMITED_DESCRIPTOR_GENESIS_MISMATCH'
})

const storeDriftHeads = new Map()
const storeDriftHistory = new Map()
for (const relay of relays) {
  const wrongStoreGenesis = signedDescriptor({
    keys: relay.keys,
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    storeId: fill(32, relay.relayId === 'dal-1' ? 0x36 : 0x46),
    admissionParameterUrl: relay.admissionParameterUrl,
    admissionParameterHash: relay.admissionParameterHash,
    descriptorSequence: 0,
    previousDescriptorHash: null,
    nonceByte: relay.relayId === 'dal-1' ? 0x37 : 0x47
  })
  const head = signedDescriptor({
    keys: relay.keys,
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    storeId: relay.storeId,
    admissionParameterUrl: relay.admissionParameterUrl,
    admissionParameterHash: relay.admissionParameterHash,
    descriptorSequence: 1,
    previousDescriptorHash: wrongStoreGenesis.hash,
    nonceByte: relay.relayId === 'dal-1' ? 0x38 : 0x48
  })
  storeDriftHeads.set(relay.relayId, head)
  storeDriftHistory.set(relay.relayId, new Map([
    [hex(wrongStoreGenesis.hash), wrongStoreGenesis],
    [hex(head.hash), head]
  ]))
}
await expectRecoveryFailure({
  authority,
  relays,
  heads: storeDriftHeads,
  history: storeDriftHistory,
  code: 'PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID'
})

const admissionDriftHeads = new Map(relays.map(relay => [
  relay.relayId,
  signedDescriptor({
    keys: relay.keys,
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    storeId: relay.storeId,
    admissionParameterUrl: relay.admissionParameterUrl,
    admissionParameterHash: fill(32, 0xee),
    descriptorSequence: 1,
    previousDescriptorHash: relay.genesis.hash,
    nonceByte: relay.relayId === 'dal-1' ? 0x39 : 0x49
  })
]))
// ROTATION TOLERANCE (descriptor-driven admission): the same head descriptors
// now carry a ROTATED admission binding (0xee) — the fleet's forward channel
// rotated the signed parameterHash, exactly like the live v5 -> v6 -> v7
// rotations. The release profile pins no hash, so the SAME build must
// qualify against the rotated descriptors exactly as before (previously this
// case demanded PEERIT_LIMITED_DESCRIPTOR_ADMISSION_PROFILE_DRIFT).
const rotatedServer = relayServer({ relays, heads: admissionDriftHeads })
const rotatedState = substrate('peerit-limited-cell-get-recovery-rotation')
await rotatedState.sync.ready()
const rotatedRecovery = await recoverPeeritSeedWithLimitedCellGetAuthorityV1({
  releaseAuthority: authority,
  sync: rotatedState.sync,
  now: () => TEST_NOW,
  monotonicMillis: () => 1_000,
  webCrypto: globalThis.crypto,
  fetch: rotatedServer.fetch,
  timeoutMillis: 1_000
})
assert.equal(rotatedRecovery.ok, true)
assert.equal(rotatedRecovery.cached, false)
assert.equal(rotatedRecovery.recordCount, 2)
assert.equal(rotatedRecovery.networkPuts, 0)
assert.equal(rotatedRecovery.qualifiedRelayCount, 2)
assert.equal(rotatedState.setRelayCalls(), 0)

const parameterUrlDriftHeads = new Map(relays.map(relay => {
  const drift = bytes(relay.admissionParameterUrl)
  drift[drift.byteLength - 1] ^= 0x01
  return [relay.relayId, signedDescriptor({
    keys: relay.keys,
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    storeId: relay.storeId,
    admissionParameterUrl: drift,
    admissionParameterHash: relay.admissionParameterHash,
    descriptorSequence: 1,
    previousDescriptorHash: relay.genesis.hash,
    nonceByte: relay.relayId === 'dal-1' ? 0x3a : 0x4a
  })]
}))
await expectRecoveryFailure({
  authority,
  relays,
  heads: parameterUrlDriftHeads,
  beforeHealth: true,
  code: 'PEERIT_LIMITED_DESCRIPTOR_ADMISSION_PROFILE_DRIFT'
})

let monotonic = 0
await expectRecoveryFailure({
  authority,
  relays,
  code: 'PEERIT_LIMITED_CELL_GET_QUALIFICATION_EXPIRED',
  monotonicMillis: () => {
    const value = monotonic
    monotonic += 60_001
    return value
  }
})

assert.equal(textDecoder.decode(seedBytes).includes('dropPrivateKey'), false)
console.log('peerit limited Cell-GET recovery: signed two-relay success, exact allowlist, zero PUT/setRelays, and fail-closed drift checks passed')
