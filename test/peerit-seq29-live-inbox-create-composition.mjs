import assert from 'node:assert/strict'
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign
} from 'node:crypto'
import fs from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:https'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  peeritLimitedCellPutProfileSourceV1
} from '../js/substrate/limited-cell-put-profile.mjs'
import {
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  createPeeritSeq29CustodyFirstLiveInboxCreateCompositionV1,
  createPeeritSeq29LiveInboxCreateCompositionV1,
  createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1
} from '../scripts/seq29-live-inbox-create-composition.mjs'
import {
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1,
  PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
  peeritLimitedInboxTopicCeremonyPlanHashV1
} from '../scripts/limited-inbox-topic-ceremony.mjs'
import {
  canonicalPeeritLimitedPublicInboxJsonV1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  createPeeritSeq29FilesystemAttemptJournalV1,
  recoverPeeritSeq29FilesystemAttemptBindingV1
} from '../scripts/lib/seq29-live-ceremony-journal.mjs'
import {
  preparePeeritSeq29LiveInboxCreateCustodyFirstV1,
  preparePeeritSeq29LiveInboxCreateReleaseV1,
  qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1,
  snapshotPeeritSeq29LiveInboxCreateReleasePreparationV1,
  snapshotPeeritSeq29LiveInboxCreateQualificationV1
} from '../scripts/seq29-live-inbox-create-qualification.mjs'
import {
  runPeeritSeq29LiveInboxCeremonyConductorV1
} from '../scripts/seq29-live-inbox-ceremony-conductor.mjs'
import {
  loadPeeritSeq29AcceptedHiveRelayOperatorV1
} from '../scripts/lib/seq29-accepted-hiverelay-operator.mjs'
import {
  preparePeeritSeq29OfflineInboxCreateRequestsV1,
  resumePeeritSeq29LiveInboxCreatePreNetworkCustodyCrashFixtureV1,
  sealPeeritSeq29LiveInboxCreatePreNetworkCustodyCrashFixtureV1,
  resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1
} from '../scripts/lib/seq29-live-inbox-create-pre-network-custody.mjs'
import {
  loadPeeritSeq29ExactLoopbackProtocolFixtureV1
} from './lib/seq29-exact-loopback-protocol-fixture.mjs'

const TLS_CHILD_ENV = 'PEERIT_SEQ29_EXACT_SOURCE_TLS_CHILD'
const CRASH_CHILD_ENV = 'PEERIT_SEQ29_PRE_CUSTODY_CRASH_CHILD'
const tlsFixtureDirectory = path.resolve(import.meta.dirname,
  'fixtures/peerit-seq29-loopback-tls')
const tlsCertificatePath = path.join(tlsFixtureDirectory, 'certificate.pem')
const tlsPrivateKeyPath = path.join(tlsFixtureDirectory, 'private-key.pem')
// These are public, test-only TLS fixture bytes. They are unrelated to live
// relay, signing, custody or custodian keys.
const tlsCertificateBytes = readFileSync(tlsCertificatePath)
const tlsPrivateKeyBytes = readFileSync(tlsPrivateKeyPath)
assert.equal(createHash('sha256').update(tlsCertificateBytes).digest('hex'),
  'a42a73d2a292e052c3fad3742d2a2f9381e66d805f1d5d80fbc53c6c690a089a')
assert.equal(createHash('sha256').update(tlsPrivateKeyBytes).digest('hex'),
  '89c93482c5e7499284878fd785a7723b1192e5d130d74a64298a792d387130b9')
if (process.env[TLS_CHILD_ENV] !== '1') {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url)], {
    stdio: 'inherit',
    env: {
      ...process.env,
      [TLS_CHILD_ENV]: '1',
      NODE_EXTRA_CA_CERTS: tlsCertificatePath
    }
  })
  const [status, signal] = await once(child, 'exit')
  if (status !== 0) {
    throw new Error(`trusted-TLS loopback child failed: ${status ?? signal}`)
  }
  process.exit(0)
}

const CANDIDATE_COMMIT = 'adeacef07c5de4d17d5ed1389fee7a35095b862f'
const CANDIDATE_TREE = '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'
const EPOCH_MILLIS = 21_600_000

process.env.PEERIT_SEQ29_CREATE_EXACT_SOURCE_E2E_TEST = '1'
process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST = '1'

if (process.env[CRASH_CHILD_ENV] === '1') {
  const config = JSON.parse(await fs.readFile(
    process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_CONFIG, 'utf8'))
  globalThis.fetch = async () => {
    await fs.writeFile(config.networkMarker, 'unexpected network\n', { flag: 'a' })
    throw new Error('crash fixture crossed the zero-network boundary')
  }
  if (process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_MODE === 'SEAL') {
    const releasePreparation = await preparePeeritSeq29LiveInboxCreateReleaseV1({
      seedBootstrapBytes: new Uint8Array(await fs.readFile(config.seedBootstrapPath)),
      limitedCellPutProfileBytes: new Uint8Array(await fs.readFile(config.profilePath)),
      now: () => config.nowUnixMillis,
      fixture: {
        allowFixture: true,
        seedAuthorityPublicKey: config.seedAuthorityPublicKey
      }
    })
    const releaseSnapshot =
      snapshotPeeritSeq29LiveInboxCreateReleasePreparationV1(releasePreparation)
    assert.deepEqual(releaseSnapshot, config.releaseSnapshot)
    const preparation = await preparePeeritSeq29OfflineInboxCreateRequestsV1({
      releaseSnapshot
    })
    await sealPeeritSeq29LiveInboxCreatePreNetworkCustodyCrashFixtureV1({
      preparation,
      directory: process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_DIRECTORY,
      custodianKeyDirectory: config.keyDirectory,
      crashStage: process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_STAGE
    })
  } else if (process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_MODE === 'RESUME') {
    const input = {
      releaseSnapshot: config.releaseSnapshot,
      directory: process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_DIRECTORY,
      custodianKeyDirectory: config.keyDirectory
    }
    if (process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_STAGE === 'NONE') {
      await resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1(input)
    } else {
      await resumePeeritSeq29LiveInboxCreatePreNetworkCustodyCrashFixtureV1({
        ...input,
        crashStage: process.env.PEERIT_SEQ29_PRE_CUSTODY_CRASH_STAGE
      })
    }
  } else {
    throw new Error('unknown pre-custody crash worker mode')
  }
  process.exit(0)
}

const exactFixture = await loadPeeritSeq29ExactLoopbackProtocolFixtureV1()
const repeatedFixture = await loadPeeritSeq29ExactLoopbackProtocolFixtureV1()
assert.strictEqual(exactFixture.protocol, repeatedFixture.protocol)
assert.equal(exactFixture.identity.candidateCommit, CANDIDATE_COMMIT)
assert.equal(exactFixture.identity.candidateTree, CANDIDATE_TREE)
const {
  protocol,
  serviceDescriptorVector,
  admissionParametersVector
} = exactFixture

const {
  ADVERTISED_OPERATION_BITS,
  FAMILY,
  FRAME_KIND,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  admissionParametersHash,
  admissionParametersV1,
  blindAdmissionParametersRequestV1,
  blindDescribeGetV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindServiceDescriptorV1,
  blake2b256,
  decodeCanonical,
  decodeOuterEnvelope,
  durabilityContinuityBindingV1,
  durabilityContinuityHash,
  durabilityProfileHash,
  durabilityProfileV1,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  inboxCreateCommitment,
  inboxCreateRequestCommitment,
  inboxCreateV1,
  inboxReceiptV1,
  resultSignaturePayload,
  serviceDescriptorHash
} = protocol

function cloneCanonical (codec, value) {
  return decodeCanonical(codec, encodeCanonical(codec, value), {
    copyBytes: true
  })
}

function bindDurability (descriptor) {
  descriptor.durabilityProfileHash = durabilityProfileHash(
    encodeCanonical(durabilityProfileV1, descriptor.durability))
  descriptor.durabilityContinuityHash = durabilityContinuityHash(
    encodeCanonical(durabilityContinuityBindingV1, {
      version: 1,
      profileId: descriptor.durability.profileId,
      externalJournalId: descriptor.durability.externalJournalId,
      externalWitnessPublicKey:
        descriptor.durability.externalWitnessPublicKey,
      externalJournalReplicationClass:
        descriptor.durability.externalJournalReplicationClass,
      externalJournalFailureGroupId:
        descriptor.durability.externalJournalFailureGroupId,
      restoreEvidenceFeedId: descriptor.durability.restoreEvidenceFeedId
    }))
  return descriptor
}

function descriptorValue (overrides = {}) {
  const value = decodeCanonical(
    blindServiceDescriptorV1, serviceDescriptorVector, { copyBytes: true })
  value.endpoints[0].envelopeClassBits = 0x7e
  value.enabledOperationBits = ADVERTISED_OPERATION_BITS
  Object.assign(value, overrides)
  return bindDurability(value)
}

function successorValue (snapshot, overrides = {}) {
  const previous = snapshot.descriptor
  const next = cloneCanonical(blindServiceDescriptorV1, previous)
  next.descriptorSequence = previous.descriptorSequence + 1n
  next.previousDescriptorHash = Buffer.from(snapshot.hash)
  next.issuedEpoch = previous.issuedEpoch + 1
  next.expiresEpoch = previous.expiresEpoch + 1
  next.descriptorNonce = Buffer.alloc(32,
    Number(0x30n + next.descriptorSequence))
  next.signature = Buffer.alloc(64,
    Number(0x50n + next.descriptorSequence))
  Object.assign(next, overrides)
  return bindDurability(next)
}

function parameterValue (relayPublicKey, overrides = {}) {
  const value = decodeCanonical(
    admissionParametersV1, admissionParametersVector, { copyBytes: true })
  value.relayPublicKey = Buffer.from(relayPublicKey)
  Object.assign(value, overrides)
  return value
}

const fixtureSource = Object.freeze({
  bindDurability,
  descriptorValue,
  parameterValue,
  successorValue
})

const loopbackServerErrors = []
const loopbackTls = Object.freeze({
  cert: tlsCertificateBytes,
  key: tlsPrivateKeyBytes
})
const loopbackServers = ['dal-1', 'syd-1'].map(relayId => createServer(
  loopbackTls,
  (request, response) => {
    handleLoopbackRequest(relayId, request, response).catch(cause => {
      loopbackServerErrors.push(cause)
      if (!response.headersSent) response.writeHead(500)
      response.end()
    })
  }))

for (const server of loopbackServers) {
  await new Promise((resolve, reject) => {
    const failed = cause => reject(cause)
    server.once('error', failed)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', failed)
      resolve()
    })
  })
}
const loopbackOriginByRelay = new Map(loopbackServers.map((server, index) => [
  ['dal-1', 'syd-1'][index],
  `https://127.0.0.1:${server.address().port}`
]))

function sha256 (value) {
  return createHash('sha256').update(value).digest()
}

function hex (value) {
  return Buffer.from(value).toString('hex')
}

function seed (label) {
  return new Uint8Array(sha256(Buffer.from(
    `peerit.seq29.exact-source-e2e\0${label}`, 'utf8')))
}

function ed25519PrivateKey (value) {
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(value)
    ]),
    format: 'der',
    type: 'pkcs8'
  })
}

function ed25519PublicKey (value) {
  return new Uint8Array(createPublicKey(ed25519PrivateKey(value))
    .export({ format: 'der', type: 'spki' }).subarray(-32))
}

function signCanonical (codec, value, domain, privateSeed) {
  value.signature = Buffer.alloc(64)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - 64)
  value.signature = sign(null, resultSignaturePayload(domain, unsigned),
    ed25519PrivateKey(privateSeed))
  return encodeCanonical(codec, value)
}

function sameBytes (left, right) {
  return Buffer.from(left).equals(Buffer.from(right))
}

function exactResponse (outerClass, request, body) {
  const dispatch = encodeDispatchFrame({
    frameKind: FRAME_KIND.RESPONSE,
    familyId: request.familyId,
    operationId: request.operationId,
    requestId: request.requestId,
    body
  })
  const envelope = encodeOuterEnvelope({
    innerDispatch: dispatch,
    outerClass
  }, { randomFill: padding => padding.fill(0) })
  return envelope
}

const nowUnixMillis = Date.now()
const nowEpoch = Math.floor(nowUnixMillis / EPOCH_MILLIS)
const relayRows = []
for (const [index, relayId] of ['dal-1', 'syd-1'].entries()) {
  const privateSeed = seed(`relay:${relayId}`)
  const relayPublicKey = ed25519PublicKey(privateSeed)
  const storeId = new Uint8Array(sha256(Buffer.from(`store:${relayId}`)))
  const loopbackOrigin = loopbackOriginByRelay.get(relayId)
  const canonicalDescribeUrl = `${loopbackOrigin}/api/blind/v1/describe`
  const issuanceUrl = `${loopbackOrigin}/`
  const parameters = fixtureSource.parameterValue(relayPublicKey, {
    profileId: 3,
    schemeId: 1,
    conformanceClass: 1,
    roleBits: 49,
    verifierKey: Buffer.alloc(0),
    resourceCosts: [
      {
        familyId: FAMILY.CELL,
        operationId: OPERATION.CELL.PUT,
        resourceClass: 1,
        leaseClass: 1,
        costUnits: 10n
      },
      {
        familyId: FAMILY.INBOX,
        operationId: OPERATION.INBOX.CREATE,
        resourceClass: 1,
        leaseClass: 4,
        costUnits: 10n
      }
    ],
    tokenMaxBytes: 512,
    issuanceUrl: Buffer.from(issuanceUrl),
    issuerRelayKey: Buffer.alloc(32, 0x70 + index),
    validFromEpoch: nowEpoch - 1,
    expiresEpoch: nowEpoch + 3,
    nonce: Buffer.alloc(32, 0x30 + index)
  })
  const parameterBytes = signCanonical(
    admissionParametersV1,
    parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS,
    privateSeed
  )
  const parameterHash = admissionParametersHash(parameterBytes)
  const genesis = fixtureSource.descriptorValue({
    relayPublicKey: Buffer.from(relayPublicKey),
    storeId: Buffer.from(storeId),
    issuedEpoch: nowEpoch - 1,
    expiresEpoch: nowEpoch + 3,
    capacityBand: 2,
    descriptorNonce: Buffer.alloc(32, 0x40 + index)
  })
  genesis.protocols = [1, 2, 3, 4].map(protocolId => ({
    protocolId,
    major: 1,
    minor: 0,
    featureBits: 0n,
    profileHash: Buffer.alloc(32, 0x20 + protocolId)
  }))
  genesis.endpoints = [{
    ...genesis.endpoints[0],
    endpointId: 1,
    transportId: 1,
    transportProfileHash: Buffer.alloc(32, 0x2f),
    roleBits: 49,
    privacyProfileBits: 1,
    canonicalUrl: Buffer.from(canonicalDescribeUrl),
    endpointKey: null,
    envelopeClassBits: 0x7e,
    wireClassBits: 0,
    maxStreams: 0,
    auxiliaryUrl: null,
    auxiliaryHash: null
  }]
  genesis.admissionProfiles = [{
    profileId: 3,
    schemeId: 1,
    conformanceClass: 1,
    roleBits: 49,
    parameterUrl: null,
    parameterHash: Buffer.from(parameterHash)
  }]
  fixtureSource.bindDurability(genesis)
  const genesisBytes = signCanonical(
    blindServiceDescriptorV1,
    genesis,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    privateSeed
  )
  const genesisHash = serviceDescriptorHash(genesisBytes)
  const head = fixtureSource.successorValue({
    descriptor: genesis,
    hash: genesisHash
  }, {
    issuedEpoch: nowEpoch,
    expiresEpoch: nowEpoch + 3,
    descriptorNonce: Buffer.alloc(32, 0x50 + index)
  })
  const headBytes = signCanonical(
    blindServiceDescriptorV1,
    head,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR,
    privateSeed
  )
  const headHash = serviceDescriptorHash(headBytes)
  relayRows.push(Object.freeze({
    relayId,
    privateSeed,
    relayPublicKey,
    storeId,
    canonicalDescribeUrl,
    issuanceUrl,
    parameterBytes,
    parameterHash,
    genesis,
    genesisBytes,
    genesisHash,
    head,
    headBytes,
    headHash
  }))
}

const supportedProtocolProfiles = relayRows[0].head.protocols.map(value => ({
  protocolId: value.protocolId,
  major: value.major,
  minimumMinor: value.minor,
  profileHash: hex(value.profileHash)
}))
const supportedTransportProfiles = [{
  transportId: 1,
  transportSupportBit: 1,
  transportProfileHash: hex(relayRows[0].head.endpoints[0].transportProfileHash)
}]
const profileBytes = new TextEncoder().encode(
  peeritLimitedCellPutProfileSourceV1({
    releaseSequence: 28,
    supportedProtocolProfiles,
    supportedTransportProfiles,
    relays: relayRows.map(row => ({
      relayId: row.relayId,
      relayPublicKey: hex(row.relayPublicKey),
      issuanceUrl: `https://relay-${row.relayId === 'dal-1' ? 'dal' : 'syd'}.p2phiverelay.xyz:8443/`
    }))
  }))

const seedAuthoritySeed = seed('seed-authority')
const seedAuthorityPublicKey = ed25519PublicKey(seedAuthoritySeed)
const dummyRecordId = hex(sha256(Buffer.from('record')))
const seedArtifact = await createPeeritSeedBootstrapV1({
  schema: 'peerit-seed-bootstrap-v1',
  version: 1,
  profile: 'LIMITED_PUBLIC_TEST_V1',
  operatorBoundary: 'two-owner-operated-relays-not-independent-operators',
  bootstrapSequence: 0,
  previousBootstrapHash: null,
  releaseSequence: 29,
  authorityPublicKey: hex(seedAuthorityPublicKey),
  issuedAt: nowUnixMillis - 1000,
  expiresAt: nowUnixMillis + 24 * 60 * 60 * 1000,
  relays: relayRows.map(row => ({
    relayId: row.relayId,
    canonicalDescribeUrl: row.canonicalDescribeUrl,
    continuityRootRelayPublicKey: hex(row.relayPublicKey),
    storeId: hex(row.storeId),
    descriptorGenesisHash: hex(row.genesisHash),
    minimumDescriptorSequence: 1,
    familyId: 3,
    operationId: 1,
    endpointId: 1,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1
  })),
  records: [{
    recordId: dummyRecordId,
    wireKeys: ['v2!seq29-exact-source-e2e'],
    authorPublicKey: hex(sha256(Buffer.from('author'))),
    innerCodec: 334,
    innerLength: 8,
    sizeClass: 1,
    logicalHash: hex(sha256(Buffer.from('logical'))),
    encodingCommitment: hex(sha256(Buffer.from('encoding'))),
    replicas: relayRows.map(row => ({
      relayId: row.relayId,
      targetId: `fixture-target-${row.relayId}`,
      readCapability: {
        version: 1,
        relayPublicKey: hex(row.relayPublicKey),
        storageSlot: hex(sha256(Buffer.from(`slot:${row.relayId}`))),
        cellKey: hex(sha256(Buffer.from(`cell-key:${row.relayId}`))),
        sizeClass: 1,
        expectedCellBlobHash: hex(sha256(Buffer.from(`blob:${row.relayId}`)))
      }
    }))
  }]
}, { seedHex: hex(seedAuthoritySeed) })
const seedBootstrapBytes = encodePeeritSeedBootstrapV1(seedArtifact)

const protocolCalls = []
const issuerCalls = new Map(relayRows.map(row => [row.relayId, {
  challenge: 0,
  redeem: 0
}]))
const createCountByRelay = new Map(relayRows.map(row => [row.relayId, 0]))
const custodyDurableBeforeCreate = []
const networkEvents = []
let custodyDirectory = null
let preNetworkCustodyDirectory = null

function signedHealth (row, challenge) {
  return signCanonical(blindHealthResultV1, {
    version: 1,
    relayPublicKey: Buffer.from(row.relayPublicKey),
    storeId: Buffer.from(row.storeId),
    descriptorSequence: row.head.descriptorSequence,
    descriptorHash: Buffer.from(row.headHash),
    endpointId: challenge.endpointId,
    transportSupportBit: challenge.transportSupportBit,
    durabilityContinuityHash: Buffer.from(row.head.durabilityContinuityHash),
    durabilityProfileHash: Buffer.from(row.head.durabilityProfileHash),
    clientNonce: Buffer.from(challenge.clientNonce),
    readyRoleBits: challenge.requestedRoleBits,
    readyOperationBits: challenge.requestedOperationBits,
    clockState: 1,
    effectiveEpochFloor: nowEpoch,
    integrityState: 1,
    checkpointAgeBand: 1,
    scrubAgeBand: 1,
    rebalanceState: 0,
    capacityBand: 2,
    challengeEpoch: nowEpoch,
    signature: Buffer.alloc(64)
  }, RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT, row.privateSeed)
}

function relayBinding (row) {
  return {
    version: 1,
    relayPublicKey: Buffer.from(row.relayPublicKey),
    storeId: Buffer.from(row.storeId),
    descriptorSequence: row.head.descriptorSequence,
    descriptorHash: Buffer.from(row.headHash),
    durabilityProfileId: row.head.durability.profileId,
    durabilityContinuityHash: Buffer.from(row.head.durabilityContinuityHash),
    durabilityProfileHash: Buffer.from(row.head.durabilityProfileHash),
    restoreEvidenceHeadSequence:
      row.head.durability.restoreEvidenceCheckpointSequence,
    restoreEvidenceHeadHash:
      Buffer.from(row.head.durability.restoreEvidenceCheckpointHash),
    externalCommitWitness: null
  }
}

async function protocolBody (row, frame) {
  if (frame.familyId === FAMILY.DESCRIBE &&
      frame.operationId === OPERATION.DESCRIBE.GET) {
    const request = decodeCanonical(blindDescribeGetV1, frame.body, { copyBytes: true })
    if (request.descriptorHash == null || sameBytes(request.descriptorHash, row.headHash)) {
      return row.headBytes
    }
    assert.equal(sameBytes(request.descriptorHash, row.genesisHash), true)
    return row.genesisBytes
  }
  if (frame.familyId === FAMILY.DESCRIBE &&
      frame.operationId === OPERATION.DESCRIBE.CHALLENGE) {
    const challenge = decodeCanonical(blindHealthChallengeV1, frame.body,
      { copyBytes: true })
    return signedHealth(row, challenge)
  }
  if (frame.familyId === FAMILY.DESCRIBE &&
      frame.operationId === OPERATION.DESCRIBE.ADMISSION_PARAMETERS) {
    const request = decodeCanonical(blindAdmissionParametersRequestV1, frame.body,
      { copyBytes: true })
    assert.deepEqual({ profileId: request.profileId, schemeId: request.schemeId },
      { profileId: 3, schemeId: 1 })
    return row.parameterBytes
  }
  assert.equal(frame.familyId, FAMILY.INBOX)
  assert.equal(frame.operationId, OPERATION.INBOX.CREATE)
  const request = decodeCanonical(inboxCreateV1, frame.body, { copyBytes: true })
  assert.equal(request.admission.profileId, 3)
  assert.equal(request.admission.schemeId, 1)
  assert.equal(sameBytes(request.admission.parameterHash, row.parameterHash), true)
  assert.equal(request.admission.token.byteLength, 104)
  createCountByRelay.set(row.relayId, createCountByRelay.get(row.relayId) + 1)
  if (custodyDirectory != null) {
    const entries = await fs.readdir(custodyDirectory, { recursive: true })
    custodyDurableBeforeCreate.push(entries.some(value =>
      value.endsWith('0001-prepared.cenc')))
  }
  const createCommitment = inboxCreateCommitment({
    ...request,
    relayPublicKey: row.relayPublicKey
  })
  const requestCommitment = inboxCreateRequestCommitment({
    inboxCreateCommitment: createCommitment,
    clientNonce: request.clientNonce
  })
  return signCanonical(inboxReceiptV1, {
    version: 1,
    relayBinding: relayBinding(row),
    topicCommitment: blake2b256(request.physicalTopic),
    stateRevision: 0n,
    leaseClass: request.leaseClass,
    leaseEpoch: nowEpoch + 1,
    requestNonce: Buffer.from(request.clientNonce),
    requestCommitment,
    result: INBOX_RECEIPT_RESULT.CREATED,
    signature: Buffer.alloc(64)
  }, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, row.privateSeed)
}

async function requestBody (request, maximumBytes) {
  const chunks = []
  let total = 0
  for await (const chunk of request) {
    total += chunk.byteLength
    assert.ok(total <= maximumBytes, 'loopback request exceeded its exact bound')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks, total)
}

function writeJson (response, value) {
  const body = Buffer.from(JSON.stringify(value))
  response.writeHead(200, {
    'content-type': 'application/json',
    'content-length': String(body.byteLength)
  })
  response.end(body)
}

async function handleLoopbackRequest (relayId, request, response) {
  const row = relayRows.find(value => value.relayId === relayId)
  assert.ok(row, `unknown loopback relay ${relayId}`)
  const url = new URL(request.url, loopbackOriginByRelay.get(relayId))
  const preFiles = preNetworkCustodyDirectory == null
    ? []
    : await fs.readdir(preNetworkCustodyDirectory, { recursive: true }).catch(() => [])
  const custodyFiles = custodyDirectory == null
    ? []
    : await fs.readdir(custodyDirectory, { recursive: true }).catch(() => [])
  networkEvents.push(Object.freeze({
    relayId,
    path: url.pathname,
    preNetworkPrepared: preFiles.includes('0001-pre-network-prepared.json'),
    exactPlanBound: preFiles.includes('0002-exact-plan-binding.json'),
    normalCustodyPrepared: custodyFiles.some(value =>
      value.endsWith('0001-prepared.cenc'))
  }))
  const counts = issuerCalls.get(relayId)
  if (url.pathname === '/challenge') {
    assert.equal(request.method, 'GET')
    counts.challenge++
    const challenge = new Uint8Array(74)
    challenge[0] = 1
    challenge[1] = relayId === 'dal-1' ? 0xd1 : 0x5d
    challenge[41] = 20
    writeJson(response, {
      scheme: 'pow-issuance-v1',
      challenge: Buffer.from(challenge).toString('base64url'),
      difficultyBits: 20,
      expiresAtUnix: 4_000_000_000
    })
    return
  }
  if (url.pathname === '/redeem') {
    assert.equal(request.method, 'POST')
    const redeem = JSON.parse((await requestBody(request, 4096)).toString('utf8'))
    assert.equal(redeem.allowance, 1)
    assert.match(redeem.nonce, /^[0-9a-f]{16}$/)
    counts.redeem++
    writeJson(response, {
      scheme: 'pow-issuance-v1',
      token: (relayId === 'dal-1' ? '83' : '84').repeat(103),
      allowance: 1,
      expiryEpoch: nowEpoch + 2
    })
    return
  }
  assert.equal(new Set([
    '/api/blind/v1/describe',
    '/api/blind/v1/inbox'
  ]).has(url.pathname), true)
  assert.equal(request.method, 'POST')
  const requestBytes = await requestBody(request, 65_536)
  const outer = decodeOuterEnvelope(new Uint8Array(requestBytes), {
    copyInner: true,
    copyBody: true
  })
  assert.equal(url.pathname, outer.frame.familyId === FAMILY.DESCRIBE
    ? '/api/blind/v1/describe'
    : '/api/blind/v1/inbox')
  protocolCalls.push(Object.freeze({
    relayId: row.relayId,
    familyId: outer.frame.familyId,
    operationId: outer.frame.operationId
  }))
  const body = exactResponse(outer.outerClass, outer.frame,
    await protocolBody(row, outer.frame))
  response.writeHead(200, {
    'content-type': PROTOCOL.mediaType,
    'content-length': String(body.byteLength)
  })
  response.end(Buffer.from(body))
}

function assertNoCallables (value, seen = new Set()) {
  if (typeof value === 'function') assert.fail('public composition leaked a callable')
  if (value == null || typeof value !== 'object' || seen.has(value)) return
  seen.add(value)
  for (const child of Object.values(value)) assertNoCallables(child, seen)
}

const root = await fs.mkdtemp('/private/tmp/peerit-seq29-exact-source-e2e-')
const keyDirectory = path.join(root, 'custodian-keys')
custodyDirectory = path.join(root, 'custody')
preNetworkCustodyDirectory = path.join(root, 'pre-network-custody')
const defaultFetch = globalThis.fetch
try {
  await fs.mkdir(keyDirectory, { mode: 0o700 })
  await fs.chmod(keyDirectory, 0o700)
  for (let index = 1; index <= 3; index++) {
    const file = path.join(keyDirectory, `custodian-${index}.x25519`)
    await fs.writeFile(file, seed(`custodian:${index}`), { mode: 0o600 })
    await fs.chmod(file, 0o600)
  }

  const crashSeedBootstrapPath = path.join(root, 'crash-seed-bootstrap.json')
  const crashProfilePath = path.join(root, 'crash-profile.json')
  const crashNetworkMarker = path.join(root, 'crash-network-marker')
  await fs.writeFile(crashSeedBootstrapPath, seedBootstrapBytes, { mode: 0o600 })
  await fs.writeFile(crashProfilePath, profileBytes, { mode: 0o600 })
  const crashReleasePreparation =
    await preparePeeritSeq29LiveInboxCreateReleaseV1({
      seedBootstrapBytes,
      limitedCellPutProfileBytes: profileBytes,
      now: () => nowUnixMillis,
      fixture: {
        allowFixture: true,
        seedAuthorityPublicKey: hex(seedAuthorityPublicKey)
      }
    })
  const crashReleaseSnapshot =
    snapshotPeeritSeq29LiveInboxCreateReleasePreparationV1(
      crashReleasePreparation)
  const crashConfigPath = path.join(root, 'crash-worker-config.json')
  await fs.writeFile(crashConfigPath, JSON.stringify({
    seedBootstrapPath: crashSeedBootstrapPath,
    profilePath: crashProfilePath,
    networkMarker: crashNetworkMarker,
    keyDirectory,
    nowUnixMillis,
    seedAuthorityPublicKey: hex(seedAuthorityPublicKey),
    releaseSnapshot: crashReleaseSnapshot
  }), { mode: 0o600 })

  async function crashWorker (directory, mode, crashStage) {
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url)], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        [TLS_CHILD_ENV]: '1',
        [CRASH_CHILD_ENV]: '1',
        PEERIT_SEQ29_PRE_CUSTODY_CRASH_CONFIG: crashConfigPath,
        PEERIT_SEQ29_PRE_CUSTODY_CRASH_DIRECTORY: directory,
        PEERIT_SEQ29_PRE_CUSTODY_CRASH_MODE: mode,
        PEERIT_SEQ29_PRE_CUSTODY_CRASH_STAGE: crashStage
      }
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    const [status, signal] = await once(child, 'exit')
    return { status, signal, stdout, stderr }
  }

  function assertKilled (result, stage) {
    assert.equal(result.status, null, `${stage} unexpectedly exited: ${result.stderr}`)
    assert.equal(result.signal, 'SIGKILL', `${stage} did not use real process death`)
  }

  async function assertSinglePreparedTransaction (directory) {
    const sealed = path.join(directory, 'sealed')
    const transactions = (await fs.readdir(sealed)).filter(name =>
      /^seq29-[0-9a-f]{64}$/.test(name))
    assert.equal(transactions.length, 1,
      'crash recovery must not create duplicate custody transactions')
    assert.deepEqual((await fs.readdir(path.join(sealed, transactions[0]))).sort(), [
      '0001-prepared.cenc',
      'identity.json'
    ])
  }

  const outerCrashStages = [
    'OUTER_AFTER_STAGE_FSYNC_BEFORE_LINK',
    'OUTER_AFTER_LINK_BEFORE_ALIAS_UNLINK',
    'OUTER_AFTER_ALIAS_UNLINK_BEFORE_DIRECTORY_FSYNC'
  ]
  const crashCases = [
    'INNER_AFTER_PREPARED_FSYNC_BEFORE_GUARD_RELEASE',
    'AFTER_DURABLE_PREPARE',
    'DURING_SELF_VERIFICATION',
    ...outerCrashStages.flatMap(stage => [stage, stage])
  ]
  for (const [index, crashStage] of crashCases.entries()) {
    const directory = path.join(root, `crash-${index}-${crashStage.toLowerCase()}`)
    const sealStage = outerCrashStages.includes(crashStage)
      ? 'AFTER_DURABLE_PREPARE'
      : crashStage
    assertKilled(await crashWorker(directory, 'SEAL', sealStage), sealStage)
    if (outerCrashStages.includes(crashStage)) {
      assertKilled(await crashWorker(directory, 'RESUME', crashStage), crashStage)
      const preparedPath = path.join(directory, '0001-pre-network-prepared.json')
      const stagePath = path.join(directory,
        '.0001-pre-network-prepared.json.peerit-stage-v1')
      if (crashStage === 'OUTER_AFTER_STAGE_FSYNC_BEFORE_LINK') {
        assert.equal((await fs.lstat(stagePath)).nlink, 1)
        await assert.rejects(fs.lstat(preparedPath), error => error.code === 'ENOENT')
      } else if (crashStage === 'OUTER_AFTER_LINK_BEFORE_ALIAS_UNLINK') {
        const stageMetadata = await fs.lstat(stagePath)
        const targetMetadata = await fs.lstat(preparedPath)
        assert.equal(stageMetadata.nlink, 2)
        assert.equal(targetMetadata.nlink, 2)
        assert.equal(stageMetadata.ino, targetMetadata.ino)
      } else {
        assert.equal((await fs.lstat(preparedPath)).nlink, 1)
        await assert.rejects(fs.lstat(stagePath), error => error.code === 'ENOENT')
      }
    }
    const resumed = await crashWorker(directory, 'RESUME', 'NONE')
    assert.equal(resumed.status, 0, `crash recovery failed: ${resumed.stderr}`)
    assert.equal(resumed.signal, null)
    assert.deepEqual((await fs.readdir(directory)).sort(), [
      '0000-pre-network-identity.json',
      '0001-pre-network-prepared.json',
      'sealed'
    ])
    await assertSinglePreparedTransaction(directory)
    await resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
      releaseSnapshot: crashReleaseSnapshot,
      directory,
      custodianKeyDirectory: keyDirectory
    })
  }
  assert.deepEqual(networkEvents, [],
    'every real process-death and recovery path must remain zero-network')
  await assert.rejects(fs.lstat(crashNetworkMarker), error => error.code === 'ENOENT')

  const hostileTemplate = path.join(root, 'hostile-template')
  assertKilled(await crashWorker(hostileTemplate, 'SEAL',
    'AFTER_DURABLE_PREPARE'), 'hostile template durable prepare')
  const completedTemplate = await crashWorker(hostileTemplate, 'RESUME', 'NONE')
  assert.equal(completedTemplate.status, 0, completedTemplate.stderr)
  const outerPreparedName = '0001-pre-network-prepared.json'
  const outerStageName = `.${outerPreparedName}.peerit-stage-v1`

  async function hostileCopy (label) {
    const directory = path.join(root, `hostile-${label}`)
    await fs.cp(hostileTemplate, directory, { recursive: true })
    await fs.chmod(directory, 0o700)
    return directory
  }

  const symlinkRoot = await hostileCopy('stage-symlink')
  const symlinkTarget = path.join(root, 'hostile-symlink-target')
  await fs.writeFile(symlinkTarget, 'attacker-owned\n', { mode: 0o600 })
  await fs.unlink(path.join(symlinkRoot, outerPreparedName))
  await fs.symlink(symlinkTarget, path.join(symlinkRoot, outerStageName))
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: symlinkRoot,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS')
  assert.equal(await fs.readFile(symlinkTarget, 'utf8'), 'attacker-owned\n')
  assert.equal((await fs.lstat(path.join(symlinkRoot, outerStageName))).isSymbolicLink(), true)

  const hardlinkRoot = await hostileCopy('stage-hardlink')
  const hardlinkTarget = path.join(root, 'hostile-hardlink-target')
  await fs.writeFile(hardlinkTarget, '{}\n', { mode: 0o600 })
  await fs.unlink(path.join(hardlinkRoot, outerPreparedName))
  await fs.link(hardlinkTarget, path.join(hardlinkRoot, outerStageName))
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: hardlinkRoot,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS')
  assert.equal((await fs.lstat(hardlinkTarget)).nlink, 2,
    'hostile hard-link stage must not be unlinked')

  const wrongStageRoot = await hostileCopy('wrong-stage-bytes')
  const wrongStage = path.join(wrongStageRoot, outerStageName)
  await fs.unlink(path.join(wrongStageRoot, outerPreparedName))
  await fs.writeFile(wrongStage, '{}\n', { mode: 0o600 })
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: wrongStageRoot,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_PRE_NETWORK_CUSTODY_STATE_CONFLICT')
  assert.equal(await fs.readFile(wrongStage, 'utf8'), '{}\n',
    'wrong-byte stage shadow must not be unlinked')

  const externalAliasRoot = await hostileCopy('canonical-external-alias')
  const externalAlias = path.join(externalAliasRoot, 'attacker-alias')
  await fs.link(path.join(externalAliasRoot, outerPreparedName), externalAlias)
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: externalAliasRoot,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS')
  assert.equal((await fs.lstat(externalAlias)).nlink, 2,
    'an unowned canonical hard-link alias must remain untouched')

  const nlinkThreeRoot = await hostileCopy('canonical-nlink-three')
  const nlinkThreeTarget = path.join(nlinkThreeRoot, outerPreparedName)
  const nlinkThreeStage = path.join(nlinkThreeRoot, outerStageName)
  const nlinkThreeAlias = path.join(nlinkThreeRoot, 'attacker-alias')
  await fs.link(nlinkThreeTarget, nlinkThreeStage)
  await fs.link(nlinkThreeTarget, nlinkThreeAlias)
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: nlinkThreeRoot,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS')
  assert.equal((await fs.lstat(nlinkThreeTarget)).nlink, 3)

  const exactOrphanRoot = await hostileCopy('exact-orphan-stage')
  const exactOrphanTarget = path.join(exactOrphanRoot, outerPreparedName)
  const exactOrphanStage = path.join(exactOrphanRoot, outerStageName)
  const exactOrphanInode = (await fs.lstat(exactOrphanTarget)).ino
  await fs.copyFile(exactOrphanTarget, exactOrphanStage)
  await fs.chmod(exactOrphanStage, 0o600)
  await resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: exactOrphanRoot,
    custodianKeyDirectory: keyDirectory
  })
  assert.equal((await fs.lstat(exactOrphanTarget)).ino, exactOrphanInode)
  await assert.rejects(fs.lstat(exactOrphanStage), error => error.code === 'ENOENT')

  const tamperedInnerRoot = await hostileCopy('tampered-inner')
  await fs.unlink(path.join(tamperedInnerRoot, outerPreparedName))
  const tamperedTransactions = await fs.readdir(path.join(tamperedInnerRoot, 'sealed'))
  const tamperedEnvelope = path.join(tamperedInnerRoot, 'sealed',
    tamperedTransactions[0], '0001-prepared.cenc')
  const tamperedBytes = await fs.readFile(tamperedEnvelope)
  tamperedBytes[tamperedBytes.length - 1] ^= 1
  await fs.writeFile(tamperedEnvelope, tamperedBytes, { mode: 0o600 })
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: tamperedInnerRoot,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED')
  await assert.rejects(fs.lstat(path.join(tamperedInnerRoot, outerPreparedName)),
    error => error.code === 'ENOENT')
  await assert.rejects(fs.lstat(path.join(tamperedInnerRoot, outerStageName)),
    error => error.code === 'ENOENT')

  async function crashedInnerGuard (label) {
    const directory = path.join(root, `hostile-inner-guard-${label}`)
    assertKilled(await crashWorker(directory, 'SEAL',
      'INNER_AFTER_PREPARED_FSYNC_BEFORE_GUARD_RELEASE'),
    `inner guard ${label}`)
    const transactions = await fs.readdir(path.join(directory, 'sealed'))
    assert.equal(transactions.length, 1)
    return {
      directory,
      guard: path.join(directory, 'sealed', transactions[0],
        '.peerit-seq29-transition.lock')
    }
  }

  const foreignGuard = await crashedInnerGuard('foreign-host')
  const foreignOwner = JSON.parse(await fs.readFile(foreignGuard.guard, 'utf8'))
  foreignOwner.hostBootIdentity = '00'.repeat(32)
  const foreignBytes = JSON.stringify(foreignOwner, null, 2) + '\n'
  await fs.writeFile(foreignGuard.guard, foreignBytes, { mode: 0o600 })
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: foreignGuard.directory,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY')
  assert.equal(await fs.readFile(foreignGuard.guard, 'utf8'), foreignBytes,
    'foreign-host guard must never be reclaimed by local PID inference')

  const malformedGuard = await crashedInnerGuard('malformed-stage-binding')
  const malformedOwner = JSON.parse(await fs.readFile(malformedGuard.guard, 'utf8'))
  malformedOwner.stage = '.peerit-seq29-transition.lock.hostile.stage'
  const malformedBytes = JSON.stringify(malformedOwner, null, 2) + '\n'
  await fs.writeFile(malformedGuard.guard, malformedBytes, { mode: 0o600 })
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: malformedGuard.directory,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS')
  assert.equal(await fs.readFile(malformedGuard.guard, 'utf8'), malformedBytes,
    'noncanonical stage binding must not be reclaimed')

  const aliasedGuard = await crashedInnerGuard('external-hardlink')
  const guardAlias = `${aliasedGuard.guard}.attacker-alias`
  await fs.link(aliasedGuard.guard, guardAlias)
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: aliasedGuard.directory,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS')
  assert.equal((await fs.lstat(guardAlias)).nlink, 2,
    'unowned transition-guard hardlink must remain untouched')

  const symlinkGuard = await crashedInnerGuard('symlink')
  const guardTarget = `${symlinkGuard.guard}.attacker-target`
  const guardTargetBytes = await fs.readFile(symlinkGuard.guard)
  await fs.writeFile(guardTarget, guardTargetBytes, { mode: 0o600 })
  await fs.unlink(symlinkGuard.guard)
  await fs.symlink(guardTarget, symlinkGuard.guard)
  await assert.rejects(resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    releaseSnapshot: crashReleaseSnapshot,
    directory: symlinkGuard.directory,
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS')
  assert.deepEqual(await fs.readFile(guardTarget), guardTargetBytes,
    'transition-guard symlink target must remain untouched')
  assert.deepEqual(networkEvents, [],
    'hostile recovery states must fail before any loopback or external request')

  const acceptedA = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
  const acceptedB = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
  assert.strictEqual(acceptedA.control, acceptedB.control)
  assert.equal(acceptedA.identity.candidateCommit, CANDIDATE_COMMIT)
  assert.equal(acceptedA.identity.candidateTree, CANDIDATE_TREE)

  const custodyFirst = await preparePeeritSeq29LiveInboxCreateCustodyFirstV1({
    seedBootstrapBytes,
    limitedCellPutProfileBytes: profileBytes,
    preNetworkCustodyDirectory,
    custodianKeyDirectory: keyDirectory,
    now: () => nowUnixMillis,
    fixture: {
      allowFixture: true,
      seedAuthorityPublicKey: hex(seedAuthorityPublicKey)
    }
  })
  assert.equal(custodyFirst.state, 'PREPARED_BEFORE_NETWORK')
  assert.equal(custodyFirst.networkRequests, 0)
  assert.deepEqual(networkEvents, [],
    'offline authentication, seed generation and durable pre-custody must make zero requests')
  assert.deepEqual((await fs.readdir(preNetworkCustodyDirectory)).sort(), [
    '0000-pre-network-identity.json',
    '0001-pre-network-prepared.json',
    'sealed'
  ])
  const resumedPreNetworkCustody =
    await resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
      releaseSnapshot: custodyFirst.snapshot.releaseSnapshot,
      directory: preNetworkCustodyDirectory,
      custodianKeyDirectory: keyDirectory
    })
  assert.deepEqual(networkEvents, [],
    'reopening and self-verifying durable pre-custody must remain offline')
  const qualification =
    await qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1({
      preparation: custodyFirst.releasePreparation,
      preNetworkCustody: resumedPreNetworkCustody,
      monotonicMillis: () => 1000
    })
  assert.equal(qualification.qualifiedRelayCount, 2)
  assert.strictEqual(globalThis.fetch, defaultFetch,
    'the exact loopback must use the unmodified Node default fetch')
  assert.equal(qualification.candidateCommit, CANDIDATE_COMMIT)
  const qualificationNetworkCount = networkEvents.length
  assert.ok(qualificationNetworkCount > 0)
  assert.equal(networkEvents.every(event => event.preNetworkPrepared), true,
    'the first and every qualification request must follow durable pre-network custody')
  assert.equal(networkEvents.some(event => event.exactPlanBound ||
    event.normalCustodyPrepared), false,
  'qualification is read-only and precedes exact-plan custody')
  const snapshot = snapshotPeeritSeq29LiveInboxCreateQualificationV1(
    qualification)
  assert.deepEqual(snapshot.relays.map(row => row.relayId), ['dal-1', 'syd-1'])
  assert.equal(snapshot.relays.every(row =>
    row.familyId === 3 && row.operationId === 1), true)
  await assert.rejects(createPeeritSeq29LiveInboxCreateCompositionV1({
    qualification: Object.freeze({ ...qualification }),
    issuedUnixMillis: String(nowUnixMillis - 1000),
    expiresUnixMillis: String(nowUnixMillis + 24 * 60 * 60 * 1000),
    authorityPublicKey: '91'.repeat(32),
    stripeSelectionKey: '92'.repeat(32),
    announcementMasterKey: '93'.repeat(32),
    bootstrapSequence: 0,
    previousBootstrapHash: null,
    journalDirectory: path.join(root, 'forged-journal'),
    custodyDirectory: path.join(root, 'forged-custody'),
    publicOutputDirectory: path.join(root, 'forged-output'),
    custodianKeyDirectory: keyDirectory
  }), error => error.code === 'PEERIT_SEQ29_CREATE_QUALIFICATION_REQUIRED')

  const composition = await createPeeritSeq29CustodyFirstLiveInboxCreateCompositionV1({
    qualification,
    preNetworkCustody: resumedPreNetworkCustody,
    issuedUnixMillis: String(nowUnixMillis - 1000),
    expiresUnixMillis: String(nowUnixMillis + 24 * 60 * 60 * 1000),
    authorityPublicKey: '91'.repeat(32),
    stripeSelectionKey: '92'.repeat(32),
    announcementMasterKey: '93'.repeat(32),
    bootstrapSequence: 0,
    previousBootstrapHash: null,
    journalDirectory: path.join(root, 'journal'),
    custodyDirectory,
    publicOutputDirectory: path.join(root, 'public-output'),
    custodianKeyDirectory: keyDirectory
  })
  assert.equal(composition.automaticExecution, false)
  assert.equal(composition.schema,
    'peerit-seq29-live-inbox-create-custody-first-composition-v1')
  assert.equal(composition.candidateCommit, CANDIDATE_COMMIT)
  assert.deepEqual(composition.qualification, qualification)
  assert.equal(composition.authority.planHash, composition.planHash)
  assert.deepEqual(composition.plan.relays.map(row => ({
    relayId: row.relayId,
    canonicalDescribeUrl: row.canonicalDescribeUrl,
    relayPublicKey: row.relayPublicKey
  })), snapshot.relays.map(row => ({
    relayId: row.relayId,
    canonicalDescribeUrl: row.canonicalDescribeUrl,
    relayPublicKey: row.relayPublicKey
  })))
  assert.equal(composition.dryRun.networkRequests, 0)
  assert.equal(composition.dryRun.mutationBudget.inboxCreate, 2)
  assert.equal([...createCountByRelay.values()].reduce((a, b) => a + b, 0), 0)
  assertNoCallables(composition)
  const serialized = JSON.stringify(composition)
  for (const forbidden of [
    'admissionProvider', 'issuanceUrl', 'privateKey', 'relayPublicKey":{',
    'endpointByRelay', 'transportCreate', 'token":"'
  ]) assert.equal(serialized.includes(forbidden), false)

  const freshQualification =
    await qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1({
      preparation: custodyFirst.releasePreparation,
      preNetworkCustody: resumedPreNetworkCustody,
      monotonicMillis: () => 2000
    })
  const freshQualificationNetwork = networkEvents.slice(
    qualificationNetworkCount)
  assert.deepEqual(freshQualificationNetwork.map(event => [
    event.relayId, event.path
  ]), [
    ...Array.from({ length: 5 }, () => ['dal-1', '/api/blind/v1/describe']),
    ...Array.from({ length: 5 }, () => ['syd-1', '/api/blind/v1/describe'])
  ], 'fresh recovery qualification performs the exact read-only descriptor exchange')
  const hashObject = value => createHash('sha256').update(
    canonicalPeeritLimitedPublicInboxJsonV1(value)).digest('hex')
  async function sealAttemptBinding (label, persistedPlan,
    persistedQualification, recover = true) {
    const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(persistedPlan)
    const commitValue =
      `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${planHash}`
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({
      directory: path.join(root, `${label}-binding-journal`)
    })
    await journal.beginAttempt({
      schema: 'peerit-limited-inbox-create-only-attempt-v1',
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
      releaseSequence: 29,
      planHash,
      relayIdentityDigest: 'd'.repeat(64),
      commitTokenHash: createHash('sha256').update(commitValue).digest('hex'),
      operationBudget: { family: 'INBOX', operation: 'CREATE', maximum: 2 },
      plan: persistedPlan,
      planSha256: hashObject(persistedPlan),
      persistedQualification,
      persistedQualificationSha256: hashObject(persistedQualification)
    })
    return {
      journal,
      binding: recover
        ? recoverPeeritSeq29FilesystemAttemptBindingV1({ journal })
        : null
    }
  }
  const initialSealed = await sealAttemptBinding('initial-recovery',
    composition.plan, composition.persistedQualification)
  const recoveryInput = {
    qualification: freshQualification,
    preNetworkCustody: resumedPreNetworkCustody,
    persistedAttemptBinding: initialSealed.binding,
    expectedPlanHash: composition.planHash,
    journalDirectory: path.join(root, 'recovery-journal'),
    custodyDirectory: path.join(root, 'recovery-custody'),
    publicOutputDirectory: path.join(root, 'recovery-public-output'),
    custodianKeyDirectory: keyDirectory
  }
  const recoveryComposition =
    await createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1(
      recoveryInput)
  assert.equal(recoveryComposition.schema,
    'peerit-seq29-live-inbox-create-persisted-plan-recovery-composition-v1')
  assert.equal(recoveryComposition.planHash, composition.planHash)
  assert.deepEqual(recoveryComposition.plan, composition.plan)
  assert.deepEqual(recoveryComposition.persistedQualification,
    composition.persistedQualification)
  assert.equal(recoveryComposition.executionBoundary,
    'EXPLICIT_IN_PROCESS_PERSISTED_PLAN_FRESH_ENDPOINT_RECOVERY_ONLY')
  await assert.rejects(
    createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1({
      ...recoveryInput,
      expectedPlanHash: recoveryInput.expectedPlanHash.toUpperCase()
    }), error => error.code === 'PEERIT_SEQ29_CREATE_PLAN_INVALID')
  await assert.rejects(
    createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1({
      ...recoveryInput,
      persistedAttemptBinding: {
        schema: initialSealed.binding.schema,
        planHash: initialSealed.binding.planHash
      },
      journalDirectory: path.join(root, 'plain-binding-journal'),
      custodyDirectory: path.join(root, 'plain-binding-custody'),
      publicOutputDirectory: path.join(root, 'plain-binding-output')
    }), error => error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY',
    'a plain lookalike object cannot self-assert sealed continuity')
  const floorDriftPlan = structuredClone(composition.plan)
  floorDriftPlan.relays[0].descriptorFloor.sequence = String(
    BigInt(floorDriftPlan.relays[0].descriptorFloor.sequence) + 1n)
  const floorDriftHash = peeritLimitedInboxTopicCeremonyPlanHashV1(
    floorDriftPlan)
  const floorDriftContinuity = {
    ...composition.persistedQualification,
    planHash: floorDriftHash
  }
  const floorDriftSealed = await sealAttemptBinding('floor-drift',
    floorDriftPlan, floorDriftContinuity)
  await assert.rejects(
    createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1({
      ...recoveryInput,
      persistedAttemptBinding: floorDriftSealed.binding,
      expectedPlanHash: floorDriftHash,
      journalDirectory: path.join(root, 'drift-recovery-journal'),
      custodyDirectory: path.join(root, 'drift-recovery-custody'),
      publicOutputDirectory: path.join(root, 'drift-recovery-output')
    }), error => error.code === 'PEERIT_SEQ29_CREATE_RECOVERY_PLAN_DRIFT')
  const sourceDriftContinuity = {
    ...composition.persistedQualification,
    seedBootstrapSha256: 'f'.repeat(64)
  }
  const sourceDriftSealed = await sealAttemptBinding('source-drift',
    composition.plan, sourceDriftContinuity)
  await assert.rejects(
    createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1({
      ...recoveryInput,
      persistedAttemptBinding: sourceDriftSealed.binding,
      journalDirectory: path.join(root, 'source-drift-journal'),
      custodyDirectory: path.join(root, 'source-drift-custody'),
      publicOutputDirectory: path.join(root, 'source-drift-output')
    }), error => error.code === 'PEERIT_SEQ29_CREATE_RECOVERY_SOURCE_DRIFT')

  const freshReference = BigInt(snapshot.referenceUnixMillis)
  async function timeBoundRecoveryInput (label, reference, issued, expires) {
    const persistedPlan = structuredClone(composition.plan)
    persistedPlan.referenceUnixMillis = String(reference)
    persistedPlan.issuedUnixMillis = String(issued)
    persistedPlan.expiresUnixMillis = String(expires)
    const expectedPlanHash = peeritLimitedInboxTopicCeremonyPlanHashV1(
      persistedPlan)
    const persistedQualification = {
      ...composition.persistedQualification,
      planHash: expectedPlanHash,
      referenceUnixMillis: String(reference)
    }
    const sealed = await sealAttemptBinding(label, persistedPlan,
      persistedQualification)
    return {
      ...recoveryInput,
      persistedAttemptBinding: sealed.binding,
      expectedPlanHash,
      journalDirectory: path.join(root, `${label}-journal`),
      custodyDirectory: path.join(root, `${label}-custody`),
      publicOutputDirectory: path.join(root, `${label}-output`)
    }
  }
  const justBefore = await timeBoundRecoveryInput('just-before-expiry',
    freshReference, freshReference - 3n, freshReference + 1n)
  assert.equal((await
  createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1(
    justBefore)).planHash, justBefore.expectedPlanHash,
  'a fresh qualification strictly before expiry may recover the exact plan')
  for (const [label, expires] of [
    ['at-expiry', freshReference],
    ['after-expiry', freshReference - 1n]
  ]) {
    const expired = await timeBoundRecoveryInput(label,
      freshReference - 2n, freshReference - 3n, expires)
    await assert.rejects(
      createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1(
        expired),
      error => error.code === 'PEERIT_SEQ29_CREATE_RECOVERY_PLAN_EXPIRED')
  }
  const substituted = await sealAttemptBinding('substituted-bytes',
    composition.plan, composition.persistedQualification, false)
  const beginPath = path.join(substituted.journal.inspect().slot,
    '0000-begin.json')
  const beginEvent = JSON.parse(await fs.readFile(beginPath, 'utf8'))
  beginEvent.body.request.persistedQualification.seedBootstrapSha256 =
    'e'.repeat(64)
  await fs.writeFile(beginPath, JSON.stringify(beginEvent, null, 2) + '\n', {
    mode: 0o600
  })
  assert.throws(() => recoverPeeritSeq29FilesystemAttemptBindingV1({
    journal: substituted.journal
  }), error => error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
  'substituted journal bytes cannot become a branded continuity proof')
  assert.equal([...createCountByRelay.values()].reduce((a, b) => a + b, 0), 0,
    'fresh endpoint recovery composition cannot dispatch CREATE by itself')

  const executionNetworkBaseline = networkEvents.length
  const executed = await runPeeritSeq29LiveInboxCeremonyConductorV1({
    conductor: composition.conductor,
    executeBoundary: '--execute',
    commitToken: composition.commitToken
  })
  assert.deepEqual(executed.result.mutationLedger, {
    inboxCreate: 2,
    inboxRenew: 0,
    inboxClose: 0,
    inboxAppend: 0,
    cellPut: 0,
    other: 0
  })
  assert.deepEqual(executed.result.signingPackage.createRequests.map(row => ({
    relayId: row.relayId,
    clientNonce: row.clientNonce,
    requestCommitment: row.requestCommitment,
    createPublicKey: row.createPublicKey,
    renewPublicKey: row.renewPublicKey,
    closePublicKey: row.closePublicKey
  })), custodyFirst.snapshot.requests.map(row => ({
    relayId: row.relayId,
    clientNonce: row.clientNonce,
    requestCommitment: row.requestCommitment,
    createPublicKey: row.createPublicKey,
    renewPublicKey: row.renewPublicKey,
    closePublicKey: row.closePublicKey
  })), 'final signed-package requests must exactly replay pre-network commitments')
  assert.deepEqual([...createCountByRelay], [['dal-1', 1], ['syd-1', 1]])
  assert.deepEqual(custodyDurableBeforeCreate, [true, true])
  assert.deepEqual([...issuerCalls].map(([relayId, value]) => [
    relayId, value.challenge, value.redeem
  ]), [['dal-1', 1, 1], ['syd-1', 1, 1]])
  const executionNetwork = networkEvents.slice(executionNetworkBaseline)
  assert.deepEqual(executionNetwork.map(event => [event.relayId, event.path]), [
    ['dal-1', '/challenge'],
    ['dal-1', '/redeem'],
    ['syd-1', '/challenge'],
    ['syd-1', '/redeem'],
    ['dal-1', '/api/blind/v1/inbox'],
    ['syd-1', '/api/blind/v1/inbox']
  ])
  assert.equal(executionNetwork.every(event => event.preNetworkPrepared &&
    event.exactPlanBound && event.normalCustodyPrepared), true,
  'admission and CREATE must follow both durable custody stages and their exact-plan binding')
  const mutationCalls = protocolCalls.filter(call =>
    call.familyId !== FAMILY.DESCRIBE)
  assert.deepEqual(mutationCalls.map(call => [
    call.relayId, call.familyId, call.operationId
  ]), [
    ['dal-1', FAMILY.INBOX, OPERATION.INBOX.CREATE],
    ['syd-1', FAMILY.INBOX, OPERATION.INBOX.CREATE]
  ])

  await assert.rejects(runPeeritSeq29LiveInboxCeremonyConductorV1({
    conductor: composition.conductor,
    executeBoundary: '--execute',
    commitToken: composition.commitToken
  }))
  assert.deepEqual([...createCountByRelay], [['dal-1', 1], ['syd-1', 1]],
    'durable replay cannot produce a third CREATE or retry')
  assert.deepEqual([...issuerCalls].map(([relayId, value]) => [
    relayId, value.challenge, value.redeem
  ]), [['dal-1', 1, 1], ['syd-1', 1, 1]])
  await assert.rejects(runPeeritSeq29LiveInboxCeremonyConductorV1({
    conductor: JSON.parse(JSON.stringify(composition.conductor)),
    executeBoundary: '--execute',
    commitToken: composition.commitToken
  }), error => error.code === 'PEERIT_SEQ29_LIVE_CONDUCTOR_AUTHORITY_REQUIRED')
  const networkCountBeforeRootReplacement = networkEvents.length
  await fs.rename(preNetworkCustodyDirectory,
    `${preNetworkCustodyDirectory}-original`)
  await fs.mkdir(preNetworkCustodyDirectory, { mode: 0o700 })
  await assert.rejects(
    qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1({
      preparation: custodyFirst.releasePreparation,
      preNetworkCustody: resumedPreNetworkCustody,
      monotonicMillis: () => 1000
    }),
    error => error.code ===
      'PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED')
  assert.equal(networkEvents.length, networkCountBeforeRootReplacement,
    'replaced custody root must fail before default fetch')
  assert.deepEqual(loopbackServerErrors, [])
} finally {
  await Promise.all(loopbackServers.map(server => new Promise((resolve, reject) => {
    server.close(error => error == null ? resolve() : reject(error))
  })))
  await fs.rm(root, { recursive: true, force: true })
}

console.log('peerit seq29 exact adeacef real-loopback E2E: default fetch, same branded endpoint control, durable custody, exactly DAL+SYD CREATE, no retries or other mutations')
