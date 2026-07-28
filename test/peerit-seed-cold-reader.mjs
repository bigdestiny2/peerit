import assert from 'node:assert/strict'
import { canonical } from '../js/canon.js'
import { genKeyPair, ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { createSync, memoryStorage } from '../js/sync.js'
import {
  createPeeritCapabilityVault,
  memoryCapabilityVaultKv
} from '../js/substrate/capability-vault.js'
import { createPeeritSeedColdReaderV1 } from '../js/substrate/cold-reader.mjs'
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
  PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  PEERIT_SEED_BOOTSTRAP_RELEASE_BINDING_V1,
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1,
  hashPeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import { qualifySeedRelayFixtures } from './fixtures/peerit-qualified-seed-relays.mjs'

function hex (value) {
  return Buffer.from(value).toString('hex')
}

async function signedProfile (identity, name) {
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
}

function relay (relayId, publicKey, fill) {
  return {
    relayId,
    canonicalDescribeUrl: `https://${relayId}.example/api/blind/v1/describe`,
    continuityRootRelayPublicKey: publicKey,
    storeId: fill.toString(16).padStart(2, '0').repeat(32),
    descriptorGenesisHash: (fill + 1).toString(16).padStart(2, '0').repeat(32),
    minimumDescriptorSequence: 0,
    familyId: 2,
    operationId: 2,
    endpointId: 1,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1
  }
}

function replica (relayRoot, targetId, fill, sizeClass) {
  return {
    relayId: relayRoot.relayId,
    targetId,
    readCapability: {
      version: 1,
      relayPublicKey: relayRoot.continuityRootRelayPublicKey,
      storageSlot: fill.toString(16).padStart(2, '0').repeat(32),
      cellKey: (fill + 1).toString(16).padStart(2, '0').repeat(32),
      sizeClass,
      expectedCellBlobHash: (fill + 2).toString(16).padStart(2, '0').repeat(32)
    }
  }
}

await cryptoReady()

const author = createIdentity({
  forceDev: true,
  lazy: true,
  storage: memoryStorage(),
  session: memoryStorage()
})
await author.ready()
await author.ensureActive('peerit-seed-cold-reader')
const operation = await signedProfile(author, 'Recovered from signed Blind Cells')
const envelope = await createPeeritInnerOperationBatchV1([operation])
const authority = await genKeyPair()
const relayAKey = await genKeyPair()
const relayBKey = await genKeyPair()
const relayA = relay('dal-1', relayAKey.pubHex, 0x10)
const relayB = relay('syd-1', relayBKey.pubHex, 0x20)
const recordId = hex(hashPeeritInnerOperationIntentIdV1(envelope.innerCodec, envelope.innerBytes))
const payload = {
  schema: PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  version: 1,
  profile: PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  operatorBoundary: PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  bootstrapSequence: 0,
  previousBootstrapHash: null,
  releaseSequence: 13,
  authorityPublicKey: authority.pubHex,
  issuedAt: 1_000,
  expiresAt: 10_000,
  relays: [relayA, relayB],
  records: [{
    recordId,
    wireKeys: [...envelope.operationWireKeys],
    authorPublicKey: envelope.authorPublicKey,
    innerCodec: envelope.innerCodec,
    innerLength: Number(envelope.innerLength),
    sizeClass: envelope.sizeClass,
    logicalHash: hex(envelope.logicalHash),
    encodingCommitment: hex(envelope.encodingCommitment),
    replicas: [
      replica(relayA, 'cell-v1:dal-1:seed', 0x30, envelope.sizeClass),
      replica(relayB, 'cell-v1:syd-1:seed', 0x40, envelope.sizeClass)
    ]
  }]
}
const artifact = await createPeeritSeedBootstrapV1(payload, { seedHex: authority.seedHex })
const artifactBytes = encodePeeritSeedBootstrapV1(artifact)
const artifactHash = await hashPeeritSeedBootstrapV1(artifactBytes)
const verification = {
  authorityPublicKey: authority.pubHex,
  releaseSequence: 13,
  expectedArtifactHash: artifactHash,
  previousBootstrapHash: null
}

const verified = await verifyPeeritSeedBootstrapV1(artifactBytes, { ...verification, now: 2_000 })
assert.equal(verified.payload.records[0].recordId, recordId)
await assert.rejects(
  verifyPeeritSeedBootstrapV1(artifactBytes, { ...verification, releaseSequence: 14, now: 2_000 }),
  error => error && error.code === 'PEERIT_SEED_BOOTSTRAP_RELEASE_MISMATCH'
)
await assert.rejects(
  createPeeritSeedBootstrapV1({
    ...payload,
    relays: [relayA, relayB],
    records: [{
      ...payload.records[0],
      replicas: [
        {
          ...payload.records[0].replicas[0],
          readCapability: {
            ...payload.records[0].replicas[0].readCapability,
            relayPublicKey: relayB.continuityRootRelayPublicKey
          }
        },
        payload.records[0].replicas[1]
      ]
    }]
  }, { seedHex: authority.seedHex }),
  error => error && error.code === 'PEERIT_SEED_BOOTSTRAP_BAD_READ_CAPABILITY'
)

assert.equal(Object.hasOwn(artifact.payload, 'releaseManifestHash'), false,
  'the signed bootstrap cannot embed the terminal manifest that reverse-binds it')
assert.deepEqual(PEERIT_SEED_BOOTSTRAP_RELEASE_BINDING_V1, {
  direction: 'authenticated-terminal-release-profile-to-bootstrap',
  authenticatedReleaseField: 'peeritSeedBootstrapSha256',
  hashAlgorithm: 'sha256',
  verificationOption: 'expectedArtifactHash',
  bootstrapEmbedsTerminalManifestHash: false
})
const changedPayload = JSON.parse(JSON.stringify(payload))
changedPayload.expiresAt--
const changedArtifact = await createPeeritSeedBootstrapV1(changedPayload, { seedHex: authority.seedHex })
const changedBytes = encodePeeritSeedBootstrapV1(changedArtifact)
assert.notEqual(await hashPeeritSeedBootstrapV1(changedBytes), artifactHash)
await assert.rejects(
  verifyPeeritSeedBootstrapV1(changedBytes, { ...verification, now: 2_000 }),
  error => error && error.code === 'PEERIT_SEED_BOOTSTRAP_RELEASE_MISMATCH'
)

function substrate (name, shared = createMemoryJournalState(), clock = 2_000) {
  const journal = createMemoryPeeritJournal({ shared, clock: () => clock })
  const sync = createSync({
    mode: 'substrate',
    journal,
    relays: [],
    autoFlush: false,
    channelName: name
  })
  return { shared, journal, sync }
}

let readMode = 'fallback'
const reads = []
const adapters = await qualifySeedRelayFixtures([relayA, relayB], async (relayId, request) => {
  reads.push(relayId)
  if (readMode === 'never-settles-first' && relayId === relayA.relayId) return new Promise(() => {})
  if (readMode === 'fallback' && relayId === relayA.relayId) {
    const error = new Error('simulated first-replica outage')
    error.code = 'BLIND_CELL_UNAVAILABLE'
    throw error
  }
  if (readMode === 'tampered') {
    return { innerBytes: new Uint8Array(envelope.innerBytes.length), evidenceRef: 'fixture:tampered' }
  }
  if (readMode === 'must-not-read') throw new Error('network must not run for cached bootstrap')
  return {
    innerBytes: envelope.innerBytes,
    evidenceRef: `fixture:${relayId}:${request.recordId}`
  }
})

const main = substrate('peerit-seed-cold-reader-one')
await main.sync.ready()
const capabilityKv = memoryCapabilityVaultKv()
const capabilityVault = createPeeritCapabilityVault({
  kv: capabilityKv,
  crypto: globalThis.crypto,
  now: () => 2_000
})
const reader = createPeeritSeedColdReaderV1({
  sync: main.sync,
  capabilityVault,
  relays: adapters,
  now: () => 2_000
})

// Adapter-shaped input and a caller-forged verified=true result never cross the
// private qualification/result brands.
const forgedReader = createPeeritSeedColdReaderV1({
  sync: main.sync,
  relays: [
    { readCellCapability: async () => ({ verified: true, innerBytes: envelope.innerBytes, evidenceRef: 'forged' }) },
    { readCellCapability: async () => ({ verified: true, innerBytes: envelope.innerBytes, evidenceRef: 'forged' }) }
  ],
  now: () => 2_000
})
await assert.rejects(
  forgedReader.read(artifactBytes, verification),
  error => error && error.code === 'PEERIT_VERIFIED_RELAY_ADAPTER_REQUIRED'
)

// Every signed continuity and operation/transport component is enforced at the
// branded adapter seam before any capability is used or network GET begins.
for (const mutate of [
  value => { value.relays[0].canonicalDescribeUrl = 'https://other.example/api/blind/v1/describe' },
  value => {
    value.relays[0].continuityRootRelayPublicKey = '99'.repeat(32)
    value.records[0].replicas[0].readCapability.relayPublicKey = '99'.repeat(32)
  },
  value => { value.relays[0].storeId = '98'.repeat(32) },
  value => { value.relays[0].descriptorGenesisHash = '97'.repeat(32) },
  value => { value.relays[0].minimumDescriptorSequence = 1 },
  value => { value.relays[0].familyId = 3 },
  value => { value.relays[0].operationId = 3 },
  value => { value.relays[0].endpointId = 2 },
  value => { value.relays[0].transportId = 2 },
  value => { value.relays[0].transportSupportBit = 2 },
  value => { value.relays[0].privacyProfileBit = 2 }
]) {
  const mismatchPayload = JSON.parse(JSON.stringify(payload))
  mutate(mismatchPayload)
  const mismatchArtifact = await createPeeritSeedBootstrapV1(mismatchPayload, { seedHex: authority.seedHex })
  const mismatchBytes = encodePeeritSeedBootstrapV1(mismatchArtifact)
  await assert.rejects(
    reader.read(mismatchBytes, {
      ...verification,
      expectedArtifactHash: await hashPeeritSeedBootstrapV1(mismatchBytes)
    }),
    error => error && error.code === 'PEERIT_COLD_READER_RELAY_BINDING_MISMATCH'
  )
}
assert.equal(reads.length, 0, 'relay-binding mismatches fail before any GET')

const recovered = await reader.read(artifactBytes, verification)
assert.deepEqual(reads, ['dal-1', 'syd-1'])
assert.equal(recovered.cached, false)
assert.equal(recovered.networkGets, 2)
assert.equal(recovered.networkPuts, 0)
assert.equal(recovered.fallbackCount, 1)
assert.equal(recovered.ingest.pendingIntentsCreated, 0)
assert.equal(recovered.ingest.relayTargetsCreated, 0)
assert.equal((await main.sync.get(envelope.operationWireKeys[0])).name, operation.data.name)
assert.equal(main.shared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(main.shared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
assert.equal(main.shared.stores.get(JOURNAL_STORES.DEDUPE).size, 0)
assert.equal((await main.journal.summary()).pendingIntentCount, 0)

const persistedReader = await capabilityVault.loadReaderCapability(
  recovered.sourceId,
  recordId,
  payload.records[0].replicas[1].targetId
)
assert.equal(persistedReader.payload.kind, 'public-reader-v1')
assert.deepEqual(persistedReader.payload.readCapability.cellKey,
  new Uint8Array(Buffer.from(payload.records[0].replicas[1].readCapability.cellKey, 'hex')))
const rawVault = JSON.stringify([...capabilityKv.records.values()], (_key, value) =>
  value instanceof Uint8Array ? Buffer.from(value).toString('hex') : value)
assert.doesNotMatch(rawVault, new RegExp(payload.records[0].replicas[1].readCapability.cellKey, 'i'))
await assert.rejects(capabilityVault.persistReaderCapability({
  ...persistedReader.payload,
  targetId: 'cell-v1:forged-management-cap',
  readCapability: { ...persistedReader.payload.readCapability, dropPrivateKey: new Uint8Array(32) }
}), /management or unknown fields/)

main.sync.destroy()
const restarted = substrate('peerit-seed-cold-reader-restarted', main.shared, 2_001)
await restarted.sync.ready()
readMode = 'must-not-read'
const readCountBeforeRestart = reads.length
const restartedReader = createPeeritSeedColdReaderV1({
  sync: restarted.sync,
  relays: adapters,
  now: () => 2_001
})
const cached = await restartedReader.read(artifactBytes, verification)
assert.equal(cached.cached, true)
assert.equal(cached.networkGets, 0)
assert.equal(cached.networkPuts, 0)
assert.equal(reads.length, readCountBeforeRestart)
assert.equal((await restarted.sync.get(envelope.operationWireKeys[0])).name, operation.data.name)
assert.equal(main.shared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(main.shared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
restarted.sync.destroy()

// A non-cooperative first adapter cannot hold the batch forever. The hard
// deadline aborts it, safely observes any late rejection, and falls through.
const deadline = substrate('peerit-seed-cold-reader-hard-deadline')
await deadline.sync.ready()
readMode = 'never-settles-first'
reads.length = 0
const deadlineReader = createPeeritSeedColdReaderV1({
  sync: deadline.sync,
  relays: adapters,
  now: () => 2_000,
  timeoutMillis: 20
})
const startedAt = Date.now()
const deadlineRecovered = await deadlineReader.read(artifactBytes, verification)
assert.deepEqual(reads, ['dal-1', 'syd-1'])
assert.equal(deadlineRecovered.fallbackCount, 1)
assert.equal(deadlineRecovered.networkPuts, 0)
assert.ok(Date.now() - startedAt < 500, 'non-cooperative adapter is bounded by a real deadline')
deadline.sync.destroy()

const failure = substrate('peerit-seed-cold-reader-failure')
await failure.sync.ready()
readMode = 'tampered'
const failureReader = createPeeritSeedColdReaderV1({
  sync: failure.sync,
  relays: adapters,
  now: () => 2_000
})
await assert.rejects(
  failureReader.read(artifactBytes, verification),
  error => error && error.code === 'PEERIT_REMOTE_INGEST_ENVELOPE_MISMATCH'
)
assert.equal(await failure.sync.discoveryFloor(verified.sourceId), null)
assert.equal(failure.shared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(failure.shared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
failure.sync.destroy()

console.log('peerit signed seed bootstrap and GET-only cold reader: ok')
