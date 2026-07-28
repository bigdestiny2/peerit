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
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'

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
    minimumDescriptorSequence: 1
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
const releaseManifestHash = 'a3'.repeat(32)
const payload = {
  schema: PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  version: 1,
  profile: PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  operatorBoundary: PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  bootstrapSequence: 0,
  previousBootstrapHash: null,
  releaseSequence: 13,
  releaseManifestHash,
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
const verification = {
  authorityPublicKey: authority.pubHex,
  releaseSequence: 13,
  releaseManifestHash,
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

const shared = createMemoryJournalState()
const journal = createMemoryPeeritJournal({ shared, clock: () => 2_000 })
const sync = createSync({
  mode: 'substrate',
  journal,
  relays: [],
  autoFlush: false,
  channelName: 'peerit-seed-cold-reader-one'
})
await sync.ready()
const capabilityKv = memoryCapabilityVaultKv()
const capabilityVault = createPeeritCapabilityVault({
  kv: capabilityKv,
  crypto: globalThis.crypto,
  now: () => 2_000
})
const reads = []
const reader = createPeeritSeedColdReaderV1({
  sync,
  capabilityVault,
  relays: [{ id: relayA.relayId }, { id: relayB.relayId }],
  now: () => 2_000,
  readReplica: async (_relay, request) => {
    reads.push(request.relayId)
    if (request.relayId === relayA.relayId) {
      const error = new Error('simulated first-replica outage')
      error.code = 'BLIND_CELL_UNAVAILABLE'
      throw error
    }
    return {
      verified: true,
      relayId: request.relayId,
      targetId: request.targetId,
      innerBytes: envelope.innerBytes,
      evidenceRef: `fixture:${request.relayId}:${request.recordId}`
    }
  }
})

const recovered = await reader.read(artifactBytes, verification)
assert.deepEqual(reads, ['dal-1', 'syd-1'])
assert.equal(recovered.cached, false)
assert.equal(recovered.networkGets, 2)
assert.equal(recovered.networkPuts, 0)
assert.equal(recovered.fallbackCount, 1)
assert.equal(recovered.ingest.pendingIntentsCreated, 0)
assert.equal(recovered.ingest.relayTargetsCreated, 0)
assert.equal((await sync.get(envelope.operationWireKeys[0])).name, operation.data.name)
assert.equal(shared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(shared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
assert.equal(shared.stores.get(JOURNAL_STORES.DEDUPE).size, 0)
assert.equal((await journal.summary()).pendingIntentCount, 0)

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

sync.destroy()
const restartedJournal = createMemoryPeeritJournal({ shared, clock: () => 2_001 })
const restartedSync = createSync({
  mode: 'substrate',
  journal: restartedJournal,
  relays: [],
  autoFlush: false,
  channelName: 'peerit-seed-cold-reader-restarted'
})
await restartedSync.ready()
let restartedReads = 0
const restartedReader = createPeeritSeedColdReaderV1({
  sync: restartedSync,
  relays: [{ id: relayA.relayId }, { id: relayB.relayId }],
  now: () => 2_001,
  readReplica: async () => { restartedReads++; throw new Error('must not run') }
})
const cached = await restartedReader.read(artifactBytes, verification)
assert.equal(cached.cached, true)
assert.equal(cached.networkGets, 0)
assert.equal(cached.networkPuts, 0)
assert.equal(restartedReads, 0)
assert.equal((await restartedSync.get(envelope.operationWireKeys[0])).name, operation.data.name)
assert.equal(shared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(shared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
restartedSync.destroy()

const failureShared = createMemoryJournalState()
const failureJournal = createMemoryPeeritJournal({ shared: failureShared, clock: () => 2_000 })
const failureSync = createSync({
  mode: 'substrate',
  journal: failureJournal,
  relays: [],
  autoFlush: false,
  channelName: 'peerit-seed-cold-reader-failure'
})
await failureSync.ready()
const failureReader = createPeeritSeedColdReaderV1({
  sync: failureSync,
  relays: [{ id: relayA.relayId }, { id: relayB.relayId }],
  now: () => 2_000,
  readReplica: async (_relay, request) => ({
    verified: true,
    relayId: request.relayId,
    targetId: request.targetId,
    innerBytes: new Uint8Array(envelope.innerBytes.length),
    evidenceRef: 'fixture:tampered'
  })
})
await assert.rejects(
  failureReader.read(artifactBytes, verification),
  error => error && error.code === 'PEERIT_REMOTE_INGEST_ENVELOPE_MISMATCH'
)
assert.equal(await failureSync.discoveryFloor(verified.sourceId), null)
assert.equal(failureShared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(failureShared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
failureSync.destroy()

console.log('peerit signed seed bootstrap and GET-only cold reader: ok')
