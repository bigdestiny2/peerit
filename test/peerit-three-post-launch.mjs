import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { ready as cryptoReady, genKeyPair } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { contentId, TYPE } from '../js/model.js'
import { memoryStorage } from '../js/sync.js'
import {
  PEERIT_THREE_POST_RELAY_TUPLE_SCHEMA_V1,
  PEERIT_THREE_POST_SCOPE_SCHEMA_V1,
  bindCurrentRelayTupleV1,
  composeThreePostPlanV1,
  createSignedThreePostBootstrapV1,
  createThreePostVaultBridgeV1,
  publishThreePostPlanV1,
  recoverThreePostPlanV1,
  selectThreePostWaveZeroV1,
  sha256Hex,
  validateCurrentRelayTupleV1
} from '../scripts/lib/three-post-launch.mjs'
import { createPeeritSeedPublisherVaultV1 } from '../scripts/lib/seed-publisher-vault.mjs'
import { runThreePostBootstrapOnlyCliV1 } from '../scripts/peerit-three-post-launch.mjs'
import { verifyPeeritSeedBootstrapV1 } from '../js/substrate/seed-bootstrap-v1.mjs'
import { qualifySeedRelayFixtures } from './fixtures/peerit-qualified-seed-relays.mjs'

const hex = value => Buffer.from(value).toString('hex')
const fill = (value, length = 32) => new Uint8Array(length).fill(value)
const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'peerit-three-post-launch-'))
const vaultPath = path.join(directory, 'publisher', 'state.enc')
const passphraseText = 'local three post fixture passphrase'
const passphrase = () => new TextEncoder().encode(passphraseText)
let clock = 2_000

await cryptoReady()

async function identity (label) {
  const value = createIdentity({
    forceDev: true,
    lazy: true,
    storage: memoryStorage(),
    session: memoryStorage()
  })
  await value.ready()
  await value.ensureActive(label)
  return value
}

const identities = new Map([
  ['mod-ai', await identity('three-post-mod')],
  ['ops-homelab', await identity('three-post-ops')],
  ['builder-nostr', await identity('three-post-builder')]
])
const personas = {
  personas: Object.fromEntries([...identities].map(([name, value]) => [name, { pubkeyHex: value.me().pubkey }]))
}
const posts = [
  { order: 1, opPersona: 'mod-ai', title: 'Pinned local AI norms', seed: 'fixture-ai-1', bodyText: 'Numbers and reproducible settings.' },
  { order: 2, opPersona: 'ops-homelab', title: 'A local model benchmark', seed: 'fixture-ai-2', bodyText: 'Measured locally with a fixed prompt.' },
  { order: 3, opPersona: 'builder-nostr', title: 'Serving overhead notes', seed: 'fixture-ai-3', bodyText: 'Cold and warm paths differ.' }
].map(row => ({ board: 'ai_local', pinned: row.order === 1, announcement: false, bounty: false, replies: [], ...row }))
const manifest = {
  boards: [{ slug: 'ai_local', title: 'r/ai_local', description: 'Local models.', claimPersona: 'mod-ai' }],
  posts
}
const manifestBytes = Buffer.from(JSON.stringify(manifest))
const manifestSha256 = sha256Hex(manifestBytes)
const scopePosts = []
for (const post of posts) {
  scopePosts.push({
    order: post.order,
    seed: post.seed,
    title: post.title,
    cid: await contentId(TYPE.POST, identities.get(post.opPersona).me().pubkey, post.seed)
  })
}
const scope = Object.freeze({
  schema: PEERIT_THREE_POST_SCOPE_SCHEMA_V1,
  board: 'ai_local',
  communityCount: 1,
  postCount: 3,
  posts: Object.freeze(scopePosts.map(Object.freeze))
})
const selection = await selectThreePostWaveZeroV1({
  manifest,
  manifestSha256,
  personas,
  scope,
  expectedManifestSha256: manifestSha256
})
const plan = await composeThreePostPlanV1({
  selection,
  personas,
  identityFor: name => identities.get(name),
  now: clock
})
assert.equal(plan.records.length, 4)
assert.deepEqual(plan.expectedCids, scopePosts.map(row => row.cid))

function tupleRow (relayId, root, base) {
  return {
    relayId,
    canonicalDescribeUrl: `https://${relayId}.example/api/blind/v1/describe`,
    continuityRootRelayPublicKey: root,
    storeId: base.toString(16).padStart(2, '0').repeat(32),
    descriptorGenesisHash: (base + 1).toString(16).padStart(2, '0').repeat(32),
    descriptorHeadHash: (base + 1).toString(16).padStart(2, '0').repeat(32),
    descriptorSequence: 0,
    familyId: 2,
    operationId: 2,
    endpointId: 1,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1
  }
}

const dalKey = await genKeyPair()
const sydKey = await genKeyPair()
const relayTuple = validateCurrentRelayTupleV1({
  schema: PEERIT_THREE_POST_RELAY_TUPLE_SCHEMA_V1,
  relays: [tupleRow('dal-1', dalKey.pubHex, 0x10), tupleRow('syd-1', sydKey.pubHex, 0x20)]
})
const remoteCells = new Map(relayTuple.relays.map(row => [row.relayId, new Map()]))
const calls = []
const ambiguousRecordId = plan.records[0].recordId
let ambiguousOnce = true

function vault () {
  return createPeeritSeedPublisherVaultV1({ filePath: vaultPath, passphrase: passphrase(), now: () => clock++ })
}

function rawAdapter (adapterOptions, row) {
  const targetId = `cell-v1:${row.relayId}:three-post`
  const writeContext = adapterOptions.endpointContext
  const readContext = adapterOptions.readEndpointContext

  async function prepare (publication) {
    const nonce = fill(row.relayId === 'dal-1' ? 0x31 : 0x41)
    nonce[0] ^= publication.innerBytes.at(-1)
    const requestCommitment = new Uint8Array(createHashBytes(publication.innerBytes, row.relayId))
    const prepared = {
      request: { version: 1, clientNonce: nonce },
      requestBytes: new Uint8Array([0x50, ...requestCommitment.slice(0, 8)]),
      requestCommitment,
      wire: { familyId: 2, operationId: 1, expectedResultBodyBytes: 1 },
      readCap: {
        version: 1,
        relayPublicKey: new Uint8Array(Buffer.from(row.continuityRootRelayPublicKey, 'hex')),
        storageSlot: createHashBytes(publication.logicalHash, `${row.relayId}:slot`),
        cellKey: createHashBytes(publication.encodingCommitment, `${row.relayId}:key`),
        sizeClass: publication.sizeClass,
        expectedCellBlobHash: createHashBytes(publication.innerBytes, `${row.relayId}:blob`)
      },
      writeCap: { createPrivateKey: fill(row.relayId === 'dal-1' ? 0x51 : 0x61) }
    }
    await adapterOptions.persistPreparedReplica({
      ...publication,
      targetId,
      targetContext: writeContext,
      readTargetContext: readContext,
      prepared
    })
    return prepared
  }

  async function verifiedReadback (publication, prepared, phase) {
    calls.push({ operation: 'GET', relayId: row.relayId, recordId: publication.intentId, phase })
    const innerBytes = remoteCells.get(row.relayId).get(`${targetId}\n${publication.intentId}`)
    if (!innerBytes) throw Object.assign(new Error('Cell unavailable'), { code: 'HIVERELAY_CELL_NOT_FOUND' })
    assert.deepEqual(innerBytes, publication.innerBytes)
    const requestCommitment = createHashBytes(publication.innerBytes, `${row.relayId}:get:${phase}`)
    const persisted = await adapterOptions.persistVerifiedReadback({
      ...publication,
      targetId,
      targetContext: writeContext,
      readTargetContext: readContext,
      prepared,
      readCapability: prepared.readCap,
      readbackRequestBytes: new Uint8Array([0x47, 0x45, 0x54]),
      readbackRequestCommitment: requestCommitment,
      readbackResultBytes: new Uint8Array([0x80]),
      readbackInnerBytes: innerBytes
    })
    return { ok: true, acknowledged: true, readbackVerified: true, evidenceRef: persisted.evidenceRef }
  }

  return Object.freeze({
    compatible: true,
    prepare,
    async send (delivery) {
      const persisted = await adapterOptions.loadPersistedReplica(delivery.intentId, targetId)
      assert.equal(persisted.payload.stage, 1)
      calls.push({ operation: 'PUT', relayId: row.relayId, recordId: delivery.intentId })
      remoteCells.get(row.relayId).set(`${targetId}\n${delivery.intentId}`, new Uint8Array(delivery.innerBytes))
      if (ambiguousOnce && delivery.intentId === ambiguousRecordId && row.relayId === 'dal-1') {
        ambiguousOnce = false
        throw Object.assign(new Error('simulated response loss after commit'), { code: 'TRANSPORT_FAILURE' })
      }
      await adapterOptions.persistVerifiedResult({
        ...delivery,
        targetId,
        targetContext: writeContext,
        readTargetContext: readContext,
        prepared: delivery.prepared,
        resultBytes: new Uint8Array([0x70]),
        readCapability: delivery.prepared.readCap
      })
      return verifiedReadback(delivery, delivery.prepared, 'send')
    },
    async reconcile (publication) {
      const persisted = await adapterOptions.loadPersistedReplica(publication.intentId, targetId)
      assert.equal(persisted.payload.stage === 1 || persisted.payload.stage === 2, true)
      return verifiedReadback(publication, persisted.payload.prepared, 'reconcile')
    },
    async readCellCapability (request) {
      calls.push({ operation: 'GET', relayId: row.relayId, recordId: request.recordId, phase: 'cold' })
      const innerBytes = remoteCells.get(row.relayId).get(`${request.targetId}\n${request.recordId}`)
      if (!innerBytes) throw Object.assign(new Error('Cell unavailable'), { code: 'HIVERELAY_CELL_NOT_FOUND' })
      return { innerBytes, evidenceRef: `cold:${row.relayId}:${request.recordId}` }
    }
  })
}

function createHashBytes (value, suffix = '') {
  // Keep this synchronous fixture helper independent of application hashes.
  const input = Buffer.concat([Buffer.from(value), Buffer.from(String(suffix))])
  return new Uint8Array((awaitableHash(input)))
}

function awaitableHash (input) {
  // node:crypto is deliberately loaded lazily so fixture material never enters
  // application code paths.
  return Buffer.from(sha256Hex(input), 'hex')
}

async function qualify (activeVault) {
  const bridge = createThreePostVaultBridgeV1({ vault: activeVault, relayTuple, now: () => clock++ })
  const byRoot = new Map(relayTuple.relays.map(row => [row.continuityRootRelayPublicKey, row]))
  const adapters = await qualifySeedRelayFixtures(relayTuple.relays.map(row => ({
    ...row,
    minimumDescriptorSequence: row.descriptorSequence
  })), async () => { throw new Error('fixture raw cold read should be supplied by adapter') }, {
    persistPreparedReplica: bridge.persistPreparedReplica,
    persistVerifiedResult: bridge.persistVerifiedResult,
    persistVerifiedReadback: bridge.persistVerifiedReadback,
    loadPersistedReplica: bridge.loadPersistedReplica,
    createRelayAdapter (adapterOptions) {
      const root = hex(adapterOptions.relayPublicKey)
      return rawAdapter(adapterOptions, byRoot.get(root))
    }
  })
  const entries = adapters.map(adapter => {
    const context = adapter && adapter.id
    const row = relayTuple.relays.find(candidate => adapter.id.includes(candidate.continuityRootRelayPublicKey))
    assert.ok(row, `qualified adapter ${context} maps to one relay tuple`)
    return { relayId: row.relayId, adapter }
  })
  assert.equal(bindCurrentRelayTupleV1(entries).tupleSha256, relayTuple.tupleSha256)
  return entries
}

let active = vault()
let adapters = await qualify(active)
await assert.rejects(
  publishThreePostPlanV1({ vault: active, plan, relays: adapters }),
  /simulated response loss after commit/
)
active.close()

// New process-equivalent publisher instance: recover exact randomized authored
// bytes and exact prepared Cell requests from disk, then reconcile the one
// ambiguous send by GET. No second PUT may target that record/relay.
active = vault()
const recoveredPlan = await recoverThreePostPlanV1(active, {
  expectedManifestSha256: manifestSha256,
  expectedCids: scopePosts.map(row => row.cid)
})
assert.deepEqual(recoveredPlan.records.map(row => row.recordId).sort(), plan.records.map(row => row.recordId).sort())
adapters = await qualify(active)
const result = await publishThreePostPlanV1({ vault: active, plan: recoveredPlan, relays: adapters })
assert.equal(result.receipts.complete, true)
assert.equal(result.recoveryGets, 1)
assert.equal(calls.filter(call => call.operation === 'PUT').length, 8)
assert.equal(calls.filter(call => call.operation === 'PUT' && call.recordId === ambiguousRecordId && call.relayId === 'dal-1').length, 1)
assert.equal(calls.some(call => call.operation === 'GET' && call.phase === 'reconcile' && call.recordId === ambiguousRecordId), true)

const authority = await genKeyPair()
const signed = await createSignedThreePostBootstrapV1({
  vault: active,
  plan: recoveredPlan,
  relayTuple: result.relayTuple,
  authoritySeedHex: authority.seedHex,
  authorityPublicKey: authority.pubHex,
  releaseSequence: 13,
  issuedAt: 10_000,
  expiresAt: 20_000
})
assert.equal(signed.verified.payload.records.length, 4)
assert.equal(signed.relayTupleSha256, relayTuple.tupleSha256)

const cells = Object.fromEntries(relayTuple.relays.map(row => [
  row.relayId,
  Object.fromEntries([...remoteCells.get(row.relayId)].map(([targetId, value]) => [targetId, Buffer.from(value).toString('base64')]))
]))
const childFixturePath = path.join(directory, 'fresh-process.json')
await fs.writeFile(childFixturePath, JSON.stringify({
  artifactBase64: Buffer.from(signed.artifactBytes).toString('base64'),
  relays: relayTuple.relays.map(row => ({ ...row, minimumDescriptorSequence: row.descriptorSequence })),
  cells,
  records: signed.artifact.payload.records,
  expectedCids: scopePosts.map(row => row.cid),
  now: 15_000,
  verification: {
    authorityPublicKey: authority.pubHex,
    releaseSequence: 13,
    expectedArtifactHash: signed.artifactHash,
    previousBootstrapHash: null
  }
}), { mode: 0o600 })
const helper = fileURLToPath(new URL('./fixtures/peerit-three-post-cold-process.mjs', import.meta.url))
const child = spawnSync(process.execPath, [helper, childFixturePath], {
  cwd: fileURLToPath(new URL('..', import.meta.url)),
  encoding: 'utf8',
  timeout: 30_000
})
assert.equal(child.status, 0, child.stderr || child.stdout)
const cold = JSON.parse(child.stdout)
assert.equal(cold.ok, true)
assert.equal(cold.networkPuts, 0)
assert.deepEqual(cold.expectedCids, scopePosts.map(row => row.cid).sort())

// A rollback release is a distinct discovery source because sourceId includes
// releaseSequence. Re-sign exactly the same completed records and capabilities
// as a sequence-zero release-14 bootstrap, with no adapter and therefore no
// possible network operation or PUT.
const putsBeforeBootstrapOnly = calls.filter(call => call.operation === 'PUT').length
const manifestPath = path.join(directory, 'manifest.json')
const relayTuplePath = path.join(directory, 'relay-tuple.json')
const passphrasePath = path.join(directory, 'vault-passphrase')
const authoritySeedPath = path.join(directory, 'bootstrap-authority-seed')
const rollbackReceiptsPath = path.join(directory, 'seq14-receipts.json')
const rollbackBootstrapPath = path.join(directory, 'seq14-bootstrap.json')
await fs.writeFile(manifestPath, manifestBytes, { mode: 0o600 })
await fs.writeFile(relayTuplePath, JSON.stringify(relayTuple), { mode: 0o600 })
await fs.writeFile(passphrasePath, passphraseText, { mode: 0o600 })
await fs.writeFile(authoritySeedPath, authority.seedHex, { mode: 0o600 })
const passphraseHandle = await fs.open(passphrasePath, 'r')
const authorityHandle = await fs.open(authoritySeedPath, 'r')
const priorPassphraseFd = process.env.PEERIT_SEED_VAULT_PASSPHRASE_FD
const priorAuthorityFd = process.env.PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD
let rollback
try {
  process.env.PEERIT_SEED_VAULT_PASSPHRASE_FD = String(passphraseHandle.fd)
  process.env.PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD = String(authorityHandle.fd)
  rollback = await runThreePostBootstrapOnlyCliV1([
    '--bootstrap-only',
    '--manifest', manifestPath,
    '--relay-tuple', relayTuplePath,
    '--vault', vaultPath,
    '--receipts', rollbackReceiptsPath,
    '--bootstrap', rollbackBootstrapPath,
    '--release-sequence', '14',
    '--issued-at', '12000',
    '--expires-at', '22000'
  ], { expectedCids: scopePosts.map(row => row.cid) })
} finally {
  if (priorPassphraseFd == null) delete process.env.PEERIT_SEED_VAULT_PASSPHRASE_FD
  else process.env.PEERIT_SEED_VAULT_PASSPHRASE_FD = priorPassphraseFd
  if (priorAuthorityFd == null) delete process.env.PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD
  else process.env.PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD = priorAuthorityFd
  await passphraseHandle.close()
  await authorityHandle.close()
}
assert.equal(rollback.physicalPutsThisRun, 0)
assert.equal(rollback.networkGets, 0)
assert.equal(rollback.releaseSequence, 14)
assert.equal(rollback.bootstrapSequence, 0)
assert.equal(rollback.previousBootstrapHash, null)
assert.equal(calls.filter(call => call.operation === 'PUT').length, putsBeforeBootstrapOnly)
const rollbackArtifactBytes = await fs.readFile(rollbackBootstrapPath)
const rollbackVerified = await verifyPeeritSeedBootstrapV1(rollbackArtifactBytes, {
  authorityPublicKey: authority.pubHex,
  releaseSequence: 14,
  expectedArtifactHash: rollback.bootstrapSha256,
  previousBootstrapHash: null,
  now: 15_000
})
assert.equal(rollbackVerified.payload.bootstrapSequence, 0)
assert.deepEqual(rollbackVerified.payload.records, signed.verified.payload.records)
assert.deepEqual(rollbackVerified.payload.relays, signed.verified.payload.relays)
assert.notEqual(hex(rollbackVerified.sourceId), hex(signed.verified.sourceId))

const encrypted = await fs.readFile(vaultPath, 'utf8')
assert.doesNotMatch(encrypted, new RegExp(Buffer.from(plan.records[0].publication.innerBytes).toString('base64')))
assert.equal((await fs.stat(vaultPath)).mode & 0o777, 0o600)
active.close()
await fs.rm(directory, { recursive: true, force: true })

console.log('peerit three-post publisher: durable prepare, GET-only ambiguity, signed bootstrap, fresh-process cold read ok')
