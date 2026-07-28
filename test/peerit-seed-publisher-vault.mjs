import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { TextEncoder } from 'node:util'
import {
  PEERIT_SEED_RECEIPT_MANIFEST_SCHEMA_V1,
  createPeeritSeedPublisherVaultV1
} from '../scripts/lib/seed-publisher-vault.mjs'

const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'peerit-seed-publisher-vault-'))
const filePath = path.join(directory, 'private', 'publisher-state.enc')
const legacyFilePath = path.join(directory, 'legacy', 'publisher-state.enc')
const passphrase = new TextEncoder().encode('fixture passphrase owned by the test')
const now = 100

const legacyAmbiguousVault = '{"schema":"peerit-seed-publisher-vault-v1","version":1,"kdf":"scrypt","N":32768,"r":8,"p":1,"salt":"00112233445566778899aabbccddeeff","nonce":"00112233445566778899aabb","ciphertext":"ed7c02571dc3a18ab4221ef9a359f2d8401c984c63ecb6991ed9f0984fbf7ab55442cf99872a0241e018a57d14092115dcdbd2cff69bc8d03fe9cef4143dc930dc8807d84ac54d01af355b51e82a5d7a06505b176f94720874b8f9a04766a084603f72d9956528dc334e3597e80012de9dc20caf72519e3c56dea4ed8f0f6972c77d9938ac3f4e66ec86c8fdcc7b30355fa23de6d690789db7867e9a5cae01960486d5ac7d376c48efdd0725a98b6d42f5e49c9a7eb3aef870a09422fbff0f5526318f6e91bf762e7ac6e9b8e0e09f02f2b3c9355d33bc480992c143146ba2e52d3c60eed93515039474e54ab5ab1de01f928a2e39f1bf10dc44b87c959818b4b5bf78312a86fdf5df7ca408b39a1eabb540f6efe559dbd345915a1850af0d9dc12d9f5033d934d82552939ecd66cb101244cdca868e1910ee0cf32cc94cfbda4f884f0927ece4258fbd5688dbb2680728b22eba61464926eddb2241bd56eed5eef657ab8244ce9e5f5d281fd0f5007a54ffa8ece1fba4260e83291b1e6f3f3109d46b3f40910c729ac21e1c417f48a7b02f595b968e04ca379cd75b2f98ab319fa75bb0a493765c283cd60c28080b5dc19ced03601486e10efa428d57a160b372bd1efe8b9494932eeac2d3c886c2e687eed9866fa96ef9c836d2c0ef4010f9904b9cba432c5080bc7137407e7f0069b4a6ad4a3dbfddd6e079086244a545002f2e94f8e4d7270077600dd84e4683319d4d9fc2402ef0122ac6ed6d1a37057afb68b6cff47838de69bf94ec8b2b0bd744c687f0c0805e7305e5029c797c4f305c25c2a84c2ece265c3b47e1a2593a2fe86254fed34fdeccec5933","tag":"363605a63710ba22f5f67291eeb7b187"}\n'

function capability (prefix) {
  return {
    version: 1,
    opaqueFixtureSecret: `${prefix}_SECRET_SENTINEL`,
    bytes: new Uint8Array(32).fill(prefix.charCodeAt(0))
  }
}

function preparedAttempt (recordId, relayId, attemptId, fill) {
  return {
    recordId,
    relayId,
    attemptId,
    preparedAt: now,
    requestBytes: new Uint8Array([fill, fill + 1, fill + 2]),
    requestCommitment: new Uint8Array(32).fill(fill + 3),
    clientNonce: new Uint8Array(32).fill(fill + 4),
    targetContext: {
      relayId,
      descriptorHash: new Uint8Array(32).fill(fill + 5),
      endpointId: 1,
      operationId: 1
    },
    readerCapability: capability(`READER_${recordId}_${relayId}_${attemptId}`),
    managementCapability: capability(`MANAGER_${recordId}_${relayId}_${attemptId}`)
  }
}

function verifiedReplica (recordId, relayId, attemptId, verifiedAt) {
  return {
    recordId,
    relayId,
    attemptId,
    verifiedAt,
    evidenceRef: `fixture:${recordId}:${relayId}`,
    readbackHash: `${relayId}-readback-hash`
  }
}

function vault () {
  return createPeeritSeedPublisherVaultV1({ filePath, passphrase, now: () => now })
}

// A predecessor vault can contain a nonzero physical PUT counter without the
// exact prepared-attempt material introduced by this repair. It must never be
// interpreted as a clean relay slot after upgrade.
await fs.mkdir(path.dirname(legacyFilePath), { recursive: true })
await fs.writeFile(legacyFilePath, legacyAmbiguousVault, { mode: 0o600 })
const legacy = createPeeritSeedPublisherVaultV1({
  filePath: legacyFilePath,
  passphrase,
  now: () => now
})
assert.deepEqual(await legacy.resumePlan(['legacy']), [{
  recordId: 'legacy',
  eligible: true,
  eligibleAt: 0,
  actions: [
    { relayId: 'dal', action: 'legacy-ambiguous-manual-recovery' },
    { relayId: 'syd', action: 'prepare-put' }
  ]
}])
await assert.rejects(
  legacy.preparePutAttempt(preparedAttempt('legacy', 'dal', 'legacy-forbidden-a2', 0x08)),
  error => error && error.code === 'PEERIT_SEED_VAULT_LEGACY_AMBIGUOUS'
)
assert.equal((await legacy.sanitizedReceiptManifest()).records[0].replicas[0].attemptState,
  'legacy-ambiguous-no-recovery-material')
legacy.close()

let active = vault()
await active.bindPlan({
  manifestSha256: 'ab'.repeat(32),
  records: [
    { recordId: 'parent', plannedRelays: ['syd', 'dal'] },
    {
      recordId: 'reply',
      parentRecordId: 'parent',
      minimumParentAgeMs: 1_000,
      plannedRelays: ['dal', 'syd']
    }
  ]
})

assert.deepEqual(await active.resumePlan(['reply'], 1_000), [{
  recordId: 'reply',
  eligible: false,
  reason: 'parent-incomplete',
  actions: []
}])
await assert.rejects(
  active.assertComplete(['parent', 'reply']),
  error => error && error.code === 'PEERIT_SEED_PUBLISH_PARTIAL' && error.exitCode === 2
)

// Crash boundary 1: exact request/capability material is durable before send.
const parentDal = preparedAttempt('parent', 'dal', 'parent-dal-a1', 0x10)
await active.preparePutAttempt(parentDal)
active.close()
active = vault()
let resumed = (await active.resumePlan(['parent'], 1_000))[0]
assert.deepEqual(resumed.actions, [
  { relayId: 'dal', action: 'send-prepared-put' },
  { relayId: 'syd', action: 'prepare-put' }
])
const recoveredPrepared = await active.loadPreparedAttempt('parent', 'dal')
assert.equal(recoveredPrepared.stage, 'prepared-not-sent')
assert.deepEqual(recoveredPrepared.requestBytes, parentDal.requestBytes)
assert.deepEqual(recoveredPrepared.requestCommitment, parentDal.requestCommitment)
assert.deepEqual(recoveredPrepared.clientNonce, parentDal.clientNonce)
assert.equal(recoveredPrepared.targetContext.relayId, parentDal.targetContext.relayId)
assert.deepEqual(recoveredPrepared.targetContext.descriptorHash, parentDal.targetContext.descriptorHash)
assert.equal(recoveredPrepared.targetContext.endpointId, parentDal.targetContext.endpointId)
assert.equal(recoveredPrepared.targetContext.operationId, parentDal.targetContext.operationId)
assert.deepEqual(recoveredPrepared.readerCapability.bytes, parentDal.readerCapability.bytes)
assert.deepEqual(recoveredPrepared.managementCapability.bytes, parentDal.managementCapability.bytes)

// Crash boundary 2: once the send boundary may have been crossed, restart can
// only perform an authenticated GET reconciliation and cannot mint a new PUT.
await active.recordPutSendStarted('parent', 'dal', parentDal.attemptId, 101)
active.close()
active = vault()
resumed = (await active.resumePlan(['parent'], 1_000))[0]
assert.deepEqual(resumed.actions, [
  { relayId: 'dal', action: 'reconcile-get-only' },
  { relayId: 'syd', action: 'prepare-put' }
])
await assert.rejects(
  active.preparePutAttempt(preparedAttempt('parent', 'dal', 'parent-dal-forbidden', 0x20)),
  error => error && error.code === 'PEERIT_SEED_VAULT_ATTEMPT_PENDING'
)

// Crash boundary 3: a verified PUT response that was not yet receipt-committed
// is still GET-only on restart, using the exact pre-send capability material.
const parentSyd = preparedAttempt('parent', 'syd', 'parent-syd-a1', 0x30)
await active.preparePutAttempt(parentSyd)
await active.recordPutSendStarted('parent', 'syd', parentSyd.attemptId, 102)
await active.recordPutResponseVerified({
  recordId: 'parent',
  relayId: 'syd',
  attemptId: parentSyd.attemptId,
  verifiedAt: 103,
  evidenceRef: 'fixture:parent:syd:put-response',
  resultHash: 'syd-put-result-hash'
})
active.close()
active = vault()
resumed = (await active.resumePlan(['parent'], 1_000))[0]
assert.deepEqual(resumed.actions, [
  { relayId: 'dal', action: 'reconcile-get-only' },
  { relayId: 'syd', action: 'reconcile-get-only' }
])
const recoveredResponse = await active.loadPreparedAttempt('parent', 'syd')
assert.equal(recoveredResponse.stage, 'response-verified')
assert.equal(recoveredResponse.responseEvidenceRef, 'fixture:parent:syd:put-response')
assert.equal(recoveredResponse.resultHash, 'syd-put-result-hash')
assert.deepEqual(recoveredResponse.requestCommitment, parentSyd.requestCommitment)
assert.deepEqual(recoveredResponse.readerCapability.bytes, parentSyd.readerCapability.bytes)
assert.deepEqual(recoveredResponse.managementCapability.bytes, parentSyd.managementCapability.bytes)

await active.recordVerifiedReplica(verifiedReplica('parent', 'dal', parentDal.attemptId, 100))
const parentComplete = await active.recordVerifiedReplica(
  verifiedReplica('parent', 'syd', parentSyd.attemptId, 200)
)
assert.equal(parentComplete.complete, true)
assert.equal(parentComplete.completedAt, 200)
assert.equal((await active.resumePlan(['reply'], 1_199))[0].reason, 'parent-age-gate')
const eligibleReply = (await active.resumePlan(['reply'], 1_200))[0]
assert.equal(eligibleReply.eligible, true)
assert.deepEqual(eligibleReply.actions, [
  { relayId: 'dal', action: 'prepare-put' },
  { relayId: 'syd', action: 'prepare-put' }
])

active.close()
active = vault()
const resumedParent = (await active.resumePlan(['parent'], 1_200))[0]
assert.deepEqual(resumedParent.actions, [
  { relayId: 'dal', action: 'get-only-revalidate' },
  { relayId: 'syd', action: 'get-only-revalidate' }
])
const recovery = await active.recordRecoveryGet('parent', 'dal', 'fixture:restart:get-only', 1_201)
assert.equal(recovery.putAttempts, 1)
assert.equal(recovery.recoveryGets, 1)

let receipts = await active.sanitizedReceiptManifest()
assert.equal(receipts.schema, PEERIT_SEED_RECEIPT_MANIFEST_SCHEMA_V1)
assert.equal(receipts.complete, false)
assert.equal(receipts.records[0].replicas[0].putAttempts, 1)
assert.equal(receipts.records[0].replicas[0].recoveryGets, 1)
assert.equal(receipts.records[0].replicas[0].attemptState, 'readback-verified')

// No authenticated non-processing proof contract exists yet. An ambiguous
// attempt therefore remains fail-closed forever: a caller-supplied evidence
// label cannot authorize a physical replacement PUT.
const replyDalLost = preparedAttempt('reply', 'dal', 'reply-dal-lost', 0x40)
await active.preparePutAttempt(replyDalLost)
await active.recordPutSendStarted('reply', 'dal', replyDalLost.attemptId, 1_200)
assert.equal((await active.resumePlan(['reply'], 1_202))[0].actions[0].action, 'reconcile-get-only')
await assert.rejects(
  active.preparePutAttempt(preparedAttempt('reply', 'dal', 'reply-dal-forbidden-a2', 0x50)),
  error => error && error.code === 'PEERIT_SEED_VAULT_ATTEMPT_PENDING'
)

// Complete the independent happy-path record on a fresh plan row so receipt
// and capability-custody assertions do not weaken the ambiguous-attempt rule.
await active.bindPlan({
  manifestSha256: 'ab'.repeat(32),
  records: [{ recordId: 'complete', plannedRelays: ['dal', 'syd'] }]
})
const replyDal = preparedAttempt('complete', 'dal', 'complete-dal-a1', 0x50)
const replySyd = preparedAttempt('reply', 'syd', 'reply-syd-a1', 0x60)
await active.preparePutAttempt(replyDal)
await active.preparePutAttempt(replySyd)
await active.recordPutSendStarted('complete', 'dal', replyDal.attemptId, 1_202)
await active.recordPutSendStarted('reply', 'syd', replySyd.attemptId, 1_202)
await active.recordVerifiedReplica(verifiedReplica('complete', 'dal', replyDal.attemptId, 1_202))
await active.recordVerifiedReplica(verifiedReplica('reply', 'syd', replySyd.attemptId, 1_203))
const completeSyd = preparedAttempt('complete', 'syd', 'complete-syd-a1', 0x70)
await active.preparePutAttempt(completeSyd)
await active.recordPutSendStarted('complete', 'syd', completeSyd.attemptId, 1_203)
await active.recordVerifiedReplica(verifiedReplica('complete', 'syd', completeSyd.attemptId, 1_204))
assert.equal(await active.assertComplete(['parent', 'complete']), true)
receipts = await active.sanitizedReceiptManifest()
assert.equal(receipts.complete, false, 'the deliberately ambiguous reply remains incomplete')
const publicJson = JSON.stringify(receipts)
assert.doesNotMatch(publicJson, /READER_.*SECRET_SENTINEL/)
assert.doesNotMatch(publicJson, /MANAGER_.*SECRET_SENTINEL/)

const encrypted = await fs.readFile(filePath, 'utf8')
assert.doesNotMatch(encrypted, /READER_.*SECRET_SENTINEL/)
assert.doesNotMatch(encrypted, /MANAGER_.*SECRET_SENTINEL/)
assert.equal((await fs.stat(filePath)).mode & 0o777, 0o600)

const wrong = createPeeritSeedPublisherVaultV1({
  filePath,
  passphrase: new TextEncoder().encode('a different wrong fixture password')
})
await assert.rejects(
  wrong.sanitizedReceiptManifest(),
  error => error && error.code === 'PEERIT_SEED_VAULT_AUTHENTICATION_FAILED'
)
wrong.close()
active.close()
await fs.rm(directory, { recursive: true, force: true })

console.log('peerit restart-safe encrypted seed publisher vault: ok')
