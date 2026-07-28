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
const passphrase = new TextEncoder().encode('fixture passphrase owned by the test')
const now = 100

function capability (prefix) {
  return {
    version: 1,
    opaqueFixtureSecret: `${prefix}_SECRET_SENTINEL`,
    bytes: new Uint8Array(32).fill(prefix.charCodeAt(0))
  }
}

function verifiedReplica (recordId, relayId, verifiedAt) {
  return {
    recordId,
    relayId,
    verifiedAt,
    evidenceRef: `fixture:${recordId}:${relayId}`,
    readbackHash: `${relayId}-readback-hash`,
    readerCapability: capability(`READER_${recordId}_${relayId}`),
    managementCapability: capability(`MANAGER_${recordId}_${relayId}`)
  }
}

const vault = createPeeritSeedPublisherVaultV1({ filePath, passphrase, now: () => now })
await vault.bindPlan({
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

assert.deepEqual(await vault.resumePlan(['reply'], 1_000), [{
  recordId: 'reply',
  eligible: false,
  reason: 'parent-incomplete',
  actions: []
}])
await assert.rejects(
  vault.assertComplete(['parent', 'reply']),
  error => error && error.code === 'PEERIT_SEED_PUBLISH_PARTIAL' && error.exitCode === 2
)

await vault.recordPutAttempt('parent', 'dal')
await vault.recordPutAttempt('parent', 'syd')
await vault.recordVerifiedReplica(verifiedReplica('parent', 'dal', 100))
const parentComplete = await vault.recordVerifiedReplica(verifiedReplica('parent', 'syd', 200))
assert.equal(parentComplete.complete, true)
assert.equal(parentComplete.completedAt, 200)
assert.equal((await vault.resumePlan(['reply'], 1_199))[0].reason, 'parent-age-gate')
const eligibleReply = (await vault.resumePlan(['reply'], 1_200))[0]
assert.equal(eligibleReply.eligible, true)
assert.deepEqual(eligibleReply.actions, [
  { relayId: 'dal', action: 'put' },
  { relayId: 'syd', action: 'put' }
])

vault.close()
const restarted = createPeeritSeedPublisherVaultV1({ filePath, passphrase, now: () => now })
const resumedParent = (await restarted.resumePlan(['parent'], 1_200))[0]
assert.deepEqual(resumedParent.actions, [
  { relayId: 'dal', action: 'get-only-revalidate' },
  { relayId: 'syd', action: 'get-only-revalidate' }
])
const recovery = await restarted.recordRecoveryGet('parent', 'dal', 'fixture:restart:get-only', 1_201)
assert.equal(recovery.putAttempts, 1)
assert.equal(recovery.recoveryGets, 1)

let receipts = await restarted.sanitizedReceiptManifest()
assert.equal(receipts.schema, PEERIT_SEED_RECEIPT_MANIFEST_SCHEMA_V1)
assert.equal(receipts.complete, false)
assert.equal(receipts.records[0].replicas[0].putAttempts, 1)
assert.equal(receipts.records[0].replicas[0].recoveryGets, 1)

await restarted.recordPutAttempt('reply', 'dal')
await restarted.recordPutAttempt('reply', 'syd')
await restarted.recordVerifiedReplica(verifiedReplica('reply', 'dal', 1_200))
await restarted.recordVerifiedReplica(verifiedReplica('reply', 'syd', 1_201))
assert.equal(await restarted.assertComplete(['parent', 'reply']), true)
receipts = await restarted.sanitizedReceiptManifest()
assert.equal(receipts.complete, true)
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
restarted.close()
await fs.rm(directory, { recursive: true, force: true })

console.log('peerit restart-safe encrypted seed publisher vault: ok')
