import assert from 'node:assert/strict'
import {
  JOURNAL_STORES,
  PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  hashPeeritInnerCellEncodingCommitmentV1,
  hashPeeritInnerLogicalHashV1,
  hashPeeritInnerOperationIntentIdV1
} from '../js/substrate/peerit-operation-authority-v1.js'
import {
  peeritAuthorBindCellSizeClassForInnerLengthV1
} from '../js/substrate/author-bind-inner-envelope-policy.mjs'

const toHex = value => Buffer.from(value).toString('hex')

function authoredIntent () {
  const payload = new TextEncoder().encode(JSON.stringify({
    operations: [{ data: { body: 'durable Seq29 publication' }, type: 'post' }],
    version: 1
  }))
  const innerBytes = new Uint8Array(7 + payload.byteLength)
  innerBytes[0] = (PEERIT_INNER_OPERATION_BATCH_V1_CODEC >>> 8) & 0xff
  innerBytes[1] = PEERIT_INNER_OPERATION_BATCH_V1_CODEC & 0xff
  innerBytes[2] = 1
  innerBytes[3] = (payload.byteLength >>> 24) & 0xff
  innerBytes[4] = (payload.byteLength >>> 16) & 0xff
  innerBytes[5] = (payload.byteLength >>> 8) & 0xff
  innerBytes[6] = payload.byteLength & 0xff
  innerBytes.set(payload, 7)
  const sizeClass = peeritAuthorBindCellSizeClassForInnerLengthV1(
    BigInt(innerBytes.byteLength))
  const logicalHash = hashPeeritInnerLogicalHashV1(
    PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)
  const encodingCommitment = hashPeeritInnerCellEncodingCommitmentV1(
    PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes, logicalHash, sizeClass)
  return {
    wireFormat: PEERIT_INNER_OPERATION_BATCH_WIRE_FORMAT_V1,
    innerCodec: PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
    innerBytes,
    innerLength: innerBytes.byteLength,
    logicalHash,
    encodingCommitment,
    sizeClass,
    intentId: toHex(hashPeeritInnerOperationIntentIdV1(
      PEERIT_INNER_OPERATION_BATCH_V1_CODEC, innerBytes)),
    logicalId: toHex(logicalHash),
    records: [{ key: 'post!seq29-durable', value: { body: 'durable Seq29 publication' } }],
    createdAt: 450,
    discoveryState: 'queued'
  }
}

const authorityPublicKey = 'a1'.repeat(32)
const firstWrapperHash = 'b1'.repeat(32)
const secondWrapperHash = 'b2'.repeat(32)
const relayIds = ['dal', 'syd']
const shared = createMemoryJournalState()
const firstTab = createMemoryPeeritJournal({ shared, clock: () => 100 })
const secondTab = createMemoryPeeritJournal({ shared, clock: () => 101 })
await Promise.all([firstTab.ready(), secondTab.ready()])

const firstBootstrap = {
  releaseSequence: 29,
  authorityPublicKey,
  completeSignedWrapperHash: firstWrapperHash,
  bootstrapSequence: 0n,
  relayIds
}
const accepted = await firstTab.acceptSeq29PublicInboxBootstrap(firstBootstrap)
assert.equal(accepted.duplicate, false)
assert.deepEqual(accepted.appendFloors, { dal: 0n, syd: 0n })
assert.deepEqual(await secondTab.getSeq29PublicInboxBootstrapFloor(authorityPublicKey), {
  schema: 'PeeritLimitedPublicInboxBootstrapFloorV1',
  version: 1,
  highestAcceptedBootstrapSequence: '0',
  completeSignedWrapperHash: firstWrapperHash
})
assert.deepEqual(await secondTab.getSeq29PublicInboxAppendFloors(firstBootstrap), {
  dal: 0n,
  syd: 0n
})

const record = {
  key: `profile!${'c1'.repeat(32)}`,
  value: {
    id: 'c1'.repeat(32),
    _k: 'c1'.repeat(32),
    _sig: 'd1'.repeat(64),
    name: 'remote only'
  }
}
const firstPoll = {
  ...firstBootstrap,
  relayPolls: [
    {
      relayId: 'dal',
      previousAppendRevision: 0n,
      newAppendRevision: 3n,
      observationHash: '11'.repeat(32)
    },
    {
      relayId: 'syd',
      previousAppendRevision: 0n,
      newAppendRevision: 7n,
      observationHash: '22'.repeat(32)
    }
  ],
  records: [record],
  observedAt: 200
}
const committed = await firstTab.commitSeq29PublicInboxPoll(firstPoll)
assert.equal(committed.duplicate, false)
assert.deepEqual(committed.appendFloors, { dal: 3n, syd: 7n })
assert.deepEqual(await secondTab.getView(record.key), record.value)
assert.equal(shared.stores.get(JOURNAL_STORES.INTENTS).size, 0)
assert.equal(shared.stores.get(JOURNAL_STORES.TARGETS).size, 0)
assert.equal(shared.stores.get(JOURNAL_STORES.DEDUPE).size, 0)

const duplicate = await secondTab.commitSeq29PublicInboxPoll(firstPoll)
assert.equal(duplicate.duplicate, true,
  'a losing tab may reproduce the exact already-committed transition')
await assert.rejects(
  secondTab.commitSeq29PublicInboxPoll({
    ...firstPoll,
    relayPolls: firstPoll.relayPolls.map((poll, index) => index === 0
      ? { ...poll, observationHash: '33'.repeat(32) }
      : poll)
  }),
  error => error.code === 'PEERIT_JOURNAL_SEQ29_APPEND_FORK',
  'a losing tab cannot replace the authenticated content of the same append transition')
await assert.rejects(
  secondTab.commitSeq29PublicInboxPoll({
    ...firstPoll,
    relayPolls: firstPoll.relayPolls.map((poll, index) => index === 0
      ? { ...poll, newAppendRevision: 4n }
      : poll)
  }),
  error => error.code === 'PEERIT_JOURNAL_SEQ29_APPEND_FLOOR_STALE',
  'a stale tab must re-poll instead of skipping forward from an old floor')

const nextPoll = {
  ...firstBootstrap,
  relayPolls: [
    {
      relayId: 'dal',
      previousAppendRevision: 3n,
      newAppendRevision: 4n,
      observationHash: '44'.repeat(32)
    },
    {
      relayId: 'syd',
      previousAppendRevision: 7n,
      newAppendRevision: 8n,
      observationHash: '55'.repeat(32)
    }
  ],
  records: [{ ...record, key: `profile!${'c2'.repeat(32)}`, value: { ...record.value, id: 'c2'.repeat(32) } }],
  observedAt: 300
}
shared.failNextCommit = new Error('injected all-or-nothing failure')
await assert.rejects(firstTab.commitSeq29PublicInboxPoll(nextPoll), error =>
  error.code === 'PEERIT_JOURNAL_TRANSACTION_FAILED' &&
  /injected all-or-nothing failure/.test(error.cause?.message || ''))
assert.deepEqual(await secondTab.getSeq29PublicInboxAppendFloors(firstBootstrap), {
  dal: 3n,
  syd: 7n
}, 'failed view ingest cannot advance either relay floor')
assert.equal(await secondTab.getView(nextPoll.records[0].key), null,
  'failed floor commit cannot leak a partially ingested remote view row')

await assert.rejects(firstTab.acceptSeq29PublicInboxBootstrap({
  ...firstBootstrap,
  completeSignedWrapperHash: 'ff'.repeat(32)
}), error => error.code === 'PEERIT_JOURNAL_SEQ29_BOOTSTRAP_FORK')

const secondBootstrap = {
  ...firstBootstrap,
  completeSignedWrapperHash: secondWrapperHash,
  bootstrapSequence: 1n
}
await secondTab.acceptSeq29PublicInboxBootstrap(secondBootstrap)
assert.equal([...shared.stores.get(JOURNAL_STORES.META).keys()].filter(key =>
  String(key).startsWith('seq29-public-inbox-state:v1:')).length, 1,
'advancing a signed wrapper atomically retires its exact prior state row')
assert.deepEqual(await firstTab.getSeq29PublicInboxAppendFloors(secondBootstrap), {
  dal: 0n,
  syd: 0n
}, 'a higher signed wrapper gets an exact new two-relay floor state')
await assert.rejects(
  firstTab.getSeq29PublicInboxAppendFloors(firstBootstrap),
  error => error.code === 'PEERIT_JOURNAL_SEQ29_BOOTSTRAP_ROLLBACK')
await assert.rejects(
  firstTab.acceptSeq29PublicInboxBootstrap(firstBootstrap),
  error => error.code === 'PEERIT_JOURNAL_SEQ29_BOOTSTRAP_ROLLBACK')

const racing = revision => ({
  ...secondBootstrap,
  relayPolls: relayIds.map((relayId, index) => ({
    relayId,
    previousAppendRevision: 0n,
    newAppendRevision: 1n,
    observationHash: (index === 0 ? revision : '77').repeat(32)
  })),
  records: [],
  observedAt: 400
})
const race = await Promise.allSettled([
  firstTab.commitSeq29PublicInboxPoll(racing('66')),
  secondTab.commitSeq29PublicInboxPoll(racing('88'))
])
assert.equal(race.filter(result => result.status === 'fulfilled').length, 1)
assert.equal(race.filter(result => result.status === 'rejected' &&
  result.reason.code === 'PEERIT_JOURNAL_SEQ29_APPEND_FORK').length, 1,
'cross-tab CAS accepts one observation and explicitly rejects its same-transition fork')

const authored = authoredIntent()
await firstTab.commitIntent(authored)
const authorPublicKey = '91'.repeat(32)
const publicationScope = { ...secondBootstrap, authorPublicKey }
const preparedRelays = relayIds.map((relayId, index) => ({
  relayId,
  frame: new Uint8Array(4096).fill(0x20 + index),
  request: {
    kind: 'append',
    admission: `admission-${relayId}`,
    clientNonce: `nonce-${relayId}`
  },
  requestBytes: new Uint8Array([0x40 + index, 0x50 + index]),
  requestCommitment: new Uint8Array(32).fill(0x60 + index)
}))
const durableInput = {
  ...publicationScope,
  logicalHash: authored.logicalId,
  intentId: authored.intentId,
  authorSequence: 0n,
  previousAuthorRecordId: null,
  authorRecordId: '92'.repeat(32),
  announcementBytes: new Uint8Array([0x29, 0x01]),
  relays: preparedRelays,
  createdAt: 500
}
const durable = await firstTab.commitSeq29PublicationIntent(durableInput)
assert.equal(durable.duplicate, false)
assert.deepEqual(await secondTab.getSeq29PublicationAuthorHead(publicationScope), {
  nextAuthorSequence: 1n,
  previousAuthorRecordId: durableInput.authorRecordId
}, 'durable exact APPEND intent atomically advances the local AuthorBind head')
assert.equal((await secondTab.commitSeq29PublicationIntent(durableInput)).duplicate, true,
  'byte-identical logical-hash publication commit is idempotent')
await assert.rejects(() => secondTab.commitSeq29PublicationIntent({
  ...durableInput,
  relays: preparedRelays.map((relay, index) => index === 0
    ? { ...relay, requestCommitment: new Uint8Array(32).fill(0xff) }
    : relay)
}), error => error.code === 'PEERIT_JOURNAL_CORRUPT',
'a duplicate logical hash cannot replace either relay request commitment')

const firstClaim = await firstTab.claimSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'dal',
  attemptToken: 'dal-first-send',
  now: 510,
  leaseUntil: 600
})
assert.equal(firstClaim.action, 'sending')
const reloaded = createMemoryPeeritJournal({ shared, clock: () => 700 })
await reloaded.ready()
assert.equal((await reloaded.claimSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'dal',
  attemptToken: 'dal-early-reload',
  now: 550,
  leaseUntil: 650
})).claimed, false, 'reload never duplicates an in-flight APPEND before its lease expires')
const reconcileClaim = await reloaded.claimSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'dal',
  attemptToken: 'dal-reconcile',
  now: 601,
  leaseUntil: 700
})
assert.equal(reconcileClaim.action, 'reconciling',
  'an expired/crashed exact send resumes through authenticated READ reconciliation')
await reloaded.markSeq29PublicationRelayAbsent({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'dal',
  attemptToken: 'dal-reconcile',
  now: 602
})
await reloaded.completeSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'dal',
  attemptToken: 'dal-reconcile',
  now: 603,
  result: { recovered: false, appendRevision: '8' }
})
const partial = await reloaded.getSeq29PublicationIntent({
  ...publicationScope,
  logicalHash: authored.logicalId
})
assert.equal(partial.completedAt, 0)
assert.deepEqual(partial.relays.map(relay => relay.stage), ['succeeded', 'prepared'],
  'one terminal relay cannot consume or complete the dual publication')

const sydSend = await reloaded.claimSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'syd',
  attemptToken: 'syd-send',
  now: 604,
  leaseUntil: 700
})
assert.equal(sydSend.action, 'sending')
await reloaded.failSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'syd',
  attemptToken: 'syd-send',
  now: 605,
  errorCode: 'INJECTED_CRASH_AFTER_TRANSPORT'
})
const finalReload = createMemoryPeeritJournal({ shared, clock: () => 706 })
await finalReload.ready()
const sydReconcile = await finalReload.claimSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'syd',
  attemptToken: 'syd-reconcile',
  now: 606,
  leaseUntil: 706
})
assert.equal(sydReconcile.action, 'reconciling')
const terminal = await finalReload.completeSeq29PublicationRelay({
  ...publicationScope,
  logicalHash: authored.logicalId,
  relayId: 'syd',
  attemptToken: 'syd-reconcile',
  now: 607,
  result: { recovered: true, appendRevision: '9' }
})
assert.equal(terminal.completedAt, 607)
assert.deepEqual(terminal.relays.map(relay => relay.stage), ['succeeded', 'succeeded'])
assert.equal(terminal.relays[1].attempts, 2,
  'ambiguous APPEND recovery reconciles the stored frame instead of blind duplicate success')

console.log('peerit seq29 public INBOX journal: floors, durable exact APPEND intent, and crash/reload reconciliation ok')
