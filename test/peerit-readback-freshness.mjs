import assert from 'node:assert/strict'
import { canonical } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { memoryStorage } from '../js/sync.js'
import {
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import {
  PEERIT_CELL_READBACK_FRESHNESS_TTL_MS,
  createPeeritSubstrateSync
} from '../js/substrate/peerit-substrate-sync.js'
import { createBlindCellRelay } from '../js/substrate/blind-client-relay.js'
import { publicationUiState } from '../js/substrate/publication-status.js'

const TTL = 100
assert.equal(PEERIT_CELL_READBACK_FRESHNESS_TTL_MS, 86_400_000,
  'production freshness follows the frozen four six-hour lease epochs')
let sequence = 0

function failure (code, options = {}) {
  const error = new Error(code)
  error.code = code
  Object.assign(error, options)
  return error
}

function relayFixture (id, state = {}) {
  Object.assign(state, {
    present: state.present !== false,
    capability: state.capability !== false,
    mode: state.mode || 'ok',
    puts: state.puts || 0,
    gets: state.gets || 0,
    evidenceRevision: state.evidenceRevision || 0
  })
  const live = evidenceRef => Object.freeze({
    ok: true,
    acknowledged: true,
    readbackVerified: true,
    readbackRevalidated: true,
    readbackEvidenceRevision: ++state.evidenceRevision,
    policyDurable: false,
    evidenceRef
  })
  return {
    id,
    compatible: true,
    async deliver () {
      state.puts++
      state.gets++
      state.present = true
      state.capability = true
      return live(`${id}:put-get:${state.puts}:${state.gets}`)
    },
    async revalidateReadback () {
      if (!state.capability) {
        throw failure('PEERIT_SUBSTRATE_READ_CAPABILITY_MISSING', { terminal: true })
      }
      state.gets++
      if (state.mode === 'cached') {
        return Object.freeze({
          ok: true,
          acknowledged: true,
          readbackVerified: true,
          readbackEvidenceRevision: state.evidenceRevision,
          evidenceRef: `${id}:cached-stage-3`
        })
      }
      if (state.mode === 'transient') {
        throw failure('HIVERELAY_READBACK_PENDING', {
          remote: Object.freeze({ code: 6, retryable: 1 })
        })
      }
      if (state.mode === 'remote-terminal') {
        throw failure('HIVERELAY_READBACK_TERMINAL', {
          terminal: true,
          remote: Object.freeze({ code: 6, retryable: 0 })
        })
      }
      if (state.mode === 'not-found' || !state.present) {
        throw failure('HIVERELAY_READBACK_NOT_FOUND', {
          terminal: true,
          definitiveAbsence: true,
          remote: Object.freeze({ code: 13, retryable: 0 })
        })
      }
      return live(`${id}:get:${state.gets}`)
    }
  }
}

function syncFor (shared, relay, clock, suffix, options = {}) {
  return syncForRelays(shared, relay ? [relay] : [], clock, suffix, options)
}

function syncForRelays (shared, relays, clock, suffix, options = {}) {
  return createPeeritSubstrateSync({
    journal: createMemoryPeeritJournal({ shared, clock: () => clock.value }),
    relays,
    autoFlush: false,
    clock: () => clock.value,
    readbackFreshnessTtlMs: TTL,
    retryBaseMs: 10,
    retryMaxMs: 40,
    channelName: `peerit-readback-freshness-${suffix}`,
    attemptOwner: `freshness-${suffix}`,
    ...options
  })
}

function qualifiedRelayFixture (relayByte, storeByte, state = {}) {
  const relayPublicKey = new Uint8Array(32).fill(relayByte)
  const endpointContext = Object.freeze({
    relayPublicKey,
    storeId: new Uint8Array(32).fill(storeByte),
    continuityRoot: new Uint8Array(32).fill(relayByte + 1),
    durabilityContinuityHash: new Uint8Array(32).fill(storeByte + 1),
    descriptorHash: new Uint8Array(32).fill(relayByte + storeByte),
    endpointId: 1,
    familyId: 2,
    operationId: 3,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1,
    durabilityProfileId: 1
  })
  const qualified = createBlindCellRelay({
    blindClient: { createCellReplica () { throw new Error('identity-only adapter must not prepare') } },
    relayPublicKey,
    endpoint: Object.freeze({ verified: true }),
    endpointContext,
    httpClient: { request () { throw new Error('identity-only adapter must not send') } },
    persistPreparedReplica () { throw new Error('identity-only adapter must not persist') },
    persistVerifiedResult () { throw new Error('identity-only adapter must not persist') }
  })
  return Object.freeze({
    ...relayFixture(qualified.id, state),
    qualifiedContext: endpointContext
  })
}

async function signedOperation (identity, label) {
  const me = identity.me()
  const data = { id: me.pubkey, author: me.pubkey, name: label }
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

async function authorOnce (identity, relay, state, clock, label) {
  const shared = createMemoryJournalState()
  const sync = syncFor(shared, relay, clock, `${label}-author`)
  await sync.ready()
  const appended = await sync.append(await signedOperation(identity, `${label}-${++sequence}`))
  await sync.flushPublicationQueue()
  const status = await sync.status()
  assert.equal(status.publication.durability.state, 'recently-retrievable')
  assert.equal(status.publication.durability.readbackVerified, 1)
  assert.equal(state.puts, 1)
  assert.equal(state.gets, 1)
  return { shared, sync, intentId: appended.intentId }
}

await cryptoReady()
const identity = createIdentity({
  forceDev: true,
  lazy: true,
  storage: memoryStorage(),
  session: memoryStorage()
})
await identity.ready()
await identity.ensureActive('readback-freshness-test')

{
  const clock = { value: 1000 }
  const state = {}
  const relay = relayFixture('retained-target', state)
  const authored = await authorOnce(identity, relay, state, clock, 'retained')
  const firstTarget = (await authored.sync.journal.getIntent(authored.intentId)).targets[relay.id]
  assert.equal(firstTarget.lastReadbackVerifiedAt, 1000)
  assert.equal(firstTarget.readbackCurrentInvalidated, false)
  await authored.sync.flushPublicationQueue()
  assert.deepEqual([state.puts, state.gets], [1, 1],
    'same-session fresh evidence takes the no-network fast path')
  authored.sync.destroy()

  const reloaded = syncFor(authored.shared, relayFixture(relay.id, state), clock, 'retained-reload')
  await reloaded.ready()
  let status = await reloaded.status()
  assert.equal(status.publication.relay.state, 'revalidation-pending')
  assert.equal(publicationUiState(status).tone, 'warn')
  assert.equal(status.publication.durability.state, 'remote-evidence-stale',
    'reload never treats a historical timestamp as a current session check')
  assert.equal(status.publication.durability.readbackVerified, 0)
  assert.equal(status.publication.durability.historicalReadbackVerified, 1)
  await reloaded.flushPublicationQueue()
  status = await reloaded.status()
  assert.equal(status.publication.durability.state, 'recently-retrievable')
  assert.deepEqual([state.puts, state.gets], [1, 2],
    'retained-store reload forces exactly one GET and never duplicates the PUT')

  clock.value += TTL
  status = await reloaded.status()
  assert.equal(status.publication.durability.state, 'remote-evidence-stale')
  assert.equal(status.publication.durability.readbackVerified, 0,
    'the named TTL expires at its exact upper bound')
  await reloaded.flushPublicationQueue()
  assert.equal((await reloaded.status()).publication.durability.state, 'recently-retrievable')
  assert.deepEqual([state.puts, state.gets], [1, 3], 'TTL expiry refreshes by GET only')
  reloaded.destroy()
}

{
  const clock = { value: 1500 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('historical-only-target', state), state, clock, 'historical-only')
  authored.sync.destroy()
  const offline = syncFor(authored.shared, null, clock, 'historical-only-reload')
  await offline.ready()
  const status = await offline.status()
  const ui = publicationUiState(status)
  assert.equal(status.publication.relay.state, 'historically-acknowledged')
  assert.equal(status.publication.relay.activeAcknowledgedTargets, 0)
  assert.equal(status.publication.relay.acknowledgedTargets, 1)
  assert.equal(status.publication.durability.state, 'remote-evidence-stale')
  assert.equal(ui.authoringReady, true)
  assert.equal(ui.tone, 'warn')
  assert.match(ui.copy, /historical relay receipt/)
  offline.destroy()
}

{
  const clock = { value: 2000 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('cached-target', state), state, clock, 'cached')
  authored.sync.destroy()
  state.mode = 'cached'
  const reloaded = syncFor(authored.shared, relayFixture('cached-target', state), clock, 'cached-reload')
  await reloaded.ready()
  await reloaded.flushPublicationQueue()
  const status = await reloaded.status()
  assert.equal(status.publication.durability.state, 'repair-needed')
  assert.equal(status.publication.durability.readbackVerified, 0)
  assert.equal(state.puts, 1,
    'a cached stage-3 result without the live-GET marker cannot refresh TTL or cause a PUT')
  reloaded.destroy()
}

{
  const clock = { value: 3000 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('empty-target', state), state, clock, 'empty')
  authored.sync.destroy()
  state.present = false
  state.mode = 'not-found'
  const reloaded = syncFor(authored.shared, relayFixture('empty-target', state), clock, 'empty-reload')
  await reloaded.ready()
  await reloaded.flushPublicationQueue()
  const status = await reloaded.status()
  const target = (await reloaded.journal.getIntent(authored.intentId)).targets['empty-target']
  assert.equal(status.publication.relay.state, 'repair-needed')
  assert.equal(status.publication.durability.state, 'repair-needed')
  assert.equal(status.publication.durability.readbackVerified, 0)
  assert.equal(status.publication.durability.historicalReadbackVerified, 1)
  assert.equal(target.readbackRepairNeeded, true)
  assert.equal(target.state, 'readback-verified', 'historical evidence remains auditable after current loss')
  await reloaded.flushPublicationQueue()
  assert.deepEqual([state.puts, state.gets], [1, 2],
    'authenticated NOT_FOUND marks repair once without a same-target resend or unbounded GET loop')
  reloaded.destroy()
}

{
  const clock = { value: 4000 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('missing-cap-target', state), state, clock, 'missing-cap')
  authored.sync.destroy()
  state.capability = false
  const reloaded = syncFor(authored.shared, relayFixture('missing-cap-target', state), clock, 'missing-cap-reload')
  await reloaded.ready()
  await reloaded.flushPublicationQueue()
  const status = await reloaded.status()
  assert.equal(status.publication.durability.state, 'repair-needed')
  assert.equal(status.publication.durability.readbackVerified, 0)
  assert.deepEqual([state.puts, state.gets], [1, 1],
    'cleared capability fails before GET and never authorizes a replacement PUT')
  reloaded.destroy()
}

{
  const clock = { value: 4500 }
  const oldState = {}
  const original = qualifiedRelayFixture(17, 33, oldState)
  const authored = await authorOnce(identity, original, oldState, clock, 'definitive-cell-loss')
  authored.sync.destroy()

  oldState.present = false
  oldState.mode = 'not-found'
  const lostOldTarget = qualifiedRelayFixture(17, 33, oldState)
  const freshState = { present: false, capability: false }
  const freshDifferentTarget = qualifiedRelayFixture(18, 34, freshState)
  assert.equal(lostOldTarget.id, original.id,
    'the old qualified relay/store tuple reproduces the exact historical target identity')
  assert.notEqual(freshDifferentTarget.id, lostOldTarget.id)
  assert.notDeepEqual(freshDifferentTarget.qualifiedContext.relayPublicKey,
    lostOldTarget.qualifiedContext.relayPublicKey)
  assert.notDeepEqual(freshDifferentTarget.qualifiedContext.storeId,
    lostOldTarget.qualifiedContext.storeId)

  const replacement = syncForRelays(
    authored.shared,
    [lostOldTarget, freshDifferentTarget],
    clock,
    'definitive-cell-loss-replacement'
  )
  await replacement.ready()
  await replacement.flushPublicationQueue()
  const status = await replacement.status()
  const intent = await replacement.journal.getIntent(authored.intentId)
  assert.equal(intent.targets[lostOldTarget.id].readbackRepairNeeded, true)
  assert.equal(intent.targets[freshDifferentTarget.id].readbackVerified, true)
  assert.equal(status.publication.durability.state, 'recently-retrievable')
  assert.equal(status.publication.durability.readbackVerified, 1,
    'only the fresh different target restores current availability')
  assert.deepEqual([oldState.puts, oldState.gets], [1, 2],
    'definitive old-Cell loss performs one final GET and never a same-target PUT')
  assert.deepEqual([freshState.puts, freshState.gets], [1, 1],
    'one fresh qualified relay/store target receives exactly one new replica and capability-bound readback')

  await replacement.flushPublicationQueue()
  assert.deepEqual([oldState.puts, oldState.gets], [1, 2])
  assert.deepEqual([freshState.puts, freshState.gets], [1, 1],
    'recovered availability is idempotent and never recreates either Cell')
  replacement.destroy()
}

{
  const clock = { value: 5000 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('transient-target', state), state, clock, 'transient')
  authored.sync.destroy()
  state.mode = 'transient'
  const reloaded = syncFor(authored.shared, relayFixture('transient-target', state), clock, 'transient-reload')
  await reloaded.ready()
  await reloaded.flushPublicationQueue()
  let status = await reloaded.status()
  let target = (await reloaded.journal.getIntent(authored.intentId)).targets['transient-target']
  assert.equal(status.publication.durability.state, 'remote-evidence-stale')
  assert.equal(status.publication.durability.repairNeeded, 0)
  assert.equal(target.readbackCurrentInvalidated, true)
  assert.equal(target.readbackRevalidationNextAttemptAt, 5010)
  await reloaded.flushPublicationQueue()
  assert.equal(state.gets, 2, 'transient revalidation obeys persisted backoff before another GET')
  clock.value = 5010
  state.mode = 'ok'
  await reloaded.flushPublicationQueue()
  status = await reloaded.status()
  target = (await reloaded.journal.getIntent(authored.intentId)).targets['transient-target']
  assert.equal(status.publication.durability.state, 'recently-retrievable')
  assert.equal(target.readbackCurrentInvalidated, false)
  assert.deepEqual([state.puts, state.gets], [1, 3], 'a due transient retry recovers by one GET')
  reloaded.destroy()
}

{
  const clock = { value: 5500 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('remote-terminal-target', state), state, clock, 'remote-terminal')
  authored.sync.destroy()
  state.mode = 'remote-terminal'
  const reloaded = syncFor(authored.shared, relayFixture('remote-terminal-target', state), clock, 'remote-terminal-reload')
  await reloaded.ready()
  await reloaded.flushPublicationQueue()
  const target = (await reloaded.journal.getIntent(authored.intentId)).targets['remote-terminal-target']
  assert.equal((await reloaded.status()).publication.durability.state, 'repair-needed')
  assert.equal(target.lastReadbackError, 'HIVERELAY_READBACK_TERMINAL')
  assert.deepEqual([state.puts, state.gets], [1, 2],
    'canonical retryable=0 GET failure becomes a bounded repair blocker')
  reloaded.destroy()
}

{
  const clock = { value: 6000 }
  const oldState = {}
  const authored = await authorOnce(identity, relayFixture('old-target', oldState), oldState, clock, 'new-identity')
  const olderIntentId = authored.intentId
  const latest = await authored.sync.append(await signedOperation(identity, `new-identity-latest-${++sequence}`))
  await authored.sync.flushPublicationQueue()
  assert.deepEqual([oldState.puts, oldState.gets], [2, 2])
  authored.sync.destroy()
  const newState = { present: false, capability: false }
  const replacement = syncFor(
    authored.shared,
    relayFixture('new-target', newState),
    clock,
    'new-identity-reload'
  )
  await replacement.ready()
  await replacement.flushPublicationQueue()
  const status = await replacement.status()
  const olderIntent = await replacement.journal.getIntent(olderIntentId)
  const latestIntent = await replacement.journal.getIntent(latest.intentId)
  assert.equal(status.publication.durability.state, 'recently-retrievable')
  assert.deepEqual([newState.puts, newState.gets], [1, 1],
    'a compliant new target identity receives one fresh latest-intent replica and readback')
  assert.deepEqual(Object.keys(olderIntent.targets), ['old-target'],
    'bounded target adoption leaves older completed intents untouched')
  assert.deepEqual(Object.keys(latestIntent.targets).sort(), ['new-target', 'old-target'],
    'only summary.latestIntentId receives the compliant replacement replica')
  await replacement.flushPublicationQueue()
  assert.deepEqual([newState.puts, newState.gets], [1, 1],
    'the bounded latest-intent repair lane is idempotent after acknowledgement')
  replacement.destroy()
}

{
  const clock = { value: 7000 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('replaced-target', state), state, clock, 'replaced')
  authored.sync.destroy()
  let release
  let started
  const began = new Promise(resolve => { started = resolve })
  const slow = relayFixture('replaced-target', state)
  slow.revalidateReadback = async () => {
    state.gets++
    started()
    await new Promise(resolve => { release = resolve })
    throw failure('HIVERELAY_READBACK_NOT_FOUND', {
      terminal: true,
      definitiveAbsence: true
    })
  }
  const reloaded = syncFor(authored.shared, slow, clock, 'replaced-reload')
  await reloaded.ready()
  const inFlight = reloaded.flushPublicationQueue()
  await began
  reloaded.setRelays([relayFixture('replaced-target', state)])
  release()
  await inFlight
  assert.equal((await reloaded.status()).publication.durability.state, 'remote-evidence-stale',
    'an in-flight failure from a replaced adapter cannot poison its same-ID replacement')
  assert.equal((await reloaded.journal.getIntent(authored.intentId)).targets['replaced-target'].readbackRepairNeeded, false)
  await reloaded.flushPublicationQueue()
  assert.equal((await reloaded.status()).publication.durability.state, 'recently-retrievable')
  assert.deepEqual([state.puts, state.gets], [1, 3],
    'the replacement performs its own forced GET without duplicating the PUT')
  reloaded.destroy()
}

{
  const clock = { value: 7500 }
  const state = {}
  const authored = await authorOnce(identity, relayFixture('evidence-race-target', state), state, clock, 'evidence-race')
  authored.sync.destroy()
  let releaseOlder
  let olderStarted
  const olderBegan = new Promise(resolve => { olderStarted = resolve })
  const olderRelay = {
    id: 'evidence-race-target',
    compatible: true,
    deliver: async () => { throw new Error('acknowledged target must never PUT') },
    async revalidateReadback () {
      olderStarted()
      await new Promise(resolve => { releaseOlder = resolve })
      return {
        ok: true,
        acknowledged: true,
        readbackVerified: true,
        readbackRevalidated: true,
        readbackEvidenceRevision: 4,
        evidenceRef: 'race:revision-4'
      }
    }
  }
  const newerRelay = {
    ...olderRelay,
    async revalidateReadback () {
      return {
        ok: true,
        acknowledged: true,
        readbackVerified: true,
        readbackRevalidated: true,
        readbackEvidenceRevision: 5,
        evidenceRef: 'race:revision-5'
      }
    }
  }
  const olderSync = syncFor(authored.shared, olderRelay, clock, 'evidence-race-older')
  const newerSync = syncFor(authored.shared, newerRelay, clock, 'evidence-race-newer')
  await Promise.all([olderSync.ready(), newerSync.ready()])
  const olderFlush = olderSync.flushPublicationQueue()
  await olderBegan
  await newerSync.flushPublicationQueue()
  releaseOlder()
  await olderFlush
  let target = (await newerSync.journal.getIntent(authored.intentId)).targets['evidence-race-target']
  assert.equal(target.lastReadbackEvidenceRevision, 5)
  assert.equal(target.lastReadbackEvidenceRef, 'race:revision-5',
    'a late lower vault revision cannot replace the newest journal evidence reference')
  assert.equal((await newerSync.status()).publication.durability.state, 'recently-retrievable')
  assert.equal((await olderSync.status()).publication.durability.state, 'remote-evidence-stale')
  olderSync.destroy()
  newerSync.destroy()

  const equalSync = syncFor(authored.shared, newerRelay, clock, 'evidence-race-equal')
  await equalSync.ready()
  await equalSync.flushPublicationQueue()
  assert.equal((await equalSync.status()).publication.durability.state, 'remote-evidence-stale',
    'an equal vault revision cannot mint a fresh session claim')
  equalSync.destroy()

  let releaseFailure
  let failureStarted
  const failureBegan = new Promise(resolve => { failureStarted = resolve })
  const lateFailureRelay = {
    ...olderRelay,
    async revalidateReadback () {
      failureStarted()
      await new Promise(resolve => { releaseFailure = resolve })
      throw failure('HIVERELAY_READBACK_NOT_FOUND', { terminal: true, definitiveAbsence: true })
    }
  }
  const revisionSixRelay = {
    ...newerRelay,
    async revalidateReadback () {
      return {
        ok: true,
        acknowledged: true,
        readbackVerified: true,
        readbackRevalidated: true,
        readbackEvidenceRevision: 6,
        evidenceRef: 'race:revision-6'
      }
    }
  }
  const failureSync = syncFor(authored.shared, lateFailureRelay, clock, 'evidence-race-failure')
  const revisionSixSync = syncFor(authored.shared, revisionSixRelay, clock, 'evidence-race-six')
  await Promise.all([failureSync.ready(), revisionSixSync.ready()])
  const failureFlush = failureSync.flushPublicationQueue()
  await failureBegan
  await revisionSixSync.flushPublicationQueue()
  releaseFailure()
  await failureFlush
  target = (await revisionSixSync.journal.getIntent(authored.intentId)).targets['evidence-race-target']
  assert.equal(target.lastReadbackEvidenceRevision, 6)
  assert.equal(target.readbackRepairNeeded, false,
    'a stale failure observed at an older evidence revision cannot invalidate a newer success')
  failureSync.destroy()
  revisionSixSync.destroy()
}

{
  const clock = { value: 8000 }
  const firstState = {}
  const authored = await authorOnce(identity, relayFixture('rotation-target-0', firstState), firstState, clock, 'rotation-budget')
  for (let index = 1; index < 16; index++) {
    const state = { present: false, capability: false }
    authored.sync.setRelays([relayFixture(`rotation-target-${index}`, state)])
    await authored.sync.flushPublicationQueue()
    assert.deepEqual([state.puts, state.gets], [1, 1])
  }
  const exhaustedState = { present: false, capability: false }
  authored.sync.setRelays([relayFixture('rotation-target-16', exhaustedState)])
  await authored.sync.flushPublicationQueue()
  let status = await authored.sync.status()
  const saturated = await authored.sync.journal.getIntent(authored.intentId)
  assert.equal(saturated.targetCount, 16)
  assert.deepEqual([exhaustedState.puts, exhaustedState.gets], [0, 0])
  assert.equal(status.publication.local.state, 'ready')
  assert.equal(status.publication.relay.state, 'target-budget-exhausted')
  assert.equal(status.publication.durability.state, 'target-budget-exhausted')

  const next = await authored.sync.append(await signedOperation(identity, `after-target-budget-${++sequence}`))
  await authored.sync.flushPublicationQueue()
  status = await authored.sync.status()
  assert.equal(status.publication.local.state, 'ready')
  assert.equal(status.publication.durability.state, 'recently-retrievable')
  assert.deepEqual([exhaustedState.puts, exhaustedState.gets], [1, 1],
    'target-history exhaustion blocks only old-intent backfill; new local authoring uses the current relay')
  assert.equal((await authored.sync.journal.getIntent(next.intentId)).targetCount, 1)
  assert.equal((await authored.sync.journal.getIntent(authored.intentId)).targetCount, 16,
    'all bounded historical receipts remain auditable and are never retired silently')
  authored.sync.destroy()
}

{
  const clock = { value: 9000 }
  const shared = createMemoryJournalState()
  const xState = {}
  const x = relayFixture('retry-partition-x', xState)
  let oldIntentId = null
  let yMaySucceed = false
  let yRevision = 0
  const y = {
    id: 'retry-partition-y',
    compatible: true,
    async deliver (publication) {
      if (publication.intentId === oldIntentId && !yMaySucceed) {
        throw failure('RETRYABLE_NOT_SENT', { definitelyNotProcessed: true, safeToRetry: true })
      }
      return {
        ok: true,
        acknowledged: true,
        readbackVerified: true,
        readbackRevalidated: true,
        readbackEvidenceRevision: ++yRevision,
        evidenceRef: `retry-partition-y:${publication.intentId}:${yRevision}`
      }
    },
    async revalidateReadback () {
      return {
        ok: true,
        acknowledged: true,
        readbackVerified: true,
        readbackRevalidated: true,
        readbackEvidenceRevision: ++yRevision,
        evidenceRef: `retry-partition-y:read:${yRevision}`
      }
    }
  }
  const sync = createPeeritSubstrateSync({
    journal: createMemoryPeeritJournal({ shared, clock: () => clock.value }),
    relays: [x, y],
    autoFlush: false,
    clock: () => clock.value,
    readbackFreshnessTtlMs: TTL,
    retryBaseMs: 10,
    retryMaxMs: 40,
    channelName: 'peerit-readback-retry-partition',
    attemptOwner: 'retry-partition'
  })
  await sync.ready()
  const old = await sync.append(await signedOperation(identity, `retry-partition-old-${++sequence}`))
  oldIntentId = old.intentId
  await sync.flushPublicationQueue()
  assert.equal((await sync.journal.getIntent(old.intentId)).targets[y.id].state, 'retryable')

  sync.setRelays([x])
  const latest = await sync.append(await signedOperation(identity, `retry-partition-latest-${++sequence}`))
  await sync.flushPublicationQueue()
  const zState = { present: false, capability: false }
  const zDeliveries = []
  const zBase = relayFixture('retry-partition-z', zState)
  const z = {
    ...zBase,
    async deliver (publication) {
      zDeliveries.push(publication.intentId)
      return zBase.deliver(publication)
    }
  }
  clock.value += 10
  yMaySucceed = true
  sync.setRelays([y, z])
  await sync.flushPublicationQueue()
  assert.deepEqual(zDeliveries, [latest.intentId],
    'a new target receives only latest B, never retry-only historical A')
  assert.equal((await sync.journal.getIntent(old.intentId)).targets[z.id], undefined)
  assert.equal((await sync.journal.getIntent(old.intentId)).targets[y.id].state, 'readback-verified')
  sync.destroy()
}

console.log('peerit-readback-freshness: TTL, restart, loss, backoff, and bounded new-target delivery passed')
