// Local-first replacement-runtime contract. No live relays and no production
// deployment are touched. Run: node test/peerit-substrate-sync.mjs

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { canonical } from '../js/canon.js'
import { createData } from '../js/data.js'
import { createIdentity } from '../js/identity.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { resolveRuntime } from '../js/runtime.js'
import { createSync, memoryStorage } from '../js/sync.js'
import { createBlindCellRelay } from '../js/substrate/blind-client-relay.js'
import { createMemoryJournalState, createMemoryPeeritJournal } from '../js/substrate/peerit-journal.js'
import { publicationModeLabel, publicationNetSegments, publicationUiState } from '../js/substrate/publication-status.js'

let passed = 0
function ok (condition, message) {
  assert.ok(condition, message)
  passed++
  console.log('  ✓ ' + message)
}

async function until (predicate, timeout = 1500) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (await predicate()) return true
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  return false
}

function createTestSync (shared, options = {}) {
  const journal = options.journal || createMemoryPeeritJournal({
    shared,
    clock: options.clock,
    legacyStorage: options.legacyStorage,
    limits: options.journalLimits
  })
  return createSync({ ...options, mode: 'substrate', journal })
}

function doc (metas = {}) {
  return {
    querySelector (selector) {
      const match = selector.match(/meta\[name="([^"]+)"\]/)
      const name = match && match[1]
      return name && Object.hasOwn(metas, name)
        ? { getAttribute: () => metas[name] }
        : null
    }
  }
}

async function signedOperation (identity, name) {
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

async function main () {
  await cryptoReady()

  console.log('\n— explicit replacement runtime keeps host priority and accepts zero relay hints —')
  const replacement = resolveRuntime({
    rawPear: null,
    doc: doc({
      'peerit-substrate': 'blind-v1',
      'peerit-relay': 'https://legacy.example',
      'peerit-relay-readonly': 'true',
      'peerit-shard-relays': 'https://legacy-shard-a.example,https://legacy-shard-b.example'
    })
  })
  ok(replacement.mode === 'web-substrate' && replacement.readOnly === false,
    'blind-v1 selects a writable local-first runtime instead of inheriting legacy read-only state')
  ok(replacement.identityOpts.forceDev === true && replacement.identityOpts.lazy === true,
    'replacement runtime starts as an identity-less explicit-opt-in lurker')
  ok(replacement.syncOpts.mode === 'substrate' && replacement.syncOpts.relays.length === 0 && replacement.relayHints.length === 0,
    'zero relay hints is a valid replacement configuration')
  ok(replacement.shardCohort === null,
    'replacement runtime does not silently compose with the retired legacy shard path')
  assert.throws(
    () => resolveRuntime({ rawPear: null, doc: doc({ 'peerit-substrate': 'future-v9', 'peerit-relay': 'https://legacy.example' }) }),
    error => error && error.code === 'PEERIT_SUBSTRATE_VERSION_UNSUPPORTED'
  )
  passed++
  console.log('  ✓ an unknown substrate version fails closed instead of silently downgrading to a legacy relay')

  console.log('\n— fresh lurker writes post/comment/vote locally while completely offline —')
  const journalState = createMemoryJournalState()
  const identity = createIdentity({
    forceDev: true,
    lazy: true,
    storage: memoryStorage(),
    session: memoryStorage()
  })
  await identity.ready()
  ok(identity.me().pubkey == null, 'ready() does not create a writer identity')

  const sync1 = createTestSync(journalState, { relays: [], autoFlush: false, channelName: 'peerit-substrate-test-1' })
  await sync1.ready()
  ok(journalState.writeTransactions === 0,
    'fresh lurker ready() performs no journal write or empty-record creation')
  let writerActivations = 0
  const data1 = createData(sync1, identity, {
    minBits: { community: 0, post: 0, comment: 0, vote: 0, profile: 0, modaction: 0, blob: 0 },
    ensureWriter: async () => {
      writerActivations++
      await identity.ensureActive('offline-author')
    },
    withWriterSession: fn => sync1.withLocalWriterSession(fn)
  })

  await data1.createCommunity({ slug: 'offline', title: 'Offline' })
  ok(!!identity.me().pubkey && writerActivations > 0,
    'the first explicit authoring action creates the writer identity')
  const post = await data1.submitPost({ community: 'offline', kind: 'text', title: 'Local first', body: 'still usable offline' })
  const comment = await data1.addComment({ community: 'offline', postCid: post.cid, body: 'visible before delivery' })
  await data1.vote(post.cid, 'offline', 'post', 1)

  const offlineStatus = await sync1.status()
  ok(offlineStatus.publication.relay.state === 'queued-no-relay' && offlineStatus.publication.relay.pendingIntents === 4,
    'zero relays leaves each signed domain mutation durably queued instead of rejecting it')
  ok(offlineStatus.publication.durability.state === 'local-only' && offlineStatus.publication.discovery.state === 'queued',
    'durability and discovery remain independent from the local authoring result')
  ok((await data1.getPost('offline', post.cid)).title === 'Local first' &&
    (await data1.getComment('offline', post.cid, comment.cid)).body === 'visible before delivery' &&
    (await data1.tallyFor(post.cid)).score === 1,
  'post, comment, and vote are materialized locally before networking')

  const v2State = createMemoryJournalState()
  const v2Sync = createTestSync(v2State, { relays: [], autoFlush: false, channelName: 'peerit-substrate-v2' })
  await v2Sync.ready()
  const v2Data = createData(v2Sync, identity, {
    v2: true,
    minBits: { community: 0, post: 0, comment: 0, vote: 0, profile: 0, modaction: 0, blob: 0 },
    withWriterSession: fn => v2Sync.withLocalWriterSession(fn)
  })
  await v2Data.createCommunity({ slug: 'opaque', title: 'Opaque' })
  const v2Post = await v2Data.submitPost({ community: 'opaque', kind: 'text', title: 'Opaque local first', body: 'sealed graph' })
  const v2Comment = await v2Data.addComment({ community: 'opaque', postCid: v2Post.cid, body: 'sealed reply' })
  await v2Data.vote(v2Post.cid, 'opaque', 'post', 1)
  ok((await v2Data.getPost('opaque', v2Post.cid)).title === 'Opaque local first' &&
    (await v2Data.getComment('opaque', v2Post.cid, v2Comment.cid)).body === 'sealed reply' &&
    (await v2Data.tallyFor(v2Post.cid)).score === 1,
  'opaque-v2 post, comment, and vote pass signature admission and remain visible offline')
  v2Sync.destroy()

  console.log('\n— reload preserves the view and one unregistered compatible relay can deliver —')
  sync1.destroy()
  const delivered = []
  let deliverCalls = 0
  const relayContext = { sync: null }
  const relay = {
    id: 'unregistered-compatible-relay',
    compatible: true,
    async deliver (publication) {
      deliverCalls++
      for (const key of publication.recordKeys) {
        assert.ok(await relayContext.sync.get(key), 'record must already be visible before relay delivery')
      }
      delivered.push(publication)
      return { ok: true, acknowledged: true, readbackVerified: false, policyDurable: false, evidenceRef: `test-receipt:${publication.intentId}` }
    }
  }
  const sync2 = createTestSync(journalState, { relays: [relay], autoFlush: false, channelName: 'peerit-substrate-test-2' })
  relayContext.sync = sync2
  await sync2.ready()
  const data2 = createData(sync2, identity)
  ok((await data2.getPost('offline', post.cid)).title === 'Local first' &&
    (await data2.getComment('offline', post.cid, comment.cid)).body === 'visible before delivery' &&
    (await data2.tallyFor(post.cid)).score === 1,
  'offline post, comment, and vote survive a full sync-instance reload')

  await sync2.flushPublicationQueue()
  const deliveredStatus = await sync2.status()
  ok(deliverCalls === 4 && deliveredStatus.publication.relay.state === 'relay-acknowledged',
    'one compatible relay acknowledges every queued intent without registry or quorum approval')
  ok(deliveredStatus.publication.durability.state === 'remote-single' && deliveredStatus.publication.discovery.state === 'queued',
    'one acknowledgement upgrades only the truthful remote-storage label, not discovery or resilience')
  const durableAckIntents = await Promise.all(delivered.map(item => sync2.journal.getIntent(item.intentId)))
  ok(durableAckIntents.every(intent =>
    Object.values(intent.targets).some(target => target.state === 'acknowledged' && typeof target.evidenceRef === 'string')),
  'every counted acknowledgement retains a durable verified-evidence reference')

  console.log('\n— acknowledged and duplicate intents are idempotent across reload —')
  sync2.destroy()
  const sync3 = createTestSync(journalState, { relays: [relay], autoFlush: false, channelName: 'peerit-substrate-test-3' })
  await sync3.ready()
  await sync3.flushPublicationQueue()
  ok(deliverCalls === 4, 'reload does not resend intents that already have a verified acknowledgement')
  const duplicate = await sync3.append(delivered[1].operations[0])
  await sync3.flushPublicationQueue()
  ok(duplicate.duplicate === true && duplicate.queued === false && deliverCalls === 4,
    're-appending the exact signed event reuses its intent identity and cannot duplicate delivery')
  sync3.destroy()

  const lwwState = createMemoryJournalState()
  const lwwSync = createTestSync(lwwState, { relays: [], autoFlush: false, channelName: 'peerit-substrate-lww' })
  await lwwSync.ready()
  const firstLww = await lwwSync.append(await signedOperation(identity, 'first LWW value'))
  const secondOperation = await signedOperation(identity, 'second LWW value')
  const secondLww = await lwwSync.append(secondOperation)
  ok(firstLww.logicalId !== secondLww.logicalId && (await lwwSync.status()).publication.intentCount === 2,
    'distinct signed LWW updates sharing one materialized key retain distinct logical event identities')
  await assert.rejects(
    () => lwwSync.append({ type: 'profile', data: { id: 'a'.repeat(64), author: 'a'.repeat(64), _k: 'a'.repeat(64), _sig: 'b'.repeat(128) } }),
    error => error && error.code === 'PEERIT_SUBSTRATE_INVALID_SIGNATURE'
  )
  passed++
  console.log('  ✓ shape-correct fake signatures cannot enter the local materialized view')
  lwwSync.destroy()

  console.log('\n— ambiguous response loss never auto-resubmits —')
  const ambiguousState = createMemoryJournalState()
  let ambiguousSends = 0
  let reconciles = 0
  const ambiguousRelay = {
    id: 'ambiguous-relay',
    async deliver () {
      ambiguousSends++
      throw Object.assign(new Error('response lost'), { code: 'RESPONSE_LOST' })
    }
  }
  const ambiguous1 = createTestSync(ambiguousState, { relays: [ambiguousRelay], autoFlush: false, channelName: 'peerit-substrate-ambiguous-1' })
  await ambiguous1.ready()
  await ambiguous1.append(await signedOperation(identity, 'ambiguous response'))
  await ambiguous1.flushPublicationQueue()
  ok((await ambiguous1.status()).publication.relay.state === 'pending-unknown' && ambiguousSends === 1,
    'response loss is retained as pending-unknown after exactly one send')
  ambiguous1.destroy()

  const reconcileRelay = {
    ...ambiguousRelay,
    async reconcile () {
      reconciles++
      return { ok: true, acknowledged: true, evidenceRef: 'test-reconciled-receipt' }
    }
  }
  const ambiguous2 = createTestSync(ambiguousState, { relays: [ambiguousRelay], autoFlush: false, channelName: 'peerit-substrate-ambiguous-2' })
  await ambiguous2.ready()
  await ambiguous2.flushPublicationQueue()
  ok(ambiguousSends === 1, 'reload without reconciliation cannot retransmit an ambiguous request')
  ambiguous2.setRelays([reconcileRelay])
  await ambiguous2.flushPublicationQueue()
  ok(reconciles === 1 && ambiguousSends === 1 && (await ambiguous2.status()).publication.relay.state === 'relay-acknowledged',
    'same-target reconciliation can resolve ambiguity without a second mutation send')
  ambiguous2.destroy()

  console.log('\n— cross-tab claim ownership and crash boundaries —')
  const concurrentState = createMemoryJournalState()
  let concurrentSends = 0
  let releaseConcurrent
  let markConcurrentStarted
  const concurrentStarted = new Promise(resolve => { markConcurrentStarted = resolve })
  const concurrentRelay = {
    id: 'concurrent-relay',
    async deliver (publication) {
      concurrentSends++
      markConcurrentStarted()
      await new Promise(resolve => { releaseConcurrent = resolve })
      return { ok: true, acknowledged: true, evidenceRef: `concurrent:${publication.intentId}` }
    }
  }
  const concurrentA = createTestSync(concurrentState, { relays: [concurrentRelay], autoFlush: false, channelName: 'peerit-concurrent-a', deliveryLeaseMs: 10_000 })
  await concurrentA.ready()
  await concurrentA.append(await signedOperation(identity, 'cross-tab claim'))
  const flushA = concurrentA.flushPublicationQueue()
  await concurrentStarted
  const concurrentB = createTestSync(concurrentState, { relays: [concurrentRelay], autoFlush: false, channelName: 'peerit-concurrent-b', deliveryLeaseMs: 10_000 })
  await concurrentB.ready()
  await concurrentB.flushPublicationQueue()
  ok(concurrentSends === 1,
    'a second tab cannot steal or duplicate a live target claim while the first response is pending')
  releaseConcurrent()
  await flushA
  ok((await concurrentB.status()).publication.relay.state === 'relay-acknowledged',
    'the original tab can persist its verified ACK after another tab opens')
  concurrentA.destroy()
  concurrentB.destroy()

  let crashClock = 0
  let prepareCalls = 0
  let crashSends = 0
  let releaseFirstPrepare
  let markPrepareStarted
  const prepareStarted = new Promise(resolve => { markPrepareStarted = resolve })
  const crashRelay = {
    id: 'crash-boundary-relay',
    async prepare () {
      prepareCalls++
      if (prepareCalls === 1) {
        markPrepareStarted()
        await new Promise(resolve => { releaseFirstPrepare = resolve })
      }
      return { exact: 'prepared' }
    },
    async send (publication) {
      crashSends++
      return { ok: true, acknowledged: true, evidenceRef: `crash:${publication.intentId}` }
    }
  }
  const crashState = createMemoryJournalState()
  const crashA = createTestSync(crashState, { relays: [crashRelay], autoFlush: false, clock: () => crashClock, channelName: 'peerit-crash-a', deliveryLeaseMs: 1000 })
  await crashA.ready()
  await crashA.append(await signedOperation(identity, 'crash before send'))
  const crashFlushA = crashA.flushPublicationQueue()
  await prepareStarted
  crashClock = 1001
  const crashB = createTestSync(crashState, { relays: [crashRelay], autoFlush: false, clock: () => crashClock, channelName: 'peerit-crash-b', deliveryLeaseMs: 1000 })
  await crashB.ready()
  releaseFirstPrepare()
  await crashFlushA
  ok(crashSends === 0,
    'an expired pre-send claim becomes retryable and the stale owner cannot cross the send boundary')
  await crashB.flushPublicationQueue()
  ok(crashSends === 1 && (await crashB.status()).publication.relay.state === 'relay-acknowledged',
    'a new owner safely retries preparation once and delivers after the pre-send crash')
  crashA.destroy()
  crashB.destroy()

  console.log('\n— automatic retry and cross-tab adoption stay live —')
  let retryCalls = 0
  const retryRelay = {
    id: 'automatic-retry-relay',
    async deliver (publication) {
      retryCalls++
      if (retryCalls === 1) throw Object.assign(new Error('definitely not processed'), { safeToRetry: true })
      return { ok: true, acknowledged: true, evidenceRef: `retry:${publication.intentId}` }
    }
  }
  const retrySync = createTestSync(createMemoryJournalState(), { relays: [retryRelay], retryBaseMs: 10, retryMaxMs: 20, channelName: 'peerit-auto-retry' })
  await retrySync.ready()
  await retrySync.append(await signedOperation(identity, 'automatic retry'))
  ok(await until(async () => retryCalls === 2 && (await retrySync.status()).publication.relay.state === 'relay-acknowledged'),
    'a definitely-safe retry advances with bounded background backoff and no new user action')
  retrySync.destroy()

  let terminalCalls = 0
  const terminalSync = createTestSync(createMemoryJournalState(), {
    relays: [{
      id: 'terminal-relay',
      async deliver () {
        terminalCalls++
        throw Object.assign(new Error('canonical terminal result'), { terminal: true })
      }
    }],
    autoFlush: false,
    channelName: 'peerit-terminal-result'
  })
  await terminalSync.ready()
  await terminalSync.append(await signedOperation(identity, 'terminal target'))
  await terminalSync.flushPublicationQueue()
  await terminalSync.flushPublicationQueue()
  ok(terminalCalls === 1,
    'a canonical terminal relay result is retained and never reclaimed as an automatic retry')
  terminalSync.destroy()

  const adoptionState = createMemoryJournalState()
  const adoptionChannel = 'peerit-cross-tab-adoption'
  let adoptionSends = 0
  const adoptionRelay = {
    id: 'adoption-relay',
    async deliver (publication) {
      adoptionSends++
      return { ok: true, acknowledged: true, evidenceRef: `adoption:${publication.intentId}` }
    }
  }
  const adoptionReader = createTestSync(adoptionState, { relays: [adoptionRelay], channelName: adoptionChannel })
  const adoptionAuthor = createTestSync(adoptionState, { relays: [], channelName: adoptionChannel })
  await adoptionReader.ready()
  await adoptionAuthor.ready()
  await adoptionAuthor.append(await signedOperation(identity, 'cross-tab adoption'))
  ok(await until(() => adoptionSends === 1),
    'an open relay-capable tab adopts and delivers a signed intent broadcast by another tab')
  adoptionReader.destroy()
  adoptionAuthor.destroy()

  console.log('\n— UI projection keeps authoring ready while showing all four axes —')
  const queuedUi = publicationUiState(offlineStatus)
  const deliveredUi = publicationUiState(deliveredStatus)
  ok(queuedUi.authoringReady === true && !/read[- ]only/i.test(queuedUi.copy) && /queued/i.test(queuedUi.copy),
    'queued-no-relay UI is usable local-first state, never a read-only product mode')
  ok(deliveredUi.authoringReady === true && /acknowledged/i.test(deliveredUi.copy),
    'a relay acknowledgement changes status copy without changing authoring readiness')
  ok(publicationNetSegments(deliveredStatus).length === 4 && /durability/.test(publicationModeLabel(deliveredStatus)),
    'status rendering exposes local, relay, durability, and discovery separately')
  ok(publicationUiState(null).authoringReady === false,
    'missing local journal status disables only safe authoring instead of pretending the device is ready')
  const corruptStorage = { getItem: () => '{not-json', setItem: () => {}, removeItem: () => {} }
  const corruptSync = createTestSync(createMemoryJournalState(), {
    legacyStorage: corruptStorage,
    relays: [],
    autoFlush: false,
    channelName: 'peerit-corrupt-local-journal'
  })
  await corruptSync.ready()
  ok((await corruptSync.status()).publication.local.state === 'blocked',
    'a corrupt local journal keeps browsing alive but fails only local authoring closed')
  await assert.rejects(
    async () => corruptSync.append(await signedOperation(identity, 'must not enter corrupt journal')),
    error => error && error.code === 'PEERIT_SUBSTRATE_LOCAL_AUTHORING_BLOCKED'
  )
  passed++
  console.log('  ✓ a blocked local journal refuses publication instead of falling through to memory')
  corruptSync.destroy()

  const appSource = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8')
  ok(appSource.includes('requiresSerializedWebWriter() ? withDataWriterSession') &&
    appSource.includes('if (requiresAtomicWebWriter()) await requireAtomicWebWriter()') &&
    appSource.includes('if (isPeeritSubstrateRuntime()) await requireLocalSubstrateWriter()'),
  'active app wiring serializes replacement writes locally while keeping relay quorum checks legacy-only')

  console.log('\n— blind-client control code is lazy and persistence precedes HTTP —')
  const order = []
  let controlLoads = 0
  let verifications = 0
  const base = {
    maximumCellContentBytes: () => 4096,
    async createCellReplica () {
      order.push('prepare')
      return {
        request: Object.freeze({ familyId: 1, operationId: 1 }),
        requestBytes: new Uint8Array([1, 2, 3]),
        requestCommitment: new Uint8Array(32),
        wire: { familyId: 1, operationId: 1, expectedResultBodyBytes: 64 },
        readCap: Object.freeze({ kind: 'read' }),
        writeCap: Object.freeze({ kind: 'write' })
      }
    }
  }
  const endpointContext = Object.freeze({
    relayPublicKey: new Uint8Array(32).fill(7),
    storeId: new Uint8Array(32).fill(1),
    continuityRoot: new Uint8Array(32).fill(2),
    durabilityContinuityHash: new Uint8Array(32).fill(3),
    descriptorHash: new Uint8Array(32).fill(4),
    endpointId: 1,
    familyId: 2,
    operationId: 3,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1,
    durabilityProfileId: 1
  })
  const externalWitnessVerifier = () => true
  const blindRelay = createBlindCellRelay({
    blindClient: base,
    relayPublicKey: new Uint8Array(32).fill(7),
    endpoint: Object.freeze({ verified: true }),
    endpointContext,
    externalWitnessVerifier,
    httpClient: {
      async request () {
        order.push('http')
        return { ok: true, body: new Uint8Array([9]) }
      }
    },
    async persistPreparedReplica () { order.push('persist') },
    async persistVerifiedResult () {
      order.push('persist-result')
      return { evidenceRef: 'test:verified-result' }
    },
    async loadControl () {
      controlLoads++
      order.push('load-control')
      return {
        verifiedEndpointContext: () => endpointContext,
        verifyOperationResult (options) {
          assert.equal(options.externalWitnessVerifier, externalWitnessVerifier)
          verifications++
          order.push('verify')
          return { snapshotBytes: () => new Uint8Array([8]) }
        }
      }
    }
  })
  ok(controlLoads === 0, 'constructing a blind relay for lurker mode does not load the writer/control subpath')
  await blindRelay.deliver({ intentId: 'i1', logicalId: 'l1', operationBytes: new Uint8Array([1]), operations: [], recordKeys: [] })
  await blindRelay.deliver({ intentId: 'i2', logicalId: 'l2', operationBytes: new Uint8Array([2]), operations: [], recordKeys: [] })
  ok(controlLoads === 1 && verifications === 2,
    'explicit delivery lazily loads @hiverelay/blind-client/control once and verifies every result')
  const firstPersist = order.indexOf('persist')
  const firstHttp = order.indexOf('http')
  ok(firstPersist >= 0 && firstPersist < firstHttp,
    'prepared Cell capabilities and exact request material persist before any HTTP send')
  ok(order.indexOf('verify') < order.indexOf('persist-result'),
    'a verified receipt and read capability are durably indexed before the adapter returns an acknowledgement')

  const hungAdapterJournal = createMemoryPeeritJournal({ shared: createMemoryJournalState() })
  const hungIntentId = 'a'.repeat(64)
  await hungAdapterJournal.commitIntent({
    intentId: hungIntentId,
    logicalId: 'b'.repeat(64),
    operationBytes: JSON.stringify({ version: 1, operations: [{ type: 'timeout-regression' }] }),
    records: [{ key: 'post!hung-adapter', value: { id: 'hung-adapter' } }],
    createdAt: 1
  })
  let hungRequestSignal = null
  let hungRequestTimeout = null
  let hungRequestAborted = 0
  const hungAdapter = createBlindCellRelay({
    blindClient: base,
    relayPublicKey: new Uint8Array(32).fill(7),
    endpoint: Object.freeze({ verified: true }),
    endpointContext,
    httpClient: {
      request ({ signal, timeoutMillis }) {
        hungRequestSignal = signal
        hungRequestTimeout = timeoutMillis
        return new Promise((resolve, reject) => {
          const aborted = () => {
            hungRequestAborted++
            reject(signal.reason || Object.assign(new Error('hung fetch aborted'), { name: 'AbortError' }))
          }
          if (signal.aborted) aborted()
          else signal.addEventListener('abort', aborted, { once: true })
        })
      }
    },
    persistPreparedReplica: async () => {},
    persistVerifiedResult: async () => ({ evidenceRef: 'must-not-complete' }),
    loadControl: async () => ({
      verifiedEndpointContext: () => endpointContext,
      verifyOperationResult: () => { throw new Error('aborted request must not verify') }
    })
  })
  const hungAdapterSync = createTestSync(null, {
    journal: hungAdapterJournal,
    relays: [hungAdapter],
    autoFlush: false,
    deliveryAttemptTimeoutMs: 10,
    channelName: 'peerit-real-adapter-abort-regression'
  })
  await hungAdapterSync.ready()
  await hungAdapterSync.flushPublicationQueue()
  const hungAdapterIntent = await hungAdapterJournal.getIntent(hungIntentId)
  ok(hungRequestSignal && hungRequestSignal.aborted === true && hungRequestTimeout === 10 &&
    hungRequestAborted === 1 && hungAdapterIntent.targets[hungAdapter.id].state === 'pending-unknown',
  'sync attempt expiry propagates through the real blind relay adapter and aborts its hung HTTP request')
  hungAdapterSync.destroy()

  const resetContext = Object.freeze({ ...endpointContext, storeId: new Uint8Array(32).fill(5) })
  const resetRelay = createBlindCellRelay({
    blindClient: base,
    relayPublicKey: new Uint8Array(32).fill(7),
    endpoint: Object.freeze({ verified: true }),
    endpointContext: resetContext,
    httpClient: { request: async () => ({ ok: true, body: new Uint8Array([9]) }) },
    persistPreparedReplica: async () => {},
    persistVerifiedResult: async () => ({ evidenceRef: 'test:reset-result' }),
    loadControl: async () => ({
      verifiedEndpointContext: () => resetContext,
      verifyOperationResult: () => ({ snapshotBytes: () => new Uint8Array([8]) })
    })
  })
  ok(resetRelay.id !== blindRelay.id,
    'a same-key relay store reset is a new target and cannot inherit an old acknowledgement')
  const transportContext = Object.freeze({ ...endpointContext, transportSupportBit: 2 })
  const transportRelay = createBlindCellRelay({
    blindClient: base,
    relayPublicKey: new Uint8Array(32).fill(7),
    endpoint: Object.freeze({ verified: true }),
    endpointContext: transportContext,
    httpClient: { request: async () => ({ ok: true, body: new Uint8Array([9]) }) },
    persistPreparedReplica: async () => {},
    persistVerifiedResult: async () => ({ evidenceRef: 'test:transport-result' }),
    loadControl: async () => ({
      verifiedEndpointContext: () => transportContext,
      verifyOperationResult: () => ({ snapshotBytes: () => new Uint8Array([8]) })
    })
  })
  ok(transportRelay.id !== blindRelay.id,
    'a health-qualified transport change is a new target and cannot reuse another endpoint binding')
  assert.throws(() => createBlindCellRelay({
    blindClient: base,
    relayPublicKey: new Uint8Array(32).fill(7),
    endpoint: Object.freeze({ verified: true }),
    endpointContext: { ...endpointContext, transportSupportBit: 3 },
    httpClient: { request: async () => ({ ok: true, body: new Uint8Array([9]) }) },
    persistPreparedReplica: async () => {},
    persistVerifiedResult: async () => ({ evidenceRef: 'test:invalid-transport-result' })
  }), /one exact support bit/)
  passed++
  console.log('  ✓ relay target identity refuses ambiguous transport support bits')
  let transientLoads = 0
  const retryableRelay = createBlindCellRelay({
    blindClient: base,
    relayPublicKey: new Uint8Array(32).fill(7),
    endpoint: Object.freeze({ verified: true }),
    endpointContext,
    httpClient: { request: async () => ({ ok: true, body: new Uint8Array([9]) }) },
    persistPreparedReplica: async () => {},
    persistVerifiedResult: async () => ({ evidenceRef: 'test:retry-result' }),
    async loadControl () {
      transientLoads++
      if (transientLoads === 1) throw new Error('control chunk temporarily unavailable')
      return {
        verifiedEndpointContext: () => endpointContext,
        verifyOperationResult: () => ({ snapshotBytes: () => new Uint8Array([8]) })
      }
    }
  })
  await assert.rejects(
    () => retryableRelay.deliver({ intentId: 'i3', logicalId: 'l3', operationBytes: new Uint8Array([3]), operations: [], recordKeys: [] }),
    error => error && error.code === 'RETRYABLE_NOT_SENT' && error.definitelyNotProcessed === true
  )
  await retryableRelay.deliver({ intentId: 'i3', logicalId: 'l3', operationBytes: new Uint8Array([3]), operations: [], recordKeys: [] })
  ok(transientLoads === 2,
    'a pre-network control-load failure is safely retryable and does not poison the lazy loader cache')

  let persistedReplica = null
  let resumedCreates = 0
  let resumedHttpCalls = 0
  const resumeBase = {
    maximumCellContentBytes: () => 4096,
    async createCellReplica () {
      resumedCreates++
      return {
        request: Object.freeze({ familyId: 1, operationId: 1 }),
        requestBytes: new Uint8Array([resumedCreates, 2, 3]),
        requestCommitment: new Uint8Array(32).fill(resumedCreates),
        wire: { familyId: 1, operationId: 1, expectedResultBodyBytes: 64 },
        readCap: Object.freeze({ kind: 'resumed-read' }),
        writeCap: Object.freeze({ kind: 'resumed-write' })
      }
    }
  }
  const persistence = {
    async persistPreparedReplica (packet) {
      persistedReplica = {
        evidenceRef: null,
        payload: { version: 1, stage: 1, ...packet }
      }
    },
    async persistVerifiedResult (packet) {
      persistedReplica = {
        evidenceRef: 'test:resumed-verified',
        payload: { version: 1, stage: 2, ...packet }
      }
      return { evidenceRef: persistedReplica.evidenceRef }
    },
    async loadPersistedReplica () { return persistedReplica }
  }
  const createResumeRelay = () => createBlindCellRelay({
    blindClient: resumeBase,
    relayPublicKey: new Uint8Array(32).fill(7),
    endpoint: Object.freeze({ verified: true }),
    endpointContext,
    httpClient: {
      async request () {
        resumedHttpCalls++
        return { ok: true, body: new Uint8Array([9]) }
      }
    },
    ...persistence,
    loadControl: async () => ({
      verifiedEndpointContext: () => endpointContext,
      verifyOperationResult: () => ({ snapshotBytes: () => new Uint8Array([8]) })
    })
  })
  const resumedPublication = {
    intentId: 'resume-intent',
    logicalId: 'resume-logical',
    operationBytes: new Uint8Array([4]),
    operations: [],
    recordKeys: []
  }
  const beforeCrash = createResumeRelay()
  const firstPrepared = await beforeCrash.prepare(resumedPublication)
  const afterCrash = createResumeRelay()
  const recoveredPrepared = await afterCrash.prepare(resumedPublication)
  assert.deepEqual(recoveredPrepared.requestBytes, firstPrepared.requestBytes)
  ok(resumedCreates === 1,
    'a pre-send crash reloads the exact encrypted prepared request and capabilities instead of regenerating them')
  const acknowledged = await afterCrash.send({ ...resumedPublication, prepared: recoveredPrepared })
  assert.equal(acknowledged.evidenceRef, 'test:resumed-verified')
  const afterAckCrash = createResumeRelay()
  const reconciled = await afterAckCrash.reconcile(resumedPublication)
  ok(reconciled.acknowledged === true && reconciled.evidenceRef === 'test:resumed-verified' && resumedHttpCalls === 1,
    'a post-result crash reconciles the encrypted verified receipt without a duplicate network mutation')

  console.log(`\n✅ all ${passed} Peerit substrate runtime checks passed\n`)
}

main().catch(error => {
  console.error('\n❌ FAILED:', error.message, '\n', error.stack)
  process.exit(1)
})
