import assert from 'node:assert/strict'
import { canonical } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import {
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import { createPeeritSubstrateSync } from '../js/substrate/peerit-substrate-sync.js'
import { memoryStorage } from '../js/sync.js'

async function signedProfileOperation (identity, label, value) {
  const me = identity.me()
  const data = { id: me.pubkey, author: me.pubkey, name: `${label}:${JSON.stringify(value)}` }
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

async function seedSignedIntents (journal, identity, domain, values) {
  const author = createPeeritSubstrateSync({
    journal,
    relays: [],
    autoFlush: false,
    requireVerifiedRelayAdapters: false,
    channelName: `peerit-delivery-seed-${domain}`
  })
  await author.ready()
  for (const [index, value] of values.entries()) {
    await author.append(await signedProfileOperation(identity, `${domain}:${index}`, value))
  }
  author.destroy()
}

function delay (milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

await cryptoReady()
const identity = createIdentity({
  forceDev: true,
  lazy: true,
  storage: memoryStorage(),
  session: memoryStorage()
})
await identity.ready()
await identity.ensureActive('delivery-concurrency-fixture')

const state = createMemoryJournalState()
const journal = createMemoryPeeritJournal({ shared: state })
await seedSignedIntents(journal, identity, 'concurrency',
  Array.from({ length: 12 }, (_, index) => ({ index })))

let inFlight = 0
let maximumInFlight = 0
let fastCalls = 0
let abortedHungCalls = 0
function enter () {
  inFlight++
  maximumInFlight = Math.max(maximumInFlight, inFlight)
}
function leave () { inFlight-- }

function fastRelay (name) {
  return {
    id: name,
    async deliver () {
      enter()
      try {
        fastCalls++
        await delay(2)
        return { ok: true, evidenceRef: `${name}:${fastCalls}` }
      } finally {
        leave()
      }
    }
  }
}

const hungRelay = {
  id: 'hung-relay',
  deliver (payload, context = {}) {
    enter()
    return new Promise(resolve => {
      const signal = context.signal
      if (!signal) return
      const abort = () => {
        abortedHungCalls++
        leave()
        resolve({ ok: false, evidenceRef: `late:${payload.intentId}` })
      }
      if (signal.aborted) abort()
      else signal.addEventListener('abort', abort, { once: true })
    })
  }
}

const sync = createPeeritSubstrateSync({
  journal,
  relays: [fastRelay('fast-a'), hungRelay, fastRelay('fast-b')],
  autoFlush: false,
  requireVerifiedRelayAdapters: false,
  deliveryIntentConcurrency: 4,
  deliveryRelayConcurrency: 3,
  deliveryAttemptTimeoutMs: 20,
  channelName: 'peerit-delivery-concurrency-test'
})
await sync.ready()
await sync.flushPublicationQueue()

const summary = await journal.summary()
assert.equal(fastCalls, 24, 'both healthy relays receive every intent')
assert.equal(abortedHungCalls, 12, 'every hung attempt is bounded and aborted')
assert.ok(maximumInFlight >= 4, `expected bounded parallel work, saw maximum ${maximumInFlight}`)
assert.equal(summary.pendingIntentCount, 0, 'healthy acknowledgements complete every local intent')
assert.equal(summary.targetStateCounts.acknowledged, 24)
assert.equal(summary.targetStateCounts['pending-unknown'], 12)

sync.destroy()

const adversarialJournal = createMemoryPeeritJournal({ shared: createMemoryJournalState() })
await seedSignedIntents(adversarialJournal, identity, 'adversarial', [{ adversarial: true }])
const abortAckSync = createPeeritSubstrateSync({
  journal: adversarialJournal,
  relays: [{
    id: 'abort-ack-relay',
    deliver (payload, context = {}) {
      return new Promise(resolve => {
        context.signal.addEventListener('abort', () => {
          resolve({ ok: true, evidenceRef: `forged-after-deadline:${payload.intentId}` })
        }, { once: true })
      })
    }
  }],
  autoFlush: false,
  deliveryAttemptTimeoutMs: 10,
  channelName: 'peerit-delivery-abort-race-test'
})
await abortAckSync.ready()
await abortAckSync.flushPublicationQueue()
const adversarialSummary = await adversarialJournal.summary()
assert.equal(adversarialSummary.targetStateCounts.acknowledged, 0,
  'an adapter cannot turn its abort callback into an acknowledgement after deadline')
assert.equal(adversarialSummary.targetStateCounts['pending-unknown'], 1,
  'an expired attempt remains ambiguous even when the adapter resolves from abort')
abortAckSync.destroy()

const partialState = createMemoryJournalState()
const partialJournal = createMemoryPeeritJournal({ shared: partialState })
await seedSignedIntents(partialJournal, identity, 'partial', [{ partial: true }])
let ambiguousSends = 0
const partialFirst = createPeeritSubstrateSync({
  journal: partialJournal,
  relays: [{
    id: 'durable-a',
    async deliver () { return { ok: true, evidenceRef: 'durable-a:first' } }
  }, {
    id: 'ambiguous-b',
    async deliver () {
      ambiguousSends++
      throw Object.assign(new Error('response lost'), { code: 'RESPONSE_LOST' })
    }
  }],
  autoFlush: false,
  channelName: 'peerit-partial-repair-first'
})
await partialFirst.ready()
await partialFirst.flushPublicationQueue()
assert.equal((await partialJournal.summary()).pendingIntentCount, 0,
  'one durable copy may complete local pending status while another target remains ambiguous')
partialFirst.destroy()

let reconciliations = 0
const partialSecond = createPeeritSubstrateSync({
  journal: createMemoryPeeritJournal({ shared: partialState }),
  relays: [{
    id: 'durable-a',
    async deliver () { throw new Error('already acknowledged target must not resend') }
  }, {
    id: 'ambiguous-b',
    async deliver () { throw new Error('ambiguous target must reconcile before any new delivery') },
    async reconcile () {
      reconciliations++
      return { ok: true, evidenceRef: 'ambiguous-b:reconciled' }
    }
  }],
  autoFlush: false,
  channelName: 'peerit-partial-repair-second'
})
await partialSecond.ready()
await partialSecond.flushPublicationQueue()
const repairedSummary = await partialSecond.journal.summary()
assert.equal(ambiguousSends, 1, 'ambiguous target is never mutation-resubmitted')
assert.equal(reconciliations, 1, 'completed intent remains discoverable through the retry-target index')
assert.equal(repairedSummary.targetStateCounts.acknowledged, 2,
  'same-target reconciliation upgrades the second durability copy after reload')
assert.equal(repairedSummary.targetStateCounts['pending-unknown'], 0)
partialSecond.destroy()

const boundedJournal = createMemoryPeeritJournal({ shared: createMemoryJournalState() })
await seedSignedIntents(boundedJournal, identity, 'bounded', [{ bounded: true }])
const retrySelections = []
const wakeSelections = []
const originalRetryList = boundedJournal.listRetryIntentIds.bind(boundedJournal)
const originalNextWake = boundedJournal.nextWake.bind(boundedJournal)
boundedJournal.listRetryIntentIds = options => {
  retrySelections.push([...options.targetIds])
  return originalRetryList(options)
}
boundedJournal.nextWake = options => {
  wakeSelections.push([...options.targetIds])
  return originalNextWake(options)
}
const boundedCalls = new Map()
const boundedRelays = Array.from({ length: 5 }, (_, index) => ({
  id: `bounded-${index}`,
  async deliver () {
    boundedCalls.set(index, (boundedCalls.get(index) || 0) + 1)
    return { ok: true, evidenceRef: `bounded:${index}` }
  }
}))
const boundedSync = createPeeritSubstrateSync({
  journal: boundedJournal,
  relays: boundedRelays,
  maxRelayTargets: 2,
  autoFlush: false,
  channelName: 'peerit-bounded-relay-selection-test'
})
await boundedSync.ready()
await boundedSync.flushPublicationQueue()
boundedSync.autoFlush = true
boundedSync._scheduleNextAttempt()
await delay(0)
boundedSync.autoFlush = false
assert.deepEqual(retrySelections[0], ['bounded-0', 'bounded-1'],
  'retry scans use only the bounded active relay set')
assert.deepEqual(wakeSelections[0], retrySelections[0],
  'wake scheduling uses the same bounded active relay set as retry scans')
assert.deepEqual([...boundedCalls.keys()], [0, 1],
  'delivery cannot escape the bounded active relay set')
boundedSync.destroy()

console.log(`peerit-delivery-concurrency: 12 intents, 3 relays, max ${maximumInFlight} in flight, hung attempts bounded`)
