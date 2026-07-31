import assert from 'node:assert/strict'
import {
  PEERIT_RELAY_REQUALIFICATION_STATUS,
  createPeeritRelayRequalificationScheduler
} from '../js/substrate/relay-requalification-scheduler.js'

function deferred () {
  let resolve
  let reject
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve
    reject = _reject
  })
  return { promise, resolve, reject }
}

function fakeClock (initial = 1000) {
  let now = initial
  let nextId = 1
  const timers = new Map()
  const setTimer = (callback, delay) => {
    const id = nextId++
    timers.set(id, { callback, at: now + delay })
    return id
  }
  const clearTimer = id => timers.delete(id)
  const flush = async () => {
    for (let index = 0; index < 12; index++) await Promise.resolve()
  }
  const advanceTo = async target => {
    let steps = 0
    while (true) {
      if (++steps > 1000) throw new Error('fake timer storm exceeded 1000 callbacks')
      const due = [...timers.entries()]
        .filter(([, timer]) => timer.at <= target)
        .sort((left, right) => left[1].at - right[1].at || left[0] - right[0])[0]
      if (!due) break
      const [id, timer] = due
      timers.delete(id)
      now = timer.at
      timer.callback()
      await flush()
    }
    now = target
    await flush()
  }
  return {
    now: () => now,
    setNow: value => { now = value },
    setTimer,
    clearTimer,
    advanceTo,
    pending: () => [...timers.values()].map(timer => timer.at).sort((a, b) => a - b)
  }
}

function qualification (adapter, overrides = {}) {
  return Object.freeze({
    adapters: adapter ? Object.freeze([adapter]) : Object.freeze([]),
    status: Object.freeze({
      state: adapter ? 'qualified' : 'no-qualified-relay',
      active: true,
      qualifiedRelayCount: adapter ? 1 : 0,
      releaseBlockers: Object.freeze([]),
      leaseExpiresAtMonotonicMillis: adapter ? 10_000 : null,
      leaseExpiresEpoch: adapter ? 2 : null,
      ...overrides
    })
  })
}

const branded = new WeakSet()
const adapter = Object.freeze({ id: 'verified-a', deliver: async () => ({ ok: true }) })
const adapter2 = Object.freeze({ id: 'verified-b', deliver: async () => ({ ok: true }) })
branded.add(adapter)
branded.add(adapter2)

function testScheduler (clock, qualify, publish, overrides = {}) {
  return createPeeritRelayRequalificationScheduler({
    qualify,
    publish,
    verifyAdapter: value => branded.has(value),
    epochDeadlineMonotonicMillis: () => 8_000,
    monotonicMillis: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    refreshLeadMillis: 1_000,
    maximumRefreshIntervalMillis: 3_000,
    minimumRetryMillis: 1_000,
    maximumRetryMillis: 4_000,
    ...overrides
  })
}

{
  const clock = fakeClock()
  const publications = []
  const results = [qualification(adapter), qualification(adapter2, {
    leaseExpiresAtMonotonicMillis: 15_000,
    leaseExpiresEpoch: 3
  })]
  const scheduler = createPeeritRelayRequalificationScheduler({
    qualify: async () => results.shift(),
    publish: (adapters, status) => publications.push({ adapters, status }),
    verifyAdapter: value => branded.has(value),
    epochDeadlineMonotonicMillis: epoch => epoch === 2 ? 8_000 : 14_000,
    monotonicMillis: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    refreshLeadMillis: 1_000,
    maximumRefreshIntervalMillis: 3_000,
    minimumRetryMillis: 1_000,
    maximumRetryMillis: 4_000
  })
  const first = await scheduler.start()
  assert.equal(first.state, 'qualified')
  assert.equal(first.leaseExpiresAtMonotonicMillis, 8_000,
    'earliest signed epoch deadline wins over the health deadline')
  assert.equal(first.nextRequalificationMonotonicMillis, 4_000,
    'periodic cap schedules an early refresh even with a longer lease')
  assert.deepEqual(publications[0].adapters, [adapter])
  assert.deepEqual(clock.pending(), [4_000, 8_000])

  await clock.advanceTo(4_000)
  assert.deepEqual(publications.at(-1).adapters, [adapter2],
    'a successful refresh atomically replaces the previous branded target')
  assert.equal(publications.at(-1).status.leaseExpiresAtMonotonicMillis, 14_000)
  assert.equal(scheduler.status().nextRequalificationMonotonicMillis, 7_000)
  scheduler.stop()
  assert.deepEqual(publications.at(-1).adapters, [])
  assert.equal(publications.at(-1).status.state, 'stopped')
  assert.deepEqual(clock.pending(), [])
}

{
  const clock = fakeClock()
  const publications = []
  const holder = { scheduler: null }
  const scheduler = testScheduler(
    clock,
    async () => { throw Object.assign(new Error('offline'), { code: 'OFFLINE' }) },
    (adapters, status) => {
      publications.push({ adapters, status })
      if (status.state === 'requalification-error-no-fresh-relay') holder.scheduler.stop()
    }
  )
  holder.scheduler = scheduler
  await assert.rejects(scheduler.start(), error =>
    error && error.code === 'PEERIT_REQUALIFICATION_STALE_COMPLETION')
  assert.equal(scheduler.status().state, 'stopped')
  assert.deepEqual(clock.pending(), [],
    're-entrant stop during failure publication cannot leave retry timers behind')
}

{
  const clock = fakeClock()
  const publications = []
  const hanging = deferred()
  let calls = 0
  const scheduler = createPeeritRelayRequalificationScheduler({
    qualify: async () => {
      calls++
      if (calls === 1) {
        return qualification(adapter, {
          leaseExpiresAtMonotonicMillis: 9_000,
          leaseExpiresEpoch: 2
        })
      }
      if (calls === 2) throw Object.assign(new Error('temporary failure'), { code: 'TEMPORARY' })
      return hanging.promise
    },
    publish: (adapters, status) => publications.push({ adapters, status }),
    verifyAdapter: value => branded.has(value),
    epochDeadlineMonotonicMillis: () => 8_000,
    monotonicMillis: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    refreshLeadMillis: 1_000,
    maximumRefreshIntervalMillis: 6_000,
    minimumRetryMillis: 1_000,
    maximumRetryMillis: 4_000
  })
  await scheduler.start()
  await scheduler.refresh('forced-failure')
  assert.equal(publications.at(-1).status.state,
    'requalification-error-retaining-fresh-relays')
  assert.deepEqual(publications.at(-1).adapters, [adapter],
    'transient refresh failure retains a still-authorized adapter')
  await clock.advanceTo(3_000)
  assert.equal(calls, 3, 'bounded retry begins while the old lease remains fresh')
  await clock.advanceTo(8_000)
  assert.deepEqual(publications.at(-1).adapters, [],
    'an in-flight refresh cannot extend the old target beyond authority expiry')
  assert.equal(publications.at(-1).status.state, 'qualification-expired')
  assert.equal('requalificationError' in publications.at(-1).status, false,
    'expiry status is rebuilt from authenticated qualification data, not stale retry diagnostics')
  scheduler.stop()
  hanging.resolve(qualification(adapter2))
}

{
  const clock = fakeClock()
  const publications = []
  const pending = deferred()
  let observedSignal = null
  const scheduler = createPeeritRelayRequalificationScheduler({
    qualify: async ({ signal }) => {
      observedSignal = signal
      return pending.promise
    },
    publish: (adapters, status) => publications.push({ adapters, status }),
    verifyAdapter: value => branded.has(value),
    epochDeadlineMonotonicMillis: () => 8_000,
    monotonicMillis: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    refreshLeadMillis: 1_000,
    maximumRefreshIntervalMillis: 3_000,
    minimumRetryMillis: 1_000,
    maximumRetryMillis: 4_000
  })
  const starting = scheduler.start()
  scheduler.stop()
  assert.equal(observedSignal.aborted, true, 'stop aborts the active qualification signal')
  pending.resolve(qualification(adapter))
  await assert.rejects(starting, error => [
    'PEERIT_REQUALIFICATION_STOPPED',
    'PEERIT_REQUALIFICATION_STALE_COMPLETION'
  ].includes(error.code))
  assert.equal(scheduler.status().state, 'stopped')
  assert.deepEqual(publications.flatMap(entry => entry.adapters), [],
    'a completion after stop never reinstalls a relay')
}

{
  const clock = fakeClock()
  const publications = []
  const scheduler = createPeeritRelayRequalificationScheduler({
    qualify: async () => qualification(Object.freeze({ id: 'shape-only' })),
    publish: (adapters, status) => publications.push({ adapters, status }),
    verifyAdapter: value => branded.has(value),
    epochDeadlineMonotonicMillis: () => 8_000,
    monotonicMillis: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    refreshLeadMillis: 1_000,
    maximumRefreshIntervalMillis: 3_000,
    minimumRetryMillis: 1_000,
    maximumRetryMillis: 4_000
  })
  const status = await scheduler.start()
  assert.equal(status.state, 'requalification-error-no-fresh-relay')
  assert.equal(status.requalificationError, 'PEERIT_REQUALIFICATION_UNVERIFIED_ADAPTER')
  assert.deepEqual(publications[0].adapters, [])
  scheduler.stop()
}

{
  const clock = fakeClock()
  const publications = []
  let clockReads = 0
  const scheduler = testScheduler(
    clock,
    async () => qualification(adapter),
    (adapters, status) => publications.push({ adapters, status }),
    { monotonicMillis: () => ++clockReads === 1 ? 1_000 : 8_000 }
  )
  const status = await scheduler.start()
  assert.equal(status.requalificationError, 'PEERIT_REQUALIFICATION_RESULT_EXPIRED')
  assert.deepEqual(publications[0].adapters, [],
    'time advancing to the exact boundary during verification cannot install an expired result')
  scheduler.stop()
}

{
  const clock = fakeClock()
  const publications = []
  let epochDeadlineCalls = 0
  const scheduler = testScheduler(
    clock,
    async () => qualification(null),
    (adapters, status) => publications.push({ adapters, status }),
    { epochDeadlineMonotonicMillis: () => { epochDeadlineCalls++; return 8_000 } }
  )
  const status = await scheduler.start()
  assert.equal(status.state, 'no-qualified-relay')
  assert.deepEqual(publications[0].adapters, [])
  assert.equal(epochDeadlineCalls, 0, 'an empty result cannot manufacture a signed lease deadline')
  assert.deepEqual(clock.pending(), [4_000], 'zero relays use one bounded periodic refresh without an expiry timer')
  scheduler.stop()
}

{
  const clock = fakeClock()
  const publications = []
  const scheduler = testScheduler(
    clock,
    async () => qualification(adapter),
    (adapters, status) => publications.push({ adapters, status })
  )
  await scheduler.start()
  clock.setNow(900)
  const status = await scheduler.refresh('clock-rollback')
  assert.equal(status.state, 'qualification-clock-invalid')
  assert.equal(status.active, false)
  assert.equal(scheduler.running, false)
  assert.deepEqual(publications.at(-1).adapters, [], 'clock rollback revokes every installed target')
  assert.deepEqual(clock.pending(), [])
}

{
  const clock = fakeClock()
  const publications = []
  const scheduler = testScheduler(
    clock,
    async () => qualification(adapter),
    (adapters, status) => {
      if (adapters.length > 0) throw new Error('target sink failed after installation attempt')
      publications.push({ adapters, status })
    }
  )
  const status = await scheduler.start()
  assert.equal(status.state, 'relay-publication-failed')
  assert.equal(scheduler.running, false)
  assert.equal(publications.at(-1).adapters.length, 0,
    'a throwing target sink receives a best-effort fail-closed clear')
  assert.deepEqual(clock.pending(), [])
}

{
  const clock = fakeClock()
  const publications = []
  const scheduler = testScheduler(
    clock,
    async () => qualification(adapter),
    (adapters, status) => publications.push({ adapters, status }),
    { setTimer: () => { throw new Error('timer unavailable') } }
  )
  const status = await scheduler.start()
  assert.equal(status.state, 'qualification-timer-failed')
  assert.equal(scheduler.running, false)
  assert.deepEqual(publications.at(-1).adapters, [],
    'failure to arm exact expiry clears a target that was just published')
}

{
  const clock = fakeClock()
  const publications = []
  const holder = { scheduler: null }
  const scheduler = testScheduler(
    clock,
    async () => qualification(adapter),
    (adapters, status) => {
      publications.push({ adapters, status })
      if (status.state === 'qualified') holder.scheduler.stop()
    }
  )
  holder.scheduler = scheduler
  await assert.rejects(scheduler.start(), error =>
    error && error.code === 'PEERIT_REQUALIFICATION_STALE_COMPLETION')
  assert.equal(scheduler.status().state, 'stopped',
    're-entrant stop cannot be overwritten by the older qualified publication')
  assert.deepEqual(publications.at(-1).adapters, [])
  assert.deepEqual(clock.pending(), [])
}

{
  const clock = fakeClock()
  const publications = []
  const firstResult = deferred()
  const secondResult = deferred()
  let calls = 0
  const scheduler = testScheduler(
    clock,
    async () => (++calls === 1 ? firstResult.promise : secondResult.promise),
    (adapters, status) => publications.push({ adapters, status })
  )
  const firstStart = scheduler.start()
  scheduler.stop()
  const secondStart = scheduler.start()
  secondResult.resolve(qualification(adapter2))
  await secondStart
  firstResult.resolve(qualification(adapter))
  await assert.rejects(firstStart, error => error &&
    ['PEERIT_REQUALIFICATION_STOPPED', 'PEERIT_REQUALIFICATION_STALE_COMPLETION'].includes(error.code))
  assert.deepEqual(publications.at(-1).adapters, [adapter2],
    'a completion from before stop/restart cannot overwrite the new generation')
  scheduler.stop()
}

{
  const clock = fakeClock()
  const pending = deferred()
  let calls = 0
  let publications = 0
  const scheduler = testScheduler(
    clock,
    async () => { calls++; return pending.promise },
    () => { publications++ }
  )
  const first = scheduler.start()
  const second = scheduler.start()
  assert.equal(calls, 1, 'multiple starts share one in-flight qualification')
  pending.resolve(qualification(adapter))
  await Promise.all([first, second])
  assert.equal(publications, 1)
  scheduler.stop()
}

{
  const clock = fakeClock()
  const publications = []
  const oldResult = deferred()
  const oldScheduler = testScheduler(
    clock,
    async () => oldResult.promise,
    (adapters, status) => publications.push({ owner: 'old', adapters, status })
  )
  const oldStart = oldScheduler.start()
  oldScheduler.stop()
  const newScheduler = testScheduler(
    clock,
    async () => qualification(adapter2),
    (adapters, status) => publications.push({ owner: 'new', adapters, status })
  )
  await newScheduler.start()
  oldResult.resolve(qualification(adapter))
  await assert.rejects(oldStart)
  assert.deepEqual(publications.at(-1).adapters, [adapter2],
    'a stopped old scheduler cannot republish after a replacement scheduler wins')
  newScheduler.stop()
}

{
  const clock = fakeClock()
  const publications = []
  let calls = 0
  const scheduler = testScheduler(
    clock,
    async () => {
      calls++
      if (calls === 1) {
        return qualification(adapter, {
          leaseExpiresAtMonotonicMillis: 2_000,
          leaseExpiresEpoch: 2
        })
      }
      return new Promise(() => {})
    },
    (adapters, status) => publications.push({ adapters, status }),
    { epochDeadlineMonotonicMillis: () => 1_500 }
  )
  const status = await scheduler.start()
  assert.equal(status.nextRequalificationMonotonicMillis, 1_500,
    'near-expiry success waits for the authority boundary instead of a zero-delay loop')
  assert.deepEqual(clock.pending(), [1_500, 1_500])
  await clock.advanceTo(1_500)
  assert.equal(calls, 2)
  assert.equal(publications.some(entry => entry.status.state === 'qualification-expired'), true)
  scheduler.stop()
}

{
  const clock = fakeClock()
  let calls = 0
  const scheduler = testScheduler(
    clock,
    async () => {
      calls++
      throw Object.assign(new Error('offline'), { code: 'OFFLINE' })
    },
    () => {}
  )
  await scheduler.start()
  assert.deepEqual(clock.pending(), [2_000])
  await clock.advanceTo(2_000)
  assert.deepEqual(clock.pending(), [4_000])
  await clock.advanceTo(4_000)
  assert.deepEqual(clock.pending(), [8_000])
  assert.equal(calls, 3, 'retry backoff performs one attempt at each bounded deadline')
  scheduler.stop()
}

{
  const clock = fakeClock()
  const hostile = new Error('hostile error shape')
  Object.defineProperty(hostile, 'code', {
    enumerable: true,
    get () { throw new Error('error code getter must not run') }
  })
  const scheduler = testScheduler(
    clock,
    async () => { throw hostile },
    () => {}
  )
  const status = await scheduler.start()
  assert.equal(status.requalificationError, 'PEERIT_REQUALIFICATION_FAILED',
    'hostile error accessors cannot break revocation and retry handling')
  scheduler.stop()
}

{
  const clock = fakeClock()
  const publications = []
  const scheduler = testScheduler(
    clock,
    async () => qualification(adapter, {
      leaseExpiresAtMonotonicMillis: 1_000,
      leaseExpiresEpoch: 2
    }),
    (adapters, status) => publications.push({ adapters, status })
  )
  const status = await scheduler.start()
  assert.equal(status.state, 'requalification-error-no-fresh-relay')
  assert.equal(status.requalificationError, 'PEERIT_REQUALIFICATION_RESULT_EXPIRED')
  assert.deepEqual(publications[0].adapters, [],
    'a lease expiring exactly at installation time is already invalid')
  scheduler.stop()
}

{
  const clock = fakeClock()
  const publications = []
  const scheduler = testScheduler(
    clock,
    async () => qualification(adapter),
    (adapters, status) => publications.push({ adapters, status }),
    { epochDeadlineMonotonicMillis: () => Number.NaN }
  )
  const status = await scheduler.start()
  assert.equal(status.state, 'qualification-clock-invalid')
  assert.equal(scheduler.running, false)
  assert.deepEqual(publications.at(-1).adapters, [],
    'an invalid signed-epoch deadline fails closed without retrying on an untrusted clock')
}

{
  const malformedResults = []

  const accessorResult = { adapters: Object.freeze([adapter]) }
  Object.defineProperty(accessorResult, 'status', {
    enumerable: true,
    get () { throw new Error('status getter must not run') }
  })
  malformedResults.push(accessorResult)
  malformedResults.push(qualification(adapter, { releaseReady: true }))
  malformedResults.push(qualification(adapter, { qualifiedRelayCount: 0 }))

  const symbolStatus = { ...qualification(adapter).status }
  symbolStatus[Symbol('spoof')] = true
  malformedResults.push(Object.freeze({
    adapters: Object.freeze([adapter]),
    status: Object.freeze(symbolStatus)
  }))

  const inheritedResult = Object.create({ injected: true })
  inheritedResult.adapters = Object.freeze([adapter])
  inheritedResult.status = qualification(adapter).status
  malformedResults.push(inheritedResult)

  const sparseAdapters = []
  sparseAdapters.length = 1
  malformedResults.push(Object.freeze({
    adapters: sparseAdapters,
    status: qualification(adapter).status
  }))
  malformedResults.push(Object.freeze({
    adapters: Object.freeze([adapter, adapter]),
    status: qualification(adapter, { qualifiedRelayCount: 2 }).status
  }))
  malformedResults.push(qualification(adapter, {
    releaseBlockers: Object.freeze(['SPOOFED_READY'])
  }))

  for (const result of malformedResults) {
    const clock = fakeClock()
    const publications = []
    const scheduler = testScheduler(
      clock,
      async () => result,
      (adapters, status) => publications.push({ adapters, status })
    )
    const status = await scheduler.start()
    assert.equal(status.state, 'requalification-error-no-fresh-relay')
    assert.equal(status.requalificationError, 'PEERIT_REQUALIFICATION_BAD_RESULT')
    assert.deepEqual(publications[0].adapters, [],
      'malformed or spoofed qualifier data never reaches the target sink')
    scheduler.stop()
  }
}

assert.equal(PEERIT_RELAY_REQUALIFICATION_STATUS.releaseReady, true)
console.log('peerit-relay-requalification-scheduler: atomic refresh, expiry, retry, and stale completion passed')
