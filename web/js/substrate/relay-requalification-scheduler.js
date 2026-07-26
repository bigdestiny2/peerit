// Lease-aware lifecycle for already-authenticated Peerit relay qualification.
//
// This module grants no relay authority. Its qualifier must return adapters
// carrying the relay-consumer module's private brand, and the caller supplies
// that brand predicate. The scheduler owns only atomic replacement, bounded
// retry, exact lease expiry, and cancellation. A failed refresh may retain an
// existing adapter only until the earliest health/signed-epoch deadline that
// authenticated it; at that instant the adapter set is cleared before retry.

const MAX_TIMER_MILLIS = 0x7fffffff
const MAX_QUALIFIED_RELAYS = 128
const QUALIFICATION_STATUS_FIELDS = new Set([
  'state',
  'active',
  'candidateHintCount',
  'descriptorPinnedCandidateCount',
  'rawUrlHintCount',
  'candidateSources',
  'pinnedAttemptCount',
  'qualificationDeadlineMillis',
  'qualificationTimedOut',
  'qualificationFailureCount',
  'deduplicatedCandidateCount',
  'continuityDiversityDeduplicatedCount',
  'quarantinedIdentityCount',
  'qualifiedRelayCount',
  'releaseBlockers',
  'rawUrlAuthorizesOrdinaryOperations',
  'descriptorPinRequired',
  'descriptorSignatureRequired',
  'admissionParametersVerified',
  'qualificationLeaseMillis',
  'leaseExpiresAtMonotonicMillis',
  'leaseExpiresEpoch',
  'requalificationSchedulerReady',
  'signedQualificationEpochWindowRequired',
  'endpointBoundHealthRequired',
  'sharedContinuityTrustStoreRequired',
  'sameContinuityDeduplicationRequired',
  'descriptorForkQuarantineRequired',
  'oneRelayEnablesDelivery',
  'zeroRelayBehavior'
])

export const PEERIT_RELAY_REQUALIFICATION_STATUS = Object.freeze({
  implementation: 'js/substrate/relay-requalification-scheduler.js',
  atomicVerifiedTargetSwap: true,
  earliestAuthorityDeadlineEnforced: true,
  transientFailureRetainsOnlyFreshTargets: true,
  staleCompletionRejected: true,
  strictQualifierResultBoundary: true,
  monotonicClockRollbackRevokes: true,
  zeroDelaySuccessLoopPrevented: true,
  stopAbortsAndRevokes: true,
  releaseReady: true
})

function schedulerError (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  return error
}

function safeErrorCode (error, fallback) {
  try {
    const descriptor = error && typeof error === 'object'
      ? Object.getOwnPropertyDescriptor(error, 'code')
      : null
    const value = descriptor && Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ? descriptor.value
      : null
    return typeof value === 'string' && value.length > 0 ? value.slice(0, 128) : fallback
  } catch {
    return fallback
  }
}

function finiteMillis (value, field) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_CLOCK', `${field} must be finite non-negative milliseconds`)
  }
  return value
}

function finiteResultMillis (value, field) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field} must be finite non-negative milliseconds`)
  }
  return value
}

function boundedInteger (value, minimum, maximum, field) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} must be an integer in [${minimum}..${maximum}]`)
  }
  return value
}

function exactDataObject (value, allowedKeys, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field} must be a plain data object`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field} must have a plain prototype`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowedKeys.has(key)) {
      throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field} contains an unsupported field`)
    }
    const descriptor = descriptors[key]
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || descriptor.enumerable !== true) {
      throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field}.${key} must be an enumerable data property`)
    }
  }
  return descriptors
}

function exactDenseArray (value, maximumLength, field) {
  if (!Array.isArray(value) || value.length > maximumLength) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field} must be a bounded array`)
  }
  const keys = Reflect.ownKeys(value)
  if (keys.length !== value.length + 1 || !keys.includes('length')) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field} must be dense without extra properties`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const output = []
  for (let index = 0; index < value.length; index++) {
    const key = String(index)
    const descriptor = descriptors[key]
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || descriptor.enumerable !== true) {
      throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', `${field} must contain only data elements`)
    }
    output.push(descriptor.value)
  }
  return output
}

function qualificationStatusSnapshot (value, adapterCount) {
  const descriptors = exactDataObject(value, QUALIFICATION_STATUS_FIELDS, 'qualification status')
  const output = {}
  for (const [key, descriptor] of Object.entries(descriptors)) {
    const item = descriptor.value
    if (Array.isArray(item)) {
      const entries = exactDenseArray(item, 128, `qualification status.${key}`)
      if (entries.some(entry => typeof entry !== 'string' || entry.length > 256)) {
        throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT',
          `qualification status.${key} must contain bounded strings`)
      }
      output[key] = Object.freeze(entries.slice())
    } else if (item === null || typeof item === 'string' || typeof item === 'boolean') {
      if (typeof item === 'string' && item.length > 256) {
        throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT',
          `qualification status.${key} is too long`)
      }
      output[key] = item
    } else if (typeof item === 'number' && Number.isFinite(item) && item >= 0) {
      output[key] = item
    } else {
      throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT',
        `qualification status.${key} must contain bounded scalar data`)
    }
  }
  const expectedState = adapterCount === 0 ? 'no-qualified-relay' : 'qualified'
  if (output.state !== expectedState || output.active !== true ||
      output.qualifiedRelayCount !== adapterCount || !Array.isArray(output.releaseBlockers) ||
      output.releaseBlockers.length !== 0) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT',
      'qualification status contradicts the verified adapter result')
  }
  if (adapterCount === 0 &&
      (output.leaseExpiresAtMonotonicMillis !== null || output.leaseExpiresEpoch !== null)) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT',
      'an empty qualification result must not claim a lease')
  }
  return Object.freeze(output)
}

function exactQualificationResult (result, verifyAdapter, now, epochDeadline) {
  const descriptors = exactDataObject(
    result, new Set(['adapters', 'failures', 'status']), 'qualification result')
  if (!descriptors.adapters || !descriptors.status) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT', 'relay qualifier must return adapters and status')
  }
  const adapterValues = exactDenseArray(
    descriptors.adapters.value, MAX_QUALIFIED_RELAYS, 'qualification result.adapters')
  if (new Set(adapterValues).size !== adapterValues.length) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT',
      'relay qualifier returned duplicate adapter identities')
  }
  if (adapterValues.some(adapter => verifyAdapter(adapter) !== true)) {
    throw schedulerError('PEERIT_REQUALIFICATION_UNVERIFIED_ADAPTER',
      'relay qualifier returned an adapter without the consumer module brand')
  }
  const adapters = Object.freeze(adapterValues.slice())
  const status = qualificationStatusSnapshot(descriptors.status.value, adapters.length)
  if (adapters.length === 0) {
    return Object.freeze({ adapters, status, authorityDeadline: null })
  }
  const healthDeadline = finiteResultMillis(
    status.leaseExpiresAtMonotonicMillis,
    'qualification status leaseExpiresAtMonotonicMillis')
  const expiresEpoch = status.leaseExpiresEpoch
  if (!Number.isSafeInteger(expiresEpoch) || expiresEpoch < 1 || expiresEpoch > 0xffffffff) {
    throw schedulerError('PEERIT_REQUALIFICATION_BAD_RESULT',
      'qualified relays require an exact signed leaseExpiresEpoch')
  }
  const signedEpochDeadline = finiteMillis(
    epochDeadline(expiresEpoch),
    'signed epoch monotonic deadline')
  const authorityDeadline = Math.min(healthDeadline, signedEpochDeadline)
  if (authorityDeadline <= now) {
    throw schedulerError('PEERIT_REQUALIFICATION_RESULT_EXPIRED',
      'relay qualification expired before atomic installation')
  }
  return Object.freeze({ adapters, status, authorityDeadline })
}

export function createPeeritRelayRequalificationScheduler (options = {}) {
  if (typeof options.qualify !== 'function') throw new TypeError('qualify is required')
  if (typeof options.publish !== 'function') throw new TypeError('publish is required')
  if (typeof options.verifyAdapter !== 'function') throw new TypeError('verifyAdapter is required')
  if (typeof options.epochDeadlineMonotonicMillis !== 'function') {
    throw new TypeError('epochDeadlineMonotonicMillis is required')
  }
  if (typeof AbortController !== 'function') throw new TypeError('AbortController is required')
  const nowProvider = typeof options.monotonicMillis === 'function'
    ? options.monotonicMillis
    : () => globalThis.performance && typeof globalThis.performance.now === 'function'
        ? globalThis.performance.now()
        : Date.now()
  const setTimer = options.setTimer || globalThis.setTimeout
  const clearTimer = options.clearTimer || globalThis.clearTimeout
  if (typeof setTimer !== 'function' || typeof clearTimer !== 'function') {
    throw new TypeError('bounded timer functions are required')
  }
  const refreshLeadMillis = boundedInteger(
    options.refreshLeadMillis == null ? 60_000 : options.refreshLeadMillis,
    1, 60 * 60 * 1000, 'refreshLeadMillis')
  const maximumRefreshIntervalMillis = boundedInteger(
    options.maximumRefreshIntervalMillis == null ? 5 * 60_000 : options.maximumRefreshIntervalMillis,
    1, 60 * 60 * 1000, 'maximumRefreshIntervalMillis')
  const minimumRetryMillis = boundedInteger(
    options.minimumRetryMillis == null ? 1_000 : options.minimumRetryMillis,
    1, 60_000, 'minimumRetryMillis')
  const maximumRetryMillis = boundedInteger(
    options.maximumRetryMillis == null ? 60_000 : options.maximumRetryMillis,
    minimumRetryMillis, 60 * 60 * 1000, 'maximumRetryMillis')

  let running = false
  let generation = 0
  let timer = null
  let expiryTimer = null
  let timerToken = 0
  let expiryTimerToken = 0
  let inFlight = null
  let inFlightController = null
  let rerunRequested = false
  let retryMillis = minimumRetryMillis
  let current = null
  let lastClockMillis = null
  let lastStatus = Object.freeze({
    state: 'stopped',
    active: false,
    qualifiedRelayCount: 0,
    releaseBlockers: Object.freeze([])
  })

  const now = () => {
    const value = finiteMillis(nowProvider(), 'monotonic clock')
    if (lastClockMillis != null && value < lastClockMillis) {
      throw schedulerError('PEERIT_REQUALIFICATION_CLOCK_ROLLBACK',
        'monotonic qualification clock moved backwards')
    }
    lastClockMillis = value
    return value
  }

  function cancelTimer () {
    timerToken++
    const handle = timer
    timer = null
    if (handle != null) {
      try { clearTimer(handle) } catch {}
    }
  }

  function cancelExpiryTimer () {
    expiryTimerToken++
    const handle = expiryTimer
    expiryTimer = null
    if (handle != null) {
      try { clearTimer(handle) } catch {}
    }
  }

  function delayUntil (deadline) {
    return Math.max(0, Math.min(MAX_TIMER_MILLIS, Math.ceil(deadline - now())))
  }

  function publish (adapters, status) {
    // Set this first so a re-entrant stop from the publication callback cannot
    // be overwritten by the older publication after the callback returns.
    lastStatus = status
    try {
      options.publish(adapters, status)
    } catch (cause) {
      throw schedulerError('PEERIT_REQUALIFICATION_PUBLISH_FAILED',
        'relay target publication failed', cause)
    }
    return status
  }

  function fatalState (error) {
    const code = safeErrorCode(error, 'PEERIT_REQUALIFICATION_INTERNAL_FAILURE')
    running = false
    generation++
    rerunRequested = false
    cancelTimer()
    cancelExpiryTimer()
    if (inFlightController && !inFlightController.signal.aborted) {
      inFlightController.abort(error)
    }
    inFlightController = null
    current = null
    const state = code === 'PEERIT_REQUALIFICATION_CLOCK_ROLLBACK' ||
      code === 'PEERIT_REQUALIFICATION_BAD_CLOCK'
      ? 'qualification-clock-invalid'
      : code === 'PEERIT_REQUALIFICATION_TIMER_FAILED'
        ? 'qualification-timer-failed'
        : 'relay-publication-failed'
    const status = Object.freeze({
      state,
      active: false,
      qualifiedRelayCount: 0,
      releaseBlockers: Object.freeze([code])
    })
    try { publish([], status) } catch {}
    return status
  }

  function isFatalError (error) {
    return [
      'PEERIT_REQUALIFICATION_BAD_CLOCK',
      'PEERIT_REQUALIFICATION_CLOCK_ROLLBACK',
      'PEERIT_REQUALIFICATION_PUBLISH_FAILED',
      'PEERIT_REQUALIFICATION_TIMER_FAILED'
    ].includes(safeErrorCode(error, ''))
  }

  function assertCurrentRun (runGeneration, controller) {
    if (!running || runGeneration !== generation || controller.signal.aborted) {
      throw schedulerError('PEERIT_REQUALIFICATION_STALE_COMPLETION',
        'stale relay qualification completion was discarded')
    }
  }

  function scheduleRefreshAt (deadline, reason) {
    cancelTimer()
    const scheduledGeneration = generation
    const scheduledToken = timerToken
    try {
      timer = setTimer(() => {
        if (!running || scheduledGeneration !== generation || scheduledToken !== timerToken) return
        timer = null
        refresh(reason).catch(() => {})
      }, delayUntil(deadline))
    } catch (cause) {
      if (isFatalError(cause)) throw cause
      throw schedulerError('PEERIT_REQUALIFICATION_TIMER_FAILED',
        'relay refresh timer could not be scheduled', cause)
    }
  }

  function scheduleExpiry (deadline) {
    cancelExpiryTimer()
    const scheduledGeneration = generation
    const scheduledToken = expiryTimerToken
    try {
      expiryTimer = setTimer(() => {
        if (!running || scheduledGeneration !== generation || scheduledToken !== expiryTimerToken || !current ||
            current.authorityDeadline !== deadline) return
        expiryTimer = null
        try {
          if (now() < deadline) {
            scheduleExpiry(deadline)
            return
          }
          const baseStatus = current.status
          current = null
          const status = Object.freeze({
            ...baseStatus,
            state: 'qualification-expired',
            active: true,
            qualifiedRelayCount: 0,
            authorityExpired: true,
            leaseExpiresAtMonotonicMillis: deadline
          })
          publish([], status)
          if (!running || scheduledGeneration !== generation) return
          scheduleRefreshAt(now(), 'authority-expired')
        } catch (error) {
          fatalState(error)
        }
      }, delayUntil(deadline))
    } catch (cause) {
      if (isFatalError(cause)) throw cause
      throw schedulerError('PEERIT_REQUALIFICATION_TIMER_FAILED',
        'relay expiry timer could not be scheduled', cause)
    }
  }

  function nextSuccessfulRefresh (authorityDeadline) {
    const currentTime = now()
    if (currentTime >= authorityDeadline) {
      throw schedulerError('PEERIT_REQUALIFICATION_RESULT_EXPIRED',
        'relay qualification expired before atomic installation')
    }
    const desired = Math.min(
      authorityDeadline - refreshLeadMillis,
      currentTime + maximumRefreshIntervalMillis)
    // A signed epoch close to expiry must not create a zero-delay success loop.
    // If there is not even one minimum retry interval left, expiry performs the
    // revocation and triggers the next qualification at the exact boundary.
    return Math.min(authorityDeadline, Math.max(currentTime + minimumRetryMillis, desired))
  }

  function retainOrRevokeAfterFailure (error, runGeneration, controller) {
    const currentTime = now()
    const code = safeErrorCode(error, 'PEERIT_REQUALIFICATION_FAILED')
    if (current && currentTime < current.authorityDeadline) {
      const retryAt = Math.min(current.authorityDeadline, currentTime + retryMillis)
      const status = Object.freeze({
        ...current.status,
        state: 'requalification-error-retaining-fresh-relays',
        active: true,
        qualifiedRelayCount: current.adapters.length,
        requalificationError: code,
        nextRequalificationMonotonicMillis: retryAt,
        leaseExpiresAtMonotonicMillis: current.authorityDeadline
      })
      publish(current.adapters, status)
      assertCurrentRun(runGeneration, controller)
      scheduleRefreshAt(retryAt, 'retry')
      scheduleExpiry(current.authorityDeadline)
      return status
    }
    current = null
    cancelExpiryTimer()
    const retryAt = currentTime + retryMillis
    const status = Object.freeze({
      state: 'requalification-error-no-fresh-relay',
      active: true,
      qualifiedRelayCount: 0,
      releaseBlockers: Object.freeze([]),
      requalificationError: code,
      nextRequalificationMonotonicMillis: retryAt
    })
    publish([], status)
    assertCurrentRun(runGeneration, controller)
    scheduleRefreshAt(retryAt, 'retry')
    return status
  }

  async function run (reason) {
    if (!running) throw schedulerError('PEERIT_REQUALIFICATION_STOPPED', 'relay scheduler is stopped')
    if (inFlight) {
      rerunRequested = true
      return inFlight
    }
    const runGeneration = generation
    const controller = new AbortController()
    inFlightController = controller
    cancelTimer()
    const operation = (async () => {
      try {
        const result = await options.qualify(Object.freeze({
          signal: controller.signal,
          reason,
          generation: runGeneration
        }))
        assertCurrentRun(runGeneration, controller)
        const currentTime = now()
        const verified = exactQualificationResult(
          result, options.verifyAdapter, currentTime,
          options.epochDeadlineMonotonicMillis)
        retryMillis = minimumRetryMillis
        if (verified.adapters.length === 0) {
          current = null
          cancelExpiryTimer()
          const refreshAt = currentTime + maximumRefreshIntervalMillis
          const status = Object.freeze({
            ...verified.status,
            state: 'no-qualified-relay',
            active: true,
            qualifiedRelayCount: 0,
            nextRequalificationMonotonicMillis: refreshAt
          })
          publish([], status)
          assertCurrentRun(runGeneration, controller)
          scheduleRefreshAt(refreshAt, 'periodic-empty')
          return status
        }
        const refreshAt = nextSuccessfulRefresh(verified.authorityDeadline)
        current = Object.freeze({
          adapters: verified.adapters,
          authorityDeadline: verified.authorityDeadline,
          status: verified.status
        })
        const status = Object.freeze({
          ...verified.status,
          state: 'qualified',
          active: true,
          qualifiedRelayCount: verified.adapters.length,
          leaseExpiresAtMonotonicMillis: verified.authorityDeadline,
          nextRequalificationMonotonicMillis: refreshAt,
          requalificationScheduled: true
        })
        publish(verified.adapters, status)
        assertCurrentRun(runGeneration, controller)
        scheduleExpiry(verified.authorityDeadline)
        scheduleRefreshAt(refreshAt, 'scheduled-refresh')
        return status
      } catch (error) {
        if (!running || runGeneration !== generation || controller.signal.aborted) throw error
        if (isFatalError(error)) return fatalState(error)
        try {
          const status = retainOrRevokeAfterFailure(error, runGeneration, controller)
          retryMillis = Math.min(maximumRetryMillis, retryMillis * 2)
          return status
        } catch (failureError) {
          if (isFatalError(failureError)) return fatalState(failureError)
          throw failureError
        }
      } finally {
        if (inFlightController === controller) inFlightController = null
      }
    })()
    inFlight = operation
    try {
      return await operation
    } finally {
      if (inFlight === operation) inFlight = null
      if (running && runGeneration === generation && rerunRequested) {
        rerunRequested = false
        try {
          scheduleRefreshAt(now(), 'coalesced-refresh')
        } catch (error) {
          fatalState(error)
        }
      }
    }
  }

  async function start () {
    if (running) return inFlight || lastStatus
    running = true
    generation++
    retryMillis = minimumRetryMillis
    return run('start')
  }

  async function refresh (reason = 'manual') {
    return run(String(reason).slice(0, 64))
  }

  function stop () {
    if (!running) return lastStatus
    running = false
    generation++
    rerunRequested = false
    cancelTimer()
    cancelExpiryTimer()
    if (inFlightController) {
      inFlightController.abort(
        schedulerError('PEERIT_REQUALIFICATION_STOPPED', 'relay scheduler stopped'))
    }
    inFlightController = null
    inFlight = null
    current = null
    const status = Object.freeze({
      state: 'stopped',
      active: false,
      qualifiedRelayCount: 0,
      releaseBlockers: Object.freeze([])
    })
    try { publish([], status) } catch {}
    return status
  }

  return Object.freeze({
    start,
    refresh,
    stop,
    status () { return lastStatus },
    get running () { return running }
  })
}
