// A pear-shaped facade over the relay pool that exists BEFORE any relay is
// selected. Every call fails fast until the real pool is plugged in; the gossip
// layer already tolerates that everywhere (offline-deferred outbox, try/caught
// joins, poll retries), so the app renders the cached view instantly while
// selection happens in the background.
//
// The shape is load-bearing: createSync() (js/sync.js) routes on the pear-api.js
// surface predicates, and a bridge that has SOME surfaces but not the full gossip
// set throws rather than silently falling back to local dev sync. So this facade
// MUST satisfy hasGossipPearSurface() — sync + identity + swarm.v1 — or web boot
// wedges for every visitor (regression fixed in 14d8ace; guarded by
// test/lazy-pool-surface.mjs). Kept in its own Node-importable module (no browser
// globals) precisely so that test can exercise the real factory.
export function createLazyPearPool () {
  let target = null
  let writerEnabled = false
  let writerExpiresAt = 0
  const notUp = () => new Error('relay not connected yet')
  const writerNotUp = () => new Error('atomic writer quorum is not currently available')
  // Keep the expiry check in the transport capability itself. The background
  // monitor can be waiting on a slow roster/relay request when a signed roster
  // expires; no write may remain enabled during that window.
  const writerAvailable = () => !!(
    target && writerEnabled === true && target._atomicCommit === true &&
    (!writerExpiresAt || Date.now() < writerExpiresAt)
  )
  const pear = {
    get _relayCount () { return target ? target._relayCount : 0 },
    get _atomicCommit () { return writerAvailable() },
    sync: {},
    // identity is REQUIRED for hasGossipPearSurface() (js/pear-api.js). Without it
    // createSync sees an incomplete PearBrowser-shaped bridge (sync + swarm, no
    // identity) and THROWS, wedging web boot for every visitor. The gossip layer
    // never calls pear.identity (it uses opts.identity) — these only satisfy the
    // shape check; delegate to the real pool once connected in case anything does.
    identity: {
      getPublicKey: (...a) => (target && target.identity && target.identity.getPublicKey) ? target.identity.getPublicKey(...a) : null,
      sign: (...a) => (target && target.identity && target.identity.sign) ? target.identity.sign(...a) : null
    },
    swarm: { v1: { join: async (...a) => { if (!target) throw notUp(); return target.swarm.v1.join(...a) } } }
  }
  for (const m of ['create', 'join', 'append', 'get', 'list', 'range', 'count', 'heads', 'directory', 'crossHead', 'crossRows', 'recoverRows', 'proveCommitQuorum']) {
    pear.sync[m] = async (...a) => { if (!target) throw notUp(); return target.sync[m](...a) }
  }
  // A lost/expired quorum must never fall through to append. `commit` remains on
  // the bridge surface so createSync sees a stable shape, but is independently
  // gated at call time against the currently installed exact atomic pool.
  pear.sync.commit = async (...a) => {
    if (!target) throw notUp()
    if (!writerAvailable() || !target.sync || typeof target.sync.commit !== 'function') throw writerNotUp()
    return target.sync.commit(...a)
  }

  return {
    pear,
    setTarget: (next, { enableWriter, expiresAt } = {}) => {
      const before = writerAvailable()
      target = next || null
      // Installing a readable target never implicitly grants write authority.
      // Only the signed-roster monitor passes enableWriter:true after verifying
      // topology, expiry, and the pool's exact atomic capability.
      writerEnabled = !!(target && enableWriter === true && target._atomicCommit === true)
      const deadline = Number(expiresAt)
      writerExpiresAt = writerEnabled && Number.isFinite(deadline) && deadline > 0 ? deadline : 0
      return before !== writerAvailable()
    },
    clearTarget: () => {
      const changed = !!target || writerAvailable()
      target = null
      writerEnabled = false
      writerExpiresAt = 0
      return changed
    },
    setWriterEnabled: (enabled, { expiresAt } = {}) => {
      const before = writerAvailable()
      writerEnabled = !!(enabled && target && target._atomicCommit === true)
      const deadline = Number(expiresAt)
      if (!writerEnabled) writerExpiresAt = 0
      else if (Number.isFinite(deadline) && deadline > 0) writerExpiresAt = deadline
      return before !== writerAvailable()
    },
    get connected () { return !!target },
    get writerAvailable () { return writerAvailable() }
  }
}

function stateFingerprint (state) {
  return JSON.stringify({
    relays: Array.isArray(state && state.relays) ? state.relays : [],
    writerAvailable: !!(state && state.writerAvailable),
    rosterVerified: !!(state && state.rosterVerified),
    topologyId: String((state && state.topologyId) || '')
  })
}

function defaultWait (ms, signal) {
  return new Promise((resolve) => {
    if (signal && signal.aborted) return resolve()
    const timer = setTimeout(done, Math.max(0, ms))
    function done () {
      clearTimeout(timer)
      if (signal) signal.removeEventListener('abort', done)
      resolve()
    }
    if (signal) signal.addEventListener('abort', done, { once: true })
  })
}

function rosterExpiry (candidates) {
  if (!candidates || candidates.rosterVerified !== true) return 0
  const value = candidates.roster && candidates.roster.expires
  const ms = Date.parse(String(value || ''))
  return Number.isFinite(ms) ? ms : 0
}

// Continuously refresh the signed roster and every relay's exact capabilities.
// This is dependency-injected so the browser connector and a deterministic Node
// regression test drive the same state machine. A single reachable relay is a
// useful read pool, but only a non-expired, verified topology whose constructed
// pool advertises exact atomic quorum may enable publishing.
export async function monitorRelayAvailability ({
  lazy,
  resolveCandidates,
  selectRelays,
  createPool,
  writerRequired = true,
  onStateChange,
  onError,
  wait = defaultWait,
  signal,
  now = () => Date.now(),
  refreshMs = 15000,
  retryMinMs = 2000,
  retryMaxMs = 15000
} = {}) {
  if (!lazy || typeof lazy.setTarget !== 'function' || typeof lazy.clearTarget !== 'function') throw new Error('lazy relay pool is required')
  if (typeof resolveCandidates !== 'function' || typeof selectRelays !== 'function' || typeof createPool !== 'function') throw new Error('relay monitor dependencies are required')

  let retryMs = Math.max(1, Number(retryMinMs) || 2000)
  const retryCap = Math.max(retryMs, Number(retryMaxMs) || 15000)
  const normalMs = Math.max(1, Number(refreshMs) || 15000)
  let lastFingerprint = null
  let lastState = { relays: [], writerAvailable: false, rosterVerified: false, topologyId: '', selected: [] }
  let expiryTimer = null

  const emit = async (next) => {
    const fingerprint = stateFingerprint(next)
    lastState = next
    if (fingerprint === lastFingerprint) return false
    lastFingerprint = fingerprint
    if (typeof onStateChange === 'function') await onStateChange(next)
    return true
  }

  const clearExpiryTimer = () => {
    if (expiryTimer != null) clearTimeout(expiryTimer)
    expiryTimer = null
  }

  // The lazy facade independently checks Date.now() at every commit. This timer
  // additionally updates UI/status promptly when the deadline passes, including
  // while a subsequent network probe is still in flight.
  const armExpiryTimer = (expiresAt) => {
    clearExpiryTimer()
    if (!expiresAt || !lastState.writerAvailable) return
    const delay = Math.max(0, expiresAt - Date.now())
    expiryTimer = setTimeout(() => {
      expiryTimer = null
      if (!lazy.setWriterEnabled(false)) return
      const expired = { ...lastState, writerAvailable: false, rosterVerified: false, reason: 'roster-expired' }
      emit(expired).catch(() => {})
    }, delay)
  }

  try {
    while (!(signal && signal.aborted)) {
      let sleepMs = retryMs
      try {
        const candidates = await resolveCandidates()
        const selected = await selectRelays(candidates)
        const pool = selected && selected.length ? createPool(selected, candidates) : null
        const expiresAt = rosterExpiry(candidates)
        const currentTime = Number(now())
        const topology = candidates && candidates.topology
        const exactWriter = !!(
          writerRequired && pool && pool._atomicCommit === true &&
          candidates && candidates.rosterVerified === true &&
          topology && (topology.validWriterTopology === true || pool._networkQuorum === true) &&
          expiresAt > currentTime
        )

        // Retire the prior roster deadline only after this pass has completed;
        // it must keep guarding the old target while network probes are in
        // flight, but must not race and disable the freshly verified target.
        clearExpiryTimer()
        if (pool) lazy.setTarget(pool, { enableWriter: exactWriter, expiresAt })
        else lazy.clearTarget()

        const state = {
          relays: (selected || []).map((relay) => String(relay.canonicalOrigin || relay.apiBase || '')),
          readRelayCount: selected ? selected.length : 0,
          writerAvailable: lazy.pear._atomicCommit === true,
          rosterVerified: !!(candidates && candidates.rosterVerified),
          topologyId: String((topology && topology.id) || ''),
          rosterExpiresAt: expiresAt,
          selected: selected || []
        }
        await emit(state)
        armExpiryTimer(expiresAt)

        const complete = !!(pool && (!writerRequired || state.writerAvailable))
        if (complete) {
          retryMs = Math.max(1, Number(retryMinMs) || 2000)
          sleepMs = normalMs
        } else {
          sleepMs = retryMs
          retryMs = Math.min(retryCap, retryMs * 2)
        }
        // Re-verify no later than signed-roster expiry. The lazy pool's direct
        // deadline check remains the final gate if the timer/event loop is late.
        if (state.writerAvailable && expiresAt > currentTime) sleepMs = Math.min(sleepMs, Math.max(1, expiresAt - currentTime))
      } catch (error) {
        clearExpiryTimer()
        // Unknown capability state is never writable. Preserve the last target
        // for stale-but-useful reads; the next successful pass replaces or clears
        // it based on live reachability.
        lazy.setWriterEnabled(false)
        await emit({ ...lastState, writerAvailable: false, rosterVerified: false, reason: 'probe-failed' })
        if (typeof onError === 'function') onError(error)
        sleepMs = retryMs
        retryMs = Math.min(retryCap, retryMs * 2)
      }
      if (signal && signal.aborted) break
      await wait(sleepMs, signal)
    }
  } finally {
    clearExpiryTimer()
  }
}
