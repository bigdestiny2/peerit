// Official replacement-only Web + Hyper entry point. Local authoring and relay
// delivery are independent axes: release/authentication/qualification failures
// install zero relay targets but never turn a healthy local journal read-only.

import {
  getVerifiedPeeritBrowserSeedBootstrapV1,
  loadPeeritBrowserRuntimeAuthorityV1
} from './browser-runtime-authority.mjs'
import { loadPeeritProductionPinHistoryTerminalV1 } from './pin-history-bootstrap.mjs'
import { createPeeritProductRuntimeV1 } from './peerit-product-runtime.js'
import { mountPeeritProductUiV1 } from './peerit-product-ui.js'
import {
  installPeeritBlindRelayConsumer,
  recoverPeeritSeedFromActiveRelayInstallationV1,
  stopPeeritBlindRelayConsumer
} from './relay-consumer.js'
import {
  renderPeeritReleaseCoherenceStatusV1,
  verifyPeeritReleaseCoherenceV1
} from './release-coherence.js'

function blockedStatus (state, code, message = '') {
  return Object.freeze({
    state,
    active: false,
    releaseBlockers: Object.freeze([code]),
    message
  })
}

function lifecycleEnded () {
  const error = new Error('Peerit replacement boot ended with the page lifecycle')
  error.code = 'PEERIT_ENTRY_LIFECYCLE_ENDED'
  return error
}

function immutableNetworkStatus (parts) {
  const releaseBlockers = []
  for (const part of parts) {
    for (const blocker of part && part.releaseBlockers ? part.releaseBlockers : []) {
      if (!releaseBlockers.includes(blocker)) releaseBlockers.push(blocker)
    }
  }
  const authority = parts[2]
  const consumer = parts[3]
  const seedRecovery = parts[4]
  return Object.freeze({
    state: seedRecovery && seedRecovery.active === false
      ? seedRecovery.state
      : consumer && consumer.state
      ? consumer.state
      : authority && authority.state
        ? authority.state
        : 'blocked-authenticated-browser-runtime',
    active: authority && authority.active === true &&
      consumer && consumer.active === true &&
      (!seedRecovery || seedRecovery.active === true),
    releaseBlockers: Object.freeze(releaseBlockers)
  })
}

function publishNetworkStatus (status, detail, document, window) {
  document.documentElement.setAttribute('data-peerit-substrate-state', status.state)
  document.documentElement.setAttribute('data-peerit-substrate-active', status.active ? 'true' : 'false')
  Object.defineProperty(window, '__peeritBlindSubstrateStatus', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({ ...detail, network: status })
  })
}

function showFatal (error, document) {
  const boot = document && document.querySelector && document.querySelector('.boot')
  const subtitle = document && document.querySelector && document.querySelector('.boot-sub')
  if (subtitle) subtitle.textContent = 'local runtime could not start safely'
  if (boot) boot.setAttribute('data-peerit-substrate-state', 'blocked-local-runtime')
  if (document && document.documentElement) {
    document.documentElement.setAttribute('data-peerit-local-authoring', 'blocked')
  }
  console.error('[peerit] replacement product runtime failed:',
    (error && error.message) || 'local runtime assembly failed')
}

export async function bootPeeritReplacementOnly (options = {}) {
  const document = options.document || globalThis.document
  const window = options.window || globalThis.window
  if (!document || !window) throw new Error('Peerit replacement entry requires a browser document and window')

  const product = options.product || createPeeritProductRuntimeV1()
  let productUi = null
  let destroyed = false
  const lifecycle = new AbortController()
  const assertLive = () => {
    if (destroyed || lifecycle.signal.aborted) throw lifecycleEnded()
  }
  const pageshow = event => {
    if (event.persisted && window.location && typeof window.location.reload === 'function') {
      window.location.reload()
    }
  }
  const destroy = ({ preservePageshow = false } = {}) => {
    if (destroyed) return
    destroyed = true
    if (!lifecycle.signal.aborted) lifecycle.abort(lifecycleEnded())
    if (!preservePageshow) window.removeEventListener('pageshow', pageshow)
    stopPeeritBlindRelayConsumer(product.sync)
    if (productUi && typeof productUi.destroy === 'function') productUi.destroy()
    product.destroy()
  }
  const pagehide = event => destroy({ preservePageshow: event && event.persisted === true })
  // Arm invalidation before any asynchronous authority or relay work. A BFCache
  // restore gets a fresh qualification clock rather than reviving leased state.
  window.addEventListener('pagehide', pagehide, { once: true })
  window.addEventListener('pageshow', pageshow)

  try {
    await product.ready()
    assertLive()
    productUi = (options.mountUi || mountPeeritProductUiV1)(product, { document, window })
    document.documentElement.setAttribute('data-peerit-local-authoring', 'ready')

    const release = await verifyPeeritReleaseCoherenceV1({ document, signal: lifecycle.signal })
    assertLive()
    renderPeeritReleaseCoherenceStatusV1(release, { document })
    document.documentElement.setAttribute('data-peerit-release-coherent', release.active ? 'true' : 'false')

    const pinHistory = release.active
      ? await loadPeeritProductionPinHistoryTerminalV1({ document, signal: lifecycle.signal })
      : blockedStatus('blocked-production-pin-history', 'SIGNED_RELEASE_COHERENCE_REQUIRED',
        'Pin history is ignored until the static release is coherent.')
    assertLive()
    const authority = release.active && pinHistory.active
      ? await loadPeeritBrowserRuntimeAuthorityV1({
          document,
          pinHistoryTerminal: pinHistory.terminal,
          signal: lifecycle.signal
        })
      : blockedStatus('blocked-authenticated-browser-runtime',
        pinHistory.releaseBlockers[0] || 'PRODUCTION_PEERIT_SIGNED_PROFILE_PIN_UNAVAILABLE',
        pinHistory.message)
    assertLive()

    // Always cross the one official installer seam. Incomplete profile/release
    // authority clears relay targets synchronously and performs no relay fetch.
    let consumer
    try {
      consumer = await installPeeritBlindRelayConsumer({
        sync: product.sync,
        runtime: {
          mode: 'web-substrate',
          relayHints: release.active ? [...release.relayHints] : []
        },
        releaseAuthority: authority.active ? authority.authority : null,
        signal: lifecycle.signal
      })
    } finally {
      // An installer that settles after pagehide must not survive the teardown
      // just because destroy() was already called before it installed ownership.
      if (destroyed || lifecycle.signal.aborted) stopPeeritBlindRelayConsumer(product.sync)
    }
    assertLive()
    let seedRecovery = null
    if (release.seedBootstrap) {
      try {
        if (!authority.active || !consumer.active || consumer.qualifiedRelayCount !== 2) {
          throw Object.assign(new Error('seed recovery requires the authenticated exact two-relay runtime'), {
            code: 'PEERIT_SEED_RECOVERY_TWO_QUALIFIED_RELAYS_REQUIRED'
          })
        }
        const seed = getVerifiedPeeritBrowserSeedBootstrapV1(authority.authority)
        const recovered = await recoverPeeritSeedFromActiveRelayInstallationV1({
          sync: product.sync,
          artifactBytes: seed.artifactBytes,
          verification: seed.verification,
          signal: lifecycle.signal
        })
        seedRecovery = Object.freeze({
          ...recovered,
          state: recovered.cached ? 'seed-recovery-cached' : 'seed-recovery-complete',
          active: true,
          releaseBlockers: Object.freeze([])
        })
      } catch (error) {
        seedRecovery = blockedStatus('blocked-seed-recovery',
          (error && (error.code || error.name)) || 'PEERIT_SEED_RECOVERY_FAILED',
          (error && error.message) || 'signed Peerit seed recovery failed')
      }
      assertLive()
    }
    const networkStatus = immutableNetworkStatus([release, pinHistory, authority, consumer, seedRecovery])
    product.setNetworkStatus(networkStatus)
    publishNetworkStatus(networkStatus, { release, pinHistory, authority, consumer, seedRecovery }, document, window)

    return Object.freeze({ product, productUi, release, pinHistory, authority, consumer, seedRecovery, networkStatus, destroy })
  } catch (error) {
    if (!destroyed) destroy()
    throw error
  }
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  bootPeeritReplacementOnly().catch(error => {
    if (!error || error.code !== 'PEERIT_ENTRY_LIFECYCLE_ENDED') showFatal(error, document)
  })
}
