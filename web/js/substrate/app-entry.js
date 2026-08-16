// Official replacement-only Web + Hyper entry point. Local authoring and relay
// delivery are independent axes: release/authentication/qualification failures
// install zero relay targets but never turn a healthy local journal read-only.

import {
  getVerifiedPeeritBrowserRuntimeAssembly,
  loadPeeritBrowserRuntimeAuthorityV1
} from './browser-runtime-authority.mjs'
import { loadPeeritProductionPinHistoryTerminalV1 } from './pin-history-bootstrap.mjs'
import { createPeeritProductRuntimeV1 } from './peerit-product-runtime.js'
import { mountPeeritProductUiV1 } from './peerit-product-ui.js'
import {
  createPeeritSeq29PublicInboxBootCoordinatorV1
} from './public-inbox-boot-coordinator.mjs'
import {
  installPeeritBlindRelayConsumer,
  recoverPeeritSeedWithLimitedCellGetAuthorityV1,
  stopPeeritBlindRelayConsumer
} from './relay-consumer.js'
import {
  renderPeeritReleaseCoherenceStatusV1,
  verifyPeeritReleaseCoherenceV1
} from './release-coherence.js'

const PUBLIC_INBOX_POLL_INTERVAL_MILLIS = 60 * 1000

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
  const publicInbox = parts[5]
  if (publicInbox) {
    return Object.freeze({
      state: publicInbox.state,
      active: authority && authority.active === true &&
        publicInbox.active === true,
      mode: 'limited-public-inbox',
      ordinaryDelivery: consumer && consumer.active === true ? 'active' : 'local-only',
      publicInboxDelivery: publicInbox.active === true ? 'active' : 'blocked',
      explicitUserPublication: publicInbox.explicitPublicationReady === true ? 'ready' : 'blocked',
      releaseBlockers: Object.freeze(releaseBlockers)
    })
  }
  if (seedRecovery && seedRecovery.active === true) {
    return Object.freeze({
      state: seedRecovery.state,
      active: authority && authority.active === true,
      mode: 'limited-cell-get-seed-recovery',
      ordinaryDelivery: consumer && consumer.active === true ? 'active' : 'local-only',
      explicitUserPublication: 'blocked',
      releaseBlockers: Object.freeze([])
    })
  }
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
    mode: 'ordinary-relay-delivery',
    ordinaryDelivery: consumer && consumer.active === true ? 'active' : 'local-only',
    explicitUserPublication: 'blocked',
    releaseBlockers: Object.freeze(releaseBlockers)
  })
}

function publishPublicInboxStatus (status, document) {
  document.documentElement.setAttribute('data-peerit-public-inbox-state', status.state)
  document.documentElement.setAttribute(
    'data-peerit-public-inbox-active', status.active ? 'true' : 'false')
  document.documentElement.setAttribute(
    'data-peerit-explicit-publication-ready', status.explicitPublicationReady ? 'true' : 'false')
}

function createPublicInboxLifecycle (options) {
  let coordinator = null
  let timer = null
  let stopped = false
  let inFlight = null
  let status = blockedStatus(
    'starting-limited-public-inbox', 'PEERIT_PUBLIC_INBOX_STARTING')

  const update = value => {
    status = Object.freeze(value)
    publishPublicInboxStatus(status, options.document)
    return status
  }
  const poll = () => {
    if (stopped || options.signal.aborted) return Promise.reject(lifecycleEnded())
    if (inFlight) return inFlight
    inFlight = (async () => {
      try {
        if (!coordinator) coordinator = await options.createCoordinator()
        const result = await coordinator.pollAndIngest({ signal: options.signal })
        if (stopped || options.signal.aborted) throw lifecycleEnded()
        update({
          state: 'limited-public-inbox-active',
          active: true,
          explicitPublicationReady: true,
          releaseBlockers: Object.freeze([]),
          lastPoll: Object.freeze({
            completedUnixMillis: String(Date.now()),
            ingestedBatchCount: result.ingestedBatchCount,
            relayCount: result.relayResults.length
          })
        })
        return result
      } catch (error) {
        if (stopped || options.signal.aborted) throw lifecycleEnded()
        update({
          state: coordinator
            ? 'degraded-limited-public-inbox'
            : 'blocked-limited-public-inbox',
          active: false,
          explicitPublicationReady: coordinator != null,
          releaseBlockers: Object.freeze([
            (error && (error.code || error.name)) || 'PEERIT_PUBLIC_INBOX_POLL_FAILED'
          ]),
          message: (error && error.message) || 'limited public INBOX activation failed'
        })
        throw error
      } finally {
        inFlight = null
      }
    })()
    return inFlight
  }
  const schedule = () => {
    if (stopped || options.signal.aborted || timer != null) return
    timer = setTimeout(() => {
      timer = null
      poll().catch(() => {}).finally(schedule)
    }, PUBLIC_INBOX_POLL_INTERVAL_MILLIS)
  }
  const controller = Object.freeze({
    get state () { return status.state },
    get active () { return status.active },
    get releaseBlockers () { return status.releaseBlockers },
    get message () { return status.message || '' },
    get lastPoll () { return status.lastPoll || null },
    get explicitPublicationReady () { return status.explicitPublicationReady === true },
    pollNow: poll,
    start: schedule,
    destroy () {
      stopped = true
      if (timer != null) clearTimeout(timer)
      timer = null
    }
  })
  publishPublicInboxStatus(status, options.document)
  return controller
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
  let publicInbox = null
  let publicInboxPublisher = null
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
    if (publicInbox && typeof publicInbox.destroy === 'function') publicInbox.destroy()
    publicInboxPublisher = null
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
    productUi = (options.mountUi || mountPeeritProductUiV1)(product, {
      document,
      window,
      publishAuthoredIntent: async intentId => {
        assertLive()
        if (!/^[0-9a-f]{64}$/.test(String(intentId || ''))) {
          const error = new Error('The explicit user action has no exact local publication intent.')
          error.code = 'PEERIT_SEQ29_EXPLICIT_PUBLICATION_RECEIPT_REQUIRED'
          throw error
        }
        const localIntent = await product.sync.journal.getIntent(intentId)
        assertLive()
        if (!localIntent || localIntent.intentId !== intentId) {
          const error = new Error('The explicit user action is not bound to a durable local publication.')
          error.code = 'PEERIT_SEQ29_LOCAL_AUTHORED_INTENT_REQUIRED'
          throw error
        }
        if (!publicInboxPublisher) {
          const error = new Error('Authenticated Seq29 publication is not ready; retry this publication explicitly.')
          error.code = 'PEERIT_SEQ29_EXPLICIT_PUBLICATION_NOT_READY'
          throw error
        }
        return publicInboxPublisher.publishAuthoredIntent({ intentId })
      }
    })
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
        if (!authority.active) {
          throw Object.assign(new Error('seed recovery requires authenticated browser runtime authority'), {
            code: 'PEERIT_AUTHENTICATED_RELAY_RUNTIME_AUTHORITY_REQUIRED'
          })
        }
        const recovered = await recoverPeeritSeedWithLimitedCellGetAuthorityV1({
          sync: product.sync,
          releaseAuthority: authority.authority,
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
    if (release.publicInboxBootstrap) {
      if (!authority.active) {
        publicInbox = blockedStatus('blocked-limited-public-inbox',
          'PEERIT_AUTHENTICATED_RELAY_RUNTIME_AUTHORITY_REQUIRED',
          'Limited public INBOX activation requires the authenticated browser runtime.')
        publishPublicInboxStatus(publicInbox, document)
      } else {
        publicInbox = createPublicInboxLifecycle({
          document,
          signal: lifecycle.signal,
          createCoordinator: async () => {
            const coordinator = await createPeeritSeq29PublicInboxBootCoordinatorV1({
              runtimeAuthority: authority.authority,
              runtimeAppBinding: getVerifiedPeeritBrowserRuntimeAssembly(authority.authority),
              substrateSync: product.sync,
              productRuntime: product,
              signal: lifecycle.signal
            })
            assertLive()
            publicInboxPublisher = coordinator
            return coordinator
          }
        })
        await publicInbox.pollNow().catch(error => {
          if (lifecycle.signal.aborted) throw error
        })
        assertLive()
        publicInbox.start()
      }
    } else {
      publishPublicInboxStatus(Object.freeze({
        state: 'limited-public-inbox-not-required',
        active: false
      }), document)
    }
    const networkStatus = immutableNetworkStatus([
      release, pinHistory, authority, consumer, seedRecovery, publicInbox
    ])
    product.setNetworkStatus(networkStatus)
    publishNetworkStatus(networkStatus, {
      release, pinHistory, authority, consumer, seedRecovery, publicInbox
    }, document, window)

    return Object.freeze({
      product,
      productUi,
      release,
      pinHistory,
      authority,
      consumer,
      seedRecovery,
      publicInbox,
      networkStatus,
      destroy
    })
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
