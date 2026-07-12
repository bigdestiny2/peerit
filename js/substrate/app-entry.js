// Replacement-only browser entry point. Peerit's local product is assembled
// independently from authenticated relay networking: a relay qualification
// failure queues delivery but never turns a healthy device into "read-only".

import { loadPeeritBrowserRuntimeAuthorityV1 } from './browser-runtime-authority.mjs'
import { createPeeritProductRuntimeV1 } from './peerit-product-runtime.js'
import { mountPeeritProductUiV1 } from './peerit-product-ui.js'

function immutableNetworkStatus (runtime) {
  return Object.freeze({
    state: runtime && runtime.state ? runtime.state : 'blocked-authenticated-browser-runtime',
    active: runtime && runtime.active === true,
    releaseBlockers: Object.freeze([...(runtime && runtime.releaseBlockers ? runtime.releaseBlockers : [])])
  })
}

function publishNetworkStatus (status) {
  document.documentElement.setAttribute('data-peerit-substrate-state', status.state)
  document.documentElement.setAttribute('data-peerit-substrate-active', status.active ? 'true' : 'false')
  Object.defineProperty(globalThis, '__peeritBlindSubstrateStatus', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: status
  })
}

function showFatal (error) {
  const boot = document.querySelector('.boot')
  const subtitle = document.querySelector('.boot-sub')
  if (subtitle) subtitle.textContent = 'local runtime could not start safely'
  if (boot) boot.setAttribute('data-peerit-substrate-state', 'blocked-local-runtime')
  document.documentElement.setAttribute('data-peerit-local-authoring', 'blocked')
  console.error('[peerit] replacement product runtime failed:',
    (error && error.message) || 'local runtime assembly failed')
}

async function bootPeeritReplacementOnly () {
  // Authentication work may proceed beside local boot, but its completion is
  // not awaited before presenting the usable local-first product.
  const networkAssembly = loadPeeritBrowserRuntimeAuthorityV1({ document })
    .catch(error => ({
      state: 'blocked-authenticated-browser-runtime',
      active: false,
      releaseBlockers: [error && error.code ? error.code : 'BROWSER_RUNTIME_ASSEMBLY_FAILED']
    }))

  const product = createPeeritProductRuntimeV1()
  await product.ready()
  mountPeeritProductUiV1(product, { document, window })
  document.documentElement.setAttribute('data-peerit-local-authoring', 'ready')

  const networkStatus = immutableNetworkStatus(await networkAssembly)
  product.setNetworkStatus(networkStatus)
  publishNetworkStatus(networkStatus)
}

bootPeeritReplacementOnly().catch(showFatal)
