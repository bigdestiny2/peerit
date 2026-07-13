import assert from 'node:assert/strict'
import { bootPeeritReplacementOnly } from '../js/substrate/app-entry.js'

const attributes = new Map()
const metas = new Map([
  ['peerit-substrate', 'blind-v1'],
  ['peerit-release-key', 'ab'.repeat(32)],
  ['peerit-release-sequence', '7'],
  ['peerit-production-web-asset-manifest', '/peerit-web-assets-v1.cenc'],
  ['peerit-substrate-relays', 'https://relay-a.example,https://relay-b.example']
])
const elements = new Map()

function element (tagName = 'div') {
  return {
    tagName,
    children: [],
    attributes: new Map(),
    setAttribute (name, value) { this.attributes.set(name, String(value)) },
    appendChild (child) { this.children.push(child); return child },
    textContent: '',
    className: '',
    href: '',
    id: ''
  }
}

const body = element('body')
body.firstChild = null
body.insertBefore = function (child) {
  this.children.unshift(child)
  this.firstChild = this.children[0]
  if (child.id) elements.set(child.id, child)
  return child
}

const document = {
  baseURI: 'https://peerit.test/',
  body,
  documentElement: {
    setAttribute (name, value) { attributes.set(name, String(value)) }
  },
  querySelector (selector) {
    const name = selector.match(/^meta\[name="([^"]+)"\]$/)?.[1]
    if (name && metas.has(name)) {
      return { getAttribute: attribute => attribute === 'content' ? metas.get(name) : null }
    }
    return null
  },
  getElementById (id) { return elements.get(id) || null },
  createElement: element,
  createTextNode (text) { return { textContent: String(text) } }
}

const listeners = new Map()
let reloads = 0
const window = {
  location: { reload () { reloads++ } },
  addEventListener (name, listener) { listeners.set(name, listener) },
  removeEventListener (name, listener) {
    if (listeners.get(name) === listener) listeners.delete(name)
  }
}

const relayAssignments = []
const relayStatuses = []
const networkStatuses = []
let readyCalls = 0
let productDestroyCalls = 0
let uiDestroyCalls = 0
const product = {
  sync: {
    setRelays (relays) { relayAssignments.push(relays) },
    setRelayQualificationStatus (status) { relayStatuses.push(status) }
  },
  async ready () { readyCalls++; return this },
  setNetworkStatus (status) { networkStatuses.push(status); return status },
  destroy () { productDestroyCalls++ }
}

const originalFetch = globalThis.fetch
const fetches = []
globalThis.fetch = async input => {
  fetches.push(String(input))
  return {
    ok: false,
    status: 404,
    headers: { get: () => null },
    async arrayBuffer () { return new ArrayBuffer(0) }
  }
}

let boot
try {
  boot = await bootPeeritReplacementOnly({
    document,
    window,
    product,
    mountUi: () => ({ destroy () { uiDestroyCalls++ } })
  })
} finally {
  globalThis.fetch = originalFetch
}

assert.equal(readyCalls, 1)
assert.equal(attributes.get('data-peerit-local-authoring'), 'ready',
  'local lurker/authoring runtime becomes ready independently of relay delivery')
assert.equal(attributes.get('data-peerit-release-coherent'), 'false')
assert.equal(attributes.get('data-peerit-substrate-active'), 'false')
assert.equal(attributes.get('data-peerit-substrate-state'), 'blocked-build-authority')
assert.deepEqual(relayAssignments, [[]],
  'the official installer clears all relay targets while release authority is blocked')
assert.equal(relayStatuses.length, 1)
assert.equal(relayStatuses[0].state, 'blocked-build-authority')
assert.equal(networkStatuses.length, 1)
assert.equal(networkStatuses[0].state, 'blocked-build-authority')
assert.equal(networkStatuses[0].active, false)
assert.ok(networkStatuses[0].releaseBlockers.includes('SIGNED_RELEASE_COHERENCE_REQUIRED'))
assert.deepEqual(fetches, ['/peerit-web-assets-v1.cenc', '/peerit-app-artifact-v1.json'])
assert.equal(window.__peeritBlindSubstrateStatus.network, networkStatuses[0])
assert.equal(elements.get('release-manifest-warning').attributes.get('role'), 'alert')

listeners.get('pagehide')({ persisted: true })
assert.equal(productDestroyCalls, 1,
  'persisted pagehide tears down local and relay state before BFCache suspension')
assert.equal(uiDestroyCalls, 1)
assert.equal(listeners.has('pageshow'), true,
  'persisted pagehide preserves the one handler that reloads stale BFCache state')
listeners.get('pageshow')({ persisted: true })
assert.equal(reloads, 1, 'BFCache restore forces fresh authority and qualification clocks')
boot.destroy()
assert.equal(productDestroyCalls, 1)
assert.equal(uiDestroyCalls, 1)

let resolveReady
const pendingReady = new Promise(resolve => { resolveReady = resolve })
const raceListeners = new Map()
const raceWindow = {
  location: { reload () {} },
  addEventListener (name, listener) { raceListeners.set(name, listener) },
  removeEventListener (name, listener) {
    if (raceListeners.get(name) === listener) raceListeners.delete(name)
  }
}
let raceMounted = false
let raceDestroyed = 0
const raceRelayAssignments = []
const raceProduct = {
  sync: { setRelays: relays => raceRelayAssignments.push(relays) },
  ready: () => pendingReady,
  setNetworkStatus () { throw new Error('destroyed boot must not publish network state') },
  destroy () { raceDestroyed++ }
}
const racingBoot = bootPeeritReplacementOnly({
  document,
  window: raceWindow,
  product: raceProduct,
  mountUi: () => { raceMounted = true; return { destroy () {} } }
})
raceListeners.get('pagehide')({ persisted: false })
resolveReady(raceProduct)
await assert.rejects(racingBoot, error => error.code === 'PEERIT_ENTRY_LIFECYCLE_ENDED')
assert.equal(raceMounted, false,
  'an async ready continuation cannot mount UI after page teardown')
assert.deepEqual(raceRelayAssignments, [],
  'an async boot continuation cannot install relays after page teardown')
assert.equal(raceDestroyed, 1)

console.log('peerit-app-entry-composition: local product is ready with zero unverified relays, BFCache reload survives teardown, and stale async boot cannot revive')
