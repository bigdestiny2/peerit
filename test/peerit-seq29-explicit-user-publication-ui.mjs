import assert from 'node:assert/strict'
import { createIdentityStore, memoryKv } from '../js/identity-store.js'
import { createPeeritLocalIdentityV1 } from '../js/substrate/local-identity.js'
import {
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import { createPeeritProductRuntimeV1 } from '../js/substrate/peerit-product-runtime.js'
import { mountPeeritProductUiV1 } from '../js/substrate/peerit-product-ui.js'
import { createPeeritSubstrateSync } from '../js/substrate/peerit-substrate-sync.js'

const PENDING_KEY = 'peerit.seq29.pending-explicit-publication.v1'

function storage () {
  const values = new Map()
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
  }
}

function product (durableStorage) {
  return createPeeritProductRuntimeV1({
    identity: createPeeritLocalIdentityV1(),
    identityStore: createIdentityStore({ kv: memoryKv() }),
    sync: createPeeritSubstrateSync({
      journal: createMemoryPeeritJournal({ shared: createMemoryJournalState() }),
      relays: [],
      autoFlush: false,
      requireVerifiedRelayAdapters: true,
      channelName: `seq29-explicit-ui-${Math.random()}`
    }),
    storage: durableStorage,
    minBits: {
      community: 0,
      post: 0,
      comment: 0,
      vote: 0,
      profile: 0,
      modaction: 0,
      blob: 0
    }
  })
}

function browserHarness (durableStorage) {
  const documentListeners = new Map()
  const windowListeners = new Map()
  const node = () => ({ innerHTML: '', textContent: '', hidden: false })
  const nodes = new Map([
    ['[data-status]', node()],
    ['[data-user-label]', node()],
    ['#app', node()],
    ['#sidebar', node()],
    ['[data-toast]', node()]
  ])
  const document = {
    body: node(),
    querySelector: selector => nodes.get(selector) || null,
    querySelectorAll: () => [],
    addEventListener: (name, listener) => documentListeners.set(name, listener),
    removeEventListener: (name, listener) => {
      if (documentListeners.get(name) === listener) documentListeners.delete(name)
    }
  }
  const window = {
    localStorage: durableStorage,
    location: { hash: '#/create', origin: 'https://peerit.invalid' },
    addEventListener: (name, listener) => windowListeners.set(name, listener),
    removeEventListener: (name, listener) => {
      if (windowListeners.get(name) === listener) windowListeners.delete(name)
    },
    prompt: () => null,
    confirm: () => false
  }
  return { document, window, documentListeners, windowListeners }
}

function form (kind, values) {
  return {
    dataset: { form: kind },
    values,
    reset () {},
    querySelector: () => null
  }
}

function submitEvent (targetForm, isTrusted) {
  return {
    isTrusted,
    target: { closest: selector => selector === 'form[data-form]' ? targetForm : null },
    preventDefault () {}
  }
}

function clickEvent (control, isTrusted) {
  return {
    isTrusted,
    target: { closest: selector => selector === '[data-action]' ? control : null },
    preventDefault () {}
  }
}

async function until (predicate, message) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (await predicate()) return
    await new Promise(resolve => setTimeout(resolve, 5))
  }
  assert.fail(message)
}

const OriginalFormData = globalThis.FormData
globalThis.FormData = class TestFormData {
  constructor (target) { this.values = target.values }
  get (key) { return this.values[key] == null ? null : this.values[key] }
}

const durableStorage = storage()
const runtime = product(durableStorage)
await runtime.ready()
const firstBrowser = browserHarness(durableStorage)
const calls = []
const networkMutationAttempts = []
const recordDualPublicationAttempt = intentId => {
  for (const relayId of ['dal', 'syd']) {
    networkMutationAttempts.push(Object.freeze({ operation: 'CELL.PUT', relayId, intentId }))
  }
  for (const relayId of ['dal', 'syd']) {
    networkMutationAttempts.push(Object.freeze({ operation: 'INBOX.APPEND', relayId, intentId }))
  }
}
const firstUi = mountPeeritProductUiV1(runtime, {
  document: firstBrowser.document,
  window: firstBrowser.window,
  storage: durableStorage,
  async publishAuthoredIntent (intentId) {
    calls.push(intentId)
    recordDualPublicationAttempt(intentId)
    const error = new Error('injected post-commit publication interruption')
    error.code = 'INJECTED_SEQ29_PUBLICATION_INTERRUPTION'
    throw error
  }
})

try {
  await until(() => firstBrowser.documentListeners.has('submit'),
    'the shipped UI did not install its submit action')
  assert.equal(calls.length, 0, 'mount performs no publication')
  firstBrowser.windowListeners.get('hashchange')?.()
  await new Promise(resolve => setTimeout(resolve, 20))
  assert.equal(calls.length, 0, 'navigation/render performs no publication')
  assert.deepEqual(networkMutationAttempts, [],
    'mount, timers, and navigation perform no background CELL.PUT or APPEND')

  const communityForm = form('community', {
    slug: 'explicit29',
    title: 'Explicit 29',
    description: 'one trusted action, one exact durable intent'
  })
  firstBrowser.documentListeners.get('submit')(submitEvent(communityForm, true))
  await until(() => calls.length === 1, 'trusted authored action did not reach publication')
  const intentId = calls[0]
  assert.match(intentId, /^[0-9a-f]{64}$/)
  assert.equal((await runtime.sync.journal.getIntent(intentId))?.intentId, intentId,
    'the UI handed off the exact locally durable intent')
  assert.deepEqual(networkMutationAttempts, [
    { operation: 'CELL.PUT', relayId: 'dal', intentId },
    { operation: 'CELL.PUT', relayId: 'syd', intentId },
    { operation: 'INBOX.APPEND', relayId: 'dal', intentId },
    { operation: 'INBOX.APPEND', relayId: 'syd', intentId }
  ], 'one trusted authored action reaches only the explicit dual-relay publication seam')
  await until(() => durableStorage.getItem(PENDING_KEY) === intentId,
    'interrupted publication did not leave a durable explicit-retry marker')

  firstUi.destroy()
  const secondBrowser = browserHarness(durableStorage)
  const secondUi = mountPeeritProductUiV1(runtime, {
    document: secondBrowser.document,
    window: secondBrowser.window,
    storage: durableStorage,
    async publishAuthoredIntent (retriedIntentId) {
      calls.push(retriedIntentId)
      recordDualPublicationAttempt(retriedIntentId)
      return { completed: true }
    }
  })
  try {
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(calls.length, 1, 'reload performs no automatic publication recovery')
    assert.equal(networkMutationAttempts.length, 4,
      'reload performs no automatic CELL.PUT or APPEND recovery')
    const retryControl = {
      dataset: { action: 'retry-explicit-publication', intentId },
      classList: { contains: () => false }
    }
    secondBrowser.documentListeners.get('click')(clickEvent(retryControl, false))
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(calls.length, 1, 'an untrusted synthetic retry cannot publish')
    const substitutedRetryControl = {
      dataset: { action: 'retry-explicit-publication', intentId: 'f'.repeat(64) },
      classList: { contains: () => false }
    }
    secondBrowser.documentListeners.get('click')(clickEvent(substitutedRetryControl, true))
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(calls.length, 1, 'a trusted retry cannot substitute another durable intent')
    secondBrowser.documentListeners.get('click')(clickEvent(retryControl, true))
    await until(() => calls.length === 2, 'trusted retry did not resume the exact publication')
    assert.deepEqual(calls, [intentId, intentId],
      'the initial action and explicit recovery use one exact durable intent')
    assert.deepEqual(networkMutationAttempts.slice(4), [
      { operation: 'CELL.PUT', relayId: 'dal', intentId },
      { operation: 'CELL.PUT', relayId: 'syd', intentId },
      { operation: 'INBOX.APPEND', relayId: 'dal', intentId },
      { operation: 'INBOX.APPEND', relayId: 'syd', intentId }
    ], 'only the trusted exact-intent retry re-enters the dual-relay publication seam')
    await until(() => durableStorage.getItem(PENDING_KEY) == null,
      'successful explicit recovery did not clear its retry marker')

    const summaryBefore = await runtime.sync.journal.summary()
    secondBrowser.documentListeners.get('submit')(submitEvent(form('community', {
      slug: 'synthetic29', title: 'Synthetic', description: ''
    }), false))
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(calls.length, 2, 'an untrusted synthetic event cannot publish')
    assert.equal((await runtime.sync.journal.summary()).latestIntentId, summaryBefore.latestIntentId,
      'an untrusted synthetic event cannot author a local intent through the shipped UI')

    await runtime.data.createCommunity({
      slug: 'observer29', title: 'Observer 29', description: 'render-only runtime notification'
    })
    secondBrowser.windowListeners.get('hashchange')?.()
    assert.equal(secondBrowser.windowListeners.has('online'), false,
      'the shipped UI has no connectivity-triggered publication handler')
    assert.equal(secondBrowser.windowListeners.has('pageshow'), false,
      'the shipped UI has no lifecycle-triggered publication handler')
    assert.equal(secondBrowser.documentListeners.has('visibilitychange'), false,
      'the shipped UI has no visibility-triggered publication handler')
    secondBrowser.documentListeners.get('submit')(submitEvent(form('search', { q: 'seq29' }), true))
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(calls.length, 2,
      'runtime notifications, render, navigation, connectivity, lifecycle, and trusted search stay read-only')
    assert.equal(networkMutationAttempts.length, 8,
      'no background or non-authoring path performs CELL.PUT or APPEND')
  } finally {
    secondUi.destroy()
  }
} finally {
  firstUi.destroy()
  runtime.destroy()
  globalThis.FormData = OriginalFormData
}

console.log('peerit seq29 explicit UI publication: trusted local action, durable retry, reload silence, and exact-intent recovery ok')
