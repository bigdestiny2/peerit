// relay-backend.mjs — B3: the flagged, verifiable HiveRelay-outboxlog relay
// backend for peerit's browser bridge. Covers (a) runtime parses the
// peerit-relay-backend meta into config.relayBackend (defaulting to '' when the
// meta is absent), and (b) probeRelayBackend classifies a relay's token-gated
// GET /api/bridge/status into { ok, service, ready } without ever throwing.
// Hermetic: fetch is dependency-injected, no real network. Run:
//   node --test test/relay-backend.mjs
import { test } from 'node:test'
import assert from 'node:assert'
import { readRelayConfig, resolveRuntime } from '../js/runtime.js'
import { probeRelayBackend } from '../js/pear-api.js'

// Minimal fake document whose querySelector resolves meta[name="..."] lookups,
// matching the harness used by test/runtime.mjs.
function doc (metas = {}) {
  return {
    querySelector: (sel) => {
      const m = sel.match(/meta\[name="([^"]+)"\]/)
      const name = m && m[1]
      return name && Object.prototype.hasOwnProperty.call(metas, name) ? { getAttribute: () => metas[name] } : null
    }
  }
}

// A stub fetch that returns a JSON body (via res.text()) with a given status.
function jsonFetch (body, { ok = true, status = 200 } = {}) {
  return async () => ({ ok, status, text: async () => JSON.stringify(body) })
}

test('runtime parses peerit-relay-backend meta into config.relayBackend', () => {
  const cfg = readRelayConfig(doc({ 'peerit-relay': 'https://relay.example', 'peerit-relay-backend': 'hiverelay-outbox' }))
  assert.strictEqual(cfg.relayBackend, 'hiverelay-outbox')
})

test('runtime defaults relayBackend to "" when the meta is absent', () => {
  const cfg = readRelayConfig(doc({ 'peerit-relay': 'https://relay.example' }))
  assert.strictEqual(cfg.relayBackend, '')
})

test('resolveRuntime threads relayBackend through the web opts', () => {
  const rt = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://relay.example', 'peerit-relay-backend': 'hiverelay-outbox' }) })
  assert.strictEqual(rt.mode, 'web')
  assert.strictEqual(rt.relayBackend, 'hiverelay-outbox')
})

test('resolveRuntime defaults relayBackend to "" in web mode when the meta is absent', () => {
  const rt = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://relay.example' }) })
  assert.strictEqual(rt.mode, 'web')
  assert.strictEqual(rt.relayBackend, '')
})

test('probeRelayBackend: outboxlog relay → { ok:true, service:"outboxlog", ready:true }', async () => {
  const res = await probeRelayBackend({
    apiBase: 'https://relay.example',
    apiToken: 'tok',
    fetch: jsonFetch({ ready: true, service: 'outboxlog' })
  })
  assert.deepStrictEqual(res, { ok: true, service: 'outboxlog', ready: true })
})

test('probeRelayBackend: bespoke peerit-relay (no service field) → ok:true, service:null', async () => {
  const res = await probeRelayBackend({
    apiBase: 'https://relay.example',
    apiToken: 'tok',
    fetch: jsonFetch({ ready: true })
  })
  assert.strictEqual(res.ok, true)
  assert.strictEqual(res.service, null)
  assert.strictEqual(res.ready, true)
})

test('probeRelayBackend: sends X-Pear-Token and hits /api/bridge/status', async () => {
  let seenUrl = null
  let seenHeaders = null
  await probeRelayBackend({
    apiBase: 'https://relay.example',
    apiToken: 'secret-tok',
    fetch: async (url, init) => { seenUrl = url; seenHeaders = init && init.headers; return { ok: true, status: 200, text: async () => '{"ready":true,"service":"outboxlog"}' } }
  })
  assert.strictEqual(seenUrl, 'https://relay.example/api/bridge/status')
  assert.strictEqual(seenHeaders['X-Pear-Token'], 'secret-tok')
})

test('probeRelayBackend: a throwing fetch → { ok:false, service:null, ready:false }', async () => {
  const res = await probeRelayBackend({
    apiBase: 'https://relay.example',
    apiToken: 'tok',
    fetch: async () => { throw new Error('network down') }
  })
  assert.deepStrictEqual(res, { ok: false, service: null, ready: false })
})

test('probeRelayBackend: a 500 response → { ok:false, service:null, ready:false }', async () => {
  const res = await probeRelayBackend({
    apiBase: 'https://relay.example',
    apiToken: 'tok',
    fetch: jsonFetch({ error: 'boom' }, { ok: false, status: 500 })
  })
  assert.deepStrictEqual(res, { ok: false, service: null, ready: false })
})

test('probeRelayBackend: unparseable body → { ok:false, ... } (never throws)', async () => {
  const res = await probeRelayBackend({
    apiBase: 'https://relay.example',
    apiToken: 'tok',
    fetch: async () => ({ ok: true, status: 200, text: async () => 'not json' })
  })
  assert.deepStrictEqual(res, { ok: false, service: null, ready: false })
})
