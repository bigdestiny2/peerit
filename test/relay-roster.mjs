// relay-roster.mjs — signed relay roster + boot-time failover checks.
// Run: node test/relay-roster.mjs

import assert from 'node:assert'
import { genKeyPair, sign, ready as cryptoReady } from '../js/crypto.js'
import {
  normalizeRelayBase,
  normalizeRelayRosterPayload,
  parseRelayList,
  parseRosterUrls,
  readRelayRosterConfig,
  relayTopology,
  fetchRelayRosterMulti,
  resolveRelayCandidates,
  rosterSigningMessage,
  selectRelay,
  selectRelays,
  selectRelaysResilient,
  verifyRelayRoster
} from '../js/relay-roster.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }
const IDEMPOTENCY = { mode: 'bounded', latestPerOutbox: true, hotReceiptsPerOutbox: 16, tombstonesPerOutbox: 64, aggregateEntries: 1024, extraHistoryEntries: 1000 }

function response (value, status = 200, extra = {}) {
  return {
    ...extra,
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(value),
    json: async () => value
  }
}

function topology (bases) {
  const entries = bases.map((apiBase, rosterIndex) => ({ apiBase, rosterIndex, canonicalOrigin: new URL(apiBase).origin }))
  const origins = entries.map((entry) => entry.canonicalOrigin)
  return { schema: 1, verified: true, stable: true, id: 'test-signed-topology|' + bases.join('|'), size: entries.length, origins, entries, validWriterTopology: origins.length >= 2 && new Set(origins).size === origins.length }
}

async function signedRoster ({ relays, expires = '2030-01-01T00:00:00.000Z' } = {}) {
  const kp = await genKeyPair()
  const payload = normalizeRelayRosterPayload({ version: 1, expires, relays })
  const sig = await sign(kp.seedHex, rosterSigningMessage(payload))
  return {
    keypair: kp,
    roster: {
      payload,
      signature: { alg: 'Ed25519', key: kp.pubHex, sig }
    }
  }
}

async function rejects (fn, pattern, msg) {
  let err = null
  try { await fn() } catch (e) { err = e }
  ok(err && pattern.test(err.message), msg)
}

async function main () {
  await cryptoReady()
  console.log('\n— relay roster format + signature verification —')

  ok(normalizeRelayBase('same-origin') === '', 'same-origin relay normalizes to an empty apiBase')
  ok(normalizeRelayBase('https://relay.example/') === 'https://relay.example', 'relay URLs are canonicalized without a trailing slash')
  ok(parseRelayList('https://a.example, https://a.example/, http://127.0.0.1:8787, http://evil.example').length === 2,
    'relay lists dedupe and reject non-local http')

  const { keypair, roster } = await signedRoster({ relays: ['https://relay-a.example/', 'https://relay-b.example/api'] })
  const verified = await verifyRelayRoster(roster, { expectedKey: keypair.pubHex, now: Date.parse('2029-01-01T00:00:00.000Z') })
  ok(verified.relays[0] === 'https://relay-a.example' && verified.relays[1] === 'https://relay-b.example/api',
    'valid roster verifies and returns normalized relay order')
  ok(verified.topology.stable === true && verified.topology.validWriterTopology && verified.topology.entries[0].rosterIndex === 0 && verified.topology.entries[1].rosterIndex === 1,
    'verified roster preserves signed order and unique-origin topology metadata')

  const tampered = JSON.parse(JSON.stringify(roster))
  tampered.payload.relays[0] = 'https://attacker.example'
  await rejects(
    () => verifyRelayRoster(tampered, { expectedKey: keypair.pubHex, now: Date.parse('2029-01-01T00:00:00.000Z') }),
    /did not verify/,
    'tampering with a signed relay is rejected'
  )

  const expired = await signedRoster({ relays: ['https://relay.example'], expires: '2028-01-01T00:00:00.000Z' })
  await rejects(
    () => verifyRelayRoster(expired.roster, { expectedKey: expired.keypair.pubHex, now: Date.parse('2029-01-01T00:00:00.000Z') }),
    /expired/,
    'expired rosters are rejected'
  )

  const wrongKey = await genKeyPair()
  await rejects(
    () => verifyRelayRoster(roster, { expectedKey: wrongKey.pubHex, now: Date.parse('2029-01-01T00:00:00.000Z') }),
    /unexpected key/,
    'rosters must match the pinned public key'
  )

  console.log('\n— roster candidate resolution + token failover —')
  const fetchRoster = async (url) => {
    if (url === 'relay-roster.json') return response(roster)
    return response({ error: 'not found' }, 404)
  }
  const candidates = await resolveRelayCandidates({
    relays: ['https://static.example', 'https://relay-b.example/api'],
    roster: { url: 'relay-roster.json', key: keypair.pubHex },
    fetch: fetchRoster,
    now: Date.parse('2029-01-01T00:00:00.000Z')
  })
  ok(candidates.rosterVerified && candidates.relays.join(',') === 'https://relay-a.example,https://relay-b.example/api,https://static.example',
    'verified roster relays take priority, then static bootstrap relays fill in')
  ok(relayTopology(candidates.relays)?.id === candidates.topology.id,
    'candidate array carries verified topology through the unchanged app connector call')

  let capabilityTokenCalls = 0
  const capabilityFetch = async (url) => {
    const u = new URL(String(url))
    if (u.pathname.endsWith('/api/token')) { capabilityTokenCalls++; return response({ token: 'topology-token', expiresAt: Date.now() + 15 * 60_000, ttlMs: 15 * 60_000 }) }
    return response({ ready: true, atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: IDEMPOTENCY }, legacyWrites: { create: false, append: false } })
  }
  const topologySelected = await selectRelays(candidates.relays, { fetch: capabilityFetch, topology: candidates.topology })
  const topologyWriters = topologySelected.filter((relay) => relay.atomicCommit)
  ok(topologyWriters.length === 2 && topologyWriters[0].rosterIndex === 0 && topologyWriters[1].rosterIndex === 1 && topologyWriters.every((relay) => relay.ready === true && relay.rosterStable === true && relay.topologyId === candidates.topology.id),
    'relay selection preserves roster index/topology metadata for deterministic writers')
  const tokenCache = new Map()
  const firstCachedSelection = await selectRelays(candidates.relays, { fetch: capabilityFetch, topology: candidates.topology, tokenCache })
  const tokenCallsAfterFirstPass = capabilityTokenCalls
  const secondCachedSelection = await selectRelays(candidates.relays, { fetch: capabilityFetch, topology: candidates.topology, tokenCache })
  ok(firstCachedSelection.length === secondCachedSelection.length && capabilityTokenCalls === tokenCallsAfterFirstPass,
    'repeated capability probes reuse per-relay tokens until their advertised renewal window')
  const fourBases = ['https://r0.example', 'https://r1.example', 'https://r2.example', 'https://r3.example']
  const fourSelected = await selectRelaysResilient(fourBases, { fetch: capabilityFetch, topology: topology(fourBases), tries: 1 })
  ok(fourSelected.length === 4, 'resilient admission probes the full signed roster so leaders beyond the legacy three-relay read limit remain available')

  const fallback = await resolveRelayCandidates({
    relays: ['https://static.example'],
    roster: { url: 'missing.json', key: keypair.pubHex },
    fetch: fetchRoster,
    now: Date.parse('2029-01-01T00:00:00.000Z')
  })
  ok(!fallback.rosterVerified && fallback.relays[0] === 'https://static.example',
    'invalid or unavailable roster falls back to baked static relays')
  const fallbackSelected = await selectRelays(fallback.relays, { fetch: capabilityFetch, topology: fallback.topology })
  ok(fallbackSelected.length === 1 && fallbackSelected[0].ready === true && fallbackSelected[0].atomicCommit === false && fallbackSelected[0].rosterVerified === false,
    'static fallback remains readable but never becomes a writer despite exact relay capabilities')

  const tokenCalls = []
  const fetchToken = async (url, opts = {}) => {
    tokenCalls.push({ url: String(url), method: opts.method || 'GET' })
    const u = new URL(String(url))
    if (u.hostname === 'down.example') return response({ error: 'down' }, 503)
    if (u.hostname === 'up.example' && u.pathname === '/api/token') return response({ token: 'token-up' })
    if (u.hostname === 'up.example' && u.pathname === '/api/bridge/status') {
      return response({
        ready: true,
        atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: IDEMPOTENCY },
        legacyWrites: { create: false, append: false }
      })
    }
    return response({ error: 'not found' }, 404)
  }
  const failoverBases = ['https://down.example', 'https://up.example']
  const selected = await selectRelay(failoverBases, { fetch: fetchToken, topology: topology(failoverBases) })
  ok(selected && selected.apiBase === 'https://up.example' && selected.apiToken === 'token-up' && selected.atomicCommit === true,
    'token acquisition fails over to the first reachable relay')
  ok(tokenCalls.length === 3, 'failover acquires a token then authenticates the selected relay status')

  const unsafeLegacy = await selectRelay(['https://unsafe.example'], {
    fetch: async (url) => {
      const u = new URL(String(url))
      if (u.pathname === '/api/token') return response({ token: 'unsafe-token' })
      return response({
        ready: true,
        atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: IDEMPOTENCY },
        legacyWrites: { create: true, append: true }
      })
    }
  })
  ok(unsafeLegacy && unsafeLegacy.atomicCommit === false,
    'an atomic relay with legacy writer bypasses exposed is never writer-capable')

  const notReadyBases = ['https://not-ready-a.example', 'https://not-ready-b.example']
  const notReady = await selectRelays(notReadyBases, {
    topology: topology(notReadyBases),
    fetch: async (url) => {
      const u = new URL(String(url))
      if (u.pathname === '/api/token') return response({ token: 'not-ready-token' })
      return response({ ready: false, atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: IDEMPOTENCY }, legacyWrites: { create: false, append: false } })
    }
  })
  ok(notReady.length === 2 && notReady.every((relay) => relay.atomicCommit === false),
    'exact capabilities still fail closed for writers unless status.ready is true')

  const fetchStatus = async (url, opts = {}) => {
    const u = new URL(String(url))
    const token = opts.headers && opts.headers['X-Pear-Token']
    return response({ ready: true }, u.hostname === 'up.example' && token === 'static-token' ? 200 : 401)
  }
  const selectedWithToken = await selectRelay(['https://down.example', 'https://up.example'], { apiToken: 'static-token', fetch: fetchStatus })
  ok(selectedWithToken && selectedWithToken.apiBase === 'https://up.example' && selectedWithToken.apiToken === 'static-token',
    'pre-baked tokens are checked against each relay before selection')

  console.log('\n— writer origin independence + bounded redirect handling —')
  const aliased = await signedRoster({ relays: ['https://same.example/a', 'https://same.example/b'] })
  const aliasVerified = await verifyRelayRoster(aliased.roster, { expectedKey: aliased.keypair.pubHex, now: Date.parse('2029-01-01T00:00:00.000Z') })
  ok(aliasVerified.topology.validWriterTopology === false,
    'two signed paths on one canonical origin are not an independent writer topology')
  const aliasSelected = await selectRelays(aliasVerified.relays, { topology: aliasVerified.topology, fetch: capabilityFetch })
  ok(aliasSelected.length === 1 && aliasSelected[0].atomicCommit === false,
    'path aliases collapse to one read relay and can never form a writer quorum')

  const redirected = await selectRelay(['https://redirect.example'], {
    timeoutMs: 30,
    fetch: async () => response({ token: 'redirected-token' }, 200, { redirected: true, url: 'https://backend.example/api/token' })
  })
  ok(redirected === null, 'detectable HTTP redirects are rejected during relay admission')

  const finalAlias = await selectRelay(['https://front.example'], {
    timeoutMs: 30,
    fetch: async () => response({ token: 'aliased-token' }, 200, { redirected: false, url: 'https://backend.example/api/token' })
  })
  ok(finalAlias === null, 'a response whose final origin differs from the selected relay is rejected')

  const timeoutStarted = Date.now()
  const timedOut = await selectRelay(['https://hung.example'], { timeoutMs: 25, fetch: async () => new Promise(() => {}) })
  ok(timedOut === null && Date.now() - timeoutStarted < 500,
    'relay admission remains bounded even when fetch ignores AbortSignal forever')
  const stalledBody = await selectRelay(['https://hung-body.example'], {
    timeoutMs: 25,
    fetch: async () => ({ ok: true, status: 200, json: async () => new Promise(() => {}), text: async () => new Promise(() => {}) })
  })
  ok(stalledBody === null, 'relay admission also bounds a response that stalls while decoding JSON')

  console.log('\n— multi-home roster (entry-point hardening) —')
  const NOW = Date.parse('2029-01-01T00:00:00.000Z')
  const mockDoc = (metas) => ({ querySelector: (sel) => { const m = sel.match(/name="([^"]+)"/); const name = m && m[1]; return name && (name in metas) ? { getAttribute: () => metas[name] } : null } })

  ok(parseRosterUrls('a.json, https://m.example/r.json, a.json').length === 2, 'parseRosterUrls splits a comma-list and dedupes')
  const cfg = readRelayRosterConfig(mockDoc({ 'peerit-relay-roster': 'relay-roster.json, https://mirror.example/roster.json', 'peerit-relay-roster-key': keypair.pubHex }))
  ok(cfg && cfg.urls.length === 2 && cfg.url === 'relay-roster.json', 'readRelayRosterConfig parses a comma-list meta into urls[] (url = first, back-compat)')

  const multiFetch = async (url) => (String(url) === 'https://mirror.example/roster.json' ? response(roster) : response({ error: 'blocked' }, 403))
  const viaMirror = await fetchRelayRosterMulti({ urls: ['relay-roster.json', 'https://mirror.example/roster.json'], key: keypair.pubHex, fetch: multiFetch, now: NOW })
  ok(viaMirror && viaMirror.relays.length === 2, 'fetchRelayRosterMulti fails over to a mirror when the primary URL is blocked')

  const allBlocked = await fetchRelayRosterMulti({ urls: ['a', 'b'], key: keypair.pubHex, fetch: async () => response({}, 403), now: NOW })
  ok(allBlocked === null, 'fetchRelayRosterMulti returns null when every roster URL fails')

  const evil = await signedRoster({ relays: ['https://attacker.example'] })
  const mixFetch = async (url) => (String(url) === 'bad' ? response(evil.roster) : response(roster))
  const mix = await fetchRelayRosterMulti({ urls: ['bad', 'good'], key: keypair.pubHex, fetch: mixFetch, now: NOW })
  ok(mix && mix.relays[0] === 'https://relay-a.example', 'a mirror signed by the WRONG key is skipped for the correctly-pinned-signed one')

  const multiCand = await resolveRelayCandidates({ relays: [], roster: { urls: ['relay-roster.json', 'https://mirror.example/roster.json'], key: keypair.pubHex }, fetch: multiFetch, now: NOW })
  ok(multiCand.rosterVerified && multiCand.relays.length === 2, 'resolveRelayCandidates multi-homes the roster fetch (verified via the mirror)')

  console.log(`\n✅ all ${passed} relay roster checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
