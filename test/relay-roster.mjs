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
  fetchRelayRosterMulti,
  resolveRelayCandidates,
  rosterSigningMessage,
  selectRelay,
  verifyRelayRoster
} from '../js/relay-roster.js'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

function response (value, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(value),
    json: async () => value
  }
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

  const fallback = await resolveRelayCandidates({
    relays: ['https://static.example'],
    roster: { url: 'missing.json', key: keypair.pubHex },
    fetch: fetchRoster,
    now: Date.parse('2029-01-01T00:00:00.000Z')
  })
  ok(!fallback.rosterVerified && fallback.relays[0] === 'https://static.example',
    'invalid or unavailable roster falls back to baked static relays')

  const tokenCalls = []
  const fetchToken = async (url, opts = {}) => {
    tokenCalls.push({ url: String(url), method: opts.method || 'GET' })
    const u = new URL(String(url))
    if (u.hostname === 'down.example') return response({ error: 'down' }, 503)
    if (u.hostname === 'up.example' && u.pathname === '/api/token') return response({ token: 'token-up' })
    return response({ error: 'not found' }, 404)
  }
  const selected = await selectRelay(['https://down.example', 'https://up.example'], { fetch: fetchToken })
  ok(selected && selected.apiBase === 'https://up.example' && selected.apiToken === 'token-up',
    'token acquisition fails over to the first reachable relay')
  ok(tokenCalls.length === 2, 'failover probes relay candidates in order')

  const fetchStatus = async (url, opts = {}) => {
    const u = new URL(String(url))
    const token = opts.headers && opts.headers['X-Pear-Token']
    return response({ ready: true }, u.hostname === 'up.example' && token === 'static-token' ? 200 : 401)
  }
  const selectedWithToken = await selectRelay(['https://down.example', 'https://up.example'], { apiToken: 'static-token', fetch: fetchStatus })
  ok(selectedWithToken && selectedWithToken.apiBase === 'https://up.example' && selectedWithToken.apiToken === 'static-token',
    'pre-baked tokens are checked against each relay before selection')

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
