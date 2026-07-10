// Signed one-ingress network durability: the public API endpoint cannot choose
// its own witnesses, and a receipt from any unpinned key must never publish.
import assert from 'node:assert'
import { genKeyPair, ready as cryptoReady, sign } from '../js/crypto.js'
import {
  NETWORK_QUORUM_PROTOCOL,
  NETWORK_QUORUM_VERSION,
  normalizeRelayRosterPayload,
  rosterSigningMessage,
  selectRelays,
  verifyRelayRoster
} from '../js/relay-roster.js'
import { createRelayPool } from '../js/relay-pool.js'
import { BridgeGossipSync } from '../js/gossip.js'

let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }
const APP_ID = 'a'.repeat(64)
const COMMIT_ID = 'b'.repeat(64)
const HEAD = { version: 1, count: 1, root: 'c'.repeat(64) }
const IDEMPOTENCY = { mode: 'bounded', latestPerOutbox: true, hotReceiptsPerOutbox: 16, tombstonesPerOutbox: 64, aggregateEntries: 1024, extraHistoryEntries: 1000 }

function stable (value) {
  if (value === null) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}

function response (body, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body), json: async () => body }
}

async function signedReceipt (keypair) {
  const unsigned = {
    protocol: NETWORK_QUORUM_PROTOCOL,
    version: NETWORK_QUORUM_VERSION,
    appId: APP_ID,
    commitId: COMMIT_ID,
    head: HEAD,
    relayPubkey: keypair.pubHex,
    committedAt: 1000
  }
  return { ...unsigned, signature: await sign(keypair.seedHex, NETWORK_QUORUM_PROTOCOL + '|receipt|' + stable(unsigned)) }
}

async function main () {
  await cryptoReady()
  console.log('\n— single-ingress signed network durability —')
  const rosterKey = await genKeyPair()
  const operatorKey = await genKeyPair()
  const attackerKey = await genKeyPair()
  const policy = {
    protocol: NETWORK_QUORUM_PROTOCOL,
    version: NETWORK_QUORUM_VERSION,
    requiredRemoteAcks: 1,
    relays: [{ id: 'independent-operator', publicKey: operatorKey.pubHex }]
  }
  const payload = normalizeRelayRosterPayload({
    version: 1,
    expires: '2030-01-01T00:00:00.000Z',
    relays: ['https://outbox.example'],
    networkQuorum: policy
  })
  const roster = {
    payload,
    signature: { alg: 'Ed25519', key: rosterKey.pubHex, sig: await sign(rosterKey.seedHex, rosterSigningMessage(payload)) }
  }
  const verified = await verifyRelayRoster(roster, { expectedKey: rosterKey.pubHex, now: Date.parse('2029-01-01T00:00:00.000Z') })
  ok(verified.topology.validWriterTopology === false && verified.topology.networkQuorum.relays[0].publicKey === operatorKey.pubHex,
    'one public ingress remains a non-direct topology while its independent receipt key is pinned by the signed roster')

  const status = {
    ready: true,
    atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: IDEMPOTENCY },
    legacyWrites: { create: false, append: false },
    networkQuorum: { enabled: true, ...policy }
  }
  let nextReceipt = await signedReceipt(operatorKey)
  const fetch = async (url, opts = {}) => {
    const path = new URL(String(url)).pathname
    if (path === '/api/token') return response({ token: 'test-token', expiresAt: Date.now() + 900000, ttlMs: 900000 })
    if (path === '/api/bridge/status') return response(status)
    if (path === '/api/sync/commit') {
      const body = JSON.parse(opts.body)
      return response({
        ok: true,
        durable: true,
        appId: body.appId,
        commitId: body.commit.commitId,
        inviteKey: 'd'.repeat(64),
        relayVersion: 2,
        head: HEAD,
        networkDurability: { protocol: NETWORK_QUORUM_PROTOCOL, version: NETWORK_QUORUM_VERSION, requiredRemoteAcks: 1, receipts: [nextReceipt] }
      })
    }
    return response({ error: 'not found' }, 404)
  }

  const selected = await selectRelays(verified.relays, { fetch, topology: verified.topology })
  ok(selected.length === 1 && selected[0].atomicCommit === true && selected[0].networkQuorum.requiredRemoteAcks === 1,
    'the exact ingress status is admitted only because it matches the signed network policy')
  const pool = createRelayPool({ relays: selected, topology: verified.topology, fetch })
  ok(pool && pool._atomicCommit === true && pool._networkQuorum === true,
    'the browser enables publishing through the verified network quorum, not a direct two-origin pool')
  const result = await pool.sync.commit(APP_ID, { commitId: COMMIT_ID })
  ok(result.networkDurability.verified === true && result.quorum === 2,
    'a valid remote operator signature over the exact commit/head completes publication')

  nextReceipt = await signedReceipt(attackerKey)
  await assert.rejects(() => pool.sync.commit(APP_ID, { commitId: COMMIT_ID }), /valid independent durability receipts/i)
  ok(true, 'a receipt signed by a key absent from the signed roster fails closed')

  const spoofed = await selectRelays(verified.relays, {
    topology: verified.topology,
    fetch: async (url) => {
      const path = new URL(String(url)).pathname
      if (path === '/api/token') return response({ token: 'test-token' })
      return response({ ...status, networkQuorum: { enabled: true, ...policy, relays: [{ id: 'attacker', publicKey: attackerKey.pubHex }] } })
    }
  })
  ok(spoofed.length === 1 && spoofed[0].atomicCommit === false,
    'the ingress cannot replace the roster-pinned operator key in its status response')

  const singlePayload = normalizeRelayRosterPayload({
    version: 1,
    expires: '2030-01-01T00:00:00.000Z',
    relays: ['https://outbox.example'],
    singleIngressWriter: true
  })
  const singleRoster = {
    payload: singlePayload,
    signature: { alg: 'Ed25519', key: rosterKey.pubHex, sig: await sign(rosterKey.seedHex, rosterSigningMessage(singlePayload)) }
  }
  const singleVerified = await verifyRelayRoster(singleRoster, { expectedKey: rosterKey.pubHex, now: Date.parse('2029-01-01T00:00:00.000Z') })
  const singleFetch = async (url, opts = {}) => {
    const path = new URL(String(url)).pathname
    if (path === '/api/token') return response({ token: 'test-token', expiresAt: Date.now() + 900000, ttlMs: 900000 })
    if (path === '/api/bridge/status') {
      return response({
        ready: true,
        atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: IDEMPOTENCY },
        legacyWrites: { create: false, append: false }
      })
    }
    if (path === '/api/sync/commit') {
      const body = JSON.parse(opts.body)
      return response({ ok: true, durable: true, appId: body.appId, commitId: body.commit.commitId, inviteKey: 'd'.repeat(64), relayVersion: 2, head: HEAD })
    }
    return response({ error: 'not found' }, 404)
  }
  const singleSelected = await selectRelays(singleVerified.relays, { fetch: singleFetch, topology: singleVerified.topology })
  const singlePool = createRelayPool({ relays: singleSelected, topology: singleVerified.topology, fetch: singleFetch })
  ok(singleSelected[0].atomicCommit === true && singlePool._singleIngressWriter === true,
    'a signed one-ingress policy enables only the durable atomic writer, never a static fallback')
  const singleResult = await singlePool.sync.commit(APP_ID, { commitId: COMMIT_ID })
  ok(singleResult.singleIngress === true && singleResult.quorum === 1 && singleResult.durable === true,
    'single-ingress launch mode requires the normal local durable atomic receipt')
  const receiptGate = Object.create(BridgeGossipSync.prototype)
  const pending = { appId: APP_ID, commit: { commitId: COMMIT_ID, head: { data: HEAD } } }
  ok(receiptGate._receiptMatchesPending(singleResult, pending) === true,
    'the normal pending-write recovery path accepts only the pool-marked durable single-ingress receipt')
  console.log(`\n✅ all ${passed} network-quorum checks passed\n`)
}

main().catch((error) => { console.error('\n❌ FAILED:', error.message, '\n', error.stack); process.exit(1) })
