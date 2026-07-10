// Deterministic, non-network test for the writable candidate release gate.
// Run: node test/writable-candidate-preflight.mjs

import assert from 'node:assert/strict'
import {
  buildWritableCandidateProof,
  writableRateLimitPolicyFromEnv
} from '../scripts/verify-writable-candidate.mjs'
import { genKeyPair, ready as cryptoReady, sign } from '../js/crypto.js'
import { normalizeRelayRosterPayload, rosterSigningMessage } from '../js/relay-roster.js'

const RELAYS = ['https://canary-a.example', 'https://canary-b.example']
const IDEMPOTENCY = { mode: 'bounded', latestPerOutbox: true, hotReceiptsPerOutbox: 16, tombstonesPerOutbox: 64, aggregateEntries: 1024, extraHistoryEntries: 1000 }
const HTTP_RATE_LIMIT = {
  scope: 'public-writes',
  source: 'operator',
  enabled: true,
  windowMs: 60_000,
  max: 12_000,
  outboxLogEnvelope: { enabled: true, windowMs: 60_000, max: 12_000 }
}

function response (value, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(value)
  }
}

function relayFetch ({
  staleRelay = '',
  legacyOpenRelay = '',
  unsafeDescriptorRelay = '',
  unsafeIdempotencyRelay = '',
  missingCommitRelay = '',
  httpRateLimitByRelay = {}
} = {}) {
  const calls = []
  const fetch = async (input, options = {}) => {
    const url = new URL(String(input))
    calls.push({ origin: url.origin, path: url.pathname, method: options.method || 'GET' })
    if (url.pathname === '/health') return response({ ok: true })
    if (url.pathname === '/api/token') return response({ token: 'candidate-token' })
    if (url.pathname === '/api/bridge/status') {
      if (url.origin === staleRelay) return response({ ready: true })
      const httpRateLimit = Object.prototype.hasOwnProperty.call(httpRateLimitByRelay, url.origin)
        ? httpRateLimitByRelay[url.origin]
        : HTTP_RATE_LIMIT
      return response({
        ready: true,
        atomicCommit: {
          schema: 1,
          method: 'POST',
          route: '/api/sync/commit',
          enabled: true,
          durable: true,
          cas: true,
          idempotent: true,
          ...(url.origin === unsafeIdempotencyRelay ? {} : { idempotency: IDEMPOTENCY })
        },
        legacyWrites: url.origin === unsafeDescriptorRelay ? { create: true, append: true } : { create: false, append: false },
        httpRateLimit
      })
    }
    if (url.pathname === '/api/sync/capabilities') {
      return response({
        schema: 1,
        atomicCommit: {
          schema: 1,
          method: 'POST',
          route: '/api/sync/commit',
          enabled: true,
          durable: true,
          cas: true,
          idempotent: true,
          ...(url.origin === unsafeIdempotencyRelay ? {} : { idempotency: IDEMPOTENCY })
        },
        legacyWrites: url.origin === unsafeDescriptorRelay ? { create: true, append: true } : { create: false, append: false }
      })
    }
    if (url.pathname === '/api/sync/commit') {
      return response({ error: url.origin === missingCommitRelay ? 'not found' : 'bad appId' }, url.origin === missingCommitRelay ? 404 : 400)
    }
    if (url.pathname === '/api/sync/create' || url.pathname === '/api/sync/append') {
      return response({ error: url.origin === legacyOpenRelay ? 'bad request' : 'legacy writes disabled' }, url.origin === legacyOpenRelay ? 400 : 403)
    }
    return response({ error: 'not found' }, 404)
  }
  return { fetch, calls }
}

async function fixture (relays = RELAYS) {
  const keypair = await genKeyPair()
  const payload = normalizeRelayRosterPayload({
    version: 1,
    expires: '2030-01-01T00:00:00.000Z',
    relays
  })
  const roster = {
    payload,
    signature: {
      alg: 'Ed25519',
      key: keypair.pubHex,
      sig: await sign(keypair.seedHex, rosterSigningMessage(payload))
    }
  }
  const config = {
    bootstrapRelays: relays,
    readonly: false,
    relayRoster: 'relay-roster.json',
    pinnedRosterKey: keypair.pubHex,
    roster: payload
  }
  return { config, roster }
}

await cryptoReady()

const readyFixture = await fixture()
const live = relayFetch()
const ready = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: live.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(ready.status, 'ready')
assert.equal(ready.relays.filter((relay) => relay.ready).length, 2)
assert.equal(ready.syncWritesAttempted, 0)
assert.deepEqual(ready.httpRateLimitPolicy, { minRateMax: 12_000, maxRateWindowMs: 60_000 })
assert.deepEqual(ready.relays[0].httpRateLimit, HTTP_RATE_LIMIT)
assert.equal(live.calls.length, 14, 'health, token, status, capabilities, atomic-route validation, and two legacy-route guards are checked on both relays')
assert.equal(live.calls.filter((call) => call.path === '/api/sync/commit').length, 2, 'each commit route is proved with one non-mutating invalid request')

const noWritableCalls = relayFetch()
const readOnly = await buildWritableCandidateProof({
  ...readyFixture,
  config: { ...readyFixture.config, readonly: true },
  fetch: noWritableCalls.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(readOnly.status, 'blocked')
assert.match(readOnly.checks[0].message, /never auto-skip/)
assert.equal(noWritableCalls.calls.length, 0, 'read-only config fails before any candidate request')

const oneFixture = await fixture(['https://canary-a.example'])
const oneLive = relayFetch()
const one = await buildWritableCandidateProof({
  ...oneFixture,
  fetch: oneLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(one.status, 'blocked')
assert.ok(one.checks.some((check) => check.id === 'roster:failure-domains' && check.status === 'fail'))
assert.equal(oneLive.calls.length, 0, 'one-relay topology fails before live probing')

const sameOriginFixture = await fixture(['https://canary.example/a', 'https://canary.example/b'])
const sameOrigin = await buildWritableCandidateProof({
  ...sameOriginFixture,
  fetch: relayFetch().fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(sameOrigin.status, 'blocked')
assert.ok(sameOrigin.checks.some((check) => check.id === 'roster:failure-domains'))

const staleLive = relayFetch({ staleRelay: RELAYS[1] })
const stale = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: staleLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(stale.status, 'blocked')
assert.equal(stale.relays.find((relay) => relay.relay === RELAYS[1]).ready, false)
assert.ok(stale.checks.some((check) => check.status === 'fail' && /atomicCommit/.test(check.message)))

const exposedLegacy = relayFetch({ legacyOpenRelay: RELAYS[1] })
const unsafe = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: exposedLegacy.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(unsafe.status, 'blocked')
assert.equal(unsafe.relays.find((relay) => relay.relay === RELAYS[1]).ready, false)
assert.ok(unsafe.checks.some((check) => check.status === 'fail' && /publicly reachable/.test(check.message)))

const unsafeDescriptorLive = relayFetch({ unsafeDescriptorRelay: RELAYS[1] })
const unsafeDescriptor = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: unsafeDescriptorLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(unsafeDescriptor.status, 'blocked')
assert.ok(unsafeDescriptor.checks.some((check) => check.status === 'fail' && /legacyWrites/.test(check.message)))

const unsafeIdempotencyLive = relayFetch({ unsafeIdempotencyRelay: RELAYS[1] })
const unsafeIdempotency = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: unsafeIdempotencyLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(unsafeIdempotency.status, 'blocked')
assert.ok(unsafeIdempotency.checks.some((check) => check.status === 'fail' && /latestPerOutbox/.test(check.message)))

const missingCommitLive = relayFetch({ missingCommitRelay: RELAYS[1] })
const missingCommit = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: missingCommitLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(missingCommit.status, 'blocked')
assert.ok(missingCommit.checks.some((check) => check.status === 'fail' && /not safely reachable/.test(check.message)))

const missingRateLive = relayFetch({ httpRateLimitByRelay: { [RELAYS[1]]: undefined } })
const missingRate = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: missingRateLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(missingRate.status, 'blocked')
assert.ok(missingRate.checks.some((check) => check.status === 'fail' && /no valid httpRateLimit/.test(check.message)))

const coarseRateLive = relayFetch({
  httpRateLimitByRelay: {
    [RELAYS[1]]: {
      scope: 'public-writes',
      source: 'relay-api-default',
      enabled: true,
      windowMs: 60_000,
      max: 60,
      outboxLogEnvelope: { enabled: true, windowMs: 60_000, max: 1200 }
    }
  }
})
const coarseRate = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: coarseRateLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(coarseRate.status, 'blocked')
assert.ok(coarseRate.checks.some((check) => check.status === 'fail' && /source must be "operator".*coarse 60/.test(check.message)))

const disabledRateLive = relayFetch({
  httpRateLimitByRelay: {
    [RELAYS[1]]: {
      scope: 'public-writes',
      source: 'operator',
      enabled: false,
      windowMs: 60_000,
      max: null,
      outboxLogEnvelope: { enabled: false, windowMs: 60_000, max: null }
    }
  }
})
const disabledRate = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: disabledRateLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(disabledRate.status, 'blocked')
assert.ok(disabledRate.checks.some((check) => check.status === 'fail' && /httpRateLimit.enabled must be true/.test(check.message)))

const malformedRateLive = relayFetch({
  httpRateLimitByRelay: {
    [RELAYS[1]]: {
      ...HTTP_RATE_LIMIT,
      max: '12000'
    }
  }
})
const malformedRate = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: malformedRateLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(malformedRate.status, 'blocked')
assert.ok(malformedRate.checks.some((check) => check.status === 'fail' && /httpRateLimit.max must be a positive integer/.test(check.message)))

const mismatchedEnvelopeLive = relayFetch({
  httpRateLimitByRelay: {
    [RELAYS[1]]: {
      ...HTTP_RATE_LIMIT,
      outboxLogEnvelope: { enabled: true, windowMs: 60_000, max: 1200 }
    }
  }
})
const mismatchedEnvelope = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: mismatchedEnvelopeLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(mismatchedEnvelope.status, 'blocked')
assert.ok(mismatchedEnvelope.checks.some((check) => check.status === 'fail' && /must exactly match/.test(check.message)))

const excessiveWindowDescriptor = {
  ...HTTP_RATE_LIMIT,
  windowMs: 60_001,
  outboxLogEnvelope: { enabled: true, windowMs: 60_001, max: 12_000 }
}
const excessiveWindowLive = relayFetch({ httpRateLimitByRelay: { [RELAYS[1]]: excessiveWindowDescriptor } })
const excessiveWindow = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: excessiveWindowLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(excessiveWindow.status, 'blocked')
assert.ok(excessiveWindow.checks.some((check) => check.status === 'fail' && /exceeds launch maximum 60000/.test(check.message)))

const lowMaxDescriptor = {
  ...HTTP_RATE_LIMIT,
  max: 11_999,
  outboxLogEnvelope: { enabled: true, windowMs: 60_000, max: 11_999 }
}
const lowMaxLive = relayFetch({ httpRateLimitByRelay: { [RELAYS[1]]: lowMaxDescriptor } })
const lowMax = await buildWritableCandidateProof({
  ...readyFixture,
  fetch: lowMaxLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(lowMax.status, 'blocked')
assert.ok(lowMax.checks.some((check) => check.status === 'fail' && /below launch minimum 12000/.test(check.message)))

const stagedPolicy = writableRateLimitPolicyFromEnv({
  PEERIT_WRITABLE_MIN_RATE_MAX: '100',
  PEERIT_WRITABLE_MAX_RATE_WINDOW_MS: '120000'
})
assert.deepEqual(stagedPolicy, { minRateMax: 100, maxRateWindowMs: 120_000 })
assert.throws(
  () => writableRateLimitPolicyFromEnv({ PEERIT_WRITABLE_MIN_RATE_MAX: '0' }),
  /minimum public-write rate max/
)
const stagedDescriptor = {
  ...HTTP_RATE_LIMIT,
  windowMs: 120_000,
  max: 100,
  outboxLogEnvelope: { enabled: true, windowMs: 120_000, max: 100 }
}
const stagedLive = relayFetch({
  httpRateLimitByRelay: {
    [RELAYS[0]]: stagedDescriptor,
    [RELAYS[1]]: stagedDescriptor
  }
})
const staged = await buildWritableCandidateProof({
  ...readyFixture,
  ...stagedPolicy,
  fetch: stagedLive.fetch,
  now: Date.parse('2029-01-01T00:00:00.000Z')
})
assert.equal(staged.status, 'ready', 'explicit staged-gate env thresholds are honored')
assert.equal(stagedLive.calls.length, 14, 'staged policy preserves every non-mutating route probe')

console.log('writable-candidate-preflight: signed topology, atomic capability, operator rate envelope, and legacy-route guard checks passed')
