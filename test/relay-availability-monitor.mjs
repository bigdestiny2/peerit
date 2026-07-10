// relay-availability-monitor.mjs — continuous web relay/read+writer state.
// Run: node test/relay-availability-monitor.mjs

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createLazyPearPool, monitorRelayAvailability } from '../js/lazy-pool.js'

let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }

const FUTURE = new Date(Date.now() + 60_000).toISOString()
const ORIGINS = ['https://relay-a.example', 'https://relay-b.example']
const topology = {
  id: 'signed-topology-v1',
  validWriterTopology: true,
  origins: ORIGINS,
  size: 2
}

function relay (index, { atomic = true, token = 'token-' + index } = {}) {
  return {
    apiBase: ORIGINS[index],
    canonicalOrigin: ORIGINS[index],
    apiToken: token,
    atomicCommit: atomic
  }
}

function candidates ({ verified = true } = {}) {
  return {
    rosterVerified: verified,
    roster: verified ? { expires: FUTURE } : null,
    topology: verified ? topology : null,
    relays: ORIGINS.slice()
  }
}

function fakePool (selected) {
  const exact = selected.length >= 2 && selected.every((entry) => entry.atomicCommit === true)
  return {
    _relayCount: selected.length,
    _atomicCommit: exact,
    sync: {
      commit: async () => ({ ok: true }),
      list: async () => [],
      append: async () => ({ ok: true })
    },
    swarm: { v1: { join: async () => ({}) } },
    identity: {}
  }
}

console.log('\n— continuous relay monitor —')
const passes = [
  { candidates: candidates(), selected: [relay(0)] }, // read-only degradation
  { candidates: candidates(), selected: [relay(0), relay(1)] }, // quorum arrives
  { candidates: candidates(), selected: [relay(0, { token: 'renewed-a' }), relay(1, { token: 'renewed-b' })] }, // semantic no-op
  { candidates: candidates(), selected: [relay(0), relay(1, { atomic: false })] }, // capability loss
  { candidates: candidates({ verified: false }), selected: [relay(0), relay(1)] }, // unsigned/static fallback is read-only
  { candidates: candidates({ verified: false }), selected: [] } // total outage clears target
]

const lazy = createLazyPearPool()
const controller = new AbortController()
const observed = []
const snapshots = []
const waits = []
let cursor = 0

await monitorRelayAvailability({
  lazy,
  signal: controller.signal,
  refreshMs: 100,
  retryMinMs: 10,
  retryMaxMs: 40,
  resolveCandidates: async () => passes[cursor].candidates,
  selectRelays: async () => passes[cursor].selected,
  createPool: (selected) => fakePool(selected),
  onStateChange: async (state) => observed.push({
    relays: state.relays.slice(),
    writerAvailable: state.writerAvailable,
    rosterVerified: state.rosterVerified,
    topologyId: state.topologyId
  }),
  wait: async (ms) => {
    waits.push(ms)
    snapshots.push({ connected: lazy.connected, relays: lazy.pear._relayCount, writer: lazy.pear._atomicCommit })
    cursor++
    if (cursor >= passes.length) controller.abort()
  }
})

ok(snapshots[0].connected && snapshots[0].relays === 1 && !snapshots[0].writer,
  'one reachable relay is installed immediately for reads without enabling writes')
ok(snapshots[1].relays === 2 && snapshots[1].writer,
  'two exact durable relays on a verified signed topology enable the writer')
ok(snapshots[2].writer && observed.length === 5,
  'token-only renewal silently refreshes transport without a duplicate UI/wake transition')
ok(!snapshots[3].writer && snapshots[3].relays === 2,
  'loss of one exact atomic capability promptly downgrades the two-relay pool to reads')
ok(!snapshots[4].writer && snapshots[4].relays === 2,
  'two reachable relays from an unverified fallback roster can never enable writing')
ok(!snapshots[5].connected && snapshots[5].relays === 0 && !snapshots[5].writer,
  'a total outage clears the live target while cached boot content remains outside the facade')
ok(waits.join(',') === '10,100,100,10,20,40',
  'incomplete writer state keeps retrying with capped backoff; a complete state stays monitored')

console.log('\n— signed-roster expiry gate —')
const expiring = createLazyPearPool()
let commitCalls = 0
let appendCalls = 0
expiring.setTarget({
  _relayCount: 2,
  _atomicCommit: true,
  sync: {
    commit: async () => { commitCalls++; return { ok: true } },
    append: async () => { appendCalls++; return { ok: true } },
    list: async () => ['readable']
  },
  swarm: { v1: { join: async () => ({}) } },
  identity: {}
}, { enableWriter: true, expiresAt: Date.now() + 25 })

await expiring.pear.sync.commit('author', { commitId: 'a'.repeat(64) })
await new Promise((resolve) => setTimeout(resolve, 40))
ok(expiring.pear._atomicCommit === false, 'writer capability turns off at roster expiry even without a completed network probe')
ok((await expiring.pear.sync.list('author'))[0] === 'readable', 'roster expiry preserves the installed pool for verified reads')
await assert.rejects(() => expiring.pear.sync.commit('author', { commitId: 'b'.repeat(64) }), /atomic writer quorum/i)
passed++; console.log('  ✓ expired commit fails closed instead of falling through to a legacy path')
ok(commitCalls === 1 && appendCalls === 0, 'a rejected atomic commit never invokes legacy append')

console.log('\n— app writer availability wiring —')
const appSource = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8')
const writerStart = appSource.indexOf('async function ensureWriterIdentity')
const writerEnd = appSource.indexOf('\nfunction isBridgeMode', writerStart)
const writerGate = appSource.slice(writerStart, writerEnd)
const firstAvailability = writerGate.indexOf('if (durableWebWriter) await requireAtomicWebWriter()')
const vaultPrompt = writerGate.indexOf('await unlockVaultAtBoot')
const finalAvailability = writerGate.lastIndexOf('await requireAtomicWebWriter()')
const activeStart = writerGate.indexOf('if (identity.me().pubkey)')
const activeEnd = writerGate.indexOf('\n  if (_ensuringWriter)', activeStart)
const activeGate = writerGate.slice(activeStart, activeEnd)
ok(firstAvailability >= 0 && firstAvailability < vaultPrompt,
  'public-web write checks atomic quorum before vault prompt or identity mint')
ok(activeGate.indexOf('await assertDurableIdentity') >= 0 && activeGate.lastIndexOf('await requireAtomicWebWriter()') > activeGate.indexOf('await assertDurableIdentity'),
  'an existing durable identity rechecks quorum after async device verification and immediately before return')
ok(finalAvailability > vaultPrompt,
  'public-web write rechecks atomic quorum after identity activation and before signing')
ok(appSource.includes('atomic.available === true && atomic.pending !== true && atomic.recoveryNeeded !== true') && !appSource.includes('status.atomicWriterAvailable'),
  'Settings and writer UI require available atomic commit with no pending/recovery state')
ok(appSource.includes('const tokenCache = new Map()') && appSource.includes('tokenCache,') && appSource.includes('tokenCache.delete(apiBase)'),
  'background capability probes reuse per-connector relay tokens and prune removed roster entries')
ok(appSource.includes("{ postCid: box.dataset.post || '' }"),
  'comment votes pass the enclosing post CID for direct lookup')
ok(appSource.includes('Your draft stays on this page') && appSource.includes('never route() or replace the form') && appSource.includes('if (readTopologyChanged && sync && sync.wake)'),
  'writer-only availability transitions update in place without waking away typed submit/create drafts')

console.log(`\nrelay-availability-monitor: ${passed} checks passed.`)
