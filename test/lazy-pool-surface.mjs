// test/lazy-pool-surface.mjs — the instant-boot lazy pool must satisfy createSync's
// PearBrowser surface guard. Run: node test/lazy-pool-surface.mjs
//
// REGRESSION (14d8ace): web boot starts gossip against createLazyPearPool() BEFORE a
// relay is selected. createSync() (js/sync.js) inspects the pear surface: if it looks
// like a PearBrowser bridge (hasAnyPearBridgeSurface) but is NOT a complete gossip
// surface (hasGossipPearSurface), it THROWS rather than silently using local dev sync.
// The first lazy pool had sync + swarm but NO identity → hasGossipPearSurface false →
// createSync threw at boot → EVERY web visitor stuck on the splash, refresh stuck.
//
// test/instant-boot.mjs missed this because it constructs BridgeGossipSync directly,
// bypassing createSync's guard. This test drives the REAL createLazyPearPool through
// the REAL createSync + the REAL pear-api predicates, and pins the failure shape.

import assert from 'node:assert'
import { ready as cryptoReady } from '../js/crypto.js'
import { createSync } from '../js/sync.js'
import { createLazyPearPool } from '../js/lazy-pool.js'
import { hasAnyPearBridgeSurface, hasGossipPearSurface, hasIdentityPearSurface } from '../js/pear-api.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}
const PUB = 'ab'.repeat(32)
const idStub = { me: () => ({ pubkey: PUB }), sign: async () => new Uint8Array(64) }
const syncOpts = () => ({ mode: 'gossip', getMe: () => PUB, identity: idStub, storage: mem() })

await cryptoReady()

// --- 1. the real lazy pool satisfies the full gossip surface -----------------
const lazy = createLazyPearPool()
ok(hasAnyPearBridgeSurface(lazy.pear), 'lazy pool looks like a PearBrowser bridge (hasAnyPearBridgeSurface)')
ok(hasIdentityPearSurface(lazy.pear), 'lazy pool exposes identity.getPublicKey + sign (hasIdentityPearSurface) — the 14d8ace fix')
ok(hasGossipPearSurface(lazy.pear), 'lazy pool satisfies the FULL gossip surface (sync + identity + swarm.v1)')

// --- 2. createSync accepts it without throwing (the boot path) ---------------
let sync
assert.doesNotThrow(() => { sync = createSync({ ...syncOpts(), pear: lazy.pear, instantBoot: true }) },
  'createSync must NOT throw on the lazy pool')
passed++; console.log('  ✓ createSync(lazy pool) does not throw — web boot reaches gossip')
ok(sync && sync.mode === 'gossip-bridge', 'createSync returned the gossip-bridge backend (not a dev-sync fallback)')
try { if (sync && sync.destroy) sync.destroy() } catch {}

// --- 3. fail-fast contract before a relay is plugged in ----------------------
ok(lazy.connected === false, 'lazy pool starts disconnected (connected === false)')
await assert.rejects(() => lazy.pear.sync.list('x'), /relay not connected yet/,
  'sync calls fail fast (relay not connected yet) until setTarget()')
lazy.setTarget({ _relayCount: 3, sync: {}, swarm: { v1: {} }, identity: {} })
ok(lazy.connected === true, 'setTarget() marks the pool connected')
ok(lazy.pear._relayCount === 3, 'connected pool delegates _relayCount to the real target')

// --- 4. NEGATIVE CONTROL: reproduce the exact regression shape ---------------
// A pear with sync + swarm but NO identity — the pre-14d8ace lazy pool. This MUST
// be rejected by createSync (proving the guard is live and this test exercises it).
function lazyPoolWithoutIdentity () {
  const notUp = () => new Error('relay not connected yet')
  const pear = { sync: {}, swarm: { v1: { join: async () => { throw notUp() } } } }
  for (const m of ['create', 'join', 'append', 'get', 'list']) pear.sync[m] = async () => { throw notUp() }
  return pear
}
const broken = lazyPoolWithoutIdentity()
ok(hasAnyPearBridgeSurface(broken), 'broken pool still looks like a bridge (sync present)')
ok(!hasIdentityPearSurface(broken), 'broken pool has NO identity surface')
ok(!hasGossipPearSurface(broken), 'broken pool fails the full gossip surface')
assert.throws(() => createSync({ ...syncOpts(), pear: broken }),
  /refusing to fall back to local dev sync/,
  'createSync THROWS on the identity-less pool — the regression, now asserted')
passed++; console.log('  ✓ createSync(identity-less pool) throws the boot-wedge error (regression pinned)')

console.log(`\nlazy-pool-surface: ${passed} checks passed.`)
