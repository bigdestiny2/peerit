// test/lazy-identity.mjs — lurkers mint nothing; the first write mints exactly once.
// Run: node test/lazy-identity.mjs
//
// THE DESIGN (panel-verified 2026-07-08): web visitors are LURKERS — boot creates
// NO keypair, NO relay outbox, NO swarm descriptor. Every page refresh used to
// mint a fresh identity plus a ghost outbox + a permanently-remembered descriptor
// on the relay: the request amplification behind the per-IP 429 starvation, and
// the "new user every refresh" bug. The first WRITE mints one identity,
// single-flight, strictly before anything is signed.

import assert from 'node:assert'
import { DevIdentity, createIdentity } from '../js/identity.js'
import { BridgeGossipSync } from '../js/gossip.js'
import { resolveRuntime } from '../js/runtime.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const HEX64 = /^[0-9a-f]{64}$/i

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

// Counting relay mock: same shape as test/gossip.mjs but records every call that
// creates relay-side state, so we can assert a lurker leaves ZERO of it.
function countingPear () {
  const counts = { create: 0, join: 0, swarmJoin: 0, sends: 0 }
  const groups = new Map()
  const channel = { peers: [{ send: () => { counts.sends++ } }], on: () => {} }
  const ensure = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { inviteKey: 'a'.repeat(64), rows: new Map() })
    return groups.get(appId)
  }
  return {
    counts,
    groups,
    sync: {
      create: async (appId) => { counts.create++; return { appId, inviteKey: ensure(appId).inviteKey, writerPublicKey: 'b'.repeat(64) } },
      join: async (appId, inviteKey) => { counts.join++; const g = ensure(appId); if (inviteKey !== g.inviteKey) throw new Error('bad invite'); return { appId, inviteKey } },
      append: async (appId, op) => { const key = op.type.replace(':', '!') + '!' + op.data.id; ensure(appId).rows.set(key, op.data); return { ok: true, key } },
      range: async (appId, opts = {}) => [...ensure(appId).rows.entries()].map(([key, value]) => ({ key, value })).slice(0, Number(opts.limit) || 100),
      list: async () => [],
      status: async (appId) => ({ appId, inviteKey: ensure(appId).inviteKey, viewLength: ensure(appId).rows.size })
    },
    swarm: { v1: { join: async () => { counts.swarmJoin++; return channel } } }
  }
}

async function main () {
  await cryptoReady()

  console.log('\n— DevIdentity lazy tier —')
  const lazyId = new DevIdentity(mem(), mem(), { lazy: true })
  await lazyId.ready()
  const me0 = lazyId.me()
  ok(me0 && me0.pubkey === null && me0.driveKey === null, 'lazy ready() mints nothing; me() keeps the object shape with pubkey:null')
  await assert.rejects(() => lazyId.sign('x'), /no active identity/, 'sign() without an identity fails closed')
  passed++; console.log('  ✓ sign() without an identity fails closed')
  ok(lazyId.listUsers().length === 0, 'roster is empty for a lurker')

  // single-flight mint: two concurrent ensureActive() calls -> ONE identity
  const [a, b] = await Promise.all([lazyId.ensureActive(), lazyId.ensureActive()])
  ok(HEX64.test(a.pubkey) && a.pubkey === b.pubkey, 'concurrent ensureActive() single-flights to ONE minted identity')
  ok(lazyId.listUsers().length === 1, 'exactly one roster entry after the race')
  const again = await lazyId.ensureActive()
  ok(again.pubkey === a.pubkey && lazyId.listUsers().length === 1, 'ensureActive() is idempotent once minted')

  console.log('\n— eager modes unchanged —')
  const eagerId = new DevIdentity(mem(), mem(), {})
  await eagerId.ready()
  ok(HEX64.test(eagerId.me().pubkey), 'non-lazy DevIdentity still mints at ready() (dev/seeder/tests unchanged)')
  const noOpts = createIdentity({ forceDev: true, storage: mem(), session: mem() })
  await noOpts.ready()
  ok(HEX64.test(noOpts.me().pubkey), 'createIdentity without lazy stays eager')

  console.log('\n— runtime wiring —')
  const doc = (metas = {}) => ({
    querySelector: (sel) => {
      const m = sel.match(/meta\[name="([^"]+)"\]/)
      const name = m && m[1]
      return name && Object.prototype.hasOwnProperty.call(metas, name) ? { getAttribute: () => metas[name] } : null
    }
  })
  const rtWeb = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://relay.example' }) })
  ok(rtWeb.mode === 'web' && rtWeb.identityOpts.lazy === true, 'web runtime sets identityOpts.lazy (lurker tier on)')
  ok(rtWeb.identityOpts.persistSeed === undefined, 'web runtime still does NOT set persistSeed (key-at-rest bar holds)')
  const rtDev = resolveRuntime({ rawPear: null, doc: doc({}) })
  ok(rtDev.mode === 'dev' && rtDev.identityOpts.lazy === undefined, 'local-dev runtime stays eager (no lazy)')

  console.log('\n— gossip: a lurker leaves ZERO relay state —')
  const world = countingPear()
  const lurkerId = new DevIdentity(mem(), mem(), { lazy: true })
  await lurkerId.ready()
  const seedPub = 'c'.repeat(64)
  world.sync.create && await world.sync.create(seedPub) // seed outbox exists server-side
  world.counts.create = 0 // reset: only the lurker's own calls count from here
  const store = mem()
  const lurker = new BridgeGossipSync({
    pear: world,
    getMe: () => lurkerId.me().pubkey,
    identity: lurkerId,
    storage: store,
    validate: makeValidator({}),
    pollMs: 0,
    seedOutboxes: [{ appId: seedPub, inviteKey: 'a'.repeat(64) }]
  })
  await lurker.ready()
  ok(world.counts.create === 0, 'lurker boot performs ZERO sync.create (no ghost outbox)')
  ok(world.counts.join === 1, 'lurker still joins the SEED outbox read-only (content renders)')
  ok(world.counts.sends === 0, 'lurker sends ZERO swarm descriptors (silent — no /api/swarm/send burn)')
  ok(await lurker._descBytes() === null, '_descBytes() is null for a lurker (every announce path no-ops)')
  let nullPeer = false
  for (const [pub] of lurker._peers) if (!pub || !HEX64.test(pub)) nullPeer = true
  ok(!nullPeer, 'no null/invalid key ever enters _peers (heads poll payload stays clean)')
  ok(await lurker._ensureMyOutbox() === false, '_ensureMyOutbox() quietly refuses without an identity')
  await assert.rejects(() => lurker.append({ type: 'post', data: { id: 'x' } }), /outbox is unavailable/i, '')
  passed++; console.log('  ✓ direct append without identity fails politely (no mint, no create)')
  ok(world.counts.create === 0, 'the refused append minted NOTHING relay-side')

  console.log('\n— first write mints exactly once, then the outbox exists —')
  await lurkerId.ensureActive('anon') // what app.js ensureWriterIdentity does (after its read-only gate)
  ok(HEX64.test(lurkerId.me().pubkey), 'identity exists after mint')
  await lurker.append({ type: 'post', data: { id: 'p2p!x', cid: 'x' } }).catch(() => {}) // append opens the outbox inline
  ok(world.counts.create === 1, 'first write opened exactly ONE outbox')
  ok(await lurker._descBytes() !== null, 'writer now has an announceable descriptor')
  const selfPeers = [...lurker._peers.values()].filter(p => p.self)
  ok(selfPeers.length === 1 && selfPeers[0].appId === lurkerId.me().pubkey, 'self-peer registered only after the mint')

  console.log('\n— vault interplay: restore populates without minting a second key —')
  const vaultId = new DevIdentity(mem(), mem(), { lazy: true })
  await vaultId.ready()
  const donor = new DevIdentity(mem(), mem(), {})
  await donor.ready()
  const entry = donor.currentSeedEntry()
  await vaultId.restoreFromVault(entry)
  ok(vaultId.me().pubkey === entry.pubkey, 'vault restore activates the saved identity')
  const ensured = await vaultId.ensureActive()
  ok(ensured.pubkey === entry.pubkey && vaultId.listUsers().length === 1, 'ensureActive() after restore is a no-op (no fork)')

  console.log(`\nlazy-identity: ${passed} checks passed.`)
}

main().catch((e) => { console.error('❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
