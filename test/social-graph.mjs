// social-graph.mjs — the SIGNED social graph (follow! / member!), slice 1 of the
// no-infra feature wave. Follows/memberships stop being device-local prefs and
// become sealed v2 LWW records (the exact vote! pattern), so they replicate,
// survive localStorage loss, and give the network follower/member counts — while
// the relay still only ever stores opaque cells (the EDGE is a sealed graph field:
// who-follows-whom / who-joined-what is not greppable).
//   node test/social-graph.mjs

import assert from 'node:assert'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { mergeOutboxes } from '../js/gossip.js'
import { makeValidator } from '../js/pow.js'
import { expectedKeyV2 } from '../js/canon.js'
import { unseal } from '../js/seal.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'

const BITS = { community: 4, post: 4, comment: 4, vote: 4, profile: 4, modaction: 4 }
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))

// Two users sharing ONE DevSync world (the dev model: one store, many writers).
// The app invalidates view caches on sync.onChange (app.js); across two Data
// instances in one process we do it explicitly via fresh() before cross-user reads.
async function newWorld () {
  const store = memoryStorage()
  const mk = async (name) => {
    const sync = new DevSync(store, 'social-graph'); await sync.ready()
    const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
    return { sync, id, data: createData(sync, id, { minBits: BITS, v2: true }), me: id.me().pubkey }
  }
  return { alice: await mk('alice'), bob: await mk('bob') }
}
const fresh = (u) => u.data.invalidateViewCaches('vote') // what sync.onChange does in the app

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')
  const { alice, bob } = await newWorld()
  const validate = makeValidator(BITS)

  console.log('\n— follow: sealed v2 write —')
  const f = await bob.data.setFollow(alice.me)
  ok(f.target === alice.me && f.author === bob.me, 'setFollow returns the plaintext logical record')
  const fkey = (await expectedKeyV2({ ...f, _t: 'follow' })).slice(3)
  const stored = await bob.sync.get('v2!' + fkey)
  ok(stored && stored._t === 'follow' && stored.sealed, 'the outbox holds a SEALED v2 follow at its opaque okey')
  ok(JSON.stringify(stored).indexOf(alice.me) === -1, 'the follow TARGET is sealed — who-follows-whom is not greppable')
  ok((await unseal(stored.sealed)).target === alice.me, 'unseal recovers the exact edge')
  const merged = await mergeOutboxes([{ pub: bob.me, view: { ['v2!' + fkey]: stored } }], {}, validate)
  ok(merged['v2!' + fkey], 'the follow record admits through the real mergeOutboxes (okey recompute + sig)')

  console.log('\n— follow: reads + counts —')
  ok(await bob.data.isFollowing(alice.me), 'isFollowing sees the edge')
  fresh(alice)
  ok((await alice.data.followersOf(alice.me)).includes(bob.me), "alice's followers include bob (cheap prefix read)")
  ok((await bob.data.followingOf(bob.me)).includes(alice.me), "bob's following list includes alice (range scan)")
  const counts = await alice.data.followCounts(alice.me)
  ok(counts.followers === 1 && counts.following === 0, 'followCounts: alice has 1 follower, follows 0')

  console.log('\n— unfollow: LWW tombstone, re-follow wins —')
  await delay(2) // LWW is ts-ordered; ensure a strictly later timestamp
  const un = await bob.data.setFollow(alice.me, false)
  ok(un.deleted === true, 'unfollow is a deleted:true re-write of the SAME id')
  ok(!(await bob.data.isFollowing(alice.me)), 'isFollowing flips off')
  fresh(alice)
  ok((await alice.data.followersOf(alice.me)).length === 0, 'tombstoned edge drops out of followersOf')
  await delay(2)
  await bob.data.setFollow(alice.me, true)
  ok(await bob.data.isFollowing(alice.me), 'a later re-follow wins the LWW against the tombstone')
  ok((await bob.data.setFollow(bob.me).catch(e => e.message)).includes('yourself'), 'self-follow is rejected')

  console.log('\n— membership: sealed v2 write + counts —')
  await alice.data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'graph test' })
  fresh(bob)
  const m = await bob.data.setMembership('p2p')
  const mkey = (await expectedKeyV2({ ...m, _t: 'member' })).slice(3)
  const mstored = await bob.sync.get('v2!' + mkey)
  ok(mstored && mstored._t === 'member' && mstored.sealed, 'the outbox holds a SEALED v2 member record')
  ok(mstored.slug === undefined && JSON.stringify(mstored).indexOf('p2p') === -1, 'the community EDGE is sealed (field is `community`, so V2_CLEAR does not leak it)')
  ok((await unseal(mstored.sealed)).community === 'p2p', 'unseal recovers the membership edge')
  fresh(alice)
  ok((await alice.data.membersOf('p2p')).includes(bob.me), 'membersOf sees bob')
  ok((await alice.data.memberCount('p2p')) === 1, 'memberCount = 1')
  ok((await bob.data.myMemberships()).includes('p2p'), 'myMemberships lists p2p')
  ok((await bob.data.setMembership('nope').catch(e => e.message)).includes('No such community'), 'joining an unknown community is rejected')
  await delay(2)
  await bob.data.setMembership('p2p', false)
  fresh(alice)
  ok((await alice.data.memberCount('p2p')) === 0, 'leave tombstones the membership')

  console.log('\n— migration: local prefs → signed records, idempotent —')
  const prefStore = mem()
  const r1 = await bob.data.migrateLocalGraph({ follows: [alice.me], subs: ['p2p'], storage: prefStore })
  ok(r1.migrated >= 1 && !r1.skipped, 'first run writes records for local prefs (migrated=' + r1.migrated + ')')
  ok(await bob.data.isFollowing(alice.me) && (await bob.data.myMemberships()).includes('p2p'), 'migrated edges are live records')
  const r2 = await bob.data.migrateLocalGraph({ follows: [alice.me], subs: ['p2p'], storage: prefStore })
  ok(r2.skipped === true, 'second run is a no-op (per-identity flag)')

  console.log(`\n✅ all ${passed} social-graph checks passed`)
  process.exit(0)
}
main().catch((e) => { console.error('\n❌ social-graph FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
