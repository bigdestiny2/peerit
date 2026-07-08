// test/mod-ui.mjs — mod-management: addMod/removeMod wrappers + pubkey input parsing.
// Run: node test/mod-ui.mjs
//
// Context (2026-07-08): a community member founded r/welcome via the starter
// button and had NO way to add the site operator as a mod — the data layer
// supported MOD.ADD_MOD/REMOVE_MOD (resolveMods) but no UI existed, and the
// create-community copy promised "add other moderators". This locks the pieces
// the new UI stands on:
//  - parsePubkeyInput: STRICT parsing of what people paste (raw hex / u/… /
//    profile URLs) — never fish a 64-hex substring out of longer text;
//  - data.addMod/removeMod: validated wrappers over modAction;
//  - resolveMods invariants: any current mod manages, founder is unremovable.

import assert from 'node:assert'
import { DevSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { parsePubkeyInput } from '../js/util.js'
import { ready as cryptoReady } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const BITS = { community: 4, post: 4, comment: 4 }

function mem () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() }
}

// resolveMods orders actions by ts (Date.now()); actions landing in the SAME
// millisecond tie-break on random actionId order. Humans act seconds apart, but
// a test fires them back-to-back — space each mod action ~2ms so the intended
// history order is what actually resolves.
const tick = () => new Promise(r => setTimeout(r, 2))

async function main () {
  await cryptoReady()

  console.log('\n— parsePubkeyInput: strict forms only —')
  const K = 'a1b2'.repeat(16)
  ok(parsePubkeyInput(K) === K, 'raw 64-hex accepted')
  ok(parsePubkeyInput('  ' + K + '  ') === K, 'whitespace trimmed')
  ok(parsePubkeyInput(K.toUpperCase()) === K, 'uppercase normalized to lowercase')
  ok(parsePubkeyInput('u/' + K) === K, 'u/<hex> handle accepted')
  ok(parsePubkeyInput('#/u/' + K) === K, 'in-app route accepted')
  ok(parsePubkeyInput('https://peerit.site/#/u/' + K) === K, 'full profile URL accepted')
  ok(parsePubkeyInput('https://peerit.site/#/u/' + K + '/') === K, 'trailing slash tolerated')
  ok(parsePubkeyInput(K.slice(1)) === null, '63 hex chars rejected')
  ok(parsePubkeyInput(K + 'a') === null, '65 hex chars rejected (no substring fishing)')
  ok(parsePubkeyInput('the key is ' + K) === null, 'hex embedded in prose rejected')
  ok(parsePubkeyInput('') === null && parsePubkeyInput(null) === null, 'empty/null rejected')

  console.log('\n— addMod/removeMod over the shared community —')
  const storage = mem()
  const sync = new DevSync(storage, 'mod-ui-test')
  await sync.ready()
  const idA = new DevIdentity(mem(), mem()); await idA.ready()
  const alice = createData(sync, idA, { minBits: BITS })
  const alicePub = alice.me().pubkey

  const idB = new DevIdentity(mem(), mem()); await idB.ready()
  const bob = createData(sync, idB, { minBits: BITS })
  const bobPub = bob.me().pubkey

  const idC = new DevIdentity(mem(), mem()); await idC.ready()
  const carol = createData(sync, idC, { minBits: BITS })
  const carolPub = carol.me().pubkey

  await alice.createCommunity({ slug: 'modtest', title: 'Mod Test', description: 'd' })
  ok((await alice.getMods('modtest')).has(alicePub), 'founder is the initial sole mod')

  // Validation: a typo'd key becomes an ERROR, never a signed record binding junk.
  await assert.rejects(() => alice.addMod('modtest', 'not-a-key'), /64-character/, '')
  passed++; console.log('  ✓ addMod rejects a malformed key before signing anything')

  const added = await alice.addMod('modtest', bobPub.toUpperCase()) // paste-with-caps case
  ok(added.targetUser === bobPub, 'addMod normalizes the key to lowercase in the record')
  ok((await alice.getMods('modtest')).has(bobPub), 'founder added bob — bob is a mod')

  // Any CURRENT mod manages: bob (not the founder) adds carol.
  await tick()
  await bob.addMod('modtest', carolPub)
  ok((await alice.getMods('modtest')).has(carolPub), 'a non-founder mod can add another mod')

  // A mod's powers are real: carol can lock a thread.
  await tick()
  const post = await alice.submitPost({ community: 'modtest', kind: 'text', title: 'thread', body: 'b' })
  await tick()
  await carol.modAction('modtest', { action: 'lock', targetCid: post.cid })
  ok((await alice.overlay('modtest')).locked.has(post.cid), 'newly-added mod can lock a thread')

  // Removal works — and stepping down is allowed.
  await tick()
  await bob.removeMod('modtest', carolPub)
  ok(!(await alice.getMods('modtest')).has(carolPub), 'mod removal takes effect')
  await tick()
  await bob.removeMod('modtest', bobPub)
  ok(!(await alice.getMods('modtest')).has(bobPub), 'a mod may remove themselves (step down)')

  // FOUNDER PROTECTION: the removal record lands but resolveMods ignores it.
  await tick()
  await alice.addMod('modtest', bobPub)
  await tick()
  await bob.removeMod('modtest', alicePub)
  ok((await alice.getMods('modtest')).has(alicePub), 'the founder can never be removed (resolveMods invariant)')

  // Non-mods cannot manage: carol (removed) is rejected at the data layer.
  await assert.rejects(() => carol.addMod('modtest', carolPub), /Only moderators/, '')
  passed++; console.log('  ✓ a removed mod can no longer add mods (data-layer gate)')

  console.log(`\nmod-ui: ${passed} checks passed.`)
}

main().catch((e) => { console.error('❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
