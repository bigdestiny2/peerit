// test/pow-identity-bind.mjs — identity-bound PoW (v2) + dual-accept + staple rejection.
// Exercises SHIPPED js/pow.js mint/verify and the gossip admit path after JSON round-trip.
// Run: node test/pow-identity-bind.mjs

import assert from 'node:assert'
import {
  mint,
  verify,
  powTargetForVersion,
  powTargetV1,
  powTargetV2,
  POW_VERSION,
  makeValidator
} from '../js/pow.js'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { mergeOutboxes } from '../js/gossip.js'
import { ready as cryptoReady } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

const wire = (r) => JSON.parse(JSON.stringify(r))
const BITS = { community: 4, post: 4, comment: 4, vote: 4, profile: 4, modaction: 4, blob: 4 }
const mem = () => {
  const m = new Map()
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    clear: () => m.clear()
  }
}

async function main () {
  await cryptoReady()

  console.log('\n— v2 target binds to stable id (not only type+time) —')
  const a = { id: 'okey-aaa', createdAt: 1000, community: 'p2p', cid: 'c1', author: 'aa', body: 'one' }
  const b = { id: 'okey-bbb', createdAt: 1000, community: 'p2p', cid: 'c2', author: 'aa', body: 'two' }
  ok(powTargetV2('post', a) !== powTargetV2('post', b),
    'two posts same createdAt ms with different ids get different v2 targets')
  ok(powTargetV2('post', a) === 'v2|okey-aaa|post|1000',
    'v2 target shape is v2|id|type|createdAt')
  ok(powTargetForVersion('post', a, 2) === powTargetV2('post', a),
    'powTargetForVersion(..., 2) dispatches to identity-bound target')
  ok(powTargetForVersion('post', a, 1) === powTargetV1('post', a),
    'powTargetForVersion(..., 1) dispatches to legacy target')
  ok(POW_VERSION === 2, 'POW_VERSION is 2')

  console.log('\n— mint stamps pow.v = 2 and verifies after JSON round-trip —')
  const proof = await mint('post', a, 4)
  ok(proof.v === 2, 'mint stamps pow.v = 2')
  ok(typeof proof.nonce === 'number' && typeof proof.bits === 'number', 'mint returns bits+nonce')
  const rec = wire({ ...a, pow: proof })
  ok(await verify('post', rec, 4) === true, 'matching v2 proof admits after JSON round-trip')

  console.log('\n— staple rejection: reuse proof across distinct ids —')
  const stapled = wire({ ...b, pow: proof })
  ok(await verify('post', stapled, 4) === false,
    'proof minted for id A is rejected on id B after JSON round-trip')

  const sameIdDiffBody = wire({ ...a, body: 'totally different body text', pow: proof })
  ok(await verify('post', sameIdDiffBody, 4) === true,
    'same stable id keeps the proof valid even if body text differs (id is the bind)')

  console.log('\n— dual-accept: wire-captured legacy (pow.v absent) still verifies —')
  const legacyData = {
    community: 'p2p',
    cid: 'legacycid1',
    author: 'bb'.repeat(32),
    createdAt: 1710000000000,
    title: 'legacy post',
    body: 'hello'
  }
  const legacyProofFull = await mint('post', legacyData, 4, { version: 1 })
  const { v: _drop, ...legacyBare } = legacyProofFull
  ok(legacyBare.v === undefined, 'legacy fixture has no pow.v')
  const legacyRec = wire({ ...legacyData, pow: legacyBare })
  ok(await verify('post', legacyRec, 4) === true,
    'legacy proof (pow.v absent) dual-accepts after JSON round-trip')
  const legacyOther = wire({
    ...legacyData,
    cid: 'othercid',
    body: 'different',
    pow: legacyBare
  })
  ok(await verify('post', legacyOther, 4) === false,
    'legacy proof still binds to its v1 target fields (cid/author/createdAt)')

  console.log('\n— makeValidator dispatches by semantic type —')
  const validate = makeValidator(BITS)
  ok(await validate('post', rec) === true, 'makeValidator admits matching v2 proof')
  ok(await validate('post', stapled) === false, 'makeValidator rejects stapled v2 proof')
  ok(await validate('post', legacyRec) === true, 'makeValidator dual-accepts legacy')

  console.log('\n— shipped data path: two v2 posts, staple fails admit via mergeOutboxes —')
  const sync = new DevSync(memoryStorage(), 'powbind'); await sync.ready()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser('alice')
  const data = createData(sync, id, { minBits: BITS, v2: true })

  await data.createCommunity({ slug: 'powtest', title: 'PoW', description: 'd' })
  // Force same createdAt window by submitting two posts rapidly — ids still differ.
  const p1 = await data.submitPost({ community: 'powtest', kind: 'text', title: 'one', body: 'body-one' })
  const p2 = await data.submitPost({ community: 'powtest', kind: 'text', title: 'two', body: 'body-two' })
  ok(p1.cid !== p2.cid, 'two posts have distinct cids')

  const rows = (await sync.list('v2!', { limit: 500 })).map((x) => wire(x.value))
  const postRows = rows.filter((v) => v && v._t === 'post')
  ok(postRows.length >= 2, 'two sealed v2 post rows on the wire')
  for (const pr of postRows) {
    ok(pr.pow && pr.pow.v === 2, 'each stored post has pow.v = 2')
    ok(await verify('post', pr, 4) === true, 'each stored post verifies under identity-bound target after wire')
  }

  // Staple: take proof from post A, attach to post B (different id), re-check via verify + merge
  const [rA, rB] = postRows
  const stapledWire = wire({ ...rB, pow: rA.pow })
  ok(await verify('post', stapledWire, 4) === false,
    'stapled proof across two real wire post bodies is rejected after JSON round-trip')
  ok(await validate('post', stapledWire) === false,
    'makeValidator rejects stapled real wire posts')

  // mergeOutboxes boxes shape: [{ pub, view }]
  const pub = id.me().pubkey
  const view = Object.create(null)
  for (const r of (await sync.list('v2!', { limit: 500 }))) view[r.key] = wire(r.value)
  // inject stapled under a synthetic key — admit will recompute okey and also fail PoW
  view['v2!stapled-fake'] = stapledWire
  const merged = await mergeOutboxes([{ pub, view }], {}, validate)
  let stapledAdmitted = false
  for (const k in merged) {
    if (merged[k] && merged[k].pow && merged[k].pow.nonce === rA.pow.nonce &&
        merged[k].id === rB.id && merged[k].pow.targetHash === rA.pow.targetHash) {
      stapledAdmitted = true
    }
  }
  ok(!stapledAdmitted, 'mergeOutboxes does not admit a stapled proof as a second post body')
  // genuine posts still present
  const genuineIds = new Set(postRows.map((r) => r.id))
  let genuineCount = 0
  for (const k in merged) {
    if (merged[k] && genuineIds.has(merged[k].id)) genuineCount++
  }
  ok(genuineCount >= 2, 'mergeOutboxes still admits both genuine posts with matching proofs')

  console.log('\n— edit re-mint on stable okey admits —')
  await data.editPost('powtest', p1.cid, 'edited body for pow rebind')
  const afterEdit = (await sync.list('v2!', { limit: 500 }))
    .map((x) => wire(x.value))
    .find((v) => v && v._t === 'post' && v.id === rA.id)
  ok(afterEdit && afterEdit.pow && afterEdit.pow.v === 2, 'edited post re-mints pow.v = 2')
  ok(await verify('post', afterEdit, 4) === true,
    'edited post admits after re-mint on same okey + JSON round-trip')

  console.log(`\n${passed} checks passed`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
