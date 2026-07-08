// data-v2-write.mjs — slice 4b: the Opaque-Log v2 WRITE path in data.js.
// Drives real domain writes (createCommunity / submitPost / vote) through a Data
// instance with { v2:true } and proves the outbox now holds SEALED opaque records:
// the graph + content are not greppable, community slug stays cleartext by design,
// each record admits through the real mergeOutboxes, and unsealing recovers the
// exact content. The flag defaults OFF, so v1 behaviour is untouched.
//   node test/data-v2-write.mjs

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

async function newUser (v2) {
  const sync = new DevSync(memoryStorage(), 'v2-write'); await sync.ready()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser('alice')
  const data = createData(sync, id, { minBits: BITS, v2 })
  return { sync, id, data, me: id.me().pubkey }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend (Ed25519) available')
  const { sync, data, me } = await newUser(true)
  const validate = makeValidator(BITS)

  await data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'peer to peer stuff' })
  const post = await data.submitPost({ community: 'p2p', kind: 'text', title: 'Hello', body: 'a short body' })

  console.log('\n— post write —')
  ok(post.community === 'p2p' && post.cid, 'submitPost returns the plaintext logical record (for optimistic render)')
  const okey = (await expectedKeyV2({ ...post, _t: 'post' })).slice(3)
  const stored = await sync.get('v2!' + okey)
  ok(stored && stored._t === 'post' && stored.sealed && stored.id === okey, 'the outbox holds a SEALED v2 post at its opaque okey')
  const blob = JSON.stringify(stored)
  ok(blob.indexOf('p2p') === -1 && blob.indexOf('Hello') === -1 && blob.indexOf('a short body') === -1, 'community + title + body are SEALED — none appear in the stored post record')
  ok(stored.community === undefined && stored.title === undefined && stored.body === undefined, 'graph/content fields are gone from the top level; only createdAt/deleted + {iv,ct} remain')

  console.log('\n— admits + decrypts —')
  const merged = await mergeOutboxes([{ pub: me, view: { ['v2!' + okey]: stored } }], {}, validate)
  ok(merged['v2!' + okey], 'the written v2 post admits through the real mergeOutboxes')
  const f = await unseal(stored.sealed)
  ok(f.title === 'Hello' && f.body === 'a short body' && f.community === 'p2p' && f.cid === post.cid, 'unseal recovers the exact content')

  console.log('\n— vote write —')
  const v = await data.vote(post.cid, 'p2p', 'post', 1)
  const vkey = (await expectedKeyV2({ ...v, _t: 'vote' })).slice(3)
  const vstored = await sync.get('v2!' + vkey)
  ok(vstored && vstored._t === 'vote' && vstored.sealed, 'a v2 vote lands sealed at its opaque slot')
  ok(JSON.stringify(vstored).indexOf(post.cid) === -1, 'the vote TARGET is sealed — not greppable')
  ok((await unseal(vstored.sealed)).value === 1, 'the vote value decrypts to 1')

  console.log('\n— community keeps slug cleartext (name leaks by design) —')
  const cokey = (await expectedKeyV2({ _t: 'community', slug: 'p2p', creator: me })).slice(3)
  const cstored = await sync.get('v2!' + cokey)
  ok(cstored && cstored._t === 'community' && cstored.slug === 'p2p', 'community record keeps slug CLEARTEXT (dictionary-reversible anyway)')
  ok(JSON.stringify(cstored).indexOf('peer to peer stuff') === -1, 'the community description IS sealed')

  console.log('\n— flag OFF still writes v1 —')
  const u1 = await newUser(false)
  await u1.data.createCommunity({ slug: 'old', title: 'Old' })
  const p1 = await u1.data.submitPost({ community: 'old', kind: 'text', title: 'legacy', body: 'x' })
  ok(await u1.sync.get('post!old!' + p1.cid), 'with v2 OFF, a post still lands under the plaintext key post!<community>!<cid>')

  console.log(`\n✅ all ${passed} data-v2-write checks passed`)
}
main().catch(e => { console.error(e); process.exit(1) })
