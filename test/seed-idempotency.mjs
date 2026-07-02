// seed-idempotency.mjs — prove the repopulate script is SAFE to re-run before we
// ever point it at the live relay. No network: it runs seedContent() (from
// test/seed-author.mjs) TWICE against an in-memory DevSync, across two DevIdentity
// instances rebuilt from the SAME file-backed store, and asserts:
//   • STABLE AUTHOR — a persisted identity store yields the same pubkey every run
//     (no fresh claimant → no sticky-community-claim churn on r/p2p, r/worldcup);
//   • IDEMPOTENT POSTS — deterministic cids overwrite in place, so a second run adds
//     ZERO duplicate post records (the outbox holds exactly the seed set);
//   • COMMUNITY REUSE — createCommunity's "already exists" is caught, one record each.
// This is the revert-proof guard for the reseed: run it, then fire seed-author.mjs.
//   node test/seed-idempotency.mjs

import assert from 'node:assert'
import os from 'node:os'
import fs from 'node:fs'
import { join } from 'node:path'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { id as mkid } from '../js/model.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { SEED, seedContent } from './seed-author.mjs'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
// A JSON-file localStorage shim — the same persistence trick seed-author.mjs uses to
// keep one stable identity. Rebuilding a DevIdentity from it models a re-run.
function fileStore (path) {
  let d = {}; try { d = JSON.parse(fs.readFileSync(path, 'utf8')) || {} } catch {}
  const save = () => fs.writeFileSync(path, JSON.stringify(d))
  return { getItem: k => (k in d ? d[k] : null), setItem: (k, v) => { d[k] = String(v); save() }, removeItem: k => { delete d[k]; save() }, clear: () => { d = {}; save() } }
}

const BITS = { community: 4, post: 4, comment: 4 } // tiny PoW → fast
const SEED_POSTS = Object.values(SEED).reduce((n, c) => n + c.posts.length, 0)
const SEED_COMMS = Object.keys(SEED).length
const allCids = Object.values(SEED).flatMap(c => c.posts.map(p => p.cid))

// One "run" of the repopulate: rebuild the identity from the persisted store and the
// outbox from the shared storage (exactly what invoking the script twice would do).
async function run (idStorePath, outboxStorage) {
  const id = new DevIdentity(fileStore(idStorePath), mem())
  await id.ready()
  const sync = new DevSync(outboxStorage, 'seed-idem')
  await sync.ready()
  const data = createData(sync, id, { minBits: BITS })
  const res = await seedContent(data)
  return { author: id.me().pubkey, data, sync, res }
}

async function countPosts (data) {
  let posts = []
  for (const slug of Object.keys(SEED)) posts = posts.concat(await data.listPostsIn(slug, { hydrate: false }))
  return posts
}

async function main () {
  await cryptoReady()
  const idStorePath = join(fs.mkdtempSync(join(os.tmpdir(), 'peerit-seed-')), 'author.json')
  const outboxStorage = memoryStorage() // shared across both runs → same outbox

  console.log('— run 1 (fresh author + empty outbox) —')
  const r1 = await run(idStorePath, outboxStorage)
  ok(/^[0-9a-f]{64}$/.test(r1.author), 'run 1 mints a valid author pubkey')
  ok(r1.res.communities === SEED_COMMS && r1.res.posts === SEED_POSTS, `run 1 seeds ${SEED_COMMS} communities + ${SEED_POSTS} posts`)
  const p1 = await countPosts(r1.data)
  ok(p1.length === SEED_POSTS, `outbox holds exactly ${SEED_POSTS} post records after run 1`)
  ok((await r1.data.listCommunities()).length === SEED_COMMS, `outbox holds exactly ${SEED_COMMS} communities after run 1`)

  console.log('\n— run 2 (re-invoke: identity from same store, same outbox) —')
  const r2 = await run(idStorePath, outboxStorage)
  ok(r2.author === r1.author, 'STABLE AUTHOR — a persisted identity store yields the same pubkey on re-run (no fresh claimant)')
  ok(r2.res.communities === 0, 'run 2 creates NO new community (createCommunity "already exists" is caught)')
  ok(r2.res.posts === SEED_POSTS, 'run 2 re-submits the same post set (same deterministic cids)')

  const p2 = await countPosts(r2.data)
  ok(p2.length === SEED_POSTS, `IDEMPOTENT — outbox STILL holds exactly ${SEED_POSTS} posts after run 2 (zero duplicates)`)
  ok((await r2.data.listCommunities()).length === SEED_COMMS, `still exactly ${SEED_COMMS} communities after run 2 (no duplicate claim)`)

  // every deterministic cid is present exactly once, at its own key
  for (const cid of allCids) {
    const slug = Object.keys(SEED).find(s => SEED[s].posts.some(p => p.cid === cid))
    const hits = p2.filter(p => p.cid === cid)
    ok(hits.length === 1 && hits[0].id === mkid.post(slug, cid), `cid "${cid}" appears exactly once at its deterministic key (${mkid.post(slug, cid)})`)
  }

  // control: a NON-deterministic post (no cid) WOULD duplicate — proves the guard is real
  console.log('\n— control: without a fixed cid, a re-submit duplicates —')
  const before = (await r2.data.listPostsIn('p2p', { hydrate: false })).length
  await r2.data.submitPost({ community: 'p2p', kind: 'text', title: 'ad-hoc', body: 'no fixed cid' })
  await r2.data.submitPost({ community: 'p2p', kind: 'text', title: 'ad-hoc', body: 'no fixed cid' })
  const after = (await r2.data.listPostsIn('p2p', { hydrate: false })).length
  ok(after === before + 2, 'two cid-less posts create two records — so idempotency above is due to the fixed cids, not a no-op')

  console.log(`\n✅ all ${passed} seed-idempotency checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
