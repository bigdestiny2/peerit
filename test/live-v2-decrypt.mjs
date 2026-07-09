// live-v2-decrypt.mjs — DETERMINISTIC half of the live round-trip. Pulls the seed
// author's ACTUAL opaque rows off the live relay over plain HTTP, then feeds them
// through the REAL client reconstruction (data._buildV2View → listPostsIn) to prove
// a reader decrypts the live-sealed content correctly. This isolates the v2 read
// logic from the flaky swarm discovery/replication layer.
//   RELAY=https://peerit-relay.onrender.com node test/live-v2-decrypt.mjs

import assert from 'node:assert'
import { createData } from '../js/data.js'
import { DevIdentity } from '../js/identity.js'
import { ready as cryptoReady } from '../js/crypto.js'

const RELAY = process.env.RELAY || 'https://peerit-relay.onrender.com'
const SEED_PUB = 'be48baf150598739bed1fa3cf20eba81331908e05b22e9578412b0219e9237e7'
const mem = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
let passed = 0; const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

async function main () {
  await cryptoReady()
  const tok = await (await fetch(RELAY + '/api/token', { method: 'POST' })).json()
  // Pull the seed author's raw outbox rows straight off the relay (what a reader replicates).
  const res = await fetch(RELAY + `/api/sync/range?appId=${SEED_PUB}&limit=500`, { headers: { 'x-pear-token': tok.token } })
  const body = await res.json()
  const rows = Array.isArray(body) ? body : (body.rows || body.data || [])
  console.log(`fetched ${rows.length} raw rows from the seed's live outbox`)
  // head!<pub> is the plaintext census record that registers the outbox in the relay
  // directory (version only, no content — deliberately cleartext). blob! is opaque body
  // storage. Everything ELSE the app writes must be an opaque v2!<okey>.
  const content = rows.filter(r => !/^head!|^blob!/.test(String(r.key)))
  ok(content.length >= 8, `the relay served the seed's content rows (${content.length} of ${rows.length} total)`)
  ok(content.every(r => String(r.key).startsWith('v2!')), 'every content row key is an opaque v2!<okey> (no plaintext structure)')
  ok(!JSON.stringify(rows).includes('Announcing peerit'), 'no post title is greppable in the raw rows (sealed at rest)')

  // Feed those exact rows through the REAL client reconstruction via a mock sync.
  const byPrefix = (prefix, limit = 5000) => rows.filter(r => String(r.key).startsWith(prefix)).slice(0, limit)
  const rawRange = (opts = {}) => {
    let out = rows.slice().sort((a, b) => a.key.localeCompare(b.key))
    if (opts.gte != null) out = out.filter(r => r.key >= opts.gte)
    if (opts.gt != null) out = out.filter(r => r.key > opts.gt)
    if (opts.lt != null) out = out.filter(r => r.key < opts.lt)
    return out.slice(0, Math.min(Number(opts.limit) || 100, 1000))
  }
  const sync = {
    ready: async () => {}, status: async () => ({}), mode: 'mock',
    list: async (prefix, { limit = 5000 } = {}) => byPrefix(prefix, limit),
    get: async (k) => { const r = rows.find(x => x.key === k); return r ? r.value : null },
    count: async (prefix) => byPrefix(prefix).length,
    range: async (opts = {}) => rawRange(opts), append: async () => {}
  }
  const id = new DevIdentity(mem(), mem()); await id.ready()
  const data = createData(sync, id, { v2: true })

  const view = await data._buildV2View()
  const keys = Object.keys(view)
  console.log('reconstructed keys:', keys)
  ok(keys.some(k => k === 'post!p2p!seed-peerit'), 'reconstructed post!p2p!seed-peerit from an opaque row')
  ok(keys.some(k => k.startsWith('community!')), 'reconstructed the community record(s)')

  const posts = await data.listPostsIn('p2p')
  const peerit = posts.find(p => p.cid === 'seed-peerit')
  ok(peerit, `listPostsIn('p2p') surfaced the seed post (${posts.length} posts)`)
  ok(/Announcing peerit/.test(peerit.title), 'its title DECRYPTS to "Announcing peerit — a peer-to-peer Reddit"')
  ok(/signed outboxes/.test(peerit.body || ''), 'its body DECRYPTS correctly')
  ok(peerit.author === SEED_PUB, 'authorship binds to the seed signer (_k), recovered from the sealed record')

  console.log(`\n✅ all ${passed} live-decrypt checks passed — the relay held only ciphertext; the client reconstructed the plaintext.`)
  process.exit(0)
}
main().catch(e => { console.error('❌', e.message, '\n', e.stack); process.exit(1) })
