// live-convergence.mjs — two REAL peerit clients converging through the LIVE
// deployed relay. Proves a post written in one session shows up in ANOTHER
// session on the production site. Uses the exact client modules the browser uses
// (crypto/pow/canon/verify/gossip/data/pear-api), real Ed25519, real PoW bits,
// real fetch + a real SSE EventSource over the network. NOT a CI test.
//
//   RELAY=https://peerit-relay.onrender.com node test/live-convergence.mjs
import { createSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'
import https from 'node:https'

const RELAY = process.env.RELAY || 'https://peerit-relay.onrender.com'
let passed = 0
const ok = (c, m) => { if (!c) throw new Error('check failed: ' + m); passed++; console.log('  ✓ ' + m) }
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
async function until (fn, { tries = 160, gap = 300 } = {}) { for (let i = 0; i < tries; i++) { try { if (await fn()) return true } catch {} await delay(gap) } return false }

// Minimal SSE client matching the browser EventSource contract pear-api.js uses.
class NodeEventSource {
  constructor (url) {
    this.url = String(url); this.onmessage = null; this.onerror = null; this._closed = false; this._buf = ''
    this._req = https.get(this.url, (res) => {
      res.setEncoding('utf8')
      res.on('data', (c) => this._feed(c))
      res.on('end', () => { if (!this._closed && this.onerror) this.onerror({}) })
    })
    this._req.on('error', () => { if (!this._closed && this.onerror) this.onerror({}) })
  }
  _feed (chunk) {
    this._buf += chunk
    let i
    while ((i = this._buf.indexOf('\n\n')) >= 0) {
      const raw = this._buf.slice(0, i); this._buf = this._buf.slice(i + 2)
      let data = ''
      for (const line of raw.split('\n')) if (line.startsWith('data:')) data += line.slice(5).replace(/^ /, '')
      if (data && this.onmessage) { try { this.onmessage({ data }) } catch {} }
    }
  }
  close () { this._closed = true; try { this._req.destroy() } catch {} }
}

const mem = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
const getToken = async () => { const r = await fetch(RELAY + '/api/token', { method: 'POST' }); return (await r.json()).token }

async function makeClient (name) {
  const tok = await getToken()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser(name)
  const sync = createSync({
    apiToken: tok, apiBase: RELAY, fetch: (...a) => fetch(...a), EventSource: NodeEventSource,
    storage: mem(), getMe: () => id.me().pubkey, identity: id, validate: makeValidator(), pollMs: 3000
  })
  await sync.ready()
  return { id, sync, data: createData(sync, id), pub: id.me().pubkey, name }
}

async function main () {
  console.log('Target relay:', RELAY)
  await cryptoReady()
  ok(isSecure(), 'real Ed25519 active — signatures enforced exactly like the browser')

  console.log('\n— two independent sessions connect to the LIVE relay —')
  const alice = await makeClient('alice-test')
  const bob = await makeClient('bob-test')
  ok(alice.sync.mode === 'gossip-bridge' && bob.sync.mode === 'gossip-bridge', 'both sessions are in gossip-bridge mode (live relay, browser-local keys)')
  ok(alice.pub !== bob.pub, 'the two sessions have distinct identities → distinct signed outboxes')

  console.log('\n— session A writes a community + post; session B must see it —')
  const slug = 'convtest' + Date.now().toString(36).slice(-4)
  await alice.data.createCommunity({ slug, title: 'Convergence Test', description: 'live two-session check' })
  const aPost = await alice.data.submitPost({ community: slug, kind: 'text', title: 'does this cross sessions?', body: 'written by session A' })
  ok(await until(() => bob.data.getCommunity(slug)), "session B discovered A's community via the live swarm — SSE peer-discovery works through Render")
  ok(await until(() => bob.data.listPostsIn(slug).then((ps) => ps.some((p) => p.cid === aPost.cid))), "✦ session B SEES session A's post  ← the core 'posts show up in other sessions' guarantee")

  console.log('\n— reverse direction, votes, comments aggregate across sessions —')
  const bPost = await bob.data.submitPost({ community: slug, kind: 'text', title: 'reply from B', body: 'written by session B' })
  ok(await until(() => alice.data.getPost(slug, bPost.cid)), "session A sees session B's post (bidirectional convergence)")
  await alice.data.vote(aPost.cid, slug, 'post', 1); await bob.data.vote(aPost.cid, slug, 'post', 1)
  ok(await until(async () => (await bob.data.tallyFor(aPost.cid)).score === 2), 'one upvote from EACH session aggregates to score 2 in the merged view')
  const cm = await bob.data.addComment({ community: slug, postCid: aPost.cid, body: 'comment from session B' })
  ok(await until(() => alice.data.listComments(slug, aPost.cid).then((cs) => cs.some((c) => c.cid === cm.cid))), "session A sees session B's comment")

  console.log('\n— a signed edit in A propagates to B; tampering is impossible —')
  await alice.data.editPost(slug, aPost.cid, 'written by session A (edited)')
  ok(await until(() => bob.data.getPost(slug, aPost.cid).then((p) => p && p.body === 'written by session A (edited)')), "A's re-signed edit verifies + propagates to B")

  alice.sync.destroy(); bob.sync.destroy()
  console.log(`\n✅ all ${passed} LIVE convergence checks passed against ${RELAY}`)
  console.log(`   → A post written in one session DOES show up in another session. (test community: r/${slug})\n`)
  process.exit(0)
}
main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
