// seed-author.mjs — REPOPULATE peerit.site's core communities/posts. A real peerit
// client (one STABLE identity/outbox) that (re)creates r/p2p + r/worldcup on the LIVE
// network with real Ed25519 + real PoW, then STAYS ONLINE so its outbox keeps being
// announced and remains discoverable. Same client code the browser runs; Node just
// does PoW in ~1s instead of ~90s. Kill the process to stop announcing.
//
//   RELAY=https://peerit-relay.onrender.com node test/seed-author.mjs
//
// IDEMPOTENT + STABLE (the "keep in the pocket, fire when ready" repopulate):
//  • the author identity is PERSISTED to .seed-author-store.json (gitignored, holds
//    the secret seed) — so every run is the SAME author, never a fresh claimant. This
//    kills the sticky-community-claim churn (r/p2p/worldcup always owned by this key).
//  • each seed post uses a DETERMINISTIC cid, so a re-run overwrites the same post key
//    (LWW) instead of creating duplicates. Run it as many times as you like.
// PREREQUISITE before firing: confirm the relay's PEERIT_RELAY_PERSIST disk actually
// survives restarts — otherwise the reseed gets wiped on the next recycle.

import { createSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'
import https from 'node:https'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

const RELAY = process.env.RELAY || 'https://peerit-relay.onrender.com'
const STORE_PATH = process.env.SEED_STORE || fileURLToPath(new URL('../.seed-author-store.json', import.meta.url))

// The canonical seed content. Deterministic cids → idempotent re-runs.
export const SEED = {
  p2p: {
    title: 'P2P',
    description: 'The peer-to-peer stack — apps, browsers, and infrastructure with no servers. Announcements & discussion.',
    posts: [
      { cid: 'seed-peerit', title: 'Announcing peerit — a peer-to-peer Reddit', body: 'Communities, posts, comments and votes live in per-user signed outboxes that replicate directly between peers — no servers, no database to seize. Run it in PearBrowser for pure P2P, or open peerit.site in any normal browser. Every record is verified in your own browser, so a relay can carry data but can never forge or tamper.' },
      { cid: 'seed-pearbrowser', title: 'Announcing Pear Browser — the browser for the P2P web', body: 'Browse hyper:// sites, run pear:// apps, and publish your own — no app store gatekeepers. Sites are plain folders served over Hyperdrive and pinned 24/7 by HiveRelay. peerit itself runs as a Pear site inside it.' },
      { cid: 'seed-hiverelay', title: 'Announcing HiveRelay — always-on availability for P2P apps', body: 'A blind-encrypted seeding + multi-region relay backbone that keeps P2P apps and their data online even when authors are offline. Operators are paid in Lightning sats. This is what keeps peerit.site reachable from a normal browser.' },
      { cid: 'seed-whatsnew', title: "What's new: encrypted-at-rest bodies + Follow", body: 'Long post/comment bodies are now boxed — stored as opaque ciphertext the relay holds but never reads (a step toward the operator serving nothing). You can also follow authors from their profile and read a Following feed. Push notifications and full erasure-coded dispersal are on the way.' }
    ]
  },
  worldcup: {
    title: 'World Cup',
    description: 'Match threads, reactions, and debate.',
    posts: [
      { cid: 'seed-semis', title: 'Semi-finals are set — who reaches the final?', body: 'Both semi-finals of the knockout round are locked in. Drop your predictions: who goes through to the final, and who bows out at the last four? Tactical takes welcome.' },
      { cid: 'seed-semi2', title: 'Semi-final 2: live match thread', body: 'Reactions for the second semi-final here. Who is looking sharp, who is parking the bus, and is this heading to extra time? Keep it in one thread.' }
    ]
  }
}

// Retry a write through transient relay backpressure (429 / fetch failed) with
// exponential backoff, so a busy relay doesn't abort the whole seed mid-run.
async function withRetry (fn, log, tries = 7, base = 2500) {
  for (let i = 0; ; i++) {
    try { return await fn() } catch (e) {
      const msg = (e && e.message) || ''
      if (i >= tries - 1 || !/rate limit|429|fetch failed|timeout|unavailable/i.test(msg)) throw e
      const wait = Math.round(base * Math.pow(1.7, i))
      log(`  … ${msg}; backing off ${Math.round(wait / 1000)}s (try ${i + 2}/${tries})`)
      await new Promise(r => setTimeout(r, wait))
    }
  }
}

// Apply the seed to a Data instance. Idempotent: a re-run reuses the existing
// community and overwrites each post at its deterministic cid (no duplicates).
export async function seedContent (data, { log = () => {} } = {}) {
  let communities = 0, posts = 0
  for (const [slug, comm] of Object.entries(SEED)) {
    try { await withRetry(() => data.createCommunity({ slug, title: comm.title, description: comm.description }), log); communities++; log('created r/' + slug) }
    catch (e) { if (/already exists/.test(e.message || '')) log('r/' + slug + ' exists — reusing'); else throw e }
    for (const p of comm.posts) {
      const r = await withRetry(() => data.submitPost({ community: slug, kind: 'text', title: p.title, body: p.body, cid: p.cid }), log)
      posts++; log('  r/' + slug + '/' + r.cid, '—', p.title.slice(0, 42))
    }
  }
  return { communities, posts }
}

// ---- live-network runner (executed only when this file is run directly) -----
const mem = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
// A localStorage-like store backed by a JSON file — persists the author's seed so
// every run is the SAME identity. HOLDS A SECRET; the path is gitignored.
function fileStore (path) {
  let data = {}
  try { data = JSON.parse(fs.readFileSync(path, 'utf8')) || {} } catch {}
  const save = () => { try { fs.writeFileSync(path, JSON.stringify(data)) } catch (e) { console.warn('seed store write failed:', e && e.message) } }
  return { getItem: (k) => (k in data ? data[k] : null), setItem: (k, v) => { data[k] = String(v); save() }, removeItem: (k) => { delete data[k]; save() }, clear: () => { data = {}; save() } }
}
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a)

class NodeEventSource {
  constructor (url) { this.url = String(url); this.onmessage = null; this.onerror = null; this._closed = false; this._buf = ''
    this._req = https.get(this.url, (res) => { res.setEncoding('utf8'); res.on('data', (c) => this._feed(c)); res.on('end', () => { if (!this._closed && this.onerror) this.onerror({}) }) })
    this._req.on('error', () => { if (!this._closed && this.onerror) this.onerror({}) }) }
  _feed (chunk) { this._buf += chunk; let i; while ((i = this._buf.indexOf('\n\n')) >= 0) { const raw = this._buf.slice(0, i); this._buf = this._buf.slice(i + 2); let d = ''; for (const ln of raw.split('\n')) if (ln.startsWith('data:')) d += ln.slice(5).replace(/^ /, ''); if (d && this.onmessage) { try { this.onmessage({ data: d }) } catch {} } } }
  close () { this._closed = true; try { this._req.destroy() } catch {} }
}

async function main () {
  await cryptoReady()
  const tok = await (await fetch(RELAY + '/api/token', { method: 'POST' })).json()
  // Persisted store => ready() re-loads the SAME author every run (never appends).
  const id = new DevIdentity(fileStore(STORE_PATH), mem()); await id.ready()
  // writeHead:true — write a signed head!<me> census record after each write, EXACTLY as
  // the browser app does (js/app.js). This registers the outbox in the relay directory so
  // the relay durably replays its swarm descriptor to fresh readers. Without it the seed's
  // content is on the relay but effectively undiscoverable (its descriptor is only in the
  // relay's ephemeral in-memory swarm state → flaky/absent replay). pollMs low so a fresh
  // reader's join surfaces quickly. The throttled join queue (js/gossip.js) keeps the boot
  // descriptor burst under the relay's per-IP rate limit.
  const sync = createSync({ apiToken: tok.token, apiBase: RELAY, fetch: (...a) => fetch(...a), EventSource: NodeEventSource, storage: mem(), getMe: () => id.me().pubkey, identity: id, validate: makeValidator(), pollMs: 4000, writeHead: true })
  await sync.ready()
  const data = createData(sync, id, { v2: process.env.SEED_V2 !== '0' }) // reseed as blind v2 records by default (SEED_V2=0 for legacy v1)
  log('author', id.me().pubkey.slice(0, 12), '(stable, from', STORE_PATH.split('/').pop() + ')', 'mode', sync.mode, '→', RELAY)

  const res = await seedContent(data, { log })
  const st = await sync.status()
  log('DONE — seeded', res.communities, 'communities +', res.posts, 'posts; outbox has', st.viewLength, 'records.')
  log('STAYING ONLINE so the content remains discoverable. Kill this process to stop.')
  setInterval(async () => { try { const s = await sync.status(); log('heartbeat — online, peers in view:', s.peers) } catch {} }, 30000)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((e) => { console.error('❌', e.message, '\n', e.stack); process.exit(1) })
}
