// live-reader.mjs — a FRESH independent session (new identity) joins the live
// swarm and checks whether it can see content created by ANOTHER live session
// (e.g. the browser at peerit.site). Proves "posts show up in other sessions"
// against whatever is currently online. Pass the community slug to look for.
//   SLUG=livedemo node test/live-reader.mjs
import { createSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'
import https from 'node:https'

const RELAY = process.env.RELAY || 'https://peerit-relay.onrender.com'
const SLUG = process.env.SLUG || 'livedemo'
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
async function until (fn, { tries = 120, gap = 500 } = {}) { for (let i = 0; i < tries; i++) { try { const v = await fn(); if (v) return v } catch {} await delay(gap) } return null }

class NodeEventSource {
  constructor (url) {
    this.url = String(url); this.onmessage = null; this.onerror = null; this._closed = false; this._buf = ''
    this._req = https.get(this.url, (res) => { res.setEncoding('utf8'); res.on('data', (c) => this._feed(c)); res.on('end', () => { if (!this._closed && this.onerror) this.onerror({}) }) })
    this._req.on('error', () => { if (!this._closed && this.onerror) this.onerror({}) })
  }
  _feed (chunk) { this._buf += chunk; let i; while ((i = this._buf.indexOf('\n\n')) >= 0) { const raw = this._buf.slice(0, i); this._buf = this._buf.slice(i + 2); let d = ''; for (const ln of raw.split('\n')) if (ln.startsWith('data:')) d += ln.slice(5).replace(/^ /, ''); if (d && this.onmessage) { try { this.onmessage({ data: d }) } catch {} } } }
  close () { this._closed = true; try { this._req.destroy() } catch {} }
}
const mem = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
const getToken = async () => (await (await fetch(RELAY + '/api/token', { method: 'POST' })).json()).token

async function main () {
  await cryptoReady()
  const tok = await getToken()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser('reader-sessionB')
  const sync = createSync({ apiToken: tok, apiBase: RELAY, fetch: (...a) => fetch(...a), EventSource: NodeEventSource, storage: mem(), getMe: () => id.me().pubkey, identity: id, validate: makeValidator(), pollMs: 2500 })
  await sync.ready()
  const data = createData(sync, id)
  console.log('Fresh session B identity :', id.me().pubkey.slice(0, 12) + '…   mode:', sync.mode)
  console.log(`Joining the live swarm and looking for r/${SLUG} created by another session…\n`)

  const community = await until(() => data.getCommunity(SLUG))
  console.log('  r/' + SLUG + ' discovered from another session :', community ? 'YES — "' + community.title + '"' : 'NO')
  if (community) {
    const posts = await until(async () => { const ps = await data.listPostsIn(SLUG); return ps.length ? ps : null }) || []
    for (const p of posts) console.log('    • post seen across sessions  : "' + p.title + '"  by u/' + String(p.author || p._k || '').slice(0, 8))
    const st = await sync.status()
    console.log('\n  outboxes in session B\'s merged view:', st.peers, '(self + remote sessions)')
  }
  sync.destroy()
  console.log(community ? '\n✅ a post written in another live session showed up in this fresh session.' : '\n⚠️ nothing discovered — is a session that created r/' + SLUG + ' still open/online?')
  process.exit(0)
}
main().catch((e) => { console.error('❌', e.message); process.exit(1) })
