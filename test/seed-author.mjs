// seed-author.mjs — a real peerit client (one identity/outbox) that creates
// communities + posts on the LIVE network with real Ed25519 + real PoW, then
// STAYS ONLINE so its outbox keeps being announced and remains discoverable by
// browser/other sessions. Same client code the browser runs; Node just does PoW
// in ~1s instead of ~90s. Kill the process to stop announcing.
//   RELAY=https://peerit-relay.onrender.com node test/seed-author.mjs
import { createSync } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { makeValidator } from '../js/pow.js'
import https from 'node:https'

const RELAY = process.env.RELAY || 'https://peerit-relay.onrender.com'
class NodeEventSource {
  constructor (url) { this.url = String(url); this.onmessage = null; this.onerror = null; this._closed = false; this._buf = ''
    this._req = https.get(this.url, (res) => { res.setEncoding('utf8'); res.on('data', (c) => this._feed(c)); res.on('end', () => { if (!this._closed && this.onerror) this.onerror({}) }) })
    this._req.on('error', () => { if (!this._closed && this.onerror) this.onerror({}) }) }
  _feed (chunk) { this._buf += chunk; let i; while ((i = this._buf.indexOf('\n\n')) >= 0) { const raw = this._buf.slice(0, i); this._buf = this._buf.slice(i + 2); let d = ''; for (const ln of raw.split('\n')) if (ln.startsWith('data:')) d += ln.slice(5).replace(/^ /, ''); if (d && this.onmessage) { try { this.onmessage({ data: d }) } catch {} } } }
  close () { this._closed = true; try { this._req.destroy() } catch {} }
}
const mem = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear() } }
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a)

async function main () {
  await cryptoReady()
  const tok = await (await fetch(RELAY + '/api/token', { method: 'POST' })).json()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser('p2p-announcer')
  const sync = createSync({ apiToken: tok.token, apiBase: RELAY, fetch: (...a) => fetch(...a), EventSource: NodeEventSource, storage: mem(), getMe: () => id.me().pubkey, identity: id, validate: makeValidator(), pollMs: 4000 })
  await sync.ready()
  const data = createData(sync, id)
  log('author', id.me().pubkey.slice(0, 12), 'mode', sync.mode, '→', RELAY)

  log('creating r/p2p …')
  await data.createCommunity({ slug: 'p2p', title: 'P2P', description: 'The peer-to-peer stack — apps, browsers, and infrastructure with no servers. Announcements & discussion.' })
  for (const p of [
    { title: 'Announcing peerit — a peer-to-peer Reddit', body: 'Communities, posts, comments and votes live in per-user signed outboxes that replicate directly between peers — no servers, no database to seize. Run it in PearBrowser for pure P2P, or open peerit.site in any normal browser. Every record is verified in your own browser, so a relay can carry data but can never forge or tamper.' },
    { title: 'Announcing Pear Browser — the browser for the P2P web', body: 'Browse hyper:// sites, run pear:// apps, and publish your own — no app store gatekeepers. Sites are plain folders served over Hyperdrive and pinned 24/7 by HiveRelay. peerit itself runs as a Pear site inside it.' },
    { title: 'Announcing HiveRelay — always-on availability for P2P apps', body: 'A blind-encrypted seeding + multi-region relay backbone that keeps P2P apps and their data online even when authors are offline. Operators are paid in Lightning sats. This is what keeps peerit.site reachable from a normal browser.' }
  ]) { const r = await data.submitPost({ community: 'p2p', kind: 'text', title: p.title, body: p.body }); log('  posted to r/p2p:', p.title, '→', r.cid) }

  log('creating r/worldcup …')
  await data.createCommunity({ slug: 'worldcup', title: 'World Cup', description: 'Match threads, reactions, and debate.' })
  for (const p of [
    { title: 'Semi-finals are set — who reaches the final?', body: 'Both semi-finals of the knockout round are locked in. Drop your predictions: who goes through to the final, and who bows out at the last four? Tactical takes welcome.' },
    { title: 'Semi-final 2: live match thread', body: 'Reactions for the second semi-final here. Who is looking sharp, who is parking the bus, and is this heading to extra time? Keep it in one thread.' }
  ]) { const r = await data.submitPost({ community: 'worldcup', kind: 'text', title: p.title, body: p.body }); log('  posted to r/worldcup:', p.title, '→', r.cid) }

  const st = await sync.status()
  log('DONE. outbox has', st.viewLength, 'records; merged view sees', st.peers, 'sessions.')
  log('STAYING ONLINE so r/p2p + r/worldcup remain discoverable. Kill this process to stop.')
  setInterval(async () => { try { const s = await sync.status(); log('heartbeat — online, peers in view:', s.peers) } catch {} }, 30000)
}
main().catch((e) => { console.error('❌', e.message, '\n', e.stack); process.exit(1) })
