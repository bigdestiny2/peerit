// relay-roster.js — signed relay roster verification + boot-time relay failover.
//
// The roster is an untrusted JSON document. Clients trust it only when its
// payload verifies against the Ed25519 public key pinned in the audited web
// bundle/meta. Relays remain availability providers: this chooses where to ask
// for `/api/*`, it never gives a relay authority over content or identity.

import { verify as edVerify } from './crypto.js'

export const ROSTER_META = 'peerit-relay-roster'
export const ROSTER_KEY_META = 'peerit-relay-roster-key'
export const ROSTER_ALG = 'Ed25519'
export const ROSTER_VERSION = 1

const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i
const LOCAL_HTTP = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

function defaultFetch () {
  return typeof fetch === 'function' ? fetch.bind(globalThis) : null
}

function stable (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v)
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']'
  const keys = Object.keys(v).sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}'
}

function metaContent (doc, name) {
  try {
    const el = doc && doc.querySelector && doc.querySelector('meta[name="' + name + '"]')
    return el ? (el.getAttribute('content') || '') : ''
  } catch {
    return ''
  }
}

export function normalizeRelayBase (value) {
  if (value == null) return null
  const raw = String(value).trim()
  if (!raw || raw === 'same-origin' || raw === '/') return ''
  let url
  try { url = new URL(raw) } catch { return null }
  if (url.search || url.hash) return null
  const localHttp = url.protocol === 'http:' && LOCAL_HTTP.has(url.hostname)
  if (url.protocol !== 'https:' && !localHttp) return null
  const path = url.pathname.replace(/\/+$/, '')
  return url.origin + (path && path !== '/' ? path : '')
}

export function dedupeRelayList (values) {
  const out = []
  const seen = new Set()
  for (const value of values || []) {
    const base = normalizeRelayBase(value)
    if (base === null) continue
    if (seen.has(base)) continue
    seen.add(base)
    out.push(base)
  }
  return out
}

export function parseRelayList (raw) {
  if (!raw) return []
  return dedupeRelayList(String(raw).split(',').map((s) => s.trim()).filter(Boolean))
}

export function readRelayRosterConfig (doc) {
  const url = metaContent(doc, ROSTER_META).trim()
  const key = metaContent(doc, ROSTER_KEY_META).trim().toLowerCase()
  return url || key ? { url, key } : null
}

export function normalizeRelayRosterPayload (payload = {}) {
  const version = Number(payload.version || ROSTER_VERSION)
  const expires = String(payload.expires || payload.expiresAt || '').trim()
  const relays = dedupeRelayList(payload.relays || [])
  return { version, expires, relays }
}

export function rosterSigningMessage (payload) {
  return 'peerit-relay-roster-v1|' + stable(normalizeRelayRosterPayload(payload))
}

function assertCanonicalPayload (raw, payload) {
  const keys = Object.keys(raw || {}).sort().join(',')
  if (keys !== 'expires,relays,version') throw new Error('relay roster payload is not canonical')
  if (raw.version !== payload.version || raw.expires !== payload.expires) throw new Error('relay roster payload is not canonical')
  if (!Array.isArray(raw.relays) || raw.relays.length !== payload.relays.length) throw new Error('relay roster payload is not canonical')
  for (let i = 0; i < raw.relays.length; i++) {
    if (String(raw.relays[i]).trim() !== payload.relays[i]) throw new Error('relay roster payload is not canonical')
  }
}

export async function verifyRelayRoster (roster, { expectedKey, now = Date.now() } = {}) {
  if (!roster || typeof roster !== 'object') throw new Error('relay roster must be an object')
  const key = String(expectedKey || '').trim().toLowerCase()
  if (!HEX64.test(key)) throw new Error('missing or invalid pinned relay roster key')

  if (!roster.payload || typeof roster.payload !== 'object') throw new Error('relay roster payload is missing')
  const payload = normalizeRelayRosterPayload(roster.payload)
  assertCanonicalPayload(roster.payload, payload)
  if (payload.version !== ROSTER_VERSION) throw new Error('unsupported relay roster version')
  if (!payload.relays.length) throw new Error('relay roster has no valid relays')

  const expiresMs = Date.parse(payload.expires)
  if (!Number.isFinite(expiresMs)) throw new Error('relay roster expires is invalid')
  if (expiresMs <= Number(now)) throw new Error('relay roster expired')

  const sig = roster.signature || {}
  const sigKey = String(sig.key || '').trim().toLowerCase()
  const sigHex = String(sig.sig || '').trim().toLowerCase()
  if (sig.alg !== ROSTER_ALG) throw new Error('unsupported relay roster signature algorithm')
  if (sigKey !== key) throw new Error('relay roster was signed by an unexpected key')
  if (!HEX128.test(sigHex)) throw new Error('relay roster signature is invalid')

  const ok = await edVerify(key, rosterSigningMessage(payload), sigHex)
  if (!ok) throw new Error('relay roster signature did not verify')
  return { payload, relays: payload.relays, key, expires: payload.expires }
}

export async function fetchRelayRoster ({ url, key, fetch: fetchFn = defaultFetch(), now } = {}) {
  if (!url || !key) return null
  if (typeof fetchFn !== 'function') throw new Error('fetch unavailable for relay roster')
  const res = await fetchFn(url, { cache: 'no-store' })
  if (!res || !res.ok) throw new Error('relay roster fetch failed')
  const roster = typeof res.json === 'function' ? await res.json() : JSON.parse(await res.text())
  return verifyRelayRoster(roster, { expectedKey: key, now })
}

export async function resolveRelayCandidates ({ relays = [], roster = null, rosterUrl = '', rosterKey = '', fetch: fetchFn = defaultFetch(), now, onWarning } = {}) {
  const staticRelays = dedupeRelayList(relays)
  const cfg = roster || (rosterUrl || rosterKey ? { url: rosterUrl, key: rosterKey } : null)
  let verified = null
  if (cfg && cfg.url && cfg.key) {
    try {
      verified = await fetchRelayRoster({ url: cfg.url, key: cfg.key, fetch: fetchFn, now })
    } catch (err) {
      if (typeof onWarning === 'function') onWarning(err)
    }
  }
  return {
    relays: dedupeRelayList([...(verified ? verified.relays : []), ...staticRelays]),
    roster: verified,
    rosterVerified: !!verified
  }
}

function apiUrl (apiBase, path) {
  return String(apiBase || '').replace(/\/+$/, '') + path
}

async function responseJson (res) {
  if (!res || !res.ok) return null
  if (typeof res.json === 'function') return res.json()
  const text = typeof res.text === 'function' ? await res.text() : ''
  return text ? JSON.parse(text) : null
}

export async function acquireRelayToken (apiBase, { fetch: fetchFn = defaultFetch() } = {}) {
  if (typeof fetchFn !== 'function') return null
  try {
    const json = await responseJson(await fetchFn(apiUrl(apiBase, '/api/token'), { method: 'POST' }))
    return json && typeof json.token === 'string' && json.token ? json.token : null
  } catch {
    return null
  }
}

export async function relayAcceptsToken (apiBase, token, { fetch: fetchFn = defaultFetch() } = {}) {
  if (!token || typeof fetchFn !== 'function') return false
  try {
    const res = await fetchFn(apiUrl(apiBase, '/api/bridge/status'), { headers: { 'X-Pear-Token': token } })
    return !!(res && res.ok)
  } catch {
    return false
  }
}

export async function selectRelay (relays, { apiToken = '', fetch: fetchFn = defaultFetch() } = {}) {
  for (const apiBase of dedupeRelayList(relays)) {
    if (apiToken) {
      if (await relayAcceptsToken(apiBase, apiToken, { fetch: fetchFn })) return { apiBase, apiToken }
      continue
    }
    const token = await acquireRelayToken(apiBase, { fetch: fetchFn })
    if (token) return { apiBase, apiToken: token }
  }
  return null
}

// Like selectRelay but returns UP TO `max` working relays (each with a token),
// primary first — the Phase B pool that writes fan out across and whose signed
// heads are cross-checked. With one configured relay this returns a pool of one
// (single-relay behaviour); the cross-relay guarantees switch on as the roster
// grows.
export async function selectRelays (relays, { apiToken = '', fetch: fetchFn = defaultFetch(), max = 3 } = {}) {
  const out = []
  for (const apiBase of dedupeRelayList(relays)) {
    if (out.length >= max) break
    if (apiToken) {
      if (await relayAcceptsToken(apiBase, apiToken, { fetch: fetchFn })) out.push({ apiBase, apiToken })
      continue
    }
    const token = await acquireRelayToken(apiBase, { fetch: fetchFn })
    if (token) out.push({ apiBase, apiToken: token })
  }
  return out
}
