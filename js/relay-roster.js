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
export const RELAY_PROBE_TIMEOUT_MS = 5000

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
  if (url.username || url.password) return null
  const localHttp = url.protocol === 'http:' && LOCAL_HTTP.has(url.hostname)
  if (url.protocol !== 'https:' && !localHttp) return null
  const path = url.pathname.replace(/\/+$/, '')
  return url.origin + (path && path !== '/' ? path : '')
}

// Writer independence is origin-level, not URL-string-level. Two roster entries
// such as https://relay.example/a and /b are one failure domain and can never
// satisfy a two-relay quorum.
export function canonicalRelayOrigin (value) {
  const base = normalizeRelayBase(value)
  if (base === null || base === '') return null
  try { return new URL(base).origin } catch { return null }
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

const RELAY_TOPOLOGY_PROPERTY = '__peeritRelayTopology'

function buildRelayTopology (relays, { key = '' } = {}) {
  const entries = relays.map((apiBase, rosterIndex) => ({
    apiBase,
    rosterIndex,
    canonicalOrigin: canonicalRelayOrigin(apiBase)
  }))
  const origins = entries.map((entry) => entry.canonicalOrigin)
  const unique = new Set(origins.filter(Boolean))
  const valid = entries.length >= 2 && origins.every(Boolean) && unique.size === entries.length
  return {
    schema: 1,
    verified: true,
    // `stable` means the full ordered topology came from one successfully
    // verified, unexpired roster. Static fallback relays never receive it.
    stable: true,
    // Expiry renewal does not reshuffle authors. Only a signed topology/key
    // change moves the deterministic leader.
    id: `peerit-roster-v1|${key}|${relays.join('\x01')}`,
    size: entries.length,
    origins,
    entries,
    validWriterTopology: valid
  }
}

function attachRelayTopology (relays, topology) {
  if (!Array.isArray(relays) || !topology) return relays
  try {
    Object.defineProperty(relays, RELAY_TOPOLOGY_PROPERTY, {
      value: topology,
      enumerable: false,
      configurable: false,
      writable: false
    })
  } catch {}
  return relays
}

export function relayTopology (relays) {
  return (relays && relays[RELAY_TOPOLOGY_PROPERTY]) || null
}

// The roster META may hold a COMMA-LIST of URLs (same-origin file + independent
// mirrors, e.g. an IPFS gateway). Each is fetched and verified against the SAME
// pinned key, so a mirror can't forge — multi-homing only removes the single
// fetch chokepoint (entry-point blocking), never adds trust. Roster URLs keep
// their path/filename (unlike relay API bases), so they are NOT normalizeRelayBase'd.
export function parseRosterUrls (raw) {
  if (!raw) return []
  const out = []; const seen = new Set()
  for (const s of String(raw).split(',').map((x) => x.trim()).filter(Boolean)) {
    if (seen.has(s)) continue
    seen.add(s); out.push(s)
  }
  return out
}

export function readRelayRosterConfig (doc) {
  const url = metaContent(doc, ROSTER_META).trim()
  const key = metaContent(doc, ROSTER_KEY_META).trim().toLowerCase()
  if (!url && !key) return null
  const urls = parseRosterUrls(url)
  return { url: urls[0] || '', urls, key }
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
  return {
    payload,
    relays: payload.relays,
    key,
    expires: payload.expires,
    topology: buildRelayTopology(payload.relays, { key, expires: payload.expires })
  }
}

function timeoutError (label) {
  const error = new Error(label + ' timed out')
  error.code = 'RELAY_REQUEST_TIMEOUT'
  return error
}

async function boundedFetch (fetchFn, url, init = {}, timeoutMs = RELAY_PROBE_TIMEOUT_MS) {
  const ms = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0 ? Number(timeoutMs) : RELAY_PROBE_TIMEOUT_MS
  const controller = typeof AbortController === 'function' ? new AbortController() : null
  const request = { ...init, redirect: 'error', ...(controller ? { signal: controller.signal } : {}) }
  let timer = null
  const timedOut = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      try { if (controller) controller.abort() } catch {}
      reject(timeoutError('relay request'))
    }, ms)
  })
  try {
    return await Promise.race([Promise.resolve().then(() => fetchFn(url, request)), timedOut])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

async function boundedValue (operation, timeoutMs = RELAY_PROBE_TIMEOUT_MS) {
  const ms = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0 ? Number(timeoutMs) : RELAY_PROBE_TIMEOUT_MS
  let timer = null
  const timedOut = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(timeoutError('relay response body')), ms)
  })
  try {
    return await Promise.race([Promise.resolve().then(operation), timedOut])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function checkedResponseOrigin (res, requestedUrl) {
  if (!res) throw new Error('relay returned no response')
  if (res.redirected === true) throw new Error('relay redirect rejected')
  let requestedOrigin = null
  let finalOrigin = null
  try { requestedOrigin = new URL(String(requestedUrl), globalThis.location && globalThis.location.href).origin } catch {}
  if (res.url) {
    try { finalOrigin = new URL(String(res.url)).origin } catch { throw new Error('relay final URL is invalid') }
  }
  if (requestedOrigin && finalOrigin && requestedOrigin !== finalOrigin) throw new Error('relay final origin mismatch')
  return finalOrigin || requestedOrigin
}

export async function fetchRelayRoster ({ url, key, fetch: fetchFn = defaultFetch(), now, timeoutMs = RELAY_PROBE_TIMEOUT_MS } = {}) {
  if (!url || !key) return null
  if (typeof fetchFn !== 'function') throw new Error('fetch unavailable for relay roster')
  const res = await boundedFetch(fetchFn, url, { cache: 'no-store' }, timeoutMs)
  checkedResponseOrigin(res, url)
  if (!res || !res.ok) throw new Error('relay roster fetch failed')
  const roster = await boundedValue(async () => typeof res.json === 'function' ? res.json() : JSON.parse(await res.text()), timeoutMs)
  return verifyRelayRoster(roster, { expectedKey: key, now })
}

// Try each roster URL in order; return the FIRST payload that verifies against the
// pinned key. Per-URL failures are reported via onWarning; all-fail returns null.
export async function fetchRelayRosterMulti ({ urls = [], key, fetch: fetchFn = defaultFetch(), now, onWarning, timeoutMs = RELAY_PROBE_TIMEOUT_MS } = {}) {
  const list = parseRosterUrls(Array.isArray(urls) ? urls.join(',') : urls)
  if (!list.length || !key) return null
  for (const url of list) {
    try {
      const verified = await fetchRelayRoster({ url, key, fetch: fetchFn, now, timeoutMs })
      if (verified) return verified
    } catch (err) {
      if (typeof onWarning === 'function') onWarning(err)
    }
  }
  return null
}

export async function resolveRelayCandidates ({ relays = [], roster = null, rosterUrl = '', rosterUrls = null, rosterKey = '', fetch: fetchFn = defaultFetch(), now, onWarning, timeoutMs = RELAY_PROBE_TIMEOUT_MS } = {}) {
  const staticRelays = dedupeRelayList(relays)
  const cfg = roster || ((rosterUrl || rosterUrls || rosterKey) ? { url: rosterUrl, urls: rosterUrls, key: rosterKey } : null)
  let verified = null
  if (cfg && cfg.key) {
    // Prefer the multi-URL list; fall back to the single `url` for older callers.
    const urls = (cfg.urls && cfg.urls.length) ? cfg.urls : (cfg.url ? [cfg.url] : [])
    if (urls.length) verified = await fetchRelayRosterMulti({ urls, key: cfg.key, fetch: fetchFn, now, onWarning, timeoutMs })
  }
  const resolved = dedupeRelayList([...(verified ? verified.relays : []), ...staticRelays])
  attachRelayTopology(resolved, verified && verified.topology)
  return {
    relays: resolved,
    roster: verified,
    rosterVerified: !!verified,
    topology: verified ? verified.topology : null
  }
}

function apiUrl (apiBase, path) {
  return String(apiBase || '').replace(/\/+$/, '') + path
}

async function responseJson (res, timeoutMs = RELAY_PROBE_TIMEOUT_MS) {
  if (!res || !res.ok) return null
  return boundedValue(async () => {
    if (typeof res.json === 'function') return res.json()
    const text = typeof res.text === 'function' ? await res.text() : ''
    return text ? JSON.parse(text) : null
  }, timeoutMs)
}

async function acquireRelayTokenDetailed (apiBase, { fetch: fetchFn = defaultFetch(), timeoutMs = RELAY_PROBE_TIMEOUT_MS } = {}) {
  if (typeof fetchFn !== 'function') return null
  try {
    const requestUrl = apiUrl(apiBase, '/api/token')
    const res = await boundedFetch(fetchFn, requestUrl, { method: 'POST' }, timeoutMs)
    const finalOrigin = checkedResponseOrigin(res, requestUrl)
    const json = await responseJson(res, timeoutMs)
    if (!json || typeof json.token !== 'string' || !json.token) return null
    const expiresAt = Number(json.expiresAt)
    const ttlMs = Number(json.ttlMs)
    return {
      token: json.token,
      finalOrigin,
      expiresAt: Number.isSafeInteger(expiresAt) && expiresAt > 0 ? expiresAt : 0,
      ttlMs: Number.isSafeInteger(ttlMs) && ttlMs > 0 ? ttlMs : 0
    }
  } catch {
    return null
  }
}

export async function acquireRelayToken (apiBase, opts = {}) {
  const result = await acquireRelayTokenDetailed(apiBase, opts)
  return result ? result.token : null
}

export async function relayAcceptsToken (apiBase, token, { fetch: fetchFn = defaultFetch() } = {}) {
  return !!(await relayStatus(apiBase, token, { fetch: fetchFn }))
}

// Exact writable contract advertised by HiveRelay. A truthy/partial descriptor
// is not enough: every property is part of the safety boundary used before a
// relay is admitted to an atomic writer pool.
export function hasDurableAtomicCommit (body) {
  const atomic = body && body.atomicCommit
  const idempotency = atomic && atomic.idempotency
  const legacy = body && body.legacyWrites
  return !!(
    body && body.ready === true && atomic && atomic.schema === 1 && atomic.method === 'POST' &&
    atomic.route === '/api/sync/commit' && atomic.enabled === true &&
    atomic.durable === true && atomic.cas === true && atomic.idempotent === true &&
    idempotency && idempotency.mode === 'bounded' && idempotency.latestPerOutbox === true &&
    Number.isSafeInteger(idempotency.hotReceiptsPerOutbox) && idempotency.hotReceiptsPerOutbox >= 1 &&
    Number.isSafeInteger(idempotency.tombstonesPerOutbox) && idempotency.tombstonesPerOutbox >= 0 &&
    Number.isSafeInteger(idempotency.aggregateEntries) && idempotency.aggregateEntries >= 2 &&
    Number.isSafeInteger(idempotency.extraHistoryEntries) && idempotency.extraHistoryEntries >= 0 &&
    legacy && legacy.create === false && legacy.append === false
  )
}

export async function relayStatus (apiBase, token, { fetch: fetchFn = defaultFetch(), timeoutMs = RELAY_PROBE_TIMEOUT_MS } = {}) {
  if (!token || typeof fetchFn !== 'function') return false
  try {
    const requestUrl = apiUrl(apiBase, '/api/bridge/status')
    const res = await boundedFetch(fetchFn, requestUrl, { headers: { 'X-Pear-Token': token } }, timeoutMs)
    const finalOrigin = checkedResponseOrigin(res, requestUrl)
    if (!res || !res.ok) return null
    const body = await responseJson(res, timeoutMs)
    if (!body || typeof body !== 'object') return null
    try { Object.defineProperty(body, '__peeritTransport', { value: { finalOrigin }, enumerable: false }) } catch {}
    return body
  } catch {
    return null
  }
}

// Boot resilience: probe every relay ONCE per pass (fast failover), but if a whole
// pass finds NO reachable relay — the common case being the relay's per-IP rate
// limit tripped by the cold-boot fan-out + a quick refresh — retry the pass with
// capped exponential backoff instead of dropping the visitor to an empty local-only
// feed. A genuinely-down fleet still falls through after a bounded delay.
export async function selectRelaysResilient (relays, { apiToken = '', tokenCache = null, fetch: fetchFn = defaultFetch(), max = 3, tries = 4, baseMs = 500, capMs = 4000, timeoutMs = RELAY_PROBE_TIMEOUT_MS, topology = relayTopology(relays) } = {}) {
  // A deterministic leader is selected from the entire signed roster. Probe at
  // least that many candidates even when the legacy read-pool default is three,
  // otherwise a healthy fourth roster leader would be reported unavailable.
  const requiredMax = topology && topology.verified === true && topology.stable === true && topology.validWriterTopology === true
    ? Math.max(max, Number(topology.size) || 0)
    : max
  for (let i = 0; ; i++) {
    const out = await selectRelays(relays, { apiToken, tokenCache, fetch: fetchFn, max: requiredMax, timeoutMs, topology })
    if (out.length || i >= tries - 1) return out
    await new Promise((resolve) => setTimeout(resolve, Math.min(capMs, baseMs * Math.pow(2, i))))
  }
}

export async function selectRelay (relays, opts = {}) {
  const selected = await selectRelays(relays, { ...opts, max: 1 })
  return selected[0] || null
}

// Like selectRelay but returns UP TO `max` working relays (each with a token),
// primary first — the Phase B pool that writes fan out across and whose signed
// heads are cross-checked. With one configured relay this returns a pool of one
// (single-relay behaviour); the cross-relay guarantees switch on as the roster
// grows.
export async function selectRelays (relays, { apiToken = '', tokenCache = null, fetch: fetchFn = defaultFetch(), max = 3, timeoutMs = RELAY_PROBE_TIMEOUT_MS, topology = relayTopology(relays) } = {}) {
  const out = []
  const seenOrigins = new Set()
  for (const apiBase of dedupeRelayList(relays)) {
    if (out.length >= max) break
    let token = apiToken
    let tokenOrigin = null
    let tokenExpiresAt = 0
    let cached = null
    if (apiToken) {
      token = apiToken
    } else {
      cached = readRelayTokenCache(tokenCache, apiBase)
      if (cached) {
        token = cached.token
        tokenOrigin = cached.finalOrigin || null
        tokenExpiresAt = cached.expiresAt || 0
      } else {
        deleteRelayTokenCache(tokenCache, apiBase)
        const acquired = await acquireRelayTokenDetailed(apiBase, { fetch: fetchFn, timeoutMs })
        if (!acquired) continue
        token = acquired.token
        tokenOrigin = acquired.finalOrigin
        tokenExpiresAt = acquired.expiresAt
        cached = acquired
      }
    }
    let status = await relayStatus(apiBase, token, { fetch: fetchFn, timeoutMs })
    // A cached stateless token may have expired while the tab slept. Reissue
    // once on admission failure; normal 15-second capability probes otherwise
    // reuse the same token until its advertised renewal window.
    if (!status && !apiToken && readRelayTokenCache(tokenCache, apiBase, { allowNearExpiry: true })) {
      deleteRelayTokenCache(tokenCache, apiBase)
      const acquired = await acquireRelayTokenDetailed(apiBase, { fetch: fetchFn, timeoutMs })
      if (acquired) {
        token = acquired.token
        tokenOrigin = acquired.finalOrigin
        tokenExpiresAt = acquired.expiresAt
        cached = acquired
        status = await relayStatus(apiBase, token, { fetch: fetchFn, timeoutMs })
      }
    }
    if (!status) continue
    const finalOrigin = (status.__peeritTransport && status.__peeritTransport.finalOrigin) || tokenOrigin || canonicalRelayOrigin(apiBase)
    if (!finalOrigin || (tokenOrigin && finalOrigin !== tokenOrigin) || seenOrigins.has(finalOrigin)) {
      if (!apiToken) deleteRelayTokenCache(tokenCache, apiBase)
      continue
    }
    if (!apiToken && cached) writeRelayTokenCache(tokenCache, apiBase, { ...cached, token, finalOrigin, expiresAt: tokenExpiresAt })
    seenOrigins.add(finalOrigin)

    const entry = topology && Array.isArray(topology.entries) ? topology.entries.find((candidate) => candidate.apiBase === apiBase) : null
    const rosterVerified = !!(topology && topology.verified === true && topology.stable === true && topology.validWriterTopology === true && entry)
    const capabilities = {
      atomicCommit: status.atomicCommit || null,
      legacyWrites: status.legacyWrites || null,
      // Additive, read-only transport capability. It must be explicitly
      // advertised by the relay; clients otherwise retain one-outbox-at-a-time
      // range reads with the same signed-head audit.
      batchRanges: status.batchRanges || null
    }
    out.push({
      apiBase,
      apiToken: token,
      tokenExpiresAt,
      ready: status.ready === true,
      atomicCommit: rosterVerified && hasDurableAtomicCommit(status),
      capabilities,
      canonicalOrigin: finalOrigin,
      rosterVerified,
      rosterStable: rosterVerified && topology.stable === true,
      rosterIndex: entry ? entry.rosterIndex : null,
      topologyId: rosterVerified ? topology.id : null,
      rosterOrigins: rosterVerified ? topology.origins.slice() : [],
      rosterSize: rosterVerified ? topology.size : 0
    })
  }
  return out
}

const TOKEN_RENEW_SKEW_MS = 60_000

function readRelayTokenCache (cache, apiBase, { allowNearExpiry = false } = {}) {
  if (!cache) return null
  let value = null
  try { value = typeof cache.get === 'function' ? cache.get(apiBase) : cache[apiBase] } catch {}
  if (!value || typeof value.token !== 'string' || !value.token) return null
  const expiresAt = Number(value.expiresAt) || 0
  if (!allowNearExpiry && expiresAt && expiresAt <= Date.now() + TOKEN_RENEW_SKEW_MS) return null
  return { ...value, expiresAt }
}

function writeRelayTokenCache (cache, apiBase, value) {
  if (!cache || !value) return
  try {
    if (typeof cache.set === 'function') cache.set(apiBase, value)
    else cache[apiBase] = value
  } catch {}
}

function deleteRelayTokenCache (cache, apiBase) {
  if (!cache) return
  try {
    if (typeof cache.delete === 'function') cache.delete(apiBase)
    else delete cache[apiBase]
  } catch {}
}
