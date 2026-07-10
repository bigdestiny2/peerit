// pear-api.js — portable PearBrowser host bridge discovery.
//
// Preferred path is the injected `window.pear` object. PearBrowser mobile and
// newer desktop builds also expose the same capabilities as token-gated,
// same-origin `/api/*` routes; this module builds a small `window.pear`-shaped
// wrapper around those routes when the object is absent or partial.

const TOKEN_META = 'meta[name="pear-api-token"]'
export const PEAR_API_REQUEST_TIMEOUT_MS = 8000

function tokenFromDocument (doc) {
  try {
    const el = doc && doc.querySelector && doc.querySelector(TOKEN_META)
    return el && el.getAttribute('content')
  } catch {
    return null
  }
}

function defaultDocument () {
  return typeof document !== 'undefined' ? document : null
}

function defaultFetch () {
  return typeof fetch === 'function' ? fetch.bind(globalThis) : null
}

function defaultEventSource () {
  return typeof globalThis.EventSource !== 'undefined' ? globalThis.EventSource : null
}

function transportError (message, code) {
  const error = new Error(message)
  error.code = code
  return error
}

function responseOrigin (response, requestUrl) {
  if (response && response.redirected === true) throw transportError('Relay redirect rejected.', 'PEAR_API_REDIRECT')
  let requested = null
  let final = null
  try { requested = new URL(String(requestUrl), globalThis.location && globalThis.location.href).origin } catch {}
  if (response && response.url) {
    try { final = new URL(String(response.url)).origin } catch { throw transportError('Relay final URL is invalid.', 'PEAR_API_ORIGIN_MISMATCH') }
  }
  if (requested && final && requested !== final) throw transportError('Relay final origin does not match the selected relay.', 'PEAR_API_ORIGIN_MISMATCH')
  return final || requested
}

function abortableDelay (ms, signal) {
  if (signal && signal.aborted) return Promise.reject(transportError('Relay request aborted.', 'PEAR_API_ABORTED'))
  return new Promise((resolve, reject) => {
    let onAbort = null
    const timer = setTimeout(() => {
      if (onAbort && signal && typeof signal.removeEventListener === 'function') signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    if (signal && typeof signal.addEventListener === 'function') {
      onAbort = () => {
        clearTimeout(timer)
        reject(transportError('Relay request aborted.', 'PEAR_API_ABORTED'))
      }
      signal.addEventListener('abort', onAbort, { once: true })
    }
  })
}

function pathWithParams (path, params) {
  const qs = []
  for (const [key, value] of Object.entries(params || {})) {
    if (value === undefined || value === null || value === '') continue
    qs.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
  }
  return qs.length ? `${path}?${qs.join('&')}` : path
}

async function parseJsonResponse (response) {
  let value = null
  if (typeof response.text === 'function') {
    const text = await response.text()
    value = text ? JSON.parse(text) : null
  } else if (typeof response.json === 'function') {
    value = await response.json()
  }
  if (!response.ok) {
    const message = value && value.error ? value.error : (response.statusText || 'PearBrowser API error')
    const error = new Error(message)
    // Preserve machine-readable relay failures. Atomic commits need to
    // distinguish a stale compare-and-swap (409) from a transient mirror
    // outage so the writer can quarantine the former while retaining the exact
    // pending commit for either case.
    error.status = response.status
    if (value && typeof value === 'object') {
      if (value.code) error.code = value.code
      error.response = value
    }
    throw error
  }
  return value
}

function base64Encode (u8) {
  if (typeof btoa === 'function') {
    let s = ''
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i])
    return btoa(s)
  }
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64')
  throw new Error('base64 encoder unavailable')
}

function base64Decode (s) {
  if (typeof atob === 'function') {
    const bin = atob(s)
    const u8 = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
    return u8
  }
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(s, 'base64'))
  throw new Error('base64 decoder unavailable')
}

function hasSyncPearSurface (sync) {
  return !!(
    sync &&
    typeof sync.create === 'function' &&
    typeof sync.join === 'function' &&
    typeof sync.append === 'function' &&
    typeof sync.get === 'function' &&
    typeof sync.list === 'function'
  )
}

function hasSwarmV1PearSurface (swarmV1) {
  return !!(swarmV1 && typeof swarmV1.join === 'function')
}

function pickCompleteSurface (primary, fallback, complete) {
  if (complete(primary)) return primary
  return fallback || primary
}

function mergeObjectSurface (primary, fallback) {
  if (!primary) return fallback
  if (!fallback) return primary
  if (typeof primary !== 'object' || typeof fallback !== 'object') return primary
  return { ...fallback, ...primary }
}

function mergePear (primary, fallback) {
  if (!primary) return fallback
  if (!fallback) return primary
  const sync = pickCompleteSurface(primary.sync, fallback.sync, hasSyncPearSurface)
  const identity = pickCompleteSurface(primary.identity, fallback.identity, hasIdentityPearSurface)
  const swarmBase = mergeObjectSurface(primary.swarm, fallback.swarm)
  const swarmV1 = pickCompleteSurface(
    primary.swarm && primary.swarm.v1,
    fallback.swarm && fallback.swarm.v1,
    hasSwarmV1PearSurface
  )
  const swarm = swarmBase
    ? { ...swarmBase, ...(swarmV1 ? { v1: swarmV1 } : {}) }
    : undefined
  return {
    ...fallback,
    ...primary,
    sync,
    identity,
    bridge: primary.bridge || fallback.bridge,
    login: primary.login || fallback.login,
    contacts: primary.contacts || fallback.contacts,
    navigate: primary.navigate || fallback.navigate,
    share: primary.share || fallback.share,
    swarm
  }
}

export function hasAnyPearBridgeSurface (pear) {
  return !!(pear && (pear.sync || pear.identity || pear.swarm || pear.bridge || pear.login || pear.contacts || pear.drive || pear.storage || pear.runtime || pear.app))
}

export function hasIdentityPearSurface (pear) {
  return !!(pear && pear.identity && typeof pear.identity.getPublicKey === 'function' && typeof pear.identity.sign === 'function')
}

export function hasGossipPearSurface (pear) {
  return !!(
    pear &&
    hasSyncPearSurface(pear.sync) &&
    hasIdentityPearSurface(pear) &&
    pear.swarm &&
    hasSwarmV1PearSurface(pear.swarm.v1)
  )
}

export function createPearApi (opts = {}) {
  const token = opts.apiToken || opts.token || tokenFromDocument(opts.document || defaultDocument())
  const fetchFn = opts.fetch || defaultFetch()
  if (!token || typeof fetchFn !== 'function') return null

  const base = opts.apiBase || opts.base || ''
  const EventSourceCtor = opts.EventSource || defaultEventSource()
  const requestTimeoutMs = Number.isFinite(Number(opts.requestTimeoutMs)) && Number(opts.requestTimeoutMs) > 0
    ? Number(opts.requestTimeoutMs)
    : PEAR_API_REQUEST_TIMEOUT_MS

  function effectiveTimeout (requestOpts = {}) {
    return Number.isFinite(Number(requestOpts.timeoutMs)) && Number(requestOpts.timeoutMs) > 0
      ? Number(requestOpts.timeoutMs)
      : requestTimeoutMs
  }

  async function fetchAttempt (url, init = {}, requestOpts = {}) {
    const timeoutMs = effectiveTimeout(requestOpts)
    const externalSignal = requestOpts.signal || init.signal || null
    if (externalSignal && externalSignal.aborted) throw transportError('Relay request aborted.', 'PEAR_API_ABORTED')
    const controller = typeof AbortController === 'function' ? new AbortController() : null
    const onAbort = () => { try { if (controller) controller.abort() } catch {} }
    if (externalSignal && controller && typeof externalSignal.addEventListener === 'function') externalSignal.addEventListener('abort', onAbort, { once: true })
    const requestInit = {
      ...init,
      redirect: 'error',
      ...((controller && controller.signal) ? { signal: controller.signal } : (externalSignal ? { signal: externalSignal } : {}))
    }
    let timer = null
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        try { if (controller) controller.abort() } catch {}
        reject(transportError('Relay request timed out.', 'PEAR_API_TIMEOUT'))
      }, timeoutMs)
    })
    try {
      const response = await Promise.race([Promise.resolve().then(() => fetchFn(url, requestInit)), timeout])
      responseOrigin(response, url)
      return response
    } finally {
      if (timer) clearTimeout(timer)
      if (externalSignal && controller && typeof externalSignal.removeEventListener === 'function') externalSignal.removeEventListener('abort', onAbort)
    }
  }

  async function parseResponseBounded (response, requestOpts = {}) {
    const timeoutMs = effectiveTimeout(requestOpts)
    const signal = requestOpts.signal || null
    let timer = null
    let onAbort = null
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(transportError('Relay response body timed out.', 'PEAR_API_TIMEOUT')), timeoutMs)
    })
    const aborted = new Promise((resolve, reject) => {
      if (!signal || typeof signal.addEventListener !== 'function') return
      onAbort = () => reject(transportError('Relay request aborted.', 'PEAR_API_ABORTED'))
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    })
    try {
      return await Promise.race([parseJsonResponse(response), timeout, aborted])
    } finally {
      if (timer) clearTimeout(timer)
      if (onAbort && signal && typeof signal.removeEventListener === 'function') signal.removeEventListener('abort', onAbort)
    }
  }

  // Retry 429 (rate limited) / 503 (at capacity) with exponential backoff + jitter,
  // honoring Retry-After. A cold-boot fans out O(authors) reads at once, so without this
  // a busy relay throws mid-boot and the visitor sees a half-empty feed; with it the boot
  // paces itself under the per-IP limit instead of failing.
  async function fetchWithBackoff (url, init, requestOpts = {}) {
    let wait = 500
    for (let attempt = 0; ; attempt++) {
      const response = await fetchAttempt(url, init, requestOpts)
      if ((response.status === 429 || response.status === 503) && attempt < 4) {
        let delay = wait
        try { const ra = Number(response.headers && response.headers.get && response.headers.get('retry-after')); if (ra > 0) delay = ra * 1000 } catch {}
        await abortableDelay(Math.min(delay * (0.8 + Math.random() * 0.4), 8000), requestOpts.signal)
        wait *= 2
        continue
      }
      return response
    }
  }

  async function apiGet (path, requestOpts = {}) {
    const response = await fetchWithBackoff(base + path, { headers: { 'X-Pear-Token': token } }, requestOpts)
    return parseResponseBounded(response, requestOpts)
  }

  async function apiPost (path, body, requestOpts = {}) {
    const response = await fetchWithBackoff(base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Pear-Token': token },
      body: JSON.stringify(body || {})
    }, requestOpts)
    return parseResponseBounded(response, requestOpts)
  }

  function makeSwarmChannel (info) {
    const listeners = { peer: [], message: [], 'peer-leave': [], error: [], closed: [] }
    const peers = new Map()
    let destroyed = false
    let es = null

    function emit (event, ...args) {
      const fns = listeners[event] || []
      for (const fn of fns) {
        try { fn(...args) } catch (err) { setTimeout(() => { throw err }, 0) }
      }
    }

    function makePeer (peerId, pubkey) {
      return {
        id: peerId,
        pubkey: pubkey || null,
        send (data) {
          if (destroyed) throw new Error('channel destroyed')
          const u8 = data instanceof Uint8Array ? data : new Uint8Array(data)
          apiPost('/api/swarm/send', {
            channelId: info.channelId,
            peerId,
            data: base64Encode(u8)
          }).catch((err) => emit('error', err))
        }
      }
    }

    const channel = {
      channelId: info.channelId,
      topic: info.topicHex,
      topicHex: info.topicHex,
      protocol: info.protocol,
      version: info.version,
      tier: info.tier,
      get peers () { return Array.from(peers.values()) },
      on (event, fn) {
        if (!listeners[event]) listeners[event] = []
        listeners[event].push(fn)
      },
      off (event, fn) {
        const arr = listeners[event] || []
        const i = arr.indexOf(fn)
        if (i >= 0) arr.splice(i, 1)
      },
      destroy () {
        if (destroyed) return
        destroyed = true
        try { if (es) es.close() } catch {}
        apiPost('/api/swarm/leave', { channelId: info.channelId }).catch(() => {})
        emit('closed')
      }
    }

    if (!EventSourceCtor) {
      setTimeout(() => emit('error', new Error('EventSource unavailable for Pear swarm events')), 0)
      return channel
    }

    const eventsPath = pathWithParams('/api/swarm/events', { channelId: info.channelId, token })
    es = new EventSourceCtor(base + eventsPath)
    es.onmessage = (ev) => {
      let msg
      try { msg = JSON.parse(ev.data) } catch { return }
      if (msg.type === 'peer') {
        const peer = makePeer(msg.peerId, msg.pubkey)
        peers.set(msg.peerId, peer)
        emit('peer', peer)
      } else if (msg.type === 'peer-leave') {
        const peer = peers.get(msg.peerId)
        peers.delete(msg.peerId)
        if (peer) emit('peer-leave', peer)
      } else if (msg.type === 'message') {
        const peer = peers.get(msg.peerId)
        if (peer) emit('message', peer, base64Decode(msg.data))
      } else if (msg.type === 'error') {
        emit('error', new Error(msg.message || 'swarm error'))
      } else if (msg.type === 'closed') {
        channel.destroy()
      }
    }
    es.onerror = (err) => {
      // A transient SSE error must NOT tear down peer discovery — the browser's
      // EventSource auto-reconnects. Surface it and keep the channel alive; the
      // server's explicit 'closed' message (handled above) is what destroys it.
      if (!destroyed) emit('error', err instanceof Error ? err : new Error('swarm event stream error'))
    }
    return channel
  }

  return {
    sync: {
      create: (appId) => apiPost('/api/sync/create', { appId }),
      join: (appId, inviteKey) => apiPost('/api/sync/join', { appId, inviteKey }),
      append: (appId, op) => apiPost('/api/sync/append', { appId, op }),
      // Owner-signed, compare-and-swap mutation + head transaction. The relay
      // validates and durably applies this envelope atomically; relay-pool.js
      // requires matching durable receipts from at least two independent
      // relays before the client reports publication success.
      ...(opts.atomicCommit === true
        ? { commit: (appId, commit, requestOpts = {}) => apiPost('/api/sync/commit', { appId, commit }, requestOpts) }
        : {}),
      get: (appId, key) => apiGet(pathWithParams('/api/sync/get', { appId, key })),
      list: (appId, prefix, listOpts = {}) => apiGet(pathWithParams('/api/sync/list', { appId, prefix, limit: listOpts.limit })),
      range: (appId, rangeOpts = {}) => apiGet(pathWithParams('/api/sync/range', {
        appId,
        gte: rangeOpts.gte,
        gt: rangeOpts.gt,
        lte: rangeOpts.lte,
        lt: rangeOpts.lt,
        reverse: rangeOpts.reverse ? 1 : undefined,
        limit: rangeOpts.limit
      })),
      // Optional scale capability. It deliberately is NOT probed optimistically:
      // an older relay receives no extra 404 request on every refresh. An exact
      // relay-status capability enables it in relay-pool.js; each returned row
      // still goes through normal admission and the complete signed-head audit.
      ...(opts.batchRanges === true
        ? { ranges: (requests, requestOpts = {}) => apiPost('/api/sync/ranges', { requests }, requestOpts) }
        : {}),
      count: (appId, prefix) => apiGet(pathWithParams('/api/sync/count', { appId, prefix })),
      status: (appId) => apiGet(pathWithParams('/api/sync/status', { appId })),
      // Batched change-markers: one request returns a version per outbox so the
      // client only re-reads outboxes whose version moved (see gossip.js _doRefresh).
      heads: (appIds) => apiPost('/api/sync/heads', { appIds }),
      // Phase D durable directory: every outbox's SIGNED head in one call, so a
      // fresh visitor bootstraps its rollback floor + author discovery at once.
      // HiveRelay's HTTP adapter calls the pagination cursor `cursor` (older
      // peerit fakes used `after`). Send both during the compatibility window so
      // a large directory never loops over page one forever.
      directory: (opts = {}) => apiGet(pathWithParams('/api/directory', { limit: opts.limit, cursor: opts.after, after: opts.after, since: opts.since }))
    },
    identity: {
      getPublicKey: () => apiGet('/api/identity'),
      sign: (payload, namespace = '') => apiPost('/api/identity/sign', { payload: String(payload), namespace })
    },
    swarm: {
      v1: {
        join: (topicHex, joinOpts = {}) => apiPost('/api/swarm/join', {
          topicHex: topicHex || null,
          subtopic: joinOpts.subtopic === undefined ? null : joinOpts.subtopic,
          protocol: joinOpts.protocol || 'pear.swarm.v1',
          version: joinOpts.version === undefined ? 1 : joinOpts.version,
          server: !!joinOpts.server,
          client: joinOpts.client !== false,
          appName: joinOpts.appName || null,
          reason: joinOpts.reason || null
        }).then(makeSwarmChannel)
      }
    },
    bridge: {
      status: () => apiGet('/api/bridge/status')
    },
    navigate: (url) => { if (globalThis.location) globalThis.location.href = url },
    share: () => {}
  }
}

// Probe a relay's token-gated `GET /api/bridge/status` once and report what
// backend it identifies as. Used by the boot wiring to VERIFY that a build
// configured for the HiveRelay outboxlog backend is actually pointed at one.
// Dependency-injected fetch (falls back to the module default). NEVER throws:
// any network/parse/non-2xx error degrades to { ok:false, service:null, ready:false }.
// Bounded by `timeoutMs` (AbortController) so a reachable-but-hanging relay can
// never stall the caller. The token is sent as X-Pear-Token and is never logged.
export async function probeRelayBackend ({ apiBase = '', apiToken = '', fetch, timeoutMs = 5000 } = {}) {
  const fetchFn = fetch || defaultFetch()
  const miss = { ok: false, service: null, ready: false }
  if (typeof fetchFn !== 'function') return miss
  let signal = null
  let timer = null
  let timeout = null
  if (typeof AbortController === 'function' && timeoutMs > 0) {
    const ac = new AbortController()
    signal = ac.signal
    timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        try { ac.abort() } catch {}
        reject(transportError('Relay probe timed out.', 'PEAR_API_TIMEOUT'))
      }, timeoutMs)
    })
  } else if (timeoutMs > 0) {
    timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(transportError('Relay probe timed out.', 'PEAR_API_TIMEOUT')), timeoutMs)
    })
  }
  try {
    const headers = apiToken ? { 'X-Pear-Token': apiToken } : {}
    const init = signal ? { headers, signal, redirect: 'error' } : { headers, redirect: 'error' }
    const request = Promise.resolve().then(() => fetchFn(apiBase + '/api/bridge/status', init))
    const res = await (timeout ? Promise.race([request, timeout]) : request)
    responseOrigin(res, apiBase + '/api/bridge/status')
    if (!res || !res.ok) return miss
    let body = null
    if (typeof res.text === 'function') {
      const read = Promise.resolve().then(() => res.text())
      const text = await (timeout ? Promise.race([read, timeout]) : read)
      body = text ? JSON.parse(text) : null
    } else if (typeof res.json === 'function') {
      const read = Promise.resolve().then(() => res.json())
      body = await (timeout ? Promise.race([read, timeout]) : read)
    }
    if (!body || typeof body !== 'object') return miss
    return {
      ok: true,
      service: typeof body.service === 'string' ? body.service : null,
      ready: body.ready === true
    }
  } catch {
    return miss
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export function resolvePear (opts = {}) {
  const browserPear = Object.prototype.hasOwnProperty.call(opts, 'pear')
    ? opts.pear
    : (typeof window !== 'undefined' ? window.pear : null)
  const apiPear = createPearApi(opts)
  return mergePear(browserPear, apiPear)
}
