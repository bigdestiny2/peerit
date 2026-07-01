// pear-api.js — portable PearBrowser host bridge discovery.
//
// Preferred path is the injected `window.pear` object. PearBrowser mobile and
// newer desktop builds also expose the same capabilities as token-gated,
// same-origin `/api/*` routes; this module builds a small `window.pear`-shaped
// wrapper around those routes when the object is absent or partial.

const TOKEN_META = 'meta[name="pear-api-token"]'

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
  return typeof EventSource !== 'undefined' ? EventSource : null
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
    throw new Error(message)
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

  async function apiGet (path) {
    const response = await fetchFn(base + path, { headers: { 'X-Pear-Token': token } })
    return parseJsonResponse(response)
  }

  async function apiPost (path, body) {
    const response = await fetchFn(base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Pear-Token': token },
      body: JSON.stringify(body || {})
    })
    return parseJsonResponse(response)
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
      count: (appId, prefix) => apiGet(pathWithParams('/api/sync/count', { appId, prefix })),
      status: (appId) => apiGet(pathWithParams('/api/sync/status', { appId })),
      // Batched change-markers: one request returns a version per outbox so the
      // client only re-reads outboxes whose version moved (see gossip.js _doRefresh).
      heads: (appIds) => apiPost('/api/sync/heads', { appIds }),
      // Phase D durable directory: every outbox's SIGNED head in one call, so a
      // fresh visitor bootstraps its rollback floor + author discovery at once.
      directory: () => apiGet('/api/directory')
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
    navigate: (url) => { if (typeof location !== 'undefined') location.href = url },
    share: () => {}
  }
}

export function resolvePear (opts = {}) {
  const browserPear = Object.prototype.hasOwnProperty.call(opts, 'pear')
    ? opts.pear
    : (typeof window !== 'undefined' ? window.pear : null)
  const apiPear = createPearApi(opts)
  return mergePear(browserPear, apiPear)
}
