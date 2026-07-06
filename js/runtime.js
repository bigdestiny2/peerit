// runtime.js — decides HOW peerit connects, from the environment, with one hard
// rule: the PearBrowser fully-P2P path is the default and is NEVER altered by
// web/relay configuration.
//
//   pearbrowser        window.pear injected (desktop)        -> host bridge + host identity (unchanged)
//   pearbrowser-mobile host-injected same-origin /api token  -> host bridge + host identity (unchanged)
//   web                no host bridge, site configures a      -> LOCAL keys (browser signs) + an UNTRUSTED
//                      REMOTE relay (<meta name=peerit-relay>)   remote relay for sync/swarm
//   dev                nothing configured                     -> localStorage-only dev fallback
//
// The web branch can only be reached when there is NO host bridge present, so a
// normal-browser deployment cannot change what PearBrowser users get. The relay
// is untrusted by construction: signing stays in the browser (forceDev keeps
// js/identity.js on DevIdentity/SubtleCrypto and away from /api/identity/sign),
// and js/verify.js re-checks every record the relay delivers.

import { hasAnyPearBridgeSurface } from './pear-api.js'
import { parseRelayList, readRelayRosterConfig } from './relay-roster.js'

function metaContent (doc, name) {
  try {
    const el = doc && doc.querySelector && doc.querySelector('meta[name="' + name + '"]')
    return el ? (el.getAttribute('content') || '') : null
  } catch {
    return null
  }
}

// Relay config is baked into the peerit.site static export only. It is absent
// from the hyper:// drive PearBrowser loads — and even if present, it is only
// consulted in the no-host-bridge branch, so PearBrowser ignores it.
export function readRelayConfig (doc) {
  const raw = metaContent(doc, 'peerit-relay')
  if (!raw) return null
  // Comma-separated bootstrap failover list. Each entry is a relay base URL, or
  // "same-origin"/"/" (relay proxied under this origin — no CORS). A signed
  // roster, when present, is verified at boot and takes priority for ordering.
  const relays = parseRelayList(raw)
  if (!relays.length) return null
  const readonly = metaContent(doc, 'peerit-relay-readonly')
  return {
    relays,
    apiBase: relays[0],
    apiToken: metaContent(doc, 'peerit-relay-token') || '',
    // Descriptive backend kind ('' | 'peerit-relay' | 'hiverelay-outbox'). Purely
    // informational at the transport level (the wire is identical); 'hiverelay-outbox'
    // enables a one-shot boot probe of /api/bridge/status (see js/app.js).
    relayBackend: metaContent(doc, 'peerit-relay-backend') || '',
    relayRoster: readRelayRosterConfig(doc),
    shardCohort: readShardRosterConfig(doc),
    // Phase 3 (optional): a dht-relay WebSocket for the in-browser DHT transport.
    dhtRelay: metaContent(doc, 'peerit-dht-relay') || '',
    // Default to read-only: a fresh web deployment shows verified content before
    // any write/identity path is enabled. Set the meta to "false" to allow writes.
    readOnly: readonly !== 'false'
  }
}

// Shard cohort config for BlindShard dispersal. Mirrors relay-roster config
// shape: a roster URL to fetch, or an inline comma-list of relay base URLs.
export const SHARD_ROSTER_META = 'peerit-shard-roster'
export const SHARD_RELAYS_META = 'peerit-shard-relays'
export const SHARD_THRESHOLD_META = 'peerit-shard-threshold'

function isLocalHttp (url) {
  return url && (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]' || url.hostname === '::1')
}

export function normalizeShardRelay (value) {
  const raw = String(value || '').trim()
  if (!raw) return null
  try {
    const url = new URL(raw)
    if (url.search || url.hash) return null
    const localOk = url.protocol === 'http:' && isLocalHttp(url)
    if (url.protocol !== 'https:' && !localOk) return null
    return url.origin.replace(/\/+$/, '')
  } catch { return null }
}

export function parseShardRelays (raw) {
  if (!raw) return []
  const out = []
  const seen = new Set()
  for (const s of String(raw).split(',')) {
    const base = normalizeShardRelay(s.trim())
    if (!base || seen.has(base)) continue
    seen.add(base)
    out.push(base)
  }
  return out
}

export function readShardRosterConfig (doc) {
  const rosterUrl = metaContent(doc, SHARD_ROSTER_META)
  const inlineRelays = metaContent(doc, SHARD_RELAYS_META)
  const threshold = metaContent(doc, SHARD_THRESHOLD_META)
  if (!rosterUrl && !inlineRelays) return null
  return {
    rosterUrl: rosterUrl || '',
    relays: parseShardRelays(inlineRelays),
    threshold: Number(threshold) || 0
  }
}

export async function fetchShardRoster ({ url, fetch: fetchFn = defaultFetch() } = {}) {
  if (!url || typeof fetchFn !== 'function') return null
  try {
    const res = await fetchFn(url, { cache: 'no-store' })
    if (!res || !res.ok) return null
    const text = typeof res.text === 'function' ? await res.text() : ''
    const cfg = text ? JSON.parse(text) : null
    if (!cfg || !Array.isArray(cfg.relays) || cfg.relays.length < 2) return null
    const relays = cfg.relays.map((r) => {
      if (typeof r === 'string') return { url: normalizeShardRelay(r) }
      return { url: normalizeShardRelay(r.url || r.baseUrl), pubkey: String(r.pubkey || r.publicKey || '').toLowerCase() }
    }).filter(r => r.url)
    if (relays.length < 2) return null
    const threshold = Number(cfg.threshold) || Math.min(relays.length - 1, Math.ceil(relays.length / 2))
    return { threshold, relays, retainMs: Number(cfg.retainMs) || 30 * 24 * 60 * 60 * 1000 }
  } catch {
    return null
  }
}

function defaultFetch () {
  return typeof fetch === 'function' ? fetch.bind(globalThis) : null
}

// Pinned/seed outboxes baked into the web build: `<meta name="peerit-seed-outboxes">`
// as comma-separated `appId:inviteKey` pairs (both hex64). A fresh visitor joins these
// directly at boot so the curated launch content renders WITHOUT depending on flaky
// swarm-descriptor discovery. The inviteKey is a public READ capability only (writing
// still needs the author's Ed25519 secret), so it's safe to ship in a public bundle.
export function parseSeedOutboxes (raw) {
  if (!raw) return []
  return String(raw).split(',').map(s => s.trim()).filter(Boolean).map(pair => {
    const i = pair.indexOf(':')
    return { appId: pair.slice(0, i).trim(), inviteKey: pair.slice(i + 1).trim() }
  }).filter(o => /^[0-9a-f]{64}$/i.test(o.appId) && /^[0-9a-f]{64}$/i.test(o.inviteKey))
}

// `rawPear` MUST be the injected host object (window.pear), NOT a resolved /api
// surface — otherwise a configured relay would look like a host bridge.
export function resolveRuntime ({ rawPear = null, doc = null } = {}) {
  const v2 = metaContent(doc, 'peerit-v2') === 'true' // Opaque-Log v2 client (sealed graph fields + opaque okey keys)
  const shardCohort = readShardRosterConfig(doc)
  if (hasAnyPearBridgeSurface(rawPear)) {
    return { mode: 'pearbrowser', identityOpts: {}, syncOpts: {}, readOnly: false, v2, shardCohort }
  }
  if (metaContent(doc, 'pear-api-token')) {
    // PearBrowser mobile: the HOST injected a same-origin token; trust host
    // identity + same-origin /api exactly as today (no extra opts).
    return { mode: 'pearbrowser-mobile', identityOpts: {}, syncOpts: {}, readOnly: false, v2, shardCohort }
  }
  const relay = readRelayConfig(doc)
  if (relay) {
    return {
      mode: 'web',
      // Local keys: forceDev on IDENTITY ONLY keeps signing in the browser. It is
      // deliberately NOT passed to sync — sync runs BridgeGossipSync over the
      // remote /api relay (a real transport), the identity never leaves.
      identityOpts: { forceDev: true, apiBase: relay.apiBase, apiToken: relay.apiToken },
      syncOpts: { apiBase: relay.apiBase, apiToken: relay.apiToken, seedOutboxes: parseSeedOutboxes(metaContent(doc, 'peerit-seed-outboxes')) },
      relays: relay.relays,
      relayRoster: relay.relayRoster,
      shardCohort: relay.shardCohort,
      dhtRelay: relay.dhtRelay,
      relayBackend: relay.relayBackend || '',
      readOnly: relay.readOnly,
      v2
    }
  }
  // Local dev fallback (nothing configured): this is a developer's own machine, so
  // persisting the seed across reloads is a convenience, not a public-exposure risk.
  // persistSeed is scoped to THIS branch only — the web/production path above never
  // sets it, so peerit.site keeps the seed in memory only (see js/identity.js).
  return { mode: 'dev', identityOpts: { persistSeed: true }, syncOpts: {}, readOnly: false, v2, shardCohort }
}
