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
    relayRoster: readRelayRosterConfig(doc),
    // Phase 3 (optional): a dht-relay WebSocket for the in-browser DHT transport.
    dhtRelay: metaContent(doc, 'peerit-dht-relay') || '',
    // Default to read-only: a fresh web deployment shows verified content before
    // any write/identity path is enabled. Set the meta to "false" to allow writes.
    readOnly: readonly !== 'false'
  }
}

// `rawPear` MUST be the injected host object (window.pear), NOT a resolved /api
// surface — otherwise a configured relay would look like a host bridge.
export function resolveRuntime ({ rawPear = null, doc = null } = {}) {
  const v2 = metaContent(doc, 'peerit-v2') === 'true' // Opaque-Log v2 client (sealed graph fields + opaque okey keys)
  if (hasAnyPearBridgeSurface(rawPear)) {
    return { mode: 'pearbrowser', identityOpts: {}, syncOpts: {}, readOnly: false, v2 }
  }
  if (metaContent(doc, 'pear-api-token')) {
    // PearBrowser mobile: the HOST injected a same-origin token; trust host
    // identity + same-origin /api exactly as today (no extra opts).
    return { mode: 'pearbrowser-mobile', identityOpts: {}, syncOpts: {}, readOnly: false, v2 }
  }
  const relay = readRelayConfig(doc)
  if (relay) {
    return {
      mode: 'web',
      // Local keys: forceDev on IDENTITY ONLY keeps signing in the browser. It is
      // deliberately NOT passed to sync — sync runs BridgeGossipSync over the
      // remote /api relay (a real transport), the identity never leaves.
      identityOpts: { forceDev: true, apiBase: relay.apiBase, apiToken: relay.apiToken },
      syncOpts: { apiBase: relay.apiBase, apiToken: relay.apiToken },
      relays: relay.relays,
      relayRoster: relay.relayRoster,
      dhtRelay: relay.dhtRelay,
      readOnly: relay.readOnly,
      v2
    }
  }
  return { mode: 'dev', identityOpts: {}, syncOpts: {}, readOnly: false, v2 }
}
