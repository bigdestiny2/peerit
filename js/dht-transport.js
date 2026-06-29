// dht-transport.js — EXPERIMENTAL (Phase 3): wire the REAL Holepunch browser
// stack into the dep-injected adapter in js/dht-adapter.js. Runs the genuine
// HyperDHT + Noise handshake in the browser over a WebSocket dht-relay, so the
// relay is a cryptographic byte pipe that can neither read nor forge traffic.
// Exposes the same window.pear-shaped { sync, swarm:{v1} } surface, so
// js/gossip.js (BridgeGossipSync) runs UNCHANGED on top of it.
//
// ⚠ STATUS: not shipped in the no-build site (excluded from publish.mjs
// SITE_FILES) and not exercised by CI. The dep imports are dynamic so this module
// LOADS without them; they resolve only when esbuilt into dht-bundle.js (recipe
// in docs/WEB-DEPLOYMENT.md). The deps are heavy + experimental
// (@hyperswarm/dht-relay is marked do-not-use-in-production; in-browser Hyperbee
// can be memory-hungry). The peerit-specific adapter LOGIC is unit-tested
// (test/dht-adapter.mjs); the real DHT/Noise/protomux wire behavior must be
// validated on a live network before enabling.
//
// Integration: when a <meta name="peerit-dht-relay" content="wss://…"> is present
// in web mode, boot dynamically imports the built bundle, calls createDhtTransport(),
// and passes the result as `pear` to createSync/createIdentity — falling back to
// the /api relay if the bundle or DHT is unavailable.

import { createHyperPearSurface } from './dht-adapter.js'

async function sha256 (str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return new Uint8Array(buf)
}

export async function createDhtTransport ({ relayWsUrl, storage = 'peerit-dht', identity } = {}) {
  if (!relayWsUrl) throw new Error('createDhtTransport requires relayWsUrl (wss://…)')
  // Dynamic imports: bundled by esbuild, absent in the plain site (so this file
  // is harmless to load there; the caller falls back to the /api relay on throw).
  const [{ default: DHT }, { default: WSStream }, { default: Hyperswarm }, { default: Corestore }, { default: Hyperbee }, { default: Protomux }, { default: b4a }] = await Promise.all([
    import('@hyperswarm/dht-relay'), import('@hyperswarm/dht-relay/ws'),
    import('hyperswarm'), import('corestore'), import('hyperbee'), import('protomux'), import('b4a')
  ])

  const ws = new WebSocket(relayWsUrl)
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('dht-relay websocket failed')) })
  const dht = new DHT(new WSStream(true, ws))
  const swarm = new Hyperswarm({ dht })
  const store = new Corestore(storage) // random-access-web → IndexedDB in the browser
  await store.ready()

  return createHyperPearSurface({ store, swarm, Hyperbee, Protomux, b4a, sha256, identity })
}
