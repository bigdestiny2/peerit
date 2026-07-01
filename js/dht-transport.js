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
  const [{ default: DHT }, { default: WSStream }, { default: Hyperswarm }, { default: Corestore }, { default: Hyperbee }, { default: Protomux }, { default: b4a }, cencMod, { default: RAW }, { default: RAM }] = await Promise.all([
    import('@hyperswarm/dht-relay'), import('@hyperswarm/dht-relay/ws'),
    import('hyperswarm'), import('corestore'), import('hyperbee'), import('protomux'), import('b4a'), import('compact-encoding'), import('random-access-web'), import('random-access-memory')
  ])

  const ws = new WebSocket(relayWsUrl)
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('dht-relay websocket failed')) })
  const dht = new DHT(new WSStream(true, ws))
  const swarm = new Hyperswarm({ dht })
  // Corestore's storage MUST be a random-access FACTORY, not a path string (a
  // string selects a file backend → needs fs). REQUIRES corestore ~6.x +
  // hypercore ~10.x (the random-access era); corestore 7's hypercore-storage is
  // Node-file-oriented and won't browser-bundle. See docs/WEB-DEPLOYMENT.md.
  //
  // Durable path is IndexedDB via random-access-web. BUT random-access-web@2.0.3
  // ships the RAS@1 API, which has no truncate() — and hypercore@10 calls
  // storage.truncate on write. So probe the chosen backend: use IndexedDB only if
  // it exposes truncate, otherwise fall back to in-memory (the DHT wire still runs
  // — WASM crypto, Noise over the WS dht-relay, hypercore replication — it just
  // doesn't persist across reloads until a truncate-capable IDB backend is wired).
  const idbFactory = RAW(storage)
  let backend = idbFactory
  try {
    const probe = idbFactory('___truncate_probe___')
    if (typeof probe.truncate !== 'function') {
      console.warn('[peerit] in-browser DHT: IndexedDB backend lacks truncate (random-access-web is RAS@1); using in-memory store — data will not persist across reloads')
      backend = RAM
    }
    try { if (probe && probe.close) probe.close(() => {}) } catch {}
  } catch (e) {
    console.warn('[peerit] in-browser DHT: could not probe IndexedDB backend (' + (e && e.message) + '); using in-memory store')
    backend = RAM
  }
  const store = new Corestore(backend)
  await store.ready()

  const cenc = cencMod.default || cencMod
  // The REAL wire codec (fixes the pass-through fake): protomux frames the
  // descriptor channel with compact-encoding raw bytes, not identity functions.
  return createHyperPearSurface({ store, swarm, Hyperbee, Protomux, b4a, sha256, identity, codec: cenc.raw })
}
