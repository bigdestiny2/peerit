// dht-transport.js — EXPERIMENTAL (Phase 3): wire the REAL Holepunch browser
// stack into the dep-injected adapter in js/dht-adapter.js. Runs the genuine
// HyperDHT + Noise handshake in the browser over a WebSocket dht-relay, so the
// relay is a cryptographic byte pipe that can neither read nor forge traffic.
// Exposes the same window.pear-shaped { sync, swarm:{v1} } surface, so
// js/gossip.js (BridgeGossipSync) runs UNCHANGED on top of it.
//
// ⚠ STATUS: this SOURCE module is not shipped directly and is not run by `npm
// test` — but esbuild bundles it into js/dht-bundle.js, which IS listed in
// publish.mjs SITE_FILES and ships (git-tracked, ~1.2 MB) with a `--dht-relay`
// build (recipe in docs/WEB-DEPLOYMENT.md). The dep imports are dynamic so this
// module LOADS without them; they resolve only in the bundle. The deps are heavy +
// experimental (@hyperswarm/dht-relay@0.4.3 is marked do-not-use-in-production).
// The wire is validated on a testnet DHT (test/dht-live.mjs) and in a real browser;
// durable in-browser storage is js/ra-idb.js (test/ra-idb.mjs). Kept best-effort
// with automatic /api fallback (js/app.js boot).
//
// Integration: when a <meta name="peerit-dht-relay" content="wss://…"> is present
// in web mode, boot dynamically imports the built bundle, calls createDhtTransport(),
// and passes the result as `pear` to createSync/createIdentity — falling back to
// the /api relay if the bundle or DHT is unavailable.

import { createHyperPearSurface } from './dht-adapter.js'
import createIdbStorage from './ra-idb.js'

async function sha256 (str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return new Uint8Array(buf)
}

export async function createDhtTransport ({ relayWsUrl, storage = 'peerit-dht', identity } = {}) {
  if (!relayWsUrl) throw new Error('createDhtTransport requires relayWsUrl (wss://…)')
  // Dynamic imports: bundled by esbuild, absent in the plain site (so this file
  // is harmless to load there; the caller falls back to the /api relay on throw).
  const [{ default: DHT }, { default: WSStream }, { default: Hyperswarm }, { default: Corestore }, { default: Hyperbee }, { default: Protomux }, { default: b4a }, cencMod, { default: RAM }] = await Promise.all([
    import('@hyperswarm/dht-relay'), import('@hyperswarm/dht-relay/ws'),
    import('hyperswarm'), import('corestore'), import('hyperbee'), import('protomux'), import('b4a'), import('compact-encoding'), import('random-access-memory')
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
  // Durable storage is IndexedDB via js/ra-idb.js — a truncate-capable backend on
  // the RAS@3 base hypercore@10 needs (random-access-web@2.0.3 is RAS@1, no
  // truncate → the write path throws). Fall back to in-memory ONLY if IndexedDB is
  // entirely unavailable (locked-down private mode); the DHT wire still runs, it
  // just won't persist across reloads.
  let backend
  try {
    backend = createIdbStorage(String(storage || 'peerit-dht'))
  } catch (e) {
    console.warn('[peerit] in-browser DHT: IndexedDB unavailable (' + (e && e.message) + '); using in-memory store — data will not persist across reloads')
    backend = RAM
  }
  const store = new Corestore(backend)
  await store.ready()

  const cenc = cencMod.default || cencMod
  // The REAL wire codec (fixes the pass-through fake): protomux frames the
  // descriptor channel with compact-encoding raw bytes, not identity functions.
  return createHyperPearSurface({ store, swarm, Hyperbee, Protomux, b4a, sha256, identity, codec: cenc.raw })
}
