// dht-bundle.js — optional Phase 3 browser-DHT bundle placeholder.
//
// Production builds may replace this file with an esbuilt bundle for
// js/dht-transport.js. The base site ships this explicit stub so a configured
// peerit-dht-relay fails closed into the existing token-gated /api relay path
// instead of producing a network 404 for a dynamic import.

export async function createDhtTransport () {
  throw new Error('in-browser DHT transport bundle is not included in this build')
}
