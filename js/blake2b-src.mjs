// blake2b-src.mjs — entry for the browser blake2b bundle (web/js/blake2b-bundle.js,
// built by scripts/build-blake2b-bundle.mjs, dht-bundle precedent). SubtleCrypto has no
// blake2b, but the HiveRelay blind shard store addresses shards by blake2b-256
// (sodium.crypto_generichash), so the browser needs a MATCHING hasher or shard IDs won't
// line up with the store's server-side address. The vetted `blake2b` pkg produces output
// identical to sodium.crypto_generichash (verified byte-for-byte) and inlines its WASM as
// base64, so it bundles to pure JS with no separate .wasm asset.
import blake2b from 'blake2b'

// Load the WASM backend (it falls back to a pure-JS impl if unavailable). Await once at init.
export function ready () { return new Promise((resolve) => { try { blake2b.ready(() => resolve()) } catch { resolve() } }) }

// A sodium-like shim so shard-store-adapter.makeBlake2b256Hex(sodium, b4a) works unchanged
// in the browser exactly as sodium-universal does in Node.
export const sodium = {
  crypto_generichash (out, input) { blake2b(out.length).update(input).digest(out); return out }
}

// Convenience: direct blake2b-256 hex (== the store's shard address).
export function blake2b256Hex (input) {
  const out = new Uint8Array(32)
  blake2b(32).update(input).digest(out)
  let s = ''
  for (let i = 0; i < out.length; i++) s += out[i].toString(16).padStart(2, '0')
  return s
}
