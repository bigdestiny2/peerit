// reader-src.mjs — browser entry point for recovering dispersed peerit bodies.
// Re-exports the read side of blind-dealer.mjs; the build aliases sodium-universal
// to js/sodium-browser-shim.mjs so the bundle runs in a normal browser using
// @noble (pure JS), blake2b (WASM-inlined), WebCrypto, and fetch.
export { recoverBody, recoverKey, decryptBody } from './blind-dealer.mjs'
export { createHttpShardFetch } from './vendor/blind-shards/shard-transport.js'
