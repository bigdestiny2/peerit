// TEST STUB of hiverelay's shard-engine.js — ONLY the three PURE functions the
// vendored shard-pin.js + http-adapter.js import (normalizeShardAddress,
// shardError, shardHash) + DEFAULT_MAX_SHARD_BYTES. Copied VERBATIM from
// hiverelay origin/main (26c02eb) packages/services/builtin/shard-store/shard-engine.js.
//
// The real engine additionally imports hyperblobs + hyperbee for the on-disk CAS;
// peerit does not vendor those. The HTTP handler + pin auth we are testing against
// never call the CAS directly — they use only these pure helpers — so stubbing the
// storage away lets test/shard-store-adapter.mjs drive the REAL request parsing +
// REAL pin authorization against an in-memory Map. This stub carries NO storage.
import sodium from 'sodium-universal'
import b4a from 'b4a'

const HASH_BYTES = 32
const HEX64 = /^[0-9a-f]{64}$/
export const DEFAULT_MAX_SHARD_BYTES = 4 * 1024 * 1024

export function shardHash (ciphertext) {
  const bytes = b4a.isBuffer(ciphertext) ? ciphertext : b4a.from(ciphertext)
  const out = b4a.alloc(HASH_BYTES)
  sodium.crypto_generichash(out, bytes) // BLAKE2b-256
  return b4a.toString(out, 'hex')
}

/** Accept "shard:<hex>" or a bare 64-hex string; returns lowercase hex or null. */
export function normalizeShardAddress (address) {
  if (typeof address !== 'string') return null
  const raw = address.startsWith('shard:') ? address.slice('shard:'.length) : address
  const lower = raw.trim().toLowerCase()
  return HEX64.test(lower) ? lower : null
}

export function shardError (code, message) {
  const err = new Error(code + (message ? ': ' + message : ''))
  err.code = code
  return err
}
