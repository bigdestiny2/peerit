// sodium-browser-shim.mjs — minimal sodium-universal shim for the reader bundle.
// The reader path needs crypto_generichash (blake2b-256 shard addressing) and
// crypto_sign_verify_detached (Ed25519 custody-intent signature verification).
// Dealer-only methods stub-throw so the vendored blind-dealer module loads in a
// browser build without pulling the native sodium-universal dependency.
import { ed25519 } from '@noble/curves/ed25519'
import { sodium as blakeSodium } from './blake2b-src.mjs'

function toU8 (v) {
  if (v instanceof Uint8Array) return v
  if (v && typeof v.length === 'number') return new Uint8Array(v)
  throw new Error('sodium-browser-shim: expected Uint8Array')
}

export default {
  get crypto_sign_BYTES () { return 64 },
  crypto_sign_detached () { throw new Error('crypto_sign_detached is not available in the browser reader bundle') },
  crypto_sign_verify_detached (sig, msg, pub) {
    try {
      return ed25519.verify(toU8(sig), toU8(msg), toU8(pub))
    } catch {
      return false
    }
  },
  randombytes_buf () { throw new Error('randombytes_buf is not available in the browser reader bundle') },
  crypto_generichash: blakeSodium.crypto_generichash
}
