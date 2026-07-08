// box.js — BlindShard's convergent AEAD "box": the smallest composable primitive
// that turns an opaque post BODY into an opaque ciphertext BLOB a relay can hold
// without ever holding the plaintext (see BLINDSHARD-DESIGN.md §1 pipeline, §4 #1).
//
// It is CONVERGENT: the encryption key is derived from the content itself
// (contentKey = SHA-256(body)), so two identical bodies produce byte-identical
// ciphertext → free dedup on a public corpus, and the key needs no escrow — it
// travels in the public, author-signed manifest, never on the storing relay.
//
//   box(body)                -> { C, contentKey, iv, blobId }
//   unbox(C, contentKey, iv) -> body
//
// Pure SubtleCrypto (AES-256-GCM + SHA-256, both already proven in-tree —
// identity-export.js:97 ships AES-GCM, crypto.js ships SubtleCrypto SHA-256).
// NO new dependency. Opaque bytes in, opaque bytes out.
//
// SECURITY — deterministic IV is a NEW construction (design §6 risk 10).
// Standard AES-GCM (identity-export.js) uses a RANDOM per-message IV because a
// fixed (key, nonce) pair reused across two DIFFERENT plaintexts catastrophically
// breaks GCM. Here the IV is DERIVED, not random: iv = SHA-256("bs-iv"‖contentKey)
// [:12]. This is safe ONLY under convergent keying: key = f(body), so a given key
// is, by construction, only ever used to encrypt the ONE body it was derived from.
// The (key, nonce) pair is therefore never reused across distinct plaintexts.
// Two boxes of the same body reuse the same (key, nonce) on the SAME plaintext —
// which is exactly the intended, safe determinism that yields dedup. Because this
// deviates from the proven random-IV path it is pinned by fixed vectors (KATs) in
// test/box.mjs.
//
// KEY-COMMITMENT GATE — closing the AES-GCM commitment gap (design §1, §6 risk 10).
// AES-GCM is NOT key-committing: a ciphertext can, in principle, be crafted to
// decrypt to a different valid plaintext under a different key. For a public,
// convergent, content-addressed store that is a substitution hazard. unbox()
// therefore treats SHA-256(plaintext) == contentKey as a MANDATORY rejection
// (throw), not an advisory self-check: after GCM decrypt we re-hash the recovered
// plaintext and refuse to return it unless it hashes back to the key we decrypted
// with. Combined with the caller's SHA-256(C) == blobId check on the ciphertext,
// a relay cannot substitute, corrupt, or mis-key a blob without detection.

import { hashBytes } from './crypto.js'

// Domain-separation label for the derived IV. Prefixing the hash input with a
// fixed tag keeps the IV derivation from ever colliding with any other use of
// SHA-256(contentKey) elsewhere in the system.
const IV_LABEL = 'bs-iv'
const IV_BYTES = 12 // AES-GCM standard 96-bit nonce

const enc = (s) => new TextEncoder().encode(s)
const fromHex = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a }
const concat = (a, b) => { const u = new Uint8Array(a.length + b.length); u.set(a, 0); u.set(b, a.length); return u }

function subtle () {
  const s = globalThis.crypto && globalThis.crypto.subtle
  if (!s) throw new Error('Secure crypto (crypto.subtle) is unavailable here; BlindShard box/unbox require AES-GCM.')
  return s
}

// Coerce any bytes-ish input to a Uint8Array without copying when already one.
function asBytes (x, label) {
  if (x instanceof Uint8Array) return x
  if (x instanceof ArrayBuffer) return new Uint8Array(x)
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength)
  throw new Error(`${label} must be bytes (Uint8Array/ArrayBuffer); got ${typeof x}.`)
}

// Derive the deterministic 12-byte IV from the content key. contentKeyHex is the
// hex SHA-256 of the body; we hash the label bytes concatenated with the RAW key
// bytes (not the hex string) so the derivation is over the true 32-byte key.
async function deriveIv (contentKeyHex) {
  const ivFullHex = await hashBytes(concat(enc(IV_LABEL), fromHex(contentKeyHex)))
  return fromHex(ivFullHex).slice(0, IV_BYTES)
}

// Import a hex SHA-256 content key as a non-extractable AES-256-GCM key.
async function importContentKey (contentKeyHex, usages) {
  return subtle().importKey('raw', fromHex(contentKeyHex), { name: 'AES-GCM', length: 256 }, false, usages)
}

// box(bodyBytes) -> { C, contentKey, iv, blobId }
//   contentKey = SHA-256(body)                       (hex, 64 chars — the AES key)
//   iv         = SHA-256("bs-iv"‖contentKey)[:12]    (Uint8Array, 12 bytes)
//   C          = AES-256-GCM(body, key=contentKey, iv)   (Uint8Array ciphertext‖tag)
//   blobId     = SHA-256(C)                           (hex — content address of C)
// C, contentKey and blobId are deterministic in body → identical bodies box to
// identical outputs (dedup). Returns opaque bytes; the caller publishes
// {blobId, contentKey, iv} in the signed manifest and stores C as blob!<blobId>.
export async function box (bodyBytes) {
  const body = asBytes(bodyBytes, 'body')
  const contentKey = await hashBytes(body)          // hex
  const iv = await deriveIv(contentKey)             // Uint8Array(12)
  const key = await importContentKey(contentKey, ['encrypt'])
  const C = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, key, body))
  const blobId = await hashBytes(C)                 // hex
  return { C, contentKey, iv, blobId }
}

// unbox(C, contentKey, iv) -> bodyBytes
//   1. AES-256-GCM decrypt C with key=contentKey, iv → recovered plaintext P
//      (GCM's own auth tag rejects any tampered ciphertext here — throws).
//   2. HARD GATE (mandatory, NOT advisory): SHA-256(P) MUST equal contentKey,
//      else throw. This closes AES-GCM's key-commitment gap: it proves the
//      ciphertext was genuinely produced from THIS plaintext under a key that is
//      the plaintext's own hash — a substituted/mis-keyed blob cannot pass.
// (The complementary SHA-256(C) == blobId check is the CALLER's responsibility —
//  it is checkable before calling unbox, since blobId comes from the untrusted
//  manifest and C from an untrusted relay; unbox owns the plaintext↔key gate.)
export async function unbox (C, contentKey, iv) {
  const ct = asBytes(C, 'ciphertext')
  const nonce = asBytes(iv, 'iv')
  if (typeof contentKey !== 'string' || !/^[0-9a-f]{64}$/i.test(contentKey)) {
    throw new Error('unbox: contentKey must be a 64-char hex SHA-256.')
  }
  const key = await importContentKey(contentKey, ['decrypt'])
  let plaintext
  try {
    plaintext = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonce }, key, ct))
  } catch {
    // GCM auth-tag failure: ciphertext or IV was tampered with, or wrong key.
    throw new Error('unbox: AES-GCM authentication failed (tampered ciphertext, wrong iv, or wrong key).')
  }
  // MANDATORY key-commitment rejection — convergent self-check is a hard gate.
  const recomputed = await hashBytes(plaintext)
  if (recomputed.toLowerCase() !== contentKey.toLowerCase()) {
    throw new Error('unbox: content-key gate failed (SHA-256(plaintext) != contentKey); blob is substituted or mis-keyed.')
  }
  return plaintext
}
