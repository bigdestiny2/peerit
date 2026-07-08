// blob-store.js — BlindShard Phase 2 glue: turn a long post BODY into an opaque,
// content-addressed ciphertext the relay stores WITHOUT the plaintext, plus the
// signed manifest the author embeds in the post record. (BLINDSHARD-DESIGN.md §5
// Phase 2 — "box-before-store".)
//
// This is the string/base64/manifest layer on top of the pure-bytes primitive in
// box.js: box.js owns the AES-GCM + content-key gate; here we handle UTF-8 ↔ bytes,
// base64 for JSON storage, the size threshold, and the second content-address gate
// (SHA-256(C) == blobId) that box.js explicitly delegates to the caller.
//
// HONEST SCOPE (design §2, §6.1): this delivers "ciphertext-at-rest, not casually
// grep-able" — NOT dispersal and NOT operator-blindness. The signed manifest still
// carries the contentKey, so a single relay co-holding the post + blob can decrypt.
// Dispersal (no single relay holds a readable/complete item) is Phase 3.

import { box, unbox } from './box.js'
import { hashBytes } from './crypto.js'

// Only bodies in this byte range are boxed:
//  • below MIN, a second record + fetch costs more than the plaintext saves;
//  • above MAX, a single base64 blob (base64 is +33%) approaches the relay's
//    ~64 KiB per-value cap, so it stays inline until Phase 3 adds chunking/erasure
//    (design §6.4). Post bodies are capped at 40 000 elsewhere, so [2 KiB, ~34 KB]
//    is the boxed band and (34 KB, 40 KB] stays inline for now.
export const BOX_MIN_BYTES = 2048
export const BOX_MAX_BYTES = 34000
export const MANIFEST_V = 1

const te = new TextEncoder()
const td = new TextDecoder()

export function bodyByteLength (bodyStr) { return te.encode(String(bodyStr == null ? '' : bodyStr)).length }

// Whether a body should be boxed rather than stored inline as plaintext.
export function shouldBox (bodyStr) {
  const n = bodyByteLength(bodyStr)
  return n >= BOX_MIN_BYTES && n <= BOX_MAX_BYTES
}

// box()/unbox() need SubtleCrypto's AES-GCM. Where it is absent (cooperative-dev,
// or an insecure browser context) we must NOT box — the write path falls back to
// inline plaintext so posting still works, exactly as it did pre-Phase-2. Reads
// are unaffected: a record with no manifest is never hydrated.
export function canBox () { return !!(globalThis.crypto && globalThis.crypto.subtle) }

// A generous ceiling on a blob's base64 ciphertext, so verifyBlobRecord can't be
// turned into a decode/hash bomb by a peer claiming a huge ct. BOX_MAX (34 KB) →
// ~45 KB base64; this leaves margin up to the relay's ~64 KiB per-value cap.
const MAX_CT_B64 = 65536

// SELF-CERTIFICATION GATE for the merge (design §2 / review FIX 1). blob!<blobId>
// is content-addressed but its KEY is not scoped to an author (any peer may sign a
// record for any blobId), so without this an attacker can publish a validly-signed
// blob!<X> with garbage/absent ct that WINS the LWW collision at the shared key and
// blanks a victim's boxed body network-wide. Admission must therefore verify the
// content address itself: a blob is admissible ONLY if SHA-256(its ct) == its own
// blobId. Then every admissible record at blob!<X> is byte-identical, so the LWW
// winner is irrelevant and the tombstone/sig tiebreak is moot for blobs.
export async function verifyBlobRecord (val) {
  if (!val || typeof val.ct !== 'string' || !val.blobId || val.ct.length > MAX_CT_B64) return false
  try {
    const got = await hashBytes(b64Decode(val.ct))
    return got.toLowerCase() === String(val.blobId).toLowerCase()
  } catch { return false }
}

function toHex (u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s }
function fromHex (h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a }

function b64Encode (u8) {
  if (typeof btoa === 'function') { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s) }
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64')
  throw new Error('base64 encoder unavailable')
}
function b64Decode (s) {
  if (typeof atob === 'function') { const bin = atob(String(s)); const u = new Uint8Array(bin.length); for (let i = 0; i < u.length; i++) u[i] = bin.charCodeAt(i); return u }
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(String(s), 'base64'))
  throw new Error('base64 decoder unavailable')
}

// boxBody(bodyStr) -> { manifest, ct }
//   manifest = { v, blobId, contentKey, iv }   — JSON-safe (iv + keys are hex);
//              the author embeds this in the SIGNED post record so it's tamper-proof.
//   ct       = base64(C)                        — opaque ciphertext, stored as blob!<blobId>.
export async function boxBody (bodyStr) {
  const bytes = te.encode(String(bodyStr == null ? '' : bodyStr))
  const { C, contentKey, iv, blobId } = await box(bytes)
  return {
    manifest: { v: MANIFEST_V, blobId, contentKey, iv: toHex(iv) },
    ct: b64Encode(C)
  }
}

// unboxToBody(ct, manifest) -> bodyStr. Enforces BOTH content-address gates so a
// relay can neither substitute nor mis-key the blob:
//   1. SHA-256(C) === manifest.blobId    (here — the blobId comes from the signed
//                                          manifest, C from an untrusted relay);
//   2. SHA-256(plaintext) === contentKey  (inside box.js unbox() — key-commitment).
export async function unboxToBody (ct, manifest) {
  if (!manifest || !manifest.blobId || !manifest.contentKey || !manifest.iv) {
    throw new Error('unboxToBody: incomplete manifest (need blobId, contentKey, iv)')
  }
  const C = b64Decode(ct)
  const gotBlobId = await hashBytes(C)
  if (gotBlobId.toLowerCase() !== String(manifest.blobId).toLowerCase()) {
    throw new Error('unboxToBody: blob content-address mismatch (SHA-256(C) != blobId); relay substituted or corrupted the blob.')
  }
  const plaintext = await unbox(C, manifest.contentKey, fromHex(manifest.iv))
  return td.decode(plaintext)
}
