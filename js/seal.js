// seal.js — the v2 blind key-scheme primitives (docs/BLIND-OUTBOX-MIGRATION.md).
//
// Two things, both under one bundled network constant PEERIT_READ_KEY (RK):
//   1. okey()  — the OPAQUE storage key. Replaces the plaintext semantic key
//                (post!<community>!<cid>, vote!<target>!<author>, …). The record
//                TYPE is folded INTO the HMAC so the wire key is `v2!<okey>` with no
//                semantic scope — an operator can't grep or prefix-index the graph.
//   2. seal()/unseal() — an AEAD envelope for the structural fields (community,
//                targetCid, parentCid, _t, ts, vote value, short bodies…) so the
//                operator can't PASSIVELY read the graph from the value either. It
//                must affirmatively decrypt (it holds RK — a reader).
//
// HONEST CEILING (docs/OPERATOR-LIABILITY.md): RK ships to every client, so this is
// NOT confidentiality. It is no-passive-read + no-semantic-index + content-neutral +
// deniability. Never claim "the operator can't read your posts." okey is deterministic
// over guessable inputs, so TARGETED CONFIRMATION ("did A vote on known post P?") stays
// O(1) for an RK-holder — the win is no ENUMERATION, not no confirmation.
//
// Deterministic okey (same inputs → same key) is load-bearing: it preserves storage-
// layer LWW self-compaction (a re-vote/edit overwrites its own slot) exactly as the
// plaintext key did today.

const enc = new TextEncoder()
const dec = new TextDecoder()
const toHex = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s }
const fromHex = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a }
const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s) }
const unb64 = (s) => { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u }

const NUL = '\x00'
const SEAL_AAD = enc.encode('peerit.seal.v1')       // domain-binds the envelope
export const SEAL_VERSION = 1

// The app-wide network read key. PUBLIC BY DESIGN (it is bundled into every client);
// this is deniability + no-passive-index, not secrecy. Overridable for tests / a
// build-injected value via setReadKey(). 32 bytes hex.
let RK_HEX = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90'
export function setReadKey (hex) {
  if (!/^[0-9a-f]{64}$/i.test(String(hex || ''))) throw new Error('setReadKey: expected 32-byte hex')
  RK_HEX = String(hex).toLowerCase(); _okeyKey = null; _sealKey = null
}

function subtle () {
  const s = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) || null
  if (!s) throw new Error('seal.js requires WebCrypto SubtleCrypto (browser / Node 20+)')
  return s
}
function randomBytes (n) {
  const g = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) ? globalThis.crypto : null
  if (!g) throw new Error('seal.js requires crypto.getRandomValues')
  const u = new Uint8Array(n); g.getRandomValues(u); return u
}

// Domain-separated sub-keys derived from RK: SHA-256(RK ‖ label). RK is a high-entropy
// 32-byte constant, so a hash-based KDF is sufficient (no HKDF ceremony needed).
let _okeyKey = null // CryptoKey (HMAC-SHA256)
let _sealKey = null // CryptoKey (AES-256-GCM)
async function subKeyRaw (label) {
  const material = new Uint8Array([...fromHex(RK_HEX), ...enc.encode(label)])
  return new Uint8Array(await subtle().digest('SHA-256', material))
}
async function okeyKey () {
  if (!_okeyKey) _okeyKey = await subtle().importKey('raw', await subKeyRaw('okey'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return _okeyKey
}
async function sealKey () {
  if (!_sealKey) _sealKey = await subtle().importKey('raw', await subKeyRaw('seal'), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
  return _sealKey
}

async function hmac (msg) {
  const sig = new Uint8Array(await subtle().sign('HMAC', await okeyKey(), enc.encode(msg)))
  return toHex(sig) // 64 hex (full SHA-256)
}

// Family A — per-author records. Author-bound so a peer can't park a record under a
// victim's okey. `semanticId` is the SAME tuple id.* builds today (post: community‖cid,
// vote: targetCid‖author, comment: community‖postCid‖cid, profile: author, mod:
// community‖actionId, head: author).
export async function okey (t, semanticId, author) {
  if (!t || !author) throw new Error('okey: type + author required')
  return hmac(String(author) + NUL + String(t) + NUL + String(semanticId == null ? '' : semanticId))
}

// Family B — the ONE cross-author shared slot: the community claim. Author-INDEPENDENT
// so rival creators for a slug collide at one slot (anti-squat sticky-claim fires).
// Caller passes an already-normalized slug.
export async function communityOkey (normalizedSlug) {
  return hmac('community' + NUL + String(normalizedSlug == null ? '' : normalizedSlug))
}

// Membership roster slot — author-INDEPENDENT, one fetchable slot per community, so a
// fresh visitor can pull only r/x's members (bounds the O(authors) discovery pull).
export async function membersOkey (normalizedSlug) {
  return hmac('members' + NUL + String(normalizedSlug == null ? '' : normalizedSlug))
}

// Seal an object into an opaque envelope { v, iv, ct }. Random IV → identical content
// yields DIFFERENT ciphertext (defeats the convergent-confirmation attack on short/low-
// entropy bodies). Throws on a missing crypto backend.
export async function seal (obj) {
  const iv = randomBytes(12)
  const pt = enc.encode(JSON.stringify(obj))
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: SEAL_AAD }, await sealKey(), pt))
  return { v: SEAL_VERSION, iv: toHex(iv), ct: b64(ct) }
}

// Unseal; returns the object, or THROWS on tamper (GCM tag) / wrong key / bad shape.
export async function unseal (env) {
  if (!env || env.v !== SEAL_VERSION || typeof env.iv !== 'string' || typeof env.ct !== 'string') throw new Error('unseal: bad envelope')
  const pt = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: fromHex(env.iv), additionalData: SEAL_AAD }, await sealKey(), unb64(env.ct)))
  return JSON.parse(dec.decode(pt))
}

export const _internals = { toHex, fromHex, NUL }
