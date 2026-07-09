// identity-export.js — encrypted, portable export of a browser-held (DevIdentity)
// signing key, so a web/phone user can move their identity to another device.
//
// The seed is a BEARER secret: whoever holds it can sign as you, forever. So the
// export is ALWAYS passphrase-encrypted at rest — PBKDF2-SHA256 stretches the
// passphrase and AES-256-GCM seals the seed, both via crypto.subtle (no new deps).
//
// The envelope carries the pubkey in CLEARTEXT for two reasons: the UI can show
// "this file is for u/<pub>" before decrypting, and it is an integrity anchor —
// on import we sign a probe with the decrypted seed and verify it against that
// pubkey, so a seed that does not match its key is rejected. GCM already
// authenticates the ciphertext; the cleartext header is cross-checked too.
//
// This is deliberately SEPARATE from recovery.js: a recovery bundle is public
// discoverability data (outbox invite keys), this is the private signing key.

import { sign as edSign, verify as edVerify, ready as cryptoReady, isSecure } from './crypto.js'

export const EXPORT_TYPE = 'peerit-identity-export'
export const EXPORT_VERSION = 1
export const APP_NAME = 'peerit'

const PBKDF2_ITERATIONS = 600000
const MAX_ITERATIONS = 5000000 // reject a hostile file that would pin the CPU
export const MIN_PASSPHRASE = 8
const HEX64 = /^[0-9a-f]{64}$/i

function subtle () {
  const s = globalThis.crypto && globalThis.crypto.subtle
  if (!s) throw new Error('Secure crypto (crypto.subtle) is unavailable here; cannot encrypt an identity export.')
  return s
}

function randomBytes (n) {
  const g = globalThis.crypto
  if (!g || typeof g.getRandomValues !== 'function') throw new Error('Secure random generator is unavailable here.')
  return g.getRandomValues(new Uint8Array(n))
}

const enc = (s) => new TextEncoder().encode(s)
const dec = (u) => new TextDecoder().decode(u)

function b64 (u8) {
  if (typeof btoa === 'function') { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s) }
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64')
  throw new Error('base64 encoder unavailable')
}

function unb64 (s) {
  if (typeof atob === 'function') {
    const bin = atob(String(s))
    const u = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i)
    return u
  }
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(String(s), 'base64'))
  throw new Error('base64 decoder unavailable')
}

async function deriveKey (passphrase, salt, iterations) {
  const base = await subtle().importKey('raw', enc(passphrase), { name: 'PBKDF2' }, false, ['deriveKey'])
  return subtle().deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

// Prove a seed actually signs for a claimed pubkey (import-time integrity check).
async function seedMatchesPubkey (seed, pubkey) {
  const probe = `peerit-identity-import-check:${pubkey}`
  const sig = await edSign(seed, probe)
  return edVerify(pubkey, probe, sig)
}

// Encrypt a DevIdentity roster entry into a shareable envelope object.
// entry: { seed(hex64), pubkey(hex64), driveKey?, label? }.
export async function exportIdentity (entry, passphrase, opts = {}) {
  const seed = String(entry && entry.seed || '').toLowerCase()
  const pubkey = String(entry && entry.pubkey || '').toLowerCase()
  const driveKey = String(entry && entry.driveKey || pubkey).toLowerCase()
  const label = entry && entry.label ? String(entry.label) : null
  if (!HEX64.test(seed)) throw new Error('Identity seed is not a 32-byte hex key; nothing to export.')
  if (!HEX64.test(pubkey)) throw new Error('Identity public key is invalid.')
  passphrase = String(passphrase == null ? '' : passphrase)
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE} characters.`)

  await cryptoReady()
  if (!isSecure()) throw new Error('This browser has no real Ed25519 backend, so the local identity is a placeholder, not a real key. Refusing to export it.')
  // Guard against exporting a seed that does not match its own public key.
  if (!(await seedMatchesPubkey(seed, pubkey))) throw new Error('Local identity is inconsistent (seed does not match its public key); refusing to export.')

  const iterations = opts.iterations || PBKDF2_ITERATIONS
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const key = await deriveKey(passphrase, salt, iterations)
  const plaintext = enc(JSON.stringify({ seed, pubkey, driveKey, label }))
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, key, plaintext))
  const createdAt = opts.createdAt || new Date().toISOString()

  return {
    type: EXPORT_TYPE,
    version: EXPORT_VERSION,
    app: APP_NAME,
    pubkey,
    label,
    createdAt,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: b64(salt) },
    cipher: { name: 'AES-GCM', iv: b64(iv) },
    ciphertext: b64(ct)
  }
}

function parseEnvelope (input) {
  let env = input
  if (typeof input === 'string') {
    const t = input.trim()
    if (!t) throw new Error('Paste an identity export first.')
    try { env = JSON.parse(t) } catch { throw new Error('Identity export is not valid JSON.') }
  }
  if (!env || typeof env !== 'object' || Array.isArray(env)) throw new Error('Identity export must be a JSON object.')
  if (env.type !== EXPORT_TYPE) throw new Error('This file is not a peerit identity export.')
  if (env.version !== EXPORT_VERSION) throw new Error('Identity export version is not supported.')
  if (env.app !== APP_NAME) throw new Error(`Identity export is for ${env.app || 'another app'}, not ${APP_NAME}.`)
  const kdf = env.kdf || {}
  if (kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256' || !(kdf.iterations > 0) || typeof kdf.salt !== 'string') {
    throw new Error('Identity export key-derivation parameters are invalid.')
  }
  if (kdf.iterations > MAX_ITERATIONS) throw new Error('Identity export iteration count is unreasonably high; refusing to process it.')
  const cipher = env.cipher || {}
  if (cipher.name !== 'AES-GCM' || typeof cipher.iv !== 'string') throw new Error('Identity export cipher parameters are invalid.')
  if (typeof env.ciphertext !== 'string' || !env.ciphertext) throw new Error('Identity export is missing its ciphertext.')
  return env
}

// Decrypt + validate an envelope. Returns { seed, pubkey, driveKey, label }.
export async function importIdentity (input, passphrase) {
  const env = parseEnvelope(input)
  passphrase = String(passphrase == null ? '' : passphrase)
  if (!passphrase) throw new Error('Enter the passphrase used to encrypt this identity export.')

  await cryptoReady()
  if (!isSecure()) throw new Error('This browser has no real Ed25519 backend; cannot verify an imported identity.')

  const salt = unb64(env.kdf.salt)
  const iv = unb64(env.cipher.iv)
  const key = await deriveKey(passphrase, salt, env.kdf.iterations)
  let plaintext
  try {
    plaintext = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv }, key, unb64(env.ciphertext)))
  } catch {
    throw new Error('Could not decrypt — wrong passphrase, or the export is corrupted.')
  }
  let inner
  try { inner = JSON.parse(dec(plaintext)) } catch { throw new Error('Decrypted identity payload is not valid.') }

  const seed = String(inner && inner.seed || '').toLowerCase()
  if (!HEX64.test(seed)) throw new Error('Decrypted identity seed is invalid.')
  const pubkey = String(inner.pubkey || env.pubkey || '').toLowerCase()
  if (!HEX64.test(pubkey)) throw new Error('Decrypted identity public key is invalid.')
  // The cleartext header must agree with the authenticated contents.
  if (HEX64.test(String(env.pubkey || '')) && String(env.pubkey).toLowerCase() !== pubkey) {
    throw new Error('Identity export header does not match its encrypted contents.')
  }
  // The seed must actually sign for the claimed pubkey.
  if (!(await seedMatchesPubkey(seed, pubkey))) {
    throw new Error('Imported identity failed its integrity check (seed does not match its public key).')
  }

  const driveKey = String(inner.driveKey || pubkey).toLowerCase()
  const label = inner.label ? String(inner.label) : (env.label ? String(env.label) : null)
  return { seed, pubkey, driveKey, label }
}

// Cheap sniff so paste-import can route between a recovery bundle and this.
export function looksLikeIdentityExport (input) {
  let env = input
  if (typeof input === 'string') { try { env = JSON.parse(input) } catch { return false } }
  return !!(env && typeof env === 'object' && env.type === EXPORT_TYPE)
}

export function identityExportJson (envelope) {
  return JSON.stringify(envelope, null, 2) + '\n'
}

export function identityExportFilename (pubkey, createdAt) {
  const pub = String(pubkey || '').toLowerCase().slice(0, 12) || 'unknown'
  const date = String(createdAt || new Date().toISOString()).slice(0, 10)
  return `${APP_NAME}-identity-${pub}-${date}.json`
}

// Coarse passphrase strength for a UI hint (0 weak .. 4 strong). Not a gate —
// PBKDF2 slows offline cracking, it cannot rescue a trivial passphrase.
export function passphraseStrength (pw) {
  pw = String(pw == null ? '' : pw)
  if (pw.length < MIN_PASSPHRASE) return { score: 0, label: 'too short' }
  let score = 0
  if (pw.length >= 12) score++
  if (pw.length >= 20) score++
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++
  if (/\d/.test(pw)) score++
  if (/[^A-Za-z0-9]/.test(pw)) score++
  score = Math.min(4, score)
  return { score, label: ['weak', 'fair', 'okay', 'good', 'strong'][score] }
}
