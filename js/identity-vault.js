// identity-vault.js — a DURABLE, passphrase-locked home for a browser-held
// (DevIdentity) signing seed, so a web identity survives reload WITHOUT ever
// writing the seed (or a key derived from it) to disk in cleartext.
//
// This is the UX follow-up to the A1 fix (js/identity.js): A1 stopped persisting
// the raw Ed25519 seed, which — correctly — made web identities reset on every
// reload. That is unacceptable for a social app, so this module lets a user OPT IN
// to durability by choosing a passphrase. What lands on disk is ONLY the
// PBKDF2 + AES-256-GCM envelope produced by identity-export.js — the exact same
// crypto we already ship for portable exports. No new KDF, no new cipher.
//
// The at-rest guarantee is unchanged from A1: the plaintext seed and the derived
// AES key exist in memory only. localStorage holds ciphertext under 'peerit:vault:v1'
// and nothing else. Decryption happens at boot, into the same in-memory DevIdentity
// path A1 established; a wrong passphrase fails cleanly (GCM auth failure) with no
// identity restored and no partial state.
//
// Out of scope (documented, not stubbed): passphrase RECOVERY (there is no server
// and no escrow — a forgotten passphrase means the vault is unrecoverable, exactly
// like the export file) and MULTI-DEVICE sync (use the existing export/import flow,
// or seed a second device from its own vault). A vault is single-origin, single-device.

import { exportIdentity, importIdentity, EXPORT_TYPE, MIN_PASSPHRASE } from './identity-export.js'

// A localStorage key distinct from the A1 roster key ('peerit:dev:users'), so the
// vault never collides with (or resurrects) the cleartext roster A1 removed.
export const VAULT_KEY = 'peerit:vault:v1'
const HEX64 = /^[0-9a-f]{64}$/i

export { MIN_PASSPHRASE }

// Is `env` a persisted vault envelope? A vault is exactly an identity-export
// envelope (same type/shape) that we chose to keep on disk under VAULT_KEY.
export function isVaultEnvelope (env) {
  return !!(env && typeof env === 'object' && !Array.isArray(env) && env.type === EXPORT_TYPE && typeof env.ciphertext === 'string')
}

// Read + parse the stored vault envelope (or null). Never throws on a malformed
// blob — a corrupt vault is treated as "no vault" so boot can degrade to A1's
// fresh-identity path rather than wedging.
export function readVault (storage) {
  if (!storage || typeof storage.getItem !== 'function') return null
  let raw
  try { raw = storage.getItem(VAULT_KEY) } catch { return null }
  if (!raw) return null
  let env
  try { env = JSON.parse(raw) } catch { return null }
  return isVaultEnvelope(env) ? env : null
}

export function hasVault (storage) { return !!readVault(storage) }

// The cleartext pubkey the vault is FOR — lets the unlock UI say "unlock u/<pub>"
// before any decryption happens. Same anchor the export envelope carries.
export function vaultPubkey (storage) {
  const env = readVault(storage)
  return env && HEX64.test(String(env.pubkey || '')) ? String(env.pubkey).toLowerCase() : null
}

// Encrypt `entry` (a DevIdentity seed entry: { seed, pubkey, driveKey?, label? })
// under `passphrase` and persist ONLY the resulting ciphertext envelope to
// localStorage. Returns the envelope that was stored.
//
// The raw seed and the derived AES key never touch `storage`: exportIdentity does
// the sealing in memory (crypto.subtle, non-extractable key) and hands back an
// envelope whose only secret-bearing field is the AES-GCM ciphertext.
export async function saveVault (storage, entry, passphrase, opts = {}) {
  if (!storage || typeof storage.setItem !== 'function') throw new Error('No writable storage for the identity vault.')
  const seed = String((entry && entry.seed) || '').toLowerCase()
  if (!HEX64.test(seed)) throw new Error('Cannot remember this identity: it has no exportable seed.')
  passphrase = String(passphrase == null ? '' : passphrase)
  if (passphrase.length < MIN_PASSPHRASE) throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE} characters.`)
  // exportIdentity already: validates the seed matches its pubkey, PBKDF2-stretches
  // the passphrase, and AES-256-GCM seals the seed. We reuse it verbatim.
  const envelope = await exportIdentity(entry, passphrase, opts)
  // Defence in depth: never let a raw seed slip into the persisted string. The
  // envelope carries only the pubkey in cleartext; the seed lives in ciphertext.
  const json = JSON.stringify(envelope)
  if (json.includes(seed)) throw new Error('Refusing to persist vault: the raw seed leaked into the envelope.')
  storage.setItem(VAULT_KEY, json)
  return envelope
}

// Decrypt the stored vault with `passphrase` and return the identity entry
// { seed, pubkey, driveKey, label }. Throws cleanly on a wrong passphrase (the
// GCM auth failure surfaced by importIdentity) — the caller restores nothing.
export async function unlockVault (storage, passphrase) {
  const env = readVault(storage)
  if (!env) throw new Error('There is no saved identity to unlock on this device.')
  // importIdentity does the PBKDF2 derive + AES-GCM open + seed↔pubkey integrity
  // check, and throws "Could not decrypt — wrong passphrase…" on failure.
  return importIdentity(env, passphrase)
}

// Forget the durable identity: remove the ciphertext from disk. The in-memory
// identity (if any) is untouched — this only drops reload durability.
export function clearVault (storage) {
  if (!storage || typeof storage.removeItem !== 'function') return
  try { storage.removeItem(VAULT_KEY) } catch {}
}
