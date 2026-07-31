// Identity primitives shared by the legacy host adapter and the replacement
// browser runtime. This module deliberately has no host, relay, or persistence
// imports: a substrate-only browser bundle can authenticate an identity entry
// without pulling any retired transport surface into its module graph.

import {
  isSecure,
  ready as cryptoReady,
  sign as edSign,
  verify as edVerify
} from './crypto.js'

const HEX64 = /^[0-9a-f]{64}$/i

export async function verifiedIdentityEntry (entry, context = 'identity') {
  const seed = String((entry && entry.seed) || '').toLowerCase()
  const pubkey = String((entry && entry.pubkey) || '').toLowerCase()
  const driveKey = String((entry && entry.driveKey) || pubkey).toLowerCase()
  if (!HEX64.test(seed) || !HEX64.test(pubkey)) {
    throw new Error(`${context}: invalid seed or public key`)
  }
  if (!HEX64.test(driveKey)) throw new Error(`${context}: invalid drive key`)
  await cryptoReady()
  if (!isSecure()) throw new Error(`${context}: secure Ed25519 verification is unavailable`)
  const probe = `peerit-identity-entry-check:${pubkey}`
  const signature = await edSign(seed, probe)
  if (!(await edVerify(pubkey, probe, signature))) {
    throw new Error(`${context}: seed does not match public key`)
  }
  return {
    seed,
    pubkey,
    driveKey,
    label: entry && entry.label ? String(entry.label) : 'imported'
  }
}
