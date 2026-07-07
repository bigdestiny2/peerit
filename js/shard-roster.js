// shard-roster.js — signing + verification for the BlindShard cohort roster
// (PURE-PIPE-SCOPE §5.2). Mirrors relay-roster.js: the shard roster is signed by
// the SAME pinned Ed25519 roster anchor as relay-roster.json, so the web build
// keeps ONE trust pin for both planes. An unsigned/foreign/expired roster must
// never enable dispersal — a swapped cohort would silently re-point every new
// post's body + key shares at an attacker's relays.
//
// Envelope (config/shard-roster.public.json):
//   { payload: { version: 1, expires: ISO, threshold, retainMs, relays: [{url, pubkey}] },
//     signature: { alg: 'Ed25519', key: <hex64>, sig: <hex128> } }

import { verify as edVerify } from './crypto.js'

export const SHARD_ROSTER_ALG = 'Ed25519'
export const SHARD_ROSTER_VERSION = 1
const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i

// Deterministic, key-sorted JSON so signer and verifier hash identical bytes.
function stable (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v)
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']'
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}'
}

export function normalizeShardRosterPayload (payload = {}) {
  const version = Number(payload.version) || SHARD_ROSTER_VERSION
  const expires = String(payload.expires || '').trim()
  const threshold = Number(payload.threshold) || 0
  const retainMs = Number(payload.retainMs) || 30 * 24 * 60 * 60 * 1000
  const relays = (Array.isArray(payload.relays) ? payload.relays : [])
    .map((r) => ({
      url: String((r && (r.url || r.baseUrl)) || '').replace(/\/+$/, ''),
      pubkey: String((r && (r.pubkey || r.publicKey)) || '').toLowerCase()
    }))
    .filter((r) => r.url)
  return { version, expires, threshold, retainMs, relays }
}

export function shardRosterSigningMessage (payload) {
  return 'peerit-shard-roster-v1|' + stable(normalizeShardRosterPayload(payload))
}

// Verify a signed shard roster against the pinned roster key. Throws with a
// specific reason on any failure; returns the normalized payload on success.
// Hard requirements beyond the signature: unexpired, >=2 relays, every relay has
// a REAL pubkey (an empty pubkey would let an operator swap custody targets), no
// duplicate pubkeys (a duplicated operator would silently hold >= threshold), and
// a sane threshold (2 <= k <= n).
export async function verifyShardRoster (roster, { expectedKey, now = Date.now() } = {}) {
  if (!roster || typeof roster !== 'object') throw new Error('shard roster must be an object')
  const key = String(expectedKey || '').trim().toLowerCase()
  if (!HEX64.test(key)) throw new Error('missing or invalid pinned roster key for the shard roster')
  if (!roster.payload || typeof roster.payload !== 'object') throw new Error('shard roster payload is missing (unsigned legacy roster?)')

  const payload = normalizeShardRosterPayload(roster.payload)
  if (payload.version !== SHARD_ROSTER_VERSION) throw new Error('unsupported shard roster version')

  const expiresMs = Date.parse(payload.expires)
  if (!Number.isFinite(expiresMs)) throw new Error('shard roster expires is invalid')
  if (expiresMs <= Number(now)) throw new Error('shard roster expired')

  if (payload.relays.length < 2) throw new Error('shard roster needs at least 2 relays')
  const pubs = new Set()
  for (const r of payload.relays) {
    if (!HEX64.test(r.pubkey)) throw new Error('shard roster relay ' + r.url + ' has no valid pubkey')
    if (pubs.has(r.pubkey)) throw new Error('shard roster contains duplicate relay pubkeys')
    pubs.add(r.pubkey)
  }
  if (!(payload.threshold >= 2 && payload.threshold <= payload.relays.length)) {
    throw new Error('shard roster threshold must satisfy 2 <= k <= relays.length')
  }

  const sig = roster.signature || {}
  const sigKey = String(sig.key || '').trim().toLowerCase()
  if (sig.alg !== SHARD_ROSTER_ALG) throw new Error('unsupported shard roster signature algorithm')
  if (sigKey !== key) throw new Error('shard roster was signed by an unexpected key (not the pinned roster key)')
  if (!HEX128.test(String(sig.sig || '').toLowerCase())) throw new Error('shard roster signature is invalid')
  const ok = await edVerify(sigKey, shardRosterSigningMessage(roster.payload), String(sig.sig).toLowerCase())
  if (!ok) throw new Error('shard roster signature did not verify')
  return payload
}
