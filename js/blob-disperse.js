// ⚠️ RETIRED (2026-07-04) — superseded by js/blind-dealer.mjs on the vendored PVSS client.
// This is the old erasure-over-ciphertext glue (Reed-Solomon + SHA-256 addressing). The
// shipped surface (HiveRelay v0.24.0 / PR #159) is PVSS-secp256k1 + blake2b + custody
// intents. Not shipped, not imported by the live dealer; kept for reference only.
//
// blob-disperse.js — BlindShard Phase 3 glue: box a body, erasure-code the
// ciphertext into K-of-N shards, and DISPERSE them across relays so no single
// relay holds a readable OR complete item. The reverse gathers any K shards,
// verifies each by its content address, reconstructs, and decrypts.
//
// DEPENDENCY-INJECTED against the shard blob surface HiveRelay is landing
// (docs/BLINDSHARD-BLOB-SURFACE-HANDOVER.md §4): the caller passes a `backend`
//   { putShard(relayPub, shardId, bytes) -> receipt,
//     getShard(relayPub, shardId) -> bytes|null }
// so this module rides the real `shard:<hash>` PUT/GET (over the Noise-tunneled
// dht-relay-ws) by its INTERFACE, exactly as dht-adapter.js was built+tested
// against fakes before the live wire. NOT wired into data.js and NOT in
// SITE_FILES yet — Phase 3 is HELD on (a) the live blind blob surface and (b) >=3
// INDEPENDENT relays (dispersal across same-owner relays is theater). This is the
// client logic, unit-tested against a fake backend; it is NOT a claim of live
// dispersal.
//
// HONEST CEILING (design §6.1/§6.2): public content stays reconstructable by any
// reader (contentKey ships in the public manifest); dispersal removes "one relay
// holds a readable/complete copy," not "the content is secret." Blindness holds
// against INDEPENDENT relays; a fully colluding roster (or one relay mis-assigned
// >=K shards + the manifest) reconstructs everything.

import { box, unbox } from './box.js'
import { encode, decode, place, shardId, shouldErasure } from './shard.js'
import { hashBytes } from './crypto.js'

export const DEFAULT_K = 6
export const DEFAULT_N = 9

const te = new TextEncoder()
const td = new TextDecoder()
const toHex = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s }
const fromHex = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a }

// Whether a body is large enough to erasure-disperse (vs Phase-2 single-blob).
export function shouldDisperse (bodyStr) { return shouldErasure(te.encode(String(bodyStr == null ? '' : bodyStr)).length) }

// disperseBody(bodyStr, { backend, roster, k, n, replicas }) ->
//   { manifest, receipts, assignment }
//   manifest = { v, blobId, contentKey, iv, k, n, replicas, shardIds }  (shardIds[i] = shard index i)
// Writes each shard's bytes to every relay place() assigns it to; a shard is
// content-addressed (shardId = SHA-256(bytes)), so the relay self-verifies on PUT
// and can neither substitute nor mis-address it. `receipts` are the placement
// acknowledgements (custody receipts) for a Phase-4 durability quorum.
// `hashShard` is the SHARD content-address function — it MUST match the store's
// addressing. The real HiveRelay blind shard store addresses by blake2b-256
// (`sodium.crypto_generichash`, per BLIND-SHARD-STORE-SPEC.md §2); the concrete
// `/api/v1/shard` adapter injects that at wire time. The default here is SHA-256
// (crypto.js hashBytes) for the fake backend + tests — the module is hash-agnostic,
// so blake2b slots in with no logic change. (blobId, the ciphertext gate below,
// stays SHA-256: it is peerit's own integrity check, NOT a store address.)
export async function disperseBody (bodyStr, { backend, roster, k = DEFAULT_K, n = DEFAULT_N, replicas = 1, hashShard = hashBytes } = {}) {
  if (!backend || typeof backend.putShard !== 'function') throw new Error('disperseBody: backend.putShard required')
  if (!Array.isArray(roster) || !roster.length) throw new Error('disperseBody: a non-empty relay roster is required')
  const body = te.encode(String(bodyStr == null ? '' : bodyStr))
  const { C, contentKey, iv, blobId } = await box(body)

  const shards = await encode(C, { k, n })            // [{ index, bytes, id, shardLen }]
  // Address each shard with the injected hash (shard.js's own SHA-256 .id is ignored;
  // decode() needs only {index, bytes}), so the addresses match the store on the wire.
  const addressed = await Promise.all(shards.map(async (s) => ({ index: s.index, bytes: s.bytes, id: await hashShard(s.bytes) })))
  const shardIds = addressed.map((s) => s.id)          // index i -> shardId
  const byId = new Map(addressed.map((s) => [s.id, s.bytes]))
  const assignment = await place(shardIds, roster, { replicas, k }) // Map<relayPub, shardId[]>

  const receipts = []
  for (const [relayPub, ids] of assignment) {
    for (const sid of ids) {
      const receipt = await backend.putShard(relayPub, sid, byId.get(sid))
      receipts.push({ relayPub, shardId: sid, receipt })
    }
  }
  return {
    manifest: { v: 1, blobId, contentKey, iv: toHex(iv), k, n, replicas, shardIds },
    receipts,
    assignment
  }
}

// reassembleBody({ manifest, backend, roster }) -> bodyStr
// Gathers shards (recomputing the same HRW placement to know which relays to ask),
// content-address-checks each (SHA-256(bytes) === shardId — a relay can't
// substitute), RS-decodes once K are in hand, then applies the SAME two gates as
// the Phase-2 read (SHA-256(C) === blobId, and unbox()'s SHA-256(P) === contentKey).
export async function reassembleBody ({ manifest, backend, roster, hashShard = hashBytes } = {}) {
  if (!manifest || !Array.isArray(manifest.shardIds)) throw new Error('reassembleBody: manifest with shardIds required')
  if (!backend || typeof backend.getShard !== 'function') throw new Error('reassembleBody: backend.getShard required')
  const relayPubs = (roster || []).map((r) => (typeof r === 'string' ? r : (r && (r.pub || r.publicKey || r.key)))).filter(Boolean)
  if (!relayPubs.length) throw new Error('reassembleBody: a non-empty relay roster is required')
  const { k, n, shardIds } = manifest

  // HRW placement winners per shard are the EFFICIENT first-ask, but reconstruction
  // must NOT depend on the read-time roster matching the write-time roster: if the
  // roster churned (relays added/removed/reordered), HRW re-ranks and the winners
  // may be relays that never received the shard even though it is still physically
  // held elsewhere in the fleet. So try the winners first, then FALL BACK to the
  // rest of the current roster. The content-address gate (SHA-256(bytes)===shardId)
  // makes asking extra relays safe — a relay can't feed us a wrong shard.
  const winners = new Map()
  try {
    const assignment = await place(shardIds, roster, { replicas: manifest.replicas || 1, k })
    for (const [relayPub, ids] of assignment) for (const sid of ids) { if (!winners.has(sid)) winners.set(sid, []); winners.get(sid).push(relayPub) }
  } catch { /* placement infeasible against the read roster → pure fan-out below */ }
  const candidatesFor = (sid) => {
    const w = winners.get(sid) || []
    return [...w, ...relayPubs.filter((rp) => !w.includes(rp))]
  }

  const gathered = []
  for (let i = 0; i < shardIds.length && gathered.length < k; i++) {
    const sid = shardIds[i]
    for (const relayPub of candidatesFor(sid)) {
      let bytes
      try { bytes = await backend.getShard(relayPub, sid) } catch { bytes = null }
      if (!bytes) continue
      const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
      if ((await hashShard(u8)).toLowerCase() !== String(sid).toLowerCase()) continue // content-address gate (store's hash); substituted/corrupt → next candidate
      gathered.push({ index: i, bytes: u8, id: sid })
      break // got this shard; move to the next
    }
  }
  if (gathered.length < k) throw new Error(`reassembleBody: only ${gathered.length} of ${k} shards recovered — cannot reconstruct`)

  const C = await decode(gathered, { k, n })
  const gotBlobId = await hashBytes(C)
  if (gotBlobId.toLowerCase() !== String(manifest.blobId).toLowerCase()) {
    throw new Error('reassembleBody: reconstructed ciphertext does not match blobId')
  }
  const plaintext = await unbox(C, manifest.contentKey, fromHex(manifest.iv))
  return td.decode(plaintext)
}
