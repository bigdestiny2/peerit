// canon.js — canonical serialization, owner binding, and key binding. Shared by
// the signer (data.js) and the verifier (verify.js) so a signature covers
// exactly the bytes that get checked, and a record is pinned to both its author
// and its storage key.

import { TYPE, keys, semanticId } from './model.js'
import { okey, communityOkey } from './seal.js'

// The pubkey that must have authored a record of this type. The verifier
// requires the SIGNER (_k) to equal this — so you can't sign-as-someone-else.
export function ownerOf (type, data) {
  switch (type) {
    case TYPE.COMMUNITY: return data.creator
    case TYPE.MOD: return data.by
    default: return data.author // post, comment, vote, profile, head, blob, shard
  }
}

// The Hyperbee key a record MUST live under, recomputed from its own fields.
// The merge rejects any record whose actual key differs — so a peer can't park
// a record under someone else's key (e.g. evict a victim's vote/profile).
export function expectedKey (type, data) {
  switch (type) {
    case TYPE.COMMUNITY: return data.slug != null ? keys.community(data.slug) : null
    case TYPE.POST: return data.community != null && data.cid != null ? keys.post(data.community, data.cid) : null
    case TYPE.COMMENT: return data.community != null && data.postCid != null && data.cid != null ? keys.comment(data.community, data.postCid, data.cid) : null
    case TYPE.VOTE: return data.targetCid != null && data.author != null ? keys.vote(data.targetCid, data.author) : null
    case TYPE.REPORT: return data.community != null && data.targetCid != null && data.author != null ? keys.report(data.community, data.targetCid, data.author) : null
    case TYPE.PROFILE: return data.author != null ? keys.profile(data.author) : null
    case TYPE.MOD: return data.community != null && data.actionId != null ? keys.mod(data.community, data.actionId) : null
    case TYPE.HEAD: return data.author != null ? keys.head(data.author) : null
    case TYPE.BLOB: return data.blobId != null ? keys.blob(data.blobId) : null
    case TYPE.SHARD: return data.id != null ? keys.shard(data.id) : null
    case TYPE.FOLLOW: return data.target != null && data.author != null ? keys.follow(data.target, data.author) : null
    case TYPE.MEMBER: return data.community != null && data.author != null ? keys.member(data.community, data.author) : null
    default: return null
  }
}

// Signature metadata fields — excluded from the canonical form (you can't sign
// over your own signature) and stripped before hashing.
const SIG_FIELDS = new Set(['_sig', '_k', '_dk', '_ns', '_alg'])

// Deterministic, key-sorted JSON of a value, omitting signature metadata. This
// covers EVERY content field automatically, so there is no "forgot to sign field
// X" class of bug — any change to any field changes the canonical string.
function stable (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v)
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']'
  // Drop keys whose VALUE is undefined, exactly as JSON.stringify does. A record
  // is always JSON-serialized between signing and verification (sync backend,
  // relay wire, gossip replication), and JSON silently omits undefined-valued
  // keys — so if canonical() kept them (serializing undefined as null), the
  // signer would cover `"k":null` that the wire strips, and every verifier would
  // recompute a shorter canonical and reject the signature. This bit v2 edit and
  // delete: the reconstructed record carries ts/slug as undefined (comments have
  // neither), which sailed into the signed form but not onto the wire → "bad
  // signature". canonical() MUST be invariant across JSON round-trips.
  const ks = Object.keys(v).filter(k => !SIG_FIELDS.has(k) && v[k] !== undefined).sort()
  return '{' + ks.map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}'
}

export function canonical (type, data) {
  return type + '|' + stable(data)
}

// Type prefix of a Hyperbee key (`type!...`).
export function typeFromKey (key) { return String(key).split('!')[0] }

// The v2 record type — read from the signed body field `_t`, NOT from the (now
// opaque) key. The blind key scheme (docs/BLIND-OUTBOX-MIGRATION.md) lifts type out
// of the key; every former typeFromKey(key) site becomes typeOf(val) at cutover.
export function typeOf (val) { return val && val._t }

// The SEMANTIC type of an admitted row, dual-read: a v2 opaque row (key `v2!<okey>`)
// carries its type in the signed `_t` field (the key is opaque); a legacy v1 row
// derives it from the plaintext key. Every gossip typeFromKey(key) site that routes
// admit/winner/census/sticky becomes typeForRow(key, val) so both schemes coexist
// until the clean cutover. NOTE: v2 records SIGN over canonical('v2', data) (constant
// wire type, so the type never leaks in the key), so verification uses 'v2' while
// ownerOf/winner/PoW use this semantic type — see gossip.js admit().
export function typeForRow (key, val) {
  return String(key).startsWith('v2!') ? (val && val._t) : typeFromKey(key)
}

// The v2 opaque wire key a record MUST live under, recomputed from its own SIGNED
// fields — the anti-eviction gate for the blind key scheme. `v2!<okey>` where okey
// folds author + _t + semanticId, so: a peer can't park a record under a victim's
// slot (author ∈ HMAC), and the type can't leak in the key or be swapped (it's ∈ the
// HMAC AND `_t` ∈ canonical, so a flip breaks BOTH this recompute AND the signature).
// `community` is the one author-INDEPENDENT slot (rivals collide → sticky-claim fires).
// Async because okey is HMAC-SHA256 over SubtleCrypto. Uses ownerOf/semanticId so it
// stays symmetric with the plaintext expectedKey above.
export async function expectedKeyV2 (val) {
  const t = typeOf(val)
  if (!t) return null
  if (t === TYPE.COMMUNITY) return val.slug != null ? 'v2!' + await communityOkey(val.slug) : null
  const author = ownerOf(t, val)
  const sid = semanticId(t, val)
  if (author == null || sid == null) return null
  return 'v2!' + await okey(t, sid, author)
}

// ---- signed-outbox-head census ---------------------------------------------
// The set a signed `head` commits to: the sorted `key\0sig` of every SIGNED,
// NON-head record in one author's outbox. The head's `root` is a hash of this
// (joined by \x01). The producer (sync layer) and the auditor (reader) MUST
// compute it identically, so it lives here, next to canonical()/expectedKey().
// Excluding the head itself keeps appending a new head from changing the root it
// commits to. Pass `owner` (the outbox pubkey) so the auditor counts ONLY rows
// signed by that owner (value._k === owner): a foreign but validly-signed row a
// relay injects can't pad the count/root. The producer feeds its own me-scoped
// admitted view, so owner is a no-op there but keeps producer/auditor symmetric.
export function outboxCensus (rows, owner) {
  const c = []
  for (const r of (rows || [])) {
    const key = r && r.key
    const value = r && r.value
    if (!key || !value || !value._sig) continue
    if ((value._t || typeFromKey(key)) === TYPE.HEAD) continue // v2 head keys are opaque → check _t
    if (owner && value._k !== owner) continue
    c.push(key + '\x00' + value._sig)
  }
  c.sort()
  return c
}
export function censusString (census) { return (census || []).join('\x01') }

// Timestamp for last-writer-wins conflict resolution.
export function recordTs (data) {
  return (data && (data.editedAt || data.updatedAt || data.ts || data.createdAt)) || 0
}
