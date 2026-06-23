// canon.js — canonical serialization, owner binding, and key binding. Shared by
// the signer (data.js) and the verifier (verify.js) so a signature covers
// exactly the bytes that get checked, and a record is pinned to both its author
// and its storage key.

import { TYPE, keys } from './model.js'

// The pubkey that must have authored a record of this type. The verifier
// requires the SIGNER (_k) to equal this — so you can't sign-as-someone-else.
export function ownerOf (type, data) {
  switch (type) {
    case TYPE.COMMUNITY: return data.creator
    case TYPE.MOD: return data.by
    default: return data.author // post, comment, vote, profile
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
    case TYPE.PROFILE: return data.author != null ? keys.profile(data.author) : null
    case TYPE.MOD: return data.community != null && data.actionId != null ? keys.mod(data.community, data.actionId) : null
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
  const ks = Object.keys(v).filter(k => !SIG_FIELDS.has(k)).sort()
  return '{' + ks.map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}'
}

export function canonical (type, data) {
  return type + '|' + stable(data)
}

// Type prefix of a Hyperbee key (`type!...`).
export function typeFromKey (key) { return String(key).split('!')[0] }

// Timestamp for last-writer-wins conflict resolution.
export function recordTs (data) {
  return (data && (data.editedAt || data.updatedAt || data.ts || data.createdAt)) || 0
}
