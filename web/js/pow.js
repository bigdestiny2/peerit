// pow.js - proof-of-work spam gate (hashcash).
//
// Posts, comments, and community creation carry a small SHA-256 proof bound to
// the record's immutable identity. The proof is part of the signed record and is
// re-verified by every peer on ingest through gossip's validate hook.
//
// Versioning:
//   pow.v >= 2 (or explicit stamp) binds the target to the stable stored identity
//   (`data.id` / okey) + type + createdAt so a proof cannot be stapled onto a
//   different body under the same type/timestamp.
//   Legacy proofs (pow.v absent or 1) keep the pre-v2 target shapes so existing
//   wire records still admit (dual-accept).

import { LEGACY_CONTENT_SIGNATURES, LEGACY_SEALED_V2_POW_SIGNATURES } from './legacy-v2-pow-allowlist.js'
import { LEGACY_ACTION_SIGNATURES, LEGACY_TARGET_CIDS } from './legacy-action-allowlist.js'
import {
  CONTENT_PROTOCOL,
  TYPE,
  hasValidContentId,
  hasValidContentRef,
  hasValidModAction,
  validCommunitySlug,
  validUserTarget
} from './model.js'
import { unseal } from './seal.js'

export const MIN_BITS = {
  post: 16,
  comment: 14,
  community: 18,
  // BlindShard blobs (opaque bodies) carry a modest proof so a peer can't cheaply
  // flood the outbox/census with large content-addressed appends (review FIX 3).
  blob: 12
}

/** Current mint version — all new proofs stamp pow.v = POW_VERSION. */
export const POW_VERSION = 2

/**
 * Legacy (v1) target — content-shape fields. Kept for dual-accept of records
 * already on the wire. Do not use for new mints.
 */
export function powTargetV1 (type, data) {
  switch (type) {
    case 'post':
      return `post|${data.community}|${data.cid}|${data.author}|${data.createdAt}`
    case 'comment':
      return `comment|${data.community}|${data.postCid}|${data.cid}|${data.author}|${data.createdAt}`
    case 'community':
      return `community|${data.slug}|${data.creator}|${data.createdAt}`
    case 'blob':
      return `blob|${data.blobId}|${data.author}`
    default:
      return type + '|' + (data.author || data.creator || '')
  }
}

/**
 * Identity-bound (v2) target — folds the stable stored id (okey for v2 records,
 * semantic id for v1) with type and createdAt. Same author + same millisecond
 * with different bodies → different targets when ids differ.
 */
export function powTargetV2 (type, data) {
  const id = data && data.id != null ? String(data.id) : ''
  const createdAt = data && data.createdAt != null ? String(data.createdAt) : ''
  return `v2|${id}|${type}|${createdAt}`
}

/**
 * Resolve the target for a given proof version.
 * Never infer version from shape — dispatch only on explicit pow.v.
 */
export function powTargetForVersion (type, data, version) {
  const v = Number(version)
  if (Number.isFinite(v) && v >= 2) return powTargetV2(type, data)
  return powTargetV1(type, data)
}

/** @deprecated use powTargetForVersion; kept as alias for call sites that mint with default v2 */
export function powTarget (type, data) {
  return powTargetV2(type, data)
}

export function leadingZeroBits (u8) {
  let n = 0
  for (let i = 0; i < u8.length; i++) {
    const b = u8[i]
    if (b === 0) {
      n += 8
      continue
    }
    n += Math.clz32(b) - 24
    break
  }
  return n
}

async function sha256 (str) {
  const buf = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return new Uint8Array(buf)
}

function hex (u8) {
  let out = ''
  for (const b of u8) out += b.toString(16).padStart(2, '0')
  return out
}

/**
 * Mint a proof for `type`/`data`. New mints always stamp pow.v = POW_VERSION (2)
 * and bind to the identity-bound target. `data.id` must already be set for v2
 * records (data.js _toV2 sets id before mint).
 */
export async function mint (type, data, bits, opts = {}) {
  const version = opts.version != null ? Number(opts.version) : POW_VERSION
  const target = powTargetForVersion(type, data, version)
  const targetHash = hex(await sha256(target))
  let nonce = 0
  for (;;) {
    const h = await sha256(target + '|' + nonce)
    if (leadingZeroBits(h) >= bits) {
      const proof = { bits, nonce, targetHash, v: version }
      return proof
    }
    nonce++
    if ((nonce & 1023) === 0) {
      if (opts.onProgress) opts.onProgress(nonce)
      if (opts.signal && opts.signal.aborted) throw new Error('proof-of-work cancelled')
      await new Promise(resolve => setTimeout(resolve, 0))
    }
  }
}

/**
 * Verify a proof. Dual-accept:
 *   pow.v >= 2 → identity-bound target
 *   pow.v absent / 1 → legacy target
 * Never infer version from shape.
 */
export async function verify (type, data, minBits) {
  const pow = data && data.pow
  if (!pow || typeof pow.bits !== 'number' || typeof pow.nonce !== 'number') return false
  if (pow.bits < minBits) return false
  const version = pow.v != null ? Number(pow.v) : 1
  if (!Number.isFinite(version) || version < 1) return false
  const target = powTargetForVersion(type, data, version)
  if (pow.targetHash != null) {
    if (typeof pow.targetHash !== 'string' || pow.targetHash.length !== 64) return false
    if (pow.targetHash !== hex(await sha256(target))) return false
  }
  const h = await sha256(target + '|' + pow.nonce)
  return leadingZeroBits(h) >= pow.bits
}

function signatureOf (val) {
  return typeof val?._sig === 'string' ? val._sig.toLowerCase() : ''
}

function actionSignaturesFor (inventory, type) {
  if (inventory instanceof Set) return inventory
  return inventory && inventory[type] instanceof Set ? inventory[type] : new Set()
}

// v2 seals every graph/target field. Admission's key-binding gate also unseals,
// but makeValidator must be safe when called directly and must validate the
// logical fields rather than trusting their absence at the wire top level.
async function logicalValue (val) {
  if (!val || !val.sealed) return val
  let graph
  try { graph = await unseal(val.sealed) } catch { return null }
  if (!graph || typeof graph !== 'object' || Array.isArray(graph)) return null
  return {
    ...graph,
    author: val._k,
    creator: val._k,
    by: val._k,
    createdAt: val.createdAt != null ? val.createdAt : graph.createdAt,
    ts: val.ts != null ? val.ts : graph.ts,
    editedAt: val.editedAt != null ? val.editedAt : graph.editedAt,
    deleted: val.deleted != null ? val.deleted : graph.deleted,
    slug: val.slug != null ? val.slug : graph.slug
  }
}

async function validCommentTargets (logical, legacyTargetCids) {
  if (!logical || !validCommunitySlug(logical.community) || logical.postCid !== logical.targetRef?.cid) return false
  if (legacyTargetCids.has(logical.postCid)) return false
  if (!(await hasValidContentRef(logical.targetRef, TYPE.POST))) return false

  if (logical.parentCid === null) return logical.parentRef === null
  if (typeof logical.parentCid !== 'string') return false
  if (logical.parentCid !== logical.parentRef?.cid || legacyTargetCids.has(logical.parentCid)) return false
  return hasValidContentRef(logical.parentRef, TYPE.COMMENT)
}

async function validVoteTarget (logical, legacyTargetCids) {
  if (!logical || logical.protocol !== CONTENT_PROTOCOL) return false
  if (!validCommunitySlug(logical.community) || !validUserTarget(logical.author)) return false
  if (!Number.isFinite(logical.ts) || logical.ts < 0) return false
  if (logical.value !== -1 && logical.value !== 0 && logical.value !== 1) return false
  if (logical.targetType !== TYPE.POST && logical.targetType !== TYPE.COMMENT) return false
  if (logical.targetCid !== logical.targetRef?.cid || logical.targetType !== logical.targetRef?.type) return false
  if (legacyTargetCids.has(logical.targetCid)) return false
  return hasValidContentRef(logical.targetRef, logical.targetType)
}

export function makeValidator (minBits = MIN_BITS, opts = {}) {
  // The injectable Set is for isolated historical-fixture tests and migrations.
  // Production callers omit it and therefore use the frozen live inventory.
  const legacyContentSignatures = opts.legacyContentSignatures || LEGACY_CONTENT_SIGNATURES
  const legacyActionSignatures = opts.legacyActionSignatures || LEGACY_ACTION_SIGNATURES
  const legacyTargetCids = opts.legacyTargetCids || LEGACY_TARGET_CIDS
  // gossip admit() rewrites type to the semantic type (val._t) before calling
  // validate(), so we only need to dispatch on that semantic type.
  return async (type, val) => {
    const signature = signatureOf(val)
    const legacyAction = actionSignaturesFor(legacyActionSignatures, type).has(signature)
    const needsLogical = type === TYPE.POST || type === TYPE.COMMENT || type === TYPE.VOTE || type === TYPE.MOD
    const logical = needsLogical ? await logicalValue(val) : val
    if (needsLogical && !logical) return false

    if (type === TYPE.POST) {
      // No timestamp inference and no shape fallback: a non-grandfathered post
      // must explicitly be protocol 3 and reproduce its author-bound CID.
      if (!legacyContentSignatures.has(signature) && !(await hasValidContentId(type, logical))) return false
    }

    if (type === TYPE.COMMENT && !legacyAction) {
      // A comment is both content and an action on a thread. Its own identity and
      // every target identity must independently reproduce protocol-v3 CIDs.
      if (!(await hasValidContentId(type, logical))) return false
      if (!(await validCommentTargets(logical, legacyTargetCids))) return false
    }

    if (type === TYPE.VOTE && !legacyAction) {
      if (!(await validVoteTarget(logical, legacyTargetCids))) return false
    }

    if (type === TYPE.MOD && !legacyAction) {
      if (!(await hasValidModAction(logical))) return false
      if (logical.targetCid != null && legacyTargetCids.has(logical.targetCid)) return false
    }
    // A sealed record is the v2 wire form. Legacy v1 proofs are retained only for
    // legacy plaintext rows; accepting them on v2 would let one proof be replayed
    // across records whose v1 target fields are intentionally absent.
    const proofGated = type === 'post' || type === 'comment' || type === 'community' || type === 'blob'
    if (proofGated && val && val.sealed) {
      const version = val.pow && Number(val.pow.v)
      if (!Number.isFinite(version) || version < 2) {
        // Production carried sealed v2 rows before pow.v=2 existed. Admit only
        // the exact pre-cutover, release-pinned signatures; a new author cannot
        // exploit the reusable legacy target by backdating/signing another row.
        const signature = typeof val._sig === 'string' ? val._sig.toLowerCase() : ''
        if (!LEGACY_SEALED_V2_POW_SIGNATURES.has(signature)) return false
      }
    }
    if (type === 'post') return verify(type, val, minBits.post)
    if (type === 'comment') return verify(type, val, minBits.comment)
    if (type === 'community') return verify(type, val, minBits.community)
    if (type === 'blob') return verify(type, val, minBits.blob)
    return true
  }
}
