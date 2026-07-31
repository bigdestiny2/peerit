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
  hasValidReport,
  validCommunitySlug,
  validUserTarget
} from './model.js'
import { unseal } from './seal.js'

import { MIN_BITS, verify } from './pow-current.js'

export {
  MIN_BITS,
  POW_VERSION,
  leadingZeroBits,
  mint,
  powTarget,
  powTargetForVersion,
  powTargetV1,
  powTargetV2,
  verify
} from './pow-current.js'

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
    const needsLogical = type === TYPE.POST || type === TYPE.COMMENT || type === TYPE.VOTE || type === TYPE.MOD || type === TYPE.REPORT
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
    if (type === TYPE.REPORT) {
      if (!(await hasValidReport(logical))) return false
      if (legacyTargetCids.has(logical.targetCid)) return false
    }
    // A sealed record is the v2 wire form. Legacy v1 proofs are retained only for
    // legacy plaintext rows; accepting them on v2 would let one proof be replayed
    // across records whose v1 target fields are intentionally absent.
    const proofGated = type === 'post' || type === 'comment' || type === 'community' || type === 'blob' || type === 'report'
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
    if (type === 'report') return verify(type, val, minBits.report)
    return true
  }
}
