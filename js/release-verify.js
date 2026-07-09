// release-verify.js — verify that a web bundle's asset-manifest.json was signed by
// peerit's OFFLINE release key. This authenticates the manifest's release fields and
// file hashes; proving that a live origin served those exact file bytes is a separate
// external verification step (or the explicit full fetch performed by verify.html).
//
// HONEST CEILING (must not be overclaimed): on the web, ANY self-verification the
// origin serves is circular — a fully compromised origin can also swap this verifier.
// The DURABLE win is EXTERNAL verification: a mirror, an auditor, a monitoring bot, or
// verify.html loaded from a trusted copy can check peerit.site's live bundle against the
// pinned release key WITHOUT trusting peerit.site, and a self-hosted/IPFS mirror can
// prove it serves authentic code. The only path that removes the origin from the trust
// ROOT entirely is `hyper://` in PearBrowser (the drive key IS the pin). See
// docs/WEB-DEPLOYMENT.md. Mirrors the roster-signing discipline in relay-roster.js.

import { verify as edVerify, hashHex } from './crypto.js'

export const RELEASE_ALG = 'Ed25519'
export const RELEASE_MSG_VERSION = 'peerit-release-v2'
export const RELEASE_FLOOR_SCHEMA = 'peerit-release-floor-v1'
const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i

// Deterministic, key-sorted JSON so signer and verifier hash identical bytes.
function stable (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v)
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']'
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}'
}

// The exact string the offline key signs / the client verifies. Covers the
// integrity-critical fields of asset-manifest.json: the per-file SHA-256 map (what
// code runs), generated control-file hashes, the published hyper:// driveKey, and
// the webRelease config (which relay + roster the bundle trusts). The cosmetic
// `note` is intentionally excluded.
export function releaseSigningMessage (manifest) {
  const m = manifest || {}
  return RELEASE_MSG_VERSION + '\n' + stable({
    releaseSequence: m.releaseSequence,
    files: m.files || {},
    controls: m.controls || {},
    driveKey: m.driveKey || '',
    webRelease: m.webRelease || {}
  })
}

// A signed web release carries one explicit, positive monotonic sequence at both
// the manifest root and inside the signed webRelease config. The duplicate is
// deliberate: operators can inspect it directly while clients reject a partial
// config/manifest mismatch rather than guessing which value is authoritative.
export function releaseSequenceOf (manifest) {
  const sequence = manifest && manifest.releaseSequence
  if (!Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error('release: releaseSequence must be a positive safe integer')
  }
  const nested = manifest && manifest.webRelease && manifest.webRelease.releaseSequence
  if (nested !== sequence) throw new Error('release: webRelease.releaseSequence does not match releaseSequence')
  return sequence
}

// SHA-256 of the exact v2 signing message. This is a compact identity for all
// signed release fields; it is NOT a claim that the browser has re-hashed module
// bytes which were already fetched/executed during first-page load.
export async function releaseManifestIdentity (manifest) {
  releaseSequenceOf(manifest)
  return hashHex(releaseSigningMessage(manifest))
}

// Advance a caller-supplied durable floor after signature verification. Lower
// sequences are replays. Reusing a sequence for different signed fields is a
// release fork and is rejected independently of arrival order.
export function advanceReleaseFloor ({ releaseSequence, manifestIdentity, floor } = {}) {
  if (!Number.isSafeInteger(releaseSequence) || releaseSequence < 1) {
    throw new Error('release: cannot advance floor with an invalid release sequence')
  }
  const identity = String(manifestIdentity || '').toLowerCase()
  if (!HEX64.test(identity)) throw new Error('release: cannot advance floor with an invalid manifest identity')

  const prior = floor && floor.schema === RELEASE_FLOOR_SCHEMA &&
    Number.isSafeInteger(floor.releaseSequence) && floor.releaseSequence > 0 &&
    HEX64.test(String(floor.manifestIdentity || ''))
    ? { releaseSequence: floor.releaseSequence, manifestIdentity: String(floor.manifestIdentity).toLowerCase() }
    : null

  if (prior && releaseSequence < prior.releaseSequence) {
    throw new Error(`release: rollback rejected (signed sequence ${releaseSequence} is below durable sequence ${prior.releaseSequence})`)
  }
  if (prior && releaseSequence === prior.releaseSequence && identity !== prior.manifestIdentity) {
    throw new Error(`release: fork rejected (signed sequence ${releaseSequence} has a different manifest identity)`)
  }
  return { schema: RELEASE_FLOOR_SCHEMA, releaseSequence, manifestIdentity: identity }
}

// Build-time sequence invariant. deploy/web-signing-request.json is committed
// with each accepted artifact and therefore acts as the tracked prior-release
// record on the next prepare. An identical artifact may be prepared idempotently;
// changed signed fields must use a strictly higher sequence.
export function assertReleaseSequenceProgression ({ releaseSequence, manifestIdentity, priorRecord } = {}) {
  if (!Number.isSafeInteger(releaseSequence) || releaseSequence < 1 || !HEX64.test(String(manifestIdentity || ''))) {
    throw new Error('release sequence progression requires a positive sequence and manifest identity')
  }
  const priorSequence = priorRecord && priorRecord.releaseSequence
  const priorIdentity = priorRecord && String(priorRecord.signingMessageSha256 || '').toLowerCase()
  // A pre-sequence v1 request is only a migration predecessor, not a reusable
  // sequence record. The first v2 request establishes the monotonic baseline.
  if (!Number.isSafeInteger(priorSequence) || priorSequence < 1 || !HEX64.test(priorIdentity)) return
  if (releaseSequence < priorSequence) {
    throw new Error(`releaseSequence ${releaseSequence} is below the tracked release sequence ${priorSequence}`)
  }
  if (releaseSequence === priorSequence && String(manifestIdentity).toLowerCase() !== priorIdentity) {
    throw new Error(`releaseSequence ${releaseSequence} was already used for a different signed artifact; increment deploy/web-release.json releaseSequence`)
  }
}

// Verify a { alg, key, sig } signature object over a manifest against a pinned key.
// Throws with a specific reason on any failure; returns { ok:true, key } on success.
export async function verifyReleaseManifest ({ manifest, signature, expectedKey, expectedSequence } = {}) {
  if (!manifest || typeof manifest !== 'object') throw new Error('release: no manifest')
  const releaseSequence = releaseSequenceOf(manifest)
  if (expectedSequence !== undefined && releaseSequence !== expectedSequence) {
    throw new Error(`release: signed sequence ${releaseSequence} does not match the page sequence ${expectedSequence}`)
  }
  const sig = signature || {}
  if (sig.alg !== RELEASE_ALG) throw new Error('release: unsupported signature algorithm')
  if (sig.msgVersion !== RELEASE_MSG_VERSION) throw new Error('release: unsupported signing message version')
  const key = String(sig.key || '').toLowerCase()
  if (!HEX64.test(key)) throw new Error('release: signing key is not a 32-byte hex Ed25519 key')
  if (expectedKey && key !== String(expectedKey).toLowerCase()) throw new Error('release: signed by an unexpected key (not the pinned release key)')
  if (!HEX128.test(String(sig.sig || ''))) throw new Error('release: signature is not 64-byte hex')
  const ok = await edVerify(key, releaseSigningMessage(manifest), sig.sig)
  if (!ok) throw new Error('release: signature did not verify against the manifest')
  return { ok: true, key, releaseSequence }
}

export async function verifyReleaseManifestWithFloor ({ manifest, signature, expectedKey, expectedSequence, floor } = {}) {
  const verified = await verifyReleaseManifest({ manifest, signature, expectedKey, expectedSequence })
  const manifestIdentity = await releaseManifestIdentity(manifest)
  const nextFloor = advanceReleaseFloor({ releaseSequence: verified.releaseSequence, manifestIdentity, floor })
  return { ...verified, manifestIdentity, floor: nextFloor }
}
