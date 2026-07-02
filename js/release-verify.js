// release-verify.js — verify that a web bundle's asset-manifest.json was signed by
// peerit's OFFLINE release key. This is the "adapt dmc's trust chain" piece: it turns
// the web tier from "trust whatever JS the origin served this visit" into "this bundle
// is an authentic release signed by a key the origin does not hold."
//
// HONEST CEILING (must not be overclaimed): on the web, ANY self-verification the
// origin serves is circular — a fully compromised origin can also swap this verifier.
// The DURABLE win is EXTERNAL verification: a mirror, an auditor, a monitoring bot, or
// verify.html loaded from a trusted copy can check peerit.site's live bundle against the
// pinned release key WITHOUT trusting peerit.site, and a self-hosted/IPFS mirror can
// prove it serves authentic code. The only path that removes the origin from the trust
// ROOT entirely is `hyper://` in PearBrowser (the drive key IS the pin). See
// docs/WEB-DEPLOYMENT.md. Mirrors the roster-signing discipline in relay-roster.js.

import { verify as edVerify } from './crypto.js'

export const RELEASE_ALG = 'Ed25519'
export const RELEASE_MSG_VERSION = 'peerit-release-v1'
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
// code runs), the published hyper:// driveKey, and the webRelease config (which relay
// + roster the bundle trusts). The cosmetic `note` is intentionally excluded.
export function releaseSigningMessage (manifest) {
  const m = manifest || {}
  return RELEASE_MSG_VERSION + '\n' + stable({
    files: m.files || {},
    driveKey: m.driveKey || '',
    webRelease: m.webRelease || {}
  })
}

// Verify a { alg, key, sig } signature object over a manifest against a pinned key.
// Throws with a specific reason on any failure; returns { ok:true, key } on success.
export async function verifyReleaseManifest ({ manifest, signature, expectedKey } = {}) {
  if (!manifest || typeof manifest !== 'object') throw new Error('release: no manifest')
  const sig = signature || {}
  if (sig.alg !== RELEASE_ALG) throw new Error('release: unsupported signature algorithm')
  const key = String(sig.key || '').toLowerCase()
  if (!HEX64.test(key)) throw new Error('release: signing key is not a 32-byte hex Ed25519 key')
  if (expectedKey && key !== String(expectedKey).toLowerCase()) throw new Error('release: signed by an unexpected key (not the pinned release key)')
  if (!HEX128.test(String(sig.sig || ''))) throw new Error('release: signature is not 64-byte hex')
  const ok = await edVerify(key, releaseSigningMessage(manifest), sig.sig)
  if (!ok) throw new Error('release: signature did not verify against the manifest')
  return { ok: true, key }
}
