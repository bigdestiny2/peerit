#!/usr/bin/env node
// sign-release.mjs — sign a built web/ bundle with peerit's OFFLINE Ed25519 release
// key, producing web/asset-manifest.sig. Run AFTER build-web.mjs, with the release
// seed supplied out-of-band (never in the repo / CI env of the origin):
//
//   PEERIT_RELEASE_SEED=<32-byte-hex> node scripts/sign-release.mjs
//   node scripts/sign-release.mjs --manifest web/asset-manifest.json --out web/asset-manifest.sig
//
// The signature lets anyone — a mirror, an auditor, a monitoring bot, or verify.html
// loaded from a trusted copy — confirm a served bundle is an authentic peerit release
// WITHOUT trusting the serving origin. It does NOT, by itself, stop a fully compromised
// origin from also swapping the verifier; that ceiling is only removed by hyper://
// (PearBrowser). See js/release-verify.js and docs/WEB-DEPLOYMENT.md.
//
// The seed → pubkey derivation matches crypto.js exactly (PKCS8-wrapped raw seed →
// raw 32-byte Ed25519 public key), so js/release-verify.js verifyReleaseManifest()
// (which routes through crypto.js verify) accepts what this produces.

import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { releaseSigningMessage, RELEASE_ALG } from '../js/release-verify.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dir, '..')
const PKCS8_PREFIX = '302e020100300506032b657004220420' // DER prefix for a raw Ed25519 seed
const HEX64 = /^[0-9a-f]{64}$/i

function arg (name, dflt) {
  const i = process.argv.indexOf(name)
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt
}

function fail (msg) { console.error('sign-release: ' + msg); process.exit(1) }

const seed = (process.env.PEERIT_RELEASE_SEED || '').trim().toLowerCase()
if (!HEX64.test(seed)) fail('set PEERIT_RELEASE_SEED to a 32-byte (64 hex) release seed. Generate one with:\n  node -e "console.log(require(\'node:crypto\').randomBytes(32).toString(\'hex\'))"\nStore it OFFLINE — it is the root of the web release trust chain.')

const manifestPath = resolve(ROOT, arg('--manifest', 'web/asset-manifest.json'))
const outPath = resolve(ROOT, arg('--out', 'web/asset-manifest.sig'))
if (!existsSync(manifestPath)) fail(`no manifest at ${manifestPath} — run build-web.mjs first`)

const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
const message = releaseSigningMessage(manifest)

const priv = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seed, 'hex'), format: 'der', type: 'pkcs8' })
const pubHex = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
const sigHex = nodeSign(null, Buffer.from(message, 'utf8'), priv).toString('hex')

// Cross-check against the pinned key in deploy/web-release.json, if present, so a
// wrong seed can't silently ship a bundle signed by an unpinned key.
try {
  const cfg = JSON.parse(readFileSync(join(ROOT, 'deploy', 'web-release.json'), 'utf8'))
  const pinned = String(cfg.pinnedReleaseKey || '').toLowerCase()
  if (pinned && pinned !== pubHex) fail(`the release seed derives ${pubHex} but deploy/web-release.json pins ${pinned}. Refusing to sign with an unpinned key.`)
  if (!pinned) console.warn(`sign-release: deploy/web-release.json has no pinnedReleaseKey — set it to ${pubHex} and rebuild so clients/verify.html pin this release key.`)
} catch { /* config optional */ }

writeFileSync(outPath, JSON.stringify({ alg: RELEASE_ALG, key: pubHex, sig: sigHex, msgVersion: 'peerit-release-v1' }, null, 2) + '\n')
console.log(`sign-release: wrote ${outPath}`)
console.log(`  release key: ${pubHex}`)
console.log(`  manifest:    ${manifestPath} (${Object.keys(manifest.files || {}).length} files)`)
