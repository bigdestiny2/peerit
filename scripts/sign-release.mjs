#!/usr/bin/env node
// sign-release.mjs — sign a built web/ bundle with peerit's OFFLINE Ed25519 release
// key, producing web/asset-manifest.sig. Run AFTER `npm run web:prepare`, with the release
// seed supplied out-of-band (never in the repo / CI env of the origin):
//
//   keyvault exec --only peerit/release/signing-seed -- npm run release:sign
//   PEERIT_RELEASE_SEED=<32-byte-hex> node scripts/sign-release.mjs
//   node scripts/sign-release.mjs --manifest web/asset-manifest.json \
//     --request deploy/web-signing-request.json --out web/asset-manifest.sig
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

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { releaseSequenceOf, releaseSigningMessage, RELEASE_ALG, RELEASE_MSG_VERSION } from '../js/release-verify.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dir, '..')
const PKCS8_PREFIX = '302e020100300506032b657004220420' // DER prefix for a raw Ed25519 seed
const HEX64 = /^[0-9a-f]{64}$/i

function arg (name, dflt) {
  const i = process.argv.indexOf(name)
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt
}

function fail (msg) { console.error('sign-release: ' + msg); process.exit(1) }

const seed = (process.env.PEERIT_RELEASE_SEED || process.env.PEERIT_RELEASE_SIGNING_SEED || '').trim().toLowerCase()
if (!HEX64.test(seed)) fail('set PEERIT_RELEASE_SEED (or keyvault-scoped PEERIT_RELEASE_SIGNING_SEED) to a 32-byte release seed. Store it OFFLINE — it is the root of the web release trust chain.')

const manifestPath = resolve(ROOT, arg('--manifest', 'web/asset-manifest.json'))
const requestPath = resolve(ROOT, arg('--request', 'deploy/web-signing-request.json'))
const outPath = resolve(ROOT, arg('--out', 'web/asset-manifest.sig'))
if (!existsSync(manifestPath)) fail(`no manifest at ${manifestPath} — run build-web.mjs first`)
if (!existsSync(requestPath)) fail(`no signing request at ${requestPath} — run npm run web:prepare first`)

const manifestBytes = readFileSync(manifestPath)
const manifest = JSON.parse(manifestBytes.toString('utf8'))
const releaseSequence = releaseSequenceOf(manifest)
const message = releaseSigningMessage(manifest)
const request = JSON.parse(readFileSync(requestPath, 'utf8'))
const manifestSha256 = createHash('sha256').update(manifestBytes).digest('hex')
const messageSha256 = createHash('sha256').update(message, 'utf8').digest('hex')
if (request.schema !== 'peerit-web-signing-request-v2') fail('signing request has an unsupported schema')
if (request.releaseSequence !== releaseSequence) fail('signing request release sequence does not match asset-manifest.json')
if (request.manifestSha256 !== manifestSha256) fail('signing request does not match asset-manifest.json bytes')
if (request.signingMessageSha256 !== messageSha256) fail('signing request does not match the release signing message')
if (request.driveKey !== manifest.driveKey) fail('signing request drive key does not match asset-manifest.json')
if (!request.artifactFiles || typeof request.artifactFiles !== 'object' || !Object.keys(request.artifactFiles).length) fail('signing request does not bind the prepared web artifact')

const priv = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seed, 'hex'), format: 'der', type: 'pkcs8' })
const pubHex = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
if (String(request.pinnedReleaseKey || '').toLowerCase() !== pubHex) fail(`the release seed derives ${pubHex} but the signing request pins ${request.pinnedReleaseKey || '(none)'}`)
const sigHex = nodeSign(null, Buffer.from(message, 'utf8'), priv).toString('hex')

// Cross-check against the pinned key in deploy/web-release.json, if present, so a
// wrong seed can't silently ship a bundle signed by an unpinned key.
try {
  const cfg = JSON.parse(readFileSync(join(ROOT, 'deploy', 'web-release.json'), 'utf8'))
  const pinned = String(cfg.pinnedReleaseKey || '').toLowerCase()
  if (pinned && pinned !== pubHex) fail(`the release seed derives ${pubHex} but deploy/web-release.json pins ${pinned}. Refusing to sign with an unpinned key.`)
  if (!pinned) console.warn(`sign-release: deploy/web-release.json has no pinnedReleaseKey — set it to ${pubHex} and rebuild so clients/verify.html pin this release key.`)
} catch { /* config optional */ }

writeFileSync(outPath, JSON.stringify({ alg: RELEASE_ALG, key: pubHex, sig: sigHex, msgVersion: RELEASE_MSG_VERSION }, null, 2) + '\n')
console.log(`sign-release: wrote ${outPath}`)
console.log(`  release key: ${pubHex}`)
console.log(`  sequence:    ${releaseSequence}`)
console.log(`  manifest:    ${manifestPath} (${Object.keys(manifest.files || {}).length} files)`)
