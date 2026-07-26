#!/usr/bin/env node
// blind-public-test-signing-request.mjs — produce the offline signing request
// for the public-test canary artifact in the EXACT peerit-web-signing-request-v2
// format scripts/web-release.mjs would produce, without invoking the GA
// product gate (assertPeeritBlindProductReleaseReady), which remains honestly
// blocked for this bounded canary. The release-sequence progression assertion
// against the prior request is retained.
//
//   node scripts/blind-public-test-signing-request.mjs

import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  assertReleaseSequenceProgression,
  releaseSigningMessage
} from '../js/release-verify.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SIGNING_REQUEST = join(ROOT, 'deploy', 'web-signing-request.json')

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function listWebFiles (dir, prefix = '') {
  const out = []
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry)
    const rel = prefix ? `${prefix}/${entry}` : entry
    if (statSync(full).isDirectory()) out.push(...listWebFiles(full, rel))
    else out.push(rel)
  }
  return out
}

const release = JSON.parse(readFileSync(join(ROOT, 'deploy', 'web-release.json'), 'utf8'))
if (release.substrateProfile !== 'blind-v1') throw new Error('canary request requires the blind-v1 substrate release config')
const manifestPath = join(ROOT, 'web', 'asset-manifest.json')
if (!existsSync(manifestPath)) throw new Error('web/asset-manifest.json is missing — run npm run build-web first')
const manifestBytes = readFileSync(manifestPath)
const assetManifest = JSON.parse(manifestBytes.toString('utf8'))
if (assetManifest.releaseSequence !== release.releaseSequence) {
  throw new Error(`asset-manifest sequence ${assetManifest.releaseSequence} != config sequence ${release.releaseSequence}`)
}
if (!assetManifest.webRelease || assetManifest.webRelease.transport !== 'blind-substrate') {
  throw new Error('asset manifest is not a blind-substrate release')
}
const driveKey = String(assetManifest.driveKey || '').toLowerCase()
if (!/^[0-9a-f]{64}$/.test(driveKey)) throw new Error('asset manifest has no drive key')

const artifactFiles = {}
for (const file of listWebFiles(join(ROOT, 'web'))) {
  if (file === 'asset-manifest.sig') continue
  artifactFiles[file] = sha256(readFileSync(join(ROOT, 'web', ...file.split('/'))))
}
const request = {
  schema: 'peerit-web-signing-request-v2',
  manifest: 'web/asset-manifest.json',
  signature: 'web/asset-manifest.sig',
  releaseSequence: release.releaseSequence,
  driveKey,
  pinnedReleaseKey: String(release.pinnedReleaseKey || '').toLowerCase(),
  manifestSha256: sha256(manifestBytes),
  signingMessageSha256: sha256(Buffer.from(releaseSigningMessage(assetManifest), 'utf8')),
  artifactFiles
}
const priorRecord = existsSync(SIGNING_REQUEST)
  ? JSON.parse(readFileSync(SIGNING_REQUEST, 'utf8'))
  : null
assertReleaseSequenceProgression({
  releaseSequence: request.releaseSequence,
  manifestIdentity: request.signingMessageSha256,
  priorRecord
})
writeFileSync(SIGNING_REQUEST, `${JSON.stringify(request, null, 2)}\n`)
console.log(`[canary-signing-request] wrote deploy/web-signing-request.json sequence=${request.releaseSequence} manifest=${request.manifestSha256.slice(0, 16)}… files=${Object.keys(artifactFiles).length}`)
console.log('[canary-signing-request] NOTE: the GA product gate (assertPeeritBlindProductReleaseReady) remains blocked; this request is for the bounded public-test canary only.')
