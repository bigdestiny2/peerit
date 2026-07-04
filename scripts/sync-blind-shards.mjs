#!/usr/bin/env node
// sync-blind-shards.mjs — vendor the PROVEN blind-custody client from P2P-Hiverelay
// into js/vendor/blind-shards/, pinned to an exact commit. No npm registry involved:
// files are read from the local hiverelay git checkout via `git show <sha>:<path>`,
// so the copy is byte-for-byte the audited upstream (21-agent adversarial sweep,
// PR #159) and re-syncing is a one-command, auditable operation.
//
//   node scripts/sync-blind-shards.mjs            # re-vendor at the PINNED sha
//   node scripts/sync-blind-shards.mjs --sha <x>  # bump the pin (updates this header set)
//
// peerit deliberately does NOT reimplement this crypto (PVSS-secp256k1 + Feldman
// commitments): a subtle divergence would be a silent security hole. One source of
// truth, vendored, pinned. Deps the vendored files need (beyond b4a/sodium-universal
// already in peerit): @noble/secp256k1 + @noble/hashes.
import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HIVERELAY = process.env.HIVERELAY_CHECKOUT || resolve(ROOT, '../../00-core/hiverelay')
const OUT = resolve(ROOT, 'js/vendor/blind-shards')

// The PIN: P2P-Hiverelay origin/main with #159 (blind-shard dispersal proven live
// across real RelayNodes) + #157 (app-facing disperse/recover orchestration) merged.
const PINNED_SHA = '4facbaeda8ef085413ad972910422ed40a173d69'

// The dealer closure — packages/client only (Bare-safe, no server/SDK imports):
//   blind-custody.js  app-facing disperse()/recover() orchestration (#157)
//   blind-shards.js   planDispersal/recoverSecret/shardAddressOf (fail-closed share checks)
//   secret-sharing.js PVSS-secp256k1-v1 core (@noble/secp256k1 + @noble/hashes)
//   shard-transport.js createHttpShardPut/Fetch — the /api/v1/shard wire
//   custody-signing.js CORE createCustodyIntent — the FULL v2 surface incl. shareManifest
//                     (the client copy custody.js is behind: it lacks shareManifest). Only
//                     b4a + sodium-universal, so it's Bare-safe too. This is what the
//                     reference node dealer imports.
const FILES = [
  'packages/client/blind-custody.js',
  'packages/client/blind-shards.js',
  'packages/client/secret-sharing.js',
  'packages/client/shard-transport.js',
  'packages/core/core/custody-signing.js',
  'packages/client/LICENSE'
]

const argSha = (() => { const i = process.argv.indexOf('--sha'); return i >= 0 ? process.argv[i + 1] : null })()
const sha = argSha || PINNED_SHA

function gitShow (path) {
  return execFileSync('git', ['-C', HIVERELAY, 'show', `${sha}:${path}`], { maxBuffer: 16 * 1024 * 1024 })
}

mkdirSync(OUT, { recursive: true })
const manifest = { source: 'https://github.com/bigdestiny2/P2P-Hiverelay', sha, syncedAt: new Date().toISOString(), files: {} }
for (const path of FILES) {
  const bytes = gitShow(path)
  const base = path.split('/').pop()
  const isJs = base.endsWith('.js')
  const banner = isJs
    ? `// VENDORED from P2P-Hiverelay@${sha.slice(0, 12)} ${path} — DO NOT EDIT.\n// Re-sync: node scripts/sync-blind-shards.mjs   (pin lives in that script)\n`
    : ''
  const out = banner ? Buffer.concat([Buffer.from(banner), bytes]) : bytes
  writeFileSync(resolve(OUT, base), out)
  manifest.files[base] = { path, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length }
  console.log(`  vendored ${base}  (${bytes.length} bytes, sha256 ${manifest.files[base].sha256.slice(0, 16)}…)`)
}
writeFileSync(resolve(OUT, 'VENDOR-MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n')
console.log(`[sync-blind-shards] ${FILES.length} files @ ${sha.slice(0, 12)} → js/vendor/blind-shards/ (+ VENDOR-MANIFEST.json)`)
