#!/usr/bin/env node
// scripts/seed-dealer.mjs — peerit seeder-as-dealer CLI.
//
// Encrypts a post body and disperses the AES key across a HiveRelay v0.24.0
// shard-store roster using PVSS. The ciphertext is written to a file; the
// signed custody intent + share manifest are written as a JSON manifest.
//
// The ciphertext is NOT stored on the shard relays — the dealer stores the key
// shards there. The ciphertext must be published separately (outbox blob,
// seeded hyperdrive, etc.). This tool outputs both pieces.
//
// Usage:
//   node scripts/seed-dealer.mjs --config config/shard-roster.json --body "hello world"
//   node scripts/seed-dealer.mjs --config config/shard-roster.json --body-file post.md
//   node scripts/seed-dealer.mjs --config config/shard-roster.json --body-file - < post.md
//
// Outputs (by default to stdout as JSON):
//   {
//     "blindContentId": "<64hex>",
//     "ciphertextPath": "./seeded/<blindContentId>.ct",
//     "manifest": { ... },
//     "intentId": "<64hex>",
//     "relays": [ ... ]
//   }

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { disperseBody, ensurePublisher, normalizeRoster } from '../js/blind-dealer.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '..')

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error(`usage: node scripts/seed-dealer.mjs [options]

Options:
  --config <path>         Shard roster JSON (default: config/shard-roster.json)
  --body <text>           Body text to encrypt and disperse
  --body-file <path>      Read body from file (- for stdin)
  --out-dir <dir>         Directory for ciphertext file (default: ./seeded)
  --out-manifest <path>   Write manifest JSON to file (default: stdout)
  -h, --help              Show this help
`)
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    config: path.join(ROOT, 'config', 'shard-roster.json'),
    body: '',
    bodyFile: '',
    outDir: path.join(ROOT, 'seeded'),
    outManifest: ''
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--config') opts.config = argv[++i] || ''
    else if (a === '--body') opts.body = argv[++i] || ''
    else if (a === '--body-file') opts.bodyFile = argv[++i] || ''
    else if (a === '--out-dir') opts.outDir = argv[++i] || ''
    else if (a === '--out-manifest') opts.outManifest = argv[++i] || ''
    else if (a === '-h' || a === '--help') usage(0)
    else usage(2, 'unknown option: ' + a)
  }
  return opts
}

async function readBody (opts) {
  if (opts.bodyFile) {
    if (opts.bodyFile === '-') {
      let data = ''
      process.stdin.setEncoding('utf8')
      for await (const chunk of process.stdin) data += chunk
      return data
    }
    return fs.readFileSync(opts.bodyFile, 'utf8')
  }
  if (opts.body) return opts.body
  throw new Error('supply --body or --body-file')
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  const cfg = JSON.parse(fs.readFileSync(opts.config, 'utf8'))
  const body = await readBody(opts)

  // Validate roster early so we fail before doing any crypto.
  normalizeRoster(cfg)

  const publisher = await ensurePublisher(cfg.publisher)
  const { ciphertext, manifest, intent, placed } = await disperseBody(body, {
    threshold: roster.threshold,
    relays: roster.relays,
    publisher,
    retainMs: roster.retainMs,
    fetch: globalThis.fetch
  })

  // Write ciphertext to disk. The caller publishes this separately.
  fs.mkdirSync(opts.outDir, { recursive: true })
  const ctFile = path.join(opts.outDir, manifest.blindContentId + '.ct')
  fs.writeFileSync(ctFile, Buffer.from(ciphertext))

  const out = {
    kind: 'peerit-seed-dealer',
    version: 1,
    blindContentId: manifest.blindContentId,
    ciphertextPath: ctFile,
    manifest,
    intentId: intent.intentId,
    relays: roster.relays.map(r => ({ pubkey: r.pubkey, url: r.url })),
    placed
  }

  const json = JSON.stringify(out, null, 2)
  if (opts.outManifest) {
    fs.writeFileSync(opts.outManifest, json)
    console.log('manifest:', opts.outManifest)
    console.log('ciphertext:', ctFile)
  } else {
    console.log(json)
  }
}

main().catch((e) => { console.error('seed-dealer:', e.message); process.exit(1) })
