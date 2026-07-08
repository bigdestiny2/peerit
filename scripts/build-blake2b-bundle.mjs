#!/usr/bin/env node
// build-blake2b-bundle.mjs — esbuild js/blake2b-src.mjs (the vetted `blake2b` pkg, WASM
// inlined as base64) into a self-contained browser ESM module web/js/blake2b-bundle.js.
// This is the injected `hashShard` for BlindShard dispersal so browser shard IDs match
// HiveRelay's blake2b-256 shard address. Same pattern as scripts/build-dht-bundle.mjs.
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { build } from 'esbuild'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null }

export async function buildBlake2bBundle ({ outfile = '', minify = false } = {}) {
  const result = await build({
    entryPoints: [resolve(ROOT, 'js/blake2b-src.mjs')],
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    mainFields: ['browser', 'module', 'main'],
    conditions: ['browser', 'default'],
    define: { global: 'globalThis' },
    minify,
    legalComments: 'none',
    logLevel: 'silent'
  })
  const text = result.outputFiles[0].text
  if (outfile) {
    const file = resolve(ROOT, outfile)
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, text)
  }
  return Buffer.from(text)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const outfile = arg('--out') || 'web/js/blake2b-bundle.js'
  buildBlake2bBundle({ outfile, minify: process.argv.includes('--minify') })
    .then((b) => console.log(`[blake2b-bundle] wrote ${outfile} (${b.length} bytes)`))
    .catch((e) => { console.error('[blake2b-bundle] failed:', e && e.message); process.exit(1) })
}
