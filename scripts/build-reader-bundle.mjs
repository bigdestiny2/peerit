#!/usr/bin/env node
// build-reader-bundle.mjs — esbuild js/reader-src.mjs into a self-contained
// browser ESM module web/js/reader-bundle.js. Aliases sodium-universal to a
// blake2b-only shim so the vendored PVSS recover path runs in a browser without
// the native sodium dependency.
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { build } from 'esbuild'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null }

export async function buildReaderBundle ({ outfile = '', minify = false } = {}) {
  const result = await build({
    entryPoints: [resolve(ROOT, 'js/reader-src.mjs')],
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    mainFields: ['browser', 'module', 'main'],
    conditions: ['browser', 'default'],
    define: { global: 'globalThis' },
    minify,
    legalComments: 'none',
    logLevel: 'silent',
    external: ['node:crypto'],
    alias: {
      'sodium-universal': resolve(ROOT, 'js/sodium-browser-shim.mjs')
    }
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
  const outfile = arg('--out') || 'web/js/reader-bundle.js'
  const minify = process.argv.includes('--minify')
  buildReaderBundle({ outfile, minify })
    .then((b) => console.log(`[reader-bundle] wrote ${outfile} (${b.length} bytes)`))
    .catch((e) => { console.error('[reader-bundle] failed:', e && e.message); process.exit(1) })
}
