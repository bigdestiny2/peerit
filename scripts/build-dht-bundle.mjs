#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { build } from 'esbuild'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function arg (name) {
  const i = process.argv.indexOf(name)
  return i >= 0 ? process.argv[i + 1] : null
}

export async function buildDhtBundle ({ outfile = '', minify = false } = {}) {
  const result = await build({
    entryPoints: [resolve(ROOT, 'js/dht-transport.js')],
    bundle: true,
    write: false,
    format: 'esm',
    platform: 'browser',
    mainFields: ['browser', 'module', 'main'],
    conditions: ['browser', 'default'],
    inject: [resolve(ROOT, 'node-shims.mjs')],
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
  const outfile = arg('--out') || 'web/js/dht-bundle.js'
  const minify = process.argv.includes('--minify')
  const buf = await buildDhtBundle({ outfile, minify })
  console.log(`[dht:bundle] wrote ${outfile} (${buf.length} bytes)`)
}
