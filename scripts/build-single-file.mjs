#!/usr/bin/env node
// build-single-file.mjs — produce ONE self-contained index.html that boots peerit
// from a file:// URL (no server, no sibling files). This is the "PearBrowser in a
// file" delivery: send someone the .html, they open it, it dials a relay/dht-relay
// and pulls the network.
//
// WHY a separate target: file:// blocks ES-module `import` and `fetch()` of sibling
// files (CORS: `file` is not an allowed scheme). The normal web build serves js/*.js
// as ES modules over http — that can't work from disk. So here we esbuild the whole
// app into ONE classic-script IIFE and inline it (+ CSS) into a single HTML.
//
// Usage:
//   node scripts/build-single-file.mjs                 # -> dist/peerit-single.html
//   node scripts/build-single-file.mjs --out /tmp/p.html --relay https://peerit-relay.onrender.com
//
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const arg = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d }

const RELAY = arg('--relay', 'https://peerit-relay.onrender.com') // absolute: file:// has no same-origin
const READONLY = arg('--readonly', 'true')
const OUT = resolve(ROOT, arg('--out', 'dist/peerit-single.html'))
const b64sha256 = (s) => 'sha256-' + createHash('sha256').update(s).digest('base64')

// 1. bundle the whole app into ONE classic-script IIFE (no imports, no chunks).
const result = await build({
  entryPoints: [resolve(ROOT, 'js/app.js')],
  bundle: true,
  write: false,
  format: 'iife',
  platform: 'browser',
  mainFields: ['browser', 'module', 'main'],
  conditions: ['browser', 'default'],
  inject: [resolve(ROOT, 'node-shims.mjs')],
  define: { global: 'globalThis' },
  legalComments: 'none',
  logLevel: 'warning'
})
const js = result.outputFiles[0].text
const css = readFileSync(resolve(ROOT, 'styles.css'), 'utf8')
const icon = readFileSync(resolve(ROOT, 'icon.svg'), 'utf8')
const iconData = 'data:image/svg+xml,' + encodeURIComponent(icon)

// 2. assemble one HTML. CSP keeps a tight script-src via the inline bundle's hash
//    (no 'unsafe-inline'); connect-src allows the relay (https/wss).
const csp = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  `script-src '${b64sha256(js)}' 'wasm-unsafe-eval'`,
  "style-src 'unsafe-inline'",
  "img-src 'self' data: blob: http: https: hyper: pear:",
  "connect-src 'self' http: https: ws: wss: hyper: pear:",
  "form-action 'none'"
  // (no frame-ancestors: it is ignored in a <meta> CSP — only enforceable as an HTTP header,
  //  which a file:// document has none of.)
].join('; ')

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>peerit — peer-to-peer Reddit (single file)</title>
  <meta name="peerit-v2" content="true">
  <meta name="peerit-single" content="true">
  <meta name="peerit-relay" content="${RELAY}">
  <meta name="peerit-relay-readonly" content="${READONLY}">
  <link rel="icon" type="image/svg+xml" href="${iconData}">
  <style>${css}</style>
</head>
<body>
  <div class="boot">
    <div class="boot-mark">P</div>
    <div class="boot-name">peerit</div>
    <div class="boot-sub">connecting to peers…</div>
  </div>
  <script>${js}</script>
</body>
</html>
`

mkdirSync(dirname(OUT), { recursive: true })
writeFileSync(OUT, html)
console.log(`[single-file] wrote ${OUT}`)
console.log(`              html=${(html.length / 1024).toFixed(0)}kb (js=${(js.length / 1024).toFixed(0)}kb css=${(css.length / 1024).toFixed(0)}kb)`)
console.log(`              relay=${RELAY} readonly=${READONLY}`)
console.log('              open it: file://' + OUT)
