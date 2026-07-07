// test/bundle-closure.mjs — every local import in a served file must be in the
// bundle. Run: node test/bundle-closure.mjs
//
// WHY THIS EXISTS: the web app is served as separate ES modules (no bundler), so a
// static/dynamic `import './x.js'` whose target is missing from publish.mjs
// SITE_FILES 404s at load — a WHITE SCREEN for every visitor. This has shipped
// TWICE (identity-vault.js, then shard-roster.js). This test walks the static +
// dynamic import graph of every served .js file and of index.html's <script>/<link>
// and asserts each same-origin target is actually bundled. It is deliberately blunt:
// bare specifiers (npm) and remote URLs are ignored; only relative (`./`, `../`) and
// root-absolute (`/js/…`) references are checked.

import assert from 'node:assert'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SITE_FILES } from '../publish.mjs'

const __dir = join(dirname(fileURLToPath(import.meta.url)), '..')
let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

const bundled = new Set(SITE_FILES)

// Strip // line comments and /* */ block comments so a commented-out import is not
// treated as a real dependency. Not a full parser — good enough for import scanning.
function stripComments (src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1') // keep `://` in URLs intact
}

// Resolve a specifier found in `importer` (a SITE_FILES path) to a SITE_FILES-style
// path, or null if it's external (bare/remote) and should be skipped.
function resolveSpec (importer, spec) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(spec)) return null // http:, https:, data:, node:, …
  if (spec.startsWith('/')) return spec.replace(/^\/+/, '') // root-absolute -> repo-relative
  if (!spec.startsWith('.')) return null // bare specifier (npm) — not our bundle
  const parts = (dirname(importer) + '/' + spec).split('/')
  const out = []
  for (const p of parts) {
    if (p === '' || p === '.') continue
    if (p === '..') out.pop()
    else out.push(p)
  }
  return out.join('/')
}

// All import/require-ish specifiers in a JS source.
function jsSpecifiers (src) {
  const clean = stripComments(src)
  const specs = new Set()
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,          // import … from '…'  /  export … from '…'
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // dynamic import('…')
    /\bimport\s+['"]([^'"]+)['"]/g          // bare side-effect import '…'
  ]
  for (const re of patterns) { let m; while ((m = re.exec(clean))) specs.add(m[1]) }
  return [...specs]
}

// Local same-origin refs in index.html: <script src>, <link href>, module preloads.
function htmlLocalRefs (src) {
  const clean = src
  const refs = new Set()
  const re = /\b(?:src|href)\s*=\s*['"]([^'"]+)['"]/g
  let m
  while ((m = re.exec(clean))) {
    const v = m[1]
    if (/^[a-z][a-z0-9+.-]*:/i.test(v)) continue // remote
    if (v.startsWith('#') || v.startsWith('data:')) continue
    refs.add(v.replace(/^\/+/, '').replace(/[?#].*$/, ''))
  }
  return [...refs]
}

let checked = 0
const missing = []

for (const file of SITE_FILES) {
  if (!file.endsWith('.js')) continue
  const abs = join(__dir, file)
  if (!existsSync(abs)) continue // generated bundles (dht/reader) may be absent pre-build
  const src = readFileSync(abs, 'utf8')
  for (const spec of jsSpecifiers(src)) {
    const target = resolveSpec(file, spec)
    if (target === null) continue // external
    checked++
    if (!bundled.has(target)) missing.push(`${file}  ->  ${spec}  (resolved ${target})`)
  }
}

// index.html static asset references (sw-register.js is injected at build → exempt).
const INDEX_EXEMPT = new Set(['sw-register.js'])
const indexPath = join(__dir, 'index.html')
if (existsSync(indexPath)) {
  for (const ref of htmlLocalRefs(readFileSync(indexPath, 'utf8'))) {
    if (INDEX_EXEMPT.has(ref)) continue
    // only enforce refs that look like served assets (js/, css, svg) — ignore routes
    if (!/\.(js|css|svg|json|png|ico|webmanifest)$/.test(ref)) continue
    checked++
    if (!bundled.has(ref)) missing.push(`index.html  ->  ${ref}`)
  }
}

if (missing.length) {
  console.error('\n✗ bundle-closure: served files import targets NOT in publish.mjs SITE_FILES:')
  for (const m of missing) console.error('    ' + m)
  console.error('\n  A same-origin import missing from SITE_FILES 404s at load = white screen.')
  console.error('  Add the file(s) above to SITE_FILES in publish.mjs.\n')
  process.exit(1)
}

ok(checked > 0, `scanned import graph of served files (${checked} local references)`)
ok(bundled.has('js/lazy-pool.js'), 'js/lazy-pool.js is bundled (regression: app.js imports it)')
ok(bundled.has('js/shard-roster.js'), 'js/shard-roster.js is bundled (runtime.js dynamic-imports it)')

console.log(`\nbundle-closure: ${passed} checks passed, ${checked} local imports all bundled.`)
