import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync } from 'node:fs'
import { dirname, join, normalize } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import { PEERIT_BROWSER_RUNTIME_ASSET_PATHS } from '../js/substrate/browser-runtime-authority.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const served = new Set(SUBSTRATE_SITE_FILES)

for (const forbiddenFile of [
  'js/app.js',
  'js/data-dispersal.js',
  'js/legacy-action-allowlist.js',
  'js/legacy-v2-pow-allowlist.js',
  'js/pow.js',
  'js/sync.js',
  'js/gossip.js',
  'js/relay-pool.js',
  'js/lazy-pool.js',
  'js/dht-bundle.js',
  'js/shard-roster.js',
  'config/shard-roster.public.json',
  'config/seed-snapshot.json'
]) assert.equal(served.has(forbiddenFile), false, `${forbiddenFile} is outside the replacement artifact`)

for (const requiredProductFile of [
  'js/data.js',
  'js/identity-primitives.js',
  'js/identity-store.js',
  'js/pow-current.js',
  'js/substrate/local-identity.js',
  'js/substrate/peerit-journal-backend.js',
  'js/substrate/peerit-journal.js',
  'js/substrate/peerit-product-runtime.js',
  'js/substrate/peerit-product-ui.js',
  'js/substrate/peerit-substrate-sync.js'
]) assert.equal(served.has(requiredProductFile), true, `${requiredProductFile} is in the replacement product closure`)

for (const path of Object.values(PEERIT_BROWSER_RUNTIME_ASSET_PATHS)) {
  assert.equal(served.has(path.slice(1)), true, `${path} is in the authenticated runtime closure`)
}

const forbiddenRuntimeTokens = [
  '/api/sync',
  '/api/bridge/status',
  'createGossip',
  'createRelayPool',
  'createDhtTransport',
  'resolveShardCohort',
  'connectRelaysInBackground',
  'peerit-shard-roster',
  'hiverelay-outbox',
  'outbox.peerit.site'
]
const importPattern = /\b(?:import|export)\s+(?:[^'";]+?\s+from\s*)?['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g

for (const file of SUBSTRATE_SITE_FILES.filter(file => /\.(?:js|mjs)$/.test(file))) {
  const source = readFileSync(join(root, file), 'utf8')
  for (const token of forbiddenRuntimeTokens) {
    assert.equal(source.includes(token), false, `${file} contains no retired writer token ${token}`)
  }
  for (const match of source.matchAll(importPattern)) {
    const specifier = match[1] || match[2]
    if (!specifier || (!specifier.startsWith('./') && !specifier.startsWith('../'))) continue
    const target = normalize(join(dirname(file), specifier)).replaceAll('\\', '/')
    assert.equal(served.has(target), true, `${file} import ${specifier} remains inside replacement closure`)
  }
}

const output = mkdtempSync(join(tmpdir(), 'peerit-substrate-build-'))
const build = spawnSync(process.execPath, [
  'build-web.mjs', '--config', 'deploy/web-release.json', '--out', output
], {
  cwd: root,
  encoding: 'utf8'
})
assert.equal(build.status, 0, `${build.stdout}\n${build.stderr}`)

const manifest = JSON.parse(readFileSync(join(output, 'asset-manifest.json'), 'utf8'))
assert.equal(manifest.webRelease.transport, 'blind-substrate')
assert.deepEqual(new Set(Object.keys(manifest.files)), new Set([...SUBSTRATE_SITE_FILES, 'sw-register.js']))

const builtIndex = readFileSync(join(output, 'index.html'), 'utf8')
assert.match(builtIndex, /src="js\/substrate\/app-entry\.js"/)
assert.doesNotMatch(builtIndex, /src="js\/app\.js"|name="peerit-v2"/)
const csp = builtIndex.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i)?.[1] || ''
const scriptSrc = csp.split(';').map(value => value.trim()).find(value => value.startsWith('script-src')) || ''
assert.equal(scriptSrc, "script-src 'self'")
assert.doesNotMatch(scriptSrc, /data:|'unsafe-inline'|'unsafe-eval'/)

for (const file of Object.keys(manifest.files).filter(file => /\.(?:js|mjs)$/.test(file))) {
  const source = readFileSync(join(output, file), 'utf8')
  for (const token of forbiddenRuntimeTokens) {
    assert.equal(source.includes(token), false, `built ${file} contains no retired writer token ${token}`)
  }
}

assert.equal(existsSync(join(output, 'seed-snapshot.json')), false)
assert.equal(existsSync(join(output, 'js', 'app.js')), false)
assert.equal(existsSync(join(output, 'js', 'sync.js')), false)
assert.equal(existsSync(join(output, 'js', 'pear-api.js')), false)
assert.equal(existsSync(join(output, 'js', 'blind-dealer.mjs')), false)
assert.equal(existsSync(join(output, 'js', 'data-dispersal.js')), false)

const productEntry = readFileSync(join(output, 'js', 'substrate', 'app-entry.js'), 'utf8')
assert.match(productEntry, /createPeeritProductRuntimeV1/)
assert.match(productEntry, /mountPeeritProductUiV1/)
assert.doesNotMatch(productEntry, /Read-only —/)

const productRuntime = readFileSync(join(output, 'js', 'substrate', 'peerit-product-runtime.js'), 'utf8')
assert.match(productRuntime, /relays:\s*\[\]/)
assert.match(productRuntime, /v2:\s*true/)
assert.match(productRuntime, /dispersal:\s*false/)
assert.doesNotMatch(productRuntime, /relayHints:\s*\[[^\]]+\]/)

console.log('peerit-substrate-build-closure: replacement artifact has a closed import graph and no legacy writer/import/route surface')
