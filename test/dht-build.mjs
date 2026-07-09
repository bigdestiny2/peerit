// dht-build.mjs - smoke test for the Phase 3 browser DHT build path.
// No public DHT or WebSocket is contacted; this proves build-web --dht-relay
// produces a real esbuilt transport, wires the meta/CSP, and hashes it into the
// audited web manifest.

import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex')

function treeFingerprint (root) {
  if (!existsSync(root)) return null
  const files = {}
  const walk = (dir, prefix = '') => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name
      const path = join(dir, entry.name)
      if (entry.isDirectory()) walk(path, rel)
      else if (entry.isFile()) files[rel] = sha256(readFileSync(path))
      else throw new Error(`unexpected non-file in web fixture: ${rel}`)
    }
  }
  walk(root)
  return files
}

async function runBuildChecks () {
  console.log('\n— build-web DHT bundle smoke —')
  const relay = 'wss://dht-smoke.invalid/socket'
  const res = spawnSync(process.execPath, [
    'build-web.mjs',
    '--relay', 'same-origin',
    '--readonly', 'true',
    '--no-relay-roster',
    '--no-shard-roster',
    '--dht-relay', relay,
    '--drive-key', 'dht-smoke'
  ], { encoding: 'utf8' })

  if (res.status !== 0) {
    throw new Error(`build-web --dht-relay failed\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`)
  }
  ok(res.stdout.includes('dhtRelay=' + relay), 'build-web reports the configured DHT relay')

  const html = readFileSync('web/index.html', 'utf8')
  ok(html.includes(`<meta name="peerit-dht-relay" content="${relay}">`), 'index.html includes peerit-dht-relay meta')
  ok(!html.includes('name="peerit-shard-roster"'), 'disabled shard roster is absent instead of leaking stale source metadata')
  ok(/script-src[^;]*'wasm-unsafe-eval'/.test(html), 'DHT build CSP allows WASM crypto')
  ok(html.includes('connect-src') && html.includes('wss://dht-smoke.invalid'), 'DHT build CSP allows the exact relay WebSocket origin')

  const bundle = readFileSync('web/js/dht-bundle.js')
  const text = bundle.toString('utf8')
  ok(bundle.length > 500000, 'web/js/dht-bundle.js is a real bundled transport, not the stub')
  ok(text.includes('createDhtTransport'), 'bundle exports createDhtTransport')
  ok(text.includes('peerit/desc/v1'), 'bundle contains the peerit descriptor channel')
  ok(text.includes('random-access-web'), 'bundle contains the browser random-access storage backend')
  ok(!text.includes('transport bundle is not included'), 'bundle does not contain the fallback stub')

  const mod = await import(pathToFileURL(process.cwd() + '/web/js/dht-bundle.js').href + `?t=${Date.now()}`)
  ok(typeof mod.createDhtTransport === 'function', 'generated bundle is importable as an ES module')

  const manifest = JSON.parse(readFileSync('web/asset-manifest.json', 'utf8'))
  ok(manifest.files['js/dht-bundle.js'] === sha256(bundle), 'asset manifest hashes the generated DHT bundle')
}

async function main () {
  // build-web intentionally replaces web/. The release resume gate also runs the
  // full suite, so this smoke test must never destroy a frozen signed candidate.
  // Preserve and restore the complete directory even when an assertion fails.
  const backupRoot = mkdtempSync(join(tmpdir(), 'peerit-dht-build-'))
  const backupWeb = join(backupRoot, 'web')
  const hadWeb = existsSync('web')
  const originalWeb = treeFingerprint('web')
  if (hadWeb) cpSync('web', backupWeb, { recursive: true })
  try {
    await runBuildChecks()
  } finally {
    rmSync('web', { recursive: true, force: true })
    if (hadWeb) cpSync(backupWeb, 'web', { recursive: true })
    rmSync(backupRoot, { recursive: true, force: true })
  }
  ok(JSON.stringify(treeFingerprint('web')) === JSON.stringify(originalWeb), 'DHT smoke restores a pre-existing frozen web artifact byte-for-byte')
  console.log(`\n✅ all ${passed} dht-build checks passed\n`)
}

main().catch((e) => { console.error('\n❌ dht-build FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
