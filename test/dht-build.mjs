// dht-build.mjs - smoke test for the Phase 3 browser DHT build path.
// No public DHT or WebSocket is contacted; this proves build-web --dht-relay
// produces a real esbuilt transport, wires the meta/CSP, and hashes it into the
// audited web manifest.

import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex')

async function main () {
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

  console.log(`\n✅ all ${passed} dht-build checks passed\n`)
}

main().catch((e) => { console.error('\n❌ dht-build FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
