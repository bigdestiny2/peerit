import assert from 'node:assert/strict'
import {
  fetchAndVerifyPeeritWebAssetContentV1
} from '../js/substrate/browser-runtime-authority.mjs'
import {
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1
} from '../js/substrate/web-asset-manifest.mjs'
import { blake2b256 } from '../js/substrate/release-control-primitives.mjs'

const BASE = 'https://peerit.test/'
const MIME = Object.freeze({
  '/bootstrap.cenc': 'application/octet-stream',
  '/index.html': 'text/html',
  '/js/app.js': 'text/javascript',
  '/peerit-app-artifact-v1.json': 'application/json'
})

function bytes (value) {
  return value instanceof Uint8Array ? value : new TextEncoder().encode(value)
}

function fixture () {
  const assets = new Map([
    ['/bootstrap.cenc', bytes('signed discovery bootstrap')],
    ['/index.html', bytes('<!doctype html><title>peerit</title>')],
    ['/js/app.js', bytes('export const peerit = true\n')],
    ['/peerit-app-artifact-v1.json', bytes('{"schema":"peerit-app-artifact-v1"}\n')]
  ])
  const manifestBytes = encodePeeritWebAssetManifestV1({
    version: 1,
    releaseSequence: 17n,
    appArtifactHash: hashPeeritAppArtifactV1(assets.get('/peerit-app-artifact-v1.json')),
    recommendedBootstrapHashes: [hashPeeritBootstrapV1(assets.get('/bootstrap.cenc'))],
    assets: [...assets].map(([path, value]) => ({
      path,
      byteLength: BigInt(value.byteLength),
      assetHash: blake2b256(value)
    })).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
  })
  return { assets, manifestBytes }
}

function response (url, path, value, options = {}) {
  const payload = options.payload || value
  const chunks = options.chunks || [payload.subarray(0, Math.floor(payload.byteLength / 2)), payload.subarray(Math.floor(payload.byteLength / 2))]
  const reader = {
    index: 0,
    async read () {
      if (this.index >= chunks.length) return { done: true }
      return { done: false, value: chunks[this.index++] }
    },
    async cancel () {},
    releaseLock () {}
  }
  const headers = new Map([
    ['content-length', String(options.contentLength == null ? payload.byteLength : options.contentLength)],
    ['content-type', options.contentType || MIME[path] || 'application/octet-stream']
  ])
  return {
    ok: options.ok !== false,
    url: options.url || url,
    headers: { get: name => headers.get(String(name).toLowerCase()) || null },
    body: { getReader: () => reader }
  }
}

function fetchFixture (source, options = {}) {
  let active = 0
  let peak = 0
  const calls = []
  return {
    calls,
    get peak () { return peak },
    async fetch (url, request) {
      const path = new URL(url).pathname
      calls.push({ url, path, request })
      active++
      peak = Math.max(peak, active)
      try {
        if (options.delay) await new Promise(resolve => setTimeout(resolve, options.delay))
        const value = source.get(path)
        if (!value) return response(url, path, new Uint8Array(), { ok: false })
        const override = options.override && options.override(path, value, url)
        return response(url, path, value, override || {})
      } finally {
        active--
      }
    }
  }
}

function manifestWith (assets, overrides = {}) {
  return encodePeeritWebAssetManifestV1({
    version: 1,
    releaseSequence: 17n,
    appArtifactHash: overrides.appArtifactHash ||
      hashPeeritAppArtifactV1(assets.get('/peerit-app-artifact-v1.json') || new Uint8Array()),
    recommendedBootstrapHashes: overrides.recommendedBootstrapHashes || [],
    assets: [...assets].map(([path, value]) => ({
      path,
      byteLength: BigInt(value.byteLength),
      assetHash: blake2b256(value)
    })).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
  })
}

let passed = 0
async function test (name, operation) {
  await operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

await test('complete signed closure fetches every asset with bounded parallel exact-byte validation', async () => {
  const value = fixture()
  const transport = fetchFixture(value.assets, { delay: 5 })
  const result = await fetchAndVerifyPeeritWebAssetContentV1({
    fetch: transport.fetch,
    manifest: value.manifestBytes,
    baseUrl: BASE,
    maximumConcurrency: 2,
    maximumAssetBytes: 1024,
    maximumTotalBytes: 4096
  })
  assert.equal(result.complete, true)
  assert.equal(result.appArtifactVerified, true)
  assert.equal(result.verifiedAssetCount, value.assets.size)
  assert.equal(result.verifiedTotalBytes,
    [...value.assets.values()].reduce((total, entry) => total + entry.byteLength, 0))
  assert.deepEqual(result.bootstrapAssets.map(entry => entry.paths), [['/bootstrap.cenc']])
  assert.deepEqual([...result.assets.keys()].sort(), [...value.assets.keys()].sort())
  assert.equal(transport.calls.length, value.assets.size)
  assert.equal(transport.peak, 2)
  for (const call of transport.calls) {
    assert.equal(call.url, new URL(call.path, BASE).href)
    assert.equal(call.request.cache, 'reload')
    assert.equal(call.request.credentials, 'omit')
    assert.equal(call.request.redirect, 'error')
    assert.ok(call.request.signal instanceof AbortSignal)
  }
})

await test('raw asset substitution is rejected after exact bounded fetch', async () => {
  const value = fixture()
  const transport = fetchFixture(value.assets, {
    override: path => path === '/index.html'
      ? { payload: bytes('<!doctype html><title>attack</title>') }
      : null
  })
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: transport.fetch,
    manifest: value.manifestBytes,
    baseUrl: BASE,
    maximumAssetBytes: 1024,
    maximumTotalBytes: 4096
  }), error => error.code === 'WEB_ASSET_DRIFT')
})

await test('complete closure separately authenticates the domain-hashed app artifact', async () => {
  const value = fixture()
  const wrongManifest = manifestWith(value.assets, { appArtifactHash: new Uint8Array(32).fill(0x7f) })
  const transport = fetchFixture(value.assets)
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: transport.fetch,
    manifest: wrongManifest,
    baseUrl: BASE,
    maximumAssetBytes: 1024,
    maximumTotalBytes: 4096
  }), error => error.code === 'WEB_APP_ARTIFACT_DRIFT')
})

await test('recommended bootstrap hashes require matching exact same-origin asset bytes', async () => {
  const value = fixture()
  const missingBootstrap = manifestWith(value.assets, {
    recommendedBootstrapHashes: [hashPeeritBootstrapV1(bytes('unlisted bootstrap'))]
  })
  const transport = fetchFixture(value.assets)
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: transport.fetch,
    manifest: missingBootstrap,
    baseUrl: BASE,
    maximumAssetBytes: 1024,
    maximumTotalBytes: 4096
  }), error => error.code === 'WEB_BOOTSTRAP_CONTENT_MISSING')
})

await test('missing canonical app artifact fails before network access', async () => {
  const value = fixture()
  value.assets.delete('/peerit-app-artifact-v1.json')
  const manifestBytes = manifestWith(value.assets)
  const transport = fetchFixture(value.assets)
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: transport.fetch,
    manifest: manifestBytes,
    baseUrl: BASE
  }), error => error.code === 'WEB_APP_ARTIFACT_MISSING')
  assert.equal(transport.calls.length, 0)
})

await test('aggregate and per-asset budgets fail closed before network access', async () => {
  const value = fixture()
  const transport = fetchFixture(value.assets)
  const total = [...value.assets.values()].reduce((sum, entry) => sum + entry.byteLength, 0)
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: transport.fetch,
    manifest: value.manifestBytes,
    baseUrl: BASE,
    maximumAssetBytes: 1024,
    maximumTotalBytes: total - 1
  }), error => error.code === 'WEB_ASSET_FETCH_BUDGET_EXCEEDED')
  assert.equal(transport.calls.length, 0)

  const perAssetTransport = fetchFixture(value.assets)
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: perAssetTransport.fetch,
    manifest: value.manifestBytes,
    baseUrl: BASE,
    maximumAssetBytes: 8,
    maximumTotalBytes: 4096
  }), error => error.code === 'WEB_ASSET_FETCH_BUDGET_EXCEEDED')
  assert.equal(perAssetTransport.calls.length, 0)
})

await test('unsafe paths, origins, redirects, and MIME fallback responses fail closed', async () => {
  const value = fixture()
  const unsafeAssets = new Map(value.assets)
  unsafeAssets.set('/a/../escape.js', bytes('escape'))
  const unsafeManifest = manifestWith(unsafeAssets)
  const unused = fetchFixture(unsafeAssets)
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: unused.fetch,
    manifest: unsafeManifest,
    baseUrl: BASE
  }), error => error.code === 'BAD_WEB_ASSET_PATH')
  assert.equal(unused.calls.length, 0)

  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: unused.fetch,
    manifest: value.manifestBytes,
    baseUrl: 'file:///tmp/peerit/'
  }), error => error.code === 'WEB_ASSET_FETCH_ORIGIN_INVALID')

  const redirected = fetchFixture(value.assets, {
    override: path => path === '/js/app.js' ? { url: 'https://peerit.test/alias.js' } : null
  })
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: redirected.fetch,
    manifest: value.manifestBytes,
    baseUrl: BASE,
    maximumAssetBytes: 1024,
    maximumTotalBytes: 4096
  }), error => error.code === 'BROWSER_RUNTIME_ASSET_FETCH_FAILED')

  const fallback = fetchFixture(value.assets, {
    override: path => path === '/js/app.js' ? { contentType: 'text/html' } : null
  })
  await assert.rejects(fetchAndVerifyPeeritWebAssetContentV1({
    fetch: fallback.fetch,
    manifest: value.manifestBytes,
    baseUrl: BASE,
    maximumAssetBytes: 1024,
    maximumTotalBytes: 4096
  }), error => error.code === 'BROWSER_RUNTIME_ASSET_CONTENT_TYPE_INVALID')
})

process.stdout.write(`peerit web asset content fetch tests: ${passed}/${passed} passed\n`)
