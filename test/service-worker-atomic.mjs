import assert from 'node:assert'
import { createHash, webcrypto } from 'node:crypto'
import vm from 'node:vm'
import {
  canonicalAssetManifest,
  serviceWorkerCacheName,
  serviceWorkerSource
} from '../scripts/service-worker-source.mjs'

const sha256 = (body) => createHash('sha256').update(body).digest('hex')

class FakeCache {
  constructor (entries = []) {
    this.entries = new Map(entries)
  }

  async put (path, response) {
    const body = Buffer.from(await response.arrayBuffer()).toString('utf8')
    this.entries.set(String(path), body)
  }

  async match (path) {
    const body = this.entries.get(String(path))
    return body == null ? null : new Response(body, { status: 200 })
  }
}

function installHarness ({ source, incumbentName, incumbentEntries, fetchAsset }) {
  const listeners = new Map()
  const cacheMap = new Map([[incumbentName, new FakeCache(incumbentEntries)]])
  const openCalls = []
  let skipWaitingCalls = 0
  const errors = []

  const context = {
    Response,
    URL,
    Uint8Array,
    crypto: webcrypto,
    location: { origin: 'https://peerit.test' },
    fetch: fetchAsset,
    caches: {
      async open (name) {
        openCalls.push(name)
        if (!cacheMap.has(name)) cacheMap.set(name, new FakeCache())
        return cacheMap.get(name)
      },
      async keys () { return [...cacheMap.keys()] },
      async delete (name) { return cacheMap.delete(name) }
    },
    console: {
      error: (...args) => errors.push(args),
      warn: () => {},
      log: () => {}
    },
    self: {
      addEventListener: (type, handler) => listeners.set(type, handler),
      skipWaiting: () => { skipWaitingCalls++ },
      clients: { claim: async () => {} }
    }
  }
  vm.runInNewContext(source, context, { filename: 'generated-sw.js' })

  return {
    cacheMap,
    context,
    errors,
    incumbent: cacheMap.get(incumbentName),
    openCalls,
    async install () {
      let pending = null
      listeners.get('install')({ waitUntil: (promise) => { pending = promise } })
      assert.ok(pending, 'install handler passes a promise to waitUntil')
      return pending
    },
    skipWaitingCalls: () => skipWaitingCalls
  }
}

async function main () {
  const oldBodies = {
    'index.html': 'same-shell',
    'js/feature.js': 'feature-v1'
  }
  const nextBodies = {
    'index.html': 'same-shell',
    'js/feature.js': 'feature-v2'
  }
  const oldManifest = Object.fromEntries(Object.entries(oldBodies).map(([path, body]) => [path, sha256(body)]))
  const nextManifest = Object.fromEntries(Object.entries(nextBodies).map(([path, body]) => [path, sha256(body)]))

  const oldCache = serviceWorkerCacheName(oldManifest)
  const nextCache = serviceWorkerCacheName(nextManifest)
  assert.notEqual(nextCache, oldCache, 'changing a non-entry asset changes the cache identity')
  assert.equal(
    serviceWorkerCacheName({ 'js/feature.js': nextManifest['js/feature.js'], 'index.html': nextManifest['index.html'] }),
    nextCache,
    'cache identity is independent of manifest insertion order'
  )
  assert.equal(
    canonicalAssetManifest(nextManifest),
    canonicalAssetManifest({ 'js/feature.js': nextManifest['js/feature.js'], 'index.html': nextManifest['index.html'] }),
    'canonical manifest covers the complete sorted asset map'
  )

  const source = serviceWorkerSource(nextManifest)
  assert.ok(source.includes(`const CACHE = ${JSON.stringify(nextCache)};`), 'generated worker embeds the full-manifest cache identity')
  assert.ok(source.includes('const INSTALL_CONCURRENCY = 6;'), 'generated worker bounds concurrent asset verification')
  assert.ok(source.includes("const RELEASE_METADATA = ['asset-manifest.json', 'asset-manifest.sig'];"), 'generated worker retains release metadata with its audited asset generation')

  const releaseMetadata = {
    'asset-manifest.json': JSON.stringify({ files: nextManifest }),
    'asset-manifest.sig': JSON.stringify({ alg: 'Ed25519', sig: 'test' })
  }

  const harness = installHarness({
    source,
    incumbentName: oldCache,
    incumbentEntries: Object.entries(oldBodies),
    fetchAsset: async (path) => new Response(path === 'index.html' ? nextBodies[path] : 'tampered-feature', { status: 200 })
  })
  const before = [...harness.incumbent.entries]
  await assert.rejects(harness.install(), /asset hash mismatch: js\/feature\.js/)
  assert.deepEqual([...harness.incumbent.entries], before, 'failed candidate leaves every incumbent cache entry byte-identical')
  assert.deepEqual(harness.openCalls, [], 'candidate verification finishes before any Cache API write')
  assert.equal(harness.cacheMap.has(nextCache), false, 'failed verification does not create a candidate cache')
  assert.equal(harness.skipWaitingCalls(), 0, 'failed candidate never requests activation')

  let inFlight = 0
  let peakInFlight = 0
  harness.context.fetch = async (path) => {
    inFlight++
    peakInFlight = Math.max(peakInFlight, inFlight)
    await new Promise(resolve => setTimeout(resolve, 1))
    inFlight--
    return new Response(nextBodies[String(path)] || releaseMetadata[String(path)], { status: 200 })
  }
  await harness.install()
  assert.deepEqual(harness.openCalls, [nextCache], 'successful candidate writes only its manifest-addressed cache')
  assert.deepEqual([...harness.incumbent.entries], before, 'successful candidate also leaves the incumbent untouched until activation')
  assert.deepEqual([...harness.cacheMap.get(nextCache).entries], [...Object.entries(nextBodies), ...Object.entries(releaseMetadata)], 'successful candidate caches every verified asset and matching release metadata')
  assert.equal(harness.skipWaitingCalls(), 1, 'complete verified candidate requests activation once')
  assert.ok(peakInFlight > 1 && peakInFlight <= 6, 'successful candidate stages assets concurrently within the fixed bound')

  console.log('service-worker-atomic: passed 16 checks')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
