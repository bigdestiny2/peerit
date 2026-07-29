#!/usr/bin/env node
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, firefox, webkit } from 'playwright'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; " +
  "connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz " +
  "https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'"
const VALIDATOR_PATH = '/protocol/validator/peerit-validator-v1.bare.mjs'
const VERIFIED_MODULE = Buffer.from(
  "globalThis.__peeritSriStableExecutions=(globalThis.__peeritSriStableExecutions||0)+1;export const marker='verified';\n")
const MALICIOUS_STABLE_MODULE = Buffer.from(
  "globalThis.__peeritSriMaliciousExecuted=true;export const marker='substituted';\n")
const VERIFIED_SWAP_MODULE = Buffer.from("export const marker='authenticated-before-swap';\n")
const MALICIOUS_SWAP_MODULE = Buffer.from(
  "globalThis.__peeritSriSwapExecuted=true;export const marker='substituted';\n")
const counts = { stable: 0, swap: 0 }

const BOOTSTRAP = `
import { importAuthenticatedSameOriginModuleV1 } from '/js/substrate/browser-runtime-authority.mjs'

async function authenticatedBytes(path) {
  const response = await fetch(path, { cache: 'reload', credentials: 'omit', redirect: 'error' })
  if (!response.ok) throw new Error('authenticated fixture fetch failed')
  return new Uint8Array(await response.arrayBuffer())
}

async function run() {
  const validatorBytes = await authenticatedBytes('${VALIDATOR_PATH}')
  const validator = await importAuthenticatedSameOriginModuleV1({
    bytes: validatorBytes,
    canonicalPath: '${VALIDATOR_PATH}',
    timeoutMillis: 10000
  })
  const validatorVector = validator.computePeeritValidatorRuntimeVectorV1()
  const stableBytes = await authenticatedBytes('/sri-stable.mjs')
  const stable = await importAuthenticatedSameOriginModuleV1({
    bytes: stableBytes,
    canonicalPath: '/sri-stable.mjs',
    timeoutMillis: 10000
  })
  const swapBytes = await authenticatedBytes('/sri-swap.mjs')
  let swapError = null
  try {
    await importAuthenticatedSameOriginModuleV1({
      bytes: swapBytes,
      canonicalPath: '/sri-swap.mjs',
      timeoutMillis: 10000
    })
  } catch (error) {
    swapError = { code: error && error.code, message: error && error.message }
  }
  const countResponse = await fetch('/sri-counts.json', { cache: 'no-store' })
  globalThis.__peeritSriResult = {
    validatorSchemaCount: validator.PEERIT_VALIDATOR_PROFILE_BINDING_V1.schemaCount,
    validatorVectorHex: [...validatorVector]
      .map(byte => byte.toString(16).padStart(2, '0')).join(''),
    stableMarker: stable.marker,
    stableExecutions: globalThis.__peeritSriStableExecutions || 0,
    maliciousStableExecuted: globalThis.__peeritSriMaliciousExecuted === true,
    maliciousSwapExecuted: globalThis.__peeritSriSwapExecuted === true,
    swapError,
    counts: await countResponse.json()
  }
}

run().catch(error => {
  globalThis.__peeritSriResult = { fatal: { message: error && error.message, code: error && error.code } }
})
`

const HTML = '<!doctype html><meta charset="utf-8"><script type="module" src="/sri-bootstrap.mjs"></script>'

function mime (file) {
  if (file.endsWith('.mjs') || file.endsWith('.js')) return 'text/javascript'
  if (file.endsWith('.json')) return 'application/json'
  if (file.endsWith('.html')) return 'text/html'
  return 'application/octet-stream'
}

function send (response, status, type, body) {
  response.writeHead(status, {
    'Content-Type': `${type}; charset=utf-8`,
    'Content-Length': body.byteLength,
    'Cache-Control': 'no-store',
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff'
  })
  response.end(body)
}

const server = http.createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://127.0.0.1').pathname
    if (pathname === '/sri-test.html') return send(response, 200, 'text/html', Buffer.from(HTML))
    if (pathname === '/sri-bootstrap.mjs') return send(response, 200, 'text/javascript', Buffer.from(BOOTSTRAP))
    if (pathname === '/sri-stable.mjs') {
      counts.stable++
      return send(response, 200, 'text/javascript',
        counts.stable <= 2 ? VERIFIED_MODULE : MALICIOUS_STABLE_MODULE)
    }
    if (pathname === '/sri-swap.mjs') {
      counts.swap++
      return send(response, 200, 'text/javascript',
        counts.swap === 1 ? VERIFIED_SWAP_MODULE : MALICIOUS_SWAP_MODULE)
    }
    if (pathname === '/sri-counts.json') {
      return send(response, 200, 'application/json', Buffer.from(JSON.stringify(counts)))
    }
    let decoded
    try { decoded = decodeURIComponent(pathname) } catch { return send(response, 400, 'text/plain', Buffer.from('bad path')) }
    const file = path.resolve(root, `.${decoded}`)
    if (file !== root && !file.startsWith(`${root}${path.sep}`)) {
      return send(response, 403, 'text/plain', Buffer.from('forbidden'))
    }
    const body = await fs.readFile(file)
    send(response, 200, mime(file), body)
  } catch (error) {
    send(response, error && error.code === 'ENOENT' ? 404 : 500, 'text/plain', Buffer.from('not found'))
  }
})

await new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(0, '127.0.0.1', resolve)
})

const address = server.address()
const url = `http://127.0.0.1:${address.port}/sri-test.html`
const engines = { chromium, firefox, webkit }
const selected = process.argv.slice(2)
const names = selected.length === 0 ? Object.keys(engines) : selected
const results = []

try {
  for (const name of names) {
    if (!Object.hasOwn(engines, name)) throw new Error(`unknown browser engine ${name}`)
    counts.stable = 0
    counts.swap = 0
    const browser = await engines[name].launch({ headless: true })
    try {
      const page = await browser.newPage()
      await page.goto(url, { waitUntil: 'load' })
      await page.waitForFunction(() => globalThis.__peeritSriResult != null, null, { timeout: 30000 })
      const result = await page.evaluate(() => globalThis.__peeritSriResult)
      assert.equal(result.fatal, undefined, `${name} runtime failed: ${JSON.stringify(result.fatal)}`)
      assert.equal(result.validatorSchemaCount, 78, `${name} validator binding drifted`)
      assert.equal(result.validatorVectorHex,
        `0101${'11'.repeat(32)}${'22'.repeat(32)}${'33'.repeat(32)}`,
        `${name} validator did not execute under the exact production CSP`)
      assert.equal(result.stableMarker, 'verified', `${name} imported substituted stable bytes`)
      assert.equal(result.stableExecutions, 1, `${name} evaluated the authenticated module more than once`)
      assert.equal(result.maliciousStableExecuted, false, `${name} executed a later stable response`)
      assert.equal(result.maliciousSwapExecuted, false, `${name} executed bytes that failed SRI`)
      assert.equal(result.swapError && result.swapError.code,
        'BROWSER_RUNTIME_MODULE_INTEGRITY_FAILED', `${name} did not fail the swapped module at SRI`)
      assert.equal(result.counts.stable, 2, `${name} did not reuse the SRI-loaded module-map entry`)
      assert.equal(result.counts.swap, 2, `${name} did not exercise the hostile SRI response`)
      results.push({ browser: name, ...result })
    } finally {
      await browser.close()
    }
  }
} finally {
  await new Promise(resolve => server.close(resolve))
}

process.stdout.write(`${JSON.stringify({ schema: 'PeeritAuthenticatedModuleSriBrowserEvidenceV1', results })}\n`)
