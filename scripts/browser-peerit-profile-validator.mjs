#!/usr/bin/env node
import fs from 'node:fs/promises'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; " +
  "connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz " +
  "https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'"
const expected = `0101${'11'.repeat(32)}${'22'.repeat(32)}${'33'.repeat(32)}`
const html = '<!doctype html><meta charset="utf-8"><script type="module" src="/validator-bootstrap.mjs"></script>'
const bootstrap = `
import * as validator from '/protocol/validator/peerit-validator-v1.bare.mjs'
try {
  const bytes = validator.computePeeritValidatorRuntimeVectorV1()
  globalThis.__peeritValidatorResult = {
    schemaCount: validator.PEERIT_VALIDATOR_PROFILE_BINDING_V1.schemaCount,
    profileSpecHash: [...validator.PEERIT_VALIDATOR_PROFILE_BINDING_V1.profileSpecHash]
      .map(byte => byte.toString(16).padStart(2, '0')).join(''),
    runtimeVector: [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join(''),
    vectorSetHash: [...validator.computePeeritValidatorRuntimeVectorSetHashV1()]
      .map(byte => byte.toString(16).padStart(2, '0')).join('')
  }
} catch (error) {
  globalThis.__peeritValidatorResult = { fatal: { name: error && error.name, message: error && error.message } }
}
`

function contentType (file) {
  if (file.endsWith('.mjs') || file.endsWith('.js')) return 'text/javascript'
  if (file.endsWith('.html')) return 'text/html'
  return 'application/octet-stream'
}

function send (response, status, type, body) {
  response.writeHead(status, {
    'Content-Type': `${type}; charset=utf-8`,
    'Content-Length': body.byteLength,
    'Content-Security-Policy': CSP,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  })
  response.end(body)
}

const server = http.createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://127.0.0.1').pathname
    if (pathname === '/') return send(response, 200, 'text/html', Buffer.from(html))
    if (pathname === '/validator-bootstrap.mjs') {
      return send(response, 200, 'text/javascript', Buffer.from(bootstrap))
    }
    const file = path.resolve(root, `.${decodeURIComponent(pathname)}`)
    if (file !== root && !file.startsWith(`${root}${path.sep}`)) {
      return send(response, 403, 'text/plain', Buffer.from('forbidden'))
    }
    send(response, 200, contentType(file), await fs.readFile(file))
  } catch (error) {
    send(response, error && error.code === 'ENOENT' ? 404 : 500, 'text/plain', Buffer.from('not found'))
  }
})

await new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(0, '127.0.0.1', resolve)
})

const browser = await chromium.launch({ headless: true })
try {
  const page = await browser.newPage()
  await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'load' })
  await page.waitForFunction(() => globalThis.__peeritValidatorResult != null, null, { timeout: 30000 })
  const result = await page.evaluate(() => globalThis.__peeritValidatorResult)
  if (result.fatal || result.schemaCount !== 78 || result.runtimeVector !== expected ||
      result.vectorSetHash !== '84d0cfd27a3b078ea839b2ec35ae9df7dd4ab619faa39dd8bef805f0c2b1c77c' ||
      result.profileSpecHash !== '931a85e29eb3767d8d2a1920d7e127cf20d708cce6975d967522fd07f475f473') {
    throw new Error(`Chromium exact-CSP validator runtime drift: ${JSON.stringify(result)}`)
  }
  process.stdout.write(`${JSON.stringify({
    schema: 'PeeritValidatorExactProductionCspChromiumRuntimeV1',
    csp: CSP,
    ...result
  })}\n`)
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
