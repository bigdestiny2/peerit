#!/usr/bin/env node
// browser-peerit-pow-issuance-bench.mjs — prove the pow-issuance-v1 mint rate
// in a REAL Chromium context against the exact signed web/ closure under the
// exact production CSP: the vendored noble-hashes SHA-256 inner loop must land
// a 20-bit proof far inside the issuer's 120s challenge TTL.
//
//   node scripts/browser-peerit-pow-issuance-bench.mjs [--mints 12]
//
// Exit 0 only when p50 < 15s and p99 < 60s (the fleet liveness bounds) and the
// noble digest equals the WebCrypto digest on the exact 111-byte preimage.
// This is a BENCH/proof script; it performs zero network I/O.

import http from 'node:http'
import path from 'node:path'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const WEB = path.join(ROOT, 'web')
const CSP = JSON.parse(await readFile(path.join(ROOT, 'deploy', 'render-security-headers.json'), 'utf8'))
  .headers.find(row => row.name === 'Content-Security-Policy').value
const MINTS = (() => {
  const index = process.argv.indexOf('--mints')
  const value = index >= 0 ? Number(process.argv[index + 1]) : 12
  if (!Number.isSafeInteger(value) || value < 3 || value > 40) {
    console.error('--mints must be an integer in 3..40')
    process.exit(2)
  }
  return value
})()
const P50_LIMIT_MILLIS = 15_000
const P99_LIMIT_MILLIS = 60_000

const MIME = new Map([
  ['.html', 'text/html; charset=utf-8'], ['.js', 'text/javascript; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'], ['.json', 'application/json; charset=utf-8'],
  ['.cenc', 'application/octet-stream'], ['.svg', 'image/svg+xml'], ['.css', 'text/css; charset=utf-8'],
  ['.md', 'text/markdown; charset=utf-8']
])
const server = http.createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname)
    if (pathname === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': CSP })
      response.end('<!doctype html><html><head><meta charset="utf-8"><script type="module" src="/__bench__.mjs"></script></head><body></body></html>')
      return
    }
    if (pathname === '/__bench__.mjs') {
      response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'content-security-policy': CSP })
      response.end(`
        import { createPowIssuanceV1SpendProvider } from '/js/substrate/pow-issuance-spend-provider.mjs'
        import { sha256 } from '/js/vendor/noble-hashes/sha2.js'
        const provider = createPowIssuanceV1SpendProvider({ issuanceUrl: 'https://bench.invalid/' })
        window.__bench__ = { provider, sha256 }
        window.__benchReady__ = true
      `)
      return
    }
    const file = path.resolve(WEB, `.${pathname}`)
    if (file !== WEB && !file.startsWith(`${WEB}${path.sep}`)) {
      response.writeHead(403, { 'content-security-policy': CSP })
      response.end('forbidden')
      return
    }
    const bytes = await readFile(file)
    response.writeHead(200, {
      'content-type': MIME.get(path.extname(file)) || 'application/octet-stream',
      'content-security-policy': CSP
    })
    response.end(bytes)
  } catch {
    response.writeHead(404, { 'content-security-policy': CSP })
    response.end('not found')
  }
})
await new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(0, '127.0.0.1', resolve)
})

const browser = await chromium.launch({ headless: true })
try {
  const page = await (await browser.newContext()).newPage()
  const pageErrors = []
  page.on('pageerror', error => pageErrors.push(String(error.message || error)))
  await page.goto(`http://127.0.0.1:${server.address().port}/`)
  await page.waitForFunction(() => window.__benchReady__ === true, null, { timeout: 15_000 })
  const result = await page.evaluate(async (mintCount) => {
    const { provider, sha256 } = window.__bench__
    const difficultyBits = 20
    // Digest byte-equality on the exact 111-byte preimage: noble === WebCrypto.
    const challengePayload = crypto.getRandomValues(new Uint8Array(42))
    const recordCommitment = crypto.getRandomValues(new Uint8Array(32))
    const probe = new Uint8Array(111)
    probe.set(challengePayload, 0)
    probe.set(recordCommitment, 42)
    probe[110] = 0x5a
    const nobleDigest = sha256(probe)
    const webDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', probe))
    const digestEqual = nobleDigest.length === webDigest.length &&
      nobleDigest.every((byte, index) => byte === webDigest[index])
    const mints = []
    let totalCandidates = 0n
    for (let index = 0; index < mintCount; index++) {
      const mined = await provider.mintNonce({
        challengePayload: crypto.getRandomValues(new Uint8Array(42)),
        recordCommitment: crypto.getRandomValues(new Uint8Array(32)),
        difficultyBits
      })
      mints.push({ mintMillis: mined.mintMillis, attempts: mined.attempts.toString() })
      totalCandidates += mined.attempts
    }
    const sorted = mints.map(row => row.mintMillis).sort((left, right) => left - right)
    const percentile = (fraction) => sorted[Math.min(sorted.length - 1, Math.floor(fraction * sorted.length))]
    const totalMillis = mints.reduce((sum, row) => sum + row.mintMillis, 0)
    return {
      difficultyBits,
      digestEqual,
      mints,
      p50Millis: percentile(0.50),
      p99Millis: percentile(0.99),
      candidatesPerSecond: Math.round(Number(totalCandidates) / (totalMillis / 1000))
    }
  }, MINTS)
  if (pageErrors.length) throw new Error(`page errors: ${pageErrors.join(' | ')}`)
  const ok = result.digestEqual === true &&
    result.p50Millis < P50_LIMIT_MILLIS && result.p99Millis < P99_LIMIT_MILLIS
  console.log(JSON.stringify({ schema: 'peerit-pow-issuance-bench-v1', ok, ...result }, null, 2))
  console.log(`browser-peerit-pow-issuance-bench: ${ok ? 'PASS' : 'FAIL'} ` +
    `noble===WebCrypto ${result.digestEqual}, ${result.candidatesPerSecond} candidates/s, ` +
    `p50 ${result.p50Millis}ms (<${P50_LIMIT_MILLIS}), p99 ${result.p99Millis}ms (<${P99_LIMIT_MILLIS})`)
  process.exitCode = ok ? 0 : 1
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
