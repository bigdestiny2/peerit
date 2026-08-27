#!/usr/bin/env node

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { dirname, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HOST = '127.0.0.1'
const TIMEOUT_MILLIS = Number(process.env.PEERIT_SIGNED_WEB_SMOKE_TIMEOUT_MS) || 45_000

async function freePort () {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.once('error', reject)
    server.listen(0, HOST, () => {
      const address = server.address()
      server.close(error => error ? reject(error) : resolve(address.port))
    })
  })
}

async function waitForPreview (url) {
  const deadline = Date.now() + TIMEOUT_MILLIS
  let lastError = null
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { cache: 'no-store' })
      if (response.ok) return
      lastError = new Error(`HTTP ${response.status}`)
    } catch (error) {
      lastError = error
    }
    await sleep(100)
  }
  throw new Error(`release preview did not become ready: ${lastError && lastError.message}`)
}

async function stopPreview (child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  const exited = new Promise(resolve => child.once('exit', resolve))
  child.kill('SIGTERM')
  if (await Promise.race([exited.then(() => true), sleep(1500).then(() => false)])) return
  child.kill('SIGKILL')
  await exited
}

let preview = null
let browser = null

async function cleanup () {
  const activeBrowser = browser
  const activePreview = preview
  browser = null
  preview = null
  if (activeBrowser) await activeBrowser.close().catch(() => {})
  await stopPreview(activePreview).catch(() => {})
}

const stopForSignal = code => {
  void cleanup().finally(() => process.exit(code))
}
const onSigint = () => stopForSignal(130)
const onSigterm = () => stopForSignal(143)
process.once('SIGINT', onSigint)
process.once('SIGTERM', onSigterm)

try {
  const port = await freePort()
  const url = `http://${HOST}:${port}/index.html`
  let previewOutput = ''
  preview = spawn(process.execPath,
    ['scripts/serve-substrate-preview.mjs', 'web', String(port)], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe']
    })
  preview.stdout.on('data', chunk => { previewOutput += chunk })
  preview.stderr.on('data', chunk => { previewOutput += chunk })

  const previewStopped = new Promise((resolve, reject) => {
    preview.once('error', reject)
    preview.once('exit', (code, signal) => reject(new Error(
      `release preview stopped before readiness (code=${code}, signal=${signal})\n${previewOutput}`)))
  })
  await Promise.race([waitForPreview(url), previewStopped])

  browser = await chromium.launch({ headless: true })
  const context = await browser.newContext({ serviceWorkers: 'block' })
  const localOrigin = new URL(url).origin
  const localRequestPaths = new Set()
  const blockedOrigins = new Set()
  await context.route('**/*', async route => {
    const requestUrl = new URL(route.request().url())
    if (requestUrl.origin === localOrigin) {
      localRequestPaths.add(requestUrl.pathname)
      return route.continue()
    }
    blockedOrigins.add(requestUrl.origin)
    await route.abort('blockedbyclient')
  })

  const page = await context.newPage()
  const pageErrors = []
  page.on('pageerror', error => pageErrors.push(error.message))
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT_MILLIS })

  assert.equal(await page.title(), 'peerit — peer-to-peer Reddit')
  assert.equal(await page.locator('meta[name="peerit-release-sequence"]').getAttribute('content'), '29')
  assert.equal(localRequestPaths.has('/js/substrate/app-entry.js'), true,
    'signed release must load the replacement entry')
  assert.equal(localRequestPaths.has('/js/app.js'), false,
    'legacy root entry must not be present in the signed release')

  await page.locator('html[data-peerit-local-authoring="ready"]').waitFor({ timeout: TIMEOUT_MILLIS })
  await page.locator('.topbar .brand-name', { hasText: 'peerit' }).waitFor({ timeout: TIMEOUT_MILLIS })
  await page.locator('.mode-badge', { hasText: 'blind' }).waitFor({ timeout: TIMEOUT_MILLIS })
  await page.locator('html[data-peerit-release-coherent="true"]').waitFor({ timeout: TIMEOUT_MILLIS })

  const releaseBanner = page.locator('#release-manifest-warning[data-release-coherent="true"]')
  await releaseBanner.waitFor({ timeout: TIMEOUT_MILLIS })
  assert.match(await releaseBanner.innerText(), /Signed replacement release 29 is coherent\./)
  assert.equal(await page.locator('.boot').count(), 0, 'replacement UI must replace the boot shell')
  assert.deepEqual(pageErrors, [], `replacement entry raised page errors: ${pageErrors.join('; ')}`)

  console.log('[signed-release-browser-smoke] pass', JSON.stringify({
    entry: 'js/substrate/app-entry.js',
    releaseSequence: 29,
    rendered: true,
    coherent: true,
    blockedExternalOrigins: [...blockedOrigins].sort()
  }))
} finally {
  process.removeListener('SIGINT', onSigint)
  process.removeListener('SIGTERM', onSigterm)
  await cleanup()
}
