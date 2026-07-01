#!/usr/bin/env node
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_TIMEOUT_MS = Number(process.env.BROWSER_SMOKE_TIMEOUT_MS) || 45000
const HOST = process.env.HOST || DEFAULT_HOST
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error('usage: node scripts/browser-smoke.mjs [--url <http-url>] [--headed] [--keep-open]')
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    url: process.env.PEERIT_BROWSER_SMOKE_URL || '',
    headed: process.env.HEADED === '1',
    keepOpen: false
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--url') opts.url = argv[++i] || ''
    else if (arg === '--headed') opts.headed = true
    else if (arg === '--keep-open') opts.keepOpen = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  return opts
}

function routeUrl (base, hash) {
  const url = new URL(base)
  url.hash = hash
  return url.href
}

async function loadPlaywright () {
  try {
    return await import('playwright')
  } catch (err) {
    console.error([
      '[browser-smoke] Playwright is required for this optional browser gate.',
      'Install it only for operator/dev validation, not as an app runtime dependency:',
      '  npm install --no-save playwright',
      '  npx playwright install chromium',
      '',
      `Original import error: ${err.message}`
    ].join('\n'))
    process.exit(2)
  }
}

async function freePort () {
  return await new Promise((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.on('error', reject)
    server.listen(0, HOST, () => {
      const port = server.address().port
      server.close(() => resolve(port))
    })
  })
}

async function waitForHttp (url, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  let lastErr = null
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { cache: 'no-store' })
      if (res.ok) return
      lastErr = new Error(`HTTP ${res.status}`)
    } catch (err) {
      lastErr = err
    }
    await sleep(150)
  }
  throw new Error(`dev server did not become ready at ${url}: ${lastErr && lastErr.message}`)
}

async function startDevServer () {
  const port = Number(process.env.PORT) || await freePort()
  const child = spawn(process.execPath, ['dev-server.mjs'], {
    cwd: ROOT,
    env: { ...process.env, HOST, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let output = ''
  child.stdout.on('data', d => { output += d })
  child.stderr.on('data', d => { output += d })
  child.on('exit', (code, signal) => {
    if (code === 0 || signal) return
    console.error(`[browser-smoke] dev server exited with ${code}; output:\n${output}`)
  })
  const url = `http://${HOST}:${port}/`
  await waitForHttp(url, DEFAULT_TIMEOUT_MS)
  return { child, url }
}

async function stopDevServer (child) {
  if (!child || child.killed) return
  child.kill('SIGTERM')
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    sleep(1500).then(() => child.kill('SIGKILL'))
  ])
}

async function expectText (page, text, timeout = DEFAULT_TIMEOUT_MS) {
  await page.getByText(text, { exact: false }).first().waitFor({ timeout })
}

async function fillFirst (page, selector, value) {
  await page.locator(selector).first().fill(value)
}

async function submitFirst (page, selector) {
  await page.locator(selector).first().click()
}

function isExpectedConsoleError (text) {
  return text.includes("Content Security Policy directive 'frame-ancestors' is ignored when delivered via a <meta> element.")
}

function recordBrowserErrors (page, errors) {
  page.on('pageerror', err => errors.push(`pageerror: ${err.message}`))
  page.on('console', msg => {
    if (msg.type() !== 'error') return
    const text = msg.text()
    if (isExpectedConsoleError(text)) return
    errors.push(`console: ${text}`)
  })
}

async function runSmoke ({ browser, url }) {
  const stamp = Date.now().toString(36)
  const community = `codex${stamp.slice(-6)}`
  const title = `Browser smoke post ${stamp}`
  const firstComment = `first browser comment ${stamp}`
  const secondComment = `second user comment ${stamp}`
  const userName = `smoke-${stamp}`

  const context = await browser.newContext()
  const pageA = await context.newPage()
  const errors = []
  recordBrowserErrors(pageA, errors)

  await pageA.goto(routeUrl(url, '#/create'), { waitUntil: 'domcontentloaded' })
  await pageA.locator('#app').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS })

  await fillFirst(pageA, 'form[data-form="create-community"] input[name="slug"]', community)
  await fillFirst(pageA, 'form[data-form="create-community"] input[name="title"]', `Smoke ${stamp}`)
  await fillFirst(pageA, 'form[data-form="create-community"] textarea[name="description"]', 'Automated browser smoke community')
  await submitFirst(pageA, 'form[data-form="create-community"] button[type="submit"]')
  await expectText(pageA, `r/${community}`)

  await pageA.goto(routeUrl(url, `#/submit?to=${community}`), { waitUntil: 'domcontentloaded' })
  await expectText(pageA, 'Create a post')
  await fillFirst(pageA, 'form[data-form="submit-post"] input[name="title"]', title)
  await fillFirst(pageA, 'form[data-form="submit-post"] textarea[name="body"]', 'browser smoke body')
  const backupAck = pageA.locator('input[name="identity-backup-ack"]')
  if (await backupAck.count()) await backupAck.first().check()
  await submitFirst(pageA, 'form[data-form="submit-post"] button[type="submit"]')
  await expectText(pageA, title)

  await fillFirst(pageA, 'form[data-form="comment"] textarea[name="body"]', firstComment)
  await submitFirst(pageA, 'form[data-form="comment"] button[type="submit"]')
  await expectText(pageA, firstComment)

  const pageB = await context.newPage()
  recordBrowserErrors(pageB, errors)
  await pageB.goto(pageA.url(), { waitUntil: 'domcontentloaded' })
  await expectText(pageB, firstComment)

  const badge = pageB.locator('[data-act="toggle-usermenu"] .uname')
  const beforeUser = (await badge.textContent()).trim()
  await pageB.locator('[data-act="toggle-usermenu"]').click()
  await fillFirst(pageB, 'form[data-form="dev-user"] input[name="name"]', userName)
  await submitFirst(pageB, 'form[data-form="dev-user"] button[type="submit"]')
  await pageB.waitForFunction(
    (before) => document.querySelector('[data-act="toggle-usermenu"] .uname')?.textContent.trim() !== before,
    beforeUser,
    { timeout: DEFAULT_TIMEOUT_MS }
  )

  await fillFirst(pageB, 'form[data-form="comment"] textarea[name="body"]', secondComment)
  await submitFirst(pageB, 'form[data-form="comment"] button[type="submit"]')
  await expectText(pageB, secondComment)
  await expectText(pageA, secondComment)

  if (errors.length) throw new Error(`browser emitted errors:\n${errors.join('\n')}`)

  await context.close()
  return { community, title, firstComment, secondComment, userName }
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  const playwright = await loadPlaywright()
  let dev = null
  const url = opts.url || (dev = await startDevServer()).url
  let browser = null
  try {
    browser = await playwright.chromium.launch({ headless: !opts.headed })
    const result = await runSmoke({ browser, url })
    console.log('[browser-smoke] PASS', JSON.stringify({ url, ...result }))
    if (opts.keepOpen) {
      console.log('[browser-smoke] keeping browser open; Ctrl-C to stop')
      await new Promise(() => {})
    }
  } finally {
    if (browser && !opts.keepOpen) await browser.close()
    if (dev) await stopDevServer(dev.child)
  }
}

main().catch((err) => {
  console.error('[browser-smoke] FAIL', err.stack || err.message)
  process.exit(1)
})
