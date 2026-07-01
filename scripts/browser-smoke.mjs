#!/usr/bin/env node
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { genKeyPair, sign as signHostPayload } from '../js/crypto.js'

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_TIMEOUT_MS = Number(process.env.BROWSER_SMOKE_TIMEOUT_MS) || 45000
const HOST = process.env.HOST || DEFAULT_HOST
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const MOBILE_HOST_TOKEN = process.env.PEERIT_BROWSER_SMOKE_TOKEN || 'mobile-host-token'

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error('usage: node scripts/browser-smoke.mjs [--url <http-url>] [--headed] [--keep-open] [--mobile-host]')
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    url: process.env.PEERIT_BROWSER_SMOKE_URL || '',
    headed: process.env.HEADED === '1',
    keepOpen: false,
    mobileHost: process.env.PEERIT_BROWSER_SMOKE_MODE === 'mobile-host'
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--url') opts.url = argv[++i] || ''
    else if (arg === '--headed') opts.headed = true
    else if (arg === '--keep-open') opts.keepOpen = true
    else if (arg === '--mobile-host') opts.mobileHost = true
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

function escapeAttr (value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
}

function response (value, status = 200, headers = {}) {
  return {
    status,
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(value)
  }
}

function injectMobileHostMeta (html, token) {
  const metas = [
    `<meta name="pear-api-token" content="${escapeAttr(token)}">`,
    // If the mobile host token path regresses, this default-read-only web config
    // makes the fallback loud: the UI becomes web/read-only instead of writable.
    '<meta name="peerit-relay" content="same-origin">'
  ].join('\n  ')
  return html.replace(/<head([^>]*)>/i, `<head$1>\n  ${metas}`)
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

async function makeMobileHost (token = MOBILE_HOST_TOKEN) {
  const keypair = await genKeyPair()
  const publicKey = keypair.pubHex
  const driveKey = publicKey
  const calls = []
  const groups = new Map()
  let channelSeq = 0

  const ensureGroup = (appId) => {
    if (!groups.has(appId)) {
      groups.set(appId, {
        inviteKey: randomBytes(32).toString('hex'),
        rows: new Map(),
        version: 0
      })
    }
    return groups.get(appId)
  }
  const sortedRows = (g) => [...g.rows.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => ({ key, value }))

  function rowsForUrl (url) {
    const g = ensureGroup(url.searchParams.get('appId'))
    let rows = sortedRows(g)
    const prefix = url.searchParams.get('prefix') || ''
    if (prefix) rows = rows.filter((r) => r.key >= prefix && r.key < prefix + '\xff')
    for (const [bound, cmp] of [
      ['gte', (key, value) => key >= value],
      ['gt', (key, value) => key > value],
      ['lte', (key, value) => key <= value],
      ['lt', (key, value) => key < value]
    ]) {
      const value = url.searchParams.get(bound)
      if (value != null && value !== '') rows = rows.filter((r) => cmp(r.key, value))
    }
    if (url.searchParams.get('reverse')) rows.reverse()
    return rows
  }

  async function handle (request) {
    const url = new URL(request.url())
    const rawBody = request.postData()
    const body = rawBody ? JSON.parse(rawBody) : null
    const headers = request.headers()
    const suppliedToken = headers['x-pear-token'] || url.searchParams.get('token') || ''
    calls.push({
      method: request.method(),
      path: url.pathname + url.search,
      token: suppliedToken,
      body
    })

    if (suppliedToken !== token) return response({ error: 'missing or invalid Pear token' }, 401)

    try {
      const p = url.pathname
      if (p === '/api/identity') {
        return response({ publicKey, driveKey, algorithm: 'ed25519' })
      }
      if (p === '/api/identity/sign') {
        const namespace = body && body.namespace ? String(body.namespace) : ''
        const payload = body && body.payload != null ? String(body.payload) : ''
        const signature = await signHostPayload(keypair.seedHex, `pear.app.${driveKey}:${namespace}:${payload}`)
        return response({ signature, publicKey, algorithm: 'ed25519', tag: `pear.app.${driveKey}:${namespace}:${payload}` })
      }
      if (p === '/api/sync/create') {
        const g = ensureGroup(body.appId)
        return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId })
      }
      if (p === '/api/sync/join') {
        const g = ensureGroup(body.appId)
        if (body.inviteKey && body.inviteKey !== g.inviteKey) return response({ error: 'bad invite' }, 400)
        return response({ appId: body.appId, inviteKey: g.inviteKey, writerPublicKey: body.appId })
      }
      if (p === '/api/sync/append') {
        const g = ensureGroup(body.appId)
        const op = body.op
        const key = op.type.replace(':', '!') + '!' + op.data.id
        g.rows.set(key, op.data)
        g.version++
        return response({ ok: true, key })
      }
      if (p === '/api/sync/heads') {
        const heads = {}
        for (const appId of (body && body.appIds) || []) {
          const g = groups.get(appId)
          heads[appId] = g ? g.version : 0
        }
        return response({ heads })
      }
      if (p === '/api/sync/get') {
        const g = ensureGroup(url.searchParams.get('appId'))
        return response(g.rows.get(url.searchParams.get('key')) || null)
      }
      if (p === '/api/sync/list' || p === '/api/sync/range') {
        const rows = rowsForUrl(url)
        const limit = Number(url.searchParams.get('limit')) || 100
        return response(rows.slice(0, limit))
      }
      if (p === '/api/sync/count') {
        return response({ count: rowsForUrl(url).length })
      }
      if (p === '/api/sync/status') {
        const appId = url.searchParams.get('appId')
        const g = ensureGroup(appId)
        return response({ appId, inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size })
      }
      if (p === '/api/directory') {
        const heads = {}
        for (const [appId, g] of groups) {
          const head = g.rows.get('head!' + appId)
          if (head) heads[appId] = head
        }
        return response({ heads })
      }
      if (p === '/api/swarm/join') {
        const id = 'mobile-smoke-channel-' + (++channelSeq)
        return response({
          channelId: id,
          topicHex: body.topicHex || '0'.repeat(64),
          protocol: body.protocol,
          version: body.version,
          tier: 'A'
        })
      }
      if (p === '/api/swarm/send' || p === '/api/swarm/leave') return response({ ok: true })
      if (p === '/api/swarm/events') {
        return {
          status: 200,
          headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-store' },
          body: ':\n\n'
        }
      }
      if (p === '/api/bridge/status') return response({ ready: true, mobile: true })
      return response({ error: 'not found' }, 404)
    } catch (err) {
      return response({ error: err && err.message ? err.message : String(err) }, 500)
    }
  }

  return {
    token,
    publicKey,
    driveKey,
    calls,
    groups,
    handle,
    rows () { return groups.get(publicKey) ? groups.get(publicKey).rows : new Map() },
    appendCalls () { return calls.filter((c) => c.path.startsWith('/api/sync/append')) }
  }
}

async function installMobileHost (context, host) {
  await context.addInitScript(() => {
    window.__peeritSmokeEventSourceUrls = []
    window.EventSource = class PeeritSmokeEventSource {
      constructor (url) {
        this.url = String(url)
        this.readyState = 1
        window.__peeritSmokeEventSourceUrls.push(this.url)
      }
      close () { this.readyState = 2 }
    }
  })

  await context.route('**/*', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.pathname.startsWith('/api/')) {
      const res = await host.handle(request)
      await route.fulfill({ status: res.status, headers: res.headers, body: res.body })
      return
    }
    if (request.resourceType() === 'document' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const upstream = await route.fetch()
      const headers = upstream.headers()
      delete headers['content-length']
      headers['content-type'] = 'text/html; charset=utf-8'
      const html = injectMobileHostMeta(await upstream.text(), host.token)
      await route.fulfill({ status: upstream.status(), headers, body: html })
      return
    }
    await route.continue()
  })
}

async function assertMobileHostPath (page, host) {
  await page.locator('.mode-badge.live').waitFor({ timeout: DEFAULT_TIMEOUT_MS })
  await page.waitForFunction(
    () => document.querySelector('#netstatus b')?.textContent.trim() === 'gossip-bridge',
    null,
    { timeout: DEFAULT_TIMEOUT_MS }
  )
  const state = await page.evaluate((token) => ({
    badge: document.querySelector('.mode-badge')?.textContent.trim() || '',
    readOnlyClass: document.body.classList.contains('web-readonly'),
    readOnlyBanner: !!document.querySelector('.readonly-banner'),
    devUsers: localStorage.getItem('peerit:dev:users'),
    devView: localStorage.getItem('peerit:view'),
    eventSourceHasToken: (window.__peeritSmokeEventSourceUrls || []).some((url) => url.includes('/api/swarm/events') && url.includes('token=' + encodeURIComponent(token)))
  }), host.token)
  if (state.badge !== 'p2p') throw new Error(`mobile host smoke expected p2p badge, saw ${state.badge || 'none'}`)
  if (state.readOnlyClass || state.readOnlyBanner) throw new Error('mobile host smoke fell into read-only web UI')
  if (state.devUsers || state.devView) throw new Error('mobile host smoke created dev-mode localStorage state')
  if (!state.eventSourceHasToken) throw new Error('mobile host smoke did not open tokenized /api/swarm/events')
}

function assertHostWrites (host, { community, title, firstComment }) {
  const rows = host.rows()
  const keys = [...rows.keys()]
  if (!rows.has('community!' + community)) throw new Error('mobile host smoke did not write the community to /api sync')
  if (!keys.some((k) => k.startsWith(`post!${community}!`) && rows.get(k).title === title)) {
    throw new Error('mobile host smoke did not write the post to /api sync')
  }
  if (!keys.some((k) => k.startsWith(`comment!${community}!`) && rows.get(k).body === firstComment)) {
    throw new Error('mobile host smoke did not write the comment to /api sync')
  }
  const head = rows.get('head!' + host.publicKey)
  if (!head || head.author !== host.publicKey || (head.count | 0) < 3) {
    throw new Error('mobile host smoke did not maintain a signed outbox head after writes')
  }
  if (host.appendCalls().length < 3) throw new Error('mobile host smoke made too few /api append calls')
  const missingToken = host.calls.find((c) => c.token !== host.token)
  if (missingToken) throw new Error(`mobile host smoke made an un-tokened API call: ${missingToken.method} ${missingToken.path}`)
}

function mobileContextOptions () {
  return {
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2,
    isMobile: true,
    hasTouch: true,
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) PearBrowserMobileSmoke/1.0 Mobile/15E148 Safari/604.1'
  }
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

async function runMobileHostSmoke ({ browser, url }) {
  const stamp = Date.now().toString(36)
  const community = `mobile${stamp.slice(-6)}`
  const title = `PearBrowser mobile host-token smoke ${stamp}`
  const firstComment = `mobile host comment ${stamp}`
  const host = await makeMobileHost()
  const errors = []

  const context = await browser.newContext(mobileContextOptions())
  await installMobileHost(context, host)
  const page = await context.newPage()
  recordBrowserErrors(page, errors)

  let readerContext = null
  try {
    await page.goto(routeUrl(url, '#/create'), { waitUntil: 'domcontentloaded' })
    await page.locator('#app').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS })
    await assertMobileHostPath(page, host)

    await fillFirst(page, 'form[data-form="create-community"] input[name="slug"]', community)
    await fillFirst(page, 'form[data-form="create-community"] input[name="title"]', `Mobile ${stamp}`)
    await fillFirst(page, 'form[data-form="create-community"] textarea[name="description"]', 'Automated PearBrowser mobile host-token smoke community')
    await submitFirst(page, 'form[data-form="create-community"] button[type="submit"]')
    await expectText(page, `r/${community}`)
    await assertMobileHostPath(page, host)

    await page.goto(routeUrl(url, `#/submit?to=${community}`), { waitUntil: 'domcontentloaded' })
    await expectText(page, 'Create a post')
    await assertMobileHostPath(page, host)
    await fillFirst(page, 'form[data-form="submit-post"] input[name="title"]', title)
    await fillFirst(page, 'form[data-form="submit-post"] textarea[name="body"]', 'mobile host-token smoke body')
    const backupAck = page.locator('input[name="identity-backup-ack"]')
    if (await backupAck.count()) await backupAck.first().check()
    await submitFirst(page, 'form[data-form="submit-post"] button[type="submit"]')
    await expectText(page, title)
    await assertMobileHostPath(page, host)

    await fillFirst(page, 'form[data-form="comment"] textarea[name="body"]', firstComment)
    await submitFirst(page, 'form[data-form="comment"] button[type="submit"]')
    await expectText(page, firstComment)
    await assertMobileHostPath(page, host)

    assertHostWrites(host, { community, title, firstComment })

    const threadUrl = page.url()
    readerContext = await browser.newContext(mobileContextOptions())
    await installMobileHost(readerContext, host)
    const reader = await readerContext.newPage()
    recordBrowserErrors(reader, errors)
    await reader.goto(threadUrl, { waitUntil: 'domcontentloaded' })
    await reader.locator('#app').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS })
    await assertMobileHostPath(reader, host)
    await expectText(reader, title)
    await expectText(reader, firstComment)

    if (errors.length) throw new Error(`browser emitted errors:\n${errors.join('\n')}`)
  } finally {
    if (readerContext) await readerContext.close()
    await context.close()
  }

  return {
    mode: 'mobile-host',
    community,
    title,
    firstComment,
    apiCalls: host.calls.length,
    appendCalls: host.appendCalls().length,
    writer: host.publicKey.slice(0, 12)
  }
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  const playwright = await loadPlaywright()
  let dev = null
  const url = opts.url || (dev = await startDevServer()).url
  let browser = null
  try {
    browser = await playwright.chromium.launch({ headless: !opts.headed })
    const result = opts.mobileHost
      ? await runMobileHostSmoke({ browser, url })
      : await runSmoke({ browser, url })
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
