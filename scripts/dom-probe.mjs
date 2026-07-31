// dom-probe.mjs — load peerit.site in real Chromium, dump substrate state + rendered DOM
import { chromium } from 'playwright'

const URL_ = process.argv[2] || 'https://peerit.site/'
const browser = await chromium.launch()
const page = await browser.newPage()
const consoleErrors = []
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()) })
page.on('pageerror', (e) => consoleErrors.push('PAGEERROR: ' + e.message))
await page.goto(URL_, { waitUntil: 'load', timeout: 30000 })
// wait for boot to settle (substrate status attrs appear)
try {
  await page.waitForFunction(() => document.documentElement.getAttribute('data-peerit-substrate-state') !== null || document.documentElement.getAttribute('data-peerit-local-authoring') !== null, null, { timeout: 60000 })
} catch {}
await page.waitForTimeout(12000)
const attrs = await page.evaluate(() => {
  const el = document.documentElement
  const out = {}
  for (const a of el.attributes) if (a.name.startsWith('data-peerit')) out[a.name] = a.value
  return out
})
const bodyText = await page.evaluate(() => document.body ? document.body.innerText.slice(0, 2200) : '(no body)')
const links = await page.evaluate(() => [...document.querySelectorAll('a')].slice(0, 30).map(a => `${a.innerText.trim().slice(0, 40)} -> ${a.getAttribute('href')}`))
console.log('=== data-peerit attrs ===')
console.log(JSON.stringify(attrs, null, 1))
console.log('=== console errors ===')
console.log(consoleErrors.length ? consoleErrors.slice(0, 10).join('\n') : '(none)')
console.log('=== first links ===')
console.log(links.join('\n') || '(no links)')
console.log('=== body text (first 2200 chars) ===')
console.log(bodyText)
await browser.close()
