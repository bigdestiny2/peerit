#!/usr/bin/env node

// Verify the response-header policy that a static host must supply. A CSP meta
// is still useful for portable/offline copies, but frame-ancestors is ignored in
// a meta tag and therefore must be enforced at the HTTP edge.

import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_URL = 'https://peerit.site'
const TIMEOUT_MS = 20_000

function usage (code = 0, message = '') {
  if (message) console.error(`[http-headers] FAIL ${message}`)
  console.error('usage: node scripts/verify-http-security-headers.mjs [--url https://peerit.site]')
  process.exit(code)
}

function parseArgs (argv) {
  let url = DEFAULT_URL
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--url') url = argv[++i] || ''
    else if (arg.startsWith('--url=')) url = arg.slice('--url='.length)
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  let parsed
  try { parsed = new URL(url) } catch { usage(2, '--url must be a valid http(s) URL') }
  if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password) usage(2, '--url must be a credential-free http(s) URL')
  parsed.hash = ''
  parsed.search = ''
  return parsed.href
}

function directives (policy) {
  const out = new Map()
  for (const raw of String(policy || '').split(';')) {
    const parts = raw.trim().split(/\s+/).filter(Boolean)
    if (parts.length) out.set(parts[0].toLowerCase(), parts.slice(1))
  }
  return out
}

function requireSource (policy, name, source) {
  const values = policy.get(name)
  if (!values || !values.includes(source)) throw new Error(`Content-Security-Policy must include ${name} ${source}`)
}

async function artifactConnectSources () {
  const html = await readFile(join(ROOT, 'web', 'index.html'), 'utf8')
  const match = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/i)
  if (!match) throw new Error('web/index.html has no CSP meta policy')
  const meta = directives(match[1])
  if (meta.has('frame-ancestors')) throw new Error('web/index.html must not put frame-ancestors in a meta CSP; browsers ignore it')
  return meta.get('connect-src') || []
}

async function main () {
  const url = parseArgs(process.argv.slice(2))
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  let response
  try {
    response = await fetch(url, { signal: controller.signal, headers: { 'cache-control': 'no-cache' } })
  } finally {
    clearTimeout(timer)
  }
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`)

  const cspRaw = response.headers.get('content-security-policy')
  if (!cspRaw) throw new Error('missing Content-Security-Policy HTTP response header')
  const csp = directives(cspRaw)
  for (const [name, source] of [
    ['default-src', "'self'"],
    ['base-uri', "'none'"],
    ['object-src', "'none'"],
    ['script-src', "'self'"],
    ['style-src', "'self'"],
    ['img-src', "'self'"],
    ['connect-src', "'self'"],
    ['form-action', "'none'"],
    ['frame-ancestors', "'none'"]
  ]) requireSource(csp, name, source)
  for (const source of await artifactConnectSources()) requireSource(csp, 'connect-src', source)

  const simple = new Map([
    ['x-content-type-options', 'nosniff'],
    ['x-frame-options', 'DENY'],
    ['referrer-policy', 'strict-origin-when-cross-origin'],
    ['permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()']
  ])
  for (const [name, expected] of simple) {
    const value = response.headers.get(name)
    if (value !== expected) throw new Error(`${name} must be exactly ${JSON.stringify(expected)}; got ${JSON.stringify(value)}`)
  }
  console.log(`[http-headers] PASS ${url}`)
}

main().catch((err) => {
  console.error('[http-headers] FAIL', err && err.message ? err.message : err)
  process.exit(1)
})
