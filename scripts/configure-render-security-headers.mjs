#!/usr/bin/env node

// Apply the reviewed static-site response headers through Render's API. The
// token comes from the operator environment/KeyVault; this script never prints
// it. Dry-run is the default so a service ID typo cannot mutate another site.

import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const API = 'https://api.render.com/v1'

function usage (code = 0, message = '') {
  if (message) console.error(`[render-headers] FAIL ${message}`)
  console.error('usage: node scripts/configure-render-security-headers.mjs --service <srv-id> [--apply]')
  process.exit(code)
}

function parseArgs (argv) {
  const opts = { service: process.env.RENDER_SERVICE_ID || '', apply: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--service') opts.service = argv[++i] || ''
    else if (arg.startsWith('--service=')) opts.service = arg.slice('--service='.length)
    else if (arg === '--apply') opts.apply = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  if (!/^srv-[a-z0-9]+$/i.test(opts.service)) usage(2, '--service must be a Render service ID')
  return opts
}

async function request (token, path, init = {}) {
  const response = await fetch(API + path, {
    ...init,
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...(init.headers || {})
    }
  })
  const text = await response.text()
  let body = null
  try { body = text ? JSON.parse(text) : null } catch {}
  if (!response.ok) throw new Error(`${init.method || 'GET'} ${path} returned HTTP ${response.status}${body && body.message ? `: ${body.message}` : ''}`)
  return body
}

function headerRows (payload) {
  if (Array.isArray(payload)) return payload
  if (payload && Array.isArray(payload.headers)) return payload.headers
  if (payload && Array.isArray(payload.items)) return payload.items
  return []
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  const token = String(process.env.RENDER_API_KEY || '').trim()
  if (!token) throw new Error('RENDER_API_KEY is required (supply it through KeyVault or the operator environment)')
  const policy = JSON.parse(await readFile(join(ROOT, 'deploy', 'render-security-headers.json'), 'utf8'))
  if (!policy || policy.provider !== 'Render static site' || typeof policy.path !== 'string' || !Array.isArray(policy.headers)) {
    throw new Error('deploy/render-security-headers.json is not a valid Render static-site policy')
  }

  const current = headerRows(await request(token, `/services/${opts.service}/headers?limit=100`))
  const plan = []
  for (const required of policy.headers) {
    if (!required || typeof required.name !== 'string' || typeof required.value !== 'string') throw new Error('header policy contains an invalid rule')
    const matches = current.filter(row => row && row.path === policy.path && String(row.name || '').toLowerCase() === required.name.toLowerCase())
    if (matches.length === 1 && matches[0].value === required.value) {
      plan.push({ action: 'keep', name: required.name })
      continue
    }
    plan.push({ action: matches.length ? 'replace' : 'add', name: required.name, conflicts: matches.map(row => row.id).filter(Boolean) })
  }

  for (const item of plan) console.log(`[render-headers] ${item.action} ${policy.path} ${item.name}`)
  if (!opts.apply) {
    console.log('[render-headers] dry-run only; pass --apply to make the reviewed changes')
    return
  }

  for (const item of plan) {
    if (item.action === 'keep') continue
    for (const id of item.conflicts || []) await request(token, `/services/${opts.service}/headers/${encodeURIComponent(id)}`, { method: 'DELETE' })
    const required = policy.headers.find(header => header.name === item.name)
    await request(token, `/services/${opts.service}/headers`, {
      method: 'POST',
      body: JSON.stringify({ path: policy.path, name: required.name, value: required.value })
    })
  }
  console.log(`[render-headers] applied ${plan.filter(item => item.action !== 'keep').length} change(s) to ${opts.service}`)
}

main().catch((err) => {
  console.error('[render-headers] FAIL', err && err.message ? err.message : err)
  process.exit(1)
})
