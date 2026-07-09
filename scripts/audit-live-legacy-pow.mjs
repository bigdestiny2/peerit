#!/usr/bin/env node

// Read-only production audit for the sealed-v2 PoW migration boundary.
//
// Before identity-bound pow.v=2 shipped, production wrote sealed rows carrying
// reusable legacy targets. Those rows remain readable only by exact signature.
// This audit fails when production contains an unpinned legacy row, so a release
// cannot silently hide historical content or broaden the migration exception.

import assert from 'node:assert/strict'
import { mergeOutboxes } from '../js/gossip.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { LEGACY_SEALED_V2_POW_SIGNATURES } from '../js/legacy-v2-pow-allowlist.js'
import { makeValidator } from '../js/pow.js'

const relay = String(process.env.PEERIT_RELAY || 'https://outbox.peerit.site').replace(/\/$/, '')
const maxDirectoryPages = 50
const maxRangePages = 200

async function json (url, options = {}) {
  const response = await fetch(url, options)
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}: ${url}`)
  return response.json()
}

async function tokenHeaders () {
  const payload = await json(`${relay}/api/token`, { method: 'POST' })
  assert.equal(typeof payload.token, 'string', 'relay returned an access token')
  return { 'X-Pear-Token': payload.token }
}

async function listAuthors (headers) {
  const authors = new Set()
  let cursor = ''
  for (let page = 0; page < maxDirectoryPages; page++) {
    const url = new URL(`${relay}/api/directory`)
    url.searchParams.set('limit', '2000')
    if (cursor) url.searchParams.set('cursor', cursor)
    const payload = await json(url, { headers })
    const heads = payload.heads || payload
    for (const appId of Object.keys(heads || {})) {
      if (/^[0-9a-f]{64}$/i.test(appId)) authors.add(appId.toLowerCase())
    }
    if (!payload.hasMore || !payload.nextCursor) return [...authors].sort()
    cursor = payload.nextCursor
  }
  throw new Error(`directory pagination exceeded ${maxDirectoryPages} pages`)
}

async function listRows (appId, headers) {
  const rows = []
  let gt = ''
  for (let page = 0; page < maxRangePages; page++) {
    const url = new URL(`${relay}/api/sync/range`)
    url.searchParams.set('appId', appId)
    url.searchParams.set('limit', '1000')
    if (gt) url.searchParams.set('gt', gt)
    const batch = await json(url, { headers })
    assert.ok(Array.isArray(batch), `range response for ${appId} is an array`)
    if (!batch.length) return rows
    rows.push(...batch)
    const last = batch.at(-1) && batch.at(-1).key
    if (batch.length < 1000) return rows
    if (!last || last === gt) throw new Error(`range cursor stalled for ${appId}`)
    gt = last
  }
  throw new Error(`range pagination exceeded ${maxRangePages} pages for ${appId}`)
}

function isLegacySealed (value) {
  if (!value || !value.sealed || !value.pow) return false
  return value.pow.v == null || Number(value.pow.v) < 2
}

await cryptoReady()
const headers = await tokenHeaders()
const authors = await listAuthors(headers)
const validator = makeValidator()
let rowCount = 0
let legacyCount = 0
const missing = []
const rejected = []

for (const pub of authors) {
  const rows = await listRows(pub, headers)
  rowCount += rows.length
  for (const row of rows) {
    const value = row && row.value
    if (!isLegacySealed(value)) continue
    legacyCount++
    const signature = String(value._sig || '').toLowerCase()
    if (!LEGACY_SEALED_V2_POW_SIGNATURES.has(signature)) {
      missing.push({ pub, key: row.key, signature })
      continue
    }
    const merged = await mergeOutboxes([{ pub, view: { [row.key]: value } }], {}, validator)
    if (!merged[row.key]) rejected.push({ pub, key: row.key, signature })
  }
}

assert.deepEqual(missing, [], 'every live legacy sealed row is pinned by exact signature')
assert.deepEqual(rejected, [], 'every pinned live legacy sealed row passes signature, ownership, key-binding, and PoW validation')

console.log(JSON.stringify({
  ok: true,
  relay,
  authors: authors.length,
  rows: rowCount,
  legacySealedRows: legacyCount,
  allowlistedSignatures: LEGACY_SEALED_V2_POW_SIGNATURES.size
}, null, 2))
