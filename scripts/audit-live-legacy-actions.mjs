#!/usr/bin/env node

// Read-only production audit for the protocol-v3 target-reference cutover.
//
// Run while public writes are blocked. The only POST is /api/token (ephemeral
// read authorization); this script never calls create, append, or commit.
// It proves that:
//   - every live legacy comment/vote/mod signature is frozen exactly;
//   - every frozen action is still present (rollback/data-loss signal);
//   - each historical row still passes the real signature/key/admission path;
//   - every legacy content CID in live + the signed seed fixture is denied as a
//     future protocol-v3 action target.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mergeOutboxes } from '../js/gossip.js'
import { ready as cryptoReady } from '../js/crypto.js'
import {
  LEGACY_ACTION_SIGNATURES,
  LEGACY_TARGET_CIDS
} from '../js/legacy-action-allowlist.js'
import { TYPE } from '../js/model.js'
import { makeValidator } from '../js/pow.js'
import { unseal } from '../js/seal.js'

const relay = String(process.env.PEERIT_RELAY || 'https://outbox.peerit.site').replace(/\/$/, '')
const seed = JSON.parse(readFileSync(new URL('../config/seed-snapshot.json', import.meta.url), 'utf8'))
const ACTION_TYPES = new Set([TYPE.COMMENT, TYPE.VOTE, TYPE.MOD])
const CONTENT_TYPES = new Set([TYPE.POST, TYPE.COMMENT])
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
    for (const appId of Object.keys(heads || {})) if (/^[0-9a-f]{64}$/i.test(appId)) authors.add(appId.toLowerCase())
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
    const last = batch.at(-1)?.key
    if (batch.length < 1000) return rows
    if (!last || last === gt) throw new Error(`range cursor stalled for ${appId}`)
    gt = last
  }
  throw new Error(`range pagination exceeded ${maxRangePages} pages for ${appId}`)
}

function semanticType (row) {
  return row?.value?._t || String(row?.key || '').split('!')[0]
}

async function logicalValue (row) {
  const value = row?.value
  if (!value?.sealed) return value
  const graph = await unseal(value.sealed)
  return { ...graph, author: value._k, by: value._k, creator: value._k }
}

function expectedActionSignatures () {
  const out = new Map()
  for (const type of ACTION_TYPES) for (const sig of LEGACY_ACTION_SIGNATURES[type]) out.set(sig, type)
  return out
}

await cryptoReady()
const headers = await tokenHeaders()
const authors = await listAuthors(headers)
const live = []
for (const pub of authors) for (const row of await listRows(pub, headers)) live.push({ ...row, pub })

const validator = makeValidator()
const expected = expectedActionSignatures()
const observedLegacyActions = new Map()
const unexpected = []
const rejected = []

for (const row of live) {
  const type = semanticType(row)
  if (!ACTION_TYPES.has(type)) continue
  const logical = await logicalValue(row)
  if (Number(logical?.protocol) === 3) continue
  const signature = String(row.value?._sig || '').toLowerCase()
  observedLegacyActions.set(signature, type)
  if (expected.get(signature) !== type) unexpected.push({ pub: row.pub, key: row.key, type, signature })
  const merged = await mergeOutboxes([{ pub: row.pub, view: { [row.key]: row.value } }], {}, validator)
  if (!merged[row.key]) rejected.push({ pub: row.pub, key: row.key, type, signature })
}

const missing = [...expected].filter(([signature, type]) => observedLegacyActions.get(signature) !== type).map(([signature, type]) => ({ type, signature }))
assert.deepEqual(unexpected, [], 'no unpinned legacy action exists in the live read-only inventory')
assert.deepEqual(missing, [], 'every frozen legacy action is still served (no action rollback/loss)')
assert.deepEqual(rejected, [], 'every frozen action passes signature, ownership, key-binding, and admission validation')

const legacyCids = new Set()
for (const row of [
  ...live,
  ...(seed.authors || []).flatMap(author => (author.rows || []).map(row => ({ ...row, pub: author.pub })))
]) {
  const type = semanticType(row)
  if (!CONTENT_TYPES.has(type)) continue
  const logical = await logicalValue(row)
  if (Number(logical?.protocol) !== 3 && typeof logical?.cid === 'string') legacyCids.add(logical.cid)
}
const unpinnedCids = [...legacyCids].filter(cid => !LEGACY_TARGET_CIDS.has(cid)).sort()
const missingCids = [...LEGACY_TARGET_CIDS].filter(cid => !legacyCids.has(cid)).sort()
assert.deepEqual(unpinnedCids, [], 'every live/seed legacy CID is in the target deny-set')
assert.deepEqual(missingCids, [], 'the target deny-set contains no unexplained CID')

console.log(JSON.stringify({
  ok: true,
  relay,
  authors: authors.length,
  rows: live.length,
  legacyActions: Object.fromEntries([...ACTION_TYPES].map(type => [type, [...observedLegacyActions.values()].filter(value => value === type).length])),
  frozenActionSignatures: expected.size,
  frozenLegacyTargetCids: LEGACY_TARGET_CIDS.size
}, null, 2))
