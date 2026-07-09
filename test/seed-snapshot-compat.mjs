// The signed launch snapshot predates identity-bound pow.v=2. Those exact rows
// must remain readable, while newly signed legacy sealed rows stay rejected.

import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { auditOutbox, mergeOutboxes } from '../js/gossip.js'
import { makeValidator } from '../js/pow.js'
import { LEGACY_SEALED_V2_POW_SIGNATURES } from '../js/legacy-v2-pow-allowlist.js'
import { ready as cryptoReady } from '../js/crypto.js'

const snapshot = JSON.parse(readFileSync(new URL('../config/seed-snapshot.json', import.meta.url), 'utf8'))
const bits = { community: 7, post: 6, comment: 5, blob: 4 }

await cryptoReady()
assert.equal(snapshot.authors.length, 1, 'fixture has the curated seed author')

const boxes = snapshot.authors.map((author) => ({
  pub: author.pub,
  view: Object.fromEntries(author.rows.map((row) => [row.key, row.value]))
}))
const merged = await mergeOutboxes(boxes, {}, makeValidator(bits))
const expectedRows = snapshot.authors.reduce((n, author) => n + author.rows.length, 0)

assert.equal(Object.keys(merged).length, expectedRows, 'every signed snapshot row survives the PoW migration boundary')
assert.equal(Object.values(merged).filter((value) => value && value.sealed).length, 8, 'all eight sealed content rows remain visible')

for (const author of snapshot.authors) {
  const headKey = `head!${author.pub}`
  const head = merged[headKey]
  assert.ok(head, `snapshot author ${author.pub} has an admitted signed head`)
  const audit = await auditOutbox(author.rows, head, author.pub)
  assert.equal(audit.matches, true, `snapshot author ${author.pub} reproduces its signed head census`)
  assert.equal(head.version, 14, 'curated seed snapshot preserves monotonic head version 14')
  assert.equal(head.count, 8, 'curated seed snapshot head commits all eight content rows')
  assert.equal(head.root, 'b020109def378483e3201c2c9edc6ae043fd9fccb0eed353d9e16d5268883799', 'curated seed snapshot reproduces the independently recorded v14 root')
  for (const row of author.rows) {
    const value = row.value
    if (!value || !value.sealed) continue
    assert.ok(LEGACY_SEALED_V2_POW_SIGNATURES.has(String(value._sig).toLowerCase()), `snapshot row ${row.key} is explicitly grandfathered`)
  }
}

const legacy = snapshot.authors[0].rows.find((row) => row.value && row.value.sealed).value
const unlisted = { ...legacy, _sig: '00'.repeat(64) }
assert.equal(await makeValidator(bits)(legacy._t, unlisted), false, 'an unlisted sealed legacy proof is rejected')

console.log(`seed-snapshot-compat: ${expectedRows} signed rows admitted; unlisted legacy proof rejected`)
