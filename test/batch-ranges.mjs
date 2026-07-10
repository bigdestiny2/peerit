// batch-ranges.mjs — pagination/integrity boundaries for the optional
// POST /api/sync/ranges transport. The batch response is only a read
// optimisation; gossip.js retains its normal per-record and signed-head audit.

import assert from 'node:assert'
import { BridgeGossipSync } from '../js/gossip.js'

let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }
const mem = () => { const m = new Map(); return { getItem: (key) => m.get(key) || null, setItem: (key, value) => m.set(key, String(value)), removeItem: (key) => m.delete(key) } }
const row = (n) => ({ key: String(n).padStart(4, '0'), value: { n } })

async function main () {
  const first = Array.from({ length: 1001 }, (_, i) => row(i))
  const second = [row(9001)]
  const calls = []
  const sync = new BridgeGossipSync({
    pear: {
      sync: {
        ranges: async (requests) => {
          calls.push(requests)
          return {
            ranges: requests.map((request) => {
              const source = request.appId === 'a' ? first : second
              const after = request.gt ? source.filter((item) => item.key > request.gt) : source
              return { appId: request.appId, rows: after.slice(0, request.limit) }
            })
          }
        }
      }
    },
    getMe: () => null,
    identity: null,
    storage: mem(),
    readOnly: true,
    pollMs: 0
  })

  console.log('\n— batched range pagination —')
  const rows = await sync._batchRowsForPeers([
    { pub: 'a', info: { appId: 'a' } },
    { pub: 'b', info: { appId: 'b' } }
  ])
  ok(rows.get('a').length === 1001 && rows.get('a')[1000].key === '1000', 'a full 1,000-row page advances and retrieves its final row')
  ok(rows.get('b').length === 1 && rows.get('b')[0].key === '9001', 'independent outboxes finish without delaying the next page')
  ok(calls.length === 2 && calls[0].length === 2 && calls[1].length === 1, 'only unfinished outboxes are included in the second batch page')
  ok(calls[1][0].appId === 'a' && calls[1][0].gt === '0999', 'the continuation is strictly keyed to the previous page tail')

  console.log(`\n✅ all ${passed} batch-range checks passed\n`)
}

main().catch((error) => { console.error('❌', (error && error.stack) || error); process.exit(1) })
