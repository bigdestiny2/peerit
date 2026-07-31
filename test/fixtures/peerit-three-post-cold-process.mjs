import assert from 'node:assert/strict'
import fs from 'node:fs/promises'

import { createSync } from '../../js/sync.js'
import { unseal } from '../../js/seal.js'
import { createPeeritSeedColdReaderV1 } from '../../js/substrate/cold-reader.mjs'
import {
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../../js/substrate/peerit-journal.js'
import { qualifySeedRelayFixtures } from './peerit-qualified-seed-relays.mjs'

const fixture = JSON.parse(await fs.readFile(process.argv[2], 'utf8'))
const artifactBytes = new Uint8Array(Buffer.from(fixture.artifactBase64, 'base64'))
const stores = new Map(Object.entries(fixture.cells).map(([relayId, rows]) => [
  relayId,
  new Map(Object.entries(rows).map(([targetId, value]) => [targetId, new Uint8Array(Buffer.from(value, 'base64'))]))
]))
let gets = 0
const adapters = await qualifySeedRelayFixtures(fixture.relays, async (relayId, request) => {
  gets++
  const innerBytes = stores.get(relayId)?.get(`${request.targetId}\n${request.recordId}`)
  if (!innerBytes) throw Object.assign(new Error('fixture Cell unavailable'), { code: 'HIVERELAY_CELL_NOT_FOUND' })
  return { innerBytes, evidenceRef: `fresh-process:${relayId}:${request.recordId}` }
})
const shared = createMemoryJournalState()
const journal = createMemoryPeeritJournal({ shared, clock: () => fixture.now })
const sync = createSync({
  mode: 'substrate',
  journal,
  relays: [],
  autoFlush: false,
  channelName: 'peerit-three-post-fresh-process'
})
await sync.ready()
const reader = createPeeritSeedColdReaderV1({
  sync,
  relays: adapters,
  now: () => fixture.now,
  timeoutMillis: 1_000
})
const result = await reader.read(artifactBytes, fixture.verification)
assert.equal(result.networkPuts, 0)
assert.equal(result.recordCount, 4)
const observed = []
for (const record of fixture.records) {
  for (const wireKey of record.wireKeys) {
    const value = await sync.get(wireKey)
    if (value && value._t === 'post' && value.sealed) {
      const logical = await unseal(value.sealed)
      if (logical.cid) observed.push(logical.cid)
    }
  }
}
assert.deepEqual(observed.sort(), [...fixture.expectedCids].sort())
assert.equal(gets, 4, 'fresh process reads one healthy first replica per record')
sync.destroy()
process.stdout.write(JSON.stringify({ ok: true, networkGets: gets, networkPuts: 0, expectedCids: observed.sort() }))
