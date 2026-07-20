// outbox-availability-proof.mjs - release evidence tests for the representative
// fresh-client outbox availability proof.

import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import { buildOutboxAvailabilityProof } from '../scripts/outbox-availability-proof.mjs'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

async function main () {
  console.log('\n- representative outbox availability proof -')

  const ready = await buildOutboxAvailabilityProof({
    fixture: 'ready',
    now: Date.parse('2026-07-01T18:30:00.000Z')
  })
  ok(ready.kind === 'peerit-representative-outbox-availability', 'proof reports the evidence kind')
  ok(ready.status === 'ready', 'ready fixture proves fresh-client outbox recovery')
  ok(ready.checks.some((check) => check.id === 'seeder:byte-catchup' && check.status === 'pass'), 'ready fixture confirms byte catch-up')
  ok(ready.freshReader.recoveredAllRepresentativeData === true && ready.freshReader.recovered.report === true,
    'fresh reader recovers representative profile/community/post/comment/vote/report data from opaque cells')

  const blocked = await buildOutboxAvailabilityProof({
    fixture: 'missing-catchup',
    now: Date.parse('2026-07-01T18:30:00.000Z')
  })
  ok(blocked.status === 'blocked', 'missing byte catch-up blocks the proof')
  ok(blocked.checks.some((check) => check.id === 'seeder:byte-catchup' && check.status === 'fail'), 'blocked proof names byte catch-up as the failure')
  ok(blocked.checks.some((check) => check.id === 'fresh-reader:representative-data' && check.status === 'fail'), 'blocked proof also shows the fresh reader did not recover the full set')

  const cli = spawnSync(process.execPath, [
    'scripts/outbox-availability-proof.mjs',
    '--fixture', 'missing-catchup',
    '--json'
  ], { encoding: 'utf8' })
  ok(cli.status === 1, 'CLI exits 1 when byte catch-up is not confirmed')
  ok(JSON.parse(cli.stdout).checks.some((check) => check.id === 'seeder:byte-catchup' && check.status === 'fail'), 'CLI JSON pinpoints byte catch-up failure')

  console.log(`\nOK ${passed} outbox-availability-proof checks passed\n`)
}

main().catch((e) => { console.error('\nFAILED:', e.message, '\n', e.stack); process.exit(1) })
