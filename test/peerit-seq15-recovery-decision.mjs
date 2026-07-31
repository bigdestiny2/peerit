import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const decisionPath = new URL('../deploy/canary-decision-peerit-seq15-seed-recovery-20260729t172519z.json', import.meta.url)
const decisionBytes = readFileSync(decisionPath)
const decisionHash = createHash('sha256').update(decisionBytes).digest('hex')
const decision = JSON.parse(decisionBytes)
const releaseSource = readFileSync(new URL('../scripts/web-release.mjs', import.meta.url), 'utf8')

assert.equal(decisionHash, '11d95b7abd52d7c4d443548089a8dd5455be87ee81ececf50314047a6b10ba50')
assert.match(releaseSource, new RegExp(decisionHash))
assert.match(releaseSource, /canary-decision-peerit-seq15-seed-recovery-20260729t172519z\.json/)
assert.equal(decision.schema_version, 3)
assert.equal(decision.status, 'DECIDED')
assert.equal(decision.activation.functional_release_sequence, 15)
assert.equal(decision.activation.rollback_release_sequence, 16)
assert.equal(decision.activation.rollback_posture,
  'RESTORE_SEQUENCE_14_FAIL_CLOSED_RUNTIME_BEHAVIOR_AT_NEW_SEQUENCE_16')
assert.equal(decision.activation.limited_cell_get_authority_release_sequence, 15)
assert.equal(decision.activation.rollback_requires_limited_cell_get_assets, false)
assert.equal(decision.activation.claim_boundary, 'LIVE_PUBLIC_TEST_ONLY')
assert.deepEqual(decision.activation.relays, ['syd-1', 'dal-1'])
assert.deepEqual(decision.activation.allowed_browser_operations,
  ['DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET'])
assert.equal(decision.activation.network_puts_during_recovery, 0)
assert.equal(decision.activation.ordinary_delivery, 'LOCAL_ONLY')
assert.equal(decision.activation.seed_record_count, 4)
assert.equal(decision.activation.historical_seed_put_count, 8)
assert.equal(decision.activation.post_cids.length, 3)
assert.equal(decision.activation.all_five_successor,
  'EXCLUDED_UNTIL_AFTER_PEERIT_SITE_SEQUENCE_15_ACTIVATION')
assert.equal(decision.fixed_cell_get_authority.hiverelay_commit,
  'c284435c1d075423a8d1bfcea04c3e171c6757ca')
assert.equal(decision.fixed_cell_get_authority.artifact_sha256,
  '653cba3c78d3b26b1e4f06a22fff8a5896a5c5158bc24c8b06ad577196429eed')
assert.deepEqual(decision.fixed_cell_get_authority.public_exports,
  ['createBlindCellGetControl', 'createBrowserCryptoRuntime'])
assert.match(decision.decision, /zero network PUTs/)
assert.ok(decision.followups.includes('GA product gate remains honestly blocked'))

console.log('peerit seq15 recovery decision: byte-pinned fixed Cell GET, zero-PUT recovery, seq16 rollback and all-five exclusion ok')
