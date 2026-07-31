import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const decisionPath = new URL(
  '../deploy/canary-decision-peerit-seq17-exact-admission-url-recovery-20260729.json',
  import.meta.url)
const decisionBytes = readFileSync(decisionPath)
const decisionHash = createHash('sha256').update(decisionBytes).digest('hex')
const decision = JSON.parse(decisionBytes)
const releaseSource = readFileSync(new URL('../scripts/web-release.mjs', import.meta.url), 'utf8')

assert.equal(decisionHash, 'd218d4c2ff9c651b96450e5caf85911fe1e715767eecd129c8a7c20ad443297a')
assert.match(releaseSource, new RegExp(decisionHash))
assert.match(releaseSource,
  /canary-decision-peerit-seq17-exact-admission-url-recovery-20260729\.json/)
assert.equal(decision.schema_version, 4)
assert.equal(decision.status, 'DECIDED')
assert.equal(decision.activation.functional_release_sequence, 17)
assert.equal(decision.activation.rollback_release_sequence, 18)
assert.equal(decision.activation.rollback_posture,
  'COLD_FAIL_CLOSED_BEFORE_RELAY_IO_AT_SEQUENCE_18')
assert.equal(decision.activation.limited_cell_get_authority_release_sequence, 17)
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
  'EXCLUDED_AND_LOCKED_UNTIL_AFTER_SEQUENCE_17_LIVE_ACCEPTANCE')
assert.deepEqual(decision.exact_admission_parameter_url, {
  utf8: 'https://evidence.example:443/admission.cenc',
  utf8_hex: '68747470733a2f2f65766964656e63652e6578616d706c653a3434332f61646d697373696f6e2e63656e63',
  semantics: 'EVIDENCE_MIRROR_HINT_ONLY',
  browser_fetch: 'FORBIDDEN',
  dns_resolution: 'FORBIDDEN',
  url_parsing_or_normalization: 'FORBIDDEN',
  csp_change: 'FORBIDDEN',
  comparison: 'EXACT_SIGNED_UTF8_BYTES'
})
assert.equal(decision.fixed_cell_get_authority.hiverelay_commit,
  'c284435c1d075423a8d1bfcea04c3e171c6757ca')
assert.equal(decision.authority.baseline_commit,
  '0cd7b400d073d77b8b78938228c1c6c1b0106077')
assert.match(decision.decision, /zero network PUTs/)
assert.match(decision.decision, /MUST NOT be fetched, resolved, or added to CSP/)
assert.ok(decision.followups.includes('GA product gate remains honestly blocked'))

console.log('peerit seq17 corrective decision: exact URL bytes, no fetch/DNS/CSP, zero PUT, seq18 cold rollback and all-five exclusion ok')
