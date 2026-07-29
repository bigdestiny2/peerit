import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const decisionPath = new URL('../deploy/canary-decision-peerit-seq13-three-post-activation-20260729t132650z.json', import.meta.url)
const decisionBytes = readFileSync(decisionPath)
const decisionHash = createHash('sha256').update(decisionBytes).digest('hex')
const decision = JSON.parse(decisionBytes)
const releaseSource = readFileSync(new URL('../scripts/web-release.mjs', import.meta.url), 'utf8')

assert.equal(decisionHash, '86130d0257105aecff2a40fee4656edabbffb531ac94854759138a13c06b59b0')
assert.match(releaseSource, new RegExp(decisionHash))
assert.match(releaseSource, /canary-decision-peerit-seq13-three-post-activation-20260729t132650z\.json/)
assert.equal(decision.schema_version, 2)
assert.equal(decision.status, 'DECIDED')
assert.equal(decision.activation.functional_release_sequence, 13)
assert.equal(decision.activation.rollback_release_sequence, 14)
assert.equal(decision.activation.claim_boundary, 'LIVE_PUBLIC_TEST_ONLY')
assert.deepEqual(decision.activation.relays, ['syd-1', 'dal-1'])
assert.equal(decision.activation.seed_record_count, 4)
assert.equal(decision.activation.seed_put_count, 8)
assert.deepEqual(decision.activation.post_cids, [
  'f68ae14dcd4fb0764b0c5669a03ebb7d68993b7cddc31f1552b85c2cba67536f',
  'fc80b076becb28c9fbda596def255246cd506fc5ed4e5f4d22499c5cdad95f1b',
  '52f99d16c0ab47bdad025cbd4138549802e552d55835435588887e7ca178e3a6'
])
assert.equal(decision.activation.all_five_successor, 'EXCLUDED_UNTIL_AFTER_PEERIT_SITE_ACTIVATION')
assert.match(decision.decision, /WIRE_TUPLE_DRIFT remains disclosed/)
assert.ok(decision.followups.includes('GA product gate remains honestly blocked'))

console.log('peerit seq13 canary decision: byte-pinned exact two-relay/three-post scope with seq14 rollback and all-five exclusion ok')
