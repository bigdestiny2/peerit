import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import {
  assertPeeritBlindProductReleaseReady,
  PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS,
  PEERIT_BLIND_PRODUCT_RELEASE_STATUS,
  PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS,
  PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS,
  PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS
} from '../js/substrate/product-release-status.mjs'
import { PEERIT_PROFILE_STATUS } from '../js/substrate/profile-status.mjs'

const requiredBlockers = [
  'PROFILE_SEMANTIC_GRAPH_VALIDATION_INCOMPLETE',
  'EXACT_HIVERELAY_EXECUTABLE_DECODER_AUTHORITY_UNAVAILABLE',
  'PROFILE_REPLICA_DURABILITY_PROOF_RUNTIME_INCOMPLETE',
  'PROFILE_DISCOVERY_RADIX_PROPOSAL_REPLAY_RUNTIME_INCOMPLETE',
  'PROFILE_FIXED_SUPPORTING_EVIDENCE_AUTHORITY_UNAVAILABLE',
  'PROFILE_LEGACY_RECORD_RESTORE_EVIDENCE_AUTHORITY_INCOMPLETE',
  'PRODUCTION_HIVERELAY_PRODUCT_TUPLE_UNPINNED',
  'PRODUCTION_PEERIT_RELEASE_AUTHORITY_UNPINNED',
  'SIGNED_PEERIT_PROFILE_PIN_UNAVAILABLE',
  'AUTHENTICATED_BLIND_CLIENT_BROWSER_ARTIFACT_UNAVAILABLE',
  'AUTHENTICATED_PEERIT_RELAY_RUNTIME_AUTHORITY_UNAVAILABLE',
  'AUTHENTICATED_PROFILE_EXTERNAL_CODEC_DECODERS_UNASSEMBLED',
  'FIRST_VISIT_EXECUTING_VERIFIER_ORIGIN_BOOTSTRAP_UNRESOLVED',
  'SIGNED_CANONICAL_RELEASE_SERVICE_WORKER_CAS_UNIMPLEMENTED',
  'HIVERELAY_PRODUCTION_DAEMON_RUNTIME_INCOMPLETE',
  'HIVERELAY_PRODUCTION_STORE_INCOMPLETE',
  'PEERIT_BROWSER_RUNTIME_CONSUMER_UNASSEMBLED',
  'PORTABLE_PIN_HISTORY_ROLLBACK_RECOVERY_UNIMPLEMENTED',
  'POST_EVICTION_PIN_HISTORY_RECOVERY_UNIMPLEMENTED'
]

assert.equal(PEERIT_BLIND_PRODUCT_RELEASE_STATUS.profileSlice, PEERIT_PROFILE_STATUS)
assert.equal(PEERIT_BLIND_PRODUCT_RELEASE_STATUS.releaseReady, false)
assert.equal(PEERIT_BLIND_PRODUCT_RELEASE_STATUS.contextualGraphValidatorReady, false)
assert.equal(PEERIT_PROFILE_STATUS.webAssetContentFetchValidationReady, true)
assert.equal(PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS.includes(
  'PROFILE_WEB_ASSET_CONTENT_FETCH_VALIDATION_INCOMPLETE'), false)
assert.equal(PEERIT_BLIND_PRODUCT_RELEASE_STATUS.portablePinRollbackRecoveryReady, false)
assert.equal(PEERIT_BLIND_PRODUCT_RELEASE_STATUS.postEvictionPinContinuityRecoveryReady, false)
assert.equal(PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS.includes(
  'SIGNED_PIN_WITNESS_FLOOR_PERSISTENCE_UNIMPLEMENTED'), false)
for (const blocker of requiredBlockers) {
  assert.ok(PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS.includes(blocker), `${blocker} stays explicit`)
}

assert.equal(PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.emitSubstrateTuple, null)
assert.equal(PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.releaseAuthorityPublicKey, null)
assert.equal(PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.releaseReady, false)
assert.equal(PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.allFiveFamiliesExecutable, false)
assert.equal(PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.daemonProductionRuntimeReady, false)
assert.equal(PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.storeRecoveryAndRuntimeReady, false)
assert.equal(PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.authenticatedBlindClientArtifact, false)
assert.equal(PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.substrateUiAndLocalAuthoringRuntimeReady, true)
assert.equal(PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.signedCanonicalReleaseServiceWorkerCasReady, false)
assert.equal(PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.relayConsumerComposed, false)

assert.throws(() => assertPeeritBlindProductReleaseReady(), error => {
  assert.equal(error.code, 'PEERIT_BLIND_PRODUCT_CONFIG_INVALID')
  return true
})
assert.throws(() => assertPeeritBlindProductReleaseReady({
  substrateProfile: 'blind-v1',
  pinnedReleaseKey: 'ab'.repeat(32)
}), error => {
  assert.equal(error.code, 'PEERIT_BLIND_PRODUCT_INCOMPLETE')
  assert.deepEqual(error.releaseBlockers, PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS)
  return true
})

const report = join(mkdtempSync(join(tmpdir(), 'peerit-product-gate-')), 'web-release.json')
const child = spawnSync(process.execPath, [
  'scripts/web-release.mjs',
  '--verify-only',
  '--strict',
  '--drive-key',
  'cd'.repeat(32),
  '--report',
  report
], { encoding: 'utf8' })
assert.equal(child.status, 1, `${child.stdout}\n${child.stderr}`)
const result = JSON.parse(readFileSync(report, 'utf8'))
assert.equal(result.status, 'blocked')
const productCheck = result.checks.find(check => check.id === 'web-release:error')
assert.match(productCheck.message, /blind product is not release-ready/)
assert.deepEqual(productCheck.evidence.releaseBlockers, PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS)
assert.equal(productCheck.evidence.profileOnlyGateAccepted, false)
assert.equal(result.checks.some(check => /manifest|signature/.test(check.message)), false,
  'composed product gate runs before web artifact/signature verification')

console.log('peerit-product-release-gate: profile-only readiness cannot publish the incomplete Peerit/HiveRelay product')
