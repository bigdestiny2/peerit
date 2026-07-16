import assert from 'node:assert/strict'
import {
  PERSISTENCE_FAULT_PROFILES,
  parseArgs,
  persistenceFaultContentChecksum,
  verifyPersistenceFaultEvidence
} from '../scripts/browser-peerit-persistence-fault.mjs'

assert.deepEqual(parseArgs([]), { profile: 'smoke', out: null, timeoutMs: null, help: false })
assert.equal(parseArgs(['--profile=full', '--out', '/tmp/report.json', '--timeout-ms', '120000']).profile, 'full')
assert.throws(() => parseArgs(['--profile', 'production']), /smoke or full/)
assert.throws(() => parseArgs(['--timeout-ms', '9999']), /10000\.\.900000/)
assert.throws(() => parseArgs(['--url', 'https://peerit.site']), /unknown argument/)
assert.equal(PERSISTENCE_FAULT_PROFILES.full.baselineIntents > PERSISTENCE_FAULT_PROFILES.smoke.baselineIntents, true)

const gateIds = [
  'OWNED_SOURCE_MODULES',
  'REAL_BROWSER_PROCESS_SIGKILL',
  'IDB_WRITE_OBSERVED_BEFORE_KILL',
  'COMMITTED_PREFIX_ATOMIC',
  'REOPEN_RECOUNT_AND_DIGEST',
  'CONTINUE_AFTER_CRASH',
  'CDP_QUOTA_OVERRIDE_OBSERVED',
  'INJECTED_QUOTA_ERROR_MAPPED',
  'INJECTED_QUOTA_TRANSACTION_ROLLED_BACK',
  'COMMITTED_ROWS_SURVIVE_INJECTED_QUOTA',
  'CONTINUE_AFTER_INJECTED_QUOTA'
]

function fixture (profile = 'full') {
  const body = {
    schema: 'peerit-browser-persistence-fault-v1',
    evidenceClass: 'MEASURED_LOCAL_CHROMIUM_PROCESS_CRASH_AND_INJECTED_QUOTA',
    operationShape: 'peerit-unsigned-structural-operation-records-v2',
    journalIntentShape: 'peerit-inner-operation-batch-v1-derived-journal-intent-v2',
    checksumAlgorithm: 'sha256-canonical-json-v1',
    authenticityProven: false,
    claimBoundary: 'Measured on one local Chromium build and two isolated local filesystem profiles; not Firefox, not WebKit, not mobile, not production, not real quota exhaustion, and not authenticity evidence.',
    profile,
    coverage: {
      browserEngine: 'chromium',
      realProcessSigkill: true,
      realIndexedDb: true,
      cdpQuotaOverrideObserved: true,
      injectedQuotaFault: true,
      realQuotaExhaustion: false,
      otherDesktopEngines: false,
      mobile: false,
      production: false
    },
    gates: gateIds.map(id => ({ id, passed: true })),
    localFaultGateReady: true,
    fullProfileGateReady: profile === 'full',
    releaseReady: false
  }
  return { ...body, contentChecksum: persistenceFaultContentChecksum(body) }
}

const full = fixture()
assert.equal(verifyPersistenceFaultEvidence(full).verified, true)

const smoke = fixture('smoke')
assert.equal(verifyPersistenceFaultEvidence(smoke).verified, true)
assert.equal(smoke.fullProfileGateReady, false, 'smoke evidence must never satisfy the full-profile gate')

const mutated = structuredClone(full)
mutated.gates[0].passed = false
assert.equal(verifyPersistenceFaultEvidence(mutated).verified, false)
assert.ok(verifyPersistenceFaultEvidence(mutated).blockers.includes('CHECKSUM_MISMATCH'))

const recomputedFailure = structuredClone(full)
recomputedFailure.gates[0].passed = false
recomputedFailure.localFaultGateReady = false
recomputedFailure.fullProfileGateReady = false
recomputedFailure.contentChecksum = persistenceFaultContentChecksum(recomputedFailure)
assert.equal(verifyPersistenceFaultEvidence(recomputedFailure).verified, true,
  'a content checksum detects mutation but does not authenticate or require a passing experiment')

const falseAuthenticity = fixture()
falseAuthenticity.authenticityProven = true
falseAuthenticity.contentChecksum = persistenceFaultContentChecksum(falseAuthenticity)
assert.ok(verifyPersistenceFaultEvidence(falseAuthenticity).blockers.includes('AUTHENTICITY_BOUNDARY_INVALID'))

const rawJsonShape = fixture()
rawJsonShape.journalIntentShape = 'raw-json-intent-v1'
rawJsonShape.contentChecksum = persistenceFaultContentChecksum(rawJsonShape)
assert.ok(verifyPersistenceFaultEvidence(rawJsonShape).blockers.includes('JOURNAL_INTENT_SHAPE_INVALID'))

console.log('browser-peerit-persistence-fault: CLI, checksum, claim boundary, and fail-closed gate checks passed')
