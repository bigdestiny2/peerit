import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const decisionPath = new URL(
  '../deploy/canary-decision-peerit-seq19-csp-safe-live-recovery-20260729.json',
  import.meta.url)
const decisionBytes = readFileSync(decisionPath)
const decisionHash = createHash('sha256').update(decisionBytes).digest('hex')
const decision = JSON.parse(decisionBytes)
const releaseSource = readFileSync(new URL('../scripts/web-release.mjs', import.meta.url), 'utf8')

assert.equal(decisionHash, '1dfbb512cdd306dec903a407831cc3911c5844ded6e29c38d641bf700b4c1605')
assert.match(releaseSource, new RegExp(decisionHash))
assert.match(releaseSource,
  /canary-decision-peerit-seq19-csp-safe-live-recovery-20260729\.json/)
assert.equal(decision.schema_version, 5)
assert.equal(decision.decision_id,
  'peerit-seq19-csp-safe-two-relay-live-recovery-20260729')
assert.equal(decision.status, 'DECIDED')
assert.match(decision.decision, /release sequence 19/)
assert.match(decision.decision, /unchanged/)
assert.match(decision.decision, /zero network PUTs/)

const authority = decision.authority
assert.equal(authority.baseline_commit,
  '9f4cb0d600d5df6ed927b9220ea713dab9a1e49b')
assert.equal(authority.baseline_tree,
  '0268f2a59a51db0a7ada73679f2451e5bc6718a2')
assert.equal(authority.baseline_release_sequence, 18)
assert.equal(authority.failed_sequence_17_deploy_id, 'dep-d9l6u1b7uimc738lsik0')
assert.equal(authority.containment_sequence_18_deploy_id, 'dep-d9l6vn2jobas738ogetg')
assert.equal(authority.incident_evidence_sha256,
  '4259c947ba1d1ebf9d9bcd323a015c2a01df051fb2d2c085f42df1e53e879d0e')
assert.equal(authority.incident_handoff_sha256,
  '2661648ba7179f43fc8ee71ac9e5b53d611ceaf802c5bac70ab79016516231d0')
assert.equal(authority.root_cause_diagnostic_sha256,
  'cd65c0c3080e5b64ad5a79b70b7f8506409c4b49825c8e0dbbaabb6e8ff07eb4')
assert.equal(authority.maintenance_run_id,
  'peerit-seq19-csp-safe-live-recovery-20260729t220328z')
assert.equal(authority.context_lock_digest,
  '63cf32c6f6a16b954a793fc87877212f1d2ad8db114d9910507f6033dd059890')
assert.equal(authority.source_acceptance_sha256,
  '0326f1efac7cec332875c6ecf5e1fce78edcd2bfec954fb4b903fb8b72677824')

const activation = decision.activation
assert.equal(activation.functional_release_sequence, 19)
assert.equal(activation.rollback_release_sequence, 20)
assert.equal(activation.rollback_posture,
  'COLD_FAIL_CLOSED_BEFORE_RELAY_IO_AT_SEQUENCE_20')
assert.equal(activation.limited_cell_get_authority_release_sequence, 19)
assert.equal(activation.rollback_limited_cell_get_runtime_authority_exposed, false)
assert.equal(activation.rollback_generic_limited_get_assets,
  'PRESENT_BUT_INERT_AND_EXCLUDED_FROM_RUNTIME_AUTHORITY')
assert.equal(activation.claim_boundary, 'LIVE_PUBLIC_TEST_ONLY')
assert.deepEqual(activation.relays, ['dal-1', 'syd-1'])
assert.deepEqual(activation.allowed_browser_operations,
  ['DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET'])
assert.equal(activation.network_puts_during_recovery, 0)
assert.equal(activation.ordinary_delivery, 'LOCAL_ONLY')
assert.equal(activation.seed_record_count, 4)
assert.equal(activation.historical_seed_put_count, 8)
assert.equal(activation.post_cids.length, 3)
assert.equal(activation.all_five_successor,
  'EXCLUDED_AND_LOCKED_UNTIL_AFTER_SEQUENCE_19_LIVE_ACCEPTANCE')

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

const csp = decision.production_csp
assert.equal(csp.policy_file_sha256,
  'dc97c87d08bb773712cc739c37ffd4c62c121f7c92c01b20b3a8bf4a14f95724')
assert.equal(csp.script_src, "'self'")
assert.equal(csp.unsafe_eval, 'FORBIDDEN')
assert.equal(csp.wasm_unsafe_eval, 'FORBIDDEN')
assert.equal(csp.expansion, 'FORBIDDEN')
assert.equal(decision.root_cause.classification, 'VALIDATOR_WASM_BLOCKED_BY_RELEASE_CSP')
assert.match(decision.root_cause.exact_exception, /WebAssembly\.Module\(\)/)
assert.match(decision.root_cause.exact_exception, /script-src 'self'/)

const validator = decision.csp_safe_validator_authority
assert.equal(validator.accepted_source_patch_sha256,
  '123c501f36e6368ddedca089f778abb6ac86047b2236b31af72751a7daf9ef36')
assert.equal(validator.accepted_source_file_closure_sha256,
  '350ab2db0feb497107cb262c900b3adc271bd5afe1efed6eb41e94d1401f73ba')
assert.equal(validator.normalized_metafile_input_closure_sha256,
  '49bba7fd634d4085d74d13b5716491ad66415d3fbf4d1028c60a9b6d7cf628da')
assert.equal(validator.normalized_metafile_input_count, 53)
assert.equal(validator.third_party_input_allowlist_count, 25)
assert.equal(validator.validator_artifact_sha256,
  'e69bf4554720c853e340f212eda4fe7760ae119594f5f136701a71c1b214a809')
assert.equal(validator.bundle_and_bare_byte_identical, true)

const gate = decision.production_runtime_gate
assert.equal(gate.script, 'scripts/browser-peerit-production-runtime-gate.mjs')
assert.equal(gate.full_authority_loader, 'loadPeeritBrowserRuntimeAuthorityV1')
assert.equal(gate.authority_active_before_relay_io, true)
assert.equal(gate.sequence_19.expected_network_gets, 5)
assert.equal(gate.sequence_19.expected_fallback_count, 1)
assert.equal(gate.sequence_19.expected_record_count, 4)
assert.equal(gate.sequence_19.expected_cell_bytes, 16384)
assert.equal(gate.sequence_19.expected_network_puts, 0)
assert.equal(gate.sequence_19.expected_parameter_url_requests, 0)
assert.deepEqual(gate.sequence_19['dal-1'], {
  origin: 'https://relay-dal.p2phiverelay.xyz',
  descriptor_head_sha256: '549fd1df9b5cdba8ca2d97ab842bbda6a4a1433d79a82e230d8807bbd97cfebe',
  injected_cell_get_failures: 1,
  successful_cell_gets: 3,
  verified_readback_evidence_count: 3
})
assert.deepEqual(gate.sequence_19['syd-1'], {
  origin: 'https://relay-syd.p2phiverelay.xyz',
  descriptor_head_sha256: 'a4cbfe23176862cf5dbfae962ad3b919063073c4a51abe20ef4ae06c05a32153',
  injected_cell_get_failures: 0,
  successful_cell_gets: 1,
  verified_readback_evidence_count: 1
})
assert.equal(gate.sequence_20.browser_runtime_authority_active, true)
assert.equal(gate.sequence_20.limited_cell_get_runtime_authority_exposed, false)
assert.equal(gate.sequence_20.expected_error_code,
  'PEERIT_LIMITED_CELL_GET_CONTROL_INVALID')
assert.equal(gate.sequence_20.expected_relay_requests, 0)

const relays = decision.relay_authority
assert.equal(relays['dal-1'].minimum_descriptor_sequence, 5)
assert.equal(relays['dal-1'].descriptor_head_sha256,
  gate.sequence_19['dal-1'].descriptor_head_sha256)
assert.equal(relays['syd-1'].minimum_descriptor_sequence, 8)
assert.equal(relays['syd-1'].descriptor_head_sha256,
  gate.sequence_19['syd-1'].descriptor_head_sha256)
assert.ok(decision.followups.includes('GA product gate remains honestly blocked'))

console.log('peerit seq19 CSP-safe decision: exact CSP, full authority, named two-relay GET evidence, seq20 pre-I/O rollback and all-five exclusion ok')
