export const PROFILE_RELEASE_BLOCKERS = Object.freeze([
  'PROFILE_SEMANTIC_GRAPH_VALIDATION_INCOMPLETE',
  'EXACT_HIVERELAY_EXECUTABLE_DECODER_AUTHORITY_UNAVAILABLE',
  'PROFILE_REPLICA_DURABILITY_PROOF_RUNTIME_INCOMPLETE',
  'PROFILE_DISCOVERY_RADIX_PROPOSAL_REPLAY_RUNTIME_INCOMPLETE',
  'PROFILE_FIXED_SUPPORTING_EVIDENCE_AUTHORITY_UNAVAILABLE',
  'PROFILE_LEGACY_RECORD_RESTORE_EVIDENCE_AUTHORITY_INCOMPLETE',
  'PROFILE_WEB_ASSET_CONTENT_FETCH_VALIDATION_INCOMPLETE'
])

export const PROFILE_UNPUBLISHED_ARTIFACTS = Object.freeze({})

export const PROFILE_VALIDATOR_ARTIFACT_STATUS = Object.freeze({
  artifact: 'protocol/validator/peerit-validator-v1.bundle',
  bareImportMirror: 'protocol/validator/peerit-validator-v1.bare.mjs',
  vectorManifest: 'protocol/validator/peerit-validator-v1.manifest.cenc',
  artifactBytes: 863380,
  vectorCount: 234,
  validatorArtifactHash: '03a7226b916b02b738f80664bdec60d80dee183ab548c586eafcb340d3b2c779',
  validatorVectorSetHash: 'fba49f2e7e152b99f53e7b676f0a5603d863230a699fd73bbcb6bf2624e94e92',
  runtimeVectorSetHash: 'cd733144df6984a27411f849099836c889eac3b4b2119bf43f6cb07dbb2be3fb',
  deterministicBuildReady: true,
  strictCodecValidatorReady: true,
  localSemanticValidatorReady: true,
  embeddedEd25519VerifierReady: true,
  contextualGraphAuditAuthorityReady: true,
  publicContextualGraphMinterAuditOnly: true,
  exactHashFetchBudgetsReady: true,
  predecessorForkCycleAuditReady: true,
  thresholdSignatureAuditReady: true,
  custodyReconstructionAuditReady: true,
  qualificationEvidenceGraphAuditReady: true,
  deterministicMigrationArchiveAuditReady: true,
  contextualGraphValidatorReady: false,
  crossRuntimeEqualityReady: true,
  releaseReady: false
})

export const AVAILABILITY_POLICY_STATUS = Object.freeze({
  artifact: 'protocol/availability-policy-v1.cenc',
  tag: 276,
  fieldCount: 64,
  byteLength: 97,
  availabilityPolicyHash: '268c0eb215b3e538dc7655abefd6c3cf9a20f92a6de7067e459f4914ca70f83c',
  exactProfileDeclarationBound: true,
  exhaustiveByteRejectionTested: true,
  releaseReady: true
})

export const PROFILE_ARTIFACT_STATUS = Object.freeze({
  artifactId: '@peerit/hiverelay-profile-registry-v1',
  profileId: '@peerit/hiverelay-profile-v1',
  sourcePath: 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md',
  registryArtifact: 'protocol/peerit-profile-v1.cenc',
  vectorManifest: 'protocol/vectors/peerit-profile-v1.manifest.cenc',
  formatVersion: 2,
  profileSha256: '989b1e4e337acb651252d61ae9dccc19036b52e1108b5ead11ec30dad11222ff',
  profileSpecHash: '48254388c3922fb4224973b9904b563b34267fe12888e223c66f27c0a15bf32c',
  profileAbiHash: '2eed87f00bcbcb801e66b72e45109910ea9c7faf04f45149b7959f96670e8891',
  profileVectorSetHash: 'fac3bd4d7833ee5fce38650736b3bf7d25ba2e66dd425a2571d6c5db5353ee71',
  inventoryCommitment: 'ac24b3753c17e9c0af0b9d31448370f897e3fde8a6bd3fbcdadebd0ed8354482',
  schemaCount: 77,
  vectorCount: 77,
  fixtureOnly: false,
  exactProfileSourceEmbedded: true,
  deterministicTagAllocationReady: true,
  deterministicRegistryReady: true,
  deterministicVectorsReady: true,
  codecLayoutIrComplete: true,
  boundedStructuralIrReady: true,
  semanticValidationComplete: false,
  externalHiveRelayCodecImportCount: 6,
  externalWireTupleImportCount: 4,
  clientCompositionImportCount: 2,
  pendingClientExampleImportCount: 0,
  externalCodecAuthorityComplete: true,
  recordCodecsReady: true,
  validatorReady: false,
  crossRuntimeEqualityReady: true,
  releaseReady: false
})

export const RELEASE_CONTROL_SLICE_STATUS = Object.freeze({
  artifactId: '@peerit/release-control-slice-v1',
  registryArtifact: 'protocol/peerit-release-control-v1.cenc',
  vectorManifest: 'protocol/vectors/peerit-release-control-v1.manifest.cenc',
  sliceArtifactHash: 'c27b5d2eeb38e2bb0fcdc97976f2b215b237094c4c1aee0673c0c4815e1b3d36',
  recordCodecCount: 4,
  closedEnumCount: 1,
  fixtureVectorCount: 11,
  fixtureOnly: true,
  sliceLocalFraming: true,
  deterministicRegistryReady: true,
  deterministicVectorsReady: true,
  staticExpectedPinVerifierReady: true,
  authorityTransitionVerifierReady: true,
  unknownNewerPinContinuityReady: true,
  productionTuplePinned: false,
  productionAuthorityPinned: false,
  crossRuntimeEqualityReady: false,
  fullProfileAbi: false,
  releaseReady: false
})

export const SIGNED_PIN_CONTINUITY_STATUS = Object.freeze({
  transitionRecord: 'PeeritReleaseAuthorityTransitionV1',
  transitionTag: 261,
  transitionCodec: 'js/substrate/release-authority-transition.mjs',
  continuityVerifier: 'js/substrate/release-control-verifier.mjs',
  exactBrandedAnchorRequired: true,
  contiguousUnknownNewerPinsAccepted: true,
  witnessedForkRejectionReady: true,
  dualSignedAuthorityRotationReady: true,
  activationReleaseBound: true,
  brandedTerminalSnapshotReady: true,
  witnessedFloorPersistenceReady: true,
  productionTuplePinned: false,
  productionAuthorityPinned: false,
  verifierReady: true,
  releaseReady: false
})

export const PEERIT_PROFILE_STATUS = Object.freeze({
  profileId: '@peerit/hiverelay-profile-v1',
  increment: 'C_LOCAL_PUBLICATION_STATE_MACHINE',
  inventoryReady: true,
  schemaCount: 77,
  recordCount: 72,
  taggedUnionCount: 5,
  inlineShapeCount: 15,
  externalHiveRelayTypeCount: 12,
  externalHiveRelayCodecImportCount: 6,
  externalWireTupleImportCount: 4,
  clientCompositionImportCount: 2,
  pendingClientExampleImportCount: 0,
  externalCodecAuthorityComplete: true,
  profileRegistryCount: 3,
  profileArtifact: PROFILE_ARTIFACT_STATUS,
  profileRegistryReady: true,
  profileVectorManifestReady: true,
  profileHashesReady: true,
  validatorArtifact: PROFILE_VALIDATOR_ARTIFACT_STATUS,
  validatorArtifactReady: true,
  validatorVectorManifestReady: true,
  availabilityPolicy: AVAILABILITY_POLICY_STATUS,
  availabilityPolicyReady: true,
  releaseControlSlice: RELEASE_CONTROL_SLICE_STATUS,
  signedPinContinuity: SIGNED_PIN_CONTINUITY_STATUS,
  codecsReady: true,
  validatorReady: false,
  signedPinVerifierReady: true,
  witnessedFloorPersistenceReady: true,
  offlineAuthoringStateMachineReady: true,
  publicationQueueStateMachineReady: true,
  crossRuntimeEqualityReady: true,
  releaseReady: false,
  releaseBlockers: PROFILE_RELEASE_BLOCKERS
})

export function assertPeeritProfileReleaseReady () {
  if (PEERIT_PROFILE_STATUS.releaseReady) return
  const error = new Error(`Peerit blind profile is not release-ready; ${PROFILE_RELEASE_BLOCKERS.length} blockers remain`)
  error.code = 'PEERIT_PROFILE_INCOMPLETE'
  error.releaseBlockers = [...PROFILE_RELEASE_BLOCKERS]
  throw error
}
