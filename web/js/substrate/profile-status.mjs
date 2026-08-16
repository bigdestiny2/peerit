export const PROFILE_RELEASE_BLOCKERS = Object.freeze([
  'PROFILE_SEMANTIC_GRAPH_VALIDATION_INCOMPLETE',
  'EXACT_HIVERELAY_EXECUTABLE_DECODER_AUTHORITY_UNAVAILABLE',
  'PROFILE_REPLICA_DURABILITY_PROOF_RUNTIME_INCOMPLETE',
  'PROFILE_DISCOVERY_RADIX_PROPOSAL_REPLAY_RUNTIME_INCOMPLETE',
  'PROFILE_FIXED_SUPPORTING_EVIDENCE_AUTHORITY_UNAVAILABLE',
  'PROFILE_LEGACY_RECORD_RESTORE_EVIDENCE_AUTHORITY_INCOMPLETE'
])

export const PROFILE_UNPUBLISHED_ARTIFACTS = Object.freeze({})

export const PROFILE_VALIDATOR_ARTIFACT_STATUS = Object.freeze({
  artifact: 'protocol/validator/peerit-validator-v1.bundle',
  bareImportMirror: 'protocol/validator/peerit-validator-v1.bare.mjs',
  vectorManifest: 'protocol/validator/peerit-validator-v1.manifest.cenc',
  artifactBytes: 795428,
  vectorCount: 238,
  validatorArtifactHash: '96ea7425eb1028748ee009486c1e72165f1cb7c80a37eb4ac0ffed748e18ac3d',
  validatorVectorSetHash: 'b0cfcbe4deebd25632edb53c570ca9b05a1e0544532af4091ca8c43249994f9b',
  runtimeVectorSetHash: '84d0cfd27a3b078ea839b2ec35ae9df7dd4ab619faa39dd8bef805f0c2b1c77c',
  deterministicBuildReady: true,
  strictCodecValidatorReady: true,
  localSemanticValidatorReady: true,
  embeddedEd25519VerifierReady: true,
  exactProductionCspExecutionReady: true,
  dynamicExecutionFree: true,
  contextualGraphAuditAuthorityReady: true,
  publicContextualGraphMinterAuditOnly: true,
  exactHashFetchBudgetsReady: true,
  predecessorForkCycleAuditReady: true,
  thresholdSignatureAuditReady: true,
  custodyReconstructionAuditReady: true,
  qualificationEvidenceGraphAuditReady: true,
  deterministicMigrationArchiveAuditReady: true,
  contextualWebAssetManifestGraphReady: true,
  contextualGraphRuntimeUnavailableSchemaCount: 41,
  signedValidatorBundleGraphAuthorityFactoryReady: false,
  browserContextualGraphHarnessComplete: false,
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
  profileSha256: '74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd',
  profileSpecHash: '931a85e29eb3767d8d2a1920d7e127cf20d708cce6975d967522fd07f475f473',
  profileAbiHash: '205d935d74bec6f80f8b6ee934c9f281f85a07e1efd25d9977f111c34fb0ded6',
  profileVectorSetHash: 'c5f679378d5b84de88cadffd89612044df59443663e292c308dde19fa4583155',
  inventoryCommitment: '68bf44c0933e01f6eb208c65a2de486e6b7aca371b51b7022797d4ab9fad0fcc',
  schemaCount: 78,
  vectorCount: 78,
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
  webAssetContentFetchValidationReady: true,
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
  schemaCount: 78,
  recordCount: 73,
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
  webAssetContentFetchValidationReady: true,
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
