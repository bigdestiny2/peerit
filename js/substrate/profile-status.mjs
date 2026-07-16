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
  artifactBytes: 869217,
  vectorCount: 238,
  validatorArtifactHash: 'db3e717a9ba6eade51f45eacc243a3936f9c1ff3dc9d442d12a87dff2bd5c122',
  validatorVectorSetHash: 'b0cfcbe4deebd25632edb53c570ca9b05a1e0544532af4091ca8c43249994f9b',
  runtimeVectorSetHash: '84d0cfd27a3b078ea839b2ec35ae9df7dd4ab619faa39dd8bef805f0c2b1c77c',
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
  profileSha256: 'efebb212cc4d5dfd8348bc8c7e35ee5369f4ae181daaf5b476e3c3fb781e8d74',
  profileSpecHash: '6778d221a5ec5da2b12783900e8990049dafff9147311e4f67ba52252bbaf1f9',
  profileAbiHash: '2c92db4cd66395c628d4dc6353768672adf1d73e460773fd4e992999f590b616',
  profileVectorSetHash: 'ac90a7e3fa34b01f0299bc2efa468853b496f744c7d2a9307335ee8bc24552d4',
  inventoryCommitment: '5950a41c16081312298132207b9868830c8b055ba95f17c0e12024f9bef396c8',
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
