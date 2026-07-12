import assert from 'node:assert/strict'
import fs from 'node:fs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import { scanProfileDeclarations, verifyProfileInventory } from '../js/substrate/profile-inventory-scan.mjs'
import {
  AVAILABILITY_POLICY_STATUS,
  assertPeeritProfileReleaseReady,
  PEERIT_PROFILE_STATUS,
  PROFILE_RELEASE_BLOCKERS,
  SIGNED_PIN_CONTINUITY_STATUS
} from '../js/substrate/profile-status.mjs'

const profile = fs.readFileSync(new URL('../docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md', import.meta.url), 'utf8')
const deliveryMap = fs.readFileSync(new URL('../docs/PEERIT-BLIND-SUBSTRATE-DELIVERY-MAP.md', import.meta.url), 'utf8')
let passed = 0

function test (name, operation) {
  operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

function problemCodes (result) {
  return result.problems.map(entry => entry.code)
}

function declarationSource (source, name) {
  const declaration = scanProfileDeclarations(source).declarations.find(entry => entry.name === name)
  assert.ok(declaration)
  return source.split('\n').slice(declaration.startLine - 1, declaration.endLine).join('\n')
}

function removeDeclaration (source, name) {
  const declaration = scanProfileDeclarations(source).declarations.find(entry => entry.name === name)
  assert.ok(declaration)
  const lines = source.split('\n')
  lines.splice(declaration.startLine - 1, declaration.endLine - declaration.startLine + 1)
  return lines.join('\n')
}

function duplicateDeclaration (source, name) {
  const declaration = scanProfileDeclarations(source).declarations.find(entry => entry.name === name)
  assert.ok(declaration)
  const lines = source.split('\n')
  const declarationLines = lines.slice(declaration.startLine - 1, declaration.endLine)
  lines.splice(declaration.endLine, 0, ...declarationLines)
  return lines.join('\n')
}

test('canonical profile exactly matches the frozen mechanical inventory', () => {
  const result = verifyProfileInventory(profile, PEERIT_PROFILE_INVENTORY)
  assert.equal(result.ok, true)
  assert.deepEqual(result.problems, [])
  assert.equal(result.declarationCount, 77)
  assert.equal(result.recordCount, 72)
  assert.equal(result.taggedUnionCount, 5)
  assert.equal(result.inlineShapeCount, 15)
  assert.equal(result.externalTypeCount, 12)
  assert.equal(result.externalCodecImportCount, 6)
  assert.equal(result.profileRegistryCount, 3)
  assert.deepEqual(result.categoryCounts, {
    'release-control': 5,
    custody: 5,
    'qualification-evidence': 8,
    'availability-bootstrap': 9,
    announcement: 1,
    'replica-authority': 8,
    'discovery-index': 9,
    'maintainer-discovery': 11,
    'manifest-authority': 1,
    'migration-archive': 16,
    'local-security': 3,
    'web-release': 1
  })
})

test('central write authority is absent and the four independent axes are frozen', () => {
  for (const forbidden of [
    'PeeritWritePhaseV1',
    'PeeritWritePhaseHeadV1',
    'PeeritWriteLeaseV1',
    'PeeritWritePhaseLatestV1',
    'ProducerPhaseBindingV1',
    'producerPhaseBinding',
    'writePhaseFeedId',
    'writePhaseLatestUrl',
    'writePhaseReleaseSequence',
    'pausedFromWritePhase',
    'WRITE_PAUSED',
    'CUTOFF_DRAIN'
  ]) {
    assert.equal(profile.includes(forbidden), false, forbidden)
    assert.equal(deliveryMap.includes(forbidden), false, forbidden)
  }

  assert.match(profile, /four independent state axes, never one global write switch/)
  assert.match(profile, /DRAFT_LOCAL -> IDENTITY_COMMITTED -> EVENT_PREPARED/)
  assert.match(profile, /With zero\nusable relay targets the state is `QUEUED_NO_RELAY`/)
  assert.match(profile, /compatible unregistered HiveRelay may store, return,/)
  assert.match(profile, /Failure or staleness of every bootstrap source degrades\ndiscovery only/)
  assert.match(profile, /migrationStage:\s+PeeritMigrationStageV1/)
  assert.deepEqual(PEERIT_PROFILE_INVENTORY.profileRegistries.map(entry => entry.name), [
    'PeeritMigrationStageV1',
    'LegacyMissingReasonCodeV1',
    'LegacyValidatorReasonCodeV1'
  ])

  const scan = scanProfileDeclarations(profile)
  const pin = scan.declarations.find(entry => entry.name === 'PeeritHiveRelayProfilePinV1')
  const authorBind = scan.declarations.find(entry => entry.name === 'AuthorBindV1')
  assert.ok(pin)
  assert.ok(authorBind)
  assert.equal(pin.referencedTypes.includes('PeeritMigrationStageV1'), true)
  assert.deepEqual(authorBind.referencedTypes, ['ReplicaBindingV1'])

  const bootstrap = declarationSource(profile, 'AvailabilityBootstrapV1')
  const operatorRegistry = declarationSource(profile, 'PeeritOperatorGroupRegistryV1')
  assert.match(bootstrap, /bootstrapSequence:\s+u64/)
  assert.match(bootstrap, /signature:\s+64 bytes/)
  assert.doesNotMatch(bootstrap, /releaseSequence|releaseAuthority|releaseSignature/)
  assert.match(operatorRegistry, /registryWitnessSignatures:/)
  assert.doesNotMatch(operatorRegistry, /releaseSignature/)
})

test('every V1 reference has exactly one Peerit, registry, or HiveRelay owner', () => {
  const scan = scanProfileDeclarations(profile)
  const owners = new Map()
  for (const entry of PEERIT_PROFILE_INVENTORY.schemas) owners.set(entry.name, entry.owner)
  for (const entry of PEERIT_PROFILE_INVENTORY.externalTypes) owners.set(entry.name, entry.owner)
  for (const entry of PEERIT_PROFILE_INVENTORY.profileRegistries) owners.set(entry.name, entry.owner)
  assert.equal(owners.size, 92)
  for (const name of scan.allReferencedTypes) assert.equal(owners.has(name), true, name)
  assert.equal(scan.allReferencedTypes.length, owners.size)
})

test('missing, duplicate, and extra profile declarations fail separately', () => {
  let result = verifyProfileInventory(removeDeclaration(profile, 'SubstrateTupleV1'), PEERIT_PROFILE_INVENTORY)
  assert.equal(problemCodes(result).includes('MISSING_PROFILE_DECLARATION'), true)

  result = verifyProfileInventory(duplicateDeclaration(profile, 'SubstrateTupleV1'), PEERIT_PROFILE_INVENTORY)
  assert.equal(problemCodes(result).includes('DUPLICATE_PROFILE_DECLARATION'), true)

  const declaration = scanProfileDeclarations(profile).declarations[0]
  const lines = profile.split('\n')
  lines.splice(declaration.endLine, 0, 'UnexpectedPeeritShapeV1 {', '  version: u8 = 1', '}')
  result = verifyProfileInventory(lines.join('\n'), PEERIT_PROFILE_INVENTORY)
  assert.equal(problemCodes(result).includes('EXTRA_PROFILE_DECLARATION'), true)
})

test('primitive field and dependency drift cannot hide behind an unchanged name', () => {
  const primitiveDrift = profile.replace('  specHash:       32 bytes', '  specHash:       31 bytes')
  let result = verifyProfileInventory(primitiveDrift, PEERIT_PROFILE_INVENTORY)
  assert.equal(problemCodes(result).includes('DECLARATION_SOURCE_DRIFT'), true)

  const dependencyDrift = profile.replace(
    '  emitSubstrate:              SubstrateTupleV1',
    '  emitSubstrate:              UnknownSubstrateTupleV1'
  )
  result = verifyProfileInventory(dependencyDrift, PEERIT_PROFILE_INVENTORY)
  assert.equal(problemCodes(result).includes('DECLARATION_DEPENDENCY_DRIFT'), true)
  assert.equal(problemCodes(result).includes('UNCLASSIFIED_PROFILE_TYPE_REFERENCE'), true)
})

test('all nested anonymous records are content-addressed and counted', () => {
  const changedShape = profile.replace('supportingEvidenceHash: 32 bytes,', 'supportingEvidenceDigest: 32 bytes,')
  let result = verifyProfileInventory(changedShape, PEERIT_PROFILE_INVENTORY)
  assert.equal(problemCodes(result).includes('INLINE_SHAPE_DRIFT'), true)

  const addedShape = profile.replace(
    'AvailabilityRootV1 {\n  version:              u8 = 1',
    'AvailabilityRootV1 {\n  version:              u8 = 1\n  unexpectedInline:     { value: u8 }'
  )
  result = verifyProfileInventory(addedShape, PEERIT_PROFILE_INVENTORY)
  assert.equal(result.inlineShapeCount, 16)
  assert.equal(problemCodes(result).includes('INLINE_SHAPE_DRIFT'), true)
})

test('wrong schema owner and category assignments fail closed', () => {
  const wrongOwner = structuredClone(PEERIT_PROFILE_INVENTORY)
  wrongOwner.schemas[0].owner = 'hiverelay-substrate'
  let result = verifyProfileInventory(profile, wrongOwner)
  assert.equal(problemCodes(result).includes('WRONG_SCHEMA_OWNER'), true)

  const wrongCategory = structuredClone(PEERIT_PROFILE_INVENTORY)
  wrongCategory.schemas[0].category = 'custody'
  result = verifyProfileInventory(profile, wrongCategory)
  assert.equal(problemCodes(result).includes('CATEGORY_COUNT_DRIFT'), true)
})

test('missing, extra, duplicate, or wrong-owner external declarations fail', () => {
  const missing = structuredClone(PEERIT_PROFILE_INVENTORY)
  missing.externalTypes.shift()
  let result = verifyProfileInventory(profile, missing)
  assert.equal(problemCodes(result).includes('UNCLASSIFIED_PROFILE_TYPE_REFERENCE'), true)

  const extra = structuredClone(PEERIT_PROFILE_INVENTORY)
  extra.externalTypes.push({ name: 'UnusedHiveRelayTypeV1', owner: 'hiverelay-substrate', family: 'CELL' })
  result = verifyProfileInventory(profile, extra)
  assert.equal(problemCodes(result).includes('EXTRA_EXTERNAL_TYPE'), true)

  const duplicate = structuredClone(PEERIT_PROFILE_INVENTORY)
  duplicate.externalTypes.push({ ...duplicate.externalTypes[0] })
  result = verifyProfileInventory(profile, duplicate)
  assert.equal(problemCodes(result).includes('DUPLICATE_EXTERNAL_TYPE'), true)

  const wrongOwner = structuredClone(PEERIT_PROFILE_INVENTORY)
  wrongOwner.externalTypes[0].owner = 'peerit-profile'
  result = verifyProfileInventory(profile, wrongOwner)
  assert.equal(problemCodes(result).includes('WRONG_EXTERNAL_OWNER'), true)
})

test('field-level HiveRelay imports are exact and never expose internal StoreManifest state', () => {
  assert.deepEqual(PEERIT_PROFILE_INVENTORY.externalCodecImports.map(entry => entry.name), [
    'BlindCoreAckV1',
    'BlindCoreReadCapV1',
    'BlindReceiptV1',
    'InboxAppendAckV1',
    'InboxReceiptV1',
    'ReadCellCapV1'
  ])
  assert.equal(PEERIT_PROFILE_INVENTORY.externalCodecImports.some(entry => entry.name === 'BlindStoreManifestV1'), false)

  const missing = structuredClone(PEERIT_PROFILE_INVENTORY)
  missing.externalCodecImports.pop()
  let result = verifyProfileInventory(profile, missing)
  assert.equal(problemCodes(result).includes('MISSING_EXTERNAL_CODEC_IMPORT'), true)

  const internal = structuredClone(PEERIT_PROFILE_INVENTORY)
  internal.externalCodecImports.push({
    name: 'BlindStoreManifestV1',
    family: 'DURABILITY',
    authorityKind: 'CLIENT_COMPOSITION_V1',
    tupleBinding: null,
    clientSchemaCommitment: null,
    minimumBytes: 1,
    maximumBytes: 4096
  })
  result = verifyProfileInventory(profile, internal)
  assert.equal(problemCodes(result).includes('EXTRA_EXTERNAL_CODEC_IMPORT'), true)
})

test('duplicate inventory rows and declaration-kind substitution fail', () => {
  const duplicate = structuredClone(PEERIT_PROFILE_INVENTORY)
  duplicate.schemas.push(structuredClone(duplicate.schemas[0]))
  let result = verifyProfileInventory(profile, duplicate)
  assert.equal(problemCodes(result).includes('DUPLICATE_INVENTORY_DECLARATION'), true)

  const wrongKind = structuredClone(PEERIT_PROFILE_INVENTORY)
  wrongKind.schemas.find(entry => entry.name === 'ReplicaBindingV1').kind = 'record'
  result = verifyProfileInventory(profile, wrongKind)
  assert.equal(problemCodes(result).includes('WRONG_DECLARATION_KIND'), true)
})

test('canonical profile and local publication slices clear only proven blockers and remain non-release-ready', () => {
  assert.equal(PEERIT_PROFILE_STATUS.inventoryReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileRegistryReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileVectorManifestReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.fixtureOnly, false)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.schemaCount, 77)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.vectorCount, 77)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.codecLayoutIrComplete, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.boundedStructuralIrReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.semanticValidationComplete, false)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.externalHiveRelayCodecImportCount, 6)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.externalWireTupleImportCount, 4)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.clientCompositionImportCount, 2)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.pendingClientExampleImportCount, 0)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.externalCodecAuthorityComplete, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.recordCodecsReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.crossRuntimeEqualityReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.validatorArtifactReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.validatorVectorManifestReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.validatorArtifact.vectorCount, 234)
  assert.equal(PEERIT_PROFILE_STATUS.validatorArtifact.crossRuntimeEqualityReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.profileArtifact.releaseReady, false)
  assert.equal(PEERIT_PROFILE_STATUS.availabilityPolicyReady, true)
  assert.equal(AVAILABILITY_POLICY_STATUS.fieldCount, 64)
  assert.equal(AVAILABILITY_POLICY_STATUS.byteLength, 97)
  assert.equal(AVAILABILITY_POLICY_STATUS.releaseReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.offlineAuthoringStateMachineReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.publicationQueueStateMachineReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.releaseControlSlice.deterministicRegistryReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.releaseControlSlice.staticExpectedPinVerifierReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.releaseControlSlice.authorityTransitionVerifierReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.releaseControlSlice.unknownNewerPinContinuityReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.releaseControlSlice.fixtureOnly, true)
  assert.equal(PEERIT_PROFILE_STATUS.releaseControlSlice.fullProfileAbi, false)
  assert.equal(PEERIT_PROFILE_STATUS.releaseControlSlice.releaseReady, false)
  assert.equal(PEERIT_PROFILE_STATUS.signedPinVerifierReady, true)
  assert.equal(PEERIT_PROFILE_STATUS.signedPinContinuity, SIGNED_PIN_CONTINUITY_STATUS)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.exactBrandedAnchorRequired, true)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.contiguousUnknownNewerPinsAccepted, true)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.witnessedForkRejectionReady, true)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.dualSignedAuthorityRotationReady, true)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.witnessedFloorPersistenceReady, true)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.brandedTerminalSnapshotReady, true)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.productionTuplePinned, false)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.productionAuthorityPinned, false)
  assert.equal(SIGNED_PIN_CONTINUITY_STATUS.releaseReady, false)
  assert.equal(PEERIT_PROFILE_STATUS.releaseReady, false)
  assert.deepEqual(PEERIT_PROFILE_STATUS.releaseBlockers, PROFILE_RELEASE_BLOCKERS)
  assert.deepEqual(PROFILE_RELEASE_BLOCKERS, [
    'PROFILE_SEMANTIC_GRAPH_VALIDATION_INCOMPLETE',
    'EXACT_HIVERELAY_EXECUTABLE_DECODER_AUTHORITY_UNAVAILABLE',
    'PROFILE_REPLICA_DURABILITY_PROOF_RUNTIME_INCOMPLETE',
    'PROFILE_DISCOVERY_RADIX_PROPOSAL_REPLAY_RUNTIME_INCOMPLETE',
    'PROFILE_FIXED_SUPPORTING_EVIDENCE_AUTHORITY_UNAVAILABLE',
    'PROFILE_LEGACY_RECORD_RESTORE_EVIDENCE_AUTHORITY_INCOMPLETE',
    'PROFILE_WEB_ASSET_CONTENT_FETCH_VALIDATION_INCOMPLETE'
  ])
  assert.throws(() => assertPeeritProfileReleaseReady(), error => {
    assert.equal(error.code, 'PEERIT_PROFILE_INCOMPLETE')
    assert.deepEqual(error.releaseBlockers, PROFILE_RELEASE_BLOCKERS)
    return true
  })
})

process.stdout.write(`substrate profile inventory tests: ${passed}/${passed} passed\n`)
