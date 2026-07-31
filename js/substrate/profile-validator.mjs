import sodium from 'sodium-javascript'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  domainLengthHash,
  isAllZero,
  u32Bytes,
  u64Bytes
} from './release-control-primitives.mjs'
import {
  createPeeritProfileCodecCatalogFromIr,
  encodePeeritProfileRecordPrefixFromIr
} from './profile-codec-ir.mjs'
import { assertPeeritContextualGraphAuthorityV1 } from './profile-contextual-graph-validator.mjs'
import { assertPeeritAuthorBindInnerEnvelopeV1 } from './author-bind-inner-envelope-policy.mjs'

const MAX_U64 = (1n << 64n) - 1n
const LEASE_EPOCH_MILLIS = 21600000n
const PROFILE_SIGNATURE_DOMAIN = Object.freeze({
  PeeritHiveRelayProfilePinV1: 'peerit.hiverelay.profile-pin.v1',
  PeeritPinHistoryCheckpointV1: 'peerit.pin-history-checkpoint.v1',
  PeeritMigrationTransitionEvidenceV1: 'peerit.migration-transition-evidence.v1',
  AvailabilityRootV1: 'peerit.hiverelay.root.v1',
  MaintainerIngressBindingV1: 'peerit.hiverelay.maintainer-ingress.v1',
  AvailabilityBootstrapV1: 'peerit.hiverelay.bootstrap.v1',
  PeeritAnnouncementV1: 'peerit.hiverelay.announcement.v1',
  AuthorBindV1: 'peerit.hiverelay.author-bind.v1',
  RepairAddV1: 'peerit.hiverelay.repair-add.v1',
  MaintainerObservationV1: 'peerit.hiverelay.maintainer-observation.v1',
  MaintainerObservationReceiptV1: 'peerit.hiverelay.maintainer-observation-receipt.v1',
  MaintainerObservationHeadV1: 'peerit.hiverelay.maintainer-observation-head.v1',
  DiscoveryProposalV1: 'peerit.hiverelay.discovery-proposal.v1',
  MigrationGenesisV1: 'peerit.hiverelay.migration-genesis.v1',
  LegacyCutoffV1: 'peerit.hiverelay.legacy-cutoff.v1',
  LegacyArchiveDistributionV1: 'peerit.hiverelay.legacy-archive-distribution.v1',
  LegacyRetirementEvidenceV1: 'peerit.legacy-retirement-evidence.v1',
  DeviceChainStartV1: 'peerit.hiverelay.device-chain-start.v1'
})

const SINGLE_SIGNATURE_KEY = Object.freeze({
  PeeritHiveRelayProfilePinV1: 'releaseAuthorityPublicKey',
  PeeritPinHistoryCheckpointV1: '$releaseAuthorityPublicKey',
  PeeritMigrationTransitionEvidenceV1: '$releaseAuthorityPublicKey',
  AvailabilityRootV1: 'rootVerifyKey',
  MaintainerIngressBindingV1: 'maintainerKey',
  AvailabilityBootstrapV1: 'rootVerifyKey',
  PeeritAnnouncementV1: 'publisherPublicKey',
  AuthorBindV1: 'authorPublicKey',
  RepairAddV1: 'repairerPublicKey',
  MaintainerObservationV1: 'maintainerKey',
  MaintainerObservationReceiptV1: 'maintainerKey',
  MaintainerObservationHeadV1: 'maintainerKey',
  DiscoveryProposalV1: 'proposerKey',
  MigrationGenesisV1: '$releaseAuthorityPublicKey',
  LegacyCutoffV1: '$releaseAuthorityPublicKey',
  LegacyArchiveDistributionV1: '$releaseAuthorityPublicKey',
  LegacyRetirementEvidenceV1: '$releaseAuthorityPublicKey',
  DeviceChainStartV1: 'accountPublicKey'
})

const SINGLE_SIGNATURE_FIELD = Object.freeze({
  LegacyArchiveDistributionV1: 'releaseSignature',
  MigrationGenesisV1: 'releaseSignature'
})

const REPLICA_ARRAY_FIELDS = new Set([
  'initialReplicas',
  'rootReplicas',
  'discoveryCheckpointReplicas',
  'discoverySnapshotReplicas',
  'nextRootReplicas',
  'legacyArchiveBundleReplicas',
  'originalRecordsReplicas',
  'logReplicas'
])

function failValidator (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details != null) error.details = details
  throw error
}

function normalizedOwner (owner) {
  return owner.replace(/\[\d+\]/g, '[]')
}

function fieldName (owner) {
  const normalized = normalizedOwner(owner)
  return normalized.slice(normalized.lastIndexOf('.') + 1).replace(/\[\]$/, '')
}

function strictIncreasing (values, projection, field) {
  let previous = null
  const seen = []
  for (let index = 0; index < values.length; index++) {
    const current = projection(values[index], index)
    if (previous != null && compareBytes(previous, current) >= 0) {
      failValidator('NONCANONICAL_PROFILE_SEMANTIC_ORDER', `${field} is not strictly ordered by its named projection`)
    }
    previous = current
    seen.push(current)
  }
  return seen
}

function distinctBytes (values, field) {
  const sorted = [...values].sort(compareBytes)
  for (let index = 1; index < sorted.length; index++) {
    if (bytesEqual(sorted[index - 1], sorted[index])) failValidator('DUPLICATE_PROFILE_VALUE', `${field} contains a duplicate`)
  }
}

function nonzero (value, field) {
  if (value == null || isAllZero(value)) failValidator('ZERO_PROFILE_VALUE', `${field} must be nonzero`)
}

function checkedAdd (...values) {
  let result = 0n
  for (const value of values) {
    result += BigInt(value)
    if (result > MAX_U64) failValidator('PROFILE_INTEGER_OVERFLOW', 'profile u64 arithmetic overflowed')
  }
  return result
}

function samePresence (...values) {
  return values.every(value => value == null) || values.every(value => value != null)
}

function replicaIdentityProjection (binding) {
  let variant
  let value
  if (binding && Number.isSafeInteger(binding.variant)) {
    variant = binding.variant
    value = binding.value
  } else if (binding && Object.prototype.hasOwnProperty.call(binding, 'cellBlobHash')) {
    variant = 1
    value = binding
  } else {
    variant = 2
    value = binding
  }
  let projection
  if (variant === 1) {
    projection = concatBytes(
      value.logicalHash,
      value.encodingCommitment,
      value.relayPublicKey,
      value.readCapability,
      value.cellBlobHash,
      Uint8Array.of(value.sizeClass),
      u32Bytes(value.allocationEpoch)
    )
  } else if (variant === 2) {
    projection = concatBytes(
      value.logicalHash,
      value.encodingCommitment,
      value.relayPublicKey,
      value.corePublicKey,
      u64Bytes(value.firstBlockIndex),
      u32Bytes(value.blockCount),
      value.coreSliceCommitment
    )
  } else {
    failValidator('BAD_REPLICA_BINDING', `unknown replica binding variant ${variant}`)
  }
  return blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.replica-id.v1'),
    Uint8Array.of(variant),
    u64Bytes(projection.byteLength),
    projection
  ))
}

export function peeritProfileNamedSortProjection (owner, type, value, encoded) {
  const normalized = normalizedOwner(owner)
  const field = fieldName(owner)
  if (REPLICA_ARRAY_FIELDS.has(field)) return replicaIdentityProjection(value)
  if (normalized.endsWith('AvailabilityBootstrapV1.inboxEpochSets')) {
    return u32Bytes(0xffffffff - value.inboxEpoch)
  }
  if (normalized.endsWith('LegacyArchiveDistributionV1.copies')) {
    return concatBytes(value.operatorGroupId, Uint8Array.of(value.copyKind), value.locator)
  }
  if (normalized.endsWith('WebAssetManifestV1.assets')) return value.path
  if (normalized.endsWith('PeeritWriteOperationEvidenceShardV1.entries')) return value.logicalIntentEvidenceId
  if (normalized.endsWith('PeeritWriteSupportingEvidenceManifestV1.artifacts')) {
    return concatBytes(value.supportingEvidenceHash, Uint8Array.of(value.evidenceKind))
  }
  if (normalized.endsWith('PeeritReleaseQualificationEvidenceBundleV1.runtimeEvidence')) return value.runtimeEvidenceKeyHash
  return encoded
}

function validateSingleSignature (compiled, inventory, externalAuthorityByName, schemaName, value, context) {
  const domain = PROFILE_SIGNATURE_DOMAIN[schemaName]
  if (domain == null) return
  const keyField = SINGLE_SIGNATURE_KEY[schemaName]
  let publicKey
  if (keyField.startsWith('$')) publicKey = context[keyField.slice(1)]
  else publicKey = value[keyField]
  if (publicKey == null) failValidator('PROFILE_CRYPTO_CONTEXT_REQUIRED', `${schemaName} requires ${keyField.slice(1)} in validator context`)
  nonzero(publicKey, `${schemaName} signature key`)
  const signatureField = SINGLE_SIGNATURE_FIELD[schemaName] || 'signature'
  const prefix = encodePeeritProfileRecordPrefixFromIr(compiled, inventory, schemaName, value, signatureField, {
    externalAuthorityByName,
    sortProjection: peeritProfileNamedSortProjection
  })
  const message = concatBytes(asciiBytes(domain), prefix)
  if (!sodium.crypto_sign_verify_detached(value[signatureField], message, publicKey)) {
    failValidator('INVALID_PROFILE_SIGNATURE', `${schemaName} signature is invalid`)
  }
}

function validateCommonSequencePredecessor (sequence, predecessor, field) {
  if ((sequence === 0n) !== (predecessor == null)) {
    failValidator('BAD_PROFILE_CAUSAL_LINK', `${field} sequence zero alone must omit its predecessor`)
  }
}

function validateRecordSemantics (schemaName, value, context) {
  switch (schemaName) {
    case 'PeeritHiveRelayProfilePinV1': {
      validateCommonSequencePredecessor(value.releaseSequence, value.previousPinHash, schemaName)
      const emit = context.catalog.SubstrateTupleV1.encode(value.emitSubstrate)
      if (value.readSubstrates.filter(tuple => bytesEqual(context.catalog.SubstrateTupleV1.encode(tuple), emit)).length !== 1) {
        failValidator('BAD_EMIT_SUBSTRATE', 'emitSubstrate must occur exactly once in readSubstrates')
      }
      if (value.legacyImportMode > 2 || value.legacyReadMode > 1 || value.migrationStage !== value.legacyImportMode) {
        failValidator('BAD_MIGRATION_STATE', 'profile pin migration stage/import/read mode is invalid')
      }
      if (!samePresence(value.legacyCutoffHash, value.migrationGenesisRecordId, value.cutoffActivationReleaseSequence) ||
          (value.legacyImportMode === 0) !== (value.legacyCutoffHash == null)) {
        failValidator('BAD_MIGRATION_STATE', 'cutoff fields must be jointly absent in mode zero and jointly present later')
      }
      if (value.legacyReadMode === 1 && (value.legacyImportMode !== 2 || value.legacyRetirementEvidenceHash == null || value.legacyRetirementActivationReleaseSequence == null)) {
        failValidator('BAD_MIGRATION_STATE', 'archive-only read mode requires archive import and retirement evidence')
      }
      const expectedKeyId = blake2b256(concatBytes(asciiBytes('peerit.release-authority-key-id.v1'), value.releaseAuthorityPublicKey))
      if (!bytesEqual(expectedKeyId, value.releaseAuthorityKeyId)) failValidator('BAD_RELEASE_KEY_ID', 'releaseAuthorityKeyId does not match its public key')
      break
    }
    case 'PeeritPinHistoryCheckpointV1':
      validateCommonSequencePredecessor(value.checkpointSequence, value.previousCheckpointHash, schemaName)
      if ((value.checkpointSequence === 0n) !== (value.previousPinHash == null)) failValidator('BAD_PROFILE_CAUSAL_LINK', 'checkpoint previous pin presence is invalid')
      break
    case 'PeeritPinHistoryBundleV1':
      if (value.checkpoints.length !== value.pins.length) failValidator('BAD_PIN_HISTORY_BUNDLE', 'checkpoint and pin counts must match')
      break
    case 'PeeritReleaseAuthorityTransitionV1':
      if (value.nextSequence !== value.previousSequence + 1n || value.validFromRelease === 0n ||
          bytesEqual(value.previousPublicKey, value.nextPublicKey)) {
        failValidator('BAD_AUTHORITY_TRANSITION', 'authority transition sequence, activation, or keys are invalid')
      }
      nonzero(value.previousPublicKey, 'previousPublicKey')
      nonzero(value.nextPublicKey, 'nextPublicKey')
      break
    case 'PeeritCustodySeedPayloadV1':
      nonzero(value.secretSeed, 'secretSeed')
      nonzero(value.derivedPublicKey, 'derivedPublicKey')
      break
    case 'PeeritInboxManagementBundleV1':
      if (![24, 48].includes(value.entries.length)) failValidator('BAD_INBOX_MANAGEMENT_BUNDLE', 'management bundle must have 24 or 48 entries')
      break
    case 'PeeritCustodyEncryptedShareV1':
      if (value.shareIndex < 1 || value.shareIndex > 3) failValidator('BAD_CUSTODY_SHARE', 'shareIndex must be 1, 2, or 3')
      for (const field of ['custodySetId', 'keyCommitment', 'sealedPayloadHash', 'custodianPublicKey', 'ephemeralPublicKey', 'nonce', 'sealedShare']) nonzero(value[field], field)
      break
    case 'PeeritCustodyEnvelopeV1': {
      if (value.plaintextLength < 1n || value.plaintextLength > 16777216n || BigInt(value.sealedPayload.byteLength) !== value.plaintextLength + 16n) {
        failValidator('BAD_CUSTODY_ENVELOPE', 'plaintext/sealed-payload lengths are inconsistent')
      }
      const indices = value.encryptedShares.map(share => share.shareIndex)
      if (indices.join(',') !== '1,2,3') failValidator('BAD_CUSTODY_ENVELOPE', 'custody shares must be ordered 1,2,3')
      for (const share of value.encryptedShares) {
        if (!bytesEqual(share.custodySetId, value.custodySetId) || share.bundleKind !== value.bundleKind ||
            !bytesEqual(share.keyCommitment, value.keyCommitment) ||
            !bytesEqual(share.sealedPayloadHash, domainLengthHash('peerit.hiverelay.custody-sealed-payload.v1', value.sealedPayload))) {
          failValidator('BAD_CUSTODY_ENVELOPE', 'custody share does not bind its envelope')
        }
      }
      distinctBytes(value.encryptedShares.map(share => share.custodianPublicKey), 'custodianPublicKey')
      distinctBytes(value.encryptedShares.map(share => share.ephemeralPublicKey), 'ephemeralPublicKey')
      distinctBytes(value.encryptedShares.map(share => share.nonce), 'share nonce')
      break
    }
    case 'PeeritMigrationTransitionEvidenceV1':
      if (value.windowStartedUnixMillis >= value.windowEndedUnixMillis || value.toMigrationStage !== value.fromMigrationStage + 1 ||
          value.targetLegacyImportMode !== value.toMigrationStage || value.targetLegacyReadMode > 1 ||
          checkedAdd(value.terminalSuccessfulWrites, value.terminalFailedWrites, value.pendingOrUnknownWrites) !== value.attemptedLogicalWrites) {
        failValidator('BAD_MIGRATION_EVIDENCE', 'migration transition window, edge, or counters are invalid')
      }
      break
    case 'PeeritWriteOperationEvidenceV1':
      nonzero(value.logicalIntentEvidenceId, 'logicalIntentEvidenceId')
      if (value.terminalClass > 2 || value.failureBits > 0x3f ||
          (value.terminalClass === 0) !== (value.terminalUnixMillis == null) ||
          (value.terminalUnixMillis != null && value.terminalUnixMillis < value.attemptedUnixMillis)) {
        failValidator('BAD_WRITE_OPERATION_EVIDENCE', 'terminal class/time or failure bits are invalid')
      }
      break
    case 'PeeritWriteOperationEvidenceShardV1':
      if (value.windowStartedUnixMillis >= value.windowEndedUnixMillis) failValidator('BAD_EVIDENCE_WINDOW', 'evidence window must be nonempty')
      strictIncreasing(value.entries, entry => entry.logicalIntentEvidenceId, 'operation evidence entries')
      for (const entry of value.entries) {
        if (entry.attemptedUnixMillis < value.windowStartedUnixMillis || entry.attemptedUnixMillis >= value.windowEndedUnixMillis ||
            (entry.terminalUnixMillis != null && entry.terminalUnixMillis > value.windowEndedUnixMillis)) {
          failValidator('BAD_EVIDENCE_WINDOW', 'operation evidence entry is outside its shard window')
        }
      }
      break
    case 'PeeritWriteOperationEvidenceManifestV1':
      if (value.windowStartedUnixMillis >= value.windowEndedUnixMillis) failValidator('BAD_EVIDENCE_WINDOW', 'evidence window must be nonempty')
      for (let index = 0; index < value.shards.length; index++) {
        const shard = value.shards[index]
        if (shard.entryCount === 0n || compareBytes(shard.firstLogicalIntentEvidenceId, shard.lastLogicalIntentEvidenceId) > 0 ||
            (index > 0 && compareBytes(value.shards[index - 1].lastLogicalIntentEvidenceId, shard.firstLogicalIntentEvidenceId) >= 0)) {
          failValidator('BAD_EVIDENCE_SHARD_RANGE', 'shard references must be nonempty, ordered, and disjoint')
        }
      }
      if (value.shards.reduce((sum, shard) => checkedAdd(sum, shard.entryCount), 0n) !== value.totalEntryCount) {
        failValidator('BAD_EVIDENCE_SHARD_COUNT', 'shard counts do not reproduce totalEntryCount')
      }
      break
    case 'PeeritWriteRuntimeEvidenceV1':
      if (value.runtimeClass < 1 || value.runtimeClass > 6 ||
          checkedAdd(value.terminalSuccessfulWrites, value.terminalFailedWrites, value.pendingOrUnknownWrites) !== value.attemptedLogicalWrites ||
          value.operationEvidenceCount !== value.attemptedLogicalWrites) {
        failValidator('BAD_RUNTIME_EVIDENCE', 'runtime class or counters are invalid')
      }
      if (!bytesEqual(value.runtimeEvidenceKeyHash, blake2b256(concatBytes(
        asciiBytes('peerit.write-runtime-evidence-key.v1'),
        Uint8Array.of(value.runtimeClass), value.runtimeVersionHash, value.platformConfigurationHash, value.captureEvidenceHash
      )))) failValidator('BAD_RUNTIME_EVIDENCE_KEY', 'runtimeEvidenceKeyHash does not match its projection')
      break
    case 'PeeritWriteSupportingEvidenceManifestV1':
      if (value.windowStartedUnixMillis >= value.windowEndedUnixMillis) failValidator('BAD_EVIDENCE_WINDOW', 'evidence window must be nonempty')
      for (const artifact of value.artifacts) if (artifact.evidenceKind < 1 || artifact.evidenceKind > 6) failValidator('BAD_SUPPORTING_EVIDENCE_KIND', 'supporting evidence kind is not closed')
      distinctBytes(value.artifacts.map(artifact => artifact.supportingEvidenceHash), 'supportingEvidenceHash')
      break
    case 'PeeritReleaseQualificationEvidenceBundleV1':
      if (value.measuredMigrationStage > 2 || value.windowStartedUnixMillis >= value.windowEndedUnixMillis ||
          value.operationEvidenceCount !== value.attemptedLogicalWrites ||
          checkedAdd(value.terminalSuccessfulWrites, value.terminalFailedWrites, value.pendingOrUnknownWrites) !== value.attemptedLogicalWrites) {
        failValidator('BAD_QUALIFICATION_EVIDENCE', 'qualification stage, window, or counters are invalid')
      }
      break
    case 'AvailabilityRootV1':
      distinctBytes(value.recoveryKeys, 'recoveryKeys')
      distinctBytes(value.discoveryMaintainerKeys, 'discoveryMaintainerKeys')
      nonzero(value.rootVerifyKey, 'rootVerifyKey')
      break
    case 'PeeritOperatorGroupRegistryV1':
      validateCommonSequencePredecessor(value.registrySequence, value.previousRegistryHash, schemaName)
      distinctBytes(value.witnesses.map(entry => entry.witnessGroupId), 'witnessGroupId')
      distinctBytes(value.witnesses.map(entry => entry.witnessKey), 'witnessKey')
      distinctBytes(value.groups.map(entry => entry.groupId), 'groupId')
      for (const witness of value.witnesses) if (witness.issuedLeaseEpoch > witness.expiresLeaseEpoch) failValidator('BAD_REGISTRY_LEASE', 'witness lease interval is inverted')
      for (const group of value.groups) {
        if (group.issuedLeaseEpoch > group.expiresLeaseEpoch) failValidator('BAD_REGISTRY_LEASE', 'group lease interval is inverted')
        for (const row of group.profile1StoreFailureDomains) {
          nonzero(row.storeId, 'profile1 storeId')
          nonzero(row.localFailureDomainId, 'localFailureDomainId')
          nonzero(row.chaosEvidenceHash, 'chaosEvidenceHash')
        }
      }
      break
    case 'AvailabilityBootstrapV1':
      validateCommonSequencePredecessor(value.bootstrapSequence, value.previousBootstrapHash, schemaName)
      if (!samePresence(value.legacyCutoffHash, value.migrationGenesisRecordId)) failValidator('BAD_BOOTSTRAP_MIGRATION', 'bootstrap migration fields must be jointly present or absent')
      if (value.inboxEpochSets.length === 2 && value.inboxEpochSets[1].inboxEpoch + 1 !== value.inboxEpochSets[0].inboxEpoch) {
        failValidator('BAD_INBOX_EPOCH_ORDER', 'bootstrap inbox epoch sets must be newest then exactly previous')
      }
      break
    case 'InboxEpochSetV1':
      if (value.bindings.some(binding => binding.inboxEpoch !== value.inboxEpoch) ||
          value.bindings.filter(binding => binding.stripeIndex > 7).length !== 0) {
        failValidator('BAD_INBOX_EPOCH_SET', 'inbox bindings do not equal their epoch or eight-stripe registry')
      }
      break
    case 'RootRotateV1': {
      if (value.nextGeneration !== value.previousGeneration + 1n) failValidator('BAD_ROOT_ROTATION', 'root generation must increment exactly once')
      const recovery = value.oldRootSignature == null
      if (recovery !== (value.recoverySignatures.length > 0) || value.nextRootReplicas.length !== 3) {
        failValidator('BAD_ROOT_ROTATION', 'normal/recovery signature mode or replica count is invalid')
      }
      if ((value.discoveryRecoveryMergeHash == null) !== (value.discoveryRecoveryMergeReadCaps.length === 0)) {
        failValidator('BAD_ROOT_ROTATION', 'recovery merge hash and caps presence disagree')
      }
      break
    }
    case 'PeeritAnnouncementV1':
      if (value.manifestMode === 1) {
        if (value.manifestRecord.byteLength < 1 || value.manifestReadCaps.length !== 0) failValidator('BAD_ANNOUNCEMENT_MODE', 'INLINE announcement payload/caps are invalid')
      } else if (value.manifestMode === 2) {
        if (value.manifestRecord.byteLength !== 0 || value.manifestReadCaps.length < 1) failValidator('BAD_ANNOUNCEMENT_MODE', 'CELL_REFERENCE announcement payload/caps are invalid')
      } else failValidator('BAD_ANNOUNCEMENT_MODE', 'announcement mode is not closed')
      break
    case 'AuthorBindV1':
      validateCommonSequencePredecessor(value.authorSequence, value.previousAuthorRecordId, schemaName)
      assertPeeritAuthorBindInnerEnvelopeV1(value)
      break
    case 'RepairAddV1':
      nonzero(value.repairNonce, 'repairNonce')
      if (value.hintExpiresLeaseEpoch < value.issuedLeaseEpoch || !bytesEqual(value.replica.value.logicalHash, value.logicalHash)) failValidator('BAD_REPAIR_HINT', 'repair hint expiry or logical hash is invalid')
      break
    case 'ChargedProbeEvidenceV1':
      if (value.probeKind < 1 || value.probeKind > 2) failValidator('BAD_PROBE_KIND', 'probe kind must be CELL_4K_PROVE or CORE_4K_PROVE')
      nonzero(value.storeId, 'storeId')
      break
    case 'RelayProbeEvidenceSetV1':
      validateCommonSequencePredecessor(value.setSequence, value.previousSetHash, schemaName)
      if (value.expiresLeaseEpoch < value.createdLeaseEpoch) failValidator('BAD_PROBE_SET_LEASE', 'probe evidence set lease is inverted')
      break
    case 'DiscoveryAvailabilityEntryV1':
      if (value.availabilityStatus > 2 || (value.availabilityRevision === 0n) !== (value.previousAvailabilityHash == null)) failValidator('BAD_AVAILABILITY_ENTRY', 'availability status or revision link is invalid')
      break
    case 'DiscoveryIndexBranchV1':
      if (value.indexKind < 1 || value.indexKind > 2 || value.depth + value.compressedPrefix.byteLength >= 32 ||
          value.subtreeCount !== value.children.reduce((sum, child) => checkedAdd(sum, child.subtreeCount), 0n)) {
        failValidator('BAD_DISCOVERY_INDEX_BRANCH', 'index kind/path/count is invalid')
      }
      strictIncreasing(value.children, child => Uint8Array.of(child.edgeByte), 'discovery branch children')
      break
    case 'DiscoveryIndexProofV1': {
      if (value.indexKind < 1 || value.indexKind > 2) failValidator('BAD_DISCOVERY_INDEX_PROOF', 'index kind is not closed')
      const total = value.nodes.reduce((sum, node) => sum + node.taggedNodeBytes.byteLength, 0)
      if (total !== value.totalNodeBytes || total > 16777216) failValidator('BAD_DISCOVERY_INDEX_PROOF', 'totalNodeBytes does not equal node bytes or exceeds 16 MiB')
      for (const node of value.nodes) if (!bytesEqual(node.nodeHash, context.hashDiscoveryIndexNode(node.taggedNodeBytes))) failValidator('BAD_DISCOVERY_INDEX_NODE_HASH', 'proof node hash does not match bytes')
      break
    }
    case 'MaintainerSubmitV1':
      nonzero(value.requestNonce, 'requestNonce')
      break
    case 'MaintainerSubmitResultV1':
      if (value.status < 1 || value.status > 3 ||
          (value.status === 1) !== (value.receipt != null) ||
          (value.status === 3) !== (value.retryAfterMillis > 0)) {
        failValidator('BAD_MAINTAINER_RESULT', 'maintainer result status/payload is invalid')
      }
      break
    case 'MaintainerObservationV1':
      validateCommonSequencePredecessor(value.observationSequence, value.previousObservationHash, schemaName)
      break
    case 'DiscoveryProposalV1':
      if (value.proposalSlot < 2n || value.observationCutoffUnixMillis !== (value.proposalSlot - 2n) * 60000n) failValidator('BAD_DISCOVERY_PROPOSAL_SLOT', 'proposal slot/cutoff relation is invalid')
      break
    case 'DiscoverySnapshotV1': {
      const initial = value.snapshotSequence === 0n
      if (initial !== (value.previousSnapshotHash == null) || initial !== (value.previousSnapshotReadCaps.length === 0) ||
          initial !== (value.previousFrontierRoot == null) || initial !== (value.previousAvailabilityRoot == null) ||
          value.createdLeaseEpoch !== Number(value.createdUnixMillis / LEASE_EPOCH_MILLIS) ||
          (value.addedCount === 0n) !== (value.addedRoot == null) ||
          (value.addedRoot == null) !== (value.addedRootReadCaps.length === 0)) {
        failValidator('BAD_DISCOVERY_SNAPSHOT', 'snapshot predecessor, lease, or addition fields are inconsistent')
      }
      break
    }
    case 'DiscoveryCheckpointV1':
      validateCommonSequencePredecessor(value.checkpointSequence, value.previousCheckpointHash, schemaName)
      if (value.createdLeaseEpoch !== Number(value.createdUnixMillis / LEASE_EPOCH_MILLIS)) failValidator('BAD_DISCOVERY_CHECKPOINT', 'checkpoint lease epoch does not match its timestamp')
      break
    case 'DiscoveryRecoveryMergeV1':
      if (value.nextGeneration !== value.previousGeneration + 1n) failValidator('BAD_DISCOVERY_RECOVERY_MERGE', 'recovery merge generation must increment once')
      break
    case 'CoreObjectChunkV1':
      if (value.chunkCount === 0 || value.chunkIndex >= value.chunkCount || !bytesEqual(value.chunkHash, blake2b256(value.chunkBytes))) failValidator('BAD_CORE_OBJECT_CHUNK', 'chunk index/count/hash is invalid')
      break
    case 'LegacySourceCutoffV1': {
      if (value.snapshotStatus < 1 || value.snapshotStatus > 3) failValidator('BAD_LEGACY_SOURCE_STATUS', 'legacy snapshot status is not closed')
      const absent = value.terminalHeadBytes == null && value.terminalHeadHash == null
      const present = value.terminalHeadBytes != null && value.terminalHeadHash != null
      if ((value.snapshotStatus === 2 && !absent) || (value.snapshotStatus !== 2 && !present) ||
          (present && !bytesEqual(value.terminalHeadHash, blake2b256(value.terminalHeadBytes)))) {
        failValidator('BAD_LEGACY_SOURCE_STATUS', 'legacy terminal head fields/status are inconsistent')
      }
      break
    }
    case 'LegacyCutoffV1':
      if (value.drainStartedUnixMillis >= value.drainEndedUnixMillis) failValidator('BAD_LEGACY_CUTOFF_WINDOW', 'legacy cutoff drain window must be nonempty')
      break
    case 'LegacyArchiveDistributionV1':
      for (const copy of value.copies) if (copy.copyKind < 1 || copy.copyKind > 3) failValidator('BAD_LEGACY_COPY_KIND', 'legacy copy kind is not closed')
      distinctBytes(value.copies.map(copy => copy.operatorGroupId), 'legacy copy operator group')
      break
    case 'LegacyValidRecordEntryV1':
      if (value.category < 1 || value.category > 2 || !bytesEqual(value.exactOriginalSignedBytesHash, blake2b256(value.exactOriginalSignedBytes))) failValidator('BAD_LEGACY_VALID_ENTRY', 'legacy valid entry category or byte hash is invalid')
      break
    case 'LegacyInvalidRecordEntryV1':
      if (!bytesEqual(value.exactOriginalSignedBytesHash, blake2b256(value.exactOriginalSignedBytes))) failValidator('BAD_LEGACY_INVALID_ENTRY', 'invalid legacy byte hash is invalid')
      break
    case 'LegacyArchiveIndexV1': {
      const count = value.entries.reduce((totals, entry) => {
        if (entry.category < 1 || entry.category > 4) failValidator('BAD_LEGACY_INDEX_CATEGORY', 'legacy index category is not closed')
        if (entry.category === 2) totals.conflicts.add(bytesToHex(entry.primarySortId))
        else totals[entry.category]++
        return totals
      }, { 1: 0, 3: 0, 4: 0, conflicts: new Set() })
      if (BigInt(count[1]) !== value.retainedRecordCount || BigInt(count.conflicts.size) !== value.conflictRecordCount ||
          BigInt(count[3]) !== value.invalidRecordCount || BigInt(count[4]) !== value.missingRangeCount) {
        failValidator('BAD_LEGACY_INDEX_COUNT', 'legacy index category counts do not reproduce headers')
      }
      break
    }
    case 'LegacyArchiveBundleV1':
      if (value.archiveBytes.byteLength + value.indexBytes.byteLength + value.distributionBytes.byteLength > 251658240) failValidator('BAD_LEGACY_ARCHIVE_BUNDLE_SIZE', 'legacy archive bundle exceeds 240 MiB')
      break
    case 'LegacyRetirementEvidenceV1':
      if (value.retirementWindowStartedUnixMillis >= value.retirementWindowEndedUnixMillis || bytesEqual(value.precedingDualReadPinHashes[0], value.precedingDualReadPinHashes[1])) failValidator('BAD_LEGACY_RETIREMENT_EVIDENCE', 'retirement window or predecessor hashes are invalid')
      break
    case 'PeeritRecoveryBundleV1':
      nonzero(value.salt, 'recovery salt')
      if (BigInt(value.sealed.byteLength) !== value.ciphertextLength + 16n) failValidator('BAD_RECOVERY_BUNDLE', 'recovery sealed length is invalid')
      break
    case 'DeviceChainStartV1':
      nonzero(value.deviceChainId, 'deviceChainId')
      break
    case 'WebAssetManifestV1':
      distinctBytes(value.assets.map(asset => asset.path), 'web asset path')
      break
  }
}

function snapshotExternalAuthorityMap (inventory, authorities) {
  const output = new Map()
  for (const row of inventory.externalCodecImports) output.set(row.name, authorities[row.name])
  return output
}

export function createPeeritProfileValidatorV1 (compiled, inventory, options = {}) {
  if (Object.prototype.hasOwnProperty.call(options, 'validateGraph')) {
    failValidator('UNBRANDED_CONTEXTUAL_GRAPH_CALLBACK_REJECTED', 'validateGraph callbacks are not a production authority; use a branded contextualGraphAuthority')
  }
  let contextualGraphAuthority = null
  if (options.contextualGraphAuthority != null) {
    contextualGraphAuthority = assertPeeritContextualGraphAuthorityV1(options.contextualGraphAuthority, {
      compiled,
      inventory,
      sortProjection: peeritProfileNamedSortProjection,
      production: options.production === true
    })
  }
  if (options.production === true) {
    if (options.verifySignatures === false) failValidator('PRODUCTION_SIGNATURE_VERIFICATION_REQUIRED', 'production profile validation cannot disable signatures')
    if (contextualGraphAuthority == null) failValidator('CONTEXTUAL_GRAPH_AUTHORITY_REQUIRED', 'production profile validation requires a branded contextualGraphAuthority')
  }
  const catalog = createPeeritProfileCodecCatalogFromIr(compiled, inventory, {
    externalAuthorities: options.externalAuthorities,
    sortProjection: peeritProfileNamedSortProjection,
    production: options.production === true
  })
  const externalAuthorityByName = snapshotExternalAuthorityMap(inventory, options.externalAuthorities)
  const sharedContext = Object.freeze({
    catalog,
    hashDiscoveryIndexNode: options.hashDiscoveryIndexNode || (bytes => domainLengthHash('peerit.hiverelay.discovery-index-node-hash.v1', bytes)),
    ...options.context
  })
  return Object.freeze({
    catalog,
    validate (schemaName, input, context = {}) {
      const codec = catalog[schemaName]
      if (codec == null) failValidator('UNKNOWN_PROFILE_SCHEMA', `unknown profile schema ${schemaName}`)
      const bytes = new Uint8Array(input)
      const value = codec.decode(bytes)
      const validationContext = { ...sharedContext, ...context, catalog }
      validateRecordSemantics(schemaName, value, validationContext)
      if (options.verifySignatures !== false) {
        validateSingleSignature(compiled, inventory, externalAuthorityByName, schemaName, value, validationContext)
      }
      const contextual = contextualGraphAuthority == null
        ? null
        : contextualGraphAuthority.validateRecord(schemaName, value, bytes, validationContext)
      return Object.freeze({ schemaName, bytes, value, contextual })
    }
  })
}

export const PEERIT_PROFILE_VALIDATOR_CAPABILITIES_V1 = Object.freeze({
  schemaCount: 78,
  strictCanonicalEncodeDecode: true,
  boundedDecodeBeforeAllocation: true,
  namedSortProjections: true,
  localCrossFieldValidation: true,
  embeddedEd25519Verification: true,
  externalCodecAuthorityRequired: true,
  unbrandedGraphCallbacksRejected: true,
  auditContextualGraphAuthoritySupported: true,
  productionConstructionRejectsPublicAuditMinters: true,
  fixedProductionContextualGraphAuthorityReady: false,
  graphAndFetchedEvidenceValidationRequiresContext: true
})
