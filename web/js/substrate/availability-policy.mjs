import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  domainLengthHash,
  failReleaseControl
} from './release-control-primitives.mjs'
import { decodePeeritProfileRegistry } from './profile-artifact-codec.mjs'

export const PEERIT_AVAILABILITY_POLICY_TAG = 0x0114
export const PEERIT_AVAILABILITY_POLICY_ARTIFACT = 'protocol/availability-policy-v1.cenc'
export const PEERIT_AVAILABILITY_POLICY_HASH_DOMAIN = 'peerit.hiverelay.availability-policy-hash.v1'

const DECLARATION_ORDINAL = 20
const DECLARATION_SOURCE_SHA256 = 'f8a451f45f4c2d8c17ac6b57b81e8224f3843b5b3d4022b6e7a4435e9e6c95c6'
const DECLARATION_SOURCE_HASH = '65a96d4206f64e01bdff9053f09d1f785118fb701a53a8252da67501dfb904b6'
const DECLARATION_CATEGORY = 'availability-bootstrap'

// HiveRelay's generic nonzero-ID bitmaps use the ID itself as the bit position
// (as cellSizeClassBits and leaseClassBits do). Inbox frameClassBits is a
// family-specific exception: frame class n occupies bit n-1.
const ALLOWED_DURABILITY_PROFILE_BITS = (1 << 1) | (1 << 2)
const INBOX_FRAME_CLASS_BITS = (1 << (1 - 1)) | (1 << (2 - 1))

const FIELD_TABLE = Object.freeze([
  ['version', 'u8', 1],
  ['minimumOperatorGroups', 'u8', 3],
  ['maxCountedReplicasPerGroup', 'u8', 1],
  ['requireDistinctStoreIds', 'u8', 1],
  ['maxCountedProfile2ReplicasPerSharedJournalGroup', 'u8', 1],
  ['maxCountedProfile1ReplicasPerLocalFailureDomain', 'u8', 1],
  ['allowedDurabilityProfileBits', 'u8', ALLOWED_DURABILITY_PROFILE_BITS],
  ['resilientClaimMinimumExternalWriteAcks', 'u8', 1],
  ['resilientClaimMinimumExternalProbeAcks', 'u8', 1],
  ['oneFailureWriteLivenessProfile2Target', 'u8', 2],
  ['requiredProfile2BodyRpoBand', 'u8', 1],
  ['requiredProfile2BodyRtoBand', 'u8', 2],
  ['maximumProfile2RestoreDrillAgeBand', 'u8', 6],
  ['criticalReplicaTarget', 'u8', 3],
  ['criticalReadbackThreshold', 'u8', 3],
  ['cellReplicaTarget', 'u8', 3],
  ['cellPolicyAckTarget', 'u8', 2],
  ['cellPolicyRecentReadTarget', 'u8', 2],
  ['coreReplicaTarget', 'u8', 3],
  ['corePolicyMirrorTarget', 'u8', 2],
  ['corePolicyRecentServeTarget', 'u8', 2],
  ['inboxStripeCountLog2', 'u8', 3],
  ['inboxReplicaTargetPerStripe', 'u8', 3],
  ['inboxPolicyAppendTarget', 'u8', 2],
  ['inboxPolicyRecentReadTarget', 'u8', 2],
  ['proofFreshnessEpochs', 'u8', 4],
  ['challengeCadenceEpochs', 'u8', 1],
  ['repairDeadlineEpochs', 'u8', 2],
  ['repairMaintainerTarget', 'u8', 3],
  ['discoveryMaintainerTarget', 'u8', 4],
  ['repairHintRefreshEpochs', 'u8', 28],
  ['contentLeaseClass', 'u8', 4],
  ['renewWhenRemainingEpochsBelow', 'u16', 120],
  ['inboxLeaseClass', 'u8', 4],
  ['inboxRetentionClass', 'u8', 3],
  ['inboxEpochSpan', 'u16', 28],
  ['inboxPreviousOverlapEpochs', 'u16', 28],
  ['inboxFrameClassBits', 'u8', INBOX_FRAME_CLASS_BITS],
  ['maxAnnouncementBytes', 'u16', 12288],
  ['normalInboxReadsPerRefresh', 'u8', 16],
  ['auditInboxReadsPerRefresh', 'u8', 24],
  ['coldInboxReadsPerRefresh', 'u8', 32],
  ['inboxPageLimit', 'u8', 32],
  ['normalFrameDecryptBudget', 'u16', 256],
  ['normalInboxByteBudget', 'u32', 4194304],
  ['auditFrameDecryptBudget', 'u16', 512],
  ['auditInboxByteBudget', 'u32', 8388608],
  ['coldFrameDecryptBudget', 'u16', 512],
  ['coldInboxByteBudget', 'u32', 8388608],
  ['maxConcurrentInboxReads', 'u8', 4],
  ['crossAuditIntervalRefreshes', 'u8', 240],
  ['foregroundInboxRefreshSeconds', 'u16', 15],
  ['backgroundInboxRefreshSeconds', 'u16', 300],
  ['checkpointCadenceSeconds', 'u16', 60],
  ['checkpointMaxLagSeconds', 'u16', 300],
  ['recentBucketSeconds', 'u16', 300],
  ['recentWindowBuckets', 'u16', 2016],
  ['snapshotHistoryRetentionDays', 'u16', 365],
  ['maxFrontierRecords', 'u32', 16777216],
  ['coldStartRecordBudget', 'u16', 256],
  ['coldStartByteBudget', 'u32', 16777216],
  ['alertEvaluationSeconds', 'u16', 60],
  ['softAlertOpenIntervals', 'u8', 3],
  ['softAlertClearIntervals', 'u8', 5]
].map(row => Object.freeze(row)))

function hex (value) {
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

function plainExactPolicy (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    failReleaseControl('BAD_AVAILABILITY_POLICY', 'AvailabilityPolicyV1 must be a plain object')
  }
  const expected = FIELD_TABLE.map(row => row[0])
  const keys = Reflect.ownKeys(value)
  if (keys.length !== expected.length || keys.some(key => typeof key !== 'string') ||
      expected.some(key => !Object.prototype.hasOwnProperty.call(value, key))) {
    failReleaseControl('BAD_AVAILABILITY_POLICY', 'AvailabilityPolicyV1 fields are missing or unexpected')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const output = {}
  for (const row of FIELD_TABLE) {
    const field = row[0]
    const constant = row[2]
    const descriptor = descriptors[field]
    if (!descriptor || !descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
        descriptor.value !== constant) {
      failReleaseControl('BAD_AVAILABILITY_POLICY', `${field} must equal its frozen policy constant`)
    }
    output[field] = constant
  }
  return output
}

export const PEERIT_AVAILABILITY_POLICY_V1 = Object.freeze(Object.fromEntries(
  FIELD_TABLE.map(([field, _type, value]) => [field, value])
))

export const PEERIT_AVAILABILITY_POLICY_FIELDS = FIELD_TABLE

export function encodeAvailabilityPolicyV1 (input = PEERIT_AVAILABILITY_POLICY_V1) {
  const value = plainExactPolicy(input)
  const writer = new CanonicalWriter()
  writer.u16(PEERIT_AVAILABILITY_POLICY_TAG, 'AvailabilityPolicyV1 tag')
  for (const [field, type] of FIELD_TABLE) writer[type](value[field], `AvailabilityPolicyV1.${field}`)
  return writer.finish()
}

export function decodeAvailabilityPolicyV1 (input) {
  const bytes = asBytes(input, 'AvailabilityPolicyV1 bytes')
  const reader = new CanonicalReader(bytes)
  if (reader.u16('AvailabilityPolicyV1 tag') !== PEERIT_AVAILABILITY_POLICY_TAG) {
    failReleaseControl('BAD_AVAILABILITY_POLICY_TAG',
      `AvailabilityPolicyV1 tag must be ${PEERIT_AVAILABILITY_POLICY_TAG}`)
  }
  const value = {}
  for (const [field, type] of FIELD_TABLE) value[field] = reader[type](`AvailabilityPolicyV1.${field}`)
  reader.expectEnd('AvailabilityPolicyV1')
  const validated = plainExactPolicy(value)
  const canonical = encodeAvailabilityPolicyV1(validated)
  if (canonical.byteLength !== bytes.byteLength || canonical.some((byte, index) => byte !== bytes[index])) {
    failReleaseControl('NONCANONICAL_AVAILABILITY_POLICY', 'AvailabilityPolicyV1 does not round-trip canonically')
  }
  return Object.freeze(validated)
}

export function availabilityPolicyHash (input) {
  const bytes = asBytes(input, 'AvailabilityPolicyV1 bytes')
  decodeAvailabilityPolicyV1(bytes)
  return domainLengthHash(PEERIT_AVAILABILITY_POLICY_HASH_DOMAIN, bytes)
}

export function assertAvailabilityPolicyRegistryBinding (registryBytes) {
  const registry = decodePeeritProfileRegistry(registryBytes)
  const row = registry.schemas.find(value => value.name === 'AvailabilityPolicyV1')
  const category = row == null ? null : registry.categories.find(value => value.id === row.categoryId)
  if (!row || row.ordinal !== DECLARATION_ORDINAL || row.tag !== PEERIT_AVAILABILITY_POLICY_TAG ||
      row.kind !== 'record' || row.owner !== 'peerit-profile' || hex(row.sourceSha256) !== DECLARATION_SOURCE_SHA256 ||
      hex(row.sourceHash) !== DECLARATION_SOURCE_HASH || category?.name !== DECLARATION_CATEGORY ||
      row.dependencies.length !== 0 || row.inlineShapes.length !== 0) {
    failReleaseControl('AVAILABILITY_POLICY_REGISTRY_DRIFT',
      'AvailabilityPolicyV1 is not bound to its exact full-profile declaration')
  }
  return true
}
