import {
  CanonicalReader,
  CanonicalWriter,
  asciiBytes,
  bytesEqual,
  compareBytes,
  failReleaseControl
} from './release-control-primitives.mjs'

export const RELEASE_CONTROL_ARTIFACT_ID = '@peerit/release-control-slice-v1'
export const RELEASE_CONTROL_REGISTRY_MAGIC = 'PTRCSL01'
export const PEERIT_PROFILE_ID = '@peerit/hiverelay-profile-v1'

export const RELEASE_CONTROL_TAG = Object.freeze({
  SUBSTRATE_TUPLE_V1: 0x0101,
  PROFILE_PIN_V1: 0x0102,
  PIN_HISTORY_CHECKPOINT_V1: 0x0103,
  PIN_HISTORY_BUNDLE_V1: 0x0104
})

export const PEERIT_MIGRATION_STAGE = Object.freeze({
  LIVE_DUAL_READ: 0,
  FROZEN_CUTOFF: 1,
  ARCHIVE_ONLY: 2
})

export const RELEASE_CONTROL_DOMAIN = Object.freeze({
  PROFILE_PIN_SIGNATURE: 'peerit.hiverelay.profile-pin.v1',
  PIN_HISTORY_CHECKPOINT_SIGNATURE: 'peerit.pin-history-checkpoint.v1',
  RELEASE_AUTHORITY_KEY_ID: 'peerit.release-authority-key-id.v1',
  PROFILE_PIN_HASH: 'peerit.hiverelay.profile-pin-hash.v1',
  PIN_HISTORY_CHECKPOINT_HASH: 'peerit.pin-history-checkpoint-hash.v1',
  PIN_HISTORY_BUNDLE_HASH: 'peerit.pin-history-bundle-hash.v1'
})

export const RELEASE_CONTROL_LIMIT = Object.freeze({
  READ_SUBSTRATES_MIN: 1,
  READ_SUBSTRATES_MAX: 3,
  RECOMMENDED_BOOTSTRAPS_MAX: 16,
  PIN_HISTORY_RETENTION_DAYS: 3650,
  BUNDLE_ITEMS_MIN: 1,
  BUNDLE_ITEMS_MAX: 256,
  CHECKPOINT_BYTES_MIN: 1,
  CHECKPOINT_BYTES_MAX: 1024,
  PIN_BYTES_MIN: 1,
  PIN_BYTES_MAX: 8192
})

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function field (name, encoding) {
  return { name, encoding }
}

export const RELEASE_CONTROL_REGISTRY = deepFreeze({
  artifactId: RELEASE_CONTROL_ARTIFACT_ID,
  formatVersion: 1,
  productionComplete: false,
  records: [
    {
      tag: RELEASE_CONTROL_TAG.SUBSTRATE_TUPLE_V1,
      name: 'SubstrateTupleV1',
      maximumCompleteBytes: 98,
      signatureDomain: null,
      fields: [
        field('specHash', 'fixed32'),
        field('abiHash', 'fixed32'),
        field('vectorSetHash', 'fixed32')
      ]
    },
    {
      tag: RELEASE_CONTROL_TAG.PROFILE_PIN_V1,
      name: 'PeeritHiveRelayProfilePinV1',
      maximumCompleteBytes: RELEASE_CONTROL_LIMIT.PIN_BYTES_MAX,
      signatureDomain: RELEASE_CONTROL_DOMAIN.PROFILE_PIN_SIGNATURE,
      fields: [
        field('version', 'u8=1'),
        field('profileId', `ascii[${asciiBytes(PEERIT_PROFILE_ID).byteLength}]=${PEERIT_PROFILE_ID}`),
        field('releaseSequence', 'u64be'),
        field('previousPinHash', 'optional-u8(fixed32)'),
        field('emitSubstrate', 'complete(SubstrateTupleV1)'),
        field('readSubstrates', 'u8-count[1..3](sorted-unique complete(SubstrateTupleV1))'),
        field('profileSpecHash', 'fixed32'),
        field('profileAbiHash', 'fixed32'),
        field('profileVectorSetHash', 'fixed32'),
        field('validatorArtifactHash', 'fixed32'),
        field('validatorVectorSetHash', 'fixed32'),
        field('availabilityPolicyHash', 'fixed32'),
        field('recommendedBootstrapHashes', 'u8-count[0..16](sorted-unique fixed32)'),
        field('pinHistoryRetentionDays', 'u16be=3650'),
        field('appArtifactHash', 'fixed32'),
        field('webAssetManifestHash', 'fixed32'),
        field('legacySourceSetHash', 'fixed32'),
        field('migrationStage', 'PeeritMigrationStageV1:u8'),
        field('migrationTransitionEvidenceHash', 'optional-u8(fixed32)'),
        field('legacyImportMode', 'u8[0..2]'),
        field('legacyReadMode', 'u8[0..1]'),
        field('legacyCutoffHash', 'optional-u8(fixed32)'),
        field('migrationGenesisRecordId', 'optional-u8(fixed32)'),
        field('cutoffActivationReleaseSequence', 'optional-u8(u64be)'),
        field('legacyRetirementEvidenceHash', 'optional-u8(fixed32)'),
        field('legacyRetirementActivationReleaseSequence', 'optional-u8(u64be)'),
        field('releaseAuthoritySequence', 'u64be'),
        field('releaseAuthorityPublicKey', 'fixed32'),
        field('releaseAuthorityKeyId', 'fixed32'),
        field('authorityTransitionHash', 'optional-u8(fixed32);unsupported-in-slice'),
        field('signature', 'fixed64')
      ]
    },
    {
      tag: RELEASE_CONTROL_TAG.PIN_HISTORY_CHECKPOINT_V1,
      name: 'PeeritPinHistoryCheckpointV1',
      maximumCompleteBytes: RELEASE_CONTROL_LIMIT.CHECKPOINT_BYTES_MAX,
      signatureDomain: RELEASE_CONTROL_DOMAIN.PIN_HISTORY_CHECKPOINT_SIGNATURE,
      fields: [
        field('version', 'u8=1'),
        field('checkpointSequence', 'u64be'),
        field('previousCheckpointHash', 'optional-u8(fixed32)'),
        field('pinHash', 'fixed32'),
        field('previousPinHash', 'optional-u8(fixed32)'),
        field('issuedUnixMillis', 'u64be'),
        field('releaseAuthoritySequence', 'u64be'),
        field('releaseAuthorityKeyId', 'fixed32'),
        field('signature', 'fixed64')
      ]
    },
    {
      tag: RELEASE_CONTROL_TAG.PIN_HISTORY_BUNDLE_V1,
      name: 'PeeritPinHistoryBundleV1',
      maximumCompleteBytes: 2360327,
      signatureDomain: null,
      fields: [
        field('version', 'u8=1'),
        field('checkpoints', 'u16be-count[1..256](u16be-bytes[1..1024])'),
        field('pins', 'u16be-count[1..256](u16be-bytes[1..8192])')
      ]
    }
  ],
  enums: [
    {
      name: 'PeeritMigrationStageV1',
      encoding: 'u8',
      values: [
        { id: PEERIT_MIGRATION_STAGE.LIVE_DUAL_READ, name: 'LIVE_DUAL_READ' },
        { id: PEERIT_MIGRATION_STAGE.FROZEN_CUTOFF, name: 'FROZEN_CUTOFF' },
        { id: PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY, name: 'ARCHIVE_ONLY' }
      ]
    }
  ],
  hashRecipes: [
    { name: 'pinHistoryBundleHash', domain: RELEASE_CONTROL_DOMAIN.PIN_HISTORY_BUNDLE_HASH, recipe: 'BLAKE2b-256(domain || len64(completeBundle) || completeBundle)' },
    { name: 'pinHistoryCheckpointHash', domain: RELEASE_CONTROL_DOMAIN.PIN_HISTORY_CHECKPOINT_HASH, recipe: 'BLAKE2b-256(domain || len64(completeSignedCheckpoint) || completeSignedCheckpoint)' },
    { name: 'profilePinHash', domain: RELEASE_CONTROL_DOMAIN.PROFILE_PIN_HASH, recipe: 'BLAKE2b-256(domain || len64(completeSignedPin) || completeSignedPin)' },
    { name: 'releaseAuthorityKeyId', domain: RELEASE_CONTROL_DOMAIN.RELEASE_AUTHORITY_KEY_ID, recipe: 'BLAKE2b-256(domain || releaseAuthorityPublicKey)' }
  ],
  rules: [
    { id: 'authority-rotation', text: 'authorityTransitionHash MUST be absent; PeeritReleaseAuthorityTransitionV1 is outside this slice' },
    { id: 'bundle-authority', text: 'the bundle adds no authority; every inner record validates independently' },
    { id: 'canonical-tag', text: 'inside this non-production slice every complete record starts with its slice-local u16be tag; the full profile ABI must pin or replace this framing before production' },
    { id: 'checkpoint-chain', text: 'checkpoints and pins are one-to-one, exact +1, fork-free, and predecessor-bound' },
    { id: 'migration-monotonicity', text: 'stage/import/read modes may stay or advance exactly one step and never downgrade' },
    { id: 'static-expectations', text: 'this slice verifies only pins already authenticated by an exact expectedPins projection; the separate full-profile continuation verifier accepts contiguous previously unknown newer pins from a branded anchor' },
    { id: 'profile-pin-signature', text: 'Ed25519 signs ASCII(peerit.hiverelay.profile-pin.v1) || complete canonical tagged fields before signature' },
    { id: 'checkpoint-signature', text: 'Ed25519 signs ASCII(peerit.pin-history-checkpoint.v1) || complete canonical tagged fields before signature' },
    { id: 'slice-honesty', text: 'this artifact never supplies profileAbiHash and cannot replace protocol/peerit-profile-v1.cenc' }
  ],
  exclusions: [
    'PeeritReleaseAuthorityTransitionV1 codec and dual-signature verification inside this slice (implemented by the separate full-profile continuation verifier)',
    'availability policy artifact',
    'final HiveRelay substrate tuple',
    'full Peerit profile registry and vectors',
    'online continuity acceptance inside this slice (implemented by the separate full-profile continuation verifier)',
    'production release authority keys',
    'validator artifact and vectors'
  ]
})

function sortedByBytes (values, projection) {
  return [...values].sort((left, right) => compareBytes(asciiBytes(projection(left)), asciiBytes(projection(right))))
}

function writeOptionalText (writer, value, fieldName) {
  if (value == null) {
    writer.u8(0, `${fieldName} presence`)
    return
  }
  writer.u8(1, `${fieldName} presence`)
  writer.utf8U16(value, fieldName)
}

function readOptionalText (reader, fieldName) {
  const present = reader.u8(`${fieldName} presence`)
  if (present === 0) return null
  if (present !== 1) failReleaseControl('BAD_RELEASE_CONTROL_REGISTRY', `${fieldName} presence must be 0 or 1`)
  return reader.utf8U16(fieldName)
}

export function encodeReleaseControlRegistry (registry = RELEASE_CONTROL_REGISTRY) {
  const writer = new CanonicalWriter()
  writer.literalAscii(RELEASE_CONTROL_REGISTRY_MAGIC, 'registry magic')
  writer.u16(registry.formatVersion, 'registry formatVersion')
  writer.utf8U16(registry.artifactId, 'registry artifactId')
  writer.u8(registry.productionComplete === true ? 1 : 0, 'registry productionComplete')

  const records = [...registry.records].sort((left, right) => left.tag - right.tag)
  writer.u16(records.length, 'registry record count')
  for (const record of records) {
    writer.u16(record.tag, `${record.name} tag`)
    writer.utf8U16(record.name, 'record name')
    writer.u32(record.maximumCompleteBytes, `${record.name} maximumCompleteBytes`)
    writeOptionalText(writer, record.signatureDomain, `${record.name} signatureDomain`)
    writer.u16(record.fields.length, `${record.name} field count`)
    for (const entry of record.fields) {
      writer.utf8U16(entry.name, `${record.name} field name`)
      writer.utf8U16(entry.encoding, `${record.name}.${entry.name} encoding`)
    }
  }

  const enums = sortedByBytes(registry.enums, entry => entry.name)
  writer.u16(enums.length, 'registry enum count')
  for (const entry of enums) {
    writer.utf8U16(entry.name, 'enum name')
    writer.utf8U16(entry.encoding, `${entry.name} encoding`)
    const values = [...entry.values].sort((left, right) => left.id - right.id)
    writer.u16(values.length, `${entry.name} value count`)
    for (const value of values) {
      writer.u8(value.id, `${entry.name} value id`)
      writer.utf8U16(value.name, `${entry.name} value name`)
    }
  }

  const hashRecipes = sortedByBytes(registry.hashRecipes, entry => entry.name)
  writer.u16(hashRecipes.length, 'registry hash recipe count')
  for (const entry of hashRecipes) {
    writer.utf8U16(entry.name, 'hash recipe name')
    writer.utf8U16(entry.domain, `${entry.name} domain`)
    writer.utf8U16(entry.recipe, `${entry.name} recipe`)
  }

  const rules = sortedByBytes(registry.rules, entry => entry.id)
  writer.u16(rules.length, 'registry rule count')
  for (const entry of rules) {
    writer.utf8U16(entry.id, 'rule id')
    writer.utf8U16(entry.text, `${entry.id} text`)
  }

  const exclusions = [...registry.exclusions].sort((left, right) => compareBytes(asciiBytes(left), asciiBytes(right)))
  writer.u16(exclusions.length, 'registry exclusion count')
  for (const entry of exclusions) writer.utf8U16(entry, 'registry exclusion')
  return writer.finish()
}

export function decodeReleaseControlRegistry (value) {
  const reader = new CanonicalReader(value)
  reader.expectLiteralAscii(RELEASE_CONTROL_REGISTRY_MAGIC, 'registry magic')
  const formatVersion = reader.u16('registry formatVersion')
  const artifactId = reader.utf8U16('registry artifactId')
  const productionComplete = reader.u8('registry productionComplete')
  if (productionComplete !== 0) {
    failReleaseControl('BAD_RELEASE_CONTROL_REGISTRY', 'release-control slice cannot claim production completeness')
  }

  const records = []
  const recordCount = reader.u16('registry record count')
  for (let i = 0; i < recordCount; i++) {
    const tag = reader.u16('record tag')
    const name = reader.utf8U16('record name')
    const maximumCompleteBytes = reader.u32(`${name} maximumCompleteBytes`)
    const signatureDomain = readOptionalText(reader, `${name} signatureDomain`)
    const fields = []
    const fieldCount = reader.u16(`${name} field count`)
    for (let j = 0; j < fieldCount; j++) {
      const fieldName = reader.utf8U16(`${name} field name`)
      fields.push({ name: fieldName, encoding: reader.utf8U16(`${name}.${fieldName} encoding`) })
    }
    records.push({ tag, name, maximumCompleteBytes, signatureDomain, fields })
  }

  const enums = []
  const enumCount = reader.u16('registry enum count')
  for (let i = 0; i < enumCount; i++) {
    const name = reader.utf8U16('enum name')
    const encoding = reader.utf8U16(`${name} encoding`)
    const values = []
    const valueCount = reader.u16(`${name} value count`)
    for (let j = 0; j < valueCount; j++) {
      values.push({ id: reader.u8(`${name} value id`), name: reader.utf8U16(`${name} value name`) })
    }
    enums.push({ name, encoding, values })
  }

  const hashRecipes = []
  const hashRecipeCount = reader.u16('registry hash recipe count')
  for (let i = 0; i < hashRecipeCount; i++) {
    const name = reader.utf8U16('hash recipe name')
    hashRecipes.push({
      name,
      domain: reader.utf8U16(`${name} domain`),
      recipe: reader.utf8U16(`${name} recipe`)
    })
  }

  const rules = []
  const ruleCount = reader.u16('registry rule count')
  for (let i = 0; i < ruleCount; i++) {
    const id = reader.utf8U16('rule id')
    rules.push({ id, text: reader.utf8U16(`${id} text`) })
  }

  const exclusions = []
  const exclusionCount = reader.u16('registry exclusion count')
  for (let i = 0; i < exclusionCount; i++) exclusions.push(reader.utf8U16('registry exclusion'))
  reader.expectEnd('release-control registry')

  const registry = {
    artifactId,
    formatVersion,
    productionComplete: false,
    records,
    enums,
    hashRecipes,
    rules,
    exclusions
  }
  if (!bytesEqual(encodeReleaseControlRegistry(registry), value)) {
    failReleaseControl('BAD_RELEASE_CONTROL_REGISTRY', 'release-control registry is not canonical')
  }
  return registry
}

export function assertReleaseControlRegistryArtifact (value) {
  const decoded = decodeReleaseControlRegistry(value)
  const expected = encodeReleaseControlRegistry()
  if (!bytesEqual(value, expected)) {
    failReleaseControl('RELEASE_CONTROL_REGISTRY_DRIFT', 'registry artifact does not equal the executable registry')
  }
  return decoded
}

export function assertMigrationStage (value, field = 'migrationStage') {
  if (!Number.isSafeInteger(value) || value < PEERIT_MIGRATION_STAGE.LIVE_DUAL_READ || value > PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY) {
    failReleaseControl('BAD_MIGRATION_STAGE', `${field} is not a PeeritMigrationStageV1 value`)
  }
  return value
}
