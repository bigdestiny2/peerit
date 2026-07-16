import assert from 'node:assert/strict'
import fs from 'node:fs'
import {
  PEERIT_PROFILE_EXTERNAL_AUTHORITY,
  PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  assertPeeritProfileCodecLayoutIrSet,
  compilePeeritProfileCodecIr,
  decodePeeritProfileSchemaCodecIr,
  encodePeeritProfileSchemaCodecIr,
  encodePeeritProfileValueFromIr
} from '../js/substrate/profile-codec-ir.mjs'
import { buildPeeritProfileArtifacts } from '../js/substrate/profile-artifact-builder.mjs'
import {
  decodePeeritProfileRegistry,
  encodePeeritProfileRegistry
} from '../js/substrate/profile-artifact-codec.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import {
  PEERIT_AVAILABILITY_POLICY_V1,
  encodeAvailabilityPolicyV1
} from '../js/substrate/availability-policy.mjs'
import { bytesEqual } from '../js/substrate/release-control-primitives.mjs'
import { buildReleaseControlFixture } from '../scripts/release-control-fixture.mjs'

const profile = fs.readFileSync(new URL('../docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md', import.meta.url), 'utf8')
const ir = compilePeeritProfileCodecIr(profile, PEERIT_PROFILE_INVENTORY)
const byName = new Map(ir.schemas.map(entry => [entry.name, entry]))
const fixture = buildReleaseControlFixture()
let passed = 0

function test (name, operation) {
  operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

function codec (name) {
  const value = byName.get(name)
  assert.ok(value, name)
  return value
}

function field (schemaName, fieldName) {
  const value = codec(schemaName).body.fields.find(entry => entry.name === fieldName)
  assert.ok(value, `${schemaName}.${fieldName}`)
  return value.type
}

test('all 78 declarations compile to deterministic finite tagged codec IR', () => {
  assert.equal(ir.version, 1)
  assert.equal(ir.tagEncoding, 'u16be')
  assert.equal(ir.optionalPresenceEncoding, 'u8-0-or-1')
  assert.equal(ir.schemaCount, 78)
  assert.equal(ir.boundedSchemaCount, 78)
  assert.equal(ir.boundedStructuralIrReady, true)
  assert.equal(ir.semanticValidationComplete, false)
  assert.equal(ir.schemas.every(entry => entry.maximumCompleteBytes > 2n), true)
  for (let index = 0; index < ir.schemas.length; index++) {
    assert.equal(ir.schemas[index].ordinal, index + 1)
    assert.equal(ir.schemas[index].tag, 0x0100 + index + 1)
  }
})

test('every schema IR has one canonical binary representation and survives strict decode', () => {
  for (const schema of ir.schemas) {
    const bytes = encodePeeritProfileSchemaCodecIr(schema)
    const decoded = decodePeeritProfileSchemaCodecIr(bytes)
    assert.equal(decoded.name, schema.name)
    assert.equal(decoded.ordinal, schema.ordinal)
    assert.equal(decoded.tag, schema.tag)
    assert.equal(decoded.kind, schema.kind)
    assert.equal(decoded.maximumCompleteBytes, schema.maximumCompleteBytes)
    assert.deepEqual(encodePeeritProfileSchemaCodecIr(decoded), bytes)
    assert.throws(() => decodePeeritProfileSchemaCodecIr(bytes.slice(0, -1)))
    assert.throws(() => decodePeeritProfileSchemaCodecIr(new Uint8Array([...bytes, 0])))
  }
})

test('VNext AuthorBind uses one closed UTF-8 Cell envelope codec', () => {
  const envelope = codec('PeeritInnerOperationBatchV1')
  const innerCodec = field('AuthorBindV1', 'innerCodec')
  const innerLength = field('AuthorBindV1', 'innerLength')
  const replicas = field('AuthorBindV1', 'initialReplicas')
  const sizeClass = field('CellReplicaBindingV1', 'sizeClass')
  const payload = field('PeeritInnerOperationBatchV1', 'canonicalOperationBatch')

  assert.equal(envelope.ordinal, 78)
  assert.equal(envelope.tag, 334)
  assert.equal(innerCodec.kind, 'uint')
  assert.equal(innerCodec.bits, 16)
  assert.equal(innerCodec.constant, 334n)
  assert.equal(innerLength.minimum, 8n)
  assert.equal(innerLength.maximum, 1048519n)
  assert.equal(replicas.kind, 'array')
  assert.equal(replicas.value.kind, 'local')
  assert.equal(replicas.value.name, 'CellReplicaBindingV1')
  assert.equal(sizeClass.minimum, 1n)
  assert.equal(sizeClass.maximum, 5n)
  assert.equal(payload.flavor, 'canonical-utf8')
  assert.equal(payload.minimum, 1n)
  assert.equal(payload.maximum, 1048512n)
})

test('the full registry embeds exact bounded IR and executable codecs without claiming release readiness', () => {
  const artifacts = buildPeeritProfileArtifacts(new TextEncoder().encode(profile), PEERIT_PROFILE_INVENTORY)
  const registry = decodePeeritProfileRegistry(artifacts.registryBytes)
  assert.equal(registry.registryComplete, true)
  assert.equal(registry.codecLayoutIrComplete, true)
  assert.equal(registry.codecsComplete, true)
  assert.equal(registry.releaseReady, false)
  assert.equal(registry.schemas.length, 78)
  for (let index = 0; index < registry.schemas.length; index++) {
    assert.deepEqual(
      encodePeeritProfileSchemaCodecIr(registry.schemas[index].codecIr),
      encodePeeritProfileSchemaCodecIr(ir.schemas[index])
    )
  }

  const substituted = structuredClone(registry)
  substituted.schemas[0].codecIr.maximumCompleteBytes++
  assert.throws(
    () => decodePeeritProfileRegistry(encodePeeritProfileRegistry(substituted)),
    error => ['PROFILE_CODEC_IR_MAXIMUM_MISMATCH', 'PROFILE_CODEC_IR_SOURCE_MISMATCH'].includes(error.code)
  )
})

test('IR-generated release-control and availability-policy bytes equal the existing executable codecs', () => {
  const cases = [
    ['SubstrateTupleV1', fixture.tuples.tupleA, fixture.tupleBytes[0]],
    ['PeeritHiveRelayProfilePinV1', fixture.pins[0], fixture.pinBytes[0]],
    ['PeeritPinHistoryCheckpointV1', fixture.checkpoints[0], fixture.checkpointBytes[0]],
    ['PeeritPinHistoryBundleV1', {
      version: 1,
      checkpoints: fixture.checkpointBytes,
      pins: fixture.pinBytes
    }, fixture.bundleBytes],
    ['AvailabilityPolicyV1', PEERIT_AVAILABILITY_POLICY_V1, encodeAvailabilityPolicyV1()]
  ]
  for (const [name, value, expected] of cases) {
    const actual = encodePeeritProfileValueFromIr(ir, PEERIT_PROFILE_INVENTORY, name, value)
    assert.equal(bytesEqual(actual, expected), true, name)
  }
  assert.equal(codec('SubstrateTupleV1').maximumCompleteBytes, 98n)
  assert.equal(codec('PeeritPinHistoryBundleV1').maximumCompleteBytes, 2360327n)
  assert.equal(codec('AvailabilityPolicyV1').maximumCompleteBytes, 97n)
})

test('external fields split exact WIRE and client-composition authorities', () => {
  assert.equal(ir.externalWireTupleBinding, PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING)
  assert.equal(PEERIT_PROFILE_INVENTORY.externalTypes.length, 12)
  assert.equal(PEERIT_PROFILE_INVENTORY.externalCodecImports.length, 6)
  assert.equal(ir.externalWireImportCount, 4)
  assert.equal(ir.clientCompositionImportCount, 2)
  assert.equal(ir.pendingClientExampleImportCount, 0)
  assert.equal(ir.externalCodecAuthorityComplete, true)
  for (const external of PEERIT_PROFILE_INVENTORY.externalCodecImports) {
    assert.equal(external.minimumBytes >= 1, true)
    assert.equal(external.maximumBytes >= external.minimumBytes, true)
  }
  const readCap = field('CellReplicaBindingV1', 'readCapability')
  assert.deepEqual(readCap, {
    kind: 'external',
    name: 'ReadCellCapV1',
    family: 'CELL',
    authorityKind: PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1,
    tupleBinding: PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
    clientSchemaCommitment: null,
    minimum: 99n,
    maximum: 131n,
    lengthPrefixBits: 8
  })
  assert.equal(field('InboxManagementEntryV1', 'latestReceipt').lengthPrefixBits, 16)
  assert.equal(field('InboxManagementEntryV1', 'latestReceipt').authorityKind,
    PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1)
  assert.equal(field('InboxManagementEntryV1', 'latestReceipt').tupleBinding,
    PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING)
  assert.equal(PEERIT_PROFILE_INVENTORY.externalCodecImports.some(entry => entry.name === 'BlindStoreManifestV1'), false)
})

test('recovery bundle ciphertext and sealed payload have one finite dependent bound', () => {
  const ciphertextLength = field('PeeritRecoveryBundleV1', 'ciphertextLength')
  const sealed = field('PeeritRecoveryBundleV1', 'sealed')
  assert.deepEqual(ciphertextLength, {
    kind: 'uint',
    bits: 64,
    minimum: 1n,
    maximum: 16777216n,
    constant: null
  })
  assert.deepEqual(sealed, {
    kind: 'dependent-bytes',
    lengthField: 'ciphertextLength',
    add: 16,
    maximum: 16777232n
  })
  assert.equal(codec('PeeritRecoveryBundleV1').maximumCompleteBytes, 16777333n)
})

test('legacy invalid and missing evidence use distinct closed nonzero u16 registries', () => {
  const validator = PEERIT_PROFILE_INVENTORY.profileRegistries.find(entry => entry.name === 'LegacyValidatorReasonCodeV1')
  const missing = PEERIT_PROFILE_INVENTORY.profileRegistries.find(entry => entry.name === 'LegacyMissingReasonCodeV1')
  assert.equal(validator.encoding, 'u16')
  assert.equal(missing.encoding, 'u16')
  assert.deepEqual(validator.values.map(entry => entry.id), [1, 2, 3, 4, 5, 6, 7])
  assert.deepEqual(missing.values.map(entry => entry.id), [1, 2, 3, 4, 5])
  assert.equal(field('LegacyInvalidRecordEntryV1', 'validatorReasonCode').name, validator.name)
  assert.equal(field('LegacyMissingRangeEntryV1', 'missingReasonCode').name, missing.name)
})

test('duplicate fields, unbounded recovery bytes, and tuple-less external imports fail closed', () => {
  const duplicate = profile.replace(
    '  sealedPayloadHash:    32 bytes\n',
    '  sealedPayloadHash:    32 bytes\n  sealedPayloadHash:    32 bytes\n'
  )
  assert.throws(
    () => compilePeeritProfileCodecIr(duplicate, PEERIT_PROFILE_INVENTORY),
    error => error.code === 'PROFILE_CODEC_IR_DUPLICATE_FIELD'
  )

  const unbounded = profile.replace(
    '  sealed:            exact bytes[ciphertextLength + 16; max=16777232]',
    '  sealed:            exact ciphertext plus 16-byte tag'
  )
  assert.throws(
    () => compilePeeritProfileCodecIr(unbounded, PEERIT_PROFILE_INVENTORY),
    error => error.code === 'PROFILE_CODEC_IR_UNDERSPECIFIED'
  )

  const tupleless = structuredClone(PEERIT_PROFILE_INVENTORY)
  delete tupleless.externalCodecImports[0].tupleBinding
  assert.throws(
    () => compilePeeritProfileCodecIr(profile, tupleless),
    error => error.code === 'PROFILE_CODEC_IR_UNDERSPECIFIED'
  )
})

test('sorted arrays are strict by canonical bytes while ordered arrays retain order', () => {
  const wrong = structuredClone(fixture.pins[0])
  wrong.recommendedBootstrapHashes.reverse()
  assert.throws(
    () => encodePeeritProfileValueFromIr(ir, PEERIT_PROFILE_INVENTORY, 'PeeritHiveRelayProfilePinV1', wrong),
    error => error.code === 'BAD_PROFILE_CODEC_VALUE'
  )
  const ordered = {
    version: 1,
    checkpoints: fixture.checkpointBytes,
    pins: fixture.pinBytes
  }
  assert.equal(bytesEqual(
    encodePeeritProfileValueFromIr(ir, PEERIT_PROFILE_INVENTORY, 'PeeritPinHistoryBundleV1', ordered),
    fixture.bundleBytes
  ), true)

  const accessor = { ...fixture.tuples.tupleA }
  Object.defineProperty(accessor, 'specHash', { enumerable: true, get: () => fixture.tuples.tupleA.specHash })
  assert.throws(
    () => encodePeeritProfileValueFromIr(ir, PEERIT_PROFILE_INVENTORY, 'SubstrateTupleV1', accessor),
    error => error.code === 'BAD_PROFILE_CODEC_VALUE'
  )
  const hidden = { ...fixture.tuples.tupleA }
  Object.defineProperty(hidden, 'extra', { value: 1 })
  assert.throws(
    () => encodePeeritProfileValueFromIr(ir, PEERIT_PROFILE_INVENTORY, 'SubstrateTupleV1', hidden),
    error => error.code === 'BAD_PROFILE_CODEC_VALUE'
  )
})

test('canonical-looking malformed IR, authority substitution, and excessive nesting fail before use', () => {
  const tupleBytes = encodePeeritProfileSchemaCodecIr(codec('SubstrateTupleV1'))
  const malformedLength = tupleBytes.slice()
  const fieldOffset = Buffer.from(malformedLength).indexOf(Buffer.from('specHash'))
  assert.notEqual(fieldOffset, -1)
  const fixedLengthOffset = fieldOffset + 'specHash'.length + 1
  malformedLength.fill(0, fixedLengthOffset, fixedLengthOffset + 4)
  assert.throws(
    () => decodePeeritProfileSchemaCodecIr(malformedLength),
    error => ['BAD_PROFILE_CODEC_IR', 'PROFILE_CODEC_IR_MAXIMUM_MISMATCH'].includes(error.code)
  )

  const substituted = structuredClone(ir.schemas)
  const readCapability = substituted.find(entry => entry.name === 'CellReplicaBindingV1').body.fields
    .find(entry => entry.name === 'readCapability').type
  readCapability.authorityKind = PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1
  readCapability.tupleBinding = PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING
  assert.throws(
    () => assertPeeritProfileCodecLayoutIrSet(substituted, PEERIT_PROFILE_INVENTORY),
    error => error.code === 'PROFILE_CODEC_IR_EXTERNAL_IMPORT_DRIFT'
  )

  let nested = { kind: 'fixed-bytes', length: 1 }
  for (let index = 0; index < 33; index++) nested = { kind: 'optional', value: nested }
  const excessive = {
    ordinal: 1,
    tag: 0x0101,
    name: 'ExcessiveV1',
    kind: 'record',
    maximumCompleteBytes: 36n,
    body: { kind: 'record', fields: [{ name: 'value', type: nested }] }
  }
  assert.throws(
    () => encodePeeritProfileSchemaCodecIr(excessive),
    error => error.code === 'BAD_PROFILE_CODEC_IR'
  )
})

test('value generation snapshots data descriptors and does not reread hostile Proxy properties', () => {
  let propertyReads = 0
  const proxy = new Proxy({ ...fixture.tuples.tupleA }, {
    get (target, property, receiver) {
      propertyReads++
      return Reflect.get(target, property, receiver)
    }
  })
  assert.equal(bytesEqual(
    encodePeeritProfileValueFromIr(ir, PEERIT_PROFILE_INVENTORY, 'SubstrateTupleV1', proxy),
    fixture.tupleBytes[0]
  ), true)
  assert.equal(propertyReads, 0)
})

process.stdout.write(`peerit profile codec IR tests: ${passed}/${passed} passed\n`)
