import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import sodium from 'sodium-javascript'
import {
  compilePeeritProfileCodecIr,
  createPeeritProfileCodecCatalogFromIr,
  encodePeeritProfileRecordPrefixFromIr
} from '../js/substrate/profile-codec-ir.mjs'
import { createPeeritProfileStructuralFixtureFactory } from '../js/substrate/profile-codec-fixtures.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import { authenticatePeeritProfileExternalCodecAuthorityV1 } from '../js/substrate/profile-external-authority.mjs'
import {
  createPeeritProfileValidatorV1,
  peeritProfileNamedSortProjection
} from '../js/substrate/profile-validator.mjs'
import {
  PEERIT_AUTHOR_BIND_CELL_CONTENT_CAPACITY_V1,
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  assertPeeritAuthorBindInnerEnvelopeV1,
  peeritAuthorBindCellSizeClassForInnerLengthV1
} from '../js/substrate/author-bind-inner-envelope-policy.mjs'
import {
  decodePeeritValidatorVectorManifestV1,
  hashPeeritValidatorArtifactV1,
  hashPeeritValidatorVectorSetV1
} from '../js/substrate/validator-artifact.mjs'
import { PROFILE_VALIDATOR_ARTIFACT_STATUS } from '../js/substrate/profile-status.mjs'
import {
  asciiBytes,
  bytesEqual,
  bytesToHex,
  concatBytes
} from '../js/substrate/release-control-primitives.mjs'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const profile = fs.readFileSync(path.join(root, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md'), 'utf8')
const compiled = compilePeeritProfileCodecIr(profile, PEERIT_PROFILE_INVENTORY)

function externalAuthorities () {
  const wireArtifacts = {
    specBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-wire-v1.md'))),
    abiBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-abi-v1.cenc'))),
    vectorManifestBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc')))
  }
  const clientArtifacts = {
    formatAuthorityBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'))),
    vectorManifestBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')))
  }
  const object = {}
  const map = new Map()
  for (const row of PEERIT_PROFILE_INVENTORY.externalCodecImports) {
    const authority = authenticatePeeritProfileExternalCodecAuthorityV1({
      name: row.name,
      authorityKind: row.authorityKind,
      authorityBinding: row.tupleBinding,
      artifacts: row.authorityKind === 'WIRE_TUPLE_V1' ? wireArtifacts : clientArtifacts,
      assertCanonical (bytes, name) {
        assert.equal(name, row.name)
        assert.equal(bytes instanceof Uint8Array, true)
        assert.equal(bytes.byteLength >= row.minimumBytes && bytes.byteLength <= row.maximumBytes, true)
      }
    })
    object[row.name] = authority
    map.set(row.name, authority)
  }
  return { object: Object.freeze(object), map }
}

const authorities = externalAuthorities()
const runtimeOptions = Object.freeze({
  externalAuthorityByName: authorities.map,
  sortProjection: peeritProfileNamedSortProjection
})
const catalog = createPeeritProfileCodecCatalogFromIr(compiled, PEERIT_PROFILE_INVENTORY, {
  externalAuthorities: authorities.object,
  sortProjection: peeritProfileNamedSortProjection
})
const fixtures = createPeeritProfileStructuralFixtureFactory(compiled, PEERIT_PROFILE_INVENTORY, runtimeOptions)

let passed = 0
async function test (name, operation) {
  await operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

await test('all 78 generated codecs round-trip exact tags and reject truncation, tag bitflips, and trailing bytes', () => {
  assert.equal(Object.keys(catalog).length, 78)
  for (const schema of compiled.schemas) {
    const bytes = catalog[schema.name].encode(fixtures.create(schema.name, schema.ordinal * 1009))
    const decoded = catalog[schema.name].decode(bytes)
    assert.equal(bytesEqual(catalog[schema.name].encode(decoded), bytes), true, schema.name)
    assert.throws(() => catalog[schema.name].decode(bytes.slice(0, -1)), undefined, schema.name)
    const badTag = new Uint8Array(bytes)
    badTag[0] ^= 0x80
    assert.throws(() => catalog[schema.name].decode(badTag), undefined, schema.name)
    assert.throws(() => catalog[schema.name].decode(new Uint8Array([...bytes, 0])), undefined, schema.name)
  }
})

await test('checked validator vector manifest binds 78 structural positives plus truncation, bitflip, reorder, duplicate, and cross-field negatives', () => {
  const manifestBytes = new Uint8Array(fs.readFileSync(path.join(root, PROFILE_VALIDATOR_ARTIFACT_STATUS.vectorManifest)))
  const rows = decodePeeritValidatorVectorManifestV1(manifestBytes)
  assert.equal(rows.length, 238)
  assert.equal(rows.filter(row => row.path.startsWith('positive/')).length, 78)
  assert.equal(rows.filter(row => row.path.startsWith('negative/truncated/')).length, 78)
  assert.equal(rows.filter(row => row.path.startsWith('negative/bitflip-tag/')).length, 78)
  assert.equal(rows.some(row => row.path.endsWith('reordered-recovery-keys.cenc')), true)
  assert.equal(rows.some(row => row.path.endsWith('duplicate-recovery-key.cenc')), true)
  assert.equal(rows.some(row => row.path.endsWith('recovery-length-mismatch.cenc')), true)
  assert.equal(rows.some(row => row.path.endsWith('inner-operation-batch-invalid-utf8.cenc')), true)
  for (const row of rows) {
    const bytes = new Uint8Array(fs.readFileSync(path.join(root, 'protocol/validator/vectors', row.path)))
    assert.equal(BigInt(bytes.byteLength), row.vectorLength, row.path)
  }
  assert.equal(bytesToHex(hashPeeritValidatorVectorSetV1(manifestBytes)), PROFILE_VALIDATOR_ARTIFACT_STATUS.validatorVectorSetHash)
})

await test('reorder, duplicate, and dependent-length vectors fail for their exact structural reason', () => {
  const read = name => new Uint8Array(fs.readFileSync(path.join(root, 'protocol/validator/vectors/negative/semantic', name)))
  assert.throws(
    () => catalog.AvailabilityRootV1.decode(read('reordered-recovery-keys.cenc')),
    error => error.code === 'NONCANONICAL_PROFILE_CODEC_ORDER'
  )
  assert.throws(
    () => catalog.AvailabilityRootV1.decode(read('duplicate-recovery-key.cenc')),
    error => error.code === 'NONCANONICAL_PROFILE_CODEC_ORDER'
  )
  assert.throws(
    () => catalog.PeeritRecoveryBundleV1.decode(read('recovery-length-mismatch.cenc')),
    error => error.code === 'BAD_PROFILE_CODEC_VALUE'
  )
  assert.throws(
    () => catalog.PeeritInnerOperationBatchV1.decode(read('inner-operation-batch-invalid-utf8.cenc')),
    error => error.code === 'BAD_RELEASE_CONTROL_ENCODING'
  )
})

await test('external codecs require exact authenticated bindings and StoreManifest can never enter the catalog', () => {
  assert.equal(PEERIT_PROFILE_INVENTORY.externalCodecImports.some(row => row.name === 'BlindStoreManifestV1'), false)
  const missing = { ...authorities.object }
  delete missing.ReadCellCapV1
  assert.throws(
    () => createPeeritProfileCodecCatalogFromIr(compiled, PEERIT_PROFILE_INVENTORY, { externalAuthorities: missing }),
    error => error.code === 'PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH'
  )
  const wrong = { ...authorities.object, ReadCellCapV1: { ...authorities.object.ReadCellCapV1, authorityBinding: 'wire-v1:wrong' } }
  assert.throws(
    () => createPeeritProfileCodecCatalogFromIr(compiled, PEERIT_PROFILE_INVENTORY, { externalAuthorities: wrong }),
    error => error.code === 'PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH'
  )
  const symbol = { ...authorities.object }
  symbol[Symbol('StoreManifest')] = authorities.object.ReadCellCapV1
  assert.throws(
    () => createPeeritProfileCodecCatalogFromIr(compiled, PEERIT_PROFILE_INVENTORY, { externalAuthorities: symbol }),
    error => error.code === 'PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH'
  )
})

await test('codec input snapshots reject accessors, symbols, sparse arrays, unexpected fields, and hostile byte mutation', () => {
  const tuple = fixtures.create('SubstrateTupleV1')
  Object.defineProperty(tuple, 'specHash', { enumerable: true, get: () => new Uint8Array(32) })
  assert.throws(() => catalog.SubstrateTupleV1.encode(tuple), error => error.code === 'BAD_PROFILE_CODEC_VALUE')

  const symbol = fixtures.create('SubstrateTupleV1')
  symbol[Symbol('extra')] = 1
  assert.throws(() => catalog.SubstrateTupleV1.encode(symbol), error => error.code === 'BAD_PROFILE_CODEC_VALUE')

  const pin = fixtures.create('PeeritHiveRelayProfilePinV1')
  pin.readSubstrates = new Array(1)
  assert.throws(() => catalog.PeeritHiveRelayProfilePinV1.encode(pin), error => error.code === 'BAD_PROFILE_CODEC_VALUE')

  const external = fixtures.create('CellReplicaBindingV1')
  const before = new Uint8Array(external.readCapability)
  const mutating = { ...authorities.object }
  mutating.ReadCellCapV1 = authenticatePeeritProfileExternalCodecAuthorityV1({
    name: 'ReadCellCapV1',
    authorityKind: authorities.object.ReadCellCapV1.authorityKind,
    authorityBinding: authorities.object.ReadCellCapV1.authorityBinding,
    artifacts: {
      formatAuthorityBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'))),
      vectorManifestBytes: new Uint8Array(fs.readFileSync(path.join(root, 'protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')))
    },
    assertCanonical (bytes) { bytes.fill(0) }
  })
  const hostileCatalog = createPeeritProfileCodecCatalogFromIr(compiled, PEERIT_PROFILE_INVENTORY, {
    externalAuthorities: mutating,
    sortProjection: peeritProfileNamedSortProjection
  })
  hostileCatalog.CellReplicaBindingV1.encode(external)
  assert.equal(bytesEqual(external.readCapability, before), true)
})

await test('local semantic validator enforces mode, counter, causal, lease, and nonzero relations', () => {
  const validator = createPeeritProfileValidatorV1(compiled, PEERIT_PROFILE_INVENTORY, {
    externalAuthorities: authorities.object,
    verifySignatures: false
  })
  const write = fixtures.create('PeeritWriteOperationEvidenceV1')
  validator.validate('PeeritWriteOperationEvidenceV1', catalog.PeeritWriteOperationEvidenceV1.encode(write))
  write.failureBits = 0x80
  assert.throws(() => validator.validate('PeeritWriteOperationEvidenceV1', catalog.PeeritWriteOperationEvidenceV1.encode(write)), error => error.code === 'BAD_WRITE_OPERATION_EVIDENCE')

  const announcement = fixtures.create('PeeritAnnouncementV1')
  announcement.manifestMode = 1
  announcement.manifestRecord = Uint8Array.of(1)
  validator.validate('PeeritAnnouncementV1', catalog.PeeritAnnouncementV1.encode(announcement))
  announcement.manifestReadCaps = [new Uint8Array(99)]
  assert.throws(() => validator.validate('PeeritAnnouncementV1', catalog.PeeritAnnouncementV1.encode(announcement)), error => error.code === 'BAD_ANNOUNCEMENT_MODE')

  const repair = fixtures.create('RepairAddV1')
  repair.hintExpiresLeaseEpoch = repair.issuedLeaseEpoch
  repair.replica.value.logicalHash = new Uint8Array(repair.logicalHash)
  validator.validate('RepairAddV1', catalog.RepairAddV1.encode(repair))
  repair.repairNonce.fill(0)
  assert.throws(() => validator.validate('RepairAddV1', catalog.RepairAddV1.encode(repair)), error => error.code === 'ZERO_PROFILE_VALUE')
})

await test('AuthorBind closes the VNext envelope to one consistent Cell representation', () => {
  const validator = createPeeritProfileValidatorV1(compiled, PEERIT_PROFILE_INVENTORY, {
    externalAuthorities: authorities.object,
    verifySignatures: false
  })
  const authorBind = fixtures.create('AuthorBindV1')
  authorBind.logicalHash = new Uint8Array(authorBind.initialReplicas[0].logicalHash)
  authorBind.innerCodec = PEERIT_INNER_OPERATION_BATCH_V1_CODEC
  authorBind.innerLength = 8n
  authorBind.initialReplicas[0].sizeClass = 1
  assertPeeritAuthorBindInnerEnvelopeV1(authorBind)
  validator.validate('AuthorBindV1', catalog.AuthorBindV1.encode(authorBind))

  assert.equal(peeritAuthorBindCellSizeClassForInnerLengthV1(8n), 1)
  assert.equal(peeritAuthorBindCellSizeClassForInnerLengthV1(PEERIT_AUTHOR_BIND_CELL_CONTENT_CAPACITY_V1[1]), 1)
  assert.equal(peeritAuthorBindCellSizeClassForInnerLengthV1(PEERIT_AUTHOR_BIND_CELL_CONTENT_CAPACITY_V1[1] + 1n), 2)
  assert.equal(peeritAuthorBindCellSizeClassForInnerLengthV1(1048519n), 5)

  const nonMinimalClass = structuredClone(authorBind)
  nonMinimalClass.innerLength = PEERIT_AUTHOR_BIND_CELL_CONTENT_CAPACITY_V1[1] + 1n
  assert.throws(() => assertPeeritAuthorBindInnerEnvelopeV1(nonMinimalClass), error => error.code === 'BAD_AUTHOR_BIND')
  nonMinimalClass.initialReplicas[0].sizeClass = 2
  assertPeeritAuthorBindInnerEnvelopeV1(nonMinimalClass)
  validator.validate('AuthorBindV1', catalog.AuthorBindV1.encode(nonMinimalClass))

  const badCodec = structuredClone(authorBind)
  badCodec.innerCodec = PEERIT_INNER_OPERATION_BATCH_V1_CODEC - 1
  assert.throws(() => assertPeeritAuthorBindInnerEnvelopeV1(badCodec), error => error.code === 'BAD_AUTHOR_BIND')
  assert.throws(() => catalog.AuthorBindV1.encode(badCodec), error => error.code === 'BAD_PROFILE_CODEC_VALUE')

  const badLength = structuredClone(authorBind)
  badLength.innerLength = 7n
  assert.throws(() => assertPeeritAuthorBindInnerEnvelopeV1(badLength), error => error.code === 'BAD_AUTHOR_BIND')
  assert.throws(() => catalog.AuthorBindV1.encode(badLength), error => error.code === 'BAD_PROFILE_CODEC_VALUE')

  const badClass = structuredClone(authorBind)
  badClass.initialReplicas[0].sizeClass = 0
  assert.throws(() => assertPeeritAuthorBindInnerEnvelopeV1(badClass), error => error.code === 'BAD_AUTHOR_BIND')
  assert.throws(() => catalog.AuthorBindV1.encode(badClass), error => error.code === 'BAD_PROFILE_CODEC_VALUE')

  const mismatchedReplica = structuredClone(authorBind)
  const second = structuredClone(mismatchedReplica.initialReplicas[0])
  second.encodingCommitment[0] ^= 1
  mismatchedReplica.initialReplicas.push(second)
  assert.throws(() => assertPeeritAuthorBindInnerEnvelopeV1(mismatchedReplica), error => error.code === 'BAD_AUTHOR_BIND')
})

await test('embedded Ed25519 verifier accepts the exact domain+prefix and rejects a signature bitflip', () => {
  const value = fixtures.create('AvailabilityRootV1')
  const seed = new Uint8Array(32).fill(0x41)
  const publicKey = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  value.rootVerifyKey = publicKey
  const prefix = encodePeeritProfileRecordPrefixFromIr(compiled, PEERIT_PROFILE_INVENTORY, 'AvailabilityRootV1', value, 'signature', runtimeOptions)
  sodium.crypto_sign_detached(value.signature, concatBytes(asciiBytes('peerit.hiverelay.root.v1'), prefix), secretKey)
  const validator = createPeeritProfileValidatorV1(compiled, PEERIT_PROFILE_INVENTORY, { externalAuthorities: authorities.object })
  const encoded = catalog.AvailabilityRootV1.encode(value)
  validator.validate('AvailabilityRootV1', encoded)
  const bad = new Uint8Array(encoded)
  bad[bad.byteLength - 1] ^= 1
  assert.throws(() => validator.validate('AvailabilityRootV1', bad), error => error.code === 'INVALID_PROFILE_SIGNATURE')
})

await test('deterministic validator bundle imports as ESM and emits the frozen runtime vector', async () => {
  const artifact = new Uint8Array(fs.readFileSync(path.join(root, PROFILE_VALIDATOR_ARTIFACT_STATUS.artifact)))
  assert.equal(artifact.byteLength, PROFILE_VALIDATOR_ARTIFACT_STATUS.artifactBytes)
  assert.equal(bytesToHex(hashPeeritValidatorArtifactV1(artifact)), PROFILE_VALIDATOR_ARTIFACT_STATUS.validatorArtifactHash)
  const module = await import(`data:text/javascript;base64,${Buffer.from(artifact).toString('base64')}`)
  assert.equal(module.PEERIT_VALIDATOR_PROFILE_BINDING_V1.schemaCount, 78)
  const runtime = module.computePeeritValidatorRuntimeVectorV1()
  assert.equal(runtime.byteLength, 98)
  assert.deepEqual([...runtime.slice(0, 4)], [1, 1, 17, 17])
  assert.equal(bytesToHex(module.computePeeritValidatorRuntimeVectorSetHashV1()), PROFILE_VALIDATOR_ARTIFACT_STATUS.runtimeVectorSetHash)
})

process.stdout.write(`peerit profile validator tests: ${passed}/${passed} passed\n`)
