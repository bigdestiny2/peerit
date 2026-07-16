import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import sodium from 'sodium-javascript'
import sodiumNative from 'sodium-native'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  compilePeeritProfileCodecIr,
  createPeeritProfileCodecCatalogFromIr,
  encodePeeritProfileRecordPrefixFromIr
} from '../js/substrate/profile-codec-ir.mjs'
import { createPeeritProfileStructuralFixtureFactory } from '../js/substrate/profile-codec-fixtures.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import { authenticatePeeritProfileExternalCodecAuthorityV1 } from '../js/substrate/profile-external-authority.mjs'
import {
  createPeeritContextualGraphAuditAuthorityV1,
  createPeeritSupportingEvidenceAuditAuthorityV1,
  hashPeeritProfileRecordIdV1,
  hashPeeritProfilePinV1,
  PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1
} from '../js/substrate/profile-contextual-graph-validator.mjs'
import {
  createPeeritProfileValidatorV1,
  peeritProfileNamedSortProjection
} from '../js/substrate/profile-validator.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  domainLengthHash,
  u16Bytes,
  u32Bytes,
  u64Bytes
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

function keyPair (fill) {
  const publicKey = new Uint8Array(32)
  const secretKey = new Uint8Array(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, new Uint8Array(32).fill(fill))
  return { publicKey, secretKey }
}

function signLastField (schemaName, value, field, domain, secretKey) {
  const prefix = encodePeeritProfileRecordPrefixFromIr(compiled, PEERIT_PROFILE_INVENTORY, schemaName, value, field, runtimeOptions)
  sodium.crypto_sign_detached(value[field], concatBytes(asciiBytes(domain), prefix), secretKey)
}

function genericSupportingAuthority (overrides = {}) {
  const verifiers = {}
  for (let kind = 1; kind <= 6; kind++) verifiers[kind] = overrides[kind] || (() => ({ valid: true }))
  return createPeeritSupportingEvidenceAuditAuthorityV1(verifiers)
}

function evidenceStore () {
  const values = new Map()
  return {
    values,
    put (hash, bytes) { values.set(bytesToHex(hash), new Uint8Array(bytes)) },
    fetch ({ expectedHash }) {
      const value = values.get(bytesToHex(expectedHash))
      if (value == null) throw new Error('missing fixture evidence')
      return new Uint8Array(value)
    }
  }
}

function graphAuthority (store, options = {}) {
  return createPeeritContextualGraphAuditAuthorityV1({
    compiled,
    inventory: PEERIT_PROFILE_INVENTORY,
    catalog,
    externalAuthorityByName: authorities.map,
    sortProjection: peeritProfileNamedSortProjection,
    fetchByHash: store.fetch.bind(store),
    supportingEvidenceAuthority: options.supportingEvidenceAuthority || genericSupportingAuthority(),
    budgets: options.budgets || {}
  })
}

function makePin (sequence, predecessorBytes, pair = keyPair(41)) {
  const pin = fixtures.create('PeeritHiveRelayProfilePinV1', 1000 + Number(sequence))
  pin.releaseSequence = BigInt(sequence)
  pin.previousPinHash = predecessorBytes == null ? null : hashPeeritProfilePinV1(predecessorBytes)
  pin.emitSubstrate = fixtures.create('SubstrateTupleV1', 9000)
  pin.readSubstrates = [pin.emitSubstrate]
  pin.pinHistoryRetentionDays = 3650
  pin.migrationStage = 0
  pin.migrationTransitionEvidenceHash = null
  pin.legacyImportMode = 0
  pin.legacyReadMode = 0
  pin.legacyCutoffHash = null
  pin.migrationGenesisRecordId = null
  pin.cutoffActivationReleaseSequence = null
  pin.legacyRetirementEvidenceHash = null
  pin.legacyRetirementActivationReleaseSequence = null
  pin.releaseAuthoritySequence = 0n
  pin.releaseAuthorityPublicKey = new Uint8Array(pair.publicKey)
  pin.releaseAuthorityKeyId = blake2b256(concatBytes(asciiBytes('peerit.release-authority-key-id.v1'), pair.publicKey))
  pin.authorityTransitionHash = null
  signLastField('PeeritHiveRelayProfilePinV1', pin, 'signature', 'peerit.hiverelay.profile-pin.v1', pair.secretKey)
  return catalog.PeeritHiveRelayProfilePinV1.encode(pin)
}

let passed = 0
async function test (name, operation) {
  await operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

await test('production mode rejects omitted and unbranded contextual graph callbacks', () => {
  assert.throws(
    () => createPeeritProfileValidatorV1(compiled, PEERIT_PROFILE_INVENTORY, {
      externalAuthorities: authorities.object,
      production: true
    }),
    error => error.code === 'CONTEXTUAL_GRAPH_AUTHORITY_REQUIRED'
  )
  assert.throws(
    () => createPeeritProfileValidatorV1(compiled, PEERIT_PROFILE_INVENTORY, {
      externalAuthorities: authorities.object,
      validateGraph () {}
    }),
    error => error.code === 'UNBRANDED_CONTEXTUAL_GRAPH_CALLBACK_REJECTED'
  )
  const forgedAuditBrand = graphAuthority(evidenceStore(), {
    supportingEvidenceAuthority: genericSupportingAuthority({
      1: () => ({ valid: true }),
      2: () => ({ valid: true }),
      3: () => ({ valid: true }),
      4: () => ({ valid: true }),
      5: () => ({ valid: true }),
      6: () => ({ valid: true })
    })
  })
  assert.throws(
    () => createPeeritProfileValidatorV1(compiled, PEERIT_PROFILE_INVENTORY, {
      externalAuthorities: authorities.object,
      contextualGraphAuthority: forgedAuditBrand,
      production: true
    }),
    error => error.code === 'CONTEXTUAL_GRAPH_PRODUCTION_AUTHORITY_REQUIRED'
  )
})

await test('AuthorBind contextual validation fails closed until Cell readback authority exists', () => {
  assert.throws(
    () => graphAuthority(evidenceStore()).validateAuthorChain(new Uint8Array()),
    error => error.code === 'CONTEXTUAL_GRAPH_RUNTIME_UNAVAILABLE'
  )
})

await test('profile pin graph accepts one exact contiguous signed chain', () => {
  const store = evidenceStore()
  const pin0 = makePin(0)
  const pin1 = makePin(1, pin0)
  const pin2 = makePin(2, pin1)
  store.put(hashPeeritProfilePinV1(pin0), pin0)
  store.put(hashPeeritProfilePinV1(pin1), pin1)
  const chain = graphAuthority(store).validatePinChain(pin2)
  assert.equal(chain.length, 3)
  assert.deepEqual(chain.map(row => row.value.releaseSequence), [0n, 1n, 2n])
})

await test('profile pin graph rejects missing, substituted, duplicate-sequence, and over-depth predecessors', () => {
  const pin0 = makePin(0)
  const pin1 = makePin(1, pin0)
  const pin2 = makePin(2, pin1)

  const missing = evidenceStore()
  assert.throws(() => graphAuthority(missing).validatePinChain(pin2), error => error.code === 'FETCHED_EVIDENCE_UNAVAILABLE')

  const substituted = evidenceStore()
  substituted.values.set(bytesToHex(hashPeeritProfilePinV1(pin1)), pin0)
  assert.throws(() => graphAuthority(substituted).validatePinChain(pin2), error => error.code === 'FETCHED_EVIDENCE_HASH_MISMATCH')

  const duplicate = evidenceStore()
  const duplicateSequence = makePin(2, pin0)
  duplicate.put(hashPeeritProfilePinV1(pin0), pin0)
  assert.throws(() => graphAuthority(duplicate).validatePinChain(duplicateSequence), error => error.code === 'PROFILE_PIN_CHAIN_GAP_OR_FORK')

  const bounded = evidenceStore()
  bounded.put(hashPeeritProfilePinV1(pin0), pin0)
  bounded.put(hashPeeritProfilePinV1(pin1), pin1)
  assert.throws(
    () => graphAuthority(bounded, { budgets: { maximumGraphDepth: 2 } }).validatePinChain(pin2),
    error => error.code === 'CONTEXTUAL_GRAPH_BUDGET_EXCEEDED'
  )

  const witnessedFork = makePin(2, pin1, keyPair(42))
  bounded.put(hashPeeritProfilePinV1(pin1), pin1)
  assert.throws(
    () => graphAuthority(bounded).validatePinChain(witnessedFork, {
      witnessedPinHashes: new Map([['2', bytesToHex(hashPeeritProfilePinV1(pin2))]])
    }),
    error => error.code === 'PROFILE_PIN_SAME_SEQUENCE_FORK'
  )
})

function makeRoot (generation, seedBase) {
  const root = fixtures.create('AvailabilityRootV1', seedBase * 97)
  const signer = keyPair(seedBase)
  const recovery = [keyPair(seedBase + 1), keyPair(seedBase + 2), keyPair(seedBase + 3)]
    .sort((left, right) => compareBytes(left.publicKey, right.publicKey))
  const maintainers = [keyPair(seedBase + 4), keyPair(seedBase + 5), keyPair(seedBase + 6), keyPair(seedBase + 7)]
    .sort((left, right) => compareBytes(left.publicKey, right.publicKey))
  root.generation = BigInt(generation)
  root.rootVerifyKey = new Uint8Array(signer.publicKey)
  root.recoveryKeys = recovery.map(pair => new Uint8Array(pair.publicKey))
  root.recoveryThreshold = 2
  root.discoveryMaintainerKeys = maintainers.map(pair => new Uint8Array(pair.publicKey))
  root.discoveryMaintainerThreshold = 3
  signLastField('AvailabilityRootV1', root, 'signature', 'peerit.hiverelay.root.v1', signer.secretKey)
  const bytes = catalog.AvailabilityRootV1.encode(root)
  return { value: root, bytes, signer, recovery, maintainers, recordId: hashPeeritProfileRecordIdV1(1, bytes) }
}

function rootRotateCommitment (value) {
  const prefix = encodePeeritProfileRecordPrefixFromIr(compiled, PEERIT_PROFILE_INVENTORY, 'RootRotateV1', value, 'oldRootSignature', runtimeOptions).slice(2)
  return blake2b256(concatBytes(asciiBytes('peerit.hiverelay.root-rotate.v1'), u64Bytes(prefix.byteLength), prefix))
}

function makeRootRotation (previous, next, recoveryMode = false) {
  const value = fixtures.create('RootRotateV1', 7711)
  value.previousRootRecordId = new Uint8Array(previous.recordId)
  value.nextRootRecordId = new Uint8Array(next.recordId)
  value.previousGeneration = previous.value.generation
  value.nextGeneration = next.value.generation
  value.nextRootLogicalHash = new Uint8Array(32).fill(0x91)
  value.nextRootReplicas = value.nextRootReplicas.slice(0, 3)
  for (const binding of value.nextRootReplicas) binding.value.logicalHash = new Uint8Array(value.nextRootLogicalHash)
  value.nextRootReplicas.sort((left, right) => compareBytes(
    peeritProfileNamedSortProjection('RootRotateV1.nextRootReplicas[0]', null, left, new Uint8Array()),
    peeritProfileNamedSortProjection('RootRotateV1.nextRootReplicas[0]', null, right, new Uint8Array())
  ))
  value.discoveryRecoveryMergeHash = null
  value.discoveryRecoveryMergeReadCaps = []
  value.oldRootSignature = recoveryMode ? null : new Uint8Array(64)
  value.recoverySignatures = []
  value.newRootSignature = new Uint8Array(64)
  let commitment = rootRotateCommitment(value)
  if (recoveryMode) {
    value.recoverySignatures = previous.recovery.slice(0, 2).map(pair => ({
      recoveryKey: new Uint8Array(pair.publicKey),
      signature: new Uint8Array(64)
    }))
    commitment = rootRotateCommitment(value)
    for (let index = 0; index < value.recoverySignatures.length; index++) {
      sodium.crypto_sign_detached(value.recoverySignatures[index].signature, commitment, previous.recovery[index].secretKey)
    }
  } else {
    sodium.crypto_sign_detached(value.oldRootSignature, commitment, previous.signer.secretKey)
  }
  sodium.crypto_sign_detached(value.newRootSignature, commitment, next.signer.secretKey)
  return value
}

await test('root rotation verifies normal and exact 2-of-3 recovery commitments', () => {
  const previous = makeRoot(0, 51)
  const next = makeRoot(1, 81)
  const store = evidenceStore()
  const authority = graphAuthority(store)
  const context = { acceptedRootBytes: previous.bytes, nextRootBytes: next.bytes }
  const normal = makeRootRotation(previous, next, false)
  authority.validateRootRotation(catalog.RootRotateV1.encode(normal), context)
  const recovery = makeRootRotation(previous, next, true)
  authority.validateRootRotation(catalog.RootRotateV1.encode(recovery), context)

  recovery.recoverySignatures[1].recoveryKey = new Uint8Array(recovery.recoverySignatures[0].recoveryKey)
  assert.throws(
    () => authority.validateRootRotation(catalog.RootRotateV1.encode(recovery), context),
    error => ['BAD_PROFILE_CODEC_VALUE', 'CONTEXTUAL_GRAPH_DUPLICATE', 'INVALID_ROOT_RECOVERY_SIGNATURE'].includes(error.code)
  )

  const invalidThresholdSignature = makeRootRotation(previous, next, true)
  invalidThresholdSignature.recoverySignatures[0].signature[0] ^= 1
  assert.throws(
    () => authority.validateRootRotation(catalog.RootRotateV1.encode(invalidThresholdSignature), context),
    error => error.code === 'INVALID_ROOT_RECOVERY_SIGNATURE'
  )
})

function witnessMessage (witness) {
  return concatBytes(
    asciiBytes('peerit.hiverelay.operator-group-witness.v1'),
    witness.witnessGroupId,
    witness.witnessKey,
    u32Bytes(witness.issuedLeaseEpoch),
    u32Bytes(witness.expiresLeaseEpoch)
  )
}

function u8Array (values) {
  return concatBytes(Uint8Array.of(values.length), values)
}

function groupFields (group) {
  return concatBytes(
    group.groupId,
    group.operatorStatementKey,
    u8Array(group.continuityRoots),
    u8Array(group.maintainerKeys),
    u8Array(group.failureDomainCommitments),
    u8Array(group.profile1StoreFailureDomains.map(row => concatBytes(row.continuityRoot, row.storeId, row.localFailureDomainId, row.chaosEvidenceHash))),
    u32Bytes(group.issuedLeaseEpoch),
    u32Bytes(group.expiresLeaseEpoch)
  )
}

function groupCommitment (group) {
  const fields = groupFields(group)
  return blake2b256(concatBytes(asciiBytes('peerit.hiverelay.operator-group-statement.v1'), u64Bytes(fields.byteLength), fields))
}

function makeRegistry () {
  const value = fixtures.create('PeeritOperatorGroupRegistryV1', 9103)
  const witnesses = [keyPair(111), keyPair(112), keyPair(113)].map((pair, index) => {
    const witness = {
      witnessGroupId: new Uint8Array(32).fill(10 + index),
      witnessKey: new Uint8Array(pair.publicKey),
      issuedLeaseEpoch: 1,
      expiresLeaseEpoch: 100,
      witnessStatementSignature: new Uint8Array(64)
    }
    sodium.crypto_sign_detached(witness.witnessStatementSignature, witnessMessage(witness), pair.secretKey)
    return { pair, value: witness }
  })
  witnesses.sort((left, right) => compareBytes(concatBytes(left.value.witnessGroupId, left.value.witnessKey), concatBytes(right.value.witnessGroupId, right.value.witnessKey)))
  const groups = [keyPair(121), keyPair(122), keyPair(123)].map((pair, index) => {
    const group = {
      groupId: new Uint8Array(32).fill(50 + index),
      operatorStatementKey: new Uint8Array(pair.publicKey),
      continuityRoots: [new Uint8Array(32).fill(70 + index)],
      maintainerKeys: [],
      failureDomainCommitments: [new Uint8Array(32).fill(90 + index)],
      profile1StoreFailureDomains: [],
      issuedLeaseEpoch: 1,
      expiresLeaseEpoch: 100,
      operatorSignature: new Uint8Array(64),
      witnessSignatures: witnesses.slice(0, 2).map(row => ({ witnessKey: new Uint8Array(row.pair.publicKey), signature: new Uint8Array(64) }))
    }
    const commitment = groupCommitment(group)
    sodium.crypto_sign_detached(group.operatorSignature, commitment, pair.secretKey)
    for (let witnessIndex = 0; witnessIndex < group.witnessSignatures.length; witnessIndex++) {
      sodium.crypto_sign_detached(group.witnessSignatures[witnessIndex].signature, commitment, witnesses[witnessIndex].pair.secretKey)
    }
    group.witnessSignatures.sort((left, right) => compareBytes(concatBytes(left.witnessKey, left.signature), concatBytes(right.witnessKey, right.signature)))
    return { pair, value: group }
  })
  groups.sort((left, right) => compareBytes(left.value.groupId, right.value.groupId))
  value.registrySequence = 0n
  value.previousRegistryHash = null
  value.witnessThreshold = 2
  value.witnesses = witnesses.map(row => row.value)
  value.groups = groups.map(row => row.value)
  value.registryWitnessSignatures = [new Uint8Array(96), new Uint8Array(96)]
  const resignRegistry = () => {
    const prefix = encodePeeritProfileRecordPrefixFromIr(compiled, PEERIT_PROFILE_INVENTORY, 'PeeritOperatorGroupRegistryV1', value, 'registryWitnessSignatures', runtimeOptions)
    const message = concatBytes(asciiBytes('peerit.hiverelay.operator-group-registry.v1'), prefix)
    value.registryWitnessSignatures = witnesses.slice(0, 2).map(row => {
      const packed = new Uint8Array(96)
      packed.set(row.pair.publicKey)
      sodium.crypto_sign_detached(packed.subarray(32), message, row.pair.secretKey)
      return packed
    }).sort(compareBytes)
  }
  resignRegistry()
  return { value, witnesses, groups, resignRegistry }
}

await test('operator registry verifies nested thresholds and rejects global identity collapse', () => {
  const store = evidenceStore()
  const authority = graphAuthority(store)
  const fixture = makeRegistry()
  authority.validateOperatorGroupRegistry(catalog.PeeritOperatorGroupRegistryV1.encode(fixture.value), { effectiveLeaseEpoch: 50 })

  fixture.value.groups[1].continuityRoots = [new Uint8Array(fixture.value.groups[0].continuityRoots[0])]
  const changed = fixture.value.groups[1]
  const commitment = groupCommitment(changed)
  sodium.crypto_sign_detached(changed.operatorSignature, commitment, fixture.groups[1].pair.secretKey)
  for (const signature of changed.witnessSignatures) {
    const signer = fixture.witnesses.find(row => bytesEqual(row.pair.publicKey, signature.witnessKey))
    sodium.crypto_sign_detached(signature.signature, commitment, signer.pair.secretKey)
  }
  fixture.resignRegistry()
  assert.throws(
    () => authority.validateOperatorGroupRegistry(catalog.PeeritOperatorGroupRegistryV1.encode(fixture.value), { effectiveLeaseEpoch: 50 }),
    error => error.code === 'CONTEXTUAL_GRAPH_DUPLICATE'
  )
})

function custodyEnvelopeAad (envelope) {
  const prefix = encodePeeritProfileRecordPrefixFromIr(compiled, PEERIT_PROFILE_INVENTORY, 'PeeritCustodyEnvelopeV1', envelope, 'payloadNonce', runtimeOptions).slice(2)
  return concatBytes(prefix, u32Bytes(envelope.sealedPayload.byteLength))
}

function custodyShareAad (share) {
  return encodePeeritProfileRecordPrefixFromIr(compiled, PEERIT_PROFILE_INVENTORY, 'PeeritCustodyEncryptedShareV1', share, 'sealedShare', runtimeOptions).slice(2)
}

function x25519Pair (fill) {
  const privateKey = new Uint8Array(32).fill(fill)
  const publicKey = new Uint8Array(32)
  sodium.crypto_scalarmult_base(publicKey, privateKey)
  return { privateKey, publicKey }
}

function makeCustodyEnvelope () {
  const payload = fixtures.create('PeeritCustodySeedPayloadV1', 4411)
  const signing = keyPair(141)
  payload.secretKind = 1
  payload.secretSeed = new Uint8Array(32).fill(141)
  payload.derivedPublicKey = new Uint8Array(signing.publicKey)
  const plaintext = catalog.PeeritCustodySeedPayloadV1.encode(payload)
  const dataKey = new Uint8Array(32)
  const coefficient = new Uint8Array(32)
  for (let index = 0; index < 32; index++) {
    dataKey[index] = 1 + index
    coefficient[index] = 0xa5 ^ index
  }
  const custodySetId = new Uint8Array(32).fill(0x51)
  const keyCommitment = blake2b256(concatBytes(asciiBytes('peerit.hiverelay.custody-key.v1'), custodySetId, dataKey))
  const envelope = fixtures.create('PeeritCustodyEnvelopeV1', 5519)
  envelope.custodySetId = custodySetId
  envelope.bundleKind = 1
  envelope.plaintextCodec = 1
  envelope.plaintextLength = BigInt(plaintext.byteLength)
  envelope.plaintextHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-plaintext.v1'),
    Uint8Array.of(1),
    u16Bytes(1),
    u64Bytes(plaintext.byteLength),
    plaintext
  ))
  envelope.keyCommitment = keyCommitment
  envelope.payloadNonce = new Uint8Array(24).fill(0x61)
  envelope.sealedPayload = new Uint8Array(plaintext.byteLength + 16)
  const custodians = [x25519Pair(151), x25519Pair(152), x25519Pair(153)]
  const ephemerals = [x25519Pair(161), x25519Pair(162), x25519Pair(163)]
  envelope.encryptedShares = custodians.map((custodian, index) => ({
    version: 1,
    custodySetId: new Uint8Array(custodySetId),
    bundleKind: 1,
    shareIndex: index + 1,
    threshold: 2,
    totalShares: 3,
    keyCommitment: new Uint8Array(keyCommitment),
    sealedPayloadHash: new Uint8Array(32).fill(1),
    custodianPublicKey: new Uint8Array(custodian.publicKey),
    ephemeralPublicKey: new Uint8Array(ephemerals[index].publicKey),
    nonce: new Uint8Array(24).fill(0x71 + index),
    sealedShare: new Uint8Array(48)
  }))
  envelope.sealedPayload = PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1.xchacha20poly1305Encrypt(
    plaintext,
    custodyEnvelopeAad(envelope),
    envelope.payloadNonce,
    dataKey
  )
  const sealedPayloadHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.custody-sealed-payload.v1'),
    u64Bytes(envelope.sealedPayload.byteLength),
    envelope.sealedPayload
  ))
  for (let index = 0; index < envelope.encryptedShares.length; index++) {
    const share = envelope.encryptedShares[index]
    share.sealedPayloadHash = new Uint8Array(sealedPayloadHash)
    const shareBytes = new Uint8Array(32)
    for (let byte = 0; byte < 32; byte++) {
      shareBytes[byte] = dataKey[byte] ^ PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1.gfMultiply(coefficient[byte], index + 1)
    }
    const shared = new Uint8Array(32)
    sodium.crypto_scalarmult(shared, ephemerals[index].privateKey, custodians[index].publicKey)
    const shareKey = hkdf(sha256, shared, custodySetId, concatBytes(
      asciiBytes('peerit.hiverelay.custody-share-key.v1'),
      Uint8Array.of(1, index + 1),
      custodians[index].publicKey,
      ephemerals[index].publicKey
    ), 32)
    share.sealedShare = PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1.xchacha20poly1305Encrypt(shareBytes, custodyShareAad(share), share.nonce, shareKey)
    shared.fill(0)
    shareKey.fill(0)
    shareBytes.fill(0)
  }
  dataKey.fill(0)
  coefficient.fill(0)
  return { envelope, plaintext, payload, custodians }
}

await test('custody reconstruction authenticates exact AAD, recipient, shares, key, payload hash, and codec', () => {
  const store = evidenceStore()
  const authority = graphAuthority(store)
  const fixture = makeCustodyEnvelope()
  const bytes = catalog.PeeritCustodyEnvelopeV1.encode(fixture.envelope)
  const recovered = authority.recoverCustodyEnvelope(bytes, [fixture.custodians[0].privateKey, fixture.custodians[1].privateKey])
  assert.equal(bytesEqual(recovered.plaintext, fixture.plaintext), true)
  assert.equal(bytesEqual(recovered.value.derivedPublicKey, fixture.payload.derivedPublicKey), true)

  const corrupted = structuredClone(fixture.envelope)
  corrupted.encryptedShares[0].sealedShare[0] ^= 1
  const corruptedBytes = catalog.PeeritCustodyEnvelopeV1.encode(corrupted)
  assert.throws(
    () => authority.recoverCustodyEnvelope(corruptedBytes, [fixture.custodians[0].privateKey, fixture.custodians[1].privateKey]),
    error => error.code === 'CUSTODY_AEAD_FAILED'
  )
  const recoveredAroundOneMalicious = authority.recoverCustodyEnvelope(corruptedBytes, fixture.custodians.map(row => row.privateKey))
  assert.equal(bytesEqual(recoveredAroundOneMalicious.plaintext, fixture.plaintext), true)

  const aadTamper = structuredClone(fixture.envelope)
  aadTamper.payloadNonce[0] ^= 1
  assert.throws(
    () => authority.recoverCustodyEnvelope(catalog.PeeritCustodyEnvelopeV1.encode(aadTamper), [fixture.custodians[0].privateKey, fixture.custodians[1].privateKey]),
    error => error.code === 'CUSTODY_RECONSTRUCTION_FAILED'
  )
  assert.throws(
    () => authority.recoverCustodyEnvelope(bytes, [x25519Pair(201).privateKey, fixture.custodians[1].privateKey]),
    error => error.code === 'CUSTODY_WRONG_RECIPIENT'
  )
})

await test('portable XChaCha20-Poly1305 bytes equal libsodium-native', () => {
  const plaintext = new Uint8Array(257).map((_, index) => index & 0xff)
  const aad = new Uint8Array(93).map((_, index) => (index * 7) & 0xff)
  const nonce = new Uint8Array(24).map((_, index) => (index * 11) & 0xff)
  const key = new Uint8Array(32).map((_, index) => (index * 13) & 0xff)
  const portable = PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1.xchacha20poly1305Encrypt(plaintext, aad, nonce, key)
  const native = new Uint8Array(plaintext.byteLength + 16)
  sodiumNative.crypto_aead_xchacha20poly1305_ietf_encrypt(native, plaintext, aad, null, nonce, key)
  assert.equal(bytesEqual(portable, native), true)
  assert.equal(bytesEqual(PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1.xchacha20poly1305Decrypt(native, aad, nonce, key), plaintext), true)
})

function supportingHash (kind, bytes) {
  return blake2b256(concatBytes(
    asciiBytes('peerit.write-supporting-evidence.v1'),
    Uint8Array.of(kind),
    u64Bytes(bytes.byteLength),
    bytes
  ))
}

function operationRoot (entries) {
  if (entries.length === 0) return blake2b256(asciiBytes('peerit.write-operation-evidence-empty.v1'))
  let level = entries.map(entry => domainLengthHash('peerit.write-operation-evidence-leaf.v1', catalog.PeeritWriteOperationEvidenceV1.encode(entry)))
  let treeLevel = 1
  while (level.length > 1) {
    const next = []
    for (let index = 0; index < level.length; index += 2) {
      next.push(index + 1 === level.length
        ? level[index]
        : blake2b256(concatBytes(asciiBytes('peerit.write-operation-evidence-node.v1'), u32Bytes(treeLevel), level[index], level[index + 1])))
    }
    level = next
    treeLevel++
  }
  return level[0]
}

function qualificationSubject (bundle) {
  const substrate = catalog.SubstrateTupleV1.encode(bundle.substrate)
  return blake2b256(concatBytes(
    asciiBytes('peerit.release-qualification-subject.v1'),
    bundle.appArtifactHash,
    bundle.validatorArtifactHash,
    bundle.profileSpecHash,
    bundle.profileAbiHash,
    bundle.profileVectorSetHash,
    bundle.availabilityPolicyHash,
    bundle.recommendedBootstrapSetHash,
    bundle.webAssetManifestHash,
    u64Bytes(substrate.byteLength),
    substrate,
    Uint8Array.of(bundle.measuredMigrationStage)
  ))
}

function makeQualificationFixture ({ failureBits = 0, shardWindowDelta = 0 } = {}) {
  const store = evidenceStore()
  const logicalIntentEvidenceId = new Uint8Array(32).fill(0x31)
  const versionBytes = Uint8Array.of(0x51, 1, 2, 3)
  const platformBytes = Uint8Array.of(0x52, 4, 5, 6)
  const captureBytes = Uint8Array.of(0x22, 1, 7, 8)
  const runtimeVersionHash = supportingHash(5, versionBytes)
  const platformConfigurationHash = supportingHash(5, platformBytes)
  const captureEvidenceHash = supportingHash(2, captureBytes)
  const runtimeEvidenceKeyHash = blake2b256(concatBytes(
    asciiBytes('peerit.write-runtime-evidence-key.v1'),
    Uint8Array.of(1),
    runtimeVersionHash,
    platformConfigurationHash,
    captureEvidenceHash
  ))
  const ledgerBytes = concatBytes(Uint8Array.of(0x44), logicalIntentEvidenceId)
  const resultBytes = concatBytes(Uint8Array.of(0x11), logicalIntentEvidenceId, Uint8Array.of(1, 0))
  const ledgerHash = supportingHash(4, ledgerBytes)
  const resultHash = supportingHash(1, resultBytes)
  const artifacts = [
    { evidenceKind: 4, bytes: ledgerBytes, supportingEvidenceHash: ledgerHash },
    { evidenceKind: 1, bytes: resultBytes, supportingEvidenceHash: resultHash },
    { evidenceKind: 5, bytes: versionBytes, supportingEvidenceHash: runtimeVersionHash },
    { evidenceKind: 5, bytes: platformBytes, supportingEvidenceHash: platformConfigurationHash },
    { evidenceKind: 2, bytes: captureBytes, supportingEvidenceHash: captureEvidenceHash }
  ].sort((left, right) => compareBytes(
    concatBytes(left.supportingEvidenceHash, Uint8Array.of(left.evidenceKind)),
    concatBytes(right.supportingEvidenceHash, Uint8Array.of(right.evidenceKind))
  ))
  const entry = {
    version: 1,
    logicalIntentEvidenceId,
    attemptedUnixMillis: 1001n,
    terminalClass: 1,
    terminalUnixMillis: 1002n,
    runtimeEvidenceKeyHash,
    failureBits,
    supportingEvidenceHashes: [ledgerHash, resultHash].sort(compareBytes)
  }
  const rootHash = operationRoot([entry])
  const bundle = fixtures.create('PeeritReleaseQualificationEvidenceBundleV1', 8121)
  bundle.measuredMigrationStage = 0
  bundle.evidenceBaseUrl = new TextEncoder().encode('https://evidence.peerit.site/v1')
  bundle.windowStartedUnixMillis = 1000n
  bundle.windowEndedUnixMillis = 2000n
  bundle.attemptedLogicalWrites = 1n
  bundle.terminalSuccessfulWrites = 1n
  bundle.terminalFailedWrites = 0n
  bundle.pendingOrUnknownWrites = 0n
  bundle.acknowledgedWriteLosses = (failureBits & 1) === 0 ? 0n : 1n
  bundle.unresolvedLegacyOnlyWrites = (failureBits & 2) === 0 ? 0n : 1n
  bundle.forbiddenLegacyWrites = (failureBits & 4) === 0 ? 0n : 1n
  bundle.signatureOrCodecDisagreements = (failureBits & 8) === 0 ? 0n : 1n
  bundle.floorRollbacks = (failureBits & 16) === 0 ? 0n : 1n
  bundle.hiddenPrivacyDowngrades = (failureBits & 32) === 0 ? 0n : 1n
  bundle.operationEvidenceCount = 1n
  bundle.operationEvidenceRoot = rootHash
  bundle.reconstructionEvidenceHashes = []
  bundle.qualificationSubjectHash = qualificationSubject(bundle)

  const shard = {
    version: 1,
    qualificationSubjectHash: new Uint8Array(bundle.qualificationSubjectHash),
    windowStartedUnixMillis: bundle.windowStartedUnixMillis + BigInt(shardWindowDelta),
    windowEndedUnixMillis: bundle.windowEndedUnixMillis,
    entries: [entry]
  }
  const shardBytes = catalog.PeeritWriteOperationEvidenceShardV1.encode(shard)
  const shardHash = domainLengthHash('peerit.write-operation-evidence-shard.v1', shardBytes)
  const manifest = {
    version: 1,
    qualificationSubjectHash: new Uint8Array(bundle.qualificationSubjectHash),
    windowStartedUnixMillis: bundle.windowStartedUnixMillis,
    windowEndedUnixMillis: bundle.windowEndedUnixMillis,
    totalEntryCount: 1n,
    operationEvidenceRoot: rootHash,
    shards: [{
      firstLogicalIntentEvidenceId: new Uint8Array(logicalIntentEvidenceId),
      lastLogicalIntentEvidenceId: new Uint8Array(logicalIntentEvidenceId),
      entryCount: 1n,
      entryMerkleRoot: rootHash,
      shardArtifactHash: shardHash
    }]
  }
  const manifestBytes = catalog.PeeritWriteOperationEvidenceManifestV1.encode(manifest)
  bundle.operationEvidenceManifestHash = domainLengthHash('peerit.write-operation-evidence-manifest.v1', manifestBytes)
  const supportingManifest = {
    version: 1,
    qualificationSubjectHash: new Uint8Array(bundle.qualificationSubjectHash),
    windowStartedUnixMillis: bundle.windowStartedUnixMillis,
    windowEndedUnixMillis: bundle.windowEndedUnixMillis,
    artifacts: artifacts.map(row => ({
      supportingEvidenceHash: new Uint8Array(row.supportingEvidenceHash),
      evidenceKind: row.evidenceKind,
      byteLength: BigInt(row.bytes.byteLength)
    }))
  }
  const supportingManifestBytes = catalog.PeeritWriteSupportingEvidenceManifestV1.encode(supportingManifest)
  bundle.supportingEvidenceManifestHash = domainLengthHash('peerit.write-supporting-evidence-manifest.v1', supportingManifestBytes)
  bundle.runtimeEvidence = [{
    version: 1,
    runtimeEvidenceKeyHash,
    runtimeClass: 1,
    runtimeVersionHash,
    platformConfigurationHash,
    captureEvidenceHash,
    attemptedLogicalWrites: 1n,
    terminalSuccessfulWrites: 1n,
    terminalFailedWrites: 0n,
    pendingOrUnknownWrites: 0n,
    operationEvidenceCount: 1n,
    operationEvidenceRoot: rootHash
  }]
  const bundleBytes = catalog.PeeritReleaseQualificationEvidenceBundleV1.encode(bundle)
  store.put(shardHash, shardBytes)
  store.put(bundle.operationEvidenceManifestHash, manifestBytes)
  store.put(bundle.supportingEvidenceManifestHash, supportingManifestBytes)
  for (const row of artifacts) store.put(row.supportingEvidenceHash, row.bytes)
  const supportingEvidenceAuthority = genericSupportingAuthority({
    1: ({ bytes }) => ({
      valid: bytes[0] === 0x11,
      logicalIntentEvidenceId: bytes.slice(1, 33),
      terminalClass: bytes[33],
      failureBits: bytes[34]
    }),
    2: ({ bytes }) => ({ valid: bytes[0] === 0x22, runtimeClass: bytes[1] }),
    4: ({ bytes }) => ({ valid: bytes[0] === 0x44, logicalIntentEvidenceId: bytes.slice(1, 33) }),
    5: ({ bytes }) => ({ valid: bytes[0] === 0x51 || bytes[0] === 0x52 })
  })
  return { store, bundle, bundleBytes, supportingEvidenceAuthority }
}

await test('qualification evidence reconstructs exact shards, Merkle roots, typed facts, runtime rows, counts, and windows', () => {
  const fixture = makeQualificationFixture()
  const result = graphAuthority(fixture.store, { supportingEvidenceAuthority: fixture.supportingEvidenceAuthority })
    .validateQualificationEvidenceBundle(fixture.bundleBytes)
  assert.equal(result.operationCount, 1)

  const badCounter = structuredClone(fixture.bundle)
  badCounter.terminalSuccessfulWrites = 0n
  badCounter.pendingOrUnknownWrites = 1n
  assert.throws(
    () => graphAuthority(fixture.store, { supportingEvidenceAuthority: fixture.supportingEvidenceAuthority })
      .validateQualificationEvidenceBundle(catalog.PeeritReleaseQualificationEvidenceBundleV1.encode(badCounter)),
    error => error.code === 'BAD_QUALIFICATION_EVIDENCE_AGGREGATE'
  )

  const wrongWindow = makeQualificationFixture({ shardWindowDelta: 1 })
  assert.throws(
    () => graphAuthority(wrongWindow.store, { supportingEvidenceAuthority: wrongWindow.supportingEvidenceAuthority })
      .validateQualificationEvidenceBundle(wrongWindow.bundleBytes),
    error => error.code === 'BAD_OPERATION_EVIDENCE_SHARD_BINDING'
  )

  const falseSummary = makeQualificationFixture({ failureBits: 1 })
  assert.throws(
    () => graphAuthority(falseSummary.store, { supportingEvidenceAuthority: falseSummary.supportingEvidenceAuthority })
      .validateQualificationEvidenceBundle(falseSummary.bundleBytes),
    error => error.code === 'SUPPORTING_EVIDENCE_SUMMARY_MISMATCH'
  )

  const oversize = makeQualificationFixture()
  const oversizedManifest = new Uint8Array(1048577).fill(0x7a)
  oversize.bundle.operationEvidenceManifestHash = domainLengthHash('peerit.write-operation-evidence-manifest.v1', oversizedManifest)
  oversize.store.put(oversize.bundle.operationEvidenceManifestHash, oversizedManifest)
  assert.throws(
    () => graphAuthority(oversize.store, { supportingEvidenceAuthority: oversize.supportingEvidenceAuthority })
      .validateQualificationEvidenceBundle(catalog.PeeritReleaseQualificationEvidenceBundleV1.encode(oversize.bundle)),
    error => error.code === 'FETCHED_EVIDENCE_OVERSIZE'
  )
})

function makeLegacyArchiveFixture () {
  const store = evidenceStore()
  const release = keyPair(211)
  const source = {
    version: 1,
    sourceRelayIdentity: new Uint8Array(32).fill(0x21),
    sourceDescriptorHash: new Uint8Array(32).fill(0x22),
    legacyServiceId: new TextEncoder().encode('outboxlog-v1'),
    terminalHeadBytes: null,
    terminalHeadHash: null,
    snapshotStatus: 2
  }
  const sourceSetBytes = catalog.LegacySourceSetV1.encode({
    version: 1,
    sources: [{
      sourceRelayIdentity: source.sourceRelayIdentity,
      sourceDescriptorHash: source.sourceDescriptorHash,
      legacyServiceId: source.legacyServiceId
    }]
  })
  const sourceSetHash = domainLengthHash('peerit.hiverelay.legacy-source-set-hash.v1', sourceSetBytes)
  const pendingPinValue = catalog.PeeritHiveRelayProfilePinV1.decode(makePin(0, null, release))
  pendingPinValue.legacySourceSetHash = new Uint8Array(sourceSetHash)
  signLastField('PeeritHiveRelayProfilePinV1', pendingPinValue, 'signature', 'peerit.hiverelay.profile-pin.v1', release.secretKey)
  const pendingPinBytes = catalog.PeeritHiveRelayProfilePinV1.encode(pendingPinValue)
  const pendingPinHash = hashPeeritProfilePinV1(pendingPinBytes)
  store.put(pendingPinHash, pendingPinBytes)

  const cutoff = fixtures.create('LegacyCutoffV1', 9217)
  cutoff.legacyWriteCutoffReleaseSequence = 0n
  cutoff.cutoffPendingPinHash = new Uint8Array(pendingPinHash)
  cutoff.legacySourceSetHash = new Uint8Array(sourceSetHash)
  cutoff.drainStartedUnixMillis = 1000000n
  cutoff.drainEndedUnixMillis = cutoff.drainStartedUnixMillis + 86400000n
  cutoff.sources = [source]
  cutoff.releaseAuthoritySequence = pendingPinValue.releaseAuthoritySequence
  cutoff.releaseAuthorityKeyId = new Uint8Array(pendingPinValue.releaseAuthorityKeyId)
  signLastField('LegacyCutoffV1', cutoff, 'signature', 'peerit.hiverelay.legacy-cutoff.v1', release.secretKey)
  const cutoffBytes = catalog.LegacyCutoffV1.encode(cutoff)
  const cutoffHash = domainLengthHash('peerit.hiverelay.legacy-cutoff-hash.v1', cutoffBytes)

  const retained = fixtures.create('LegacyValidRecordEntryV1', 9301)
  retained.category = 1
  retained.logicalRecordId = new Uint8Array(32).fill(0x41)
  retained.exactOriginalSignedBytes = new TextEncoder().encode('canonical signed legacy record')
  retained.exactOriginalSignedBytesHash = blake2b256(retained.exactOriginalSignedBytes)
  retained.validatorResultCode = 0
  retained.newReplicaBindings = []
  const archiveEntry = { variant: 1, value: retained }
  const taggedEntryBytes = catalog.LegacyArchiveEntryV1.encode(archiveEntry)
  const untaggedEntryBytes = catalog.LegacyValidRecordEntryV1.encode(retained)
  const entryHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.legacy-archive-entry.v1'),
    Uint8Array.of(1),
    u64Bytes(taggedEntryBytes.byteLength),
    taggedEntryBytes
  ))
  const archive = { version: 1, cutoffBytes, entries: [archiveEntry] }
  const archiveBytes = catalog.PeeritLegacyArchiveV1.encode(archive)
  const archiveArtifactHash = domainLengthHash('peerit.hiverelay.legacy-archive.v1', archiveBytes)
  const retainedRoot = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.legacy-category-leaf.v1'),
    Uint8Array.of(1),
    u64Bytes(untaggedEntryBytes.byteLength),
    untaggedEntryBytes
  ))
  const emptyRoot = category => blake2b256(concatBytes(asciiBytes('peerit.hiverelay.legacy-category-empty.v1'), Uint8Array.of(category)))
  const censusRoot = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.census-leaf.v1'),
    retained.logicalRecordId,
    retained.exactOriginalSignedBytesHash
  ))
  const originalRecordsLogicalHash = blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.original-records.v1'),
    retained.logicalRecordId,
    u64Bytes(retained.exactOriginalSignedBytes.byteLength),
    retained.exactOriginalSignedBytes
  ))
  const index = {
    version: 1,
    legacyArchiveArtifactHash: archiveArtifactHash,
    legacyCutoffHash: cutoffHash,
    retainedRecordCount: 1n,
    conflictRecordCount: 0n,
    invalidRecordCount: 0n,
    missingRangeCount: 0n,
    retainedCategoryRoot: retainedRoot,
    conflictCategoryRoot: emptyRoot(2),
    invalidCategoryRoot: emptyRoot(3),
    missingCategoryRoot: emptyRoot(4),
    legacyCensusRoot: censusRoot,
    originalRecordsLogicalHash,
    entries: [{
      category: 1,
      primarySortId: retained.logicalRecordId,
      secondarySortId: retained.exactOriginalSignedBytesHash,
      entryHash,
      archiveOffset: BigInt(archiveBytes.byteLength - taggedEntryBytes.byteLength),
      archiveLength: taggedEntryBytes.byteLength
    }]
  }
  let indexBytes = catalog.LegacyArchiveIndexV1.encode(index)
  let indexHash = domainLengthHash('peerit.hiverelay.legacy-archive-index.v1', indexBytes)
  const distribution = fixtures.create('LegacyArchiveDistributionV1', 9403)
  distribution.legacyArchiveArtifactHash = new Uint8Array(archiveArtifactHash)
  distribution.legacyArchiveIndexHash = new Uint8Array(indexHash)
  distribution.copies = [
    {
      copyKind: 1,
      operatorGroupId: new Uint8Array(32).fill(0x61),
      failureDomainCommitment: new Uint8Array(32).fill(0x71),
      locator: new TextEncoder().encode('hyperdrive://legacy-peerit-fixture'),
      artifactHash: new Uint8Array(archiveArtifactHash),
      indexHash: new Uint8Array(indexHash)
    },
    {
      copyKind: 2,
      operatorGroupId: new Uint8Array(32).fill(0x62),
      failureDomainCommitment: new Uint8Array(32).fill(0x72),
      locator: new TextEncoder().encode('https://archive.example/peerit-v1.cenc'),
      artifactHash: new Uint8Array(archiveArtifactHash),
      indexHash: new Uint8Array(indexHash)
    }
  ]
  distribution.releaseAuthoritySequence = pendingPinValue.releaseAuthoritySequence
  distribution.releaseAuthorityKeyId = new Uint8Array(pendingPinValue.releaseAuthorityKeyId)
  const rebuild = () => {
    indexBytes = catalog.LegacyArchiveIndexV1.encode(index)
    indexHash = domainLengthHash('peerit.hiverelay.legacy-archive-index.v1', indexBytes)
    distribution.legacyArchiveIndexHash = new Uint8Array(indexHash)
    for (const copy of distribution.copies) copy.indexHash = new Uint8Array(indexHash)
    signLastField('LegacyArchiveDistributionV1', distribution, 'releaseSignature', 'peerit.hiverelay.legacy-archive-distribution.v1', release.secretKey)
    const distributionBytes = catalog.LegacyArchiveDistributionV1.encode(distribution)
    const bundle = { version: 1, archiveBytes, indexBytes, distributionBytes }
    return {
      bundle,
      bundleBytes: catalog.LegacyArchiveBundleV1.encode(bundle),
      indexBytes,
      indexHash,
      distributionBytes
    }
  }
  return { store, release, pendingPinValue, pendingPinBytes, cutoff, cutoffBytes, archive, archiveBytes, retained, index, distribution, rebuild }
}

await test('deterministic legacy archive rebuilds cutoff/source set, offsets, hashes, category/census roots, counts, and distribution', () => {
  const fixture = makeLegacyArchiveFixture()
  const authority = graphAuthority(fixture.store)
  const built = fixture.rebuild()
  const result = authority.validateDeterministicLegacyArchiveBundle(built.bundleBytes)
  assert.equal(result.counts.retained, 1n)
  assert.equal(result.counts.conflicts, 0n)
  assert.equal(bytesEqual(result.cutoffResult.sourceSetHash, fixture.cutoff.legacySourceSetHash), true)

  fixture.index.entries[0].archiveOffset++
  const badOffset = fixture.rebuild()
  assert.throws(
    () => authority.validateDeterministicLegacyArchiveBundle(badOffset.bundleBytes),
    error => error.code === 'BAD_LEGACY_ARCHIVE_INDEX'
  )
  fixture.index.entries[0].archiveOffset--

  fixture.index.legacyCensusRoot[0] ^= 1
  const badRoot = fixture.rebuild()
  assert.throws(
    () => authority.validateDeterministicLegacyArchiveBundle(badRoot.bundleBytes),
    error => error.code === 'BAD_LEGACY_ARCHIVE_SUMMARY'
  )
})

function sortReplicaBindings (field, values) {
  return values.sort((left, right) => compareBytes(
    peeritProfileNamedSortProjection(`MigrationGenesisV1.${field}[0]`, null, left, new Uint8Array()),
    peeritProfileNamedSortProjection(`MigrationGenesisV1.${field}[0]`, null, right, new Uint8Array())
  ))
}

function makeGenesisFixture () {
  const archiveFixture = makeLegacyArchiveFixture()
  const built = archiveFixture.rebuild()
  const authority = graphAuthority(archiveFixture.store)
  const archiveResult = authority.validateDeterministicLegacyArchiveBundle(built.bundleBytes)
  archiveFixture.store.put(archiveResult.bundleLogicalHash, built.bundleBytes)
  const genesis = fixtures.create('MigrationGenesisV1', 9511)
  genesis.releaseSequence = 1n
  genesis.releaseAuthorityKeyId = new Uint8Array(archiveFixture.pendingPinValue.releaseAuthorityKeyId)
  genesis.cutoffPendingPinHash = hashPeeritProfilePinV1(archiveFixture.pendingPinBytes)
  genesis.legacySourceSetHash = new Uint8Array(archiveFixture.cutoff.legacySourceSetHash)
  genesis.legacyCutoffHash = new Uint8Array(archiveResult.cutoffResult.cutoffHash)
  genesis.legacyCensusRoot = new Uint8Array(archiveResult.roots.census)
  genesis.retainedRecordCount = archiveResult.counts.retained
  genesis.invalidRecordCount = archiveResult.counts.invalid
  genesis.conflictRecordCount = archiveResult.counts.conflicts
  genesis.missingRangeCount = archiveResult.counts.missing
  genesis.invalidCategoryRoot = new Uint8Array(archiveResult.roots.invalid)
  genesis.conflictCategoryRoot = new Uint8Array(archiveResult.roots.conflict)
  genesis.missingCategoryRoot = new Uint8Array(archiveResult.roots.missing)
  genesis.legacyArchiveArtifactHash = new Uint8Array(archiveResult.archiveArtifactHash)
  genesis.legacyArchiveIndexHash = new Uint8Array(archiveResult.archiveIndexHash)
  genesis.legacyArchiveDistributionHash = new Uint8Array(archiveResult.distributionHash)
  genesis.legacyArchiveBundleLogicalHash = new Uint8Array(archiveResult.bundleLogicalHash)
  genesis.originalRecordsLogicalHash = new Uint8Array(archiveResult.originalRecordsLogicalHash)
  for (const binding of genesis.legacyArchiveBundleReplicas) binding.value.logicalHash = new Uint8Array(genesis.legacyArchiveBundleLogicalHash)
  for (const binding of genesis.originalRecordsReplicas) binding.value.logicalHash = new Uint8Array(genesis.originalRecordsLogicalHash)
  genesis.legacyArchiveBundleReplicas = sortReplicaBindings('legacyArchiveBundleReplicas', genesis.legacyArchiveBundleReplicas)
  genesis.originalRecordsReplicas = sortReplicaBindings('originalRecordsReplicas', genesis.originalRecordsReplicas)
  signLastField('MigrationGenesisV1', genesis, 'releaseSignature', 'peerit.hiverelay.migration-genesis.v1', archiveFixture.release.secretKey)
  const genesisBytes = catalog.MigrationGenesisV1.encode(genesis)
  const genesisId = hashPeeritProfileRecordIdV1(6, genesisBytes)
  const activation = catalog.PeeritHiveRelayProfilePinV1.decode(makePin(1, archiveFixture.pendingPinBytes, archiveFixture.release))
  activation.legacySourceSetHash = new Uint8Array(genesis.legacySourceSetHash)
  activation.migrationStage = 1
  activation.legacyImportMode = 1
  activation.legacyReadMode = 0
  activation.legacyCutoffHash = new Uint8Array(genesis.legacyCutoffHash)
  activation.migrationGenesisRecordId = new Uint8Array(genesisId)
  activation.cutoffActivationReleaseSequence = 1n
  activation.migrationTransitionEvidenceHash = new Uint8Array(32).fill(0x81)
  signLastField('PeeritHiveRelayProfilePinV1', activation, 'signature', 'peerit.hiverelay.profile-pin.v1', archiveFixture.release.secretKey)
  const activationBytes = catalog.PeeritHiveRelayProfilePinV1.encode(activation)
  archiveFixture.store.put(genesisId, genesisBytes)
  return { archiveFixture, built, authority, archiveResult, genesis, genesisBytes, genesisId, activation, activationBytes }
}

await test('migration genesis reproduces the activation pin and exact archive/index/distribution/census graph', () => {
  const fixture = makeGenesisFixture()
  const result = fixture.authority.validateMigrationGenesisDeterministic(fixture.genesisBytes, { activationPinBytes: fixture.activationBytes })
  assert.equal(bytesEqual(result.recordId, fixture.genesisId), true)
  assert.equal(bytesEqual(result.archive.bundleLogicalHash, fixture.genesis.legacyArchiveBundleLogicalHash), true)

  const tampered = structuredClone(fixture.genesis)
  tampered.retainedRecordCount = 2n
  signLastField('MigrationGenesisV1', tampered, 'releaseSignature', 'peerit.hiverelay.migration-genesis.v1', fixture.archiveFixture.release.secretKey)
  const tamperedBytes = catalog.MigrationGenesisV1.encode(tampered)
  const activation = structuredClone(fixture.activation)
  activation.migrationGenesisRecordId = hashPeeritProfileRecordIdV1(6, tamperedBytes)
  signLastField('PeeritHiveRelayProfilePinV1', activation, 'signature', 'peerit.hiverelay.profile-pin.v1', fixture.archiveFixture.release.secretKey)
  assert.throws(
    () => fixture.authority.validateMigrationGenesisDeterministic(tamperedBytes, {
      activationPinBytes: catalog.PeeritHiveRelayProfilePinV1.encode(activation)
    }),
    error => error.code === 'BAD_MIGRATION_GENESIS_ARCHIVE_BINDING'
  )
})

function migratePin (sequence, predecessorBytes, fixture, readMode) {
  const pin = catalog.PeeritHiveRelayProfilePinV1.decode(makePin(sequence, predecessorBytes, fixture.archiveFixture.release))
  pin.legacySourceSetHash = new Uint8Array(fixture.genesis.legacySourceSetHash)
  pin.migrationStage = 2
  pin.legacyImportMode = 2
  pin.legacyReadMode = readMode
  pin.legacyCutoffHash = new Uint8Array(fixture.genesis.legacyCutoffHash)
  pin.migrationGenesisRecordId = new Uint8Array(fixture.genesisId)
  pin.cutoffActivationReleaseSequence = 1n
  pin.migrationTransitionEvidenceHash = new Uint8Array(32).fill(0x90 + Number(sequence))
  if (readMode === 1) {
    pin.legacyRetirementActivationReleaseSequence = BigInt(sequence)
  }
  signLastField('PeeritHiveRelayProfilePinV1', pin, 'signature', 'peerit.hiverelay.profile-pin.v1', fixture.archiveFixture.release.secretKey)
  return { value: pin, bytes: catalog.PeeritHiveRelayProfilePinV1.encode(pin) }
}

function makeRetirementFixture () {
  const fixture = makeGenesisFixture()
  const older = migratePin(2, fixture.activationBytes, fixture, 0)
  const previous = migratePin(3, older.bytes, fixture, 0)
  previous.value.migrationTransitionEvidenceHash = null
  signLastField('PeeritHiveRelayProfilePinV1', previous.value, 'signature', 'peerit.hiverelay.profile-pin.v1', fixture.archiveFixture.release.secretKey)
  previous.bytes = catalog.PeeritHiveRelayProfilePinV1.encode(previous.value)
  const evidence = fixtures.create('LegacyRetirementEvidenceV1', 9601)
  evidence.previousPinHash = hashPeeritProfilePinV1(previous.bytes)
  evidence.targetReleaseSequence = 4n
  evidence.legacyCutoffHash = new Uint8Array(fixture.genesis.legacyCutoffHash)
  evidence.migrationGenesisRecordId = new Uint8Array(fixture.genesisId)
  evidence.retirementWindowStartedUnixMillis = 1000000000n
  evidence.retirementWindowEndedUnixMillis = evidence.retirementWindowStartedUnixMillis + 7776000000n
  evidence.retainedCensusRoot = new Uint8Array(fixture.genesis.legacyCensusRoot)
  evidence.retainedRecordCount = fixture.genesis.retainedRecordCount
  evidence.unresolvedValidLegacyOnlyCount = 0n
  evidence.acknowledgedWriteLossCount = 0n
  evidence.forbiddenLegacyWriteCount = 0n
  evidence.externalCopyRestoreEvidenceHashes = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)]
  evidence.relayRestoreEvidenceHashes = [new Uint8Array(32).fill(3), new Uint8Array(32).fill(4), new Uint8Array(32).fill(5)]
  evidence.freshUserExportEvidenceHash = new Uint8Array(32).fill(6)
  evidence.reconstructionRehearsalHashes = [new Uint8Array(32).fill(7), new Uint8Array(32).fill(8)]
  evidence.precedingDualReadPinHashes = [hashPeeritProfilePinV1(previous.bytes), hashPeeritProfilePinV1(older.bytes)]
  evidence.evidenceBundleHash = new Uint8Array(32).fill(9)
  evidence.releaseAuthoritySequence = previous.value.releaseAuthoritySequence
  evidence.releaseAuthorityKeyId = new Uint8Array(previous.value.releaseAuthorityKeyId)
  signLastField('LegacyRetirementEvidenceV1', evidence, 'signature', 'peerit.legacy-retirement-evidence.v1', fixture.archiveFixture.release.secretKey)
  let evidenceBytes = catalog.LegacyRetirementEvidenceV1.encode(evidence)
  const target = migratePin(4, previous.bytes, fixture, 1)
  target.value.legacyRetirementEvidenceHash = domainLengthHash('peerit.legacy-retirement-evidence-hash.v1', evidenceBytes)
  signLastField('PeeritHiveRelayProfilePinV1', target.value, 'signature', 'peerit.hiverelay.profile-pin.v1', fixture.archiveFixture.release.secretKey)
  target.bytes = catalog.PeeritHiveRelayProfilePinV1.encode(target.value)
  fixture.archiveFixture.store.put(hashPeeritProfilePinV1(previous.bytes), previous.bytes)
  fixture.archiveFixture.store.put(hashPeeritProfilePinV1(older.bytes), older.bytes)
  fixture.archiveFixture.store.put(fixture.genesisId, fixture.genesisBytes)
  const rebuild = () => {
    signLastField('LegacyRetirementEvidenceV1', evidence, 'signature', 'peerit.legacy-retirement-evidence.v1', fixture.archiveFixture.release.secretKey)
    evidenceBytes = catalog.LegacyRetirementEvidenceV1.encode(evidence)
    target.value.legacyRetirementEvidenceHash = domainLengthHash('peerit.legacy-retirement-evidence-hash.v1', evidenceBytes)
    signLastField('PeeritHiveRelayProfilePinV1', target.value, 'signature', 'peerit.hiverelay.profile-pin.v1', fixture.archiveFixture.release.secretKey)
    target.bytes = catalog.PeeritHiveRelayProfilePinV1.encode(target.value)
  }
  rebuild()
  return { fixture, older, previous, evidence, target, get evidenceBytes () { return evidenceBytes }, rebuild }
}

await test('retirement references bind a 90-day zero-loss gate, contiguous dual-read pins, genesis census, and target pin', () => {
  const retirement = makeRetirementFixture()
  const result = retirement.fixture.authority.validateLegacyRetirementReferences(retirement.evidenceBytes, { targetPinBytes: retirement.target.bytes })
  assert.equal(bytesEqual(result.evidenceHash, retirement.target.value.legacyRetirementEvidenceHash), true)

  retirement.evidence.precedingDualReadPinHashes.reverse()
  retirement.rebuild()
  assert.throws(
    () => retirement.fixture.authority.validateLegacyRetirementReferences(retirement.evidenceBytes, { targetPinBytes: retirement.target.bytes }),
    error => error.code === 'BAD_LEGACY_RETIREMENT_PREDECESSORS'
  )
})

process.stdout.write(`peerit contextual graph validator tests: ${passed}/${passed} passed\n`)
