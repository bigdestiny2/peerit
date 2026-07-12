import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  buildPeeritProfileArtifacts,
  verifyPeeritProfileArtifactSet
} from '../js/substrate/profile-artifact-builder.mjs'
import {
  PEERIT_PROFILE_ARTIFACT_ID,
  PEERIT_PROFILE_ID,
  PEERIT_PROFILE_TAG_BASE,
  PROFILE_ARTIFACT_DOMAIN,
  PROFILE_HASH_RECIPES,
  assertPeeritProfileVectorManifest,
  canonicalProfileSourceBytes,
  decodePeeritProfileDeclarationVector,
  decodePeeritProfileRegistry,
  decodePeeritProfileVectorManifest,
  encodePeeritProfileRegistry,
  encodePeeritProfileVectorManifest,
  hashPeeritProfileAbi,
  hashPeeritProfileSpec,
  hashPeeritProfileVectorSet,
  validatePeeritProfileVectorPath
} from '../js/substrate/profile-artifact-codec.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import { PROFILE_ARTIFACT_STATUS } from '../js/substrate/profile-status.mjs'
import { RELEASE_CONTROL_TAG } from '../js/substrate/release-control-registry.mjs'
import {
  CanonicalWriter,
  blake2b256,
  bytesEqual,
  concatBytes
} from '../js/substrate/release-control-primitives.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const profileSource = new Uint8Array(fs.readFileSync(path.join(root, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md')))
const registryBytes = new Uint8Array(fs.readFileSync(path.join(root, 'protocol/peerit-profile-v1.cenc')))
const manifestBytes = new Uint8Array(fs.readFileSync(path.join(root, 'protocol/vectors/peerit-profile-v1.manifest.cenc')))
const manifestEntries = decodePeeritProfileVectorManifest(manifestBytes)
const vectors = new Map(manifestEntries.map(entry => [
  entry.path,
  new Uint8Array(fs.readFileSync(path.join(root, 'protocol/vectors', entry.path)))
]))
let passed = 0

async function test (name, operation) {
  await operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

function changedByte (value, offset = value.byteLength - 1) {
  const output = value.slice()
  output[offset] ^= 0x01
  return output
}

function findBytes (haystack, text) {
  const needle = new TextEncoder().encode(text)
  return Buffer.from(haystack).indexOf(Buffer.from(needle))
}

function registryFlagOffset (bytes) {
  let offset = 8 + 2
  for (let index = 0; index < 3; index++) {
    const length = bytes[offset] * 0x100 + bytes[offset + 1]
    offset += 2 + length
  }
  return offset
}

function malformedManifest (orderedPaths) {
  const writer = new CanonicalWriter()
  writer.u32(orderedPaths.length, 'count')
  for (const path of orderedPaths) {
    writer.utf8U16(path, 'path')
    writer.u64(1n, 'length')
    writer.fixed(blake2b256(Uint8Array.of(1)), 32, 'hash')
  }
  return writer.finish()
}

await test('checked-in full registry and all 77 vectors reproduce from the exact profile and inventory', () => {
  const result = verifyPeeritProfileArtifactSet({
    profileSource,
    inventory: PEERIT_PROFILE_INVENTORY,
    registryBytes,
    vectorManifestBytes: manifestBytes,
    vectors
  })
  assert.equal(result.schemaCount, 77)
  assert.equal(result.vectorCount, 77)
  assert.equal(result.registryComplete, true)
  assert.equal(result.codecLayoutIrComplete, true)
  assert.equal(result.codecsComplete, true)
  assert.equal(result.releaseReady, false)
  assert.equal(Buffer.from(result.profileSpecHash).toString('hex'), PROFILE_ARTIFACT_STATUS.profileSpecHash)
  assert.equal(Buffer.from(result.profileAbiHash).toString('hex'), PROFILE_ARTIFACT_STATUS.profileAbiHash)
  assert.equal(Buffer.from(result.profileVectorSetHash).toString('hex'), PROFILE_ARTIFACT_STATUS.profileVectorSetHash)
  assert.equal(Buffer.from(result.inventoryCommitment).toString('hex'), PROFILE_ARTIFACT_STATUS.inventoryCommitment)
})

await test('registry embeds and domain-binds the exact canonical profile source', () => {
  const registry = decodePeeritProfileRegistry(registryBytes)
  assert.equal(registry.artifactId, PEERIT_PROFILE_ARTIFACT_ID)
  assert.equal(registry.profileId, PEERIT_PROFILE_ID)
  assert.equal(bytesEqual(registry.profileSourceBytes, profileSource), true)
  assert.equal(bytesEqual(registry.profileSpecHash, hashPeeritProfileSpec(profileSource)), true)
  assert.deepEqual(registry.hashRecipes, PROFILE_HASH_RECIPES)
  assert.deepEqual(registry.hashRecipes.map(entry => entry.domain), [
    PROFILE_ARTIFACT_DOMAIN.DECLARATION_SOURCE_HASH,
    PROFILE_ARTIFACT_DOMAIN.INVENTORY_COMMITMENT,
    PROFILE_ARTIFACT_DOMAIN.PROFILE_ABI_HASH,
    PROFILE_ARTIFACT_DOMAIN.PROFILE_SPEC_HASH,
    PROFILE_ARTIFACT_DOMAIN.PROFILE_VECTOR_SET_HASH
  ])
})

await test('source-order tag allocation is contiguous and pins the four release-control slice tags', () => {
  const registry = decodePeeritProfileRegistry(registryBytes)
  assert.equal(registry.tagBase, PEERIT_PROFILE_TAG_BASE)
  for (let index = 0; index < registry.schemas.length; index++) {
    assert.equal(registry.schemas[index].ordinal, index + 1)
    assert.equal(registry.schemas[index].tag, PEERIT_PROFILE_TAG_BASE + index + 1)
  }
  assert.deepEqual(registry.schemas.slice(0, 4).map(entry => entry.tag), [
    RELEASE_CONTROL_TAG.SUBSTRATE_TUPLE_V1,
    RELEASE_CONTROL_TAG.PROFILE_PIN_V1,
    RELEASE_CONTROL_TAG.PIN_HISTORY_CHECKPOINT_V1,
    RELEASE_CONTROL_TAG.PIN_HISTORY_BUNDLE_V1
  ])
})

await test('registry captures all ownership, categories, external types, enum values, dependencies, and anonymous shapes', () => {
  const registry = decodePeeritProfileRegistry(registryBytes)
  assert.equal(registry.schemas.length, 77)
  assert.equal(registry.schemas.filter(entry => entry.kind === 'record').length, 72)
  assert.equal(registry.schemas.filter(entry => entry.kind === 'tagged-union').length, 5)
  assert.equal(registry.schemas.reduce((total, entry) => total + entry.inlineShapes.length, 0), 15)
  assert.equal(registry.categories.length, 12)
  assert.equal(registry.externalTypes.length, 12)
  assert.deepEqual(registry.profileRegistries.map(entry => [entry.name, entry.encoding, entry.values.map(value => value.id)]), [
    ['LegacyMissingReasonCodeV1', 'u16', [1, 2, 3, 4, 5]],
    ['LegacyValidatorReasonCodeV1', 'u16', [1, 2, 3, 4, 5, 6, 7]],
    ['PeeritMigrationStageV1', 'u8', [0, 1, 2]]
  ])
  assert.equal(registry.schemas.every(entry => entry.codecIr.maximumCompleteBytes > 0n), true)
  assert.equal(registry.externalTypes.length, 12)
  assert.equal(registry.externalCodecImports.length, 6)
  assert.equal(registry.externalCodecImports.filter(entry => entry.authorityKind === 'WIRE_TUPLE_V1').length, 4)
  assert.equal(registry.externalCodecImports.filter(entry => entry.authorityKind === 'CLIENT_COMPOSITION_V1').length, 2)
  assert.equal(registry.externalCodecImports.some(entry => entry.name === 'BlindStoreManifestV1'), false)
})

await test('manifest is the exact HiveRelay path/length/raw-BLAKE2b construction', () => {
  assert.equal(manifestEntries.length, 77)
  assertPeeritProfileVectorManifest(manifestBytes, vectors)
  for (const entry of manifestEntries) {
    const bytes = vectors.get(entry.path)
    assert.equal(BigInt(bytes.byteLength), entry.length, entry.path)
    assert.equal(bytesEqual(blake2b256(bytes), entry.hash), true, entry.path)
  }
  assert.equal(bytesEqual(hashPeeritProfileVectorSet(manifestBytes), buildPeeritProfileArtifacts(profileSource, PEERIT_PROFILE_INVENTORY).profileVectorSetHash), true)
})

await test('each declaration vector independently binds the exact spec, ABI, inventory, tag, and source', () => {
  const registry = decodePeeritProfileRegistry(registryBytes)
  const abiHash = hashPeeritProfileAbi(registryBytes)
  for (let index = 0; index < manifestEntries.length; index++) {
    const vector = decodePeeritProfileDeclarationVector(vectors.get(manifestEntries[index].path))
    assert.equal(vector.profileId, PEERIT_PROFILE_ID)
    assert.equal(bytesEqual(vector.profileSpecHash, registry.profileSpecHash), true)
    assert.equal(bytesEqual(vector.profileAbiHash, abiHash), true)
    assert.equal(bytesEqual(vector.inventoryCommitment, registry.inventoryCommitment), true)
    assert.equal(vector.schema.name, registry.schemas[index].name)
    assert.equal(vector.schema.source, registry.schemas[index].source)
  }
})

await test('canonical construction is independent of inventory array ordering', () => {
  const reordered = structuredClone(PEERIT_PROFILE_INVENTORY)
  reordered.schemas.reverse()
  reordered.categories.reverse()
  reordered.externalTypes.reverse()
  reordered.externalCodecImports.reverse()
  reordered.profileRegistries.reverse()
  const rebuilt = buildPeeritProfileArtifacts(profileSource, reordered)
  assert.equal(bytesEqual(rebuilt.registryBytes, registryBytes), true)
  assert.equal(bytesEqual(rebuilt.vectorManifestBytes, manifestBytes), true)
})

await test('profile source canonicalization rejects BOM, CRLF, missing LF, and extra LF', () => {
  const text = new TextDecoder().decode(profileSource)
  assert.throws(() => canonicalProfileSourceBytes(`\ufeff${text}`), error => error.code === 'NONCANONICAL_PROFILE_SOURCE')
  assert.throws(() => canonicalProfileSourceBytes(text.replaceAll('\n', '\r\n')), error => error.code === 'NONCANONICAL_PROFILE_SOURCE')
  assert.throws(() => canonicalProfileSourceBytes(text.slice(0, -1)), error => error.code === 'NONCANONICAL_PROFILE_SOURCE')
  assert.throws(() => canonicalProfileSourceBytes(`${text}\n`), error => error.code === 'NONCANONICAL_PROFILE_SOURCE')
})

await test('changed profile prose changes all three release hashes and cannot reuse checked artifacts', () => {
  const text = new TextDecoder().decode(profileSource)
  const changedSource = new TextEncoder().encode(text.replace('**Status:** build specification;', '**Status:** deterministic build specification;'))
  const changed = buildPeeritProfileArtifacts(changedSource, PEERIT_PROFILE_INVENTORY)
  const original = buildPeeritProfileArtifacts(profileSource, PEERIT_PROFILE_INVENTORY)
  assert.equal(bytesEqual(changed.profileSpecHash, original.profileSpecHash), false)
  assert.equal(bytesEqual(changed.profileAbiHash, original.profileAbiHash), false)
  assert.equal(bytesEqual(changed.profileVectorSetHash, original.profileVectorSetHash), false)
  assert.throws(() => verifyPeeritProfileArtifactSet({
    profileSource: changedSource,
    inventory: PEERIT_PROFILE_INVENTORY,
    registryBytes,
    vectorManifestBytes: manifestBytes,
    vectors
  }), error => error.code === 'PROFILE_SOURCE_BINDING_MISMATCH')
})

await test('declaration or inventory drift fails before artifact generation', () => {
  const text = new TextDecoder().decode(profileSource)
  const changedDeclaration = text.replace('specHash:       32 bytes', 'specHash:       31 bytes')
  assert.throws(() => buildPeeritProfileArtifacts(changedDeclaration, PEERIT_PROFILE_INVENTORY), error => error.code === 'PROFILE_INVENTORY_DRIFT')
  const changedInventory = structuredClone(PEERIT_PROFILE_INVENTORY)
  changedInventory.schemas[0].owner = 'hiverelay-substrate'
  assert.throws(() => buildPeeritProfileArtifacts(profileSource, changedInventory), error => error.code === 'PROFILE_INVENTORY_DRIFT')
})

await test('registry corruption, embedded-source substitution, and false completeness claims fail closed', () => {
  assert.throws(() => decodePeeritProfileRegistry(changedByte(registryBytes)), error => [
    'PROFILE_INVENTORY_COMMITMENT_MISMATCH',
    'DECLARATION_SOURCE_COMMITMENT_MISMATCH'
  ].includes(error.code))

  const sourceOffset = findBytes(registryBytes, '# Peerit profile for the HiveRelay blind substrate')
  assert.notEqual(sourceOffset, -1)
  assert.throws(() => decodePeeritProfileRegistry(changedByte(registryBytes, sourceOffset + 2)), error => error.code === 'PROFILE_SOURCE_BINDING_MISMATCH')

  const flags = registryFlagOffset(registryBytes)
  assert.throws(() => decodePeeritProfileRegistry(changedByte(registryBytes, flags + 1)), error => error.code === 'FALSE_PROFILE_COMPLETENESS_CLAIM')
})

await test('self-consistent alternate identity, hash domains, ownership, and category accounting are rejected', () => {
  const wrongIdentity = structuredClone(decodePeeritProfileRegistry(registryBytes))
  wrongIdentity.artifactId = '@peerit/attacker-profile-registry-v1'
  assert.throws(() => decodePeeritProfileRegistry(encodePeeritProfileRegistry(wrongIdentity)), error => error.code === 'BAD_PROFILE_ARTIFACT_IDENTITY')

  const wrongDomain = structuredClone(decodePeeritProfileRegistry(registryBytes))
  wrongDomain.hashRecipes[0].domain = `${wrongDomain.hashRecipes[0].domain}.wrong`
  assert.throws(() => decodePeeritProfileRegistry(encodePeeritProfileRegistry(wrongDomain)), error => error.code === 'PROFILE_HASH_RECIPE_DRIFT')

  const wrongOwner = structuredClone(decodePeeritProfileRegistry(registryBytes))
  wrongOwner.schemas[0].owner = 'hiverelay-substrate'
  assert.throws(() => decodePeeritProfileRegistry(encodePeeritProfileRegistry(wrongOwner)), error => error.code === 'BAD_PROFILE_OWNER')

  const wrongCategoryCount = structuredClone(decodePeeritProfileRegistry(registryBytes))
  wrongCategoryCount.categories[0].schemaCount++
  assert.throws(() => decodePeeritProfileRegistry(encodePeeritProfileRegistry(wrongCategoryCount)), error => error.code === 'BAD_PROFILE_CATEGORY_REGISTRY')
})

await test('header substitution that remains structurally decodable still fails exact source/inventory validation', () => {
  const flags = registryFlagOffset(registryBytes)
  const sourceShaOffset = flags + 4 + 2
  const substituted = changedByte(registryBytes, sourceShaOffset)
  decodePeeritProfileRegistry(substituted)
  assert.throws(() => verifyPeeritProfileArtifactSet({
    profileSource,
    inventory: PEERIT_PROFILE_INVENTORY,
    registryBytes: substituted,
    vectorManifestBytes: manifestBytes,
    vectors
  }), error => error.code === 'PROFILE_REGISTRY_ARTIFACT_DRIFT')
})

await test('manifest rejects forbidden paths, duplicates, noncanonical order, truncation, and trailing bytes', () => {
  for (const badPath of ['/absolute', 'a\\b', 'a//b', 'a/../b', `profile/${'e\u0301'}`]) {
    assert.throws(() => validatePeeritProfileVectorPath(badPath), error => error.code === 'BAD_PROFILE_VECTOR_PATH' || error.code === 'BAD_RELEASE_CONTROL_ENCODING')
  }
  assert.throws(() => encodePeeritProfileVectorManifest([
    { path: 'same', bytes: Uint8Array.of(1) },
    { path: 'same', bytes: Uint8Array.of(2) }
  ]), error => error.code === 'DUPLICATE_PROFILE_VECTOR_PATH')
  assert.throws(() => decodePeeritProfileVectorManifest(malformedManifest(['z', 'a'])), error => error.code === 'BAD_PROFILE_VECTOR_ORDER')
  assert.throws(() => decodePeeritProfileVectorManifest(manifestBytes.slice(0, -1)), /truncated/)
  assert.throws(() => decodePeeritProfileVectorManifest(concatBytes(manifestBytes, Uint8Array.of(0))), /trailing bytes/)
})

await test('vector substitution, mutation, omission, and extras fail against the manifest', () => {
  const paths = [...vectors.keys()]
  const substituted = new Map(vectors)
  substituted.set(paths[0], vectors.get(paths[1]))
  assert.throws(() => assertPeeritProfileVectorManifest(manifestBytes, substituted), error => error.code === 'PROFILE_VECTOR_BYTES_DRIFT')

  const mutated = new Map(vectors)
  mutated.set(paths[0], changedByte(vectors.get(paths[0])))
  assert.throws(() => assertPeeritProfileVectorManifest(manifestBytes, mutated), error => error.code === 'PROFILE_VECTOR_BYTES_DRIFT')

  const missing = new Map(vectors)
  missing.delete(paths[0])
  assert.throws(() => assertPeeritProfileVectorManifest(manifestBytes, missing), error => error.code === 'PROFILE_VECTOR_SET_DRIFT')

  const extra = new Map(vectors)
  extra.set('profile/declarations/9999-extra.cenc', Uint8Array.of(0))
  assert.throws(() => assertPeeritProfileVectorManifest(manifestBytes, extra), error => error.code === 'PROFILE_VECTOR_SET_DRIFT')

  const duplicateArray = [...vectors].map(([path, bytes]) => ({ path, bytes }))
  duplicateArray.push({ path: paths[0], bytes: vectors.get(paths[0]) })
  assert.throws(() => assertPeeritProfileVectorManifest(manifestBytes, duplicateArray), error => error.code === 'PROFILE_VECTOR_SET_DRIFT')
})

process.stdout.write(`peerit profile artifact tests: ${passed}/${passed} passed\n`)
