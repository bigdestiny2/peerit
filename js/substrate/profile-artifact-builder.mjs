import {
  bytesEqual,
  compareBytes,
  hexToBytes,
  utf8Bytes
} from './release-control-primitives.mjs'
import { verifyProfileInventory } from './profile-inventory-scan.mjs'
import { compilePeeritProfileCodecIr } from './profile-codec-ir.mjs'
import {
  PEERIT_PROFILE_ARTIFACT_ID,
  PEERIT_PROFILE_ID,
  PEERIT_PROFILE_SOURCE_PATH,
  PEERIT_PROFILE_TAG_BASE,
  PROFILE_HASH_RECIPES,
  assertPeeritProfileVectorManifest,
  canonicalProfileSourceBytes,
  decodePeeritProfileDeclarationVector,
  decodePeeritProfileRegistry,
  encodePeeritProfileDeclarationVector,
  encodePeeritProfileRegistry,
  encodePeeritProfileVectorManifest,
  hashPeeritProfileAbi,
  hashPeeritProfileSpec,
  hashPeeritProfileVectorSet
} from './profile-artifact-codec.mjs'

function failBuild (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details != null) error.details = details
  throw error
}

function compareText (left, right) {
  return compareBytes(utf8Bytes(left), utf8Bytes(right))
}

function sortedByName (entries) {
  return [...entries].sort((left, right) => compareText(left.name, right.name))
}

function immutableBytes (value) {
  return new Uint8Array(value)
}

function normalizeInventoryModel (profileSourceBytes, scanResult, inventory, codecIr) {
  const categories = [...inventory.categories].sort((left, right) => compareText(left.id, right.id)).map((entry, index) => ({
    id: index + 1,
    name: entry.id,
    owner: entry.owner,
    schemaCount: entry.schemaCount
  }))
  const categoryIds = new Map(categories.map(entry => [entry.name, entry.id]))
  const inventorySchemas = new Map(inventory.schemas.map(entry => [entry.name, entry]))
  const codecSchemas = new Map(codecIr.schemas.map(entry => [entry.name, entry]))
  const schemas = scanResult.scan.declarations.map((declaration, index) => {
    const entry = inventorySchemas.get(declaration.name)
    const categoryId = categoryIds.get(entry.category)
    if (categoryId == null) failBuild('PROFILE_INVENTORY_DRIFT', `${entry.name} has no canonical category ID`)
    return {
      ordinal: index + 1,
      tag: PEERIT_PROFILE_TAG_BASE + index + 1,
      name: entry.name,
      kind: entry.kind,
      categoryId,
      owner: entry.owner,
      sourceSha256: hexToBytes(entry.sourceSha256, 32, `${entry.name} sourceSha256`),
      source: declaration.source,
      dependencies: [...entry.dependencies],
      inlineShapes: entry.inlineShapes.map(shape => ({
        ordinal: shape.ordinal,
        depth: shape.depth,
        relativeLine: shape.relativeLine,
        sha256: hexToBytes(shape.sha256, 32, `${entry.name} inline shape sha256`)
      })),
      codecIr: codecSchemas.get(entry.name)
    }
  })

  return {
    artifactId: PEERIT_PROFILE_ARTIFACT_ID,
    profileId: PEERIT_PROFILE_ID,
    profileSourcePath: PEERIT_PROFILE_SOURCE_PATH,
    profileSourceBytes,
    profileSourceSha256: hexToBytes(scanResult.profileSha256, 32, 'profileSourceSha256'),
    tagBase: PEERIT_PROFILE_TAG_BASE,
    inventoryVersion: inventory.inventoryVersion,
    inventoryOwner: inventory.owner,
    categories,
    externalTypes: sortedByName(inventory.externalTypes).map(entry => ({ ...entry })),
    externalCodecImports: sortedByName(inventory.externalCodecImports).map(entry => ({ ...entry })),
    profileRegistries: sortedByName(inventory.profileRegistries).map(entry => ({
      name: entry.name,
      owner: entry.owner,
      category: entry.category,
      kind: entry.kind,
      encoding: entry.encoding,
      values: entry.values.map(value => ({ ...value }))
    })),
    codecLayoutIrComplete: true,
    hashRecipes: PROFILE_HASH_RECIPES.map(entry => ({ ...entry })),
    schemas
  }
}

export function buildPeeritProfileArtifacts (profileSource, inventory) {
  if (!inventory || typeof inventory !== 'object') failBuild('PROFILE_INVENTORY_MISSING', 'profile inventory is required')
  const profileSourceBytes = canonicalProfileSourceBytes(profileSource)
  const profileText = new TextDecoder('utf-8', { fatal: true }).decode(profileSourceBytes)
  const scanResult = verifyProfileInventory(profileText, inventory)
  if (!scanResult.ok) {
    failBuild('PROFILE_INVENTORY_DRIFT', 'profile source does not equal the checked inventory', scanResult.problems)
  }
  const codecIr = compilePeeritProfileCodecIr(profileText, inventory, { tagBase: PEERIT_PROFILE_TAG_BASE })
  if (codecIr.schemaCount !== scanResult.declarationCount || codecIr.boundedSchemaCount !== scanResult.declarationCount) {
    failBuild('PROFILE_CODEC_IR_INCOMPLETE', 'every profile declaration must compile to finite codec IR')
  }
  const registryModel = normalizeInventoryModel(profileSourceBytes, scanResult, inventory, codecIr)
  const registryBytes = encodePeeritProfileRegistry(registryModel)
  const registry = decodePeeritProfileRegistry(registryBytes)
  const profileSpecHash = hashPeeritProfileSpec(profileSourceBytes)
  const profileAbiHash = hashPeeritProfileAbi(registryBytes)
  const vectors = registry.schemas.map(schema => {
    const path = `profile/declarations/${String(schema.ordinal).padStart(4, '0')}-${schema.name}.cenc`
    const bytes = encodePeeritProfileDeclarationVector({
      profileId: registry.profileId,
      profileSpecHash,
      profileAbiHash,
      inventoryCommitment: registry.inventoryCommitment,
      schema
    })
    return Object.freeze({ path, bytes })
  })
  const vectorManifestBytes = encodePeeritProfileVectorManifest(vectors)
  const profileVectorSetHash = hashPeeritProfileVectorSet(vectorManifestBytes)
  return Object.freeze({
    registryBytes,
    vectorManifestBytes,
    vectors: Object.freeze(vectors),
    profileSpecHash,
    profileAbiHash,
    profileVectorSetHash,
    inventoryCommitment: immutableBytes(registry.inventoryCommitment),
    codecIr,
    profileSha256: scanResult.profileSha256,
    registry
  })
}

function suppliedVectorMap (vectors) {
  if (vectors instanceof Map) return new Map(vectors)
  if (!Array.isArray(vectors)) failBuild('PROFILE_VECTOR_SET_DRIFT', 'vectors must be a Map or array')
  const map = new Map()
  for (const entry of vectors) {
    if (!entry || typeof entry !== 'object' || typeof entry.path !== 'string') {
      failBuild('PROFILE_VECTOR_SET_DRIFT', 'each vector must have path and bytes')
    }
    if (map.has(entry.path)) failBuild('PROFILE_VECTOR_SET_DRIFT', `duplicate supplied vector ${entry.path}`)
    map.set(entry.path, entry.bytes)
  }
  return map
}

export function verifyPeeritProfileArtifactSet ({
  profileSource,
  inventory,
  registryBytes,
  vectorManifestBytes,
  vectors
}) {
  const expected = buildPeeritProfileArtifacts(profileSource, inventory)
  // Decode untrusted inputs before exact comparison so corrupt structures fail with their structural reason.
  const actualRegistry = decodePeeritProfileRegistry(registryBytes)
  if (!bytesEqual(actualRegistry.profileSourceBytes, canonicalProfileSourceBytes(profileSource))) {
    failBuild('PROFILE_SOURCE_BINDING_MISMATCH', 'registry embeds a different profile source')
  }
  if (!bytesEqual(registryBytes, expected.registryBytes)) {
    failBuild('PROFILE_REGISTRY_ARTIFACT_DRIFT', 'registry bytes do not equal the deterministic source/inventory build')
  }
  if (!bytesEqual(vectorManifestBytes, expected.vectorManifestBytes)) {
    failBuild('PROFILE_VECTOR_MANIFEST_DRIFT', 'vector manifest does not equal the deterministic source/inventory build')
  }
  const supplied = suppliedVectorMap(vectors)
  assertPeeritProfileVectorManifest(vectorManifestBytes, supplied)
  if (supplied.size !== expected.vectors.length) {
    failBuild('PROFILE_VECTOR_SET_DRIFT', 'profile vector set has the wrong cardinality')
  }
  const expectedByPath = new Map(expected.vectors.map(entry => [entry.path, entry.bytes]))
  for (const [path, bytes] of supplied) {
    const expectedBytes = expectedByPath.get(path)
    if (expectedBytes == null) failBuild('PROFILE_VECTOR_SET_DRIFT', `unexpected profile vector ${path}`)
    const decoded = decodePeeritProfileDeclarationVector(bytes)
    if (!bytesEqual(decoded.profileSpecHash, expected.profileSpecHash) ||
        !bytesEqual(decoded.profileAbiHash, expected.profileAbiHash) ||
        !bytesEqual(decoded.inventoryCommitment, expected.inventoryCommitment)) {
      failBuild('PROFILE_VECTOR_SOURCE_BINDING_MISMATCH', `${path} is not bound to this exact profile registry`)
    }
    if (!bytesEqual(bytes, expectedBytes)) failBuild('PROFILE_VECTOR_BYTES_DRIFT', `${path} differs from its deterministic vector`)
  }
  return Object.freeze({
    schemaCount: expected.registry.schemas.length,
    vectorCount: expected.vectors.length,
    profileSpecHash: immutableBytes(expected.profileSpecHash),
    profileAbiHash: immutableBytes(expected.profileAbiHash),
    profileVectorSetHash: immutableBytes(expected.profileVectorSetHash),
    inventoryCommitment: immutableBytes(expected.inventoryCommitment),
    registryComplete: true,
    codecLayoutIrComplete: true,
    codecsComplete: true,
    releaseReady: false
  })
}
