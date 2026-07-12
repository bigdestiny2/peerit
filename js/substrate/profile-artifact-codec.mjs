import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  blake2b256,
  bytesEqual,
  compareBytes,
  domainLengthHash,
  fixedBytesValue,
  utf8Bytes
} from './release-control-primitives.mjs'
import {
  PEERIT_PROFILE_EXTERNAL_AUTHORITY,
  PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  assertPeeritProfileCodecLayoutIrSet,
  compilePeeritProfileCodecIr,
  decodePeeritProfileSchemaCodecIr,
  encodePeeritProfileSchemaCodecIr
} from './profile-codec-ir.mjs'

export const PEERIT_PROFILE_ARTIFACT_ID = '@peerit/hiverelay-profile-registry-v1'
export const PEERIT_PROFILE_ID = '@peerit/hiverelay-profile-v1'
export const PEERIT_PROFILE_SOURCE_PATH = 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md'
export const PEERIT_PROFILE_REGISTRY_MAGIC = 'PTRPRF01'
export const PEERIT_PROFILE_VECTOR_MAGIC = 'PTPVEC01'
export const PEERIT_PROFILE_FORMAT_VERSION = 2
export const PEERIT_PROFILE_TAG_BASE = 0x0100
export const PEERIT_PROFILE_SCHEMA_COUNT = 77

export const PROFILE_ARTIFACT_DOMAIN = Object.freeze({
  PROFILE_SPEC_HASH: 'peerit.hiverelay.profile-spec-hash.v1',
  PROFILE_ABI_HASH: 'peerit.hiverelay.profile-abi-hash.v1',
  PROFILE_VECTOR_SET_HASH: 'peerit.hiverelay.profile-vector-set-hash.v1',
  INVENTORY_COMMITMENT: 'peerit.hiverelay.profile-inventory.v1',
  DECLARATION_SOURCE_HASH: 'peerit.hiverelay.profile-declaration-source.v1'
})

export const PROFILE_HASH_RECIPES = Object.freeze([
  Object.freeze({
    name: 'declarationSourceHash',
    domain: PROFILE_ARTIFACT_DOMAIN.DECLARATION_SOURCE_HASH,
    recipe: 'BLAKE2b-256(domain || len64(exactNormalizedDeclarationSourceBytes) || exactNormalizedDeclarationSourceBytes)'
  }),
  Object.freeze({
    name: 'inventoryCommitment',
    domain: PROFILE_ARTIFACT_DOMAIN.INVENTORY_COMMITMENT,
    recipe: 'BLAKE2b-256(domain || len64(canonicalInventoryPayloadBytes) || canonicalInventoryPayloadBytes)'
  }),
  Object.freeze({
    name: 'profileAbiHash',
    domain: PROFILE_ARTIFACT_DOMAIN.PROFILE_ABI_HASH,
    recipe: 'BLAKE2b-256(domain || len64(completeProfileRegistryBytes) || completeProfileRegistryBytes)'
  }),
  Object.freeze({
    name: 'profileSpecHash',
    domain: PROFILE_ARTIFACT_DOMAIN.PROFILE_SPEC_HASH,
    recipe: 'BLAKE2b-256(domain || len64(exactProfileSourceBytes) || exactProfileSourceBytes)'
  }),
  Object.freeze({
    name: 'profileVectorSetHash',
    domain: PROFILE_ARTIFACT_DOMAIN.PROFILE_VECTOR_SET_HASH,
    recipe: 'BLAKE2b-256(domain || len64(canonicalVectorManifestBytes) || canonicalVectorManifestBytes)'
  })
])

const SCHEMA_KIND = Object.freeze({ record: 0, 'tagged-union': 1 })
const SCHEMA_KIND_BY_ID = Object.freeze(['record', 'tagged-union'])
const MAX_VECTOR_ENTRIES = 65535
const textEncoder = new TextEncoder()

function failProfileArtifact (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details != null) error.details = details
  throw error
}

function requireCount (value, maximum, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', `${field} is outside 0..${maximum}`)
  }
  return value
}

function requireIdentifier (value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9._@/-]*$/.test(value)) {
    failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', `${field} is not a canonical identifier`)
  }
  return value
}

function compareText (left, right) {
  return compareBytes(utf8Bytes(left), utf8Bytes(right))
}

function assertStrictTextOrder (values, projection, field) {
  for (let index = 1; index < values.length; index++) {
    if (compareText(projection(values[index - 1]), projection(values[index])) >= 0) {
      failProfileArtifact('BAD_PROFILE_ARTIFACT_ORDER', `${field} must be strictly sorted and unique`)
    }
  }
}

function enumEncodingBits (encoding, field) {
  const match = /^u(8|16|32|64)$/.exec(encoding)
  if (!match) failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', `${field} has an unsupported enum encoding`)
  return Number(match[1])
}

function writeEnumId (writer, bits, value, field) {
  if (!Number.isSafeInteger(value) || value < 0) failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', `${field} is not an unsigned integer`)
  if (bits === 8) writer.u8(value, field)
  else if (bits === 16) writer.u16(value, field)
  else if (bits === 32) writer.u32(value, field)
  else writer.u64(BigInt(value), field)
}

function readEnumId (reader, bits, field) {
  const value = bits === 8 ? reader.u8(field) : bits === 16 ? reader.u16(field) : bits === 32 ? reader.u32(field) : reader.u64(field)
  if (typeof value === 'bigint') {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', `${field} exceeds safe registry IDs`)
    return Number(value)
  }
  return value
}

function sourceBytesFrom (value) {
  if (typeof value === 'string') return utf8Bytes(value, 'profile source')
  return asBytes(value, 'profile source')
}

export function canonicalProfileSourceBytes (value) {
  const bytes = sourceBytesFrom(value)
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    failProfileArtifact('NONCANONICAL_PROFILE_SOURCE', 'profile source must be valid UTF-8')
  }
  if (text.startsWith('\ufeff')) {
    failProfileArtifact('NONCANONICAL_PROFILE_SOURCE', 'profile source must not contain a UTF-8 BOM')
  }
  if (text !== text.normalize('NFC')) {
    failProfileArtifact('NONCANONICAL_PROFILE_SOURCE', 'profile source must be NFC')
  }
  if (text.includes('\r')) {
    failProfileArtifact('NONCANONICAL_PROFILE_SOURCE', 'profile source must use LF, never CR')
  }
  if (!text.endsWith('\n') || text.endsWith('\n\n')) {
    failProfileArtifact('NONCANONICAL_PROFILE_SOURCE', 'profile source must have exactly one final LF')
  }
  const canonical = textEncoder.encode(text)
  if (!bytesEqual(canonical, bytes)) {
    failProfileArtifact('NONCANONICAL_PROFILE_SOURCE', 'profile source bytes are not canonical UTF-8')
  }
  return canonical
}

export function hashPeeritProfileSpec (sourceBytes) {
  return domainLengthHash(PROFILE_ARTIFACT_DOMAIN.PROFILE_SPEC_HASH, canonicalProfileSourceBytes(sourceBytes))
}

export function hashPeeritProfileAbi (registryBytes) {
  return domainLengthHash(PROFILE_ARTIFACT_DOMAIN.PROFILE_ABI_HASH, registryBytes)
}

export function hashPeeritProfileVectorSet (manifestBytes) {
  return domainLengthHash(PROFILE_ARTIFACT_DOMAIN.PROFILE_VECTOR_SET_HASH, manifestBytes)
}

export function hashPeeritDeclarationSource (source) {
  return domainLengthHash(PROFILE_ARTIFACT_DOMAIN.DECLARATION_SOURCE_HASH, utf8Bytes(source, 'declaration source'))
}

function encodeHashRecipes (writer, recipes) {
  const sorted = [...recipes].sort((left, right) => compareText(left.name, right.name))
  assertStrictTextOrder(sorted, entry => entry.name, 'hash recipes')
  writer.u16(requireCount(sorted.length, 0xffff, 'hash recipe count'), 'hash recipe count')
  for (const entry of sorted) {
    writer.utf8U16(requireIdentifier(entry.name, 'hash recipe name'), 'hash recipe name')
    writer.utf8U16(entry.domain, `${entry.name} domain`)
    writer.utf8U16(entry.recipe, `${entry.name} recipe`)
  }
}

function decodeHashRecipes (reader) {
  const recipes = []
  const count = reader.u16('hash recipe count')
  for (let index = 0; index < count; index++) {
    const name = reader.utf8U16('hash recipe name')
    recipes.push({
      name,
      domain: reader.utf8U16(`${name} domain`),
      recipe: reader.utf8U16(`${name} recipe`)
    })
  }
  assertStrictTextOrder(recipes, entry => entry.name, 'hash recipes')
  return recipes
}

function encodeSchemaEntry (writer, entry, expectedOrdinal, tagBase) {
  if (!Number.isSafeInteger(expectedOrdinal) || expectedOrdinal < 1 || expectedOrdinal > 0xffff - tagBase ||
      entry.ordinal !== expectedOrdinal || entry.tag !== tagBase + expectedOrdinal) {
    failProfileArtifact('BAD_PROFILE_TAG_ALLOCATION', `schema ${entry.name} must use ordinal ${expectedOrdinal} and tag ${tagBase + expectedOrdinal}`)
  }
  const kind = SCHEMA_KIND[entry.kind]
  if (kind == null) failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', `unknown schema kind ${entry.kind}`)
  writer.u16(entry.ordinal, `${entry.name} ordinal`)
  writer.u16(entry.tag, `${entry.name} tag`)
  writer.utf8U16(requireIdentifier(entry.name, 'schema name'), 'schema name')
  writer.u8(kind, `${entry.name} kind`)
  writer.u8(requireCount(entry.categoryId, 0xff, `${entry.name} categoryId`), `${entry.name} categoryId`)
  writer.utf8U16(requireIdentifier(entry.owner, `${entry.name} owner`), `${entry.name} owner`)
  writer.fixed(entry.sourceSha256, 32, `${entry.name} sourceSha256`)
  const sourceHash = hashPeeritDeclarationSource(entry.source)
  if (entry.sourceHash != null && !bytesEqual(entry.sourceHash, sourceHash)) {
    failProfileArtifact('DECLARATION_SOURCE_COMMITMENT_MISMATCH', `${entry.name} source commitment does not match its exact source`)
  }
  writer.fixed(sourceHash, 32, `${entry.name} sourceHash`)
  writer.utf8U16(entry.source, `${entry.name} source`)

  assertStrictTextOrder(entry.dependencies, value => value, `${entry.name} dependencies`)
  writer.u16(requireCount(entry.dependencies.length, 0xffff, `${entry.name} dependency count`), `${entry.name} dependency count`)
  for (const dependency of entry.dependencies) {
    writer.utf8U16(requireIdentifier(dependency, `${entry.name} dependency`), `${entry.name} dependency`)
  }

  writer.u16(requireCount(entry.inlineShapes.length, 0xffff, `${entry.name} inline shape count`), `${entry.name} inline shape count`)
  for (let index = 0; index < entry.inlineShapes.length; index++) {
    const shape = entry.inlineShapes[index]
    if (shape.ordinal !== index + 1) {
      failProfileArtifact('BAD_PROFILE_ARTIFACT_ORDER', `${entry.name} inline shapes must use contiguous ordinals`)
    }
    writer.u16(shape.ordinal, `${entry.name} shape ordinal`)
    writer.u16(requireCount(shape.depth, 0xffff, `${entry.name} shape depth`), `${entry.name} shape depth`)
    writer.u16(requireCount(shape.relativeLine, 0xffff, `${entry.name} shape relativeLine`), `${entry.name} shape relativeLine`)
    writer.fixed(shape.sha256, 32, `${entry.name} shape sha256`)
  }

  const codecIrBytes = encodePeeritProfileSchemaCodecIr(entry.codecIr)
  if (entry.codecIr.ordinal !== entry.ordinal || entry.codecIr.tag !== entry.tag ||
      entry.codecIr.name !== entry.name || entry.codecIr.kind !== entry.kind) {
    failProfileArtifact('PROFILE_CODEC_IR_IDENTITY_MISMATCH', `${entry.name} codec IR has a different schema identity`)
  }
  writer.u32(codecIrBytes.byteLength, `${entry.name} codec IR length`)
  writer.fixed(codecIrBytes, codecIrBytes.byteLength, `${entry.name} codec IR`)
}

function decodeSchemaEntry (reader, expectedOrdinal, tagBase, decodedOrdinal = null) {
  const ordinal = decodedOrdinal == null ? reader.u16('schema ordinal') : decodedOrdinal
  const tag = reader.u16('schema tag')
  const name = reader.utf8U16('schema name')
  const kindId = reader.u8(`${name} kind`)
  const kind = SCHEMA_KIND_BY_ID[kindId]
  if (kind == null) failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', `${name} has unknown schema kind ${kindId}`)
  const categoryId = reader.u8(`${name} categoryId`)
  const owner = reader.utf8U16(`${name} owner`)
  const sourceSha256 = reader.fixed(32, `${name} sourceSha256`)
  const sourceHash = reader.fixed(32, `${name} sourceHash`)
  const source = reader.utf8U16(`${name} source`)
  const expectedSourceHash = hashPeeritDeclarationSource(source)
  if (!bytesEqual(sourceHash, expectedSourceHash)) {
    failProfileArtifact('DECLARATION_SOURCE_COMMITMENT_MISMATCH', `${name} source commitment does not match its exact source`)
  }

  const dependencies = []
  const dependencyCount = reader.u16(`${name} dependency count`)
  for (let index = 0; index < dependencyCount; index++) dependencies.push(reader.utf8U16(`${name} dependency`))
  assertStrictTextOrder(dependencies, value => value, `${name} dependencies`)

  const inlineShapes = []
  const shapeCount = reader.u16(`${name} inline shape count`)
  for (let index = 0; index < shapeCount; index++) {
    inlineShapes.push({
      ordinal: reader.u16(`${name} shape ordinal`),
      depth: reader.u16(`${name} shape depth`),
      relativeLine: reader.u16(`${name} shape relativeLine`),
      sha256: reader.fixed(32, `${name} shape sha256`)
    })
  }
  const codecIrLength = reader.u32(`${name} codec IR length`)
  if (codecIrLength < 1 || codecIrLength > 0x100000) {
    failProfileArtifact('BAD_PROFILE_CODEC_IR', `${name} codec IR length is outside 1..1048576`)
  }
  const codecIr = decodePeeritProfileSchemaCodecIr(reader.fixed(codecIrLength, `${name} codec IR`))
  const entry = { ordinal, tag, name, kind, categoryId, owner, sourceSha256, sourceHash, source, dependencies, inlineShapes, codecIr }
  // Reuse all allocation, ordering, and shape checks without accepting alternate encodings.
  encodeSchemaEntry(new CanonicalWriter(), entry, expectedOrdinal, tagBase)
  return entry
}

function encodeInventoryPayload (model) {
  const writer = new CanonicalWriter()
  writer.u16(requireCount(model.inventoryVersion, 0xffff, 'inventoryVersion'), 'inventoryVersion')
  writer.utf8U16(requireIdentifier(model.inventoryOwner, 'inventoryOwner'), 'inventoryOwner')
  if (model.codecLayoutIrComplete !== true) failProfileArtifact('PROFILE_CODEC_IR_INCOMPLETE', 'inventory bounded structural codec-layout IR completeness must be true')
  writer.u8(1, 'codecLayoutIrComplete')

  assertStrictTextOrder(model.categories, entry => entry.name, 'categories')
  writer.u16(requireCount(model.categories.length, 0xffff, 'category count'), 'category count')
  for (let index = 0; index < model.categories.length; index++) {
    const category = model.categories[index]
    if (category.id !== index + 1) failProfileArtifact('BAD_PROFILE_ARTIFACT_ORDER', 'category IDs must be contiguous in canonical name order')
    writer.u8(category.id, `${category.name} category id`)
    writer.utf8U16(requireIdentifier(category.name, 'category name'), 'category name')
    writer.utf8U16(requireIdentifier(category.owner, `${category.name} owner`), `${category.name} owner`)
    writer.u16(requireCount(category.schemaCount, 0xffff, `${category.name} schemaCount`), `${category.name} schemaCount`)
  }

  assertStrictTextOrder(model.externalTypes, entry => entry.name, 'external types')
  writer.u16(requireCount(model.externalTypes.length, 0xffff, 'external type count'), 'external type count')
  for (const entry of model.externalTypes) {
    writer.utf8U16(requireIdentifier(entry.name, 'external type name'), 'external type name')
    writer.utf8U16(requireIdentifier(entry.owner, `${entry.name} owner`), `${entry.name} owner`)
    writer.utf8U16(requireIdentifier(entry.family, `${entry.name} family`), `${entry.name} family`)
  }

  assertStrictTextOrder(model.externalCodecImports, entry => entry.name, 'external codec imports')
  writer.u16(requireCount(model.externalCodecImports.length, 0xffff, 'external codec import count'), 'external codec import count')
  for (const entry of model.externalCodecImports) {
    writer.utf8U16(requireIdentifier(entry.name, 'external codec import name'), 'external codec import name')
    writer.utf8U16(requireIdentifier(entry.family, `${entry.name} import family`), `${entry.name} import family`)
    writer.utf8U16(entry.authorityKind, `${entry.name} authorityKind`)
    writer.u8(entry.tupleBinding == null ? 0 : 1, `${entry.name} tupleBinding presence`)
    if (entry.tupleBinding != null) writer.utf8U16(entry.tupleBinding, `${entry.name} tupleBinding`)
    writer.u8(entry.clientSchemaCommitment == null ? 0 : 1, `${entry.name} clientSchemaCommitment presence`)
    if (entry.clientSchemaCommitment != null) writer.fixed(entry.clientSchemaCommitment, 32, `${entry.name} clientSchemaCommitment`)
    writer.u32(requireCount(entry.minimumBytes, 0xffffffff, `${entry.name} minimumBytes`), `${entry.name} minimumBytes`)
    writer.u32(requireCount(entry.maximumBytes, 0xffffffff, `${entry.name} maximumBytes`), `${entry.name} maximumBytes`)
  }

  assertStrictTextOrder(model.profileRegistries, entry => entry.name, 'profile registries')
  writer.u16(requireCount(model.profileRegistries.length, 0xffff, 'profile registry count'), 'profile registry count')
  for (const entry of model.profileRegistries) {
    writer.utf8U16(requireIdentifier(entry.name, 'profile registry name'), 'profile registry name')
    writer.utf8U16(requireIdentifier(entry.owner, `${entry.name} owner`), `${entry.name} owner`)
    writer.utf8U16(requireIdentifier(entry.category, `${entry.name} category`), `${entry.name} category`)
    writer.utf8U16(requireIdentifier(entry.kind, `${entry.name} kind`), `${entry.name} kind`)
    writer.utf8U16(requireIdentifier(entry.encoding, `${entry.name} encoding`), `${entry.name} encoding`)
    const bits = enumEncodingBits(entry.encoding, `${entry.name} encoding`)
    writer.u16(requireCount(entry.values.length, 0xffff, `${entry.name} value count`), `${entry.name} value count`)
    let previousId = -1
    for (let index = 0; index < entry.values.length; index++) {
      const value = entry.values[index]
      if (!Number.isSafeInteger(value.id) || value.id <= previousId || BigInt(value.id) >= (1n << BigInt(bits))) {
        failProfileArtifact('BAD_PROFILE_ARTIFACT_ORDER', `${entry.name} enum IDs must be strictly increasing within u${bits}`)
      }
      previousId = value.id
      writeEnumId(writer, bits, value.id, `${entry.name} value id`)
      writer.utf8U16(requireIdentifier(value.name, `${entry.name} value name`), `${entry.name} value name`)
    }
  }

  encodeHashRecipes(writer, model.hashRecipes)

  writer.u16(requireCount(model.schemas.length, 0xffff, 'schema count'), 'schema count')
  for (let index = 0; index < model.schemas.length; index++) {
    encodeSchemaEntry(writer, model.schemas[index], index + 1, model.tagBase)
  }
  return writer.finish()
}

function decodeInventoryPayload (payload, tagBase) {
  const reader = new CanonicalReader(payload)
  const inventoryVersion = reader.u16('inventoryVersion')
  const inventoryOwner = reader.utf8U16('inventoryOwner')
  const codecLayoutIrComplete = reader.u8('codecLayoutIrComplete')
  if (codecLayoutIrComplete !== 1) failProfileArtifact('PROFILE_CODEC_IR_INCOMPLETE', 'inventory bounded structural codec-layout IR completeness must equal 1')

  const categories = []
  const categoryCount = reader.u16('category count')
  for (let index = 0; index < categoryCount; index++) {
    categories.push({
      id: reader.u8('category id'),
      name: reader.utf8U16('category name'),
      owner: reader.utf8U16('category owner'),
      schemaCount: reader.u16('category schemaCount')
    })
  }

  const externalTypes = []
  const externalTypeCount = reader.u16('external type count')
  for (let index = 0; index < externalTypeCount; index++) {
    const name = reader.utf8U16('external type name')
    externalTypes.push({ name, owner: reader.utf8U16(`${name} owner`), family: reader.utf8U16(`${name} family`) })
  }

  const externalCodecImports = []
  const externalCodecImportCount = reader.u16('external codec import count')
  for (let index = 0; index < externalCodecImportCount; index++) {
    const name = reader.utf8U16('external codec import name')
    const family = reader.utf8U16(`${name} import family`)
    const authorityKind = reader.utf8U16(`${name} authorityKind`)
    const tuplePresent = reader.u8(`${name} tupleBinding presence`)
    if (tuplePresent > 1) failProfileArtifact('BAD_PROFILE_EXTERNAL_CODEC_IMPORT', `${name} tupleBinding presence must be 0 or 1`)
    const tupleBinding = tuplePresent === 1 ? reader.utf8U16(`${name} tupleBinding`) : null
    const commitmentPresent = reader.u8(`${name} clientSchemaCommitment presence`)
    if (commitmentPresent > 1) failProfileArtifact('BAD_PROFILE_EXTERNAL_CODEC_IMPORT', `${name} clientSchemaCommitment presence must be 0 or 1`)
    const clientSchemaCommitment = commitmentPresent === 1 ? reader.fixed(32, `${name} clientSchemaCommitment`) : null
    externalCodecImports.push({
      name,
      family,
      authorityKind,
      tupleBinding,
      clientSchemaCommitment,
      minimumBytes: reader.u32(`${name} minimumBytes`),
      maximumBytes: reader.u32(`${name} maximumBytes`)
    })
  }

  const profileRegistries = []
  const profileRegistryCount = reader.u16('profile registry count')
  for (let index = 0; index < profileRegistryCount; index++) {
    const name = reader.utf8U16('profile registry name')
    const entry = {
      name,
      owner: reader.utf8U16(`${name} owner`),
      category: reader.utf8U16(`${name} category`),
      kind: reader.utf8U16(`${name} kind`),
      encoding: reader.utf8U16(`${name} encoding`),
      values: []
    }
    const bits = enumEncodingBits(entry.encoding, `${name} encoding`)
    const valueCount = reader.u16(`${name} value count`)
    for (let valueIndex = 0; valueIndex < valueCount; valueIndex++) {
      entry.values.push({ id: readEnumId(reader, bits, `${name} value id`), name: reader.utf8U16(`${name} value name`) })
    }
    profileRegistries.push(entry)
  }

  const hashRecipes = decodeHashRecipes(reader)
  const schemas = []
  const schemaCount = reader.u16('schema count')
  for (let index = 0; index < schemaCount; index++) schemas.push(decodeSchemaEntry(reader, index + 1, tagBase))
  reader.expectEnd('profile inventory payload')

  const model = { inventoryVersion, inventoryOwner, codecLayoutIrComplete: true, categories, externalTypes, externalCodecImports, profileRegistries, hashRecipes, schemas, tagBase }
  const canonical = encodeInventoryPayload(model)
  if (!bytesEqual(canonical, payload)) {
    failProfileArtifact('NONCANONICAL_PROFILE_REGISTRY', 'profile inventory payload is not canonical')
  }
  if (schemas.length !== PEERIT_PROFILE_SCHEMA_COUNT) {
    failProfileArtifact('BAD_PROFILE_SCHEMA_COUNT', `profile v1 must contain exactly ${PEERIT_PROFILE_SCHEMA_COUNT} schemas`)
  }
  if (JSON.stringify(hashRecipes) !== JSON.stringify(PROFILE_HASH_RECIPES)) {
    failProfileArtifact('PROFILE_HASH_RECIPE_DRIFT', 'profile registry hash recipes do not equal the version-1 domain registry')
  }
  const categoryIds = new Set(categories.map(entry => entry.id))
  const categoryNames = new Set(categories.map(entry => entry.name))
  if (categoryIds.size !== categories.length || categoryNames.size !== categories.length) {
    failProfileArtifact('BAD_PROFILE_CATEGORY_REGISTRY', 'profile categories must have unique IDs and names')
  }
  for (const category of categories) {
    if (category.owner !== inventoryOwner) failProfileArtifact('BAD_PROFILE_OWNER', `${category.name} has the wrong owner`)
    const actualCount = schemas.filter(schema => schema.categoryId === category.id).length
    if (actualCount !== category.schemaCount) {
      failProfileArtifact('BAD_PROFILE_CATEGORY_REGISTRY', `${category.name} schema count does not match its declarations`)
    }
  }
  const schemaNames = new Set(schemas.map(entry => entry.name))
  const externalNames = new Set(externalTypes.map(entry => entry.name))
  const externalImportNames = new Set(externalCodecImports.map(entry => entry.name))
  const profileRegistryNames = new Set(profileRegistries.map(entry => entry.name))
  if (schemaNames.size !== schemas.length || externalNames.size !== externalTypes.length ||
      externalImportNames.size !== externalCodecImports.length || profileRegistryNames.size !== profileRegistries.length) {
    failProfileArtifact('BAD_PROFILE_TYPE_REGISTRY', 'profile type names must be unique within each ownership class')
  }
  const classified = new Set([...schemaNames, ...externalNames, ...profileRegistryNames])
  if (classified.size !== schemaNames.size + externalNames.size + profileRegistryNames.size) {
    failProfileArtifact('BAD_PROFILE_TYPE_REGISTRY', 'a type name cannot have more than one owner')
  }
  for (const schema of schemas) {
    if (schema.owner !== inventoryOwner) failProfileArtifact('BAD_PROFILE_OWNER', `${schema.name} has the wrong owner`)
    if (!categoryIds.has(schema.categoryId)) failProfileArtifact('BAD_PROFILE_CATEGORY_REGISTRY', `${schema.name} has an unknown category ID`)
    for (const dependency of schema.dependencies) {
      if (!classified.has(dependency)) failProfileArtifact('BAD_PROFILE_TYPE_REGISTRY', `${schema.name} has unclassified dependency ${dependency}`)
    }
  }
  for (const entry of externalTypes) {
    if (entry.owner !== 'hiverelay-substrate') failProfileArtifact('BAD_PROFILE_OWNER', `${entry.name} has the wrong external owner`)
  }
  for (const entry of externalCodecImports) {
    const classifiedType = externalTypes.find(value => value.name === entry.name)
    const wire = entry.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1
    const clientComposition = entry.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1
    if (!classifiedType || classifiedType.family !== entry.family || entry.minimumBytes < 1 || entry.maximumBytes < entry.minimumBytes ||
        (!wire && !clientComposition) ||
        (wire && (entry.tupleBinding !== PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING || entry.clientSchemaCommitment != null)) ||
        (clientComposition && (entry.tupleBinding !== PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING || entry.clientSchemaCommitment != null))) {
      failProfileArtifact('BAD_PROFILE_EXTERNAL_CODEC_IMPORT', `${entry.name} has an invalid external-codec authority or bound`)
    }
  }
  for (const entry of profileRegistries) {
    if (entry.owner !== inventoryOwner) failProfileArtifact('BAD_PROFILE_OWNER', `${entry.name} has the wrong registry owner`)
    if (!categoryNames.has(entry.category)) failProfileArtifact('BAD_PROFILE_CATEGORY_REGISTRY', `${entry.name} has an unknown category`)
  }
  return model
}

export function encodePeeritProfileRegistry (model) {
  if (!model || typeof model !== 'object') failProfileArtifact('BAD_PROFILE_ARTIFACT_ENCODING', 'profile registry model must be an object')
  const sourceBytes = canonicalProfileSourceBytes(model.profileSourceBytes)
  const tagBase = model.tagBase == null ? PEERIT_PROFILE_TAG_BASE : model.tagBase
  if (tagBase !== PEERIT_PROFILE_TAG_BASE) {
    failProfileArtifact('BAD_PROFILE_TAG_ALLOCATION', `profile tag base must be ${PEERIT_PROFILE_TAG_BASE}`)
  }
  const normalized = { ...model, tagBase, hashRecipes: model.hashRecipes || PROFILE_HASH_RECIPES }
  const payload = encodeInventoryPayload(normalized)
  const inventoryCommitment = domainLengthHash(PROFILE_ARTIFACT_DOMAIN.INVENTORY_COMMITMENT, payload)

  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_PROFILE_REGISTRY_MAGIC, 'profile registry magic')
  writer.u16(PEERIT_PROFILE_FORMAT_VERSION, 'profile registry formatVersion')
  writer.utf8U16(model.artifactId || PEERIT_PROFILE_ARTIFACT_ID, 'profile registry artifactId')
  writer.utf8U16(model.profileId || PEERIT_PROFILE_ID, 'profileId')
  writer.utf8U16(model.profileSourcePath || PEERIT_PROFILE_SOURCE_PATH, 'profileSourcePath')
  writer.u8(1, 'registryComplete')
  writer.u8(1, 'codecLayoutIrComplete')
  writer.u8(1, 'codecsComplete')
  writer.u8(0, 'releaseReady')
  writer.u16(tagBase, 'profile tag base')
  writer.fixed(model.profileSourceSha256, 32, 'profileSourceSha256')
  writer.fixed(hashPeeritProfileSpec(sourceBytes), 32, 'profileSpecHash')
  writer.u32(sourceBytes.byteLength, 'profile source length')
  writer.fixed(sourceBytes, sourceBytes.byteLength, 'profile source bytes')
  writer.fixed(inventoryCommitment, 32, 'inventoryCommitment')
  writer.u32(payload.byteLength, 'inventory payload length')
  writer.fixed(payload, payload.byteLength, 'inventory payload')
  return writer.finish()
}

export function decodePeeritProfileRegistry (value) {
  const bytes = asBytes(value, 'profile registry bytes')
  const reader = new CanonicalReader(bytes)
  reader.expectLiteralAscii(PEERIT_PROFILE_REGISTRY_MAGIC, 'profile registry magic')
  const formatVersion = reader.u16('profile registry formatVersion')
  if (formatVersion !== PEERIT_PROFILE_FORMAT_VERSION) {
    failProfileArtifact('BAD_PROFILE_ARTIFACT_VERSION', `unsupported profile registry version ${formatVersion}`)
  }
  const artifactId = reader.utf8U16('profile registry artifactId')
  const profileId = reader.utf8U16('profileId')
  const profileSourcePath = reader.utf8U16('profileSourcePath')
  if (artifactId !== PEERIT_PROFILE_ARTIFACT_ID || profileId !== PEERIT_PROFILE_ID || profileSourcePath !== PEERIT_PROFILE_SOURCE_PATH) {
    failProfileArtifact('BAD_PROFILE_ARTIFACT_IDENTITY', 'profile registry identity/source path does not equal the version-1 registry')
  }
  const registryComplete = reader.u8('registryComplete')
  const codecLayoutIrComplete = reader.u8('codecLayoutIrComplete')
  const codecsComplete = reader.u8('codecsComplete')
  const releaseReady = reader.u8('releaseReady')
  if (registryComplete !== 1 || codecLayoutIrComplete !== 1 || codecsComplete !== 1 || releaseReady !== 0) {
    failProfileArtifact('FALSE_PROFILE_COMPLETENESS_CLAIM', 'registry must claim complete registry, bounded codec IR, and executable codecs, while release readiness remains false')
  }
  const tagBase = reader.u16('profile tag base')
  if (tagBase !== PEERIT_PROFILE_TAG_BASE) failProfileArtifact('BAD_PROFILE_TAG_ALLOCATION', 'profile registry uses an unknown tag base')
  const profileSourceSha256 = reader.fixed(32, 'profileSourceSha256')
  const profileSpecHash = reader.fixed(32, 'profileSpecHash')
  const sourceLength = reader.u32('profile source length')
  const profileSourceBytes = canonicalProfileSourceBytes(reader.fixed(sourceLength, 'profile source bytes'))
  if (!bytesEqual(profileSpecHash, hashPeeritProfileSpec(profileSourceBytes))) {
    failProfileArtifact('PROFILE_SOURCE_BINDING_MISMATCH', 'embedded profile source does not reproduce profileSpecHash')
  }
  const inventoryCommitment = reader.fixed(32, 'inventoryCommitment')
  const payloadLength = reader.u32('inventory payload length')
  const inventoryPayload = reader.fixed(payloadLength, 'inventory payload')
  if (!bytesEqual(inventoryCommitment, domainLengthHash(PROFILE_ARTIFACT_DOMAIN.INVENTORY_COMMITMENT, inventoryPayload))) {
    failProfileArtifact('PROFILE_INVENTORY_COMMITMENT_MISMATCH', 'inventory payload does not reproduce inventoryCommitment')
  }
  reader.expectEnd('profile registry')
  const inventory = decodeInventoryPayload(inventoryPayload, tagBase)
  assertPeeritProfileCodecLayoutIrSet(inventory.schemas.map(entry => entry.codecIr), inventory)
  const compiledCodecIr = compilePeeritProfileCodecIr(
    new TextDecoder('utf-8', { fatal: true }).decode(profileSourceBytes),
    {
      schemas: inventory.schemas,
      externalTypes: inventory.externalTypes,
      externalCodecImports: inventory.externalCodecImports,
      profileRegistries: inventory.profileRegistries
    },
    { tagBase }
  )
  if (compiledCodecIr.schemas.length !== inventory.schemas.length) {
    failProfileArtifact('PROFILE_CODEC_IR_SOURCE_MISMATCH', 'embedded codec IR count does not equal the embedded profile source')
  }
  for (let index = 0; index < inventory.schemas.length; index++) {
    if (!bytesEqual(
      encodePeeritProfileSchemaCodecIr(compiledCodecIr.schemas[index]),
      encodePeeritProfileSchemaCodecIr(inventory.schemas[index].codecIr)
    )) {
      failProfileArtifact('PROFILE_CODEC_IR_SOURCE_MISMATCH', `${inventory.schemas[index].name} codec IR does not compile from the embedded profile source`)
    }
  }

  return Object.freeze({
    artifactId,
    profileId,
    profileSourcePath,
    formatVersion,
    registryComplete: true,
    codecLayoutIrComplete: true,
    codecsComplete: true,
    releaseReady: false,
    tagBase,
    profileSourceSha256,
    profileSpecHash,
    profileSourceBytes,
    inventoryCommitment,
    ...inventory
  })
}

function encodeDeclarationVectorSchema (writer, schema) {
  encodeSchemaEntry(writer, schema, schema.ordinal, PEERIT_PROFILE_TAG_BASE)
}

export function encodePeeritProfileDeclarationVector (value) {
  const writer = new CanonicalWriter()
  writer.literalAscii(PEERIT_PROFILE_VECTOR_MAGIC, 'profile vector magic')
  writer.u16(PEERIT_PROFILE_FORMAT_VERSION, 'profile vector formatVersion')
  writer.utf8U16(value.profileId, 'profile vector profileId')
  writer.fixed(value.profileSpecHash, 32, 'profile vector profileSpecHash')
  writer.fixed(value.profileAbiHash, 32, 'profile vector profileAbiHash')
  writer.fixed(value.inventoryCommitment, 32, 'profile vector inventoryCommitment')
  encodeDeclarationVectorSchema(writer, value.schema)
  return writer.finish()
}

export function decodePeeritProfileDeclarationVector (value) {
  const bytes = asBytes(value, 'profile declaration vector')
  const reader = new CanonicalReader(bytes)
  reader.expectLiteralAscii(PEERIT_PROFILE_VECTOR_MAGIC, 'profile vector magic')
  const formatVersion = reader.u16('profile vector formatVersion')
  if (formatVersion !== PEERIT_PROFILE_FORMAT_VERSION) failProfileArtifact('BAD_PROFILE_ARTIFACT_VERSION', 'unknown profile vector version')
  const profileId = reader.utf8U16('profile vector profileId')
  if (profileId !== PEERIT_PROFILE_ID) failProfileArtifact('BAD_PROFILE_ARTIFACT_IDENTITY', 'profile vector has the wrong profile ID')
  const profileSpecHash = reader.fixed(32, 'profile vector profileSpecHash')
  const profileAbiHash = reader.fixed(32, 'profile vector profileAbiHash')
  const inventoryCommitment = reader.fixed(32, 'profile vector inventoryCommitment')
  const ordinal = reader.u16('profile vector schema ordinal')
  if (ordinal < 1 || ordinal > PEERIT_PROFILE_SCHEMA_COUNT) {
    failProfileArtifact('BAD_PROFILE_TAG_ALLOCATION', 'profile vector ordinal is outside the version-1 registry')
  }
  const schema = decodeSchemaEntry(reader, ordinal, PEERIT_PROFILE_TAG_BASE, ordinal)
  reader.expectEnd('profile declaration vector')
  const decoded = { profileId, profileSpecHash, profileAbiHash, inventoryCommitment, schema }
  if (!bytesEqual(encodePeeritProfileDeclarationVector(decoded), bytes)) {
    failProfileArtifact('NONCANONICAL_PROFILE_VECTOR', 'profile declaration vector is not canonical')
  }
  return decoded
}

export function validatePeeritProfileVectorPath (value) {
  if (typeof value !== 'string' || value.length === 0 || value !== value.normalize('NFC')) {
    failProfileArtifact('BAD_PROFILE_VECTOR_PATH', 'vector path must be nonempty NFC text')
  }
  if (value.startsWith('/') || value.includes('\\')) {
    failProfileArtifact('BAD_PROFILE_VECTOR_PATH', 'vector path must be relative and use slash separators')
  }
  const components = value.split('/')
  if (components.some(component => component === '' || component === '.' || component === '..')) {
    failProfileArtifact('BAD_PROFILE_VECTOR_PATH', 'vector path contains a forbidden component')
  }
  const bytes = utf8Bytes(value, 'vector path')
  if (bytes.byteLength > 0xffff) failProfileArtifact('BAD_PROFILE_VECTOR_PATH', 'vector path exceeds u16 bytes')
  return bytes
}

export function encodePeeritProfileVectorManifest (entries) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_VECTOR_ENTRIES) {
    failProfileArtifact('BAD_PROFILE_VECTOR_MANIFEST', `vector manifest must contain 1..${MAX_VECTOR_ENTRIES} entries`)
  }
  const normalized = entries.map(entry => {
    if (!entry || typeof entry !== 'object') failProfileArtifact('BAD_PROFILE_VECTOR_MANIFEST', 'vector entry must be an object')
    const pathBytes = validatePeeritProfileVectorPath(entry.path)
    const vectorBytes = asBytes(entry.bytes, `${entry.path} bytes`)
    return { path: entry.path, pathBytes, length: BigInt(vectorBytes.byteLength), hash: blake2b256(vectorBytes) }
  }).sort((left, right) => compareBytes(left.pathBytes, right.pathBytes))
  for (let index = 1; index < normalized.length; index++) {
    if (compareBytes(normalized[index - 1].pathBytes, normalized[index].pathBytes) === 0) {
      failProfileArtifact('DUPLICATE_PROFILE_VECTOR_PATH', normalized[index].path)
    }
  }
  const writer = new CanonicalWriter()
  writer.u32(normalized.length, 'vector manifest entry count')
  for (const entry of normalized) {
    writer.utf8U16(entry.path, 'vector path')
    writer.u64(entry.length, `${entry.path} length`)
    writer.fixed(entry.hash, 32, `${entry.path} hash`)
  }
  return writer.finish()
}

export function decodePeeritProfileVectorManifest (value) {
  const reader = new CanonicalReader(value)
  const count = reader.u32('vector manifest entry count')
  if (count < 1 || count > MAX_VECTOR_ENTRIES) {
    failProfileArtifact('BAD_PROFILE_VECTOR_MANIFEST', `vector manifest must contain 1..${MAX_VECTOR_ENTRIES} entries`)
  }
  const entries = []
  let previousPathBytes = null
  for (let index = 0; index < count; index++) {
    const path = reader.utf8U16('vector path')
    const pathBytes = validatePeeritProfileVectorPath(path)
    if (previousPathBytes != null && compareBytes(previousPathBytes, pathBytes) >= 0) {
      failProfileArtifact('BAD_PROFILE_VECTOR_ORDER', 'vector manifest paths must be strictly sorted and unique')
    }
    previousPathBytes = pathBytes
    entries.push(Object.freeze({ path, length: reader.u64(`${path} length`), hash: reader.fixed(32, `${path} hash`) }))
  }
  reader.expectEnd('profile vector manifest')
  return Object.freeze(entries)
}

export function assertPeeritProfileVectorManifest (manifestBytes, vectors) {
  const entries = decodePeeritProfileVectorManifest(manifestBytes)
  let supplied
  if (vectors instanceof Map) {
    supplied = vectors
  } else {
    supplied = new Map()
    for (const entry of vectors) {
      if (supplied.has(entry.path)) failProfileArtifact('PROFILE_VECTOR_SET_DRIFT', `duplicate supplied vector ${entry.path}`)
      supplied.set(entry.path, entry.bytes)
    }
  }
  if (supplied.size !== entries.length) {
    failProfileArtifact('PROFILE_VECTOR_SET_DRIFT', `expected ${entries.length} exact vectors, received ${supplied.size}`)
  }
  for (const entry of entries) {
    if (!supplied.has(entry.path)) failProfileArtifact('PROFILE_VECTOR_SET_DRIFT', `missing vector ${entry.path}`)
    const bytes = asBytes(supplied.get(entry.path), `${entry.path} bytes`)
    if (BigInt(bytes.byteLength) !== entry.length || !bytesEqual(blake2b256(bytes), entry.hash)) {
      failProfileArtifact('PROFILE_VECTOR_BYTES_DRIFT', `${entry.path} does not match its manifest length/hash`)
    }
  }
  for (const path of supplied.keys()) {
    if (!entries.some(entry => entry.path === path)) failProfileArtifact('PROFILE_VECTOR_SET_DRIFT', `unexpected vector ${path}`)
  }
  return entries
}

export function assertFixedProfileHash (value, field) {
  return fixedBytesValue(value, 32, field)
}
