import { sha256 as sha256Hash } from '../vendor/noble-hashes/sha2.js'
import { bytesToHex } from './release-control-primitives.mjs'

const DECLARATION_HEADER = /^([A-Za-z][A-Za-z0-9]*V1)(\s+=\s+tagged union)?\s+\{\s*(?:\/\/.*)?$/
const PROFILE_TYPE_REFERENCE = /\b[A-Za-z][A-Za-z0-9]*V1\b/g

function sha256 (value) {
  return bytesToHex(sha256Hash(new TextEncoder().encode(value)))
}

function sortedUnique (values) {
  return [...new Set(values)].sort()
}

function braceTokens (source) {
  const tokens = []
  const stack = []
  let quote = null
  let escaped = false
  let lineComment = false

  for (let index = 0; index < source.length; index++) {
    const character = source[index]
    const next = source[index + 1]

    if (lineComment) {
      if (character === '\n') lineComment = false
      continue
    }
    if (quote) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === quote) quote = null
      continue
    }
    if (character === '/' && next === '/') {
      lineComment = true
      index++
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      continue
    }
    if (character === '{') {
      const token = { kind: 'open', index, depth: stack.length, match: null }
      stack.push(token)
      tokens.push(token)
      continue
    }
    if (character === '}') {
      const open = stack.pop()
      if (!open) throw new Error(`unmatched closing brace at byte ${index}`)
      const token = { kind: 'close', index, depth: stack.length, match: open }
      open.match = token
      tokens.push(token)
    }
  }

  return { tokens, openCount: stack.length }
}

function normalizeShape (value) {
  return value.replace(/[ \t]+$/gm, '').trim()
}

function inlineShapes (source) {
  const { tokens, openCount } = braceTokens(source)
  if (openCount !== 0) throw new Error('declaration has an unclosed brace')
  const opens = tokens.filter(token => token.kind === 'open')
  if (opens.length === 0 || opens[0].depth !== 0) throw new Error('declaration has no outer record brace')
  return opens.slice(1).map((open, index) => {
    const shape = normalizeShape(source.slice(open.index, open.match.index + 1))
    return Object.freeze({
      ordinal: index + 1,
      depth: open.depth,
      relativeLine: source.slice(0, open.index).split('\n').length,
      sha256: sha256(shape)
    })
  })
}

function referencedTypes (source) {
  return sortedUnique(source.match(PROFILE_TYPE_REFERENCE) || [])
}

export function scanProfileDeclarations (profileText) {
  if (typeof profileText !== 'string') throw new TypeError('profileText must be a string')
  const lines = profileText.split('\n')
  const declarations = []
  let inTextFence = false

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]
    if (line === '```text') {
      inTextFence = true
      continue
    }
    if (line === '```') {
      inTextFence = false
      continue
    }
    if (!inTextFence) continue

    const header = DECLARATION_HEADER.exec(line)
    if (!header) continue
    const declarationLines = [line]
    let end = index
    let analysis = braceTokens(line)
    while (analysis.openCount !== 0) {
      end++
      if (end >= lines.length || lines[end] === '```') {
        throw new Error(`unterminated declaration ${header[1]} at line ${index + 1}`)
      }
      declarationLines.push(lines[end])
      analysis = braceTokens(declarationLines.join('\n'))
    }

    const source = declarationLines.join('\n')
    const canonicalSource = normalizeShape(source)
    const name = header[1]
    declarations.push(Object.freeze({
      name,
      kind: header[2] ? 'tagged-union' : 'record',
      startLine: index + 1,
      endLine: end + 1,
      source: canonicalSource,
      sourceSha256: sha256(canonicalSource),
      referencedTypes: Object.freeze(referencedTypes(source).filter(type => type !== name)),
      inlineShapes: Object.freeze(inlineShapes(source))
    }))
    index = end
  }

  return Object.freeze({
    profileSha256: sha256(profileText),
    declarations: Object.freeze(declarations),
    allReferencedTypes: Object.freeze(referencedTypes(profileText))
  })
}

function duplicateNames (values) {
  const counts = new Map()
  for (const value of values) counts.set(value, (counts.get(value) || 0) + 1)
  return [...counts].filter(([, count]) => count > 1).map(([name]) => name).sort()
}

function sameJson (left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function problem (code, detail) {
  return Object.freeze({ code, detail })
}

export function verifyProfileInventory (profileText, inventory) {
  if (!inventory || typeof inventory !== 'object') throw new TypeError('inventory must be an object')
  const scan = scanProfileDeclarations(profileText)
  const entries = inventory.schemas || []
  const externalTypes = inventory.externalTypes || []
  const externalCodecImports = inventory.externalCodecImports || []
  const registries = inventory.profileRegistries || []
  const categories = inventory.categories || []
  const problems = []

  const actualNames = scan.declarations.map(declaration => declaration.name)
  const expectedNames = entries.map(entry => entry.name)
  const actualByName = new Map(scan.declarations.map(declaration => [declaration.name, declaration]))
  const externalByName = new Map(externalTypes.map(entry => [entry.name, entry]))
  const externalImportByName = new Map(externalCodecImports.map(entry => [entry.name, entry]))
  const registryByName = new Map(registries.map(entry => [entry.name, entry]))
  const categoryIds = categories.map(category => category.id)

  for (const name of duplicateNames(actualNames)) problems.push(problem('DUPLICATE_PROFILE_DECLARATION', name))
  for (const name of duplicateNames(expectedNames)) problems.push(problem('DUPLICATE_INVENTORY_DECLARATION', name))
  for (const name of duplicateNames(externalTypes.map(entry => entry.name))) problems.push(problem('DUPLICATE_EXTERNAL_TYPE', name))
  for (const name of duplicateNames(externalCodecImports.map(entry => entry.name))) problems.push(problem('DUPLICATE_EXTERNAL_CODEC_IMPORT', name))
  for (const name of duplicateNames(registries.map(entry => entry.name))) problems.push(problem('DUPLICATE_PROFILE_REGISTRY', name))
  for (const name of duplicateNames(categoryIds)) problems.push(problem('DUPLICATE_CATEGORY', name))

  for (const name of sortedUnique(expectedNames.filter(name => !actualNames.includes(name)))) {
    problems.push(problem('MISSING_PROFILE_DECLARATION', name))
  }
  for (const name of sortedUnique(actualNames.filter(name => !expectedNames.includes(name)))) {
    problems.push(problem('EXTRA_PROFILE_DECLARATION', name))
  }

  for (const entry of entries) {
    if (entry.owner !== 'peerit-profile') problems.push(problem('WRONG_SCHEMA_OWNER', `${entry.name}:${entry.owner}`))
    if (!categoryIds.includes(entry.category)) problems.push(problem('UNKNOWN_SCHEMA_CATEGORY', `${entry.name}:${entry.category}`))
    const declaration = actualByName.get(entry.name)
    if (!declaration) continue
    if (declaration.kind !== entry.kind) problems.push(problem('WRONG_DECLARATION_KIND', entry.name))
    if (declaration.sourceSha256 !== entry.sourceSha256) problems.push(problem('DECLARATION_SOURCE_DRIFT', entry.name))
    if (!sameJson(declaration.referencedTypes, entry.dependencies)) {
      problems.push(problem('DECLARATION_DEPENDENCY_DRIFT', entry.name))
    }
    if (!sameJson(declaration.inlineShapes, entry.inlineShapes)) {
      problems.push(problem('INLINE_SHAPE_DRIFT', entry.name))
    }
  }

  for (const external of externalTypes) {
    if (external.owner !== 'hiverelay-substrate') problems.push(problem('WRONG_EXTERNAL_OWNER', `${external.name}:${external.owner}`))
    if (actualByName.has(external.name)) problems.push(problem('EXTERNAL_TYPE_DECLARED_BY_PROFILE', external.name))
  }
  const declaredGenericTypes = sortedUnique(scan.declarations.flatMap(declaration =>
    [...declaration.source.matchAll(/\bgeneric\s+([A-Za-z][A-Za-z0-9]*V1)\b/g)].map(match => match[1])
  ))
  for (const entry of externalCodecImports) {
    if (!externalByName.has(entry.name)) problems.push(problem('UNCLASSIFIED_EXTERNAL_CODEC_IMPORT', entry.name))
    if (actualByName.has(entry.name) || registryByName.has(entry.name)) problems.push(problem('INVALID_EXTERNAL_CODEC_IMPORT_OWNER', entry.name))
  }
  for (const name of sortedUnique(declaredGenericTypes.filter(name => !externalImportByName.has(name)))) {
    problems.push(problem('MISSING_EXTERNAL_CODEC_IMPORT', name))
  }
  for (const name of sortedUnique([...externalImportByName.keys()].filter(name => !declaredGenericTypes.includes(name)))) {
    problems.push(problem('EXTRA_EXTERNAL_CODEC_IMPORT', name))
  }
  for (const registry of registries) {
    if (registry.owner !== 'peerit-profile') problems.push(problem('WRONG_REGISTRY_OWNER', `${registry.name}:${registry.owner}`))
    if (actualByName.has(registry.name)) problems.push(problem('REGISTRY_DECLARED_AS_SCHEMA', registry.name))
  }

  const classifiedNames = new Set([...expectedNames, ...externalByName.keys(), ...registryByName.keys()])
  for (const name of scan.allReferencedTypes) {
    if (!classifiedNames.has(name)) problems.push(problem('UNCLASSIFIED_PROFILE_TYPE_REFERENCE', name))
  }
  for (const name of externalByName.keys()) {
    if (!scan.allReferencedTypes.includes(name)) problems.push(problem('EXTRA_EXTERNAL_TYPE', name))
  }
  for (const name of registryByName.keys()) {
    if (!scan.allReferencedTypes.includes(name)) problems.push(problem('EXTRA_PROFILE_REGISTRY', name))
  }

  for (const declaration of scan.declarations) {
    for (const dependency of declaration.referencedTypes) {
      if (!classifiedNames.has(dependency)) {
        problems.push(problem('UNCLASSIFIED_DECLARATION_DEPENDENCY', `${declaration.name}:${dependency}`))
      }
    }
  }

  const categoryCounts = Object.fromEntries(categories.map(category => [
    category.id,
    entries.filter(entry => entry.category === category.id).length
  ]))
  for (const category of categories) {
    if (categoryCounts[category.id] !== category.schemaCount) {
      problems.push(problem('CATEGORY_COUNT_DRIFT', `${category.id}:${categoryCounts[category.id]}/${category.schemaCount}`))
    }
  }
  const inlineShapeCount = scan.declarations.reduce((total, declaration) => total + declaration.inlineShapes.length, 0)
  const recordCount = scan.declarations.filter(declaration => declaration.kind === 'record').length
  const taggedUnionCount = scan.declarations.filter(declaration => declaration.kind === 'tagged-union').length

  return Object.freeze({
    ok: problems.length === 0,
    profileSha256: scan.profileSha256,
    declarationCount: scan.declarations.length,
    recordCount,
    taggedUnionCount,
    inlineShapeCount,
    externalTypeCount: externalTypes.length,
    externalCodecImportCount: externalCodecImports.length,
    profileRegistryCount: registries.length,
    categoryCounts: Object.freeze(categoryCounts),
    problems: Object.freeze(problems),
    scan
  })
}
