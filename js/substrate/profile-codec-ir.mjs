import {
  CanonicalReader,
  CanonicalWriter,
  asBytes,
  asciiBytes,
  bytesEqual,
  compareBytes,
  concatBytes,
  decodeUtf8,
  utf8Bytes
} from './release-control-primitives.mjs'
import { scanProfileDeclarations } from './profile-inventory-scan.mjs'
import {
  PEERIT_PROFILE_EXTERNAL_AUTHORITY,
  PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  isAuthenticatedPeeritProfileExternalCodecAuthorityV1,
  isProductionTrustedPeeritProfileExternalCodecAuthorityV1
} from './profile-external-authority.mjs'

export {
  PEERIT_PROFILE_EXTERNAL_AUTHORITY,
  PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
} from './profile-external-authority.mjs'

export const PEERIT_PROFILE_CODEC_IR_VERSION = 1

const MAX_U64 = (1n << 64n) - 1n
const MAX_CODEC_IR_BYTES = 1024 * 1024
const MAX_CODEC_IR_DEPTH = 32
const MAX_CODEC_IR_NODES = 16384
const MAX_CODEC_IR_FIELDS = 4096
const MAX_CODEC_IR_ARRAY_COUNT = 1048576

const NODE_KIND = Object.freeze({
  uint: 1,
  'fixed-bytes': 2,
  'literal-ascii': 3,
  bytes: 4,
  'dependent-bytes': 5,
  optional: 6,
  local: 7,
  external: 8,
  array: 9,
  record: 10,
  registry: 11,
  union: 12
})

const NODE_KIND_BY_ID = Object.freeze(Object.fromEntries(
  Object.entries(NODE_KIND).map(([name, id]) => [id, name])
))

const BYTE_FLAVOR = Object.freeze({
  opaque: 0,
  canonical: 1,
  'canonical-utf8': 2,
  'canonical-https-url': 3,
  'canonical-child': 4,
  'canonical-signed-child': 5,
  'canonical-legacy': 6
})

const BYTE_FLAVOR_BY_ID = Object.freeze(Object.fromEntries(
  Object.entries(BYTE_FLAVOR).map(([name, id]) => [id, name])
))

const ARRAY_ORDER = Object.freeze({ ordered: 0, sorted: 1 })
const ARRAY_ORDER_BY_ID = Object.freeze(['ordered', 'sorted'])

const SYMBOLIC_CONSTANTS = Object.freeze({
  'profiles 1 and 2 only': 6n,
  'classes 1 and 2 only': 3n,
  L90: 4n,
  R30: 3n
})

function failCodecIr (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details != null) error.details = details
  throw error
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      failCodecIr('BAD_PROFILE_CODEC_IR', `${field} must be an unsigned safe integer or bigint`)
    }
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    failCodecIr('BAD_PROFILE_CODEC_IR', `${field} is outside u64`)
  }
  return value
}

function requireIdentifier (value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9]*$/.test(value)) {
    failCodecIr('BAD_PROFILE_CODEC_IR', `${field} is not a canonical identifier`)
  }
  return value
}

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

function stripLineComment (line) {
  let quote = null
  let escaped = false
  for (let index = 0; index < line.length - 1; index++) {
    const character = line[index]
    if (quote != null) {
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      continue
    }
    if (character === '/' && line[index + 1] === '/') return line.slice(0, index)
  }
  return line
}

function normalizeExpression (value) {
  return value.replace(/\s+/g, ' ').replace(/\s+,/g, ',').trim().replace(/,$/, '').trim()
}

function splitFieldFragments (body) {
  const fragments = []
  let current = ''
  let depth = 0
  let quote = null
  let escaped = false
  const source = body.split('\n').map(stripLineComment).join('\n')
  for (let index = 0; index < source.length; index++) {
    const character = source[index]
    if (quote != null) {
      current += character
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      current += character
      continue
    }
    if (character === '{') depth++
    if (character === '}') depth--
    if (depth < 0) failCodecIr('PROFILE_CODEC_IR_PARSE_FAILED', 'inline record closes before it opens')
    if (depth === 0 && (character === ',' || character === '\n')) {
      const fragment = normalizeExpression(current)
      if (fragment) fragments.push(fragment)
      current = ''
      continue
    }
    current += character
  }
  if (depth !== 0 || quote != null) {
    failCodecIr('PROFILE_CODEC_IR_PARSE_FAILED', 'inline record has an unterminated delimiter')
  }
  const fragment = normalizeExpression(current)
  if (fragment) fragments.push(fragment)
  return fragments
}

function fieldEntries (body, owner) {
  const entries = []
  let current = null
  for (const fragment of splitFieldFragments(body)) {
    const match = /^([A-Za-z][A-Za-z0-9]*):\s*(.*)$/.exec(fragment)
    if (match) {
      if (current != null) entries.push(current)
      current = { name: match[1], expression: match[2] }
      continue
    }
    if (current == null) {
      failCodecIr('PROFILE_CODEC_IR_PARSE_FAILED', `${owner} contains a field continuation without a field`)
    }
    current.expression = `${current.expression} ${fragment}`
  }
  if (current != null) entries.push(current)
  const names = new Set()
  for (const entry of entries) {
    entry.expression = normalizeExpression(entry.expression)
    if (entry.expression.length === 0) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner}.${entry.name} has no encoding`)
    }
    if (names.has(entry.name)) {
      failCodecIr('PROFILE_CODEC_IR_DUPLICATE_FIELD', `${owner} repeats field ${entry.name}`)
    }
    names.add(entry.name)
  }
  if (entries.length === 0) failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} has no fields`)
  return entries
}

function declarationBody (source) {
  const open = source.indexOf('{')
  const close = source.lastIndexOf('}')
  if (open < 0 || close <= open) failCodecIr('PROFILE_CODEC_IR_PARSE_FAILED', 'declaration has no complete body')
  return source.slice(open + 1, close)
}

function prefixBitsForMaximum (maximum, field) {
  maximum = asU64(maximum, field)
  if (maximum <= 0xffn) return 8
  if (maximum <= 0xffffn) return 16
  if (maximum <= 0xffffffffn) return 32
  return 64
}

function uintMaximum (bits) {
  return (1n << BigInt(bits)) - 1n
}

function parseConstant (source, bits, owner) {
  const value = normalizeExpression(source)
  if (Object.prototype.hasOwnProperty.call(SYMBOLIC_CONSTANTS, value)) return SYMBOLIC_CONSTANTS[value]
  const numeric = /^(\d+)(?:\s+\(.*\))?$/.exec(value)
  if (!numeric) {
    failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} uses unknown integer constant ${JSON.stringify(value)}`)
  }
  const result = BigInt(numeric[1])
  if (result > uintMaximum(bits)) failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} constant exceeds u${bits}`)
  return result
}

function bytesFlavor (prefix) {
  if (/HTTPS URL/.test(prefix)) return 'canonical-https-url'
  if (/UTF-8/.test(prefix)) return 'canonical-utf8'
  if (/legacy/.test(prefix)) return 'canonical-legacy'
  if (/complete signed|fields before/.test(prefix)) return 'canonical-signed-child'
  if (/\b[A-Za-z][A-Za-z0-9]*V1\b/.test(prefix)) return 'canonical-child'
  if (/canonical/.test(prefix)) return 'canonical'
  return 'opaque'
}

function parseType (expression, context) {
  expression = normalizeExpression(expression)
  const owner = context.owner

  let match = /^optional\s+(.+)$/.exec(expression)
  if (match) return { kind: 'optional', value: parseType(match[1], context) }

  match = /^(sorted|ordered) array\[(\d+)\.\.(\d+)\] of (.+)$/.exec(expression)
  if (match) {
    const minimum = Number(match[2])
    const maximum = Number(match[3])
    if (!Number.isSafeInteger(maximum) || maximum < minimum) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} has invalid array bounds`)
    }
    return {
      kind: 'array',
      order: match[1],
      minimum,
      maximum,
      countPrefixBits: prefixBitsForMaximum(BigInt(maximum), `${owner} array maximum`),
      value: parseType(match[4], context)
    }
  }

  match = /^\{(.*)\}$/.exec(expression)
  if (match) {
    return {
      kind: 'record',
      fields: fieldEntries(match[1], `${owner} inline record`).map(entry => ({
        name: entry.name,
        type: parseType(entry.expression, { ...context, owner: `${owner}.${entry.name}` })
      }))
    }
  }

  match = /^exactly one tagged\s+([A-Za-z][A-Za-z0-9]*V1)$/.exec(expression)
  if (match) return { kind: 'local', name: match[1], maximumCompleteBytes: null }
  match = /^tagged\s+([A-Za-z][A-Za-z0-9]*V1)$/.exec(expression)
  if (match) return { kind: 'local', name: match[1], maximumCompleteBytes: null }

  match = /^generic\s+([A-Za-z][A-Za-z0-9]*V1)$/.exec(expression)
  if (match) {
    const external = context.externalTypes.get(match[1])
    if (external == null) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} names unknown external codec ${match[1]}`)
    }
    return {
      kind: 'external',
      name: external.name,
      family: external.family,
      authorityKind: external.authorityKind,
      tupleBinding: external.tupleBinding,
      clientSchemaCommitment: external.clientSchemaCommitment,
      minimum: BigInt(external.minimumBytes),
      maximum: BigInt(external.maximumBytes),
      lengthPrefixBits: prefixBitsForMaximum(BigInt(external.maximumBytes), `${owner} external maximum`)
    }
  }

  match = /^exact ASCII\s+"([\x20-\x7e]*)"\s+\((\d+) bytes\)$/.exec(expression)
  if (match) {
    const bytes = asciiBytes(match[1], owner)
    if (bytes.byteLength !== Number(match[2])) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} ASCII literal length does not match`)
    }
    return { kind: 'literal-ascii', value: match[1] }
  }

  match = /^"([\x20-\x7e]*)"$/.exec(expression)
  if (match) return { kind: 'literal-ascii', value: match[1] }

  match = /^u(8|16|32|64)(?:\s+in\s+(\d+)\.\.(\d+))?(?:\s*=\s*(.+))?$/.exec(expression)
  if (match) {
    const bits = Number(match[1])
    const minimum = match[2] == null ? 0n : BigInt(match[2])
    const maximum = match[3] == null ? uintMaximum(bits) : BigInt(match[3])
    if (maximum < minimum || maximum > uintMaximum(bits)) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} has invalid u${bits} constraints`)
    }
    const constant = match[4] == null ? null : parseConstant(match[4], bits, owner)
    if (constant != null && (constant < minimum || constant > maximum)) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} constant is outside its declared range`)
    }
    return { kind: 'uint', bits, minimum, maximum, constant }
  }

  match = /^(\d+)(?:-byte\b.*|\s+.*\bbytes?\b.*)$/.exec(expression)
  if (match) return { kind: 'fixed-bytes', length: Number(match[1]) }

  match = /^exact bytes\[([A-Za-z][A-Za-z0-9]*)\s*\+\s*(\d+);\s*max=(\d+)\]$/.exec(expression)
  if (match) {
    return {
      kind: 'dependent-bytes',
      lengthField: match[1],
      add: Number(match[2]),
      maximum: BigInt(match[3])
    }
  }

  match = /^(.*?)(?:bytes)\[(\d+)\.\.(\d+)\]$/.exec(expression)
  if (match) {
    const minimum = BigInt(match[2])
    const maximum = BigInt(match[3])
    if (maximum < minimum) failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} has invalid byte bounds`)
    return {
      kind: 'bytes',
      flavor: bytesFlavor(match[1]),
      contentType: (match[1].match(/\b([A-Za-z][A-Za-z0-9]*V1)\b/) || [])[1] || null,
      minimum,
      maximum,
      lengthPrefixBits: prefixBitsForMaximum(maximum, `${owner} byte maximum`)
    }
  }

  if (context.registries.has(expression)) {
    const registry = context.registries.get(expression)
    return { kind: 'registry', name: registry.name, bits: Number(registry.encoding.slice(1)) }
  }

  if (/^[A-Za-z][A-Za-z0-9]*V1$/.test(expression)) {
    if (!context.localTypes.has(expression)) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} names unclassified local codec ${expression}`)
    }
    return { kind: 'local', name: expression, maximumCompleteBytes: null }
  }

  failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner} has no executable codec for ${JSON.stringify(expression)}`)
}

function parseUnionVariants (source, context) {
  const variants = []
  const ids = new Set()
  const body = declarationBody(source)
  for (const fragment of splitFieldFragments(body)) {
    const match = /^(\d+):\s*(.+)$/.exec(fragment)
    if (!match) failCodecIr('PROFILE_CODEC_IR_PARSE_FAILED', `${context.owner} has malformed union variant ${fragment}`)
    const id = Number(match[1])
    let expression = normalizeExpression(match[2])
    let guard = null
    const guardMatch = /^(.*) with ([A-Za-z][A-Za-z0-9]*) (\d+)$/.exec(expression)
    if (guardMatch) {
      expression = normalizeExpression(guardMatch[1])
      guard = { field: guardMatch[2], equals: BigInt(guardMatch[3]) }
    }
    if (id < 1 || id > 0xff || ids.has(id)) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${context.owner} union IDs must be unique in 1..255`)
    }
    ids.add(id)
    variants.push({ id, guard, type: parseType(expression, { ...context, owner: `${context.owner} variant ${id}` }) })
  }
  variants.sort((left, right) => left.id - right.id)
  for (let index = 1; index < variants.length; index++) {
    if (variants[index].id !== variants[index - 1].id + 1) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${context.owner} union IDs must be contiguous`)
    }
  }
  if (variants.length === 0) failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${context.owner} has no union variants`)
  return { kind: 'union', tagBits: 8, variants }
}

function typeMaximum (type, localMaximums) {
  switch (type.kind) {
    case 'uint': return BigInt(type.bits / 8)
    case 'fixed-bytes': return BigInt(type.length)
    case 'literal-ascii': return BigInt(asciiBytes(type.value).byteLength)
    case 'bytes': return BigInt(type.lengthPrefixBits / 8) + type.maximum
    case 'dependent-bytes': return type.maximum
    case 'optional': return 1n + typeMaximum(type.value, localMaximums)
    case 'local': {
      const maximum = localMaximums == null ? type.maximumCompleteBytes : localMaximums.get(type.name)
      if (maximum == null) failCodecIr('PROFILE_CODEC_IR_DEPENDENCY_CYCLE', `codec maximum for ${type.name} is unresolved`)
      return maximum
    }
    case 'external': return BigInt(type.lengthPrefixBits / 8) + type.maximum
    case 'array': return BigInt(type.countPrefixBits / 8) + BigInt(type.maximum) * typeMaximum(type.value, localMaximums)
    case 'record': return type.fields.reduce((total, field) => total + typeMaximum(field.type, localMaximums), 0n)
    case 'registry': return BigInt(type.bits / 8)
    case 'union': return BigInt(type.tagBits / 8) + type.variants.reduce((maximum, variant) => {
      const value = typeMaximum(variant.type, localMaximums)
      return value > maximum ? value : maximum
    }, 0n)
    default: failCodecIr('BAD_PROFILE_CODEC_IR', `unknown codec node ${type.kind}`)
  }
}

function localDependencies (type, output = new Set()) {
  if (type.kind === 'local') output.add(type.name)
  else if (type.kind === 'optional' || type.kind === 'array') localDependencies(type.value, output)
  else if (type.kind === 'record') for (const field of type.fields) localDependencies(field.type, output)
  else if (type.kind === 'union') for (const variant of type.variants) localDependencies(variant.type, output)
  return output
}

function validateDependentLengths (type, owner) {
  if (type.kind === 'record') {
    for (let index = 0; index < type.fields.length; index++) {
      const field = type.fields[index]
      if (field.type.kind === 'dependent-bytes') {
        const lengthIndex = type.fields.findIndex(entry => entry.name === field.type.lengthField)
        const lengthType = lengthIndex < 0 ? null : type.fields[lengthIndex].type
        if (lengthIndex < 0 || lengthIndex >= index || lengthType.kind !== 'uint' ||
            lengthType.maximum + BigInt(field.type.add) !== field.type.maximum) {
          failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${owner}.${field.name} has an invalid dependent length source or maximum`)
        }
      }
      validateDependentLengths(field.type, `${owner}.${field.name}`)
    }
  } else if (type.kind === 'optional' || type.kind === 'array') {
    validateDependentLengths(type.value, owner)
  } else if (type.kind === 'union') {
    for (const variant of type.variants) validateDependentLengths(variant.type, `${owner} variant ${variant.id}`)
  }
}

function assertCodecPrefix (bits, maximum, owner) {
  if (![8, 16, 32, 64].includes(bits) || bits !== prefixBitsForMaximum(maximum, `${owner} maximum`)) {
    failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} uses a noncanonical fixed-width prefix`)
  }
}

function assertCodecTypeSemantics (type, context, owner, state, depth = 0) {
  state.nodes++
  if (state.nodes > MAX_CODEC_IR_NODES || depth > MAX_CODEC_IR_DEPTH || !type || typeof type !== 'object') {
    failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} exceeds codec IR structural limits`)
  }
  switch (type.kind) {
    case 'uint':
      if (![8, 16, 32, 64].includes(type.bits) || typeof type.minimum !== 'bigint' ||
          typeof type.maximum !== 'bigint' || type.minimum < 0n || type.maximum < type.minimum ||
          type.maximum > uintMaximum(type.bits) ||
          (type.constant != null && (typeof type.constant !== 'bigint' || type.constant < type.minimum || type.constant > type.maximum))) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has invalid unsigned integer constraints`)
      }
      return BigInt(type.bits / 8)
    case 'fixed-bytes':
      if (!Number.isSafeInteger(type.length) || type.length < 1 || type.length > 0xffffffff) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has an invalid fixed byte length`)
      }
      return BigInt(type.length)
    case 'literal-ascii': {
      const bytes = asciiBytes(type.value, owner)
      if (bytes.byteLength < 1 || bytes.byteLength > 0xffff) failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has an invalid ASCII literal`)
      return BigInt(bytes.byteLength)
    }
    case 'bytes':
      if (!Object.prototype.hasOwnProperty.call(BYTE_FLAVOR, type.flavor) || typeof type.minimum !== 'bigint' ||
          typeof type.maximum !== 'bigint' || type.minimum < 0n || type.maximum < type.minimum || type.maximum > MAX_U64 ||
          (type.contentType != null && !/^[A-Za-z][A-Za-z0-9]*V1$/.test(type.contentType))) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has invalid bounded-byte metadata`)
      }
      assertCodecPrefix(type.lengthPrefixBits, type.maximum, `${owner} byte length`)
      return BigInt(type.lengthPrefixBits / 8) + type.maximum
    case 'dependent-bytes':
      requireIdentifier(type.lengthField, `${owner} dependent length field`)
      if (!Number.isSafeInteger(type.add) || type.add < 0 || typeof type.maximum !== 'bigint' ||
          type.maximum < BigInt(type.add) || type.maximum > MAX_U64) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has invalid dependent-byte metadata`)
      }
      return type.maximum
    case 'optional':
      return 1n + assertCodecTypeSemantics(type.value, context, `${owner} optional value`, state, depth + 1)
    case 'local': {
      requireIdentifier(type.name, `${owner} local codec name`)
      if (typeof type.maximumCompleteBytes !== 'bigint' || type.maximumCompleteBytes < 3n || type.maximumCompleteBytes > MAX_U64) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has an invalid local-codec maximum`)
      }
      const target = context.schemaByName?.get(type.name)
      if (context.schemaByName && (!target || target.maximumCompleteBytes !== type.maximumCompleteBytes)) {
        failCodecIr('PROFILE_CODEC_IR_LOCAL_BINDING_MISMATCH', `${owner} local codec maximum does not bind ${type.name}`)
      }
      if (context.usedLocalNames) context.usedLocalNames.add(type.name)
      return type.maximumCompleteBytes
    }
    case 'external': {
      requireIdentifier(type.name, `${owner} external codec name`)
      requireIdentifier(type.family, `${owner} external codec family`)
      const wire = type.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1
      const clientComposition = type.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1
      if ((!wire && !clientComposition) ||
          (wire && (type.tupleBinding !== PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING || type.clientSchemaCommitment != null)) ||
          (clientComposition && (type.tupleBinding !== PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING || type.clientSchemaCommitment != null)) ||
          typeof type.minimum !== 'bigint' || typeof type.maximum !== 'bigint' ||
          type.minimum < 1n || type.maximum < type.minimum || type.maximum > 0xffffffffn) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has invalid external-codec authority or bounds`)
      }
      assertCodecPrefix(type.lengthPrefixBits, type.maximum, `${owner} external length`)
      const expected = context.externalImportByName?.get(type.name)
      if (context.externalImportByName && (!expected || expected.family !== type.family ||
          expected.authorityKind !== type.authorityKind || expected.tupleBinding !== type.tupleBinding ||
          expected.clientSchemaCommitment != null || BigInt(expected.minimumBytes) !== type.minimum ||
          BigInt(expected.maximumBytes) !== type.maximum)) {
        failCodecIr('PROFILE_CODEC_IR_EXTERNAL_IMPORT_DRIFT', `${owner} does not equal its external import registry row`)
      }
      if (context.usedExternalNames) context.usedExternalNames.add(type.name)
      return BigInt(type.lengthPrefixBits / 8) + type.maximum
    }
    case 'array': {
      if (!Object.prototype.hasOwnProperty.call(ARRAY_ORDER, type.order) ||
          !Number.isSafeInteger(type.minimum) || !Number.isSafeInteger(type.maximum) ||
          type.minimum < 0 || type.maximum < type.minimum || type.maximum < 1 ||
          type.maximum > MAX_CODEC_IR_ARRAY_COUNT) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has invalid array metadata`)
      }
      assertCodecPrefix(type.countPrefixBits, BigInt(type.maximum), `${owner} array count`)
      return BigInt(type.countPrefixBits / 8) + BigInt(type.maximum) *
        assertCodecTypeSemantics(type.value, context, `${owner} array value`, state, depth + 1)
    }
    case 'record': {
      if (!Array.isArray(type.fields) || type.fields.length < 1 || type.fields.length > MAX_CODEC_IR_FIELDS) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has an invalid record field count`)
      }
      const names = new Set()
      let maximum = 0n
      for (let index = 0; index < type.fields.length; index++) {
        const field = type.fields[index]
        requireIdentifier(field.name, `${owner} field name`)
        if (names.has(field.name)) failCodecIr('PROFILE_CODEC_IR_DUPLICATE_FIELD', `${owner} repeats field ${field.name}`)
        names.add(field.name)
        if (field.type.kind === 'dependent-bytes') {
          const lengthIndex = type.fields.findIndex(entry => entry.name === field.type.lengthField)
          const lengthType = lengthIndex < 0 ? null : type.fields[lengthIndex].type
          if (lengthIndex < 0 || lengthIndex >= index || lengthType.kind !== 'uint' ||
              lengthType.maximum + BigInt(field.type.add) !== field.type.maximum) {
            failCodecIr('BAD_PROFILE_CODEC_IR', `${owner}.${field.name} has an invalid dependent length binding`)
          }
        }
        maximum += assertCodecTypeSemantics(field.type, context, `${owner}.${field.name}`, state, depth + 1)
      }
      return maximum
    }
    case 'registry': {
      requireIdentifier(type.name, `${owner} registry name`)
      if (![8, 16, 32, 64].includes(type.bits)) failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has an invalid registry width`)
      const expected = context.registryByName?.get(type.name)
      if (context.registryByName && (!expected || Number(expected.encoding.slice(1)) !== type.bits)) {
        failCodecIr('PROFILE_CODEC_IR_REGISTRY_BINDING_MISMATCH', `${owner} does not bind registry ${type.name}`)
      }
      if (context.usedRegistryNames) context.usedRegistryNames.add(type.name)
      return BigInt(type.bits / 8)
    }
    case 'union': {
      if (type.tagBits !== 8 || !Array.isArray(type.variants) || type.variants.length < 1 || type.variants.length > 0xff) {
        failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has invalid union metadata`)
      }
      let maximum = 0n
      for (let index = 0; index < type.variants.length; index++) {
        const variant = type.variants[index]
        if (!Number.isSafeInteger(variant.id) || variant.id !== index + 1 || variant.id > 0xff) {
          failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} union variant IDs must be contiguous from one`)
        }
        if (variant.guard != null) {
          requireIdentifier(variant.guard.field, `${owner} union guard field`)
          if (typeof variant.guard.equals !== 'bigint' || variant.guard.equals < 0n || variant.guard.equals > MAX_U64) {
            failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} union guard value is invalid`)
          }
        }
        const variantMaximum = assertCodecTypeSemantics(variant.type, context, `${owner} variant ${variant.id}`, state, depth + 1)
        if (variantMaximum > maximum) maximum = variantMaximum
      }
      return 1n + maximum
    }
    default:
      failCodecIr('BAD_PROFILE_CODEC_IR', `${owner} has unknown codec node ${type.kind}`)
  }
}

function assertSchemaCodecLayout (schema, context = {}) {
  if (!schema || typeof schema !== 'object' || !Number.isSafeInteger(schema.ordinal) || schema.ordinal < 1 ||
      !Number.isSafeInteger(schema.tag) || schema.tag < 1 || schema.tag > 0xffff ||
      !/^[A-Za-z][A-Za-z0-9]*V1$/.test(schema.name) ||
      !['record', 'tagged-union'].includes(schema.kind) ||
      (schema.kind === 'record') !== (schema.body?.kind === 'record') ||
      (schema.kind === 'tagged-union') !== (schema.body?.kind === 'union') ||
      typeof schema.maximumCompleteBytes !== 'bigint') {
    failCodecIr('BAD_PROFILE_CODEC_IR', 'profile schema codec IR identity is invalid')
  }
  const computedMaximum = 2n + assertCodecTypeSemantics(schema.body, context, schema.name, { nodes: 0 })
  if (computedMaximum !== schema.maximumCompleteBytes || computedMaximum > MAX_U64) {
    failCodecIr('PROFILE_CODEC_IR_MAXIMUM_MISMATCH', `${schema.name} maximumCompleteBytes does not equal its IR`)
  }
  return true
}

export function assertPeeritProfileCodecLayoutIrSet (schemas, inventory) {
  if (!Array.isArray(schemas) || schemas.length < 1 || schemas.length > 0xffff || !inventory || typeof inventory !== 'object') {
    failCodecIr('BAD_PROFILE_CODEC_IR', 'codec layout IR set and inventory are required')
  }
  validateInventoryCodecInputs(inventory)
  const schemaByName = new Map(schemas.map(entry => [entry.name, entry]))
  if (schemaByName.size !== schemas.length) failCodecIr('BAD_PROFILE_CODEC_IR', 'codec layout IR schema names must be unique')
  const context = {
    schemaByName,
    externalImportByName: new Map(inventory.externalCodecImports.map(entry => [entry.name, entry])),
    registryByName: new Map(inventory.profileRegistries.map(entry => [entry.name, entry])),
    usedLocalNames: new Set(),
    usedExternalNames: new Set(),
    usedRegistryNames: new Set()
  }
  for (let index = 0; index < schemas.length; index++) {
    const schema = schemas[index]
    if (schema.ordinal !== index + 1 || schema.tag !== 0x0100 + index + 1) {
      failCodecIr('BAD_PROFILE_CODEC_IR', `${schema.name} has a noncontiguous ordinal or tag`)
    }
    assertSchemaCodecLayout(schema, context)
  }
  const usedExternal = [...context.usedExternalNames].sort()
  const declaredExternal = [...context.externalImportByName.keys()].sort()
  if (JSON.stringify(usedExternal) !== JSON.stringify(declaredExternal)) {
    failCodecIr('PROFILE_CODEC_IR_EXTERNAL_IMPORT_DRIFT', 'codec layout external imports do not equal the declared import registry')
  }
  const usedRegistries = [...context.usedRegistryNames].sort()
  const declaredRegistries = [...context.registryByName.keys()].sort()
  if (JSON.stringify(usedRegistries) !== JSON.stringify(declaredRegistries)) {
    failCodecIr('PROFILE_CODEC_IR_REGISTRY_BINDING_MISMATCH', 'codec layout registry references do not equal the declared closed registries')
  }
  return true
}

function validateInventoryCodecInputs (inventory) {
  if (!inventory || typeof inventory !== 'object') failCodecIr('BAD_PROFILE_CODEC_IR', 'profile inventory is required')
  const externalNames = new Map()
  for (const entry of inventory.externalTypes || []) {
    if (externalNames.has(entry.name)) failCodecIr('BAD_PROFILE_CODEC_IR', `duplicate external codec ${entry.name}`)
    externalNames.set(entry.name, entry)
  }
  const importNames = new Set()
  for (const entry of inventory.externalCodecImports || []) {
    if (importNames.has(entry.name) || !externalNames.has(entry.name) || externalNames.get(entry.name).family !== entry.family) {
      failCodecIr('BAD_PROFILE_CODEC_IR', `duplicate or unclassified external codec import ${entry.name}`)
    }
    importNames.add(entry.name)
    const wire = entry.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1
    const clientComposition = entry.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1
    if ((!wire && !clientComposition) ||
        (wire && (entry.tupleBinding !== PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING || entry.clientSchemaCommitment != null)) ||
        (clientComposition && (entry.tupleBinding !== PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING || entry.clientSchemaCommitment != null)) ||
        !Number.isSafeInteger(entry.minimumBytes) || !Number.isSafeInteger(entry.maximumBytes) ||
        entry.minimumBytes < 1 || entry.maximumBytes < entry.minimumBytes) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${entry.name} has an invalid external-codec authority or finite bound`)
    }
  }
  const registryNames = new Set()
  for (const entry of inventory.profileRegistries || []) {
    if (registryNames.has(entry.name)) failCodecIr('BAD_PROFILE_CODEC_IR', `duplicate profile registry ${entry.name}`)
    registryNames.add(entry.name)
    if (!/^u(?:8|16|32|64)$/.test(entry.encoding) || !Array.isArray(entry.values) || entry.values.length === 0) {
      failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${entry.name} lacks a closed integer registry`)
    }
    const bits = Number(entry.encoding.slice(1))
    const ids = new Set()
    for (const value of entry.values) {
      if (!Number.isSafeInteger(value.id) || value.id < 0 || BigInt(value.id) > uintMaximum(bits) || ids.has(value.id)) {
        failCodecIr('PROFILE_CODEC_IR_UNDERSPECIFIED', `${entry.name} has an invalid or duplicate value ID`)
      }
      ids.add(value.id)
    }
  }
}

export function compilePeeritProfileCodecIr (profileText, inventory, options = {}) {
  if (typeof profileText !== 'string') failCodecIr('BAD_PROFILE_CODEC_IR', 'profileText must be a string')
  validateInventoryCodecInputs(inventory)
  const scan = scanProfileDeclarations(profileText)
  const localTypes = new Set(scan.declarations.map(entry => entry.name))
  const externalTypes = new Map(inventory.externalCodecImports.map(entry => [entry.name, entry]))
  const registries = new Map(inventory.profileRegistries.map(entry => [entry.name, entry]))
  const inventorySchemas = new Map(inventory.schemas.map(entry => [entry.name, entry]))
  const tagBase = options.tagBase == null ? 0x0100 : options.tagBase
  const parsed = scan.declarations.map((declaration, index) => {
    const inventoryEntry = inventorySchemas.get(declaration.name)
    if (inventoryEntry == null) failCodecIr('BAD_PROFILE_CODEC_IR', `${declaration.name} is absent from the inventory`)
    const context = { owner: declaration.name, localTypes, externalTypes, registries }
    const body = declaration.kind === 'tagged-union'
      ? parseUnionVariants(declaration.source, context)
      : {
          kind: 'record',
          fields: fieldEntries(declarationBody(declaration.source), declaration.name).map(entry => ({
            name: entry.name,
            type: parseType(entry.expression, { ...context, owner: `${declaration.name}.${entry.name}` })
          }))
        }
    validateDependentLengths(body, declaration.name)
    return {
      ordinal: index + 1,
      tag: tagBase + index + 1,
      name: declaration.name,
      kind: declaration.kind,
      body,
      dependencies: [...localDependencies(body)].sort(),
      maximumCompleteBytes: null
    }
  })

  const byName = new Map(parsed.map(entry => [entry.name, entry]))
  const maximums = new Map()
  const visiting = new Set()
  function resolveMaximum (entry) {
    if (maximums.has(entry.name)) return maximums.get(entry.name)
    if (visiting.has(entry.name)) failCodecIr('PROFILE_CODEC_IR_DEPENDENCY_CYCLE', `codec graph cycles through ${entry.name}`)
    visiting.add(entry.name)
    for (const dependency of entry.dependencies) resolveMaximum(byName.get(dependency))
    const maximum = 2n + typeMaximum(entry.body, maximums)
    if (maximum > MAX_U64) failCodecIr('PROFILE_CODEC_IR_UNBOUNDED', `${entry.name} maximum exceeds u64`)
    entry.maximumCompleteBytes = maximum
    maximums.set(entry.name, maximum)
    visiting.delete(entry.name)
    return maximum
  }
  for (const entry of parsed) resolveMaximum(entry)
  function bindLocalMaximums (type) {
    if (type.kind === 'local') type.maximumCompleteBytes = maximums.get(type.name)
    else if (type.kind === 'optional' || type.kind === 'array') bindLocalMaximums(type.value)
    else if (type.kind === 'record') for (const field of type.fields) bindLocalMaximums(field.type)
    else if (type.kind === 'union') for (const variant of type.variants) bindLocalMaximums(variant.type)
  }
  for (const entry of parsed) bindLocalMaximums(entry.body)
  const usedExternalImports = new Set()
  function collectExternalImports (type) {
    if (type.kind === 'external') usedExternalImports.add(type.name)
    else if (type.kind === 'optional' || type.kind === 'array') collectExternalImports(type.value)
    else if (type.kind === 'record') for (const field of type.fields) collectExternalImports(field.type)
    else if (type.kind === 'union') for (const variant of type.variants) collectExternalImports(variant.type)
  }
  for (const entry of parsed) collectExternalImports(entry.body)
  const declaredImports = [...externalTypes.keys()].sort()
  const usedImports = [...usedExternalImports].sort()
  if (JSON.stringify(declaredImports) !== JSON.stringify(usedImports)) {
    failCodecIr('PROFILE_CODEC_IR_EXTERNAL_IMPORT_DRIFT', `declared imports ${declaredImports.join(',')} do not equal field imports ${usedImports.join(',')}`)
  }
  assertPeeritProfileCodecLayoutIrSet(parsed, inventory)

  const wireImportCount = [...externalTypes.values()].filter(entry => entry.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1).length
  const clientCompositionImportCount = [...externalTypes.values()].filter(entry => entry.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1).length
  return deepFreeze({
    version: PEERIT_PROFILE_CODEC_IR_VERSION,
    tagEncoding: 'u16be',
    optionalPresenceEncoding: 'u8-0-or-1',
    schemaCount: parsed.length,
    boundedSchemaCount: parsed.filter(entry => entry.maximumCompleteBytes != null).length,
    boundedStructuralIrReady: parsed.every(entry => entry.maximumCompleteBytes != null),
    semanticValidationComplete: false,
    externalCodecImportCount: usedExternalImports.size,
    externalWireTupleBinding: PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
    externalWireImportCount: wireImportCount,
    clientCompositionImportCount,
    pendingClientExampleImportCount: 0,
    externalCodecAuthorityComplete: wireImportCount + clientCompositionImportCount === usedExternalImports.size,
    schemas: parsed
  })
}

function writeU64 (writer, value, field) {
  writer.u64(asU64(value, field), field)
}

function encodeField (writer, field) {
  writer.utf8U16(requireIdentifier(field.name, 'codec field name'), 'codec field name')
  encodeType(writer, field.type)
}

function encodeType (writer, type) {
  const kind = NODE_KIND[type.kind]
  if (kind == null) failCodecIr('BAD_PROFILE_CODEC_IR', `unknown codec IR node ${type.kind}`)
  writer.u8(kind, 'codec node kind')
  switch (type.kind) {
    case 'uint':
      writer.u8(type.bits, 'uint bits')
      writeU64(writer, type.minimum, 'uint minimum')
      writeU64(writer, type.maximum, 'uint maximum')
      writer.u8(type.constant == null ? 0 : 1, 'uint constant presence')
      if (type.constant != null) writeU64(writer, type.constant, 'uint constant')
      return
    case 'fixed-bytes':
      writer.u32(type.length, 'fixed byte length')
      return
    case 'literal-ascii':
      writer.utf8U16(type.value, 'ASCII literal')
      return
    case 'bytes':
      writer.u8(BYTE_FLAVOR[type.flavor], 'byte flavor')
      writer.u8(type.lengthPrefixBits, 'byte length prefix bits')
      writeU64(writer, type.minimum, 'byte minimum')
      writeU64(writer, type.maximum, 'byte maximum')
      writer.u8(type.contentType == null ? 0 : 1, 'byte content type presence')
      if (type.contentType != null) writer.utf8U16(requireIdentifier(type.contentType, 'byte content type'), 'byte content type')
      return
    case 'dependent-bytes':
      writer.utf8U16(requireIdentifier(type.lengthField, 'dependent byte field'), 'dependent byte field')
      writer.u32(type.add, 'dependent byte addend')
      writeU64(writer, type.maximum, 'dependent byte maximum')
      return
    case 'optional':
      encodeType(writer, type.value)
      return
    case 'local':
      writer.utf8U16(requireIdentifier(type.name, 'local codec name'), 'local codec name')
      writeU64(writer, type.maximumCompleteBytes, 'local codec maximum complete bytes')
      return
    case 'external':
      writer.utf8U16(requireIdentifier(type.name, 'external codec name'), 'external codec name')
      writer.utf8U16(requireIdentifier(type.family, 'external codec family'), 'external codec family')
      writer.utf8U16(type.authorityKind, 'external authority kind')
      writer.u8(type.tupleBinding == null ? 0 : 1, 'external tuple binding presence')
      if (type.tupleBinding != null) writer.utf8U16(type.tupleBinding, 'external tuple binding')
      writer.u8(type.clientSchemaCommitment == null ? 0 : 1, 'client schema commitment presence')
      if (type.clientSchemaCommitment != null) writer.fixed(type.clientSchemaCommitment, 32, 'client schema commitment')
      writer.u8(type.lengthPrefixBits, 'external length prefix bits')
      writeU64(writer, type.minimum, 'external byte minimum')
      writeU64(writer, type.maximum, 'external byte maximum')
      return
    case 'array':
      writer.u8(ARRAY_ORDER[type.order], 'array order')
      writer.u8(type.countPrefixBits, 'array count prefix bits')
      writer.u32(type.minimum, 'array minimum')
      writer.u32(type.maximum, 'array maximum')
      encodeType(writer, type.value)
      return
    case 'record':
      writer.u16(type.fields.length, 'record field count')
      for (const field of type.fields) encodeField(writer, field)
      return
    case 'registry':
      writer.utf8U16(requireIdentifier(type.name, 'registry codec name'), 'registry codec name')
      writer.u8(type.bits, 'registry bits')
      return
    case 'union':
      writer.u8(type.tagBits, 'union tag bits')
      writer.u16(type.variants.length, 'union variant count')
      for (const variant of type.variants) {
        writer.u16(variant.id, 'union variant ID')
        writer.u8(variant.guard == null ? 0 : 1, 'union guard presence')
        if (variant.guard != null) {
          writer.utf8U16(requireIdentifier(variant.guard.field, 'union guard field'), 'union guard field')
          writeU64(writer, variant.guard.equals, 'union guard value')
        }
        encodeType(writer, variant.type)
      }
  }
}

function readType (reader, state = { nodes: 0 }, depth = 0) {
  state.nodes++
  if (state.nodes > MAX_CODEC_IR_NODES || depth > MAX_CODEC_IR_DEPTH) {
    failCodecIr('BAD_PROFILE_CODEC_IR', 'codec IR exceeds its node/depth budget')
  }
  const kindId = reader.u8('codec node kind')
  const kind = NODE_KIND_BY_ID[kindId]
  if (kind == null) failCodecIr('BAD_PROFILE_CODEC_IR', `unknown codec IR node ID ${kindId}`)
  switch (kind) {
    case 'uint': {
      const bits = reader.u8('uint bits')
      const minimum = reader.u64('uint minimum')
      const maximum = reader.u64('uint maximum')
      const present = reader.u8('uint constant presence')
      if (present > 1) failCodecIr('BAD_PROFILE_CODEC_IR', 'uint constant presence must be 0 or 1')
      return { kind, bits, minimum, maximum, constant: present === 1 ? reader.u64('uint constant') : null }
    }
    case 'fixed-bytes': return { kind, length: reader.u32('fixed byte length') }
    case 'literal-ascii': return { kind, value: reader.utf8U16('ASCII literal') }
    case 'bytes': {
      const flavorId = reader.u8('byte flavor')
      const flavor = BYTE_FLAVOR_BY_ID[flavorId]
      if (flavor == null) failCodecIr('BAD_PROFILE_CODEC_IR', `unknown byte flavor ${flavorId}`)
      const lengthPrefixBits = reader.u8('byte length prefix bits')
      const minimum = reader.u64('byte minimum')
      const maximum = reader.u64('byte maximum')
      const present = reader.u8('byte content type presence')
      if (present > 1) failCodecIr('BAD_PROFILE_CODEC_IR', 'byte content type presence must be 0 or 1')
      return { kind, flavor, lengthPrefixBits, minimum, maximum, contentType: present === 1 ? reader.utf8U16('byte content type') : null }
    }
    case 'dependent-bytes': return {
      kind,
      lengthField: reader.utf8U16('dependent byte field'),
      add: reader.u32('dependent byte addend'),
      maximum: reader.u64('dependent byte maximum')
    }
    case 'optional': return { kind, value: readType(reader, state, depth + 1) }
    case 'local': return {
      kind,
      name: reader.utf8U16('local codec name'),
      maximumCompleteBytes: reader.u64('local codec maximum complete bytes')
    }
    case 'external': {
      const name = reader.utf8U16('external codec name')
      const family = reader.utf8U16('external codec family')
      const authorityKind = reader.utf8U16('external authority kind')
      const tuplePresent = reader.u8('external tuple binding presence')
      if (tuplePresent > 1) failCodecIr('BAD_PROFILE_CODEC_IR', 'external tuple binding presence must be 0 or 1')
      const tupleBinding = tuplePresent === 1 ? reader.utf8U16('external tuple binding') : null
      const commitmentPresent = reader.u8('client schema commitment presence')
      if (commitmentPresent > 1) failCodecIr('BAD_PROFILE_CODEC_IR', 'client schema commitment presence must be 0 or 1')
      const clientSchemaCommitment = commitmentPresent === 1 ? reader.fixed(32, 'client schema commitment') : null
      return {
        kind,
        name,
        family,
        authorityKind,
        tupleBinding,
        clientSchemaCommitment,
        lengthPrefixBits: reader.u8('external length prefix bits'),
        minimum: reader.u64('external byte minimum'),
        maximum: reader.u64('external byte maximum')
      }
    }
    case 'array': return {
      kind,
      order: ARRAY_ORDER_BY_ID[reader.u8('array order')],
      countPrefixBits: reader.u8('array count prefix bits'),
      minimum: reader.u32('array minimum'),
      maximum: reader.u32('array maximum'),
      value: readType(reader, state, depth + 1)
    }
    case 'record': {
      const fields = []
      const count = reader.u16('record field count')
      if (count < 1 || count > MAX_CODEC_IR_FIELDS) failCodecIr('BAD_PROFILE_CODEC_IR', 'codec record field count is outside its budget')
      for (let index = 0; index < count; index++) fields.push({ name: reader.utf8U16('codec field name'), type: readType(reader, state, depth + 1) })
      return { kind, fields }
    }
    case 'registry': return { kind, name: reader.utf8U16('registry codec name'), bits: reader.u8('registry bits') }
    case 'union': {
      const tagBits = reader.u8('union tag bits')
      const variants = []
      const count = reader.u16('union variant count')
      if (count < 1 || count > 0xff) failCodecIr('BAD_PROFILE_CODEC_IR', 'codec union variant count is outside 1..255')
      for (let index = 0; index < count; index++) {
        const id = reader.u16('union variant ID')
        const present = reader.u8('union guard presence')
        if (present > 1) failCodecIr('BAD_PROFILE_CODEC_IR', 'union guard presence must be 0 or 1')
        const guard = present === 1
          ? { field: reader.utf8U16('union guard field'), equals: reader.u64('union guard value') }
          : null
        variants.push({ id, guard, type: readType(reader, state, depth + 1) })
      }
      return { kind, tagBits, variants }
    }
  }
}

export function encodePeeritProfileSchemaCodecIr (schema) {
  assertSchemaCodecLayout(schema)
  const writer = new CanonicalWriter()
  writer.u8(PEERIT_PROFILE_CODEC_IR_VERSION, 'codec IR version')
  writer.u16(schema.ordinal, 'codec schema ordinal')
  writer.u16(schema.tag, 'codec schema tag')
  writer.utf8U16(requireIdentifier(schema.name, 'codec schema name'), 'codec schema name')
  writer.u8(schema.kind === 'record' ? 0 : schema.kind === 'tagged-union' ? 1 : 0xff, 'codec schema kind')
  writeU64(writer, schema.maximumCompleteBytes, 'codec maximum complete bytes')
  encodeType(writer, schema.body)
  return writer.finish()
}

export function decodePeeritProfileSchemaCodecIr (input) {
  const bytes = asBytes(input, 'profile schema codec IR')
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_CODEC_IR_BYTES) {
    failCodecIr('BAD_PROFILE_CODEC_IR', `profile schema codec IR must be bytes[1..${MAX_CODEC_IR_BYTES}]`)
  }
  const reader = new CanonicalReader(bytes)
  const version = reader.u8('codec IR version')
  if (version !== PEERIT_PROFILE_CODEC_IR_VERSION) failCodecIr('BAD_PROFILE_CODEC_IR', `unknown codec IR version ${version}`)
  const ordinal = reader.u16('codec schema ordinal')
  const tag = reader.u16('codec schema tag')
  const name = reader.utf8U16('codec schema name')
  const kindId = reader.u8('codec schema kind')
  const kind = kindId === 0 ? 'record' : kindId === 1 ? 'tagged-union' : null
  if (kind == null) failCodecIr('BAD_PROFILE_CODEC_IR', `unknown codec schema kind ${kindId}`)
  const maximumCompleteBytes = reader.u64('codec maximum complete bytes')
  const body = readType(reader)
  reader.expectEnd('profile schema codec IR')
  const value = deepFreeze({ version, ordinal, tag, name, kind, maximumCompleteBytes, body })
  assertSchemaCodecLayout(value)
  const canonical = encodePeeritProfileSchemaCodecIr(value)
  if (!bytesEqual(canonical, bytes)) failCodecIr('NONCANONICAL_PROFILE_CODEC_IR', `${name} codec IR is not canonical`)
  return value
}

function writeInteger (writer, bits, value, field) {
  if (bits === 8) writer.u8(Number(value), field)
  else if (bits === 16) writer.u16(Number(value), field)
  else if (bits === 32) writer.u32(Number(value), field)
  else if (bits === 64) writer.u64(value, field)
  else failCodecIr('BAD_PROFILE_CODEC_IR', `${field} has unsupported integer width ${bits}`)
}

function strictObjectSnapshot (value, fields, owner) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} must be an object`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} must be a plain object`)
  const names = fields.map(field => field.name)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== names.length || keys.some(key => typeof key !== 'string') ||
      names.some(name => !Object.prototype.hasOwnProperty.call(descriptors, name))) {
    failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} fields are missing or unexpected`)
  }
  const snapshot = Object.create(null)
  for (const name of names) {
    const descriptor = descriptors[name]
    if (!descriptor || !descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner}.${name} must be an enumerable data property`)
    }
    snapshot[name] = descriptor.value
  }
  return snapshot
}

function strictArraySnapshot (value, owner) {
  if (!Array.isArray(value)) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} must be an array`)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors)
  const lengthDescriptor = descriptors.length
  const length = lengthDescriptor?.value
  if (!lengthDescriptor || !Number.isSafeInteger(length) || length < 0) {
    failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} has an invalid array length`)
  }
  const expected = new Set(Array.from({ length }, (_, index) => String(index)).concat('length'))
  if (keys.length !== expected.size || keys.some(key => typeof key !== 'string' || !expected.has(key))) {
    failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} must be dense and have no extra properties`)
  }
  const snapshot = new Array(length)
  for (let index = 0; index < length; index++) {
    const descriptor = descriptors[index]
    if (!descriptor || !descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner}[${index}] must be an enumerable data property`)
    }
    snapshot[index] = descriptor.value
  }
  return snapshot
}

function immutableInputBytes (value, owner) {
  return new Uint8Array(asBytes(value, owner))
}

function validateByteFlavor (bytes, type, owner) {
  if (type.flavor === 'canonical-utf8' || type.flavor === 'canonical-https-url') {
    const text = decodeUtf8(bytes, owner)
    if (!bytesEqual(bytes, utf8Bytes(text, owner))) {
      failCodecIr('NONCANONICAL_PROFILE_CODEC_VALUE', `${owner} is not canonical UTF-8`)
    }
    if (type.flavor === 'canonical-https-url') {
      let parsed
      try {
        parsed = new URL(text)
      } catch {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} is not an absolute HTTPS URL`)
      }
      if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '' ||
          parsed.search !== '' || parsed.hash !== '' || parsed.href !== text) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${owner} must be a canonical credential-free HTTPS URL without query or fragment`)
      }
    }
  }
}

function externalAuthorityFor (type, context) {
  const authority = context.externalAuthorityByName?.get(type.name)
  if (authority == null) {
    failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_REQUIRED', `${context.owner} requires authenticated ${type.name} codec authority`)
  }
  if (authority.authorityKind !== type.authorityKind || authority.authorityBinding !== type.tupleBinding ||
      typeof authority.assertCanonical !== 'function') {
    failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${context.owner} external authority does not equal the registry binding for ${type.name}`)
  }
  return authority
}

function canonicalSortProjection (context, type, value, encoded) {
  if (typeof context.sortProjection !== 'function') return encoded
  const projection = context.sortProjection(context.owner, type, value, encoded)
  return immutableInputBytes(projection, `${context.owner} sort projection`)
}

function encodeValue (writer, type, value, context) {
  switch (type.kind) {
    case 'uint': {
      const integer = asU64(value, context.owner)
      if (type.constant != null && integer !== type.constant) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} must equal its constant`)
      if (integer < type.minimum || integer > type.maximum) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} is outside its range`)
      writeInteger(writer, type.bits, integer, context.owner)
      return
    }
    case 'fixed-bytes':
      writer.fixed(immutableInputBytes(value, context.owner), type.length, context.owner)
      return
    case 'literal-ascii':
      if (value !== type.value) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} does not equal its literal`)
      writer.literalAscii(type.value, context.owner)
      return
    case 'bytes': {
      const bytes = immutableInputBytes(value, context.owner)
      if (BigInt(bytes.byteLength) < type.minimum || BigInt(bytes.byteLength) > type.maximum) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} is outside its byte bounds`)
      }
      validateByteFlavor(bytes, type, context.owner)
      writeInteger(writer, type.lengthPrefixBits, BigInt(bytes.byteLength), `${context.owner} length`)
      writer.fixed(bytes, bytes.byteLength, context.owner)
      return
    }
    case 'dependent-bytes': {
      const bytes = immutableInputBytes(value, context.owner)
      const base = asU64(context.parent[type.lengthField], `${context.owner} length field`)
      const expected = base + BigInt(type.add)
      if (BigInt(bytes.byteLength) !== expected || BigInt(bytes.byteLength) > type.maximum) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} does not match ${type.lengthField}+${type.add}`)
      }
      writer.fixed(bytes, bytes.byteLength, context.owner)
      return
    }
    case 'optional':
      if (value == null) writer.u8(0, `${context.owner} presence`)
      else {
        writer.u8(1, `${context.owner} presence`)
        encodeValue(writer, type.value, value, context)
      }
      return
    case 'local':
      encodeSchemaValue(writer, context.schemaByName.get(type.name), value, context)
      return
    case 'external': {
      const bytes = immutableInputBytes(value, context.owner)
      if (BigInt(bytes.byteLength) < type.minimum || BigInt(bytes.byteLength) > type.maximum) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} external bytes are outside bounds`)
      }
      const authority = externalAuthorityFor(type, context)
      authority.assertCanonical(new Uint8Array(bytes), type.name)
      writeInteger(writer, type.lengthPrefixBits, BigInt(bytes.byteLength), `${context.owner} length`)
      writer.fixed(bytes, bytes.byteLength, context.owner)
      return
    }
    case 'array': {
      const values = strictArraySnapshot(value, context.owner)
      if (values.length < type.minimum || values.length > type.maximum) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} count is outside bounds`)
      }
      writeInteger(writer, type.countPrefixBits, BigInt(values.length), `${context.owner} count`)
      const encoded = []
      for (let index = 0; index < values.length; index++) {
        const itemWriter = new CanonicalWriter()
        encodeValue(itemWriter, type.value, values[index], { ...context, owner: `${context.owner}[${index}]` })
        const itemBytes = itemWriter.finish()
        encoded.push({
          bytes: itemBytes,
          projection: canonicalSortProjection(context, type, values[index], itemBytes)
        })
      }
      if (type.order === 'sorted') {
        for (let index = 1; index < encoded.length; index++) {
          if (compareBytes(encoded[index - 1].projection, encoded[index].projection) >= 0) {
            failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} must be strictly sorted and duplicate-free`)
          }
        }
      }
      for (const item of encoded) writer.fixed(item.bytes, item.bytes.byteLength, `${context.owner} item`)
      return
    }
    case 'record':
      value = strictObjectSnapshot(value, type.fields, context.owner)
      for (const field of type.fields) {
        encodeValue(writer, field.type, value[field.name], { ...context, owner: `${context.owner}.${field.name}`, parent: value })
      }
      return
    case 'registry': {
      const registry = context.registryByName.get(type.name)
      if (!registry.values.some(entry => BigInt(entry.id) === asU64(value, context.owner))) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} is outside closed registry ${type.name}`)
      }
      writeInteger(writer, type.bits, asU64(value, context.owner), context.owner)
      return
    }
    case 'union': {
      value = strictObjectSnapshot(value, [{ name: 'variant' }, { name: 'value' }], context.owner)
      if (!Number.isSafeInteger(value.variant)) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} must contain variant and value`)
      }
      const variant = type.variants.find(entry => entry.id === value.variant)
      if (variant == null) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} has unknown union variant`)
      if (variant.guard != null) {
        const guarded = value.value?.[variant.guard.field]
        if (asU64(guarded, `${context.owner}.${variant.guard.field}`) !== variant.guard.equals) {
          failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} variant ${variant.id} requires ${variant.guard.field}=${variant.guard.equals}`)
        }
      }
      writeInteger(writer, type.tagBits, BigInt(variant.id), `${context.owner} variant`)
      encodeValue(writer, variant.type, value.value, { ...context, owner: `${context.owner}.value` })
    }
  }
}

function encodeSchemaValue (writer, schema, value, context) {
  if (schema == null) failCodecIr('BAD_PROFILE_CODEC_IR', 'local codec schema is missing')
  writer.u16(schema.tag, `${schema.name} tag`)
  encodeValue(writer, schema.body, value, { ...context, owner: schema.name, parent: value })
}

export function encodePeeritProfileValueFromIr (compiled, inventory, schemaName, value, options = {}) {
  const schemaByName = new Map(compiled.schemas.map(entry => [entry.name, entry]))
  const schema = schemaByName.get(schemaName)
  if (schema == null) failCodecIr('BAD_PROFILE_CODEC_VALUE', `unknown profile codec ${schemaName}`)
  const writer = new CanonicalWriter()
  encodeSchemaValue(writer, schema, value, {
    schemaByName,
    registryByName: new Map(inventory.profileRegistries.map(entry => [entry.name, entry])),
    externalAuthorityByName: options.externalAuthorityByName,
    sortProjection: options.sortProjection
  })
  const bytes = writer.finish()
  if (BigInt(bytes.byteLength) > schema.maximumCompleteBytes) {
    failCodecIr('BAD_PROFILE_CODEC_IR', `${schema.name} encoder exceeded its compiled maximum`)
  }
  return bytes
}

export function encodePeeritProfileRecordPrefixFromIr (compiled, inventory, schemaName, value, fieldExclusive, options = {}) {
  const schemaByName = new Map(compiled.schemas.map(entry => [entry.name, entry]))
  const schema = schemaByName.get(schemaName)
  if (schema == null || schema.body.kind !== 'record') {
    failCodecIr('BAD_PROFILE_CODEC_VALUE', `${schemaName} is not a profile record codec`)
  }
  const end = schema.body.fields.findIndex(field => field.name === fieldExclusive)
  if (end < 0) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${schemaName} has no field ${fieldExclusive}`)
  const snapshot = strictObjectSnapshot(value, schema.body.fields, schemaName)
  const writer = new CanonicalWriter()
  writer.u16(schema.tag, `${schema.name} tag`)
  const context = {
    schemaByName,
    registryByName: new Map(inventory.profileRegistries.map(entry => [entry.name, entry])),
    externalAuthorityByName: options.externalAuthorityByName,
    sortProjection: options.sortProjection
  }
  for (let index = 0; index < end; index++) {
    const field = schema.body.fields[index]
    encodeValue(writer, field.type, snapshot[field.name], {
      ...context,
      owner: `${schema.name}.${field.name}`,
      parent: snapshot,
      depth: 1
    })
  }
  return writer.finish()
}

export function encodePeeritProfileTypeValueFromIr (compiled, inventory, type, value, owner = 'profile value', options = {}) {
  const writer = new CanonicalWriter()
  encodeValue(writer, type, value, {
    schemaByName: new Map(compiled.schemas.map(entry => [entry.name, entry])),
    registryByName: new Map(inventory.profileRegistries.map(entry => [entry.name, entry])),
    externalAuthorityByName: options.externalAuthorityByName,
    sortProjection: options.sortProjection,
    owner,
    parent: options.parent || null,
    depth: 0
  })
  return writer.finish()
}

function readIntegerValue (reader, bits, field) {
  if (bits === 8) return BigInt(reader.u8(field))
  if (bits === 16) return BigInt(reader.u16(field))
  if (bits === 32) return BigInt(reader.u32(field))
  if (bits === 64) return reader.u64(field)
  failCodecIr('BAD_PROFILE_CODEC_IR', `${field} has unsupported integer width ${bits}`)
}

function publicIntegerValue (value, bits) {
  return bits === 64 ? value : Number(value)
}

function decodeValue (reader, type, context, state) {
  state.nodes++
  if (state.nodes > MAX_CODEC_IR_NODES || context.depth > MAX_CODEC_IR_DEPTH) {
    failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} exceeds the codec depth/node budget`)
  }
  switch (type.kind) {
    case 'uint': {
      const integer = readIntegerValue(reader, type.bits, context.owner)
      if (integer < type.minimum || integer > type.maximum || (type.constant != null && integer !== type.constant)) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} is outside its compiled range or constant`)
      }
      return publicIntegerValue(integer, type.bits)
    }
    case 'fixed-bytes':
      return reader.fixed(type.length, context.owner)
    case 'literal-ascii':
      return reader.expectLiteralAscii(type.value, context.owner)
    case 'bytes': {
      const length = readIntegerValue(reader, type.lengthPrefixBits, `${context.owner} length`)
      if (length < type.minimum || length > type.maximum || length > BigInt(reader.remaining)) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} length is outside bounds or truncated`)
      }
      const bytes = reader.fixed(Number(length), context.owner)
      validateByteFlavor(bytes, type, context.owner)
      return bytes
    }
    case 'dependent-bytes': {
      const base = asU64(context.parent[type.lengthField], `${context.owner} length source`)
      const length = base + BigInt(type.add)
      if (length > type.maximum || length > BigInt(reader.remaining) || length > BigInt(Number.MAX_SAFE_INTEGER)) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} dependent length is invalid or truncated`)
      }
      return reader.fixed(Number(length), context.owner)
    }
    case 'optional': {
      const present = reader.u8(`${context.owner} presence`)
      if (present === 0) return null
      if (present !== 1) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} presence must be 0 or 1`)
      return decodeValue(reader, type.value, { ...context, depth: context.depth + 1 }, state)
    }
    case 'local':
      return decodeSchemaValue(reader, context.schemaByName.get(type.name), { ...context, depth: context.depth + 1 }, state)
    case 'external': {
      const length = readIntegerValue(reader, type.lengthPrefixBits, `${context.owner} length`)
      if (length < type.minimum || length > type.maximum || length > BigInt(reader.remaining)) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} external length is outside bounds or truncated`)
      }
      const bytes = reader.fixed(Number(length), context.owner)
      externalAuthorityFor(type, context).assertCanonical(new Uint8Array(bytes), type.name)
      return bytes
    }
    case 'array': {
      const count = readIntegerValue(reader, type.countPrefixBits, `${context.owner} count`)
      if (count < BigInt(type.minimum) || count > BigInt(type.maximum) || count > BigInt(MAX_CODEC_IR_ARRAY_COUNT)) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} count is outside bounds`)
      }
      const values = []
      let previousProjection = null
      for (let index = 0; index < Number(count); index++) {
        const itemWriter = new CanonicalWriter()
        const item = decodeValue(reader, type.value, { ...context, owner: `${context.owner}[${index}]`, depth: context.depth + 1 }, state)
        encodeValue(itemWriter, type.value, item, { ...context, owner: `${context.owner}[${index}]`, depth: context.depth + 1 })
        const itemBytes = itemWriter.finish()
        const projection = canonicalSortProjection(context, type, item, itemBytes)
        if (type.order === 'sorted' && previousProjection != null && compareBytes(previousProjection, projection) >= 0) {
          failCodecIr('NONCANONICAL_PROFILE_CODEC_ORDER', `${context.owner} is not strictly sorted or contains a duplicate`)
        }
        previousProjection = projection
        values.push(item)
      }
      return values
    }
    case 'record': {
      const output = {}
      for (const field of type.fields) {
        output[field.name] = decodeValue(reader, field.type, {
          ...context,
          owner: `${context.owner}.${field.name}`,
          parent: output,
          depth: context.depth + 1
        }, state)
      }
      return output
    }
    case 'registry': {
      const integer = readIntegerValue(reader, type.bits, context.owner)
      const registry = context.registryByName.get(type.name)
      if (!registry || !registry.values.some(entry => BigInt(entry.id) === integer)) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} is outside closed registry ${type.name}`)
      }
      return publicIntegerValue(integer, type.bits)
    }
    case 'union': {
      const variantId = Number(readIntegerValue(reader, type.tagBits, `${context.owner} variant`))
      const variant = type.variants.find(entry => entry.id === variantId)
      if (variant == null) failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} has unknown union variant ${variantId}`)
      const value = decodeValue(reader, variant.type, { ...context, owner: `${context.owner}.value`, depth: context.depth + 1 }, state)
      if (variant.guard != null && asU64(value?.[variant.guard.field], `${context.owner}.${variant.guard.field}`) !== variant.guard.equals) {
        failCodecIr('BAD_PROFILE_CODEC_VALUE', `${context.owner} variant ${variant.id} violates its guard`)
      }
      return { variant: variantId, value }
    }
    default:
      failCodecIr('BAD_PROFILE_CODEC_IR', `${context.owner} uses unknown codec node ${type.kind}`)
  }
}

function decodeSchemaValue (reader, schema, context, state) {
  if (schema == null) failCodecIr('BAD_PROFILE_CODEC_IR', 'local codec schema is missing')
  const tag = reader.u16(`${schema.name} tag`)
  if (tag !== schema.tag) failCodecIr('BAD_PROFILE_CODEC_TAG', `${schema.name} tag ${tag} does not equal ${schema.tag}`)
  return decodeValue(reader, schema.body, { ...context, owner: schema.name }, state)
}

export function decodePeeritProfileValueFromIr (compiled, inventory, schemaName, input, options = {}) {
  const schemaByName = new Map(compiled.schemas.map(entry => [entry.name, entry]))
  const schema = schemaByName.get(schemaName)
  if (schema == null) failCodecIr('BAD_PROFILE_CODEC_VALUE', `unknown profile codec ${schemaName}`)
  const bytes = immutableInputBytes(input, `${schemaName} bytes`)
  if (bytes.byteLength < 2 || BigInt(bytes.byteLength) > schema.maximumCompleteBytes) {
    failCodecIr('BAD_PROFILE_CODEC_VALUE', `${schemaName} bytes are outside the compiled complete-record bound`)
  }
  const context = {
    schemaByName,
    registryByName: new Map(inventory.profileRegistries.map(entry => [entry.name, entry])),
    externalAuthorityByName: options.externalAuthorityByName,
    sortProjection: options.sortProjection,
    owner: schemaName,
    parent: null,
    depth: 0
  }
  const reader = new CanonicalReader(bytes)
  const decoded = decodeSchemaValue(reader, schema, context, { nodes: 0 })
  reader.expectEnd(schemaName)
  const reencoded = encodePeeritProfileValueFromIr(compiled, inventory, schemaName, decoded, options)
  if (!bytesEqual(bytes, reencoded)) {
    failCodecIr('NONCANONICAL_PROFILE_CODEC_VALUE', `${schemaName} does not round-trip canonically`)
  }
  return decoded
}

function snapshotExternalAuthorities (inventory, authorities, production) {
  if (!authorities || typeof authorities !== 'object') {
    if (inventory.externalCodecImports.length === 0) return new Map()
    failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_REQUIRED', 'external codec authority bindings are required')
  }
  const descriptors = Object.getOwnPropertyDescriptors(authorities)
  const keys = Reflect.ownKeys(descriptors)
  const expected = inventory.externalCodecImports.map(entry => entry.name).sort()
  if (keys.some(key => typeof key !== 'string') || keys.length !== expected.length ||
      expected.some(name => !Object.prototype.hasOwnProperty.call(descriptors, name))) {
    failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', 'external authority catalog must contain exactly the declared imports')
  }
  const output = new Map()
  for (const row of inventory.externalCodecImports) {
    const descriptor = descriptors[row.name]
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${row.name} authority must be a data property`)
    }
    const authority = descriptor.value
    if (!authority || typeof authority !== 'object' || !isAuthenticatedPeeritProfileExternalCodecAuthorityV1(authority)) {
      failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${row.name} authority is not authenticated from exact pinned artifacts`)
    }
    if (production === true && !isProductionTrustedPeeritProfileExternalCodecAuthorityV1(authority)) {
      failCodecIr('PROFILE_EXTERNAL_CODEC_PRODUCTION_AUTHORITY_REQUIRED', `${row.name} requires the decoder from a verified browser runtime authority`)
    }
    const authorityDescriptors = Object.getOwnPropertyDescriptors(authority)
    if (Reflect.ownKeys(authorityDescriptors).some(key => typeof key !== 'string') ||
        !Object.prototype.hasOwnProperty.call(authorityDescriptors, 'authorityKind') ||
        !Object.prototype.hasOwnProperty.call(authorityDescriptors, 'authorityBinding') ||
        !Object.prototype.hasOwnProperty.call(authorityDescriptors, 'assertCanonical') ||
        !Object.values(authorityDescriptors).every(value => Object.prototype.hasOwnProperty.call(value, 'value'))) {
      failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${row.name} authority surface must contain data properties only`)
    }
    const snapshot = Object.freeze({
      authorityKind: authorityDescriptors.authorityKind.value,
      authorityBinding: authorityDescriptors.authorityBinding.value,
      assertCanonical: authorityDescriptors.assertCanonical.value
    })
    if (snapshot.authorityKind !== row.authorityKind || snapshot.authorityBinding !== row.tupleBinding ||
        typeof snapshot.assertCanonical !== 'function') {
      failCodecIr('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${row.name} authority does not equal its pinned registry row`)
    }
    output.set(row.name, snapshot)
  }
  return output
}

export function createPeeritProfileCodecCatalogFromIr (compiled, inventory, options = {}) {
  assertPeeritProfileCodecLayoutIrSet(compiled.schemas, inventory)
  const externalAuthorityByName = snapshotExternalAuthorities(
    inventory,
    options.externalAuthorities,
    options.production === true
  )
  const runtimeOptions = Object.freeze({ externalAuthorityByName, sortProjection: options.sortProjection })
  const catalog = Object.create(null)
  for (const schema of compiled.schemas) {
    catalog[schema.name] = Object.freeze({
      tag: schema.tag,
      maximumCompleteBytes: schema.maximumCompleteBytes,
      encode: value => encodePeeritProfileValueFromIr(compiled, inventory, schema.name, value, runtimeOptions),
      decode: bytes => decodePeeritProfileValueFromIr(compiled, inventory, schema.name, bytes, runtimeOptions)
    })
  }
  return Object.freeze(catalog)
}

export function peeritProfileSchemaCodecIrHashInput (schema) {
  return concatBytes(Uint8Array.of(PEERIT_PROFILE_CODEC_IR_VERSION), encodePeeritProfileSchemaCodecIr(schema))
}
