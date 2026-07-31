import { compareBytes } from './release-control-primitives.mjs'
import { encodePeeritProfileTypeValueFromIr } from './profile-codec-ir.mjs'
import { peeritProfileNamedSortProjection } from './profile-validator.mjs'

function deterministicBytes (length, seed) {
  const output = new Uint8Array(length)
  for (let index = 0; index < length; index++) output[index] = (seed * 29 + index * 17 + 1) & 0xff
  if (length > 0 && output.every(byte => byte === 0)) output[length - 1] = 1
  return output
}

function registryValue (inventory, type) {
  const registry = inventory.profileRegistries.find(entry => entry.name === type.name)
  const value = registry.values[0].id
  return type.bits === 64 ? BigInt(value) : value
}

function minimumInteger (type) {
  const value = type.constant == null ? type.minimum : type.constant
  return type.bits === 64 ? value : Number(value)
}

export function createPeeritProfileStructuralFixtureFactory (compiled, inventory, options = {}) {
  const schemaByName = new Map(compiled.schemas.map(entry => [entry.name, entry]))
  let serial = 1

  function valueFor (type, owner, seed = ++serial, parent = null) {
    switch (type.kind) {
      case 'uint': return minimumInteger(type)
      case 'fixed-bytes': return deterministicBytes(type.length, seed)
      case 'literal-ascii': return type.value
      case 'bytes': {
        if (type.flavor === 'canonical-utf8') return new TextEncoder().encode(`fixture-${seed}`)
        if (type.flavor === 'canonical-https-url') return new TextEncoder().encode(`https://example.com/fixture-${seed}`)
        return deterministicBytes(Number(type.minimum), seed)
      }
      case 'dependent-bytes':
        return deterministicBytes(Number(BigInt(parent[type.lengthField]) + BigInt(type.add)), seed)
      case 'optional': return null
      case 'local': return valueFor(schemaByName.get(type.name).body, type.name, seed)
      case 'external': return deterministicBytes(Number(type.minimum), seed)
      case 'array': {
        const values = []
        for (let index = 0; index < type.minimum; index++) {
          values.push(valueFor(type.value, `${owner}[${index}]`, seed + index + 1))
        }
        if (type.order === 'sorted') {
          const projections = values.map((value, index) => ({
            value,
            encoded: encodePeeritProfileTypeValueFromIr(compiled, inventory, type.value, value, `${owner}[${index}]`, options)
          }))
          for (let index = 0; index < projections.length; index++) {
            projections[index].projection = peeritProfileNamedSortProjection(
              `${owner}[${index}]`, type, projections[index].value, projections[index].encoded
            )
          }
          projections.sort((left, right) => compareBytes(left.projection, right.projection))
          return projections.map(entry => entry.value)
        }
        return values
      }
      case 'record': {
        const value = {}
        for (let index = 0; index < type.fields.length; index++) {
          const field = type.fields[index]
          value[field.name] = valueFor(field.type, `${owner}.${field.name}`, seed + index, value)
        }
        return value
      }
      case 'registry': return registryValue(inventory, type)
      case 'union': {
        const variant = type.variants[0]
        const value = valueFor(variant.type, `${owner}.value`, seed)
        if (variant.guard != null) value[variant.guard.field] = Number(variant.guard.equals)
        return { variant: variant.id, value }
      }
      default: throw new Error(`unsupported fixture codec node ${type.kind}`)
    }
  }

  return Object.freeze({
    create (schemaName, seed = null) {
      const schema = schemaByName.get(schemaName)
      if (schema == null) throw new Error(`unknown profile schema ${schemaName}`)
      return valueFor(schema.body, schema.name, seed == null ? (serial += 101) : seed)
    }
  })
}
