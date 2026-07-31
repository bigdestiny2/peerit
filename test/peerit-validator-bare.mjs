import {
  PEERIT_VALIDATOR_PROFILE_BINDING_V1,
  computePeeritValidatorRuntimeVectorV1,
  computePeeritValidatorRuntimeVectorSetHashV1
} from '../protocol/validator/peerit-validator-v1.bare.mjs'

function hex (bytes) {
  let output = ''
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0')
  return output
}

if (PEERIT_VALIDATOR_PROFILE_BINDING_V1.schemaCount !== 78) throw new Error('Bare validator schema count drift')
const actual = hex(computePeeritValidatorRuntimeVectorV1())
const expected = `0101${'11'.repeat(32)}${'22'.repeat(32)}${'33'.repeat(32)}`
if (actual !== expected) throw new Error('Bare validator runtime vector drift')
const vectorSetHash = hex(computePeeritValidatorRuntimeVectorSetHashV1())
if (vectorSetHash !== '84d0cfd27a3b078ea839b2ec35ae9df7dd4ab619faa39dd8bef805f0c2b1c77c') throw new Error('Bare all-codec vector-set drift')
console.log(JSON.stringify({ schema: 'PeeritValidatorBareRuntimeV1', schemaCount: 78, runtimeVector: actual, vectorSetHash }))
