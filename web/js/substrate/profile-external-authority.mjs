import {
  asBytes,
  bytesEqual,
  domainLengthHash,
  hexToBytes
} from './release-control-primitives.mjs'

export const PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1 = Object.freeze({
  specHash: '470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9',
  abiHash: 'aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d',
  vectorSetHash: '09bd04c86f6f62b4636b9360fd2fca985a63537a0cec8642918f450ec70f9e78'
})
export const PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING =
  `wire-v1:${PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.specHash}:` +
  `${PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.abiHash}:` +
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.vectorSetHash

export const PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1 = Object.freeze({
  formatHash: '5637708aff4a6e93a6ff3a2f96361aa0b1597c229346e124eebeb2d7618ae09a',
  vectorSetHash: 'ea176ea78a611256689604541e55ba420d426dda2fa4dd64fb3ac9ac7503934d'
})
export const PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING =
  `client-composition-v1:${PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1.formatHash}:` +
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1.vectorSetHash

export const PEERIT_PROFILE_EXTERNAL_AUTHORITY = Object.freeze({
  WIRE_TUPLE_V1: 'WIRE_TUPLE_V1',
  CLIENT_COMPOSITION_V1: 'CLIENT_COMPOSITION_V1'
})

const WIRE_NAMES = Object.freeze(new Set(['BlindCoreAckV1', 'BlindReceiptV1', 'InboxAppendAckV1', 'InboxReceiptV1']))
const CLIENT_NAMES = Object.freeze(new Set(['BlindCoreReadCapV1', 'ReadCellCapV1']))
const AUTHENTICATED = new WeakMap()

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function strictDataSnapshot (value, names, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${field} must be a plain data object`)
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${field} must be a plain data object`)
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors)
  if (keys.length !== names.length || keys.some(key => typeof key !== 'string') || names.some(name => !Object.hasOwn(descriptors, name))) {
    fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${field} has a missing, unexpected, or symbolic property`)
  }
  const output = Object.create(null)
  for (const name of names) {
    const descriptor = descriptors[name]
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${field}.${name} must be an enumerable data property`)
    output[name] = descriptor.value
  }
  return output
}

function requireHash (domain, bytes, expectedHex, field) {
  bytes = new Uint8Array(asBytes(bytes, field))
  if (!bytesEqual(domainLengthHash(domain, bytes), hexToBytes(expectedHex, 32, `${field} expected hash`))) {
    fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_HASH_MISMATCH', `${field} does not reproduce its pinned authority hash`)
  }
  return bytes
}

export function authenticatePeeritProfileExternalCodecAuthorityV1 (input) {
  const value = strictDataSnapshot(input,
    ['name', 'authorityKind', 'authorityBinding', 'artifacts', 'assertCanonical'],
    'external codec authority')
  if (typeof value.assertCanonical !== 'function') fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', 'external canonical validator must be a function')
  if (value.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1) {
    if (!WIRE_NAMES.has(value.name) || value.authorityBinding !== PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING) {
      fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${value.name} is not a pinned WIRE import`)
    }
    const artifacts = strictDataSnapshot(value.artifacts, ['specBytes', 'abiBytes', 'vectorManifestBytes'], `${value.name} WIRE artifacts`)
    requireHash('hiverelay.blind.spec-hash.v1', artifacts.specBytes, PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.specHash, 'WIRE spec')
    requireHash('hiverelay.blind.abi-hash.v1', artifacts.abiBytes, PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.abiHash, 'WIRE ABI')
    requireHash('hiverelay.blind.vector-set-hash.v1', artifacts.vectorManifestBytes, PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.vectorSetHash, 'WIRE vectors')
  } else if (value.authorityKind === PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1) {
    if (!CLIENT_NAMES.has(value.name) || value.authorityBinding !== PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING) {
      fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${value.name} is not a pinned client-composition import`)
    }
    const artifacts = strictDataSnapshot(value.artifacts, ['formatAuthorityBytes', 'vectorManifestBytes'], `${value.name} client-composition artifacts`)
    requireHash('hiverelay.blind.client-composition-format-hash.v1', artifacts.formatAuthorityBytes,
      PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1.formatHash, 'client-composition format')
    requireHash('hiverelay.blind.client-composition-vector-set-hash.v1', artifacts.vectorManifestBytes,
      PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1.vectorSetHash, 'client-composition vectors')
  } else {
    fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `unknown external authority kind ${value.authorityKind}`)
  }
  const authority = Object.freeze({
    name: value.name,
    authorityKind: value.authorityKind,
    authorityBinding: value.authorityBinding,
    assertCanonical: value.assertCanonical
  })
  AUTHENTICATED.set(authority, Object.freeze({ productionTrusted: false }))
  return authority
}

export function isAuthenticatedPeeritProfileExternalCodecAuthorityV1 (value) {
  return value != null && typeof value === 'object' && AUTHENTICATED.has(value)
}

export function isProductionTrustedPeeritProfileExternalCodecAuthorityV1 (value) {
  return value != null && typeof value === 'object' &&
    AUTHENTICATED.get(value)?.productionTrusted === true
}

function productionAuthority (name, authorityKind, authorityBinding, decoder, runtimeAuthority) {
  const authority = Object.freeze({
    name,
    authorityKind,
    authorityBinding,
    assertCanonical (input, expectedName) {
      if (arguments.length !== 2 || expectedName !== name) {
        fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', `${name} authority cannot validate another schema`)
      }
      decoder(name, input)
    }
  })
  AUTHENTICATED.set(authority, Object.freeze({
    productionTrusted: true,
    runtimeAuthority
  }))
  return authority
}

// The dynamic import avoids a static profile-artifact/browser-runtime cycle.
// A caller can invoke this public function, but cannot mint anything from a
// shape-copy: getVerifiedPeeritBrowserRuntimeAssembly accepts only the private
// browser-runtime WeakMap brand created after exact artifact verification and
// authenticated module execution.
export async function assemblePeeritProfileExternalCodecAuthoritiesV1 (runtimeAuthority) {
  const { getVerifiedPeeritBrowserRuntimeAssembly } = await import('./browser-runtime-authority.mjs')
  const runtime = getVerifiedPeeritBrowserRuntimeAssembly(runtimeAuthority)
  const decoder = runtime?.control?.decodeBlindExternalProfileValueV1
  if (typeof decoder !== 'function') {
    fail('PROFILE_EXTERNAL_CODEC_AUTHORITY_MISMATCH', 'verified browser runtime has no closed external-profile decoder')
  }
  const output = Object.create(null)
  for (const name of WIRE_NAMES) {
    output[name] = productionAuthority(
      name,
      PEERIT_PROFILE_EXTERNAL_AUTHORITY.WIRE_TUPLE_V1,
      PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
      decoder,
      runtimeAuthority
    )
  }
  for (const name of CLIENT_NAMES) {
    output[name] = productionAuthority(
      name,
      PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1,
      PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
      decoder,
      runtimeAuthority
    )
  }
  return Object.freeze(output)
}
