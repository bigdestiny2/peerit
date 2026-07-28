// relay-consumer.js — fail-closed browser seam for generic HiveRelay relay
// discovery and qualification.
//
// Candidate provenance is deliberately permissionless: recommendations, user
// entries, peers, and DHT observations are equal untrusted inputs. A URL is only
// a hint. Even a descriptor hash supplied beside that URL is only an immutable
// fetch coordinate; relay authority comes from the authenticated Peerit profile
// pins plus the blind-client descriptor chain, signatures, fresh health,
// admission parameters, and exact operation qualification.
//
// The active qualifier below composes the local @hiverelay/blind-client control
// contract without weakening any of its opaque types. The production installer
// remains fail closed until the release graph can supply the authenticated
// browser artifact/profile/runtime authority. Lease-aware requalification and
// encrypted device-local state are implemented and browser-tested; portable
// capability recovery remains an explicit release blocker. Local authoring and
// its publication queue remain available with zero relays.

import {
  PROFILE_RELEASE_BLOCKERS,
  assertPeeritProfileReleaseReady
} from './profile-status.mjs'
import { createPeeritCapabilityVault } from './capability-vault.js'
import { createPeeritDescriptorTrustBackend } from './descriptor-trust-backend.js'
import {
  PEERIT_RELAY_REQUALIFICATION_STATUS,
  createPeeritRelayRequalificationScheduler
} from './relay-requalification-scheduler.js'
import {
  getVerifiedPeeritBrowserRuntimeAssembly,
  isVerifiedPeeritBrowserRuntimeAuthority
} from './browser-runtime-authority.mjs'

const MAX_HINTS = 128
const MAX_HINTS_PER_SOURCE = MAX_HINTS / 4
const MAX_CONCURRENT_QUALIFICATIONS = 8
const MAX_HINT_BYTES = 2048
const HEX_32 = /^[0-9a-f]{64}$/i
const SOURCES = Object.freeze(['recommendation', 'user', 'peer', 'dht'])
const VERIFIED_RELAY_ADAPTERS = new WeakSet()
const VERIFIED_RELAY_ADAPTER_CONTEXTS = new WeakMap()
const VERIFIED_RELAY_CELL_GET_RESULTS = new WeakSet()
// One ownership record covers both asynchronous module setup and the live
// scheduler. Replacing/stopping an install invalidates all older continuations
// before they can publish to the same sync instance.
const ACTIVE_RELAY_INSTALLATIONS = new WeakMap()
// No public minter exists. A future signed-profile verifier must be integrated
// in this module before production activation can cross this authority seam.
const VERIFIED_RELEASE_AUTHORITIES = new WeakSet()

export const PEERIT_BLIND_CLIENT_PERSISTENCE_BLOCKERS = Object.freeze([
  'PORTABLE_CELL_CAPABILITY_RECOVERY_BUNDLE_UNASSEMBLED'
])

export const PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS = Object.freeze([
  ...PROFILE_RELEASE_BLOCKERS,
  'SIGNED_PEERIT_PROFILE_PIN_UNAVAILABLE',
  'AUTHENTICATED_PEERIT_RELAY_RUNTIME_AUTHORITY_UNAVAILABLE',
  'AUTHENTICATED_BLIND_CLIENT_BROWSER_ARTIFACT_UNAVAILABLE',
  'AUTHENTICATED_PROFILE_EXTERNAL_CODEC_DECODERS_UNASSEMBLED',
  'FIRST_VISIT_EXECUTING_VERIFIER_ORIGIN_BOOTSTRAP_UNRESOLVED',
  'PERMISSIONLESS_CANDIDATE_FEEDS_UNASSEMBLED',
  'PERMISSIONLESS_RELAY_CSP_UNASSEMBLED',
  ...PEERIT_BLIND_CLIENT_PERSISTENCE_BLOCKERS
].filter((value, index, all) => all.indexOf(value) === index))

export const PEERIT_BLIND_CLIENT_CONSUMER_STATUS = Object.freeze({
  releaseReady: false,
  activeQualification: false,
  requalificationScheduler: PEERIT_RELAY_REQUALIFICATION_STATUS,
  requalificationSchedulerReady: true,
  releaseBlockers: PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS
})

function localHttp (url) {
  return url.protocol === 'http:' &&
    (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]')
}

function normalizedUrl (value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_HINT_BYTES) return null
  try {
    const url = new URL(value)
    if (url.username || url.password || url.search || url.hash) return null
    if (url.protocol !== 'https:' && !localHttp(url)) return null
    return url.href
  } catch {
    return null
  }
}

function fixedHex (value) {
  if (typeof value === 'string') return HEX_32.test(value) ? value.toLowerCase() : null
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) return null
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

function bytes (value, field, exactLength = null) {
  let output
  if (value instanceof Uint8Array) {
    output = new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  } else if (value instanceof ArrayBuffer) {
    output = new Uint8Array(value)
  } else if (ArrayBuffer.isView(value)) {
    output = new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  } else if (typeof value === 'string' && HEX_32.test(value)) {
    output = new Uint8Array(32)
    for (let index = 0; index < 32; index++) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  } else {
    throw new TypeError(`${field} must be bytes${exactLength === 32 ? ' or 64 lowercase hex characters' : ''}`)
  }
  if (exactLength != null && output.byteLength !== exactLength) {
    throw new TypeError(`${field} must be exactly ${exactLength} bytes`)
  }
  return new Uint8Array(output)
}

function bytesEqual (left, right) {
  left = bytes(left, 'left bytes')
  right = bytes(right, 'right bytes')
  if (left.byteLength !== right.byteLength) return false
  let difference = 0
  for (let index = 0; index < left.byteLength; index++) difference |= left[index] ^ right[index]
  return difference === 0
}

function positiveInteger (value, field) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${field} must be a positive safe integer`)
  return value
}

function exactOperationRequirement (value, field) {
  if (!value || typeof value !== 'object') throw new TypeError(`${field} is required`)
  return Object.freeze({
    familyId: positiveInteger(value.familyId, `${field}.familyId`),
    operationId: positiveInteger(value.operationId, `${field}.operationId`),
    endpointId: positiveInteger(value.endpointId, `${field}.endpointId`),
    requiredRoleBits: positiveInteger(value.requiredRoleBits, `${field}.requiredRoleBits`),
    privacyProfileBit: positiveInteger(value.privacyProfileBit, `${field}.privacyProfileBit`),
    transportSupportBit: positiveInteger(value.transportSupportBit, `${field}.transportSupportBit`)
  })
}

function exactProfile (value) {
  if (!value || typeof value !== 'object') throw new TypeError('verified Peerit relay profile authority is required')
  if (!Array.isArray(value.supportedProtocolProfiles) || value.supportedProtocolProfiles.length < 1 ||
      !Array.isArray(value.supportedTransportProfiles) || value.supportedTransportProfiles.length < 1) {
    throw new TypeError('verified Peerit protocol and transport profile pins are required')
  }
  const requirement = exactOperationRequirement(value.requirement, 'requirement')
  const readRequirement = exactOperationRequirement(value.readRequirement, 'readRequirement')
  for (const field of [
    'familyId', 'endpointId', 'requiredRoleBits', 'privacyProfileBit', 'transportSupportBit'
  ]) {
    if (readRequirement[field] !== requirement[field]) {
      throw new TypeError(`readRequirement.${field} must match the Cell PUT endpoint requirement`)
    }
  }
  if (readRequirement.operationId === requirement.operationId) {
    throw new TypeError('readRequirement must select a distinct Cell GET operation')
  }
  const admissionProfile = value.admissionProfile
  if (!admissionProfile || typeof admissionProfile !== 'object') {
    throw new TypeError('Peerit signed admission profile pin is required')
  }
  return Object.freeze({
    supportedProtocolProfiles: value.supportedProtocolProfiles,
    supportedTransportProfiles: value.supportedTransportProfiles,
    requirement,
    readRequirement,
    describeFamilyId: positiveInteger(value.describeFamilyId, 'profile.describeFamilyId'),
    admissionParametersOperationId: positiveInteger(
      value.admissionParametersOperationId, 'profile.admissionParametersOperationId'),
    admissionProfile: Object.freeze({
      profileId: positiveInteger(admissionProfile.profileId, 'admissionProfile.profileId'),
      schemeId: positiveInteger(admissionProfile.schemeId, 'admissionProfile.schemeId'),
      conformanceClass: positiveInteger(
        admissionProfile.conformanceClass, 'admissionProfile.conformanceClass'),
      roleBits: positiveInteger(admissionProfile.roleBits, 'admissionProfile.roleBits'),
      parameterUrl: admissionProfile.parameterUrl == null
        ? null
        : bytes(admissionProfile.parameterUrl, 'admissionProfile.parameterUrl'),
      parameterHash: bytes(admissionProfile.parameterHash, 'admissionProfile.parameterHash', 32)
    })
  })
}

function assertControlContract (control) {
  const functions = [
    'BlindDescriptorBootstrapHttpClient',
    'BlindDirectHttpClient',
    'BlindRelayQualifier',
    'DescriptorTrustStore',
    'createAdmissionParametersRequest',
    'qualifyDescribeControlEndpoint',
    'trustedAdmissionProfile',
    'trustedDescriptorValidity',
    'verifiedEndpointContext',
    'verifiedAdmissionParametersValidity',
    'verifiedHealthValidity',
    'verifyAdmissionParametersBytes',
    'createGetCellRequest',
    'openVerifiedCellGetResult'
  ]
  if (!control || functions.some(name => typeof control[name] !== 'function')) {
    throw new TypeError('authenticated @hiverelay/blind-client/control browser namespace is required')
  }
  const maximumAgeMillis = control.HEALTH_QUALIFICATION_LIMITS &&
    control.HEALTH_QUALIFICATION_LIMITS.maximumAgeMillis
  if (!Number.isSafeInteger(maximumAgeMillis) || maximumAgeMillis < 1 || maximumAgeMillis > 60 * 60 * 1000) {
    throw new TypeError('blind-client health qualification lease limit is missing or invalid')
  }
  return control
}

function contextSnapshot (control, endpoint, requirement) {
  // This call is the package's unforgeable brand check. Never accept endpoint-
  // shaped input, a URL, or a relay adapter's own claims in its place.
  const value = control.verifiedEndpointContext(endpoint)
  const context = Object.freeze({
    descriptorHash: bytes(value.descriptorHash, 'endpoint descriptorHash', 32),
    descriptorSequence: BigInt(value.descriptorSequence),
    relayPublicKey: bytes(value.relayPublicKey, 'endpoint relayPublicKey', 32),
    storeId: bytes(value.storeId, 'endpoint storeId', 32),
    continuityRoot: bytes(value.continuityRoot, 'endpoint continuityRoot', 32),
    familyId: positiveInteger(value.familyId, 'endpoint familyId'),
    operationId: positiveInteger(value.operationId, 'endpoint operationId'),
    endpointId: positiveInteger(value.endpointId, 'endpoint endpointId'),
    transportId: positiveInteger(value.transportId, 'endpoint transportId'),
    transportSupportBit: positiveInteger(value.transportSupportBit, 'endpoint transportSupportBit'),
    privacyProfileBit: positiveInteger(value.privacyProfileBit, 'endpoint privacyProfileBit'),
    durabilityProfileId: positiveInteger(value.durabilityProfileId, 'endpoint durabilityProfileId'),
    durabilityContinuityHash: bytes(value.durabilityContinuityHash, 'endpoint durabilityContinuityHash', 32)
  })
  for (const field of ['familyId', 'operationId', 'endpointId', 'transportSupportBit', 'privacyProfileBit']) {
    if (context[field] !== requirement[field]) {
      const error = new Error(`verified endpoint changed the exact Peerit ${field} requirement`)
      error.code = 'PEERIT_VERIFIED_ENDPOINT_PROFILE_DRIFT'
      throw error
    }
  }
  return context
}

async function seedReadContextSnapshot (control, profile, candidate, context, readContext, backend) {
  let descriptorGenesisHash = null
  if (context.descriptorSequence === 0n) {
    descriptorGenesisHash = fixedHex(context.descriptorHash)
  } else if (backend && typeof backend.read === 'function' &&
      typeof control.verifyDescriptorBytes === 'function') {
    const key = `descriptor:${fixedHex(context.continuityRoot)}:${fixedHex(context.storeId)}`
    const record = await backend.read(key)
    const state = record && record.value
    if (!state || state.sequence !== context.descriptorSequence ||
        !bytesEqual(state.rootRelayPublicKey, context.continuityRoot) ||
        !bytesEqual(state.storeId, context.storeId) ||
        !bytesEqual(state.currentHash, context.descriptorHash) ||
        !Array.isArray(state.history) || state.history.length !== Number(context.descriptorSequence) + 1) {
      throw qualificationError('PEERIT_DESCRIPTOR_HISTORY_BINDING_UNAVAILABLE',
        'qualified endpoint cannot reproduce its exact persisted descriptor history')
    }
    const genesis = control.verifyDescriptorBytes(state.history[0], {
      history: true,
      supportedProtocolProfiles: profile.supportedProtocolProfiles,
      supportedTransportProfiles: profile.supportedTransportProfiles
    })
    descriptorGenesisHash = fixedHex(genesis.descriptorHash)
  }
  return Object.freeze({
    canonicalDescribeUrl: candidate.canonicalUrl,
    continuityRootRelayPublicKey: fixedHex(context.continuityRoot),
    storeId: fixedHex(context.storeId),
    descriptorGenesisHash,
    descriptorSequence: context.descriptorSequence,
    familyId: readContext.familyId,
    operationId: readContext.operationId,
    endpointId: readContext.endpointId,
    transportId: readContext.transportId,
    transportSupportBit: readContext.transportSupportBit,
    privacyProfileBit: readContext.privacyProfileBit
  })
}

function identityKey (context) {
  return `${fixedHex(context.continuityRoot)}:${fixedHex(context.storeId)}`
}

function assertPairedCellEndpointContexts (writeContext, readContext) {
  for (const field of [
    'descriptorHash', 'relayPublicKey', 'storeId', 'continuityRoot',
    'durabilityContinuityHash'
  ]) {
    if (!bytesEqual(writeContext[field], readContext[field])) {
      throw qualificationError('PEERIT_CELL_READ_ENDPOINT_IDENTITY_DRIFT',
        `qualified Cell GET endpoint changed ${field}`)
    }
  }
  for (const field of [
    'descriptorSequence', 'familyId', 'endpointId', 'transportId',
    'transportSupportBit', 'privacyProfileBit', 'durabilityProfileId'
  ]) {
    if (writeContext[field] !== readContext[field]) {
      throw qualificationError('PEERIT_CELL_READ_ENDPOINT_IDENTITY_DRIFT',
        `qualified Cell GET endpoint changed ${field}`)
    }
  }
  if (writeContext.operationId === readContext.operationId) {
    throw qualificationError('PEERIT_CELL_READ_ENDPOINT_OPERATION_INVALID',
      'qualified Cell GET endpoint reused the Cell PUT operation')
  }
}

function endpointKey (context) {
  return `${identityKey(context)}:${context.endpointId}`
}

function relayAdapterId (context) {
  return `blind-cell-v1:${endpointKey(context)}`
}

function qualificationLeaseError (code, message, definitelyNotProcessed) {
  const error = qualificationError(code, message)
  if (definitelyNotProcessed) {
    error.definitelyNotProcessed = true
    error.safeToRetry = true
  }
  return error
}

function validityEpoch (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw qualificationError('PEERIT_RELAY_VALIDITY_UNTRUSTED', `${field} is outside the protocol u32 epoch range`)
  }
  return value
}

function descriptorValiditySnapshot (control, trustedDescriptor) {
  const value = control.trustedDescriptorValidity(trustedDescriptor)
  if (!value || typeof value !== 'object') {
    throw qualificationError('PEERIT_DESCRIPTOR_VALIDITY_UNTRUSTED',
      'trusted descriptor validity was not returned by the blind-client brand')
  }
  const issuedEpoch = validityEpoch(value.issuedEpoch, 'descriptor issuedEpoch')
  const expiresEpoch = validityEpoch(value.expiresEpoch, 'descriptor expiresEpoch')
  if (expiresEpoch <= issuedEpoch) {
    throw qualificationError('PEERIT_DESCRIPTOR_VALIDITY_UNTRUSTED',
      'trusted descriptor has an empty signed epoch window')
  }
  return Object.freeze({ issuedEpoch, expiresEpoch })
}

function healthValiditySnapshot (control, health, maximumAgeMillis) {
  const value = control.verifiedHealthValidity(health)
  const verifiedAt = value && value.verifiedAtMonotonicMillis
  const expiresAt = value && value.expiresAtMonotonicMillis
  if (typeof verifiedAt !== 'number' || !Number.isFinite(verifiedAt) || verifiedAt < 0 ||
      typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) ||
      expiresAt !== verifiedAt + maximumAgeMillis) {
    throw qualificationError('PEERIT_HEALTH_VALIDITY_UNTRUSTED',
      'verified health did not expose the exact blind-client monotonic validity bound')
  }
  return Object.freeze({ verifiedAtMonotonicMillis: verifiedAt, expiresAtMonotonicMillis: expiresAt })
}

function admissionValiditySnapshot (control, verifiedAdmissionParameters) {
  const value = control.verifiedAdmissionParametersValidity(verifiedAdmissionParameters)
  if (!value || typeof value !== 'object') {
    throw qualificationError('PEERIT_ADMISSION_VALIDITY_UNTRUSTED',
      'verified admission validity was not returned by the blind-client brand')
  }
  const validFromEpoch = validityEpoch(value.validFromEpoch, 'admission validFromEpoch')
  const expiresEpoch = validityEpoch(value.expiresEpoch, 'admission expiresEpoch')
  if (expiresEpoch <= validFromEpoch) {
    throw qualificationError('PEERIT_ADMISSION_VALIDITY_UNTRUSTED',
      'verified admission parameters have an empty signed epoch window')
  }
  return Object.freeze({ validFromEpoch, expiresEpoch })
}

function brandedAdapter (adapter, context, seedReadContext, lease) {
  if (!adapter || typeof adapter !== 'object' || adapter.compatible === false ||
      (typeof adapter.deliver !== 'function' &&
       !(typeof adapter.prepare === 'function' && typeof adapter.send === 'function'))) {
    throw new TypeError('verified relay adapter must be compatible and implement deliver or prepare/send')
  }
  if (!lease || typeof lease.nowMonotonicMillis !== 'function' || typeof lease.nowEpoch !== 'function' ||
      typeof lease.healthVerifiedAtMonotonicMillis !== 'number' ||
      typeof lease.healthExpiresAtMonotonicMillis !== 'number' ||
      lease.healthExpiresAtMonotonicMillis <= lease.healthVerifiedAtMonotonicMillis ||
      !Number.isSafeInteger(lease.qualifiedEpoch) || !Number.isSafeInteger(lease.validFromEpoch) ||
      !Number.isSafeInteger(lease.expiresEpoch) || lease.qualifiedEpoch < lease.validFromEpoch ||
      lease.qualifiedEpoch >= lease.expiresEpoch) {
    throw new TypeError('verified relay adapter requires a bounded qualification lease')
  }
  const assertFresh = definitelyNotProcessed => {
    const currentMonotonicMillis = lease.nowMonotonicMillis()
    const currentEpoch = lease.nowEpoch()
    if (currentMonotonicMillis < lease.healthVerifiedAtMonotonicMillis ||
        currentEpoch < lease.qualifiedEpoch) {
      throw qualificationLeaseError('PEERIT_RELAY_QUALIFICATION_CLOCK_INVALID',
        'qualification clock moved backwards; relay must be requalified',
        definitelyNotProcessed)
    }
    if (currentMonotonicMillis >= lease.healthExpiresAtMonotonicMillis ||
        currentEpoch >= lease.expiresEpoch) {
      throw qualificationLeaseError('PEERIT_RELAY_QUALIFICATION_EXPIRED',
        'relay descriptor/health/admission qualification expired before network use',
        definitelyNotProcessed)
    }
  }
  const bind = name => typeof adapter[name] === 'function'
    ? async (...args) => {
      // A reconcile call represents an already-ambiguous earlier send. If its
      // qualification expires, it must remain pending-unknown; it is never a
      // definitely-not-processed retry signal.
      assertFresh(name !== 'reconcile' && name !== 'revalidateReadback')
      const value = await adapter[name](...args)
      // A GET that began under a valid health lease is historical evidence if
      // the lease expires while it is in flight. It must not become a current
      // availability claim until a newly qualified adapter checks again.
      if (value && value.readbackRevalidated === true) assertFresh(false)
      return value
    }
    : undefined
  const readCellCapability = typeof adapter.readCellCapability === 'function'
    ? async (request, operationContext = {}) => {
      assertFresh(false)
      const value = await adapter.readCellCapability(request, operationContext)
      if (!value || typeof value !== 'object' || value.innerBytes == null ||
          typeof value.evidenceRef !== 'string' || value.evidenceRef.length < 1 ||
          value.evidenceRef.length > 1024 || !request || typeof request !== 'object') {
        throw qualificationError('PEERIT_CELL_GET_RESULT_UNVERIFIED',
          'qualified Cell GET adapter returned an invalid authenticated result')
      }
      const result = Object.freeze({
        relayId: String(request.relayId),
        targetId: String(request.targetId),
        innerBytes: bytes(value.innerBytes, 'verified Cell GET innerBytes'),
        evidenceRef: value.evidenceRef
      })
      VERIFIED_RELAY_CELL_GET_RESULTS.add(result)
      assertFresh(false)
      return result
    }
    : undefined
  // Adapter construction may itself take long enough to cross a signed or
  // health boundary. Refuse to mint the Peerit brand once that happens.
  assertFresh(true)
  const result = Object.freeze({
    id: relayAdapterId(context),
    compatible: true,
    deliver: bind('deliver'),
    prepare: bind('prepare'),
    send: bind('send'),
    reconcile: bind('reconcile'),
    revalidateReadback: bind('revalidateReadback'),
    readCellCapability
  })
  VERIFIED_RELAY_ADAPTERS.add(result)
  VERIFIED_RELAY_ADAPTER_CONTEXTS.set(result, seedReadContext)
  return result
}

export function isPeeritVerifiedRelayAdapter (value) {
  return !!(value && typeof value === 'object' && VERIFIED_RELAY_ADAPTERS.has(value))
}

export function verifiedPeeritRelayCellGetContext (value) {
  const context = value && VERIFIED_RELAY_ADAPTER_CONTEXTS.get(value)
  if (!context) {
    throw qualificationError('PEERIT_VERIFIED_RELAY_ADAPTER_REQUIRED',
      'a currently qualified branded Peerit relay adapter is required')
  }
  return context
}

export function assertVerifiedPeeritRelayCellGetResult (value) {
  if (!value || !VERIFIED_RELAY_CELL_GET_RESULTS.has(value)) {
    throw qualificationError('PEERIT_CELL_GET_RESULT_UNVERIFIED',
      'a branded authenticated Cell GET result is required')
  }
  return value
}

function candidate (input, source) {
  const object = input && typeof input === 'object' && !(input instanceof Uint8Array)
    ? input
    : null
  const canonicalUrl = normalizedUrl(object ? (object.canonicalUrl || object.url) : input)
  if (!canonicalUrl) return null
  const expectedDescriptorHash = object == null || object.expectedDescriptorHash == null
    ? null
    : fixedHex(object.expectedDescriptorHash)
  if (object && object.expectedDescriptorHash != null && !expectedDescriptorHash) return null
  const continuityRootRelayPublicKey = object == null || object.continuityRootRelayPublicKey == null
    ? null
    : fixedHex(object.continuityRootRelayPublicKey)
  if (object && object.continuityRootRelayPublicKey != null && !continuityRootRelayPublicKey) return null
  return {
    canonicalUrl,
    expectedDescriptorHash,
    continuityRootRelayPublicKey,
    descriptorPinned: expectedDescriptorHash != null,
    sources: [source]
  }
}

// This collector grants no source membership authority. Source labels exist
// only for diagnostics and diversity accounting; identical observations merge.
export function collectPermissionlessRelayCandidates (input = {}) {
  const byKey = new Map()
  for (const source of SOURCES) {
    const values = Array.isArray(input[source]) ? input[source] : []
    // No one untrusted source, and especially no reservoir of inert raw URLs,
    // may crowd every other discovery path out of the bounded candidate set.
    const normalizedValues = values.slice(0, MAX_HINTS)
      .map(value => candidate(value, source))
      .filter(Boolean)
      .sort((left, right) => Number(right.descriptorPinned) - Number(left.descriptorPinned))
      .slice(0, MAX_HINTS_PER_SOURCE)
    for (const normalized of normalizedValues) {
      const key = `${normalized.canonicalUrl}\n${normalized.expectedDescriptorHash || ''}\n${normalized.continuityRootRelayPublicKey || ''}`
      const previous = byKey.get(key)
      if (previous) {
        if (!previous.sources.includes(source)) previous.sources.push(source)
      } else {
        byKey.set(key, normalized)
      }
    }
  }
  return Object.freeze([...byKey.values()].map(value => Object.freeze({
    ...value,
    sources: Object.freeze([...value.sources].sort())
  })))
}

function qualificationError (code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function safeQualificationErrorCode (error, fallback) {
  try {
    const descriptor = error && typeof error === 'object'
      ? Object.getOwnPropertyDescriptor(error, 'code')
      : null
    const value = descriptor && Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ? descriptor.value
      : null
    return typeof value === 'string' && value.length > 0 ? value.slice(0, 128) : fallback
  } catch {
    return fallback
  }
}

function qualificationSources (candidates) {
  return Object.freeze([...new Set(candidates.flatMap(candidate => candidate.sources))].sort())
}

function nowEpochProvider (value) {
  if (typeof value !== 'function') throw new TypeError('trusted epoch provider is required')
  return () => {
    const epoch = value()
    if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > 0xffffffff) {
      throw new TypeError('trusted epoch provider returned a value outside u32')
    }
    return epoch
  }
}

function monotonicMillisProvider (value) {
  const provider = typeof value === 'function'
    ? value
    : () => globalThis.performance && typeof globalThis.performance.now === 'function'
        ? globalThis.performance.now()
        : Date.now()
  return () => {
    const current = provider()
    if (typeof current !== 'number' || !Number.isFinite(current) || current < 0) {
      throw new TypeError('monotonic clock returned an invalid timestamp')
    }
    return current
  }
}

function descriptorIdentity (descriptor, candidateValue) {
  if (!descriptor) return null
  let root = null
  if (candidateValue.continuityRootRelayPublicKey) {
    root = bytes(candidateValue.continuityRootRelayPublicKey, 'candidate continuity root', 32)
  } else if (BigInt(descriptor.descriptorSequence) === 0n) {
    root = bytes(descriptor.relayPublicKey, 'genesis relay public key', 32)
  }
  if (!root) return null
  return `${fixedHex(root)}:${fixedHex(bytes(descriptor.storeId, 'descriptor storeId', 32))}`
}

function awaitAbortable (value, signal) {
  const promise = Promise.resolve(value)
  if (!signal || typeof signal.addEventListener !== 'function') return promise
  if (signal.aborted) {
    return Promise.reject(signal.reason ||
      qualificationError('PEERIT_RELAY_QUALIFICATION_ABORTED', 'relay qualification was aborted'))
  }
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (callback, result) => {
      if (settled) return
      settled = true
      signal.removeEventListener('abort', onAbort)
      callback(result)
    }
    const onAbort = () => finish(reject, signal.reason ||
      qualificationError('PEERIT_RELAY_QUALIFICATION_ABORTED', 'relay qualification was aborted'))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(value => finish(resolve, value), error => finish(reject, error))
  })
}

async function admissionProviderFor (options, qualification, signal) {
  let provider = options.admissionProvider
  if (typeof options.createAdmissionProvider === 'function') {
    provider = await awaitAbortable(options.createAdmissionProvider(Object.freeze({
      candidate: qualification.candidate,
      endpointContext: qualification.context,
      verifiedAdmissionParameters: qualification.verifiedAdmissionParameters,
      admissionProfile: qualification.profile.admissionProfile,
      signal
    })), signal)
  }
  if (typeof provider !== 'function') {
    throw qualificationError('PEERIT_ADMISSION_PROVIDER_REQUIRED',
      'a Peerit admission token provider is required before a relay can be installed')
  }
  return async context => {
    const value = await provider(context, Object.freeze({
      endpointContext: qualification.context,
      verifiedAdmissionParameters: qualification.verifiedAdmissionParameters,
      admissionProfile: qualification.profile.admissionProfile
    }))
    if (!value || typeof value !== 'object' ||
        value.profileId !== qualification.profile.admissionProfile.profileId ||
        value.schemeId !== qualification.profile.admissionProfile.schemeId ||
        !bytesEqual(value.parameterHash, qualification.profile.admissionProfile.parameterHash)) {
      throw qualificationError('PEERIT_ADMISSION_TOKEN_PROFILE_DRIFT',
        'admission provider returned a token for a different signed parameter profile')
    }
    return Object.freeze({
      profileId: value.profileId,
      schemeId: value.schemeId,
      parameterHash: bytes(value.parameterHash, 'admission token parameterHash', 32),
      token: bytes(value.token, 'admission token')
    })
  }
}

function advertisedAdmissionProfile (control, trustedDescriptor, pinned) {
  const advertised = control.trustedAdmissionProfile(trustedDescriptor, pinned.profileId)
  const sameParameterUrl = advertised != null &&
    ((advertised.parameterUrl == null && pinned.parameterUrl == null) ||
      (advertised.parameterUrl != null && pinned.parameterUrl != null &&
       bytesEqual(advertised.parameterUrl, pinned.parameterUrl)))
  if (!advertised || advertised.schemeId !== pinned.schemeId ||
      advertised.conformanceClass !== pinned.conformanceClass ||
      advertised.roleBits !== pinned.roleBits || !sameParameterUrl ||
      !bytesEqual(advertised.parameterHash, pinned.parameterHash)) {
    throw qualificationError('PEERIT_DESCRIPTOR_ADMISSION_PROFILE_DRIFT',
      'signed relay descriptor does not advertise the exact authenticated Peerit admission profile')
  }
  return advertised
}

async function verifyAdmissionForCandidate (options) {
  const {
    control,
    directClient,
    runtime,
    profile,
    qualified,
    nowEpoch,
    signal,
    timeoutMillis
  } = options
  const advertisedProfile = advertisedAdmissionProfile(
    control, qualified.trustedDescriptor, profile.admissionProfile)
  const request = control.createAdmissionParametersRequest({
    runtime,
    profileId: profile.admissionProfile.profileId,
    schemeId: profile.admissionProfile.schemeId
  })
  const controlEndpoint = control.qualifyDescribeControlEndpoint({
    trustedDescriptor: qualified.trustedDescriptor,
    nowEpoch: nowEpoch(),
    familyId: profile.describeFamilyId,
    operationId: profile.admissionParametersOperationId,
    endpointId: profile.requirement.endpointId,
    requiredRoleBits: profile.requirement.requiredRoleBits,
    privacyProfileBit: profile.requirement.privacyProfileBit,
    transportSupportBit: profile.requirement.transportSupportBit
  })
  const response = await awaitAbortable(directClient.request({
    endpoint: controlEndpoint,
    ...request.wire,
    body: request.requestBytes,
    signal,
    timeoutMillis
  }), signal)
  if (!response || response.ok !== true) {
    throw qualificationError('PEERIT_ADMISSION_PARAMETERS_UNAVAILABLE',
      'relay did not return its signed admission parameters')
  }
  const verified = control.verifyAdmissionParametersBytes(
    response.body,
    qualified.trustedDescriptor,
    advertisedProfile,
    { nowEpoch: nowEpoch() }
  )
  if (!verified || !bytesEqual(verified.parameterHash, profile.admissionProfile.parameterHash)) {
    throw qualificationError('PEERIT_ADMISSION_PARAMETERS_UNTRUSTED',
      'relay admission parameters do not match the authenticated Peerit profile pin')
  }
  return verified
}

// Active, non-installing qualification seam. It deliberately requires its
// authenticated control namespace, exact Peerit profile pins, continuity store,
// capability persistence callbacks, and adapter factory as explicit inputs.
// The production installer below is the only code that may feed its result to
// sync.setRelays, and does so only after the compile-time release assertion.
export async function qualifyPermissionlessRelayCandidates (options = {}) {
  const control = assertControlContract(options.control)
  const profile = exactProfile(options.profile)
  const runtime = options.cryptoRuntime
  if (!runtime || typeof runtime.randomBytes !== 'function') {
    throw new TypeError('authenticated blind-client crypto runtime is required')
  }
  const nowEpoch = nowEpochProvider(options.nowEpoch)
  const monotonicMillis = monotonicMillisProvider(options.monotonicMillis)
  const qualificationLeaseMillis = control.HEALTH_QUALIFICATION_LIMITS.maximumAgeMillis
  if (typeof options.createRelayAdapter !== 'function') {
    throw new TypeError('authenticated Peerit blind relay adapter factory is required')
  }
  if (typeof options.persistPreparedReplica !== 'function' ||
      typeof options.persistVerifiedResult !== 'function' ||
      typeof options.persistVerifiedReadback !== 'function' ||
      typeof options.loadPersistedReplica !== 'function') {
    throw qualificationError('PEERIT_ENCRYPTED_CAPABILITY_VAULT_REQUIRED',
      'encrypted prepared/result/readback persistence and crash recovery loading are required')
  }

  let trustStore = options.trustStore
  if (!trustStore && options.descriptorTrustBackend) {
    trustStore = new control.DescriptorTrustStore(options.descriptorTrustBackend)
  }
  if (!trustStore || typeof trustStore.accept !== 'function') {
    throw qualificationError('PEERIT_ENCRYPTED_CONTINUITY_VAULT_REQUIRED',
      'a persistent encrypted descriptor continuity trust store is required')
  }

  const candidates = Array.isArray(options.candidates)
    ? options.candidates.slice(0, MAX_HINTS)
    : []
  const totalQualificationTimeoutMillis = Number.isSafeInteger(options.totalQualificationTimeoutMillis)
    ? Math.max(1000, Math.min(120000, options.totalQualificationTimeoutMillis))
    : 30000
  const bootstrapClient = options.bootstrapClient || new control.BlindDescriptorBootstrapHttpClient({
    runtime,
    fetch: options.fetch,
    allowInsecureLoopback: options.allowInsecureLoopback === true
  })
  const directClient = options.directClient || new control.BlindDirectHttpClient({
    runtime,
    fetch: options.fetch,
    allowInsecureLoopback: options.allowInsecureLoopback === true
  })
  if (!bootstrapClient || typeof bootstrapClient.fetchVerifiedDescriptor !== 'function' ||
      !directClient || typeof directClient.request !== 'function') {
    throw new TypeError('blind-client descriptor bootstrap and direct control clients are required')
  }
  if (typeof AbortController !== 'function') {
    throw new TypeError('AbortController is required for a bounded relay qualification deadline')
  }
  const qualificationAbort = new AbortController()
  let qualificationTimedOut = false
  const forwardAbort = () => qualificationAbort.abort(options.signal && options.signal.reason)
  if (options.signal && options.signal.aborted) forwardAbort()
  else if (options.signal && typeof options.signal.addEventListener === 'function') {
    options.signal.addEventListener('abort', forwardAbort, { once: true })
  }
  const qualificationTimer = setTimeout(() => {
    qualificationTimedOut = true
    qualificationAbort.abort(qualificationError('PEERIT_RELAY_QUALIFICATION_DEADLINE',
      'bounded permissionless relay qualification deadline expired'))
  }, totalQualificationTimeoutMillis)
  const qualificationSignal = qualificationAbort.signal

  const selected = new Map()
  const quarantinedIdentities = new Set()
  const failures = []
  let deduplicatedCandidateCount = 0
  const pinnedCandidates = candidates.filter(candidateValue =>
    candidateValue && candidateValue.descriptorPinned === true && candidateValue.expectedDescriptorHash)
  let pinnedAttemptCount = 0

  const qualifyOne = async candidateValue => {
    pinnedAttemptCount++
    let observedDescriptor = null
    try {
      const capturingBootstrap = Object.freeze({
        async fetchVerifiedDescriptor (request) {
          observedDescriptor = await bootstrapClient.fetchVerifiedDescriptor(request)
          return observedDescriptor
        }
      })
      const qualifier = new control.BlindRelayQualifier({
        runtime,
        nowEpoch,
        monotonicMillis,
        supportedProtocolProfiles: profile.supportedProtocolProfiles,
        supportedTransportProfiles: profile.supportedTransportProfiles,
        trustStore,
        bootstrapClient: capturingBootstrap,
        directClient
      })
      const expectedDescriptorHash = bytes(
        candidateValue.expectedDescriptorHash, 'candidate expectedDescriptorHash', 32)
      const candidate = {
        canonicalUrl: new TextEncoder().encode(candidateValue.canonicalUrl),
        expectedDescriptorHash,
        continuityRootRelayPublicKey: candidateValue.continuityRootRelayPublicKey == null
          ? null
          : bytes(candidateValue.continuityRootRelayPublicKey, 'candidate continuityRootRelayPublicKey', 32)
      }
      const qualified = await awaitAbortable(qualifier.qualifyCandidate(candidate, profile.requirement, {
        signal: qualificationSignal,
        timeoutMillis: options.timeoutMillis
      }), qualificationSignal)
      const context = contextSnapshot(control, qualified.endpoint, profile.requirement)
      const readQualified = await awaitAbortable(qualifier.qualifyCandidate(candidate, profile.readRequirement, {
        signal: qualificationSignal,
        timeoutMillis: options.timeoutMillis
      }), qualificationSignal)
      const readContext = contextSnapshot(control, readQualified.endpoint, profile.readRequirement)
      assertPairedCellEndpointContexts(context, readContext)
      const seedReadContext = await seedReadContextSnapshot(
        control, profile, candidateValue, context, readContext, options.descriptorTrustBackend)
      const descriptorValidity = descriptorValiditySnapshot(control, qualified.trustedDescriptor)
      const healthValidity = healthValiditySnapshot(
        control, qualified.health, qualificationLeaseMillis)
      const readHealthValidity = healthValiditySnapshot(
        control, readQualified.health, qualificationLeaseMillis)
      if (context.durabilityProfileId === 2 && typeof options.externalWitnessVerifier !== 'function') {
        throw qualificationError('PEERIT_EXTERNAL_WITNESS_VERIFIER_REQUIRED',
          'durability profile 2 requires an authenticated external commit-witness verifier')
      }
      if (!bytesEqual(context.descriptorHash, expectedDescriptorHash)) {
        throw qualificationError('PEERIT_DESCRIPTOR_PIN_DRIFT',
          'verified endpoint descriptor hash does not match the fetched immutable pin')
      }
      if (candidateValue.continuityRootRelayPublicKey &&
          !bytesEqual(context.continuityRoot,
            bytes(candidateValue.continuityRootRelayPublicKey, 'candidate continuity root', 32))) {
        throw qualificationError('PEERIT_CONTINUITY_PIN_DRIFT',
          'verified endpoint continuity root does not match the candidate pin')
      }
      const identity = identityKey(context)
      if (quarantinedIdentities.has(identity)) {
        throw qualificationError('PEERIT_RELAY_CONTINUITY_QUARANTINED',
          'relay continuity/store identity was quarantined after a descriptor fork')
      }
      const verifiedAdmissionParameters = await verifyAdmissionForCandidate({
        control,
        directClient,
        runtime,
        profile,
        qualified,
        nowEpoch,
        signal: qualificationSignal,
        timeoutMillis: options.timeoutMillis
      })
      const admissionValidity = admissionValiditySnapshot(control, verifiedAdmissionParameters)
      const signedValidFromEpoch = Math.max(
        descriptorValidity.issuedEpoch, admissionValidity.validFromEpoch)
      const signedExpiresEpoch = Math.min(
        descriptorValidity.expiresEpoch, admissionValidity.expiresEpoch)
      const qualifiedEpoch = nowEpoch()
      if (qualifiedEpoch < signedValidFromEpoch) {
        throw qualificationLeaseError('PEERIT_RELAY_QUALIFICATION_CLOCK_INVALID',
          'trusted epoch moved before the signed descriptor/admission validity window', true)
      }
      if (qualifiedEpoch >= signedExpiresEpoch) {
        throw qualificationLeaseError('PEERIT_RELAY_QUALIFICATION_EXPIRED',
          'signed descriptor/admission validity expired during qualification', true)
      }
      if (quarantinedIdentities.has(identity)) {
        throw qualificationError('PEERIT_RELAY_CONTINUITY_QUARANTINED',
          'relay continuity/store identity was quarantined while admission was verified')
      }
      const key = endpointKey(context)
      const previous = selected.get(key)
      if (previous && previous.context.descriptorSequence >= context.descriptorSequence) {
        deduplicatedCandidateCount++
        return
      }
      const provider = await admissionProviderFor(options, {
        candidate: candidateValue,
        context,
        verifiedAdmissionParameters,
        profile
      }, qualificationSignal)
      const adapter = await awaitAbortable(options.createRelayAdapter(Object.freeze({
        blindClient: options.blindClient || control,
        control,
        endpoint: qualified.endpoint,
        endpointContext: context,
        readEndpoint: readQualified.endpoint,
        readEndpointContext: readContext,
        relayPublicKey: context.relayPublicKey,
        runtime,
        fetch: options.fetch,
        allowInsecureLoopback: options.allowInsecureLoopback === true,
        admissionProvider: provider,
        persistPreparedReplica: options.persistPreparedReplica,
        persistVerifiedResult: options.persistVerifiedResult,
        persistVerifiedReadback: options.persistVerifiedReadback,
        loadPersistedReplica: options.loadPersistedReplica,
        externalWitnessVerifier: options.externalWitnessVerifier,
        timeoutMillis: options.timeoutMillis,
        signal: qualificationSignal
      })), qualificationSignal)
      if (quarantinedIdentities.has(identity)) {
        throw qualificationError('PEERIT_RELAY_CONTINUITY_QUARANTINED',
          'relay continuity/store identity was quarantined before adapter installation')
      }
      const current = selected.get(key)
      if (current && current.context.descriptorSequence >= context.descriptorSequence) {
        deduplicatedCandidateCount++
        return
      }
      if (current) deduplicatedCandidateCount++
      const lease = Object.freeze({
        nowMonotonicMillis: monotonicMillis,
        nowEpoch,
        healthVerifiedAtMonotonicMillis: Math.max(
          healthValidity.verifiedAtMonotonicMillis,
          readHealthValidity.verifiedAtMonotonicMillis),
        healthExpiresAtMonotonicMillis: Math.min(
          healthValidity.expiresAtMonotonicMillis,
          readHealthValidity.expiresAtMonotonicMillis),
        qualifiedEpoch,
        validFromEpoch: signedValidFromEpoch,
        expiresEpoch: signedExpiresEpoch
      })
      selected.set(key, Object.freeze({
        adapter: brandedAdapter(adapter, context, seedReadContext, lease),
        context,
        identity,
        key,
        lease
      }))
    } catch (error) {
      const code = safeQualificationErrorCode(error, 'PEERIT_RELAY_QUALIFICATION_FAILED')
      if (code === 'DESCRIPTOR_FORK') {
        const identity = descriptorIdentity(observedDescriptor, candidateValue)
        if (identity) {
          quarantinedIdentities.add(identity)
          for (const [key, entry] of selected) {
            if (entry.identity === identity) selected.delete(key)
          }
        }
      }
      failures.push(Object.freeze({
        code,
        sources: Object.freeze([...(candidateValue.sources || [])].slice(0, SOURCES.length).map(String).sort())
      }))
    }
  }

  let nextCandidate = 0
  const requestedConcurrency = Number.isSafeInteger(options.maxConcurrentQualifications)
    ? options.maxConcurrentQualifications
    : MAX_CONCURRENT_QUALIFICATIONS
  const workerCount = Math.min(
    pinnedCandidates.length,
    Math.max(1, Math.min(MAX_CONCURRENT_QUALIFICATIONS, requestedConcurrency))
  )
  await Promise.all(Array.from({ length: workerCount }, async () => {
    while (!qualificationSignal.aborted && nextCandidate < pinnedCandidates.length) {
      const index = nextCandidate++
      await qualifyOne(pinnedCandidates[index])
    }
  })).finally(() => {
    clearTimeout(qualificationTimer)
    if (options.signal && typeof options.signal.removeEventListener === 'function') {
      options.signal.removeEventListener('abort', forwardAbort)
    }
  })

  // Trust and fork state remain scoped to continuity+store, while installed
  // relay independence is scoped to the operator continuity root. One operator
  // cannot fill Peerit's target budget by minting extra stores or endpoints.
  const continuitySelected = new Map()
  for (const entry of selected.values()) {
    const root = fixedHex(entry.context.continuityRoot)
    const previous = continuitySelected.get(root)
    if (!previous || entry.context.descriptorSequence > previous.context.descriptorSequence ||
        (entry.context.descriptorSequence === previous.context.descriptorSequence && entry.key < previous.key)) {
      continuitySelected.set(root, entry)
    }
  }
  const selectedEntries = [...continuitySelected.values()]
    .sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0)
  const adapters = Object.freeze(selectedEntries.map(entry => entry.adapter))
  const leaseExpiresAtMonotonicMillis = selectedEntries.length > 0
    ? Math.min(...selectedEntries.map(entry => entry.lease.healthExpiresAtMonotonicMillis))
    : null
  const leaseExpiresEpoch = selectedEntries.length > 0
    ? Math.min(...selectedEntries.map(entry => entry.lease.expiresEpoch))
    : null
  const continuityDiversityDeduplicatedCount = selected.size - adapters.length
  const status = Object.freeze({
    state: adapters.length > 0 ? 'qualified' : 'no-qualified-relay',
    active: true,
    candidateHintCount: candidates.length,
    descriptorPinnedCandidateCount: candidates.filter(value => value && value.descriptorPinned === true).length,
    rawUrlHintCount: candidates.filter(value => !value || value.descriptorPinned !== true).length,
    candidateSources: qualificationSources(candidates.filter(Boolean)),
    pinnedAttemptCount,
    qualificationDeadlineMillis: totalQualificationTimeoutMillis,
    qualificationTimedOut,
    qualificationFailureCount: failures.length,
    deduplicatedCandidateCount,
    continuityDiversityDeduplicatedCount,
    quarantinedIdentityCount: quarantinedIdentities.size,
    qualifiedRelayCount: adapters.length,
    releaseBlockers: Object.freeze([]),
    rawUrlAuthorizesOrdinaryOperations: false,
    descriptorPinRequired: true,
    descriptorSignatureRequired: true,
    admissionParametersVerified: adapters.length > 0,
    qualificationLeaseMillis,
    leaseExpiresAtMonotonicMillis,
    leaseExpiresEpoch,
    requalificationSchedulerReady: true,
    signedQualificationEpochWindowRequired: true,
    endpointBoundHealthRequired: true,
    sharedContinuityTrustStoreRequired: true,
    sameContinuityDeduplicationRequired: true,
    descriptorForkQuarantineRequired: true,
    oneRelayEnablesDelivery: true,
    zeroRelayBehavior: 'queued-local-first'
  })
  return Object.freeze({ adapters, failures: Object.freeze(failures), status })
}

function blockedStatus (candidates) {
  const sources = [...new Set(candidates.flatMap(candidate => candidate.sources))].sort()
  return Object.freeze({
    state: 'blocked-build-authority',
    active: false,
    candidateHintCount: candidates.length,
    descriptorPinnedCandidateCount: candidates.filter(candidate => candidate.descriptorPinned).length,
    rawUrlHintCount: candidates.filter(candidate => !candidate.descriptorPinned).length,
    candidateSources: Object.freeze(sources),
    qualifiedRelayCount: 0,
    releaseBlockers: PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS,
    rawUrlAuthorizesOrdinaryOperations: false,
    descriptorPinRequired: true,
    descriptorSignatureRequired: true,
    admissionParametersVerified: false,
    requalificationSchedulerReady: true,
    signedQualificationEpochWindowRequired: true,
    endpointBoundHealthRequired: true,
    sharedContinuityTrustStoreRequired: true,
    sameContinuityDeduplicationRequired: true,
    descriptorForkQuarantineRequired: true,
    oneRelayEnablesDelivery: true,
    zeroRelayBehavior: 'queued-local-first'
  })
}

function runtimeBlockedStatus (candidates, error) {
  const base = blockedStatus(candidates)
  const code = safeQualificationErrorCode(error, 'PEERIT_AUTHENTICATED_RELAY_RUNTIME_REQUIRED')
  return Object.freeze({
    ...base,
    state: 'blocked-runtime-authority',
    releaseBlockers: Object.freeze([...new Set([...base.releaseBlockers, code])])
  })
}

function publishRelayStatus (sync, relays, status) {
  // This is the sole relay-target mutation seam. A caller cannot install a raw
  // URL, endpoint-shaped object, or self-declared adapter through this module.
  const verified = relays.filter(isPeeritVerifiedRelayAdapter)
  sync.setRelays(verified)
  if (typeof sync.setRelayQualificationStatus === 'function') {
    sync.setRelayQualificationStatus(status)
  }
}

export function stopPeeritBlindRelayConsumer (sync) {
  const installation = sync && ACTIVE_RELAY_INSTALLATIONS.get(sync)
  if (!installation) return false
  ACTIVE_RELAY_INSTALLATIONS.delete(sync)
  if (installation.externalSignal && installation.forwardAbort &&
      typeof installation.externalSignal.removeEventListener === 'function') {
    installation.externalSignal.removeEventListener('abort', installation.forwardAbort)
  }
  if (!installation.controller.signal.aborted) {
    installation.controller.abort(qualificationError('PEERIT_RELAY_INSTALL_STOPPED',
      'Peerit relay installation was stopped'))
  }
  if (installation.scheduler) installation.scheduler.stop()
  return true
}

function beginRelayInstallation (sync, externalSignal) {
  stopPeeritBlindRelayConsumer(sync)
  const controller = new AbortController()
  const installation = {
    controller,
    scheduler: null,
    externalSignal: externalSignal || null,
    forwardAbort: null
  }
  installation.forwardAbort = () => {
    if (ACTIVE_RELAY_INSTALLATIONS.get(sync) === installation) {
      stopPeeritBlindRelayConsumer(sync)
    }
  }
  ACTIVE_RELAY_INSTALLATIONS.set(sync, installation)
  if (externalSignal && externalSignal.aborted) installation.forwardAbort()
  else if (externalSignal && typeof externalSignal.addEventListener === 'function') {
    externalSignal.addEventListener('abort', installation.forwardAbort, { once: true })
  }
  return installation
}

function ownsRelayInstallation (sync, installation) {
  return ACTIVE_RELAY_INSTALLATIONS.get(sync) === installation
}

function assertRelayInstallationCurrent (sync, installation) {
  if (!ownsRelayInstallation(sync, installation) || installation.controller.signal.aborted) {
    throw qualificationError('PEERIT_RELAY_INSTALL_SUPERSEDED',
      'an older relay installation continuation was discarded')
  }
}

function attachRelayScheduler (sync, installation, scheduler) {
  assertRelayInstallationCurrent(sync, installation)
  installation.scheduler = scheduler
}

function releaseInactiveRelayInstallation (sync, installation) {
  if (!ownsRelayInstallation(sync, installation)) return
  ACTIVE_RELAY_INSTALLATIONS.delete(sync)
  if (installation.externalSignal && installation.forwardAbort &&
      typeof installation.externalSignal.removeEventListener === 'function') {
    installation.externalSignal.removeEventListener('abort', installation.forwardAbort)
  }
}

function supersededInstallationStatus () {
  return Object.freeze({
    state: 'relay-installation-superseded',
    active: false,
    qualifiedRelayCount: 0,
    releaseBlockers: Object.freeze([])
  })
}

// Current production behavior is intentionally bounded and non-networking while
// the release assertion is incomplete. Once it is complete, the same installer
// can activate only from authenticated release-provided modules and exact profile
// data; passing fetch/load functions or a raw URL cannot bypass the assertion or
// the blind-client endpoint brand.
export async function installPeeritBlindRelayConsumer (options = {}) {
  const sync = options.sync
  const runtime = options.runtime
  if (!runtime || runtime.mode !== 'web-substrate') {
    return Object.freeze({ state: 'not-applicable', active: false, qualifiedRelayCount: 0 })
  }
  if (!sync || typeof sync.setRelays !== 'function') {
    throw new TypeError('Peerit blind relay consumer requires sync.setRelays')
  }
  const supplied = options.candidates || {}
  const recommendations = Array.isArray(runtime.relayHints) ? runtime.relayHints : []
  const candidates = collectPermissionlessRelayCandidates({
    recommendation: [...recommendations, ...(Array.isArray(supplied.recommendation) ? supplied.recommendation : [])],
    user: supplied.user || [],
    peer: supplied.peer || [],
    dht: supplied.dht || []
  })

  // Defence in depth at the last production mutation seam. The runtime selector
  // already consulted this assertion, but no caller may install a relay by
  // constructing a sync object directly while the profile is incomplete.
  try {
    assertPeeritProfileReleaseReady()
  } catch (error) {
    if (!error || error.code !== 'PEERIT_PROFILE_INCOMPLETE') throw error
    stopPeeritBlindRelayConsumer(sync)
    const status = blockedStatus(candidates)
    publishRelayStatus(sync, [], status)
    return status
  }

  if (isVerifiedPeeritBrowserRuntimeAuthority(options.releaseAuthority)) {
    // Preserve the installer-local brand as a second authority boundary. Only
    // the assembly module can make its first brand; raw module namespaces,
    // hashes, or caller-shaped authority objects never enter this WeakSet.
    VERIFIED_RELEASE_AUTHORITIES.add(options.releaseAuthority)
  }
  if (!options.releaseAuthority || !VERIFIED_RELEASE_AUTHORITIES.has(options.releaseAuthority)) {
    stopPeeritBlindRelayConsumer(sync)
    const error = qualificationError('PEERIT_AUTHENTICATED_RELAY_RUNTIME_AUTHORITY_REQUIRED',
      'a module-branded signed-profile/runtime authority is required before relay qualification can activate')
    const status = runtimeBlockedStatus(candidates, error)
    publishRelayStatus(sync, [], status)
    return status
  }
  if (typeof AbortController !== 'function') {
    const error = qualificationError('PEERIT_RELAY_INSTALL_ABORT_UNAVAILABLE',
      'AbortController is required for relay installation ownership')
    const status = runtimeBlockedStatus(candidates, error)
    publishRelayStatus(sync, [], status)
    return status
  }
  if (options.signal != null &&
      (typeof options.signal !== 'object' || typeof options.signal.addEventListener !== 'function' ||
       typeof options.signal.removeEventListener !== 'function' || typeof options.signal.aborted !== 'boolean')) {
    throw new TypeError('relay installation signal must be an AbortSignal')
  }

  // Revoke any previous target before asynchronous requalification. This never
  // touches the local journal: zero compatible relays means signed intents stay
  // queued for a later authenticated candidate.
  const installation = beginRelayInstallation(sync, options.signal)
  try {
    const runtimeAssembly = getVerifiedPeeritBrowserRuntimeAssembly(options.releaseAuthority)
    assertRelayInstallationCurrent(sync, installation)
    publishRelayStatus(sync, [], blockedStatus(candidates))
    assertRelayInstallationCurrent(sync, installation)
    const control = runtimeAssembly.control
    assertRelayInstallationCurrent(sync, installation)
    const createRelayAdapter = runtimeAssembly.createRelayAdapter
    const capabilityVault = createPeeritCapabilityVault({
      crypto: options.capabilityCrypto,
      indexedDB: options.indexedDB
    })
    if (!capabilityVault || typeof capabilityVault.persistPreparedReplica !== 'function' ||
        typeof capabilityVault.persistVerifiedResult !== 'function' ||
        typeof capabilityVault.persistVerifiedReadback !== 'function') {
      throw qualificationError('PEERIT_ENCRYPTED_CAPABILITY_VAULT_REQUIRED',
        'encrypted Cell capability persistence is unavailable')
    }
    const descriptorTrustBackend = createPeeritDescriptorTrustBackend({
      crypto: options.continuityCrypto,
      indexedDB: options.indexedDB
    })
    if (typeof options.releaseAuthority.epochDeadlineMonotonicMillis !== 'function') {
      throw qualificationError('PEERIT_AUTHENTICATED_EPOCH_CLOCK_REQUIRED',
        'signed runtime authority must supply exact lease-epoch monotonic deadlines')
    }
    assertRelayInstallationCurrent(sync, installation)
    const scheduler = createPeeritRelayRequalificationScheduler({
      qualify: ({ signal }) => qualifyPermissionlessRelayCandidates({
        ...options,
        signal,
        control,
        createRelayAdapter,
        trustStore: undefined,
        descriptorTrustBackend,
        persistPreparedReplica: capabilityVault.persistPreparedReplica,
        persistVerifiedResult: capabilityVault.persistVerifiedResult,
        persistVerifiedReadback: capabilityVault.persistVerifiedReadback,
        loadPersistedReplica: capabilityVault.load,
        candidates
      }),
      publish: (adapters, status) => publishRelayStatus(sync, adapters, status),
      verifyAdapter: isPeeritVerifiedRelayAdapter,
      epochDeadlineMonotonicMillis: epoch =>
        options.releaseAuthority.epochDeadlineMonotonicMillis(epoch),
      monotonicMillis: options.monotonicMillis,
      refreshLeadMillis: options.requalificationRefreshLeadMillis,
      maximumRefreshIntervalMillis: options.maximumRequalificationIntervalMillis,
      minimumRetryMillis: options.requalificationMinimumRetryMillis,
      maximumRetryMillis: options.requalificationMaximumRetryMillis
    })
    attachRelayScheduler(sync, installation, scheduler)
    const status = await scheduler.start()
    if (!ownsRelayInstallation(sync, installation)) return supersededInstallationStatus()
    if (!scheduler.running) releaseInactiveRelayInstallation(sync, installation)
    return status
  } catch (error) {
    if (!ownsRelayInstallation(sync, installation)) return supersededInstallationStatus()
    stopPeeritBlindRelayConsumer(sync)
    const status = runtimeBlockedStatus(candidates, error)
    publishRelayStatus(sync, [], status)
    return status
  }
}
