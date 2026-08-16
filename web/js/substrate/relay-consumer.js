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
  getVerifiedPeeritBrowserSeedBootstrapV1,
  getVerifiedPeeritBrowserRuntimeAssembly,
  isVerifiedPeeritBrowserRuntimeAuthority
} from './browser-runtime-authority.mjs'
import { verifyPeeritSeedBootstrapV1 } from './seed-bootstrap-v1.mjs'

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
    descriptorHeadHash: fixedHex(context.descriptorHash),
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
        !bytesEqual(value.parameterHash, qualification.verifiedAdmissionParameters.parameterHash)) {
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
      advertised.roleBits !== pinned.roleBits || !sameParameterUrl) {
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
  // The expected admission parameterHash is descriptor-driven: it comes from
  // the CURRENT signature-verified descriptor's advertised binding (which
  // verifyAdmissionParametersBytes has already equated to the served
  // parameters' own hash), never from a release-pinned file that rotation
  // would stale.
  if (!verified || !bytesEqual(verified.parameterHash, advertisedProfile.parameterHash)) {
    throw qualificationError('PEERIT_ADMISSION_PARAMETERS_UNTRUSTED',
      'relay admission parameters do not match the current descriptor admission binding')
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

function publishInstallationRelayStatus (sync, installation, relays, status) {
  assertRelayInstallationCurrent(sync, installation)
  const verified = Object.freeze(relays.filter(isPeeritVerifiedRelayAdapter))
  const changed = verified.length !== installation.adapters.length ||
    verified.some((adapter, index) => adapter !== installation.adapters[index])
  if (changed) {
    installation.adapterGeneration++
    if (installation.recoveryController && !installation.recoveryController.signal.aborted) {
      installation.recoveryController.abort(qualificationError(
        'PEERIT_SEED_RECOVERY_RELAY_SET_CHANGED',
        'qualified relay set changed during seed recovery'))
    }
    installation.recoveryController = null
    installation.adapters = verified
  }
  publishRelayStatus(sync, verified, status)
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
  if (installation.recoveryController && !installation.recoveryController.signal.aborted) {
    installation.recoveryController.abort(qualificationError(
      'PEERIT_SEED_RECOVERY_ABORTED', 'Peerit seed recovery stopped with relay installation'))
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
    adapters: Object.freeze([]),
    adapterGeneration: 0,
    capabilityVault: null,
    recoveryController: null,
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

// Seed recovery never exposes the branded adapter set. It can run only against
// the exact current two-relay installation and is invalidated by page teardown,
// installation replacement, relay rotation, or qualification lease expiry.
export async function recoverPeeritSeedFromActiveRelayInstallationV1 (options = {}) {
  const sync = options.sync
  const installation = sync && ACTIVE_RELAY_INSTALLATIONS.get(sync)
  if (!installation || installation.controller.signal.aborted ||
      installation.adapters.length !== 2 || !installation.capabilityVault) {
    throw qualificationError('PEERIT_SEED_RECOVERY_TWO_QUALIFIED_RELAYS_REQUIRED',
      'seed recovery requires one active installation with exactly two qualified relays')
  }
  if (options.signal != null &&
      (typeof options.signal !== 'object' || typeof options.signal.addEventListener !== 'function' ||
       typeof options.signal.removeEventListener !== 'function' || typeof options.signal.aborted !== 'boolean')) {
    throw new TypeError('seed recovery signal must be an AbortSignal')
  }
  if (installation.recoveryController && !installation.recoveryController.signal.aborted) {
    installation.recoveryController.abort(qualificationError(
      'PEERIT_SEED_RECOVERY_SUPERSEDED', 'newer seed recovery superseded the prior attempt'))
  }
  const controller = new AbortController()
  installation.recoveryController = controller
  const forward = signal => () => controller.abort(signal.reason || qualificationError(
    'PEERIT_SEED_RECOVERY_ABORTED', 'seed recovery was aborted'))
  const parents = [installation.controller.signal, options.signal].filter(Boolean)
  const listeners = parents.map(signal => [signal, forward(signal)])
  for (const [signal, listener] of listeners) {
    if (signal.aborted) listener()
    else signal.addEventListener('abort', listener, { once: true })
  }
  const generation = installation.adapterGeneration
  const adapters = installation.adapters
  try {
    if (controller.signal.aborted) throw controller.signal.reason
    const { createPeeritSeedColdReaderV1 } = await import('./cold-reader.mjs')
    assertRelayInstallationCurrent(sync, installation)
    if (generation !== installation.adapterGeneration || adapters !== installation.adapters) {
      throw qualificationError('PEERIT_SEED_RECOVERY_RELAY_SET_CHANGED',
        'qualified relay set changed before seed recovery began')
    }
    const reader = createPeeritSeedColdReaderV1({
      sync,
      relays: adapters,
      capabilityVault: installation.capabilityVault,
      signal: controller.signal,
      concurrency: options.concurrency,
      timeoutMillis: options.timeoutMillis,
      now: options.now
    })
    const result = await reader.read(options.artifactBytes, options.verification)
    assertRelayInstallationCurrent(sync, installation)
    if (controller.signal.aborted || generation !== installation.adapterGeneration ||
        adapters !== installation.adapters) {
      throw controller.signal.reason || qualificationError(
        'PEERIT_SEED_RECOVERY_RELAY_SET_CHANGED', 'qualified relay set changed during seed recovery')
    }
    return result
  } finally {
    if (installation.recoveryController === controller) installation.recoveryController = null
    for (const [signal, listener] of listeners) signal.removeEventListener('abort', listener)
  }
}

function exactLimitedCellGetControl (value) {
  if (!value || typeof value !== 'object' ||
      typeof value.createBlindCellGetControl !== 'function' ||
      typeof value.createBrowserCryptoRuntime !== 'function' ||
      Object.keys(value).sort().join('\0') !==
        ['createBlindCellGetControl', 'createBrowserCryptoRuntime'].sort().join('\0')) {
    throw qualificationError('PEERIT_LIMITED_CELL_GET_CONTROL_INVALID',
      'authenticated limited Cell-GET module is not the exact two-export surface')
  }
  return value
}

function exactLimitedDescriptorControl (value) {
  const required = [
    'BlindDescriptorBootstrapHttpClient',
    'DescriptorTrustStore',
    'createDescribeGetRequest',
    'trustedAdmissionProfile',
    'trustedDescriptorValidity',
    'verifyDescriptorBytes'
  ]
  if (!value || typeof value !== 'object' ||
      required.some(name => typeof value[name] !== 'function')) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CONTROL_INVALID',
      'authenticated full control module cannot verify limited Cell-GET descriptor authority')
  }
  return value
}

const LIMITED_DESCRIBE_MEDIA_TYPE = 'application/vnd.hiverelay.blind-v1'
const LIMITED_DESCRIBE_OUTER_CLASS = 3
const LIMITED_DESCRIBE_OUTER_BYTES = 65_536
const LIMITED_DESCRIBE_DISPATCH_HEADER_BYTES = 45
const LIMITED_DESCRIBE_RESULT_BODY_LIMIT = 16_384
const LIMITED_DESCRIBE_MAX_TIMEOUT_MILLIS = 15_000

function readU32be (value, offset) {
  return ((value[offset] * 0x1000000) +
    (value[offset + 1] << 16) +
    (value[offset + 2] << 8) +
    value[offset + 3]) >>> 0
}

function writeU32be (value, offset, number) {
  value[offset] = (number >>> 24) & 0xff
  value[offset + 1] = (number >>> 16) & 0xff
  value[offset + 2] = (number >>> 8) & 0xff
  value[offset + 3] = number & 0xff
}

function readU64be (value, offset) {
  let result = 0n
  for (let index = 0; index < 8; index++) {
    result = (result << 8n) | BigInt(value[offset + index])
  }
  return result
}

function allZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function limitedRandomBytes (runtime, length, field) {
  if (!runtime || typeof runtime.randomBytes !== 'function') {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_RUNTIME_INVALID',
      'authenticated descriptor discovery runtime has no random source')
  }
  const output = bytes(runtime.randomBytes(length), field)
  if (output.byteLength !== length) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_RUNTIME_INVALID',
      `authenticated descriptor discovery runtime returned the wrong ${field} length`)
  }
  return output
}

function nonzeroLimitedRequestId (runtime) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const requestId = limitedRandomBytes(runtime, 16, 'descriptor requestId')
    if (!allZero(requestId)) return requestId
  }
  throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_RUNTIME_INVALID',
    'authenticated descriptor discovery runtime returned only zero request IDs')
}

function currentDescriptorRequest (descriptorControl, runtime) {
  const request = descriptorControl.createDescribeGetRequest({ runtime })
  if (!request || !request.request || request.request.descriptorHash != null ||
      !request.wire || request.wire.familyId !== 1 || request.wire.operationId !== 1 ||
      request.wire.expectedResultBodyBytes !== LIMITED_DESCRIBE_RESULT_BODY_LIMIT) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_REQUEST_INVALID',
      'authenticated full control did not produce the fixed current DESCRIBE.GET request')
  }
  const body = bytes(request.requestBytes, 'current DESCRIBE.GET request bytes')
  const requestId = nonzeroLimitedRequestId(runtime)
  const dispatch = new Uint8Array(LIMITED_DESCRIBE_DISPATCH_HEADER_BYTES + body.byteLength)
  writeU32be(dispatch, 0, dispatch.byteLength - 4)
  dispatch[4] = 1
  dispatch[5] = 1
  dispatch[6] = 1
  dispatch[7] = 1
  dispatch.set(requestId, 9)
  writeU32be(dispatch, 41, body.byteLength)
  dispatch.set(body, LIMITED_DESCRIBE_DISPATCH_HEADER_BYTES)
  if (dispatch.byteLength + 6 > LIMITED_DESCRIBE_OUTER_BYTES) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_REQUEST_INVALID',
      'current DESCRIBE.GET request exceeds its fixed outer class')
  }
  const envelope = new Uint8Array(LIMITED_DESCRIBE_OUTER_BYTES)
  envelope[0] = 1
  envelope[1] = LIMITED_DESCRIBE_OUTER_CLASS
  writeU32be(envelope, 2, dispatch.byteLength)
  envelope.set(dispatch, 6)
  const padding = limitedRandomBytes(
    runtime, envelope.byteLength - 6 - dispatch.byteLength, 'descriptor request padding')
  envelope.set(padding, 6 + dispatch.byteLength)
  return Object.freeze({ body: envelope, requestId })
}

function limitedDescribeTimeoutMillis (value) {
  if (value == null) return LIMITED_DESCRIBE_MAX_TIMEOUT_MILLIS
  if (!Number.isSafeInteger(value) || value < 1 ||
      value > LIMITED_DESCRIBE_MAX_TIMEOUT_MILLIS) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_TIMEOUT_INVALID',
      `descriptor timeoutMillis must be within 1..${LIMITED_DESCRIBE_MAX_TIMEOUT_MILLIS}`)
  }
  return value
}

function limitedDescribeAbortScope (parent, timeoutMillis) {
  if (typeof AbortController !== 'function') {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_ABORT_UNAVAILABLE',
      'AbortController is required for bounded current descriptor discovery')
  }
  const controller = new AbortController()
  const forward = () => controller.abort(parent && parent.reason)
  if (parent) {
    if (parent.aborted) forward()
    else parent.addEventListener('abort', forward, { once: true })
  }
  const timer = setTimeout(() => controller.abort(qualificationError(
    'PEERIT_LIMITED_DESCRIPTOR_DEADLINE', 'current descriptor discovery deadline elapsed')),
  timeoutMillis)
  return Object.freeze({
    signal: controller.signal,
    close () {
      clearTimeout(timer)
      if (parent) parent.removeEventListener('abort', forward)
    }
  })
}

async function readExactLimitedDescribeResponse (response, signal) {
  const declared = response.headers && typeof response.headers.get === 'function'
    ? response.headers.get('content-length')
    : null
  const contentEncoding = response.headers && typeof response.headers.get === 'function'
    ? response.headers.get('content-encoding')
    : null
  const transferEncoding = response.headers && typeof response.headers.get === 'function'
    ? response.headers.get('transfer-encoding')
    : null
  if (contentEncoding != null || transferEncoding != null) {
    throw qualificationError('RELAY_PROTOCOL_VIOLATION',
      'encoded or transfer-framed bootstrap responses are forbidden')
  }
  if (declared !== String(LIMITED_DESCRIBE_OUTER_BYTES)) {
    throw qualificationError('RELAY_PROTOCOL_VIOLATION',
      'bootstrap response must declare the exact selected class')
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw qualificationError('TRANSPORT_UNAVAILABLE',
      'a bounded streaming bootstrap response is required')
  }
  const reader = response.body.getReader()
  const output = new Uint8Array(LIMITED_DESCRIBE_OUTER_BYTES)
  let total = 0
  const onAbort = () => Promise.resolve(reader.cancel(signal.reason)).catch(() => {})
  if (signal.aborted) onAbort()
  else signal.addEventListener('abort', onAbort, { once: true })
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = bytes(value, 'bootstrap response chunk')
      total += chunk.byteLength
      if (total > output.byteLength) {
        throw qualificationError('RELAY_PROTOCOL_VIOLATION',
          'bootstrap response exceeds the selected class')
      }
      output.set(chunk, total - chunk.byteLength)
    }
  } finally {
    signal.removeEventListener('abort', onAbort)
    if (total > output.byteLength && typeof reader.cancel === 'function') {
      await reader.cancel().catch(() => {})
    }
    if (typeof reader.releaseLock === 'function') reader.releaseLock()
  }
  if (total !== output.byteLength) {
    throw qualificationError('RELAY_PROTOCOL_VIOLATION',
      'bootstrap response is shorter than the selected class')
  }
  return output
}

function limitedDescribeResponseBody (input, requestId) {
  const envelope = bytes(input, 'current descriptor response')
  if (envelope.byteLength !== LIMITED_DESCRIBE_OUTER_BYTES ||
      envelope[0] !== 1 || envelope[1] !== LIMITED_DESCRIBE_OUTER_CLASS) {
    throw qualificationError('RELAY_PROTOCOL_VIOLATION',
      'current descriptor response changed the fixed outer envelope')
  }
  const innerLength = readU32be(envelope, 2)
  if (innerLength < LIMITED_DESCRIBE_DISPATCH_HEADER_BYTES ||
      innerLength + 6 > envelope.byteLength) {
    throw qualificationError('RELAY_PROTOCOL_VIOLATION',
      'current descriptor response has an invalid inner length')
  }
  const dispatch = envelope.subarray(6, 6 + innerLength)
  const bodyLength = readU32be(dispatch, 41)
  if (readU32be(dispatch, 0) !== dispatch.byteLength - 4 ||
      dispatch.byteLength !== LIMITED_DESCRIBE_DISPATCH_HEADER_BYTES + bodyLength ||
      bodyLength > LIMITED_DESCRIBE_RESULT_BODY_LIMIT ||
      dispatch[4] !== 1 || dispatch[6] !== 1 || dispatch[7] !== 1 ||
      dispatch[8] !== 0 || readU64be(dispatch, 25) !== 0n ||
      readU64be(dispatch, 33) !== 0n ||
      !bytesEqual(dispatch.subarray(9, 25), requestId)) {
    throw qualificationError('RELAY_PROTOCOL_VIOLATION',
      'current descriptor response framing or correlation is invalid')
  }
  if (dispatch[5] === 3) {
    throw qualificationError('TRANSPORT_FAILURE',
      'descriptor bootstrap returned a canonical relay error')
  }
  if (dispatch[5] !== 2) {
    throw qualificationError('RELAY_PROTOCOL_VIOLATION',
      'current descriptor response is not a unary response')
  }
  return new Uint8Array(dispatch.subarray(LIMITED_DESCRIBE_DISPATCH_HEADER_BYTES))
}

async function fetchCurrentLimitedDescriptor ({
  descriptorControl,
  runtime,
  canonicalUrl,
  profile,
  nowEpoch,
  fetch,
  signal,
  timeoutMillis
}) {
  if (typeof fetch !== 'function') {
    throw qualificationError('TRANSPORT_UNAVAILABLE',
      'fetch implementation is required for current descriptor discovery')
  }
  const request = currentDescriptorRequest(descriptorControl, runtime)
  const scope = limitedDescribeAbortScope(signal, limitedDescribeTimeoutMillis(timeoutMillis))
  try {
    const response = await fetch(new TextDecoder('utf-8', { fatal: true }).decode(canonicalUrl), {
      method: 'POST',
      headers: [['content-type', LIMITED_DESCRIBE_MEDIA_TYPE]],
      body: request.body,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: scope.signal
    })
    if (!response || response.status !== 200) {
      throw qualificationError('TRANSPORT_FAILURE',
        'descriptor bootstrap returned a non-protocol status')
    }
    const contentType = response.headers && typeof response.headers.get === 'function'
      ? response.headers.get('content-type')
      : null
    if (contentType !== LIMITED_DESCRIBE_MEDIA_TYPE) {
      throw qualificationError('RELAY_PROTOCOL_VIOLATION',
        'bootstrap response media type is not the blind protocol')
    }
    const envelope = await readExactLimitedDescribeResponse(response, scope.signal)
    return descriptorControl.verifyDescriptorBytes(
      limitedDescribeResponseBody(envelope, request.requestId), {
        nowEpoch: nowEpoch(),
        supportedProtocolProfiles: profile.supportedProtocolProfiles,
        supportedTransportProfiles: profile.supportedTransportProfiles
      })
  } finally {
    scope.close()
  }
}

function limitedDescriptorLinkage (descriptor) {
  if (!descriptor || typeof descriptor.snapshotBytes !== 'function') {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID',
      'authenticated descriptor snapshot is unavailable')
  }
  const snapshot = bytes(descriptor.snapshotBytes(), 'authenticated descriptor snapshot')
  const prefixLength = 1 + 32 + 32 + 8 + 1
  if (snapshot.byteLength < prefixLength || snapshot[0] !== 1) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID',
      'authenticated descriptor linkage prefix is invalid')
  }
  const descriptorSequence = readU64be(snapshot, 65)
  const previousTag = snapshot[73]
  const previousDescriptorHash = previousTag === 0
    ? null
    : previousTag === 1 && snapshot.byteLength >= prefixLength + 32
        ? new Uint8Array(snapshot.subarray(74, 106))
        : undefined
  if (previousDescriptorHash === undefined ||
      descriptorSequence !== BigInt(descriptor.descriptorSequence) ||
      !bytesEqual(snapshot.subarray(1, 33), descriptor.relayPublicKey) ||
      !bytesEqual(snapshot.subarray(33, 65), descriptor.storeId)) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID',
      'authenticated descriptor linkage disagrees with its full control brand')
  }
  return Object.freeze({
    descriptorHash: bytes(descriptor.descriptorHash, 'descriptor hash', 32),
    descriptorSequence,
    previousDescriptorHash,
    relayPublicKey: bytes(descriptor.relayPublicKey, 'descriptor relay public key', 32),
    storeId: bytes(descriptor.storeId, 'descriptor storeId', 32)
  })
}

function sameLimitedAdmissionProfile (actual, expected) {
  const sameParameterUrl =
    ((actual?.parameterUrl == null && expected?.parameterUrl == null) ||
      (actual?.parameterUrl != null && expected?.parameterUrl != null &&
        bytesEqual(actual.parameterUrl, expected.parameterUrl)))
  // The admission parameterHash is deliberately NOT pinned here: it rotates
  // with the fleet and is carried by the current signature-verified descriptor
  // (the descriptor chain IS its forward channel). The release-signed profile
  // pins only the admission scheme's stable shape; wherever signed admission
  // parameters are consumed, verifyAdmissionParametersBytes verifies them
  // against the descriptor's own advertised binding with no weakening.
  return actual && expected &&
    actual.profileId === expected.profileId &&
    actual.schemeId === expected.schemeId &&
    actual.conformanceClass === expected.conformanceClass &&
    actual.roleBits === expected.roleBits &&
    sameParameterUrl
}

function limitedRelayContext (relay, head, profile) {
  const requirement = profile.requirement
  const transport = profile.supportedTransportProfiles.find(value =>
    value.transportId === relay.transportId)
  const exact = {
    familyId: relay.familyId,
    operationId: relay.operationId,
    endpointId: relay.endpointId,
    transportSupportBit: relay.transportSupportBit,
    privacyProfileBit: relay.privacyProfileBit
  }
  for (const field of Object.keys(exact)) {
    if (exact[field] !== requirement[field]) {
      throw qualificationError('PEERIT_LIMITED_CELL_GET_CONTEXT_DRIFT',
        `signed seed relay changed the release-pinned ${field}`)
    }
  }
  if (!transport || transport.transportSupportBit !== relay.transportSupportBit ||
      fixedHex(head.storeId) !== relay.storeId) {
    throw qualificationError('PEERIT_LIMITED_CELL_GET_CONTEXT_DRIFT',
      'signed seed relay changed its release-pinned transport or store')
  }
  return Object.freeze({
    descriptorHash: bytes(head.descriptorHash, 'qualified descriptor hash', 32),
    descriptorSequence: BigInt(head.descriptorSequence),
    continuityRoot: bytes(
      relay.continuityRootRelayPublicKey, 'continuity root relay public key', 32),
    storeId: bytes(head.storeId, 'qualified descriptor storeId', 32),
    familyId: requirement.familyId,
    operationId: requirement.operationId,
    endpointId: requirement.endpointId,
    transportId: relay.transportId,
    transportSupportBit: requirement.transportSupportBit,
    privacyProfileBit: requirement.privacyProfileBit
  })
}

// A cold first visit re-walks the signed descriptor chain head→genesis with one
// sequential describe round-trip per link. The walk carries no overall deadline,
// so a single transient transport abort (a dropped connection, a network change,
// or the vendored client's own per-request deadline truncating one response)
// would otherwise fail the whole chain and surface as blocked-seed-recovery.
// Retry ONLY transient transport failures, a bounded number of times with
// exponential backoff (400ms × 2^attempt → a ~12s cumulative window) so a
// SUSTAINED transient outage (a network change / VPN or WiFi handoff that
// aborts several consecutive describes) is survived, not just an isolated blip.
// A TRUNCATED HTTP body — the relay edge closing the connection mid-response so
// the vendored client reads fewer bytes than the response's declared size class
// ("bootstrap response is shorter than the selected class") — is the same class
// of transient short read: the incomplete body is never parsed, verified, or
// accepted, so re-asking relaxes nothing. That retry is scoped to the EXACT
// vendored short-read message; every OTHER RELAY_PROTOCOL_VIOLATION (framing,
// wrong content-length, trailing bytes, malformed frame) still fails closed
// forever. And as before, a verification failure (discontinuity, duplicate,
// fork, drift, bad signature) is never retried and fails closed immediately,
// and an explicit caller/lifecycle abort is never retried either.
const LIMITED_WALK_TRANSIENT_RETRY_ATTEMPTS = 6
const LIMITED_WALK_TRANSIENT_RETRY_BASE_MILLIS = 400

export function isTransientDescriptorFetchFailure (error) {
  if (!error || typeof error !== 'object') return false
  if (error.code === 'TRANSPORT_FAILURE') return true
  if (error.name === 'AbortError') return true
  if (error instanceof TypeError) return true
  // Exact truncated-body short-reads only. The walk's responses come from two
  // vendored readers — the describe/bootstrap reader ("bootstrap response is
  // shorter than the selected class") and the health-challenge / generic reader
  // ("response is shorter than the selected class") — and either can be cut
  // mid-body by the relay edge; both are the same transient short read, never
  // parsed or verified. Every OTHER RELAY_PROTOCOL_VIOLATION fails closed.
  return error.code === 'RELAY_PROTOCOL_VIOLATION' &&
    (error.message === 'bootstrap response is shorter than the selected class' ||
     error.message === 'response is shorter than the selected class')
}

function abortableWalkDelay (milliseconds, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(signal.reason || Object.assign(new Error('descriptor walk retry aborted'), { name: 'AbortError' }))
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason || Object.assign(new Error('descriptor walk retry aborted'), { name: 'AbortError' }))
    }
    const timer = setTimeout(() => {
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve()
    }, milliseconds)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })
  })
}

async function fetchDescriptorWithTransientRetry (fetchOnce, signal) {
  let lastError = null
  for (let attempt = 0; attempt < LIMITED_WALK_TRANSIENT_RETRY_ATTEMPTS; attempt++) {
    if (signal && signal.aborted) {
      throw signal.reason || Object.assign(new Error('descriptor walk aborted'), { name: 'AbortError' })
    }
    try {
      return await fetchOnce()
    } catch (error) {
      lastError = error
      const callerAborted = signal && signal.aborted
      if (callerAborted || !isTransientDescriptorFetchFailure(error) ||
          attempt === LIMITED_WALK_TRANSIENT_RETRY_ATTEMPTS - 1) {
        throw error
      }
      await abortableWalkDelay(LIMITED_WALK_TRANSIENT_RETRY_BASE_MILLIS * (2 ** attempt), signal)
    }
  }
  throw lastError
}

async function qualifyLimitedSeedRelay ({
  readControl,
  descriptorControl,
  runtime,
  fetch,
  relay,
  relayProfile,
  profile,
  nowEpoch,
  monotonicMillis,
  signal,
  timeoutMillis
}) {
  const canonicalUrl = new TextEncoder().encode(relay.canonicalDescribeUrl)
  const headDescriptor = await fetchDescriptorWithTransientRetry(() =>
    fetchCurrentLimitedDescriptor({
      descriptorControl,
      runtime,
      canonicalUrl,
      profile,
      nowEpoch,
      fetch,
      signal,
      timeoutMillis
    }), signal)
  const head = limitedDescriptorLinkage(headDescriptor)
  if (head.descriptorSequence < BigInt(relay.minimumDescriptorSequence) ||
      fixedHex(head.storeId) !== relay.storeId) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_HEAD_INVALID',
      'current descriptor head is below or outside the signed seed relay anchor')
  }

  const descending = [headDescriptor]
  const seen = new Set([fixedHex(head.descriptorHash)])
  let current = head
  while (current.descriptorSequence > 0n) {
    if (descending.length >= profile.maximumDescriptorHistory ||
        current.previousDescriptorHash == null) {
      throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INCOMPLETE',
        'descriptor history did not reach signed genesis within its closed bound')
    }
    const previousHash = fixedHex(current.previousDescriptorHash)
    if (seen.has(previousHash)) {
      throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_DUPLICATE',
        'descriptor history repeated a hash')
    }
    const bootstrapClient = new descriptorControl.BlindDescriptorBootstrapHttpClient({
      runtime,
      fetch
    })
    const previousDescriptor = await fetchDescriptorWithTransientRetry(() =>
      bootstrapClient.fetchVerifiedDescriptor({
        canonicalUrl,
        expectedDescriptorHash: current.previousDescriptorHash,
        nowEpoch: nowEpoch(),
        history: true,
        supportedProtocolProfiles: profile.supportedProtocolProfiles,
        supportedTransportProfiles: profile.supportedTransportProfiles,
        signal,
        timeoutMillis
      }), signal)
    const previous = limitedDescriptorLinkage(previousDescriptor)
    if (previous.descriptorSequence + 1n !== current.descriptorSequence ||
        fixedHex(previous.descriptorHash) !== previousHash ||
        fixedHex(previous.storeId) !== relay.storeId) {
      throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID',
        'descriptor history has a sequence, hash, or store discontinuity')
    }
    seen.add(previousHash)
    descending.push(previousDescriptor)
    current = previous
  }
  if (current.previousDescriptorHash != null ||
      fixedHex(current.descriptorHash) !== relay.descriptorGenesisHash ||
      fixedHex(current.relayPublicKey) !== relay.continuityRootRelayPublicKey ||
      fixedHex(current.storeId) !== relay.storeId) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_GENESIS_MISMATCH',
      'descriptor history does not terminate at the signed relay genesis')
  }

  const ascending = descending.reverse()
  const trustStore = new descriptorControl.DescriptorTrustStore()
  let trusted = await trustStore.accept(ascending[0], {
    pinnedDescriptorHash: bytes(relay.descriptorGenesisHash, 'descriptor genesis hash', 32),
    continuityRootRelayPublicKey: bytes(
      relay.continuityRootRelayPublicKey, 'continuity root relay public key', 32)
  })
  for (let index = 1; index < ascending.length; index++) {
    trusted = await trustStore.accept(ascending[index], {
      continuityRootRelayPublicKey: bytes(
        relay.continuityRootRelayPublicKey, 'continuity root relay public key', 32)
    })
  }
  if (fixedHex(trusted.descriptorHash) !== fixedHex(head.descriptorHash)) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID',
      'accepted descriptor chain did not terminate at the fetched head')
  }
  const advertised = descriptorControl.trustedAdmissionProfile(
    trusted, relayProfile.admissionProfile.profileId)
  if (!sameLimitedAdmissionProfile(advertised, relayProfile.admissionProfile)) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_ADMISSION_PROFILE_DRIFT',
      'descriptor does not carry the release-signed admission-v3 profile')
  }

  // The health proof (a DESCRIBE.CHALLENGE over the direct client) is the one
  // remaining relay fetch in this qualification; a transient transport abort of
  // it is retried exactly like the chain-walk describes above. A genuine
  // not-qualified / health rejection is non-transient and still fails closed.
  const qualified = await fetchDescriptorWithTransientRetry(async () => {
    const qualifiedAtMonotonicMillis = monotonicMillis()
    try {
      const endpoint = await readControl.qualifyCellGetCandidate({
        canonicalUrl,
        expectedDescriptorHash: head.descriptorHash,
        continuityRootRelayPublicKey: bytes(
          relay.continuityRootRelayPublicKey, 'continuity root relay public key', 32),
        signal,
        timeoutMillis
      }, {
        endpointId: profile.requirement.endpointId,
        requiredRoleBits: profile.requirement.requiredRoleBits,
        privacyProfileBit: profile.requirement.privacyProfileBit,
        transportSupportBit: profile.requirement.transportSupportBit,
        signal,
        timeoutMillis
      })
      return Object.freeze({ endpoint, qualifiedAtMonotonicMillis })
    } catch (error) {
      if (error && (error.code === 'DESCRIPTOR_CHAIN_INVALID' ||
          error.code === 'DESCRIPTOR_HISTORY_LIMIT' ||
          error.code === 'UNTRUSTED_RELAY_IDENTITY')) {
        throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID',
          'limited Cell-GET control rejected the authenticated descriptor history')
      }
      throw error
    }
  }, signal)
  // The limited control performed the health proof before returning its opaque
  // endpoint. Retain the start of that successful attempt, not a later clock
  // sample, so adapter freshness is conservative.
  const qualifiedAtMonotonicMillis = qualified.qualifiedAtMonotonicMillis
  const context = limitedRelayContext(relay, head, profile)
  const validity = descriptorControl.trustedDescriptorValidity(trusted)
  const epoch = nowEpoch()
  if (!validity || epoch < validity.issuedEpoch || epoch >= validity.expiresEpoch) {
    throw qualificationError('PEERIT_LIMITED_DESCRIPTOR_EXPIRED',
      'qualified descriptor is outside its signed epoch window')
  }
  return Object.freeze({
    qualified,
    qualifiedAtMonotonicMillis,
    context,
    head,
    validity
  })
}

function brandedLimitedSeedAdapter ({
  relay,
  control,
  qualification,
  nowEpoch,
  monotonicMillis,
  signal,
  timeoutMillis
}) {
  const qualifiedAt = qualification.qualifiedAtMonotonicMillis
  if (typeof qualifiedAt !== 'number' || !Number.isFinite(qualifiedAt) ||
      qualifiedAt < 0) {
    throw qualificationError('PEERIT_LIMITED_CELL_GET_QUALIFICATION_INVALID',
      'limited Cell-GET qualification has no trusted monotonic observation')
  }
  const localHealthDeadline = qualifiedAt + 60_000
  const assertFresh = () => {
    if (signal && signal.aborted) throw signal.reason
    const monotonic = monotonicMillis()
    const epoch = nowEpoch()
    if (monotonic < qualifiedAt || monotonic >= localHealthDeadline ||
        epoch < qualification.validity.issuedEpoch ||
        epoch >= qualification.validity.expiresEpoch) {
      throw qualificationError('PEERIT_LIMITED_CELL_GET_QUALIFICATION_EXPIRED',
        'ephemeral signed-health Cell-GET qualification expired')
    }
  }
  const readCellCapability = async (request, operationContext = {}) => {
    assertFresh()
    const result = await control.readCell({
      endpoint: qualification.qualified.endpoint,
      readCap: request.readCapability,
      signal: operationContext.signal || signal,
      timeoutMillis
    })
    const verified = Object.freeze({
      relayId: String(request.relayId),
      targetId: String(request.targetId),
      innerBytes: bytes(result.structuredContent, 'verified limited Cell GET innerBytes'),
      evidenceRef: `cell-get:${relay.relayId}:${fixedHex(qualification.head.descriptorHash)}:${fixedHex(result.requestCommitment)}`
    })
    VERIFIED_RELAY_CELL_GET_RESULTS.add(verified)
    assertFresh()
    return verified
  }
  assertFresh()
  const context = Object.freeze({
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    continuityRootRelayPublicKey: relay.continuityRootRelayPublicKey,
    storeId: relay.storeId,
    descriptorGenesisHash: relay.descriptorGenesisHash,
    descriptorHeadHash: fixedHex(qualification.head.descriptorHash),
    descriptorSequence: qualification.context.descriptorSequence,
    familyId: qualification.context.familyId,
    operationId: qualification.context.operationId,
    endpointId: qualification.context.endpointId,
    transportId: qualification.context.transportId,
    transportSupportBit: qualification.context.transportSupportBit,
    privacyProfileBit: qualification.context.privacyProfileBit
  })
  const adapter = Object.freeze({
    id: `limited-seed:${relay.relayId}:${context.descriptorHeadHash}`,
    compatible: true,
    readCellCapability
  })
  VERIFIED_RELAY_ADAPTERS.add(adapter)
  VERIFIED_RELAY_ADAPTER_CONTEXTS.set(adapter, context)
  return adapter
}

async function limitedSeedCachedResult (sync, seed, signal) {
  if (!sync || typeof sync.discoveryFloor !== 'function' ||
      typeof sync.ingestVerifiedRemoteBatch !== 'function') {
    throw new TypeError('limited seed recovery requires the remote-ingest substrate sync boundary')
  }
  if (signal && signal.aborted) throw signal.reason
  const floor = await sync.discoveryFloor(seed.sourceId)
  if (signal && signal.aborted) throw signal.reason
  if (!floor) {
    if (seed.payload.bootstrapSequence !== 0 ||
        seed.payload.previousBootstrapHash != null) {
      throw qualificationError('PEERIT_COLD_READER_GAP',
        'cold browser requires bootstrap sequence zero')
    }
    return null
  }
  if (seed.payload.bootstrapSequence < floor.checkpointSequence) {
    throw qualificationError('PEERIT_COLD_READER_ROLLBACK',
      'signed bootstrap is below the persisted source floor')
  }
  if (seed.payload.bootstrapSequence === floor.checkpointSequence) {
    if (seed.artifactHash !== floor.checkpointHash) {
      throw qualificationError('PEERIT_COLD_READER_FORK',
        'signed bootstrap conflicts at the persisted source floor')
    }
    return Object.freeze({
      ok: true,
      cached: true,
      networkGets: 0,
      networkPuts: 0,
      sourceId: seed.sourceId,
      checkpointSequence: floor.checkpointSequence,
      checkpointHash: floor.checkpointHash,
      recordCount: seed.payload.records.length,
      fallbackCount: 0
    })
  }
  if (seed.payload.bootstrapSequence !== floor.checkpointSequence + 1 ||
      seed.payload.previousBootstrapHash !== floor.checkpointHash) {
    throw qualificationError('PEERIT_COLD_READER_GAP',
      'signed bootstrap does not directly extend the persisted source floor')
  }
  return null
}

// Release-scoped, non-installing recovery seam. It verifies the signed seed
// before the first relay fetch, walks both current descriptor heads to the
// signed genesis anchors, health-qualifies only CELL.GET, ingests the verified
// records, and never calls sync.setRelays or prepares a PUT.
export async function recoverPeeritSeedWithLimitedCellGetAuthorityV1 (options = {}) {
  if (Object.prototype.hasOwnProperty.call(options, 'artifactBytes') ||
      Object.prototype.hasOwnProperty.call(options, 'verification')) {
    throw qualificationError('PEERIT_LIMITED_SEED_AUTHORITY_INJECTION',
      'limited recovery seed bytes and verification are fixed by the signed runtime authority')
  }
  if (!isVerifiedPeeritBrowserRuntimeAuthority(options.releaseAuthority)) {
    throw qualificationError('PEERIT_AUTHENTICATED_RELAY_RUNTIME_AUTHORITY_REQUIRED',
      'limited seed recovery requires the signed browser runtime authority')
  }
  const runtimeAssembly = getVerifiedPeeritBrowserRuntimeAssembly(options.releaseAuthority)
  const limited = runtimeAssembly.limitedCellGet
  const seedBootstrap = getVerifiedPeeritBrowserSeedBootstrapV1(
    options.releaseAuthority)
  const namespace = exactLimitedCellGetControl(limited && limited.control)
  const descriptorControl = exactLimitedDescriptorControl(runtimeAssembly.control)
  const profile = limited && typeof limited.profileSnapshot === 'function'
    ? limited.profileSnapshot()
    : null
  if (!profile || profile.networkPuts !== 0 || profile.ordinaryDelivery !== 'local-only') {
    throw qualificationError('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID',
      'signed limited recovery profile is unavailable')
  }
  if (!seedBootstrap || !seedBootstrap.artifactBytes || !seedBootstrap.verification) {
    throw qualificationError('PEERIT_AUTHENTICATED_SEED_BOOTSTRAP_REQUIRED',
      'signed runtime authority does not bind a seed bootstrap')
  }
  const now = typeof options.now === 'function' ? options.now : Date.now
  const nowEpoch = () => Math.floor(now() / 21_600_000)
  const monotonicMillis = typeof options.monotonicMillis === 'function'
    ? options.monotonicMillis
    : () => globalThis.performance && typeof globalThis.performance.now === 'function'
        ? globalThis.performance.now()
        : Date.now()
  const seed = await verifyPeeritSeedBootstrapV1(seedBootstrap.artifactBytes, {
    ...seedBootstrap.verification,
    now: now()
  })
  if (options.signal && options.signal.aborted) throw options.signal.reason
  const cached = await limitedSeedCachedResult(options.sync, seed, options.signal)
  if (cached) {
    return Object.freeze({
      ...cached,
      qualifiedRelayCount: 0,
      ordinaryDelivery: 'local-only',
      descriptorHeads: Object.freeze([])
    })
  }

  const runtime = namespace.createBrowserCryptoRuntime(options.webCrypto || globalThis.crypto)
  const fetch = options.fetch || (typeof globalThis.fetch === 'function'
    ? globalThis.fetch.bind(globalThis)
    : null)
  const control = namespace.createBlindCellGetControl({
    runtime,
    nowEpoch,
    monotonicMillis,
    supportedProtocolProfiles: profile.supportedProtocolProfiles,
    supportedTransportProfiles: profile.supportedTransportProfiles,
    fetch
  })
  const profileRelays = new Map(profile.relays.map(relay => [relay.relayId, relay]))
  const qualifications = await Promise.all(seed.payload.relays.map(async relay => {
    const relayProfile = profileRelays.get(relay.relayId)
    if (!relayProfile) {
      throw qualificationError('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID',
        'signed seed relay has no signed admission profile')
    }
    return qualifyLimitedSeedRelay({
      readControl: control,
      descriptorControl,
      runtime,
      fetch,
      relay,
      relayProfile,
      profile,
      nowEpoch,
      monotonicMillis,
      signal: options.signal,
      timeoutMillis: options.timeoutMillis
    })
  }))
  const adapters = seed.payload.relays.map((relay, index) => brandedLimitedSeedAdapter({
    relay,
    control,
    qualification: qualifications[index],
    nowEpoch,
    monotonicMillis,
    signal: options.signal,
    timeoutMillis: options.timeoutMillis
  }))
  const { createPeeritSeedColdReaderV1 } = await import('./cold-reader.mjs')
  const reader = createPeeritSeedColdReaderV1({
    sync: options.sync,
    relays: adapters,
    signal: options.signal,
    concurrency: options.concurrency,
    timeoutMillis: options.timeoutMillis,
    now
  })
  const recovered = await reader.read(
    seedBootstrap.artifactBytes, seedBootstrap.verification)
  return Object.freeze({
    ...recovered,
    qualifiedRelayCount: adapters.length,
    ordinaryDelivery: 'local-only',
    networkPuts: 0,
    descriptorHeads: Object.freeze(qualifications.map((qualification, index) => Object.freeze({
      relayId: seed.payload.relays[index].relayId,
      descriptorSequence: qualification.context.descriptorSequence,
      descriptorHeadHash: fixedHex(qualification.head.descriptorHash)
    })))
  })
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
    installation.capabilityVault = capabilityVault
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
      publish: (adapters, status) => publishInstallationRelayStatus(sync, installation, adapters, status),
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
