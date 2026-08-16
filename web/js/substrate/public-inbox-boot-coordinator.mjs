// Sequence-29 public INBOX boot coordinator.
//
// The app entry may activate this module only through the authenticated browser
// runtime. App code never supplies profile validators, app/bootstrap bytes, or
// endpoint handles: those are retained or minted behind module brands here.
import { hashBytes } from '../crypto.js'
import {
  getVerifiedPeeritBrowserPublicInboxBootstrapV1,
  getVerifiedPeeritBrowserRuntimeAssembly
} from './browser-runtime-authority.mjs'
import {
  assertVerifiedPeeritPublicInboxAnnouncementReadbackV1,
  pollPeeritPublicInboxBindingV1,
  verifyPeeritPublicInboxAnnouncementReadbackV1
} from './inbox-discovery.mjs'
import {
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1,
  PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
  assertPeeritSeq29PublicBrowserControlV1,
  isVerifiedPeeritLimitedPublicInboxBootstrapV1,
  verifyPeeritLimitedPublicInboxBootstrapV1
} from './inbox-topic-v1.mjs'
import {
  publishPeeritPublicInboxAnnouncementV1,
  reconcilePeeritPublicInboxAnnouncementV1,
  restorePeeritPublicInboxAnnouncementV1
} from './inbox-pointer-publish.mjs'
import {
  getPeeritProductSeq29AuthoringAuthorityV1
} from './peerit-product-runtime.js'
import { assertPeeritSubstrateSyncV1 } from './peerit-substrate-sync.js'
import {
  acceptPeeritSeq29PublicInboxBootstrapV1,
  claimPeeritSeq29PublicationRelayV1,
  commitPeeritSeq29PublicationIntentV1,
  commitPeeritSeq29PublicInboxPollV1,
  completePeeritSeq29PublicationRelayV1,
  createPeeritSeq29PublicInboxSyncAuthorityV1,
  failPeeritSeq29PublicationRelayV1,
  getPeeritSeq29PublicInboxAppendFloorsV1,
  getPeeritSeq29PublicInboxBootstrapFloorV1,
  getPeeritSeq29PublicationAuthorHeadV1,
  getPeeritSeq29PublicationIntentV1,
  getPeeritSeq29LocalAuthoredPublicationV1,
  markPeeritSeq29PublicationRelayAbsentV1
} from './seq29-public-inbox-sync.mjs'
import { decodePeeritInnerOperationBatchV1 } from './peerit-operation-authority-v1.js'
import {
  asBytes,
  blake2b256,
  bytesEqual,
  bytesToHex
} from './release-control-primitives.mjs'
import { hashPeeritAppArtifactV1 } from './web-asset-manifest.mjs'

const COORDINATOR_PATH = 'js/substrate/public-inbox-boot-coordinator.mjs'
const HEX32 = /^[0-9a-f]{64}$/
const AUTHORIZATIONS = new WeakMap()
const CONSUMED_AUTHORIZATIONS = new WeakSet()
const QUALIFIED_ENDPOINT_SETS = new WeakMap()
const LEASE_EPOCH_MILLIS = 21600000n
const DESCRIBE_MEDIA_TYPE = 'application/vnd.hiverelay.blind-v1'
const DESCRIBE_OUTER_CLASS = 3
const DESCRIBE_OUTER_BYTES = 65_536
const DESCRIBE_DISPATCH_HEADER_BYTES = 45
const DESCRIBE_RESULT_BODY_LIMIT = 16_384
const DESCRIBE_MAX_TIMEOUT_MILLIS = 15_000
const MAX_DESCRIPTOR_HISTORY = 4096

const OPERATIONS = Object.freeze({
  putEndpoint: Object.freeze({ familyId: 2, operationId: 1 }),
  cellGetEndpoint: Object.freeze({ familyId: 2, operationId: 2 }),
  appendEndpoint: Object.freeze({ familyId: 3, operationId: 4 }),
  readEndpoint: Object.freeze({ familyId: 3, operationId: 5 })
})

// Static shipped-wiring inventory only. These values grant no runtime or
// network authority: publication still requires a trusted UI event, an exact
// durable authored intent, authenticated dual-relay qualification, dual
// CELL.PUT + same-relay readback, and a fresh runtime-owned APPEND authority.
export const PEERIT_SEQ29_PUBLIC_INBOX_COORDINATOR_STATUS_V1 = Object.freeze({
  releaseSequence: PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
  shippedEntryReady: true,
  appEntryActivated: true,
  callerSelectedProfileValidatorAccepted: false,
  productionProfileValidatorAccepted: false,
  runtimeOwnedValidationOnlyProfileValidatorRequired: true,
  dualInboxReadReady: true,
  intrinsicAuthorityIngestReady: true,
  cellPutAndAuthorBindReadbackGateReady: true,
  dualAppendReady: true,
  explicitProductPublicationBlocked: false
})

const QUALIFICATION_OPERATIONS = Object.freeze([
  Object.freeze({ field: 'putEndpoint', familyId: 2, operationId: 1 }),
  Object.freeze({ field: 'cellGetEndpoint', familyId: 2, operationId: 2 }),
  Object.freeze({ field: 'appendEndpoint', familyId: 3, operationId: 4 }),
  Object.freeze({ field: 'readEndpoint', familyId: 3, operationId: 5 })
])

function qualificationProfile () {
  return Object.freeze({
    supportedProtocolProfiles: Object.freeze([1, 2, 3].map(protocolId => Object.freeze({
      protocolId,
      major: 1,
      minimumMinor: 0,
      profileHash: new Uint8Array(32).fill(0x0a)
    }))),
    supportedTransportProfiles: Object.freeze([Object.freeze({
      transportId: 1,
      transportSupportBit: 1,
      transportProfileHash: new Uint8Array(32).fill(0x0b)
    })])
  })
}

function fail (code, message, cause, details) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  if (details !== undefined) error.details = details
  throw error
}

function bytes (value, field, length = null) {
  let output
  try { output = new Uint8Array(asBytes(value, field)) } catch (cause) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_BOOT_INVALID', `${field} must be bytes`, cause)
  }
  if (length != null && output.byteLength !== length) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_BOOT_INVALID', `${field} must be ${length} bytes`)
  }
  return output
}

function parseJson (value, field) {
  try {
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(value))
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object')
    return parsed
  } catch (cause) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_BOOT_INVALID', `${field} is not a UTF-8 JSON object`, cause)
  }
}

function releaseSequence (value, field) {
  const sequence = typeof value === 'bigint' ? value : BigInt(value)
  if (sequence !== BigInt(PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1)) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_RELEASE_MISMATCH', `${field} is not release sequence 29`)
  }
  return sequence
}

function endpointContext (control, endpoint, field) {
  let value
  try { value = control.verifiedEndpointContext(endpoint) } catch (cause) {
    fail('PEERIT_SEQ29_RELAY_ENDPOINT_UNAUTHENTICATED', `${field} is not an authenticated endpoint`, cause)
  }
  if (!value || typeof value !== 'object') {
    fail('PEERIT_SEQ29_RELAY_ENDPOINT_UNAUTHENTICATED', `${field} has no authenticated identity`)
  }
  const descriptorSequence = typeof value.descriptorSequence === 'bigint'
    ? value.descriptorSequence
    : BigInt(value.descriptorSequence)
  return Object.freeze({
    relayPublicKey: bytes(value.relayPublicKey, `${field} relayPublicKey`, 32),
    storeId: bytes(value.storeId, `${field} storeId`, 32),
    durabilityContinuityHash: bytes(
      value.durabilityContinuityHash, `${field} durabilityContinuityHash`, 32),
    continuityRoot: bytes(value.continuityRoot, `${field} continuityRoot`, 32),
    descriptorHash: bytes(value.descriptorHash, `${field} descriptorHash`, 32),
    descriptorSequence,
    familyId: value.familyId,
    operationId: value.operationId
  })
}

function sameIdentity (left, right) {
  return bytesEqual(left.relayPublicKey, right.relayPublicKey) &&
    bytesEqual(left.storeId, right.storeId) &&
    bytesEqual(left.durabilityContinuityHash, right.durabilityContinuityHash) &&
    bytesEqual(left.continuityRoot, right.continuityRoot) &&
    left.descriptorSequence === right.descriptorSequence &&
    bytesEqual(left.descriptorHash, right.descriptorHash)
}

function currentUnixMillis (value) {
  let output
  if (value == null) output = BigInt(Date.now())
  else output = typeof value === 'bigint' ? value : BigInt(value)
  if (output < 0n) {
    fail('PEERIT_SEQ29_QUALIFICATION_CLOCK_INVALID',
      'public INBOX qualification time is negative')
  }
  return output
}

function currentMonotonicMillis (provider) {
  const value = provider == null
    ? (globalThis.performance && typeof globalThis.performance.now === 'function'
        ? globalThis.performance.now()
        : 0)
    : provider()
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail('PEERIT_SEQ29_QUALIFICATION_CLOCK_INVALID',
      'public INBOX monotonic time is invalid')
  }
  return value
}

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
  let output = 0n
  for (let index = 0; index < 8; index++) {
    output = (output << 8n) | BigInt(value[offset + index])
  }
  return output
}

function allZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function randomBytes (runtime, length, field) {
  const output = bytes(runtime.randomBytes(length), field)
  if (output.byteLength !== length) {
    fail('PEERIT_SEQ29_DESCRIPTOR_RUNTIME_INVALID',
      `${field} has the wrong length`)
  }
  return output
}

function describeRequestId (runtime) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const requestId = randomBytes(runtime, 16, 'descriptor requestId')
    if (!allZero(requestId)) return requestId
  }
  fail('PEERIT_SEQ29_DESCRIPTOR_RUNTIME_INVALID',
    'authenticated browser runtime returned only zero descriptor request IDs')
}

function currentDescriptorRequest (control, runtime) {
  const request = control.createDescribeGetRequest({ runtime })
  if (!request || !request.request || request.request.descriptorHash != null ||
      !request.wire || request.wire.familyId !== 1 || request.wire.operationId !== 1 ||
      request.wire.expectedResultBodyBytes !== DESCRIBE_RESULT_BODY_LIMIT) {
    fail('PEERIT_SEQ29_DESCRIPTOR_REQUEST_INVALID',
      'authenticated control did not produce the fixed current DESCRIBE.GET request')
  }
  const body = bytes(request.requestBytes, 'current DESCRIBE.GET request bytes')
  const requestId = describeRequestId(runtime)
  const dispatch = new Uint8Array(DESCRIBE_DISPATCH_HEADER_BYTES + body.byteLength)
  writeU32be(dispatch, 0, dispatch.byteLength - 4)
  dispatch[4] = 1
  dispatch[5] = 1
  dispatch[6] = 1
  dispatch[7] = 1
  dispatch.set(requestId, 9)
  writeU32be(dispatch, 41, body.byteLength)
  dispatch.set(body, DESCRIBE_DISPATCH_HEADER_BYTES)
  if (dispatch.byteLength + 6 > DESCRIBE_OUTER_BYTES) {
    fail('PEERIT_SEQ29_DESCRIPTOR_REQUEST_INVALID',
      'current DESCRIBE.GET request exceeds its fixed outer class')
  }
  const envelope = new Uint8Array(DESCRIBE_OUTER_BYTES)
  envelope[0] = 1
  envelope[1] = DESCRIBE_OUTER_CLASS
  writeU32be(envelope, 2, dispatch.byteLength)
  envelope.set(dispatch, 6)
  envelope.set(randomBytes(
    runtime,
    envelope.byteLength - 6 - dispatch.byteLength,
    'descriptor request padding'), 6 + dispatch.byteLength)
  return Object.freeze({ body: envelope, requestId })
}

function descriptorTimeoutMillis (value) {
  if (value == null) return DESCRIBE_MAX_TIMEOUT_MILLIS
  if (!Number.isSafeInteger(value) || value < 1 ||
      value > DESCRIBE_MAX_TIMEOUT_MILLIS) {
    fail('PEERIT_SEQ29_DESCRIPTOR_TIMEOUT_INVALID',
      `descriptor timeoutMillis must be within 1..${DESCRIBE_MAX_TIMEOUT_MILLIS}`)
  }
  return value
}

function descriptorAbortScope (parent, timeoutMillis) {
  if (typeof AbortController !== 'function') {
    fail('PEERIT_SEQ29_DESCRIPTOR_ABORT_UNAVAILABLE',
      'AbortController is required for bounded descriptor discovery')
  }
  const controller = new AbortController()
  const forward = () => controller.abort(parent?.reason)
  if (parent != null) {
    if (typeof parent.addEventListener !== 'function' ||
        typeof parent.removeEventListener !== 'function') {
      fail('PEERIT_SEQ29_DESCRIPTOR_ABORT_INVALID',
        'descriptor signal is not an AbortSignal')
    }
    if (parent.aborted) forward()
    else parent.addEventListener('abort', forward, { once: true })
  }
  const timer = setTimeout(() => controller.abort(Object.assign(
    new Error('current descriptor discovery deadline elapsed'),
    { code: 'PEERIT_SEQ29_DESCRIPTOR_DEADLINE' }
  )), timeoutMillis)
  return Object.freeze({
    signal: controller.signal,
    close () {
      clearTimeout(timer)
      if (parent != null) parent.removeEventListener('abort', forward)
    }
  })
}

async function readExactDescriptorResponse (response, signal) {
  const header = name => response.headers && typeof response.headers.get === 'function'
    ? response.headers.get(name)
    : null
  if (header('content-length') !== String(DESCRIBE_OUTER_BYTES) ||
      header('content-encoding') != null || header('transfer-encoding') != null) {
    fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response changed its fixed unencoded outer class')
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response is not a bounded stream')
  }
  const reader = response.body.getReader()
  const output = new Uint8Array(DESCRIBE_OUTER_BYTES)
  let total = 0
  const onAbort = () => Promise.resolve(reader.cancel(signal.reason)).catch(() => {})
  if (signal.aborted) onAbort()
  else signal.addEventListener('abort', onAbort, { once: true })
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = bytes(value, 'descriptor response chunk')
      total += chunk.byteLength
      if (total > output.byteLength) {
        fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
          'descriptor response exceeds its fixed outer class')
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
    fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response is shorter than its fixed outer class')
  }
  return output
}

function currentDescriptorResponseBody (input, requestId) {
  const envelope = bytes(input, 'current descriptor response')
  if (envelope.byteLength !== DESCRIBE_OUTER_BYTES ||
      envelope[0] !== 1 || envelope[1] !== DESCRIBE_OUTER_CLASS) {
    fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response changed its fixed outer envelope')
  }
  const innerLength = readU32be(envelope, 2)
  if (innerLength < DESCRIBE_DISPATCH_HEADER_BYTES ||
      innerLength + 6 > envelope.byteLength) {
    fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response has an invalid inner length')
  }
  const dispatch = envelope.subarray(6, 6 + innerLength)
  const bodyLength = readU32be(dispatch, 41)
  if (readU32be(dispatch, 0) !== dispatch.byteLength - 4 ||
      dispatch.byteLength !== DESCRIBE_DISPATCH_HEADER_BYTES + bodyLength ||
      bodyLength > DESCRIBE_RESULT_BODY_LIMIT || dispatch[4] !== 1 ||
      dispatch[6] !== 1 || dispatch[7] !== 1 || dispatch[8] !== 0 ||
      readU64be(dispatch, 25) !== 0n || readU64be(dispatch, 33) !== 0n ||
      !bytesEqual(dispatch.subarray(9, 25), requestId)) {
    fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response framing or correlation is invalid')
  }
  if (dispatch[5] === 3) {
    fail('PEERIT_SEQ29_DESCRIPTOR_FETCH_FAILED',
      'relay returned a canonical descriptor error')
  }
  if (dispatch[5] !== 2) {
    fail('PEERIT_SEQ29_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response is not unary')
  }
  return new Uint8Array(dispatch.subarray(DESCRIBE_DISPATCH_HEADER_BYTES))
}

async function fetchCurrentDescriptor ({
  control,
  runtime,
  canonicalUrl,
  profile,
  nowEpoch,
  fetch,
  signal,
  timeoutMillis
}) {
  if (typeof fetch !== 'function') {
    fail('PEERIT_SEQ29_DESCRIPTOR_FETCH_UNAVAILABLE',
      'fetch is required for current descriptor discovery')
  }
  const request = currentDescriptorRequest(control, runtime)
  const scope = descriptorAbortScope(signal, descriptorTimeoutMillis(timeoutMillis))
  try {
    const response = await fetch(canonicalUrl, {
      method: 'POST',
      headers: [['content-type', DESCRIBE_MEDIA_TYPE]],
      body: request.body,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: scope.signal
    })
    if (!response || response.status !== 200 ||
        !response.headers || response.headers.get('content-type') !== DESCRIBE_MEDIA_TYPE) {
      fail('PEERIT_SEQ29_DESCRIPTOR_FETCH_FAILED',
        'relay did not return the fixed descriptor protocol response')
    }
    const envelope = await readExactDescriptorResponse(response, scope.signal)
    return control.verifyDescriptorBytes(
      currentDescriptorResponseBody(envelope, request.requestId), {
        nowEpoch,
        supportedProtocolProfiles: profile.supportedProtocolProfiles,
        supportedTransportProfiles: profile.supportedTransportProfiles
      })
  } finally {
    scope.close()
  }
}

function descriptorLinkage (descriptor) {
  if (!descriptor || typeof descriptor.snapshotBytes !== 'function') {
    fail('PEERIT_SEQ29_DESCRIPTOR_CHAIN_INVALID',
      'authenticated descriptor snapshot is unavailable')
  }
  const snapshot = bytes(descriptor.snapshotBytes(), 'authenticated descriptor snapshot')
  const prefixLength = 1 + 32 + 32 + 8 + 1
  if (snapshot.byteLength < prefixLength || snapshot[0] !== 1) {
    fail('PEERIT_SEQ29_DESCRIPTOR_CHAIN_INVALID',
      'authenticated descriptor linkage prefix is invalid')
  }
  const descriptorSequence = readU64be(snapshot, 65)
  const previousTag = snapshot[73]
  let previousDescriptorHash
  if (previousTag === 0) previousDescriptorHash = null
  else if (previousTag === 1 && snapshot.byteLength >= prefixLength + 32) {
    previousDescriptorHash = new Uint8Array(snapshot.subarray(74, 106))
  }
  if (previousDescriptorHash === undefined ||
      descriptorSequence !== BigInt(descriptor.descriptorSequence) ||
      !bytesEqual(snapshot.subarray(1, 33), descriptor.relayPublicKey) ||
      !bytesEqual(snapshot.subarray(33, 65), descriptor.storeId)) {
    fail('PEERIT_SEQ29_DESCRIPTOR_CHAIN_INVALID',
      'authenticated descriptor linkage disagrees with its control brand')
  }
  return Object.freeze({
    descriptorHash: bytes(descriptor.descriptorHash, 'descriptor hash', 32),
    descriptorSequence,
    previousDescriptorHash,
    relayPublicKey: bytes(descriptor.relayPublicKey, 'descriptor relayPublicKey', 32),
    storeId: bytes(descriptor.storeId, 'descriptor storeId', 32)
  })
}

async function authenticateCurrentDescriptorHead ({
  control,
  runtime,
  binding,
  profile,
  nowEpoch,
  fetch,
  signal,
  timeoutMillis
}) {
  const canonicalUrl = new TextEncoder().encode(binding.canonicalDescribeUrl)
  const headDescriptor = await fetchCurrentDescriptor({
    control,
    runtime,
    canonicalUrl: binding.canonicalDescribeUrl,
    profile,
    nowEpoch,
    fetch,
    signal,
    timeoutMillis
  })
  const head = descriptorLinkage(headDescriptor)
  if (head.descriptorSequence < binding.descriptorFloorSequence ||
      !bytesEqual(head.storeId, binding.storeId) ||
      !bytesEqual(head.relayPublicKey, binding.relayPublicKey)) {
    fail('PEERIT_SEQ29_DESCRIPTOR_HEAD_INVALID',
      `${binding.relayId} current descriptor is below or outside its signed identity`)
  }

  const descending = [headDescriptor]
  const seen = new Set([bytesToHex(head.descriptorHash)])
  let current = head
  let crossedSignedFloor = false
  const assertFloor = linkage => {
    if (linkage.descriptorSequence !== binding.descriptorFloorSequence) return
    if (!bytesEqual(linkage.descriptorHash, binding.descriptorFloorHash) ||
        !bytesEqual(linkage.relayPublicKey, binding.relayPublicKey)) {
      fail('PEERIT_SEQ29_DESCRIPTOR_FLOOR_FORK',
        `${binding.relayId} descriptor history forks its signed floor`)
    }
    crossedSignedFloor = true
  }
  assertFloor(current)
  const bootstrapClient = new control.BlindDescriptorBootstrapHttpClient({
    runtime,
    fetch
  })
  while (current.descriptorSequence > 0n) {
    if (descending.length >= MAX_DESCRIPTOR_HISTORY ||
        current.previousDescriptorHash == null) {
      fail('PEERIT_SEQ29_DESCRIPTOR_CHAIN_INCOMPLETE',
        `${binding.relayId} descriptor history exceeded its closed bound`)
    }
    const previousHash = bytesToHex(current.previousDescriptorHash)
    if (seen.has(previousHash)) {
      fail('PEERIT_SEQ29_DESCRIPTOR_CHAIN_DUPLICATE',
        `${binding.relayId} descriptor history repeated a hash`)
    }
    const previousDescriptor = await bootstrapClient.fetchVerifiedDescriptor({
      canonicalUrl,
      expectedDescriptorHash: current.previousDescriptorHash,
      nowEpoch,
      history: true,
      supportedProtocolProfiles: profile.supportedProtocolProfiles,
      supportedTransportProfiles: profile.supportedTransportProfiles,
      signal,
      timeoutMillis
    })
    const previous = descriptorLinkage(previousDescriptor)
    if (previous.descriptorSequence + 1n !== current.descriptorSequence ||
        !bytesEqual(previous.descriptorHash, current.previousDescriptorHash) ||
        !bytesEqual(previous.storeId, binding.storeId)) {
      fail('PEERIT_SEQ29_DESCRIPTOR_CHAIN_INVALID',
        `${binding.relayId} descriptor history is discontinuous`)
    }
    if (!crossedSignedFloor &&
        previous.descriptorSequence < binding.descriptorFloorSequence) {
      fail('PEERIT_SEQ29_DESCRIPTOR_FLOOR_MISSING',
        `${binding.relayId} descriptor history omitted its signed floor`)
    }
    assertFloor(previous)
    seen.add(previousHash)
    descending.push(previousDescriptor)
    current = previous
  }
  if (!crossedSignedFloor || current.previousDescriptorHash != null ||
      !bytesEqual(current.relayPublicKey, binding.relayPublicKey) ||
      !bytesEqual(current.storeId, binding.storeId)) {
    fail('PEERIT_SEQ29_DESCRIPTOR_ROOT_MISMATCH',
      `${binding.relayId} descriptor history is not rooted in its signed relay identity`)
  }

  const ascending = descending.reverse()
  const trustStore = new control.DescriptorTrustStore()
  let trusted = await trustStore.accept(ascending[0], {
    pinnedDescriptorHash: descriptorLinkage(ascending[0]).descriptorHash,
    continuityRootRelayPublicKey: binding.relayPublicKey
  })
  for (let index = 1; index < ascending.length; index++) {
    trusted = await trustStore.accept(ascending[index], {
      continuityRootRelayPublicKey: binding.relayPublicKey
    })
  }
  if (!bytesEqual(trusted.descriptorHash, head.descriptorHash)) {
    fail('PEERIT_SEQ29_DESCRIPTOR_CHAIN_INVALID',
      `${binding.relayId} accepted descriptor chain did not terminate at its current head`)
  }
  return Object.freeze({
    canonicalUrl,
    head,
    trusted,
    trustStore
  })
}

function qualificationRequirement (operation) {
  return Object.freeze({
    familyId: operation.familyId,
    operationId: operation.operationId,
    endpointId: 1,
    requiredRoleBits: 49,
    privacyProfileBit: 1,
    transportSupportBit: 1
  })
}

function authenticateEndpointSets (control, authority, supplied) {
  if (!Array.isArray(supplied) || supplied.length !== 2) {
    fail('PEERIT_SEQ29_RELAY_ENDPOINT_SET_INVALID', 'exactly two relay endpoint sets are required')
  }
  const byRelayId = new Map()
  for (const value of supplied) {
    if (!value || typeof value !== 'object' ||
        typeof value.relayId !== 'string' || byRelayId.has(value.relayId)) {
      fail('PEERIT_SEQ29_RELAY_ENDPOINT_SET_INVALID', 'relay endpoint IDs must be present and unique')
    }
    const binding = authority.bindings.find(candidate => candidate.relayId === value.relayId)
    if (!binding) {
      fail('PEERIT_SEQ29_RELAY_ENDPOINT_SET_INVALID',
        `relay endpoint set ${value.relayId} is absent from the signed bootstrap`)
    }
    const contexts = Object.create(null)
    let first = null
    for (const [field, expected] of Object.entries(OPERATIONS)) {
      const context = endpointContext(control, value[field], `${value.relayId}.${field}`)
      if (context.familyId !== expected.familyId || context.operationId !== expected.operationId) {
        fail('PEERIT_SEQ29_RELAY_ENDPOINT_OPERATION_MISMATCH',
          `${value.relayId}.${field} is not operation ${expected.familyId}/${expected.operationId}`)
      }
      if (!bytesEqual(context.relayPublicKey, binding.relayPublicKey) ||
          !bytesEqual(context.storeId, binding.storeId) ||
          !bytesEqual(context.durabilityContinuityHash, binding.durabilityContinuityHash)) {
        fail('PEERIT_SEQ29_RELAY_ENDPOINT_IDENTITY_MISMATCH',
          `${value.relayId}.${field} differs from the signed relay identity`)
      }
      if (context.descriptorSequence < binding.descriptorFloorSequence ||
          (context.descriptorSequence === binding.descriptorFloorSequence &&
            !bytesEqual(context.descriptorHash, binding.descriptorFloorHash))) {
        fail('PEERIT_SEQ29_RELAY_DESCRIPTOR_BELOW_FLOOR',
          `${value.relayId}.${field} is below or forks the signed descriptor floor`)
      }
      if (first != null && !sameIdentity(first, context)) {
        fail('PEERIT_SEQ29_RELAY_ENDPOINT_IDENTITY_MISMATCH',
          `${value.relayId} endpoint operations are not one authenticated descriptor identity`)
      }
      first = first || context
      contexts[field] = context
    }
    byRelayId.set(value.relayId, Object.freeze({
      relayId: value.relayId,
      binding,
      putEndpoint: value.putEndpoint,
      cellGetEndpoint: value.cellGetEndpoint,
      appendEndpoint: value.appendEndpoint,
      readEndpoint: value.readEndpoint,
      trustedDescriptor: value.trustedDescriptor || null,
      contexts: Object.freeze(contexts)
    }))
  }
  if (authority.bindings.some(binding => !byRelayId.has(binding.relayId))) {
    fail('PEERIT_SEQ29_RELAY_ENDPOINT_SET_INVALID',
      'endpoint sets do not cover both signed bootstrap bindings')
  }
  return byRelayId
}

// This authenticates routing identity only; it neither performs I/O nor mints
// a poll/publication authority. With the production control, copied endpoint
// shapes fail at verifiedEndpointContext before any URL can influence routing.
export function verifyPeeritSeq29PublicInboxRelayEndpointsV1 (input = {}) {
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(input.authority)) {
    fail('PEERIT_SEQ29_RELAY_ENDPOINT_SET_INVALID',
      'a verified public INBOX bootstrap authority is required')
  }
  const values = authenticateEndpointSets(
    input.control, input.authority, input.relayEndpoints)
  return Object.freeze([...values.values()])
}

function assertFreshQualifiedEndpointSets (
  value, expected = {}, options = {}) {
  const state = QUALIFIED_ENDPOINT_SETS.get(value)
  if (!state || (expected.authority != null && state.authority !== expected.authority) ||
      (expected.control != null && state.control !== expected.control)) {
    fail('PEERIT_SEQ29_RELAY_QUALIFICATION_REQUIRED',
      'matching module-qualified public INBOX endpoints are required')
  }
  const nowUnixMillis = currentUnixMillis(options.nowUnixMillis)
  const nowEpoch = Number(nowUnixMillis / LEASE_EPOCH_MILLIS)
  const nowMonotonicMillis = currentMonotonicMillis(options.monotonicMillis)
  if (nowEpoch >= state.descriptorExpiresEpoch ||
      nowEpoch >= state.topicExpiresEpoch ||
      nowMonotonicMillis >= state.healthExpiresAtMonotonicMillis) {
    fail('PEERIT_SEQ29_RELAY_QUALIFICATION_EXPIRED',
      'public INBOX endpoint descriptor, topic, or health qualification expired')
  }
  return value
}

export async function qualifyPeeritSeq29PublicInboxRelayEndpointsV1 (input = {}) {
  const authority = input.authority
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(authority)) {
    fail('PEERIT_SEQ29_RELAY_QUALIFICATION_REQUIRED',
      'a verified public INBOX bootstrap authority is required')
  }
  const control = assertPeeritSeq29PublicBrowserControlV1(input.control)
  if (typeof control.BlindDescriptorBootstrapHttpClient !== 'function' ||
      typeof control.BlindRelayQualifier !== 'function' ||
      typeof control.DescriptorTrustStore !== 'function' ||
      typeof control.createDescribeGetRequest !== 'function' ||
      typeof control.trustedDescriptorValidity !== 'function' ||
      typeof control.verifiedHealthValidity !== 'function' ||
      typeof control.verifiedEndpointContext !== 'function' ||
      typeof control.verifyDescriptorBytes !== 'function') {
    fail('PEERIT_SEQ29_RELAY_QUALIFICATION_REQUIRED',
      'authenticated browser control lacks bounded relay qualification')
  }
  const maximumHealthAgeMillis = control.HEALTH_QUALIFICATION_LIMITS?.maximumAgeMillis
  if (!Number.isSafeInteger(maximumHealthAgeMillis) ||
      maximumHealthAgeMillis < 1 || maximumHealthAgeMillis > 60 * 60 * 1000) {
    fail('PEERIT_SEQ29_RELAY_QUALIFICATION_REQUIRED',
      'authenticated browser control has no bounded health lease')
  }
  const runtime = input.runtime
  if (!runtime || typeof runtime.randomBytes !== 'function') {
    fail('PEERIT_SEQ29_RELAY_QUALIFICATION_REQUIRED',
      'authenticated browser crypto runtime is required')
  }
  const nowUnixMillis = currentUnixMillis(input.nowUnixMillis)
  const nowEpoch = Number(nowUnixMillis / LEASE_EPOCH_MILLIS)
  const monotonicMillis = typeof input.monotonicMillis === 'function'
    ? input.monotonicMillis
    : () => currentMonotonicMillis()
  const runtimePublicationControl = input.runtimePublicationControl
  const profile = runtimePublicationControl?.qualificationProfile || qualificationProfile()
  let fetch = null
  if (typeof input.fetch === 'function') fetch = input.fetch
  else if (typeof globalThis.fetch === 'function') fetch = globalThis.fetch.bind(globalThis)
  if (fetch == null) {
    fail('PEERIT_SEQ29_RELAY_QUALIFICATION_REQUIRED',
      'bounded relay qualification requires fetch')
  }
  let descriptorExpiresEpoch = Number.MAX_SAFE_INTEGER
  let topicExpiresEpoch = Number.MAX_SAFE_INTEGER
  let healthExpiresAtMonotonicMillis = Number.POSITIVE_INFINITY
  const supplied = []
  for (const binding of authority.bindings) {
    if (nowEpoch >= binding.allocationEpoch + 1460) {
      fail('PEERIT_SEQ29_RELAY_QUALIFICATION_EXPIRED',
        `${binding.relayId} public INBOX topic lease expired`)
    }
    topicExpiresEpoch = Math.min(topicExpiresEpoch, binding.allocationEpoch + 1460)
    const authenticatedHead = await authenticateCurrentDescriptorHead({
      control,
      runtime,
      binding,
      profile,
      nowEpoch,
      fetch,
      signal: input.signal,
      timeoutMillis: input.timeoutMillis
    })
    const qualifier = new control.BlindRelayQualifier({
      runtime,
      nowEpoch: () => nowEpoch,
      monotonicMillis,
      supportedProtocolProfiles: profile.supportedProtocolProfiles,
      supportedTransportProfiles: profile.supportedTransportProfiles,
      trustStore: authenticatedHead.trustStore,
      fetch
    })
    const candidate = Object.freeze({
      canonicalUrl: authenticatedHead.canonicalUrl,
      expectedDescriptorHash: authenticatedHead.head.descriptorHash,
      continuityRootRelayPublicKey: binding.relayPublicKey
    })
    const row = { relayId: binding.relayId }
    for (const operation of QUALIFICATION_OPERATIONS) {
      let qualified
      try {
        qualified = await qualifier.qualifyCandidate(
          candidate,
          qualificationRequirement(operation),
          { signal: input.signal, timeoutMillis: input.timeoutMillis })
      } catch (cause) {
        fail('PEERIT_SEQ29_RELAY_QUALIFICATION_FAILED',
          `${binding.relayId} ${operation.familyId}/${operation.operationId} qualification failed`, cause)
      }
      const context = endpointContext(
        control, qualified?.endpoint, `${binding.relayId}.${operation.field}`)
      if (context.descriptorSequence !== authenticatedHead.head.descriptorSequence ||
          !bytesEqual(context.descriptorHash, authenticatedHead.head.descriptorHash)) {
        fail('PEERIT_SEQ29_RELAY_DESCRIPTOR_BELOW_FLOOR',
          `${binding.relayId}.${operation.field} is not the authenticated current descriptor head`)
      }
      let descriptorValidity
      let healthValidity
      try {
        descriptorValidity = control.trustedDescriptorValidity(qualified.trustedDescriptor)
        healthValidity = control.verifiedHealthValidity(qualified.health)
      } catch (cause) {
        fail('PEERIT_SEQ29_RELAY_QUALIFICATION_FAILED',
          `${binding.relayId}.${operation.field} lacks branded validity evidence`, cause)
      }
      if (!descriptorValidity ||
          !Number.isSafeInteger(descriptorValidity.issuedEpoch) ||
          !Number.isSafeInteger(descriptorValidity.expiresEpoch) ||
          descriptorValidity.issuedEpoch > nowEpoch ||
          nowEpoch >= descriptorValidity.expiresEpoch) {
        fail('PEERIT_SEQ29_RELAY_QUALIFICATION_EXPIRED',
          `${binding.relayId}.${operation.field} descriptor lease is not current`)
      }
      const observedMonotonic = monotonicMillis()
      if (!healthValidity ||
          typeof healthValidity.verifiedAtMonotonicMillis !== 'number' ||
          typeof healthValidity.expiresAtMonotonicMillis !== 'number' ||
          healthValidity.expiresAtMonotonicMillis !==
            healthValidity.verifiedAtMonotonicMillis + maximumHealthAgeMillis ||
          observedMonotonic < healthValidity.verifiedAtMonotonicMillis ||
          observedMonotonic >= healthValidity.expiresAtMonotonicMillis) {
        fail('PEERIT_SEQ29_RELAY_QUALIFICATION_EXPIRED',
          `${binding.relayId}.${operation.field} health lease is not current`)
      }
      descriptorExpiresEpoch = Math.min(
        descriptorExpiresEpoch, descriptorValidity.expiresEpoch)
      healthExpiresAtMonotonicMillis = Math.min(
        healthExpiresAtMonotonicMillis,
        healthValidity.expiresAtMonotonicMillis)
      row[operation.field] = qualified.endpoint
      if (operation.field === 'appendEndpoint') {
        row.trustedDescriptor = qualified.trustedDescriptor
      }
    }
    supplied.push(Object.freeze(row))
  }
  const endpointSets = verifyPeeritSeq29PublicInboxRelayEndpointsV1({
    authority,
    control,
    relayEndpoints: supplied
  })
  const qualification = Object.freeze({
    endpointSets,
    descriptorExpiresEpoch,
    topicExpiresEpoch,
    healthExpiresAtMonotonicMillis
  })
  QUALIFIED_ENDPOINT_SETS.set(qualification, Object.freeze({
    authority,
    control,
    descriptorExpiresEpoch,
    topicExpiresEpoch,
    healthExpiresAtMonotonicMillis
  }))
  return qualification
}

export function mergePeeritSeq29PublicInboxPollResultsV1 (results) {
  if (!Array.isArray(results) || results.length !== 2 ||
      new Set(results.map(value => value?.relayId)).size !== 2) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_RESULT_INVALID',
      'exactly two distinct relay poll results are required')
  }
  const unique = new Map()
  for (const result of results) {
    if (!Array.isArray(result.records)) {
      fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_RESULT_INVALID',
        `${result.relayId} poll records are invalid`)
    }
    for (const record of result.records) {
      const authorPublicKey = bytes(record.authorPublicKey, 'poll authorPublicKey', 32)
      const logicalHash = bytes(record.operationBatch?.logicalHash, 'poll logicalHash', 32)
      const key = `${bytesToHex(authorPublicKey)}:${bytesToHex(logicalHash)}`
      const prior = unique.get(key)
      if (prior) {
        prior.relayIds.push(result.relayId)
        prior.appendRevisionByRelay[result.relayId] = record.appendRevision
      } else {
        unique.set(key, {
          record,
          relayIds: [result.relayId],
          appendRevisionByRelay: { [result.relayId]: record.appendRevision }
        })
      }
    }
  }
  return Object.freeze([...unique.values()].map(value => Object.freeze({
    record: value.record,
    relayIds: Object.freeze([...value.relayIds]),
    appendRevisionByRelay: Object.freeze({ ...value.appendRevisionByRelay })
  })))
}

export async function ingestPeeritSeq29PublicInboxPollResultsV1 (
  authority, results, substrateSync) {
  const syncAuthority = createPeeritSeq29PublicInboxSyncAuthorityV1({
    authority,
    substrateSync
  })
  return commitPeeritSeq29PublicInboxPollV1(syncAuthority, results)
}

function floorFor (floors, relayId) {
  const raw = floors instanceof Map ? floors.get(relayId) : floors?.[relayId]
  const value = raw == null ? 0n : (typeof raw === 'bigint' ? raw : BigInt(raw))
  if (value < 0n) {
    fail('PEERIT_SEQ29_PUBLIC_INBOX_FLOOR_INVALID', `${relayId} append floor is negative`)
  }
  return value
}

function putEvidenceByRelay (value, endpointMap) {
  if (!Array.isArray(value) || value.length !== 2) {
    fail('PEERIT_SEQ29_CELL_PUT_EVIDENCE_INVALID', 'exactly two CELL.PUT results are required')
  }
  const output = new Map()
  for (const evidence of value) {
    if (!evidence || typeof evidence.relayId !== 'string' ||
        !endpointMap.has(evidence.relayId) || output.has(evidence.relayId)) {
      fail('PEERIT_SEQ29_CELL_PUT_EVIDENCE_INVALID',
        'CELL.PUT evidence must cover each authenticated relay exactly once')
    }
    output.set(evidence.relayId, evidence)
  }
  if ([...endpointMap.keys()].some(relayId => !output.has(relayId))) {
    fail('PEERIT_SEQ29_CELL_PUT_EVIDENCE_INVALID',
      'CELL.PUT evidence does not cover both authenticated relays')
  }
  return output
}

async function verifyPutResult (state, endpointSet, evidence, readback) {
  assertVerifiedPeeritPublicInboxAnnouncementReadbackV1(readback, {
    authority: state.authority,
    binding: endpointSet.binding,
    control: state.control
  })
  const request = evidence.request
  const requestCommitment = bytes(
    evidence.requestCommitment, `${endpointSet.relayId} PUT request commitment`, 32)
  if (!request || typeof request !== 'object' || request.version !== 1 ||
      request.sizeClass !== readback.readCap.sizeClass ||
      !bytesEqual(bytes(request.storageSlot, 'PUT storageSlot', 32), readback.readCap.storageSlot) ||
      !bytesEqual(bytes(request.declaredBlobHash, 'PUT declaredBlobHash', 32),
        readback.readCap.expectedCellBlobHash)) {
    fail('PEERIT_SEQ29_CELL_PUT_EVIDENCE_INVALID',
      `${endpointSet.relayId} PUT request differs from the signed AuthorBind read capability`)
  }
  let verified
  let receipt
  try {
    verified = await state.control.verifyOperationResult({
      endpoint: endpointSet.putEndpoint,
      request,
      requestCommitment,
      resultBytes: bytes(evidence.resultBytes, `${endpointSet.relayId} PUT result`)
    })
    receipt = state.control.decodeBlindExternalProfileValueV1(
      'BlindReceiptV1', verified.snapshotBytes())
  } catch (cause) {
    fail('PEERIT_SEQ29_CELL_PUT_EVIDENCE_INVALID',
      `${endpointSet.relayId} CELL.PUT result authentication failed`, cause)
  }
  if (receipt.result !== 1 ||
      !bytesEqual(receipt.requestCommitment, requestCommitment) ||
      !bytesEqual(receipt.relayBinding.relayPublicKey, endpointSet.binding.relayPublicKey) ||
      !bytesEqual(receipt.relayBinding.storeId, endpointSet.binding.storeId) ||
      !bytesEqual(receipt.relayBinding.durabilityContinuityHash,
        endpointSet.binding.durabilityContinuityHash) ||
      !bytesEqual(receipt.cellBlobHash, readback.readCap.expectedCellBlobHash)) {
    fail('PEERIT_SEQ29_CELL_PUT_EVIDENCE_INVALID',
      `${endpointSet.relayId} CELL.PUT receipt differs from its authenticated relay and AuthorBind`)
  }
  return Object.freeze({ requestCommitment, receipt })
}

// Verifies result correlation and signed BlindReceipt identity for one PUT
// that already has a branded same-relay AuthorBind/CELL.GET readback. It does
// not mint a publication authorization; only authorizeDualAppend can do so
// after both authenticated relay rows pass.
export async function verifyPeeritSeq29CellPutReadbackEvidenceV1 (input = {}) {
  const { authority, binding, control, putEndpoint, evidence, readback } = input
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(authority) ||
      !authority.bindings.includes(binding)) {
    fail('PEERIT_SEQ29_CELL_PUT_EVIDENCE_INVALID',
      'a verified bootstrap binding is required')
  }
  return verifyPutResult(
    Object.freeze({ authority, control }),
    Object.freeze({ relayId: binding.relayId, binding, putEndpoint }),
    evidence,
    readback
  )
}

export async function settlePeeritSeq29DualAppendV1 (attempts) {
  if (!Array.isArray(attempts) || attempts.length !== 2) {
    fail('PEERIT_SEQ29_DUAL_APPEND_INCOMPLETE',
      'exactly two INBOX.APPEND attempts are required')
  }
  const settled = await Promise.allSettled(attempts)
  if (settled.some(value => value.status !== 'fulfilled')) {
    fail('PEERIT_SEQ29_DUAL_APPEND_INCOMPLETE',
      'one or both authenticated INBOX.APPEND attempts failed', undefined,
      Object.freeze(settled.map(value => value.status === 'fulfilled'
        ? Object.freeze({ ok: true, result: value.value })
        : Object.freeze({ ok: false, code: value.reason?.code || 'PEERIT_SEQ29_APPEND_FAILED' }))))
  }
  return settled.map(value => value.value)
}

function hexBytes32 (value, field) {
  if (!HEX32.test(String(value || ''))) {
    fail('PEERIT_SEQ29_PUBLICATION_INVALID', `${field} must be lowercase 32-byte hex`)
  }
  const output = new Uint8Array(32)
  for (let index = 0; index < 32; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

async function dispatchPeeritSeq29CellPut (state, endpointSet, prepared, options) {
  const response = await state.httpClient.request({
    endpoint: endpointSet.putEndpoint,
    ...prepared.wire,
    body: prepared.requestBytes,
    timeoutMillis: options.timeoutMillis,
    signal: options.signal
  })
  if (!response || response.ok !== true) {
    fail('PEERIT_SEQ29_CELL_PUT_REJECTED',
      `${endpointSet.relayId} CELL.PUT was rejected`, response?.error)
  }
  let verified
  let receiptBytes
  let receipt
  try {
    verified = await state.control.verifyOperationResult({
      endpoint: endpointSet.putEndpoint,
      request: prepared.request,
      requestCommitment: prepared.requestCommitment,
      resultBytes: response.body
    })
    receiptBytes = bytes(
      verified.snapshotBytes(), `${endpointSet.relayId} PUT receipt`)
    receipt = state.control.decodeBlindExternalProfileValueV1(
      'BlindReceiptV1', receiptBytes)
  } catch (cause) {
    fail('PEERIT_SEQ29_CELL_PUT_RESULT_INVALID',
      `${endpointSet.relayId} CELL.PUT result authentication failed`, cause)
  }
  const request = prepared.request
  const readCap = prepared.readCap
  if (receipt.version !== 1 || receipt.result !== 1 || receipt.stateRevision !== 0n ||
      receipt.leaseClass !== request.leaseClass ||
      request.version !== 1 || readCap.version !== 1 ||
      !bytesEqual(receipt.requestCommitment, prepared.requestCommitment) ||
      !bytesEqual(receipt.requestNonce, request.clientNonce) ||
      !bytesEqual(receipt.relayBinding.relayPublicKey, endpointSet.binding.relayPublicKey) ||
      !bytesEqual(receipt.relayBinding.storeId, endpointSet.binding.storeId) ||
      !bytesEqual(receipt.relayBinding.durabilityContinuityHash,
        endpointSet.binding.durabilityContinuityHash) ||
      !bytesEqual(receipt.slotCommitment, blake2b256(request.storageSlot)) ||
      !bytesEqual(receipt.cellBlobHash, request.declaredBlobHash) ||
      !bytesEqual(receipt.allocationCommitment, prepared.allocationCommitment) ||
      receipt.allocationEpoch !== request.allocationEpoch ||
      receipt.sizeClass !== request.sizeClass ||
      !bytesEqual(readCap.relayPublicKey, endpointSet.binding.relayPublicKey) ||
      !bytesEqual(readCap.storageSlot, request.storageSlot) ||
      !bytesEqual(readCap.expectedCellBlobHash, request.declaredBlobHash) ||
      readCap.sizeClass !== request.sizeClass) {
    fail('PEERIT_SEQ29_CELL_PUT_RESULT_INVALID',
      `${endpointSet.relayId} CELL.PUT receipt differs from its exact request and relay`)
  }
  return Object.freeze({
    relayId: endpointSet.relayId,
    request,
    requestBytes: prepared.requestBytes.slice(),
    requestCommitment: prepared.requestCommitment.slice(),
    readCap,
    allocationCommitment: prepared.allocationCommitment.slice(),
    resultBytes: bytes(response.body, `${endpointSet.relayId} PUT result`).slice(),
    receiptBytes: receiptBytes.slice(),
    receipt
  })
}

function storedRelay (intent, relayId) {
  const value = intent.relays.find(row => row.relayId === relayId)
  if (!value) {
    fail('PEERIT_SEQ29_PUBLICATION_RECOVERY_INVALID',
      `${relayId} is absent from the durable dual-APPEND intent`)
  }
  return value
}

async function runPeeritSeq29PublicationIntent (
  state, endpointState, authorPublicKey, intent, options = {}) {
  const endpointMap = endpointState.endpointMap
  for (const endpointSet of endpointMap.values()) {
    let current = await getPeeritSeq29PublicationIntentV1(
      state.syncAuthority, authorPublicKey, intent.logicalHash)
    const relay = storedRelay(current, endpointSet.relayId)
    if (relay.stage === 'succeeded') continue
    const now = state.substrateSync.clock()
    const attemptToken = `${endpointSet.relayId}:${bytesToHex(randomBytes(
      state.runtime, 16, 'publication recovery attempt token'))}`
    const claimed = await claimPeeritSeq29PublicationRelayV1(state.syncAuthority, {
      authorPublicKey,
      logicalHash: current.logicalHash,
      relayId: endpointSet.relayId,
      attemptToken,
      now,
      leaseUntil: now + 60_000
    })
    if (!claimed.claimed) continue
    current = claimed.intent
    const durable = storedRelay(current, endpointSet.relayId)
    let prepared
    try {
      prepared = await restorePeeritPublicInboxAnnouncementV1({
        authority: state.authority,
        binding: endpointSet.binding,
        control: state.control,
        runtime: state.runtime,
        frame: durable.frame,
        request: durable.request,
        requestBytes: durable.requestBytes,
        requestCommitment: durable.requestCommitment
      })
      if (claimed.action === 'reconciling') {
        const reconciled = await reconcilePeeritPublicInboxAnnouncementV1({
          prepared,
          control: state.control,
          runtime: state.runtime,
          endpoint: endpointSet.readEndpoint,
          httpClient: state.httpClient,
          timeoutMillis: options.timeoutMillis,
          signal: options.signal
        })
        if (reconciled.present) {
          await completePeeritSeq29PublicationRelayV1(state.syncAuthority, {
            authorPublicKey,
            logicalHash: current.logicalHash,
            relayId: endpointSet.relayId,
            attemptToken,
            now: state.substrateSync.clock(),
            result: Object.freeze({
              recovered: true,
              appendRevision: String(reconciled.appendRevision),
              snapshotRevision: String(reconciled.snapshotRevision),
              requestCommitment: bytesToHex(reconciled.requestCommitment)
            })
          })
          continue
        }
        await markPeeritSeq29PublicationRelayAbsentV1(state.syncAuthority, {
          authorPublicKey,
          logicalHash: current.logicalHash,
          relayId: endpointSet.relayId,
          attemptToken,
          now: state.substrateSync.clock()
        })
      }
      const result = await publishPeeritPublicInboxAnnouncementV1({
        prepared,
        control: state.control,
        runtime: state.runtime,
        endpoint: endpointSet.appendEndpoint,
        httpClient: state.httpClient,
        timeoutMillis: options.timeoutMillis,
        signal: options.signal
      })
      await completePeeritSeq29PublicationRelayV1(state.syncAuthority, {
        authorPublicKey,
        logicalHash: current.logicalHash,
        relayId: endpointSet.relayId,
        attemptToken,
        now: state.substrateSync.clock(),
        result: Object.freeze({
          recovered: false,
          appendRevision: String(result.appendRevision),
          storedAtEpoch: result.storedAtEpoch,
          expiresAtEpoch: result.expiresAtEpoch,
          requestCommitment: bytesToHex(result.requestCommitment)
        })
      })
    } catch (error) {
      try {
        await failPeeritSeq29PublicationRelayV1(state.syncAuthority, {
          authorPublicKey,
          logicalHash: current.logicalHash,
          relayId: endpointSet.relayId,
          attemptToken,
          now: state.substrateSync.clock(),
          errorCode: error?.code
        })
      } catch {}
      throw error
    }
  }
  return getPeeritSeq29PublicationIntentV1(
    state.syncAuthority, authorPublicKey, intent.logicalHash)
}

export async function createPeeritSeq29PublicInboxBootCoordinatorV1 (input = {}) {
  const runtimeAssembly = getVerifiedPeeritBrowserRuntimeAssembly(input.runtimeAuthority)
  if (input.runtimeAppBinding !== runtimeAssembly) {
    fail('PEERIT_SEQ29_RUNTIME_APP_BINDING_REQUIRED',
      'the exact already-authenticated runtime/app binding is required')
  }
  for (const field of [
    'appArtifactBytes', 'bootstrapBytes', 'relayEndpoints', 'profileValidator'
  ]) {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      fail('PEERIT_SEQ29_RUNTIME_AUTHORITY_INJECTION',
        `${field} cannot be supplied to the public INBOX coordinator`)
    }
  }
  // Only the exact signature-verifying, validation-only helper owned by the
  // branded runtime/app assembly crosses this boundary. It is explicitly not
  // a production/contextual validator. Acceptance remains the branded
  // same-relay CELL.GET/intrinsic readback below.
  const profileValidator = runtimeAssembly.seq29ValidationOnlyProfileValidator
  if (runtimeAssembly.validatorInstantiationAuthorized !== false ||
      runtimeAssembly.seq29ValidationOnlyValidatorInstantiationAuthorized !== true ||
      !profileValidator || typeof profileValidator.validate !== 'function' ||
      profileValidator.authorityClass !==
        'PEERIT_SEQ29_AUTHENTICATED_VALIDATION_ONLY_V1' ||
      profileValidator.productionValidator !== false ||
      profileValidator.productionTrustedExternalAuthority !== false ||
      profileValidator.signatureVerificationRequired !== true ||
      profileValidator.contextualValidationPerformed !== false ||
      runtimeAssembly.publicInboxContextualAcceptanceAuthority !==
        'peerit-seq29-public-inbox-readback-v1') {
    fail('PEERIT_SEQ29_PROFILE_VALIDATOR_AUTHORITY_UNAVAILABLE',
      'the authenticated runtime/app binding has no bounded pre-readback validator')
  }
  const control = runtimeAssembly.control
  const runtimePublicationControl = runtimeAssembly.seq29PublicationControl
  if (!runtimePublicationControl ||
      typeof runtimePublicationControl.createDualCellReplicasV1 !== 'function' ||
      typeof runtimePublicationControl.prepareAppendV1 !== 'function') {
    fail('PEERIT_SEQ29_PUBLICATION_CONTROL_UNAVAILABLE',
      'the authenticated runtime/app binding has no frozen-profile publication controller')
  }
  const runtimeClock = runtimeAssembly.runtimeClock
  if (!runtimeClock || typeof runtimeClock.unixMillis !== 'function' ||
      typeof runtimeClock.monotonicMillis !== 'function') {
    fail('PEERIT_SEQ29_RUNTIME_CLOCK_REQUIRED',
      'the authenticated runtime/app binding has no monotonic clock authority')
  }
  const retained = getVerifiedPeeritBrowserPublicInboxBootstrapV1(
    input.runtimeAuthority)
  const appArtifactBytes = bytes(retained.appArtifactBytes, 'app artifact')
  if (!bytesEqual(hashPeeritAppArtifactV1(appArtifactBytes),
    runtimeAssembly.verifiedPin.pin.appArtifactHash)) {
    fail('PEERIT_SEQ29_APP_ARTIFACT_HASH_MISMATCH',
      'the app artifact does not match the authenticated runtime pin')
  }
  const appArtifact = parseJson(appArtifactBytes, 'app artifact')
  releaseSequence(input.runtimeAuthority.releaseSequence, 'runtime authority')
  releaseSequence(runtimeAssembly.verifiedPin.pin.releaseSequence, 'runtime pin')
  releaseSequence(appArtifact.releaseSequence, 'app artifact')

  const bootstrapBytes = bytes(
    retained.bootstrapBytes, 'signed public INBOX bootstrap')
  const bootstrapSha256 = await hashBytes(bootstrapBytes)
  if (appArtifact.schema !== 'peerit-app-artifact-v1' ||
      appArtifact.peeritLimitedPublicInboxBootstrap !==
        PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1 ||
      appArtifact.peeritLimitedPublicInboxBootstrapSha256 !== bootstrapSha256 ||
      !HEX32.test(String(appArtifact.peeritLimitedPublicInboxBootstrapAuthorityPublicKey || '')) ||
      appArtifact.peeritLimitedPublicInboxBootstrapReleaseSequence !==
        PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1 ||
      retained.verification.authorityPublicKey !==
        appArtifact.peeritLimitedPublicInboxBootstrapAuthorityPublicKey ||
      retained.verification.expectedArtifactHash !== bootstrapSha256 ||
      appArtifact.files?.[PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH_V1.slice(1)] !== bootstrapSha256 ||
      !HEX32.test(String(appArtifact.files?.[COORDINATOR_PATH] || ''))) {
    fail('PEERIT_SEQ29_BOOTSTRAP_APP_BINDING_MISMATCH',
      'the authenticated app artifact does not bind these bootstrap bytes and the shipped coordinator')
  }
  const wrapper = parseJson(bootstrapBytes, 'signed public INBOX bootstrap')
  const substrateSync = assertPeeritSubstrateSyncV1(input.substrateSync)
  const productAuthoring = input.productRuntime == null
    ? null
    : getPeeritProductSeq29AuthoringAuthorityV1(input.productRuntime)
  if (productAuthoring && productAuthoring.substrateSync !== substrateSync) {
    fail('PEERIT_SEQ29_PRODUCT_SYNC_MISMATCH',
      'shipped product authoring and public INBOX coordinator must share one journal')
  }
  const persistedBootstrapFloor = await getPeeritSeq29PublicInboxBootstrapFloorV1(
    substrateSync,
    appArtifact.peeritLimitedPublicInboxBootstrapAuthorityPublicKey)
  const authority = await verifyPeeritLimitedPublicInboxBootstrapV1({
    wrapper,
    control,
    referenceUnixMillis: runtimeClock.unixMillis(),
    expectedAuthorityPublicKey:
      appArtifact.peeritLimitedPublicInboxBootstrapAuthorityPublicKey,
    floor: persistedBootstrapFloor
  })
  releaseSequence(authority.releaseSequence, 'verified public INBOX bootstrap')
  const syncAuthority = createPeeritSeq29PublicInboxSyncAuthorityV1({
    authority,
    substrateSync
  })
  const persistedBootstrap = await acceptPeeritSeq29PublicInboxBootstrapV1(syncAuthority)
  const runtime = control.createBrowserCryptoRuntime()
  const httpClient = input.httpClient || new control.BlindDirectHttpClient({ runtime })
  if (!httpClient || typeof httpClient.request !== 'function') {
    fail('PEERIT_SEQ29_DIRECT_HTTP_CLIENT_REQUIRED', 'a direct HTTP client is required')
  }
  const state = Object.freeze({
    authority,
    control,
    runtime,
    profileValidator,
    httpClient,
    substrateSync,
    syncAuthority,
    productAuthoring,
    runtimePublicationControl,
    bootstrapExpiresUnixMillis: BigInt(wrapper.payload.expiresUnixMillis)
  })
  let qualification = await qualifyPeeritSeq29PublicInboxRelayEndpointsV1({
    authority,
    control,
    runtime,
    fetch: input.fetch,
    signal: input.signal,
    timeoutMillis: input.timeoutMillis,
    nowUnixMillis: runtimeClock.unixMillis(),
    monotonicMillis: runtimeClock.monotonicMillis,
    runtimePublicationControl
  })
  const qualificationInput = options => Object.freeze({
    authority,
    control,
    runtime,
    fetch: input.fetch,
    signal: options.signal,
    timeoutMillis: options.timeoutMillis,
    nowUnixMillis: options.nowUnixMillis,
    monotonicMillis: runtimeClock.monotonicMillis,
    runtimePublicationControl
  })
  const currentEndpoints = async (options = {}) => {
    const nowUnixMillis = currentUnixMillis(options.nowUnixMillis)
    if (nowUnixMillis >= state.bootstrapExpiresUnixMillis) {
      fail('PEERIT_SEQ29_PUBLIC_INBOX_BOOTSTRAP_EXPIRED',
        'signed public INBOX bootstrap lifetime expired')
    }
    try {
      assertFreshQualifiedEndpointSets(qualification, { authority, control }, {
        nowUnixMillis,
        monotonicMillis: runtimeClock.monotonicMillis
      })
    } catch (error) {
      if (error?.code !== 'PEERIT_SEQ29_RELAY_QUALIFICATION_EXPIRED') throw error
      qualification = await qualifyPeeritSeq29PublicInboxRelayEndpointsV1(
        qualificationInput({ ...options, nowUnixMillis }))
    }
    return Object.freeze({
      qualification,
      endpointMap: new Map(
        qualification.endpointSets.map(value => [value.relayId, value]))
    })
  }
  let pollActive = false
  let publicationActive = false

  const publishAuthorized = async (authorization, options = {}) => {
    const proof = AUTHORIZATIONS.get(authorization)
    if (!proof || proof.state !== state || CONSUMED_AUTHORIZATIONS.has(authorization)) {
      fail('PEERIT_SEQ29_DUAL_APPEND_NOT_AUTHORIZED',
        'a fresh dual CELL.PUT/AuthorBind readback authorization is required')
    }
    for (const field of ['admissionByRelayId', 'admissionProviderByRelayId']) {
      if (Object.prototype.hasOwnProperty.call(options, field)) {
        fail('PEERIT_SEQ29_RUNTIME_AUTHORITY_INJECTION',
          `${field} cannot be supplied to the runtime-owned APPEND path`)
      }
    }
    const nowUnixMillis = runtimeClock.unixMillis()
    if (nowUnixMillis >= state.bootstrapExpiresUnixMillis) {
      fail('PEERIT_SEQ29_PUBLIC_INBOX_BOOTSTRAP_EXPIRED',
        'signed public INBOX bootstrap lifetime expired')
    }
    assertFreshQualifiedEndpointSets(
      proof.qualification, { authority, control }, {
        nowUnixMillis,
        monotonicMillis: runtimeClock.monotonicMillis
      })
    const announcement = profileValidator.validate(
      'PeeritAnnouncementV1', proof.announcementBytes).value
    const authorBind = profileValidator.validate(
      'AuthorBindV1', announcement.manifestRecord).value
    const authorPublicKey = bytesToHex(authorBind.authorPublicKey)
    const endpointSets = [...proof.endpointMap.values()]
    const prepared = []
    for (const endpointSet of endpointSets) {
      prepared.push(await runtimePublicationControl.prepareAppendV1({
        authority,
        binding: endpointSet.binding,
        relayId: endpointSet.relayId,
        endpoint: endpointSet.appendEndpoint,
        trustedDescriptor: endpointSet.trustedDescriptor,
        control,
        runtime,
        httpClient,
        nowEpoch: Number(nowUnixMillis / LEASE_EPOCH_MILLIS),
        announcementBytes: proof.announcementBytes,
        timeoutMillis: options.timeoutMillis,
        signal: options.signal
      }))
    }
    if (bytesEqual(prepared[0].frame, prepared[1].frame) ||
        bytesEqual(prepared[0].requestCommitment, prepared[1].requestCommitment)) {
      fail('PEERIT_SEQ29_DUAL_APPEND_RANDOMNESS_REUSE',
        'dual INBOX.APPEND attempts must have independent frames and request commitments')
    }
    const committed = await commitPeeritSeq29PublicationIntentV1(
      state.syncAuthority, {
        authorPublicKey,
        logicalHash: bytesToHex(authorBind.logicalHash),
        intentId: options.intentId,
        authorSequence: authorBind.authorSequence,
        previousAuthorRecordId: authorBind.previousAuthorRecordId == null
          ? null
          : bytesToHex(authorBind.previousAuthorRecordId),
        authorRecordId: bytesToHex(announcement.manifestRecordId),
        announcementBytes: proof.announcementBytes,
        relays: prepared.map((value, index) => Object.freeze({
          relayId: endpointSets[index].relayId,
          frame: value.frame,
          request: value.request,
          requestBytes: value.requestBytes,
          requestCommitment: value.requestCommitment
        })),
        createdAt: substrateSync.clock()
      })
    const finished = await runPeeritSeq29PublicationIntent(
      state,
      Object.freeze({ qualification: proof.qualification, endpointMap: proof.endpointMap }),
      authorPublicKey,
      committed.intent,
      options
    )
    if (finished.completedAt > 0) CONSUMED_AUTHORIZATIONS.add(authorization)
    return Object.freeze({
      duplicate: committed.duplicate,
      completed: finished.completedAt > 0,
      relayResults: Object.freeze(finished.relays.map(relay => Object.freeze({
        relayId: relay.relayId,
        stage: relay.stage,
        result: relay.result
      })))
    })
  }

  const publishAuthored = async (publication, options = {}) => {
    if (!productAuthoring) {
      fail('PEERIT_SEQ29_PRODUCT_AUTHORING_REQUIRED',
        'the shipped product runtime is required for authored publication')
    }
    const authorPublicKeyBytes = await productAuthoring.authorPublicKey()
    const authorPublicKey = bytesToHex(authorPublicKeyBytes)
    const existing = await getPeeritSeq29PublicationIntentV1(
      state.syncAuthority, authorPublicKey, publication.logicalHash)
    const endpointState = await currentEndpoints({
      ...options,
      nowUnixMillis: runtimeClock.unixMillis()
    })
    if (existing) {
      return runPeeritSeq29PublicationIntent(
        state, endpointState, authorPublicKey, existing, options)
    }
    let decoded
    try {
      decoded = await decodePeeritInnerOperationBatchV1(
        publication.innerCodec,
        publication.innerBytes,
        { expectedAuthorPublicKey: authorPublicKey }
      )
    } catch (cause) {
      fail('PEERIT_SEQ29_LOCAL_AUTHORED_INTENT_INVALID',
        'ordinary authored intent lacks the active product author authority', cause)
    }
    if (decoded.innerLength !== BigInt(publication.innerLength) ||
        !bytesEqual(decoded.logicalHash, publication.logicalHash) ||
        !bytesEqual(decoded.encodingCommitment, publication.encodingCommitment) ||
        decoded.sizeClass !== publication.sizeClass) {
      fail('PEERIT_SEQ29_LOCAL_AUTHORED_INTENT_INVALID',
        'ordinary authored intent changed before Seq29 publication')
    }
    const authorHead = await getPeeritSeq29PublicationAuthorHeadV1(
      state.syncAuthority, authorPublicKey)
    const nowUnixMillis = runtimeClock.unixMillis()
    const allocationEpoch = Number(nowUnixMillis / LEASE_EPOCH_MILLIS)
    const endpointSets = [...endpointState.endpointMap.values()]
    const preparedPuts = await runtimePublicationControl.createDualCellReplicasV1({
      rows: endpointSets.map(endpointSet => Object.freeze({
        relayId: endpointSet.relayId,
        binding: endpointSet.binding,
        endpoint: endpointSet.putEndpoint,
        trustedDescriptor: endpointSet.trustedDescriptor,
        runtime,
        httpClient,
        nowEpoch: allocationEpoch,
        allocationEpoch,
        timeoutMillis: options.timeoutMillis,
        signal: options.signal,
        publication
      }))
    })
    const putEvidence = await Promise.all(endpointSets.map((endpointSet, index) =>
      dispatchPeeritSeq29CellPut(
        state, endpointSet, preparedPuts[index], options)))
    const signed = await profileValidator.createSignedInlineAuthorBindPublicationV1({
      publication,
      replicas: putEvidence,
      authorPublicKey: authorPublicKeyBytes,
      authorSequence: authorHead.nextAuthorSequence,
      previousAuthorRecordId: authorHead.previousAuthorRecordId == null
        ? null
        : hexBytes32(authorHead.previousAuthorRecordId, 'previous AuthorBind record ID'),
      publishedLeaseEpoch: allocationEpoch,
      signAuthorBindV1: prefix => productAuthoring.signAuthorBindV1(prefix),
      signPeeritAnnouncementV1: prefix =>
        productAuthoring.signPeeritAnnouncementV1(prefix)
    })
    const authorization = await coordinator.authorizeDualAppend({
      announcementBytes: signed.announcementBytes,
      putEvidence,
      timeoutMillis: options.timeoutMillis,
      signal: options.signal
    })
    return publishAuthorized(authorization, {
      intentId: publication.intentId,
      timeoutMillis: options.timeoutMillis,
      signal: options.signal
    })
  }

  const coordinator = Object.freeze({
    version: 1,
    releaseSequence: PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
    bootstrapFloor: persistedBootstrap.bootstrapFloor,
    relayIds: Object.freeze(authority.bindings.map(value => value.relayId)),

    async pollAndIngest (options = {}) {
      if (pollActive) {
        fail('PEERIT_SEQ29_PUBLIC_INBOX_POLL_OVERLAP',
          'a dual public INBOX poll is already in progress')
      }
      pollActive = true
      try {
        const { endpointMap } = await currentEndpoints({
          ...options,
          nowUnixMillis: runtimeClock.unixMillis()
        })
        const floors = await getPeeritSeq29PublicInboxAppendFloorsV1(state.syncAuthority)
        const results = await Promise.all([...endpointMap.values()].map(endpointSet =>
          pollPeeritPublicInboxBindingV1({
            authority,
            binding: endpointSet.binding,
            control,
            runtime,
            readEndpoint: endpointSet.readEndpoint,
            cellEndpoint: endpointSet.cellGetEndpoint,
            httpClient,
            profileValidator,
            floor: floorFor(floors, endpointSet.relayId),
            limit: options.limit,
            nowUnixMillis: runtimeClock.unixMillis(),
            timeoutMillis: options.timeoutMillis,
            signal: options.signal
          })))
        const ingested = await commitPeeritSeq29PublicInboxPollV1(
          state.syncAuthority, results)
        return Object.freeze({
          ingestedBatchCount: ingested.ingestedBatchCount,
          relayResults: Object.freeze(results),
          floors: ingested.appendFloors
        })
      } finally {
        pollActive = false
      }
    },

    async authorizeDualAppend (options = {}) {
      const nowUnixMillis = runtimeClock.unixMillis()
      const endpointState = await currentEndpoints({ ...options, nowUnixMillis })
      const { endpointMap } = endpointState
      const announcementBytes = bytes(options.announcementBytes, 'signed announcement')
      const evidence = putEvidenceByRelay(options.putEvidence, endpointMap)
      const verifiedRows = await Promise.all([...endpointMap.values()].map(async endpointSet => {
        const readback = await verifyPeeritPublicInboxAnnouncementReadbackV1({
          authority,
          binding: endpointSet.binding,
          control,
          runtime,
          cellEndpoint: endpointSet.cellGetEndpoint,
          announcementBytes,
          httpClient,
          profileValidator,
          nowUnixMillis,
          timeoutMillis: options.timeoutMillis,
          signal: options.signal
        })
        const put = await verifyPutResult(
          state, endpointSet, evidence.get(endpointSet.relayId), readback)
        return Object.freeze({ relayId: endpointSet.relayId, readback, put })
      }))
      const first = verifiedRows[0].readback
      const second = verifiedRows[1].readback
      if (!bytesEqual(first.authorBind.authorPublicKey, second.authorBind.authorPublicKey) ||
          !bytesEqual(first.operationBatch.logicalHash, second.operationBatch.logicalHash) ||
          first.operationBatch.innerLength !== second.operationBatch.innerLength) {
        fail('PEERIT_SEQ29_DUAL_READBACK_MISMATCH',
          'the two authenticated readbacks do not bind one intrinsic operation batch')
      }
      const authorization = Object.freeze({
        version: 1,
        relayIds: Object.freeze(verifiedRows.map(value => value.relayId)),
        logicalHash: first.operationBatch.logicalHash.slice()
      })
      AUTHORIZATIONS.set(authorization, Object.freeze({
        state,
        qualification: endpointState.qualification,
        endpointMap,
        announcementBytes: announcementBytes.slice()
      }))
      return authorization
    },

    async publishDual (options = {}) {
      return publishAuthorized(options.authorization, options)
    },

    async resumeAuthoredPublication (options = {}) {
      if (!productAuthoring) {
        fail('PEERIT_SEQ29_PRODUCT_AUTHORING_REQUIRED',
          'the shipped product runtime is required for publication recovery')
      }
      if (publicationActive) {
        fail('PEERIT_SEQ29_PUBLICATION_OVERLAP',
          'a Seq29 authored publication pass is already in progress')
      }
      publicationActive = true
      try {
        const authorPublicKey = bytesToHex(await productAuthoring.authorPublicKey())
        return await productAuthoring.withSeq29PublicationSession(async () => {
          const logicalHash = typeof options.logicalHash === 'string'
            ? options.logicalHash
            : bytesToHex(options.logicalHash)
          const pending = await getPeeritSeq29PublicationIntentV1(
            state.syncAuthority, authorPublicKey, logicalHash)
          if (!pending) {
            fail('PEERIT_SEQ29_PUBLICATION_RECOVERY_INVALID',
              'the exact durable authored publication is unavailable')
          }
          const endpointState = await currentEndpoints({
            ...options,
            nowUnixMillis: runtimeClock.unixMillis()
          })
          return runPeeritSeq29PublicationIntent(
            state, endpointState, authorPublicKey, pending, options)
        })
      } finally {
        publicationActive = false
      }
    },

    async publishAuthoredIntent (options = {}) {
      if (!productAuthoring) {
        fail('PEERIT_SEQ29_PRODUCT_AUTHORING_REQUIRED',
          'the shipped product runtime is required for authored publication')
      }
      if (publicationActive) {
        fail('PEERIT_SEQ29_PUBLICATION_OVERLAP',
          'a Seq29 authored publication pass is already in progress')
      }
      publicationActive = true
      try {
        await productAuthoring.authorPublicKey()
        return await productAuthoring.withSeq29PublicationSession(async () => {
          const publication = await getPeeritSeq29LocalAuthoredPublicationV1(
            state.syncAuthority, options.intentId)
          return publishAuthored(publication, options)
        })
      } finally {
        publicationActive = false
      }
    }
  })
  return coordinator
}
