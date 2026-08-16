// Production qualification and module-private composition bridge for the two
// Seq29 INBOX.CREATE ceremony targets. The exported qualification authenticates
// the accepted immutable HiveRelay artifacts, signed Seq29 seed reissue, frozen
// signed-profile bytes and each relay's current descriptor chain, health and
// admission parameters. Its opaque authority exposes no CREATE request,
// token-spend, transport or lifecycle method; only this module's private
// WeakMap can carry the branded endpoints into the Node-only composition.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  canonicalPeeritLimitedPublicInboxJsonV1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  verifyPeeritLimitedCellPutProfileV1
} from '../js/substrate/limited-cell-put-profile.mjs'
import {
  asBytes,
  bytesEqual,
  bytesToHex,
  hexToBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  verifyPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1,
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1,
  PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  createPeeritSeq29LimitedInboxCeremonyAuthorityV1,
  dryRunPeeritLimitedInboxTopicCeremonyV1,
  peeritLimitedInboxTopicCeremonyPlanHashV1,
  validatePeeritLimitedInboxTopicCeremonyPlanV1
} from './limited-inbox-topic-ceremony.mjs'
import {
  createPeeritSeq29LiveInboxCeremonyConductorV1
} from './seq29-live-inbox-ceremony-conductor.mjs'
import {
  createPeeritSeq29FilesystemAttemptJournalV1,
  verifyPeeritSeq29FilesystemAttemptBindingV1
} from './lib/seq29-live-ceremony-journal.mjs'
import {
  createPeeritSeq29LocalManagementCustodyV1
} from './lib/seq29-local-management-custody.mjs'
import {
  createPeeritSeq29LocalCustodianKeyFileConfigurationV1
} from './lib/seq29-local-custodian-key-files.mjs'
import {
  createPeeritSeq29InboxCreateAdmissionAuthorityV1
} from './lib/seq29-live-inbox-create-admission.mjs'
import {
  loadPeeritSeq29AcceptedHiveRelayOperatorV1
} from './lib/seq29-accepted-hiverelay-operator.mjs'
import {
  preparePeeritSeq29OfflineInboxCreateRequestsV1,
  sealPeeritSeq29LiveInboxCreatePreNetworkCustodyV1,
  snapshotPeeritSeq29OfflineInboxCreatePreparationV1,
  verifyPeeritSeq29LiveInboxCreatePreNetworkCustodyV1
} from './lib/seq29-live-inbox-create-pre-network-custody.mjs'

export const PEERIT_SEQ29_CREATE_QUALIFICATION_SCHEMA_V1 =
  'peerit-seq29-live-inbox-create-qualification-v1'
export const PEERIT_SEQ29_CREATE_PLAN_SNAPSHOT_SCHEMA_V1 =
  'peerit-seq29-live-inbox-create-plan-snapshot-v1'
export const PEERIT_SEQ29_CREATE_PLAN_CONTINUITY_SCHEMA_V1 =
  'peerit-seq29-live-inbox-create-plan-continuity-v1'
export const PEERIT_SEQ29_ACCEPTED_HIVERELAY_TREE_V1 =
  '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'
export const PEERIT_SEQ29_SEED_AUTHORITY_PUBLIC_KEY_V1 =
  '691d524a1c2ac38de86ed592fbae6f9a906770b96fe704d3c63397a23171f6ec'
export const PEERIT_SEQ29_ACCEPTED_SEED_PREDECESSOR_SHA256_V1 =
  'f25f2eb3ac285294d823d7e58019b79906f5ea5ebbd7ff59dbf7fcf74751c556'
export const PEERIT_SEQ29_ACCEPTED_LIMITED_CELL_PUT_PROFILE_SHA256_V1 =
  'f809a8678b94198324dc0c231f10c677269578aded83a257b2bc58db2f1720f9'
export const PEERIT_SEQ29_ACCEPTED_BROWSER_CONTROL_SHA256_V1 =
  '88e51864c4a21296e64864523a7d602a1df6e24beed7dbbed45690c05eb1902f'
export const PEERIT_SEQ29_ACCEPTED_BROWSER_CONTROL_AUTHORITY_SHA256_V1 =
  '85909a01ac34e5fc374a81a7bc9a95c8b36f96665b6d04e0bf67d6c437017260'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const RELEASE_SEQUENCE = 29
const PROFILE_RELEASE_SEQUENCE = 28
const EPOCH_MILLIS = 21_600_000
const MAX_DESCRIPTOR_HISTORY = 4096
const MAX_TIMEOUT_MILLIS = 15_000
const DESCRIBE_MEDIA_TYPE = 'application/vnd.hiverelay.blind-v1'
const DESCRIBE_OUTER_CLASS = 3
const DESCRIBE_OUTER_BYTES = 65_536
const DESCRIBE_HEADER_BYTES = 45
const DESCRIBE_RESULT_LIMIT = 16_384
const HEX32 = /^[0-9a-f]{64}$/
const QUALIFICATIONS = new WeakMap()
const RELEASE_PREPARATIONS = new WeakMap()
const DECODER = new TextDecoder('utf-8', { fatal: true })
const CREATE_ADMISSION_PROFILE = Object.freeze({
  profileId: 3,
  admissionProfileId: 3,
  schemeId: 1,
  conformanceClass: 1,
  roleBits: 49
})
const EXACT_SOURCE_E2E_FIXTURE_ENV =
  'PEERIT_SEQ29_CREATE_EXACT_SOURCE_E2E_TEST'

function fail (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_CREATE_QUALIFICATION_INVALID',
      `${field} fields are missing or unexpected`)
  }
  return value
}

function exactWithOptional (value, required, optional, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('PEERIT_SEQ29_CREATE_QUALIFICATION_INVALID', `${field} must be an object`)
  }
  const allowed = new Set([...required, ...optional])
  if (required.some(key => !Object.prototype.hasOwnProperty.call(value, key)) ||
      Object.keys(value).some(key => !allowed.has(key))) {
    fail('PEERIT_SEQ29_CREATE_QUALIFICATION_INVALID',
      `${field} fields are missing or unexpected`)
  }
  return value
}

function bytes (value, field, length = null) {
  let output
  try { output = new Uint8Array(asBytes(value, field)) } catch (cause) {
    fail('PEERIT_SEQ29_CREATE_QUALIFICATION_INVALID', `${field} must be bytes`, cause)
  }
  if (length != null && output.byteLength !== length) {
    fail('PEERIT_SEQ29_CREATE_QUALIFICATION_INVALID', `${field} must be ${length} bytes`)
  }
  return output
}

function hex32 (value, field) {
  if (typeof value !== 'string' || !HEX32.test(value)) {
    fail('PEERIT_SEQ29_CREATE_PLAN_INVALID', `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`
  return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`
}

function immutableSeedProjection (payload) {
  return Object.fromEntries(Object.entries(payload).filter(([key]) =>
    !['releaseSequence', 'issuedAt', 'expiresAt'].includes(key)))
}

function isExactLoopbackFixtureDescribeUrl (value) {
  let url
  try { url = new URL(value) } catch { return false }
  return url.protocol === 'https:' && url.hostname === '127.0.0.1' &&
    /^[1-9][0-9]{3,4}$/.test(url.port) && Number(url.port) <= 65535 &&
    url.pathname === '/api/blind/v1/describe' && url.username === '' &&
    url.password === '' && url.search === '' && url.hash === ''
}

async function authenticateReleaseInputs (
  seedBytesValue,
  profileBytesValue,
  nowUnixMillis,
  fixture
) {
  const seedBytes = bytes(seedBytesValue, 'Seq29 seed bootstrap')
  const profileBytes = bytes(profileBytesValue, 'limited Cell-PUT profile')
  const profileSha256 = sha256(profileBytes)
  const fixtureOnly = fixture != null
  if (fixtureOnly) {
    exact(fixture, ['allowFixture', 'seedAuthorityPublicKey'],
      'exact-source E2E fixture authority')
    if (process.env[EXACT_SOURCE_E2E_FIXTURE_ENV] !== '1' ||
        fixture.allowFixture !== true ||
        typeof fixture.seedAuthorityPublicKey !== 'string' ||
        !HEX32.test(fixture.seedAuthorityPublicKey)) {
      fail('PEERIT_SEQ29_CREATE_FIXTURE_FORBIDDEN',
        'exact-source E2E fixture authority is disabled')
    }
  } else if (profileSha256 !==
      PEERIT_SEQ29_ACCEPTED_LIMITED_CELL_PUT_PROFILE_SHA256_V1) {
    fail('PEERIT_SEQ29_CREATE_PROFILE_MISMATCH',
      'limited Cell-PUT profile is not the exact accepted signed-release asset')
  }
  const profile = verifyPeeritLimitedCellPutProfileV1(profileBytes, {
    releaseSequence: PROFILE_RELEASE_SEQUENCE
  })

  const seedSha256 = sha256(seedBytes)
  const seed = await verifyPeeritSeedBootstrapV1(seedBytes, {
    authorityPublicKey: fixtureOnly
      ? fixture.seedAuthorityPublicKey
      : PEERIT_SEQ29_SEED_AUTHORITY_PUBLIC_KEY_V1,
    releaseSequence: RELEASE_SEQUENCE,
    expectedArtifactHash: seedSha256,
    previousBootstrapHash: null,
    now: nowUnixMillis
  })
  if (seed.payload.bootstrapSequence !== 0 || seed.payload.previousBootstrapHash !== null ||
      seed.payload.records.length !== (fixtureOnly ? 1 : 39) ||
      seed.payload.relays.length !== 2) {
    fail('PEERIT_SEQ29_CREATE_SEED_MISMATCH',
      'Seq29 seed is not the exact release-terminal source-zero two-relay shape')
  }

  if (fixtureOnly) {
    if (seed.payload.relays.some((relay, index) =>
      relay.relayId !== ['dal-1', 'syd-1'][index] ||
      !isExactLoopbackFixtureDescribeUrl(relay.canonicalDescribeUrl)) ||
        new Set(seed.payload.relays.map(relay =>
          new URL(relay.canonicalDescribeUrl).origin)).size !== 2) {
      fail('PEERIT_SEQ29_CREATE_FIXTURE_FORBIDDEN',
        'exact-source E2E fixture relays must use two distinct strict IPv4 loopback origins')
    }
  } else {
    const predecessorBytes = new Uint8Array(readFileSync(resolve(
      ROOT, 'deploy/peerit-seed-bootstrap-v1-seq28.json')))
    if (sha256(predecessorBytes) !== PEERIT_SEQ29_ACCEPTED_SEED_PREDECESSOR_SHA256_V1) {
      fail('PEERIT_SEQ29_CREATE_SEED_MISMATCH',
        'checked-in Seq28 seed predecessor changed')
    }
    const predecessorJson = JSON.parse(new TextDecoder('utf-8', { fatal: true })
      .decode(predecessorBytes))
    const predecessor = await verifyPeeritSeedBootstrapV1(predecessorBytes, {
      authorityPublicKey: PEERIT_SEQ29_SEED_AUTHORITY_PUBLIC_KEY_V1,
      releaseSequence: PROFILE_RELEASE_SEQUENCE,
      expectedArtifactHash: PEERIT_SEQ29_ACCEPTED_SEED_PREDECESSOR_SHA256_V1,
      previousBootstrapHash: null,
      now: predecessorJson.payload.issuedAt
    })
    if (stable(immutableSeedProjection(seed.payload)) !==
        stable(immutableSeedProjection(predecessor.payload))) {
      fail('PEERIT_SEQ29_CREATE_SEED_MISMATCH',
        'Seq29 seed changed content outside the reviewed release/time reissue')
    }
  }

  const profileRelays = new Map(profile.relays.map(row => [row.relayId, row]))
  for (const relay of seed.payload.relays) {
    const pinned = profileRelays.get(relay.relayId)
    if (!pinned || bytesToHex(pinned.relayPublicKey) !==
        relay.continuityRootRelayPublicKey) {
      fail('PEERIT_SEQ29_CREATE_PROFILE_MISMATCH',
        'signed seed relay does not match the frozen profile issuer identity')
    }
  }
  return Object.freeze({ seed, seedSha256, profile, profileSha256, fixtureOnly })
}

function readU32be (value, offset) {
  return ((value[offset] * 0x1000000) + (value[offset + 1] << 16) +
    (value[offset + 2] << 8) + value[offset + 3]) >>> 0
}

function writeU32be (value, offset, number) {
  value[offset] = (number >>> 24) & 0xff
  value[offset + 1] = (number >>> 16) & 0xff
  value[offset + 2] = (number >>> 8) & 0xff
  value[offset + 3] = number & 0xff
}

function readU64be (value, offset) {
  let output = 0n
  for (let index = 0; index < 8; index++) output = (output << 8n) | BigInt(value[offset + index])
  return output
}

function nonzeroRequestId (runtime) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const value = bytes(runtime.randomBytes(16), 'DESCRIBE requestId', 16)
    if (value.some(byte => byte !== 0)) return value
  }
  fail('PEERIT_SEQ29_CREATE_RUNTIME_INVALID', 'runtime returned only zero request IDs')
}

function currentDescriptorRequest (control, runtime) {
  const request = control.createDescribeGetRequest({ runtime })
  if (!request || request.request?.descriptorHash != null ||
      request.wire?.familyId !== 1 || request.wire?.operationId !== 1 ||
      request.wire?.expectedResultBodyBytes !== DESCRIBE_RESULT_LIMIT) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_REQUEST_INVALID',
      'control did not create the fixed current DESCRIBE.GET request')
  }
  const body = bytes(request.requestBytes, 'current DESCRIBE.GET request')
  const requestId = nonzeroRequestId(runtime)
  const dispatch = new Uint8Array(DESCRIBE_HEADER_BYTES + body.byteLength)
  writeU32be(dispatch, 0, dispatch.byteLength - 4)
  dispatch[4] = 1
  dispatch[5] = 1
  dispatch[6] = 1
  dispatch[7] = 1
  dispatch.set(requestId, 9)
  writeU32be(dispatch, 41, body.byteLength)
  dispatch.set(body, DESCRIBE_HEADER_BYTES)
  const envelope = new Uint8Array(DESCRIBE_OUTER_BYTES)
  envelope[0] = 1
  envelope[1] = DESCRIBE_OUTER_CLASS
  writeU32be(envelope, 2, dispatch.byteLength)
  envelope.set(dispatch, 6)
  const padding = bytes(runtime.randomBytes(
    envelope.byteLength - 6 - dispatch.byteLength), 'DESCRIBE padding')
  envelope.set(padding, 6 + dispatch.byteLength)
  return Object.freeze({ envelope, requestId })
}

function timeoutMillis (value) {
  if (value == null) return MAX_TIMEOUT_MILLIS
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_TIMEOUT_MILLIS) {
    fail('PEERIT_SEQ29_CREATE_TIMEOUT_INVALID',
      `timeoutMillis must be within 1..${MAX_TIMEOUT_MILLIS}`)
  }
  return value
}

function nowUnixMillis (provider) {
  const value = provider == null ? Date.now() : provider()
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('PEERIT_SEQ29_CREATE_CLOCK_INVALID',
      'trusted Unix-millisecond clock returned an invalid value')
  }
  return value
}

function monotonicMillisProvider (provider) {
  const source = provider == null
    ? () => globalThis.performance?.now?.() ?? Date.now()
    : provider
  return () => {
    const value = source()
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      fail('PEERIT_SEQ29_CREATE_CLOCK_INVALID',
        'trusted monotonic clock returned an invalid value')
    }
    return value
  }
}

function abortScope (parent, timeout) {
  const controller = new AbortController()
  const forward = () => controller.abort(parent?.reason)
  if (parent) {
    if (parent.aborted) forward()
    else parent.addEventListener('abort', forward, { once: true })
  }
  const timer = setTimeout(() => controller.abort(Object.assign(
    new Error('current descriptor deadline elapsed'),
    { code: 'PEERIT_SEQ29_CREATE_DESCRIPTOR_DEADLINE' }
  )), timeout)
  return Object.freeze({
    signal: controller.signal,
    close () {
      clearTimeout(timer)
      if (parent) parent.removeEventListener('abort', forward)
    }
  })
}

async function exactResponseBytes (response, signal) {
  const header = name => response.headers?.get?.(name) ?? null
  if (header('content-length') !== String(DESCRIBE_OUTER_BYTES) ||
      header('content-encoding') != null || header('transfer-encoding') != null ||
      !response.body || typeof response.body.getReader !== 'function') {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response changed the fixed unencoded streaming class')
  }
  const reader = response.body.getReader()
  const output = new Uint8Array(DESCRIBE_OUTER_BYTES)
  let total = 0
  const cancel = () => Promise.resolve(reader.cancel(signal.reason)).catch(() => {})
  if (signal.aborted) cancel()
  else signal.addEventListener('abort', cancel, { once: true })
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = bytes(value, 'descriptor response chunk')
      total += chunk.byteLength
      if (total > output.byteLength) {
        fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_RESPONSE_INVALID',
          'descriptor response exceeds its fixed class')
      }
      output.set(chunk, total - chunk.byteLength)
    }
  } finally {
    signal.removeEventListener('abort', cancel)
    if (typeof reader.releaseLock === 'function') reader.releaseLock()
  }
  if (total !== output.byteLength) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response is shorter than its fixed class')
  }
  return output
}

function responseBody (value, requestId) {
  const envelope = bytes(value, 'descriptor response')
  if (envelope.byteLength !== DESCRIBE_OUTER_BYTES || envelope[0] !== 1 ||
      envelope[1] !== DESCRIBE_OUTER_CLASS) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response outer envelope is invalid')
  }
  const length = readU32be(envelope, 2)
  if (length < DESCRIBE_HEADER_BYTES || length + 6 > envelope.byteLength) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response inner length is invalid')
  }
  const dispatch = envelope.subarray(6, 6 + length)
  const bodyLength = readU32be(dispatch, 41)
  if (readU32be(dispatch, 0) !== dispatch.byteLength - 4 ||
      dispatch.byteLength !== DESCRIBE_HEADER_BYTES + bodyLength ||
      bodyLength > DESCRIBE_RESULT_LIMIT || dispatch[4] !== 1 ||
      dispatch[5] !== 2 || dispatch[6] !== 1 || dispatch[7] !== 1 || dispatch[8] !== 0 ||
      readU64be(dispatch, 25) !== 0n || readU64be(dispatch, 33) !== 0n ||
      !bytesEqual(dispatch.subarray(9, 25), requestId)) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_RESPONSE_INVALID',
      'descriptor response framing or correlation is invalid')
  }
  return new Uint8Array(dispatch.subarray(DESCRIBE_HEADER_BYTES))
}

async function fetchCurrentDescriptor ({ control, runtime, relay, profile, nowEpoch, fetch, signal, timeout }) {
  const request = currentDescriptorRequest(control, runtime)
  const scope = abortScope(signal, timeout)
  try {
    const response = await fetch(relay.canonicalDescribeUrl, {
      method: 'POST',
      headers: [['content-type', DESCRIBE_MEDIA_TYPE]],
      body: request.envelope,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: scope.signal
    })
    if (!response || response.status !== 200 ||
        response.headers?.get?.('content-type') !== DESCRIBE_MEDIA_TYPE) {
      fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_FETCH_FAILED',
        `${relay.relayId} did not return the fixed descriptor response`)
    }
    return control.verifyDescriptorBytes(
      responseBody(await exactResponseBytes(response, scope.signal), request.requestId), {
        nowEpoch,
        supportedProtocolProfiles: profile.supportedProtocolProfiles,
        supportedTransportProfiles: profile.supportedTransportProfiles
      })
  } finally {
    scope.close()
  }
}

function descriptorLink (descriptor) {
  const snapshot = bytes(descriptor.snapshotBytes(), 'verified descriptor snapshot')
  if (snapshot.byteLength < 74 || snapshot[0] !== 1) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_CHAIN_INVALID',
      'descriptor linkage prefix is invalid')
  }
  const sequence = readU64be(snapshot, 65)
  const tag = snapshot[73]
  const previousHash = tag === 0
    ? null
    : tag === 1 && snapshot.byteLength >= 106
      ? new Uint8Array(snapshot.subarray(74, 106))
      : undefined
  if (previousHash === undefined || sequence !== BigInt(descriptor.descriptorSequence) ||
      !bytesEqual(snapshot.subarray(1, 33), descriptor.relayPublicKey) ||
      !bytesEqual(snapshot.subarray(33, 65), descriptor.storeId)) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_CHAIN_INVALID',
      'descriptor linkage disagrees with its authenticated brand')
  }
  return Object.freeze({
    hash: bytes(descriptor.descriptorHash, 'descriptor hash', 32),
    sequence,
    previousHash,
    relayPublicKey: bytes(descriptor.relayPublicKey, 'descriptor relayPublicKey', 32),
    storeId: bytes(descriptor.storeId, 'descriptor storeId', 32)
  })
}

async function qualifyCreateRelayInternal ({
  control, runtime, directClient, relay, profileRow, profile, nowEpoch,
  stateMonotonicMillis, fetch, signal, timeout
}) {
  const headDescriptor = await fetchCurrentDescriptor({
    control, runtime, relay, profile, nowEpoch, fetch, signal, timeout
  })
  const head = descriptorLink(headDescriptor)
  if (head.sequence < BigInt(relay.minimumDescriptorSequence) ||
      bytesToHex(head.storeId) !== relay.storeId ||
      bytesToHex(head.relayPublicKey) !== bytesToHex(profileRow.relayPublicKey)) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_HEAD_INVALID',
      `${relay.relayId} current descriptor is outside the signed seed/profile identity`)
  }

  const canonicalUrl = new TextEncoder().encode(relay.canonicalDescribeUrl)
  const bootstrapClient = new control.BlindDescriptorBootstrapHttpClient({ runtime, fetch })
  const descending = [headDescriptor]
  const seen = new Set([bytesToHex(head.hash)])
  let current = head
  while (current.sequence > 0n) {
    if (descending.length >= MAX_DESCRIPTOR_HISTORY || current.previousHash == null) {
      fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_CHAIN_INCOMPLETE',
        `${relay.relayId} descriptor history did not reach genesis`)
    }
    const key = bytesToHex(current.previousHash)
    if (seen.has(key)) {
      fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_CHAIN_DUPLICATE',
        `${relay.relayId} descriptor history repeated a hash`)
    }
    const previousDescriptor = await bootstrapClient.fetchVerifiedDescriptor({
      canonicalUrl,
      expectedDescriptorHash: current.previousHash,
      nowEpoch,
      history: true,
      supportedProtocolProfiles: profile.supportedProtocolProfiles,
      supportedTransportProfiles: profile.supportedTransportProfiles,
      signal,
      timeoutMillis: timeout
    })
    const previous = descriptorLink(previousDescriptor)
    if (previous.sequence + 1n !== current.sequence ||
        !bytesEqual(previous.hash, current.previousHash) ||
        !bytesEqual(previous.storeId, head.storeId)) {
      fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_CHAIN_INVALID',
        `${relay.relayId} descriptor history is discontinuous`)
    }
    seen.add(key)
    descending.push(previousDescriptor)
    current = previous
  }
  if (current.previousHash != null || bytesToHex(current.hash) !== relay.descriptorGenesisHash ||
      bytesToHex(current.relayPublicKey) !== relay.continuityRootRelayPublicKey ||
      bytesToHex(current.storeId) !== relay.storeId) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_ROOT_MISMATCH',
      `${relay.relayId} descriptor history is not rooted in the signed seed anchor`)
  }

  const trustStore = new control.DescriptorTrustStore()
  const ascending = descending.reverse()
  let trusted = await trustStore.accept(ascending[0], {
    pinnedDescriptorHash: descriptorLink(ascending[0]).hash,
    continuityRootRelayPublicKey: hexToBytes(
      relay.continuityRootRelayPublicKey, 32, 'seed continuity root')
  })
  for (let index = 1; index < ascending.length; index++) {
    trusted = await trustStore.accept(ascending[index], {
      continuityRootRelayPublicKey: hexToBytes(
        relay.continuityRootRelayPublicKey, 32, 'seed continuity root')
    })
  }
  if (!bytesEqual(trusted.descriptorHash, head.hash)) {
    fail('PEERIT_SEQ29_CREATE_DESCRIPTOR_CHAIN_INVALID',
      `${relay.relayId} trusted descriptor chain did not terminate at its head`)
  }

  const qualifier = new control.BlindRelayQualifier({
    runtime,
    nowEpoch: () => nowEpoch,
    monotonicMillis: stateMonotonicMillis,
    supportedProtocolProfiles: profile.supportedProtocolProfiles,
    supportedTransportProfiles: profile.supportedTransportProfiles,
    trustStore,
    bootstrapClient,
    directClient
  })
  const requirement = Object.freeze({
    familyId: 3,
    operationId: 1,
    endpointId: 1,
    requiredRoleBits: 49,
    privacyProfileBit: 1,
    transportSupportBit: 1
  })
  const qualified = await qualifier.qualifyCandidate(Object.freeze({
    canonicalUrl,
    expectedDescriptorHash: head.hash,
    continuityRootRelayPublicKey: hexToBytes(
      relay.continuityRootRelayPublicKey, 32, 'seed continuity root')
  }), requirement, { signal, timeoutMillis: timeout })
  const context = control.verifiedEndpointContext(qualified.endpoint)
  if (context.familyId !== 3 || context.operationId !== 1 ||
      BigInt(context.descriptorSequence) !== head.sequence ||
      !bytesEqual(context.descriptorHash, head.hash) ||
      bytesToHex(context.storeId) !== relay.storeId) {
    fail('PEERIT_SEQ29_CREATE_ENDPOINT_INVALID',
      `${relay.relayId} CREATE endpoint does not bind the authenticated current head`)
  }

  const advertised = control.trustedAdmissionProfile(
    qualified.trustedDescriptor, CREATE_ADMISSION_PROFILE.profileId)
  if (!advertised ||
      advertised.profileId !== CREATE_ADMISSION_PROFILE.profileId ||
      advertised.schemeId !== CREATE_ADMISSION_PROFILE.schemeId ||
      advertised.conformanceClass !== CREATE_ADMISSION_PROFILE.conformanceClass ||
      advertised.roleBits !== CREATE_ADMISSION_PROFILE.roleBits ||
      advertised.parameterUrl != null) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_PROFILE_DRIFT',
      `${relay.relayId} descriptor changed the frozen admission profile`)
  }
  const request = control.createAdmissionParametersRequest({
    runtime,
    profileId: CREATE_ADMISSION_PROFILE.profileId,
    schemeId: CREATE_ADMISSION_PROFILE.schemeId
  })
  const admissionEndpoint = control.qualifyDescribeControlEndpoint({
    trustedDescriptor: qualified.trustedDescriptor,
    nowEpoch,
    familyId: 1,
    operationId: 3,
    endpointId: 1,
    requiredRoleBits: 49,
    privacyProfileBit: 1,
    transportSupportBit: 1
  })
  const response = await directClient.request({
    endpoint: admissionEndpoint,
    ...request.wire,
    body: request.requestBytes,
    signal,
    timeoutMillis: timeout
  })
  if (!response?.ok) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_PARAMETERS_UNAVAILABLE',
      `${relay.relayId} did not return signed admission parameters`)
  }
  const verifiedAdmissionParameters = control.verifyAdmissionParametersBytes(
    response.body, qualified.trustedDescriptor, advertised, { nowEpoch })
  if (!bytesEqual(verifiedAdmissionParameters.parameterHash, advertised.parameterHash)) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_PARAMETERS_INVALID',
      `${relay.relayId} admission parameters changed their descriptor binding`)
  }
  const validity = control.trustedDescriptorValidity(qualified.trustedDescriptor)
  const admissionValidity = control.verifiedAdmissionParametersValidity(
    verifiedAdmissionParameters)
  return Object.freeze({
    relay,
    profileRow,
    endpoint: qualified.endpoint,
    context,
    advertised,
    verifiedAdmissionParameters,
    descriptorValidity: validity,
    admissionValidity,
    head
  })
}

async function qualifyCreateRelay (input) {
  const scope = abortScope(input.signal, input.timeout)
  try {
    return await qualifyCreateRelayInternal({ ...input, signal: scope.signal })
  } finally {
    scope.close()
  }
}

async function prepareReleaseState (input) {
  const observedUnixMillis = nowUnixMillis(input.now)
  const nowEpoch = Math.floor(observedUnixMillis / EPOCH_MILLIS)
  const release = await authenticateReleaseInputs(
    input.seedBootstrapBytes, input.limitedCellPutProfileBytes,
    observedUnixMillis, input.fixture)
  const acceptedHiveRelay = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
  const { control } = acceptedHiveRelay
  for (const name of [
    'BlindDescriptorBootstrapHttpClient', 'BlindDirectHttpClient', 'BlindRelayQualifier',
    'DescriptorTrustStore', 'createAdmissionParametersRequest', 'createDescribeGetRequest',
    'qualifyDescribeControlEndpoint', 'trustedAdmissionProfile', 'trustedDescriptorValidity',
    'verifiedAdmissionParametersValidity', 'verifiedEndpointContext',
    'verifyAdmissionParametersBytes', 'verifyDescriptorBytes'
  ]) {
    if (typeof control[name] !== 'function') {
      fail('PEERIT_SEQ29_CREATE_CONTROL_INVALID', `accepted control lacks ${name}`)
    }
  }
  if (typeof globalThis.crypto?.getRandomValues !== 'function' ||
      typeof globalThis.crypto?.subtle !== 'object') {
    fail('PEERIT_SEQ29_CREATE_RUNTIME_INVALID',
      'authenticated browser control requires Node WebCrypto')
  }
  const runtime = control.createBrowserCryptoRuntime(globalThis.crypto)
  return Object.freeze({
    referenceUnixMillis: observedUnixMillis,
    allocationEpoch: nowEpoch,
    release,
    control,
    runtime,
    fixtureOnly: release.fixtureOnly,
    acceptedHiveRelayIdentity: acceptedHiveRelay.identity
  })
}

export async function preparePeeritSeq29LiveInboxCreateReleaseV1 (input = {}) {
  exactWithOptional(input, [
    'seedBootstrapBytes', 'limitedCellPutProfileBytes'
  ], ['now', 'fixture'], 'Seq29 CREATE offline release preparation input')
  const state = await prepareReleaseState(input)
  const authority = Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-release-preparation-v1',
    version: 1,
    releaseSequence: RELEASE_SEQUENCE,
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    referenceUnixMillis: String(state.referenceUnixMillis),
    allocationEpoch: state.allocationEpoch,
    seedBootstrapSha256: state.release.seedSha256,
    limitedCellPutProfileSha256: state.release.profileSha256,
    controlArtifactSha256: state.acceptedHiveRelayIdentity.controlArtifactSha256,
    inboxOperatorArtifactSha256:
      state.acceptedHiveRelayIdentity.inboxOperatorArtifactSha256,
    networkRequests: 0,
    fixtureOnly: state.fixtureOnly
  })
  RELEASE_PREPARATIONS.set(authority, state)
  return authority
}

function releasePreparationState (value) {
  const state = RELEASE_PREPARATIONS.get(value)
  if (!state) {
    fail('PEERIT_SEQ29_CREATE_RELEASE_PREPARATION_REQUIRED',
      'an exact module-created offline release preparation is required')
  }
  return state
}

export function snapshotPeeritSeq29LiveInboxCreateReleasePreparationV1 (authority) {
  const state = releasePreparationState(authority)
  const profileRelays = new Map(state.release.profile.relays.map(row => [row.relayId, row]))
  return Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-static-release-snapshot-v1',
    version: 1,
    releaseSequence: RELEASE_SEQUENCE,
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    candidateTree: PEERIT_SEQ29_ACCEPTED_HIVERELAY_TREE_V1,
    referenceUnixMillis: String(state.referenceUnixMillis),
    allocationEpoch: state.allocationEpoch,
    seedBootstrapSha256: state.release.seedSha256,
    limitedCellPutProfileSha256: state.release.profileSha256,
    controlArtifactSha256: state.acceptedHiveRelayIdentity.controlArtifactSha256,
    inboxOperatorArtifactSha256:
      state.acceptedHiveRelayIdentity.inboxOperatorArtifactSha256,
    relays: Object.freeze(state.release.seed.payload.relays.map(relay => Object.freeze({
      relayId: relay.relayId,
      canonicalDescribeUrl: relay.canonicalDescribeUrl,
      relayPublicKey: bytesToHex(profileRelays.get(relay.relayId).relayPublicKey),
      storeId: relay.storeId,
      continuityRootRelayPublicKey: relay.continuityRootRelayPublicKey,
      descriptorGenesisHash: relay.descriptorGenesisHash,
      minimumDescriptorSequence: String(relay.minimumDescriptorSequence),
      familyId: relay.familyId,
      operationId: relay.operationId,
      endpointId: relay.endpointId,
      transportId: relay.transportId,
      transportSupportBit: relay.transportSupportBit,
      privacyProfileBit: relay.privacyProfileBit
    })))
  })
}

export async function preparePeeritSeq29LiveInboxCreateCustodyFirstV1 (
  input = {}
) {
  exactWithOptional(input, [
    'seedBootstrapBytes', 'limitedCellPutProfileBytes',
    'preNetworkCustodyDirectory', 'custodianKeyDirectory'
  ], ['now', 'fixture'], 'Seq29 custody-first offline preparation input')
  const releasePreparation = await preparePeeritSeq29LiveInboxCreateReleaseV1({
    seedBootstrapBytes: input.seedBootstrapBytes,
    limitedCellPutProfileBytes: input.limitedCellPutProfileBytes,
    ...(input.now == null ? {} : { now: input.now }),
    ...(input.fixture == null ? {} : { fixture: input.fixture })
  })
  const releaseSnapshot = snapshotPeeritSeq29LiveInboxCreateReleasePreparationV1(
    releasePreparation)
  const offlinePreparation = await preparePeeritSeq29OfflineInboxCreateRequestsV1({
    releaseSnapshot
  })
  const preNetworkCustody = await sealPeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
    preparation: offlinePreparation,
    directory: input.preNetworkCustodyDirectory,
    custodianKeyDirectory: input.custodianKeyDirectory
  })
  return Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-custody-first-preparation-v1',
    version: 1,
    releaseSequence: RELEASE_SEQUENCE,
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    releasePreparation,
    preNetworkCustody,
    snapshot: snapshotPeeritSeq29OfflineInboxCreatePreparationV1(
      offlinePreparation),
    state: 'PREPARED_BEFORE_NETWORK',
    networkRequests: 0
  })
}

async function qualifyPreparedRelease (state, input) {
  if (input.signal?.aborted) throw input.signal.reason
  const fetch = globalThis.fetch?.bind(globalThis)
  if (typeof fetch !== 'function') {
    fail('PEERIT_SEQ29_CREATE_RUNTIME_INVALID',
      'authenticated browser control requires fetch for live qualification')
  }
  const stateMonotonicMillis = monotonicMillisProvider(input.monotonicMillis)
  const { release, control, runtime } = state
  const directClient = new control.BlindDirectHttpClient({ runtime, fetch })
  const profileRelays = new Map(release.profile.relays.map(row => [row.relayId, row]))
  const timeout = timeoutMillis(input.timeoutMillis)
  const rows = []
  for (const relay of release.seed.payload.relays) {
    rows.push(await qualifyCreateRelay({
      control,
      runtime,
      directClient,
      relay,
      profileRow: profileRelays.get(relay.relayId),
      profile: release.profile,
      nowEpoch: state.allocationEpoch,
      stateMonotonicMillis,
      fetch,
      signal: input.signal,
      timeout
    }))
  }
  const authority = Object.freeze({
    schema: PEERIT_SEQ29_CREATE_QUALIFICATION_SCHEMA_V1,
    releaseSequence: RELEASE_SEQUENCE,
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    qualifiedRelayCount: rows.length,
    seedBootstrapSha256: release.seedSha256,
    limitedCellPutProfileSha256: release.profileSha256,
    controlArtifactSha256: state.acceptedHiveRelayIdentity.controlArtifactSha256,
    inboxOperatorArtifactSha256:
      state.acceptedHiveRelayIdentity.inboxOperatorArtifactSha256,
    fixtureOnly: release.fixtureOnly
  })
  const privateState = Object.freeze({
    authority,
    referenceUnixMillis: state.referenceUnixMillis,
    allocationEpoch: state.allocationEpoch,
    release,
    control,
    runtime,
    rows,
    fetch,
    signal: input.signal,
    fixtureOnly: release.fixtureOnly,
    releasePreparation: input.preparation || null,
    preNetworkCustody: input.preNetworkCustody || null,
    acceptedHiveRelayIdentity: state.acceptedHiveRelayIdentity
  })
  QUALIFICATIONS.set(authority, privateState)
  return authority
}

export async function qualifyPeeritSeq29PreparedLiveInboxCreateTargetsV1 (input = {}) {
  exactWithOptional(input, ['preparation'], [
    'signal', 'timeoutMillis', 'monotonicMillis'
  ], 'Seq29 prepared CREATE qualification input')
  return qualifyPreparedRelease(releasePreparationState(input.preparation), input)
}

export async function qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1 (
  input = {}
) {
  exactWithOptional(input, ['preparation', 'preNetworkCustody'], [
    'signal', 'timeoutMillis', 'monotonicMillis'
  ], 'Seq29 custody-first prepared CREATE qualification input')
  const releaseState = releasePreparationState(input.preparation)
  const releaseSnapshot = snapshotPeeritSeq29LiveInboxCreateReleasePreparationV1(
    input.preparation)
  const preNetworkSnapshot =
    await verifyPeeritSeq29LiveInboxCreatePreNetworkCustodyV1(
      input.preNetworkCustody)
  if (!bytesEqual(
    canonicalPeeritLimitedPublicInboxJsonV1(preNetworkSnapshot.releaseSnapshot),
    canonicalPeeritLimitedPublicInboxJsonV1(releaseSnapshot))) {
    fail('PEERIT_SEQ29_CREATE_RELEASE_PREPARATION_REQUIRED',
      'pre-network custody differs from the prepared static release')
  }
  return qualifyPreparedRelease(releaseState, input)
}

export async function qualifyPeeritSeq29LiveInboxCreateTargetsV1 (input = {}) {
  exactWithOptional(input, [
    'seedBootstrapBytes', 'limitedCellPutProfileBytes'
  ], [
    'signal', 'timeoutMillis', 'now', 'monotonicMillis', 'fixture'
  ], 'Seq29 CREATE qualification input')
  const preparation = await preparePeeritSeq29LiveInboxCreateReleaseV1({
    seedBootstrapBytes: input.seedBootstrapBytes,
    limitedCellPutProfileBytes: input.limitedCellPutProfileBytes,
    ...(input.now == null ? {} : { now: input.now }),
    ...(input.fixture == null ? {} : { fixture: input.fixture })
  })
  return qualifyPreparedRelease(releasePreparationState(preparation), {
    preparation,
    ...(input.signal == null ? {} : { signal: input.signal }),
    ...(input.timeoutMillis == null ? {} : { timeoutMillis: input.timeoutMillis }),
    ...(input.monotonicMillis == null ? {} : { monotonicMillis: input.monotonicMillis })
  })
}

function qualificationState (value) {
  const state = QUALIFICATIONS.get(value)
  if (!state) {
    fail('PEERIT_SEQ29_CREATE_QUALIFICATION_REQUIRED',
      'an exact module-created read-only CREATE qualification is required')
  }
  return state
}

export function snapshotPeeritSeq29LiveInboxCreateQualificationV1 (authority) {
  const state = qualificationState(authority)
  return Object.freeze({
    schema: PEERIT_SEQ29_CREATE_PLAN_SNAPSHOT_SCHEMA_V1,
    releaseSequence: RELEASE_SEQUENCE,
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    referenceUnixMillis: String(state.referenceUnixMillis),
    allocationEpoch: state.allocationEpoch,
    seedBootstrapSha256: state.release.seedSha256,
    limitedCellPutProfileSha256: state.release.profileSha256,
    mutationAuthorityExposed: false,
    relays: Object.freeze(state.rows.map(row => Object.freeze({
      relayId: row.relay.relayId,
      canonicalDescribeUrl: row.relay.canonicalDescribeUrl,
      relayPublicKey: bytesToHex(row.context.relayPublicKey),
      storeId: bytesToHex(row.context.storeId),
      durabilityContinuityHash: bytesToHex(row.context.durabilityContinuityHash),
      descriptorFloor: Object.freeze({
        sequence: String(row.context.descriptorSequence),
        hash: bytesToHex(row.context.descriptorHash)
      }),
      allocationEpoch: state.allocationEpoch,
      admissionParameterHash: bytesToHex(row.verifiedAdmissionParameters.parameterHash),
      descriptorExpiresEpoch: row.descriptorValidity.expiresEpoch,
      admissionExpiresEpoch: row.admissionValidity.expiresEpoch,
      operation: 'INBOX.CREATE',
      familyId: 3,
      operationId: 1
    })))
  })
}

export function createPeeritSeq29LimitedInboxCeremonyPlanFromQualificationV1 (input = {}) {
  exact(input, [
    'qualification', 'issuedUnixMillis', 'expiresUnixMillis',
    'authorityPublicKey', 'stripeSelectionKey', 'announcementMasterKey',
    'bootstrapSequence', 'previousBootstrapHash'
  ], 'Seq29 ceremony-plan materialization input')
  const state = qualificationState(input.qualification)
  const snapshot = snapshotPeeritSeq29LiveInboxCreateQualificationV1(input.qualification)
  for (const field of ['authorityPublicKey', 'stripeSelectionKey', 'announcementMasterKey']) {
    hex32(input[field], field)
  }
  const plan = {
    schema: PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1,
    version: 1,
    hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    releaseSequence: RELEASE_SEQUENCE,
    claimBoundary: 'LIVE_PUBLIC_TEST_ONLY',
    operatorBoundary: 'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS',
    topicScope: 'GLOBAL_PUBLIC_DISCOVERY',
    referenceUnixMillis: String(state.referenceUnixMillis),
    bootstrapSequence: String(input.bootstrapSequence),
    previousBootstrapHash: input.previousBootstrapHash,
    issuedUnixMillis: String(input.issuedUnixMillis),
    expiresUnixMillis: String(input.expiresUnixMillis),
    authorityPublicKey: input.authorityPublicKey,
    stripeSelectionKey: input.stripeSelectionKey,
    announcementMasterKey: input.announcementMasterKey,
    relays: snapshot.relays.map(row => ({
      relayId: row.relayId,
      canonicalDescribeUrl: row.canonicalDescribeUrl,
      relayPublicKey: row.relayPublicKey,
      storeId: row.storeId,
      durabilityContinuityHash: row.durabilityContinuityHash,
      descriptorFloor: row.descriptorFloor,
      allocationEpoch: row.allocationEpoch
    }))
  }
  return validatePeeritLimitedInboxTopicCeremonyPlanV1(plan)
}

function productionRelayAuthorities (state) {
  return state.rows.map(row => Object.freeze({
    relayId: row.relay.relayId,
    endpoint: row.endpoint,
    admission: createPeeritSeq29InboxCreateAdmissionAuthorityV1({
      relayId: row.relay.relayId,
      relayPublicKey: row.context.relayPublicKey,
      issuanceUrl: state.fixtureOnly
        ? `${new URL(row.relay.canonicalDescribeUrl).origin}/`
        : DECODER.decode(row.profileRow.issuanceUrl),
      verifiedAdmissionParameters: Object.freeze({
        parameterHash: row.verifiedAdmissionParameters.parameterHash
      }),
      endpointContext: row.context,
      validity: Object.freeze({
        allocationEpoch: state.allocationEpoch,
        validFromEpoch: Math.max(
          row.descriptorValidity.issuedEpoch,
          row.admissionValidity.validFromEpoch
        ),
        expiresEpoch: Math.min(
          row.descriptorValidity.expiresEpoch,
          row.admissionValidity.expiresEpoch
        )
      }),
      fetch: state.fetch,
      signal: state.signal
    }),
    clientNonce: null
  }))
}

function assertPersistedPlanMatchesFreshQualification (plan, qualification) {
  const snapshot = snapshotPeeritSeq29LiveInboxCreateQualificationV1(qualification)
  const freshReference = BigInt(snapshot.referenceUnixMillis)
  const persistedReference = BigInt(plan.referenceUnixMillis)
  const persistedIssued = BigInt(plan.issuedUnixMillis)
  const persistedExpires = BigInt(plan.expiresUnixMillis)
  if (plan.releaseSequence !== RELEASE_SEQUENCE ||
      plan.hiverelayCommit !== PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT ||
      plan.relays.length !== snapshot.relays.length) {
    fail('PEERIT_SEQ29_CREATE_RECOVERY_PLAN_DRIFT',
      'persisted plan differs from the fixed Seq29 release identity')
  }
  if (freshReference < persistedIssued || freshReference < persistedReference ||
      freshReference >= persistedExpires) {
    fail('PEERIT_SEQ29_CREATE_RECOVERY_PLAN_EXPIRED',
      'fresh endpoint qualification is outside the persisted plan validity window')
  }
  for (let index = 0; index < plan.relays.length; index++) {
    const persisted = plan.relays[index]
    const fresh = snapshot.relays[index]
    if (persisted.relayId !== fresh.relayId ||
        persisted.canonicalDescribeUrl !== fresh.canonicalDescribeUrl ||
        persisted.relayPublicKey !== fresh.relayPublicKey ||
        persisted.storeId !== fresh.storeId ||
        persisted.durabilityContinuityHash !== fresh.durabilityContinuityHash ||
        persisted.descriptorFloor.sequence !== fresh.descriptorFloor.sequence ||
        persisted.descriptorFloor.hash !== fresh.descriptorFloor.hash ||
        persisted.allocationEpoch !== fresh.allocationEpoch) {
      fail('PEERIT_SEQ29_CREATE_RECOVERY_PLAN_DRIFT',
        `fresh qualified endpoint ${fresh.relayId} differs from its persisted exact descriptor floor or relay identity`)
    }
  }
  return snapshot
}

function planContinuitySnapshot (plan, qualification) {
  const snapshot = snapshotPeeritSeq29LiveInboxCreateQualificationV1(qualification)
  return Object.freeze({
    schema: PEERIT_SEQ29_CREATE_PLAN_CONTINUITY_SCHEMA_V1,
    version: 1,
    planHash: peeritLimitedInboxTopicCeremonyPlanHashV1(plan),
    referenceUnixMillis: snapshot.referenceUnixMillis,
    seedBootstrapSha256: snapshot.seedBootstrapSha256,
    limitedCellPutProfileSha256: snapshot.limitedCellPutProfileSha256
  })
}

function validatePersistedPlanContinuity (value, planHash, freshSnapshot) {
  exact(value, [
    'schema', 'version', 'planHash', 'referenceUnixMillis',
    'seedBootstrapSha256', 'limitedCellPutProfileSha256'
  ], 'persisted qualification continuity')
  hex32(value.planHash, 'persisted qualification planHash')
  hex32(value.seedBootstrapSha256,
    'persisted qualification seedBootstrapSha256')
  hex32(value.limitedCellPutProfileSha256,
    'persisted qualification limitedCellPutProfileSha256')
  if (value.schema !== PEERIT_SEQ29_CREATE_PLAN_CONTINUITY_SCHEMA_V1 ||
      value.version !== 1 || value.planHash !== planHash ||
      !/^(?:0|[1-9][0-9]*)$/.test(value.referenceUnixMillis) ||
      value.seedBootstrapSha256 !== freshSnapshot.seedBootstrapSha256 ||
      value.limitedCellPutProfileSha256 !==
        freshSnapshot.limitedCellPutProfileSha256) {
    fail('PEERIT_SEQ29_CREATE_RECOVERY_SOURCE_DRIFT',
      'fresh qualification differs from the persisted release-source continuity')
  }
  return Object.freeze({ ...value })
}

async function composeQualifiedPlan (input, state, plan, options = {}) {
  const custodyFirst = options.custodyFirst === true
  const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  const persistedQualification = options.persistedQualification ||
    planContinuitySnapshot(plan, input.qualification)
  const authority = await createPeeritSeq29LimitedInboxCeremonyAuthorityV1({
    plan,
    relays: productionRelayAuthorities(state),
    attemptBinding: Object.freeze({ persistedQualification }),
    ...(custodyFirst ? { preNetworkCustody: input.preNetworkCustody } : {})
  })
  if (authority.planHash !== planHash || authority.releaseSequence !== RELEASE_SEQUENCE ||
      authority.schema !== (custodyFirst
        ? 'peerit-seq29-limited-inbox-ceremony-custody-first-authority-v1'
        : 'peerit-seq29-limited-inbox-ceremony-authority-v1')) {
    fail('PEERIT_SEQ29_CREATE_COMPOSITION_AUTHORITY_INVALID',
      'ceremony authority identity differs from the qualified plan')
  }
  const attemptJournal = createPeeritSeq29FilesystemAttemptJournalV1({
    directory: input.journalDirectory
  })
  const custodianKeys = createPeeritSeq29LocalCustodianKeyFileConfigurationV1({
    directory: input.custodianKeyDirectory
  })
  const custodyTransaction = createPeeritSeq29LocalManagementCustodyV1({
    directory: input.custodyDirectory,
    custodianPublicKeys: custodianKeys.custodianPublicKeys,
    custodianPrivateKeyProvider: custodianKeys.custodianPrivateKeyProvider
  })
  const conductor = createPeeritSeq29LiveInboxCeremonyConductorV1({
    plan,
    authority,
    attemptJournal,
    custodyTransaction,
    publicOutputDirectory: input.publicOutputDirectory
  })
  return Object.freeze({
    schema: options.schema || (custodyFirst
      ? 'peerit-seq29-live-inbox-create-custody-first-composition-v1'
      : 'peerit-seq29-live-inbox-create-composition-v1'),
    version: 1,
    releaseSequence: RELEASE_SEQUENCE,
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    qualification: Object.freeze({ ...input.qualification }),
    plan,
    planHash,
    commitToken: `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${planHash}`,
    authority: Object.freeze({ ...authority }),
    conductor,
    dryRun: dryRunPeeritLimitedInboxTopicCeremonyV1(plan),
    persistedQualification,
    executionBoundary: options.executionBoundary || (custodyFirst
      ? 'EXPLICIT_IN_PROCESS_PRE_NETWORK_AND_EXACT_PLAN_CUSTODY_ONLY'
      : 'EXPLICIT_IN_PROCESS_DOUBLE_COMMIT_ONLY'),
    automaticExecution: false
  })
}

export async function createPeeritSeq29LiveInboxCreateCompositionV1 (input = {}) {
  const custodyFirst = Object.hasOwn(input, 'preNetworkCustody')
  exact(input, [
    'qualification', 'issuedUnixMillis', 'expiresUnixMillis',
    'authorityPublicKey', 'stripeSelectionKey', 'announcementMasterKey',
    'bootstrapSequence', 'previousBootstrapHash', 'journalDirectory',
    'custodyDirectory', 'publicOutputDirectory', 'custodianKeyDirectory'
  ].concat(custodyFirst ? ['preNetworkCustody'] : []),
  'CREATE composition input')
  const state = qualificationState(input.qualification)
  if (custodyFirst && state.preNetworkCustody !== input.preNetworkCustody) {
    fail('PEERIT_SEQ29_CREATE_COMPOSITION_AUTHORITY_INVALID',
      'custody-first composition requires the exact pre-custody-gated qualification')
  }
  const plan = createPeeritSeq29LimitedInboxCeremonyPlanFromQualificationV1({
    qualification: input.qualification,
    issuedUnixMillis: input.issuedUnixMillis,
    expiresUnixMillis: input.expiresUnixMillis,
    authorityPublicKey: input.authorityPublicKey,
    stripeSelectionKey: input.stripeSelectionKey,
    announcementMasterKey: input.announcementMasterKey,
    bootstrapSequence: input.bootstrapSequence,
    previousBootstrapHash: input.previousBootstrapHash
  })
  return composeQualifiedPlan(input, state, plan, { custodyFirst })
}

export async function createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1 (
  input = {}
) {
  const custodyFirst = Object.hasOwn(input, 'preNetworkCustody')
  exact(input, [
    'qualification', 'persistedAttemptBinding',
    'expectedPlanHash', 'journalDirectory',
    'custodyDirectory', 'publicOutputDirectory', 'custodianKeyDirectory'
  ].concat(custodyFirst ? ['preNetworkCustody'] : []),
  'persisted-plan CREATE recovery composition input')
  const state = qualificationState(input.qualification)
  if (custodyFirst && state.preNetworkCustody !== input.preNetworkCustody) {
    fail('PEERIT_SEQ29_CREATE_COMPOSITION_AUTHORITY_INVALID',
      'custody-first recovery requires the exact pre-custody-gated fresh qualification')
  }
  hex32(input.expectedPlanHash, 'expectedPlanHash')
  const sealed = verifyPeeritSeq29FilesystemAttemptBindingV1(
    input.persistedAttemptBinding)
  const plan = validatePeeritLimitedInboxTopicCeremonyPlanV1(sealed.plan)
  const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  if (sealed.planHash !== planHash || planHash !== input.expectedPlanHash) {
    fail('PEERIT_SEQ29_CREATE_RECOVERY_PLAN_HASH_MISMATCH',
      'persisted plan bytes do not match the exact persisted plan hash')
  }
  const freshSnapshot = assertPersistedPlanMatchesFreshQualification(
    plan, input.qualification)
  if (String(sealed.persistedQualification?.referenceUnixMillis) !==
      plan.referenceUnixMillis) {
    fail('PEERIT_SEQ29_CREATE_RECOVERY_SOURCE_DRIFT',
      'persisted qualification reference does not bind the persisted plan')
  }
  const persistedQualification = validatePersistedPlanContinuity(
    sealed.persistedQualification, planHash, freshSnapshot)
  const composition = await composeQualifiedPlan(input, state, plan, {
    custodyFirst,
    schema: 'peerit-seq29-live-inbox-create-persisted-plan-recovery-composition-v1',
    persistedQualification,
    executionBoundary:
      'EXPLICIT_IN_PROCESS_PERSISTED_PLAN_FRESH_ENDPOINT_RECOVERY_ONLY'
  })
  if (composition.planHash !== input.expectedPlanHash) {
    fail('PEERIT_SEQ29_CREATE_RECOVERY_PLAN_HASH_MISMATCH',
      'recovery composition drifted from the persisted plan hash')
  }
  return composition
}

export async function createPeeritSeq29CustodyFirstLiveInboxCreateCompositionV1 (
  input = {}
) {
  if (!Object.hasOwn(input, 'preNetworkCustody')) {
    fail('PEERIT_SEQ29_CREATE_COMPOSITION_AUTHORITY_INVALID',
      'custody-first composition requires durable pre-network custody')
  }
  return createPeeritSeq29LiveInboxCreateCompositionV1(input)
}
