#!/usr/bin/env node

// Sequence-29 two-topic ceremony. The CLI is deliberately limited to
// validate and dry-run. The mutation executor accepts only an authority
// minted here after the exact accepted HiveRelay checkout and its opaque
// endpoint contexts have been authenticated. It never accepts a caller's
// control module or transport callback at the production execution boundary.

import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  canonicalPeeritLimitedPublicInboxJsonV1,
  PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  blake2b256,
  bytesEqual,
  bytesToHex,
  hexToBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
  PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1,
  hashPeeritLimitedPublicInboxSignedWrapperV1,
  validatePeeritLimitedPublicInboxSignedWrapperV1,
  validatePeeritLimitedPublicInboxSigningPackageV1
} from './sign-limited-public-inbox-bootstrap.mjs'
import {
  resolvePeeritSeq29InboxCreateAdmissionProviderV1
} from './lib/seq29-live-inbox-create-admission.mjs'
import {
  loadPeeritSeq29AcceptedHiveRelayOperatorV1
} from './lib/seq29-accepted-hiverelay-operator.mjs'
import {
  bindPeeritSeq29PreNetworkCustodyToExactPlanV1,
  replayPeeritSeq29CustodiedInboxCreateV1,
  snapshotPeeritSeq29LiveInboxCreatePreNetworkCustodyV1
} from './lib/seq29-live-inbox-create-pre-network-custody.mjs'

export const PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT =
  PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1
export const PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1 =
  'peerit-limited-inbox-topic-ceremony-plan-v1'
export const PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1 =
  'CREATE EXACTLY TWO SEQ29 OPEN_APPEND TOPICS '
export const PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1 = createHash('sha256')
  .update('peerit.seq29.limited-public-inbox.create-only.release-slot.v1')
  .digest('hex')

const HEX32 = /^[0-9a-f]{64}$/
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const PLAN_FIELDS = Object.freeze([
  'schema', 'version', 'hiverelayCommit', 'releaseSequence', 'claimBoundary',
  'operatorBoundary', 'topicScope', 'referenceUnixMillis', 'bootstrapSequence',
  'previousBootstrapHash', 'issuedUnixMillis', 'expiresUnixMillis',
  'authorityPublicKey', 'stripeSelectionKey', 'announcementMasterKey', 'relays'
])
const RELAY_FIELDS = Object.freeze([
  'relayId', 'canonicalDescribeUrl', 'relayPublicKey', 'storeId',
  'durabilityContinuityHash', 'descriptorFloor', 'allocationEpoch'
])
const CEREMONY_AUTHORITIES = new WeakMap()
const TEST_ONLY_FIXTURE_ENV = 'PEERIT_SEQ29_OPERATOR_FIXTURE_TEST'

function fail (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details !== undefined) error.details = details
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      `${field} fields are missing or unexpected`)
  }
  return value
}

function decimal (value, field) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID', `${field} is not canonical u64 decimal`)
  }
  const parsed = BigInt(value)
  if (parsed > ((1n << 64n) - 1n)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID', `${field} exceeds u64`)
  }
  return parsed
}

function hex32 (value, field) {
  if (typeof value !== 'string' || !HEX32.test(value)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function canonicalUrl (value) {
  if (typeof value !== 'string') {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      'canonicalDescribeUrl must be HTTPS with an explicit port')
  }
  const match = /^https:\/\/([a-z0-9.-]+):([0-9]+)(\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)$/.exec(value)
  let parsed
  try { parsed = new URL(value) } catch {}
  const port = match == null ? 0 : Number(match[2])
  if (!match || !parsed || !Number.isInteger(port) || port < 1 || port > 65535 ||
      parsed.protocol !== 'https:' || parsed.hostname !== match[1] ||
      parsed.username || parsed.password || parsed.search || parsed.hash ||
      parsed.pathname !== match[3] || value.includes('/./') || value.includes('/../') ||
      value.includes('//', 8)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      'canonicalDescribeUrl must be canonical HTTPS with a port within 1..65535')
  }
}

function noPrivateMaterial (value, trail = []) {
  if (value == null || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const lower = key.toLowerCase()
    if (lower.includes('privateseed') || lower.includes('privatekey') ||
        lower === 'secretseed' || lower.includes('appendseed')) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_SECRET',
        `public ceremony plan carries private material at ${[...trail, key].join('.')}`)
    }
    noPrivateMaterial(child, [...trail, key])
  }
}

export function validatePeeritLimitedInboxTopicCeremonyPlanV1 (input) {
  const plan = structuredClone(input)
  noPrivateMaterial(plan)
  exact(plan, PLAN_FIELDS, 'ceremony plan')
  if (plan.schema !== PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1 ||
      plan.version !== 1 ||
      plan.hiverelayCommit !== PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT ||
      plan.releaseSequence !== PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1 ||
      plan.claimBoundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
      plan.operatorBoundary !== 'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS' ||
      plan.topicScope !== 'GLOBAL_PUBLIC_DISCOVERY') {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      'ceremony plan identity, provenance, or claim boundary is invalid')
  }
  const reference = decimal(plan.referenceUnixMillis, 'referenceUnixMillis')
  const issued = decimal(plan.issuedUnixMillis, 'issuedUnixMillis')
  const expires = decimal(plan.expiresUnixMillis, 'expiresUnixMillis')
  const sequence = decimal(plan.bootstrapSequence, 'bootstrapSequence')
  if (issued > reference || reference >= expires || expires - issued > 2678400000n ||
      (sequence === 0n) !== (plan.previousBootstrapHash === null)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      'ceremony bootstrap sequence or time window is invalid')
  }
  if (plan.previousBootstrapHash !== null) hex32(plan.previousBootstrapHash, 'previousBootstrapHash')
  for (const field of ['authorityPublicKey', 'stripeSelectionKey', 'announcementMasterKey']) {
    hex32(plan[field], field)
  }
  if (!Array.isArray(plan.relays) || plan.relays.length !== 2) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      'ceremony requires exactly two relays')
  }
  const effectiveLeaseEpoch = Number(reference / 21600000n)
  for (const relay of plan.relays) {
    exact(relay, RELAY_FIELDS, `relay ${relay?.relayId || '?'}`)
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(relay.relayId)) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID', 'relayId is invalid')
    }
    canonicalUrl(relay.canonicalDescribeUrl)
    for (const field of ['relayPublicKey', 'storeId', 'durabilityContinuityHash']) {
      hex32(relay[field], `${relay.relayId}.${field}`)
    }
    exact(relay.descriptorFloor, ['sequence', 'hash'], `${relay.relayId}.descriptorFloor`)
    decimal(relay.descriptorFloor.sequence, `${relay.relayId}.descriptorFloor.sequence`)
    hex32(relay.descriptorFloor.hash, `${relay.relayId}.descriptorFloor.hash`)
    if (!Number.isSafeInteger(relay.allocationEpoch) || relay.allocationEpoch < 0 ||
        relay.allocationEpoch > 0xffffffff ||
        relay.allocationEpoch > effectiveLeaseEpoch + 1 ||
        effectiveLeaseEpoch >= relay.allocationEpoch + 1460) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
        `${relay.relayId}.allocationEpoch is outside the accepted live window`)
    }
  }
  for (const field of ['relayId', 'relayPublicKey', 'storeId']) {
    if (new Set(plan.relays.map(relay => relay[field])).size !== 2) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
        `ceremony relay ${field} values must be distinct`)
    }
  }
  return Object.freeze(plan)
}

export function peeritLimitedInboxTopicCeremonyPlanHashV1 (input) {
  const plan = validatePeeritLimitedInboxTopicCeremonyPlanV1(input)
  return createHash('sha256').update(canonicalPeeritLimitedPublicInboxJsonV1(plan)).digest('hex')
}

export function dryRunPeeritLimitedInboxTopicCeremonyV1 (input) {
  const plan = validatePeeritLimitedInboxTopicCeremonyPlanV1(input)
  const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  return Object.freeze({
    schema: 'peerit-limited-inbox-topic-ceremony-dry-run-v1',
    status: 'DRY_RUN_NO_NETWORK',
    planHash,
    commitToken: `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${planHash}`,
    hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    operations: Object.freeze(plan.relays.map(relay => Object.freeze({
      relayId: relay.relayId,
      family: 'INBOX',
      operation: 'CREATE',
      allocationEpoch: relay.allocationEpoch,
      frameClassBits: 3,
      appendAuthMode: 0,
      retentionClass: 3,
      leaseClass: 4
    }))),
    mutationBudget: Object.freeze({
      inboxCreate: 2,
      cellPut: 0,
      inboxAppend: 0,
      inboxRenew: 0,
      inboxClose: 0,
      other: 0
    }),
    publicOutput: 'UNSIGNED_SIGNING_PACKAGE_AFTER_TWO_VERIFIED_CREATE_RECEIPTS',
    privateOutput: 'SIX_MANAGEMENT_SEEDS_TO_INJECTED_CUSTODY_SINK_ONLY',
    networkRequests: 0
  })
}

function exactControl (control) {
  for (const name of [
    'createInboxReplica', 'verifyOperationResult',
    'decodeBlindExternalProfileValueV1', 'destroyInboxWriteCapability'
  ]) {
    if (typeof control?.[name] !== 'function') {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_CONTROL_INVALID',
        `accepted HiveRelay Node control lacks ${name}`)
    }
  }
  return control
}

function rejectCallables (value, field, seen = new Set()) {
  if (typeof value === 'function') {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      `${field} must not contain caller-supplied functions`)
  }
  if (value == null || typeof value !== 'object' || seen.has(value)) return
  seen.add(value)
  if (value instanceof Map) {
    for (const [key, child] of value) {
      rejectCallables(key, `${field}.mapKey`, seen)
      rejectCallables(child, `${field}.mapValue`, seen)
    }
    return
  }
  for (const [key, child] of Object.entries(value)) {
    rejectCallables(child, `${field}.${key}`, seen)
  }
}

function endpointMatchesRelay (control, endpoint, relay) {
  let context
  try { context = control.verifiedEndpointContext(endpoint) } catch (cause) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      `${relay.relayId} CREATE endpoint is not an opaque accepted-module endpoint`, {
        cause: cause?.message || String(cause)
      })
  }
  if (context.familyId !== 3 || context.operationId !== 1 ||
      bytesToHex(context.relayPublicKey) !== relay.relayPublicKey ||
      bytesToHex(context.storeId) !== relay.storeId ||
      bytesToHex(context.durabilityContinuityHash) !== relay.durabilityContinuityHash ||
      BigInt(context.descriptorSequence) < BigInt(relay.descriptorFloor.sequence) ||
      (BigInt(context.descriptorSequence) === BigInt(relay.descriptorFloor.sequence) &&
        bytesToHex(context.descriptorHash) !== relay.descriptorFloor.hash)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      `${relay.relayId} CREATE endpoint differs from its accepted relay identity or floor`)
  }
}

export async function createPeeritSeq29LimitedInboxCeremonyAuthorityV1 (input = {}) {
  const custodyFirst = Object.hasOwn(input, 'preNetworkCustody')
  const hasAttemptBinding = Object.hasOwn(input, 'attemptBinding')
  exact(input, [
    'plan', 'relays',
    ...(custodyFirst ? ['preNetworkCustody'] : []),
    ...(hasAttemptBinding ? ['attemptBinding'] : [])
  ], 'ceremony authority input')
  rejectCallables(input, 'ceremony authority input')
  const plan = validatePeeritLimitedInboxTopicCeremonyPlanV1(input.plan)
  if (hasAttemptBinding) {
    exact(input.attemptBinding, ['persistedQualification'],
      'ceremony durable attempt binding')
    if (input.attemptBinding.persistedQualification?.planHash !==
        peeritLimitedInboxTopicCeremonyPlanHashV1(plan) ||
        input.attemptBinding.persistedQualification?.referenceUnixMillis !==
          plan.referenceUnixMillis) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
        'durable attempt binding differs from the exact ceremony plan')
    }
  }
  let preNetworkSnapshot = null
  if (custodyFirst) {
    preNetworkSnapshot = snapshotPeeritSeq29LiveInboxCreatePreNetworkCustodyV1(
      input.preNetworkCustody)
    if (preNetworkSnapshot.requests.length !== 2 ||
        preNetworkSnapshot.releaseSnapshot.referenceUnixMillis !==
          plan.referenceUnixMillis ||
        plan.relays.some((relay, index) => {
          const frozen = preNetworkSnapshot.releaseSnapshot.relays[index]
          const request = preNetworkSnapshot.requests[index]
          return relay.relayId !== frozen.relayId || relay.relayId !== request.relayId ||
            relay.relayPublicKey !== frozen.relayPublicKey ||
            relay.canonicalDescribeUrl !== frozen.canonicalDescribeUrl ||
            relay.storeId !== frozen.storeId ||
            relay.allocationEpoch !== request.allocationEpoch
        })) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
        'pre-network custody differs from the exact qualified plan')
    }
  }
  if (!Array.isArray(input.relays) || input.relays.length !== 2) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      'ceremony authority requires two relay transport rows')
  }
  const acceptedHiveRelay = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
  const baseControl = acceptedHiveRelay.control
  const inboxControl = acceptedHiveRelay.inbox
  const control = exactControl(Object.freeze({
    createInboxReplica: inboxControl.createInboxReplica,
    destroyInboxWriteCapability: inboxControl.destroyInboxWriteCapability,
    verifyOperationResult: baseControl.verifyOperationResult,
    decodeBlindExternalProfileValueV1: baseControl.decodeBlindExternalProfileValueV1,
    verifiedEndpointContext: baseControl.verifiedEndpointContext
  }))
  if (typeof baseControl.BlindDirectHttpClient !== 'function' ||
      typeof baseControl.createBrowserCryptoRuntime !== 'function' ||
      typeof control.verifiedEndpointContext !== 'function' ||
      typeof globalThis.crypto?.getRandomValues !== 'function') {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      'accepted HiveRelay immutable transport/runtime surface is incomplete')
  }
  const runtime = baseControl.createBrowserCryptoRuntime(globalThis.crypto)
  const client = new baseControl.BlindDirectHttpClient({ runtime })
  const rowByRelay = new Map()
  for (const row of input.relays) {
    exact(row, ['relayId', 'endpoint', 'admission', 'clientNonce'], 'ceremony relay authority')
    const relay = plan.relays.find(value => value.relayId === row.relayId)
    if (!relay || rowByRelay.has(row.relayId)) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
        'ceremony relay authority rows must cover the exact plan once')
    }
    endpointMatchesRelay(control, row.endpoint, relay)
    if (row.clientNonce != null && (!(row.clientNonce instanceof Uint8Array) ||
        row.clientNonce.byteLength !== 32)) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
        `${row.relayId} clientNonce must be null or 32 bytes`)
    }
    const admissionProvider = row.admission?.schema ===
      'peerit-seq29-inbox-create-admission-authority-v1'
      ? resolvePeeritSeq29InboxCreateAdmissionProviderV1(row.admission, {
        relayId: relay.relayId,
        relayPublicKey: hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey')
      })
      : null
    rowByRelay.set(row.relayId, Object.freeze({
      endpoint: row.endpoint,
      admission: admissionProvider == null ? row.admission : null,
      admissionProvider,
      clientNonce: row.clientNonce == null ? null : row.clientNonce.slice()
    }))
  }
  if (plan.relays.some(relay => !rowByRelay.has(relay.relayId))) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      'ceremony relay authority rows do not cover both plan relays')
  }
  const authority = Object.freeze({
    schema: custodyFirst
      ? 'peerit-seq29-limited-inbox-ceremony-custody-first-authority-v1'
      : 'peerit-seq29-limited-inbox-ceremony-authority-v1',
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    releaseSequence: PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
    planHash: peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  })
  CEREMONY_AUTHORITIES.set(authority, Object.freeze({
    plan,
    control,
    runtime,
    rowByRelay,
    attemptBinding: hasAttemptBinding ? input.attemptBinding : null,
    preNetworkCustody: custodyFirst ? input.preNetworkCustody : null,
    fixtureOnly: false,
    async transportCreate ({ relayId, requestBytes, wire }) {
      const row = rowByRelay.get(relayId)
      if (!row) {
        fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
          'CREATE attempted outside the authenticated relay set')
      }
      return client.request({ endpoint: row.endpoint, ...wire, body: requestBytes })
    }
  }))
  return authority
}

// This test-only constructor is unreachable unless the focused test process
// opts in, and it accepts only .invalid relay plans. It is never used by the
// CLI or the production authority factory.
export function createPeeritSeq29LimitedInboxCeremonyFixtureAuthorityV1 (input = {}) {
  exact(input, [
    'allowFixture', 'plan', 'control', 'runtime', 'endpointByRelay',
    'admissionProviderByRelay', 'clientNonceByRelay', 'transportCreate'
  ], 'fixture ceremony authority input')
  if (process.env[TEST_ONLY_FIXTURE_ENV] !== '1' || input.allowFixture !== true) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      'fixture ceremony authority is disabled outside focused tests')
  }
  const plan = validatePeeritLimitedInboxTopicCeremonyPlanV1(input.plan)
  if (plan.relays.some(relay => new URL(relay.canonicalDescribeUrl).hostname
    .endsWith('.invalid') !== true)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      'fixture ceremony authority requires reserved .invalid relay names')
  }
  const authority = Object.freeze({
    schema: 'peerit-seq29-limited-inbox-ceremony-fixture-authority-v1',
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    releaseSequence: PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
    planHash: peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  })
  CEREMONY_AUTHORITIES.set(authority, Object.freeze({
    plan,
    control: exactControl(input.control),
    runtime: input.runtime,
    rowByRelay: new Map(plan.relays.map(relay => [relay.relayId, Object.freeze({
      endpoint: input.endpointByRelay.get(relay.relayId),
      admissionProvider: input.admissionProviderByRelay?.get(relay.relayId),
      clientNonce: input.clientNonceByRelay?.get(relay.relayId)
    })])),
    attemptBinding: null,
    fixtureOnly: true,
    transportCreate: input.transportCreate
  }))
  return authority
}

function publicRelay (relay) {
  return {
    relayId: relay.relayId,
    canonicalDescribeUrl: relay.canonicalDescribeUrl,
    relayPublicKey: relay.relayPublicKey,
    storeId: relay.storeId,
    durabilityContinuityHash: relay.durabilityContinuityHash,
    descriptorFloor: relay.descriptorFloor
  }
}

function bytes (value, field) {
  if (!(value instanceof Uint8Array)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_CONTROL_INVALID', `${field} must be bytes`)
  }
  return value
}

function ed25519PublicFromSeed (seed) {
  const privateDer = Buffer.alloc(ED25519_PKCS8_PREFIX.byteLength + seed.byteLength)
  privateDer.set(ED25519_PKCS8_PREFIX)
  privateDer.set(seed, ED25519_PKCS8_PREFIX.byteLength)
  try {
    return createPublicKey(createPrivateKey({
      key: privateDer,
      format: 'der',
      type: 'pkcs8'
    })).export({ format: 'der', type: 'spki' }).subarray(-32)
  } finally { privateDer.fill(0) }
}

function assertSixDistinctManagementSeeds (entries) {
  const seeds = entries.flatMap(({ created }, index) => [
    bytes(created.writeCap?.createPrivateKey, `entry ${index} CREATE seed`),
    bytes(created.writeCap?.renewPrivateKey, `entry ${index} RENEW seed`),
    bytes(created.writeCap?.closePrivateKey, `entry ${index} CLOSE seed`)
  ])
  if (seeds.length !== 6 || seeds.some(seed => seed.byteLength !== 32 ||
      seed.every(byte => byte === 0)) || !seeds.every((seed, index) =>
    seeds.slice(index + 1).every(other => !bytesEqual(seed, other)))) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_MANAGEMENT_KEYS_INVALID',
      'ceremony requires six pairwise-distinct nonzero CREATE/RENEW/CLOSE seeds')
  }
  for (const { created } of entries) {
    for (const [seedField, publicField] of [
      ['createPrivateKey', 'createPublicKey'],
      ['renewPrivateKey', 'renewPublicKey'],
      ['closePrivateKey', 'closePublicKey']
    ]) {
      const seed = bytes(created.writeCap[seedField], seedField)
      const derived = ed25519PublicFromSeed(seed)
      if (!bytesEqual(derived, bytes(created.request[publicField], publicField))) {
        fail('PEERIT_LIMITED_INBOX_CEREMONY_MANAGEMENT_KEYS_INVALID',
          `${seedField} does not derive the emitted ${publicField}`)
      }
    }
  }
  return seeds
}

function interfaceWithMethods (value, methods, code, field) {
  if (!value || typeof value !== 'object' ||
      methods.some(name => typeof value[name] !== 'function')) {
    fail(code, `${field} must implement ${methods.join(', ')}`)
  }
  return value
}

function opaqueId (value, field) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_DURABILITY_INVALID', `${field} is invalid`)
  }
  return value
}

function objectDigest (value) {
  return createHash('sha256')
    .update(canonicalPeeritLimitedPublicInboxJsonV1(value)).digest('hex')
}

function durableReceipt (value, state, fields, field, expected = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0') ||
      value.accepted !== true || value.durable !== true || value.state !== state ||
      Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_DURABILITY_INVALID',
      `${field} was not durably accepted in state ${state}`)
  }
  opaqueId(value.commitment, `${field}.commitment`)
  return value
}

function ceremonyBeginRequest (plan, planHash, commitToken, attemptBinding) {
  const request = {
    schema: 'peerit-limited-inbox-create-only-attempt-v1',
    releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    releaseSequence: PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
    planHash,
    relayIdentityDigest: releaseIdentityDigest(plan),
    commitTokenHash: createHash('sha256').update(commitToken).digest('hex'),
    operationBudget: Object.freeze({ family: 'INBOX', operation: 'CREATE', maximum: 2 })
  }
  if (attemptBinding != null) {
    request.plan = structuredClone(plan)
    request.planSha256 = objectDigest(plan)
    request.persistedQualification = structuredClone(
      attemptBinding.persistedQualification)
    request.persistedQualificationSha256 = objectDigest(
      attemptBinding.persistedQualification)
  }
  return Object.freeze(request)
}

function validatedCeremonyRecovery (recovery, expected) {
  if (!recovery || typeof recovery !== 'object' || Array.isArray(recovery) ||
      Object.keys(recovery).sort().join('\0') !== [
        'schema', 'planHash', 'attemptId', 'releaseAttemptKey',
        'relayIdentityDigest', 'signingPackage', 'signingPackageSha256',
        'custodyTransactionId', 'custodyPublicBindingDigest',
        'transportInvocations', 'executionDigest'
      ].sort().join('\0') ||
      recovery.schema !== 'peerit-limited-inbox-topic-recovery-v2' ||
      recovery.planHash !== expected.planHash || recovery.attemptId !== expected.attemptId ||
      recovery.releaseAttemptKey !== PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1 ||
      recovery.relayIdentityDigest !== expected.relayIdentityDigest ||
      objectDigest(recovery.signingPackage) !== recovery.signingPackageSha256 ||
      recovery.custodyPublicBindingDigest !== objectDigest({
        schema: 'peerit-seq29-limited-inbox-custody-public-binding-v1',
        planHash: recovery.planHash,
        signingPackageSha256: recovery.signingPackageSha256,
        signingPackage: recovery.signingPackage
      }) ||
      !Array.isArray(recovery.transportInvocations) ||
      recovery.transportInvocations.join('\0') !== expected.plan.relays
        .map(relay => `INBOX.CREATE:${relay.relayId}`).join('\0')) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_DURABILITY_INVALID',
      'durable recovery record does not bind the exact Seq29 plan and CREATE set')
  }
  validatePeeritLimitedPublicInboxSigningPackageV1(recovery.signingPackage)
  return recovery
}

async function commitCustodyPublicBinding (custody, recovery) {
  return durableReceipt(await custody.commitPublicBinding(Object.freeze({
    transactionId: recovery.custodyTransactionId,
    planHash: recovery.planHash,
    attemptId: recovery.attemptId,
    signingPackage: recovery.signingPackage,
    signingPackageSha256: recovery.signingPackageSha256,
    publicBindingDigest: recovery.custodyPublicBindingDigest
  })), 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP', [
    'accepted', 'durable', 'state', 'transactionId', 'signingPackageSha256',
    'publicBindingDigest', 'commitment'
  ], 'custody public binding commit', {
    transactionId: recovery.custodyTransactionId,
    signingPackageSha256: recovery.signingPackageSha256,
    publicBindingDigest: recovery.custodyPublicBindingDigest
  })
}

function releaseIdentityDigest (plan) {
  return objectDigest({
    schema: 'peerit-seq29-limited-inbox-release-identity-v1',
    candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    releaseSequence: PEERIT_LIMITED_PUBLIC_INBOX_RELEASE_SEQUENCE_V1,
    relays: plan.relays.map(relay => ({
      relayId: relay.relayId,
      relayPublicKey: relay.relayPublicKey,
      storeId: relay.storeId,
      durabilityContinuityHash: relay.durabilityContinuityHash,
      descriptorFloor: relay.descriptorFloor,
      allocationEpoch: relay.allocationEpoch
    }))
  })
}

function validateCreatedReplica (entry) {
  const { relay, created } = entry
  const relayKey = hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey')
  if (!created || typeof created !== 'object' || !created.request ||
      !created.readCap || !created.writeCap ||
      created.readCap.appendPublicKey !== null ||
      created.writeCap.appendPrivateKey !== null ||
      created.readCap.appendAuthMode !== 0 || created.readCap.frameClassBits !== 3 ||
      !bytesEqual(bytes(created.readCap.relayPublicKey, 'readCap relayPublicKey'), relayKey) ||
      created.request.allocationEpoch !== relay.allocationEpoch ||
      created.request.frameClassBits !== 3 || created.request.appendAuthMode !== 0 ||
      created.request.appendPublicKey !== null || created.request.retentionClass !== 3 ||
      created.request.leaseClass !== 4 || created.wire?.familyId !== 3 ||
      created.wire?.operationId !== 1) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_OPEN_APPEND_REQUIRED',
      `${relay.relayId} generated capability is not the exact OPEN_APPEND CREATE shape`)
  }
  for (const [value, field] of [
    [created.request.createPublicKey, 'request createPublicKey'],
    [created.request.renewPublicKey, 'request renewPublicKey'],
    [created.request.closePublicKey, 'request closePublicKey'],
    [created.request.clientNonce, 'request clientNonce'],
    [created.createCommitment, 'createCommitment'],
    [created.requestCommitment, 'requestCommitment'],
    [created.request.physicalTopic, 'request physicalTopic'],
    [created.readCap.physicalTopic, 'readCap physicalTopic']
  ]) {
    if (bytes(value, field).byteLength !== 32) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_CONTROL_INVALID', `${field} must be 32 bytes`)
    }
  }
  if (!bytesEqual(bytes(created.request.physicalTopic, 'request physicalTopic'),
    bytes(created.readCap.physicalTopic, 'readCap physicalTopic'))) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_CONTROL_INVALID',
      'CREATE request topic must equal the retained read capability topic')
  }
}

function managementCustodyEntries (entries) {
  return Object.freeze(entries.map(({ relay, created }) => Object.freeze({
    relayId: relay.relayId,
    allocationEpoch: relay.allocationEpoch,
    createPrivateSeed: created.writeCap.createPrivateKey,
    renewPrivateSeed: created.writeCap.renewPrivateKey,
    closePrivateSeed: created.writeCap.closePrivateKey
  })))
}

function verifyReceiptBinding (entry, receipt) {
  const { relay, created } = entry
  const binding = receipt?.relayBinding
  const topic = bytes(created.readCap.physicalTopic, 'physicalTopic')
  if (!binding ||
      !bytesEqual(bytes(binding.relayPublicKey, 'receipt relayPublicKey'),
        hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey')) ||
      !bytesEqual(bytes(binding.storeId, 'receipt storeId'),
        hexToBytes(relay.storeId, 32, 'storeId')) ||
      !bytesEqual(bytes(binding.durabilityContinuityHash, 'receipt continuity'),
        hexToBytes(relay.durabilityContinuityHash, 32, 'durabilityContinuityHash')) ||
      String(binding.descriptorSequence) !== relay.descriptorFloor.sequence ||
      !bytesEqual(bytes(binding.descriptorHash, 'receipt descriptorHash'),
        hexToBytes(relay.descriptorFloor.hash, 32, 'descriptorFloor.hash')) ||
      !bytesEqual(bytes(receipt.topicCommitment, 'receipt topicCommitment'), blake2b256(topic)) ||
      receipt.result !== 1 || String(receipt.stateRevision) !== '0' || receipt.leaseClass !== 4) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_RECEIPT_INVALID',
      `${relay.relayId} CREATE receipt does not bind the plan relay, floor and emitted topic`)
  }
}

export async function executePeeritLimitedInboxTopicCeremonyV1 (input = {}) {
  exact(input, ['authority', 'commitToken', 'attemptJournal', 'custodyTransaction'],
    'ceremony execution input')
  const authority = CEREMONY_AUTHORITIES.get(input.authority)
  if (!authority) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      'module-created authenticated ceremony authority is required')
  }
  const plan = authority.plan
  const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  if (input.commitToken !== `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${planHash}`) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_COMMIT_REQUIRED',
      'exact ceremony plan commit token is required')
  }
  const control = authority.control
  const journal = interfaceWithMethods(input.attemptJournal,
    ['beginAttempt', 'claimOperation', 'recordOutcome', 'persistRecovery', 'finishAttempt'],
    'PEERIT_LIMITED_INBOX_CEREMONY_JOURNAL_REQUIRED', 'durable attempt journal')
  const custody = interfaceWithMethods(input.custodyTransaction,
    ['prepare', 'commitPublicBinding', 'finalizeSignedBootstrap', 'quarantine'],
    'PEERIT_LIMITED_INBOX_CEREMONY_CUSTODY_REQUIRED', 'durable custody transaction')
  for (const relay of plan.relays) {
    if (!authority.rowByRelay.get(relay.relayId)?.endpoint) {
      fail('PEERIT_LIMITED_INBOX_CEREMONY_ENDPOINT_REQUIRED',
        `authenticated CREATE endpoint is missing for ${relay.relayId}`)
    }
  }
  const relayIdentityDigest = releaseIdentityDigest(plan)
  const beginRequest = ceremonyBeginRequest(
    plan, planHash, input.commitToken, authority.attemptBinding)
  const beginRequestDigest = objectDigest(beginRequest)
  const begunValue = await journal.beginAttempt(beginRequest)
  const begunFields = [
    'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
    'planHash', 'requestDigest', 'commitment'
  ]
  if (begunValue?.state === 'RECOVERY_AVAILABLE_NO_RESEND') {
    const begun = durableReceipt(begunValue, 'RECOVERY_AVAILABLE_NO_RESEND',
      [...begunFields, 'recovery'], 'attempt recovery', {
        releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
        planHash,
        requestDigest: beginRequestDigest
      })
    const recovery = validatedCeremonyRecovery(begun.recovery, {
      plan, planHash, attemptId: begun.attemptId, relayIdentityDigest
    })
    const custodyBinding = await commitCustodyPublicBinding(custody, recovery)
    return Object.freeze({
      schema: 'peerit-limited-inbox-topic-ceremony-result-v1',
      status: 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP',
      planHash,
      attemptId: begun.attemptId,
      signingPackage: recovery.signingPackage,
      custodyCommitment: custodyBinding.commitment,
      journalCommitment: begun.commitment,
      mutationLedger: Object.freeze({
        inboxCreate: 0,
        inboxRenew: 0,
        inboxClose: 0,
        inboxAppend: 0,
        cellPut: 0,
        other: 0
      }),
      recoveredOriginalMutationLedger: Object.freeze({ inboxCreate: 2 })
    })
  }
  const begun = durableReceipt(begunValue, 'CONSUMED_NO_MUTATIONS',
    begunFields, 'attempt begin', {
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      requestDigest: beginRequestDigest
    })
  const attemptId = opaqueId(begun.attemptId, 'attemptId')
  const entries = []
  const transportInvocations = []
  let custodyPending = null
  let recoveryPersisted = false
  try {
    let exactCustodyBinding = null
    if (authority.preNetworkCustody != null) {
      exactCustodyBinding = await bindPeeritSeq29PreNetworkCustodyToExactPlanV1({
        preNetworkCustody: authority.preNetworkCustody,
        plan,
        planHash,
        attemptId,
        normalCustody: custody
      })
      custodyPending = durableReceipt(Object.freeze({
        accepted: true,
        durable: true,
        state: 'SEALED_PENDING_CREATE',
        transactionId: exactCustodyBinding.transactionId,
        commitment: exactCustodyBinding.commitment
      }), 'SEALED_PENDING_CREATE',
      ['accepted', 'durable', 'state', 'transactionId', 'commitment'],
      'exact-plan custody binding')
      opaqueId(custodyPending.transactionId, 'custody transactionId')
    }
    for (const relay of plan.relays) {
      const row = authority.rowByRelay.get(relay.relayId)
      const created = exactCustodyBinding == null
        ? await control.createInboxReplica({
          runtime: authority.runtime,
          relayPublicKey: Uint8Array.from(Buffer.from(relay.relayPublicKey, 'hex')),
          allocationEpoch: relay.allocationEpoch,
          frameClassBits: 3,
          appendAuthMode: 0,
          retentionClass: 3,
          leaseClass: 4,
          ...(row.admissionProvider
            ? { admissionProvider: row.admissionProvider }
            : { admission: row.admission }),
          clientNonce: row.clientNonce
        })
        : await replayPeeritSeq29CustodiedInboxCreateV1({
          binding: exactCustodyBinding,
          relayId: relay.relayId,
          admissionProvider: row.admissionProvider
        })
      const entry = { relay, created, receiptBytes: null }
      // Track before inspecting any generated field so malformed output is
      // still destroyed in finally.
      entries.push(entry)
      validateCreatedReplica(entry)
    }
    assertSixDistinctManagementSeeds(entries)
    if (exactCustodyBinding == null) {
      custodyPending = durableReceipt(await custody.prepare(Object.freeze({
        schema: 'peerit-limited-inbox-topic-private-custody-input-v1',
        disposition: 'SEALED_PENDING_CREATE',
        planHash,
        attemptId,
        entries: managementCustodyEntries(entries)
      })), 'SEALED_PENDING_CREATE',
      ['accepted', 'durable', 'state', 'transactionId', 'commitment'], 'custody prepare')
      opaqueId(custodyPending.transactionId, 'custody transactionId')
    }

    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index]
      const { relay, created } = entry
      const endpoint = authority.rowByRelay.get(relay.relayId).endpoint
      const operationKey = `INBOX.CREATE:${relay.relayId}`
      const claimRequest = Object.freeze({
        attemptId,
        releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
        planHash,
        operationIndex: index,
        operationKey,
        family: 'INBOX',
        operation: 'CREATE',
        relayId: relay.relayId
      })
      durableReceipt(await journal.claimOperation(claimRequest), 'DISPATCH_CLAIMED',
        [
          'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
          'planHash', 'operationKey', 'requestDigest', 'commitment'
        ], `claim ${operationKey}`, {
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
          planHash,
          operationKey,
          requestDigest: objectDigest(claimRequest)
        })
      let response
      transportInvocations.push(operationKey)
      try {
        response = await authority.transportCreate({
          relayId: relay.relayId,
          endpoint,
          request: created.request,
          requestBytes: created.requestBytes,
          requestCommitment: created.requestCommitment,
          wire: created.wire
        })
      } catch (cause) {
        const outcomeRequest = Object.freeze({
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
          planHash,
          operationKey,
          state: 'AMBIGUOUS_TERMINAL'
        })
        durableReceipt(await journal.recordOutcome(outcomeRequest), 'AMBIGUOUS_TERMINAL',
          [
            'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
            'planHash', 'operationKey', 'requestDigest', 'commitment'
          ], `outcome ${operationKey}`, {
            attemptId,
            releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
            planHash,
            operationKey,
            requestDigest: objectDigest(outcomeRequest)
          })
        fail('PEERIT_LIMITED_INBOX_CEREMONY_CREATE_AMBIGUOUS',
          `${relay.relayId} CREATE transport outcome is ambiguous`, cause)
      }
      if (!response || response.ok !== true) {
        const outcomeRequest = Object.freeze({
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
          planHash,
          operationKey,
          state: 'REJECTED_TERMINAL'
        })
        durableReceipt(await journal.recordOutcome(outcomeRequest), 'REJECTED_TERMINAL',
          [
            'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
            'planHash', 'operationKey', 'requestDigest', 'commitment'
          ], `outcome ${operationKey}`, {
            attemptId,
            releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
            planHash,
            operationKey,
            requestDigest: objectDigest(outcomeRequest)
          })
        fail('PEERIT_LIMITED_INBOX_CEREMONY_CREATE_REJECTED',
          `${relay.relayId} CREATE was rejected`)
      }
      try {
        const verified = await control.verifyOperationResult({
          endpoint,
          request: created.request,
          requestCommitment: created.requestCommitment,
          resultBytes: response.body
        })
        const receiptBytes = bytes(verified.snapshotBytes(), 'verified CREATE receipt').slice()
        const receipt = control.decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes)
        verifyReceiptBinding(entry, receipt)
        entry.receiptBytes = receiptBytes
      } catch (cause) {
        const outcomeRequest = Object.freeze({
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
          planHash,
          operationKey,
          state: 'INVALID_RESULT_TERMINAL'
        })
        durableReceipt(await journal.recordOutcome(outcomeRequest), 'INVALID_RESULT_TERMINAL',
          [
            'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
            'planHash', 'operationKey', 'requestDigest', 'commitment'
          ], `outcome ${operationKey}`, {
            attemptId,
            releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
            planHash,
            operationKey,
            requestDigest: objectDigest(outcomeRequest)
          })
        throw cause
      }
      const outcomeRequest = Object.freeze({
        attemptId,
        releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
        planHash,
        operationKey,
        state: 'VERIFIED_TERMINAL',
        receiptSha256: createHash('sha256').update(entry.receiptBytes).digest('hex')
      })
      durableReceipt(await journal.recordOutcome(outcomeRequest), 'VERIFIED_TERMINAL',
        [
          'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
          'planHash', 'operationKey', 'requestDigest', 'commitment'
        ], `outcome ${operationKey}`, {
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
          planHash,
          operationKey,
          requestDigest: objectDigest(outcomeRequest)
        })
    }

    const inboxEpoch = Math.floor(Number(BigInt(plan.referenceUnixMillis) / 21600000n) / 28)
    const payload = {
      schema: 'peerit-limited-public-inbox-bootstrap-v1',
      version: 1,
      artifactClass: 'LIMITED_PUBLIC_TEST_RELEASE',
      claimBoundary: plan.claimBoundary,
      operatorBoundary: plan.operatorBoundary,
      topicScope: plan.topicScope,
      profileId: '@peerit/hiverelay-profile-v1',
      releaseSequence: plan.releaseSequence,
      bootstrapSequence: plan.bootstrapSequence,
      previousBootstrapHash: plan.previousBootstrapHash,
      issuedUnixMillis: plan.issuedUnixMillis,
      expiresUnixMillis: plan.expiresUnixMillis,
      authorityPublicKey: plan.authorityPublicKey,
      relays: plan.relays.map(publicRelay),
      inboxEpochSets: [{
        inboxEpoch,
        stripeCountLog2: 0,
        stripeSelectionKey: plan.stripeSelectionKey,
        announcementMasterKey: plan.announcementMasterKey,
        bindings: entries.map(({ relay, created, receiptBytes }) => ({
          inboxEpoch,
          stripeIndex: 0,
          relayId: relay.relayId,
          relayPublicKey: relay.relayPublicKey,
          allocationEpoch: relay.allocationEpoch,
          createPublicKey: bytesToHex(created.request.createPublicKey),
          physicalTopic: bytesToHex(created.readCap.physicalTopic),
          frameClassBits: 3,
          appendAuthMode: 0,
          retentionClass: 3,
          leaseClass: 4,
          createReceiptCanonicalHex: bytesToHex(receiptBytes)
        }))
      }]
    }
    const signingPackage = {
      schema: PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1,
      version: 1,
      offlineOnly: true,
      hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
      createRequests: entries.map(({ relay, created }) => ({
        relayId: relay.relayId,
        allocationEpoch: created.request.allocationEpoch,
        physicalTopic: bytesToHex(created.request.physicalTopic),
        frameClassBits: created.request.frameClassBits,
        appendAuthMode: created.request.appendAuthMode,
        createPublicKey: bytesToHex(created.request.createPublicKey),
        appendPublicKey: null,
        renewPublicKey: bytesToHex(created.request.renewPublicKey),
        closePublicKey: bytesToHex(created.request.closePublicKey),
        retentionClass: created.request.retentionClass,
        leaseClass: created.request.leaseClass,
        clientNonce: bytesToHex(created.request.clientNonce),
        createCommitment: bytesToHex(created.createCommitment),
        requestCommitment: bytesToHex(created.requestCommitment)
      })),
      payload
    }
    validatePeeritLimitedPublicInboxSigningPackageV1(signingPackage)
    const signingPackageSha256 = objectDigest(signingPackage)
    const executionDigest = objectDigest({
      schema: 'peerit-limited-inbox-topic-execution-v1',
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      relayIdentityDigest,
      transportInvocations,
      receipts: entries.map(({ relay, receiptBytes }) => ({
        operationKey: `INBOX.CREATE:${relay.relayId}`,
        receiptSha256: createHash('sha256').update(receiptBytes).digest('hex')
      })),
      signingPackageSha256
    })
    const custodyPublicBindingDigest = objectDigest({
      schema: 'peerit-seq29-limited-inbox-custody-public-binding-v1',
      planHash,
      signingPackageSha256,
      signingPackage
    })
    const recovery = Object.freeze({
      schema: 'peerit-limited-inbox-topic-recovery-v2',
      planHash,
      attemptId,
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      relayIdentityDigest,
      signingPackage,
      signingPackageSha256,
      custodyTransactionId: custodyPending.transactionId,
      custodyPublicBindingDigest,
      transportInvocations: Object.freeze([...transportInvocations]),
      executionDigest
    })
    const persistRequest = Object.freeze({
      attemptId,
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      recovery,
      recoveryDigest: objectDigest(recovery)
    })
    const persistedRecovery = durableReceipt(await journal.persistRecovery(persistRequest),
      'RECOVERY_DURABLE_NO_RESEND', [
        'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
        'planHash', 'requestDigest', 'recoveryDigest', 'commitment'
      ], 'public signing-package recovery persistence', {
        attemptId,
        releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
        planHash,
        requestDigest: objectDigest(persistRequest),
        recoveryDigest: persistRequest.recoveryDigest
      })
    recoveryPersisted = true
    const custodyBinding = await commitCustodyPublicBinding(custody, recovery)
    return Object.freeze({
      schema: 'peerit-limited-inbox-topic-ceremony-result-v1',
      status: 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP',
      planHash,
      attemptId,
      signingPackage,
      custodyCommitment: custodyBinding.commitment,
      journalCommitment: persistedRecovery.commitment,
      mutationLedger: Object.freeze({
        inboxCreate: transportInvocations.length,
        inboxRenew: 0,
        inboxClose: 0,
        inboxAppend: 0,
        cellPut: 0,
        other: 0
      })
    })
  } catch (cause) {
    if (custodyPending && !recoveryPersisted) {
      try {
        durableReceipt(await custody.quarantine(Object.freeze({
          transactionId: custodyPending.transactionId,
          planHash,
          attemptId,
          disposition: transportInvocations.length === 0
            ? 'QUARANTINED_NO_CREATE'
            : 'QUARANTINED_CREATE_OUTCOME'
        })), 'QUARANTINED',
        ['accepted', 'durable', 'state', 'transactionId', 'commitment'],
        'custody quarantine')
      } catch {}
    }
    // Once the exact signing package and CREATE receipts are durable, this is
    // a resumable no-resend state. Never terminally finish that release slot
    // merely because the independent custody public-binding write failed.
    if (!recoveryPersisted) {
      try {
        const finishRequest = Object.freeze({
          attemptId,
          releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
          planHash,
          state: 'QUARANTINED_TERMINAL_NO_RETRY',
          recoveryPersisted,
          transportInvocations: Object.freeze([...transportInvocations])
        })
        durableReceipt(await journal.finishAttempt(finishRequest),
          'QUARANTINED_TERMINAL_NO_RETRY', [
            'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
            'planHash', 'requestDigest', 'commitment'
          ], 'terminal attempt finish', {
            attemptId,
            releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
            planHash,
            requestDigest: objectDigest(finishRequest)
          })
      } catch {}
    }
    fail('PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED',
      'ceremony failed closed; created topics, if any, are quarantined and no lifecycle compensation was attempted', {
        attemptId,
        generatedCreateCapabilities: entries.length,
        transportInvocations: transportInvocations.length,
        lifecycleCompensationWrites: 0,
        recoveryPersisted,
        causeCode: cause?.code || null,
        causeMessage: cause?.message || null
      })
  } finally {
    // A broken destroy hook for one capability must not prevent every other
    // generated capability from being wiped.
    for (const entry of entries) {
      try { control.destroyInboxWriteCapability(entry.created.writeCap) } catch {}
    }
  }
}

export async function finalizePeeritLimitedInboxTopicCeremonyV1 (input = {}) {
  exact(input, [
    'authority', 'commitToken', 'signedBootstrap', 'attemptJournal', 'custodyTransaction'
  ], 'ceremony finalization input')
  const authority = CEREMONY_AUTHORITIES.get(input.authority)
  if (!authority) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID',
      'module-created authenticated ceremony authority is required')
  }
  const plan = authority.plan
  const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  if (input.commitToken !== `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${planHash}`) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_COMMIT_REQUIRED',
      'exact ceremony plan commit token is required')
  }
  const journal = interfaceWithMethods(input.attemptJournal,
    ['beginAttempt', 'claimOperation', 'recordOutcome', 'persistRecovery', 'finishAttempt'],
    'PEERIT_LIMITED_INBOX_CEREMONY_JOURNAL_REQUIRED', 'durable attempt journal')
  const custody = interfaceWithMethods(input.custodyTransaction,
    ['prepare', 'commitPublicBinding', 'finalizeSignedBootstrap', 'quarantine'],
    'PEERIT_LIMITED_INBOX_CEREMONY_CUSTODY_REQUIRED', 'durable custody transaction')
  const relayIdentityDigest = releaseIdentityDigest(plan)
  const beginRequest = ceremonyBeginRequest(
    plan, planHash, input.commitToken, authority.attemptBinding)
  const begun = durableReceipt(await journal.beginAttempt(beginRequest),
    'RECOVERY_AVAILABLE_NO_RESEND', [
      'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
      'planHash', 'requestDigest', 'recovery', 'commitment'
    ], 'attempt finalization recovery', {
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      requestDigest: objectDigest(beginRequest)
    })
  const recovery = validatedCeremonyRecovery(begun.recovery, {
    plan, planHash, attemptId: begun.attemptId, relayIdentityDigest
  })
  await commitCustodyPublicBinding(custody, recovery)
  const signed = validatePeeritLimitedPublicInboxSignedWrapperV1(input.signedBootstrap, {
    allowFixture: authority.fixtureOnly,
    createRequests: recovery.signingPackage.createRequests
  })
  if (objectDigest(signed.payload) !== objectDigest(recovery.signingPackage.payload)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_SIGNED_BOOTSTRAP_INVALID',
      'signed bootstrap payload differs from the exact durable signing package')
  }
  const signedBootstrap = Object.freeze({ payload: signed.payload, signature: signed.signature })
  const signedBootstrapHash = hashPeeritLimitedPublicInboxSignedWrapperV1(
    signed.canonicalBytes, {
      allowFixture: authority.fixtureOnly,
      createRequests: recovery.signingPackage.createRequests
    })
  const finalizationDigest = objectDigest({
    schema: 'peerit-seq29-limited-inbox-custody-finalization-v1',
    planHash,
    publicBindingDigest: recovery.custodyPublicBindingDigest,
    signedBootstrapHash,
    signedBootstrap
  })
  const committed = durableReceipt(await custody.finalizeSignedBootstrap(Object.freeze({
    transactionId: recovery.custodyTransactionId,
    planHash,
    attemptId: recovery.attemptId,
    signingPackageSha256: recovery.signingPackageSha256,
    publicBindingDigest: recovery.custodyPublicBindingDigest,
    signedBootstrap,
    signedBootstrapHash,
    finalizationDigest
  })), 'COMMITTED', [
    'accepted', 'durable', 'state', 'transactionId', 'publicBindingDigest',
    'signedBootstrapHash', 'finalizationDigest', 'managementBundleDigest', 'commitment'
  ], 'custody signed-bootstrap finalization', {
    transactionId: recovery.custodyTransactionId,
    publicBindingDigest: recovery.custodyPublicBindingDigest,
    signedBootstrapHash,
    finalizationDigest
  })
  if (!/^[0-9a-f]{64}$/.test(committed.managementBundleDigest)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_DURABILITY_INVALID',
      'custody finalization omitted its exact management bundle digest')
  }
  const finishRequest = Object.freeze({
    attemptId: recovery.attemptId,
    releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
    planHash,
    state: 'COMMITTED_CREATE_ONLY',
    executionDigest: recovery.executionDigest,
    signedBootstrapHash,
    managementBundleDigest: committed.managementBundleDigest,
    custodyCommitment: committed.commitment,
    transportInvocations: recovery.transportInvocations
  })
  const finished = durableReceipt(await journal.finishAttempt(finishRequest),
    'COMMITTED_CREATE_ONLY', [
      'accepted', 'durable', 'state', 'attemptId', 'releaseAttemptKey',
      'planHash', 'requestDigest', 'executionDigest', 'commitment'
    ], 'attempt finish', {
      attemptId: recovery.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      requestDigest: objectDigest(finishRequest),
      executionDigest: recovery.executionDigest
    })
  return Object.freeze({
    schema: 'peerit-limited-inbox-topic-ceremony-result-v1',
    status: 'COMMITTED_CREATE_ONLY',
    planHash,
    attemptId: recovery.attemptId,
    signedBootstrapHash,
    managementBundleDigest: committed.managementBundleDigest,
    custodyCommitment: committed.commitment,
    journalCommitment: finished.commitment,
    mutationLedger: Object.freeze({
      inboxCreate: 0,
      inboxRenew: 0,
      inboxClose: 0,
      inboxAppend: 0,
      cellPut: 0,
      other: 0
    }),
    recoveredOriginalMutationLedger: Object.freeze({ inboxCreate: 2 })
  })
}

function readCanonicalPlan (path) {
  const bytes = readFileSync(resolve(path))
  let value
  try { value = JSON.parse(bytes.toString('utf8')) } catch {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID', 'plan is not JSON')
  }
  const canonical = Buffer.from(JSON.stringify(value, null, 2) + '\n')
  if (!canonical.equals(bytes)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
      'plan must be canonical pretty JSON with one trailing newline')
  }
  return value
}

function main () {
  const command = process.argv[2]
  const inputIndex = process.argv.indexOf('--input')
  const path = inputIndex >= 0 ? process.argv[inputIndex + 1] : null
  if (!path || !['validate', 'dry-run'].includes(command)) {
    fail('PEERIT_LIMITED_INBOX_CEREMONY_USAGE',
      'usage: limited-inbox-topic-ceremony.mjs <validate|dry-run> --input <plan.json>')
  }
  const plan = readCanonicalPlan(path)
  const report = command === 'validate'
    ? { status: 'VALID', planHash: peeritLimitedInboxTopicCeremonyPlanHashV1(plan), networkRequests: 0 }
    : dryRunPeeritLimitedInboxTopicCeremonyV1(plan)
  console.log(JSON.stringify(report, null, 2))
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { main() } catch (error) {
    console.error(`${error.code || 'PEERIT_LIMITED_INBOX_CEREMONY_FAILED'}: ${error.message}`)
    process.exitCode = 1
  }
}
