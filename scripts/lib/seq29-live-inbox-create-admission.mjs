// Node-operator-only, one-shot pow-issuance admission for the fixed Seq29
// INBOX.CREATE ceremony. The returned value is inert metadata; the callable
// provider and every minted token remain in this module's WeakMap.

import {
  createPowIssuanceV1SpendProvider,
  POW_ISSUANCE_V1_SCHEME_ID
} from '../../js/substrate/pow-issuance-spend-provider.mjs'
import {
  asBytes,
  bytesEqual,
  bytesToHex,
  fixedBytesValue
} from '../../js/substrate/release-control-primitives.mjs'

const CANDIDATE_COMMIT = 'adeacef07c5de4d17d5ed1389fee7a35095b862f'
const EPOCH_MILLIS = 21_600_000
const PROVIDERS = new WeakMap()
const RELAY_IDS = new Set(['dal-1', 'syd-1'])
const CREATE_ADMISSION_PROFILE_ID = 3
const CREATE_ADMISSION_SCHEME_ID = 1
const CREATE_ADMISSION_CONFORMANCE_CLASS = 1
const CREATE_ADMISSION_ROLE_BITS = 49
const CREATE_ADMISSION_DIFFICULTY_BITS = 20
const CREATE_ADMISSION_MAXIMUM_TOKEN_ALLOWANCE = 2
const CREATE_ADMISSION_MAXIMUM_CELL_SIZE_CLASS = 2
const CREATE_ADMISSION_MAXIMUM_CELL_LEASE_CLASS = 2
const EXACT_SOURCE_E2E_FIXTURE_ENV =
  'PEERIT_SEQ29_CREATE_EXACT_SOURCE_E2E_TEST'

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function integer (value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_INVALID',
      `${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function relayId (value) {
  if (!RELAY_IDS.has(value)) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_INVALID',
      'relayId must be one of the fixed dal-1/syd-1 ceremony relays')
  }
  return value
}

function issuerOrigin (value, id) {
  const expected = `https://relay-${id === 'dal-1' ? 'dal' : 'syd'}.p2phiverelay.xyz:8443/`
  if (value === expected) return value
  let fixture = false
  if (process.env[EXACT_SOURCE_E2E_FIXTURE_ENV] === '1') {
    try {
      const url = new URL(value)
      fixture = url.protocol === 'https:' && url.hostname === '127.0.0.1' &&
        /^[1-9][0-9]{3,4}$/.test(url.port) && Number(url.port) <= 65535 &&
        url.pathname === '/' && url.username === '' &&
        url.password === '' && url.search === '' && url.hash === ''
    } catch {}
  }
  if (!fixture) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_INVALID',
      `${id} issuer origin differs from its signed profile pin`)
  }
  return value
}

function exactCreateAdmissionPolicy () {
  const policy = Object.freeze({
    profileId: CREATE_ADMISSION_PROFILE_ID,
    admissionProfileId: CREATE_ADMISSION_PROFILE_ID,
    schemeId: CREATE_ADMISSION_SCHEME_ID,
    conformanceClass: CREATE_ADMISSION_CONFORMANCE_CLASS,
    roleBits: CREATE_ADMISSION_ROLE_BITS,
    difficultyBits: CREATE_ADMISSION_DIFFICULTY_BITS,
    maximumTokenAllowance: CREATE_ADMISSION_MAXIMUM_TOKEN_ALLOWANCE,
    maximumCellSizeClass: CREATE_ADMISSION_MAXIMUM_CELL_SIZE_CLASS,
    maximumCellLeaseClass: CREATE_ADMISSION_MAXIMUM_CELL_LEASE_CLASS
  })
  if (policy.profileId !== 3 || policy.admissionProfileId !== 3 ||
      policy.schemeId !== POW_ISSUANCE_V1_SCHEME_ID ||
      policy.schemeId !== 1 || policy.conformanceClass !== 1 ||
      policy.roleBits !== 49 || policy.difficultyBits !== 20 ||
      policy.maximumTokenAllowance !== 2 ||
      policy.maximumCellSizeClass !== 2 ||
      policy.maximumCellLeaseClass !== 2) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_POLICY_INVALID',
      'the internal INBOX.CREATE admission policy differs from the accepted fixed boundary')
  }
  return policy
}

export function createPeeritSeq29InboxCreateAdmissionAuthorityV1 (input = {}) {
  exact(input, [
    'relayId', 'relayPublicKey', 'issuanceUrl', 'verifiedAdmissionParameters',
    'endpointContext', 'validity', 'fetch', 'signal'
  ], 'CREATE admission authority input')
  const policy = exactCreateAdmissionPolicy()
  const id = relayId(input.relayId)
  const relayPublicKey = fixedBytesValue(input.relayPublicKey, 32, 'relayPublicKey')
  const context = exact(input.endpointContext, [
    'descriptorHash', 'descriptorSequence', 'relayPublicKey', 'storeId',
    'continuityRoot', 'familyId', 'operationId', 'endpointId', 'transportId',
    'transportSupportBit', 'privacyProfileBit', 'durabilityProfileId',
    'durabilityContinuityHash', 'durabilityProfileHash',
    'restoreEvidenceHeadSequence', 'restoreEvidenceHeadHash',
    'externalWitnessPublicKey', 'externalJournalId'
  ], 'verified endpoint context')
  if (context.familyId !== 3 || context.operationId !== 1 ||
      !bytesEqual(asBytes(context.relayPublicKey, 'endpoint relayPublicKey'),
        relayPublicKey)) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_SCOPE_INVALID',
      `${id} admission authority is not bound to its verified INBOX.CREATE endpoint`)
  }
  const advertised = exact(input.verifiedAdmissionParameters, [
    'parameterHash'
  ], 'verified admission parameters projection')
  if (typeof input.fetch !== 'function') {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_SCOPE_INVALID',
      `${id} admission fetch differs from the fixed CREATE boundary`)
  }
  const parameterHash = fixedBytesValue(
    advertised.parameterHash, 32, 'verified admission parameterHash')
  const validity = exact(input.validity, [
    'allocationEpoch', 'validFromEpoch', 'expiresEpoch'
  ], 'CREATE admission validity')
  const allocationEpoch = integer(
    validity.allocationEpoch, 'allocationEpoch', 0, 0xffffffff)
  const validFromEpoch = integer(
    validity.validFromEpoch, 'validFromEpoch', 0, 0xffffffff)
  const expiresEpoch = integer(
    validity.expiresEpoch, 'expiresEpoch', 0, 0xffffffff)
  if (allocationEpoch < validFromEpoch || allocationEpoch >= expiresEpoch ||
      Math.floor(Date.now() / EPOCH_MILLIS) !== allocationEpoch) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_EXPIRED',
      `${id} qualification/admission window is not current`)
  }
  const spend = createPowIssuanceV1SpendProvider({
    issuanceUrl: issuerOrigin(input.issuanceUrl, id),
    fetch: input.fetch,
    signal: input.signal
  })
  let consumed = false
  async function provide (operationContext) {
    if (consumed) {
      fail('PEERIT_SEQ29_CREATE_ADMISSION_CONSUMED',
        `${id} INBOX.CREATE admission authority is one-shot`)
    }
    // Consume before any issuer request. An ambiguous issuer outcome cannot
    // remint and cannot create a third/retry path in this process.
    consumed = true
    if (Math.floor(Date.now() / EPOCH_MILLIS) !== allocationEpoch) {
      fail('PEERIT_SEQ29_CREATE_ADMISSION_EXPIRED',
        `${id} allocation epoch changed after qualification`)
    }
    exact(operationContext, [
      'familyId', 'operationId', 'requestCommitment', 'relayPublicKey',
      'frameClassBits', 'retentionClass', 'leaseClass'
    ], 'INBOX.CREATE admission context')
    const requestCommitment = fixedBytesValue(
      operationContext.requestCommitment, 32, 'requestCommitment')
    if (operationContext.familyId !== 3 || operationContext.operationId !== 1 ||
        operationContext.frameClassBits !== 3 || operationContext.retentionClass !== 3 ||
        operationContext.leaseClass !== 4 ||
        !bytesEqual(asBytes(operationContext.relayPublicKey,
          'operation relayPublicKey'), relayPublicKey)) {
      fail('PEERIT_SEQ29_CREATE_ADMISSION_SCOPE_INVALID',
        `${id} admission context escaped the fixed INBOX.CREATE profile`)
    }
    const commitments = [requestCommitment]
    const recordCommitment = spend.recordBindingRoot(commitments)
    const challenge = await spend.fetchChallenge(input.signal)
    if (challenge.difficultyBits !== policy.difficultyBits) {
      fail('PEERIT_SEQ29_CREATE_ADMISSION_DIFFICULTY_DRIFT',
        `${id} issuer challenge differs from the exact CREATE difficulty`)
    }
    const mined = await spend.mintNonce({
      challengePayload: challenge.challengePayload,
      recordCommitment,
      difficultyBits: policy.difficultyBits,
      signal: input.signal
    })
    const redeemed = await spend.redeem({
      challengeWire: challenge.challengeWire,
      nonce: mined.nonce,
      recordCommitment,
      allowance: 1,
      signal: input.signal
    })
    if (redeemed.allowance !== 1) {
      fail('PEERIT_SEQ29_CREATE_ADMISSION_ALLOWANCE_DRIFT',
        `${id} issuer token differs from the one-slot CREATE allowance`)
    }
    return Object.freeze({
      profileId: policy.profileId,
      schemeId: policy.schemeId,
      parameterHash: parameterHash.slice(),
      token: spend.presentation(redeemed.token, 0, commitments)
    })
  }
  const authority = Object.freeze({
    schema: 'peerit-seq29-inbox-create-admission-authority-v1',
    version: 1,
    candidateCommit: CANDIDATE_COMMIT,
    releaseSequence: 29,
    relayId: id,
    relayPublicKey: bytesToHex(relayPublicKey),
    family: 'INBOX',
    operation: 'CREATE',
    profileId: policy.profileId,
    admissionProfileId: policy.admissionProfileId,
    schemeId: policy.schemeId,
    conformanceClass: policy.conformanceClass,
    roleBits: policy.roleBits,
    parameterHash: bytesToHex(parameterHash),
    allocationEpoch,
    expiresEpoch,
    difficultyBits: policy.difficultyBits,
    maximumTokenAllowance: policy.maximumTokenAllowance,
    maximumCellSizeClass: policy.maximumCellSizeClass,
    maximumCellLeaseClass: policy.maximumCellLeaseClass,
    tokenAllowance: 1,
    oneShot: true
  })
  PROVIDERS.set(authority, Object.freeze({ provide, relayPublicKey }))
  return authority
}

export function resolvePeeritSeq29InboxCreateAdmissionProviderV1 (
  authority,
  expected = {}
) {
  exact(expected, ['relayId', 'relayPublicKey'], 'CREATE admission resolution')
  const state = PROVIDERS.get(authority)
  const expectedKey = fixedBytesValue(expected.relayPublicKey, 32,
    'expected relayPublicKey')
  if (!state || authority.relayId !== expected.relayId ||
      !bytesEqual(state.relayPublicKey, expectedKey)) {
    fail('PEERIT_SEQ29_CREATE_ADMISSION_AUTHORITY_REQUIRED',
      'a matching module-created one-shot CREATE admission authority is required')
  }
  return state.provide
}
