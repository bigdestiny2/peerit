import assert from 'node:assert/strict'

import {
  createPeeritSeq29InboxCreateAdmissionAuthorityV1,
  resolvePeeritSeq29InboxCreateAdmissionProviderV1
} from '../scripts/lib/seq29-live-inbox-create-admission.mjs'

const EPOCH_MILLIS = 21_600_000
const relayPublicKey = new Uint8Array(32).fill(0x81)
const parameterHash = new Uint8Array(32).fill(0x82)
const requestCommitment = new Uint8Array(32).fill(0x84)

function base64url (value) {
  return Buffer.from(value).toString('base64url')
}

function endpointContext () {
  return Object.freeze({
    descriptorHash: new Uint8Array(32).fill(1),
    descriptorSequence: 1n,
    relayPublicKey,
    storeId: new Uint8Array(32).fill(2),
    continuityRoot: relayPublicKey,
    familyId: 3,
    operationId: 1,
    endpointId: 1,
    transportId: 1,
    transportSupportBit: 1,
    privacyProfileBit: 1,
    durabilityProfileId: 1,
    durabilityContinuityHash: new Uint8Array(32).fill(3),
    durabilityProfileHash: new Uint8Array(32).fill(4),
    restoreEvidenceHeadSequence: 0n,
    restoreEvidenceHeadHash: new Uint8Array(32).fill(5),
    externalWitnessPublicKey: new Uint8Array(32).fill(6),
    externalJournalId: new Uint8Array(32).fill(7)
  })
}

function authorityInput (fetch) {
  const allocationEpoch = Math.floor(Date.now() / EPOCH_MILLIS)
  return {
    relayId: 'dal-1',
    relayPublicKey,
    issuanceUrl: 'https://relay-dal.p2phiverelay.xyz:8443/',
    verifiedAdmissionParameters: { parameterHash },
    endpointContext: endpointContext(),
    validity: {
      allocationEpoch,
      validFromEpoch: allocationEpoch,
      expiresEpoch: allocationEpoch + 1
    },
    fetch,
    signal: undefined
  }
}

function operationContext () {
  return {
    familyId: 3,
    operationId: 1,
    requestCommitment,
    relayPublicKey,
    frameClassBits: 3,
    retentionClass: 3,
    leaseClass: 4
  }
}

function challenge (difficultyBits, payloadHex = null) {
  const value = new Uint8Array(74)
  if (payloadHex == null) {
    value[0] = 1
    value[41] = difficultyBits
  } else {
    value.set(Buffer.from(payloadHex, 'hex'))
  }
  return value
}

function challengeResponse (value, difficultyBits) {
  return {
    status: 200,
    async json () {
      return {
        scheme: 'pow-issuance-v1',
        challenge: base64url(value),
        difficultyBits,
        expiresAtUnix: 4_000_000_000
      }
    }
  }
}

function tokenResponse (allowance = 1) {
  return {
    status: 200,
    async json () {
      return {
        scheme: 'pow-issuance-v1',
        token: '83'.repeat(103),
        allowance,
        expiryEpoch: 0xffffffff
      }
    }
  }
}

// Caller-selected descriptor/pow projections are no longer part of the
// constructor surface. Adding either one fails before issuer traffic.
{
  let calls = 0
  const input = authorityInput(async () => { calls++ })
  assert.throws(() => createPeeritSeq29InboxCreateAdmissionAuthorityV1({
    ...input,
    admissionProfile: {
      profileId: 8,
      schemeId: 1,
      conformanceClass: 1,
      roleBits: 49,
      parameterUrl: null
    }
  }), error => error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_INVALID')
  assert.throws(() => createPeeritSeq29InboxCreateAdmissionAuthorityV1({
    ...input,
    powIssuance: {
      schemeId: 1,
      profileId: 8,
      conformanceClass: 1,
      roleBits: 49,
      difficultyBits: 1,
      maximumTokenAllowance: 2,
      maximumCellSizeClass: 2,
      maximumCellLeaseClass: 2
    }
  }), error => error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_INVALID')
  assert.equal(calls, 0)
}

// The inert authority makes every accepted CREATE policy constant explicit.
{
  const authority = createPeeritSeq29InboxCreateAdmissionAuthorityV1(
    authorityInput(async () => { throw new Error('issuer must not be called') }))
  assert.deepEqual({
    profileId: authority.profileId,
    admissionProfileId: authority.admissionProfileId,
    schemeId: authority.schemeId,
    conformanceClass: authority.conformanceClass,
    roleBits: authority.roleBits,
    difficultyBits: authority.difficultyBits,
    maximumTokenAllowance: authority.maximumTokenAllowance,
    maximumCellSizeClass: authority.maximumCellSizeClass,
    maximumCellLeaseClass: authority.maximumCellLeaseClass,
    tokenAllowance: authority.tokenAllowance,
    oneShot: authority.oneShot
  }, {
    profileId: 3,
    admissionProfileId: 3,
    schemeId: 1,
    conformanceClass: 1,
    roleBits: 49,
    difficultyBits: 20,
    maximumTokenAllowance: 2,
    maximumCellSizeClass: 2,
    maximumCellLeaseClass: 2,
    tokenAllowance: 1,
    oneShot: true
  })
  assert.throws(() => resolvePeeritSeq29InboxCreateAdmissionProviderV1(
    Object.freeze({ ...authority }), { relayId: 'dal-1', relayPublicKey }),
  error => error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_AUTHORITY_REQUIRED')
}

// Any challenge other than the fixed 20-bit boundary consumes the capability
// before the issuer can redeem or a caller can retry.
{
  const calls = []
  const authority = createPeeritSeq29InboxCreateAdmissionAuthorityV1(
    authorityInput(async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' })
      return challengeResponse(challenge(19), 19)
    }))
  const provider = resolvePeeritSeq29InboxCreateAdmissionProviderV1(
    authority, { relayId: 'dal-1', relayPublicKey })
  await assert.rejects(provider(operationContext()), error =>
    error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_DIFFICULTY_DRIFT')
  await assert.rejects(provider(operationContext()), error =>
    error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_CONSUMED')
  assert.deepEqual(calls.map(value => value.method), ['GET'])
}

// This fixed challenge has a valid nonce zero for the test request commitment,
// so the real miner exercises the exact 20-bit path without a slow search.
{
  const challenge20 = challenge(20,
    '0100000000000000000000000000000000000000000000000000000000000000000012d4330000000014')
  const calls = []
  let redeemBody = null
  const authority = createPeeritSeq29InboxCreateAdmissionAuthorityV1(
    authorityInput(async (url, options = {}) => {
      calls.push({ url, method: options.method || 'GET' })
      if (String(url).endsWith('/challenge')) {
        return challengeResponse(challenge20, 20)
      }
      redeemBody = JSON.parse(options.body)
      return tokenResponse(1)
    }))
  const provider = resolvePeeritSeq29InboxCreateAdmissionProviderV1(
    authority, { relayId: 'dal-1', relayPublicKey })
  const admission = await provider(operationContext())
  assert.equal(admission.profileId, 3)
  assert.equal(admission.schemeId, 1)
  assert.deepEqual(admission.parameterHash, parameterHash)
  assert.equal(admission.token.byteLength, 104)
  assert.deepEqual(calls.map(value => value.method), ['GET', 'POST'])
  assert.equal(redeemBody.allowance, 1)
  assert.equal(redeemBody.nonce, '0000000000000000')
  await assert.rejects(provider(operationContext()), error =>
    error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_CONSUMED')
  assert.equal(calls.length, 2)
}

// Even after valid work, an issuer cannot expand the returned one-slot token.
{
  const challenge20 = challenge(20,
    '0100000000000000000000000000000000000000000000000000000000000000000012d4330000000014')
  const calls = []
  const authority = createPeeritSeq29InboxCreateAdmissionAuthorityV1(
    authorityInput(async (url, options = {}) => {
      calls.push(options.method || 'GET')
      return String(url).endsWith('/challenge')
        ? challengeResponse(challenge20, 20)
        : tokenResponse(2)
    }))
  const provider = resolvePeeritSeq29InboxCreateAdmissionProviderV1(
    authority, { relayId: 'dal-1', relayPublicKey })
  await assert.rejects(provider(operationContext()), error =>
    error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_ALLOWANCE_DRIFT')
  await assert.rejects(provider(operationContext()), error =>
    error.code === 'PEERIT_SEQ29_CREATE_ADMISSION_CONSUMED')
  assert.deepEqual(calls, ['GET', 'POST'])
}

console.log('peerit seq29 live CREATE admission: fixed 3/1/1/49/20/2/2/2 policy and one-shot allowance verified')
