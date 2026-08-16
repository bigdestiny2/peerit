import assert from 'node:assert/strict'
import {
  POW_ISSUANCE_V1_TOKEN_BYTES,
  createPowIssuanceV1AdmissionProviderFactory
} from '../js/substrate/pow-issuance-spend-provider.mjs'

const relayPublicKey = new Uint8Array(32).fill(0x41)
const parameterHash = new Uint8Array(32).fill(0x42)
const challenge = new Uint8Array(74)
challenge[0] = 1
challenge[41] = 1
let challengeRequests = 0
let redeemRequests = 0
const factory = createPowIssuanceV1AdmissionProviderFactory({
  profileId: 23,
  schemeId: 1,
  issuers: [{
    relayPublicKey,
    issuanceUrl: 'https://issuer.seq29-provider.test/'
  }],
  async fetch (url, init = {}) {
    if (String(url).endsWith('/challenge')) {
      challengeRequests++
      return {
        status: 200,
        async json () {
          return {
            scheme: 'pow-issuance-v1',
            challenge: Buffer.from(challenge).toString('base64url'),
            difficultyBits: 1,
            expiresAtUnix: 1
          }
        }
      }
    }
    redeemRequests++
    const request = JSON.parse(init.body)
    return {
      status: 200,
      async json () {
        return {
          scheme: 'pow-issuance-v1',
          token: '51'.repeat(POW_ISSUANCE_V1_TOKEN_BYTES),
          allowance: request.allowance,
          expiryEpoch: 100
        }
      }
    }
  }
})
const provider = await factory.createAdmissionProvider({
  endpointContext: { relayPublicKey },
  verifiedAdmissionParameters: { parameterHash },
  admissionProfile: {
    profileId: 23,
    schemeId: 1,
    parameterUrl: null
  }
})

const appendSession = factory.beginOperationRecord({
  operations: [{ kind: 'append', relayPublicKey }]
})
const append = await provider({
  familyId: 3,
  operationId: 4,
  relayPublicKey,
  requestCommitment: new Uint8Array(32).fill(0x43)
})
await appendSession.complete
assert.equal(append.profileId, 23)
assert.equal(append.schemeId, 1)
assert.deepEqual(append.parameterHash, parameterHash)
assert.equal(append.token.byteLength, POW_ISSUANCE_V1_TOKEN_BYTES + 1)
assert.equal(append.token[POW_ISSUANCE_V1_TOKEN_BYTES], 0,
  'the fresh one-slot APPEND record carries spend index zero')
appendSession.close()

assert.throws(() => factory.beginOperationRecord({
  operations: [{ kind: 'create', relayPublicKey }]
}), error => error.code === 'PEERIT_POW_ISSUANCE_OPERATION_INVALID',
'the shipped operation-record constructor cannot express CREATE authority')
await assert.rejects(() => provider({
  familyId: 3,
  operationId: 1,
  relayPublicKey,
  requestCommitment: new Uint8Array(32).fill(0x44)
}), error => error.code === 'PEERIT_POW_ISSUANCE_OPERATION_INVALID',
'the shipped browser provider rejects CREATE contexts')

assert.equal(challengeRequests, 1)
assert.equal(redeemRequests, 1,
  'rejected CREATE authority causes no issuer traffic')
console.log('peerit seq29 pow provider: exact one-slot APPEND admitted; CREATE unavailable')
