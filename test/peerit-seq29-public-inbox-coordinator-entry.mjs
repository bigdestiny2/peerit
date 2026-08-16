import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import { ready as cryptoReady } from '../js/crypto.js'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import {
  PEERIT_SEQ29_PUBLIC_INBOX_COORDINATOR_STATUS_V1,
  mergePeeritSeq29PublicInboxPollResultsV1,
  qualifyPeeritSeq29PublicInboxRelayEndpointsV1,
  settlePeeritSeq29DualAppendV1,
  verifyPeeritSeq29PublicInboxRelayEndpointsV1
} from '../js/substrate/public-inbox-boot-coordinator.mjs'
import {
  verifyPeeritLimitedPublicInboxBootstrapV1
} from '../js/substrate/inbox-topic-v1.mjs'
import * as browserControl from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'

await cryptoReady()

const coordinatorPath = 'js/substrate/public-inbox-boot-coordinator.mjs'
assert.equal(SUBSTRATE_SITE_FILES.includes(coordinatorPath), true,
  'seq29 coordinator is part of the authenticated shipped closure')
assert.deepEqual(PEERIT_SEQ29_PUBLIC_INBOX_COORDINATOR_STATUS_V1, {
  releaseSequence: 29,
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

const [entrySource, coordinatorSource, productUiSource] = await Promise.all([
  fs.readFile(new URL('../js/substrate/app-entry.js', import.meta.url), 'utf8'),
  fs.readFile(new URL('../js/substrate/public-inbox-boot-coordinator.mjs', import.meta.url), 'utf8'),
  fs.readFile(new URL('../js/substrate/peerit-product-ui.js', import.meta.url), 'utf8')
])
assert.equal(entrySource.includes('public-inbox-boot-coordinator'), true,
  'the shipped coordinator is connected to the app activation boundary')
assert.equal(entrySource.includes('peerit-limited-public-inbox-bootstrap-v1.json'), false,
  'the entry never fetches bootstrap bytes outside the authenticated runtime')
assert.equal(coordinatorSource.includes('input.profileValidator'), false,
  'the coordinator never accepts a caller-selected profile validator')
assert.match(coordinatorSource,
  /runtimeAssembly\.validatorInstantiationAuthorized !== false/,
  'general production-validator construction remains rejected')
assert.match(coordinatorSource,
  /seq29ValidationOnlyValidatorInstantiationAuthorized !== true/,
  'only the explicit runtime-owned pre-readback validator is admitted')
assert.equal(entrySource.includes('profileValidator'), false,
  'app entry never calls or treats the validation-only helper as acceptance authority')
assert.equal(entrySource.includes('get coordinator'), false,
  'app entry does not expose the internal publication coordinator')
assert.equal((entrySource.match(/publicInboxPublisher\.publishAuthoredIntent\(\{ intentId \}\)/g) || []).length, 1,
  'app entry has exactly one internal exact-intent publication call')
assert.match(entrySource, /await product\.sync\.journal\.getIntent\(intentId\)/,
  'the one publication call is preceded by an exact durable local-intent lookup')
assert.match(productUiSource, /event\?\.isTrusted === true/,
  'the shipped UI requires a trusted browser event before publication')
assert.match(productUiSource, /retry-explicit-publication/,
  'partial publication is resumed only from an explicit retry control')
assert.equal(entrySource.includes('resumeAuthoredPublication'), false,
  'the app entry has no automatic durable-publication recovery call')
assert.equal(productUiSource.includes('resumeAuthoredPublication'), false,
  'the shipped UI cannot invoke coordinator recovery behind the user')
assert.equal(/(?:setTimeout|setInterval|online|visibilitychange|pageshow|hashchange)[\s\S]{0,240}publishAuthoredIntent/.test(productUiSource), false,
  'timers, lifecycle, connectivity, and navigation handlers never trigger publication')
assert.match(coordinatorSource, /verifiedEndpointContext/,
  'relay endpoint selection crosses the authenticated endpoint identity boundary')
assert.match(coordinatorSource,
  /'appArtifactBytes', 'bootstrapBytes', 'relayEndpoints', 'profileValidator'/,
  'the coordinator rejects caller-selected assets, endpoints, and validator authority')
assert.match(coordinatorSource, /verifyPeeritPublicInboxAnnouncementReadbackV1/,
  'dual publication stays behind signed AuthorBind and CELL.GET readback')
assert.match(coordinatorSource,
  /const preparedPuts = await runtimePublicationControl\.createDualCellReplicasV1\(\{[\s\S]*?rows: endpointSets\.map/,
  'the authored path prepares one CELL.PUT row for every authenticated relay')
assert.match(coordinatorSource,
  /const putEvidence = await Promise\.all\(endpointSets\.map\([\s\S]*?dispatchPeeritSeq29CellPut/,
  'the authored path requires CELL.PUT evidence from both authenticated relays')
assert.match(coordinatorSource,
  /const authorization = await coordinator\.authorizeDualAppend\([\s\S]*?return publishAuthorized\(authorization/,
  'only dual CELL.PUT/readback authorization reaches the runtime-owned APPEND path')
const pollBody = coordinatorSource.match(
  /async pollAndIngest \(options = \{\}\) \{([\s\S]*?)\n {4}\},\n\n {4}async authorizeDualAppend/)
assert.ok(pollBody, 'the shipped background poll boundary is structurally present')
for (const forbidden of [
  'publishAuthored', 'publishAuthorized', 'dispatchPeeritSeq29CellPut',
  'createDualCellReplicasV1', 'prepareAppendV1'
]) {
  assert.equal(pollBody[1].includes(forbidden), false,
    `background polling cannot reach ${forbidden}`)
}
assert.equal(coordinatorSource.includes('createInboxReplica'), false,
  'the coordinator has no INBOX lifecycle/CREATE path')
assert.equal(coordinatorSource.includes('createWatchInboxRequest'), false,
  'the coordinator has no INBOX lifecycle/WATCH path')
assert.equal(coordinatorSource.includes('createRenewInboxRequest'), false,
  'the coordinator has no INBOX lifecycle/RENEW path')
assert.equal(coordinatorSource.includes('createCloseInboxRequest'), false,
  'the coordinator has no INBOX lifecycle/CLOSE path')

const fixture = JSON.parse(await fs.readFile(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json', import.meta.url)))
const fixtureNow = 1780000001000n
const authority = await verifyPeeritLimitedPublicInboxBootstrapV1({
  wrapper: fixture,
  control: browserControl,
  referenceUnixMillis: fixtureNow,
  allowFixture: true
})

function relayQualificationHarness (options = {}) {
  const endpointContexts = new WeakMap()
  const descriptorValidities = new WeakMap()
  const healthValidities = new WeakMap()
  const calls = []
  const historyCalls = []
  const descriptorsByHash = new Map()
  const headsByRelayId = new Map()
  const descriptorIdToHead = new Map()
  const hashHex = value => Buffer.from(value).toString('hex')
  const same = (left, right) => Buffer.from(left).equals(Buffer.from(right))
  const u64 = value => {
    const output = new Uint8Array(8)
    let remaining = BigInt(value)
    for (let index = output.byteLength - 1; index >= 0; index--) {
      output[index] = Number(remaining & 0xffn)
      remaining >>= 8n
    }
    return output
  }
  const descriptor = ({ binding, sequence, hash, previousDescriptorHash }) => {
    const snapshot = new Uint8Array(previousDescriptorHash == null ? 74 : 106)
    snapshot[0] = 1
    snapshot.set(binding.relayPublicKey, 1)
    snapshot.set(binding.storeId, 33)
    snapshot.set(u64(sequence), 65)
    snapshot[73] = previousDescriptorHash == null ? 0 : 1
    if (previousDescriptorHash != null) snapshot.set(previousDescriptorHash, 74)
    return Object.freeze({
      descriptorHash: hash,
      descriptorSequence: sequence,
      relayPublicKey: binding.relayPublicKey,
      storeId: binding.storeId,
      snapshotBytes: () => snapshot.slice()
    })
  }
  authority.bindings.forEach((binding, relayIndex) => {
    const headSequence = binding.descriptorFloorSequence + 1n
    let previousDescriptorHash = null
    for (let sequence = 0n; sequence <= headSequence; sequence++) {
      const isFloor = sequence === binding.descriptorFloorSequence
      const isHead = sequence === headSequence
      let hash
      if (isFloor) {
        hash = options.forkSignedFloor === true && relayIndex === 0
          ? new Uint8Array(32).fill(0xee)
          : binding.descriptorFloorHash
      } else {
        hash = new Uint8Array(32).fill(
          Number(0x10n + BigInt(relayIndex) * 0x40n + sequence))
      }
      const value = descriptor({ binding, sequence, hash, previousDescriptorHash })
      descriptorsByHash.set(hashHex(hash), value)
      if (isHead) {
        headsByRelayId.set(binding.relayId, value)
        descriptorIdToHead.set(relayIndex + 1, value)
      }
      previousDescriptorHash = hash
    }
  })

  class DescriptorTrustStore {
    constructor () {
      this.accepted = []
    }

    async accept (value, acceptOptions = {}) {
      if (this.accepted.length === 0) {
        assert.equal(value.descriptorSequence, 0n)
        assert.equal(same(acceptOptions.pinnedDescriptorHash, value.descriptorHash), true)
        const binding = authority.bindings.find(candidate =>
          same(candidate.relayPublicKey, acceptOptions.continuityRootRelayPublicKey))
        assert.ok(binding)
      } else {
        const previous = this.accepted[this.accepted.length - 1]
        const snapshot = value.snapshotBytes()
        assert.equal(value.descriptorSequence, previous.descriptorSequence + 1n)
        assert.equal(same(snapshot.subarray(74, 106), previous.descriptorHash), true)
      }
      this.accepted.push(value)
      return value
    }
  }

  class BlindDescriptorBootstrapHttpClient {
    async fetchVerifiedDescriptor (request) {
      assert.equal(request.history, true)
      const value = descriptorsByHash.get(hashHex(request.expectedDescriptorHash))
      assert.ok(value, 'history request is pinned to a known predecessor hash')
      const canonicalUrl = new TextDecoder().decode(request.canonicalUrl)
      const binding = authority.bindings.find(candidate =>
        candidate.canonicalDescribeUrl === canonicalUrl)
      assert.ok(binding)
      historyCalls.push(Object.freeze({
        hash: hashHex(request.expectedDescriptorHash),
        relayId: binding.relayId,
        sequence: value.descriptorSequence
      }))
      return value
    }
  }

  class BlindRelayQualifier {
    constructor (qualifierOptions) {
      assert.equal(typeof qualifierOptions.runtime.randomBytes, 'function')
      assert.equal(qualifierOptions.nowEpoch(), Number(fixtureNow / 21600000n))
      assert.ok(qualifierOptions.trustStore instanceof DescriptorTrustStore)
      assert.ok(qualifierOptions.trustStore.accepted.length > 1,
        'qualification receives a trust store walked from genesis to current head')
      assert.deepEqual(
        qualifierOptions.supportedProtocolProfiles.map(value => value.protocolId),
        [1, 2, 3])
      assert.deepEqual(
        qualifierOptions.supportedTransportProfiles.map(value => value.transportId),
        [1])
    }

    async qualifyCandidate (candidate, requirement) {
      const binding = authority.bindings.find(value =>
        same(headsByRelayId.get(value.relayId).descriptorHash,
          candidate.expectedDescriptorHash))
      assert.ok(binding, 'candidate is bound to the authenticated current descriptor head')
      const head = headsByRelayId.get(binding.relayId)
      assert.equal(head.descriptorSequence, binding.descriptorFloorSequence + 1n,
        'the focused fixture exercises a descriptor rotation beyond the signed floor')
      assert.equal(new TextDecoder().decode(candidate.canonicalUrl),
        binding.canonicalDescribeUrl)
      assert.deepEqual(candidate.continuityRootRelayPublicKey, binding.relayPublicKey)
      calls.push(Object.freeze({
        relayId: binding.relayId,
        familyId: requirement.familyId,
        operationId: requirement.operationId
      }))
      const endpoint = Object.freeze({
        relayId: binding.relayId,
        familyId: requirement.familyId,
        operationId: requirement.operationId
      })
      endpointContexts.set(endpoint, Object.freeze({
        relayPublicKey: binding.relayPublicKey,
        storeId: binding.storeId,
        durabilityContinuityHash: binding.durabilityContinuityHash,
        continuityRoot: new Uint8Array(32).fill(
          authority.bindings.indexOf(binding) + 0x40),
        descriptorHash: options.descriptorHash || head.descriptorHash,
        descriptorSequence: options.descriptorSequence == null
          ? head.descriptorSequence
          : options.descriptorSequence,
        familyId: requirement.familyId,
        operationId: requirement.operationId
      }))
      const trustedDescriptor = Object.freeze({})
      const health = Object.freeze({})
      descriptorValidities.set(trustedDescriptor, Object.freeze({
        issuedEpoch: Number(fixtureNow / 21600000n),
        expiresEpoch: Number(fixtureNow / 21600000n) + 2
      }))
      healthValidities.set(health, Object.freeze({
        verifiedAtMonotonicMillis: 100,
        expiresAtMonotonicMillis: options.healthExpiresAt == null
          ? 60100
          : options.healthExpiresAt
      }))
      return Object.freeze({ endpoint, trustedDescriptor, health })
    }
  }

  function currentDescriptorResponse (url, requestBody) {
    const bindingIndex = authority.bindings.findIndex(binding =>
      binding.canonicalDescribeUrl === url)
    assert.notEqual(bindingIndex, -1)
    assert.equal(requestBody.byteLength, 65_536)
    assert.equal(requestBody[0], 1)
    assert.equal(requestBody[1], 3)
    const requestId = requestBody.subarray(15, 31)
    const dispatch = new Uint8Array(46)
    const writeU32 = (offset, value) => {
      dispatch[offset] = (value >>> 24) & 0xff
      dispatch[offset + 1] = (value >>> 16) & 0xff
      dispatch[offset + 2] = (value >>> 8) & 0xff
      dispatch[offset + 3] = value & 0xff
    }
    writeU32(0, dispatch.byteLength - 4)
    dispatch[4] = 1
    dispatch[5] = 2
    dispatch[6] = 1
    dispatch[7] = 1
    dispatch.set(requestId, 9)
    writeU32(41, 1)
    dispatch[45] = bindingIndex + 1
    const envelope = new Uint8Array(65_536)
    envelope[0] = 1
    envelope[1] = 3
    envelope[2] = (dispatch.byteLength >>> 24) & 0xff
    envelope[3] = (dispatch.byteLength >>> 16) & 0xff
    envelope[4] = (dispatch.byteLength >>> 8) & 0xff
    envelope[5] = dispatch.byteLength & 0xff
    envelope.set(dispatch, 6)
    return envelope
  }

  const fetch = async (url, request) => {
    const envelope = currentDescriptorResponse(url, request.body)
    let delivered = false
    return Object.freeze({
      status: 200,
      headers: Object.freeze({
        get (name) {
          if (name === 'content-type') return 'application/vnd.hiverelay.blind-v1'
          if (name === 'content-length') return '65536'
          return null
        }
      }),
      body: Object.freeze({
        getReader () {
          return Object.freeze({
            async read () {
              if (delivered) return { done: true, value: undefined }
              delivered = true
              return { done: false, value: envelope }
            },
            async cancel () {},
            releaseLock () {}
          })
        }
      })
    })
  }

  return Object.freeze({
    calls,
    fetch,
    historyCalls,
    control: Object.freeze({
      ...browserControl,
      BlindDescriptorBootstrapHttpClient,
      BlindRelayQualifier,
      DescriptorTrustStore,
      HEALTH_QUALIFICATION_LIMITS: Object.freeze({ maximumAgeMillis: 60000 }),
      createDescribeGetRequest () {
        return Object.freeze({
          request: Object.freeze({ descriptorHash: null }),
          requestBytes: Uint8Array.of(1),
          wire: Object.freeze({
            familyId: 1,
            operationId: 1,
            expectedResultBodyBytes: 16_384
          })
        })
      },
      verifyDescriptorBytes (value) {
        const head = descriptorIdToHead.get(value[0])
        assert.ok(head, 'current descriptor response selects a fixture head')
        return head
      },
      verifiedEndpointContext (endpoint) {
        const value = endpointContexts.get(endpoint)
        if (!value) throw new Error('unverified endpoint')
        return value
      },
      trustedDescriptorValidity (value) {
        const validity = descriptorValidities.get(value)
        if (!validity) throw new Error('unverified descriptor')
        return validity
      },
      verifiedHealthValidity (value) {
        const validity = healthValidities.get(value)
        if (!validity) throw new Error('unverified health')
        return validity
      }
    })
  })
}

const qualifiedHarness = relayQualificationHarness()
const qualified = await qualifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: qualifiedHarness.control,
  runtime: Object.freeze({ randomBytes: length => new Uint8Array(length).fill(0x5a) }),
  fetch: qualifiedHarness.fetch,
  nowUnixMillis: fixtureNow,
  monotonicMillis: () => 101
})
assert.equal(qualified.endpointSets.length, 2)
assert.equal(authority.bindings.every(binding =>
  qualifiedHarness.historyCalls.some(value =>
    value.relayId === binding.relayId &&
    value.sequence === binding.descriptorFloorSequence)), true,
'each current-head history walk crosses its exact signed descriptor floor')
assert.deepEqual(qualifiedHarness.calls.map(value =>
  `${value.relayId}:${value.familyId}/${value.operationId}`),
authority.bindings.flatMap(binding => [
  `${binding.relayId}:2/1`,
  `${binding.relayId}:2/2`,
  `${binding.relayId}:3/4`,
  `${binding.relayId}:3/5`
]), 'each relay qualifies only PUT, GET, APPEND, and READ')
assert.equal(qualifiedHarness.calls.some(value =>
  value.familyId === 3 && [1, 2, 3].includes(value.operationId)), false,
'qualification never requests CREATE, RENEW, or CLOSE')

const staleHealthHarness = relayQualificationHarness({ healthExpiresAt: 60099 })
await assert.rejects(qualifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: staleHealthHarness.control,
  runtime: Object.freeze({ randomBytes: length => new Uint8Array(length).fill(0x5a) }),
  fetch: staleHealthHarness.fetch,
  nowUnixMillis: fixtureNow,
  monotonicMillis: () => 101
}), error => error.code === 'PEERIT_SEQ29_RELAY_QUALIFICATION_EXPIRED',
'qualification rejects a health lease that is not the authenticated bounded duration')

const forkedHistoryHarness = relayQualificationHarness({ forkSignedFloor: true })
await assert.rejects(qualifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: forkedHistoryHarness.control,
  runtime: Object.freeze({ randomBytes: length => new Uint8Array(length).fill(0x5a) }),
  fetch: forkedHistoryHarness.fetch,
  nowUnixMillis: fixtureNow,
  monotonicMillis: () => 101
}), error => error.code === 'PEERIT_SEQ29_DESCRIPTOR_FLOOR_FORK',
'an otherwise continuous current-head history cannot bypass the exact signed floor hash')

function relayEndpointHarness (mutate = null) {
  const contexts = new WeakMap()
  const relayEndpoints = authority.bindings.map((binding, relayIndex) => {
    const common = {
      relayPublicKey: binding.relayPublicKey,
      storeId: binding.storeId,
      durabilityContinuityHash: binding.durabilityContinuityHash,
      continuityRoot: new Uint8Array(32).fill(0x70 + relayIndex),
      descriptorHash: binding.descriptorFloorHash,
      descriptorSequence: binding.descriptorFloorSequence
    }
    const output = { relayId: binding.relayId }
    for (const [field, familyId, operationId] of [
      ['putEndpoint', 2, 1],
      ['cellGetEndpoint', 2, 2],
      ['appendEndpoint', 3, 4],
      ['readEndpoint', 3, 5]
    ]) {
      const endpoint = Object.freeze({ relayId: binding.relayId, field })
      output[field] = endpoint
      contexts.set(endpoint, Object.freeze({ ...common, familyId, operationId }))
    }
    return output
  })
  if (mutate) mutate({ relayEndpoints, contexts })
  return {
    relayEndpoints,
    control: {
      verifiedEndpointContext (endpoint) {
        const value = contexts.get(endpoint)
        if (!value) throw new Error('unverified endpoint')
        return value
      }
    }
  }
}

const endpoints = relayEndpointHarness()
const authenticatedEndpoints = verifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: endpoints.control,
  relayEndpoints: endpoints.relayEndpoints
})
assert.deepEqual(authenticatedEndpoints.map(value => value.relayId).sort(),
  authority.bindings.map(value => value.relayId).sort())
assert.throws(() => verifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: endpoints.control,
  relayEndpoints: endpoints.relayEndpoints.map((value, index) => index === 0
    ? { ...value, readEndpoint: { ...value.readEndpoint } }
    : value)
}), error => error.code === 'PEERIT_SEQ29_RELAY_ENDPOINT_UNAUTHENTICATED',
'shape-copied endpoints cannot select a relay')

const crossRelay = relayEndpointHarness(({ relayEndpoints }) => {
  relayEndpoints[0].readEndpoint = relayEndpoints[1].readEndpoint
})
assert.throws(() => verifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: crossRelay.control,
  relayEndpoints: crossRelay.relayEndpoints
}), error => error.code === 'PEERIT_SEQ29_RELAY_ENDPOINT_IDENTITY_MISMATCH',
'an authenticated endpoint from the other relay cannot be mapped by URL or array position')

const belowFloor = relayEndpointHarness(({ relayEndpoints, contexts }) => {
  const endpoint = relayEndpoints[0].readEndpoint
  contexts.set(endpoint, Object.freeze({
    ...contexts.get(endpoint),
    descriptorSequence: authority.bindings[0].descriptorFloorSequence - 1n
  }))
})
assert.throws(() => verifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: belowFloor.control,
  relayEndpoints: belowFloor.relayEndpoints
}), error => error.code === 'PEERIT_SEQ29_RELAY_DESCRIPTOR_BELOW_FLOOR')

const forkedFloor = relayEndpointHarness(({ relayEndpoints, contexts }) => {
  const endpoint = relayEndpoints[0].readEndpoint
  contexts.set(endpoint, Object.freeze({
    ...contexts.get(endpoint),
    descriptorHash: new Uint8Array(32).fill(0xff)
  }))
})
assert.throws(() => verifyPeeritSeq29PublicInboxRelayEndpointsV1({
  authority,
  control: forkedFloor.control,
  relayEndpoints: forkedFloor.relayEndpoints
}), error => error.code === 'PEERIT_SEQ29_RELAY_DESCRIPTOR_BELOW_FLOOR')

const signedAnnouncementId = new Uint8Array(32).fill(0x11)
const publisherPublicKey = new Uint8Array(32).fill(0x12)
const authorPublicKey = new Uint8Array(32).fill(0x13)
const logicalHash = new Uint8Array(32).fill(0x14)
const record = Object.freeze({
  signedAnnouncementId,
  publisherPublicKey,
  authorPublicKey,
  operationBatch: Object.freeze({ logicalHash })
})
const merged = mergePeeritSeq29PublicInboxPollResultsV1([
  { relayId: 'dal', records: [{ ...record, appendRevision: 3n }] },
  { relayId: 'syd', records: [{ ...record, appendRevision: 7n }] }
])
assert.equal(merged.length, 1, 'dual relay copies dedupe to one intrinsic batch')
assert.deepEqual(merged[0].relayIds, ['dal', 'syd'])
assert.deepEqual(merged[0].appendRevisionByRelay, { dal: 3n, syd: 7n })

assert.deepEqual(await settlePeeritSeq29DualAppendV1([
  Promise.resolve({ appendRevision: 8n }),
  Promise.resolve({ appendRevision: 9n })
]), [{ appendRevision: 8n }, { appendRevision: 9n }])
await assert.rejects(settlePeeritSeq29DualAppendV1([
  Promise.resolve({ appendRevision: 8n }),
  Promise.reject(Object.assign(new Error('relay rejected'), { code: 'APPEND_REJECTED' }))
]), error => error.code === 'PEERIT_SEQ29_DUAL_APPEND_INCOMPLETE' &&
  error.details[0].ok === true && error.details[1].code === 'APPEND_REJECTED',
'partial dual APPEND is an explicit incomplete publication, never success')

console.log('peerit seq29 public INBOX shipped coordinator entry boundary: ok')
