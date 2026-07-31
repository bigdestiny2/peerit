import assert from 'node:assert/strict'
import {
  qualifyPermissionlessRelayCandidates
} from '../../js/substrate/relay-consumer.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()
const endpointContexts = new WeakMap()
const trustedDescriptorValidities = new WeakMap()
const verifiedHealthValidities = new WeakMap()
const verifiedAdmissionValidities = new WeakMap()

function bytes (hex) { return new Uint8Array(Buffer.from(hex, 'hex')) }
function same (left, right) { return Buffer.from(left).equals(Buffer.from(right)) }

export async function qualifySeedRelayFixtures (rows, readByRelay, options = {}) {
  const fixtures = new Map(rows.map(row => [row.canonicalDescribeUrl, Object.freeze({
    row,
    root: bytes(row.continuityRootRelayPublicKey),
    storeId: bytes(row.storeId),
    descriptorHash: bytes(row.descriptorGenesisHash),
    relayPublicKey: bytes(row.continuityRootRelayPublicKey),
    descriptorSequence: 0n
  })]))

  class TrustStore {
    async accept (descriptor, trust = {}) {
      assert.ok(same(trust.pinnedDescriptorHash, descriptor.descriptorHash))
      assert.ok(same(trust.continuityRootRelayPublicKey, descriptor.fixture.root))
      const value = Object.freeze({ fixture: descriptor.fixture, rootRelayPublicKey: descriptor.fixture.root })
      trustedDescriptorValidities.set(value, Object.freeze({ issuedEpoch: 100, expiresEpoch: 104 }))
      return value
    }
  }

  class BootstrapClient {
    async fetchVerifiedDescriptor (request) {
      const fixture = fixtures.get(decoder.decode(request.canonicalUrl))
      if (!fixture || !same(request.expectedDescriptorHash, fixture.descriptorHash)) {
        throw Object.assign(new Error('fixture descriptor mismatch'), { code: 'RELAY_PROTOCOL_VIOLATION' })
      }
      return Object.freeze({
        fixture,
        descriptorHash: fixture.descriptorHash,
        descriptorSequence: fixture.descriptorSequence,
        relayPublicKey: fixture.relayPublicKey,
        storeId: fixture.storeId
      })
    }
  }

  function endpoint (context) {
    const value = Object.freeze({})
    endpointContexts.set(value, Object.freeze(context))
    return value
  }

  class Qualifier {
    constructor (input) {
      this.bootstrapClient = input.bootstrapClient
      this.trustStore = input.trustStore
    }

    async qualifyCandidate (candidate, requirement, request = {}) {
      const descriptor = await this.bootstrapClient.fetchVerifiedDescriptor({
        ...candidate,
        signal: request.signal
      })
      const trustedDescriptor = await this.trustStore.accept(descriptor, {
        pinnedDescriptorHash: candidate.expectedDescriptorHash,
        continuityRootRelayPublicKey: candidate.continuityRootRelayPublicKey
      })
      const context = {
        fixture: descriptor.fixture,
        descriptorHash: descriptor.descriptorHash,
        descriptorSequence: descriptor.descriptorSequence,
        relayPublicKey: descriptor.relayPublicKey,
        storeId: descriptor.storeId,
        continuityRoot: trustedDescriptor.rootRelayPublicKey,
        familyId: requirement.familyId,
        operationId: requirement.operationId,
        endpointId: requirement.endpointId,
        transportId: descriptor.fixture.row.transportId,
        transportSupportBit: requirement.transportSupportBit,
        privacyProfileBit: requirement.privacyProfileBit,
        durabilityProfileId: 1,
        durabilityContinuityHash: new Uint8Array(32).fill(0x70)
      }
      const health = Object.freeze({})
      verifiedHealthValidities.set(health, Object.freeze({
        verifiedAtMonotonicMillis: 1_000,
        expiresAtMonotonicMillis: 601_000
      }))
      return Object.freeze({
        endpoint: endpoint(context),
        trustedDescriptor,
        verifiedDescriptor: descriptor,
        health,
        descriptorHash: descriptor.descriptorHash,
        continuityRootRelayPublicKey: trustedDescriptor.rootRelayPublicKey
      })
    }
  }

  class DirectClient {
    async request () { return Object.freeze({ ok: true, body: new Uint8Array([1]) }) }
  }

  const parameterHash = new Uint8Array(32).fill(0xa1)
  const control = Object.freeze({
    HEALTH_QUALIFICATION_LIMITS: Object.freeze({ maximumAgeMillis: 600_000 }),
    BlindDescriptorBootstrapHttpClient: BootstrapClient,
    BlindDirectHttpClient: DirectClient,
    BlindRelayQualifier: Qualifier,
    DescriptorTrustStore: TrustStore,
    createGetCellRequest: async () => Object.freeze({}),
    openVerifiedCellGetResult: async () => new Uint8Array(),
    createAdmissionParametersRequest () {
      return Object.freeze({
        request: Object.freeze({}),
        requestBytes: encoder.encode('admission'),
        wire: Object.freeze({ familyId: 1, operationId: 3, expectedResultBodyBytes: 16_384 })
      })
    },
    qualifyDescribeControlEndpoint ({ trustedDescriptor, familyId, operationId }) {
      return endpoint({ fixture: trustedDescriptor.fixture, familyId, operationId })
    },
    trustedAdmissionProfile () {
      return Object.freeze({
        profileId: 7,
        schemeId: 9,
        conformanceClass: 1,
        roleBits: 1,
        parameterUrl: null,
        parameterHash
      })
    },
    trustedDescriptorValidity (trusted) {
      return trustedDescriptorValidities.get(trusted)
    },
    verifiedHealthValidity (health) {
      return verifiedHealthValidities.get(health)
    },
    verifiedEndpointContext (value) {
      const context = endpointContexts.get(value)
      if (!context || context.descriptorHash == null) throw new Error('VerifiedEndpoint required')
      return context
    },
    verifyAdmissionParametersBytes () {
      const verified = Object.freeze({ parameterHash })
      verifiedAdmissionValidities.set(verified, Object.freeze({ validFromEpoch: 100, expiresEpoch: 103 }))
      return verified
    },
    verifiedAdmissionParametersValidity (value) {
      return verifiedAdmissionValidities.get(value)
    }
  })

  const candidates = rows.map(row => ({
    canonicalUrl: row.canonicalDescribeUrl,
    expectedDescriptorHash: row.descriptorGenesisHash,
    continuityRootRelayPublicKey: row.continuityRootRelayPublicKey,
    descriptorPinned: true,
    sources: ['fixture']
  }))
  const result = await qualifyPermissionlessRelayCandidates({
    control,
    cryptoRuntime: { randomBytes: length => new Uint8Array(length).fill(0x55) },
    nowEpoch: () => 101,
    monotonicMillis: () => 1_000,
    profile: {
      supportedProtocolProfiles: [{ protocolId: 2, major: 1, minimumMinor: 0, profileHash: new Uint8Array(32).fill(0x81) }],
      supportedTransportProfiles: [{ transportId: 1, transportSupportBit: 1, transportProfileHash: new Uint8Array(32).fill(0x82) }],
      requirement: {
        familyId: 2,
        operationId: 1,
        endpointId: 1,
        requiredRoleBits: 1,
        privacyProfileBit: 1,
        transportSupportBit: 1
      },
      readRequirement: {
        familyId: 2,
        operationId: 2,
        endpointId: 1,
        requiredRoleBits: 1,
        privacyProfileBit: 1,
        transportSupportBit: 1
      },
      describeFamilyId: 1,
      admissionParametersOperationId: 3,
      admissionProfile: {
        profileId: 7,
        schemeId: 9,
        conformanceClass: 1,
        roleBits: 1,
        parameterUrl: null,
        parameterHash
      }
    },
    candidates,
    trustStore: new TrustStore(),
    bootstrapClient: new BootstrapClient(),
    directClient: new DirectClient(),
    admissionProvider: async () => ({
      profileId: 7,
      schemeId: 9,
      parameterHash,
      token: new Uint8Array([1])
    }),
    persistPreparedReplica: async () => {},
    persistVerifiedResult: async () => ({ evidenceRef: 'fixture:put' }),
    persistVerifiedReadback: async () => ({ evidenceRef: 'fixture:readback' }),
    loadPersistedReplica: async () => null,
    async createRelayAdapter (adapterOptions) {
      const fixture = endpointContexts.get(adapterOptions.readEndpoint).fixture
      return Object.freeze({
        compatible: true,
        deliver: async () => ({ ok: true }),
        readCellCapability: (request, context) => readByRelay(fixture.row.relayId, request, context)
      })
    },
    ...options
  })
  assert.equal(result.failures.length, 0)
  assert.equal(result.adapters.length, rows.length)
  return result.adapters
}
