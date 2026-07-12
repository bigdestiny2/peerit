import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createSync } from '../js/sync.js'
import { createMemoryPeeritJournal } from '../js/substrate/peerit-journal.js'
import {
  PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS,
  PEERIT_BLIND_CLIENT_CONSUMER_STATUS,
  PEERIT_BLIND_CLIENT_PERSISTENCE_BLOCKERS,
  collectPermissionlessRelayCandidates,
  installPeeritBlindRelayConsumer,
  isPeeritVerifiedRelayAdapter,
  qualifyPermissionlessRelayCandidates
} from '../js/substrate/relay-consumer.js'
import { SITE_FILES } from '../publish.mjs'

const descriptorHash = '11'.repeat(32)
const continuityRoot = '22'.repeat(32)

const candidates = collectPermissionlessRelayCandidates({
  recommendation: [
    'https://relay-a.example:443/api/blind/v1/describe',
    'http://public-cleartext.example/api/blind/v1/describe'
  ],
  user: [
    'https://relay-a.example:443/api/blind/v1/describe',
    {
      canonicalUrl: 'https://relay-a.example:443/api/blind/v1/describe',
      expectedDescriptorHash: descriptorHash,
      continuityRootRelayPublicKey: continuityRoot
    }
  ],
  peer: [{
    url: 'https://relay-a.example:443/api/blind/v1/describe',
    expectedDescriptorHash: descriptorHash,
    continuityRootRelayPublicKey: continuityRoot
  }],
  dht: [{
    canonicalUrl: 'https://relay-b.example:443/api/blind/v1/describe',
    expectedDescriptorHash: new Uint8Array(32).fill(0x33)
  }]
})

assert.equal(candidates.length, 3)
assert.deepEqual(candidates[0].sources, ['recommendation', 'user'])
assert.equal(candidates[0].descriptorPinned, false, 'a URL remains an unpinned hint')
assert.deepEqual(candidates[1].sources, ['peer', 'user'])
assert.equal(candidates[1].expectedDescriptorHash, descriptorHash)
assert.equal(candidates[1].continuityRootRelayPublicKey, continuityRoot)
assert.deepEqual(candidates[2].sources, ['dht'])

const crowded = collectPermissionlessRelayCandidates({
  recommendation: Array.from({ length: 128 }, (_, index) =>
    `https://raw-${index}.example/api/blind/v1/describe`),
  user: [{
    canonicalUrl: 'https://one-valid.example/api/blind/v1/describe',
    expectedDescriptorHash: descriptorHash,
    continuityRootRelayPublicKey: continuityRoot
  }]
})
assert.equal(crowded.length, 33)
assert.equal(crowded.some(value => value.canonicalUrl ===
  'https://one-valid.example/api/blind/v1/describe' && value.descriptorPinned), true,
'128 inert recommendation URLs cannot crowd out a pinned user candidate')

let networkCalls = 0
const relayAssignments = []
let observedStatus = null
const fakeSync = {
  setRelays (relays) { relayAssignments.push(relays) },
  setRelayQualificationStatus (status) { observedStatus = status }
}
const blocked = await installPeeritBlindRelayConsumer({
  sync: fakeSync,
  runtime: {
    mode: 'web-substrate',
    relayHints: ['https://recommended.example:443/api/blind/v1/describe']
  },
  candidates: {
    user: [{
      canonicalUrl: 'https://user.example:443/api/blind/v1/describe',
      expectedDescriptorHash: descriptorHash
    }],
    peer: ['https://peer.example:443/api/blind/v1/describe'],
    dht: ['https://dht.example:443/api/blind/v1/describe']
  },
  fetch: async () => { networkCalls++; throw new Error('must not fetch') },
  loadControl: async () => { networkCalls++; throw new Error('must not import control') },
  loadRelayAdapter: async () => { networkCalls++; throw new Error('must not import adapter') }
})

assert.equal(blocked.state, 'blocked-build-authority')
assert.equal(blocked.active, false)
assert.equal(blocked.qualifiedRelayCount, 0)
assert.equal(blocked.rawUrlAuthorizesOrdinaryOperations, false)
assert.equal(blocked.signedQualificationEpochWindowRequired, true)
assert.equal(blocked.endpointBoundHealthRequired, true)
assert.equal(blocked.sharedContinuityTrustStoreRequired, true)
assert.equal(blocked.sameContinuityDeduplicationRequired, true)
assert.equal(blocked.descriptorForkQuarantineRequired, true)
assert.equal(blocked.oneRelayEnablesDelivery, true)
assert.equal(blocked.zeroRelayBehavior, 'queued-local-first')
assert.equal(blocked.candidateHintCount, 4)
assert.equal(blocked.descriptorPinnedCandidateCount, 1)
assert.deepEqual(blocked.candidateSources, ['dht', 'peer', 'recommendation', 'user'])
assert.deepEqual(blocked.releaseBlockers, PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS)
assert.ok(blocked.releaseBlockers.includes('AUTHENTICATED_PEERIT_RELAY_RUNTIME_AUTHORITY_UNAVAILABLE'))
assert.equal(blocked.releaseBlockers.includes('RELAY_REQUALIFICATION_SCHEDULER_UNASSEMBLED'), false)
assert.equal(blocked.requalificationSchedulerReady, true)
assert.deepEqual(relayAssignments, [[]], 'the only current setRelays wiring installs no unauthorized targets')
assert.equal(observedStatus, blocked)
assert.equal(networkCalls, 0, 'missing build authority fails before fetch or client import')

const journal = createMemoryPeeritJournal()
const sync = createSync({ mode: 'substrate', journal, relays: [{ id: 'must-be-cleared', deliver: async () => ({ ok: true }) }], autoFlush: false })
await sync.ready()
await installPeeritBlindRelayConsumer({
  sync,
  runtime: { mode: 'web-substrate', relayHints: ['https://raw.example:443/api/blind/v1/describe'] }
})
const status = await sync.status()
assert.equal(status.peers, 0)
assert.equal(status.relayQualification.state, 'blocked-build-authority')
assert.equal(status.relayQualification.rawUrlAuthorizesOrdinaryOperations, false)
assert.equal(status.publication.relay.state, 'idle')
sync.destroy()

const irrelevantAssignments = []
const irrelevant = await installPeeritBlindRelayConsumer({
  sync: { setRelays: relays => irrelevantAssignments.push(relays) },
  runtime: { mode: 'pearbrowser', relayHints: [] }
})
assert.equal(irrelevant.state, 'not-applicable')
assert.deepEqual(irrelevantAssignments, [])

assert.equal(PEERIT_BLIND_CLIENT_CONSUMER_STATUS.releaseReady, false)
assert.ok(SITE_FILES.includes('js/substrate/relay-consumer.js'))
assert.ok(SITE_FILES.includes('js/substrate/capability-vault.js'))
assert.ok(SITE_FILES.includes('js/substrate/descriptor-trust-backend.js'))
assert.ok(SITE_FILES.includes('js/substrate/relay-requalification-scheduler.js'))
assert.ok(SITE_FILES.includes('js/substrate/blind-client-relay.js'),
  'the local adapter is shipped only behind the authenticated exact-byte control authority')
const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
assert.equal(packageJson.dependencies && packageJson.dependencies['@hiverelay/blind-client'], undefined)
const appSource = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8')
assert.ok(appSource.indexOf('await sync.ready()') < appSource.indexOf('installPeeritBlindRelayConsumer({'))
assert.ok(appSource.indexOf("window.addEventListener('pagehide'") <
  appSource.indexOf('installPeeritBlindRelayConsumer({'),
'pagehide invalidation is armed before asynchronous relay installation starts')
assert.ok(appSource.indexOf('stopPeeritBlindRelayConsumer(sync)') < appSource.indexOf('sync.destroy()'),
  'browser teardown invalidates the relay owner before destroying sync')
assert.match(appSource, /event\.persisted && runtime && runtime\.mode === 'web-substrate'/,
  'a BFCache restore boots a fresh qualification clock instead of reviving stopped state')
const consumerSource = readFileSync(new URL('../js/substrate/relay-consumer.js', import.meta.url), 'utf8')
assert.match(consumerSource, /ACTIVE_RELAY_INSTALLATIONS/)
assert.doesNotMatch(consumerSource, /ACTIVE_RELAY_SCHEDULERS/)
assert.ok(consumerSource.indexOf('assertRelayInstallationCurrent(sync, installation)') <
  consumerSource.indexOf('const control = runtimeAssembly.control'),
'installation ownership is checked before authenticated control authority is consumed')
const installerSource = consumerSource.slice(consumerSource.indexOf(
  'export async function installPeeritBlindRelayConsumer'))
assert.doesNotMatch(installerSource, /options\.(?:loadControl|loadAdapter|createAdapter|control)\b/,
  'caller-selected control and adapter injection seams are absent')

// The active seam is tested with a shape-compatible local blind-client control
// contract. Its private WeakMap models VerifiedEndpoint branding; its qualifier
// models the package-owned hash/signature/trust/health boundary. Peerit is tested
// only for the composition it owns: no raw URL authority, admission verification,
// continuity/store/endpoint dedupe, fork quarantine, and branded adapter output.
const encoder = new TextEncoder()
const decoder = new TextDecoder()
const endpointContexts = new WeakMap()
const trustedDescriptorValidities = new WeakMap()
const verifiedHealthValidities = new WeakMap()
const verifiedAdmissionValidities = new WeakMap()
const fixtureByUrl = new Map()
const bootstrapCalls = []

const fill = value => new Uint8Array(32).fill(value)
const asHex = value => Buffer.from(value).toString('hex')
const same = (left, right) => Buffer.from(left).equals(Buffer.from(right))
const blindError = (code, message = code) => Object.assign(new Error(message), { code })

function relayFixture (url, values) {
  const fixture = Object.freeze({
    url,
    root: fill(values.root),
    relayPublicKey: fill(values.relayPublicKey == null ? values.root : values.relayPublicKey),
    storeId: fill(values.store),
    descriptorHash: fill(values.hash),
    descriptorSequence: BigInt(values.sequence || 0),
    mode: values.mode || 'valid'
  })
  fixtureByUrl.set(url, fixture)
  return fixture
}

const valid = relayFixture('https://valid.example/api/blind/v1/describe', {
  root: 0x11, store: 0x12, hash: 0x13
})
relayFixture('https://valid-alias.example/api/blind/v1/describe', {
  root: 0x11, store: 0x12, hash: 0x13
})
const validOtherStore = relayFixture('https://valid-other-store.example/api/blind/v1/describe', {
  root: 0x11, store: 0x15, hash: 0x16
})
const forkA = relayFixture('https://fork-a.example/api/blind/v1/describe', {
  root: 0x21, store: 0x22, hash: 0x23
})
const forkB = relayFixture('https://fork-b.example/api/blind/v1/describe', {
  root: 0x21, store: 0x22, hash: 0x24
})
const stale = relayFixture('https://stale.example/api/blind/v1/describe', {
  root: 0x31, store: 0x32, hash: 0x33, mode: 'stale-health'
})
const untrusted = relayFixture('https://untrusted.example/api/blind/v1/describe', {
  root: 0x41, store: 0x42, hash: 0x43, mode: 'invalid-signature'
})
const admissionDrift = relayFixture('https://admission-drift.example/api/blind/v1/describe', {
  root: 0x51, store: 0x52, hash: 0x53, mode: 'admission-drift'
})

class FakeDescriptorTrustStore {
  constructor () {
    this.records = new Map()
    this.quarantined = new Set()
  }

  async accept (descriptor, options = {}) {
    const root = options.continuityRootRelayPublicKey || descriptor.relayPublicKey
    const key = `${asHex(root)}:${asHex(descriptor.storeId)}`
    if (this.quarantined.has(key)) throw blindError('DESCRIPTOR_FORK')
    const previous = this.records.get(key)
    if (previous && previous.sequence === descriptor.descriptorSequence &&
        !same(previous.hash, descriptor.descriptorHash)) {
      this.quarantined.add(key)
      throw blindError('DESCRIPTOR_FORK')
    }
    this.records.set(key, { sequence: descriptor.descriptorSequence, hash: descriptor.descriptorHash })
    const trusted = Object.freeze({ fixture: descriptor.fixture, rootRelayPublicKey: new Uint8Array(root) })
    trustedDescriptorValidities.set(trusted, Object.freeze({ issuedEpoch: 100, expiresEpoch: 104 }))
    return trusted
  }
}

class FakeBootstrapClient {
  async fetchVerifiedDescriptor (request) {
    const url = decoder.decode(request.canonicalUrl)
    bootstrapCalls.push(url)
    const fixture = fixtureByUrl.get(url)
    if (!fixture || fixture.mode === 'invalid-signature') {
      throw blindError('RELAY_PROTOCOL_VIOLATION', 'descriptor signature is untrusted')
    }
    if (fixture.mode === 'timeout') {
      return new Promise((resolve, reject) => {
        if (request.signal && request.signal.aborted) return reject(request.signal.reason)
        request.signal.addEventListener('abort', () => reject(request.signal.reason), { once: true })
      })
    }
    if (!same(request.expectedDescriptorHash, fixture.descriptorHash)) {
      throw blindError('RELAY_PROTOCOL_VIOLATION', 'descriptor hash pin mismatch')
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

function mintEndpoint (context) {
  const endpoint = Object.freeze({})
  endpointContexts.set(endpoint, Object.freeze(context))
  return endpoint
}

class FakeBlindRelayQualifier {
  constructor (options) {
    this.bootstrapClient = options.bootstrapClient
    this.trustStore = options.trustStore
  }

  async qualifyCandidate (candidate, requirement, options = {}) {
    const descriptor = await this.bootstrapClient.fetchVerifiedDescriptor({ ...candidate, signal: options.signal })
    const trustedDescriptor = await this.trustStore.accept(descriptor, {
      pinnedDescriptorHash: candidate.expectedDescriptorHash,
      continuityRootRelayPublicKey: candidate.continuityRootRelayPublicKey
    })
    if (descriptor.fixture.mode === 'stale-health') {
      throw blindError('RELAY_NOT_QUALIFIED', 'signed health challenge is stale')
    }
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
      transportId: 1,
      transportSupportBit: requirement.transportSupportBit,
      privacyProfileBit: requirement.privacyProfileBit,
      durabilityProfileId: 1,
      durabilityContinuityHash: fill(0x70)
    }
    const health = Object.freeze({ fresh: true })
    verifiedHealthValidities.set(health, Object.freeze({
      verifiedAtMonotonicMillis: qualificationClock,
      expiresAtMonotonicMillis: qualificationClock + 600000
    }))
    return Object.freeze({
      endpoint: mintEndpoint(context),
      trustedDescriptor,
      verifiedDescriptor: descriptor,
      health,
      descriptorHash: descriptor.descriptorHash,
      continuityRootRelayPublicKey: trustedDescriptor.rootRelayPublicKey
    })
  }
}

class FakeDirectClient {
  async request ({ endpoint }) {
    const context = endpointContexts.get(endpoint)
    if (!context) throw blindError('BAD_CLIENT_INPUT', 'VerifiedEndpoint required')
    return Object.freeze({ ok: true, body: Object.freeze({ fixture: context.fixture }) })
  }
}

const admissionParameterHash = fill(0xa1)
const fakeControl = Object.freeze({
  HEALTH_QUALIFICATION_LIMITS: Object.freeze({ maximumAgeMillis: 600000 }),
  BlindDescriptorBootstrapHttpClient: FakeBootstrapClient,
  BlindDirectHttpClient: FakeDirectClient,
  BlindRelayQualifier: FakeBlindRelayQualifier,
  DescriptorTrustStore: FakeDescriptorTrustStore,
  createAdmissionParametersRequest ({ profileId, schemeId }) {
    return Object.freeze({
      request: Object.freeze({ profileId, schemeId }),
      requestBytes: encoder.encode('admission-parameters'),
      wire: Object.freeze({ familyId: 1, operationId: 3, expectedResultBodyBytes: 16384 })
    })
  },
  qualifyDescribeControlEndpoint (options) {
    return mintEndpoint({
      fixture: options.trustedDescriptor.fixture,
      familyId: options.familyId,
      operationId: options.operationId
    })
  },
  trustedAdmissionProfile (trustedDescriptor) {
    return Object.freeze({
      profileId: 7,
      schemeId: 9,
      conformanceClass: 1,
      roleBits: 1,
      parameterUrl: null,
      parameterHash: trustedDescriptor.fixture.mode === 'admission-drift'
        ? fill(0xa2)
        : admissionParameterHash
    })
  },
  trustedDescriptorValidity (trustedDescriptor) {
    const validity = trustedDescriptorValidities.get(trustedDescriptor)
    if (!validity) throw blindError('BAD_CLIENT_INPUT', 'TrustedDescriptor required')
    return Object.freeze({ ...validity })
  },
  verifiedHealthValidity (health) {
    const validity = verifiedHealthValidities.get(health)
    if (!validity) throw blindError('BAD_CLIENT_INPUT', 'VerifiedHealth required')
    return Object.freeze({ ...validity })
  },
  verifiedEndpointContext (endpoint) {
    const context = endpointContexts.get(endpoint)
    if (!context || context.descriptorHash == null) throw blindError('BAD_CLIENT_INPUT', 'VerifiedEndpoint required')
    return context
  },
  verifyAdmissionParametersBytes (body, trustedDescriptor, profile, { nowEpoch }) {
    assert.equal(body.fixture, trustedDescriptor.fixture)
    assert.equal(nowEpoch, qualificationEpoch)
    assert.equal(profile.profileId, 7)
    assert.equal(profile.schemeId, 9)
    const verified = Object.freeze({ parameterHash: admissionParameterHash })
    verifiedAdmissionValidities.set(verified, Object.freeze({ validFromEpoch: 100, expiresEpoch: 103 }))
    return verified
  },
  verifiedAdmissionParametersValidity (verified) {
    const validity = verifiedAdmissionValidities.get(verified)
    if (!validity) throw blindError('BAD_CLIENT_INPUT', 'VerifiedAdmissionParameters required')
    return Object.freeze({ ...validity })
  }
})

const activeCandidates = collectPermissionlessRelayCandidates({
  recommendation: ['https://raw-only.example/api/blind/v1/describe'],
  user: [
    { canonicalUrl: valid.url, expectedDescriptorHash: valid.descriptorHash, continuityRootRelayPublicKey: valid.root },
    {
      canonicalUrl: 'https://valid-alias.example/api/blind/v1/describe',
      expectedDescriptorHash: valid.descriptorHash,
      continuityRootRelayPublicKey: valid.root
    },
    {
      canonicalUrl: validOtherStore.url,
      expectedDescriptorHash: validOtherStore.descriptorHash,
      continuityRootRelayPublicKey: validOtherStore.root
    },
    { canonicalUrl: forkA.url, expectedDescriptorHash: forkA.descriptorHash, continuityRootRelayPublicKey: forkA.root },
    { canonicalUrl: forkB.url, expectedDescriptorHash: forkB.descriptorHash, continuityRootRelayPublicKey: forkB.root },
    { canonicalUrl: stale.url, expectedDescriptorHash: stale.descriptorHash, continuityRootRelayPublicKey: stale.root },
    {
      canonicalUrl: untrusted.url,
      expectedDescriptorHash: untrusted.descriptorHash,
      continuityRootRelayPublicKey: untrusted.root
    },
    {
      canonicalUrl: admissionDrift.url,
      expectedDescriptorHash: admissionDrift.descriptorHash,
      continuityRootRelayPublicKey: admissionDrift.root
    }
  ]
})
const createdAdapterContexts = []
let qualificationClock = 1000
let qualificationEpoch = 101
const qualificationOptions = {
  control: fakeControl,
  cryptoRuntime: { randomBytes: length => new Uint8Array(length).fill(0x55) },
  nowEpoch: () => qualificationEpoch,
  monotonicMillis: () => qualificationClock,
  profile: {
    supportedProtocolProfiles: [{ protocolId: 2, major: 1, minimumMinor: 0, profileHash: fill(0x81) }],
    supportedTransportProfiles: [{ transportId: 1, transportSupportBit: 1, transportProfileHash: fill(0x82) }],
    requirement: {
      familyId: 2,
      operationId: 4,
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
      parameterHash: admissionParameterHash
    }
  },
  admissionProvider: async () => ({
    profileId: 7,
    schemeId: 9,
    parameterHash: admissionParameterHash,
    token: new Uint8Array([1])
  }),
  persistPreparedReplica: async () => {},
  persistVerifiedResult: async () => ({ evidenceRef: 'test:verified' }),
  loadPersistedReplica: async () => null,
  async createRelayAdapter (options) {
    const context = fakeControl.verifiedEndpointContext(options.endpoint)
    assert.ok(same(context.relayPublicKey, options.endpointContext.relayPublicKey))
    createdAdapterContexts.push(context)
    return Object.freeze({
      compatible: true,
      deliver: async () => ({ ok: true }),
      reconcile: async () => ({ ok: true })
    })
  }
}
const qualified = await qualifyPermissionlessRelayCandidates({
  ...qualificationOptions,
  candidates: activeCandidates,
  trustStore: new FakeDescriptorTrustStore(),
  bootstrapClient: new FakeBootstrapClient(),
  directClient: new FakeDirectClient()
})

assert.equal(qualified.status.state, 'qualified')
assert.equal(qualified.status.qualifiedRelayCount, 1, 'one independently valid relay is enough to enable delivery')
assert.equal(qualified.status.rawUrlHintCount, 1)
assert.equal(qualified.status.pinnedAttemptCount, 8)
assert.equal(qualified.status.deduplicatedCandidateCount, 1, 'same continuity/store/endpoint aliases collapse')
assert.equal(qualified.status.continuityDiversityDeduplicatedCount, 1,
  'one continuity root cannot multiply Peerit targets through another store or endpoint')
assert.equal(qualified.status.quarantinedIdentityCount, 1)
assert.equal(qualified.status.admissionParametersVerified, true)
assert.equal(qualified.status.signedQualificationEpochWindowRequired, true)
assert.equal(qualified.status.requalificationSchedulerReady, true)
assert.equal(qualified.status.leaseExpiresAtMonotonicMillis, 601000)
assert.equal(qualified.status.leaseExpiresEpoch, 103)
assert.equal(bootstrapCalls.includes('https://raw-only.example/api/blind/v1/describe'), false,
  'a raw URL never reaches descriptor bootstrap')
const qualificationFailureCodes = new Set(qualified.failures.map(failure => failure.code))
for (const requiredCode of [
  'DESCRIPTOR_FORK',
  'PEERIT_DESCRIPTOR_ADMISSION_PROFILE_DRIFT',
  'RELAY_NOT_QUALIFIED',
  'RELAY_PROTOCOL_VIOLATION'
]) assert.equal(qualificationFailureCodes.has(requiredCode), true, `missing ${requiredCode}`)
assert.ok(createdAdapterContexts.length >= 2)
assert.equal(isPeeritVerifiedRelayAdapter(qualified.adapters[0]), true)
assert.equal(isPeeritVerifiedRelayAdapter({ deliver: async () => ({ ok: true }) }), false,
  'adapter-shaped input cannot forge the Peerit verified-relay brand')
assert.match(qualified.adapters[0].id, new RegExp(`${asHex(valid.root)}:${asHex(valid.storeId)}`))
assert.ok(!qualified.adapters[0].id.includes(asHex(forkA.root)), 'a fork removes its earlier provisional adapter')
await qualified.adapters[0].deliver({})
qualificationClock = 601000
await assert.rejects(qualified.adapters[0].deliver({}), error =>
  error && error.code === 'PEERIT_RELAY_QUALIFICATION_EXPIRED' && error.definitelyNotProcessed === true)
await assert.rejects(qualified.adapters[0].reconcile({}), error =>
  error && error.code === 'PEERIT_RELAY_QUALIFICATION_EXPIRED' && error.definitelyNotProcessed !== true)

qualificationClock = 1000
qualificationEpoch = 102
await qualified.adapters[0].deliver({})
qualificationEpoch = 103
await assert.rejects(qualified.adapters[0].deliver({}), error =>
  error && error.code === 'PEERIT_RELAY_QUALIFICATION_EXPIRED' && error.definitelyNotProcessed === true)
await assert.rejects(qualified.adapters[0].reconcile({}), error =>
  error && error.code === 'PEERIT_RELAY_QUALIFICATION_EXPIRED' && error.definitelyNotProcessed !== true)
qualificationEpoch = 100
await assert.rejects(qualified.adapters[0].deliver({}), error =>
  error && error.code === 'PEERIT_RELAY_QUALIFICATION_CLOCK_INVALID' && error.definitelyNotProcessed === true)
qualificationEpoch = 101
const timeoutFixtures = Array.from({ length: 8 }, (_, index) => relayFixture(
  `https://timeout-${index}.example/api/blind/v1/describe`,
  { root: 0x60 + index, store: 0x70 + index, hash: 0x80 + index, mode: 'timeout' }
))
const boundedCandidates = collectPermissionlessRelayCandidates({
  dht: [
    { canonicalUrl: valid.url, expectedDescriptorHash: valid.descriptorHash, continuityRootRelayPublicKey: valid.root },
    ...timeoutFixtures.map(fixture => ({
      canonicalUrl: fixture.url,
      expectedDescriptorHash: fixture.descriptorHash,
      continuityRootRelayPublicKey: fixture.root
    }))
  ]
})
const boundedStartedAt = Date.now()
const bounded = await qualifyPermissionlessRelayCandidates({
  ...qualificationOptions,
  candidates: boundedCandidates,
  trustStore: new FakeDescriptorTrustStore(),
  bootstrapClient: new FakeBootstrapClient(),
  directClient: new FakeDirectClient(),
  totalQualificationTimeoutMillis: 1000,
  maxConcurrentQualifications: 8
})
assert.equal(bounded.status.qualifiedRelayCount, 1)
assert.equal(bounded.status.qualificationTimedOut, true)
assert.equal(bounded.status.qualificationDeadlineMillis, 1000)
assert.ok(Date.now() - boundedStartedAt < 4000,
  'untrusted timeout candidates cannot extend qualification beyond its absolute deadline')
const adapterTimeoutCandidates = collectPermissionlessRelayCandidates({
  user: [{
    canonicalUrl: valid.url,
    expectedDescriptorHash: valid.descriptorHash,
    continuityRootRelayPublicKey: valid.root
  }]
})
let adapterQualificationSignal = null
const adapterTimeoutStartedAt = Date.now()
const adapterTimedOut = await qualifyPermissionlessRelayCandidates({
  ...qualificationOptions,
  candidates: adapterTimeoutCandidates,
  trustStore: new FakeDescriptorTrustStore(),
  bootstrapClient: new FakeBootstrapClient(),
  directClient: new FakeDirectClient(),
  totalQualificationTimeoutMillis: 1000,
  async createRelayAdapter ({ signal }) {
    adapterQualificationSignal = signal
    return new Promise(() => {})
  }
})
assert.equal(adapterTimedOut.status.qualificationTimedOut, true)
assert.equal(adapterTimedOut.adapters.length, 0)
assert.equal(adapterQualificationSignal.aborted, true,
  'the absolute deadline aborts and escapes even an adapter factory that ignores its signal')
assert.ok(Date.now() - adapterTimeoutStartedAt < 4000,
  'an adapter factory cannot escape the absolute qualification deadline')
const enforcedSync = createSync({
  mode: 'substrate',
  journal: createMemoryPeeritJournal(),
  relays: [{ id: 'raw-bypass', deliver: async () => ({ ok: true }) }],
  requireVerifiedRelayAdapters: true,
  autoFlush: false
})
await enforcedSync.ready()
assert.equal((await enforcedSync.status()).peers, 0, 'production substrate sync rejects a raw adapter bypass')
enforcedSync.setRelays([
  { id: 'raw-bypass', deliver: async () => ({ ok: true }) },
  qualified.adapters[0]
])
assert.equal((await enforcedSync.status()).peers, 1, 'production substrate sync accepts only the module-branded adapter')
enforcedSync.destroy()
assert.deepEqual(PEERIT_BLIND_CLIENT_PERSISTENCE_BLOCKERS, [
  'PORTABLE_CELL_CAPABILITY_RECOVERY_BUNDLE_UNASSEMBLED'
])

console.log('peerit-relay-consumer: hints stay inert; verified admission/health endpoints dedupe and quarantine before install')
