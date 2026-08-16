import assert from 'node:assert/strict'
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign
} from 'node:crypto'
import fs from 'node:fs/promises'
import {
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1,
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1,
  PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  createPeeritSeq29LimitedInboxCeremonyAuthorityV1,
  createPeeritSeq29LimitedInboxCeremonyFixtureAuthorityV1,
  dryRunPeeritLimitedInboxTopicCeremonyV1,
  executePeeritLimitedInboxTopicCeremonyV1,
  finalizePeeritLimitedInboxTopicCeremonyV1,
  peeritLimitedInboxTopicCeremonyPlanHashV1,
  validatePeeritLimitedInboxTopicCeremonyPlanV1
} from '../scripts/limited-inbox-topic-ceremony.mjs'
import {
  createPeeritSeq29BoundedPublicationAuthorityV1,
  createPeeritSeq29BoundedPublicationFixtureAuthorityV1,
  preparePeeritSeq29BoundedPublicationV1,
  runPeeritSeq29BoundedPublicationDrillV1,
  validatePeeritSeq29PublicationInputsBeforeAttemptV1,
  validatePeeritSeq29PreparedPutReadbackBindingV1,
  validatePeeritSeq29PublicationSigningRequestV1
} from '../scripts/limited-public-inbox-publication-drill.mjs'
import {
  PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1,
  PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1,
  hashPeeritLimitedPublicInboxSignedWrapperV1,
  signPeeritLimitedPublicInboxBootstrapV1,
  validatePeeritLimitedPublicInboxSignedWrapperV1,
  validatePeeritLimitedPublicInboxSigningPackageV1
} from '../scripts/sign-limited-public-inbox-bootstrap.mjs'
import {
  canonicalPeeritLimitedPublicInboxJsonV1
} from '../js/substrate/inbox-topic-v1.mjs'
import { blake2b256 } from '../js/substrate/release-control-primitives.mjs'
import {
  decodeBlindExternalProfileValueV1
} from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'

const fixture = JSON.parse(await fs.readFile(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json',
  import.meta.url)))
const protocolVector = JSON.parse(await fs.readFile(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-protocol-vector.json',
  import.meta.url)))
process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST = '1'
const fixtureSet = fixture.payload.inboxEpochSets[0]
const fromHex = value => new Uint8Array(Buffer.from(value, 'hex'))
const toHex = value => Buffer.from(value).toString('hex')
const objectDigest = value => createHash('sha256')
  .update(canonicalPeeritLimitedPublicInboxJsonV1(value)).digest('hex')

function u32 (value) {
  return Buffer.from([
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255
  ])
}

function fixtureSeed (label) {
  return createHash('sha256').update(Buffer.concat([
    Buffer.from('peerit.seq29.fixture-only.generator.v1', 'ascii'),
    Buffer.from([0]),
    Buffer.from(`ed25519:${label}`, 'utf8'),
    u32(0)
  ])).digest('hex')
}

function publicForSeed (seed) {
  return new Uint8Array(createPublicKey(createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed)
    ]),
    format: 'der',
    type: 'pkcs8'
  })).export({ format: 'der', type: 'spki' }).subarray(-32))
}

function u64 (value) {
  const out = Buffer.alloc(8)
  out.writeBigUInt64BE(BigInt(value))
  return out
}

function signingPackage (payload = fixture.payload) {
  const clonedPayload = structuredClone(payload)
  const set = clonedPayload.inboxEpochSets[0]
  return {
    schema: PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1,
    version: 1,
    offlineOnly: true,
    hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    createRequests: set.bindings.map((binding, index) => {
      const receipt = decodeBlindExternalProfileValueV1(
        'InboxReceiptV1', fromHex(binding.createReceiptCanonicalHex))
      return {
        relayId: binding.relayId,
        allocationEpoch: binding.allocationEpoch,
        physicalTopic: binding.physicalTopic,
        frameClassBits: 3,
        appendAuthMode: 0,
        createPublicKey: binding.createPublicKey,
        appendPublicKey: null,
        renewPublicKey: (index === 0 ? '71' : '72').repeat(32),
        closePublicKey: (index === 0 ? '81' : '82').repeat(32),
        retentionClass: 3,
        leaseClass: 4,
        clientNonce: toHex(receipt.requestNonce),
        createCommitment: (index === 0 ? '91' : '92').repeat(32),
        requestCommitment: toHex(receipt.requestCommitment)
      }
    }),
    payload: clonedPayload
  }
}

const packageBytes = Buffer.from(JSON.stringify(signingPackage(), null, 2) + '\n')
const checked = validatePeeritLimitedPublicInboxSigningPackageV1(
  packageBytes, { allowFixture: true })
assert.equal(checked.payload.inboxEpochSets[0].bindings.length, 2)
assert.equal(Object.isFrozen(checked.payload.inboxEpochSets[0].bindings[0]), true)
assert.throws(
  () => validatePeeritLimitedPublicInboxSigningPackageV1(
    packageBytes.subarray(0, packageBytes.byteLength - 1), { allowFixture: true }),
  error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_NONCANONICAL')
assert.throws(
  () => validatePeeritLimitedPublicInboxSigningPackageV1(signingPackage()),
  error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_ARTIFACT_CLASS')

for (const mutate of [
  value => { value.payload.inboxEpochSets[0].bindings[0].createReceiptCanonicalHex = '00' },
  value => {
    value.payload.inboxEpochSets[0].bindings[0].createReceiptCanonicalHex =
      value.payload.inboxEpochSets[0].bindings[1].createReceiptCanonicalHex
  }
]) {
  const malformedReceiptPackage = signingPackage()
  mutate(malformedReceiptPackage)
  assert.throws(
    () => signPeeritLimitedPublicInboxBootstrapV1({
      signingPackage: malformedReceiptPackage,
      environment: {
        [PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1]: fixtureSeed('bootstrap-authority')
      },
      allowFixture: true
    }),
    error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_RECEIPT_INVALID',
    'malformed or cross-bound CREATE receipt is rejected before signing')
}

const secretProbe = structuredClone(fixture.payload)
secretProbe.relays[0].descriptorFloor.probe = { nested: { managementSeed: '00'.repeat(32) } }
assert.throws(
  () => signPeeritLimitedPublicInboxBootstrapV1({
    signingPackage: signingPackage(secretProbe),
    environment: {
      [PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1]: fixtureSeed('bootstrap-authority')
    },
    allowFixture: true
  }),
  error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_SECRET',
  'nested managementSeed fails before a signed output exists')

for (const mutate of [
  payload => { payload.relays[0].descriptorFloor.unknown = true },
  payload => { payload.inboxEpochSets[0].unknown = true },
  payload => { payload.inboxEpochSets[0].bindings[0].unknown = true }
]) {
  const payload = structuredClone(fixture.payload)
  mutate(payload)
  assert.throws(
    () => validatePeeritLimitedPublicInboxSigningPackageV1(
      signingPackage(payload), { allowFixture: true }),
    error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID')
}

const signed = signPeeritLimitedPublicInboxBootstrapV1({
  signingPackage: packageBytes,
  environment: {
    [PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1]: fixtureSeed('bootstrap-authority')
  },
  allowFixture: true
})
assert.equal(signed.wrapper.signature, fixture.signature)
assert.deepEqual(JSON.parse(signed.canonicalBytes), fixture)
assert.equal(validatePeeritLimitedPublicInboxSignedWrapperV1(
  signed.canonicalBytes, { allowFixture: true }).signature, fixture.signature)
const wrapperUnknown = structuredClone(fixture)
wrapperUnknown.payload.relays[0].descriptorFloor.unknown = true
assert.throws(
  () => validatePeeritLimitedPublicInboxSignedWrapperV1(wrapperUnknown, { allowFixture: true }),
  error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID')
const wrapperExtra = { ...fixture, unknown: true }
assert.throws(
  () => validatePeeritLimitedPublicInboxSignedWrapperV1(wrapperExtra, { allowFixture: true }),
  error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID')
const wrapperTamper = structuredClone(fixture)
wrapperTamper.signature = `${wrapperTamper.signature.slice(0, -2)}00`
assert.throws(
  () => validatePeeritLimitedPublicInboxSignedWrapperV1(wrapperTamper, { allowFixture: true }),
  error => error.code === 'PEERIT_LIMITED_INBOX_SIGNER_SELF_VERIFY_FAILED')

const ceremonyPlan = {
  schema: PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1,
  version: 1,
  hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  releaseSequence: 29,
  claimBoundary: fixture.payload.claimBoundary,
  operatorBoundary: fixture.payload.operatorBoundary,
  topicScope: fixture.payload.topicScope,
  referenceUnixMillis: '1780000001000',
  bootstrapSequence: fixture.payload.bootstrapSequence,
  previousBootstrapHash: fixture.payload.previousBootstrapHash,
  issuedUnixMillis: fixture.payload.issuedUnixMillis,
  expiresUnixMillis: fixture.payload.expiresUnixMillis,
  authorityPublicKey: fixture.payload.authorityPublicKey,
  stripeSelectionKey: fixtureSet.stripeSelectionKey,
  announcementMasterKey: fixtureSet.announcementMasterKey,
  relays: fixture.payload.relays.map(relay => ({
    ...relay,
    allocationEpoch: fixtureSet.bindings.find(binding => binding.relayId === relay.relayId).allocationEpoch
  }))
}
const ceremonyHash = peeritLimitedInboxTopicCeremonyPlanHashV1(ceremonyPlan)
const ceremonyToken = `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${ceremonyHash}`
const ceremonyDryRun = dryRunPeeritLimitedInboxTopicCeremonyV1(ceremonyPlan)
assert.equal(ceremonyDryRun.operations.length, 2)
assert.equal(ceremonyDryRun.networkRequests, 0)
for (const port of ['0', '65536', '99999']) {
  const plan = structuredClone(ceremonyPlan)
  plan.relays[0].canonicalDescribeUrl = `https://fixture-relay-a.invalid:${port}/blind/v1/describe`
  assert.throws(
    () => validatePeeritLimitedInboxTopicCeremonyPlanV1(plan),
    error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID')
}

function durableJournal (options = {}) {
  const releases = new Map()
  const claims = new Set()
  const events = []
  let attempts = 0
  const receipt = (state, request, fields = {}) => {
    const value = {
      accepted: true,
      durable: true,
      state,
      ...('attemptId' in request ? { attemptId: request.attemptId } : {}),
      ...('releaseAttemptKey' in request ? { releaseAttemptKey: request.releaseAttemptKey } : {}),
      ...('planHash' in request ? { planHash: request.planHash } : {}),
      ...('releaseIdentityDigest' in request
        ? { releaseIdentityDigest: request.releaseIdentityDigest }
        : {}),
      ...('operationKey' in request ? { operationKey: request.operationKey } : {}),
      requestDigest: objectDigest(request),
      ...fields,
      commitment: `${state.toLowerCase()}:${events.length}`
    }
    if (options.wrongClaimAttempt && state === 'DISPATCH_CLAIMED') {
      value.attemptId = 'wrong-attempt'
    }
    if (options.wrongOutcomeOperation && state === 'VERIFIED_TERMINAL') {
      value.operationKey = 'wrong-operation'
    }
    if (options.wrongFinishDigest &&
        (state === 'COMMITTED_CREATE_ONLY' || state === 'COMMITTED_EXACT_BUDGET')) {
      value.executionDigest = '00'.repeat(32)
    }
    return value
  }
  return {
    events,
    async beginAttempt (value) {
      events.push(`begin:${value.releaseAttemptKey}`)
      const existing = releases.get(value.releaseAttemptKey)
      if (existing?.recovery) {
        return receipt('RECOVERY_AVAILABLE_NO_RESEND', value, {
          attemptId: existing.attemptId,
          recovery: existing.recovery
        })
      }
      if (existing) {
        const error = new Error('attempt token is already consumed')
        error.code = 'PEERIT_TEST_ATTEMPT_REUSED'
        throw error
      }
      attempts++
      const attemptId = `attempt-${attempts}`
      releases.set(value.releaseAttemptKey, { attemptId, recovery: null })
      return receipt('CONSUMED_NO_MUTATIONS', value, { attemptId })
    },
    async claimOperation (value) {
      events.push(`claim:${value.operationKey}`)
      if (claims.has(`${value.attemptId}:${value.operationKey}`)) {
        throw Object.assign(new Error('duplicate operation claim'), { code: 'PEERIT_TEST_DUPLICATE_CLAIM' })
      }
      claims.add(`${value.attemptId}:${value.operationKey}`)
      return receipt('DISPATCH_CLAIMED', value)
    },
    async recordOutcome (value) {
      events.push(`outcome:${value.operationKey}:${value.state}`)
      return receipt(value.state, value)
    },
    async persistRecovery (value) {
      events.push(`persist-recovery:${value.recoveryDigest}`)
      const release = releases.get(value.releaseAttemptKey)
      assert.equal(release?.attemptId, value.attemptId)
      release.recovery = structuredClone(value.recovery)
      return receipt('RECOVERY_DURABLE_NO_RESEND', value, {
        recoveryDigest: value.recoveryDigest
      })
    },
    async finishAttempt (value) {
      events.push(`finish:${value.state}`)
      if (value.state === 'COMMITTED_CREATE_ONLY') {
        assert.equal(typeof value.custodyCommitment, 'string')
        assert.ok(value.custodyCommitment.length > 0)
      }
      const fields = {}
      if (value.executionDigest) fields.executionDigest = value.executionDigest
      return receipt(value.state, value, fields)
    },
    attempts: () => attempts,
    options
  }
}

function custodyTransaction (options = {}) {
  const events = []
  const snapshots = []
  const pending = new Map()
  const publicBindings = new Map()
  const finalized = new Set()
  let prepared = 0
  return {
    events,
    snapshots,
    async prepare (value) {
      events.push('custody:prepare')
      if (options.rejectPrepare) {
        throw Object.assign(new Error('custody unavailable'), { code: 'PEERIT_TEST_CUSTODY_REJECTED' })
      }
      const seeds = value.entries.flatMap(entry =>
        ['createPrivateSeed', 'renewPrivateSeed', 'closePrivateSeed'].map(field => entry[field]))
      assert.equal(value.entries.every(entry => !('appendPrivateSeed' in entry)), true)
      assert.equal(seeds.length, 6)
      assert.equal(seeds.every(seed => seed.some(byte => byte !== 0)), true)
      assert.equal(new Set(seeds.map(toHex)).size, 6)
      snapshots.push(seeds.map(toHex))
      prepared++
      pending.set(`custody-${prepared}`, structuredClone(value))
      return {
        accepted: true,
        durable: true,
        state: 'SEALED_PENDING_CREATE',
        transactionId: `custody-${prepared}`,
        commitment: `sealed-${prepared}`
      }
    },
    async commitPublicBinding (value) {
      events.push('custody:commit-public-binding')
      if (options.rejectPublicBindingOnce &&
          events.filter(event => event === 'custody:commit-public-binding').length === 1) {
        throw Object.assign(new Error('injected durable public-binding outage'), {
          code: 'PEERIT_TEST_PUBLIC_BINDING_OUTAGE'
        })
      }
      const sealed = pending.get(value.transactionId)
      assert.ok(sealed)
      if (options.substitutePackage) value = { ...value, signingPackage: signingPackage() }
      assert.equal(objectDigest(value.signingPackage), value.signingPackageSha256)
      assert.equal(objectDigest({
        schema: 'peerit-seq29-limited-inbox-custody-public-binding-v1',
        planHash: value.planHash,
        signingPackageSha256: value.signingPackageSha256,
        signingPackage: value.signingPackage
      }), value.publicBindingDigest)
      for (const entry of sealed.entries) {
        const request = value.signingPackage.createRequests
          .find(row => row.relayId === entry.relayId)
        const binding = value.signingPackage.payload.inboxEpochSets[0].bindings
          .find(row => row.relayId === entry.relayId)
        assert.ok(request && binding)
        assert.equal(request.createPublicKey, toHex(publicForSeed(entry.createPrivateSeed)))
        assert.equal(request.renewPublicKey, toHex(publicForSeed(entry.renewPrivateSeed)))
        assert.equal(request.closePublicKey, toHex(publicForSeed(entry.closePrivateSeed)))
        assert.equal(request.physicalTopic, binding.physicalTopic)
        assert.equal(request.createPublicKey, binding.createPublicKey)
        decodeBlindExternalProfileValueV1(
          'InboxReceiptV1', fromHex(binding.createReceiptCanonicalHex))
      }
      const prior = publicBindings.get(value.transactionId)
      if (prior && prior !== value.publicBindingDigest) {
        throw Object.assign(new Error('custody public binding substitution'), {
          code: 'PEERIT_TEST_CUSTODY_PUBLIC_BINDING_SUBSTITUTION'
        })
      }
      publicBindings.set(value.transactionId, value.publicBindingDigest)
      return {
        accepted: true,
        durable: true,
        state: 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP',
        transactionId: value.transactionId,
        signingPackageSha256: value.signingPackageSha256,
        publicBindingDigest: value.publicBindingDigest,
        commitment: `public-bound-${value.transactionId}`
      }
    },
    async finalizeSignedBootstrap (value) {
      events.push('custody:finalize-signed-bootstrap')
      assert.equal(publicBindings.get(value.transactionId), value.publicBindingDigest)
      if (finalized.has(value.transactionId)) {
        throw Object.assign(new Error('custody already finalized'), {
          code: 'PEERIT_TEST_CUSTODY_ALREADY_FINALIZED'
        })
      }
      assert.equal(objectDigest(value.signedBootstrap), value.signedBootstrapHash)
      const managementBundleDigest = objectDigest({
        transactionId: value.transactionId,
        publicBindingDigest: value.publicBindingDigest,
        signedBootstrapHash: value.signedBootstrapHash,
        entries: pending.get(value.transactionId).entries.map(entry => ({
          relayId: entry.relayId,
          createPublicKey: toHex(publicForSeed(entry.createPrivateSeed)),
          renewPublicKey: toHex(publicForSeed(entry.renewPrivateSeed)),
          closePublicKey: toHex(publicForSeed(entry.closePrivateSeed))
        }))
      })
      finalized.add(value.transactionId)
      return {
        accepted: true,
        durable: true,
        state: 'COMMITTED',
        transactionId: value.transactionId,
        publicBindingDigest: value.publicBindingDigest,
        signedBootstrapHash: value.signedBootstrapHash,
        finalizationDigest: value.finalizationDigest,
        managementBundleDigest,
        commitment: `finalized-${value.transactionId}`
      }
    },
    async quarantine (value) {
      events.push(`custody:quarantine:${value.disposition}`)
      return {
        accepted: true,
        durable: true,
        state: 'QUARANTINED',
        transactionId: value.transactionId,
        commitment: `quarantined-${value.transactionId}`
      }
    }
  }
}

function ceremonyControl (options = {}) {
  const calls = []
  const capabilities = []
  const receiptByRelay = new Map()
  let destroyed = 0
  let decoded = 0
  const control = {
    async createInboxReplica (input) {
      const relayKey = toHex(input.relayPublicKey)
      const binding = fixtureSet.bindings.find(value => value.relayPublicKey === relayKey)
      assert.ok(binding)
      const marker = calls.length + 1
      const createSeed = fromHex(fixtureSeed(`fixture-only-inbox-create-${marker - 1}`))
      const renewSeed = fromHex(fixtureSeed(`fixture-only-inbox-renew-${marker - 1}`))
      const closeSeed = fromHex(fixtureSeed(`fixture-only-inbox-close-${marker - 1}`))
      const existingReceipt = decodeBlindExternalProfileValueV1(
        'InboxReceiptV1', fromHex(binding.createReceiptCanonicalHex))
      const createPublicKey = publicForSeed(createSeed)
      const renewPublicKey = publicForSeed(renewSeed)
      const closePublicKey = publicForSeed(closeSeed)
      const createCommitment = blake2b256(Buffer.concat([
        Buffer.from('hiverelay.blind.inbox-create.v1', 'ascii'),
        Buffer.from(binding.relayPublicKey, 'hex'),
        Buffer.from(binding.physicalTopic, 'hex'),
        u32(binding.allocationEpoch),
        Buffer.from([3, 0]),
        Buffer.alloc(32),
        Buffer.from(createPublicKey),
        Buffer.from(renewPublicKey),
        Buffer.from(closePublicKey),
        Buffer.from([3, 4])
      ]))
      const requestCommitment = blake2b256(Buffer.concat([
        Buffer.from('hiverelay.blind.request.v1inbox-create', 'ascii'),
        Buffer.from(createCommitment),
        Buffer.from(existingReceipt.requestNonce)
      ]))
      const writeCap = {
        createPrivateKey: createSeed,
        appendPrivateKey: options.malformedAt === marker ? new Uint8Array(32).fill(9) : null,
        renewPrivateKey: renewSeed,
        closePrivateKey: closeSeed
      }
      const created = {
        request: {
          allocationEpoch: binding.allocationEpoch,
          physicalTopic: fromHex(binding.physicalTopic),
          frameClassBits: 3,
          appendAuthMode: 0,
          createPublicKey,
          appendPublicKey: null,
          renewPublicKey,
          closePublicKey,
          retentionClass: 3,
          leaseClass: 4,
          clientNonce: existingReceipt.requestNonce
        },
        requestBytes: new Uint8Array([marker]),
        requestCommitment,
        createCommitment,
        wire: { familyId: 3, operationId: 1, expectedResultBodyBytes: 16384 },
        readCap: {
          relayPublicKey: fromHex(binding.relayPublicKey),
          physicalTopic: fromHex(binding.physicalTopic),
          frameClassBits: 3,
          appendAuthMode: 0,
          appendPublicKey: null
        },
        writeCap
      }
      calls.push({ input, binding })
      capabilities.push(writeCap)
      const receiptBytes = fromHex(binding.createReceiptCanonicalHex)
      receiptBytes.set(existingReceipt.requestNonce, 257)
      receiptBytes.set(requestCommitment, 289)
      const unsigned = receiptBytes.subarray(0, receiptBytes.byteLength - 64)
      const relaySeed = fixtureSeed(binding.relayId.endsWith('a') ? 'relay-a' : 'relay-b')
      const relayPrivateKey = createPrivateKey({
        key: Buffer.concat([
          Buffer.from('302e020100300506032b657004220420', 'hex'),
          Buffer.from(relaySeed, 'hex')
        ]),
        format: 'der',
        type: 'pkcs8'
      })
      const signature = nodeSign(null, Buffer.concat([
        Buffer.from('hiverelay.blind.inbox-receipt.v1', 'ascii'),
        u64(unsigned.byteLength),
        Buffer.from(unsigned)
      ]), relayPrivateKey)
      receiptBytes.set(signature, unsigned.byteLength)
      receiptByRelay.set(binding.relayId, receiptBytes)
      return created
    },
    async verifyOperationResult ({ endpoint }) {
      return { snapshotBytes: () => receiptByRelay.get(endpoint.relayId) }
    },
    decodeBlindExternalProfileValueV1 (_name, receiptBytes) {
      decoded++
      const binding = fixtureSet.bindings.find(value =>
        toHex(receiptByRelay.get(value.relayId)) === toHex(receiptBytes))
      const relay = fixture.payload.relays.find(value => value.relayId === binding.relayId)
      return {
        relayBinding: {
          relayPublicKey: fromHex(relay.relayPublicKey),
          storeId: options.tamperStore ? new Uint8Array(32).fill(0xee) : fromHex(relay.storeId),
          durabilityContinuityHash: fromHex(relay.durabilityContinuityHash),
          descriptorSequence: BigInt(relay.descriptorFloor.sequence),
          descriptorHash: fromHex(relay.descriptorFloor.hash)
        },
        topicCommitment: blake2b256(fromHex(binding.physicalTopic)),
        result: 1,
        stateRevision: 0n,
        leaseClass: 4
      }
    },
    destroyInboxWriteCapability (cap) {
      destroyed++
      for (const field of [
        'createPrivateKey', 'appendPrivateKey', 'renewPrivateKey', 'closePrivateKey'
      ]) cap[field]?.fill(0)
    }
  }
  return { control, calls, capabilities, decoded: () => decoded, destroyed: () => destroyed }
}

function ceremonyExecution (overrides = {}) {
  const journal = overrides.journal || durableJournal()
  const custody = overrides.custody || custodyTransaction()
  const harness = overrides.harness || ceremonyControl()
  const transportCalls = overrides.transportCalls || []
  const plan = overrides.plan || ceremonyPlan
  const endpointByRelay = new Map(plan.relays.map(relay =>
    [relay.relayId, { relayId: relay.relayId }]))
  const admissionProviderByRelay = new Map(plan.relays.map(relay =>
    [relay.relayId, async () => ({})]))
  const clientNonceByRelay = new Map(plan.relays.map(relay => [relay.relayId, null]))
  const transportCreate = async value => {
    transportCalls.push(value.relayId)
    if (overrides.ambiguousRelay === value.relayId) {
      throw Object.assign(new Error('socket closed after send'), { code: 'AMBIGUOUS' })
    }
    return { ok: true, body: new Uint8Array([7]) }
  }
  const authority = createPeeritSeq29LimitedInboxCeremonyFixtureAuthorityV1({
    allowFixture: true,
    plan,
    control: harness.control,
    runtime: {},
    endpointByRelay,
    admissionProviderByRelay,
    clientNonceByRelay,
    transportCreate
  })
  return {
    journal,
    custody,
    harness,
    transportCalls,
    input: {
      authority,
      commitToken: overrides.commitToken || ceremonyToken,
      attemptJournal: journal,
      custodyTransaction: custody
    }
  }
}

const ceremony = ceremonyExecution()
await assert.rejects(
  createPeeritSeq29LimitedInboxCeremonyAuthorityV1({
    plan: ceremonyPlan,
    hiverelaySourceRoot: '/private/tmp/not-an-authority',
    relays: [],
    control: ceremony.harness.control,
    transportCreate () {}
  }),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID',
  'production ceremony factory rejects raw control/transport injection')
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1({
    ...ceremony.input,
    control: ceremony.harness.control,
    transportCreate () {}
  }),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_PLAN_INVALID')
assert.equal(ceremony.transportCalls.length, 0,
  'raw production ceremony callbacks fail before transport')
const ceremonyResult = await executePeeritLimitedInboxTopicCeremonyV1(ceremony.input)
assert.equal(ceremonyResult.mutationLedger.inboxCreate, 2)
assert.match(ceremonyResult.journalCommitment, /^recovery_durable_no_resend:/)
assert.deepEqual(ceremony.transportCalls,
  ceremonyPlan.relays.map(relay => relay.relayId))
assert.equal(ceremony.harness.decoded(), 2)
assert.equal(ceremony.custody.events[0], 'custody:prepare')
assert.equal(ceremony.custody.events.at(-1), 'custody:commit-public-binding')
assert.equal(ceremony.harness.destroyed(), 2)
assert.equal(ceremony.harness.capabilities.every(cap =>
  ['createPrivateKey', 'renewPrivateKey', 'closePrivateKey']
    .every(field => cap[field].every(byte => byte === 0))), true)
validatePeeritLimitedPublicInboxSigningPackageV1(
  Buffer.from(JSON.stringify(ceremonyResult.signingPackage, null, 2) + '\n'))

const transportBeforeReuse = ceremony.transportCalls.length
const recoveredCeremony = await executePeeritLimitedInboxTopicCeremonyV1(ceremony.input)
assert.equal(recoveredCeremony.status, 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP')
assert.equal(ceremony.transportCalls.length, transportBeforeReuse,
  'durable ceremony recovery never resends CREATE')

const ceremonySigned = signPeeritLimitedPublicInboxBootstrapV1({
  signingPackage: ceremonyResult.signingPackage,
  environment: {
    [PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1]: fixtureSeed('bootstrap-authority')
  },
  allowFixture: true
})
const finalizedCeremony = await finalizePeeritLimitedInboxTopicCeremonyV1({
  authority: ceremony.input.authority,
  commitToken: ceremony.input.commitToken,
  signedBootstrap: ceremonySigned.wrapper,
  attemptJournal: ceremony.journal,
  custodyTransaction: ceremony.custody
})
assert.equal(finalizedCeremony.status, 'COMMITTED_CREATE_ONLY')
assert.equal(finalizedCeremony.signedBootstrapHash, ceremonySigned.signedBootstrapHash)
assert.equal(finalizedCeremony.signedBootstrapHash,
  hashPeeritLimitedPublicInboxSignedWrapperV1(ceremonySigned.canonicalBytes, {
    allowFixture: true,
    createRequests: ceremonyResult.signingPackage.createRequests
  }), 'ceremony finalization and publication phase one share the protocol complete-wrapper hash')
assert.equal(finalizedCeremony.signedBootstrapHash,
  objectDigest(ceremonySigned.wrapper),
  'ceremony custody uses the authoritative compact-canonical protocol identity')
assert.equal(hashPeeritLimitedPublicInboxSignedWrapperV1(
  Buffer.from(JSON.stringify(fixture, null, 2) + '\n'), { allowFixture: true }),
protocolVector.bootstrapFloor.completeSignedWrapperHash,
'the signer helper reproduces the authoritative protocol vector wrapper identity')
assert.match(finalizedCeremony.managementBundleDigest, /^[0-9a-f]{64}$/)
assert.equal(ceremony.transportCalls.length, transportBeforeReuse,
  'signed-bootstrap custody finalization performs no CREATE resend')
await assert.rejects(
  finalizePeeritLimitedInboxTopicCeremonyV1({
    authority: ceremony.input.authority,
    commitToken: ceremony.input.commitToken,
    signedBootstrap: ceremonySigned.wrapper,
    attemptJournal: ceremony.journal,
    custodyTransaction: ceremony.custody
  }),
  error => error.code === 'PEERIT_TEST_CUSTODY_ALREADY_FINALIZED')

const substitutedCustody = ceremonyExecution({
  custody: custodyTransaction({ substitutePackage: true })
})
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(substitutedCustody.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED' &&
    error.details.transportInvocations === 2)
assert.equal(substitutedCustody.transportCalls.length, 2,
  'custody package substitution cannot trigger CREATE retry or finalization')

const resumableCustody = ceremonyExecution({
  custody: custodyTransaction({ rejectPublicBindingOnce: true })
})
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(resumableCustody.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED' &&
    error.details.recoveryPersisted === true && error.details.transportInvocations === 2)
assert.equal(resumableCustody.journal.events.some(event =>
  event === 'finish:QUARANTINED_TERMINAL_NO_RETRY'), false,
'a post-recovery custody outage must preserve the resumable release slot')
const resumedCustody = await executePeeritLimitedInboxTopicCeremonyV1(resumableCustody.input)
assert.equal(resumedCustody.status, 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP')
assert.equal(resumableCustody.transportCalls.length, 2,
  'resuming an exact persisted signing package never resends CREATE')

const changedPlan = structuredClone(ceremonyPlan)
changedPlan.announcementMasterKey = 'ab'.repeat(32)
const changedPlanHash = peeritLimitedInboxTopicCeremonyPlanHashV1(changedPlan)
const changedPlanExecution = ceremonyExecution({
  plan: changedPlan,
  journal: ceremony.journal,
  custody: ceremony.custody,
  harness: ceremony.harness,
  transportCalls: ceremony.transportCalls,
  commitToken: `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${changedPlanHash}`
})
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(changedPlanExecution.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_DURABILITY_INVALID')
assert.equal(ceremony.transportCalls.length, transportBeforeReuse,
  'a different valid plan cannot reopen the fixed Seq29 ceremony slot')

const custodyFailure = ceremonyExecution({ custody: custodyTransaction({ rejectPrepare: true }) })
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(custodyFailure.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED' &&
    error.details.transportInvocations === 0)
assert.equal(custodyFailure.transportCalls.length, 0,
  'durable custody rejection occurs before any CREATE mutation')
assert.equal(custodyFailure.harness.destroyed(), 2)

const malformed = ceremonyExecution({ harness: ceremonyControl({ malformedAt: 2 }) })
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(malformed.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED' &&
    error.details.transportInvocations === 0)
assert.equal(malformed.harness.destroyed(), 2,
  'every generated capability is destroyed even when validation fails')

const receiptTamper = ceremonyExecution({ harness: ceremonyControl({ tamperStore: true }) })
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(receiptTamper.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED' &&
    error.details.causeCode === 'PEERIT_LIMITED_INBOX_CEREMONY_RECEIPT_INVALID')
assert.equal(receiptTamper.custody.events.some(event => event.startsWith('custody:quarantine:')), true)

const ambiguousCeremony = ceremonyExecution({ ambiguousRelay: ceremonyPlan.relays[1].relayId })
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(ambiguousCeremony.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED' &&
    error.details.transportInvocations === 2)
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(ambiguousCeremony.input),
  error => error.code === 'PEERIT_TEST_ATTEMPT_REUSED')
assert.equal(ambiguousCeremony.transportCalls.length, 2,
  'ambiguous CREATE is terminal and restart cannot exceed the two-CREATE budget')

const badToken = ceremonyExecution()
badToken.input.commitToken = 'wrong'
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(badToken.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_COMMIT_REQUIRED')
assert.equal(badToken.journal.attempts(), 0)
assert.equal(badToken.transportCalls.length, 0)

const wrongCeremonyClaim = ceremonyExecution({
  journal: durableJournal({ wrongClaimAttempt: true })
})
await assert.rejects(
  executePeeritLimitedInboxTopicCeremonyV1(wrongCeremonyClaim.input),
  error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_QUARANTINED' &&
    error.details.transportInvocations === 0)
assert.equal(wrongCeremonyClaim.transportCalls.length, 0,
  'mis-correlated durable claim cannot precede a CREATE send')

const vectorInnerBytes = fromHex(protocolVector.inner.canonicalHex)
const vectorAnnouncementBytes = fromHex(protocolVector.announcement.canonicalHex)
const vectorPublication = Object.freeze({
  innerCodec: protocolVector.inner.codec,
  innerBytes: vectorInnerBytes,
  innerLength: protocolVector.inner.byteLength,
  sizeClass: protocolVector.cells[0].sizeClass,
  logicalHash: fromHex(protocolVector.inner.logicalHash),
  encodingCommitment: fromHex(protocolVector.inner.encodingCommitment)
})
const vectorReadCaps = protocolVector.cells.map(cell =>
  decodeBlindExternalProfileValueV1(
    'ReadCellCapV1', fromHex(cell.readCapabilityCanonicalHex)))

const preAttemptRows = protocolVector.cells.map((cell, index) => ({
  relayId: `relay-${index}`
}))
const preAttemptPublication = {
  intentId: 'seq29-vector-intent',
  logicalId: 'seq29-vector-logical',
  ...vectorPublication
}
const preAttemptPublications = Object.fromEntries(preAttemptRows.map(row => [
  row.relayId, structuredClone(preAttemptPublication)
]))
assert.match(validatePeeritSeq29PublicationInputsBeforeAttemptV1({
  rows: preAttemptRows,
  publications: preAttemptPublications
}).publicationDigest, /^[0-9a-f]{64}$/)
const preAttemptBeginCalls = 0
for (const [field, mutate] of [
  ['logicalHash', value => { value.logicalHash[0] ^= 1 }],
  ['encodingCommitment', value => { value.encodingCommitment[0] ^= 1 }],
  ['sizeClass', value => { value.sizeClass++ }]
]) {
  const publications = structuredClone(preAttemptPublications)
  mutate(publications[preAttemptRows[0].relayId])
  assert.throws(() => validatePeeritSeq29PublicationInputsBeforeAttemptV1({
    rows: preAttemptRows,
    publications
  }), error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
  `${field} mismatch fails before a publication attempt begins`)
}
assert.equal(preAttemptBeginCalls, 0,
  'intrinsic publication mismatches cannot consume the fixed release slot or dispatch PUT')

const vectorSigningRequest = {
  schema: 'peerit-seq29-publication-signing-request-v1',
  version: 1,
  candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  releaseSequence: 29,
  bootstrapHash: hashPeeritLimitedPublicInboxSignedWrapperV1(
    Buffer.from(JSON.stringify(fixture, null, 2) + '\n'), { allowFixture: true }),
  releaseIdentityDigest: 'a7'.repeat(32),
  authorSequence: protocolVector.authorBind.authorSequence,
  previousAuthorRecordId: protocolVector.authorBind.previousAuthorRecordId,
  authorPublicKey: protocolVector.authorBind.authorPublicKey,
  innerCodec: protocolVector.inner.codec,
  innerLength: String(protocolVector.inner.byteLength),
  innerBytesCanonicalHex: protocolVector.inner.canonicalHex,
  innerSha256: createHash('sha256').update(vectorInnerBytes).digest('hex'),
  logicalHash: protocolVector.inner.logicalHash,
  initialReplicas: protocolVector.cells.map(cell => {
    const receipt = decodeBlindExternalProfileValueV1(
      'BlindReceiptV1', fromHex(cell.relayReceiptCanonicalHex))
    const relay = fixture.payload.relays.find(value => value.relayPublicKey === cell.relayPublicKey)
    return {
      version: 1,
      logicalHash: cell.logicalHash,
      encodingCommitment: cell.encodingCommitment,
      relayId: relay.relayId,
      relayPublicKey: cell.relayPublicKey,
      storeId: toHex(receipt.relayBinding.storeId),
      durabilityContinuityHash: toHex(receipt.relayBinding.durabilityContinuityHash),
      readCapabilityCanonicalHex: cell.readCapabilityCanonicalHex,
      cellBlobHash: cell.cellBlobHash,
      sizeClass: cell.sizeClass,
      allocationEpoch: cell.allocationEpoch,
      leaseEpoch: cell.leaseEpoch,
      createPublicKey: cell.createPublicKey,
      renewPublicKey: cell.renewPublicKey,
      dropPublicKey: cell.dropPublicKey,
      allocationCommitment: cell.allocationCommitment,
      relayReceiptCanonicalHex: cell.relayReceiptCanonicalHex,
      putClientNonce: cell.capabilityBoundPut.clientNonce,
      putRequestCanonicalHex: cell.capabilityBoundPut.requestCanonicalHex,
      putRequestCommitment: cell.capabilityBoundPut.requestCommitment,
      putResultCanonicalHex: cell.relayReceiptCanonicalHex
    }
  }),
  publishedLeaseEpoch: protocolVector.announcement.publishedLeaseEpoch,
  publisherPublicKey: protocolVector.announcement.publisherPublicKey
}
const validatedVectorSigningRequest =
  validatePeeritSeq29PublicationSigningRequestV1(vectorSigningRequest)
assert.equal(validatedVectorSigningRequest.innerBytesCanonicalHex,
  protocolVector.inner.canonicalHex)
assert.deepEqual(validatedVectorSigningRequest.initialReplicas.map(row => ({
  version: row.version,
  logicalHash: row.logicalHash,
  encodingCommitment: row.encodingCommitment,
  relayPublicKey: row.relayPublicKey,
  readCapabilityCanonicalHex: row.readCapabilityCanonicalHex,
  cellBlobHash: row.cellBlobHash,
  sizeClass: row.sizeClass,
  allocationEpoch: row.allocationEpoch,
  leaseEpoch: row.leaseEpoch,
  createPublicKey: row.createPublicKey,
  renewPublicKey: row.renewPublicKey,
  dropPublicKey: row.dropPublicKey,
  allocationCommitment: row.allocationCommitment,
  relayReceiptCanonicalHex: row.relayReceiptCanonicalHex
})), protocolVector.cells.map(cell => ({
  version: 1,
  logicalHash: cell.logicalHash,
  encodingCommitment: cell.encodingCommitment,
  relayPublicKey: cell.relayPublicKey,
  readCapabilityCanonicalHex: cell.readCapabilityCanonicalHex,
  cellBlobHash: cell.cellBlobHash,
  sizeClass: cell.sizeClass,
  allocationEpoch: cell.allocationEpoch,
  leaseEpoch: cell.leaseEpoch,
  createPublicKey: cell.createPublicKey,
  renewPublicKey: cell.renewPublicKey,
  dropPublicKey: cell.dropPublicKey,
  allocationCommitment: cell.allocationCommitment,
  relayReceiptCanonicalHex: cell.relayReceiptCanonicalHex
})), 'the offline signing request alone reconstructs the exact valid vector AuthorBind replicas')
assert.deepEqual({
  authorSequence: validatedVectorSigningRequest.authorSequence,
  previousAuthorRecordId: validatedVectorSigningRequest.previousAuthorRecordId,
  authorPublicKey: validatedVectorSigningRequest.authorPublicKey,
  publishedLeaseEpoch: validatedVectorSigningRequest.publishedLeaseEpoch,
  publisherPublicKey: validatedVectorSigningRequest.publisherPublicKey
}, {
  authorSequence: protocolVector.authorBind.authorSequence,
  previousAuthorRecordId: protocolVector.authorBind.previousAuthorRecordId,
  authorPublicKey: protocolVector.authorBind.authorPublicKey,
  publishedLeaseEpoch: protocolVector.announcement.publishedLeaseEpoch,
  publisherPublicKey: protocolVector.announcement.publisherPublicKey
}, 'the request alone carries the exact AuthorBind and announcement signing identities')

for (const [field, mutate] of [
  ['encodingCommitment', value => { value.initialReplicas[0].encodingCommitment = '00'.repeat(32) }],
  ['innerBytes', value => { value.innerBytesCanonicalHex = `00${value.innerBytesCanonicalHex.slice(2)}` }],
  ['version', value => { value.initialReplicas[0].version = 2 }],
  ['logicalHash', value => { value.initialReplicas[0].logicalHash = '00'.repeat(32) }],
  ['clientNonce', value => { value.initialReplicas[0].putClientNonce = '00'.repeat(32) }],
  ['requestNonce', value => {
    const request = Buffer.from(value.initialReplicas[0].putRequestCanonicalHex, 'hex')
    request[39] ^= 1
    value.initialReplicas[0].putRequestCanonicalHex = request.toString('hex')
  }],
  ['requestCommitment', value => { value.initialReplicas[0].putRequestCommitment = '00'.repeat(32) }],
  ['receipt', value => {
    value.initialReplicas[0].relayReceiptCanonicalHex =
      value.initialReplicas[1].relayReceiptCanonicalHex
  }],
  ['resultReceipt', value => {
    value.initialReplicas[0].putResultCanonicalHex = value.initialReplicas[1].putResultCanonicalHex
  }],
  ['sameRelayRecoveryRow', value => {
    value.initialReplicas[0] = structuredClone(value.initialReplicas[1])
  }]
]) {
  const tampered = structuredClone(vectorSigningRequest)
  mutate(tampered)
  assert.throws(() => validatePeeritSeq29PublicationSigningRequestV1(tampered),
    error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_SIGNING_REQUEST_INVALID' ||
      error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_INVALID' ||
      error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_JOURNAL_INVALID',
    `offline signing request rejects ${field} substitution`)
}

function vectorPutReadback (readCap) {
  return {
    readCap,
    authorBind: {
      innerCodec: vectorPublication.innerCodec,
      innerLength: BigInt(vectorPublication.innerLength),
      logicalHash: vectorPublication.logicalHash
    },
    replica: {
      relayPublicKey: readCap.relayPublicKey,
      sizeClass: vectorPublication.sizeClass,
      logicalHash: vectorPublication.logicalHash,
      encodingCommitment: vectorPublication.encodingCommitment
    },
    operationBatch: {
      innerCodec: vectorPublication.innerCodec,
      innerLength: BigInt(vectorPublication.innerLength),
      sizeClass: vectorPublication.sizeClass,
      innerBytes: vectorPublication.innerBytes,
      logicalHash: vectorPublication.logicalHash,
      encodingCommitment: vectorPublication.encodingCommitment
    }
  }
}

const vectorPutRequest = Object.freeze({
  version: 1,
  sizeClass: vectorReadCaps[0].sizeClass,
  storageSlot: vectorReadCaps[0].storageSlot,
  declaredBlobHash: vectorReadCaps[0].expectedCellBlobHash
})
assert.equal(
  validatePeeritSeq29PreparedPutReadbackBindingV1({
    request: vectorPutRequest,
    readCap: vectorReadCaps[0],
    publication: vectorPublication,
    announcementBytes: vectorAnnouncementBytes,
    verifiedAnnouncementBytes: vectorAnnouncementBytes.slice(),
    readback: vectorPutReadback(vectorReadCaps[0])
  }).logicalHash,
  protocolVector.inner.logicalHash)
assert.throws(
  () => validatePeeritSeq29PreparedPutReadbackBindingV1({
    request: vectorPutRequest,
    readCap: vectorReadCaps[0],
    publication: vectorPublication,
    announcementBytes: vectorAnnouncementBytes,
    verifiedAnnouncementBytes: vectorAnnouncementBytes.slice(),
    readback: vectorPutReadback(vectorReadCaps[1])
  }),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_READBACK_INVALID',
  'an unrelated PUT and preexisting same-logical-hash announcement cannot satisfy readback')

function exactPrepared (row, family, operation, marker, options = {}) {
  const expected = family === 'CELL'
    ? { familyId: 2, operationId: 1 }
    : { familyId: 3, operationId: 4 }
  const requestBytes = new Uint8Array([
    options.wireFamilyId ?? expected.familyId,
    options.wireOperationId ?? expected.operationId,
    marker
  ])
  const requestCommitment = createHash('sha256').update(requestBytes).digest('hex')
  return Object.freeze({
    relayId: row.relayId,
    relayPublicKey: row.relayPublicKey,
    storeId: row.storeId,
    durabilityContinuityHash: row.durabilityContinuityHash,
    physicalTopic: row.physicalTopic,
    family,
    operation,
    requestBytes,
    requestCommitment,
    evidenceRef: `prepared:${family}.${operation}:${row.relayId}`
  })
}

function drillControl (options = {}) {
  const calls = []
  let marker = 0
  return {
    calls,
    control: {
      async prepareCellPut (row) {
        calls.push(`prepare-put:${row.relayId}`)
        marker++
        return exactPrepared(row, 'CELL', 'PUT', marker, options.wrongWireAt === marker
          ? { wireFamilyId: 3, wireOperationId: 4 }
          : {})
      },
      async verifyCellPutReadback ({ row }) {
        calls.push(`verify-put:${row.relayId}`)
        return {
          relayId: row.relayId,
          cellGetVerified: true,
          authorBindVerified: true,
          announcementBytes: new Uint8Array([row.relayId.endsWith('a') ? 1 : 2]),
          evidenceRef: `put-readback:${row.relayId}`
        }
      },
      async prepareInboxAppend ({ row }) {
        calls.push(`prepare-append:${row.relayId}`)
        marker++
        return exactPrepared(row, 'INBOX', 'APPEND', marker, options.wrongWireAt === marker
          ? { wireFamilyId: 2, wireOperationId: 1 }
          : {})
      },
      async verifyInboxAppend ({ row }) {
        calls.push(`verify-append:${row.relayId}`)
        return { relayId: row.relayId, acknowledged: true, evidenceRef: `append:${row.relayId}` }
      },
      async freshReadCellGet ({ row }) {
        calls.push(`fresh:${row.relayId}`)
        return {
          relayId: row.relayId,
          inboxReadVerified: true,
          cellGetVerified: true,
          announcementMatched: true,
          evidenceRef: `fresh:${row.relayId}`
        }
      },
      async decodeWireRequest (requestBytes) {
        return {
          familyId: requestBytes[0],
          operationId: requestBytes[1],
          requestCommitment: createHash('sha256').update(requestBytes).digest('hex'),
          relayPublicKey: options.wrongDecodedRelay || fixture.payload.relays
            .find(relay => relay.relayId.endsWith(requestBytes[2] % 2 === 1 ? 'a' : 'b')).relayPublicKey,
          physicalTopic: fixtureSet.bindings
            .find(binding => binding.relayId.endsWith(requestBytes[2] % 2 === 1 ? 'a' : 'b')).physicalTopic
        }
      },
      async verifyWriteResult ({ row, prepared, response }) {
        return {
          relayId: row.relayId,
          relayPublicKey: row.relayPublicKey,
          storeId: row.storeId,
          durabilityContinuityHash: row.durabilityContinuityHash,
          physicalTopic: row.physicalTopic,
          familyId: prepared.family === 'CELL' ? 2 : 3,
          operationId: prepared.operation === 'PUT' ? 1 : 4,
          requestCommitment: prepared.requestCommitment,
          resultSha256: createHash('sha256').update(response.body).digest('hex'),
          evidenceRef: `result:${prepared.family}.${prepared.operation}:${row.relayId}`
        }
      }
    }
  }
}

function publicationAuthority (overrides = {}) {
  const harness = overrides.harness || drillControl()
  const wrapper = overrides.wrapper || fixture
  return {
    harness,
    authority: createPeeritSeq29BoundedPublicationFixtureAuthorityV1({
      allowFixture: true,
      hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
      signedBootstrap: wrapper,
      signedBootstrapHash: objectDigest(wrapper),
      control: harness.control,
      send: overrides.send || (async value => ({
        ok: true,
        body: new Uint8Array([value.requestBytes[2], 0xa5])
      }))
    })
  }
}

function drillExecution (overrides = {}) {
  const journal = overrides.journal || durableJournal()
  const dispatches = []
  const send = async value => {
    dispatches.push(value.operationKey)
    if (value.operationKey === overrides.ambiguousOperation) {
      throw Object.assign(new Error('connection lost after write'), { code: 'AMBIGUOUS' })
    }
    return { ok: true, body: new Uint8Array([value.requestBytes[2], 0xa5]) }
  }
  const authorityHarness = overrides.authorityHarness || publicationAuthority({
    ...overrides,
    send
  })
  return {
    journal,
    dispatches,
    authorityHarness,
    input: {
      authority: authorityHarness.authority,
      attemptJournal: journal
    }
  }
}

const drill = drillExecution()
await assert.rejects(
  preparePeeritSeq29BoundedPublicationV1({
    control: drill.authorityHarness.harness.control,
    send () {}
  }),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
  'production phase one rejects raw control/send injection')
await assert.rejects(
  createPeeritSeq29BoundedPublicationAuthorityV1({
    control: drill.authorityHarness.harness.control,
    send () {}
  }),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
  'production drill factory rejects raw control/send injection')
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1({
    ...drill.input,
    send () {}
  }),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_INVALID')
assert.equal(drill.dispatches.length, 0,
  'raw send callback fails before the durable attempt and transport')
const drillReport = await runPeeritSeq29BoundedPublicationDrillV1(drill.input)
assert.deepEqual(drill.dispatches, [
  'CELL.PUT:fixture-relay-a',
  'CELL.PUT:fixture-relay-b',
  'INBOX.APPEND:fixture-relay-a',
  'INBOX.APPEND:fixture-relay-b'
])
assert.deepEqual(drillReport.mutationLedger, {
  cellPut: 2,
  inboxAppend: 2,
  inboxCreate: 0,
  inboxRenew: 0,
  inboxClose: 0,
  other: 0
})

await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1(drill.input),
  error => error.code === 'PEERIT_TEST_ATTEMPT_REUSED')
assert.equal(drill.dispatches.length, 4,
  'fixed release attempt cannot be reopened')
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1({
    ...drill.input,
    attemptToken: 'caller-token-two'
  }),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_INVALID')
assert.equal(drill.dispatches.length, 4,
  'caller-chosen token freshness is outside the closed runner contract')

const ambiguousOperation = 'INBOX.APPEND:fixture-relay-b'
const ambiguousDrill = drillExecution({ ambiguousOperation })
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1(ambiguousDrill.input),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_ABORTED' &&
    error.details.causeCode === 'PEERIT_SEQ29_PUBLICATION_DRILL_TRANSPORT_AMBIGUOUS')
assert.equal(ambiguousDrill.dispatches.length, 4)
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1(ambiguousDrill.input),
  error => error.code === 'PEERIT_TEST_ATTEMPT_REUSED')
assert.equal(ambiguousDrill.dispatches.length, 4,
  'ambiguous APPEND is terminal and cannot exceed 2 PUT + 2 APPEND')

const wrongWire = drillExecution({ harness: drillControl({ wrongWireAt: 1 }) })
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1(wrongWire.input),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_ABORTED' &&
    error.details.causeCode === 'PEERIT_SEQ29_PUBLICATION_DRILL_WIRE_INVALID')
assert.equal(wrongWire.dispatches.length, 0,
  'mismatched family/op labels and wire bytes fail before the first send')

const wrongDrillClaim = drillExecution({
  journal: durableJournal({ wrongClaimAttempt: true })
})
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1(wrongDrillClaim.input),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_ABORTED' &&
    error.details.actualDispatches.length === 0)
assert.equal(wrongDrillClaim.dispatches.length, 0,
  'wrong attemptId in a claim receipt fails before send')

const wrongDrillOutcome = drillExecution({
  journal: durableJournal({ wrongOutcomeOperation: true })
})
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1(wrongDrillOutcome.input),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_ABORTED' &&
    error.details.actualDispatches.length === 1)
assert.equal(wrongDrillOutcome.dispatches.length, 1,
  'wrong operationKey in an outcome receipt cannot advance to another send')

const wrongDrillFinish = drillExecution({
  journal: durableJournal({ wrongFinishDigest: true })
})
await assert.rejects(
  runPeeritSeq29BoundedPublicationDrillV1(wrongDrillFinish.input),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_ABORTED' &&
    error.details.actualDispatches.length === 4)
assert.equal(wrongDrillFinish.dispatches.length, 4,
  'wrong finish digest cannot fabricate PASS or trigger a retry')

const extraHook = drillControl()
extraHook.control.createCloseInboxRequest = () => {
  throw new Error('must never be reachable')
}
assert.throws(
  () => publicationAuthority({ harness: extraHook }),
  error => error.code === 'PEERIT_SEQ29_PUBLICATION_DRILL_INVALID',
  'extra lifecycle/transport hooks are rejected by the exact authority surface')

const duplicateIdentityWrapper = structuredClone(fixture)
duplicateIdentityWrapper.payload.relays[1] = structuredClone(duplicateIdentityWrapper.payload.relays[0])
duplicateIdentityWrapper.payload.inboxEpochSets[0].bindings[1] =
  structuredClone(duplicateIdentityWrapper.payload.inboxEpochSets[0].bindings[0])
assert.throws(
  () => publicationAuthority({ wrapper: duplicateIdentityWrapper }),
  error => error.code === 'PEERIT_LIMITED_INBOX_SIGNING_PACKAGE_INVALID' ||
    error.code === 'PEERIT_LIMITED_INBOX_SIGNER_SELF_VERIFY_FAILED')

console.log('peerit seq29 adversarial signer + custody-first ceremony + metered drill: ok')
