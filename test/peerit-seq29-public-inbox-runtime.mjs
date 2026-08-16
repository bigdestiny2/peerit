import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import { genKeyPair, ready as cryptoReady, signBytes } from '../js/crypto.js'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import {
  buildPeeritSubstrateRuntimeArtifactV1,
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH,
  verifyPeeritSubstrateRuntimeArtifactV1
} from '../scripts/substrate-runtime-artifact.mjs'
import * as control from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'
import {
  canonicalPeeritLimitedPublicInboxJsonV1,
  assertPeeritSeq29PublicBrowserControlV1,
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1,
  verifyPeeritLimitedPublicInboxBootstrapV1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  derivePeeritInboxAnnouncementFrameKeyV1,
  openPeeritInboxAnnouncementFrameV1,
  peeritInboxAnnouncementFrameAadV1
} from '../js/substrate/inbox-pointer-frame-v1.mjs'
import {
  pollPeeritPublicInboxBindingV1,
  verifyPeeritPublicInboxAnnouncementReadbackV1
} from '../js/substrate/inbox-discovery.mjs'
import {
  ingestPeeritSeq29PublicInboxPollResultsV1,
  settlePeeritSeq29DualAppendV1,
  verifyPeeritSeq29CellPutReadbackEvidenceV1
} from '../js/substrate/public-inbox-boot-coordinator.mjs'
import {
  preparePeeritPublicInboxAnnouncementV1,
  publishPeeritPublicInboxAnnouncementV1
} from '../js/substrate/inbox-pointer-publish.mjs'
import { decodePeeritProfileRegistry } from '../js/substrate/profile-artifact-codec.mjs'
import {
  asciiBytes,
  blake2b256,
  concatBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import { createPeeritSubstrateSync } from '../js/substrate/peerit-substrate-sync.js'
import {
  acceptPeeritSeq29PublicInboxBootstrapV1,
  commitPeeritSeq29PublicInboxPollV1,
  createPeeritSeq29PublicInboxSyncAuthorityV1,
  getPeeritSeq29PublicInboxAppendFloorsV1
} from '../js/substrate/seq29-public-inbox-sync.mjs'
import * as validatorModule from '../protocol/validator/peerit-validator-v1.bare.mjs'

const FIXTURE_NOW = 1780000001000n
const fixture = JSON.parse(await fs.readFile(
  new URL('./fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json', import.meta.url)))
const vector = JSON.parse(await fs.readFile(
  new URL('./fixtures/peerit-seq29-limited-public-test-v1/positive-protocol-vector.json', import.meta.url)))
const fromHex = value => Uint8Array.from(Buffer.from(value, 'hex'))
const toHex = value => Buffer.from(value).toString('hex')
const clone = value => structuredClone(value)
const PROFILE1_DURABILITY_CONTINUITY_HASH =
  'b0d28be1ec93dc70931de0715994deb0295507ada3a26b64b61c261b9c3306eb'

async function until (predicate, timeoutMillis = 1500) {
  const deadline = Date.now() + timeoutMillis
  while (Date.now() < deadline) {
    if (await predicate()) return true
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  return false
}

await cryptoReady()

async function fixtureProfileValidator () {
  const registry = decodePeeritProfileRegistry(await fs.readFile(
    new URL('../protocol/peerit-profile-v1.cenc', import.meta.url)))
  const wire = {
    specBytes: new Uint8Array(await fs.readFile(new URL(
      '../protocol/external-authority/hiverelay-blind-wire-v1.md', import.meta.url))),
    abiBytes: new Uint8Array(await fs.readFile(new URL(
      '../protocol/external-authority/hiverelay-blind-abi-v1.cenc', import.meta.url))),
    vectorManifestBytes: new Uint8Array(await fs.readFile(new URL(
      '../protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc', import.meta.url)))
  }
  const client = {
    formatAuthorityBytes: new Uint8Array(await fs.readFile(new URL(
      '../protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc', import.meta.url))),
    vectorManifestBytes: new Uint8Array(await fs.readFile(new URL(
      '../protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc', import.meta.url)))
  }
  const externalAuthorities = Object.create(null)
  for (const row of registry.externalCodecImports) {
    externalAuthorities[row.name] =
      validatorModule.authenticatePeeritProfileExternalCodecAuthorityV1({
        name: row.name,
        authorityKind: row.authorityKind,
        authorityBinding: row.tupleBinding,
        artifacts: row.authorityKind === 'WIRE_TUPLE_V1' ? wire : client,
        assertCanonical (bytes, name) {
          control.decodeBlindExternalProfileValueV1(name, bytes)
        }
      })
  }
  return validatorModule.createPeeritValidatorV1({ externalAuthorities })
}

assert.equal('createInboxReplica' in control, false)
assert.equal('createWatchInboxRequest' in control, false)
assert.equal(assertPeeritSeq29PublicBrowserControlV1(control), control)
assert.throws(
  () => assertPeeritSeq29PublicBrowserControlV1({ ...control, createInboxReplica () {} }),
  error => error.code === 'PEERIT_LIMITED_INBOX_BROWSER_CREATE_FORBIDDEN')

await assert.rejects(
  verifyPeeritLimitedPublicInboxBootstrapV1({ wrapper: fixture, control, referenceUnixMillis: FIXTURE_NOW }),
  error => error.code === 'PEERIT_LIMITED_INBOX_BOOTSTRAP_FIXTURE_FORBIDDEN')

const authority = await verifyPeeritLimitedPublicInboxBootstrapV1({
  wrapper: fixture,
  control,
  referenceUnixMillis: FIXTURE_NOW,
  allowFixture: true
})
assert.equal(authority.artifactClass, 'FIXTURE_ONLY')
assert.equal(authority.bootstrapSequence, 0n)
assert.equal(authority.bindings.length, 2)
assert.deepEqual(
  fixture.payload.relays.map(relay => relay.durabilityContinuityHash),
  [PROFILE1_DURABILITY_CONTINUITY_HASH, PROFILE1_DURABILITY_CONTINUITY_HASH],
  'profile-1 canonical continuity may repeat while relay identity/store/topic bindings remain distinct')
for (const values of [
  fixture.payload.relays.map(relay => relay.relayId),
  fixture.payload.relays.map(relay => relay.relayPublicKey),
  fixture.payload.relays.map(relay => relay.storeId),
  fixture.payload.inboxEpochSets[0].bindings.map(binding => binding.physicalTopic)
]) {
  assert.equal(new Set(values).size, 2,
    'relay IDs, keys, stores, and physical topics remain pairwise distinct')
}
const immutableRouteBinding = authority.bindings[0]
const routeSnapshot = Object.freeze({
  relayPublicKey: toHex(immutableRouteBinding.relayPublicKey),
  physicalTopic: toHex(immutableRouteBinding.physicalTopic),
  storeId: toHex(immutableRouteBinding.storeId),
  durabilityContinuityHash: toHex(immutableRouteBinding.durabilityContinuityHash),
  descriptorFloorHash: toHex(immutableRouteBinding.descriptorFloorHash),
  createPublicKey: toHex(immutableRouteBinding.createPublicKey),
  capRelayPublicKey: toHex(immutableRouteBinding.readCap.relayPublicKey),
  capPhysicalTopic: toHex(immutableRouteBinding.readCap.physicalTopic)
})
for (const bytes of [
  immutableRouteBinding.relayPublicKey,
  immutableRouteBinding.physicalTopic,
  immutableRouteBinding.storeId,
  immutableRouteBinding.durabilityContinuityHash,
  immutableRouteBinding.descriptorFloorHash,
  immutableRouteBinding.createPublicKey,
  immutableRouteBinding.readCap.relayPublicKey,
  immutableRouteBinding.readCap.physicalTopic
]) bytes.fill(0xff)
assert.deepEqual({
  relayPublicKey: toHex(immutableRouteBinding.relayPublicKey),
  physicalTopic: toHex(immutableRouteBinding.physicalTopic),
  storeId: toHex(immutableRouteBinding.storeId),
  durabilityContinuityHash: toHex(immutableRouteBinding.durabilityContinuityHash),
  descriptorFloorHash: toHex(immutableRouteBinding.descriptorFloorHash),
  createPublicKey: toHex(immutableRouteBinding.createPublicKey),
  capRelayPublicKey: toHex(immutableRouteBinding.readCap.relayPublicKey),
  capPhysicalTopic: toHex(immutableRouteBinding.readCap.physicalTopic)
}, routeSnapshot,
'mutating every exposed verified route/capability byte copy cannot change branded bootstrap routing')
const privateLeak = clone(fixture)
privateLeak.payload.inboxEpochSets[0].bindings[0].createPrivateSeed = '00'.repeat(32)
await assert.rejects(
  verifyPeeritLimitedPublicInboxBootstrapV1({
    wrapper: privateLeak, control, referenceUnixMillis: FIXTURE_NOW, allowFixture: true
  }),
  error => error.code === 'PEERIT_LIMITED_INBOX_PRIVATE_MANAGEMENT_MATERIAL')

const badSignature = clone(fixture)
badSignature.signature = `${badSignature.signature.slice(0, -2)}${badSignature.signature.endsWith('00') ? '01' : '00'}`
await assert.rejects(
  verifyPeeritLimitedPublicInboxBootstrapV1({
    wrapper: badSignature, control, referenceUnixMillis: FIXTURE_NOW, allowFixture: true
  }),
  error => error.code === 'PEERIT_LIMITED_INBOX_BOOTSTRAP_SIGNATURE_INVALID')

const firstVector = vector.frames[0]
const firstBinding = authority.bindings.find(binding => binding.relayId === firstVector.relayId)
const secondBinding = authority.bindings.find(binding => binding.relayId !== firstVector.relayId)
assert.ok(firstBinding)
assert.ok(secondBinding)
assert.equal(
  toHex(await derivePeeritInboxAnnouncementFrameKeyV1({ authority, binding: firstBinding })),
  firstVector.frameKey)
assert.equal(
  toHex(peeritInboxAnnouncementFrameAadV1({ authority, binding: firstBinding })),
  firstVector.aadHex)

const frame = fromHex(firstVector.frameCanonicalHex)
const announcement = await openPeeritInboxAnnouncementFrameV1({
  authority,
  binding: firstBinding,
  frame
})
assert.equal(toHex(announcement), vector.announcement.canonicalHex)

const tampered = frame.slice()
tampered[tampered.length - 1] ^= 1
await assert.rejects(
  openPeeritInboxAnnouncementFrameV1({ authority, binding: firstBinding, frame: tampered }),
  error => error.code === 'PEERIT_INBOX_ANNOUNCEMENT_FRAME_INVALID')
await assert.rejects(
  openPeeritInboxAnnouncementFrameV1({ authority, binding: secondBinding, frame }),
  error => error.code === 'PEERIT_INBOX_ANNOUNCEMENT_FRAME_INVALID')

const profileValidator = await fixtureProfileValidator()
const relayPages = vector.readPages.filter(page => page.relayId === firstBinding.relayId)
const inner = fromHex(vector.inner.canonicalHex)

function discoveryControl (openedInner = inner, pages = relayPages, cell = vector.cells[0]) {
  let readIndex = 0
  return {
    BlindDirectHttpClient: class {},
    createReadInboxRequest: async ({ cursor }) => ({
      request: { kind: 'read', cursor },
      requestBytes: new Uint8Array([readIndex]),
      requestCommitment: new Uint8Array(32),
      wire: { familyId: 3, operationId: 3, expectedResultBodyBytes: 70000 }
    }),
    createGetCellRequest: async ({ readCap }) => ({
      request: { kind: 'get' },
      requestBytes: new Uint8Array([3]),
      requestCommitment: new Uint8Array(32),
      readCap,
      wire: { familyId: 2, operationId: 2, expectedResultBodyBytes: 4098 }
    }),
    async verifyOperationResult ({ request }) {
      if (request.kind === 'read') {
        const page = pages[readIndex++]
        return { snapshotBytes: () => fromHex(page.resultCanonicalHex) }
      }
      if (request.kind === 'put') {
        return { snapshotBytes: () => fromHex(cell.relayReceiptCanonicalHex) }
      }
      return { snapshotBytes: () => fromHex(cell.capabilityBoundGet.getResultCanonicalHex) }
    },
    async openVerifiedCellGetResult () { return openedInner.slice() },
    decodeBlindExternalProfileValueV1: control.decodeBlindExternalProfileValueV1
  }
}

const httpClient = { async request () { return { ok: true, body: new Uint8Array([1]) } } }
const discovered = await pollPeeritPublicInboxBindingV1({
  authority,
  binding: firstBinding,
  control: discoveryControl(),
  runtime: {},
  readEndpoint: {},
  cellEndpoint: {},
  httpClient,
  profileValidator,
  nowUnixMillis: FIXTURE_NOW
})
assert.equal(discovered.records.length, 1, discovered.rejections.map(value => value.rejection).join(','))
assert.equal(discovered.rejections.length, 0)
assert.equal(discovered.records[0].operationBatch.innerCodec, 334)
assert.equal(discovered.records[0].operationBatch.operations.length > 0, true)
assert.equal(toHex(discovered.records[0].authorPublicKey), vector.inner.oneAuthorPublicKey)

const secondRelayPages = vector.readPages.filter(page => page.relayId === secondBinding.relayId)
const discoveredSecond = await pollPeeritPublicInboxBindingV1({
  authority,
  binding: secondBinding,
  control: discoveryControl(inner, secondRelayPages),
  runtime: {},
  readEndpoint: {},
  cellEndpoint: {},
  httpClient,
  profileValidator,
  nowUnixMillis: FIXTURE_NOW
})
assert.equal(discoveredSecond.records.length, 1)
const inboxJournalState = createMemoryJournalState()
const inboxSync = createPeeritSubstrateSync({
  journal: createMemoryPeeritJournal({ shared: inboxJournalState }),
  relays: [],
  autoFlush: false,
  channelName: 'peerit-seq29-runtime-ingest'
})
await inboxSync.ready()
assert.equal(typeof inboxSync.acceptSeq29PublicInboxBootstrap, 'undefined',
  'the generic sync core exposes no unbranded Seq29 bootstrap mutation API')
assert.equal(typeof inboxSync.commitAuthenticatedSeq29PublicInboxPoll, 'undefined',
  'the generic sync core exposes no shape-only prepared Seq29 ingest API')
assert.throws(
  () => createPeeritSeq29PublicInboxSyncAuthorityV1({
    authority: { ...authority },
    substrateSync: inboxSync
  }),
  error => error.code === 'PEERIT_SUBSTRATE_SEQ29_COORDINATOR_AUTHORITY_REQUIRED',
  'a shape-copy of the signed bootstrap authority cannot mint sync authority')
const inboxSyncAuthority = createPeeritSeq29PublicInboxSyncAuthorityV1({
  authority,
  substrateSync: inboxSync
})
await assert.rejects(
  commitPeeritSeq29PublicInboxPollV1({ ...inboxSyncAuthority }, [discovered, discoveredSecond]),
  error => error.code === 'PEERIT_SUBSTRATE_SEQ29_COORDINATOR_AUTHORITY_REQUIRED',
  'a shape-copy of the opaque coordinator sync authority cannot ingest records')
await acceptPeeritSeq29PublicInboxBootstrapV1(
  inboxSyncAuthority, { observedAt: Number(FIXTURE_NOW) })
const dualIngest = await ingestPeeritSeq29PublicInboxPollResultsV1(
  authority, [discovered, discoveredSecond], inboxSync)
assert.equal(dualIngest.ingestedBatchCount, 1,
  'the same intrinsic batch discovered on both relays is ingested once')
assert.equal(dualIngest.pendingIntentsCreated, 0)
assert.equal(dualIngest.relayTargetsCreated, 0)
assert.equal((await inboxSync.status()).publication.relay.pendingIntents, 0,
  'public INBOX ingest creates no authored intent or outbound relay target')
for (let index = 0; index < discovered.records[0].operationBatch.operations.length; index++) {
  assert.deepEqual(
    await inboxSync.get(discovered.records[0].operationBatch.operationWireKeys[index]),
    discovered.records[0].operationBatch.operations[index].data,
    'intrinsically re-decoded public INBOX row enters only the remote materialized view')
}
await assert.rejects(
  ingestPeeritSeq29PublicInboxPollResultsV1(authority, [
    { ...discovered }, discoveredSecond
  ], inboxSync),
  error => error.code === 'PEERIT_SEQ29_PUBLIC_INBOX_POLL_AUTHORITY_REQUIRED',
  'shape-copied poll results cannot reach the intrinsic ingest boundary')

const announcementBytes = fromHex(vector.announcement.canonicalHex)
const publicationRows = []
for (const binding of authority.bindings) {
  const cell = vector.cells.find(value => value.relayPublicKey === toHex(binding.relayPublicKey))
  assert.ok(cell)
  const boundControl = discoveryControl(inner, [], cell)
  const readback = await verifyPeeritPublicInboxAnnouncementReadbackV1({
    authority,
    binding,
    control: boundControl,
    runtime: {},
    cellEndpoint: {},
    announcementBytes,
    httpClient,
    profileValidator,
    nowUnixMillis: FIXTURE_NOW
  })
  const readCap = control.decodeBlindExternalProfileValueV1(
    'ReadCellCapV1', fromHex(cell.readCapabilityCanonicalHex))
  const putEvidence = {
    request: {
      kind: 'put',
      version: 1,
      sizeClass: readCap.sizeClass,
      storageSlot: readCap.storageSlot,
      declaredBlobHash: readCap.expectedCellBlobHash
    },
    requestCommitment: fromHex(cell.capabilityBoundPut.requestCommitment),
    resultBytes: new Uint8Array([0x70])
  }
  const verifiedPut = await verifyPeeritSeq29CellPutReadbackEvidenceV1({
    authority,
    binding,
    control: boundControl,
    putEndpoint: {},
    evidence: putEvidence,
    readback
  })
  assert.equal(verifiedPut.receipt.result, 1)
  publicationRows.push({ binding, readback, verifiedPut })
}
assert.equal(publicationRows.length, 2,
  'both independent CELL.PUT results and same-relay AuthorBind GET readbacks verify')
await assert.rejects(
  verifyPeeritSeq29CellPutReadbackEvidenceV1({
    authority,
    binding: publicationRows[1].binding,
    control: discoveryControl(inner, [], vector.cells[1]),
    putEndpoint: {},
    evidence: {},
    readback: publicationRows[0].readback
  }),
  error => error.code === 'PEERIT_PUBLIC_INBOX_READBACK_AUTHORITY_REQUIRED',
  'a readback cannot be transplanted across a binding or control authority')

const u32 = value => Uint8Array.of(
  (value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255)
const u64 = value => {
  const output = new Uint8Array(8)
  let rest = BigInt(value)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(rest & 255n)
    rest >>= 8n
  }
  return output
}
function appendAck (binding, request, requestCommitment, appendRevision) {
  return concatBytes(
    Uint8Array.of(1, 1),
    binding.relayPublicKey,
    binding.storeId,
    u64(binding.descriptorFloorSequence),
    binding.descriptorFloorHash,
    Uint8Array.of(1),
    binding.durabilityContinuityHash,
    new Uint8Array(32).fill(0x31),
    u64(0),
    new Uint8Array(32),
    Uint8Array.of(0),
    new Uint8Array(32).fill(0x32),
    request.frameHash,
    u64(appendRevision),
    u32(10),
    u32(11),
    new Uint8Array(32).fill(0x33),
    requestCommitment,
    Uint8Array.of(1),
    new Uint8Array(64).fill(0x34)
  )
}
const appendEndpointByRelay = new Map(authority.bindings.map(binding =>
  [binding.relayId, Object.freeze({ relayId: binding.relayId })]))
const appendControl = {
  async createAppendInboxRequest ({ readCap, frame }) {
    const binding = authority.bindings.find(value =>
      toHex(value.relayPublicKey) === toHex(readCap.relayPublicKey))
    const requestCommitment = new Uint8Array(32).fill(
      binding === authority.bindings[0] ? 0x41 : 0x42)
    return {
      request: { kind: 'append', binding, frameHash: blake2b256(frame) },
      requestBytes: new Uint8Array([0x61]),
      requestCommitment,
      wire: { familyId: 3, operationId: 4, expectedResultBodyBytes: 512 }
    }
  },
  async verifyOperationResult ({ endpoint, request, requestCommitment }) {
    assert.equal(endpoint, appendEndpointByRelay.get(request.binding.relayId))
    return {
      snapshotBytes: () => appendAck(
        request.binding,
        request,
        requestCommitment,
        request.binding === authority.bindings[0] ? 8n : 9n)
    }
  }
}
const preparedAppends = await Promise.all(authority.bindings.map(binding =>
  preparePeeritPublicInboxAnnouncementV1({
    authority,
    binding,
    control: appendControl,
    runtime: {},
    announcementBytes
  })))
assert.notEqual(toHex(preparedAppends[0].frame), toHex(preparedAppends[1].frame),
  'the two encrypted APPEND frames are independently randomized')
const dualAppend = await settlePeeritSeq29DualAppendV1(preparedAppends.map(prepared =>
  publishPeeritPublicInboxAnnouncementV1({
    prepared,
    control: appendControl,
    endpoint: appendEndpointByRelay.get(prepared.binding.relayId),
    runtime: {},
    httpClient,
    timeoutMillis: 1000
  })))
assert.deepEqual(dualAppend.map(value => value.appendRevision), [8n, 9n])

const rejectedClient = {
  async request ({ endpoint }) {
    if (endpoint === appendEndpointByRelay.get(authority.bindings[1].relayId)) {
      return { ok: false, error: { code: 6, retryable: 0 } }
    }
    return { ok: true, body: new Uint8Array([1]) }
  }
}
const retryPrepared = await Promise.all(authority.bindings.map(binding =>
  preparePeeritPublicInboxAnnouncementV1({
    authority,
    binding,
    control: appendControl,
    runtime: {},
    announcementBytes
  })))
await assert.rejects(
  settlePeeritSeq29DualAppendV1(retryPrepared.map(prepared =>
    publishPeeritPublicInboxAnnouncementV1({
      prepared,
      control: appendControl,
      endpoint: appendEndpointByRelay.get(prepared.binding.relayId),
      runtime: {},
      httpClient: rejectedClient
    }))),
  error => error.code === 'PEERIT_SEQ29_DUAL_APPEND_INCOMPLETE' &&
    error.details.filter(value => value.ok).length === 1,
  'one successful and one rejected APPEND remains an incomplete dual publication')

const noSameRelayCapValidator = {
  validate (name, bytes) {
    const validated = profileValidator.validate(name, bytes)
    if (name !== 'AuthorBindV1') return validated
    return {
      ...validated,
      value: Object.freeze({
        ...validated.value,
        initialReplicas: Object.freeze(validated.value.initialReplicas.filter(replica =>
          toHex(replica.relayPublicKey) !== toHex(firstBinding.relayPublicKey)))
      })
    }
  }
}
const noCap = await pollPeeritPublicInboxBindingV1({
  authority,
  binding: firstBinding,
  control: discoveryControl(),
  runtime: {},
  readEndpoint: {},
  cellEndpoint: {},
  httpClient,
  profileValidator: noSameRelayCapValidator,
  nowUnixMillis: FIXTURE_NOW
})
assert.equal(noCap.records.length, 0)
assert.equal(noCap.rejections[0].rejection, 'PEERIT_PUBLIC_INBOX_SAME_RELAY_CAP_REQUIRED')
const rejectedEntryState = createMemoryJournalState()
const rejectedEntrySync = createPeeritSubstrateSync({
  journal: createMemoryPeeritJournal({ shared: rejectedEntryState }),
  relays: [],
  autoFlush: false,
  channelName: 'peerit-seq29-authenticated-rejection-ingest'
})
await rejectedEntrySync.ready()
const rejectedEntrySyncAuthority = createPeeritSeq29PublicInboxSyncAuthorityV1({
  authority,
  substrateSync: rejectedEntrySync
})
await acceptPeeritSeq29PublicInboxBootstrapV1(rejectedEntrySyncAuthority)
const rejectedEntryIngest = await ingestPeeritSeq29PublicInboxPollResultsV1(
  authority, [noCap, discoveredSecond], rejectedEntrySync)
assert.equal(rejectedEntryIngest.appendFloors[firstBinding.relayId], noCap.newFloor,
  'a deterministic invalid entry inside an authenticated READ may advance its relay floor')

const floorsBeforeGetFailures = await getPeeritSeq29PublicInboxAppendFloorsV1(
  rejectedEntrySyncAuthority)
const validatorOutage = {
  validate () {
    const error = new Error('injected authenticated profile validator outage')
    error.code = 'PEERIT_PUBLIC_INBOX_ANNOUNCEMENT_INVALID'
    throw error
  }
}
await assert.rejects(
  pollPeeritPublicInboxBindingV1({
    authority,
    binding: firstBinding,
    control: discoveryControl(),
    runtime: {},
    readEndpoint: {},
    cellEndpoint: {},
    httpClient,
    profileValidator: validatorOutage,
    nowUnixMillis: FIXTURE_NOW
  }),
  error => error.code === 'PEERIT_PUBLIC_INBOX_PROFILE_VALIDATION_FAILED',
  'a local authenticated profile-validator outage aborts even if it spoofs a rejection code')
assert.deepEqual(
  await getPeeritSeq29PublicInboxAppendFloorsV1(rejectedEntrySyncAuthority),
  floorsBeforeGetFailures,
  'a profile-validator outage leaves both durable relay floors unchanged')
const resultAuthFailureControl = discoveryControl()
const verifyBeforeResultAuthFailure = resultAuthFailureControl.verifyOperationResult
resultAuthFailureControl.verifyOperationResult = async input => {
  if (input.request.kind === 'get') throw new Error('injected corrupt relay result')
  return verifyBeforeResultAuthFailure(input)
}
await assert.rejects(
  pollPeeritPublicInboxBindingV1({
    authority,
    binding: firstBinding,
    control: resultAuthFailureControl,
    runtime: {},
    readEndpoint: {},
    cellEndpoint: {},
    httpClient,
    profileValidator,
    nowUnixMillis: FIXTURE_NOW
  }),
  error => error.code === 'PEERIT_PUBLIC_INBOX_CELL_GET_RESULT_INVALID',
  'a corrupt or unauthenticated CELL.GET result aborts instead of advancing the entry floor')

const capabilityOpenFailureControl = discoveryControl()
capabilityOpenFailureControl.openVerifiedCellGetResult = async () => {
  throw new Error('injected local capability-opening corruption')
}
await assert.rejects(
  pollPeeritPublicInboxBindingV1({
    authority,
    binding: firstBinding,
    control: capabilityOpenFailureControl,
    runtime: {},
    readEndpoint: {},
    cellEndpoint: {},
    httpClient,
    profileValidator,
    nowUnixMillis: FIXTURE_NOW
  }),
  error => error.code === 'PEERIT_PUBLIC_INBOX_CELL_GET_OPEN_INVALID',
  'a capability-opening or local crypto failure aborts instead of advancing the entry floor')
assert.deepEqual(
  await getPeeritSeq29PublicInboxAppendFloorsV1(rejectedEntrySyncAuthority),
  floorsBeforeGetFailures,
  'result-auth and capability-open failures leave both durable relay floors unchanged')

await assert.rejects(
  pollPeeritPublicInboxBindingV1({
    authority,
    binding: firstBinding,
    control: discoveryControl(),
    runtime: {},
    readEndpoint: {},
    cellEndpoint: {},
    httpClient: {
      async request ({ body }) {
        return body[0] === 3
          ? { ok: false, error: { code: 'INJECTED_CELL_TRANSPORT_FAILURE' } }
          : { ok: true, body: new Uint8Array([1]) }
      }
    },
    profileValidator,
    nowUnixMillis: FIXTURE_NOW
  }),
  error => error.code === 'PEERIT_PUBLIC_INBOX_CELL_GET_REJECTED',
  'a CELL.GET transport failure aborts the poll instead of becoming a floor-advancing rejection')

const corruptInner = inner.slice()
corruptInner[corruptInner.length - 1] ^= 1
const intrinsic = await pollPeeritPublicInboxBindingV1({
  authority,
  binding: firstBinding,
  control: discoveryControl(corruptInner),
  runtime: {},
  readEndpoint: {},
  cellEndpoint: {},
  httpClient,
  profileValidator,
  nowUnixMillis: FIXTURE_NOW
})
assert.equal(intrinsic.records.length, 0)
assert.equal(intrinsic.rejections[0].rejection,
  'PEERIT_PUBLIC_INBOX_INTRINSIC_AUTHORITY_INVALID')

const remoteOnlyShared = createMemoryJournalState()
const remoteOnlyChannel = `peerit-seq29-remote-only-${Date.now()}`
let remoteOnlyRelaySends = 0
const remoteOnlyReader = createPeeritSubstrateSync({
  journal: createMemoryPeeritJournal({ shared: remoteOnlyShared }),
  relays: [{
    id: 'pre-existing-outbound-relay',
    async deliver () {
      remoteOnlyRelaySends++
      return { ok: true, acknowledged: true }
    }
  }],
  autoFlush: false,
  channelName: remoteOnlyChannel
})
const remoteOnlyMutator = createPeeritSubstrateSync({
  journal: createMemoryPeeritJournal({ shared: remoteOnlyShared }),
  relays: [],
  autoFlush: false,
  channelName: remoteOnlyChannel
})
await Promise.all([remoteOnlyReader.ready(), remoteOnlyMutator.ready()])
await remoteOnlyMutator.appendBatch(discovered.records[0].operationBatch.operations)
assert.equal(await until(() => remoteOnlyReader._summary.pendingIntentCount === 1), true,
  'the relay-capable tab observes one pre-existing outbound intent before remote-only mutations')
remoteOnlyReader.autoFlush = true
let remoteOnlyNotifications = 0
const stopRemoteOnlyNotifications = remoteOnlyReader.onChange(() => {
  remoteOnlyNotifications++
})
const remoteOnlyAuthority = createPeeritSeq29PublicInboxSyncAuthorityV1({
  authority,
  substrateSync: remoteOnlyMutator
})
await acceptPeeritSeq29PublicInboxBootstrapV1(remoteOnlyAuthority)
assert.equal(await until(() => remoteOnlyNotifications > 0), true,
  'the bootstrap-only cross-tab notification is observed')
await new Promise(resolve => setTimeout(resolve, 25))
assert.equal(remoteOnlyRelaySends, 0,
  'a bootstrap-only journal commit cannot flush a pre-existing outbound intent')
remoteOnlyNotifications = 0
await commitPeeritSeq29PublicInboxPollV1(
  remoteOnlyAuthority, [discovered, discoveredSecond])
assert.equal(await until(() => remoteOnlyNotifications > 0), true,
  'the remote-view/floor cross-tab notification is observed')
await new Promise(resolve => setTimeout(resolve, 25))
assert.equal(remoteOnlyRelaySends, 0,
  'a remote-view/floor journal commit cannot flush a pre-existing outbound intent')
stopRemoteOnlyNotifications()
remoteOnlyReader.destroy()
remoteOnlyMutator.destroy()

// Build/release closure: production composition accepts only an explicitly
// supplied, release-class signed bootstrap. The repository FIXTURE_ONLY vector
// remains useful as signed protocol input, but can never become a production
// fallback or enter release bytes unchanged.
const bootstrapSigner = await genKeyPair()
const releaseBootstrap = clone(fixture)
const releaseReferenceNow = BigInt(Date.now())
releaseBootstrap.payload.artifactClass = 'LIMITED_PUBLIC_TEST_RELEASE'
releaseBootstrap.payload.authorityPublicKey = bootstrapSigner.pubHex
releaseBootstrap.payload.issuedUnixMillis = String(releaseReferenceNow - 1000n)
releaseBootstrap.payload.expiresUnixMillis = String(
  releaseReferenceNow + (7n * 24n * 60n * 60n * 1000n))
releaseBootstrap.payload.inboxEpochSets[0].inboxEpoch = Math.floor(
  Number(releaseReferenceNow / 21600000n) / 28)
for (const binding of releaseBootstrap.payload.inboxEpochSets[0].bindings) {
  binding.inboxEpoch = releaseBootstrap.payload.inboxEpochSets[0].inboxEpoch
}
releaseBootstrap.signature = toHex(await signBytes(bootstrapSigner.seedHex, concatBytes(
  asciiBytes(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1),
  Uint8Array.of(0),
  canonicalPeeritLimitedPublicInboxJsonV1(releaseBootstrap.payload)
)))
await verifyPeeritLimitedPublicInboxBootstrapV1({
  wrapper: releaseBootstrap,
  control,
  referenceUnixMillis: releaseReferenceNow,
  expectedAuthorityPublicKey: bootstrapSigner.pubHex
})
const releaseBootstrapBytes = Buffer.from(JSON.stringify(releaseBootstrap, null, 2) + '\n')

const seedSigner = await genKeyPair()
const seedFixtureBytes = Buffer.from(await fs.readFile(
  new URL('../deploy/peerit-seed-bootstrap-v1-seq28.json', import.meta.url)))
const seedFixture = JSON.parse(seedFixtureBytes)
const releaseSeed = await createPeeritSeedBootstrapV1({
  ...seedFixture.payload,
  releaseSequence: 29,
  authorityPublicKey: seedSigner.pubHex
}, { seedHex: seedSigner.seedHex })
const releaseSeedBytes = Buffer.from(encodePeeritSeedBootstrapV1(releaseSeed))
const sourceRuntimeFiles = new Map(await Promise.all(SUBSTRATE_SITE_FILES.map(async path => [
  path,
  Buffer.from(await fs.readFile(new URL(`../${path}`, import.meta.url)))
])))
const releaseKey = 'a5'.repeat(32)
const baseBuild = {
  sourceFiles: sourceRuntimeFiles,
  substrateProfile: 'blind-v1',
  relayHints: [
    'https://relay-syd.p2phiverelay.xyz/api/blind/v1/describe',
    'https://relay-dal.p2phiverelay.xyz/api/blind/v1/describe'
  ],
  releaseSequence: 29,
  releaseKey,
  seedBootstrapBytes: releaseSeedBytes,
  seedDiscoveryAuthorityPublicKey: seedSigner.pubHex
}
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1(baseBuild),
  /public INBOX bootstrap/i,
  'sequence 29 fails closed when the release ceremony has not supplied a signed bootstrap')
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1({
  ...baseBuild,
  limitedPublicInboxBootstrapBytes: Buffer.from(JSON.stringify(fixture, null, 2) + '\n'),
  limitedPublicInboxBootstrapAuthorityPublicKey: fixture.payload.authorityPublicKey
}), /production-test class|limited public test release/i,
'the signed FIXTURE_ONLY vector cannot enter production closure bytes')

async function signedBootstrapMutation (mutate) {
  const value = clone(releaseBootstrap)
  mutate(value)
  value.signature = toHex(await signBytes(bootstrapSigner.seedHex, concatBytes(
    asciiBytes(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1),
    Uint8Array.of(0),
    canonicalPeeritLimitedPublicInboxJsonV1(value.payload)
  )))
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

const unknownSignedFieldBootstrap = await signedBootstrapMutation(value => {
  value.payload.signedButUnknown = true
})
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1({
  ...baseBuild,
  limitedPublicInboxBootstrapBytes: unknownSignedFieldBootstrap,
  limitedPublicInboxBootstrapAuthorityPublicKey: bootstrapSigner.pubHex
}), /fields are missing or unexpected/,
'a valid signature cannot authorize an unknown payload field')
const zeroRelayBootstrap = await signedBootstrapMutation(value => {
  value.payload.relays = []
})
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1({
  ...baseBuild,
  limitedPublicInboxBootstrapBytes: zeroRelayBootstrap,
  limitedPublicInboxBootstrapAuthorityPublicKey: bootstrapSigner.pubHex
}), /exactly two relays/,
'a valid signature cannot authorize a zero-relay bootstrap')
const privateMaterialBootstrap = clone(releaseBootstrap)
privateMaterialBootstrap.privateSeed = '00'.repeat(32)
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1({
  ...baseBuild,
  limitedPublicInboxBootstrapBytes:
    Buffer.from(JSON.stringify(privateMaterialBootstrap, null, 2) + '\n'),
  limitedPublicInboxBootstrapAuthorityPublicKey: bootstrapSigner.pubHex
}), /forbidden management material/,
'unsigned top-level private management material is rejected before signature acceptance')

const releaseArtifact = buildPeeritSubstrateRuntimeArtifactV1({
  ...baseBuild,
  limitedPublicInboxBootstrapBytes: releaseBootstrapBytes,
  limitedPublicInboxBootstrapAuthorityPublicKey: bootstrapSigner.pubHex
})
assert.deepEqual(
  releaseArtifact.files.get(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH),
  releaseBootstrapBytes)
assert.deepEqual(releaseArtifact.inboxBootstrap, {
  bytes: releaseBootstrapBytes,
  path: '/peerit-limited-public-inbox-bootstrap-v1.json',
  sha256: releaseArtifact.appArtifact.peeritLimitedPublicInboxBootstrapSha256,
  authorityPublicKey: bootstrapSigner.pubHex,
  releaseSequence: 29
})
const releaseVerified = verifyPeeritSubstrateRuntimeArtifactV1({
  files: releaseArtifact.files,
  releaseSequence: 29,
  releaseKey
})
assert.deepEqual(releaseVerified.inboxBootstrap, {
  path: '/peerit-limited-public-inbox-bootstrap-v1.json',
  sha256: releaseArtifact.inboxBootstrap.sha256,
  authorityPublicKey: bootstrapSigner.pubHex,
  releaseSequence: 29
})
const releaseIndex = releaseArtifact.files.get('index.html').toString('utf8')
assert.match(releaseIndex, /https:\/\/relay-dal\.p2phiverelay\.xyz:8443/)
assert.match(releaseIndex, /https:\/\/relay-syd\.p2phiverelay\.xyz:8443/)
const tamperedReleaseFiles = new Map(releaseArtifact.files)
const tamperedBootstrap = Buffer.from(releaseBootstrapBytes)
tamperedBootstrap[tamperedBootstrap.length - 3] ^= 1
tamperedReleaseFiles.set(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_PATH, tamperedBootstrap)
assert.throws(() => verifyPeeritSubstrateRuntimeArtifactV1({
  files: tamperedReleaseFiles,
  releaseSequence: 29,
  releaseKey
}), /public INBOX bootstrap|WEB_ASSET_DRIFT/,
'signed app/Web closure rejects any bootstrap byte tamper')
assert.throws(() => buildPeeritSubstrateRuntimeArtifactV1({
  sourceFiles: sourceRuntimeFiles,
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence: 28,
  releaseKey,
  seedBootstrapBytes: seedFixtureBytes,
  seedDiscoveryAuthorityPublicKey: seedFixture.payload.authorityPublicKey,
  limitedPublicInboxBootstrapBytes: releaseBootstrapBytes,
  limitedPublicInboxBootstrapAuthorityPublicKey: bootstrapSigner.pubHex
}), /requires releaseSequence 29/i,
'pre-sequence-29 closure cannot carry a public INBOX bootstrap')

console.log('peerit seq29 public INBOX runtime + signed build closure fixture: ok')
