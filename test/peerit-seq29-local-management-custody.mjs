import assert from 'node:assert/strict'
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  sign
} from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  createPeeritSeq29LocalManagementCustodyFixtureV1,
  createPeeritSeq29LocalManagementCustodyV1,
  inspectPeeritSeq29LocalManagementPreparedTransitionV1,
  PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1,
  peeritSeq29LocalManagementCustodyPathsV1,
  peeritSeq29LocalManagementCustodyTransactionIdV1,
  recoverPeeritSeq29LocalManagementPreparedTransitionV1,
  recoverPeeritSeq29LimitedManagementCustodyEnvelopeFixtureV1,
  recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1
} from '../scripts/lib/seq29-local-management-custody.mjs'
import {
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1,
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1,
  PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  createPeeritSeq29LimitedInboxCeremonyFixtureAuthorityV1,
  executePeeritLimitedInboxTopicCeremonyV1,
  finalizePeeritLimitedInboxTopicCeremonyV1,
  peeritLimitedInboxTopicCeremonyPlanHashV1
} from '../scripts/limited-inbox-topic-ceremony.mjs'
import {
  signPeeritLimitedPublicInboxBootstrapV1
} from '../scripts/sign-limited-public-inbox-bootstrap.mjs'
import {
  createPeeritSeq29FilesystemAttemptJournalV1
} from '../scripts/lib/seq29-live-ceremony-journal.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  concatBytes,
  u32Bytes,
  u64Bytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  decodeBlindExternalProfileValueV1
} from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'
import {
  canonicalPeeritLimitedPublicInboxJsonV1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  compilePeeritProfileCodecIr,
  createPeeritProfileCodecCatalogFromIr
} from '../js/substrate/profile-codec-ir.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import {
  authenticatePeeritProfileExternalCodecAuthorityV1
} from '../js/substrate/profile-external-authority.mjs'
import { xchacha20poly1305 } from '../js/vendor/noble-ciphers/chacha.js'

process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST = '1'
const fixture = JSON.parse(await fs.readFile(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json', import.meta.url)))
const protocolContract = JSON.parse(await fs.readFile(new URL(
  '../protocol/seq29-limited-public-test/limited-management-custody-v1.json', import.meta.url)))
const protocolVector = JSON.parse(await fs.readFile(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-protocol-vector.json', import.meta.url)))
const authoritativeCustodyVector = protocolVector.managementCustody
const fixtureSet = fixture.payload.inboxEpochSets[0]
const temporaryRoots = []

function sha256Hex (value) {
  return createHash('sha256').update(value).digest('hex')
}

function fromHex (value) {
  return new Uint8Array(Buffer.from(value, 'hex'))
}

function fixtureSeed (label) {
  const domain = 'peerit.seq29.fixture-only.generator.v1'
  const output = createHash('sha256').update(Buffer.concat([
    Buffer.from(domain, 'ascii'), Buffer.from([0]), Buffer.from(`ed25519:${label}`, 'utf8'),
    Buffer.from([0, 0, 0, 0])
  ])).digest()
  return new Uint8Array(output)
}

function privateKeyForSeed (seed) {
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed)
    ]),
    format: 'der',
    type: 'pkcs8'
  })
}

function publicForSeed (seed) {
  return new Uint8Array(createPublicKey(privateKeyForSeed(seed))
    .export({ format: 'der', type: 'spki' }).subarray(-32))
}

function x25519PublicForPrivate (seed) {
  const privateKey = x25519PrivateKey(seed)
  return new Uint8Array(createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' }).subarray(-32))
}

function x25519PrivateKey (seed) {
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(seed)
    ]),
    format: 'der',
    type: 'pkcs8'
  })
}

function x25519PublicKey (raw) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(raw)
    ]),
    format: 'der',
    type: 'spki'
  })
}

function receiptForBinding (binding) {
  return decodeBlindExternalProfileValueV1(
    'InboxReceiptV1', fromHex(binding.createReceiptCanonicalHex))
}

function u64 (value) {
  return Buffer.from(u64Bytes(value))
}

function relayPrivateKey (relayId) {
  return privateKeyForSeed(fixtureSeed(relayId.endsWith('a') ? 'relay-a' : 'relay-b'))
}

function ressignReceipt (receiptBytes, relayId) {
  const unsigned = receiptBytes.subarray(0, receiptBytes.byteLength - 64)
  const signature = sign(null, Buffer.concat([
    Buffer.from('hiverelay.blind.inbox-receipt.v1', 'ascii'),
    u64(unsigned.byteLength), Buffer.from(unsigned)
  ]), relayPrivateKey(relayId))
  receiptBytes.set(signature, unsigned.byteLength)
}

function ceremonyControl () {
  const receiptByRelay = new Map()
  const events = []
  return {
    events,
    control: {
      async createInboxReplica (input) {
        const binding = fixtureSet.bindings.find(value =>
          value.relayPublicKey === bytesToHex(input.relayPublicKey))
        const index = fixtureSet.bindings.indexOf(binding)
        const createPrivateKey = fixtureSeed(`fixture-only-inbox-create-${index}`)
        const renewPrivateKey = fixtureSeed(`fixture-only-inbox-renew-${index}`)
        const closePrivateKey = fixtureSeed(`fixture-only-inbox-close-${index}`)
        const receipt = receiptForBinding(binding)
        const createPublicKey = publicForSeed(createPrivateKey)
        const renewPublicKey = publicForSeed(renewPrivateKey)
        const closePublicKey = publicForSeed(closePrivateKey)
        const createCommitment = blake2b256(concatBytes(
          asciiBytes('hiverelay.blind.inbox-create.v1'), fromHex(binding.relayPublicKey),
          fromHex(binding.physicalTopic), u32Bytes(binding.allocationEpoch),
          Uint8Array.of(3, 0), new Uint8Array(32), createPublicKey, renewPublicKey,
          closePublicKey, Uint8Array.of(3, 4)
        ))
        const requestCommitment = blake2b256(concatBytes(
          asciiBytes('hiverelay.blind.request.v1inbox-create'), createCommitment,
          receipt.requestNonce
        ))
        const receiptBytes = fromHex(binding.createReceiptCanonicalHex)
        receiptBytes.set(requestCommitment, 289)
        ressignReceipt(receiptBytes, binding.relayId)
        receiptByRelay.set(binding.relayId, receiptBytes)
        return {
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
            clientNonce: receipt.requestNonce
          },
          requestBytes: Uint8Array.of(index + 1),
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
          writeCap: {
            createPrivateKey,
            appendPrivateKey: null,
            renewPrivateKey,
            closePrivateKey
          }
        }
      },
      async verifyOperationResult ({ endpoint }) {
        return { snapshotBytes: () => receiptByRelay.get(endpoint.relayId) }
      },
      decodeBlindExternalProfileValueV1 (_name, receiptBytes) {
        return decodeBlindExternalProfileValueV1('InboxReceiptV1', receiptBytes)
      },
      destroyInboxWriteCapability (capability) {
        for (const field of [
          'createPrivateKey', 'appendPrivateKey', 'renewPrivateKey', 'closePrivateKey'
        ]) capability[field]?.fill(0)
      }
    }
  }
}

function plan () {
  return {
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
      allocationEpoch: fixtureSet.bindings.find(binding =>
        binding.relayId === relay.relayId).allocationEpoch
    }))
  }
}

async function temporaryRoot (label) {
  const base = process.platform === 'darwin' ? '/private/tmp' : os.tmpdir()
  const value = await fs.mkdtemp(path.join(base, `peerit-seq29-custody-${label}-`))
  temporaryRoots.push(value)
  return value
}

function journalAndAuthority (root) {
  const value = plan()
  const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(value)
  const persistedQualification = Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-plan-continuity-v1',
    version: 1,
    planHash,
    referenceUnixMillis: value.referenceUnixMillis,
    seedBootstrapSha256: sha256Hex('fixture-seed-bootstrap-v1'),
    limitedCellPutProfileSha256: sha256Hex('fixture-limited-cell-put-profile-v1')
  })
  const harness = ceremonyControl()
  const journal = createPeeritSeq29FilesystemAttemptJournalV1({
    directory: path.join(root, 'journal')
  })
  const endpointByRelay = new Map(value.relays.map(relay => [
    relay.relayId, { relayId: relay.relayId }
  ]))
  const authority = createPeeritSeq29LimitedInboxCeremonyFixtureAuthorityV1({
    allowFixture: true,
    plan: value,
    control: harness.control,
    runtime: {},
    attemptBinding: { persistedQualification },
    endpointByRelay,
    admissionProviderByRelay: new Map(value.relays.map(relay => [relay.relayId, async () => ({})])),
    clientNonceByRelay: new Map(value.relays.map(relay => [relay.relayId, null])),
    async transportCreate ({ relayId }) {
      harness.events.push(`CREATE:${relayId}`)
      return { ok: true, body: Uint8Array.of(1) }
    }
  })
  return {
    value,
    planHash,
    journal,
    authority,
    harness,
    commitToken: `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${planHash}`
  }
}

function instrumentedCustody (adapter, events, captured = {}) {
  return Object.freeze(Object.fromEntries([
    'prepare', 'commitPublicBinding', 'finalizeSignedBootstrap', 'quarantine'
  ].map(name => [name, async value => {
    events.push(`custody:${name}:begin`)
    captured[name] = structuredClone(value)
    const receipt = await adapter[name](value)
    assert.equal(receipt.durable, true, `${name} returns a durable receipt`)
    captured[`${name}Receipt`] = structuredClone(receipt)
    events.push(`custody:${name}:durable`)
    return receipt
  }])))
}

function signPackage (signingPackage) {
  return signPeeritLimitedPublicInboxBootstrapV1({
    signingPackage,
    seedHex: bytesToHex(fixtureSeed('bootstrap-authority')),
    allowFixture: true
  }).wrapper
}

function findPattern (bytes, pattern) {
  return Buffer.from(bytes).indexOf(Buffer.from(pattern)) >= 0
}

function readU16 (bytes, offset) {
  return bytes[offset] * 256 + bytes[offset + 1]
}

function readU32 (bytes, offset) {
  return bytes[offset] * 0x1000000 + bytes[offset + 1] * 0x10000 +
    bytes[offset + 2] * 0x100 + bytes[offset + 3]
}

function finalEnvelopeLayout (bytes) {
  const sealedPayloadLength = readU32(bytes, 108)
  return {
    sealedPayloadLength,
    sealedPayloadStart: 136,
    shareCountOffset: 136 + sealedPayloadLength,
    shareStart: index => 137 + sealedPayloadLength + index * 237
  }
}

function authenticatedMaliciousShare (input, shareIndex, custodianPrivateKey) {
  const output = new Uint8Array(input)
  const layout = finalEnvelopeLayout(output)
  const shareStart = layout.shareStart(shareIndex)
  const custodySetId = output.slice(1, 33)
  const bundleKind = output[33]
  const index = output[shareStart + 34]
  const custodianPublicKey = output.slice(shareStart + 101, shareStart + 133)
  const ephemeralPublicKey = output.slice(shareStart + 133, shareStart + 165)
  const nonce = output.slice(shareStart + 165, shareStart + 189)
  const aad = output.slice(shareStart, shareStart + 189)
  const sealedShare = output.slice(shareStart + 189, shareStart + 237)
  const shared = new Uint8Array(diffieHellman({
    privateKey: x25519PrivateKey(custodianPrivateKey),
    publicKey: x25519PublicKey(ephemeralPublicKey)
  }))
  const key = new Uint8Array(hkdfSync('sha256', shared, custodySetId, concatBytes(
    asciiBytes('peerit.hiverelay.custody-share-key.v1'),
    Uint8Array.of(bundleKind), Uint8Array.of(index),
    custodianPublicKey, ephemeralPublicKey
  ), 32))
  let plaintext
  try {
    plaintext = xchacha20poly1305(key, nonce, aad).decrypt(sealedShare)
    plaintext[0] ^= 1
    output.set(xchacha20poly1305(key, nonce, aad).encrypt(plaintext), shareStart + 189)
    return output
  } finally {
    plaintext?.fill(0)
    key.fill(0)
    shared.fill(0)
  }
}

async function regularFiles (directory) {
  const output = []
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name)
    if (entry.isDirectory()) output.push(...await regularFiles(target))
    else if (entry.isFile()) output.push(target)
  }
  return output
}

async function independentCanonicalChildCatalog () {
  const read = relative => fs.readFile(new URL(`../${relative}`, import.meta.url))
    .then(value => new Uint8Array(value))
  const wireArtifacts = {
    specBytes: await read('protocol/external-authority/hiverelay-blind-wire-v1.md'),
    abiBytes: await read('protocol/external-authority/hiverelay-blind-abi-v1.cenc'),
    vectorManifestBytes: await read(
      'protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc')
  }
  const clientArtifacts = {
    formatAuthorityBytes: await read(
      'protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'),
    vectorManifestBytes: await read(
      'protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')
  }
  const externalAuthorities = {}
  for (const row of PEERIT_PROFILE_INVENTORY.externalCodecImports) {
    externalAuthorities[row.name] = authenticatePeeritProfileExternalCodecAuthorityV1({
      name: row.name,
      authorityKind: row.authorityKind,
      authorityBinding: row.tupleBinding,
      artifacts: row.authorityKind === 'WIRE_TUPLE_V1' ? wireArtifacts : clientArtifacts,
      assertCanonical (value, name) {
        assert.equal(name, row.name)
        decodeBlindExternalProfileValueV1(name, value)
      }
    })
  }
  const profile = await fs.readFile(new URL(
    '../docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md', import.meta.url), 'utf8')
  return createPeeritProfileCodecCatalogFromIr(
    compilePeeritProfileCodecIr(profile, PEERIT_PROFILE_INVENTORY),
    PEERIT_PROFILE_INVENTORY,
    { externalAuthorities: Object.freeze(externalAuthorities) }
  )
}

function containsBytesDeep (value, pattern, seen = new Set()) {
  if (value instanceof Uint8Array) return findPattern(value, pattern)
  if (value == null || typeof value !== 'object' || seen.has(value)) return false
  seen.add(value)
  if (Array.isArray(value)) return value.some(item => containsBytesDeep(item, pattern, seen))
  return Object.values(value).some(item => containsBytesDeep(item, pattern, seen))
}

async function expectReject (promise, codes, message) {
  await assert.rejects(promise, error => codes.includes(error.code), message)
}

function deferred () {
  let release
  const promise = new Promise(resolve => { release = resolve })
  return { promise, resolve: release }
}

function deferredProvider (privateKeys) {
  let gate = null
  return {
    arm () {
      assert.equal(gate, null, 'only one custodian provider gate is armed at a time')
      gate = { entered: deferred(), release: deferred() }
      return gate
    },
    async provide () {
      if (gate != null) {
        const current = gate
        gate = null
        current.entered.resolve()
        await current.release.promise
      }
      return privateKeys.map(value => new Uint8Array(value))
    }
  }
}

async function pathExists (value) {
  try {
    await fs.lstat(value)
    return true
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false
    throw cause
  }
}

try {
  assert.deepEqual({
    bundleKind: PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1.bundleKind,
    plaintextCodec: PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1.plaintextCodec,
    threshold: PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1.threshold,
    totalShares: PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1.totalShares
  }, { bundleKind: 2, plaintextCodec: 3, threshold: 2, totalShares: 3 },
  'runtime freezes the exact distinct local codec-3 policy')
  assert.deepEqual({
    schema: protocolContract.schema,
    bundleName: protocolContract.bundle.name,
    envelopeName: protocolContract.envelope.name,
    childName: protocolContract.bundle.entryCodec.name,
    childSourceSha256: protocolContract.bundle.entryCodec.sourceSha256,
    bundleKind: protocolContract.envelope.bundleKind,
    plaintextCodec: protocolContract.envelope.plaintextCodec
  }, {
    schema: 'peerit-seq29-limited-public-inbox-management-custody-v1',
    bundleName: 'PeeritLimitedPublicInboxManagementBundleV1',
    envelopeName: 'PeeritLimitedPublicInboxCustodyEnvelopeV1',
    childName: 'InboxManagementEntryV1',
    childSourceSha256: '898162c532d73c70c873ec5000b3390deb768f0cd21716c8e009aa3a62aa74cc',
    bundleKind: 2,
    plaintextCodec: 3
  }, 'implementation authority is the exact codec-3 contract and canonical child source')
  assert.throws(() => peeritSeq29LocalManagementCustodyPathsV1({
    directory: '/private/tmp/peerit-seq29-path-boundary',
    transactionId: '..'
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_INVALID',
  'custody path derivation rejects traversal and accepts only canonical transaction IDs')

  const exactOrder8X25519PublicKeys = [
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'
  ]
  const mistypedOrder8X25519PublicKeys = [
    'e0eb7a7c3b41b8ae1656e3fa1f6f7f3c0a37f7d5b4f47f170bcfdc728d63333f',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224e8b01f22f4f',
    '5f9c95bca3508c24b1d0b1559c83ef5b0445cc4581c8e86d8224eddd09f1157'
  ]
  for (let index = 0; index < exactOrder8X25519PublicKeys.length; index++) {
    const raw = fromHex(exactOrder8X25519PublicKeys[index])
    assert.equal(x25519PublicKey(raw).asymmetricKeyType, 'x25519',
      `Node accepts exact order-8 encoding ${index + 1} as an X25519 public key`)
    assert.equal(PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1
      .lowOrderX25519PublicKeys.includes(exactOrder8X25519PublicKeys[index]), true,
    `custody blocklist freezes exact libsodium order-8 encoding ${index + 1}`)
    const pins = authoritativeCustodyVector.fixtureCustodianPublicKeys.map(fromHex)
    pins[index] = raw
    assert.throws(() => createPeeritSeq29LocalManagementCustodyV1({
      directory: path.join(os.tmpdir(), `peerit-seq29-order8-${index + 1}`),
      custodianPublicKeys: pins,
      custodianPrivateKeyProvider: async () => []
    }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_LOW_ORDER_KEY',
    `custody rejects exact order-8 encoding ${index + 1} before storage or exchange`)
  }
  for (const mistyped of mistypedOrder8X25519PublicKeys) {
    assert.equal(PEERIT_SEQ29_LIMITED_MANAGEMENT_CUSTODY_PROTOCOL_V1
      .lowOrderX25519PublicKeys.includes(mistyped), false,
    'custody does not retain a mistyped order-8 blocklist value')
  }

  let vectorPlaintext
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const recovered = await recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
      envelope: fromHex(authoritativeCustodyVector.envelopeCanonicalHex),
      custodianPublicKeys: authoritativeCustodyVector.fixtureCustodianPublicKeys.map(fromHex),
      custodianPrivateKeys: pair.map(index =>
        fromHex(authoritativeCustodyVector.fixtureCustodianPrivateKeys[index])),
      signedBootstrap: fixture
    })
    try {
      assert.equal(sha256Hex(recovered.plaintext), authoritativeCustodyVector.plaintextSha256,
        `authoritative contract vector pair ${pair.join('+')} recovers exact plaintext`)
      assert.equal(recovered.signedBootstrapHash,
        '0f88bf73e4914e35dbb407aa4196e0cfbdae87d724b35a95e6a24859458c1aac',
        'codec-3 bundle uses compact stable-canonical complete-wrapper hash')
      if (vectorPlaintext == null) {
        vectorPlaintext = new Uint8Array(recovered.plaintext)
      } else {
        assert.equal(bytesEqual(recovered.plaintext, vectorPlaintext), true,
          'all authoritative vector pairs recover byte-identically')
      }
    } finally { recovered.destroy() }
  }
  vectorPlaintext.fill(0)
  const canonicalChildCatalog = await independentCanonicalChildCatalog()

  const root = await temporaryRoot('happy')
  const custodianPrivateKeys = [1, 2, 3].map(index =>
    new Uint8Array(createHash('sha256').update(`custodian-${index}`).digest()))
  const custodianPublicKeys = custodianPrivateKeys.map(x25519PublicForPrivate)
  const ceremony = journalAndAuthority(root)
  const custodyRoot = path.join(root, 'custody')
  let providerCalls = 0
  let lastProvidedKeys = []
  const adapter = createPeeritSeq29LocalManagementCustodyV1({
    directory: custodyRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () => {
      providerCalls++
      lastProvidedKeys = custodianPrivateKeys.map(value => new Uint8Array(value))
      return lastProvidedKeys
    }
  })
  const captured = {}
  const custody = instrumentedCustody(adapter, ceremony.harness.events, captured)
  const result = await executePeeritLimitedInboxTopicCeremonyV1({
    authority: ceremony.authority,
    commitToken: ceremony.commitToken,
    attemptJournal: ceremony.journal,
    custodyTransaction: custody
  })
  assert.equal(result.status, 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP')
  assert.equal(ceremony.harness.events[0], 'custody:prepare:begin')
  assert.equal(ceremony.harness.events[1], 'custody:prepare:durable')
  assert.equal(ceremony.harness.events[2].startsWith('CREATE:'), true,
    'encrypted custody is durable before the first CREATE invocation')
  assert.deepEqual(ceremony.harness.events.slice(-2), [
    'custody:commitPublicBinding:begin', 'custody:commitPublicBinding:durable'
  ])
  assert.equal(lastProvidedKeys.every(key => key.every(byte => byte === 0)), true,
    'short-lived provider key copies are wiped after the durable transition')
  const repeatedPrepare = await adapter.prepare(structuredClone(captured.prepare))
  assert.equal(repeatedPrepare.commitment, captured.prepareReceipt.commitment,
    'same-request prepare is byte-identically idempotent')

  const transactionId = peeritSeq29LocalManagementCustodyTransactionIdV1({
    planHash: ceremony.planHash,
    attemptId: result.attemptId
  })
  const paths = peeritSeq29LocalManagementCustodyPathsV1({
    directory: custodyRoot,
    transactionId
  })
  const prepared = new Uint8Array(await fs.readFile(paths.prepared))
  assert.equal((await fs.stat(paths.directory)).mode & 0o777, 0o700)
  assert.equal((await fs.stat(paths.prepared)).mode & 0o777, 0o600)
  for (let index = 0; index < 2; index++) {
    for (const role of ['create', 'renew', 'close']) {
      const seed = fixtureSeed(`fixture-only-inbox-${role}-${index}`)
      assert.equal(findPattern(prepared, seed), false,
        `${role} seed ${index} is absent from durable prepared ciphertext`)
    }
  }
  assert.equal(findPattern(prepared, asciiBytes(result.attemptId)), false,
    'private attempt metadata is encrypted rather than logged in the prepared envelope')

  const restarted = createPeeritSeq29LocalManagementCustodyV1({
    directory: custodyRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () => custodianPrivateKeys.map(value => new Uint8Array(value))
  })
  const recoveredExecution = await executePeeritLimitedInboxTopicCeremonyV1({
    authority: ceremony.authority,
    commitToken: ceremony.commitToken,
    attemptJournal: ceremony.journal,
    custodyTransaction: restarted
  })
  assert.equal(recoveredExecution.status, 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP')
  assert.equal(ceremony.harness.events.filter(value => value.startsWith('CREATE:')).length, 2,
    'restart reuses durable recovery without resending CREATE')

  const signedBootstrap = signPackage(result.signingPackage)
  const finalizationCaptured = {}
  const finalizationCustody = instrumentedCustody(
    restarted, ceremony.harness.events, finalizationCaptured)
  const finalized = await finalizePeeritLimitedInboxTopicCeremonyV1({
    authority: ceremony.authority,
    commitToken: ceremony.commitToken,
    signedBootstrap,
    attemptJournal: ceremony.journal,
    custodyTransaction: finalizationCustody
  })
  assert.equal(finalized.status, 'COMMITTED_CREATE_ONLY')
  const envelope = new Uint8Array(await fs.readFile(paths.finalEnvelope))
  assert.equal(envelope[0], 1)
  assert.equal(envelope[33], 2, 'final envelope freezes INBOX_MANAGEMENT bundleKind=2')
  assert.equal(readU16(envelope, 34), 3,
    'final envelope is the distinct limited plaintextCodec=3, never generic codec 2')
  const envelopeLayout = finalEnvelopeLayout(envelope)
  assert.ok(envelopeLayout.sealedPayloadLength > 16)
  assert.equal(envelope[envelopeLayout.shareCountOffset], 3)
  assert.equal((await fs.stat(paths.finalEnvelope)).mode & 0o777, 0o600)
  assert.equal(sha256Hex(await fs.readFile(paths.finalEnvelope)).length, 64)
  for (let index = 0; index < 2; index++) {
    for (const role of ['create', 'renew', 'close']) {
      assert.equal(findPattern(envelope, fixtureSeed(`fixture-only-inbox-${role}-${index}`)), false,
        `${role} seed ${index} is absent from final ciphertext`)
    }
  }

  let expectedPlaintext
  const compactSignedBootstrapHash = sha256Hex(
    canonicalPeeritLimitedPublicInboxJsonV1(signedBootstrap))
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const recovered = await recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
      envelope,
      custodianPublicKeys,
      custodianPrivateKeys: pair.map(index => new Uint8Array(custodianPrivateKeys[index])),
      signedBootstrap
    })
    try {
      assert.equal(recovered.entries.length, 2)
      assert.equal(recovered.signedBootstrapHash, compactSignedBootstrapHash,
        'generated codec-3 bundle binds the compact stable-canonical wrapper hash')
      if (expectedPlaintext == null) {
        expectedPlaintext = new Uint8Array(recovered.plaintext)
      } else {
        assert.equal(bytesEqual(recovered.plaintext, expectedPlaintext), true,
          `pair ${pair.join('+')} recovers the exact same management bundle`)
      }
    } finally { recovered.destroy() }
  }

  const successfulTransientEvents = []
  const instrumentedRecovery = await recoverPeeritSeq29LimitedManagementCustodyEnvelopeFixtureV1({
    envelope,
    custodianPublicKeys,
    custodianPrivateKeys: [0, 1].map(index =>
      new Uint8Array(custodianPrivateKeys[index])),
    signedBootstrap,
    observeSecretTransient (event) {
      assert.equal(event.schema, 'peerit-seq29-local-custody-secret-transient-v1')
      assert.ok(event.bytes instanceof Uint8Array)
      if (event.event.startsWith('ZEROIZED_')) {
        assert.equal(event.bytes.every(byte => byte === 0), true,
          `${event.event} is zero before the success-path observer receives it`)
      }
      successfulTransientEvents.push(event)
    }
  })
  const successfulParentViews = successfulTransientEvents.filter(event =>
    event.event.startsWith('PARENT_PLAINTEXT_'))
  const liveSuccessfulParentViews = successfulParentViews.filter(event =>
    event.bytes.some(byte => byte !== 0))
  assert.equal(successfulParentViews.length, 6,
    'two complete validations expose only three non-copying plaintext views each')
  assert.equal(liveSuccessfulParentViews.length, 3,
    'candidate views are already zero and only returned-plaintext views remain live')
  assert.equal(liveSuccessfulParentViews.every(event =>
    event.bytes.buffer === instrumentedRecovery.plaintext.buffer), true,
  'live entry and prefix views share the returned plaintext backing buffer')
  assert.equal(successfulTransientEvents.filter(event =>
    event.event === 'ZEROIZED_BUNDLE_COMMITMENT_PREIMAGE').length, 2,
  'success wipes each complete bundle-commitment preimage')
  assert.equal(successfulTransientEvents.filter(event =>
    event.event === 'ZEROIZED_DECODE_ENTRY_CANONICAL_REENCODE').length, 4,
  'success wipes every decoder canonical management-entry re-encode')
  assert.equal(successfulTransientEvents.filter(event =>
    event.event === 'ZEROIZED_OUTER_ENTRY_CANONICAL_REENCODE').length, 4,
  'success wipes every outer-validator canonical management-entry re-encode')
  instrumentedRecovery.destroy()
  assert.equal(successfulParentViews.every(event =>
    event.bytes.every(byte => byte === 0)), true,
  'destroy wipes every success-path entry and prefix view through its parent plaintext')

  const failingTransientEvents = []
  let outerCanonicalZeroizations = 0
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeFixtureV1({
    envelope,
    custodianPublicKeys,
    custodianPrivateKeys: [0, 1].map(index =>
      new Uint8Array(custodianPrivateKeys[index])),
    signedBootstrap,
    observeSecretTransient (event) {
      failingTransientEvents.push(event)
      if (event.event.startsWith('ZEROIZED_')) {
        assert.equal(event.bytes.every(byte => byte === 0), true,
          `${event.event} is zero before the failure-path observer receives it`)
      }
      if (event.event === 'ZEROIZED_OUTER_ENTRY_CANONICAL_REENCODE') {
        outerCanonicalZeroizations++
      }
      if (outerCanonicalZeroizations === 3) {
        outerCanonicalZeroizations++
        const error = new Error('fixture abort after zeroizing outer canonical re-encode')
        error.code = 'PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH'
        throw error
      }
    }
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_BINDING_MISMATCH'],
  'final-validation failure after canonical re-encoding wipes the returned candidate')
  assert.equal(failingTransientEvents.some(event =>
    event.event === 'ZEROIZED_DECODE_ENTRY_CANONICAL_REENCODE'), true,
  'failure observes a zeroized decoder canonical re-encode')
  assert.equal(failingTransientEvents.some(event =>
    event.event === 'ZEROIZED_OUTER_ENTRY_CANONICAL_REENCODE'), true,
  'failure observes a zeroized outer canonical re-encode')
  assert.equal(failingTransientEvents.filter(event =>
    event.event.startsWith('PARENT_PLAINTEXT_')).every(event =>
    event.bytes.every(byte => byte === 0)), true,
  'failure wipes all non-copying entry and prefix views through the rejected plaintext')
  assert.equal(failingTransientEvents.filter(event =>
    event.event.startsWith('ZEROIZED_')).every(event =>
    event.bytes.every(byte => byte === 0)), true,
  'every retained failure-path transient remains zeroized')

  assert.equal(expectedPlaintext[0], 1)
  assert.equal(Buffer.from(expectedPlaintext.subarray(1, 9)).readBigUInt64BE(), 29n)
  assert.equal(expectedPlaintext[73], 0)
  assert.equal(expectedPlaintext[85], 2,
    'canonical plaintext has exact initial-release entry cardinality two')
  assert.equal(bytesEqual(expectedPlaintext.subarray(41, 73),
    fromHex(compactSignedBootstrapHash)), true,
  'canonical plaintext embeds the compact complete-wrapper hash')
  const bundlePrefix = expectedPlaintext.subarray(0, expectedPlaintext.byteLength - 32)
  assert.equal(bytesEqual(expectedPlaintext.subarray(-32), blake2b256(concatBytes(
    asciiBytes('peerit.hiverelay.limited-public-inbox-management-bundle.v1'),
    u64Bytes(bundlePrefix.byteLength), bundlePrefix
  ))), true, 'codec-3 bundle commitment binds every canonical field')
  let childOffset = 86
  for (let index = 0; index < 2; index++) {
    const childLength = readU16(expectedPlaintext, childOffset)
    const childBytes = expectedPlaintext.slice(childOffset + 2, childOffset + 2 + childLength)
    const canonicalChild = canonicalChildCatalog.InboxManagementEntryV1.decode(childBytes)
    assert.equal(bytesEqual(
      canonicalChildCatalog.InboxManagementEntryV1.encode(canonicalChild), childBytes
    ), true, `generated management entry ${index} is canonical under the independent profile codec`)
    childOffset += 2 + childLength
  }
  expectedPlaintext.fill(0)

  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope,
    custodianPublicKeys,
    custodianPrivateKeys: [new Uint8Array(custodianPrivateKeys[0])],
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_THRESHOLD'], 'one key cannot recover')
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope,
    custodianPublicKeys,
    custodianPrivateKeys: [new Uint8Array(custodianPrivateKeys[0]), new Uint8Array(custodianPrivateKeys[0])],
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE'], 'duplicate keys fail')
  const wrongKey = new Uint8Array(createHash('sha256').update('wrong recipient').digest())
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope,
    custodianPublicKeys,
    custodianPrivateKeys: [new Uint8Array(custodianPrivateKeys[0]), wrongKey],
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_WRONG_RECIPIENT'], 'wrong recipient fails')
  const tampered = new Uint8Array(envelope)
  tampered[tampered.byteLength - 1] ^= 1
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: tampered,
    custodianPublicKeys,
    custodianPrivateKeys: custodianPrivateKeys.map(value => new Uint8Array(value)),
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED'],
  'an unauthenticated share-ciphertext mutation fails even when all three keys are supplied')
  const malicious = authenticatedMaliciousShare(envelope, 2, custodianPrivateKeys[2])
  const tolerated = await recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: malicious,
    custodianPublicKeys,
    custodianPrivateKeys: custodianPrivateKeys.map(value => new Uint8Array(value)),
    signedBootstrap
  })
  try {
    assert.deepEqual(tolerated.rejectedShares, [],
      'all-three recovery authenticates every share and uses the one honest pair')
  } finally { tolerated.destroy() }
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: malicious,
    custodianPublicKeys,
    custodianPrivateKeys: [0, 2].map(index => new Uint8Array(custodianPrivateKeys[index])),
    signedBootstrap
  }), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_RECONSTRUCTION_FAILED'
  ], 'an authenticated malicious share plus only one honest share fails closed')
  const tamperedPayload = new Uint8Array(envelope)
  tamperedPayload[envelopeLayout.sealedPayloadStart] ^= 1
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: tamperedPayload,
    custodianPublicKeys,
    custodianPrivateKeys: custodianPrivateKeys.map(value => new Uint8Array(value)),
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_CORRUPT', 'PEERIT_SEQ29_LOCAL_CUSTODY_RECONSTRUCTION_FAILED'],
  'payload tamper fails')

  const duplicateEphemeral = new Uint8Array(envelope)
  duplicateEphemeral.set(duplicateEphemeral.subarray(
    envelopeLayout.shareStart(0) + 133, envelopeLayout.shareStart(0) + 165
  ), envelopeLayout.shareStart(1) + 133)
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: duplicateEphemeral,
    custodianPublicKeys,
    custodianPrivateKeys: custodianPrivateKeys.map(value => new Uint8Array(value)),
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE'], 'duplicate ephemeral keys fail')

  const duplicateNonce = new Uint8Array(envelope)
  duplicateNonce.set(duplicateNonce.subarray(
    envelopeLayout.shareStart(0) + 165, envelopeLayout.shareStart(0) + 189
  ), envelopeLayout.shareStart(1) + 165)
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: duplicateNonce,
    custodianPublicKeys,
    custodianPrivateKeys: custodianPrivateKeys.map(value => new Uint8Array(value)),
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE'], 'duplicate share nonces fail')

  const duplicateCiphertext = new Uint8Array(envelope)
  duplicateCiphertext.set(duplicateCiphertext.subarray(
    envelopeLayout.shareStart(0) + 189, envelopeLayout.shareStart(0) + 237
  ), envelopeLayout.shareStart(1) + 189)
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: duplicateCiphertext,
    custodianPublicKeys,
    custodianPrivateKeys: custodianPrivateKeys.map(value => new Uint8Array(value)),
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE'], 'duplicate share ciphertexts fail')

  const lowOrderEphemeral = new Uint8Array(envelope)
  lowOrderEphemeral.fill(0,
    envelopeLayout.shareStart(0) + 133, envelopeLayout.shareStart(0) + 165)
  lowOrderEphemeral[envelopeLayout.shareStart(0) + 133] = 1
  await expectReject(recoverPeeritSeq29LimitedManagementCustodyEnvelopeV1({
    envelope: lowOrderEphemeral,
    custodianPublicKeys,
    custodianPrivateKeys: custodianPrivateKeys.map(value => new Uint8Array(value)),
    signedBootstrap
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_LOW_ORDER_KEY'],
  'nonzero known low-order ephemeral key fails before exchange')

  const lowOrderPins = custodianPublicKeys.map(value => new Uint8Array(value))
  lowOrderPins[1] = new Uint8Array(32)
  lowOrderPins[1][0] = 1
  assert.throws(() => createPeeritSeq29LocalManagementCustodyV1({
    directory: path.join(root, 'low-order'),
    custodianPublicKeys: lowOrderPins,
    custodianPrivateKeyProvider: async () => []
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_LOW_ORDER_KEY',
  'nonzero low-order recipient fails')
  const highBitAliasPins = custodianPublicKeys.map(value => new Uint8Array(value))
  highBitAliasPins[0][31] |= 0x80
  assert.throws(() => createPeeritSeq29LocalManagementCustodyV1({
    directory: path.join(root, 'high-bit-alias'),
    custodianPublicKeys: highBitAliasPins,
    custodianPrivateKeyProvider: async () => []
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_NONCANONICAL_KEY',
  'an X25519 high-bit alias of a valid recipient pin fails before storage or exchange')
  const fieldPrimePins = custodianPublicKeys.map(value => new Uint8Array(value))
  fieldPrimePins[0] = new Uint8Array([0xed, ...Array(30).fill(0xff), 0x7f])
  assert.throws(() => createPeeritSeq29LocalManagementCustodyV1({
    directory: path.join(root, 'field-prime-alias'),
    custodianPublicKeys: fieldPrimePins,
    custodianPrivateKeyProvider: async () => []
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_NONCANONICAL_KEY',
  'an X25519 u-coordinate at the field prime fails as noncanonical')
  const duplicatePins = custodianPublicKeys.map(value => new Uint8Array(value))
  duplicatePins[2] = new Uint8Array(duplicatePins[0])
  assert.throws(() => createPeeritSeq29LocalManagementCustodyV1({
    directory: path.join(root, 'duplicate-pins'),
    custodianPublicKeys: duplicatePins,
    custodianPrivateKeyProvider: async () => []
  }), error => error.code === 'PEERIT_SEQ29_LOCAL_CUSTODY_DUPLICATE',
  'duplicate custodian public pins fail')

  const finalizedAgain = await restarted.finalizeSignedBootstrap(
    structuredClone(finalizationCaptured.finalizeSignedBootstrap))
  assert.equal(finalizedAgain.commitment,
    finalizationCaptured.finalizeSignedBootstrapReceipt.commitment,
    'same exact finalization is idempotent across the durable envelope')

  const mismatchedFinalization = await restarted.finalizeSignedBootstrap({
    transactionId,
    planHash: ceremony.planHash,
    attemptId: result.attemptId,
    signingPackageSha256: createHash('sha256').update(JSON.stringify(result.signingPackage)).digest('hex'),
    publicBindingDigest: '00'.repeat(32),
    signedBootstrap,
    signedBootstrapHash: '00'.repeat(32),
    finalizationDigest: '00'.repeat(32)
  }).catch(error => error)
  assert.ok(mismatchedFinalization instanceof Error,
    'mismatched repeated finalization fails without replacing the immutable envelope')
  assert.equal(bytesEqual(envelope, await fs.readFile(paths.finalEnvelope)), true)

  const raceRoot = await temporaryRoot('transition-race')
  const raceProvider = deferredProvider(custodianPrivateKeys)
  const raceAdapter = createPeeritSeq29LocalManagementCustodyV1({
    directory: raceRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: () => raceProvider.provide()
  })
  const racePeer = createPeeritSeq29LocalManagementCustodyV1({
    directory: raceRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () =>
      custodianPrivateKeys.map(value => new Uint8Array(value))
  })
  const racePrepared = await raceAdapter.prepare(structuredClone(captured.prepare))
  const racePaths = peeritSeq29LocalManagementCustodyPathsV1({
    directory: raceRoot,
    transactionId: racePrepared.transactionId
  })
  const raceQuarantineRequest = {
    transactionId: racePrepared.transactionId,
    planHash: captured.prepare.planHash,
    attemptId: captured.prepare.attemptId,
    disposition: 'QUARANTINED_CREATE_OUTCOME'
  }
  const commitGate = raceProvider.arm()
  const racingCommit = raceAdapter.commitPublicBinding(
    structuredClone(captured.commitPublicBinding))
  await commitGate.entered.promise
  await expectReject(racePeer.quarantine(raceQuarantineRequest), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY'
  ], 'a quarantine cannot cross an awaited public-binding provider transition')
  await expectReject(racePeer.finalizeSignedBootstrap(
    structuredClone(finalizationCaptured.finalizeSignedBootstrap)
  ), ['PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY'],
  'finalization cannot cross an awaited public-binding provider transition')
  assert.equal(await pathExists(racePaths.publicBinding), false,
    'no public binding becomes visible while its guarded provider transition is pending')
  assert.equal(await pathExists(racePaths.quarantine), false,
    'a losing quarantine race writes no terminal marker')
  commitGate.release.resolve()
  await racingCommit
  assert.equal(await pathExists(racePaths.publicBinding), true)

  const finalGate = raceProvider.arm()
  const racingFinalization = raceAdapter.finalizeSignedBootstrap(
    structuredClone(finalizationCaptured.finalizeSignedBootstrap))
  await finalGate.entered.promise
  await expectReject(racePeer.quarantine(raceQuarantineRequest), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY'
  ], 'quarantine cannot cross an awaited final-envelope provider transition')
  await expectReject(racePeer.finalizeSignedBootstrap(
    structuredClone(finalizationCaptured.finalizeSignedBootstrap)
  ), ['PEERIT_SEQ29_LOCAL_CUSTODY_TRANSITION_BUSY'],
  'a second finalization cannot split an awaited final-envelope transition')
  assert.equal(await pathExists(racePaths.finalEnvelope), false,
    'no final envelope becomes visible while self-verification is pending')
  finalGate.release.resolve()
  await racingFinalization
  assert.equal(await pathExists(racePaths.finalEnvelope), true)
  assert.equal(await pathExists(racePaths.quarantine), false)

  const mismatchRoot = await temporaryRoot('provider-mismatch')
  const wrongCustodianKey = new Uint8Array(createHash('sha256')
    .update('wrong generated-envelope custodian').digest())
  const mismatchAdapter = createPeeritSeq29LocalManagementCustodyV1({
    directory: mismatchRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () => [
      new Uint8Array(custodianPrivateKeys[0]), new Uint8Array(wrongCustodianKey)
    ]
  })
  const mismatchTransactionId = peeritSeq29LocalManagementCustodyTransactionIdV1({
    planHash: captured.prepare.planHash,
    attemptId: captured.prepare.attemptId
  })
  const mismatchPaths = peeritSeq29LocalManagementCustodyPathsV1({
    directory: mismatchRoot,
    transactionId: mismatchTransactionId
  })
  await expectReject(mismatchAdapter.prepare(structuredClone(captured.prepare)), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_WRONG_RECIPIENT'
  ], 'a provider/public-pin mismatch fails generated-stage self-verification')
  assert.equal(await pathExists(mismatchPaths.identity), false,
    'provider mismatch writes no transaction identity')
  assert.equal(await pathExists(mismatchPaths.prepared), false,
    'provider mismatch writes no sealed prepared stage')

  async function corruptStageProbe (stage) {
    const corruptRoot = await temporaryRoot(`corrupt-${stage.toLowerCase()}`)
    const corruptAdapter = createPeeritSeq29LocalManagementCustodyFixtureV1({
      directory: corruptRoot,
      custodianPublicKeys,
      custodianPrivateKeyProvider: async () =>
        custodianPrivateKeys.map(value => new Uint8Array(value)),
      corruptGeneratedEnvelope (generatedStage, generatedEnvelope) {
        if (generatedStage === stage) generatedEnvelope[generatedEnvelope.byteLength - 1] ^= 1
      }
    })
    const corruptTransactionId = peeritSeq29LocalManagementCustodyTransactionIdV1({
      planHash: captured.prepare.planHash,
      attemptId: captured.prepare.attemptId
    })
    const corruptPaths = peeritSeq29LocalManagementCustodyPathsV1({
      directory: corruptRoot,
      transactionId: corruptTransactionId
    })
    if (stage === 'PREPARED') {
      await expectReject(corruptAdapter.prepare(structuredClone(captured.prepare)), [
        'PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED'
      ], 'a corrupt generated prepared envelope is rejected before durability')
      assert.equal(await pathExists(corruptPaths.identity), false)
      assert.equal(await pathExists(corruptPaths.prepared), false)
      return
    }
    await corruptAdapter.prepare(structuredClone(captured.prepare))
    if (stage === 'PUBLIC_BOUND') {
      await expectReject(corruptAdapter.commitPublicBinding(
        structuredClone(captured.commitPublicBinding)
      ), ['PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED'],
      'a corrupt generated public-binding envelope is rejected before durability')
      assert.equal(await pathExists(corruptPaths.prepared), true)
      assert.equal(await pathExists(corruptPaths.publicBinding), false)
      return
    }
    await corruptAdapter.commitPublicBinding(structuredClone(captured.commitPublicBinding))
    await expectReject(corruptAdapter.finalizeSignedBootstrap(
      structuredClone(finalizationCaptured.finalizeSignedBootstrap)
    ), ['PEERIT_SEQ29_LOCAL_CUSTODY_AUTH_FAILED'],
    'a corrupt generated final envelope is rejected before durability')
    assert.equal(await pathExists(corruptPaths.publicBinding), true)
    assert.equal(await pathExists(corruptPaths.finalEnvelope), false)
  }
  await corruptStageProbe('PREPARED')
  await corruptStageProbe('PUBLIC_BOUND')
  await corruptStageProbe('FINAL')

  const rootReplacementBase = await temporaryRoot('root-replacement')
  const replaceableRoot = path.join(rootReplacementBase, 'custody')
  const rootReplacementAdapter = createPeeritSeq29LocalManagementCustodyV1({
    directory: replaceableRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () =>
      custodianPrivateKeys.map(value => new Uint8Array(value))
  })
  const displacedRoot = path.join(rootReplacementBase, 'custody-displaced')
  await fs.rename(replaceableRoot, displacedRoot)
  await fs.symlink(displacedRoot, replaceableRoot, 'dir')
  await expectReject(rootReplacementAdapter.prepare(structuredClone(captured.prepare)), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
    'PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED'
  ], 'a replaced custody root is rejected before prepare state access')

  const transactionReplacementRoot = await temporaryRoot('transaction-replacement')
  const transactionReplacementAdapter = createPeeritSeq29LocalManagementCustodyV1({
    directory: transactionReplacementRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () =>
      custodianPrivateKeys.map(value => new Uint8Array(value))
  })
  const transactionPrepared = await transactionReplacementAdapter.prepare(
    structuredClone(captured.prepare))
  const transactionReplacementPaths = peeritSeq29LocalManagementCustodyPathsV1({
    directory: transactionReplacementRoot,
    transactionId: transactionPrepared.transactionId
  })
  const displacedTransaction = `${transactionReplacementPaths.directory}-displaced`
  await fs.rename(transactionReplacementPaths.directory, displacedTransaction)
  await fs.symlink(displacedTransaction, transactionReplacementPaths.directory, 'dir')
  await expectReject(transactionReplacementAdapter.quarantine({
    transactionId: transactionPrepared.transactionId,
    planHash: captured.prepare.planHash,
    attemptId: captured.prepare.attemptId,
    disposition: 'QUARANTINED_NO_CREATE'
  }), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS',
    'PEERIT_SEQ29_LOCAL_CUSTODY_DIRECTORY_REPLACED'
  ], 'quarantine rejects a replaced transaction directory before reading prepared custody')

  const modeDriftRoot = await temporaryRoot('mode-drift')
  const modeDriftAdapter = createPeeritSeq29LocalManagementCustodyV1({
    directory: modeDriftRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () =>
      custodianPrivateKeys.map(value => new Uint8Array(value))
  })
  await fs.chmod(modeDriftRoot, 0o755)
  await expectReject(modeDriftAdapter.prepare(structuredClone(captured.prepare)), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS'
  ], 'custody root mode drift is rejected before prepare')
  await fs.chmod(modeDriftRoot, 0o700)
  const modePrepared = await modeDriftAdapter.prepare(structuredClone(captured.prepare))
  const modePaths = peeritSeq29LocalManagementCustodyPathsV1({
    directory: modeDriftRoot,
    transactionId: modePrepared.transactionId
  })
  await fs.chmod(modePaths.directory, 0o755)
  await expectReject(modeDriftAdapter.quarantine({
    transactionId: modePrepared.transactionId,
    planHash: captured.prepare.planHash,
    attemptId: captured.prepare.attemptId,
    disposition: 'QUARANTINED_NO_CREATE'
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS'],
  'transaction-directory mode drift is rejected before quarantine state access')
  await fs.chmod(modePaths.directory, 0o700)
  const staleGuard = path.join(modePaths.directory, '.peerit-seq29-transition.lock')
  await fs.mkdir(staleGuard, { mode: 0o700 })
  await expectReject(modeDriftAdapter.quarantine({
    transactionId: modePrepared.transactionId,
    planHash: captured.prepare.planHash,
    attemptId: captured.prepare.attemptId,
    disposition: 'QUARANTINED_NO_CREATE'
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_PERMISSIONS'],
  'an unbranded transition-guard shadow fails closed instead of being reclaimed')
  await fs.rmdir(staleGuard)

  const quarantineRoot = await temporaryRoot('quarantine')
  const quarantineKeys = custodianPrivateKeys.map(value => new Uint8Array(value))
  let quarantineProviderCalls = 0
  const quarantineAdapter = createPeeritSeq29LocalManagementCustodyV1({
    directory: quarantineRoot,
    custodianPublicKeys,
    custodianPrivateKeyProvider: async () => {
      quarantineProviderCalls++
      return quarantineKeys.map(value => new Uint8Array(value))
    }
  })
  const quarantineRequest = {
    schema: 'peerit-limited-inbox-topic-private-custody-input-v1',
    disposition: 'SEALED_PENDING_CREATE',
    planHash: 'ab'.repeat(32),
    attemptId: 'quarantine-attempt',
    entries: fixtureSet.bindings.map((binding, index) => ({
      relayId: binding.relayId,
      allocationEpoch: binding.allocationEpoch,
      createPrivateSeed: fixtureSeed(`fixture-only-inbox-create-${index}`),
      renewPrivateSeed: fixtureSeed(`fixture-only-inbox-renew-${index}`),
      closePrivateSeed: fixtureSeed(`fixture-only-inbox-close-${index}`)
    }))
  }
  const preparedReceipt = await quarantineAdapter.prepare(quarantineRequest)
  const providerCallsBeforeInspection = quarantineProviderCalls
  const inspectedPrepared =
    await inspectPeeritSeq29LocalManagementPreparedTransitionV1({
      custody: quarantineAdapter,
      planHash: quarantineRequest.planHash,
      attemptId: quarantineRequest.attemptId
    })
  assert.deepEqual(Object.keys(inspectedPrepared).sort(), [
    'accepted', 'commitment', 'durable', 'state', 'transactionId'
  ])
  assert.deepEqual(inspectedPrepared, preparedReceipt)
  assert.equal(quarantineProviderCalls, providerCallsBeforeInspection,
    'PREPARED inspection must not call the private-key provider or decrypt custody')
  assert.equal(JSON.stringify(inspectedPrepared).includes('seed'), false,
    'PREPARED inspection must not return entries or seed material')
  const preparedTransition =
    await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
      custody: quarantineAdapter,
      planHash: quarantineRequest.planHash,
      attemptId: quarantineRequest.attemptId,
      commitment: preparedReceipt.commitment
    })
  const transitionedSeeds = preparedTransition.entries.flatMap(entry => [
    entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed
  ])
  assert.equal(transitionedSeeds.every(value => value.some(byte => byte !== 0)), true)
  preparedTransition.destroy()
  assert.equal(transitionedSeeds.every(value => value.every(byte => byte === 0)), true,
    'explicit PREPARED transition recovery wipes every returned seed copy')
  const quarantine = await quarantineAdapter.quarantine({
    transactionId: preparedReceipt.transactionId,
    planHash: quarantineRequest.planHash,
    attemptId: quarantineRequest.attemptId,
    disposition: 'QUARANTINED_NO_CREATE'
  })
  assert.equal(quarantine.state, 'QUARANTINED')
  await expectReject(
    recoverPeeritSeq29LocalManagementPreparedTransitionV1({
      custody: quarantineAdapter,
      planHash: quarantineRequest.planHash,
      attemptId: quarantineRequest.attemptId,
      commitment: preparedReceipt.commitment
    }),
    ['PEERIT_SEQ29_LOCAL_CUSTODY_QUARANTINED'],
    'PREPARED recovery is unavailable after the transaction becomes terminal')
  await expectReject(
    inspectPeeritSeq29LocalManagementPreparedTransitionV1({
      custody: quarantineAdapter,
      planHash: quarantineRequest.planHash,
      attemptId: quarantineRequest.attemptId
    }),
    ['PEERIT_SEQ29_LOCAL_CUSTODY_QUARANTINED'],
    'PREPARED inspection is unavailable after the transaction becomes terminal')
  const quarantinePaths = peeritSeq29LocalManagementCustodyPathsV1({
    directory: quarantineRoot,
    transactionId: preparedReceipt.transactionId
  })
  assert.equal((await fs.stat(quarantinePaths.quarantine)).mode & 0o777, 0o600)
  const repeatedQuarantine = await quarantineAdapter.quarantine({
    transactionId: preparedReceipt.transactionId,
    planHash: quarantineRequest.planHash,
    attemptId: quarantineRequest.attemptId,
    disposition: 'QUARANTINED_NO_CREATE'
  })
  assert.equal(repeatedQuarantine.commitment, quarantine.commitment)
  await expectReject(quarantineAdapter.prepare(structuredClone(quarantineRequest)), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_QUARANTINED'
  ], 'QUARANTINED_NO_CREATE is terminal and prepare cannot reopen it')
  await expectReject(quarantineAdapter.commitPublicBinding({
    ...structuredClone(captured.commitPublicBinding),
    transactionId: preparedReceipt.transactionId,
    planHash: quarantineRequest.planHash,
    attemptId: quarantineRequest.attemptId
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_QUARANTINED'],
  'terminal quarantine rejects public binding before inspecting its signing package')
  await expectReject(quarantineAdapter.finalizeSignedBootstrap({
    ...structuredClone(finalizationCaptured.finalizeSignedBootstrap),
    transactionId: preparedReceipt.transactionId,
    planHash: quarantineRequest.planHash,
    attemptId: quarantineRequest.attemptId
  }), ['PEERIT_SEQ29_LOCAL_CUSTODY_QUARANTINED'],
  'terminal quarantine rejects finalization before reading private bound state')
  const createOutcomeRequest = {
    ...structuredClone(quarantineRequest),
    planHash: 'ac'.repeat(32),
    attemptId: 'quarantine-create-outcome-attempt'
  }
  const createOutcomePrepared = await quarantineAdapter.prepare(createOutcomeRequest)
  await quarantineAdapter.quarantine({
    transactionId: createOutcomePrepared.transactionId,
    planHash: createOutcomeRequest.planHash,
    attemptId: createOutcomeRequest.attemptId,
    disposition: 'QUARANTINED_CREATE_OUTCOME'
  })
  await expectReject(quarantineAdapter.prepare(createOutcomeRequest), [
    'PEERIT_SEQ29_LOCAL_CUSTODY_QUARANTINED'
  ], 'QUARANTINED_CREATE_OUTCOME is terminal and prepare cannot reopen it')

  const seedPatterns = []
  for (let index = 0; index < 2; index++) {
    for (const role of ['create', 'renew', 'close']) {
      seedPatterns.push(fixtureSeed(`fixture-only-inbox-${role}-${index}`))
    }
  }
  const allLocalCustodyFiles = []
  for (const temporaryRoot of temporaryRoots) {
    allLocalCustodyFiles.push(...await regularFiles(temporaryRoot))
  }
  for (const file of allLocalCustodyFiles) {
    const bytes = await fs.readFile(file)
    for (const seed of seedPatterns) {
      assert.equal(findPattern(bytes, seed), false,
        `${path.basename(file)} contains no plaintext management seed`)
    }
  }
  for (const publicValue of [result, recoveredExecution, finalized]) {
    for (const seed of seedPatterns) {
      assert.equal(containsBytesDeep(publicValue, seed), false,
        'public ceremony results contain no private management seed')
    }
  }

  const source = await fs.readFile(new URL(
    '../scripts/lib/seq29-local-management-custody.mjs', import.meta.url), 'utf8')
  for (const forbidden of [
    'console.log(', 'console.error(', 'process.stdout', 'process.stderr',
    'fetch(', 'http://', 'https://', 'INBOX.RENEW', 'INBOX.CLOSE',
    'PeeritInboxManagementBundleV1', 'PeeritCustodyEnvelopeV1'
  ]) assert.equal(source.includes(forbidden), false, `source excludes ${forbidden}`)
  assert.ok(providerCalls >= 1, 'custodian key provider is used only for local recovery transitions')
  console.log('peerit seq29 local management custody tests: ok')
} finally {
  await Promise.all(temporaryRoots.map(root => fs.rm(root, { recursive: true, force: true })))
}
