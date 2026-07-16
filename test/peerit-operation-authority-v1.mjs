import assert from 'node:assert/strict'
import { canonical, expectedKeyV2 } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { seal } from '../js/seal.js'
import { memoryStorage } from '../js/sync.js'
import {
  PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
  PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATIONS,
  PEERIT_OPERATION_TYPES_V1,
  createPeeritInnerOperationBatchV1,
  decodePeeritInnerOperationBatchV1,
  hashPeeritInnerCellEncodingCommitmentV1,
  hashPeeritInnerLogicalHashV1,
  peeritOperationWireKeyV1
} from '../js/substrate/peerit-operation-authority-v1.js'

let passed = 0
async function test (name, operation) {
  await operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

function newIdentity (label) {
  return createIdentity({
    forceDev: true,
    lazy: true,
    storage: memoryStorage(),
    session: memoryStorage(),
    label
  })
}

async function activate (identity, label) {
  await identity.ready()
  await identity.ensureActive(label)
  return identity
}

async function signedRecord (identity, type, data) {
  const signature = await identity.sign(canonical(type, data))
  return {
    type,
    data: {
      ...data,
      _sig: signature.signature,
      _k: signature.publicKey,
      _dk: signature.driveKey,
      _ns: signature.namespace,
      _alg: signature.algorithm
    }
  }
}

async function signedProfile (identity, extra = {}) {
  const me = identity.me()
  return signedRecord(identity, 'profile', { id: me.pubkey, author: me.pubkey, ...extra })
}

async function signedV2Profile (identity, suffix = 'one', extra = {}) {
  const me = identity.me()
  const wireKey = await expectedKeyV2({ _t: 'profile', author: me.pubkey })
  return signedRecord(identity, 'v2', {
    id: wireKey.slice(3),
    _t: 'profile',
    sealed: await seal({ name: `opaque ${suffix}` }),
    ...extra
  })
}

async function signedOperation (identity, type = 'profile', suffix = 'one', extra = {}) {
  if (type === 'v2') return signedV2Profile(identity, suffix, extra)
  if (type === 'profile') return signedProfile(identity, extra)
  const me = identity.me()
  return signedRecord(identity, type, { id: me.pubkey, author: me.pubkey, ...extra })
}

function clone (value) {
  return structuredClone(value)
}

function rawEnvelope (payload) {
  const body = new TextEncoder().encode(payload)
  const bytes = new Uint8Array(7 + body.byteLength)
  bytes[0] = 1
  bytes[1] = 78
  bytes[2] = 1
  bytes[3] = (body.byteLength >>> 24) & 0xff
  bytes[4] = (body.byteLength >>> 16) & 0xff
  bytes[5] = (body.byteLength >>> 8) & 0xff
  bytes[6] = body.byteLength & 0xff
  bytes.set(body, 7)
  return bytes
}

await cryptoReady()
const alice = await activate(newIdentity('operation-authority-alice'), 'operation-authority-alice')
const bob = await activate(newIdentity('operation-authority-bob'), 'operation-authority-bob')

await test('valid V1 and V2 signed operations encode to one exact canonical tag-334 envelope', async () => {
  const v1 = await signedOperation(alice, 'profile', 'v1', { name: 'NFC café', omitted: undefined, list: [undefined, 'x'] })
  const v2 = await signedOperation(alice, 'v2', 'v2')
  const envelope = await createPeeritInnerOperationBatchV1([v1, v2], {
    expectedAuthorPublicKey: alice.me().pubkey
  })
  assert.equal(envelope.innerCodec, PEERIT_INNER_OPERATION_BATCH_V1_CODEC)
  assert.equal(envelope.innerBytes[0], 1)
  assert.equal(envelope.innerBytes[1], 78)
  assert.equal(envelope.innerBytes[2], 1)
  assert.equal(envelope.authorPublicKey, alice.me().pubkey)
  assert.equal(envelope.operations.length, 2)
  assert.equal(envelope.operations[0].data.omitted, undefined)
  assert.deepEqual(envelope.operations[0].data.list, [null, 'x'])
  assert.deepEqual(envelope.operationWireKeys, [
    peeritOperationWireKeyV1(v1),
    peeritOperationWireKeyV1(v2)
  ])

  const decoded = await decodePeeritInnerOperationBatchV1(envelope.innerCodec, envelope.innerBytes, {
    expectedAuthorPublicKey: alice.me().pubkey
  })
  assert.equal(decoded.canonicalOperationBatch, envelope.canonicalOperationBatch)
  assert.deepEqual(decoded.operations, envelope.operations)
  assert.deepEqual(decoded.logicalHash, envelope.logicalHash)
  assert.deepEqual(decoded.encodingCommitment, envelope.encodingCommitment)
  assert.equal(decoded.sizeClass, envelope.sizeClass)
})

await test('logical and Cell encoding commitments reproduce only exact envelope bytes and smallest size class', async () => {
  const operation = await signedOperation(alice, 'profile', 'commitment')
  const envelope = await createPeeritInnerOperationBatchV1([operation])
  assert.deepEqual(
    hashPeeritInnerLogicalHashV1(envelope.innerCodec, envelope.innerBytes),
    envelope.logicalHash
  )
  assert.deepEqual(
    hashPeeritInnerCellEncodingCommitmentV1(
      envelope.innerCodec,
      envelope.innerBytes,
      envelope.logicalHash,
      envelope.sizeClass
    ),
    envelope.encodingCommitment
  )
  assert.throws(
    () => hashPeeritInnerCellEncodingCommitmentV1(
      envelope.innerCodec,
      envelope.innerBytes,
      envelope.logicalHash,
      envelope.sizeClass + 1
    ),
    error => error.code === 'PEERIT_OPERATION_ENVELOPE_COMMITMENT'
  )
})

await test('a batch crossing the 4 KiB Cell boundary selects class two deterministically', async () => {
  const operation = await signedOperation(alice, 'profile', 'size-two', { note: 'x'.repeat(5000) })
  const envelope = await createPeeritInnerOperationBatchV1([operation])
  assert.ok(envelope.innerLength > 4063n)
  assert.equal(envelope.sizeClass, 2)
})

await test('legacy finite negative zero is normalized to canonical JSON zero without changing its valid signature', async () => {
  const operation = await signedOperation(alice, 'profile', 'negative-zero', { score: -0 })
  const envelope = await createPeeritInnerOperationBatchV1([operation])
  assert.match(envelope.canonicalOperationBatch, /"score":0/)
  assert.equal(Object.is(envelope.operations[0].data.score, -0), false)
})

await test('valid pre-existing NFD user content remains signed, exact, and round-trippable', async () => {
  const nfd = 'cafe\u0301'
  assert.notEqual(nfd, nfd.normalize('NFC'))
  const operation = await signedProfile(alice, { name: nfd })
  const envelope = await createPeeritInnerOperationBatchV1([operation])
  const decoded = await decodePeeritInnerOperationBatchV1(envelope.innerCodec, envelope.innerBytes)
  assert.equal(decoded.operations[0].data.name, nfd)
  assert.equal(envelope.canonicalOperationBatch.includes(nfd), true)
})

await test('signed V1 and V2 records cannot select a different storage slot', async () => {
  const wrongV1 = await signedProfile(alice, { id: 'f'.repeat(64) })
  assert.notEqual(wrongV1.data.id, alice.me().pubkey)
  await assert.rejects(
    createPeeritInnerOperationBatchV1([wrongV1]),
    error => error.code === 'PEERIT_OPERATION_BATCH_KEY_BINDING'
  )

  const wrongV2 = await signedRecord(alice, 'v2', {
    id: '0'.repeat(64),
    _t: 'profile',
    sealed: await seal({ name: 'wrong opaque slot' })
  })
  await assert.rejects(
    createPeeritInnerOperationBatchV1([wrongV2]),
    error => error.code === 'PEERIT_OPERATION_BATCH_KEY_BINDING'
  )

  const validV2 = await signedV2Profile(alice, 'malformed-sealed')
  const malformedV2 = await signedRecord(alice, 'v2', {
    ...validV2.data,
    sealed: { v: 1, iv: '00', ct: 'not-a-cell' }
  })
  await assert.rejects(
    createPeeritInnerOperationBatchV1([malformedV2]),
    error => error.code === 'PEERIT_OPERATION_BATCH_KEY_BINDING'
  )
})

await test('record-key and canonical resource bounds reject before a journal transaction can latch', async () => {
  const actionId = 'x'.repeat(4096)
  const me = alice.me()
  const oversizedKey = await signedRecord(alice, 'modaction', {
    id: `community!${actionId}`,
    community: 'community',
    actionId,
    by: me.pubkey
  })
  await assert.rejects(
    createPeeritInnerOperationBatchV1([oversizedKey]),
    error => error.code === 'PEERIT_OPERATION_BATCH_KEY_BOUND'
  )
  const profile = await signedProfile(alice)
  await assert.rejects(
    createPeeritInnerOperationBatchV1([profile], { maxRecordKeyBytes: 64 }),
    error => error.code === 'PEERIT_OPERATION_BATCH_KEY_BOUND'
  )
  let nested = 'leaf'
  for (let index = 0; index <= 64; index++) nested = { nested }
  const tooDeep = await signedProfile(alice, { nested })
  await assert.rejects(
    createPeeritInnerOperationBatchV1([tooDeep]),
    error => error.code === 'PEERIT_OPERATION_BATCH_RESOURCE_LIMIT'
  )
})

await test('mixed authors, duplicate local keys, and oversized batches reject before any envelope exists', async () => {
  const aliceOperation = await signedOperation(alice, 'profile', 'same')
  const bobOperation = await signedOperation(bob, 'profile', 'other')
  await assert.rejects(
    createPeeritInnerOperationBatchV1([aliceOperation, bobOperation]),
    error => error.code === 'PEERIT_OPERATION_BATCH_MIXED_AUTHOR'
  )
  await assert.rejects(
    createPeeritInnerOperationBatchV1([aliceOperation, clone(aliceOperation)]),
    error => error.code === 'PEERIT_OPERATION_BATCH_DUPLICATE_VIEW_KEY'
  )
  await assert.rejects(
    createPeeritInnerOperationBatchV1(new Array(PEERIT_INNER_OPERATION_BATCH_V1_MAX_OPERATIONS + 1).fill(aliceOperation)),
    error => error.code === 'PEERIT_OPERATION_BATCH_BAD_INPUT'
  )
})

await test('closed operation types and exact lowercase Peerit signature metadata are enforced before verification', async () => {
  assert.equal(PEERIT_OPERATION_TYPES_V1.includes('head'), false)
  assert.equal(PEERIT_OPERATION_TYPES_V1.includes('shard'), false)
  const v1 = await signedOperation(alice, 'profile', 'metadata')
  const uppercase = clone(v1)
  uppercase.data._k = uppercase.data._k.toUpperCase()
  await assert.rejects(
    createPeeritInnerOperationBatchV1([uppercase]),
    error => error.code === 'PEERIT_OPERATION_BATCH_METADATA'
  )
  const internal = await signedOperation(alice, 'head', 'internal')
  await assert.rejects(
    createPeeritInnerOperationBatchV1([internal]),
    error => error.code === 'PEERIT_OPERATION_BATCH_UNSUPPORTED_TYPE'
  )
  const badV2 = await signedOperation(alice, 'v2', 'bad-v2')
  badV2.data._t = 'not-an-app-type'
  await assert.rejects(
    createPeeritInnerOperationBatchV1([badV2]),
    error => error.code === 'PEERIT_OPERATION_BATCH_UNSUPPORTED_TYPE'
  )
})

await test('tampering a signed operation, raw framing, UTF-8, or canonical JSON is fail-closed', async () => {
  const operation = await signedOperation(alice, 'profile', 'tamper')
  const envelope = await createPeeritInnerOperationBatchV1([operation])
  const tamperedOperation = clone(operation)
  tamperedOperation.data.id += '-tampered'
  await assert.rejects(
    createPeeritInnerOperationBatchV1([tamperedOperation]),
    error => error.code === 'PEERIT_OPERATION_BATCH_SIGNATURE'
  )

  const badTag = envelope.innerBytes
  badTag[0] ^= 1
  await assert.rejects(
    decodePeeritInnerOperationBatchV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, badTag),
    error => error.code === 'PEERIT_OPERATION_ENVELOPE_CODEC'
  )
  const badLength = envelope.innerBytes
  badLength[6] ^= 1
  await assert.rejects(
    decodePeeritInnerOperationBatchV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, badLength),
    error => error.code === 'PEERIT_OPERATION_ENVELOPE_LENGTH'
  )
  await assert.rejects(
    decodePeeritInnerOperationBatchV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC,
      Uint8Array.of(1, 78, 1, 0, 0, 0, 1, 0x94)),
    error => error.code === 'PEERIT_OPERATION_ENVELOPE_UTF8'
  )
  const whitespace = rawEnvelope(envelope.canonicalOperationBatch.replace('{', '{ '))
  await assert.rejects(
    decodePeeritInnerOperationBatchV1(PEERIT_INNER_OPERATION_BATCH_V1_CODEC, whitespace),
    error => error.code === 'PEERIT_OPERATION_BATCH_NONCANONICAL'
  )
})

await test('returned envelope bytes and commitments are defensive copies while operation input is snapshotted', async () => {
  const operation = await signedOperation(alice, 'profile', 'snapshot', { title: 'before' })
  const envelope = await createPeeritInnerOperationBatchV1([operation])
  operation.data.title = 'after'
  assert.equal(envelope.operations[0].data.title, 'before')
  const bytes = envelope.innerBytes
  bytes[0] ^= 1
  const logicalHash = envelope.logicalHash
  logicalHash[0] ^= 1
  const decoded = await decodePeeritInnerOperationBatchV1(envelope.innerCodec, envelope.innerBytes)
  assert.equal(decoded.operations[0].data.title, 'before')
  assert.notEqual(logicalHash[0], envelope.logicalHash[0])
})

process.stdout.write(`peerit operation authority V1 tests: ${passed}/11 passed\n`)
