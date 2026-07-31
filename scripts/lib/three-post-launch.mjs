// Local orchestration for the owner-approved r/ai_local launch slice.
//
// This module performs no discovery or network I/O. Callers must inject two
// currently-qualified, branded relay adapters. Exact authored envelopes and
// Cell preparation material are persisted in the encrypted publisher vault
// before a send boundary is crossed. Once that boundary may have been crossed,
// automatic recovery is GET-only.

import { createHash } from 'node:crypto'

import { canonical, expectedKeyV2 } from '../../js/canon.js'
import { TYPE, CONTENT_PROTOCOL, contentId } from '../../js/model.js'
import { MIN_BITS, mint } from '../../js/pow.js'
import { seal } from '../../js/seal.js'
import { normalizeSlug, isValidSlug } from '../../js/util.js'
import {
  createPeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from '../../js/substrate/peerit-operation-authority-v1.js'
import {
  isPeeritVerifiedRelayAdapter,
  verifiedPeeritRelayCellGetContext
} from '../../js/substrate/relay-consumer.js'
import {
  PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
  PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
  PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1,
  hashPeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '../../js/substrate/seed-bootstrap-v1.mjs'

export const PEERIT_THREE_POST_SCOPE_SCHEMA_V1 = 'peerit-three-post-scope-v1'
export const PEERIT_THREE_POST_RELAY_TUPLE_SCHEMA_V1 = 'peerit-qualified-relay-tuple-v1'
export const PEERIT_THREE_POST_RECORD_MATERIAL_SCHEMA_V1 = 'peerit-three-post-record-material-v1'
export const PEERIT_THREE_POST_MANIFEST_SHA256 =
  '36c15537d9e853cfb599cf59568a067e573a87c8de858183e332dfd3eb9192c0'

export const PEERIT_THREE_POST_SCOPE_V1 = Object.freeze({
  schema: PEERIT_THREE_POST_SCOPE_SCHEMA_V1,
  board: 'ai_local',
  communityCount: 1,
  postCount: 3,
  posts: Object.freeze([
    Object.freeze({
      order: 1,
      seed: 'v1-seed-ai_local-1',
      cid: 'f68ae14dcd4fb0764b0c5669a03ebb7d68993b7cddc31f1552b85c2cba67536f',
      title: 'r/ai_local — numbers over vibes'
    }),
    Object.freeze({
      order: 2,
      seed: 'v1-seed-ai_local-2',
      cid: 'fc80b076becb28c9fbda596def255246cd506fc5ed4e5f4d22499c5cdad95f1b',
      title: 'Running gpt-oss-120b (117B params) at 85.60 tok/s on a desktop — and it beat a DGX Spark'
    }),
    Object.freeze({
      order: 3,
      seed: 'v1-seed-ai_local-3',
      cid: '52f99d16c0ab47bdad025cbd4138549802e552d55835435588887e7ca178e3a6',
      title: "Different stack, different numbers: Qwen3 on QVAC (Tether's on-device SDK) vs raw llama.cpp"
    })
  ])
})

const HEX32 = /^[0-9a-f]{64}$/
const V2_CLEAR = new Set(['createdAt', 'ts', 'editedAt', 'deleted', 'slug'])
const V2_DROP = new Set(['id', '_t', 'author', 'creator', 'by', 'pow', '_sig', '_k', '_dk', '_ns', '_alg'])

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function plain (value, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('PEERIT_THREE_POST_BAD_INPUT', `${field} must be an object`)
  }
  return value
}

function text (value, field, maximum = 4096) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum ||
      value.includes('\0') || value !== value.normalize('NFC')) {
    fail('PEERIT_THREE_POST_BAD_INPUT', `${field} must be bounded nonempty NFC text`)
  }
  return value
}

function hex32 (value, field) {
  if (!HEX32.test(String(value || ''))) {
    fail('PEERIT_THREE_POST_BAD_INPUT', `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function bytes (value, field, length = null) {
  let output
  if (value instanceof Uint8Array) output = new Uint8Array(value)
  else if (value instanceof ArrayBuffer) output = new Uint8Array(value.slice(0))
  else if (ArrayBuffer.isView(value)) {
    output = new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength))
  } else fail('PEERIT_THREE_POST_BAD_INPUT', `${field} must be bytes`)
  if (length != null && output.byteLength !== length) {
    fail('PEERIT_THREE_POST_BAD_INPUT', `${field} must be ${length} bytes`)
  }
  return output
}

function hex (value, field = 'bytes') {
  return Buffer.from(bytes(value, field)).toString('hex')
}

function fromHex (value, field) {
  return new Uint8Array(Buffer.from(hex32(value, field), 'hex'))
}

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`
}

export function sha256Hex (value) {
  return createHash('sha256').update(value).digest('hex')
}

function manifestPublicKey (personas, persona) {
  const entry = plain(plain(personas, 'persona directory').personas, 'persona directory.personas')[persona]
  if (!entry) fail('PEERIT_THREE_POST_PERSONA_MISSING', `persona ${persona} is unavailable`)
  return hex32(entry.pubkeyHex, `persona ${persona} public key`)
}

function assertScope (scope) {
  plain(scope, 'three-post scope')
  if (scope.schema !== PEERIT_THREE_POST_SCOPE_SCHEMA_V1 || scope.communityCount !== 1 ||
      scope.postCount !== 3 || !Array.isArray(scope.posts) || scope.posts.length !== 3) {
    fail('PEERIT_THREE_POST_SCOPE_MISMATCH', 'scope must select exactly one community claim and three posts')
  }
  text(scope.board, 'scope.board', 24)
  return scope
}

export async function selectThreePostWaveZeroV1 ({
  manifest,
  manifestSha256,
  personas,
  scope = PEERIT_THREE_POST_SCOPE_V1,
  expectedManifestSha256 = PEERIT_THREE_POST_MANIFEST_SHA256
}) {
  scope = assertScope(scope)
  plain(manifest, 'manifest')
  hex32(manifestSha256, 'manifestSha256')
  if (expectedManifestSha256 != null && manifestSha256 !== hex32(expectedManifestSha256, 'expectedManifestSha256')) {
    fail('PEERIT_THREE_POST_MANIFEST_MISMATCH', 'seed manifest does not match the owner-approved custody hash')
  }
  const boards = (manifest.boards || []).filter(row => row && row.slug === scope.board)
  const posts = (manifest.posts || []).filter(row => row && row.board === scope.board)
    .sort((left, right) => left.order - right.order)
  if (boards.length !== 1 || posts.length !== 3) {
    fail('PEERIT_THREE_POST_SCOPE_MISMATCH', 'manifest selection is not exactly one claim and three OPs')
  }
  const board = boards[0]
  const items = [{
    kind: 'community',
    board: scope.board,
    persona: text(board.claimPersona, 'board.claimPersona', 128),
    boardTitle: text(board.title, 'board.title', 100),
    description: typeof board.description === 'string' ? board.description : ''
  }]
  for (let index = 0; index < scope.posts.length; index++) {
    const expected = scope.posts[index]
    const post = posts[index]
    if (!post || post.order !== expected.order || post.seed !== expected.seed || post.title !== expected.title) {
      fail('PEERIT_THREE_POST_SCOPE_MISMATCH', `ai_local post ${index + 1} does not match the approved seed/title/order`)
    }
    const persona = text(post.opPersona, `post ${index + 1}.opPersona`, 128)
    const publicKey = manifestPublicKey(personas, persona)
    const cid = await contentId(TYPE.POST, publicKey, post.seed)
    if (cid !== expected.cid) {
      fail('PEERIT_THREE_POST_CID_MISMATCH', `ai_local post ${index + 1} does not reproduce its approved CID`)
    }
    items.push({
      kind: 'post',
      board: scope.board,
      order: post.order,
      persona,
      title: post.title,
      body: String(post.bodyText || ''),
      seed: post.seed,
      cid,
      expectedCid: expected.cid
    })
  }
  manifestPublicKey(personas, board.claimPersona)
  return Object.freeze({
    schema: PEERIT_THREE_POST_SCOPE_SCHEMA_V1,
    manifestSha256,
    board: scope.board,
    expectedCids: Object.freeze(scope.posts.map(row => row.cid)),
    items: Object.freeze(items.map(Object.freeze))
  })
}

async function toV2Stored (semanticType, logical) {
  const wireKey = await expectedKeyV2({ ...logical, _t: semanticType })
  if (!wireKey) fail('PEERIT_THREE_POST_COMPOSITION_FAILED', `cannot derive ${semanticType} v2 key`)
  const clear = {}
  const graph = {}
  for (const [key, value] of Object.entries(logical)) {
    if (value === undefined || V2_DROP.has(key)) continue
    if (V2_CLEAR.has(key)) clear[key] = value
    else graph[key] = value
  }
  return {
    wireKey,
    stored: { id: wireKey.slice(3), _t: semanticType, ...clear, sealed: await seal(graph) }
  }
}

async function composeV2Operation (semanticType, logical, identity) {
  const { wireKey, stored } = await toV2Stored(semanticType, logical)
  stored.pow = await mint(semanticType, stored, MIN_BITS[semanticType] || 0)
  const signature = await identity.sign(canonical('v2', stored))
  Object.assign(stored, {
    _sig: signature.signature,
    _k: signature.publicKey,
    _dk: signature.driveKey,
    _ns: signature.namespace,
    _alg: signature.algorithm
  })
  return { wireKey, operation: { type: 'v2', data: stored } }
}

function communityLogical (item, publicKey, now) {
  const slug = normalizeSlug(item.board)
  if (!isValidSlug(slug)) fail('PEERIT_THREE_POST_COMPOSITION_FAILED', 'community slug is invalid')
  return {
    id: slug,
    slug,
    title: item.boardTitle.slice(0, 100),
    description: item.description.slice(0, 500),
    rules: [],
    creator: publicKey,
    createdAt: now,
    updatedAt: now,
    author: publicKey
  }
}

function postLogical (item, publicKey, now) {
  return {
    id: `${item.board}!${item.cid}`,
    cid: item.cid,
    community: item.board,
    kind: 'text',
    protocol: CONTENT_PROTOCOL,
    contentNonce: item.seed,
    title: item.title.trim().slice(0, 300),
    body: item.body.slice(0, 40000),
    url: '',
    author: publicKey,
    createdAt: now,
    editedAt: 0,
    deleted: false
  }
}

async function publicationFor (operation, authorPublicKey) {
  const envelope = await createPeeritInnerOperationBatchV1([operation], {
    expectedAuthorPublicKey: authorPublicKey
  })
  const innerBytes = new Uint8Array(envelope.innerBytes)
  return {
    intentId: hex(hashPeeritInnerOperationIntentIdV1(envelope.innerCodec, innerBytes)),
    logicalId: hex(envelope.logicalHash),
    innerCodec: envelope.innerCodec,
    innerBytes,
    innerLength: Number(envelope.innerLength),
    sizeClass: envelope.sizeClass,
    logicalHash: new Uint8Array(envelope.logicalHash),
    encodingCommitment: new Uint8Array(envelope.encodingCommitment),
    authorPublicKey: envelope.authorPublicKey,
    wireKeys: [...envelope.operationWireKeys].sort()
  }
}

function identityPublicKey (identity, persona) {
  const value = identity && typeof identity.me === 'function' ? identity.me().pubkey : null
  return hex32(value, `identity ${persona} public key`)
}

export async function composeThreePostPlanV1 ({ selection, personas, identityFor, now = Date.now() }) {
  if (!selection || selection.schema !== PEERIT_THREE_POST_SCOPE_SCHEMA_V1 ||
      !Array.isArray(selection.items) || selection.items.length !== 4) {
    fail('PEERIT_THREE_POST_SCOPE_MISMATCH', 'an exact three-post wave-zero selection is required')
  }
  if (typeof identityFor !== 'function') {
    fail('PEERIT_THREE_POST_BAD_INPUT', 'identityFor must restore process-local signers')
  }
  if (!Number.isSafeInteger(now) || now < 0) fail('PEERIT_THREE_POST_BAD_INPUT', 'composition time is invalid')
  const records = []
  for (const item of selection.items) {
    const identity = await identityFor(item.persona)
    const publicKey = identityPublicKey(identity, item.persona)
    if (publicKey !== manifestPublicKey(personas, item.persona)) {
      fail('PEERIT_THREE_POST_PERSONA_MISMATCH', `identity ${item.persona} does not match its manifest public key`)
    }
    const semanticType = item.kind === 'community' ? TYPE.COMMUNITY : TYPE.POST
    const logical = item.kind === 'community'
      ? communityLogical(item, publicKey, now)
      : postLogical(item, publicKey, now)
    const { operation } = await composeV2Operation(semanticType, logical, identity)
    const publication = await publicationFor(operation, publicKey)
    records.push(Object.freeze({
      recordId: publication.intentId,
      kind: item.kind,
      board: item.board,
      order: item.order == null ? 0 : item.order,
      cid: item.cid || null,
      publication: Object.freeze(publication)
    }))
  }
  if (new Set(records.map(row => row.recordId)).size !== 4) {
    fail('PEERIT_THREE_POST_COMPOSITION_FAILED', 'the four authored envelopes do not have unique intent ids')
  }
  return Object.freeze({
    schema: PEERIT_THREE_POST_SCOPE_SCHEMA_V1,
    manifestSha256: selection.manifestSha256,
    board: selection.board,
    expectedCids: selection.expectedCids,
    records: Object.freeze(records)
  })
}

function materialForRecord (record) {
  return {
    schema: PEERIT_THREE_POST_RECORD_MATERIAL_SCHEMA_V1,
    version: 1,
    kind: record.kind,
    board: record.board,
    order: record.order,
    cid: record.cid,
    publication: record.publication
  }
}

function recordFromMaterial (recordId, material) {
  plain(material, `record ${recordId} material`)
  if (material.schema !== PEERIT_THREE_POST_RECORD_MATERIAL_SCHEMA_V1 || material.version !== 1 ||
      !material.publication || material.publication.intentId !== recordId) {
    fail('PEERIT_THREE_POST_RECORD_MATERIAL_INVALID', `record ${recordId} durable material is invalid`)
  }
  return Object.freeze({
    recordId,
    kind: material.kind,
    board: material.board,
    order: material.order,
    cid: material.cid,
    publication: Object.freeze(material.publication)
  })
}

export async function persistThreePostPlanV1 (vault, plan, relayIds) {
  if (!vault || typeof vault.bindPlan !== 'function' || !plan || !Array.isArray(plan.records)) {
    fail('PEERIT_THREE_POST_BAD_INPUT', 'publisher vault and composed plan are required')
  }
  const plannedRelays = [...new Set(relayIds.map(String))].sort()
  if (plannedRelays.length !== 2) fail('PEERIT_THREE_POST_RELAY_FLOOR', 'exactly two relay ids are required')
  return vault.bindPlan({
    manifestSha256: plan.manifestSha256,
    records: plan.records.map(record => ({
      recordId: record.recordId,
      plannedRelays,
      recordMaterial: materialForRecord(record)
    }))
  })
}

export async function recoverThreePostPlanV1 (vault, options = {}) {
  const receipts = await vault.sanitizedReceiptManifest()
  const expectedManifestSha256 = options.expectedManifestSha256 || PEERIT_THREE_POST_MANIFEST_SHA256
  if (receipts.manifestSha256 !== expectedManifestSha256 || receipts.records.length !== 4) {
    fail('PEERIT_THREE_POST_PLAN_RECOVERY_FAILED', 'vault is not bound to the exact four-record three-post plan')
  }
  const records = []
  for (const receipt of receipts.records) {
    records.push(recordFromMaterial(receipt.recordId, await vault.loadRecordMaterial(receipt.recordId)))
  }
  const posts = records.filter(record => record.kind === 'post').sort((left, right) => left.order - right.order)
  const expectedCids = options.expectedCids || PEERIT_THREE_POST_SCOPE_V1.posts.map(row => row.cid)
  if (records.filter(record => record.kind === 'community').length !== 1 || posts.length !== 3 ||
      posts.some((record, index) => record.cid !== expectedCids[index])) {
    fail('PEERIT_THREE_POST_PLAN_RECOVERY_FAILED', 'durable plan is not the approved claim plus three CIDs')
  }
  return Object.freeze({
    schema: PEERIT_THREE_POST_SCOPE_SCHEMA_V1,
    manifestSha256: receipts.manifestSha256,
    board: posts[0].board,
    expectedCids: Object.freeze([...expectedCids]),
    records: Object.freeze(records)
  })
}

function tupleRelay (row, index) {
  plain(row, `relay tuple[${index}]`)
  const url = new URL(text(row.canonicalDescribeUrl, `relay tuple[${index}].canonicalDescribeUrl`))
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
      url.pathname !== '/api/blind/v1/describe') {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'relay tuple requires an exact Blind HTTPS describe URL')
  }
  const integer = (value, field) => {
    if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff) {
      fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', `${field} is invalid`)
    }
    return value
  }
  if (!Number.isSafeInteger(row.descriptorSequence) || row.descriptorSequence < 0) {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'descriptorSequence is invalid')
  }
  return {
    relayId: text(row.relayId, `relay tuple[${index}].relayId`, 128),
    canonicalDescribeUrl: url.href,
    continuityRootRelayPublicKey: hex32(row.continuityRootRelayPublicKey, 'continuityRootRelayPublicKey'),
    storeId: hex32(row.storeId, 'storeId'),
    descriptorGenesisHash: hex32(row.descriptorGenesisHash, 'descriptorGenesisHash'),
    descriptorHeadHash: hex32(row.descriptorHeadHash, 'descriptorHeadHash'),
    descriptorSequence: row.descriptorSequence,
    familyId: integer(row.familyId, 'familyId'),
    operationId: integer(row.operationId, 'operationId'),
    endpointId: integer(row.endpointId, 'endpointId'),
    transportId: integer(row.transportId, 'transportId'),
    transportSupportBit: integer(row.transportSupportBit, 'transportSupportBit'),
    privacyProfileBit: integer(row.privacyProfileBit, 'privacyProfileBit')
  }
}

export function validateCurrentRelayTupleV1 (input) {
  plain(input, 'relay tuple')
  if (input.schema !== PEERIT_THREE_POST_RELAY_TUPLE_SCHEMA_V1 ||
      !Array.isArray(input.relays) || input.relays.length !== 2) {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'exactly two qualified relay tuples are required')
  }
  const relays = input.relays.map(tupleRelay).sort((left, right) => left.relayId.localeCompare(right.relayId))
  if (new Set(relays.map(row => row.relayId)).size !== 2 ||
      new Set(relays.map(row => row.continuityRootRelayPublicKey)).size !== 2) {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'relay ids and continuity roots must be distinct')
  }
  const payload = { schema: PEERIT_THREE_POST_RELAY_TUPLE_SCHEMA_V1, relays }
  return Object.freeze({ ...payload, tupleSha256: sha256Hex(Buffer.from(stable(payload))) })
}

export function bindCurrentRelayTupleV1 (entries) {
  if (!Array.isArray(entries) || entries.length !== 2) {
    fail('PEERIT_THREE_POST_RELAY_FLOOR', 'exactly two currently qualified relay adapters are required')
  }
  const relays = entries.map((entry, index) => {
    plain(entry, `qualified relay[${index}]`)
    if (!isPeeritVerifiedRelayAdapter(entry.adapter)) {
      fail('PEERIT_THREE_POST_RELAY_UNVERIFIED', `${entry.relayId || index} is not a branded qualified relay adapter`)
    }
    const context = verifiedPeeritRelayCellGetContext(entry.adapter)
    const sequence = Number(context.descriptorSequence)
    if (!Number.isSafeInteger(sequence)) {
      fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'descriptor sequence exceeds the bootstrap integer bound')
    }
    return {
      relayId: text(entry.relayId, `qualified relay[${index}].relayId`, 128),
      canonicalDescribeUrl: context.canonicalDescribeUrl,
      continuityRootRelayPublicKey: context.continuityRootRelayPublicKey,
      storeId: context.storeId,
      descriptorGenesisHash: context.descriptorGenesisHash,
      descriptorHeadHash: context.descriptorHeadHash,
      descriptorSequence: sequence,
      familyId: context.familyId,
      operationId: context.operationId,
      endpointId: context.endpointId,
      transportId: context.transportId,
      transportSupportBit: context.transportSupportBit,
      privacyProfileBit: context.privacyProfileBit
    }
  })
  return validateCurrentRelayTupleV1({ schema: PEERIT_THREE_POST_RELAY_TUPLE_SCHEMA_V1, relays })
}

function bindingMap (tuple) {
  const verified = validateCurrentRelayTupleV1(tuple)
  return new Map(verified.relays.map(row => [row.relayId, row]))
}

function relayIdForContext (bindings, input) {
  const root = typeof input.targetContext.relayPublicKey === 'string'
    ? input.targetContext.relayPublicKey
    : hex(input.prepared.readCap.relayPublicKey)
  const matches = [...bindings.values()].filter(row => row.continuityRootRelayPublicKey === root)
  if (matches.length !== 1) fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'prepared replica does not match one relay root')
  return matches[0].relayId
}

function attemptIdForPrepared (prepared) {
  return hex(bytes(prepared.requestCommitment, 'prepared.requestCommitment', 32))
}

function assertPublicationMatch (input, material) {
  const publication = material.publication
  for (const field of ['intentId', 'logicalId', 'innerCodec', 'innerLength', 'sizeClass']) {
    if (input[field] !== publication[field]) {
      fail('PEERIT_THREE_POST_RECORD_MATERIAL_INVALID', `prepared replica ${field} does not match durable authored material`)
    }
  }
  if (hex(input.logicalHash) !== hex(publication.logicalHash) ||
      hex(input.encodingCommitment) !== hex(publication.encodingCommitment)) {
    fail('PEERIT_THREE_POST_RECORD_MATERIAL_INVALID', 'prepared replica commitments do not match durable authored material')
  }
  return publication
}

export function createThreePostVaultBridgeV1 ({ vault, relayTuple, now = Date.now }) {
  if (!vault || typeof vault.preparePutAttempt !== 'function' || typeof vault.loadPreparedAttempt !== 'function') {
    fail('PEERIT_THREE_POST_BAD_INPUT', 'encrypted publisher vault is required')
  }
  const bindings = bindingMap(relayTuple)
  const clock = typeof now === 'function' ? now : Date.now

  async function persistPreparedReplica (input) {
    plain(input, 'prepared replica')
    const material = await vault.loadRecordMaterial(input.intentId)
    const publication = assertPublicationMatch(input, material)
    const relayId = relayIdForContext(bindings, input)
    const prepared = plain(input.prepared, 'prepared replica.prepared')
    const clientNonce = bytes(plain(prepared.request, 'prepared.request').clientNonce, 'prepared.request.clientNonce', 32)
    return vault.preparePutAttempt({
      recordId: input.intentId,
      relayId,
      attemptId: attemptIdForPrepared(prepared),
      preparedAt: clock(),
      requestBytes: bytes(prepared.requestBytes, 'prepared.requestBytes'),
      requestCommitment: bytes(prepared.requestCommitment, 'prepared.requestCommitment', 32),
      clientNonce,
      targetContext: {
        targetId: text(input.targetId, 'prepared targetId'),
        write: plain(input.targetContext, 'prepared targetContext'),
        read: plain(input.readTargetContext, 'prepared readTargetContext'),
        publicationIntentId: publication.intentId
      },
      readerCapability: plain(prepared.readCap, 'prepared.readCap'),
      managementCapability: {
        schema: 'peerit-three-post-prepared-cell-v1',
        prepared
      }
    })
  }

  async function loadPersistedReplica (intentId, targetId) {
    for (const relayId of bindings.keys()) {
      let attempt
      try { attempt = await vault.loadPreparedAttempt(intentId, relayId) } catch (error) {
        if (error && error.code === 'PEERIT_SEED_VAULT_PREPARED_MISSING') continue
        throw error
      }
      if (attempt.targetContext.targetId !== targetId) continue
      const material = await vault.loadRecordMaterial(intentId)
      const publication = material.publication
      const stage = attempt.stage === 'response-verified' ? 2 : attempt.stage === 'readback-verified' ? 3 : 1
      return {
        stage: stage === 1 ? 'prepared' : stage === 2 ? 'verified' : 'readback-verified',
        revision: 1,
        evidenceRef: attempt.responseEvidenceRef,
        payload: {
          version: 1,
          stage,
          intentId: publication.intentId,
          logicalId: publication.logicalId,
          innerCodec: publication.innerCodec,
          innerLength: publication.innerLength,
          sizeClass: publication.sizeClass,
          logicalHash: publication.logicalHash,
          encodingCommitment: publication.encodingCommitment,
          targetId,
          targetContext: attempt.targetContext.write,
          readTargetContext: attempt.targetContext.read,
          prepared: attempt.managementCapability.prepared,
          readCapability: attempt.readerCapability
        }
      }
    }
    return null
  }

  async function persistVerifiedResult (input) {
    const relayId = relayIdForContext(bindings, input)
    const resultHash = sha256Hex(Buffer.from(bytes(input.resultBytes, 'verified resultBytes')))
    const attemptId = attemptIdForPrepared(input.prepared)
    await vault.recordPutResponseVerified({
      recordId: input.intentId,
      relayId,
      attemptId,
      verifiedAt: clock(),
      evidenceRef: `blind-cell-put:${resultHash}`,
      resultHash
    })
    return { evidenceRef: `blind-cell-put:${resultHash}`, revision: 2 }
  }

  async function persistVerifiedReadback (input) {
    const relayId = relayIdForContext(bindings, input)
    const readbackHash = sha256Hex(Buffer.from(bytes(input.readbackInnerBytes, 'readback innerBytes')))
    const evidenceRef = `blind-cell-get:${hex(bytes(input.readbackRequestCommitment, 'readback request commitment', 32))}`
    const verifiedAt = clock()
    await vault.recordVerifiedReplica({
      recordId: input.intentId,
      relayId,
      attemptId: attemptIdForPrepared(input.prepared),
      verifiedAt,
      evidenceRef,
      readbackHash
    })
    return { evidenceRef, revision: Math.max(1, verifiedAt) }
  }

  return Object.freeze({
    persistPreparedReplica,
    persistVerifiedResult,
    persistVerifiedReadback,
    loadPersistedReplica
  })
}

function relayEntryMap (entries) {
  const map = new Map()
  for (const entry of entries) {
    if (map.has(entry.relayId)) fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'duplicate relay entry')
    map.set(entry.relayId, entry.adapter)
  }
  return map
}

function materialPublication (material) {
  return recordFromMaterial(material.publication.intentId, material).publication
}

export async function publishThreePostPlanV1 ({ vault, plan, relays, relayTuple = null }) {
  const rebound = bindCurrentRelayTupleV1(relays)
  const tuple = relayTuple == null ? rebound : validateCurrentRelayTupleV1(relayTuple)
  if (tuple.tupleSha256 !== rebound.tupleSha256) {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'branded relay adapters do not reproduce the supplied current tuple')
  }
  const adapters = relayEntryMap(relays)
  if (tuple.relays.some(row => !adapters.has(row.relayId))) {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_INVALID', 'relay adapters do not match the bound tuple ids')
  }
  await persistThreePostPlanV1(vault, plan, tuple.relays.map(row => row.relayId))

  // Finish every local preparation first. The vault already holds all four
  // exact authored envelopes, and each successful prepare callback adds the
  // exact request/capabilities before any send below is permitted.
  for (const record of plan.records) {
    const state = (await vault.resumePlan([record.recordId]))[0]
    for (const action of state.actions) {
      if (action.action === 'prepare-put') {
        const adapter = adapters.get(action.relayId)
        if (!adapter || typeof adapter.prepare !== 'function') {
          fail('PEERIT_THREE_POST_RELAY_UNVERIFIED', `${action.relayId} has no split prepare operation`)
        }
        await adapter.prepare(record.publication)
      } else if (action.action === 'legacy-ambiguous-manual-recovery') {
        fail('PEERIT_THREE_POST_LEGACY_AMBIGUOUS', 'legacy publisher state cannot be automatically recovered')
      }
    }
  }

  let networkPuts = 0
  let recoveryGets = 0
  for (const record of plan.records) {
    const state = (await vault.resumePlan([record.recordId]))[0]
    for (const action of state.actions) {
      const adapter = adapters.get(action.relayId)
      if (action.action === 'send-prepared-put') {
        const attempt = await vault.loadPreparedAttempt(record.recordId, action.relayId)
        await vault.recordPutSendStarted(record.recordId, action.relayId, attempt.attemptId)
        networkPuts++
        const result = await adapter.send({
          ...record.publication,
          prepared: attempt.managementCapability.prepared
        })
        if (!result || result.ok !== true || result.readbackVerified !== true) {
          fail('PEERIT_THREE_POST_READBACK_REQUIRED', `${record.recordId}/${action.relayId} lacks verified readback`)
        }
      } else if (action.action === 'reconcile-get-only') {
        if (!adapter || typeof adapter.reconcile !== 'function') {
          fail('PEERIT_THREE_POST_RECONCILE_UNAVAILABLE', `${action.relayId} has no authenticated GET reconciliation`)
        }
        recoveryGets++
        const result = await adapter.reconcile(record.publication)
        if (!result || result.ok !== true || result.readbackVerified !== true) {
          fail('PEERIT_THREE_POST_READBACK_REQUIRED', `${record.recordId}/${action.relayId} ambiguity remains unresolved`)
        }
      } else if (action.action !== 'get-only-revalidate') {
        fail('PEERIT_THREE_POST_PUBLISH_STATE', `unsupported publisher action ${action.action}`)
      }
    }
  }
  await vault.assertComplete(plan.records.map(record => record.recordId))
  return Object.freeze({
    ok: true,
    recordCount: 4,
    expectedCids: plan.expectedCids,
    networkPuts,
    recoveryGets,
    relayTuple: tuple,
    receipts: await vault.sanitizedReceiptManifest()
  })
}

function publicReadCapability (value) {
  plain(value, 'read capability')
  return {
    version: value.version,
    relayPublicKey: hex(bytes(value.relayPublicKey, 'readCapability.relayPublicKey', 32)),
    storageSlot: hex(bytes(value.storageSlot, 'readCapability.storageSlot', 32)),
    cellKey: hex(bytes(value.cellKey, 'readCapability.cellKey', 32)),
    sizeClass: value.sizeClass,
    expectedCellBlobHash: value.expectedCellBlobHash == null
      ? null
      : hex(bytes(value.expectedCellBlobHash, 'readCapability.expectedCellBlobHash', 32))
  }
}

function bootstrapRelay (row) {
  return {
    relayId: row.relayId,
    canonicalDescribeUrl: row.canonicalDescribeUrl,
    continuityRootRelayPublicKey: row.continuityRootRelayPublicKey,
    storeId: row.storeId,
    descriptorGenesisHash: row.descriptorGenesisHash,
    minimumDescriptorSequence: row.descriptorSequence,
    familyId: row.familyId,
    operationId: row.operationId,
    endpointId: row.endpointId,
    transportId: row.transportId,
    transportSupportBit: row.transportSupportBit,
    privacyProfileBit: row.privacyProfileBit
  }
}

export async function createSignedThreePostBootstrapV1 ({
  vault,
  plan,
  relayTuple,
  authoritySeedHex,
  authorityPublicKey,
  releaseSequence,
  issuedAt,
  expiresAt,
  bootstrapSequence = 0,
  previousBootstrapHash = null
}) {
  const tuple = validateCurrentRelayTupleV1(relayTuple)
  await vault.assertComplete(plan.records.map(record => record.recordId))
  const records = []
  for (const record of plan.records) {
    const material = await vault.loadRecordMaterial(record.recordId)
    const publication = materialPublication(material)
    const replicas = []
    for (const relay of tuple.relays) {
      const attempt = await vault.loadPreparedAttempt(record.recordId, relay.relayId)
      if (attempt.stage !== 'readback-verified') {
        fail('PEERIT_THREE_POST_READBACK_REQUIRED', `${record.recordId}/${relay.relayId} is not readback verified`)
      }
      replicas.push({
        relayId: relay.relayId,
        targetId: attempt.targetContext.targetId,
        readCapability: publicReadCapability(attempt.readerCapability)
      })
    }
    records.push({
      recordId: publication.intentId,
      wireKeys: [...publication.wireKeys].sort(),
      authorPublicKey: publication.authorPublicKey,
      innerCodec: publication.innerCodec,
      innerLength: publication.innerLength,
      sizeClass: publication.sizeClass,
      logicalHash: hex(publication.logicalHash),
      encodingCommitment: hex(publication.encodingCommitment),
      replicas: replicas.sort((left, right) => left.relayId.localeCompare(right.relayId))
    })
  }
  records.sort((left, right) => left.recordId.localeCompare(right.recordId))
  const payload = {
    schema: PEERIT_SEED_BOOTSTRAP_SCHEMA_V1,
    version: 1,
    profile: PEERIT_SEED_BOOTSTRAP_PROFILE_V1,
    operatorBoundary: PEERIT_SEED_BOOTSTRAP_OPERATOR_BOUNDARY_V1,
    bootstrapSequence,
    previousBootstrapHash,
    releaseSequence,
    authorityPublicKey: hex32(authorityPublicKey, 'authorityPublicKey'),
    issuedAt,
    expiresAt,
    relays: tuple.relays.map(bootstrapRelay).sort((left, right) => left.relayId.localeCompare(right.relayId)),
    records
  }
  const artifact = await createPeeritSeedBootstrapV1(payload, { seedHex: authoritySeedHex })
  const artifactBytes = encodePeeritSeedBootstrapV1(artifact)
  const artifactHash = await hashPeeritSeedBootstrapV1(artifactBytes)
  const verified = await verifyPeeritSeedBootstrapV1(artifactBytes, {
    authorityPublicKey,
    releaseSequence,
    expectedArtifactHash: artifactHash,
    previousBootstrapHash,
    now: issuedAt
  })
  return Object.freeze({ artifact, artifactBytes, artifactHash, verified, relayTupleSha256: tuple.tupleSha256 })
}

export function sanitizedThreePostPreflightV1 ({ plan, relayTuple }) {
  const tuple = validateCurrentRelayTupleV1(relayTuple)
  if (!plan || !Array.isArray(plan.records) || plan.records.length !== 4) {
    fail('PEERIT_THREE_POST_SCOPE_MISMATCH', 'preflight requires the exact four-record plan')
  }
  return Object.freeze({
    schema: 'peerit-three-post-preflight-v1',
    ok: true,
    mode: 'local-only-zero-network',
    manifestSha256: plan.manifestSha256,
    board: plan.board,
    communityClaims: plan.records.filter(row => row.kind === 'community').length,
    posts: plan.records.filter(row => row.kind === 'post').length,
    expectedCids: [...plan.expectedCids],
    cellClasses: plan.records.map(row => row.publication.sizeClass),
    cellLengths: plan.records.map(row => row.publication.innerLength),
    relayIds: tuple.relays.map(row => row.relayId),
    relayDescriptorSequences: tuple.relays.map(row => row.descriptorSequence),
    relayTupleSha256: tuple.tupleSha256,
    networkGets: 0,
    networkPuts: 0
  })
}

export const _internals = Object.freeze({ fromHex, stable })
