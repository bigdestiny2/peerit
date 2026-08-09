// peerit INBOX topic convention v1 — the deterministic per-board inbox topic
// every peerit publisher and reader derives independently. Pure-JS only
// (strict-CSP safe: no node:crypto, no Buffer, no eval, no WASM).
//
// THE CONVENTION (the decision record cites this verbatim):
//   topicSeed = blake2b256("peerit/inbox-topic-seed/v1" ‖ utf8(boardSlug) ‖ relayPublicKey)
//   stream block i = blake2b256("peerit/inbox-topic-drng/v1" ‖ topicSeed ‖ u32be(i))
//   The seeded runtime hands the vendored blind client's createInboxReplica
//   exactly four 32-byte draws — the create, append, renew, close capability
//   private seeds, in that order (verified against
//   00-core/hiverelay/packages/blind-client/capabilities.js
//   generateDistinctCapabilityKeys: one draw per name, redraws only on an
//   ed25519 public-key collision, which a deterministic stream cannot hit
//   non-deterministically). The replica's clientNonce is supplied EXPLICITLY
//   as stream block 4, so the runtime draw count is exactly 4 and the whole
//   derivation — capability keys, physical topic, create commitment, request
//   commitment, and (with a fixed admission) the CREATE request bytes — is
//   BYTE-IDENTICAL on every re-derivation.
//
// Pinned replica shape: allocationEpoch 0 (the inbox runtime has no allocation
// epoch window check — unlike cells — so epoch 0 is valid and makes the topic
// permanent), frameClassBits 1 (4096-byte pointer frames only), retentionClass
// 2, leaseClass 4 (≈90 days; INBOX.RENEW has no fleet pow cost row, so the
// longest lease minimizes re-CREATE churn — after a tombstone the
// byte-identical re-CREATE simply re-opens the same topic), appendAuthMode 1
// (SIGNATURE_REQUIRED; the board's append capability signs every frame).
//
// physicalTopic = blake2b256("hiverelay.blind.inbox-topic.v1" ‖
//   u32be(allocationEpoch) ‖ createPublicKey) is computed by the vendored
//   client; this module never re-implements relay protocol hashes.
import {
  asciiBytes,
  asBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  concatBytes,
  fixedBytesValue,
  u32Bytes,
  utf8Bytes
} from './release-control-primitives.mjs'

export const PEERIT_INBOX_TOPIC_SEED_DOMAIN_V1 = 'peerit/inbox-topic-seed/v1'
export const PEERIT_INBOX_TOPIC_DRNG_DOMAIN_V1 = 'peerit/inbox-topic-drng/v1'

// The pinned convention shape (see the module header).
export const PEERIT_INBOX_TOPIC_SHAPE_V1 = Object.freeze({
  allocationEpoch: 0,
  frameClassBits: 1,
  retentionClass: 2,
  leaseClass: 4,
  appendAuthMode: 1
})

// createInboxReplica consumes exactly four 32-byte draws (create, append,
// renew, close capability seeds); the clientNonce is block 4, supplied
// explicitly. Anything else is artifact drift and fails closed.
const TOPIC_KEY_DRAWS_V1 = 4

export const PEERIT_INBOX_BOARD_SLUG_PATTERN_V1 = /^[a-z0-9-]{1,64}$/

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

export function validatePeeritInboxBoardSlugV1 (boardSlug) {
  if (typeof boardSlug !== 'string' || !PEERIT_INBOX_BOARD_SLUG_PATTERN_V1.test(boardSlug)) {
    fail('PEERIT_INBOX_TOPIC_INVALID', 'boardSlug must be lowercase [a-z0-9-]{1,64}')
  }
  return boardSlug
}

function copy32 (value, field) {
  return fixedBytesValue(value, 32, field).slice()
}

export function peeritInboxTopicSeedV1 (boardSlug, relayPublicKey) {
  validatePeeritInboxBoardSlugV1(boardSlug)
  const key = fixedBytesValue(relayPublicKey, 32, 'relayPublicKey')
  return blake2b256(concatBytes(
    asciiBytes(PEERIT_INBOX_TOPIC_SEED_DOMAIN_V1),
    utf8Bytes(boardSlug, 'boardSlug'),
    key))
}

// stream block i = blake2b256(DRNG ‖ seed ‖ u32be(i))
export function peeritInboxTopicStreamBlockV1 (seed, index) {
  const seedBytes = fixedBytesValue(seed, 32, 'topicSeed')
  if (!Number.isSafeInteger(index) || index < 0 || index > 0xffffffff) {
    fail('PEERIT_INBOX_TOPIC_INVALID', 'stream block index is outside u32')
  }
  return blake2b256(concatBytes(
    asciiBytes(PEERIT_INBOX_TOPIC_DRNG_DOMAIN_V1),
    seedBytes,
    u32Bytes(index, 'stream block index')))
}

// A runtime wrapper for the vendored blind client: randomBytes(n) draws
// successive 32-byte blocks of the deterministic topic stream (n must be 32 —
// the topic derivation draws nothing else); every other runtime capability
// (AES-GCM etc.) delegates to baseRuntime unchanged.
export function createPeeritInboxTopicRuntimeV1 ({ boardSlug, relayPublicKey, baseRuntime } = {}) {
  if (!baseRuntime || typeof baseRuntime !== 'object') {
    fail('PEERIT_INBOX_TOPIC_INVALID', 'a base crypto runtime is required')
  }
  const seed = peeritInboxTopicSeedV1(boardSlug, relayPublicKey)
  let nextBlock = 0
  const runtime = Object.freeze({
    ...baseRuntime,
    randomBytes (length) {
      if (length !== 32) {
        fail('PEERIT_INBOX_TOPIC_INVALID', 'the seeded inbox-topic stream yields only 32-byte blocks')
      }
      const block = peeritInboxTopicStreamBlockV1(seed, nextBlock)
      nextBlock += 1
      return block
    }
  })
  return Object.freeze({
    seed,
    runtime,
    drawsSoFar () { return nextBlock }
  })
}

// The derivation-only admission: createInboxReplica insists on an admission
// value at construction time, but the admission is NOT covered by the create
// request commitment (inboxCreateRequestCommitment commits to the create
// commitment and the clientNonce only), so a placeholder derivation yields
// the EXACT capability set, physical topic, create commitment and request
// commitment. A request built with this placeholder is never sendable — the
// relay would reject its zero parameterHash/token. The publish flow re-derives
// with a real pow-issuance admissionProvider before any CREATE crosses the
// wire; discovery never sends the CREATE at all.
export const PEERIT_INBOX_TOPIC_PLACEHOLDER_ADMISSION_V1 = Object.freeze({
  profileId: 8,
  schemeId: 1,
  parameterHash: new Uint8Array(32),
  token: new Uint8Array(32)
})

// Derive the board topic end-to-end through the vendored client. Returns the
// full replica surface so the publish flow can send the (real-admission)
// CREATE and sign APPENDs, and so the drill can assert byte-identity.
export async function derivePeeritInboxTopicV1 ({
  boardSlug,
  relayPublicKey,
  control,
  baseRuntime,
  admission,
  admissionProvider
} = {}) {
  if (!control || typeof control.createInboxReplica !== 'function') {
    fail('PEERIT_INBOX_TOPIC_INVALID', 'the vendored blind client control surface is required')
  }
  validatePeeritInboxBoardSlugV1(boardSlug)
  const relayKey = fixedBytesValue(relayPublicKey, 32, 'relayPublicKey')
  const seeded = createPeeritInboxTopicRuntimeV1({ boardSlug, relayPublicKey: relayKey, baseRuntime })
  const clientNonce = peeritInboxTopicStreamBlockV1(seeded.seed, TOPIC_KEY_DRAWS_V1)
  const options = {
    runtime: seeded.runtime,
    relayPublicKey: relayKey,
    allocationEpoch: PEERIT_INBOX_TOPIC_SHAPE_V1.allocationEpoch,
    frameClassBits: PEERIT_INBOX_TOPIC_SHAPE_V1.frameClassBits,
    retentionClass: PEERIT_INBOX_TOPIC_SHAPE_V1.retentionClass,
    leaseClass: PEERIT_INBOX_TOPIC_SHAPE_V1.leaseClass,
    appendAuthMode: PEERIT_INBOX_TOPIC_SHAPE_V1.appendAuthMode,
    clientNonce
  }
  if (typeof admissionProvider === 'function') options.admissionProvider = admissionProvider
  else if (admission != null) options.admission = admission
  else options.admission = PEERIT_INBOX_TOPIC_PLACEHOLDER_ADMISSION_V1
  const prepared = await control.createInboxReplica(options)
  if (seeded.drawsSoFar() !== TOPIC_KEY_DRAWS_V1) {
    fail('PEERIT_INBOX_TOPIC_RUNTIME_DRIFT',
      `createInboxReplica consumed ${seeded.drawsSoFar()} stream draws, expected exactly ${TOPIC_KEY_DRAWS_V1} (create/append/renew/close)`)
  }
  const readCap = prepared.readCap
  if (!readCap || !bytesEqual(asBytes(readCap.relayPublicKey, 'readCap relayPublicKey'), relayKey)) {
    fail('PEERIT_INBOX_TOPIC_RELAY_DRIFT', 'the derived read capability does not bind the requested relay')
  }
  return Object.freeze({
    boardSlug,
    relayPublicKey: relayKey.slice(),
    seed: seeded.seed.slice(),
    clientNonce: clientNonce.slice(),
    writeCap: prepared.writeCap,
    readCap: prepared.readCap,
    physicalTopic: copy32(readCap.physicalTopic, 'physicalTopic'),
    createCommitment: copy32(prepared.createCommitment, 'createCommitment'),
    requestCommitment: copy32(prepared.requestCommitment, 'requestCommitment'),
    request: prepared.request,
    requestBytes: asBytes(prepared.requestBytes, 'requestBytes').slice(),
    wire: prepared.wire,
    topic: bytesToHex(asBytes(readCap.physicalTopic, 'physicalTopic')),
    placeholderAdmission: options.admission === PEERIT_INBOX_TOPIC_PLACEHOLDER_ADMISSION_V1
  })
}
