// pow-issuance-v1 browser spend provider: challenge → proof-of-work → one-use
// token → per-slot presentation, for the Peerit CELL.PUT write path.
// Pure-JS only (vendored noble-hashes + WebCrypto; strict-CSP safe: no
// node:crypto, no eval, no WASM).
// The byte layouts are exactly docs/POW-ISSUANCE-V1.md and the DEPLOYED
// fleet's pow-issuance-v1/token-codec.js (00-core/hiverelay — HMAC-SHA256 key
// derivation, never blake2b); the local drill test
// (test/peerit-pow-issuance-spend.mjs) asserts byte-identity against that codec.
//
// The pow-issuance token is IN ADDITION to the in-record Peerit PoW (comment
// 14 / post 16 bits, minted and verified on ingest): it buys one-use admission
// of an already self-proving sealed record. Relays stay blind — every byte that
// crosses is the opaque admission envelope the sealed Cell request requires.
import {
  asciiBytes,
  asBytes,
  bytesEqual,
  bytesToHex,
  compareBytes,
  concatBytes,
  fixedBytesValue,
  hexToBytes,
  u64Bytes
} from './release-control-primitives.mjs'
import { sha256 } from '../vendor/noble-hashes/sha2.js'

export const POW_ISSUANCE_V1_SCHEME_ID = 1
export const POW_ISSUANCE_V1_SCHEME_VERSION = 1
export const POW_ISSUANCE_V1_WIRE_VERSION = 1
export const POW_ISSUANCE_V1_MAX_ALLOWANCE = 8
// The fleet issuer caps allowance at 2 (the relay admission adapter cap is 8):
// a two-slot token — one CELL.PUT slot per relay — is the most one mint buys.
export const POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP = 2

export const POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES = 42
export const POW_ISSUANCE_V1_CHALLENGE_BYTES = 74
export const POW_ISSUANCE_V1_TOKEN_BYTES = 103

const RECORD_BINDING_DOMAIN = asciiBytes('hiverelay/pow-issuance-v1/record-binding')
const POW_DOMAIN = asciiBytes('hiverelay/pow-issuance-v1/pow')

// The mint inner loop hashes with the vendored noble-hashes SHA-256 (pure JS,
// strict-CSP safe). Awaiting a WebCrypto Promise per candidate collapsed the
// effective in-page rate (~10.7k candidates/s — a 20-bit proof can outlive the
// issuer's 120s challenge TTL); noble hashes ~6x10^5 111-byte preimages per
// second in Chromium, so the same proof lands in seconds. The ascending nonce
// search — and therefore the first valid proof — is byte-exact unchanged
// (SHA-256 is SHA-256; the local drill asserts digest equality against
// WebCrypto and byte-parity against the relay's token-codec.js).
const MINT_YIELD_MILLIS = 75

// MessageChannel yields are not timer-throttled (background/headless pages can
// clamp setTimeout to ~1s); the mint stays responsive without surrendering its
// rate to the throttler. Node's timers are never throttled (and worker ports
// hold the event loop open), so Node takes a plain setTimeout yield; browsers
// get a fresh, immediately-closed channel per yield.
const MINT_YIELD_VIA_TIMER = typeof process === 'object' && process !== null &&
  process.versions && typeof process.versions.node === 'string'
function yieldMintControl () {
  if (MINT_YIELD_VIA_TIMER || typeof MessageChannel !== 'function') {
    return new Promise(resolve => setTimeout(resolve, 0))
  }
  const channel = new MessageChannel()
  return new Promise(resolve => {
    channel.port1.onmessage = () => {
      channel.port1.close()
      channel.port2.close()
      resolve()
    }
    channel.port2.postMessage(null)
  })
}

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function integer (value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('PEERIT_POW_ISSUANCE_INVALID', `${field} is outside ${minimum}..${maximum}`)
  }
  return value
}

function commitmentList (value, field = 'commitments') {
  if (!Array.isArray(value) || value.length < 1 || value.length > POW_ISSUANCE_V1_MAX_ALLOWANCE) {
    fail('PEERIT_POW_ISSUANCE_INVALID', `${field} is outside 1..8 slots`)
  }
  return value.map((commitment, index) =>
    fixedBytesValue(commitment, 32, `${field}[${index}]`))
}

// recordCommitment = HMAC-SHA256(key=BIND, count‖c₀‖…‖c_{allowance-1})
// Deployed fleet codec: 00-core/hiverelay packages/blind-daemon/
// pow-issuance-v1/token-codec.js (SHA-256/HMAC-SHA256, never blake2b — the
// blake2b256 design is superseded and the fleet verifier rejects it).
// noble-hashes/hmac.js is not vendored; HMAC is composed inline over the
// vendored sha256 (RFC 2104, 64-byte block).
function hmacSha256 (key, data) {
  let k = key
  if (k.length > 64) k = sha256(k)
  const inner = new Uint8Array(64 + data.length)
  const outer = new Uint8Array(64 + 32)
  for (let i = 0; i < 64; i++) {
    const b = i < k.length ? k[i] : 0
    inner[i] = b ^ 0x36
    outer[i] = b ^ 0x5c
  }
  inner.set(data, 64)
  outer.set(sha256(inner), 64)
  return sha256(outer)
}

export function powIssuanceV1RecordBindingRoot (commitments) {
  const slots = commitmentList(commitments)
  return hmacSha256(RECORD_BINDING_DOMAIN, concatBytes(Uint8Array.of(slots.length), slots))
}

// PoW preimage = POW ‖ challengePayload(42B) ‖ recordCommitment(32B) ‖ nonce:u64be
export function powIssuanceV1Preimage (challengePayload, recordCommitment, nonce) {
  const payload = fixedBytesValue(challengePayload, 42, 'challengePayload')
  const commitment = fixedBytesValue(recordCommitment, 32, 'recordCommitment')
  return concatBytes(POW_DOMAIN, payload, commitment, u64Bytes(nonce, 'nonce'))
}

export function countLeadingZeroBits (digest) {
  const bytes = asBytes(digest, 'digest')
  let count = 0
  for (const byte of bytes) {
    if (byte === 0) {
      count += 8
      continue
    }
    return count + Math.clz32(byte) - 24
  }
  return count
}

// admission.token = token ‖ u8(spendIndex) ‖ siblings:32×(allowance-1), siblings
// in slot order (every commitment except the spent slot).
export function buildPowIssuanceV1Presentation (token, spendIndex, commitments) {
  const tokenBytes = fixedBytesValue(token, POW_ISSUANCE_V1_TOKEN_BYTES, 'token')
  const slots = commitmentList(commitments)
  integer(spendIndex, 'spendIndex', 0, slots.length - 1)
  const siblings = slots.filter((unused, index) => index !== spendIndex)
  return concatBytes(tokenBytes, Uint8Array.of(spendIndex), siblings)
}

function fromBase64Url (value, field) {
  if (typeof value !== 'string' || !/^[0-9A-Za-z_-]+$/.test(value)) {
    fail('PEERIT_POW_ISSUANCE_CHALLENGE_INVALID', `${field} is not base64url`)
  }
  if (typeof atob !== 'function') {
    fail('PEERIT_POW_ISSUANCE_CHALLENGE_INVALID', 'base64 decoding is unavailable')
  }
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  const output = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) output[index] = binary.charCodeAt(index)
  return output
}

function normalizeIssuanceUrl (value, allowInsecureLoopback) {
  if (typeof value !== 'string' || !value) {
    fail('PEERIT_POW_ISSUANCE_ISSUER_INVALID', 'pow-issuance issuanceUrl is required')
  }
  let url
  try {
    url = new URL(value)
  } catch {
    fail('PEERIT_POW_ISSUANCE_ISSUER_INVALID', 'pow-issuance issuanceUrl is not a URL')
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === '[::1]'
  if (url.protocol !== 'https:' && !(allowInsecureLoopback === true && loopback && url.protocol === 'http:')) {
    fail('PEERIT_POW_ISSUANCE_ISSUER_INVALID', 'pow-issuance issuanceUrl must be HTTPS')
  }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    fail('PEERIT_POW_ISSUANCE_ISSUER_INVALID', 'pow-issuance issuanceUrl must be a bare origin')
  }
  return url.origin
}

function subtleOrFail (subtle) {
  const runtime = subtle || (globalThis.crypto && globalThis.crypto.subtle)
  if (!runtime || typeof runtime.digest !== 'function') {
    fail('PEERIT_POW_ISSUANCE_CRYPTO_UNAVAILABLE', 'secure WebCrypto SHA-256 is unavailable')
  }
  return runtime
}

function throwIfAborted (signal) {
  if (signal && signal.aborted) {
    throw signal.reason || Object.assign(new Error('pow-issuance spend was aborted'), { code: 'ABORT_ERR' })
  }
}

// The low-level client half of one issuer origin: fetch a challenge, mint the
// hashcash nonce over challenge‖recordCommitment, redeem for a one-use token.
export function createPowIssuanceV1SpendProvider (options = {}) {
  const subtle = subtleOrFail(options.subtle)
  const fetchValue = typeof options.fetch === 'function'
    ? options.fetch
    : (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null)
  if (!fetchValue) fail('PEERIT_POW_ISSUANCE_FETCH_UNAVAILABLE', 'a fetch implementation is required')
  const issuerOrigin = normalizeIssuanceUrl(options.issuanceUrl, options.allowInsecureLoopback === true)
  const parentSignal = options.signal

  async function fetchChallenge (signal = parentSignal) {
    throwIfAborted(signal)
    const response = await fetchValue(`${issuerOrigin}/challenge`, { signal: signal || undefined })
    throwIfAborted(signal)
    if (!response || response.status !== 200) {
      fail('PEERIT_POW_ISSUANCE_CHALLENGE_UNAVAILABLE',
        `pow-issuance issuer refused a challenge (HTTP ${response ? response.status : 'none'})`)
    }
    let body
    try {
      body = await response.json()
    } catch {
      fail('PEERIT_POW_ISSUANCE_CHALLENGE_INVALID', 'pow-issuance challenge response is not JSON')
    }
    if (!body || body.scheme !== 'pow-issuance-v1') {
      fail('PEERIT_POW_ISSUANCE_CHALLENGE_INVALID', 'pow-issuance challenge response is not pow-issuance-v1')
    }
    const challengeBytes = fromBase64Url(body.challenge, 'challenge')
    if (challengeBytes.byteLength !== POW_ISSUANCE_V1_CHALLENGE_BYTES) {
      fail('PEERIT_POW_ISSUANCE_CHALLENGE_INVALID', 'pow-issuance challenge is not 74 bytes')
    }
    const challengePayload = challengeBytes.slice(0, POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES)
    if (challengePayload[0] !== POW_ISSUANCE_V1_WIRE_VERSION) {
      fail('PEERIT_POW_ISSUANCE_CHALLENGE_INVALID', 'pow-issuance challenge version is unsupported')
    }
    const difficultyBits = integer(body.difficultyBits, 'difficultyBits', 1, 32)
    if (challengePayload[41] !== difficultyBits) {
      fail('PEERIT_POW_ISSUANCE_CHALLENGE_INVALID',
        'pow-issuance challenge difficulty disagrees with its signed payload')
    }
    return Object.freeze({
      challengeWire: body.challenge,
      challengeBytes,
      challengePayload,
      difficultyBits,
      expiresAtUnix: integer(body.expiresAtUnix, 'expiresAtUnix', 0, Number.MAX_SAFE_INTEGER)
    })
  }

  // Ascending hashcash search: sha256 leading-zero-bits ≥ difficultyBits.
  // Synchronous noble-hashes digests over one reusable frame. The nonce is an
  // in-place big-endian byte counter (carry-incremented, usually one byte per
  // candidate) — BigInt/arithmetic per candidate would cost most of the rate.
  // The ascending order and first valid proof are exact; the BigInt nonce is
  // reconstructed once, after the search. A Number-side cadence drives the
  // progress/cancellation/yield boundary (no per-candidate BigInt modulo).
  async function mintNonce (input = {}) {
    const challengePayload = fixedBytesValue(input.challengePayload, 42, 'challengePayload')
    const recordCommitment = fixedBytesValue(input.recordCommitment, 32, 'recordCommitment')
    const difficultyBits = integer(input.difficultyBits, 'difficultyBits', 1, 32)
    const signal = input.signal || parentSignal
    const prefix = concatBytes(POW_DOMAIN, challengePayload, recordCommitment)
    const frame = new Uint8Array(prefix.byteLength + 8)
    frame.set(prefix)
    const counterBase = prefix.byteLength
    const started = Date.now()
    let lastYield = started
    let cadence = 0
    // nonce < MAX_MINING_NONCE (2^62) exactly while the counter's top byte < 0x40.
    while (frame[counterBase] < 0x40) {
      if (countLeadingZeroBits(sha256(frame)) >= difficultyBits) {
        let nonce = 0n
        for (let index = 0; index < 8; index++) {
          nonce = (nonce << 8n) | BigInt(frame[counterBase + index])
        }
        return Object.freeze({
          nonce,
          attempts: nonce + 1n,
          mintMillis: Date.now() - started,
          difficultyBits
        })
      }
      let carry = 7
      while (carry >= 0) {
        frame[counterBase + carry] = (frame[counterBase + carry] + 1) & 0xff
        if (frame[counterBase + carry] !== 0) break
        carry -= 1
      }
      cadence += 1
      if (cadence === 4096) {
        cadence = 0
        let candidateCount = 0n
        for (let index = 0; index < 8; index++) {
          candidateCount = (candidateCount << 8n) | BigInt(frame[counterBase + index])
        }
        if (typeof input.onProgress === 'function') input.onProgress(candidateCount)
        throwIfAborted(signal)
        if (Date.now() - lastYield >= MINT_YIELD_MILLIS) {
          await yieldMintControl()
          lastYield = Date.now()
        }
      }
    }
    fail('PEERIT_POW_ISSUANCE_MINING_EXHAUSTED', 'pow-issuance mining space is exhausted')
  }

  async function redeem (input = {}) {
    const signal = input.signal || parentSignal
    throwIfAborted(signal)
    const recordCommitment = fixedBytesValue(input.recordCommitment, 32, 'recordCommitment')
    const allowance = integer(input.allowance, 'allowance', 1, POW_ISSUANCE_V1_MAX_ALLOWANCE)
    const nonce = input.nonce
    if (typeof nonce !== 'bigint' || nonce < 0n || nonce > ((1n << 64n) - 1n)) {
      fail('PEERIT_POW_ISSUANCE_INVALID', 'nonce is outside u64')
    }
    if (typeof input.challengeWire !== 'string' || !input.challengeWire) {
      fail('PEERIT_POW_ISSUANCE_INVALID', 'the base64url challenge wire value is required')
    }
    const response = await fetchValue(`${issuerOrigin}/redeem`, {
      method: 'POST',
      signal: signal || undefined,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        challenge: input.challengeWire,
        nonce: bytesToHex(u64Bytes(nonce)),
        recordCommitment: bytesToHex(recordCommitment),
        allowance
      })
    })
    throwIfAborted(signal)
    let body
    try {
      body = await response.json()
    } catch {
      fail('PEERIT_POW_ISSUANCE_REDEEM_REJECTED', 'pow-issuance redeem response is not JSON')
    }
    if (!response || response.status !== 200) {
      const error = new Error(`pow-issuance issuer rejected the redeem (HTTP ${response ? response.status : 'none'}: ${body && body.error ? body.error : 'unknown'})`)
      error.code = 'PEERIT_POW_ISSUANCE_REDEEM_REJECTED'
      error.httpStatus = response ? response.status : 0
      error.issuerError = body && typeof body.error === 'string' ? body.error : null
      throw error
    }
    if (!body || body.scheme !== 'pow-issuance-v1' || typeof body.token !== 'string') {
      fail('PEERIT_POW_ISSUANCE_TOKEN_INVALID', 'pow-issuance redeem response is not pow-issuance-v1')
    }
    const token = hexToBytes(body.token, POW_ISSUANCE_V1_TOKEN_BYTES, 'token')
    return Object.freeze({
      token,
      allowance: integer(body.allowance, 'redeemed allowance', 1, POW_ISSUANCE_V1_MAX_ALLOWANCE),
      expiryEpoch: integer(body.expiryEpoch, 'expiryEpoch', 0, 0xffffffff)
    })
  }

  // One full mint over the ordered commitment list: binding root → challenge →
  // PoW → token. Returns everything the per-slot presentations and the drill
  // transcript need. A challenge that outlives the mint is a liveness event,
  // never a verification failure: the mint restarts from a FRESH challenge
  // (bounded, abortable). Invalid-proof rejections (POW_INSUFFICIENT_WORK) are
  // never retried — they fail closed as drift.
  async function mint (input = {}) {
    const slots = commitmentList(input.commitments)
    if (slots.length > POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP) {
      fail('PEERIT_POW_ISSUANCE_ALLOWANCE_EXCEEDED',
        'the fleet issuer mints at most a two-slot token per proof')
    }
    const recordCommitment = powIssuanceV1RecordBindingRoot(slots)
    const maxAttempts = integer(input.challengeAttempts == null ? 3 : input.challengeAttempts,
      'challengeAttempts', 1, 8)
    let challenge = null
    let mined = null
    let redeemed = null
    let expiryRetries = 0
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      throwIfAborted(input.signal || parentSignal)
      challenge = await fetchChallenge(input.signal)
      mined = await mintNonce({
        challengePayload: challenge.challengePayload,
        recordCommitment,
        difficultyBits: challenge.difficultyBits,
        signal: input.signal,
        onProgress: input.onProgress
      })
      try {
        redeemed = await redeem({
          challengeWire: challenge.challengeWire,
          nonce: mined.nonce,
          recordCommitment,
          allowance: slots.length,
          signal: input.signal
        })
        break
      } catch (error) {
        const expired = error && error.code === 'PEERIT_POW_ISSUANCE_REDEEM_REJECTED' &&
          error.issuerError === 'POW_CHALLENGE_EXPIRED'
        if (!expired || attempt === maxAttempts) throw error
        expiryRetries += 1
        if (typeof input.onExpiryRetry === 'function') input.onExpiryRetry(attempt, error)
      }
    }
    if (redeemed.allowance !== slots.length) {
      fail('PEERIT_POW_ISSUANCE_TOKEN_INVALID', 'pow-issuance token allowance disagrees with the request')
    }
    return Object.freeze({
      token: redeemed.token,
      allowance: redeemed.allowance,
      expiryEpoch: redeemed.expiryEpoch,
      recordCommitment,
      challengePayload: challenge.challengePayload,
      nonce: mined.nonce,
      attempts: mined.attempts,
      mintMillis: mined.mintMillis,
      difficultyBits: challenge.difficultyBits,
      expiryRetries
    })
  }

  return Object.freeze({
    issuerOrigin,
    fetchChallenge,
    mintNonce,
    redeem,
    mint,
    recordBindingRoot: powIssuanceV1RecordBindingRoot,
    presentation: buildPowIssuanceV1Presentation
  })
}

function issuerRow (value, index, allowInsecureLoopback) {
  if (!value || typeof value !== 'object') {
    fail('PEERIT_POW_ISSUANCE_ISSUER_INVALID', `issuers[${index}] is required`)
  }
  return Object.freeze({
    relayPublicKey: fixedBytesValue(value.relayPublicKey, 32, `issuers[${index}].relayPublicKey`),
    issuanceUrl: normalizeIssuanceUrl(value.issuanceUrl, allowInsecureLoopback)
  })
}

// The flush-wiring half: a factory compatible with the relay-consumer
// createAdmissionProvider seam (relay-consumer.js admissionProviderFor). The
// seam calls it once per PUT-qualified relay with {candidate, endpointContext,
// verifiedAdmissionParameters, admissionProfile, signal}; the returned provider
// is invoked per CELL.PUT with {requestCommitment, relayPublicKey, …} and must
// answer {profileId, schemeId, parameterHash, token(presentation bytes)}.
//
// One authored record spans both relays, so one record session collects ONE
// request commitment per expected relay, mints ONE token whose binding root
// commits to the slot list ordered by relay public key bytes (slot 0 = smallest
// key — syd-1 on the current fleet), and hands each relay the presentation for
// its own slot. The shared issuer key lets the single token redeem on both
// relays; the binding root makes each spend authorize exactly one request.
// Per-relay operation records (T2 INBOX-discovery half): one authored record
// spans the CELL.PUT and the board INBOX.APPEND on the SAME relay, so one
// operation record collects the two request commitments in DECLARED order
// (slot 0 = 'put', slot 1 = 'append' — never relay-key-sorted; this is the
// per-relay shape, not the cross-relay [PUT_syd, PUT_dal] shape beginRecord
// covers) and mints ONE token whose binding root commits to that slot list.
// INBOX.CREATE is a separate one-slot operation record (kind 'create'), opened
// only when the board topic is absent.
//
// Kind is inferred from the artifact's frozen admission context
// (familyId/operationId): CELL.PUT (2/1) → 'put', INBOX.APPEND (3/4) →
// 'append', INBOX.CREATE (3/1) → 'create'. Anything else fails closed.
const OPERATION_RECORD_KINDS = Object.freeze({
  put: Object.freeze({ familyId: 2, operationId: 1 }),
  append: Object.freeze({ familyId: 3, operationId: 4 }),
  create: Object.freeze({ familyId: 3, operationId: 1 })
})

function operationRecordKind (familyId, operationId) {
  for (const [kind, pair] of Object.entries(OPERATION_RECORD_KINDS)) {
    if (pair.familyId === familyId && pair.operationId === operationId) return kind
  }
  return null
}

export function createPowIssuanceV1AdmissionProviderFactory (options = {}) {
  const profileId = integer(options.profileId, 'profileId', 1, 0xffff)
  const schemeId = integer(options.schemeId, 'schemeId', 1, 0xffff)
  if (schemeId !== POW_ISSUANCE_V1_SCHEME_ID) {
    fail('PEERIT_POW_ISSUANCE_INVALID', 'pow-issuance spend providers are bound to schemeId 1')
  }
  if (!Array.isArray(options.issuers) || options.issuers.length < 1) {
    fail('PEERIT_POW_ISSUANCE_ISSUER_INVALID', 'at least one pinned relay issuer origin is required')
  }
  const allowInsecureLoopback = options.allowInsecureLoopback === true
  const issuers = options.issuers.map((row, index) => issuerRow(row, index, allowInsecureLoopback))
  for (const [index, row] of issuers.entries()) {
    if (issuers.findIndex(candidate => bytesEqual(candidate.relayPublicKey, row.relayPublicKey)) !== index) {
      fail('PEERIT_POW_ISSUANCE_ISSUER_INVALID', 'relay issuer pins must not repeat a relay public key')
    }
  }
  const subtle = subtleOrFail(options.subtle)
  const fetchValue = options.fetch
  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null

  // At most one record session is open at a time: writes are explicit user
  // actions, and their admission spends serialize through this slot.
  let openRecord = null

  function beginRecord (input = {}) {
    if (openRecord) {
      fail('PEERIT_POW_ISSUANCE_RECORD_BUSY',
        'a pow-issuance record is already spending; writes are serialized explicit user actions')
    }
    if (!Array.isArray(input.relayPublicKeys) || input.relayPublicKeys.length < 1 ||
        input.relayPublicKeys.length > POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP) {
      fail('PEERIT_POW_ISSUANCE_INVALID',
        `a record expects 1..${POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP} relay slots (the fleet issuer cap)`)
    }
    const seen = new Set()
    const relays = input.relayPublicKeys.map((key, index) => {
      const relayPublicKey = fixedBytesValue(key, 32, `relayPublicKeys[${index}]`)
      const issuer = issuers.find(row => bytesEqual(row.relayPublicKey, relayPublicKey))
      if (!issuer) {
        fail('PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY',
          'a record relay is not one of the signed profile issuer pins')
      }
      const hex = bytesToHex(relayPublicKey)
      if (seen.has(hex)) fail('PEERIT_POW_ISSUANCE_INVALID', 'a record relay is listed twice')
      seen.add(hex)
      return issuer
    })
    // Slot order is relay-public-key byte order: deterministic on both delivery
    // paths, and (syd-1 52f4… < dal-1 8b3f…) matches the fleet slot layout.
    const slots = [...relays].sort((left, right) =>
      compareBytes(left.relayPublicKey, right.relayPublicKey))
    const orderedCommitments = new Array(slots.length).fill(null)
    const pending = new Map() // relay key hex -> {slotIndex, requestCommitment, resolve, reject}
    let mintPromise = null
    let settled = false
    let resolveComplete
    let rejectComplete
    const complete = new Promise((resolve, reject) => {
      resolveComplete = resolve
      rejectComplete = reject
    })
    // The session owner decides when to await completion; never surface an
    // unhandled rejection from a record nobody watched to the end.
    complete.catch(() => {})

    function ensureMint (signal) {
      if (!mintPromise) {
        if (orderedCommitments.some(commitment => commitment == null)) {
          fail('PEERIT_POW_ISSUANCE_SESSION_INVALID', 'pow-issuance record mint started before every slot registered')
        }
        const provider = createPowIssuanceV1SpendProvider({
          issuanceUrl: slots[0].issuanceUrl,
          fetch: fetchValue,
          subtle,
          allowInsecureLoopback,
          signal
        })
        mintPromise = provider.mint({ commitments: orderedCommitments, signal, onProgress })
        mintPromise.then(
          minted => {
            for (const entry of pending.values()) {
              entry.resolve(Object.freeze({
                minted,
                presentation: buildPowIssuanceV1Presentation(
                  minted.token, entry.slotIndex, orderedCommitments)
              }))
            }
            resolveComplete(minted)
          },
          error => {
            for (const entry of pending.values()) entry.reject(error)
            rejectComplete(error)
          })
      }
      return mintPromise
    }

    // One CELL.PUT context → this relay's slot presentation. The commitment
    // registers against the relay's slot; when every slot has registered, the
    // single shared mint resolves all of them at once.
    async function spend (context, signal) {
      throwIfAborted(signal)
      if (settled || openRecord !== session) {
        fail('PEERIT_POW_ISSUANCE_NO_OPEN_RECORD',
          'no open pow-issuance record covers this CELL.PUT; writes begin with an explicit user action')
      }
      const relayPublicKey = fixedBytesValue(context.relayPublicKey, 32, 'relayPublicKey')
      const requestCommitment = fixedBytesValue(context.requestCommitment, 32, 'requestCommitment')
      const hex = bytesToHex(relayPublicKey)
      const slotIndex = slots.findIndex(row => bytesEqual(row.relayPublicKey, relayPublicKey))
      if (slotIndex < 0) {
        fail('PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY',
          'a CELL.PUT arrived from a relay outside the open record slot list')
      }
      const existing = pending.get(hex)
      if (existing && mintPromise) {
        fail('PEERIT_POW_ISSUANCE_RECORD_SEALED',
          'the record token is already minted; a fresh request commitment needs a new record')
      }
      if (existing) {
        // A delivery retry that failed before the prepared replica persisted may
        // replace its commitment until the mint has started.
        existing.reject(Object.assign(
          new Error('pow-issuance slot commitment was replaced before mint'),
          { code: 'PEERIT_POW_ISSUANCE_SLOT_REPLACED' }))
        pending.delete(hex)
      }
      const ready = new Promise((resolve, reject) => {
        pending.set(hex, { slotIndex, requestCommitment, resolve, reject })
      })
      orderedCommitments[slotIndex] = requestCommitment
      if (pending.size === slots.length) ensureMint(signal)
      return ready
    }

    const session = Object.freeze({
      allowance: slots.length,
      slotIndexOf (relayPublicKey) {
        const key = asBytes(relayPublicKey, 'relayPublicKey')
        return slots.findIndex(row => bytesEqual(row.relayPublicKey, key))
      },
      complete,
      spend,
      close () {
        if (settled) return
        settled = true
        if (openRecord === session) openRecord = null
        const error = Object.assign(
          new Error('pow-issuance record closed before its token was spent'),
          { code: 'PEERIT_POW_ISSUANCE_RECORD_CLOSED' })
        for (const entry of pending.values()) entry.reject(error)
        pending.clear()
        rejectComplete(error)
      }
    })

    openRecord = session
    return session
  }

  // The T2 INBOX-discovery session type: slots are the DECLARED operations in
  // declaration order (slot 0 = first entry), each `{relayPublicKey, kind}`
  // with kind 'put' | 'append' | 'create' and an optional pre-declared
  // `requestCommitment` (a slot whose commitment is already known — e.g. the
  // completed CELL.PUT the pointer publish binds). At most
  // POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP slots (the fleet issuer cap);
  // (relayPublicKey, kind) pairs must be distinct. Providers drive
  // `session.spend(context)` with the artifact's frozen admission context; the
  // kind is inferred from familyId/operationId, the slot from (relay, kind).
  // The single shared mint resolves every slot's presentation at once, exactly
  // like beginRecord — ONE token per relay per record.
  function beginOperationRecord (input = {}) {
    if (openRecord) {
      fail('PEERIT_POW_ISSUANCE_RECORD_BUSY',
        'a pow-issuance record is already spending; writes are serialized explicit user actions')
    }
    if (!Array.isArray(input.operations) || input.operations.length < 1 ||
        input.operations.length > POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP) {
      fail('PEERIT_POW_ISSUANCE_INVALID',
        `an operation record expects 1..${POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP} operation slots (the fleet issuer cap)`)
    }
    const seen = new Set()
    const slots = input.operations.map((operation, index) => {
      if (!operation || typeof operation !== 'object') {
        fail('PEERIT_POW_ISSUANCE_INVALID', `operations[${index}] is required`)
      }
      const kind = typeof operation.kind === 'string' && Object.hasOwn(OPERATION_RECORD_KINDS, operation.kind)
        ? operation.kind
        : fail('PEERIT_POW_ISSUANCE_OPERATION_INVALID',
            `operations[${index}].kind must be one of ${Object.keys(OPERATION_RECORD_KINDS).join('/')}`)
      const relayPublicKey = fixedBytesValue(operation.relayPublicKey, 32, `operations[${index}].relayPublicKey`)
      const issuer = issuers.find(row => bytesEqual(row.relayPublicKey, relayPublicKey))
      if (!issuer) {
        fail('PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY',
          'an operation record relay is not one of the signed profile issuer pins')
      }
      const identity = `${bytesToHex(relayPublicKey)}:${kind}`
      if (seen.has(identity)) {
        fail('PEERIT_POW_ISSUANCE_INVALID', 'an operation record lists the same relay operation twice')
      }
      seen.add(identity)
      return Object.freeze({
        kind,
        issuer,
        relayPublicKey,
        identity,
        requestCommitment: operation.requestCommitment == null
          ? null
          : fixedBytesValue(operation.requestCommitment, 32, `operations[${index}].requestCommitment`)
      })
    })
    const orderedCommitments = slots.map(slot => slot.requestCommitment)
    const pending = new Map() // slot identity -> {slotIndex, requestCommitment, resolve, reject}
    let mintPromise = null
    let settled = false
    let resolveComplete
    let rejectComplete
    const complete = new Promise((resolve, reject) => {
      resolveComplete = resolve
      rejectComplete = reject
    })
    // The session owner decides when to await completion; never surface an
    // unhandled rejection from a record nobody watched to the end.
    complete.catch(() => {})

    function ensureMint (signal) {
      if (!mintPromise) {
        if (orderedCommitments.some(commitment => commitment == null)) {
          fail('PEERIT_POW_ISSUANCE_SESSION_INVALID', 'pow-issuance record mint started before every slot registered')
        }
        const provider = createPowIssuanceV1SpendProvider({
          issuanceUrl: slots[0].issuer.issuanceUrl,
          fetch: fetchValue,
          subtle,
          allowInsecureLoopback,
          signal
        })
        mintPromise = provider.mint({ commitments: orderedCommitments, signal, onProgress })
        mintPromise.then(
          minted => {
            for (const entry of pending.values()) {
              entry.resolve(Object.freeze({
                minted,
                presentation: buildPowIssuanceV1Presentation(
                  minted.token, entry.slotIndex, orderedCommitments)
              }))
            }
            resolveComplete(minted)
          },
          error => {
            for (const entry of pending.values()) entry.reject(error)
            rejectComplete(error)
          })
      }
      return mintPromise
    }

    // One admission context → this (relay, kind) slot's presentation. The
    // commitment registers against the slot (a pre-declared slot must match
    // byte-exactly); when every slot has registered, the single shared mint
    // resolves all of them at once.
    async function spend (context, signal) {
      throwIfAborted(signal)
      if (settled || openRecord !== session) {
        fail('PEERIT_POW_ISSUANCE_NO_OPEN_RECORD',
          'no open pow-issuance record covers this operation; writes begin with an explicit user action')
      }
      if (!context || typeof context !== 'object') {
        fail('PEERIT_POW_ISSUANCE_OPERATION_INVALID', 'an operation admission context is required')
      }
      const kind = operationRecordKind(context.familyId, context.operationId)
      if (kind == null) {
        fail('PEERIT_POW_ISSUANCE_OPERATION_INVALID',
          `pow-issuance operation records only admit CELL.PUT (2/1), INBOX.APPEND (3/4), and INBOX.CREATE (3/1), got ${context.familyId}/${context.operationId}`)
      }
      const relayPublicKey = fixedBytesValue(context.relayPublicKey, 32, 'relayPublicKey')
      const requestCommitment = fixedBytesValue(context.requestCommitment, 32, 'requestCommitment')
      const slotIndex = slots.findIndex(row => row.kind === kind && bytesEqual(row.relayPublicKey, relayPublicKey))
      if (slotIndex < 0) {
        fail('PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY',
          'an admission context arrived outside the open operation record slot list')
      }
      const slot = slots[slotIndex]
      if (slot.requestCommitment && !bytesEqual(slot.requestCommitment, requestCommitment)) {
        fail('PEERIT_POW_ISSUANCE_COMMITMENT_DRIFT',
          'the admission context commitment contradicts the slot\'s pre-declared commitment')
      }
      const existing = pending.get(slot.identity)
      if (existing && mintPromise) {
        fail('PEERIT_POW_ISSUANCE_RECORD_SEALED',
          'the record token is already minted; a fresh request commitment needs a new record')
      }
      if (existing) {
        // A delivery retry that failed before the prepared replica persisted may
        // replace its commitment until the mint has started.
        existing.reject(Object.assign(
          new Error('pow-issuance slot commitment was replaced before mint'),
          { code: 'PEERIT_POW_ISSUANCE_SLOT_REPLACED' }))
        pending.delete(slot.identity)
      }
      const ready = new Promise((resolve, reject) => {
        pending.set(slot.identity, { slotIndex, requestCommitment, resolve, reject })
      })
      orderedCommitments[slotIndex] = requestCommitment
      if (pending.size === slots.length) ensureMint(signal)
      return ready
    }

    const session = Object.freeze({
      allowance: slots.length,
      slotIndexOf (kind, relayPublicKey) {
        const key = asBytes(relayPublicKey, 'relayPublicKey')
        return slots.findIndex(row => row.kind === kind && bytesEqual(row.relayPublicKey, key))
      },
      // The commitment registered against a (kind, relay) slot — declared or
      // captured — or null before registration. Survives mint/close so a later
      // publish step can bind its evidence to the exact admitted requests.
      slotCommitment (kind, relayPublicKey) {
        const index = session.slotIndexOf(kind, relayPublicKey)
        if (index < 0) fail('PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY', 'no operation slot covers that relay operation')
        const commitment = orderedCommitments[index]
        return commitment == null ? null : commitment
      },
      complete,
      spend,
      close () {
        if (settled) return
        settled = true
        if (openRecord === session) openRecord = null
        const error = Object.assign(
          new Error('pow-issuance record closed before its token was spent'),
          { code: 'PEERIT_POW_ISSUANCE_RECORD_CLOSED' })
        for (const entry of pending.values()) entry.reject(error)
        pending.clear()
        rejectComplete(error)
      }
    })

    openRecord = session
    return session
  }

  // The seam contract: relay-consumer admissionProviderFor invokes this once
  // per PUT-qualified relay and wraps the returned provider with its own
  // profileId/schemeId/parameterHash drift checks. The parameterHash is
  // relay-specific and descriptor-driven: it always echoes the relay's own
  // verified pow-issuance parameters, never a release-pinned file.
  async function createAdmissionProvider (input = {}) {
    const admissionProfile = input.admissionProfile
    if (!admissionProfile || admissionProfile.schemeId !== schemeId ||
        admissionProfile.profileId !== profileId || admissionProfile.parameterUrl != null) {
      fail('PEERIT_POW_ISSUANCE_PROFILE_DRIFT',
        'the relay did not advertise the exact signed pow-issuance admission profile')
    }
    const verified = input.verifiedAdmissionParameters
    if (!verified || typeof verified !== 'object') {
      fail('PEERIT_POW_ISSUANCE_PARAMETERS_UNTRUSTED', 'verified relay admission parameters are required')
    }
    const parameterHash = fixedBytesValue(verified.parameterHash, 32, 'verifiedAdmissionParameters.parameterHash')
    const context = input.endpointContext
    const relayPublicKey = context && context.relayPublicKey != null
      ? fixedBytesValue(context.relayPublicKey, 32, 'endpointContext.relayPublicKey')
      : null
    const issuer = relayPublicKey && issuers.find(row => bytesEqual(row.relayPublicKey, relayPublicKey))
    if (!issuer) {
      fail('PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY',
        'the qualified relay is not one of the signed profile issuer pins')
    }
    const qualificationSignal = input.signal
    return async function powIssuanceAdmissionProvider (putContext) {
      if (!putContext || putContext.familyId !== 2 || putContext.operationId !== 1) {
        fail('PEERIT_POW_ISSUANCE_OPERATION_INVALID',
          'pow-issuance spend providers only admit CELL.PUT (family 2, operation 1)')
      }
      if (!bytesEqual(asBytes(putContext.relayPublicKey, 'relayPublicKey'), issuer.relayPublicKey)) {
        fail('PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY',
          'a CELL.PUT context crossed relay identity inside one provider')
      }
      if (!openRecord) {
        fail('PEERIT_POW_ISSUANCE_NO_OPEN_RECORD',
          'no open pow-issuance record covers this CELL.PUT; writes begin with an explicit user action')
      }
      const spent = await openRecord.spend(putContext, qualificationSignal)
      return Object.freeze({
        profileId,
        schemeId,
        parameterHash,
        token: spent.presentation
      })
    }
  }

  return Object.freeze({
    profileId,
    schemeId,
    issuers,
    createAdmissionProvider,
    beginRecord,
    beginOperationRecord,
    closeOpenRecord () {
      if (openRecord) openRecord.close()
    }
  })
}
