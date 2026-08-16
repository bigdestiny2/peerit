// Sequence-29 encrypted public-INBOX transport frame. This is the runtime
// counterpart of protocol/seq29-limited-public-test's accepted frame codec:
// HKDF-SHA256 binds the release bootstrap, relay, epoch, stripe, and topic;
// XChaCha20-Poly1305 authenticates an INLINE signed announcement plus random
// padding in one exact 4096-byte frame.
import { xchacha20poly1305 } from '../vendor/noble-ciphers/chacha.js'
import {
  asciiBytes,
  asBytes,
  bytesEqual,
  concatBytes,
  u32Bytes
} from './release-control-primitives.mjs'
import { isVerifiedPeeritLimitedPublicInboxBootstrapV1 } from './inbox-topic-v1.mjs'

export const PEERIT_INBOX_ANNOUNCEMENT_FRAME_VERSION_V1 = 1
export const PEERIT_INBOX_ANNOUNCEMENT_FRAME_CLASS_V1 = 1
export const PEERIT_INBOX_ANNOUNCEMENT_FRAME_BYTES_V1 = 4096
export const PEERIT_INBOX_ANNOUNCEMENT_NONCE_BYTES_V1 = 24
export const PEERIT_INBOX_ANNOUNCEMENT_TAG_BYTES_V1 = 16
export const PEERIT_INBOX_ANNOUNCEMENT_PLAINTEXT_BYTES_V1 =
  PEERIT_INBOX_ANNOUNCEMENT_FRAME_BYTES_V1 - PEERIT_INBOX_ANNOUNCEMENT_NONCE_BYTES_V1 -
  PEERIT_INBOX_ANNOUNCEMENT_TAG_BYTES_V1
export const PEERIT_INBOX_ANNOUNCEMENT_MAX_BYTES_V1 =
  PEERIT_INBOX_ANNOUNCEMENT_PLAINTEXT_BYTES_V1 - 4

const KEY_DOMAIN = asciiBytes('peerit.hiverelay.inbox-frame-key.v1')
const AAD_DOMAIN = asciiBytes('peerit.hiverelay.inbox-frame-aad.v1')

function fail (message, cause) {
  const error = new Error(message)
  error.code = 'PEERIT_INBOX_ANNOUNCEMENT_FRAME_INVALID'
  if (cause !== undefined) error.cause = cause
  throw error
}

function bindingFor (authority, binding) {
  if (!isVerifiedPeeritLimitedPublicInboxBootstrapV1(authority)) {
    fail('verified sequence-29 bootstrap authority is required')
  }
  if (!authority.bindings.includes(binding)) {
    fail('frame binding does not belong to the verified bootstrap authority')
  }
  if (binding.inboxEpoch !== authority.inboxEpoch || binding.stripeIndex !== 0) {
    fail('frame binding epoch or stripe differs from the verified bootstrap')
  }
  return binding
}

function bytes (value, length, field) {
  let output
  try { output = new Uint8Array(asBytes(value, field)) } catch (cause) {
    fail(`${field} must be bytes`, cause)
  }
  if (length != null && output.byteLength !== length) fail(`${field} must be exactly ${length} bytes`)
  return output
}

function randomBytes (length) {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    fail('secure browser randomness is unavailable')
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length))
}

async function hkdfSha256 (ikm, salt, info) {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) fail('WebCrypto HKDF-SHA256 is unavailable')
  let key
  try {
    key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
    return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256))
  } catch (cause) {
    fail('frame HKDF-SHA256 derivation failed', cause)
  }
}

export function peeritInboxAnnouncementFrameAadV1 ({ authority, binding }) {
  bindingFor(authority, binding)
  return concatBytes(
    AAD_DOMAIN,
    u32Bytes(authority.inboxEpoch),
    Uint8Array.of(binding.stripeIndex),
    binding.relayPublicKey,
    binding.physicalTopic,
    Uint8Array.of(PEERIT_INBOX_ANNOUNCEMENT_FRAME_CLASS_V1)
  )
}

export async function derivePeeritInboxAnnouncementFrameKeyV1 ({ authority, binding }) {
  bindingFor(authority, binding)
  const info = concatBytes(
    KEY_DOMAIN,
    u32Bytes(authority.inboxEpoch),
    Uint8Array.of(binding.stripeIndex),
    binding.relayPublicKey
  )
  return hkdfSha256(authority.announcementMasterKey, binding.physicalTopic, info)
}

function fixtureBytes (input, field, length) {
  if (input[field] == null) return null
  if (input.allowFixtureValues !== true || input.authority.artifactClass !== 'FIXTURE_ONLY') {
    fail(`${field} may only be injected for an explicitly fixture-only authority`)
  }
  return bytes(input[field], length, field)
}

export async function sealPeeritInboxAnnouncementFrameV1 (input = {}) {
  const { authority, binding } = input
  bindingFor(authority, binding)
  const announcement = bytes(input.announcementBytes, null, 'announcementBytes')
  if (announcement.byteLength < 1 || announcement.byteLength > PEERIT_INBOX_ANNOUNCEMENT_MAX_BYTES_V1) {
    fail(`announcementBytes must contain 1..${PEERIT_INBOX_ANNOUNCEMENT_MAX_BYTES_V1} bytes`)
  }
  const paddingLength = PEERIT_INBOX_ANNOUNCEMENT_PLAINTEXT_BYTES_V1 - 4 - announcement.byteLength
  const nonce = fixtureBytes(input, 'nonce', PEERIT_INBOX_ANNOUNCEMENT_NONCE_BYTES_V1) ||
    randomBytes(PEERIT_INBOX_ANNOUNCEMENT_NONCE_BYTES_V1)
  const padding = fixtureBytes(input, 'padding', paddingLength) || randomBytes(paddingLength)
  const plaintext = new Uint8Array(PEERIT_INBOX_ANNOUNCEMENT_PLAINTEXT_BYTES_V1)
  plaintext.set(u32Bytes(announcement.byteLength), 0)
  plaintext.set(announcement, 4)
  plaintext.set(padding, 4 + announcement.byteLength)
  const key = await derivePeeritInboxAnnouncementFrameKeyV1({ authority, binding })
  try {
    const sealed = xchacha20poly1305(key, nonce, peeritInboxAnnouncementFrameAadV1({ authority, binding }))
      .encrypt(plaintext)
    const frame = concatBytes(nonce, sealed)
    if (frame.byteLength !== PEERIT_INBOX_ANNOUNCEMENT_FRAME_BYTES_V1) fail('sealed frame length is invalid')
    return frame
  } catch (cause) {
    if (cause?.code === 'PEERIT_INBOX_ANNOUNCEMENT_FRAME_INVALID') throw cause
    fail('XChaCha20-Poly1305 frame sealing failed', cause)
  } finally {
    key.fill(0)
    plaintext.fill(0)
    padding.fill(0)
  }
}

export async function openPeeritInboxAnnouncementFrameV1 (input = {}) {
  const { authority, binding } = input
  bindingFor(authority, binding)
  const frame = bytes(input.frame, PEERIT_INBOX_ANNOUNCEMENT_FRAME_BYTES_V1, 'frame')
  const nonce = frame.subarray(0, PEERIT_INBOX_ANNOUNCEMENT_NONCE_BYTES_V1)
  const ciphertext = frame.subarray(PEERIT_INBOX_ANNOUNCEMENT_NONCE_BYTES_V1)
  const key = await derivePeeritInboxAnnouncementFrameKeyV1({ authority, binding })
  let plaintext
  try {
    plaintext = xchacha20poly1305(key, nonce, peeritInboxAnnouncementFrameAadV1({ authority, binding }))
      .decrypt(ciphertext)
    if (plaintext.byteLength !== PEERIT_INBOX_ANNOUNCEMENT_PLAINTEXT_BYTES_V1) {
      fail('decrypted frame plaintext length is invalid')
    }
    const announcementLength = ((plaintext[0] * 0x1000000) + (plaintext[1] << 16) +
      (plaintext[2] << 8) + plaintext[3]) >>> 0
    if (announcementLength < 1 || announcementLength > PEERIT_INBOX_ANNOUNCEMENT_MAX_BYTES_V1) {
      fail('decrypted announcement length is invalid')
    }
    return plaintext.slice(4, 4 + announcementLength)
  } catch (cause) {
    if (cause?.code === 'PEERIT_INBOX_ANNOUNCEMENT_FRAME_INVALID') throw cause
    fail('XChaCha20-Poly1305 frame authentication failed', cause)
  } finally {
    key.fill(0)
    if (plaintext != null) plaintext.fill(0)
  }
}

export function peeritInboxAnnouncementFrameMatchesBindingV1 (left, right) {
  return left.inboxEpoch === right.inboxEpoch && left.stripeIndex === right.stripeIndex &&
    bytesEqual(left.relayPublicKey, right.relayPublicKey) && bytesEqual(left.physicalTopic, right.physicalTopic)
}
