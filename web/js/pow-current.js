// Current Peerit proof-of-work rules. This module contains no historical
// inventory, endpoint, migration, or relay dependency and is the only PoW code
// shipped in the replacement browser product.

export const MIN_BITS = Object.freeze({
  post: 16,
  comment: 14,
  community: 18,
  blob: 12,
  report: 12
})

export const POW_VERSION = 2

export function powTargetV1 (type, data) {
  switch (type) {
    case 'post':
      return `post|${data.community}|${data.cid}|${data.author}|${data.createdAt}`
    case 'comment':
      return `comment|${data.community}|${data.postCid}|${data.cid}|${data.author}|${data.createdAt}`
    case 'community':
      return `community|${data.slug}|${data.creator}|${data.createdAt}`
    case 'blob':
      return `blob|${data.blobId}|${data.author}`
    default:
      return type + '|' + (data.author || data.creator || '')
  }
}

export function powTargetV2 (type, data) {
  const id = data && data.id != null ? String(data.id) : ''
  const createdAt = data && data.createdAt != null ? String(data.createdAt) : ''
  return `v2|${id}|${type}|${createdAt}`
}

export function powTargetForVersion (type, data, version) {
  const value = Number(version)
  if (Number.isFinite(value) && value >= 2) return powTargetV2(type, data)
  return powTargetV1(type, data)
}

export function powTarget (type, data) {
  return powTargetV2(type, data)
}

export function leadingZeroBits (bytes) {
  let bits = 0
  for (let index = 0; index < bytes.length; index++) {
    const byte = bytes[index]
    if (byte === 0) {
      bits += 8
      continue
    }
    bits += Math.clz32(byte) - 24
    break
  }
  return bits
}

async function sha256 (value) {
  const runtime = globalThis.crypto && globalThis.crypto.subtle
  if (!runtime) throw new Error('secure SHA-256 is unavailable')
  const digest = await runtime.digest('SHA-256', new TextEncoder().encode(value))
  return new Uint8Array(digest)
}

// WebCrypto is deliberately asynchronous. Awaiting every candidate serially
// pays that boundary cost once per nonce and is disproportionately slow in
// Firefox. A small fixed batch preserves the exact ascending nonce search (and
// therefore the first valid proof) while allowing the browser to schedule hash
// work efficiently. The batch divides the existing 1024-candidate progress and
// cancellation boundary, so responsiveness and observable progress do not
// change.
const HASH_BATCH_SIZE = 64

async function sha256Batch (prefix, firstNonce) {
  const pending = new Array(HASH_BATCH_SIZE)
  for (let offset = 0; offset < pending.length; offset++) {
    pending[offset] = sha256(prefix + (firstNonce + offset))
  }
  return Promise.all(pending)
}

function hex (bytes) {
  let output = ''
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0')
  return output
}

export async function mint (type, data, bits, options = {}) {
  const version = options.version != null ? Number(options.version) : POW_VERSION
  const target = powTargetForVersion(type, data, version)
  const targetHash = hex(await sha256(target))
  const prefix = target + '|'
  let nonce = 0
  for (;;) {
    const digests = await sha256Batch(prefix, nonce)
    for (let offset = 0; offset < digests.length; offset++) {
      if (leadingZeroBits(digests[offset]) >= bits) {
        return { bits, nonce: nonce + offset, targetHash, v: version }
      }
    }
    nonce += HASH_BATCH_SIZE
    if ((nonce & 1023) === 0) {
      if (options.onProgress) options.onProgress(nonce)
      if (options.signal && options.signal.aborted) throw new Error('proof-of-work cancelled')
      await new Promise(resolve => setTimeout(resolve, 0))
    }
  }
}

export async function verify (type, data, minBits) {
  const proof = data && data.pow
  if (!proof || typeof proof.bits !== 'number' || typeof proof.nonce !== 'number') return false
  if (proof.bits < minBits) return false
  const version = proof.v != null ? Number(proof.v) : 1
  if (!Number.isFinite(version) || version < 1) return false
  const target = powTargetForVersion(type, data, version)
  if (proof.targetHash != null) {
    if (typeof proof.targetHash !== 'string' || proof.targetHash.length !== 64) return false
    if (proof.targetHash !== hex(await sha256(target))) return false
  }
  const digest = await sha256(target + '|' + proof.nonce)
  return leadingZeroBits(digest) >= proof.bits
}
