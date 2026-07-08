// pow.js - proof-of-work spam gate (hashcash).
//
// Posts, comments, and community creation carry a small SHA-256 proof bound to
// the record's immutable identity. The proof is part of the signed record and is
// re-verified by every peer on ingest through gossip's validate hook.

export const MIN_BITS = {
  post: 16,
  comment: 14,
  community: 18,
  // BlindShard blobs (opaque bodies) carry a modest proof so a peer can't cheaply
  // flood the outbox/census with large content-addressed appends (review FIX 3).
  blob: 12
}

export function powTarget (type, data) {
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

export function leadingZeroBits (u8) {
  let n = 0
  for (let i = 0; i < u8.length; i++) {
    const b = u8[i]
    if (b === 0) {
      n += 8
      continue
    }
    n += Math.clz32(b) - 24
    break
  }
  return n
}

async function sha256 (str) {
  const buf = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return new Uint8Array(buf)
}

function hex (u8) {
  let out = ''
  for (const b of u8) out += b.toString(16).padStart(2, '0')
  return out
}

export async function mint (type, data, bits, opts = {}) {
  const target = powTarget(type, data)
  const targetHash = hex(await sha256(target))
  let nonce = 0
  for (;;) {
    const h = await sha256(target + '|' + nonce)
    if (leadingZeroBits(h) >= bits) return { bits, nonce, targetHash }
    nonce++
    if ((nonce & 1023) === 0) {
      if (opts.onProgress) opts.onProgress(nonce)
      if (opts.signal && opts.signal.aborted) throw new Error('proof-of-work cancelled')
      await new Promise(resolve => setTimeout(resolve, 0))
    }
  }
}

export async function verify (type, data, minBits) {
  const pow = data && data.pow
  if (!pow || typeof pow.bits !== 'number' || typeof pow.nonce !== 'number') return false
  if (pow.bits < minBits) return false
  const target = powTarget(type, data)
  if (pow.targetHash != null) {
    if (typeof pow.targetHash !== 'string' || pow.targetHash.length !== 64) return false
    if (pow.targetHash !== hex(await sha256(target))) return false
  }
  const h = await sha256(target + '|' + pow.nonce)
  return leadingZeroBits(h) >= pow.bits
}

export function makeValidator (minBits = MIN_BITS) {
  return async (type, val) => {
    if (type === 'post') return verify(type, val, minBits.post)
    if (type === 'comment') return verify(type, val, minBits.comment)
    if (type === 'community') return verify(type, val, minBits.community)
    if (type === 'blob') return verify(type, val, minBits.blob)
    return true
  }
}
