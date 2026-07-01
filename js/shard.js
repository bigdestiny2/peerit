// shard.js — BlindShard erasure + placement primitive (Phase 3, §1/§3b/§4/§5).
//
// The dispersal step of BlindShard: take opaque AEAD *ciphertext* (never
// plaintext — this module never sees a key), erasure-code it K-of-N with a
// systematic Reed-Solomon code (any K of N shards reconstruct), content-address
// each shard by SHA-256 (self-verifying — a relay cannot substitute a shard
// without the reader detecting it), and deterministically place shards across a
// signed relay roster via HRW/rendezvous hashing under the load-bearing
// invariant: NO relay is assigned >= K shards of one item, so no single relay
// can reconstruct (§1 "key separation / blindness collapse if one relay holds
// >= K shards").
//
// DEPENDENCY-INJECTED by design (§4 net-new #4/#6):
//   * `codec`   — the Reed-Solomon implementation. A working pure-JS reference
//                 codec (`referenceCodec`) ships here so the module is testable
//                 today; PRODUCTION injects a WASM RS (reed-solomon-erasure /
//                 zfec-style GF(2^8)) with the SAME interface — nothing else in
//                 this module changes when it swaps in.
//   * backend   — this module produces/consumes plain shard byte-arrays + their
//                 content-addressed ids. It does NOT talk to any store. The
//                 HiveRelay blind-blob surface (the net-new `shard:<hash>` PUT/
//                 GET, §4 #5) is a SEPARATE backend the caller injects; encode/
//                 place hand it (id -> bytes) pairs, decode consumes gathered
//                 bytes. Standalone primitive: no gossip/canon/relay-pool wiring.
//
// SIZE GATE (§3b/§4): erasure is only worth it for sizeable bodies — gate to
// ciphertext >= ~8 KiB. Below that, keep the body inline / single-blob (Phase 2)
// and DO NOT shard. `SHARD_MIN_BYTES` + `shouldErasure()` express the gate; this
// module still *works* on tiny inputs (tests exercise both) but callers should
// consult the gate before spending erasure CPU.
//
// TEARDOWN: the pure functions here allocate no long-lived resources. A codec
// MAY hold WASM memory / a worker; if a codec exposes `destroy()`/`free()` we
// surface it via `destroyCodec(codec)` so callers can release it explicitly
// (mafintosh: explicit teardown). The reference codec needs none (returns false).

// ---------------------------------------------------------------------------
// Codec interface (what an injected RS backend must provide)
// ---------------------------------------------------------------------------
//
//   codec.encode(dataShards: Uint8Array[], parityCount: number) -> Uint8Array[]
//       Given K equal-length DATA shards, return the `parityCount` PARITY
//       shards (systematic: the data shards are unchanged and NOT returned).
//
//   codec.reconstruct(present: (Uint8Array|null)[], k: number) -> Uint8Array[]
//       `present` has length N; each slot is the shard bytes if available or
//       null if missing. At least K non-null. Returns the K reconstructed DATA
//       shards (indices 0..K-1), from which the original bytes are un-padded.
//
//   codec.destroy?() -> void   (optional; released via destroyCodec)
//
// Both operate on raw bytes only; they never see keys or plaintext.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Erasure size gate: bodies (ciphertext) smaller than this stay inline / single
// blob (Phase 2). ~8 KiB per §3b — below it the 1.5x blowup + K-parallel-get
// retrieval cost isn't justified.
export const SHARD_MIN_BYTES = 8 * 1024

// A 4-byte big-endian length header we prepend to the ciphertext before
// splitting into K data shards, so decode() can strip zero-padding exactly and
// return the ciphertext byte-for-byte regardless of which shards were dropped.
const LEN_HEADER = 4

export function shouldErasure (byteLength, min = SHARD_MIN_BYTES) {
  return byteLength >= min
}

// ---------------------------------------------------------------------------
// Bytes-in SHA-256 (crypto.js `hashHex` is UTF-8/string-only — §3b/§4 #2 note
// content-addressing needs a bytes path). Self-contained, same backend ladder.
// ---------------------------------------------------------------------------

let _nodeCrypto = null
async function sha256Bytes (bytes) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle
  if (subtle) {
    try { return new Uint8Array(await subtle.digest('SHA-256', bytes)) } catch {}
  }
  if (!_nodeCrypto) {
    try { const mod = await import('node:crypto'); _nodeCrypto = mod.default || mod } catch {}
  }
  if (_nodeCrypto) {
    return new Uint8Array(_nodeCrypto.createHash('sha256').update(Buffer.from(bytes)).digest())
  }
  throw new Error('shard.js: no SHA-256 backend (need SubtleCrypto or node:crypto)')
}

const toHex = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s }
const fromHex = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a }

// shardId(shard) = SHA-256(shard) as hex. Self-verifying: any holder recomputes
// it; a substituted shard fails the check and the reader routes around it.
export async function shardId (shardBytes) {
  return toHex(await sha256Bytes(shardBytes))
}

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic for the reference Reed-Solomon codec.
// Field: 0x11D (x^8 + x^4 + x^3 + x^2 + 1), the same polynomial zfec/Storj use.
// ---------------------------------------------------------------------------

const GF_EXP = new Uint8Array(512)
const GF_LOG = new Uint8Array(256)
;(function initGF () {
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11D
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]
})()

const gfMul = (a, b) => (a === 0 || b === 0) ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]
const gfDiv = (a, b) => {
  if (b === 0) throw new Error('gf div by zero')
  if (a === 0) return 0
  return GF_EXP[(GF_LOG[a] + 255 - GF_LOG[b]) % 255]
}

// Build the N x K systematic generator matrix: the top KxK block is the
// identity (systematic — data shards pass through unchanged), the bottom
// (N-K)xK block is a Vandermonde-derived block giving any-K-reconstruct.
// We use a Vandermonde matrix and never need to invert the identity rows, so
// any K rows of this matrix are invertible (Cauchy/Vandermonde MDS property).
function buildGenerator (k, n) {
  // Vandermonde matrix over GF(2^8) with distinct nonzero evaluation points
  // a_i = i+1: V[i][j] = a_i^j. Any K rows are linearly independent (MDS), which
  // is exactly the any-K-of-N reconstruct property. n <= 255 keeps a_i distinct.
  const rows = []
  for (let i = 0; i < n; i++) {
    const row = new Uint8Array(k)
    let val = 1
    const a = i + 1
    for (let j = 0; j < k; j++) { row[j] = val; val = gfMul(val, a) }
    rows.push(row)
  }
  // Systematic transform: invert the top KxK Vandermonde block and multiply the
  // whole matrix by that inverse, so the top block becomes the identity (data
  // shards pass through unchanged; the happy path is a concat, no GF math).
  const top = rows.slice(0, k).map(r => Uint8Array.from(r))
  const inv = invertMatrix(top, k)
  const gen = rows.map(r => matVecRow(r, inv, k))
  return gen // n rows, each length k
}

// Multiply row vector (length k) by KxK matrix `m` -> row vector length k.
function matVecRow (row, m, k) {
  const out = new Uint8Array(k)
  for (let j = 0; j < k; j++) {
    let acc = 0
    for (let t = 0; t < k; t++) acc ^= gfMul(row[t], m[t][j])
    out[j] = acc
  }
  return out
}

// Invert a KxK GF(2^8) matrix via Gauss-Jordan. Throws if singular.
function invertMatrix (src, k) {
  const m = src.map(r => Uint8Array.from(r))
  const inv = []
  for (let i = 0; i < k; i++) { const r = new Uint8Array(k); r[i] = 1; inv.push(r) }
  for (let col = 0; col < k; col++) {
    let pivot = col
    while (pivot < k && m[pivot][col] === 0) pivot++
    if (pivot === k) throw new Error('shard.js: singular matrix (non-invertible shard selection)')
    if (pivot !== col) { [m[pivot], m[col]] = [m[col], m[pivot]];[inv[pivot], inv[col]] = [inv[col], inv[pivot]] }
    const pv = m[col][col]
    for (let j = 0; j < k; j++) { m[col][j] = gfDiv(m[col][j], pv); inv[col][j] = gfDiv(inv[col][j], pv) }
    for (let row = 0; row < k; row++) {
      if (row === col) continue
      const factor = m[row][col]
      if (factor === 0) continue
      for (let j = 0; j < k; j++) {
        m[row][j] ^= gfMul(factor, m[col][j])
        inv[row][j] ^= gfMul(factor, inv[col][j])
      }
    }
  }
  return inv
}

// ---------------------------------------------------------------------------
// Reference codec (pure JS, systematic RS). PRODUCTION swaps a WASM RS in here.
// ---------------------------------------------------------------------------

export const referenceCodec = {
  name: 'reference-gf256-rs',

  // dataShards: K equal-length Uint8Arrays. Returns N-K parity shards.
  encode (dataShards, parityCount) {
    const k = dataShards.length
    const n = k + parityCount
    const shardLen = dataShards[0].length
    const gen = buildGenerator(k, n)
    const parity = []
    for (let p = 0; p < parityCount; p++) {
      const genRow = gen[k + p] // row in the parity block
      const out = new Uint8Array(shardLen)
      for (let t = 0; t < k; t++) {
        const coeff = genRow[t]
        if (coeff === 0) continue
        const ds = dataShards[t]
        for (let b = 0; b < shardLen; b++) out[b] ^= gfMul(coeff, ds[b])
      }
      parity.push(out)
    }
    return parity
  },

  // present: length-N array, each slot bytes-or-null (>= K non-null). Returns
  // the K reconstructed DATA shards (indices 0..K-1).
  reconstruct (present, k) {
    const n = present.length
    const parityCount = n - k
    const shardLen = (present.find(s => s) || new Uint8Array(0)).length
    // Fast path: all K data shards present -> systematic, no GF math (§3b).
    let allData = true
    for (let i = 0; i < k; i++) if (!present[i]) { allData = false; break }
    if (allData) {
      const out = []
      for (let i = 0; i < k; i++) out.push(present[i])
      return out
    }
    // General path: pick any K available shards, invert their KxK generator
    // sub-matrix, and solve for the K data shards.
    const gen = buildGenerator(k, n)
    const chosenRows = []
    const chosenIdx = []
    for (let i = 0; i < n && chosenRows.length < k; i++) {
      if (present[i]) { chosenRows.push(gen[i]); chosenIdx.push(i) }
    }
    if (chosenRows.length < k) throw new Error(`shard.js: only ${chosenRows.length} of ${k} shards present — cannot reconstruct`)
    const sub = chosenRows.map(r => Uint8Array.from(r))
    const inv = invertMatrix(sub, k)
    // data = inv * chosenShards
    const data = []
    for (let i = 0; i < k; i++) data.push(new Uint8Array(shardLen))
    for (let b = 0; b < shardLen; b++) {
      for (let i = 0; i < k; i++) {
        let acc = 0
        for (let t = 0; t < k; t++) acc ^= gfMul(inv[i][t], present[chosenIdx[t]][b])
        data[i][b] = acc
      }
    }
    return data
  }
}

export function destroyCodec (codec) {
  if (codec && typeof codec.destroy === 'function') { codec.destroy(); return true }
  if (codec && typeof codec.free === 'function') { codec.free(); return true }
  return false
}

// ---------------------------------------------------------------------------
// encode / decode
// ---------------------------------------------------------------------------

// Split ciphertext (with a 4-byte length header) into K equal-length data
// shards (zero-padded), so any-K reconstruct + exact un-pad on decode.
function splitIntoDataShards (ciphertext, k) {
  const total = LEN_HEADER + ciphertext.length
  const shardLen = Math.ceil(total / k)
  const framed = new Uint8Array(shardLen * k) // zero-padded
  // big-endian length header
  framed[0] = (ciphertext.length >>> 24) & 0xff
  framed[1] = (ciphertext.length >>> 16) & 0xff
  framed[2] = (ciphertext.length >>> 8) & 0xff
  framed[3] = ciphertext.length & 0xff
  framed.set(ciphertext, LEN_HEADER)
  const shards = []
  for (let i = 0; i < k; i++) shards.push(framed.subarray(i * shardLen, (i + 1) * shardLen))
  return { shards, shardLen }
}

/**
 * encode(ciphertextBytes, { k, n, codec }) -> Promise<shard[]>
 * Systematic Reed-Solomon: returns N shards (K data + N-K parity), each
 *   { index, bytes: Uint8Array, id: hex(SHA-256(bytes)) }.
 * Any K of the N shards reconstruct the original ciphertext exactly.
 * The `codec` is injected; defaults to the pure-JS reference codec.
 */
export async function encode (ciphertextBytes, { k, n, codec = referenceCodec } = {}) {
  if (!(ciphertextBytes instanceof Uint8Array)) ciphertextBytes = new Uint8Array(ciphertextBytes)
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 1 || n < k) {
    throw new Error(`shard.js: bad k/n (k=${k}, n=${n}); require 1<=k<=n`)
  }
  if (n > 255) throw new Error('shard.js: reference codec supports n<=255')
  const { shards: dataShards, shardLen } = splitIntoDataShards(ciphertextBytes, k)
  const parity = codec.encode(dataShards, n - k)
  const all = []
  for (let i = 0; i < k; i++) all.push(dataShards[i])
  for (let i = 0; i < parity.length; i++) all.push(parity[i])
  // Materialize + content-address. (subarray views -> owned copies for ids.)
  const out = []
  for (let i = 0; i < n; i++) {
    const bytes = Uint8Array.from(all[i])
    out.push({ index: i, bytes, id: await shardId(bytes), shardLen })
  }
  return out
}

/**
 * decode(shards, { k, n, codec }) -> Promise<Uint8Array> (the ciphertext).
 * `shards` is any subset (>= K) of encode()'s output; each item must carry its
 * `index` (0..n-1) and `bytes`. Missing indices are treated as erased.
 * Reconstructs the K data shards, strips padding via the length header, and
 * returns the ciphertext byte-for-byte.
 */
export async function decode (shards, { k, n, codec = referenceCodec } = {}) {
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 1 || n < k) {
    throw new Error(`shard.js: bad k/n (k=${k}, n=${n})`)
  }
  const present = new Array(n).fill(null)
  let count = 0
  for (const s of shards) {
    if (!s || s.index == null || !s.bytes) continue
    if (s.index < 0 || s.index >= n) throw new Error(`shard.js: shard index ${s.index} out of range 0..${n - 1}`)
    if (present[s.index]) continue // dedupe
    present[s.index] = s.bytes instanceof Uint8Array ? s.bytes : new Uint8Array(s.bytes)
    count++
  }
  if (count < k) throw new Error(`shard.js: have ${count} shards, need ${k} to reconstruct`)
  const dataShards = codec.reconstruct(present, k)
  // Reassemble framed buffer and strip the length header + padding.
  const shardLen = dataShards[0].length
  const framed = new Uint8Array(shardLen * k)
  for (let i = 0; i < k; i++) framed.set(dataShards[i], i * shardLen)
  const len = (framed[0] << 24) | (framed[1] << 16) | (framed[2] << 8) | framed[3]
  if (len < 0 || len > framed.length - LEN_HEADER) throw new Error('shard.js: corrupt length header on reconstruct')
  return framed.subarray(LEN_HEADER, LEN_HEADER + len)
}

// ---------------------------------------------------------------------------
// place() — deterministic HRW/rendezvous shard placement (§1, §3a, §4 #6)
// ---------------------------------------------------------------------------

/**
 * place(shardIds, roster, { replicas, k }) -> Promise<Map<relayPub, shardId[]>>
 *
 * Deterministic HRW (Highest-Random-Weight / rendezvous) placement: for each
 * shard, relays are RANKED by SHA-256(relayPub ‖ shardId) and the top
 * `replicas` win. Any reader recomputes the identical assignment from the same
 * signed roster (auditability — §3a).
 *
 * INVARIANT (load-bearing, §1 blindness): no relay may be assigned >= K shards
 * of one item. If HRW would push a relay to K shards, that shard skips to the
 * next-ranked relay under the cap. This keeps every relay strictly below the
 * reconstruction threshold, so no single relay can reassemble the item — the
 * whole point of dispersal. Throws if the roster is too small to satisfy both
 * `replicas` per shard AND the < K cap.
 *
 * `roster` is an array of relay identifiers (pubkey hex strings) OR objects
 * with a `.pub`/`.publicKey` field. Order-independent (HRW is by hash).
 */
export async function place (shardIds, roster, { replicas = 1, k } = {}) {
  const relays = roster.map(r => (typeof r === 'string' ? r : (r.pub || r.publicKey || r.key)))
  if (relays.some(r => typeof r !== 'string' || !r)) throw new Error('shard.js: roster entries must be pubkey strings or {pub}')
  const R = relays.length
  const cap = (k == null) ? Infinity : k - 1 // < k shards per relay
  if (replicas > R) throw new Error(`shard.js: replicas=${replicas} > roster size ${R}`)

  // Feasibility: total shard-placements = shardIds.length * replicas must fit
  // under R relays each holding at most `cap` shards.
  if (cap !== Infinity && shardIds.length * replicas > R * cap) {
    throw new Error(`shard.js: roster too small — ${shardIds.length} shards x ${replicas} replicas needs > ${R} relays x (k-1)=${cap} capacity`)
  }

  // Precompute HRW rank of every (relay, shard) pair, then assign per shard in
  // rank order, skipping relays already at the cap. Deterministic given roster.
  const assignment = new Map() // relayPub -> shardId[]
  const load = new Map() // relayPub -> count
  for (const r of relays) { assignment.set(r, []); load.set(r, 0) }

  for (const sid of shardIds) {
    // rank relays for this shard by HRW weight (ascending hex hash = highest
    // weight first; any total order works as long as it's deterministic).
    const ranked = []
    for (const r of relays) {
      const w = toHex(await sha256Bytes(concatBytes(fromHexLoose(r), fromHexLoose(sid))))
      ranked.push({ r, w })
    }
    ranked.sort((a, b) => (a.w < b.w ? -1 : a.w > b.w ? 1 : 0))
    let placed = 0
    for (const { r } of ranked) {
      if (placed >= replicas) break
      if (load.get(r) >= cap) continue // enforce < k invariant
      assignment.get(r).push(sid)
      load.set(r, load.get(r) + 1)
      placed++
    }
    if (placed < replicas) {
      throw new Error(`shard.js: could not place ${replicas} replicas of ${sid.slice(0, 12)}… under the <k cap (roster exhausted)`)
    }
  }
  // Drop relays that got nothing, for a clean map.
  for (const r of relays) if (assignment.get(r).length === 0) assignment.delete(r)
  return assignment
}

// Accept either hex strings (pubkeys/shardIds) or raw byte arrays for hashing.
function fromHexLoose (v) {
  if (v instanceof Uint8Array) return v
  if (typeof v === 'string' && /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return fromHex(v)
  // non-hex string: hash its UTF-8 bytes (keeps determinism for arbitrary ids)
  return new TextEncoder().encode(String(v))
}
function concatBytes (a, b) { const u = new Uint8Array(a.length + b.length); u.set(a, 0); u.set(b, a.length); return u }

export const _internal = { buildGenerator, invertMatrix, gfMul, gfDiv, sha256Bytes, splitIntoDataShards }
