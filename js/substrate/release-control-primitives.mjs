const MAX_U64 = (1n << 64n) - 1n
const MASK_64 = MAX_U64

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: true })

export function failReleaseControl (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

export function asBytes (value, field = 'value') {
  if (value instanceof Uint8Array) return value
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be bytes`)
}

export function fixedBytesValue (value, length, field) {
  value = asBytes(value, field)
  if (value.byteLength !== length) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be exactly ${length} bytes`)
  }
  return value
}

export function isAllZero (value) {
  value = asBytes(value)
  for (const byte of value) if (byte !== 0) return false
  return true
}

export function bytesEqual (left, right) {
  left = asBytes(left, 'left bytes')
  right = asBytes(right, 'right bytes')
  if (left.byteLength !== right.byteLength) return false
  let difference = 0
  for (let i = 0; i < left.byteLength; i++) difference |= left[i] ^ right[i]
  return difference === 0
}

export function compareBytes (left, right) {
  left = asBytes(left, 'left bytes')
  right = asBytes(right, 'right bytes')
  const length = Math.min(left.byteLength, right.byteLength)
  for (let i = 0; i < length; i++) {
    if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1
  }
  if (left.byteLength === right.byteLength) return 0
  return left.byteLength < right.byteLength ? -1 : 1
}

export function concatBytes (...values) {
  const arrays = values.flat().map((value, index) => asBytes(value, `bytes[${index}]`))
  const length = arrays.reduce((total, value) => total + value.byteLength, 0)
  const output = new Uint8Array(length)
  let offset = 0
  for (const value of arrays) {
    output.set(value, offset)
    offset += value.byteLength
  }
  return output
}

export function asciiBytes (value, field = 'ASCII value') {
  if (typeof value !== 'string' || /[^\x20-\x7e]/.test(value)) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be printable ASCII`)
  }
  return textEncoder.encode(value)
}

export function utf8Bytes (value, field = 'UTF-8 value') {
  if (typeof value !== 'string' || value !== value.normalize('NFC')) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be NFC text`)
  }
  return textEncoder.encode(value)
}

export function decodeUtf8 (value, field = 'UTF-8 bytes') {
  try {
    const decoded = textDecoder.decode(asBytes(value, field))
    if (decoded !== decoded.normalize('NFC')) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} is not NFC`)
    }
    return decoded
  } catch (error) {
    if (error && error.code) throw error
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} is not valid UTF-8`)
  }
}

export function asU64 (value, field = 'u64') {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be an unsigned safe integer or bigint`)
    }
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} is outside u64`)
  }
  return value
}

export function u16Bytes (value, field = 'u16') {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} is outside u16`)
  }
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff)
}

export function u32Bytes (value, field = 'u32') {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} is outside u32`)
  }
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  )
}

export function u64Bytes (value, field = 'u64') {
  value = asU64(value, field)
  const output = new Uint8Array(8)
  for (let i = 7; i >= 0; i--) {
    output[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

export class CanonicalWriter {
  #chunks = []

  u8 (value, field = 'u8') {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} is outside u8`)
    }
    this.#chunks.push(Uint8Array.of(value))
  }

  u16 (value, field = 'u16') {
    this.#chunks.push(u16Bytes(value, field))
  }

  u32 (value, field = 'u32') {
    this.#chunks.push(u32Bytes(value, field))
  }

  u64 (value, field = 'u64') {
    this.#chunks.push(u64Bytes(value, field))
  }

  fixed (value, length, field) {
    this.#chunks.push(fixedBytesValue(value, length, field))
  }

  literalAscii (value, field) {
    this.#chunks.push(asciiBytes(value, field))
  }

  utf8U16 (value, field) {
    const encoded = utf8Bytes(value, field)
    if (encoded.byteLength > 0xffff) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} exceeds u16 bytes`)
    }
    this.u16(encoded.byteLength, `${field} length`)
    this.#chunks.push(encoded)
  }

  optionalFixed (value, length, field) {
    if (value == null) {
      this.u8(0, `${field} presence`)
      return
    }
    this.u8(1, `${field} presence`)
    this.fixed(value, length, field)
  }

  optionalU64 (value, field) {
    if (value == null) {
      this.u8(0, `${field} presence`)
      return
    }
    this.u8(1, `${field} presence`)
    this.u64(value, field)
  }

  bytesU16 (value, minimum, maximum, field) {
    value = asBytes(value, field)
    if (value.byteLength < minimum || value.byteLength > maximum || value.byteLength > 0xffff) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be bytes[${minimum}..${maximum}]`)
    }
    this.u16(value.byteLength, `${field} length`)
    this.#chunks.push(value)
  }

  finish () {
    return concatBytes(this.#chunks)
  }
}

export class CanonicalReader {
  #bytes
  #offset = 0

  constructor (value) {
    this.#bytes = asBytes(value, 'canonical bytes')
  }

  get remaining () {
    return this.#bytes.byteLength - this.#offset
  }

  #take (length, field) {
    if (!Number.isSafeInteger(length) || length < 0 || this.remaining < length) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `truncated ${field}`)
    }
    const value = this.#bytes.slice(this.#offset, this.#offset + length)
    this.#offset += length
    return value
  }

  u8 (field = 'u8') {
    return this.#take(1, field)[0]
  }

  u16 (field = 'u16') {
    const bytes = this.#take(2, field)
    return bytes[0] * 0x100 + bytes[1]
  }

  u32 (field = 'u32') {
    const bytes = this.#take(4, field)
    return bytes[0] * 0x1000000 + bytes[1] * 0x10000 + bytes[2] * 0x100 + bytes[3]
  }

  u64 (field = 'u64') {
    const bytes = this.#take(8, field)
    let value = 0n
    for (const byte of bytes) value = (value << 8n) | BigInt(byte)
    return value
  }

  fixed (length, field) {
    return this.#take(length, field)
  }

  expectLiteralAscii (expected, field) {
    const encoded = asciiBytes(expected, field)
    const actual = this.#take(encoded.byteLength, field)
    if (!bytesEqual(actual, encoded)) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} does not match its fixed value`)
    }
    return expected
  }

  utf8U16 (field) {
    const length = this.u16(`${field} length`)
    const bytes = this.#take(length, field)
    const value = decodeUtf8(bytes, field)
    if (!bytesEqual(utf8Bytes(value, field), bytes)) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} is not canonical UTF-8`)
    }
    return value
  }

  optionalFixed (length, field) {
    const present = this.u8(`${field} presence`)
    if (present === 0) return null
    if (present !== 1) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} presence must be 0 or 1`)
    }
    return this.fixed(length, field)
  }

  optionalU64 (field) {
    const present = this.u8(`${field} presence`)
    if (present === 0) return null
    if (present !== 1) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} presence must be 0 or 1`)
    }
    return this.u64(field)
  }

  bytesU16 (minimum, maximum, field) {
    const length = this.u16(`${field} length`)
    if (length < minimum || length > maximum) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be bytes[${minimum}..${maximum}]`)
    }
    return this.#take(length, field)
  }

  expectEnd (field = 'record') {
    if (this.remaining !== 0) {
      failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} has trailing bytes`)
    }
  }
}

const BLAKE2B_IV = Object.freeze([
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n
])

const BLAKE2B_SIGMA = Object.freeze([
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
])

function rotateRight64 (value, shift) {
  const bits = BigInt(shift)
  return ((value >> bits) | (value << (64n - bits))) & MASK_64
}

function readU64LE (bytes, offset) {
  let value = 0n
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(bytes[offset + i])
  return value
}

function writeU64LE (bytes, value, offset) {
  for (let i = 0; i < 8; i++) {
    bytes[offset + i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function blake2bMix (state, a, b, c, d, x, y) {
  state[a] = (state[a] + state[b] + x) & MASK_64
  state[d] = rotateRight64(state[d] ^ state[a], 32)
  state[c] = (state[c] + state[d]) & MASK_64
  state[b] = rotateRight64(state[b] ^ state[c], 24)
  state[a] = (state[a] + state[b] + y) & MASK_64
  state[d] = rotateRight64(state[d] ^ state[a], 16)
  state[c] = (state[c] + state[d]) & MASK_64
  state[b] = rotateRight64(state[b] ^ state[c], 63)
}

function compressBlake2b (hash, block, count, last) {
  const message = new Array(16)
  for (let i = 0; i < 16; i++) message[i] = readU64LE(block, i * 8)

  const state = [...hash, ...BLAKE2B_IV]
  state[12] ^= count & MASK_64
  state[13] ^= count >> 64n
  if (last) state[14] ^= MASK_64

  for (const sigma of BLAKE2B_SIGMA) {
    blake2bMix(state, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]])
    blake2bMix(state, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]])
    blake2bMix(state, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]])
    blake2bMix(state, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]])
    blake2bMix(state, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]])
    blake2bMix(state, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]])
    blake2bMix(state, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]])
    blake2bMix(state, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]])
  }

  for (let i = 0; i < 8; i++) hash[i] = (hash[i] ^ state[i] ^ state[i + 8]) & MASK_64
}

export function blake2b256 (value) {
  const input = asBytes(value, 'BLAKE2b input')
  const hash = [...BLAKE2B_IV]
  hash[0] ^= 0x01010020n

  let offset = 0
  let count = 0n
  while (offset + 128 < input.byteLength) {
    const block = input.slice(offset, offset + 128)
    count += 128n
    compressBlake2b(hash, block, count, false)
    offset += 128
  }

  const finalBlock = new Uint8Array(128)
  const remaining = input.byteLength - offset
  finalBlock.set(input.slice(offset))
  count += BigInt(remaining)
  compressBlake2b(hash, finalBlock, count, true)

  const output = new Uint8Array(32)
  for (let i = 0; i < 4; i++) writeU64LE(output, hash[i], i * 8)
  return output
}

export function domainHash (domain, value) {
  return blake2b256(concatBytes(asciiBytes(domain, 'hash domain'), asBytes(value, 'hash input')))
}

export function domainLengthHash (domain, value) {
  value = asBytes(value, 'hash input')
  return blake2b256(concatBytes(asciiBytes(domain, 'hash domain'), u64Bytes(value.byteLength), value))
}

export function bytesToHex (value) {
  value = asBytes(value)
  let output = ''
  for (const byte of value) output += byte.toString(16).padStart(2, '0')
  return output
}

export function hexToBytes (value, length, field = 'hex value') {
  if (typeof value !== 'string' || !/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must be lowercase hexadecimal`)
  }
  const output = new Uint8Array(value.length / 2)
  for (let i = 0; i < output.byteLength; i++) output[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
  if (length != null && output.byteLength !== length) {
    failReleaseControl('BAD_RELEASE_CONTROL_ENCODING', `${field} must encode ${length} bytes`)
  }
  return output
}

export { MAX_U64 }
