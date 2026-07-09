// qr.js — QR transfer for the identity export. Two directions:
//
//   encodeQR(text)  -> { size, modules }  a byte-mode QR matrix (for display)
//   scanQR(...)                            read a QR via the native BarcodeDetector
//
// The encoder is a compact port of Project Nayuki's QR Code generator (MIT):
// byte mode, automatic version, ECC level M (falls back to L for large payloads).
// Alignment-pattern positions are COMPUTED, not table-driven, so the only
// hand-carried tables are the two canonical ECC tables below. The whole thing is
// validated end-to-end at review time by decoding a generated code with
// BarcodeDetector, so a wrong table value cannot pass silently.
//
// The scanner uses BarcodeDetector, which ships on Android/desktop Chromium (the
// phone case) but NOT iOS Safari — callers must offer file/paste as a fallback
// and check isScanSupported() first.

// --- ECC tables (index [ecc 0=L,1=M,2=Q,3=H][version 1..40]; [0] unused) ------
const ECC_CODEWORDS_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
]
const NUM_ERROR_CORRECTION_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
]
const MIN_VERSION = 1
const MAX_VERSION = 40
// Highest version validated to decode via BarcodeDetector (see test notes). The
// densest versions (35+) can produce codes cameras fail to read, so we refuse to
// emit them and let the caller fall back to file/copy. Identity exports are ~v22,
// far under this ceiling — this is a safety rail, not a normal limit.
const MAX_ENCODE_VERSION = 34
const ECC_FORMAT_BITS = [1, 0, 3, 2] // L,M,Q,H -> the 2-bit format field value

function getNumRawDataModules (ver) {
  let result = (16 * ver + 128) * ver + 64
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2
    result -= (25 * numAlign - 10) * numAlign - 55
    if (ver >= 7) result -= 36
  }
  return result
}

function getNumDataCodewords (ver, ecc) {
  return Math.floor(getNumRawDataModules(ver) / 8) -
    ECC_CODEWORDS_PER_BLOCK[ecc][ver] * NUM_ERROR_CORRECTION_BLOCKS[ecc][ver]
}

function getAlignmentPatternPositions (ver) {
  if (ver === 1) return []
  const numAlign = Math.floor(ver / 7) + 2
  const step = Math.floor((ver * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2
  const result = [6]
  for (let pos = ver * 4 + 10; result.length < numAlign; pos -= step) result.splice(1, 0, pos)
  return result
}

// --- Reed-Solomon over GF(256) ------------------------------------------------
function gfMul (x, y) {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z & 0xff
}

function rsComputeDivisor (degree) {
  const result = new Uint8Array(degree)
  result[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root)
      if (j + 1 < degree) result[j] ^= result[j + 1]
    }
    root = gfMul(root, 0x02)
  }
  return result
}

function rsComputeRemainder (data, divisor) {
  const result = new Uint8Array(divisor.length)
  for (const b of data) {
    const factor = b ^ result[0]
    result.copyWithin(0, 1)
    result[result.length - 1] = 0
    for (let i = 0; i < result.length; i++) result[i] ^= gfMul(divisor[i], factor)
  }
  return result
}

// --- bit helpers --------------------------------------------------------------
function appendBits (val, len, bb) {
  for (let i = len - 1; i >= 0; i--) bb.push((val >>> i) & 1)
}

function bytesToDataCodewords (data, ver, ecc) {
  const capacityBits = getNumDataCodewords(ver, ecc) * 8
  const bb = []
  appendBits(0x4, 4, bb) // byte mode
  const lenBits = ver <= 9 ? 8 : 16
  appendBits(data.length, lenBits, bb)
  for (const b of data) appendBits(b, 8, bb)
  if (bb.length > capacityBits) return null // does not fit this version
  appendBits(0, Math.min(4, capacityBits - bb.length), bb) // terminator
  while (bb.length % 8 !== 0) bb.push(0)
  const codewords = []
  for (let i = 0; i < bb.length; i += 8) {
    let byte = 0
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bb[i + j]
    codewords.push(byte)
  }
  for (let pad = 0xec; codewords.length < capacityBits / 8; pad ^= 0xec ^ 0x11) codewords.push(pad)
  return codewords
}

function addEccAndInterleave (data, ver, ecc) {
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ecc][ver]
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecc][ver]
  const rawCodewords = Math.floor(getNumRawDataModules(ver) / 8)
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks)
  const shortBlockLen = Math.floor(rawCodewords / numBlocks)

  const blocks = []
  const divisor = rsComputeDivisor(blockEccLen)
  let k = 0
  for (let i = 0; i < numBlocks; i++) {
    const datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1)
    const dat = data.slice(k, k + datLen)
    k += datLen
    const ecfw = rsComputeRemainder(dat, divisor)
    const block = dat.slice()
    if (i < numShortBlocks) block.push(0) // pad slot for interleaving alignment
    for (const b of ecfw) block.push(b)
    blocks.push(block)
  }

  const result = []
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      // Skip the pad slot in short blocks' data region.
      if (!(i === shortBlockLen - blockEccLen && j < numShortBlocks)) result.push(blocks[j][i])
    }
  }
  return result
}

// --- matrix construction ------------------------------------------------------
function makeMatrix (ver) {
  const size = ver * 4 + 17
  const modules = []
  const isFunction = []
  for (let i = 0; i < size; i++) { modules.push(new Array(size).fill(false)); isFunction.push(new Array(size).fill(false)) }
  return { size, modules, isFunction }
}

function setFunctionModule (m, x, y, dark) {
  m.modules[y][x] = dark
  m.isFunction[y][x] = true
}

function drawFinder (m, x, y) {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const xx = x + dx, yy = y + dy
      if (xx < 0 || xx >= m.size || yy < 0 || yy >= m.size) continue
      const dist = Math.max(Math.abs(dx), Math.abs(dy))
      setFunctionModule(m, xx, yy, dist !== 2 && dist !== 4)
    }
  }
}

function drawAlignment (m, x, y) {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      setFunctionModule(m, x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
    }
  }
}

function drawFormatBits (m, ecc, mask) {
  const data = (ECC_FORMAT_BITS[ecc] << 3) | mask
  let rem = data
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
  const bits = ((data << 10) | rem) ^ 0x5412
  for (let i = 0; i <= 5; i++) setFunctionModule(m, 8, i, ((bits >>> i) & 1) !== 0)
  setFunctionModule(m, 8, 7, ((bits >>> 6) & 1) !== 0)
  setFunctionModule(m, 8, 8, ((bits >>> 7) & 1) !== 0)
  setFunctionModule(m, 7, 8, ((bits >>> 8) & 1) !== 0)
  for (let i = 9; i < 15; i++) setFunctionModule(m, 14 - i, 8, ((bits >>> i) & 1) !== 0)
  for (let i = 0; i < 8; i++) setFunctionModule(m, m.size - 1 - i, 8, ((bits >>> i) & 1) !== 0)
  for (let i = 8; i < 15; i++) setFunctionModule(m, 8, m.size - 15 + i, ((bits >>> i) & 1) !== 0)
  setFunctionModule(m, 8, m.size - 8, true)
}

function drawVersion (m, ver) {
  if (ver < 7) return
  let rem = ver
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
  const bits = (ver << 12) | rem
  for (let i = 0; i < 18; i++) {
    const bit = ((bits >>> i) & 1) !== 0
    const a = m.size - 11 + (i % 3)
    const b = Math.floor(i / 3)
    setFunctionModule(m, a, b, bit)
    setFunctionModule(m, b, a, bit)
  }
}

function drawFunctionPatterns (m, ver, ecc) {
  for (let i = 0; i < m.size; i++) {
    setFunctionModule(m, 6, i, i % 2 === 0)
    setFunctionModule(m, i, 6, i % 2 === 0)
  }
  drawFinder(m, 3, 3)
  drawFinder(m, m.size - 4, 3)
  drawFinder(m, 3, m.size - 4)
  const align = getAlignmentPatternPositions(ver)
  for (let i = 0; i < align.length; i++) {
    for (let j = 0; j < align.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue
      drawAlignment(m, align[i], align[j])
    }
  }
  drawFormatBits(m, ecc, 0) // placeholder; real mask drawn after selection
  drawVersion(m, ver)
}

function drawCodewords (m, codewords) {
  let i = 0
  for (let right = m.size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vert = 0; vert < m.size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j
        const upward = ((right + 1) & 2) === 0
        const y = upward ? m.size - 1 - vert : vert
        if (m.isFunction[y][x]) continue
        m.modules[y][x] = i < codewords.length * 8 ? ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0 : false
        i++
      }
    }
  }
}

function applyMask (m, mask) {
  for (let y = 0; y < m.size; y++) {
    for (let x = 0; x < m.size; x++) {
      if (m.isFunction[y][x]) continue
      let invert = false
      switch (mask) {
        case 0: invert = (x + y) % 2 === 0; break
        case 1: invert = y % 2 === 0; break
        case 2: invert = x % 3 === 0; break
        case 3: invert = (x + y) % 3 === 0; break
        case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break
        case 5: invert = (x * y) % 2 + (x * y) % 3 === 0; break
        case 6: invert = ((x * y) % 2 + (x * y) % 3) % 2 === 0; break
        case 7: invert = ((x + y) % 2 + (x * y) % 3) % 2 === 0; break
      }
      if (invert) m.modules[y][x] = !m.modules[y][x]
    }
  }
}

// Mask-selection penalty. Rules 1 (runs), 2 (2x2 blocks) and 4 (dark balance);
// rule 3 (finder-like runs) is omitted — it only fine-tunes the mask choice, and
// every mask still produces a spec-valid, scannable code.
function penalty (m) {
  const size = m.size
  let p = 0
  // Rule 1: runs of 5+ same-color modules along each row and column.
  for (let axis = 0; axis < 2; axis++) {
    for (let i = 0; i < size; i++) {
      let runColor = false, runLen = 0
      for (let j = 0; j < size; j++) {
        const dark = axis === 0 ? m.modules[i][j] : m.modules[j][i]
        if (dark === runColor) {
          runLen++
          if (runLen === 5) p += 3
          else if (runLen > 5) p++
        } else { runColor = dark; runLen = 1 }
      }
    }
  }
  // 2x2 blocks.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = m.modules[y][x]
      if (c === m.modules[y][x + 1] && c === m.modules[y + 1][x] && c === m.modules[y + 1][x + 1]) p += 3
    }
  }
  // Balance of dark/light.
  let dark = 0
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (m.modules[y][x]) dark++
  const total = size * size
  const k = Math.floor((Math.abs(dark * 20 - total * 10) + total - 1) / total) - 1
  p += Math.max(0, k) * 10
  return p
}

// Encode text (UTF-8) into a QR matrix. Returns { size, version, ecc, modules }.
export function encodeQR (text, opts = {}) {
  const data = new TextEncoder().encode(String(text))
  const eccOrder = opts.ecc != null ? [opts.ecc] : [1, 0] // prefer M, fall back to L
  for (const ecc of eccOrder) {
    for (let ver = MIN_VERSION; ver <= MAX_ENCODE_VERSION; ver++) {
      const codewords = bytesToDataCodewords(data, ver, ecc)
      if (!codewords) continue
      const allCodewords = addEccAndInterleave(codewords, ver, ecc)
      const m = makeMatrix(ver)
      drawFunctionPatterns(m, ver, ecc)
      drawCodewords(m, allCodewords)
      // Choose the mask with the lowest penalty.
      let bestMask = 0, bestPenalty = Infinity
      for (let mask = 0; mask < 8; mask++) {
        applyMask(m, mask)
        drawFormatBits(m, ecc, mask)
        const pen = penalty(m)
        if (pen < bestPenalty) { bestPenalty = pen; bestMask = mask }
        applyMask(m, mask) // undo (self-inverse)
      }
      applyMask(m, bestMask)
      drawFormatBits(m, ecc, bestMask)
      return { size: m.size, version: ver, ecc, modules: m.modules }
    }
  }
  throw new Error('Too large for a reliably scannable QR code — use Download or Copy instead.')
}

// Render a QR matrix as a crisp SVG string (module = 1 unit + a quiet border).
export function qrToSvg (qr, opts = {}) {
  const border = opts.border == null ? 4 : opts.border
  const dim = qr.size + border * 2
  const dark = opts.dark || '#000000'
  const light = opts.light || '#ffffff'
  let path = ''
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.modules[y][x]) path += `M${x + border},${y + border}h1v1h-1z`
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" stroke="none" shape-rendering="crispEdges">` +
    `<rect width="100%" height="100%" fill="${light}"/>` +
    `<path d="${path}" fill="${dark}"/></svg>`
}

// --- scanning (import side) ---------------------------------------------------
export function isScanSupported () {
  return typeof globalThis !== 'undefined' && typeof globalThis.BarcodeDetector === 'function'
}

// Scan QR frames from a MediaStream video into `onResult(text)`. Returns a stop()
// function. Throws synchronously if BarcodeDetector is unavailable.
export async function scanQR (videoEl, onResult, onError) {
  if (!isScanSupported()) throw new Error('This browser cannot scan QR codes; use the file or paste option instead.')
  const detector = new globalThis.BarcodeDetector({ formats: ['qr_code'] })
  const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
  videoEl.srcObject = stream
  await videoEl.play().catch(() => {})
  let stopped = false
  const stop = () => {
    stopped = true
    try { for (const track of stream.getTracks()) track.stop() } catch {}
    try { videoEl.srcObject = null } catch {}
  }
  const tick = async () => {
    if (stopped) return
    try {
      const codes = await detector.detect(videoEl)
      if (codes && codes.length && codes[0].rawValue) { stop(); onResult(codes[0].rawValue); return }
    } catch (err) { if (onError) onError(err) }
    if (!stopped) requestAnimationFrame(tick)
  }
  requestAnimationFrame(tick)
  return stop
}
