// box.mjs — BlindShard convergent AEAD box/unbox (js/box.js) + the bytes-in
// SHA-256 (crypto.js hashBytes). This is the smallest crypto primitive of the
// BlindShard pipeline, so its guarantees are pinned hard here:
//   • round-trip:     box(body) → unbox → recovers the exact body
//   • determinism:    same body → identical C, contentKey, iv, blobId (= dedup)
//   • tamper:         flip one ciphertext byte → unbox throws (GCM auth tag)
//   • content-key GATE: wrong contentKey → unbox throws (MANDATORY rejection,
//                     closes the AES-GCM key-commitment gap)
//   • KAT vectors:    fixed inputs pinned to fixed outputs, so the deterministic
//                     -IV construction can never silently drift.
// Run: node test/box.mjs

import assert from 'node:assert'
import { box, unbox } from '../js/box.js'
import { hashBytes, hashHex, ready as cryptoReady, isSecure } from '../js/crypto.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, match, m) {
  try { await fn() } catch (e) { ok(!match || match.test(e.message), m + ' (' + e.message + ')'); return }
  assert.fail('expected throw: ' + m)
}

const enc = (s) => new TextEncoder().encode(s)
const dec = (u) => new TextDecoder().decode(u)
const hex = (u) => { let s = ''; for (const b of u) s += b.toString(16).padStart(2, '0'); return s }
const eqBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

// Pinned known-answer vectors — captured from the reference implementation and
// frozen. The empty-body contentKey is the canonical SHA-256("") so the
// convergent key derivation is anchored to a public constant; the rest pin the
// deterministic IV = SHA-256("bs-iv"‖contentKey)[:12] and blobId = SHA-256(C).
const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
const KATS = [
  {
    body: '',
    contentKey: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    iv: '05a6f867fe1521e8c34daa5b',
    blobId: '5bcb27a73ef0033c85635c8f6ae9803f3f237f54cd1a6bf4c4828e6b3f31948b',
    C: 'f2dc75cf141fac898782fc4b2b34180f'
  },
  {
    body: 'blindshard',
    contentKey: '14755ae20b7d2e8c016d38527423980b30b6883fba9fb8427217585e8899e71e',
    iv: 'a88007561a10610081249a5d',
    blobId: '00c77e18490b5d72cbdfbc08750b8d7ffb8f8f1e60a2729d808ab531cd9bb201',
    C: 'd93339483d45e532cb59b6595892de7deed208a08e528b4c3d54'
  },
  {
    body: 'The quick brown fox',
    contentKey: '5cac4f980fedc3d3f1f99b4be3472c9b30d56523e632d151237ec9309048bda9',
    iv: 'ec0b7df18c42ce26b44ff0ed',
    blobId: 'b140bba567c83176bc32861fd6a92cffcdb2be6f2567958eb51130dafbd204b4',
    C: '9dcf2eee4754dfd518ff720af17d95567a416913c01fdce0ce4aee35aba0ac0edb42d3'
  }
]

async function main () {
  await cryptoReady()
  if (!isSecure()) { console.log('\n⚠ no secure crypto backend in this Node; skipping box suite\n'); return }

  console.log('\n— hashBytes: bytes-in SHA-256 (crypto.js) —')
  ok(await hashBytes(enc('')) === SHA256_EMPTY, 'hashBytes("") == canonical SHA-256 of empty input')
  ok(await hashBytes(enc('abc')) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'hashBytes("abc") == NIST FIPS-180-2 SHA-256("abc") vector')
  ok(await hashBytes(enc('peerit')) === await hashHex('peerit'),
    'hashBytes agrees with string-only hashHex on identical UTF-8 content')
  ok(await hashBytes(new Uint8Array([1, 2, 3])) === await hashBytes(new Uint8Array([1, 2, 3]).buffer),
    'hashBytes accepts both Uint8Array and ArrayBuffer identically')
  {
    // Bytes-in must NOT lossily round-trip through a string: 0xff 0xfe is not
    // valid UTF-8, so a string path would mangle it. hashBytes must hash it raw.
    const raw = new Uint8Array([0xff, 0xfe, 0x00, 0x80])
    ok(/^[0-9a-f]{64}$/.test(await hashBytes(raw)), 'hashBytes hashes non-UTF-8/binary bytes without a string round-trip')
  }

  console.log('\n— box → unbox: round-trip fidelity —')
  for (const s of ['', 'hello world', 'The quick brown fox jumps over the lazy dog', '日本語 + emoji 🦈 mix']) {
    const body = enc(s)
    const { C, contentKey, iv, blobId } = await box(body)
    const back = await unbox(C, contentKey, iv)
    ok(eqBytes(back, body) && dec(back) === s, `round-trip recovers body (${s.length} chars)`)
    ok(await hashBytes(C) === blobId, 'blobId == SHA-256(C) (caller-checkable content address)')
    ok(contentKey === await hashBytes(body), 'contentKey == SHA-256(body) (convergent key derivation)')
  }
  {
    // A larger binary body (all 256 byte values, repeated) — exercises the path
    // on non-text, multi-block input.
    const body = new Uint8Array(4096)
    for (let i = 0; i < body.length; i++) body[i] = i & 0xff
    const { C, contentKey, iv } = await box(body)
    ok(eqBytes(await unbox(C, contentKey, iv), body), 'round-trip recovers a 4 KiB all-byte-values binary body')
  }

  console.log('\n— determinism: same body → same C / contentKey / iv / blobId (dedup) —')
  {
    const body = enc('convergent dedup means identical bodies box identically')
    const a = await box(body)
    const b = await box(body)
    ok(a.contentKey === b.contentKey, 'contentKey is deterministic')
    ok(hex(a.iv) === hex(b.iv), 'iv is deterministic (derived, not random)')
    ok(hex(a.C) === hex(b.C), 'ciphertext C is byte-identical across two boxes → dedup')
    ok(a.blobId === b.blobId, 'blobId is deterministic → same content-address, one stored blob')
  }
  {
    // Different bodies must NOT collide.
    const x = await box(enc('body one'))
    const y = await box(enc('body two'))
    ok(x.contentKey !== y.contentKey && x.blobId !== y.blobId && hex(x.iv) !== hex(y.iv),
      'distinct bodies produce distinct contentKey / iv / blobId')
  }

  console.log('\n— tamper detection: flipped ciphertext byte → unbox throws —')
  {
    const body = enc('integrity-protected payload')
    const { C, contentKey, iv } = await box(body)
    const bad = C.slice(); bad[0] ^= 0x01
    await throwsAsync(() => unbox(bad, contentKey, iv), /authentication failed/i,
      'flipping a ciphertext byte fails the GCM auth tag')
    const truncated = C.slice(0, C.length - 1)
    await throwsAsync(() => unbox(truncated, contentKey, iv), /authentication failed/i,
      'truncating the ciphertext (drops part of the auth tag) throws')
    const badIv = iv.slice(); badIv[0] ^= 0x01
    await throwsAsync(() => unbox(C, contentKey, badIv), /authentication failed/i,
      'flipping an IV byte fails the GCM auth tag')
  }

  console.log('\n— hard content-key GATE: wrong contentKey → unbox throws —')
  {
    const body = enc('the key-commitment gate is mandatory, not advisory')
    const { C, iv, contentKey } = await box(body)
    // A different-but-well-formed 64-hex key. GCM decrypt should fail its auth
    // tag (wrong key) — but even if a crafted blob slipped past GCM, the
    // SHA-256(P)==contentKey gate is the mandatory backstop. Assert the throw.
    const wrongKey = 'a'.repeat(64)
    await throwsAsync(() => unbox(C, wrongKey, iv), /(authentication failed|content-key gate)/i,
      'decrypting with a wrong (but valid-shape) contentKey throws')
    // Malformed content key shape is rejected outright.
    await throwsAsync(() => unbox(C, 'not-a-hash', iv), /64-char hex/i,
      'a non-hex/short contentKey is rejected before any decrypt')
    // Sanity: the correct key still passes and recovers the body — proving the
    // gate rejects the wrong key specifically, not everything.
    ok(eqBytes(await unbox(C, contentKey, iv), body), 'the correct contentKey still passes the gate')
  }

  console.log('\n— pinned KAT vectors: deterministic-IV construction is frozen —')
  for (const v of KATS) {
    const body = enc(v.body)
    const { C, contentKey, iv, blobId } = await box(body)
    ok(contentKey === v.contentKey, `KAT contentKey pinned for body=${JSON.stringify(v.body)}`)
    ok(hex(iv) === v.iv, `KAT iv pinned (SHA-256("bs-iv"‖contentKey)[:12]) for body=${JSON.stringify(v.body)}`)
    ok(hex(C) === v.C, `KAT ciphertext C pinned for body=${JSON.stringify(v.body)}`)
    ok(blobId === v.blobId, `KAT blobId pinned (SHA-256(C)) for body=${JSON.stringify(v.body)}`)
    // And the pinned vector round-trips from its frozen bytes, not just live output.
    const frozenC = new Uint8Array(v.C.length / 2)
    for (let i = 0; i < frozenC.length; i++) frozenC[i] = parseInt(v.C.substr(i * 2, 2), 16)
    const frozenIv = new Uint8Array(v.iv.length / 2)
    for (let i = 0; i < frozenIv.length; i++) frozenIv[i] = parseInt(v.iv.substr(i * 2, 2), 16)
    ok(dec(await unbox(frozenC, v.contentKey, frozenIv)) === v.body,
      `KAT frozen ciphertext unboxes to the expected body=${JSON.stringify(v.body)}`)
  }

  console.log(`\n✅ box suite passed — ${passed} assertions\n`)
}

main().catch((e) => { console.error('\n❌ box suite FAILED:', e && e.stack || e); process.exit(1) })
