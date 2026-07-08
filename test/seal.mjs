// seal.mjs — the v2 blind key-scheme primitives (js/seal.js).
// Proves: okey is deterministic (LWW self-compaction survives), author-bound (no
// parking under a victim's slot), type-folded (no type leak in the wire key),
// community/members slots are author-INDEPENDENT (anti-squat collision + roster);
// the sealed envelope round-trips, is randomized (identical input → different ct, so
// short bodies aren't convergent-confirmable), and fails closed on tamper / wrong key.
//   node test/seal.mjs

import assert from 'node:assert'
import { okey, communityOkey, membersOkey, seal, unseal, setReadKey } from '../js/seal.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, m) { try { await fn() } catch { ok(true, m); return } assert.fail('expected throw: ' + m) }

const A = 'a'.repeat(64) // author A
const B = 'b'.repeat(64) // author B

async function main () {
  // ---- okey: deterministic + opaque + author-bound + type-folded ----
  console.log('— okey —')
  const k1 = await okey('post', 'p2p!hello', A)
  const k2 = await okey('post', 'p2p!hello', A)
  ok(/^[0-9a-f]{64}$/.test(k1), 'okey is 64-hex opaque')
  ok(k1 === k2, 'okey is DETERMINISTIC — a re-write hits the same slot (LWW self-compaction survives)')
  ok(await okey('post', 'p2p!hello', B) !== k1, 'okey is AUTHOR-BOUND — B cannot compute A’s slot (no parking under a victim)')
  ok(await okey('vote', 'p2p!hello', A) !== k1, 'type is FOLDED into okey — a vote and a post on the same id get different slots (no type leak in the wire key)')
  ok(await okey('post', 'p2p!other', A) !== k1, 'a different semanticId → a different slot')

  // ---- community + members: author-INDEPENDENT shared slots ----
  console.log('\n— shared slots (anti-squat + roster) —')
  const c1 = await communityOkey('worldcup')
  ok(await communityOkey('worldcup') === c1, 'communityOkey deterministic')
  ok(/^[0-9a-f]{64}$/.test(c1), 'communityOkey is 64-hex')
  ok((await communityOkey('worldcup')) === c1, 'communityOkey is AUTHOR-INDEPENDENT — rival creators collide at one slot (sticky-claim fires)')
  ok(await communityOkey('p2p') !== c1, 'different slug → different community slot')
  ok(await membersOkey('worldcup') !== c1, 'members slot is distinct from the community slot')
  ok(await membersOkey('worldcup') === await membersOkey('worldcup'), 'membersOkey deterministic + author-independent (one fetchable roster slot)')

  // ---- seal / unseal round-trip + randomized + tamper-fails ----
  console.log('\n— sealed envelope —')
  const rec = { _t: 'post', community: 'worldcup', cid: 'x1', createdAt: 123, body: 'lol' }
  const e1 = await seal(rec)
  ok(e1.v === 1 && /^[0-9a-f]{24}$/.test(e1.iv) && typeof e1.ct === 'string', 'seal → { v, iv(12B hex), ct }')
  ok(JSON.stringify(await unseal(e1)) === JSON.stringify(rec), 'unseal round-trips the exact object')

  const e2 = await seal(rec)
  ok(e1.ct !== e2.ct && e1.iv !== e2.iv, 'RANDOMIZED — identical input → different ciphertext (short bodies are not convergent-confirmable)')
  const short = await seal({ _t: 'comment', body: '+1' })
  const short2 = await seal({ _t: 'comment', body: '+1' })
  ok(short.ct !== short2.ct, 'identical short comments produce different ciphertext (no dictionary-confirm by ct equality)')

  await throwsAsync(() => unseal({ v: 1, iv: e1.iv, ct: e1.ct.slice(0, -4) + 'AAAA' }), 'a tampered ciphertext fails the GCM tag (fail-closed)')
  await throwsAsync(() => unseal({ v: 2, iv: e1.iv, ct: e1.ct }), 'an unknown envelope version is rejected')

  // ---- wrong read key can't unseal / recomputes different okeys ----
  console.log('\n— read-key binding —')
  const kBefore = await okey('post', 'p2p!hello', A)
  setReadKey('f'.repeat(64)) // a DIFFERENT network read key
  await throwsAsync(() => unseal(e1), 'a different read key cannot unseal (AES-GCM key mismatch)')
  ok(await okey('post', 'p2p!hello', A) !== kBefore, 'a different read key derives different okeys')
  setReadKey('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90') // restore default
  ok(await okey('post', 'p2p!hello', A) === kBefore, 'restoring the read key restores the okeys (determinism across the constant)')

  console.log(`\n✅ all ${passed} seal checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
