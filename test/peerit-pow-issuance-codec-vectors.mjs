// Self-contained pow-issuance-v1 codec pin vectors — runs in every environment
// (including CI, where the relay source tree is absent). The full-stack drill
// (test/peerit-pow-issuance-spend.mjs) covers integration where 00-core/hiverelay
// is checked out; these vectors pin the production binding primitive everywhere.
//
// Why these exist: the v1-integration tree carried the superseded
// blake2b256(BIND‖count‖c₀‖c₁) record-binding design; the DEPLOYED fleet
// (00-core/hiverelay packages/blind-daemon/pow-issuance-v1/token-codec.js)
// requires HMAC-SHA256(key=BIND, count‖c₀‖c₁). A client built against the wrong
// tree produced spends the fleet could never accept (surfaced as canonical
// INTERNAL via the pre-hunk adapter bridge). These vectors were verified against
// the fleet module during the 2026-08-07 diagnosis and pin the fleet primitive.

import assert from 'node:assert/strict'
import { powIssuanceV1RecordBindingRoot } from '../js/substrate/pow-issuance-spend-provider.mjs'

const hex = bytes => Buffer.from(bytes).toString('hex')

const cases = [
  {
    name: 'two slots [32×0x01, 32×0x02]',
    slots: [new Uint8Array(32).fill(0x01), new Uint8Array(32).fill(0x02)],
    expected: '25ce7c823116a3d63265703133d11680c02cc7466a069a283b6d8613def6e47e'
  },
  {
    name: 'one slot [32×0x77]',
    slots: [new Uint8Array(32).fill(0x77)],
    expected: '135b2246b1b8ab7e270b4538cc3ea88e3aac579e02fd94030254fff11a9b2acc'
  }
]

for (const { name, slots, expected } of cases) {
  const got = hex(powIssuanceV1RecordBindingRoot(slots))
  assert.equal(got, expected, `${name}: binding root must equal the fleet-pinned HMAC-SHA256 vector`)
  console.log(`    [codec-vectors] PASS ${name} → ${expected.slice(0, 16)}…`)
}

console.log('    [codec-vectors] pow-issuance-v1 record binding root matches the deployed fleet HMAC-SHA256 codec (2/2 vectors)')
