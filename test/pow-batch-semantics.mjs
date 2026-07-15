// pow-batch-semantics.mjs — the batched mint loop must be observationally
// identical to the serial one: first valid ascending nonce, same targetHash,
// same verification, and the same 1024-nonce progress/cancellation boundary.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  leadingZeroBits,
  mint,
  powTargetForVersion,
  verify
} from '../js/pow.js'

function digest (value) {
  return createHash('sha256').update(value, 'utf8').digest()
}

function firstSequentialNonce (type, data, bits, version) {
  const prefix = `${powTargetForVersion(type, data, version)}|`
  for (let nonce = 0; ; nonce++) {
    if (leadingZeroBits(digest(prefix + nonce)) >= bits) return nonce
  }
}

const fixtures = [
  {
    type: 'community',
    version: 2,
    bits: 10,
    data: {
      id: 'batch-semantics-community',
      slug: 'batch-semantics',
      creator: '1'.repeat(64),
      createdAt: 1_780_000_000_001
    }
  },
  {
    type: 'post',
    version: 1,
    bits: 10,
    data: {
      id: 'batch-semantics-post',
      community: 'batch-semantics',
      cid: 'batch-semantics-cid',
      author: '2'.repeat(64),
      createdAt: 1_780_000_000_002
    }
  }
]

for (const fixture of fixtures) {
  const expectedNonce = firstSequentialNonce(
    fixture.type, fixture.data, fixture.bits, fixture.version)
  const proof = await mint(fixture.type, fixture.data, fixture.bits, {
    version: fixture.version
  })
  assert.equal(proof.nonce, expectedNonce,
    `${fixture.type} returns the first valid ascending nonce`)
  assert.equal(proof.v, fixture.version)
  assert.equal(proof.targetHash,
    digest(powTargetForVersion(fixture.type, fixture.data, fixture.version)).toString('hex'))
  assert.equal(await verify(fixture.type, { ...fixture.data, pow: proof }, fixture.bits), true)
}

const controller = new AbortController()
const progress = []
await assert.rejects(mint('post', {
  id: 'batch-cancellation-boundary',
  createdAt: 1_780_000_000_003
}, 256, {
  signal: controller.signal,
  onProgress (nonce) {
    progress.push(nonce)
    if (nonce === 2048) controller.abort()
  }
}), /proof-of-work cancelled/)
assert.deepEqual(progress, [1024, 2048],
  'batching preserves the existing progress and cancellation boundary')

console.log('pow-batch-semantics: nonce order, target binding, verification, progress, and cancellation passed')
