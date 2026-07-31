import assert from 'node:assert/strict'
import {
  PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2,
  PEERIT_LAB_OPERATION_SHAPE_V2,
  createStructuralPeeritVnextJournalIntent,
  inspectStructuralPeeritVnextJournalIntent,
  isStructuralPeeritVnextJournalInspectionEvidence
} from './fixtures/peerit-vnext-journal-fixture.mjs'

const intent = createStructuralPeeritVnextJournalIntent({
  operations: [{
    type: 'post',
    data: { id: 'known-answer-1', communityId: 'c1', body: 'hello', ordinal: 7 }
  }],
  records: [{ key: 'post!known-answer-1', value: { id: 'known-answer-1' } }],
  createdAt: 1_700_000_000_000
})

assert.equal(PEERIT_LAB_OPERATION_SHAPE_V2, 'peerit-unsigned-structural-operation-records-v2')
assert.equal(PEERIT_LAB_JOURNAL_INTENT_SHAPE_V2, 'peerit-inner-operation-batch-v1-derived-journal-intent-v2')
assert.equal(Buffer.from(intent.innerBytes).toString('hex'),
  '014e01000000797b226f7065726174696f6e73223a5b7b2264617461223a7b22626f6479223a2268656c6c6f222c22636f6d6d756e6974794964223a226331222c226964223a226b6e6f776e2d616e737765722d31222c226f7264696e616c223a377d2c2274797065223a22706f7374227d5d2c2276657273696f6e223a317d')
assert.equal(intent.innerLength, 128)
assert.equal(intent.sizeClass, 1)
assert.equal(Buffer.from(intent.logicalHash).toString('hex'), '13002e9a3bb07ebe7d894a5d25db176a6ff3a548dbfe88246c46493e00f017d4')
assert.equal(Buffer.from(intent.encodingCommitment).toString('hex'), 'cf5d568b26fc7093c710287c329e13e4f466165514fbccb78ecd6670727bc064')
assert.equal(intent.intentId, 'e0b535c2945cd3a05780e53782747fb205d4b3026f2009a30f0d377d1de6368e')
assert.equal(intent.logicalId, '13002e9a3bb07ebe7d894a5d25db176a6ff3a548dbfe88246c46493e00f017d4')

const inspection = inspectStructuralPeeritVnextJournalIntent(intent)
assert.equal(inspection.verified, true)
assert.equal(inspection.codecBytesHex, '014e')
assert.equal(inspection.version, 1)
assert.equal(inspection.declaredPayloadLength, 121)
assert.equal(inspection.payloadLength, 121)
assert.equal(inspection.smallestSizeClass, 1)
assert.ok(Object.values(inspection.checks).every(Boolean))
assert.equal(isStructuralPeeritVnextJournalInspectionEvidence(inspection), true)
const tamperedInspection = structuredClone(inspection)
tamperedInspection.logicalHashHex = '0'.repeat(64)
assert.equal(isStructuralPeeritVnextJournalInspectionEvidence(tamperedInspection), false)

assert.throws(() => createStructuralPeeritVnextJournalIntent({
  operations: [{ type: 'v2', data: { id: 'synthetic-type' } }]
}), /exact Peerit/)
assert.throws(() => createStructuralPeeritVnextJournalIntent({
  operations: [{ type: 'post', data: { id: 'extra-key' }, unsigned: true }]
}), /exact Peerit/)

function tamper (mutate, failedCheck) {
  const changed = structuredClone(intent)
  mutate(changed)
  const observed = inspectStructuralPeeritVnextJournalIntent(changed)
  assert.equal(observed.verified, false)
  assert.equal(observed.checks[failedCheck], false)
}

tamper(changed => { changed.innerBytes[0] ^= 1 }, 'codecBytes')
tamper(changed => { changed.innerBytes[2] = 2 }, 'version')
tamper(changed => { changed.innerBytes[6]-- }, 'payloadLength')
tamper(changed => { changed.sizeClass = 2 }, 'smallestSizeClass')
tamper(changed => { changed.logicalHash[0] ^= 1 }, 'logicalHash')
tamper(changed => { changed.encodingCommitment[0] ^= 1 }, 'encodingCommitment')
tamper(changed => { changed.intentId = `0${changed.intentId.slice(1)}` }, 'intentId')
tamper(changed => { changed.logicalId = `0${changed.logicalId.slice(1)}` }, 'logicalId')

console.log('peerit-vnext-journal-fixture: known-answer and tamper checks passed')
