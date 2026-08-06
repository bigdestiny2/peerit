// peerit-transient-fetch-classifiers.mjs — pins the SCOPE of the two first-visit
// transient-retry classifiers. Both retry ONLY transient transport conditions —
// TRANSPORT_FAILURE / AbortError / fetch TypeError / (cell) cold-reader deadline —
// PLUS the one exact vendored TRUNCATED-BODY short-read message, and fail closed
// on every OTHER RELAY_PROTOCOL_VIOLATION. A truncated body is never parsed,
// verified, or accepted, so re-asking relaxes nothing; every other protocol
// violation (framing, content-length, trailing bytes, malformed frame, and even a
// near-miss rewording of the short-read message) must fail closed forever.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { isTransientDescriptorFetchFailure } from '../js/substrate/relay-consumer.js'
import { isTransientCellGetFailure } from '../js/substrate/cold-reader.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const DESCRIBE_SHORT_READ = 'bootstrap response is shorter than the selected class'
const CELL_GET_SHORT_READ = 'response is shorter than the selected class'

function violation (message) {
  return Object.assign(new Error(message), { code: 'RELAY_PROTOCOL_VIOLATION' })
}
function coded (code) {
  return Object.assign(new Error('x'), { code })
}

// ---- (a) descriptor-walk classifier: transient (retried) ----
assert.equal(isTransientDescriptorFetchFailure(violation(DESCRIBE_SHORT_READ)), true,
  'the exact truncated-bootstrap short-read must be retried')
assert.equal(isTransientDescriptorFetchFailure(violation(CELL_GET_SHORT_READ)), true,
  'the walk also emits the health-challenge / generic-reader short-read variant; it must be retried too')
assert.equal(isTransientDescriptorFetchFailure(coded('TRANSPORT_FAILURE')), true)
assert.equal(isTransientDescriptorFetchFailure(Object.assign(new Error('x'), { name: 'AbortError' })), true)
assert.equal(isTransientDescriptorFetchFailure(new TypeError('Failed to fetch')), true)

// ---- (a) descriptor-walk classifier: fail-closed (never retried) ----
assert.equal(isTransientDescriptorFetchFailure(violation('descriptor durability profile hash is invalid')), false,
  'a different RELAY_PROTOCOL_VIOLATION must fail closed')
assert.equal(isTransientDescriptorFetchFailure(violation('relay rejected its signed health challenge')), false)
assert.equal(isTransientDescriptorFetchFailure(violation('bootstrap response is shorter')), false,
  'a near-miss prefix is NOT the exact short-read message')
assert.equal(isTransientDescriptorFetchFailure(violation(`${DESCRIBE_SHORT_READ} `)), false,
  'a trailing-space variant is NOT the exact short-read message')
assert.equal(isTransientDescriptorFetchFailure(violation(`${CELL_GET_SHORT_READ} `)), false,
  'a trailing-space variant of the health-challenge message is NOT exact')
assert.equal(isTransientDescriptorFetchFailure({ code: 'RELAY_PROTOCOL_VIOLATION' }), false,
  'a code with no message is not retried')
assert.equal(isTransientDescriptorFetchFailure({ message: DESCRIBE_SHORT_READ }), false,
  'the exact message without the violation code is not retried')
assert.equal(isTransientDescriptorFetchFailure(coded('PEERIT_LIMITED_DESCRIPTOR_CHAIN_INVALID')), false)
assert.equal(isTransientDescriptorFetchFailure(coded('PEERIT_LIMITED_DESCRIPTOR_ADMISSION_PROFILE_DRIFT')), false)
assert.equal(isTransientDescriptorFetchFailure(null), false)
assert.equal(isTransientDescriptorFetchFailure('RELAY_PROTOCOL_VIOLATION'), false)
assert.equal(isTransientDescriptorFetchFailure(42), false)

// ---- (a) cell-GET classifier: transient (retried) ----
assert.equal(isTransientCellGetFailure(violation(CELL_GET_SHORT_READ)), true,
  'the exact truncated-cell short-read must be retried')
assert.equal(isTransientCellGetFailure(coded('TRANSPORT_FAILURE')), true)
assert.equal(isTransientCellGetFailure(coded('PEERIT_COLD_READER_DEADLINE')), true)
assert.equal(isTransientCellGetFailure(Object.assign(new Error('x'), { name: 'AbortError' })), true)
assert.equal(isTransientCellGetFailure(new TypeError('Failed to fetch')), true)

// ---- (a) cell-GET classifier: fail-closed (never retried) ----
assert.equal(isTransientCellGetFailure(violation('descriptor durability profile hash is invalid')), false,
  'a different RELAY_PROTOCOL_VIOLATION must fail closed')
assert.equal(isTransientCellGetFailure(violation(DESCRIBE_SHORT_READ)), false,
  'the DESCRIBE short-read message is not the cell-get one')
assert.equal(isTransientCellGetFailure(violation('response is shorter')), false,
  'a near-miss prefix is NOT the exact short-read message')
assert.equal(isTransientCellGetFailure(violation(`${CELL_GET_SHORT_READ} `)), false,
  'a trailing-space variant is NOT the exact short-read message')
assert.equal(isTransientCellGetFailure({ code: 'RELAY_PROTOCOL_VIOLATION' }), false)
assert.equal(isTransientCellGetFailure({ message: CELL_GET_SHORT_READ }), false)
assert.equal(isTransientCellGetFailure(coded('PEERIT_COLD_READER_RECORD_UNAVAILABLE')), false)
assert.equal(isTransientCellGetFailure(null), false)

// ---- (b) pinning: the exact vendored short-read messages exist verbatim, so a
// vendored rebuild that rewords either message fails loudly here instead of
// silently disabling the retry. ----
function pinContains (relPath, needle) {
  const text = readFileSync(join(root, relPath), 'utf8')
  assert.equal(text.includes(needle), true,
    `vendored artifact ${relPath} must contain the exact short-read message ${JSON.stringify(needle)}; ` +
    'a reworded vendored message would silently disable the bounded transient retry')
}
// The LIMITED-recovery describe walk runs over the cell-get client; the broad
// qualification path runs over the control client. Pin the describe short-read
// in BOTH so neither vendored line can drift the message the walk actually sees.
pinContains('vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs', DESCRIBE_SHORT_READ)
pinContains('vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs', DESCRIBE_SHORT_READ)
pinContains('vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs', CELL_GET_SHORT_READ)
// The served web/ copies are byte-identical build outputs of the same artifacts.
pinContains('web/vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs', DESCRIBE_SHORT_READ)
pinContains('web/vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs', DESCRIBE_SHORT_READ)
pinContains('web/vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs', CELL_GET_SHORT_READ)

console.log('peerit-transient-fetch-classifiers: both classifiers retry ONLY the exact vendored short-read ' +
  'messages within RELAY_PROTOCOL_VIOLATION and fail closed on every other violation; vendored messages pinned verbatim')
