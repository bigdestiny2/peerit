import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  parsePeeritSeq29CompletionDriverArgvV1,
  peeritSeq29CompletionDriverHelpV1,
  runPeeritSeq29CompletionDriverV1
} from '../scripts/seq29-completion-driver.mjs'
import {
  createPeeritSeq29CompletionReceiptStoreV1,
  PEERIT_SEQ29_COMPLETION_PHASES_V1
} from '../scripts/lib/seq29-completion-receipts.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const driverPath = join(root, 'scripts', 'seq29-completion-driver.mjs')
const driverSource = readFileSync(driverPath, 'utf8')
const forbidden = Object.freeze([
  /explicit-confirmation/i,
  new RegExp(['PEERIT', 'SEQ29', 'EXPLICIT', 'CONFIRMATION', 'V1'].join('_')),
  /copy\s*\/\s*paste/i,
  /copy and paste/i,
  /paste (?:it|this|that)/i,
  /--(?:token|secret|commit|hash|path|command|pass)(?:\s|=|$)/i,
  /\bPASS\b/
])

function assertNoRelayInterface (value, field) {
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  for (const pattern of forbidden) {
    assert.doesNotMatch(text, pattern,
      `${field} must not expose caller-relayed authority material`)
  }
}

function artifactKeys (phase) {
  return {
    create: [
      'create-journal', 'plan', 'public-inbox-bootstrap', 'qualification'
    ],
    'web-prepare': ['outer-manifest', 'prepare-journal', 'signing-request'],
    'release-sign': ['outer-signature'],
    'decision-pin': ['decision', 'source-edit'],
    'web-reprepare': [
      'app-artifact', 'canonical-manifest', 'outer-manifest',
      'outer-signature', 'signing-request'
    ],
    'deploy-web': ['deploy-receipt'],
    'history-append': ['pin-history'],
    'history-sign': ['pin-history-signature'],
    verify: ['verification-report']
  }[phase]
}

function artifacts (phase, digit) {
  return Object.fromEntries(artifactKeys(phase).map(key =>
    [key, digit.repeat(64)]))
}

const help = peeritSeq29CompletionDriverHelpV1()
assert.equal(help,
  'usage: node scripts/seq29-completion-driver.mjs status\n' +
  '       node scripts/seq29-completion-driver.mjs continue\n')
assertNoRelayInterface(help, 'driver help')
assertNoRelayInterface(driverSource, 'driver source')
assert.doesNotMatch(driverSource, /seq29-owner-decision\.mjs/,
  'completion driver must not invoke the legacy decision CLI')
assert.doesNotMatch(driverSource, /seq29-live-ceremony-materializer\.mjs/,
  'completion driver must not invoke the legacy materializer CLI')

assert.deepEqual(parsePeeritSeq29CompletionDriverArgvV1(['--help']),
  { operation: 'help' })
assert.deepEqual(parsePeeritSeq29CompletionDriverArgvV1(['status']),
  { operation: 'status' })
// `continue` is a zero-argument internal resume — no phase selection.
assert.deepEqual(parsePeeritSeq29CompletionDriverArgvV1(['continue']),
  { operation: 'continue' })
for (const argv of [
  [],
  ['help'],
  ['status', '--root', root],
  ['continue', 'create', '--token', 'caller-value'],
  ['continue', 'create', '--secret=caller-value'],
  ['continue', 'create', '--commit', 'caller-value'],
  ['continue', 'create', '--hash', 'a'.repeat(64)],
  ['continue', 'create', '--path', root],
  ['continue', 'create', '--command', 'anything'],
  ['continue', 'create', '--pass', 'anything'],
  ['continue', 'unknown'],
  ...PEERIT_SEQ29_COMPLETION_PHASES_V1.map(phase => ['continue', phase]),
  ['continue', 'publish'],
  ['--help', 'extra']
]) {
  assert.throws(() => parsePeeritSeq29CompletionDriverArgvV1(argv), error =>
    error.code === 'PEERIT_SEQ29_COMPLETION_USAGE')
}

const helpChild = spawnSync(process.execPath, [driverPath, '--help'], {
  encoding: 'utf8',
  env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
  shell: false
})
assert.equal(helpChild.status, 0)
assert.equal(helpChild.stderr, '')
assert.equal(helpChild.stdout, help)
assertNoRelayInterface(helpChild.stdout, 'emitted help')

const deploy = join(root, '.deploy')
const before = readdirSync(deploy).sort()
const statusChild = spawnSync(process.execPath, [driverPath, 'status'], {
  encoding: 'utf8',
  env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
  shell: false
})
assert.equal(statusChild.status, 0)
assert.equal(statusChild.stderr, '')
const emittedStatus = JSON.parse(statusChild.stdout)
assert.equal(emittedStatus.status.nextPhase, 'create')
assert.equal(emittedStatus.status.state, 'INCOMPLETE',
  'status must never report READY while the next phase has no installed handler')
assert.deepEqual(readdirSync(deploy).sort(), before,
  'driver status must be read-only')
assertNoRelayInterface(emittedStatus, 'emitted status')
assertNoRelayInterface(await runPeeritSeq29CompletionDriverV1(['status']),
  'in-process status')
await assert.rejects(runPeeritSeq29CompletionDriverV1(['continue']), error =>
  error.code === 'PEERIT_SEQ29_COMPLETION_PHASE_PENDING',
'zero-argument resume must fail closed while the next phase is not installed')

{
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  const receiptRoot = mkdtempSync(join(base,
    'peerit-seq29-driver-interface-receipts-'))
  mkdirSync(join(receiptRoot, '.deploy'), { mode: 0o755 })
  const store = createPeeritSeq29CompletionReceiptStoreV1({
    root: receiptRoot,
    installedPhases: PEERIT_SEQ29_COMPLETION_PHASES_V1
  })
  for (let index = 0;
    index < PEERIT_SEQ29_COMPLETION_PHASES_V1.length;
    index++) {
    const phase = PEERIT_SEQ29_COMPLETION_PHASES_V1[index]
    store.record({
      phase,
      artifacts: artifacts(phase, String((index + 1) % 10))
    })
  }
  const directory = join(receiptRoot, '.deploy', 'seq29-completion-v1')
  for (const name of readdirSync(directory)) {
    assertNoRelayInterface(readFileSync(join(directory, name), 'utf8'),
      'sealed completion receipt')
  }
  assertNoRelayInterface(store.inspect(), 'receipt-backed status')
}

console.log('peerit seq29 completion driver interface tests: ok')
