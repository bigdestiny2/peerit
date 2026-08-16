import assert from 'node:assert/strict'
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createPeeritSeq29CompletionReceiptStoreV1,
  inspectPeeritSeq29CompletionStatusV1,
  PEERIT_SEQ29_COMPLETION_PHASES_V1
} from '../scripts/lib/seq29-completion-receipts.mjs'

const keys = Object.freeze({
  create: ['create-journal', 'plan', 'public-inbox-bootstrap', 'qualification'],
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
})

function fixture (label, deployMode = 0o755) {
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  const root = mkdtempSync(join(base, `peerit-seq29-receipts-${label}-`))
  mkdirSync(join(root, '.deploy'), { mode: deployMode })
  return {
    root,
    store: createPeeritSeq29CompletionReceiptStoreV1({
      root,
      installedPhases: PEERIT_SEQ29_COMPLETION_PHASES_V1
    })
  }
}

function artifacts (phase, digit = 'a') {
  return Object.fromEntries(keys[phase].map(key => [key, digit.repeat(64)]))
}

{
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  const root = mkdtempSync(join(base, 'peerit-seq29-receipts-read-only-'))
  const before = statSync(root)
  const status = inspectPeeritSeq29CompletionStatusV1({
    root,
    installedPhases: []
  })
  assert.equal(status.nextPhase, 'create')
  assert.equal(status.state, 'INCOMPLETE',
    'an uninstalled next phase must report INCOMPLETE, never READY')
  assert.equal(inspectPeeritSeq29CompletionStatusV1({
    root,
    installedPhases: ['create']
  }).state, 'READY',
  'an installed next phase is the only READY state short of COMPLETE')
  assert.throws(() => inspectPeeritSeq29CompletionStatusV1({ root }),
    error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_INVALID',
    'status without a declared installed phase list fails closed')
  assert.throws(() => inspectPeeritSeq29CompletionStatusV1({
    root,
    installedPhases: ['publish']
  }), error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_INVALID',
  'a removed live-publication phase is not installable')
  assert.equal(statSync(root).ino, before.ino)
  assert.throws(() => statSync(join(root, '.deploy')), /ENOENT/,
    'read-only status must not create its evidence directory')
}

{
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  const root = mkdtempSync(join(base, 'peerit-seq29-receipts-deploy-link-'))
  const target = mkdtempSync(join(base, 'peerit-seq29-receipts-deploy-target-'))
  symlinkSync(target, join(root, '.deploy'))
  assert.throws(() => inspectPeeritSeq29CompletionStatusV1({
    root,
    installedPhases: []
  }), error =>
    error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
  'status must authenticate an existing outer deployment directory')
}

{
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  const root = mkdtempSync(join(base, 'peerit-seq29-receipts-empty-swap-'))
  const deploy = join(root, '.deploy')
  mkdirSync(deploy, { mode: 0o755 })
  assert.equal(inspectPeeritSeq29CompletionStatusV1({
    root,
    installedPhases: []
  }).nextPhase, 'create')
  const replacement = join(root, '.deploy-replacement')
  const retired = join(root, '.deploy-retired')
  mkdirSync(replacement, { mode: 0o755 })
  renameSync(deploy, retired)
  renameSync(replacement, deploy)
  assert.throws(() => inspectPeeritSeq29CompletionStatusV1({
    root,
    installedPhases: []
  }), error =>
    error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
  'empty status must reject an outer deployment directory inode substitution')
}

{
  const { root, store } = fixture('outer-0755')
  assert.equal(store.inspect().nextPhase, 'create')
  assert.equal(statSync(join(root, '.deploy')).mode &
    0o7777, 0o755)
  for (let index = 0; index < PEERIT_SEQ29_COMPLETION_PHASES_V1.length; index++) {
    const phase = PEERIT_SEQ29_COMPLETION_PHASES_V1[index]
    const status = store.record({
      phase,
      artifacts: artifacts(phase, ((index + 1) % 10).toString())
    })
    assert.equal(status.completedPhases.at(-1), phase)
    assert.equal(status.receipts.at(-1).phase, phase)
  }
  assert.equal(store.inspect().state, 'COMPLETE')
}

for (const [label, value] of [
  ['empty', {}],
  ['missing', { 'create-journal': 'a'.repeat(64) }],
  ['extra', { ...artifacts('create'), unexpected: 'a'.repeat(64) }]
]) {
  const { store } = fixture(label)
  assert.throws(() => store.record({ phase: 'create', artifacts: value }),
    error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_INVALID')
}

{
  const { store } = fixture('close-uncertain')
  process.env.PEERIT_SEQ29_COMPLETION_RECEIPT_TEST_FAULT = 'CLOSE_UNCERTAIN'
  assert.throws(() => store.record({
    phase: 'create',
    artifacts: artifacts('create')
  }), error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED')
  delete process.env.PEERIT_SEQ29_COMPLETION_RECEIPT_TEST_FAULT
  assert.throws(() => store.inspect(),
    error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
    'uncertain close status can never be reported as completed')
}

{
  const { store } = fixture('directory-sync-uncertain')
  process.env.PEERIT_SEQ29_COMPLETION_RECEIPT_TEST_FAULT =
    'DIRECTORY_SYNC_UNCERTAIN'
  assert.throws(() => store.record({
    phase: 'create',
    artifacts: artifacts('create')
  }), error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED')
  delete process.env.PEERIT_SEQ29_COMPLETION_RECEIPT_TEST_FAULT
  assert.throws(() => store.inspect(),
    error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
    'directory-sync uncertainty leaves its durable intent and cannot appear complete')
}

for (const kind of ['special-mode', 'symlink', 'hardlink', 'inode-swap']) {
  const { root, store } = fixture(kind)
  store.record({ phase: 'create', artifacts: artifacts('create') })
  store.inspect()
  const receipt = join(root, '.deploy', 'seq29-completion-v1',
    '0000-create.json')
  if (kind === 'special-mode') {
    chmodSync(receipt, 0o1600)
  } else if (kind === 'symlink') {
    const target = join(root, 'receipt-symlink-target')
    renameSync(receipt, target)
    symlinkSync(target, receipt)
  } else if (kind === 'hardlink') {
    linkSync(receipt, join(root, 'receipt-alias'))
  } else {
    const replacement = join(root, 'receipt-replacement')
    writeFileSync(replacement, readFileSync(receipt), { mode: 0o600 })
    renameSync(replacement, receipt)
  }
  assert.throws(() => store.inspect(),
    error => error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT')
}

{
  const { root, store } = fixture('directory-inode-swap')
  store.record({ phase: 'create', artifacts: artifacts('create') })
  const directory = join(root, '.deploy', 'seq29-completion-v1')
  const eventName = '0000-create.json'
  const replacement = `${directory}.replacement`
  const retired = `${directory}.retired`
  mkdirSync(replacement, { mode: 0o700 })
  renameSync(join(directory, eventName), join(replacement, eventName))
  renameSync(directory, retired)
  renameSync(replacement, directory)
  assert.throws(() => store.inspect(), error =>
    error.code === 'PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
  'same-content completion receipt directory substitution must fail closed')
}

console.log('peerit seq29 completion receipt tests: ok')
