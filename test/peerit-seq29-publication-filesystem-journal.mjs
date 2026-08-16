import assert from 'node:assert/strict'
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1
} from '../scripts/limited-public-inbox-publication-drill.mjs'
import {
  createPeeritSeq29PublicationFilesystemJournalV1,
  recoverPeeritSeq29PublicationFilesystemResultV1
} from '../scripts/lib/seq29-publication-filesystem-journal.mjs'

const relays = Object.freeze(['dal-1', 'syd-1'])
const manifest = Object.freeze([
  ...relays.map(relayId => `CELL.PUT:${relayId}`),
  ...relays.map(relayId => `INBOX.APPEND:${relayId}`)
])
const beginRequest = Object.freeze({
  schema: 'peerit-seq29-bounded-publication-attempt-v1',
  releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
  releaseIdentityDigest: '11'.repeat(32),
  operationManifest: manifest
})

function root (label) {
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  return mkdtempSync(join(base, `peerit-seq29-publication-${label}-`))
}

function claim (attemptId, index) {
  return Object.freeze({
    attemptId,
    releaseAttemptKey: PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1,
    releaseIdentityDigest: beginRequest.releaseIdentityDigest,
    operationIndex: index,
    operationKey: manifest[index],
    requestSha256: String(index + 2).repeat(64),
    requestCommitment: String(index + 6).repeat(64)
  })
}

function outcome (claim, state = 'VERIFIED_TERMINAL') {
  return Object.freeze({
    attemptId: claim.attemptId,
    releaseAttemptKey: claim.releaseAttemptKey,
    releaseIdentityDigest: claim.releaseIdentityDigest,
    operationKey: claim.operationKey,
    requestSha256: claim.requestSha256,
    state,
    ...(state === 'VERIFIED_TERMINAL'
      ? { resultSha256: 'a'.repeat(64) }
      : {})
  })
}

function dispatch (claim) {
  const [familyOperation, relayId] = claim.operationKey.split(':')
  const [family, operation] = familyOperation.split('.')
  return Object.freeze({
    family,
    operation,
    relayId,
    operationKey: claim.operationKey,
    requestSha256: claim.requestSha256,
    requestCommitment: claim.requestCommitment
  })
}

async function committedJournal () {
  const directory = root('committed')
  const journal = createPeeritSeq29PublicationFilesystemJournalV1({ directory })
  const begun = await journal.beginAttempt(beginRequest)
  const claims = []
  for (let index = 0; index < 4; index++) {
    const request = claim(begun.attemptId, index)
    claims.push(request)
    await journal.claimOperation(request)
    await journal.recordOutcome(outcome(request))
  }
  await journal.finishAttempt({
    attemptId: begun.attemptId,
    releaseAttemptKey: begun.releaseAttemptKey,
    releaseIdentityDigest: begun.releaseIdentityDigest,
    executionDigest: 'f'.repeat(64),
    state: 'COMMITTED_EXACT_BUDGET',
    dispatches: claims.map(dispatch)
  })
  return { directory, journal, claims }
}

{
  const directory = root('empty-slot-crash')
  const journal = createPeeritSeq29PublicationFilesystemJournalV1({ directory })
  mkdirSync(journal.inspect().slot, { mode: 0o700 })
  await assert.rejects(journal.beginAttempt(beginRequest),
    error => error.code === 'PEERIT_SEQ29_PUBLICATION_JOURNAL_NO_RETRY',
    'an unsealed but consumed publication slot can never be retried')
}

{
  const { journal } = await committedJournal()
  assert.deepEqual(journal.inspect().eventKinds, [
    'begin', 'claim', 'outcome', 'claim', 'outcome',
    'claim', 'outcome', 'claim', 'outcome', 'finish'
  ])
  const result = recoverPeeritSeq29PublicationFilesystemResultV1({ journal })
  assert.equal(result.status, 'COMMITTED_EXACT_BUDGET')
  assert.equal(result.claimedDispatches, 4)
  assert.equal(result.verifiedMutations, 4)
  assert.equal(result.ambiguousDispatches, 0)
  assert.deepEqual(result.mutationLedger, {
    cellPut: 2,
    inboxAppend: 2,
    inboxCreate: 0,
    inboxRenew: 0,
    inboxClose: 0,
    other: 0
  })
}

{
  const directory = root('dispatch-drift')
  const journal = createPeeritSeq29PublicationFilesystemJournalV1({ directory })
  const begun = await journal.beginAttempt(beginRequest)
  const request = claim(begun.attemptId, 0)
  await journal.claimOperation(request)
  await journal.recordOutcome(outcome(request, 'AMBIGUOUS_TERMINAL'))
  const drifted = { ...dispatch(request), requestCommitment: 'e'.repeat(64) }
  await assert.rejects(journal.finishAttempt({
    attemptId: begun.attemptId,
    releaseAttemptKey: begun.releaseAttemptKey,
    releaseIdentityDigest: begun.releaseIdentityDigest,
    executionDigest: 'f'.repeat(64),
    state: 'TERMINAL_NO_RETRY',
    dispatches: [drifted]
  }), error => error.code === 'PEERIT_SEQ29_PUBLICATION_JOURNAL_TERMINAL')
  await journal.finishAttempt({
    attemptId: begun.attemptId,
    releaseAttemptKey: begun.releaseAttemptKey,
    releaseIdentityDigest: begun.releaseIdentityDigest,
    executionDigest: 'f'.repeat(64),
    state: 'TERMINAL_NO_RETRY',
    dispatches: [dispatch(request)]
  })
  const result = recoverPeeritSeq29PublicationFilesystemResultV1({ journal })
  assert.equal(result.verifiedMutations, 0,
    'an ambiguous claimed send is not reported as a mutation')
  assert.equal(result.ambiguousDispatches, 1)
  assert.equal(result.mutationLedger.cellPut, 0)
  await assert.rejects(journal.beginAttempt(beginRequest),
    error => error.code === 'PEERIT_SEQ29_PUBLICATION_JOURNAL_NO_RETRY')
}

for (const kind of ['special-mode', 'symlink', 'hardlink', 'inode-swap']) {
  const directory = root(kind)
  const journal = createPeeritSeq29PublicationFilesystemJournalV1({ directory })
  await journal.beginAttempt(beginRequest)
  const status = journal.inspect()
  const event = join(status.slot, '0000-begin.json')
  if (kind === 'special-mode') {
    chmodSync(event, 0o1600)
  } else if (kind === 'symlink') {
    const target = join(directory, 'symlink-target.json')
    renameSync(event, target)
    symlinkSync(target, event)
  } else if (kind === 'hardlink') {
    linkSync(event, join(directory, 'hardlink-target.json'))
  } else {
    const replacement = `${event}.replacement`
    writeFileSync(replacement, readFileSync(event), { mode: 0o600 })
    renameSync(replacement, event)
  }
  assert.throws(() => journal.inspect(), error => [
    'PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
    'PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS'
  ].includes(error.code), `${kind} must fail closed`)
}

for (const fault of [
  'EVENT_CLOSE_UNCERTAIN',
  'POST_LINK_DIRECTORY_SYNC_UNCERTAIN'
]) {
  const directory = root(`fault-${fault.toLowerCase()}`)
  const journal = createPeeritSeq29PublicationFilesystemJournalV1({ directory })
  process.env.PEERIT_SEQ29_PUBLICATION_JOURNAL_TEST_FAULT = fault
  try {
    await assert.rejects(journal.beginAttempt(beginRequest), error =>
      error.code === 'PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED')
  } finally {
    delete process.env.PEERIT_SEQ29_PUBLICATION_JOURNAL_TEST_FAULT
  }
  assert.throws(() => journal.inspect(), error =>
    error.code === 'PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
  `${fault} must leave terminal visible uncertainty rather than a resumable event`)
  await assert.rejects(journal.beginAttempt(beginRequest), error =>
    error.code === 'PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
  `${fault} must never silently retry or accept the uncertain event`)
}

{
  const directory = root('directory-inode-swap')
  const journal = createPeeritSeq29PublicationFilesystemJournalV1({ directory })
  await journal.beginAttempt(beginRequest)
  const slot = journal.inspect().slot
  const eventName = '0000-begin.json'
  const replacement = `${slot}.replacement`
  const retired = `${slot}.retired`
  mkdirSync(replacement, { mode: 0o700 })
  renameSync(join(slot, eventName), join(replacement, eventName))
  renameSync(slot, retired)
  renameSync(replacement, slot)
  assert.throws(() => journal.inspect(), error =>
    error.code === 'PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
  'same-content publication directory inode substitution must fail closed')
}

console.log('peerit seq29 publication filesystem journal tests: ok')
