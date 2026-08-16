import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1,
  PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1,
  PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
  peeritLimitedInboxTopicCeremonyPlanHashV1
} from '../scripts/limited-inbox-topic-ceremony.mjs'
import {
  PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1
} from '../scripts/sign-limited-public-inbox-bootstrap.mjs'
import { canonicalPeeritLimitedPublicInboxJsonV1 } from '../js/substrate/inbox-topic-v1.mjs'
import {
  createPeeritSeq29FilesystemAttemptJournalV1,
  recoverPeeritSeq29FilesystemFinalResultV1
} from '../scripts/lib/seq29-live-ceremony-journal.mjs'
import {
  materializePeeritSeq29LiveCeremonyFinalReceiptV1
} from '../scripts/lib/seq29-live-ceremony-materializer.mjs'
import {
  createPeeritSeq29LiveInboxCeremonyConductorV1,
  runPeeritSeq29LiveInboxCeremonyConductorV1
} from '../scripts/seq29-live-inbox-ceremony-conductor.mjs'
import {
  decodeBlindExternalProfileValueV1
} from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'

const fixture = JSON.parse(await fs.readFile(new URL(
  './fixtures/peerit-seq29-limited-public-test-v1/positive-bootstrap.json',
  import.meta.url)))
const fixtureSet = fixture.payload.inboxEpochSets[0]
process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST = '1'
const temporaryRoots = []

function digest (value) {
  return createHash('sha256')
    .update(canonicalPeeritLimitedPublicInboxJsonV1(value)).digest('hex')
}

function fixtureSigningPackage () {
  return {
    schema: PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_PACKAGE_SCHEMA_V1,
    version: 1,
    offlineOnly: true,
    hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
    createRequests: fixtureSet.bindings.map((binding, index) => {
      const receipt = decodeBlindExternalProfileValueV1(
        'InboxReceiptV1', new Uint8Array(Buffer.from(binding.createReceiptCanonicalHex, 'hex')))
      return {
        relayId: binding.relayId,
        allocationEpoch: binding.allocationEpoch,
        physicalTopic: binding.physicalTopic,
        frameClassBits: 3,
        appendAuthMode: 0,
        createPublicKey: binding.createPublicKey,
        appendPublicKey: null,
        renewPublicKey: (index === 0 ? '71' : '72').repeat(32),
        closePublicKey: (index === 0 ? '81' : '82').repeat(32),
        retentionClass: 3,
        leaseClass: 4,
        clientNonce: Buffer.from(receipt.requestNonce).toString('hex'),
        createCommitment: (index === 0 ? '91' : '92').repeat(32),
        requestCommitment: Buffer.from(receipt.requestCommitment).toString('hex')
      }
    }),
    payload: structuredClone(fixture.payload)
  }
}

async function temporaryRoot (label) {
  const tmpBase = process.platform === 'darwin' ? '/private/tmp' : os.tmpdir()
  const root = await fs.mkdtemp(path.join(tmpBase, `peerit-seq29-${label}-`))
  temporaryRoots.push(root)
  return root
}

const plan = {
  schema: PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_PLAN_SCHEMA_V1,
  version: 1,
  hiverelayCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  releaseSequence: 29,
  claimBoundary: fixture.payload.claimBoundary,
  operatorBoundary: fixture.payload.operatorBoundary,
  topicScope: fixture.payload.topicScope,
  referenceUnixMillis: '1780000001000',
  bootstrapSequence: fixture.payload.bootstrapSequence,
  previousBootstrapHash: fixture.payload.previousBootstrapHash,
  issuedUnixMillis: fixture.payload.issuedUnixMillis,
  expiresUnixMillis: fixture.payload.expiresUnixMillis,
  authorityPublicKey: fixture.payload.authorityPublicKey,
  stripeSelectionKey: fixtureSet.stripeSelectionKey,
  announcementMasterKey: fixtureSet.announcementMasterKey,
  relays: fixture.payload.relays.map(relay => ({
    ...relay,
    allocationEpoch: fixtureSet.bindings
      .find(binding => binding.relayId === relay.relayId).allocationEpoch
  }))
}
const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
const commitToken = `${PEERIT_LIMITED_INBOX_TOPIC_CEREMONY_COMMIT_PREFIX_V1}${planHash}`
const persistedQualification = {
  schema: 'peerit-seq29-live-inbox-create-plan-continuity-v1',
  version: 1,
  planHash,
  referenceUnixMillis: plan.referenceUnixMillis,
  seedBootstrapSha256: '31'.repeat(32),
  limitedCellPutProfileSha256: '32'.repeat(32)
}
const beginRequest = {
  schema: 'peerit-limited-inbox-create-only-attempt-v1',
  releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
  candidateCommit: PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  releaseSequence: 29,
  planHash,
  relayIdentityDigest: '11'.repeat(32),
  commitTokenHash: createHash('sha256').update(commitToken).digest('hex'),
  operationBudget: { family: 'INBOX', operation: 'CREATE', maximum: 2 },
  plan,
  planSha256: digest(plan),
  persistedQualification,
  persistedQualificationSha256: digest(persistedQualification)
}

function claimRequest (attemptId, index) {
  const relayId = plan.relays[index].relayId
  return {
    attemptId,
    releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
    planHash,
    operationIndex: index,
    operationKey: `INBOX.CREATE:${relayId}`,
    family: 'INBOX',
    operation: 'CREATE',
    relayId
  }
}

function outcomeRequest (attemptId, index, state = 'VERIFIED_TERMINAL') {
  const claim = claimRequest(attemptId, index)
  return {
    attemptId,
    releaseAttemptKey: claim.releaseAttemptKey,
    planHash,
    operationKey: claim.operationKey,
    state,
    ...(state === 'VERIFIED_TERMINAL' ? { receiptSha256: `${index + 1}`.repeat(64) } : {})
  }
}

try {
  {
    const root = await temporaryRoot('interrupted')
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    const begun = await journal.beginAttempt(beginRequest)
    assert.equal(begun.state, 'CONSUMED_NO_MUTATIONS')
    await assert.rejects(
      journal.beginAttempt(beginRequest),
      error => error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND',
      'an interrupted attempt cannot resend CREATE')
    const inspection = journal.inspect()
    assert.equal(inspection.eventCount, 1)
    const files = await fs.readdir(inspection.slot)
    assert.deepEqual(files, ['0000-begin.json'])
    assert.equal((await fs.stat(path.join(inspection.slot, files[0]))).mode & 0o777, 0o600)
  }

  {
    const root = await temporaryRoot('empty-slot-crash')
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    const slot = journal.inspect().slot
    await fs.mkdir(slot, { mode: 0o700 })
    await assert.rejects(journal.beginAttempt(beginRequest),
      error => error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND',
      'a crash after slot creation but before begin sealing consumes the slot without retry')
  }

  {
    const root = await temporaryRoot('recovery')
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    const begun = await journal.beginAttempt(beginRequest)
    for (let index = 0; index < 2; index++) {
      const claim = claimRequest(begun.attemptId, index)
      const claimed = await journal.claimOperation(claim)
      assert.equal(claimed.requestDigest, digest(claim))
      await journal.recordOutcome(outcomeRequest(begun.attemptId, index))
    }
    const packageValue = fixtureSigningPackage()
    const signingPackageSha256 = digest(packageValue)
    const recovery = {
      schema: 'peerit-limited-inbox-topic-recovery-v2',
      planHash,
      attemptId: begun.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      relayIdentityDigest: beginRequest.relayIdentityDigest,
      signingPackage: packageValue,
      signingPackageSha256,
      custodyTransactionId: 'fixture-custody-transaction',
      custodyPublicBindingDigest: digest({
        schema: 'peerit-seq29-limited-inbox-custody-public-binding-v1',
        planHash,
        signingPackageSha256,
        signingPackage: packageValue
      }),
      transportInvocations: plan.relays.map(relay => `INBOX.CREATE:${relay.relayId}`),
      executionDigest: '21'.repeat(32)
    }
    const recoveryRequest = {
      attemptId: begun.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      recovery,
      recoveryDigest: digest(recovery)
    }
    await journal.persistRecovery(recoveryRequest)
    const restarted = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    const recovered = await restarted.beginAttempt(beginRequest)
    assert.equal(recovered.state, 'RECOVERY_AVAILABLE_NO_RESEND')
    assert.deepEqual(recovered.recovery, recovery)
    assert.equal(restarted.inspect().eventCount, 6,
      'recovery readback appends no event and schedules no resend')
    await restarted.finishAttempt({
      attemptId: begun.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      state: 'COMMITTED_CREATE_ONLY',
      executionDigest: '21'.repeat(32),
      signedBootstrapHash: '33'.repeat(32),
      managementBundleDigest: '44'.repeat(32),
      custodyCommitment: 'custody-commitment',
      transportInvocations: plan.relays.map(relay => `INBOX.CREATE:${relay.relayId}`)
    })
    assert.equal(restarted.inspect().eventKinds.at(-1), 'finish')
    const finalResult = recoverPeeritSeq29FilesystemFinalResultV1({
      journal: restarted,
      planHash,
      signedBootstrapHash: '33'.repeat(32)
    })
    assert.equal(finalResult.status, 'COMMITTED_CREATE_ONLY')
    assert.equal(finalResult.custodyCommitment, 'custody-commitment')
    assert.equal(finalResult.journalCommitment, restarted.inspect().finalEventHash)
    await assert.rejects(
      restarted.beginAttempt(beginRequest),
      error => error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND',
      'final result recovery reads the terminal seal without replaying custody or CREATE')
  }

  {
    const root = await temporaryRoot('partial-failure')
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    const begun = await journal.beginAttempt(beginRequest)
    await journal.claimOperation(claimRequest(begun.attemptId, 0))
    await journal.recordOutcome(outcomeRequest(
      begun.attemptId, 0, 'REJECTED_TERMINAL'))
    await journal.finishAttempt({
      attemptId: begun.attemptId,
      releaseAttemptKey: PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
      planHash,
      state: 'QUARANTINED_TERMINAL_NO_RETRY',
      recoveryPersisted: false,
      transportInvocations: [`INBOX.CREATE:${plan.relays[0].relayId}`]
    })
    await assert.rejects(
      createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
        .beginAttempt(beginRequest),
      error => error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND',
      'a partial rejected attempt remains terminal and never retries')
    assert.deepEqual(journal.inspect().eventKinds,
      ['begin', 'claim-0', 'outcome-0', 'finish'])
  }

  {
    const root = await temporaryRoot('slot-binding')
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    await journal.beginAttempt(beginRequest)
    const driftPlan = structuredClone(plan)
    driftPlan.announcementMasterKey = 'fe'.repeat(32)
    const driftPlanHash = peeritLimitedInboxTopicCeremonyPlanHashV1(driftPlan)
    const driftContinuity = {
      ...persistedQualification,
      planHash: driftPlanHash
    }
    await assert.rejects(
      journal.beginAttempt({
        ...beginRequest,
        planHash: driftPlanHash,
        plan: driftPlan,
        planSha256: digest(driftPlan),
        persistedQualification: driftContinuity,
        persistedQualificationSha256: digest(driftContinuity)
      }),
      error => error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_SLOT_CONSUMED',
      'the fixed release slot cannot be rebound to another plan')
  }

  for (const kind of ['special-mode', 'symlink', 'hardlink', 'inode-swap']) {
    const root = await temporaryRoot(`sealed-${kind}`)
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    await journal.beginAttempt(beginRequest)
    const status = journal.inspect()
    const event = path.join(status.slot, '0000-begin.json')
    if (kind === 'special-mode') {
      await fs.chmod(event, 0o1600)
    } else if (kind === 'symlink') {
      const target = path.join(root, 'symlink-target.json')
      await fs.rename(event, target)
      await fs.symlink(target, event)
    } else if (kind === 'hardlink') {
      await fs.link(event, path.join(root, 'hardlink-target.json'))
    } else {
      const replacement = path.join(root, 'inode-replacement.json')
      await fs.writeFile(replacement, await fs.readFile(event), { mode: 0o600 })
      await fs.rename(replacement, event)
    }
    assert.throws(() => journal.inspect(), error => [
      'PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      'PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS'
    ].includes(error.code), `${kind} sealed CREATE journal drift must fail closed`)
  }

  for (const fault of [
    'EVENT_CLOSE_UNCERTAIN',
    'POST_LINK_DIRECTORY_SYNC_UNCERTAIN'
  ]) {
    const root = await temporaryRoot(`journal-fault-${fault.toLowerCase()}`)
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    process.env.PEERIT_SEQ29_LIVE_JOURNAL_TEST_FAULT = fault
    try {
      await assert.rejects(journal.beginAttempt(beginRequest), error =>
        error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED')
    } finally {
      delete process.env.PEERIT_SEQ29_LIVE_JOURNAL_TEST_FAULT
    }
    assert.throws(() => journal.inspect(), error =>
      error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
    `${fault} leaves visible terminal uncertainty rather than a resumable event`)
    await assert.rejects(journal.beginAttempt(beginRequest), error =>
      error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
    `${fault} must never silently retry or accept the uncertain CREATE event`)
  }

  {
    const root = await temporaryRoot('journal-directory-inode-swap')
    const journal = createPeeritSeq29FilesystemAttemptJournalV1({ directory: root })
    await journal.beginAttempt(beginRequest)
    const slot = journal.inspect().slot
    const eventName = '0000-begin.json'
    const replacement = `${slot}.replacement`
    const retired = `${slot}.retired`
    await fs.mkdir(replacement, { mode: 0o700 })
    await fs.rename(path.join(slot, eventName), path.join(replacement, eventName))
    await fs.rename(slot, retired)
    await fs.rename(replacement, slot)
    assert.throws(() => journal.inspect(), error =>
      error.code === 'PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
    'same-content CREATE journal directory inode substitution must fail closed')
  }

  {
    const root = await temporaryRoot('public-receipt')
    const result = {
      schema: 'peerit-limited-inbox-topic-ceremony-result-v1',
      status: 'COMMITTED_CREATE_ONLY',
      planHash,
      attemptId: 'ab'.repeat(32),
      signedBootstrapHash: '51'.repeat(32),
      managementBundleDigest: '52'.repeat(32),
      custodyCommitment: 'custody-final-commitment',
      journalCommitment: '54'.repeat(32),
      mutationLedger: {
        inboxCreate: 0,
        inboxRenew: 0,
        inboxClose: 0,
        inboxAppend: 0,
        cellPut: 0,
        other: 0
      },
      recoveredOriginalMutationLedger: { inboxCreate: 2 }
    }
    const first = materializePeeritSeq29LiveCeremonyFinalReceiptV1({
      directory: root,
      result
    })
    assert.equal(first.receiptCreated, true)
    assert.equal((await fs.stat(first.receiptPath)).mode & 0o777, 0o444)
    assert.throws(
      () => materializePeeritSeq29LiveCeremonyFinalReceiptV1({
        directory: root,
        result
      }),
      error => error.code === 'PEERIT_SEQ29_LIVE_MATERIALIZATION_CONFLICT',
      'even byte-identical output cannot reuse a create-only target')
  }

  {
    const root = await temporaryRoot('owned-temp-residue')
    const result = {
      schema: 'peerit-limited-inbox-topic-ceremony-result-v1',
      status: 'COMMITTED_CREATE_ONLY',
      planHash,
      attemptId: 'ad'.repeat(32),
      signedBootstrapHash: '61'.repeat(32),
      managementBundleDigest: '62'.repeat(32),
      custodyCommitment: 'custody-residue-proof',
      journalCommitment: '63'.repeat(32),
      mutationLedger: {
        inboxCreate: 0,
        inboxRenew: 0,
        inboxClose: 0,
        inboxAppend: 0,
        cellPut: 0,
        other: 0
      },
      recoveredOriginalMutationLedger: { inboxCreate: 2 }
    }
    const ownedResidue = path.join(root,
      '.peerit-seq29-limited-public-inbox-ceremony-receipt-v1.json.999.aaaaaaaaaaaaaaaaaaaaaaaa.tmp')
    const unrelated = path.join(root, '.unrelated.999.aaaaaaaaaaaaaaaaaaaaaaaa.tmp')
    await fs.writeFile(ownedResidue, 'stale', { mode: 0o600 })
    await fs.writeFile(unrelated, 'unrelated', { mode: 0o600 })
    assert.throws(
      () => materializePeeritSeq29LiveCeremonyFinalReceiptV1({ directory: root, result }),
      error => error.code === 'PEERIT_SEQ29_LIVE_MATERIALIZATION_TEMP_RESIDUE',
      'exact owned temporary residue fails before materialization')
    assert.equal(await fs.readFile(ownedResidue, 'utf8'), 'stale')
    assert.equal(await fs.readFile(unrelated, 'utf8'), 'unrelated')
    await assert.rejects(
      fs.access(path.join(root,
        'peerit-seq29-limited-public-inbox-ceremony-receipt-v1.json')),
      'owned residue failure leaves no target output')
  }

  for (const nested of [false, true]) {
    const root = await temporaryRoot(nested ? 'nested-getter' : 'custody-getter')
    let getterCalls = 0
    const mutationLedger = {
      inboxCreate: 0,
      inboxRenew: 0,
      inboxClose: 0,
      inboxAppend: 0,
      cellPut: 0,
      other: 0
    }
    if (nested) {
      Object.defineProperty(mutationLedger, 'other', {
        enumerable: true,
        configurable: true,
        get () {
          getterCalls++
          return getterCalls === 1 ? 0 : 'SECRET_SEED'
        }
      })
    }
    const result = {
      schema: 'peerit-limited-inbox-topic-ceremony-result-v1',
      status: 'COMMITTED_CREATE_ONLY',
      planHash,
      attemptId: 'ae'.repeat(32),
      signedBootstrapHash: '71'.repeat(32),
      managementBundleDigest: '72'.repeat(32),
      custodyCommitment: 'safe-custody-commitment',
      journalCommitment: '73'.repeat(32),
      mutationLedger,
      recoveredOriginalMutationLedger: { inboxCreate: 2 }
    }
    if (!nested) {
      Object.defineProperty(result, 'custodyCommitment', {
        enumerable: true,
        configurable: true,
        get () {
          getterCalls++
          return getterCalls === 1 ? 'safe-custody-commitment' : 'SECRET_SEED'
        }
      })
    }
    assert.throws(
      () => materializePeeritSeq29LiveCeremonyFinalReceiptV1({ directory: root, result }),
      error => error.code === 'PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      `${nested ? 'nested' : 'custodyCommitment'} getter is rejected as non-data`)
    assert.equal(getterCalls, 0, 'rejected accessors are never invoked')
    assert.deepEqual(await fs.readdir(root), [],
      'accessor rejection creates neither target nor owned temporary output')
  }

  {
    const root = await temporaryRoot('cli')
    const planPath = path.join(root, 'plan.json')
    await fs.writeFile(planPath, JSON.stringify(plan, null, 2) + '\n')
    const script = path.resolve('scripts/seq29-live-inbox-ceremony-conductor.mjs')
    const validate = JSON.parse(execFileSync(process.execPath,
      [script, 'validate', '--input', planPath], { encoding: 'utf8' }))
    assert.equal(validate.status, 'VALID')
    assert.equal(validate.networkRequests, 0)
    const dryRun = JSON.parse(execFileSync(process.execPath,
      [script, 'dry-run', '--input', planPath], { encoding: 'utf8' }))
    assert.equal(dryRun.status, 'DRY_RUN_NO_NETWORK')
    assert.equal(dryRun.networkRequests, 0)
    assert.equal(dryRun.commitToken, commitToken)
    assert.throws(
      () => execFileSync(process.execPath,
        [script, 'dry-run', '--input', planPath, '--execute'], { encoding: 'utf8' }),
      error => error.stderr.includes('PEERIT_SEQ29_LIVE_CONDUCTOR_AUTHORITY_NOT_SERIALIZABLE'),
      'the standalone CLI refuses to deserialize raw endpoints for execution')
  }

  {
    let journalCalls = 0
    const attemptJournal = Object.fromEntries([
      'beginAttempt', 'claimOperation', 'recordOutcome', 'persistRecovery', 'finishAttempt'
    ].map(name => [name, async () => { journalCalls++; throw new Error(name) }]))
    const custodyTransaction = Object.fromEntries([
      'prepare', 'commitPublicBinding', 'finalizeSignedBootstrap', 'quarantine'
    ].map(name => [name, async () => { throw new Error(name) }]))
    const forgedAuthority = {
      schema: 'peerit-seq29-limited-inbox-ceremony-authority-v1',
      planHash,
      releaseSequence: 29
    }
    const conductor = createPeeritSeq29LiveInboxCeremonyConductorV1({
      plan,
      authority: forgedAuthority,
      attemptJournal,
      custodyTransaction,
      publicOutputDirectory: await temporaryRoot('forged-authority-output')
    })
    await assert.rejects(
      runPeeritSeq29LiveInboxCeremonyConductorV1({
        conductor,
        executeBoundary: '--execute',
        commitToken
      }),
      error => error.code === 'PEERIT_LIMITED_INBOX_CEREMONY_AUTHORITY_INVALID')
    assert.equal(journalCalls, 0,
      'core authority branding rejects a forged conductor before journal or transport')
  }

  console.log('peerit seq29 live ceremony conductor tests: ok')
} finally {
  await Promise.all(temporaryRoots.map(root => fs.rm(root, { recursive: true, force: true })))
}
