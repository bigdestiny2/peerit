#!/usr/bin/env node

// The production execution boundary is intentionally in-process. Qualified
// HiveRelay endpoint objects are branded by the accepted control module and
// cannot be serialized to JSON without losing their authentication identity.

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  createPeeritSeq29LimitedInboxCeremonyAuthorityV1,
  dryRunPeeritLimitedInboxTopicCeremonyV1,
  executePeeritLimitedInboxTopicCeremonyV1,
  finalizePeeritLimitedInboxTopicCeremonyV1,
  peeritLimitedInboxTopicCeremonyPlanHashV1,
  validatePeeritLimitedInboxTopicCeremonyPlanV1
} from './limited-inbox-topic-ceremony.mjs'
import { canonicalPeeritLimitedPublicInboxJsonV1 } from '../js/substrate/inbox-topic-v1.mjs'
import {
  validatePeeritLimitedPublicInboxSignedWrapperV1
} from './sign-limited-public-inbox-bootstrap.mjs'
import {
  materializePeeritSeq29LiveCeremonyFinalReceiptV1,
  materializePeeritSeq29LiveCeremonyPublicOutputsV1
} from './lib/seq29-live-ceremony-materializer.mjs'
import {
  recoverPeeritSeq29FilesystemFinalResultV1
} from './lib/seq29-live-ceremony-journal.mjs'
import {
  createPeeritSeq29LocalManagementCustodyV1
} from './lib/seq29-local-management-custody.mjs'

const CONDUCTORS = new WeakMap()

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function methods (value, names, field) {
  if (!value || typeof value !== 'object' || names.some(name => typeof value[name] !== 'function')) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_INVALID', `${field} lacks ${names.join(', ')}`)
  }
  return value
}

export function createPeeritSeq29LiveInboxCeremonyConductorV1 (input = {}) {
  exact(input, [
    'plan', 'authority', 'attemptJournal', 'custodyTransaction', 'publicOutputDirectory'
  ], 'conductor input')
  const plan = validatePeeritLimitedInboxTopicCeremonyPlanV1(input.plan)
  const planHash = peeritLimitedInboxTopicCeremonyPlanHashV1(plan)
  const acceptedAuthoritySchema = input.authority?.schema ===
    'peerit-seq29-limited-inbox-ceremony-authority-v1' ||
    input.authority?.schema ===
      'peerit-seq29-limited-inbox-ceremony-custody-first-authority-v1' ||
    (process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST === '1' &&
      input.authority?.schema ===
        'peerit-seq29-limited-inbox-ceremony-fixture-authority-v1')
  if (!input.authority || typeof input.authority !== 'object' ||
      !acceptedAuthoritySchema ||
      input.authority.planHash !== planHash || input.authority.releaseSequence !== 29) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_AUTHORITY_REQUIRED',
      'the exact in-process branded Seq29 ceremony authority is required')
  }
  methods(input.attemptJournal, [
    'beginAttempt', 'claimOperation', 'recordOutcome', 'persistRecovery', 'finishAttempt'
  ], 'attemptJournal')
  methods(input.custodyTransaction, [
    'prepare', 'commitPublicBinding', 'finalizeSignedBootstrap', 'quarantine'
  ], 'custodyTransaction')
  if (typeof input.publicOutputDirectory !== 'string' || input.publicOutputDirectory.length < 1) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_INVALID', 'publicOutputDirectory is required')
  }
  const conductor = Object.freeze({
    schema: 'peerit-seq29-live-inbox-ceremony-conductor-v1',
    version: 1,
    releaseSequence: 29,
    planHash,
    executionBoundary: 'IN_PROCESS_BRANDED_AUTHORITY_ONLY'
  })
  CONDUCTORS.set(conductor, Object.freeze({
    plan,
    authority: input.authority,
    attemptJournal: input.attemptJournal,
    custodyTransaction: input.custodyTransaction,
    publicOutputDirectory: resolve(input.publicOutputDirectory)
  }))
  return conductor
}

export async function createPeeritSeq29LiveInboxCeremonyConductorFromQualifiedAuthorityV1 (
  input = {}
) {
  exact(input, [
    'plan', 'relays', 'attemptJournal',
    'custodyTransaction', 'publicOutputDirectory'
  ], 'qualified conductor input')
  const authority = await createPeeritSeq29LimitedInboxCeremonyAuthorityV1({
    plan: input.plan,
    relays: input.relays
  })
  return createPeeritSeq29LiveInboxCeremonyConductorV1({
    plan: input.plan,
    authority,
    attemptJournal: input.attemptJournal,
    custodyTransaction: input.custodyTransaction,
    publicOutputDirectory: input.publicOutputDirectory
  })
}

// Production custody remains an in-process boundary. The provider returns
// short-lived copies of two or three local X25519 custodian private keys; the
// adapter snapshots and wipes those copies after each durable transition.
export async function createPeeritSeq29LiveInboxCeremonyConductorWithLocalCustodyV1 (
  input = {}
) {
  exact(input, [
    'plan', 'relays', 'attemptJournal',
    'publicOutputDirectory', 'custodyDirectory', 'custodianPublicKeys',
    'custodianPrivateKeyProvider'
  ], 'local-custody conductor input')
  const custodyTransaction = createPeeritSeq29LocalManagementCustodyV1({
    directory: input.custodyDirectory,
    custodianPublicKeys: input.custodianPublicKeys,
    custodianPrivateKeyProvider: input.custodianPrivateKeyProvider
  })
  return createPeeritSeq29LiveInboxCeremonyConductorFromQualifiedAuthorityV1({
    plan: input.plan,
    relays: input.relays,
    attemptJournal: input.attemptJournal,
    custodyTransaction,
    publicOutputDirectory: input.publicOutputDirectory
  })
}

export async function runPeeritSeq29LiveInboxCeremonyConductorV1 (input = {}) {
  exact(input, ['conductor', 'executeBoundary', 'commitToken'], 'conductor execution input')
  const privateState = CONDUCTORS.get(input.conductor)
  if (!privateState) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_AUTHORITY_REQUIRED',
      'a module-created in-process conductor is required')
  }
  if (input.executeBoundary !== '--execute') {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_EXECUTE_REQUIRED',
      'the exact --execute boundary is required')
  }
  const result = await executePeeritLimitedInboxTopicCeremonyV1({
    authority: privateState.authority,
    commitToken: input.commitToken,
    attemptJournal: privateState.attemptJournal,
    custodyTransaction: privateState.custodyTransaction
  })
  const materialization = materializePeeritSeq29LiveCeremonyPublicOutputsV1({
    directory: privateState.publicOutputDirectory,
    result
  })
  return Object.freeze({ result, materialization })
}

export async function finalizePeeritSeq29LiveInboxCeremonyConductorV1 (input = {}) {
  exact(input, [
    'conductor', 'executeBoundary', 'commitToken', 'signedBootstrap'
  ], 'conductor finalization input')
  const privateState = CONDUCTORS.get(input.conductor)
  if (!privateState) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_AUTHORITY_REQUIRED',
      'a module-created in-process conductor is required')
  }
  if (input.executeBoundary !== '--execute') {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_EXECUTE_REQUIRED',
      'the exact --execute boundary is required')
  }
  let result
  try {
    result = await finalizePeeritLimitedInboxTopicCeremonyV1({
      authority: privateState.authority,
      commitToken: input.commitToken,
      signedBootstrap: input.signedBootstrap,
      attemptJournal: privateState.attemptJournal,
      custodyTransaction: privateState.custodyTransaction
    })
  } catch (cause) {
    if (cause?.code !== 'PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND') throw cause
    const checked = validatePeeritLimitedPublicInboxSignedWrapperV1(input.signedBootstrap)
    const suppliedHash = createHash('sha256').update(
      canonicalPeeritLimitedPublicInboxJsonV1({
        payload: checked.payload,
        signature: checked.signature
      })
    ).digest('hex')
    result = recoverPeeritSeq29FilesystemFinalResultV1({
      journal: privateState.attemptJournal,
      planHash: input.conductor.planHash,
      signedBootstrapHash: suppliedHash
    })
  }
  const materialization = materializePeeritSeq29LiveCeremonyFinalReceiptV1({
    directory: privateState.publicOutputDirectory,
    result
  })
  return Object.freeze({ result, materialization })
}

function readCanonicalPlan (path) {
  const bytes = readFileSync(resolve(path))
  let value
  try { value = JSON.parse(bytes.toString('utf8')) } catch {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_PLAN_INVALID', 'plan is not JSON')
  }
  const canonical = Buffer.from(JSON.stringify(value, null, 2) + '\n')
  if (!canonical.equals(bytes)) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_PLAN_INVALID',
      'plan must be canonical pretty JSON with one trailing newline')
  }
  return value
}

function main () {
  if (process.argv.includes('--execute')) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_AUTHORITY_NOT_SERIALIZABLE',
      '--execute cannot load qualified opaque endpoint objects from JSON; use createPeeritSeq29LiveInboxCeremonyConductorV1 in the same process that created the branded authority')
  }
  const command = process.argv[2]
  const inputIndex = process.argv.indexOf('--input')
  const path = inputIndex >= 0 ? process.argv[inputIndex + 1] : null
  if (!path || !['validate', 'dry-run'].includes(command)) {
    fail('PEERIT_SEQ29_LIVE_CONDUCTOR_USAGE',
      'usage: seq29-live-inbox-ceremony-conductor.mjs <validate|dry-run> --input <plan.json>')
  }
  const plan = readCanonicalPlan(path)
  const report = command === 'validate'
    ? {
        status: 'VALID',
        planHash: peeritLimitedInboxTopicCeremonyPlanHashV1(plan),
        executionBoundary: 'IN_PROCESS_BRANDED_AUTHORITY_ONLY',
        networkRequests: 0
      }
    : dryRunPeeritLimitedInboxTopicCeremonyV1(plan)
  console.log(JSON.stringify(report, null, 2))
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { main() } catch (error) {
    console.error(`${error.code || 'PEERIT_SEQ29_LIVE_CONDUCTOR_FAILED'}: ${error.message}`)
    process.exitCode = 1
  }
}
