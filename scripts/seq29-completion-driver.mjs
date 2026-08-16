#!/usr/bin/env node

import { createHash } from 'node:crypto'
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync
} from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  createPeeritSeq29CompletionReceiptStoreV1,
  inspectPeeritSeq29CompletionStatusV1
} from './lib/seq29-completion-receipts.mjs'
import { appendPeeritSeq29PinHistoryJournaledV1 } from
  './lib/seq29-pin-history-writer.mjs'
import {
  beginPeeritSeq29InitialWebPrepareV1,
  completePeeritSeq29InitialWebPrepareV1
} from './lib/seq29-initial-web-prepare-journal.mjs'
import {
  PEERIT_SEQ29_COMPLETION_CREATE_ARTIFACTS_V1,
  runPeeritSeq29CompletionCreatePhaseV1
} from './lib/seq29-completion-live-create.mjs'
import {
  PEERIT_SEQ29_COMPLETION_DECISION_PIN_ARTIFACTS_V1,
  PEERIT_SEQ29_COMPLETION_DEPLOY_WEB_ARTIFACTS_V1,
  runPeeritSeq29CompletionDecisionPinPhaseV1,
  runPeeritSeq29CompletionDeployWebPhaseV1,
  runPeeritSeq29CompletionHistorySignPhaseV1,
  runPeeritSeq29CompletionReleaseSignPhaseV1
} from './lib/seq29-completion-static-phases.mjs'
import { runPeeritSeq29WebReleasePhaseV1 } from './web-release.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const STATUS_SCHEMA = 'peerit-seq29-completion-driver-result-v1'
const ERROR_SCHEMA = 'peerit-seq29-completion-driver-error-v1'

const FIXED_ARTIFACTS = Object.freeze({
  create: PEERIT_SEQ29_COMPLETION_CREATE_ARTIFACTS_V1,
  'web-prepare': Object.freeze({
    'outer-manifest': Object.freeze(['web/asset-manifest.json', 0o644]),
    'prepare-journal': Object.freeze([
      '.deploy/seq29-initial-web-prepare-v1/committed.json', 0o600
    ]),
    'signing-request': Object.freeze(['deploy/web-signing-request.json', 0o644])
  }),
  'release-sign': Object.freeze({
    'outer-signature': Object.freeze(['web/asset-manifest.sig', 0o644])
  }),
  'decision-pin': PEERIT_SEQ29_COMPLETION_DECISION_PIN_ARTIFACTS_V1,
  'web-reprepare': Object.freeze({
    'app-artifact': Object.freeze(['web/peerit-app-artifact-v1.json', 0o644]),
    'canonical-manifest': Object.freeze(['web/peerit-web-assets-v1.cenc', 0o644]),
    'outer-manifest': Object.freeze(['web/asset-manifest.json', 0o644]),
    'outer-signature': Object.freeze(['web/asset-manifest.sig', 0o644]),
    'signing-request': Object.freeze(['deploy/web-signing-request.json', 0o644])
  }),
  'deploy-web': PEERIT_SEQ29_COMPLETION_DEPLOY_WEB_ARTIFACTS_V1,
  'history-append': Object.freeze({
    'pin-history': Object.freeze(['deploy/web-release-pin-history.json', 0o644])
  }),
  'history-sign': Object.freeze({
    'pin-history-signature': Object.freeze([
      'deploy/web-release-pin-history.json.sig.json', 0o644
    ])
  }),
  verify: Object.freeze({
    'verification-report': Object.freeze(['.deploy/last-web-release.json', 0o644])
  })
})

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

export function peeritSeq29CompletionDriverHelpV1 () {
  return [
    'usage: node scripts/seq29-completion-driver.mjs status',
    '       node scripts/seq29-completion-driver.mjs continue'
  ].join('\n') + '\n'
}

// The fixed interface is exactly `status`, zero-argument `continue` and
// `--help`. No phase selection, token, hash, path, phrase, command or
// caller-relayed value of any kind: `continue` resumes internally at the
// exact next durable phase proven by the sealed receipt chain.
export function parsePeeritSeq29CompletionDriverArgvV1 (argv) {
  if (!Array.isArray(argv) || Object.keys(argv).join('\0') !==
      Array.from({ length: argv.length }, (_, index) => String(index)).join('\0') ||
      argv.some(value => typeof value !== 'string')) {
    fail('PEERIT_SEQ29_COMPLETION_USAGE', 'driver arguments are not exact strings')
  }
  if (argv.length === 1 && argv[0] === '--help') {
    return Object.freeze({ operation: 'help' })
  }
  if (argv.length === 1 && argv[0] === 'status') {
    return Object.freeze({ operation: 'status' })
  }
  if (argv.length === 1 && argv[0] === 'continue') {
    return Object.freeze({ operation: 'continue' })
  }
  fail('PEERIT_SEQ29_COMPLETION_USAGE', 'driver invocation is outside the fixed interface')
}

function fullMode (metadata) {
  return metadata.mode & 0o7777n
}

function sameFileIdentity (left, right) {
  return left.isFile() && right.isFile() &&
    !left.isSymbolicLink() && !right.isSymbolicLink() &&
    left.dev === right.dev && left.ino === right.ino &&
    left.uid === right.uid && left.gid === right.gid &&
    left.mode === right.mode && left.nlink === right.nlink &&
    left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
}

function assertTrustedArtifactParents (root, path) {
  const rootPath = resolve(root)
  const parent = dirname(resolve(path))
  const suffix = relative(rootPath, parent)
  if (suffix === '..' || suffix.startsWith(`..${sep}`)) {
    fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
      'fixed completion artifact escapes the repository root')
  }
  let cursor = rootPath
  for (const part of ['', ...(suffix === '' ? [] : suffix.split(sep))]) {
    if (part !== '') cursor = join(cursor, part)
    let metadata
    try { metadata = lstatSync(cursor, { bigint: true }) } catch {
      fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
        'fixed completion artifact parent is missing')
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
        (fullMode(metadata) & 0o7022n) !== 0n ||
        (typeof process.getuid === 'function' &&
          metadata.uid !== BigInt(process.getuid()))) {
      fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
        'fixed completion artifact parent is not trusted')
    }
  }
}

function digestFixedFile (root, relativePath, expectedMode) {
  const path = join(root, relativePath)
  assertTrustedArtifactParents(root, path)
  let named
  try { named = lstatSync(path, { bigint: true }) } catch {
    fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
      'fixed completion artifact is missing')
  }
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n ||
      fullMode(named) !== BigInt(expectedMode) ||
      named.size > 16n * 1024n * 1024n ||
      (typeof process.getuid === 'function' &&
        named.uid !== BigInt(process.getuid()))) {
    fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
      'fixed completion artifact identity is invalid')
  }
  let descriptor
  let content
  let primary
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor, { bigint: true })
    if (!sameFileIdentity(named, opened) || opened.nlink !== 1n ||
        fullMode(opened) !== BigInt(expectedMode)) {
      fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
        'fixed completion artifact changed before authenticated read')
    }
    content = readFileSync(descriptor)
    const after = fstatSync(descriptor, { bigint: true })
    const namedAfter = lstatSync(path, { bigint: true })
    if (BigInt(content.byteLength) !== opened.size ||
        !sameFileIdentity(opened, after) ||
        !sameFileIdentity(opened, namedAfter) || namedAfter.nlink !== 1n ||
        fullMode(namedAfter) !== BigInt(expectedMode)) {
      fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
        'fixed completion artifact changed during authenticated read')
    }
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try { closeSync(descriptor) } catch {
      if (!primary) primary = new Error('artifact close uncertainty')
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_SEQ29_')) throw primary
    fail('PEERIT_SEQ29_COMPLETION_ARTIFACT_INVALID',
      'fixed completion artifact could not be authenticated')
  }
  return createHash('sha256').update(content).digest('hex')
}

function fixedArtifacts (root, phase) {
  const fields = FIXED_ARTIFACTS[phase]
  if (!fields) {
    fail('PEERIT_SEQ29_COMPLETION_PHASE_PENDING',
      'fixed phase authority is not yet installed')
  }
  return Object.freeze(Object.fromEntries(Object.entries(fields).map(
    ([field, [path, mode]]) => [field, digestFixedFile(root, path, mode)])))
}

// Installed fixed phase handlers: every phase of the frozen chain now has
// one. Status honesty still derives from this exact set — a phase without an
// installed handler would report INCOMPLETE and `continue` would fail
// closed; the receipts library pins that fail-closed semantic. Live
// authority (keyvault signing seed, relay writes, static deploy) is
// exercised only inside the handler of the phase that needs it, when the
// operator resumes; never during status.
const PHASE_HANDLERS = Object.freeze({
  create: async (root) => {
    await runPeeritSeq29CompletionCreatePhaseV1(root)
  },
  'web-prepare': async (root) => {
    const prepared = beginPeeritSeq29InitialWebPrepareV1({ root })
    if (prepared.state !== 'COMPLETED') {
      await runPeeritSeq29WebReleasePhaseV1({ phase: 'prepare' })
      completePeeritSeq29InitialWebPrepareV1({ root })
    }
  },
  'release-sign': async (root) => {
    await runPeeritSeq29CompletionReleaseSignPhaseV1(root)
  },
  'decision-pin': async (root) => {
    await runPeeritSeq29CompletionDecisionPinPhaseV1(root)
  },
  'web-reprepare': async () => {
    await runPeeritSeq29WebReleasePhaseV1({ phase: 'prepare' })
  },
  'deploy-web': async (root) => {
    await runPeeritSeq29CompletionDeployWebPhaseV1(root)
  },
  'history-append': async (root) => {
    appendPeeritSeq29PinHistoryJournaledV1({ root })
  },
  'history-sign': async (root) => {
    await runPeeritSeq29CompletionHistorySignPhaseV1(root)
  },
  verify: async () => {
    await runPeeritSeq29WebReleasePhaseV1({ phase: 'verify' })
  }
})
const INSTALLED_PHASES = Object.freeze(Object.keys(PHASE_HANDLERS))

// Exported for the offline phase-handler contract tests; the fixed evidence
// set and installed-phase registry are part of the driver contract.
export const PEERIT_SEQ29_COMPLETION_FIXED_ARTIFACTS_V1 = FIXED_ARTIFACTS
export const PEERIT_SEQ29_COMPLETION_INSTALLED_PHASES_V1 = INSTALLED_PHASES

async function continuePhase (root, phase) {
  const handler = PHASE_HANDLERS[phase]
  if (!handler) {
    fail('PEERIT_SEQ29_COMPLETION_PHASE_PENDING',
      'fixed phase authority is not yet installed')
  }
  await handler(root)
  return fixedArtifacts(root, phase)
}

function driverResult (status) {
  return Object.freeze({
    schema: STATUS_SCHEMA,
    version: 1,
    status
  })
}

function inspectStatus () {
  return inspectPeeritSeq29CompletionStatusV1({
    root: ROOT,
    installedPhases: INSTALLED_PHASES
  })
}

export async function runPeeritSeq29CompletionDriverV1 (argv) {
  const parsed = parsePeeritSeq29CompletionDriverArgvV1(argv)
  if (parsed.operation === 'help') {
    return Object.freeze({ help: peeritSeq29CompletionDriverHelpV1() })
  }
  const status = inspectStatus()
  if (parsed.operation === 'status') {
    return driverResult(status)
  }
  // Zero-argument internal resume: the sealed receipt chain alone selects
  // the next phase. A complete chain is idempotent; an incomplete chain
  // whose next phase has no installed handler fails closed — status must
  // have already reported INCOMPLETE for exactly this state.
  if (status.state === 'COMPLETE') {
    return driverResult(status)
  }
  if (status.state !== 'READY' || status.nextPhase === null) {
    fail('PEERIT_SEQ29_COMPLETION_PHASE_PENDING',
      'fixed phase authority is not yet installed')
  }
  const artifacts = await continuePhase(ROOT, status.nextPhase)
  const store = createPeeritSeq29CompletionReceiptStoreV1({
    root: ROOT,
    installedPhases: INSTALLED_PHASES
  })
  return driverResult(store.record({ phase: status.nextPhase, artifacts }))
}

function emit (value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n')
}

const direct = process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (direct) {
  runPeeritSeq29CompletionDriverV1(process.argv.slice(2)).then(value => {
    if (Object.hasOwn(value, 'help')) process.stdout.write(value.help)
    else emit(value)
  }).catch(error => {
    const detailTrail = []
    for (let cursor = error; cursor; cursor = cursor.cause) {
      if (cursor.details && typeof cursor.details === 'object') {
        detailTrail.push({ code: String(cursor.code || ''), ...cursor.details })
      }
      if (detailTrail.length >= 4) break
    }
    emit({
      schema: ERROR_SCHEMA,
      version: 1,
      state: 'BLOCKED',
      code: String(error?.code || 'PEERIT_SEQ29_COMPLETION_FAILED'),
      ...(detailTrail.length > 0 ? { details: detailTrail } : {})
    })
    process.exitCode = 1
  })
}
