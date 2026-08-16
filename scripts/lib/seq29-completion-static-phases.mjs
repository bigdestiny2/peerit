// Sequence-29 completion driver: the offline/static phase handlers —
// release-sign, decision-pin, deploy-web and history-sign. Every secret
// enters through the keyvault-injected process environment only; nothing is
// accepted from caller-supplied values. Each handler fails closed with a
// coded error before touching the network or the filesystem when its
// required authority is absent.

import { spawnSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  materializePeeritSeq29OwnerDecisionV1,
  writePeeritSeq29OwnerDecisionCreateOnlyV1,
  verifyPinnedPeeritSeq29OwnerDecisionV1,
  PEERIT_SEQ29_DECISION_DRAFT_PATH_V1,
  PEERIT_SEQ29_DECISION_PATH_V1,
  PEERIT_SEQ29_DECISION_SHA256_V1,
  PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1
} from '../seq29-owner-decision.mjs'

const RELEASE_SIGNING_SEED_ENV = 'PEERIT_RELEASE_SIGNING_SEED'
const HEX64 = /^[0-9a-f]{64}$/
const DECISION_SOURCE_PATH = 'scripts/seq29-owner-decision.mjs'
const UNPINNED_SOURCE_LINE =
  "export const PEERIT_SEQ29_DECISION_SHA256_V1 = ''"
const DEPLOY_STATE_DIRECTORY = '.deploy/seq29-deploy-web-v1'
const DEPLOY_RECEIPT_NAME = 'deploy-receipt.json'
const DEPLOY_VERIFY_URL = 'https://peerit.site'
const DEPLOY_VERIFY_TIMEOUT_MILLIS = 10 * 60 * 1000
const DEPLOY_VERIFY_INTERVAL_MILLIS = 15 * 1000

// The exact seq29 artifacts deploy-web asserts and commits, beyond the
// force-added ignored `web/` tree and the root hyperdrive manifest.
const DEPLOY_TRACKED_PATHS = Object.freeze([
  'manifest.json',
  'deploy/web-release.json',
  'deploy/web-signing-request.json',
  'deploy/peerit-seed-bootstrap-v1-seq29.json',
  'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
  PEERIT_SEQ29_DECISION_PATH_V1,
  DECISION_SOURCE_PATH
])
const DEPLOY_REQUIRED_FILES = Object.freeze([
  'deploy/web-release.json',
  'deploy/web-signing-request.json',
  'deploy/peerit-seed-bootstrap-v1-seq29.json',
  'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
  PEERIT_SEQ29_DECISION_PATH_V1,
  'web/asset-manifest.json',
  'web/asset-manifest.sig',
  'web/peerit-app-artifact-v1.json',
  'web/peerit-web-assets-v1.cenc'
])

// The materialization input mirrors artifactBytesAtRoot in the decision
// module; the module asserts these bytes still match the root exactly.
const DECISION_ARTIFACT_PATHS = Object.freeze({
  seedBootstrap: 'deploy/peerit-seed-bootstrap-v1-seq29.json',
  publicInboxBootstrap:
    'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
  appArtifact: 'web/peerit-app-artifact-v1.json',
  canonicalWebAssetManifest: 'web/peerit-web-assets-v1.cenc',
  outerAssetManifest: 'web/asset-manifest.json',
  outerSignature: 'web/asset-manifest.sig',
  signingRequest: 'deploy/web-signing-request.json',
  releaseConfig: 'deploy/web-release.json'
})

export const PEERIT_SEQ29_COMPLETION_DECISION_PIN_ARTIFACTS_V1 =
  Object.freeze({
    decision: Object.freeze([PEERIT_SEQ29_DECISION_PATH_V1, 0o444]),
    'source-edit': Object.freeze([DECISION_SOURCE_PATH, 0o644])
  })

export const PEERIT_SEQ29_COMPLETION_DEPLOY_WEB_ARTIFACTS_V1 =
  Object.freeze({
    'deploy-receipt': Object.freeze([
      `${DEPLOY_STATE_DIRECTORY}/${DEPLOY_RECEIPT_NAME}`, 0o444
    ])
  })

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function fsyncDirectory (path) {
  const descriptor = openSync(path, 'r')
  try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
}

function createOnlyFile (path, bytes, mode) {
  const parent = dirname(path)
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`
  let descriptor
  try {
    descriptor = openSync(temporary, 'wx', 0o600)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1) {
      fail('PEERIT_SEQ29_COMPLETION_IO_FAILED',
        'temporary evidence output is not a single-link regular file')
    }
    writeFileSync(descriptor, bytes)
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = undefined
    chmodSync(temporary, mode)
    linkSync(temporary, path)
    fsyncDirectory(parent)
  } catch (cause) {
    if (cause?.code === 'EEXIST') {
      fail('PEERIT_SEQ29_COMPLETION_CONFLICT',
        'create-only phase evidence already exists and is never reused')
    }
    if (String(cause?.code || '').startsWith('PEERIT_')) throw cause
    fail('PEERIT_SEQ29_COMPLETION_IO_FAILED',
      `create-only phase evidence could not be sealed: ${cause?.message || cause}`)
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor) } catch {}
    }
    try { unlinkSync(temporary) } catch {}
  }
}

// The signing seed must be injected by keyvault into the environment before
// the operator resumes; its absence fails closed before any child process,
// file or network access happens.
function requireReleaseSigningSeed () {
  const seed = String(process.env[RELEASE_SIGNING_SEED_ENV] || '')
    .trim().toLowerCase()
  if (!HEX64.test(seed)) {
    fail('PEERIT_SEQ29_COMPLETION_SIGNER_REQUIRED',
      `${RELEASE_SIGNING_SEED_ENV} must be injected as exact 32-byte hexadecimal before this phase can run`)
  }
}

function runNodeScript (root, script, args, code) {
  const result = spawnSync(process.execPath, [join(root, script), ...args], {
    cwd: root,
    env: process.env,
    encoding: 'utf8'
  })
  if (result.error || result.status !== 0) {
    fail(code, `${script} did not complete its completion phase step`)
  }
  return result
}

function git (root, args) {
  const result = spawnSync('git', args, {
    cwd: root,
    env: process.env,
    encoding: 'utf8'
  })
  if (result.error || result.status !== 0) {
    fail('PEERIT_SEQ29_COMPLETION_DEPLOY_GIT_FAILED',
      `git ${String(args[0])} did not succeed during the deploy phase`)
  }
  return String(result.stdout || '').trim()
}

function assertRealRegularFile (root, relativePath) {
  let metadata
  try {
    metadata = lstatSync(join(root, relativePath))
  } catch {
    fail('PEERIT_SEQ29_COMPLETION_DEPLOY_ARTIFACT_MISSING',
      `required sequence-29 release artifact is missing: ${relativePath}`)
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail('PEERIT_SEQ29_COMPLETION_DEPLOY_ARTIFACT_MISSING',
      `required sequence-29 release artifact is not a real file: ${relativePath}`)
  }
}

export async function runPeeritSeq29CompletionReleaseSignPhaseV1 (root) {
  root = resolve(String(root || ''))
  requireReleaseSigningSeed()
  runNodeScript(root, join('scripts', 'sign-release.mjs'), [],
    'PEERIT_SEQ29_COMPLETION_RELEASE_SIGN_FAILED')
}

export async function runPeeritSeq29CompletionHistorySignPhaseV1 (root) {
  root = resolve(String(root || ''))
  requireReleaseSigningSeed()
  runNodeScript(root, join('scripts', 'blind-public-test-sign.mjs'),
    ['sign', 'deploy/web-release-pin-history.json'],
    'PEERIT_SEQ29_COMPLETION_HISTORY_SIGN_FAILED')
  runNodeScript(root, join('scripts', 'blind-public-test-sign.mjs'),
    ['verify', 'deploy/web-release-pin-history.json'],
    'PEERIT_SEQ29_COMPLETION_HISTORY_SIGN_FAILED')
}

export async function runPeeritSeq29CompletionDecisionPinPhaseV1 (root) {
  root = resolve(String(root || ''))
  // Already pinned: re-verify the exact source pin and decision bytes only.
  if (PEERIT_SEQ29_DECISION_SHA256_V1 !== '') {
    verifyPinnedPeeritSeq29OwnerDecisionV1({ root })
    return
  }
  const draftBytes = readFileSync(
    join(root, PEERIT_SEQ29_DECISION_DRAFT_PATH_V1))
  const artifacts = Object.freeze(Object.fromEntries(
    Object.entries(DECISION_ARTIFACT_PATHS).map(([field, relativePath]) =>
      [field, readFileSync(join(root, relativePath))])))
  const materialized = materializePeeritSeq29OwnerDecisionV1({
    root,
    draftBytes,
    expectedDraftSha256: sha256(draftBytes),
    explicitConfirmation: PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1,
    decidedAt: new Date().toISOString(),
    artifacts
  })
  writePeeritSeq29OwnerDecisionCreateOnlyV1({ root, materialized })
  // Mechanical source pin: exactly one line changes, nothing else.
  const sourcePath = join(root, DECISION_SOURCE_PATH)
  const before = readFileSync(sourcePath, 'utf8')
  if (before.split(UNPINNED_SOURCE_LINE).length - 1 !== 1) {
    fail('PEERIT_SEQ29_COMPLETION_DECISION_PIN_SOURCE',
      'the decision source does not contain exactly one unpinned decision line')
  }
  const after = before.replace(UNPINNED_SOURCE_LINE,
    `export const PEERIT_SEQ29_DECISION_SHA256_V1 = '${materialized.decisionSha256}'`)
  writeFileSync(sourcePath, after)
  if (readFileSync(sourcePath, 'utf8') !== after) {
    fail('PEERIT_SEQ29_COMPLETION_DECISION_PIN_SOURCE',
      'the decision source pin changed during writeback')
  }
  // Re-import the pinned module so its frozen constant reflects the edit,
  // then re-run the full pinned verification against the root.
  const pinned = await import(
    `${pathToFileURL(sourcePath).href}?pinned=${materialized.decisionSha256}`)
  pinned.verifyPinnedPeeritSeq29OwnerDecisionV1({ root })
}

export async function runPeeritSeq29CompletionDeployWebPhaseV1 (root) {
  root = resolve(String(root || ''))
  // (a) the exact seq29 release artifacts must be present locally.
  for (const relativePath of DEPLOY_REQUIRED_FILES) {
    assertRealRegularFile(root, relativePath)
  }
  const releaseConfig = JSON.parse(
    readFileSync(join(root, 'deploy', 'web-release.json'), 'utf8'))
  if (releaseConfig.releaseSequence !== 29) {
    fail('PEERIT_SEQ29_COMPLETION_DEPLOY_CONFIG',
      'deploy/web-release.json is not pinned to release sequence 29')
  }
  // (c) commit the exact candidate, prove the Git tree is complete, push.
  git(root, ['add', '-f', '--', 'web'])
  git(root, ['add', '--', ...DEPLOY_TRACKED_PATHS])
  if (git(root, ['status', '--porcelain']) !== '') {
    git(root, ['commit', '-m',
      'release: peerit sequence 29 limited public inbox'])
  }
  const commit = git(root, ['rev-parse', 'HEAD'])
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    fail('PEERIT_SEQ29_COMPLETION_DEPLOY_GIT_FAILED',
      'the deploy commit identity is malformed')
  }
  // (b) the committed tree must contain every signed byte a static host
  // can serve; run only after the candidate commit exists.
  runNodeScript(root, join('scripts', 'check-web-commit.mjs'), ['HEAD'],
    'PEERIT_SEQ29_COMPLETION_DEPLOY_TREE_INCOMPLETE')
  // The completion branch carries the release candidate; local `main` may be
  // stale, so push the exact verified HEAD to the deploy branch explicitly.
  git(root, ['push', 'origin', 'HEAD:main'])
  const pushedAt = new Date().toISOString()
  // (d) poll the deployed origin until it serves the exact signed bytes.
  const deadline = Date.now() + DEPLOY_VERIFY_TIMEOUT_MILLIS
  let verifyAttempts = 0
  for (;;) {
    verifyAttempts++
    const verification = spawnSync(process.execPath,
      [join(root, 'scripts', 'verify-deployed-web.mjs'),
        '--url', DEPLOY_VERIFY_URL],
      { cwd: root, env: process.env, encoding: 'utf8' })
    if (!verification.error && verification.status === 0) break
    if (Date.now() >= deadline) {
      fail('PEERIT_SEQ29_COMPLETION_DEPLOY_VERIFY_TIMEOUT',
        'the deployed origin did not converge to the exact signed bytes in time')
    }
    await new Promise(resolve => setTimeout(resolve,
      DEPLOY_VERIFY_INTERVAL_MILLIS))
  }
  const verifiedAt = new Date().toISOString()
  // (e) seal the create-only deploy receipt for driver authentication.
  const stateDirectory = join(root, DEPLOY_STATE_DIRECTORY)
  if (!existsSync(stateDirectory)) {
    mkdirSync(stateDirectory, { mode: 0o700 })
    fsyncDirectory(dirname(stateDirectory))
  }
  createOnlyFile(join(stateDirectory, DEPLOY_RECEIPT_NAME),
    Buffer.from(JSON.stringify({
      schema: 'peerit-seq29-deploy-web-receipt-v1',
      version: 1,
      releaseSequence: 29,
      commit,
      pushedAt,
      verifiedAt,
      verifyAttempts,
      verifyUrl: DEPLOY_VERIFY_URL,
      outcome: 'ORIGIN_SERVES_EXACT_SIGNED_BYTES'
    }, null, 2) + '\n'), 0o444)
}
