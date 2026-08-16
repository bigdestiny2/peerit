// Sequence-29 completion driver: the live `create` phase handler. This module
// is the only completion component that may touch the live ceremony stack; the
// driver file itself stays free of any ceremony, decision or secret-bearing
// reference. All authority enters through the process environment (keyvault
// injected) or fresh CSPRNG bytes — never through caller-supplied values.
//
// Resume safety: the fixed attempt journal makes a second INBOX.CREATE resend
// impossible. A fully durable ceremony (final public receipt, signed public
// bootstrap bundle, plan and qualification snapshots all present) short-
// circuits to the idempotent release-config refresh. Any partial durable
// state fails closed with a coded recovery-required error instead of
// re-entering the live flow.

import {
  createPrivateKey,
  createPublicKey,
  randomBytes
} from 'node:crypto'
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
  readdirSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import {
  reissuePeeritSeedBootstrapSequence29V1,
  writePeeritSeedBootstrapReissueOutputV1
} from '../reissue-peerit-seed-bootstrap.mjs'
import {
  preparePeeritSeq29LiveInboxCreateCustodyFirstV1,
  qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1,
  createPeeritSeq29CustodyFirstLiveInboxCreateCompositionV1,
  snapshotPeeritSeq29LiveInboxCreateQualificationV1
} from '../seq29-live-inbox-create-qualification.mjs'
import {
  resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1
} from './seq29-live-inbox-create-pre-network-custody.mjs'
import {
  runPeeritSeq29LiveInboxCeremonyConductorV1,
  finalizePeeritSeq29LiveInboxCeremonyConductorV1
} from '../seq29-live-inbox-ceremony-conductor.mjs'
import {
  PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1,
  signPeeritLimitedPublicInboxBootstrapV1
} from '../sign-limited-public-inbox-bootstrap.mjs'

const STATE_DIRECTORY = '.deploy/seq29-create-v1'
const SEED_SOURCE_PATH = 'deploy/peerit-seed-bootstrap-v1-seq28.json'
const SEED_BUNDLE_PATH = 'deploy/peerit-seed-bootstrap-v1-seq29.json'
const INBOX_BUNDLE_PATH =
  'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json'
const PROFILE_PATH = 'peerit-limited-cell-put-profile-v1.json'
const RELEASE_CONFIG_PATH = 'deploy/web-release.json'
const CUSTODIAN_KEY_DIRECTORY = '/Users/localllm/.peerit-seq29-custodian-keys-v1'
const CEREMONY_RECEIPT_NAME =
  'peerit-seq29-limited-public-inbox-ceremony-receipt-v1.json'
const SECRETS_NAME = 'ceremony-secrets.json'
const PKCS8_ED25519_PREFIX = '302e020100300506032b657004220420'
const THIRTY_ONE_DAYS_MILLIS = 31 * 24 * 60 * 60 * 1000
const HEX64 = /^[0-9a-f]{64}$/

// The fixed digested evidence set the driver authenticates after this handler
// completes. Declared here so the driver file never names ceremony modules.
export const PEERIT_SEQ29_COMPLETION_CREATE_ARTIFACTS_V1 = Object.freeze({
  'create-journal': Object.freeze([
    `${STATE_DIRECTORY}/public-output/${CEREMONY_RECEIPT_NAME}`, 0o444
  ]),
  plan: Object.freeze([`${STATE_DIRECTORY}/plan.json`, 0o444]),
  'public-inbox-bootstrap': Object.freeze([INBOX_BUNDLE_PATH, 0o444]),
  qualification: Object.freeze([`${STATE_DIRECTORY}/qualification.json`, 0o444])
})

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function fsyncDirectory (path) {
  const descriptor = openSync(path, 'r')
  try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
}

// Create-only publication, mirroring the custody materializer: a fresh 0600
// temporary is fsynced, chmodded to its final mode and hard-linked into place,
// so an existing artifact can never be replaced.
function createOnlyFile (path, bytes, mode) {
  const parent = dirname(path)
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`
  let descriptor
  try {
    descriptor = openSync(temporary, 'wx', 0o600)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1) {
      fail('PEERIT_SEQ29_COMPLETION_CREATE_IO_FAILED',
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
      fail('PEERIT_SEQ29_COMPLETION_CREATE_CONFLICT',
        'create-only ceremony evidence already exists and is never reused')
    }
    if (String(cause?.code || '').startsWith('PEERIT_')) throw cause
    fail('PEERIT_SEQ29_COMPLETION_CREATE_IO_FAILED',
      `create-only ceremony evidence could not be sealed: ${cause?.message || cause}`)
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor) } catch {}
    }
    try { unlinkSync(temporary) } catch {}
  }
}

function ensurePrivateStateDirectory (root, path) {
  if (!existsSync(path)) {
    mkdirSync(path, { mode: 0o700 })
    fsyncDirectory(dirname(path))
  }
  const metadata = lstatSync(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      (metadata.mode & 0o777) !== 0o700) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_PERMISSIONS',
      'create-phase state directory must be a real owner-only directory')
  }
  if (typeof process.getuid === 'function' &&
      metadata.uid !== process.getuid()) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_PERMISSIONS',
      'create-phase state directory is not owned by the current operator')
  }
}

function deriveEd25519PublicKey (seedBytes) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from(PKCS8_ED25519_PREFIX, 'hex'), seedBytes
    ]),
    format: 'der',
    type: 'pkcs8'
  })
  return createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
    .subarray(-32).toString('hex')
}

// deploy/web-release.json stays canonical pretty JSON with one trailing
// newline, exactly as scripts/web-release.mjs reads it. The update is
// idempotent so the post-ceremony short-circuit can safely repeat it.
function refreshReleaseConfig (root, authorityPublicKey) {
  const path = join(root, RELEASE_CONFIG_PATH)
  const before = readFileSync(path)
  let config
  try { config = JSON.parse(before.toString('utf8')) } catch {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_CONFIG_INVALID',
      'deploy/web-release.json is not JSON')
  }
  if (Buffer.from(JSON.stringify(config, null, 2) + '\n').compare(before) !== 0) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_CONFIG_INVALID',
      'deploy/web-release.json bytes are not canonical pretty JSON')
  }
  if (config.releaseSequence !== 28 && config.releaseSequence !== 29) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_CONFIG_INVALID',
      'deploy/web-release.json must be at sequence 28 or 29 before the create phase')
  }
  if (!HEX64.test(authorityPublicKey)) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_CONFIG_INVALID',
      'the public inbox authority public key is malformed')
  }
  config.releaseSequence = 29
  config.peeritSeedBootstrapBundle = SEED_BUNDLE_PATH
  config.peeritLimitedPublicInboxBootstrapBundle = INBOX_BUNDLE_PATH
  config.peeritLimitedPublicInboxBootstrapAuthorityPublicKey =
    authorityPublicKey
  const after = Buffer.from(JSON.stringify(config, null, 2) + '\n')
  if (!after.equals(before)) writeFileSync(path, after)
}

function bundleAuthorityPublicKey (root) {
  let envelope
  try {
    envelope = JSON.parse(readFileSync(join(root, INBOX_BUNDLE_PATH), 'utf8'))
  } catch {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_EVIDENCE_INVALID',
      'the signed public inbox bootstrap bundle is missing or unreadable')
  }
  const key = String(envelope?.payload?.authorityPublicKey || '')
  if (!HEX64.test(key)) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_EVIDENCE_INVALID',
      'the signed public inbox bootstrap bundle has no exact authority key')
  }
  return key
}

export async function runPeeritSeq29CompletionCreatePhaseV1 (root) {
  root = resolve(String(root || ''))
  const stateDirectory = join(root, STATE_DIRECTORY)
  const preNetworkCustodyDirectory =
    join(stateDirectory, 'pre-network-custody')
  const journalDirectory = join(stateDirectory, 'journal')
  const custodyDirectory = join(stateDirectory, 'custody')
  const publicOutputDirectory = join(stateDirectory, 'public-output')
  const secretsPath = join(stateDirectory, SECRETS_NAME)
  const planPath = join(stateDirectory, 'plan.json')
  const qualificationPath = join(stateDirectory, 'qualification.json')
  const ceremonyReceiptPath =
    join(publicOutputDirectory, CEREMONY_RECEIPT_NAME)
  const inboxBundlePath = join(root, INBOX_BUNDLE_PATH)

  // Fully durable ceremony: never re-enter the live flow. Only the
  // idempotent release-config refresh remains.
  if (existsSync(ceremonyReceiptPath) && existsSync(inboxBundlePath) &&
      existsSync(planPath) && existsSync(qualificationPath)) {
    refreshReleaseConfig(root, bundleAuthorityPublicKey(root))
    return
  }
  // Partial durable state: fail closed. The sealed attempt journal forbids
  // any automatic resend; recovery is an explicit operator flow.
  if (existsSync(secretsPath) ||
      existsSync(preNetworkCustodyDirectory) ||
      (existsSync(journalDirectory) &&
        readdirSync(journalDirectory).length > 0)) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_RECOVERY_REQUIRED',
      'partial sequence-29 live ceremony state exists; the sealed journal forbids automatic resume')
  }

  ensurePrivateStateDirectory(root, stateDirectory)

  // Step 0: release-terminal seed bootstrap reissue (offline, zero network),
  // only when the sequence-29 bundle has never been materialized.
  const seedBundlePath = join(root, SEED_BUNDLE_PATH)
  if (!existsSync(seedBundlePath)) {
    const now = Date.now()
    const reissued = await reissuePeeritSeedBootstrapSequence29V1({
      sourceBytes: readFileSync(join(root, SEED_SOURCE_PATH)),
      issuedAt: now,
      expiresAt: now + THIRTY_ONE_DAYS_MILLIS
    })
    writePeeritSeedBootstrapReissueOutputV1(seedBundlePath, reissued.bytes)
  }

  // Step 1: offline custody-first preparation (production: no fixture).
  const custodyFirst = await preparePeeritSeq29LiveInboxCreateCustodyFirstV1({
    seedBootstrapBytes: readFileSync(seedBundlePath),
    limitedCellPutProfileBytes: readFileSync(join(root, PROFILE_PATH)),
    preNetworkCustodyDirectory,
    custodianKeyDirectory: CUSTODIAN_KEY_DIRECTORY
  })

  // Step 2: reopen and self-verify the durable pre-network custody.
  const preNetworkCustody =
    await resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1({
      releaseSnapshot: custodyFirst.snapshot.releaseSnapshot,
      directory: preNetworkCustodyDirectory,
      custodianKeyDirectory: CUSTODIAN_KEY_DIRECTORY
    })

  // Step 3: live read-only qualification of dal-1 and syd-1.
  const qualification =
    await qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1({
      preparation: custodyFirst.releasePreparation,
      preNetworkCustody,
      monotonicMillis: () => performance.now()
    })

  // Step 4: fresh CSPRNG ceremony keys, persisted 0600 for an explicit
  // recovery flow. Never logged, never part of any receipt.
  const authoritySeed = randomBytes(32)
  const authorityPublicKey = deriveEd25519PublicKey(authoritySeed)
  const stripeSelectionKey = randomBytes(32).toString('hex')
  const announcementMasterKey = randomBytes(32).toString('hex')
  const issuedUnixMillis = String(Date.now())
  const expiresUnixMillis = String(Date.now() + THIRTY_ONE_DAYS_MILLIS)
  createOnlyFile(secretsPath, Buffer.from(JSON.stringify({
    schema: 'peerit-seq29-completion-create-ceremony-secrets-v1',
    version: 1,
    authoritySeedHex: authoritySeed.toString('hex'),
    authorityPublicKey,
    stripeSelectionKey,
    announcementMasterKey,
    issuedUnixMillis,
    expiresUnixMillis
  }, null, 2) + '\n'), 0o600)

  // Step 5: the exact custody-first composition. Execution is never
  // automatic; it requires the explicit in-process boundary below.
  const composition =
    await createPeeritSeq29CustodyFirstLiveInboxCreateCompositionV1({
      qualification,
      preNetworkCustody,
      issuedUnixMillis,
      expiresUnixMillis,
      authorityPublicKey,
      stripeSelectionKey,
      announcementMasterKey,
      bootstrapSequence: 0,
      previousBootstrapHash: null,
      journalDirectory,
      custodyDirectory,
      publicOutputDirectory,
      custodianKeyDirectory: CUSTODIAN_KEY_DIRECTORY
    })
  if (composition.automaticExecution !== false) {
    fail('PEERIT_SEQ29_COMPLETION_CREATE_COMPOSITION_INVALID',
      'the live composition must require the explicit execution boundary')
  }

  // Step 6: THE live step — exactly two INBOX.CREATE admissions on dal/syd —
  // then the offline authority signature and the durable finalization.
  const executed = await runPeeritSeq29LiveInboxCeremonyConductorV1({
    conductor: composition.conductor,
    executeBoundary: '--execute',
    commitToken: composition.commitToken
  })
  const signed = signPeeritLimitedPublicInboxBootstrapV1({
    signingPackage: executed.result.signingPackage,
    environment: {
      [PEERIT_LIMITED_PUBLIC_INBOX_SIGNING_SEED_ENV_V1]:
        authoritySeed.toString('hex')
    }
  })
  authoritySeed.fill(0)
  createOnlyFile(inboxBundlePath, signed.canonicalBytes, 0o444)
  await finalizePeeritSeq29LiveInboxCeremonyConductorV1({
    conductor: composition.conductor,
    executeBoundary: '--execute',
    commitToken: composition.commitToken,
    signedBootstrap: signed.wrapper
  })

  // Step 7: create-only digested evidence for the driver's fixed artifact
  // authentication (the ceremony receipt and bundle are already durable).
  createOnlyFile(planPath,
    Buffer.from(JSON.stringify(composition.plan, null, 2) + '\n'), 0o444)
  createOnlyFile(qualificationPath, Buffer.from(JSON.stringify(
    snapshotPeeritSeq29LiveInboxCreateQualificationV1(qualification),
    null, 2) + '\n'), 0o444)

  // Step 8: pin the release config to sequence 29 and both bundles.
  refreshReleaseConfig(root, authorityPublicKey)
}
