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
  readdirSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, parse, relative, resolve, sep } from 'node:path'
import { canonicalPeeritLimitedPublicInboxJsonV1 } from '../../js/substrate/inbox-topic-v1.mjs'
import { validatePeeritLimitedPublicInboxSigningPackageV1 } from '../sign-limited-public-inbox-bootstrap.mjs'

function fail (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details !== undefined) error.details = details
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function exactArray (value, length, field) {
  if (!Array.isArray(value) || value.length !== length ||
      Object.keys(value).join('\0') !== Array.from({ length }, (_, index) => String(index)).join('\0')) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      `${field} must be a dense exact ${length}-element array`)
  }
  return value
}

function hex64 (value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function opaqueId (value, field) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256 ||
      !/^[A-Za-z0-9._:-]+$/.test(value)) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      `${field} must be a bounded opaque identifier`)
  }
  return value
}

function snapshotDataOnlyJson (value, field = 'value', active = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID', `${field} number is not a safe integer`)
    }
    return value
  }
  if (typeof value !== 'object' || active.has(value)) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      `${field} is cyclic or is not plain JSON data`)
  }
  active.add(value)
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      `${field} must not contain symbol properties`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  let snapshot
  if (Array.isArray(value)) {
    exactArray(value, value.length, field)
    const admitted = new Set([
      ...Array.from({ length: value.length }, (_, index) => String(index)),
      'length'
    ])
    if (Object.keys(descriptors).some(key => !admitted.has(key))) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
        `${field} has non-index array properties`)
    }
    snapshot = []
    for (let index = 0; index < value.length; index++) {
      const descriptor = descriptors[index]
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
          descriptor.enumerable !== true) {
        fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
          `${field}[${index}] must be an enumerable data property`)
      }
      snapshot.push(snapshotDataOnlyJson(descriptor.value, `${field}[${index}]`, active))
    }
  } else {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID', `${field} is not a plain object`)
    }
    snapshot = Object.create(null)
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
          descriptor.enumerable !== true) {
        fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
          `${field}.${key} must be an enumerable data property`)
      }
      snapshot[key] = snapshotDataOnlyJson(descriptor.value, `${field}.${key}`, active)
    }
  }
  active.delete(value)
  return snapshot
}

function noPrivateMaterial (value, trail = []) {
  if (typeof value === 'string' &&
      /(?:PRIVATE|SECRET|CAPABILITY|WRITE_CAP)[_-]?(?:SEED|KEY|MATERIAL)?/i.test(value)) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_SECRET',
      `public materialization contains a secret sentinel at ${trail.join('.') || '<root>'}`)
  }
  if (value == null || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    const lower = key.toLowerCase()
    if (lower.includes('privateseed') || lower.includes('privatekey') ||
        lower.includes('secretseed') || lower.includes('appendseed') ||
        lower.includes('renewseed') || lower.includes('closeseed') ||
        lower.includes('createseed') || lower.includes('capabilityseed')) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_SECRET',
        `public materialization contains private material at ${[...trail, key].join('.')}`)
    }
    noPrivateMaterial(child, [...trail, key])
  }
}

function validateMutationLedger (value, expectedInboxCreate, field) {
  exact(value, [
    'inboxCreate', 'inboxRenew', 'inboxClose', 'inboxAppend', 'cellPut', 'other'
  ], field)
  for (const [key, amount] of Object.entries(value)) {
    if (!Number.isSafeInteger(amount) || amount < 0 ||
        amount !== (key === 'inboxCreate' ? expectedInboxCreate : 0)) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
        `${field}.${key} differs from the exact create-only ledger`)
    }
  }
  return {
    inboxCreate: expectedInboxCreate,
    inboxRenew: 0,
    inboxClose: 0,
    inboxAppend: 0,
    cellPut: 0,
    other: 0
  }
}

function validateRecoveredLedger (value) {
  exact(value, ['inboxCreate'], 'recoveredOriginalMutationLedger')
  if (value.inboxCreate !== 2) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      'recoveredOriginalMutationLedger must bind exactly two original CREATEs')
  }
  return { inboxCreate: 2 }
}

function validateIntermediateResult (value) {
  value = snapshotDataOnlyJson(value, 'intermediate result')
  noPrivateMaterial(value)
  const recovered = Object.prototype.hasOwnProperty.call(value,
    'recoveredOriginalMutationLedger')
  exact(value, [
    'schema', 'status', 'planHash', 'attemptId', 'signingPackage',
    'custodyCommitment', 'journalCommitment', 'mutationLedger',
    ...(recovered ? ['recoveredOriginalMutationLedger'] : [])
  ], 'intermediate result')
  if (value.schema !== 'peerit-limited-inbox-topic-ceremony-result-v1' ||
      value.status !== 'COMMITTED_AWAITING_SIGNED_BOOTSTRAP') {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      'intermediate result has the wrong ceremony identity')
  }
  hex64(value.planHash, 'planHash')
  opaqueId(value.attemptId, 'attemptId')
  opaqueId(value.custodyCommitment, 'custodyCommitment')
  hex64(value.journalCommitment, 'journalCommitment')
  const mutationLedger = validateMutationLedger(value.mutationLedger, recovered ? 0 : 2,
    'mutationLedger')
  const recoveredOriginalMutationLedger = recovered
    ? validateRecoveredLedger(value.recoveredOriginalMutationLedger)
    : null
  const checked = validatePeeritLimitedPublicInboxSigningPackageV1(value.signingPackage)
  const signingPackage = {
    schema: checked.schema,
    version: checked.version,
    offlineOnly: checked.offlineOnly,
    hiverelayCommit: checked.hiverelayCommit,
    createRequests: checked.createRequests,
    payload: checked.payload
  }
  return Object.freeze({
    schema: value.schema,
    status: value.status,
    planHash: value.planHash,
    attemptId: value.attemptId,
    signingPackage,
    custodyCommitment: value.custodyCommitment,
    journalCommitment: value.journalCommitment,
    mutationLedger,
    recoveredOriginalMutationLedger
  })
}

function validateFinalResult (value) {
  value = snapshotDataOnlyJson(value, 'final result')
  noPrivateMaterial(value)
  exact(value, [
    'schema', 'status', 'planHash', 'attemptId', 'signedBootstrapHash',
    'managementBundleDigest', 'custodyCommitment', 'journalCommitment',
    'mutationLedger', 'recoveredOriginalMutationLedger'
  ], 'final result')
  if (value.schema !== 'peerit-limited-inbox-topic-ceremony-result-v1' ||
      value.status !== 'COMMITTED_CREATE_ONLY') {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      'final result has the wrong ceremony identity')
  }
  hex64(value.planHash, 'planHash')
  opaqueId(value.attemptId, 'attemptId')
  hex64(value.signedBootstrapHash, 'signedBootstrapHash')
  hex64(value.managementBundleDigest, 'managementBundleDigest')
  opaqueId(value.custodyCommitment, 'custodyCommitment')
  hex64(value.journalCommitment, 'journalCommitment')
  return Object.freeze({
    schema: value.schema,
    status: value.status,
    planHash: value.planHash,
    attemptId: value.attemptId,
    signedBootstrapHash: value.signedBootstrapHash,
    managementBundleDigest: value.managementBundleDigest,
    custodyCommitment: value.custodyCommitment,
    journalCommitment: value.journalCommitment,
    mutationLedger: validateMutationLedger(value.mutationLedger, 0, 'mutationLedger'),
    recoveredOriginalMutationLedger: validateRecoveredLedger(
      value.recoveredOriginalMutationLedger)
  })
}

function canonicalPrettyBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8')
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function fsyncDirectory (path) {
  const descriptor = openSync(path, 'r')
  try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
}

function currentIdentity () {
  return {
    uid: typeof process.getuid === 'function' ? process.getuid() : null
  }
}

function assertOwned (metadata, field) {
  const identity = currentIdentity()
  if (identity.uid != null && metadata.uid !== identity.uid) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_PERMISSIONS',
      `${field} is not owned by the current operator identity`)
  }
}

function assertNoSymlinkParents (path) {
  const absolute = resolve(path)
  const root = parse(absolute).root
  const suffix = relative(root, absolute)
  let cursor = root
  for (const component of suffix === '' ? [] : suffix.split(sep)) {
    cursor = join(cursor, component)
    if (!existsSync(cursor)) break
    const metadata = lstatSync(cursor)
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_PERMISSIONS',
        `${cursor} is not a real directory`)
    }
  }
}

function ensurePrivateOutputRoot (value) {
  if (typeof value !== 'string' || value.length < 1 || value.includes('\0')) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_INVALID',
      'output directory must be a nonempty filesystem path')
  }
  const outputDirectory = resolve(value)
  const parent = dirname(outputDirectory)
  assertNoSymlinkParents(parent)
  if (!existsSync(outputDirectory)) {
    try { mkdirSync(outputDirectory, { mode: 0o700 }) } catch (cause) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_IO_FAILED',
        'could not create private output root', { cause: cause?.message || String(cause) })
    }
    fsyncDirectory(parent)
  }
  const metadata = lstatSync(outputDirectory)
  if (metadata.isSymbolicLink() || !metadata.isDirectory() ||
      (metadata.mode & 0o777) !== 0o700) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_PERMISSIONS',
      'output root must be a real directory with exact mode 0700')
  }
  assertOwned(metadata, 'output root')
  return outputDirectory
}

function escapeRegex (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function rejectOwnedTempResidue (target) {
  const parent = dirname(target)
  const name = basename(target)
  const pattern = new RegExp(
    `^\\.${escapeRegex(name)}\\.[1-9][0-9]*\\.[0-9a-f]{24}\\.tmp$`
  )
  const residues = readdirSync(parent).filter(entry => pattern.test(entry))
  if (residues.length > 0) {
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_TEMP_RESIDUE',
      `${name} has owned temporary residue: ${residues.join(', ')}`)
  }
}

function createOnlyExact (target, value) {
  const snapshot = snapshotDataOnlyJson(value, `output ${basename(target)}`)
  noPrivateMaterial(snapshot)
  const bytes = canonicalPrettyBytes(snapshot)
  const parent = dirname(target)
  rejectOwnedTempResidue(target)
  const temporary = join(parent,
    `.${basename(target)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  let descriptor
  try {
    descriptor = openSync(temporary, 'wx', 0o600)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_IO_FAILED',
        'temporary output is not a single-link regular file')
    }
    writeFileSync(descriptor, bytes)
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = undefined
    chmodSync(temporary, 0o444)
    linkSync(temporary, target)
    unlinkSync(temporary)
    const materialized = lstatSync(target)
    if (!materialized.isFile() || materialized.isSymbolicLink() ||
        materialized.nlink !== 1 || (materialized.mode & 0o777) !== 0o444) {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_PERMISSIONS',
        `${basename(target)} is not a single-link read-only regular file`)
    }
    assertOwned(materialized, basename(target))
    fsyncDirectory(parent)
    return Object.freeze({ created: true, sha256: sha256(bytes) })
  } catch (cause) {
    if (cause?.code === 'EEXIST') {
      fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_CONFLICT',
        `${basename(target)} already exists; create-only output is never reused`)
    }
    if (cause?.code?.startsWith('PEERIT_')) throw cause
    fail('PEERIT_SEQ29_LIVE_MATERIALIZATION_IO_FAILED',
      `could not create ${basename(target)}`, { cause: cause?.message || String(cause) })
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor) } catch {}
    }
    try { unlinkSync(temporary) } catch {}
    try { fsyncDirectory(parent) } catch {}
  }
}

export function materializePeeritSeq29LiveCeremonyPublicOutputsV1 (input = {}) {
  exact(input, ['directory', 'result'], 'materialization input')
  const result = validateIntermediateResult(input.result)
  const signingPackage = result.signingPackage
  const signingPackageBytes = canonicalPrettyBytes(signingPackage)
  const signingPackageSha256 = sha256(canonicalPeeritLimitedPublicInboxJsonV1(signingPackage))
  const outputDirectory = ensurePrivateOutputRoot(input.directory)
  const signingPackagePath = join(outputDirectory,
    'peerit-seq29-limited-public-inbox-signing-package-v1.json')
  const receiptPath = join(outputDirectory,
    'peerit-seq29-limited-public-inbox-custody-public-binding-receipt-v1.json')
  const receipt = {
    schema: 'peerit-seq29-limited-public-inbox-custody-public-binding-receipt-v1',
    version: 1,
    status: result.status,
    releaseSequence: 29,
    planHash: result.planHash,
    attemptId: result.attemptId,
    signingPackageSha256,
    signingPackageFileSha256: sha256(signingPackageBytes),
    custodyCommitment: result.custodyCommitment,
    journalCommitment: result.journalCommitment,
    mutationLedger: result.mutationLedger,
    ...(result.recoveredOriginalMutationLedger === null
      ? {}
      : { recoveredOriginalMutationLedger: result.recoveredOriginalMutationLedger })
  }
  noPrivateMaterial(receipt)
  const signingPackageWrite = createOnlyExact(signingPackagePath, signingPackage)
  const receiptWrite = createOnlyExact(receiptPath, receipt)
  return Object.freeze({
    status: 'PUBLIC_OUTPUTS_MATERIALIZED_CREATE_ONLY',
    signingPackagePath,
    signingPackageSha256,
    signingPackageCreated: signingPackageWrite.created,
    receiptPath,
    receiptSha256: receiptWrite.sha256,
    receiptCreated: receiptWrite.created
  })
}

export function materializePeeritSeq29LiveCeremonyFinalReceiptV1 (input = {}) {
  exact(input, ['directory', 'result'], 'final receipt materialization input')
  const result = validateFinalResult(input.result)
  const outputDirectory = ensurePrivateOutputRoot(input.directory)
  const receiptPath = join(outputDirectory,
    'peerit-seq29-limited-public-inbox-ceremony-receipt-v1.json')
  const receipt = {
    schema: 'peerit-seq29-limited-public-inbox-ceremony-receipt-v1',
    version: 1,
    status: result.status,
    releaseSequence: 29,
    planHash: result.planHash,
    attemptId: result.attemptId,
    signedBootstrapHash: result.signedBootstrapHash,
    managementBundleDigest: result.managementBundleDigest,
    custodyCommitment: result.custodyCommitment,
    journalCommitment: result.journalCommitment,
    mutationLedger: result.mutationLedger,
    recoveredOriginalMutationLedger: result.recoveredOriginalMutationLedger
  }
  const receiptWrite = createOnlyExact(receiptPath, receipt)
  return Object.freeze({
    status: 'FINAL_RECEIPT_MATERIALIZED_CREATE_ONLY',
    receiptPath,
    receiptSha256: receiptWrite.sha256,
    receiptCreated: receiptWrite.created
  })
}
