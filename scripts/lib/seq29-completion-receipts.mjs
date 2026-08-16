import { createHash } from 'node:crypto'
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'

export const PEERIT_SEQ29_COMPLETION_PHASES_V1 = Object.freeze([
  'create',
  'web-prepare',
  'release-sign',
  'decision-pin',
  'web-reprepare',
  'deploy-web',
  'history-append',
  'history-sign',
  'verify'
])

const EVENT_SCHEMA = 'peerit-seq29-completion-receipt-v1'
const STATUS_SCHEMA = 'peerit-seq29-completion-status-v1'
const HEX64 = /^[0-9a-f]{64}$/
const MAX_RECEIPT_BYTES = 256 * 1024
const STORES = new WeakMap()
const RECEIPT_IDENTITIES = new Map()
const DIRECTORY_IDENTITIES = new Map()
const UNCERTAIN_RECEIPTS = new Set()
const PHASE_ARTIFACTS = Object.freeze({
  create: Object.freeze([
    'create-journal', 'plan', 'public-inbox-bootstrap', 'qualification'
  ]),
  'web-prepare': Object.freeze([
    'outer-manifest', 'prepare-journal', 'signing-request'
  ]),
  'release-sign': Object.freeze(['outer-signature']),
  'decision-pin': Object.freeze(['decision', 'source-edit']),
  'web-reprepare': Object.freeze([
    'app-artifact', 'canonical-manifest', 'outer-manifest',
    'outer-signature', 'signing-request'
  ]),
  // Live user-content publication was removed from completion: the deploy-web
  // phase is a static site deploy only — no content intent, AuthorBind,
  // CELL.PUT or INBOX.APPEND. The four content writes stay available only to
  // a later genuine trusted same-origin UI action.
  'deploy-web': Object.freeze(['deploy-receipt']),
  'history-append': Object.freeze(['pin-history']),
  'history-sign': Object.freeze(['pin-history-signature']),
  verify: Object.freeze(['verification-report'])
})

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function canonical (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
}

function digest (value) {
  return createHash('sha256').update(canonical(value)).digest('hex')
}

function bytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

function fullMode (metadata) {
  return metadata.mode & 0o7777
}

function assertOwned (metadata, field) {
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      `${field} is not owned by the current operator`)
  }
}

function sameDirectoryIdentity (left, right) {
  return left.isDirectory() && right.isDirectory() &&
    !left.isSymbolicLink() && !right.isSymbolicLink() &&
    left.dev === right.dev && left.ino === right.ino &&
    left.uid === right.uid && left.gid === right.gid &&
    fullMode(left) === fullMode(right)
}

function directoryIdentity (metadata) {
  return Object.freeze({
    dev: metadata.dev,
    ino: metadata.ino,
    uid: metadata.uid,
    gid: metadata.gid,
    mode: fullMode(metadata)
  })
}

function matchesDirectoryIdentity (identity, metadata) {
  return identity.dev === metadata.dev && identity.ino === metadata.ino &&
    identity.uid === metadata.uid && identity.gid === metadata.gid &&
    identity.mode === fullMode(metadata)
}

function authenticateDirectory (path, { synchronize = false } = {}) {
  let named
  try {
    named = lstatSync(path)
  } catch {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED',
      'completion receipt directory could not be inspected')
  }
  if (!named.isDirectory() || named.isSymbolicLink()) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      'completion receipt directory is not a real directory')
  }
  assertOwned(named, 'completion receipt directory')
  const identityKey = resolve(path)
  const known = DIRECTORY_IDENTITIES.get(identityKey)
  if (known && !matchesDirectoryIdentity(known, named)) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      'completion receipt directory changed authenticated identity')
  }
  let descriptor
  let primary
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_DIRECTORY || 0) |
      (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor)
    if (!sameDirectoryIdentity(named, opened)) {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
        'completion receipt directory changed identity before authenticated open')
    }
    assertOwned(opened, 'opened completion receipt directory')
    if (synchronize) fsyncSync(descriptor)
    const after = fstatSync(descriptor)
    const namedAfter = lstatSync(path)
    if (!sameDirectoryIdentity(opened, after) ||
        !sameDirectoryIdentity(opened, namedAfter)) {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
        'completion receipt directory changed during authenticated access')
    }
    DIRECTORY_IDENTITIES.set(identityKey, directoryIdentity(namedAfter))
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try {
      closeSync(descriptor)
    } catch {
      if (!primary) primary = new Error('directory close uncertainty')
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_SEQ29_')) throw primary
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED',
      'completion receipt directory could not be durably accessed')
  }
  return named
}

function fsyncDirectory (path) {
  return authenticateDirectory(path, { synchronize: true })
}

function entryExists (path) {
  try {
    lstatSync(path)
    return true
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED',
      'completion evidence path could not be inspected')
  }
}

function authenticateRepositoryRoot (root) {
  const metadata = authenticateDirectory(root)
  if ((fullMode(metadata) & 0o7022) !== 0) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      'repository root is not an authenticated owner-only-write directory')
  }
  return metadata
}

function assertTrustedParents (root, target) {
  const suffix = relative(resolve(root), dirname(resolve(target)))
  if (suffix === '..' || suffix.startsWith(`..${sep}`)) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      'completion evidence path escapes the repository root')
  }
  let cursor = resolve(root)
  for (const part of suffix === '' ? [] : suffix.split(sep)) {
    const metadata = lstatSync(cursor)
    if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
        (fullMode(metadata) & 0o022) !== 0) {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
        'completion evidence parent is not a trusted directory')
    }
    assertOwned(metadata, 'completion evidence parent')
    cursor = join(cursor, part)
    if (!existsSync(cursor)) return
  }
  if (existsSync(cursor)) {
    const metadata = lstatSync(cursor)
    if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
        (fullMode(metadata) & 0o022) !== 0) {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
        'completion evidence parent is not a trusted directory')
    }
    assertOwned(metadata, 'completion evidence parent')
  }
}

function ensureDirectory (root, path, mode) {
  assertTrustedParents(root, join(path, 'child'))
  if (!existsSync(path)) {
    mkdirSync(path, { mode })
    fsyncDirectory(dirname(path))
  }
  const metadata = authenticateDirectory(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      fullMode(metadata) !== mode) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      'completion receipt directory must retain exact private mode')
  }
  assertOwned(metadata, 'completion receipt directory')
}

function ensureOuterDeployDirectory (root, path) {
  assertTrustedParents(root, join(path, 'child'))
  if (!existsSync(path)) {
    mkdirSync(path, { mode: 0o700 })
    fsyncDirectory(dirname(path))
  }
  const metadata = authenticateDirectory(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      (fullMode(metadata) & 0o7022) !== 0) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      'outer deployment directory is not an authenticated owner-only-write directory')
  }
  assertOwned(metadata, 'outer deployment directory')
}

function validateArtifacts (artifacts, phase) {
  const expected = PHASE_ARTIFACTS[phase]
  if (!artifacts || typeof artifacts !== 'object' || Array.isArray(artifacts) ||
      !expected || Object.keys(artifacts).sort().join('\0') !==
        [...expected].sort().join('\0') ||
      Object.values(artifacts).some(value => !HEX64.test(value))) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_INVALID',
      'receipt artifact evidence differs from the exact nonempty phase set')
  }
  return Object.freeze({ ...artifacts })
}

function readReceipt (path) {
  if (UNCERTAIN_RECEIPTS.has(resolve(path))) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
      `${basename(path)} has uncertain close status`)
  }
  const named = lstatSync(path)
  const identityKey = resolve(path)
  const known = RECEIPT_IDENTITIES.get(identityKey)
  if (known && (known.dev !== named.dev || known.ino !== named.ino)) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
      `${basename(path)} changed sealed inode identity`)
  }
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1 ||
      fullMode(named) !== 0o600 || named.size > MAX_RECEIPT_BYTES) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
      `${basename(path)} is not a private sealed receipt`)
  }
  assertOwned(named, 'completion receipt')
  let descriptor
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
  } catch {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
      `${basename(path)} could not be opened as a sealed receipt`)
  }
  let content
  try {
    const opened = fstatSync(descriptor)
    if (opened.dev !== named.dev || opened.ino !== named.ino ||
        opened.size !== named.size || opened.nlink !== 1 ||
        fullMode(opened) !== 0o600) {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
        `${basename(path)} changed identity before readback`)
    }
    content = readFileSync(descriptor)
    const after = fstatSync(descriptor)
    const linked = lstatSync(path)
    if (content.byteLength !== opened.size || after.dev !== opened.dev ||
        after.ino !== opened.ino || after.size !== opened.size ||
        linked.dev !== opened.dev || linked.ino !== opened.ino ||
        linked.size !== opened.size || linked.nlink !== 1 ||
        fullMode(linked) !== 0o600 || linked.isSymbolicLink()) {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
        `${basename(path)} changed identity during readback`)
    }
  } finally {
    try { closeSync(descriptor) } catch {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED',
        'sealed completion receipt descriptor could not be closed')
    }
  }
  RECEIPT_IDENTITIES.set(identityKey, Object.freeze({
    dev: named.dev,
    ino: named.ino
  }))
  let value
  try { value = JSON.parse(content) } catch {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
      `${basename(path)} is not sealed JSON`)
  }
  exact(value, [
    'schema', 'version', 'sequence', 'phase', 'state', 'artifacts',
    'previousReceiptHash', 'receiptHash'
  ], 'completion receipt')
  const unsigned = { ...value }
  delete unsigned.receiptHash
  if (value.schema !== EVENT_SCHEMA || value.version !== 1 ||
      value.state !== 'COMPLETED' || !Number.isSafeInteger(value.sequence) ||
      value.sequence < 0 || !PEERIT_SEQ29_COMPLETION_PHASES_V1.includes(value.phase) ||
      !HEX64.test(value.receiptHash) || value.receiptHash !== digest(unsigned) ||
      !bytes(value).equals(content)) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
      `${basename(path)} has invalid canonical receipt content`)
  }
  validateArtifacts(value.artifacts, value.phase)
  return Object.freeze(value)
}

function load (directory) {
  authenticateDirectory(directory)
  const names = readdirSync(directory).sort()
  authenticateDirectory(directory)
  if (names.some(name => !/^[0-9]{4}-[a-z0-9-]+\.json$/.test(name))) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
      'completion receipt directory contains an unexpected entry')
  }
  const receipts = names.map(name => readReceipt(join(directory, name)))
  for (let index = 0; index < receipts.length; index++) {
    const receipt = receipts[index]
    if (receipt.sequence !== index ||
        receipt.phase !== PEERIT_SEQ29_COMPLETION_PHASES_V1[index] ||
        nameFor(index, receipt.phase) !== names[index] ||
        receipt.previousReceiptHash !== (index === 0
          ? null
          : receipts[index - 1].receiptHash)) {
      fail('PEERIT_SEQ29_COMPLETION_RECEIPT_CORRUPT',
        'completion receipt sequence or hash chain is discontinuous')
    }
  }
  return receipts
}

function nameFor (sequence, phase) {
  return `${String(sequence).padStart(4, '0')}-${phase}.json`
}

// Status honesty is fail-closed: the caller must declare exactly which
// phases have installed fixed handlers. A phase chain that cannot actually
// execute its next phase reports INCOMPLETE — never a false READY. Only an
// installed next phase reports READY, and only a fully sealed chain reports
// COMPLETE. Failures surface as thrown coded errors (BLOCKED at the driver
// boundary), never as a ready-looking status.
function validateInstalledPhases (value) {
  if (!Array.isArray(value) ||
      new Set(value).size !== value.length ||
      value.some(phase => typeof phase !== 'string' ||
        !PEERIT_SEQ29_COMPLETION_PHASES_V1.includes(phase))) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_INVALID',
      'installed phase authority list is invalid')
  }
  return Object.freeze([...value])
}

function statusFor (receipts, installedPhases) {
  const nextPhase = PEERIT_SEQ29_COMPLETION_PHASES_V1[receipts.length] || null
  return Object.freeze({
    schema: STATUS_SCHEMA,
    version: 1,
    state: nextPhase == null
      ? 'COMPLETE'
      : installedPhases.includes(nextPhase) ? 'READY' : 'INCOMPLETE',
    completedPhases: Object.freeze(receipts.map(receipt => receipt.phase)),
    nextPhase,
    receipts: Object.freeze(receipts.map(receipt => Object.freeze({
      phase: receipt.phase,
      artifacts: Object.freeze({ ...receipt.artifacts }),
      receiptHash: receipt.receiptHash
    })))
  })
}

export function inspectPeeritSeq29CompletionStatusV1 (input = {}) {
  exact(input, ['root', 'installedPhases'], 'completion status input')
  const installedPhases = validateInstalledPhases(input.installedPhases)
  const root = resolve(String(input.root || ''))
  const deploy = join(root, '.deploy')
  const directory = join(deploy, 'seq29-completion-v1')
  authenticateRepositoryRoot(root)
  if (!entryExists(deploy)) return statusFor([], installedPhases)
  ensureOuterDeployDirectory(root, deploy)
  if (!entryExists(directory)) return statusFor([], installedPhases)
  const metadata = authenticateDirectory(directory)
  if (fullMode(metadata) !== 0o700) {
    fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
      'completion receipt directory must retain exact private mode')
  }
  return statusFor(load(directory), installedPhases)
}

export function createPeeritSeq29CompletionReceiptStoreV1 (input = {}) {
  exact(input, ['root', 'installedPhases'], 'completion receipt store input')
  const installedPhases = validateInstalledPhases(input.installedPhases)
  const root = resolve(String(input.root || ''))
  const deploy = join(root, '.deploy')
  ensureOuterDeployDirectory(root, deploy)
  const directory = join(deploy, 'seq29-completion-v1')
  ensureDirectory(root, directory, 0o700)
  const store = Object.freeze({
    inspect () {
      return statusFor(load(directory), installedPhases)
    },
    record (input = {}) {
      exact(input, ['phase', 'artifacts'], 'completion receipt input')
      const receipts = load(directory)
      const sequence = receipts.length
      const expectedPhase = PEERIT_SEQ29_COMPLETION_PHASES_V1[sequence]
      if (input.phase !== expectedPhase) {
        fail('PEERIT_SEQ29_COMPLETION_PHASE_ORDER',
          'completion can continue only at its exact next fixed phase')
      }
      const unsigned = {
        schema: EVENT_SCHEMA,
        version: 1,
        sequence,
        phase: input.phase,
        state: 'COMPLETED',
        artifacts: validateArtifacts(input.artifacts, input.phase),
        previousReceiptHash: sequence === 0
          ? null
          : receipts.at(-1).receiptHash
      }
      const receipt = { ...unsigned, receiptHash: digest(unsigned) }
      const path = join(directory, nameFor(sequence, input.phase))
      const pendingPath = join(directory,
        `.pending-${nameFor(sequence, input.phase)}`)
      let pendingDescriptor
      try {
        pendingDescriptor = openSync(pendingPath, 'wx', 0o600)
        writeFileSync(pendingDescriptor, `${input.phase}\n`)
        fsyncSync(pendingDescriptor)
        closeSync(pendingDescriptor)
        pendingDescriptor = undefined
        fsyncDirectory(directory)
      } catch {
        if (pendingDescriptor !== undefined) {
          try { closeSync(pendingDescriptor) } catch {}
        }
        fail('PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED',
          'completion receipt durability intent could not be sealed')
      }
      let descriptor
      let primaryError = null
      try {
        descriptor = openSync(path, 'wx', 0o600)
        const opened = fstatSync(descriptor)
        if (!opened.isFile() || opened.nlink !== 1 ||
            fullMode(opened) !== 0o600) {
          fail('PEERIT_SEQ29_COMPLETION_RECEIPT_PERMISSIONS',
            'new completion receipt is not an exact private regular file')
        }
        assertOwned(opened, 'new completion receipt')
        writeFileSync(descriptor, bytes(receipt))
        fsyncSync(descriptor)
      } catch (cause) {
        primaryError = cause
      }
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor)
          if (process.env.PEERIT_SEQ29_COMPLETION_RECEIPT_TEST_FAULT ===
              'CLOSE_UNCERTAIN') {
            throw new Error('injected close uncertainty')
          }
        } catch (cause) {
          if (primaryError == null) primaryError = cause
        }
      }
      if (primaryError) {
        if (existsSync(path)) UNCERTAIN_RECEIPTS.add(resolve(path))
        if (primaryError?.code?.startsWith('PEERIT_')) throw primaryError
        fail(primaryError?.code === 'EEXIST'
          ? 'PEERIT_SEQ29_COMPLETION_RECEIPT_EXISTS'
          : 'PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED',
        'completion receipt could not be sealed with certain close status')
      }
      try {
        if (process.env.PEERIT_SEQ29_COMPLETION_RECEIPT_TEST_FAULT ===
            'DIRECTORY_SYNC_UNCERTAIN') {
          throw new Error('injected directory sync uncertainty')
        }
        fsyncDirectory(directory)
      } catch {
        UNCERTAIN_RECEIPTS.add(resolve(path))
        fail('PEERIT_SEQ29_COMPLETION_RECEIPT_IO_FAILED',
          'completion receipt directory entry has uncertain durability')
      }
      unlinkSync(pendingPath)
      fsyncDirectory(directory)
      const sealed = readReceipt(path)
      return statusFor([...receipts, sealed], installedPhases)
    }
  })
  STORES.set(store, Object.freeze({ root, directory }))
  return store
}
