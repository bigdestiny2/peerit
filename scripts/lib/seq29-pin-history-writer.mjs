import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as nodeVerify
} from 'node:crypto'
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'
import { appendPeeritWebReleasePinHistoryV1 } from '../append-web-release-pin-history.mjs'

const PLAN_SCHEMA = 'peerit-seq29-pin-history-write-plan-v1'
const RECEIPT_SCHEMA = 'peerit-seq29-pin-history-write-receipt-v1'
const HISTORY = 'deploy/web-release-pin-history.json'
const SIGNATURE = 'deploy/web-release-pin-history.json.sig.json'
const CONFIG = 'deploy/web-release.json'
const REQUEST = 'deploy/web-signing-request.json'
const MANIFEST = 'web/asset-manifest.json'
const JOURNAL = '.deploy/seq29-pin-history-write-v1'
const MAX_FILE_BYTES = 4 * 1024 * 1024
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const SPKI_PREFIX = '302a300506032b6570032100'
const TEST_FAULT = 'PEERIT_SEQ29_PIN_HISTORY_WRITER_TEST_FAULT'

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
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

function hash (value) {
  return createHash('sha256').update(value).digest('hex')
}

function recordHash (value) {
  return hash(canonical(value))
}

function recordBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

function fullMode (metadata) {
  return metadata.mode & 0o7777
}

function assertOwned (metadata, field) {
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
      `${field} is not owned by the current operator`)
  }
}

function assertTrustedPath (root, path) {
  const rootPath = resolve(root)
  const parent = dirname(resolve(path))
  const suffix = relative(rootPath, parent)
  if (suffix === '..' || suffix.startsWith(`..${sep}`)) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
      'fixed pin-history path escapes the repository root')
  }
  let cursor = rootPath
  for (const part of suffix === '' ? [] : suffix.split(sep)) {
    const metadata = lstatSync(cursor)
    if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
        (fullMode(metadata) & 0o7022) !== 0) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
        'pin-history parent is not an authenticated owner-only-write directory')
    }
    assertOwned(metadata, 'pin-history parent')
    cursor = join(cursor, part)
  }
  const metadata = lstatSync(cursor)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      (fullMode(metadata) & 0o7022) !== 0) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
      'pin-history parent is not an authenticated owner-only-write directory')
  }
  assertOwned(metadata, 'pin-history parent')
}

function sameIdentity (left, right) {
  return left.dev === right.dev && left.ino === right.ino &&
    left.uid === right.uid && left.gid === right.gid &&
    left.size === right.size && left.nlink === right.nlink &&
    fullMode(left) === fullMode(right)
}

function inspectFile (path, expectedMode, { synchronize = false } = {}) {
  let named
  try { named = lstatSync(path) } catch {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      `${basename(path)} is missing`)
  }
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1 ||
      fullMode(named) !== expectedMode || named.size > MAX_FILE_BYTES) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
      `${basename(path)} is not an exact single-link regular file`)
  }
  assertOwned(named, basename(path))
  let descriptor
  let content
  let primary
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || !sameIdentity(named, opened)) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
        `${basename(path)} changed identity before authenticated read`)
    }
    content = readFileSync(descriptor)
    if (synchronize) fsyncSync(descriptor)
    const after = fstatSync(descriptor)
    const namedAfter = lstatSync(path)
    if (content.byteLength !== opened.size || !sameIdentity(opened, after) ||
        !sameIdentity(opened, namedAfter)) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
        `${basename(path)} changed during authenticated read`)
    }
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try { closeSync(descriptor) } catch {
      if (!primary) primary = new Error('file close uncertainty')
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_SEQ29_')) throw primary
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED',
      'authenticated pin-history file access failed')
  }
  return Object.freeze({
    bytes: Buffer.from(content),
    sha256: hash(content),
    dev: String(named.dev),
    ino: String(named.ino),
    size: named.size,
    mode: fullMode(named)
  })
}

function assertSnapshot (snapshot, current, field, { allowSuccessor = false } = {}) {
  if ((!allowSuccessor && current.sha256 !== snapshot.sha256) ||
      current.dev !== snapshot.dev || current.ino !== snapshot.ino ||
      current.size !== snapshot.size || current.mode !== snapshot.mode) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PREIMAGE_DRIFT',
      `${field} differs from the sealed writer preimage`)
  }
}

function fsyncDirectory (path) {
  const named = lstatSync(path)
  if (!named.isDirectory() || named.isSymbolicLink()) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
      'pin-history directory is not real')
  }
  assertOwned(named, 'pin-history directory')
  let descriptor
  let primary
  try {
    descriptor = openSync(path, constants.O_RDONLY |
      (constants.O_DIRECTORY || 0) | (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor)
    if (!opened.isDirectory() || !sameIdentity(named, opened)) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
        'pin-history directory changed before authenticated sync')
    }
    fsyncSync(descriptor)
    const after = fstatSync(descriptor)
    const namedAfter = lstatSync(path)
    if (!sameIdentity(opened, after) || !sameIdentity(opened, namedAfter)) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
        'pin-history directory changed during authenticated sync')
    }
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try { closeSync(descriptor) } catch {
      if (!primary) primary = new Error('directory close uncertainty')
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_SEQ29_')) throw primary
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED',
      'pin-history directory durability is uncertain')
  }
}

function createPrivateDirectory (root, path) {
  assertTrustedPath(root, join(dirname(path), 'entry'))
  if (!existsSync(path)) {
    try { mkdirSync(path, { mode: 0o700 }) } catch {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED',
        'pin-history journal directory could not be created')
    }
    fsyncDirectory(dirname(path))
  }
  const metadata = lstatSync(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      fullMode(metadata) !== 0o700) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
      'pin-history journal must retain exact mode 0700')
  }
  assertOwned(metadata, 'pin-history journal')
}

function createSealedFile (path, content, mode = 0o600) {
  let descriptor
  let primary
  try {
    descriptor = openSync(path, 'wx', 0o600)
    fchmodSync(descriptor, mode)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1 || fullMode(opened) !== mode) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS',
        'new pin-history transaction file is not exact')
    }
    writeFileSync(descriptor, content)
    fsyncSync(descriptor)
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try { closeSync(descriptor) } catch {
      if (!primary) primary = new Error('transaction close uncertainty')
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_SEQ29_')) throw primary
    fail(primary.code === 'EEXIST'
      ? 'PEERIT_SEQ29_PIN_HISTORY_WRITE_CONFLICT'
      : 'PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED',
    'pin-history transaction file could not be sealed')
  }
  return inspectFile(path, mode)
}

function parseJson (content, field) {
  try {
    const value = JSON.parse(Buffer.from(content).toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error()
    return value
  } catch {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT', `${field} is not JSON`)
  }
}

function verifyPredecessorSignature (files) {
  const config = parseJson(files.config.bytes, 'release config')
  const envelope = parseJson(files.signature.bytes, 'predecessor signature')
  const key = String(config.pinnedReleaseKey || '').toLowerCase()
  if (!HEX64.test(key) || envelope.schema !==
      'peerit-blind-public-test-artifact-sig/v1' || envelope.alg !== 'ed25519' ||
      envelope.key !== key || envelope.signedFile !== HISTORY ||
      envelope.signedBytesSha256 !== files.history.sha256 ||
      !HEX128.test(String(envelope.sig || ''))) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_SIGNATURE_INVALID',
      'predecessor signature envelope does not bind the exact history bytes')
  }
  let verified = false
  try {
    verified = nodeVerify(null, files.history.bytes, createPublicKey({
      key: Buffer.from(SPKI_PREFIX + key, 'hex'),
      format: 'der',
      type: 'spki'
    }), Buffer.from(envelope.sig, 'hex'))
  } catch {}
  if (!verified) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_SIGNATURE_INVALID',
      'signed predecessor pin-history does not verify')
  }
}

function snapshotFiles (root) {
  const paths = Object.freeze({
    config: join(root, CONFIG),
    request: join(root, REQUEST),
    manifest: join(root, MANIFEST),
    history: join(root, HISTORY),
    signature: join(root, SIGNATURE)
  })
  for (const path of Object.values(paths)) assertTrustedPath(root, path)
  const files = Object.freeze(Object.fromEntries(Object.entries(paths).map(
    ([field, path]) => [field, inspectFile(path, 0o644)])))
  verifyPredecessorSignature(files)
  return Object.freeze({ paths, files })
}

function serializedSnapshot (snapshot, relativePath) {
  return Object.freeze({
    relativePath,
    sha256: snapshot.sha256,
    dev: snapshot.dev,
    ino: snapshot.ino,
    size: snapshot.size,
    mode: snapshot.mode
  })
}

function validatePlan (value) {
  exact(value, [
    'schema', 'version', 'state', 'files', 'successorSha256',
    'successorBase64', 'temporaryName', 'planHash'
  ], 'pin-history write plan')
  exact(value.files, ['config', 'request', 'manifest', 'history', 'signature'],
    'pin-history plan files')
  for (const file of Object.values(value.files)) {
    exact(file, ['relativePath', 'sha256', 'dev', 'ino', 'size', 'mode'],
      'pin-history plan file')
    if (!HEX64.test(file.sha256) || !Number.isSafeInteger(file.size) ||
        file.size < 0 || file.size > MAX_FILE_BYTES || file.mode !== 0o644) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
        'pin-history plan file identity is invalid')
    }
  }
  const unsigned = { ...value }
  delete unsigned.planHash
  let successor
  try { successor = Buffer.from(value.successorBase64, 'base64') } catch {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'pin-history successor encoding is invalid')
  }
  if (value.schema !== PLAN_SCHEMA || value.version !== 1 ||
      value.state !== 'PENDING' || !HEX64.test(value.successorSha256) ||
      successor.toString('base64') !== value.successorBase64 ||
      successor.byteLength > MAX_FILE_BYTES || hash(successor) !== value.successorSha256 ||
      !/^\.seq29-pin-history-[0-9a-f]{24}\.tmp$/.test(value.temporaryName) ||
      !HEX64.test(value.planHash) || recordHash(unsigned) !== value.planHash) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'pin-history write plan is not canonical or self-consistent')
  }
  return Object.freeze({ value, successor })
}

function readPlan (journal) {
  const path = join(journal, 'pending.json')
  const inspected = inspectFile(path, 0o600)
  const value = parseJson(inspected.bytes, 'pin-history write plan')
  if (!recordBytes(value).equals(inspected.bytes)) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'pin-history write plan bytes are not canonical')
  }
  return validatePlan(value)
}

function validateReceipt (value, plan) {
  exact(value, [
    'schema', 'version', 'state', 'planHash', 'predecessorSha256',
    'successorSha256', 'receiptHash'
  ], 'pin-history write receipt')
  const unsigned = { ...value }
  delete unsigned.receiptHash
  if (value.schema !== RECEIPT_SCHEMA || value.version !== 1 ||
      value.state !== 'COMPLETED' || value.planHash !== plan.planHash ||
      value.predecessorSha256 !== plan.files.history.sha256 ||
      value.successorSha256 !== plan.successorSha256 ||
      value.receiptHash !== recordHash(unsigned)) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'pin-history write receipt does not bind its plan')
  }
  return Object.freeze(value)
}

function readReceipt (journal, plan) {
  const inspected = inspectFile(join(journal, 'committed.json'), 0o600,
    { synchronize: true })
  const value = parseJson(inspected.bytes, 'pin-history write receipt')
  if (!recordBytes(value).equals(inspected.bytes)) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'pin-history write receipt bytes are not canonical')
  }
  return validateReceipt(value, plan)
}

function inspectFromPlan (root, file) {
  const expected = new Map([
    [CONFIG, 'config'], [REQUEST, 'request'], [MANIFEST, 'manifest'],
    [HISTORY, 'history'], [SIGNATURE, 'signature']
  ])
  if (!expected.has(file.relativePath)) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'pin-history plan names a non-fixed source')
  }
  return inspectFile(join(root, file.relativePath), file.mode)
}

function assertUnchangedSources (root, plan, { historySuccessor = false } = {}) {
  for (const [field, snapshot] of Object.entries(plan.files)) {
    const current = inspectFromPlan(root, snapshot)
    if (field === 'history' && historySuccessor) {
      if (current.sha256 !== plan.successorSha256 ||
          current.mode !== snapshot.mode) {
        fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_PREIMAGE_DRIFT',
          'pin-history target is neither the sealed predecessor nor successor')
      }
    } else {
      assertSnapshot(snapshot, current, field)
    }
  }
}

function sealReceipt (journal, plan) {
  const unsigned = {
    schema: RECEIPT_SCHEMA,
    version: 1,
    state: 'COMPLETED',
    planHash: plan.planHash,
    predecessorSha256: plan.files.history.sha256,
    successorSha256: plan.successorSha256
  }
  const receipt = { ...unsigned, receiptHash: recordHash(unsigned) }
  createSealedFile(join(journal, 'committed.json'), recordBytes(receipt))
  fsyncDirectory(journal)
  return readReceipt(journal, plan)
}

function completePlan (root, journal, plan, successor) {
  const historyPath = join(root, HISTORY)
  const current = inspectFile(historyPath, plan.files.history.mode)
  if (current.sha256 === plan.successorSha256) {
    assertUnchangedSources(root, plan, { historySuccessor: true })
    fsyncDirectory(dirname(historyPath))
    return sealReceipt(journal, plan)
  }
  assertSnapshot(plan.files.history, current, 'history')
  assertUnchangedSources(root, plan)
  const temporary = join(dirname(historyPath), plan.temporaryName)
  let staged
  if (existsSync(temporary)) {
    staged = inspectFile(temporary, plan.files.history.mode, { synchronize: true })
    if (staged.sha256 !== plan.successorSha256 ||
        !staged.bytes.equals(successor)) {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
        'staged pin-history successor differs from the sealed plan')
    }
  } else {
    staged = createSealedFile(temporary, successor, plan.files.history.mode)
    if (process.env[TEST_FAULT] === 'TEMP_CLOSE_UNCERTAIN') {
      fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED',
        'staged pin-history close durability is uncertain')
    }
  }
  fsyncDirectory(dirname(historyPath))
  assertUnchangedSources(root, plan)
  renameSync(temporary, historyPath)
  const replaced = inspectFile(historyPath, plan.files.history.mode)
  if (replaced.sha256 !== plan.successorSha256 ||
      replaced.dev !== staged.dev || replaced.ino !== staged.ino ||
      !replaced.bytes.equals(successor)) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'atomic pin-history replacement does not equal its sealed successor')
  }
  assertUnchangedSources(root, plan, { historySuccessor: true })
  if (process.env[TEST_FAULT] === 'POST_RENAME_DIRECTORY_SYNC_UNCERTAIN') {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED',
      'pin-history replacement directory durability is uncertain')
  }
  fsyncDirectory(dirname(historyPath))
  return sealReceipt(journal, plan)
}

function status (receipt) {
  return Object.freeze({
    schema: 'peerit-seq29-pin-history-write-status-v1',
    version: 1,
    state: 'COMPLETED',
    predecessorSha256: receipt.predecessorSha256,
    successorSha256: receipt.successorSha256,
    receiptHash: receipt.receiptHash
  })
}

export function appendPeeritSeq29PinHistoryJournaledV1 (input = {}) {
  exact(input, ['root'], 'pin-history writer input')
  const root = resolve(String(input.root || ''))
  const journal = join(root, JOURNAL)
  createPrivateDirectory(root, journal)
  const names = readdirSync(journal).sort()
  if (names.some(name => !['pending.json', 'committed.json'].includes(name)) ||
      (names.includes('committed.json') && !names.includes('pending.json'))) {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT',
      'pin-history writer journal contains unexpected or incomplete state')
  }
  if (names.includes('pending.json')) {
    const { value: plan, successor } = readPlan(journal)
    if (names.includes('committed.json')) {
      const receipt = readReceipt(journal, plan)
      assertUnchangedSources(root, plan, { historySuccessor: true })
      fsyncDirectory(journal)
      return status(receipt)
    }
    return status(completePlan(root, journal, plan, successor))
  }

  const snapshot = snapshotFiles(root)
  const derived = appendPeeritWebReleasePinHistoryV1({
    write: false,
    configBytes: snapshot.files.config.bytes,
    requestBytes: snapshot.files.request.bytes,
    manifestBytes: snapshot.files.manifest.bytes,
    historyBytes: snapshot.files.history.bytes
  })
  const unsigned = {
    schema: PLAN_SCHEMA,
    version: 1,
    state: 'PENDING',
    files: {
      config: serializedSnapshot(snapshot.files.config, CONFIG),
      request: serializedSnapshot(snapshot.files.request, REQUEST),
      manifest: serializedSnapshot(snapshot.files.manifest, MANIFEST),
      history: serializedSnapshot(snapshot.files.history, HISTORY),
      signature: serializedSnapshot(snapshot.files.signature, SIGNATURE)
    },
    successorSha256: hash(derived.bytes),
    successorBase64: Buffer.from(derived.bytes).toString('base64'),
    temporaryName: `.seq29-pin-history-${randomBytes(12).toString('hex')}.tmp`
  }
  const plan = { ...unsigned, planHash: recordHash(unsigned) }
  createSealedFile(join(journal, 'pending.json'), recordBytes(plan))
  fsyncDirectory(journal)
  if (process.env[TEST_FAULT] === 'AFTER_PENDING') {
    fail('PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED',
      'pin-history write paused after durable plan sealing')
  }
  return status(completePlan(root, journal, plan,
    Buffer.from(derived.bytes)))
}
