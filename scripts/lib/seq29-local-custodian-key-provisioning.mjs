// Create-only provisioning for the three raw Seq29 X25519 custodian keys.
// The production entry point has no fixture controls. Test-only entropy and
// fault injection are separately gated and never reachable from the CLI.

import { randomFillSync } from 'node:crypto'
import {
  constants,
  closeSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  writeSync
} from 'node:fs'
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep
} from 'node:path'

import {
  createPeeritSeq29LocalCustodianKeyFileConfigurationV1
} from './seq29-local-custodian-key-files.mjs'

const KEY_BYTES = 32
const KEY_FILES = Object.freeze([
  'custodian-1.x25519',
  'custodian-2.x25519',
  'custodian-3.x25519'
])
const FIXTURE_ENV = 'PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_TEST'

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function exactWithOptional (value, required, optional, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_INVALID', `${field} must be an object`)
  }
  const allowed = new Set([...required, ...optional])
  if (required.some(name => !Object.hasOwn(value, name)) ||
      Object.keys(value).some(name => !allowed.has(name))) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function currentUid () {
  if (typeof process.getuid !== 'function') {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_UNSUPPORTED',
      'custodian provisioning requires POSIX ownership checks')
  }
  return BigInt(process.getuid())
}

function requireSecureOpenFlags () {
  for (const name of [
    'O_CREAT', 'O_DIRECTORY', 'O_EXCL', 'O_NOFOLLOW', 'O_RDONLY', 'O_RDWR'
  ]) {
    if (!Number.isInteger(constants[name]) ||
        (name !== 'O_RDONLY' && constants[name] === 0)) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_UNSUPPORTED',
        'custodian provisioning requires secure POSIX open flags')
    }
  }
}

function lstatIfPresent (path) {
  try {
    return lstatSync(path, { bigint: true })
  } catch (cause) {
    if (cause?.code === 'ENOENT') return null
    throw cause
  }
}

function inodeIdentity (metadata) {
  return Object.freeze({
    dev: metadata.dev,
    ino: metadata.ino,
    uid: metadata.uid
  })
}

function sameInode (metadata, identity) {
  return metadata.dev === identity.dev && metadata.ino === identity.ino &&
    metadata.uid === identity.uid
}

function stableIdentity (metadata) {
  return [
    metadata.dev,
    metadata.ino,
    metadata.uid,
    metadata.mode,
    metadata.nlink
  ].join(':')
}

function exactIdentity (metadata) {
  return [
    stableIdentity(metadata),
    metadata.size,
    metadata.mtimeNs,
    metadata.ctimeNs
  ].join(':')
}

function assertDirectoryMetadata (metadata, uid, mode, field) {
  if (metadata.isSymbolicLink() || !metadata.isDirectory() ||
      metadata.uid !== uid || metadata.nlink < 1n ||
      (metadata.mode & 0o7777n) !== BigInt(mode)) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
      `${field} does not have the required owned directory topology`)
  }
}

function assertPrivateFileMetadata (metadata, uid, expectedSize, field) {
  if (metadata.isSymbolicLink() || !metadata.isFile() ||
      metadata.uid !== uid || metadata.nlink !== 1n ||
      (metadata.mode & 0o7777n) !== 0o600n ||
      metadata.size !== BigInt(expectedSize)) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
      `${field} does not have the required owned file topology`)
  }
}

function pathComponents (path) {
  const root = parse(path).root
  const suffix = relative(root, path)
  const output = [root]
  let cursor = root
  for (const component of suffix === '' ? [] : suffix.split(sep)) {
    cursor = join(cursor, component)
    output.push(cursor)
  }
  return output
}

function snapshotOwnedParentChain (parent, uid) {
  let canonical
  try {
    canonical = realpathSync(parent)
  } catch {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
      'target parent must already be a real directory')
  }
  if (canonical !== parent) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
      'target parent chain must contain no symbolic links')
  }

  const snapshots = []
  let operatorBoundarySeen = false
  for (const path of pathComponents(parent)) {
    const metadata = lstatSync(path, { bigint: true })
    if (metadata.isSymbolicLink() || !metadata.isDirectory() || metadata.nlink < 1n) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
        'target parent chain must contain only real directories')
    }
    if (metadata.uid !== 0n && metadata.uid !== uid) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
        'target parent chain contains a directory owned by another identity')
    }
    const writableByOthers = (metadata.mode & 0o022n) !== 0n
    const rootStickyBoundary = metadata.uid === 0n &&
      (metadata.mode & 0o1000n) !== 0n
    if (writableByOthers && !rootStickyBoundary) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
        'target parent chain contains an unsafe writable directory')
    }
    if (uid !== 0n && metadata.uid === uid) operatorBoundarySeen = true
    if (uid !== 0n && operatorBoundarySeen && metadata.uid !== uid) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
        'target parent chain leaves its operator-owned boundary')
    }
    snapshots.push(Object.freeze({
      path,
      identity: inodeIdentity(metadata),
      mode: metadata.mode
    }))
  }
  const direct = lstatSync(parent, { bigint: true })
  if (direct.uid !== uid || (direct.mode & 0o022n) !== 0n) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
      'target parent must be owned by the current operator and not writable by others')
  }
  return Object.freeze(snapshots)
}

function validateParentChain (snapshots) {
  for (const snapshot of snapshots) {
    const metadata = lstatSync(snapshot.path, { bigint: true })
    if (metadata.isSymbolicLink() || !metadata.isDirectory() ||
        metadata.nlink < 1n || !sameInode(metadata, snapshot.identity) ||
        metadata.mode !== snapshot.mode) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'target parent chain changed during provisioning')
    }
  }
}

function openVerifiedDirectory (path, expected) {
  const descriptor = openSync(path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
  try {
    const opened = fstatSync(descriptor, { bigint: true })
    const named = lstatSync(path, { bigint: true })
    if (!sameInode(opened, named) || opened.mode !== named.mode ||
        !opened.isDirectory() || !named.isDirectory() || named.isSymbolicLink() ||
        (expected != null && !sameInode(opened, expected))) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'directory identity changed during secure open')
    }
    return descriptor
  } catch (cause) {
    closeSync(descriptor)
    throw cause
  }
}

function validateHeldParent (descriptor, parent, snapshot) {
  const opened = fstatSync(descriptor, { bigint: true })
  const named = lstatSync(parent, { bigint: true })
  if (!sameInode(opened, snapshot.identity) ||
      !sameInode(named, snapshot.identity) ||
      opened.mode !== snapshot.mode || named.mode !== snapshot.mode ||
      !opened.isDirectory() || !named.isDirectory() || named.isSymbolicLink()) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'target parent changed during provisioning')
  }
}

function validateHeldTarget (
  descriptor, directory, identity, stableTargetIdentity, uid
) {
  const opened = fstatSync(descriptor, { bigint: true })
  const named = lstatSync(directory, { bigint: true })
  assertDirectoryMetadata(opened, uid, 0o700, 'target directory')
  assertDirectoryMetadata(named, uid, 0o700, 'target directory')
  if (!sameInode(opened, identity) || !sameInode(named, identity) ||
      stableIdentity(opened) !== stableIdentity(named) ||
      stableIdentity(opened) !== stableTargetIdentity) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'target directory changed during provisioning')
  }
  return named
}

function keysAreDistinctAndNonzero (keys) {
  for (const key of keys) {
    if (key.every(byte => byte === 0)) return false
  }
  for (let left = 0; left < keys.length; left++) {
    for (let right = left + 1; right < keys.length; right++) {
      if (keys[left].equals(keys[right])) return false
    }
  }
  return true
}

function generateKeys (fillRandom) {
  const keys = []
  try {
    for (let index = 0; index < KEY_FILES.length; index++) {
      const key = Buffer.alloc(KEY_BYTES)
      keys.push(key)
      fillRandom(key, index)
    }
    if (!keysAreDistinctAndNonzero(keys)) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_ENTROPY_INVALID',
        'generated custodian private keys must be distinct and nonzero')
    }
    return keys
  } catch (cause) {
    for (const key of keys) key.fill(0)
    throw cause
  }
}

function writeExact (descriptor, bytes, write) {
  let offset = 0
  while (offset < bytes.byteLength) {
    const count = write(
      descriptor, bytes, offset, bytes.byteLength - offset, offset)
    if (!Number.isInteger(count) || count < 1 ||
        count > bytes.byteLength - offset) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED',
        'custodian private key write did not make valid progress')
    }
    offset += count
  }
}

function captureTargetAfterKnownFileCreate (state) {
  const opened = fstatSync(state.directoryDescriptor, { bigint: true })
  const named = lstatSync(state.directory, { bigint: true })
  assertDirectoryMetadata(opened, state.uid, 0o700, 'target directory')
  assertDirectoryMetadata(named, state.uid, 0o700, 'target directory')
  if (!sameInode(opened, state.directoryIdentity) ||
      !sameInode(named, state.directoryIdentity) ||
      stableIdentity(opened) !== stableIdentity(named)) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'target directory changed during known file creation')
  }
  const expectedNames = [...state.createdFiles.keys()].sort()
  const names = readdirSync(state.directory).sort()
  if (names.join('\0') !== expectedNames.join('\0')) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'target directory gained an entry outside the known create-only set')
  }
  for (const name of names) {
    const metadata = lstatSync(join(state.directory, name), { bigint: true })
    assertPrivateFileMetadata(metadata, state.uid, KEY_BYTES, 'custodian private key')
    if (!sameInode(metadata, state.createdFiles.get(name))) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian private key inode changed during known file creation')
    }
  }
  const openedAfter = fstatSync(state.directoryDescriptor, { bigint: true })
  const namedAfter = lstatSync(state.directory, { bigint: true })
  if (stableIdentity(openedAfter) !== stableIdentity(opened) ||
      stableIdentity(namedAfter) !== stableIdentity(opened)) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'target directory changed while capturing known file creation')
  }
  state.directoryStableIdentity = stableIdentity(opened)
}

function validateKnownTargetTopology (state) {
  validateHeldTarget(
    state.directoryDescriptor, state.directory, state.directoryIdentity,
    state.directoryStableIdentity, state.uid)
  const expectedNames = [...state.createdFiles.keys()].sort()
  const names = readdirSync(state.directory).sort()
  if (names.join('\0') !== expectedNames.join('\0')) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'target directory differs from the exact known create-only topology')
  }
  for (const name of names) {
    const metadata = lstatSync(join(state.directory, name), { bigint: true })
    assertPrivateFileMetadata(metadata, state.uid, KEY_BYTES, 'custodian private key')
    if (!sameInode(metadata, state.createdFiles.get(name))) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian private key inode changed in known target topology')
    }
  }
}

function createPrivateKeyFile (
  state, name, bytes, write, syncFile, syncDirectory, closeFile
) {
  validateKnownTargetTopology(state)
  const path = join(state.directory, name)
  let descriptor
  let complete = false
  let closeFailure = null
  try {
    descriptor = openSync(path,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR |
      constants.O_NOFOLLOW, 0o600)
    const opened = fstatSync(descriptor, { bigint: true })
    if (!opened.isFile() || opened.isSymbolicLink() || opened.uid !== state.uid ||
        opened.nlink !== 1n || opened.size !== 0n ||
        (opened.mode & 0o077n) !== 0n) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
        'new custodian private key did not have a private owned inode')
    }
    state.createdFiles.set(name, inodeIdentity(opened))
    fchmodSync(descriptor, 0o600)
    const before = fstatSync(descriptor, { bigint: true })
    const beforeNamed = lstatSync(path, { bigint: true })
    assertPrivateFileMetadata(before, state.uid, 0, 'new custodian private key')
    if (exactIdentity(before) !== exactIdentity(beforeNamed)) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian private key changed before its exact write')
    }
    writeExact(descriptor, bytes, write)
    syncFile(descriptor, 'KEY_FULL')
    const after = fstatSync(descriptor, { bigint: true })
    const afterNamed = lstatSync(path, { bigint: true })
    assertPrivateFileMetadata(after, state.uid, KEY_BYTES, 'custodian private key')
    if (!sameInode(after, state.createdFiles.get(name)) ||
        exactIdentity(after) !== exactIdentity(afterNamed) ||
        stableIdentity(after) !== stableIdentity(before)) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian private key changed during its exact write and fsync')
    }
    state.completedFiles.add(name)
    complete = true
  } catch (cause) {
    if (cause?.code === 'EEXIST') {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian target topology changed before file creation')
    }
    throw cause
  } finally {
    if (descriptor != null) {
      if (!complete) {
        state.residueFileFsyncAttempted = true
        try {
          syncFile(descriptor, 'KEY_PARTIAL_PRESERVE')
        } catch {
          state.residueFileFsyncFailed = true
        }
      }
      state.residueFileCloseAttempted = true
      try {
        closeFile(descriptor)
      } catch (cause) {
        state.residueFileCloseFailed = true
        closeFailure = cause
      }
    }
  }
  if (complete && closeFailure != null) throw closeFailure
  syncDirectory(state.directoryDescriptor, 'TARGET_AFTER_KEY')
  captureTargetAfterKnownFileCreate(state)
  verifyPrivateKeyFile(state, name, bytes)
}

function verifyPrivateKeyFile (state, name, expectedBytes) {
  validateHeldTarget(
    state.directoryDescriptor, state.directory, state.directoryIdentity,
    state.directoryStableIdentity, state.uid)
  const path = join(state.directory, name)
  const before = lstatSync(path, { bigint: true })
  assertPrivateFileMetadata(before, state.uid, KEY_BYTES, 'custodian private key')
  if (!sameInode(before, state.createdFiles.get(name))) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'custodian private key inode changed before exact readback')
  }
  let descriptor
  const output = Buffer.alloc(KEY_BYTES)
  const extra = Buffer.alloc(1)
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    const opened = fstatSync(descriptor, { bigint: true })
    if (exactIdentity(opened) !== exactIdentity(before)) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian private key changed during readback open')
    }
    let offset = 0
    while (offset < output.byteLength) {
      const count = readSync(
        descriptor, output, offset, output.byteLength - offset, offset)
      if (count === 0) break
      offset += count
    }
    const after = fstatSync(descriptor, { bigint: true })
    const afterNamed = lstatSync(path, { bigint: true })
    if (offset !== output.byteLength ||
        readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        exactIdentity(after) !== exactIdentity(before) ||
        exactIdentity(afterNamed) !== exactIdentity(before) ||
        !output.equals(expectedBytes)) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian private key bytes or identity changed after creation')
    }
  } finally {
    output.fill(0)
    extra.fill(0)
    if (descriptor != null) closeSync(descriptor)
  }
}

function verifyFinalTopology (state, expectedKeys) {
  validateHeldTarget(
    state.directoryDescriptor, state.directory, state.directoryIdentity,
    state.directoryStableIdentity, state.uid)
  const names = readdirSync(state.directory).sort()
  if (names.join('\0') !== [...KEY_FILES].sort().join('\0')) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
      'custodian target does not contain the exact fixed key-file set')
  }
  for (let index = 0; index < KEY_FILES.length; index++) {
    const name = KEY_FILES[index]
    const metadata = lstatSync(join(state.directory, name), { bigint: true })
    assertPrivateFileMetadata(metadata, state.uid, KEY_BYTES, 'custodian private key')
    if (!sameInode(metadata, state.createdFiles.get(name))) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED',
        'custodian private key inode changed after creation')
    }
    verifyPrivateKeyFile(state, name, expectedKeys[index])
  }
}

function normalizeFailure (cause) {
  if (typeof cause?.code === 'string' &&
      cause.code.startsWith('PEERIT_SEQ29_CUSTODIAN_PROVISION_')) return cause
  const error = new Error('custodian key provisioning failed without exposing details')
  error.code = 'PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED'
  return error
}

function failureTargetTopologyIsExact (state) {
  try {
    validateParentChain(state.parentChain)
    validateHeldParent(
      state.parentDescriptor, state.parent, state.directParentSnapshot)
    const opened = fstatSync(state.directoryDescriptor, { bigint: true })
    const named = lstatSync(state.directory, { bigint: true })
    assertDirectoryMetadata(opened, state.uid, 0o700, 'target directory')
    assertDirectoryMetadata(named, state.uid, 0o700, 'target directory')
    if (!sameInode(opened, state.directoryIdentity) ||
        !sameInode(named, state.directoryIdentity) ||
        stableIdentity(opened) !== stableIdentity(named)) return false

    const expectedNames = [...state.createdFiles.keys()].sort()
    const names = readdirSync(state.directory).sort()
    if (names.join('\0') !== expectedNames.join('\0')) return false
    const fileSnapshots = new Map()
    for (const name of names) {
      const metadata = lstatSync(join(state.directory, name), { bigint: true })
      if (metadata.isSymbolicLink() || !metadata.isFile() ||
          metadata.uid !== state.uid || metadata.nlink !== 1n ||
          (metadata.mode & 0o7777n) !== 0o600n ||
          metadata.size < 0n || metadata.size > BigInt(KEY_BYTES) ||
          (state.completedFiles.has(name) && metadata.size !== BigInt(KEY_BYTES)) ||
          !sameInode(metadata, state.createdFiles.get(name))) return false
      fileSnapshots.set(name, exactIdentity(metadata))
    }

    if (readdirSync(state.directory).sort().join('\0') !==
        expectedNames.join('\0')) return false
    for (const name of names) {
      const metadata = lstatSync(join(state.directory, name), { bigint: true })
      if (exactIdentity(metadata) !== fileSnapshots.get(name)) return false
    }
    const openedAfter = fstatSync(state.directoryDescriptor, { bigint: true })
    const namedAfter = lstatSync(state.directory, { bigint: true })
    return stableIdentity(openedAfter) === stableIdentity(opened) &&
      stableIdentity(namedAfter) === stableIdentity(opened)
  } catch {
    return false
  }
}

function partialFailure (cause, residueDurability, targetTopologyExact) {
  const durabilitySummary = [
    `file=${residueDurability.fileFsync}`,
    `file-close=${residueDurability.fileClose}`,
    `target=${residueDurability.targetFsync}`,
    `parent=${residueDurability.parentFsync}`
  ].join(',')
  const status = targetTopologyExact
    ? 'PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_PRESERVED'
    : 'PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_EXTERNAL_TOPOLOGY_DRIFT'
  const topologySummary = targetTopologyExact
    ? 'the named target matched the held create-only inode topology at the failure boundary'
    : 'the named target was missing, replaced, changed, or could not be revalidated against the held inode topology'
  const error = new Error(
    `provisioning did not complete; ${topologySummary}; no pathname cleanup was attempted; residue sync ${durabilitySummary}; preserve all evidence and retry only with a fresh absolute target`)
  error.code = status
  error.status = status
  error.failureCode = cause.code
  error.residueDurability = residueDurability
  error.targetTopology = targetTopologyExact
    ? 'OBSERVED_EXACT_AT_FAILURE_BOUNDARY'
    : 'EXTERNAL_DRIFT_OR_UNVERIFIED'
  return error
}

function provision (input, dependencies) {
  exact(input, ['directory'], 'custodian provisioning input')
  if (typeof input.directory !== 'string' || input.directory.includes('\0') ||
      !isAbsolute(input.directory) || input.directory !== resolve(input.directory) ||
      basename(input.directory) === '' || basename(input.directory) === '.' ||
      basename(input.directory) === '..') {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_INVALID',
      'custodian target must be one canonical absolute directory path')
  }
  requireSecureOpenFlags()
  const uid = currentUid()
  const directory = input.directory
  const parent = dirname(directory)
  const parentChain = snapshotOwnedParentChain(parent, uid)
  const directParentSnapshot = parentChain[parentChain.length - 1]
  validateParentChain(parentChain)
  const parentDescriptor = openVerifiedDirectory(parent, directParentSnapshot.identity)
  const state = {
    uid,
    directory,
    parent,
    parentChain,
    directParentSnapshot,
    parentDescriptor,
    directoryDescriptor: null,
    directoryCreated: false,
    directoryIdentity: null,
    directoryStableIdentity: null,
    residueFileFsyncAttempted: false,
    residueFileFsyncFailed: false,
    residueFileCloseAttempted: false,
    residueFileCloseFailed: false,
    createdFiles: new Map(),
    completedFiles: new Set()
  }
  let keys = []
  try {
    validateHeldParent(parentDescriptor, parent, directParentSnapshot)
    if (lstatIfPresent(directory) != null) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_ALREADY_EXISTS',
        'custodian target already exists; create-only provisioning never reuses it')
    }
    keys = generateKeys(dependencies.fillRandom)
    validateHeldParent(parentDescriptor, parent, directParentSnapshot)
    if (lstatIfPresent(directory) != null) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_ALREADY_EXISTS',
        'custodian target already exists; create-only provisioning never reuses it')
    }
    try {
      mkdirSync(directory, { mode: 0o700 })
    } catch (cause) {
      if (cause?.code === 'EEXIST') {
        fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_ALREADY_EXISTS',
          'custodian target already exists; create-only provisioning never reuses it')
      }
      throw cause
    }
    state.directoryCreated = true
    const created = lstatSync(directory, { bigint: true })
    if (created.isSymbolicLink() || !created.isDirectory() ||
        created.uid !== uid || created.nlink < 1n ||
        (created.mode & 0o077n) !== 0n) {
      fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS',
        'new custodian target did not have a private owned inode')
    }
    state.directoryIdentity = inodeIdentity(created)
    state.directoryDescriptor = openVerifiedDirectory(
      directory, state.directoryIdentity)
    fchmodSync(state.directoryDescriptor, 0o700)
    dependencies.syncDirectory(state.directoryDescriptor, 'TARGET_INITIAL')
    state.directoryStableIdentity = stableIdentity(
      fstatSync(state.directoryDescriptor, { bigint: true }))
    validateHeldTarget(
      state.directoryDescriptor, directory, state.directoryIdentity,
      state.directoryStableIdentity, uid)
    dependencies.syncDirectory(parentDescriptor, 'PARENT_INITIAL')
    validateParentChain(parentChain)
    dependencies.onStage?.('AFTER_DIRECTORY_FSYNC')

    for (let index = 0; index < KEY_FILES.length; index++) {
      createPrivateKeyFile(
        state, KEY_FILES[index], keys[index], dependencies.write,
        dependencies.syncFile, dependencies.syncDirectory,
        dependencies.closeFile)
      dependencies.onStage?.(`AFTER_KEY_${index + 1}_FSYNC`)
    }
    verifyFinalTopology(state, keys)
    createPeeritSeq29LocalCustodianKeyFileConfigurationV1({ directory })
    dependencies.onStage?.('AFTER_VALIDATOR')
    verifyFinalTopology(state, keys)
    dependencies.syncDirectory(state.directoryDescriptor, 'TARGET_FINAL')
    dependencies.syncDirectory(parentDescriptor, 'PARENT_FINAL')
    validateParentChain(parentChain)
    validateHeldParent(parentDescriptor, parent, directParentSnapshot)
    return Object.freeze({
      status: 'PEERIT_SEQ29_CUSTODIAN_KEYS_CREATED',
      keyCount: KEY_FILES.length
    })
  } catch (cause) {
    const failed = normalizeFailure(cause)
    let targetFsync = 'NOT_APPLICABLE'
    let parentFsync = 'NOT_APPLICABLE'
    if (state.directoryCreated) {
      if (state.directoryDescriptor != null) {
        targetFsync = 'SYNCED'
        try {
          dependencies.syncDirectory(
            state.directoryDescriptor, 'TARGET_FAILURE_PRESERVE')
        } catch {
          targetFsync = 'FAILED'
        }
      }
      parentFsync = 'SYNCED'
      try {
        dependencies.syncDirectory(
          parentDescriptor, 'PARENT_FAILURE_PRESERVE')
      } catch {
        parentFsync = 'FAILED'
      }
    }
    if (state.directoryCreated) {
      const fileFsync = state.residueFileFsyncAttempted
        ? (state.residueFileFsyncFailed ? 'FAILED' : 'SYNCED')
        : 'NOT_APPLICABLE'
      const targetTopologyExact = state.directoryDescriptor != null &&
        failureTargetTopologyIsExact(state)
      if (state.directoryDescriptor != null) {
        try { closeSync(state.directoryDescriptor) } catch {}
        state.directoryDescriptor = null
      }
      throw partialFailure(failed, Object.freeze({
        fileFsync,
        fileClose: state.residueFileCloseAttempted
          ? (state.residueFileCloseFailed ? 'FAILED' : 'CLOSED')
          : 'NOT_APPLICABLE',
        targetFsync,
        parentFsync
      }), targetTopologyExact)
    }
    throw failed
  } finally {
    for (const key of keys) key.fill(0)
    if (state.directoryDescriptor != null) {
      try { closeSync(state.directoryDescriptor) } catch {}
    }
    try { closeSync(parentDescriptor) } catch {}
  }
}

export function provisionPeeritSeq29LocalCustodianKeysV1 (input = {}) {
  return provision(input, {
    fillRandom (output) { randomFillSync(output) },
    write: writeSync,
    syncFile: fsyncSync,
    syncDirectory: fsyncSync,
    closeFile: closeSync,
    onStage: null
  })
}

// Fixture-only surface for deterministic entropy, short/failed writes and
// process-death simulation. Production callers and the CLI cannot select it.
export function provisionPeeritSeq29LocalCustodianKeysFixtureV1 (
  input = {}, fixture = {}
) {
  if (process.env[FIXTURE_ENV] !== '1') {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_DISABLED',
      'custodian provisioning fixtures are disabled outside explicit tests')
  }
  exactWithOptional(fixture, ['fillRandom'], [
    'closeFile', 'onStage', 'syncDirectory', 'syncFile', 'write'
  ], 'custodian provisioning fixture')
  if (typeof fixture.fillRandom !== 'function' ||
      (fixture.write != null && typeof fixture.write !== 'function') ||
      (fixture.closeFile != null && typeof fixture.closeFile !== 'function') ||
      (fixture.syncFile != null && typeof fixture.syncFile !== 'function') ||
      (fixture.syncDirectory != null &&
        typeof fixture.syncDirectory !== 'function') ||
      (fixture.onStage != null && typeof fixture.onStage !== 'function')) {
    fail('PEERIT_SEQ29_CUSTODIAN_PROVISION_INVALID',
      'custodian provisioning fixture functions are invalid')
  }
  return provision(input, {
    fillRandom: fixture.fillRandom,
    write: fixture.write || writeSync,
    syncFile: fixture.syncFile || fsyncSync,
    syncDirectory: fixture.syncDirectory || fsyncSync,
    closeFile: fixture.closeFile || closeSync,
    onStage: fixture.onStage || null
  })
}
