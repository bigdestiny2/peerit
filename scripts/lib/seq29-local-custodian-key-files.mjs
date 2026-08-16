// Fail-closed local configuration for the three Seq29 X25519 custodians.
// Files are raw 32-byte private keys. No key bytes or paths are logged or
// returned by the public composition result.

import {
  constants,
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  statSync
} from 'node:fs'
import { createPrivateKey, createPublicKey } from 'node:crypto'
import { join, parse, relative, resolve, sep } from 'node:path'

const KEY_FILES = Object.freeze([
  'custodian-1.x25519',
  'custodian-2.x25519',
  'custodian-3.x25519'
])

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function currentUid () {
  return typeof process.getuid === 'function' ? process.getuid() : null
}

function metadataIdentity (value) {
  return [
    value.dev, value.ino, value.mode, value.nlink, value.uid, value.size,
    value.mtimeNs, value.ctimeNs
  ].join(':')
}

function assertOwned (metadata, field) {
  const uid = currentUid()
  if (uid != null && metadata.uid !== BigInt(uid)) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
      `${field} is not owned by the current operator identity`)
  }
}

function assertRealParents (value) {
  const absolute = resolve(value)
  const root = parse(absolute).root
  let cursor = root
  for (const component of relative(root, absolute).split(sep).filter(Boolean)) {
    cursor = join(cursor, component)
    const metadata = lstatSync(cursor, { bigint: true })
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
        'custodian key directory path contains a symlink or non-directory')
    }
  }
}

function assertDirectory (directory) {
  assertRealParents(directory)
  let canonical
  try { canonical = realpathSync(directory) } catch {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_INVALID',
      'custodian key directory does not resolve')
  }
  if (canonical !== directory) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
      'custodian key directory must be an absolute real path')
  }
  const metadata = statSync(directory, { bigint: true })
  assertOwned(metadata, 'custodian key directory')
  if (!metadata.isDirectory() || (metadata.mode & 0o777n) !== 0o700n) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
      'custodian key directory must have exact mode 0700')
  }
  const names = readdirSync(directory).sort()
  if (names.join('\0') !== [...KEY_FILES].sort().join('\0')) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_INVALID',
      'custodian key directory must contain exactly three fixed key files')
  }
  return metadataIdentity(metadata)
}

function readPrivateKey (directory, directoryIdentity, name) {
  if (metadataIdentity(statSync(directory, { bigint: true })) !== directoryIdentity) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
      'custodian key directory identity changed')
  }
  const path = join(directory, name)
  const before = lstatSync(path, { bigint: true })
  assertOwned(before, 'custodian private key')
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
      before.size !== 32n || (before.mode & 0o777n) !== 0o600n ||
      typeof constants.O_NOFOLLOW !== 'number') {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
      'each custodian private key must be a single-link 32-byte mode-0600 file')
  }
  let descriptor
  const output = new Uint8Array(32)
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    const opened = fstatSync(descriptor, { bigint: true })
    if (metadataIdentity(opened) !== metadataIdentity(before)) {
      fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
        'custodian private key changed before open')
    }
    let offset = 0
    while (offset < output.byteLength) {
      const count = readSync(descriptor, output, offset, output.byteLength - offset, offset)
      if (count === 0) break
      offset += count
    }
    const extra = Buffer.alloc(1)
    if (offset !== output.byteLength || readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
          metadataIdentity(before) ||
        metadataIdentity(lstatSync(path, { bigint: true })) !==
          metadataIdentity(before)) {
      fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
        'custodian private key changed during its exact read')
    }
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
  if (output.every(byte => byte === 0)) {
    output.fill(0)
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_INVALID',
      'custodian private keys must be nonzero')
  }
  return output
}

function publicKeyForPrivate (value) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(value)
    ]),
    format: 'der',
    type: 'pkcs8'
  })
  return new Uint8Array(createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' }).subarray(-32))
}

export function createPeeritSeq29LocalCustodianKeyFileConfigurationV1 (
  input = {}
) {
  exact(input, ['directory'], 'custodian key-file configuration input')
  if (typeof input.directory !== 'string' || input.directory !== resolve(input.directory)) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_INVALID',
      'custodian key directory must be an absolute path')
  }
  const directory = input.directory
  const directoryIdentity = assertDirectory(directory)
  function readAll () {
    if (assertDirectory(directory) !== directoryIdentity) {
      fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_PERMISSIONS',
        'custodian key directory changed after configuration')
    }
    const keys = []
    try {
      for (const name of KEY_FILES) {
        keys.push(readPrivateKey(directory, directoryIdentity, name))
      }
    } catch (cause) {
      for (const key of keys) key.fill(0)
      throw cause
    }
    if (new Set(keys.map(value => Buffer.from(value).toString('hex'))).size !== 3) {
      for (const key of keys) key.fill(0)
      fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_INVALID',
        'custodian private keys must be distinct')
    }
    return keys
  }
  const initial = readAll()
  let custodianPublicKeys
  try {
    custodianPublicKeys = initial.map(publicKeyForPrivate)
  } finally {
    for (const key of initial) key.fill(0)
  }
  if (new Set(custodianPublicKeys.map(value =>
    Buffer.from(value).toString('hex'))).size !== 3) {
    fail('PEERIT_SEQ29_CUSTODIAN_KEY_CONFIG_INVALID',
      'custodian public keys must be distinct')
  }
  return Object.freeze({
    custodianPublicKeys: Object.freeze(custodianPublicKeys),
    async custodianPrivateKeyProvider () {
      // The accepted custody adapter snapshots and wipes these fresh copies.
      return readAll()
    }
  })
}
