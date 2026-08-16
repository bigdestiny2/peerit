// Node-only authenticated loader for the complete HiveRelay execution closure
// used by Seq29 qualification and the two CREATE ceremony. Both artifacts are
// captured as immutable bytes, authenticated, and then imported from those
// same bytes. No checkout, Git command, package resolver or native addon is in
// the production authority path.

import { createHash } from 'node:crypto'
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1 =
  'adeacef07c5de4d17d5ed1389fee7a35095b862f'
export const PEERIT_SEQ29_ACCEPTED_HIVERELAY_TREE_V1 =
  '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const CONTROL_DIRECTORY = resolve(ROOT, 'vendor/hiverelay-blind-client-v1')
const OPERATOR_DIRECTORY = resolve(
  ROOT, 'scripts/vendor/hiverelay-seq29-inbox-operator-v1')
const CONTROL_FILES = Object.freeze([
  'authority.json',
  'blind-client-control-v1.chromium-evidence.json',
  'blind-client-control-v1.cross-host-evidence.json',
  'blind-client-control-v1.manifest.cenc',
  'blind-client-control-v1.mjs'
])
const OPERATOR_FILES = Object.freeze([
  'authority.json',
  'seq29-inbox-operator-v1.mjs'
])
const CONTROL_ARTIFACT_SHA256 =
  '88e51864c4a21296e64864523a7d602a1df6e24beed7dbbed45690c05eb1902f'
const CONTROL_AUTHORITY_SHA256 =
  '85909a01ac34e5fc374a81a7bc9a95c8b36f96665b6d04e0bf67d6c437017260'
const OPERATOR_ARTIFACT_SHA256 =
  '141e2aadf686fb80cf43d65fd7451f673841f62586e3ffebb75bf7a03ea4a2cb'
const OPERATOR_AUTHORITY_SHA256 =
  '432fb47f55796384ced05fefbca89e18bd55ce9a74ae52d6d60200a15e0ad000'
const CONTROL_ARTIFACT_LENGTH = 234813
const OPERATOR_ARTIFACT_LENGTH = 163445
const OPERATOR_EXPORTS = Object.freeze([
  'createInboxReplica',
  'destroyInboxWriteCapability'
])

let acceptedPromise = null

function fail (message, cause) {
  const error = new Error(message)
  error.code = 'PEERIT_SEQ29_ACCEPTED_HIVERELAY_OPERATOR_INVALID'
  if (cause !== undefined) error.cause = cause
  throw error
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function metadataIdentity (value) {
  return [
    value.dev, value.ino, value.mode, value.nlink, value.uid, value.size,
    value.mtimeNs, value.ctimeNs
  ].join(':')
}

function exactDirectory (directory, names) {
  let canonical
  let metadata
  try {
    canonical = realpathSync(directory)
    metadata = lstatSync(directory, { bigint: true })
  } catch (cause) {
    fail('accepted HiveRelay artifact directory is unavailable', cause)
  }
  if (canonical !== directory || metadata.isSymbolicLink() ||
      !metadata.isDirectory() || readdirSync(directory).sort().join('\0') !==
        [...names].sort().join('\0')) {
    fail('accepted HiveRelay artifact directory membership or identity changed')
  }
  return metadataIdentity(metadata)
}

function exactRead (directory, directoryIdentity, name, length, digest) {
  if (metadataIdentity(lstatSync(directory, { bigint: true })) !== directoryIdentity) {
    fail('accepted HiveRelay artifact directory changed during authentication')
  }
  const path = join(directory, name)
  const before = lstatSync(path, { bigint: true })
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
      before.size !== BigInt(length) || (before.mode & 0o777n) !== 0o644n ||
      typeof constants.O_NOFOLLOW !== 'number') {
    fail('accepted HiveRelay artifact is not a single-link mode-0644 regular file')
  }
  const output = new Uint8Array(length)
  let descriptor
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    if (metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
        metadataIdentity(before)) {
      fail('accepted HiveRelay artifact changed before its exact read')
    }
    let offset = 0
    while (offset < output.byteLength) {
      const count = readSync(descriptor, output, offset, output.byteLength - offset, offset)
      if (count === 0) break
      offset += count
    }
    const extra = Buffer.alloc(1)
    if (offset !== output.byteLength ||
        readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
          metadataIdentity(before) ||
        metadataIdentity(lstatSync(path, { bigint: true })) !==
          metadataIdentity(before) || sha256(output) !== digest) {
      fail('accepted HiveRelay artifact changed during its exact read')
    }
  } catch (cause) {
    if (cause?.code === 'PEERIT_SEQ29_ACCEPTED_HIVERELAY_OPERATOR_INVALID') throw cause
    fail('accepted HiveRelay artifact could not be read exactly', cause)
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
  return output
}

function canonicalAuthority (bytes, expected) {
  let source
  let value
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    value = JSON.parse(source)
  } catch (cause) {
    fail('accepted HiveRelay authority is not canonical JSON', cause)
  }
  if (JSON.stringify(value, null, 2) + '\n' !== source ||
      value.schema !== expected.schema || value.version !== expected.version ||
      value.candidateCommit !== PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1 ||
      value.candidateTree !== PEERIT_SEQ29_ACCEPTED_HIVERELAY_TREE_V1 ||
      value.artifactLength !== expected.artifactLength ||
      value.artifactRawSha256 !== expected.artifactSha256 ||
      !Array.isArray(value.exactSortedExports) ||
      value.exactSortedExports.join('\0') !== expected.exports.join('\0')) {
    fail('accepted HiveRelay authority identity changed')
  }
  return Object.freeze(value)
}

function dataModuleUrl (value) {
  return `data:text/javascript;base64,${Buffer.from(value).toString('base64')}`
}

async function loadAccepted () {
  const controlDirectoryIdentity = exactDirectory(CONTROL_DIRECTORY, CONTROL_FILES)
  const operatorDirectoryIdentity = exactDirectory(OPERATOR_DIRECTORY, OPERATOR_FILES)
  const controlBytes = exactRead(
    CONTROL_DIRECTORY, controlDirectoryIdentity, 'blind-client-control-v1.mjs',
    CONTROL_ARTIFACT_LENGTH, CONTROL_ARTIFACT_SHA256)
  const controlAuthorityBytes = exactRead(
    CONTROL_DIRECTORY, controlDirectoryIdentity, 'authority.json', 4846,
    CONTROL_AUTHORITY_SHA256)
  const operatorBytes = exactRead(
    OPERATOR_DIRECTORY, operatorDirectoryIdentity, 'seq29-inbox-operator-v1.mjs',
    OPERATOR_ARTIFACT_LENGTH, OPERATOR_ARTIFACT_SHA256)
  const operatorAuthorityBytes = exactRead(
    OPERATOR_DIRECTORY, operatorDirectoryIdentity, 'authority.json', 11255,
    OPERATOR_AUTHORITY_SHA256)
  const controlAuthority = canonicalAuthority(controlAuthorityBytes, {
    schema: 'PeeritVendoredHiveRelayBlindClientV2',
    version: 2,
    artifactLength: CONTROL_ARTIFACT_LENGTH,
    artifactSha256: CONTROL_ARTIFACT_SHA256,
    exports: JSON.parse(new TextDecoder().decode(controlAuthorityBytes)).exactSortedExports
  })
  const operatorAuthority = canonicalAuthority(operatorAuthorityBytes, {
    schema: 'PeeritVendoredHiveRelaySeq29InboxOperatorV1',
    version: 1,
    artifactLength: OPERATOR_ARTIFACT_LENGTH,
    artifactSha256: OPERATOR_ARTIFACT_SHA256,
    exports: OPERATOR_EXPORTS
  })
  const [control, inbox] = await Promise.all([
    import(dataModuleUrl(controlBytes)),
    import(dataModuleUrl(operatorBytes))
  ])
  if (Object.keys(control).sort().join('\0') !==
        [...controlAuthority.exactSortedExports].sort().join('\0') ||
      Object.keys(inbox).sort().join('\0') !== OPERATOR_EXPORTS.join('\0') ||
      typeof control.createBrowserCryptoRuntime !== 'function' ||
      typeof control.BlindDirectHttpClient !== 'function' ||
      OPERATOR_EXPORTS.some(name => typeof inbox[name] !== 'function') ||
      exactDirectory(CONTROL_DIRECTORY, CONTROL_FILES) !== controlDirectoryIdentity ||
      exactDirectory(OPERATOR_DIRECTORY, OPERATOR_FILES) !== operatorDirectoryIdentity) {
    fail('accepted HiveRelay artifact changed during authenticated import')
  }
  return Object.freeze({
    control,
    inbox,
    controlAuthority,
    operatorAuthority,
    identity: Object.freeze({
      candidateCommit: PEERIT_SEQ29_ACCEPTED_HIVERELAY_COMMIT_V1,
      candidateTree: PEERIT_SEQ29_ACCEPTED_HIVERELAY_TREE_V1,
      controlArtifactSha256: CONTROL_ARTIFACT_SHA256,
      inboxOperatorArtifactSha256: OPERATOR_ARTIFACT_SHA256
    })
  })
}

export async function loadPeeritSeq29AcceptedHiveRelayOperatorV1 () {
  if (acceptedPromise == null) acceptedPromise = loadAccepted()
  try {
    return await acceptedPromise
  } catch (cause) {
    acceptedPromise = null
    throw cause
  }
}
