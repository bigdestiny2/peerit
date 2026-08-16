import {
  createHash,
  createPublicKey,
  verify as nodeVerify
} from 'node:crypto'
import {
  closeSync,
  constants,
  fchmodSync,
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
import { dirname, join, posix, relative, resolve, sep } from 'node:path'
import {
  RELEASE_ALG,
  RELEASE_MSG_VERSION,
  releaseSequenceOf,
  releaseSigningMessage
} from '../../js/release-verify.js'

const PLAN_SCHEMA = 'peerit-seq29-initial-web-prepare-plan-v1'
const RECEIPT_SCHEMA = 'peerit-seq29-initial-web-prepare-receipt-v1'
const STATUS_SCHEMA = 'peerit-seq29-initial-web-prepare-status-v1'
const JOURNAL = '.deploy/seq29-initial-web-prepare-v1'
const MAX_SOURCE_BYTES = 16 * 1024 * 1024
const MAX_PLAN_BYTES = 64 * 1024 * 1024
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const SPKI_PREFIX = '302a300506032b6570032100'
const TEMP_PATTERN = /^\.(?:pending|committed)-[0-9a-f]{24}\.tmp$/

const BEFORE_FILES = Object.freeze({
  releaseConfig: Object.freeze(['deploy/web-release.json', 0o644]),
  appArtifact: Object.freeze(['web/peerit-app-artifact-v1.json', 0o644]),
  canonicalManifest: Object.freeze(['web/peerit-web-assets-v1.cenc', 0o644]),
  outerManifest: Object.freeze(['web/asset-manifest.json', 0o644]),
  signingRequest: Object.freeze(['deploy/web-signing-request.json', 0o644]),
  outerSignature: Object.freeze(['web/asset-manifest.sig', 0o644])
})

const TARGET_FILES = Object.freeze({
  appArtifact: Object.freeze(['web/peerit-app-artifact-v1.json', 0o644]),
  canonicalManifest: Object.freeze(['web/peerit-web-assets-v1.cenc', 0o644]),
  outerManifest: Object.freeze(['web/asset-manifest.json', 0o644]),
  signingRequest: Object.freeze(['deploy/web-signing-request.json', 0o644])
})

const DIRECTORY_IDENTITIES = new Map()

function beginAuthenticatedOperation () {
  DIRECTORY_IDENTITIES.clear()
}

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
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

function jsonBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function recordHash (value) {
  return sha256(canonical(value))
}

function fullMode (metadata) {
  return metadata.mode & 0o7777n
}

function assertOwned (metadata, field) {
  if (typeof process.getuid === 'function' &&
      metadata.uid !== BigInt(process.getuid())) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      `${field} is not owned by the current operator`)
  }
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

function sameDirectoryIdentity (left, right) {
  return left.isDirectory() && right.isDirectory() &&
    !left.isSymbolicLink() && !right.isSymbolicLink() &&
    left.dev === right.dev && left.ino === right.ino &&
    left.uid === right.uid && left.gid === right.gid &&
    left.mode === right.mode
}

function directoryIdentity (metadata) {
  return Object.freeze({
    dev: String(metadata.dev),
    ino: String(metadata.ino),
    uid: String(metadata.uid),
    gid: String(metadata.gid),
    mode: String(metadata.mode)
  })
}

function authenticateDirectory (path, { synchronize = false } = {}) {
  let named
  try { named = lstatSync(path, { bigint: true }) } catch {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_IO_FAILED',
      'web-prepare directory could not be inspected')
  }
  if (!named.isDirectory() || named.isSymbolicLink()) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      'web-prepare directory is not real')
  }
  assertOwned(named, 'web-prepare directory')
  const key = resolve(path)
  const known = DIRECTORY_IDENTITIES.get(key)
  if (known && (known.dev !== String(named.dev) ||
      known.ino !== String(named.ino) || known.uid !== String(named.uid) ||
      known.gid !== String(named.gid) || known.mode !== String(named.mode))) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      'web-prepare directory changed authenticated identity')
  }
  let descriptor
  let primary
  try {
    descriptor = openSync(path, constants.O_RDONLY |
      (constants.O_DIRECTORY || 0) | (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor, { bigint: true })
    if (!sameDirectoryIdentity(named, opened)) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
        'web-prepare directory changed before authenticated open')
    }
    if (synchronize) fsyncSync(descriptor)
    const after = fstatSync(descriptor, { bigint: true })
    const namedAfter = lstatSync(path, { bigint: true })
    if (!sameDirectoryIdentity(opened, after) ||
        !sameDirectoryIdentity(opened, namedAfter)) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
        'web-prepare directory changed during authenticated access')
    }
    DIRECTORY_IDENTITIES.set(key, directoryIdentity(namedAfter))
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try { closeSync(descriptor) } catch {
      if (!primary) primary = new Error('directory close uncertainty')
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_')) throw primary
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_IO_FAILED',
      'web-prepare directory could not be durably authenticated')
  }
  return named
}

function fsyncDirectory (path) {
  authenticateDirectory(path, { synchronize: true })
}

function entryExists (path) {
  try {
    lstatSync(path)
    return true
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_IO_FAILED',
      'web-prepare path could not be inspected')
  }
}

function assertTrustedParents (root, path) {
  const rootPath = resolve(root)
  const parent = dirname(resolve(path))
  const suffix = relative(rootPath, parent)
  if (suffix === '..' || suffix.startsWith(`..${sep}`)) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      'web-prepare path escapes the repository root')
  }
  let cursor = rootPath
  for (const part of ['', ...(suffix === '' ? [] : suffix.split(sep))]) {
    if (part !== '') cursor = join(cursor, part)
    const metadata = authenticateDirectory(cursor)
    if ((fullMode(metadata) & 0o7022n) !== 0n) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
        'web-prepare parent is not owner-only-write')
    }
  }
}

function inspectFile (root, path, expectedMode, maximum = MAX_SOURCE_BYTES) {
  assertTrustedParents(root, path)
  let named
  try { named = lstatSync(path, { bigint: true }) } catch {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_MISSING',
      'web-prepare file is missing')
  }
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n ||
      fullMode(named) !== BigInt(expectedMode) || named.size < 1n ||
      named.size > BigInt(maximum)) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      'web-prepare file is not an exact regular file')
  }
  assertOwned(named, 'web-prepare file')
  let descriptor
  let content
  let primary
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor, { bigint: true })
    if (!sameFileIdentity(named, opened)) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
        'web-prepare file changed before authenticated read')
    }
    content = readFileSync(descriptor)
    const after = fstatSync(descriptor, { bigint: true })
    const namedAfter = lstatSync(path, { bigint: true })
    if (BigInt(content.byteLength) !== opened.size ||
        !sameFileIdentity(opened, after) ||
        !sameFileIdentity(opened, namedAfter)) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
        'web-prepare file changed during authenticated read')
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
    if (String(primary.code || '').startsWith('PEERIT_')) throw primary
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_IO_FAILED',
      'web-prepare file could not be authenticated')
  }
  return Object.freeze({
    bytes: Buffer.from(content),
    sha256: sha256(content),
    dev: String(named.dev),
    ino: String(named.ino),
    uid: String(named.uid),
    gid: String(named.gid),
    size: String(named.size),
    mode: Number(fullMode(named)),
    mtimeNs: String(named.mtimeNs),
    ctimeNs: String(named.ctimeNs)
  })
}

function snapshotRecord (value, relativePath) {
  return Object.freeze({
    relativePath,
    sha256: value.sha256,
    dev: value.dev,
    ino: value.ino,
    uid: value.uid,
    gid: value.gid,
    size: value.size,
    mode: value.mode,
    mtimeNs: value.mtimeNs,
    ctimeNs: value.ctimeNs,
    base64: value.bytes.toString('base64')
  })
}

function validateSnapshot (value, relativePath, mode, field) {
  exact(value, [
    'relativePath', 'sha256', 'dev', 'ino', 'uid', 'gid', 'size', 'mode',
    'mtimeNs', 'ctimeNs', 'base64'
  ], field)
  let content
  try { content = Buffer.from(value.base64, 'base64') } catch {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      `${field} preservation encoding is invalid`)
  }
  if (value.relativePath !== relativePath || value.mode !== mode ||
      !HEX64.test(value.sha256) || sha256(content) !== value.sha256 ||
      content.toString('base64') !== value.base64 ||
      String(content.byteLength) !== value.size ||
      !/^[0-9]+$/.test(value.dev) || !/^[0-9]+$/.test(value.ino) ||
      !/^[0-9]+$/.test(value.uid) || !/^[0-9]+$/.test(value.gid) ||
      !/^[0-9]+$/.test(value.mtimeNs) || !/^[0-9]+$/.test(value.ctimeNs)) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      `${field} preservation identity is invalid`)
  }
  return Object.freeze({ ...value, bytes: content })
}

function sameSnapshot (expected, current) {
  return [
    'sha256', 'dev', 'ino', 'uid', 'gid', 'size', 'mode', 'mtimeNs', 'ctimeNs'
  ].every(field => expected[field] === current[field])
}

function assertSnapshotCurrent (root, snapshot, field) {
  const current = inspectFile(root, join(root, snapshot.relativePath), snapshot.mode)
  if (!sameSnapshot(snapshot, current) || !snapshot.bytes.equals(current.bytes)) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PREIMAGE_DRIFT',
      `${field} differs from its preserved predecessor`)
  }
  return current
}

function parseCanonicalJson (content, field) {
  let value
  try { value = JSON.parse(Buffer.from(content).toString('utf8')) } catch {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT', `${field} is not JSON`)
  }
  if (!jsonBytes(value).equals(Buffer.from(content))) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      `${field} is not canonical pretty JSON`)
  }
  return value
}

function safeManifestPath (file) {
  if (typeof file !== 'string' || !file || file.length > 240 ||
      !/^[A-Za-z0-9._/-]+$/.test(file) || file.startsWith('/') ||
      file.includes('\\') || file.includes('//')) return false
  const segments = file.split('/')
  return !segments.some(segment => !segment || segment === '.' || segment === '..') &&
    posix.normalize(file) === file
}

function listWebFiles (root, directory = join(root, 'web'), prefix = '') {
  assertTrustedParents(root, join(directory, 'entry'))
  const names = readdirSync(directory, { withFileTypes: true })
  const files = []
  for (const entry of names) {
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name
    if (!safeManifestPath(relativePath) || entry.isSymbolicLink()) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
        'web artifact contains an unsafe path')
    }
    const path = join(directory, entry.name)
    if (entry.isDirectory()) {
      const metadata = authenticateDirectory(path)
      if ((fullMode(metadata) & 0o7022n) !== 0n) {
        fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
          'web artifact directory is not owner-only-write')
      }
      files.push(...listWebFiles(root, path, relativePath))
    } else if (entry.isFile()) {
      inspectFile(root, path, 0o644)
      files.push(relativePath)
    } else {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
        'web artifact contains a non-regular entry')
    }
  }
  return files.sort()
}

function validateArtifactFiles (root, request, signatureRequired) {
  if (!request.artifactFiles || typeof request.artifactFiles !== 'object' ||
      Array.isArray(request.artifactFiles) ||
      Object.keys(request.artifactFiles).length < 1) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      'web signing request artifact inventory is invalid')
  }
  const expectedNames = Object.keys(request.artifactFiles).sort()
  if (expectedNames.some(name => !safeManifestPath(name)) ||
      new Set(expectedNames.map(name => name.toLowerCase())).size !==
        expectedNames.length) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      'web signing request artifact inventory is unsafe')
  }
  const actualNames = listWebFiles(root)
  const expectedActual = signatureRequired
    ? [...expectedNames, 'asset-manifest.sig'].sort()
    : expectedNames
  if (actualNames.join('\0') !== expectedActual.join('\0')) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_TARGET_INCOMPLETE',
      'web artifact inventory is incomplete or contains extras')
  }
  for (const name of expectedNames) {
    if (!HEX64.test(request.artifactFiles[name]) ||
        inspectFile(root, join(root, 'web', ...name.split('/')), 0o644).sha256 !==
          request.artifactFiles[name]) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_TARGET_INVALID',
        'web artifact differs from its signing-request inventory')
    }
  }
}

function verifyReleaseSignature (manifest, signature, pinned) {
  if (signature.alg !== RELEASE_ALG || signature.msgVersion !== RELEASE_MSG_VERSION ||
      signature.key !== pinned || !HEX128.test(String(signature.sig || ''))) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PREDECESSOR_INVALID',
      'predecessor release signature envelope is invalid')
  }
  let valid = false
  try {
    valid = nodeVerify(null, Buffer.from(releaseSigningMessage(manifest)),
      createPublicKey({
        key: Buffer.from(SPKI_PREFIX + pinned, 'hex'),
        format: 'der',
        type: 'spki'
      }), Buffer.from(signature.sig, 'hex'))
  } catch {}
  if (!valid) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PREDECESSOR_INVALID',
      'predecessor release signature does not verify')
  }
}

function validatePredecessor (root, files, { verifyTree = true } = {}) {
  const config = parseCanonicalJson(files.releaseConfig.bytes, 'release config')
  const manifest = parseCanonicalJson(files.outerManifest.bytes,
    'predecessor outer manifest')
  const request = parseCanonicalJson(files.signingRequest.bytes,
    'predecessor signing request')
  const signature = parseCanonicalJson(files.outerSignature.bytes,
    'predecessor outer signature')
  let sequence
  try { sequence = releaseSequenceOf(manifest) } catch {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PREDECESSOR_INVALID',
      'predecessor release sequence is invalid')
  }
  const pinned = String(config.pinnedReleaseKey || '').toLowerCase()
  const manifestSha256 = sha256(files.outerManifest.bytes)
  if (config.releaseSequence !== 29 || sequence !== 28 || !HEX64.test(pinned) ||
      request.schema !== 'peerit-web-signing-request-v2' ||
      request.manifest !== 'web/asset-manifest.json' ||
      request.signature !== 'web/asset-manifest.sig' ||
      request.releaseSequence !== 28 || request.driveKey !== manifest.driveKey ||
      request.pinnedReleaseKey !== pinned || request.manifestSha256 !== manifestSha256 ||
      request.signingMessageSha256 !==
        sha256(Buffer.from(releaseSigningMessage(manifest))) ||
      request.artifactFiles?.['asset-manifest.json'] !== manifestSha256 ||
      request.artifactFiles?.['peerit-app-artifact-v1.json'] !==
        files.appArtifact.sha256 ||
      request.artifactFiles?.['peerit-web-assets-v1.cenc'] !==
        files.canonicalManifest.sha256) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PREDECESSOR_INVALID',
      'signed predecessor files do not bind one exact Sequence-28 artifact')
  }
  if (verifyTree) validateArtifactFiles(root, request, true)
  verifyReleaseSignature(manifest, signature, pinned)
  return Object.freeze({ request })
}

function validateTarget (root) {
  const signaturePath = join(root, 'web/asset-manifest.sig')
  if (entryExists(signaturePath)) return null
  const manifestPath = join(root, 'web/asset-manifest.json')
  const requestPath = join(root, 'deploy/web-signing-request.json')
  if (!entryExists(manifestPath) || !entryExists(requestPath)) return null
  const manifestFile = inspectFile(root, manifestPath, 0o644)
  const requestFile = inspectFile(root, requestPath, 0o644)
  const manifest = parseCanonicalJson(manifestFile.bytes, 'prepared outer manifest')
  const request = parseCanonicalJson(requestFile.bytes, 'prepared signing request')
  if (manifest.releaseSequence !== 29 || request.releaseSequence !== 29) return null
  let sequence
  try { sequence = releaseSequenceOf(manifest) } catch {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_TARGET_INVALID',
      'prepared release sequence is invalid')
  }
  const config = parseCanonicalJson(inspectFile(root,
    join(root, 'deploy/web-release.json'), 0o644).bytes, 'release config')
  const pinned = String(config.pinnedReleaseKey || '').toLowerCase()
  const manifestSha256 = sha256(manifestFile.bytes)
  if (sequence !== 29 || config.releaseSequence !== 29 || !HEX64.test(pinned) ||
      request.schema !== 'peerit-web-signing-request-v2' ||
      request.manifest !== 'web/asset-manifest.json' ||
      request.signature !== 'web/asset-manifest.sig' ||
      request.driveKey !== manifest.driveKey || request.pinnedReleaseKey !== pinned ||
      manifest.webRelease?.releaseSequence !== 29 ||
      manifest.webRelease?.releaseKey !== pinned ||
      request.manifestSha256 !== manifestSha256 ||
      request.signingMessageSha256 !==
        sha256(Buffer.from(releaseSigningMessage(manifest))) ||
      request.artifactFiles?.['asset-manifest.json'] !== manifestSha256) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_TARGET_INVALID',
      'prepared files do not bind one exact unsigned Sequence-29 artifact')
  }
  validateArtifactFiles(root, request, false)
  const files = Object.freeze(Object.fromEntries(Object.entries(TARGET_FILES).map(
    ([field, [relativePath, mode]]) =>
      [field, inspectFile(root, join(root, relativePath), mode)])))
  return Object.freeze({ files, request })
}

function atomicFile (root, directory, name, content, mode, prefix) {
  const token = createHash('sha256').update(Buffer.concat([
    Buffer.from(content), Buffer.from(String(process.pid)),
    Buffer.from(String(process.hrtime.bigint()))
  ])).digest('hex').slice(0, 24)
  const temporary = join(directory, `.${prefix}-${token}.tmp`)
  const target = join(directory, name)
  let descriptor
  let primary
  let linked = false
  try {
    descriptor = openSync(temporary, 'wx', 0o600)
    fchmodSync(descriptor, mode)
    const opened = fstatSync(descriptor, { bigint: true })
    if (!opened.isFile() || opened.nlink !== 1n ||
        fullMode(opened) !== BigInt(mode)) {
      fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
        'new web-prepare journal file is not exact')
    }
    writeFileSync(descriptor, content)
    fsyncSync(descriptor)
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try { closeSync(descriptor) } catch {
      if (!primary) primary = new Error('journal close uncertainty')
    }
  }
  if (!primary) {
    try {
      linkSync(temporary, target)
      linked = true
      if (process.env.PEERIT_SEQ29_INITIAL_WEB_PREPARE_TEST_FAULT ===
          'POST_LINK_SYNC_UNCERTAIN') {
        throw new Error('injected post-link synchronization uncertainty')
      }
      fsyncDirectory(directory)
      unlinkSync(temporary)
      fsyncDirectory(directory)
    } catch (cause) {
      primary = cause
    }
  }
  if (primary) {
    if (!linked) {
      try { unlinkSync(temporary) } catch {}
    }
    if (String(primary.code || '').startsWith('PEERIT_')) throw primary
    fail(primary.code === 'EEXIST'
      ? 'PEERIT_SEQ29_INITIAL_WEB_PREPARE_CONFLICT'
      : 'PEERIT_SEQ29_INITIAL_WEB_PREPARE_IO_FAILED',
    'web-prepare journal file could not be sealed')
  }
  return inspectFile(root, target, mode, MAX_PLAN_BYTES)
}

function normalizeAlias (root, directory, name, prefix, mode) {
  const target = join(directory, name)
  if (!entryExists(target)) return
  const named = lstatSync(target, { bigint: true })
  for (const candidate of readdirSync(directory)) {
    if (!candidate.startsWith(`.${prefix}-`) || !candidate.endsWith('.tmp')) continue
    const path = join(directory, candidate)
    let metadata
    try { metadata = lstatSync(path, { bigint: true }) } catch { continue }
    if (metadata.isFile() && !metadata.isSymbolicLink() &&
        metadata.dev === named.dev && metadata.ino === named.ino) unlinkSync(path)
  }
  fsyncDirectory(directory)
  inspectFile(root, target, mode, MAX_PLAN_BYTES)
}

function ensureJournal (root) {
  const deploy = join(root, '.deploy')
  const rootMetadata = authenticateDirectory(root)
  if ((fullMode(rootMetadata) & 0o7022n) !== 0n) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      'repository root is not owner-only-write')
  }
  if (!entryExists(deploy)) {
    mkdirSync(deploy, { mode: 0o700 })
    fsyncDirectory(root)
  }
  assertTrustedParents(root, join(deploy, 'entry'))
  const deployMetadata = authenticateDirectory(deploy)
  if ((fullMode(deployMetadata) & 0o7022n) !== 0n) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      'outer deployment directory is not owner-only-write')
  }
  const journal = join(root, JOURNAL)
  if (!entryExists(journal)) {
    mkdirSync(journal, { mode: 0o700 })
    fsyncDirectory(deploy)
  }
  const metadata = authenticateDirectory(journal)
  if (fullMode(metadata) !== 0o700n) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS',
      'web-prepare journal must retain exact mode 0700')
  }
  const names = readdirSync(journal).sort()
  if (names.some(name =>
    !['pending.json', 'committed.json'].includes(name) &&
      !TEMP_PATTERN.test(name)) ||
      (names.includes('committed.json') && !names.includes('pending.json'))) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      'web-prepare journal contains unexpected or incomplete state')
  }
  return Object.freeze({ journal, names })
}

function validatePlan (value) {
  exact(value, ['schema', 'version', 'state', 'files', 'planHash'],
    'initial web-prepare plan')
  exact(value.files, Object.keys(BEFORE_FILES), 'preserved predecessor files')
  const files = Object.freeze(Object.fromEntries(Object.entries(BEFORE_FILES).map(
    ([field, [relativePath, mode]]) =>
      [field, validateSnapshot(value.files[field], relativePath, mode, field)])))
  const unsigned = { ...value }
  delete unsigned.planHash
  if (value.schema !== PLAN_SCHEMA || value.version !== 1 ||
      value.state !== 'PENDING' || !HEX64.test(value.planHash) ||
      recordHash(unsigned) !== value.planHash) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      'initial web-prepare plan identity is invalid')
  }
  validatePredecessor(null, files, { verifyTree: false })
  return Object.freeze({ value: Object.freeze(value), files })
}

function readPlan (root, journal) {
  normalizeAlias(root, journal, 'pending.json', 'pending', 0o600)
  const inspected = inspectFile(root, join(journal, 'pending.json'), 0o600,
    MAX_PLAN_BYTES)
  return validatePlan(parseCanonicalJson(inspected.bytes,
    'initial web-prepare plan'))
}

function validateReceipt (value, plan, target) {
  exact(value, [
    'schema', 'version', 'state', 'planHash', 'artifacts', 'receiptHash'
  ], 'initial web-prepare receipt')
  exact(value.artifacts, Object.keys(TARGET_FILES),
    'initial web-prepare receipt artifacts')
  const expected = Object.fromEntries(Object.entries(target.files).map(
    ([field, file]) => [field, file.sha256]))
  const unsigned = { ...value }
  delete unsigned.receiptHash
  if (value.schema !== RECEIPT_SCHEMA || value.version !== 1 ||
      value.state !== 'COMPLETED' || value.planHash !== plan.value.planHash ||
      Object.entries(expected).some(([field, digest]) =>
        value.artifacts[field] !== digest) ||
      Object.values(value.artifacts).some(digest => !HEX64.test(digest)) ||
      value.receiptHash !== recordHash(unsigned)) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      'initial web-prepare receipt is invalid')
  }
  return Object.freeze(value)
}

function readReceipt (root, journal, plan, target) {
  normalizeAlias(root, journal, 'committed.json', 'committed', 0o600)
  const inspected = inspectFile(root, join(journal, 'committed.json'), 0o600,
    MAX_PLAN_BYTES)
  return validateReceipt(parseCanonicalJson(inspected.bytes,
    'initial web-prepare receipt'), plan, target)
}

function sealReceipt (root, journal, plan, target) {
  const unsigned = {
    schema: RECEIPT_SCHEMA,
    version: 1,
    state: 'COMPLETED',
    planHash: plan.value.planHash,
    artifacts: Object.freeze(Object.fromEntries(Object.entries(target.files).map(
      ([field, file]) => [field, file.sha256])))
  }
  const receipt = { ...unsigned, receiptHash: recordHash(unsigned) }
  if (!entryExists(join(journal, 'committed.json'))) {
    atomicFile(root, journal, 'committed.json', jsonBytes(receipt),
      0o600, 'committed')
  }
  fsyncDirectory(journal)
  return readReceipt(root, journal, plan, target)
}

function completedStatus (receipt) {
  return Object.freeze({
    schema: STATUS_SCHEMA,
    version: 1,
    state: 'COMPLETED',
    planHash: receipt.planHash,
    artifacts: Object.freeze({ ...receipt.artifacts }),
    receiptHash: receipt.receiptHash
  })
}

function assertRecoverablePartial (root, plan) {
  assertSnapshotCurrent(root, plan.files.releaseConfig, 'release config')
  const signaturePath = join(root, 'web/asset-manifest.sig')
  if (entryExists(signaturePath)) {
    for (const [field, snapshot] of Object.entries(plan.files)) {
      assertSnapshotCurrent(root, snapshot, field)
    }
    return
  }
  assertSnapshotCurrent(root, plan.files.signingRequest, 'signing request')
  if (entryExists(join(root, 'web'))) {
    listWebFiles(root)
  }
}

function createPlan (root) {
  const current = Object.freeze(Object.fromEntries(Object.entries(BEFORE_FILES).map(
    ([field, [relativePath, mode]]) =>
      [field, inspectFile(root, join(root, relativePath), mode)])))
  validatePredecessor(root, current)
  const unsigned = {
    schema: PLAN_SCHEMA,
    version: 1,
    state: 'PENDING',
    files: Object.fromEntries(Object.entries(BEFORE_FILES).map(
      ([field, [relativePath]]) =>
        [field, snapshotRecord(current[field], relativePath)]))
  }
  return Object.freeze({ ...unsigned, planHash: recordHash(unsigned) })
}

export function beginPeeritSeq29InitialWebPrepareV1 (input = {}) {
  beginAuthenticatedOperation()
  exact(input, ['root'], 'initial web-prepare begin input')
  const root = resolve(String(input.root || ''))
  const { journal, names } = ensureJournal(root)
  if (!names.includes('pending.json')) {
    const plan = createPlan(root)
    atomicFile(root, journal, 'pending.json', jsonBytes(plan), 0o600, 'pending')
    fsyncDirectory(journal)
  }
  const plan = readPlan(root, journal)
  assertSnapshotCurrent(root, plan.files.releaseConfig, 'release config')
  const target = validateTarget(root)
  if (target) {
    return completedStatus(sealReceipt(root, journal, plan, target))
  }
  assertRecoverablePartial(root, plan)
  if (entryExists(join(journal, 'committed.json'))) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      'completed web-prepare receipt exists without its exact target')
  }
  return Object.freeze({
    schema: STATUS_SCHEMA,
    version: 1,
    state: 'PENDING',
    planHash: plan.value.planHash,
    priorSigningRequest: Object.freeze(parseCanonicalJson(
      plan.files.signingRequest.bytes, 'preserved predecessor signing request'))
  })
}

export function readPeeritSeq29InitialWebPreparePredecessorV1 (input = {}) {
  beginAuthenticatedOperation()
  exact(input, ['root'], 'initial web-prepare predecessor input')
  const root = resolve(String(input.root || ''))
  const journal = join(root, JOURNAL)
  if (!entryExists(journal)) return null
  const state = ensureJournal(root)
  if (!state.names.includes('pending.json')) return null
  const plan = readPlan(root, journal)
  assertSnapshotCurrent(root, plan.files.releaseConfig, 'release config')
  return Object.freeze({
    schema: 'peerit-seq29-initial-web-prepare-predecessor-v1',
    version: 1,
    planHash: plan.value.planHash,
    priorSigningRequest: Object.freeze(parseCanonicalJson(
      plan.files.signingRequest.bytes, 'preserved predecessor signing request'))
  })
}

export function completePeeritSeq29InitialWebPrepareV1 (input = {}) {
  beginAuthenticatedOperation()
  exact(input, ['root'], 'initial web-prepare completion input')
  const root = resolve(String(input.root || ''))
  const { journal, names } = ensureJournal(root)
  if (!names.includes('pending.json')) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_CORRUPT',
      'initial web-prepare plan is absent')
  }
  const plan = readPlan(root, journal)
  assertSnapshotCurrent(root, plan.files.releaseConfig, 'release config')
  const target = validateTarget(root)
  if (!target) {
    fail('PEERIT_SEQ29_INITIAL_WEB_PREPARE_TARGET_INCOMPLETE',
      'initial Sequence-29 web-prepare effect is incomplete')
  }
  return completedStatus(sealReceipt(root, journal, plan, target))
}
