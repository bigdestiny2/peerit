import { createHash, randomBytes } from 'node:crypto'
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
  writeFileSync
} from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'

const SNAPSHOTS = new WeakMap()
const STAGE_SNAPSHOTS = new WeakMap()
const RESTORED_STAGES = new WeakMap()
const STABLE_FIELDS = Object.freeze([
  'appArtifact',
  'canonicalWebAssetManifest',
  'outerAssetManifest',
  'outerSignature',
  'signingRequest'
])
const REGENERATED_FIELDS = Object.freeze([
  'appArtifact',
  'canonicalWebAssetManifest',
  'outerAssetManifest',
  'signingRequest'
])
const SIGNATURE_MODE = 0o644

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_REPREPARE_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function ownerUid () {
  return typeof process.getuid === 'function' ? process.getuid() : null
}

function assertOwned (metadata, field) {
  const uid = ownerUid()
  if (uid != null && metadata.uid !== uid) {
    fail('PEERIT_SEQ29_REPREPARE_PERMISSIONS',
      `${field} is not owned by the current operator`)
  }
}

function fullMode (metadata) {
  return metadata.mode & 0o7777
}

function assertTrustedDirectory (path, field, exactMode = null) {
  const metadata = lstatSync(path)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      metadata.nlink < 1 || (fullMode(metadata) & 0o022) !== 0 ||
      (exactMode != null && fullMode(metadata) !== exactMode)) {
    fail('PEERIT_SEQ29_REPREPARE_PERMISSIONS',
      `${field} must be a real owned directory without group/world write or special-mode drift`)
  }
  assertOwned(metadata, field)
  return metadata
}

function assertTrustedParents (root, target) {
  const absoluteRoot = resolve(root)
  const absoluteTarget = resolve(target)
  const suffix = relative(absoluteRoot, dirname(absoluteTarget))
  if (suffix === '..' || suffix.startsWith(`..${sep}`)) {
    fail('PEERIT_SEQ29_REPREPARE_PERMISSIONS',
      'reprepare path escapes the authenticated repository root')
  }
  assertTrustedDirectory(absoluteRoot, 'repository root')
  let cursor = absoluteRoot
  for (const component of suffix === '' ? [] : suffix.split(sep)) {
    cursor = join(cursor, component)
    if (!existsSync(cursor)) break
    assertTrustedDirectory(cursor, `reprepare parent ${cursor}`)
  }
}

function ensurePrivateDirectory (root, path) {
  assertTrustedParents(root, join(path, 'child'))
  if (!existsSync(path)) {
    const parent = dirname(path)
    assertTrustedDirectory(parent, `reprepare parent ${parent}`)
    mkdirSync(path, { mode: 0o700 })
    fsyncDirectory(parent)
  }
  assertTrustedDirectory(path, 'private reprepare stage', 0o700)
}

function fsyncDirectory (path) {
  let descriptor
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
  } catch {
    fail('PEERIT_SEQ29_REPREPARE_PERMISSIONS',
      'reprepare directory could not be opened without following links')
  }
  try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
}

function inspectRegular (root, path, field, expectedMode) {
  assertTrustedParents(root, path)
  const metadata = lstatSync(path)
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
      fullMode(metadata) !== expectedMode) {
    fail('PEERIT_SEQ29_REPREPARE_PERMISSIONS',
      `${field} must be a single-link regular file with exact mode ${expectedMode.toString(8)}`)
  }
  assertOwned(metadata, field)
  let descriptor
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
  } catch {
    fail('PEERIT_SEQ29_REPREPARE_PERMISSIONS',
      `${field} could not be opened as a no-follow regular file`)
  }
  let bytes
  try {
    const opened = fstatSync(descriptor)
    if (opened.dev !== metadata.dev || opened.ino !== metadata.ino ||
        opened.size !== metadata.size || fullMode(opened) !== expectedMode ||
        opened.nlink !== 1) {
      fail('PEERIT_SEQ29_REPREPARE_IDENTITY_DRIFT',
        `${field} changed identity before it was read`)
    }
    bytes = readFileSync(descriptor)
    const after = fstatSync(descriptor)
    if (after.dev !== opened.dev || after.ino !== opened.ino ||
        after.size !== opened.size || fullMode(after) !== expectedMode ||
        after.nlink !== 1) {
      fail('PEERIT_SEQ29_REPREPARE_IDENTITY_DRIFT',
        `${field} changed identity while it was read`)
    }
    const linked = lstatSync(path)
    if (linked.dev !== opened.dev || linked.ino !== opened.ino ||
        linked.size !== opened.size || fullMode(linked) !== expectedMode ||
        linked.nlink !== 1 || !linked.isFile() || linked.isSymbolicLink()) {
      fail('PEERIT_SEQ29_REPREPARE_IDENTITY_DRIFT',
        `${field} path changed identity while it was read`)
    }
  } finally {
    closeSync(descriptor)
  }
  return Object.freeze({
    bytes,
    sha256: sha256(bytes),
    byteLength: bytes.byteLength,
    mode: expectedMode,
    dev: String(metadata.dev),
    ino: String(metadata.ino)
  })
}

function assertSameInspection (before, after, field) {
  if (before.dev !== after.dev || before.ino !== after.ino ||
      before.mode !== after.mode || before.byteLength !== after.byteLength ||
      before.sha256 !== after.sha256 || !before.bytes.equals(after.bytes)) {
    fail('PEERIT_SEQ29_REPREPARE_IDENTITY_DRIFT',
      `${field} changed identity, mode, or bytes after authentication`)
  }
}

function createOnlyExact (root, path, bytes, mode, field) {
  assertTrustedParents(root, path)
  if (existsSync(path)) {
    fail('PEERIT_SEQ29_REPREPARE_STALE_STAGE',
      `${field} already exists; preserved signature remains unattached`)
  }
  const descriptor = openSync(path, 'wx', mode)
  try {
    const metadata = fstatSync(descriptor)
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
        fullMode(metadata) !== mode) {
      fail('PEERIT_SEQ29_REPREPARE_PERMISSIONS',
        `${field} did not open as its exact create-only file`)
    }
    assertOwned(metadata, field)
    writeFileSync(descriptor, bytes)
    fsyncSync(descriptor)
  } finally {
    closeSync(descriptor)
  }
  fsyncDirectory(dirname(path))
  const restored = inspectRegular(root, path, field, mode)
  if (!restored.bytes.equals(bytes) || restored.sha256 !== sha256(bytes)) {
    fail('PEERIT_SEQ29_REPREPARE_SIGNATURE_DRIFT',
      `${field} changed during create-only restore`)
  }
  return restored
}

function pathsFor (root, signingRequestPath) {
  return Object.freeze({
    appArtifact: join(root, 'web', 'peerit-app-artifact-v1.json'),
    canonicalWebAssetManifest: join(root, 'web', 'peerit-web-assets-v1.cenc'),
    outerAssetManifest: join(root, 'web', 'asset-manifest.json'),
    outerSignature: join(root, 'web', 'asset-manifest.sig'),
    signingRequest: resolve(signingRequestPath)
  })
}

export function snapshotPeeritSeq29PinnedWebReprepareV1 (input = {}) {
  exact(input, ['root', 'signingRequestPath'], 'pinned reprepare snapshot input')
  const root = resolve(String(input.root || ''))
  const paths = pathsFor(root, input.signingRequestPath)
  const values = {}
  for (const field of STABLE_FIELDS) {
    values[field] = inspectRegular(root, paths[field],
      `Sequence-29 ${field}`, field === 'outerSignature' ? SIGNATURE_MODE : 0o644)
  }
  const deployRoot = join(root, '.deploy')
  if (!existsSync(deployRoot)) {
    assertTrustedDirectory(root, 'repository root')
    mkdirSync(deployRoot, { mode: 0o700 })
    fsyncDirectory(root)
  }
  assertTrustedDirectory(deployRoot, 'private deployment evidence root')
  const stageContainer = join(root, '.deploy', 'seq29-pinned-reprepare-v1')
  ensurePrivateDirectory(root, stageContainer)
  const stageRoot = join(stageContainer,
    `attempt-${randomBytes(16).toString('hex')}`)
  try { mkdirSync(stageRoot, { mode: 0o700 }) } catch {
    fail('PEERIT_SEQ29_REPREPARE_STALE_STAGE',
      'a unique private reprepare attempt could not be created')
  }
  fsyncDirectory(stageContainer)
  assertTrustedDirectory(stageRoot, 'private reprepare attempt', 0o700)
  const snapshot = Object.freeze({
    schema: 'peerit-seq29-pinned-web-reprepare-snapshot-v1',
    version: 1,
    stageWebDirectory: join(stageRoot, 'web'),
    stageSigningRequestPath: join(stageRoot, 'web-signing-request.json'),
    hashes: Object.freeze(Object.fromEntries(STABLE_FIELDS.map(field => [
      field, values[field].sha256
    ])))
  })
  SNAPSHOTS.set(snapshot, Object.freeze({ root, paths, values }))
  return snapshot
}

export function writePeeritSeq29PinnedWebStageSigningRequestV1 (input = {}) {
  exact(input, ['snapshot', 'bytes'],
    'pinned reprepare staged signing-request input')
  const state = SNAPSHOTS.get(input.snapshot)
  if (!state) {
    fail('PEERIT_SEQ29_REPREPARE_SNAPSHOT_REQUIRED',
      'the exact in-process authenticated reprepare snapshot is required')
  }
  if (!(input.bytes instanceof Uint8Array)) {
    fail('PEERIT_SEQ29_REPREPARE_INVALID',
      'staged signing request must be exact bytes')
  }
  const written = createOnlyExact(state.root,
    input.snapshot.stageSigningRequestPath, Buffer.from(input.bytes), 0o644,
    'Sequence-29 staged signing request')
  return Object.freeze({ sha256: written.sha256 })
}

export function restorePeeritSeq29PinnedWebSignatureToStageV1 (input = {}) {
  exact(input, ['snapshot', 'stageSnapshot'],
    'pinned reprepare stage restore input')
  const state = SNAPSHOTS.get(input.snapshot)
  if (!state) {
    fail('PEERIT_SEQ29_REPREPARE_SNAPSHOT_REQUIRED',
      'the exact in-process authenticated reprepare snapshot is required')
  }
  const stagedState = STAGE_SNAPSHOTS.get(input.stageSnapshot)
  if (!stagedState || stagedState.sourceSnapshot !== input.snapshot) {
    fail('PEERIT_SEQ29_REPREPARE_STAGE_SNAPSHOT_REQUIRED',
      'the exact in-process staged-output snapshot is required')
  }
  const liveNow = {}
  for (const field of STABLE_FIELDS) {
    liveNow[field] = inspectRegular(state.root, state.paths[field],
      `Sequence-29 live ${field}`,
      field === 'outerSignature' ? SIGNATURE_MODE : 0o644)
    assertSameInspection(state.values[field], liveNow[field],
      `Sequence-29 live ${field}`)
  }
  const stagedNow = {}
  for (const field of Object.keys(stagedState.paths)) {
    stagedNow[field] = inspectRegular(state.root, stagedState.paths[field],
      `Sequence-29 staged ${field}`, 0o644)
    assertSameInspection(stagedState.values[field], stagedNow[field],
      `Sequence-29 staged ${field}`)
  }
  const staged = Object.fromEntries(REGENERATED_FIELDS.map(field => [
    field, stagedNow[field].bytes
  ]))
  for (const field of REGENERATED_FIELDS) {
    if (!staged[field].equals(state.values[field].bytes)) {
      fail('PEERIT_SEQ29_REPREPARE_OUTPUT_DRIFT',
        `source-pinned Sequence-29 reprepare changed ${field}; signature remains unattached`)
    }
  }
  const signaturePath = join(input.snapshot.stageWebDirectory,
    'asset-manifest.sig')
  const signature = createOnlyExact(state.root, signaturePath,
    state.values.outerSignature.bytes, state.values.outerSignature.mode,
    'Sequence-29 staged returned signature')
  const restored = Object.freeze({
    schema: 'peerit-seq29-pinned-web-stage-signature-restored-v1',
    stageWebDirectory: input.snapshot.stageWebDirectory,
    signatureSha256: signature.sha256
  })
  RESTORED_STAGES.set(restored, Object.freeze({
    sourceSnapshot: input.snapshot,
    stageSnapshot: input.stageSnapshot,
    signature
  }))
  return restored
}

export function snapshotPeeritSeq29PinnedWebStageOutputsV1 (input = {}) {
  exact(input, ['snapshot'], 'pinned reprepare staged-output snapshot input')
  const sourceState = SNAPSHOTS.get(input.snapshot)
  if (!sourceState) {
    fail('PEERIT_SEQ29_REPREPARE_SNAPSHOT_REQUIRED',
      'the exact in-process authenticated reprepare snapshot is required')
  }
  const paths = Object.freeze({
    appArtifact: join(input.snapshot.stageWebDirectory,
      'peerit-app-artifact-v1.json'),
    canonicalWebAssetManifest: join(input.snapshot.stageWebDirectory,
      'peerit-web-assets-v1.cenc'),
    outerAssetManifest: join(input.snapshot.stageWebDirectory,
      'asset-manifest.json'),
    signingRequest: input.snapshot.stageSigningRequestPath
  })
  const values = {}
  for (const field of Object.keys(paths)) {
    values[field] = inspectRegular(sourceState.root, paths[field],
      `Sequence-29 staged ${field}`, 0o644)
  }
  const stageSnapshot = Object.freeze({
    schema: 'peerit-seq29-pinned-web-stage-output-snapshot-v1',
    version: 1,
    hashes: Object.freeze(Object.fromEntries(Object.keys(paths).map(field => [
      field, values[field].sha256
    ])))
  })
  STAGE_SNAPSHOTS.set(stageSnapshot, Object.freeze({
    sourceSnapshot: input.snapshot,
    paths,
    values
  }))
  return stageSnapshot
}

export function verifyPeeritSeq29PinnedWebStageFinalV1 (input = {}) {
  exact(input, ['restored'], 'pinned reprepare final stage input')
  const restoredState = RESTORED_STAGES.get(input.restored)
  if (!restoredState) {
    fail('PEERIT_SEQ29_REPREPARE_STAGE_SNAPSHOT_REQUIRED',
      'the exact in-process restored stage is required')
  }
  const state = SNAPSHOTS.get(restoredState.sourceSnapshot)
  const stagedState = STAGE_SNAPSHOTS.get(restoredState.stageSnapshot)
  if (!state || !stagedState) {
    fail('PEERIT_SEQ29_REPREPARE_STAGE_SNAPSHOT_REQUIRED',
      'the restored stage lost its authenticated snapshots')
  }
  const liveFinal = {}
  for (const field of STABLE_FIELDS) {
    liveFinal[field] = inspectRegular(state.root, state.paths[field],
      `Sequence-29 final live ${field}`,
      field === 'outerSignature' ? SIGNATURE_MODE : 0o644)
    assertSameInspection(state.values[field], liveFinal[field],
      `Sequence-29 final live ${field}`)
  }
  const stagedFinal = {}
  for (const field of Object.keys(stagedState.paths)) {
    stagedFinal[field] = inspectRegular(state.root, stagedState.paths[field],
      `Sequence-29 final staged ${field}`, 0o644)
    assertSameInspection(stagedState.values[field], stagedFinal[field],
      `Sequence-29 final staged ${field}`)
  }
  const signaturePath = join(
    restoredState.sourceSnapshot.stageWebDirectory, 'asset-manifest.sig')
  const signatureFinal = inspectRegular(state.root, signaturePath,
    'Sequence-29 final staged returned signature', SIGNATURE_MODE)
  assertSameInspection(restoredState.signature, signatureFinal,
    'Sequence-29 final staged returned signature')
  return Object.freeze({
    before: Object.freeze(Object.fromEntries(STABLE_FIELDS.map(field => [
      field, state.values[field].bytes
    ]))),
    after: Object.freeze({
      appArtifact: stagedFinal.appArtifact.bytes,
      canonicalWebAssetManifest: stagedFinal.canonicalWebAssetManifest.bytes,
      outerAssetManifest: stagedFinal.outerAssetManifest.bytes,
      outerSignature: signatureFinal.bytes,
      signingRequest: stagedFinal.signingRequest.bytes
    }),
    stageWebDirectory: restoredState.sourceSnapshot.stageWebDirectory
  })
}

export function inspectPeeritSeq29PinnedWebReprepareSourceV1 (input = {}) {
  const snapshot = snapshotPeeritSeq29PinnedWebReprepareV1(input)
  return Object.freeze({
    status: 'AUTHENTICATED_SOURCE_INTACT',
    stageWebDirectory: snapshot.stageWebDirectory,
    hashes: snapshot.hashes
  })
}
