import assert from 'node:assert/strict'
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  restorePeeritSeq29PinnedWebSignatureToStageV1,
  snapshotPeeritSeq29PinnedWebReprepareV1,
  snapshotPeeritSeq29PinnedWebStageOutputsV1,
  verifyPeeritSeq29PinnedWebStageFinalV1,
  writePeeritSeq29PinnedWebStageSigningRequestV1
} from '../scripts/lib/seq29-pinned-web-reprepare.mjs'

const names = Object.freeze({
  appArtifact: 'peerit-app-artifact-v1.json',
  canonicalWebAssetManifest: 'peerit-web-assets-v1.cenc',
  outerAssetManifest: 'asset-manifest.json'
})

function fixture () {
  const root = mkdtempSync(join(tmpdir(), 'peerit-seq29-reprepare-'))
  mkdirSync(join(root, 'web'), { mode: 0o755 })
  mkdirSync(join(root, 'deploy'), { mode: 0o755 })
  const values = Object.freeze({
    appArtifact: Buffer.from('{"app":"stable"}\n'),
    canonicalWebAssetManifest: Buffer.from('{"manifest":"stable"}\n'),
    outerAssetManifest: Buffer.from('{"outer":"stable"}\n'),
    outerSignature: Buffer.from('{"signature":"returned"}\n'),
    signingRequest: Buffer.from('{"request":"stable"}\n')
  })
  for (const [field, name] of Object.entries(names)) {
    writeFileSync(join(root, 'web', name), values[field], { mode: 0o644 })
  }
  writeFileSync(join(root, 'web', 'asset-manifest.sig'),
    values.outerSignature, { mode: 0o644 })
  const signingRequestPath = join(root, 'deploy', 'web-signing-request.json')
  writeFileSync(signingRequestPath, values.signingRequest, { mode: 0o644 })
  return { root, signingRequestPath, values }
}

function writeStage (snapshot, values, count = 3) {
  rmSync(snapshot.stageWebDirectory, { recursive: true, force: true })
  mkdirSync(snapshot.stageWebDirectory, { mode: 0o755 })
  for (const [field, name] of Object.entries(names).slice(0, count)) {
    writeFileSync(join(snapshot.stageWebDirectory, name), values[field], {
      mode: 0o644
    })
  }
}

function sourcePaths (state) {
  return Object.freeze([
    join(state.root, 'web', names.appArtifact),
    join(state.root, 'web', names.canonicalWebAssetManifest),
    join(state.root, 'web', names.outerAssetManifest),
    join(state.root, 'web', 'asset-manifest.sig'),
    state.signingRequestPath
  ])
}

function snapshotFor (state) {
  return snapshotPeeritSeq29PinnedWebReprepareV1({
    root: state.root,
    signingRequestPath: state.signingRequestPath
  })
}

function snapshotStageFor (snapshot, state) {
  writePeeritSeq29PinnedWebStageSigningRequestV1({
    snapshot,
    bytes: state.values.signingRequest
  })
  return snapshotPeeritSeq29PinnedWebStageOutputsV1({ snapshot })
}

{
  const state = fixture()
  const snapshot = snapshotFor(state)
  writeStage(snapshot, state.values)
  const stageSnapshot = snapshotStageFor(snapshot, state)
  const restored = restorePeeritSeq29PinnedWebSignatureToStageV1({
    snapshot,
    stageSnapshot
  })
  const result = verifyPeeritSeq29PinnedWebStageFinalV1({ restored })
  assert.deepEqual(result.before, result.after)
  assert.deepEqual(readFileSync(join(snapshot.stageWebDirectory,
    'asset-manifest.sig')), state.values.outerSignature)
}

for (const mode of [0o1644]) {
  const state = fixture()
  chmodSync(join(state.root, 'web', 'asset-manifest.sig'), mode)
  assert.throws(() => snapshotFor(state),
    error => error.code === 'PEERIT_SEQ29_REPREPARE_PERMISSIONS')
}

{
  const state = fixture()
  linkSync(join(state.root, 'web', 'asset-manifest.sig'),
    join(state.root, 'web', 'signature-hardlink'))
  assert.throws(() => snapshotFor(state),
    error => error.code === 'PEERIT_SEQ29_REPREPARE_PERMISSIONS')
}

{
  const state = fixture()
  const realWeb = join(state.root, 'real-web')
  renameSync(join(state.root, 'web'), realWeb)
  symlinkSync(realWeb, join(state.root, 'web'))
  assert.throws(() => snapshotFor(state),
    error => error.code === 'PEERIT_SEQ29_REPREPARE_PERMISSIONS')
}

{
  const state = fixture()
  const snapshot = snapshotFor(state)
  writeStage(snapshot, state.values)
  const stageSnapshot = snapshotStageFor(snapshot, state)
  writeFileSync(join(snapshot.stageWebDirectory, 'asset-manifest.sig'),
    Buffer.from('stale'), { mode: 0o644 })
  assert.throws(() => restorePeeritSeq29PinnedWebSignatureToStageV1({
    snapshot,
    stageSnapshot
  }), error => error.code === 'PEERIT_SEQ29_REPREPARE_STALE_STAGE')
  assert.deepEqual(readFileSync(join(snapshot.stageWebDirectory,
    'asset-manifest.sig')), Buffer.from('stale'))
}

{
  const state = fixture()
  const snapshot = snapshotFor(state)
  writeStage(snapshot, {
    ...state.values,
    appArtifact: Buffer.from('{"app":"drift"}\n')
  })
  const stageSnapshot = snapshotStageFor(snapshot, state)
  assert.throws(() => restorePeeritSeq29PinnedWebSignatureToStageV1({
    snapshot,
    stageSnapshot
  }), error => error.code === 'PEERIT_SEQ29_REPREPARE_OUTPUT_DRIFT')
  assert.throws(() => readFileSync(join(snapshot.stageWebDirectory,
    'asset-manifest.sig')), error => error.code === 'ENOENT')
}

for (const field of Object.keys(names)) {
  const state = fixture()
  const snapshot = snapshotFor(state)
  writeStage(snapshot, state.values)
  const stagePath = join(snapshot.stageWebDirectory, names[field])
  const alternate = `${stagePath}.replacement`
  const stageSnapshot = snapshotStageFor(snapshot, state)
  writeFileSync(alternate, state.values[field], { mode: 0o644 })
  renameSync(alternate, stagePath)
  assert.throws(() => restorePeeritSeq29PinnedWebSignatureToStageV1({
    snapshot,
    stageSnapshot
  }), error => error.code === 'PEERIT_SEQ29_REPREPARE_IDENTITY_DRIFT')
  assert.throws(() => readFileSync(join(snapshot.stageWebDirectory,
    'asset-manifest.sig')), error => error.code === 'ENOENT')
}

for (const kind of ['symlink', 'hardlink']) {
  const state = fixture()
  const snapshot = snapshotFor(state)
  writeStage(snapshot, state.values)
  writePeeritSeq29PinnedWebStageSigningRequestV1({
    snapshot,
    bytes: state.values.signingRequest
  })
  const app = join(snapshot.stageWebDirectory, names.appArtifact)
  const target = join(snapshot.stageWebDirectory, 'app-target')
  renameSync(app, target)
  if (kind === 'symlink') symlinkSync(target, app)
  else linkSync(target, app)
  assert.throws(() => snapshotPeeritSeq29PinnedWebStageOutputsV1({ snapshot }),
    error => error.code === 'PEERIT_SEQ29_REPREPARE_PERMISSIONS')
}

{
  const state = fixture()
  const snapshot = snapshotFor(state)
  writeStage(snapshot, state.values)
  const stageSnapshot = snapshotStageFor(snapshot, state)
  const source = join(state.root, 'web', names.appArtifact)
  const replacement = `${source}.replacement`
  writeFileSync(replacement, state.values.appArtifact, { mode: 0o644 })
  renameSync(replacement, source)
  assert.throws(() => restorePeeritSeq29PinnedWebSignatureToStageV1({
    snapshot,
    stageSnapshot
  }), error => error.code === 'PEERIT_SEQ29_REPREPARE_IDENTITY_DRIFT')
}

{
  const state = fixture()
  const snapshot = snapshotFor(state)
  writeStage(snapshot, state.values)
  const stageSnapshot = snapshotStageFor(snapshot, state)
  const restored = restorePeeritSeq29PinnedWebSignatureToStageV1({
    snapshot,
    stageSnapshot
  })
  const stagePath = join(snapshot.stageWebDirectory, names.appArtifact)
  const replacement = `${stagePath}.post-restore`
  writeFileSync(replacement, state.values.appArtifact, { mode: 0o644 })
  renameSync(replacement, stagePath)
  assert.throws(() => verifyPeeritSeq29PinnedWebStageFinalV1({ restored }),
    error => error.code === 'PEERIT_SEQ29_REPREPARE_IDENTITY_DRIFT',
    'immediate downstream validation must reject a post-restore inode swap')
}

{
  const state = fixture()
  const first = snapshotFor(state)
  writeStage(first, state.values, 1)
  const second = snapshotFor(state)
  assert.notEqual(first.stageWebDirectory, second.stageWebDirectory)
  assert.deepEqual(readFileSync(join(first.stageWebDirectory,
    names.appArtifact)), state.values.appArtifact,
  'a later continue preserves failed-attempt residue in its unique directory')
}

for (let failurePoint = 0; failurePoint <= 4; failurePoint++) {
  const state = fixture()
  const originals = sourcePaths(state).map(path => readFileSync(path))
  const snapshot = snapshotFor(state)
  writeStage(snapshot, state.values, Math.min(failurePoint, 3))
  if (failurePoint === 4) {
    writePeeritSeq29PinnedWebStageSigningRequestV1({
      snapshot,
      bytes: state.values.signingRequest
    })
  }
  assert.deepEqual(sourcePaths(state).map(path => readFileSync(path)), originals,
    `stage failure after output ${failurePoint} must not mutate the live signed set`)
  const recoverySnapshot = snapshotFor(state)
  writeStage(recoverySnapshot, state.values)
  const stageSnapshot = snapshotStageFor(recoverySnapshot, state)
  const restored = restorePeeritSeq29PinnedWebSignatureToStageV1({
    snapshot: recoverySnapshot,
    stageSnapshot
  })
  const recovered = verifyPeeritSeq29PinnedWebStageFinalV1({ restored })
  assert.deepEqual(recovered.before, recovered.after,
    `a fixed continue must recover after output ${failurePoint} without supplied bytes`)
}

console.log('peerit seq29 pinned web reprepare tests: ok')
