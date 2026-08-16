import assert from 'node:assert/strict'
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign
} from 'node:crypto'
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { releaseSigningMessage } from '../js/release-verify.js'
import {
  beginPeeritSeq29InitialWebPrepareV1,
  completePeeritSeq29InitialWebPrepareV1,
  readPeeritSeq29InitialWebPreparePredecessorV1
} from '../scripts/lib/seq29-initial-web-prepare-journal.mjs'

const PKCS8_PREFIX = '302e020100300506032b657004220420'
const seed = '31'.repeat(32)
const privateKey = createPrivateKey({
  key: Buffer.from(PKCS8_PREFIX + seed, 'hex'),
  format: 'der',
  type: 'pkcs8'
})
const publicKey = createPublicKey(privateKey).export({
  format: 'der',
  type: 'spki'
}).subarray(-32).toString('hex')
const driveKey = '42'.repeat(32)

function hash (value) {
  return createHash('sha256').update(value).digest('hex')
}

function canonical (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
}

function json (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

function writeExact (path, content, mode = 0o644) {
  writeFileSync(path, content, { mode })
  chmodSync(path, mode)
}

function manifestFor (sequence, appHash, canonicalHash) {
  return {
    releaseSequence: sequence,
    files: {
      'peerit-app-artifact-v1.json': appHash,
      'peerit-web-assets-v1.cenc': canonicalHash
    },
    controls: {},
    driveKey,
    webRelease: { releaseSequence: sequence, releaseKey: publicKey }
  }
}

function requestFor (manifestBytes, manifest, appHash, canonicalHash) {
  const manifestHash = hash(manifestBytes)
  return {
    schema: 'peerit-web-signing-request-v2',
    manifest: 'web/asset-manifest.json',
    signature: 'web/asset-manifest.sig',
    releaseSequence: manifest.releaseSequence,
    driveKey,
    pinnedReleaseKey: publicKey,
    manifestSha256: manifestHash,
    signingMessageSha256: hash(Buffer.from(releaseSigningMessage(manifest))),
    artifactFiles: {
      'asset-manifest.json': manifestHash,
      'peerit-app-artifact-v1.json': appHash,
      'peerit-web-assets-v1.cenc': canonicalHash
    }
  }
}

function fixture (label) {
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  const root = mkdtempSync(join(base, `peerit-seq29-initial-web-${label}-`))
  mkdirSync(join(root, 'deploy'), { mode: 0o755 })
  mkdirSync(join(root, 'web'), { mode: 0o755 })
  mkdirSync(join(root, '.deploy'), { mode: 0o755 })
  const config = {
    releaseSequence: 29,
    pinnedReleaseKey: publicKey
  }
  const appBytes = json({ schema: 'predecessor-app-v1' })
  const canonicalBytes = Buffer.from('predecessor-canonical\n')
  const manifest = manifestFor(28, hash(appBytes), hash(canonicalBytes))
  const manifestBytes = json(manifest)
  const request = requestFor(manifestBytes, manifest,
    hash(appBytes), hash(canonicalBytes))
  const signature = {
    alg: 'Ed25519',
    key: publicKey,
    sig: sign(null, Buffer.from(releaseSigningMessage(manifest)),
      privateKey).toString('hex'),
    msgVersion: 'peerit-release-v2'
  }
  writeExact(join(root, 'deploy/web-release.json'), json(config))
  writeExact(join(root, 'deploy/web-signing-request.json'), json(request))
  writeExact(join(root, 'web/peerit-app-artifact-v1.json'), appBytes)
  writeExact(join(root, 'web/peerit-web-assets-v1.cenc'), canonicalBytes)
  writeExact(join(root, 'web/asset-manifest.json'), manifestBytes)
  writeExact(join(root, 'web/asset-manifest.sig'), json(signature))
  return Object.freeze({ root, request })
}

function materializeTarget (root, label = 'target') {
  const oldWeb = join(root, `web-${label}-old`)
  renameSync(join(root, 'web'), oldWeb)
  mkdirSync(join(root, 'web'), { mode: 0o755 })
  const appBytes = json({ schema: `seq29-${label}-app-v1` })
  const canonicalBytes = Buffer.from(`seq29-${label}-canonical\n`)
  const manifest = manifestFor(29, hash(appBytes), hash(canonicalBytes))
  const manifestBytes = json(manifest)
  const request = requestFor(manifestBytes, manifest,
    hash(appBytes), hash(canonicalBytes))
  writeExact(join(root, 'web/peerit-app-artifact-v1.json'), appBytes)
  writeExact(join(root, 'web/peerit-web-assets-v1.cenc'), canonicalBytes)
  writeExact(join(root, 'web/asset-manifest.json'), manifestBytes)
  writeExact(join(root, 'deploy/web-signing-request.json'), json(request))
  return Object.freeze({ oldWeb, request })
}

{
  const value = fixture('success')
  const begun = beginPeeritSeq29InitialWebPrepareV1({ root: value.root })
  assert.equal(begun.state, 'PENDING')
  assert.deepEqual(begun.priorSigningRequest, value.request)
  assert.deepEqual(
    readPeeritSeq29InitialWebPreparePredecessorV1({ root: value.root })
      .priorSigningRequest,
    value.request)
  materializeTarget(value.root)
  const completed = completePeeritSeq29InitialWebPrepareV1({ root: value.root })
  assert.equal(completed.state, 'COMPLETED')
  assert.equal(beginPeeritSeq29InitialWebPrepareV1({ root: value.root }).state,
    'COMPLETED')
}

{
  const value = fixture('effect-before-receipt')
  beginPeeritSeq29InitialWebPrepareV1({ root: value.root })
  materializeTarget(value.root)
  const manifestPath = join(value.root, 'web/asset-manifest.json')
  const before = statSync(manifestPath)
  const recovered = beginPeeritSeq29InitialWebPrepareV1({ root: value.root })
  assert.equal(recovered.state, 'COMPLETED')
  const after = statSync(manifestPath)
  assert.equal(after.ino, before.ino,
    'recovery must seal the existing effect without rebuilding it')
  assert.equal(after.mtimeMs, before.mtimeMs)
}

{
  const value = fixture('post-link-sync-recovery')
  process.env.PEERIT_SEQ29_INITIAL_WEB_PREPARE_TEST_FAULT =
    'POST_LINK_SYNC_UNCERTAIN'
  try {
    assert.throws(() => beginPeeritSeq29InitialWebPrepareV1({ root: value.root }),
      error => error.code === 'PEERIT_SEQ29_INITIAL_WEB_PREPARE_IO_FAILED')
  } finally {
    delete process.env.PEERIT_SEQ29_INITIAL_WEB_PREPARE_TEST_FAULT
  }
  assert.equal(beginPeeritSeq29InitialWebPrepareV1({ root: value.root }).state,
    'PENDING',
    'a visible post-link uncertainty is reauthenticated before recovery continues')
}

{
  const value = fixture('partial-retry')
  beginPeeritSeq29InitialWebPrepareV1({ root: value.root })
  renameSync(join(value.root, 'web'), join(value.root, 'web-interrupted'))
  mkdirSync(join(value.root, 'web'), { mode: 0o755 })
  writeExact(join(value.root, 'web/partial.txt'), Buffer.from('partial\n'))
  assert.equal(beginPeeritSeq29InitialWebPrepareV1({ root: value.root }).state,
    'PENDING', 'an unsigned partial build can retry from the preserved predecessor')
  renameSync(join(value.root, 'web'), join(value.root, 'web-partial'))
  mkdirSync(join(value.root, 'web'), { mode: 0o755 })
  const appBytes = json({ schema: 'seq29-retry-app-v1' })
  const canonicalBytes = Buffer.from('seq29-retry-canonical\n')
  const manifest = manifestFor(29, hash(appBytes), hash(canonicalBytes))
  const manifestBytes = json(manifest)
  writeExact(join(value.root, 'web/peerit-app-artifact-v1.json'), appBytes)
  writeExact(join(value.root, 'web/peerit-web-assets-v1.cenc'), canonicalBytes)
  writeExact(join(value.root, 'web/asset-manifest.json'), manifestBytes)
  writeExact(join(value.root, 'deploy/web-signing-request.json'), json(
    requestFor(manifestBytes, manifest, hash(appBytes), hash(canonicalBytes))))
  assert.equal(completePeeritSeq29InitialWebPrepareV1({ root: value.root }).state,
    'COMPLETED')
}

{
  const value = fixture('same-bytes-inode')
  beginPeeritSeq29InitialWebPrepareV1({ root: value.root })
  const signature = join(value.root, 'web/asset-manifest.sig')
  const replacement = `${signature}.replacement`
  writeExact(replacement, readFileSync(signature))
  renameSync(replacement, signature)
  assert.throws(() => beginPeeritSeq29InitialWebPrepareV1({ root: value.root }),
    error => error.code === 'PEERIT_SEQ29_INITIAL_WEB_PREPARE_PREIMAGE_DRIFT')
}

{
  const value = fixture('preservation-substitution')
  beginPeeritSeq29InitialWebPrepareV1({ root: value.root })
  const pendingPath = join(value.root,
    '.deploy/seq29-initial-web-prepare-v1/pending.json')
  const pending = JSON.parse(readFileSync(pendingPath))
  const bytes = Buffer.from('substituted-app\n')
  pending.files.appArtifact.base64 = bytes.toString('base64')
  pending.files.appArtifact.sha256 = hash(bytes)
  pending.files.appArtifact.size = String(bytes.byteLength)
  const unsigned = { ...pending }
  delete unsigned.planHash
  pending.planHash = hash(canonical(unsigned))
  writeExact(pendingPath, json(pending), 0o600)
  assert.throws(() => beginPeeritSeq29InitialWebPrepareV1({ root: value.root }),
    error => error.code ===
      'PEERIT_SEQ29_INITIAL_WEB_PREPARE_PREDECESSOR_INVALID',
    'self-rehashed preservation bytes cannot replace signed predecessor evidence')
}

{
  const value = fixture('target-mismatch')
  beginPeeritSeq29InitialWebPrepareV1({ root: value.root })
  materializeTarget(value.root, 'mismatch')
  const requestPath = join(value.root, 'deploy/web-signing-request.json')
  const request = JSON.parse(readFileSync(requestPath))
  request.manifestSha256 = '00'.repeat(32)
  writeExact(requestPath, json(request))
  assert.throws(() => beginPeeritSeq29InitialWebPrepareV1({ root: value.root }),
    error => error.code === 'PEERIT_SEQ29_INITIAL_WEB_PREPARE_TARGET_INVALID',
    'a mismatched complete-looking target must not be treated as a retryable partial')
}

for (const kind of ['special-mode', 'hardlink', 'symlink-parent']) {
  const value = fixture(kind)
  const signature = join(value.root, 'web/asset-manifest.sig')
  if (kind === 'special-mode') {
    chmodSync(signature, 0o1644)
  } else if (kind === 'hardlink') {
    linkSync(signature, `${signature}.alias`)
  } else {
    const web = join(value.root, 'web')
    const moved = join(value.root, 'web-real')
    renameSync(web, moved)
    symlinkSync(moved, web)
  }
  assert.throws(() => beginPeeritSeq29InitialWebPrepareV1({ root: value.root }),
    error => error.code === 'PEERIT_SEQ29_INITIAL_WEB_PREPARE_PERMISSIONS')
}

console.log('peerit seq29 initial web-prepare journal tests: ok')
