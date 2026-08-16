import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
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
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { releaseSigningMessage } from '../js/release-verify.js'
import {
  appendPeeritSeq29PinHistoryJournaledV1
} from '../scripts/lib/seq29-pin-history-writer.mjs'

const PKCS8_PREFIX = '302e020100300506032b657004220420'
const seed = '11'.repeat(32)
const privateKey = createPrivateKey({
  key: Buffer.from(PKCS8_PREFIX + seed, 'hex'),
  format: 'der',
  type: 'pkcs8'
})
const publicKey = createPublicKey(privateKey).export({
  format: 'der',
  type: 'spki'
}).subarray(-32).toString('hex')
const driveKey = '22'.repeat(32)
const discoveryKey = '33'.repeat(32)
const inboxKey = '44'.repeat(32)
const relayHints = [
  'https://relay-syd.example/api/blind/v1/describe',
  'https://relay-dal.example/api/blind/v1/describe'
]

function hash (value) {
  return createHash('sha256').update(value).digest('hex')
}

function json (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

function writeExact (path, content) {
  writeFileSync(path, content, { mode: 0o644 })
  chmodSync(path, 0o644)
}

function fixture (label) {
  const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
  const root = mkdtempSync(join(base, `peerit-seq29-history-writer-${label}-`))
  mkdirSync(join(root, 'deploy'), { mode: 0o755 })
  mkdirSync(join(root, 'web'), { mode: 0o755 })
  mkdirSync(join(root, '.deploy'), { mode: 0o755 })
  const config = {
    substrateProfile: 'blind-v1',
    relayHints,
    productionPinHistoryBundle: 'peerit-production-pin-history-v1.cenc',
    peeritSeedBootstrapBundle: 'deploy/peerit-seed-bootstrap-v1.json',
    peeritSeedDiscoveryAuthorityPublicKey: discoveryKey,
    peeritLimitedPublicInboxBootstrapBundle:
      'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json',
    peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxKey,
    releaseSequence: 29,
    pinnedReleaseKey: publicKey
  }
  const manifest = {
    releaseSequence: 29,
    files: {
      'index.html': '55'.repeat(32),
      'peerit-limited-public-inbox-bootstrap-v1.json': '66'.repeat(32)
    },
    controls: { 'sw.js': '77'.repeat(32) },
    driveKey,
    webRelease: {
      releaseSequence: 29,
      transport: 'blind-substrate',
      substrateProfile: 'blind-v1',
      relayHints,
      networkDelivery: 'profile-gated',
      legacyDestination: null,
      productionPinHistory: '/peerit-production-pin-history-v1.cenc',
      appArtifact: '/peerit-app-artifact-v1.json',
      appArtifactHash: '88'.repeat(32),
      canonicalWebAssetManifest: '/peerit-web-assets-v1.cenc',
      canonicalWebAssetManifestHash: '99'.repeat(32),
      peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
      peeritSeedBootstrapSha256: 'aa'.repeat(32),
      peeritSeedDiscoveryAuthorityPublicKey: discoveryKey,
      peeritSeedBootstrapReleaseSequence: 29,
      peeritLimitedPublicInboxBootstrap:
        '/peerit-limited-public-inbox-bootstrap-v1.json',
      peeritLimitedPublicInboxBootstrapSha256: '66'.repeat(32),
      peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxKey,
      peeritLimitedPublicInboxBootstrapReleaseSequence: 29,
      releaseKey: publicKey
    }
  }
  const manifestBytes = json(manifest)
  const manifestSha256 = hash(manifestBytes)
  const request = {
    schema: 'peerit-web-signing-request-v2',
    manifest: 'web/asset-manifest.json',
    signature: 'web/asset-manifest.sig',
    releaseSequence: 29,
    driveKey,
    pinnedReleaseKey: publicKey,
    manifestSha256,
    signingMessageSha256: hash(Buffer.from(releaseSigningMessage(manifest))),
    artifactFiles: {
      'asset-manifest.json': manifestSha256,
      'index.html': '55'.repeat(32)
    }
  }
  const history = {
    schema: 'peerit-web-release-pin-history/v1',
    note: 'signed predecessor fixture',
    entries: [{ releaseSequence: 28 }]
  }
  const historyBytes = json(history)
  const signature = {
    schema: 'peerit-blind-public-test-artifact-sig/v1',
    alg: 'ed25519',
    key: publicKey,
    signedFile: 'deploy/web-release-pin-history.json',
    signedBytesSha256: hash(historyBytes),
    sig: sign(null, historyBytes, privateKey).toString('hex')
  }
  writeExact(join(root, 'deploy', 'web-release.json'), json(config))
  writeExact(join(root, 'deploy', 'web-signing-request.json'), json(request))
  writeExact(join(root, 'web', 'asset-manifest.json'), manifestBytes)
  writeExact(join(root, 'deploy', 'web-release-pin-history.json'), historyBytes)
  writeExact(join(root, 'deploy', 'web-release-pin-history.json.sig.json'),
    json(signature))
  return Object.freeze({ root, historyBytes, signatureBytes: json(signature) })
}

function assertCompleted (root) {
  const result = appendPeeritSeq29PinHistoryJournaledV1({ root })
  assert.equal(result.state, 'COMPLETED')
  const value = JSON.parse(readFileSync(join(root,
    'deploy/web-release-pin-history.json')))
  assert.deepEqual(value.entries.map(entry => entry.releaseSequence), [28, 29])
  return result
}

function pauseAfterPlan (root) {
  process.env.PEERIT_SEQ29_PIN_HISTORY_WRITER_TEST_FAULT = 'AFTER_PENDING'
  try {
    assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({ root }),
      error => error.code === 'PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED')
  } finally {
    delete process.env.PEERIT_SEQ29_PIN_HISTORY_WRITER_TEST_FAULT
  }
}

{
  const value = fixture('success')
  const first = assertCompleted(value.root)
  const second = assertCompleted(value.root)
  assert.deepEqual(second, first, 'completed history append is idempotent')
  assert.deepEqual(readFileSync(join(value.root,
    'deploy/web-release-pin-history.json.sig.json')), value.signatureBytes,
  'history append preserves the signed predecessor signature for the sign phase')
}

for (const fault of [
  'AFTER_PENDING',
  'TEMP_CLOSE_UNCERTAIN',
  'POST_RENAME_DIRECTORY_SYNC_UNCERTAIN'
]) {
  const value = fixture(fault.toLowerCase())
  process.env.PEERIT_SEQ29_PIN_HISTORY_WRITER_TEST_FAULT = fault
  try {
    assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({
      root: value.root
    }), error => error.code === 'PEERIT_SEQ29_PIN_HISTORY_WRITE_IO_FAILED')
  } finally {
    delete process.env.PEERIT_SEQ29_PIN_HISTORY_WRITER_TEST_FAULT
  }
  assertCompleted(value.root)
}

{
  const value = fixture('same-bytes-inode-swap')
  pauseAfterPlan(value.root)
  const target = join(value.root, 'deploy/web-release-pin-history.json')
  const replacement = `${target}.replacement`
  writeExact(replacement, readFileSync(target))
  renameSync(replacement, target)
  assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({
    root: value.root
  }), error => error.code === 'PEERIT_SEQ29_PIN_HISTORY_WRITE_PREIMAGE_DRIFT')
}

for (const [field, relativePath] of [
  ['config', 'deploy/web-release.json'],
  ['request', 'deploy/web-signing-request.json'],
  ['manifest', 'web/asset-manifest.json'],
  ['signature', 'deploy/web-release-pin-history.json.sig.json']
]) {
  const value = fixture(`post-plan-${field}`)
  pauseAfterPlan(value.root)
  const path = join(value.root, relativePath)
  writeExact(path, Buffer.concat([readFileSync(path), Buffer.from('\n')]))
  assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({
    root: value.root
  }), error => error.code === 'PEERIT_SEQ29_PIN_HISTORY_WRITE_PREIMAGE_DRIFT',
  `${field} drift after durable plan sealing must fail before replacement`)
}

{
  const value = fixture('invalid-predecessor-signature')
  const path = join(value.root,
    'deploy/web-release-pin-history.json.sig.json')
  const envelope = JSON.parse(readFileSync(path))
  envelope.sig = `${envelope.sig.slice(0, -1)}${envelope.sig.endsWith('0') ? '1' : '0'}`
  writeExact(path, json(envelope))
  assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({
    root: value.root
  }), error => error.code ===
    'PEERIT_SEQ29_PIN_HISTORY_WRITE_SIGNATURE_INVALID')
}

{
  const value = fixture('corrupt-journal')
  pauseAfterPlan(value.root)
  const pending = join(value.root,
    '.deploy/seq29-pin-history-write-v1/pending.json')
  writeFileSync(pending, Buffer.concat([readFileSync(pending), Buffer.from(' ')]))
  assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({
    root: value.root
  }), error => error.code === 'PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT')
}

{
  const value = fixture('extra-journal-entry')
  pauseAfterPlan(value.root)
  writeFileSync(join(value.root,
    '.deploy/seq29-pin-history-write-v1/unexpected.json'), '{}\n', {
    mode: 0o600
  })
  assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({
    root: value.root
  }), error => error.code === 'PEERIT_SEQ29_PIN_HISTORY_WRITE_CORRUPT')
}

{
  const value = fixture('parallel-first-call')
  const moduleUrl = new URL(
    '../scripts/lib/seq29-pin-history-writer.mjs', import.meta.url).href
  const source = [
    `import { appendPeeritSeq29PinHistoryJournaledV1 as run } from ${JSON.stringify(moduleUrl)}`,
    `run({ root: ${JSON.stringify(value.root)} })`
  ].join('\n')
  const runChild = () => new Promise(resolve => {
    const child = spawn(process.execPath,
      ['--input-type=module', '--eval', source], {
        env: {
          PATH: process.env.PATH || '',
          PEERIT_SEQ29_PIN_HISTORY_WRITER_TEST_FAULT: 'AFTER_PENDING'
        },
        stdio: 'ignore'
      })
    child.on('exit', code => resolve(code))
  })
  const outcomes = await Promise.all([runChild(), runChild()])
  assert.equal(outcomes.some(code => code !== 0), true,
    'parallel first callers cannot both claim a fresh transaction')
  assertCompleted(value.root)
}

for (const kind of ['special-mode', 'symlink', 'hardlink']) {
  const value = fixture(kind)
  const target = join(value.root, 'deploy/web-release-pin-history.json')
  if (kind === 'special-mode') {
    chmodSync(target, 0o1644)
  } else if (kind === 'symlink') {
    const moved = `${target}.moved`
    renameSync(target, moved)
    symlinkSync(moved, target)
  } else {
    linkSync(target, `${target}.alias`)
  }
  assert.throws(() => appendPeeritSeq29PinHistoryJournaledV1({
    root: value.root
  }), error => error.code === 'PEERIT_SEQ29_PIN_HISTORY_WRITE_PERMISSIONS')
}

console.log('peerit seq29 journaled pin-history writer tests: ok')
