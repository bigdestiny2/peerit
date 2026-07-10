import assert from 'node:assert/strict'
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  dirtyReleaseStatus,
  filterReleaseDirtyLines,
  inspectReleaseGitStatus,
  releaseInputClosure,
  runReadonlyLivePreflights,
  validatePendingPublishEvidence,
  validatePublicOptions,
  validateStrictPublishReport
} from '../ship.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const TEST_SEED = '11'.repeat(32)
const DRIVE_KEY = 'ab'.repeat(32)

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function publicKeyFromSeed (seed) {
  const priv = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seed, 'hex'), format: 'der', type: 'pkcs8' })
  return createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
}

function childEnv (extra = {}) {
  return {
    PATH: process.env.PATH || '',
    HOME: tmpdir(),
    TMPDIR: tmpdir(),
    NODE_ENV: 'test',
    ...extra
  }
}

function runNode (cwd, args, { env = {}, expect = 0 } = {}) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    env: childEnv(env),
    encoding: 'utf8',
    timeout: 120000
  })
  assert.equal(
    result.status,
    expect,
    `node ${args.join(' ')} exited ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
  )
  return result
}

function copyFixture () {
  const parent = mkdtempSync(join(tmpdir(), 'peerit-release-workflow-'))
  const fixture = join(parent, 'peerit')
  const excluded = new Set(['.git', '.deploy', '.hiverelay-local', '.hiverelay-seed', 'dist', 'node_modules', 'reports', 'web'])
  cpSync(ROOT, fixture, {
    recursive: true,
    filter: (source) => {
      const rel = relative(ROOT, source)
      if (!rel) return true
      return !excluded.has(rel.split(sep)[0])
    }
  })
  symlinkSync(join(ROOT, 'node_modules'), join(fixture, 'node_modules'), 'dir')
  return { parent, fixture }
}

async function main () {
  console.log('— live publish bypasses fail closed —')
  for (const candidate of [
    { publish: true, skipWeb: true, allowDirty: false, skipTests: false },
    { publish: true, skipWeb: false, allowDirty: true, skipTests: false },
    { publish: true, skipWeb: false, allowDirty: false, skipTests: true }
  ]) {
    assert.throws(() => validatePublicOptions(candidate), /refuses release-gate bypasses/)
  }
  assert.doesNotThrow(() => validatePublicOptions({ publish: true, skipWeb: false, allowDirty: false, skipTests: false }))
  assert.equal(dirtyReleaseStatus({ publish: true, allowDirty: false }, ['M index.html']), 'fail')
  assert.equal(dirtyReleaseStatus({ publish: true, allowDirty: true }, ['M index.html']), 'fail')
  assert.equal(dirtyReleaseStatus({ publish: false, allowDirty: true }, ['M index.html']), 'warn')
  console.log('✓ live publish rejects no-web, skipped tests, dirty overrides, and an actually dirty release tree')

  console.log('\n— release input closure + dirty/untracked gates —')
  const closure = releaseInputClosure({ root: ROOT })
  for (const required of [
    'scripts/service-worker-source.mjs',
    'scripts/build-reader-bundle.mjs',
    'scripts/build-dht-bundle.mjs',
    'scripts/csp.mjs',
    'js/reader-src.mjs',
    'js/dht-transport.js',
    'js/crypto.js',
    'config/seed-snapshot.json',
    'deploy/web-release.json',
    'deploy/CAPACITY.md',
    'deploy/peerit-relay/Caddyfile',
    'deploy/peerit-relay/README.md',
    'deploy/peerit-relay/docker-compose.yml',
    'docs/PROTOCOL-V3-CONTENT-IDENTITY.md',
    'scripts/audit-live-legacy-actions.mjs',
    'scripts/local-writable-two-relay.mjs',
    'scripts/soak-atomic-two-relay.mjs',
    'test/seed-idempotency.mjs'
  ]) assert.ok(closure.includes(required), `release input closure includes ${required}`)
  assert.equal(closure.some((file) => file.startsWith('docs/diagrams/')), false, 'unrelated diagrams are outside the release cleanliness gate')
  const buildInputDirty = filterReleaseDirtyLines([
    'M  scripts/service-worker-source.mjs',
    '?? js/reader-src.mjs'
  ])
  assert.deepEqual(buildInputDirty, ['M  scripts/service-worker-source.mjs', '?? js/reader-src.mjs'])
  assert.equal(dirtyReleaseStatus({ publish: true, allowDirty: false }, buildInputDirty), 'fail')
  let gitArgs = []
  const inspected = inspectReleaseGitStatus({
    root: ROOT,
    files: closure,
    spawnSyncImpl: (_cmd, args) => {
      gitArgs = args
      return { status: 0, stdout: ' M scripts/service-worker-source.mjs\n?? js/reader-src.mjs\n', stderr: '' }
    }
  })
  assert.ok(gitArgs.includes('--untracked-files=all'))
  assert.ok(gitArgs.includes('scripts/service-worker-source.mjs') && gitArgs.includes('js/reader-src.mjs'))
  assert.deepEqual(inspected.dirty, ['M scripts/service-worker-source.mjs', '?? js/reader-src.mjs'])
  assert.equal(dirtyReleaseStatus({ publish: true, allowDirty: false }, inspected.dirty), 'fail')
  console.log('✓ tracked and untracked transitive build inputs block live publish; unrelated diagrams do not')

  console.log('\n— pending publish evidence is exact + durable —')
  const validPublishReport = {
    appId: 'peerit',
    local: false,
    strictAnchor: true,
    status: 'ready',
    driveKey: DRIVE_KEY,
    url: `hyper://${DRIVE_KEY}/`,
    contentKey: 'cd'.repeat(32),
    minAnchorPeers: 1,
    siteFiles: 40,
    manifestUpdated: true,
    durability: {
      metadata: { durable: true, activePeers: 1 },
      blobs: { durable: true, activePeers: 1, blobLocalLen: 20, blobRemoteMax: 20 }
    }
  }
  assert.doesNotThrow(() => validateStrictPublishReport(validPublishReport, DRIVE_KEY))
  const publishBytes = Buffer.from(JSON.stringify(validPublishReport, null, 2) + '\n')
  const pending = { publish: true, driveKey: DRIVE_KEY, publishReportSha256: sha256(publishBytes) }
  assert.doesNotThrow(() => validatePendingPublishEvidence(pending, publishBytes))
  assert.throws(() => validatePendingPublishEvidence(pending, Buffer.concat([publishBytes, Buffer.from('\n')])), /publish report bytes changed/)
  const minimalBytes = Buffer.from(JSON.stringify({ driveKey: DRIVE_KEY }))
  assert.throws(() => validatePendingPublishEvidence({ ...pending, publishReportSha256: sha256(minimalBytes) }, minimalBytes), /not a ready strict public/)
  const weak = { ...validPublishReport, durability: { ...validPublishReport.durability, blobs: { ...validPublishReport.durability.blobs, durable: false } } }
  const weakBytes = Buffer.from(JSON.stringify(weak))
  assert.throws(() => validatePendingPublishEvidence({ ...pending, publishReportSha256: sha256(weakBytes) }, weakBytes), /durable full-blob evidence/)
  console.log('✓ resume rejects byte-tampered, minimal, or non-durable publish reports')

  console.log('\n— mode-specific live preflights —')
  const offlineCalls = []
  assert.deepEqual(await runReadonlyLivePreflights({ publish: false, readonly: true, relay: 'https://relay.invalid', runStep: async (step) => offlineCalls.push(step) }), [])
  assert.equal(offlineCalls.length, 0, 'offline ship:check runs no live audit')
  const liveCalls = []
  assert.deepEqual(await runReadonlyLivePreflights({ publish: true, readonly: true, relay: 'https://relay.invalid', runStep: async (step) => liveCalls.push(step) }), ['production-readonly', 'live-legacy-pow', 'live-legacy-actions'])
  assert.deepEqual(liveCalls.map((step) => [step.cmd, ...step.args]), [
    ['node', 'scripts/verify-production-readonly.mjs'],
    ['npm', 'run', 'audit:live-legacy-pow'],
    ['npm', 'run', 'audit:live-legacy-actions']
  ])
  await assert.rejects(
    runReadonlyLivePreflights({
      publish: true,
      readonly: true,
      relay: 'https://relay.invalid',
      runStep: async (step) => { if (step.id === 'live-legacy-pow') throw new Error('audit failed') }
    }),
    /live-legacy-pow preflight failed/
  )
  await assert.rejects(
    runReadonlyLivePreflights({
      publish: true,
      readonly: true,
      relay: 'https://relay.invalid',
      runStep: async (step) => { if (step.id === 'live-legacy-actions') throw new Error('inventory drift') }
    }),
    /live-legacy-actions preflight failed/
  )
  const writableCalls = []
  assert.deepEqual(await runReadonlyLivePreflights({
    publish: true,
    readonly: false,
    relay: 'https://relay.invalid',
    runStep: async (step) => writableCalls.push(step)
  }), ['writable-candidate', 'live-legacy-actions'])
  assert.deepEqual(writableCalls.map((step) => [step.cmd, ...step.args]), [
    ['node', 'scripts/verify-writable-candidate.mjs'],
    ['npm', 'run', 'audit:live-legacy-actions']
  ])
  assert.equal(writableCalls[1].env.PEERIT_RELAY, 'https://relay.invalid')
  await assert.rejects(
    runReadonlyLivePreflights({
      publish: true,
      readonly: false,
      relay: 'https://relay.invalid',
      runStep: async () => { throw new Error('capability missing') }
    }),
    /writable-candidate preflight failed/
  )
  console.log('✓ ship:live requires read-only containment or the writable atomic-capability proof; ship:check stays offline')

  console.log('\n— build once → external sign → verify only —')
  const { parent, fixture } = copyFixture()
  try {
    const configPath = join(fixture, 'deploy', 'web-release.json')
    const config = JSON.parse(readFileSync(configPath, 'utf8'))
    config.readonly = true
    config.relayBackend = ''
    config.relayRosterMirrors = []
    config.dhtRelay = ''
    config.shardRoster = ''
    config.pinnedReleaseKey = publicKeyFromSeed(TEST_SEED)
    writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n')
    const requestPath = join(fixture, 'deploy', 'web-signing-request.json')
    if (existsSync(requestPath)) unlinkSync(requestPath) // isolate from the checkout's tracked prior-release record

    const common = [
      '--strict',
      '--drive-key', DRIVE_KEY,
      '--report', '.deploy/web-report.json'
    ]
    runNode(fixture, ['scripts/web-release.mjs', '--prepare', ...common])

    const manifestPath = join(fixture, 'web', 'asset-manifest.json')
    const signaturePath = join(fixture, 'web', 'asset-manifest.sig')
    const prepareReport = JSON.parse(readFileSync(join(fixture, '.deploy', 'web-report.json'), 'utf8'))
    const request = JSON.parse(readFileSync(requestPath, 'utf8'))
    const builtManifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
    assert.equal(prepareReport.status, 'awaiting-signature')
    assert.equal(request.schema, 'peerit-web-signing-request-v2')
    assert.equal(request.releaseSequence, config.releaseSequence)
    assert.equal(request.driveKey, DRIVE_KEY)
    assert.equal(request.manifestSha256, sha256(readFileSync(manifestPath)))
    const builtIndex = readFileSync(join(fixture, 'web', 'index.html'), 'utf8')
    assert.match(builtIndex, new RegExp(`name="peerit-release-key" content="${config.pinnedReleaseKey}"`))
    assert.match(builtIndex, new RegExp(`name="peerit-release-sequence" content="${config.releaseSequence}"`))
    assert.equal(builtManifest.releaseSequence, config.releaseSequence)
    assert.deepEqual(builtManifest.webRelease, {
      releaseSequence: config.releaseSequence,
      relay: config.bootstrapRelays.join(','),
      relayBackend: config.relayBackend || '',
      readonly: 'true',
      relayRoster: 'relay-roster.json',
      relayRosterKey: config.pinnedRosterKey,
      relayRosterSha256: sha256(readFileSync(join(fixture, 'relay-roster.json'))),
      shardRoster: '',
      shardRosterSha256: '',
      releaseKey: config.pinnedReleaseKey
    })
    assert.deepEqual(Object.keys(builtManifest.controls).sort(), ['sw.js', 'verify.html'])
    assert.equal(builtManifest.controls['sw.js'], sha256(readFileSync(join(fixture, 'web', 'sw.js'))))
    assert.equal(builtManifest.controls['verify.html'], sha256(readFileSync(join(fixture, 'web', 'verify.html'))))
    assert.match(readFileSync(join(fixture, 'web', 'verify.html'), 'utf8'), /m\.controls/)
    assert.equal(existsSync(signaturePath), false)

    // This deterministic test key exists only inside the temporary fixture.
    runNode(fixture, ['scripts/sign-release.mjs'], { env: { PEERIT_RELEASE_SIGNING_SEED: TEST_SEED } })
    const manifestBefore = readFileSync(manifestPath)
    const signatureBefore = readFileSync(signaturePath)
    const sentinel = join(fixture, 'web', '.verify-only-sentinel')
    mkdirSync(sentinel)

    runNode(fixture, ['scripts/web-release.mjs', '--verify-only', ...common])
    const verifyReport = JSON.parse(readFileSync(join(fixture, '.deploy', 'web-report.json'), 'utf8'))
    assert.equal(verifyReport.status, 'ready')
    assert.equal(existsSync(sentinel), true, 'verify-only must not remove/rebuild web/')
    assert.deepEqual(readFileSync(manifestPath), manifestBefore, 'verify-only must not rewrite asset-manifest.json')
    assert.deepEqual(readFileSync(signaturePath), signatureBefore, 'verify-only must not rewrite the returned signature')

    // The default mode is also verify-only, preventing an accidental post-sign build.
    runNode(fixture, ['scripts/web-release.mjs', ...common])
    assert.equal(existsSync(sentinel), true)
    assert.deepEqual(readFileSync(manifestPath), manifestBefore)

    const assetPath = join(fixture, 'web', 'styles.css')
    const assetBefore = readFileSync(assetPath)
    writeFileSync(assetPath, Buffer.concat([assetBefore, Buffer.from('\n/* tampered after signing */\n')]))
    const assetDrift = runNode(fixture, ['scripts/web-release.mjs', '--verify-only', ...common], { expect: 1 })
    assert.match(assetDrift.stdout + assetDrift.stderr, /manifested web asset hash mismatch: styles\.css/)
    assert.equal(existsSync(sentinel), true, 'failed verification must not rebuild the artifact')
    writeFileSync(assetPath, assetBefore)

    const extraPath = join(fixture, 'web', 'unmanifested.js')
    writeFileSync(extraPath, 'throw new Error("must never deploy")\n')
    const extra = runNode(fixture, ['scripts/web-release.mjs', '--verify-only', ...common], { expect: 1 })
    assert.match(extra.stdout + extra.stderr, /unmanifested release file: unmanifested\.js/)
    unlinkSync(extraPath)

    const verifyPagePath = join(fixture, 'web', 'verify.html')
    const verifyPageBefore = readFileSync(verifyPagePath)
    writeFileSync(verifyPagePath, Buffer.concat([verifyPageBefore, Buffer.from('\n<!-- changed after prepare -->\n')]))
    const controlDrift = runNode(fixture, ['scripts/web-release.mjs', '--verify-only', ...common], { expect: 1 })
    assert.match(controlDrift.stdout + controlDrift.stderr, /signed control web asset hash mismatch: verify\.html/)
    writeFileSync(verifyPagePath, verifyPageBefore)

    const changed = JSON.parse(manifestBefore.toString('utf8'))
    changed.note = 'changed after signing'
    writeFileSync(manifestPath, JSON.stringify(changed, null, 2) + '\n')
    const drift = runNode(fixture, ['scripts/web-release.mjs', '--verify-only', ...common], { expect: 1 })
    assert.match(drift.stdout + drift.stderr, /signing request no longer matches|do not rebuild or edit/)
    writeFileSync(manifestPath, manifestBefore)

    unlinkSync(signaturePath)
    const unsigned = runNode(fixture, ['scripts/web-release.mjs', '--verify-only', ...common], { expect: 1 })
    assert.match(unsigned.stdout + unsigned.stderr, /asset-manifest\.sig is missing|required web release file is missing: asset-manifest\.sig/)

    unlinkSync(manifestPath)
    const missing = runNode(fixture, ['scripts/web-release.mjs', '--verify-only', ...common], { expect: 1 })
    assert.match(missing.stdout + missing.stderr, /asset-manifest\.json is missing/)

    // Re-preparing the exact same signed identity is idempotent. Changing any
    // signed file while keeping the tracked sequence must fail and demand a bump.
    runNode(fixture, ['scripts/web-release.mjs', '--prepare', ...common])
    const sourceStyles = join(fixture, 'styles.css')
    writeFileSync(sourceStyles, Buffer.concat([readFileSync(sourceStyles), Buffer.from('\n/* changed signed candidate */\n')]))
    const reusedSequence = runNode(fixture, ['scripts/web-release.mjs', '--prepare', ...common], { expect: 1 })
    assert.match(reusedSequence.stdout + reusedSequence.stderr, /releaseSequence .* already used|increment deploy\/web-release\.json releaseSequence/)
    console.log('✓ verification preserves the signed build and rejects drift, missing signatures, and missing artifacts')
  } finally {
    rmSync(parent, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err.stack || err.message)
  process.exit(1)
})
