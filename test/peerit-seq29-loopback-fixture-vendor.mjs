import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  loadPeeritSeq29ExactLoopbackProtocolFixtureV1
} from './lib/seq29-exact-loopback-protocol-fixture.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const script = join(root, 'scripts/vendor-hiverelay-seq29-loopback-fixture.mjs')
const loader = join(root, 'test/lib/seq29-exact-loopback-protocol-fixture.mjs')
const vendor = join(root, 'test/vendor/hiverelay-seq29-loopback-v1')
const authority = JSON.parse(readFileSync(join(vendor, 'authority.json'), 'utf8'))
const sourceRoot = realpathSync(resolve(
  process.env.HIVERELAY_BLIND_ROOT ||
  '/private/tmp/peerit-hiverelay-adeacef-audit.rYnmQt/source'))
const dependencyRoot = realpathSync(resolve(
  process.env.HIVERELAY_SEQ29_DEPENDENCY_ROOT ||
  '/Users/localllm/.pear-wt/s29artifact5/node_modules'))
const exactExports = Object.freeze([
  'ADVERTISED_OPERATION_BITS',
  'FAMILY',
  'FRAME_KIND',
  'INBOX_RECEIPT_RESULT',
  'OPERATION',
  'PROTOCOL',
  'RESULT_SIGNATURE_DOMAIN_ID',
  'admissionParametersHash',
  'admissionParametersV1',
  'blindAdmissionParametersRequestV1',
  'blindDescribeGetV1',
  'blindHealthChallengeV1',
  'blindHealthResultV1',
  'blindServiceDescriptorV1',
  'blake2b256',
  'decodeCanonical',
  'decodeOuterEnvelope',
  'durabilityContinuityBindingV1',
  'durabilityContinuityHash',
  'durabilityProfileHash',
  'durabilityProfileV1',
  'encodeCanonical',
  'encodeDispatchFrame',
  'encodeOuterEnvelope',
  'inboxCreateCommitment',
  'inboxCreateRequestCommitment',
  'inboxCreateV1',
  'inboxReceiptV1',
  'resultSignaturePayload',
  'serviceDescriptorHash'
].sort())
const outputNames = Object.freeze([
  'admission-parameters.bin',
  'authority.json',
  'protocol-response-fixture-v1.mjs',
  'service-descriptor.bin'
])

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function invoke ({
  source = sourceRoot,
  dependency = dependencyRoot,
  destination = vendor,
  env = process.env
} = {}) {
  return spawnSync(process.execPath, [
    script,
    '--check',
    `--source-root=${source}`,
    `--dependency-root=${dependency}`,
    `--destination-root=${destination}`
  ], { encoding: 'utf8', env })
}

function expectOk (input, label) {
  const result = invoke(input)
  assert.equal(result.status, 0, `${label}: ${result.stderr}`)
  const decoded = JSON.parse(result.stdout)
  assert.equal(decoded.checked, true)
  assert.equal(decoded.purpose,
    'test-only-localhost-response-fixture-not-production-authority')
  assert.equal(decoded.artifactRawSha256,
    '36ec4f9d202742c1008568f47a4cd235b82f30d8c0bc95c6117dd4f665376bd3')
}

function expectInvalid (input, pattern, label) {
  const result = invoke(input)
  assert.notEqual(result.status, 0, label)
  assert.match(`${result.stderr}\n${result.stdout}`, pattern, label)
}

function copyDependencyRecord (record, destination) {
  const output = join(destination, ...record.path.split('/'))
  rmSync(output, { force: true })
  mkdirSync(dirname(output), { recursive: true })
  copyFileSync(join(dependencyRoot, ...record.path.split('/')), output)
  chmodSync(output, 0o644)
}

function copyVendor (destination) {
  mkdirSync(destination, { recursive: true })
  for (const name of outputNames) {
    copyFileSync(join(vendor, name), join(destination, name))
    chmodSync(join(destination, name), 0o644)
  }
}

function poisonPackedBlob (repository, record) {
  const packDirectory = join(repository, '.git/objects/pack')
  const indexes = execFileSync('/usr/bin/find', [
    packDirectory, '-type', 'f', '-name', '*.idx'
  ], { encoding: 'utf8' }).trim().split('\n').filter(Boolean)
  for (const index of indexes) {
    const inventory = execFileSync('/usr/bin/git', [
      'verify-pack', '-v', index
    ], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
    const line = inventory.split('\n').find(value =>
      value.startsWith(`${record.blobOid} `))
    if (line == null) continue
    const fields = line.trim().split(/\s+/)
    const storedLength = Number(fields[3])
    const offset = Number(fields[4])
    assert.equal(Number.isSafeInteger(storedLength) && storedLength > 4, true)
    assert.equal(Number.isSafeInteger(offset) && offset >= 0, true)
    const pack = index.replace(/\.idx$/, '.pack')
    const original = readFileSync(pack)
    const changed = Buffer.from(original)
    changed[offset + Math.floor(storedLength / 2)] ^= 1
    chmodSync(pack, 0o644)
    writeFileSync(pack, changed)
    return () => {
      writeFileSync(pack, original)
      chmodSync(pack, 0o444)
    }
  }
  throw new Error(`packed test object is unavailable: ${record.blobOid}`)
}

async function importFixtureLoader (fixtureRoot, tag) {
  const module = await import(`${pathToFileURL(join(
    fixtureRoot, 'test/lib/seq29-exact-loopback-protocol-fixture.mjs')).href}?${tag}`)
  return module.loadPeeritSeq29ExactLoopbackProtocolFixtureV1()
}

expectOk({}, 'the exact accepted Git objects and dependencies must reproduce')

const accepted = await loadPeeritSeq29ExactLoopbackProtocolFixtureV1()
assert.deepEqual(Object.keys(accepted.protocol).sort(), exactExports)
assert.equal(accepted.authority.purpose,
  'test-only-localhost-response-fixture-not-production-authority')
assert.equal(accepted.serviceDescriptorVector.byteLength, 1371)
assert.equal(accepted.admissionParametersVector.byteLength, 242)
assert.equal(accepted.protocol.decodeCanonical(
  accepted.protocol.blindServiceDescriptorV1,
  accepted.serviceDescriptorVector
).version, 1)
assert.equal(accepted.protocol.decodeCanonical(
  accepted.protocol.admissionParametersV1,
  accepted.admissionParametersVector
).version, 1)
accepted.serviceDescriptorVector[0] ^= 1
const fresh = await loadPeeritSeq29ExactLoopbackProtocolFixtureV1()
assert.equal(sha256(fresh.serviceDescriptorVector),
  'ce46d09e84f9d030e6834713988172556ec4e07901293577eb844a1c92e47973',
  'callers must receive fresh vector bytes rather than cached mutable authority')

const executableLoader = readFileSync(loader, 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '')
assert.doesNotMatch(executableLoader, /node:child_process|\b(?:execFile|spawn|fork)\w*\b/)
assert.doesNotMatch(executableLoader, /\b(?:git|Git|sourceRoot)\b/)
assert.match(executableLoader, /import\(dataModuleUrl\(artifactBytes\)\)/)
for (const productionPath of [
  join(root, 'scripts/lib'),
  join(root, 'js/substrate')
]) {
  const result = spawnSync('rg', [
    '-n',
    'seq29-exact-loopback-protocol-fixture|hiverelay-seq29-loopback-v1',
    productionPath
  ], { encoding: 'utf8' })
  assert.equal(result.status, 1,
    `production authority must not import the test fixture: ${result.stdout}`)
}

const fixture = mkdtempSync(join(tmpdir(), 'peerit-seq29-loopback-vendor-test-'))
const fixtureSource = join(fixture, 'source')
const fixtureDependency = join(fixture, 'node_modules')
const fixtureVendor = join(fixture, 'vendor')
const runtimeRoot = join(fixture, 'runtime')
const runtimeLoader = join(
  runtimeRoot, 'test/lib/seq29-exact-loopback-protocol-fixture.mjs')
const runtimeVendor = join(runtimeRoot, 'test/vendor/hiverelay-seq29-loopback-v1')

try {
  execFileSync('/usr/bin/git', [
    'clone', '--no-local', '--no-checkout', '--quiet', sourceRoot, fixtureSource
  ], { stdio: 'pipe' })
  const dependencyRecords = new Map([
    ...authority.inputInventory,
    ...authority.resolutionManifestInventory
  ].filter(record => record.kind === 'dependency').map(record =>
    [record.path, record]))
  for (const record of dependencyRecords.values()) {
    copyDependencyRecord(record, fixtureDependency)
  }
  copyVendor(fixtureVendor)

  const deepWorktreePath = join(
    fixtureSource, 'packages/blind-protocol/schema-catalog-runtime-authority.js')
  mkdirSync(dirname(deepWorktreePath), { recursive: true })
  writeFileSync(deepWorktreePath, 'throw new Error("raw worktree execution")\n', {
    mode: 0o644
  })

  const sentinel = join(fixture, 'git-sentinel')
  const poisonBin = join(fixture, 'poison-bin')
  const poisonHome = join(fixture, 'poison-home')
  const poisonHooks = join(fixture, 'poison-hooks')
  mkdirSync(poisonBin)
  mkdirSync(poisonHome)
  mkdirSync(poisonHooks)
  const poisonCommand = `#!/bin/sh\nprintf poison > ${JSON.stringify(sentinel)}\nexit 97\n`
  writeFileSync(join(poisonBin, 'git'), poisonCommand, { mode: 0o755 })
  writeFileSync(join(poisonHooks, 'post-checkout'), poisonCommand, { mode: 0o755 })
  writeFileSync(join(poisonHome, '.gitconfig'), [
    '[core]',
    `\thooksPath = ${poisonHooks}`,
    `\tfsmonitor = ${join(poisonBin, 'git')}`,
    '[filter "lfs"]',
    `\tclean = ${join(poisonBin, 'git')}`,
    `\tsmudge = ${join(poisonBin, 'git')}`,
    '\trequired = true',
    ''
  ].join('\n'), { mode: 0o644 })
  expectOk({
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor,
    env: {
      ...process.env,
      PATH: `${poisonBin}:${process.env.PATH || ''}`,
      HOME: poisonHome,
      GIT_CONFIG_GLOBAL: join(poisonHome, '.gitconfig'),
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'core.fsmonitor',
      GIT_CONFIG_VALUE_0: join(poisonBin, 'git'),
      GIT_ALTERNATE_OBJECT_DIRECTORIES: join(fixture, 'poison-objects'),
      GIT_DIR: join(fixture, 'poison-git-dir'),
      GIT_OBJECT_DIRECTORY: join(fixture, 'poison-objects'),
      GIT_REPLACE_REF_BASE: 'refs/poison-replacements',
      GIT_WORK_TREE: join(fixture, 'poison-worktree')
    }
  }, 'hostile Git routing/config/hooks/filters/PATH and raw worktree drift must be inert')
  assert.throws(() => readFileSync(sentinel), error => error.code === 'ENOENT',
    'no hostile Git command, hook, filter or fsmonitor may execute')

  const deepSource = authority.inputInventory.find(record =>
    record.path === 'packages/blind-protocol/schema-catalog-runtime-authority.js')
  const restoreDeepSource = poisonPackedBlob(fixtureSource, deepSource)
  expectInvalid({
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor
  }, /(?:exact accepted Git object is unavailable|accepted Git blob bytes changed)/,
  'a one-byte deep accepted Git object drift must fail closed')
  restoreDeepSource()

  const sourceManifest = authority.resolutionManifestInventory.find(record =>
    record.path === 'packages/blind-protocol/package.json')
  const restoreManifest = poisonPackedBlob(fixtureSource, sourceManifest)
  expectInvalid({
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor
  }, /(?:exact accepted Git object is unavailable|accepted Git blob bytes changed)/,
  'a one-byte accepted source manifest drift must fail closed')
  restoreManifest()

  const deepDependency = authority.inputInventory.find(record =>
    record.path === 'sodium-javascript/internal/ed25519.js')
  const deepDependencyPath = join(fixtureDependency, deepDependency.path)
  const deepDependencyBytes = readFileSync(deepDependencyPath)
  deepDependencyBytes[Math.floor(deepDependencyBytes.length / 2)] ^= 1
  writeFileSync(deepDependencyPath, deepDependencyBytes)
  expectInvalid({
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor
  }, /dependency root input bytes or identity changed/,
  'a one-byte deep dependency drift must fail closed')
  copyDependencyRecord(deepDependency, fixtureDependency)

  const dependencyManifest = authority.resolutionManifestInventory.find(record =>
    record.path === 'compact-encoding/package.json')
  const dependencyManifestPath = join(fixtureDependency, dependencyManifest.path)
  const dependencyManifestBytes = readFileSync(dependencyManifestPath)
  dependencyManifestBytes[Math.floor(dependencyManifestBytes.length / 2)] ^= 1
  writeFileSync(dependencyManifestPath, dependencyManifestBytes)
  expectInvalid({
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor
  }, /dependency root input bytes or identity changed/,
  'a one-byte dependency manifest drift must fail closed')
  copyDependencyRecord(dependencyManifest, fixtureDependency)

  const linkedDependency = authority.inputInventory.find(record =>
    record.path === 'nanoassert/index.js')
  const linkedDependencyPath = join(fixtureDependency, linkedDependency.path)
  const secondLink = `${linkedDependencyPath}.second-link`
  linkSync(linkedDependencyPath, secondLink)
  expectInvalid({
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor
  }, /single-link regular file/,
  'a multiply-linked dependency input must fail closed')
  unlinkSync(secondLink)

  const symlinkDependency = authority.inputInventory.find(record =>
    record.path === 'b4a/lib/base64.js')
  const symlinkDependencyPath = join(fixtureDependency, symlinkDependency.path)
  unlinkSync(symlinkDependencyPath)
  symlinkSync(join(dependencyRoot, symlinkDependency.path), symlinkDependencyPath)
  expectInvalid({
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor
  }, /single-link regular file/,
  'a symlinked dependency input must fail closed')
  copyDependencyRecord(symlinkDependency, fixtureDependency)

  mkdirSync(dirname(runtimeLoader), { recursive: true })
  copyFileSync(loader, runtimeLoader)
  chmodSync(runtimeLoader, 0o644)
  copyVendor(runtimeVendor)
  await importFixtureLoader(runtimeRoot, 'accepted')

  const vectorPath = join(runtimeVendor, 'service-descriptor.bin')
  const vectorBytes = readFileSync(vectorPath)
  vectorBytes[Math.floor(vectorBytes.length / 2)] ^= 1
  writeFileSync(vectorPath, vectorBytes)
  await assert.rejects(importFixtureLoader(runtimeRoot, 'vector-drift'),
    error => error.code === 'PEERIT_SEQ29_LOOPBACK_FIXTURE_INVALID',
    'a one-byte vendored vector drift must fail closed')
  copyFileSync(join(vendor, 'service-descriptor.bin'), vectorPath)
  chmodSync(vectorPath, 0o644)

  const artifactPath = join(runtimeVendor, 'protocol-response-fixture-v1.mjs')
  const artifactBytes = readFileSync(artifactPath)
  artifactBytes[Math.floor(artifactBytes.length / 2)] ^= 1
  writeFileSync(artifactPath, artifactBytes)
  await assert.rejects(importFixtureLoader(runtimeRoot, 'artifact-drift'),
    error => error.code === 'PEERIT_SEQ29_LOOPBACK_FIXTURE_INVALID',
    'a one-byte artifact mutation must fail before authenticated import')
  copyFileSync(join(vendor, 'protocol-response-fixture-v1.mjs'), artifactPath)
  chmodSync(artifactPath, 0o644)

  const missing = join(runtimeVendor, 'admission-parameters.bin')
  unlinkSync(missing)
  await assert.rejects(importFixtureLoader(runtimeRoot, 'missing'),
    /membership or identity changed/,
    'a missing vendored fixture output must fail closed')
  copyFileSync(join(vendor, 'admission-parameters.bin'), missing)
  chmodSync(missing, 0o644)

  const extra = join(runtimeVendor, 'unexpected.js')
  writeFileSync(extra, 'export default 1\n', { mode: 0o644 })
  await assert.rejects(importFixtureLoader(runtimeRoot, 'extra'),
    /membership or identity changed/,
    'an extra vendored fixture output must fail closed')
  unlinkSync(extra)

  const symlinkOutput = join(runtimeVendor, 'admission-parameters.bin')
  unlinkSync(symlinkOutput)
  symlinkSync(join(vendor, 'admission-parameters.bin'), symlinkOutput)
  await assert.rejects(importFixtureLoader(runtimeRoot, 'symlink'),
    /single-link mode-0644 regular file/,
    'a symlinked vendored fixture output must fail closed')
  unlinkSync(symlinkOutput)
  copyFileSync(join(vendor, 'admission-parameters.bin'), symlinkOutput)
  chmodSync(symlinkOutput, 0o644)

  const hardLink = join(fixture, 'fixture-hard-link')
  linkSync(join(runtimeVendor, 'protocol-response-fixture-v1.mjs'), hardLink)
  await assert.rejects(importFixtureLoader(runtimeRoot, 'hard-link'),
    /single-link mode-0644 regular file/,
    'a multiply-linked vendored fixture output must fail closed')
  unlinkSync(hardLink)
  await importFixtureLoader(runtimeRoot, 'restored')
} finally {
  rmSync(fixture, { recursive: true, force: true })
}

console.log('peerit Seq29 loopback fixture vendor: exact Git-object reconstruction, authenticated data import, hostile source/dependency/vector/output checks ok')
