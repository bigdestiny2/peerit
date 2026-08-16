import assert from 'node:assert/strict'
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
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const script = join(root, 'scripts/vendor-hiverelay-seq29-inbox-operator.mjs')
const vendor = join(root, 'scripts/vendor/hiverelay-seq29-inbox-operator-v1')
const authority = JSON.parse(readFileSync(join(vendor, 'authority.json'), 'utf8'))
const sourceRoot = realpathSync(resolve(
  process.env.HIVERELAY_BLIND_ROOT ||
  '/private/tmp/peerit-hiverelay-adeacef-audit.rYnmQt/source'))
const dependencyRoot = realpathSync(resolve(
  process.env.HIVERELAY_SEQ29_DEPENDENCY_ROOT || join(sourceRoot, 'node_modules')))
const resolutionProbes = Object.freeze([
  Object.freeze({ kind: 'accepted-source', path: 'packages/blind-client/crypto.js' }),
  Object.freeze({ kind: 'accepted-source', path: 'packages/blind-protocol/crypto.js' })
])

function invoke ({ source = sourceRoot, dependency = dependencyRoot, destination = vendor } = {}) {
  return spawnSync(process.execPath, [
    script,
    '--check',
    `--source-root=${source}`,
    `--dependency-root=${dependency}`,
    `--destination-root=${destination}`
  ], { encoding: 'utf8' })
}

function expectOk (input, label) {
  const result = invoke(input)
  assert.equal(result.status, 0, `${label}: ${result.stderr}`)
  const decoded = JSON.parse(result.stdout)
  assert.equal(decoded.checked, true)
  assert.equal(decoded.artifactRawSha256,
    '141e2aadf686fb80cf43d65fd7451f673841f62586e3ffebb75bf7a03ea4a2cb')
}

function expectInvalid (input, pattern, label) {
  const result = invoke(input)
  assert.notEqual(result.status, 0, label)
  assert.match(`${result.stderr}\n${result.stdout}`, pattern, label)
}

expectOk({}, 'the exact accepted source and dependency roots must reproduce the vendor')

const fixture = mkdtempSync(join(tmpdir(), 'peerit-seq29-inbox-operator-vendor-test-'))
const fixtureSource = join(fixture, 'source')
const fixtureDependency = join(fixture, 'node_modules')
const fixtureVendor = join(fixture, 'vendor')

function location (record, source = fixtureSource, dependency = fixtureDependency) {
  return join(record.kind === 'accepted-source' ? source : dependency, record.path)
}

function original (record) {
  return join(record.kind === 'accepted-source' ? sourceRoot : dependencyRoot, record.path)
}

function copyRecord (record) {
  const output = location(record)
  rmSync(output, { force: true })
  mkdirSync(dirname(output), { recursive: true })
  copyFileSync(original(record), output)
  chmodSync(output, 0o644)
}

try {
  for (const record of [
    ...authority.inputInventory,
    ...authority.resolutionManifestInventory,
    ...resolutionProbes
  ]) copyRecord(record)
  mkdirSync(fixtureVendor, { recursive: true })
  for (const name of ['authority.json', 'seq29-inbox-operator-v1.mjs']) {
    copyFileSync(join(vendor, name), join(fixtureVendor, name))
    chmodSync(join(fixtureVendor, name), 0o644)
  }

  const fixtureInput = {
    source: fixtureSource,
    dependency: fixtureDependency,
    destination: fixtureVendor
  }
  expectOk(fixtureInput, 'an isolated authenticated byte fixture must reproduce')

  const deepSource = authority.inputInventory.find(record =>
    record.path === 'packages/blind-protocol/schema-catalog-runtime-authority.js')
  const deepSourcePath = location(deepSource)
  const deepSourceBytes = readFileSync(deepSourcePath)
  deepSourceBytes[Math.floor(deepSourceBytes.length / 2)] ^= 1
  writeFileSync(deepSourcePath, deepSourceBytes)
  expectInvalid(fixtureInput, /input bytes or identity changed/,
    'a flipped deep accepted source must fail before build')
  copyRecord(deepSource)

  const deepDependency = authority.inputInventory.find(record =>
    record.path === 'sodium-javascript/internal/ed25519.js')
  const deepDependencyPath = location(deepDependency)
  const deepDependencyBytes = readFileSync(deepDependencyPath)
  deepDependencyBytes[Math.floor(deepDependencyBytes.length / 2)] ^= 1
  writeFileSync(deepDependencyPath, deepDependencyBytes)
  expectInvalid(fixtureInput, /input bytes or identity changed/,
    'a flipped deep dependency source must fail before build')
  copyRecord(deepDependency)

  const packageManifest = authority.resolutionManifestInventory.find(record =>
    record.path === 'sodium-javascript/package.json')
  const packageBytes = readFileSync(location(packageManifest))
  packageBytes[Math.floor(packageBytes.length / 2)] ^= 1
  writeFileSync(location(packageManifest), packageBytes)
  expectInvalid(fixtureInput, /input bytes or identity changed/,
    'a flipped resolution package manifest must fail before build')
  copyRecord(packageManifest)

  const missing = authority.inputInventory.find(record =>
    record.path === 'sha512-wasm/sha512.js')
  unlinkSync(location(missing))
  expectInvalid(fixtureInput, /input is unavailable or unsafe/,
    'a missing transitive input must fail closed')
  copyRecord(missing)

  const symlink = authority.inputInventory.find(record =>
    record.path === 'b4a/lib/base64.js')
  unlinkSync(location(symlink))
  symlinkSync(original(symlink), location(symlink))
  expectInvalid(fixtureInput, /single-link regular file/,
    'a symlinked transitive input must fail closed')
  copyRecord(symlink)

  const hardLinked = authority.inputInventory.find(record =>
    record.path === 'nanoassert/index.js')
  const hardLink = `${location(hardLinked)}.second-link`
  linkSync(location(hardLinked), hardLink)
  expectInvalid(fixtureInput, /single-link regular file/,
    'a multiply-linked input must fail closed')
  unlinkSync(hardLink)

  const wrongMode = authority.inputInventory.find(record =>
    record.path === 'b4a/lib/hex.js')
  chmodSync(location(wrongMode), 0o600)
  expectInvalid(fixtureInput, /mode-0644 single-link regular file/,
    'a transitive input with changed mode must fail closed')
  chmodSync(location(wrongMode), 0o644)

  const authorityPath = join(fixtureVendor, 'authority.json')
  const authorityBytes = readFileSync(authorityPath)
  authorityBytes[Math.floor(authorityBytes.length / 2)] ^= 1
  writeFileSync(authorityPath, authorityBytes)
  expectInvalid(fixtureInput, /input bytes or identity changed/,
    'a flipped authority must fail check mode')
  copyFileSync(join(vendor, 'authority.json'), authorityPath)
  chmodSync(authorityPath, 0o644)

  unlinkSync(join(fixtureVendor, 'seq29-inbox-operator-v1.mjs'))
  expectInvalid(fixtureInput, /missing or extra files/,
    'a missing vendored output must fail check mode')
  copyFileSync(join(vendor, 'seq29-inbox-operator-v1.mjs'),
    join(fixtureVendor, 'seq29-inbox-operator-v1.mjs'))
  chmodSync(join(fixtureVendor, 'seq29-inbox-operator-v1.mjs'), 0o644)

  writeFileSync(join(fixtureVendor, 'unexpected.js'), 'export default 1\n', { mode: 0o644 })
  expectInvalid(fixtureInput, /missing or extra files/,
    'an extra vendored output must fail check mode')
  unlinkSync(join(fixtureVendor, 'unexpected.js'))

  expectOk(fixtureInput, 'the restored fixture must reproduce again')
} finally {
  rmSync(fixture, { recursive: true, force: true })
}

const runtimeSource = readFileSync(
  join(root, 'scripts/lib/seq29-accepted-hiverelay-operator.mjs'), 'utf8')
const executableRuntimeSource = runtimeSource
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '')
assert.doesNotMatch(executableRuntimeSource, /node:child_process/)
assert.doesNotMatch(executableRuntimeSource, /\b(?:execFile|spawn|fork)\w*\b/)
assert.doesNotMatch(executableRuntimeSource, /\b(?:git|Git)\b/)
assert.doesNotMatch(executableRuntimeSource, /\b(?:sourceRoot|hiverelaySourceRoot)\b/)
assert.match(executableRuntimeSource, /import\(dataModuleUrl\(operatorBytes\)\)/,
  'runtime must import the same authenticated artifact bytes')

console.log('peerit Seq29 inbox operator vendor: exact reconstruction and hostile source/output checks ok')
