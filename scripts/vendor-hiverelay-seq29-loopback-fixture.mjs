#!/usr/bin/env node

// Authoring-only reconstruction of the strictly test-only HiveRelay response
// fixture. Accepted source bytes are read from the pinned Git object graph;
// neither a checkout nor this checker belongs to the production authority.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build, version as esbuildVersion } from 'esbuild'

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_DESTINATION = resolve(
  PROJECT_ROOT, 'test/vendor/hiverelay-seq29-loopback-v1')
const AUTHORITY_NAME = 'authority.json'
const ARTIFACT_NAME = 'protocol-response-fixture-v1.mjs'
const SERVICE_VECTOR_NAME = 'service-descriptor.bin'
const ADMISSION_VECTOR_NAME = 'admission-parameters.bin'
const OUTPUT_NAMES = Object.freeze([
  ADMISSION_VECTOR_NAME,
  AUTHORITY_NAME,
  ARTIFACT_NAME,
  SERVICE_VECTOR_NAME
].sort())
const AUTHORITY_LENGTH = 20742
const AUTHORITY_SHA256 =
  '2290e43b774ca6cb450031d7970e6c719cb3f9def72fa5b347e696ad738acdaf'
const CANDIDATE_COMMIT = 'adeacef07c5de4d17d5ed1389fee7a35095b862f'
const CANDIDATE_TREE = '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'
const SAFE_RELATIVE_PATH = /^(?:[A-Za-z0-9._@-]+\/)*[A-Za-z0-9._@-]+$/
const EXACT_EXPORTS = Object.freeze([
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
const ENTRY_SOURCE = Buffer.from(
  `export {\n${EXACT_EXPORTS.map(name => `  ${name}`).join(',\n')}\n} from './packages/blind-protocol/index.js'\n`)

function fail (message, cause) {
  const error = new Error(message)
  error.code = 'PEERIT_SEQ29_LOOPBACK_FIXTURE_VENDOR_INVALID'
  if (cause !== undefined) error.cause = cause
  throw error
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function option (name) {
  const prefix = `--${name}=`
  const values = process.argv.slice(2).filter(value => value.startsWith(prefix))
  if (values.length !== 1 || values[0].length === prefix.length) {
    fail(`exactly one explicit ${prefix}<absolute-path> is required`)
  }
  const value = values[0].slice(prefix.length)
  if (!isAbsolute(value)) fail(`${prefix} must be absolute`)
  return resolve(value)
}

const argumentsList = process.argv.slice(2)
const checkArguments = argumentsList.filter(value => value === '--check')
if (checkArguments.length > 1) fail('--check must not be repeated')
const check = checkArguments.length === 1
const sourceInput = option('source-root')
const dependencyInput = option('dependency-root')
const destinationArguments = argumentsList.filter(argument =>
  argument.startsWith('--destination-root='))
if (destinationArguments.length > 1) fail('--destination-root= must not be repeated')
const destinationText = destinationArguments[0]?.slice('--destination-root='.length)
if (destinationText != null && (!isAbsolute(destinationText) || destinationText === '')) {
  fail('--destination-root= must name an absolute path')
}
const destinationInput = destinationText == null
  ? DEFAULT_DESTINATION
  : resolve(destinationText)
for (const argument of argumentsList) {
  if (argument !== '--check' &&
      !argument.startsWith('--source-root=') &&
      !argument.startsWith('--dependency-root=') &&
      !argument.startsWith('--destination-root=')) {
    fail(`unknown argument: ${argument}`)
  }
}

function metadataIdentity (value) {
  return [
    value.dev, value.ino, value.mode, value.nlink, value.uid, value.gid,
    value.size, value.mtimeNs, value.ctimeNs
  ].join(':')
}

function authenticatedDirectory (input, label) {
  let supplied
  let canonical
  let metadata
  try {
    supplied = lstatSync(input, { bigint: true })
    canonical = realpathSync(input)
    metadata = lstatSync(canonical, { bigint: true })
  } catch (cause) {
    fail(`${label} is unavailable`, cause)
  }
  if (!supplied.isDirectory() || supplied.isSymbolicLink() ||
      !metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${label} must be a non-symlink directory`)
  }
  return Object.freeze({
    path: canonical,
    identity: metadataIdentity(metadata),
    label
  })
}

function authenticateParents (root, recordPath, identities) {
  const components = dirname(recordPath) === '.'
    ? []
    : dirname(recordPath).split('/')
  let current = root.path
  for (const component of components) {
    current = join(current, component)
    const metadata = lstatSync(current, { bigint: true })
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail(`${root.label} has a symlink or non-directory component: ${recordPath}`)
    }
    const identity = metadataIdentity(metadata)
    if (identities.has(current) && identities.get(current) !== identity) {
      fail(`${root.label} directory changed during authentication: ${recordPath}`)
    }
    identities.set(current, identity)
  }
}

function validRecord (record, requireBlobOid = false) {
  return record != null && SAFE_RELATIVE_PATH.test(record.path) &&
    !record.path.includes('..') && record.mode === '100644' &&
    Number.isInteger(record.bytes) && record.bytes >= 0 &&
    /^[0-9a-f]{64}$/.test(record.sha256) &&
    (!requireBlobOid || /^[0-9a-f]{40}$/.test(record.blobOid))
}

function exactFileRead (root, record, identities) {
  if (!validRecord(record)) fail(`authority inventory record is invalid: ${record?.path}`)
  if (metadataIdentity(lstatSync(root.path, { bigint: true })) !== root.identity) {
    fail(`${root.label} changed during authentication`)
  }
  authenticateParents(root, record.path, identities)
  const input = join(root.path, ...record.path.split('/'))
  let before
  let descriptor
  try {
    before = lstatSync(input, { bigint: true })
    if (realpathSync(input) !== input || !before.isFile() ||
        before.isSymbolicLink() || before.nlink !== 1n ||
        (before.mode & 0o777n) !== 0o644n || before.size !== BigInt(record.bytes) ||
        typeof constants.O_NOFOLLOW !== 'number' || constants.O_NOFOLLOW === 0) {
      fail(`${root.label} input must be a mode-0644 single-link regular file: ${record.path}`)
    }
    descriptor = openSync(input, constants.O_RDONLY | constants.O_NOFOLLOW)
    if (metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
        metadataIdentity(before)) {
      fail(`${root.label} input changed before exact read: ${record.path}`)
    }
    const bytes = Buffer.alloc(record.bytes)
    let offset = 0
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset)
      if (count === 0) break
      offset += count
    }
    const extra = Buffer.alloc(1)
    if (offset !== bytes.length || readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        sha256(bytes) !== record.sha256 ||
        metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
          metadataIdentity(before) ||
        metadataIdentity(lstatSync(input, { bigint: true })) !==
          metadataIdentity(before)) {
      fail(`${root.label} input bytes or identity changed: ${record.path}`)
    }
    return bytes
  } catch (cause) {
    if (cause?.code === 'PEERIT_SEQ29_LOOPBACK_FIXTURE_VENDOR_INVALID') throw cause
    fail(`${root.label} input is unavailable or unsafe: ${record.path}`, cause)
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
}

function gitEnvironment () {
  const env = {}
  for (const [name, value] of Object.entries(process.env)) {
    if (!name.startsWith('GIT_')) env[name] = value
  }
  return {
    ...env,
    PATH: '/usr/bin:/bin',
    GIT_ATTR_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0'
  }
}

function git (source, argumentsValue, options = {}) {
  if (metadataIdentity(lstatSync(source.path, { bigint: true })) !== source.identity) {
    fail('accepted Git source root changed during authentication')
  }
  try {
    return execFileSync('/usr/bin/git', [
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'core.attributesFile=/dev/null',
      '-c', 'filter.lfs.required=false',
      '-c', 'protocol.file.allow=never',
      '-C', source.path,
      ...argumentsValue
    ], {
      encoding: options.encoding,
      env: gitEnvironment(),
      maxBuffer: options.maxBuffer || (32 * 1024 * 1024),
      stdio: ['ignore', 'pipe', 'pipe']
    })
  } catch (cause) {
    fail(`exact accepted Git object is unavailable: ${cause.stderr?.toString().trim() || cause.message}`,
      cause)
  }
}

function exactGitRecord (source, record) {
  if (!validRecord(record, true) || record.kind !== 'accepted-source') {
    fail(`accepted Git inventory record is invalid: ${record?.path}`)
  }
  const line = git(source, ['ls-tree', CANDIDATE_COMMIT, '--', record.path], {
    encoding: 'utf8'
  }).trim()
  const match = /^(\d{6}) blob ([0-9a-f]{40})\t(.+)$/.exec(line)
  if (match == null || match[1] !== record.mode || match[2] !== record.blobOid ||
      match[3] !== record.path ||
      git(source, ['cat-file', '-t', record.blobOid], { encoding: 'utf8' }).trim() !==
        'blob' ||
      Number(git(source, ['cat-file', '-s', record.blobOid], {
        encoding: 'utf8'
      }).trim()) !== record.bytes) {
    fail(`accepted Git blob identity changed: ${record.path}`)
  }
  const bytes = Buffer.from(git(source, ['cat-file', 'blob', record.blobOid]))
  if (bytes.length !== record.bytes || sha256(bytes) !== record.sha256) {
    fail(`accepted Git blob bytes changed: ${record.path}`)
  }
  return bytes
}

function canonicalAuthority (destination) {
  const root = authenticatedDirectory(destination, 'test-only vendor directory')
  if (readdirSync(root.path).sort().join('\0') !== OUTPUT_NAMES.join('\0')) {
    fail('test-only vendor directory has missing or extra files')
  }
  const bytes = exactFileRead(root, {
    path: AUTHORITY_NAME,
    mode: '100644',
    bytes: AUTHORITY_LENGTH,
    sha256: AUTHORITY_SHA256
  }, new Map())
  let authority
  try {
    authority = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch (cause) {
    fail('test-only vendor authority is not UTF-8 JSON', cause)
  }
  if (JSON.stringify(authority, null, 2) + '\n' !== bytes.toString('utf8') ||
      authority.schema !== 'PeeritTestOnlyHiveRelaySeq29LoopbackFixtureV1' ||
      authority.version !== 1 ||
      authority.purpose !== 'test-only-localhost-response-fixture-not-production-authority' ||
      authority.candidateCommit !== CANDIDATE_COMMIT ||
      authority.candidateTree !== CANDIDATE_TREE ||
      authority.artifactPath !==
        'test/vendor/hiverelay-seq29-loopback-v1/protocol-response-fixture-v1.mjs' ||
      authority.entry?.path !== 'peerit-seq29-loopback-fixture-entry.mjs' ||
      authority.entry?.bytes !== ENTRY_SOURCE.length ||
      authority.entry?.sha256 !== sha256(ENTRY_SOURCE) ||
      authority.build?.tool !== 'esbuild' ||
      authority.build?.version !== esbuildVersion ||
      authority.build?.bundle !== true || authority.build?.platform !== 'browser' ||
      authority.build?.format !== 'esm' || authority.build?.target?.join('\0') !== 'es2022' ||
      authority.build?.minify !== true || authority.build?.legalComments !== 'none' ||
      authority.build?.disabledBuiltinImports?.join('\0') !== 'node:crypto' ||
      authority.exactSortedExports?.join('\0') !== EXACT_EXPORTS.join('\0') ||
      !Array.isArray(authority.inputInventory) ||
      !Array.isArray(authority.resolutionManifestInventory) ||
      !Array.isArray(authority.resolutionProbeInventory) ||
      !Array.isArray(authority.vectorInventory) || authority.vectorInventory.length !== 2) {
    fail('test-only vendor authority identity or build contract changed')
  }
  return Object.freeze({ root, bytes, value: Object.freeze(authority) })
}

function authenticateInputs (authority, roots) {
  git(roots.source, ['cat-file', '-e', `${CANDIDATE_COMMIT}^{commit}`])
  if (git(roots.source, ['rev-parse', `${CANDIDATE_COMMIT}^{commit}`], {
    encoding: 'utf8'
  }).trim() !== CANDIDATE_COMMIT ||
      git(roots.source, ['rev-parse', `${CANDIDATE_COMMIT}^{tree}`], {
        encoding: 'utf8'
      }).trim() !== CANDIDATE_TREE) {
    fail('accepted Git commit or tree changed')
  }
  const groups = [
    authority.inputInventory,
    authority.resolutionManifestInventory,
    authority.resolutionProbeInventory,
    authority.vectorInventory
  ]
  const seen = new Set()
  const captured = new Map()
  const dependencyIdentities = new Map()
  for (const records of groups) {
    for (const record of records) {
      const key = `${record.kind}\0${record.path}`
      if (seen.has(key) ||
          (record.kind !== 'accepted-source' && record.kind !== 'dependency')) {
        fail(`authority inventory membership is invalid: ${record.path}`)
      }
      seen.add(key)
      captured.set(key, record.kind === 'accepted-source'
        ? exactGitRecord(roots.source, record)
        : exactFileRead(roots.dependency, record, dependencyIdentities))
    }
  }
  for (const [path, identity] of dependencyIdentities) {
    if (metadataIdentity(lstatSync(path, { bigint: true })) !== identity) {
      fail(`dependency directory changed during authentication: ${path}`)
    }
  }
  if (metadataIdentity(lstatSync(roots.dependency.path, { bigint: true })) !==
      roots.dependency.identity ||
      git(roots.source, ['rev-parse', `${CANDIDATE_COMMIT}^{tree}`], {
        encoding: 'utf8'
      }).trim() !== CANDIDATE_TREE) {
    fail('accepted input roots changed during authentication')
  }
  return captured
}

function materializeSnapshot (snapshotSource, authority, captured) {
  for (const record of [
    ...authority.inputInventory,
    ...authority.resolutionManifestInventory,
    ...authority.resolutionProbeInventory
  ]) {
    const prefix = record.kind === 'dependency'
      ? join(snapshotSource, 'node_modules')
      : snapshotSource
    const output = join(prefix, ...record.path.split('/'))
    mkdirSync(dirname(output), { recursive: true, mode: 0o755 })
    writeFileSync(output, captured.get(`${record.kind}\0${record.path}`), {
      flag: 'wx',
      mode: 0o644
    })
  }
}

function normalizedInput (name, snapshotSource, entryPath) {
  if (name === '(disabled):crypto') return Object.freeze({ disabled: 'node:crypto' })
  const absolute = resolve(name)
  if (absolute === entryPath) return Object.freeze({ entry: true })
  const dependencyRoot = join(snapshotSource, 'node_modules')
  if (absolute.startsWith(dependencyRoot + sep)) {
    return Object.freeze({
      kind: 'dependency',
      path: relative(dependencyRoot, absolute).split(sep).join('/')
    })
  }
  if (absolute.startsWith(snapshotSource + sep)) {
    return Object.freeze({
      kind: 'accepted-source',
      path: relative(snapshotSource, absolute).split(sep).join('/')
    })
  }
  fail(`esbuild reached outside its authenticated snapshot: ${name}`)
}

async function reconstructArtifact (authority, captured) {
  const snapshot = realpathSync(mkdtempSync(join(tmpdir(), 'peerit-seq29-loopback-fixture-')))
  const snapshotSource = join(snapshot, 'source')
  mkdirSync(snapshotSource, { recursive: true, mode: 0o755 })
  try {
    materializeSnapshot(snapshotSource, authority, captured)
    const protocolRoot = join(snapshotSource, 'packages/blind-protocol')
    const protocolManifest = JSON.parse(captured.get(
      'accepted-source\0packages/blind-protocol/package.json').toString('utf8'))
    const entryPath = join(snapshotSource, authority.entry.path)
    const result = await build({
      stdin: {
        contents: ENTRY_SOURCE.toString('utf8'),
        resolveDir: snapshotSource,
        sourcefile: authority.entry.path,
        loader: 'js'
      },
      bundle: true,
      platform: 'browser',
      format: 'esm',
      target: ['es2022'],
      minify: true,
      legalComments: 'none',
      metafile: true,
      write: false,
      outfile: join(snapshot, ARTIFACT_NAME),
      plugins: [{
        name: 'peerit-exact-hiverelay-resolution',
        setup (context) {
          context.onResolve({ filter: /^@hiverelay\/blind-protocol(?:\/.*)?$/ }, args => {
            const suffix = args.path.slice('@hiverelay/blind-protocol'.length)
            const key = suffix === '' ? '.' : `.${suffix}`
            const target = protocolManifest.exports?.[key]
            if (typeof target !== 'string') fail(`unknown protocol export: ${args.path}`)
            return { path: resolve(protocolRoot, target) }
          })
        }
      }]
    })
    if (result.outputFiles.length !== 1) fail('esbuild output membership changed')
    const output = Buffer.from(result.outputFiles[0].contents)
    if (output.length !== authority.artifactLength ||
        sha256(output) !== authority.artifactRawSha256) {
      fail(`deterministic fixture artifact changed: ${output.length}/${sha256(output)}`)
    }
    const executed = []
    const disabled = []
    let entryCount = 0
    for (const [name, metadata] of Object.entries(result.metafile.inputs)) {
      const normalized = normalizedInput(name, snapshotSource, entryPath)
      if (normalized.entry === true) entryCount++
      else if (normalized.disabled != null) disabled.push(normalized.disabled)
      else executed.push(`${normalized.kind}\0${normalized.path}\0${metadata.bytes}`)
    }
    const expected = authority.inputInventory.map(record =>
      `${record.kind}\0${record.path}\0${record.bytes}`)
    if (entryCount !== 1 ||
        disabled.sort().join('\0') !== authority.build.disabledBuiltinImports.join('\0') ||
        executed.sort().join('\n') !== expected.sort().join('\n')) {
      fail('esbuild execution closure changed from the authenticated inventory')
    }
    const outputs = Object.values(result.metafile.outputs)
    if (outputs.length !== 1 ||
        outputs[0].exports?.sort().join('\0') !== EXACT_EXPORTS.join('\0') ||
        Object.keys(outputs[0].inputs || {}).length !==
          authority.inputInventory.length + 2) {
      fail('esbuild output graph or exports changed')
    }
    return output
  } finally {
    rmSync(snapshot, { recursive: true, force: true })
  }
}

function atomicPublish (destination, name, bytes) {
  const temporary = join(destination, `.${name}.${process.pid}.tmp`)
  let created = false
  try {
    writeFileSync(temporary, bytes, { flag: 'wx', mode: 0o644 })
    created = true
    renameSync(temporary, join(destination, name))
    created = false
  } finally {
    if (created) rmSync(temporary, { force: true })
  }
}

const authorityOutput = canonicalAuthority(destinationInput)
const roots = Object.freeze({
  source: authenticatedDirectory(sourceInput, 'accepted Git source root'),
  dependency: authenticatedDirectory(dependencyInput, 'dependency root')
})
const captured = authenticateInputs(authorityOutput.value, roots)
const artifact = await reconstructArtifact(authorityOutput.value, captured)
const vectorOutputs = new Map(authorityOutput.value.vectorInventory.map(record => [
  record.path.endsWith(`/${SERVICE_VECTOR_NAME}`)
    ? SERVICE_VECTOR_NAME
    : ADMISSION_VECTOR_NAME,
  Object.freeze({
    record,
    bytes: captured.get(`${record.kind}\0${record.path}`)
  })
]))
if (vectorOutputs.size !== 2 || !vectorOutputs.has(SERVICE_VECTOR_NAME) ||
    !vectorOutputs.has(ADMISSION_VECTOR_NAME)) {
  fail('test vector output membership changed')
}

if (check) {
  const outputIdentity = authorityOutput.root.identity
  const identities = new Map()
  const vendoredArtifact = exactFileRead(authorityOutput.root, {
    path: ARTIFACT_NAME,
    mode: '100644',
    bytes: authorityOutput.value.artifactLength,
    sha256: authorityOutput.value.artifactRawSha256
  }, identities)
  if (!vendoredArtifact.equals(artifact)) {
    fail('vendored fixture artifact is not the deterministic output')
  }
  for (const [name, value] of vectorOutputs) {
    const vendored = exactFileRead(authorityOutput.root, {
      path: name,
      mode: '100644',
      bytes: value.record.bytes,
      sha256: value.record.sha256
    }, identities)
    if (!vendored.equals(value.bytes)) fail(`vendored test vector changed: ${name}`)
  }
  if (metadataIdentity(lstatSync(authorityOutput.root.path, { bigint: true })) !==
      outputIdentity || readdirSync(authorityOutput.root.path).sort().join('\0') !==
        OUTPUT_NAMES.join('\0')) {
    fail('test-only vendor directory changed during output authentication')
  }
} else {
  atomicPublish(authorityOutput.root.path, ARTIFACT_NAME, artifact)
  for (const [name, value] of vectorOutputs) {
    atomicPublish(authorityOutput.root.path, name, value.bytes)
  }
}

process.stdout.write(`${JSON.stringify(Object.freeze({
  schema: 'PeeritTestOnlyHiveRelaySeq29LoopbackFixtureResultV1',
  checked: check,
  purpose: authorityOutput.value.purpose,
  candidateCommit: CANDIDATE_COMMIT,
  candidateTree: CANDIDATE_TREE,
  artifactLength: artifact.length,
  artifactRawSha256: sha256(artifact),
  authorityRawSha256: sha256(authorityOutput.bytes),
  inputCount: authorityOutput.value.inputInventory.length,
  resolutionManifestCount: authorityOutput.value.resolutionManifestInventory.length,
  resolutionProbeCount: authorityOutput.value.resolutionProbeInventory.length,
  vectorCount: authorityOutput.value.vectorInventory.length
}), null, 2)}\n`)
