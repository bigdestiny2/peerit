#!/usr/bin/env node

// Authoring-only deterministic reconstruction of the frozen Seq29 inbox
// operator. Production loads only the authenticated vendored bytes and never
// reaches either source root supplied here.

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
  PROJECT_ROOT, 'scripts/vendor/hiverelay-seq29-inbox-operator-v1')
const AUTHORITY_NAME = 'authority.json'
const ARTIFACT_NAME = 'seq29-inbox-operator-v1.mjs'
const OUTPUT_NAMES = Object.freeze([AUTHORITY_NAME, ARTIFACT_NAME])
const AUTHORITY_LENGTH = 11255
const AUTHORITY_SHA256 =
  '432fb47f55796384ced05fefbca89e18bd55ce9a74ae52d6d60200a15e0ad000'
const CANDIDATE_COMMIT = 'adeacef07c5de4d17d5ed1389fee7a35095b862f'
const CANDIDATE_TREE = '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'
const ENTRY_SOURCE = Buffer.from(
  "export { createInboxReplica, destroyInboxWriteCapability } from './packages/blind-client/inbox.js'\n")
const SAFE_RELATIVE_PATH = /^(?:[A-Za-z0-9._@-]+\/)*[A-Za-z0-9._@-]+$/
// esbuild verifies the original relative target exists before applying each
// authenticated package.json browser substitution. These two files never enter
// the execution graph, but their exact identities are still pinned here.
const RESOLUTION_PROBES = Object.freeze([
  Object.freeze({
    kind: 'accepted-source',
    path: 'packages/blind-client/crypto.js',
    mode: '100644',
    bytes: 61,
    sha256: 'fc263cc04cb48ae94094a3fe2fc6a57bd459f07d6573177c2c4caeb97c52c00e'
  }),
  Object.freeze({
    kind: 'accepted-source',
    path: 'packages/blind-protocol/crypto.js',
    mode: '100644',
    bytes: 61,
    sha256: 'fc263cc04cb48ae94094a3fe2fc6a57bd459f07d6573177c2c4caeb97c52c00e'
  })
])

function fail (message, cause) {
  const error = new Error(message)
  error.code = 'PEERIT_SEQ29_INBOX_OPERATOR_VENDOR_INVALID'
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
const destinationOptions = argumentsList
  .filter(value => value.startsWith('--destination-root='))
if (destinationOptions.length > 1) fail('--destination-root= must not be repeated')
const destinationOption = destinationOptions[0]
const destinationInput = destinationOption == null
  ? DEFAULT_DESTINATION
  : resolve(destinationOption.slice('--destination-root='.length))
if (destinationOption != null &&
    (!isAbsolute(destinationOption.slice('--destination-root='.length)) ||
     destinationOption.length === '--destination-root='.length)) {
  fail('--destination-root= must name an absolute path')
}
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

function authenticatedRoot (input, label) {
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
      fail(`${root.label} has a symlink or non-directory path component: ${recordPath}`)
    }
    const identity = metadataIdentity(metadata)
    const prior = identities.get(current)
    if (prior != null && prior !== identity) {
      fail(`${root.label} directory changed during authentication: ${recordPath}`)
    }
    identities.set(current, identity)
  }
}

function exactReadRecord (root, record, identities) {
  if (!SAFE_RELATIVE_PATH.test(record.path) || record.path.includes('..') ||
      record.mode !== '100644' || !Number.isInteger(record.bytes) ||
      record.bytes < 0 || !/^[0-9a-f]{64}$/.test(record.sha256)) {
    fail(`authority inventory record is invalid: ${record.path}`)
  }
  if (metadataIdentity(lstatSync(root.path, { bigint: true })) !== root.identity) {
    fail(`${root.label} changed during authentication`)
  }
  authenticateParents(root, record.path, identities)
  const path = join(root.path, ...record.path.split('/'))
  let before
  let descriptor
  try {
    before = lstatSync(path, { bigint: true })
    if (realpathSync(path) !== path || !before.isFile() ||
        before.isSymbolicLink() || before.nlink !== 1n ||
        (before.mode & 0o777n) !== 0o644n ||
        before.size !== BigInt(record.bytes) ||
        typeof constants.O_NOFOLLOW !== 'number' || constants.O_NOFOLLOW === 0) {
      fail(`${root.label} input must be a mode-0644 single-link regular file: ${record.path}`)
    }
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
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
    if (offset !== bytes.length ||
        readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        sha256(bytes) !== record.sha256 ||
        metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
          metadataIdentity(before) ||
        metadataIdentity(lstatSync(path, { bigint: true })) !==
          metadataIdentity(before)) {
      fail(`${root.label} input bytes or identity changed: ${record.path}`)
    }
    return bytes
  } catch (cause) {
    if (cause?.code === 'PEERIT_SEQ29_INBOX_OPERATOR_VENDOR_INVALID') throw cause
    fail(`${root.label} input is unavailable or unsafe: ${record.path}`, cause)
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
}

function authenticateInventory (authority, roots) {
  const records = [
    ...authority.inputInventory,
    ...authority.resolutionManifestInventory,
    ...RESOLUTION_PROBES
  ]
  const seen = new Set()
  const identities = new Map()
  const captured = new Map()
  for (const record of records) {
    const key = `${record.kind}\0${record.path}`
    if (seen.has(key) ||
        (record.kind !== 'accepted-source' && record.kind !== 'dependency')) {
      fail(`authority inventory membership is invalid: ${record.path}`)
    }
    seen.add(key)
    const root = record.kind === 'accepted-source' ? roots.source : roots.dependency
    captured.set(key, exactReadRecord(root, record, identities))
  }
  for (const [path, identity] of identities) {
    if (metadataIdentity(lstatSync(path, { bigint: true })) !== identity) {
      fail(`input directory changed during authentication: ${path}`)
    }
  }
  for (const root of Object.values(roots)) {
    if (metadataIdentity(lstatSync(root.path, { bigint: true })) !== root.identity) {
      fail(`${root.label} changed during authentication`)
    }
  }
  return captured
}

function canonicalAuthority (destination) {
  const root = authenticatedRoot(destination, 'vendored output directory')
  const record = Object.freeze({
    path: AUTHORITY_NAME,
    mode: '100644',
    bytes: AUTHORITY_LENGTH,
    sha256: AUTHORITY_SHA256
  })
  const bytes = exactReadRecord(root, record, new Map())
  let authority
  try {
    authority = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch (cause) {
    fail('vendored authority is not UTF-8 JSON', cause)
  }
  if (JSON.stringify(authority, null, 2) + '\n' !== bytes.toString('utf8') ||
      authority.schema !== 'PeeritVendoredHiveRelaySeq29InboxOperatorV1' ||
      authority.version !== 1 || authority.candidateCommit !== CANDIDATE_COMMIT ||
      authority.candidateTree !== CANDIDATE_TREE ||
      authority.artifactPath !==
        'scripts/vendor/hiverelay-seq29-inbox-operator-v1/seq29-inbox-operator-v1.mjs' ||
      authority.entry?.bytes !== ENTRY_SOURCE.length ||
      authority.entry?.sha256 !== sha256(ENTRY_SOURCE) ||
      authority.build?.tool !== 'esbuild' ||
      authority.build?.version !== esbuildVersion ||
      authority.build?.bundle !== true || authority.build?.platform !== 'browser' ||
      authority.build?.format !== 'esm' ||
      authority.build?.target?.join('\0') !== 'es2022' ||
      authority.build?.minify !== true ||
      authority.build?.legalComments !== 'none' ||
      authority.build?.disabledBuiltinImports?.join('\0') !== 'node:crypto' ||
      authority.exactSortedExports?.join('\0') !==
        'createInboxReplica\0destroyInboxWriteCapability' ||
      !Array.isArray(authority.inputInventory) ||
      !Array.isArray(authority.resolutionManifestInventory)) {
    fail('vendored authority identity or build contract changed')
  }
  return Object.freeze({ root, bytes, value: Object.freeze(authority) })
}

function materializeSnapshot (snapshotSource, authority, captured) {
  for (const record of [
    ...authority.inputInventory,
    ...authority.resolutionManifestInventory,
    ...RESOLUTION_PROBES
  ]) {
    const key = `${record.kind}\0${record.path}`
    const prefix = record.kind === 'dependency'
      ? join(snapshotSource, 'node_modules')
      : snapshotSource
    const output = join(prefix, ...record.path.split('/'))
    mkdirSync(dirname(output), { recursive: true, mode: 0o755 })
    writeFileSync(output, captured.get(key), { flag: 'wx', mode: 0o644 })
  }
}

function normalizedMetafileInput (name, snapshotSource, entryPath) {
  if (name === '(disabled):crypto') return Object.freeze({ disabled: 'node:crypto' })
  const absolute = resolve(name)
  if (absolute === entryPath) return Object.freeze({ entry: true })
  const dependencyPrefix = join(snapshotSource, 'node_modules') + sep
  const sourcePrefix = snapshotSource + sep
  if (absolute.startsWith(dependencyPrefix)) {
    return Object.freeze({
      kind: 'dependency',
      path: relative(join(snapshotSource, 'node_modules'), absolute).split(sep).join('/')
    })
  }
  if (absolute.startsWith(sourcePrefix)) {
    return Object.freeze({
      kind: 'accepted-source',
      path: relative(snapshotSource, absolute).split(sep).join('/')
    })
  }
  fail(`esbuild reached outside its authenticated snapshot: ${name}`)
}

async function buildArtifact (authority, captured) {
  const snapshot = realpathSync(
    mkdtempSync(join(tmpdir(), 'peerit-seq29-inbox-operator-')))
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
      fail(`deterministic inbox operator artifact changed: ${output.length}/${sha256(output)}`)
    }
    const executed = []
    const disabled = []
    let entryCount = 0
    for (const [name, metadata] of Object.entries(result.metafile.inputs)) {
      const normalized = normalizedMetafileInput(name, snapshotSource, entryPath)
      if (normalized.entry === true) {
        entryCount++
      } else if (normalized.disabled != null) {
        disabled.push(normalized.disabled)
      } else {
        executed.push(`${normalized.kind}\0${normalized.path}\0${metadata.bytes}`)
      }
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
        outputs[0].exports?.sort().join('\0') !==
          [...authority.exactSortedExports].sort().join('\0') ||
        Object.keys(outputs[0].inputs || {}).length !== authority.inputInventory.length + 2) {
      fail('esbuild output graph or exports changed')
    }
    return output
  } finally {
    rmSync(snapshot, { recursive: true, force: true })
  }
}

function exactOutputMembership (destination, allowMissingArtifact = false) {
  const names = readdirSync(destination).sort()
  const expected = allowMissingArtifact
    ? names.includes(ARTIFACT_NAME) ? [...OUTPUT_NAMES].sort() : [AUTHORITY_NAME]
    : [...OUTPUT_NAMES].sort()
  if (names.join('\0') !== expected.join('\0')) {
    fail('vendored output directory contains missing or extra files')
  }
}

function publishArtifact (destination, output) {
  exactOutputMembership(destination, true)
  const temporary = join(destination, `.${ARTIFACT_NAME}.${process.pid}.tmp`)
  let created = false
  try {
    writeFileSync(temporary, output, { flag: 'wx', mode: 0o644 })
    created = true
    renameSync(temporary, join(destination, ARTIFACT_NAME))
    created = false
  } finally {
    if (created) rmSync(temporary, { force: true })
  }
}

const authorityOutput = canonicalAuthority(destinationInput)
const roots = Object.freeze({
  source: authenticatedRoot(sourceInput, 'accepted source root'),
  dependency: authenticatedRoot(dependencyInput, 'dependency root')
})
const captured = authenticateInventory(authorityOutput.value, roots)
const artifact = await buildArtifact(authorityOutput.value, captured)

if (check) {
  exactOutputMembership(authorityOutput.root.path)
  const artifactRecord = Object.freeze({
    path: ARTIFACT_NAME,
    mode: '100644',
    bytes: authorityOutput.value.artifactLength,
    sha256: authorityOutput.value.artifactRawSha256
  })
  const vendored = exactReadRecord(authorityOutput.root, artifactRecord, new Map())
  if (!vendored.equals(artifact)) fail('vendored artifact is not the deterministic output')
} else {
  publishArtifact(authorityOutput.root.path, artifact)
  exactOutputMembership(authorityOutput.root.path)
}

const result = Object.freeze({
  schema: 'PeeritVendoredHiveRelaySeq29InboxOperatorResultV1',
  checked: check,
  candidateCommit: authorityOutput.value.candidateCommit,
  candidateTree: authorityOutput.value.candidateTree,
  artifactLength: artifact.length,
  artifactRawSha256: sha256(artifact),
  authorityRawSha256: sha256(authorityOutput.bytes),
  inputCount: authorityOutput.value.inputInventory.length,
  resolutionManifestCount: authorityOutput.value.resolutionManifestInventory.length,
  resolverProbeCount: RESOLUTION_PROBES.length
})
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
