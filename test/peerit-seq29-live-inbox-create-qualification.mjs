import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, dirname, extname, join, resolve } from 'node:path'

import * as qualification from
  '../scripts/seq29-live-inbox-create-qualification.mjs'
import {
  loadPeeritSeq29AcceptedHiveRelayOperatorV1
} from '../scripts/lib/seq29-accepted-hiverelay-operator.mjs'

const ROOT = resolve(import.meta.dirname, '..')
const productionAuthorityPaths = [
  'scripts/seq29-live-inbox-create-qualification.mjs',
  'scripts/limited-inbox-topic-ceremony.mjs',
  'scripts/seq29-live-inbox-ceremony-conductor.mjs',
  'scripts/lib/seq29-accepted-hiverelay-operator.mjs'
]
const productionAuthoritySource = productionAuthorityPaths.map(relative =>
  readFileSync(resolve(ROOT, relative), 'utf8')).join('\n')
const COMPOSITION_ENTRY = resolve(ROOT,
  'scripts/seq29-live-inbox-create-composition.mjs')
const ACCEPTED_LOADER = resolve(ROOT,
  'scripts/lib/seq29-accepted-hiverelay-operator.mjs')
const RAW_CONTROL_MODULE = resolve(ROOT,
  'vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs')
const STATIC_MODULE_SPECIFIER =
  /(?:^|\n)\s*(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g

function compositionStaticClosure () {
  const files = new Set()
  const edges = []
  const queue = [COMPOSITION_ENTRY]
  while (queue.length > 0) {
    const file = queue.shift()
    if (files.has(file)) continue
    files.add(file)
    const source = readFileSync(file, 'utf8')
    STATIC_MODULE_SPECIFIER.lastIndex = 0
    let match
    while ((match = STATIC_MODULE_SPECIFIER.exec(source)) != null) {
      const specifier = match[1]
      if (!specifier.startsWith('.')) continue
      let target = resolve(dirname(file), specifier)
      if (extname(target) === '') {
        if (existsSync(`${target}.mjs`)) target = `${target}.mjs`
        else if (existsSync(`${target}.js`)) target = `${target}.js`
      }
      assert.equal(existsSync(target), true,
        `composition import does not resolve: ${specifier} from ${file}`)
      edges.push(Object.freeze({ file, target }))
      queue.push(target)
    }
  }
  return Object.freeze({ files, edges })
}

const compositionClosure = compositionStaticClosure()
for (const required of [
  ACCEPTED_LOADER,
  resolve(ROOT, 'scripts/sign-limited-public-inbox-bootstrap.mjs'),
  resolve(ROOT, 'scripts/lib/seq29-local-management-custody.mjs')
]) {
  assert.equal(compositionClosure.files.has(required), true,
    `composition closure omitted ${required}`)
}
assert.equal(compositionClosure.edges.some(edge =>
  edge.target === RAW_CONTROL_MODULE), false,
'composition closure must have no static/raw import of the control artifact')
assert.deepEqual([...compositionClosure.files].filter(file =>
  readFileSync(file, 'utf8').includes('blind-client-control-v1.mjs')), [ACCEPTED_LOADER],
'only the authenticated captured-bytes loader may name the raw control artifact')

for (const decoderConsumer of [
  resolve(ROOT, 'scripts/sign-limited-public-inbox-bootstrap.mjs'),
  resolve(ROOT, 'scripts/lib/seq29-local-management-custody.mjs')
]) {
  const source = readFileSync(decoderConsumer, 'utf8')
  assert.match(source,
    /const\s*\{\s*decodeBlindExternalProfileValueV1\s*\}\s*=\s*\(await loadPeeritSeq29AcceptedHiveRelayOperatorV1\(\)\)\.control/,
    `${decoderConsumer} must privately bind its decoder from the authenticated loader`)
}

assert.deepEqual(Object.keys(qualification).sort(), [
  'PEERIT_SEQ29_ACCEPTED_BROWSER_CONTROL_AUTHORITY_SHA256_V1',
  'PEERIT_SEQ29_ACCEPTED_BROWSER_CONTROL_SHA256_V1',
  'PEERIT_SEQ29_ACCEPTED_HIVERELAY_TREE_V1',
  'PEERIT_SEQ29_ACCEPTED_LIMITED_CELL_PUT_PROFILE_SHA256_V1',
  'PEERIT_SEQ29_ACCEPTED_SEED_PREDECESSOR_SHA256_V1',
  'PEERIT_SEQ29_CREATE_PLAN_CONTINUITY_SCHEMA_V1',
  'PEERIT_SEQ29_CREATE_PLAN_SNAPSHOT_SCHEMA_V1',
  'PEERIT_SEQ29_CREATE_QUALIFICATION_SCHEMA_V1',
  'PEERIT_SEQ29_SEED_AUTHORITY_PUBLIC_KEY_V1',
  'createPeeritSeq29CustodyFirstLiveInboxCreateCompositionV1',
  'createPeeritSeq29LimitedInboxCeremonyPlanFromQualificationV1',
  'createPeeritSeq29LiveInboxCreateCompositionV1',
  'createPeeritSeq29PersistedPlanLiveInboxCreateRecoveryCompositionV1',
  'preparePeeritSeq29LiveInboxCreateCustodyFirstV1',
  'preparePeeritSeq29LiveInboxCreateReleaseV1',
  'qualifyPeeritSeq29CustodyFirstPreparedLiveInboxCreateTargetsV1',
  'qualifyPeeritSeq29LiveInboxCreateTargetsV1',
  'qualifyPeeritSeq29PreparedLiveInboxCreateTargetsV1',
  'snapshotPeeritSeq29LiveInboxCreateQualificationV1',
  'snapshotPeeritSeq29LiveInboxCreateReleasePreparationV1'
].sort())

for (const forbidden of [
  'node:child_process',
  'execFileSync',
  'spawnSync',
  'hiverelaySourceRoot',
  'GIT_CONFIG',
  'hash-object',
  "'status'",
  'packages/blind-client/runtime/node.js'
]) {
  assert.equal(productionAuthoritySource.includes(forbidden), false,
    `production authority must not contain ${forbidden}`)
}
assert.equal(existsSync(resolve(ROOT,
  'scripts/lib/seq29-live-inbox-create-qualification-state.mjs')), false)
assert.equal(existsSync(resolve(ROOT,
  'scripts/lib/seq29-live-inbox-create-composition.mjs')), false)

const accepted = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
assert.equal(accepted.identity.candidateCommit,
  'adeacef07c5de4d17d5ed1389fee7a35095b862f')
assert.equal(accepted.identity.candidateTree,
  '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c')
assert.equal(typeof accepted.control.verifiedEndpointContext, 'function')
assert.equal(typeof accepted.control.BlindDirectHttpClient, 'function')
assert.equal(typeof accepted.inbox.createInboxReplica, 'function')
assert.strictEqual((await loadPeeritSeq29AcceptedHiveRelayOperatorV1()).control,
  accepted.control)
assert.strictEqual(
  (await loadPeeritSeq29AcceptedHiveRelayOperatorV1()).control
    .decodeBlindExternalProfileValueV1,
  accepted.control.decodeBlindExternalProfileValueV1)
const [bootstrapModule, custodyModule] = await Promise.all([
  import('../scripts/sign-limited-public-inbox-bootstrap.mjs'),
  import('../scripts/lib/seq29-local-management-custody.mjs')
])
assert.equal(Object.hasOwn(bootstrapModule,
  'decodeBlindExternalProfileValueV1'), false)
assert.equal(Object.hasOwn(custodyModule,
  'decodeBlindExternalProfileValueV1'), false)

const forged = Object.freeze({
  schema: qualification.PEERIT_SEQ29_CREATE_QUALIFICATION_SCHEMA_V1,
  releaseSequence: 29,
  candidateCommit: accepted.identity.candidateCommit,
  qualifiedRelayCount: 2,
  seedBootstrapSha256: '11'.repeat(32),
  limitedCellPutProfileSha256: '12'.repeat(32),
  controlArtifactSha256: accepted.identity.controlArtifactSha256,
  inboxOperatorArtifactSha256: accepted.identity.inboxOperatorArtifactSha256,
  fixtureOnly: false
})
assert.throws(() =>
  qualification.snapshotPeeritSeq29LiveInboxCreateQualificationV1(forged),
error => error?.code === 'PEERIT_SEQ29_CREATE_QUALIFICATION_REQUIRED')
assert.throws(() =>
  qualification.createPeeritSeq29LimitedInboxCeremonyPlanFromQualificationV1({
    qualification: forged,
    issuedUnixMillis: '1',
    expiresUnixMillis: '2',
    authorityPublicKey: '21'.repeat(32),
    stripeSelectionKey: '22'.repeat(32),
    announcementMasterKey: '23'.repeat(32),
    bootstrapSequence: 0,
    previousBootstrapHash: null
  }), error => error?.code === 'PEERIT_SEQ29_CREATE_QUALIFICATION_REQUIRED')
await assert.rejects(
  qualification.qualifyPeeritSeq29LiveInboxCreateTargetsV1({
    seedBootstrapBytes: new Uint8Array(),
    limitedCellPutProfileBytes: new Uint8Array(),
    fetch: async () => assert.fail('caller-selected transport executed')
  }),
  error => error?.code === 'PEERIT_SEQ29_CREATE_QUALIFICATION_INVALID')

// Hostile repository/global/system/XDG/config-count/fsmonitor/hooks/filter
// state, plus an executable fake `git`, cannot influence the immutable loader.
// Any Git invocation or config-driven sentinel execution leaves a marker.
const hostileRoot = mkdtempSync(join(tmpdir(), 'peerit-seq29-no-git-'))
try {
  const marker = join(hostileRoot, 'executed')
  const bin = join(hostileRoot, 'bin')
  const home = join(hostileRoot, 'home')
  const xdg = join(hostileRoot, 'xdg')
  const hooks = join(hostileRoot, 'hooks')
  const sentinel = join(hostileRoot, 'sentinel.sh')
  const config = join(hostileRoot, 'hostile.gitconfig')
  mkdirSync(bin)
  mkdirSync(home)
  mkdirSync(join(xdg, 'git'), { recursive: true })
  mkdirSync(hooks)
  writeFileSync(join(bin, 'git'),
    `#!/bin/sh\n: > ${JSON.stringify(marker)}\nexit 99\n`)
  chmodSync(join(bin, 'git'), 0o755)
  writeFileSync(sentinel,
    `#!/bin/sh\n: > ${JSON.stringify(marker)}\nexit 98\n`)
  chmodSync(sentinel, 0o755)
  writeFileSync(config, '[core]\n' +
    `\tfsmonitor = ${sentinel}\n` +
    `\thooksPath = ${hooks}\n` +
    '[filter "peerit-hostile"]\n' +
    `\tprocess = ${sentinel}\n` +
    `\tclean = ${sentinel}\n` +
    `\tsmudge = ${sentinel}\n` +
    `[diff]\n\texternal = ${sentinel}\n`)
  writeFileSync(join(home, '.gitconfig'), readFileSync(config))
  writeFileSync(join(xdg, 'git/config'), readFileSync(config))
  const child = `
    const root = ${JSON.stringify(ROOT)}
    const loader = await import(root + '/scripts/lib/seq29-accepted-hiverelay-operator.mjs')
    const qualification = await import(root + '/scripts/seq29-live-inbox-create-qualification.mjs')
    const one = await loader.loadPeeritSeq29AcceptedHiveRelayOperatorV1()
    const two = await loader.loadPeeritSeq29AcceptedHiveRelayOperatorV1()
    if (one.control !== two.control) throw new Error('control module identity changed')
    try {
      await qualification.qualifyPeeritSeq29LiveInboxCreateTargetsV1({
        hiverelaySourceRoot: '/hostile/external/worktree',
        seedBootstrapBytes: new Uint8Array(),
        limitedCellPutProfileBytes: new Uint8Array()
      })
      throw new Error('legacy source-root input was accepted')
    } catch (error) {
      if (error.code !== 'PEERIT_SEQ29_CREATE_QUALIFICATION_INVALID') throw error
    }
  `
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', child], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}${delimiter}${process.env.PATH || ''}`,
      HOME: home,
      XDG_CONFIG_HOME: xdg,
      GIT_CONFIG_GLOBAL: config,
      GIT_CONFIG_SYSTEM: config,
      GIT_CONFIG_NOSYSTEM: '0',
      GIT_CONFIG_PARAMETERS: `'core.fsmonitor'='${sentinel}'`,
      GIT_CONFIG_COUNT: '2',
      GIT_CONFIG_KEY_0: 'core.fsmonitor',
      GIT_CONFIG_VALUE_0: sentinel,
      GIT_CONFIG_KEY_1: 'core.hooksPath',
      GIT_CONFIG_VALUE_1: hooks,
      GIT_DIR: '/hostile/git-dir',
      GIT_WORK_TREE: '/hostile/worktree',
      GIT_COMMON_DIR: '/hostile/common-dir',
      GIT_OBJECT_DIRECTORY: '/hostile/objects',
      GIT_ALTERNATE_OBJECT_DIRECTORIES: '/hostile/alternate-objects'
    }
  })
  assert.equal(result.status, 0, result.stderr || result.stdout)
  assert.equal(existsSync(marker), false,
    'production qualification/ceremony must execute neither Git nor hostile config')
} finally {
  rmSync(hostileRoot, { recursive: true, force: true })
}

console.log('peerit seq29 qualification: immutable same-module control, private WeakMap branding, and zero Git/config execution')
