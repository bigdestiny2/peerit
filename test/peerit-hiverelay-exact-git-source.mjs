import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHiveRelayExactGitSourceV1 } from '../scripts/lib/hiverelay-exact-git-source.mjs'

const root = path.resolve(process.env.HIVERELAY_BLIND_ROOT || '/Users/localllm/.pear-wt/s29artifact5')
const gitEnv = {
  ...process.env,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_NO_LAZY_FETCH: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0'
}
const advancedHead = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
  encoding: 'utf8',
  env: gitEnv
}).trim()
const source = createHiveRelayExactGitSourceV1({
  root,
  commit: 'adeacef07c5de4d17d5ed1389fee7a35095b862f',
  expectedTree: '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'
})
assert.equal(source.commit, 'adeacef07c5de4d17d5ed1389fee7a35095b862f')
assert.equal(source.tree, '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c')
assert.notEqual(advancedHead, source.commit, 'the default worktree must exercise exact-object selection past candidate HEAD')
assert.deepEqual(Reflect.ownKeys(source), ['root', 'commit', 'tree', 'read'])
assert.equal('importExactModule' in source, false,
  'exact-object source must not expose an import that could execute code from advanced HEAD')
assert.equal(source.read(
  'packages/blind-client-public-browser/browser-artifacts/blind-client-public-control-v1.mjs'
).equals(fs.readFileSync('vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs')), true)
assert.throws(() => source.read('packages/blind-client-public-browser/browser-artifacts'), error =>
  error.code === 'PEERIT_HIVERELAY_EXACT_GIT_SOURCE_NOT_BLOB',
'tree paths must never be rendered as source bytes')
assert.throws(() => source.read(
  'packages/blind-client-public-browser/browser-artifacts/absent-peerit-artifact.mjs'
), error => error.code === 'PEERIT_HIVERELAY_EXACT_GIT_SOURCE_UNAVAILABLE',
'an absent path must fail closed')
assert.throws(() => createHiveRelayExactGitSourceV1({
  root: path.join(root, 'missing-repository'),
  commit: source.commit,
  expectedTree: source.tree
}), error => error.code === 'PEERIT_HIVERELAY_EXACT_GIT_SOURCE_UNAVAILABLE')
assert.throws(() => createHiveRelayExactGitSourceV1({
  root,
  commit: source.commit,
  expectedTree: '0000000000000000000000000000000000000000'
}), /candidate tree changed/)
const emptyRepository = fs.mkdtempSync(path.join(os.tmpdir(), 'peerit-hiverelay-object-absence-'))
try {
  execFileSync('git', ['init', '--quiet', emptyRepository], { env: gitEnv })
  const helperUrl = new URL('../scripts/lib/hiverelay-exact-git-source.mjs', import.meta.url).href
  const poisonObjects = path.join(emptyRepository, '.git', 'objects')
  const poisonedReadLength = execFileSync(process.execPath, ['--input-type=module', '--eval', `
    import { createHiveRelayExactGitSourceV1 } from ${JSON.stringify(helperUrl)}
    const source = createHiveRelayExactGitSourceV1({
      root: ${JSON.stringify(root)},
      commit: 'adeacef07c5de4d17d5ed1389fee7a35095b862f',
      expectedTree: '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'
    })
    process.stdout.write(String(source.read('packages/blind-client-public-browser/browser-artifacts/blind-client-public-control-v1.mjs').byteLength))
  `], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_ALTERNATE_OBJECT_DIRECTORIES: poisonObjects,
      GIT_COMMON_DIR: path.join(emptyRepository, '.git'),
      GIT_DIR: path.join(emptyRepository, '.git'),
      GIT_OBJECT_DIRECTORY: poisonObjects,
      GIT_REPLACE_REF_BASE: 'refs/poison-replacements',
      GIT_WORK_TREE: emptyRepository
    }
  }).trim()
  assert.equal(poisonedReadLength, '234813',
    'repository/object routing environment must not redirect the exact source helper')
  assert.throws(() => createHiveRelayExactGitSourceV1({
    root: emptyRepository,
    commit: source.commit,
    expectedTree: source.tree
  }), error => error.code === 'PEERIT_HIVERELAY_EXACT_GIT_SOURCE_UNAVAILABLE')
  assert.throws(() => execFileSync(process.execPath, [
    'scripts/vendor-hiverelay-blind-client.mjs',
    '--check',
    `--hiverelay-root=${emptyRepository}`
  ], { stdio: 'pipe' }), error =>
    error.status !== 0 &&
    error.stderr.toString().includes('PEERIT_HIVERELAY_EXACT_GIT_SOURCE_UNAVAILABLE'))
} finally {
  fs.rmSync(emptyRepository, { recursive: true, force: true })
}

console.log(`peerit HiveRelay exact Git source: advanced HEAD ${advancedHead}, exact object and fail-closed absence ok`)
