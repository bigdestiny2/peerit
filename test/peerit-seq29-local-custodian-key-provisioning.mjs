import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  realpathSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  writeSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import {
  provisionPeeritSeq29LocalCustodianKeysFixtureV1
} from '../scripts/lib/seq29-local-custodian-key-provisioning.mjs'
import {
  createPeeritSeq29LocalCustodianKeyFileConfigurationV1
} from '../scripts/lib/seq29-local-custodian-key-files.mjs'

process.env.PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_TEST = '1'

const KEY_FILES = Object.freeze([
  'custodian-1.x25519',
  'custodian-2.x25519',
  'custodian-3.x25519'
])
const base = process.platform === 'darwin' ? '/private/tmp' : tmpdir()
const root = realpathSync(mkdtempSync(join(base,
  'peerit-seq29-custodian-provision-test-')))
const retainedEntropyBuffers = []

function fixture (overrides = {}) {
  return {
    fillRandom (output, index) {
      retainedEntropyBuffers.push(output)
      output.fill(index + 1)
    },
    ...overrides
  }
}

function target (name) {
  return join(root, name)
}

function assertCode (code) {
  return error => error?.code === code
}

function assertPartial (failureCode, residueDurability = null) {
  return error => {
    assert.equal(error?.code,
      'PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_PRESERVED')
    assert.equal(error?.status,
      'PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_PRESERVED')
    assert.equal(error?.failureCode, failureCode)
    assert.equal(error?.targetTopology, 'OBSERVED_EXACT_AT_FAILURE_BOUNDARY')
    assert.equal(error?.message.includes(root), false)
    if (residueDurability != null) {
      assert.deepEqual(error?.residueDurability, residueDurability)
    }
    return true
  }
}

function assertExternalTopologyDrift (failureCode) {
  return error => {
    assert.equal(error?.code,
      'PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_EXTERNAL_TOPOLOGY_DRIFT')
    assert.equal(error?.status,
      'PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_EXTERNAL_TOPOLOGY_DRIFT')
    assert.equal(error?.failureCode, failureCode)
    assert.equal(error?.targetTopology, 'EXTERNAL_DRIFT_OR_UNVERIFIED')
    assert.equal(error?.message.includes(root), false)
    assert.equal(error?.message.includes('preserved the exact residue'), false)
    return true
  }
}

function assertAbsent (path) {
  assert.throws(() => lstatSync(path), error => error?.code === 'ENOENT')
}

function assertExactPrivateTree (directory) {
  const rootMetadata = lstatSync(directory)
  assert.equal(rootMetadata.isDirectory(), true)
  assert.equal(rootMetadata.isSymbolicLink(), false)
  assert.equal(rootMetadata.mode & 0o7777, 0o700)
  if (typeof process.getuid === 'function') {
    assert.equal(rootMetadata.uid, process.getuid())
  }
  assert.deepEqual(readdirSync(directory).sort(), [...KEY_FILES].sort())
  const inodes = new Set()
  for (const name of KEY_FILES) {
    const metadata = lstatSync(join(directory, name))
    assert.equal(metadata.isFile(), true)
    assert.equal(metadata.isSymbolicLink(), false)
    assert.equal(metadata.nlink, 1)
    assert.equal(metadata.mode & 0o7777, 0o600)
    assert.equal(metadata.size, 32)
    if (typeof process.getuid === 'function') {
      assert.equal(metadata.uid, process.getuid())
    }
    inodes.add(`${metadata.dev}:${metadata.ino}`)
  }
  assert.equal(inodes.size, 3)
}

try {
  delete process.env.PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_TEST
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: target('fixture-disabled') }, fixture()),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_DISABLED'))
  process.env.PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_TEST = '1'

  const relative = 'relative-private-key-target'
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: relative }, fixture()),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_INVALID'))
  assertAbsent(resolve(relative))

  const existing = target('existing')
  mkdirSync(existing, { mode: 0o700 })
  writeFileSync(join(existing, 'operator-note'), 'keep', { mode: 0o600 })
  let existingEntropyCalled = false
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1({ directory: existing }, {
      fillRandom (output, index) {
        existingEntropyCalled = true
        output.fill(index + 1)
      }
    }),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_ALREADY_EXISTS'))
  assert.equal(existingEntropyCalled, false)
  assert.equal(readFileSync(join(existing, 'operator-note'), 'utf8'), 'keep')

  const targetSymlink = target('existing-target-symlink')
  symlinkSync(existing, targetSymlink)
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: targetSymlink }, fixture()),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_ALREADY_EXISTS'))
  assert.equal(readFileSync(join(existing, 'operator-note'), 'utf8'), 'keep')

  const realParent = target('real-parent')
  mkdirSync(realParent, { mode: 0o700 })
  const linkedParent = target('linked-parent')
  symlinkSync(realParent, linkedParent)
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: join(linkedParent, 'keys') }, fixture()),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS'))
  assertAbsent(join(realParent, 'keys'))

  const writableParent = target('writable-parent')
  mkdirSync(writableParent, { mode: 0o700 })
  chmodSync(writableParent, 0o722)
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: join(writableParent, 'keys') }, fixture()),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS'))
  assertAbsent(join(writableParent, 'keys'))
  chmodSync(writableParent, 0o700)

  const zero = target('zero')
  const zeroBuffers = []
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1({ directory: zero }, {
      fillRandom (output) {
        zeroBuffers.push(output)
        output.fill(0)
      }
    }),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_ENTROPY_INVALID'))
  assertAbsent(zero)
  assert.equal(zeroBuffers.length, 3)
  assert.equal(zeroBuffers.every(value => value.every(byte => byte === 0)), true)

  const duplicate = target('duplicate')
  const duplicateBuffers = []
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1({ directory: duplicate }, {
      fillRandom (output) {
        duplicateBuffers.push(output)
        output.fill(0x5a)
      }
    }),
  error => {
    const serialized = `${error?.code}:${error?.message}`
    assert.equal(serialized.includes('5a'.repeat(32)), false)
    assert.equal(serialized.includes(Buffer.alloc(32, 0x5a).toString('base64')), false)
    return error?.code === 'PEERIT_SEQ29_CUSTODIAN_PROVISION_ENTROPY_INVALID'
  })
  assertAbsent(duplicate)
  assert.equal(duplicateBuffers.every(value => value.every(byte => byte === 0)), true)

  const shortWrites = target('short-writes')
  let shortWriteCount = 0
  const shortWriteResult = provisionPeeritSeq29LocalCustodianKeysFixtureV1(
    { directory: shortWrites }, fixture({
      write (descriptor, bytes, offset, length, position) {
        shortWriteCount++
        return writeSync(descriptor, bytes, offset, Math.min(length, 5), position)
      }
    }))
  assert.deepEqual(shortWriteResult, {
    status: 'PEERIT_SEQ29_CUSTODIAN_KEYS_CREATED',
    keyCount: 3
  })
  assert.equal(shortWriteCount > 3, true)
  assertExactPrivateTree(shortWrites)
  assert.equal(retainedEntropyBuffers.every(value =>
    value.every(byte => byte === 0)), true)

  const configuration =
    createPeeritSeq29LocalCustodianKeyFileConfigurationV1({
      directory: shortWrites
    })
  assert.equal(configuration.custodianPublicKeys.length, 3)
  assert.equal(new Set(configuration.custodianPublicKeys.map(value =>
    Buffer.from(value).toString('hex'))).size, 3)
  const privateKeys = await configuration.custodianPrivateKeyProvider()
  try {
    assert.deepEqual(privateKeys.map(value => [...value]), [
      Array(32).fill(1),
      Array(32).fill(2),
      Array(32).fill(3)
    ])
  } finally {
    for (const key of privateKeys) key.fill(0)
  }

  const stalledWrite = target('stalled-write')
  let writeCalls = 0
  const stalledSyncStages = []
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: stalledWrite }, fixture({
        write (descriptor, bytes, offset, length, position) {
          writeCalls++
          if (writeCalls === 2) return 0
          return writeSync(descriptor, bytes, offset, Math.min(length, 7), position)
        },
        syncFile (descriptor, stage) {
          stalledSyncStages.push(stage)
          fsyncSync(descriptor)
        }
      })),
  assertPartial('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED', {
    fileFsync: 'SYNCED',
    fileClose: 'CLOSED',
    targetFsync: 'SYNCED',
    parentFsync: 'SYNCED'
  }))
  assert.deepEqual(stalledSyncStages, ['KEY_PARTIAL_PRESERVE'])
  assert.equal(lstatSync(stalledWrite).mode & 0o7777, 0o700)
  assert.deepEqual(readdirSync(stalledWrite), [KEY_FILES[0]])
  assert.equal(lstatSync(join(stalledWrite, KEY_FILES[0])).mode & 0o7777, 0o600)
  assert.equal(lstatSync(join(stalledWrite, KEY_FILES[0])).size, 7)

  const writeAndCloseFailed = target('write-and-close-failed')
  let writeAndCloseCalls = 0
  let incompleteCloseCalls = 0
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: writeAndCloseFailed }, fixture({
        write (descriptor, bytes, offset, length, position) {
          writeAndCloseCalls++
          if (writeAndCloseCalls === 2) return 0
          return writeSync(descriptor, bytes, offset, Math.min(length, 7), position)
        },
        closeFile (descriptor) {
          incompleteCloseCalls++
          closeSync(descriptor)
          const error = new Error('fixture close failure')
          error.code = 'PEERIT_SEQ29_CUSTODIAN_PROVISION_CLOSE_FAILED'
          throw error
        }
      })),
  assertPartial('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED', {
    fileFsync: 'SYNCED',
    fileClose: 'FAILED',
    targetFsync: 'SYNCED',
    parentFsync: 'SYNCED'
  }))
  assert.equal(incompleteCloseCalls, 1)
  assert.deepEqual(readdirSync(writeAndCloseFailed), [KEY_FILES[0]])
  assert.equal(lstatSync(join(writeAndCloseFailed, KEY_FILES[0])).size, 7)

  const completedCloseFailed = target('completed-close-failed')
  let completedCloseCalls = 0
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: completedCloseFailed }, fixture({
        closeFile (descriptor) {
          completedCloseCalls++
          closeSync(descriptor)
          const error = new Error('fixture close failure')
          error.code = 'PEERIT_SEQ29_CUSTODIAN_PROVISION_CLOSE_FAILED'
          throw error
        }
      })),
  assertPartial('PEERIT_SEQ29_CUSTODIAN_PROVISION_CLOSE_FAILED', {
    fileFsync: 'NOT_APPLICABLE',
    fileClose: 'FAILED',
    targetFsync: 'SYNCED',
    parentFsync: 'SYNCED'
  }))
  assert.equal(completedCloseCalls, 1)
  assert.deepEqual(readdirSync(completedCloseFailed), [KEY_FILES[0]])
  assert.equal(readFileSync(join(completedCloseFailed, KEY_FILES[0])).equals(
    Buffer.alloc(32, 1)), true)

  const partialFsyncFailed = target('partial-fsync-failed')
  let partialFailureWriteCalls = 0
  const partialFailureSyncStages = []
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: partialFsyncFailed }, fixture({
        write (descriptor, bytes, offset, length, position) {
          partialFailureWriteCalls++
          if (partialFailureWriteCalls === 2) return 0
          return writeSync(descriptor, bytes, offset, Math.min(length, 7), position)
        },
        syncFile (descriptor, stage) {
          partialFailureSyncStages.push(stage)
          if (stage === 'KEY_PARTIAL_PRESERVE') {
            const error = new Error('fixture fsync failure')
            error.code = 'EIO'
            throw error
          }
          fsyncSync(descriptor)
        }
      })),
  assertPartial('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED', {
    fileFsync: 'FAILED',
    fileClose: 'CLOSED',
    targetFsync: 'SYNCED',
    parentFsync: 'SYNCED'
  }))
  assert.deepEqual(partialFailureSyncStages, ['KEY_PARTIAL_PRESERVE'])
  assert.deepEqual(readdirSync(partialFsyncFailed), [KEY_FILES[0]])
  assert.equal(lstatSync(join(partialFsyncFailed, KEY_FILES[0])).size, 7)

  const directoryFsyncFailed = target('directory-fsync-failed')
  let directoryFailureWriteCalls = 0
  const directoryFailureSyncStages = []
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: directoryFsyncFailed }, fixture({
        write (descriptor, bytes, offset, length, position) {
          directoryFailureWriteCalls++
          if (directoryFailureWriteCalls === 2) return 0
          return writeSync(descriptor, bytes, offset, Math.min(length, 7), position)
        },
        syncDirectory (descriptor, stage) {
          directoryFailureSyncStages.push(stage)
          if (stage === 'TARGET_FAILURE_PRESERVE' ||
              stage === 'PARENT_FAILURE_PRESERVE') {
            const error = new Error('fixture directory fsync failure')
            error.code = 'EIO'
            throw error
          }
          fsyncSync(descriptor)
        }
      })),
  assertPartial('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED', {
    fileFsync: 'SYNCED',
    fileClose: 'CLOSED',
    targetFsync: 'FAILED',
    parentFsync: 'FAILED'
  }))
  assert.deepEqual(directoryFailureSyncStages, [
    'TARGET_INITIAL',
    'PARENT_INITIAL',
    'TARGET_FAILURE_PRESERVE',
    'PARENT_FAILURE_PRESERVE'
  ])
  assert.deepEqual(readdirSync(directoryFsyncFailed), [KEY_FILES[0]])
  assert.equal(lstatSync(join(directoryFsyncFailed, KEY_FILES[0])).size, 7)

  const contentChanged = target('same-inode-content-changed')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: contentChanged }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_KEY_1_FSYNC') return
          writeFileSync(join(contentChanged, KEY_FILES[0]), Buffer.alloc(32, 0x6d), {
            flag: 'r+'
          })
        }
      })),
  assertPartial('PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED'))
  assert.deepEqual(readdirSync(contentChanged).sort(), [...KEY_FILES].sort())
  assert.equal(readFileSync(join(contentChanged, KEY_FILES[0])).equals(
    Buffer.alloc(32, 0x6d)), true)

  const replaced = target('replaced-inode')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1({ directory: replaced },
      fixture({
        onStage (stage) {
          if (stage !== 'AFTER_KEY_1_FSYNC') return
          const first = join(replaced, KEY_FILES[0])
          unlinkSync(first)
          writeFileSync(first, Buffer.alloc(32, 0x7c), {
            flag: constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
            mode: 0o600
          })
          throw new Error('fixture replacement')
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED'))
  assert.equal(readFileSync(join(replaced, KEY_FILES[0])).equals(
    Buffer.alloc(32, 0x7c)), true)

  const hardlinked = target('hardlinked-inode')
  const outsideHardlink = target('outside-hardlink')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: hardlinked }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_KEY_1_FSYNC') return
          linkSync(join(hardlinked, KEY_FILES[0]), outsideHardlink)
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS'))
  assert.equal(lstatSync(join(hardlinked, KEY_FILES[0])).nlink, 2)
  assert.equal(lstatSync(outsideHardlink).nlink, 2)

  const permissionChanged = target('permission-changed')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: permissionChanged }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_KEY_1_FSYNC') return
          chmodSync(join(permissionChanged, KEY_FILES[0]), 0o644)
          throw new Error('fixture permission change')
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED'))
  assert.equal(lstatSync(join(permissionChanged, KEY_FILES[0])).mode & 0o777, 0o644)

  const ownerModeChanged = target('owner-mode-changed')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: ownerModeChanged }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_KEY_1_FSYNC') return
          chmodSync(join(ownerModeChanged, KEY_FILES[0]), 0o400)
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS'))
  assert.equal(lstatSync(join(ownerModeChanged, KEY_FILES[0])).mode & 0o7777, 0o400)

  const specialModeChanged = target('special-mode-changed')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: specialModeChanged }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_DIRECTORY_FSYNC') return
          chmodSync(specialModeChanged, 0o1700)
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS'))
  assert.equal(lstatSync(specialModeChanged).mode & 0o7777, 0o1700)

  const specialFileModeChanged = target('special-file-mode-changed')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: specialFileModeChanged }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_KEY_3_FSYNC') return
          chmodSync(join(specialFileModeChanged, KEY_FILES[0]), 0o1600)
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_PERMISSIONS'))
  assert.equal(
    lstatSync(join(specialFileModeChanged, KEY_FILES[0])).mode & 0o7777, 0o1600)

  const topologyAnomaly = target('target-topology-anomaly')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: topologyAnomaly }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_DIRECTORY_FSYNC') return
          mkdirSync(join(topologyAnomaly, 'unknown-subdirectory'), { mode: 0o700 })
        }
      })),
  assertExternalTopologyDrift(
    'PEERIT_SEQ29_CUSTODIAN_PROVISION_DIRECTORY_REPLACED'))
  assert.deepEqual(readdirSync(topologyAnomaly), ['unknown-subdirectory'])

  const renamedTarget = target('renamed-target')
  const movedTarget = target('renamed-target-original-residue')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: renamedTarget }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_KEY_1_FSYNC') return
          renameSync(renamedTarget, movedTarget)
          mkdirSync(renamedTarget, { mode: 0o700 })
          throw new Error('fixture target rename and replacement')
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED'))
  assert.deepEqual(readdirSync(renamedTarget), [])
  assert.deepEqual(readdirSync(movedTarget), [KEY_FILES[0]])
  assert.equal(readFileSync(join(movedTarget, KEY_FILES[0])).equals(
    Buffer.alloc(32, 1)), true)

  const unlinkedTarget = target('unlinked-target')
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1(
      { directory: unlinkedTarget }, fixture({
        onStage (stage) {
          if (stage !== 'AFTER_DIRECTORY_FSYNC') return
          rmdirSync(unlinkedTarget)
          mkdirSync(unlinkedTarget, { mode: 0o700 })
          throw new Error('fixture target unlink and replacement')
        }
      })),
  assertExternalTopologyDrift('PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED'))
  assert.deepEqual(readdirSync(unlinkedTarget), [])

  const crashTarget = target('crash-residue')
  const crashDriver = resolve(import.meta.dirname,
    'fixtures/seq29-custodian-provision-crash.mjs')
  const crash = spawnSync(process.execPath, [crashDriver, crashTarget], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PEERIT_SEQ29_CUSTODIAN_PROVISION_FIXTURE_TEST: '1'
    }
  })
  assert.equal(crash.status, null)
  assert.equal(crash.signal, 'SIGKILL')
  assert.equal(crash.stdout, '')
  assert.equal(crash.stderr, '')
  assert.equal(lstatSync(crashTarget).mode & 0o7777, 0o700)
  assert.deepEqual(readdirSync(crashTarget), [KEY_FILES[0]])
  assert.equal(readFileSync(join(crashTarget, KEY_FILES[0])).equals(
    Buffer.alloc(32, 17)), true)
  let retryEntropyCalled = false
  assert.throws(() =>
    provisionPeeritSeq29LocalCustodianKeysFixtureV1({ directory: crashTarget }, {
      fillRandom (output, index) {
        retryEntropyCalled = true
        output.fill(index + 1)
      }
    }),
  assertCode('PEERIT_SEQ29_CUSTODIAN_PROVISION_ALREADY_EXISTS'))
  assert.equal(retryEntropyCalled, false)

  const freshRetry = target('fresh-retry')
  const retry = provisionPeeritSeq29LocalCustodianKeysFixtureV1(
    { directory: freshRetry }, fixture())
  assert.equal(retry.status, 'PEERIT_SEQ29_CUSTODIAN_KEYS_CREATED')
  assertExactPrivateTree(freshRetry)

  const secretPathToken = 'DO_NOT_ECHO_OPERATOR_PATH_TOKEN'
  const cli = resolve(import.meta.dirname,
    '../scripts/seq29-provision-local-custodian-keys.mjs')
  const invalidCli = spawnSync(process.execPath, [cli, secretPathToken], {
    encoding: 'utf8'
  })
  assert.equal(invalidCli.status, 1)
  assert.equal(invalidCli.stdout, '')
  assert.equal(invalidCli.stderr.includes(secretPathToken), false)
  assert.equal(invalidCli.stderr.includes('private key'), false)

  const secretAbsoluteToken = target('DO_NOT_ECHO_ABSOLUTE_TARGET_TOKEN')
  mkdirSync(secretAbsoluteToken, { mode: 0o700 })
  const existingCli = spawnSync(process.execPath, [cli, secretAbsoluteToken], {
    encoding: 'utf8'
  })
  assert.equal(existingCli.status, 1)
  assert.equal(existingCli.stdout, '')
  assert.equal(existingCli.stderr.includes(secretAbsoluteToken), false)

  const source = readFileSync(cli, 'utf8')
  assert.equal(source.includes('PROVISION_FIXTURE_TEST'), false)
  assert.equal(source.includes('provisionPeeritSeq29LocalCustodianKeysFixtureV1'), false)
  const provisioningSource = readFileSync(resolve(import.meta.dirname,
    '../scripts/lib/seq29-local-custodian-key-provisioning.mjs'), 'utf8')
  for (const forbiddenDeletion of ['unlinkSync', 'rmdirSync', 'renameSync']) {
    assert.equal(provisioningSource.includes(forbiddenDeletion), false)
  }
  assert.equal(retainedEntropyBuffers.every(value =>
    value.every(byte => byte === 0)), true)

  console.log('peerit seq29 local custodian key provisioning: ok')
} finally {
  rmSync(root, { recursive: true, force: true })
}
