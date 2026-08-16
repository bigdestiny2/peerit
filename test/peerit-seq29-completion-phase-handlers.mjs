import assert from 'node:assert/strict'
import { lstatSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  PEERIT_SEQ29_COMPLETION_FIXED_ARTIFACTS_V1,
  PEERIT_SEQ29_COMPLETION_INSTALLED_PHASES_V1
} from '../scripts/seq29-completion-driver.mjs'
import {
  PHASE_ARTIFACTS,
  PEERIT_SEQ29_COMPLETION_PHASES_V1
} from '../scripts/lib/seq29-completion-receipts.mjs'
import {
  runPeeritSeq29CompletionHistorySignPhaseV1,
  runPeeritSeq29CompletionReleaseSignPhaseV1
} from '../scripts/lib/seq29-completion-static-phases.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const driverSource = readFileSync(
  join(root, 'scripts', 'seq29-completion-driver.mjs'), 'utf8')

// The driver file must never reference caller-relayed authority interfaces.
for (const pattern of [
  /explicit-confirmation/i,
  new RegExp(['PEERIT', 'SEQ29', 'EXPLICIT', 'CONFIRMATION', 'V1'].join('_')),
  /copy\s*\/\s*paste/i,
  /copy and paste/i,
  /paste (?:it|this|that)/i,
  /--(?:token|secret|commit|hash|path|command|pass)(?:\s|=|$)/i,
  /\bPASS\b/,
  /seq29-owner-decision\.mjs/,
  /seq29-live-ceremony-materializer\.mjs/
]) {
  assert.doesNotMatch(driverSource, pattern,
    `driver source must stay free of relayed authority interfaces: ${pattern}`)
}

// Handler registry completeness: every frozen chain phase is installed and
// declares a fixed digested evidence set whose fields are exactly the frozen
// PHASE_ARTIFACTS set for that phase.
assert.deepEqual([...PEERIT_SEQ29_COMPLETION_INSTALLED_PHASES_V1].sort(),
  [...PEERIT_SEQ29_COMPLETION_PHASES_V1].sort(),
  'every frozen chain phase must have an installed handler')
for (const phase of PEERIT_SEQ29_COMPLETION_PHASES_V1) {
  const fixed = PEERIT_SEQ29_COMPLETION_FIXED_ARTIFACTS_V1[phase]
  assert.ok(fixed && typeof fixed === 'object' && !Array.isArray(fixed),
    `${phase} must declare fixed digested artifacts`)
  assert.deepEqual(Object.keys(fixed).sort(),
    [...PHASE_ARTIFACTS[phase]].sort(),
    `${phase} fixed artifact fields must match the frozen receipt set`)
  for (const [field, entry] of Object.entries(fixed)) {
    assert.ok(Array.isArray(entry) && entry.length === 2,
      `${phase}.${field} must be an exact [path, mode] pair`)
    const [path, mode] = entry
    assert.equal(typeof path, 'string')
    assert.ok(path.length > 0 && !path.startsWith('/') &&
      !path.includes('\0') && !path.split('/').includes('..'),
      `${phase}.${field} must be a repository-relative path`)
    assert.equal(typeof mode, 'number')
    assert.ok(mode >= 0 && mode <= 0o777,
      `${phase}.${field} must declare an exact permission mode`)
  }
}

// The source-edit evidence digests the decision module itself; its declared
// mode must match the file's actual committed mode.
{
  const sourceEdit =
    PEERIT_SEQ29_COMPLETION_FIXED_ARTIFACTS_V1['decision-pin']['source-edit']
  const metadata = lstatSync(join(root, sourceEdit[0]))
  assert.equal(metadata.mode & 0o777, sourceEdit[1],
    'source-edit declared mode must match the decision module mode')
}

// Fail-closed authority: release-sign and history-sign must throw the coded
// signer-required error before touching the network or the filesystem when
// the keyvault-injected seed is absent or malformed.
{
  const saved = process.env.PEERIT_RELEASE_SIGNING_SEED
  delete process.env.PEERIT_RELEASE_SIGNING_SEED
  try {
    await assert.rejects(runPeeritSeq29CompletionReleaseSignPhaseV1(root),
      error => error.code === 'PEERIT_SEQ29_COMPLETION_SIGNER_REQUIRED')
    await assert.rejects(runPeeritSeq29CompletionHistorySignPhaseV1(root),
      error => error.code === 'PEERIT_SEQ29_COMPLETION_SIGNER_REQUIRED')
    process.env.PEERIT_RELEASE_SIGNING_SEED = 'not-exact-hex'
    await assert.rejects(runPeeritSeq29CompletionReleaseSignPhaseV1(root),
      error => error.code === 'PEERIT_SEQ29_COMPLETION_SIGNER_REQUIRED')
    await assert.rejects(runPeeritSeq29CompletionHistorySignPhaseV1(root),
      error => error.code === 'PEERIT_SEQ29_COMPLETION_SIGNER_REQUIRED')
  } finally {
    if (saved === undefined) delete process.env.PEERIT_RELEASE_SIGNING_SEED
    else process.env.PEERIT_RELEASE_SIGNING_SEED = saved
  }
}

console.log('peerit seq29 completion phase handlers tests: ok')
