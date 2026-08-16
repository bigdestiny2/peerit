import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'

const root = path.resolve(process.env.HIVERELAY_BLIND_ROOT || '/Users/localllm/.pear-wt/s29artifact5')
const verifierSource = fs.readFileSync('scripts/verify-hiverelay-profile-authorities.mjs', 'utf8')
assert.doesNotMatch(verifierSource, /\bimport\s*\(/,
  'authority audit must not dynamically import executable code from the supplied HiveRelay checkout')
assert.doesNotMatch(verifierSource, /pathToFileURL|client-composition-authority\.js/,
  'authority audit must not retain an external executable import seam')
const output = JSON.parse(execFileSync(process.execPath, [
  'scripts/verify-hiverelay-profile-authorities.mjs',
  `--hiverelay-root=${root}`
], { encoding: 'utf8' }))

assert.equal(output.artifactMetadataRecomputed, true)
assert.equal(output.externalExecutableImports, false)
assert.equal(output.clientCompositionLocallyVerified, true)
assert.equal(output.wirePosture, 'EXTERNAL_CURRENT_DIFFERS_FROM_PEERIT_FROZEN_ACCEPTED')
assert.deepEqual(output.externalWire, {
  specHash: 'c9ddd235c3963461174e3de13c25a4c995b53ff320be822d8304f870766b6592',
  abiHash: '199ba15d94d4d112cfac520a67055ce15ec870f0f6f7bd9adaaf47d552334567',
  vectorSetHash: 'fa54012cd0d7e4e620878c67e61f435ecb31ddec05a6283917987cc84279ee05'
})
assert.deepEqual(output.peeritFrozenWire, {
  specHash: '470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9',
  abiHash: 'aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d',
  vectorSetHash: '09bd04c86f6f62b4636b9360fd2fca985a63537a0cec8642918f450ec70f9e78'
})

console.log('peerit HiveRelay profile authorities: exact external and frozen Peerit closures distinguished')
