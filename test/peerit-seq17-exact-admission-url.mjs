import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  PEERIT_LIMITED_CELL_GET_PARAMETER_URL_V1,
  verifyPeeritLimitedCellGetProfileV1
} from '../js/substrate/limited-cell-get-profile.mjs'
import './peerit-seq17-recovery-decision.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const profilePath = path.join(root, 'peerit-limited-cell-get-profile-v1.json')
const source = fs.readFileSync(profilePath, 'utf8')
const profileVerifierSource = fs.readFileSync(path.join(
  root, 'js/substrate/limited-cell-get-profile.mjs'), 'utf8')
const relayConsumerSource = fs.readFileSync(path.join(
  root, 'js/substrate/relay-consumer.js'), 'utf8')
const renderBlueprint = fs.readFileSync(path.join(root, 'render.yaml'), 'utf8')
const renderHeaders = fs.readFileSync(path.join(
  root, 'deploy/render-security-headers.json'), 'utf8')
const parsed = JSON.parse(source)
const encoder = new TextEncoder()
const expectedUrlHex =
  '68747470733a2f2f65766964656e63652e6578616d706c653a3434332f61646d697373696f6e2e63656e63'

function hexBytes (value) {
  return new Uint8Array(Buffer.from(value, 'hex'))
}

function canonicalBytes (value) {
  return encoder.encode(JSON.stringify(value, null, 2) + '\n')
}

function verify (value) {
  return verifyPeeritLimitedCellGetProfileV1(canonicalBytes(value), {
    releaseSequence: parsed.releaseSequence,
    hive: {
      artifactHash: hexBytes(parsed.hiveCellGet.artifactHash),
      manifestHash: hexBytes(parsed.hiveCellGet.manifestHash)
    }
  })
}

assert.equal(PEERIT_LIMITED_CELL_GET_PARAMETER_URL_V1,
  'https://evidence.example:443/admission.cenc')
const profile = verify(parsed)
assert.equal(profile.releaseSequence, parsed.releaseSequence)
for (const relay of profile.relays) {
  assert.equal(Buffer.from(relay.admissionProfile.parameterUrl).toString('hex'),
    expectedUrlHex)
}

for (const drift of [
  null,
  'https://evidence.example/admission.cenc',
  'https://EVIDENCE.example:443/admission.cenc',
  'https://evidence.example:443/admission.cenc?',
  'http://evidence.example:443/admission.cenc',
  'https://attacker.example:443/admission.cenc',
  'https://evidence.example:443/admission.cend'
]) {
  const value = structuredClone(parsed)
  value.relays[0].admissionProfile.parameterUrl = drift
  assert.throws(() => verify(value), error =>
    error?.code === 'PEERIT_LIMITED_CELL_GET_PROFILE_INVALID',
  `non-exact parameterUrl must fail: ${String(drift)}`)
}

const omitted = structuredClone(parsed)
delete omitted.relays[0].admissionProfile.parameterUrl
assert.throws(() => verify(omitted), error =>
  error?.code === 'PEERIT_LIMITED_CELL_GET_PROFILE_INVALID')

const wrongSequence = structuredClone(parsed)
wrongSequence.releaseSequence = parsed.releaseSequence + 1
assert.throws(() => verify(wrongSequence), error =>
  error?.code === 'PEERIT_LIMITED_CELL_GET_PROFILE_INVALID')

assert.equal(source.includes('evidence.example'), true)
assert.doesNotMatch(profileVerifierSource, /new URL\([^\n]*parameterUrl/)
assert.doesNotMatch(profileVerifierSource, /fetch\([^\n]*parameterUrl/)
assert.doesNotMatch(relayConsumerSource, /new URL\([^\n]*parameterUrl/)
assert.doesNotMatch(relayConsumerSource, /fetch\([^\n]*parameterUrl/)
assert.equal(renderBlueprint.includes('evidence.example'), false)
assert.equal(renderHeaders.includes('evidence.example'), false)
console.log('peerit seq19 exact admission URL: canonical UTF-8 bytes pinned; null and semantic drift rejected')
