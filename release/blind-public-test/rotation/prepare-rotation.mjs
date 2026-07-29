#!/usr/bin/env node
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs/promises'
import {
  byteHex,
  currentEpoch,
  fileSha256,
  inspectRotationInputs,
  loadRotationPolicy,
  parseAbsoluteFileList,
  prepareRotationBundle
} from './core.mjs'
import { serviceDescriptorHash } from '@hiverelay/blind-protocol'

function required (environment, name) {
  const value = environment[name]
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`)
  return value
}

function canonicalAbsolute (value, name) {
  if (!path.isAbsolute(value) || path.normalize(value) !== value || value.includes('\0')) {
    throw new Error(`${name} must be one canonical absolute path`)
  }
  return value
}

const environment = process.env
const mode = environment.HIVERELAY_OPERATOR_MODE || 'inspect'
if (mode !== 'inspect' && mode !== 'prepare') throw new Error('HIVERELAY_OPERATOR_MODE must be inspect or prepare')

const scriptFile = fileURLToPath(import.meta.url)
const moduleFile = fileURLToPath(new URL('./core.mjs', import.meta.url))
const defaultPolicyFile = fileURLToPath(new URL('./admission-policy-v2.json', import.meta.url))
const policyFile = canonicalAbsolute(environment.HIVERELAY_OPERATOR_POLICY_FILE || defaultPolicyFile,
  'HIVERELAY_OPERATOR_POLICY_FILE')
const expectedPolicySha256 = required(environment, 'HIVERELAY_OPERATOR_EXPECTED_POLICY_SHA256')
const { policy, sha256: policySha256 } = await loadRotationPolicy(policyFile, expectedPolicySha256)
const relayId = required(environment, 'HIVERELAY_OPERATOR_RELAY_ID')
const descriptorFiles = parseAbsoluteFileList(
  required(environment, 'HIVERELAY_BLIND_DESCRIPTOR_FILES'), 'HIVERELAY_BLIND_DESCRIPTOR_FILES')
const admissionFiles = parseAbsoluteFileList(
  required(environment, 'HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES'),
  'HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES')
const nowEpoch = environment.HIVERELAY_OPERATOR_NOW_EPOCH == null
  ? currentEpoch()
  : Number(required(environment, 'HIVERELAY_OPERATOR_NOW_EPOCH'))
const descriptorChainBytes = await Promise.all(descriptorFiles.map(file => fs.readFile(file)))
const admissionParameterBytes = await Promise.all(admissionFiles.map(file => fs.readFile(file)))
const inspected = await inspectRotationInputs({
  descriptorChainBytes,
  admissionParameterBytes,
  nowEpoch,
  relayId,
  policy
})
const expectedSequence = required(environment, 'HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE')
const expectedHash = required(environment, 'HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH')
const actualHash = byteHex(serviceDescriptorHash(descriptorChainBytes.at(-1)))
if (expectedSequence !== inspected.head.descriptorSequence.toString() || expectedHash !== actualHash) {
  throw new Error('configured expected descriptor sequence/hash do not match the inspected predecessor')
}

const publicInspection = {
  schema: 'hiverelay-blind-public-test-rotation-inspection-v1',
  mode,
  relayId,
  policySha256,
  policyStatus: policy.raw.status,
  nowEpoch,
  predecessorSequence: inspected.head.descriptorSequence.toString(),
  predecessorHash: actualHash,
  predecessorWindow: [inspected.head.issuedEpoch, inspected.head.expiresEpoch],
  chainLength: descriptorFiles.length,
  successorSequence: inspected.nextSequence.toString(),
  successorWindow: [inspected.issuedEpoch, inspected.expiresEpoch],
  successorAdmissionWindow: [inspected.issuedEpoch, inspected.admissionExpiresEpoch],
  class2AlreadyPresent: !inspected.rowPolicy.class2Added,
  class2Candidate: {
    familyId: 2,
    operationId: 1,
    resourceClass: 2,
    leaseClass: 1,
    costUnits: '40'
  },
  secretRead: false,
  filesWritten: false
}

if (mode === 'inspect') {
  console.log(JSON.stringify(publicInspection))
} else {
  const rotationRoot = canonicalAbsolute(required(environment, 'HIVERELAY_OPERATOR_ROTATION_ROOT'),
    'HIVERELAY_OPERATOR_ROTATION_ROOT')
  const prepared = await prepareRotationBundle({
    descriptorFiles,
    admissionFiles,
    secretKeyFile: canonicalAbsolute(
      required(environment, 'HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE'),
      'HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE'),
    policy,
    policySha256,
    relayId,
    nowEpoch,
    rotationRoot,
    toolDigests: {
      prepareRotationSha256: await fileSha256(scriptFile),
      rotationCoreSha256: await fileSha256(moduleFile)
    }
  })
  console.log(JSON.stringify({
    ...publicInspection,
    mode: prepared.mode,
    directory: prepared.directory,
    successorHash: prepared.result.successorHash,
    admissionParameterHash: prepared.result.admissionParameterHash,
    secretRead: true,
    secretRetained: false,
    filesWritten: prepared.mode !== 'reused'
  }))
}
