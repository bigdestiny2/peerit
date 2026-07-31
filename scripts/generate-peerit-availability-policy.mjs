#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  PEERIT_AVAILABILITY_POLICY_ARTIFACT,
  PEERIT_AVAILABILITY_POLICY_V1,
  assertAvailabilityPolicyRegistryBinding,
  availabilityPolicyHash,
  encodeAvailabilityPolicyV1
} from '../js/substrate/availability-policy.mjs'
import { AVAILABILITY_POLICY_STATUS } from '../js/substrate/profile-status.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const REGISTRY = resolve(ROOT, 'protocol/peerit-profile-v1.cenc')
const OUTPUT = resolve(ROOT, PEERIT_AVAILABILITY_POLICY_ARTIFACT)
const CHECK = process.argv.includes('--check')

function hex (value) {
  return Buffer.from(value).toString('hex')
}

async function main () {
  const registryBytes = new Uint8Array(await readFile(REGISTRY))
  assertAvailabilityPolicyRegistryBinding(registryBytes)
  const bytes = encodeAvailabilityPolicyV1(PEERIT_AVAILABILITY_POLICY_V1)
  const hash = availabilityPolicyHash(bytes)
  if (hex(hash) !== AVAILABILITY_POLICY_STATUS.availabilityPolicyHash ||
      bytes.byteLength !== AVAILABILITY_POLICY_STATUS.byteLength) {
    throw new Error('availability policy status hash/length is stale')
  }
  if (CHECK) {
    const existing = new Uint8Array(await readFile(OUTPUT))
    if (existing.byteLength !== bytes.byteLength || existing.some((byte, index) => byte !== bytes[index])) {
      throw new Error(`${PEERIT_AVAILABILITY_POLICY_ARTIFACT} is stale; run npm run generate:availability-policy`)
    }
  } else {
    await writeFile(OUTPUT, bytes)
  }
  process.stdout.write(JSON.stringify({
    schema: 'PeeritAvailabilityPolicyArtifactV1',
    path: PEERIT_AVAILABILITY_POLICY_ARTIFACT,
    byteLength: bytes.byteLength,
    availabilityPolicyHash: hex(hash),
    registryBound: true,
    releaseReady: false
  }, null, 2) + '\n')
}

main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
