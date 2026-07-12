#!/usr/bin/env node
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import { verifyProfileInventory } from '../js/substrate/profile-inventory-scan.mjs'
import {
  PEERIT_PROFILE_STATUS,
  PROFILE_ARTIFACT_STATUS,
  PROFILE_RELEASE_BLOCKERS,
  PROFILE_UNPUBLISHED_ARTIFACTS
} from '../js/substrate/profile-status.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const profilePath = path.join(root, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md')
const profileBytes = fs.readFileSync(profilePath)
const profileText = profileBytes.toString('utf8')

assert.equal(profileBytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])), false, 'profile must not have a UTF-8 BOM')
assert.equal(profileText.includes('\r'), false, 'profile must use LF, never CR')
assert.equal(profileText.endsWith('\n'), true, 'profile must have one final LF')
assert.equal(profileText.endsWith('\n\n'), false, 'profile must have exactly one final LF')

const result = verifyProfileInventory(profileText, PEERIT_PROFILE_INVENTORY)
if (!result.ok) {
  for (const entry of result.problems) process.stderr.write(`${entry.code}: ${entry.detail}\n`)
  process.exit(1)
}

assert.equal(PEERIT_PROFILE_STATUS.inventoryReady, true)
assert.equal(PEERIT_PROFILE_STATUS.releaseReady, false)
assert.deepEqual(PEERIT_PROFILE_STATUS.releaseBlockers, PROFILE_RELEASE_BLOCKERS)
assert.equal(result.declarationCount, PEERIT_PROFILE_STATUS.schemaCount)
assert.equal(result.recordCount, PEERIT_PROFILE_STATUS.recordCount)
assert.equal(result.taggedUnionCount, PEERIT_PROFILE_STATUS.taggedUnionCount)
assert.equal(result.inlineShapeCount, PEERIT_PROFILE_STATUS.inlineShapeCount)
assert.equal(result.externalTypeCount, PEERIT_PROFILE_STATUS.externalHiveRelayTypeCount)
assert.equal(result.profileRegistryCount, PEERIT_PROFILE_STATUS.profileRegistryCount)
assert.equal(PEERIT_PROFILE_STATUS.profileRegistryReady, true)
assert.equal(PEERIT_PROFILE_STATUS.profileVectorManifestReady, true)
assert.equal(PROFILE_ARTIFACT_STATUS.fixtureOnly, false)
assert.equal(PROFILE_RELEASE_BLOCKERS.includes('PROFILE_REGISTRY_ARTIFACT_MISSING'), false)
assert.equal(PROFILE_RELEASE_BLOCKERS.includes('PROFILE_VECTOR_MANIFEST_MISSING'), false)
assert.equal(fs.existsSync(path.join(root, PROFILE_ARTIFACT_STATUS.registryArtifact)), true)
assert.equal(fs.existsSync(path.join(root, PROFILE_ARTIFACT_STATUS.vectorManifest)), true)

for (const [blocker, relativePath] of Object.entries(PROFILE_UNPUBLISHED_ARTIFACTS)) {
  assert.equal(PROFILE_RELEASE_BLOCKERS.includes(blocker), true, `${blocker} must remain explicit`)
  assert.equal(fs.existsSync(path.join(root, relativePath)), false, `${relativePath} exists but its release blocker remains`)
}

process.stdout.write(`${JSON.stringify({
  schema: 'PeeritBlindProfileMechanicalInventoryV1',
  profileSha256: result.profileSha256,
  declarations: result.declarationCount,
  records: result.recordCount,
  taggedUnions: result.taggedUnionCount,
  inlineShapes: result.inlineShapeCount,
  categories: result.categoryCounts,
  externalHiveRelayTypes: PEERIT_PROFILE_INVENTORY.externalTypes.map(entry => entry.name),
  externalHiveRelayCodecImports: PEERIT_PROFILE_INVENTORY.externalCodecImports.map(entry => ({
    name: entry.name,
    authorityKind: entry.authorityKind
  })),
  profileRegistries: PEERIT_PROFILE_INVENTORY.profileRegistries.map(entry => entry.name),
  profileArtifacts: {
    registry: PROFILE_ARTIFACT_STATUS.registryArtifact,
    vectors: PROFILE_ARTIFACT_STATUS.vectorManifest,
    profileSpecHash: PROFILE_ARTIFACT_STATUS.profileSpecHash,
    profileAbiHash: PROFILE_ARTIFACT_STATUS.profileAbiHash,
    profileVectorSetHash: PROFILE_ARTIFACT_STATUS.profileVectorSetHash
  },
  releaseReady: PEERIT_PROFILE_STATUS.releaseReady,
  releaseBlockers: PROFILE_RELEASE_BLOCKERS
}, null, 2)}\n`)
