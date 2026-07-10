// Exact-deployment verifier mode regression.
// Run: node test/deployed-web-mode.mjs

import assert from 'node:assert/strict'
import {
  releaseConfig,
  verifyIndexConfig,
  verifyManifestConfig
} from '../scripts/verify-deployed-web.mjs'

const HASH = 'a'.repeat(64)
const DRIVE = 'b'.repeat(64)
const ROSTER_KEY = 'c'.repeat(64)
const RELEASE_KEY = 'd'.repeat(64)

function rawConfig (readonly) {
  return {
    bootstrapRelays: ['https://relay-a.example', 'https://relay-b.example'],
    readonly,
    releaseSequence: 7,
    relayRoster: 'relay-roster.json',
    pinnedRosterKey: ROSTER_KEY,
    pinnedReleaseKey: RELEASE_KEY,
    dhtRelay: '',
    shardRoster: '',
    seedOutboxes: [],
    roster: {
      version: 1,
      expires: '2030-01-01T00:00:00.000Z',
      relays: ['https://relay-a.example', 'https://relay-b.example']
    }
  }
}

function indexHtml (release, readonly = release.readonly, extra = '') {
  return `<!doctype html><head>
    <meta name="peerit-relay" content="${release.relay}">
    <meta name="peerit-relay-readonly" content="${readonly}">
    <meta name="peerit-relay-roster" content="${release.relayRoster}">
    <meta name="peerit-relay-roster-key" content="${release.pinnedRosterKey}">
    <meta name="peerit-release-key" content="${release.pinnedReleaseKey}">
    <meta name="peerit-release-sequence" content="${release.releaseSequence}">
    ${extra}
  </head>`
}

function manifestFor (release) {
  return {
    releaseSequence: release.releaseSequence,
    driveKey: DRIVE,
    files: { 'relay-roster.json': HASH },
    webRelease: {
      releaseSequence: release.releaseSequence,
      relay: release.relay,
      relayBackend: '',
      readonly: release.readonly,
      relayRoster: release.relayRoster,
      relayRosterKey: release.pinnedRosterKey,
      relayRosterSha256: HASH,
      shardRoster: '',
      shardRosterSha256: '',
      releaseKey: release.pinnedReleaseKey
    }
  }
}

const readonly = releaseConfig(rawConfig(true))
assert.equal(readonly.readonly, 'true')
verifyIndexConfig(indexHtml(readonly), readonly)
verifyManifestConfig(manifestFor(readonly), readonly, HASH, '', DRIVE)

const writable = releaseConfig(rawConfig(false))
assert.equal(writable.readonly, 'false')
verifyIndexConfig(indexHtml(writable), writable)
verifyManifestConfig(manifestFor(writable), writable, HASH, '', DRIVE)

assert.throws(
  () => releaseConfig({ ...rawConfig(false), readonly: undefined }),
  /explicitly set readonly=true or readonly=false/
)
assert.throws(
  () => releaseConfig({
    ...rawConfig(false),
    roster: { ...rawConfig(false).roster, relays: ['https://relay-a.example'] }
  }),
  /at least two signed roster relays/
)
assert.throws(
  () => releaseConfig({ ...rawConfig(true), shardRoster: 'config/shards.json' }),
  /read-only release must not configure a shard roster/
)
assert.throws(
  () => verifyIndexConfig(indexHtml(writable, 'true'), writable),
  /readonly meta does not match/
)
assert.throws(
  () => verifyManifestConfig({
    ...manifestFor(writable),
    webRelease: { ...manifestFor(writable).webRelease, readonly: 'true' }
  }, writable, HASH, '', DRIVE),
  /webRelease.readonly does not match/
)
assert.throws(
  () => verifyIndexConfig(indexHtml(readonly, 'true', '<meta name="peerit-shard-roster" content="unexpected.json">'), readonly),
  /must not contain peerit-shard-roster/
)

console.log('deployed-web-mode: read-only and writable verifier modes passed')
