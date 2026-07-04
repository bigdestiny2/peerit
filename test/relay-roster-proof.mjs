// relay-roster-proof.mjs - release evidence tests for signed relay roster config.

import assert from 'node:assert'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { genKeyPair, ready as cryptoReady, sign } from '../js/crypto.js'
import {
  normalizeRelayRosterPayload,
  rosterSigningMessage
} from '../js/relay-roster.js'
import { buildRelayRosterProof } from '../scripts/relay-roster-proof.mjs'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

async function signedRoster (relays, expires = '2030-01-01T00:00:00.000Z') {
  const keypair = await genKeyPair()
  const payload = normalizeRelayRosterPayload({ version: 1, expires, relays })
  return {
    keypair,
    roster: {
      payload,
      signature: {
        alg: 'Ed25519',
        key: keypair.pubHex,
        sig: await sign(keypair.seedHex, rosterSigningMessage(payload))
      }
    }
  }
}

function releaseConfig ({ key, relays, expires = '2030-01-01T00:00:00.000Z' }) {
  return {
    bootstrapRelays: relays,
    readonly: false,
    relayRoster: 'relay-roster.json',
    pinnedRosterKey: key,
    dhtRelay: '',
    roster: { version: 1, expires, relays }
  }
}

async function main () {
  await cryptoReady()
  console.log('\n- relay roster release evidence -')

  const readyFixture = await signedRoster(['https://relay-a.example', 'https://relay-b.example'])
  const ready = await buildRelayRosterProof({
    config: releaseConfig({
      key: readyFixture.keypair.pubHex,
      relays: ['https://relay-a.example', 'https://relay-b.example']
    }),
    roster: readyFixture.roster,
    now: Date.parse('2029-01-01T00:00:00.000Z')
  })
  ok(ready.kind === 'peerit-relay-roster-evidence', 'proof reports the evidence kind')
  ok(ready.status === 'ready', 'matching signed roster and release config are ready')
  ok(!ready.checks.some(check => check.status === 'fail'), 'ready proof has no failing rows')

  const blocked = await buildRelayRosterProof({
    config: releaseConfig({
      key: readyFixture.keypair.pubHex,
      relays: ['https://relay-a.example', 'https://new-relay.example']
    }),
    roster: readyFixture.roster,
    now: Date.parse('2029-01-01T00:00:00.000Z')
  })
  ok(blocked.status === 'blocked', 'unsigned release config changes block the proof')
  ok(blocked.checks.some(check => check.id === 'roster:payload-match' && check.status === 'fail'), 'blocked proof names the roster payload mismatch')
  ok(blocked.checks.some(check => check.id === 'roster:bootstrap-covered' && check.status === 'fail'), 'blocked proof names missing bootstrap relays')

  const tmp = mkdtempSync(join(tmpdir(), 'peerit-roster-proof-'))
  const configFile = join(tmp, 'web-release.json')
  const rosterFile = join(tmp, 'relay-roster.json')
  const reportFile = join(tmp, 'relay-roster-evidence.json')
  writeFileSync(configFile, JSON.stringify(releaseConfig({
    key: readyFixture.keypair.pubHex,
    relays: ['https://relay-a.example', 'https://relay-b.example']
  }), null, 2))
  writeFileSync(rosterFile, JSON.stringify(readyFixture.roster, null, 2))
  const cli = spawnSync(process.execPath, [
    'scripts/relay-roster-proof.mjs',
    '--config', configFile,
    '--roster', rosterFile,
    '--out', reportFile,
    '--json'
  ], { encoding: 'utf8' })
  ok(cli.status === 0, 'CLI exits 0 for ready roster evidence')
  const report = JSON.parse(readFileSync(reportFile, 'utf8'))
  ok(report.status === 'ready', 'CLI writes reusable ready evidence')
  ok(JSON.parse(cli.stdout).status === 'ready', 'CLI prints machine-readable JSON')

  writeFileSync(configFile, JSON.stringify(releaseConfig({
    key: readyFixture.keypair.pubHex,
    relays: ['https://relay-a.example', 'https://new-relay.example']
  }), null, 2))
  const blockedCli = spawnSync(process.execPath, [
    'scripts/relay-roster-proof.mjs',
    '--config', configFile,
    '--roster', rosterFile,
    '--json'
  ], { encoding: 'utf8' })
  ok(blockedCli.status === 1, 'CLI exits 1 when config and signed roster drift')
  ok(JSON.parse(blockedCli.stdout).checks.some(check => check.id === 'roster:payload-match' && check.status === 'fail'), 'CLI JSON pinpoints the mismatch')

  console.log(`\nOK ${passed} relay-roster-proof checks passed\n`)
}

main().catch((e) => { console.error('\nFAILED:', e.message, '\n', e.stack); process.exit(1) })
