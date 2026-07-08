#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dedupeRelayList,
  normalizeRelayRosterPayload,
  verifyRelayRoster
} from '../js/relay-roster.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dir, '..')
const DEFAULT_CONFIG = resolve(ROOT, 'deploy', 'web-release.json')
const HEX64 = /^[0-9a-f]{64}$/i

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error([
    'usage: node scripts/relay-roster-proof.mjs [--config deploy/web-release.json] [--roster relay-roster.json] [--out <file>] [--json]'
  ].join('\n'))
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    config: process.env.PEERIT_WEB_RELEASE_CONFIG || DEFAULT_CONFIG,
    roster: '',
    out: '',
    json: false
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--config') opts.config = resolve(ROOT, argv[++i] || '')
    else if (arg === '--roster') opts.roster = resolve(ROOT, argv[++i] || '')
    else if (arg === '--out') opts.out = resolve(ROOT, argv[++i] || '')
    else if (arg === '--json') opts.json = true
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }

  return opts
}

function readJsonFile (file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}

function addCheck (report, id, status, message, evidence = undefined) {
  const check = { id, status, message }
  if (evidence !== undefined) check.evidence = evidence
  report.checks.push(check)
  return check
}

function finishReport (report) {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 }
  for (const check of report.checks) counts[check.status] = (counts[check.status] || 0) + 1
  report.counts = counts
  report.status = counts.fail > 0 ? 'blocked' : (counts.warn > 0 ? 'review' : 'ready')
  report.summary = report.status === 'blocked'
    ? `${counts.fail} relay roster proof check${counts.fail === 1 ? '' : 's'} failed.`
    : report.status === 'review'
      ? `${counts.warn} relay roster proof warning${counts.warn === 1 ? '' : 's'} to review.`
      : 'Signed relay roster matches the web release config.'
}

function samePayload (a, b) {
  return JSON.stringify(normalizeRelayRosterPayload(a)) === JSON.stringify(normalizeRelayRosterPayload(b))
}

function normalizeReleaseConfig (raw = {}) {
  const bootstrapRelays = Array.isArray(raw.bootstrapRelays)
    ? raw.bootstrapRelays.map((v) => String(v).trim()).filter(Boolean)
    : String(raw.relay || '').split(',').map((v) => v.trim()).filter(Boolean)
  const roster = normalizeRelayRosterPayload(raw.roster || {
    version: 1,
    expires: raw.expires,
    relays: raw.relays || bootstrapRelays
  })

  return {
    bootstrapRelays,
    normalizedBootstrapRelays: dedupeRelayList(bootstrapRelays),
    relayRoster: raw.relayRoster || 'relay-roster.json',
    pinnedRosterKey: String(raw.pinnedRosterKey || raw.rosterKey || '').trim().toLowerCase(),
    roster
  }
}

export async function buildRelayRosterProof ({
  config,
  roster,
  configFile = 'deploy/web-release.json',
  rosterFile = 'relay-roster.json',
  now = Date.now()
} = {}) {
  const report = {
    kind: 'peerit-relay-roster-evidence',
    appId: 'peerit',
    generatedAt: new Date(now).toISOString(),
    config: configFile,
    roster: rosterFile,
    checks: []
  }

  const release = normalizeReleaseConfig(config)
  report.release = {
    bootstrapRelays: release.normalizedBootstrapRelays,
    rosterRelays: release.roster.relays,
    pinnedRosterKey: release.pinnedRosterKey,
    expires: release.roster.expires
  }

  if (!release.bootstrapRelays.length) {
    addCheck(report, 'config:bootstrap-relays', 'fail', 'deploy/web-release.json must configure at least one bootstrap relay.')
  } else if (release.normalizedBootstrapRelays.length !== release.bootstrapRelays.length) {
    addCheck(report, 'config:bootstrap-relays', 'fail', 'bootstrapRelays must be canonical, supported, and unique.', {
      raw: release.bootstrapRelays,
      normalized: release.normalizedBootstrapRelays
    })
  } else {
    addCheck(report, 'config:bootstrap-relays', 'pass', `Release config has ${release.bootstrapRelays.length} canonical bootstrap relay${release.bootstrapRelays.length === 1 ? '' : 's'}.`, {
      relays: release.normalizedBootstrapRelays
    })
  }

  if (!HEX64.test(release.pinnedRosterKey)) {
    addCheck(report, 'config:pinned-key', 'fail', 'deploy/web-release.json must pin a 32-byte relay roster public key.')
  } else {
    addCheck(report, 'config:pinned-key', 'pass', `Release config pins roster key ${release.pinnedRosterKey.slice(0, 12)}...`, {
      key: release.pinnedRosterKey
    })
  }

  if (!release.roster.relays.length) {
    addCheck(report, 'config:roster-relays', 'fail', 'deploy/web-release.json roster.relays must include at least one relay.')
  } else {
    addCheck(report, 'config:roster-relays', 'pass', `Release config asks the signed roster to carry ${release.roster.relays.length} relay${release.roster.relays.length === 1 ? '' : 's'}.`, {
      relays: release.roster.relays
    })
  }

  if (!roster || typeof roster !== 'object') {
    addCheck(report, 'roster:json', 'fail', `${rosterFile} is missing or invalid.`)
    finishReport(report)
    return report
  }
  addCheck(report, 'roster:json', 'pass', `${rosterFile} parses.`)

  const signer = String(roster.signature && roster.signature.key || '').trim().toLowerCase()
  report.signedRoster = {
    signer,
    relays: normalizeRelayRosterPayload(roster.payload).relays,
    expires: normalizeRelayRosterPayload(roster.payload).expires
  }

  if (signer !== release.pinnedRosterKey) {
    addCheck(report, 'roster:signer', 'fail', `${rosterFile} signer does not match deploy/web-release.json pinnedRosterKey.`, {
      signer,
      pinnedRosterKey: release.pinnedRosterKey
    })
  } else {
    addCheck(report, 'roster:signer', 'pass', `${rosterFile} signer matches the pinned key.`)
  }

  if (!samePayload(roster.payload, release.roster)) {
    addCheck(report, 'roster:payload-match', 'fail', `${rosterFile} payload does not match deploy/web-release.json roster.`, {
      configRelays: release.roster.relays,
      signedRelays: report.signedRoster.relays,
      configExpires: release.roster.expires,
      signedExpires: report.signedRoster.expires
    })
  } else {
    addCheck(report, 'roster:payload-match', 'pass', `${rosterFile} payload matches deploy/web-release.json roster.`, {
      relays: release.roster.relays
    })
  }

  const missingBootstrap = release.normalizedBootstrapRelays.filter(relay => !report.signedRoster.relays.includes(relay))
  if (missingBootstrap.length) {
    addCheck(report, 'roster:bootstrap-covered', 'fail', 'Signed relay roster is missing bootstrap relays from deploy/web-release.json.', {
      missing: missingBootstrap
    })
  } else {
    addCheck(report, 'roster:bootstrap-covered', 'pass', 'Signed relay roster covers every configured bootstrap relay.')
  }

  try {
    const verified = await verifyRelayRoster(roster, { expectedKey: release.pinnedRosterKey, now })
    addCheck(report, 'roster:signature', 'pass', `${rosterFile} signature verifies with the pinned key.`, {
      expires: verified.expires,
      relays: verified.relays
    })
    const daysLeft = Math.floor((Date.parse(verified.expires) - now) / 86400000)
    if (daysLeft < 14) {
      addCheck(report, 'roster:expiry', 'warn', `Signed relay roster expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}.`, {
        expires: verified.expires
      })
    } else {
      addCheck(report, 'roster:expiry', 'pass', `Signed relay roster expiry has ${daysLeft} days remaining.`, {
        expires: verified.expires
      })
    }
  } catch (err) {
    addCheck(report, 'roster:signature', 'fail', `${rosterFile} signature proof failed: ${err.message}`)
  }

  finishReport(report)
  return report
}

function printHuman (report) {
  for (const check of report.checks) {
    const prefix = check.status.toUpperCase().padEnd(4)
    console.log(`[relay-roster] ${prefix} ${check.message}`)
  }
  console.log(`[relay-roster] status=${report.status} pass=${report.counts.pass || 0} warn=${report.counts.warn || 0} fail=${report.counts.fail || 0} info=${report.counts.info || 0}`)
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  let config
  let roster
  let rosterFile = opts.roster

  try {
    config = readJsonFile(opts.config)
  } catch (err) {
    const report = {
      kind: 'peerit-relay-roster-evidence',
      appId: 'peerit',
      generatedAt: new Date().toISOString(),
      config: relative(ROOT, opts.config),
      roster: rosterFile ? relative(ROOT, rosterFile) : '',
      checks: []
    }
    addCheck(report, 'config:json', 'fail', `${relative(ROOT, opts.config)} is missing or invalid: ${err.message}`)
    finishReport(report)
    if (opts.json) console.log(JSON.stringify(report, null, 2))
    else printHuman(report)
    process.exit(1)
  }

  const release = normalizeReleaseConfig(config)
  if (!rosterFile) rosterFile = resolve(ROOT, release.relayRoster)

  try {
    if (!existsSync(rosterFile)) throw new Error('file does not exist')
    roster = readJsonFile(rosterFile)
  } catch {
    roster = null
  }

  const report = await buildRelayRosterProof({
    config,
    roster,
    configFile: relative(ROOT, opts.config),
    rosterFile: relative(ROOT, rosterFile)
  })

  if (opts.out) {
    mkdirSync(dirname(opts.out), { recursive: true })
    writeFileSync(opts.out, JSON.stringify(report, null, 2) + '\n')
  }

  if (opts.json) console.log(JSON.stringify(report, null, 2))
  else printHuman(report)

  process.exit(report.status === 'blocked' ? 1 : 0)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((err) => {
    console.error('[relay-roster] FAIL', err.stack || err.message)
    process.exit(1)
  })
}
