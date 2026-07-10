#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const checks = []

function read (rel) {
  return fs.readFileSync(path.join(root, rel), 'utf8')
}

function exists (rel) {
  return fs.existsSync(path.join(root, rel))
}

function add (name, ok, detail) {
  checks.push({ name, ok: Boolean(ok), detail })
}

function includes (rel, needle) {
  return exists(rel) && read(rel).includes(needle)
}

function loadJson (rel) {
  return JSON.parse(read(rel))
}

function runNodeCheck (rel) {
  const result = spawnSync(process.execPath, ['--check', rel], {
    cwd: root,
    encoding: 'utf8'
  })
  return {
    ok: result.status === 0,
    output: (result.stderr || result.stdout || '').trim()
  }
}

add('growth spec exists', exists('docs/GROWTH_AUTOMATION_SPEC.md'), 'docs/GROWTH_AUTOMATION_SPEC.md')

const packageJson = loadJson('package.json')
add('launch scripts registered', packageJson.scripts && packageJson.scripts['launch:readiness'] && packageJson.scripts['launch:seed-plan'] && packageJson.scripts['launch:utm'] && packageJson.scripts['launch:briefs'], 'package.json exposes launch:readiness, launch:seed-plan, launch:utm, and launch:briefs')

try {
  const release = loadJson('deploy/web-release.json')
  const relays = Array.isArray(release.roster && release.roster.relays) ? release.roster.relays.filter(Boolean) : []
  const networkQuorum = release.roster && release.roster.networkQuorum
  const readonly = release.readonly !== false
  add('public write topology is redundant', readonly || relays.length >= 2 || !!networkQuorum, readonly
    ? 'single-relay previews are acceptable only in read-only mode'
    : networkQuorum
      ? `${relays.length} browser ingress plus ${networkQuorum.relays && networkQuorum.relays.length || 0} roster-pinned receipt operator(s)`
      : `${relays.length} signed relay failure domain(s); writable public launch requires at least 2`)
  add('public release key pinned', /^[0-9a-f]{64}$/i.test(String(release.pinnedReleaseKey || '')), 'deploy/web-release.json must pin the Ed25519 key that signs asset-manifest.json')
} catch (err) {
  add('web release config valid', false, err.message)
}

try {
  const capacity = loadJson('reports/soak-outboxlog-local-2026-07-09.json')
  const clients = Number(capacity.clients || capacity.config && capacity.config.clients || 0)
  add('public capacity target measured', clients >= 2000, `${clients || 0} clients measured; public launch gate requires a documented 2,000-client staging run`)
} catch (err) {
  add('public capacity target measured', false, err.message)
}

let launchConfig = null
try {
  launchConfig = loadJson('launch/communities.json')
  const communities = Array.isArray(launchConfig.communities) ? launchConfig.communities : []
  const slugs = communities.map(c => c.slug)
  const unique = new Set(slugs)
  add('launch community config valid', communities.length >= 8 && unique.size === communities.length, `${communities.length} communities, ${unique.size} unique slugs`)
  add('launch community starter depth', communities.every(c => Number(c.starterPostCount) >= 10 && Number(c.discussionPromptCount) >= 3), 'each board needs starter posts and prompts')
  add('no excluded darknet positioning', !communities.some(c => /dread|darknet|darknet[-\s]?market/i.test(`${c.slug} ${c.title} ${c.audience} ${c.launchRole}`)), 'launch config avoids illegal/darknet-market positioning')
} catch (err) {
  add('launch community config valid', false, err.message)
}

const poWSyntax = exists('js/pow.js') ? runNodeCheck('js/pow.js') : { ok: false, output: 'js/pow.js missing' }
add('PoW module exists and parses', poWSyntax.ok, poWSyntax.output || 'js/pow.js')
add('gossip has app validate hook', includes('js/gossip.js', 'validate(type') || includes('js/gossip.js', 'validate)') || includes('js/gossip.js', 'opts.validate'), 'gossip ingest must reject no-PoW records before cache')
add('data mints PoW before signing', includes('js/data.js', '_powSign') && includes('js/data.js', 'mint('), 'posts/comments/communities must mint before signature')
add('PoW tests present', includes('test/gossip.mjs', 'proof-of-work') || includes('test/smoke.mjs', 'proof-of-work') || includes('test/gossip.mjs', 'no-PoW'), 'tests should reject signed records without PoW')
add('read-only gateway tracked', exists('docs/GROWTH_AUTOMATION_SPEC.md') && read('docs/GROWTH_AUTOMATION_SPEC.md').includes('Read-Only Gateway'), 'gateway preview remains a required launch workstream')

const failures = checks.filter(c => !c.ok)
for (const check of checks) {
  const mark = check.ok ? 'PASS' : 'FAIL'
  console.log(`${mark} ${check.name}${check.detail ? ` - ${check.detail}` : ''}`)
}

if (failures.length) {
  console.error(`\nLaunch readiness blocked: ${failures.length} check(s) failed.`)
  process.exit(1)
}

console.log('\nLaunch readiness passed.')
