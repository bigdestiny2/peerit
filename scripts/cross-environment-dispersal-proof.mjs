#!/usr/bin/env node
// cross-environment-dispersal-proof.mjs — run all peerit dispersal proofs
// across environments and produce one go/no-go report.
//
//   node scripts/cross-environment-dispersal-proof.mjs [path/to/roster.json]
//
// Environments exercised:
//   1. Node dealer + Node reader (js/blind-dealer.mjs)
//   2. Node dealer + browser reader bundle (js/reader-bundle.js)
//   3. PearBrowser bridge peers read shards from the remote cohort (post records
//      replicate through P2P bridge sync; shards/ciphertext stay on the HTTP cohort)
//   4. App wiring (runtime.js → data.js dispersal flag plumbing)
//
// Exit 0 = all environments pass. Writes reports/cross-environment-dispersal-<date>.json.
import fs from 'node:fs'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const COHORT_DEFAULT = path.join(process.env.HOME || '/tmp', '.hiverelay-shard-cohort', 'roster.json')
const ROSTER_PATH = process.argv[2] || COHORT_DEFAULT
const REPORT_DIR = path.join(ROOT, 'reports')

function run (cmd, args, { env = process.env, timeoutMs = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: ROOT, env, stdio: 'pipe' })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d })
    child.stderr.on('data', (d) => { stderr += d })
    const timer = setTimeout(() => { child.kill('SIGTERM'); reject(new Error('timeout')) }, timeoutMs)
    child.on('error', (e) => { clearTimeout(timer); reject(e) })
    child.on('exit', (code) => {
      clearTimeout(timer)
      if (code === 0) resolve({ stdout, stderr })
      else reject(new Error(`exit ${code}: ${stderr || stdout}`))
    })
  })
}

async function proofNodeReader () {
  // reader-bundle-live.mjs already uses the browser bundle, but it also proves
  // the Node dealer path because it calls disperseBody. We run it to cover both
  // the Node dealer and the browser reader in one check.
  await run('node', ['scripts/reader-bundle-live.mjs', ROSTER_PATH])
  return { nodeDealer: true, browserReader: true }
}

async function proofBridgeTransport () {
  await run('node', ['test/pearbrowser-dispersal-convergence.mjs'])
  return { bridgeCohortRead: true }
}

async function proofAppWiring () {
  await run('node', ['test/dispersal-app-wiring.mjs'])
  return { appWiring: true }
}

async function main () {
  if (!fs.existsSync(ROSTER_PATH)) {
    console.error(`[cross-env] roster not found: ${ROSTER_PATH}`)
    console.error('  start a local cohort: cd ../hiverelay && node scripts/run-local-shard-cohort.mjs')
    process.exit(2)
  }

  console.log(`\n[cross-env] roster: ${ROSTER_PATH}`)
  const cfg = JSON.parse(fs.readFileSync(ROSTER_PATH, 'utf8'))
  console.log(`[cross-env] cohort: ${cfg.relays?.length || 0} relays, k=${cfg.threshold}`)

  const report = {
    kind: 'cross-environment-dispersal',
    generatedAt: new Date().toISOString(),
    rosterPath: ROSTER_PATH,
    cohort: { threshold: cfg.threshold, count: cfg.relays?.length || 0, relays: cfg.relays?.map(r => r.baseUrl || r.url) },
    checks: {},
    status: 'started'
  }

  const checks = {}

  console.log('\n— 1/4 Node dealer + browser reader bundle —')
  try {
    Object.assign(checks, await proofNodeReader())
    console.log('  ✅ Node dealer + browser reader pass')
  } catch (e) {
    console.error('  ❌ Node dealer / browser reader failed:', e.message)
    checks.nodeDealer = false
    checks.browserReader = false
  }

  console.log('\n— 2/4 PearBrowser bridge peers read from remote cohort —')
  try {
    Object.assign(checks, await proofBridgeTransport())
    console.log('  ✅ Bridge peers read from remote cohort pass')
  } catch (e) {
    console.error('  ❌ Bridge peers read from remote cohort failed:', e.message)
    checks.bridgeCohortRead = false
  }

  console.log('\n— 3/4 App/runtime wiring —')
  try {
    Object.assign(checks, await proofAppWiring())
    console.log('  ✅ App wiring pass')
  } catch (e) {
    console.error('  ❌ App wiring failed:', e.message)
    checks.appWiring = false
  }

  console.log('\n— 4/4 Web build ships reader bundle —')
  try {
    const bundlePath = path.join(ROOT, 'web', 'js', 'reader-bundle.js')
    if (!fs.existsSync(bundlePath)) throw new Error('web/js/reader-bundle.js missing; run npm run build-web')
    const stat = fs.statSync(bundlePath)
    if (stat.size < 1000) throw new Error('reader bundle looks like a stub')
    checks.webBundleShipsReader = true
    console.log(`  ✅ Web reader bundle present (${stat.size} bytes)`)
  } catch (e) {
    console.error('  ❌ Web reader bundle check failed:', e.message)
    checks.webBundleShipsReader = false
  }

  report.checks = checks
  report.status = Object.values(checks).every(Boolean) ? 'pass' : 'fail'

  fs.mkdirSync(REPORT_DIR, { recursive: true })
  const date = new Date().toISOString().slice(0, 10)
  const reportPath = path.join(REPORT_DIR, `cross-environment-dispersal-${date}.json`)
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2))

  console.log(`\n[cross-env] report: ${reportPath}`)
  if (report.status === 'pass') {
    console.log('[cross-env] ✅ PASS — dispersal works across Node, browser bundle, PearBrowser bridge cohort reads, and app wiring\n')
    process.exit(0)
  } else {
    console.error('[cross-env] ❌ FAIL — see report above\n')
    process.exit(1)
  }
}

main().catch((e) => {
  console.error('[cross-env] ❌', e.message, '\n', e.stack)
  process.exit(1)
})
