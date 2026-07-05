#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { SITE_FILES } from './publish.mjs'

const __dir = dirname(fileURLToPath(import.meta.url))

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error('usage: node ship.mjs [--publish] [--allow-dirty] [--no-test] [--no-web] [--anchor-timeout-ms 240000] [--report <file>]')
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    publish: false,
    allowDirty: false,
    skipTests: false,
    skipWeb: process.env.SKIP_WEB_RELEASE === '1',
    anchorTimeoutMs: process.env.ANCHOR_TIMEOUT_MS || '240000',
    report: join(__dir, '.deploy', 'last-ship.json'),
    publishReport: join(__dir, '.deploy', 'last-publish.json'),
    webReport: join(__dir, '.deploy', 'last-web-release.json')
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--publish' || arg === '--live') opts.publish = true
    else if (arg === '--check') opts.publish = false
    else if (arg === '--allow-dirty') opts.allowDirty = true
    else if (arg === '--no-test') opts.skipTests = true
    else if (arg === '--no-web') opts.skipWeb = true
    else if (arg === '--anchor-timeout-ms') opts.anchorTimeoutMs = argv[++i] || ''
    else if (arg === '--report') {
      const value = argv[++i]
      if (!value) usage(2, '--report requires a file path')
      opts.report = resolve(__dir, value)
    } else if (arg === '--publish-report') {
      const value = argv[++i]
      if (!value) usage(2, '--publish-report requires a file path')
      opts.publishReport = resolve(__dir, value)
    }
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }

  const timeout = Number(opts.anchorTimeoutMs)
  if (!Number.isFinite(timeout) || timeout <= 0) usage(2, '--anchor-timeout-ms must be a positive number')
  return opts
}

const opts = parseArgs(process.argv.slice(2))
const report = {
  appId: 'peerit',
  mode: opts.publish ? 'publish' : 'check',
  generatedAt: new Date().toISOString(),
  checks: [],
  publish: null,
  webRelease: null,
  status: 'started',
  summary: ''
}

function addCheck (id, status, message, evidence = undefined) {
  const check = { id, status, message }
  if (evidence) check.evidence = evidence
  report.checks.push(check)
  const prefix = status === 'pass' ? 'PASS' : status === 'warn' ? 'WARN' : status === 'fail' ? 'FAIL' : 'INFO'
  console.log(`[ship] ${prefix} ${message}`)
}

function finishReport () {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 }
  for (const check of report.checks) {
    if (counts[check.status] !== undefined) counts[check.status]++
  }
  report.counts = counts
  report.status = counts.fail > 0 ? 'blocked' : (counts.warn > 0 ? 'review' : 'ready')
  report.summary = report.status === 'blocked'
    ? `${counts.fail} failing ship check${counts.fail === 1 ? '' : 's'} must be fixed before publish.`
    : report.status === 'review'
      ? `${counts.warn} warning${counts.warn === 1 ? '' : 's'} to review before publish.`
      : 'Ready to ship.'
}

function writeReport () {
  finishReport()
  try {
    mkdirSync(dirname(opts.report), { recursive: true })
    writeFileSync(opts.report, JSON.stringify(report, null, 2) + '\n')
    console.log(`[ship] report: ${opts.report}`)
  } catch (err) {
    report.reportWriteError = err.message
    const fallback = join(tmpdir(), `peerit-ship-${Date.now()}.json`)
    writeFileSync(fallback, JSON.stringify(report, null, 2) + '\n')
    console.warn(`[ship] WARN could not write report to ${opts.report}: ${err.message}`)
    console.log(`[ship] report: ${fallback}`)
  }
}

function readJson (file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function run (cmd, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: __dir,
      stdio: 'inherit',
      env: options.env || process.env
    })
    child.on('error', reject)
    child.on('exit', (code, signal) => {
      if (code === 0) resolve()
      else reject(new Error(`${cmd} ${args.join(' ')} exited with ${signal || code}`))
    })
  })
}

function verifySiteFiles () {
  let totalBytes = 0
  const missing = []
  const empty = []
  for (const file of SITE_FILES) {
    const abs = join(__dir, file)
    if (!existsSync(abs)) {
      missing.push(file)
      continue
    }
    const stat = statSync(abs)
    totalBytes += stat.size
    if (stat.size <= 0) empty.push(file)
  }
  if (missing.length) addCheck('files:missing', 'fail', `${missing.length} served file${missing.length === 1 ? '' : 's'} missing.`, { missing })
  else addCheck('files:present', 'pass', `${SITE_FILES.length} served files are present.`, { files: SITE_FILES.length, bytes: totalBytes })

  if (empty.length) addCheck('files:empty', 'fail', `${empty.length} served file${empty.length === 1 ? ' is' : 's are'} empty.`, { empty })
}

function verifyStaticImports () {
  const served = new Set(SITE_FILES)
  const missing = []
  const importRe = /(?:^|\n)\s*import\s+(?:[^'"]+\s+from\s*)?['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g

  for (const file of SITE_FILES) {
    if (!file.endsWith('.js')) continue
    const abs = join(__dir, file)
    if (!existsSync(abs)) continue
    const src = readFileSync(abs, 'utf8')
    for (const match of src.matchAll(importRe)) {
      const spec = match[1] || match[2] || ''
      if (!spec.startsWith('./') && !spec.startsWith('../')) continue
      const imported = relative(__dir, resolve(__dir, dirname(file), spec.split(/[?#]/)[0])).replace(/\\/g, '/')
      if (!imported.startsWith('..') && !served.has(imported)) {
        missing.push({ from: file, import: spec, file: imported })
      }
    }
  }

  if (missing.length) {
    addCheck('files:imports', 'fail', `${missing.length} static module import${missing.length === 1 ? ' is' : 's are'} missing from SITE_FILES.`, { missing })
  } else {
    addCheck('files:imports', 'pass', 'Static module imports are included in the publish file list.')
  }
}

function verifyManifest () {
  const manifestPath = join(__dir, 'manifest.json')
  const manifest = readJson(manifestPath)
  if (!manifest) {
    addCheck('manifest:parse', 'fail', 'manifest.json is missing or invalid JSON.')
    return
  }
  if (manifest.name) addCheck('manifest:name', 'pass', `Manifest name is "${manifest.name}".`)
  else addCheck('manifest:name', 'fail', 'Manifest name is required.')
  if (manifest.description) addCheck('manifest:description', 'pass', 'Manifest description is present.')
  else addCheck('manifest:description', 'warn', 'Manifest description is missing.')
  if (/^[0-9a-f]{64}$/i.test(String(manifest.driveKey || ''))) {
    addCheck('manifest:drive-key', 'pass', `Manifest has drive key ${manifest.driveKey.slice(0, 12)}...`, { driveKey: manifest.driveKey })
  } else {
    addCheck('manifest:drive-key', 'warn', 'Manifest has no current drive key; publish will fill it.')
  }
}

function currentManifestDriveKey () {
  const manifest = readJson(join(__dir, 'manifest.json'))
  return String(manifest && manifest.driveKey || '')
}

function verifyGitCleanForServedFiles () {
  const tracked = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: __dir, encoding: 'utf8' })
  if (tracked.status !== 0) {
    addCheck('git:repo', 'warn', 'Git status is unavailable; served-file cleanliness was not checked.')
    return
  }

  const files = [
    ...SITE_FILES,
    'manifest.json',
    'relay-roster.json',
    'config/shard-roster.public.json',
    'deploy/web-release.json',
    'docs/WEB-DEPLOYMENT.md',
    'README.md',
    'build-web.mjs',
    'ship.mjs',
    'publish.mjs',
    'package.json',
    'scripts/web-release.mjs'
  ]
  const res = spawnSync('git', ['status', '--porcelain', '--', ...files], { cwd: __dir, encoding: 'utf8' })
  if (res.status !== 0) {
    addCheck('git:status', 'warn', 'Git status failed for served files.', { stderr: res.stderr.trim() })
    return
  }

  const dirty = res.stdout.split('\n').map((line) => line.trim()).filter(Boolean)
  if (!dirty.length) {
    addCheck('git:release-clean', 'pass', 'Release files are clean in git.')
    return
  }

  addCheck(
    'git:release-dirty',
    opts.allowDirty ? 'warn' : 'fail',
    `${dirty.length} release file${dirty.length === 1 ? ' is' : 's are'} dirty; commit or pass --allow-dirty before publishing.`,
    { dirty }
  )
}

async function runTests () {
  if (opts.skipTests) {
    addCheck('tests:skipped', 'warn', 'Tests were skipped by --no-test.')
    return
  }

  try {
    await run('node', ['test/smoke.mjs'])
    await run('node', ['test/gossip.mjs'])
    await run('node', ['test/bridge.mjs'])
    addCheck('tests:node', 'pass', 'Smoke, gossip, and bridge suites passed.')
  } catch (err) {
    addCheck('tests:node', 'fail', err.message)
  }
}

async function runPublish () {
  const publishEnv = {
    ...process.env,
    STRICT_ANCHOR: '1',
    ANCHOR_TIMEOUT_MS: String(opts.anchorTimeoutMs),
    DURABILITY: process.env.DURABILITY || 'archive',
    DEPLOY_REPORT: opts.publishReport
  }
  if (publishEnv.KEEP) {
    delete publishEnv.KEEP
    addCheck('publish:keep-ignored', 'warn', 'KEEP is ignored by ship so the post-publish web release can be rebuilt with the new drive key.')
  }

  mkdirSync(dirname(opts.publishReport), { recursive: true })
  await run('node', ['publish.mjs'], { env: publishEnv })

  const publishReport = readJson(opts.publishReport)
  report.publish = publishReport
  if (!publishReport) {
    addCheck('publish:report', 'warn', 'Publish completed, but no deploy report was written.')
    return
  }

  const meta = publishReport.durability && publishReport.durability.metadata
  const blobs = publishReport.durability && publishReport.durability.blobs
  if (meta && meta.durable && blobs && blobs.durable) {
    addCheck('publish:durable', 'pass', `Strict publish anchored ${publishReport.url}.`, {
      driveKey: publishReport.driveKey,
      contentKey: publishReport.contentKey,
      metadata: meta,
      blobs
    })
  } else {
    addCheck('publish:durable', 'fail', 'Publish finished without durable metadata and blob evidence.', { metadata: meta, blobs })
  }
}

async function runWebRelease (driveKey) {
  if (opts.skipWeb) {
    addCheck('web-release:skipped', 'warn', 'Web release build was skipped by --no-web.')
    return
  }

  mkdirSync(dirname(opts.webReport), { recursive: true })
  try {
    await run('node', ['scripts/web-release.mjs', '--drive-key', driveKey, '--report', opts.webReport])
  } catch (err) {
    const webReport = readJson(opts.webReport)
    report.webRelease = webReport
    addCheck('web-release:build', 'fail', err.message, webReport ? { status: webReport.status, summary: webReport.summary } : undefined)
    return
  }

  const webReport = readJson(opts.webReport)
  report.webRelease = webReport
  if (!webReport) {
    addCheck('web-release:report', 'warn', 'Web release completed, but no report was written.')
    return
  }
  if (webReport.status === 'ready') {
    addCheck('web-release:ready', 'pass', 'Web bundle, relay-roster.json, pinned key, and deploy docs are in sync.', {
      driveKey: webReport.driveKey,
      relayRoster: webReport.release && webReport.release.relayRoster,
      pinnedRosterKey: webReport.release && webReport.release.pinnedRosterKey
    })
  } else if (webReport.status === 'review') {
    addCheck('web-release:review', 'warn', webReport.summary, { status: webReport.status })
  } else {
    addCheck('web-release:blocked', 'fail', webReport.summary || 'Web release checks failed.', { status: webReport.status })
  }
}

async function main () {
  console.log(`[ship] ${opts.publish ? 'release publish' : 'release check'} for peerit`)
  verifySiteFiles()
  verifyStaticImports()
  verifyManifest()
  await runWebRelease(currentManifestDriveKey())
  verifyGitCleanForServedFiles()
  await runTests()

  finishReport()
  if (report.status === 'blocked') {
    writeReport()
    process.exit(1)
  }

  if (opts.publish) {
    await runPublish()
    await runWebRelease((report.publish && report.publish.driveKey) || currentManifestDriveKey())
  }
  writeReport()
  process.exit(report.status === 'blocked' ? 1 : 0)
}

main().catch((err) => {
  addCheck('ship:error', 'fail', err.message)
  writeReport()
  process.exit(1)
})
