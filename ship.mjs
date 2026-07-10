#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { createInterface } from 'node:readline/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { SITE_FILES } from './publish.mjs'

const __dir = dirname(fileURLToPath(import.meta.url))
const DEFAULT_PENDING_SHIP = join(__dir, '.deploy', 'pending-ship.json')
const DEFAULT_SIGNING_REQUEST = join(__dir, 'deploy', 'web-signing-request.json')
const WEB_MANIFEST = join(__dir, 'web', 'asset-manifest.json')
const WEB_SIGNATURE = join(__dir, 'web', 'asset-manifest.sig')

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error('usage: node ship.mjs [--publish] [--resume-signature] [--sign-command <command>] [--anchor-timeout-ms 240000] [--report <file>]')
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    publish: false,
    allowDirty: false,
    skipTests: false,
    skipWeb: process.env.SKIP_WEB_RELEASE === '1',
    resumeSignature: false,
    signCommand: process.env.PEERIT_RELEASE_SIGN_COMMAND || '',
    anchorTimeoutMs: process.env.ANCHOR_TIMEOUT_MS || '240000',
    report: join(__dir, '.deploy', 'last-ship.json'),
    publishReport: join(__dir, '.deploy', 'last-publish.json'),
    webReport: join(__dir, '.deploy', 'last-web-release.json'),
    signingRequest: process.env.WEB_SIGNING_REQUEST || DEFAULT_SIGNING_REQUEST,
    pendingShip: process.env.PENDING_SHIP_REPORT || DEFAULT_PENDING_SHIP
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--publish' || arg === '--live') opts.publish = true
    else if (arg === '--check') opts.publish = false
    else if (arg === '--allow-dirty') opts.allowDirty = true
    else if (arg === '--no-test') opts.skipTests = true
    else if (arg === '--no-web') opts.skipWeb = true
    else if (arg === '--resume-signature') opts.resumeSignature = true
    else if (arg === '--sign-command') {
      const value = argv[++i]
      if (!value) usage(2, '--sign-command requires a command')
      opts.signCommand = value
    } else if (arg === '--anchor-timeout-ms') opts.anchorTimeoutMs = argv[++i] || ''
    else if (arg === '--report') {
      const value = argv[++i]
      if (!value) usage(2, '--report requires a file path')
      opts.report = resolve(__dir, value)
    } else if (arg === '--publish-report') {
      const value = argv[++i]
      if (!value) usage(2, '--publish-report requires a file path')
      opts.publishReport = resolve(__dir, value)
    } else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }

  const timeout = Number(opts.anchorTimeoutMs)
  if (!Number.isFinite(timeout) || timeout <= 0) usage(2, '--anchor-timeout-ms must be a positive number')
  return opts
}

export function validatePublicOptions (candidate) {
  if (!candidate.publish) return
  const bypasses = []
  if (candidate.skipWeb) bypasses.push('--no-web/SKIP_WEB_RELEASE')
  if (candidate.allowDirty) bypasses.push('--allow-dirty')
  if (candidate.skipTests) bypasses.push('--no-test')
  if (bypasses.length) {
    throw new Error(`live publish refuses release-gate bypasses: ${bypasses.join(', ')}`)
  }
}

export function dirtyReleaseStatus (candidate, dirty) {
  if (!dirty || dirty.length === 0) return 'pass'
  return candidate.allowDirty && !candidate.publish ? 'warn' : 'fail'
}

const RELEASE_EXPLICIT_INPUTS = [
  'build-web.mjs',
  'publish.mjs',
  'ship.mjs',
  'manifest.json',
  'package.json',
  'package-lock.json',
  'relay-roster.json',
  'node-shims.mjs',
  'web',
  'config/seed-snapshot.json',
  'config/shard-roster.public.json',
  'deploy/web-release.json',
  'deploy/web-signing-request.json',
  'deploy/CAPACITY.md',
  'deploy/peerit-relay/Caddyfile',
  'deploy/peerit-relay/README.md',
  'deploy/peerit-relay/docker-compose.yml',
  'docs/PROTOCOL-V3-CONTENT-IDENTITY.md',
  'docs/WEB-DEPLOYMENT.md',
  'scripts/audit-live-legacy-actions.mjs',
  'scripts/audit-live-legacy-pow.mjs',
  'scripts/build-dht-bundle.mjs',
  'scripts/build-reader-bundle.mjs',
  'scripts/csp.mjs',
  'scripts/service-worker-source.mjs',
  'scripts/sign-release.mjs',
  'scripts/local-writable-two-relay.mjs',
  'scripts/soak-atomic-two-relay.mjs',
  'scripts/verify-production-readonly.mjs',
  'scripts/verify-writable-candidate.mjs',
  'scripts/web-release.mjs',
  // esbuild entry points and aliases are strings rather than JS imports.
  'js/dht-transport.js',
  'js/reader-src.mjs',
  'js/sodium-browser-shim.mjs'
]

function localImportSpecifiers (source) {
  const specs = new Set()
  const patterns = [
    /\b(?:import|export)\s+[^;]*?\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  ]
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) specs.add(match[1])
  }
  return [...specs].filter((spec) => spec && (spec.startsWith('./') || spec.startsWith('../')))
}

function resolveLocalImport (root, fromFile, spec) {
  const clean = spec.split(/[?#]/)[0]
  const base = resolve(root, dirname(fromFile), clean)
  const candidates = [base, `${base}.js`, `${base}.mjs`, join(base, 'index.js'), join(base, 'index.mjs')]
  for (const candidate of candidates) {
    if (!existsSync(candidate) || !statSync(candidate).isFile()) continue
    const rel = relative(root, candidate).replace(/\\/g, '/')
    if (!rel.startsWith('../') && rel !== '..') return rel
  }
  return ''
}

function packageTestFiles (root) {
  const pkg = readJson(join(root, 'package.json'))
  const command = String((pkg && pkg.scripts && pkg.scripts.test) || '')
  const files = []
  for (const match of command.matchAll(/(?:^|&&)\s*node(?:\s+--test)?\s+([^\s&]+\.(?:mjs|js))/g)) files.push(match[1])
  return files
}

export function releaseInputClosure ({ root = __dir, siteFiles = SITE_FILES } = {}) {
  const pending = [...new Set([...siteFiles, ...RELEASE_EXPLICIT_INPUTS, ...packageTestFiles(root)])]
  const closure = new Set(pending)
  while (pending.length) {
    const file = pending.pop()
    const abs = resolve(root, file)
    if (!existsSync(abs) || !statSync(abs).isFile() || !/\.(?:mjs|js)$/.test(file)) continue
    const source = readFileSync(abs, 'utf8')
    for (const spec of localImportSpecifiers(source)) {
      const imported = resolveLocalImport(root, file, spec)
      if (!imported || closure.has(imported)) continue
      closure.add(imported)
      pending.push(imported)
    }
  }
  return [...closure].sort()
}

export function filterReleaseDirtyLines (lines, { allowPublishedManifest = false, allowPreparedArtifacts = false } = {}) {
  return lines.filter((line) => {
    if (allowPublishedManifest && /(?:^|\s)manifest\.json$/.test(line)) return false
    if (allowPreparedArtifacts && (/(?:^|\s)deploy\/web-signing-request\.json$/.test(line) || /(?:^|\s)web(?:\/|$)/.test(line))) return false
    return true
  })
}

export function inspectReleaseGitStatus ({
  root = __dir,
  files = releaseInputClosure({ root }),
  allowPublishedManifest = false,
  allowPreparedArtifacts = false,
  spawnSyncImpl = spawnSync
} = {}) {
  const res = spawnSyncImpl('git', ['status', '--porcelain', '--untracked-files=all', '--', ...files], { cwd: root, encoding: 'utf8' })
  if (!res || res.status !== 0) throw new Error(`git status failed for release inputs${res && res.stderr ? `: ${String(res.stderr).trim()}` : ''}`)
  const allDirty = String(res.stdout || '').split('\n').map((line) => line.trim()).filter(Boolean)
  return {
    allDirty,
    dirty: filterReleaseDirtyLines(allDirty, { allowPublishedManifest, allowPreparedArtifacts })
  }
}

function sha256Bytes (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function validateStrictPublishReport (publishReport, expectedDriveKey = '') {
  const value = publishReport && typeof publishReport === 'object' ? publishReport : null
  if (!value) throw new Error('publish report is missing or invalid')
  const driveKey = String(value.driveKey || '').toLowerCase()
  const minPeers = Number(value.minAnchorPeers)
  const metadata = value.durability && value.durability.metadata
  const blobs = value.durability && value.durability.blobs
  if (value.appId !== 'peerit' || value.local !== false || value.strictAnchor !== true || value.status !== 'ready') {
    throw new Error('publish report is not a ready strict public peerit publish')
  }
  if (!/^[0-9a-f]{64}$/.test(driveKey)) throw new Error('publish report has an invalid drive key')
  if (expectedDriveKey && driveKey !== String(expectedDriveKey).toLowerCase()) throw new Error('publish report drive key does not match the prepared release')
  if (value.url !== `hyper://${driveKey}/`) throw new Error('publish report URL does not match its drive key')
  if (!/^[0-9a-f]{64}$/i.test(String(value.contentKey || ''))) throw new Error('publish report has an invalid content key')
  if (!Number.isInteger(minPeers) || minPeers < 1) throw new Error('publish report has an invalid minimum anchor peer count')
  if (!metadata || metadata.durable !== true || Number(metadata.activePeers) < minPeers) {
    throw new Error('publish report lacks durable metadata evidence')
  }
  if (!blobs || blobs.durable !== true || Number(blobs.activePeers) < minPeers || !(Number(blobs.blobLocalLen) > 0) || Number(blobs.blobRemoteMax) < Number(blobs.blobLocalLen)) {
    throw new Error('publish report lacks durable full-blob evidence')
  }
  if (value.manifestUpdated !== true || !(Number(value.siteFiles) > 0)) throw new Error('publish report lacks manifest/site publication evidence')
  return value
}

export function validatePendingPublishEvidence (pending, reportBytes, publishReport = null) {
  if (!pending || pending.publish !== true || !/^[0-9a-f]{64}$/i.test(String(pending.publishReportSha256 || ''))) {
    throw new Error('pending handoff does not bind a strict publish report')
  }
  const bytes = Buffer.isBuffer(reportBytes) ? reportBytes : Buffer.from(String(reportBytes || ''))
  if (sha256Bytes(bytes) !== pending.publishReportSha256) throw new Error('publish report bytes changed after the signing handoff')
  let parsed = publishReport
  if (!parsed) {
    try { parsed = JSON.parse(bytes.toString('utf8')) } catch { throw new Error('publish report is invalid JSON') }
  }
  return validateStrictPublishReport(parsed, pending.driveKey)
}

const opts = parseArgs(process.argv.slice(2))
try {
  validatePublicOptions(opts)
} catch (err) {
  usage(2, err.message)
}
const report = {
  appId: 'peerit',
  mode: opts.publish ? 'publish' : 'check',
  generatedAt: new Date().toISOString(),
  checks: [],
  publish: null,
  webRelease: null,
  status: 'started',
  summary: '',
  awaitingSignature: false
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
  report.status = counts.fail > 0 || (opts.publish && counts.warn > 0)
    ? 'blocked'
    : report.awaitingSignature
      ? 'awaiting-signature'
      : (counts.warn > 0 ? 'review' : 'ready')
  report.summary = report.status === 'blocked'
    ? opts.publish && counts.fail === 0 && counts.warn > 0
      ? `${counts.warn} ship warning${counts.warn === 1 ? ' is' : 's are'} forbidden for live publish.`
      : `${counts.fail} failing ship check${counts.fail === 1 ? '' : 's'} must be fixed before publish.`
    : report.status === 'awaiting-signature'
      ? 'The final web artifact is frozen and waiting for its offline signature.'
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

function sha256File (file) {
  return sha256Bytes(readFileSync(file))
}

function currentGitHead () {
  const res = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: __dir, encoding: 'utf8' })
  return res.status === 0 ? res.stdout.trim() : ''
}

function writePendingShip (driveKey) {
  const request = readJson(opts.signingRequest)
  if (!request) throw new Error('web signing request is missing after prepare')
  if (!existsSync(WEB_MANIFEST)) throw new Error('web/asset-manifest.json is missing after prepare')
  if (request.driveKey !== driveKey || request.manifestSha256 !== sha256File(WEB_MANIFEST)) {
    throw new Error('prepared web artifact does not match its signing request')
  }
  let publishReportSha256 = ''
  if (opts.publish) {
    if (!existsSync(opts.publishReport)) throw new Error('strict publish report is missing before the signing handoff')
    const publishReportBytes = readFileSync(opts.publishReport)
    validateStrictPublishReport(JSON.parse(publishReportBytes.toString('utf8')), driveKey)
    publishReportSha256 = sha256Bytes(publishReportBytes)
  }
  const pending = {
    schema: 'peerit-pending-ship-v2',
    publish: opts.publish,
    driveKey,
    manifestSha256: request.manifestSha256,
    signingMessageSha256: request.signingMessageSha256,
    signingRequestSha256: sha256File(opts.signingRequest),
    pinnedReleaseKey: request.pinnedReleaseKey,
    catalogManifestSha256: sha256File(join(__dir, 'manifest.json')),
    publishReportSha256,
    gitHead: currentGitHead()
  }
  mkdirSync(dirname(opts.pendingShip), { recursive: true })
  writeFileSync(opts.pendingShip, JSON.stringify(pending, null, 2) + '\n')
  report.pendingShip = { ...pending, file: opts.pendingShip }
  return pending
}

function loadPendingShip () {
  const pending = readJson(opts.pendingShip)
  if (!pending || pending.schema !== 'peerit-pending-ship-v2') {
    throw new Error(`no resumable signing handoff at ${opts.pendingShip}; run ship without --resume-signature first`)
  }
  if (pending.publish !== opts.publish) {
    throw new Error(`pending handoff belongs to ${pending.publish ? 'ship:live' : 'ship:check'}, not this command`)
  }
  if (!/^[0-9a-f]{64}$/i.test(String(pending.driveKey || ''))) throw new Error('pending handoff has an invalid drive key')
  if (currentManifestDriveKey().toLowerCase() !== pending.driveKey.toLowerCase()) {
    throw new Error('manifest.json drive key changed after the artifact was prepared')
  }
  if (pending.catalogManifestSha256 !== sha256File(join(__dir, 'manifest.json'))) {
    throw new Error('manifest.json changed after the artifact was prepared')
  }
  if (!existsSync(WEB_MANIFEST) || sha256File(WEB_MANIFEST) !== pending.manifestSha256) {
    throw new Error('prepared asset-manifest.json changed after the signing handoff')
  }
  const request = readJson(opts.signingRequest)
  if (!request || request.manifestSha256 !== pending.manifestSha256 || request.signingMessageSha256 !== pending.signingMessageSha256) {
    throw new Error('offline-signing request changed after the signing handoff')
  }
  if (pending.signingRequestSha256 !== sha256File(opts.signingRequest)) {
    throw new Error('offline-signing request bytes changed after the signing handoff')
  }
  const head = currentGitHead()
  if (pending.gitHead && head !== pending.gitHead) throw new Error('git HEAD changed after the artifact was prepared')
  if (pending.publish) {
    if (!existsSync(opts.publishReport)) throw new Error('strict publish report is missing during resume')
    const publishReportBytes = readFileSync(opts.publishReport)
    const publishReport = validatePendingPublishEvidence(pending, publishReportBytes)
    report.publish = publishReport
  }
  report.pendingShip = { ...pending, file: opts.pendingShip }
  addCheck('web-release:resume', 'pass', 'Resuming the frozen artifact without rebuilding or republishing.', {
    driveKey: pending.driveKey,
    manifestSha256: pending.manifestSha256
  })
  return pending
}

function clearPendingShip () {
  if (existsSync(opts.pendingShip)) unlinkSync(opts.pendingShip)
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

function runShell (command) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, {
      cwd: __dir,
      stdio: 'inherit',
      env: process.env,
      shell: true
    })
    child.on('error', reject)
    child.on('exit', (code, signal) => {
      if (code === 0) resolve()
      else reject(new Error(`external signing command exited with ${signal || code}`))
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
  return String((manifest && manifest.driveKey) || '')
}

function verifyGitCleanForServedFiles ({ allowPublishedManifest = false, allowPreparedArtifacts = false } = {}) {
  const tracked = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: __dir, encoding: 'utf8' })
  if (tracked.status !== 0) {
    addCheck('git:repo', opts.publish ? 'fail' : 'warn', 'Git status is unavailable; served-file cleanliness was not checked.')
    return
  }

  let inspected
  try {
    inspected = inspectReleaseGitStatus({ root: __dir, allowPublishedManifest, allowPreparedArtifacts })
  } catch (err) {
    addCheck('git:status', opts.publish ? 'fail' : 'warn', err.message)
    return
  }
  const { allDirty, dirty } = inspected
  if (!dirty.length) {
    addCheck('git:release-clean', 'pass', (allowPublishedManifest || allowPreparedArtifacts) && allDirty.length
      ? 'Release files are clean apart from exact generated files bound by the pending signing handoff.'
      : 'Release files are clean in git.')
    return
  }

  addCheck(
    'git:release-dirty',
    dirtyReleaseStatus(opts, dirty),
    `${dirty.length} release file${dirty.length === 1 ? ' is' : 's are'} dirty; live publish always requires a clean release tree.`,
    { dirty }
  )
}

async function runTests () {
  if (opts.skipTests) {
    addCheck('tests:skipped', opts.publish ? 'fail' : 'warn', opts.publish ? 'Tests cannot be skipped for a live publish.' : 'Tests were skipped by --no-test.')
    return
  }

  try {
    // The release gate must execute the same complete suite advertised to
    // contributors. The old three-file subset let regressions in identity,
    // v2, recovery, relay-pool, and storage tests ship unnoticed.
    await run('npm', ['test'])
    addCheck('tests:node', 'pass', 'The complete npm test suite passed.')
  } catch (err) {
    addCheck('tests:node', 'fail', err.message)
  }
}

export async function runLiveReleasePreflights ({ publish, readonly, relay, runStep }) {
  if (!publish) return []
  if (typeof runStep !== 'function') throw new Error('live release preflight runner is required')
  let steps
  if (readonly === false) {
    if (!relay) throw new Error('writable release has no production bootstrap relay to audit')
    steps = [
      {
        id: 'writable-candidate',
        cmd: 'node',
        args: ['scripts/verify-writable-candidate.mjs'],
        env: {}
      },
      {
        id: 'live-legacy-actions',
        cmd: 'npm',
        args: ['run', 'audit:live-legacy-actions'],
        env: { PEERIT_RELAY: relay }
      }
    ]
  } else {
    if (!relay) throw new Error('read-only release has no production bootstrap relay to probe')
    steps = [
      {
        id: 'production-readonly',
        cmd: 'node',
        args: ['scripts/verify-production-readonly.mjs'],
        env: { PEERIT_RELAY: relay }
      },
      {
        id: 'live-legacy-pow',
        cmd: 'npm',
        args: ['run', 'audit:live-legacy-pow'],
        env: { PEERIT_RELAY: relay }
      },
      {
        id: 'live-legacy-actions',
        cmd: 'npm',
        args: ['run', 'audit:live-legacy-actions'],
        env: { PEERIT_RELAY: relay }
      }
    ]
  }
  for (const step of steps) {
    try {
      await runStep(step)
    } catch (cause) {
      const err = new Error(`${step.id} preflight failed: ${cause && cause.message ? cause.message : cause}`)
      err.preflightId = step.id
      throw err
    }
  }
  return steps.map((step) => step.id)
}

// Backward-compatible export for release workflow consumers. Unlike the old
// implementation, readonly=false is NOT a skip: it selects the mandatory
// writable-candidate proof.
export const runReadonlyLivePreflights = runLiveReleasePreflights

async function runProductionLivePreflights () {
  const release = readJson(join(__dir, 'deploy', 'web-release.json'))
  if (!release) {
    addCheck('production-live:config', 'fail', 'deploy/web-release.json is missing or invalid.')
    return
  }
  const relay = Array.isArray(release.bootstrapRelays) ? String(release.bootstrapRelays[0] || '') : ''
  if (release.readonly !== false && !relay) {
    addCheck('production-readonly:relay', 'fail', 'Read-only release has no production bootstrap relay to probe.')
    return
  }
  try {
    await runLiveReleasePreflights({
      publish: opts.publish,
      readonly: release.readonly,
      relay,
      runStep: async (step) => {
        await run(step.cmd, step.args, { env: { ...process.env, ...step.env } })
        if (step.id === 'production-readonly') {
          addCheck('production-readonly:enforced', 'pass', `Production edge blocks create/append while reads remain healthy at ${relay}.`)
        } else if (step.id === 'live-legacy-pow') {
          addCheck('live-legacy-pow:clean', 'pass', `Live legacy-PoW audit passed against ${relay}.`)
        } else if (step.id === 'live-legacy-actions') {
          addCheck('live-legacy-actions:clean', 'pass', `Live legacy-action inventory matched its exact frozen signatures at ${relay}.`)
        } else {
          addCheck('writable-candidate:ready', 'pass', 'Every signed relay passed the durable atomic-commit proof and blocks legacy writer routes.')
        }
      }
    })
  } catch (err) {
    const failureChecks = {
      'live-legacy-pow': 'live-legacy-pow:clean',
      'live-legacy-actions': 'live-legacy-actions:clean',
      'writable-candidate': 'writable-candidate:ready'
    }
    const id = failureChecks[err.preflightId] || 'production-readonly:enforced'
    addCheck(id, 'fail', `Live release preflight failed: ${err.message}`, relay ? { relay } : undefined)
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
    addCheck('publish:keep-ignored', 'info', 'KEEP is ignored by ship so the signing handoff can complete with the published drive key.')
  }

  mkdirSync(dirname(opts.publishReport), { recursive: true })
  await run('node', ['publish.mjs'], { env: publishEnv })

  const publishReport = readJson(opts.publishReport)
  report.publish = publishReport
  if (!publishReport) {
    addCheck('publish:report', 'fail', 'Publish completed, but no deploy report was written; the signed web handoff cannot be bound to a drive key.')
    return
  }
  try {
    validateStrictPublishReport(publishReport)
    const meta = publishReport.durability.metadata
    const blobs = publishReport.durability.blobs
    addCheck('publish:durable', 'pass', `Strict publish anchored ${publishReport.url}.`, {
      driveKey: publishReport.driveKey,
      contentKey: publishReport.contentKey,
      metadata: meta,
      blobs
    })
  } catch (err) {
    addCheck('publish:durable', 'fail', err.message, { publishReport: opts.publishReport })
  }
}

async function runWebRelease (driveKey, phase) {
  if (opts.skipWeb) {
    addCheck('web-release:skipped', 'warn', 'Web release build was skipped by --no-web.')
    return false
  }

  mkdirSync(dirname(opts.webReport), { recursive: true })
  const phaseFlag = phase === 'prepare' ? '--prepare' : '--verify-only'
  try {
    await run('node', [
      'scripts/web-release.mjs', phaseFlag,
      '--strict',
      '--drive-key', driveKey,
      '--report', opts.webReport,
      '--signing-request', opts.signingRequest
    ])
  } catch (err) {
    const webReport = readJson(opts.webReport)
    report.webRelease = webReport
    addCheck(`web-release:${phase}`, 'fail', err.message, webReport ? { status: webReport.status, summary: webReport.summary } : undefined)
    return false
  }

  const webReport = readJson(opts.webReport)
  report.webRelease = webReport
  if (!webReport) {
    addCheck('web-release:report', 'warn', 'Web release completed, but no report was written.')
    return false
  }
  if (phase === 'prepare' && webReport.status === 'awaiting-signature') {
    addCheck('web-release:prepared', 'pass', 'Built the final web artifact exactly once and froze its offline-signing request.', {
      driveKey: webReport.driveKey,
      manifestSha256: webReport.signingRequest && webReport.signingRequest.manifestSha256
    })
    return true
  }
  if (phase === 'verify' && webReport.status === 'ready') {
    addCheck('web-release:ready', 'pass', 'Web bundle, relay-roster.json, pinned key, and deploy docs are in sync.', {
      driveKey: webReport.driveKey,
      relayRoster: webReport.release && webReport.release.relayRoster,
      pinnedRosterKey: webReport.release && webReport.release.pinnedRosterKey,
      pinnedReleaseKey: webReport.release && webReport.release.pinnedReleaseKey,
      manifestSha256: webReport.signingRequest && webReport.signingRequest.manifestSha256
    })
    return true
  } else if (webReport.status === 'review') {
    addCheck('web-release:review', 'warn', webReport.summary, { status: webReport.status })
    return true
  } else {
    addCheck('web-release:blocked', 'fail', webReport.summary || 'Web release checks failed.', { status: webReport.status })
    return false
  }
}

async function awaitSignatureHandoff () {
  if (existsSync(WEB_SIGNATURE)) {
    addCheck('web-release:signature-returned', 'pass', 'asset-manifest.sig is present; continuing directly to verify-only.')
    return true
  }
  if (opts.signCommand) {
    console.log('[ship] invoking the operator-supplied signing command; its contents are not written to the report')
    await runShell(opts.signCommand)
    addCheck('web-release:sign-command', 'pass', 'Operator-supplied signing command completed.')
    return true
  }
  if (process.stdin.isTTY && process.stdout.isTTY) {
    console.log('\n[ship] OFFLINE SIGNING HANDOFF')
    console.log(`[ship] request:  ${opts.signingRequest}`)
    console.log(`[ship] manifest: ${WEB_MANIFEST}`)
    console.log(`[ship] return:   ${WEB_SIGNATURE}`)
    console.log('[ship] scoped keyvault helper: keyvault exec --only peerit/release/signing-seed -- npm run release:sign')
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    try {
      await rl.question('[ship] Return asset-manifest.sig, then press Enter to verify without rebuilding: ')
    } finally {
      rl.close()
    }
    return true
  }

  report.awaitingSignature = true
  const resume = opts.publish
    ? 'npm run ship:live -- --resume-signature'
    : 'npm run ship:check -- --resume-signature'
  addCheck('web-release:signature-pending', 'info', `Offline signature is pending. Return web/asset-manifest.sig, then run: ${resume}`, {
    signingRequest: opts.signingRequest,
    manifest: WEB_MANIFEST,
    signature: WEB_SIGNATURE,
    resume
  })
  return false
}

async function main () {
  console.log(`[ship] ${opts.publish ? 'release publish' : 'release check'} for peerit`)
  verifySiteFiles()
  verifyStaticImports()
  verifyManifest()
  verifyGitCleanForServedFiles({
    allowPublishedManifest: opts.publish && opts.resumeSignature,
    allowPreparedArtifacts: opts.resumeSignature
  })
  await runTests()
  if (opts.publish) await runProductionLivePreflights()

  finishReport()
  if (report.status === 'blocked') {
    writeReport()
    process.exit(1)
  }

  let driveKey = ''
  if (opts.resumeSignature) {
    driveKey = loadPendingShip().driveKey
  } else {
    if (opts.skipWeb) {
      addCheck('web-release:skipped', 'warn', 'Web release was skipped for this non-publishing check.')
      writeReport()
      process.exit(0)
    }
    if (opts.publish) {
      // The public Hyperdrive key is not known until strict publication succeeds.
      // Only then can the final web manifest be built once and handed to the
      // offline signer. No build occurs after this point.
      await runPublish()
      finishReport()
      if (report.status === 'blocked') {
        writeReport()
        process.exit(1)
      }
    }
    driveKey = (report.publish && report.publish.driveKey) || currentManifestDriveKey()
    const prepared = await runWebRelease(driveKey, 'prepare')
    if (!prepared) {
      writeReport()
      process.exit(1)
    }
    writePendingShip(driveKey)
  }

  if (!(await awaitSignatureHandoff())) {
    writeReport()
    process.exit(2)
  }

  // Re-read the handoff after the signer returns. This proves the manifest,
  // signing request, drive key, publish report, and git commit are unchanged.
  // Verification below is explicitly --verify-only and cannot invoke a build.
  loadPendingShip()
  verifyGitCleanForServedFiles({ allowPublishedManifest: opts.publish, allowPreparedArtifacts: true })
  finishReport()
  if (report.status === 'blocked') {
    writeReport()
    process.exit(1)
  }
  await runWebRelease(driveKey, 'verify')
  finishReport()
  if (report.status !== 'blocked') clearPendingShip()
  writeReport()
  process.exit(report.status === 'blocked' ? 1 : 0)
}

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isDirectRun) {
  main().catch((err) => {
    addCheck('ship:error', 'fail', err.message)
    writeReport()
    process.exit(1)
  })
}
