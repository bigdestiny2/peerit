#!/usr/bin/env node
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline/promises'
import { stdin as input, stdout as output } from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { encodeQR, qrToSvg } from '../js/qr.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEPLOY_DIR = join(ROOT, '.deploy')
const HEX64 = /^[0-9a-f]{64}$/i
const PROOF_TYPE = 'peerit-local-bridge-proof'

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error(`usage: node scripts/local-bridge-proof.mjs [options]

Options:
  --session <id>       Stable proof session id (default: generated)
  --url <hyper-url>    Use an already-running local publish URL
  --no-publish         Do not spawn publish.mjs --local (requires --url)
  --skip-headless      Skip bridge-convergence/runtime preflight
  --keep-publish       Leave the local publish process running after validation
  --plan-only          Write an operator-required report and exit before prompting
  --report <file>      JSON report path (default: .deploy/local-bridge-proof-<session>.json)
  --markdown <file>    Markdown report path (default: .deploy/local-bridge-proof-<session>.md)
  --verify <file>      Validate an existing proof report or snapshot array and exit
  -h, --help           Show this help
`)
  process.exit(code)
}

function normalizeSession (raw) {
  const s = String(raw || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 16)
  return s || ('bp' + Date.now().toString(36) + randomBytes(2).toString('hex')).slice(0, 16)
}

function parseArgs (argv) {
  const envSession = process.env.PEERIT_BRIDGE_PROOF_SESSION || ''
  const opts = {
    session: envSession ? normalizeSession(envSession) : '',
    sessionExplicit: !!envSession,
    url: process.env.PEERIT_BRIDGE_PROOF_URL || '',
    noPublish: false,
    skipHeadless: process.env.PEERIT_BRIDGE_PROOF_SKIP_HEADLESS === '1',
    keepPublish: process.env.PEERIT_BRIDGE_PROOF_KEEP_PUBLISH === '1',
    planOnly: process.env.PEERIT_BRIDGE_PROOF_PLAN_ONLY === '1',
    report: '',
    markdown: '',
    verify: ''
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--session') {
      opts.session = normalizeSession(argv[++i])
      opts.sessionExplicit = true
    } else if (arg === '--url') opts.url = argv[++i] || ''
    else if (arg === '--no-publish') opts.noPublish = true
    else if (arg === '--skip-headless') opts.skipHeadless = true
    else if (arg === '--keep-publish') opts.keepPublish = true
    else if (arg === '--plan-only') opts.planOnly = true
    else if (arg === '--report') opts.report = argv[++i] || ''
    else if (arg === '--markdown') opts.markdown = argv[++i] || ''
    else if (arg === '--verify') opts.verify = argv[++i] || ''
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  if (opts.noPublish && !opts.url) usage(2, '--no-publish requires --url')
  if (opts.verify && opts.planOnly) usage(2, '--plan-only cannot be combined with --verify')
  if (!opts.verify && !opts.session) opts.session = normalizeSession('')
  opts.report = resolve(ROOT, opts.report || `.deploy/local-bridge-proof-${opts.session}.json`)
  opts.markdown = resolve(ROOT, opts.markdown || `.deploy/local-bridge-proof-${opts.session}.md`)
  return opts
}

function delay (ms) { return new Promise(resolve => setTimeout(resolve, ms)) }

function ensureDir (file) {
  mkdirSync(dirname(file), { recursive: true })
}

function runNodeCheck (label, args) {
  return new Promise((resolve) => {
    const startedAt = new Date().toISOString()
    const child = spawn(process.execPath, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', d => { stdout += d })
    child.stderr.on('data', d => { stderr += d })
    child.on('close', (code, signal) => {
      resolve({
        label,
        command: [process.execPath, ...args].join(' '),
        startedAt,
        finishedAt: new Date().toISOString(),
        status: code === 0 ? 'pass' : 'fail',
        code,
        signal,
        stdout: tail(stdout),
        stderr: tail(stderr)
      })
    })
  })
}

function tail (text, max = 12000) {
  text = String(text || '')
  return text.length > max ? text.slice(text.length - max) : text
}

async function runHeadlessGates (skip) {
  if (skip) return [{ label: 'headless gates', status: 'skipped', command: '--skip-headless' }]
  const checks = []
  for (const [label, args] of [
    ['bridge convergence', ['test/bridge-convergence.mjs']],
    ['runtime dispatch', ['test/runtime.mjs']]
  ]) {
    console.log(`[bridge-proof] running ${label}...`)
    const check = await runNodeCheck(label, args)
    checks.push(check)
    if (check.status !== 'pass') {
      throw new Error(`${label} failed; rerun ${check.command} for full output`)
    }
  }
  return checks
}

function readJsonFile (file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}

async function waitForLocalPublish (child, reportFile, outputRef, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs
  let lastReport = null
  while (Date.now() < deadline) {
    if (existsSync(reportFile)) {
      try {
        lastReport = readJsonFile(reportFile)
        if (lastReport && lastReport.url && lastReport.status === 'local-ready') {
          return { url: lastReport.url, report: lastReport }
        }
      } catch {}
    }
    const match = String(outputRef.text || '').match(/hyper:\/\/[0-9a-f]{64}\//i)
    if (match) return { url: match[0], report: lastReport }
    if (child.exitCode != null) {
      throw new Error(`publish.mjs --local exited early with code ${child.exitCode}`)
    }
    await delay(250)
  }
  throw new Error(`local publish did not produce a hyper:// URL within ${timeoutMs}ms`)
}

async function startLocalPublish (session) {
  mkdirSync(DEPLOY_DIR, { recursive: true })
  const publishReport = join(DEPLOY_DIR, `local-publish-${session}.json`)
  const outputRef = { text: '' }
  console.log('[bridge-proof] starting publish.mjs --local...')
  const child = spawn(process.execPath, ['publish.mjs', '--local'], {
    cwd: ROOT,
    env: { ...process.env, DEPLOY_REPORT: publishReport },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  child.stdout.on('data', d => {
    const text = String(d)
    outputRef.text += text
    output.write(text)
  })
  child.stderr.on('data', d => {
    const text = String(d)
    outputRef.text += text
    output.write(text)
  })
  const ready = await waitForLocalPublish(child, publishReport, outputRef)
  return { child, url: ready.url, publishReport: ready.report, publishReportPath: publishReport }
}

async function stopLocalPublish (child) {
  if (!child || child.killed || child.exitCode != null) return
  child.kill('SIGTERM')
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    delay(1500).then(() => child.kill('SIGKILL'))
  ])
}

function roleUrls (baseUrl, session) {
  const root = String(baseUrl || '').replace(/#.*$/, '').replace(/\/?$/, '/')
  const path = `#/bridge-proof/${encodeURIComponent(session)}`
  return {
    a: `${root}${path}?role=a`,
    b: `${root}${path}?role=b`
  }
}

function qrSvg (text) {
  try {
    return qrToSvg(encodeQR(text), { border: 4 })
  } catch {
    return ''
  }
}

function writeGuideHtml ({ file, session, url, urls }) {
  const html = `<!doctype html>
<meta charset="utf-8">
<title>peerit local bridge proof ${escapeHtml(session)}</title>
<style>
body{font:15px system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.45;margin:32px;max-width:960px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:24px}
.qr{border:1px solid #ddd;border-radius:8px;padding:16px}
.qr svg{width:100%;height:auto;max-width:260px}
a{overflow-wrap:anywhere}
</style>
<h1>peerit local bridge proof</h1>
<p>Session <code>${escapeHtml(session)}</code> from local publish <code>${escapeHtml(url)}</code>.</p>
<div class="grid">
  <section class="qr"><h2>Device A</h2><p><a href="${escapeAttr(urls.a)}">${escapeHtml(urls.a)}</a></p>${qrSvg(urls.a)}</section>
  <section class="qr"><h2>Device B</h2><p><a href="${escapeAttr(urls.b)}">${escapeHtml(urls.b)}</a></p>${qrSvg(urls.b)}</section>
</div>
<ol>
  <li>Open Device A, click "Write Device A proof record".</li>
  <li>Open Device B, click "Check A and write Device B proof record", then copy its proof JSON.</li>
  <li>Return to Device A, refresh until Device B is visible, then copy its proof JSON.</li>
</ol>
`
  ensureDir(file)
  writeFileSync(file, html)
}

function escapeHtml (value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
function escapeAttr (value) { return escapeHtml(value).replace(/'/g, '&#39;') }

function snapshotRole (snapshot) {
  return String((snapshot && snapshot.role) || '').toLowerCase()
}

function latestByRole (snapshots, role) {
  return snapshots.filter(s => snapshotRole(s) === role).sort((a, b) => String(a.generatedAt || '').localeCompare(String(b.generatedAt || ''))).at(-1) || null
}

function addCheck (checks, id, pass, detail) {
  checks.push({ id, status: pass ? 'pass' : 'fail', detail })
}

function proofRecords (snapshot) {
  return snapshot && snapshot.proof && snapshot.proof.records ? snapshot.proof.records : {}
}

function observations (snapshot) {
  return snapshot && snapshot.proof && snapshot.proof.observations ? snapshot.proof.observations : {}
}

export function validateProofSnapshots (snapshots, opts = {}) {
  snapshots = Array.isArray(snapshots) ? snapshots : []
  const session = opts.session ? normalizeSession(opts.session) : ''
  const checks = []
  const a = latestByRole(snapshots, 'a')
  const b = latestByRole(snapshots, 'b')

  addCheck(checks, 'roles-present', !!(a && b), 'one Device A and one Device B snapshot are present')
  for (const [role, snap] of [['a', a], ['b', b]]) {
    addCheck(checks, `${role}-type`, !!(snap && snap.type === PROOF_TYPE && snap.version === 1), `Device ${role.toUpperCase()} snapshot has the expected proof envelope`)
    if (session) addCheck(checks, `${role}-session`, !!(snap && snap.session === session), `Device ${role.toUpperCase()} snapshot session matches ${session}`)
    addCheck(checks, `${role}-bridge-mode`, !!(snap && snap.status && snap.status.mode === 'gossip-bridge'), `Device ${role.toUpperCase()} reports gossip-bridge mode`)
    addCheck(checks, `${role}-peers`, Number((snap && snap.status && snap.status.peers) || 0) >= 2, `Device ${role.toUpperCase()} reports at least two outboxes`)
    addCheck(checks, `${role}-writer`, !!(snap && HEX64.test(snap.writer || '')), `Device ${role.toUpperCase()} has a 64-hex writer key`)
  }

  const aWriter = a && a.writer
  const bWriter = b && b.writer
  addCheck(checks, 'distinct-writers', !!(HEX64.test(aWriter || '') && HEX64.test(bWriter || '') && aWriter !== bWriter), 'Device A and B writer keys are distinct')

  const aRecords = proofRecords(a)
  const bRecords = proofRecords(b)
  const aA = aRecords.aPost || bRecords.aPost
  const bB = aRecords.bPost || bRecords.bPost
  const communityA = a && a.proof && a.proof.communitySlug
  const communityB = b && b.proof && b.proof.communitySlug
  addCheck(checks, 'same-community', !!(communityA && communityA === communityB), 'both devices used the same proof community')
  addCheck(checks, 'a-owns-a-post', !!(aA && aA.author === aWriter), 'Device A owns the A proof post')
  addCheck(checks, 'b-owns-b-post', !!(bB && bB.author === bWriter), 'Device B owns the B proof post')
  addCheck(checks, 'b-saw-a', !!(bRecords.aPost && bRecords.aPost.author === aWriter && observations(b).sawA), 'Device B saw Device A content')
  addCheck(checks, 'a-saw-b', !!(aRecords.bPost && aRecords.bPost.author === bWriter && observations(a).sawB), 'Device A saw Device B content')
  addCheck(checks, 'cross-converged', !!(aRecords.aPost && aRecords.bPost && bRecords.aPost && bRecords.bPost), 'both proof snapshots contain both A and B records')

  const status = checks.every(c => c.status === 'pass') ? 'pass' : 'fail'
  return { status, checks }
}

function loadSnapshotsForVerify (file) {
  const parsed = readJsonFile(resolve(ROOT, file))
  if (Array.isArray(parsed)) return parsed
  if (Array.isArray(parsed.snapshots)) return parsed.snapshots
  if (parsed.type === PROOF_TYPE) return [parsed]
  throw new Error('verify file must be a snapshot, snapshot array, or proof report with snapshots[]')
}

async function promptSnapshot (rl, label) {
  console.log(`[bridge-proof] paste ${label} proof JSON. Multi-line JSON is OK; parsing completes at the closing brace.`)
  let buffer = ''
  while (true) {
    const line = await rl.question(`${label}> `)
    buffer += (buffer ? '\n' : '') + line
    try {
      const parsed = JSON.parse(buffer)
      if (!parsed || parsed.type !== PROOF_TYPE) throw new Error(`not a ${PROOF_TYPE} snapshot`)
      return parsed
    } catch (err) {
      if (buffer.length > 250000) throw new Error(`${label} proof JSON is too large or invalid: ${err.message}`)
    }
  }
}

function summarizeFailures (validation) {
  return validation.checks.filter(c => c.status !== 'pass').map(c => `  - ${c.id}: ${c.detail}`).join('\n')
}

export function operatorRequiredValidation () {
  return {
    status: 'operator-required',
    checks: [
      {
        id: 'two-real-pearbrowser-instances',
        status: 'pending',
        detail: 'open Device A and Device B URLs in two separate PearBrowser instances or profiles'
      },
      {
        id: 'device-a-snapshot',
        status: 'pending',
        detail: 'Device A must write its proof record and later copy a final snapshot that sees Device B'
      },
      {
        id: 'device-b-snapshot',
        status: 'pending',
        detail: 'Device B must see Device A, write its proof record, and copy its snapshot'
      },
      {
        id: 'validator-pass',
        status: 'pending',
        detail: 'rerun the report through --verify or complete the interactive prompt until every proof check passes'
      }
    ]
  }
}

function reportMarkdown (report) {
  const rows = report.validation.checks.map(c => `| ${c.id} | ${c.status} | ${String(c.detail).replace(/\|/g, '\\|')} |`).join('\n')
  return `# peerit local bridge proof

- Session: \`${report.session}\`
- Status: \`${report.status}\`
- Generated: \`${report.generatedAt}\`
- Local URL: \`${report.url}\`
- Device A writer: \`${(report.snapshotsByRole.a && report.snapshotsByRole.a.writer) || ''}\`
- Device B writer: \`${(report.snapshotsByRole.b && report.snapshotsByRole.b.writer) || ''}\`

| Check | Status | Detail |
| --- | --- | --- |
${rows}
`
}

function writeReport (report, jsonFile, markdownFile) {
  ensureDir(jsonFile)
  writeFileSync(jsonFile, JSON.stringify(report, null, 2) + '\n')
  ensureDir(markdownFile)
  writeFileSync(markdownFile, reportMarkdown(report))
}

function makeReport ({ opts, url, urls, guideFile, headlessChecks, publishReport, publishReportPath, snapshots, validation }) {
  const snapshotsByRole = { a: latestByRole(snapshots, 'a'), b: latestByRole(snapshots, 'b') }
  return {
    type: 'peerit-local-bridge-proof-report',
    version: 1,
    session: opts.session,
    generatedAt: new Date().toISOString(),
    status: validation.status,
    url,
    urls,
    guideFile,
    headlessChecks,
    publishReportPath,
    publishReport,
    snapshots,
    snapshotsByRole,
    validation
  }
}

async function interactiveSnapshots (session) {
  const rl = createInterface({ input, output })
  try {
    const snapshots = []
    snapshots.push(await promptSnapshot(rl, 'Device B'))
    snapshots.push(await promptSnapshot(rl, 'Device A final'))
    let validation = validateProofSnapshots(snapshots, { session })
    for (let attempt = 0; validation.status !== 'pass' && attempt < 2; attempt++) {
      console.log('[bridge-proof] validation is not green yet:')
      console.log(summarizeFailures(validation))
      const needsA = validation.checks.some(c => c.status !== 'pass' && ['a-saw-b', 'cross-converged', 'a-peers', 'a-bridge-mode'].includes(c.id))
      const needsB = validation.checks.some(c => c.status !== 'pass' && ['b-saw-a', 'cross-converged', 'b-peers', 'b-bridge-mode'].includes(c.id))
      if (needsB) snapshots.push(await promptSnapshot(rl, 'Device B updated'))
      if (needsA) snapshots.push(await promptSnapshot(rl, 'Device A updated'))
      if (!needsA && !needsB) break
      validation = validateProofSnapshots(snapshots, { session })
    }
    return { snapshots, validation }
  } finally {
    rl.close()
  }
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  if (opts.verify) {
    const snapshots = loadSnapshotsForVerify(opts.verify)
    const validation = validateProofSnapshots(snapshots, { session: opts.session })
    console.log(JSON.stringify(validation, null, 2))
    process.exit(validation.status === 'pass' ? 0 : 1)
  }

  let publish = null
  let stopping = false
  const stopOnSignal = async (signal) => {
    if (stopping) return
    stopping = true
    await stopLocalPublish(publish && publish.child)
    process.exit(signal === 'SIGINT' ? 130 : 143)
  }
  process.once('SIGINT', stopOnSignal)
  process.once('SIGTERM', stopOnSignal)
  const headlessChecks = await runHeadlessGates(opts.skipHeadless)
  try {
    if (opts.noPublish) {
      publish = { url: opts.url, publishReport: null, publishReportPath: null, child: null }
    } else {
      publish = await startLocalPublish(opts.session)
    }
    const url = opts.url || publish.url
    const urls = roleUrls(url, opts.session)
    const guideFile = join(DEPLOY_DIR, `local-bridge-proof-${opts.session}.html`)
    writeGuideHtml({ file: guideFile, session: opts.session, url, urls })
    console.log('\n[bridge-proof] local PearBrowser proof URLs:')
    console.log(`  Device A: ${urls.a}`)
    console.log(`  Device B: ${urls.b}`)
    console.log(`[bridge-proof] QR guide: ${guideFile}`)
    console.log('\n[bridge-proof] steps:')
    console.log('  1. Device A: open its URL and click "Write Device A proof record".')
    console.log('  2. Device B: open its URL, click "Check A and write Device B proof record", then "Copy proof JSON".')
    console.log('  3. Device A: click "Refresh" until Device B is visible, then "Copy proof JSON".')
    console.log('')

    if (opts.planOnly) {
      const report = makeReport({
        opts,
        url,
        urls,
        guideFile,
        headlessChecks,
        publishReport: publish.publishReport,
        publishReportPath: publish.publishReportPath,
        snapshots: [],
        validation: operatorRequiredValidation()
      })
      writeReport(report, opts.report, opts.markdown)
      console.log('[bridge-proof] operator-required')
      console.log(`[bridge-proof] wrote report: ${opts.report}`)
      console.log(`[bridge-proof] wrote markdown: ${opts.markdown}`)
      if (opts.keepPublish && publish.child) {
        console.log('[bridge-proof] keeping local publish alive; Ctrl-C to stop')
        await new Promise(() => {})
      }
      return
    }

    const { snapshots, validation } = await interactiveSnapshots(opts.session)
    const report = makeReport({
      opts,
      url,
      urls,
      guideFile,
      headlessChecks,
      publishReport: publish.publishReport,
      publishReportPath: publish.publishReportPath,
      snapshots,
      validation
    })
    writeReport(report, opts.report, opts.markdown)
    if (validation.status !== 'pass') {
      console.error('[bridge-proof] FAIL')
      console.error(summarizeFailures(validation))
      console.error(`[bridge-proof] wrote report: ${opts.report}`)
      process.exitCode = 1
      return
    }
    console.log('[bridge-proof] PASS')
    console.log(`[bridge-proof] wrote report: ${opts.report}`)
    console.log(`[bridge-proof] wrote markdown: ${opts.markdown}`)
    if (opts.keepPublish && publish.child) {
      console.log('[bridge-proof] keeping local publish alive; Ctrl-C to stop')
      await new Promise(() => {})
    }
  } finally {
    process.off('SIGINT', stopOnSignal)
    process.off('SIGTERM', stopOnSignal)
    if (!opts.keepPublish && publish && publish.child) await stopLocalPublish(publish.child)
  }
}

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isDirectRun) {
  main().catch((err) => {
    console.error('[bridge-proof] failed:', err.stack || err.message)
    process.exit(1)
  })
}
