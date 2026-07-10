#!/usr/bin/env node
// recover-outboxlog-seed-state.mjs — controlled offline repair for a persisted
// HiveRelay OutboxLog seed. It never contacts a relay: stop the service, verify
// the source snapshot separately, rehearse against a copy, then run --apply on
// the stopped service's state file. The preconditions make an accidental replay
// into the wrong outbox or over a newer head fail closed.
import { createHash } from 'node:crypto'
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

function usage (message = '') {
  if (message) console.error('error:', message)
  console.error('usage: node scripts/recover-outboxlog-seed-state.mjs --state <outboxlog-state.json> --snapshot <seed-snapshot.json> --app-id <hex> --expect-version <n> --expect-count <n> --expect-root <hex> --expect-live-version <n> --expect-live-count <n> --expect-live-root <hex> [--expect-snapshot-sha256 <hex>] [--replace-existing] [--apply]')
  process.exit(2)
}

function args (argv) {
  const out = { apply: false, replaceExisting: false }
  const values = new Set(['state', 'snapshot', 'app-id', 'expect-version', 'expect-count', 'expect-root', 'expect-live-version', 'expect-live-count', 'expect-live-root', 'expect-snapshot-sha256'])
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--apply') out.apply = true
    else if (arg === '--replace-existing') out.replaceExisting = true
    else if (arg.startsWith('--') && values.has(arg.slice(2))) {
      const value = argv[++i]
      if (!value) usage(`${arg} requires a value`)
      out[arg.slice(2)] = value
    } else usage(`unknown argument ${arg}`)
  }
  for (const key of ['state', 'snapshot', 'app-id', 'expect-version', 'expect-count', 'expect-root', 'expect-live-version', 'expect-live-count', 'expect-live-root']) {
    if (!out[key]) usage(`--${key} is required`)
  }
  for (const key of ['expect-version', 'expect-count', 'expect-live-version', 'expect-live-count']) {
    out[key] = Number(out[key])
    if (!Number.isSafeInteger(out[key]) || out[key] < 0) usage(`--${key} must be a non-negative integer`)
  }
  for (const key of ['expect-root', 'expect-live-root']) {
    out[key] = String(out[key]).toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(out[key])) usage(`--${key} must be 64 hex characters`)
  }
  if (out['expect-snapshot-sha256']) {
    out['expect-snapshot-sha256'] = String(out['expect-snapshot-sha256']).toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(out['expect-snapshot-sha256'])) usage('--expect-snapshot-sha256 must be 64 hex characters')
  }
  if (!/^[0-9a-f]{64}$/i.test(String(out['app-id']))) usage('--app-id must be 64 hex characters')
  return out
}

function readJson (file, label) {
  try { return JSON.parse(readFileSync(file, 'utf8')) } catch (err) { throw new Error(`${label} cannot be parsed: ${err.message}`) }
}

function sameSignature (left, right) {
  return String(left && left._sig || '').toLowerCase() === String(right && right._sig || '').toLowerCase()
}

function atomicJsonWrite (file, value) {
  const dir = dirname(file)
  mkdirSync(dir, { recursive: true })
  const temp = `${file}.recovery-${process.pid}-${Date.now()}.tmp`
  let fd
  try {
    fd = openSync(temp, 'w', 0o600)
    writeFileSync(fd, JSON.stringify(value))
    fsyncSync(fd)
    closeSync(fd)
    fd = undefined
    renameSync(temp, file)
    const dirFd = openSync(dir, 'r')
    try { fsyncSync(dirFd) } finally { closeSync(dirFd) }
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

try {
  const opts = args(process.argv.slice(2))
  const statePath = resolve(opts.state)
  const snapshotPath = resolve(opts.snapshot)
  const snapshotBytes = readFileSync(snapshotPath)
  const snapshotHash = createHash('sha256').update(snapshotBytes).digest('hex')
  if (opts['expect-snapshot-sha256'] && snapshotHash !== opts['expect-snapshot-sha256']) {
    throw new Error('snapshot SHA-256 does not match the approved recovery source')
  }
  const snapshot = readJson(snapshotPath, 'snapshot')
  const state = readJson(statePath, 'state')
  if (!Array.isArray(snapshot.authors)) throw new Error('snapshot authors is invalid')
  if (!Array.isArray(state.groups)) throw new Error('state groups is invalid')

  const appId = opts['app-id'].toLowerCase()
  const source = snapshot.authors.find((author) => String(author && author.pub || '').toLowerCase() === appId)
  if (!source || !Array.isArray(source.rows)) throw new Error('approved snapshot does not contain the requested outbox')
  const sourceRows = new Map()
  for (const row of source.rows) {
    if (!row || typeof row.key !== 'string' || !row.value || sourceRows.has(row.key)) throw new Error('snapshot has an invalid or duplicate row')
    sourceRows.set(row.key, row.value)
  }
  const headKey = `head!${appId}`
  const sourceHead = sourceRows.get(headKey)
  if (!sourceHead || sourceHead.author !== appId || sourceHead.id !== appId || sourceHead.version !== opts['expect-version'] || sourceHead.count !== opts['expect-count'] || String(sourceHead.root || '').toLowerCase() !== opts['expect-root']) {
    throw new Error('snapshot signed head does not match the approved recovery target')
  }
  if (sourceRows.size !== sourceHead.count + 1) throw new Error('snapshot row count is inconsistent with its signed head')

  const groupIndex = state.groups.findIndex((entry) => Array.isArray(entry) && String(entry[0] || '').toLowerCase() === appId)
  if (groupIndex < 0 || !state.groups[groupIndex][1] || !Array.isArray(state.groups[groupIndex][1].rows)) throw new Error('state does not contain a valid target outbox')
  const group = state.groups[groupIndex][1]
  const liveRows = new Map(group.rows)
  const liveHead = liveRows.get(headKey)
  if (!liveHead || liveHead.author !== appId || liveHead.id !== appId || liveHead.version !== opts['expect-live-version'] || liveHead.count !== opts['expect-live-count'] || String(liveHead.root || '').toLowerCase() !== opts['expect-live-root']) {
    throw new Error('live signed head changed since recovery was approved')
  }
  if (liveHead.version > sourceHead.version) throw new Error('live signed head is newer than the approved recovery source')

  const sourceContent = [...sourceRows.keys()].filter((key) => key !== headKey)
  const liveContent = [...liveRows.keys()].filter((key) => key !== headKey)
  const unexpected = liveContent.filter((key) => !sourceRows.has(key)).sort()
  if (unexpected.length) throw new Error(`live outbox has ${unexpected.length} row(s) absent from the approved snapshot`)
  const missing = sourceContent.filter((key) => !liveRows.has(key)).sort()
  const replacements = sourceContent.filter((key) => liveRows.has(key) && !sameSignature(sourceRows.get(key), liveRows.get(key))).sort()
  const headChanged = !sameSignature(sourceHead, liveHead)
  const changes = missing.length + replacements.length + (headChanged ? 1 : 0)
  if (replacements.length && !opts.replaceExisting) throw new Error('live rows differ from the approved snapshot; re-run only with --replace-existing after explicit approval')

  const plan = {
    mode: opts.apply ? 'apply' : 'dry-run',
    appId,
    snapshotSha256: snapshotHash,
    before: { version: liveHead.version, count: liveHead.count, root: liveHead.root, rows: liveRows.size, groupVersion: group.version },
    after: { version: sourceHead.version, count: sourceHead.count, root: sourceHead.root, rows: sourceRows.size },
    changes: { add: missing, replace: replacements, replaceHead: headChanged }
  }
  if (opts.apply) {
    group.rows = [...sourceRows.entries()]
    const count = Math.max(1, changes)
    group.version = Math.max(Number(group.version) || 0, sourceHead.version) + count
    state.directorySeq = (Number(state.directorySeq) || 0) + 1
    group.directorySeq = state.directorySeq
    state.appendSeq = (Number(state.appendSeq) || 0) + count
    atomicJsonWrite(statePath, state)
    plan.after.groupVersion = group.version
    plan.after.directorySeq = group.directorySeq
    plan.after.appendSeq = state.appendSeq
  }
  console.log(JSON.stringify(plan, null, 2))
} catch (err) {
  console.error(`[outboxlog-recovery] FAIL ${err.message}`)
  process.exitCode = 1
}
