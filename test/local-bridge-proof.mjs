import assert from 'node:assert'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { validateProofSnapshots, operatorRequiredValidation } from '../scripts/local-bridge-proof.mjs'

let passed = 0
const ok = (cond, msg) => { assert.ok(cond, msg); passed++; console.log('  ✓ ' + msg) }

const session = 'bpunit'
const aWriter = 'a'.repeat(64)
const bWriter = 'b'.repeat(64)
const communitySlug = 'bridge_bpunit'

function snapshot ({ role, writer, records, peers = 2, mode = 'gossip-bridge', at = '2026-07-01T00:00:00.000Z' }) {
  const sawA = !!records.aPost
  const sawB = !!records.bPost
  return {
    type: 'peerit-local-bridge-proof',
    version: 1,
    session,
    role,
    generatedAt: at,
    writer,
    status: { mode, peers, viewLength: Object.keys(records).length },
    proof: {
      communitySlug,
      observations: {
        bridgeMode: mode === 'gossip-bridge',
        peersAtLeast2: peers >= 2,
        sawA,
        sawB,
        wroteOwnRole: role === 'a' ? records.aPost && records.aPost.author === writer : records.bPost && records.bPost.author === writer,
        sawPeerRole: role === 'a' ? records.bPost && records.bPost.author !== writer : records.aPost && records.aPost.author !== writer,
        writersDistinct: records.aPost && records.bPost && records.aPost.author !== records.bPost.author,
        crossDeviceConverged: records.aPost && records.bPost && records.aPost.author !== records.bPost.author
      },
      records
    }
  }
}

const aPost = { cid: 'a1', title: 'Bridge proof A bpunit', author: aWriter }
const bPost = { cid: 'b1', title: 'Bridge proof B bpunit', author: bWriter }

console.log('\n— local bridge proof report validation —')

let validation = validateProofSnapshots([
  snapshot({ role: 'b', writer: bWriter, records: { aPost, bPost } }),
  snapshot({ role: 'a', writer: aWriter, records: { aPost, bPost }, at: '2026-07-01T00:00:01.000Z' })
], { session })
ok(validation.status === 'pass', 'accepts two gossip-bridge snapshots with distinct writers and bidirectional visibility')

validation = validateProofSnapshots([
  snapshot({ role: 'b', writer: aWriter, records: { aPost, bPost: { ...bPost, author: aWriter } } }),
  snapshot({ role: 'a', writer: aWriter, records: { aPost, bPost: { ...bPost, author: aWriter } } })
], { session })
ok(validation.status === 'fail' && validation.checks.some(c => c.id === 'distinct-writers' && c.status === 'fail'), 'rejects same-writer evidence')

validation = validateProofSnapshots([
  snapshot({ role: 'b', writer: bWriter, records: { aPost, bPost }, mode: 'gossip-dev' }),
  snapshot({ role: 'a', writer: aWriter, records: { aPost, bPost } })
], { session })
ok(validation.status === 'fail' && validation.checks.some(c => c.id === 'b-bridge-mode' && c.status === 'fail'), 'rejects non-bridge snapshots')

validation = validateProofSnapshots([
  snapshot({ role: 'b', writer: bWriter, records: { aPost, bPost } }),
  snapshot({ role: 'a', writer: aWriter, records: { aPost } })
], { session })
ok(validation.status === 'fail' && validation.checks.some(c => c.id === 'a-saw-b' && c.status === 'fail'), 'rejects one-way convergence')

validation = operatorRequiredValidation()
ok(validation.status === 'operator-required' && validation.checks.every(c => c.status === 'pending'), 'describes an explicitly unrun operator proof as pending')

const dir = mkdtempSync(join(tmpdir(), 'peerit-bridge-proof-'))
const report = join(dir, 'bridge-proof-plan.json')
const markdown = join(dir, 'bridge-proof-plan.md')
const cli = spawnSync(process.execPath, [
  'scripts/local-bridge-proof.mjs',
  '--plan-only',
  '--skip-headless',
  '--no-publish',
  '--url',
  'hyper://' + '1'.repeat(64) + '/',
  '--session',
  session,
  '--report',
  report,
  '--markdown',
  markdown
], { encoding: 'utf8' })
ok(cli.status === 0, 'plan-only CLI exits cleanly with an operator-required report')
const parsedReport = JSON.parse(readFileSync(report, 'utf8'))
ok(parsedReport.status === 'operator-required' && parsedReport.snapshots.length === 0, 'plan-only report records no snapshots and cannot be mistaken for proof')
ok(readFileSync(markdown, 'utf8').includes('operator-required'), 'plan-only markdown names the operator-required status')

console.log(`\n✅ all ${passed} local-bridge-proof checks passed\n`)
