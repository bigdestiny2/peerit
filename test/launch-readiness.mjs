import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const scratch = mkdtempSync(join(tmpdir(), 'peerit-launch-readiness-'))

function report (environment = 'staging') {
  return {
    kind: 'peerit-two-relay-atomic-soak',
    status: 'pass',
    options: {
      clients: 2000,
      environment,
      trafficProfile: 'distributed',
      restarts: 1,
      maxP99Ms: 2000
    },
    metrics: { latencyMs: { p99: 1999 } }
  }
}

function run (file) {
  return spawnSync(process.execPath, ['scripts/launch-readiness.mjs'], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, PEERIT_CAPACITY_REPORT: file }
  })
}

try {
  const staging = join(scratch, 'staging.json')
  writeFileSync(staging, JSON.stringify(report()) + '\n')
  const stagingResult = run(staging)
  assert.equal(stagingResult.status, 0, stagingResult.stderr || stagingResult.stdout)
  assert.match(stagingResult.stdout, /PASS public capacity target measured/)

  const local = join(scratch, 'local.json')
  writeFileSync(local, JSON.stringify(report('local')) + '\n')
  const localResult = run(local)
  assert.notEqual(localResult.status, 0)
  assert.match(localResult.stdout, /FAIL public capacity target measured/)
  console.log('launch readiness capacity gate: staging-only evidence verified')
} finally {
  rmSync(scratch, { recursive: true, force: true })
}
