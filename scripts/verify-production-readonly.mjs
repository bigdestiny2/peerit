#!/usr/bin/env node

// Non-destructive production containment proof.
//
// The create/append probes deliberately omit authorization and contain no valid
// appId or signed operation. If the edge rule is absent, the relay can only
// answer 400/401; the probes can never allocate or append state. A passing run
// proves the edge intercepted both write routes before they reached HiveRelay.

const relay = String(process.env.PEERIT_RELAY || 'https://outbox.peerit.site').replace(/\/$/, '')
const seedAppId = '6b565bc4cc28544526c85c09760f53bf735464393ad931bb026fb10e0757de30'

async function request (path, options = {}) {
  const response = await fetch(relay + path, options)
  const text = await response.text()
  let body = null
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  return { response, body }
}

for (const path of ['/api/sync/create', '/api/sync/append']) {
  const { response, body } = await request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}'
  })
  if (response.status !== 403) throw new Error(`${path} expected edge-enforced 403, got ${response.status}`)
  if (!body || !/read-only/i.test(String(body.error || ''))) throw new Error(`${path} did not return the read-only maintenance contract`)
}

const health = await request('/health')
if (health.response.status !== 200) throw new Error(`/health expected 200, got ${health.response.status}`)

const issued = await request('/api/token', { method: 'POST' })
if (issued.response.status !== 200 || !issued.body || !issued.body.token) throw new Error('token issuance failed')
const headers = { 'X-Pear-Token': issued.body.token }
const directory = await request('/api/directory?limit=2000', { headers })
if (directory.response.status !== 200) throw new Error(`/api/directory expected 200, got ${directory.response.status}`)

const range = await request(`/api/sync/range?appId=${seedAppId}&limit=1000`, { headers })
if (range.response.status !== 200 || !Array.isArray(range.body)) throw new Error('existing outbox range read failed')

console.log(JSON.stringify({
  ok: true,
  relay,
  blocked: ['/api/sync/create', '/api/sync/append'],
  health: health.response.status,
  directory: directory.response.status,
  seedRowsServed: range.body.length
}, null, 2))
