#!/usr/bin/env node
// export-seed-snapshot.mjs — export the pinned seed outboxes' SIGNED rows from the
// live relay into config/seed-snapshot.json, which build-web.mjs bakes into the
// bundle as web/seed-snapshot.json (hash-pinned). A first-ever visitor renders
// this instantly; every row is re-verified client-side by the same admit() gate
// as live gossip, so the snapshot can go stale but can never forge.
//
//   node scripts/export-seed-snapshot.mjs            # relays + outboxes from deploy/web-release.json
//   RELAY=https://outbox.peerit.site node scripts/export-seed-snapshot.mjs
//
// Re-run at release time (after reseeding) so the snapshot tracks the seed content.
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join(ROOT, 'config', 'seed-snapshot.json')
const release = JSON.parse(readFileSync(join(ROOT, 'deploy', 'web-release.json'), 'utf8'))
const RELAY = process.env.RELAY || (release.bootstrapRelays && release.bootstrapRelays[0])
const seedOutboxes = (release.seedOutboxes || []).filter(o => o && /^[0-9a-f]{64}$/i.test(o.appId || ''))
if (!RELAY || !seedOutboxes.length) { console.error('need a relay (deploy/web-release.json bootstrapRelays or RELAY=) and seedOutboxes'); process.exit(2) }

async function main () {
  const tok = await (await fetch(RELAY + '/api/token', { method: 'POST' })).json()
  const headers = { 'X-Pear-Token': tok.token }
  const authors = []
  for (const o of seedOutboxes) {
    const rows = []
    let gt = ''
    // Paginate with the non-advance guard (never trust a cursor to move).
    while (rows.length < 50000) {
      const qs = new URLSearchParams({ appId: o.appId, limit: '1000' })
      if (gt) qs.set('gt', gt)
      const res = await fetch(RELAY + '/api/sync/range?' + qs, { headers })
      if (!res.ok) throw new Error('range ' + o.appId.slice(0, 12) + ' HTTP ' + res.status)
      const batch = await res.json()
      const list = Array.isArray(batch) ? batch : (batch.rows || [])
      if (!list.length) break
      for (const r of list) { if (r && typeof r.key === 'string' && r.value) rows.push({ key: r.key, value: r.value }) }
      const last = list[list.length - 1] && list[list.length - 1].key
      if (!last || last === gt || list.length < 1000) break
      gt = last
    }
    if (rows.length) authors.push({ pub: o.appId, rows })
    console.log('  ' + o.appId.slice(0, 12) + '… → ' + rows.length + ' row(s)')
  }
  if (!authors.length) { console.error('no rows exported — is the relay seeded?'); process.exit(1) }
  const snap = { v: 1, generatedAt: new Date().toISOString(), relay: RELAY, authors }
  writeFileSync(OUT, JSON.stringify(snap) + '\n')
  const total = authors.reduce((n, a) => n + a.rows.length, 0)
  console.log('wrote ' + OUT + ' (' + authors.length + ' author(s), ' + total + ' rows, ' + JSON.stringify(snap).length + ' bytes)')
}
main().catch((e) => { console.error('❌', e.message); process.exit(1) })
