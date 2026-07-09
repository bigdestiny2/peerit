// Regression: the v2 reader must cursor through more than the transport's
// 1000-row page instead of silently dropping records by opaque-key order.
import assert from 'node:assert'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'

const mem = () => { const m = new Map(); return { getItem: k => m.get(k) || null, setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) } }

async function main () {
  await cryptoReady()
  const id = new DevIdentity(mem(), mem()); await id.ready(); await id.createUser('pager')
  const raw = []
  const sync = {
    list: async (prefix, opts = {}) => raw.filter(r => r.key.startsWith(prefix)).slice(0, Math.min(Number(opts.limit) || 100, 1000)),
    range: async (opts = {}) => {
      let rows = raw.slice().sort((a, b) => a.key.localeCompare(b.key))
      if (opts.gte != null) rows = rows.filter(r => r.key >= opts.gte)
      if (opts.gt != null) rows = rows.filter(r => r.key > opts.gt)
      if (opts.lt != null) rows = rows.filter(r => r.key < opts.lt)
      return rows.slice(0, Math.min(Number(opts.limit) || 100, 1000))
    },
    get: async () => null,
    append: async () => {}
  }
  const data = createData(sync, id, { v2: true })
  for (let i = 0; i < 1005; i++) {
    const stored = await data._toV2('community', {
      id: 'c' + i,
      slug: 'c' + i,
      title: 'Community ' + i,
      description: '',
      rules: [],
      creator: id.me().pubkey,
      author: id.me().pubkey,
      createdAt: i + 1,
      updatedAt: i + 1
    })
    stored._k = id.me().pubkey; stored._dk = id.me().pubkey; stored._ns = 'peerit'; stored._alg = 'ed25519'
    raw.push({ key: 'v2!' + stored.id, value: stored })
  }
  const view = await data._buildV2View()
  assert.equal(Object.keys(view).filter(k => k.startsWith('community!')).length, 1005)
  assert.equal((await data.listCommunities()).length, 1005)
  console.log('v2-pagination: passed 2 checks')
}

main().catch((err) => { console.error(err); process.exit(1) })
