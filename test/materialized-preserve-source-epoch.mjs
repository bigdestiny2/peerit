// Regression: local-write preserve must not stamp matSource to a viewEpoch that
// advanced during append with remote rows (HiveRelay OutboxLog vote asymmetry).
import { createData } from '../js/data.js'
import { TYPE } from '../js/model.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { DevIdentity } from '../js/identity.js'

function ok (cond, msg) {
  if (!cond) {
    console.error('FAIL', msg)
    process.exitCode = 1
  } else console.log('  ✓', msg)
}

function mem () {
  const m = new Map()
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k)
  }
}

class FakeSync {
  constructor () {
    this.mode = 'dev'
    this.viewEpoch = 0
    this._view = Object.create(null)
    this._listeners = new Set()
  }
  async ready () { return this }
  onChange (fn) { this._listeners.add(fn); return () => this._listeners.delete(fn) }
  _emit (changed) { for (const fn of this._listeners) fn(changed) }
  async append (op) {
    const key = op.type.replace(':', '!') + '!' + op.data.id
    this._view[key] = op.data
    // Simulate a peer refresh landing a REMOTE vote during our local append,
    // advancing the merge epoch the way BridgeGossipSync does.
    const remoteKey = 'vote!targetcid0000000000000000000000000000000000000000000000000001!aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    this._view[remoteKey] = {
      id: 'targetcid0000000000000000000000000000000000000000000000000001!aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      targetCid: 'targetcid0000000000000000000000000000000000000000000000000001',
      targetType: TYPE.POST,
      author: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      value: 1,
      community: 'ab',
      ts: Date.now(),
      protocol: 3,
      targetRef: { type: TYPE.POST, cid: 'targetcid0000000000000000000000000000000000000000000000000001', author: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', contentNonce: '00', protocol: 3 }
    }
    this.viewEpoch++
    this._emit([key, remoteKey])
    return { ok: true }
  }
  async get (key) { return Object.prototype.hasOwnProperty.call(this._view, key) ? this._view[key] : null }
  async list (prefix, opts = {}) {
    const limit = opts.limit || 1000
    return Object.keys(this._view).filter(k => !prefix || k.startsWith(prefix)).sort().slice(0, limit).map(key => ({ key, value: this._view[key] }))
  }
  async range (opts = {}) { return this.list(opts.gte || '', opts) }
  async count (prefix) { return (await this.list(prefix)).length }
  async status () { return { mode: this.mode, peers: 2, viewLength: Object.keys(this._view).length } }
  destroy () {}
}

await cryptoReady()
const local = mem()
const session = mem()
const id = new DevIdentity(local, session, { persistSeed: true })
await id.ready()
await id.createUser('preserve-race')
const sync = new FakeSync()
const data = createData(sync, id, { minBits: { community: 0, post: 0, comment: 0 } })

// Seed a live materialized index so the preserve path is eligible.
const index = await data._index()
ok(!!index, 'materialized index builds')

// Local vote while append advances viewEpoch with a remote vote.
const me = id.me().pubkey
// Bypass full vote() target validation: call _emit like vote does after target checks.
const targetCid = 'targetcid0000000000000000000000000000000000000000000000000001'
const voteData = {
  id: `${targetCid}!${me}`,
  targetCid,
  targetType: TYPE.POST,
  community: 'ab',
  protocol: 3,
  targetRef: { type: TYPE.POST, cid: targetCid, author: me, contentNonce: '00', protocol: 3 },
  value: 1,
  author: me,
  ts: Date.now()
}
await data._emit(TYPE.VOTE, voteData)
data.invalidateViewCaches('vote')

const raw = await data.rawVotes(targetCid)
const authors = new Set(raw.map(v => v.author))
ok(authors.has(me), 'local vote present after source-advancing write')
ok(authors.has('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 'remote vote not lost to preserved incomplete index')
ok(raw.length >= 2, 'both votes visible in tally source (' + raw.length + ')')

if (process.exitCode) {
  console.error('\nmaterialized-preserve-source-epoch: FAILED')
  process.exit(1)
}
console.log('\nmaterialized-preserve-source-epoch: all checks passed')
