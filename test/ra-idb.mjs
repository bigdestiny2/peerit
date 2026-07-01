// ra-idb.mjs — deterministic unit test for js/ra-idb.js (the durable IndexedDB
// backend for hypercore@10 in the browser). Uses a tiny in-memory IndexedDB mock
// (injected via xopts.idb) so the block math, truncate, del, and reopen-persistence
// are validated without a browser. The real DHT wire is covered by dht-live.mjs;
// this covers the storage engine's correctness.
//
// Needs random-access-storage@3 + b4a (installed by `npm run dht:deps`). Skips
// cleanly (exit 0) if they're absent.
//   node test/ra-idb.mjs

import assert from 'node:assert'

let b4a
try {
  await import('random-access-storage')
  b4a = (await import('b4a')).default
} catch (e) {
  console.log('SKIP ra-idb: deps not installed (' + (e && e.message) + ')')
  process.exit(0)
}

const createIdbStorage = (await import('../js/ra-idb.js')).default

// ---- minimal in-memory IndexedDB mock ------------------------------------
// Models just what ra-idb.js uses: idb.open → db.transaction → objectStore →
// get/put/delete, with async requests and a transaction that "completes" once it
// goes idle. Databases persist across open() calls (keyed by name) so reopen
// durability is testable. Values are structured-cloned (Uint8Array copied).
function makeIdbMock () {
  const dbs = new Map()
  function emitter () {
    const h = {}
    return {
      result: undefined,
      error: null,
      addEventListener (t, fn) { (h[t] || (h[t] = [])).push(fn) },
      _emit (t) { (h[t] || []).forEach((fn) => fn({ target: this })) }
    }
  }
  function clone (v) { return v instanceof Uint8Array ? v.slice() : v }
  class Tx {
    constructor (db) { this.db = db; this.pending = 0; this.done = false; this._h = {} }
    addEventListener (t, fn) { (this._h[t] || (this._h[t] = [])).push(fn) }
    _emit (t) { (this._h[t] || []).forEach((fn) => fn({ target: this })) }
    objectStore () { return new Store(this) }
    _req (fn) {
      const req = emitter()
      this.pending++
      queueMicrotask(() => {
        try { req.result = fn(); req._emit('success') } catch (e) { req.error = e; this.done = true; req._emit('error') }
        this.pending--
        queueMicrotask(() => { if (this.pending === 0 && !this.done) { this.done = true; this._emit('complete') } })
      })
      return req
    }
    abort () { if (!this.done) { this.done = true; this._emit('abort') } }
  }
  class Store {
    constructor (tx) { this.tx = tx }
    get (key) { return this.tx._req(() => (this.tx.db.data.has(key) ? this.tx.db.data.get(key) : undefined)) }
    put (value, key) { return this.tx._req(() => { this.tx.db.data.set(key, clone(value)); return undefined }) }
    delete (key) { return this.tx._req(() => { this.tx.db.data.delete(key); return undefined }) }
  }
  return {
    open (name) {
      const req = emitter()
      queueMicrotask(() => {
        let db = dbs.get(name)
        const fresh = !db
        if (fresh) { db = { name, data: new Map() }; dbs.set(name, db) }
        db.transaction = () => new Tx(db)
        db.createObjectStore = () => {}
        req.result = db
        if (fresh) req._emit('upgradeneeded')
        req._emit('success')
      })
      return req
    }
  }
}

// ---- promisified RAS@3 public API ----------------------------------------
const pread = (f, o, s) => new Promise((res, rej) => f.read(o, s, (e, d) => (e ? rej(e) : res(d))))
const pwrite = (f, o, d) => new Promise((res, rej) => f.write(o, d, (e) => (e ? rej(e) : res())))
const ptrunc = (f, o) => new Promise((res, rej) => f.truncate(o, (e) => (e ? rej(e) : res())))
const pdel = (f, o, s) => new Promise((res, rej) => f.del(o, s, (e) => (e ? rej(e) : res())))
const pstat = (f) => new Promise((res, rej) => f.stat((e, st) => (e ? rej(e) : res(st))))
const popen = (f) => new Promise((res, rej) => f.open((e) => (e ? rej(e) : res())))

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

async function main () {
  const idb = makeIdbMock()
  const factory = createIdbStorage('peerit-test', { idb })
  const f = factory('core')

  // 1. multi-page write + read (10000 bytes over 4096-byte pages = 3 pages)
  const big = b4a.alloc(10000)
  for (let i = 0; i < big.length; i++) big[i] = (i * 7 + 3) & 0xff
  await pwrite(f, 0, big)
  ok((await pstat(f)).size === 10000, 'length is 10000 after a 3-page write')
  ok(b4a.equals(await pread(f, 0, 10000), big), 'full multi-page read matches what was written')
  ok(b4a.equals(await pread(f, 4090, 20), big.subarray(4090, 4110)), 'cross-page-boundary read matches')

  // 2. overwrite an interior partial range
  const patch = b4a.from([1, 2, 3, 4, 5])
  await pwrite(f, 5000, patch)
  ok(b4a.equals(await pread(f, 5000, 5), patch), 'interior partial overwrite reads back')
  ok(b4a.equals(await pread(f, 4998, 2), big.subarray(4998, 5000)), 'bytes just before the patch are untouched')

  // 3. truncate down — length shrinks, tail pages gone, reads beyond fail
  await ptrunc(f, 5000)
  ok((await pstat(f)).size === 5000, 'truncate to 5000 updates length')
  ok(b4a.equals(await pread(f, 0, 100), big.subarray(0, 100)), 'data below the truncate point survives')
  let threw = false
  try { await pread(f, 4999, 10) } catch { threw = true }
  ok(threw, 'read past the truncated length is refused')

  // 4. reopen (fresh IdbFile, same db) — durability across "restart"
  const f2 = factory('core')
  await popen(f2)
  ok((await pstat(f2)).size === 5000, 'reopened file recovers the persisted length (5000)')
  ok(b4a.equals(await pread(f2, 0, 100), big.subarray(0, 100)), 'reopened file recovers persisted data')

  // 5. grow again after truncate, then read the new region
  const grow = b4a.from([9, 9, 9, 9])
  await pwrite(f2, 5000, grow)
  ok((await pstat(f2)).size === 5004, 'writing past the (truncated) end grows the file')
  ok(b4a.equals(await pread(f2, 5000, 4), grow), 'the grown region reads back correctly')

  // 6. interior del zeroes the covered bytes (length unchanged)
  await pdel(f2, 100, 50)
  const zeros = b4a.alloc(50)
  ok(b4a.equals(await pread(f2, 100, 50), zeros), 'interior del zeroes the range')
  ok((await pstat(f2)).size === 5004, 'interior del leaves length unchanged')

  // 7. isolation: a different file in the same db is independent
  const other = factory('other')
  await pwrite(other, 0, b4a.from([42]))
  ok((await pstat(other)).size === 1, 'a second file in the same db has its own length')
  ok((await pstat(f2)).size === 5004, 'writing the second file did not disturb the first')

  console.log(`\n✅ all ${passed} ra-idb checks passed — durable IndexedDB backend (RAS@3 + truncate) is correct\n`)
  process.exit(0)
}
main().catch((e) => { console.error('\n❌ ra-idb FAILED:', e && e.message, '\n', e && e.stack); process.exit(1) })
