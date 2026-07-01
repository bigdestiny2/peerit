// js/ra-idb.js — durable IndexedDB storage for hypercore@10 in the browser.
//
// WHY: random-access-web@2.0.3 ships the RAS@1 API, which has no truncate();
// hypercore@10 calls storage.truncate on write → "this.storage.truncate is not a
// function". This is a from-scratch backend on the SAME random-access-storage@3
// base that random-access-memory@6 uses (the one hypercore@10 is proven to work
// with), so it inherits the request queue + open/close semantics hypercore expects,
// implements a real _truncate, and uses b4a (browser-correct buffers) instead of
// Node Buffer.
//
// Block model (classic random-access-idb): one IndexedDB database per `dbname`, a
// single 'data' object store shared by every file. Keys:
//   "<file>\0<pageIndex>" → the page's bytes (Uint8Array, pageSize each)
//   "<file>\0length"       → the file's byte length (number)
// RAS serializes ops per file, so a file never has two overlapping transactions.

import RandomAccessStorage from 'random-access-storage'
import b4a from 'b4a'

const DELIM = '\0'
const DEFAULT_PAGE = 4096

export default function createIdbStorage (dbname, xopts = {}) {
  const idb = xopts.idb || (typeof indexedDB !== 'undefined' ? indexedDB : null)
  if (!idb) throw new Error('indexedDB not present and not provided')
  const pageSize = xopts.size || DEFAULT_PAGE

  let db = null
  let openErr = null
  const waiters = []
  const open = idb.open(dbname)
  open.addEventListener('upgradeneeded', () => { open.result.createObjectStore('data') })
  open.addEventListener('success', () => { db = open.result; flush() })
  open.addEventListener('error', () => { openErr = open.error || new Error('indexedDB open failed'); flush() })
  function flush () { while (waiters.length) waiters.shift()(openErr, db) }
  function getdb (cb) { if (db || openErr) queueMicrotask(() => cb(openErr, db)); else waiters.push(cb) }

  return function (name, opts = {}) {
    if (typeof name === 'object') { opts = name; name = opts.name }
    return new IdbFile(name, getdb, pageSize)
  }
}

class IdbFile extends RandomAccessStorage {
  constructor (name, getdb, pageSize) {
    super()
    this.name = name
    this.pageSize = pageSize
    this.length = 0
    this._getdb = getdb
  }

  _tx (mode, cb) {
    this._getdb((err, db) => {
      if (err) return cb(err)
      let tx
      try { tx = db.transaction(['data'], mode) } catch (e) { return cb(e) }
      cb(null, tx.objectStore('data'), tx)
    })
  }

  _pageKey (page) { return this.name + DELIM + page }
  get _lenKey () { return this.name + DELIM + 'length' }

  _open (req) {
    this._tx('readonly', (err, store) => {
      if (err) return req.callback(err)
      const g = store.get(this._lenKey)
      g.addEventListener('success', () => { this.length = g.result || 0; req.callback(null) })
      g.addEventListener('error', () => req.callback(g.error))
    })
  }

  // The shared db stays open — corestore closes individual files, not the database.
  _close (req) { req.callback(null) }

  _stat (req) { req.callback(null, { size: this.length }) }

  _read (req) {
    if (req.offset + req.size > this.length) return req.callback(new Error('Could not satisfy length'))
    if (req.size === 0) return req.callback(null, b4a.alloc(0))
    this._tx('readonly', (err, store) => {
      if (err) return req.callback(err)
      const data = b4a.alloc(req.size)
      let i = Math.floor(req.offset / this.pageSize)
      let rel = req.offset % this.pageSize
      let start = 0
      let pending = 0
      let done = false
      const fail = (e) => { if (!done) { done = true; req.callback(e) } }
      const finish = () => { if (!done && pending === 0) { done = true; req.callback(null, data) } }
      while (start < req.size) {
        const avail = this.pageSize - rel
        const want = req.size - start
        const len = avail < want ? avail : want
        const s = start, r = rel
        pending++
        const g = store.get(this._pageKey(i))
        g.addEventListener('success', () => {
          const page = g.result
          if (page) { const u = page instanceof Uint8Array ? page : new Uint8Array(page); b4a.copy(u, data, s, r, r + len) }
          pending--; finish()
        })
        g.addEventListener('error', () => fail(g.error))
        start += len; rel = 0; i++
      }
      finish()
    })
  }

  _write (req) {
    this._tx('readwrite', (err, store, tx) => {
      if (err) return req.callback(err)
      const endByte = req.offset + req.size
      let i = Math.floor(req.offset / this.pageSize)
      let rel = req.offset % this.pageSize
      let start = 0
      let pending = 0
      let failed = false
      const pages = [] // { page, buf }
      const fail = (e) => { if (!failed) { failed = true; try { tx.abort() } catch {} req.callback(e) } }
      const maybeCommit = () => {
        if (failed || pending > 0) return
        for (const p of pages) store.put(p.buf, this._pageKey(p.page))
        const newLen = Math.max(this.length, endByte)
        store.put(newLen, this._lenKey)
        tx.addEventListener('complete', () => { this.length = newLen; req.callback(null) })
        tx.addEventListener('error', () => fail(tx.error || new Error('idb write error')))
        tx.addEventListener('abort', () => { if (!failed) fail(tx.error || new Error('idb write aborted')) })
      }
      while (start < req.size) {
        const free = this.pageSize - rel
        const len = free < (req.size - start) ? free : req.size - start
        const page = i, r = rel, s = start
        if (len === this.pageSize) {
          const buf = b4a.alloc(this.pageSize)
          b4a.copy(req.data, buf, 0, s, s + len)
          pages.push({ page, buf })
        } else {
          pending++
          const g = store.get(this._pageKey(page))
          g.addEventListener('success', () => {
            const existing = g.result ? (g.result instanceof Uint8Array ? g.result : new Uint8Array(g.result)) : null
            const buf = b4a.alloc(this.pageSize)
            if (existing) b4a.copy(existing, buf, 0, 0, Math.min(existing.length, this.pageSize))
            b4a.copy(req.data, buf, r, s, s + len)
            pages.push({ page, buf })
            pending--; maybeCommit()
          })
          g.addEventListener('error', () => fail(g.error))
        }
        start += len; rel = 0; i++
      }
      maybeCommit()
    })
  }

  _truncate (req) {
    const newLen = req.offset
    if (newLen >= this.length) {
      // grow / no-op: just record the length (pages materialise on write)
      this._tx('readwrite', (err, store, tx) => {
        if (err) return req.callback(err)
        store.put(newLen, this._lenKey)
        tx.addEventListener('complete', () => { this.length = newLen; req.callback(null) })
        tx.addEventListener('error', () => req.callback(tx.error || new Error('idb truncate error')))
      })
      return
    }
    const oldLast = this.length > 0 ? Math.floor((this.length - 1) / this.pageSize) : -1
    const firstDelete = Math.ceil(newLen / this.pageSize) // pages fully beyond newLen
    const boundaryPage = newLen > 0 ? Math.floor((newLen - 1) / this.pageSize) : -1
    const boundaryFill = newLen % this.pageSize // >0 → zero boundary page bytes [boundaryFill..end)
    this._tx('readwrite', (err, store, tx) => {
      if (err) return req.callback(err)
      const commit = () => {
        for (let p = firstDelete; p <= oldLast; p++) store.delete(this._pageKey(p))
        store.put(newLen, this._lenKey)
        tx.addEventListener('complete', () => { this.length = newLen; req.callback(null) })
        tx.addEventListener('error', () => req.callback(tx.error || new Error('idb truncate error')))
        tx.addEventListener('abort', () => req.callback(tx.error || new Error('idb truncate aborted')))
      }
      if (boundaryFill > 0 && boundaryPage >= 0 && boundaryPage < firstDelete) {
        const g = store.get(this._pageKey(boundaryPage))
        g.addEventListener('success', () => {
          if (g.result) {
            const u = g.result instanceof Uint8Array ? g.result : new Uint8Array(g.result)
            const buf = b4a.alloc(this.pageSize)
            b4a.copy(u, buf, 0, 0, Math.min(u.length, this.pageSize))
            buf.fill(0, boundaryFill)
            store.put(buf, this._pageKey(boundaryPage))
          }
          commit()
        })
        g.addEventListener('error', () => req.callback(g.error))
      } else {
        commit()
      }
    })
  }

  _del (req) {
    // delete-to-end == truncate to offset
    if (req.size === Infinity || req.offset + req.size >= this.length) {
      req.offset = Math.min(req.offset, this.length)
      return this._truncate(req)
    }
    // interior clear: zero the covered bytes via read-modify-write
    this._tx('readwrite', (err, store, tx) => {
      if (err) return req.callback(err)
      let i = Math.floor(req.offset / this.pageSize)
      let rel = req.offset % this.pageSize
      let start = 0
      let pending = 0
      let failed = false
      const edits = []
      const fail = (e) => { if (!failed) { failed = true; try { tx.abort() } catch {} req.callback(e) } }
      const commit = () => {
        if (failed || pending > 0) return
        for (const e of edits) store.put(e.buf, this._pageKey(e.page))
        tx.addEventListener('complete', () => req.callback(null))
        tx.addEventListener('error', () => fail(tx.error || new Error('idb del error')))
      }
      while (start < req.size) {
        const free = this.pageSize - rel
        const len = free < (req.size - start) ? free : req.size - start
        const page = i, r = rel
        pending++
        const g = store.get(this._pageKey(page))
        g.addEventListener('success', () => {
          if (g.result) {
            const u = g.result instanceof Uint8Array ? g.result : new Uint8Array(g.result)
            const buf = b4a.alloc(this.pageSize)
            b4a.copy(u, buf, 0, 0, Math.min(u.length, this.pageSize))
            buf.fill(0, r, r + len)
            edits.push({ page, buf })
          }
          pending--; commit()
        })
        g.addEventListener('error', () => fail(g.error))
        start += len; rel = 0; i++
      }
      commit()
    })
  }
}
