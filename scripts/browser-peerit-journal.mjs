#!/usr/bin/env node
// Real-browser IndexedDB gate for Peerit's production journal backend.
// Run: node scripts/browser-peerit-journal.mjs

import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HOST = '127.0.0.1'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const timeoutMs = 30_000

function id (number) { return Number(number).toString(16).padStart(64, '0') }

async function freePort () {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.on('error', reject)
    server.listen(0, HOST, () => {
      const port = server.address().port
      server.close(() => resolve(port))
    })
  })
}

async function waitForHttp (url) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { cache: 'no-store' })
      if (response.ok) return
    } catch {}
    await sleep(100)
  }
  throw new Error(`dev server did not start at ${url}`)
}

async function startServer () {
  const port = await freePort()
  const child = spawn(process.execPath, ['dev-server.mjs'], {
    cwd: ROOT,
    env: { ...process.env, HOST, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let output = ''
  child.stdout.on('data', chunk => { output += chunk })
  child.stderr.on('data', chunk => { output += chunk })
  const url = `http://${HOST}:${port}/`
  try { await waitForHttp(url) } catch (error) {
    child.kill('SIGKILL')
    error.cause = new Error(output)
    throw error
  }
  return { child, url }
}

async function stopServer (child) {
  if (!child || child.killed) return
  child.kill('SIGTERM')
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    sleep(1500).then(() => child.kill('SIGKILL'))
  ])
}

async function deleteDatabase (page, name) {
  await page.evaluate(name => new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => reject(new Error(`delete blocked for ${name}`))
  }), name)
}

async function initJournal (page, dbName) {
  return page.evaluate(async dbName => {
    const modulePath = '/js/substrate/peerit-journal.js'
    const module = await import(modulePath)
    globalThis.__peeritJournalModule = module
    globalThis.__peeritJournal = module.createIndexedDbPeeritJournal({
      indexedDB: globalThis.indexedDB,
      IDBKeyRange: globalThis.IDBKeyRange,
      dbName,
      legacyStorage: globalThis.localStorage,
      markerStorage: globalThis.localStorage
    })
    return globalThis.__peeritJournal.ready()
  }, dbName)
}

async function createSchemaFixture (page, { name, version, corruption = null, target = null }) {
  await page.evaluate(({ name, version, corruption, target }) => new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(name, version)
    request.onupgradeneeded = () => {
      const db = request.result
      db.createObjectStore('meta', { keyPath: 'key' })
      const view = db.createObjectStore('view', { keyPath: 'key' })
      view.createIndex('updatedAt', 'updatedAt')
      const intents = db.createObjectStore('intents', { keyPath: 'intentId' })
      intents.createIndex('createdAt', 'createdAt')
      intents.createIndex('updatedAt', 'updatedAt')
      intents.createIndex('completedAt', 'completedAt')
      intents.createIndex('pendingOrderKey', 'pendingOrderKey')
      const targets = db.createObjectStore('targets', { keyPath: 'key' })
      targets.createIndex('intentId', 'intentId')
      targets.createIndex('state', 'state')
      targets.createIndex('leaseUntil', 'leaseUntil')
      targets.createIndex('updatedAt', 'updatedAt')
      if (version === 4) {
        targets.createIndex('targetStateAttemptOrder', ['targetId', 'state', 'attempts', 'updatedAt', 'intentId'])
      } else {
        targets.createIndex('targetStateDueOrder',
          corruption === 'keyPath'
            ? ['targetId', 'state', 'updatedAt', 'intentId']
            : ['targetId', 'state', 'nextAttemptAt', 'updatedAt', 'attempts', 'intentId'],
          { unique: corruption === 'options' })
      }
      targets.createIndex('targetStateLeaseOrder', ['targetId', 'state', 'leaseUntil', 'intentId'])
      targets.createIndex('stateLeaseOrder', ['state', 'leaseUntil', 'intentId', 'targetId'])
      const dedupe = db.createObjectStore('dedupe', { keyPath: 'intentId' })
      dedupe.createIndex('completedAt', 'completedAt')
      dedupe.createIndex('expiresAt', 'expiresAt')
      if (target) targets.put(target)
    }
    request.onerror = () => reject(request.error)
    request.onsuccess = () => { request.result.close(); resolve() }
  }), { name, version, corruption, target })
}

async function commit (page, number) {
  return page.evaluate(({ number, intentId, logicalId }) => {
    return globalThis.__peeritJournal.commitIntent({
      intentId,
      logicalId,
      operationBytes: JSON.stringify({ version: 1, operations: [{ type: 'post', data: { id: String(number) } }] }),
      records: [{ key: `post!${number}`, value: { id: String(number), body: `browser ${number}` } }],
      createdAt: number,
      discoveryState: 'queued'
    })
  }, { number, intentId: id(number), logicalId: id(number + 10_000) })
}

async function main () {
  const playwright = await import('playwright')
  const { child, url } = await startServer()
  const browser = await playwright.chromium.launch({ headless: true })
  let passed = 0
  const ok = (condition, message) => {
    if (!condition) throw new Error(message)
    passed++
    console.log('  ✓ ' + message)
  }
  try {
    const context = await browser.newContext()
    const first = await context.newPage()
    const second = await context.newPage()
    await Promise.all([first.goto(url), second.goto(url)])

    const dbName = `peerit-journal-browser-${Date.now()}`
    await deleteDatabase(first, dbName)
    const ready = await initJournal(first, dbName)
    const freshExists = await first.evaluate(async name => (await globalThis.indexedDB.databases()).some(db => db.name === name), dbName)
    ok(ready.dormant === true && freshExists === false,
      'fresh lurker readiness creates no IndexedDB database')

    await initJournal(second, dbName)
    await Promise.all([commit(first, 1), commit(second, 2)])
    const summary = await first.evaluate(() => globalThis.__peeritJournal.summary())
    ok(summary.intentCount === 2 && summary.viewRecordCount === 2,
      'separate tabs commit without lost IndexedDB metadata or view records')

    const duplicate = await Promise.all([commit(first, 3), commit(second, 3)])
    ok(duplicate.filter(result => result.duplicate).length === 1,
      'separate tabs atomically deduplicate the same exact intent')

    const claims = await Promise.all([
      first.evaluate(intentId => globalThis.__peeritJournal.claimTarget({
        intentId, targetId: 'relay', state: 'delivering', attemptToken: 'tab-one', leaseUntil: 1000, now: 0
      }), id(1)),
      second.evaluate(intentId => globalThis.__peeritJournal.claimTarget({
        intentId, targetId: 'relay', state: 'delivering', attemptToken: 'tab-two', leaseUntil: 1000, now: 0
      }), id(1))
    ])
    ok(claims.filter(Boolean).length === 1,
      'separate tabs elect exactly one target owner without Web Locks')

    const schema = await first.evaluate(() => {
      const db = globalThis.__peeritJournal.backend.db
      const stores = [...db.objectStoreNames]
      const tx = db.transaction(['intents', 'targets'], 'readonly')
      return {
        version: db.version,
        stores,
        intentIndexes: [...tx.objectStore('intents').indexNames],
        targetIndexes: [...tx.objectStore('targets').indexNames],
        dueIndex: (() => {
          const index = tx.objectStore('targets').index('targetStateDueOrder')
          return { keyPath: index.keyPath, unique: index.unique, multiEntry: index.multiEntry }
        })()
      }
    })
    ok(schema.version === 5 && ['meta', 'view', 'intents', 'targets', 'dedupe'].every(name => schema.stores.includes(name)) &&
      schema.intentIndexes.includes('pendingOrderKey') &&
      JSON.stringify([...schema.targetIndexes].sort()) === JSON.stringify([
        'intentId', 'leaseUntil', 'state', 'stateLeaseOrder',
        'targetStateDueOrder', 'targetStateLeaseOrder', 'updatedAt'
      ].sort()) &&
      JSON.stringify(schema.dueIndex.keyPath) === JSON.stringify([
        'targetId', 'state', 'nextAttemptAt', 'updatedAt', 'attempts', 'intentId'
      ]) && schema.dueIndex.unique === false && schema.dueIndex.multiEntry === false,
    'production schema creates exact bounded stores and due-order index key paths/options')

    await Promise.all([
      first.evaluate(() => globalThis.__peeritJournal.close()),
      second.evaluate(() => globalThis.__peeritJournal.close())
    ])
    await initJournal(first, dbName)
    const reloaded = await first.evaluate(() => globalThis.__peeritJournal.getView('post!2'))
    ok(reloaded && reloaded.body === 'browser 2',
      'closing and reopening a real IndexedDB connection preserves committed records')
    await first.evaluate(() => globalThis.__peeritJournal.close())
    await deleteDatabase(first, dbName)

    const upgradeDb = `${dbName}-v4-upgrade`
    const upgradeIntentId = id(40)
    const upgradeTarget = {
      key: `${upgradeIntentId}\u0000upgrade-relay`,
      intentId: upgradeIntentId,
      targetId: 'upgrade-relay',
      state: 'retryable',
      attempts: -3,
      updatedAt: -4,
      leaseUntil: 0
    }
    await deleteDatabase(first, upgradeDb)
    await createSchemaFixture(first, { name: upgradeDb, version: 4, target: upgradeTarget })
    await initJournal(first, upgradeDb)
    const upgraded = await first.evaluate(key => {
      const db = globalThis.__peeritJournal.backend.db
      const tx = db.transaction(['targets'], 'readonly')
      const store = tx.objectStore('targets')
      const due = store.index('targetStateDueOrder')
      return new Promise((resolve, reject) => {
        const request = store.get(key)
        request.onsuccess = () => resolve({
          version: db.version,
          target: request.result,
          indexes: [...store.indexNames],
          due: { keyPath: due.keyPath, unique: due.unique, multiEntry: due.multiEntry }
        })
        request.onerror = () => reject(request.error)
      })
    }, upgradeTarget.key)
    ok(upgraded.version === 5 && upgraded.target.attempts === 1 &&
      upgraded.target.updatedAt === 0 && upgraded.target.nextAttemptAt === 0 &&
      !upgraded.indexes.includes('targetStateAttemptOrder') &&
      JSON.stringify(upgraded.due.keyPath) === JSON.stringify([
        'targetId', 'state', 'nextAttemptAt', 'updatedAt', 'attempts', 'intentId'
      ]) && upgraded.due.unique === false && upgraded.due.multiEntry === false,
    'v4 target rows upgrade to normalized v5 due scheduling and obsolete indexes are removed')
    await first.evaluate(() => globalThis.__peeritJournal.close())
    await deleteDatabase(first, upgradeDb)

    for (const corruption of ['keyPath', 'options']) {
      const corruptDb = `${dbName}-v5-${corruption}`
      await deleteDatabase(first, corruptDb)
      await createSchemaFixture(first, { name: corruptDb, version: 5, corruption })
      const code = await first.evaluate(async name => {
        const module = await import('../../../../js/substrate/peerit-journal.js')
        const journal = module.createIndexedDbPeeritJournal({
          indexedDB: globalThis.indexedDB,
          IDBKeyRange: globalThis.IDBKeyRange,
          dbName: name,
          legacyStorage: null,
          markerStorage: null
        })
        try { await journal.ready(); return null } catch (error) { return error && error.code }
      }, corruptDb)
      ok(code === 'PEERIT_JOURNAL_CORRUPT',
        `an existing v5 database with wrong due-index ${corruption} fails closed`)
      await deleteDatabase(first, corruptDb)
    }

    const fairnessDb = `${dbName}-online-fairness`
    await deleteDatabase(first, fairnessDb)
    await initJournal(first, fairnessDb)
    const fairness = await first.evaluate(async () => {
      const journal = globalThis.__peeritJournal
      const hex = number => Number(number).toString(16).padStart(64, '0')
      const queue = async (number, updatedAt) => {
        const intentId = hex(number)
        await journal.commitIntent({
          intentId,
          logicalId: hex(number + 10_000),
          operationBytes: JSON.stringify({ version: 1, operations: [{ number }] }),
          records: [{ key: `post!fair!${number}`, value: { number } }],
          createdAt: number
        })
        const token = await journal.claimTarget({
          intentId,
          targetId: 'fair-relay',
          state: 'delivering',
          attemptToken: `queue:${number}`,
          leaseUntil: updatedAt + 1,
          now: updatedAt
        })
        await journal.failTarget({
          intentId,
          targetId: 'fair-relay',
          attemptToken: token,
          state: 'retryable',
          lastError: 'queued',
          now: updatedAt,
          nextAttemptAt: 0
        })
      }
      const oldCount = 64
      for (let number = 1000; number < 1000 + oldCount; number++) await queue(number, 1)
      const seen = new Set()
      for (let round = 0; round < 4; round++) {
        for (let arrival = 0; arrival < 8; arrival++) await queue(2000 + round * 8 + arrival, 10 + round)
        const page = await journal.listRetryIntentIds({ now: 100, targetIds: ['fair-relay'], limit: 16 })
        for (const intentId of page.intentIds) {
          const number = Number.parseInt(intentId, 16)
          if (number >= 1000 && number < 1000 + oldCount) seen.add(intentId)
          const token = await journal.claimTarget({
            intentId,
            targetId: 'fair-relay',
            state: 'delivering',
            expectedState: 'retryable',
            attemptToken: `consume:${round}:${intentId}`,
            leaseUntil: 201 + round,
            now: 200 + round
          })
          await journal.failTarget({
            intentId,
            targetId: 'fair-relay',
            attemptToken: token,
            state: 'terminal',
            lastError: 'consumed',
            now: 200 + round
          })
        }
      }
      return { oldCount, oldSeen: seen.size, onlineArrivals: 32 }
    })
    ok(fairness.oldSeen === fairness.oldCount && fairness.onlineArrivals === 32,
      'real IndexedDB due-order scans do not starve old retries during continuous online arrival')
    await first.evaluate(() => globalThis.__peeritJournal.close())
    await deleteDatabase(first, fairnessDb)

    const legacyDb = `${dbName}-legacy`
    const legacyId = id(50)
    await deleteDatabase(first, legacyDb)
    const legacyRaw = JSON.stringify({
      version: 1,
      revision: 1,
      viewRevision: 1,
      view: { 'post!legacy': { id: 'legacy', body: 'forged browser row' } },
      intents: {
        [legacyId]: {
          intentId: legacyId,
          logicalId: id(10_050),
          operationBytes: JSON.stringify({ version: 1, operations: [{ type: 'post', data: { id: 'legacy' } }] }),
          recordKeys: ['post!legacy'],
          createdAt: 1,
          updatedAt: 1,
          targets: { relay: { state: 'acknowledged', evidenceRef: 'fabricated', policyDurable: true } }
        }
      }
    })
    await first.evaluate(({ name, legacyKey, raw }) => new Promise((resolve, reject) => {
      const open = globalThis.indexedDB.open(name, 1)
      open.onupgradeneeded = () => open.result.createObjectStore('state')
      open.onerror = () => reject(open.error)
      open.onsuccess = () => {
        const db = open.result
        const tx = db.transaction(['state'], 'readwrite')
        tx.objectStore('state').put(raw, legacyKey)
        tx.oncomplete = () => { db.close(); resolve() }
        tx.onerror = () => reject(tx.error)
      }
    }), {
      name: legacyDb,
      legacyKey: 'peerit:substrate-sync:v1',
      raw: legacyRaw
    })
    const quarantined = await first.evaluate(async ({ name, legacyKey }) => {
      const module = await import('../../../../js/substrate/peerit-journal.js')
      const journal = module.createIndexedDbPeeritJournal({
        indexedDB: globalThis.indexedDB,
        IDBKeyRange: globalThis.IDBKeyRange,
        dbName: name,
        legacyStorage: null,
        markerStorage: null
      })
      let code = null
      try { await journal.ready() } catch (error) { code = error && error.code }
      const db = journal.backend.db
      const source = await new Promise((resolve, reject) => {
        const request = db.transaction(['state'], 'readonly').objectStore('state').get(legacyKey)
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
      })
      const counts = await new Promise((resolve, reject) => {
        const tx = db.transaction(['meta', 'view'], 'readonly')
        const meta = tx.objectStore('meta').count()
        const view = tx.objectStore('view').count()
        tx.oncomplete = () => resolve({ meta: meta.result, view: view.result })
        tx.onerror = () => reject(tx.error)
      })
      await journal.close()
      return { code, source, counts }
    }, { name: legacyDb, legacyKey: 'peerit:substrate-sync:v1' })
    ok(quarantined.code === 'PEERIT_JOURNAL_LEGACY_UNVERIFIED' &&
      quarantined.source === legacyRaw && quarantined.counts.meta === 0 && quarantined.counts.view === 0,
    'real IndexedDB quarantines unsigned legacy rows/receipts and preserves the source without visible writes')
    await deleteDatabase(first, legacyDb)
    await context.close()
    console.log(`\n✅ all ${passed} real-browser Peerit journal checks passed`)
  } finally {
    await browser.close()
    await stopServer(child)
  }
}

main().catch(error => {
  console.error('\n❌ browser Peerit journal gate failed:', error)
  process.exitCode = 1
})
