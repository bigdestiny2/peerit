#!/usr/bin/env node
// Real-browser IndexedDB gate for encrypted blind-client capability and
// descriptor-continuity state. Run: node scripts/browser-peerit-substrate-state.mjs

import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { setTimeout as sleep } from 'node:timers/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HOST = '127.0.0.1'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const timeoutMs = 30_000
const CAPABILITY_DB = 'peerit-substrate-capabilities'
const DESCRIPTOR_DB = 'peerit-substrate-descriptor-trust'

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
  const url = `http://${HOST}:${port}/js/substrate/capability-vault.js`
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

async function rawRecordAudit (page, name, forbidden) {
  return page.evaluate(async ({ name, forbidden }) => {
    const records = await new Promise((resolve, reject) => {
      const request = globalThis.indexedDB.open(name, 1)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        const db = request.result
        const tx = db.transaction('records', 'readonly')
        const all = tx.objectStore('records').getAll()
        all.onsuccess = () => resolve(all.result)
        all.onerror = () => reject(all.error)
        tx.oncomplete = () => db.close()
      }
    })
    const json = JSON.stringify(records, (_key, value) =>
      value instanceof Uint8Array ? [...value] : value)
    const key = records[0] && records[0].wrapKey
    let nonextractable = key instanceof CryptoKey && key.extractable === false
    if (nonextractable) {
      try {
        await crypto.subtle.exportKey('raw', key)
        nonextractable = false
      } catch {}
    }
    return {
      count: records.length,
      nonextractable,
      clearMatches: forbidden.filter(value => json.includes(value))
    }
  }, { name, forbidden })
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

    const browserScheduler = await first.evaluate(async () => {
      const moduleUrl = `${globalThis.location.origin}/js/substrate/relay-requalification-scheduler.js`
      const { createPeeritRelayRequalificationScheduler } = await import(moduleUrl)
      const brands = new WeakSet()
      const adapter = Object.freeze({ id: 'chromium-verified-relay' })
      brands.add(adapter)
      const publications = []
      const startedAt = performance.now()
      const healthDeadline = startedAt + 1_000
      const signedDeadline = startedAt + 250
      let calls = 0
      let abortObserved = false
      const scheduler = createPeeritRelayRequalificationScheduler({
        async qualify ({ signal }) {
          calls++
          if (calls === 1) {
            return Object.freeze({
              adapters: Object.freeze([adapter]),
              status: Object.freeze({
                state: 'qualified',
                active: true,
                qualifiedRelayCount: 1,
                releaseBlockers: Object.freeze([]),
                leaseExpiresAtMonotonicMillis: healthDeadline,
                leaseExpiresEpoch: 7
              })
            })
          }
          return new Promise((resolve, reject) => {
            if (signal.aborted) {
              abortObserved = true
              reject(signal.reason)
              return
            }
            signal.addEventListener('abort', () => {
              abortObserved = true
              reject(signal.reason)
            }, { once: true })
          })
        },
        publish (adapters, status) {
          publications.push({ count: adapters.length, state: status.state, at: performance.now() })
        },
        verifyAdapter: value => brands.has(value),
        epochDeadlineMonotonicMillis: () => signedDeadline,
        monotonicMillis: () => performance.now(),
        refreshLeadMillis: 100,
        maximumRefreshIntervalMillis: 500,
        minimumRetryMillis: 25,
        maximumRetryMillis: 100
      })
      const installed = await scheduler.start()
      scheduler.refresh('chromium-in-flight-expiry').catch(() => {})
      await new Promise(resolve => setTimeout(resolve, 350))
      const expired = publications.find(entry => entry.state === 'qualification-expired')
      const stateBeforeStop = scheduler.status().state
      scheduler.stop()
      await new Promise(resolve => setTimeout(resolve, 0))

      const badPublications = []
      const badScheduler = createPeeritRelayRequalificationScheduler({
        qualify: async () => Object.freeze({
          adapters: Object.freeze([adapter]),
          status: Object.freeze({
            state: 'qualified',
            active: true,
            qualifiedRelayCount: 1,
            releaseBlockers: Object.freeze([]),
            leaseExpiresAtMonotonicMillis: performance.now() + 1_000,
            leaseExpiresEpoch: 8,
            releaseReady: true
          })
        }),
        publish: (adapters, status) => badPublications.push({ count: adapters.length, status }),
        verifyAdapter: value => brands.has(value),
        epochDeadlineMonotonicMillis: () => performance.now() + 900,
        monotonicMillis: () => performance.now(),
        refreshLeadMillis: 100,
        maximumRefreshIntervalMillis: 500,
        minimumRetryMillis: 25,
        maximumRetryMillis: 100
      })
      const badStatus = await badScheduler.start()
      badScheduler.stop()
      return {
        installedDeadline: installed.leaseExpiresAtMonotonicMillis,
        healthDeadline,
        signedDeadline,
        expired: !!expired,
        expiredAt: expired && expired.at,
        expiredCleared: !!expired && expired.count === 0,
        stateBeforeStop,
        abortObserved,
        calls,
        stopped: scheduler.running === false,
        badState: badStatus.state,
        badError: badStatus.requalificationError,
        badInstalled: badPublications.some(entry => entry.count > 0)
      }
    })
    ok(browserScheduler.installedDeadline === browserScheduler.signedDeadline &&
      browserScheduler.installedDeadline < browserScheduler.healthDeadline,
    'Chromium ESM installs only to the earlier signed-epoch deadline')
    ok(browserScheduler.expired && browserScheduler.expiredCleared &&
      browserScheduler.expiredAt >= browserScheduler.signedDeadline &&
      browserScheduler.stateBeforeStop === 'qualification-expired' &&
      browserScheduler.abortObserved && browserScheduler.calls === 2 && browserScheduler.stopped,
    'Chromium timers revoke exactly during an in-flight refresh and stop aborts its controller')
    ok(browserScheduler.badState === 'requalification-error-no-fresh-relay' &&
      browserScheduler.badError === 'PEERIT_REQUALIFICATION_BAD_RESULT' &&
      browserScheduler.badInstalled === false,
    'Chromium rejects status-spoofed qualifier output before target publication')

    await deleteDatabase(first, CAPABILITY_DB)
    await deleteDatabase(first, DESCRIPTOR_DB)

    const capabilityResults = await Promise.all([first, second].map((page, index) => page.evaluate(async marker => {
      const moduleUrl = `${globalThis.location.origin}/js/substrate/capability-vault.js`
      const { createPeeritCapabilityVault } = await import(moduleUrl)
      const vault = createPeeritCapabilityVault({
        indexedDB: globalThis.indexedDB,
        crypto: globalThis.crypto
      })
      globalThis.__peeritCapabilityVault = vault
      const packet = {
        intentId: 'browser-intent',
        logicalId: 'browser-logical',
        targetId: 'cell-v1:browser-relay:browser-store',
        targetContext: {
          relayPublicKey: new Uint8Array(32).fill(0x11),
          storeId: new Uint8Array(32).fill(0x22),
          endpointId: 1,
          descriptorSequence: 1n
        },
        prepared: {
          requestBytes: new Uint8Array([0x42, 0x52, 0x4f, 0x57, 0x53, 0x45, 0x52, marker]),
          requestCommitment: new Uint8Array(32).fill(0x30 + marker),
          readCap: { cellKey: new Uint8Array(32).fill(0x40 + marker) },
          writeCap: {
            createPrivateKey: new Uint8Array(32).fill(0x50 + marker),
            renewPrivateKey: new Uint8Array(32).fill(0x60 + marker),
            dropPrivateKey: new Uint8Array(32).fill(0x70 + marker)
          }
        }
      }
      globalThis.__peeritCapabilityPacket = packet
      try {
        const result = await vault.persistPreparedReplica(packet)
        return { won: true, marker, evidenceRef: result.evidenceRef }
      } catch (error) {
        return { won: false, marker, error: String((error && error.message) || error) }
      }
    }, index + 1)))
    const winners = capabilityResults.filter(value => value.won)
    ok(winners.length === 1,
      'real IndexedDB admits exactly one conflicting cross-tab capability preparation')
    const winnerIndex = capabilityResults.findIndex(value => value.won)
    const winnerPage = winnerIndex === 0 ? first : second
    const verified = await winnerPage.evaluate(async () => {
      const packet = globalThis.__peeritCapabilityPacket
      return globalThis.__peeritCapabilityVault.persistVerifiedResult({
        ...packet,
        resultBytes: new Uint8Array([9, 8, 7, 6]),
        readCapability: packet.prepared.readCap
      })
    })
    ok(verified.stage === 'verified' && verified.revision === 2,
      'verified acknowledgement state commits after its prepared secrets')

    const reloadedCapability = await second.evaluate(async () => {
      const moduleUrl = `${globalThis.location.origin}/js/substrate/capability-vault.js`
      const { createPeeritCapabilityVault } = await import(moduleUrl)
      return createPeeritCapabilityVault({
        indexedDB: globalThis.indexedDB,
        crypto: globalThis.crypto
      })
        .load('browser-intent', 'cell-v1:browser-relay:browser-store')
    })
    ok(reloadedCapability && reloadedCapability.stage === 'verified' &&
      reloadedCapability.payload.resultBytes.join(',') === '9,8,7,6',
    'a new browser instance reloads the exact verified result and read capability')

    const capabilityAudit = await rawRecordAudit(first, CAPABILITY_DB,
      ['browser-intent', 'browser-logical', 'browser-relay'])
    ok(capabilityAudit.count === 1 && capabilityAudit.nonextractable &&
      capabilityAudit.clearMatches.length === 0,
    'browser storage uses a non-extractable key and exposes no clear intent, logical, or relay identity')

    const rootHex = 'a1'.repeat(32)
    const storeHex = 'b2'.repeat(32)
    const descriptorKey = `descriptor:${rootHex}:${storeHex}`
    const descriptorResults = await Promise.all([first, second].map((page, index) => page.evaluate(async ({
      index, descriptorKey
    }) => {
      const moduleUrl = `${globalThis.location.origin}/js/substrate/descriptor-trust-backend.js`
      const { createPeeritDescriptorTrustBackend } = await import(moduleUrl)
      const backend = createPeeritDescriptorTrustBackend({
        indexedDB: globalThis.indexedDB,
        crypto: globalThis.crypto
      })
      globalThis.__peeritDescriptorBackend = backend
      const descriptor = new TextEncoder().encode(`browser-signed-descriptor-${index}`)
      const state = {
        rootRelayPublicKey: new Uint8Array(32).fill(0xa1),
        storeId: new Uint8Array(32).fill(0xb2),
        currentBytes: descriptor,
        currentHash: new Uint8Array(32).fill(0xc0 + index),
        sequence: 0n,
        identitySequence: 0n,
        relayPublicKey: new Uint8Array(32).fill(0xd0 + index),
        durabilityProfileId: 1,
        durabilityContinuityHash: new Uint8Array(32).fill(0xe0 + index),
        history: [descriptor],
        quarantined: false
      }
      return backend.compareAndSwap(descriptorKey, 0, state)
    }, { index: index + 1, descriptorKey })))
    ok(descriptorResults.filter(Boolean).length === 1,
      'real IndexedDB descriptor TOFU compare-and-swap has exactly one cross-tab winner')

    const quarantined = await first.evaluate(async descriptorKey => {
      const backend = globalThis.__peeritDescriptorBackend
      const current = await backend.read(descriptorKey)
      const nextBytes = new TextEncoder().encode('browser-signed-descriptor-quarantined')
      const next = {
        ...current.value,
        currentBytes: nextBytes,
        currentHash: new Uint8Array(32).fill(0xf1),
        sequence: 1n,
        identitySequence: 1n,
        relayPublicKey: new Uint8Array(32).fill(0xf2),
        history: [...current.value.history, nextBytes],
        quarantined: true
      }
      const swapped = await backend.compareAndSwap(descriptorKey, current.version, next)
      const reloaded = await backend.read(descriptorKey)
      return { swapped, version: reloaded.version, quarantined: reloaded.value.quarantined }
    }, descriptorKey)
    ok(quarantined.swapped && quarantined.version === 2 && quarantined.quarantined,
      'descriptor continuity and quarantine atomically survive a real browser update')

    const descriptorAudit = await rawRecordAudit(first, DESCRIPTOR_DB,
      [rootHex, storeHex, 'browser-signed-descriptor'])
    ok(descriptorAudit.count === 1 && descriptorAudit.nonextractable &&
      descriptorAudit.clearMatches.length === 0,
    'descriptor continuity uses a non-extractable key with no clear root, store, or descriptor bytes')

    await first.evaluate(async ({ capabilityDb, descriptorDb }) => {
      async function tamper (name) {
        return new Promise((resolve, reject) => {
          const request = globalThis.indexedDB.open(name, 1)
          request.onerror = () => reject(request.error)
          request.onsuccess = () => {
            const db = request.result
            const tx = db.transaction('records', 'readwrite')
            const store = tx.objectStore('records')
            const cursor = store.openCursor()
            cursor.onsuccess = () => {
              const value = structuredClone(cursor.result.value)
              value.ciphertext[0] ^= 0xff
              cursor.result.update(value)
            }
            cursor.onerror = () => reject(cursor.error)
            tx.oncomplete = () => { db.close(); resolve() }
            tx.onerror = () => reject(tx.error)
          }
        })
      }
      await tamper(capabilityDb)
      await tamper(descriptorDb)
    }, { capabilityDb: CAPABILITY_DB, descriptorDb: DESCRIPTOR_DB })
    const tamperCodes = await first.evaluate(async descriptorKey => {
      const output = []
      try {
        await globalThis.__peeritCapabilityVault.load(
          'browser-intent', 'cell-v1:browser-relay:browser-store')
      } catch (error) { output.push(String((error && error.message) || error)) }
      try { await globalThis.__peeritDescriptorBackend.read(descriptorKey) } catch (error) { output.push(error.code) }
      return output
    }, descriptorKey)
    ok(tamperCodes.length === 2 && /authentication failed/.test(tamperCodes[0]) &&
      tamperCodes[1] === 'PEERIT_DESCRIPTOR_TRUST_CORRUPT',
    'ciphertext tampering fails closed in both real-browser stores')

    await deleteDatabase(first, CAPABILITY_DB)
    await deleteDatabase(first, DESCRIPTOR_DB)
    await context.close()
    console.log(`\n✅ all ${passed} real-browser substrate state checks passed`)
  } finally {
    await browser.close()
    await stopServer(child)
  }
}

main().catch(error => {
  console.error('\n❌ browser Peerit substrate state gate failed:', error)
  process.exitCode = 1
})
