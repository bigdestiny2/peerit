#!/usr/bin/env node
// Real Chromium gate for Peerit's encrypted pin-history continuity witness.
// The test starts from the checked release-control vectors, verifies Ed25519
// with browser WebCrypto, and exercises the production IndexedDB adapter across
// independent page/module instances.

import { spawn } from 'node:child_process'
import { sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { dirname, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import {
  checkpointSignaturePayload,
  encodePeeritHiveRelayProfilePinV1,
  encodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryCheckpointV1,
  pinHistoryCheckpointHash,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesEqual
} from '../js/substrate/release-control-primitives.mjs'
import { buildReleaseControlFixture } from './release-control-fixture.mjs'

const HOST = '127.0.0.1'
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DB_NAME = 'peerit-pin-history-witness-v1'
const DB_STORE = 'records'
const TIMEOUT_MILLIS = 30_000
const VECTOR_ROOT = resolve(ROOT, 'protocol/vectors/release-control')

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
  const deadline = Date.now() + TIMEOUT_MILLIS
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
  const origin = `http://${HOST}:${port}`
  const url = `${origin}/substrate-state-browser-gate.html`
  try { await waitForHttp(url) } catch (error) {
    child.kill('SIGKILL')
    error.cause = new Error(output)
    throw error
  }
  return { child, origin, url }
}

async function stopServer (child) {
  if (!child || child.killed) return
  child.kill('SIGTERM')
  await Promise.race([
    new Promise(resolve => child.once('exit', resolve)),
    sleep(1500).then(() => child.kill('SIGKILL'))
  ])
}

function fixtureHash (label) {
  return blake2b256(asciiBytes(
    `peerit.pin-history-witness.browser-fixture-only.v1:${label}`))
}

function continuation (fixture, previousPinBytes, previousCheckpointBytes,
  sequence, label) {
  const pin = fixture.signPin({
    ...fixture.pins[1],
    releaseSequence: sequence,
    previousPinHash: profilePinHash(previousPinBytes),
    appArtifactHash: fixtureHash(`app:${label}`),
    webAssetManifestHash: fixtureHash(`web:${label}`),
    migrationTransitionEvidenceHash: null,
    authorityTransitionHash: null,
    signature: undefined
  })
  const pinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  const checkpoint = {
    version: 1,
    checkpointSequence: sequence,
    previousCheckpointHash: pinHistoryCheckpointHash(previousCheckpointBytes),
    pinHash: profilePinHash(pinBytes),
    previousPinHash: pin.previousPinHash,
    issuedUnixMillis: 1700000000000n + sequence * 1000n,
    releaseAuthoritySequence: pin.releaseAuthoritySequence,
    releaseAuthorityKeyId: pin.releaseAuthorityKeyId,
    signature: undefined
  }
  checkpoint.signature = new Uint8Array(sign(
    null, Buffer.from(checkpointSignaturePayload(checkpoint)),
    fixture.releasePrivateKey))
  const checkpointBytes = encodePeeritPinHistoryCheckpointV1(checkpoint)
  return { pinBytes, checkpointBytes }
}

function array (value) {
  return [...value]
}

async function checkedBrowserFixture () {
  const fixture = buildReleaseControlFixture()
  const names = [
    ['profile-pin-sequence-0.bin', fixture.pinBytes[0]],
    ['profile-pin-sequence-1.bin', fixture.pinBytes[1]],
    ['checkpoint-sequence-0.bin', fixture.checkpointBytes[0]],
    ['checkpoint-sequence-1.bin', fixture.checkpointBytes[1]],
    ['pin-history-bundle.bin', fixture.bundleBytes],
    ['fixture-release-public-key.bin', fixture.releasePublicKey]
  ]
  const checked = Object.create(null)
  for (const [name, expected] of names) {
    const value = new Uint8Array(await readFile(resolve(VECTOR_ROOT, name)))
    if (!bytesEqual(value, expected)) {
      throw new Error(`checked release-control vector drift: ${name}`)
    }
    checked[name] = value
  }

  const second = continuation(fixture, checked['profile-pin-sequence-1.bin'],
    checked['checkpoint-sequence-1.bin'], 2n, 'sequence-2')
  const third = continuation(fixture, second.pinBytes,
    second.checkpointBytes, 3n, 'sequence-3')
  const baseBundle = encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [checked['profile-pin-sequence-0.bin']],
    checkpoints: [checked['checkpoint-sequence-0.bin']]
  })
  const continuationBundle = encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [checked['profile-pin-sequence-1.bin'], second.pinBytes],
    checkpoints: [checked['checkpoint-sequence-1.bin'], second.checkpointBytes]
  })
  const aheadBundle = encodePeeritPinHistoryBundleV1({
    version: 1,
    pins: [third.pinBytes],
    checkpoints: [third.checkpointBytes]
  })
  return {
    releasePublicKey: array(checked['fixture-release-public-key.bin']),
    checkedFullBundle: array(checked['pin-history-bundle.bin']),
    baseBundle: array(baseBundle),
    continuationBundle: array(continuationBundle),
    aheadBundle: array(aheadBundle)
  }
}

async function deleteDatabase (page) {
  await page.evaluate(({ dbName }) => new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.deleteDatabase(dbName)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => reject(new Error(`delete blocked for ${dbName}`))
  }), { dbName: DB_NAME })
}

async function setupPage (page, origin, fixture) {
  return page.evaluate(async ({ origin, fixture }) => {
    const backendModule = await import(
      `${origin}/js/substrate/pin-history-witness-backend.mjs`)
    const codec = await import(
      `${origin}/js/substrate/release-control-codec.mjs`)
    const verifier = await import(
      `${origin}/js/substrate/release-control-verifier.mjs`)
    const trustedPublicKey = Uint8Array.from(fixture.releasePublicKey)
    const importedPublicKey = await crypto.subtle.importKey(
      'raw', trustedPublicKey, { name: 'Ed25519' }, false, ['verify'])
    const sameBytes = (left, right) => left.byteLength === right.byteLength &&
      left.every((value, index) => value === right[index])
    let webCryptoVerifications = 0
    const verifierCrypto = Object.freeze({
      async verifyEd25519 (publicKey, message, signature) {
        if (!sameBytes(publicKey, trustedPublicKey)) return false
        webCryptoVerifications++
        return crypto.subtle.verify(
          { name: 'Ed25519' }, importedPublicKey, signature, message)
      }
    })
    const checkedFullBundle = Uint8Array.from(fixture.checkedFullBundle)
    const decodedFull = codec.decodePeeritPinHistoryBundleV1(checkedFullBundle)
    const expectedPins = decodedFull.pins.map(pinBytes =>
      verifier.canonicalExpectedPinProjection(
        codec.decodePeeritHiveRelayProfilePinV1(pinBytes)))
    if (!expectedPins.every(value =>
      sameBytes(value.releaseAuthorityPublicKey, trustedPublicKey))) {
      throw new Error('checked pins do not bind the checked fixture authority')
    }
    const base = await verifier.verifyPeeritPinHistoryBundleV1(
      Uint8Array.from(fixture.baseBundle), {
        crypto: verifierCrypto,
        expectedPins: [expectedPins[0]]
      })
    const middle = await verifier.verifyPeeritPinHistoryBundleV1(
      checkedFullBundle, { crypto: verifierCrypto, expectedPins })
    const continuationBytes = Uint8Array.from(fixture.continuationBundle)
    const terminal = await verifier.verifyPeeritPinHistoryContinuationV1(
      continuationBytes, {
        crypto: verifierCrypto,
        anchor: base,
        authorityTransitions: []
      })
    const ahead = await verifier.verifyPeeritPinHistoryContinuationV1(
      Uint8Array.from(fixture.aheadBundle), {
        crypto: verifierCrypto,
        anchor: terminal,
        authorityTransitions: []
      })
    const scope = backendModule.peeritPinHistoryProfileScopeV1()
    const backend = backendModule.createPeeritPinHistoryWitnessBackend({
      indexedDB: globalThis.indexedDB,
      crypto,
      verifierCrypto
    })
    globalThis.__peeritPinHistoryBrowser = {
      ahead,
      backend,
      backendModule,
      base,
      continuationBytes,
      middle,
      scope,
      terminal,
      verifier,
      verifierCrypto
    }
    return {
      baseSequence: base.terminalSequence.toString(),
      middleSequence: middle.terminalSequence.toString(),
      terminalSequence: terminal.terminalSequence.toString(),
      aheadSequence: ahead.terminalSequence.toString(),
      webCryptoVerifications
    }
  }, { origin, fixture })
}

async function readRawRecord (page, saveAs = null) {
  return page.evaluate(async ({ dbName, dbStore, saveAs }) => {
    const record = await new Promise((resolve, reject) => {
      const request = globalThis.indexedDB.open(dbName, 1)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        const db = request.result
        const tx = db.transaction(dbStore, 'readonly')
        const cursor = tx.objectStore(dbStore).openCursor()
        cursor.onerror = () => reject(cursor.error)
        cursor.onsuccess = () => resolve(cursor.result && {
          key: cursor.result.key,
          value: cursor.result.value
        })
        tx.oncomplete = () => db.close()
      }
    })
    if (!record) throw new Error('pin-history witness record is missing')
    if (saveAs) globalThis[saveAs] = structuredClone(record)
    let exportRejected = false
    try { await crypto.subtle.exportKey('raw', record.value.wrapKey) } catch {
      exportRejected = true
    }
    return {
      casVersion: record.value.casVersion,
      cryptoKey: record.value.wrapKey instanceof CryptoKey,
      extractable: record.value.wrapKey.extractable,
      exportRejected,
      generation: record.value.generation,
      key: record.key,
      recordKey: record.value.recordKey
    }
  }, { dbName: DB_NAME, dbStore: DB_STORE, saveAs })
}

async function writeSavedRecord (page, savedAs) {
  await page.evaluate(({ dbName, dbStore, savedAs }) => new Promise(
    (resolve, reject) => {
      const saved = globalThis[savedAs]
      if (!saved) return reject(new Error(`saved record ${savedAs} is missing`))
      const request = globalThis.indexedDB.open(dbName, 1)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        const db = request.result
        const tx = db.transaction(dbStore, 'readwrite')
        tx.objectStore(dbStore).put(structuredClone(saved.value), saved.key)
        tx.oncomplete = () => { db.close(); resolve() }
        tx.onabort = () => reject(tx.error)
      }
    }), { dbName: DB_NAME, dbStore: DB_STORE, savedAs })
}

async function createEmptyDatabase (page) {
  await page.evaluate(({ dbName, dbStore }) => new Promise(
    (resolve, reject) => {
      const request = globalThis.indexedDB.open(dbName, 1)
      request.onupgradeneeded = () => request.result.createObjectStore(dbStore)
      request.onerror = () => reject(request.error)
      request.onsuccess = () => { request.result.close(); resolve() }
    }), { dbName: DB_NAME, dbStore: DB_STORE })
}

async function main () {
  const fixture = await checkedBrowserFixture()
  const playwright = await import('playwright')
  const { child, origin, url } = await startServer()
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
    await deleteDatabase(first)

    const firstSetup = await setupPage(first, origin, fixture)
    const secondSetup = await setupPage(second, origin, fixture)
    ok(firstSetup.baseSequence === '0' && firstSetup.middleSequence === '1' &&
      firstSetup.terminalSequence === '2' && firstSetup.aheadSequence === '3' &&
      firstSetup.webCryptoVerifications >= 8 &&
      secondSetup.webCryptoVerifications >= 8,
    'checked vectors produce page-local brands through browser WebCrypto Ed25519')

    const fresh = await first.evaluate(async ({ dbName }) => {
      if (typeof globalThis.indexedDB.databases !== 'function') {
        throw new Error('Chromium indexedDB.databases() is unavailable')
      }
      const before = (await globalThis.indexedDB.databases())
        .some(entry => entry && entry.name === dbName)
      const state = globalThis.__peeritPinHistoryBrowser
      const read = await state.backend.read(state.scope)
      const after = (await globalThis.indexedDB.databases())
        .some(entry => entry && entry.name === dbName)
      return { before, after, version: read.version, value: read.value }
    }, { dbName: DB_NAME })
    ok(!fresh.before && !fresh.after && fresh.version === 0 && fresh.value == null,
      'fresh lurker read does not create IndexedDB when enumeration is available')

    const initialized = await first.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      const inserted = await state.backend.initialize(
        state.scope, 0, state.base)
      const exists = (await globalThis.indexedDB.databases()).some(entry =>
        entry && entry.name === 'peerit-pin-history-witness-v1')
      const read = await state.backend.read(state.scope)
      const staleObserver = state.backendModule
        .createPeeritPinHistoryWitnessBackend({
          indexedDB: globalThis.indexedDB,
          crypto,
          verifierCrypto: state.verifierCrypto
        })
      await staleObserver.read(state.scope)
      state.staleObserver = staleObserver
      return {
        inserted,
        exists,
        version: read.version,
        base: read.value.baseSequence.toString(),
        terminal: read.value.terminalSequence.toString()
      }
    })
    ok(initialized.inserted && initialized.exists && initialized.version === 1 &&
      initialized.base === '0' && initialized.terminal === '0',
    'initialize immediately commits the authenticated base floor')

    const firstRaw = await readRawRecord(first, '__peeritPinHistoryV1')
    const secondRaw = await readRawRecord(second)
    ok(firstRaw.casVersion === 1 && firstRaw.cryptoKey && secondRaw.cryptoKey &&
      firstRaw.extractable === false && firstRaw.exportRejected &&
      secondRaw.extractable === false && secondRaw.exportRejected &&
      firstRaw.key === firstRaw.recordKey,
    'AES-GCM CryptoKey structured-clones across pages and remains non-extractable')

    const reloadedBase = await second.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      const read = await state.backend.read(state.scope)
      const rehydrated = await state.backend.rehydrate(
        state.scope, state.base, state.verifierCrypto)
      const snapshot = state.verifier
        .getVerifiedPinHistoryTerminalSnapshotV1(rehydrated)
      return {
        version: read.version,
        base: read.value.baseSequence.toString(),
        terminal: snapshot.terminalSequence.toString(),
        exact: rehydrated === state.base
      }
    })
    ok(reloadedBase.version === 1 && reloadedBase.base === '0' &&
      reloadedBase.terminal === '0' && reloadedBase.exact,
    'a new page decrypts the record and rehydrates the exact branded base floor')

    const race = await Promise.all([first, second].map(page => page.evaluate(
      async () => {
        const state = globalThis.__peeritPinHistoryBrowser
        return state.backend.append(state.scope, 1, {
          anchor: state.base,
          authorityTransitions: [],
          completeBundle: state.continuationBytes,
          verifiedResult: state.terminal
        })
      })))
    ok(race.filter(Boolean).length === 1,
      'two independent pages racing one IndexedDB CAS have exactly one winner')

    const latest = await readRawRecord(first, '__peeritPinHistoryV2')
    ok(latest.casVersion === 2,
      'the CAS race advances exactly one durable generation')

    // Re-encrypt the valid version-two plaintext under the original version-one
    // header. The stale backend has observed version one only. This catches a
    // same-CAS terminal substitution even when generation and AEAD are valid.
    const sameCasCode = await first.evaluate(async ({ dbName, dbStore }) => {
      const state = globalThis.__peeritPinHistoryBrowser
      const old = globalThis.__peeritPinHistoryV1
      const latest = globalThis.__peeritPinHistoryV2
      const aad = record => new TextEncoder().encode(JSON.stringify([
        'peerit.pin-history-witness-record.v1',
        record.recordKey,
        record.generation,
        record.casVersion
      ]))
      const clear = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: latest.value.iv,
        additionalData: aad(latest.value),
        tagLength: 128
      }, latest.value.wrapKey, latest.value.ciphertext)
      const forged = structuredClone(old.value)
      forged.iv = crypto.getRandomValues(new Uint8Array(12))
      forged.ciphertext = new Uint8Array(await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv: forged.iv,
        additionalData: aad(forged),
        tagLength: 128
      }, forged.wrapKey, clear))
      await new Promise((resolve, reject) => {
        const request = globalThis.indexedDB.open(dbName, 1)
        request.onerror = () => reject(request.error)
        request.onsuccess = () => {
          const db = request.result
          const tx = db.transaction(dbStore, 'readwrite')
          tx.objectStore(dbStore).put(forged, old.key)
          tx.oncomplete = () => { db.close(); resolve() }
          tx.onabort = () => reject(tx.error)
        }
      })
      try {
        await state.staleObserver.read(state.scope)
        return null
      } catch (error) { return error.code }
    }, { dbName: DB_NAME, dbStore: DB_STORE })
    ok(sameCasCode === 'PEERIT_PIN_HISTORY_WITNESS_ROLLBACK',
      'a valid-AEAD terminal substitution at the same CAS version fails closed')
    await writeSavedRecord(first, '__peeritPinHistoryV2')

    const third = await context.newPage()
    await third.goto(url)
    await setupPage(third, origin, fixture)
    const rehydrated = await third.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      const read = await state.backend.read(state.scope)
      const exact = await state.backend.rehydrate(
        state.scope, state.base, state.verifierCrypto)
      const exactSnapshot = state.verifier
        .getVerifiedPinHistoryTerminalSnapshotV1(exact)
      const terminal = await state.backend.rehydrate(
        state.scope, state.terminal, state.verifierCrypto)
      return {
        version: read.version,
        segments: read.value.segmentCount,
        terminalSequence: exactSnapshot.terminalSequence.toString(),
        terminalIdentity: terminal === state.terminal
      }
    })
    ok(rehydrated.version === 2 && rehydrated.segments === 1 &&
      rehydrated.terminalSequence === '2' && rehydrated.terminalIdentity,
    'a fresh page replays exact persisted bytes to the witnessed terminal floor')

    const baseErrors = await third.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      const code = async value => {
        try {
          await state.backend.rehydrate(
            state.scope, value, state.verifierCrypto)
          return null
        } catch (error) { return error.code }
      }
      return {
        inside: await code(state.middle),
        ahead: await code(state.ahead)
      }
    })
    ok(baseErrors.inside === 'PEERIT_PIN_HISTORY_WITNESS_BASE_FORK' &&
      baseErrors.ahead === 'PEERIT_PIN_HISTORY_WITNESS_BASE_AHEAD',
    'inside-segment and newer-than-witness app bases have distinct fail-closed outcomes')

    const compacted = await third.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      const swapped = await state.backend.compact(state.scope, 2, {
        authenticatedBase: state.terminal
      })
      const read = await state.backend.read(state.scope)
      let older
      try {
        await state.backend.rehydrate(
          state.scope, state.base, state.verifierCrypto)
      } catch (error) { older = error.code }
      const current = await state.backend.rehydrate(
        state.scope, state.terminal, state.verifierCrypto)
      return {
        swapped,
        version: read.version,
        base: read.value.baseSequence.toString(),
        segments: read.value.segmentCount,
        older,
        currentIdentity: current === state.terminal
      }
    })
    ok(compacted.swapped && compacted.version === 3 && compacted.base === '2' &&
      compacted.segments === 0 &&
      compacted.older === 'PEERIT_PIN_HISTORY_WITNESS_BASE_TOO_OLD' &&
      compacted.currentIdentity,
    'authenticated compaction makes older and exact-current app bases explicit')
    await readRawRecord(third, '__peeritPinHistoryLatest')

    const tamperCodes = await third.evaluate(async ({ dbName, dbStore }) => {
      const state = globalThis.__peeritPinHistoryBrowser
      const saved = globalThis.__peeritPinHistoryLatest
      const replace = value => new Promise((resolve, reject) => {
        const request = globalThis.indexedDB.open(dbName, 1)
        request.onerror = () => reject(request.error)
        request.onsuccess = () => {
          const db = request.result
          const tx = db.transaction(dbStore, 'readwrite')
          tx.objectStore(dbStore).put(value, saved.key)
          tx.oncomplete = () => { db.close(); resolve() }
          tx.onabort = () => reject(tx.error)
        }
      })
      const code = async mutate => {
        const changed = structuredClone(saved.value)
        mutate(changed)
        await replace(changed)
        let output = null
        try { await state.backend.read(state.scope) } catch (error) {
          output = error.code
        }
        await replace(structuredClone(saved.value))
        await state.backend.read(state.scope)
        return output
      }
      let profile
      try {
        await state.backend.read({
          ...state.scope,
          profileScopeHash: new Uint8Array(32).fill(0xa5)
        })
      } catch (error) { profile = error.code }
      return {
        ciphertext: await code(record => { record.ciphertext[0] ^= 0xff }),
        aad: await code(record => { record.generation = 'ab'.repeat(32) }),
        lookup: await code(record => {
          record.recordKey = `pin-history-witness:v1:${'00'.repeat(32)}`
        }),
        profile
      }
    }, { dbName: DB_NAME, dbStore: DB_STORE })
    ok(tamperCodes.ciphertext === 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT' &&
      tamperCodes.aad === 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT' &&
      tamperCodes.lookup === 'PEERIT_PIN_HISTORY_WITNESS_CORRUPT' &&
      tamperCodes.profile === 'PEERIT_PIN_HISTORY_WITNESS_SCOPE_MISMATCH',
    'ciphertext, AAD, lookup-key, and profile substitution all fail closed')

    // The in-process observation catches a valid older record. A fresh process
    // has no portable witness and therefore accepts it; that limitation remains
    // an explicit false status rather than a papered-over claim.
    await writeSavedRecord(first, '__peeritPinHistoryV1')
    const rollback = await third.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      try { await state.backend.read(state.scope); return null } catch (error) {
        return error.code
      }
    })
    const fourth = await context.newPage()
    await fourth.goto(url)
    await setupPage(fourth, origin, fixture)
    const portable = await fourth.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      const read = await state.backend.read(state.scope)
      return {
        version: read.version,
        terminal: read.value.terminalSequence.toString(),
        portableReady: state.backendModule
          .PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS
          .portableExternalRollbackRecoveryReady,
        evictionReady: state.backendModule
          .PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS
          .postEvictionContinuityRecoveryReady
      }
    })
    ok(rollback === 'PEERIT_PIN_HISTORY_WITNESS_ROLLBACK' &&
      portable.version === 1 && portable.terminal === '0' &&
      portable.portableReady === false && portable.evictionReady === false,
    'runtime rollback detection stays true while portable rollback recovery stays false')
    await writeSavedRecord(third, '__peeritPinHistoryLatest')
    await third.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      await state.backend.read(state.scope)
    })

    await deleteDatabase(first)
    const deleted = await third.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      try { await state.backend.read(state.scope); return null } catch (error) {
        return error.code
      }
    })
    const fifth = await context.newPage()
    await fifth.goto(url)
    await setupPage(fifth, origin, fixture)
    const afterEviction = await fifth.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      return state.backend.read(state.scope)
    })
    await createEmptyDatabase(first)
    const reset = await third.evaluate(async () => {
      const state = globalThis.__peeritPinHistoryBrowser
      try { await state.backend.read(state.scope); return null } catch (error) {
        return error.code
      }
    })
    ok(deleted === 'PEERIT_PIN_HISTORY_WITNESS_SILENT_RESET' &&
      reset === 'PEERIT_PIN_HISTORY_WITNESS_SILENT_RESET' &&
      afterEviction.version === 0 && afterEviction.value == null,
    'observed deletion/reset fail closed while a fresh post-eviction context has no recovery witness')

    await deleteDatabase(first)
    await context.close()
    console.log(`\n✅ all ${passed} real-browser pin-history witness checks passed`)
  } finally {
    await browser.close()
    await stopServer(child)
  }
}

main().catch(error => {
  console.error('\n❌ browser pin-history witness gate failed:', error)
  process.exitCode = 1
})
