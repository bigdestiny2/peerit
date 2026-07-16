#!/usr/bin/env node

// Chromium product gate for the local-only Peerit + HiveRelay blind-cell
// stand-up. This exercises the ordinary UI and real product proof-of-work; it
// does not inject a reduced PoW policy, a fake relay adapter, or a test data API.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { dirname, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { startLocalBlindBrowserStandup } from './local-blind-browser-standup.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HIVE_RELAY_ROOT = resolve(process.env.HIVERELAY_BLIND_ROOT || resolve(ROOT, '..', 'hiverelay-blind'))
const ACTION_TIMEOUT_MS = 180_000
const COMMUNITY = 'blindgate'
const POST_TITLE = 'Blind cell recovery survives a relay restart'
const POST_BODY = 'This exact signed post is committed locally before its intentionally lost relay response is reconciled.'
const COMMENT_BODY = 'The same durable writer adopted this comment after reload.'

function hex (value) {
  return Buffer.from(value).toString('hex')
}

function descriptorKeyFor (standup) {
  const candidate = standup.metadata.qualification.candidate
  const canonical = `descriptor:${hex(candidate.continuityRootRelayPublicKey)}:${hex(candidate.storeId)}`
  const digest = createHash('sha256').update(JSON.stringify([
    'peerit.substrate-descriptor-trust.v1',
    canonical
  ])).digest('hex')
  return `descriptor-trust:v1:${digest}`
}

function watchPage (page, label, browserErrors) {
  page.on('pageerror', error => {
    browserErrors.push({ source: `${label}:page`, message: error.stack || error.message, url: null })
  })
  page.on('console', message => {
    if (message.type() !== 'error') return
    const location = message.location()
    browserErrors.push({
      source: `${label}:console`,
      message: message.text(),
      url: location && location.url ? location.url : null
    })
  })
}

async function runtimeSnapshot (page) {
  return page.evaluate(async () => {
    const api = globalThis.__peeritLocalBlindStandup
    if (!api) return null
    const [product, evidence] = await Promise.all([
      api.productStatus(),
      api.fixtureEvidence()
    ])
    const publication = product && product.sync && product.sync.publication
    const relay = publication && publication.relay
    const durability = publication && publication.durability
    return {
      phase: api.phase,
      error: api.error,
      runId: api.config && api.config.runId,
      localNetworkStateReset: api.config && api.config.localNetworkStateReset,
      qualificationState: api.qualification && api.qualification.state,
      qualifiedRelayCount: api.qualification && api.qualification.qualifiedRelayCount,
      lurker: product && product.lurker,
      writer: product && product.identity && product.identity.pubkey,
      authoringReady: product && product.publication && product.publication.authoringReady,
      localState: product && product.publication && product.publication.localState,
      relayState: relay && relay.state,
      pendingIntents: relay && relay.pendingIntents,
      acknowledgedTargets: relay && relay.acknowledgedTargets,
      durabilityState: durability && durability.state,
      readbackVerified: durability && durability.readbackVerified,
      historicalReadbackVerified: durability && durability.historicalReadbackVerified,
      repairNeeded: durability && durability.repairNeeded,
      revalidationPending: durability && durability.revalidationPending,
      intentCount: publication && publication.intentCount,
      viewLength: product && product.sync && product.sync.viewLength,
      evidence: {
        cellRecords: evidence.cellRecords,
        droppedCellPutResponses: evidence.droppedCellPutResponses,
        proxyCellRequests: evidence.proxyCellRequests,
        proxyCellPutRequests: evidence.proxyCellPutRequests,
        proxyCellGetRequests: evidence.proxyCellGetRequests,
        relayRestarts: evidence.relayRestarts,
        relayErrors: evidence.relayErrors
      }
    }
  })
}

async function waitForReady (page) {
  await page.waitForFunction(() => {
    const api = globalThis.__peeritLocalBlindStandup
    return document.documentElement.getAttribute('data-peerit-local-blind-state') === 'ready' &&
      api && api.phase === 'ready'
  }, null, { timeout: ACTION_TIMEOUT_MS })
  const snapshot = await runtimeSnapshot(page)
  assert.ok(snapshot, 'local blind runtime API must be installed')
  assert.equal(snapshot.phase, 'ready')
  assert.equal(snapshot.error, null)
  assert.equal(snapshot.qualificationState, 'qualified')
  assert.equal(snapshot.qualifiedRelayCount, 1)
  assert.equal(snapshot.authoringReady, true)
  assert.equal(snapshot.localState, 'ready')
  assert.equal(await page.locator('[data-status] .substrate-status').getAttribute('data-local-ready'), 'true')
  return snapshot
}

function publicationMatches (snapshot, expected) {
  return snapshot && snapshot.phase === 'ready' &&
    snapshot.evidence.cellRecords === expected.cells &&
    snapshot.evidence.droppedCellPutResponses === expected.drops &&
    snapshot.evidence.proxyCellRequests === expected.cellRequests &&
    snapshot.evidence.proxyCellPutRequests === expected.cellPuts &&
    snapshot.evidence.proxyCellGetRequests === expected.cellGets &&
    snapshot.evidence.relayRestarts === expected.restarts &&
    snapshot.intentCount === expected.intents &&
    snapshot.pendingIntents === 0 &&
    snapshot.relayState === 'relay-acknowledged' &&
    snapshot.durabilityState === 'recently-retrievable' &&
    snapshot.readbackVerified === expected.readbacks
}

async function flushUntilPublished (page, expected) {
  const deadline = Date.now() + ACTION_TIMEOUT_MS
  let last = null
  while (Date.now() < deadline) {
    await page.evaluate(async () => {
      const api = globalThis.__peeritLocalBlindStandup
      if (api) await api.flush()
    })
    last = await runtimeSnapshot(page)
    if (publicationMatches(last, expected)) return last
    await sleep(100)
  }
  assert.fail(`publication did not reach authenticated readback: ${JSON.stringify(last)}`)
}

async function assertAcknowledgedUi (page) {
  await page.waitForFunction(() => {
    const relay = document.querySelector('.substrate-axis.axis-1')
    const durability = document.querySelector('.substrate-axis.axis-2')
    return relay && relay.textContent === 'relay relay-acknowledged' &&
      durability && durability.textContent === 'durability recently-retrievable'
  }, null, { timeout: ACTION_TIMEOUT_MS })
  const status = await page.locator('[data-status]').innerText()
  assert.match(status, /Saved locally; [0-9]+ compatible relay/)
  assert.match(status, /relay relay-acknowledged/)
  assert.match(status, /durability recently-retrievable/)
}

async function beginDigestObservation (page) {
  await page.evaluate(() => {
    if (globalThis.__peeritDigestObservation) return
    const subtle = globalThis.crypto && globalThis.crypto.subtle
    if (!subtle || typeof subtle.digest !== 'function') return
    const digest = subtle.digest.bind(subtle)
    const observation = { calls: 0 }
    Object.defineProperty(globalThis, '__peeritDigestObservation', {
      configurable: false,
      enumerable: false,
      writable: false,
      value: observation
    })
    subtle.digest = async (...args) => {
      observation.calls++
      return digest(...args)
    }
  })
}

async function mutationDiagnostic (page) {
  return page.evaluate(async () => {
    const api = globalThis.__peeritLocalBlindStandup
    const [product, evidence] = api
      ? await Promise.all([api.productStatus(), api.fixtureEvidence()])
      : [null, null]
    const publication = product && product.sync && product.sync.publication
    return {
      url: globalThis.location.href,
      phase: api && api.phase,
      digestCalls: globalThis.__peeritDigestObservation && globalThis.__peeritDigestObservation.calls,
      toast: document.querySelector('[data-toast]:not([hidden])')?.textContent || null,
      submitDisabled: document.querySelector('form button[type="submit"]')?.disabled ?? null,
      relayState: publication && publication.relay && publication.relay.state,
      pendingIntents: publication && publication.relay && publication.relay.pendingIntents,
      durabilityState: publication && publication.durability && publication.durability.state,
      readbackVerified: publication && publication.durability && publication.durability.readbackVerified,
      cellRecords: evidence && evidence.cellRecords,
      droppedCellPutResponses: evidence && evidence.droppedCellPutResponses,
      appText: document.querySelector('#app')?.innerText.slice(0, 500) || null
    }
  })
}

async function waitForUiMutation (page, success, label) {
  const toast = page.locator('[data-toast]:not([hidden])')
  const deadline = Date.now() + ACTION_TIMEOUT_MS
  let nextDiagnostic = Date.now() + 60_000
  while (Date.now() < deadline) {
    if (await success.isVisible()) return
    if (await toast.isVisible()) assert.fail(`Peerit UI mutation failed: ${await toast.textContent()}`)
    if (Date.now() >= nextDiagnostic) {
      process.stderr.write(`[browser-peerit-local-blind-standup] waiting for ${label}: ${JSON.stringify(await mutationDiagnostic(page))}\n`)
      nextDiagnostic += 60_000
    }
    await sleep(100)
  }
  assert.fail(`Peerit UI mutation timed out during ${label}: ${JSON.stringify(await mutationDiagnostic(page))}`)
}

async function databaseAudit (page) {
  return page.evaluate(async () => {
    const databaseNames = (await globalThis.indexedDB.databases()).map(entry => entry.name).filter(Boolean).sort()
    const readStore = async (databaseName, storeName) => {
      if (!databaseNames.includes(databaseName)) return { keys: [], values: [] }
      const database = await new Promise((resolve, reject) => {
        const request = globalThis.indexedDB.open(databaseName)
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
        request.onblocked = () => reject(new Error(`${databaseName} open was blocked`))
      })
      try {
        if (!database.objectStoreNames.contains(storeName)) return { keys: [], values: [] }
        return await new Promise((resolve, reject) => {
          const transaction = database.transaction(storeName, 'readonly')
          const store = transaction.objectStore(storeName)
          const keysRequest = store.getAllKeys()
          const valuesRequest = store.getAll()
          transaction.oncomplete = () => resolve({
            keys: keysRequest.result,
            values: valuesRequest.result
          })
          transaction.onabort = () => reject(transaction.error)
          transaction.onerror = () => {}
        })
      } finally {
        database.close()
      }
    }
    const [descriptors, capabilities, identities, view] = await Promise.all([
      readStore('peerit-substrate-descriptor-trust', 'records'),
      readStore('peerit-substrate-capabilities', 'records'),
      readStore('peerit-identity', 'device'),
      readStore('peerit-substrate-journal', 'view')
    ])
    return {
      databaseNames,
      descriptorKeys: descriptors.keys.map(String).sort(),
      descriptors: descriptors.values.map(record => ({
        recordKey: record.recordKey,
        generation: record.generation,
        casVersion: record.casVersion
      })).sort((left, right) => String(left.recordKey).localeCompare(String(right.recordKey))),
      capabilities: capabilities.values.map(record => ({
        recordId: record.recordId,
        revision: record.revision,
        stage: record.stage
      })).sort((left, right) => String(left.recordId).localeCompare(String(right.recordId))),
      identities: identities.values.map(record => ({ pubkey: record.pubkey, recordVersion: record.recordVersion })),
      view: view.values.map(record => ({
        key: record.key,
        semanticType: record.value && record.value._t,
        powBits: record.value && record.value.pow && record.value.pow.bits,
        powVersion: record.value && record.value.pow && record.value.pow.v
      })).sort((left, right) => String(left.key).localeCompare(String(right.key)))
    }
  })
}

function assertRealPow (audit) {
  assert.equal(audit.view.length, 3, 'community, post, and comment must be three local graph records')
  const pow = Object.fromEntries(audit.view.map(record => [record.semanticType, {
    bits: record.powBits,
    version: record.powVersion
  }]))
  assert.deepEqual(pow.community, { bits: 18, version: 2 })
  assert.deepEqual(pow.post, { bits: 16, version: 2 })
  assert.deepEqual(pow.comment, { bits: 14, version: 2 })
  return pow
}

async function createCommunity (page) {
  await page.getByRole('link', { name: 'Create a community', exact: true }).click()
  const form = page.locator('form[data-form="community"]')
  await form.locator('input[name="slug"]').fill(COMMUNITY)
  await form.locator('input[name="title"]').fill('Blind Gate')
  await form.locator('textarea[name="description"]').fill('Real blind-cell browser recovery gate.')
  await form.getByRole('button', { name: 'Create community', exact: true }).click()
  await waitForUiMutation(page, page.getByRole('heading', { name: `r/${COMMUNITY}`, exact: true }), 'community creation')
}

async function createPostWithLostResponse (page) {
  await beginDigestObservation(page)
  const armed = await page.evaluate(() => globalThis.__peeritLocalBlindStandup.armDroppedCellPutResponse())
  assert.deepEqual(armed, { armed: true })
  await page.getByRole('link', { name: 'Create post', exact: true }).first().click()
  const form = page.locator('form[data-form="post"]')
  await form.locator('input[name="title"]').fill(POST_TITLE)
  await form.locator('textarea[name="body"]').fill(POST_BODY)
  await form.getByRole('button', { name: 'Publish locally', exact: true }).click()
  await waitForUiMutation(page, page.locator('.post.full .post-title > a').filter({ hasText: POST_TITLE }), 'post creation')
  assert.equal(await page.locator('.post.full .post-title > a').textContent(), POST_TITLE)
}

async function addComment (page) {
  await beginDigestObservation(page)
  const form = page.locator('form[data-form="comment"]')
  await form.locator('textarea[name="body"]').fill(COMMENT_BODY)
  await form.getByRole('button', { name: 'Comment', exact: true }).click()
  await waitForUiMutation(page, page.locator('.comment .md').filter({ hasText: COMMENT_BODY }), 'comment creation')
}

async function main () {
  const playwright = await import('playwright')
  let appPort = null
  const browserErrors = []
  let browser = null
  let context = null
  let page = null
  let standup = null
  try {
    browser = await playwright.chromium.launch({ headless: true })
    context = await browser.newContext()

    standup = await startLocalBlindBrowserStandup({
      hiveRelayRoot: HIVE_RELAY_ROOT,
      port: 0
    })
    appPort = Number(new URL(standup.url).port)
    assert.ok(Number.isSafeInteger(appPort) && appPort > 0 && appPort <= 65535)
    assert.equal(new URL(standup.url).port, String(appPort))
    const firstRunId = standup.metadata.runId
    const firstDescriptorKey = descriptorKeyFor(standup)
    page = await context.newPage()
    watchPage(page, 'first-fixture', browserErrors)
    await page.goto(standup.url, { waitUntil: 'domcontentloaded' })

    const fresh = await waitForReady(page)
    assert.equal(fresh.runId, firstRunId)
    assert.equal(fresh.localNetworkStateReset, true)
    assert.equal(fresh.lurker, true)
    assert.equal(fresh.writer, null)
    assert.equal(fresh.intentCount, 0)
    assert.equal(fresh.evidence.cellRecords, 0)
    assert.equal(await page.locator('[data-user-label]').textContent(), 'lurking')
    const freshDatabases = (await databaseAudit(page)).databaseNames
    assert.equal(freshDatabases.includes('peerit-identity'), false,
      'lurker boot must not create or inspect the identity database')

    await createCommunity(page)
    const communityPublished = await flushUntilPublished(page, {
      cells: 1,
      drops: 0,
      cellRequests: 2,
      cellPuts: 1,
      cellGets: 1,
      restarts: 0,
      intents: 1,
      readbacks: 1
    })
    await assertAcknowledgedUi(page)
    assert.match(communityPublished.writer, /^[0-9a-f]{64}$/)
    const durableWriter = communityPublished.writer

    await createPostWithLostResponse(page)
    const recoveredPost = await flushUntilPublished(page, {
      cells: 2,
      drops: 1,
      cellRequests: 4,
      cellPuts: 2,
      cellGets: 2,
      restarts: 0,
      intents: 2,
      readbacks: 1
    })
    await assertAcknowledgedUi(page)
    assert.equal(recoveredPost.writer, durableWriter)
    assert.equal(recoveredPost.evidence.relayErrors.length, 1)
    assert.equal(recoveredPost.evidence.relayErrors[0].code, 'ERR_STREAM_DESTROYED')
    const beforeRestartAudit = await databaseAudit(page)
    assert.deepEqual(beforeRestartAudit.capabilities.map(record => record.revision).sort((a, b) => a - b), [2, 3],
      'the ambiguous post reaches stage 3 directly while the ordinary community retains its PUT receipt revision')

    const restarted = await page.evaluate(() => globalThis.__peeritLocalBlindStandup.restartRelay())
    assert.equal(restarted.relayRestarts, 1)
    assert.equal(restarted.cellRecords, 2)
    await page.reload({ waitUntil: 'domcontentloaded' })
    const reloaded = await waitForReady(page)
    assert.equal(reloaded.runId, firstRunId)
    assert.equal(reloaded.localNetworkStateReset, false)
    assert.equal(reloaded.lurker, true,
      'reload remains lazy until a new explicit mutation adopts the durable writer')
    assert.equal(reloaded.writer, null)
    assert.equal(reloaded.evidence.cellRecords, 2)
    assert.equal(reloaded.evidence.proxyCellRequests, 5,
      'reload performs exactly one forced GET and no duplicate PUT')
    assert.equal(reloaded.evidence.proxyCellPutRequests, 2,
      'reload must not issue a duplicate idempotent PUT')
    assert.equal(reloaded.evidence.proxyCellGetRequests, 3,
      'reload must perform exactly one additional forced GET')
    assert.equal(reloaded.durabilityState, 'recently-retrievable')
    assert.equal(reloaded.readbackVerified, 1)
    const afterReloadAudit = await databaseAudit(page)
    assert.deepEqual(afterReloadAudit.capabilities.map(record => record.revision).sort((a, b) => a - b), [3, 3],
      'the latest retained Cell advances one monotonic capability revision after forced GET')
    await page.locator('.post.full .post-title > a').filter({ hasText: POST_TITLE }).waitFor({ timeout: ACTION_TIMEOUT_MS })
    assert.equal(await page.locator('.post.full .post-title > a').textContent(), POST_TITLE)
    assert.equal(await page.locator('.post.full .md').textContent(), POST_BODY)
    assert.equal(await page.locator('.post.full .sub-link').textContent(), `r/${COMMUNITY}`)

    await addComment(page)
    const commentPublished = await flushUntilPublished(page, {
      cells: 3,
      drops: 1,
      cellRequests: 7,
      cellPuts: 3,
      cellGets: 4,
      restarts: 1,
      intents: 3,
      readbacks: 1
    })
    await assertAcknowledgedUi(page)
    assert.equal(commentPublished.writer, durableWriter,
      'the post-reload comment must adopt the original durable writer')
    assert.equal(commentPublished.viewLength, 3)
    assert.equal(commentPublished.evidence.relayErrors.length, 1)

    const firstAudit = await databaseAudit(page)
    assert.deepEqual(firstAudit.descriptorKeys, [firstDescriptorKey])
    assert.equal(firstAudit.descriptors.length, 1)
    assert.equal(firstAudit.descriptors[0].recordKey, firstDescriptorKey)
    assert.equal(firstAudit.capabilities.length, 3)
    assert.ok(firstAudit.capabilities.every(record => record.stage === 3),
      'all first-fixture Cell capabilities must contain authenticated readback')
    assert.deepEqual(firstAudit.identities.map(record => record.pubkey), [durableWriter])
    const realPow = assertRealPow(firstAudit)

    await page.close()
    page = null
    await standup.close()
    standup = null

    standup = await startLocalBlindBrowserStandup({
      hiveRelayRoot: HIVE_RELAY_ROOT,
      port: appPort
    })
    assert.equal(new URL(standup.url).port, String(appPort))
    const secondRunId = standup.metadata.runId
    const secondDescriptorKey = descriptorKeyFor(standup)
    assert.notEqual(secondRunId, firstRunId)
    assert.equal(secondDescriptorKey, firstDescriptorKey,
      'the deterministic fixture deliberately reuses one relay/store authority')
    page = await context.newPage()
    watchPage(page, 'second-fixture', browserErrors)
    await page.goto(standup.url, { waitUntil: 'domcontentloaded' })

    const secondReady = await waitForReady(page)
    assert.equal(secondReady.runId, secondRunId)
    assert.equal(secondReady.localNetworkStateReset, true,
      'a new local fixture run on the same origin must reset relay-scoped state')
    assert.equal(secondReady.qualificationState, 'qualified')
    assert.equal(secondReady.qualifiedRelayCount, 1)
    const secondPostLink = page.locator('.post.card .post-title > a').filter({ hasText: POST_TITLE })
    await secondPostLink.waitFor({ timeout: ACTION_TIMEOUT_MS })
    assert.equal(await secondPostLink.textContent(), POST_TITLE)
    await secondPostLink.click()
    await page.locator('.post.full .post-title > a').filter({ hasText: POST_TITLE }).waitFor({ timeout: ACTION_TIMEOUT_MS })
    assert.equal(await page.locator('.post.full .post-title > a').textContent(), POST_TITLE)
    await page.locator('.comment .md').filter({ hasText: COMMENT_BODY }).waitFor({ timeout: ACTION_TIMEOUT_MS })

    const secondSnapshot = await runtimeSnapshot(page)
    assert.equal(secondSnapshot.intentCount, 3)
    assert.equal(secondSnapshot.evidence.cellRecords, 0)
    assert.equal(secondSnapshot.evidence.proxyCellRequests, 0)
    assert.equal(secondSnapshot.evidence.proxyCellPutRequests, 0)
    assert.equal(secondSnapshot.evidence.proxyCellGetRequests, 0)
    assert.equal(secondSnapshot.relayState, 'repair-needed')
    assert.equal(secondSnapshot.durabilityState, 'repair-needed')
    assert.equal(secondSnapshot.readbackVerified, 0)
    assert.equal(secondSnapshot.historicalReadbackVerified, 1)
    assert.equal(secondSnapshot.repairNeeded, 1)
    const secondAudit = await databaseAudit(page)
    assert.deepEqual(secondAudit.descriptorKeys, [secondDescriptorKey])
    assert.equal(secondAudit.descriptors.length, 1)
    assert.equal(secondAudit.descriptors[0].recordKey, secondDescriptorKey)
    assert.notEqual(secondAudit.descriptors[0].generation, firstAudit.descriptors[0].generation,
      'run-id reset must replace the encrypted descriptor generation')
    assert.equal(secondAudit.capabilities.length, 0,
      'run-id reset must clear, not fork, the prior relay-scoped capabilities')
    assert.deepEqual(secondAudit.identities.map(record => record.pubkey), [durableWriter])
    assert.equal(secondSnapshot.evidence.relayErrors.length, 0)
    const expectedInjectedBrowserErrors = browserErrors.filter(error =>
      error.source === 'first-fixture:console' &&
      error.message === 'Failed to load resource: the server responded with a status of 500 (Internal Server Error)' &&
      typeof error.url === 'string' && error.url.includes('/__fixture/proxy?target='))
    const unexpectedErrors = browserErrors.filter(error => !expectedInjectedBrowserErrors.includes(error))
    assert.equal(expectedInjectedBrowserErrors.length, 1,
      'the severed response must produce exactly one Chromium proxy resource error')
    assert.deepEqual(unexpectedErrors, [], 'browser page and console errors must remain empty')

    process.stdout.write(JSON.stringify({
      schema: 'PeeritHiveRelayLocalBlindBrowserGateV1',
      localTestOnly: true,
      appPort,
      browser: 'chromium',
      hiveRelayCommit: standup.metadata.hiveRelayCommit,
      peeritCommit: standup.metadata.peeritCommit,
      firstRun: {
        runId: firstRunId,
        freshLurker: true,
        qualifiedRelays: 1,
        cells: commentPublished.evidence.cellRecords,
        droppedPutResponses: commentPublished.evidence.droppedCellPutResponses,
        cellRequests: commentPublished.evidence.proxyCellRequests,
        cellPuts: commentPublished.evidence.proxyCellPutRequests,
        cellGets: commentPublished.evidence.proxyCellGetRequests,
        relayRestarts: commentPublished.evidence.relayRestarts,
        writerAdoptedAfterReload: commentPublished.writer === durableWriter,
        capabilityReadbacks: firstAudit.capabilities.length,
        realProductPow: realPow
      },
      secondRun: {
        runId: secondRunId,
        sameOriginPort: true,
        relayStateReset: secondReady.localNetworkStateReset,
        qualifiedRelays: secondReady.qualifiedRelayCount,
        cells: secondSnapshot.evidence.cellRecords,
        cellRequests: secondSnapshot.evidence.proxyCellRequests,
        cellPuts: secondSnapshot.evidence.proxyCellPutRequests,
        cellGets: secondSnapshot.evidence.proxyCellGetRequests,
        relayState: secondSnapshot.relayState,
        durabilityState: secondSnapshot.durabilityState,
        readbackVerified: secondSnapshot.readbackVerified,
        historicalReadbackVerified: secondSnapshot.historicalReadbackVerified,
        repairNeeded: secondSnapshot.repairNeeded,
        descriptorRecords: secondAudit.descriptorKeys.length,
        capabilityReadbacks: secondAudit.capabilities.length,
        descriptorGenerationReplaced: secondAudit.descriptors[0].generation !== firstAudit.descriptors[0].generation,
        priorCapabilitiesCleared: secondAudit.capabilities.length === 0
      },
      expectedInjectedBrowserErrors: expectedInjectedBrowserErrors.length,
      unexpectedBrowserErrors: unexpectedErrors.length
    }, null, 2) + '\n')
  } finally {
    if (page) await page.close().catch(() => {})
    if (standup) await standup.close().catch(() => {})
    if (context) await context.close().catch(() => {})
    if (browser) await browser.close().catch(() => {})
  }
}

main().catch(error => {
  process.stderr.write(`[browser-peerit-local-blind-standup] ${error.stack || error.message}\n`)
  process.exitCode = 1
})
