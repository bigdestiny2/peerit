// Writer identity race regressions. A record captures one semantic owner before
// any asynchronous PoW/sign work. Switching or importing another identity while
// that work yields must abort before append/appendBatch can see the record.

import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { ready as cryptoReady } from '../js/crypto.js'

const mem = () => {
  const m = new Map()
  return {
    getItem: (key) => m.has(key) ? m.get(key) : null,
    setItem: (key, value) => m.set(key, String(value)),
    removeItem: (key) => m.delete(key)
  }
}

function syncSpy () {
  const calls = []
  return {
    calls,
    async get () { return null },
    async range () { return [] },
    async append (op, writerSession) { calls.push({ method: 'append', ops: [op], writerSession }); return { ok: true } },
    async appendBatch (ops, writerSession) { calls.push({ method: 'appendBatch', ops, writerSession }); return { ok: true } },
    async status () { return { atomicCommit: { available: true, pending: false, recoveryNeeded: false } } }
  }
}

async function twoUserIdentity () {
  const identity = new DevIdentity(mem(), mem(), { lazy: true })
  await identity.ready()
  const a = await identity.createUser('alice')
  const b = await identity.createUser('bob')
  assert.equal(identity.switchUser(a.pubkey), true)
  return { identity, a, b }
}

function stubThreadReads (data) {
  data.getCommunity = async (slug) => ({ slug, creator: 'f'.repeat(64), createdAt: 1 })
  data.overlay = async () => ({ banned: new Set(), locked: new Set(), mods: new Set() })
}

function sharedWriterSession () {
  let tail = Promise.resolve()
  const sessions = []
  const withSession = (fn) => {
    const session = Object.freeze({})
    sessions.push(session)
    const invoke = () => fn(session)
    const run = tail.then(invoke, invoke)
    tail = run.then(() => undefined, () => undefined)
    return run
  }
  withSession.sessions = sessions
  return withSession
}

await cryptoReady()

console.log('\n— identity switch during PoW —')
{
  const sync = syncSpy()
  const { identity, b } = await twoUserIdentity()
  const data = createData(sync, identity, {
    minBits: { post: 1 },
    mint: async () => {
      await Promise.resolve() // the PoW worker yields to UI/user action
      identity.switchUser(b.pubkey)
      return { bits: 1, nonce: 0, targetHash: '0'.repeat(64), v: 2 }
    }
  })
  stubThreadReads(data)
  await assert.rejects(
    data.submitPost({ community: 'race', kind: 'text', title: 'must not land', body: 'owner A' }),
    /identity changed after proof-of-work/i
  )
  assert.equal(sync.calls.length, 0, 'a PoW-yield switch reaches neither append nor appendBatch')
  assert.equal(data.hasWriteInFlight(), false, 'write-intent guard releases after the aborted publication')
}

console.log('— durable import during PoW —')
{
  const sync = syncSpy()
  const { identity } = await twoUserIdentity()
  const imported = new DevIdentity(mem(), mem(), { lazy: true })
  await imported.ready()
  await imported.createUser('imported')
  const importedEntry = imported.currentSeedEntry()
  const data = createData(sync, identity, {
    minBits: { community: 1 },
    mint: async () => {
      await Promise.resolve()
      await identity.restoreFromDurableImport(importedEntry)
      return { bits: 1, nonce: 0, targetHash: '0'.repeat(64), v: 2 }
    }
  })
  data.getCommunity = async () => null
  await assert.rejects(
    data.createCommunity({ slug: 'import_race', title: 'must not land' }),
    /identity changed after proof-of-work/i
  )
  assert.equal(identity.me().pubkey, importedEntry.pubkey, 'the explicit import itself completed')
  assert.equal(sync.calls.length, 0, 'a PoW-yield import reaches neither append nor appendBatch')
}

console.log('— v2 signer switch —')
{
  const sync = syncSpy()
  const { identity, b } = await twoUserIdentity()
  const sign = identity.sign.bind(identity)
  let switched = false
  identity.sign = async (...args) => {
    const signed = await sign(...args)
    if (!switched) {
      switched = true
      identity.switchUser(b.pubkey)
    }
    return signed
  }
  const data = createData(sync, identity, {
    v2: true,
    minBits: { post: 0 },
    mint: async () => ({ bits: 0, nonce: 0, targetHash: '0'.repeat(64), v: 2 })
  })
  stubThreadReads(data)
  await assert.rejects(
    data.submitPost({ community: 'race', kind: 'text', title: 'sealed race', body: 'owner A' }),
    /identity changed after signing/i
  )
  assert.equal(sync.calls.length, 0, 'a v2 record signed while the active identity switches never reaches sync')
}

console.log('— boxed blob/batch owner switch —')
{
  const sync = syncSpy()
  const { identity, b } = await twoUserIdentity()
  let switched = false
  const data = createData(sync, identity, {
    minBits: { blob: 1, post: 1 },
    mint: async (type) => {
      await Promise.resolve()
      if (type === 'blob' && !switched) {
        switched = true
        identity.switchUser(b.pubkey)
      }
      return { bits: 1, nonce: 0, targetHash: '0'.repeat(64), v: 2 }
    }
  })
  stubThreadReads(data)
  await assert.rejects(
    data.submitPost({ community: 'race', kind: 'text', title: 'boxed race', body: 'x'.repeat(3000) }),
    /identity changed after proof-of-work/i
  )
  assert.equal(sync.calls.length, 0, 'neither a staged blob nor its parent batch reaches sync under a different active owner')
}

console.log('— cross-instance writer session ordering —')
{
  const sync = syncSpy()
  const { identity, a, b } = await twoUserIdentity()
  const withWriterSession = sharedWriterSession()
  let releasePow
  let powStartedResolve
  const powStarted = new Promise((resolve) => { powStartedResolve = resolve })
  const powGate = new Promise((resolve) => { releasePow = resolve })
  const order = []
  const data = createData(sync, identity, {
    minBits: { post: 1 },
    withWriterSession,
    mint: async () => {
      order.push('pow-start')
      powStartedResolve()
      await powGate
      order.push('pow-finish')
      return { bits: 1, nonce: 0, targetHash: '0'.repeat(64), v: 2 }
    }
  })
  stubThreadReads(data)

  const publication = data.submitPost({ community: 'race', kind: 'text', title: 'serialized A', body: 'owner A' })
  await powStarted
  let imported = false
  // Models a second tab/instance taking the same peerit:atomic-commit lock for
  // import. It must queue behind Data's full outer intent, not only append().
  const identityMutation = withWriterSession(async () => {
    imported = true
    order.push('import')
    identity.switchUser(b.pubkey)
  })
  await Promise.resolve()
  assert.equal(imported, false, 'a second instance cannot import while the first is in PoW')
  releasePow()
  const post = await publication
  await identityMutation
  assert.equal(post.author, a.pubkey)
  assert.equal(sync.calls.length, 1)
  assert.equal(sync.calls[0].ops[0].data._k, a.pubkey, 'publication commits under its captured owner before identity mutation enters')
  assert.equal(sync.calls[0].writerSession, withWriterSession.sessions[0], 'Data threads only its exact outer writer-session capability into sync.appendBatch')
  assert.deepEqual(order, ['pow-start', 'pow-finish', 'import'])
  assert.equal(identity.me().pubkey, b.pubkey, 'queued identity mutation runs only after publication completes')
}

console.log('— public-web UI and recovery gates —')
{
  const source = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8')
  assert.match(source, /atomic\.available === true && atomic\.pending !== true && atomic\.recoveryNeeded !== true/)
  assert.match(source, /localDevIdentityControlsAllowed\(\) && me\.pubkey/)
  assert.match(source, /if \(!localDevIdentityControlsAllowed\(\)\) throw new Error\('Developer user switching is unavailable on the public web app\.'/)
  assert.match(source, /withIdentityMutationGuard\('import'/)
  assert.match(source, /withIdentityMutationGuard\('forget'/)
  assert.match(source, /withWriterSession: requiresAtomicWebWriter\(\) \? withAtomicDataWriterSession : null/)
  assert.match(source, /sync\.withAtomicWriterSession/)
  assert.match(source, /Previous publication is still being completed/)
  assert.match(source, /Publication recovery is required/)

  const bootStart = source.indexOf('async function boot')
  const transportStart = source.indexOf('// BlindShard dispersal', bootStart)
  const bootIdentity = source.slice(bootStart, transportStart)
  assert.ok(bootStart >= 0 && transportStart > bootStart, 'test isolates the real boot identity section')
  assert.ok(!bootIdentity.includes('await unlockVaultAtBoot'), 'vault-only browse does not open the unlock/delete modal at boot')
  assert.ok(!source.includes('data.migrateLocalGraph('), 'returning browse performs no automatic signed graph migration')
  assert.match(source, /recoverPendingWithIdentity\(appId, async \(\) =>/)
  assert.match(source, /recoveryOnly: true, expectedPubkey: appId/)
  assert.match(source, /error\.code !== 'PEERIT_PENDING_WRITER_LOCK'/)
  assert.match(source, /sync\.withAtomicWriterSession\(async \(writerSession\) =>/)
  assert.match(source, /return fn\(writerSession\)/)
  assert.match(source, /beginIdentityForget\(localStorage/)
  assert.match(source, /expectedToken = beforeDevice\.status === 'corrupt'/)
  assert.match(source, /beforeDevice\.status === 'unavailable'/)
  assert.match(source, /resetCorruptDurableIdentity\(identity, deviceIdStore/)

  const recoveryButton = '<button class="btn btn-primary" type="button" data-act="recover-pending-publication">Recover previous publication</button>'
  assert.ok(source.includes(recoveryButton), 'pending/recovery notice exposes a non-submit recovery control even while the native composer submit is disabled')
  assert.match(source, /writerAvailabilityContent\(status\)/)
  assert.match(source, /case 'recover-pending-publication': return void recoverPendingPublicationFromControl\(t\)/)
  const recoveryControlStart = source.indexOf('async function recoverPendingPublicationFromControl')
  const atomicSessionStart = source.indexOf('async function withAtomicDataWriterSession', recoveryControlStart)
  const recoveryControl = source.slice(recoveryControlStart, atomicSessionStart)
  assert.ok(recoveryControlStart >= 0 && atomicSessionStart > recoveryControlStart, 'test isolates the recovery control handler')
  assert.ok(!recoveryControl.includes('route()'), 'explicit recovery leaves the current form DOM and its draft untouched')
}

console.log('writer-identity-race: all checks passed')
