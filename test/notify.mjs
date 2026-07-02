// notify.mjs — peerit push-notification client core (js/notify.js): capability
// lifecycle + notify-feed-head watch reconciliation + opaque wake handling, driven
// against a FAKE notify backend. Validates the CLIENT LOGIC only (the real HiveRelay
// notify service is reviewed-but-unmerged); this is the "logic-first, wire-later"
// foundation, like blob-disperse / dht-adapter. Run: node test/notify.mjs

import assert from 'node:assert'
import { NotifyClient, reconcileWatches, WATCH_SOURCE_KIND } from '../js/notify.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, m) { try { await fn() } catch { ok(true, m); return } assert.fail('expected throw: ' + m) }

// A fake notify service: records the signed RPCs the adapter would make, mints
// watchIds, and lets a test simulate a wake being delivered to the device.
function fakeBackend () {
  let n = 0
  const calls = { register: 0, watched: [], revoked: [] }
  let failWatchFor = null
  return {
    calls,
    failWatch (appId) { failWatchFor = appId },
    async ensureRegistration ({ pushProvider }) {
      calls.register++
      return { app: 'peerit', device: 'dev-' + (pushProvider || 'web'), receiveCap: 'rc', sendCap: 'sc' }
    },
    async watchFeedHead ({ caps, sourceAppId }) {
      assert.ok(caps && caps.receiveCap && caps.sendCap, 'watch carries the caps')
      if (sourceAppId === failWatchFor) throw new Error('relay rejected watch')
      calls.watched.push(sourceAppId)
      return { watchId: 'w' + (++n), source: { kind: WATCH_SOURCE_KIND, key: sourceAppId } }
    },
    async revokeWatch ({ caps, watchId }) { assert.ok(caps, 'revoke carries caps'); calls.revoked.push(watchId) }
  }
}

const A = 'a'.repeat(64); const B = 'b'.repeat(64); const C = 'c'.repeat(64)

async function main () {
  // ---- pure reconciliation ----
  console.log('— reconcileWatches (pure) —')
  {
    const cur = new Map([[A, 'w1'], [B, 'w2']])
    const r = reconcileWatches([B, C], cur)
    ok(r.toWatch.length === 1 && r.toWatch[0] === C, 'adds the newly-wanted outbox')
    ok(r.toRevoke.length === 1 && r.toRevoke[0].appId === A && r.toRevoke[0].watchId === 'w1', 'revokes the no-longer-wanted outbox (with its watchId)')
    ok(reconcileWatches([A, B], cur).toWatch.length === 0 && reconcileWatches([A, B], cur).toRevoke.length === 0, 'no-op when the set is unchanged')
    ok(reconcileWatches([], cur).toRevoke.length === 2, 'empty want revokes everything')
    ok(reconcileWatches([A, A, null, ''], new Map()).toWatch.length === 1, 'dedupes + drops falsy appIds')
  }

  // ---- lifecycle: enable + sync ----
  console.log('\n— enable + syncWatches —')
  const backend = fakeBackend()
  const woke = []
  const notify = new NotifyClient({ backend, onWake: (e) => woke.push(e) })

  await throwsAsync(() => notify.syncWatches([A]), 'syncWatches before enable() throws')
  const caps = await notify.enable({ pushProvider: 'webpush-sub-1' })
  ok(caps.receiveCap === 'rc' && notify.enabled, 'enable registers device + caps (idempotent adapter call)')

  let res = await notify.syncWatches([A, B])
  ok(res.added === 2 && res.active === 2 && backend.calls.watched.join() === [A, B].join(), 'sync installs a feed-head watch per wanted outbox')

  res = await notify.syncWatches([B, C]) // drop A, keep B, add C
  ok(res.added === 1 && res.removed === 1 && notify.activeWatchCount() === 2, 'sync installs the diff only (add C, revoke A)')
  ok(backend.calls.revoked.length === 1 && backend.calls.watched.includes(C), 'A revoked, C added; B untouched')
  ok(notify.watchedOutboxes().sort().join() === [B, C].sort().join(), 'active watch set == the wanted set')

  res = await notify.syncWatches([]) // unfollow everything
  ok(res.removed === 2 && notify.activeWatchCount() === 0, 'clearing the set revokes all watches')

  // ---- best-effort: one failing watch does not abort the rest ----
  console.log('\n— best-effort error handling —')
  const b2 = fakeBackend(); b2.failWatch(B)
  const n2 = new NotifyClient({ backend: b2 })
  await n2.enable({ pushProvider: 'x' })
  const r2 = await n2.syncWatches([A, B, C])
  ok(r2.active === 2 && r2.errors.length === 1 && r2.errors[0].appId === B, 'a rejected watch is recorded; A and C still registered')
  ok(n2.watchedOutboxes().sort().join() === [A, C].sort().join(), 'the failed outbox is simply not in the active set')

  // ---- opaque wake -> app resync hook ----
  console.log('\n— wake handling —')
  notify.handleWake({ reason: 'watch_wake', watchId: 'w9' })
  ok(woke.length === 1 && woke[0].reason === 'watch_wake', 'handleWake invokes the app-resync hook with the opaque event')
  // a throwing onWake must never propagate into the push transport
  const n3 = new NotifyClient({ backend: fakeBackend(), onWake: () => { throw new Error('boom') } })
  n3.handleWake({})
  ok(true, 'a throwing onWake is swallowed (a wake never crashes the transport)')

  console.log(`\n✅ all ${passed} notify checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
