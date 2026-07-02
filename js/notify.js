// notify.js — peerit push-notification client (Mode-2 "notify-feed-head" watches).
//
// Wakes a device when a WATCHED outbox's head advances → the OS-suspended app
// opens and syncs the truth over p2p. A wake is an opaque, coalesced poke: it
// carries NO payload and is never authoritative ("push wakes the app; p2p sync
// gives the app truth"). The relay stays BLIND — it verifies signed capabilities
// and forwards opaque wakes; it never learns the notification content.
//
// DEPENDENCY-INJECTED against the HiveRelay `notify` service (docs/NOTIFY-INTEGRATION.md,
// reviewed in PR #147 but not yet merged/deployed). This module is the STABLE core —
// capability lifecycle + watch reconciliation + wake handling — behind an abstract
// `backend`, so the exact signed-request/wire shapes live in a thin adapter finalized
// when notify ships (the dht-adapter / blob-disperse "logic-first, wire-later" pattern).
// NOT wired into app boot; needs notify deployed + a WebPush provider configured.
//
// SCOPE + HONEST CEILING (see the doc):
//  • WEB/RELAY tier only. PearBrowser is pure p2p with no always-on relay to hold the
//    wake capability or a push-provider token, so push is an ADDITIVE web-tier feature.
//  • Registering a watch tells the relay "this device watches outbox O". On peerit's
//    web /api relay the social graph (who-posted-what-where) is ALREADY cleartext, so a
//    feed-head watch leaks nothing new — do NOT market it as hiding who-follows-whom.
//  • The wake is opaque + lossy (coalesced, may be dropped); correctness never depends
//    on it — a missed wake just means the app syncs on next open, as it does today.

export const WATCH_SOURCE_KIND = 'notify-feed-head'

// Pure reconciliation: given the outbox appIds the user wants woken for and the
// watches currently registered (Map appId -> watchId), compute the minimal change.
// Kept pure + exported so it is trivially testable and callers can preview a sync.
export function reconcileWatches (wantAppIds, current) {
  const want = new Set((wantAppIds || []).filter(Boolean))
  const cur = current instanceof Map ? current : new Map()
  const toWatch = []
  const toRevoke = []
  for (const appId of want) if (!cur.has(appId)) toWatch.push(appId)
  for (const appId of cur.keys()) if (!want.has(appId)) toRevoke.push({ appId, watchId: cur.get(appId) })
  return { toWatch, toRevoke }
}

// Backend interface (implemented by the real notify adapter at merge time; a fake in
// tests). Each method performs the signed notify RPCs; this module never signs — the
// adapter owns peerit-identity signing in the notify wire format.
//   ensureRegistration({ pushProvider }) -> { app, device, receiveCap, sendCap }  (idempotent)
//   watchFeedHead({ caps, sourceAppId })  -> { watchId }
//   revokeWatch({ caps, watchId })        -> any
export class NotifyClient {
  constructor ({ backend, onWake } = {}) {
    if (!backend || typeof backend.ensureRegistration !== 'function') throw new Error('NotifyClient: backend with ensureRegistration/watchFeedHead/revokeWatch required')
    this.backend = backend
    this.onWake = typeof onWake === 'function' ? onWake : () => {}
    this.enabled = false
    this.caps = null              // { app, device, receiveCap, sendCap }
    this._watches = new Map()     // watched outbox appId -> watchId
  }

  // Idempotent enable: bind the device's push provider (e.g. a WebPush subscription),
  // register the device, and install the receive/send capabilities the watches need.
  async enable ({ pushProvider } = {}) {
    this.caps = await this.backend.ensureRegistration({ pushProvider })
    this.enabled = true
    return this.caps
  }

  // Reconcile the registered watches to exactly `wantAppIds` (the outboxes the user
  // wants woken for — see the doc for how that set is populated). Revokes first, then
  // adds, so a churn never transiently exceeds the intended set. Best-effort per item:
  // one failing watch/revoke does not abort the rest (recorded in `errors`).
  async syncWatches (wantAppIds) {
    if (!this.enabled) throw new Error('NotifyClient: enable() before syncWatches()')
    const { toWatch, toRevoke } = reconcileWatches(wantAppIds, this._watches)
    const errors = []
    for (const { appId, watchId } of toRevoke) {
      try { await this.backend.revokeWatch({ caps: this.caps, watchId }); this._watches.delete(appId) } catch (e) { errors.push({ op: 'revoke', appId, error: e && e.message }) }
    }
    for (const appId of toWatch) {
      try { const res = await this.backend.watchFeedHead({ caps: this.caps, sourceAppId: appId }); if (res && res.watchId) this._watches.set(appId, res.watchId) } catch (e) { errors.push({ op: 'watch', appId, error: e && e.message }) }
    }
    return { added: toWatch.length - errors.filter(e => e.op === 'watch').length, removed: toRevoke.length - errors.filter(e => e.op === 'revoke').length, active: this._watches.size, errors }
  }

  // The device's push transport (Service Worker WebPush handler / SSE) calls this when
  // a wake arrives. The wake is opaque; peerit's onWake handler triggers a p2p resync
  // and (optionally) a UI badge — it must NOT treat the wake as content.
  handleWake (event) { try { this.onWake(event || {}) } catch { /* a wake must never throw into the transport */ } }

  watchedOutboxes () { return [...this._watches.keys()] }
  activeWatchCount () { return this._watches.size }
}
