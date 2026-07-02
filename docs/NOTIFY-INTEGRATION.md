# peerit push notifications via HiveRelay `notify` (Mode-2 feed-head watches)

> **Goal:** wake a backgrounded/killed peerit app when there's new activity it cares
> about, through a relay that never learns the content. The one-line rule (from the
> notify service): **push wakes the app; p2p sync gives the app truth.** A wake is a
> lossy, opaque hint — the woken app fetches real state from its own P2P data.
>
> **Status (2026-07-02):** stable client CORE built + tested (`js/notify.js`,
> `test/notify.mjs`), dependency-injected against the notify interface — logic-first,
> wired when the `notify` service (HiveRelay PR #147, reviewed, not yet merged/deployed)
> ships. Not in `SITE_FILES`, not wired into boot. Mirrors the Phase-3 dispersal /
> dht-adapter pattern.

---

## 1. The mapping problem — what does a "feed-head watch" watch in peerit?

`notify-feed-head` wakes a device when **one outbox's signed head advances**. peerit is
a Reddit-shape app: users subscribe to **communities**, and a community's posts arrive
from **many** authors' outboxes (multi-writer gossip). So the watch unit (one outbox)
does not map 1:1 onto "new post in r/x". Three candidate triggers:

| Trigger | Maps to feed-head? | Verdict |
|---|---|---|
| **Follow-author** — wake when a specific author posts | ✅ 1:1 (watch that author's outbox head) | **Adopt first.** Bounded (a user follows N authors), clean, a real feature. |
| **Subscribed-community activity** — wake on any new post in r/x | ❌ the writer set is dynamic/unbounded — can't be N feed-head watches | Defer. Needs a relay-side per-community aggregation not in notify's model. |
| **Replies / mentions inbox** — wake when someone replies to me | ❌ a reply lives in the *replier's* outbox — no single head to watch | Defer. Needs a per-user "mentions" outbox the replier also appends to (data-model change). |

**Decision:** ship **follow-author** first — the only clean single-outbox-head mapping.
It adds a lightweight "follow a user" capability (peerit already discovers + replicates
peer outboxes via gossip, so the substrate exists). The watch set = the user's curated
followed-author pubkeys. Community-wide and replies-inbox wakes are future work behind a
different relay primitive.

---

## 2. Architecture

```
peerit.site (web tier)                         HiveRelay (blind)
 ┌───────────────────────────┐                 ┌─────────────────────────────┐
 │ user follows authors  ────┼──watch set──▶   │ notify service              │
 │ NotifyClient.syncWatches  │  (signed caps)  │  · verifies ReceiveCap/     │
 │                           │                 │    SendCap, never reads     │
 │ WebPush subscription  ────┼──provider bind─▶│  · notify-feed-head watch   │
 │ (Service Worker + VAPID)  │                 │    composes onto the        │
 └───────────────────────────┘                 │    co-resident outboxlog's  │
        ▲  opaque wake (no payload)            │    subscribe() (one path)   │
        └──────────────────────────────────────┤  · fires an opaque wake     │
   SW push handler → focus app → p2p RESYNC    │    when head!<author> moves │
                                               └─────────────────────────────┘
```

- **Provider = WebPush** (peerit.site is a web app): the Service Worker registers a
  push subscription (VAPID); its endpoint/keys are the provider token peerit binds to a
  notify **provider binding**. APNs/FCM are for a future native shell.
- **Capability lifecycle** (all signed by the peerit user's Ed25519 identity, in the
  notify wire format): bind provider → register device → install `ReceiveCap` (this
  device may be woken on channel `message`, mode `watch`) → install `SendCap`. Then one
  `watch` per followed author with `source = { kind: 'notify-feed-head', key: <authorPub> }`.
- **Wake path:** author appends → their outbox `head!<author>` advances → the relay's
  notify (composed on the same relay's outboxlog `subscribe()`) fires **one opaque,
  coalesced** wake → the SW receives it → focuses/opens peerit → `NotifyClient.handleWake`
  triggers a normal p2p resync (+ optional unread badge). No payload is delivered.

---

## 3. What's built now (`js/notify.js`, DI'd + tested)

- `reconcileWatches(wantAppIds, current)` — pure diff (add/revoke) between the wanted
  followed set and the registered watches. The stable, load-bearing bit.
- `NotifyClient({ backend, onWake })`:
  - `enable({ pushProvider })` — idempotent register (device + caps) via the adapter.
  - `syncWatches(wantAppIds)` — reconcile registered watches to the followed set
    (revoke-then-add; best-effort, one failure never aborts the rest).
  - `handleWake(event)` — the SW/SSE calls this on a wake; invokes the app-resync hook;
    a throwing hook can never crash the transport.
- `backend` is the injected notify surface: `ensureRegistration` / `watchFeedHead` /
  `revokeWatch`. The **exact signed-request/wire shapes live in the not-yet-built
  adapter**, so this core doesn't depend on notify's final param format.
- Tests: `test/notify.mjs` (16) — reconcile cases, enable→sync, add/revoke churn,
  best-effort failure, wake→resync, transport-safe throwing hook.

---

## 4. Remaining to make it live (each a real dependency)

| # | Piece | Blocked on |
|---|---|---|
| **N1** | **Follow-author feature** — data + UI to curate the followed-author set (the watch-set source). | peerit-only; buildable now. |
| **N2** | **WebPush provider** — SW push handler + VAPID keypair + subscription → provider binding. | peerit-only; buildable now (needs a VAPID key). |
| **N3** | **Concrete notify backend adapter** — signs the notify RPCs with the peerit identity in the notify wire format (`notifySignaturePayload(domain, body)`), calls the notify client SDK; wired into boot. | **notify merged + deployed** on the relay. |
| **N4** | Wake UX — focus/open, unread badge, resync. | after N3. |

---

## 5. Blindness & honest ceiling (do not overclaim)

- **Web/relay tier ONLY.** PearBrowser is pure p2p with no always-on relay to hold a
  wake capability or a push-provider token, so push is an **additive web-tier feature**,
  not something the hyper:// path gets. Steer high-assurance users to PearBrowser as
  before; push is a convenience for the always-available web tier.
- **No NEW social-graph leak.** A watch tells the relay "device D watches outbox O
  (author O)". On peerit's web `/api` relay the social graph — who-posted-what-where —
  is **already cleartext by construction** ([BLINDSHARD-DESIGN.md §6.3](BLINDSHARD-DESIGN.md)),
  so a feed-head watch reveals nothing the web relay doesn't already see. **Do not**
  market push as hiding who-follows-whom.
- **The relay never reads content.** It verifies signed caps and forwards an **opaque,
  payload-free** wake; the app syncs the actual post over p2p. The relay learning "some
  activity happened for device D" is the entire disclosure.
- **Wakes are lossy + coalesced.** Correctness never depends on a wake (a dropped/coalesced
  wake just means the app syncs on next open, exactly as today). Never treat a wake as
  authoritative or as content.
- **Delivery metadata is device-scoped** (per the notify service's design): only the
  woken device can read its own delivery events; the relay can't forge feed rows or read
  who-woke-whom.
