# B4 — Retiring `peerit-seeder` (client seed-gap → relay-held durability)

**Status:** draft / scope. This is the fourth leg of the pure-pipe convergence
(after B1 fleet outboxlog-enable, B2/B7 takedown, B3 the HiveRelay-outbox relay
backend). It closes the "client seed-gap" — the reason peerit needs an always-on
`peerit-seeder` box today — by moving content durability onto the HiveRelay
relay + fleet, which peerit's web build already writes to.

> **The one decision this doc surfaces:** `peerit-seeder` can be retired for the
> web / pure-pipe path **only if the HiveRelay `outboxlog` runs its fleet-durable
> journal** (`persistence: 'hypercore-outboxes'` + persistence cores seeded to the
> fleet). Under the plain single-relay JSON-state mode, retiring the seeder trades
> ≥N-replica durability for one box's disk — a **regression**. See §3.

---

## 1. What `peerit-seeder` does today

`02-apps/peerit-seeder/seeder.mjs` is an always-on Node process that keeps peerit
user data available 24/7. It exists because:

- PearBrowser does **not** push `window.pear.sync` data to the HiveRelay fleet —
  it keeps each user's outbox in the local corestore and announces it on the swarm
  **only while the app is open**. When every browser holding a post goes offline,
  the post is unreachable.
- A browser **cannot seed its own hypercore** (no Node / corestore / hyperswarm).

So the seeder replicates each user's outbox hypercore (a single-writer log; its
`inviteKey` *is* the hypercore) over the bridge's discovery topic and calls
`HiveRelayClient.seed(key, { replicas, ttlDays, durability, discoveryKey })` to
pin it on the fleet with archive durability (AutoHeal keeps ≥N replicas across ≥M
regions). It confirms a real fleet copy (`remoteLength ≥ length`) and re-affirms
every 30 min.

**This is a bespoke, always-on box per world — exactly the "special relay of its
own" the pure-pipe North Star wants to eliminate.**

## 2. Why the HiveRelay-outbox backend (B3) subsumes it — for the web path

peerit's **web** build (`resolveRuntime` → `mode: 'web'`) runs
**`BridgeGossipSync`** over the relay's `/api/*`, not local hypercores:

- Every write is `pear.sync.append(appId, op)` → **`POST /api/sync/append`**
  (`js/gossip.js:802`, `:841`). The **relay holds each user's outbox log
  server-side.**
- Reads are `/api/sync/heads` + `/api/sync/get` (`js/gossip.js:858+`).
- The signed-anchor model (`canon.js` census + the Phase C durable head-floor)
  means the transport carries **no authority** — a relay can't forge or
  selectively drop without detection, so moving the store to HiveRelay changes
  *who stores*, not *who is trusted*.

Because the always-on relay holds the log, the seeder's job (bridge the gap when
the author is offline) is **already covered on the web path** — provided the relay
itself is durable. That proviso is §3.

## 3. The durability requirement (the crux)

HiveRelay `outboxlog` persists two ways (`packages/services/builtin/outboxlog/index.js`):

| Mode | How | Fleet-durable? |
|---|---|---|
| **JSON state** (default) | signed rows → `<storage>/outboxlog-state.json` | ❌ single relay's disk — a relay loss = log loss |
| **`hypercore-outboxes` journal** | outbox logs stored as hypercores; `seedPersistenceCores()` (`index.js:244` → `hypercore-journal.js:225` `seedCores` → `seeder.seedCore(coreKey)`) hands them to the relay's fleet **seeder** → AutoHeal ≥N replicas | ✅ same guarantee peerit-seeder gave |

**Retiring `peerit-seeder` is safe ONLY under the `hypercore-outboxes` journal
with persistence-core seeding wired.** Otherwise it is a durability regression.

**HiveRelay work required (the actual B4 blocker is HERE, not in peerit):**
1. Configure `outboxlog.persistence: 'hypercore-outboxes'` (or `'hypercore'`). Opt-in
   today — the default is the single-relay JSON state file (not fleet-durable).
2. **Wire `seedPersistenceCores`.** ⚠️ As of `origin/main`, `seedPersistenceCores`
   (`index.js:244`) has **zero callers** — it is defined but never invoked, so the
   outbox cores are **not** handed to the fleet seeder even under the hypercore
   journal. This is a concrete HiveRelay **code change**, not just a config toggle:
   call `seedPersistenceCores(node.seeder)` on outboxlog start and on a re-affirm
   interval (mirroring `peerit-seeder`'s 30-min RESEED), and confirm the fleet
   actually downloaded (`remoteLength ≥ length`) before treating a world as durable.
3. Confirm the fleet AutoHeals the outbox cores to the replica floor
   (`getDurableStatus` / `waitForDurable`).

## 4. Retirement criteria (checklist)

Turn off `peerit-seeder` for a world only when **all** hold:

- [ ] Relay runs `outboxlog` with `persistence: 'hypercore-outboxes'`.
- [ ] `seedPersistenceCores` confirmed wired + re-affirming (fleet has the outbox cores).
- [ ] `getDurableStatus` reports ≥ replica floor for the outbox cores.
- [ ] peerit web build is on the **`hiverelay-outbox`** backend (B3) so writes go
      to `/api/sync/append` on that relay.
- [ ] **Durability smoke:** an author writes a post; then **all** author browsers
      *and* the seeder go offline; a fresh visitor on a cold device still reads the
      post (a fleet-only fetch — the exact test the seeder's own comment describes,
      2026-06-23).
- [ ] Then, and only then: stop running `peerit-seeder` for that world.

## 5. What changes on the peerit side

**Little to no browser code.** The web/outbox build already appends durably to the
relay; the durability guarantee lives in the relay's journal config (§3). The
`peerit-seed-outboxes` curated-content meta and the external seeder box become
unnecessary for **durability** once the relay runs the fleet-durable journal.

Optional, self-contained client hook (recommended, tracked as B4a): extend the B3
backend probe so a build configured for `hiverelay-outbox` can **verify the relay
is fleet-durable before relying on it** — i.e. have HiveRelay's `/api/bridge/status`
report `{ service:'outboxlog', durable:true }` when the hypercore journal +
seeding are active, and have peerit `console.warn` (non-blocking, like the B3
probe) if a "retire the seeder" build is pointed at a non-durable relay. This
turns the §4 checklist's most error-prone line into a runtime guard. It needs a
small coordinated HiveRelay change (expose `durable` in bridge status) — drafted
separately if we want it.

## 6. Out of scope: the native PearBrowser path

The native PearBrowser app's `window.pear.sync` is **local hypercores**, not the
HTTP relay bridge, so `peerit-seeder` still applies there. Retiring it for native
would require the app to seed its own outbox to the fleet from within the app (it
*does* have corestore/swarm) — a separate track. It is **not needed for the
pure-pipe North Star** ("works in any browser and scales"), whose target is the
web build covered by §2–§5.

---

### TL;DR
peerit's web build already writes durably to the HiveRelay relay, so
`peerit-seeder` is redundant for the pure-pipe path **once the relay's outbox log
is fleet-durable**. That is not yet true on `origin/main`: the fleet-durable
journal is opt-in **and** its `seedPersistenceCores` hook is currently unwired
(zero callers), so the real B4 blocker is a **HiveRelay code change** (§3.2), not a
peerit browser rewrite. After that: the §4 durability smoke, then turn the seeder
off. The optional §5 probe hook makes "am I safe to retire the seeder?" a runtime
check instead of a manual checklist.
