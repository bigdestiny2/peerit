# 2026-07-09 — Peerit live audit + performance program close-out

**Date:** 2026-07-09  
**Scope:** Live peerit.site data plane, identity-bound PoW, local capacity instrument, HiveRelay OutboxLog local proofs  
**Honesty posture:** public forum; relay is untrusted carrier of **plaintext** public content; single-operator topology today (not a multi-operator “blind host” claim).

---

## 1. Live status (criterion 1) — **DONE / green**

| Check | Result |
|---|---|
| `https://peerit.site/` | **HTTP 200** (static plane) |
| Published assets | 200 (styles, app.js, roster, snapshot, manifest) |
| Listed roster relay | `https://outbox.peerit.site` only |
| `outbox.peerit.site/health` | **HTTP 200** (`version` 0.24.3) |
| `POST /api/token` + `GET /api/directory` | **200**, `count=3` / `total=3` heads |
| 502 on listed primary | **none** after restore |

**Root cause of prior 502:** HiveRelay crash-loop on `SERVICE_START_FAILED: outboxlog` because partitioned Hypercore journal threw `OutboxLogPartitionedHypercoreJournal: bad index block 42`. Caddy proxied to `:9100` with no healthy backend.

**Ops fix applied (Bern VPS `45.59.123.112`):**
- Stopped crash loop
- Backed up `/root/.hiverelay/config.json`
- Switched OutboxLog from `persistence: "hypercore-outboxes"` → JSON `persistencePath: /root/.hiverelay/storage/outboxlog-state.json` (intact state file retained)
- Restarted `hiverelay.service` → listening on `0.0.0.0:9100`, token + directory healthy

**Evidence:** implementer `{SCRATCH}/live-plane.log`  
**Roster:** unchanged (still single listed relay; no re-sign required). `proof:relay-roster` → `status=ready`, 9 pass.

**Residual live risks:** single listed relay remains a single point of failure; Hypercore journal path disabled until index rebuild; ship report still `blocked` in availability proof (warn only).

---

## 2. Flood-gate integrity (criterion 2) — **DONE**

Shipped `js/pow.js` (+ `web/js/pow.js` parity):

- **v2 mint** stamps `pow.v = 2` and binds target to `v2|<id>|<type>|<createdAt>`
- **Dual-accept:** `pow.v >= 2` → identity target; absent/`1` → legacy v1 target
- **Tests:** `test/pow-identity-bind.mjs` (in default `npm test` via `test:pow`)
  - staple across two distinct post ids rejected after `JSON.parse(JSON.stringify(...))`
  - matching proofs + wire legacy fixture accepted
  - real v2 data path + `mergeOutboxes` admit
  - edit re-mint on stable okey admits

**Evidence:** `{SCRATCH}/pow-tests.log` (28 checks passed)

---

## 3. Capacity measurement (criterion 3) — **DONE (instrument + baseline)**

| Artifact | Path |
|---|---|
| Soak driver | `scripts/soak-outboxlog.mjs` (`npm run soak:outboxlog`) |
| Contract | `deploy/CAPACITY.md` |
| Measured run | `reports/soak-outboxlog-local-2026-07-09.json` + `{SCRATCH}/soak-report.json` |

**Measured local run:** clients=30, success=30/30, write p99≈20 ms, errors=0, 429=0, **authors-until-cap = 20000**, status=**pass**.

Local harness registers OutboxLog namespace `peerit` (Peerit stamps `_ns:'peerit'`).

**Explicitly NOT done (deferred):** M4 staging soak at marketing target M (e.g. 2000) with 2-relay pool + induced failure; production rate-limit envelope; multi-region staging fleet.

---

## 4. In-repo gates (criterion 4) — **DONE**

| Gate | Result | Evidence |
|---|---|---|
| `npm test` | **exit 0** (includes `pow-identity-bind`) | `{SCRATCH}/peerit-npm-test.log` |
| `proof:hiverelay-outboxlog` | **status=pass**, 13 checks | `reports/hiverelay-outboxlog-convergence-2026-07-09.json`, `{SCRATCH}/outboxlog-proof.log` |
| `proof:relay-roster` | **status=ready**, 9 pass | `{SCRATCH}/relay-roster-proof.json` |

Proof harness fixes landed:
- configure `outboxlog.namespace: 'peerit'` on local RelayAPI
- `DevIdentity(..., { persistSeed: true })` so reload keeps writer key

---

## 5. Done vs deferred (program honesty)

### Done in this session
1. Live outbox restore (JSON persistence fallback after corrupt journal)
2. Identity-bound PoW + dual-accept + tests wired into `npm test`
3. Soak driver + `deploy/CAPACITY.md` + measured baseline JSON
4. Local OutboxLog convergence proof green
5. Relay roster proof green (no roster change)
6. This close-out report

### Deferred (not claimed as complete)
| Item | Why deferred |
|---|---|
| M2 multi-relay roster re-sign + CSP multi-host | Needs `PEERIT_ROSTER_SEED` offline key; not in this environment |
| M3 second seeder / mirror re-fanout / external uptime productization | Ops follow-up |
| M4 marketing-scale soak on staging | Non-goal for this session; instrument exists |
| Independent multi-operator blindness / DMCA agent | Legal + recruiting |
| PearBrowser two-instance `proof:bridge:local` | Operator GUI required |
| Hypercore-outboxes journal repair on live | Intentionally left on JSON until index rebuild |
| Production Playwright smoke | Playwright not installed (`browser-smoke-skip.log`) |
| Ecosystem hypercore 11 / monorepo consolidation | Continuous-plan lane, out of scope |

---

## 6. Topology honesty (copy guard)

- **Live web:** peerit.site static origin + **one** signed roster relay (`outbox.peerit.site`).
- **Failover hosts** (`peerit-relay.onrender.com`, `153-75-89-206.sslip.io`) may be reachable but are **not** in the signed live roster → clients will not use them until re-sign + redeploy.
- **Shard roster** empty → no “blind host / complete copy impossible” present-tense claim.
- Public posts/comments are **plaintext-to-relay** by design.

---

## 7. Suggested next ops (outside this close-out)

1. Rebuild Hypercore outbox journal offline and re-enable `hypercore-outboxes` with a migration, or keep JSON + periodic snapshot ops.
2. Add external uptime probe on `/api/directory` + group headroom alert at 80% of 20k.
3. When seed available: 2-relay roster sign + CDN roster mirror + cached-roster fallback (SCALE M2).
4. Run soak sweep M∈{100,500,1000,2000} on staging; fill CAPACITY.md knee.

---

*Evidence roots: `02-apps/peerit/reports/*2026-07-09*`, `deploy/CAPACITY.md`, implementer scratch logs under the goal harness SCRATCH directory.*
