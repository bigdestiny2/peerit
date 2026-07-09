# Scale-Readiness Plan — from "fine for hundreds" to "proven for a spike of thousands"

> **Release-decision notice (2026-07-09):** this document is retained as design
> background. The canonical live-service sequence and go/no-go gates are now in
> [`PUBLIC-RELEASE-REMEDIATION-PLAN.md`](PUBLIC-RELEASE-REMEDIATION-PLAN.md).
> Several findings below (including v2 PoW and pagination) have already been
> addressed in the current worktree and must not be treated as current status.

**Status:** PLAN · 2026-07-08 · owner-split labelled per the Service Contract (`hiverelay/docs/SERVICE-CONTRACT.md`) — app releases must never require a fleet update.
**Scope:** the five mass-marketing gates from the readiness report. Closes the availability, spam, capacity, honesty, and liability gates for a marketing spike. Does **not** cover the decentralization/blindness claim, which is blocked on recruiting independent operators (a real-world problem, explicitly deferred — see §9).

---

## 1. Verdict

Not spike-ready today, but the gap is **weeks of focused work, not a rebuild** — because most of the heavy machinery is already built and merely dormant.

- **Rough effort:** ~4–6 weeks across app + ops, plus 2–3 **user-owned signing/legal steps** (roster re-sign; DMCA contact).
- **Biggest UNKNOWN — capacity.** No test has ever driven more than 2 concurrent clients. We do not yet know whether the binding limit is the 20 000-group cap, the 60 req/60 s per-IP rate limit, or box RAM (the relay is a memory core). Everything downstream sizes off this measurement.
- **Biggest KNOWN defect — the v2 proof-of-work flood gate is degenerate.** A v2 proof binds to `(type, createdAt)`, not the record, so one proof staples onto unlimited distinct bodies. Trivially bypassable; must be fixed with a dual-accept migration **before** marketing drives signup volume.
- **The go/no-go is empirical.** Mass marketing is cleared only when a **soak test at a committed target scale passes written thresholds** in `deploy/CAPACITY.md` — not on a promise.

Two conceptual corrections that shape the whole plan (both surfaced by the completeness critique):

1. **A second relay buys availability, not capacity.** `fanoutAppend` (relay-pool.js:123) replicates *every* group to *every* relay, and `crossHead` (relay-pool.js:42) reads heads from *every* relay — so a 2nd relay means both boxes hold all 20 000 groups (zero cap headroom) and each client's reconcile **doubles** its request count against the per-IP limiter. The pool is for outage/censorship survival. Group-cap and rate-limit relief are separate levers (bigger box, higher cap, or sharding).
2. **The group cap is a hard author ceiling.** appId = author pubkey; every one of an author's records lives under an opaque key *within their single outbox* (data.js:159, `okey = HMAC(RK, owner‖_t‖semanticId)`). So **groups ≈ authors who have ever written** (lurkers create nothing — lazy identity). `DEFAULT_MAX_GROUPS = 20000` (outbox-log.js:18) therefore means **~20 000 writing authors before the relay 503s new authors** ("relay at group capacity", outbox-log.js:96). A marketing spike where >20k people *post* hits this **without any load at all** — from signups alone.

---

## 2. What is already built (do not reinvent)

| Capability | Status | Evidence |
|---|---|---|
| Multi-relay write fan-out + read recovery | **built, tested, dormant** | relay-pool.js `fanoutAppend`:123, `crossHead`:42 (highest *verified* head wins → rollback defense), `recoverRows`:82 (census-root match → strip defense), `directory`:98 merge |
| Roster mirror failover | **built, tested, dormant** | relay-roster.js `fetchRelayRosterMulti`:152 (first URL that verifies against the pinned key wins), `parseRosterUrls`:75; test/relay-roster.mjs:139 proves mirror failover + wrong-key rejection; build-web.mjs:203 threads `PEERIT_RELAY_ROSTER_MIRRORS` into the meta |
| 2nd-relay deploy runbook | **exists** | deploy/peerit-relay/README.md (Docker + Caddy + sslip.io, no domain needed) |
| Content-blind takedown surface | **built, dormant (404 until admin token)** | outbox-log.js suppression/DO-NOT-SERVE + journal; http-adapter.js `handleAdminRoute` (`/api/admin/{takedown,restore,takedowns,sweep}`) — drops by opaque `(appId,key)` id *without reading content* |
| Group cap + ghost sweep | **shipped** | outbox-log.js:18 cap, `sweepGhosts` + hourly timer (HiveRelay v0.24.3, #184) |
| Read-path rate-limit relief | **shipped** | HiveRelay #186 (v0.24.3): reads exempt from the per-IP budget; rejected requests no longer self-lock |
| Relay health/alert channels | **exists** | HiveRelay HealthMonitor / AlertManager |

The dormant items are cheap to flip. The genuinely-new work is: **the PoW fix, the soak instrument, the static-asset thundering-herd hardening, a staging clone, and the monitoring/redundancy/liability wiring.**

---

## 3. Milestones (sequenced by dependency + risk-reduction, not by gate number)

### M0 — Turn the flood gate back on (PoW fix) · GATE 3 · app · ~1 week

A known live defect marketing volume would immediately exploit. ~10 lines of core change; the identity to bind (`okey`) is already on the stored record.

- **W1 — identity-bound v2 target.** In `js/pow.js` add a v2 branch that folds `stored.id` (the okey, present at data.js:173) + `_t` + `createdAt` into the target, e.g. `v2|${id}|${_t}|${createdAt}`. Stamp an explicit `pow.v = 2` at mint so `verify()` dispatches the *exact* target the record was minted under — **never infer version from shape.** Confirm `_toV2` sets `id` *before* `mint` runs (data.js:183).
- **W2 — dual-accept migration (must ship with W1, never after).** In `makeValidator`/`verify` (pow.js:72): `pow.v >= 2` verifies the identity-bound target; `pow.v` absent/1 verifies the legacy target. All new writes stamp `pow.v = 2`. Pure app-side verify logic — **no relay change.** Without W2, every v2 record already on the live relay would fail admit and the network partitions.
- **W1-scope (critique fix) — audit ALL re-mint sites.** Every `pow:true` emit path must move to the new target: `submitPost` (data.js:642), `updateCommunity` (608), the four edit/delete re-emits (674, 687, 754, 783, 796), `addComment` (754), `createCommunity` (587). Each edit/delete currently re-mints over the reconstructed record — after W1 they re-mint over the identity-bound target, and the `okey` is **stable across an edit** (same owner+type+semanticId), so the re-minted proof still binds.
- **W3 (optional, gated behind W2)** — re-evaluate `MIN_BITS` now that per-record cost matters; any floor raise applies **only** to `pow.v = 2` records so legacy in-flight proofs aren't retroactively rejected (verify checks `pow.bits >= minBits`, pow.js:74).

**Exit criteria.** For two v2 posts by the same author in the same `createdAt` ms with different bodies, the targets differ and a cross-stapled proof returns `admit() = false` through `mergeOutboxes` while the matching proof returns `true` — asserted **after `JSON.parse(JSON.stringify(record))`** — the wire round-trip that hid the last consensus bug (see `test/v2-edit-delete.mjs`; a proof/canonical checked in-memory passes while the wire form fails). **Additional (critique):** edit an existing v2 post → round-trip → `admit() = true` (proof re-binds to the same okey); a **real captured-from-wire legacy record** (`pow.v` absent) still `admit() = true`. W1 has not shipped without W2.

---

### M1 — Measure capacity (soak instrument + thresholds) · GATE 4 · app + ops · ~1–1.5 weeks

The empirical foundation for the whole go/no-go. Zero dependencies. A fork of an existing driver, no new deps.

- **G4-1 — the soak driver.** Fork `scripts/hiverelay-outboxlog-convergence.mjs` → `scripts/soak-outboxlog.mjs`. Reuse `createSync`/`createData`/`DevIdentity`/`pow` verbatim; spawn `M` clients (`--clients`, `--ramp-s`) each looping boot → reconcile → write against a **LOCAL relay only** (never outbox.peerit.site). Capture p50/p99/max latency, error rate, 429 count, peak RSS, final group total. Sweep `M ∈ {100, 500, 1000, 2000}`; record the **knee** (first M where p99 > 2 s or error > 1 %). Reproduce clients **sharing one source IP** to exercise the per-IP bucket (many browsers behind one NAT share ONE 60 req/60 s bucket).
- **G4-1b — static-asset fan-in (critical, critique fix).** The soak MUST also hammer the `cache:'no-store'` static paths a cold spike stampedes: `relay-roster.json` (relay-roster.js:144), `seed-snapshot.json` (app.js:452), `asset-manifest.json` + `.sig` (app.js:376). If those are served from the same origin as the relay (or a CDN-less TLS origin), that origin — not the relay — falls over first. Measure their p99/error under M cold clients.
- **G4-2 — `deploy/CAPACITY.md`.** From the runs, author a written pass/fail contract. Must output **one hard number: `authors-until-20k-cap = X`** (measured, ~1 group/author but confirm nothing else consumes groups) and gate marketing on `X > projected-signups × 1.3`. Include: reconcile requests/user/refresh vs 60/min **with shared-NAT contention**, seeder MB/min at knee-M, and the RAM-vs-cap knee. **State plainly: the 2-relay pool does NOT raise `X` or relieve the rate limit.**

**Exit criteria.** `node scripts/soak-outboxlog.mjs --relay http://localhost:PORT --clients 2000 --ramp-s 30` runs to completion and prints a JSON report with all metrics incl. the static-asset paths; the 4-count sweep names the concrete knee M; `deploy/CAPACITY.md` exists with real numbers, an explicit `authors-until-cap = X`, and written PASS thresholds, and names whether the binding limit is group cap, rate limiter, or RAM.

---

### M2 — Flip dormant availability + stand up the liability posture · GATES 1/5/2 · ~2 weeks, two parallel tracks

Turn the built-but-dormant multi-relay pool and takedown surface live. Gated on one **user** re-sign (G1-3) and one **user** legal filing (WI-3).

**Track A — Availability (GATE 1)**
- **G1-1 (ops)** — stand up a 2nd operator-run relay from deploy/peerit-relay/README.md, on a **different provider/region** than outbox.peerit.site (maximize failure-domain separation). *Start this in week one — it's the long pole.* Independence caveat: a 2nd box the same operator runs is not true operator-diversity, but it is a real availability win.
- **G1-2 (app)** — list both relays in `deploy/web-release.json` `bootstrapRelays` + `roster.relays`, primary first. build-web.mjs:151 cross-checks the payload against config, so both lists must match after signing.
- **G1-3 (USER)** — re-sign `relay-roster.json` to the 2-relay payload with `PEERIT_ROSTER_SEED` (keyvault). The only consensus-adjacent step, but there is **no live-record migration** — clients just verify the new payload against the same pinned key.
- **G1-4 (ops)** — publish the byte-identical signed roster to ≥1 host that is **not the web origin** (IPFS/Arweave/2nd TLS origin), set `PEERIT_RELAY_ROSTER_MIRRORS`, and confirm the mirror origin lands in the emitted CSP `connect-src` (build-web.mjs:219). **Serve the roster + snapshot + manifest from a CDN/object store with edge caching, not the relay box** (critique) — short `max-age` that still respects `payload.expires` (relay-roster.js:127), not `no-store`.
- **G1-4b (app, critical critique fix) — cached-roster fallback.** Persist the last verified roster (payload + signature) to localStorage; on a fetch-all-fail (origin + mirrors down at spike), re-verify the cached copy against the pinned key and use it if unexpired. Removes a spike-time single point of failure (today `resolveRelayCandidates` fetches fresh every boot; all-URLs-down bricks new clients even when the relays are healthy). Precedent: the `cachedViewHasRows` verified-cache pattern (app.js).
- **G1-5 (app)** — prove `crossHead` rollback-defense + `recoverRows` strip-defense + read-off-relay-2 against the **real 2-relay pool under partition** (new `scripts/two-relay-partition-proof.mjs` via `createRelayPool`, a handful of records — rate-limit-safe).

**Track B — Liability (GATE 5)**
- **WI-1 (ops, quick win)** — provision `PEERIT_ADMIN_TOKEN` on the live relay so the takedown surface flips 404 → 401. No code, no app release, no fleet update.
- **WI-2 (ops)** — operator takedown runbook (drop/restore/list by opaque id, content-blind).
- **WI-3 (USER)** — publish an abuse/DMCA contact + designated-agent statement; name a monitored owner. *A legal decision, not code.*
- **WI-4 (app)** — client report affordance that surfaces the exact `(appId, key)` for v1 and `v2!<okey>` records. **No admin token in the bundle; no auto-POST.**
- **WI-5 (app)** — operator-onboarding checklist (roster inclusion requires: abuse contact, takedown capability, independence).
- **WI-6 (app)** — release preflight roster-attestation + single-operator warning.

**Track C — Honesty (GATE 2, shippable now)**
- **TM-1 (app)** — `docs/THREAT-MODEL.md`: the definitive hidden-vs-leaks table. *Hidden today* (true): content + graph values (v2 sealed fields, seal.js:80/101). *Leaks today* (honest ceiling): author roster + per-author counts + timing via `/api/directory` heads (gossip.js:598-640), community name (`slug`, cleartext, data.js:147), author pubkey (`_k`, data.js:213), request IP (inherent). Mark **GATE-2 UNMET**.
- **COPY-1/2 (app)** — correct the README overclaim (README.md:382 "no complete copy" while `shardRoster` is empty) to present-tense reality; sweep the repo for "blind host"/"sees nothing" language.
- **OPS-2 (app)** — release-time honesty guard: the build fails if blindness/dispersal copy ships while the shard roster is dark.

**Exit criteria (M2).** Both relays return 200/401 + issue tokens from an external IP; `web-release.json` lists both and `relay-roster.json` verifies against the pinned key with `npm run web:release` passing end-to-end; boot resolves a verified 2-relay roster from the mirror with the web-origin roster blocked, and from the localStorage cache with ALL fetch URLs blocked; the partition proof prints PASS for fan-out-landed-on-both, crossHead-newer-wins, recoverRows-reconstructs-stripped, read-with-relay-1-down. Unauthenticated `/api/admin/takedowns` → 401 and a runbook round-trips suppress/restore on a test box; a reachable, monitored DMCA contact is published; report yields the correct `(appId,key)` with no admin token in the client. `docs/THREAT-MODEL.md` exists, no present-tense "complete copy"/"blind host" claim survives, and the honesty guard blocks blindness copy while the shard roster is dark.

**M2 also builds the staging clone (critique — prerequisite of M4):** a 2-box, memory-core relay pool seeded from a snapshot, owned by ops. G4-1's local run and M4's target run both point at **staging**, never production.

---

### M3 — Monitoring, redundancy, durable abuse controls · GATES 4/1/3 · ~1.5 weeks · mostly ops + config

Close the silent-degradation gaps a spike exposes.

- **G4-4 + G4-6 (ops, quick win) — external liveness + group-headroom probe** on outbox.peerit.site (single committed cron+curl or uptime-kuma) hitting `/api/directory` (already returns `count` + `total` = group-count, outbox-log.js:207) with a real alert channel (Discord/email) at **>80 % of 20k or non-200.** Zero code, respects the 60 s poll limit. **This is the sole GATE-4 headroom alert required for spike-readiness** — it does not depend on any fleet release.
- **G1-6 (ops) — synthetic availability + divergence monitoring** for both relays + the roster mirror: health/token/directory + roster sha256 match, **and cross-relay directory-total divergence** (critique — alert when relays *disagree*, not just when one is down), from a network other than the app egress IP.
- **G4-5 (ops)** — put `peerit-seeder` + `peerit-mirror` under systemd (`Restart=always`, `WatchdogSec`) with a liveness probe that confirms the seeder's replicated head advances; provision a **2nd always-on seeder** on an independent box (no roster re-sign — seeders aren't in the roster).
- **Mirror-durability monitor (critique, major).** `fanoutAppend` awaits only the primary; mirror appends are fire-and-forget `.catch(()=>{})` (relay-pool.js:125), so a spike-throttled mirror silently drops writes → single-homed records. Add a **mirror-append success counter** to the soak build (assert drop-rate under load < threshold) **and** a periodic **re-fanout job** (re-push the primary's head to lagging mirrors) or at minimum the divergence alert above.
- **W4 (relay, rides HiveRelay's own train — NO peerit deadline)** — a generic per-identity/per-outbox token-bucket **write** cap (namespace-agnostic; must not reference peerit schema). Relay-owned plumbing per the Service Contract.
- **W5 (app)** — signed portable **block/mute** edge modeled on FOLLOW (`block!<targetPub>!<authorPub>`, LWW tombstone, v2-sealed), filtered at render, unioned with local hide. Abuse controls that survive device loss.
- **G4-3 (relay, demoted to nice-to-have)** — group-cap-headroom check inside HealthMonitor. Rides the fleet updater; **not on the spike critical path** (G4-4's external probe covers it) — honoring the Service Contract.

**Exit criteria (M3).** A relay at ≥80 % cap alerts (external probe) and killing one relay flips only its status while reads still succeed, alert firing within ~2 min; both seeders hold the seed outboxes and killing the primary leaves content fully available on a fresh boot; seeder/mirror auto-restart after `kill -9`; a block edge round-trips through JSON + admits, its okey binds to the author, unblock wins LWW, and a second device with the same identity renders the same muted set; cross-relay directory divergence beyond threshold alerts.

---

### M4 — SOAK GATE: production-scale go/no-go · GATES 4/1 · ~0.5–1 week if M1–M3 landed

The single hard acceptance gate. Re-runs the M1 instrument against the **now-production topology** (2-relay pool, fan-out writes, monitoring live) on the **staging clone** — never at spike volume against outbox.peerit.site (that self-inflicts the outage the plan warns of).

- Run at the **committed target M** (pinned in `deploy/CAPACITY.md` before M1 — e.g. **2 000 concurrent clients + a projected 8 000 registered authors**; the user sets the real number from the marketing plan). Clients share a source IP to exercise the per-IP bucket.
- Capture p50/p99/max, error rate, 429 count, **peak RSS per relay**, group total, **per-client request fan-out across the 2-relay pool** (crossHead over 2 relays = 2× head reads/reconcile — re-derive the shared-NAT 429 envelope for the *2-relay* case, critique), cross-relay reconcile latency, and **mirror-append drop-rate**.
- Include an **induced-failure check**: force one relay unreachable mid-run and confirm reads still succeed and the alert path fires.
- On FAIL → remediation (tune ghost-sweep TTL/interval, resize box or move memory-core → hypercore core, adjust rate limits, add relay #3 or raise `maxGroups`) and re-run. **The gate does not open on a promise.**

**Exit criteria (mass marketing cleared).** A documented run at target M asserts PASS on **every** `deploy/CAPACITY.md` threshold: p99 < 2 s, error < 1 %, 429 within the per-IP envelope under shared-NAT for the 2-relay fan-out, `authors-until-cap = X > projected-signups × 1.3`, peak RSS below box RAM with margin, mirror drop-rate below threshold, cross-relay reads succeed with one relay forced down, and the alert path fired during the induced-failure check.

---

## 4. Owner split

| Owner | Items |
|---|---|
| **app** | M0 PoW fix (W1/W2/W3, app-side verify only); soak driver G4-1/G4-1b; list 2 relays G1-2; cached-roster fallback G1-4b; partition proof G1-5; report affordance WI-4; onboarding checklist WI-5; release preflight WI-6; honesty docs TM-1/COPY-1/2 + honesty guard OPS-2; portable block/mute W5 |
| **relay** | Per-identity/per-outbox write cap W4; group-cap health check G4-3. **Both ride HiveRelay's own release train — no peerit deadline, no peerit schema references** (Service Contract) |
| **ops** | 2nd relay G1-1; roster multi-home + CDN/edge-cache G1-4; **staging clone**; capacity doc G4-2; external liveness+headroom probe G4-4; divergence monitor G1-6; seeder systemd + 2nd seeder G4-5/G4-6; provision `PEERIT_ADMIN_TOKEN` WI-1; takedown runbook WI-2 |
| **user** | Re-sign `relay-roster.json` with `PEERIT_ROSTER_SEED` G1-3 (only consensus-adjacent step, no record migration); publish DMCA/abuse contact WI-3 (legal); set the target-M / projected-signups number; decide the alert channel of record; independent-operator recruitment (deferred) |

---

## 5. Critical path (the blocking spine)

1. **M0** PoW fix + dual-accept (W1 never without W2; test with a real wire-captured legacy fixture) — before marketing drives signups.
2. **M1** soak driver + static-asset fan-in → `deploy/CAPACITY.md` with a pinned target M and `authors-until-cap = X`.
3. **M2** availability flip (2nd relay → list → **user re-sign** → mirror + CDN + cached fallback → partition proof) **‖ in parallel** liability + honesty posture; **build the staging clone here.**
4. **M3** monitoring + seeder redundancy + mirror-durability + block/mute.
5. **M4 SOAK GATE** at target M on staging with monitoring live → documented PASS = **go**.

---

## 6. First week (quick wins, highest risk-reduction first)

- **M0 W1+W2 together** — the ~10-line identity-bound PoW fix + dual-accept; one regression test that staples a proof across two bodies and asserts rejection *after* a JSON round-trip through `mergeOutboxes`, using a real captured-from-wire legacy fixture. Highest single risk-reduction.
- **G4-1** — fork the convergence harness into `scripts/soak-outboxlog.mjs`. Zero dependencies; the instrument everything else needs.
- **G4-4 + WI-1 (ops)** — external liveness/headroom probe on the live relay **and** provision `PEERIT_ADMIN_TOKEN`. Zero code; kills the two worst current blind spots (unwatched single relay filling toward the cap; no takedown when a DMCA notice arrives).
- **TM-1 + COPY-1** — write `docs/THREAT-MODEL.md` and fix the README overclaim. Pure docs; closes the known honesty gap and gives every later item one truth to cite.
- **G1-1 (ops)** — begin standing up the 2nd relay (long pole).

---

## 7. What a spike would still break — folded from the completeness critique

| # | Blind spot | Where it's handled |
|---|---|---|
| Critical | **Thundering herd** on `no-store` roster/snapshot/manifest fetches stampedes the origin; soak never tested it | G4-1b static-asset fan-in + G1-4 CDN/edge-cache + G1-4b cached-roster fallback |
| Critical | **PoW fix under-scoped** — 6 edit/re-emit sites re-mint; okey-across-edit untested | M0 W1-scope audit + edit-round-trip acceptance case |
| Critical | **Soak gate unfalsifiable** — no target M, no `authors-until-cap` number | Pinned target M + `X` in `deploy/CAPACITY.md` before M1 |
| Major | **2-relay pool amplifies load** (fanout replicates all groups; crossHead doubles reads) — no cap/rate relief | §1 correction + G4-2 states it + M4 measures 2-relay fan-out |
| Major | **Fanout durability window** — fire-and-forget mirror writes drop under load → single-homed records | Mirror-append counter + re-fanout job / divergence alert (M3) |
| Major | **No staging clone** to run M4 against without hammering prod | Staging clone built in M2 |
| Major | **No cached-roster fallback** — roster-origin outage bricks new clients | G1-4b |
| Minor | G4-3 sits on the spike path as a fleet dependency | Demoted; G4-4 external probe is the required alert |
| Minor | asset-manifest cold-cache stampede untested | Folded into G4-1b static-asset fan-in |

---

## 8. Acceptance = the SOAK GATE (one sentence)

**Mass marketing is cleared only when a documented soak run at the committed target M, against the 2-relay staging pool with monitoring live, asserts PASS on every threshold in `deploy/CAPACITY.md` — including an induced single-relay failure — and never before.**

---

## 9. Explicitly deferred — does NOT gate the spike

**GATE-2 "blindness" earned (≥3 independent operators + dispersal on).** Today the shard cohort is one legal entity wearing two hats (config/shard-roster.public.json: 2 same-owner URLs + a placeholder, pubkeys empty; RELAY-OPERATOR-RECRUITMENT.md §1: independent-entity count = 1). No code can self-satisfy this — it's a weeks-to-months **recruiting** problem. It gates the *decentralization / legal-deniability marketing claim*, **not** the thousands-scale availability/capacity claim. Honesty about the gap (TM-1 / COPY-1 / OPS-2 release guard) **is** in scope and ships in M2 so marketing copy cannot outrun the roster.

---

*Sources: peerit `feat/blind-outbox` @ 7f82bbe, HiveRelay `main` @ v0.24.3, and the readiness report. Every claim is cited to file:line above; the plan reuses dormant infrastructure wherever it exists and labels every item's owner per the Service Contract.*
