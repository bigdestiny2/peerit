# Peerit OutboxLog capacity contract

**Status:** measured baseline (local HiveRelay OutboxLog, 2026-07-09)  
**Legacy instrument:** `npm run soak:outboxlog` → `scripts/soak-outboxlog.mjs`
**Writable-candidate instrument:** `npm run soak:atomic-two-relay` → `scripts/soak-atomic-two-relay.mjs`
**Never soak production** (`outbox.peerit.site` / marketing spike volume). Staging/local only.

## Hard limits (code defaults)

| Limit | Value | Source | Meaning |
|---|---|---|---|
| `DEFAULT_MAX_GROUPS` | **20 000** | HiveRelay `outbox-log.js` | Hard ceiling on distinct outboxes (≈ **writing authors**) |
| Per-record body | 64 KiB | OutboxLog | Append 413 when exceeded |
| Per-IP rate limit | production fleet config | HiveRelay HTTP | Local/staging runs must pass an explicit canonical operator envelope and verify the advertised effective policy |

**authors-until-cap = 20 000** (measured mapping: 1 group per author who has ever written; lurkers create nothing).  
A marketing spike with projected signups **P** requires `20 000 > P × 1.3` before mass push.  
A second relay does **not** raise this number (fan-out replicates groups to every pool member).

## Measured baseline (local in-process OutboxLog)

Command (representative):

```bash
cd 02-apps/peerit
node scripts/soak-outboxlog.mjs --clients 30 --ramp-s 4 --loops 1 \
  --out reports/soak-local.json
```

| Metric | Result (clients=30, loops=1) |
|---|---|
| success | **30/30** |
| write p50 | ~12–20 ms class (PoW bits reduced for soak) |
| write **p99** | **~20 ms** |
| error rate | **0** |
| 429 count | **0** (local API rate limit disabled for soak) |
| peak RSS | ~140 MB process |
| directory total after run | 30 (= success authors) |
| status | **pass** |

Evidence path from implementer run: `{SCRATCH}/soak-report.json` (status=pass).

## Durable two-relay atomic baseline

The public writer candidate must use this path; the legacy single-relay
create/append baseline above is not release evidence for writable mode.

Representative bounded command (2026-07-10):

```bash
npm run soak:atomic-two-relay -- \
  --hiverelay-root /path/to/hiverelay-atomic-candidate \
  --clients 6 --iterations 3 --restarts 2 \
  --out /tmp/peerit-atomic-two-relay-evidence.json
```

| Metric / invariant | Result |
|---|---|
| concurrent writers | 6 (+ 1 recovery writer) |
| measured concurrent commits | 36 (community, post/blob, vote, and bound comment writes) |
| unflushed relay-engine recreations | 2 |
| injected post-fsync response loss | recovered exact pending envelope |
| acknowledged loss / signed-head fork / census mismatch | **0 / 0 / 0** |
| write p50 / p99 / max | **99 / 141 / 141 ms** |
| measured throughput | **57.6 commits/s** |
| relay state | exact groups, bytes, commit history, head roots, and signatures |

This is a correctness and bounded-performance baseline, not the M4 marketing
capacity result. It exercises two real loopback `RelayAPI` + atomic-only
`OutboxLog` instances with separate fsynced JSONL journals, a lost HTTP response
after durable commit, exact retry after process-like recreation without a flush,
and full signed-census comparison on both origins.

### Shared-NAT policy knee versus engine capacity

The instrument has two explicit traffic profiles. They answer different
questions and neither result may be substituted for the other:

- `--traffic-profile shared-nat` keeps every browser behind one source IP and
  therefore exercises the real OutboxLog adapter policy of 1,200 accepted
  requests per 60 seconds per IP.
- `--traffic-profile distributed` enables trusted-proxy handling only inside the
  loopback fixture and assigns one deterministic forwarded IP per writer. This
  isolates durable-engine throughput from the shared-NAT bucket; it does not
  disable journal fsync, atomic CAS, quorum receipts, restart recovery, or census
  verification.

The fixture passes its envelope through canonical
`outboxlog.http.rateLimit`; it does not monkeypatch RelayAPI gates. Before load,
it requires every relay's `/api/bridge/status.httpRateLimit` to report
`source:"operator"` and the exact effective/outbox envelope requested with
`--rate-limit-max` and `--rate-limit-window-ms`. Explicit disabling is accepted
only with the distributed profile.

Diagnostic sweep (2026-07-10, same local two-relay candidate):

| profile | writers / writer commits | result | p99 / throughput | finding |
|---|---:|---|---|---|
| shared NAT | 20 / 200 | pass | 345 ms / 60.96/s | below the HTTP bucket knee |
| shared NAT | 30 / 300 | **blocked** | n/a | relay A reached 1,200 accepted requests, then returned 429 during vote publication |
| shared NAT | 50 / 200 | **blocked in census audit** | write phase completed | all 200 writes converged, then relay A's audit request hit the exact 1,200-request ceiling |
| distributed | 30 / 300 | pass | 1,948 ms / 46.27/s | exact two-relay census after restart; no 429, pending commit, fork, or loss |
| distributed | 50 / 200 | pass | 952 ms / 58.53/s | exact two-relay census after restart; no 429, pending commit, fork, or loss |
| shared NAT, configured 12,000/60s | 30 / 300 | pass | 518 ms / 62.14/s | exact restart census; 0 HTTP 429; peak RSS 168 MB |
| distributed, configured 1,200/60s/IP | 200 / 2,000 | **correctness pass; performance fail** | 4,866 ms / 58.48/s | exact restart census and 0 HTTP 429, but p99 exceeds the 2-second contract; peak RSS 285 MB / heap 160 MB |

```bash
# Shared-NAT policy gate (30 writers × 10 commits)
npm run soak:atomic-two-relay -- --hiverelay-root /path/to/hiverelay \
  --traffic-profile shared-nat --rate-limit-max 12000 \
  --rate-limit-window-ms 60000 --clients 30 --iterations 7 \
  --restarts 1 --commit-timeout-ms 5000 --out /tmp/shared-nat.json

# Distributed engine gate (200 writers × 10 commits)
npm run soak:atomic-two-relay -- --hiverelay-root /path/to/hiverelay \
  --traffic-profile distributed --rate-limit-max 1200 \
  --rate-limit-window-ms 60000 --clients 200 --iterations 7 \
  --restarts 1 --commit-timeout-ms 5000 --max-p99-ms 2000 \
  --out /tmp/distributed.json
```

These are local diagnostic results, not the production-equivalent staging M4
sweep and not mass-marketing clearance.

#### Why the one-process 200-writer p99 is not a production-engine verdict

The 200-writer run is a valid failure of the local 2-second contract, but its
latency is dominated by closed-loop queueing inside the fixture. It co-locates
201 Peerit clients, both RelayAPI/OutboxLog engines, telemetry, restart replay,
and roughly 4,005 synchronous journal fsyncs on one Node event loop and disk.

Evidence from the recorded telemetry:

- 50 writers / 200 commits sustained 58.53 commits/s at p99 952 ms.
- 200 writers / 2,000 commits sustained essentially the same 58.48 commits/s,
  while p50 rose to 3,247 ms and p99 to 4,866 ms.
- With about 200 operations continuously in flight, Little's law predicts
  `200 / 58.48 = 3.42s` residence time, close to the measured 3.261-second mean.
- Relay-visible commit handling averaged 6.90/6.87 ms (max 232/231 ms); heads
  averaged 20.23 ms (max 437 ms). There were no 429s, forks, lost commits, or
  pending envelopes.
- Each relay ended at 2,002 commits, below the 4,096-entry checkpoint interval,
  so no periodic checkpoint ran during the measured writer phase. The journal
  ownership lease is acquired at construction, not per commit.

This does not waive the latency gate. It means the next decisive measurement
must isolate load generators, relay A, and relay B in separate processes and,
for production-equivalent evidence, separate hosts/disks. Instrument client
preflight/build/leader/mirror phases plus relay request queue, validation/CAS,
journal write, fsync, apply, event-loop delay, GC, and memory. Only if isolated
staging still saturates durable sync should the engine change: first a single
ordered asynchronous commit queue, then (if required) a bounded 2-5 ms group
commit whose receipts are released only after the shared durable sync. Never
remove the forced self-audit or acknowledge before fsync.

The 30-writer shared-NAT failure is not an OutboxLog group/storage/commit
capacity response and not a CAS/census correctness failure. The primary relay
also serves each client's pre-commit `get`/`heads`/`range` checks, so one public
write expands into several requests against the same IP bucket. At the knee the
observed non-200 responses were all HTTP 429; the durable engines remained
healthy. With the 5-second commit deadline, client backoff is aborted and the
nested error is `COMMIT_RELAY_ABORTED`, wrapped as a pending quorum failure. A
15-second diagnostic deadline exposes the underlying `status:429` directly and
still fails, so raising the timeout is not a capacity fix.

HiveRelay candidate `d8c8218` closes the code-level configurability gap: it
accepts canonical `outboxlog.http.rateLimit`, returns an accurate `Retry-After`,
and exposes source/effective policy telemetry. The 12,000/60s local shared-NAT
run proves that configuration removes the former 30-writer 429 knee without
raising Peerit's 5-second deadline.

**BLOCK — writable public release:** do not infer production readiness from that
local pass. Every signed public relay still needs the reviewed HiveRelay build,
the chosen explicit operator envelope, and matching status telemetry behind its
real trusted proxy. Run the shared-NAT profile against production-equivalent
staging at the supported-office/VPN envelope. Separately, the distributed
200-writer run fails the written p99 contract (4,866 ms > 2,000 ms), so writable
release still lacks passing high-concurrency evidence. The one-process result
does not by itself prove that independently hosted relay engines miss the gate;
that must be decided by the isolated staging sweep described above.

### Knee note

At M=30 the legacy local memory-core OutboxLog is well under thresholds, and the
bounded durable two-relay path is below the 2-second latency gate. A full sweep
`M ∈ {100, 500, 1000, 2000}` against a **staging** clone (not production) remains  
required before mass-marketing clearance (SCALE-READINESS M4). This document  
records the **instrument + numeric contract**, not marketing go.

The instrument accepts the full 2,000-client target and exits non-zero whenever
the measured end-to-end write p99 is not below `--max-p99-ms` (2,000 by
default). Set `--max-rss-mb` to the reviewed memory budget of each staging
load-generator/relay process so the evidence records an explicit resource
ceiling. Local co-location remains diagnostic only; production clearance still
requires isolated generators and relay hosts.

## Pass thresholds (written contract)

A soak run at committed target **M** is **PASS** only if **all** hold:

1. **write p99 < 2000 ms**
2. **error rate < 1%**
3. **429 count** within the shared-NAT envelope for the topology under test  
   (document the configured envelope and measured 429s; never silently disable it)
4. **authors-until-cap = 20000** and `directoryTotal` / group growth consistent with ~1 group/author
5. **peak RSS** below box RAM with margin (record measured value)

Committed target for next staging M4 (placeholder until marketing sets P):

- **target M = 2000 concurrent clients** (not yet measured at full M)
- **projected-signups gate:** `20000 > projected_signups × 1.3`

## How to re-measure

```bash
# local HiveRelay OutboxLog (default)
npm run soak:outboxlog -- --clients 50 --ramp-s 5 --out reports/soak.json

# optional static-origin fan-in (CDN/origin stampede)
npm run soak:outboxlog -- --clients 50 --static-origin https://peerit.site --out reports/soak-static.json
# (static-origin is read-only; still do not write-soak production outbox)
```

## Deferred (not claimed here)

- M4 staging soak at marketing target M with 2-relay pool + induced failure  
- Deploy and verify the configured OutboxLog policy on every signed public relay
- Production-equivalent shared-NAT envelope and distributed p99 under 2 seconds
- Long-duration RSS/latency-slope and checkpoint-pause measurement
- Three independent relay origins if one-relay-loss write availability is a launch promise
