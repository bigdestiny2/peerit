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
| Per-IP rate limit | production fleet config | HiveRelay HTTP | Soak driver widens limits only for the in-process local RelayAPI |

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

Diagnostic sweep (2026-07-10, same local two-relay candidate):

| profile | writers / writer commits | result | p99 / throughput | finding |
|---|---:|---|---|---|
| shared NAT | 20 / 200 | pass | 345 ms / 60.96/s | below the HTTP bucket knee |
| shared NAT | 30 / 300 | **blocked** | n/a | relay A reached 1,200 accepted requests, then returned 429 during vote publication |
| shared NAT | 50 / 200 | **blocked in census audit** | write phase completed | all 200 writes converged, then relay A's audit request hit the exact 1,200-request ceiling |
| distributed | 30 / 300 | pass | 1,948 ms / 46.27/s | exact two-relay census after restart; no 429, pending commit, fork, or loss |
| distributed | 50 / 200 | pass | 952 ms / 58.53/s | exact two-relay census after restart; no 429, pending commit, fork, or loss |

These are local diagnostic results, not the production-equivalent staging M4
sweep and not mass-marketing clearance.

The 30-writer shared-NAT failure is not an OutboxLog group/storage/commit
capacity response and not a CAS/census correctness failure. The primary relay
also serves each client's pre-commit `get`/`heads`/`range` checks, so one public
write expands into several requests against the same IP bucket. At the knee the
observed non-200 responses were all HTTP 429; the durable engines remained
healthy. With the 5-second commit deadline, client backoff is aborted and the
nested error is `COMMIT_RELAY_ABORTED`, wrapped as a pending quorum failure. A
15-second diagnostic deadline exposes the underlying `status:429` directly and
still fails, so raising the timeout is not a capacity fix.

**BLOCK — writable public release:** the current HiveRelay adapter limit is a
fixed internal default and `RelayAPI` does not pass an operator-configurable
OutboxLog rate policy into the adapter. Shared offices, carrier NATs, and VPN
exits can therefore exhaust one another's write/read budget. Before cutover,
HiveRelay needs an explicit operator configuration
for this bucket (preferably route/read/write aware), structured 429 telemetry,
and an accurate `Retry-After`; Peerit then needs a production-equivalent
shared-NAT test at the chosen supported-user envelope. Keep the distributed
engine sweep as a separate gate so policy tuning cannot conceal an engine knee.

### Knee note

At M=30 the legacy local memory-core OutboxLog is well under thresholds, and the
bounded durable two-relay path is below the 2-second latency gate. A full sweep
`M ∈ {100, 500, 1000, 2000}` against a **staging** clone (not production) remains  
required before mass-marketing clearance (SCALE-READINESS M4). This document  
records the **instrument + numeric contract**, not marketing go.

## Pass thresholds (written contract)

A soak run at committed target **M** is **PASS** only if **all** hold:

1. **write p99 < 2000 ms**
2. **error rate < 1%**
3. **429 count** within the shared-NAT envelope for the topology under test  
   (document measured 429s; local soak disables production rate limits)
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
- Operator-configurable OutboxLog rate policy + production shared-NAT envelope
- Long-duration RSS/latency-slope and checkpoint-pause measurement
- Three independent relay origins if one-relay-loss write availability is a launch promise
