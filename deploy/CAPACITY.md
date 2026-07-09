# Peerit OutboxLog capacity contract

**Status:** measured baseline (local HiveRelay OutboxLog, 2026-07-09)  
**Instrument:** `npm run soak:outboxlog` → `scripts/soak-outboxlog.mjs`  
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

### Knee note

At M=30 the local memory-core OutboxLog is well under thresholds. A full sweep  
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
- Production rate-limit envelope under shared NAT  
- Hypercore journal durability path re-enabled on live fleet (JSON state recovery applied 2026-07-09 after corrupt index block 42)
