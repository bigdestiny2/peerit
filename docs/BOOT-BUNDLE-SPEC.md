# GET /api/boot — one-shot cold-boot bundle (hand-off to the relay side / bern)

**Status:** SPEC / hand-off. The relay work is bern's (HiveRelay outboxlog); the client
wiring is peerit's and I'll add it the moment the endpoint exists. Fully backward
compatible: absent → the client uses today's fan-out.

## Why
A cold boot today is O(authors) requests against the relay:
`POST /api/token` → `GET /api/directory` (paginated) → for each discovered outbox
`GET /api/sync/heads` + `GET /api/sync/range` (paginated). On a phone this is a burst
of ~10+ requests that (a) is slow (serial round-trips) and (b) trips the per-IP rate
limit (`/api/token` 429s after ~8), which is exactly what dropped returning visitors to
an empty feed until the client-side retry band-aid (`selectRelaysResilient`).

`GET /api/boot` collapses that burst into **one cacheable request**. It is the single
biggest remaining latency + reliability win for the web app, and it makes the relay
essentially unthrottlable at boot because the response is a CDN/Caddy-cacheable blob.

## The endpoint
```
GET /api/boot?hot=1&limit=50            (no auth required — see Trust)
->
{
  "v": 1,
  "serverTime": 1783500000000,
  "directory": [                         // every outbox's signed head (== /api/directory heads)
    { "appId": "<hex64>", "version": 12, "head": { …signed head! record… } },
    …
  ],
  "hot": [                               // enough rows to render the default feed WITHOUT a follow-up read
    { "appId": "<hex64>",
      "rows": [ { "key": "v2!<okey>", "value": { …signed record… } }, … ] },
    …
  ],
  "seedOutboxes": ["<appId>", …],        // optional: which appIds the operator considers curated/pinned
  "truncated": false                     // true if `hot` was capped; client falls back to range reads for the rest
}
```

- `directory`: the same signed `head!<appId>` census the client already consumes from
  `/api/directory`, so the rollback floor + withholding audit keep working unchanged.
- `hot`: the rows needed for first paint — the pinned seed outboxes in full, plus the
  top-N most-recent rows per active outbox (operator picks the ranking; recency is fine).
  Cap the total (`limit`) and set `truncated` so the client range-reads the tail lazily.
- Everything in `hot` is a **signed record**; keys stay opaque (`v2!<okey>`), values stay
  sealed. The bundle leaks no more than the existing directory + range endpoints already do.

## Trust model (unchanged — this is an optimization, not a trust addition)
Every row the client accepts still goes through `admit()` (Ed25519 signature +
key-binding + PoW), exactly as with live gossip. So `/api/boot`:
- can **withhold** or serve **stale** rows → the client detects it via the signed-head
  census (`auditOutbox`) and cross-relay head comparison, same as any read today;
- can **never forge** a row for anyone — a bad/lying/cached `/api/boot` renders nothing
  it shouldn't.

Because responses are integrity-checked client-side, they are safe to cache **anywhere**.

## Caching (the reliability multiplier)
- `Cache-Control: public, max-age=10` (5–15s is plenty). A thundering herd of cold
  boots collapses to one origin computation per window; every client re-verifies, so a
  cache cannot lie. Put it behind Caddy on bern (or a CDN) and the per-IP limit becomes
  a non-issue for boot.
- **Exempt `/api/boot` from the tight `/api/token` per-IP limit** (or serve it
  pre-auth): reads of signed records don't need the write-path throttle. This is the
  root fix for the refresh-drop the client currently retries around.

## Client integration (peerit's side — I'll do this)
peerit already renders cache/snapshot first and connects in the background
(`instantBoot` + `connectRelaysInBackground`). `/api/boot` slots in as the **first**
background call in `_connectNet()`:
1. `GET /api/boot` (one request) → seed `directory` into the floor + register outboxes
   as content peers + prime `_peerViews` with the verified `hot` rows → `_emit()`.
2. Then the normal poll takes over (heads-gated incremental reads) for live updates.
3. If `/api/boot` 404s (old relay), fall back to the existing directory + range fan-out.
   Degrades gracefully; no hard dependency.

Net: a returning visitor renders from local cache in ~0ms (already shipped); a
first-ever visitor renders from the baked snapshot in ~0ms (already shipped); and the
live reconcile is now **one** cacheable request instead of a rate-limit-tripping burst.

## Acceptance
- One unauthenticated `GET /api/boot` returns enough to render the seed + default feed.
- `Cache-Control` set; a second identical request within the window is a cache hit.
- Client re-verifies every row (drop the signature on one → it's rejected, feed still renders the rest).
- Absent endpoint → client falls back to the current fan-out with no error.

## Scope split
- **bern (relay):** implement `GET /api/boot` on the outboxlog service; set caching; exempt it from the token rate limit (or serve pre-auth). Reuses the existing directory + range internals — it's an aggregating read, not new storage.
- **peerit (client, me):** wire it into `_connectNet()` with graceful fallback + a test that a tampered `hot` row is rejected. Ready to land the day the endpoint is up.
