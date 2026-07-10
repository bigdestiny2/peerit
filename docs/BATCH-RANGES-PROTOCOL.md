# Batch Range Reads — additive relay contract

**Status:** client implemented; relay deployment pending.

Peerit currently reads one complete author outbox at a time, then verifies every
row and audits the complete row set against that author's signed `head!` census.
That is correct but makes a cold refresh request-bound. This document specifies
an additive HTTP optimisation that reduces round trips without changing what the
client accepts.

## Capability

A relay may advertise the following in its authenticated bridge-status payload:

```json
{
  "batchRanges": {
    "schema": 1,
    "method": "POST",
    "route": "/api/sync/ranges",
    "enabled": true
  }
}
```

Peerit enables the endpoint only when all five fields match exactly. Missing,
unknown, or malformed capability data means normal `GET /api/sync/range` reads;
the client must never probe an older relay just to discover this feature.

## Request and response

`POST /api/sync/ranges` is token-gated exactly like the existing sync routes.
It accepts a bounded list of ordinary range reads:

```json
{
  "requests": [
    { "appId": "<author-pubkey>", "gt": "", "limit": 1000 }
  ]
}
```

The server returns exactly one reply per request, in any order:

```json
{
  "ranges": [
    {
      "appId": "<author-pubkey>",
      "rows": [{ "key": "…", "value": { "…": "…" } }]
    }
  ]
}
```

The server applies the same lexicographic `gt` and `limit` semantics as
`GET /api/sync/range`. Rows in each reply must be strictly ascending, must not
exceed the requested limit, and must contain no data the corresponding ordinary
range request would not return. Enforce server caps of at most 32 requests and
1,000 rows per request. The client paginates repeatedly until every outbox is
complete, with its existing 50,000-row per-outbox ceiling.

## Non-negotiable safety properties

- This endpoint is content-blind and read-only. It neither writes nor interprets
  Peerit records.
- A response is transport data, not proof. Peerit still verifies each record
  signature/key binding and audits the **complete** result against the
  author-signed head census.
- A malformed response, a missing requested app ID, duplicate app ID, unordered
  page, or response failure makes the client discard the whole batch and use
  the established per-outbox paginated reader.
- Existing head-floor rollback checks and cross-relay recovery are unchanged.

## Relationship to selective community discovery

This makes a known set of author outboxes cheaper to fetch. It does **not** by
itself discover that set. The present signed `member!<community>!<author>` edge
is held in the member's own opaque outbox; it is not a shared roster cell and
cannot safely be treated as one.

A true O(members-of-community) cold boot needs a separate relay-backed,
author-independent roster CRDT: self-signed member entries, owner-bound merge
by member public key, tombstone-wins LWW semantics, and a directly fetchable
opaque community slot. That needs an explicit HiveRelay implementation and
adversarial tests before Peerit uses it for completeness-sensitive discovery.
Until then, directory discovery remains the correctness fallback and Peerit must
not claim that manifests or the batch endpoint eliminate its O(authors)
cold-start ceiling.
