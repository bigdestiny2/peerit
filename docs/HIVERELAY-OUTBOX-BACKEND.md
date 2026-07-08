# HiveRelay outboxlog backend (B3)

peerit's browser bridge can be pointed at a **HiveRelay `outboxlog` service** instead
of the bespoke `peerit-relay`. The two are **wire-identical** — same `/api/token`,
`/api/sync/*`, `/api/directory`, `/api/swarm/*` — so retiring `peerit-relay` in favour
of HiveRelay is an **endpoint swap**, not a protocol change. (Proven end-to-end by
`npm run proof:hiverelay-outboxlog`.)

B3 makes that swap **explicit, verifiable, and default-off**.

## How to build against a HiveRelay outboxlog relay

```sh
node build-web.mjs \
  --relay https://<your-hiverelay-outbox-url> \
  --relay-backend hiverelay-outbox
```

- `--relay <url>` is unchanged: it is still the relay base URL the browser talks to,
  and `scripts/csp.mjs` still pins that origin in the CSP `connect-src`. You do **not**
  need any new CSP or transport wiring — the HiveRelay URL is a normal relay origin.
- `--relay-backend <kind>` is the new, purely descriptive flag. Valid kinds:
  - *(unset / empty)* — the default. **Behaviour is byte-identical to before this flag
    existed.** No `peerit-relay-backend` meta is injected and no boot probe runs.
  - `peerit-relay` — records that the relay is the bespoke peerit-relay. No probe.
  - `hiverelay-outbox` — records that the relay is a HiveRelay outboxlog service, and
    turns on the boot probe below.

The flag can also be set via env `PEERIT_RELAY_BACKEND=hiverelay-outbox` or via
`deploy/web-release.json` `"relayBackend": "hiverelay-outbox"`. An unknown value is a
hard build error. The chosen kind is recorded in `web/asset-manifest.json`
(`webRelease.relayBackend`) so an auditor can see what the build was configured for.

When set (and `--relay` is present), the build injects:

```html
<meta name="peerit-relay-backend" content="hiverelay-outbox">
```

next to the existing `<meta name="peerit-relay">`.

## The boot probe (`hiverelay-outbox` only)

When `relayBackend === 'hiverelay-outbox'`, once a relay token is available at boot,
the app calls `probeRelayBackend()` (js/pear-api.js) **once**. It does a token-gated
`GET <relay>/api/bridge/status` and expects JSON `{ ready: true, service: 'outboxlog' }`.

If the relay does **not** report `service === 'outboxlog'` (e.g. the URL points at a
bespoke peerit-relay, which answers `/api/bridge/status` without a `service` field, or
at the wrong host), the app emits a single warning and **keeps booting**:

```
[peerit] configured hiverelay-outbox backend but relay /api/bridge/status did not report service=outboxlog — check the relay URL
```

This is a **visible sanity check, not a gate**: a mismatch, a 500, a parse error, or a
network failure all degrade to the warning (or nothing) — boot is never blocked and the
app is never hard-crashed. The probe never throws and never logs the token.

## Default-off guarantee

With `--relay-backend` absent (or `peerit-relay`), nothing new happens: no extra meta,
no probe, no warning. The served bundle (index.html + all JS) is byte-identical to a
build made before B3 existed; only `asset-manifest.json` gains a descriptive
`webRelease.relayBackend: ""` record.
