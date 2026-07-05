# Public BlindShard cohort — run shard-store relays for peerit

This deploys one or more **HiveRelay shard-store relays**: content-addressed
blind blob stores that hold PVSS key shares (and, once peerit's ciphertext-off-VPS
path lands, the ciphertext blobs). Each relay stores opaque shards it cannot
read, link to a post, or reconstruct alone.

> **Honest scope:** running multiple relays yourself is a **mechanism/deployment**
> proof, not the independence property. For real collusion-resistance you need
> ≥3 independent legal entities running relays they alone control. See
> [`docs/RELAY-OPERATOR-RECRUITMENT.md`](../../docs/RELAY-OPERATOR-RECRUITMENT.md).

---

## Prerequisites

- Docker + Docker Compose on the host.
- A public IP and either a domain or `sslip.io` address.
- A local clone of `P2P-Hiverelay` checked out to the `feat/local-shard-cohort`
  branch (the shard-store plugin + ciphertext-off-VPS support is not yet merged
  to `main`).
- `git`, `openssl`, and a shell.

---

## 1. Build the HiveRelay image with shard-store support

From the **Hiverelay repo root** (`P2P-Hiverelay`, `feat/shard-store` branch):

```sh
git checkout feat/local-shard-cohort
docker build -t hiverelay:shard-store .
```

This produces a local image tagged `hiverelay:shard-store` that the Compose
file below uses.

---

## 2. Configure this host

Copy the example env and edit it:

```sh
cd deploy/shard-cohort
cp .env.example .env
# edit .env: set RELAY_DOMAIN, RELAY_API_KEY, PEERIT_ORIGIN, HIVERELAY_API_PORT
```

| Variable | What it does |
|---|---|
| `RELAY_DOMAIN` | Public domain, e.g. `shard-a.peerit.site` or `153-75-89-206.sslip.io`. |
| `RELAY_API_KEY` | Random 32-byte hex secret. The peerit **dealer** needs this to PUT shards; readers do not. |
| `PEERIT_ORIGIN` | Origin allowed to fetch shards from a browser, e.g. `https://peerit.site`. |
| `HIVERELAY_API_PORT` | Internal API port (default `9100`). Caddy forwards 443 → this. |
| `RELAY_INDEX` | 0-based index for this relay (used for storage path). |
| `HIVERELAY_STORAGE` | Persistent host path for relay data. |

---

## 3. Start the relay

```sh
docker compose up -d
```

Caddy will issue a Let's Encrypt certificate for `RELAY_DOMAIN` and expose:

- `POST /api/v1/shard` — store a shard (needs `X-Shard-Pin` + relay API key for PUT auth).
- `GET  /api/v1/shard/<hash>` — fetch a shard by content address (hash-knowledge read capability).
- `GET  /health` — liveness.

Verify from anywhere:

```sh
curl -s https://$RELAY_DOMAIN/health
```

---

## 4. Add the relay to peerit's shard roster

After the relay has started once, extract its pubkey from storage:

```sh
node deploy/shard-cohort/extract-pubkey.mjs \
  /path/to/relay/storage \
  https://shard-a.peerit.site \
  $RELAY_API_KEY
```

Once you have N entries, assemble the roster:

```json
{
  "threshold": 2,
  "retainMs": 2592000000,
  "relays": [
    { "baseUrl": "https://shard-a.peerit.site", "pubkey": "...", "apiKey": "..." },
    { "baseUrl": "https://shard-b.peerit.site", "pubkey": "...", "apiKey": "..." },
    { "baseUrl": "https://shard-c.peerit.site", "pubkey": "...", "apiKey": "..." }
  ]
}
```

- **Public reader roster** (commit to peerit): `config/shard-roster.public.json` —
  includes only `baseUrl` and `pubkey`, no `apiKey`.
- **Dealer roster** (kept outside git, e.g. `~/.hiverelay-shard-cohort/roster.json`):
  includes `apiKey`s so the node dealer can PUT shards.

Update `deploy/web-release.json`:

```json
"shardRoster": "config/shard-roster.public.json"
```

Then rebuild and ship:

```sh
npm run web:release
npm run ship:check   # or ship:live
```

---

## 5. Prove the cohort live

From peerit:

```sh
node scripts/reader-bundle-live.mjs ~/.hiverelay-shard-cohort/roster.json
```

This disperses a seed body to the cohort and reconstructs it with the browser
reader bundle. Once that passes, the cohort is live for peerit.

---

## Operator recruitment

To get real independence, hand this same `deploy/shard-cohort/` directory to an
arms-length operator and have them:

1. Run it on **their** infra, **their** domain, **their** payment trail.
2. Send you their `baseUrl` and `pubkey` (keep `apiKey` to themselves if they
   want to be the only one who can PUT to their relay, or share it with the
   dealer if they trust the peerit operator).
3. Sign the minimal independence checklist in
   [`docs/RELAY-OPERATOR-RECRUITMENT.md`](../../docs/RELAY-OPERATOR-RECRUITMENT.md).

---

## Upgrade path

- **Ciphertext-off-VPS:** once peerit's `data.js` writes the ciphertext blob to
  the shard cohort instead of the outbox, the relay's outbox holds only the
  keyless manifest — the body bytes live on the shard cohort.
- **Independent operators:** replace same-owner relays one-by-one by re-signing
  the roster without them and adding the new operator's URL.
