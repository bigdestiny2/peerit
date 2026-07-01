# peerit in-browser DHT relay (self-host on a VPS)

A `wss://` WebSocket relay that lets a **normal browser** run a real HyperDHT +
Noise session against the public Holepunch DHT. It is a **blind byte pipe** — it
forwards encrypted frames and never sees peerit content, plaintext, or keys. It is
NOT an `/api` relay and holds no data; it only bridges the browser onto the DHT so
peers replicate directly. See [`../../docs/WEB-DEPLOYMENT.md`](../../docs/WEB-DEPLOYMENT.md) (Phase 3) for how it fits.

peerit's web build uses this **best-effort, with the `/api` relay as automatic
fallback** — if the DHT relay is down or blocked, the app keeps working over `/api`.

## What you provide

- A VPS with a public IPv4 (and ideally IPv6), ports **80** and **443** open.
- **Docker + Docker Compose** on it.
- A **domain you control** with a DNS record pointing at the VPS (e.g.
  `dht.peerit.example → <VPS IP>`). TLS needs a real hostname (Let's Encrypt).

## Deploy

```sh
# on the VPS, in this directory
cp .env.example .env
$EDITOR .env                       # set DHT_RELAY_DOMAIN + ACME_EMAIL
docker compose up -d --build       # builds the relay image, starts Caddy + relay
docker compose logs -f caddy       # watch the cert get issued (a minute or two)
```

Caddy fetches a Let's Encrypt cert for `DHT_RELAY_DOMAIN` on first start and renews
it automatically. The relay speaks plain `ws` on the private compose network only;
all public traffic is `wss://` terminated by Caddy.

## Verify

```sh
# 1. TLS + Caddy are up (200/301/404 all prove the cert works):
curl -sSI https://$DHT_RELAY_DOMAIN | head -3

# 2. WebSocket upgrade reaches the relay (expects "101 Switching Protocols"):
curl -sSI -o /dev/null -w '%{http_code}\n' \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://$DHT_RELAY_DOMAIN

# 3. relay logs show connections opening as browsers join:
docker compose logs -f dht-relay
```

## Point peerit at it

Once `wss://$DHT_RELAY_DOMAIN` is live, build the web bundle against it and ship:

```sh
cd ../..                            # 02-apps/peerit
npm run dht:deps && npm run dht:bundle
node build-web.mjs --relay https://peerit-relay.onrender.com --readonly false \
  --dht-relay wss://dht.peerit.example --drive-key <hyper-key>
# then publish web/ to peerit.site as usual
```

The bundle already prefers the DHT transport when the `peerit-dht-relay` meta is
present and falls back to `/api` otherwise (`js/app.js` boot).

## Operational notes

- **Keep the `caddy_data` volume.** It holds the issued certs; deleting it forces
  re-issuance and can hit Let's Encrypt rate limits.
- **`@hyperswarm/dht-relay@0.4.3`** is the only published version and is marked
  do-not-use-in-production upstream. That's why peerit keeps this path best-effort
  with `/api` fallback. Run more than one relay + list them if you want redundancy.
- **Update:** `docker compose pull && docker compose up -d --build`.
- **Stop:** `docker compose down` (keeps volumes) — add `-v` only if you intend to
  discard the certs.

## Alternative: no Docker (systemd + certbot)

If you'd rather not use Docker, run the relay directly and let it terminate TLS
with a certbot cert (the binary supports `--cert`/`--key`):

```sh
npm i @hyperswarm/dht-relay@0.4.3
certbot certonly --standalone -d dht.peerit.example      # gets fullchain.pem + privkey.pem
node node_modules/@hyperswarm/dht-relay/bin.js --host 0.0.0.0 --port 443 \
  --cert /etc/letsencrypt/live/dht.peerit.example/fullchain.pem \
  --key  /etc/letsencrypt/live/dht.peerit.example/privkey.pem
```

Wrap that in a systemd unit (`Restart=always`) and add a certbot renewal hook that
restarts the service. The Docker+Caddy path above automates cert renewal for you.
