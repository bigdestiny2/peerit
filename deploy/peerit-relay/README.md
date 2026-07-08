# Phase 1 — your VPS as the PRIMARY relay + a real 2-relay signed roster

This is the smallest, highest-leverage decentralization step from
[`../../docs/HIVERELAY-OUTBOXLOG-PLAN.md`](../../docs/HIVERELAY-OUTBOXLOG-PLAN.md):
turn peerit's signed roster from **one** relay into **two independent origins**,
with your VPS as relay #1. The instant the roster lists two reachable relays,
`js/relay-pool.js` activates cross-relay head reconciliation and read-recovery —
so seizing or lying with one relay no longer controls what a client sees. No
HiveRelay code required; it's a deploy + a re-sign + a rebuild.

The repo side is already done: [`../web-release.json`](../web-release.json) now
lists `https://153-75-89-206.sslip.io` (your VPS, **primary**) and the Render relay
(#2). Relay order = pool order = primary, and boot skips an unreachable relay, so
if the VPS is down at load the client falls back to Render automatically.

---

## 0. First: rotate the VPS root password

The root password was shared into a chat, so treat it as burned. On the box:
`passwd`, then set up SSH keys and `PasswordAuthentication no`. A root box on a
public IP is scanned within minutes.

## 1. Deploy the relay (on the VPS — your steps; I can't use your credentials)

Prereqs: Docker + Compose on the VPS; ports 80 + 443 open. **No domain needed** —
`153-75-89-206.sslip.io` already resolves to `153.75.89.206`, and Caddy gets a real
Let's Encrypt cert for it.

```sh
# on the VPS, in a copy of this deploy/peerit-relay/ directory
git clone <your peerit-relay repo> ./peerit-relay     # zero npm deps; just source
cp .env.example .env
#   set PEERIT_RELAY_SECRET  ->  openssl rand -hex 32   (keep it stable + secret)
#   set PEERIT_RELAY_ORIGINS ->  your web origin (e.g. https://peerit.site)
docker compose up -d
docker compose logs -f caddy        # watch the cert issue (a minute or two)
```

Verify from anywhere:
```sh
curl -s -o /dev/null -w '%{http_code}\n' https://153-75-89-206.sslip.io/api/health   # 200/401 = alive
curl -s -X POST https://153-75-89-206.sslip.io/api/token | head -c 80                 # issues a token
```

## 2. Re-sign the roster + rebuild the web bundle (needs your offline seed)

`deploy/web-release.json` already declares both relays. Signing needs the private
seed for the pinned key `f7441ced…` — which only you hold. From `02-apps/peerit`:

```sh
PEERIT_ROSTER_SEED=<your 32-byte hex seed> npm run web:release
```

This signs `relay-roster.json` to match the 2-relay config, rebuilds `web/`, and
verifies the meta tags, manifest, SW pins, and roster hash all agree. If the seed
doesn't derive `f7441ced…`, either use the correct seed or rotate: generate a new
key, set `pinnedRosterKey` in `deploy/web-release.json` to the new public key, and
re-run — the new key flows into `index.html` automatically.

> Don't have the seed and don't want to rotate? You can also sign from the relay
> repo: `PEERIT_ROSTER_SEED=<seed> npm run roster:sign -- --relay https://153-75-89-206.sslip.io --relay https://peerit-relay.onrender.com --out ../peerit/relay-roster.json`, then `npm run web:release` (no seed) to verify + build.

## 3. Ship

Publish `web/` the usual way (`npm run ship:live`, or host `web/` on your origin).

## 4. Confirm the pool is live (both relays)

After the site is live, load it and check the boot picks up two relays:
```js
// in the site's devtools console
window.__peerit && window.__peerit.sync.status().then(console.log)
```
You should see the pool select 2 relays (VPS primary). Kill the VPS relay
(`docker compose stop peerit-relay`), reload — the app should still work off Render
and the boot log should show the fallback. That is "seize one relay, lose nothing"
working for reads. (Writes fan out to both; non-primary is best-effort async.)

---

## What this does and doesn't buy (honest)

- **Buys:** cross-relay rollback/strip detection goes live (`relay-pool.js` `crossHead`/`recoverRows`), the single-Render chokepoint is gone, and content lives on two independent operators.
- **Doesn't buy yet:** the roster URL + the JS bundle are still served from one web origin — block that and the app can't boot regardless of relay count. Mitigation (later): inline the signed roster into the bundle + distribute the code via IPFS/mirrors. And cross-relay write durability is best-effort-async (`fanoutAppend` awaits only the primary), so a write can "succeed" before it reaches relay #2.
- **Public forum, honest framing:** this relay stores plaintext — that's the accepted tradeoff for a public forum. Your liability posture rests on **decentralization + pseudonymity**, not on the operator being unable to read content. Blind mode (Phase 4) is for private namespaces only.

## Upgrade path

- Swap sslip.io for a domain you own: change `RELAY_DOMAIN` in `.env` + the relay URL in `deploy/web-release.json`, re-sign, rebuild.
- Add a 3rd independent operator (another VPS, or a HiveRelay `dht-relay-ws` once exposed) to the roster for deeper redundancy.
- Move to `PEERIT_RELAY_CORE=hypercore` (DHT-replicated, needs `npm i` in the relay image) when you want relays to replicate to each other over the swarm rather than only via client fan-out.
