# Running peerit on a normal browser (peerit.com) — censorship-resistant

peerit is built for PearBrowser (a `hyper://` site with `window.pear`). This
describes the additive path for serving it from a normal DNS so any browser can
use it, **without weakening the PearBrowser build and without trusting the
server with your identity or your content's integrity.**

## The one principle

**Keys, signing, and verification stay in the browser; every gateway/relay is an
untrusted availability provider — it can withhold or reorder, but can never
forge, tamper, or impersonate.** peerit already enforces this: authenticity is an
Ed25519 signature verified client-side at merge (`js/verify.js` + `js/gossip.js`
`admit`), with proof-of-work re-checked at ingest. The web build signs **locally**
(`forceDev` → `DevIdentity`/SubtleCrypto) and never delegates to the server.

```
browser (keys + verify)  ──HTTP/SSE──►  relay (untrusted)  ──Hyperswarm──►  seeders · PearBrowser peers · other relays
       signs locally                   withholds, can't forge               the real P2P network
```

## Does this affect the PearBrowser P2P build? No.

The web path is a **fallback branch reached only when there is no host bridge**
(`js/runtime.js` `resolveRuntime`). With `window.pear` injected (desktop) or a
host `pear-api-token` (mobile), peerit uses the host path with host-held keys —
**even if a relay `<meta>` is present in the same `index.html`**. `forceDev` is
applied to *identity only*, never to sync, so the web build signs locally while
still using the real relay transport. Locked by `test/runtime.mjs`. The
deterministic `hyper://` key is unchanged, so the live drive + installs keep
working — the web is additive publishing.

## Three layers

| layer | how | censorship-resistance |
|---|---|---|
| **code delivery** | static export to peerit.com + IPFS/ENS/Arweave; SRI + Service-Worker pin; `/verify` | tampering detectable; survives one gateway/DNS dying |
| **data transport** | untrusted relay speaking peerit's `/api/*` (Phase 1) → in-browser DHT pipe (Phase 3) | relay withholds, never forges; seeders keep data available |
| **identity / keys** | browser-local Ed25519 (`forceDev`), recovery-bundle backup | relay can never sign as a user; forgeries dropped at merge |

## Phase status

| phase | what | status |
|---|---|---|
| **0 — read-only verified mirror** | runtime dispatch, read-only UI + banner, static export | ✅ built, browser-verified |
| **1 — relay + local keys (full app)** | `02-apps/peerit-relay` (token, CORS, rate-limit, swarm hub, memory + hypercore cores), client token acquisition + write path | ✅ built; Node e2e over real HTTP + browser `gossip-bridge` verified |
| **2 — hardened delivery** | `build-web.mjs` (SRI, Service Worker `sw.js`, `asset-manifest.json`, `verify.html`), multi-relay failover | ✅ built, browser-verified; signed relay roster = remaining hardening |
| **3 — in-browser DHT pipe** | `js/dht-adapter.js` (maps hypercore stack → pear surface, **adapter logic unit-tested** via `test/dht-adapter.mjs`), `js/dht-transport.js` (wires the real deps), boot wiring + `build-web --dht-relay` | ⚠ adapter tested + wired; the real DHT/Noise/protomux wire + esbuild bundle need live validation |

## Build & serve the web bundle

```sh
# produce web/ — relay can be an absolute URL, a comma-separated failover list,
# or "same-origin" (relay proxied under peerit.com/api/*, no CORS)
node build-web.mjs --relay https://relay.peerit.com --readonly false \
  --drive-key <the published hyper:// key>

# local end-to-end (what the browser test does):
#   1) relay:  cd ../peerit-relay && PEERIT_RELAY_ORIGINS=http://127.0.0.1:8780 node relay.mjs
#   2) bundle: node build-web.mjs --relay same-origin --readonly true --drive-key <key>
#   3) serve:  node web-serve.mjs           # proxies /api/* → the relay, serves web/ on :8780
```

The exported `index.html` gets the relay `<meta>`, SRI on the entry module +
stylesheet, and a Service Worker that pins the audited bundle by SHA-256
(so the app survives the origin going down and global JS swaps are detectable).

## Deploy checklist (operator — these are your steps, not the code's)

1. **Relay:** deploy `02-apps/peerit-relay` (see its README) behind TLS at
   `relay.peerit.com`, or proxy it same-origin at `peerit.com/api/*`. Run more
   than one and list them comma-separated in `--relay` for failover.
2. **Seeders:** run `02-apps/peerit-seeder` so outboxes stay available offline.
3. **Code:** host `web/` on peerit.com; also pin to IPFS (DNSLink), Arweave, and
   set ENS `peerit.eth` contenthash → CID so the app survives DNS/registrar seizure.
4. **Verify path:** publish the `hyper://` drive (`KEEP=1 node publish.mjs`) and put
   its key in `--drive-key`; `peerit.com/verify.html` lets anyone cross-check.

## Phase 3 build recipe (when ready to validate on a network)

The adapter (`js/dht-adapter.js`) is unit-tested and the boot wiring is already in
place — boot dynamically imports `./dht-bundle.js` and prefers the DHT transport
when a `<meta name="peerit-dht-relay">` is present, falling back to the `/api`
relay otherwise. Remaining is to build the bundle and validate on a live network:

```sh
cd 02-apps/peerit
npm i @hyperswarm/dht-relay hyperswarm corestore hyperbee protomux b4a random-access-web compact-encoding
npx esbuild js/dht-transport.js --bundle --format=esm --outfile=web/dht-bundle.js
node build-web.mjs --relay https://relay.peerit.com --readonly false \
  --dht-relay wss://dht-relay.peerit.com --drive-key <key>
```

Live-path caveats to fix before relying on it (called out in the code):
- protomux message `encoding` must be a real compact-encoding codec (`require('compact-encoding').raw`), not the pass-through the in-memory fake uses.
- `@hyperswarm/dht-relay` is pinned old on npm and marked do-not-use-in-production — pin to maintained HEAD and own the risk; watch in-browser Hyperbee memory.

## Honest limits (what the web can never match vs PearBrowser)

- **Origin-ships-JS:** a normal browser re-downloads and trusts peerit.com's JS
  every visit; a compromised origin can serve targeted backdoored JS to one IP
  and read the in-browser key. Content-addressing + SRI + SW pinning + `/verify`
  make *global* tampering detectable, but can't protect a casual visitor on first
  hit. peerit.com keeps records **unforgeable**; it can't prove the JS you ran is
  the audited JS. High-assurance users: install PearBrowser.
- **Privacy:** a clearnet origin sees your IP; any relay learns peer IPs (WebRTC
  can leak local IPs). Mitigate with no-log relays + an onion mirror + TURN-only
  ICE — none reach PearBrowser parity.
- **Liveness:** the relay (+ its DNS) is a chokepoint that can be blocked or
  pressured (it can withhold, never forge). Mitigate with multiple relays + a
  signed roster.
- **Key durability:** a cleared browser loses the key unless the recovery bundle
  was backed up — made mandatory on first mint.
