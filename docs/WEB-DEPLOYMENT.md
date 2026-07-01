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
| **2 — hardened delivery** | `build-web.mjs` (SRI, Service Worker `sw.js`, `asset-manifest.json`, `verify.html`), signed relay roster, boot-time multi-relay failover | ✅ built; signed roster + failover covered by Node e2e/unit tests, browser smoke still recommended per deploy |
| **3 — in-browser DHT pipe** | `js/dht-adapter.js` (maps hypercore stack → pear surface, **adapter logic unit-tested** via `test/dht-adapter.mjs`), `js/dht-transport.js` (wires the real deps), `js/ra-idb.js` (durable IndexedDB, `test/ra-idb.mjs`), boot wiring + `build-web --dht-relay` | ✅ wire validated on a testnet DHT (`test:dht-live`) AND in a real browser (Brave) against a local dht-relay — WASM crypto, `global`/`Buffer`/`process` shims, WS pipe, and durable IndexedDB outbox (persists across reload) all confirmed. ⬜ remaining: public `wss://` dht-relay end-to-end between two browsers |

## Build & serve the web bundle

```sh
# produce web/ — relay can be an absolute URL, a comma-separated failover list,
# or "same-origin" (relay proxied under peerit.com/api/*, no CORS)
node build-web.mjs --relay https://relay.peerit.com --readonly false \
  --relay-roster relay-roster.json --relay-roster-key <roster signing pubkey> \
  --drive-key <the published hyper:// key>

# local end-to-end (what the browser test does):
#   1) relay:  cd ../peerit-relay && PEERIT_RELAY_ORIGINS=http://127.0.0.1:8780 node relay.mjs
#   2) bundle: node build-web.mjs --relay same-origin --readonly true --drive-key <key>
#   3) serve:  node web-serve.mjs           # proxies /api/* → the relay, serves web/ on :8780
```

The exported `index.html` gets the relay `<meta>`, SRI on the entry module +
stylesheet, and a Service Worker that pins the audited bundle by SHA-256
(so the app survives the origin going down and global JS swaps are detectable).

## Signed relay roster

The static `<meta name="peerit-relay">` remains a bootstrap fallback. For normal
deploys, publish a signed roster so clients can prefer the current relay fleet
without trusting DNS, the relay, or the roster host:

```json
{
  "payload": {
    "version": 1,
    "expires": "2026-12-31T00:00:00.000Z",
    "relays": ["https://relay-a.peerit.com", "https://relay-b.peerit.com"]
  },
  "signature": {
    "alg": "Ed25519",
    "key": "<64-hex public key pinned in index.html>",
    "sig": "<128-hex signature over peerit-relay-roster-v1|canonical(payload)>"
  }
}
```

Generate it offline from the relay package:

```sh
cd 02-apps/peerit-relay
npm run roster:sign -- --generate-key
PEERIT_ROSTER_SEED=<seed from offline key storage> npm run roster:sign -- \
  --relay https://relay-a.peerit.com --relay https://relay-b.peerit.com \
  --expires 2026-12-31T00:00:00.000Z --out ../peerit/relay-roster.json
```

Build with `--relay-roster relay-roster.json --relay-roster-key <public key>`.
At boot, a normal browser verifies the roster key + expiry, tries the signed
relays in order, obtains a first-visit token from the first reachable relay, and
falls back to the baked `peerit-relay` list if the roster is unavailable or bad.

## Deploy checklist (operator — these are your steps, not the code's)

1. **Relay:** deploy `02-apps/peerit-relay` (see its README) behind TLS at
   `relay.peerit.com`, or proxy it same-origin at `peerit.com/api/*`. Run more
   than one; put the fleet in `relay-roster.json`, and keep `--relay` as a
   conservative bootstrap fallback.
2. **Seeders:** run `02-apps/peerit-seeder` so outboxes stay available offline.
3. **Code:** host `web/` on peerit.com; also pin to IPFS (DNSLink), Arweave, and
   set ENS `peerit.eth` contenthash → CID so the app survives DNS/registrar seizure.
4. **Verify path:** publish the `hyper://` drive (`KEEP=1 node publish.mjs`) and put
   its key in `--drive-key`; `peerit.com/verify.html` lets anyone cross-check.

## Manual validation still required

- Failover is boot-time selection: the client chooses the first reachable relay
  before opening its gossip bridge. If the active relay dies mid-session, the
  user should reload to re-run selection; live migration of an already-open
  SSE/swarm channel is intentionally out of this hardening pass.
- Validate the production relay fleet behind real TLS/CORS, shared
  `PEERIT_RELAY_SECRET`, and reverse-proxy headers. CI proves the HTTP/SSE
  contract and failover flow against local relays, not public network routing.
- Validate cross-relay data availability with the hypercore production core and
  seeders online. The memory e2e proves browser convergence through one selected
  relay; real multi-region liveness still depends on the deployed DHT/seeder
  topology.

## Phase 3 build recipe (when ready to validate on a network)

The adapter (`js/dht-adapter.js`) is unit-tested and the boot wiring is already in
place — boot dynamically imports `./dht-bundle.js` and prefers the DHT transport
when a `<meta name="peerit-dht-relay">` is present, falling back to the `/api`
relay otherwise. Remaining is to build the bundle and validate on a live network:

```sh
cd 02-apps/peerit
# CRITICAL version pin (2026-07-01): corestore ~6.x + hypercore ~10.x — the
# random-access era. Unpinned `npm i corestore` grabs 7.x, whose hypercore-storage
# is Node-file-oriented (fs/path/rocksdb) and will NOT browser-bundle. Also needs
# sodium-javascript (the WASM crypto fallback for browsers).
npm run dht:deps          # installs the pinned heavy deps (one --no-save command)
npm run dht:bundle        # esbuild → js/dht-bundle.js. Build to the repo-root js/
                          # FIRST so build-web copies it into web/js/ with a
                          # matching SW manifest hash. The script carries the four
                          # browser fixes (see below): --define:global=globalThis,
                          # --inject:node-shims.mjs (Buffer + process).
node build-web.mjs --relay https://relay.peerit.com --readonly false \
  --dht-relay wss://dht-relay.peerit.com --drive-key <key>
# build-web AUTO-RELAXES the web build's CSP when --dht-relay is set:
# script-src += 'wasm-unsafe-eval' (WASM crypto), connect-src += ws: wss:
# (WebSocket to the dht-relay). The PearBrowser index.html + the /api-only web
# build keep the strict CSP untouched.
```

**Hosting the `wss://` dht-relay:** [`deploy/dht-relay/`](../deploy/dht-relay/) is a
self-contained bundle (Docker Compose: the `@hyperswarm/dht-relay` binary behind
Caddy for automatic Let's Encrypt `wss://` + WebSocket passthrough). Point a
subdomain at a VPS, set `.env`, `docker compose up -d --build`, then pass the
resulting `wss://` URL to `build-web.mjs --dht-relay`. The relay is a blind byte
pipe — it never sees content or keys. Runbook in [`deploy/dht-relay/README.md`](../deploy/dht-relay/README.md).

**Four browser-only gaps a Node/testnet test can't catch (all fixed, browser-validated 2026-07-01):**
1. **CSP** — strict `script-src 'self'` throws `WebAssembly.Module() violates 'unsafe-eval'`; `connect-src` needs explicit `ws:`/`wss:` (http/https don't cover them). Fixed by `build-web.mjs` `relaxCspForDht`, gated on `--dht-relay`.
2. **`global` undefined** — HyperDHT reads `global.Pear?.config` eagerly at load. Fixed by esbuild `--define:global=globalThis`.
3. **`Buffer`/`process`** — unguarded global uses (`process.nextTick` in hypercore's close path). Fixed by esbuild `--inject:node-shims.mjs`.
4. **`random-access-web@2.0.3` has no `truncate`** (RAS@1 API; hypercore@10 requires it). **Fixed** by `js/ra-idb.js` — a self-contained durable IndexedDB backend on `random-access-storage@3` (the base hypercore@10 + `random-access-memory@6` use), classic block model, real `_truncate`. `dht-transport.js` uses it (RAM only if `indexedDB` is entirely unavailable). Unit-tested by `test/ra-idb.mjs` (16 checks incl. reopen-persistence) and browser-verified (outbox persists across reload, no truncate error).

**Validation status (2026-07-01):**
- ✅ **bundle builds clean** (~1.2 MB) with the pinned versions — no `fs`/`path`.
- ✅ **wire VALIDATED on a local testnet DHT** — `npm run test:dht-live`
  (`test/dht-live.mjs`) runs two real `BridgeGossipSync` peers over the real
  corestore + hyperswarm + protomux + hypercore-replication stack on a
  `@hyperswarm/testnet` DHT: descriptor gossip frames correctly with
  `compact-encoding.raw`, outbox hypercores replicate over Noise, and they converge
  bidirectionally. The codec fix + adapter are correct on the real wire.
- ✅ **browser runtime VALIDATED (2026-07-01, Brave):** served the esbuilt bundle
  against a LOCAL `@hyperswarm/dht-relay` (`ws://127.0.0.1`). The browser took the
  DHT path (`[peerit] using in-browser DHT transport`), instantiated the WASM crypto
  (CSP fix), resolved `global`/`Buffer`/`process` (esbuild fixes), created the local
  identity + outbox hypercore in-browser on DURABLE IndexedDB (`js/ra-idb.js`, no
  truncate error, no in-memory fallback), and held an ESTABLISHED WebSocket to the
  dht-relay (confirmed host-side via `lsof`). The app UI rendered and ran on the DHT
  transport; a reload reopened the same identity + outbox cleanly from IndexedDB.
- ⬜ **still to validate:** a PUBLIC `wss://` dht-relay (TLS) + the public HyperDHT
  end-to-end between two independent browsers. The protocol, the browser runtime,
  durable storage, and the WS pipe are proven; public hosting is the remaining step.

Live-path caveats:
- ✅ **fixed in code (2026-07-01):** the protomux descriptor codec is now
  dependency-injected — `dht-transport.js` passes `compact-encoding`'s `raw` to
  `dht-adapter.js` (`createHyperPearSurface({… codec})`); the in-memory fake still
  uses the pass-through default, so `test/dht-adapter.mjs` stays green. No hand-patch
  needed before bundling.
- ⚠ still needs LIVE validation on a real DHT (Noise handshake + hypercore replication
  timing + hole-punch) — the fakes model replication as a shared registry, not the wire.
- `@hyperswarm/dht-relay` is pinned old on npm and marked do-not-use-in-production — pin
  to maintained HEAD and own the risk; watch in-browser Hyperbee memory. **Keep this a
  best-effort path with `/api`-relay fallback (it already is); do not make it the default
  until validated.**

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
  signed roster; boot-time failover selects a reachable relay, while mid-session
  relay death still requires reconnect/reload.
- **Key durability:** a cleared browser loses the key unless the recovery bundle
  was backed up — made mandatory on first mint.
