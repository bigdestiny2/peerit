# Running peerit on a normal browser (peerit.site) — censorship-resistant

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
| **code delivery** | static export to peerit.site + IPFS/ENS/Arweave; SRI + Service-Worker pin; `/verify` | tampering detectable; survives one gateway/DNS dying |
| **data transport** | untrusted relay speaking peerit's `/api/*` (Phase 1) → in-browser DHT pipe (Phase 3) | relay withholds, never forges; seeders keep data available |
| **identity / keys** | browser-local Ed25519 (`forceDev`); passphrase-encrypted identity export to move/back up the key | relay can never sign as a user; forgeries dropped at merge |

## Phase status

| phase | what | status |
|---|---|---|
| **0 — read-only verified mirror** | runtime dispatch, read-only UI + banner, static export | ✅ built, browser-verified |
| **1 — relay + local keys (full app)** | `02-apps/peerit-relay` (token, CORS, rate-limit, swarm hub, memory + hypercore cores), client token acquisition + write path | ✅ built; Node e2e over real HTTP + browser `gossip-bridge` verified |
| **2 — hardened delivery** | `build-web.mjs` (SRI, Service Worker `sw.js`, `asset-manifest.json`, `verify.html`), signed relay roster, boot-time multi-relay failover | ✅ built; signed roster + failover covered by Node e2e/unit tests, browser smoke still recommended per deploy |
| **3 — in-browser DHT pipe** | `js/dht-adapter.js` (maps hypercore stack → pear surface), `js/dht-transport.js` (wires the real deps), `build-web --dht-relay` (esbuilds the browser transport into `web/js/dht-bundle.js`) | ✅ build path smoke-tested; adapter tested; local testnet DHT wire test available; public browser+dht-relay deployment still needs operator validation |

## Build & serve the web bundle

```sh
# release path: validate/sign relay-roster.json, build web/, then prove that
# the bundle, pinned roster key, manifest drive key, and docs agree.
npm run web:release

# when rotating the relay fleet, edit deploy/web-release.json, then sign + build
# from the offline roster seed. The private seed is never committed.
PEERIT_ROSTER_SEED=<32-byte-hex-seed> npm run web:release

# local end-to-end (what the browser test does):
#   1) relay:  cd ../peerit-relay && PEERIT_RELAY_ORIGINS=http://127.0.0.1:8780 node relay.mjs
#   2) bundle: npm run build-web -- --relay same-origin --readonly true --no-relay-roster --drive-key <key>
#   3) serve:  node web-serve.mjs           # proxies /api/* → the relay, serves web/ on :8780
```

To point the build at a **HiveRelay `outboxlog`** relay instead of the bespoke
`peerit-relay`, add `--relay-backend hiverelay-outbox` (the wire is identical, so
`--relay` and the CSP pinning are unchanged). This is default-off and adds a
one-shot boot probe of `/api/bridge/status`. See
[HIVERELAY-OUTBOX-BACKEND.md](./HIVERELAY-OUTBOX-BACKEND.md).

The exported `index.html` gets the relay `<meta>`, SRI on the entry module +
stylesheet, and a Service Worker that pins the audited bundle by SHA-256
(so the app survives the origin going down and global JS swaps are detectable).
`build-web.mjs` reads [`deploy/web-release.json`](../deploy/web-release.json) by
default, validates the local signed roster against the pinned public key, copies
`relay-roster.json` into `web/`, and records the roster hash/key in
`asset-manifest.json`.

## Signed relay roster

The static `<meta name="peerit-relay">` remains a bootstrap fallback. For normal
deploys, publish a signed roster so clients can prefer the current relay fleet
without trusting DNS, the relay, or the roster host:

```json
{
  "payload": {
    "version": 1,
    "expires": "2026-12-31T00:00:00.000Z",
    "relays": ["https://relay-a.peerit.site", "https://relay-b.peerit.site"]
  },
  "signature": {
    "alg": "Ed25519",
    "key": "<64-hex public key pinned in index.html>",
    "sig": "<128-hex signature over peerit-relay-roster-v1|canonical(payload)>"
  }
}
```

The release source of truth is [`deploy/web-release.json`](../deploy/web-release.json):
it contains the bootstrap fallback relay list, the canonical roster payload, and
the public roster key pinned into `index.html`. The committed
[`relay-roster.json`](../relay-roster.json) must have the same canonical payload
and must be signed by that pinned key.

Generate or rotate it with the web release command:

```sh
PEERIT_ROSTER_SEED=<seed from offline key storage> npm run web:release
```

Without `PEERIT_ROSTER_SEED`, `npm run web:release` verifies the existing
`relay-roster.json` and fails if its signer, payload, expiry, or generated web
bundle does not match the config. At boot, a normal browser verifies the roster
key + expiry, tries the signed relays in order, obtains a first-visit token from
the first reachable relay, and falls back to the baked `peerit-relay` list if the
roster is unavailable or bad.

If the roster signing key itself must rotate, change `pinnedRosterKey` and sign
the new `relay-roster.json` in the same release. The guard treats any signer/key
drift outside that explicit config change as a publish blocker.

## Deploy checklist (operator — these are your steps, not the code's)

1. **Relay:** deploy `02-apps/peerit-relay` (see its README) behind TLS at
   `relay.peerit.site`, or proxy it same-origin at `peerit.site/api/*`. Run more
   than one; put the fleet in `deploy/web-release.json`, and keep
   `bootstrapRelays` as a conservative fallback.
2. **Seeders:** run `02-apps/peerit-seeder` so outboxes stay available offline.
3. **Code:** run `npm run ship:live`. It publishes the `hyper://` drive, writes
   the new key to `manifest.json`, then runs `npm run web:release` with that key
   so `web/asset-manifest.json` and `web/verify.html` cannot lag behind.
4. **Host/mirror:** host `web/` on peerit.site; also pin to IPFS (DNSLink),
   Arweave, and set ENS `peerit.eth` contenthash → CID so the app survives
   DNS/registrar seizure. `peerit.site/verify.html` lets anyone cross-check the
   web bundle against the published drive key.

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

## Phase 3 DHT build path

The checked-in `js/dht-bundle.js` is a fail-closed stub for non-DHT builds. When
`--dht-relay` is set, `build-web.mjs` now esbuilds `js/dht-transport.js` with the
pinned browser DHT dependency set, swaps that generated artifact into
`web/js/dht-bundle.js`, relaxes CSP for WASM crypto plus the exact relay
WebSocket origin, and hashes the generated bundle into `asset-manifest.json`.
Boot dynamically imports `./dht-bundle.js` and prefers the DHT transport when a
`<meta name="peerit-dht-relay">` is present, falling back to the `/api` relay
otherwise.

```sh
cd 02-apps/peerit
npm install               # installs the exact devDependency pins below
npm run dht:bundle        # optional direct bundle smoke helper
node build-web.mjs --relay https://relay.peerit.site --readonly false \
  --dht-relay wss://dht-relay.peerit.site --drive-key <key>
```

Exact pins used by the browser DHT bundle:
`@hyperswarm/dht-relay@0.4.3`, `corestore@6.18.4`, `hypercore@10.38.2`,
`hyperbee@2.27.3`, `hyperswarm@4.17.0`, `protomux@3.11.0`, `b4a@1.8.1`,
`compact-encoding@3.3.0`, `random-access-web@2.0.3`,
`random-access-memory@6.2.1`, `sodium-javascript@0.8.0`, `buffer@5.1.0`, and
`esbuild@0.24.2`.

Critical pin note (2026-07-01): keep `corestore` on 6.x and `hypercore` on 10.x,
the random-access-storage era. Unpinned `npm install corestore` can select newer
file-storage-oriented releases that pull Node `fs`/`path`/RocksDB code and will
not browser-bundle.

**Validation status (2026-07-01):**
- ✅ **DHT web build smoke:** `node test/dht-build.mjs` runs
  `build-web --dht-relay`, verifies the generated non-stub bundle is importable,
  checks DHT meta/CSP, and confirms `asset-manifest.json` pins the generated
  bundle hash.
- ✅ **wire VALIDATED on a local testnet DHT** — `npm run test:dht-live`
  (`test/dht-live.mjs`) runs two real `BridgeGossipSync` peers over the real
  corestore + hyperswarm + protomux + hypercore-replication stack on a
  `@hyperswarm/testnet` DHT: descriptor gossip frames correctly with
  `compact-encoding.raw`, outbox hypercores replicate over Noise, and they converge
  bidirectionally. The codec fix + adapter are correct on the real wire.
- ⬜ **still to validate on real hardware:** the browser runtime (IndexedDB via
  random-access-web, an actual WebSocket to a public `wss://` dht-relay, in-browser
  Hyperbee memory) + the public DHT. The testnet proved the protocol; the browser +
  dht-relay + public-DHT deployment is the remaining step.

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

- **Origin-ships-JS:** a normal browser re-downloads and trusts peerit.site's JS
  every visit; a compromised origin can serve targeted backdoored JS to one IP
  and read the in-browser key. Content-addressing + SRI + SW pinning + `/verify`
  make *global* tampering detectable, but can't protect a casual visitor on first
  hit. peerit.site keeps records **unforgeable**; it can't prove the JS you ran is
  the audited JS. High-assurance users: install PearBrowser.
- **Privacy:** a clearnet origin sees your IP; any relay learns peer IPs (WebRTC
  can leak local IPs). Mitigate with no-log relays + an onion mirror + TURN-only
  ICE — none reach PearBrowser parity.
- **Liveness:** the relay (+ its DNS) is a chokepoint that can be blocked or
  pressured (it can withhold, never forge). Mitigate with multiple relays + a
  signed roster; boot-time failover selects a reachable relay, while mid-session
  relay death still requires reconnect/reload.
- **Key durability:** in web mode the identity is a browser-local Ed25519 seed in
  `localStorage`; clearing site data destroys it. The **recovery bundle does NOT
  contain the signing key** (only public keys + outbox invite keys for
  discovery), so it cannot restore the identity. To move or back up the key,
  Settings → *Move this identity to another device* exports a passphrase-encrypted
  file (PBKDF2 → AES-256-GCM) that imports as the same identity on another browser
  or phone (file, paste, or QR). See
  [`docs/identity-recovery-protocol.md`](identity-recovery-protocol.md#3-web-mode-identity-export).
