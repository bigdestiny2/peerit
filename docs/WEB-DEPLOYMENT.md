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
| **3 — in-browser DHT pipe** | `js/dht-adapter.js` (maps hypercore stack → pear surface, **adapter logic unit-tested** via `test/dht-adapter.mjs`), `js/dht-transport.js` (wires the real deps), `js/ra-idb.js` (durable IndexedDB, `test/ra-idb.mjs`), boot wiring + `build-web --dht-relay` | ✅ wire validated on a testnet DHT (`test:dht-live`) AND in a real browser (Brave) against a local dht-relay — WASM crypto, `global`/`Buffer`/`process` shims, WS pipe, and durable IndexedDB outbox (persists across reload) all confirmed. ⬜ remaining: public `wss://` dht-relay end-to-end between two browsers |

## Build & serve the web bundle

```sh
# Before changing any signed release field (including source bytes or drive key),
# increment deploy/web-release.json releaseSequence. Sequence 1 is the first v2
# signed release; an unchanged candidate may be reproduced idempotently.

# 1. Build the release candidate exactly once. This writes the non-secret,
# deterministic deploy/web-signing-request.json for the offline signer.
npm run web:prepare -- --drive-key <64-hex-hyperdrive-key>

# 2. Sign outside the build/deploy host and return only the signature file.
# This scoped command injects PEERIT_RELEASE_SIGNING_SEED without shell expansion.
keyvault exec --only peerit/release/signing-seed -- npm run release:sign

# 3. Verify the frozen bytes. This command NEVER builds or rewrites web/.
npm run web:verify -- --drive-key <same-64-hex-hyperdrive-key>

# `web:release` is a compatibility alias for the same verify-only command.
npm run web:release -- --drive-key <same-64-hex-hyperdrive-key>

# Relay-roster rotation happens only during prepare. The private seed is never
# committed and verify-only refuses it rather than mutating the roster.
PEERIT_ROSTER_SEED=<32-byte-hex-seed> npm run web:prepare -- --drive-key <key>

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

`web:verify` recomputes SHA-256 for every `asset-manifest.json.files` entry,
rejects missing files, unsafe or case-colliding paths, symlinks, and unexpected
unmanifested files, then verifies `asset-manifest.sig`. The signing request also
freezes the complete artifact. Release message v2 additionally signs the
`asset-manifest.json.controls` hashes for `sw.js` and `verify.html`, and the
in-browser verifier recomputes those control hashes alongside normal assets.
It contains public hashes and keys only, so
`deploy/web-signing-request.json` is intentionally suitable for source control
and for a Render verify-only build step.
The packaged `web:prepare`, `web:verify`, and `web:release` commands all enable
strict mode: a warning is a failed release, including on Render.

`releaseSequence` is a positive monotonic integer signed into both the manifest
root and `webRelease`. The committed `deploy/web-signing-request.json` is the
tracked prior-release record: prepare allows the same sequence only when the v2
signing-message hash is identical, rejects a lower sequence, and rejects a changed
signed artifact that reuses a sequence. Because a new Hyperdrive key is signed,
every normal `ship:live` publication must increment the sequence. Commit the new
signing request with the frozen artifact so the next release retains that floor.

Normal browsers also retain a best-effort local sequence + manifest-identity floor
per pinned release key. A returning browser with intact site storage rejects a
valid older signed release and an equal-sequence/different-manifest fork. This is
not a universal freshness oracle: a first-time visitor has no prior floor, clearing
site storage removes it, and key rotation starts a new key-scoped floor.

The boot check authenticates the signed manifest only. On a first visit, the ES
module graph necessarily loads before `app.js` can perform that check, so the log
must not be read as proof that already-executed module bytes were hashed. The
service worker hash-pins assets after a complete successful install; the independent
operator check for the live first-load artifact is the full-byte command:

```sh
npm run proof:web-deploy -- --url https://peerit.site
```

`verify.html` performs a user-invoked full fetch/hash comparison. Peerit does not
repeat that roughly 40-file transfer on every visitor boot.

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
PEERIT_ROSTER_SEED=<seed from offline key storage> npm run web:prepare -- --drive-key <key>
```

Without `PEERIT_ROSTER_SEED`, `npm run web:prepare` verifies the existing
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
3. **Code:** run `npm run ship:live` from a clean release tree. After the strict
   Hyperdrive publish yields its final key, ship builds `web/` once and pauses for
   the external signature. In a TTY, return `web/asset-manifest.sig` and press
   Enter. In non-interactive operation, ship exits with status 2 and resumes with
   `npm run ship:live -- --resume-signature`; resume verifies the frozen handoff
   and never republishes or rebuilds. The pending handoff hashes the exact publish
   report bytes; resume revalidates a ready strict report with durable metadata
   and full-blob evidence before accepting it. An explicit operator wrapper can instead be
   invoked with `--sign-command '<command>'`. Never put the seed in that command
   string or in Render; let the wrapper/HSM own secret retrieval.
   Increment `deploy/web-release.json.releaseSequence` before this step whenever
   this publication changes any signed field; the newly published drive key alone
   makes ordinary releases distinct.
4. **Commit the exact candidate:** after successful verify-only, review and
   force-add the ignored static artifact together with its public request and
   published manifest:

   ```sh
   git add -f web
   git add deploy/web-signing-request.json manifest.json
   git commit -m "release: prepare signed web candidate"
   npm run check:web-commit
   ```

   Run `check:web-commit` only after committing the candidate and before
   creating the static-host deploy. It reads the committed
   `web/asset-manifest.json` and fails if any signed byte is present locally but
   absent from that Git tree (which a host such as Render cannot serve).

   Render must use
   `node scripts/web-release.mjs --verify-only --strict` as its
   dependency-install-free verification command and `web` as its publish
   directory. The verifier imports only tracked local modules and Node builtins;
   Render must never run dependency installation, `build-web`, `web:prepare`, or
   receive either signing seed. Verification failure blocks the deploy. The
   previous immutable candidate commit is the static rollback point. Once Render
   reports that exact commit live, independently compare every served byte with
   the signed local artifact:

   ```sh
   npm run proof:web-deploy -- --url https://peerit.site
   ```

   A portable CSP meta cannot enforce `frame-ancestors`; browsers ignore that
   directive outside an HTTP response header. Apply every rule in
   [`deploy/render-security-headers.json`](../deploy/render-security-headers.json)
   to `/*` in the Render static-site header settings (or the equivalent edge
   host configuration). The CSP's `connect-src` must contain every exact origin
   carried by the signed `web/index.html` artifact. This is a release gate, not
   a best-effort hardening step:

   ```sh
   npm run proof:http-headers -- --url https://peerit.site
   ```

   With the Render API key injected by KeyVault, the reviewed policy can be
   reconciled without copying credentials into a terminal history:

   ```sh
   npm run configure:render-headers -- --service <render-static-service-id> --apply
   ```
5. **Host/mirror:** host that exact `web/` on peerit.site; also pin to IPFS (DNSLink),
   Arweave, and set ENS `peerit.eth` contenthash → CID so the app survives
   DNS/registrar seizure. `peerit.site/verify.html` lets anyone cross-check the
   web bundle against the published drive key.

`ship:live` rejects `--no-web`/`SKIP_WEB_RELEASE`, `--no-test`, and
`--allow-dirty`; an actually dirty release tree also blocks before public
publication. For a read-only candidate it also runs the non-destructive live
`proof:production-readonly`, `audit:live-legacy-pow`, and
`audit:live-legacy-actions` before publishing; for a writable candidate it runs
`proof:writable-candidate` plus the same exact-signature legacy-action audit.
That proof
fails unless the config explicitly says `readonly:false`, the pinned roster
signature verifies, and at least two signed relays use distinct origins. It then
checks **every** signed relay's `/api/bridge/status` and
`/api/sync/capabilities` for the durable, CAS, idempotent
`POST /api/sync/commit` contract. A safely invalid commit request must reach
that route and fail validation before allocation, which catches a proxy that
advertises but does not mount it. The proof issues no sync mutation or valid
commit. The bounded idempotency descriptor must retain every outbox's newest
receipt, so cross-author pressure cannot evict a publication still awaiting its
mirror. It also sends invalid, non-mutating requests to the legacy create/append routes
and fails unless the public edge or relay policy blocks both paths.
Offline `ship:check` runs no live-network probe. With one signed relay,
`deploy/web-release.json` must remain `readonly:true`.
Live ship treats every remaining warning as blocking; a `review` result is not a
publishable result.

### Writable-web candidate gate

Do not change the live signed configuration to discover whether a backend is
writer-capable. Prepare a production-equivalent canary/staging config and signed
roster first, then run:

```sh
# Deterministic browser-shaped lifecycle: boot as a lurker, post explicitly,
# mint/persist one identity, commit to two relays, reload as the same identity.
npm run test:writable-web

# Non-mutating network proof against every relay in the candidate signed roster.
PEERIT_WEB_RELEASE_CONFIG=deploy/web-release.staging.json \
  npm run proof:writable-candidate
```

The candidate proof never treats read-only mode, a missing capability endpoint,
one relay, two URLs on one origin, or an old append-only relay as “not
applicable”; each blocks. Only after this passes should a new release sequence be
built and signed. The current `deploy/web-release.json` remains the source of
truth for the live release until that deliberate cutover.

The clean-tree gate is derived from the transitive local import closure of the
build, signing, verification, served-site, and registered test entry points,
plus string-addressed esbuild inputs and release configs. That includes the
service-worker source, CSP helper, DHT/reader builders and their browser entry
modules, the writable-soak/local-fixture tools, the capacity contract, and the
protocol-v3 cutover inventory. Dirty or untracked closure inputs block live
publish; unrelated user documents and diagrams are intentionally outside this
gate.

## Manual validation still required

- Relay selection is continuously monitored. A lost relay, expired roster, or
  downgraded capability disables publishing in-session; a surviving relay can
  continue serving verified reads while the client retries the full topology.
  Validate long-lived SSE/swarm reconnection separately under real proxy idle
  timeouts.
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
  signed roster. The browser continuously re-verifies roster expiry and exact
  relay capabilities: a surviving relay remains usable for verified reads, while
  publishing immediately fails closed unless every origin in the signed writer
  topology is reachable and durable. Recovery happens in-session without erasing
  a typed post/community draft.
- **Key durability:** a visitor starts without an identity. The first explicit
  post/comment/vote mints one browser-local Ed25519 seed and, before publishing,
  stores it as AES-GCM ciphertext under a non-extractable WebCrypto key in
  IndexedDB. This protects against passive storage reads, not same-origin XSS or
  disk/profile extraction; clearing site data still destroys it. To move or back
  up the key, Settings → *Move this identity to another device* exports a
  passphrase-encrypted file (PBKDF2 → AES-256-GCM) that imports as the same
  identity on another browser or phone (file, paste, or QR). See
  [`docs/identity-recovery-protocol.md`](identity-recovery-protocol.md#3-web-mode-identity-export).
