# peerit

[![Verify](https://github.com/bigdestiny2/peerit/actions/workflows/verify.yml/badge.svg)](https://github.com/bigdestiny2/peerit/actions/workflows/verify.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-4f8cff.svg)](LICENSE)

**Local-first community software and a browser P2P reference app.** Peerit has
communities, posts, threaded comments, votes, profiles, moderation views and
pluggable feeds. Authors sign operations at the edge; each client verifies and
materializes its own view instead of asking a platform database what is true.

Peerit is also where we test reusable patterns for P2P applications that must
work inside the real constraints of browsers: durable intent journals,
host-backed and browser-local identity, blind capability storage, signed
discovery, exact readback, deterministic convergence, rollback floors and
verifiable releases.

> **Current boundary:** peerit.site serves the coherent signed **Sequence 29**
> artifact under `LIVE_PUBLIC_TEST_ONLY`, but its sole public-INBOX epoch ended
> on 2026-08-20. The shipped coordinator now fails closed to local-only mode:
> the UI and previously materialized local records remain usable, while fresh
> signed-seed recovery, public network publication, and discovery require
> runtime repair and a signed rotation successor. The GA gate remains blocked.
> See [Current status](docs/CURRENT-STATUS.md) before repeating a project claim.

[Open peerit.site](https://peerit.site) ·
[Plain-language explainer](EXPLAINER.md) ·
[Browser-P2P patterns](PATTERNS.md) ·
[Architecture](docs/ARCHITECTURE.md) ·
[Documentation map](docs/README.md)

![Each Peerit author signs and journals an operation locally. With current signed network authorities, the browser can publish encrypted cells and a discovery pointer for another client to verify before materializing it.](docs/how-peerit-works.svg)

## What “peer-to-peer in a browser” means here

Peerit separates **authority**, **storage**, **discovery**, **transport** and
**presentation**. That distinction matters more than whether an HTTP request
appears somewhere in the stack.

```text
explicit user action
        │
        ▼
durable identity ── host-owned in Pear Browser, device-owned on the web
        │
        ▼
signed operation ── canonical fields, author binding, proof-of-work where required
        │
        ▼
local journal + materialized view ── survives reloads and retry races
        │
        ├── encrypted immutable CELL replicas ── receipt + capability GET readback
        │
        └── small append-only INBOX pointer ── authenticated discovery
                                      │
                                      ▼
another client verifies bootstrap → relay → pointer → cell → operation
                                      │
                                      ▼
                           its own local feed and policy view
```

The normal web path still has a website origin, relay connections, browser
storage and browser lifecycle limits. A normal browser is not a native
HyperDHT node. Relays may delay, observe transport metadata or withhold bytes;
they are not trusted to forge an author, reinterpret a record, or decide the
client's moderation and ranking policy.

## Current runtime surfaces

| Surface | Purpose | Status |
| --- | --- | --- |
| `web/` signed artifact | Exact browser bundle represented by the release ledger | Sequence 29 is deployed and coherent; its network activation is currently blocked on signed epoch rotation and limited Cell-GET runtime repair |
| `js/substrate/` | Replacement local-first product runtime, authenticated boot and blind substrate composition | Active development on `main`; includes host-identity integration newer than the signed Sequence 29 artifact |
| Root `index.html` + `js/app.js` | Legacy/compatibility UI and domain playground | Useful for tests and experiments; **not** the production entry point |
| Pear Browser host bridge | Keeps the per-app signing seed behind `window.pear.identity` | Local record signing is implemented and tested on `main`; it is not in Sequence 29 and does not yet satisfy that path's `signAuthorBindV1` requirement |
| Plain-browser development | Local storage, IndexedDB and controlled fixtures | Development only; status is shown explicitly |

This table prevents a recurring failure mode: source, experimental and released
behavior must not be described as if they were the same thing.

## What we tried to make P2P work in browsers

Peerit did not arrive at the current design in one jump. These are the main
approaches we implemented or investigated, what each one taught us, and why no
single transport is presented as a magic “serverless web” answer.

| Attempt | What worked and what we learned | Where it stands |
| --- | --- | --- |
| Local-only and multi-tab simulation | Proved that signing, a durable intent journal, deterministic merge and the product UI can remain useful with no network. It cannot provide cross-device discovery or remote durability. | **Development pattern**; still valuable for deterministic testing |
| Per-author signed outboxes over HTTP/SSE | Let stock browsers compose many single-writer logs while keeping record authority with authors. The relay remains an availability and coordination dependency, and semantic relay APIs couple infrastructure to the app. | **Core ideas tested**; historical delivery family, not the Sequence 29 route |
| Signed relay rosters, CAS and receipt quorums | Made rollback floors, ambiguous writes and “how many origins durably accepted this exact commit?” measurable. Receipts do not prove continued retrievability or independent custody, and a coordinating leader is still a choke point. | **Tested legacy pattern**; evidence model reused elsewhere |
| Pear host identity plus native Hypercore/HyperDHT experiments | A capable host can provide keys, sockets and P2P storage that do not exist in an ordinary browser tab. Only the seedless host-signing adapter is implemented in current source; the direct swarm/storage paths are separate legacy experiments rather than a completed browser integration. | **Host identity implemented in source**; direct/native transport is historical/experimental and excluded from the web release |
| WebSocket-to-DHT conduit | Allowed a browser to reach DHT-style peers through a compatible bridge. The conduit can observe metadata and withhold traffic, so this is reachability through infrastructure, not direct browser DHT participation. | **Compatibility experiment**, excluded from Sequence 29 |
| BlindShard and split-transport designs | Explored ciphertext dispersal and separating ingress from storage so no single service necessarily holds a complete body. The benefit depends on independent operators plus tested repair, rotation and recovery. | **Experimental/design work**, not shipped |
| Browser-native Hypercore/Corestore on IndexedDB | Could reduce the gap between native and web peers, but crash recovery, quota eviction, snapshots, iterators, multi-tab writers and browser transports need real evidence first. | **Design/unproven**, deliberately not a release claim |
| Immutable blind Cells plus a small public INBOX | Separates encrypted content storage from discovery, persists intent before I/O, authenticates receipts/readback and keeps relays application-agnostic. This became the signed Sequence 29 bounded public-test path. | **Bounded release evidence**; current public network activation is blocked pending signed epoch rotation and runtime repair |

The durable conclusion is not that stock browsers need no infrastructure. It is
that infrastructure can be kept outside the authorship and validation boundary:
the client signs, journals, verifies and materializes; transports carry opaque
bytes and must produce narrowly stated availability evidence. The full
[browser-P2P pattern catalogue](PATTERNS.md) turns those experiments into 13
reusable implementation rules with code and test links.

## The reusable patterns

The full [pattern catalogue](PATTERNS.md) labels each idea as released,
implemented, experimental, specified or rejected and links to executable proof.
The short version:

| Pattern | Why it exists |
| --- | --- |
| Sign at the edge; verify after every transport | A relay or peer can carry a record but cannot become its author |
| Persist intent before network I/O | A tab crash, reload or flaky relay does not erase or duplicate a signed action |
| Immutable body cells + tiny discovery pointers | Large encrypted payloads and append-only discovery can evolve independently |
| Capability URLs/frames, not semantic relay APIs | Infrastructure stores opaque bytes without understanding posts, votes or communities |
| Read back before claiming publication | An acknowledgement is not proof that the exact bytes are retrievable |
| Lazy identity with explicit mutation | Reading does not silently mint an identity; the first write crosses a visible trust boundary |
| Deterministic local materialization | Replicas can receive records in different orders and still converge |
| Signed bootstraps, descriptor floors and release history | Discovery and code updates fail closed on rollback or substitution |
| Client-owned moderation and feed policy | Transport does not become the product's speech or ranking authority |
| Honest capability ladders | Pear Browser, an ordinary browser and a local fixture expose different guarantees |

The catalogue also records experiments that are useful but not shipped, including
event-sourced multi-party workflows, private record envelopes, split transport
and browser-native Hypercore storage.

## Try the exact checked-in surfaces

Requires a supported Node.js 22 or newer release. CI runs the full ship gate on
Node.js 22 and checks core compatibility on Node.js 24.

```bash
git clone https://github.com/bigdestiny2/peerit.git
cd peerit
npm ci
```

Preview the exact committed release artifact on a locked-down loopback server:

```bash
npm run preview:release
# http://127.0.0.1:8791
```

Run the legacy/domain source playground (useful for multi-tab UI experiments,
but not the production entry point):

```bash
npm run dev
# http://127.0.0.1:8777
```

Run the local blind-browser stand-up when working on the replacement runtime:

```bash
npm run dev:local-blind-browser
```

The local stand-up exercises controlled development infrastructure. It does not
turn fixture evidence into a production claim.

## Verify it

Fast repository and documentation guard:

```bash
npm run test:docs
```

Core, protocol and release-source checks:

```bash
npm test
npm run test:peerit-substrate
npm run test:peerit-operation-authority
```

Historical owner-decision and artifact-reconstruction audits evaluate
time-bounded authority at the canonical externally pinned decision time. Live
browser activation independently evaluates the same authority against its
current wall clock, so green repository checks do not reactivate an expired
network epoch; see
[Current status](docs/CURRENT-STATUS.md#what-is-deployed-versus-currently-active).

Browser behavior and accessibility:

```bash
npx --no-install playwright install chromium firefox webkit
npm run test:browser:signed-release
npm run test:browser
npm run test:browser:mobile
npm run test:browser:android
npm run test:browser:firefox
npm run test:browser:webkit
npm run test:accessibility
```

Or run the same aggregate gate used by GitHub Actions:

```bash
npm run test:ci
```

Live proofs are deliberately separate from deterministic CI because they make
network and deployment claims. See [Current status](docs/CURRENT-STATUS.md) and
the [test command matrix](TEST-COMMAND-MATRIX-2026-07-01.md) for the appropriate
operator-run evidence.

## Repository map

```text
peerit/
├── js/
│   ├── substrate/       # replacement runtime, journal, boot authority, blind transport
│   ├── data.js          # signed domain operations and query API
│   ├── model.js         # record types and key model
│   ├── moderation.js    # client-owned policy views
│   ├── feed-algorithms.js
│   └── verify.js        # record authority checks
├── protocol/            # canonical profiles, validators and conformance vectors
├── deploy/              # signed release inputs, decisions and pin history
├── web/                 # exact generated/signed browser release artifact
├── scripts/             # deterministic builders, drills and evidence gates
├── test/                # unit, protocol, fault, browser and release verification
├── docs/                # current guides plus dated design/evidence records
├── PATTERNS.md           # reusable browser-P2P pattern catalogue
├── EXPLAINER.md          # plain-language product and trust model
└── SECURITY.md           # reporting and threat-model entry points
```

Start code reading at
[`js/substrate/app-entry.js`](js/substrate/app-entry.js),
[`js/substrate/peerit-product-runtime.js`](js/substrate/peerit-product-runtime.js),
[`js/substrate/peerit-journal.js`](js/substrate/peerit-journal.js) and
[`js/substrate/public-inbox-boot-coordinator.mjs`](js/substrate/public-inbox-boot-coordinator.mjs).

## Security and honest limits

- **Two owner-operated relays are not decentralization.** Sequence 29 records
  bounded activation evidence, not independent custody or censorship resistance;
  its public-INBOX epoch currently needs a signed rotation.
- **Opaque is not anonymous.** Relays can observe timing, sizes, IP/network
  metadata and the capabilities presented to them even when they cannot parse
  Peerit semantics.
- **The web origin remains a code-delivery trust point on first visit.** Signed
  manifests, pin history and the service worker make substitution visible and
  improve continuity; they do not make DNS or hosting disappear.
- **Browser storage is evictable and origin-scoped.** Durable local journaling is
  a recovery mechanism, not permanent custody. Export and replication still
  matter.
- **Sybil resistance is partial.** Proof-of-work and reputation can raise cost;
  neither proves one human per key.
- **Client policy is plural.** Moderation and ranking are verifiable local views,
  not a universal consensus handed down by a relay.

Read [SECURITY.md](SECURITY.md), [Architecture](docs/ARCHITECTURE.md) and
[Current status](docs/CURRENT-STATUS.md) before reviewing or extending a trust
boundary.

## Contributing

Bug reports, protocol counterexamples and new pattern experiments are welcome.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) first: changes that affect a public
claim need matching tests and an explicit maturity label. Never commit identity
seeds, capability vaults, custodian material or live operator evidence.

Peerit is available under the [MIT License](LICENSE).
