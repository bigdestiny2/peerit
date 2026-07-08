# Peerit Test Command Matrix - 2026-07-01

Source root: `/Users/localllm/Projects/pear-ecosystem/02-apps/peerit`

Peerit is still a dependency-free P2P site at runtime. The default suite stays
pure Node, while browser and availability checks are now explicit operator gates
that can be run repeatedly.

## Executive Status

Green in this loop:

- `node --check scripts/browser-smoke.mjs`
- `node --check scripts/availability-proof.mjs`
- JavaScript/module syntax sweep for all `.js` and `.mjs` files outside
  `node_modules`
- `npm test`: 336 checks passed across smoke, gossip, bridge, bridge convergence,
  local bridge proof, runtime, relay roster, DHT adapter/build, durability,
  identity export, and representative outbox availability suites
- `npm run ship:check`: served files clean, smoke/gossip/bridge suites passed,
  `.deploy/last-ship.json` status `ready`
- `npm run ship:live`: strict HiveRelay publish completed; metadata and blob
  bytes durable on relays; live at
  `hyper://ec6e2d6d9d22b9d6b40e11a9ca3042be3197e4bdca9e9a7f079be6ee830761b4/`
- `npm run proof:availability`: representative outbox evidence passed; current
  overall status is `review` only because `.deploy/last-ship.json` now records
  dirty release files
- `npm run proof:availability:live`: representative outbox evidence passed;
  current strict mode is blocked by the same dirty ship-report gate
- `npm run proof:availability -- --url http://127.0.0.1:8777` with the local dev server running
- `npm run proof:outbox-availability`: status `ready`; fresh reader recovered
  representative profile/community/post/comment/vote data after byte catch-up
- `npm run proof:outbox-availability:report`: wrote
  `reports/representative-outbox-availability-2026-07-01.json`
- `npm run proof:relay-roster -- --out .deploy/relay-roster-evidence-2026-07-02.json --json`:
  ready with 9 pass checks; the signed roster covers both configured relays.
- `npm run proof:bridge:local`: checked in as the repeatable local Hyperdrive
  bridge proof wrapper; not run here because it requires two real PearBrowser
  instances. The wrapper now also supports `--plan-only` for a structured
  `operator-required` handoff report that contains no snapshots and is not
  counted as bridge proof.
- `npm run proof:hiverelay-outboxlog -- --out reports/hiverelay-outboxlog-convergence-2026-07-01.json`:
  green with 13 pass checks; two generated Peerit `web/js` clients converged
  through a local HiveRelay RelayAPI running the real `OutboxLogApp`.
- `npm run proof:app-membership`: green with 51 gossip checks; includes the
  closed-group app validator proof that member-signed private content is
  admitted, outsider-signed private post/comment records are rejected even with
  valid signatures and PoW, and public outsider records still converge.
- `npm run test:browser`: green after installing optional Playwright tooling;
  covers create/post/comment, post edit, comment edit, comment delete, post
  soft-delete, and cross-tab tombstone propagation.
- `npm run test:browser:mobile`: green after installing optional Playwright
  tooling; mobile host-token smoke stayed writable through `/api`.
- Browser UI path through the in-app browser: create community, create post, add
  comment in tab A, open tab B, create/switch dev user, add second comment, and
  verify tab A receives it without reload.

Expected checkout limitation:

- Playwright is optional operator/dev tooling, not a runtime dependency. A fresh
  dependency-free checkout still needs `npm install --no-save playwright` and
  `npx playwright install chromium` before browser smokes can run.

Not run in this loop:

- `npm run publish:local`
- Real PearBrowser bridge runtime
- Live peerit-seeder/HiveRelay outbox proof against real production invite keys

## Package Scripts

| Command | Scope | Current status |
| --- | --- | --- |
| `npm test` | Headless product/gossip/bridge/runtime/relay checks | Green: 336 checks passed. |
| `npm run test:browser` | Optional Playwright dev-browser smoke | Green: create/post/comment plus post/comment edit and delete prompt/confirm flows across two tabs. Requires optional Playwright tooling in a fresh checkout. |
| `npm run test:browser:mobile` | Optional Playwright PearBrowser mobile `/api` token smoke | Green: injects `pear-api-token`, proves writable `gossip-bridge`, and fails on read-only/dev fallback. Requires optional Playwright tooling in a fresh checkout. |
| `npm run proof:availability` | Static app/file/manifest/seeder/mirror plus representative outbox evidence | Current rerun: review, 11 pass, 1 warn, 1 info; representative outbox report passed, ship report is dirty-worktree blocked. |
| `npm run proof:availability -- --url http://127.0.0.1:8777` | Same proof plus HTTP fetch of every published asset | Green against `npm run dev` on 2026-07-01. |
| `npm run proof:availability:live` | Strict live evidence mode | Current rerun: blocked by `.deploy/last-ship.json` dirty-worktree status; live publish bytes and representative outbox report passed. |
| `npm run proof:outbox-availability` | Fresh-client representative outbox proof | Ready: 7 pass; fails if byte catch-up is not confirmed. |
| `npm run proof:outbox-availability:report` | Writes checked-in representative outbox evidence | Ready: wrote `reports/representative-outbox-availability-2026-07-01.json`. |
| `npm run proof:relay-roster` | Signed relay roster/release config drift gate | Ready: 9 pass; signed roster covers `https://153-75-89-206.sslip.io` and `https://peerit-relay.onrender.com`. |
| `npm run proof:bridge:local` | Starts `publish.mjs --local`, prints Device A/B `#/bridge-proof/<session>` URLs, validates copied snapshots | Checked in; writes `.deploy/local-bridge-proof-<session>.json` and `.md`. Requires two PearBrowser instances, so not run here; `--plan-only` writes an explicit `operator-required` non-proof report. |
| `npm run proof:hiverelay-outboxlog` | Generated Peerit web build modules over a local HiveRelay RelayAPI running `outboxlog` | Green: 13 pass checks; wrote `reports/hiverelay-outboxlog-convergence-2026-07-01.json`. |
| `npm run proof:app-membership` | App-level group membership proof through Peerit's merge validator hook | Green: 51 gossip checks; proves group membership is app policy, not HiveRelay substrate policy. |
| `npm run publish:local` | Local Hyperdrive publish for PearBrowser testing | Not run; deliberate PearBrowser runtime gate. |
| `npm run ship:live` | Public publish/seed/catalog workflow | Green: strict publish completed with durable metadata and blobs. |

## Focused Checks Run

### Availability Proof

Command:

```sh
npm run proof:availability
```

Result:

- Current rerun: review, 11 pass, 1 warn, 1 info.
- Verified 26 published files, non-empty bytes, `index.html` references,
  static module imports, manifest drive key/url consistency, peerit-seeder
  byte catch-up heuristics, checked-in representative outbox recovery evidence,
  and peerit-mirror metadata/blob mirroring.
- Consumed the current `.deploy/last-ship.json`; it now reports `blocked`
  because release files are dirty in this local worktree.
- Consumed a fresh `.deploy/last-publish.json` report proving durable metadata
  and blob byte replication.
- The warning is the ignored `.deploy/last-ship.json` currently saying
  `git:release-dirty` after local worktree edits; it is not an outbox proof
  failure.

### Representative Outbox Availability Proof

Commands:

```sh
npm run proof:outbox-availability
npm run proof:outbox-availability:report
node test/outbox-availability-proof.mjs
```

Result:

- Green: proof status `ready`, 7 pass.
- Wrote `reports/representative-outbox-availability-2026-07-01.json`.
- Representative data set: profile, community, post, comment, vote, and signed
  `head!<author>`.
- Seeder-style evidence confirms `remoteLength >= localLength` and
  `remoteBytes >= localBytes` before trusting the copy.
- Fresh reader starts with empty storage, author/seeder are offline in the
  scenario, and the reader recovers all representative records with no
  unresolved withholding.
- Negative fixture `--fixture missing-catchup` exits 1 and names
  `seeder:byte-catchup` as the failing check.

### Default Test Suite

Command:

```sh
npm test
```

Result:

- Green: 336 checks passed.
- Coverage includes product smoke, signed gossip/security, bridge fallback,
  two-writer bridge convergence, local bridge proof report/plan validation,
  runtime dispatch, relay roster verification, DHT adapter/build checks, signed
  outbox-head durability, relay-pool recovery, head-floor/directory rollback
  protection, identity export, and representative outbox availability.

### Signed Relay Roster Proof

Command:

```sh
npm run proof:relay-roster -- --out .deploy/relay-roster-evidence-2026-07-02.json --json
```

Result:

- Ready: 9 pass, 0 warn, 0 fail.
- `deploy/web-release.json` and `relay-roster.json` both carry the same two
  relays: `https://153-75-89-206.sslip.io` and
  `https://peerit-relay.onrender.com`.
- The signed roster payload matches the release config, covers every configured
  bootstrap relay, verifies with the pinned key
  `4a7402d1a950dc3be8a434cb3ee664231ca0e58be8c745dabcaf2346ee0e0f7f`, and
  expires on `2026-12-31T00:00:00.000Z`.

### App-Level Membership Proof

Command:

```sh
npm run proof:app-membership
```

Result:

- Green: 51 gossip checks passed.
- The proof composes Peerit's existing proof-of-work validator with an app-owned
  closed-group membership map.
- Signed member content for the closed group is admitted.
- Signed outsider post/comment rows for the closed group are rejected even when
  their signatures and proof-of-work are otherwise valid.
- The same outsider can still publish public records, so the proof does not
  change Peerit's public forum semantics.
- No HiveRelay change is required; the relay remains an append/durability/gossip
  substrate while group membership remains Peerit policy.

### Ship Preflight

Command:

```sh
npm run ship:check
```

Result:

- Green: 23 served files present, static imports included, manifest fields
  present, served app files clean in git.
- Smoke, gossip, and bridge suites passed.
- Wrote `.deploy/last-ship.json` with status `ready`.

### Live Publish

Command:

```sh
npm run ship:live
```

Result:

- Green: release preflight passed and public publish completed.
- HiveRelay client: `../../00-core/hiverelay/packages/client/index.js`.
- Relays connected: 7.
- Publish seed acceptances: 4.
- Metadata seed acceptances: 4.
- Content/blob seed acceptances: 4.
- Metadata durable: 6 active peers, remote bytes caught up.
- Blob durable: 7 active peers, `168/168` blocks mirrored.
- Live URL:
  `hyper://ec6e2d6d9d22b9d6b40e11a9ca3042be3197e4bdca9e9a7f079be6ee830761b4/`.

### Strict Live Availability Proof

Command:

```sh
npm run proof:availability:live
```

Result:

- Current rerun: blocked, 11 pass, 1 fail, 1 info.
- Verified static file surface, manifest drive key, current ship report, live
  publish report, seeder byte catch-up heuristic, and mirror byte-mirroring
  heuristic.
- The fail is `deploy:ship-report`: `.deploy/last-ship.json` currently records
  dirty release files. The live publish byte evidence and representative outbox
  report both passed.

### Local HTTP Asset Proof

Command:

```sh
npm run dev
npm run proof:availability -- --url http://127.0.0.1:8777
```

Result:

- Green/review: 11 pass, 1 warn.
- Fetched all 23 published assets from the locked-down dev server.
- This covers the local version of the "index.html loads but js/app.js 404s"
  failure class.

### Browser UI Smoke

Validated path:

1. Created `r/codex15wchd`.
2. Created `Browser smoke post mr15wchd`.
3. Added `first browser comment mr15wchd` in tab A.
4. Opened the same thread in tab B.
5. Created/switched to a second dev identity via the account dropdown.
6. Added `second user comment mr15wchd` in tab B.
7. Verified tab A received the second comment without reload.

The checked-in command for this is:

```sh
npm run test:browser
```

The mobile host-token variant is:

```sh
npm run test:browser:mobile
```

It serves the real app, injects `<meta name="pear-api-token">` plus a default
read-only web relay meta, mocks the same-origin `/api` host with real Ed25519
signatures, writes a community/post/comment through the UI, and fails if the
page shows `web`/read-only, creates dev localStorage state, or misses tokened
`/api` writes.

Direct execution in this checkout currently exits with clear setup guidance
because Playwright is not installed:

```sh
npm install --no-save playwright
npx playwright install chromium
npm run test:browser
npm run test:browser:mobile
```

## Runtime And Release Gates

Treat these as unproven until intentionally run:

- `npm run proof:bridge:local`: local Hyperdrive publish and PearBrowser bridge proof.
  Use `npm run proof:bridge:local -- --plan-only --skip-headless --no-publish --url hyper://<driveKey>/`
  only to archive an operator-required handoff; it is not proof.
- `npm run proof:hiverelay-outboxlog`: generated web modules against HiveRelay
  OutboxLog via HTTP+SSE; green locally, not a production relay durability proof.
- `npm run publish:local`: raw local Hyperdrive host.
- Real PearBrowser bridge path: `window.pear.sync`, `window.pear.identity`, and
  `window.pear.swarm` behavior.
- Live peerit-seeder/HiveRelay proof for real production outbox invite keys.

## Known Gaps

- The browser smoke is checked in, but the dependency-free checkout does not
  install Playwright by default.
- Post/comment edit/delete controls still use `prompt()`/`confirm()`; the
  optional browser smoke now covers and passes those flows in this checkout.
- No local PearBrowser `proof:bridge:local` bridge test was run in this loop.
- Live relay durability is proven by the current publish report; catalog
  visibility still needs an independent PearBrowser/browser check.
- Representative user-data recovery is now repeatable locally; production
  outbox availability still needs real seeder/HiveRelay byte catch-up evidence
  for real invite keys.

## Recommended Next Edges

1. Run `npm run proof:bridge:local` with two PearBrowser instances and archive
   the generated `.deploy/local-bridge-proof-<session>.json` report.
2. Run the same fresh-client flow against live peerit-seeder output for real
   production outboxes and archive the byte catch-up evidence.
