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
- `npm test`: 211 checks passed across smoke, gossip, bridge, bridge convergence,
  runtime, relay roster, and DHT adapter suites
- `npm run ship:check`: served files clean, smoke/gossip/bridge suites passed,
  `.deploy/last-ship.json` status `ready`
- `npm run proof:availability`
- `npm run proof:availability -- --url http://127.0.0.1:8777` with the local dev server running
- Browser UI path through the in-app browser: create community, create post, add
  comment in tab A, open tab B, create/switch dev user, add second comment, and
  verify tab A receives it without reload.

Expected local limitation:

- `npm run test:browser` exits with setup guidance until Playwright is installed
  in the operator checkout. Playwright is not a runtime dependency.

Not run in this loop:

- `npm run publish:local`
- `npm run publish`
- Real PearBrowser bridge runtime
- Public catalog visibility
- Live relay durability from a fresh publish report
- Fresh user-data seeder/cold-reader proof

## Package Scripts

| Command | Scope | Current status |
| --- | --- | --- |
| `npm test` | Headless product/gossip/bridge/runtime/relay checks | Green: 211 checks passed. |
| `npm run test:browser` | Optional Playwright dev-browser smoke | Checked in; requires `npm install --no-save playwright` and `npx playwright install chromium`. |
| `npm run proof:availability` | Static app/file/manifest/seeder/mirror evidence | Review: 10 pass, 1 warn, 1 info; warns only because no live publish report exists. |
| `npm run proof:availability -- --url http://127.0.0.1:8777` | Same proof plus HTTP fetch of every published asset | Green against `npm run dev` on 2026-07-01. |
| `npm run proof:availability:live` | Strict live evidence mode | Operator gate; fails unless live publish/ship reports prove durable metadata + blob bytes. |
| `npm run publish:local` | Local Hyperdrive publish for PearBrowser testing | Not run; deliberate PearBrowser runtime gate. |
| `npm run publish` | Public publish/seed/catalog workflow | Not run; outward-facing release gate. |

## Focused Checks Run

### Availability Proof

Command:

```sh
npm run proof:availability
```

Result:

- Green/review: 10 pass, 1 warn, 1 info.
- Verified 23 published files, non-empty bytes, `index.html` references,
  static module imports, manifest drive key/url consistency, peerit-seeder
  byte catch-up heuristics, and peerit-mirror metadata/blob mirroring.
- Consumed a fresh `npm run ship:check` report with status `ready`.
- Warning: `.deploy/last-publish.json` is absent, so live relay byte anchoring is
  not proven by this local checkout.

### Default Test Suite

Command:

```sh
npm test
```

Result:

- Green: 211 checks passed.
- Coverage includes product smoke, signed gossip/security, bridge fallback,
  two-writer bridge convergence, runtime dispatch, relay roster verification,
  and DHT adapter convergence.

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

Direct execution in this checkout currently exits with clear setup guidance
because Playwright is not installed:

```sh
npm install --no-save playwright
npx playwright install chromium
npm run test:browser
```

## Runtime And Release Gates

Treat these as unproven until intentionally run:

- `npm run publish:local`: local Hyperdrive publish and PearBrowser bridge proof.
- `npm run ship:live`: release preflight plus strict HiveRelay publish and
  durability report.
- `npm run proof:availability:live`: strict verification of current
  `.deploy/last-ship.json` and `.deploy/last-publish.json`.
- Real PearBrowser bridge path: `window.pear.sync`, `window.pear.identity`, and
  `window.pear.swarm` behavior.
- Fresh-client user-data availability proof for representative outboxes.

## Known Gaps

- The browser smoke is checked in, but the dependency-free checkout does not
  install Playwright by default.
- Post/comment edit controls still use `prompt()` and are not covered by the
  browser smoke.
- No local PearBrowser `publish:local` bridge test was run in this loop.
- Live relay/catalog/durability proof remains a deliberate operator action.
- User-data availability still depends on seeder/mirror evidence and fresh-reader
  checks, not the static app proof alone.

## Recommended Next Edges

1. Run `npm run test:browser` in an operator checkout with Playwright installed.
2. Add a PearBrowser-side `publish:local` bridge proof once the runtime can be
   driven repeatably from a command.
3. Add a fresh-client representative outbox proof that consumes peerit-seeder
   evidence and fails when byte catch-up is not confirmed.
