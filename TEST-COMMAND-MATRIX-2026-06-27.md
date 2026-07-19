# Peerit Test Command Matrix - 2026-06-27

> Superseded for current command status by
> [`TEST-COMMAND-MATRIX-2026-07-01.md`](TEST-COMMAND-MATRIX-2026-07-01.md).
> This file remains as historical evidence for the June browser-dev smoke.

Source root: `~/pear-ecosystem/02-apps/peerit`

Peerit is a dependency-free P2P site: static HTML/CSS/JS plus headless Node tests for the data model, UI-adjacent pure logic, and signed gossip security model. This matrix is for local validation only. Publish, relay, catalog, and real PearBrowser runtime checks are intentionally separate operator-run gates.

## Executive Status

Green locally:

- Node runtime is available: `v22.22.0`.
- `npm test` passes: 80 total checks across the two shipped test files.
- `node test/smoke.mjs` passes: 55 product/core checks.
- `node test/gossip.mjs` passes: 25 gossip/security checks.
- JavaScript/module syntax sweep passes for all `.js` and `.mjs` files outside `node_modules`.
- `npm run dev` now has a browser-level loopback proof: create community, create post, add comment, create/switch dev user, add a second comment in another tab, and verify cross-tab update without reload.

Not run in this local loop:

- `npm run publish:local`, because it produces a Hyperdrive publish artifact and is a PearBrowser validation gate.
- `npm run publish`, because it is outward-facing and seeds/registers through the live publish path.
- Real PearBrowser bridge runtime, catalog visibility, relay durability, and data seeder checks.

## Package Scripts

| Command | Scope | Current status |
| --- | --- | --- |
| `npm test` | Runs `node test/smoke.mjs && node test/gossip.mjs` | Green: 55 smoke checks + 25 gossip checks. |
| `npm run dev` | Starts `node dev-server.mjs` on `127.0.0.1:8777` | Green browser smoke on 2026-06-27; see `PEERIT_BROWSER_DEV_SMOKE_PROOF_2026-06-27.md`. |
| `npm run publish:local` | Runs `node publish.mjs --local` | Not run; local PearBrowser publish gate. |
| `npm run publish` | Runs `node publish.mjs` | Not run; outward-facing publish/seed/register gate. |

## Focused Checks Run

### Node Runtime

Command:

```sh
node --version
```

Result:

- Green: `v22.22.0`.

### Full Local Test Suite

Command:

```sh
npm test
```

Result:

- Green.
- `test/smoke.mjs`: 55 checks.
- `test/gossip.mjs`: 25 checks.
- Total: 80 checks.

Coverage summary:

- Core ranking, markdown safety, route parsing, onboarding constants, local prefs, and dev reducer key parity.
- Community/post/comment/vote/profile/karma/moderation flows over the dev sync backend.
- Edit/delete, lock, ban/unban, approve, sorting, and activity behavior.
- Real Ed25519-backed gossip authenticity, tamper rejection, key binding, community sticky ownership, tombstone conflict resolution, 3-peer convergence, cross-outbox votes/moderation, forged relay rejection, edit propagation, and bridge restart behavior.

### Individual Product/Core Smoke

Command:

```sh
node test/smoke.mjs
```

Result:

- Green: 55 checks.

### Individual Gossip/Security Smoke

Command:

```sh
node test/gossip.mjs
```

Result:

- Green: 25 checks.

### Syntax Sweep

Command:

```sh
find . -path './node_modules' -prune -o \( -name '*.js' -o -name '*.mjs' \) -type f -exec node --check {} \;
```

Result:

- Green.
- No syntax errors reported.

### Browser-Level Dev Smoke

Command:

```sh
npm run dev
```

Result:

- Green through the local loopback browser preview.
- Created `r/codex243225`, posted `Browser smoke post 243225`, added one comment in tab A, opened the post in tab B, created/switched to a second dev user through the account dropdown, added a second comment in tab B, and verified tab A received the second comment without reload.
- The smoke found and fixed a dev-only testability issue: the old new-user control used `prompt()`, which was unavailable in the browser harness. It is now an inline dropdown form.

## Runtime And Release Gates

Treat these as unproven until intentionally run:

- `npm run dev`: local browser preview smoke at `http://127.0.0.1:8777`.
- `npm run ship:check`: release preflight for tests, manifest, served files, and git cleanliness.
- `npm run ship:live`: release preflight plus strict HiveRelay publish and durability report.
- `npm run publish:local`: local Hyperdrive publish suitable for PearBrowser testing.
- `npm run publish`: public publish/seed/register workflow.
- `STRICT_ANCHOR=1 KEEP=1 npm run publish`: durable public publish workflow.
- Real PearBrowser bridge path: `window.pear.sync`, `window.pear.identity`, and `window.pear.swarm` behavior.
- Data availability/seeder checks from `DURABILITY.md`.

## Known Gaps

- Browser/UI proof currently exists as documented in-app browser evidence, not a checked-in automated test script.
- Post/comment edit controls still use `prompt()` and were not covered by the browser smoke.
- No local PearBrowser bridge test was run in this loop.
- `ship:check` now catches uncommitted served-file drift before publish; the current
  workspace can still be blocked by unrelated dirty served files until those are
  committed, stashed, or deliberately allowed with `--allow-dirty`.
- Outward publish, relay, catalog, and durability proof remain deliberate
  operator actions through `npm run ship:live`.
- No package install/audit gate exists because the app declares no runtime npm dependencies.

## Recommended Next Edges

1. Add a repeatable checked-in browser smoke script for the now-proven `npm run dev` path.
2. Add a deliberate PearBrowser bridge proof for `publish:local` once an operator wants a runtime gate.
3. Add a PearBrowser-side full-fetch verification after `ship:live` once a stable
   local command can open the new `hyper://` drive from a cold peer.
