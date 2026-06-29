# Peerit Browser Dev Smoke Proof - 2026-06-27

Source root: `/Users/localllm/Projects/pear-ecosystem/02-apps/peerit`

## Scope

This loop stayed inside Peerit. It did not run publish, local publish, catalog, relay, durability, or outward-facing release commands.

The goal was to prove the local browser preview path behind `npm run dev`.

## Source Change

- Updated `js/app.js`.
  - Replaced the dev-user `prompt()` flow with an inline `data-form="dev-user"` form in the account dropdown.
  - Routed the form through the existing submit handler.
  - Kept dev-user creation scoped to the local dev fallback.
- Updated `styles.css`.
  - Added compact dropdown styling for the new dev-user form.

Why:

- The browser-level smoke exposed that `window.prompt` was unavailable in the in-app browser harness.
- A form-based dev-user flow is more testable and more accessible than a prompt.

## Browser Smoke

Dev server:

```sh
npm run dev
```

Server output:

```text
peerit dev server on http://127.0.0.1:8777 (public files only, no-store)
```

Browser path:

1. Opened `http://127.0.0.1:8777/#/create`.
2. Created community `r/codex243225`.
3. Created post `Browser smoke post 243225`.
4. Added comment `Cross-tab comment from browser smoke 243225` in tab A.
5. Opened the same post URL in tab B.
6. Verified tab B saw the post and first comment.
7. Created and switched to dev user `codex_user_243225` through the new dropdown form.
8. Added comment `Second-user cross-tab comment 243225` in tab B.
9. Verified tab A saw the second-user comment without a reload.

Observed proof:

```json
{
  "slug": "codex243225",
  "postTitle": "Browser smoke post 243225",
  "firstComment": "Cross-tab comment from browser smoke 243225",
  "secondUser": "codex_user_243225",
  "secondComment": "Second-user cross-tab comment 243225",
  "tabBSecondCommentCount": 1,
  "tabASecondCommentCount": 1,
  "tabAFirstCommentCount": 1,
  "tabBFirstCommentCount": 1
}
```

## Validation

| Command | Result |
| --- | --- |
| `node --check js/app.js` | Pass |
| `npm test` | Pass, 55 smoke checks + 25 gossip checks |
| `find . -path './node_modules' -prune -o \( -name '*.js' -o -name '*.mjs' \) -type f -exec node --check {} \;` | Pass |

## Residual Risk

- This is the loopback browser dev fallback, not PearBrowser bridge runtime.
- `publish:local`, public publish, catalog registration, relay durability, and cold-peer fetch remain manual/operator gates.
- The browser smoke is documented evidence, not yet a checked-in automated browser test.
- Post/comment edit controls still use `prompt()` and were not covered by this smoke.

## Next Edge

Add a repeatable browser smoke script or PearBrowser bridge proof for `publish:local`, while keeping public publish and durability gates explicit operator actions.
