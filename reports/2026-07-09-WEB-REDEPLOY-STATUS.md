# 2026-07-09 Web redeploy status — COMPLETE

## Production apex updated

| Item | Status |
|---|---|
| **https://peerit.site** | **Live** on Render `peerit-site` (`srv-d91q9sfavr4c73fr611g`) |
| Deploy | `dep-d97qrvjeo5us73aes36g` — commit `60d7300`, API trigger, clear-cache, **succeeded** |
| PoW | Live `js/pow.js` includes `POW_VERSION = 2` + identity-bound targets |
| Outbox | `outbox.peerit.site` healthy (token + directory) |
| Availability proof | `pass=12` `warn=1` `fail=0` against https://peerit.site |

## Single production site

- Apex remains **Render** only (no DNS cutover needed).
- Temporary CF Pages custom-domain bind for `peerit.site` removed (pending CNAME was never cut over).
- Bern `/var/www/peerit.site` kept offline; Caddy `peerit.site` host block removed so only Render serves the domain.
- Optional backup URL `https://peerit-site.pages.dev` may still exist but is **not** the marketing origin.

## How it was redeployed

```bash
render login
render workspace set tea-d5d0ucjuibrs73fg7l90   # My Workspace
render deploys create srv-d91q9sfavr4c73fr611g \
  --clear-cache --commit 60d7300 --wait --confirm
```

## Verify anytime

```bash
curl -sS https://peerit.site/js/pow.js | grep POW_VERSION
# export const POW_VERSION = 2
```
