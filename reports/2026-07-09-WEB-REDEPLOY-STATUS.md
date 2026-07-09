# 2026-07-09 Web redeploy status

## Shipped
- GitHub `main` @ `48ac977` — identity-bound PoW, soak tooling, audit close-out
- `npm run web:release` green (roster verified, 41 files in `web/`)
- **Cloudflare Pages production deploy:** https://peerit-site.pages.dev  
  - Contains `POW_VERSION = 2` / identity-bound targets  
  - `proof:availability --url https://peerit-site.pages.dev` → pass=12, warn=1 (ship report)
- **Bern VPS** (`45.59.123.112`): `/var/www/peerit.site` populated; Caddy `peerit.site` site block added (ready for DNS cutover)

## Not yet cut over
- Apex **https://peerit.site** still serves the **2026-07-08** Render origin (`peerit-site.onrender.com`, last-modified Wed 08 Jul 2026 13:45:47 UTC) — **no POW_VERSION** in live `js/pow.js`.
- No Render API token / deploy hook in this environment; GitHub push did not auto-redeploy Render.
- Cloudflare Pages custom domain `peerit.site` is **pending** (`CNAME record not set`).

## One-step cutover (pick one)

### A. Cloudflare Pages (recommended for this deploy)
At Namecheap DNS for `peerit.site`:
1. Remove/override A/CNAME currently pointing at Render (`peerit-site.onrender.com`).
2. Add **CNAME** (or ALIAS/ANAME for apex): `peerit.site` → `peerit-site.pages.dev`
3. Wait for SSL on CF Pages domain to leave `pending`.

### B. Bern VPS (already staged)
1. Set **A** record `peerit.site` → `45.59.123.112`
2. Caddy will mint Let's Encrypt for `peerit.site` (already configured).

### C. Render dashboard (keep current host)
1. Open service **peerit-site** on Render.
2. Connect repo `bigdestiny2/peerit` branch `main` if not connected.
3. Build: `npm install && npm run web:release` · Publish dir: `web`
4. Manual deploy / clear cache.

## Verify after cutover
```bash
curl -sS "https://peerit.site/js/pow.js" | grep POW_VERSION
# expect: export const POW_VERSION = 2
```
