# BlindShard Production Roll Plan

**Goal:** activate live BlindShard dispersal for peerit across Node, browser, and PearBrowser runtimes.  
**Current state:** client mechanism complete and tested; blocked on relay credentials and a third relay.  
**Blocking items:**
1. Production relay Ed25519 pubkeys and `RELAY_API_KEY`s.
2. Public relays must run HiveRelay `feat/local-shard-cohort` ≥ commit `91093c3` (the `shareIndex` fix).
3. A third shard relay (ideally an independent operator).

---

## 1. What is already done

| Item | Evidence |
|---|---|
| v2 opaque log + dispersal compose in `data.js` | `test/dispersal-app-wiring.mjs` passes |
| Local 3-relay shard cohort mechanism proof | `node scripts/blind-dispersal-live.mjs ~/.hiverelay-shard-cohort/roster.json` passes |
| Browser reader bundle build + live recovery | `node scripts/reader-bundle-live.mjs ~/.hiverelay-shard-cohort/roster.json` passes |
| PearBrowser bridge-mode dispersal convergence | `test/pearbrowser-dispersal-convergence.mjs` passes |
| HiveRelay `shareIndex` custody-assignment bug fixed | commit `91093c3` pushed to `feat/local-shard-cohort` |
| Production roster template + build fail-closed | `config/shard-roster.public.json` updated; `build-web.mjs` refuses missing/invalid pubkeys or `<3` relays |
| Dispersal timeout + fallback to single-blob | `data.js` races `disperseBody` against 15 s timeout |
| Adversarial review | `docs/BLINDSHARD-ADVERSARIAL-REVIEW.md` |

---

## 2. Pre-flight checklist for operators

Before any live build, verify:

- [ ] Each public HiveRelay is checked out to `feat/local-shard-cohort` at or after `91093c3`.
- [ ] Each relay has `RELAY_API_KEY` set in its `.env` and the shard-store surface is mounted (`GET /api/v1/shard/<hash>` returns 401 for missing auth, not 404).
- [ ] Each relay has `PEERIT_ORIGIN=https://peerit.site` (or the actual origin) in `.env` for CORS.
- [ ] A third relay is provisioned and meets the same criteria.
- [ ] `deploy/shard-cohort/extract-pubkey.mjs` has been run on each host to obtain the 64-hex `publicKey`.
- [ ] `~/.hiverelay-shard-cohort/roster.json` is created with all three URLs, pubkeys, and `apiKey`s.

---

## 3. Deployment steps

### Step 0 — provision the third relay

Use `deploy/shard-cohort/` on a new host:

```sh
cd deploy/shard-cohort
cp .env.example .env
# edit .env: RELAY_DOMAIN, RELAY_API_KEY, PEERIT_ORIGIN, HIVERELAY_STORAGE, etc.
docker compose up -d
```

Or, if reusing an existing peerit-relay host, upgrade it to `feat/local-shard-cohort` and add `RELAY_API_KEY`.

### Step 1 — upgrade existing public relays

On each existing relay host:

```sh
cd /path/to/P2P-Hiverelay
git fetch origin
git checkout feat/local-shard-cohort
git reset --hard origin/feat/local-shard-cohort   # ensure the shareIndex fix is present
# verify commit 91093c3 or later:
git log --oneline -1
# build + restart
docker build -t hiverelay:shard-store .
# edit .env: add RELAY_API_KEY and PEERIT_ORIGIN if missing
docker compose up -d
```

### Step 2 — extract pubkeys

On each relay host:

```sh
node /path/to/peerit/deploy/shard-cohort/extract-pubkey.mjs \
  $HIVERELAY_STORAGE \
  https://<relay-domain> \
  $RELAY_API_KEY
```

Collect the three JSON objects.

### Step 3 — fill the public roster

Edit `config/shard-roster.public.json`:

```json
{
  "_comment": "PRODUCTION shard cohort for peerit.site ...",
  "threshold": 2,
  "retainMs": 2592000000,
  "relays": [
    { "baseUrl": "https://153-75-89-206.sslip.io", "pubkey": "<pubkey1>" },
    { "baseUrl": "https://peerit-relay.onrender.com", "pubkey": "<pubkey2>" },
    { "baseUrl": "https://<third-relay>", "pubkey": "<pubkey3>" }
  ]
}
```

### Step 4 — create the dealer roster (outside git)

```sh
mkdir -p ~/.hiverelay-shard-cohort
cat > ~/.hiverelay-shard-cohort/roster.json <<'EOF'
{
  "threshold": 2,
  "retainMs": 2592000000,
  "relays": [
    { "baseUrl": "https://153-75-89-206.sslip.io", "pubkey": "<pubkey1>", "apiKey": "<apiKey1>" },
    { "baseUrl": "https://peerit-relay.onrender.com", "pubkey": "<pubkey2>", "apiKey": "<apiKey2>" },
    { "baseUrl": "https://<third-relay>", "pubkey": "<pubkey3>", "apiKey": "<apiKey3>" }
  ]
}
EOF
chmod 600 ~/.hiverelay-shard-cohort/roster.json
```

### Step 5 — prove the live cohort

```sh
# Node dealer round-trip against the production cohort
node scripts/blind-dispersal-live.mjs ~/.hiverelay-shard-cohort/roster.json

# Browser reader bundle round-trip
node scripts/reader-bundle-live.mjs ~/.hiverelay-shard-cohort/roster.json
```

Both should report PASS and write evidence to `reports/`.

### Step 6 — build and ship the web release

```sh
npm run ship:check   # prepare once, external-sign, verify-only
# if everything is green:
npm run ship:live
```

`build-web.mjs` will now pass `assertShardRoster` because pubkeys are valid and `n=3`.

### Step 7 — clear stale service-worker caches

After `ship:live`, mobile/desktop visitors may still have an old bundle cached. Instruct users to:

- On mobile: force-close the app or clear browser cache for `peerit.site`.
- On desktop PearBrowser: the hyper drive is content-addressed; new drive key → new content, but advise a restart if stale.

---

## 4. Cross-environment test matrix

Run this matrix after Step 5 and again after Step 6.

| Runtime | Authoring | Reading dispersed body | Command / procedure |
|---|---|---|---|
| Node (dev/seeder) | ✅ dispersal | ✅ `recoverBody` | `npm test` includes `test/dispersal-app-wiring.mjs` |
| Browser (peerit.site) | ❌ (read-only default) | ✅ reader-bundle.js + fetch | `scripts/reader-bundle-live.mjs` |
| PearBrowser (hyper:// drive) | ❌ falls back to single-blob | ✅ if webview fetch works; ⚠️ verify real webview | Manual: open PearBrowser, create post from Node author, open it in PearBrowser |
| Bridge sync (fake host) | ✅ dispersal | ✅ `test/pearbrowser-dispersal-convergence.mjs` | `npm test` |

**Critical manual test:** in real PearBrowser, open a dispersed post authored from Node. If the body fails to load (`_blobMissing`), the webview cannot fetch cross-origin shard relays; implement a `pear.bridge.fetchShard` host API.

---

## 5. Go / no-go criteria

**GO:**
- [ ] 3+ relays with valid pubkeys and apiKeys.
- [ ] `blind-dispersal-live.mjs` and `reader-bundle-live.mjs` pass against production.
- [ ] `npm test` passes.
- [ ] `npm run web:release` passes.
- [ ] PearBrowser manual read test passes (or documented fallback if webview fetch is blocked).

**NO-GO (ship without dispersal, keep v2 + single-blob):**
- [ ] Only 2 relays available.
- [ ] Cannot obtain relay pubkeys/apiKeys.
- [ ] Public relays are not on the fixed branch.
- [ ] Production live proofs fail.

---

## 6. Post-launch monitoring

| Signal | How to watch | Response |
|---|---|---|
| Dispersal fallback rate | Client logs `[peerit] dispersal box failed, falling back` | If high, check relay health / CORS / apiKey expiry. |
| Shard fetch failures | `_blobMissing` posts in UI | Check shard relay uptime; run repair pass when implemented. |
| Relay drift | `npm run proof:relay-roster` | Re-sign roster if relays change. |
| Roster expiry | `npm run web:release` warns if roster expires <14 days | Re-sign relay roster before expiry. |
| Independent-operator count | Track roster ownership | Recruit additional independent operators to move toward real collusion-resistance. |

---

## 7. Honest marketing boundaries

Until at least one independent operator is in the roster, do **not** say:
- "No single operator can read your posts."
- "BlindShard makes posts secret."
- "The operator cannot see the content."

**Permitted claims:**
- "Long post bodies are stored as ciphertext, not plaintext, on the relay."
- "With ≥3 independent relays, no single relay holds a readable body or enough fragments to reconstruct one."
- "Readers reconstruct bodies at the edge using signed manifests and blind shards."
- "The operator of any single relay holds only opaque, incomplete fragments they cannot decrypt or link to a post." (only true with independent operators)

---

## 8. Open follow-ups (not blockers)

1. **Custody-receipt quorum** — turn fire-and-forget shard PUTs into acknowledged placement.
2. **Client-driven repair** — re-upload missing shards from cached plaintext/K shards.
3. **Hashcash/PoW on open shard writes** — if allowing untrusted publishers to PUT shards.
4. **Serve-time takedown channel** — for safe-harbor compliance on the outbox/manifest tier.
5. **PearBrowser bridge transport** — if real webview fetch is blocked.
6. **Independent-operator recruitment** — replace same-owner relays over time.
