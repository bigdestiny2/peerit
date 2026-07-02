# Scoping — peerit as a self-contained `data:` URL bootstrap (no hosted origin)

> **Companion to [`WEB-DEPLOYMENT.md`](WEB-DEPLOYMENT.md), [`BLINDSHARD-DESIGN.md`](BLINDSHARD-DESIGN.md),
> and [`OPERATOR-LIABILITY.md`](OPERATOR-LIABILITY.md).** The idea (from a Pear-dev chat): instead of
> hosting peerit's JS on peerit.site — the "origin ships the JS every visit" ceiling named in
> `WEB-DEPLOYMENT.md` — deliver a tiny sandboxed bootstrap **as** a `data:` URL: a loader with a
> baked-in Ed25519 pubkey that fetches the real app bundle from p2p/content-addressed storage,
> verifies it against the key, and runs it. It runs in an opaque origin so it's sandboxed.
>
> **Result of a deep multi-agent feasibility scope (2026-07-02):** the browser-fact claims below
> were adversarially fact-checked against primary sources (Chromium/Mozilla/WebKit + MDN). Where a
> fact-check corrected the raw research, the corrected fact is used. **Not legal advice.**

---

## 1. Verdict

**Headline: feasible only as a bookmark/paste-delivered, ephemeral, read-mostly *verifier-and-launcher*
stub — NOT a shareable link, NOT the writable peerit app, and it relocates the first-contact trust
problem rather than removing it.**

Three hard walls, all fact-check-confirmed, define the shape:

- **(a) It cannot be a clickable/shareable link.** Top-level navigation to `data:text/html` is blocked
  as anti-phishing in **every** modern browser via **every** content-initiated mechanism — `<a href>`
  (incl. ctrl-click / open-in-new-tab), `window.open`, `window.location`, meta-refresh, and 302/redirect
  (Chrome 60, Edge 79, Firefox 59, Safari 14, iOS Safari 14, Samsung 8.2; ~93.8% of global browsers).
  The **only** top-level entry that works is a human **typing/pasting the string into the address bar,
  or a bookmark**. "Hand someone a `data:` link" is dead on arrival; the realistic delivery is "paste
  this blob / import this bookmark," which is worse UX than a URL and is *itself* an out-of-band trust act.

- **(b) The sandbox has no crypto and no persistence.** A `data:` doc is an opaque origin → **not a secure
  context** (`isSecureContext === false`). Therefore `crypto.subtle` is **undefined** (only
  `crypto.getRandomValues` survives), and `localStorage` / `sessionStorage` / `document.cookie` /
  `indexedDB.open()` all throw `SecurityError`. peerit's shipped `js/crypto.js` backend is exactly
  `subtle | node | none` with **no pure-JS/WASM fallback**, so in a `data:` doc it lands on
  `backend='none'` and can sign/verify **nothing**. Everything security-critical — Ed25519 verify of the
  manifest, the signed relay-roster check (`js/relay-roster.js`), identity keygen/sign, and
  `identity-export.js` (which explicitly refuses to export when `!isSecure()`) — is gone in the sandbox.

- **(c) So "run peerit in the sandbox" is impossible; only "verify then hand off" is possible.** The stub
  can `fetch()` a content-addressed bundle (cross-origin, `Origin: null`, satisfied by wildcard-CORS
  gateways) and carry a **bundled pure-JS Ed25519 + SHA-256** to verify it — but the verified app still
  cannot run *with identity or storage* inside the opaque origin. Writing (posting, holding your Ed25519
  seed, gossiping an outbox) **requires a real secure origin**.

**What that leaves as genuinely buildable:**
- ✅ **Ephemeral read-only viewer** — paste blob → verify bundle → render a snapshot/feed fetched from a
  CORS gateway. No identity, no writes, nothing survives the tab.
- ⚠️ **Writable app** — only via **handoff to a real HTTPS origin** (PWA/TOFU or user-run localhost), at
  which point an origin is reintroduced (albeit a self-hosted / user-controlled one).
- ❌ **"Shareable `data:` link that boots the full app for anyone"** — not achievable in any current browser.

---

## 2. Architecture (the design that survives the constraints)

**Stub (baked into the `data:` blob):** (1) a pinned Ed25519 pubkey (trust root) + expected manifest
content-hash; (2) a **self-contained pure-JS Ed25519 `verify` + SHA-256** — net-new, because
`crypto.subtle` is absent; (3) a fetcher for the signed manifest + bundle from a content-addressed CORS
source; (4) a verifier that recomputes SHA-256 and checks the manifest signature against the pinned key,
refusing on mismatch; (5) a runner (viewer) or handoff (writer).

**Encoding: percent-encode, not base64.** For mostly-ASCII HTML/JS, percent-encoding beats base64's fixed
+33%. Byte caps are *not* the constraint (Chromium/FF ~512 MB, Safari ~2 GB); **address-bar ergonomics**
are — keep the human-inspectable trust root **well under ~8 KB**. Inline only the stub; fetch the real
bundle. A WASM Ed25519 likely busts the budget → prefer a compact pure-JS (noble-style) Ed25519.

**Trust chain:** `pinned pubkey (in blob)` → `fetch signed manifest` → `verify manifest sig with pinned
key` → `fetch bundle/BlindShards` → `recompute SHA-256, compare` → `run (viewer) or hand off (writer)`.
Cryptographically sound **relative to the root** — but the root is the one unverified thing (§5 R6).
Reuses the shape of `build-web.mjs`'s `asset-manifest.json` (SHA-256 of every file) + `verify.html`; adds a
**signing** step over the manifest (net-new; today integrity rides on SRI + SW pin).

**Run mechanism (viewer):** verified JS executes in the same opaque origin (running it can't grant a secure
context). Use `blob:` URL + dynamic `import()`. Chrome additionally needs a paste-then-`window.open()`-then-
`<iframe src="data:...">` workaround to reach the doc; Firefox/Safari render address-bar-entered
`data:text/html` directly.

**Persistence handoff (the crux — opaque origin has no IndexedDB but peerit needs it):**
- **Mode A — Ephemeral viewer** (only fully-in-sandbox option): no identity, no writes, read-only snapshot.
  Buildable, limited.
- **Mode B — Identity-import-per-session**: needs a full pure-JS reimplementation of Ed25519 *sign* +
  PBKDF2/AES-GCM (all `crypto.subtle` today) → large net-new hand-rolled crypto surface + audit risk.
- **Mode C — Handoff to a real origin** (the honest writable answer): the stub is a *verifying launcher*
  that installs/opens the verified bundle at a genuine HTTPS origin (PWA or user-run localhost) where the
  **shipped** peerit runs unchanged. Reintroduces an origin, but a user-controlled one.

**Resolution:** the tension is not resolvable inside the sandbox. Ship **Mode A** as the sandbox-native
artifact; treat **Mode C** as the writable path; treat **Mode B** as a gated research spike. Do **not**
claim the full identity-bearing app runs from a `data:` URL.

---

## 3. Works-in-all-browsers reality (fact-checked)

| Capability | Chrome/Edge | Firefox | Safari (desktop) | Mobile |
|---|---|---|---|---|
| Top-level `data:` via link / `window.open` / `location` / meta-refresh / redirect | ❌ blocked | ❌ blocked | ❌ redirect blocked; direct-nav coverage *uncertain*¹ | ❌ blocked |
| Top-level `data:` via address-bar type/paste | ✅ | ✅ | ✅ | ⚠️ pasting multi-KB blobs is painful |
| Bookmark a `data:` URL | ✅ | ✅ | ✅ | ⚠️ awkward |
| `data:` as `<iframe>`/subresource of a real page | ✅ | ✅ | ✅ | ✅ |
| `crypto.subtle` in the `data:` doc | ❌ | ❌ | ❌ | ❌ |
| `crypto.getRandomValues` in the `data:` doc | ✅ | ✅ | ✅ | ✅ |
| localStorage / IndexedDB / cookies in the `data:` doc | ❌ | ❌ | ❌ | ❌ |
| `fetch()` to wildcard-CORS gateway (`Origin: null` → `ACAO:*`) | ✅ | ✅ | ✅ | ✅ |
| `wss://` WebSocket from `data:` doc (relay must accept `Origin: null`) | ✅ | ✅ | ✅ | ✅ |
| `blob:` + `import()` to run verified JS in-sandbox | ✅ | ✅ | ✅ | ✅ |

¹ Fact-check flagged the Safari claim *uncertain*: the cited WebKit commit blocks *redirects* to `data:`,
not demonstrably meta-refresh / JS-redirect / direct top-level nav. Verify empirically (Phase 0).

**Net:** the only universally-working delivery is **manual address-bar paste or bookmark on desktop**;
Chrome needs the window→iframe trick for anything programmatic. **Mobile is effectively unusable** for
pasting multi-KB blobs — a real UX ceiling.

---

## 4. Phased build plan

- **Phase 0 — kill-or-continue spike (~1–2 days).** A hand-written `data:text/html` blob that, when pasted
  into the address bar, (1) `fetch()`es a small JS payload from a wildcard-CORS gateway, (2) verifies it
  with a bundled **pure-JS Ed25519 + SHA-256** against a hard-coded pubkey, (3) runs it via `blob:`+
  `import()`. Test in Chrome (incl. window→iframe), Firefox, Safari + note mobile. **Kill if** verify+run
  fails in any engine, or the pure-JS Ed25519 blows the ~8 KB budget.
- **Phase 1 — ephemeral read-only viewer (Mode A, ~3–5 days).** Fetch peerit's real read-only render path +
  a feed snapshot from a CORS gateway (IPFS **subdomain** gateway or self-run HyperGateway with `ACAO:*`;
  `arweave.net`, **not** raw Arweave nodes). Reuses `js/verify.js` + `gossip.js admit`; net-new: a viewer
  entrypoint that runs without `localStorage`/`crypto.subtle`.
- **Phase 2 — distribution + inspectability (~2–3 days).** Solve "how does a user get the *right* blob":
  short/fingerprintable key display, cross-channel fingerprint publication, signed-release page, QR.
- **Phase 3 — writable via handoff (Mode C, ~1–2 weeks).** Stub becomes a verifying launcher that installs/
  opens the verified bundle at a real origin (PWA / localhost) where shipped peerit runs unchanged; wire
  `identity-export.js` for key portability.
- **Phase 3-alt (research only) — in-sandbox writable (Mode B).** Pure-JS Ed25519 sign + PBKDF2/AES-GCM.
  High effort, high audit risk. Do not commit without Phase 0 + a crypto-core audit budget.

**Do NOT ride on `dht-transport.js`** for any sandbox path: it needs IndexedDB (Corestore/`random-access-web`)
which throws in an opaque origin, is experimental/excluded-from-publish, and uses a do-not-use-in-prod
dht-relay. BlindShard `shard.js`/`box.js` verify/decode logic can be reused for content-addressed fetch+
verify, but its crypto also assumes `crypto.subtle` → needs the pure-JS core first.

---

## 5. Open risks / kill-criteria

| # | Risk | Cheap experiment (before heavy investment) | Kill-criterion |
|---|---|---|---|
| R1 | No secure context → no `crypto.subtle` | Phase 0: pure-JS Ed25519 verify in a real `data:` doc, 3 engines | Can't fit a trustworthy compact pure-JS Ed25519 in budget + pass audit → sandbox verify dead, only Mode C survives |
| R2 | No persistence in opaque origin | Confirm storage APIs throw in each engine (5 min) | Confirmed → writable-in-sandbox off the table without full pure-JS crypto |
| R3 | Not a shareable link (anti-phishing) | Try link/`window.open`/paste in 3 engines (30 min) | Confirmed → reframe deliverable as "paste/bookmark blob" |
| R4 | Mobile unusable for multi-KB paste | Paste a 4–8 KB blob into iOS Safari + Android Chrome | Unusable → desktop-only tool |
| R5 | CORS reachability of the source | curl gateway for `ACAO`; test null-origin fetch | Prefer IPFS subdomain gateways / self-run HyperGateway; raw Arweave has no CORS |
| **R6** | **Trust distribution / correct-link first-contact (the strategic risk)** | Prototype fingerprint cross-publication + short-key display; user-test whether anyone verifies | **No realistic path gets users the *correct* root → scheme is lateral-to-worse than status quo** |
| R7 | Budget blowout (crypto + loader > ~8 KB) | Measure Phase-0 stub size | > tens-of-KB → move crypto core into fetched-and-verified payload |
| R8 | Hand-rolled crypto bugs | RFC 8032 test vectors + differential vs `crypto.subtle` | Fails vectors → do not ship |

---

## 6. How it fits (BlindShard north star + operator liability)

A **genuine but partial** move toward the "pure pipe" ideal, and it must be sold honestly. **What it really
changes:** the operator stops *serving the app JS*, so the "origin ships the JS every visit, can't prove you
ran the audited code" ceiling no longer sits on peerit.site — a real shift in where the serving role and
liability sit, directionally aligned with removing the operator from the trust/serving path. **What it does
NOT change:** it **relocates rather than eliminates** the first-contact problem. Today you trust "the JS
peerit.site served me"; tomorrow you trust "the pubkey baked into the blob someone handed me" — an equally
unaudited artifact obtained equally out-of-band (R6). The downstream signature chain over p2p-fetched code
is strong, but it is verification *relative to an unverified root*, and a chain is only as trustworthy as its
root. On top of that the scheme **buys new breakage**: no shareable link, no `crypto.subtle`, no persistence,
mobile-hostile paste, and a writable app that only returns by handing off to a real origin.

**Bottom line:** build it (if at all) as an **ephemeral verifying viewer/launcher** that demonstrably removes
peerit.site from the *serving* path — a real, defensible liability improvement that fits BlindShard. Do
**not** pitch it as "the final piece that removes the operator from the trust path" or "a shareable link that
boots the full app": it is neither. Its ceiling is a sandboxed verifier whose security collapses to the
**correct-root-key distribution problem (R6)** — solve that convincingly first, or the whole exercise is a
lateral move dressed as a reduction.
