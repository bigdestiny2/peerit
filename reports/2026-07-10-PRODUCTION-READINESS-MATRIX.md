# Peerit production-readiness matrix — 2026-07-10

This is the current-state update to the original public-release audit. A pass
means evidence exists at the stated scope; it does **not** turn an unmeasured
or operator-dependent property into a claim.

## Current release posture

**Public writable canary — live. Not general-availability / marketing-scale
clearance.**

`peerit.site` serves signed release **sequence 6** from Git commit
`2bd72c1`. The artifact verification reports `readonly=false`, 44 signed assets,
and both signed control files. Its single signed ingress is
`https://outbox.peerit.site`.

## Requirement matrix

| Audit requirement | Current state | Authoritative evidence | What still makes it incomplete |
| --- | --- | --- | --- |
| Signed writable release on `main` | **Pass** | `npm run web:verify`, `npm run check:web-commit`, Render deploy `dep-d98jduvavr4c739kring`, `npm run proof:web-deploy -- --url https://peerit.site` | Nothing for artifact integrity; observe normal rollback policy. |
| Live writer route is durable and refuses legacy mutation routes | **Pass** | `npm run proof:writable-candidate -- --json`: atomic CAS/idempotent receipt, operator 12,000/60s envelope, zero preflight mutations | This is one-ingress canary durability, not independent-failure durability. |
| HTTP response hardening | **Fail — immediate edge task** | `npm run proof:http-headers -- --url https://peerit.site` fails because `Content-Security-Policy` is absent | Apply all five `deploy/render-security-headers.json` rules on Render and re-run the proof. |
| Source-controlled Render deployment policy | **Ready, not applied** | `render.yaml`; `render blueprints validate render.yaml` returned `valid: true`; `npm run verify:render-blueprint` passes | Link the Blueprint to the existing `peerit-site` service and review the matched service before applying it. |
| Live relay recovery | **Partial / canary-grade** | Live service active, zero restarts during the 2026-07-10 recheck; daily local backup timer active; prior restore drill verified JSON state/journal | Backup is still same-host; long-duration growth and a clean-host/off-host restore remain unproved. |
| One-relay failure writes without loss | **Fail** | Signed roster deliberately permits `singleIngressWriter:true`; no second receipt operator is configured | Obtain and validate an independent writable OutboxLog operator, sign a multi-origin roster, prove receipt quorum and induced failure recovery. |
| Feed rendering on growing content | **Improved** | Feed windowing/pagination tests; signed sequence 6 includes cursor-safe directory pagination and watermark delta discovery with reset and peer-cap fallback tests | No end-to-end large-content/device memory benchmark; 20k-author discovery needs an index/lazy-discovery design rather than a larger peer cap. |
| Automated browser coverage | **Pass for emulation** | `npm run test:ci`: Chromium, iPhone-shaped host path, Android-Chrome-shaped host path, Firefox, WebKit, and WCAG 2.0/2.1 A/AA checks | Real iOS persistence/reload and assistive-technology review remain manual evidence. |
| Two genuine PearBrowser devices | **Fail / operator required** | `npm run proof:bridge:local` workflow and snapshot validator exist | Run it on two isolated PearBrowser profiles/devices, including restart and bidirectional convergence, then retain the passing report. |
| 2,000-client release capacity | **Fail — hard GA gate** | `npm run launch:readiness` fails only this capacity check; local 200-client atomic run had correctness success but p99 4,866ms | Run isolated staging sweep at 100/500/1,000/2,000 with shared-NAT and distributed profiles, relay failure, and reviewed RSS budgets. A local co-located run is diagnostic only. |
| Launch content / preview cleanup | **Fail — editorial decision** | `launch/communities.json` has 13 planned boards; public content still contains test-era/legacy material | Approve curated v3 content, seed it from the intended launch identity, then archive or explicitly label historical/test communities. |

## Exact next actions

1. **Render operator:** sign in to the existing `peerit-site` dashboard, apply
   the five header rules from `deploy/render-security-headers.json` to `/*`, then
   run `npm run proof:http-headers -- --url https://peerit.site`. Link
   `render.yaml` to the existing service after checking that it matches rather
   than creates a duplicate.
2. **Relay operator + independent host:** supply the second operator endpoint
   and explicit namespace agreement; do not infer it from a generic HiveRelay
   network. The subsequent roster change requires a new signed web release.
3. **Staging operator:** reserve isolated load generators and two staging
   relays. Preserve every JSON report and failure-injection result; the pass
   condition is p99 < 2s, errors <1%, policy-compliant 429s, and RSS headroom at
   every target.
4. **Device operator:** complete the two-device PearBrowser report plus real
   iOS reload/persistence and a human screen-reader review.
5. **Editorial owner:** approve v3 communities, starter posts, archive policy,
   and production identity before any launch-content write.

Until those requirements are evidenced, call the public service a writable
canary. Do not describe it as independently durable, fully device-certified,
or marketing-scale ready.
