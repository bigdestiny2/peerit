# Peerit documentation

Peerit has accumulated production code, signed release evidence, protocol
contracts, experiments, plans, reports, and visual explainers. They are not all
current at the same time. This index tells readers which documents answer which
question and how to interpret older material.

## Start here

| Question | Document | Status |
| --- | --- | --- |
| What is Peerit today? | [`EXPLAINER.md`](../EXPLAINER.md) | Current plain-language explanation |
| What is deployed, signed, and active? | [`CURRENT-STATUS.md`](./CURRENT-STATUS.md) | Current release/source/activation matrix |
| How do the runtime and P2P patterns fit together? | [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Current architecture and maturity catalogue |
| What exactly does Sequence 29 permit? | [`SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md`](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md) | Normative bounded-test contract |
| What was activated? | [`deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json`](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json) | Accepted release decision |

The one-line status is:

> Sequence 29 is deployed as a coherent artifact accepted under the bounded
> `LIVE_PUBLIC_TEST_ONLY` decision. Its public-network path is currently blocked
> pending a signed INBOX epoch rotation and limited Cell-GET runtime repair.
> General availability remains blocked. Pear host-backed identity is implemented
> on `main` but is not in the signed Sequence 29 artifact.

Evidence for each clause is collected in
[`CURRENT-STATUS.md`](./CURRENT-STATUS.md#status-at-a-glance).

## Authority order

When documents disagree, use this order:

1. Exact signed artifacts, manifests, pin history, and accepted release
   decisions.
2. Normative protocol and release contracts for that exact sequence.
3. Current implementation and executable tests.
4. [`CURRENT-STATUS.md`](./CURRENT-STATUS.md) and
   [`ARCHITECTURE.md`](./ARCHITECTURE.md).
5. Research notes, plans, roadmaps, reports, and explainers.

Prose cannot promote a fixture to a release, broaden a bounded claim, or make a
source-only feature part of an already signed artifact.

## Current release and protocol references

These documents are relevant to the current blind-substrate path, but their
scope still matters:

| Document | Scope |
| --- | --- |
| [`SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md`](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md) | Normative limits for the two-relay Sequence 29 public INBOX test |
| [`PEERIT-BLIND-SUBSTRATE-PROFILE.md`](./PEERIT-BLIND-SUBSTRATE-PROFILE.md) | Peerit application profile over the blind substrate; does not by itself prove a deployed product |
| [`PROTOCOL-V3-CONTENT-IDENTITY.md`](./PROTOCOL-V3-CONTENT-IDENTITY.md) | Application content-identity rules |
| [`identity-recovery-protocol.md`](./identity-recovery-protocol.md) | Historical signed-outbox recovery design plus current-source web identity notes; not a Sequence 29 release claim |
| [`WEB-DEPLOYMENT.md`](./WEB-DEPLOYMENT.md) | Deployment reference; release only through the signed artifact pipeline |
| [`BRIDGE_VERIFICATION.md`](./BRIDGE_VERIFICATION.md) | Host-bridge verification material; not evidence that the Sequence 29 web closure uses the legacy bridge |
| [`PEERIT-SEQ29-CUSTODIAN-KEY-PROVISIONING.md`](./PEERIT-SEQ29-CUSTODIAN-KEY-PROVISIONING.md) | Offline Sequence 29 custodian-key provisioning procedure |

For the exact released bytes, use the checked-in
[`web/peerit-app-artifact-v1.json`](../web/peerit-app-artifact-v1.json),
[`web/asset-manifest.json`](../web/asset-manifest.json), and release decision.

## Pattern and research library

These documents explain useful designs and experiments. They are not release
claims unless [`CURRENT-STATUS.md`](./CURRENT-STATUS.md) says otherwise.

### Browser and trust boundaries

- [`BROWSER-PEAR-APPS-THE-HONEST-CEILING.html`](./BROWSER-PEAR-APPS-THE-HONEST-CEILING.html)
- [`DATA-URL-BOOTSTRAP-SCOPE.md`](./DATA-URL-BOOTSTRAP-SCOPE.md)
- [`BROWSER-ZERO-TRUST-PROOF-EXPLAINER.html`](./BROWSER-ZERO-TRUST-PROOF-EXPLAINER.html)

### Local durability, discovery, and scale

- [`P2P-DURABILITY-SPEC.md`](./P2P-DURABILITY-SPEC.md)
- [`availability.md`](./availability.md)
- [`ROCKSDB-IDB-BROWSER-STORAGE-DISCOVERY.md`](./ROCKSDB-IDB-BROWSER-STORAGE-DISCOVERY.md)
- [`BATCH-RANGES-PROTOCOL.md`](./BATCH-RANGES-PROTOCOL.md)
- [`SCALE-READINESS-PLAN.md`](./SCALE-READINESS-PLAN.md)
- [`PEERIT-BROWSER-POW-PERFORMANCE-LAB.md`](./PEERIT-BROWSER-POW-PERFORMANCE-LAB.md)

### Relay, capability, and privacy experiments

- [`BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md`](./BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md)
- [`BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md`](./BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md)
- [`PURE-PIPE-SCOPE.md`](./PURE-PIPE-SCOPE.md)
- [`SPLIT-TRANSPORT-SPEC-V1-2026-07-26.md`](./SPLIT-TRANSPORT-SPEC-V1-2026-07-26.md)
- [`RELAY-TAKEDOWN-SPEC.md`](./RELAY-TAKEDOWN-SPEC.md)
- [`OPERATOR-LIABILITY.md`](./OPERATOR-LIABILITY.md)

### Threshold dispersal / BlindShard

- [`BLINDSHARD-DESIGN.md`](./BLINDSHARD-DESIGN.md)
- [`BLINDSHARD-ADVERSARIAL-REVIEW.md`](./BLINDSHARD-ADVERSARIAL-REVIEW.md)
- [`BLINDSHARD-RECORD-WIRING-SPEC.md`](./BLINDSHARD-RECORD-WIRING-SPEC.md)
- [`BLINDSHARD-BLOB-SURFACE-HANDOVER.md`](./BLINDSHARD-BLOB-SURFACE-HANDOVER.md)

Sequence 29 excludes the legacy dispersal writer modules from its signed
closure
([closure test](../test/peerit-substrate-build-closure.mjs#L370-L390)). Read
these as experimental/research material, not as a description of the deployed
Sequence 29 transport.

### Product policy

- [`COMMUNITY-MODERATION-AND-PLUGGABLE-FEEDS-RESEARCH.md`](./COMMUNITY-MODERATION-AND-PLUGGABLE-FEEDS-RESEARCH.md)
- [`NOTIFY-INTEGRATION.md`](./NOTIFY-INTEGRATION.md)

The replacement UI currently ships local feed and moderation projections. It
does not follow that every proposed notification, reputation, or governance
surface is released.

## Historical material

Historical documents remain valuable because they preserve threat models,
failed approaches, release evidence, and the reasoning behind newer patterns.
They must not be read as the current product contract.

Treat the following as **historical by default** unless a current truth page
explicitly cites a still-active invariant:

- dated plans, status pages, reports, and handovers whose title or filename
  names an earlier point in time;
- release notes and decisions for Sequences 13 through 28;
- `VNext`, cutover, launch, migration, remediation, and delivery plans written
  before the accepted Sequence 29 decision;
- generated `HOW-*.html` explainers that describe an earlier topology; and
- the superseded signed-outbox-only description in
  [`docs/pattern.md`](./pattern.md). The root [`PATTERNS.md`](../PATTERNS.md) is
  the current maturity-labelled catalogue.

Concrete examples include:

- [`VNEXT-CUTOVER-REPORT-2026-07-31.html`](./VNEXT-CUTOVER-REPORT-2026-07-31.html)
- [`PEERIT-OPS-ARCHITECTURE-2026-07-19.html`](./PEERIT-OPS-ARCHITECTURE-2026-07-19.html)
- [`HIVERELAY-STATUS-JULY19-VS-JULY26.html`](./HIVERELAY-STATUS-JULY19-VS-JULY26.html)
- [`PEERIT-LAUNCH-STATUS-SEQ25-2026-08-06.html`](./PEERIT-LAUNCH-STATUS-SEQ25-2026-08-06.html)
- [`T2-BROWSER-WRITES-LANE-PLAN-2026-08-06.md`](./T2-BROWSER-WRITES-LANE-PLAN-2026-08-06.md)
- [`ROADMAP-NEXT-2026-08.md`](./ROADMAP-NEXT-2026-08.md)
- [`PEAR-ECOSYSTEM-VNEXT-COMPLETION-AND-LAUNCH-MASTER-PLAN.md`](./PEAR-ECOSYSTEM-VNEXT-COMPLETION-AND-LAUNCH-MASTER-PLAN.md)
- [`PUBLIC-RELEASE-REMEDIATION-PLAN.md`](./PUBLIC-RELEASE-REMEDIATION-PLAN.md)

[`how-peerit-works.svg`](./how-peerit-works.svg) is the current high-level
lifecycle visual. It deliberately omits wire formats and release ceremony; use
[`ARCHITECTURE.md`](./ARCHITECTURE.md) and the exact Sequence 29 contract for
those boundaries.

### Historical does not mean false

A historical document may still contain a correct cryptographic invariant or a
useful pattern. Reuse it by linking the current code and tests, stating the new
scope, and giving it a current maturity label. Do not revive its old deployment
or trust claims by implication.

## Status labels for new documents

New design or architecture documents should begin with a compact status block:

```text
Status: Released test | Current source | Experimental | Historical
Applies to: exact release sequence, source commit, or experiment
Last verified: YYYY-MM-DD
Evidence: code, tests, and (for release claims) signed artifact + decision
```

Use the labels consistently:

- **Released test** — in an exact signed closure with an accepted bounded
  activation decision; this does not imply that expiring network authorities
  remain active today.
- **Current source** — implemented and tested on `main`, but not necessarily
  released.
- **Experimental** — a lab, fixture, prototype, or design without current
  release authority.
- **Historical** — point-in-time context or a superseded architecture.

Do not use “production,” “fully trustless,” “serverless,” “zero trust,” or
“decentralized” without naming the exact integrity, availability, privacy,
bootstrap, and operator boundaries that support the term.

## Maintaining the truth layer

When a new sequence or P2P pattern lands:

1. Update [`CURRENT-STATUS.md`](./CURRENT-STATUS.md) only after exact evidence
   exists.
2. Update the execution-mode and pattern maturity rows in
   [`ARCHITECTURE.md`](./ARCHITECTURE.md).
3. Keep [`EXPLAINER.md`](../EXPLAINER.md) plain-language and bounded by those
   facts.
4. Add code and test links for source claims.
5. Add artifact, manifest, signature/pin, and accepted-decision links for release
   claims.
6. Mark the superseded point-in-time document historical instead of silently
   rewriting what it originally recorded.
