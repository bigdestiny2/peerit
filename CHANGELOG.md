# Changelog

Peerit has two version axes:

- **Product version** (`package.json` and `manifest.json`) tracks the application
  and developer-facing release line.
- **Signed release sequence** tracks an exact browser artifact and its trust
  history. A higher sequence does not imply general availability or a broader
  claim boundary.

Do not infer the deployed topology from the product version alone. The
[current-status page](docs/CURRENT-STATUS.md) is the maintained index for code,
artifact and deployment maturity.

## Unreleased

### GitHub and reference-app modernization

- Replaced the stale outbox-only landing page with an honest view of the
  replacement runtime, signed Sequence 29 artifact and source/release split.
- Expanded `PATTERNS.md` into an evidence-linked browser-P2P pattern catalogue
  with explicit maturity and rejected-claim labels.
- Added maintained status, architecture and documentation indexes plus
  contribution, security, issue and pull-request guidance.
- Split deterministic protocol and browser CI, added repository/link/secret-path
  guards, a deterministic smoke for the exact signed replacement artifact,
  pinned GitHub Actions by commit, and added dependency update policy.
- Raised the development floor to supported Node.js releases (22 and 24 in CI).
- Removed an accidentally tracked machine-local `node_modules` symlink and
  broadened the private read-capability-vault ignore rule.
- Documented the host-identity integration already present on `main`, including
  that it is newer than the signed Sequence 29 artifact and is not yet an
  end-to-end Sequence 29 publication path.

## Signed release sequence 29 — bounded public test

Accepted on 2026-08-16 as the `LIVE_PUBLIC_TEST_ONLY` successor for the exact
source-pinned artifacts in
[`deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json`](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json).

- Added bounded browser `CELL.PUT`, `CELL.GET`, `INBOX.APPEND` and `INBOX.READ`
  composition after authenticated boot and exact readback.
- Added a signed public-INBOX bootstrap, append/read discovery, immutable Cell
  replicas and explicit publication UI.
- Bound the test to two distinct owner-operated relays. It does **not** claim
  independent operators, production topology, completeness, anonymity,
  censorship resistance or GA readiness.

The normative boundary is
[`docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md`](docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md),
not this summary.

Operational note as of 2026-08-27: peerit.site still serves the exact coherent
Sequence 29 bytes, but the artifact's sole public-INBOX epoch was current only
through 2026-08-20. The shipped coordinator therefore blocks public-INBOX
publication and discovery pending a separately signed rotation successor. Fresh
signed-seed recovery is also blocked by the signed runtime's exact limited
Cell-GET control-surface check.

## Historical sequences

Earlier sequence decisions and evidence remain under [`deploy/`](deploy/) and
[`docs/`](docs/). They are retained for rollback, migration and audit history;
they are not the maintained statement of current behavior. Start at
[`docs/README.md`](docs/README.md) rather than selecting the newest-looking dated
filename.
