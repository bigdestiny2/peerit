# Contributing to peerit

Thanks for helping improve peerit. This repository combines a browser product,
P2P protocol work, security-sensitive verification code, generated release
artifacts, and operational tooling. A useful change is not only correct; it is
clear about which runtime it affects, what it guarantees, and how that claim was
tested.

## Before you start

- Read the [project overview](README.md) and the reusable
  [browser-P2P patterns](PATTERNS.md).
- Search existing issues before opening a new one.
- Use a public issue for bugs, features, and pattern proposals. Report suspected
  vulnerabilities privately under the [security policy](SECURITY.md).
- Discuss broad protocol, storage, identity, or release-authority changes before
  investing in a large patch. Compatibility and rollout constraints are part of
  the design, not follow-up work.

## Set up a development checkout

Peerit requires a supported Node.js 22 or newer release. The shipped app has no runtime npm
dependencies, but its tests, browser harnesses, generators, and release tools do.

```sh
git clone https://github.com/bigdestiny2/peerit.git
cd peerit
npm ci
npm run dev
```

The local server listens on `127.0.0.1:8777`. It is a development fallback, not a
production relay.

Never add real signing seeds, read-capability vaults, custodian keys, relay
credentials, identity exports, or operator evidence containing secrets to the
repository. Do not use `git add -A` around launch or release work; inspect the
exact paths you intend to stage.

## Choose the right validation level

Run the smallest relevant test while iterating, then the complete applicable
gate before requesting review.

```sh
# One focused test
node test/<relevant-test>.mjs

# Core repository suite
npm test

# Blind-substrate and protocol/profile closure
npm run test:peerit-substrate

# GitHub documentation and repository-hygiene surface
node test/github-surface.mjs
```

Browser-facing changes also need a real browser gate:

```sh
npx --no-install playwright install chromium firefox webkit
npm run test:browser:signed-release
npm run test:browser
npm run test:browser:mobile
npm run test:accessibility
```

Choose additional platform or release gates from `package.json` based on the
changed surface. Networked proofs, live drills, signing ceremonies, deployment,
and publish commands are not ordinary contributor tests. Do not run an
outward-facing command without explicit operator authority and the required
credentials.

## Change the authoritative source

- Edit application source under `js/`, root HTML/CSS, protocol source, or the
  relevant generator. Do not hand-edit a generated copy merely to make a drift
  check pass.
- The committed `web/` tree is a signed release artifact. Regenerate and verify
  it through the documented release path when a change actually requires a new
  web candidate; see [web deployment](docs/WEB-DEPLOYMENT.md).
- Vendored clients, protocol bundles, schemas, vectors, and authority files must
  retain their exact provenance and pass their existing pin/generation checks.
- Keep tests deterministic and offline unless their name and documentation make
  the live-network boundary explicit.

## Document a browser-P2P pattern

Peerit is also a reference implementation. When proposing or documenting a
reusable pattern, include:

1. the browser or P2P constraint that motivated it;
2. the authority and trust boundary;
3. what the pattern guarantees and explicitly does not guarantee;
4. its maturity using the catalogue labels: `CORE / TESTED`, `BOUNDED RELEASE`,
   `INTEGRATION PROOF`, or `DESIGN / UNPROVEN`;
5. links to the smallest implementation and adversarial tests that demonstrate
   it; and
6. failure, recovery, and migration behavior.

Do not promote an experiment to a current guarantee solely because code exists.
Claims need evidence from the runtime and topology to which they apply.

## Code and test conventions

- Use ES modules and follow the existing JavaScript style.
- Prefer small modules with explicit dependency injection at transport, storage,
  clock, entropy, identity, and filesystem boundaries.
- Add adversarial or fault-injection coverage for changes to signatures,
  canonical encoding, key binding, capabilities, retry identity, persistence,
  conflict resolution, or release verification.
- Fail closed on ambiguous security or durability results. A warning is not
  release evidence.
- Keep error output useful without printing secret bytes, credential-bearing
  URLs, or private filesystem paths.
- Preserve compatibility deliberately. If compatibility is broken, document the
  cutoff, migration, and rollback behavior.

## Pull requests

Keep a pull request focused and complete the repository pull-request template.
Reviewers should be able to answer these questions from the description:

- What changed, and why is this the right layer for it?
- Which runtimes and trust boundaries are affected?
- Which tests or evidence passed?
- Are generated, vendored, protocol, documentation, or release artifacts
  intentionally changed?
- Does this change any public guarantee or limitation?
- Were any live, signing, publishing, or destructive actions performed?

Short, scoped commits are easier to audit. Commit messages should describe the
behavioral change, not only the files touched.
