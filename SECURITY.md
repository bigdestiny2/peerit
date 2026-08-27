# Security policy

Peerit treats signatures, canonical record encoding, identity custody,
capability scope, deterministic merge, browser persistence, and signed release
verification as security boundaries. Availability and privacy claims are also
kept deliberately narrower than the cryptography alone might suggest.

## Supported versions

Security fixes target the current `main` branch and the currently deployed,
signed Peerit release. Historical commits, old release sequences, experimental
branches, and superseded protocol candidates do not receive routine patches.
When a fix changes a wire format or trust root, the advisory will state the
affected release sequence and migration boundary.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/bigdestiny2/peerit/security/advisories/new).

Include as much of the following as is safe:

- affected commit, release sequence, runtime, and browser or host version;
- the violated security property or trust boundary;
- minimal reproduction steps or a proof-of-concept using test-only keys and
  local fixtures;
- realistic impact and attacker prerequisites;
- whether the issue crosses a relay, browser origin, identity, storage,
  protocol, or release-signing boundary; and
- any suggested remediation or relevant regression test.

Never send a real private key, signing seed, read capability, identity export,
custodian key, relay credential, access token, private operator URL, or an
unredacted vault. Maintainers can request narrowly scoped follow-up evidence
through the private advisory.

Please allow time for validation and coordinated remediation before public
disclosure. The project will credit reporters who want attribution, unless legal
or safety constraints prevent it.

## What belongs in a security report

Examples include:

- forging, misattributing, replaying, or mutating an admitted record;
- bypassing canonical encoding, content identity, author binding, moderation
  authority, proof-of-work, or capability limits;
- extracting or silently replacing browser-held identity material;
- accepting stale, incomplete, unsigned, or mismatched release artifacts as
  current;
- turning an ambiguous write or retry into duplicate or unauthorized state;
- crossing the documented blind-storage or relay-visible-data boundary;
- persistent cross-site scripting, unsafe URL handling, service-worker cache
  poisoning, or a CSP bypass in the shipped app; and
- a dependency or build compromise that can alter signed output without being
  detected by the repository's verification gates.

## Documented limitations are not automatically vulnerabilities

Peerit's design does not by itself guarantee one-human-one-identity, globally
fair first-claim names, anonymity, secrecy for public content, or availability
when every holder of required data is offline. An untrusted relay may withhold or
delay bytes; the important security question is whether it can make a client
accept forged, unauthorized, or impermissibly stale state.

These limitations are summarized in the [project overview](README.md), the
[patterns guide](PATTERNS.md), and the
[durability specification](docs/P2P-DURABILITY-SPEC.md). Report an issue when the
implementation violates those documented boundaries, presents a weaker state as
verified, or permits an attacker to cross a boundary the project claims to
enforce.

## Handling security-sensitive changes

Security fixes should include a regression test that fails on the vulnerable
behavior and passes on the remediation. Avoid placing exploit details in public
branches before a coordinated patch is ready. Release-signing, live relay,
credential, and deployment actions require separate operator authority; a code
review does not grant it.
