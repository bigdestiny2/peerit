## Summary

<!-- What changed, and what problem does it solve? -->

## Affected surfaces

<!-- Check every relevant surface. -->

- [ ] PearBrowser runtime
- [ ] Normal-browser runtime
- [ ] Local development fallback
- [ ] Identity, signatures, canonical encoding, or record admission
- [ ] Storage, journal, retry, replication, or recovery
- [ ] Blind substrate, relay integration, or protocol/profile artifacts
- [ ] Generated or vendored files
- [ ] Web release, service worker, deployment, or operator tooling
- [ ] Documentation, examples, or GitHub community files only

## Trust and compatibility

<!-- Describe changes to authority, key custody, relay visibility, availability,
rollback protection, compatibility, or public claims. Write "No change" when
none apply. -->

## Verification

<!-- List exact commands and results. Distinguish deterministic local tests from
browser, live-network, or operator evidence. -->

```text
command -> result
```

## Pattern maturity and documentation

<!-- If this adds or changes a reusable browser-P2P pattern, use one catalogue
label: CORE / TESTED, BOUNDED RELEASE, INTEGRATION PROOF, DESIGN / UNPROVEN, or not
applicable. Link implementation and adversarial evidence, and state non-goals. -->

- Maturity: not applicable
- [ ] Public guarantees and honest limitations remain accurate.
- [ ] Relevant documentation and examples are updated.
- [ ] Local Markdown links pass `node test/github-surface.mjs`.

## Release and safety checklist

- [ ] I followed [CONTRIBUTING.md](../CONTRIBUTING.md).
- [ ] I added or updated tests for the behavior and failure mode.
- [ ] I did not commit secrets, keys, capabilities, credentials, private operator
      details, or a private vault.
- [ ] Generated and vendored changes came from their authoritative generator or
      pinning flow; I did not hand-edit drift.
- [ ] Protocol or persisted-state changes document compatibility, migration, and
      rollback behavior.
- [ ] Security-sensitive details follow [SECURITY.md](../SECURITY.md).
- [ ] No live, signing, publishing, deployment, or destructive action was taken,
      or each action and its explicit authority is described below.

## External actions

<!-- Usually "None". Otherwise list the exact live/signing/publishing/deployment
actions, approval, target, and non-secret evidence. -->

None.
