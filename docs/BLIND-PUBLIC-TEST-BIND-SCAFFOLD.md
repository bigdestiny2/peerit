# Blind public-test bind scaffold (SUPERSEDED — now bound)

**Status:** `bound_public_test_canary` (superseded 2026-07-26 — see [`docs/BLIND-PUBLIC-TEST-CANARY-EVIDENCE.md`](BLIND-PUBLIC-TEST-CANARY-EVIDENCE.md)) · **Claim boundary:** `LIVE_PUBLIC_TEST_ONLY`  
**Config:** [`config/blind-public-test-bind.scaffold.json`](../config/blind-public-test-bind.scaffold.json) (signed, `bound: true` on both relays)

Peerit-side **pin and catalogue scaffold** for HiveRelay Track B public-test. Host Blind stacks may already be qualified in run evidence; **Peerit catalogue bind and seed publish stay off** until the checklist in the JSON is complete.

## Two failure domains

| Seat | ID | DNS / edge | Public IP (from evidence) |
|------|-----|------------|---------------------------|
| phase-1 | `syd-1` | `https://relay-syd.p2phiverelay.xyz:443` | `104.194.135.205` |
| phase-2 | `dal-1` | `https://relay-dal.p2phiverelay.xyz:443` | `172.86.90.115` |

Catalogue slots list both URLs with `bound: false` and `seed_publish: false`.

## Frozen pins (from run artifacts)

Source run (read-only):

`00-core/pear-agent-system/runs/hiverelay-vnext-direct-https-public-test-storage-first-20260724t110740z`

### Deployed (live-qualify evidence — use for host bind)

| Pin | Value |
|-----|--------|
| Release | `1.0.0-rc.1.public-test.1` |
| Edge linux/amd64 manifest | `sha256:949d82e387672099fc87e0e1cba2c3e2591c5eb82e7fdea413efeeae4bcc4ec1` |
| Daemon linux/amd64 manifest | `sha256:baaa83c363602b71f665f2cf4966ed5298ca72287dd2026a53fa8cd9f21a8b7e` |
| Edge OCI archive sha256 | `sha256:5aca19210990909d07b8525f9f26e718f0a220b246f2db4a646dadd9bee9eeb4` |
| Daemon OCI archive sha256 | `sha256:d73256c37a4cde954b64d2baf928b5ef90ac5f6cd424dba0666ba97636fc88c3` |
| syd-1 descriptor head | `82dbf188f51d37453980534697280530a0e370dd8d7488cd222ed246e9fe2b10` |
| syd-1 storeId | `5193f588aa3b55886e27dc35ead0777d6b3f787e575458d9b2d914f413b130de` |
| dal-1 descriptor head | `a18d0dc92a56ed41553a5ca8dee71c9b79f4afeb2d8ad2865ef858f6fbc84ea5` |

### Reconstructed manifest (pending conductor re-sign — not assumed deployed)

After worktree teardown the reconstructed `artifact-manifest.json` lists different index digests (`79a4e8e7…` / `57b7c2b1…`). Those are recorded under `pins.reconstructed_manifest_pending_resign` only; **do not mix pin sets**.

Fields with no stable named hash in frozen JSON remain `PENDING_*` (not fabricated).

## Relation to fleet Track A (`v0.25.0-rc.1`)

| Plane | Version | Port |
|-------|---------|------|
| Fleet utility relay | `v0.25.0-rc.1` canary (Track A) | `:9100` |
| Blind edge + daemon | `1.0.0-rc.1.public-test.1` (Track B) | `:443` + private socket |

See HiveRelay `docs/LADDER-SHIP-MAP.md` on branch `feat/service-http-wiring`.

## Explicit non-actions

- No Peerit seed publish from this scaffold  
- No stable/canary flip to public-test OCI tags  
- No Blind compose edits from Peerit  
- Catalogue `bound` flags stay false until Peerit two-FD e2e  

When owner review passes the JSON checklist, flip `status` / `bound` only with fresh DESCRIBE probe evidence.
