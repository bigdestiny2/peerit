# 2026-07-09 Peerit production read-only containment

**Applied:** 2026-07-09 19:07 UTC
**Scope:** `outbox.peerit.site` write edge and `peerit-site` deployment lock
**Reason:** hold the currently live single-relay service read-only while the
signed static hotfix and longer-term reliability work are released.

## Change

Caddy now intercepts `POST /api/sync/create` and
`POST /api/sync/append` and returns HTTP 403 with the read-only maintenance
contract. Other OutboxLog routes continue to proxy to HiveRelay on
`127.0.0.1:9100`.

This is a service-boundary control. It does not rely on the browser hiding
write buttons, and it does not change, restart, or rewrite HiveRelay.

## Verification

`npm run proof:production-readonly` passed from an external client:

- create: 403;
- append: 403;
- health: 200;
- token issuance: 200;
- directory: 200;
- existing seed range read: 200.

The HiveRelay systemd process retained PID `1116480` and its original active
timestamp (`2026-07-09 12:29:01 UTC`). The persisted OutboxLog state SHA-256 was
unchanged before and after the Caddy reload:

```text
75e8ecb2f7f3c919293c5d256c8d56ad001fbda703fc02728f7433eb27d6c21a
```

The post-change Caddyfile SHA-256 is:

```text
42b81da0a93425243228f84f6fdd9600abb9cf098f47380afe35583c66fc5a50
```

## Rollback

The exact pre-change Caddyfile is retained on the Bern host at:

```text
/etc/caddy/Caddyfile.pre-peerit-readonly-20260709T190720Z
```

Rollback requires copying that file over `/etc/caddy/Caddyfile`, validating it
with `caddy validate`, reloading Caddy, and repeating both the read and write
route checks. Do not restart or roll back HiveRelay data as part of an edge
rollback.

Public writes must not be re-enabled until the writable release gates in
`docs/PUBLIC-RELEASE-REMEDIATION-PLAN.md` pass.

## Static-site deployment lock

Render service `srv-d91q9sfavr4c73fr611g` (`peerit-site`) was also changed from
`autoDeploy: yes` to `autoDeploy: no` before any Git push. Render confirmed
`autoDeployTrigger: off`. The existing live deploy was not replaced by this
configuration change. Static releases now require an explicit full-commit
deploy after the tracked `web/` artifact passes strict verify-only.
