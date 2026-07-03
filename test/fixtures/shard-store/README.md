# Vendored HiveRelay shard-store contract fixtures

These files let `test/shard-store-adapter.mjs` validate peerit's client shard
adapter (`js/shard-store-adapter.js`) against the **real** shipped server code,
not a hand-rolled fake (which would just re-encode our own assumptions).

| file | provenance |
|------|------------|
| `shard-pin.js` | VERBATIM copy of hiverelay `origin/main` @ `26c02eb` `packages/services/builtin/shard-store/shard-pin.js` (v0.22.0 source). Pin envelope + `verifyShardPin` + `authorizeShardPin`. Depends only on `sodium-universal`, `b4a`, `./shard-engine.js`. |
| `http-adapter.js` | VERBATIM copy of the same commit's `http-adapter.js`. `resolveShardRoute` + `handleShardHttp` — the exact HTTP request parsing + response shaping the deployed `/api/v1/shard` bridge runs. |
| `shard-engine.js` | STUB — only the three PURE functions the two files above import (`normalizeShardAddress`, `shardError`, `shardHash`), copied verbatim. The real engine's hyperblobs+hyperbee CAS is replaced by an in-memory Map in the test, since peerit does not vendor those deps and the HTTP/pin layer never touches the CAS directly. |

To refresh after a hiverelay release:

```
HR=../../00-core/hiverelay
git -C $HR show origin/main:packages/services/builtin/shard-store/shard-pin.js > shard-pin.js
git -C $HR show origin/main:packages/services/builtin/shard-store/http-adapter.js > http-adapter.js
# re-check shard-engine.js still matches the three pure functions
```

The client adapter itself replicates the tiny pin-envelope serialization
(`stable`/`pinBody`/`shardPinSignable`) because the browser build cannot import
hiverelay source; the test cross-checks that replica against the vendored
`verifyShardPin` so any drift fails loudly.
