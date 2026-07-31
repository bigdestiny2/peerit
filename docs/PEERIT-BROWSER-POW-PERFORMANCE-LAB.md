# Peerit browser PoW performance lab

This lab answers one narrow question: how quickly does Peerit's production
browser `js/pow-current.js` `mint()` loop attempt candidate SHA-256 hashes on the
desktop engines available on the machine running the lab?

It is client spam-friction evidence. It is not HiveRelay admission evidence,
relay enforcement evidence, an adversarial-security proof, or authorization to
change difficulty or release software.

## Run it

```sh
npm run measure:pow-browser
```

The default run asks Playwright for Chromium, Firefox, and WebKit, executes them
sequentially, and measures community, post, and comment targets separately. A
missing engine is recorded as `unavailable`; use the strict command when all
three installed desktop engines are required:

```sh
npm run measure:pow-browser:strict -- --out /tmp/peerit-pow-browser.json
npm run verify:pow-browser-report -- --in /tmp/peerit-pow-browser.json
```

Useful bounded overrides are:

```sh
node scripts/browser-peerit-pow-performance.mjs \
  --browser chromium \
  --warmup-hashes 4096 \
  --sample-hashes 32768 \
  --samples 6 \
  --timeout-ms 30000
```

Warm-up and sample counts must be multiples of 1,024 because that is the exact
progress/cancellation boundary in the production implementation. Counts and
timeouts are bounded by the CLI parser. Samples run in rotating action order so
each action occupies every position in a three-round cycle instead of making a
later action inherit all warm-session slowdown.

## What is actually measured

The lab serves the exact bytes of `js/pow-current.js` from a loopback-only HTTP
server. Each browser hashes those source bytes itself before importing the
module. The browser then calls production `mint()` with an artificial 256-bit
benchmark target and aborts exactly on a configured progress boundary. This
makes every sample a fixed amount of real production-loop work rather than a
lucky or unlucky first-success sample.

The reported unit is effective candidate SHA-256 attempts per second. It
includes the production target-hash setup, asynchronous Web Crypto calls, and
the event-loop yield every 1,024 candidates, so it is deliberately not a claim
about raw hardware SHA-256 throughput. A low-cost four-bit `mint()`/`verify()`
round trip checks semantics after each action benchmark; it is not a production
difficulty timing sample.

Each action reports aggregate throughput plus the sample minimum, median,
maximum, mean, standard deviation, and coefficient of variation. Modeled
latencies always use the minimum observed sample rate. That is intentionally
conservative and keeps a noisy or slowing browser session visible instead of
letting a fast aggregate silently produce optimistic tails.

For action difficulty `b`, the model assumes each candidate is an independent,
uniform SHA-256 output with success probability `p = 2^-b`. The first-success
attempt quantile is:

```text
n(q) = ceil(log(1 - q) / log(1 - p))
```

The lab divides `n(0.50)`, `n(0.95)`, and `n(0.99)` by the measured
action-specific effective candidate rate. These are modeled stochastic
latencies under constant throughput, not observed production tail latencies.

## Evidence boundary

The verifier owns the current source hash, PoW version, action difficulty bits,
geometric math, aggregate math, and the closed report shape. Editing a report's
difficulty, model, claim boundary, or adding a `ready` threshold fails even if
the content checksum is recomputed.

The checksum only detects accidental or unresealed mutation. It is not a
signature and proves no author, host, browser binary, or measurement honesty.
Every valid report therefore keeps `authentic`, `difficultyChangeAuthorized`,
and `releaseReady` false and records these unmeasured surfaces:

- relay admission and enforcement;
- adversarial resistance and abuse economics;
- mobile devices and production device distributions;
- production load, thermal throttling, background contention, and energy use.

Use this lab to identify client performance work and to build a real device
matrix. Treat relay admission as a separate blind-substrate protocol and test
it at the relay boundary with its own authority and evidence.
