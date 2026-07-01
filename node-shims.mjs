// node-shims.mjs — esbuild --inject shim for the in-browser DHT bundle.
//
// The Holepunch stack (hypercore/corestore/hyperswarm) was written for Node and
// reaches for a handful of Node globals that don't exist in a browser:
//   - Buffer          → the `buffer` npm polyfill (already a transitive dep)
//   - process.nextTick → real unguarded use in hypercore's close path
// esbuild replaces bare `Buffer`/`process` identifiers with these exports.
// `global` is handled separately by `--define:global=globalThis` (it appears as
// `global.Pear?...` property access, which --define rewrites but --inject can't).
import { Buffer as _Buffer } from 'buffer'

export const Buffer = _Buffer

// Minimal process: just enough for what the bundle actually touches. nextTick
// maps to a microtask (ordering close enough for hypercore's deferred callbacks).
export const process = {
  nextTick: (fn, ...args) => queueMicrotask(() => fn(...args)),
  env: {},
  browser: true,
  version: 'v20.0.0',
  platform: 'browser',
  argv: [],
  cwd: () => '/',
  on: () => {},
  once: () => {},
  off: () => {},
  removeListener: () => {}
}
