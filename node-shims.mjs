// node-shims.mjs - esbuild --inject shim for the browser DHT bundle.
// The Holepunch stack still has a few Node-global reads after browser-field
// resolution. Keep the shim tiny and explicit so the generated bundle stays
// browser-native apart from Buffer/process compatibility.
import { Buffer } from 'buffer'

const process = globalThis.process || {
  browser: true,
  env: {},
  argv: [],
  version: '',
  versions: {},
  cwd: () => '/',
  nextTick: (fn, ...args) => queueMicrotask(() => fn(...args))
}

if (!globalThis.Buffer) globalThis.Buffer = Buffer
if (!globalThis.process) globalThis.process = process

export { Buffer, process }
