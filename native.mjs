import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const DHT = require('hyperdht'); const createTestnet = require('@hyperswarm/testnet'); const b4a = require('b4a')
const T = (p, ms, l) => Promise.race([p.then((v) => ({ ok: true, v })), new Promise((r) => setTimeout(() => r({ ok: false, v: 'TIMEOUT ' + l }), ms))])
const tn = await createTestnet(3)
const a = new DHT({ bootstrap: tn.bootstrap }); await a.ready()
const b = new DHT({ bootstrap: tn.bootstrap }); await b.ready()
const s = a.createServer(); let got = false
s.on('connection', (c) => { got = true; c.on('data', (d) => console.log('  native server DATA:', b4a.toString(d))) })
const l = await T(s.listen(a.defaultKeyPair), 10000, 'native listen')
console.log('native listen:', l.ok ? 'PASS' : l.v)
const c = b.connect(a.defaultKeyPair.publicKey)
const cc = await T(new Promise((res, rej) => { c.once('open', () => res('open')); c.once('error', rej) }), 10000, 'native connect')
console.log('native connect:', cc.ok ? 'PASS' : cc.v)
if (cc.ok) { c.write(b4a.from('hello-native')); await new Promise((r) => setTimeout(r, 1000)) }
console.log('RESULT native: listen=' + (l.ok ? 'PASS' : 'FAIL') + ' connect=' + (cc.ok ? 'PASS' : 'FAIL') + ' serverGotData=' + got)
await Promise.allSettled([a.destroy(), b.destroy(), tn.destroy()]); process.exit(0)
