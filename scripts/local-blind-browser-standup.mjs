#!/usr/bin/env node

// Local-only browser stand-up for the replacement Peerit product.
//
// This starts HiveRelay's real blind daemon, public edge, and filesystem Cell
// store, then serves Peerit's existing product UI on loopback.  The browser
// qualifies the signed relay descriptor with Peerit's exact vendored HiveRelay
// client.  A bounded same-origin proxy exists only because the fixture uses an
// ephemeral self-signed certificate; it forwards exclusively to that one
// loopback edge.  No production pin, release gate, operator, or deployment
// claim is bypassed or modified.

import { execFile } from 'node:child_process'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import http from 'node:http'
import {
  readFile,
  stat
} from 'node:fs/promises'
import { promisify } from 'node:util'
import {
  dirname,
  extname,
  isAbsolute,
  join,
  normalize,
  relative,
  resolve
} from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const execFileAsync = promisify(execFile)
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_HIVERELAY_ROOT = resolve(ROOT, '..', 'hiverelay-blind')
const HOST = '127.0.0.1'
const VENDOR_DIRECTORY = join(ROOT, 'vendor', 'hiverelay-blind-client-v1')
const VENDOR_ARTIFACT_PATH = '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'
const MAX_PROXY_REQUEST_BYTES = 2 * 1024 * 1024
const MAX_PROXY_RESPONSE_BYTES = 8 * 1024 * 1024
const MIME = Object.freeze({
  '.cenc': 'application/octet-stream',
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml'
})

function fail (message, code = 'PEERIT_LOCAL_BLIND_STANDUP_INVALID') {
  const error = new Error(message)
  error.code = code
  throw error
}

function forbidden (message) {
  const error = new Error(message)
  error.code = 'PEERIT_LOCAL_BLIND_STANDUP_FORBIDDEN'
  error.statusCode = 403
  throw error
}

function parseArgs (argv) {
  const options = {
    hiveRelayRoot: resolve(process.env.HIVERELAY_BLIND_ROOT || DEFAULT_HIVERELAY_ROOT),
    port: 0,
    keepFixture: false,
    help: false
  }
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    if (argument === '--hiverelay-root') {
      const value = argv[++index]
      if (!value) fail('--hiverelay-root requires a path')
      options.hiveRelayRoot = resolve(value)
    } else if (argument === '--port') {
      const value = Number(argv[++index])
      if (!Number.isSafeInteger(value) || value < 0 || value > 65535) {
        fail('--port must be an integer within 0..65535')
      }
      options.port = value
    } else if (argument === '--keep-fixture') {
      options.keepFixture = true
    } else if (argument === '-h' || argument === '--help') {
      options.help = true
    } else {
      fail(`unknown option: ${argument}`)
    }
  }
  return options
}

function usage () {
  return `usage: node scripts/local-blind-browser-standup.mjs [options]

Options:
  --hiverelay-root <path>  isolated HiveRelay blind checkout
  --port <0..65535>        loopback Peerit port (default: available port)
  --keep-fixture           retain the temporary HiveRelay fixture after exit
  -h, --help               show this help
`
}

function hex (value) {
  return Buffer.from(value).toString('hex')
}

function jsonValue (value) {
  if (value instanceof Uint8Array || Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    return Object.freeze({ $bytes: hex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) })
  }
  if (value instanceof ArrayBuffer) return Object.freeze({ $bytes: hex(new Uint8Array(value)) })
  if (typeof value === 'bigint') return Object.freeze({ $bigint: String(value) })
  if (Array.isArray(value)) return value.map(jsonValue)
  if (value && typeof value === 'object') {
    const output = {}
    for (const [key, child] of Object.entries(value)) output[key] = jsonValue(child)
    return output
  }
  return value
}

function jsonBytes (value) {
  return Buffer.from(JSON.stringify(jsonValue(value), null, 2) + '\n')
}

function htmlBytes () {
  return Buffer.from(`<!doctype html>
<html lang="en" data-peerit-local-blind-state="loading">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; form-action 'none'">
  <meta name="peerit-substrate" content="blind-v1">
  <meta name="peerit-local-blind-standup" content="synthetic-loopback-only">
  <title>peerit — local blind-cell stand-up</title>
  <link rel="icon" type="image/svg+xml" href="/icon.svg">
  <link rel="stylesheet" href="/styles.css">
  <style>.local-fixture-banner{padding:7px 18px;text-align:center;color:#f7d774;background:rgba(247,215,116,.08);border-bottom:1px solid rgba(247,215,116,.25);font:600 12px/1.4 var(--sans)}</style>
</head>
<body>
  <div class="boot" data-local-blind-boot>
    <div class="boot-mark">P</div>
    <div class="boot-name">peerit</div>
    <div class="boot-sub">starting the local blind-cell fixture…</div>
  </div>
  <script type="module" src="/scripts/local-blind-browser-entry.mjs"></script>
</body>
</html>
`)
}

function inside (root, file) {
  const child = relative(root, file)
  return child === '' || (!child.startsWith('..') && !isAbsolute(child))
}

function staticFile (pathname) {
  if (pathname === '/styles.css' || pathname === '/icon.svg') {
    return join(ROOT, pathname.slice(1))
  }
  if (pathname === '/scripts/local-blind-browser-entry.mjs') {
    return join(ROOT, 'scripts', 'local-blind-browser-entry.mjs')
  }
  if (/^\/js\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+\.(?:js|mjs)$/.test(pathname)) {
    return join(ROOT, pathname.slice(1))
  }
  if (/^\/vendor\/hiverelay-blind-client-v1\/[A-Za-z0-9._~-]+\.(?:mjs|json|cenc)$/.test(pathname)) {
    return join(ROOT, pathname.slice(1))
  }
  return null
}

function sendBytes (request, response, statusCode, type, bytes, headers = {}) {
  response.writeHead(statusCode, {
    'Content-Type': type,
    'Content-Length': String(bytes.byteLength),
    'Cache-Control': 'no-store, max-age=0',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  })
  if (request.method === 'HEAD') response.end()
  else response.end(bytes)
}

function readRequestBody (request, maximumBytes = MAX_PROXY_REQUEST_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    let settled = false
    const removeDataListeners = () => {
      request.off('data', onData)
      request.off('end', onEnd)
    }
    const onError = error => {
      if (settled) return
      settled = true
      removeDataListeners()
      reject(error)
    }
    const onData = chunk => {
      if (settled) return
      total += chunk.byteLength
      if (total > maximumBytes) {
        const error = new Error('request exceeded the local fixture bound')
        error.statusCode = 413
        settled = true
        removeDataListeners()
        reject(error)
        // Keep the one-shot error listener installed until destroy has emitted;
        // otherwise Node may surface the asynchronous socket error as unhandled.
        request.destroy(error)
        return
      }
      chunks.push(Buffer.from(chunk))
    }
    const onEnd = () => {
      if (settled) return
      settled = true
      request.off('data', onData)
      request.off('error', onError)
      resolve(Buffer.concat(chunks, total))
    }
    request.on('data', onData)
    request.once('end', onEnd)
    request.once('error', onError)
  })
}

function listen (server, port) {
  return new Promise((resolve, reject) => {
    const onError = error => { server.off('listening', onListening); reject(error) }
    const onListening = () => { server.off('error', onError); resolve() }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(port, HOST)
  })
}

function closeServer (server) {
  if (!server.listening) return Promise.resolve()
  if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections()
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections()
  return new Promise(resolve => server.close(resolve))
}

async function repositoryState (root) {
  try {
    const commandOptions = { timeout: 10_000, maxBuffer: 1024 * 1024 }
    const commitResult = await execFileAsync(
      'git', ['-C', root, 'rev-parse', 'HEAD'], commandOptions)
    let trackedDirty = false
    for (const args of [
      ['-C', root, 'diff', '--quiet', '--'],
      ['-C', root, 'diff', '--cached', '--quiet', '--']
    ]) {
      try {
        await execFileAsync('git', args, commandOptions)
      } catch (error) {
        if (error && error.code === 1) trackedDirty = true
        else throw error
      }
    }
    return Object.freeze({ commit: commitResult.stdout.trim(), trackedDirty })
  } catch {
    return Object.freeze({ commit: null, trackedDirty: null })
  }
}

function selectedFixtureStatus (fixture, counters) {
  const status = fixture.status()
  const accounting = status && status.storage && status.storage.accounting
  return Object.freeze({
    schema: 'PeeritHiveRelayLocalBlindBrowserEvidenceV1',
    localTestOnly: true,
    proxyRequests: counters.proxyRequests,
    proxyDescriptorRequests: counters.proxyDescriptorRequests,
    proxyDescribeRequests: counters.proxyDescribeRequests,
    proxyCellRequests: counters.proxyCellRequests,
    proxyCellPutRequests: counters.proxyCellPutRequests,
    proxyCellGetRequests: counters.proxyCellGetRequests,
    admissionTokensIssued: counters.admissionTokensIssued,
    relayRestarts: counters.relayRestarts,
    droppedCellPutResponses: fixture.droppedCellPutResponses(),
    cellRecords: accounting && accounting.cellRecords,
    storedBytes: accounting && accounting.storedBytes,
    operationalIntegrity: status && status.storage && status.storage.operationalIntegrity,
    relayErrors: fixture.errors()
  })
}

export async function startLocalBlindBrowserStandup (options = {}) {
  const hiveRelayRoot = resolve(options.hiveRelayRoot || options.hiverelayRoot || DEFAULT_HIVERELAY_ROOT)
  const fixtureModuleUrl = pathToFileURL(join(
    hiveRelayRoot,
    'scripts',
    'run-real-blind-relay-lab.mjs'
  )).href
  const protocolModuleUrl = pathToFileURL(join(
    hiveRelayRoot,
    'packages',
    'blind-protocol',
    'index.js'
  )).href
  const [fixtureModule, protocolModule] = await Promise.all([
    import(fixtureModuleUrl),
    import(protocolModuleUrl)
  ])
  if (typeof fixtureModule.createRealBlindRelayTestFixture !== 'function') {
    fail('HiveRelay checkout does not export the real blind relay fixture')
  }
  if (typeof protocolModule.decodeOuterEnvelope !== 'function') {
    fail('HiveRelay checkout does not export the frozen blind envelope decoder')
  }
  const fixture = await fixtureModule.createRealBlindRelayTestFixture({ keep: options.keepFixture === true })
  if (typeof fixture.browserQualificationConfig !== 'function') {
    await fixture.close()
    fail('HiveRelay fixture does not expose browserQualificationConfig()')
  }
  const qualificationConfig = fixture.browserQualificationConfig()
  const target = new URL(qualificationConfig.candidate.canonicalUrl)
  if (target.protocol !== 'https:' || target.hostname !== HOST || target.username || target.password) {
    await fixture.close()
    fail('HiveRelay browser fixture refused a non-loopback HTTPS target')
  }
  const relayOrigin = target.origin
  let vendorArtifactBytes
  let vendorArtifactHash
  try {
    const [artifact, authoritySource] = await Promise.all([
      readFile(join(VENDOR_DIRECTORY, 'blind-client-control-v1.mjs')),
      readFile(join(VENDOR_DIRECTORY, 'authority.json'), 'utf8')
    ])
    const authority = JSON.parse(authoritySource)
    // artifactHash is HiveRelay's domain-separated release hash, not a raw
    // SHA-256 digest. The browser verifier below recomputes that authority from
    // these cached bytes before importing the immutable in-memory route.
    if (!/^[0-9a-f]{64}$/.test(authority.artifactHash || '') ||
        authority.artifactLength !== artifact.byteLength) {
      fail('vendored HiveRelay client does not match its checked-in authority')
    }
    vendorArtifactBytes = artifact
    vendorArtifactHash = authority.artifactHash
  } catch (error) {
    await fixture.close()
    throw error
  }
  const immutableVendorPath = `/__fixture/vendor/${vendorArtifactHash}.mjs`
  const counters = {
    proxyRequests: 0,
    proxyDescriptorRequests: 0,
    proxyDescribeRequests: 0,
    proxyCellRequests: 0,
    proxyCellPutRequests: 0,
    proxyCellGetRequests: 0,
    admissionTokensIssued: 0,
    relayRestarts: 0
  }
  const runId = randomBytes(16).toString('hex')
  const fixtureToken = randomBytes(32).toString('hex')
  const expectedFixtureToken = Buffer.from(fixtureToken, 'utf8')
  const authorizeFixtureRequest = request => {
    const value = request.headers['x-peerit-local-fixture-token']
    const provided = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.alloc(0)
    if (provided.byteLength !== expectedFixtureToken.byteLength ||
        !timingSafeEqual(provided, expectedFixtureToken)) {
      forbidden('local fixture mutation/proxy token is missing or invalid')
    }
  }
  const repositories = await Promise.all([
    repositoryState(ROOT),
    repositoryState(hiveRelayRoot)
  ])
  const metadata = Object.freeze({
    schema: 'PeeritHiveRelayLocalBlindBrowserConfigV1',
    localTestOnly: true,
    transport: Object.freeze({
      browserToHarness: 'same-origin-loopback-http',
      harnessToRelay: 'ephemeral-self-signed-loopback-https',
      exactBlindProtocolBytesForwarded: true
    }),
    peeritCommit: repositories[0].commit,
    peeritTrackedDirty: repositories[0].trackedDirty,
    hiveRelayCommit: repositories[1].commit,
    hiveRelayTrackedDirty: repositories[1].trackedDirty,
    runId,
    fixtureToken,
    vendorArtifact: Object.freeze({
      artifactHash: vendorArtifactHash,
      artifactLength: vendorArtifactBytes.byteLength,
      immutablePath: immutableVendorPath
    }),
    qualification: qualificationConfig
  })
  let transition = Promise.resolve()
  let closed = false

  const server = http.createServer(async (request, response) => {
    try {
      const serverAddress = server.address()
      const expectedHost = serverAddress && typeof serverAddress !== 'string'
        ? `${HOST}:${serverAddress.port}`
        : null
      if (!expectedHost || request.headers.host !== expectedHost) {
        forbidden('local fixture Host header is not the bound loopback authority')
      }
      const url = new URL(request.url || '/', `http://${HOST}`)
      const pathname = normalize(url.pathname)
      if (pathname === '/' || pathname === '/standup') {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          response.writeHead(405, { Allow: 'GET, HEAD' }); response.end(); return
        }
        sendBytes(request, response, 200, MIME['.html'], htmlBytes())
        return
      }
      if (pathname === '/__fixture/config') {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          response.writeHead(405, { Allow: 'GET, HEAD' }); response.end(); return
        }
        sendBytes(request, response, 200, MIME['.json'], jsonBytes(metadata))
        return
      }
      if (pathname === VENDOR_ARTIFACT_PATH || pathname === immutableVendorPath) {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          response.writeHead(405, { Allow: 'GET, HEAD' }); response.end(); return
        }
        sendBytes(request, response, 200, MIME['.mjs'], vendorArtifactBytes)
        return
      }
      if (pathname === '/__fixture/evidence' || pathname === '/healthz') {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          response.writeHead(405, { Allow: 'GET, HEAD' }); response.end(); return
        }
        sendBytes(request, response, 200, MIME['.json'], jsonBytes(selectedFixtureStatus(fixture, counters)))
        return
      }
      if (pathname === '/__fixture/admission') {
        if (request.method !== 'POST') {
          response.writeHead(405, { Allow: 'POST' }); response.end(); return
        }
        authorizeFixtureRequest(request)
        await readRequestBody(request, 64 * 1024)
        const admission = await fixture.admissionProvider()
        counters.admissionTokensIssued++
        sendBytes(request, response, 200, MIME['.json'], jsonBytes(admission))
        return
      }
      if (pathname === '/__fixture/drop-next-cell-put-response') {
        if (request.method !== 'POST') {
          response.writeHead(405, { Allow: 'POST' }); response.end(); return
        }
        authorizeFixtureRequest(request)
        await readRequestBody(request, 0)
        fixture.dropNextCellPutResponse()
        sendBytes(request, response, 200, MIME['.json'], jsonBytes({ armed: true }))
        return
      }
      if (pathname === '/__fixture/restart') {
        if (request.method !== 'POST') {
          response.writeHead(405, { Allow: 'POST' }); response.end(); return
        }
        authorizeFixtureRequest(request)
        await readRequestBody(request, 0)
        transition = transition.then(async () => {
          await fixture.restart()
          counters.relayRestarts++
        })
        await transition
        sendBytes(request, response, 200, MIME['.json'], jsonBytes(selectedFixtureStatus(fixture, counters)))
        return
      }
      if (pathname === '/__fixture/proxy') {
        if (request.method !== 'GET' && request.method !== 'POST') {
          response.writeHead(405, { Allow: 'GET, POST' }); response.end(); return
        }
        authorizeFixtureRequest(request)
        const targetValue = url.searchParams.get('target')
        if (!targetValue || targetValue.length > 4096) fail('local proxy target is missing or oversized')
        const relayUrl = new URL(targetValue)
        if (relayUrl.origin !== relayOrigin || relayUrl.username || relayUrl.password || relayUrl.hash) {
          fail('local proxy target is outside the one fixture relay origin')
        }
        const body = request.method === 'POST' ? await readRequestBody(request) : undefined
        counters.proxyRequests++
        if (request.method === 'GET') counters.proxyDescriptorRequests++
        else if (relayUrl.pathname.endsWith('/describe')) counters.proxyDescribeRequests++
        else if (relayUrl.pathname.endsWith('/cell')) {
          counters.proxyCellRequests++
          const outer = protocolModule.decodeOuterEnvelope(body, {
            copyInner: true,
            copyBody: true
          })
          if (outer.frame.familyId !== protocolModule.FAMILY.CELL) {
            fail('local Cell proxy received a non-Cell blind envelope')
          }
          if (outer.frame.operationId === protocolModule.OPERATION.CELL.PUT) {
            counters.proxyCellPutRequests++
          } else if (outer.frame.operationId === protocolModule.OPERATION.CELL.GET) {
            counters.proxyCellGetRequests++
          } else {
            fail('local Cell proxy received an unexpected Cell operation')
          }
        }
        const forwardedHeaders = []
        const contentType = request.headers['content-type']
        if (contentType) forwardedHeaders.push(['content-type', String(contentType)])
        if (body) forwardedHeaders.push(['content-length', String(body.byteLength)])
        const result = await fixture.fetch(relayUrl.href, {
          method: request.method,
          headers: forwardedHeaders,
          body
        })
        const responseBytes = Buffer.from(await result.arrayBuffer())
        if (responseBytes.byteLength > MAX_PROXY_RESPONSE_BYTES) {
          fail('local proxy response exceeded its fixed bound')
        }
        const responseType = result.headers.get('content-type') || 'application/octet-stream'
        sendBytes(request, response, result.status, responseType, responseBytes)
        return
      }

      if (request.method !== 'GET' && request.method !== 'HEAD') {
        response.writeHead(405, { Allow: 'GET, HEAD' }); response.end(); return
      }
      const file = staticFile(pathname)
      if (!file || !inside(ROOT, file)) {
        response.writeHead(404); response.end('not found'); return
      }
      const exact = normalize(file)
      if (!inside(ROOT, exact) || !(await stat(exact)).isFile()) {
        response.writeHead(404); response.end('not found'); return
      }
      const bytes = await readFile(exact)
      sendBytes(request, response, 200, MIME[extname(exact)] || 'application/octet-stream', bytes)
    } catch (error) {
      if (response.headersSent) {
        response.destroy(error)
        return
      }
      const statusCode = Number.isSafeInteger(error && error.statusCode) ? error.statusCode : 500
      const body = Buffer.from(JSON.stringify({
        error: error && error.code ? String(error.code) : 'LOCAL_FIXTURE_ERROR',
        message: (error && error.message) || 'local fixture request failed'
      }) + '\n')
      sendBytes(request, response, statusCode, MIME['.json'], body)
    }
  })

  try {
    await listen(server, Number.isSafeInteger(options.port) ? options.port : 0)
  } catch (error) {
    await fixture.close()
    throw error
  }
  const address = server.address()
  if (!address || typeof address === 'string') {
    await closeServer(server)
    await fixture.close()
    fail('local Peerit server did not bind a TCP address')
  }
  const url = `http://${HOST}:${address.port}/standup`
  return Object.freeze({
    url,
    hiveRelayRoot,
    fixture,
    metadata,
    evidence: () => selectedFixtureStatus(fixture, counters),
    async close () {
      if (closed) return
      closed = true
      await closeServer(server).catch(() => {})
      await transition.catch(() => {})
      await fixture.close()
    }
  })
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(usage())
    return
  }
  const standup = await startLocalBlindBrowserStandup(options)
  let stopping = null
  const stop = signal => {
    if (stopping) return stopping
    stopping = standup.close().finally(() => {
      process.stdout.write(`[local-blind-browser] stopped after ${signal}\n`)
    })
    return stopping
  }
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => { stop(signal).then(() => process.exit(0), () => process.exit(1)) })
  }
  process.stdout.write(`${JSON.stringify({
    schema: 'PeeritHiveRelayLocalBlindBrowserStandupV1',
    localTestOnly: true,
    url: standup.url,
    peeritCommit: standup.metadata.peeritCommit,
    peeritTrackedDirty: standup.metadata.peeritTrackedDirty,
    hiveRelayCommit: standup.metadata.hiveRelayCommit,
    hiveRelayTrackedDirty: standup.metadata.hiveRelayTrackedDirty,
    hiveRelayRoot: standup.hiveRelayRoot
  })}\n`)
}

const invoked = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (invoked) {
  main().catch(error => {
    process.stderr.write(`[local-blind-browser] ${error.code || 'ERROR'}: ${error.stack || error.message}\n`)
    process.exitCode = 1
  })
}
