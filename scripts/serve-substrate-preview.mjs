#!/usr/bin/env node
// Loopback-only static server for exercising an already built replacement
// artifact. It serves exact byte lengths and MIME types required by the
// authenticated browser loader and never exposes repository files.

import { createServer } from 'node:http'
import { readFile, stat } from 'node:fs/promises'
import { extname, isAbsolute, join, normalize, relative, resolve } from 'node:path'

const rootArgument = process.argv[2]
if (!rootArgument) throw new Error('usage: node scripts/serve-substrate-preview.mjs <built-directory> [port]')
const root = resolve(rootArgument)
const port = Number(process.argv[3] || process.env.PORT || 8791)
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('preview port is invalid')

const MIME = Object.freeze({
  '.cenc': 'application/octet-stream',
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/plain; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml'
})

function insideRoot (file) {
  const path = relative(root, file)
  return path === '' || (!path.startsWith('..') && !isAbsolute(path))
}

function requestPath (request) {
  let path
  try { path = decodeURIComponent(new URL(request.url || '/', 'http://preview.invalid').pathname) } catch {
    return null
  }
  if (path.includes('\0')) return null
  if (path.endsWith('/')) path += 'index.html'
  const file = normalize(join(root, path.replace(/^\/+/, '')))
  return insideRoot(file) ? file : null
}

const server = createServer(async (request, response) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { Allow: 'GET, HEAD' })
    response.end()
    return
  }
  const file = requestPath(request)
  if (!file) {
    response.writeHead(400)
    response.end('bad request')
    return
  }
  try {
    const [info, bytes] = await Promise.all([stat(file), readFile(file)])
    if (!info.isFile()) throw new Error('not a file')
    response.writeHead(200, {
      'Cache-Control': 'no-store, max-age=0',
      'Content-Length': String(bytes.byteLength),
      'Content-Type': MIME[extname(file).toLowerCase()] || 'application/octet-stream',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'X-Content-Type-Options': 'nosniff'
    })
    response.end(request.method === 'HEAD' ? undefined : bytes)
  } catch {
    response.writeHead(404, {
      'Cache-Control': 'no-store, max-age=0',
      'Content-Type': 'text/plain; charset=utf-8'
    })
    response.end('not found')
  }
})

server.listen(port, '127.0.0.1', () => {
  console.log(`Peerit substrate preview: http://127.0.0.1:${port}/`)
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => server.close(() => process.exit(0)))
}
