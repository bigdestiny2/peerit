// web-serve.mjs — dev-only static server for the generated web/ bundle (the
// peerit.com static export from build-web.mjs). Lets the browser preview load
// the web build the way a normal browser would. NOT part of the published site.
import http from 'node:http'
import https from 'node:https'
import { readFile } from 'node:fs/promises'
import { extname, join, normalize, relative, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, ''), 'web')
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json' }
const PORT = Number(process.env.PORT) || 8780
const HOST = process.env.HOST || '127.0.0.1'
// Same-origin relay proxy: /api/* → the relay. This mirrors a real deploy where
// the relay lives behind the same domain (no CORS) and lets the preview reach it.
const RELAY = process.env.PEERIT_RELAY_PROXY || 'http://127.0.0.1:8787'

function proxyToRelay (req, res) {
  const u = new URL(RELAY)
  const secure = u.protocol === 'https:'
  const mod = secure ? https : http
  const port = u.port || (secure ? 443 : 80)
  const headers = { ...req.headers, host: u.host } // SNI/host must match the upstream cert
  const up = mod.request({ hostname: u.hostname, port, path: req.url, method: req.method, headers, servername: u.hostname }, (ur) => {
    res.writeHead(ur.statusCode || 502, ur.headers) // pipes JSON and text/event-stream (SSE) alike
    ur.pipe(res)
  })
  up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end('relay unreachable') })
  req.pipe(up)
}

http.createServer(async (req, res) => {
  let p
  try { p = decodeURIComponent((req.url || '/').split('?')[0]) } catch { res.writeHead(400); return res.end('bad request') }
  if (p.startsWith('/api/')) return proxyToRelay(req, res)
  if (p === '/' || p === '') p = '/index.html'
  const file = normalize(join(ROOT, p.replace(/^\/+/, '')))
  const rel = relative(ROOT, file)
  if (rel.startsWith('..') || isAbsolute(rel) || p.includes('\0')) { res.writeHead(403); return res.end('forbidden') }
  try {
    const data = await readFile(file)
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store, max-age=0', 'X-Content-Type-Options': 'nosniff' })
    res.end(data)
  } catch { res.writeHead(404); res.end('not found') }
}).listen(PORT, HOST, () => console.log(`peerit web bundle on http://${HOST}:${PORT}`))
