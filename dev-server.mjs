// dev-server.mjs — tiny static server for local preview ONLY. Sends correct JS
// MIME for ES modules and `Cache-Control: no-store` so edits always reload.
// Not part of the published P2P site (see publish.mjs SITE_FILES).
import http from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, join, normalize, relative, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '')
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json' }
const PORT = Number(process.env.PORT) || 8777
const HOST = process.env.HOST || '127.0.0.1'
const PUBLIC_FILES = new Set(['/index.html', '/styles.css', '/icon.svg', '/manifest.json', '/config/shard-roster.json'])

function isPublicPath (p) {
  return PUBLIC_FILES.has(p) || /^\/js\/[a-z0-9-]+\.js$/i.test(p) || /^\/config\/shard-roster\.json$/i.test(p)
}

function isInsideRoot (file) {
  const rel = relative(ROOT, file)
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))
}

http.createServer(async (req, res) => {
  let p
  try {
    p = decodeURIComponent((req.url || '/').split('?')[0])
  } catch {
    res.writeHead(400); return res.end('bad request')
  }
  if (p === '/' || p === '') p = '/index.html'
  if (!isPublicPath(p) || p.includes('\0')) { res.writeHead(404); return res.end('not found') }
  const file = normalize(join(ROOT, p.replace(/^\/+/, '')))
  if (!isInsideRoot(file)) { res.writeHead(403); return res.end('forbidden') }
  try {
    const data = await readFile(file)
    res.writeHead(200, {
      'Content-Type': MIME[extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-store, max-age=0',
      'X-Content-Type-Options': 'nosniff',
      'Cross-Origin-Resource-Policy': 'same-origin'
    })
    res.end(data)
  } catch { res.writeHead(404); res.end('not found') }
}).listen(PORT, HOST, () => console.log(`peerit dev server on http://${HOST}:${PORT} (public files only, no-store)`))
