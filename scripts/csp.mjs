// csp.mjs — pure Content-Security-Policy transforms for the web build.
//
// The shipped index.html deliberately carries NO http:/https: wildcard in
// connect-src (a wildcard turns a same-origin read/XSS into remote exfiltration —
// audit PT-BRW-002). build-web.mjs pins connect-src to EXACTLY the origins a given
// deployment talks to (relays, roster mirrors, shard cohort, DHT relay). These
// helpers are factored out here so they are unit-testable without importing
// build-web.mjs, which builds on import.

// Rewrite the CSP <meta> in an HTML string for a web deployment.
export function patchCspForWeb (html, { dhtRelay = '', connectOrigins = [] } = {}) {
  return html.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]*)(")/, (m, before, policy, after) => {
    return before + patchCsp(policy, { dhtRelay, connectOrigins }) + after
  })
}

// Transform a raw CSP policy string:
//   - script-src: add 'wasm-unsafe-eval' ONLY when a DHT-relay WASM transport is bundled.
//   - connect-src: add the specific relay/DHT/mirror origins (never a wildcard).
export function patchCsp (policy, { dhtRelay = '', connectOrigins = [] } = {}) {
  const wsOrigin = dhtRelay ? cspSourceForWebSocket(dhtRelay) : null
  const connectSources = [...connectOrigins]
  if (wsOrigin) addSource(connectSources, wsOrigin)
  const out = []
  let sawScript = false
  let sawConnect = false
  for (const raw of policy.split(';')) {
    const part = raw.trim()
    if (!part) continue
    const [name, ...sources] = part.split(/\s+/)
    if (name === 'script-src') {
      sawScript = true
      if (dhtRelay) addSource(sources, "'wasm-unsafe-eval'")
    } else if (name === 'connect-src') {
      sawConnect = true
      for (const s of connectSources) addSource(sources, s)
    }
    out.push([name, ...sources].join(' '))
  }
  if (!sawScript && dhtRelay) out.push("script-src 'self' 'wasm-unsafe-eval'")
  if (!sawConnect) out.push(['connect-src', "'self'", ...connectSources].join(' '))
  return out.join('; ')
}

export function addSource (sources, source) {
  if (source && !sources.includes(source)) sources.push(source)
}

// A connect-src origin (scheme://host[:port]) for an https/http relay base URL.
// "same-origin"/"/" needs no source ('self' covers it); invalid entries are dropped.
export function cspConnectOrigin (base) {
  const raw = String(base || '').trim()
  if (!raw || raw === 'same-origin' || raw === '/') return null
  try {
    const url = new URL(raw)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    return url.origin
  } catch { return null }
}

export function cspSourceForWebSocket (relay) {
  const url = new URL(relay)
  return `${url.protocol}//${url.host}`
}
