export const PEERIT_RELEASE_RELAY_HINT_LIMITS = Object.freeze({
  maximumHints: 128,
  maximumHintBytes: 2048
})

export function normalizePeeritReleaseRelayHintsV1 (value, label = 'release') {
  if (!Array.isArray(value) || value.length > PEERIT_RELEASE_RELAY_HINT_LIMITS.maximumHints) {
    throw new Error(`${label} relay hints exceed the fixed count bound`)
  }
  const output = []
  const seen = new Set()
  for (const entry of value) {
    if (typeof entry !== 'string') throw new Error(`${label} relay hint must be a string`)
    const hint = entry.trim()
    if (!hint || hint.includes(',') || new TextEncoder().encode(hint).byteLength >
        PEERIT_RELEASE_RELAY_HINT_LIMITS.maximumHintBytes) {
      throw new Error(`${label} relay hint exceeds the fixed byte bound`)
    }
    let url
    try { url = new URL(hint) } catch { throw new Error(`${label} relay hint is not a URL`) }
    const loopback = url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    if ((url.protocol !== 'https:' && !loopback) || url.username || url.password ||
        url.search || url.hash || url.hostname === 'outbox.peerit.site') {
      throw new Error(`${label} relay hint violates the replacement transport policy`)
    }
    if (seen.has(hint)) throw new Error(`${label} relay hints must be unique`)
    seen.add(hint)
    output.push(hint)
  }
  return Object.freeze(output)
}
