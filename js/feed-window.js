// Feed pagination is deliberately a pure, UI-level window. Ranking still happens
// over the complete verified set so "hot", "top", and sticky ordering stay
// globally correct; callers hydrate and render only `items`.

export const FEED_PAGE_SIZE = 25

export function parseFeedPage (value) {
  const raw = String(value == null ? '' : value).trim()
  if (!/^[1-9][0-9]*$/.test(raw)) return 1
  const page = Number(raw)
  return Number.isSafeInteger(page) ? page : 1
}

export function windowFeed (ranked, requestedPage, pageSize = FEED_PAGE_SIZE) {
  const list = Array.isArray(ranked) ? ranked : []
  const size = Number.isSafeInteger(pageSize) && pageSize > 0 ? pageSize : FEED_PAGE_SIZE
  const totalItems = list.length
  const totalPages = Math.max(1, Math.ceil(totalItems / size))
  const page = Math.min(parseFeedPage(requestedPage), totalPages)
  const start = (page - 1) * size
  return {
    items: list.slice(start, start + size),
    page,
    pageSize: size,
    totalItems,
    totalPages,
    hasPrevious: page > 1,
    hasNext: page < totalPages
  }
}
