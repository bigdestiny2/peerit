// ranking.js — Reddit-style ranking algorithms. Pure functions over
// { score, up, down, createdAt } shapes so they're unit-testable.

import { FEED_PAGE_SIZE, parseFeedPage } from './feed-window.js'
import { moderationTier } from './moderation.js'

const EPOCH = 1134028003000 // Reddit's epoch (2005-12-08) in ms

function sign (n) { return n > 0 ? 1 : n < 0 ? -1 : 0 }

// Hot ranking: log of score + age term. Newer + higher-scored ranks higher.
export function hotScore (score, createdAt) {
  const s = score || 0
  const order = Math.log10(Math.max(Math.abs(s), 1))
  const seconds = (createdAt - EPOCH) / 1000
  return order * sign(s) + seconds / 45000
}

// Controversial: high when up and down are large AND balanced.
export function controversyScore (up, down) {
  up = up || 0; down = down || 0
  if (up <= 0 || down <= 0) return 0
  const magnitude = up + down
  const balance = up > down ? down / up : up / down
  return Math.pow(magnitude, balance)
}

// Wilson lower bound — "best" comment sort. Rewards high ratio with confidence.
export function wilsonScore (up, down) {
  up = up || 0; down = down || 0
  const n = up + down
  if (n === 0) return 0
  const z = 1.281551565545 // 80% confidence
  const p = up / n
  const left = p + (z * z) / (2 * n)
  const right = z * Math.sqrt((p * (1 - p) + (z * z) / (4 * n)) / n)
  const under = 1 + (z * z) / n
  return (left - right) / under
}

// "Rising": velocity for fresh posts (score per hour, ages out after a day).
export function risingScore (score, createdAt, now = Date.now()) {
  const ageHours = Math.max((now - createdAt) / 3600000, 0.0167)
  if (ageHours > 24) return -Infinity
  return (score || 0) / ageHours
}

// Reputation weight of a VOTER (Slice 3, ported from p2pbuilders/js/reputation.js):
// a vote's influence scales with the voter's age + upvotes received, so a brand-new
// key can vote but barely moves the needle. Blunts (does not eliminate) Sybil
// ballot-stuffing — the honest ceiling: a fresh key still counts, just ~0.02.
//   weight = clamp( log2(1 + ageDays) * sqrt(1 + receivedUpvotes) / 50, 0.02, 1 )
export function weight (ageDays, receivedUpvotes) {
  const a = Math.max(0, ageDays || 0)
  const r = Math.max(0, receivedUpvotes || 0)
  const w = Math.log2(1 + a) * Math.sqrt(1 + r) / 50
  return Math.max(0.02, Math.min(1, w))
}

// Tally votes for a target. `votes` = array of { value, author }. Last value per
// author wins (the materialized view already dedups by key, but tallying here is
// defensive). `weightOf(pub) -> [ageDays, receivedUpvotes]` (optional): when
// supplied, `weighted` is the reputation-weighted score used for RANKING, while
// `score` stays raw (up-down) for DISPLAY. Unweighted callers get weighted==score.
export function tally (votes, me, weightOf) {
  const byAuthor = new Map()
  for (const v of votes || []) byAuthor.set(v.author, v.value)
  let up = 0
  let down = 0
  let myVote = 0
  let weighted = 0
  for (const [author, value] of byAuthor) {
    if (value === 1) up++
    else if (value === -1) down++
    if (me && author === me) myVote = value
    if (weightOf) weighted += (value || 0) * weight(...(weightOf(author) || [0, 0]))
  }
  if (!weightOf) weighted = up - down
  return { up, down, score: up - down, weighted, myVote, total: up + down }
}

// Ranking uses the reputation-weighted score when present, else raw score.
function rankScore (t) { return t ? (t.weighted != null ? t.weighted : t.score) : 0 }

const TIME_WINDOWS = {
  hour: 3600000,
  day: 86400000,
  week: 604800000,
  month: 2592000000,
  year: 31536000000,
  all: Infinity
}

// Sort an array of posts (each carrying .createdAt and a tally {score,up,down}).
export function sortPosts (posts, sort = 'hot', timeWindow = 'all', now = Date.now()) {
  let list = posts.slice()
  if ((sort === 'top' || sort === 'controversial') && timeWindow !== 'all') {
    const cutoff = now - (TIME_WINDOWS[timeWindow] || Infinity)
    list = list.filter(p => p.createdAt >= cutoff)
  }
  // Stickied posts always float to the top (community sticky), preserving sort within.
  const cmp = comparator(sort, now)
  list.sort((a, b) => {
    const sa = a.stickied ? 1 : 0
    const sb = b.stickied ? 1 : 0
    if (sa !== sb) return sb - sa
    const ma = moderationTier(a)
    const mb = moderationTier(b)
    if (ma !== mb) return ma - mb
    return cmp(a, b)
  })
  return list
}

// Return only one globally-ranked feed window without first allocating and
// sorting a second full-size array. The input remains the complete verified
// record set, so score-based sorts retain their global ordering semantics; the
// bounded heap merely avoids sorting records that cannot appear on this page.
// This intentionally does not hydrate bodies or calculate tallies: callers can
// skip both for chronological feeds and do them only for the visible window.
export function rankPostsWindow (posts, sort = 'hot', timeWindow = 'all', requestedPage = 1, pageSize = FEED_PAGE_SIZE, now = Date.now()) {
  const list = Array.isArray(posts) ? posts : []
  const size = Number.isSafeInteger(pageSize) && pageSize > 0 ? pageSize : FEED_PAGE_SIZE
  const eligible = post => {
    if (!post || typeof post !== 'object') return false
    if ((sort === 'top' || sort === 'controversial') && timeWindow !== 'all') {
      const cutoff = now - (TIME_WINDOWS[timeWindow] || Infinity)
      return Number(post.createdAt) >= cutoff
    }
    return true
  }
  let totalItems = 0
  for (const post of list) if (eligible(post)) totalItems++

  const totalPages = Math.max(1, Math.ceil(totalItems / size))
  const page = Math.min(parseFeedPage(requestedPage), totalPages)
  const wanted = Math.min(totalItems, page * size)
  if (!wanted) {
    return { items: [], page, pageSize: size, totalItems, totalPages, hasPrevious: false, hasNext: false }
  }

  const postComparator = comparator(sort, now)
  const compare = (a, b) => {
    const aSticky = a.post.stickied ? 1 : 0
    const bSticky = b.post.stickied ? 1 : 0
    if (aSticky !== bSticky) return bSticky - aSticky
    const aModeration = moderationTier(a.post)
    const bModeration = moderationTier(b.post)
    if (aModeration !== bModeration) return aModeration - bModeration
    const ranked = postComparator(a.post, b.post)
    // Array#sort is stable, so preserve that existing tie behaviour even when
    // the requested page is selected via a heap instead of a full sort.
    return ranked || (a.index - b.index)
  }
  const heap = [] // root is the least desirable selected row
  for (let index = 0; index < list.length; index++) {
    const post = list[index]
    if (!eligible(post)) continue
    const row = { post, index }
    if (heap.length < wanted) heapPushWorst(heap, row, compare)
    else if (compare(row, heap[0]) < 0) {
      heap[0] = row
      heapSinkWorst(heap, 0, compare)
    }
  }
  heap.sort(compare)
  const start = (page - 1) * size
  return {
    items: heap.slice(start, start + size).map(row => row.post),
    page,
    pageSize: size,
    totalItems,
    totalPages,
    hasPrevious: page > 1,
    hasNext: page < totalPages
  }
}

function heapPushWorst (heap, row, compare) {
  heap.push(row)
  let child = heap.length - 1
  while (child > 0) {
    const parent = Math.floor((child - 1) / 2)
    // The less desirable row belongs closer to the root.
    if (compare(heap[parent], heap[child]) > 0) break
    ;[heap[parent], heap[child]] = [heap[child], heap[parent]]
    child = parent
  }
}

function heapSinkWorst (heap, parent, compare) {
  for (;;) {
    const left = parent * 2 + 1
    const right = left + 1
    let worst = parent
    if (left < heap.length && compare(heap[left], heap[worst]) > 0) worst = left
    if (right < heap.length && compare(heap[right], heap[worst]) > 0) worst = right
    if (worst === parent) return
    ;[heap[parent], heap[worst]] = [heap[worst], heap[parent]]
    parent = worst
  }
}

export function sortComments (comments, sort = 'best', now = Date.now()) {
  const cmp = comparator(sort, now, true)
  return comments.slice().sort((a, b) => {
    const moderation = moderationTier(a) - moderationTier(b)
    return moderation || cmp(a, b)
  })
}

function comparator (sort, now, isComment) {
  switch (sort) {
    case 'new': return (a, b) => b.createdAt - a.createdAt
    case 'old': return (a, b) => a.createdAt - b.createdAt
    case 'top': return (a, b) => (rankScore(b.tally) - rankScore(a.tally)) || (b.createdAt - a.createdAt)
    case 'controversial':
      return (a, b) => (controversyScore(b.tally.up, b.tally.down) - controversyScore(a.tally.up, a.tally.down)) || (b.createdAt - a.createdAt)
    case 'rising':
      return (a, b) => (risingScore(rankScore(b.tally), b.createdAt, now) - risingScore(rankScore(a.tally), a.createdAt, now)) || (b.createdAt - a.createdAt)
    case 'best':
      return (a, b) => (wilsonScore(b.tally.up, b.tally.down) - wilsonScore(a.tally.up, a.tally.down)) || (b.createdAt - a.createdAt)
    case 'hot':
    default:
      return (a, b) => (hotScore(rankScore(b.tally), b.createdAt) - hotScore(rankScore(a.tally), a.createdAt)) || (b.createdAt - a.createdAt)
  }
}

export const POST_SORTS = ['hot', 'new', 'top', 'rising', 'controversial']
export const COMMENT_SORTS = ['best', 'top', 'new', 'controversial', 'old']
export const TIME_WINDOW_KEYS = ['hour', 'day', 'week', 'month', 'year', 'all']
