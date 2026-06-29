// ranking.js — Reddit-style ranking algorithms. Pure functions over
// { score, up, down, createdAt } shapes so they're unit-testable.

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

// Tally votes for a target. `votes` = array of { value, author }.
// Last value per author wins (the materialized view already dedups by key,
// but tallying here is defensive).
export function tally (votes, me) {
  const byAuthor = new Map()
  for (const v of votes || []) byAuthor.set(v.author, v.value)
  let up = 0, down = 0, myVote = 0
  for (const [author, value] of byAuthor) {
    if (value === 1) up++
    else if (value === -1) down++
    if (me && author === me) myVote = value
  }
  return { up, down, score: up - down, myVote, total: up + down }
}

const TIME_WINDOWS = {
  hour: 3600000, day: 86400000, week: 604800000,
  month: 2592000000, year: 31536000000, all: Infinity
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
    const sa = a.stickied ? 1 : 0, sb = b.stickied ? 1 : 0
    if (sa !== sb) return sb - sa
    return cmp(a, b)
  })
  return list
}

export function sortComments (comments, sort = 'best', now = Date.now()) {
  const cmp = comparator(sort, now, true)
  return comments.slice().sort(cmp)
}

function comparator (sort, now, isComment) {
  switch (sort) {
    case 'new': return (a, b) => b.createdAt - a.createdAt
    case 'old': return (a, b) => a.createdAt - b.createdAt
    case 'top': return (a, b) => (b.tally.score - a.tally.score) || (b.createdAt - a.createdAt)
    case 'controversial':
      return (a, b) => (controversyScore(b.tally.up, b.tally.down) - controversyScore(a.tally.up, a.tally.down)) || (b.createdAt - a.createdAt)
    case 'rising':
      return (a, b) => (risingScore(b.tally.score, b.createdAt, now) - risingScore(a.tally.score, a.createdAt, now)) || (b.createdAt - a.createdAt)
    case 'best':
      return (a, b) => (wilsonScore(b.tally.up, b.tally.down) - wilsonScore(a.tally.up, a.tally.down)) || (b.createdAt - a.createdAt)
    case 'hot':
    default:
      return (a, b) => (hotScore(b.tally.score, b.createdAt) - hotScore(a.tally.score, a.createdAt)) || (b.createdAt - a.createdAt)
  }
}

export const POST_SORTS = ['hot', 'new', 'top', 'rising', 'controversial']
export const COMMENT_SORTS = ['best', 'top', 'new', 'controversial', 'old']
export const TIME_WINDOW_KEYS = ['hour', 'day', 'week', 'month', 'year', 'all']
