import assert from 'node:assert/strict'
import { rankPostsWindow, sortPosts } from '../js/ranking.js'
import { windowFeed } from '../js/feed-window.js'

const base = 1_700_000_000_000
const post = (cid, createdAt, score = 0, extra = {}) => ({
  cid,
  createdAt,
  tally: { up: Math.max(score, 0), down: Math.max(-score, 0), score, weighted: score },
  ...extra
})

const chronological = Array.from({ length: 10_000 }, (_, index) => post(String(index), base + index))
const newest = rankPostsWindow(chronological, 'new', 'all', 1, 25, base + 20_000)
assert.equal(newest.totalItems, 10_000)
assert.equal(newest.totalPages, 400)
assert.equal(newest.items.length, 25)
assert.equal(newest.items[0].cid, '9999')
assert.equal(newest.items.at(-1).cid, '9975')

const topInput = [
  post('one', base + 1, 1),
  post('two', base + 2, 5),
  post('three', base + 3, 3),
  post('four', base + 4, 4),
  post('sticky', base, -10, { stickied: true })
]
const topPage = rankPostsWindow(topInput, 'top', 'all', 2, 2, base + 20_000)
assert.equal(topPage.totalItems, 5)
assert.equal(topPage.items.length, 2)
assert.deepEqual(topPage.items.map(row => row.cid), ['four', 'three'])

const windowed = rankPostsWindow([
  post('old', base - 2 * 86400000, 100),
  post('recent', base - 1000, 1)
], 'top', 'day', 1, 25, base)
assert.equal(windowed.totalItems, 1, 'time filters are counted before pagination')
assert.equal(windowed.items[0].cid, 'recent')

const equal = [post('first', base, 1), post('second', base, 1), post('third', base, 1)]
assert.deepEqual(
  rankPostsWindow(equal, 'top', 'all', 1, 25, base).items.map(row => row.cid),
  sortPosts(equal, 'top', 'all', base).map(row => row.cid),
  'heap selection preserves stable tie ordering'
)

// The bounded selector is an optimization, not a second ranking definition.
// Compare it with the established full-sort path across all feed modes and
// time filters before accepting the 20k-record smoke below.
let state = 0xdecafbad
const random = () => {
  state = (state * 1664525 + 1013904223) >>> 0
  return state / 0x100000000
}
const mixed = Array.from({ length: 257 }, (_, index) => post(
  `mixed-${index}`,
  base - Math.floor(random() * 400 * 86400000),
  Math.floor(random() * 21) - 10,
  { stickied: index % 79 === 0 }
))
for (const sort of ['hot', 'new', 'top', 'rising', 'controversial']) {
  for (const timeWindow of ['hour', 'day', 'week', 'month', 'year', 'all']) {
    const expected = windowFeed(sortPosts(mixed, sort, timeWindow, base), 4, 17)
    const actual = rankPostsWindow(mixed, sort, timeWindow, 4, 17, base)
    assert.equal(actual.totalItems, expected.totalItems, `${sort}/${timeWindow}: total count`)
    assert.equal(actual.page, expected.page, `${sort}/${timeWindow}: clamped page`)
    assert.deepEqual(actual.items.map(row => row.cid), expected.items.map(row => row.cid), `${sort}/${timeWindow}: page contents`)
  }
}

const large = Array.from({ length: 20_000 }, (_, index) => post(
  `large-${index}`,
  base + index,
  (index % 19) - 9,
  { stickied: index === 101 }
))
const largePage = rankPostsWindow(large, 'hot', 'all', 1, 25, base + 25_000)
assert.equal(largePage.totalItems, 20_000)
assert.equal(largePage.items.length, 25, 'large feed selection keeps only the visible page')
assert.equal(largePage.items[0].cid, 'large-101', 'a global sticky still wins the bounded selection')

console.log('ranking-window: deterministic + 20k feed-window checks passed')
