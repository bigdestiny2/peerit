import assert from 'node:assert/strict'
import { FEED_PAGE_SIZE, parseFeedPage, windowFeed } from '../js/feed-window.js'

const posts = Array.from({ length: 61 }, (_, i) => ({ cid: String(i + 1) }))

assert.equal(FEED_PAGE_SIZE, 25, 'the public feed has a conservative bounded default')
assert.equal(parseFeedPage(), 1, 'missing query starts at page one')
assert.equal(parseFeedPage('0'), 1, 'zero is not a valid page')
assert.equal(parseFeedPage('-2'), 1, 'negative page is not valid')
assert.equal(parseFeedPage('2.5'), 1, 'fractional page is not valid')
assert.equal(parseFeedPage('9007199254740992'), 1, 'unsafe page values fail closed to page one')

const first = windowFeed(posts)
assert.equal(first.page, 1)
assert.equal(first.totalPages, 3)
assert.equal(first.totalItems, 61)
assert.equal(first.items.length, 25)
assert.equal(first.items[0].cid, '1')
assert.equal(first.hasPrevious, false)
assert.equal(first.hasNext, true)

const middle = windowFeed(posts, '2')
assert.equal(middle.page, 2)
assert.equal(middle.items.length, 25)
assert.equal(middle.items[0].cid, '26')
assert.equal(middle.hasPrevious, true)
assert.equal(middle.hasNext, true)

const last = windowFeed(posts, '999')
assert.equal(last.page, 3, 'out-of-range links resolve to the final available page')
assert.equal(last.items.length, 11)
assert.equal(last.items[0].cid, '51')
assert.equal(last.hasNext, false)

const empty = windowFeed([], '4')
assert.equal(empty.page, 1)
assert.equal(empty.totalPages, 1)
assert.deepEqual(empty.items, [])

console.log('feed-windowing: 22 checks passed')
