import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const app = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8')
const productUi = readFileSync(new URL('../js/substrate/peerit-product-ui.js', import.meta.url), 'utf8')
const css = readFileSync(new URL('../styles.css', import.meta.url), 'utf8')
const publish = readFileSync(new URL('../publish.mjs', import.meta.url), 'utf8')

for (const marker of [
  'Community',
  'Consensus only',
  'Open / unmoderated',
  'data-act="open-report"',
  'data-act="community-keep"',
  'data-act="reveal-moderated"',
  'data-form="report-content"',
  'Algorithm:'
]) assert.ok(app.includes(marker), `app includes moderation UI marker: ${marker}`)

assert.ok(css.includes('.moderation-controls') && css.includes('.moderation-placeholder') && css.includes('.moderation-badge'),
  'moderation controls, explanation placeholder, and badges are styled')
assert.ok(publish.includes("'js/feed-algorithms.js'") && publish.includes("'js/moderation.js'"),
  'the served bundle includes policy and algorithm modules')

for (const marker of [
  'preparePeeritPostsForRenderV1',
  'data.moderationMany',
  'rankFeedWindow',
  'data-preference="moderation-view"',
  'data-preference="feed-algorithm"',
  "action === 'report-content'",
  "action === 'keep-content'",
  "action === 'withdraw-report'",
  "action === 'reveal-content'",
  'Switch to Open'
]) assert.ok(productUi.includes(marker), `blind product UI includes moderation marker: ${marker}`)

const preparation = productUi.slice(productUi.indexOf('export async function preparePeeritPostsForRenderV1'),
  productUi.indexOf('export async function preparePeeritCommentsForRenderV1'))
assert.ok(preparation.indexOf('data.moderationMany') < preparation.indexOf('rankFeedWindow'),
  'the blind product applies selected moderation policy before the interchangeable ranker')

console.log('community-moderation-ui: controls, actions, explanations, and bundle entries present')
