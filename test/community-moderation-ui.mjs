import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const app = readFileSync(new URL('../js/app.js', import.meta.url), 'utf8')
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

console.log('community-moderation-ui: controls, actions, explanations, and bundle entries present')
