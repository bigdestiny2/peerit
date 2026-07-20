// feed-algorithms.js — open, interchangeable built-in feed algorithm registry.
//
// Candidate selection and moderation are host responsibilities. Algorithms see
// only the already-admitted, policy-annotated candidates and return an ordered
// window. Each implementation ships in this MIT-licensed source tree and is
// addressed by a stable id/version rather than a hidden server-side setting.

import { rankPostsWindow } from './ranking.js'

const LICENSE = 'MIT'
const MODULE = './ranking.js'

export const FEED_ALGORITHMS = Object.freeze([
  ['hot', 'Hot', 'hotScore'],
  ['new', 'New', 'createdAt-desc'],
  ['top', 'Top', 'weighted-score'],
  ['rising', 'Rising', 'risingScore'],
  ['controversial', 'Controversial', 'controversyScore']
].map(([id, name, implementation]) => Object.freeze({
  id: `peerit.${id}.v1`,
  key: id,
  name,
  version: 1,
  license: LICENSE,
  source: MODULE,
  implementation,
  input: 'peerit.feed-candidates.v1',
  output: 'peerit.feed-window.v1'
})))

const BY_KEY = new Map(FEED_ALGORITHMS.map(manifest => [manifest.key, manifest]))

export function feedAlgorithm (key) {
  return BY_KEY.get(String(key || '').toLowerCase()) || BY_KEY.get('hot')
}

export function rankFeedWindow (posts, key, timeWindow, requestedPage, pageSize, now) {
  const manifest = feedAlgorithm(key)
  return {
    ...rankPostsWindow(posts, manifest.key, timeWindow, requestedPage, pageSize, now),
    algorithm: manifest
  }
}
