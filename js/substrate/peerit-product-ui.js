// Minimal, replacement-only Peerit browser UI. It renders only admitted local
// application records and calls the local-first product runtime; it owns no
// relay URL, transport fallback, or network permission logic.

import { COMMENT_SORTS, POST_SORTS, sortComments } from '../ranking.js'
import { feedAlgorithm, rankFeedWindow } from '../feed-algorithms.js'
import { MODERATION_VIEW, VISIBILITY, cleanModerationView } from '../moderation.js'
import { REPORT_REASONS, REPORT_VERDICT, TYPE } from '../model.js'
import { publicationNetSegments } from './publication-status.js'

const DEFAULT_COMMUNITY = 'welcome'
const MODERATION_VIEW_STORAGE_KEY = 'peerit.moderation-view.v1'
const FEED_ALGORITHM_STORAGE_KEY = 'peerit.feed-algorithm.v1'

function esc (value) {
  return String(value == null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function shortKey (value) {
  const key = String(value || '')
  return key ? `${key.slice(0, 8)}…${key.slice(-4)}` : 'lurking'
}

function when (value) {
  const millis = Number(value) || 0
  if (!millis) return 'just now'
  const delta = Math.max(0, Date.now() - millis)
  if (delta < 60_000) return 'just now'
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h ago`
  return `${Math.floor(delta / 86_400_000)}d ago`
}

function colorFor (value) {
  let hash = 0
  for (const char of String(value || 'peerit')) hash = ((hash * 31) + char.charCodeAt(0)) >>> 0
  return `hsl(${hash % 360} 72% 62%)`
}

function pathPart (value) { return encodeURIComponent(String(value || '')) }

function communityHref (slug) { return `#/r/${pathPart(slug)}` }

function postHref (post) {
  return `#/r/${pathPart(post.community)}/post/${pathPart(post.cid)}`
}

function parseRoute (location) {
  const raw = String(location.hash || '#/').slice(1) || '/'
  const url = new URL(raw, location.origin || 'https://peerit.invalid')
  const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent)
  if (parts[0] === 'r' && parts[1] && parts[2] === 'post' && parts[3]) {
    return { name: 'post', community: parts[1], cid: parts[3], query: url.searchParams }
  }
  if (parts[0] === 'r' && parts[1]) return { name: 'community', community: parts[1], query: url.searchParams }
  if (parts[0] === 'create') return { name: 'create', query: url.searchParams }
  if (parts[0] === 'submit') return { name: 'submit', community: parts[1] || '', query: url.searchParams }
  if (parts[0] === 'profile') return { name: 'profile', query: url.searchParams }
  if (parts[0] === 'search') return { name: 'search', query: url.searchParams }
  return { name: 'home', query: url.searchParams }
}

function empty (title, copy, action = '') {
  return `<div class="empty"><h3>${esc(title)}</h3><p>${esc(copy)}</p>${action}</div>`
}

function axesHtml (status) {
  const axes = publicationNetSegments(status.sync)
  return `<div class="substrate-status" data-local-ready="${status.publication.authoringReady ? 'true' : 'false'}">
    <div class="substrate-copy">${esc(status.publication.copy)}</div>
    <div class="substrate-axes">${axes.map((axis, index) =>
      `<span class="substrate-axis axis-${index}">${esc(axis)}</span>`).join('')}</div>
  </div>`
}

function selectedFeedAlgorithm (value) {
  return feedAlgorithm(value).key
}

export async function preparePeeritPostsForRenderV1 (data, posts, sort, moderationView, {
  directCid = null
} = {}) {
  const tallies = await data.tallyMany(posts.map(post => post.cid))
  let rows = posts.map(post => ({
    ...post,
    tally: tallies.get(post.cid) || { score: 0, up: 0, down: 0, myVote: 0 }
  }))
  rows = await data.moderationMany(rows, { view: cleanModerationView(moderationView) })
  if (!directCid && moderationView !== MODERATION_VIEW.OPEN) {
    rows = rows.filter(row => row.moderation?.visibility !== VISIBILITY.BURIED)
  }
  return rankFeedWindow(rows, selectedFeedAlgorithm(sort), 'all', 1,
    Math.max(1, rows.length), Date.now()).items
}

export async function preparePeeritCommentsForRenderV1 (data, comments, sort, viewer,
  moderationView = MODERATION_VIEW.COMMUNITY) {
  const rows = comments.map(comment => ({ ...comment }))
  const tallies = await data.tallyMany(rows.map(row => row.cid))
  for (const comment of rows) {
    comment.tally = tallies.get(comment.cid) || { score: 0, up: 0, down: 0, myVote: 0 }
    comment._mine = comment.author === viewer
  }
  const moderated = await data.moderationMany(rows, { view: cleanModerationView(moderationView) })
  return sortComments(moderated.filter(row => moderationView === MODERATION_VIEW.OPEN ||
    row.moderation?.visibility !== VISIBILITY.BURIED), COMMENT_SORTS.includes(sort) ? sort : 'best')
}

function moderationSummary (record) {
  const moderation = record.moderation
  if (!moderation || (moderation.raw === 0 && moderation.visibility === VISIBILITY.VISIBLE)) return ''
  const reasons = (moderation.reasons || []).map(row => `${row.reason} ${row.count}`).join(', ')
  const labelledState = moderation.view === MODERATION_VIEW.OPEN
    ? moderation.consensusState
    : moderation.visibility
  return `<div class="moderation-label" data-visibility="${esc(labelledState)}">community: ${esc(labelledState)} · ${esc(moderation.bury || 0)} bury / ${esc(moderation.keep || 0)} keep${reasons ? ` · ${esc(reasons)}` : ''}</div>`
}

function moderationActions (record, targetType, postCid = '') {
  const mine = record.moderation?.myVerdict
  return `<button class="pa" data-action="report-content" data-community="${esc(record.community)}" data-cid="${esc(record.cid)}" data-target-type="${esc(targetType)}" data-post-cid="${esc(postCid)}">flag</button><button class="pa" data-action="keep-content" data-community="${esc(record.community)}" data-cid="${esc(record.cid)}" data-target-type="${esc(targetType)}" data-post-cid="${esc(postCid)}">vouch</button>${mine ? `<button class="pa" data-action="withdraw-report" data-community="${esc(record.community)}" data-cid="${esc(record.cid)}" data-post-cid="${esc(postCid)}">withdraw vote</button>` : ''}`
}

function isCollapsed (record, revealed) {
  return record.moderation?.visibility === VISIBILITY.COLLAPSED && !revealed.has(record.cid)
}

function voteBox (record, targetType, postCid = '') {
  const tally = record.tally || { score: 0, myVote: 0 }
  return `<div class="votes">
    <button class="arrow up${tally.myVote === 1 ? ' on' : ''}" data-action="vote" data-community="${esc(record.community)}" data-cid="${esc(record.cid)}" data-target-type="${esc(targetType)}" data-post-cid="${esc(postCid)}" data-value="1" aria-label="upvote">▲</button>
    <span class="score${tally.score > 0 ? ' pos' : tally.score < 0 ? ' neg' : ''}">${esc(tally.score)}</span>
    <button class="arrow down${tally.myVote === -1 ? ' on' : ''}" data-action="vote" data-community="${esc(record.community)}" data-cid="${esc(record.cid)}" data-target-type="${esc(targetType)}" data-post-cid="${esc(postCid)}" data-value="-1" aria-label="downvote">▼</button>
  </div>`
}

function postCard (post, { full = false, mine = false, revealed = new Set() } = {}) {
  const body = post.deleted ? '' : String(post.body || '')
  const text = full ? body : body.slice(0, 700)
  const href = postHref(post)
  const link = post.kind !== 'text' && post.url
    ? `<a class="post-link" href="${esc(post.url)}" target="_blank" rel="noopener noreferrer">${esc(post.url)}</a>`
    : text ? `<div class="post-excerpt md">${esc(text)}${!full && body.length > text.length ? `… <a href="${href}">read more →</a>` : ''}</div>` : ''
  const collapsed = isCollapsed(post, revealed)
  const buried = post.moderation?.visibility === VISIBILITY.BURIED
  return `<article class="post ${full ? 'full' : 'card'}" data-post="${esc(post.cid)}">
    ${voteBox(post, TYPE.POST)}
    <div class="post-main">
      <div class="post-meta"><a class="sub-link" href="${communityHref(post.community)}">r/${esc(post.community)}</a><span>·</span><span class="author">u/${esc(shortKey(post.author))}</span><span>·</span><span>${esc(when(post.createdAt))}</span></div>
      ${moderationSummary(post)}
      ${buried ? '<div class="removed-note">Buried by your selected policy. Switch to Open to inspect this otherwise-valid record.</div>' : collapsed ? `<div class="removed-note">Collapsed by your selected community policy. <button class="pa" data-action="reveal-content" data-cid="${esc(post.cid)}">show anyway</button></div>` : `<h2 class="post-title"><a href="${href}">${esc(post.title || '[untitled]')}</a><span class="kind">${esc(post.kind || 'text')}</span></h2>${post.deleted ? '<div class="removed-note">[deleted by author]</div>' : link}`}
      <div class="post-actions"><a class="pa" href="${href}">comments</a>${moderationActions(post, TYPE.POST)}${mine && !post.deleted ? `<button class="pa" data-action="edit-post" data-community="${esc(post.community)}" data-cid="${esc(post.cid)}">edit</button><button class="pa danger" data-action="delete-post" data-community="${esc(post.community)}" data-cid="${esc(post.cid)}">delete</button>` : ''}</div>
    </div>
  </article>`
}

function sortTabs (sort, base, kinds = POST_SORTS) {
  return `<nav class="sorttabs">${kinds.map(kind =>
    `<a class="tab${sort === kind ? ' active' : ''}" href="${base}${base.includes('?') ? '&' : '?'}sort=${pathPart(kind)}">${esc(kind)}</a>`).join('')}</nav>`
}

async function homeView (runtime, route, ui) {
  const data = runtime.data
  const communities = await data.listCommunities()
  const sort = selectedFeedAlgorithm(route.query.get('sort') || ui.feedAlgorithm)
  ui.feedAlgorithm = sort
  const posts = await preparePeeritPostsForRenderV1(data,
    await data.listAllPosts(communities.map(row => row.slug)), sort, ui.moderationView)
  const me = runtime.identity.me().pubkey
  const welcome = '<section class="welcome-panel"><div class="welcome-copy"><span class="tag">blind substrate</span><h2>Local-first communities, without a relay permission gate</h2><p>Browse as a lurker. Your first explicit post creates one durable device identity; every event is signed and visible locally before delivery.</p></div><div class="welcome-actions"><a class="btn btn-primary" href="#/create">Create a community</a><a class="btn btn-ghost" href="how-it-works.html">How it works</a></div></section>'
  const feed = posts.length
    ? `<div class="feed">${posts.map(post => postCard(post, { mine: post.author === me, revealed: ui.revealed })).join('')}</div>`
    : empty('Recovering the verified seed…', 'First visit: the browser verifies two signed relay chains and the 39-record launch seed from scratch — about a minute, no server does it for you. Later visits load instantly. Still empty after two minutes? The relays may be unreachable — refresh to retry.', '<div class="empty-actions"><a class="btn btn-primary" href="#/create">Create community</a></div>')
  return `<div class="feed-head"><h1>Home</h1><a class="btn btn-ghost" href="#/submit/${pathPart(communities[0]?.slug || DEFAULT_COMMUNITY)}">New post</a></div>${welcome}${sortTabs(sort, '#/')}${feed}`
}

async function communityView (runtime, route, ui) {
  const data = runtime.data
  const community = await data.getCommunity(route.community)
  if (!community) return empty('Community not found', `r/${route.community} is not in this verified local view.`, '<a class="btn btn-ghost" href="#/">Back home</a>')
  const sort = selectedFeedAlgorithm(route.query.get('sort') || ui.feedAlgorithm)
  ui.feedAlgorithm = sort
  const posts = await preparePeeritPostsForRenderV1(data,
    await data.listPostsIn(community.slug), sort, ui.moderationView)
  const me = runtime.identity.me().pubkey
  return `<section class="community-banner"><div class="comm-icon lg" style="background:${colorFor(community.slug)}">r/</div><div class="cb-info"><h1>r/${esc(community.slug)}</h1><div class="dim">${esc(community.title || '')}</div><div class="small dim">${esc(community.description || '')}</div></div><a class="btn btn-primary" href="#/submit/${pathPart(community.slug)}">Create post</a></section>${sortTabs(sort, communityHref(community.slug))}${posts.length ? `<div class="feed">${posts.map(post => postCard(post, { mine: post.author === me, revealed: ui.revealed })).join('')}</div>` : empty('No posts in this policy view', 'Create the first signed post, wait for authenticated discovery, or inspect the Open view.', `<a class="btn btn-primary" href="#/submit/${pathPart(community.slug)}">Create post</a>`)}`
}

function commentTree (comments, ui) {
  const byParent = new Map()
  for (const comment of comments) {
    const key = comment.parentCid || ''
    if (!byParent.has(key)) byParent.set(key, [])
    byParent.get(key).push(comment)
  }
  const render = (parent, depth = 0) => (byParent.get(parent) || []).map(comment => {
    const mine = comment._mine === true
    const collapsed = isCollapsed(comment, ui.revealed)
    return `<article class="comment" data-comment="${esc(comment.cid)}"><div class="comment-row">${voteBox(comment, TYPE.COMMENT, comment.postCid)}<div class="comment-body"><div class="comment-head"><span class="author">u/${esc(shortKey(comment.author))}</span><span class="dim">${esc(when(comment.createdAt))}</span></div>${moderationSummary(comment)}<div class="md">${collapsed ? `<span class="dim">Collapsed by your policy. <button class="pa" data-action="reveal-content" data-cid="${esc(comment.cid)}">show anyway</button></span>` : comment.deleted ? '<span class="dim">[deleted]</span>' : esc(comment.body || '')}</div><div class="comment-actions"><button class="pa" data-action="reply" data-cid="${esc(comment.cid)}">reply</button>${moderationActions(comment, TYPE.COMMENT, comment.postCid)}${mine && !comment.deleted ? `<button class="pa" data-action="edit-comment" data-community="${esc(comment.community)}" data-post-cid="${esc(comment.postCid)}" data-cid="${esc(comment.cid)}">edit</button><button class="pa danger" data-action="delete-comment" data-community="${esc(comment.community)}" data-post-cid="${esc(comment.postCid)}" data-cid="${esc(comment.cid)}">delete</button>` : ''}</div></div></div>${depth < 32 ? `<div class="children">${render(comment.cid, depth + 1)}</div>` : ''}</article>`
  }).join('')
  return render('')
}

async function postView (runtime, route, ui) {
  const data = runtime.data
  const post = await data.getPost(route.community, route.cid)
  if (!post) return empty('Post not found', 'This post is not in the verified local view.', `<a class="btn btn-ghost" href="${communityHref(route.community)}">Back to community</a>`)
  const [moderatedPost] = await preparePeeritPostsForRenderV1(data, [post], 'new', ui.moderationView,
    { directCid: post.cid })
  const sort = route.query.get('sort') || 'best'
  const commentRows = await data.listComments(route.community, route.cid)
  const me = runtime.identity.me().pubkey
  const comments = await preparePeeritCommentsForRenderV1(data, commentRows, sort, me, ui.moderationView)
  const buriedAudit = moderatedPost.moderation?.visibility === VISIBILITY.BURIED && ui.moderationView !== MODERATION_VIEW.OPEN
    ? '<div class="notice warn"><b>Buried in this policy view</b><p>This direct link remains available for audit. Switch to Open to inspect the content.</p></div>'
    : ''
  return `<div class="post-detail">${buriedAudit}${postCard(moderatedPost, { full: true, mine: post.author === me, revealed: ui.revealed })}<section class="comment-section"><form class="composer" data-form="comment"><input type="hidden" name="community" value="${esc(route.community)}"><input type="hidden" name="postCid" value="${esc(route.cid)}"><input type="hidden" name="parentCid" value=""><label>Join the discussion<textarea name="body" rows="4" maxlength="10000" required placeholder="Signed and stored on this device — cross-device relay publishing opens in a later milestone…"></textarea></label><div class="composer-actions"><button class="btn btn-primary" type="submit">Comment</button><span class="small dim" data-reply-note></span></div></form><div class="comment-bar"><span>${comments.length} visible comment${comments.length === 1 ? '' : 's'}</span><span class="csort">${COMMENT_SORTS.map(kind => `<a class="${sort === kind ? 'active' : ''}" href="${postHref(post)}?sort=${pathPart(kind)}">${esc(kind)}</a>`).join('')}</span></div>${comments.length ? `<div class="comments">${commentTree(comments, ui)}</div>` : '<div class="no-comments">No comments in this policy view.</div>'}</section></div>`
}

async function createView () {
  return '<section class="panel"><h1>Create a community</h1><form data-form="community"><label>Community name<input name="slug" minlength="2" maxlength="24" pattern="[A-Za-z0-9_]+" required placeholder="builders"></label><label>Title<input name="title" maxlength="100" required placeholder="Builders"></label><label>Description<textarea name="description" maxlength="500" rows="4"></textarea></label><div class="notice"><b>Local-first</b><p>This creates one signed event in your durable local journal first. Relay delivery and discovery can complete later.</p></div><div class="form-actions"><button class="btn btn-primary" type="submit">Create community</button><a class="btn btn-ghost" href="#/">Cancel</a></div></form></section>'
}

async function submitView (runtime, route) {
  const communities = await runtime.data.listCommunities()
  if (!communities.length) return empty('Create a community first', 'A post belongs to a signed community record.', '<a class="btn btn-primary" href="#/create">Create community</a>')
  const selected = communities.some(row => row.slug === route.community) ? route.community : communities[0].slug
  return `<section class="panel"><h1>Create a post</h1><form data-form="post"><label>Community<select name="community">${communities.map(row => `<option value="${esc(row.slug)}"${row.slug === selected ? ' selected' : ''}>r/${esc(row.slug)}</option>`).join('')}</select></label><label>Title<input name="title" maxlength="300" required></label><div class="kind-tabs"><label><input type="radio" name="kind" value="text" checked> Text</label><label><input type="radio" name="kind" value="link"> Link</label></div><label data-body-field>Body<textarea name="body" maxlength="40000" rows="9" placeholder="Signed and stored on this device — cross-device relay publishing opens in a later milestone…"></textarea></label><label data-url-field hidden>URL<input name="url" maxlength="2000" placeholder="https://"></label><div class="form-actions"><button class="btn btn-primary" type="submit">Publish locally</button><a class="btn btn-ghost" href="${communityHref(selected)}">Cancel</a></div></form></section>`
}

async function profileView (runtime) {
  const me = runtime.identity.me()
  const profile = me.pubkey ? await runtime.data.getProfile(me.pubkey) : null
  return `<section class="panel"><h1>Your identity</h1><div class="notice${me.pubkey ? '' : ' warn'}"><b>${me.pubkey ? 'Durable writer active' : 'Lurker mode'}</b><p>${me.pubkey ? `This device will keep using ${shortKey(me.pubkey)}.` : 'No key has been created. Your first explicit mutation will persist one encrypted device identity before signing.'}</p></div><form data-form="profile"><label>Display name<input name="name" maxlength="32" value="${esc(profile?.name || '')}"></label><label>Bio<textarea name="bio" maxlength="500" rows="5">${esc(profile?.bio || '')}</textarea></label><label>Color<input name="color" maxlength="32" value="${esc(profile?.color || '')}" placeholder="#4f8cff"></label><div class="form-actions"><button class="btn btn-primary" type="submit">Save signed profile</button></div></form></section>`
}

async function searchView (runtime, route, ui) {
  const query = route.query.get('q') || ''
  const result = query ? await runtime.data.search(query) : { communities: [], posts: [], comments: [] }
  const me = runtime.identity.me().pubkey
  if (!query) return empty('Search your verified view', 'Enter a query in the search bar. Search runs locally over admitted records.')
  const posts = await preparePeeritPostsForRenderV1(runtime.data, result.posts, 'new', ui.moderationView)
  const comments = await preparePeeritCommentsForRenderV1(runtime.data, result.comments, 'new', me, ui.moderationView)
  return `<div class="feed-head"><h1>Search</h1><span class="dim">${esc(query)}</span></div>${result.communities.map(row => `<div class="comm-row"><div class="comm-icon" style="background:${colorFor(row.slug)}">r/</div><div class="comm-info"><a class="comm-name" href="${communityHref(row.slug)}">r/${esc(row.slug)}</a><div class="dim small">${esc(row.description || '')}</div></div></div>`).join('')}${posts.length ? `<div class="feed">${posts.map(post => postCard(post, { mine: post.author === me, revealed: ui.revealed })).join('')}</div>` : ''}${comments.length ? `<section class="card"><h3>Comments</h3>${comments.map(row => `<div>${moderationSummary(row)}<a href="#/r/${pathPart(row.community)}/post/${pathPart(row.postCid)}">${esc(String(row.body || '').slice(0, 180))}</a></div>`).join('')}</section>` : ''}${!result.communities.length && !posts.length && !comments.length ? empty('No local matches', 'Discovery may add more verified records later.') : ''}`
}

async function sidebarView (runtime, ui) {
  const communities = (await runtime.data.listCommunities()).slice(0, 8)
  return `<section class="card side"><h3>Your feed</h3><label class="small">Moderation<select data-preference="moderation-view">${Object.values(MODERATION_VIEW).map(view => `<option value="${view}"${ui.moderationView === view ? ' selected' : ''}>${view}</option>`).join('')}</select></label><p class="dim small">Community applies moderator actions plus eligible majority votes. Consensus ignores moderator actions. Open shows otherwise-valid content and labels the result.</p><label class="small">Algorithm<select data-preference="feed-algorithm">${POST_SORTS.map(key => `<option value="${key}"${ui.feedAlgorithm === key ? ' selected' : ''}>${feedAlgorithm(key).name}</option>`).join('')}</select></label><p class="dim small">Algorithms are interchangeable MIT-licensed modules. Moderation is applied before ranking.</p></section><section class="card side"><h3>Communities</h3>${communities.length ? communities.map((row, index) => `<a class="side-comm" href="${communityHref(row.slug)}"><span class="rank">${index + 1}</span><span class="comm-icon sm" style="background:${colorFor(row.slug)}">r/</span><span>r/${esc(row.slug)}</span></a>`).join('') : '<p class="dim small">No local communities yet.</p>'}<a class="see-all" href="#/create">Create community</a></section><section class="card side"><h3>What relays can see</h3><p class="dim small">Generic relay operations, opaque cells or frames, timing, size bands, transport metadata, and capabilities presented to that relay—not Peerit post fields or graph semantics.</p></section>`
}

async function routeView (runtime, route, ui) {
  if (route.name === 'community') return communityView(runtime, route, ui)
  if (route.name === 'post') return postView(runtime, route, ui)
  if (route.name === 'create') return createView(runtime, route)
  if (route.name === 'submit') return submitView(runtime, route)
  if (route.name === 'profile') return profileView(runtime, route)
  if (route.name === 'search') return searchView(runtime, route, ui)
  return homeView(runtime, route, ui)
}

export function mountPeeritProductUiV1 (runtime, options = {}) {
  const document = options.document || globalThis.document
  const window = options.window || globalThis.window
  if (!document || !document.body || !window) throw new TypeError('Peerit product UI requires a browser document')
  let renderVersion = 0
  let busy = false
  let destroyed = false
  const storage = options.storage || window.localStorage
  const ui = {
    moderationView: cleanModerationView(storage?.getItem(MODERATION_VIEW_STORAGE_KEY)),
    feedAlgorithm: selectedFeedAlgorithm(storage?.getItem(FEED_ALGORITHM_STORAGE_KEY)),
    // Deliberately session-only: a new browser session respects the selected
    // policy again instead of silently remembering every reveal forever.
    revealed: new Set()
  }

  document.body.innerHTML = '<header class="topbar"><a class="brand" href="#/"><span class="brand-mark">P</span><span class="brand-name">peerit</span></a><form class="search" data-form="search"><input name="q" type="search" maxlength="200" placeholder="Search your verified local view" aria-label="Search"><button class="search-submit" type="submit" aria-label="Run search">⌕</button></form><div class="topbar-right"><span class="mode-badge live">blind</span><a class="user-pill" href="#/profile" aria-label="Your identity"><span class="avatar" style="background:linear-gradient(135deg,var(--accent),var(--accent-2))"></span><span class="uname" data-user-label>lurking</span></a></div></header><div data-status></div><main class="layout"><section class="content" id="app"><div class="panel skel"><div class="sk-line w40"></div><div class="sk-line w80"></div></div></section><aside class="sidebar" id="sidebar"></aside></main><div class="toast" data-toast hidden></div>'

  const showError = error => {
    const node = document.querySelector('[data-toast]')
    if (!node) return
    node.textContent = (error && error.message) || 'The action could not be completed.'
    node.hidden = false
    clearTimeout(showError.timer)
    showError.timer = setTimeout(() => { node.hidden = true }, 6000)
  }

  const render = async () => {
    const version = ++renderVersion
    try {
      const status = await runtime.status()
      const route = parseRoute(window.location)
      const routeFeed = route.query.get('sort')
      if (routeFeed && POST_SORTS.includes(routeFeed)) {
        ui.feedAlgorithm = selectedFeedAlgorithm(routeFeed)
        storage?.setItem(FEED_ALGORITHM_STORAGE_KEY, ui.feedAlgorithm)
      }
      const [main, sidebar] = await Promise.all([routeView(runtime, route, ui), sidebarView(runtime, ui)])
      if (destroyed || version !== renderVersion) return
      document.querySelector('[data-status]').innerHTML = axesHtml(status)
      document.querySelector('[data-user-label]').textContent = status.lurker ? 'lurking' : shortKey(status.identity.pubkey)
      document.querySelector('#app').innerHTML = main
      document.querySelector('#sidebar').innerHTML = sidebar
      for (const control of document.querySelectorAll('form button[type="submit"]')) {
        control.disabled = busy || !status.publication.authoringReady
      }
    } catch (error) {
      if (destroyed || version !== renderVersion) return
      document.querySelector('#app').innerHTML = empty('Local view unavailable', error.message || 'Peerit could not render the verified local view.')
      showError(error)
    }
  }

  const mutate = async operation => {
    if (busy) return
    busy = true
    await render()
    try { await operation() } catch (error) { showError(error) } finally {
      busy = false
      await render()
    }
  }

  const navigateSearch = value => {
    const query = String(value || '').trim()
    window.location.hash = query ? `#/search?q=${encodeURIComponent(query)}` : '#/'
  }

  const onSubmit = event => {
    const form = event.target.closest('form[data-form]')
    if (!form) return
    event.preventDefault()
    const values = new FormData(form)
    const kind = form.dataset.form
    if (kind === 'search') {
      navigateSearch(values.get('q'))
      return
    }
    mutate(async () => {
      if (kind === 'community') {
        const community = await runtime.data.createCommunity({
          slug: values.get('slug'), title: values.get('title'), description: values.get('description')
        })
        window.location.hash = communityHref(community.slug)
      } else if (kind === 'post') {
        const post = await runtime.data.submitPost({
          community: values.get('community'),
          kind: values.get('kind'),
          title: values.get('title'),
          body: values.get('body'),
          url: values.get('url')
        })
        window.location.hash = postHref(post)
      } else if (kind === 'comment') {
        await runtime.data.addComment({
          community: values.get('community'),
          postCid: values.get('postCid'),
          parentCid: values.get('parentCid') || null,
          body: values.get('body')
        })
        form.reset()
      } else if (kind === 'profile') {
        await runtime.data.setProfile({ name: values.get('name'), bio: values.get('bio'), color: values.get('color') })
      }
    })
  }

  const onKeydown = event => {
    if (event.key !== 'Enter' || !event.target.matches('form[data-form="search"] input[name="q"]')) return
    event.preventDefault()
    navigateSearch(event.target.value)
  }

  const onClick = event => {
    const control = event.target.closest('[data-action]')
    if (!control) return
    const action = control.dataset.action
    event.preventDefault()
    mutate(async () => {
      if (action === 'vote') {
        const current = control.classList.contains('on') ? 0 : Number(control.dataset.value)
        await runtime.data.vote(control.dataset.cid, control.dataset.community, control.dataset.targetType, current,
          { postCid: control.dataset.postCid || undefined })
      } else if (action === 'report-content' || action === 'keep-content') {
        const verdict = action === 'keep-content' ? REPORT_VERDICT.KEEP : REPORT_VERDICT.BURY
        let reason = 'other'
        let note = ''
        if (verdict === REPORT_VERDICT.BURY) {
          const answer = window.prompt(`Reason (${REPORT_REASONS.join(', ')})`, 'spam')
          if (answer == null) return
          reason = REPORT_REASONS.includes(answer) ? answer : 'other'
          note = window.prompt('Optional note (never shown to the relay)', '') || ''
        }
        await runtime.data.reportContent(control.dataset.community, {
          targetCid: control.dataset.cid,
          targetType: control.dataset.targetType,
          postCid: control.dataset.postCid || undefined,
          verdict,
          reason,
          note
        })
      } else if (action === 'withdraw-report') {
        await runtime.data.withdrawReport(control.dataset.community, control.dataset.cid,
          { postCid: control.dataset.postCid || undefined })
      } else if (action === 'reveal-content') {
        ui.revealed.add(control.dataset.cid)
      } else if (action === 'reply') {
        const form = document.querySelector('form[data-form="comment"]')
        if (!form) return
        form.elements.parentCid.value = control.dataset.cid
        form.querySelector('[data-reply-note]').textContent = `replying to ${shortKey(control.dataset.cid)}`
        form.elements.body.focus()
      } else if (action === 'edit-post') {
        const post = await runtime.data.getPost(control.dataset.community, control.dataset.cid)
        const body = window.prompt('Edit post body', post?.body || '')
        if (body != null) await runtime.data.editPost(control.dataset.community, control.dataset.cid, body)
      } else if (action === 'delete-post') {
        if (window.confirm('Delete this post?')) await runtime.data.deletePost(control.dataset.community, control.dataset.cid)
      } else if (action === 'edit-comment') {
        const comment = await runtime.data.getComment(control.dataset.community, control.dataset.postCid, control.dataset.cid)
        const body = window.prompt('Edit comment', comment?.body || '')
        if (body != null) await runtime.data.editComment(control.dataset.community, control.dataset.postCid, control.dataset.cid, body)
      } else if (action === 'delete-comment') {
        if (window.confirm('Delete this comment?')) await runtime.data.deleteComment(control.dataset.community, control.dataset.postCid, control.dataset.cid)
      }
    })
  }

  const onChange = event => {
    if (event.target.matches('[data-preference="moderation-view"]')) {
      ui.moderationView = cleanModerationView(event.target.value)
      storage?.setItem(MODERATION_VIEW_STORAGE_KEY, ui.moderationView)
      render()
      return
    }
    if (event.target.matches('[data-preference="feed-algorithm"]')) {
      ui.feedAlgorithm = selectedFeedAlgorithm(event.target.value)
      storage?.setItem(FEED_ALGORITHM_STORAGE_KEY, ui.feedAlgorithm)
      render()
      return
    }
    if (!event.target.matches('input[name="kind"]')) return
    const form = event.target.closest('form[data-form="post"]')
    if (!form) return
    const link = event.target.value === 'link'
    form.querySelector('[data-body-field]').hidden = link
    form.querySelector('[data-url-field]').hidden = !link
  }

  document.addEventListener('submit', onSubmit)
  document.addEventListener('keydown', onKeydown)
  document.addEventListener('click', onClick)
  document.addEventListener('change', onChange)
  window.addEventListener('hashchange', render)
  const unsubscribe = runtime.onChange(render)
  render()

  return Object.freeze({
    render,
    destroy () {
      if (destroyed) return
      destroyed = true
      unsubscribe()
      document.removeEventListener('submit', onSubmit)
      document.removeEventListener('keydown', onKeydown)
      document.removeEventListener('click', onClick)
      document.removeEventListener('change', onChange)
      window.removeEventListener('hashchange', render)
      clearTimeout(showError.timer)
    }
  })
}
