// app.js — peerit UI. Hash router + async views rendered into #app, with all
// interaction handled by event delegation. Reads/writes go through Data; ranking
// and threading come from ranking.js / model.js. Works identically on the real
// PearBrowser bridge and the localStorage dev-fallback.

import { createSync } from './sync.js'
import { createIdentity } from './identity.js'
import { createData } from './data.js'
import { Prefs } from './prefs.js'
import { renderMarkdown, excerpt } from './markdown.js'
import { sortPosts, sortComments, POST_SORTS, COMMENT_SORTS, TIME_WINDOW_KEYS } from './ranking.js'
import { buildCommentTree, sortCommentTree, countDescendants, MOD } from './model.js'
import {
  escapeHtml as esc, timeAgo, fmtCount, parseRoute, buildRoute,
  colorFor, shortKey, debounce, normalizeSlug, safeUserUrl
} from './util.js'

// ---- app singletons ---------------------------------------------------------
let sync, identity, data, prefs
let renderToken = 0
let _lastHash = ''
const openReplies = new Set()      // comment cids with an open reply box
let editing = null                 // { kind:'post'|'comment', ... } inline editor
const nameCache = new Map()        // pub -> display name (sync-ish for render)

const $ = (sel, root = document) => root.querySelector(sel)
const app = () => $('#app')

// Resolve + cache display names so synchronous render can use them.
async function primeNames (pubs) {
  await Promise.all([...new Set(pubs)].filter(p => p && !nameCache.has(p)).map(async p => {
    nameCache.set(p, await data.displayName(p))
  }))
}
const nameOf = (pub) => nameCache.get(pub) || ('u/' + String(pub || '?').slice(0, 8))

// ---- boot -------------------------------------------------------------------
async function boot () {
  // Identity first — the gossip layer needs to know who "me" is to pick which
  // outbox to write to (getMe is read dynamically so user-switching just works).
  identity = createIdentity()
  await identity.ready()
  sync = createSync({ getMe: () => identity.me().pubkey, identity })
  await sync.ready()
  data = createData(sync, identity)
  refreshPrefs()

  // Live updates: re-render the current view when the shared view changes,
  // unless the user is mid-typing in a composer.
  const soft = debounce(() => {
    const a = document.activeElement
    // Don't rip focus from anything the user is interacting with: a form field,
    // a select, or any focused control inside the content area. The live update
    // lands as soon as focus moves on. (Local actions re-render explicitly.)
    if (a && (/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) || a.isContentEditable)) return
    if (a && a !== document.body && app() && app().contains(a)) return
    route()
  }, 350)
  sync.onChange(soft)
  sync.onChange(() => updateNetStatus())
  setInterval(updateNetStatus, 3000) // reflects bridge poll / background peer arrivals

  window.addEventListener('hashchange', route)
  document.addEventListener('click', onClick)
  document.addEventListener('submit', onSubmit)
  document.addEventListener('input', onInput)
  document.addEventListener('error', onResourceError, true)
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return
    const d = $('#userdrop')
    if (d && !d.hidden) { d.hidden = true; const b = $('[data-act="toggle-usermenu"]'); if (b) { b.setAttribute('aria-expanded', 'false'); b.focus() } }
  })

  renderChrome()
  if (!location.hash) location.hash = '#/'
  route()
}

function refreshPrefs () {
  prefs = new Prefs(typeof localStorage !== 'undefined' ? localStorage : null, identity.me().pubkey)
}

// ---- chrome (header + sidebar shell) ----------------------------------------
function renderChrome () {
  document.body.innerHTML = `
    <header class="topbar">
      <a class="brand" href="#/">
        <span class="brand-mark">P</span><span class="brand-name">peerit</span>
      </a>
      <form class="search" data-form="search">
        <input name="q" placeholder="Search posts, comments, communities" autocomplete="off">
      </form>
      <div class="topbar-right">
        <a class="btn btn-ghost" href="#/submit" title="Create a post">＋ Post</a>
        <div class="usermenu" id="usermenu"></div>
      </div>
    </header>
    <main class="layout">
      <section id="app" class="content"></section>
      <aside id="sidebar" class="sidebar"></aside>
    </main>
    <div id="toasts" class="toasts"></div>
    <div id="modal-root"></div>
    <button id="netstatus" class="netstatus" data-act="netstatus" title="P2P sync status — click to refresh">…</button>`
  renderUserMenu()
  updateNetStatus()
}

// Live P2P status chip: backend mode, peer count, record count, your writer key.
async function updateNetStatus () {
  const el = $('#netstatus'); if (!el || !sync) return
  try {
    const s = await sync.status()
    const me = identity.me()
    const secure = s.secure !== false
    el.className = 'netstatus ' + (s.mode && s.mode.includes('bridge') ? 'bridge' : (secure ? 'ok' : 'warn'))
    el.innerHTML = `<b>${esc(s.mode || 'sync')}</b> · ${s.peers != null ? s.peers : 1}p · ${s.viewLength || 0} recs · <span class="mono">${esc((me.pubkey || '').slice(0, 6))}…</span>${secure ? '' : ' · ⚠ insecure'}`
  } catch (e) { el.textContent = 'sync: ' + (e.message || 'error') }
}

async function renderUserMenu () {
  const me = identity.me()
  await primeNames([me.pubkey])
  const el = $('#usermenu')
  if (!el) return
  const badge = sync.mode === 'dev'
    ? '<span class="mode-badge dev" title="Running on local dev fallback (no PearBrowser bridge detected)">dev</span>'
    : '<span class="mode-badge live" title="Connected to PearBrowser P2P bridge">p2p</span>'
  el.innerHTML = `
    ${badge}
    <button class="user-pill" data-act="toggle-usermenu" aria-haspopup="menu" aria-label="Account menu">
      <span class="avatar" style="background:${colorFor(me.pubkey)}"></span>
      <span class="uname">${esc(nameOf(me.pubkey))}</span>
    </button>
    <div class="dropdown" id="userdrop" role="menu" hidden>
      <a role="menuitem" href="#/submit">＋ Create post</a>
      <a role="menuitem" href="#/create">＋ Create community</a>
      <a role="menuitem" href="#/communities">Communities</a>
      <div class="dd-sep"></div>
      <a role="menuitem" href="#/u/${esc(me.pubkey)}">My profile</a>
      <a role="menuitem" href="#/saved">Saved</a>
      <a role="menuitem" href="#/settings">Settings</a>
      ${identity.isDev ? '<div class="dd-sep"></div>' + devUserSwitcher() : ''}
    </div>`
}

function devUserSwitcher () {
  const users = identity.listUsers()
  const me = identity.me().pubkey
  return `<div class="dd-label">Dev: switch user</div>` +
    users.map(u => `<button class="dd-user ${u.pubkey === me ? 'active' : ''}" data-act="switch-user" data-pub="${esc(u.pubkey)}">
        <span class="avatar sm" style="background:${colorFor(u.pubkey)}"></span>${esc(u.label || ('u/' + u.pubkey.slice(0, 8)))}
      </button>`).join('') +
    `<button class="dd-user new" data-act="new-user">＋ New dev user</button>`
}

// ---- router -----------------------------------------------------------------
function route () {
  const { path, query } = parseRoute(location.hash)
  const token = ++renderToken
  const guard = (html) => { if (token === renderToken) { app().innerHTML = html } }
  // Reset scroll on genuine navigation (not on same-route soft refreshes).
  if (location.hash !== _lastHash) { _lastHash = location.hash; try { window.scrollTo(0, 0) } catch {} }

  if (path.length === 0) return viewFeed({ scope: 'home', query, guard, token })
  switch (path[0]) {
    case 'all': return viewFeed({ scope: 'all', query, guard, token })
    case 'popular': return viewFeed({ scope: 'all', query, guard, token })
    case 'communities': return viewCommunities({ guard, token })
    case 'submit': return viewSubmit({ query, guard, token })
    case 'create': return viewCreateCommunity({ guard, token })
    case 'search': return viewSearch({ query, guard, token })
    case 'settings': return viewSettings({ guard, token })
    case 'saved': return viewSaved({ guard, token })
    case 'u': return viewProfile({ pub: path[1], guard, token })
    case 'r':
      if (path[2] === 'comments' && path[3]) return viewPost({ community: path[1], cid: path[3], query, guard, token })
      if (path[2] === 'about') return viewCommunityAbout({ community: path[1], guard, token })
      return viewFeed({ scope: 'community', community: path[1], query, guard, token })
    default: return guard(notFound())
  }
}

// ---- shared building blocks -------------------------------------------------
function sortTabs (active, base, query) {
  return `<div class="sorttabs">` + POST_SORTS.map(s =>
    `<a class="tab ${s === active ? 'active' : ''}" href="${buildRoute(base, { ...query, sort: s, t: undefined })}">${s}</a>`
  ).join('') +
  ((active === 'top' || active === 'controversial')
    ? `<select class="timewin" data-act="timewindow" aria-label="Top time window">` + TIME_WINDOW_KEYS.map(t =>
        `<option value="${t}" ${query.t === t ? 'selected' : ''}>${t}</option>`).join('') + `</select>`
    : '') +
  `</div>`
}

function voteWidget (rec, type) {
  const t = rec.tally || { score: 0, myVote: 0 }
  const up = t.myVote === 1 ? 'on' : ''
  const down = t.myVote === -1 ? 'on' : ''
  const cls = t.myVote === 1 ? 'pos' : t.myVote === -1 ? 'neg' : ''
  return `<div class="votes" data-cid="${esc(rec.cid)}" data-community="${esc(rec.community)}" data-type="${type}">
    <button class="arrow up ${up}" data-act="vote" data-dir="1" aria-label="upvote">▲</button>
    <span class="score ${cls}">${fmtCount(t.score)}</span>
    <button class="arrow down ${down}" data-act="vote" data-dir="-1" aria-label="downvote">▼</button>
  </div>`
}

function authorLine (rec, extra = '') {
  const edited = rec.editedAt ? ` · edited ${timeAgo(rec.editedAt)}` : ''
  return `<a class="author" href="#/u/${esc(rec.author)}">${esc(nameOf(rec.author))}</a>
    <span class="dim">· ${timeAgo(rec.createdAt)}${edited}${extra}</span>`
}

function postCard (post, ov, opts = {}) {
  const ref = post.community + '/' + post.cid
  const removed = ov && ov.removed.has(post.cid)
  const locked = ov && ov.locked.has(post.cid)
  const stickied = ov && ov.stickied.has(post.cid)
  const isMod = opts.mods && opts.mods.has(identity.me().pubkey)
  const mine = post.author === identity.me().pubkey
  const permalink = buildRoute(['r', post.community, 'comments', post.cid])
  const commentCount = opts.commentCounts ? (opts.commentCounts.get(post.cid) || 0) : null

  let bodyHtml = ''
  if (post.deleted) bodyHtml = `<div class="removed-note">[deleted by author]</div>`
  else if (removed) bodyHtml = `<div class="removed-note">[removed by moderators]</div>`
  else if (post.kind === 'link') bodyHtml = `<a class="post-link" href="${esc(safeUrl(post.url))}" target="_blank" rel="noopener noreferrer nofollow">${esc(post.url)} ↗</a>`
  else if (post.kind === 'image') bodyHtml = `<a href="${esc(safeUrl(post.url))}" target="_blank" rel="noopener noreferrer nofollow"><img class="post-img" src="${esc(safeUrl(post.url))}" alt="${esc(post.title || 'image post')}" loading="lazy" data-fallback-url="${esc(safeUrl(post.url))}"></a>`
  else if (!opts.full) bodyHtml = post.body ? `<div class="post-excerpt">${esc(excerpt(post.body, 280))}</div>` : ''
  else bodyHtml = post.body ? `<div class="md">${renderMarkdown(post.body)}</div>` : ''

  return `<article class="post ${opts.full ? 'full' : 'card'}" data-cid="${esc(post.cid)}" data-community="${esc(post.community)}">
    ${voteWidget(post, 'post')}
    <div class="post-main">
      <div class="post-meta">
        ${stickied ? '<span class="pin">📌 pinned</span>' : ''}
        <a class="sub-link" href="#/r/${esc(post.community)}">r/${esc(post.community)}</a>
        <span class="dim">· posted by</span> ${authorLine(post)}
        ${locked ? '<span class="lock" title="Locked">🔒</span>' : ''}
      </div>
      <h2 class="post-title">${opts.full ? esc(post.title) : `<a href="${permalink}">${esc(post.title)}</a>`}
        ${post.kind === 'link' && !opts.full ? '<span class="kind">link</span>' : ''}
      </h2>
      ${bodyHtml}
      <div class="post-actions">
        <a class="pa" href="${permalink}">💬 ${commentCount == null ? '' : fmtCount(commentCount) + ' '}comments</a>
        <button class="pa" data-act="save" data-ref="${esc(ref)}">${prefs.isSaved(ref) ? '★ saved' : '☆ save'}</button>
        <button class="pa" data-act="copylink" data-ref="${esc(ref)}">🔗 share</button>
        ${mine && !post.deleted ? `<button class="pa" data-act="edit-post">✎ edit</button><button class="pa danger" data-act="delete-post">🗑 delete</button>` : ''}
        ${!opts.full ? `<button class="pa" data-act="hide" data-ref="${esc(ref)}">${prefs.isHidden(ref) ? 'unhide' : 'hide'}</button>` : ''}
        ${isMod ? modMenu(post, ov) : ''}
      </div>
    </div>
  </article>`
}

function modMenu (post, ov) {
  const removed = ov.removed.has(post.cid)
  const locked = ov.locked.has(post.cid)
  const stuck = ov.stickied.has(post.cid)
  return `<span class="modtools">
    <button class="pa mod" data-act="mod" data-mod="${removed ? MOD.APPROVE : MOD.REMOVE}">${removed ? '✓ approve' : '⊘ remove'}</button>
    <button class="pa mod" data-act="mod" data-mod="${locked ? MOD.UNLOCK : MOD.LOCK}">${locked ? '🔓 unlock' : '🔒 lock'}</button>
    <button class="pa mod" data-act="mod" data-mod="${stuck ? MOD.UNSTICKY : MOD.STICKY}">${stuck ? 'unpin' : '📌 pin'}</button>
    <button class="pa mod danger" data-act="mod" data-mod="${MOD.BAN}" data-user="${esc(post.author)}">ban author</button>
  </span>`
}

function safeUrl (u) {
  return safeUserUrl(u) || '#'
}

function onResourceError (e) {
  const img = e.target
  if (!img || img.tagName !== 'IMG' || !img.classList.contains('post-img')) return
  const url = img.dataset.fallbackUrl || img.currentSrc || img.src || '#'
  const a = document.createElement('a')
  a.href = safeUrl(url)
  a.target = '_blank'
  a.rel = 'noopener noreferrer nofollow'
  a.className = 'post-link'
  a.textContent = a.href + ' ↗'
  const wrapper = img.closest('a')
  if (wrapper && wrapper.parentNode) wrapper.replaceWith(a)
  else img.replaceWith(a)
}

// ---- FEED views (home / all / community) ------------------------------------
async function viewFeed ({ scope, community, query, guard, token }) {
  const sort = query.sort || prefs.sort || 'hot'
  const tw = query.t || 'all'
  guard(skeleton(scope === 'community' ? 'r/' + esc(community) : (scope === 'home' ? 'Home' : 'Popular')))

  let communityMeta = null, ov = null, mods = null
  let posts = []
  if (scope === 'community') {
    communityMeta = await data.getCommunity(community)
    if (!communityMeta) return done(guard, token, notFound('r/' + esc(community) + " doesn't exist yet"), renderSidebarHome)
    ov = await data.overlay(community)
    mods = ov.mods
    posts = await data.listPostsIn(community)
  } else if (scope === 'home') {
    const subs = prefs.subs()
    if (!subs.length) {
      // No subscriptions yet -> behave like "all" but nudge onboarding.
      posts = await data.listAllPosts()
    } else {
      posts = await data.listAllPosts(subs)
    }
  } else {
    posts = await data.listAllPosts()
  }

  // hide locally-hidden, enrich with tallies, compute overlays per community.
  posts = posts.filter(p => !prefs.isHidden(p.community + '/' + p.cid))
  posts = await data.withTallies(posts)

  // mark stickied (community feed only) + overlay removal
  if (scope === 'community' && ov) {
    posts.forEach(p => { p.stickied = ov.stickied.has(p.cid) })
  }
  const ranked = sortPosts(posts, sort, tw)

  // comment counts + author names
  await primeNames(ranked.map(p => p.author))
  const commentCounts = await countCommentsFor(ranked)

  if (token !== renderToken) return
  prefs.setSort(sort)

  const title = scope === 'community'
    ? communityCard(communityMeta, mods)
    : (scope === 'home' ? `<div class="feed-head"><h1>Home</h1><span class="dim">posts from communities you follow</span></div>`
                        : `<div class="feed-head"><h1>Popular</h1><span class="dim">across all of peerit</span></div>`)

  const base = scope === 'community' ? ['r', community] : (scope === 'home' ? [] : ['all'])
  let body
  if (!ranked.length) {
    body = emptyFeed(scope, community)
  } else {
    body = ranked.map(p => postCard(p, scope === 'community' ? ov : null, {
      mods: scope === 'community' ? mods : null, commentCounts
    })).join('')
  }

  guard(`${title}${sortTabs(sort, base, query)}<div class="feed">${body}</div>`)
  if (scope === 'community') renderSidebar(communitySidebar(communityMeta, mods), token)
  else renderSidebar(await sidebarHome(), token)
}

async function countCommentsFor (posts) {
  const map = new Map()
  await Promise.all(posts.map(async p => {
    map.set(p.cid, await sync.count(`comment!${p.community}!${p.cid}!`))
  }))
  return map
}

function emptyFeed (scope, community) {
  if (scope === 'community') {
    return `<div class="empty"><h3>No posts in r/${esc(community)} yet</h3>
      <p>Be the first to post.</p><a class="btn btn-primary" href="#/submit?to=${esc(community)}">Create a post</a></div>`
  }
  return `<div class="empty"><h3>It's quiet here</h3>
    <p>No posts yet. Start a community and make the first post.</p>
    <div class="empty-actions">
      <a class="btn btn-primary" href="#/create">Create a community</a>
      <button class="btn btn-ghost" data-act="seed-demo">Load demo content</button>
    </div></div>`
}

// ---- POST + COMMENTS view ---------------------------------------------------
async function viewPost ({ community, cid, query, guard, token }) {
  guard(skeleton('Loading post…'))
  const post = await data.getPost(community, cid)
  if (!post) return done(guard, token, notFound('That post no longer exists'), renderSidebarHome)
  const communityMeta = await data.getCommunity(community)
  const ov = await data.overlay(community)
  const csort = query.csort || 'best'

  const [pWith] = await data.withTallies([post])
  pWith.stickied = ov.stickied.has(cid)

  let comments = await data.listComments(community, cid)
  comments = await data.withTallies(comments)
  // apply removal overlay to comment bodies
  comments.forEach(c => { c._removed = ov.removed.has(c.cid) })
  await primeNames([post.author, ...comments.map(c => c.author)])

  const { roots } = buildCommentTree(comments)
  const sorter = (nodes) => sortComments(nodes, csort)
  const sorted = sortCommentTree(roots, sorter)

  if (token !== renderToken) return
  const locked = ov.locked.has(cid)
  const isMod = ov.mods.has(identity.me().pubkey)

  const banned = ov.banned.has(identity.me().pubkey)
  const composer = (pWith.deleted || ov.removed.has(cid))
    ? `<div class="locked-note">This post is no longer available.</div>`
    : locked
      ? `<div class="locked-note">🔒 This thread is locked. New comments are disabled.</div>`
      : banned
        ? `<div class="locked-note">🚫 You are banned from r/${esc(community)} and can't comment here.</div>`
        : `<form class="composer" data-form="comment" data-community="${esc(community)}" data-post="${esc(cid)}" data-parent="">
         <textarea name="body" placeholder="What are your thoughts? (markdown supported)" rows="4"></textarea>
         <div class="composer-actions"><button class="btn btn-primary" type="submit">Comment</button></div>
       </form>`

  const csortTabs = `<div class="csort">sort: ` + COMMENT_SORTS.map(s =>
    `<a class="${s === csort ? 'active' : ''}" href="${buildRoute(['r', community, 'comments', cid], { csort: s })}">${s}</a>`).join(' ') + `</div>`

  const commentsHtml = sorted.length
    ? sorted.map(n => commentNode(n, pWith, ov, isMod, 0)).join('')
    : `<div class="no-comments">No comments yet. Be the first.</div>`

  guard(`<div class="post-detail">
      ${postCard(pWith, ov, { full: true, mods: ov.mods })}
    </div>
    <div class="comment-section">
      ${composer}
      <div class="comment-bar">${countDescendantsTotal(sorted)} comments ${csortTabs}</div>
      <div class="comments">${commentsHtml}</div>
    </div>`)
  renderSidebar(communitySidebar(communityMeta, ov.mods), token)
}

function countDescendantsTotal (roots) {
  let n = roots.length
  for (const r of roots) n += countDescendants(r)
  return fmtCount(n)
}

function commentNode (node, post, ov, isMod, depth) {
  const mine = node.author === identity.me().pubkey
  const collapsedId = 'c_' + node.cid
  const removed = node._removed
  const deleted = node.deleted
  const locked = !!(ov.locked && ov.locked.has(post.cid))
  const childCount = countDescendants(node)
  let bodyHtml
  if (deleted) bodyHtml = `<div class="removed-note">[deleted]</div>`
  else if (removed) bodyHtml = `<div class="removed-note">[removed by moderators]</div>`
  else bodyHtml = `<div class="md">${renderMarkdown(node.body)}</div>`

  const replyOpen = openReplies.has(node.cid) && !locked
  const replyForm = replyOpen ? `
    <form class="composer reply" data-form="comment" data-community="${esc(node.community)}" data-post="${esc(post.cid)}" data-parent="${esc(node.cid)}">
      <textarea name="body" placeholder="Reply…" rows="3"></textarea>
      <div class="composer-actions">
        <button class="btn btn-primary" type="submit">Reply</button>
        <button class="btn btn-ghost" type="button" data-act="cancel-reply" data-cid="${esc(node.cid)}">Cancel</button>
      </div>
    </form>` : ''

  const children = node.children.length
    ? `<div class="children">${node.children.map(c => commentNode(c, post, ov, isMod, depth + 1)).join('')}</div>` : ''

  return `<div class="comment" data-cid="${esc(node.cid)}" data-community="${esc(node.community)}" id="${collapsedId}">
    <div class="comment-row">
      <button class="collapse" data-act="collapse" data-target="${collapsedId}" title="collapse" aria-label="Collapse or expand comment thread">[–]</button>
      <div class="comment-body">
        <div class="comment-head">
          ${voteWidgetInline(node)}
          ${authorLine(node)} ${childCount ? `<span class="dim">· ${childCount} ${childCount === 1 ? 'reply' : 'replies'}</span>` : ''}
        </div>
        ${bodyHtml}
        <div class="comment-actions">
          ${!deleted && !removed && !locked ? `<button class="pa" data-act="reply" data-cid="${esc(node.cid)}">↳ reply</button>` : ''}
          ${mine && !deleted ? `<button class="pa" data-act="edit-comment" data-cid="${esc(node.cid)}">✎ edit</button>
            <button class="pa danger" data-act="delete-comment" data-cid="${esc(node.cid)}">🗑 delete</button>` : ''}
          ${isMod ? `<button class="pa mod" data-act="mod" data-mod="${removed ? MOD.APPROVE : MOD.REMOVE}" data-cid="${esc(node.cid)}">${removed ? '✓ approve' : '⊘ remove'}</button>` : ''}
        </div>
        ${replyForm}
      </div>
    </div>
    ${children}
  </div>`
}

function voteWidgetInline (rec) {
  const t = rec.tally || { score: 0, myVote: 0 }
  const cls = t.myVote === 1 ? 'pos' : t.myVote === -1 ? 'neg' : ''
  return `<span class="votes inline" data-cid="${esc(rec.cid)}" data-community="${esc(rec.community)}" data-type="comment">
    <button class="arrow up ${t.myVote === 1 ? 'on' : ''}" data-act="vote" data-dir="1" aria-label="upvote">▲</button>
    <span class="score ${cls}">${fmtCount(t.score)}</span>
    <button class="arrow down ${t.myVote === -1 ? 'on' : ''}" data-act="vote" data-dir="-1" aria-label="downvote">▼</button>
  </span>`
}

// ---- SUBMIT view ------------------------------------------------------------
async function viewSubmit ({ query, guard, token }) {
  const communities = await data.listCommunities()
  if (token !== renderToken) return
  const to = query.to || (communities[0] && communities[0].slug) || ''
  if (!communities.length) {
    return done(guard, token, `<div class="empty"><h3>No communities yet</h3>
      <p>You need a community before you can post.</p>
      <a class="btn btn-primary" href="#/create">Create a community</a></div>`, renderSidebarHome)
  }
  const bannedHere = (await data.overlay(to)).banned.has(identity.me().pubkey)
  if (token !== renderToken) return
  guard(`<div class="panel">
    <h1>Create a post</h1>
    ${bannedHere ? `<div class="locked-note">🚫 You are banned from r/${esc(to)} — pick another community.</div>` : ''}
    <form data-form="submit-post">
      <label>Community
        <select name="community">${communities.map(c => `<option value="${esc(c.slug)}" ${c.slug === to ? 'selected' : ''}>r/${esc(c.slug)}</option>`).join('')}</select>
      </label>
      <div class="kind-tabs">
        <label><input type="radio" name="kind" value="text" checked> Text</label>
        <label><input type="radio" name="kind" value="link"> Link</label>
        <label><input type="radio" name="kind" value="image"> Image</label>
      </div>
      <label>Title <input name="title" maxlength="300" placeholder="An interesting title" required></label>
      <label class="field-body">Body (markdown) <textarea name="body" rows="10" placeholder="Text (optional)"></textarea></label>
      <label class="field-url" hidden>URL <input name="url" placeholder="https:// or hyper:// or pear://"></label>
      <div class="form-actions"><button class="btn btn-primary" type="submit">Post</button>
        <a class="btn btn-ghost" href="#/r/${esc(to)}">Cancel</a></div>
    </form>
  </div>`)
  renderSidebar(await sidebarHome(), token)
}

// ---- CREATE COMMUNITY view --------------------------------------------------
async function viewCreateCommunity ({ guard, token }) {
  guard(`<div class="panel">
    <h1>Create a community</h1>
    <form data-form="create-community">
      <label>Name <span class="dim">r/</span>
        <input name="slug" maxlength="24" placeholder="programming" required>
        <small class="hint">2–24 chars: lowercase letters, numbers, underscores</small>
      </label>
      <label>Display title <input name="title" maxlength="100" placeholder="Programming"></label>
      <label>Description <textarea name="description" rows="3" maxlength="500" placeholder="What is this community about?"></textarea></label>
      <div class="form-actions"><button class="btn btn-primary" type="submit">Create community</button>
        <a class="btn btn-ghost" href="#/communities">Cancel</a></div>
    </form>
    <p class="dim small">You'll be the founding moderator. Anyone can post and comment; you can remove content, lock threads, pin posts, ban users, and add other moderators.</p>
  </div>`)
  renderSidebar(await sidebarHome(), token)
}

// ---- COMMUNITIES list -------------------------------------------------------
async function viewCommunities ({ guard, token }) {
  guard(skeleton('Communities'))
  const communities = await data.listCommunities()
  await Promise.all(communities.map(async c => { c._count = await sync.count(`post!${c.slug}!`) }))
  communities.sort((a, b) => (b._count || 0) - (a._count || 0))
  if (token !== renderToken) return
  guard(`<div class="feed-head"><h1>Communities</h1><a class="btn btn-primary" href="#/create">＋ Create</a></div>
    <div class="comm-list">${communities.length ? communities.map(c => `
      <div class="comm-row">
        <span class="comm-icon" style="background:${colorFor(c.slug)}">r/</span>
        <div class="comm-info">
          <a class="comm-name" href="#/r/${esc(c.slug)}">r/${esc(c.slug)}</a>
          <div class="dim small">${esc(c.description || '')}</div>
          <div class="dim small">${fmtCount(c._count || 0)} posts</div>
        </div>
        <button class="btn ${prefs.isSubscribed(c.slug) ? 'btn-ghost' : 'btn-primary'} sm" data-act="sub" data-slug="${esc(c.slug)}">${prefs.isSubscribed(c.slug) ? 'Joined' : 'Join'}</button>
      </div>`).join('') : `<div class="empty"><h3>No communities yet</h3><a class="btn btn-primary" href="#/create">Create the first one</a> <button class="btn btn-ghost" data-act="seed-demo">Load demo content</button></div>`}</div>`)
  renderSidebar(await sidebarHome(), token)
}

async function viewCommunityAbout ({ community, guard, token }) {
  const c = await data.getCommunity(community)
  if (!c) return done(guard, token, notFound(), renderSidebarHome)
  const ov = await data.overlay(community)
  await primeNames([...ov.mods])
  if (token !== renderToken) return
  guard(`${communityCard(c, ov.mods)}
    <div class="panel">
      <h2>About r/${esc(c.slug)}</h2>
      <p>${esc(c.description || 'No description.')}</p>
      <h3>Moderators</h3>
      <ul class="mod-list">${[...ov.mods].map(m => `<li><a href="#/u/${esc(m)}">${esc(nameOf(m))}</a>${m === c.creator ? ' <span class="tag">founder</span>' : ''}</li>`).join('')}</ul>
      <h3>Created</h3><p class="dim">${new Date(c.createdAt).toLocaleString()}</p>
    </div>`)
  renderSidebar(communitySidebar(c, ov.mods), token)
}

// ---- PROFILE view -----------------------------------------------------------
async function viewProfile ({ pub, guard, token }) {
  guard(skeleton('Profile'))
  const me = identity.me()
  const mine = pub === me.pubkey
  const profile = await data.getProfile(pub)
  const karma = await data.karmaFor(pub)
  const activity = await data.userActivity(pub, { limit: 50 })
  await primeNames([pub])
  if (token !== renderToken) return

  const items = [
    ...activity.posts.map(p => ({ kind: 'post', t: p.createdAt, p })),
    ...activity.comments.map(c => ({ kind: 'comment', t: c.createdAt, c }))
  ].sort((a, b) => b.t - a.t).slice(0, 60)

  const feed = items.length ? items.map(it => it.kind === 'post'
    ? `<div class="activity post"><span class="atag">post</span> in <a href="#/r/${esc(it.p.community)}">r/${esc(it.p.community)}</a> · ${timeAgo(it.p.createdAt)}
        <a class="alink" href="${buildRoute(['r', it.p.community, 'comments', it.p.cid])}">${esc(it.p.title)}</a></div>`
    : `<div class="activity comment"><span class="atag">comment</span> on <a class="alink" href="${buildRoute(['r', it.c.community, 'comments', it.c.postCid])}">${esc(it.c.postTitle || 'a post')}</a> · ${timeAgo(it.c.createdAt)}
        <div class="md small">${renderMarkdown(it.c.body)}</div></div>`
  ).join('') : `<div class="empty"><p>No activity yet.</p></div>`

  guard(`<div class="profile-head">
      <span class="avatar lg" style="background:${colorFor(pub)}"></span>
      <div>
        <h1>${esc(nameOf(pub))}</h1>
        <div class="dim mono">${esc(shortKey(pub, 10))}</div>
        ${profile && profile.bio ? `<p class="bio">${esc(profile.bio)}</p>` : ''}
        ${mine ? '<button class="btn btn-ghost sm" data-act="edit-profile">Edit profile</button>' : ''}
      </div>
    </div>
    <div class="karma-row">
      <div class="karma"><b>${fmtCount(karma.total)}</b><span>karma</span></div>
      <div class="karma"><b>${fmtCount(karma.postKarma)}</b><span>post</span></div>
      <div class="karma"><b>${fmtCount(karma.commentKarma)}</b><span>comment</span></div>
      <div class="karma"><b>${fmtCount(karma.postCount)}</b><span>posts</span></div>
      <div class="karma"><b>${fmtCount(karma.commentCount)}</b><span>comments</span></div>
    </div>
    <h2 class="section-title">Activity</h2>
    <div class="activity-feed">${feed}</div>`)
  renderSidebar(await sidebarHome(), token)
}

// ---- SAVED view -------------------------------------------------------------
async function viewSaved ({ guard, token }) {
  guard(skeleton('Saved'))
  const refs = prefs.saved()
  const posts = []
  for (const ref of refs) {
    const [c, cid] = ref.split('/')
    const p = await data.getPost(c, cid)
    if (p) posts.push(p)
  }
  const withT = await data.withTallies(posts)
  await primeNames(withT.map(p => p.author))
  const counts = await countCommentsFor(withT)
  if (token !== renderToken) return
  guard(`<div class="feed-head"><h1>Saved</h1></div>
    <div class="feed">${withT.length ? withT.map(p => postCard(p, null, { commentCounts: counts })).join('') : '<div class="empty"><p>Nothing saved yet. Hit ☆ save on any post.</p></div>'}</div>`)
  renderSidebar(await sidebarHome(), token)
}

// ---- SEARCH view ------------------------------------------------------------
async function viewSearch ({ query, guard, token }) {
  const q = (query.q || '').trim()
  guard(skeleton('Search'))
  if (!q) return done(guard, token, `<div class="empty"><h3>Search peerit</h3><p>Type a query in the bar above.</p></div>`, renderSidebarHome)
  const needle = q.toLowerCase()
  const communities = (await data.listCommunities())
  const commHits = communities.filter(c => (c.slug + ' ' + (c.title || '') + ' ' + (c.description || '')).toLowerCase().includes(needle))
  const allPosts = await data.listAllPosts()
  const postHits = allPosts.filter(p => !p.deleted && (p.title + ' ' + (p.body || '')).toLowerCase().includes(needle)).slice(0, 50)
  const withT = await data.withTallies(postHits)
  await primeNames(withT.map(p => p.author))
  const counts = await countCommentsFor(withT)
  if (token !== renderToken) return
  guard(`<div class="feed-head"><h1>Results for "${esc(q)}"</h1></div>
    ${commHits.length ? `<h2 class="section-title">Communities</h2><div class="comm-list">${commHits.map(c => `
      <div class="comm-row"><span class="comm-icon" style="background:${colorFor(c.slug)}">r/</span>
        <div class="comm-info"><a class="comm-name" href="#/r/${esc(c.slug)}">r/${esc(c.slug)}</a><div class="dim small">${esc(c.description || '')}</div></div></div>`).join('')}</div>` : ''}
    <h2 class="section-title">Posts</h2>
    <div class="feed">${withT.length ? sortPosts(withT, 'top').map(p => postCard(p, null, { commentCounts: counts })).join('') : '<div class="empty"><p>No matching posts.</p></div>'}</div>`)
  renderSidebar(await sidebarHome(), token)
}

// ---- SETTINGS view ----------------------------------------------------------
async function viewSettings ({ guard, token }) {
  const me = identity.me()
  const profile = await data.getProfile(me.pubkey)
  const status = await data.status()
  if (token !== renderToken) return
  guard(`<div class="panel">
    <h1>Settings</h1>
    <h2>Profile</h2>
    <form data-form="profile">
      <label>Display name <input name="name" maxlength="32" value="${esc(profile && profile.name || '')}" placeholder="pick a name"></label>
      <label>Bio <textarea name="bio" rows="3" maxlength="500" placeholder="about you">${esc(profile && profile.bio || '')}</textarea></label>
      <div class="form-actions"><button class="btn btn-primary" type="submit">Save profile</button></div>
    </form>
    <h2>Identity</h2>
    <p class="mono small">pubkey: ${esc(me.pubkey)}</p>
    <h2>Network</h2>
    <ul class="kv">
      <li><span>Mode</span><b>${sync.mode === 'dev' ? 'Local dev fallback' : 'PearBrowser P2P bridge'}</b></li>
      <li><span>App id</span><b>peerit</b></li>
      <li><span>Records in view</span><b>${fmtCount(status.viewLength || 0)}</b></li>
      ${status.inviteKey ? `<li><span>Group key</span><b class="mono small">${esc(shortKey(status.inviteKey, 12))}</b></li>` : ''}
    </ul>
    ${identity.isDev ? `<h2>Dev tools</h2>
      <p class="dim small">You're running outside PearBrowser. Multiple browser tabs share one world via localStorage + BroadcastChannel, so you can simulate several users.</p>
      <div class="form-actions">
        <button class="btn btn-ghost" data-act="seed-demo">Load demo content</button>
        <button class="btn btn-ghost danger" data-act="wipe">Wipe all local data</button>
      </div>` : ''}
  </div>`)
  renderSidebar(await sidebarHome(), token)
}

// ---- sidebar ----------------------------------------------------------------
function renderSidebar (html, token) { if (token != null && token !== renderToken) return; const s = $('#sidebar'); if (s) s.innerHTML = html }
function renderSidebarHome (token) { sidebarHome().then(html => renderSidebar(html, token)) }

async function sidebarHome () {
  const communities = await data.listCommunities()
  await Promise.all(communities.map(async c => { c._count = await sync.count(`post!${c.slug}!`) }))
  communities.sort((a, b) => (b._count || 0) - (a._count || 0))
  const top = communities.slice(0, 8)
  return `<div class="card side">
      <h3>peerit</h3>
      <p class="dim small">A peer-to-peer Reddit. No servers — posts, comments and votes live in a shared Holepunch log and replicate directly between peers.</p>
      <a class="btn btn-primary block" href="#/submit">Create post</a>
      <a class="btn btn-ghost block" href="#/create">Create community</a>
    </div>
    <div class="card side">
      <h3>Top communities</h3>
      ${top.length ? top.map((c, i) => `<a class="side-comm" href="#/r/${esc(c.slug)}"><span class="rank">${i + 1}</span><span class="comm-icon sm" style="background:${colorFor(c.slug)}">r/</span><span class="grow">r/${esc(c.slug)}</span><span class="dim small">${fmtCount(c._count || 0)}</span></a>`).join('') : '<p class="dim small">None yet.</p>'}
      <a class="see-all" href="#/communities">See all →</a>
    </div>`
}

function communityCard (c, mods) {
  const sub = prefs.isSubscribed(c.slug)
  return `<div class="community-banner">
    <span class="comm-icon lg" style="background:${colorFor(c.slug)}">r/</span>
    <div class="cb-info">
      <h1>r/${esc(c.slug)}</h1>
      <span class="dim">${esc(c.title || '')}</span>
    </div>
    <button class="btn ${sub ? 'btn-ghost' : 'btn-primary'}" data-act="sub" data-slug="${esc(c.slug)}">${sub ? 'Joined' : 'Join'}</button>
    <a class="btn btn-ghost" href="#/submit?to=${esc(c.slug)}">＋ Post</a>
  </div>`
}

function communitySidebar (c, mods) {
  if (!c) return ''
  return `<div class="card side">
      <h3>About r/${esc(c.slug)}</h3>
      <p class="small">${esc(c.description || 'No description.')}</p>
      <div class="dim small">Created ${timeAgo(c.createdAt)}</div>
      <a class="btn btn-primary block" href="#/submit?to=${esc(c.slug)}">Create post</a>
      <a class="btn btn-ghost block" href="#/r/${esc(c.slug)}/about">Community info</a>
    </div>
    ${c.rules && c.rules.length ? `<div class="card side"><h3>Rules</h3><ol class="rules">${c.rules.map(r => `<li>${esc(typeof r === 'string' ? r : r.title)}</li>`).join('')}</ol></div>` : ''}
    <div class="card side"><h3>Moderators</h3>${mods ? [...mods].map(m => `<a class="side-comm" href="#/u/${esc(m)}"><span class="avatar sm" style="background:${colorFor(m)}"></span><span class="grow">${esc(nameOf(m))}</span>${m === c.creator ? '<span class="tag">founder</span>' : ''}</a>`).join('') : ''}</div>`
}

// ---- skeleton / empty / 404 -------------------------------------------------
function skeleton (label) {
  return `<div class="feed-head"><h1>${label}</h1></div><div class="feed">
    ${'<div class="post card skel"><div class="votes"></div><div class="post-main"><div class="sk-line w40"></div><div class="sk-line w80"></div><div class="sk-line w60"></div></div></div>'.repeat(3)}
  </div>`
}
function notFound (msg) { return `<div class="empty"><h3>404</h3><p>${esc(msg || 'Nothing here.')}</p><a class="btn btn-primary" href="#/">Go home</a></div>` }
function done (guard, token, html, sidebarFn) { if (token === renderToken) { guard(html); if (sidebarFn) sidebarFn() } }

// ---- event handlers ---------------------------------------------------------
async function onClick (e) {
  const t = e.target.closest('[data-act]')
  if (!t) {
    // close dropdown on outside click
    const drop = $('#userdrop')
    if (drop && !e.target.closest('#usermenu')) drop.hidden = true
    return
  }
  const act = t.dataset.act
  try {
    switch (act) {
      case 'vote': return void await onVote(t)
      case 'save': { prefs.toggleSaved(t.dataset.ref); t.textContent = prefs.isSaved(t.dataset.ref) ? '★ saved' : '☆ save'; return }
      case 'hide': { prefs.toggleHidden(t.dataset.ref); route(); return }
      case 'sub': { const slug = t.dataset.slug; const now = prefs.toggleSub(slug); toast(now ? 'Joined r/' + slug : 'Left r/' + slug); route(); return }
      case 'copylink': return void copyLink(t.dataset.ref)
      case 'collapse': return toggleCollapse(t)
      case 'reply': { openReplies.add(t.dataset.cid); route(); return }
      case 'cancel-reply': { openReplies.delete(t.dataset.cid); route(); return }
      case 'toggle-usermenu': { const d = $('#userdrop'); if (d) { d.hidden = !d.hidden; t.setAttribute('aria-expanded', String(!d.hidden)) } return }
      case 'netstatus': return void updateNetStatus()
      case 'switch-user': { identity.switchUser(t.dataset.pub); if (sync.announce) sync.announce(); refreshPrefs(); nameCache.clear(); renderUserMenu(); route(); toast('Switched user'); return }
      case 'new-user': return void await newDevUser()
      case 'seed-demo': return void await seedDemo()
      case 'wipe': return void wipe()
      case 'timewindow': return // handled in change via select; ignore click
      case 'edit-post': return void editPost(t)
      case 'delete-post': return void deletePost(t)
      case 'edit-comment': return void editComment(t)
      case 'delete-comment': return void deleteComment(t)
      case 'edit-profile': { location.hash = '#/settings'; return }
      case 'mod': return void await onMod(t)
    }
  } catch (err) { toast(err.message || String(err), 'error') }
}

function onInput (e) {
  // toggle submit-post body/url fields by kind
  if (e.target.name === 'kind') return
  if (e.target.matches('input[name="kind"]')) {}
  const form = e.target.closest('form[data-form="submit-post"]')
  if (form && e.target.name === 'kind') return
}

// kind radio toggles (separate listener for change)
document.addEventListener('change', (e) => {
  if (e.target.matches('form[data-form="submit-post"] input[name="kind"]')) {
    const form = e.target.closest('form')
    const kind = form.querySelector('input[name="kind"]:checked').value
    form.querySelector('.field-body').hidden = kind !== 'text'
    form.querySelector('.field-url').hidden = kind === 'text'
  }
  if (e.target.matches('select.timewin')) {
    const { path, query } = parseRoute(location.hash)
    location.hash = buildRoute(path, { ...query, t: e.target.value })
  }
  if (e.target.matches('select[name="community"]')) { /* no-op */ }
})

async function onVote (t) {
  const box = t.closest('.votes')
  const cid = box.dataset.cid
  const community = box.dataset.community
  const type = box.dataset.type
  const dir = Number(t.dataset.dir)
  const cur = box.querySelector('.arrow.up').classList.contains('on') ? 1 : box.querySelector('.arrow.down').classList.contains('on') ? -1 : 0
  const next = cur === dir ? 0 : dir
  const scoreEl = box.querySelector('.score')
  const base = parseScore(scoreEl.textContent) - cur
  const paint = (v) => {
    scoreEl.textContent = fmtCount(base + v)
    box.querySelector('.arrow.up').classList.toggle('on', v === 1)
    box.querySelector('.arrow.down').classList.toggle('on', v === -1)
    scoreEl.classList.toggle('pos', v === 1)
    scoreEl.classList.toggle('neg', v === -1)
  }
  paint(next) // optimistic
  try {
    await data.vote(cid, community, type, next)
  } catch (err) {
    paint(cur) // roll back the optimistic UI on failure
    throw err  // surfaced as a toast by onClick
  }
}
function parseScore (s) {
  s = String(s).trim()
  if (/k$/i.test(s)) return Math.round(parseFloat(s) * 1000)
  if (/m$/i.test(s)) return Math.round(parseFloat(s) * 1000000)
  return parseInt(s, 10) || 0
}

function toggleCollapse (btn) {
  const node = document.getElementById(btn.dataset.target)
  if (!node) return
  const collapsed = node.classList.toggle('collapsed')
  btn.textContent = collapsed ? '[+]' : '[–]'
}

async function onMod (t) {
  const mod = t.dataset.mod
  const post = t.closest('.post') || t.closest('.comment')
  const community = post.dataset.community
  const cid = t.dataset.cid || post.dataset.cid
  const user = t.dataset.user
  if (mod === MOD.BAN) {
    if (!confirm('Ban ' + nameOf(user) + ' from r/' + community + '?')) return
    await data.banUser(community, user, '')
    toast('User banned')
  } else {
    await data.modAction(community, { action: mod, targetCid: cid })
    toast('Done: ' + mod)
  }
  route()
}

async function editPost (t) {
  const post = t.closest('.post')
  const community = post.dataset.community, cid = post.dataset.cid
  const rec = await data.getPost(community, cid)
  const next = prompt('Edit post body (markdown):', rec.body || '')
  if (next == null) return
  await data.editPost(community, cid, next)
  toast('Post updated'); route()
}
async function deletePost (t) {
  const post = t.closest('.post')
  if (!confirm('Delete this post?')) return
  await data.deletePost(post.dataset.community, post.dataset.cid)
  toast('Post deleted'); route()
}
async function editComment (t) {
  const node = t.closest('.comment')
  const community = node.dataset.community, cid = t.dataset.cid
  const { path } = parseRoute(location.hash)
  const postCid = path[3]
  const rec = await sync.get(`comment!${community}!${postCid}!${cid}`)
  const next = prompt('Edit comment:', rec.body || '')
  if (next == null) return
  await data.editComment(community, postCid, cid, next)
  toast('Comment updated'); route()
}
async function deleteComment (t) {
  const node = t.closest('.comment')
  const { path } = parseRoute(location.hash)
  if (!confirm('Delete this comment?')) return
  await data.deleteComment(node.dataset.community, path[3], t.dataset.cid)
  toast('Comment deleted'); route()
}

async function onSubmit (e) {
  const form = e.target.closest('form[data-form]')
  if (!form) return
  e.preventDefault()
  const f = form.dataset.form
  const fd = new FormData(form)
  if (form.dataset.busy) return // block double-submit while the write is in flight
  const btn = form.querySelector('button[type="submit"]')
  if (f !== 'search') {
    form.dataset.busy = '1'
    if (btn) { btn.dataset.label = btn.textContent; btn.disabled = true; btn.textContent = '…' }
  }
  try {
    if (f === 'search') { const q = (fd.get('q') || '').trim(); if (q) location.hash = buildRoute(['search'], { q }); return }
    if (f === 'create-community') {
      const c = await data.createCommunity({ slug: fd.get('slug'), title: fd.get('title'), description: fd.get('description') })
      prefs.subscribe(c.slug)
      toast('Created r/' + c.slug)
      location.hash = '#/r/' + c.slug
      return
    }
    if (f === 'submit-post') {
      const p = await data.submitPost({
        community: fd.get('community'), kind: fd.get('kind'),
        title: fd.get('title'), body: fd.get('body'), url: fd.get('url')
      })
      toast('Posted')
      location.hash = buildRoute(['r', p.community, 'comments', p.cid])
      return
    }
    if (f === 'comment') {
      const body = fd.get('body')
      const parent = form.dataset.parent || null
      await data.addComment({ community: form.dataset.community, postCid: form.dataset.post, parentCid: parent, body })
      if (parent) openReplies.delete(parent)
      form.reset()
      toast('Comment added'); route()
      return
    }
    if (f === 'profile') {
      await data.setProfile({ name: fd.get('name'), bio: fd.get('bio') })
      data.invalidateProfile(identity.me().pubkey)
      nameCache.delete(identity.me().pubkey)
      await renderUserMenu()
      toast('Profile saved'); route()
      return
    }
  } catch (err) { toast(err.message || String(err), 'error') }
  finally {
    delete form.dataset.busy
    if (btn && document.contains(btn)) { btn.disabled = false; btn.textContent = btn.dataset.label || btn.textContent }
  }
}

// ---- dev helpers ------------------------------------------------------------
async function newDevUser () {
  const name = prompt('New dev user name:', 'user_' + Math.floor(Math.random() * 999))
  if (!name) return
  await identity.createUser(name)
  if (sync.announce) await sync.announce()
  refreshPrefs(); nameCache.clear()
  await renderUserMenu(); route(); toast('Created & switched to ' + name)
}

async function seedDemo () {
  toast('Seeding demo content…')
  const demo = [
    { slug: 'p2p', title: 'Peer-to-Peer', desc: 'Everything decentralized, distributed, and serverless.' },
    { slug: 'holepunch', title: 'Holepunch', desc: 'Hypercore, Hyperswarm, Autobase, Pear.' },
    { slug: 'privacy', title: 'Privacy', desc: 'Own your data. Encrypt everything.' }
  ]
  for (const d of demo) {
    try { await data.createCommunity({ slug: d.slug, title: d.title, description: d.desc }) } catch {}
    prefs.subscribe(d.slug)
  }
  const posts = [
    { c: 'p2p', kind: 'text', title: 'Why peer-to-peer beats the cloud', body: 'No servers means **no single point of failure**, no monthly bill, and no landlord who can deplatform you.\n\n- Data lives with the people who care about it\n- It works offline and syncs when you reconnect\n- Censorship-resistant by design' },
    { c: 'holepunch', kind: 'text', title: 'Autobase is underrated', body: 'Multi-writer logs that linearize deterministically. Once it clicks, you stop reaching for a database.' },
    { c: 'holepunch', kind: 'link', title: 'Hyperswarm DHT explained', url: 'https://docs.holepunch.to' },
    { c: 'privacy', kind: 'text', title: 'Threat-model your apps', body: 'Ask: who can read this, who can write this, and what happens when a node goes rogue?' },
    { c: 'p2p', kind: 'text', title: 'peerit is Reddit with no data center', body: 'This very app is a P2P site. The thread you are reading replicated to you directly from a peer.' }
  ]
  const created = []
  for (const p of posts) {
    try { created.push(await data.submitPost({ community: p.c, kind: p.kind, title: p.title, body: p.body, url: p.url })) } catch (e) { console.error('seed post failed', e) }
  }
  // a few comments + votes for texture
  if (created[0]) {
    const c1 = await data.addComment({ community: created[0].community, postCid: created[0].cid, body: 'This is exactly why I switched. No regrets.' })
    await data.addComment({ community: created[0].community, postCid: created[0].cid, parentCid: c1.cid, body: 'Same. The offline-first part sold me.' })
    await data.vote(created[0].cid, created[0].community, 'post', 1)
  }
  toast('Demo content ready')
  location.hash = '#/'
  route()
}

function wipe () {
  if (!confirm('Wipe ALL local peerit data (communities, posts, prefs)? This cannot be undone.')) return
  try {
    const ls = localStorage
    Object.keys(ls).filter(k => k.startsWith('peerit:')).forEach(k => ls.removeItem(k))
    sessionStorage.removeItem('peerit:dev:active')
  } catch {}
  location.reload()
}

// ---- misc -------------------------------------------------------------------
function copyLink (ref) {
  const [c, cid] = ref.split('/')
  const url = location.origin + location.pathname + buildRoute(['r', c, 'comments', cid])
  try { navigator.clipboard.writeText(url); toast('Link copied') }
  catch { toast(url) }
}

function toast (msg, kind = 'ok') {
  const root = $('#toasts'); if (!root) return
  const el = document.createElement('div')
  el.className = 'toast ' + kind
  el.textContent = msg
  root.appendChild(el)
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300) }, 2600)
}

// expose for debugging / tests
if (typeof window !== 'undefined') window.__peerit = { get data () { return data }, get sync () { return sync }, route }

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot)
  else boot()
}

export { boot }
