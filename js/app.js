// app.js — peerit UI. Hash router + async views rendered into #app, with all
// interaction handled by event delegation. Reads/writes go through Data; ranking
// and threading come from ranking.js / model.js. Works identically on the real
// PearBrowser bridge and the localStorage dev-fallback.

import { createSync } from './sync.js'
import { createIdentity } from './identity.js'
import { resolveRuntime } from './runtime.js'
import { resolveRelayCandidates, selectRelays } from './relay-roster.js'
import { createRelayPool } from './relay-pool.js'
import { cacheClassForChangedKeys, createData } from './data.js'
import { Prefs } from './prefs.js'
import { STARTER_COMMUNITIES, STARTER_POSTS, WELCOME_COMMUNITY, starterCommunity } from './onboarding.js'
import { renderMarkdown, excerpt } from './markdown.js'
import { sortPosts, sortComments, POST_SORTS, COMMENT_SORTS, TIME_WINDOW_KEYS } from './ranking.js'
import { buildCommentTree, sortCommentTree, annotateDescendants, countDescendants, MOD } from './model.js'
import { COPY as RECOVERY_COPY, buildRecoveryBundle, cleanOutboxes, peeritSeederCommand, recoveryBundleFilename, recoveryBundleJson } from './recovery.js'
import { exportIdentity, importIdentity, looksLikeIdentityExport, identityExportJson, identityExportFilename, passphraseStrength, MIN_PASSPHRASE } from './identity-export.js'
import { encodeQR, qrToSvg, isScanSupported, scanQR } from './qr.js'
import {
  escapeHtml as esc, timeAgo, fmtCount, parseRoute, buildRoute,
  colorFor, shortKey, debounce, normalizeSlug, safeUserUrl
} from './util.js'

// ---- app singletons ---------------------------------------------------------
let sync, identity, data, prefs
let runtime = null                 // { mode, identityOpts, syncOpts, readOnly } from resolveRuntime
let renderToken = 0
let _lastHash = ''
const openReplies = new Set()      // comment cids with an open reply box
const collapsedComments = new Set() // comment cids the user has collapsed (survives re-renders)
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
  // Decide the runtime from the environment. In PearBrowser (window.pear) this
  // resolves to empty opts == the existing host path, untouched. Only a normal
  // browser with no host bridge and a configured relay gets the web path
  // (local keys + remote untrusted relay). See js/runtime.js.
  runtime = resolveRuntime({
    rawPear: (typeof window !== 'undefined' ? window.pear : null),
    doc: (typeof document !== 'undefined' ? document : null)
  })
  // Identity first — the gossip layer needs to know who "me" is to pick which
  // outbox to write to (getMe is read dynamically so user-switching just works).
  // In web mode this is a browser-LOCAL key (forceDev); the relay never signs.
  identity = createIdentity(runtime.identityOpts)
  await identity.ready()

  // Web mode transport selection (PearBrowser/dev use runtime.syncOpts = {}):
  //   1) strongest: an in-browser DHT pipe (Phase 3) if a dht-relay is configured
  //      AND its built bundle loads — the relay can't even read the traffic.
  //   2) otherwise: verify the signed relay roster (when configured), then get
  //      a first-visit token from the first reachable /api relay.
  //   3) on any failure: local-only (no token → no bridge surface → dev fallback).
  let pearOverride = null
  let relayPool = null
  if (runtime.mode === 'web') {
    if (runtime.dhtRelay) {
      try {
        const m = await import('./dht-bundle.js') // esbuilt Phase 3 bundle (absent in the base site)
        pearOverride = await m.createDhtTransport({ relayWsUrl: runtime.dhtRelay, identity })
        console.log('[peerit] using in-browser DHT transport')
      } catch (e) { console.warn('[peerit] DHT transport unavailable; using /api relay:', e && e.message) }
    }
    if (!pearOverride) {
      const candidates = await resolveRelayCandidates({
        relays: runtime.relays || [runtime.syncOpts.apiBase],
        roster: runtime.relayRoster,
        fetch: globalThis.fetch && globalThis.fetch.bind(globalThis),
        onWarning: (e) => console.warn('[peerit] relay roster unavailable:', e && e.message)
      })
      // Phase B: select UP TO 3 working relays and drive them as a pool — writes
      // fan out and each author's signed head is cross-checked (highest version
      // wins), which defeats a single relay serving a stale/absent head. Degrades
      // to a pool of one (single-relay behaviour) when only one is configured.
      const selected = await selectRelays(candidates.relays, {
        apiToken: runtime.syncOpts.apiToken,
        fetch: globalThis.fetch && globalThis.fetch.bind(globalThis)
      })
      if (selected.length) {
        relayPool = createRelayPool({ relays: selected, fetch: runtime.syncOpts.fetch, EventSource: runtime.syncOpts.EventSource })
        if (candidates.rosterVerified) console.log('[peerit] verified signed relay roster; pool of ' + selected.length + ' relay(s)')
      } else {
        runtime.syncOpts.apiToken = ''
        console.warn('[peerit] no relay reachable — falling back to local-only mode')
      }
    }
  }
  // writeHead: maintain a signed head!<me> census after each write (the outbox
  // "merkle root" — lets any reader detect a relay withholding records). Real
  // runs only; existing count-based tests don't set it.
  const pearForSync = pearOverride || relayPool
  sync = pearForSync
    ? createSync({ getMe: () => identity.me().pubkey, identity, pear: pearForSync, writeHead: true, readOnly: runtime.readOnly })
    : createSync({ getMe: () => identity.me().pubkey, identity, ...runtime.syncOpts, writeHead: true, readOnly: runtime.readOnly })
  await sync.ready()
  data = createData(sync, identity)
  refreshPrefs()
  sync.onChange((changed) => data.invalidateViewCaches(cacheClassForChangedKeys(changed)))

  // Live updates: when peers' data changes, repaint just the affected vote
  // widgets in place when we can, and only fall back to a full re-render for
  // structural changes (new/edited/deleted posts & comments, mod actions). The
  // bridge tells us WHICH keys changed (gossip.js); dev mode reports nothing, so
  // it always does a full render. Changes accumulate across the debounce window.
  let pendingKeys = null   // Set of changed storage keys since the last flush
  let pendingFull = false  // a change we can't patch → must full-render
  const flush = async () => {
    const a = document.activeElement
    // Don't rip focus from anything the user is interacting with: a form field,
    // a select, or any focused control inside the content area. The live update
    // lands as soon as focus moves on. (Local actions re-render explicitly.)
    if (a && (/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) || a.isContentEditable)) return
    if (a && a !== document.body && app() && app().contains(a)) return
    const full = pendingFull, keys = pendingKeys
    pendingFull = false; pendingKeys = null
    if (!full && keys && await patchVotesInPlace(keys)) return // repainted in place; no re-render
    route()
  }
  const soft = debounce(flush, 350)
  sync.onChange((changed) => {
    if (!changed) pendingFull = true
    else { if (!pendingKeys) pendingKeys = new Set(); for (const k of changed) pendingKeys.add(k) }
    soft()
  })
  sync.onChange(() => updateNetStatus())
  // The gossip layer already re-merges + emits onChange on its own poll and on
  // every real event, so a separate status timer here is redundant.

  window.addEventListener('hashchange', route)
  window.addEventListener('pagehide', () => { try { if (sync && sync.destroy) sync.destroy() } catch {} })
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

function isBridgeMode () {
  return !!(sync && String(sync.mode || '').includes('bridge'))
}

// Web read-only mode: the page is served from a normal origin against a relay
// with writes disabled. Content is fetched + verified, but posting/voting is
// blocked until a write path (local keys + writable relay) is enabled.
function isReadOnly () { return !!(runtime && runtime.readOnly) }

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
  // Web read-only: hide write affordances (composer, vote arrows, post/create
  // links) via a body class, and explain why. The write handlers are guarded
  // independently, so this is purely about not offering dead controls.
  document.body.classList.toggle('web-readonly', isReadOnly())
  if (isReadOnly()) {
    const banner = document.createElement('div')
    banner.className = 'readonly-banner'
    banner.innerHTML = 'Read-only — you\'re viewing peerit over a public relay. Posts and votes are verified here, but to participate, <a href="https://pears.com/" target="_blank" rel="noopener">open peerit in PearBrowser</a>.'
    document.body.insertBefore(banner, document.body.firstChild)
  }
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
    el.innerHTML = `<b>${esc(s.mode || 'sync')}</b> · ${s.peers != null ? s.peers : 1}p · ${s.viewLength || 0} recs · <span class="mono">${esc((me.pubkey || '').slice(0, 6))}…</span>${secure ? '' : ' · ⚠ insecure'}${isReadOnly() ? ' · read-only' : ''}`
  } catch (e) { el.textContent = 'sync: ' + (e.message || 'error') }
}

async function renderUserMenu () {
  const me = identity.me()
  await primeNames([me.pubkey])
  const el = $('#usermenu')
  if (!el) return
  const badge = (runtime && runtime.mode === 'web')
    ? '<span class="mode-badge web" title="Bridged to peerit\'s P2P network over a public relay — records are verified, but install PearBrowser for fully trustless P2P">web</span>'
    : !isBridgeMode()
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
    `<form class="dd-new-user" data-form="dev-user">
      <input name="name" placeholder="New dev user" maxlength="32" autocomplete="off" required>
      <button type="submit" title="Create dev user">＋</button>
    </form>`
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
    case 'bridge-proof': return viewBridgeProof({ session: path[1], query, guard, token })
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

// ---- local PearBrowser bridge proof ----------------------------------------
function bridgeProofSession (raw) {
  const s = normalizeSlug(raw || '')
  return s || Date.now().toString(36)
}
function bridgeProofRole (raw) { return String(raw || '').toLowerCase() === 'b' ? 'b' : 'a' }
function bridgeProofSlug (session) { return normalizeSlug('bridge_' + bridgeProofSession(session)).slice(0, 24) }
function bridgeProofTitle (session, role) { return `Bridge proof ${role.toUpperCase()} ${bridgeProofSession(session)}` }
function bridgeProofBody (session, role) { return `Local publish bridge proof ${role.toUpperCase()} for ${bridgeProofSession(session)}.` }

function slimProofRecord (rec) {
  if (!rec) return null
  return {
    cid: rec.cid || '',
    slug: rec.slug || '',
    title: rec.title || '',
    author: rec.author || rec.creator || '',
    creator: rec.creator || '',
    createdAt: rec.createdAt || 0,
    updatedAt: rec.updatedAt || 0
  }
}

function sanitizeBridgeProofStatus (status) {
  return {
    mode: status && status.mode || '',
    secure: !(status && status.secure === false),
    peers: status && status.peers != null ? status.peers : null,
    viewLength: status && status.viewLength != null ? status.viewLength : null,
    relays: status && status.relays != null ? status.relays : null,
    outboxAppId: status && status.outboxAppId || '',
    withholding: Array.isArray(status && status.withholding) ? status.withholding.slice() : [],
    outboxes: Array.isArray(status && status.outboxes)
      ? status.outboxes.map(o => ({ appId: o.appId || '', current: !!o.current }))
      : []
  }
}

async function findBridgeProofPost (session, role) {
  const slug = bridgeProofSlug(session)
  const title = bridgeProofTitle(session, role)
  const posts = await data.listPostsIn(slug).catch(() => [])
  return posts.find(p => p && p.title === title) || null
}

async function ensureBridgeProofPost (session, role, onProgress) {
  const existing = await findBridgeProofPost(session, role)
  if (existing) return existing
  return data.submitPost({
    community: bridgeProofSlug(session),
    kind: 'text',
    title: bridgeProofTitle(session, role),
    body: bridgeProofBody(session, role),
    onProgress
  })
}

async function buildBridgeProofSnapshot (session, role) {
  session = bridgeProofSession(session)
  role = bridgeProofRole(role)
  const slug = bridgeProofSlug(session)
  const me = identity.me()
  const status = sanitizeBridgeProofStatus(await sync.status())
  const community = await data.getCommunity(slug).catch(() => null)
  const aPost = community ? await findBridgeProofPost(session, 'a') : null
  const bPost = community ? await findBridgeProofPost(session, 'b') : null
  const aAuthor = aPost && aPost.author
  const bAuthor = bPost && bPost.author
  const observations = {
    bridgeMode: status.mode === 'gossip-bridge',
    peersAtLeast2: Number(status.peers || 0) >= 2,
    writerKey: (me.pubkey || '').slice(0, 6),
    sawA: !!aPost,
    sawB: !!bPost,
    wroteOwnRole: role === 'a' ? !!(aPost && aPost.author === me.pubkey) : !!(bPost && bPost.author === me.pubkey),
    sawPeerRole: role === 'a' ? !!(bPost && bPost.author !== me.pubkey) : !!(aPost && aPost.author !== me.pubkey),
    writersDistinct: !!(aAuthor && bAuthor && aAuthor !== bAuthor),
    crossDeviceConverged: !!(aAuthor && bAuthor && aAuthor !== bAuthor)
  }
  return {
    type: 'peerit-local-bridge-proof',
    version: 1,
    session,
    role,
    generatedAt: new Date().toISOString(),
    url: location.href,
    userAgent: navigator.userAgent,
    writer: me.pubkey,
    writerKey: observations.writerKey,
    status,
    proof: {
      communitySlug: slug,
      expectedTitles: { a: bridgeProofTitle(session, 'a'), b: bridgeProofTitle(session, 'b') },
      observations,
      records: {
        community: slimProofRecord(community),
        aPost: slimProofRecord(aPost),
        bPost: slimProofRecord(bPost)
      }
    }
  }
}

async function waitForBridgeProofPost (session, role, timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const found = await findBridgeProofPost(session, role)
    if (found) return found
    if (sync && sync._refresh) {
      try { await sync._refresh() } catch {}
    }
    await new Promise(resolve => setTimeout(resolve, 700))
  }
  return null
}

async function runBridgeProofAction (session, role, onProgress) {
  session = bridgeProofSession(session)
  role = bridgeProofRole(role)
  const status = await sync.status()
  if (status.mode !== 'gossip-bridge') throw new Error('Bridge proof requires gossip-bridge mode.')
  if (sync.announce) await sync.announce()
  const slug = bridgeProofSlug(session)
  if (role === 'a') {
    let community = await data.getCommunity(slug)
    if (!community) {
      community = await data.createCommunity({
        slug,
        title: `Bridge Proof ${session}`,
        description: `Local publish bridge proof ${session}`,
        onProgress
      })
      prefs.subscribe(slug)
    }
    const post = await ensureBridgeProofPost(session, 'a', onProgress)
    return { community, post }
  }
  const aPost = await waitForBridgeProofPost(session, 'a')
  if (!aPost) throw new Error('Device A proof post is not visible here yet.')
  const bPost = await ensureBridgeProofPost(session, 'b', onProgress)
  return { aPost, post: bPost }
}

async function viewBridgeProof ({ session, query, guard, token }) {
  session = bridgeProofSession(session)
  const role = bridgeProofRole(query.role)
  guard(skeleton('Bridge proof'))
  const snapshot = await buildBridgeProofSnapshot(session, role)
  if (token !== renderToken) return
  const obs = snapshot.proof.observations
  const status = snapshot.status
  const roleLabel = role.toUpperCase()
  const ownAction = role === 'a' ? 'Write Device A proof record' : 'Check A and write Device B proof record'
  const peerLabel = role === 'a' ? 'Device B post visible' : 'Device A post visible'
  guard(`<section class="panel">
    <h1>Bridge proof ${esc(roleLabel)}</h1>
    <p class="dim small settings-copy">Session <b class="mono">${esc(session)}</b> writes to r/${esc(snapshot.proof.communitySlug)} on this local Hyperdrive publish.</p>
    <ul class="kv settings-kv">
      <li><span>Mode</span><b>${esc(status.mode || 'unknown')}</b></li>
      <li><span>Writer key</span><b class="mono">${esc(snapshot.writerKey)}...</b></li>
      <li><span>Peers</span><b>${esc(status.peers == null ? '?' : String(status.peers))}</b></li>
      <li><span>Records</span><b>${esc(status.viewLength == null ? '?' : String(status.viewLength))}</b></li>
      <li><span>${esc(peerLabel)}</span><b>${obs.sawPeerRole ? 'yes' : 'not yet'}</b></li>
      <li><span>Distinct A/B writers</span><b>${obs.writersDistinct ? 'yes' : 'not yet'}</b></li>
    </ul>
    <div class="form-actions wrap">
      <button class="btn btn-primary" type="button" data-act="bridge-proof-write" data-session="${esc(session)}" data-role="${esc(role)}">${esc(ownAction)}</button>
      <button class="btn btn-ghost" type="button" data-act="bridge-proof-copy" data-session="${esc(session)}" data-role="${esc(role)}">Copy proof JSON</button>
      <button class="btn btn-ghost" type="button" data-act="bridge-proof-refresh" data-session="${esc(session)}" data-role="${esc(role)}">Refresh</button>
      <a class="btn btn-ghost" href="#/r/${esc(snapshot.proof.communitySlug)}">Open r/${esc(snapshot.proof.communitySlug)}</a>
    </div>
    <label class="key-label">Current proof snapshot
      <textarea class="keybox mono" rows="12" spellcheck="false" readonly>${esc(JSON.stringify(snapshot, null, 2))}</textarea>
    </label>
  </section>`)
  renderSidebarHome()
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

function postSort (sort) {
  return POST_SORTS.includes(sort) ? sort : 'hot'
}

function voteWidget (rec, type) {
  const t = rec.tally || { score: 0, myVote: 0 }
  const up = t.myVote === 1 ? 'on' : ''
  const down = t.myVote === -1 ? 'on' : ''
  const cls = t.myVote === 1 ? 'pos' : t.myVote === -1 ? 'neg' : ''
  return `<div class="votes" data-cid="${esc(rec.cid)}" data-community="${esc(rec.community)}" data-type="${type}" data-myvote="${t.myVote || 0}">
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
  const overflow = actionOverflow(post, ov, { isMod, mine, full: opts.full })

  let bodyHtml = ''
  if (post.deleted) bodyHtml = `<div class="removed-note">[deleted by author]</div>`
  else if (removed) bodyHtml = `<div class="removed-note">[removed by moderators]</div>`
  else if (post.kind === 'link') bodyHtml = `<a class="post-link" href="${esc(safeUrl(post.url))}" target="_blank" rel="noopener noreferrer nofollow">${esc(post.url)} ↗</a>`
  else if (post.kind === 'image') bodyHtml = `<a href="${esc(safeUrl(post.url))}" target="_blank" rel="noopener noreferrer nofollow"><img class="post-img" src="${esc(safeUrl(post.url))}" alt="${esc(post.title || 'image post')}" loading="lazy" data-fallback-url="${esc(safeUrl(post.url))}"></a>`
  else if (post._blobMissing) bodyHtml = `<div class="removed-note">[encrypted body unavailable — no relay is currently serving it]</div>`
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
        ${!opts.full ? `<button class="pa" data-act="hide" data-ref="${esc(ref)}">${prefs.isHidden(ref) ? 'unhide' : 'hide'}</button>` : ''}
        ${overflow}
      </div>
    </div>
  </article>`
}

function actionOverflow (post, ov, { isMod, mine }) {
  const items = []
  if (mine && !post.deleted) {
    items.push('<button class="pa" data-act="edit-post">✎ edit</button>')
    items.push('<button class="pa danger" data-act="delete-post">🗑 delete</button>')
  }
  if (isMod && ov) items.push(modMenu(post, ov))
  if (!items.length) return ''
  return `<details class="more-actions">
    <summary class="pa" aria-label="More post actions">More</summary>
    <div class="more-menu">${items.join('')}</div>
  </details>`
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
  const sort = postSort(query.sort || prefs.sort)
  const tw = query.t || 'all'
  guard(skeleton(scope === 'community' ? 'r/' + esc(community) : (scope === 'home' ? 'Home' : 'Popular')))

  let communityMeta = null, ov = null, mods = null
  let followedSlugs = []
  let posts = []
  if (scope === 'community') {
    communityMeta = await data.getCommunity(community)
    if (!communityMeta) {
      const starter = starterCommunity(community)
      return done(guard, token, starter ? starterCommunityLanding(starter) : notFound('r/' + esc(community) + " doesn't exist yet"), renderSidebarHome)
    }
    ov = await data.overlay(community)
    mods = ov.mods
    posts = await data.listPostsIn(community)
  } else if (scope === 'home') {
    followedSlugs = prefs.subs()
    if (!followedSlugs.length) {
      // No subscriptions yet -> behave like "all" but nudge onboarding.
      posts = await data.listAllPosts()
    } else {
      posts = await data.listAllPosts(followedSlugs)
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
    : (scope === 'home' ? `<div class="feed-head"><h1>Home</h1><span class="dim">${followedSlugs.length ? 'posts from communities you follow' : 'all communities until you join some'}</span></div>`
                        : `<div class="feed-head"><h1>Popular</h1><span class="dim">across all of peerit</span></div>`)

  const base = scope === 'community' ? ['r', community] : (scope === 'home' ? [] : ['all'])
  const showWelcome = scope === 'home' && !prefs.seenWelcome
  let body
  if (!ranked.length) {
    body = showWelcome ? starterFeed() : emptyFeed(scope, community)
  } else {
    body = (showWelcome ? welcomePanel(true) : '') + ranked.map(p => postCard(p, scope === 'community' ? ov : null, {
      mods: scope === 'community' ? mods : null, commentCounts
    })).join('')
  }

  guard(`${title}${sortTabs(sort, base, query)}<div class="feed">${body}</div>`)
  if (scope === 'community') renderSidebar(communitySidebar(communityMeta, mods), token)
  else renderSidebar(await sidebarHome(), token)
}

async function countCommentsFor (posts) {
  return data.commentCountsFor(posts)
}

function emptyFeed (scope, community) {
  if (scope === 'community') {
    return `<div class="empty"><h3>No posts in r/${esc(community)} yet</h3>
      <p>Be the first to post.</p><a class="btn btn-primary" href="#/submit?to=${esc(community)}">Create a post</a></div>`
  }
  return `<div class="empty"><h3>No live posts yet</h3>
    <p>Start a community, make the first post, or bring back the starter feed.</p>
    <div class="empty-actions">
      <a class="btn btn-primary" href="#/create">Create a community</a>
      <button class="btn btn-ghost" data-act="show-welcome">Show starter feed</button>
    </div></div>`
}

function starterFeed () {
  return `${welcomePanel(false)}
    <div class="starter-grid">
      ${STARTER_COMMUNITIES.map(starterCommunityCard).join('')}
    </div>
    <h2 class="section-title starter-title">Starter feed</h2>
    ${STARTER_POSTS.map(starterPostCard).join('')}
    <div class="starter-note">Starter cards are local to this first screen. Live posts replace them as soon as peers sync or you create a community.</div>`
}

function welcomePanel (compact) {
  const mode = runtime && runtime.mode === 'web' ? 'web' : (isBridgeMode() ? 'p2p' : 'dev')
  return `<section class="welcome-panel ${compact ? 'compact' : ''}">
    <div class="welcome-copy">
      <span class="tag">${esc(mode)}</span>
      <h2>Welcome to peerit</h2>
      <p>${compact
        ? 'Your live feed is ready. Join the welcome desk when you want an easy first place to post.'
        : 'A starter feed is waiting here while your peer graph fills in. Nothing below is written to the shared network until you choose a community.'}</p>
    </div>
    <div class="welcome-actions">
      <button class="btn btn-primary" data-act="start-community" data-slug="${esc(WELCOME_COMMUNITY.slug)}">Join r/${esc(WELCOME_COMMUNITY.slug)}</button>
      <a class="btn btn-ghost" href="#/create">Create community</a>
      <button class="btn btn-ghost" data-act="dismiss-welcome">Dismiss</button>
    </div>
  </section>`
}

function starterCommunityCard (c) {
  return `<article class="starter-community">
    <span class="comm-icon" style="background:${colorFor(c.slug)}">r/</span>
    <div>
      <h3>r/${esc(c.slug)}</h3>
      <p>${esc(c.description)}</p>
      <button class="pa" data-act="start-community" data-slug="${esc(c.slug)}">Open or start</button>
    </div>
  </article>`
}

function starterPostCard (p) {
  const c = starterCommunity(p.community)
  return `<article class="starter-post">
    <div class="starter-post-meta">
      <span class="comm-icon sm" style="background:${colorFor(p.community)}">r/</span>
      <span>r/${esc(p.community)}</span>
      <span class="tag">starter</span>
    </div>
    <h2>${esc(p.title)}</h2>
    <p>${esc(p.body)}</p>
    <div class="post-actions">
      <button class="pa" data-act="start-community" data-slug="${esc(p.community)}">Open or start r/${esc(p.community)}</button>
      ${c ? `<span class="dim small">${esc(c.title)}</span>` : ''}
    </div>
  </article>`
}

function starterCommunityLanding (c) {
  return `<section class="welcome-panel">
    <div class="welcome-copy">
      <span class="tag">starter</span>
      <h2>r/${esc(c.slug)}</h2>
      <p>${esc(c.description)}</p>
    </div>
    <div class="welcome-actions">
      <button class="btn btn-primary" data-act="start-community" data-slug="${esc(c.slug)}">Start r/${esc(c.slug)}</button>
      <a class="btn btn-ghost" href="#/">Home</a>
    </div>
  </section>`
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
  annotateDescendants(sorted) // one bottom-up pass so commentNode reads node._descendants in O(1)

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
  for (const r of roots) n += (r._descendants != null ? r._descendants : countDescendants(r))
  return fmtCount(n)
}

function commentNode (node, post, ov, isMod, depth) {
  const mine = node.author === identity.me().pubkey
  const collapsedId = 'c_' + node.cid
  const isCollapsed = collapsedComments.has(node.cid) // preserved across live re-renders
  const removed = node._removed
  const deleted = node.deleted
  const locked = !!(ov.locked && ov.locked.has(post.cid))
  const childCount = node._descendants != null ? node._descendants : countDescendants(node)
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

  return `<div class="comment${isCollapsed ? ' collapsed' : ''}" data-cid="${esc(node.cid)}" data-community="${esc(node.community)}" id="${collapsedId}">
    <div class="comment-row">
      <button class="collapse" data-act="collapse" data-target="${collapsedId}" title="collapse" aria-label="Collapse or expand comment thread">${isCollapsed ? '[+]' : '[–]'}</button>
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
  return `<span class="votes inline" data-cid="${esc(rec.cid)}" data-community="${esc(rec.community)}" data-type="comment" data-myvote="${t.myVote || 0}">
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
  const showBackupWarning = await needsFirstPostBackupWarning(communities)
  const bannedHere = (await data.overlay(to)).banned.has(identity.me().pubkey)
  if (token !== renderToken) return
  guard(`<div class="panel">
    <h1>Create a post</h1>
    ${bannedHere ? `<div class="locked-note">🚫 You are banned from r/${esc(to)} — pick another community.</div>` : ''}
    <form data-form="submit-post">
      ${showBackupWarning ? firstPostBackupWarningHtml() : ''}
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
      </div>`).join('') : `<div class="empty"><h3>No communities yet</h3>
        <p>Start with the welcome desk or create your own space.</p>
        <div class="empty-actions">
          <button class="btn btn-primary" data-act="start-community" data-slug="${esc(WELCOME_COMMUNITY.slug)}">Start r/${esc(WELCOME_COMMUNITY.slug)}</button>
          <a class="btn btn-ghost" href="#/create">Create community</a>
        </div></div>`}</div>`)
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
  const { communities: commHits, posts: postHits, comments: commentHits } = await data.search(q)
  const withT = await data.withTallies(postHits)
  await primeNames([...withT.map(p => p.author), ...commentHits.map(c => c.author)])
  const counts = await countCommentsFor(withT)
  if (token !== renderToken) return
  guard(`<div class="feed-head"><h1>Results for "${esc(q)}"</h1></div>
    ${commHits.length ? `<h2 class="section-title">Communities</h2><div class="comm-list">${commHits.map(c => `
      <div class="comm-row"><span class="comm-icon" style="background:${colorFor(c.slug)}">r/</span>
        <div class="comm-info"><a class="comm-name" href="#/r/${esc(c.slug)}">r/${esc(c.slug)}</a><div class="dim small">${esc(c.description || '')}</div></div></div>`).join('')}</div>` : ''}
    <h2 class="section-title">Posts</h2>
    <div class="feed">${withT.length ? sortPosts(withT, 'top').map(p => postCard(p, null, { commentCounts: counts })).join('') : '<div class="empty"><p>No matching posts.</p></div>'}</div>
    <h2 class="section-title">Comments</h2>
    <div class="activity-feed">${commentHits.length ? commentHits.map(c => `
      <div class="activity"><span class="atag">comment</span> by <a href="#/u/${esc(c.author)}">${esc(nameOf(c.author))}</a>
        on <a href="${buildRoute(['r', c.community, 'comments', c.postCid])}">${esc(c.postTitle || 'a post')}</a>
        <div class="md small">${renderMarkdown(excerpt(c.body, 220))}</div></div>`).join('') : '<div class="empty"><p>No matching comments.</p></div>'}</div>`)
  renderSidebar(await sidebarHome(), token)
}

// ---- SETTINGS view ----------------------------------------------------------
function settingsOutboxes (status, me) {
  const fallback = status && status.inviteKey
    ? { appId: status.outboxAppId || (me && me.pubkey) || 'peerit', inviteKey: status.inviteKey }
    : null
  return cleanOutboxes(status && status.outboxes, fallback)
}

function currentSettingsOutbox (status, me) {
  const outboxes = settingsOutboxes(status, me)
  const currentAppId = (status && status.outboxAppId) || (me && me.pubkey)
  return outboxes.find(o => o.appId === currentAppId) || outboxes[0] || null
}

function settingsRecoveryBundle (status, me, createdAt) {
  return buildRecoveryBundle({
    publicKey: me && me.pubkey,
    driveKey: me && me.driveKey,
    outboxes: settingsOutboxes(status, me),
    createdAt
  })
}

function settingsSeederCommand (status, me) {
  return peeritSeederCommand(settingsOutboxes(status, me))
}

function outboxListHtml (outboxes, current) {
  if (outboxes.length < 2) return ''
  return `<details class="outbox-list">
    <summary>${fmtCount(outboxes.length)} known outboxes included in the command and bundle</summary>
    <ul>${outboxes.map(o => `<li><span class="mono small">${esc(shortKey(o.appId, 10))}</span>${current && o.appId === current.appId ? '<b>current</b>' : ''}<code class="mono">${esc(shortKey(o.inviteKey, 10))}</code></li>`).join('')}</ul>
  </details>`
}

async function pearBackupStatus () {
  const pearIdentity = typeof window !== 'undefined' && window.pear && window.pear.identity
  if (!pearIdentity) return { known: false }
  for (const name of ['getBackupStatus', 'backupStatus', 'getRecoveryStatus']) {
    if (typeof pearIdentity[name] !== 'function') continue
    try {
      const r = await pearIdentity[name]()
      const backedUp = !!(r && (r.backedUp || r.phraseBackedUp || r.mnemonicBackedUp || r.status === 'backed-up' || r.status === 'backedUp'))
      return { known: true, backedUp }
    } catch {}
  }
  return { known: false }
}

function backupStatusHtml (backup) {
  // Web/dev identities are browser-local keys, not a PearBrowser phrase — point at
  // the export flow instead of PearBrowser backup instructions.
  if (identity.isDev) {
    return '<button class="btn btn-ghost sm" type="button" data-act="export-identity">Export to back up</button>'
  }
  if (backup && backup.known && backup.backedUp) {
    return '<span class="status-pill good">PearBrowser phrase backed up</span>'
  }
  return '<button class="btn btn-ghost sm" type="button" data-act="pear-backup-help">Open PearBrowser backup instructions</button>'
}

// In web/dev mode the identity is a key held only in THIS browser — there is no
// PearBrowser phrase — so the backup copy must talk about exporting, not a phrase.
const WEB_IDENTITY_COPY = Object.freeze({
  summary: 'This identity lives only in this browser. Export it to move it to another device or keep a backup — peerit has no server that can recover it for you.',
  detail: "Your posting key is stored in this browser's local storage. If you clear site data or lose this device without exporting, the identity is gone for good. Export creates a passphrase-encrypted file you can import on another browser or your phone.",
  ackLabel: 'I understand this identity is stored only in this browser and peerit cannot recover it for me.'
})

function identityBackupSummary () { return identity.isDev ? WEB_IDENTITY_COPY.summary : RECOVERY_COPY.backupSummary }
function identityBackupDetail () { return identity.isDev ? WEB_IDENTITY_COPY.detail : RECOVERY_COPY.identityBackup }

function firstPostBackupWarningHtml () {
  const ack = identity.isDev ? WEB_IDENTITY_COPY.ackLabel : 'I understand that peerit cannot recover my PearBrowser recovery phrase.'
  return `<div class="notice warn identity-backup-warning">
    <b>${esc(identityBackupSummary())}</b>
    <p>${esc(identityBackupDetail())}</p>
    <label class="checkline"><input type="checkbox" name="identity-backup-ack" required> ${esc(ack)}</label>
  </div>`
}

async function hasPostsBy (pub, communities) {
  for (const c of communities || []) {
    const posts = await data.listPostsIn(c.slug).catch(() => [])
    if (posts.some(p => p && p.author === pub)) return true
  }
  return false
}

async function needsFirstPostBackupWarning (communities) {
  if (prefs.identityBackupAcked) return false
  return !(await hasPostsBy(identity.me().pubkey, communities))
}

async function viewSettings ({ guard, token }) {
  const me = identity.me()
  const profile = await data.getProfile(me.pubkey)
  const status = await data.status()
  const outboxes = settingsOutboxes(status, me)
  const currentOutbox = currentSettingsOutbox(status, me)
  const seederCommand = settingsSeederCommand(status, me)
  const hasOutbox = !!(currentOutbox && currentOutbox.inviteKey && seederCommand)
  const modeLabel = isBridgeMode() ? 'PearBrowser P2P bridge' : 'Local dev fallback'
  const backup = await pearBackupStatus()
  if (token !== renderToken) return
  guard(`<div class="panel settings-panel">
    <h1>Settings</h1>
    <h2>Profile</h2>
    <form data-form="profile">
      <label>Display name <input name="name" maxlength="32" value="${esc(profile && profile.name || '')}" placeholder="pick a name"></label>
      <label>Bio <textarea name="bio" rows="3" maxlength="500" placeholder="about you">${esc(profile && profile.bio || '')}</textarea></label>
      <div class="form-actions"><button class="btn btn-primary" type="submit">Save profile</button></div>
    </form>
    <h2>Identity / Recovery</h2>
    <p class="settings-copy"><b>${esc(identityBackupSummary())}</b></p>
    <p class="dim small settings-copy">${esc(identityBackupDetail())}</p>
    <ul class="kv settings-kv">
      <li><span>App identity fingerprint</span><b class="mono small key-inline" title="${esc(me.pubkey)}">${esc(shortKey(me.pubkey, 12))}</b></li>
      <li><span>App drive key fingerprint</span><b class="mono small" title="${esc(me.driveKey)}">${esc(shortKey(me.driveKey, 12))}</b></li>
      <li><span>Backup status</span><b>${backupStatusHtml(backup)}</b></li>
      <li><span>Sync mode</span><b>${modeLabel}</b></li>
    </ul>
    ${identity.isDev ? `<h2>Move this identity to another device</h2>
      <p class="dim small settings-copy">Export your posting key as a <b>passphrase-encrypted</b> file, then import it in another browser or on your phone to post as the same u/${esc(shortKey(me.pubkey, 6))}. Anyone who gets both the file and the passphrase can post as you — treat it like a password.</p>
      <div class="form-actions wrap">
        <button class="btn btn-primary" type="button" data-act="export-identity">Export this identity</button>
      </div>
      <form data-form="import-identity" class="import-identity">
        <h3>Import an identity here</h3>
        <p class="dim small settings-copy">Adds the imported identity alongside any already in this browser and switches to it. Your current identities are kept.</p>
        <label>Passphrase <input type="password" name="passphrase" autocomplete="off" placeholder="the passphrase used at export"></label>
        <label>Identity export (paste, load a file, or scan a QR)
          <textarea class="keybox mono" name="payload" rows="5" spellcheck="false" placeholder='{"type":"peerit-identity-export",...}'></textarea>
        </label>
        <input type="file" accept="application/json,.json" data-file="import-identity" hidden>
        <div class="form-actions wrap">
          <button class="btn btn-ghost" type="button" data-act="pick-identity-file">Load file…</button>
          ${isScanSupported() ? '<button class="btn btn-ghost" type="button" data-act="scan-identity-qr">Scan QR</button>' : ''}
          <button class="btn btn-primary" type="submit">Import identity</button>
        </div>
      </form>` : ''}
    <h2>Outbox seeding</h2>
    <div class="outbox-workflow">
      <p class="dim small settings-copy">Your posts, comments, votes, profile, communities, and mod actions are signed records in your outbox. Signatures prove authorship; seeding improves availability.</p>
      <div class="notice">
        <b>What the Group key does</b>
        <p>Your Group key helps your app data stay discoverable. It is not your identity phrase and does not let anyone sign as you, but it can let another device or seeder replicate your public outbox.</p>
      </div>
      ${hasOutbox ? `
        <label class="key-label">Full outbox/group key
          <textarea class="keybox mono" readonly spellcheck="false" rows="3">${esc(currentOutbox.inviteKey)}</textarea>
          <span class="hint">Treat this as an app data recovery / seeding key. Share it deliberately with an always-on seeder, not as a public profile field.</span>
        </label>
        <div class="form-actions wrap">
          <button class="btn btn-primary" type="button" data-act="copy-outbox-key">Copy Group key</button>
          <button class="btn btn-ghost" type="button" data-act="copy-recovery-bundle">Copy recovery bundle</button>
          <button class="btn btn-ghost" type="button" data-act="export-recovery-bundle">Export bundle</button>
        </div>
        <label class="key-label">peerit-seeder command
          <textarea class="keybox command mono" readonly spellcheck="false" rows="${outboxes.length > 1 ? 4 : 3}">${esc(seederCommand)}</textarea>
          <span class="hint">Run this from a checkout next to peerit, or adjust the directory before running it on an always-on box.</span>
        </label>
        <div class="form-actions wrap">
          <button class="btn btn-primary" type="button" data-act="copy-seeder-command">Copy seeder command</button>
        </div>
        ${outboxListHtml(outboxes, currentOutbox)}
        <ul class="kv settings-kv">
          <li><span>Outboxes in bundle</span><b>${fmtCount(outboxes.length)}</b></li>
          <li><span>Peers discovered</span><b>${fmtCount(status.peers != null ? status.peers : 1)}</b></li>
          <li><span>Records in merged view</span><b>${fmtCount(status.viewLength || 0)}</b></li>
          <li><span>Seeder status</span><b>Not measured in app</b></li>
        </ul>
        <p class="dim small settings-copy">Availability is still conditional: a seeder or relay must hold the bytes and stay reachable. Seeder logs should confirm byte replication because seed accepted is not the same as bytes replicated.</p>
      ` : `
        <div class="empty compact">
          <h3>No seedable outbox here</h3>
          <p>PearBrowser outbox keys are available when peerit is running on the P2P bridge. The local dev fallback is useful for testing, but it does not produce a seeder-ready Group key.</p>
        </div>
      `}
    </div>
    <h2>Import app recovery bundle</h2>
    <form data-form="import-recovery" class="import-recovery">
      <p class="dim small settings-copy">Import compares the bundle drive key and public key with this app before accepting it. Restore your PearBrowser phrase first, then open the same production app drive key.</p>
      <label>Recovery bundle JSON
        <textarea class="keybox mono" name="bundle" rows="8" spellcheck="false" placeholder='{"version":1,"app":"peerit",...}' required></textarea>
      </label>
      <div class="form-actions wrap">
        <button class="btn btn-primary" type="submit">Import bundle</button>
      </div>
    </form>
    ${identity.isDev ? `<h2>Dev tools</h2>
      <p class="dim small">You're running outside PearBrowser. Multiple browser tabs share one world via localStorage + BroadcastChannel, so you can simulate several users.</p>
      <div class="form-actions">
        <button class="btn btn-ghost" data-act="show-welcome">Show starter feed</button>
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
      case 'sub': {
        const slug = normalizeSlug(t.dataset.slug)
        const now = prefs.toggleSub(slug)
        if (now) prefs.markWelcomeSeen()
        toast(now ? 'Joined r/' + slug : 'Left r/' + slug)
        route()
        return
      }
      case 'copylink': return void await copyLink(t.dataset.ref)
      case 'copy-outbox-key': return void await copyOutboxKey()
      case 'copy-seeder-command': return void await copySeederCommand()
      case 'copy-recovery-bundle': return void await copyRecoveryBundle()
      case 'export-recovery-bundle': return void await exportRecoveryBundle()
      case 'export-identity': return void openExportIdentityModal()
      case 'download-identity-file': return void downloadIdentityExport()
      case 'copy-identity-string': return void await copyIdentityExport()
      case 'show-identity-qr': return void showIdentityQr()
      case 'pick-identity-file': return void pickIdentityFile(t)
      case 'scan-identity-qr': return void await openIdentityScanner(t)
      case 'stop-identity-scan': return void stopIdentityScan()
      case 'pear-backup-help': return void showPearBackupInstructions()
      case 'close-modal': return void closeModal()
      case 'collapse': return toggleCollapse(t)
      case 'reply': { openReplies.add(t.dataset.cid); route(); return }
      case 'cancel-reply': { openReplies.delete(t.dataset.cid); route(); return }
      case 'toggle-usermenu': { const d = $('#userdrop'); if (d) { d.hidden = !d.hidden; t.setAttribute('aria-expanded', String(!d.hidden)) } return }
      case 'netstatus': return void updateNetStatus()
      case 'switch-user': { identity.switchUser(t.dataset.pub); data.invalidateViewCaches(); if (sync.announce) sync.announce(); refreshPrefs(); nameCache.clear(); renderUserMenu(); route(); toast('Switched user'); return }
      case 'start-community': return void await startCommunity(t.dataset.slug)
      case 'bridge-proof-write': return void await onBridgeProofWrite(t)
      case 'bridge-proof-copy': return void await onBridgeProofCopy(t)
      case 'bridge-proof-refresh': { if (sync && sync._refresh) await sync._refresh(); route(); return }
      case 'dismiss-welcome': { prefs.markWelcomeSeen(); route(); return }
      case 'show-welcome': { prefs.markWelcomeUnseen(); location.hash = '#/'; route(); return }
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
  if (e.target.matches('input[type="file"][data-file="import-identity"]')) {
    const file = e.target.files && e.target.files[0]
    const form = e.target.closest('form')
    const ta = form && form.querySelector('textarea[name="payload"]')
    e.target.value = '' // allow re-picking the same file
    if (!file || !ta) return
    const reader = new FileReader()
    reader.onload = () => { ta.value = String(reader.result || ''); toast('File loaded — enter your passphrase and Import.') }
    reader.onerror = () => toast('Could not read that file', 'error')
    reader.readAsText(file)
  }
})

// Live passphrase-strength hint on the export modal.
document.addEventListener('input', (e) => {
  if (!e.target.matches('form[data-form="export-identity"] input[name="passphrase"]')) return
  const hint = e.target.closest('form').querySelector('[data-role="pw-hint"]')
  if (hint) { const v = e.target.value; hint.textContent = v ? 'Strength: ' + passphraseStrength(v).label : '' }
})

async function onVote (t) {
  if (isReadOnly()) { toast('Read-only here — open peerit in PearBrowser to vote.', 'error'); return }
  const box = t.closest('.votes')
  const cid = box.dataset.cid
  const community = box.dataset.community
  const type = box.dataset.type
  const dir = Number(t.dataset.dir)
  const up = box.querySelector('.arrow.up')
  const down = box.querySelector('.arrow.down')
  const scoreEl = box.querySelector('.score')
  const cur = Number(box.dataset.myvote) || 0
  const next = cur === dir ? 0 : dir
  const base = parseScore(scoreEl.textContent) - cur
  const paint = (v) => {
    scoreEl.textContent = fmtCount(base + v)
    up.classList.toggle('on', v === 1)
    down.classList.toggle('on', v === -1)
    scoreEl.classList.toggle('pos', v === 1)
    scoreEl.classList.toggle('neg', v === -1)
    box.dataset.myvote = v
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

const cssEscape = (s) => (typeof CSS !== 'undefined' && CSS.escape) ? CSS.escape(String(s)) : String(s).replace(/["\\]/g, '\\$&')

function repaintVotes (box, t) {
  const score = box.querySelector('.score')
  const up = box.querySelector('.arrow.up')
  const down = box.querySelector('.arrow.down')
  if (score) { score.textContent = fmtCount(t.score); score.classList.toggle('pos', t.myVote === 1); score.classList.toggle('neg', t.myVote === -1) }
  if (up) up.classList.toggle('on', t.myVote === 1)
  if (down) down.classList.toggle('on', t.myVote === -1)
  box.dataset.myvote = t.myVote || 0
}

// Try to satisfy a live update by repainting vote widgets in place. Returns true
// only if EVERY changed key was a vote (so no structural re-render is needed);
// any post/comment/community/mod/profile change returns false → full route().
// Off-screen targets are simply skipped — their data is already in the store.
async function patchVotesInPlace (keys) {
  const cids = new Set()
  for (const k of keys) {
    if (k.startsWith('vote!')) {
      // vote!<targetCid>!<author> — the author (pubkey) is the '!'-free LAST
      // segment, so strip from the last '!' to recover the full targetCid
      // (robust even if a targetCid ever contains '!').
      const rest = k.slice(5)
      const i = rest.lastIndexOf('!')
      cids.add(i >= 0 ? rest.slice(0, i) : rest)
    } else {
      return false                        // a structural change — let route() handle it
    }
  }
  // NB: vote patches intentionally do NOT re-sort the feed — a remote vote
  // nudging a score won't reshuffle posts under the reader (Reddit behaves the
  // same). The next navigation re-ranks via sortPosts.
  for (const cid of cids) {
    const boxes = document.querySelectorAll('.votes[data-cid="' + cssEscape(cid) + '"]')
    if (!boxes.length) continue           // not on screen; nothing to paint
    const t = await data.tallyFor(cid)
    for (const box of boxes) repaintVotes(box, t)
  }
  return true
}

function toggleCollapse (btn) {
  const node = document.getElementById(btn.dataset.target)
  if (!node) return
  const cid = btn.dataset.target.slice(2) // strip the 'c_' prefix of collapsedId
  const collapsed = node.classList.toggle('collapsed')
  if (collapsed) {
    collapsedComments.add(cid)
    if (collapsedComments.size > 5000) collapsedComments.delete(collapsedComments.values().next().value) // bound memory (FIFO)
  } else collapsedComments.delete(cid)
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
  // If the body is a boxed blob no relay is currently serving, refuse the edit —
  // otherwise the prompt seeds an empty body and saving would drop the manifest.
  if (rec && rec._blobMissing) { toast('This post’s content is still syncing — try again in a moment.', 'error'); return }
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
  const rec = await data.getComment(community, postCid, cid) // hydrated so a boxed body isn't seeded empty
  if (rec && rec._blobMissing) { toast('This comment’s content is still syncing — try again in a moment.', 'error'); return }
  const next = prompt('Edit comment:', (rec && rec.body) || '')
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
  // Read-only web mode: search + local identity management still work; everything
  // else is a network write and stays blocked.
  const localOnlyForms = new Set(['search', 'import-identity', 'export-identity'])
  if (!localOnlyForms.has(f) && isReadOnly()) { toast('peerit is read-only here — open it in PearBrowser to post, comment, or vote.', 'error'); return }
  if (form.dataset.busy) return // block double-submit while the write is in flight
  const btn = form.querySelector('button[type="submit"]')
  if (f !== 'search') {
    form.dataset.busy = '1'
    if (btn) { btn.dataset.label = btn.textContent; btn.disabled = true; btn.textContent = '…' }
  }
  // Proof-of-work (community/post/comment) can run hundreds of thousands of
  // hashes; surface progress on the submit button so it doesn't look frozen.
  const onProgress = btn ? (nonce) => { btn.textContent = '… ' + nonce.toLocaleString() } : undefined
  try {
    if (f === 'search') { const q = (fd.get('q') || '').trim(); if (q) location.hash = buildRoute(['search'], { q }); return }
    if (f === 'create-community') {
      const c = await data.createCommunity({ slug: fd.get('slug'), title: fd.get('title'), description: fd.get('description'), onProgress })
      prefs.subscribe(c.slug)
      prefs.markWelcomeSeen()
      toast('Created r/' + c.slug)
      location.hash = '#/r/' + c.slug
      return
    }
    if (f === 'submit-post') {
      if (await needsFirstPostBackupWarning(await data.listCommunities())) {
        if (fd.get('identity-backup-ack') !== 'on') throw new Error('Please acknowledge the PearBrowser identity backup warning before posting.')
        prefs.acknowledgeIdentityBackup()
      }
      const p = await data.submitPost({
        community: fd.get('community'), kind: fd.get('kind'),
        title: fd.get('title'), body: fd.get('body'), url: fd.get('url'), onProgress
      })
      prefs.markWelcomeSeen()
      toast('Posted')
      location.hash = buildRoute(['r', p.community, 'comments', p.cid])
      return
    }
    if (f === 'comment') {
      const body = fd.get('body')
      const parent = form.dataset.parent || null
      await data.addComment({ community: form.dataset.community, postCid: form.dataset.post, parentCid: parent, body, onProgress })
      if (parent) openReplies.delete(parent)
      prefs.markWelcomeSeen()
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
    if (f === 'import-recovery') {
      const result = await data.importRecoveryBundle(String(fd.get('bundle') || ''))
      if (result.failures && result.failures.length) {
        toast(`Recovery bundle accepted, but ${result.failures.length} outbox${result.failures.length === 1 ? '' : 'es'} failed to join`, 'error')
      } else if (result.imported) {
        toast('Recovery bundle imported: identity restored, outboxes joined, records visible.')
      } else {
        toast('Recovery bundle imported: identity restored, no outboxes were included.')
      }
      route()
      return
    }
    if (f === 'export-identity') {
      await runIdentityExport(String(fd.get('passphrase') || ''), String(fd.get('confirm') || ''))
      return
    }
    if (f === 'import-identity') {
      await importIdentityFromForm(String(fd.get('payload') || ''), String(fd.get('passphrase') || ''))
      form.reset()
      return
    }
    if (f === 'dev-user') {
      await createDevUser(String(fd.get('name') || '').trim())
      return
    }
  } catch (err) { toast(err.message || String(err), 'error') }
  finally {
    delete form.dataset.busy
    if (btn && document.contains(btn)) { btn.disabled = false; btn.textContent = btn.dataset.label || btn.textContent }
  }
}

// ---- dev helpers ------------------------------------------------------------
async function createDevUser (name) {
  if (!name) return
  await identity.createUser(name)
  data.invalidateViewCaches()
  if (sync.announce) await sync.announce()
  refreshPrefs(); nameCache.clear()
  await renderUserMenu(); route(); toast('Created & switched to ' + name)
}

async function startCommunity (slug) {
  const starter = starterCommunity(slug)
  if (!starter) throw new Error('Unknown starter community')
  let community = await data.getCommunity(starter.slug)
  if (!community) {
    try {
      community = await data.createCommunity({
        slug: starter.slug,
        title: starter.title,
        description: starter.description,
        rules: starter.rules
      })
      toast('Created r/' + starter.slug)
    } catch (err) {
      community = await data.getCommunity(starter.slug)
      if (!community) throw err
      toast('Joined r/' + starter.slug)
    }
  } else {
    toast('Joined r/' + starter.slug)
  }
  prefs.subscribe(starter.slug)
  prefs.markWelcomeSeen()
  location.hash = '#/r/' + starter.slug
  route()
}

async function onBridgeProofWrite (btn) {
  if (isReadOnly()) throw new Error('Bridge proof cannot write in read-only mode.')
  const role = bridgeProofRole(btn.dataset.role)
  const session = bridgeProofSession(btn.dataset.session)
  const onProgress = (nonce) => { btn.textContent = '... ' + nonce.toLocaleString() }
  btn.disabled = true
  const label = btn.textContent
  try {
    await runBridgeProofAction(session, role, onProgress)
    toast(role === 'a' ? 'Device A proof record written.' : 'Device B proof record written.')
    route()
  } finally {
    btn.disabled = false
    btn.textContent = label
  }
}

async function onBridgeProofCopy (btn) {
  if (sync && sync._refresh) {
    try { await sync._refresh() } catch {}
  }
  const snapshot = await buildBridgeProofSnapshot(btn.dataset.session, btn.dataset.role)
  await copyText(JSON.stringify(snapshot), 'Bridge proof copied.')
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
function showPearBackupInstructions () {
  const root = $('#modal-root')
  const body = `${RECOVERY_COPY.identityBackup}\n\nOpen PearBrowser settings and back up your 12-word recovery phrase before relying on this app identity. peerit will never ask you to paste that phrase here.`
  if (!root) { alert(body); return }
  root.innerHTML = `<div class="modal-backdrop">
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="backup-title">
      <h2 id="backup-title">PearBrowser backup</h2>
      <p>${esc(RECOVERY_COPY.identityBackup)}</p>
      <p class="dim small">Open PearBrowser settings and back up your 12-word recovery phrase before relying on this app identity. peerit will never ask you to paste that phrase here.</p>
      <div class="form-actions"><button class="btn btn-primary" type="button" data-act="close-modal">Done</button></div>
    </div>
  </div>`
}

// ---- web identity export / import -------------------------------------------
let _identityExport = null // { envelope, json, filename } for the open export modal
let _identityScanStop = null

function openExportIdentityModal () {
  const root = $('#modal-root'); if (!root) { toast('Export needs the in-app modal', 'error'); return }
  const me = identity.me()
  _identityExport = null
  root.innerHTML = `<div class="modal-backdrop">
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="idexport-title">
      <h2 id="idexport-title">Export identity</h2>
      <p class="dim small">Encrypts u/${esc(shortKey(me.pubkey, 8))} under a passphrase. You'll need the SAME passphrase to import it on the other device — peerit can't reset it.</p>
      <form data-form="export-identity">
        <label>Passphrase <input type="password" name="passphrase" autocomplete="new-password" minlength="${MIN_PASSPHRASE}" required placeholder="at least ${MIN_PASSPHRASE} characters"></label>
        <label>Confirm passphrase <input type="password" name="confirm" autocomplete="new-password" required></label>
        <p class="dim small" data-role="pw-hint"></p>
        <div class="form-actions wrap">
          <button class="btn btn-primary" type="submit">Encrypt &amp; continue</button>
          <button class="btn btn-ghost" type="button" data-act="close-modal">Cancel</button>
        </div>
      </form>
    </div>
  </div>`
}

async function runIdentityExport (passphrase, confirm) {
  if (passphrase !== confirm) throw new Error('The two passphrases do not match.')
  const entry = identity.currentSeedEntry && identity.currentSeedEntry()
  if (!entry) throw new Error('No exportable identity in this browser.')
  const envelope = await exportIdentity(entry, passphrase)
  const json = identityExportJson(envelope)
  _identityExport = { envelope, json, filename: identityExportFilename(envelope.pubkey, envelope.createdAt) }
  renderIdentityExportResult()
}

function renderIdentityExportResult () {
  const root = $('#modal-root'); if (!root || !_identityExport) return
  const me = identity.me()
  root.innerHTML = `<div class="modal-backdrop">
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="idexport-title">
      <h2 id="idexport-title">Identity encrypted ✓</h2>
      <p class="dim small">Encrypted export for u/${esc(shortKey(me.pubkey, 8))}. Move it to your other device, then use <b>Import an identity here</b> with the same passphrase.</p>
      <div class="form-actions wrap">
        <button class="btn btn-primary" type="button" data-act="download-identity-file">Download file</button>
        <button class="btn btn-ghost" type="button" data-act="copy-identity-string">Copy text</button>
        <button class="btn btn-ghost" type="button" data-act="show-identity-qr">Show QR</button>
      </div>
      <div class="qr-holder" data-role="qr-holder"></div>
      <div class="form-actions"><button class="btn btn-ghost" type="button" data-act="close-modal">Done</button></div>
    </div>
  </div>`
}

function downloadIdentityExport () {
  if (!_identityExport) return
  downloadText(_identityExport.filename, _identityExport.json, 'application/json')
  toast('Identity file downloaded — keep it and the passphrase safe.')
}

async function copyIdentityExport () {
  if (!_identityExport) return
  await copyText(_identityExport.json, 'Encrypted identity copied to clipboard.')
}

function showIdentityQr () {
  const holder = document.querySelector('[data-role="qr-holder"]')
  if (!holder || !_identityExport) return
  try {
    const qr = encodeQR(_identityExport.json)
    holder.innerHTML = `<div class="qr-code">${qrToSvg(qr, { border: 4 })}</div><p class="dim small">Scan this from the Import screen on your other device.</p>`
  } catch (err) {
    holder.innerHTML = `<p class="dim small">${esc(err.message || 'Could not render a QR')} — use Download or Copy instead.</p>`
  }
}

function pickIdentityFile (btn) {
  const form = btn.closest('form')
  const input = form && form.querySelector('input[type="file"][data-file="import-identity"]')
  if (input) input.click()
}

async function openIdentityScanner (btn) {
  const form = btn.closest('form')
  const root = $('#modal-root'); if (!root) return
  root.innerHTML = `<div class="modal-backdrop">
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="idscan-title">
      <h2 id="idscan-title">Scan identity QR</h2>
      <p class="dim small">Point the camera at the QR shown on your other device.</p>
      <video data-role="scan-video" playsinline muted class="scan-video"></video>
      <div class="form-actions"><button class="btn btn-ghost" type="button" data-act="stop-identity-scan">Cancel</button></div>
    </div>
  </div>`
  const video = root.querySelector('[data-role="scan-video"]')
  try {
    _identityScanStop = await scanQR(video, (text) => {
      const isExport = looksLikeIdentityExport(text)
      stopIdentityScan()
      const ta = form && form.querySelector('textarea[name="payload"]')
      if (ta && isExport) ta.value = text
      toast(isExport ? 'QR scanned — enter your passphrase and Import.' : 'Scanned a QR, but it is not a peerit identity export.', isExport ? 'ok' : 'error')
    })
  } catch (err) {
    stopIdentityScan()
    toast(err.message || 'Camera unavailable', 'error')
  }
}

function stopIdentityScan () {
  if (_identityScanStop) { try { _identityScanStop() } catch {} _identityScanStop = null }
  closeModal()
}

async function importIdentityFromForm (payload, passphrase) {
  if (!looksLikeIdentityExport(payload)) throw new Error('That does not look like a peerit identity export — paste the exported JSON, load the file, or scan the QR.')
  const entry = await importIdentity(payload, passphrase)
  await identity.addUser(entry)
  // Mirror the switch-user side effects so the whole UI reflects the new identity.
  data.invalidateViewCaches()
  if (sync.announce) await sync.announce()
  refreshPrefs(); nameCache.clear()
  await renderUserMenu(); route()
  toast('Identity imported — now posting as u/' + shortKey(entry.pubkey, 6))
}

function closeModal () {
  const root = $('#modal-root')
  if (root) root.innerHTML = ''
}

async function currentRecoveryExport () {
  const me = identity.me()
  const status = await data.status()
  const outboxes = settingsOutboxes(status, me)
  if (!outboxes.length) throw new Error('No seedable outbox here')
  const bundle = settingsRecoveryBundle(status, me, new Date())
  return {
    me,
    status,
    outboxes,
    currentOutbox: currentSettingsOutbox(status, me),
    command: settingsSeederCommand(status, me),
    bundle,
    json: recoveryBundleJson(bundle)
  }
}

async function copyText (text, message) {
  if (!text) throw new Error('Nothing to copy')
  if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(text)
  } else {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.left = '-9999px'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand && document.execCommand('copy')
    ta.remove()
    if (!ok) throw new Error('Copy failed')
  }
  toast(message)
}

function downloadText (filename, text, type) {
  if (typeof Blob === 'undefined' || typeof URL === 'undefined' || !URL.createObjectURL) throw new Error('Download is not available here')
  const blob = new Blob([text], { type: type || 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

async function copyOutboxKey () {
  const snapshot = await currentRecoveryExport()
  if (!snapshot.currentOutbox || !snapshot.currentOutbox.inviteKey) throw new Error('No Group key available')
  await copyText(snapshot.currentOutbox.inviteKey, 'Group key copied')
}

async function copySeederCommand () {
  const snapshot = await currentRecoveryExport()
  await copyText(snapshot.command, 'Seeder command copied')
}

async function copyRecoveryBundle () {
  const snapshot = await currentRecoveryExport()
  await copyText(snapshot.json, 'Recovery bundle copied')
}

async function exportRecoveryBundle () {
  const snapshot = await currentRecoveryExport()
  downloadText(recoveryBundleFilename(snapshot.bundle), snapshot.json, 'application/json;charset=utf-8')
  toast('Recovery bundle exported')
}

async function copyLink (ref) {
  const [c, cid] = ref.split('/')
  const url = location.origin + location.pathname + buildRoute(['r', c, 'comments', cid])
  try { await copyText(url, 'Link copied') }
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
if (typeof window !== 'undefined') {
  window.__peerit = {
    get data () { return data },
    get sync () { return sync },
    route,
    bridgeProofSnapshot: buildBridgeProofSnapshot,
    runBridgeProof: runBridgeProofAction
  }
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot)
  else boot()
}

export { boot }
