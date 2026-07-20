// prefs.js — per-device, per-user local state that does NOT belong in the shared
// P2P log: which communities you've subscribed to, saved/hidden posts, and your
// sort preferences. Keyed by the active identity pubkey so simulated dev users
// keep separate prefs. Stored in localStorage.

import { isValidSlug, normalizeSlug } from './util.js'

const DEFAULTS = Object.freeze({
  subs: [],
  saved: [],
  hidden: [],
  follows: [], // author pubkeys the user follows (local; powers the Following feed + notify feed-head watches)
  sort: 'hot',
  moderationView: 'community',
  theme: 'dark',
  seenWelcome: false,
  identityBackupAcked: false,
  notifSeen: 0 // ms timestamp of the newest notification the user has seen (device-local read marker)
})
const SORTS = new Set(['hot', 'new', 'top', 'rising', 'controversial'])
const MODERATION_VIEWS = new Set(['community', 'consensus', 'open'])

export class Prefs {
  constructor (storage, pubkey) {
    this.storage = storage || (typeof localStorage !== 'undefined' ? localStorage : memShim())
    this.pub = pubkey || 'anon'
    this.key = 'peerit:prefs:' + this.pub
    this.data = this._load()
  }

  _load () {
    try {
      const s = this.storage.getItem(this.key)
      const d = s ? JSON.parse(s) : {}
      return cleanPrefs(Object.assign({}, DEFAULTS, d))
    } catch {
      return cleanPrefs(DEFAULTS)
    }
  }

  _save () { this.storage.setItem(this.key, JSON.stringify(this.data)) }

  // Subscriptions
  isSubscribed (slug) { slug = cleanSlug(slug); return !!(slug && this.data.subs.includes(slug)) }
  subscribe (slug) {
    slug = cleanSlug(slug)
    if (!slug) return false
    if (!this.data.subs.includes(slug)) { this.data.subs.push(slug); this._save() }
    return true
  }
  unsubscribe (slug) {
    slug = cleanSlug(slug)
    if (!slug) return false
    const next = this.data.subs.filter(s => s !== slug)
    if (next.length !== this.data.subs.length) { this.data.subs = next; this._save() }
    return false
  }
  toggleSub (slug) { this.isSubscribed(slug) ? this.unsubscribe(slug) : this.subscribe(slug); return this.isSubscribed(slug) }
  subs () { return this.data.subs.slice() }

  // Saved posts (store "community/cid")
  isSaved (ref) { ref = cleanRef(ref); return !!(ref && this.data.saved.includes(ref)) }
  toggleSaved (ref) {
    ref = cleanRef(ref)
    if (!ref) return false
    if (this.isSaved(ref)) this.data.saved = this.data.saved.filter(r => r !== ref)
    else this.data.saved.unshift(ref)
    this._save(); return this.isSaved(ref)
  }
  saved () { return this.data.saved.slice() }

  // Hidden posts
  isHidden (ref) { ref = cleanRef(ref); return !!(ref && this.data.hidden.includes(ref)) }
  toggleHidden (ref) {
    ref = cleanRef(ref)
    if (!ref) return false
    if (this.isHidden(ref)) this.data.hidden = this.data.hidden.filter(r => r !== ref)
    else this.data.hidden.unshift(ref)
    this._save(); return this.isHidden(ref)
  }
  hidden () { return this.data.hidden.slice() }

  // Follows (author pubkeys). Local + private — a signed public follow list would
  // leak the social graph; kept in localStorage like subs/saved. This is the source
  // set for the Following feed and for notify feed-head watches (js/notify.js).
  isFollowing (pub) { pub = cleanPub(pub); return !!(pub && this.data.follows.includes(pub)) }
  follow (pub) {
    pub = cleanPub(pub)
    if (!pub) return false
    if (!this.data.follows.includes(pub)) { this.data.follows.unshift(pub); this._save() }
    return true
  }
  unfollow (pub) {
    pub = cleanPub(pub)
    if (!pub) return false
    const next = this.data.follows.filter(p => p !== pub)
    if (next.length !== this.data.follows.length) { this.data.follows = next; this._save() }
    return false
  }
  toggleFollow (pub) { this.isFollowing(pub) ? this.unfollow(pub) : this.follow(pub); return this.isFollowing(pub) }
  follows () { return this.data.follows.slice() }

  // Misc prefs
  setSort (s) { this.data.sort = cleanSort(s); this._save(); return this.data.sort }
  get sort () { return this.data.sort }
  setModerationView (view) { this.data.moderationView = cleanModerationView(view); this._save(); return this.data.moderationView }
  get moderationView () { return this.data.moderationView }
  setWelcomeSeen (seen = true) { this.data.seenWelcome = !!seen; this._save() }
  markWelcomeSeen () { this.setWelcomeSeen(true) }
  markWelcomeUnseen () { this.setWelcomeSeen(false) }
  get seenWelcome () { return this.data.seenWelcome }
  acknowledgeIdentityBackup () { this.data.identityBackupAcked = true; this._save() }
  get identityBackupAcked () { return !!this.data.identityBackupAcked }

  // Inbox read-marker: the newest notification ts the user has seen. Device-local
  // by design — "read" state is personal UI, not shared network data.
  get notifSeen () { return this.data.notifSeen || 0 }
  markNotifsSeen (ts) { const t = Number(ts) || Date.now(); if (t > this.data.notifSeen) { this.data.notifSeen = t; this._save() } }
}

function cleanPrefs (d) {
  return {
    subs: cleanList(d.subs, cleanSlug),
    saved: cleanList(d.saved, cleanRef),
    hidden: cleanList(d.hidden, cleanRef),
    follows: cleanList(d.follows, cleanPub),
    sort: cleanSort(d.sort),
    moderationView: cleanModerationView(d.moderationView),
    theme: d.theme === 'light' ? 'light' : 'dark',
    seenWelcome: !!d.seenWelcome,
    identityBackupAcked: !!d.identityBackupAcked,
    notifSeen: Number(d.notifSeen) || 0
  }
}

function cleanList (items, clean) {
  const out = []
  const seen = new Set()
  if (!Array.isArray(items)) return out
  for (const item of items) {
    const v = clean(item)
    if (!v || seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}

function cleanSlug (slug) {
  const s = normalizeSlug(slug)
  return isValidSlug(s) ? s : ''
}

function cleanPub (pub) {
  const p = String(pub || '').trim().toLowerCase()
  return /^[0-9a-f]{64}$/.test(p) ? p : ''
}

function cleanRef (ref) {
  const [community, cid, ...rest] = String(ref || '').split('/')
  if (rest.length || !cid) return ''
  const slug = cleanSlug(community)
  const id = String(cid || '').trim()
  return slug && id ? slug + '/' + id : ''
}

function cleanSort (sort) {
  sort = String(sort || '').toLowerCase()
  return SORTS.has(sort) ? sort : DEFAULTS.sort
}

function cleanModerationView (view) {
  view = String(view || '').toLowerCase()
  return MODERATION_VIEWS.has(view) ? view : DEFAULTS.moderationView
}

function memShim () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }
}
