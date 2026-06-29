// prefs.js — per-device, per-user local state that does NOT belong in the shared
// P2P log: which communities you've subscribed to, saved/hidden posts, and your
// sort preferences. Keyed by the active identity pubkey so simulated dev users
// keep separate prefs. Stored in localStorage.

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
      return Object.assign({ subs: [], saved: [], hidden: [], sort: 'hot', theme: 'dark', seenWelcome: false, identityBackupAcked: false }, d)
    } catch {
      return { subs: [], saved: [], hidden: [], sort: 'hot', theme: 'dark', seenWelcome: false, identityBackupAcked: false }
    }
  }

  _save () { this.storage.setItem(this.key, JSON.stringify(this.data)) }

  // Subscriptions
  isSubscribed (slug) { return this.data.subs.includes(slug) }
  subscribe (slug) { if (!this.data.subs.includes(slug)) { this.data.subs.push(slug); this._save() } }
  unsubscribe (slug) { this.data.subs = this.data.subs.filter(s => s !== slug); this._save() }
  toggleSub (slug) { this.isSubscribed(slug) ? this.unsubscribe(slug) : this.subscribe(slug); return this.isSubscribed(slug) }
  subs () { return this.data.subs.slice() }

  // Saved posts (store "community/cid")
  isSaved (ref) { return this.data.saved.includes(ref) }
  toggleSaved (ref) {
    if (this.isSaved(ref)) this.data.saved = this.data.saved.filter(r => r !== ref)
    else this.data.saved.unshift(ref)
    this._save(); return this.isSaved(ref)
  }
  saved () { return this.data.saved.slice() }

  // Hidden posts
  isHidden (ref) { return this.data.hidden.includes(ref) }
  toggleHidden (ref) {
    if (this.isHidden(ref)) this.data.hidden = this.data.hidden.filter(r => r !== ref)
    else this.data.hidden.unshift(ref)
    this._save(); return this.isHidden(ref)
  }
  hidden () { return this.data.hidden.slice() }

  // Misc prefs
  setSort (s) { this.data.sort = s; this._save() }
  get sort () { return this.data.sort }
  setWelcomeSeen (seen = true) { this.data.seenWelcome = !!seen; this._save() }
  markWelcomeSeen () { this.setWelcomeSeen(true) }
  markWelcomeUnseen () { this.setWelcomeSeen(false) }
  get seenWelcome () { return this.data.seenWelcome }
  acknowledgeIdentityBackup () { this.data.identityBackupAcked = true; this._save() }
  get identityBackupAcked () { return !!this.data.identityBackupAcked }
}

function memShim () {
  const m = new Map()
  return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }
}
