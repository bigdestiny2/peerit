// Draft-safe structural refresh scheduling. A successful pending-publication
// recovery emits a normal structural onChange event, but must not let that event
// replace the still-unsubmitted composer that launched recovery.

function controlKey (control) {
  if (!control || !control.name) return null
  const tag = String(control.tagName || '').toUpperCase()
  const type = String(control.type || '').toLowerCase()
  if (type === 'file' || type === 'button' || type === 'submit' || type === 'reset' || type === 'image') return null
  return `${String(control.name)}\u0000${tag}\u0000${type}`
}

export function snapshotComposerDraft (form) {
  if (!form || !form.elements) return null
  const ordinals = new Map()
  const fields = []
  for (const control of Array.from(form.elements)) {
    const key = controlKey(control)
    if (!key) continue
    const ordinal = ordinals.get(key) || 0
    ordinals.set(key, ordinal + 1)
    const state = { key, ordinal, value: String(control.value == null ? '' : control.value) }
    if (control.type === 'checkbox' || control.type === 'radio') state.checked = !!control.checked
    if (control.multiple && control.options) {
      state.selected = Array.from(control.options).filter(option => option.selected).map(option => String(option.value))
    }
    fields.push(state)
  }
  return { fields }
}

export function restoreComposerDraft (form, snapshot) {
  if (!form || !form.elements || !snapshot || !Array.isArray(snapshot.fields)) return false
  const controls = new Map()
  for (const control of Array.from(form.elements)) {
    const key = controlKey(control)
    if (!key) continue
    if (!controls.has(key)) controls.set(key, [])
    controls.get(key).push(control)
  }
  for (const state of snapshot.fields) {
    const control = controls.get(state.key) && controls.get(state.key)[state.ordinal]
    if (!control) continue
    if (Array.isArray(state.selected) && control.options) {
      const selected = new Set(state.selected)
      for (const option of Array.from(control.options)) option.selected = selected.has(String(option.value))
    } else {
      control.value = state.value
    }
    if (Object.prototype.hasOwnProperty.call(state, 'checked')) control.checked = state.checked
  }
  return true
}

export function createLiveRefreshController ({ document, route, patchVotesInPlace, integrityStatusKey = null, delay = 350 } = {}) {
  let pendingKeys = null
  let pendingFull = false
  let timer = null
  let deferredRetry = null
  let heldDraft = null

  const hasPending = () => pendingFull || !!(pendingKeys && pendingKeys.size)
  const formConnected = (form) => {
    if (!form) return false
    if (typeof form.isConnected === 'boolean') return form.isConnected
    return !document || typeof document.contains !== 'function' || document.contains(form)
  }
  const ownsDraft = () => {
    if (!heldDraft) return false
    if (formConnected(heldDraft.form)) return true
    heldDraft = null
    return false
  }
  const clearDeferred = () => {
    if (!deferredRetry || !document) return
    document.removeEventListener('focusout', deferredRetry, true)
    document.removeEventListener('visibilitychange', deferredRetry)
    deferredRetry = null
  }
  const schedule = () => {
    if (timer != null) clearTimeout(timer)
    timer = setTimeout(() => {
      timer = null
      flush().catch(error => console.warn('[peerit live refresh]', error && error.message))
    }, delay)
  }
  const armDeferred = () => {
    if (deferredRetry || !document) return
    deferredRetry = () => {
      clearDeferred()
      schedule()
    }
    document.addEventListener('focusout', deferredRetry, true)
    document.addEventListener('visibilitychange', deferredRetry)
  }
  const flush = async () => {
    if (!hasPending()) return 'idle'
    // Recovery owns this exact form until the user navigates/submits it. Keep the
    // accumulated structural change pending; releaseDraft() schedules it again.
    if (ownsDraft()) return 'held'
    const active = document && document.activeElement
    const focusIsActive = !document || typeof document.hasFocus !== 'function' || document.hasFocus()
    const formControlActive = active && (/^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName) || active.isContentEditable || (active.tagName === 'BUTTON' && active.closest && active.closest('form[data-form]')))
    if (focusIsActive && formControlActive) { armDeferred(); return 'focused' }
    const full = pendingFull
    const keys = pendingKeys
    pendingFull = false
    pendingKeys = null
    if (!full && keys && typeof patchVotesInPlace === 'function' && await patchVotesInPlace(keys)) return 'patched'
    if (typeof route === 'function') route()
    return 'routed'
  }
  const onChange = (changed) => {
    if (Array.isArray(changed) && integrityStatusKey != null) changed = changed.filter(key => key !== integrityStatusKey)
    if (Array.isArray(changed) && changed.length === 0) return
    if (!changed) pendingFull = true
    else {
      if (!pendingKeys) pendingKeys = new Set()
      for (const key of changed) pendingKeys.add(key)
    }
    schedule()
  }
  const holdDraft = (form) => {
    const token = Object.freeze({})
    heldDraft = { form, token }
    return token
  }
  const releaseDraft = (token = null, { schedulePending = true, discardPending = false } = {}) => {
    if (!heldDraft || (token && heldDraft.token !== token)) return false
    heldDraft = null
    clearDeferred()
    if (discardPending) {
      pendingFull = false
      pendingKeys = null
      if (timer != null) clearTimeout(timer)
      timer = null
    }
    if (schedulePending && hasPending()) schedule()
    return true
  }
  const destroy = () => {
    if (timer != null) clearTimeout(timer)
    timer = null
    clearDeferred()
    heldDraft = null
  }

  return { onChange, flush, holdDraft, releaseDraft, ownsDraft, destroy }
}
