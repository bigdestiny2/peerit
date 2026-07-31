// publication-status.js — pure UI projection for the four independent Peerit
// publication axes. Relay/durability/discovery problems never disable a composer;
// only a local cryptographic or durable-journal failure may do that.

function publication (status) {
  return status && status.publication && typeof status.publication === 'object'
    ? status.publication
    : null
}

export function isPeeritSubstrateStatus (status) {
  return !!(status && status.mode === 'peerit-substrate' && publication(status))
}

export function publicationUiState (status) {
  const value = publication(status)
  // Missing status is not proof that the durable local journal is healthy. Fail
  // only this axis closed; relay/durability/discovery remain descriptive.
  const local = (value && value.local) || { state: 'blocked', visibleRecords: 0 }
  const relay = (value && value.relay) || { state: 'idle', acknowledgedTargets: 0, pendingIntents: 0, usableTargets: 0 }
  const durability = (value && value.durability) || { state: 'local-only' }
  const discovery = (value && value.discovery) || { state: 'idle' }
  const authoringReady = local.state === 'ready'

  let copy = 'Lurker mode is active. An identity is created only after you submit; signed publications commit locally before networking.'
  if (!authoringReady) {
    copy = 'Local authoring is blocked because Peerit cannot safely protect or journal the signed event on this device.'
  } else if (relay.state === 'queued-no-relay') {
    copy = 'Saved locally and queued. No compatible relay is reachable yet; you can keep using Peerit while delivery retries later.'
  } else if (relay.state === 'pending-unknown') {
    copy = 'Saved locally. A relay outcome is unknown, so Peerit is reconciling the exact request without creating another event.'
  } else if (relay.state === 'target-rejected') {
    copy = 'Saved locally. The selected relay returned a terminal rejection; Peerit will keep the event and may use another compatible target.'
  } else if (relay.state === 'repair-needed') {
    copy = 'Saved locally. A historical relay receipt no longer proves current retrieval; Peerit has marked this replica for safe repair without blindly resending it.'
  } else if (relay.state === 'target-budget-exhausted') {
    copy = 'Saved locally. This event retained its full bounded relay audit history, so Peerit will not silently delete receipts or backfill it to another rotating target.'
  } else if (relay.state === 'historically-acknowledged') {
    copy = 'Saved locally. Peerit retains a historical relay receipt, but no currently qualified relay proves that copy is still available.'
  } else if (relay.state === 'revalidation-pending') {
    copy = 'Saved locally. Peerit has a historical relay receipt and is waiting for a fresh authenticated retrieval check.'
  } else if (relay.state === 'delivering' || relay.state === 'queued') {
    copy = 'Saved locally. Relay delivery is in progress; durability and discovery update independently.'
  } else if (relay.state === 'relay-acknowledged') {
    const count = Number(relay.activeAcknowledgedTargets) || 1
    copy = `Saved locally; ${count} compatible relay${count === 1 ? '' : 's'} acknowledged storage. Durability and discovery remain separate claims.`
  }

  return Object.freeze({
    authoringReady,
    tone: authoringReady && ![
      'pending-unknown',
      'repair-needed',
      'target-budget-exhausted',
      'historically-acknowledged',
      'revalidation-pending'
    ].includes(relay.state)
      ? 'normal'
      : 'warn',
    copy,
    localState: local.state,
    relayState: relay.state,
    durabilityState: durability.state,
    discoveryState: discovery.state
  })
}

export function publicationModeLabel (status) {
  const ui = publicationUiState(status)
  return `Blind substrate · local ${ui.localState} · relay ${ui.relayState} · durability ${ui.durabilityState} · discovery ${ui.discoveryState}`
}

export function publicationNetSegments (status) {
  const ui = publicationUiState(status)
  return Object.freeze([
    `local ${ui.localState}`,
    `relay ${ui.relayState}`,
    `durability ${ui.durabilityState}`,
    `discovery ${ui.discoveryState}`
  ])
}
