// Release-update UI policy. A cached, previously verified page can briefly see
// a newer signed manifest while its service worker stages that newer bundle.
// That is an expected handover, not an integrity failure. Keep this classifier
// pure so the UI cannot accidentally suppress a genuine first-visit/deploy
// mismatch or rollback warning.

export const SERVICE_WORKER_RELEASE_RETRY_MS = 45_000

export function isServiceWorkerReleaseUpgrade ({ pageSequence, signedSequence, serviceWorkerUpdate } = {}) {
  return Number.isSafeInteger(pageSequence) && pageSequence > 0 &&
    Number.isSafeInteger(signedSequence) && signedSequence > pageSequence &&
    serviceWorkerUpdate &&
    serviceWorkerUpdate.hadController === true &&
    serviceWorkerUpdate.controllerChanged !== true
}
