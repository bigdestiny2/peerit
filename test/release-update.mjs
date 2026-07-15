import assert from 'node:assert/strict'
import {
  SERVICE_WORKER_RELEASE_RETRY_MS,
  isServiceWorkerReleaseUpgrade
} from '../js/release-update.js'

assert.equal(SERVICE_WORKER_RELEASE_RETRY_MS, 45_000)
assert.equal(isServiceWorkerReleaseUpgrade({
  pageSequence: 4,
  signedSequence: 6,
  serviceWorkerUpdate: { hadController: true, controllerChanged: false }
}), true, 'a controlled cached page may wait for a newer signed service-worker release')
assert.equal(isServiceWorkerReleaseUpgrade({
  pageSequence: 4,
  signedSequence: 6,
  serviceWorkerUpdate: { hadController: false, controllerChanged: false }
}), false, 'a fresh page/deploy mismatch remains an integrity failure')
assert.equal(isServiceWorkerReleaseUpgrade({
  pageSequence: 6,
  signedSequence: 6,
  serviceWorkerUpdate: { hadController: true, controllerChanged: false }
}), false, 'matching releases do not display an update state')
assert.equal(isServiceWorkerReleaseUpgrade({
  pageSequence: 6,
  signedSequence: 4,
  serviceWorkerUpdate: { hadController: true, controllerChanged: false }
}), false, 'a rollback-shaped sequence remains an integrity failure')
assert.equal(isServiceWorkerReleaseUpgrade({
  pageSequence: 4,
  signedSequence: 6,
  serviceWorkerUpdate: { hadController: true, controllerChanged: true }
}), false, 'a controller change must reload rather than masking a persistent mismatch')

console.log('release-update: 6 checks passed')
