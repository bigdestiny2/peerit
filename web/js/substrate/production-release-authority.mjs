// Peerit's immutable production release trust root.
//
// These values are intentionally null until an independently reviewed release
// ceremony publishes both the Ed25519 authority key and the exact genesis pin
// hash. Build flags, HTML metadata, fetched JSON, and relay responses must never
// be allowed to fill this object: doing so would turn origin-controlled bytes
// into their own trust root.

export const PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 = Object.freeze({
  publicKey: null,
  genesisPinHash: null
})

export const PEERIT_PRODUCTION_PIN_HISTORY_META = 'peerit-production-pin-history'
export const PEERIT_PRODUCTION_PIN_HISTORY_PATH = '/peerit-production-pin-history-v1.cenc'
