// Peerit's immutable production release trust root.
// Generated only by scripts/production-pin-history-ceremony.mjs prepare.

import { hexToBytes } from './release-control-primitives.mjs'

const PUBLIC_KEY = 'd6633deaf051b4063585d561a58e435f62a305b75cee697241ae6cbd6e01001b'
const GENESIS_PIN_HASH = '597f549686b89df44575623e61608182a00879fcf4d4a8e96eb553471b287f36'

export const PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 = Object.freeze({
  get publicKey () { return hexToBytes(PUBLIC_KEY, 32, 'production release authority public key') },
  get genesisPinHash () { return hexToBytes(GENESIS_PIN_HASH, 32, 'production genesis pin hash') }
})

export const PEERIT_PRODUCTION_PIN_HISTORY_META = 'peerit-production-pin-history'
export const PEERIT_PRODUCTION_PIN_HISTORY_PATH = '/peerit-production-pin-history-v1.cenc'
