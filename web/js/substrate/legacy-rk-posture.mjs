import {
  domainLengthHash,
  utf8Bytes
} from './release-control-primitives.mjs'

export const PEERIT_LEGACY_RK_POSTURE_DOMAIN_V1 =
  'peerit.legacy-rk-posture.v1'

// RK was designed as a network-wide reader constant for public content. It is
// shipped to readers and is therefore reachable by relays, origins, bundles,
// and anyone who can inspect the application. Calling it a secret would create
// a false confidentiality boundary and an unsafe rotation ceremony.
export const PEERIT_LEGACY_RK_POSTURE_V1 = Object.freeze({
  version: 1,
  classification: 'PUBLIC_REACHABLE_LEGACY_NETWORK_CONSTANT',
  confidentiality: 'NONE_PUBLIC_FORUM_READ_KEY',
  reachableByDesign: true,
  currentlyRequiredByLegacyReaders: true,
  secretRotationAvailable: false,
  retirementAuthorized: false,
  retirementRequirement:
    'A reviewed migration pin and bundle-closure proof must remove every legacy RK consumer before retirement.',
  prohibitedClaim:
    'RK MUST NOT be described, generated, rotated, escrowed, or recovered as a secret.',
  legacyConsumers: Object.freeze([
    'js/canon.js',
    'js/data.js',
    'js/gossip.js',
    'js/pow.js',
    'js/seal.js',
    'js/substrate/peerit-operation-authority-v1.js'
  ])
})

const CANONICAL_POSTURE = [
  'PeeritLegacyRkPostureV1',
  'version=1',
  'classification=PUBLIC_REACHABLE_LEGACY_NETWORK_CONSTANT',
  'confidentiality=NONE_PUBLIC_FORUM_READ_KEY',
  'reachableByDesign=true',
  'currentlyRequiredByLegacyReaders=true',
  'secretRotationAvailable=false',
  'retirementAuthorized=false',
  'retirementRequirement=A reviewed migration pin and bundle-closure proof must remove every legacy RK consumer before retirement.',
  'prohibitedClaim=RK MUST NOT be described, generated, rotated, escrowed, or recovered as a secret.',
  'legacyConsumers=js/canon.js,js/data.js,js/gossip.js,js/pow.js,js/seal.js,js/substrate/peerit-operation-authority-v1.js'
].join('\n') + '\n'

export function encodePeeritLegacyRkPostureV1 () {
  return utf8Bytes(CANONICAL_POSTURE, 'PeeritLegacyRkPostureV1')
}

export function hashPeeritLegacyRkPostureV1 () {
  return domainLengthHash(
    PEERIT_LEGACY_RK_POSTURE_DOMAIN_V1,
    encodePeeritLegacyRkPostureV1()
  )
}
