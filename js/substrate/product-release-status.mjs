// Complete Peerit blind-product release boundary.
//
// Profile artifacts intentionally report only the application profile slice.
// Public release additionally needs a signed production substrate choice, the
// actual HiveRelay daemon/store product, and the browser consumer composing it.
// A final WIRE tuple, configured web-signing key, or green unit suite is not a
// substitute for that production evidence.

import {
  PEERIT_PROFILE_STATUS,
  PROFILE_VALIDATOR_ARTIFACT_STATUS,
  RELEASE_CONTROL_SLICE_STATUS,
  SIGNED_PIN_CONTINUITY_STATUS
} from './profile-status.mjs'
import {
  PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS,
  PEERIT_BLIND_CLIENT_CONSUMER_STATUS
} from './relay-consumer.js'
import { PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS } from './pin-history-witness-backend.mjs'

const HEX_32 = /^[0-9a-f]{64}$/

function unique (values) {
  return Object.freeze(values.filter((value, index, all) => all.indexOf(value) === index))
}

function exactSubstrateTuple (value) {
  return value != null && typeof value === 'object' &&
    HEX_32.test(String(value.specHash || '')) &&
    HEX_32.test(String(value.abiHash || '')) &&
    HEX_32.test(String(value.vectorSetHash || ''))
}

const productionSubstrateAuthority = {
  // The exact final WIRE/client-composition authorities are imported by the
  // profile, but no signed Peerit production pin selects an emit tuple yet.
  finalWireAndClientAuthoritiesImported: PEERIT_PROFILE_STATUS.externalCodecAuthorityComplete,
  signedProductionProfilePinArtifact: null,
  emitSubstrateTuple: null,
  emitSubstrateTuplePinned: RELEASE_CONTROL_SLICE_STATUS.productionTuplePinned,
  releaseAuthorityPublicKey: null,
  releaseAuthorityPinned: RELEASE_CONTROL_SLICE_STATUS.productionAuthorityPinned,
  webAssetReleaseKeyCrossBound: false
}
export const PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS = Object.freeze({
  ...productionSubstrateAuthority,
  releaseReady: exactSubstrateTuple(productionSubstrateAuthority.emitSubstrateTuple) &&
    productionSubstrateAuthority.emitSubstrateTuplePinned &&
    HEX_32.test(String(productionSubstrateAuthority.releaseAuthorityPublicKey || '')) &&
    productionSubstrateAuthority.releaseAuthorityPinned &&
    productionSubstrateAuthority.webAssetReleaseKeyCrossBound
})

const productionHiveRelayRuntime = {
  evidenceArtifact: null,
  signedProductionTupleMatched: false,
  allFiveFamiliesExecutable: false,
  daemonProductionRuntimeReady: false,
  storeFormatAuthorityReady: false,
  storeGenesisPublicationAuthorityReady: false,
  storeRecoveryAndRuntimeReady: false
}
export const PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS = Object.freeze({
  ...productionHiveRelayRuntime,
  releaseReady: productionHiveRelayRuntime.evidenceArtifact != null &&
    productionHiveRelayRuntime.signedProductionTupleMatched &&
    productionHiveRelayRuntime.allFiveFamiliesExecutable &&
    productionHiveRelayRuntime.daemonProductionRuntimeReady &&
    productionHiveRelayRuntime.storeFormatAuthorityReady &&
    productionHiveRelayRuntime.storeGenesisPublicationAuthorityReady &&
    productionHiveRelayRuntime.storeRecoveryAndRuntimeReady
})

const browserProductRuntime = {
  // The replacement-only build closure is isolated, but its current entry is a
  // release-blocked shell. It does not yet mount Peerit's UI/model, lurker boot,
  // explicit first-write identity flow, or durable offline publication queue.
  substrateUiAndLocalAuthoringRuntimeReady: false,
  authenticatedBlindClientArtifact: false,
  blindClientArtifactHashPinnedByProductionPin: false,
  authenticatedPeeritRuntimeAuthority: false,
  relayConsumerComposed: PEERIT_BLIND_CLIENT_CONSUMER_STATUS.releaseReady,
  contextualGraphValidatorReady: PROFILE_VALIDATOR_ARTIFACT_STATUS.contextualGraphValidatorReady,
  portablePinRollbackRecoveryReady:
    PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.portableExternalRollbackRecoveryReady,
  postEvictionPinContinuityRecoveryReady:
    PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.postEvictionContinuityRecoveryReady
}
export const PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS = Object.freeze({
  ...browserProductRuntime,
  releaseReady: Object.values(browserProductRuntime).every(value => value === true)
})

export const PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS = unique([
  ...PEERIT_BLIND_CLIENT_CONSUMER_BLOCKERS,
  ...(!PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.substrateUiAndLocalAuthoringRuntimeReady
    ? ['PEERIT_SUBSTRATE_UI_AND_LOCAL_AUTHORING_RUNTIME_UNASSEMBLED']
    : []),
  ...(!exactSubstrateTuple(PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.emitSubstrateTuple) ||
      !PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.emitSubstrateTuplePinned
    ? ['PRODUCTION_HIVERELAY_PRODUCT_TUPLE_UNPINNED']
    : []),
  ...(!PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.releaseAuthorityPinned ||
      !HEX_32.test(String(PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.releaseAuthorityPublicKey || '')) ||
      !PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.webAssetReleaseKeyCrossBound
    ? ['PRODUCTION_PEERIT_RELEASE_AUTHORITY_UNPINNED']
    : []),
  ...(!PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.daemonProductionRuntimeReady ||
      !PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.allFiveFamiliesExecutable ||
      !PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.signedProductionTupleMatched
    ? ['HIVERELAY_PRODUCTION_DAEMON_RUNTIME_INCOMPLETE']
    : []),
  ...(!PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.storeFormatAuthorityReady ||
      !PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.storeGenesisPublicationAuthorityReady ||
      !PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS.storeRecoveryAndRuntimeReady
    ? ['HIVERELAY_PRODUCTION_STORE_INCOMPLETE']
    : []),
  ...(!PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.authenticatedBlindClientArtifact ||
      !PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.blindClientArtifactHashPinnedByProductionPin ||
      !PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.authenticatedPeeritRuntimeAuthority ||
      !PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.relayConsumerComposed
    ? ['PEERIT_BROWSER_RUNTIME_CONSUMER_UNASSEMBLED']
    : []),
  ...(!PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.portablePinRollbackRecoveryReady
    ? ['PORTABLE_PIN_HISTORY_ROLLBACK_RECOVERY_UNIMPLEMENTED']
    : []),
  ...(!PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS.postEvictionPinContinuityRecoveryReady
    ? ['POST_EVICTION_PIN_HISTORY_RECOVERY_UNIMPLEMENTED']
    : [])
])

export const PEERIT_BLIND_PRODUCT_RELEASE_STATUS = Object.freeze({
  productId: '@peerit/hiverelay-blind-product-v1',
  substrateProfile: 'blind-v1',
  profileSlice: PEERIT_PROFILE_STATUS,
  profileSliceReady: PEERIT_PROFILE_STATUS.releaseReady,
  productionSubstrateAuthority: PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS,
  productionHiveRelayRuntime: PEERIT_PRODUCTION_HIVERELAY_RUNTIME_STATUS,
  browserRuntime: PEERIT_BROWSER_PRODUCT_RUNTIME_STATUS,
  signedPinContinuityVerifierReady: SIGNED_PIN_CONTINUITY_STATUS.verifierReady,
  contextualGraphValidatorReady: PROFILE_VALIDATOR_ARTIFACT_STATUS.contextualGraphValidatorReady,
  portablePinRollbackRecoveryReady:
    PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.portableExternalRollbackRecoveryReady,
  postEvictionPinContinuityRecoveryReady:
    PEERIT_PIN_HISTORY_WITNESS_BACKEND_STATUS.postEvictionContinuityRecoveryReady,
  releaseReady: PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS.length === 0,
  releaseBlockers: PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS
})

function configurationFailure (message) {
  const error = new Error(message)
  error.code = 'PEERIT_BLIND_PRODUCT_CONFIG_INVALID'
  throw error
}

export function assertPeeritBlindProductReleaseReady (releaseConfig) {
  if (!releaseConfig || typeof releaseConfig !== 'object' ||
      releaseConfig.substrateProfile !== 'blind-v1') {
    configurationFailure('Peerit blind product gate requires the blind-v1 release configuration')
  }

  if (!PEERIT_BLIND_PRODUCT_RELEASE_STATUS.releaseReady) {
    const error = new Error(
      `Peerit blind product is not release-ready; ${PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS.length} product blockers remain`)
    error.code = 'PEERIT_BLIND_PRODUCT_INCOMPLETE'
    error.releaseBlockers = [...PEERIT_BLIND_PRODUCT_RELEASE_BLOCKERS]
    error.releaseStatus = PEERIT_BLIND_PRODUCT_RELEASE_STATUS
    throw error
  }

  const expectedKey = PEERIT_PRODUCTION_SUBSTRATE_AUTHORITY_STATUS.releaseAuthorityPublicKey
  const configuredKey = String(releaseConfig.pinnedReleaseKey || '').toLowerCase()
  if (!HEX_32.test(String(expectedKey || '')) || configuredKey !== expectedKey) {
    configurationFailure('web release key is not the exact key authenticated by the production Peerit profile pin')
  }
  return PEERIT_BLIND_PRODUCT_RELEASE_STATUS
}
