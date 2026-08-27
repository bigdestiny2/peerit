import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  RELEASE_ALG,
  RELEASE_MSG_VERSION,
  releaseSigningMessage
} from '../js/release-verify.js'
import {
  decodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritWebAssetManifestV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  blake2b256,
  bytesToHex
} from '../js/substrate/release-control-primitives.mjs'
import {
  verifyPeeritAppArtifactReleaseBindingsV1,
  verifyPeeritLimitedPublicInboxBootstrapArtifactV1
} from './substrate-runtime-artifact.mjs'

export const PEERIT_SEQ29_DECISION_ID_V1 =
  'peerit-seq29-limited-public-inbox-activation-20260813'
export const PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT_V1 =
  'adeacef07c5de4d17d5ed1389fee7a35095b862f'
export const PEERIT_SEQ29_DECISION_DRAFT_PATH_V1 =
  'deploy/canary-decision-peerit-seq29-limited-public-inbox-DRAFT.json'
export const PEERIT_SEQ29_DECISION_PATH_V1 =
  'deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json'
// Mechanical source-pin step. Sequence-29 verify/publish stays fail-closed
// while this is empty and unless the final decision bytes match it exactly.
export const PEERIT_SEQ29_DECISION_SHA256_V1 = 'a6f56012c72acb4cb0fa956ea1928811fd865927640ac441c126aa84071d9863'
export const PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1 =
  'AUTHORIZE_PEERIT_SEQ29_LIVE_PUBLIC_TEST_ONLY_BROWSER_ACTIVATION'
export const PEERIT_SEQ29_DECISION_TEXT_V1 =
  'ACCEPT Peerit release sequence 29 as the LIVE bounded-public-test launch successor for the exact source-pinned artifacts and explicit browser activation authority.'

const HEX64 = /^[0-9a-f]{64}$/
const SOURCE_DECISION_FILE =
  'deploy/canary-decision-peerit-t2-cell-put-pow-issuance-20260806.json'
const SOURCE_DECISION_SHA256 =
  '5431c9ea9e2d41fbc391ba02c4d8d5a1cff63a2ffb332e09722e6e365d816b2b'
const SEED_PATH = 'deploy/peerit-seed-bootstrap-v1-seq29.json'
const INBOX_PATH = 'deploy/peerit-limited-public-inbox-bootstrap-v1-seq29.json'
const APP_PATH = 'web/peerit-app-artifact-v1.json'
const CANONICAL_MANIFEST_PATH = 'web/peerit-web-assets-v1.cenc'
const OUTER_MANIFEST_PATH = 'web/asset-manifest.json'
const OUTER_SIGNATURE_PATH = 'web/asset-manifest.sig'
const SIGNING_REQUEST_PATH = 'deploy/web-signing-request.json'
const RELEASE_CONFIG_PATH = 'deploy/web-release.json'
const EXPECTED_DRAFT_UNRESOLVED = Object.freeze([
  'authority.explicit_browser_activation_confirmation',
  'release_artifacts.seed_bootstrap.sha256',
  'release_artifacts.public_inbox_bootstrap.sha256',
  'release_artifacts.public_inbox_bootstrap.authority_public_key',
  'release_artifacts.release_config_sha256',
  'release_artifacts.app_artifact_hash',
  'release_artifacts.canonical_web_asset_manifest_hash',
  'release_artifacts.outer_asset_manifest_sha256',
  'release_artifacts.outer_signing_message_sha256',
  'release_artifacts.signing_request_sha256',
  'byte_pinned_decision_sha256'
])
const MATERIALIZED_DECISIONS = new WeakSet()
const MATERIALIZATION_ARTIFACT_FIELDS = Object.freeze([
  'seedBootstrap', 'publicInboxBootstrap', 'appArtifact',
  'canonicalWebAssetManifest', 'outerAssetManifest', 'outerSignature', 'signingRequest',
  'releaseConfig'
])
const REPREPARE_FIELDS = Object.freeze([
  'appArtifact', 'canonicalWebAssetManifest', 'outerAssetManifest',
  'outerSignature', 'signingRequest'
])

function fail (message, code = 'PEERIT_SEQ29_OWNER_DECISION_INVALID') {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail(`${field} fields are missing or unexpected`)
  }
  return value
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function same (left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function read (root, path) {
  try { return readFileSync(join(root, path)) } catch (cause) {
    fail(`Sequence-29 owner decision bound file is missing: ${path} (${cause.message})`)
  }
}

function bytes (value, field) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    fail(`${field} must be exact bytes`)
  }
  return Buffer.from(value)
}

function artifactBytesAtRoot (root) {
  return Object.freeze({
    seedBootstrap: read(root, SEED_PATH),
    publicInboxBootstrap: read(root, INBOX_PATH),
    appArtifact: read(root, APP_PATH),
    canonicalWebAssetManifest: read(root, CANONICAL_MANIFEST_PATH),
    outerAssetManifest: read(root, OUTER_MANIFEST_PATH),
    outerSignature: read(root, OUTER_SIGNATURE_PATH),
    signingRequest: read(root, SIGNING_REQUEST_PATH),
    releaseConfig: read(root, RELEASE_CONFIG_PATH)
  })
}

function exactArtifactBytes (value, field = 'Sequence-29 materialization artifacts') {
  const input = exact(value, MATERIALIZATION_ARTIFACT_FIELDS, field)
  return Object.freeze(Object.fromEntries(MATERIALIZATION_ARTIFACT_FIELDS.map(name =>
    [name, bytes(input[name], `${field}.${name}`)])))
}

function assertArtifactsMatchRoot (root, provided) {
  const current = artifactBytesAtRoot(root)
  for (const field of MATERIALIZATION_ARTIFACT_FIELDS) {
    if (!current[field].equals(provided[field])) {
      fail(`Sequence-29 materialization artifact changed before decision creation: ${field}`,
        'PEERIT_SEQ29_OWNER_DECISION_ARTIFACT_DRIFT')
    }
  }
}

export function peeritSeq29OwnerDecisionPhaseV1 (input = {}) {
  exact(input, ['phase', 'sourcePin'], 'Sequence-29 decision phase input')
  const phase = String(input.phase || '')
  const sourcePin = String(input.sourcePin || '')
  if (!['prepare', 'verify'].includes(phase)) {
    fail('Sequence-29 decision phase must be prepare or verify')
  }
  if (sourcePin === '') {
    if (phase === 'prepare') return 'DRAFT_PREPARE_ONLY'
    fail('Sequence-29 owner decision source pin is unresolved',
      'PEERIT_SEQ29_OWNER_DECISION_PIN_REQUIRED')
  }
  if (!HEX64.test(sourcePin)) {
    fail('Sequence-29 owner decision source pin is malformed',
      'PEERIT_SEQ29_OWNER_DECISION_PIN_INVALID')
  }
  return 'PINNED_FINAL_REQUIRED'
}

function assertStaticDecisionShape (decision) {
  exact(decision, [
    'schema_version', 'decision_id', 'status', 'decision', 'decided_at',
    'authority', 'activation', 'release_artifacts', 'evidence', 'unresolved',
    'followups'
  ], 'Sequence-29 owner decision')
  const authority = exact(decision.authority, [
    'baseline_release_sequence', 'cited_prior_decisions',
    'explicit_browser_activation_confirmation'
  ], 'Sequence-29 decision authority')
  const activation = exact(decision.activation, [
    'functional_release_sequence', 'claim_boundary', 'relays',
    'allowed_browser_operations', 'forbidden_browser_operations',
    'dual_append_after_verified_cell_put_readback',
    'dual_read_same_relay_cell_get_intrinsic_ingest',
    'browser_management_seed_access', 'ga_product_gate'
  ], 'Sequence-29 decision activation')
  const artifacts = exact(decision.release_artifacts, [
    'accepted_hiverelay_candidate_commit', 'release_config_sha256', 'seed_bootstrap',
    'public_inbox_bootstrap', 'app_artifact_hash',
    'canonical_web_asset_manifest_hash', 'outer_asset_manifest_sha256',
    'outer_signing_message_sha256', 'signing_request_sha256'
  ], 'Sequence-29 decision release_artifacts')
  const seed = exact(artifacts.seed_bootstrap, [
    'path', 'sha256', 'authority_public_key', 'release_sequence',
    'bootstrap_sequence', 'previous_bootstrap_hash', 'records'
  ], 'Sequence-29 decision seed_bootstrap')
  const inbox = exact(artifacts.public_inbox_bootstrap, [
    'path', 'sha256', 'authority_public_key', 'artifact_class',
    'release_sequence', 'binding_count'
  ], 'Sequence-29 decision public_inbox_bootstrap')
  const evidence = exact(decision.evidence, [
    'corrected_direct_full_suite', 'independent_v9_control_commit',
    'pushed_main_ci_commit', 'github_actions'
  ], 'Sequence-29 decision evidence')
  const fullSuite = exact(evidence.corrected_direct_full_suite,
    ['tests', 'assertions', 'receipt_sha256'],
    'Sequence-29 corrected direct full-suite evidence')
  const actions = exact(evidence.github_actions, ['test', 'publish_docker_image'],
    'Sequence-29 GitHub Actions evidence')
  const testAction = exact(actions.test, ['run_id', 'url', 'conclusion'],
    'Sequence-29 Test action')
  const dockerAction = exact(actions.publish_docker_image,
    ['run_id', 'url', 'conclusion'], 'Sequence-29 Docker action')

  if (decision.schema_version !== 7 || decision.decision_id !== PEERIT_SEQ29_DECISION_ID_V1 ||
      authority.baseline_release_sequence !== 28 ||
      !same(authority.cited_prior_decisions, [{
        file: SOURCE_DECISION_FILE,
        sha256: SOURCE_DECISION_SHA256
      }]) || activation.functional_release_sequence !== 29 ||
      activation.claim_boundary !== 'LIVE_PUBLIC_TEST_ONLY' ||
      !same(activation.relays, ['dal-1', 'syd-1']) ||
      !same(activation.allowed_browser_operations, [
        'DESCRIBE.GET', 'DESCRIBE.CHALLENGE', 'CELL.GET', 'CELL.PUT',
        'INBOX.APPEND', 'INBOX.READ'
      ]) || !same(activation.forbidden_browser_operations, [
    'INBOX.CREATE', 'INBOX.RENEW', 'INBOX.CLOSE'
  ]) || activation.dual_append_after_verified_cell_put_readback !== true ||
      activation.dual_read_same_relay_cell_get_intrinsic_ingest !== true ||
      activation.browser_management_seed_access !== 'FORBIDDEN' ||
      activation.ga_product_gate !==
        'BLOCKED — DISCLOSED-OPEN, none cleared by this scope' ||
      artifacts.accepted_hiverelay_candidate_commit !==
        PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT_V1 ||
      seed.path !== SEED_PATH ||
      seed.authority_public_key !==
        '691d524a1c2ac38de86ed592fbae6f9a906770b96fe704d3c63397a23171f6ec' ||
      seed.release_sequence !== 29 || seed.bootstrap_sequence !== 0 ||
      seed.previous_bootstrap_hash !== null || seed.records !== 39 ||
      inbox.path !== INBOX_PATH ||
      inbox.artifact_class !== 'LIMITED_PUBLIC_TEST_RELEASE' ||
      inbox.release_sequence !== 29 || inbox.binding_count !== 2 ||
      fullSuite.tests !== 4037 || fullSuite.assertions !== 23710 ||
      fullSuite.receipt_sha256 !==
        'a349ccee216a1f174f476abb29f5997fff755eaec709fe9186d1a8426d027af1' ||
      evidence.independent_v9_control_commit !==
        '692cff73e8f04eca4e0e5ea14e8cae664af58ebd' ||
      evidence.pushed_main_ci_commit !==
        '43f51e0b41b5f67a7f4f63c124c6af9dec194e9b' ||
      !same(testAction, {
        run_id: '31729754451',
        url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/31729754451',
        conclusion: 'success'
      }) || !same(dockerAction, {
    run_id: '31729754371',
    url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/31729754371',
    conclusion: 'success'
  }) || !same(decision.followups, [
    'Materialize only from accepted local evidence and signed artifacts; never fabricate a hash or signature.',
    'GA product gate remains honestly blocked and disclosed-open.'
  ])) {
    fail('Sequence-29 owner decision has drifted from its exact fail-closed schema')
  }
  return { authority, activation, artifacts, seed, inbox }
}

export function verifyPeeritSeq29OwnerDecisionV1 (input = {}) {
  const bytes = Buffer.isBuffer(input.decisionBytes)
    ? Buffer.from(input.decisionBytes)
    : Buffer.from(input.decisionBytes || [])
  let decision
  try { decision = JSON.parse(bytes.toString('utf8')) } catch {
    fail('Sequence-29 owner decision is not JSON')
  }
  if (Buffer.from(JSON.stringify(decision, null, 2) + '\n').compare(bytes) !== 0) {
    fail('Sequence-29 owner decision bytes are not canonical pretty JSON')
  }
  const { authority, artifacts, seed, inbox } = assertStaticDecisionShape(decision)
  if (decision.status === 'DRAFT_MATERIALIZATION_REQUIRED') {
    if (decision.decision !== null || decision.decided_at !== null ||
        authority.explicit_browser_activation_confirmation !== null ||
        [artifacts.release_config_sha256, seed.sha256,
          inbox.sha256, inbox.authority_public_key,
          artifacts.app_artifact_hash, artifacts.canonical_web_asset_manifest_hash,
          artifacts.outer_asset_manifest_sha256,
          artifacts.outer_signing_message_sha256,
          artifacts.signing_request_sha256].some(value => value !== null) ||
        !same(decision.unresolved, EXPECTED_DRAFT_UNRESOLVED)) {
      fail('Sequence-29 owner decision draft does not preserve its exact unresolved fields')
    }
    if (input.allowDraft === true) return Object.freeze({ status: 'draft', decision })
    fail(`Sequence-29 public INBOX decision remains an unresolved draft: ${decision.unresolved.join(', ')}`,
      'PEERIT_SEQ29_OWNER_DECISION_DRAFT')
  }
  const decidedAtUnixMillis = typeof decision.decided_at === 'string'
    ? Date.parse(decision.decided_at)
    : NaN
  if (decision.status !== 'DECIDED' ||
      typeof decision.decided_at !== 'string' ||
      Number.isNaN(decidedAtUnixMillis) ||
      new Date(decidedAtUnixMillis).toISOString() !== decision.decided_at ||
      authority.explicit_browser_activation_confirmation !== true ||
      typeof decision.decision !== 'string' ||
      !decision.decision.startsWith(
        'ACCEPT Peerit release sequence 29 as the LIVE bounded-public-test launch successor') ||
      !same(decision.unresolved, []) ||
      [artifacts.release_config_sha256, seed.sha256,
        inbox.sha256, inbox.authority_public_key,
        artifacts.app_artifact_hash, artifacts.canonical_web_asset_manifest_hash,
        artifacts.outer_asset_manifest_sha256,
        artifacts.outer_signing_message_sha256,
        artifacts.signing_request_sha256].some(value => !HEX64.test(String(value || '')))) {
    fail('Sequence-29 owner decision is not fully materialized')
  }
  const expectedDecisionSha256 = String(input.expectedDecisionSha256 || '')
  if (!HEX64.test(expectedDecisionSha256) || sha256(bytes) !== expectedDecisionSha256) {
    fail('Sequence-29 owner decision bytes do not match the externally pinned decision hash')
  }
  const root = String(input.root || '')
  const seedBytes = read(root, SEED_PATH)
  const inboxBytes = read(root, INBOX_PATH)
  const appBytes = read(root, APP_PATH)
  const canonicalManifestBytes = read(root, CANONICAL_MANIFEST_PATH)
  const outerManifestBytes = read(root, OUTER_MANIFEST_PATH)
  const outerSignatureBytes = read(root, OUTER_SIGNATURE_PATH)
  const signingRequestBytes = read(root, SIGNING_REQUEST_PATH)
  const releaseConfigBytes = read(root, RELEASE_CONFIG_PATH)
  let outer
  let request
  let releaseConfig
  let signature
  try {
    outer = JSON.parse(outerManifestBytes)
    signature = JSON.parse(outerSignatureBytes)
    request = JSON.parse(signingRequestBytes)
    releaseConfig = JSON.parse(releaseConfigBytes)
  } catch {
    fail('Sequence-29 outer manifest, signature, signing request, or release config is not JSON')
  }
  if (JSON.stringify(releaseConfig, null, 2) + '\n' !== releaseConfigBytes.toString('utf8')) {
    fail('Sequence-29 release config bytes are not canonical pretty JSON')
  }
  exact(request, [
    'schema', 'manifest', 'signature', 'releaseSequence', 'driveKey',
    'pinnedReleaseKey', 'manifestSha256', 'signingMessageSha256',
    'artifactFiles'
  ], 'Sequence-29 signing request')
  exact(signature, ['alg', 'key', 'sig', 'msgVersion'],
    'Sequence-29 outer manifest signature')
  const computed = {
    releaseConfigSha256: sha256(releaseConfigBytes),
    seedSha256: sha256(seedBytes),
    inboxSha256: sha256(inboxBytes),
    appArtifactHash: bytesToHex(hashPeeritAppArtifactV1(appBytes)),
    canonicalWebAssetManifestHash:
      bytesToHex(hashPeeritWebAssetManifestV1(canonicalManifestBytes)),
    outerAssetManifestSha256: sha256(outerManifestBytes),
    outerSigningMessageSha256:
      sha256(Buffer.from(releaseSigningMessage(outer), 'utf8')),
    signingRequestSha256: sha256(signingRequestBytes)
  }
  let signedInboxBinding
  let appBinding
  let canonicalManifest
  try {
    // Audit the immutable acceptance decision at its canonical decision time.
    // Live activation performs its own wall-clock verification in the browser.
    signedInboxBinding = verifyPeeritLimitedPublicInboxBootstrapArtifactV1({
      bytes: inboxBytes,
      expectedAuthorityPublicKey: inbox.authority_public_key,
      expectedReleaseSequence: inbox.release_sequence,
      referenceUnixMillis: BigInt(decidedAtUnixMillis)
    })
    appBinding = verifyPeeritAppArtifactReleaseBindingsV1(appBytes)
    canonicalManifest = decodePeeritWebAssetManifestV1(canonicalManifestBytes)
  } catch (cause) {
    fail(`Sequence-29 public INBOX release binding is not authenticated: ${cause.message}`)
  }
  const canonicalInboxAsset = canonicalManifest.assets.find(asset =>
    asset.path === '/peerit-limited-public-inbox-bootstrap-v1.json')
  const canonicalAppAsset = canonicalManifest.assets.find(asset =>
    asset.path === '/peerit-app-artifact-v1.json')
  const canonicalInboxMatches = canonicalInboxAsset != null &&
    canonicalInboxAsset.byteLength === BigInt(inboxBytes.byteLength) &&
    Buffer.from(canonicalInboxAsset.assetHash).equals(Buffer.from(blake2b256(inboxBytes)))
  const canonicalAppMatches = canonicalAppAsset != null &&
    canonicalAppAsset.byteLength === BigInt(appBytes.byteLength) &&
    Buffer.from(canonicalAppAsset.assetHash).equals(Buffer.from(blake2b256(appBytes)))
  const canonicalAppRootMatches = Buffer.from(canonicalManifest.appArtifactHash)
    .equals(Buffer.from(hashPeeritAppArtifactV1(appBytes)))
  if (artifacts.release_config_sha256 !== computed.releaseConfigSha256 ||
      seed.sha256 !== computed.seedSha256 || inbox.sha256 !== computed.inboxSha256 ||
      signedInboxBinding.sha256 !== computed.inboxSha256 ||
      signedInboxBinding.authorityPublicKey !== inbox.authority_public_key ||
      signedInboxBinding.artifactClass !== inbox.artifact_class ||
      signedInboxBinding.releaseSequence !== inbox.release_sequence ||
      signedInboxBinding.bindingCount !== inbox.binding_count ||
      artifacts.app_artifact_hash !== computed.appArtifactHash ||
      artifacts.canonical_web_asset_manifest_hash !==
        computed.canonicalWebAssetManifestHash ||
      artifacts.outer_asset_manifest_sha256 !== computed.outerAssetManifestSha256 ||
      artifacts.outer_signing_message_sha256 !== computed.outerSigningMessageSha256 ||
      artifacts.signing_request_sha256 !== computed.signingRequestSha256 ||
      appBinding.releaseSequence !== 29 ||
      appBinding.inboxBootstrap?.path !==
        '/peerit-limited-public-inbox-bootstrap-v1.json' ||
      appBinding.inboxBootstrap?.sha256 !== computed.inboxSha256 ||
      appBinding.inboxBootstrap?.authorityPublicKey !==
        signedInboxBinding.authorityPublicKey ||
      appBinding.inboxBootstrap?.releaseSequence !==
        signedInboxBinding.releaseSequence ||
      appBinding.files?.['peerit-limited-public-inbox-bootstrap-v1.json'] !==
        computed.inboxSha256 ||
      canonicalManifest.releaseSequence !== 29n ||
      !canonicalInboxMatches || !canonicalAppMatches || !canonicalAppRootMatches ||
      outer?.releaseSequence !== 29 || outer?.webRelease?.releaseSequence !== 29 ||
      outer?.webRelease?.appArtifactHash !== computed.appArtifactHash ||
      outer?.webRelease?.canonicalWebAssetManifestHash !==
        computed.canonicalWebAssetManifestHash ||
      outer?.webRelease?.peeritSeedBootstrapSha256 !== computed.seedSha256 ||
      outer?.webRelease?.peeritLimitedPublicInboxBootstrapSha256 !==
        computed.inboxSha256 ||
      outer?.webRelease?.peeritLimitedPublicInboxBootstrap !==
        '/peerit-limited-public-inbox-bootstrap-v1.json' ||
      outer?.webRelease?.peeritLimitedPublicInboxBootstrapAuthorityPublicKey !==
        signedInboxBinding.authorityPublicKey ||
      outer?.webRelease?.peeritLimitedPublicInboxBootstrapReleaseSequence !==
        signedInboxBinding.releaseSequence ||
      outer?.files?.['peerit-seed-bootstrap-v1.json'] !== computed.seedSha256 ||
      outer?.files?.['peerit-limited-public-inbox-bootstrap-v1.json'] !==
        computed.inboxSha256 ||
      outer?.files?.['peerit-app-artifact-v1.json'] !== sha256(appBytes) ||
      outer?.files?.['peerit-web-assets-v1.cenc'] !==
        sha256(canonicalManifestBytes) ||
      request.schema !== 'peerit-web-signing-request-v2' ||
      request.releaseSequence !== 29 ||
      request.manifest !== OUTER_MANIFEST_PATH ||
      request.signature !== OUTER_SIGNATURE_PATH ||
      !HEX64.test(String(request.driveKey || '')) ||
      request.driveKey !== outer?.driveKey ||
      request.pinnedReleaseKey !== releaseConfig.pinnedReleaseKey ||
      request.manifestSha256 !== computed.outerAssetManifestSha256 ||
      request.signingMessageSha256 !== computed.outerSigningMessageSha256 ||
      request.artifactFiles?.['asset-manifest.json'] !==
        computed.outerAssetManifestSha256 ||
      request.artifactFiles?.['peerit-app-artifact-v1.json'] !== sha256(appBytes) ||
      request.artifactFiles?.['peerit-web-assets-v1.cenc'] !==
        sha256(canonicalManifestBytes) ||
      request.artifactFiles?.['peerit-seed-bootstrap-v1.json'] !==
        computed.seedSha256 ||
      request.artifactFiles?.['peerit-limited-public-inbox-bootstrap-v1.json'] !==
        computed.inboxSha256 ||
      Buffer.from(JSON.stringify(signature, null, 2) + '\n').compare(outerSignatureBytes) !== 0 ||
      signature.alg !== RELEASE_ALG || signature.msgVersion !== RELEASE_MSG_VERSION ||
      signature.key !== releaseConfig.pinnedReleaseKey ||
      !/^[0-9a-f]{128}$/.test(String(signature.sig || '')) ||
      !nodeVerify(null, Buffer.from(releaseSigningMessage(outer), 'utf8'),
        createPublicKey({
          key: Buffer.concat([
            Buffer.from('302a300506032b6570032100', 'hex'),
            Buffer.from(signature.key, 'hex')
          ]),
          format: 'der',
          type: 'spki'
        }), Buffer.from(signature.sig, 'hex')) ||
      releaseConfig.substrateProfile !== 'blind-v1' ||
      releaseConfig.releaseSequence !== signedInboxBinding.releaseSequence ||
      releaseConfig.peeritLimitedPublicInboxBootstrapBundle !== inbox.path ||
      releaseConfig.peeritLimitedPublicInboxBootstrapAuthorityPublicKey !==
        signedInboxBinding.authorityPublicKey) {
    fail('Sequence-29 owner decision does not byte-bind the exact release artifacts and signing request')
  }
  return Object.freeze({
    status: 'decided',
    decision,
    computed: Object.freeze(computed),
    signedInboxBinding
  })
}

export function materializePeeritSeq29OwnerDecisionV1 (input = {}) {
  exact(input, [
    'root', 'draftBytes', 'expectedDraftSha256', 'explicitConfirmation',
    'decidedAt', 'artifacts'
  ], 'Sequence-29 decision materialization input')
  const rootInput = String(input.root || '')
  if (!rootInput) fail('Sequence-29 materialization root is required')
  const root = resolve(rootInput)
  const draftBytes = bytes(input.draftBytes, 'Sequence-29 decision draft')
  const expectedDraftSha256 = String(input.expectedDraftSha256 || '')
  if (!HEX64.test(expectedDraftSha256)) {
    fail('Sequence-29 expected DRAFT hash is malformed',
      'PEERIT_SEQ29_OWNER_DECISION_DRAFT_PIN_INVALID')
  }
  if (sha256(draftBytes) !== expectedDraftSha256) {
    fail('Sequence-29 DRAFT bytes do not match the explicit reviewed hash',
      'PEERIT_SEQ29_OWNER_DECISION_DRAFT_PIN_MISMATCH')
  }
  if (input.explicitConfirmation !== PEERIT_SEQ29_EXPLICIT_CONFIRMATION_V1) {
    fail('Sequence-29 explicit browser activation confirmation is missing or inexact',
      'PEERIT_SEQ29_OWNER_DECISION_CONFIRMATION_REQUIRED')
  }
  const decidedAt = String(input.decidedAt || '')
  const decidedAtUnixMillis = Date.parse(decidedAt)
  if (Number.isNaN(decidedAtUnixMillis) ||
      new Date(decidedAtUnixMillis).toISOString() !== decidedAt) {
    fail('Sequence-29 decidedAt must be an exact canonical ISO-8601 instant',
      'PEERIT_SEQ29_OWNER_DECISION_TIME_INVALID')
  }
  const verifiedDraft = verifyPeeritSeq29OwnerDecisionV1({
    decisionBytes: draftBytes,
    allowDraft: true
  })
  const artifacts = exactArtifactBytes(input.artifacts)
  assertArtifactsMatchRoot(root, artifacts)

  let outer
  let inboxBinding
  try {
    // Materialization proves authority at the proposed decision instant; it does
    // not extend that authority's live runtime lifetime.
    outer = JSON.parse(artifacts.outerAssetManifest)
    const inboxEnvelope = JSON.parse(artifacts.publicInboxBootstrap)
    const inboxAuthorityPublicKey = String(
      inboxEnvelope?.payload?.authorityPublicKey || '')
    if (!HEX64.test(inboxAuthorityPublicKey)) {
      fail('Sequence-29 public INBOX artifact authority is missing or malformed')
    }
    inboxBinding = verifyPeeritLimitedPublicInboxBootstrapArtifactV1({
      bytes: artifacts.publicInboxBootstrap,
      expectedAuthorityPublicKey: inboxAuthorityPublicKey,
      expectedReleaseSequence: 29,
      referenceUnixMillis: BigInt(decidedAtUnixMillis)
    })
  } catch (cause) {
    fail(`Sequence-29 materialization artifact is not authenticated: ${cause.message}`)
  }
  const decision = structuredClone(verifiedDraft.decision)
  decision.status = 'DECIDED'
  decision.decision = PEERIT_SEQ29_DECISION_TEXT_V1
  decision.decided_at = decidedAt
  decision.authority.explicit_browser_activation_confirmation = true
  decision.release_artifacts.release_config_sha256 = sha256(artifacts.releaseConfig)
  decision.release_artifacts.seed_bootstrap.sha256 = sha256(artifacts.seedBootstrap)
  decision.release_artifacts.public_inbox_bootstrap.sha256 =
    sha256(artifacts.publicInboxBootstrap)
  decision.release_artifacts.public_inbox_bootstrap.authority_public_key =
    inboxBinding.authorityPublicKey
  decision.release_artifacts.app_artifact_hash =
    bytesToHex(hashPeeritAppArtifactV1(artifacts.appArtifact))
  decision.release_artifacts.canonical_web_asset_manifest_hash =
    bytesToHex(hashPeeritWebAssetManifestV1(artifacts.canonicalWebAssetManifest))
  decision.release_artifacts.outer_asset_manifest_sha256 =
    sha256(artifacts.outerAssetManifest)
  decision.release_artifacts.outer_signing_message_sha256 =
    sha256(Buffer.from(releaseSigningMessage(outer), 'utf8'))
  decision.release_artifacts.signing_request_sha256 = sha256(artifacts.signingRequest)
  decision.unresolved = []

  const decisionBytes = Buffer.from(JSON.stringify(decision, null, 2) + '\n')
  const decisionSha256 = sha256(decisionBytes)
  verifyPeeritSeq29OwnerDecisionV1({
    root,
    decisionBytes,
    expectedDecisionSha256: decisionSha256
  })
  assertArtifactsMatchRoot(root, artifacts)
  const result = Object.freeze({
    decisionBytes,
    decisionSha256,
    decisionPath: PEERIT_SEQ29_DECISION_PATH_V1,
    sourcePin: Object.freeze({
      name: 'PEERIT_SEQ29_DECISION_SHA256_V1',
      value: decisionSha256
    })
  })
  MATERIALIZED_DECISIONS.add(result)
  return result
}

export function writePeeritSeq29OwnerDecisionCreateOnlyV1 (input = {}) {
  exact(input, ['root', 'materialized'], 'Sequence-29 create-only decision output')
  if (!MATERIALIZED_DECISIONS.has(input.materialized)) {
    fail('Sequence-29 decision output requires the exact branded materialization result')
  }
  const root = resolve(String(input.root || ''))
  const output = join(root, PEERIT_SEQ29_DECISION_PATH_V1)
  try {
    writeFileSync(output, input.materialized.decisionBytes, {
      flag: 'wx',
      mode: 0o444
    })
  } catch (cause) {
    fail(`Sequence-29 final decision is create-only and was not written: ${cause.message}`,
      'PEERIT_SEQ29_OWNER_DECISION_CREATE_ONLY')
  }
  const written = readFileSync(output)
  if (!written.equals(input.materialized.decisionBytes) ||
      sha256(written) !== input.materialized.decisionSha256) {
    fail('Sequence-29 final decision changed during create-only materialization')
  }
  return Object.freeze({
    path: PEERIT_SEQ29_DECISION_PATH_V1,
    sha256: input.materialized.decisionSha256,
    sourcePin: input.materialized.sourcePin
  })
}

export function verifyPeeritSeq29PinnedReprepareV1 (input = {}) {
  exact(input, ['sourcePin', 'decisionBytes', 'before', 'after'],
    'Sequence-29 pinned reprepare input')
  const sourcePin = String(input.sourcePin || '')
  if (!HEX64.test(sourcePin)) {
    fail('Sequence-29 reprepare source pin is malformed',
      'PEERIT_SEQ29_OWNER_DECISION_PIN_INVALID')
  }
  if (sha256(bytes(input.decisionBytes, 'Sequence-29 final decision')) !== sourcePin) {
    fail('Sequence-29 reprepare source pin does not match the exact final decision bytes',
      'PEERIT_SEQ29_OWNER_DECISION_PIN_MISMATCH')
  }
  const before = exact(input.before, REPREPARE_FIELDS, 'Sequence-29 pre-pin outputs')
  const after = exact(input.after, REPREPARE_FIELDS, 'Sequence-29 reprepare outputs')
  const hashes = {}
  for (const field of REPREPARE_FIELDS) {
    const prior = bytes(before[field], `Sequence-29 pre-pin outputs.${field}`)
    const current = bytes(after[field], `Sequence-29 reprepare outputs.${field}`)
    if (!prior.equals(current)) {
      fail(`source-pinned Sequence-29 re-prepare changed ${field}`,
        'PEERIT_SEQ29_OWNER_DECISION_REPREPARE_DRIFT')
    }
    hashes[field] = sha256(current)
  }
  return Object.freeze({ sourcePin, hashes: Object.freeze(hashes) })
}

export function verifyPinnedPeeritSeq29OwnerDecisionV1 (input = {}) {
  const root = resolve(String(input.root || ''))
  peeritSeq29OwnerDecisionPhaseV1({
    phase: 'verify',
    sourcePin: PEERIT_SEQ29_DECISION_SHA256_V1
  })
  return verifyPeeritSeq29OwnerDecisionV1({
    root,
    decisionBytes: read(root, PEERIT_SEQ29_DECISION_PATH_V1),
    expectedDecisionSha256: PEERIT_SEQ29_DECISION_SHA256_V1
  })
}

function parseMaterializeArgs (argv) {
  if (argv[0] !== 'materialize') {
    fail('usage: node scripts/seq29-owner-decision.mjs materialize --root <path> --expected-draft-sha256 <lowercase-hex> --decided-at <ISO> --explicit-confirmation <token>')
  }
  const output = { root: '', expectedDraftSha256: '', decidedAt: '', explicitConfirmation: '' }
  for (let index = 1; index < argv.length; index++) {
    const arg = argv[index]
    const value = argv[++index]
    if (!value) fail(`${arg} requires a value`)
    if (arg === '--root') output.root = value
    else if (arg === '--expected-draft-sha256') output.expectedDraftSha256 = value
    else if (arg === '--decided-at') output.decidedAt = value
    else if (arg === '--explicit-confirmation') output.explicitConfirmation = value
    else fail(`unknown Sequence-29 materialization option: ${arg}`)
  }
  if (!output.root) fail('--root is required')
  return output
}

function runMaterializeCli (argv) {
  const opts = parseMaterializeArgs(argv)
  const root = resolve(opts.root)
  const materialized = materializePeeritSeq29OwnerDecisionV1({
    root,
    draftBytes: read(root, PEERIT_SEQ29_DECISION_DRAFT_PATH_V1),
    expectedDraftSha256: opts.expectedDraftSha256,
    explicitConfirmation: opts.explicitConfirmation,
    decidedAt: opts.decidedAt,
    artifacts: artifactBytesAtRoot(root)
  })
  const receipt = writePeeritSeq29OwnerDecisionCreateOnlyV1({ root, materialized })
  process.stdout.write(JSON.stringify(receipt, null, 2) + '\n')
}

const isDirectRun = process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isDirectRun) {
  try { runMaterializeCli(process.argv.slice(2)) } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
