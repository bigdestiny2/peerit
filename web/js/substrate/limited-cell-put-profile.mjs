import { asBytes, bytesToHex } from './release-control-primitives.mjs'

export const PEERIT_LIMITED_CELL_PUT_PROFILE_PATH_V1 =
  '/peerit-limited-cell-put-profile-v1.json'

// Bound at the sequence-28 owner ceremony. The profile is INVALID under any
// earlier release sequence: the limited Cell-PUT authority did not exist
// before the sequence that signed this profile's bytes.
export const PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE = 28

export const PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1 = 1 // pow-issuance-v1 (docs/POW-ISSUANCE-V1.md)
export const PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1 = 8 // fleet OPEN write profile
export const PEERIT_LIMITED_CELL_PUT_DIFFICULTY_BITS_V1 = 20
export const PEERIT_LIMITED_CELL_PUT_MAX_TOKEN_ALLOWANCE_V1 = 2 // fleet issuer cap
export const PEERIT_LIMITED_CELL_PUT_MAX_SIZE_CLASS_V1 = 2
export const PEERIT_LIMITED_CELL_PUT_MAX_LEASE_CLASS_V1 = 2
export const PEERIT_LIMITED_CELL_PUT_ISSUER_ORIGINS_V1 = Object.freeze([
  'https://relay-dal.p2phiverelay.xyz:8443',
  'https://relay-syd.p2phiverelay.xyz:8443'
])

const HEX_32 = /^[0-9a-f]{64}$/
const decoder = new TextDecoder('utf-8', { fatal: true })
const encoder = new TextEncoder()

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', `${field} fields are missing or unexpected`)
  }
  return value
}

function integer (value, field, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', `${field} is outside its bound`)
  }
  return value
}

function hex32 (value, field) {
  if (!HEX_32.test(String(value || ''))) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function fromHex (value) {
  const output = new Uint8Array(32)
  for (let index = 0; index < 32; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

function immutable (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value) ||
      value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return value
  for (const child of Object.values(value)) immutable(child)
  return Object.freeze(value)
}

function profileHashRow (value, index) {
  exact(value, ['protocolId', 'major', 'minimumMinor', 'profileHash'],
    `supportedProtocolProfiles[${index}]`)
  return {
    protocolId: integer(value.protocolId, `supportedProtocolProfiles[${index}].protocolId`, 1, 4),
    major: integer(value.major, `supportedProtocolProfiles[${index}].major`, 1, 1),
    minimumMinor: integer(value.minimumMinor, `supportedProtocolProfiles[${index}].minimumMinor`, 0, 0),
    profileHash: fromHex(hex32(value.profileHash, `supportedProtocolProfiles[${index}].profileHash`))
  }
}

function operationRequirement (value, field, operationId) {
  exact(value, [
    'familyId', 'operationId', 'endpointId', 'requiredRoleBits',
    'privacyProfileBit', 'transportSupportBit'
  ], field)
  return {
    familyId: integer(value.familyId, `${field}.familyId`, 2, 2),
    operationId: integer(value.operationId, `${field}.operationId`, operationId, operationId),
    endpointId: integer(value.endpointId, `${field}.endpointId`, 1, 1),
    requiredRoleBits: integer(value.requiredRoleBits, `${field}.requiredRoleBits`, 49, 49),
    privacyProfileBit: integer(value.privacyProfileBit, `${field}.privacyProfileBit`, 1, 1),
    transportSupportBit: integer(value.transportSupportBit, `${field}.transportSupportBit`, 1, 1)
  }
}

function admissionProfile (value, relayId) {
  exact(value, [
    'profileId', 'schemeId', 'conformanceClass', 'roleBits',
    'parameterUrl'
  ], `${relayId}.admissionProfile`)
  if (value.parameterUrl !== null) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID',
      `${relayId} pow-issuance parameterUrl must be null (parameters ride the signed descriptor)`)
  }
  // The admission parameterHash is deliberately absent from the release
  // profile: it rotates with the fleet and is carried by the current
  // signature-verified descriptor (descriptor-driven), so no release file may
  // pin it. The stable admission scheme shape below is all a release may pin.
  return {
    profileId: integer(value.profileId, `${relayId}.profileId`,
      PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1, PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1),
    schemeId: integer(value.schemeId, `${relayId}.schemeId`,
      PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1, PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1),
    conformanceClass: integer(value.conformanceClass, `${relayId}.conformanceClass`, 1, 1),
    roleBits: integer(value.roleBits, `${relayId}.roleBits`, 49, 49),
    parameterUrl: null
  }
}

function relayRow (value, index) {
  exact(value, ['relayId', 'relayPublicKey', 'issuanceUrl', 'admissionProfile'], `relays[${index}]`)
  if (value.relayId !== ['dal-1', 'syd-1'][index]) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'relay admission pins must be sorted dal-1, syd-1')
  }
  if (typeof value.issuanceUrl !== 'string' ||
      value.issuanceUrl !== `https://relay-${value.relayId === 'dal-1' ? 'dal' : 'syd'}.p2phiverelay.xyz:8443/`) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID',
      `${value.relayId} issuanceUrl must be the exact signed pow-issuance issuer origin`)
  }
  return {
    relayId: value.relayId,
    relayPublicKey: fromHex(hex32(value.relayPublicKey, `relays[${index}].relayPublicKey`)),
    issuanceUrl: encoder.encode(value.issuanceUrl),
    admissionProfile: admissionProfile(value.admissionProfile, value.relayId)
  }
}

export function verifyPeeritLimitedCellPutProfileV1 (input, options = {}) {
  const bytes = new Uint8Array(asBytes(input, 'limited Cell-PUT profile'))
  let source
  let value
  try {
    source = decoder.decode(bytes)
    value = JSON.parse(source)
  } catch {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'limited Cell-PUT profile is not canonical JSON')
  }
  if (JSON.stringify(value, null, 2) + '\n' !== source) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'limited Cell-PUT profile bytes are not canonical pretty JSON')
  }
  exact(value, [
    'schema', 'version', 'releaseSequence', 'mode', 'ordinaryDelivery',
    'networkPuts', 'maximumDescriptorHistory', 'powIssuance',
    'supportedProtocolProfiles', 'supportedTransportProfiles', 'requirement',
    'readRequirement', 'relays'
  ], 'limited Cell-PUT profile')
  const expectedSequence = integer(
    options.releaseSequence, 'expected release sequence', PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE)
  if (value.schema !== 'peerit-limited-cell-put-profile-v1' || value.version !== 1 ||
      value.releaseSequence !== expectedSequence || value.mode !== 'explicit-user-writes' ||
      value.ordinaryDelivery !== 'local-only' || value.networkPuts !== 1 ||
      value.maximumDescriptorHistory !== 4096) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'limited Cell-PUT release posture is invalid')
  }
  // Writes are explicit user actions only (networkPuts 1 = enabled, never
  // background/automatic); ordinary feed delivery stays local-only exactly as
  // the read-only profile pins it.

  exact(value.powIssuance, [
    'schemeId', 'profileId', 'conformanceClass', 'roleBits', 'difficultyBits',
    'maximumTokenAllowance', 'maximumCellSizeClass', 'maximumCellLeaseClass'
  ], 'powIssuance')
  const powIssuance = {
    schemeId: integer(value.powIssuance.schemeId, 'powIssuance.schemeId',
      PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1, PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1),
    profileId: integer(value.powIssuance.profileId, 'powIssuance.profileId',
      PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1, PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1),
    conformanceClass: integer(value.powIssuance.conformanceClass, 'powIssuance.conformanceClass', 1, 1),
    roleBits: integer(value.powIssuance.roleBits, 'powIssuance.roleBits', 49, 49),
    difficultyBits: integer(value.powIssuance.difficultyBits, 'powIssuance.difficultyBits',
      PEERIT_LIMITED_CELL_PUT_DIFFICULTY_BITS_V1, PEERIT_LIMITED_CELL_PUT_DIFFICULTY_BITS_V1),
    maximumTokenAllowance: integer(value.powIssuance.maximumTokenAllowance,
      'powIssuance.maximumTokenAllowance', 1, PEERIT_LIMITED_CELL_PUT_MAX_TOKEN_ALLOWANCE_V1),
    maximumCellSizeClass: integer(value.powIssuance.maximumCellSizeClass,
      'powIssuance.maximumCellSizeClass', 1, PEERIT_LIMITED_CELL_PUT_MAX_SIZE_CLASS_V1),
    maximumCellLeaseClass: integer(value.powIssuance.maximumCellLeaseClass,
      'powIssuance.maximumCellLeaseClass', 1, PEERIT_LIMITED_CELL_PUT_MAX_LEASE_CLASS_V1)
  }

  if (!Array.isArray(value.supportedProtocolProfiles) ||
      value.supportedProtocolProfiles.length !== 4) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'four protocol profile pins are required')
  }
  const supportedProtocolProfiles = value.supportedProtocolProfiles.map(profileHashRow)
  if (supportedProtocolProfiles.some((row, index) => row.protocolId !== index + 1)) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'protocol profile pins must be sorted 1 through 4')
  }

  if (!Array.isArray(value.supportedTransportProfiles) ||
      value.supportedTransportProfiles.length !== 1) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'one direct HTTPS profile pin is required')
  }
  const transport = exact(value.supportedTransportProfiles[0], [
    'transportId', 'transportSupportBit', 'transportProfileHash'
  ], 'supportedTransportProfiles[0]')
  const supportedTransportProfiles = [{
    transportId: integer(transport.transportId, 'transportId', 1, 1),
    transportSupportBit: integer(transport.transportSupportBit, 'transportSupportBit', 1, 1),
    transportProfileHash: fromHex(hex32(transport.transportProfileHash, 'transportProfileHash'))
  }]

  // CELL.PUT is the admitted write; the paired CELL.GET requirement qualifies
  // the same endpoint for the write path's own authenticated readback.
  const requirement = operationRequirement(value.requirement, 'requirement', 1)
  const readRequirement = operationRequirement(value.readRequirement, 'readRequirement', 2)

  if (!Array.isArray(value.relays) || value.relays.length !== 2) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'exactly two relay admission pins are required')
  }
  const relays = value.relays.map(relayRow)

  return immutable({
    schema: value.schema,
    version: 1,
    releaseSequence: expectedSequence,
    mode: value.mode,
    ordinaryDelivery: value.ordinaryDelivery,
    networkPuts: 1,
    maximumDescriptorHistory: 4096,
    powIssuance,
    supportedProtocolProfiles,
    supportedTransportProfiles,
    requirement,
    readRequirement,
    relays
  })
}

// The deterministic profile source a ceremony signs: canonical pretty JSON,
// exactly what verifyPeeritLimitedCellPutProfileV1 re-reads byte-for-byte.
export function peeritLimitedCellPutProfileSourceV1 (options = {}) {
  const releaseSequence = options.releaseSequence == null
    ? PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE
    : integer(options.releaseSequence, 'release sequence', PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE)
  const relays = options.relays
  if (!Array.isArray(relays) || relays.length !== 2) {
    fail('PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID', 'exactly two relay pins are required')
  }
  const rows = relays.map((relay, index) => ({
    relayId: relay.relayId,
    relayPublicKey: bytesToHex(fromHex(hex32(relay.relayPublicKey, `relays[${index}].relayPublicKey`))),
    issuanceUrl: relay.issuanceUrl,
    admissionProfile: {
      profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
      schemeId: PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1,
      conformanceClass: 1,
      roleBits: 49,
      parameterUrl: null
    }
  }))
  return JSON.stringify({
    schema: 'peerit-limited-cell-put-profile-v1',
    version: 1,
    releaseSequence,
    mode: 'explicit-user-writes',
    ordinaryDelivery: 'local-only',
    networkPuts: 1,
    maximumDescriptorHistory: 4096,
    powIssuance: {
      schemeId: PEERIT_LIMITED_CELL_PUT_SCHEME_ID_V1,
      profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
      conformanceClass: 1,
      roleBits: 49,
      difficultyBits: PEERIT_LIMITED_CELL_PUT_DIFFICULTY_BITS_V1,
      maximumTokenAllowance: PEERIT_LIMITED_CELL_PUT_MAX_TOKEN_ALLOWANCE_V1,
      maximumCellSizeClass: PEERIT_LIMITED_CELL_PUT_MAX_SIZE_CLASS_V1,
      maximumCellLeaseClass: PEERIT_LIMITED_CELL_PUT_MAX_LEASE_CLASS_V1
    },
    supportedProtocolProfiles: options.supportedProtocolProfiles,
    supportedTransportProfiles: options.supportedTransportProfiles,
    requirement: {
      familyId: 2,
      operationId: 1,
      endpointId: 1,
      requiredRoleBits: 49,
      privacyProfileBit: 1,
      transportSupportBit: 1
    },
    readRequirement: {
      familyId: 2,
      operationId: 2,
      endpointId: 1,
      requiredRoleBits: 49,
      privacyProfileBit: 1,
      transportSupportBit: 1
    },
    relays: rows
  }, null, 2) + '\n'
}
