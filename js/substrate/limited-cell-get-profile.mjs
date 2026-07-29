import { asBytes, bytesToHex } from './release-control-primitives.mjs'

export const PEERIT_LIMITED_CELL_GET_PROFILE_PATH_V1 =
  '/peerit-limited-cell-get-profile-v1.json'
export const PEERIT_LIMITED_CELL_GET_ARTIFACT_PATH_V1 =
  '/vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.mjs'
export const PEERIT_LIMITED_CELL_GET_MANIFEST_PATH_V1 =
  '/vendor/hiverelay-blind-cell-get-v1/blind-client-cell-get-v1.manifest.cenc'

const HEX_32 = /^[0-9a-f]{64}$/
const decoder = new TextDecoder('utf-8', { fatal: true })
const encoder = new TextEncoder()
export const PEERIT_LIMITED_CELL_GET_PARAMETER_URL_V1 =
  'https://evidence.example:443/admission.cenc'

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', `${field} fields are missing or unexpected`)
  }
  return value
}

function integer (value, field, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', `${field} is outside its bound`)
  }
  return value
}

function hex32 (value, field) {
  if (!HEX_32.test(String(value || ''))) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', `${field} must be lowercase 32-byte hexadecimal`)
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

function admissionProfile (value, relayId) {
  exact(value, [
    'profileId', 'schemeId', 'conformanceClass', 'roleBits',
    'parameterUrl', 'parameterHash'
  ], `${relayId}.admissionProfile`)
  if (value.parameterUrl !== PEERIT_LIMITED_CELL_GET_PARAMETER_URL_V1) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID',
      `${relayId} admission parameterUrl must match the exact signed evidence hint`)
  }
  return {
    profileId: integer(value.profileId, `${relayId}.profileId`, 7, 7),
    schemeId: integer(value.schemeId, `${relayId}.schemeId`, 9, 9),
    conformanceClass: integer(value.conformanceClass, `${relayId}.conformanceClass`, 1, 1),
    roleBits: integer(value.roleBits, `${relayId}.roleBits`, 49, 49),
    parameterUrl: encoder.encode(value.parameterUrl),
    parameterHash: fromHex(hex32(value.parameterHash, `${relayId}.parameterHash`))
  }
}

export function verifyPeeritLimitedCellGetProfileV1 (input, options = {}) {
  const bytes = new Uint8Array(asBytes(input, 'limited Cell-GET profile'))
  let source
  let value
  try {
    source = decoder.decode(bytes)
    value = JSON.parse(source)
  } catch {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'limited Cell-GET profile is not canonical JSON')
  }
  if (JSON.stringify(value, null, 2) + '\n' !== source) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'limited Cell-GET profile bytes are not canonical pretty JSON')
  }
  exact(value, [
    'schema', 'version', 'releaseSequence', 'mode', 'ordinaryDelivery',
    'networkPuts', 'maximumDescriptorHistory', 'hiveCellGet',
    'supportedProtocolProfiles', 'supportedTransportProfiles', 'requirement',
    'relays'
  ], 'limited Cell-GET profile')
  const expectedSequence = integer(options.releaseSequence, 'expected release sequence', 15)
  if (value.schema !== 'peerit-limited-cell-get-profile-v1' || value.version !== 1 ||
      value.releaseSequence !== expectedSequence || value.mode !== 'seed-recovery-only' ||
      value.ordinaryDelivery !== 'local-only' || value.networkPuts !== 0 ||
      value.maximumDescriptorHistory !== 4096) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'limited Cell-GET release posture is invalid')
  }

  exact(value.hiveCellGet, [
    'artifactPath', 'manifestPath', 'artifactHash', 'manifestHash'
  ], 'hiveCellGet')
  if (value.hiveCellGet.artifactPath !== PEERIT_LIMITED_CELL_GET_ARTIFACT_PATH_V1 ||
      value.hiveCellGet.manifestPath !== PEERIT_LIMITED_CELL_GET_MANIFEST_PATH_V1 ||
      hex32(value.hiveCellGet.artifactHash, 'hiveCellGet.artifactHash') !==
        bytesToHex(options.hive.artifactHash) ||
      hex32(value.hiveCellGet.manifestHash, 'hiveCellGet.manifestHash') !==
        bytesToHex(options.hive.manifestHash)) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'limited profile does not bind the authenticated Hive artifact')
  }

  if (!Array.isArray(value.supportedProtocolProfiles) ||
      value.supportedProtocolProfiles.length !== 4) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'four protocol profile pins are required')
  }
  const supportedProtocolProfiles = value.supportedProtocolProfiles.map(profileHashRow)
  if (supportedProtocolProfiles.some((row, index) => row.protocolId !== index + 1)) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'protocol profile pins must be sorted 1 through 4')
  }

  if (!Array.isArray(value.supportedTransportProfiles) ||
      value.supportedTransportProfiles.length !== 1) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'one direct HTTPS profile pin is required')
  }
  const transport = exact(value.supportedTransportProfiles[0], [
    'transportId', 'transportSupportBit', 'transportProfileHash'
  ], 'supportedTransportProfiles[0]')
  const supportedTransportProfiles = [{
    transportId: integer(transport.transportId, 'transportId', 1, 1),
    transportSupportBit: integer(transport.transportSupportBit, 'transportSupportBit', 1, 1),
    transportProfileHash: fromHex(hex32(transport.transportProfileHash, 'transportProfileHash'))
  }]

  exact(value.requirement, [
    'familyId', 'operationId', 'endpointId', 'requiredRoleBits',
    'privacyProfileBit', 'transportSupportBit'
  ], 'requirement')
  const requirement = {
    familyId: integer(value.requirement.familyId, 'requirement.familyId', 2, 2),
    operationId: integer(value.requirement.operationId, 'requirement.operationId', 2, 2),
    endpointId: integer(value.requirement.endpointId, 'requirement.endpointId', 1, 1),
    requiredRoleBits: integer(value.requirement.requiredRoleBits, 'requirement.requiredRoleBits', 49, 49),
    privacyProfileBit: integer(value.requirement.privacyProfileBit, 'requirement.privacyProfileBit', 1, 1),
    transportSupportBit: integer(value.requirement.transportSupportBit, 'requirement.transportSupportBit', 1, 1)
  }

  if (!Array.isArray(value.relays) || value.relays.length !== 2) {
    fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'exactly two relay admission pins are required')
  }
  const relays = value.relays.map((row, index) => {
    exact(row, ['relayId', 'admissionProfile'], `relays[${index}]`)
    if (row.relayId !== ['dal-1', 'syd-1'][index]) {
      fail('PEERIT_LIMITED_CELL_GET_PROFILE_INVALID', 'relay admission pins must be sorted dal-1, syd-1')
    }
    return { relayId: row.relayId, admissionProfile: admissionProfile(row.admissionProfile, row.relayId) }
  })

  return immutable({
    schema: value.schema,
    version: 1,
    releaseSequence: expectedSequence,
    mode: value.mode,
    ordinaryDelivery: value.ordinaryDelivery,
    networkPuts: 0,
    maximumDescriptorHistory: 4096,
    hiveCellGet: { ...value.hiveCellGet },
    supportedProtocolProfiles,
    supportedTransportProfiles,
    requirement,
    relays
  })
}
