// blind-descriptor-parse.mjs — independent minimal cenc reader for the
// deployed BlindServiceDescriptorV1 wire layout (registry layout verified
// against the public-test release worktree packages/blind-protocol/schemas.js,
// pin-history entry 4). Shares no code with the vendored client verifier; used
// by the bind probe and drills as the independent second implementation.

export class Reader {
  constructor (bytes) {
    this.b = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength)
    this.o = 0
  }

  u8 () { return this.b[this.o++] }
  u16 () { const v = (this.b[this.o] << 8) | this.b[this.o + 1]; this.o += 2; return v }
  u32 () { const v = this.b.readUInt32BE(this.o); this.o += 4; return v }
  u64 () { const v = this.b.readBigUInt64BE(this.o); this.o += 8; return v }

  compactUint () {
    const marker = this.u8()
    if (marker <= 0xfc) return marker
    if (marker === 0xfd) { const v = this.b.readUInt16LE(this.o); this.o += 2; return v }
    if (marker === 0xfe) { const v = this.b.readUInt32LE(this.o); this.o += 4; return v }
    const v = this.b.readBigUInt64LE(this.o); this.o += 8; return Number(v)
  }

  fixed (n) { const v = this.b.slice(this.o, this.o + n); this.o += n; return v }
  optFixed (n) { const tag = this.u8(); if (tag === 0) return null; if (tag !== 1) throw new Error('bad optional tag'); return this.fixed(n) }
  utf8Bounded (max) { const n = this.compactUint(); if (n < 1 || n > max) throw new Error('bounded utf8 out of range'); const v = this.b.slice(this.o, this.o + n); this.o += n; return v }
  optUtf8Bounded (max) { const tag = this.u8(); if (tag === 0) return null; if (tag !== 1) throw new Error('bad optional tag'); return this.utf8Bounded(max) }
}

export function parseDescriptor (bytes) {
  const r = new Reader(bytes)
  const d = {}
  d.version = r.u8()
  if (d.version !== 1) throw new Error(`descriptor version ${d.version}`)
  d.relayPublicKey = r.fixed(32)
  d.storeId = r.fixed(32)
  d.descriptorSequence = r.u64()
  d.previousDescriptorHash = r.optFixed(32)
  d.identitySequence = r.u64()
  d.previousRelayKey = r.optFixed(32)
  if (r.u8() !== 0) throw new Error('unexpected identity transition in probe descriptor')
  d.build = {
    specHash: r.fixed(32),
    abiHash: r.fixed(32),
    vectorSetHash: r.fixed(32),
    evidenceFormatHash: r.fixed(32),
    evidenceVectorSetHash: r.fixed(32),
    storeFormatHash: r.fixed(32),
    storeVectorSetHash: r.fixed(32),
    privateIpcFormatHash: r.fixed(32),
    privateIpcVectorSetHash: r.fixed(32),
    buildArtifactHash: r.fixed(32),
    buildArtifactUrl: r.utf8Bounded(512),
    buildManifestUrl: r.utf8Bounded(512),
    buildManifestHash: r.fixed(32),
    releaseEvidenceBundleUrl: r.utf8Bounded(512),
    releaseEvidenceBundleHash: r.fixed(32),
    releaseSupportHorizonHash: r.fixed(32),
    runtimeBoundaryEvidenceUrl: r.utf8Bounded(512),
    runtimeBoundaryEvidenceHash: r.fixed(32)
  }
  const protocolCount = r.compactUint()
  if (protocolCount < 1 || protocolCount > 16) throw new Error('protocol count out of range')
  d.protocols = []
  for (let i = 0; i < protocolCount; i++) {
    d.protocols.push({ protocolId: r.u16(), major: r.u16(), minor: r.u16(), featureBits: r.u64(), profileHash: r.fixed(32) })
  }
  const endpointCount = r.compactUint()
  if (endpointCount < 1 || endpointCount > 16) throw new Error('endpoint count out of range')
  d.endpoints = []
  for (let i = 0; i < endpointCount; i++) {
    d.endpoints.push({
      endpointId: r.u8(),
      transportId: r.u8(),
      transportProfileHash: r.fixed(32),
      roleBits: r.u16(),
      privacyProfileBits: r.u16(),
      canonicalUrl: r.utf8Bounded(512),
      endpointKey: r.optFixed(32),
      envelopeClassBits: r.u16(),
      wireClassBits: r.u8(),
      maxStreams: r.u16(),
      auxiliaryUrl: r.optUtf8Bounded(512),
      auxiliaryHash: r.optFixed(32)
    })
  }
  d.cellSizeClassBits = r.u8()
  d.leaseClassBits = r.u8()
  d.maxBatchCount = r.u16()
  d.maxResponseBytes = r.u32()
  d.maxSponsoredCoreLength = r.u64()
  d.enabledOperationBits = r.u32()
  const admissionCount = r.compactUint()
  if (admissionCount < 1 || admissionCount > 8) throw new Error('admission profile count out of range')
  d.admissionProfiles = []
  for (let i = 0; i < admissionCount; i++) {
    d.admissionProfiles.push({
      profileId: r.u16(),
      schemeId: r.u16(),
      conformanceClass: r.u8(),
      roleBits: r.u16(),
      parameterUrl: r.optUtf8Bounded(512),
      parameterHash: r.fixed(32)
    })
  }
  d.durability = {
    profileId: r.u8(),
    storeFormatMajor: r.u16(),
    storeFormatMinor: r.u16(),
    storeFormatHash: r.fixed(32),
    externalJournalId: r.fixed(32),
    externalWitnessPublicKey: r.fixed(32),
    externalJournalReplicationClass: r.u8(),
    externalJournalFailureGroupId: r.fixed(32),
    externalCheckpointAgeBand: r.u8(),
    externalJournalTopologyUrl: r.optUtf8Bounded(512),
    externalJournalTopologyHash: r.fixed(32),
    restoreEvidenceFeedUrl: r.optUtf8Bounded(512),
    restoreEvidenceFeedId: r.fixed(32),
    restoreEvidenceCheckpointSequence: r.u64(),
    restoreEvidenceCheckpointHash: r.fixed(32),
    acknowledgedRpoBand: r.u8(),
    targetRtoBand: r.u8(),
    redundancyClass: r.u8(),
    restoreDrillAgeBand: r.u8()
  }
  d.durabilityContinuityHash = r.fixed(32)
  d.durabilityProfileHash = r.fixed(32)
  d.storeLifecycleState = r.u8()
  d.drainStartedEpoch = (() => { const tag = r.u8(); if (tag === 0) return null; if (tag !== 1) throw new Error('bad optional tag'); return r.u32() })()
  d.capacityBand = r.u8()
  d.issuedEpoch = r.u32()
  d.expiresEpoch = r.u32()
  d.descriptorNonce = r.fixed(32)
  d.signedLength = r.o
  d.signature = r.fixed(64)
  d.totalLength = r.o
  return d
}
