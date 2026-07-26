const OWNER = Object.freeze({
  PEERIT: 'peerit-profile',
  HIVERELAY: 'hiverelay-substrate'
})

export const PROFILE_CATEGORIES = Object.freeze([
  Object.freeze({ id: 'release-control', owner: OWNER.PEERIT, schemaCount: 5 }),
  Object.freeze({ id: 'custody', owner: OWNER.PEERIT, schemaCount: 5 }),
  Object.freeze({ id: 'qualification-evidence', owner: OWNER.PEERIT, schemaCount: 8 }),
  Object.freeze({ id: 'availability-bootstrap', owner: OWNER.PEERIT, schemaCount: 9 }),
  Object.freeze({ id: 'announcement', owner: OWNER.PEERIT, schemaCount: 1 }),
  Object.freeze({ id: 'replica-authority', owner: OWNER.PEERIT, schemaCount: 9 }),
  Object.freeze({ id: 'discovery-index', owner: OWNER.PEERIT, schemaCount: 9 }),
  Object.freeze({ id: 'maintainer-discovery', owner: OWNER.PEERIT, schemaCount: 11 }),
  Object.freeze({ id: 'manifest-authority', owner: OWNER.PEERIT, schemaCount: 1 }),
  Object.freeze({ id: 'migration-archive', owner: OWNER.PEERIT, schemaCount: 16 }),
  Object.freeze({ id: 'local-security', owner: OWNER.PEERIT, schemaCount: 3 }),
  Object.freeze({ id: 'web-release', owner: OWNER.PEERIT, schemaCount: 1 })
])

const SOURCE_HASHES = Object.freeze({
  SubstrateTupleV1: '1591fffdcf846be527e5a1c0431acf2b5dcaa5c923db6e3337bafd5158cb22df',
  PeeritHiveRelayProfilePinV1: 'a0cdb6195a25604219ee8f246d22cb7c7fd8aa5fa6725dfa7bf7dac37829bdec',
  PeeritPinHistoryCheckpointV1: '970327d1ba4eb5b9ece0395d8515a37e32884bb0b4b1f828455137950bd4d91b',
  PeeritPinHistoryBundleV1: '7459ef8cb25930fdeb75a55caeb25e68665959ebfb547e693efcb4b8ac151677',
  PeeritReleaseAuthorityTransitionV1: 'a9de554ca8cafc50bf5b9d209f6a5ff788b26145090fd20a7c06411eea425eb3',
  PeeritCustodySeedPayloadV1: '7255f476294a5d0f8d6e3b3e9bb3c373065e2a7008ebcc7776f2adfe1ac94a17',
  InboxManagementEntryV1: '898162c532d73c70c873ec5000b3390deb768f0cd21716c8e009aa3a62aa74cc',
  PeeritInboxManagementBundleV1: 'fc0b62e3eb18c3d65fba4b03eca31cfa83bac08939b74e028b677e0ea3edfaa1',
  PeeritCustodyEncryptedShareV1: '3cb39b69323417a54cc3fc1bdbbf492b6db5cc02cdf693b26cf261e0d71e50e4',
  PeeritCustodyEnvelopeV1: '7591af2e19407e02dbddd68cb24c06d99c87d65e2e794ff60f44c0044d6c395a',
  PeeritMigrationTransitionEvidenceV1: '0d5b2799c38468c61992e446d7e668532cbe310de060323c3edc7f3dbecaacbf',
  PeeritWriteOperationEvidenceV1: '14ea10a45fa68c85d4d4e209354d09cc9d3c613ce78f373e8f6506703bc8af2c',
  PeeritWriteOperationEvidenceShardV1: '4644f97b62a2181c188ef0b84675d120435b4a42a2b150192f053bc0ba9e3982',
  PeeritWriteOperationEvidenceShardRefV1: 'bc5849af2fa13a4d48e87a8565e2b73b6db3fad990928f1238738613ba1175b0',
  PeeritWriteOperationEvidenceManifestV1: 'd46220b57a246313b9e1822a0433311cffeae328fc7fa7473902f72ca37cde08',
  PeeritWriteRuntimeEvidenceV1: 'c090b665943d4fec440b0d1afd4149a34b2129ea8199ec48159a5d10f79a4c8d',
  PeeritWriteSupportingEvidenceManifestV1: '04dbf9a21cb0f944755a941e32091bcb96d7f05098f4e732f221104fdf1e9c9f',
  PeeritReleaseQualificationEvidenceBundleV1: '56cd31ee113dccf7e798a5671a29e99deca464fde3537767d6ec18ee5596b7f8',
  AvailabilityRootV1: '671ec881166d5f3e17905e2497685a468dbab587dd124d68a2064eb7f28f9299',
  AvailabilityPolicyV1: 'f8a451f45f4c2d8c17ac6b57b81e8224f3843b5b3d4022b6e7a4435e9e6c95c6',
  PeeritOperatorGroupRegistryV1: '6476729520ab027248e8cdada1219439201eccc885ba6245a813dfc00123fc7f',
  DiscoveryMaintainerLogBindingV1: '65903baf95cbdcd61fd3d78ced240a7f83c509ea4e391c8db8930580b2648277',
  MaintainerIngressBindingV1: '071b44265ae44a968031cf27d599a5f712a7ceccc77ff335d4f07515b9abc28c',
  AvailabilityBootstrapV1: '592ce7cf70d2be3138dd8fae14a40136f1709350b5df7d507d0a32ec44751018',
  InboxEpochSetV1: 'fade5e5abd0b9436e0f7f77271da032d0f2f627d4f32337fa2fd24b79ccc8d2c',
  InboxStripeBindingV1: '28d110d2e256cbfab0bd12be2303fda0535307f762f9198df3c9d65c7a0da5ac',
  RootRotateV1: '93847bdfd5f4d16c44752028d1a095b8e83a374d0cb9e0da2cc40027e02fe14d',
  PeeritAnnouncementV1: '4671b700aa6fe42f61db81afa1ee61e9e3fd619b76b3e3037fc523424e1022ff',
  CellReplicaBindingV1: 'f14b42a1d2497e67ace723a285d7c645719c15e89204b8f3fa863a5b28a6dbf7',
  CoreReplicaBindingV1: '28e84095822c0af86189065babcc7b88ecbce0c105b77c9dcdc995d0fb57bd04',
  ReplicaBindingV1: '1eed230a836b2bdfc1628fd8943970313b9efdd09b46f9d994f413886c3c2b58',
  AuthorBindV1: 'f3aea18d72625b87c67e1e18302d4ed23d55c6981f216f595a9239c2905c7297',
  RepairAddV1: '87b4c649b266b9864db88014dc39e207bfa5ca138805b2b25caeea3478dde458',
  ChargedProbeEvidenceV1: '26ef8e5c8981736d00b56a010e1fccebc85eab98b1d8f97144593a650f265c3e',
  RelayProbeEvidenceSetV1: '6e576ac5ee223406a10aa420678cf9dff9792b059104497b46de657f8f96dae9',
  DiscoveryAvailabilityEntryV1: '1ccb885351e5a15bf9b960e3a7e504b5c2f0f506fbc1a043b1761849fd716342',
  DiscoveryIndexChildV1: '765477e1e39527aad806bea4b54bd17b7b15a9a7d97b8de4c0b08d182d1b8537',
  DiscoveryIndexBranchV1: '6fc1383fe540b3b700509ed216648ddb7e106c5e4f6089ec9a054b05ce83da9a',
  DiscoveryMembershipLeafV1: 'f1c473ef5f70ce2c6322030ae156139b0ed2c0830d854a99bac0f23fbdb6aec2',
  DiscoveryAvailabilityLeafV1: '2f573680c3cc0ca7b29b3ce6fdc29772dc85e02e6feed140789e9b3a53a4178d',
  DiscoveryIndexNodeV1: '102ce72f7f9c073c2e7968942cb6de322ac134a7d3cd54f3fb844b3b73d71ca9',
  DiscoveryRecentBucketV1: '6720d062ae577c79de43a13c5e22a9ed75c0ea20ecfce4797694d38c0b850d7b',
  DiscoveryIndexQueryV1: 'a992a0933520ac60372c5d3f93d2429da6cc9fb101b9129d366619316d1a30cc',
  DiscoveryIndexProofV1: '1d1a252409091e766d8a9f4024c5593dcac41f08ae7629ad174b07433350fb41',
  MaintainerSubmitV1: '84442d921552b35372232fcbcaf9ca7db93a2b9ea65ed2a7e1d669acbe54b44f',
  MaintainerSubmitResultV1: '4f115e014cbe524b8b9fc7e5f2ecc427f80bde2d5593b1c07c2160d28571d3e5',
  MaintainerObservationV1: 'ad8d9ae67384de5bee173a37994314ce48793770b56e91cb605679e63b5307d2',
  MaintainerObservationReceiptV1: 'cecb3e92a6755129db7510e093cc76b84875406c352be5cae0a1fe5935478e46',
  MaintainerObservationHeadV1: '6fac6ca5b905d30baaedb97b07681d02a0b596c8eeb25dc9090800e959ae8866',
  DiscoveryProposalV1: 'c0bfd4caf681f72f4d42d5d113e429aedbfc89f22b7a9bffbec589d1d14f691b',
  DiscoverySnapshotV1: '83f7a79f89519e4e2ed7ee7e97032481c7e0a19c8b68a3246286f80519b66aee',
  DiscoveryCheckpointV1: '63ff815782d2718fe74c284d6428eebae78a5a843070e527fadc6a00cd279528',
  DiscoveryFloorV1: 'bb1ab329fbc8fc99500e555d5fdbcaa3793f6205bfb5254adc4e358fa0d9312d',
  DiscoveryRecoveryParentV1: '8a5e7496b6819272958c83eca890107decc1ff789f84b705d1829dba127d862f',
  DiscoveryRecoveryMergeV1: 'dde6f42f44df8e9ae2fc63ec6b7ffeb08d4f10f47e3c79b01db80517c9d12164',
  MigrationGenesisV1: 'dc7aae68fb16c2348d0d52dff5908cc5be2fa8627aa78add8dcf9db6433b0613',
  ManifestRecordV1: 'b45f8c8765f158f38ed38e861aa8608f8aa49006c9c28461cb02314bb7223fd5',
  CoreObjectChunkV1: '10463f9416075ea480a730b66bd0eec63d236df424b7e4cabda0a6af0cd61dd5',
  LegacySourceV1: '6bf6e263d652be1048717be3b713f07cd8f7eca4c4ec4c0497fe86409d4b0eae',
  LegacySourceSetV1: 'd909ea024785ce933568481ac75ce8731411a113ad74dfdc90546695794cfccf',
  LegacySourceCutoffV1: '2e5e3e157f7ecc5f8be0609cccc310ab307711531d7ec6afd6ce9e826cef734e',
  LegacyCutoffV1: '536794270e2f19151bc7530e2179577114a16ff8fade2ec500353f433861f43e',
  LegacyArchiveDistributionV1: '182c407345027a24ec94ab8ca6fd4e9cba867725a60730b4698675b28d010b23',
  LegacyProvenanceV1: '1af689039444ab7beffee7cd855af5e76d2df890dd74d6bca8b0e00db58fdb45',
  LegacyValidRecordEntryV1: '14edd800fad70443950cb95938047d863a80aa5eb7ca6e148152f3da4d253fb0',
  LegacyInvalidRecordEntryV1: 'b83e23086148d0dd93de27530ef4cc81f131b7d9978f44f4144e35ea8104656a',
  LegacyMissingRangeEntryV1: '5b99fe9634d53cbf9d25908cde2ad7fdd480f15468d08229d68ad4801c602bb8',
  LegacyArchiveEntryV1: 'b39f55d33eb78f8084ceba33f97bf4c089093d9588caede153ffead23cec7246',
  LegacyArchiveIndexEntryV1: 'f0fd3097625ea0d0f03883e942c112a3b40b1309cdb36e6dbe0a7d1333a51c4b',
  LegacyArchiveIndexV1: '5fb9773efde31827bd9e43f14ad5d32dc154a7ea991ee682f926791e79b7d4e9',
  PeeritLegacyArchiveV1: 'ddb5c494f3284b00e17a7d59df6d83dc03aaca1bff71cefc4caf36922f1296d6',
  LegacyArchiveBundleV1: '4fb9be96ddd5b0f28577aec672b1c61d4aeb91e998c5f2d0a0a5f1c0ca7ce528',
  LegacyRetirementEvidenceV1: '5682b2f35e62fdc76428a1506470db8fac02fe168d0e3e5543f78bdfd5ced291',
  LocalAccountRecordV1: 'f1e84c2f3d8d9fa32ca50ac9821834660dab63e5e900a1d9df04100dbc76bbe9',
  PeeritRecoveryBundleV1: '127b108fd6bb3f05dc0d89d1a2b20268684a07d05ce583b0ad98bcaf6dbcce00',
  DeviceChainStartV1: 'c0bf52a841e40d6a6378b39a5324dd637afb86053253dd7c5b98a38f1356b914',
  WebAssetManifestV1: 'a27b262741553c97553b588565e74594900ee20d013a7113cbeeea30c7e2df6b',
  PeeritInnerOperationBatchV1: '480568025f957858f92536a6e928d8332616639f13589e1b90fae255daae97ea'
})

function shape (ordinal, depth, relativeLine, sha256) {
  return Object.freeze({ ordinal, depth, relativeLine, sha256 })
}

function schema (name, category, dependencies = [], inlineShapes = [], kind = 'record') {
  return Object.freeze({
    name,
    kind,
    category,
    owner: OWNER.PEERIT,
    sourceSha256: SOURCE_HASHES[name],
    dependencies: Object.freeze([...dependencies].sort()),
    inlineShapes: Object.freeze(inlineShapes)
  })
}

export const PROFILE_SCHEMAS = Object.freeze([
  schema('SubstrateTupleV1', 'release-control'),
  schema('PeeritHiveRelayProfilePinV1', 'release-control', ['PeeritMigrationStageV1', 'SubstrateTupleV1']),
  schema('PeeritPinHistoryCheckpointV1', 'release-control'),
  schema('PeeritPinHistoryBundleV1', 'release-control', ['PeeritHiveRelayProfilePinV1', 'PeeritPinHistoryCheckpointV1']),
  schema('PeeritReleaseAuthorityTransitionV1', 'release-control'),

  schema('PeeritCustodySeedPayloadV1', 'custody'),
  schema('InboxManagementEntryV1', 'custody', ['InboxReceiptV1', 'InboxStripeBindingV1']),
  schema('PeeritInboxManagementBundleV1', 'custody', ['InboxManagementEntryV1']),
  schema('PeeritCustodyEncryptedShareV1', 'custody'),
  schema('PeeritCustodyEnvelopeV1', 'custody', ['PeeritCustodyEncryptedShareV1', 'PeeritCustodySeedPayloadV1', 'PeeritInboxManagementBundleV1']),

  schema('PeeritMigrationTransitionEvidenceV1', 'qualification-evidence'),
  schema('PeeritWriteOperationEvidenceV1', 'qualification-evidence'),
  schema('PeeritWriteOperationEvidenceShardV1', 'qualification-evidence', ['PeeritWriteOperationEvidenceV1']),
  schema('PeeritWriteOperationEvidenceShardRefV1', 'qualification-evidence'),
  schema('PeeritWriteOperationEvidenceManifestV1', 'qualification-evidence', ['PeeritWriteOperationEvidenceShardRefV1']),
  schema('PeeritWriteRuntimeEvidenceV1', 'qualification-evidence'),
  schema('PeeritWriteSupportingEvidenceManifestV1', 'qualification-evidence', [], [
    shape(1, 1, 6, '09fb84aa0c1a58c5431170c267c25644e4dc72f90d6eea06dc064bcf650dc3d8')
  ]),
  schema('PeeritReleaseQualificationEvidenceBundleV1', 'qualification-evidence', ['PeeritWriteRuntimeEvidenceV1', 'SubstrateTupleV1']),

  schema('AvailabilityRootV1', 'availability-bootstrap'),
  schema('AvailabilityPolicyV1', 'availability-bootstrap'),
  schema('PeeritOperatorGroupRegistryV1', 'availability-bootstrap', [], [
    shape(1, 1, 6, '8f0b7e1b9b4e1e000012f8e886d5727a731a051c53a3c08da01b745dd4edb40d'),
    shape(2, 1, 13, '6a73b764e5f668582b719a77ac14b1b5da7a94045249474e17d0014463f21d06'),
    shape(3, 2, 19, 'cc332e1bfab09d1c6657c67aea09516449f27c1d7a184c4040b50813e45f0367'),
    shape(4, 2, 29, '96d50967302b64e7172a9469f1d5801f0bcbcd2d283340e8f253c0e607a64781')
  ]),
  schema('DiscoveryMaintainerLogBindingV1', 'availability-bootstrap', ['CoreReplicaBindingV1']),
  schema('MaintainerIngressBindingV1', 'availability-bootstrap'),
  schema('AvailabilityBootstrapV1', 'availability-bootstrap', ['DiscoveryMaintainerLogBindingV1', 'InboxEpochSetV1', 'MaintainerIngressBindingV1', 'ReplicaBindingV1', 'SubstrateTupleV1']),
  schema('InboxEpochSetV1', 'availability-bootstrap', ['InboxStripeBindingV1']),
  schema('InboxStripeBindingV1', 'availability-bootstrap', ['InboxReceiptV1']),
  schema('RootRotateV1', 'availability-bootstrap', ['ReadCellCapV1', 'ReplicaBindingV1'], [
    shape(1, 1, 13, 'f60b16f18d18488fbf0d9f723e19ef1851d6954dfed1f00a426b5ee63cc65c32')
  ]),

  schema('PeeritAnnouncementV1', 'announcement', ['ReadCellCapV1']),

  schema('CellReplicaBindingV1', 'replica-authority', ['BlindReceiptV1', 'ReadCellCapV1']),
  schema('CoreReplicaBindingV1', 'replica-authority', ['BlindCoreAckV1', 'BlindCoreReadCapV1']),
  schema('ReplicaBindingV1', 'replica-authority', ['CellReplicaBindingV1', 'CoreReplicaBindingV1'], [], 'tagged-union'),
  schema('AuthorBindV1', 'replica-authority', ['CellReplicaBindingV1', 'PeeritInnerOperationBatchV1']),
  schema('RepairAddV1', 'replica-authority', ['ReplicaBindingV1']),
  schema('ChargedProbeEvidenceV1', 'replica-authority'),
  schema('RelayProbeEvidenceSetV1', 'replica-authority', ['ChargedProbeEvidenceV1'], [
    shape(1, 1, 11, '72cc9a87febab6008becccb9ef32ddb24ef234acaf7d7cc89b19f6d4eaf47da4')
  ]),
  schema('CoreObjectChunkV1', 'replica-authority'),

  schema('DiscoveryAvailabilityEntryV1', 'discovery-index', ['ReadCellCapV1']),
  schema('DiscoveryIndexChildV1', 'discovery-index', ['ReadCellCapV1']),
  schema('DiscoveryIndexBranchV1', 'discovery-index', ['DiscoveryIndexChildV1']),
  schema('DiscoveryMembershipLeafV1', 'discovery-index'),
  schema('DiscoveryAvailabilityLeafV1', 'discovery-index', ['DiscoveryAvailabilityEntryV1']),
  schema('DiscoveryIndexNodeV1', 'discovery-index', ['DiscoveryAvailabilityLeafV1', 'DiscoveryIndexBranchV1', 'DiscoveryMembershipLeafV1'], [], 'tagged-union'),
  schema('DiscoveryRecentBucketV1', 'discovery-index', ['ReadCellCapV1'], [
    shape(1, 1, 12, 'b5f4c4e42e12bf73e7e9798942a84f8e61cf1f309302e5f2d681c6b790713f0c')
  ]),
  schema('DiscoveryIndexQueryV1', 'discovery-index', [], [
    shape(1, 1, 2, '6690e8fdadc56fe8037c459608d621938bb886955244079c85f4eba15c69d698'),
    shape(2, 1, 3, '95e67e465dc1d5128245a6f86602a966e3eead0165d6fdf3b25a4f14ac31be9d')
  ], 'tagged-union'),
  schema('DiscoveryIndexProofV1', 'discovery-index', ['DiscoveryIndexQueryV1'], [
    shape(1, 1, 9, '77207852e89aa1ce2ec3926273785fc22379140c94840527b0608255f1502f4f')
  ]),

  schema('MaintainerSubmitV1', 'maintainer-discovery', ['InboxAppendAckV1', 'PeeritAnnouncementV1']),
  schema('MaintainerSubmitResultV1', 'maintainer-discovery', ['MaintainerObservationReceiptV1']),
  schema('MaintainerObservationV1', 'maintainer-discovery', ['PeeritAnnouncementV1']),
  schema('MaintainerObservationReceiptV1', 'maintainer-discovery'),
  schema('MaintainerObservationHeadV1', 'maintainer-discovery', ['CoreReplicaBindingV1']),
  schema('DiscoveryProposalV1', 'maintainer-discovery', ['DiscoverySnapshotV1', 'MaintainerObservationHeadV1', 'ReadCellCapV1']),
  schema('DiscoverySnapshotV1', 'maintainer-discovery', ['ReadCellCapV1'], [
    shape(1, 1, 26, '72cc9a87febab6008becccb9ef32ddb24ef234acaf7d7cc89b19f6d4eaf47da4')
  ]),
  schema('DiscoveryCheckpointV1', 'maintainer-discovery', ['ReadCellCapV1'], [
    shape(1, 1, 19, '72cc9a87febab6008becccb9ef32ddb24ef234acaf7d7cc89b19f6d4eaf47da4')
  ]),
  schema('DiscoveryFloorV1', 'maintainer-discovery'),
  schema('DiscoveryRecoveryParentV1', 'maintainer-discovery', ['DiscoveryFloorV1', 'ReadCellCapV1']),
  schema('DiscoveryRecoveryMergeV1', 'maintainer-discovery', ['DiscoveryRecoveryParentV1', 'ReadCellCapV1']),

  schema('ManifestRecordV1', 'manifest-authority', ['AuthorBindV1', 'AvailabilityRootV1', 'DiscoveryCheckpointV1', 'DiscoverySnapshotV1', 'MigrationGenesisV1', 'RelayProbeEvidenceSetV1', 'RepairAddV1', 'RootRotateV1'], [], 'tagged-union'),

  schema('MigrationGenesisV1', 'migration-archive', ['ReplicaBindingV1']),
  schema('LegacySourceV1', 'migration-archive'),
  schema('LegacySourceSetV1', 'migration-archive', ['LegacySourceV1']),
  schema('LegacySourceCutoffV1', 'migration-archive'),
  schema('LegacyCutoffV1', 'migration-archive', ['LegacySourceCutoffV1']),
  schema('LegacyArchiveDistributionV1', 'migration-archive', [], [
    shape(1, 1, 5, '3dcbcea9db1d0d2b1afe6d470b6b1ebfc0d59dfa1101ab5cff081fc6d2d40a70')
  ]),
  schema('LegacyProvenanceV1', 'migration-archive'),
  schema('LegacyValidRecordEntryV1', 'migration-archive', ['LegacyProvenanceV1', 'ReplicaBindingV1']),
  schema('LegacyInvalidRecordEntryV1', 'migration-archive', ['LegacyProvenanceV1', 'LegacyValidatorReasonCodeV1']),
  schema('LegacyMissingRangeEntryV1', 'migration-archive', ['LegacyMissingReasonCodeV1']),
  schema('LegacyArchiveEntryV1', 'migration-archive', ['LegacyInvalidRecordEntryV1', 'LegacyMissingRangeEntryV1', 'LegacyValidRecordEntryV1'], [], 'tagged-union'),
  schema('LegacyArchiveIndexEntryV1', 'migration-archive'),
  schema('LegacyArchiveIndexV1', 'migration-archive', ['LegacyArchiveIndexEntryV1']),
  schema('PeeritLegacyArchiveV1', 'migration-archive', ['LegacyArchiveEntryV1', 'LegacyCutoffV1']),
  schema('LegacyArchiveBundleV1', 'migration-archive', ['LegacyArchiveDistributionV1', 'LegacyArchiveIndexV1', 'PeeritLegacyArchiveV1']),
  schema('LegacyRetirementEvidenceV1', 'migration-archive'),

  schema('LocalAccountRecordV1', 'local-security'),
  schema('PeeritRecoveryBundleV1', 'local-security'),
  schema('DeviceChainStartV1', 'local-security'),

  schema('WebAssetManifestV1', 'web-release', [], [
    shape(1, 1, 6, '5cdc031abaa3ce34ca8481ad574ebd2728ecf762a6b3316f4aa2fee3eda29e52')
  ]),

  // Appended to preserve every existing profile tag.  It is intentionally a
  // local Peerit envelope codec rather than a HiveRelay external wire type.
  schema('PeeritInnerOperationBatchV1', 'replica-authority')
])

function externalType (name, family) {
  return Object.freeze({ name, owner: OWNER.HIVERELAY, family })
}

function externalCodecImport (name, family, minimumBytes, maximumBytes, authorityKind, tupleBinding = null) {
  return Object.freeze({
    name,
    family,
    authorityKind,
    tupleBinding,
    clientSchemaCommitment: null,
    minimumBytes,
    maximumBytes
  })
}

export const EXTERNAL_HIVERELAY_TYPES = Object.freeze([
  externalType('BlindCoreAckV1', 'CORE'),
  externalType('BlindCoreReadCapV1', 'CORE'),
  externalType('BlindExternalCommitWitnessV1', 'DURABILITY'),
  externalType('BlindExternalJournalTopologyV1', 'DURABILITY'),
  externalType('BlindReceiptV1', 'CELL'),
  externalType('BlindRestoreEvidenceBundleV1', 'DURABILITY'),
  externalType('BlindStoreManifestV1', 'DURABILITY'),
  externalType('DurabilityProfileV1', 'DESCRIBE'),
  externalType('InboxAppendAckV1', 'INBOX'),
  externalType('InboxReceiptV1', 'INBOX'),
  externalType('ReadCellCapV1', 'CELL'),
  externalType('RelayResultBindingV1', 'DESCRIBE')
])

export const EXTERNAL_HIVERELAY_CODEC_IMPORTS = Object.freeze([
  externalCodecImport('BlindCoreAckV1', 'CORE', 1, 16384, 'WIRE_TUPLE_V1', 'wire-v1:470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9:aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d:09bd04c86f6f62b4636b9360fd2fca985a63537a0cec8642918f450ec70f9e78'),
  externalCodecImport('BlindCoreReadCapV1', 'CORE', 1, 8192, 'CLIENT_COMPOSITION_V1', 'client-composition-v1:5637708aff4a6e93a6ff3a2f96361aa0b1597c229346e124eebeb2d7618ae09a:ea176ea78a611256689604541e55ba420d426dda2fa4dd64fb3ac9ac7503934d'),
  externalCodecImport('BlindReceiptV1', 'CELL', 1, 16384, 'WIRE_TUPLE_V1', 'wire-v1:470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9:aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d:09bd04c86f6f62b4636b9360fd2fca985a63537a0cec8642918f450ec70f9e78'),
  externalCodecImport('InboxAppendAckV1', 'INBOX', 1, 16384, 'WIRE_TUPLE_V1', 'wire-v1:470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9:aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d:09bd04c86f6f62b4636b9360fd2fca985a63537a0cec8642918f450ec70f9e78'),
  externalCodecImport('InboxReceiptV1', 'INBOX', 1, 16384, 'WIRE_TUPLE_V1', 'wire-v1:470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9:aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d:09bd04c86f6f62b4636b9360fd2fca985a63537a0cec8642918f450ec70f9e78'),
  externalCodecImport('ReadCellCapV1', 'CELL', 99, 131, 'CLIENT_COMPOSITION_V1', 'client-composition-v1:5637708aff4a6e93a6ff3a2f96361aa0b1597c229346e124eebeb2d7618ae09a:ea176ea78a611256689604541e55ba420d426dda2fa4dd64fb3ac9ac7503934d')
])

export const PROFILE_REGISTRIES = Object.freeze([
  Object.freeze({
    name: 'PeeritMigrationStageV1',
    owner: OWNER.PEERIT,
    category: 'release-control',
    kind: 'closed-enum',
    encoding: 'u8',
    values: Object.freeze([
      Object.freeze({ id: 0, name: 'LIVE_DUAL_READ' }),
      Object.freeze({ id: 1, name: 'FROZEN_CUTOFF' }),
      Object.freeze({ id: 2, name: 'ARCHIVE_ONLY' })
    ])
  }),
  Object.freeze({
    name: 'LegacyMissingReasonCodeV1',
    owner: OWNER.PEERIT,
    category: 'migration-archive',
    kind: 'closed-enum',
    encoding: 'u16',
    values: Object.freeze([
      Object.freeze({ id: 1, name: 'SOURCE_UNAVAILABLE' }),
      Object.freeze({ id: 2, name: 'TERMINAL_HEAD_UNAVAILABLE' }),
      Object.freeze({ id: 3, name: 'RANGE_READ_FAILED' }),
      Object.freeze({ id: 4, name: 'RANGE_PROOF_INVALID' }),
      Object.freeze({ id: 5, name: 'SOURCE_DECLARED_GAP' })
    ])
  }),
  Object.freeze({
    name: 'LegacyValidatorReasonCodeV1',
    owner: OWNER.PEERIT,
    category: 'migration-archive',
    kind: 'closed-enum',
    encoding: 'u16',
    values: Object.freeze([
      Object.freeze({ id: 1, name: 'MALFORMED_CANONICAL_BYTES' }),
      Object.freeze({ id: 2, name: 'UNKNOWN_CODEC_OR_TAG' }),
      Object.freeze({ id: 3, name: 'SIGNATURE_INVALID' }),
      Object.freeze({ id: 4, name: 'AUTHORITY_CHAIN_INVALID' }),
      Object.freeze({ id: 5, name: 'HASH_OR_ID_MISMATCH' }),
      Object.freeze({ id: 6, name: 'CAUSAL_OR_SEQUENCE_INVALID' }),
      Object.freeze({ id: 7, name: 'POLICY_LIMIT_EXCEEDED' })
    ])
  })
])

export const PEERIT_PROFILE_INVENTORY = Object.freeze({
  inventoryVersion: 2,
  owner: OWNER.PEERIT,
  schemas: PROFILE_SCHEMAS,
  categories: PROFILE_CATEGORIES,
  externalTypes: EXTERNAL_HIVERELAY_TYPES,
  externalCodecImports: EXTERNAL_HIVERELAY_CODEC_IMPORTS,
  profileRegistries: PROFILE_REGISTRIES
})
