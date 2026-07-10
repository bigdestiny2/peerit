// Frozen protocol-v3 action cutover boundary.
//
// Pre-cutover comments, votes, and moderation records carry CID-only targets.
// They remain readable ONLY when their exact Ed25519 signature was present in
// the production inventory while public writes were blocked. A new signature,
// even over an identical legacy shape, is not compatible.
//
// Sources: the signed seed fixture plus the read-only production inventory at
// https://outbox.peerit.site, captured 2026-07-10. Re-audit without mutating the
// relay with:
//
//   node scripts/audit-live-legacy-actions.mjs

export const LEGACY_COMMENT_SIGNATURES = new Set([
  '4b128cb6050f77ca1896857f21ead075e411b2538400b2884be36812c40f7b444a71c2538725843b2091e6c607af4f86686f242a829ae120518a3ebe45aabf03',
  '4bc67666ea329c26b919f4df4592686e34431db4981598df528c4aa9ef0c15c56244f7df4e1775ac43f1d018c9be651a01c0e11d5c7cccdaba097047d27a3001'
])

export const LEGACY_VOTE_SIGNATURES = new Set([
  '0b39aa0cc9606698d47e7a9ecc8960e815ad871ce6b47f4f2ca6c3db48d86d3719f36ec71067a5044034d0ea056545eb918db826d6e48596245872438fdcc607',
  '178e5daaea03862cb5b351558105a4fa7a666d7ff19fb3ba28bdc42d19ef7e7740d70c4c940cbc602bc4c806228895ef09bced258a619ee7ec9ba260da86620e',
  '195a9b3210fe8616d0a286c73c67a861f491aebc4cff69f1fb9679731101f703a7ebcc6af6dcb3ffba2fc91ec626b168f7c02983240404b139a2cbb7274d7d08',
  '1dcdfd37c7290db8ed243ff682672224d1529877990f5685f70c53975f5eb5e1a79357fa69ccd74a96219632de03e1c30124500a1b3a2ea1db3eb3c909f9920e',
  '3312b731e6e3da3b1e2b54a52a460c44127e2d72564876fed32e01e313e13eb34e31d6972aa954ee05bd1c8d976c21457b02c53fa4c3ed07f0c932e4d8b5670a',
  '54f5b7eebcfb52a9d92dade7cd6a1d6abe1e16844cdd3b20ecc21e82e59703a071a43e65e9dc370bba89bf3543e242d3cb8b0a2b6dd5818b7fd66fbc1ad8be0c',
  '6394180e8339dc733afd331c5e4c20b38cf31aeecf3b1ec6be17b0e94fea5cafc8ab89539ed0299e052fdd77445f6db282228f0c2c14a75b2879a5e446399707',
  '70b82d5724da4655115cc3fe7fddcff49ea544bd63ef1e8d0987cdd21613823c764ba54dbe0e911e5b7f351b5bbfd7849d738dd39172f0c238f75584be42a008',
  '9a9486bbe44a96d6c89e2e39024c550f5f94b9d0337061622f99af21e3efe34121623f22bd7e4cc3e749c913601e48eaef74e0e8c5c7b4123c792d9aad5d4b01',
  'ac98e1f5b52c00aaa502dc1901a93d9752baad2df550f2e380ba48061b5a70542b159b96b7f22be68735067e5ddc95e832e3e84c3fc4348eabb3c9e7cc0a6c06',
  'cab47f4198783c023b4c0641c55bb18d7fc55d842c553dfd1343c0885c7c915beb62c86f475f21c08df8000bd62dfceac6f81dca199d0ce3a6cc408facef150b'
])

// No modaction rows existed in the frozen live inventory. Keep the explicit
// empty set: it documents that there is no shape/timestamp fallback for one.
export const LEGACY_MODACTION_SIGNATURES = new Set()

export const LEGACY_ACTION_SIGNATURES = Object.freeze({
  comment: LEGACY_COMMENT_SIGNATURES,
  vote: LEGACY_VOTE_SIGNATURES,
  modaction: LEGACY_MODACTION_SIGNATURES
})

// Every pre-cutover content CID observed in the signed seed/live inventory.
// Today none is 64-hex, so recomputing a v3 ref already rejects all of them.
// Keeping the exact deny-set makes that boundary explicit and protects a later
// fixture containing a deliberately v3-looking legacy CID.
export const LEGACY_TARGET_CIDS = new Set([
  '0mrcma59dnogthwdy',
  '0mrcnku12tt3xhrax',
  '0mrcnovoa3jd4ceq4',
  '0mrcnp8fs0ys8pj3x',
  '0mrcnpi3x2zrnuup3',
  '0mrcnq051i08wdgwr',
  '0mrcnrk423tw17lrv',
  '0mrcnt5jwuk3mjg63',
  '0mrcpcl3x8mxf16qi',
  '0mrcpeo3v2uqfe0j9',
  '0mrcph0z0k159jbop',
  '0mrcpjcivj3588ux9',
  '0mrcpr2xnr9sktn3m',
  '0mrdq50jzypxkc951',
  'seed-hiverelay',
  'seed-pearbrowser',
  'seed-peerit',
  'seed-semi2',
  'seed-semis',
  'seed-whatsnew'
])
