// moderation.js — deterministic community moderation policy.
//
// Relays store signed opaque cells; they do not decide what is visible. Every
// client runs this same pure policy over its admitted local view. The policy is
// deliberately separate from candidate selection and ranking so a reader may
// choose Community, Consensus, or Open without changing feed algorithms.

import { REPORT_VERDICT } from './model.js'

export const MODERATION_VIEW = Object.freeze({
  COMMUNITY: 'community',
  CONSENSUS: 'consensus',
  OPEN: 'open'
})

export const VISIBILITY = Object.freeze({
  VISIBLE: 'visible',
  DOWNRANKED: 'downranked',
  COLLAPSED: 'collapsed',
  BURIED: 'buried'
})

export const DEFAULT_THRESHOLDS = Object.freeze({
  downranked: Object.freeze({ bury: 3, support: 0.60 }),
  collapsed: Object.freeze({ bury: 5, support: 2 / 3 }),
  buried: Object.freeze({ bury: 7, support: 0.75 })
})

export function cleanModerationView (view) {
  return Object.values(MODERATION_VIEW).includes(view) ? view : MODERATION_VIEW.COMMUNITY
}

// Eligibility is community-local and cannot be gained by backdating a profile:
// founders/current moderators are trust roots; an active signed member joins the
// eligible set after publishing content in the community and receiving a positive
// vote directly from one of those roots. Deliberately do NOT recurse through raw
// upvotes: a root-vouched participant cannot mint arbitrary moderation identities
// by endorsing their own Sybil chain.
export function eligibleCommunityAuthors ({
  creator,
  mods = [],
  banned = [],
  memberships = [],
  posts = [],
  comments = [],
  votes = []
} = {}) {
  const bannedAuthors = new Set(banned || [])
  const eligible = new Set()
  if (creator && !bannedAuthors.has(creator)) eligible.add(creator)
  for (const pub of mods || []) if (pub && !bannedAuthors.has(pub)) eligible.add(pub)
  const roots = new Set(eligible)

  const members = new Set()
  for (const row of memberships || []) {
    if (typeof row === 'string') members.add(row)
    else if (row && !row.deleted && row.author) members.add(row.author)
  }

  const content = new Map()
  const contributors = new Set()
  for (const row of [...(posts || []), ...(comments || [])]) {
    if (!row || row.deleted || !row.cid || !row.author) continue
    content.set(row.cid, row.author)
    contributors.add(row.author)
  }

  const endorsements = new Map()
  for (const vote of votes || []) {
    if (!vote || vote.value !== 1 || !vote.author) continue
    const targetAuthor = content.get(vote.targetCid)
    if (!targetAuthor || targetAuthor === vote.author) continue
    let voters = endorsements.get(targetAuthor)
    if (!voters) endorsements.set(targetAuthor, (voters = new Set()))
    voters.add(vote.author)
  }

  for (const pub of members) {
    if (eligible.has(pub) || bannedAuthors.has(pub) || !contributors.has(pub)) continue
    const voters = endorsements.get(pub)
    if (voters && [...voters].some(voter => roots.has(voter))) eligible.add(pub)
  }
  return eligible
}

// Defensive LWW by author even though the materialized key already guarantees
// one report slot per target/author. Deleted reports are withdrawals.
export function aggregateReports (reports, {
  eligible = new Set(),
  viewer = '',
  thresholds = DEFAULT_THRESHOLDS
} = {}) {
  const latest = new Map()
  for (const report of reports || []) {
    if (!report || !report.author) continue
    const previous = latest.get(report.author)
    const newer = !previous || Number(report.ts) > Number(previous.ts)
    const tiedWinner = previous && Number(report.ts) === Number(previous.ts) &&
      reportOrderKey(report) > reportOrderKey(previous)
    if (newer || tiedWinner) latest.set(report.author, report)
  }

  let raw = 0
  let bury = 0
  let keep = 0
  let myVerdict = null
  const reasons = new Map()
  for (const report of latest.values()) {
    if (report.deleted) continue
    raw++
    if (report.author === viewer) myVerdict = report.verdict
    if (!eligible.has(report.author)) continue
    if (report.verdict === REPORT_VERDICT.BURY) {
      bury++
      reasons.set(report.reason, (reasons.get(report.reason) || 0) + 1)
    } else if (report.verdict === REPORT_VERDICT.KEEP) {
      keep++
    }
  }

  const participating = bury + keep
  const support = participating ? bury / participating : 0
  let state = VISIBILITY.VISIBLE
  if (bury >= thresholds.buried.bury && support >= thresholds.buried.support) state = VISIBILITY.BURIED
  else if (bury >= thresholds.collapsed.bury && support >= thresholds.collapsed.support) state = VISIBILITY.COLLAPSED
  else if (bury >= thresholds.downranked.bury && support >= thresholds.downranked.support) state = VISIBILITY.DOWNRANKED

  return {
    state,
    raw,
    eligible: participating,
    bury,
    keep,
    support,
    myVerdict,
    reasons: [...reasons.entries()]
      .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0]))
      .map(([reason, count]) => ({ reason, count }))
  }
}

function reportOrderKey (report) {
  return String(report?._sig || '') || JSON.stringify([
    !!report?.deleted,
    report?.verdict || '',
    report?.reason || '',
    report?.note || '',
    report?.targetCid || ''
  ])
}

export function applyModerationPolicy (consensus, {
  view = MODERATION_VIEW.COMMUNITY,
  moderatorRemoved = false
} = {}) {
  view = cleanModerationView(view)
  let visibility = consensus?.state || VISIBILITY.VISIBLE
  if (view === MODERATION_VIEW.OPEN) visibility = VISIBILITY.VISIBLE
  if (view === MODERATION_VIEW.COMMUNITY && moderatorRemoved) visibility = VISIBILITY.COLLAPSED
  return {
    ...(consensus || aggregateReports([])),
    consensusState: consensus?.state || VISIBILITY.VISIBLE,
    visibility,
    view,
    moderatorRemoved: !!moderatorRemoved
  }
}

export function moderationTier (record) {
  switch (record?.moderation?.visibility) {
    case VISIBILITY.DOWNRANKED: return 1
    case VISIBILITY.COLLAPSED: return 2
    case VISIBILITY.BURIED: return 3
    default: return 0
  }
}
