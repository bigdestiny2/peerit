#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import {
  boardFit,
  buildUtmLinks,
  defaultCampaign,
  launchCreatives,
  loadLaunchSources,
  mdEscape,
  relPath,
  root,
  sourceFiles,
  topLinksForChannel,
  writeReport
} from './lib/launch-collateral.mjs'

function argValue (name) {
  const exact = process.argv.indexOf(name)
  if (exact !== -1 && process.argv[exact + 1]) return process.argv[exact + 1]
  const prefix = `${name}=`
  const match = process.argv.find(arg => arg.startsWith(prefix))
  return match ? match.slice(prefix.length) : null
}

function defaultPearBase () {
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'))
    return manifest.homepage || manifest.url || 'hyper://peerit/'
  } catch {
    return 'hyper://peerit/'
  }
}

function oneLine (value) {
  return String(value || '').replace(/\s+/g, ' ').trim()
}

function primaryCreativeLinksForBoard (links, community, limit = 5) {
  const fitWeight = { primary: 0, strong: 1, general: 2 }
  return links
    .filter(link => link.board === community.slug && link.creative === 'p2p-reddit')
    .sort((a, b) => (fitWeight[a.boardFit] - fitWeight[b.boardFit]) || a.channelRank - b.channelRank)
    .slice(0, limit)
}

function channelBriefTitle (channel) {
  if (channel.slug.includes('4chan')) return `${channel.label} paid banner brief`
  if (channel.kind === 'operator_kit') return `${channel.label} operator referral brief`
  if (channel.kind === 'sponsor_kol') return `${channel.label} sponsor/KOL brief`
  return `${channel.label} creator/community brief`
}

function renderSponsorBriefs ({ spec, sourceMeta, matrix }) {
  const creatives = launchCreatives(spec)
  const lines = []
  lines.push('# Peerit Sponsor and KOL Briefs')
  lines.push('')
  lines.push(`Campaign: \`${matrix.campaign}\``)
  lines.push(`Sources: \`${sourceFiles.communities}\` (${sourceMeta.communitiesSha256.slice(0, 12)}), \`${sourceFiles.spec}\` (${sourceMeta.specSha256.slice(0, 12)})`)
  lines.push('')
  lines.push('## Approved Positioning')
  lines.push('')
  lines.push(`Primary line: ${spec.narrative.primary}`)
  lines.push('')
  lines.push('| Creative | Approved Copy |')
  lines.push('| --- | --- |')
  for (const creative of creatives) {
    lines.push(`| \`${creative.slug}\` | ${mdEscape(creative.copy)} |`)
  }
  lines.push('')
  lines.push('## Compensation and Kill Rules')
  lines.push('')
  if (spec.kolBudget) {
    lines.push(`- KOL/sponsorship budget: ${spec.kolBudget.budget} for ${spec.kolBudget.purpose}`)
  }
  if (spec.communityAdsBudget) {
    lines.push(`- Community ads budget: ${spec.communityAdsBudget.budget} for ${spec.communityAdsBudget.purpose}`)
  }
  for (const rule of spec.killRules) lines.push(`- ${rule}`)
  lines.push('')
  lines.push('## Creator Requirements')
  lines.push('')
  lines.push('- Disclose paid or sponsored placement wherever the platform requires it.')
  lines.push('- Send people to the tagged gateway link first; posting is through PearBrowser.')
  lines.push('- Ask for useful posts/comments, not raw clicks or empty signups.')
  lines.push('- Do not post through this automation. Operators must place links manually and follow platform rules.')
  lines.push('')
  lines.push('## Do Not Say')
  lines.push('')
  for (const avoid of spec.narrative.avoid) lines.push(`- ${avoid}`)
  for (const exclusion of spec.exclusions) lines.push(`- ${exclusion}`)
  lines.push('')
  lines.push('## Channel Briefs')
  lines.push('')
  for (const channel of spec.channels) {
    const examples = topLinksForChannel(matrix.links, channel.slug, 5)
    lines.push(`### ${channelBriefTitle(channel)}`)
    lines.push('')
    lines.push(`- Rank: ${channel.rank}`)
    lines.push(`- UTM source/medium: \`${channel.source}\` / \`${channel.medium}\``)
    lines.push(`- Objective: activated posters in boards where this audience already has a reason to reply.`)
    if (channel.slug.includes('4chan')) {
      for (const item of spec.fourChanGuidance) lines.push(`- 4chan constraint: ${item}`)
    }
    lines.push('- Template ask: read the linked board, explain why the P2P/no-account model matters for that audience, then invite one concrete post or comment.')
    lines.push('- Required CTA: "Read on the gateway, post through PearBrowser."')
    lines.push('')
    lines.push('| Board | Fit | Risk | Tagged Gateway Link |')
    lines.push('| --- | --- | --- | --- |')
    for (const link of examples) {
      lines.push(`| r/${mdEscape(link.board)} | ${mdEscape(link.boardFit)} | ${mdEscape(link.risk)} | ${link.gatewayUrl} |`)
    }
    lines.push('')
  }
  return lines.join('\n')
}

function renderFounderPacket (community, { spec, sourceMeta, matrix }) {
  const boardLinks = primaryCreativeLinksForBoard(matrix.links, community, 6)
  const channelFits = spec.channels
    .map(channel => ({ channel, fit: boardFit(channel, community) }))
    .filter(item => item.fit !== 'general')
    .sort((a, b) => a.channel.rank - b.channel.rank)

  const lines = []
  lines.push(`# Founder Packet: r/${community.slug}`)
  lines.push('')
  lines.push(`Sources: \`${sourceFiles.communities}\` (${sourceMeta.communitiesSha256.slice(0, 12)}), \`${sourceFiles.spec}\` (${sourceMeta.specSha256.slice(0, 12)})`)
  lines.push('')
  lines.push('## Board Brief')
  lines.push('')
  lines.push(`- Title: ${community.title}`)
  lines.push(`- Audience: ${community.audience}`)
  lines.push(`- Launch role: ${community.launchRole}`)
  lines.push(`- Founder brief: ${community.founderBrief}`)
  lines.push(`- Moderation risk: ${community.risk}`)
  lines.push('')
  lines.push('## Deliverables')
  lines.push('')
  lines.push(`- Create one owner/moderator identity for r/${community.slug}.`)
  lines.push(`- Publish ${Number(community.starterPostCount) || 10} quality starter posts before paid traffic.`)
  lines.push(`- Publish at least ${Number(community.discussionPromptCount) || 3} open-ended discussion prompts.`)
  lines.push('- Pin one norms post and exercise the moderation overlay before launch.')
  lines.push('- Reply daily during the first launch week so the board does not feel empty.')
  lines.push('')
  lines.push('## Pinned Norms Post Template')
  lines.push('')
  lines.push('```markdown')
  lines.push(`# Welcome to r/${community.slug}`)
  lines.push('')
  lines.push(`This board is for ${oneLine(community.audience)}`)
  lines.push('')
  lines.push('Bring concrete links, demos, build notes, questions, and careful comparisons.')
  lines.push('Keep claims precise: Peerit has no central account, uses signed identities, and gates posting with small proof-of-work.')
  lines.push('Do not position this board around illegal content, harassment, doxxing, ban evasion, or "anything goes" moderation.')
  lines.push('')
  lines.push('Read on the gateway. Post through PearBrowser.')
  lines.push('```')
  lines.push('')
  lines.push('## Starter Prompt Checklist')
  lines.push('')
  lines.push(`- "What is one ${community.title} workflow that would benefit from no central account or server?"`)
  lines.push(`- "Show a concrete ${community.title} build, benchmark, migration, or failure report."`)
  lines.push(`- "What should r/${community.slug} moderate quickly during launch week?"`)
  lines.push(`- "Where does Peerit's P2P model fit this audience, and where is it still rough?"`)
  lines.push('')
  lines.push('## Preferred Launch Channels')
  lines.push('')
  if (channelFits.length) {
    lines.push('| Rank | Channel | Fit | Source / Medium |')
    lines.push('| ---: | --- | --- | --- |')
    for (const item of channelFits) {
      lines.push(`| ${item.channel.rank} | ${mdEscape(item.channel.label)} | ${item.fit} | \`${item.channel.source}\` / \`${item.channel.medium}\` |`)
    }
  } else {
    lines.push('All approved launch channels can use this board as a general destination.')
  }
  lines.push('')
  lines.push('## Board Links')
  lines.push('')
  lines.push('| Channel | Fit | Tagged Gateway Link |')
  lines.push('| --- | --- | --- |')
  for (const link of boardLinks) {
    lines.push(`| ${mdEscape(link.channel)} | ${mdEscape(link.boardFit)} | ${link.gatewayUrl} |`)
  }
  lines.push('')
  lines.push('## Safety Boundaries')
  lines.push('')
  for (const avoid of spec.narrative.avoid) lines.push(`- Do not say: ${avoid}`)
  for (const exclusion of spec.exclusions) lines.push(`- ${exclusion}`)
  return lines.join('\n')
}

function renderFounderIndex ({ communities, spec, sourceMeta, matrix }) {
  const lines = []
  lines.push('# Peerit Founder Packets')
  lines.push('')
  lines.push(`Campaign: \`${matrix.campaign}\``)
  lines.push(`Sources: \`${sourceFiles.communities}\` (${sourceMeta.communitiesSha256.slice(0, 12)}), \`${sourceFiles.spec}\` (${sourceMeta.specSha256.slice(0, 12)})`)
  lines.push('')
  lines.push('## Launch Promise')
  lines.push('')
  lines.push(spec.narrative.primary)
  lines.push('')
  lines.push('## Board Index')
  lines.push('')
  lines.push('| Board | Starter Posts | Prompts | Risk | Launch Role | Packet |')
  lines.push('| --- | ---: | ---: | --- | --- | --- |')
  for (const community of communities) {
    lines.push(`| r/${mdEscape(community.slug)} | ${Number(community.starterPostCount) || 0} | ${Number(community.discussionPromptCount) || 0} | ${mdEscape(community.risk)} | ${mdEscape(community.launchRole)} | [packet](founder-packets/${community.slug}.md) |`)
  }
  lines.push('')
  lines.push('## Shared Founder Requirements')
  lines.push('')
  lines.push('- Each board has an owner/moderator identity.')
  lines.push('- Each board has 10-20 starter posts, at least 3 discussion prompts, and a pinned norms post.')
  lines.push('- Founders reply daily for the first launch week.')
  lines.push('- Moderation overlays are tested before paid traffic.')
  return lines.join('\n')
}

const sources = loadLaunchSources()
const gatewayBase = argValue('--gateway') || process.env.PEERIT_GATEWAY_URL || 'https://peerit.site/'
const pearBase = argValue('--pear') || process.env.PEERIT_PEAR_URL || defaultPearBase()
const campaign = argValue('--campaign') || process.env.PEERIT_LAUNCH_CAMPAIGN || defaultCampaign(sources)
const matrix = buildUtmLinks({ ...sources, gatewayBase, pearBase, campaign })

const sponsorPath = writeReport('sponsor-kol-briefs.md', renderSponsorBriefs({ ...sources, matrix }))
const founderIndexPath = writeReport('founder-packets.md', renderFounderIndex({ ...sources, matrix }))
const packetPaths = []
const packets = []
for (const community of sources.communities) {
  const body = renderFounderPacket(community, { ...sources, matrix })
  const packetPath = writeReport(`founder-packets/${community.slug}.md`, body)
  packetPaths.push(packetPath)
  packets.push({
    board: community.slug,
    path: relPath(packetPath),
    starterPostCount: Number(community.starterPostCount) || 0,
    discussionPromptCount: Number(community.discussionPromptCount) || 0,
    risk: community.risk
  })
}
const jsonPath = writeReport('launch-briefs.json', JSON.stringify({
  campaign,
  gatewayBase,
  pearBase,
  sourceMeta: sources.sourceMeta,
  sponsorBriefPath: relPath(sponsorPath),
  founderIndexPath: relPath(founderIndexPath),
  founderPackets: packets
}, null, 2))

console.log(`Wrote ${relPath(sponsorPath)}`)
console.log(`Wrote ${relPath(founderIndexPath)}`)
for (const packetPath of packetPaths) console.log(`Wrote ${relPath(packetPath)}`)
console.log(`Wrote ${relPath(jsonPath)}`)
