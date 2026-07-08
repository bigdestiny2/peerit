#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import {
  buildUtmLinks,
  csvEscape,
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

function renderCsv (links) {
  const fields = [
    'campaign',
    'campaign_tag',
    'channel_rank',
    'channel',
    'channel_slug',
    'channel_kind',
    'utm_source',
    'utm_medium',
    'creative',
    'headline',
    'board',
    'board_title',
    'board_fit',
    'risk',
    'gateway_url',
    'pear_url'
  ]
  const rows = links.map(link => [
    link.campaign,
    link.campaignTag,
    link.channelRank,
    link.channel,
    link.channelSlug,
    link.channelKind,
    link.source,
    link.medium,
    link.creative,
    link.headline,
    link.board,
    link.boardTitle,
    link.boardFit,
    link.risk,
    link.gatewayUrl,
    link.pearUrl
  ])
  return [fields, ...rows].map(row => row.map(csvEscape).join(',')).join('\n')
}

function renderMarkdown ({ config, communities, spec, sourceMeta, matrix, gatewayBase, pearBase }) {
  const creatives = launchCreatives(spec)
  const lines = []
  lines.push('# Peerit Launch UTM Link Matrix')
  lines.push('')
  lines.push(`Campaign: \`${matrix.campaign}\``)
  lines.push(`Gateway base: \`${gatewayBase}\``)
  lines.push(`Pear base: \`${pearBase}\``)
  lines.push(`Sources: \`${sourceFiles.communities}\` (${sourceMeta.communitiesSha256.slice(0, 12)}), \`${sourceFiles.spec}\` (${sourceMeta.specSha256.slice(0, 12)})`)
  lines.push('')
  lines.push('## Targets')
  lines.push('')
  lines.push(`- Activated posters: ${config.launchTarget?.activatedPosters ?? 'TBD'}`)
  lines.push(`- Living boards: ${config.launchTarget?.livingBoards ?? 'TBD'}`)
  lines.push(`- D7 returning poster rate: ${config.launchTarget?.d7ReturningPosterRate ?? 'TBD'}`)
  lines.push(`- Max cost per activated poster: $${config.launchTarget?.maxCostPerActivatedPosterUsd ?? 'TBD'}`)
  lines.push('')
  lines.push('## Matrix Shape')
  lines.push('')
  lines.push(`- Channels: ${spec.channels.length}`)
  lines.push(`- Creatives: ${creatives.length}`)
  lines.push(`- Boards: ${communities.length}`)
  lines.push(`- Tagged links: ${matrix.links.length}`)
  lines.push('')
  lines.push('## Channels')
  lines.push('')
  lines.push('| Rank | Channel | Source | Medium | Links | Focus Boards |')
  lines.push('| ---: | --- | --- | --- | ---: | --- |')
  for (const channel of spec.channels) {
    const channelLinks = matrix.links.filter(link => link.channelSlug === channel.slug)
    const focusBoards = [...new Set(channelLinks
      .filter(link => link.boardFit !== 'general')
      .map(link => `r/${link.board}`))]
      .slice(0, 5)
      .join(', ')
    lines.push(`| ${channel.rank} | ${mdEscape(channel.label)} | \`${channel.source}\` | \`${channel.medium}\` | ${channelLinks.length} | ${mdEscape(focusBoards || 'all launch boards')} |`)
  }
  lines.push('')
  lines.push('## Creatives')
  lines.push('')
  lines.push('| Creative | Headline | Source |')
  lines.push('| --- | --- | --- |')
  for (const creative of creatives) {
    lines.push(`| \`${creative.slug}\` | ${mdEscape(creative.headline)} | ${mdEscape(creative.source)} |`)
  }
  lines.push('')
  lines.push('## Channel Examples')
  lines.push('')
  for (const channel of spec.channels) {
    lines.push(`### ${channel.rank}. ${channel.label}`)
    lines.push('')
    const examples = topLinksForChannel(matrix.links, channel.slug, 3)
    for (const link of examples) {
      lines.push(`- r/${link.board} / \`${link.creative}\`: ${link.gatewayUrl}`)
    }
    lines.push('')
  }
  lines.push('## Safety Boundaries')
  lines.push('')
  lines.push('- These links are collateral only; this script does not post, message, or submit to third-party platforms.')
  for (const rule of spec.exclusions) lines.push(`- ${rule}`)
  for (const rule of spec.killRules) lines.push(`- ${rule}`)
  return lines.join('\n')
}

const sources = loadLaunchSources()
const gatewayBase = argValue('--gateway') || process.env.PEERIT_GATEWAY_URL || 'https://peerit.site/'
const pearBase = argValue('--pear') || process.env.PEERIT_PEAR_URL || defaultPearBase()
const campaign = argValue('--campaign') || process.env.PEERIT_LAUNCH_CAMPAIGN || defaultCampaign(sources)
const matrix = buildUtmLinks({ ...sources, gatewayBase, pearBase, campaign })

const csvPath = writeReport('utm-links.csv', renderCsv(matrix.links))
const jsonPath = writeReport('utm-links.json', JSON.stringify({
  campaign,
  gatewayBase,
  pearBase,
  sourceMeta: sources.sourceMeta,
  generatedFrom: matrix.generatedFrom,
  links: matrix.links
}, null, 2))
const mdPath = writeReport('utm-links.md', renderMarkdown({ ...sources, matrix, gatewayBase, pearBase }))

console.log(`Wrote ${relPath(csvPath)}`)
console.log(`Wrote ${relPath(jsonPath)}`)
console.log(`Wrote ${relPath(mdPath)}`)
