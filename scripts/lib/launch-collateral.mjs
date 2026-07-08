import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

export const sourceFiles = {
  communities: 'launch/communities.json',
  spec: 'docs/GROWTH_AUTOMATION_SPEC.md'
}

export function readRoot (rel) {
  return fs.readFileSync(path.join(root, rel), 'utf8')
}

export function loadJson (rel) {
  return JSON.parse(readRoot(rel))
}

export function sourceHash (text) {
  return crypto.createHash('sha256').update(text).digest('hex')
}

export function ensureReportsDir (...parts) {
  const dir = path.join(root, 'launch/reports', ...parts)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

export function writeReport (rel, content) {
  const outPath = path.join(root, 'launch/reports', rel)
  fs.mkdirSync(path.dirname(outPath), { recursive: true })
  fs.writeFileSync(outPath, content.endsWith('\n') ? content : content + '\n')
  return outPath
}

export function relPath (absPath) {
  return path.relative(root, absPath)
}

export function mdEscape (value) {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ')
}

export function csvEscape (value) {
  const s = String(value ?? '')
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

export function slugify (value) {
  return String(value || '')
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-')
}

export function sectionText (text, heading) {
  const start = text.indexOf(`## ${heading}`)
  if (start === -1) return ''
  const rest = text.slice(start)
  const next = rest.slice(1).search(/\n## /)
  return next === -1 ? rest : rest.slice(0, next + 1)
}

function listAfterLabel (text, label, stopLabels = []) {
  const marker = text.indexOf(label)
  if (marker === -1) return []
  let body = text.slice(marker + label.length)
  for (const stop of stopLabels) {
    const i = body.indexOf(stop)
    if (i !== -1) body = body.slice(0, i)
  }
  const items = []
  let current = null
  for (const rawLine of body.split('\n')) {
    const line = rawLine.trim()
    if (!line) continue
    if (line.startsWith('- ')) {
      if (current) items.push(current)
      current = line.slice(2).trim()
      continue
    }
    if (!current || line.startsWith('|') || line.startsWith('#')) continue
    current += ` ${line}`
  }
  if (current) items.push(current)
  return items.map(item => item.replace(/^"|"$/g, ''))
}

function parseMarkdownTable (text) {
  return text.split('\n')
    .map(line => line.trim())
    .filter(line => line.startsWith('|') && line.endsWith('|'))
    .filter(line => !/^\|\s*-/.test(line))
    .map(line => line.slice(1, -1).split('|').map(cell => cell.trim()))
}

function parseNarrative (specText) {
  const narrative = sectionText(specText, 'Launch Narrative')
  const lines = narrative.split('\n')
  const primary = []
  let collectingPrimary = false
  for (const line of lines) {
    if (line.trim() === 'Primary line:') {
      collectingPrimary = true
      continue
    }
    if (!collectingPrimary) continue
    if (!line.trim()) continue
    if (!line.trim().startsWith('>')) break
    primary.push(line.trim().replace(/^>\s?/, ''))
  }
  return {
    primary: primary.join(' ').trim(),
    supporting: listAfterLabel(narrative, 'Supporting lines:', ['Avoid:']),
    avoid: listAfterLabel(narrative, 'Avoid:')
  }
}

function parseChannels (specText) {
  const channelSection = sectionText(specText, 'Channel Strategy')
  const profiles = {
    nostr: { source: 'nostr', medium: 'organic_social', kind: 'creator_and_community' },
    'lemmy-fediverse-mbin': { source: 'fediverse', medium: 'organic_community', kind: 'community_post' },
    'privacy-and-degoogle-communities': { source: 'privacy_communities', medium: 'community_post', kind: 'community_post' },
    'self-hosting-homelab-linux-foss': { source: 'selfhosted_foss', medium: 'community_post', kind: 'community_post' },
    'hiverelay-operators-and-node-curious-homelab-users': { source: 'hiverelay_operator', medium: 'operator_referral', kind: 'operator_kit' },
    'bitcoin-lightning-cypherpunk': { source: 'bitcoin_cypherpunk', medium: 'creator_sponsorship', kind: 'sponsor_kol' },
    'reddit-alternatives-and-deplatformed-but-lawful-communities': { source: 'reddit_alternatives', medium: 'community_post', kind: 'community_post' },
    'hacker-news-lobsters-tildes-and-g-as-technical-proof-channels': { source: 'technical_forums', medium: 'organic_community', kind: 'technical_launch' },
    '4chan-biz-only-as-a-small-crypto-native-experiment': { source: '4chan_biz_paid_banner', medium: 'paid_banner', kind: 'paid_banner' }
  }

  const channels = []
  for (const line of channelSection.split('\n')) {
    const match = line.match(/^\s*(\d+)\.\s+(.+?)\.?\s*$/)
    if (!match) continue
    const rank = Number(match[1])
    const label = match[2].replace(/`/g, '')
    const slug = slugify(label)
    const profile = profiles[slug] || { source: slug, medium: 'launch_channel', kind: 'launch_channel' }
    channels.push({ rank, label, slug, ...profile })
  }
  return channels
}

function parseBudget (specText) {
  const section = sectionText(specText, 'Paid Launch Budget')
  const rows = parseMarkdownTable(section).slice(1)
  return rows.map(([bucket, budget, purpose]) => ({
    bucket,
    budget,
    budgetUsd: Number(String(budget || '').replace(/[^0-9.]/g, '')) || null,
    purpose
  }))
}

function parseReportingEvents (specText) {
  const section = sectionText(specText, 'Reporting Model')
  const rows = parseMarkdownTable(section).slice(1)
  return rows.map(([event, where, notes]) => ({ event: event.replace(/`/g, ''), where, notes }))
}

export function parseGrowthSpec (specText) {
  const date = (specText.match(/^Date:\s*(.+)$/m) || [])[1] || null
  const budget = parseBudget(specText)
  return {
    date,
    channels: parseChannels(specText),
    budget,
    kolBudget: budget.find(row => /KOL|sponsor/i.test(row.bucket)) || null,
    communityAdsBudget: budget.find(row => /Reddit|community ads/i.test(row.bucket)) || null,
    narrative: parseNarrative(specText),
    exclusions: listAfterLabel(sectionText(specText, 'Channel Strategy'), 'Explicit exclusions:', ['4chan guidance:']),
    fourChanGuidance: listAfterLabel(sectionText(specText, 'Channel Strategy'), '4chan guidance:'),
    killRules: listAfterLabel(sectionText(specText, 'Paid Launch Budget'), 'Kill rules:', ['## Channel Strategy']),
    reportingEvents: parseReportingEvents(specText)
  }
}

export function loadLaunchSources () {
  const communitiesText = readRoot(sourceFiles.communities)
  const specText = readRoot(sourceFiles.spec)
  const config = JSON.parse(communitiesText)
  const communities = Array.isArray(config.communities) ? config.communities : []
  if (!communities.length) throw new Error(`${sourceFiles.communities} has no communities`)
  const spec = parseGrowthSpec(specText)
  if (!spec.channels.length) throw new Error(`${sourceFiles.spec} has no Channel Strategy list`)
  if (!spec.narrative.primary) throw new Error(`${sourceFiles.spec} has no Launch Narrative primary line`)
  return {
    config,
    communities,
    spec,
    sourceMeta: {
      communities: sourceFiles.communities,
      communitiesSha256: sourceHash(communitiesText),
      spec: sourceFiles.spec,
      specSha256: sourceHash(specText)
    }
  }
}

export function defaultCampaign ({ config, spec }) {
  const stamp = String(config.generatedAt || spec.date || 'launch').slice(0, 7).replace(/-/g, '_')
  return `peerit_launch_${stamp}`
}

export function launchCreatives (spec) {
  const supporting = spec.narrative.supporting
  const findSupport = pattern => supporting.find(line => pattern.test(line)) || ''
  return [
    {
      slug: 'p2p-reddit',
      headline: 'Proof-of-work gated P2P Reddit',
      copy: spec.narrative.primary,
      source: 'launch-narrative-primary'
    },
    {
      slug: 'read-gateway-post-pearbrowser',
      headline: 'Read on the gateway. Post through PearBrowser.',
      copy: spec.narrative.primary,
      source: 'launch-narrative-primary'
    },
    {
      slug: 'spam-is-not-free',
      headline: 'Spam is not free',
      copy: findSupport(/Spam is not free/i),
      source: 'launch-narrative-supporting'
    },
    {
      slug: 'signed-moderation-overlay',
      headline: 'Moderation is a signed overlay',
      copy: findSupport(/Moderation is a signed overlay/i),
      source: 'launch-narrative-supporting'
    },
    {
      slug: 'hiverelay-proof',
      headline: 'Run a HiveRelay node and prove useful work',
      copy: findSupport(/Run a HiveRelay node/i) || findSupport(/Node operators can prove/i),
      source: 'launch-narrative-supporting'
    }
  ].filter(creative => creative.copy)
}

const focusBoardsByChannel = {
  nostr: ['nostr', 'p2pbuilders', 'cypherpunk', 'privacy'],
  'lemmy-fediverse-mbin': ['fediverse', 'redditalternatives', 'localfirst', 'privacy'],
  'privacy-and-degoogle-communities': ['privacy', 'cypherpunk', 'redditalternatives', 'linux'],
  'self-hosting-homelab-linux-foss': ['selfhosted', 'homelab', 'linux', 'hiverelay', 'p2pbuilders'],
  'hiverelay-operators-and-node-curious-homelab-users': ['hiverelay', 'homelab', 'selfhosted', 'p2pbuilders'],
  'bitcoin-lightning-cypherpunk': ['cypherpunk', 'nostr', 'privacy', 'hiverelay'],
  'reddit-alternatives-and-deplatformed-but-lawful-communities': ['redditalternatives', 'fediverse', 'privacy', 'showcase'],
  'hacker-news-lobsters-tildes-and-g-as-technical-proof-channels': ['p2pbuilders', 'localfirst', 'linux', 'showcase', 'ai_local'],
  '4chan-biz-only-as-a-small-crypto-native-experiment': ['cypherpunk', 'redditalternatives', 'privacy', 'ai_local']
}

export function boardFit (channel, community) {
  const focus = focusBoardsByChannel[channel.slug] || []
  if (focus[0] === community.slug) return 'primary'
  if (focus.includes(community.slug)) return 'strong'
  return 'general'
}

function taggedUrl (base, route, params) {
  const url = new URL(base)
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value)
  }
  url.hash = route
  return url.toString()
}

export function boardRoute (community) {
  return `/r/${encodeURIComponent(community.slug)}`
}

export function buildUtmLinks ({ config, communities, spec, gatewayBase, pearBase, campaign }) {
  const creatives = launchCreatives(spec)
  const links = []
  for (const channel of spec.channels) {
    for (const creative of creatives) {
      for (const community of communities) {
        const fit = boardFit(channel, community)
        const route = boardRoute(community)
        const campaignTag = `${campaign}:${channel.slug}:${creative.slug}:${community.slug}`
        const params = {
          utm_source: channel.source,
          utm_medium: channel.medium,
          utm_campaign: campaign,
          utm_content: `${creative.slug}.${community.slug}`,
          utm_term: community.slug,
          peerit_campaign_tag: campaignTag,
          peerit_channel: channel.slug,
          peerit_board: community.slug
        }
        links.push({
          campaign,
          campaignTag,
          channelRank: channel.rank,
          channel: channel.label,
          channelSlug: channel.slug,
          channelKind: channel.kind,
          source: channel.source,
          medium: channel.medium,
          creative: creative.slug,
          headline: creative.headline,
          board: community.slug,
          boardTitle: community.title,
          boardFit: fit,
          audience: community.audience,
          launchRole: community.launchRole,
          risk: community.risk,
          gatewayUrl: taggedUrl(gatewayBase, route, params),
          pearUrl: taggedUrl(pearBase, route, params)
        })
      }
    }
  }
  return {
    campaign,
    generatedFrom: {
      launchTarget: config.launchTarget || {},
      channels: spec.channels.length,
      creatives: creatives.length,
      boards: communities.length
    },
    links
  }
}

export function topLinksForChannel (links, channelSlug, limit = 5) {
  const fitWeight = { primary: 0, strong: 1, general: 2 }
  const creativeWeight = {
    'p2p-reddit': 0,
    'read-gateway-post-pearbrowser': 1,
    'spam-is-not-free': 2,
    'signed-moderation-overlay': 3,
    'hiverelay-proof': 4
  }
  const selected = []
  const seenBoards = new Set()
  for (const link of links
    .filter(link => link.channelSlug === channelSlug)
    .sort((a, b) =>
      (fitWeight[a.boardFit] - fitWeight[b.boardFit]) ||
      a.board.localeCompare(b.board) ||
      ((creativeWeight[a.creative] ?? 99) - (creativeWeight[b.creative] ?? 99)))) {
    if (seenBoards.has(link.board)) continue
    selected.push(link)
    seenBoards.add(link.board)
    if (selected.length >= limit) break
  }
  if (selected.length) return selected
  return links
    .filter(link => link.channelSlug === channelSlug)
    .sort((a, b) => (fitWeight[a.boardFit] - fitWeight[b.boardFit]) || a.board.localeCompare(b.board) || a.creative.localeCompare(b.creative))
    .slice(0, limit)
}
