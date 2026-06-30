#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const configPath = path.join(root, 'launch/communities.json')
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'))
const communities = config.communities || []

function mdEscape (value) {
  return String(value || '').replace(/\|/g, '\\|').replace(/\n/g, ' ')
}

function render () {
  const lines = []
  lines.push('# Peerit Seed Community Plan')
  lines.push('')
  lines.push(`Generated from \`launch/communities.json\`.`)
  lines.push('')
  lines.push('## Targets')
  lines.push('')
  lines.push(`- Activated posters: ${config.launchTarget?.activatedPosters || 'TBD'}`)
  lines.push(`- Living boards: ${config.launchTarget?.livingBoards || 'TBD'}`)
  lines.push(`- Max cost per activated poster: $${config.launchTarget?.maxCostPerActivatedPosterUsd || 'TBD'}`)
  lines.push('')
  lines.push('## Board Briefs')
  lines.push('')
  lines.push('| Board | Starter Posts | Prompts | Risk | Founder Brief |')
  lines.push('| --- | ---: | ---: | --- | --- |')
  for (const c of communities) {
    lines.push(`| r/${mdEscape(c.slug)} | ${Number(c.starterPostCount) || 0} | ${Number(c.discussionPromptCount) || 0} | ${mdEscape(c.risk)} | ${mdEscape(c.founderBrief)} |`)
  }
  lines.push('')
  lines.push('## 14-Day Operating Rhythm')
  lines.push('')
  lines.push('- Day 0: verify PoW gate, gateway preview, and founder identities.')
  lines.push('- Days 1-3: publish starter posts and pinned norms posts.')
  lines.push('- Days 4-7: invite founding posters and answer every good-faith reply.')
  lines.push('- Days 8-10: run first board bounties and showcase best threads.')
  lines.push('- Days 11-14: prune weak boards, double down on boards with real replies, and prepare paid tests.')
  lines.push('')
  lines.push('## Founder Deliverables')
  lines.push('')
  lines.push('- One pinned norms post.')
  lines.push('- 10+ quality starter posts before paid traffic.')
  lines.push('- 3+ open-ended discussion prompts.')
  lines.push('- Daily replies for the first launch week.')
  lines.push('- Escalation note for spam, illegal content, and harassment.')
  return lines.join('\n')
}

const output = render()
if (process.argv.includes('--write')) {
  const outDir = path.join(root, 'launch/reports')
  fs.mkdirSync(outDir, { recursive: true })
  const outPath = path.join(outDir, 'seed-plan.md')
  fs.writeFileSync(outPath, output + '\n')
  console.log(`Wrote ${path.relative(root, outPath)}`)
} else {
  console.log(output)
}
