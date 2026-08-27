// Guards Peerit's public GitHub surface against link rot and accidental
// publication of nonportable or private paths.
// Run: node test/github-surface.mjs

import assert from 'node:assert/strict'
import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync
} from 'node:fs'
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep
} from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const requiredMarkdown = Object.freeze([
  'README.md',
  'PATTERNS.md',
  'EXPLAINER.md',
  'CHANGELOG.md',
  'CONTRIBUTING.md',
  'SECURITY.md',
  '.github/PULL_REQUEST_TEMPLATE.md'
])

const optionalMarkdown = Object.freeze([
  'CODE_OF_CONDUCT.md',
  'SUPPORT.md',
  'docs/README.md',
  'docs/ARCHITECTURE.md',
  'docs/CURRENT-STATUS.md'
])

const requiredCommunityFiles = Object.freeze([
  '.github/ISSUE_TEMPLATE/bug-report.yml',
  '.github/ISSUE_TEMPLATE/feature-request.yml',
  '.github/ISSUE_TEMPLATE/pattern-proposal.yml',
  '.github/ISSUE_TEMPLATE/config.yml'
])

function git (...args) {
  const result = spawnSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024
  })
  assert.equal(result.status, 0,
    `git ${args.join(' ')} failed: ${(result.stderr || result.stdout).trim()}`)
  return result.stdout
}

function withoutFencedCode (source) {
  let fence = null
  return source.split('\n').map(line => {
    const marker = line.match(/^\s*(`{3,}|~{3,})/)
    if (marker) {
      const token = marker[1][0]
      if (fence === null) fence = token
      else if (fence === token) fence = null
      return ''
    }
    return fence === null ? line : ''
  }).join('\n')
}

function markdownTargets (source) {
  const clean = withoutFencedCode(source)
  const targets = []
  const inline = /!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^\s)]+))(?:\s+["'][^"'\n]*["'])?\s*\)/g
  const reference = /^\s*\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|(\S+))/gm

  for (const pattern of [inline, reference]) {
    let match
    while ((match = pattern.exec(clean))) {
      const target = match[1] || match[2]
      targets.push({
        target,
        line: clean.slice(0, match.index).split('\n').length
      })
    }
  }
  return targets
}

function localTargetPath (fromFile, rawTarget) {
  const target = rawTarget.trim()
  if (!target || target.startsWith('#') || target.startsWith('//')) return null
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return null
  if (target.startsWith('/')) return null

  const withoutFragment = target.replace(/[?#].*$/, '')
  if (!withoutFragment) return null

  let decoded
  try {
    decoded = decodeURIComponent(withoutFragment)
  } catch {
    return { error: `invalid percent-encoding in ${JSON.stringify(rawTarget)}` }
  }

  const absolute = resolve(root, dirname(fromFile), decoded)
  const repoRelative = relative(root, absolute)
  if (repoRelative === '..' || repoRelative.startsWith(`..${sep}`) || isAbsolute(repoRelative)) {
    return { error: `relative link escapes the repository: ${JSON.stringify(rawTarget)}` }
  }
  return { absolute, repoRelative }
}

// macOS worktrees can be case-insensitive while GitHub paths are case-sensitive.
// Walk each segment and require the spelling actually present in the directory.
function existsWithExactCase (repoRelative) {
  if (!repoRelative || repoRelative === '.') return true
  let cursor = root
  for (const segment of repoRelative.split(sep)) {
    if (!existsSync(cursor) || !statSync(cursor).isDirectory()) return false
    if (!readdirSync(cursor).includes(segment)) return false
    cursor = join(cursor, segment)
  }
  return existsSync(cursor)
}

function brokenMarkdownLinks (files) {
  const failures = []
  for (const file of files) {
    const absolute = join(root, file)
    if (!existsSync(absolute)) {
      failures.push(`${file}: required public Markdown file is missing`)
      continue
    }
    const source = readFileSync(absolute, 'utf8')
    for (const { target, line } of markdownTargets(source)) {
      const resolved = localTargetPath(file, target)
      if (resolved === null) continue
      if (resolved.error) {
        failures.push(`${file}:${line}: ${resolved.error}`)
      } else if (!existsWithExactCase(resolved.repoRelative)) {
        failures.push(
          `${file}:${line}: ${JSON.stringify(target)} resolves to missing ${resolved.repoRelative}`
        )
      }
    }
  }
  return failures
}

function trackedEntries () {
  return git('ls-files', '-s', '-z')
    .split('\0')
    .filter(Boolean)
    .map(entry => {
      const match = entry.match(/^(\d{6}) [0-9a-f]+ \d+\t([\s\S]+)$/)
      assert.ok(match, `unexpected git ls-files entry: ${JSON.stringify(entry)}`)
      return { mode: match[1], path: match[2] }
    })
}

function trackedSymlinks (entries) {
  return entries.filter(entry => entry.mode === '120000').map(entry => entry.path)
}

const privatePathPatterns = Object.freeze([
  /(^|\/)\.seed-readcap-vault[^/]*\.json$/i,
  /(^|\/)\.seed-author-store\.json$/i,
  /(^|\/)\.seed-personas-store\.json$/i,
  /^launch\/seed-identities\.json$/i,
  /(^|\/)custodian-\d+\.x25519$/i
])

function trackedPrivatePaths (entries) {
  return entries
    .map(entry => entry.path)
    .filter(path => privatePathPatterns.some(pattern => pattern.test(path)))
}

// Prove the guards themselves recognize the regressions they are meant to stop.
assert.deepEqual(
  trackedSymlinks([
    { mode: '100644', path: 'README.md' },
    { mode: '120000', path: 'node_modules' }
  ]),
  ['node_modules']
)
assert.deepEqual(
  trackedPrivatePaths([
    { mode: '100600', path: 'launch/.seed-readcap-vault-seq27.json' },
    { mode: '100644', path: 'launch/public-manifest.json' }
  ]),
  ['launch/.seed-readcap-vault-seq27.json']
)
assert.deepEqual(
  localTargetPath('README.md', '../outside.md'),
  { error: 'relative link escapes the repository: "../outside.md"' }
)

const markdownFiles = [
  ...requiredMarkdown,
  ...optionalMarkdown.filter(file => existsSync(join(root, file)))
]
for (const file of requiredCommunityFiles) {
  assert.ok(existsWithExactCase(file), `required GitHub community file is missing: ${file}`)
}
const linkFailures = brokenMarkdownLinks(markdownFiles)
assert.deepEqual(linkFailures, [],
  `broken local links in public Markdown:\n${linkFailures.map(value => `  - ${value}`).join('\n')}`)

const entries = trackedEntries()
const symlinks = trackedSymlinks(entries)
assert.deepEqual(symlinks, [],
  `tracked symlinks are nonportable and not allowed:\n${symlinks.map(value => `  - ${value}`).join('\n')}`)

const privatePaths = trackedPrivatePaths(entries)
assert.deepEqual(privatePaths, [],
  `private vault/key paths must never be tracked:\n${privatePaths.map(value => `  - ${value}`).join('\n')}`)

console.log(
  `github-surface: ${markdownFiles.length} public Markdown files and ` +
  `${requiredCommunityFiles.length} issue-template files checked; ` +
  `${entries.length} tracked paths contain no symlinks or private vault paths`
)
