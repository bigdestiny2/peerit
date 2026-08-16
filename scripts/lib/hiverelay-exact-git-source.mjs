import { execFileSync } from 'node:child_process'
import path from 'node:path'

const HEX40 = /^[0-9a-f]{40}$/
const SAFE_PATH = /^(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/
const GIT_SAFETY_ENV = Object.freeze({
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_NO_LAZY_FETCH: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0'
})
const GIT_ROUTING_ENV = Object.freeze([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_DIR',
  'GIT_OBJECT_DIRECTORY',
  'GIT_REPLACE_REF_BASE',
  'GIT_WORK_TREE'
])

function gitEnvironment () {
  const env = { ...process.env }
  for (const name of GIT_ROUTING_ENV) delete env[name]
  return { ...env, ...GIT_SAFETY_ENV }
}

function git (root, args, options = {}) {
  try {
    return execFileSync('git', ['-C', root, ...args], {
      encoding: options.encoding,
      env: gitEnvironment(),
      maxBuffer: options.maxBuffer || (8 * 1024 * 1024),
      stdio: ['ignore', 'pipe', 'pipe']
    })
  } catch (cause) {
    const error = new Error(`exact HiveRelay Git source is unavailable: ${cause.stderr?.toString().trim() || cause.message}`)
    error.code = 'PEERIT_HIVERELAY_EXACT_GIT_SOURCE_UNAVAILABLE'
    throw error
  }
}

export function createHiveRelayExactGitSourceV1 (input = {}) {
  const root = path.resolve(String(input.root || ''))
  const commit = String(input.commit || '')
  const expectedTree = String(input.expectedTree || '')
  if (!HEX40.test(commit) || !HEX40.test(expectedTree)) {
    throw new Error('exact HiveRelay commit and tree must be lowercase 20-byte hexadecimal')
  }
  git(root, ['cat-file', '-e', `${commit}^{commit}`])
  const tree = git(root, ['rev-parse', `${commit}^{tree}`], { encoding: 'utf8' }).trim()
  if (tree !== expectedTree) {
    throw new Error('exact HiveRelay candidate tree changed')
  }
  return Object.freeze({
    root,
    commit,
    tree,
    read (relative) {
      if (!SAFE_PATH.test(relative) || relative.includes('..')) {
        throw new Error('exact HiveRelay Git source path is invalid')
      }
      const object = `${commit}:${relative}`
      const type = git(root, ['cat-file', '-t', object], { encoding: 'utf8' }).trim()
      if (type !== 'blob') {
        const error = new Error(`exact HiveRelay Git source path is not a blob: ${relative}`)
        error.code = 'PEERIT_HIVERELAY_EXACT_GIT_SOURCE_NOT_BLOB'
        throw error
      }
      return Buffer.from(git(root, ['cat-file', 'blob', object]))
    }
  })
}
