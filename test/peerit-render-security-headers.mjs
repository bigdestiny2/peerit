import assert from 'node:assert/strict'
import test from 'node:test'

import { headerRows } from '../scripts/configure-render-security-headers.mjs'

const header = {
  id: 'hdr-csp',
  name: 'Content-Security-Policy',
  path: '/*',
  value: "default-src 'self'"
}

test('Render cursor rows unwrap their header records', () => {
  assert.deepEqual(headerRows([{ header, cursor: 'next-page' }]), [header])
})

test('direct, headers and items response shapes remain supported', () => {
  assert.deepEqual(headerRows([header]), [header])
  assert.deepEqual(headerRows({ headers: [header] }), [header])
  assert.deepEqual(headerRows({ items: [{ header }] }), [header])
  assert.deepEqual(headerRows(null), [])
})
