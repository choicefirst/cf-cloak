/**
 * Tests for cf-cloak TypeScript blocking engine.
 * Uses Node.js built-in test runner — zero external dependencies.
 *
 * Build first:  npm run build
 * Run:          npm test
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { matchDomain, buildBlocklist, anyBlocked } from './index.js'

// ---------------------------------------------------------------------------
// matchDomain
// ---------------------------------------------------------------------------

describe('matchDomain', () => {
  it('returns null for empty blocklist', () => {
    assert.equal(matchDomain('evil.com', new Set()), null)
  })

  it('exact match', () => {
    const bl = new Set(['evil.com'])
    assert.equal(matchDomain('evil.com', bl), 'evil.com')
  })

  it('single-level suffix match', () => {
    const bl = new Set(['doubleclick.net'])
    assert.equal(matchDomain('tracker.doubleclick.net', bl), 'doubleclick.net')
  })

  it('multi-level suffix match', () => {
    const bl = new Set(['facebook.com'])
    assert.equal(matchDomain('graph.facebook.com', bl), 'facebook.com')
    assert.equal(matchDomain('deep.sub.graph.facebook.com', bl), 'facebook.com')
  })

  it('no match on unrelated domain', () => {
    const bl = new Set(['evil.com'])
    assert.equal(matchDomain('example.com', bl), null)
  })

  it('does not match parent of a blocked suffix', () => {
    // blocking 'tracker.evil.com' should NOT block 'evil.com' itself
    const bl = new Set(['tracker.evil.com'])
    assert.equal(matchDomain('evil.com', bl), null)
  })

  it('does not match sibling subdomain', () => {
    const bl = new Set(['ads.evil.com'])
    assert.equal(matchDomain('safe.evil.com', bl), null)
  })

  it('prefers exact match over suffix match', () => {
    // Both 'foo.bar.com' and 'bar.com' are blocked; exact should win
    const bl = new Set(['foo.bar.com', 'bar.com'])
    assert.equal(matchDomain('foo.bar.com', bl), 'foo.bar.com')
  })

  it('handles single-label domain', () => {
    const bl = new Set(['localhost'])
    assert.equal(matchDomain('localhost', bl), 'localhost')
  })

  it('handles TLD-only entry gracefully (no crash)', () => {
    const bl = new Set(['com'])
    // Matching 'foo.com' against a TLD block is technically valid
    assert.equal(matchDomain('foo.com', bl), 'com')
  })
})

// ---------------------------------------------------------------------------
// buildBlocklist
// ---------------------------------------------------------------------------

describe('buildBlocklist', () => {
  it('produces a Set from an array', () => {
    const bl = buildBlocklist(['evil.com', 'bad.net'])
    assert(bl instanceof Set)
    assert.equal(bl.size, 2)
  })

  it('lowercases all entries', () => {
    const bl = buildBlocklist(['EVIL.COM', 'Bad.Net'])
    assert(bl.has('evil.com'))
    assert(bl.has('bad.net'))
  })

  it('trims whitespace', () => {
    const bl = buildBlocklist(['  evil.com  ', '\tbad.net\n'])
    assert(bl.has('evil.com'))
    assert(bl.has('bad.net'))
  })

  it('deduplicates', () => {
    const bl = buildBlocklist(['evil.com', 'evil.com', 'EVIL.COM'])
    assert.equal(bl.size, 1)
  })

  it('filters out empty strings', () => {
    const bl = buildBlocklist(['', '   ', 'evil.com'])
    assert.equal(bl.size, 1)
  })

  it('handles empty input', () => {
    const bl = buildBlocklist([])
    assert.equal(bl.size, 0)
  })
})

// ---------------------------------------------------------------------------
// anyBlocked
// ---------------------------------------------------------------------------

describe('anyBlocked', () => {
  it('returns true if any domain matches', () => {
    const bl = new Set(['evil.com'])
    assert.equal(anyBlocked(['safe.com', 'tracker.evil.com'], bl), true)
  })

  it('returns false when none match', () => {
    const bl = new Set(['evil.com'])
    assert.equal(anyBlocked(['safe.com', 'good.net'], bl), false)
  })

  it('returns false on empty domain list', () => {
    const bl = new Set(['evil.com'])
    assert.equal(anyBlocked([], bl), false)
  })

  it('normalises input domains before matching', () => {
    const bl = new Set(['evil.com'])
    assert.equal(anyBlocked(['  TRACKER.EVIL.COM  '], bl), true)
  })
})
