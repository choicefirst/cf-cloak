/**
 * Tests for cf-cloak TypeScript blocking engine.
 * Uses Node.js built-in test runner — zero external dependencies.
 *
 * Build first:  npm run build
 * Run:          npm test
 */
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { matchDomain, buildBlocklist, anyBlocked, matchDomainDetailed, buildBlocklistDetailed } from './index.js'

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

// ---------------------------------------------------------------------------
// matchDomainDetailed
// ---------------------------------------------------------------------------

describe('matchDomainDetailed', () => {
  it('returns null when no match', () => {
    const bl = new Set(['evil.com'])
    assert.equal(matchDomainDetailed('safe.com', bl), null)
  })

  it('returns suffix with null category/source for plain blocklist', () => {
    const bl = new Set(['doubleclick.net'])
    const result = matchDomainDetailed('px.doubleclick.net', bl)
    assert.deepEqual(result, {
      suffix: 'doubleclick.net',
      matchScope: 'suffix',
      registrableDomain: null,
      category: null,
      categories: [],
      source: null,
      sources: [],
      entityNames: [],
      confidenceTier: null,
      compatibilityTags: [],
      lightAction: null,
      extremeAction: null,
    })
  })

  it('returns metadata when meta map is provided', () => {
    const bl = new Set(['ads.com'])
    const meta = new Map([['ads.com', {
      registrableDomain: 'ads.com',
      category: 'ads',
      categories: ['ads'],
      source: 'easylist',
      sources: ['easylist'],
      entityNames: ['Example Ads'],
      confidenceTier: 'medium' as const,
      compatibilityTags: ['media_delivery'],
      lightAction: 'observe' as const,
      extremeAction: 'block' as const,
    }]])
    const result = matchDomainDetailed('banner.ads.com', bl, meta)
    assert.deepEqual(result, {
      suffix: 'ads.com',
      matchScope: 'suffix',
      registrableDomain: 'ads.com',
      category: 'ads',
      categories: ['ads'],
      source: 'easylist',
      sources: ['easylist'],
      entityNames: ['Example Ads'],
      confidenceTier: 'medium',
      compatibilityTags: ['media_delivery'],
      lightAction: 'observe',
      extremeAction: 'block',
    })
  })

  it('returns null category/source when suffix not in meta', () => {
    const bl = new Set(['foo.com', 'bar.net'])
    const meta = new Map([['foo.com', {
      registrableDomain: null,
      category: 'analytics',
      categories: ['analytics'],
      source: 'mine',
      sources: ['mine'],
      entityNames: [],
      confidenceTier: null,
      compatibilityTags: [],
      lightAction: null,
      extremeAction: null,
    }]])
    // bar.net is in blocklist but not in meta
    const result = matchDomainDetailed('x.bar.net', bl, meta)
    assert.deepEqual(result, {
      suffix: 'bar.net',
      matchScope: 'suffix',
      registrableDomain: null,
      category: null,
      categories: [],
      source: null,
      sources: [],
      entityNames: [],
      confidenceTier: null,
      compatibilityTags: [],
      lightAction: null,
      extremeAction: null,
    })
  })

  it('exact match on domain in meta', () => {
    const bl = new Set(['evil.com'])
    const meta = new Map([['evil.com', {
      registrableDomain: 'evil.com',
      category: 'malware',
      categories: ['malware'],
      source: 'custom',
      sources: ['custom'],
      entityNames: [],
      confidenceTier: 'high' as const,
      compatibilityTags: [],
      lightAction: 'block' as const,
      extremeAction: 'block' as const,
    }]])
    const result = matchDomainDetailed('evil.com', bl, meta)
    assert.deepEqual(result, {
      suffix: 'evil.com',
      matchScope: 'exact',
      registrableDomain: 'evil.com',
      category: 'malware',
      categories: ['malware'],
      source: 'custom',
      sources: ['custom'],
      entityNames: [],
      confidenceTier: 'high',
      compatibilityTags: [],
      lightAction: 'block',
      extremeAction: 'block',
    })
  })
})

// ---------------------------------------------------------------------------
// buildBlocklistDetailed
// ---------------------------------------------------------------------------

describe('buildBlocklistDetailed', () => {
  it('handles plain strings', () => {
    const { set, meta } = buildBlocklistDetailed(['evil.com', 'tracker.net'])
    assert.equal(set.size, 2)
    assert.equal(set.has('evil.com'), true)
    assert.equal(meta.size, 0)
  })

  it('handles rich RuleEntry objects', () => {
    const { set, meta } = buildBlocklistDetailed([
      { domain: 'doubleclick.net', category: 'ads', source: 'easylist' },
    ])
    assert.equal(set.has('doubleclick.net'), true)
    assert.deepEqual(meta.get('doubleclick.net'), {
      registrableDomain: null,
      category: 'ads',
      categories: ['ads'],
      source: 'easylist',
      sources: ['easylist'],
      entityNames: [],
      confidenceTier: null,
      compatibilityTags: [],
      lightAction: null,
      extremeAction: null,
    })
  })

  it('handles mixed plain strings and RuleEntry objects', () => {
    const { set, meta } = buildBlocklistDetailed([
      'plain.com',
      { domain: 'rich.net', category: 'analytics', source: 'mine' },
    ])
    assert.equal(set.size, 2)
    assert.equal(meta.size, 1)
    assert.equal(meta.has('plain.com'), false)
  })

  it('normalises domain case and whitespace', () => {
    const { set } = buildBlocklistDetailed(['  EVIL.COM  ', { domain: '  BAD.NET  ', category: 'ads' }])
    assert.equal(set.has('evil.com'), true)
    assert.equal(set.has('bad.net'), true)
  })

  it('skips empty strings', () => {
    const { set } = buildBlocklistDetailed(['', '   ', { domain: '' }])
    assert.equal(set.size, 0)
  })

  it('RuleEntry with missing optional fields gets null in meta', () => {
    const { meta } = buildBlocklistDetailed([{ domain: 'x.com' }])
    assert.deepEqual(meta.get('x.com'), {
      registrableDomain: null,
      category: null,
      categories: [],
      source: null,
      sources: [],
      entityNames: [],
      confidenceTier: null,
      compatibilityTags: [],
      lightAction: null,
      extremeAction: null,
    })
  })

  it('preserves richer canonical metadata with compatibility shorthands', () => {
    const { meta } = buildBlocklistDetailed([
      {
        domain: 'tracker.example.com',
        registrableDomain: 'Example.com',
        category: 'tracking',
        categories: ['tracking', 'analytics'],
        source: 'oisd_small',
        sources: ['oisd_small', 'ddg_tracker_blocklists'],
        entityNames: ['Branch Metrics', 'Branch Metrics, Inc.'],
        confidenceTier: 'high',
        compatibilityTags: ['auth', 'app_api'],
        lightAction: 'observe',
        extremeAction: 'block',
      },
    ])

    assert.deepEqual(meta.get('tracker.example.com'), {
      registrableDomain: 'example.com',
      category: 'tracking',
      categories: ['tracking', 'analytics'],
      source: 'oisd_small',
      sources: ['oisd_small', 'ddg_tracker_blocklists'],
      entityNames: ['Branch Metrics', 'Branch Metrics, Inc.'],
      confidenceTier: 'high',
      compatibilityTags: ['auth', 'app_api'],
      lightAction: 'observe',
      extremeAction: 'block',
    })
  })
})
