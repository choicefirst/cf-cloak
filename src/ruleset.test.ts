import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildRuleset,
  deriveRuleSemantics,
  lookupRule,
  normalizeHostname,
  normalizeRuleDomain,
} from './ruleset.js'

describe('normalizeHostname', () => {
  it('lowercases and strips trailing dots', () => {
    assert.equal(normalizeHostname(' Example.COM. '), 'example.com')
  })

  it('punycodes unicode hostnames', () => {
    assert.equal(normalizeHostname('bücher.example'), 'xn--bcher-kva.example')
  })

  it('rejects IP literals', () => {
    assert.equal(normalizeHostname('127.0.0.1'), null)
  })

  it('rejects single-label hostnames when configured', () => {
    assert.equal(normalizeHostname('com', { allowSingleLabel: false }), null)
  })
})

describe('normalizeRuleDomain', () => {
  it('treats wildcard domains as suffix rules', () => {
    assert.deepEqual(normalizeRuleDomain('*.Example.com'), {
      domain: 'example.com',
      matchScope: 'suffix',
    })
  })

  it('rejects invalid rule domains', () => {
    assert.equal(normalizeRuleDomain('0.0.0.0'), null)
    assert.equal(normalizeRuleDomain('com'), null)
  })
})

describe('buildRuleset', () => {
  it('deduplicates and merges repeated rules', () => {
    const ruleset = buildRuleset([
      {
        domain: '*.example.com',
        sources: ['oisd_small'],
        categories: ['ads'],
        firstSeenAt: '2026-05-20T00:00:00Z',
      },
      {
        domain: '*.example.com',
        sources: ['blocklistproject_tracking'],
        categories: ['analytics'],
        compatibilityTags: ['auth'],
        firstSeenAt: '2026-05-18T00:00:00Z',
        lastSeenAt: '2026-05-21T00:00:00Z',
      },
    ])

    assert.equal(ruleset.rules.length, 1)
    assert.deepEqual(ruleset.rules[0], {
      id: 'suffix:example.com',
      domain: 'example.com',
      matchScope: 'suffix',
      registrableDomain: null,
      sources: ['blocklistproject_tracking', 'oisd_small'],
      sourceCount: 2,
      categories: ['ads', 'analytics'],
      entityNames: [],
      confidenceTier: 'high',
      confidenceScore: 0.9,
      lightAction: 'observe',
      extremeAction: 'block',
      compatibilityTags: ['auth'],
      reviewNotes: [],
      firstSeenAt: '2026-05-18T00:00:00Z',
      lastSeenAt: '2026-05-21T00:00:00Z',
    })
  })

  it('skips invalid input rows', () => {
    const ruleset = buildRuleset([
      { domain: 'com' },
      { domain: '127.0.0.1' },
      { domain: '*.valid.example', sources: ['oisd_big'] },
    ])

    assert.equal(ruleset.rules.length, 1)
    assert.equal(ruleset.rules[0].domain, 'valid.example')
  })
})

describe('deriveRuleSemantics', () => {
  it('treats OISD Small plus DDG as high confidence and Light-blockable', () => {
    assert.deepEqual(
      deriveRuleSemantics({ sources: ['oisd_small', 'ddg_tracker_blocklists'] }),
      {
        confidenceTier: 'high',
        confidenceScore: 0.95,
        lightAction: 'block',
      },
    )
  })

  it('keeps OISD Small alone in observe-first Light behavior', () => {
    assert.deepEqual(
      deriveRuleSemantics({ sources: ['oisd_small'] }),
      {
        confidenceTier: 'medium',
        confidenceScore: 0.75,
        lightAction: 'observe',
      },
    )
  })

  it('treats DDG-only metadata as review confidence', () => {
    assert.deepEqual(
      deriveRuleSemantics({ sources: ['ddg_tracker_blocklists'] }),
      {
        confidenceTier: 'review',
        confidenceScore: 0.2,
        lightAction: 'observe',
      },
    )
  })

  it('forces observe when compatibility tags are present', () => {
    assert.deepEqual(
      deriveRuleSemantics({
        sources: ['oisd_small', 'blocklistproject_tracking'],
        compatibilityTags: ['auth'],
      }),
      {
        confidenceTier: 'high',
        confidenceScore: 0.9,
        lightAction: 'observe',
      },
    )
  })

  it('keeps review-gated optional sources in review confidence', () => {
    assert.deepEqual(
      deriveRuleSemantics({ sources: ['hagezi'] }),
      {
        confidenceTier: 'review',
        confidenceScore: 0.35,
        lightAction: 'observe',
      },
    )
  })
})

describe('lookupRule', () => {
  it('prefers an exact match over a suffix match', () => {
    const ruleset = buildRuleset([
      { domain: '*.example.com', sources: ['oisd_small'] },
      { domain: 'api.example.com', matchScope: 'exact', sources: ['blocklistproject_tracking'] },
    ])

    const match = lookupRule('api.example.com', ruleset)

    assert.notEqual(match, null)
    assert.equal(match?.matchScope, 'exact')
    assert.equal(match?.domain, 'api.example.com')
  })

  it('returns the longest suffix match', () => {
    const ruleset = buildRuleset([
      { domain: '*.example.com', sources: ['oisd_big'] },
      { domain: '*.service.example.com', sources: ['oisd_small'] },
    ])

    const match = lookupRule('cdn.service.example.com', ruleset)

    assert.notEqual(match, null)
    assert.equal(match?.matchScope, 'suffix')
    assert.equal(match?.domain, 'service.example.com')
  })

  it('returns null when nothing matches', () => {
    const ruleset = buildRuleset([{ domain: '*.example.com', sources: ['oisd_small'] }])

    assert.equal(lookupRule('api.safe.com', ruleset), null)
  })
})