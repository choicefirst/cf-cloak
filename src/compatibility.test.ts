import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { applyCompatibilityOverrides, lookupRulesetException } from './compatibility.js'
import { DEFAULT_POLICY } from './policy.js'
import { buildRuleset } from './ruleset.js'
import { evaluateRulesetRequest } from './runtime.js'

const NOW = 1_700_000_000_000

const FALSE_POSITIVE_FIXTURES = [
  {
    name: 'auth flows',
    domain: 'login.example.com',
    reason: 'auth flow',
    tags: ['auth'],
  },
  {
    name: 'payments and checkout',
    domain: 'checkout.example.com',
    reason: 'payment checkout',
    tags: ['payments'],
  },
  {
    name: 'media playback and streaming CDNs',
    domain: 'stream-cdn.example.com',
    reason: 'media stream bootstrap',
    tags: ['media_delivery'],
  },
  {
    name: 'captcha flows',
    domain: 'captcha.example.com',
    reason: 'captcha challenge',
    tags: ['captcha'],
  },
  {
    name: 'app startup APIs for top pilot apps',
    domain: 'bootstrap-api.example.com',
    reason: 'pilot app bootstrap',
    tags: ['app_api'],
  },
  {
    name: 'telemetry tied to feature availability',
    domain: 'startup-telemetry.example.com',
    reason: 'feature gated telemetry',
    tags: ['telemetry'],
  },
] as const

describe('lookupRulesetException', () => {
  it('prefers exact matches over suffix matches and normalizes the hostname', () => {
    const matched = lookupRulesetException('Auth.Example.com.', [
      {
        domain: 'example.com',
        matchScope: 'suffix',
        reason: 'catch-all auth',
        tags: ['auth'],
      },
      {
        domain: 'auth.example.com',
        matchScope: 'exact',
        reason: 'exact auth',
        tags: ['auth'],
      },
    ])

    assert.deepEqual(matched, {
      domain: 'auth.example.com',
      matchScope: 'exact',
      reason: 'exact auth',
      tags: ['auth'],
    })
  })

  it('returns the longest suffix match when no exact match exists', () => {
    const matched = lookupRulesetException('img.cdn.example.com', [
      {
        domain: 'example.com',
        matchScope: 'suffix',
        reason: 'site-wide media',
        tags: ['media_delivery'],
      },
      {
        domain: 'cdn.example.com',
        matchScope: 'suffix',
        reason: 'cdn media',
        tags: ['media_delivery'],
      },
    ])

    assert.deepEqual(matched, {
      domain: 'cdn.example.com',
      matchScope: 'suffix',
      reason: 'cdn media',
      tags: ['media_delivery'],
    })
  })
})

describe('applyCompatibilityOverrides', () => {
  it('adds compatibility tags and downgrades light-mode action to observe', () => {
    const ruleset = buildRuleset(
      [
        {
          domain: 'tracker.example.com',
          sources: ['ddg_tracker_blocklists', 'oisd_small'],
          categories: ['tracking'],
        },
      ],
      {
        version: 'ruleset-v2',
        generatedAt: '2026-05-23T00:06:00Z',
      },
    )

    const updated = applyCompatibilityOverrides(ruleset, [
      {
        domain: 'tracker.example.com',
        matchScope: 'exact',
        reason: 'core auth',
        tags: ['auth'],
      },
    ])

    assert.deepEqual(updated.rules[0], {
      ...ruleset.rules[0],
      compatibilityTags: ['auth'],
      lightAction: 'observe',
      reviewNotes: ['compatibility:core auth'],
    })
  })
})

describe('false-positive regression fixtures', () => {
  for (const fixture of FALSE_POSITIVE_FIXTURES) {
    it(`keeps ${fixture.name} observed in Light while preserving Extreme blocking`, () => {
      const ruleset = buildRuleset(
        [
          {
            domain: fixture.domain,
            sources: ['oisd_small', 'ddg_tracker_blocklists'],
            categories: ['tracking'],
          },
        ],
        {
          version: 'ruleset-v2',
          generatedAt: '2026-05-23T00:06:00Z',
        },
      )

      const baseline = evaluateRulesetRequest(fixture.domain, ruleset, DEFAULT_POLICY, {
        app: 'com.choicefirst.pilot',
        now: NOW,
      })

      assert.ok(baseline)
      assert.equal(baseline?.decision.reason, 'rule_block')
      assert.equal(baseline?.decision.action, 'block')

      const updated = applyCompatibilityOverrides(ruleset, [
        {
          domain: fixture.domain,
          matchScope: 'exact',
          reason: fixture.reason,
          tags: [...fixture.tags],
        },
      ])

      assert.deepEqual(updated.rules[0]?.compatibilityTags, fixture.tags)
      assert.equal(updated.rules[0]?.lightAction, 'observe')
      assert.deepEqual(updated.rules[0]?.reviewNotes, [`compatibility:${fixture.reason}`])

      const light = evaluateRulesetRequest(fixture.domain, updated, DEFAULT_POLICY, {
        app: 'com.choicefirst.pilot',
        now: NOW,
      })

      assert.ok(light)
      assert.equal(light?.decision.reason, 'rule_observe')
      assert.equal(light?.decision.effect, 'observe')
      assert.equal(light?.decision.action, 'allow')

      const extreme = evaluateRulesetRequest(
        fixture.domain,
        updated,
        { ...DEFAULT_POLICY, mode: 'extreme' },
        {
          app: 'com.choicefirst.pilot',
          now: NOW,
        },
      )

      assert.ok(extreme)
      assert.equal(extreme?.decision.reason, 'rule_block')
      assert.equal(extreme?.decision.effect, 'block')
      assert.equal(extreme?.decision.action, 'block')
    })
  }
})