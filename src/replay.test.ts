import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { applyCompatibilityOverrides } from './compatibility.js'
import { DEFAULT_POLICY } from './policy.js'
import { ANONYMIZED_PILOT_DNS_TRACES } from './replayFixtures.js'
import { buildReplayDiffReport, difference, replayAllSessions, replaySession } from './replay.js'
import { buildRuleset } from './ruleset.js'
import type { CanonicalRuleInput } from './ruleset.js'
import type { RulesetExceptionEntry } from './signing.js'

const NOW = 1_700_000_000_000

const PRIMARY_RULES: readonly CanonicalRuleInput[] = [
  {
    domain: 'login.example.com',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'checkout.example.com',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'stream-cdn.example.com',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'captcha.example.com',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'bootstrap-api.example.com',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'startup-telemetry.example.com',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'ads.measurement.example',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'analytics.beacon.example',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
  {
    domain: 'metrics-core.example.com',
    sources: ['oisd_small', 'ddg_tracker_blocklists'],
    categories: ['tracking'],
  },
] as const

const OPTIONAL_RULES: readonly CanonicalRuleInput[] = [
  {
    domain: 'fingerprint.optional.example',
    sources: ['hagezi'],
    categories: ['tracking'],
  },
  {
    domain: 'video-reco.optional.example',
    sources: ['easylist'],
    categories: ['tracking'],
  },
  {
    domain: 'crash-upload.optional.example',
    sources: ['steven_black'],
    categories: ['tracking'],
  },
] as const

const COMPATIBILITY_OVERRIDES: RulesetExceptionEntry[] = [
  {
    domain: 'login.example.com',
    matchScope: 'exact' as const,
    reason: 'auth flow',
    tags: ['auth'],
  },
  {
    domain: 'checkout.example.com',
    matchScope: 'exact' as const,
    reason: 'payment checkout',
    tags: ['payments'],
  },
  {
    domain: 'stream-cdn.example.com',
    matchScope: 'exact' as const,
    reason: 'media playback',
    tags: ['media_delivery'],
  },
  {
    domain: 'captcha.example.com',
    matchScope: 'exact' as const,
    reason: 'captcha challenge',
    tags: ['captcha'],
  },
  {
    domain: 'bootstrap-api.example.com',
    matchScope: 'exact' as const,
    reason: 'pilot bootstrap',
    tags: ['app_api'],
  },
  {
    domain: 'startup-telemetry.example.com',
    matchScope: 'exact' as const,
    reason: 'feature gated telemetry',
    tags: ['telemetry'],
  },
]

const primaryRuleset = applyCompatibilityOverrides(
  buildRuleset(PRIMARY_RULES, {
    version: 'replay-primary',
    generatedAt: '2026-05-23T00:06:00Z',
  }),
  COMPATIBILITY_OVERRIDES,
)

const primaryWithOptionalRuleset = applyCompatibilityOverrides(
  buildRuleset([...PRIMARY_RULES, ...OPTIONAL_RULES], {
    version: 'replay-primary-optional',
    generatedAt: '2026-05-23T00:07:00Z',
  }),
  COMPATIBILITY_OVERRIDES,
)

describe('replay traces', () => {
  it('keeps known-good pilot sessions available in Light while tagging matched trackers', () => {
    for (const session of ANONYMIZED_PILOT_DNS_TRACES) {
      const replay = replaySession(session, primaryRuleset, DEFAULT_POLICY, NOW)

      for (const domain of session.mustStayAvailable) {
        assert.equal(
          replay.blockedDomains.has(domain),
          false,
          `${session.name} should keep ${domain} available in Light`,
        )
      }

      for (const domain of session.expectedObservedInLight) {
        assert.equal(
          replay.observedDomains.has(domain),
          true,
          `${session.name} should observe ${domain} in Light`,
        )
      }

      for (const domain of session.expectedBlockedInLight) {
        assert.equal(
          replay.blockedDomains.has(domain),
          true,
          `${session.name} should still block ${domain} in Light`,
        )
      }
    }
  })

  it('measures additional blocking coverage from Extreme mode', () => {
    const light = replayAllSessions(ANONYMIZED_PILOT_DNS_TRACES, primaryRuleset, DEFAULT_POLICY, NOW)
    const extreme = replayAllSessions(
      ANONYMIZED_PILOT_DNS_TRACES,
      primaryRuleset,
      { ...DEFAULT_POLICY, mode: 'extreme' },
      NOW,
    )

    assert.ok(extreme.blockedCount > light.blockedCount)

    const incrementalExtremeCoverage = difference(extreme.blockedDomains, light.blockedDomains)
    assert.deepEqual(
      [...incrementalExtremeCoverage].sort((left, right) => left.localeCompare(right)),
      [
        'bootstrap-api.example.com',
        'captcha.example.com',
        'checkout.example.com',
        'login.example.com',
        'startup-telemetry.example.com',
        'stream-cdn.example.com',
      ],
    )
  })

  it('measures incremental matched coverage from optional sources', () => {
    const report = buildReplayDiffReport(
      ANONYMIZED_PILOT_DNS_TRACES,
      primaryRuleset,
      primaryWithOptionalRuleset,
      DEFAULT_POLICY,
      { ...DEFAULT_POLICY, mode: 'extreme' },
      NOW,
    )

    assert.ok(report.light.matchedCountDelta > 0)
    assert.ok(report.extreme.blockedCountDelta > 0)
    assert.deepEqual(
      report.light.matchedDomainsDelta,
      [
        'crash-upload.optional.example',
        'fingerprint.optional.example',
        'video-reco.optional.example',
      ],
    )
    assert.deepEqual(
      report.extreme.blockedDomainsDelta,
      [
        'crash-upload.optional.example',
        'fingerprint.optional.example',
        'video-reco.optional.example',
      ],
    )
  })
})
