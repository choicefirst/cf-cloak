import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { buildReviewGatedSourceRolloutReport } from './rollout.js'

const EMPTY_DDG_FIXTURE = JSON.stringify({
  readme: 'https://github.com/duckduckgo/tracker-blocklists',
  version: 1688648647512,
  trackers: {},
  entities: {},
})

describe('buildReviewGatedSourceRolloutReport', () => {
  it('packages a before/after report and rollback plan for one review-gated source', () => {
    const report = buildReviewGatedSourceRolloutReport({
      source: 'hagezi',
      snapshotsBySource: {
        oisd_small: {
          content: 'ads.measurement.example\n',
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
        oisd_big: {
          content: '',
          fetchedAt: '2026-05-23T00:01:00Z',
          parserVersion: '1.0.0',
        },
        ddg_tracker_blocklists: {
          content: EMPTY_DDG_FIXTURE,
          fetchedAt: '2026-05-23T00:02:00Z',
          parserVersion: '1.0.0',
        },
        blocklistproject_tracking: {
          content: '',
          fetchedAt: '2026-05-23T00:03:00Z',
          parserVersion: '1.0.0',
        },
        hagezi: {
          content: 'ads.measurement.example\nfingerprint.optional.example\n',
          fetchedAt: '2026-05-23T00:04:00Z',
          parserVersion: '1.0.0',
        },
      },
      replaySessions: [
        {
          name: 'pilot_trace',
          appId: 'com.choicefirst.pilot',
          requests: [
            'app.choicefirst.example',
            'ads.measurement.example',
            'fingerprint.optional.example',
          ],
        },
      ],
      baselineVersion: 'ruleset-v3-primary',
      candidateVersion: 'ruleset-v4-hagezi',
      issuedAt: 1_716_422_400,
      generatedAt: '2026-05-23T00:05:00Z',
      replayNow: 1_700_000_000_000,
    })

    assert.deepEqual(report.baselineSources, [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
    ])
    assert.deepEqual(report.candidateSources, [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
      'hagezi',
    ])
    assert.deepEqual(report.candidateBundle.payload.rollback, {
      previousVersion: 'ruleset-v3-primary',
      rollbackOf: null,
    })

    assert.deepEqual(report.rulesetDiff.summary, {
      addedRuleCount: 1,
      removedRuleCount: 0,
      changedRuleCount: 1,
    })
    assert.equal(report.rulesetDiff.addedRules[0]?.domain, 'fingerprint.optional.example')
    assert.equal(report.rulesetDiff.changedRules[0]?.domain, 'ads.measurement.example')
    assert.deepEqual(report.rulesetDiff.changedRules[0]?.addedSources, ['hagezi'])
    assert.deepEqual(report.rulesetDiff.changedRules[0]?.removedSources, [])

    assert.deepEqual(report.replayDiff.light.matchedDomainsDelta, ['fingerprint.optional.example'])
    assert.deepEqual(report.replayDiff.extreme.blockedDomainsDelta, ['fingerprint.optional.example'])

    assert.deepEqual(report.rollbackPlan, {
      restoreSources: [
        'oisd_small',
        'oisd_big',
        'ddg_tracker_blocklists',
        'blocklistproject_tracking',
      ],
      removeSources: ['hagezi'],
      restoreConfigurationVersion: 'ruleset-v3-primary',
      rollbackInfo: {
        previousVersion: 'ruleset-v4-hagezi',
        rollbackOf: 'ruleset-v4-hagezi',
      },
    })
    assert.deepEqual(report.warnings, [])
  })

  it('rejects sources that are not review-gated Tier C upstreams', () => {
    assert.throws(
      () => buildReviewGatedSourceRolloutReport({
        source: 'oisd_small',
        snapshotsBySource: {
          oisd_small: {
            content: 'ads.measurement.example\n',
            fetchedAt: '2026-05-23T00:00:00Z',
            parserVersion: '1.0.0',
          },
        },
        replaySessions: [],
        baselineSources: ['oisd_small'],
        baselineVersion: 'ruleset-v3-primary',
        candidateVersion: 'ruleset-v4-invalid',
        issuedAt: 1_716_422_400,
        generatedAt: '2026-05-23T00:05:00Z',
      }),
      /review-gated Tier C upstream/,
    )
  })

  it('warns when the replay set does not exercise any candidate-source deltas', () => {
    const report = buildReviewGatedSourceRolloutReport({
      source: 'hagezi',
      snapshotsBySource: {
        oisd_small: {
          content: 'ads.measurement.example\n',
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
        oisd_big: {
          content: '',
          fetchedAt: '2026-05-23T00:01:00Z',
          parserVersion: '1.0.0',
        },
        ddg_tracker_blocklists: {
          content: EMPTY_DDG_FIXTURE,
          fetchedAt: '2026-05-23T00:02:00Z',
          parserVersion: '1.0.0',
        },
        blocklistproject_tracking: {
          content: '',
          fetchedAt: '2026-05-23T00:03:00Z',
          parserVersion: '1.0.0',
        },
        hagezi: {
          content: 'telemetry.hagezi.example\n',
          fetchedAt: '2026-05-23T00:04:00Z',
          parserVersion: '1.0.0',
        },
      },
      replaySessions: [
        {
          name: 'pilot_trace',
          appId: 'com.choicefirst.pilot',
          requests: ['app.choicefirst.example', 'ads.measurement.example'],
        },
      ],
      baselineVersion: 'ruleset-v3-primary',
      candidateVersion: 'ruleset-v4-hagezi',
      issuedAt: 1_716_422_400,
      generatedAt: '2026-05-23T00:05:00Z',
      replayNow: 1_700_000_000_000,
    })

    assert.deepEqual(report.warnings, [
      'Candidate source hagezi changes the ruleset, but the configured replay sessions produced no matched or blocked delta. Review the domain-level diff before enabling it.',
    ])
  })
})