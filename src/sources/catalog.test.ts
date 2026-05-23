import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  getUpstreamSourceDefinition,
  parseUpstreamSourceData,
  PRIMARY_UPSTREAM_SOURCE_IDS,
  REVIEW_GATED_UPSTREAM_SOURCE_IDS,
} from './catalog.js'

const DDG_FIXTURE = JSON.stringify({
  readme: 'https://github.com/duckduckgo/tracker-blocklists',
  version: 1688648647512,
  trackers: {
    'api.branch.io': {
      owner: { name: 'Branch Metrics, Inc.', displayName: 'Branch Metrics' },
      default: 'block',
    },
  },
  packageNames: {
    'com.branch.sample': 'Branch Metrics, Inc.',
  },
  entities: {
    'Branch Metrics, Inc.': {
      score: 33342,
      signals: ['email_address', 'AAID'],
    },
  },
})

describe('getUpstreamSourceDefinition', () => {
  it('returns primary-source defaults for OISD Small', () => {
    assert.deepEqual(getUpstreamSourceDefinition('oisd_small'), {
      id: 'oisd_small',
      name: 'OISD Small',
      url: 'https://small.oisd.nl',
      format: 'domain_text',
      trustTier: 'A',
      reviewGate: false,
      lightUse: 'high_confidence_candidate',
      extremeDefaultEnabled: true,
    })
  })

  it('marks optional upstreams as review-gated', () => {
    for (const sourceId of REVIEW_GATED_UPSTREAM_SOURCE_IDS) {
      assert.equal(getUpstreamSourceDefinition(sourceId).reviewGate, true)
      assert.equal(getUpstreamSourceDefinition(sourceId).trustTier, 'C')
    }
  })

  it('keeps the expected primary source set', () => {
    assert.deepEqual(PRIMARY_UPSTREAM_SOURCE_IDS, [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
    ])
  })
})

describe('parseUpstreamSourceData', () => {
  it('dispatches text sources through the generic text parser', () => {
    const parsed = parseUpstreamSourceData(
      'blocklistproject_tracking',
      ['0.0.0.0 tracker.example.com', '@@auth.example.com'].join('\n'),
    )

    assert.equal(parsed.source, 'blocklistproject_tracking')
    assert.deepEqual(parsed.rules, [
      {
        domain: 'tracker.example.com',
        matchScope: 'exact',
        sources: ['blocklistproject_tracking'],
        categories: undefined,
        entityNames: undefined,
        compatibilityTags: undefined,
        confidenceTier: undefined,
        lightAction: undefined,
      },
    ])
    assert.deepEqual(parsed.exceptions, [{ domain: 'auth.example.com', matchScope: 'exact' }])
    assert.equal(parsed.version, null)
    assert.equal(parsed.readme, null)
  })

  it('dispatches DDG sources through the JSON metadata parser', () => {
    const parsed = parseUpstreamSourceData('ddg_tracker_blocklists', DDG_FIXTURE)

    assert.equal(parsed.source, 'ddg_tracker_blocklists')
    assert.equal(parsed.version, '1688648647512')
    assert.equal(parsed.readme, 'https://github.com/duckduckgo/tracker-blocklists')
    assert.deepEqual(parsed.rules, [
      {
        domain: 'api.branch.io',
        matchScope: 'exact',
        sources: ['ddg_tracker_blocklists'],
        categories: ['tracking'],
        entityNames: ['Branch Metrics', 'Branch Metrics, Inc.'],
        confidenceTier: 'review',
        lightAction: 'observe',
        reviewNotes: ['ddg_default:block'],
      },
    ])
    assert.deepEqual(parsed.packageOwners, { 'com.branch.sample': 'Branch Metrics, Inc.' })
    assert.deepEqual(parsed.entities, {
      'Branch Metrics, Inc.': {
        displayName: 'Branch Metrics',
        score: 33342,
        signals: ['AAID', 'email_address'],
      },
    })
  })
})