import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  isLikelyDdgTrackerDataset,
  normalizeDdgTrackerDomain,
  parseDdgTrackerData,
} from './ddg.js'

const FIXTURE = JSON.stringify({
  readme: 'https://github.com/duckduckgo/tracker-blocklists',
  version: 1688648647512,
  trackers: {
    'api.branch.io': {
      owner: { name: 'Branch Metrics, Inc.', displayName: 'Branch Metrics' },
      default: 'block',
    },
    'accounts.google.com': {
      owner: { name: 'Google LLC', displayName: 'Google' },
      default: 'ignore',
    },
    ' invalid host ': {
      owner: { name: 'Bad Actor', displayName: 'Bad Actor' },
      default: 'block',
    },
  },
  packageNames: {
    'com.branch.sample ': 'Branch Metrics, Inc.',
    'com.google.android.gm': 'Google LLC',
    'not a package name': 'Broken Owner',
  },
  entities: {
    'Branch Metrics, Inc.': {
      score: 33342,
      signals: ['email_address', 'AAID', 'AAID'],
    },
    'Google LLC': {
      score: 326430,
      signals: ['cookies', 'email_address'],
    },
    'Empty Entity': {
      score: Number.NaN,
      signals: [null],
    },
  },
})

describe('parseDdgTrackerData', () => {
  it('parses tracker domains into metadata-only canonical rules', () => {
    const result = parseDdgTrackerData(FIXTURE)

    assert.deepEqual(result.rules, [
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
      {
        domain: 'accounts.google.com',
        matchScope: 'exact',
        sources: ['ddg_tracker_blocklists'],
        categories: ['tracking'],
        entityNames: ['Google', 'Google LLC'],
        confidenceTier: 'review',
        lightAction: 'observe',
        reviewNotes: ['ddg_default:ignore'],
      },
    ])
  })

  it('builds entity and package-owner indexes', () => {
    const result = parseDdgTrackerData(FIXTURE)

    assert.deepEqual(result.packageOwners, {
      'com.branch.sample': 'Branch Metrics, Inc.',
      'com.google.android.gm': 'Google LLC',
    })
    assert.deepEqual(result.entities, {
      'Branch Metrics, Inc.': {
        displayName: 'Branch Metrics',
        score: 33342,
        signals: ['AAID', 'email_address'],
      },
      'Google LLC': {
        displayName: 'Google',
        score: 326430,
        signals: ['cookies', 'email_address'],
      },
      'Empty Entity': {
        displayName: null,
        score: null,
        signals: [],
      },
    })
  })

  it('returns manifest metadata fields', () => {
    const result = parseDdgTrackerData(FIXTURE)

    assert.equal(result.readme, 'https://github.com/duckduckgo/tracker-blocklists')
    assert.equal(result.version, '1688648647512')
  })
})

describe('isLikelyDdgTrackerDataset', () => {
  it('detects tracker datasets by trackers object presence', () => {
    assert.equal(isLikelyDdgTrackerDataset({ trackers: {} }), true)
    assert.equal(isLikelyDdgTrackerDataset({ packageNames: {} }), false)
    assert.equal(isLikelyDdgTrackerDataset(null), false)
  })
})

describe('normalizeDdgTrackerDomain', () => {
  it('normalizes valid tracker domains', () => {
    assert.equal(normalizeDdgTrackerDomain(' Accounts.Google.com '), 'accounts.google.com')
  })

  it('rejects invalid domains', () => {
    assert.equal(normalizeDdgTrackerDomain('0.0.0.0'), null)
  })
})