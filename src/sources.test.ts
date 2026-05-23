import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { parseSourceText } from './sources.js'

describe('parseSourceText', () => {
  it('parses plain domains, hosts entries, and adblock rules', () => {
    const result = parseSourceText(
      [
        '# comment',
        'tracker.example.com',
        '0.0.0.0 ads.example.org',
        '||analytics.example.net^$third-party',
      ].join('\n'),
      {
        source: 'oisd_small',
        categories: ['tracking'],
        confidenceTier: 'high',
      },
    )

    assert.deepEqual(result.rules, [
      {
        domain: 'tracker.example.com',
        matchScope: 'exact',
        sources: ['oisd_small'],
        categories: ['tracking'],
        entityNames: undefined,
        compatibilityTags: undefined,
        confidenceTier: 'high',
        lightAction: undefined,
      },
      {
        domain: 'ads.example.org',
        matchScope: 'exact',
        sources: ['oisd_small'],
        categories: ['tracking'],
        entityNames: undefined,
        compatibilityTags: undefined,
        confidenceTier: 'high',
        lightAction: undefined,
      },
      {
        domain: 'analytics.example.net',
        matchScope: 'suffix',
        sources: ['oisd_small'],
        categories: ['tracking'],
        entityNames: undefined,
        compatibilityTags: undefined,
        confidenceTier: 'high',
        lightAction: undefined,
      },
    ])
    assert.deepEqual(result.exceptions, [])
  })

  it('captures exception rules separately', () => {
    const result = parseSourceText(
      [
        '@@||auth.example.com^',
        '@@payments.example.com',
      ].join('\n'),
      { source: 'blocklistproject_tracking' },
    )

    assert.deepEqual(result.rules, [])
    assert.deepEqual(result.exceptions, [
      { domain: 'auth.example.com', matchScope: 'suffix' },
      { domain: 'payments.example.com', matchScope: 'exact' },
    ])
  })

  it('deduplicates repeated matches by domain and scope', () => {
    const result = parseSourceText(
      [
        'tracker.example.com',
        'tracker.example.com',
        '||tracker.example.com^',
        '||tracker.example.com^',
      ].join('\n'),
      { source: 'oisd_big' },
    )

    assert.deepEqual(result.rules, [
      {
        domain: 'tracker.example.com',
        matchScope: 'exact',
        sources: ['oisd_big'],
        categories: undefined,
        entityNames: undefined,
        compatibilityTags: undefined,
        confidenceTier: undefined,
        lightAction: undefined,
      },
      {
        domain: 'tracker.example.com',
        matchScope: 'suffix',
        sources: ['oisd_big'],
        categories: undefined,
        entityNames: undefined,
        compatibilityTags: undefined,
        confidenceTier: undefined,
        lightAction: undefined,
      },
    ])
  })

  it('ignores unsupported or invalid lines', () => {
    const result = parseSourceText(
      [
        '! comment',
        '[Adblock Plus 2.0]',
        '/regex/',
        '127.0.0.1 localhost',
        'com',
        '||',
      ].join('\n'),
      { source: 'oisd_small' },
    )

    assert.deepEqual(result.rules, [])
    assert.deepEqual(result.exceptions, [])
  })

  it('propagates optional metadata fields onto emitted rules', () => {
    const result = parseSourceText('cdn.example.com', {
      source: 'blocklistproject_tracking',
      categories: ['tracking'],
      entityNames: ['Example CDN'],
      compatibilityTags: ['media_delivery'],
      confidenceTier: 'medium',
      lightAction: 'observe',
    })

    assert.deepEqual(result.rules, [
      {
        domain: 'cdn.example.com',
        matchScope: 'exact',
        sources: ['blocklistproject_tracking'],
        categories: ['tracking'],
        entityNames: ['Example CDN'],
        compatibilityTags: ['media_delivery'],
        confidenceTier: 'medium',
        lightAction: 'observe',
      },
    ])
  })
})