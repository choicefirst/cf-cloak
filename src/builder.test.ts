import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { generateKeyPairSync } from 'node:crypto'

import {
  buildRulesetBundle,
  buildRulesetBundleFromSourceMap,
  buildSignedRulesetBundle,
  buildSignedRulesetBundleFromSourceMap,
  buildUpstreamSourceSnapshots,
  diffRulesetAgainstLegacyDomains,
  selectUpstreamSourceIds,
} from './builder.js'
import { verifyRuleset } from './signing.js'

const DDG_FIXTURE = JSON.stringify({
  readme: 'https://github.com/duckduckgo/tracker-blocklists',
  version: 1688648647512,
  trackers: {
    'tracker.example.com': {
      owner: { name: 'Example Tracker Inc.', displayName: 'Example Tracker' },
      default: 'block',
    },
  },
  entities: {
    'Example Tracker Inc.': {
      score: 1024,
      signals: ['AAID'],
    },
  },
})

describe('buildRulesetBundle', () => {
  it('selects the primary upstream source set by default', () => {
    assert.deepEqual(selectUpstreamSourceIds(), [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
    ])
  })

  it('adds review-gated upstreams only when explicitly requested', () => {
    assert.deepEqual(selectUpstreamSourceIds({ includeReviewGated: true }), [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
      '1hosts',
      'adguard_dns_filter',
      'hagezi',
      'easylist',
      'steven_black',
    ])
  })

  it('builds ordered snapshots from the default primary source set', () => {
    const snapshots = buildUpstreamSourceSnapshots({
      oisd_small: {
        content: 'tracker.example.com\n',
        fetchedAt: '2026-05-23T00:00:00Z',
        parserVersion: '1.0.0',
      },
      oisd_big: {
        content: 'tracker.example.com\n',
        fetchedAt: '2026-05-23T00:01:00Z',
        parserVersion: '1.0.0',
      },
      ddg_tracker_blocklists: {
        content: DDG_FIXTURE,
        fetchedAt: '2026-05-23T00:02:00Z',
        parserVersion: '1.0.0',
      },
      blocklistproject_tracking: {
        content: 'tracker.example.com\n',
        fetchedAt: '2026-05-23T00:03:00Z',
        parserVersion: '1.0.0',
      },
    })

    assert.deepEqual(snapshots.map((snapshot) => snapshot.source), [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
    ])
  })

  it('throws when a selected upstream snapshot is missing', () => {
    assert.throws(
      () => buildUpstreamSourceSnapshots({
        oisd_small: {
          content: 'tracker.example.com\n',
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
      }),
      /Missing snapshot for upstream source: oisd_big/,
    )
  })

  it('builds a canonical payload from multiple parsed sources', () => {
    const oisdContent = 'tracker.example.com\n'

    const bundle = buildRulesetBundle(
      [
        {
          source: 'oisd_small',
          content: oisdContent,
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
        {
          source: 'ddg_tracker_blocklists',
          content: DDG_FIXTURE,
          fetchedAt: '2026-05-23T00:01:00Z',
          parserVersion: '1.0.0',
        },
      ],
      {
        version: 'ruleset-v2',
        issuedAt: 1_716_422_400,
        generatedAt: '2026-05-23T00:02:00Z',
      },
    )

    assert.deepEqual(bundle.payload, {
      version: 'ruleset-v2',
      issuedAt: 1_716_422_400,
      generatedAt: '2026-05-23T00:02:00Z',
      rules: [
        {
          id: 'exact:tracker.example.com',
          domain: 'tracker.example.com',
          matchScope: 'exact',
          registrableDomain: null,
          sources: ['ddg_tracker_blocklists', 'oisd_small'],
          sourceCount: 2,
          categories: ['tracking'],
          entityNames: ['Example Tracker', 'Example Tracker Inc.'],
          confidenceTier: 'high',
          confidenceScore: 0.95,
          lightAction: 'block',
          extremeAction: 'block',
          compatibilityTags: [],
          reviewNotes: ['ddg_default:block'],
          firstSeenAt: '',
          lastSeenAt: '',
        },
      ],
      sourceManifest: [
        {
          source: 'oisd_small',
          url: 'https://small.oisd.nl',
          fetchedAt: '2026-05-23T00:00:00Z',
          contentHash: sha256(oisdContent),
          parserVersion: '1.0.0',
        },
        {
          source: 'ddg_tracker_blocklists',
          url: 'https://github.com/duckduckgo/tracker-blocklists',
          fetchedAt: '2026-05-23T00:01:00Z',
          contentHash: sha256(DDG_FIXTURE),
          parserVersion: '1.0.0',
        },
      ],
      systemAllowlist: [],
      compatibilityOverrides: [],
      rollback: {
        previousVersion: null,
        rollbackOf: null,
      },
    })
    assert.deepEqual(bundle.sourceExceptions, {})
    assert.deepEqual(bundle.sourceSummaries, [
      {
        source: 'oisd_small',
        ruleCount: 1,
        exceptionCount: 0,
        parsedVersion: null,
        parsedReadme: null,
      },
      {
        source: 'ddg_tracker_blocklists',
        ruleCount: 1,
        exceptionCount: 0,
        parsedVersion: '1688648647512',
        parsedReadme: 'https://github.com/duckduckgo/tracker-blocklists',
      },
    ])
  })

  it('builds a canonical payload from the default primary source map', () => {
    const oisdContent = 'tracker.example.com\n'
    const blocklistProjectContent = 'tracker.example.com\n'

    const bundle = buildRulesetBundleFromSourceMap(
      {
        oisd_small: {
          content: oisdContent,
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
        oisd_big: {
          content: oisdContent,
          fetchedAt: '2026-05-23T00:01:00Z',
          parserVersion: '1.0.0',
        },
        ddg_tracker_blocklists: {
          content: DDG_FIXTURE,
          fetchedAt: '2026-05-23T00:02:00Z',
          parserVersion: '1.0.0',
        },
        blocklistproject_tracking: {
          content: blocklistProjectContent,
          fetchedAt: '2026-05-23T00:03:00Z',
          parserVersion: '1.0.0',
        },
      },
      {
        version: 'ruleset-v2-primary',
        issuedAt: 1_716_422_700,
        generatedAt: '2026-05-23T00:04:00Z',
      },
    )

    assert.deepEqual(bundle.payload.sourceManifest.map((entry) => entry.source), [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
    ])
    assert.deepEqual(bundle.sourceSummaries.map((summary) => summary.source), [
      'oisd_small',
      'oisd_big',
      'ddg_tracker_blocklists',
      'blocklistproject_tracking',
    ])
    assert.deepEqual(bundle.payload.rules[0]?.sources, [
      'blocklistproject_tracking',
      'ddg_tracker_blocklists',
      'oisd_big',
      'oisd_small',
    ])
  })

  it('diffs canonical rules against the legacy single-source list', () => {
    const diff = diffRulesetAgainstLegacyDomains(
      [
        { domain: 'tracker.example.com', matchScope: 'exact' },
        { domain: 'broad.example.com', matchScope: 'suffix' },
        { domain: 'both.example.com', matchScope: 'exact' },
        { domain: 'both.example.com', matchScope: 'suffix' },
        { domain: 'new.example.com', matchScope: 'suffix' },
      ],
      [
        'TRACKER.EXAMPLE.COM',
        'broad.example.com',
        'both.example.com',
        'legacy-only.example.com',
        'tracker.example.com.',
        'not a domain',
      ],
    )

    assert.deepEqual(diff.onlyInLegacy, ['legacy-only.example.com'])
    assert.deepEqual(diff.onlyInRuleset, [
      {
        domain: 'new.example.com',
        matchScopes: ['suffix'],
      },
    ])
    assert.deepEqual(diff.exactScopeNarrowedFromLegacy, ['tracker.example.com'])
    assert.deepEqual(diff.invalidLegacyDomains, ['not a domain'])
    assert.deepEqual(diff.summary, {
      legacyDomainCount: 4,
      invalidLegacyDomainCount: 1,
      rulesetDomainCount: 4,
      sharedDomainCount: 3,
      onlyInLegacyCount: 1,
      onlyInRulesetCount: 1,
      exactScopeNarrowedCount: 1,
    })
  })

  it('can diff a built ruleset bundle against legacy domains', () => {
    const bundle = buildRulesetBundle(
      [
        {
          source: 'oisd_small',
          content: 'tracker.example.com\n',
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
      ],
      {
        version: 'ruleset-v2',
        issuedAt: 1_716_422_400,
        generatedAt: '2026-05-23T00:02:00Z',
      },
    )

    const diff = diffRulesetAgainstLegacyDomains(bundle.payload.rules, [
      'tracker.example.com',
      'legacy-only.example.com',
    ])

    assert.deepEqual(diff.onlyInLegacy, ['legacy-only.example.com'])
    assert.deepEqual(diff.onlyInRuleset, [])
    assert.deepEqual(diff.exactScopeNarrowedFromLegacy, ['tracker.example.com'])
    assert.deepEqual(diff.summary, {
      legacyDomainCount: 2,
      invalidLegacyDomainCount: 0,
      rulesetDomainCount: 1,
      sharedDomainCount: 1,
      onlyInLegacyCount: 1,
      onlyInRulesetCount: 0,
      exactScopeNarrowedCount: 1,
    })
  })

  it('preserves source exceptions and passthrough overrides', () => {
    const bundle = buildRulesetBundle(
      [
        {
          source: 'blocklistproject_tracking',
          content: ['0.0.0.0 tracker.example.com', '@@auth.example.com'].join('\n'),
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '2.0.0',
        },
      ],
      {
        version: 'ruleset-v3',
        issuedAt: 1_716_422_500,
        generatedAt: '2026-05-23T00:03:00Z',
        systemAllowlist: [
          {
            domain: 'auth.example.com',
            matchScope: 'exact',
            reason: 'core auth',
            tags: ['auth'],
          },
        ],
        compatibilityOverrides: [
          {
            domain: 'tracker.example.com',
            matchScope: 'suffix',
            reason: 'media delivery',
            tags: ['media_delivery'],
          },
        ],
        rollback: {
          previousVersion: 'ruleset-v2',
        },
      },
    )

    assert.deepEqual(bundle.sourceExceptions, {
      blocklistproject_tracking: [{ domain: 'auth.example.com', matchScope: 'exact' }],
    })
    assert.deepEqual(bundle.payload.systemAllowlist, [
      {
        domain: 'auth.example.com',
        matchScope: 'exact',
        reason: 'core auth',
        tags: ['auth'],
      },
    ])
    assert.deepEqual(bundle.payload.compatibilityOverrides, [
      {
        domain: 'tracker.example.com',
        matchScope: 'suffix',
        reason: 'media delivery',
        tags: ['media_delivery'],
      },
    ])
    assert.deepEqual(bundle.payload.rules[0]?.compatibilityTags, ['media_delivery'])
    assert.equal(bundle.payload.rules[0]?.lightAction, 'observe')
    assert.deepEqual(bundle.payload.rollback, {
      previousVersion: 'ruleset-v2',
      rollbackOf: null,
    })
  })

  it('builds and signs a ruleset bundle in one step', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const bundle = buildSignedRulesetBundle(
      [
        {
          source: 'oisd_small',
          content: 'tracker.example.com\n',
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
      ],
      {
        version: 'ruleset-v4',
        issuedAt: 1_716_422_600,
        generatedAt: '2026-05-23T00:04:00Z',
        privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      },
    )

    assert.equal(bundle.signedRuleset.version, bundle.payload.version)
    assert.equal(bundle.signedRuleset.signature.length > 0, true)
    assert.equal(
      verifyRuleset(
        bundle.signedRuleset,
        publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        86_400,
        bundle.signedRuleset.issuedAt + 10,
      ),
      true,
    )
  })

  it('builds and signs a ruleset bundle from an explicit source selection', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const bundle = buildSignedRulesetBundleFromSourceMap(
      {
        oisd_small: {
          content: 'tracker.example.com\n',
          fetchedAt: '2026-05-23T00:00:00Z',
          parserVersion: '1.0.0',
        },
        '1hosts': {
          content: 'tracker.example.com\n',
          fetchedAt: '2026-05-23T00:01:00Z',
          parserVersion: '1.0.0',
        },
      },
      {
        sources: ['oisd_small', '1hosts'],
        version: 'ruleset-v5',
        issuedAt: 1_716_422_800,
        generatedAt: '2026-05-23T00:05:00Z',
        privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      },
    )

    assert.deepEqual(bundle.payload.sourceManifest.map((entry) => entry.source), ['oisd_small', '1hosts'])
    assert.equal(
      verifyRuleset(
        bundle.signedRuleset,
        publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        86_400,
        bundle.signedRuleset.issuedAt + 10,
      ),
      true,
    )
  })
})

function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}