import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  loadUpstreamSourceSnapshotInputs,
  loadUpstreamSourceSnapshots,
} from './snapshotInputs.js'

describe('loadUpstreamSourceSnapshotInputs', () => {
  it('loads the selected source set with caller-provided metadata', async () => {
    const loadedSources: string[] = []

    const snapshotsBySource = await loadUpstreamSourceSnapshotInputs({
      sources: ['oisd_small', 'hagezi'],
      loadContent: async (source, definition) => {
        loadedSources.push(`${source}:${definition.name}`)
        return `content:${source}`
      },
      fetchedAt: '2026-05-23T00:00:00Z',
      parserVersion: (source) => `loader-${source}`,
    })

    assert.deepEqual(loadedSources, ['oisd_small:OISD Small', 'hagezi:HaGeZi'])
    assert.deepEqual(snapshotsBySource, {
      oisd_small: {
        content: 'content:oisd_small',
        fetchedAt: '2026-05-23T00:00:00Z',
        parserVersion: 'loader-oisd_small',
      },
      hagezi: {
        content: 'content:hagezi',
        fetchedAt: '2026-05-23T00:00:00Z',
        parserVersion: 'loader-hagezi',
      },
    })
  })

  it('can build ordered snapshots from includeReviewGated selection', async () => {
    const snapshots = await loadUpstreamSourceSnapshots({
      includeReviewGated: true,
      loadContent: (source) => `content:${source}`,
      fetchedAt: '2026-05-23T00:00:00Z',
      parserVersion: 'snapshot-loader-v1',
    })

    assert.deepEqual(
      snapshots.map((snapshot) => snapshot.source),
      [
        'oisd_small',
        'oisd_big',
        'ddg_tracker_blocklists',
        'blocklistproject_tracking',
        '1hosts',
        'adguard_dns_filter',
        'hagezi',
        'easylist',
        'steven_black',
      ],
    )
    assert.equal(snapshots[0]?.content, 'content:oisd_small')
    assert.equal(snapshots[8]?.parserVersion, 'snapshot-loader-v1')
  })
})