import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import type { DdgEntityMetadata } from './ddg.js'
import { parseUpstreamSourceData, UPSTREAM_SOURCES } from './catalog.js'
import { buildRuleset } from '../ruleset.js'
import type { CanonicalRule, NormalizedRuleDomain, SourceId } from '../ruleset.js'

interface SourceParserSnapshot {
  version: string | null
  readme: string | null
  exceptions: NormalizedRuleDomain[]
  packageOwners: Record<string, string>
  entities: Record<string, DdgEntityMetadata>
  canonicalRules: CanonicalRule[]
}

const FIXTURE_FILE_BY_SOURCE: Record<SourceId, string> = {
  oisd_small: 'oisd_small.txt',
  oisd_big: 'oisd_big.txt',
  ddg_tracker_blocklists: 'ddg_tracker_blocklists.json',
  blocklistproject_tracking: 'blocklistproject_tracking.txt',
  '1hosts': '1hosts.txt',
  adguard_dns_filter: 'adguard_dns_filter.txt',
  hagezi: 'hagezi.txt',
  easylist: 'easylist.txt',
  steven_black: 'steven_black.txt',
}

const FIXTURE_DIR = resolveFixtureDirectory()
const SNAPSHOTS = JSON.parse(
  readFileSync(join(FIXTURE_DIR, 'parserSnapshots.json'), 'utf8'),
) as Record<SourceId, SourceParserSnapshot>

describe('source parser snapshots', () => {
  for (const source of Object.keys(UPSTREAM_SOURCES) as SourceId[]) {
    it(`matches the sanitized ${source} snapshot`, () => {
      const parsed = parseUpstreamSourceData(source, readFixture(source))
      const ruleset = buildRuleset(parsed.rules, {
        version: `snapshot-${source}`,
        generatedAt: '2026-05-23T00:00:00Z',
      })

      assert.deepEqual(
        {
          version: parsed.version,
          readme: parsed.readme,
          exceptions: parsed.exceptions,
          packageOwners: parsed.packageOwners,
          entities: parsed.entities,
          canonicalRules: ruleset.rules,
        },
        SNAPSHOTS[source],
      )
    })
  }
})

function readFixture(source: SourceId): string {
  return readFileSync(join(FIXTURE_DIR, FIXTURE_FILE_BY_SOURCE[source]), 'utf8')
}

function resolveFixtureDirectory(): string {
  const compiledFixtureDir = resolve(__dirname, '../../src/sources/fixtures')
  if (existsSync(compiledFixtureDir)) {
    return compiledFixtureDir
  }

  return resolve(__dirname, './fixtures')
}