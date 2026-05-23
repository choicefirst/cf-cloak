import type { CanonicalRuleInput, NormalizedRuleDomain, SourceId } from '../ruleset.js'
import { parseSourceText } from '../sources.js'
import type { DdgEntityMetadata } from './ddg.js'
import { parseDdgTrackerData } from './ddg.js'

export type UpstreamSourceFormat = 'domain_text' | 'ddg_json'
export type UpstreamSourceTrustTier = 'A' | 'B' | 'C'
export type UpstreamLightUse =
  | 'high_confidence_candidate'
  | 'corroboration_only'
  | 'metadata_only'
  | 'review_only'

export interface UpstreamSourceDefinition {
  id: SourceId
  name: string
  url: string
  format: UpstreamSourceFormat
  trustTier: UpstreamSourceTrustTier
  reviewGate: boolean
  lightUse: UpstreamLightUse
  extremeDefaultEnabled: boolean
}

export interface ParsedUpstreamSourceData {
  source: SourceId
  rules: CanonicalRuleInput[]
  exceptions: NormalizedRuleDomain[]
  version: string | null
  readme: string | null
  entities: Record<string, DdgEntityMetadata>
  packageOwners: Record<string, string>
}

export const UPSTREAM_SOURCES: Record<SourceId, UpstreamSourceDefinition> = {
  oisd_small: {
    id: 'oisd_small',
    name: 'OISD Small',
    url: 'https://small.oisd.nl',
    format: 'domain_text',
    trustTier: 'A',
    reviewGate: false,
    lightUse: 'high_confidence_candidate',
    extremeDefaultEnabled: true,
  },
  oisd_big: {
    id: 'oisd_big',
    name: 'OISD Big',
    url: 'https://big.oisd.nl',
    format: 'domain_text',
    trustTier: 'A',
    reviewGate: false,
    lightUse: 'corroboration_only',
    extremeDefaultEnabled: true,
  },
  ddg_tracker_blocklists: {
    id: 'ddg_tracker_blocklists',
    name: 'DuckDuckGo tracker blocklists',
    url: 'https://github.com/duckduckgo/tracker-blocklists',
    format: 'ddg_json',
    trustTier: 'B',
    reviewGate: false,
    lightUse: 'metadata_only',
    extremeDefaultEnabled: false,
  },
  blocklistproject_tracking: {
    id: 'blocklistproject_tracking',
    name: 'Blocklist Project Tracking',
    url: 'https://blocklistproject.github.io/Lists/tracking.txt',
    format: 'domain_text',
    trustTier: 'B',
    reviewGate: false,
    lightUse: 'corroboration_only',
    extremeDefaultEnabled: true,
  },
  '1hosts': {
    id: '1hosts',
    name: '1Hosts',
    url: 'https://github.com/badmojr/1Hosts',
    format: 'domain_text',
    trustTier: 'C',
    reviewGate: true,
    lightUse: 'review_only',
    extremeDefaultEnabled: false,
  },
  adguard_dns_filter: {
    id: 'adguard_dns_filter',
    name: 'AdGuard DNS Filter',
    url: 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt',
    format: 'domain_text',
    trustTier: 'C',
    reviewGate: true,
    lightUse: 'review_only',
    extremeDefaultEnabled: false,
  },
  hagezi: {
    id: 'hagezi',
    name: 'HaGeZi',
    url: 'https://github.com/hagezi/dns-blocklists',
    format: 'domain_text',
    trustTier: 'C',
    reviewGate: true,
    lightUse: 'review_only',
    extremeDefaultEnabled: false,
  },
  easylist: {
    id: 'easylist',
    name: 'EasyList',
    url: 'https://easylist.to/easylist/easylist.txt',
    format: 'domain_text',
    trustTier: 'C',
    reviewGate: true,
    lightUse: 'review_only',
    extremeDefaultEnabled: false,
  },
  steven_black: {
    id: 'steven_black',
    name: 'Steven Black hosts',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    format: 'domain_text',
    trustTier: 'C',
    reviewGate: true,
    lightUse: 'review_only',
    extremeDefaultEnabled: false,
  },
}

export const PRIMARY_UPSTREAM_SOURCE_IDS: SourceId[] = [
  'oisd_small',
  'oisd_big',
  'ddg_tracker_blocklists',
  'blocklistproject_tracking',
]

export const REVIEW_GATED_UPSTREAM_SOURCE_IDS: SourceId[] = [
  '1hosts',
  'adguard_dns_filter',
  'hagezi',
  'easylist',
  'steven_black',
]

export function getUpstreamSourceDefinition(source: SourceId): UpstreamSourceDefinition {
  return UPSTREAM_SOURCES[source]
}

export function parseUpstreamSourceData(
  source: SourceId,
  content: string,
): ParsedUpstreamSourceData {
  const definition = getUpstreamSourceDefinition(source)

  if (definition.format === 'ddg_json') {
    const parsed = parseDdgTrackerData(content)
    return {
      source,
      rules: parsed.rules,
      exceptions: [],
      version: parsed.version,
      readme: parsed.readme,
      entities: parsed.entities,
      packageOwners: parsed.packageOwners,
    }
  }

  const parsed = parseSourceText(content, { source })
  return {
    source,
    rules: parsed.rules,
    exceptions: parsed.exceptions,
    version: null,
    readme: null,
    entities: {},
    packageOwners: {},
  }
}