import { createHash } from 'node:crypto'

import type { CanonicalRule, MatchScope, NormalizedRuleDomain, SourceId } from './ruleset.js'
import { buildRuleset, normalizeHostname } from './ruleset.js'
import type {
  RulesetExceptionEntry,
  RulesetPayload,
  RulesetRollbackInfo,
  SignedRuleset,
} from './signing.js'
import { signRuleset } from './signing.js'
import { applyCompatibilityOverrides } from './compatibility.js'
import {
  PRIMARY_UPSTREAM_SOURCE_IDS,
  REVIEW_GATED_UPSTREAM_SOURCE_IDS,
  getUpstreamSourceDefinition,
  parseUpstreamSourceData,
} from './sources/catalog.js'

export interface UpstreamSourceSnapshot {
  source: SourceId
  content: string
  fetchedAt: string
  parserVersion: string
}

export type UpstreamSourceSnapshotInput = Omit<UpstreamSourceSnapshot, 'source'>

export interface UpstreamSourceSelectionOptions {
  sources?: readonly SourceId[]
  includeReviewGated?: boolean
}

export interface BuildRulesetBundleOptions {
  version: string
  issuedAt: number
  generatedAt: string
  rollback?: Partial<RulesetRollbackInfo>
  systemAllowlist?: RulesetExceptionEntry[]
  compatibilityOverrides?: RulesetExceptionEntry[]
}

export interface BuiltRulesetSourceSummary {
  source: SourceId
  ruleCount: number
  exceptionCount: number
  parsedVersion: string | null
  parsedReadme: string | null
}

export interface BuiltRulesetBundle {
  payload: RulesetPayload
  sourceExceptions: Partial<Record<SourceId, NormalizedRuleDomain[]>>
  sourceSummaries: BuiltRulesetSourceSummary[]
}

export interface BuildSignedRulesetBundleOptions extends BuildRulesetBundleOptions {
  privateKeyPem: string
}

export interface BuildRulesetBundleFromSourceMapOptions
  extends BuildRulesetBundleOptions, UpstreamSourceSelectionOptions {}

export interface BuildSignedRulesetBundleFromSourceMapOptions
  extends BuildSignedRulesetBundleOptions, UpstreamSourceSelectionOptions {}

export interface BuiltSignedRulesetBundle extends BuiltRulesetBundle {
  signedRuleset: SignedRuleset
}

export interface LegacyRulesetDiffEntry {
  domain: string
  matchScopes: MatchScope[]
}

export interface LegacyRulesetDiffSummary {
  legacyDomainCount: number
  invalidLegacyDomainCount: number
  rulesetDomainCount: number
  sharedDomainCount: number
  onlyInLegacyCount: number
  onlyInRulesetCount: number
  exactScopeNarrowedCount: number
}

export interface LegacyRulesetDiff {
  onlyInLegacy: string[]
  onlyInRuleset: LegacyRulesetDiffEntry[]
  exactScopeNarrowedFromLegacy: string[]
  invalidLegacyDomains: string[]
  summary: LegacyRulesetDiffSummary
}

export function selectUpstreamSourceIds(
  options: UpstreamSourceSelectionOptions = {},
): SourceId[] {
  const selectedSources = options.sources
    ? options.sources
    : options.includeReviewGated
      ? [...PRIMARY_UPSTREAM_SOURCE_IDS, ...REVIEW_GATED_UPSTREAM_SOURCE_IDS]
      : PRIMARY_UPSTREAM_SOURCE_IDS

  const uniqueSources: SourceId[] = []
  const seenSources = new Set<SourceId>()

  for (const source of selectedSources) {
    if (seenSources.has(source)) continue
    seenSources.add(source)
    uniqueSources.push(source)
  }

  return uniqueSources
}

export function diffRulesetAgainstLegacyDomains(
  rules: readonly Pick<CanonicalRule, 'domain' | 'matchScope'>[],
  legacyDomains: readonly string[],
): LegacyRulesetDiff {
  const legacyDomainSet = new Set<string>()
  const invalidLegacyDomainSet = new Set<string>()

  for (const legacyDomain of legacyDomains) {
    const trimmed = legacyDomain.trim().toLowerCase()
    if (trimmed.length === 0) continue

    const normalizedDomain = normalizeHostname(trimmed, { allowSingleLabel: false })
    if (normalizedDomain === null) {
      invalidLegacyDomainSet.add(trimmed)
      continue
    }

    legacyDomainSet.add(normalizedDomain)
  }

  const rulesetScopesByDomain = new Map<string, Set<MatchScope>>()
  for (const rule of rules) {
    const scopes = rulesetScopesByDomain.get(rule.domain) ?? new Set<MatchScope>()
    scopes.add(rule.matchScope)
    rulesetScopesByDomain.set(rule.domain, scopes)
  }

  const onlyInLegacy = [...legacyDomainSet]
    .filter((domain) => !rulesetScopesByDomain.has(domain))
    .sort()

  const onlyInRuleset = [...rulesetScopesByDomain.entries()]
    .filter(([domain]) => !legacyDomainSet.has(domain))
    .map(([domain, matchScopes]) => ({
      domain,
      matchScopes: sortMatchScopes(matchScopes),
    }))
    .sort(compareLegacyRulesetDiffEntry)

  const exactScopeNarrowedFromLegacy = [...legacyDomainSet]
    .filter((domain) => {
      const scopes = rulesetScopesByDomain.get(domain)
      return scopes !== undefined && scopes.has('exact') && !scopes.has('suffix')
    })
    .sort()

  const sharedDomainCount = [...legacyDomainSet].filter((domain) => rulesetScopesByDomain.has(domain)).length

  return {
    onlyInLegacy,
    onlyInRuleset,
    exactScopeNarrowedFromLegacy,
    invalidLegacyDomains: [...invalidLegacyDomainSet].sort(),
    summary: {
      legacyDomainCount: legacyDomainSet.size,
      invalidLegacyDomainCount: invalidLegacyDomainSet.size,
      rulesetDomainCount: rulesetScopesByDomain.size,
      sharedDomainCount,
      onlyInLegacyCount: onlyInLegacy.length,
      onlyInRulesetCount: onlyInRuleset.length,
      exactScopeNarrowedCount: exactScopeNarrowedFromLegacy.length,
    },
  }
}

export function buildUpstreamSourceSnapshots(
  snapshotsBySource: Partial<Record<SourceId, UpstreamSourceSnapshotInput>>,
  options: UpstreamSourceSelectionOptions = {},
): UpstreamSourceSnapshot[] {
  return selectUpstreamSourceIds(options).map((source) => {
    const snapshot = snapshotsBySource[source]
    if (!snapshot) {
      throw new Error(`Missing snapshot for upstream source: ${source}`)
    }

    return {
      source,
      ...snapshot,
    }
  })
}

export function buildRulesetBundle(
  snapshots: readonly UpstreamSourceSnapshot[],
  options: BuildRulesetBundleOptions,
): BuiltRulesetBundle {
  const allRules = []
  const sourceExceptions: Partial<Record<SourceId, NormalizedRuleDomain[]>> = {}
  const sourceSummaries: BuiltRulesetSourceSummary[] = []

  for (const snapshot of snapshots) {
    const parsed = parseUpstreamSourceData(snapshot.source, snapshot.content)
    allRules.push(...parsed.rules)

    if (parsed.exceptions.length > 0) {
      sourceExceptions[snapshot.source] = parsed.exceptions
    }

    sourceSummaries.push({
      source: snapshot.source,
      ruleCount: parsed.rules.length,
      exceptionCount: parsed.exceptions.length,
      parsedVersion: parsed.version,
      parsedReadme: parsed.readme,
    })
  }

  const ruleset = buildRuleset(allRules, {
    version: options.version,
    generatedAt: options.generatedAt,
  })
  const compatibleRuleset = applyCompatibilityOverrides(
    ruleset,
    options.compatibilityOverrides ?? [],
  )

  return {
    payload: {
      version: options.version,
      issuedAt: options.issuedAt,
      generatedAt: options.generatedAt,
      rules: compatibleRuleset.rules,
      sourceManifest: snapshots.map((snapshot) => {
        const definition = getUpstreamSourceDefinition(snapshot.source)
        return {
          source: snapshot.source,
          url: definition.url,
          fetchedAt: snapshot.fetchedAt,
          contentHash: sha256(snapshot.content),
          parserVersion: snapshot.parserVersion,
        }
      }),
      systemAllowlist: options.systemAllowlist ?? [],
      compatibilityOverrides: options.compatibilityOverrides ?? [],
      rollback: {
        previousVersion: options.rollback?.previousVersion ?? null,
        rollbackOf: options.rollback?.rollbackOf ?? null,
      },
    },
    sourceExceptions,
    sourceSummaries,
  }
}

function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

export function buildRulesetBundleFromSourceMap(
  snapshotsBySource: Partial<Record<SourceId, UpstreamSourceSnapshotInput>>,
  options: BuildRulesetBundleFromSourceMapOptions,
): BuiltRulesetBundle {
  const { sources, includeReviewGated, ...bundleOptions } = options

  return buildRulesetBundle(
    buildUpstreamSourceSnapshots(snapshotsBySource, { sources, includeReviewGated }),
    bundleOptions,
  )
}

export function buildSignedRulesetBundle(
  snapshots: readonly UpstreamSourceSnapshot[],
  options: BuildSignedRulesetBundleOptions,
): BuiltSignedRulesetBundle {
  const { privateKeyPem, ...bundleOptions } = options
  const builtBundle = buildRulesetBundle(snapshots, bundleOptions)

  return {
    ...builtBundle,
    signedRuleset: {
      ...builtBundle.payload,
      signature: signRuleset(builtBundle.payload, privateKeyPem),
    },
  }
}

export function buildSignedRulesetBundleFromSourceMap(
  snapshotsBySource: Partial<Record<SourceId, UpstreamSourceSnapshotInput>>,
  options: BuildSignedRulesetBundleFromSourceMapOptions,
): BuiltSignedRulesetBundle {
  const { sources, includeReviewGated, ...bundleOptions } = options

  return buildSignedRulesetBundle(
    buildUpstreamSourceSnapshots(snapshotsBySource, { sources, includeReviewGated }),
    bundleOptions,
  )
}

function sortMatchScopes(matchScopes: Iterable<MatchScope>): MatchScope[] {
  const scopeRank: Record<MatchScope, number> = {
    exact: 0,
    suffix: 1,
  }

  return [...new Set(matchScopes)].sort((left, right) => scopeRank[left] - scopeRank[right])
}

function compareLegacyRulesetDiffEntry(left: LegacyRulesetDiffEntry, right: LegacyRulesetDiffEntry): number {
  return left.domain.localeCompare(right.domain)
}