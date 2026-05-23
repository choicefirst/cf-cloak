/**
 * cf-cloak — ChoiceFirst open-source blocking engine (TypeScript mirror)
 *
 * This module exposes the same domain-matching logic as the Kotlin
 * DnsPacket object so the React/web layer can apply identical blocking
 * decisions (e.g. preview rule coverage, classify domains in the UI)
 * without duplicating logic.
 *
 * Licensed under AGPLv3. Commercial use requires a separate license.
 * See README.md for details.
 */

import type { ConfidenceTier, MatchScope, ModeAction } from './ruleset.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A blocklist rule with optional metadata.
 * The string shorthand (domain only) is accepted anywhere a RuleEntry is.
 */
export interface RuleEntry {
  domain: string
  registrableDomain?: string | null
  category?: string
  categories?: readonly string[]
  source?: string
  sources?: readonly string[]
  entityNames?: readonly string[]
  confidenceTier?: ConfidenceTier
  compatibilityTags?: readonly string[]
  lightAction?: ModeAction
  extremeAction?: ModeAction
}

export interface DetailedRuleMetadata {
  registrableDomain: string | null
  category: string | null
  categories: string[]
  source: string | null
  sources: string[]
  entityNames: string[]
  confidenceTier: ConfidenceTier | null
  compatibilityTags: string[]
  lightAction: ModeAction | null
  extremeAction: ModeAction | null
}

/**
 * Rich match result returned by [matchDomainDetailed].
 * Mirrors the Kotlin `MatchResult` data class in DnsPacket.kt.
 */
export interface MatchResult extends DetailedRuleMetadata {
  /** The blocklist suffix that matched (e.g. "doubleclick.net"). */
  suffix: string
  /** Whether the match was exact or suffix-derived. */
  matchScope: MatchScope
}

/**
 * Suffix-match a domain name against a blocklist set.
 *
 * Mirrors DnsPacket.matchedBlock() in the Android library exactly:
 * - Exact match first
 * - Then walks up the label hierarchy (foo.bar.com → bar.com → com)
 *
 * @param name      Fully-qualified domain name, already lowercased.
 * @param blocklist Set of blocked domains/suffixes (lowercase).
 * @returns         The matched blocklist entry, or `null` if no match.
 *
 * @example
 * matchDomain('tracker.doubleclick.net', new Set(['doubleclick.net'])) // → 'doubleclick.net'
 * matchDomain('example.com', new Set(['evil.com']))                    // → null
 */
export function matchDomain(name: string, blocklist: ReadonlySet<string>): string | null {
  if (blocklist.has(name)) return name
  let idx = name.indexOf('.')
  while (idx >= 0 && idx < name.length - 1) {
    const suffix = name.slice(idx + 1)
    if (blocklist.has(suffix)) return suffix
    idx = name.indexOf('.', idx + 1)
  }
  return null
}

/**
 * Given a list of raw domain strings from the blocklist source,
 * normalise and deduplicate them into a Set ready for matchDomain().
 */
export function buildBlocklist(domains: readonly string[]): Set<string> {
  const out = new Set<string>()
  for (const d of domains) {
    const norm = d.trim().toLowerCase()
    if (norm.length > 0) out.add(norm)
  }
  return out
}

/**
 * Build a blocklist Set and a metadata Map from a mixed array of plain
 * domain strings or rich [RuleEntry] objects.
 *
 * Back-compatible: plain strings produce entries with null category/source.
 *
 * @example
 * const { set, meta } = buildBlocklistDetailed([
 *   { domain: 'doubleclick.net', category: 'ads', source: 'easylist' },
 *   'tracker.com',
 * ])
 */
export function buildBlocklistDetailed(
  rules: readonly (RuleEntry | string)[],
): { set: Set<string>; meta: Map<string, DetailedRuleMetadata> } {
  const set = new Set<string>()
  const meta = new Map<string, DetailedRuleMetadata>()
  for (const rule of rules) {
    if (typeof rule === 'string') {
      const norm = rule.trim().toLowerCase()
      if (norm.length > 0) set.add(norm)
    } else {
      const norm = rule.domain.trim().toLowerCase()
      if (norm.length > 0) {
        set.add(norm)
        meta.set(norm, buildDetailedRuleMetadata(rule))
      }
    }
  }
  return { set, meta }
}

/**
 * Rich-result variant of [matchDomain].
 *
 * Mirrors `DnsPacket.matchedBlockDetailed()` in the Kotlin layer exactly.
 *
 * @param meta  Optional metadata map produced by [buildBlocklistDetailed].
 *              Pass an empty Map for plain blocklists (back-compat).
 */
export function matchDomainDetailed(
  name: string,
  blocklist: ReadonlySet<string>,
  meta: ReadonlyMap<string, DetailedRuleMetadata> = new Map(),
): MatchResult | null {
  const suffix = matchDomain(name, blocklist)
  if (suffix === null) return null
  const m = meta.get(suffix)
  return {
    suffix,
    matchScope: name === suffix ? 'exact' : 'suffix',
    registrableDomain: m?.registrableDomain ?? null,
    category: m?.category ?? null,
    categories: m?.categories ?? [],
    source: m?.source ?? null,
    sources: m?.sources ?? [],
    entityNames: m?.entityNames ?? [],
    confidenceTier: m?.confidenceTier ?? null,
    compatibilityTags: m?.compatibilityTags ?? [],
    lightAction: m?.lightAction ?? null,
    extremeAction: m?.extremeAction ?? null,
  }
}

function buildDetailedRuleMetadata(rule: RuleEntry): DetailedRuleMetadata {
  const categories = normalizeLowercaseList(rule.categories, rule.category)
  const sources = normalizeLowercaseList(rule.sources, rule.source)

  return {
    registrableDomain: normalizeOptionalLowercase(rule.registrableDomain),
    category: categories[0] ?? null,
    categories,
    source: sources[0] ?? null,
    sources,
    entityNames: normalizePreservedList(rule.entityNames),
    confidenceTier: rule.confidenceTier ?? null,
    compatibilityTags: normalizeLowercaseList(rule.compatibilityTags),
    lightAction: rule.lightAction ?? null,
    extremeAction: rule.extremeAction ?? null,
  }
}

function normalizeOptionalLowercase(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const normalized = value.trim().toLowerCase()
  return normalized.length > 0 ? normalized : null
}

function normalizeLowercaseList(
  values: readonly string[] | undefined,
  fallback?: string | null,
): string[] {
  const normalizedValues = new Set<string>()

  for (const value of values ?? []) {
    const normalized = value.trim().toLowerCase()
    if (normalized.length > 0) normalizedValues.add(normalized)
  }

  if (typeof fallback === 'string') {
    const normalized = fallback.trim().toLowerCase()
    if (normalized.length > 0) normalizedValues.add(normalized)
  }

  return [...normalizedValues]
}

function normalizePreservedList(values: readonly string[] | undefined): string[] {
  const normalizedValues = new Set<string>()

  for (const value of values ?? []) {
    const normalized = value.trim()
    if (normalized.length > 0) normalizedValues.add(normalized)
  }

  return [...normalizedValues]
}

/**
 * Check whether any domain in a given array would be blocked.
 * Useful for rule preview in the UI.
 */
export function anyBlocked(domains: readonly string[], blocklist: ReadonlySet<string>): boolean {
  return domains.some((d) => matchDomain(d.trim().toLowerCase(), blocklist) !== null)
}

export { sniHostname } from './sni.js'

// ── Canonical rulesets ───────────────────────────────────────────────────────
export type {
  BuildRulesetOptions,
  CanonicalRule,
  CanonicalRuleInput,
  ConfidenceTier,
  DerivedRuleSemantics,
  DeriveRuleSemanticsOptions,
  MatchScope,
  ModeAction,
  NormalizeHostnameOptions,
  NormalizedRuleDomain,
  Ruleset,
  SourceId,
} from './ruleset.js'
export {
  buildRuleset,
  deriveRuleSemantics,
  lookupRule,
  normalizeHostname,
  normalizeRuleDomain,
} from './ruleset.js'

// ── Source parsing ───────────────────────────────────────────────────────────
export type { ParseSourceTextOptions, ParsedSourceTextResult } from './sources.js'
export { parseSourceText } from './sources.js'
export type {
  DdgEntityEntry,
  DdgEntityMetadata,
  DdgTrackerDataset,
  DdgTrackerEntry,
  DdgTrackerOwner,
  ParsedDdgTrackerDataResult,
} from './sources/ddg.js'
export {
  isLikelyDdgTrackerDataset,
  normalizeDdgTrackerDomain,
  parseDdgTrackerData,
} from './sources/ddg.js'
export type {
  ParsedUpstreamSourceData,
  UpstreamLightUse,
  UpstreamSourceDefinition,
  UpstreamSourceFormat,
  UpstreamSourceTrustTier,
} from './sources/catalog.js'
export {
  getUpstreamSourceDefinition,
  parseUpstreamSourceData,
  PRIMARY_UPSTREAM_SOURCE_IDS,
  REVIEW_GATED_UPSTREAM_SOURCE_IDS,
  UPSTREAM_SOURCES,
} from './sources/catalog.js'
export type {
  BuildRulesetBundleFromSourceMapOptions,
  BuildSignedRulesetBundleOptions,
  BuildSignedRulesetBundleFromSourceMapOptions,
  BuildRulesetBundleOptions,
  LegacyRulesetDiff,
  LegacyRulesetDiffEntry,
  LegacyRulesetDiffSummary,
  BuiltSignedRulesetBundle,
  BuiltRulesetBundle,
  BuiltRulesetSourceSummary,
  UpstreamSourceSelectionOptions,
  UpstreamSourceSnapshot,
  UpstreamSourceSnapshotInput,
} from './builder.js'
export {
  buildRulesetBundle,
  buildRulesetBundleFromSourceMap,
  buildSignedRulesetBundle,
  buildSignedRulesetBundleFromSourceMap,
  buildUpstreamSourceSnapshots,
  diffRulesetAgainstLegacyDomains,
  selectUpstreamSourceIds,
} from './builder.js'
export type { NormalizedRulesetException } from './compatibility.js'
export { applyCompatibilityOverrides, lookupRulesetException } from './compatibility.js'
export type {
  BuildLocalDnsEventOptions,
  BuiltPolicyRequestFromRuleset,
  DnsOrSniRulesetRequest,
  DnsRulesetRequest,
  EvaluatedRulesetRequest,
  EvaluatedDnsOrSniRulesetRequestWithEvent,
  EvaluatedRulesetRequestWithEvent,
  LocalDnsEvent,
  LocalDnsEventAction,
  LocalDnsEventReason,
  ResolvedDnsOrSniHostname,
  RulesetHostnameSource,
  RulesetRequestOptions,
  SniRulesetRequest,
} from './runtime.js'
export {
  buildLocalDnsEvent,
  buildPolicyRequestFromRuleset,
  evaluateDnsOrSniRulesetRequestWithEvent,
  evaluateRulesetRequest,
  evaluateRulesetRequestWithEvent,
  resolveDnsOrSniHostname,
} from './runtime.js'

// ── Policy engine ─────────────────────────────────────────────────────────────
export type {
  Action,
  DecisionEffect,
  MatchedPolicyRule,
  TempAllow,
  EnforcementMode,
  Policy,
  PolicyRequest,
  Decision,
  DecisionReason,
} from './policy.js'
export { DEFAULT_POLICY, evaluate } from './policy.js'

// ── Blocklist signing / verification ──────────────────────────────────────────
export type { SignedBlocklist } from './signing.js'
export type {
  RulesetExceptionEntry,
  RulesetPayload,
  RulesetRollbackInfo,
  RulesetSourceManifestEntry,
  SignedRuleset,
} from './signing.js'
export {
  buildCanonicalRulesetJson,
  buildRulesetSignaturePayload,
  buildSignaturePayload,
  signBlocklist,
  signRuleset,
  verifyBlocklist,
  verifyRuleset,
} from './signing.js'

// ── Replay analysis ──────────────────────────────────────────────────────────
export type {
  ReplayDiffReport,
  ReplayModeDiffReport,
  ReplaySummary,
  ReplayTraceSessionInput,
} from './replay.js'
export {
  buildReplayDiffReport,
  buildReplayModeDiffReport,
  createReplaySummary,
  difference,
  mergeReplaySummary,
  replayAllSessions,
  replaySession,
} from './replay.js'

// ── Review-gated source rollout analysis ─────────────────────────────────────
export type {
  BuildReviewGatedSourceRolloutReportOptions,
  ReviewGatedRolloutRuleChange,
  ReviewGatedRolloutRuleSnapshot,
  ReviewGatedRolloutRulesetDiff,
  ReviewGatedRolloutRulesetDiffSummary,
  ReviewGatedSourceRollbackPlan,
  ReviewGatedSourceRolloutReport,
} from './rollout.js'
export { buildReviewGatedSourceRolloutReport } from './rollout.js'

// ── Snapshot input loaders ───────────────────────────────────────────────────
export type {
  LoadUpstreamSourceSnapshotInputsOptions,
  UpstreamSourceContentLoader,
} from './snapshotInputs.js'
export {
  loadUpstreamSourceSnapshotInputs,
  loadUpstreamSourceSnapshots,
} from './snapshotInputs.js'
