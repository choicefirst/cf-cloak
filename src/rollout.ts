import {
  buildRulesetBundleFromSourceMap,
  selectUpstreamSourceIds,
  type BuiltRulesetBundle,
  type UpstreamSourceSnapshotInput,
} from './builder.js'
import { DEFAULT_POLICY, type Policy } from './policy.js'
import {
  buildReplayDiffReport,
  type ReplayDiffReport,
  type ReplayTraceSessionInput,
} from './replay.js'
import {
  buildRuleset,
  type CanonicalRule,
  type ConfidenceTier,
  type MatchScope,
  type ModeAction,
  type SourceId,
} from './ruleset.js'
import type { RulesetExceptionEntry, RulesetRollbackInfo } from './signing.js'
import { getUpstreamSourceDefinition, type UpstreamSourceDefinition } from './sources/catalog.js'

export interface ReviewGatedRolloutRuleSnapshot {
  id: string
  domain: string
  matchScope: MatchScope
  sources: SourceId[]
  sourceCount: number
  confidenceTier: ConfidenceTier
  confidenceScore: number
  lightAction: ModeAction
}

export interface ReviewGatedRolloutRuleChange {
  id: string
  domain: string
  matchScope: MatchScope
  before: ReviewGatedRolloutRuleSnapshot
  after: ReviewGatedRolloutRuleSnapshot
  addedSources: SourceId[]
  removedSources: SourceId[]
}

export interface ReviewGatedRolloutRulesetDiffSummary {
  addedRuleCount: number
  removedRuleCount: number
  changedRuleCount: number
}

export interface ReviewGatedRolloutRulesetDiff {
  addedRules: ReviewGatedRolloutRuleSnapshot[]
  removedRules: ReviewGatedRolloutRuleSnapshot[]
  changedRules: ReviewGatedRolloutRuleChange[]
  summary: ReviewGatedRolloutRulesetDiffSummary
}

export interface ReviewGatedSourceRollbackPlan {
  restoreSources: SourceId[]
  removeSources: SourceId[]
  restoreConfigurationVersion: string
  rollbackInfo: RulesetRollbackInfo
}

export interface ReviewGatedSourceRolloutReport {
  source: SourceId
  sourceDefinition: UpstreamSourceDefinition
  baselineSources: SourceId[]
  candidateSources: SourceId[]
  baselineBundle: BuiltRulesetBundle
  candidateBundle: BuiltRulesetBundle
  rulesetDiff: ReviewGatedRolloutRulesetDiff
  replayDiff: ReplayDiffReport
  rollbackPlan: ReviewGatedSourceRollbackPlan
  warnings: string[]
}

export interface BuildReviewGatedSourceRolloutReportOptions {
  source: SourceId
  snapshotsBySource: Partial<Record<SourceId, UpstreamSourceSnapshotInput>>
  replaySessions: readonly ReplayTraceSessionInput[]
  baselineSources?: readonly SourceId[]
  baselineVersion: string
  candidateVersion: string
  issuedAt: number
  generatedAt: string
  replayNow?: number
  lightPolicy?: Policy
  extremePolicy?: Policy
  systemAllowlist?: RulesetExceptionEntry[]
  compatibilityOverrides?: RulesetExceptionEntry[]
}

export function buildReviewGatedSourceRolloutReport(
  options: BuildReviewGatedSourceRolloutReportOptions,
): ReviewGatedSourceRolloutReport {
  const sourceDefinition = getUpstreamSourceDefinition(options.source)
  if (!sourceDefinition.reviewGate || sourceDefinition.trustTier !== 'C') {
    throw new Error(`Source ${options.source} is not a review-gated Tier C upstream.`)
  }

  const baselineSources = selectUpstreamSourceIds({ sources: options.baselineSources })
  if (baselineSources.includes(options.source)) {
    throw new Error(`Source ${options.source} is already enabled in the baseline source set.`)
  }

  const candidateSources = selectUpstreamSourceIds({
    sources: [...baselineSources, options.source],
  })

  const sharedBundleOptions = {
    issuedAt: options.issuedAt,
    generatedAt: options.generatedAt,
    systemAllowlist: options.systemAllowlist,
    compatibilityOverrides: options.compatibilityOverrides,
  }

  const baselineBundle = buildRulesetBundleFromSourceMap(options.snapshotsBySource, {
    ...sharedBundleOptions,
    version: options.baselineVersion,
    sources: baselineSources,
  })

  const candidateBundle = buildRulesetBundleFromSourceMap(options.snapshotsBySource, {
    ...sharedBundleOptions,
    version: options.candidateVersion,
    sources: candidateSources,
    rollback: {
      previousVersion: baselineBundle.payload.version,
    },
  })

  const baselineRuleset = buildRuleset(baselineBundle.payload.rules, {
    version: baselineBundle.payload.version,
    generatedAt: baselineBundle.payload.generatedAt,
  })
  const candidateRuleset = buildRuleset(candidateBundle.payload.rules, {
    version: candidateBundle.payload.version,
    generatedAt: candidateBundle.payload.generatedAt,
  })

  const lightPolicy = options.lightPolicy ?? DEFAULT_POLICY
  const extremePolicy = options.extremePolicy ?? { ...lightPolicy, mode: 'extreme' as const }
  const rulesetDiff = diffCanonicalRulesets(
    baselineBundle.payload.rules,
    candidateBundle.payload.rules,
  )
  const replayDiff = buildReplayDiffReport(
    options.replaySessions,
    baselineRuleset,
    candidateRuleset,
    lightPolicy,
    extremePolicy,
    options.replayNow,
  )

  return {
    source: options.source,
    sourceDefinition,
    baselineSources,
    candidateSources,
    baselineBundle,
    candidateBundle,
    rulesetDiff,
    replayDiff,
    rollbackPlan: {
      restoreSources: baselineSources,
      removeSources: [options.source],
      restoreConfigurationVersion: baselineBundle.payload.version,
      rollbackInfo: {
        previousVersion: candidateBundle.payload.version,
        rollbackOf: candidateBundle.payload.version,
      },
    },
    warnings: buildRolloutWarnings(options.source, rulesetDiff, replayDiff),
  }
}

function buildRolloutWarnings(
  source: SourceId,
  rulesetDiff: ReviewGatedRolloutRulesetDiff,
  replayDiff: ReplayDiffReport,
): string[] {
  const warnings: string[] = []
  const hasRulesetChanges =
    rulesetDiff.summary.addedRuleCount > 0 ||
    rulesetDiff.summary.removedRuleCount > 0 ||
    rulesetDiff.summary.changedRuleCount > 0
  const hasReplayDelta =
    replayDiff.light.matchedCountDelta !== 0 ||
    replayDiff.light.observedCountDelta !== 0 ||
    replayDiff.light.blockedCountDelta !== 0 ||
    replayDiff.extreme.matchedCountDelta !== 0 ||
    replayDiff.extreme.observedCountDelta !== 0 ||
    replayDiff.extreme.blockedCountDelta !== 0

  if (hasRulesetChanges && !hasReplayDelta) {
    warnings.push(
      `Candidate source ${source} changes the ruleset, but the configured replay sessions produced no matched or blocked delta. Review the domain-level diff before enabling it.`,
    )
  }

  return warnings
}

function diffCanonicalRulesets(
  baselineRules: readonly CanonicalRule[],
  candidateRules: readonly CanonicalRule[],
): ReviewGatedRolloutRulesetDiff {
  const baselineById = new Map(baselineRules.map((rule) => [rule.id, rule]))
  const candidateById = new Map(candidateRules.map((rule) => [rule.id, rule]))

  const addedRules = [...candidateById.entries()]
    .filter(([id]) => !baselineById.has(id))
    .map(([, rule]) => toRuleSnapshot(rule))
    .sort(compareRuleSnapshots)

  const removedRules = [...baselineById.entries()]
    .filter(([id]) => !candidateById.has(id))
    .map(([, rule]) => toRuleSnapshot(rule))
    .sort(compareRuleSnapshots)

  const changedRules = [...candidateById.entries()]
    .flatMap(([id, candidateRule]) => {
      const baselineRule = baselineById.get(id)
      if (!baselineRule) return []

      const before = toRuleSnapshot(baselineRule)
      const after = toRuleSnapshot(candidateRule)
      const addedSources = difference(after.sources, before.sources)
      const removedSources = difference(before.sources, after.sources)

      const changed =
        addedSources.length > 0 ||
        removedSources.length > 0 ||
        before.sourceCount !== after.sourceCount ||
        before.confidenceTier !== after.confidenceTier ||
        before.confidenceScore !== after.confidenceScore ||
        before.lightAction !== after.lightAction

      if (!changed) return []

      return [
        {
          id: after.id,
          domain: after.domain,
          matchScope: after.matchScope,
          before,
          after,
          addedSources,
          removedSources,
        },
      ]
    })
    .sort((left, right) => left.id.localeCompare(right.id))

  return {
    addedRules,
    removedRules,
    changedRules,
    summary: {
      addedRuleCount: addedRules.length,
      removedRuleCount: removedRules.length,
      changedRuleCount: changedRules.length,
    },
  }
}

function toRuleSnapshot(rule: CanonicalRule): ReviewGatedRolloutRuleSnapshot {
  return {
    id: rule.id,
    domain: rule.domain,
    matchScope: rule.matchScope,
    sources: [...rule.sources],
    sourceCount: rule.sourceCount,
    confidenceTier: rule.confidenceTier,
    confidenceScore: rule.confidenceScore,
    lightAction: rule.lightAction,
  }
}

function difference(left: readonly SourceId[], right: readonly SourceId[]): SourceId[] {
  const rightSet = new Set(right)

  return [...new Set(left)]
    .filter((value) => !rightSet.has(value))
    .sort((first, second) => first.localeCompare(second))
}

function compareRuleSnapshots(
  left: ReviewGatedRolloutRuleSnapshot,
  right: ReviewGatedRolloutRuleSnapshot,
): number {
  return left.id.localeCompare(right.id)
}