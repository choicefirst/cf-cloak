import type { CanonicalRule, MatchScope, Ruleset } from './ruleset.js'
import { deriveRuleSemantics, normalizeHostname } from './ruleset.js'
import type { RulesetExceptionEntry } from './signing.js'

export interface NormalizedRulesetException extends RulesetExceptionEntry {
  domain: string
  matchScope: MatchScope
}

export function lookupRulesetException(
  hostname: string,
  exceptions: readonly RulesetExceptionEntry[],
): NormalizedRulesetException | null {
  const normalizedHostname = normalizeHostname(hostname)
  if (normalizedHostname === null) {
    return null
  }

  let bestSuffix: NormalizedRulesetException | null = null

  for (const exception of exceptions) {
    const normalizedException = normalizeExceptionEntry(exception)
    if (normalizedException === null) {
      continue
    }

    if (normalizedException.matchScope === 'exact') {
      if (normalizedHostname === normalizedException.domain) {
        return normalizedException
      }
      continue
    }

    if (!matchesSuffix(normalizedHostname, normalizedException.domain)) {
      continue
    }

    if (bestSuffix === null || normalizedException.domain.length > bestSuffix.domain.length) {
      bestSuffix = normalizedException
    }
  }

  return bestSuffix
}

export function applyCompatibilityOverrides(
  ruleset: Ruleset,
  compatibilityOverrides: readonly RulesetExceptionEntry[],
): Ruleset {
  if (compatibilityOverrides.length === 0) {
    return ruleset
  }

  const normalizedOverrides = compatibilityOverrides
    .map(normalizeExceptionEntry)
    .filter((override): override is NormalizedRulesetException => override !== null)

  if (normalizedOverrides.length === 0) {
    return ruleset
  }

  const rules = ruleset.rules.map((rule) => applyCompatibilityOverridesToRule(rule, normalizedOverrides))

  return reindexRuleset(ruleset, rules)
}

function applyCompatibilityOverridesToRule(
  rule: CanonicalRule,
  compatibilityOverrides: readonly NormalizedRulesetException[],
): CanonicalRule {
  const matchedOverrides = compatibilityOverrides.filter((override) =>
    matchesException(rule.domain, override),
  )

  if (matchedOverrides.length === 0) {
    return rule
  }

  const compatibilityTags = uniqueSorted([
    ...rule.compatibilityTags,
    ...matchedOverrides.flatMap((override) => override.tags),
  ])
  const reviewNotes = uniqueSorted([
    ...rule.reviewNotes,
    ...matchedOverrides.map((override) => `compatibility:${override.reason}`),
  ])
  const semantics = deriveRuleSemantics({
    sources: rule.sources,
    compatibilityTags,
  })

  return {
    ...rule,
    compatibilityTags,
    lightAction: semantics.lightAction,
    reviewNotes,
  }
}

function reindexRuleset(ruleset: Ruleset, rules: readonly CanonicalRule[]): Ruleset {
  const exact = new Map<string, CanonicalRule>()
  const suffix = new Map<string, CanonicalRule>()

  for (const rule of rules) {
    if (rule.matchScope === 'exact') {
      exact.set(rule.domain, rule)
      continue
    }

    suffix.set(rule.domain, rule)
  }

  return {
    ...ruleset,
    rules: [...rules],
    exact,
    suffix,
  }
}

function normalizeExceptionEntry(
  exception: RulesetExceptionEntry,
): NormalizedRulesetException | null {
  const trimmedDomain = exception.domain.trim()
  const wildcard = trimmedDomain.startsWith('*.')
  const normalizedDomain = normalizeHostname(wildcard ? trimmedDomain.slice(2) : trimmedDomain)

  if (normalizedDomain === null) {
    return null
  }

  return {
    ...exception,
    domain: normalizedDomain,
    matchScope: wildcard ? 'suffix' : exception.matchScope,
  }
}

function matchesException(domain: string, exception: NormalizedRulesetException): boolean {
  if (exception.matchScope === 'exact') {
    return domain === exception.domain
  }

  return matchesSuffix(domain, exception.domain)
}

function matchesSuffix(domain: string, suffix: string): boolean {
  return domain === suffix || domain.endsWith(`.${suffix}`)
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort()
}