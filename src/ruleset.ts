export type SourceId =
  | 'oisd_small'
  | 'oisd_big'
  | 'ddg_tracker_blocklists'
  | 'blocklistproject_tracking'
  | '1hosts'
  | 'adguard_dns_filter'
  | 'hagezi'
  | 'easylist'
  | 'steven_black'

export type MatchScope = 'exact' | 'suffix'
export type ConfidenceTier = 'high' | 'medium' | 'review'
export type ModeAction = 'block' | 'observe'

export interface CanonicalRule {
  id: string
  domain: string
  matchScope: MatchScope
  registrableDomain: string | null
  sources: SourceId[]
  sourceCount: number
  categories: string[]
  entityNames: string[]
  confidenceTier: ConfidenceTier
  confidenceScore: number
  lightAction: ModeAction
  extremeAction: 'block'
  compatibilityTags: string[]
  reviewNotes: string[]
  firstSeenAt: string
  lastSeenAt: string
}

export interface CanonicalRuleInput {
  domain: string
  matchScope?: MatchScope
  registrableDomain?: string | null
  sources?: readonly SourceId[]
  categories?: readonly string[]
  entityNames?: readonly string[]
  confidenceTier?: ConfidenceTier
  confidenceScore?: number
  lightAction?: ModeAction
  compatibilityTags?: readonly string[]
  reviewNotes?: readonly string[]
  firstSeenAt?: string
  lastSeenAt?: string
}

export interface NormalizedRuleDomain {
  domain: string
  matchScope: MatchScope
}

export interface NormalizeHostnameOptions {
  allowSingleLabel?: boolean
}

export interface Ruleset {
  version: string
  generatedAt: string | null
  rules: CanonicalRule[]
  exact: ReadonlyMap<string, CanonicalRule>
  suffix: ReadonlyMap<string, CanonicalRule>
}

export interface BuildRulesetOptions {
  version?: string
  generatedAt?: string | null
}

export interface DeriveRuleSemanticsOptions {
  sources: readonly SourceId[]
  compatibilityTags?: readonly string[]
}

export interface DerivedRuleSemantics {
  confidenceTier: ConfidenceTier
  confidenceScore: number
  lightAction: ModeAction
}

const confidenceTierRank: Record<ConfidenceTier, number> = {
  review: 0,
  medium: 1,
  high: 2,
}

const confidenceScoreByTier: Record<ConfidenceTier, number> = {
  review: 0.35,
  medium: 0.65,
  high: 0.9,
}

const modeActionRank: Record<ModeAction, number> = {
  observe: 0,
  block: 1,
}

export function normalizeHostname(
  hostname: string,
  options: NormalizeHostnameOptions = {},
): string | null {
  const allowSingleLabel = options.allowSingleLabel ?? true
  const trimmed = hostname.trim().toLowerCase()
  if (trimmed.length === 0) return null

  const candidate = trimmed.replace(/\.+$/u, '')
  if (candidate.length === 0) return null
  if (/[\s/@?#]/u.test(candidate) || candidate.includes(':')) return null

  let asciiHostname: string
  try {
    asciiHostname = new URL(`http://${candidate}`).hostname
  } catch {
    return null
  }

  if (asciiHostname.length === 0 || isIpLiteral(asciiHostname)) return null

  const labels = asciiHostname.split('.')
  if (!allowSingleLabel && labels.length < 2) return null

  for (const label of labels) {
    if (!isValidHostnameLabel(label)) return null
  }

  return asciiHostname
}

export function normalizeRuleDomain(rawDomain: string): NormalizedRuleDomain | null {
  const trimmed = rawDomain.trim()
  if (trimmed.length === 0) return null

  const matchScope: MatchScope = trimmed.startsWith('*.') ? 'suffix' : 'exact'
  const domain = normalizeHostname(
    matchScope === 'suffix' ? trimmed.slice(2) : trimmed,
    { allowSingleLabel: false },
  )
  if (domain === null) return null

  return { domain, matchScope }
}

export function buildRuleset(
  rules: readonly CanonicalRuleInput[],
  options: BuildRulesetOptions = {},
): Ruleset {
  const merged = new Map<string, CanonicalRule>()

  for (const rule of rules) {
    const normalizedRule = normalizeCanonicalRule(rule)
    if (normalizedRule === null) continue

    const key = `${normalizedRule.matchScope}:${normalizedRule.domain}`
    const existing = merged.get(key)
    merged.set(key, existing ? mergeCanonicalRules(existing, normalizedRule) : normalizedRule)
  }

  const orderedRules = [...merged.values()].sort(compareCanonicalRules)
  const exact = new Map<string, CanonicalRule>()
  const suffix = new Map<string, CanonicalRule>()

  for (const rule of orderedRules) {
    const index = rule.matchScope === 'exact' ? exact : suffix
    index.set(rule.domain, rule)
  }

  return {
    version: options.version ?? 'dev',
    generatedAt: options.generatedAt ?? null,
    rules: orderedRules,
    exact,
    suffix,
  }
}

export function lookupRule(hostname: string, ruleset: Pick<Ruleset, 'exact' | 'suffix'>): CanonicalRule | null {
  const normalizedHostname = normalizeHostname(hostname)
  if (normalizedHostname === null) return null

  const exactMatch = ruleset.exact.get(normalizedHostname)
  if (exactMatch) return exactMatch

  let idx = normalizedHostname.indexOf('.')
  while (idx >= 0 && idx < normalizedHostname.length - 1) {
    const suffix = normalizedHostname.slice(idx + 1)
    const suffixMatch = ruleset.suffix.get(suffix)
    if (suffixMatch) return suffixMatch
    idx = normalizedHostname.indexOf('.', idx + 1)
  }

  return null
}

export function deriveRuleSemantics(
  options: DeriveRuleSemanticsOptions,
): DerivedRuleSemantics {
  const sources = uniqueSorted(options.sources)
  const compatibilityTags = uniqueSorted(options.compatibilityTags ?? [])
  const confidenceTier = deriveConfidenceTierFromSources(sources)

  return {
    confidenceTier,
    confidenceScore: deriveConfidenceScore(confidenceTier, sources),
    lightAction: deriveLightAction(confidenceTier, compatibilityTags),
  }
}

function normalizeCanonicalRule(rule: CanonicalRuleInput): CanonicalRule | null {
  const normalizedDomain = normalizeRuleDomain(rule.domain)
  if (normalizedDomain === null) return null

  const matchScope = rule.matchScope ?? normalizedDomain.matchScope
  const domain = normalizedDomain.domain
  const sources = uniqueSorted(rule.sources ?? [])
  const compatibilityTags = uniqueSorted(rule.compatibilityTags ?? [])
  const derivedSemantics = deriveRuleSemantics({ sources, compatibilityTags })
  const registrableDomain =
    rule.registrableDomain === undefined || rule.registrableDomain === null
      ? null
      : normalizeHostname(rule.registrableDomain, { allowSingleLabel: false })

  const confidenceTier = rule.confidenceTier ?? derivedSemantics.confidenceTier
  const confidenceScore = clampConfidenceScore(
    rule.confidenceScore ?? derivedSemantics.confidenceScore,
  )

  return {
    id: `${matchScope}:${domain}`,
    domain,
    matchScope,
    registrableDomain,
    sources,
    sourceCount: sources.length,
    categories: uniqueSorted(rule.categories ?? []),
    entityNames: uniqueSorted(rule.entityNames ?? []),
    confidenceTier,
    confidenceScore,
    lightAction: rule.lightAction ?? deriveLightAction(confidenceTier, compatibilityTags),
    extremeAction: 'block',
    compatibilityTags,
    reviewNotes: uniqueSorted(rule.reviewNotes ?? []),
    firstSeenAt: rule.firstSeenAt ?? '',
    lastSeenAt: rule.lastSeenAt ?? rule.firstSeenAt ?? '',
  }
}

function mergeCanonicalRules(left: CanonicalRule, right: CanonicalRule): CanonicalRule {
  const sources = uniqueSorted([...left.sources, ...right.sources])
  const mergedCompatibilityTags = uniqueSorted([...left.compatibilityTags, ...right.compatibilityTags])
  const strongerTier =
    confidenceTierRank[right.confidenceTier] > confidenceTierRank[left.confidenceTier]
      ? right.confidenceTier
      : left.confidenceTier
  const strongerAction =
    modeActionRank[right.lightAction] > modeActionRank[left.lightAction]
      ? right.lightAction
      : left.lightAction
  const derivedSemantics = deriveRuleSemantics({
    sources,
    compatibilityTags: mergedCompatibilityTags,
  })
  const mergedConfidenceTier =
    confidenceTierRank[derivedSemantics.confidenceTier] > confidenceTierRank[strongerTier]
      ? derivedSemantics.confidenceTier
      : strongerTier

  return {
    id: left.id,
    domain: left.domain,
    matchScope: left.matchScope,
    registrableDomain: left.registrableDomain ?? right.registrableDomain,
    sources,
    sourceCount: sources.length,
    categories: uniqueSorted([...left.categories, ...right.categories]),
    entityNames: uniqueSorted([...left.entityNames, ...right.entityNames]),
    confidenceTier: mergedConfidenceTier,
    confidenceScore: Math.max(left.confidenceScore, right.confidenceScore, derivedSemantics.confidenceScore),
    lightAction:
      mergedCompatibilityTags.length > 0
        ? 'observe'
        : modeActionRank[derivedSemantics.lightAction] > modeActionRank[strongerAction]
          ? derivedSemantics.lightAction
          : strongerAction,
    extremeAction: 'block',
    compatibilityTags: mergedCompatibilityTags,
    reviewNotes: uniqueSorted([...left.reviewNotes, ...right.reviewNotes]),
    firstSeenAt: minTimestamp(left.firstSeenAt, right.firstSeenAt),
    lastSeenAt: maxTimestamp(left.lastSeenAt, right.lastSeenAt),
  }
}

function compareCanonicalRules(left: CanonicalRule, right: CanonicalRule): number {
  if (left.domain === right.domain) {
    return left.matchScope.localeCompare(right.matchScope)
  }
  return left.domain.localeCompare(right.domain)
}

function deriveConfidenceTierFromSources(sources: readonly SourceId[]): ConfidenceTier {
  if (sources.length === 0) return 'review'

  const hasOisdSmall = sources.includes('oisd_small')
  const hasOisdBig = sources.includes('oisd_big')
  const hasBlocklistProject = sources.includes('blocklistproject_tracking')
  const hasDdg = sources.includes('ddg_tracker_blocklists')

  if (hasOisdSmall && (hasDdg || hasBlocklistProject)) return 'high'
  if (hasOisdSmall || hasOisdBig || hasBlocklistProject) return 'medium'
  return 'review'
}

function deriveConfidenceScore(
  confidenceTier: ConfidenceTier,
  sources: readonly SourceId[],
): number {
  if (confidenceTier === 'high') {
    return sources.includes('ddg_tracker_blocklists') ? 0.95 : 0.9
  }
  if (confidenceTier === 'medium') {
    return sources.includes('oisd_small') ? 0.75 : confidenceScoreByTier.medium
  }
  if (sources.length === 1 && sources[0] === 'ddg_tracker_blocklists') {
    return 0.2
  }
  return confidenceScoreByTier.review
}

function deriveLightAction(
  confidenceTier: ConfidenceTier,
  compatibilityTags: readonly string[],
): ModeAction {
  if (compatibilityTags.length > 0) return 'observe'
  return confidenceTier === 'high' ? 'block' : 'observe'
}

function clampConfidenceScore(score: number): number {
  if (!Number.isFinite(score)) return 0
  if (score < 0) return 0
  if (score > 1) return 1
  return score
}

function isIpLiteral(value: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/u.test(value) || value.includes(':')
}

function isValidHostnameLabel(label: string): boolean {
  return label.length > 0
    && label.length <= 63
    && /^[a-z0-9-]+$/u.test(label)
    && !label.startsWith('-')
    && !label.endsWith('-')
}

function uniqueSorted<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values.map((value) => value.trim() as T).filter((value) => value.length > 0))].sort(
    (left, right) => left.localeCompare(right),
  )
}

function minTimestamp(left: string, right: string): string {
  if (left.length === 0) return right
  if (right.length === 0) return left
  return left <= right ? left : right
}

function maxTimestamp(left: string, right: string): string {
  if (left.length === 0) return right
  if (right.length === 0) return left
  return left >= right ? left : right
}