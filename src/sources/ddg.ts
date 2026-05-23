import type { CanonicalRuleInput } from '../ruleset.js'
import { normalizeHostname, normalizeRuleDomain } from '../ruleset.js'

export interface DdgTrackerOwner {
  name?: string
  displayName?: string
}

export interface DdgTrackerEntry {
  owner?: DdgTrackerOwner
  default?: string
}

export interface DdgEntityEntry {
  score?: number
  signals?: unknown
}

export interface DdgTrackerDataset {
  readme?: string
  version?: string | number
  trackers?: Record<string, DdgTrackerEntry>
  packageNames?: Record<string, string>
  entities?: Record<string, DdgEntityEntry>
}

export interface DdgEntityMetadata {
  displayName: string | null
  score: number | null
  signals: string[]
}

export interface ParsedDdgTrackerDataResult {
  readme: string | null
  version: string | null
  rules: CanonicalRuleInput[]
  packageOwners: Record<string, string>
  entities: Record<string, DdgEntityMetadata>
}

export function parseDdgTrackerData(input: string | DdgTrackerDataset): ParsedDdgTrackerDataResult {
  const dataset = typeof input === 'string' ? safeParseJson(input) : input
  const trackerEntries = Object.entries(dataset.trackers ?? {})
  const ownerDisplayNames = new Map<string, string>()

  for (const [, entry] of trackerEntries) {
    const owner = normalizeOwner(entry.owner)
    if (owner === null) continue
    if (owner.displayName !== null) {
      ownerDisplayNames.set(owner.name, owner.displayName)
    }
  }

  const rules: CanonicalRuleInput[] = []
  const ruleKeys = new Set<string>()

  for (const [rawDomain, entry] of trackerEntries) {
    const normalizedRule = normalizeRuleDomain(rawDomain)
    if (normalizedRule === null) continue

    const key = `${normalizedRule.matchScope}:${normalizedRule.domain}`
    if (ruleKeys.has(key)) continue
    ruleKeys.add(key)

    const owner = normalizeOwner(entry.owner)
    const entityNames = owner === null
      ? undefined
      : uniqueSorted([owner.displayName ?? owner.name, owner.name])
    const defaultAction = normalizeDefault(entry.default)

    rules.push({
      domain: normalizedRule.domain,
      matchScope: normalizedRule.matchScope,
      sources: ['ddg_tracker_blocklists'],
      categories: ['tracking'],
      entityNames,
      confidenceTier: 'review',
      lightAction: 'observe',
      reviewNotes: [`ddg_default:${defaultAction}`],
    })
  }

  const entities: Record<string, DdgEntityMetadata> = {}
  for (const [rawName, entry] of Object.entries(dataset.entities ?? {})) {
    const name = normalizeText(rawName)
    if (name === null) continue

    entities[name] = {
      displayName: ownerDisplayNames.get(name) ?? null,
      score: typeof entry.score === 'number' && Number.isFinite(entry.score) ? entry.score : null,
      signals: Array.isArray(entry.signals)
        ? uniqueSorted(entry.signals.filter((value): value is string => typeof value === 'string'))
        : [],
    }
  }

  const packageOwners: Record<string, string> = {}
  for (const [rawPackageName, rawOwnerName] of Object.entries(dataset.packageNames ?? {})) {
    const packageName = normalizePackageName(rawPackageName)
    const ownerName = normalizeText(rawOwnerName)
    if (packageName === null || ownerName === null) continue
    packageOwners[packageName] = ownerName
  }

  return {
    readme: normalizeText(dataset.readme) ?? null,
    version: dataset.version === undefined ? null : String(dataset.version),
    rules,
    packageOwners,
    entities,
  }
}

function safeParseJson(input: string): DdgTrackerDataset {
  const parsed = JSON.parse(input) as unknown
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('DuckDuckGo tracker data must be a JSON object.')
  }
  return parsed as DdgTrackerDataset
}

function normalizeOwner(owner: DdgTrackerOwner | undefined): { name: string; displayName: string | null } | null {
  const name = normalizeText(owner?.name)
  if (name === null) return null
  const displayName = normalizeText(owner?.displayName)
  return { name, displayName }
}

function normalizeDefault(value: string | undefined): 'block' | 'ignore' {
  return value === 'ignore' ? 'ignore' : 'block'
}

function normalizePackageName(value: string): string | null {
  const trimmed = value.trim().toLowerCase()
  if (trimmed.length === 0) return null
  return /^[a-z0-9._]+$/u.test(trimmed) ? trimmed : null
}

function normalizeText(value: string | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function uniqueSorted<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values.map((value) => value.trim() as T).filter((value) => value.length > 0))].sort(
    (left, right) => left.localeCompare(right),
  )
}

export function isLikelyDdgTrackerDataset(input: unknown): input is DdgTrackerDataset {
  if (typeof input !== 'object' || input === null) return false
  const candidate = input as DdgTrackerDataset
  return typeof candidate.trackers === 'object' && candidate.trackers !== null
}

export function normalizeDdgTrackerDomain(domain: string): string | null {
  const normalizedRule = normalizeRuleDomain(domain)
  if (normalizedRule !== null) return normalizedRule.domain
  return normalizeHostname(domain, { allowSingleLabel: false })
}