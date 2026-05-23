import type {
  CanonicalRuleInput,
  ConfidenceTier,
  ModeAction,
  NormalizedRuleDomain,
  SourceId,
} from './ruleset.js'
import { normalizeRuleDomain } from './ruleset.js'

export interface ParseSourceTextOptions {
  source: SourceId
  categories?: readonly string[]
  entityNames?: readonly string[]
  compatibilityTags?: readonly string[]
  confidenceTier?: ConfidenceTier
  lightAction?: ModeAction
}

export interface ParsedSourceTextResult {
  rules: CanonicalRuleInput[]
  exceptions: NormalizedRuleDomain[]
}

export function parseSourceText(
  text: string,
  options: ParseSourceTextOptions,
): ParsedSourceTextResult {
  const rules: CanonicalRuleInput[] = []
  const exceptions: NormalizedRuleDomain[] = []
  const ruleKeys = new Set<string>()
  const exceptionKeys = new Set<string>()

  for (const rawLine of text.split(/\r?\n/u)) {
    const parsed = parseSourceLine(rawLine)
    if (parsed === null) continue

    const key = `${parsed.matchScope}:${parsed.domain}`

    if (parsed.exception) {
      if (!exceptionKeys.has(key)) {
        exceptionKeys.add(key)
        exceptions.push({ domain: parsed.domain, matchScope: parsed.matchScope })
      }
      continue
    }

    if (ruleKeys.has(key)) continue
    ruleKeys.add(key)

    rules.push({
      domain: parsed.domain,
      matchScope: parsed.matchScope,
      sources: [options.source],
      categories: options.categories ? [...options.categories] : undefined,
      entityNames: options.entityNames ? [...options.entityNames] : undefined,
      compatibilityTags: options.compatibilityTags ? [...options.compatibilityTags] : undefined,
      confidenceTier: options.confidenceTier,
      lightAction: options.lightAction,
    })
  }

  return { rules, exceptions }
}

interface ParsedSourceLine extends NormalizedRuleDomain {
  exception: boolean
}

function parseSourceLine(line: string): ParsedSourceLine | null {
  let trimmed = line.trim()
  if (trimmed.length === 0) return null
  if (trimmed.startsWith('!') || trimmed.startsWith('#') || trimmed.startsWith('[')) return null

  let exception = false
  if (trimmed.startsWith('@@')) {
    exception = true
    trimmed = trimmed.slice(2).trim()
  }

  const hashIndex = trimmed.indexOf('#')
  if (hashIndex >= 0) {
    trimmed = trimmed.slice(0, hashIndex).trim()
  }
  if (trimmed.length === 0) return null
  if (trimmed.startsWith('/')) return null

  const adblockRule = parseAdblockRule(trimmed)
  if (adblockRule !== null) return { ...adblockRule, exception }

  const hostsRule = parseHostsRule(trimmed)
  if (hostsRule !== null) return { ...hostsRule, exception }

  const plainRule = normalizeRuleDomain(trimmed)
  if (plainRule !== null) return { ...plainRule, exception }

  return null
}

function parseAdblockRule(line: string): NormalizedRuleDomain | null {
  if (!line.startsWith('||')) return null

  const body = line.slice(2)
  const separatorIndex = body.search(/[\^/$]/u)
  const hostToken = (separatorIndex === -1 ? body : body.slice(0, separatorIndex)).trim()
  if (hostToken.length === 0) return null

  return normalizeRuleDomain(hostToken.startsWith('*.') ? hostToken : `*.${hostToken}`)
}

function parseHostsRule(line: string): NormalizedRuleDomain | null {
  const tokens = line.split(/\s+/u)
  if (tokens.length < 2) return null
  if (!looksLikeHostsAddress(tokens[0])) return null

  return normalizeRuleDomain(tokens[1])
}

function looksLikeHostsAddress(token: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/u.test(token) || /^[0-9a-f:]+$/iu.test(token)
}