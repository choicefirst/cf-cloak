import type {
  CanonicalRule,
  ConfidenceTier,
  MatchScope,
  Ruleset,
  SourceId,
} from './ruleset.js'
import { lookupRule, normalizeHostname } from './ruleset.js'
import { lookupRulesetException } from './compatibility.js'
import type { Decision, EnforcementMode, Policy, PolicyRequest } from './policy.js'
import { DEFAULT_POLICY, evaluate } from './policy.js'
import type { RulesetExceptionEntry } from './signing.js'
import { sniHostname } from './sni.js'

export type RulesetHostnameSource = 'dns' | 'sni'

export interface DnsRulesetRequest {
  kind: 'dns'
  hostname: string
}

export interface SniRulesetRequest {
  kind: 'sni'
  payload: Uint8Array
}

export type DnsOrSniRulesetRequest = DnsRulesetRequest | SniRulesetRequest

export interface ResolvedDnsOrSniHostname {
  hostname: string
  hostnameSource: RulesetHostnameSource
}

export interface RulesetRequestOptions {
  app?: string | null
  systemAllowlist?: readonly RulesetExceptionEntry[]
}

export interface BuiltPolicyRequestFromRuleset {
  normalizedDomain: string
  matchedRule: CanonicalRule | null
  policyRequest: PolicyRequest
}

export interface EvaluatedRulesetRequest extends BuiltPolicyRequestFromRuleset {
  decision: Decision
}

export type LocalDnsEventAction = 'blocked' | 'observed' | 'allowed_override' | 'allowed_temp'

export type LocalDnsEventReason =
  | 'auto_block_light'
  | 'auto_block_extreme'
  | 'observed_light'
  | 'user_override_allow'
  | 'user_override_block'
  | 'system_allowlist'
  | 'temp_unblock'

export interface LocalDnsEvent {
  id: string
  occurredAt: string
  hostname: string
  registrableDomain: string | null
  matchedDomain: string
  matchScope: MatchScope
  appId: string | null
  mode: EnforcementMode
  action: LocalDnsEventAction
  reason: LocalDnsEventReason
  sources: SourceId[]
  categories: string[]
  confidenceTier: ConfidenceTier
  compatibilityTags: string[]
  blocklistVersion: string
  policyVersion: number
}

export interface BuildLocalDnsEventOptions {
  eventId: string
  occurredAt: string
}

export interface EvaluatedRulesetRequestWithEvent extends EvaluatedRulesetRequest {
  event: LocalDnsEvent | null
}

export interface EvaluatedDnsOrSniRulesetRequestWithEvent extends EvaluatedRulesetRequestWithEvent {
  hostnameSource: RulesetHostnameSource
}

export function resolveDnsOrSniHostname(
  request: DnsOrSniRulesetRequest,
): ResolvedDnsOrSniHostname | null {
  if (request.kind === 'dns') {
    return {
      hostname: request.hostname,
      hostnameSource: 'dns',
    }
  }

  const hostname = sniHostname(request.payload)
  if (hostname === null) {
    return null
  }

  return {
    hostname,
    hostnameSource: 'sni',
  }
}

export function buildPolicyRequestFromRuleset(
  domain: string,
  ruleset: Ruleset,
  options: RulesetRequestOptions = {},
): BuiltPolicyRequestFromRuleset | null {
  const normalizedDomain = normalizeHostname(domain)
  if (normalizedDomain === null) {
    return null
  }

  const matchedRule = lookupRule(normalizedDomain, ruleset)
  const matchedSystemAllowlist = options.systemAllowlist
    ? lookupRulesetException(normalizedDomain, options.systemAllowlist)
    : null

  return {
    normalizedDomain,
    matchedRule,
    policyRequest: {
      domain: normalizedDomain,
      matchedRule: matchedRule ?? null,
      matchedSuffix: matchedRule?.domain ?? null,
      category: matchedRule?.categories[0] ?? null,
      app: options.app ?? null,
      ...(matchedSystemAllowlist ? { systemAllowlisted: true } : {}),
      lightAction: matchedRule?.lightAction ?? null,
      extremeAction: matchedRule?.extremeAction ?? null,
    },
  }
}

export function evaluateRulesetRequest(
  domain: string,
  ruleset: Ruleset,
  policy: Policy,
  options: RulesetRequestOptions & { now?: number } = {},
): EvaluatedRulesetRequest | null {
  const builtRequest = buildPolicyRequestFromRuleset(domain, ruleset, options)
  if (builtRequest === null) {
    return null
  }

  const mode = policy.mode ?? DEFAULT_POLICY.mode ?? 'light'
  const policyRequest = {
    ...builtRequest.policyRequest,
    mode,
  }

  return {
    ...builtRequest,
    policyRequest,
    decision: evaluate(policyRequest, policy, options.now),
  }
}

export function buildLocalDnsEvent(
  evaluatedRequest: EvaluatedRulesetRequest,
  ruleset: Pick<Ruleset, 'version'>,
  policy: Policy,
  options: BuildLocalDnsEventOptions,
): LocalDnsEvent | null {
  if (evaluatedRequest.matchedRule === null) {
    return null
  }

  const mode = evaluatedRequest.policyRequest.mode ?? policy.mode ?? DEFAULT_POLICY.mode ?? 'light'

  return {
    id: options.eventId,
    occurredAt: options.occurredAt,
    hostname: evaluatedRequest.normalizedDomain,
    registrableDomain: evaluatedRequest.matchedRule.registrableDomain,
    matchedDomain: evaluatedRequest.matchedRule.domain,
    matchScope: evaluatedRequest.matchedRule.matchScope,
    appId: evaluatedRequest.policyRequest.app ?? null,
    mode,
    action: mapDecisionToEventAction(evaluatedRequest.decision),
    reason: mapDecisionToEventReason(evaluatedRequest.decision, mode),
    sources: [...evaluatedRequest.matchedRule.sources],
    categories: [...evaluatedRequest.matchedRule.categories],
    confidenceTier: evaluatedRequest.matchedRule.confidenceTier,
    compatibilityTags: [...evaluatedRequest.matchedRule.compatibilityTags],
    blocklistVersion: ruleset.version,
    policyVersion: policy.version,
  }
}

export function evaluateRulesetRequestWithEvent(
  domain: string,
  ruleset: Ruleset,
  policy: Policy,
  options: RulesetRequestOptions & BuildLocalDnsEventOptions & { now?: number },
): EvaluatedRulesetRequestWithEvent | null {
  const evaluatedRequest = evaluateRulesetRequest(domain, ruleset, policy, options)
  if (evaluatedRequest === null) {
    return null
  }

  return {
    ...evaluatedRequest,
    event: buildLocalDnsEvent(evaluatedRequest, ruleset, policy, options),
  }
}

export function evaluateDnsOrSniRulesetRequestWithEvent(
  request: DnsOrSniRulesetRequest,
  ruleset: Ruleset,
  policy: Policy,
  options: RulesetRequestOptions & BuildLocalDnsEventOptions & { now?: number },
): EvaluatedDnsOrSniRulesetRequestWithEvent | null {
  const resolvedRequest = resolveDnsOrSniHostname(request)
  if (resolvedRequest === null) {
    return null
  }

  const evaluatedRequest = evaluateRulesetRequestWithEvent(
    resolvedRequest.hostname,
    ruleset,
    policy,
    options,
  )
  if (evaluatedRequest === null) {
    return null
  }

  return {
    ...evaluatedRequest,
    hostnameSource: resolvedRequest.hostnameSource,
  }
}

function mapDecisionToEventAction(decision: Decision): LocalDnsEventAction {
  if (decision.reason === 'temp_allow') {
    return 'allowed_temp'
  }
  if (decision.action === 'block') {
    return 'blocked'
  }
  if (decision.effect === 'observe') {
    return 'observed'
  }

  return 'allowed_override'
}

function mapDecisionToEventReason(
  decision: Decision,
  mode: EnforcementMode,
): LocalDnsEventReason {
  switch (decision.reason) {
    case 'temp_allow':
      return 'temp_unblock'
    case 'system_allowlist':
      return 'system_allowlist'
    case 'domain_override':
    case 'app_override':
    case 'category_disabled':
      return decision.action === 'block' ? 'user_override_block' : 'user_override_allow'
    case 'category_blocked':
      return 'user_override_block'
    case 'rule_observe':
      return 'observed_light'
    case 'rule_block':
    case 'default_block':
      return mode === 'extreme' ? 'auto_block_extreme' : 'auto_block_light'
    case 'default_allow':
      return mode === 'light' ? 'observed_light' : 'user_override_allow'
  }
}