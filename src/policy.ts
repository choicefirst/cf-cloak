/**
 * cf-cloak Policy Engine
 *
 * A pure, side-effect-free decision function that determines whether a domain
 * request should be blocked or allowed, given a policy configuration.
 *
 * Priority order (highest → lowest):
 *  1. Temporary allows   — user clicked "allow for now" until expiry timestamp
 *  2. Domain overrides   — explicit per-suffix block/allow rules
 *  3. App overrides      — per-Android-package block/allow rules
 *  4. Category check     — category blocking enabled/disabled
 *  5. Canonical rule     — Light/Extreme mode may observe or block the match
 *  6. Blocklist match    — plain matched domains fall back to defaultAction
 *  7. Not in blocklist   — always allow (never block unlisted domains)
 *
 * Licensed under AGPLv3. See the repository root for full terms.
 */

import type { CanonicalRule, ModeAction } from './ruleset.js'

export type Action = 'block' | 'allow'
export type DecisionEffect = 'block' | 'allow' | 'observe'
export type EnforcementMode = 'light' | 'extreme'

/**
 * A temporary exception that allows a specific domain/suffix until
 * the given epoch-ms timestamp. Used for "allow for now" flows.
 */
export interface TempAllow {
  /** Domain name or suffix to allow (case-insensitive, exact or suffix match). */
  domain: string
  /** Unix epoch milliseconds at which this exception expires. */
  expiresAt: number
}

/**
 * The policy configuration that controls blocking behaviour.
 *
 * All fields except `version` are optional on the wire — the evaluator falls
 * back to the defaults in DEFAULT_POLICY when fields are missing.
 */
export interface Policy {
  /** Schema version — increment when the shape changes. */
  version: number
  /** The active enforcement mode for canonical rules. */
  mode?: EnforcementMode
  /**
   * Action applied when a domain is in the blocklist and no other rule
   * overrides it. Default: 'block'.
   */
  defaultAction: Action
  /**
   * Per-category on/off switches.
   *   true  → category blocking is active (default when key is absent)
   *   false → category is opted-out; matching domains are allowed through
   */
  categoryEnabled: Record<string, boolean>
  /**
   * Per-Android-package-name forced action.
   * Overrides category + default but is overridden by domain overrides and
   * temp-allows.
   */
  appOverrides: Record<string, Action>
  /**
    * Per-domain forced action.
    * A key may match the domain exactly or as a suffix (e.g. "evil.com"
    * matches "www.evil.com"). Exact matches beat suffix matches, and among
    * suffixes the longest match wins. Overridden only by temp-allows.
   */
  domainOverrides: Record<string, Action>
  /**
   * Temporary exceptions — checked first, expire automatically.
   * Array is walked in declaration order; the first non-expired match wins.
   */
  tempAllows: TempAllow[]
}

/** The policy applied when none has been explicitly configured. */
export const DEFAULT_POLICY: Policy = {
  version: 2,
  mode: 'light',
  defaultAction: 'block',
  categoryEnabled: {},
  appOverrides: {},
  domainOverrides: {},
  tempAllows: [],
}

export type DecisionReason =
  | 'temp_allow'
  | 'domain_override'
  | 'system_allowlist'
  | 'app_override'
  | 'category_disabled'
  | 'category_blocked'
  | 'rule_observe'
  | 'rule_block'
  | 'default_block'
  | 'default_allow'

export interface Decision {
  action: Action
  effect: DecisionEffect
  reason: DecisionReason
}

export type MatchedPolicyRule = Pick<
  CanonicalRule,
  | 'domain'
  | 'confidenceScore'
  | 'entityNames'
  | 'matchScope'
  | 'sources'
  | 'categories'
  | 'confidenceTier'
  | 'compatibilityTags'
  | 'reviewNotes'
  | 'lightAction'
  | 'extremeAction'
>

/** Input to the evaluate() function. */
export interface PolicyRequest {
  /** The queried domain, already lowercased. */
  domain: string
  /** Explicit active mode for this evaluation when the caller has already resolved it. */
  mode?: EnforcementMode | null
  /**
   * Preferred canonical match object from the ruleset runtime. When present,
   * evaluation reads category and mode actions from here before consulting the
   * legacy decomposed fields below.
   */
  matchedRule?: MatchedPolicyRule | null
  /** Category from blocklist metadata, or null/undefined if no metadata. */
  category?: string | null
  /** Android package name of the requesting app, or null/undefined if unknown. */
  app?: string | null
  /** True when a shipped system allowlist entry matched this domain. */
  systemAllowlisted?: boolean | null
  /**
   * The blocklist suffix that matched this domain, or null/undefined when the
   * domain is NOT in the blocklist.  When absent, the domain is allowed unless
   * a domain/app override explicitly blocks it.
   */
  matchedSuffix?: string | null
  /** Canonical Light-mode action for the matched rule, when available. */
  lightAction?: ModeAction | null
  /** Canonical Extreme-mode action for the matched rule, when available. */
  extremeAction?: ModeAction | null
}

/**
 * Evaluate a DNS/SNI request against a policy and return the blocking decision.
 *
 * This function is pure — it has no side effects. The VPN service acts on the
 * returned decision (block → NXDOMAIN / RST, allow → forward).
 *
 * @param request  The normalised request to evaluate.
 * @param policy   The active policy (pass DEFAULT_POLICY if none configured).
 * @param now      Current epoch-ms — injectable for deterministic testing.
 */
export function evaluate(
  request: PolicyRequest,
  policy: Policy,
  now = Date.now(),
): Decision {
  const domain = request.domain.toLowerCase()
  const mode = resolveEnforcementMode(request.mode ?? policy.mode)
  const matchedDomain = getMatchedDomain(request)
  const matchedCategory = getMatchedCategory(request)

  // ── 1. Temp allows (highest priority) ────────────────────────────────────
  for (const ta of policy.tempAllows) {
    if (ta.expiresAt > now && domainMatchesSuffix(domain, ta.domain.toLowerCase())) {
      return { action: 'allow', effect: 'allow', reason: 'temp_allow' }
    }
  }

  // ── 2. Domain overrides ───────────────────────────────────────────────────
  const domainOverrideAction = getDomainOverrideAction(domain, policy.domainOverrides)
  if (domainOverrideAction !== null) {
    return { action: domainOverrideAction, effect: domainOverrideAction, reason: 'domain_override' }
  }

  // ── 3. System allowlist ───────────────────────────────────────────────────
  if (request.systemAllowlisted && matchedDomain !== null) {
    return { action: 'allow', effect: 'allow', reason: 'system_allowlist' }
  }

  // ── 4. App overrides ──────────────────────────────────────────────────────
  if (request.app) {
    const override = policy.appOverrides[request.app]
    if (override !== undefined) {
      return { action: override, effect: override, reason: 'app_override' }
    }
  }

  // ── 5. Category + default (applies only when domain IS in blocklist) ──────
  if (matchedDomain !== null) {
    if (matchedCategory) {
      const enabled = policy.categoryEnabled[matchedCategory]
      if (enabled === false) {
        // User opted this category out — allow even though it's in the list
        return { action: 'allow', effect: 'allow', reason: 'category_disabled' }
      }
      if (enabled === true) {
        return { action: 'block', effect: 'block', reason: 'category_blocked' }
      }
      // key absent → fall through to defaultAction
    }

    const matchedRuleAction = getMatchedRuleAction(request, mode)
    if (matchedRuleAction === 'observe') {
      return { action: 'allow', effect: 'observe', reason: 'rule_observe' }
    }
    if (matchedRuleAction === 'block') {
      return { action: 'block', effect: 'block', reason: 'rule_block' }
    }

    return {
      action: policy.defaultAction,
      effect: policy.defaultAction,
      reason: policy.defaultAction === 'block' ? 'default_block' : 'default_allow',
    }
  }

  // ── 5. Domain not in blocklist → allow ───────────────────────────────────
  return { action: 'allow', effect: 'allow', reason: 'default_allow' }
}

function getMatchedRuleAction(
  request: PolicyRequest,
  mode: EnforcementMode,
): ModeAction | null {
  if (mode === 'extreme') {
    return request.matchedRule?.extremeAction ?? request.extremeAction ?? null
  }

  return request.matchedRule?.lightAction ?? request.lightAction ?? null
}

function getMatchedDomain(request: PolicyRequest): string | null {
  return request.matchedRule?.domain ?? request.matchedSuffix ?? null
}

function getMatchedCategory(request: PolicyRequest): string | null {
  return request.matchedRule?.categories[0] ?? request.category ?? null
}

function resolveEnforcementMode(mode: EnforcementMode | null | undefined): EnforcementMode {
  return mode ?? DEFAULT_POLICY.mode ?? 'light'
}

function getDomainOverrideAction(
  domain: string,
  overrides: Record<string, Action>,
): Action | null {
  let bestAction: Action | null = null
  let bestMatchLength = -1
  let bestMatchIsExact = false

  for (const [rawCandidate, action] of Object.entries(overrides)) {
    const candidate = rawCandidate.toLowerCase()
    if (!domainMatchesSuffix(domain, candidate)) {
      continue
    }

    const isExact = domain === candidate
    if (
      bestAction === null ||
      (isExact && !bestMatchIsExact) ||
      (isExact === bestMatchIsExact && candidate.length > bestMatchLength)
    ) {
      bestAction = action
      bestMatchLength = candidate.length
      bestMatchIsExact = isExact
    }
  }

  return bestAction
}

/**
 * Returns true if `domain` equals `suffix` or is a subdomain of it.
 * Both arguments must be pre-lowercased.
 */
function domainMatchesSuffix(domain: string, suffix: string): boolean {
  return domain === suffix || domain.endsWith(`.${suffix}`)
}
