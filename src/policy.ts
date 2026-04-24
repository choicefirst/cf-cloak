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
 *  5. Blocklist match    — domain is in blocklist → apply defaultAction
 *  6. Not in blocklist   — always allow (never block unlisted domains)
 *
 * Licensed under AGPLv3. See the repository root for full terms.
 */

export type Action = 'block' | 'allow'

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
   * Per-domain-suffix forced action.
   * Matches the domain exactly or any subdomain (e.g. "evil.com" matches
   * "www.evil.com"). Overridden only by temp-allows.
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
  version: 1,
  defaultAction: 'block',
  categoryEnabled: {},
  appOverrides: {},
  domainOverrides: {},
  tempAllows: [],
}

export type DecisionReason =
  | 'temp_allow'
  | 'domain_override'
  | 'app_override'
  | 'category_disabled'
  | 'category_blocked'
  | 'default_block'
  | 'default_allow'

export interface Decision {
  action: Action
  reason: DecisionReason
}

/** Input to the evaluate() function. */
export interface PolicyRequest {
  /** The queried domain, already lowercased. */
  domain: string
  /** Category from blocklist metadata, or null/undefined if no metadata. */
  category?: string | null
  /** Android package name of the requesting app, or null/undefined if unknown. */
  app?: string | null
  /**
   * The blocklist suffix that matched this domain, or null/undefined when the
   * domain is NOT in the blocklist.  When absent, the domain is allowed unless
   * a domain/app override explicitly blocks it.
   */
  matchedSuffix?: string | null
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

  // ── 1. Temp allows (highest priority) ────────────────────────────────────
  for (const ta of policy.tempAllows) {
    if (ta.expiresAt > now && domainMatchesSuffix(domain, ta.domain.toLowerCase())) {
      return { action: 'allow', reason: 'temp_allow' }
    }
  }

  // ── 2. Domain overrides ───────────────────────────────────────────────────
  for (const [suffix, action] of Object.entries(policy.domainOverrides)) {
    if (domainMatchesSuffix(domain, suffix.toLowerCase())) {
      return { action, reason: 'domain_override' }
    }
  }

  // ── 3. App overrides ──────────────────────────────────────────────────────
  if (request.app) {
    const override = policy.appOverrides[request.app]
    if (override !== undefined) {
      return { action: override, reason: 'app_override' }
    }
  }

  // ── 4. Category + default (applies only when domain IS in blocklist) ──────
  if (request.matchedSuffix) {
    if (request.category) {
      const enabled = policy.categoryEnabled[request.category]
      if (enabled === false) {
        // User opted this category out — allow even though it's in the list
        return { action: 'allow', reason: 'category_disabled' }
      }
      if (enabled === true) {
        return { action: 'block', reason: 'category_blocked' }
      }
      // key absent → fall through to defaultAction
    }
    return {
      action: policy.defaultAction,
      reason: policy.defaultAction === 'block' ? 'default_block' : 'default_allow',
    }
  }

  // ── 5. Domain not in blocklist → allow ───────────────────────────────────
  return { action: 'allow', reason: 'default_allow' }
}

/**
 * Returns true if `domain` equals `suffix` or is a subdomain of it.
 * Both arguments must be pre-lowercased.
 */
function domainMatchesSuffix(domain: string, suffix: string): boolean {
  return domain === suffix || domain.endsWith(`.${suffix}`)
}
