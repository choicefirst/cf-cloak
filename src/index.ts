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

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A blocklist rule with optional metadata.
 * The string shorthand (domain only) is accepted anywhere a RuleEntry is.
 */
export interface RuleEntry {
  domain: string
  category?: string
  source?: string
}

/**
 * Rich match result returned by [matchDomainDetailed].
 * Mirrors the Kotlin `MatchResult` data class in DnsPacket.kt.
 */
export interface MatchResult {
  /** The blocklist suffix that matched (e.g. "doubleclick.net"). */
  suffix: string
  /** Tracker category (e.g. "analytics", "ads") or null for plain blocklists. */
  category: string | null
  /** Blocklist source identifier or null for plain blocklists. */
  source: string | null
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
): { set: Set<string>; meta: Map<string, { category: string | null; source: string | null }> } {
  const set = new Set<string>()
  const meta = new Map<string, { category: string | null; source: string | null }>()
  for (const rule of rules) {
    if (typeof rule === 'string') {
      const norm = rule.trim().toLowerCase()
      if (norm.length > 0) set.add(norm)
    } else {
      const norm = rule.domain.trim().toLowerCase()
      if (norm.length > 0) {
        set.add(norm)
        meta.set(norm, { category: rule.category ?? null, source: rule.source ?? null })
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
  meta: ReadonlyMap<string, { category: string | null; source: string | null }> = new Map(),
): MatchResult | null {
  const suffix = matchDomain(name, blocklist)
  if (suffix === null) return null
  const m = meta.get(suffix)
  return {
    suffix,
    category: m?.category ?? null,
    source: m?.source ?? null,
  }
}

/**
 * Check whether any domain in a given array would be blocked.
 * Useful for rule preview in the UI.
 */
export function anyBlocked(domains: readonly string[], blocklist: ReadonlySet<string>): boolean {
  return domains.some((d) => matchDomain(d.trim().toLowerCase(), blocklist) !== null)
}

export { sniHostname } from './sni.js'

// ── Policy engine ─────────────────────────────────────────────────────────────
export type {
  Action,
  TempAllow,
  Policy,
  PolicyRequest,
  Decision,
  DecisionReason,
} from './policy.js'
export { DEFAULT_POLICY, evaluate } from './policy.js'

// ── Blocklist signing / verification ──────────────────────────────────────────
export type { SignedBlocklist } from './signing.js'
export { buildSignaturePayload, signBlocklist, verifyBlocklist } from './signing.js'
