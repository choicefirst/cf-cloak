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
export declare function matchDomain(name: string, blocklist: ReadonlySet<string>): string | null;
/**
 * Given a list of raw domain strings from the blocklist source,
 * normalise and deduplicate them into a Set ready for matchDomain().
 */
export declare function buildBlocklist(domains: readonly string[]): Set<string>;
/**
 * Check whether any domain in a given array would be blocked.
 * Useful for rule preview in the UI.
 */
export declare function anyBlocked(domains: readonly string[], blocklist: ReadonlySet<string>): boolean;
//# sourceMappingURL=index.d.ts.map