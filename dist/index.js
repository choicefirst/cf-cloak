"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchDomain = matchDomain;
exports.buildBlocklist = buildBlocklist;
exports.anyBlocked = anyBlocked;
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
function matchDomain(name, blocklist) {
    if (blocklist.has(name))
        return name;
    let idx = name.indexOf('.');
    while (idx >= 0 && idx < name.length - 1) {
        const suffix = name.slice(idx + 1);
        if (blocklist.has(suffix))
            return suffix;
        idx = name.indexOf('.', idx + 1);
    }
    return null;
}
/**
 * Given a list of raw domain strings from the blocklist source,
 * normalise and deduplicate them into a Set ready for matchDomain().
 */
function buildBlocklist(domains) {
    const out = new Set();
    for (const d of domains) {
        const norm = d.trim().toLowerCase();
        if (norm.length > 0)
            out.add(norm);
    }
    return out;
}
/**
 * Check whether any domain in a given array would be blocked.
 * Useful for rule preview in the UI.
 */
function anyBlocked(domains, blocklist) {
    return domains.some((d) => matchDomain(d.trim().toLowerCase(), blocklist) !== null);
}
//# sourceMappingURL=index.js.map