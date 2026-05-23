package app.choicefirst.eu.cloak

import java.nio.ByteBuffer

/**
 * Rich result returned by [DnsPacket.matchedBlockDetailed].
 * Carries the matched blocklist suffix plus optional category/source metadata
 * that is populated when the blocklist is served with rich annotations.
 */
data class MatchResult(
    val suffix: String,
    val matchScope: String = "suffix",
    val registrableDomain: String? = null,
    val confidenceScore: Double? = null,
    val entityNames: List<String> = emptyList(),
    val category: String?,
    val categories: List<String> = emptyList(),
    val source: String?,
    val sources: List<String> = emptyList(),
    val confidenceTier: String? = null,
    val compatibilityTags: List<String> = emptyList(),
    val reviewNotes: List<String> = emptyList(),
    val lightAction: ModeAction?,
    val extremeAction: ModeAction?,
)

fun MatchResult.toMatchedPolicyRule(): MatchedPolicyRule = MatchedPolicyRule(
    domain = suffix,
    confidenceScore = confidenceScore,
    entityNames = entityNames,
    matchScope = matchScope,
    registrableDomain = registrableDomain,
    categories = categories.ifEmpty { listOfNotNull(category) },
    confidenceTier = confidenceTier,
    compatibilityTags = compatibilityTags,
    reviewNotes = reviewNotes,
    lightAction = lightAction,
    extremeAction = extremeAction,
)

data class RuleMetadata(
    val category: String?,
    val registrableDomain: String? = null,
    val confidenceScore: Double? = null,
    val entityNames: List<String> = emptyList(),
    val categories: List<String> = emptyList(),
    val source: String?,
    val sources: List<String> = emptyList(),
    val confidenceTier: String? = null,
    val compatibilityTags: List<String> = emptyList(),
    val reviewNotes: List<String> = emptyList(),
    val lightAction: ModeAction?,
    val extremeAction: ModeAction?,
)

/**
 * Minimal DNS packet helpers — enough to extract the queried name from a
 * request and synthesize an NXDOMAIN response for blocked domains.
 *
 * We do not parse the full DNS wire format; we only touch the fields we
 * need. For anything we don't recognise (e.g. an EDNS OPT record, non-A
 * queries), we fall through to forwarding — the real upstream resolver
 * handles the complexity.
 *
 * This file is the open-source trust surface for ChoiceFirst's blocking
 * engine. Licensed under AGPLv3. See the repository root for full terms.
 */
object DnsPacket {

    private fun metadataKey(matchScope: String, domain: String): String = "$matchScope:$domain"

    /** Extract the first QNAME from a DNS query payload. Returns null on parse failure. */
    fun queryName(payload: ByteArray): String? {
        if (payload.size < 12) return null
        val buf = ByteBuffer.wrap(payload)
        // Skip 12-byte header (id, flags, counts). QNAME starts at offset 12.
        buf.position(12)

        val sb = StringBuilder()
        try {
            while (buf.hasRemaining()) {
                val len = buf.get().toInt() and 0xFF
                if (len == 0) break
                // Pointer compression (11xxxxxx) shouldn't appear in queries,
                // but handle defensively by bailing.
                if (len and 0xC0 != 0) return null
                if (len > buf.remaining()) return null
                val label = ByteArray(len)
                buf.get(label)
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(label, Charsets.US_ASCII))
            }
        } catch (_: Exception) {
            return null
        }
        return sb.toString().lowercase()
    }

    /**
     * Build a DNS response that mirrors the request's id/flags/question and
     * sets rcode=3 (NXDOMAIN). The VPN writes this back through the tun FD
     * so the client app receives a normal-looking "no such host" error.
     */
    fun nxDomainResponse(request: ByteArray): ByteArray {
        val out = request.copyOf()
        if (out.size < 12) return out
        // Flags: QR=1, Opcode=copied, AA=0, TC=0, RD=copied, RA=1, Z=0, RCODE=3
        val rdBit = out[2].toInt() and 0x01
        out[2] = (0x80 or rdBit).toByte()      // QR + RD bit
        out[3] = (0x80 or 0x03).toByte()       // RA + RCODE=NXDOMAIN
        // ANCOUNT / NSCOUNT / ARCOUNT = 0 (QDCOUNT stays as-is)
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }

    /**
     * Suffix match: foo.doubleclick.net matches "doubleclick.net".
     * Returns the matched blocklist entry, or null if no match.
     */
    fun matchedBlock(name: String, blocklist: Set<String>): String? {
        if (name in blocklist) return name
        var idx = name.indexOf('.')
        while (idx >= 0 && idx < name.length - 1) {
            val suffix = name.substring(idx + 1)
            if (suffix in blocklist) return suffix
            idx = name.indexOf('.', idx + 1)
        }
        return null
    }

    /**
     * Rich-result variant of [matchedBlock].
     *
     * @param metadata Optional map from blocklist suffix → (category, source).
     *                 Pass [emptyMap] when the blocklist is a flat set (back-compat).
     * @return [MatchResult] carrying the matched suffix plus any metadata, or null.
     */
    fun matchedBlockDetailed(
        name: String,
        blocklist: Set<String>,
        metadata: Map<String, Pair<String?, String?>> = emptyMap(),
    ): MatchResult? {
        val suffix = matchedBlock(name, blocklist) ?: return null
        val (category, source) = metadata[suffix] ?: (null to null)
        return MatchResult(
            suffix = suffix,
            matchScope = if (name == suffix) "exact" else "suffix",
            confidenceScore = null,
            entityNames = emptyList(),
            category = category,
            categories = listOfNotNull(category),
            source = source,
            sources = listOfNotNull(source),
            lightAction = null,
            extremeAction = null,
        )
    }

    fun matchedRuleDetailed(
        name: String,
        exactBlocklist: Set<String>,
        suffixBlocklist: Set<String>,
        metadata: Map<String, RuleMetadata> = emptyMap(),
    ): MatchResult? {
        if (name in exactBlocklist) {
            val ruleMetadata = metadata[metadataKey("exact", name)]
            return MatchResult(
                suffix = name,
                matchScope = "exact",
                registrableDomain = ruleMetadata?.registrableDomain,
                confidenceScore = ruleMetadata?.confidenceScore,
                entityNames = ruleMetadata?.entityNames ?: emptyList(),
                category = ruleMetadata?.category,
                categories = ruleMetadata?.categories ?: emptyList(),
                source = ruleMetadata?.source,
                sources = ruleMetadata?.sources ?: emptyList(),
                confidenceTier = ruleMetadata?.confidenceTier,
                compatibilityTags = ruleMetadata?.compatibilityTags ?: emptyList(),
                reviewNotes = ruleMetadata?.reviewNotes ?: emptyList(),
                lightAction = ruleMetadata?.lightAction,
                extremeAction = ruleMetadata?.extremeAction,
            )
        }

        var idx = name.indexOf('.')
        while (idx >= 0 && idx < name.length - 1) {
            val suffix = name.substring(idx + 1)
            if (suffix in suffixBlocklist) {
                val ruleMetadata = metadata[metadataKey("suffix", suffix)]
                return MatchResult(
                    suffix = suffix,
                    matchScope = "suffix",
                    registrableDomain = ruleMetadata?.registrableDomain,
                    confidenceScore = ruleMetadata?.confidenceScore,
                    entityNames = ruleMetadata?.entityNames ?: emptyList(),
                    category = ruleMetadata?.category,
                    categories = ruleMetadata?.categories ?: emptyList(),
                    source = ruleMetadata?.source,
                    sources = ruleMetadata?.sources ?: emptyList(),
                    confidenceTier = ruleMetadata?.confidenceTier,
                    compatibilityTags = ruleMetadata?.compatibilityTags ?: emptyList(),
                    reviewNotes = ruleMetadata?.reviewNotes ?: emptyList(),
                    lightAction = ruleMetadata?.lightAction,
                    extremeAction = ruleMetadata?.extremeAction,
                )
            }
            idx = name.indexOf('.', idx + 1)
        }

        return null
    }
}
