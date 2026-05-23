package app.choicefirst.eu.cloak

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Verifies Ed25519 blocklist signatures produced by the Supabase signing service.
 *
 * The corresponding private key is held exclusively by the Supabase Edge Function
 * and is never present in this library or in any shipped artifact.
 *
 * Wire format (matches signing.ts):
 *   "<version>:<sha256hex-of-sorted-domains>:<issuedAt-epoch-seconds>"
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
object SignatureVerifier {

    /**
     * Verify a blocklist signature.
     *
     * @param version          Blocklist version string.
     * @param domains          Domain list (order does not matter — sorted internally).
     * @param issuedAt         Unix epoch seconds at which the signature was issued.
     * @param signatureBase64Url Ed25519 signature, base64url-encoded (no padding).
     * @param publicKeySpkiPem SPKI PEM of the committed public key.
     * @param maxAgeSeconds    Maximum acceptable age of the signature (default: 7 days).
     *                         Pass [Long.MAX_VALUE] to disable expiry check (tests only).
     * @param nowSeconds       Current epoch seconds (injectable for deterministic testing).
     * @return true only when the signature is valid and not expired.
     */
    @JvmOverloads
    fun verify(
        version: String,
        domains: List<String>,
        issuedAt: Long,
        signatureBase64Url: String,
        publicKeySpkiPem: String,
        maxAgeSeconds: Long = 7L * 24 * 3600,
        nowSeconds: Long = System.currentTimeMillis() / 1000L,
    ): Boolean {
        // 1. Expiry check
        if (maxAgeSeconds != Long.MAX_VALUE && nowSeconds - issuedAt > maxAgeSeconds) return false

        // 2. Build canonical payload (must match signing.ts buildSignaturePayload exactly)
        val payload = buildPayload(version, domains, issuedAt)

        // 3. Decode public key
        val pubKey = try {
            val pemBody = publicKeySpkiPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\\s".toRegex(), "")
            val keyBytes = Base64.getDecoder().decode(pemBody)
            val spec = X509EncodedKeySpec(keyBytes)
            KeyFactory.getInstance("Ed25519").generatePublic(spec)
        } catch (_: Exception) {
            return false
        }

        // 4. Decode signature (base64url without padding)
        val sigBytes = try {
            val padded = signatureBase64Url
                .replace('-', '+')
                .replace('_', '/')
                .let { s ->
                    when (s.length % 4) {
                        2 -> "$s=="
                        3 -> "$s="
                        else -> s
                    }
                }
            Base64.getDecoder().decode(padded)
        } catch (_: Exception) {
            return false
        }

        // 5. Verify
        return try {
            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(pubKey)
            sig.update(payload.toByteArray(Charsets.UTF_8))
            sig.verify(sigBytes)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Build the canonical payload string that is signed.
     * Mirrors [buildSignaturePayload] in cf-cloak/src/signing.ts.
     */
    internal fun buildPayload(version: String, domains: List<String>, issuedAt: Long): String {
        val sorted = domains.map { it.lowercase().trim() }.sorted()
        val joined = sorted.joinToString("\n")
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(joined.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        return "$version:$hash:$issuedAt"
    }
}
