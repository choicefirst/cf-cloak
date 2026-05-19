package app.choicefirst.eu.cloak

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

/**
 * JVM unit tests for [SignatureVerifier] and [SignatureVerifier.buildPayload].
 *
 * These tests generate an ephemeral Ed25519 keypair so they are fully
 * self-contained and never depend on the committed private key.
 */
class SignatureVerifierTest {

    companion object {
        // Ephemeral keypair for all tests in this class
        private val KEY_PAIR = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        private val PUB_KEY_PEM: String = run {
            val encoded = Base64.getEncoder().encodeToString(KEY_PAIR.public.encoded)
            "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----"
        }

        private val NOW_SEC = System.currentTimeMillis() / 1000L

        private fun sign(version: String, domains: List<String>, issuedAt: Long): String {
            val payload = SignatureVerifier.buildPayload(version, domains, issuedAt)
            val sig = Signature.getInstance("Ed25519")
            sig.initSign(KEY_PAIR.private)
            sig.update(payload.toByteArray(Charsets.UTF_8))
            val raw = sig.sign()
            // base64url, no padding
            return Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        }
    }

    // ── buildPayload ──────────────────────────────────────────────────────────

    @Test
    fun `buildPayload is deterministic regardless of domain order`() {
        val a = SignatureVerifier.buildPayload("v1", listOf("b.com", "a.com"), 0)
        val b = SignatureVerifier.buildPayload("v1", listOf("a.com", "b.com"), 0)
        assertEquals(a, b)
    }

    @Test
    fun `buildPayload contains version and issuedAt`() {
        val p = SignatureVerifier.buildPayload("v42", listOf("x.com"), 99999)
        assertTrue(p.startsWith("v42:"))
        assertTrue(p.endsWith(":99999"))
    }

    @Test
    fun `buildPayload changes with domain list`() {
        val a = SignatureVerifier.buildPayload("v1", listOf("evil.com"), 0)
        val b = SignatureVerifier.buildPayload("v1", listOf("good.com"), 0)
        assertNotEquals(a, b)
    }

    @Test
    fun `buildPayload normalises domain to lowercase`() {
        val a = SignatureVerifier.buildPayload("v1", listOf("EVIL.COM"), 0)
        val b = SignatureVerifier.buildPayload("v1", listOf("evil.com"), 0)
        assertEquals(a, b)
    }

    // ── verify ────────────────────────────────────────────────────────────────

    @Test
    fun `valid signature verifies`() {
        val domains = listOf("evil.com", "tracker.example.com")
        val sig = sign("v1", domains, NOW_SEC)
        assertTrue(SignatureVerifier.verify("v1", domains, NOW_SEC, sig, PUB_KEY_PEM, Long.MAX_VALUE, NOW_SEC))
    }

    @Test
    fun `tampered domain list fails`() {
        val domains = listOf("evil.com")
        val sig = sign("v1", domains, NOW_SEC)
        assertFalse(SignatureVerifier.verify("v1", listOf("injected.com"), NOW_SEC, sig, PUB_KEY_PEM, Long.MAX_VALUE, NOW_SEC))
    }

    @Test
    fun `tampered version fails`() {
        val domains = listOf("evil.com")
        val sig = sign("v1", domains, NOW_SEC)
        assertFalse(SignatureVerifier.verify("v99", domains, NOW_SEC, sig, PUB_KEY_PEM, Long.MAX_VALUE, NOW_SEC))
    }

    @Test
    fun `tampered issuedAt fails`() {
        val domains = listOf("evil.com")
        val sig = sign("v1", domains, NOW_SEC)
        assertFalse(SignatureVerifier.verify("v1", domains, NOW_SEC - 1, sig, PUB_KEY_PEM, Long.MAX_VALUE, NOW_SEC))
    }

    @Test
    fun `truncated signature returns false`() {
        val domains = listOf("evil.com")
        assertFalse(SignatureVerifier.verify("v1", domains, NOW_SEC, "AAAA", PUB_KEY_PEM, Long.MAX_VALUE, NOW_SEC))
    }

    @Test
    fun `expired signature is rejected`() {
        val domains = listOf("evil.com")
        val oldIssuedAt = NOW_SEC - 8L * 24 * 3600 // 8 days ago
        val sig = sign("v1", domains, oldIssuedAt)
        assertFalse(SignatureVerifier.verify("v1", domains, oldIssuedAt, sig, PUB_KEY_PEM, 7L * 24 * 3600, NOW_SEC))
    }

    @Test
    fun `fresh signature within maxAgeSeconds passes`() {
        val domains = listOf("evil.com")
        val issuedAt = NOW_SEC - 3600 // 1 hour ago
        val sig = sign("v1", domains, issuedAt)
        assertTrue(SignatureVerifier.verify("v1", domains, issuedAt, sig, PUB_KEY_PEM, 7L * 24 * 3600, NOW_SEC))
    }
}
