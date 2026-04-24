package app.choicefirst.cf.cloak

import org.junit.Assert.*
import org.junit.Test

/**
 * JVM unit tests for [PolicyEngine] and [Policy.fromJson].
 */
class PolicyEngineTest {

    private val NOW = 1_700_000_000_000L

    // ── Default policy ────────────────────────────────────────────────────────

    @Test
    fun `blocks matched domain with DEFAULT_BLOCK reason`() {
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com"),
            Policy.DEFAULT,
            NOW,
        )
        assertEquals(PolicyAction.BLOCK, d.action)
        assertEquals(DecisionReason.DEFAULT_BLOCK, d.reason)
    }

    @Test
    fun `allows unmatched domain`() {
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "safe.com", matchedSuffix = null),
            Policy.DEFAULT,
            NOW,
        )
        assertEquals(PolicyAction.ALLOW, d.action)
        assertEquals(DecisionReason.DEFAULT_ALLOW, d.reason)
    }

    // ── Temp allows ───────────────────────────────────────────────────────────

    @Test
    fun `temp allow before expiry overrides block`() {
        val p = Policy(tempAllows = listOf(TempAllow("evil.com", NOW + 60_000)))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com"),
            p, NOW,
        )
        assertEquals(PolicyAction.ALLOW, d.action)
        assertEquals(DecisionReason.TEMP_ALLOW, d.reason)
    }

    @Test
    fun `expired temp allow does not apply`() {
        val p = Policy(tempAllows = listOf(TempAllow("evil.com", NOW - 1)))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com"),
            p, NOW,
        )
        assertEquals(PolicyAction.BLOCK, d.action)
    }

    @Test
    fun `temp allow is case-insensitive`() {
        val p = Policy(tempAllows = listOf(TempAllow("EVIL.COM", NOW + 60_000)))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com"),
            p, NOW,
        )
        assertEquals(DecisionReason.TEMP_ALLOW, d.reason)
    }

    // ── Domain overrides ──────────────────────────────────────────────────────

    @Test
    fun `domain override allow wins over blocklist match`() {
        val p = Policy(domainOverrides = mapOf("evil.com" to PolicyAction.ALLOW))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com"),
            p, NOW,
        )
        assertEquals(PolicyAction.ALLOW, d.action)
        assertEquals(DecisionReason.DOMAIN_OVERRIDE, d.reason)
    }

    @Test
    fun `domain override block wins even when not in blocklist`() {
        val p = Policy(domainOverrides = mapOf("example.com" to PolicyAction.BLOCK))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "www.example.com", matchedSuffix = null),
            p, NOW,
        )
        assertEquals(PolicyAction.BLOCK, d.action)
        assertEquals(DecisionReason.DOMAIN_OVERRIDE, d.reason)
    }

    @Test
    fun `domain override sibling does not match`() {
        val p = Policy(domainOverrides = mapOf("other.evil.com" to PolicyAction.ALLOW))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com"),
            p, NOW,
        )
        // No domain override applies — falls through to default block
        assertEquals(PolicyAction.BLOCK, d.action)
    }

    // ── App overrides ─────────────────────────────────────────────────────────

    @Test
    fun `app override allow bypasses blocklist`() {
        val p = Policy(appOverrides = mapOf("com.browser" to PolicyAction.ALLOW))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com", app = "com.browser"),
            p, NOW,
        )
        assertEquals(PolicyAction.ALLOW, d.action)
        assertEquals(DecisionReason.APP_OVERRIDE, d.reason)
    }

    @Test
    fun `app override ignored when app is null`() {
        val p = Policy(appOverrides = mapOf("com.browser" to PolicyAction.ALLOW))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com", app = null),
            p, NOW,
        )
        assertEquals(PolicyAction.BLOCK, d.action)
    }

    // ── Category rules ────────────────────────────────────────────────────────

    @Test
    fun `category disabled allows matched domain`() {
        val p = Policy(categoryEnabled = mapOf("ads" to false))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com", category = "ads"),
            p, NOW,
        )
        assertEquals(PolicyAction.ALLOW, d.action)
        assertEquals(DecisionReason.CATEGORY_DISABLED, d.reason)
    }

    @Test
    fun `category enabled blocks matched domain even when defaultAction is allow`() {
        val p = Policy(defaultAction = PolicyAction.ALLOW, categoryEnabled = mapOf("ads" to true))
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com", category = "ads"),
            p, NOW,
        )
        assertEquals(PolicyAction.BLOCK, d.action)
        assertEquals(DecisionReason.CATEGORY_BLOCKED, d.reason)
    }

    @Test
    fun `absent category key falls through to defaultAction`() {
        val p = Policy(categoryEnabled = emptyMap())
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com", category = "ads"),
            p, NOW,
        )
        assertEquals(DecisionReason.DEFAULT_BLOCK, d.reason)
    }

    // ── Priority ordering ─────────────────────────────────────────────────────

    @Test
    fun `temp_allow beats domain_override block`() {
        val p = Policy(
            tempAllows = listOf(TempAllow("evil.com", NOW + 60_000)),
            domainOverrides = mapOf("evil.com" to PolicyAction.BLOCK),
        )
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com"),
            p, NOW,
        )
        assertEquals(DecisionReason.TEMP_ALLOW, d.reason)
    }

    @Test
    fun `domain_override beats app_override`() {
        val p = Policy(
            domainOverrides = mapOf("evil.com" to PolicyAction.ALLOW),
            appOverrides = mapOf("com.app" to PolicyAction.BLOCK),
        )
        val d = PolicyEngine.evaluate(
            PolicyRequest(domain = "tracker.evil.com", matchedSuffix = "evil.com", app = "com.app"),
            p, NOW,
        )
        assertEquals(DecisionReason.DOMAIN_OVERRIDE, d.reason)
        assertEquals(PolicyAction.ALLOW, d.action)
    }

    // ── Policy.fromJson ───────────────────────────────────────────────────────

    @Test
    fun `fromJson parses minimal policy`() {
        val json = """{"version":1,"defaultAction":"block"}"""
        val p = Policy.fromJson(json)
        assertEquals(1, p.version)
        assertEquals(PolicyAction.BLOCK, p.defaultAction)
    }

    @Test
    fun `fromJson parses defaultAction allow`() {
        val p = Policy.fromJson("""{"version":1,"defaultAction":"allow"}""")
        assertEquals(PolicyAction.ALLOW, p.defaultAction)
    }

    @Test
    fun `fromJson parses categoryEnabled`() {
        val p = Policy.fromJson("""{"version":1,"categoryEnabled":{"ads":false,"analytics":true}}""")
        assertEquals(false, p.categoryEnabled["ads"])
        assertEquals(true, p.categoryEnabled["analytics"])
    }

    @Test
    fun `fromJson parses appOverrides`() {
        val p = Policy.fromJson("""{"version":1,"appOverrides":{"com.browser":"allow"}}""")
        assertEquals(PolicyAction.ALLOW, p.appOverrides["com.browser"])
    }

    @Test
    fun `fromJson parses domainOverrides`() {
        val p = Policy.fromJson("""{"version":1,"domainOverrides":{"evil.com":"block"}}""")
        assertEquals(PolicyAction.BLOCK, p.domainOverrides["evil.com"])
    }

    @Test
    fun `fromJson parses tempAllows`() {
        val p = Policy.fromJson("""{"version":1,"tempAllows":[{"domain":"evil.com","expiresAt":9999}]}""")
        assertEquals(1, p.tempAllows.size)
        assertEquals("evil.com", p.tempAllows[0].domain)
        assertEquals(9999L, p.tempAllows[0].expiresAt)
    }

    @Test
    fun `fromJson falls back to block on unknown defaultAction`() {
        val p = Policy.fromJson("""{"version":1,"defaultAction":"unknown"}""")
        assertEquals(PolicyAction.BLOCK, p.defaultAction)
    }

    @Test
    fun `fromJson handles missing optional fields gracefully`() {
        val p = Policy.fromJson("""{"version":2}""")
        assertEquals(2, p.version)
        assertEquals(PolicyAction.BLOCK, p.defaultAction)
        assertTrue(p.categoryEnabled.isEmpty())
        assertTrue(p.appOverrides.isEmpty())
        assertTrue(p.domainOverrides.isEmpty())
        assertTrue(p.tempAllows.isEmpty())
    }
}
