package app.choicefirst.eu.cloak

import java.io.ByteArrayInputStream
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

class CfVpnServiceTest {

    @Test
    fun `shouldFlushImmediately turns true at the batch threshold`() {
        assertFalse(CfVpnService.shouldFlushImmediately(499))
        assertTrue(CfVpnService.shouldFlushImmediately(500))
        assertTrue(CfVpnService.shouldFlushImmediately(750))
    }

    @Test
    fun `prepareEventStore prunes raw and daily rows before trimming the ring buffer`() {
        val operations = mutableListOf<String>()
        val store = object : EventStore {
            override fun insert(event: BlockedEvent) = Unit

            override fun query(since: Long, app: String?, limit: Int): List<BlockedEvent> = emptyList()

            override fun appStats(since: Long): List<AppStat> = emptyList()

            override fun dailyStats(since: Long, action: String?): List<DailyEventStat> = emptyList()

            override fun clear() = Unit

            override fun deleteOlderThan(cutoffTs: Long) {
                operations += "prune:$cutoffTs"
            }

            override fun deleteDailyOlderThan(cutoffTs: Long) {
                operations += "prune_daily:$cutoffTs"
            }

            override fun trim(maxRows: Int) {
                operations += "trim:$maxRows"
            }
        }

        val now = 1_716_422_400_000L
        val expectedCutoff = now - TimeUnit.DAYS.toMillis(7)
        val expectedDailyCutoff = startOfLocalDayDaysAgo(now, 29)

        CfVpnService.prepareEventStore(store, now)

        assertEquals(
            listOf("prune:$expectedCutoff", "prune_daily:$expectedDailyCutoff", "trim:10000"),
            operations,
        )
    }

    @Test
    fun `parseSystemAllowlistJson groups exact and suffix entries`() {
        val parsed = CfVpnService.parseSystemAllowlistJson(
            """
            [
              {"domain":"api.example.com","match_scope":"exact"},
              {"domain":"example.com","match_scope":"suffix"},
              {"domain":"  ","match_scope":"exact"}
            ]
            """.trimIndent(),
        )

        assertNotNull(parsed)
        assertEquals(setOf("api.example.com"), parsed!!.exactDomains)
        assertEquals(setOf("example.com"), parsed.suffixDomains)
    }

    @Test
    fun `parseRuleBundleJson keeps source, category, compatibility, score, notes, and entity metadata`() {
                val parsed = CfVpnService.parseRuleBundleJson(
                        """
                        [
                            {
                                "domain":"example.com",
                                "match_scope":"suffix",
                                "registrable_domain":"example.com",
                                "entity_names":["Branch Metrics","Branch Metrics, Inc."],
                                "confidence_score":0.95,
                                "category":"tracking",
                                "categories":["tracking","analytics"],
                                "source":"oisd_small",
                                "sources":["oisd_small","ddg_tracker_blocklists"],
                                "confidence_tier":"high",
                                "compatibility_tags":["auth","app_api"],
                                "review_notes":["ddg_default:block","compatibility:core auth"],
                                "light_action":"observe",
                                "extreme_action":"block"
                            }
                        ]
                        """.trimIndent(),
                )

                val metadata = parsed?.metadata?.get("suffix:example.com")
                assertNotNull(metadata)
        assertEquals("tracking", metadata?.category)
        assertEquals(listOf("tracking", "analytics"), metadata?.categories)
            assertEquals("example.com", metadata?.registrableDomain)
                assertEquals(listOf("Branch Metrics", "Branch Metrics, Inc."), metadata?.entityNames)
                assertEquals(0.95, metadata?.confidenceScore ?: 0.0, 0.0001)
                assertEquals("oisd_small", metadata?.source)
                assertEquals(listOf("oisd_small", "ddg_tracker_blocklists"), metadata?.sources)
                assertEquals("high", metadata?.confidenceTier)
                assertEquals(listOf("auth", "app_api"), metadata?.compatibilityTags)
                assertEquals(listOf("ddg_default:block", "compatibility:core auth"), metadata?.reviewNotes)
    }

    @Test
    fun `matchesSystemAllowlist checks exact and suffix domains`() {
        assertTrue(
            CfVpnService.matchesSystemAllowlist(
                domain = "api.example.com",
                exactDomains = setOf("api.example.com"),
                suffixDomains = setOf("example.com"),
            ),
        )

        assertTrue(
            CfVpnService.matchesSystemAllowlist(
                domain = "cdn.example.com",
                exactDomains = emptySet(),
                suffixDomains = setOf("example.com"),
            ),
        )

        assertFalse(
            CfVpnService.matchesSystemAllowlist(
                domain = "safe.test",
                exactDomains = setOf("api.example.com"),
                suffixDomains = setOf("example.com"),
            ),
        )
    }

    @Test
    fun `buildRemoteBlockedEvent keeps minimized remote fields only`() {
        val remoteEvent = CfVpnService.buildRemoteBlockedEvent(
            eventId = "evt-123",
            matched = "Tracker.Example.com",
            matchResult = MatchResult(
                suffix = "tracker.example.com",
                registrableDomain = "example.com",
                category = "tracking",
                source = "oisd_small",
                lightAction = ModeAction.BLOCK,
                extremeAction = ModeAction.BLOCK,
            ),
            blocklistVersion = "ruleset-2026-05-23",
            occurredAt = "2026-05-23T00:00:00Z",
        )

        assertNotNull(remoteEvent)
        assertEquals("evt-123", remoteEvent?.eventId)
        assertEquals("tracker.example.com", remoteEvent?.matchedDomain)
        assertEquals("example.com", remoteEvent?.registrableDomain)
        assertEquals("ruleset-2026-05-23", remoteEvent?.blocklistVersion)
        assertEquals("2026-05-23T00:00:00Z", remoteEvent?.occurredAt)
    }

    @Test
    fun `buildRemoteBlockedEvent returns null when event id is blank`() {
        val remoteEvent = CfVpnService.buildRemoteBlockedEvent(
            eventId = "   ",
            matched = "tracker.example.com",
            matchResult = null,
            blocklistVersion = "ruleset-2026-05-23",
            occurredAt = "2026-05-23T00:00:00Z",
        )

        assertNull(remoteEvent)
    }

    @Test
    fun `buildRemoteBlockedEvent returns null when matched domain is blank`() {
        val remoteEvent = CfVpnService.buildRemoteBlockedEvent(
            eventId = "evt-123",
            matched = "   ",
            matchResult = null,
            blocklistVersion = "ruleset-2026-05-23",
            occurredAt = "2026-05-23T00:00:00Z",
        )

        assertNull(remoteEvent)
    }

    @Test
    fun `buildRemoteBlockedEventsBody uses explicit minimized field names`() {
        val body = CfVpnService.buildRemoteBlockedEventsBody(
            listOf(
                CfVpnService.RemoteBlockedEvent(
                    eventId = "evt-123",
                    matchedDomain = "tracker.example.com",
                    registrableDomain = "example.com",
                    blocklistVersion = "ruleset-2026-05-23",
                    occurredAt = "2026-05-23T00:00:00Z",
                ),
                CfVpnService.RemoteBlockedEvent(
                    eventId = "evt-456",
                    matchedDomain = "pixel.example.net",
                    registrableDomain = null,
                    blocklistVersion = null,
                    occurredAt = "2026-05-23T00:01:00Z",
                ),
            ),
        )

        assertTrue(body.contains("\"event_id\":\"evt-123\""))
        assertTrue(body.contains("\"matched_domain\":\"tracker.example.com\""))
        assertTrue(body.contains("\"registrable_domain\":\"example.com\""))
        assertTrue(body.contains("\"blocklist_version\":\"ruleset-2026-05-23\""))
        assertTrue(body.contains("\"matched_domain\":\"pixel.example.net\""))
        assertFalse(body.contains("\"domain\":\"pixel.example.net\""))
    }

    @Test
    fun `buildCompressedRemoteBlockedEventsPayload gzips the request body`() {
        val body = CfVpnService.buildRemoteBlockedEventsBody(
            listOf(
                CfVpnService.RemoteBlockedEvent(
                    eventId = "evt-123",
                    matchedDomain = "tracker.example.com",
                    registrableDomain = "example.com",
                    blocklistVersion = "ruleset-2026-05-23",
                    occurredAt = "2026-05-23T00:00:00Z",
                ),
            ),
        )

        val compressed = CfVpnService.buildCompressedRemoteBlockedEventsPayload(body)
        val decompressed = GZIPInputStream(ByteArrayInputStream(compressed)).bufferedReader(Charsets.UTF_8).use { it.readText() }

        assertEquals(body, decompressed)
    }

    @Test
    fun `local event mapping preserves observed and override semantics`() {
        val observed = Decision(
            action = PolicyAction.ALLOW,
            effect = DecisionEffect.OBSERVE,
            reason = DecisionReason.RULE_OBSERVE,
        )
        val override = Decision(
            action = PolicyAction.ALLOW,
            effect = DecisionEffect.ALLOW,
            reason = DecisionReason.SYSTEM_ALLOWLIST,
        )

        assertEquals("observed", CfVpnService.localEventAction(observed))
        assertEquals("observed_light", CfVpnService.localEventReason(observed, EnforcementMode.LIGHT))
        assertEquals("allowed_override", CfVpnService.localEventAction(override))
        assertEquals("system_allowlist", CfVpnService.localEventReason(override, EnforcementMode.LIGHT))
    }

    @Test
    fun `local event mapping preserves blocked and temp semantics`() {
        val blocked = Decision(
            action = PolicyAction.BLOCK,
            effect = DecisionEffect.BLOCK,
            reason = DecisionReason.RULE_BLOCK,
        )
        val tempAllow = Decision(
            action = PolicyAction.ALLOW,
            effect = DecisionEffect.ALLOW,
            reason = DecisionReason.TEMP_ALLOW,
        )

        assertEquals("blocked", CfVpnService.localEventAction(blocked))
        assertEquals("auto_block_extreme", CfVpnService.localEventReason(blocked, EnforcementMode.EXTREME))
        assertEquals("allowed_temp", CfVpnService.localEventAction(tempAllow))
        assertEquals("temp_unblock", CfVpnService.localEventReason(tempAllow, EnforcementMode.LIGHT))
    }

    @Test
    fun `evaluateHostnameRequest uses the same matched pipeline for observed requests`() {
        val evaluation = CfVpnService.evaluateHostnameRequest(
            domain = "tracker.example.com",
            app = "com.example.browser",
            matchResult = MatchResult(
                suffix = "example.com",
                category = "tracking",
                source = "oisd_small",
                lightAction = ModeAction.OBSERVE,
                extremeAction = ModeAction.BLOCK,
            ),
            policy = Policy.DEFAULT,
            exactSystemAllowlist = emptySet(),
            suffixSystemAllowlist = emptySet(),
        )

        assertEquals("com.example.browser", evaluation.app)
        assertEquals("example.com", evaluation.matchResult?.suffix)
        assertEquals(EnforcementMode.LIGHT, evaluation.policyRequest.mode)
        assertEquals(PolicyAction.ALLOW, evaluation.decision.action)
        assertEquals(DecisionEffect.OBSERVE, evaluation.decision.effect)
        assertEquals(DecisionReason.RULE_OBSERVE, evaluation.decision.reason)
    }

    @Test
    fun `evaluateHostnameRequest carries system allowlist through the shared pipeline`() {
        val evaluation = CfVpnService.evaluateHostnameRequest(
            domain = "api.example.com",
            app = "com.example.browser",
            matchResult = MatchResult(
                suffix = "example.com",
                category = "tracking",
                source = "oisd_small",
                lightAction = ModeAction.BLOCK,
                extremeAction = ModeAction.BLOCK,
            ),
            policy = Policy.DEFAULT,
            exactSystemAllowlist = setOf("api.example.com"),
            suffixSystemAllowlist = emptySet(),
        )

        assertTrue(evaluation.policyRequest.systemAllowlisted)
        assertEquals(DecisionReason.SYSTEM_ALLOWLIST, evaluation.decision.reason)
        assertEquals(PolicyAction.ALLOW, evaluation.decision.action)
    }

    @Test
    fun `evaluateShadowHostnameRequest records light and extreme would-block outcomes`() {
        val shadowTelemetry = CfVpnService.evaluateShadowHostnameRequest(
            domain = "tracker.example.com",
            app = "com.example.browser",
            matchResult = MatchResult(
                suffix = "example.com",
                category = "tracking",
                source = "oisd_small",
                lightAction = ModeAction.OBSERVE,
                extremeAction = ModeAction.BLOCK,
            ),
            policy = Policy.DEFAULT,
            exactSystemAllowlist = emptySet(),
            suffixSystemAllowlist = emptySet(),
        )

        assertNotNull(shadowTelemetry)
        assertFalse(shadowTelemetry!!.wouldBlockLight)
        assertTrue(shadowTelemetry.wouldBlockExtreme)
        assertEquals("example.com", shadowTelemetry.matchResult.suffix)
    }

    @Test
    fun `evaluateShadowHostnameRequest respects the staged system allowlist`() {
        val shadowTelemetry = CfVpnService.evaluateShadowHostnameRequest(
            domain = "api.example.com",
            app = "com.example.browser",
            matchResult = MatchResult(
                suffix = "example.com",
                category = "tracking",
                source = "oisd_small",
                lightAction = ModeAction.BLOCK,
                extremeAction = ModeAction.BLOCK,
            ),
            policy = Policy.DEFAULT,
            exactSystemAllowlist = setOf("api.example.com"),
            suffixSystemAllowlist = emptySet(),
        )

        assertNotNull(shadowTelemetry)
        assertFalse(shadowTelemetry!!.wouldBlockLight)
        assertFalse(shadowTelemetry.wouldBlockExtreme)
    }
}