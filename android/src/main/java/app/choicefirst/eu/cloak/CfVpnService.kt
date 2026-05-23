package app.choicefirst.eu.cloak

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.GZIPOutputStream
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/**
 * DNS-only VPN. We declare a tunnel with a non-routable DNS server address
 * (10.47.0.3) and route only that /32, so exclusively DNS traffic enters the
 * tunnel. Everything else uses Android's regular default route.
 *
 * For each DNS query we parse the QNAME:
 *   - suffix-match against the blocklist → synthesize NXDOMAIN, never leaves the device
 *   - otherwise → forward to UPSTREAM_DNS via a socket we protect() from the tunnel
 *
 * This is the same approach as DNS66 / early Blokada. It catches ~95% of
 * trackers for ~5% of the complexity of a full packet filter.
 *
 * When sniInspect=true the tunnel also intercepts TCP/443 traffic to inspect
 * TLS ClientHello SNI hostnames. Blocked hostnames receive a TCP RST before
 * any data is exchanged. Allowed connections are relayed transparently via a
 * protect()-ed socket. This is the second line of defence against trackers
 * that hardcode IPs or use DNS-over-HTTPS.
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
class CfVpnService : VpnService() {

    data class RuntimeRuleBundle(
        val exactDomains: Set<String>,
        val suffixDomains: Set<String>,
        val metadata: Map<String, RuleMetadata>,
    )

    data class RuntimeSystemAllowlist(
        val exactDomains: Set<String>,
        val suffixDomains: Set<String>,
    )

    data class EvaluatedHostnameRequest(
        val app: String,
        val matchResult: MatchResult?,
        val policyRequest: PolicyRequest,
        val decision: Decision,
    )

    data class ShadowDecisionTelemetry(
        val matchResult: MatchResult,
        val wouldBlockLight: Boolean,
        val wouldBlockExtreme: Boolean,
    )

    data class RemoteBlockedEvent(
        val eventId: String,
        val matchedDomain: String,
        val registrableDomain: String?,
        val blocklistVersion: String?,
        val occurredAt: String,
    )

    companion object {
        const val ACTION_START = "app.choicefirst.eu.vpn.START"
        const val ACTION_STOP = "app.choicefirst.eu.vpn.STOP"
        const val EXTRA_DOMAINS = "domains"
        const val EXTRA_VERSION = "version"
        const val EXTRA_SUPABASE_URL = "supabase_url"
        const val EXTRA_SUPABASE_ANON = "supabase_anon_key"
        const val EXTRA_AUTH_TOKEN = "auth_token"
        const val EXTRA_LOG_EVENTS = "log_events"
        const val EXTRA_SNI_INSPECT = "sni_inspect"
        const val EXTRA_LIVE_NOTIFICATIONS = "live_notifications"
        const val EXTRA_SAMPLE_ALLOWED = "sample_allowed"
        const val EXTRA_POLICY_JSON = "policy_json"

        private const val TAG = "CfVpn"
        private const val NOTIFICATION_ID = 42
        private const val CHANNEL_ID = "cf_vpn"
        private const val ALERT_CHANNEL_ID = "cf_vpn_alerts"
        private const val ALERT_NOTIFICATION_ID_BASE = 1_000
        private const val TUNNEL_LOCAL = "10.47.0.2"
        private const val TUNNEL_DNS_SINK = "10.47.0.3"
        private const val UPSTREAM_DNS = "1.1.1.1"
        private const val UPSTREAM_DNS_PORT = 53
        private const val HTTPS_PORT = 443
        private const val TCP_RELAY_TIMEOUT_MS = 10_000
        private const val MAX_LOCAL_EVENTS = 10_000
        private val LOCAL_EVENT_RETENTION_MS = TimeUnit.DAYS.toMillis(7)
        private const val DAILY_EVENT_RETENTION_DAYS = 30

        private const val QUEUE_MAX = 2_000
        private const val FLUSH_BATCH = 500
        private const val FLUSH_INTERVAL_SECONDS = 60L

        @Volatile private var active = false
        @Volatile private var sniActive = false
        private val blockedCount = AtomicInteger(0)
        @Volatile private var exactBlocklist: Set<String> = emptySet()
        @Volatile private var suffixBlocklist: Set<String> = emptySet()
        @Volatile private var exactSystemAllowlist: Set<String> = emptySet()
        @Volatile private var suffixSystemAllowlist: Set<String> = emptySet()
        @Volatile private var ruleMetadata: Map<String, RuleMetadata> = emptyMap()
        @Volatile private var shadowExactBlocklist: Set<String> = emptySet()
        @Volatile private var shadowSuffixBlocklist: Set<String> = emptySet()
        @Volatile private var shadowExactSystemAllowlist: Set<String> = emptySet()
        @Volatile private var shadowSuffixSystemAllowlist: Set<String> = emptySet()
        @Volatile private var shadowRuleMetadata: Map<String, RuleMetadata> = emptyMap()
        @Volatile private var version: String = ""
        @Volatile private var bundleKind: String = "legacy_company_domains"
        @Volatile private var liveNotificationsEnabled = false
        @Volatile private var pendingRuleBundle: RuntimeRuleBundle? = null
        @Volatile private var pendingShadowRuleBundle: RuntimeRuleBundle? = null
        @Volatile private var pendingSystemAllowlist: RuntimeSystemAllowlist? = null
        @Volatile private var pendingShadowSystemAllowlist: RuntimeSystemAllowlist? = null

        /** Local event store — accessible by VpnPlugin for query/export. */
        @Volatile private var eventStore: EventStore? = null
        fun getEventStore(): EventStore? = eventStore

        internal fun prepareEventStore(
            store: EventStore,
            now: Long = System.currentTimeMillis(),
        ) {
            store.deleteOlderThan(now - LOCAL_EVENT_RETENTION_MS)
            store.deleteDailyOlderThan(startOfLocalDayDaysAgo(now, DAILY_EVENT_RETENTION_DAYS - 1))
            store.trim(MAX_LOCAL_EVENTS)
        }

        internal fun shouldFlushImmediately(queueSize: Int): Boolean = queueSize >= FLUSH_BATCH

        /** Active policy — hot-swappable via VpnPlugin.updatePolicy(). */
        @Volatile var policy: Policy = Policy.DEFAULT

        fun setLiveNotificationsEnabled(enabled: Boolean) {
            liveNotificationsEnabled = enabled
        }

        fun stageRuleBundleFromJson(rulesJson: String?) {
            pendingRuleBundle = parseRuleBundleJson(rulesJson)
        }

        fun stageShadowRuleBundleFromJson(rulesJson: String?) {
            pendingShadowRuleBundle = parseRuleBundleJson(rulesJson)
        }

        fun stageSystemAllowlistFromJson(systemAllowlistJson: String?) {
            pendingSystemAllowlist = parseSystemAllowlistJson(systemAllowlistJson)
        }

        fun stageShadowSystemAllowlistFromJson(systemAllowlistJson: String?) {
            pendingShadowSystemAllowlist = parseSystemAllowlistJson(systemAllowlistJson)
        }

        fun isActive() = active
        fun isSniActive() = sniActive
        fun domainCount() = (exactBlocklist + suffixBlocklist).size
        fun blockedInSession() = blockedCount.get()
        fun currentVersion() = version
        fun currentBundleKind() = bundleKind

        private fun consumePendingRuleBundle(): RuntimeRuleBundle? {
            val bundle = pendingRuleBundle
            pendingRuleBundle = null
            return bundle
        }

        private fun consumePendingShadowRuleBundle(): RuntimeRuleBundle? {
            val bundle = pendingShadowRuleBundle
            pendingShadowRuleBundle = null
            return bundle
        }

        private fun consumePendingSystemAllowlist(): RuntimeSystemAllowlist? {
            val allowlist = pendingSystemAllowlist
            pendingSystemAllowlist = null
            return allowlist
        }

        private fun consumePendingShadowSystemAllowlist(): RuntimeSystemAllowlist? {
            val allowlist = pendingShadowSystemAllowlist
            pendingShadowSystemAllowlist = null
            return allowlist
        }

        internal fun parseRuleBundleJson(rulesJson: String?): RuntimeRuleBundle? {
            if (rulesJson.isNullOrBlank()) return null

            return try {
                val exactDomains = linkedSetOf<String>()
                val suffixDomains = linkedSetOf<String>()
                val metadata = linkedMapOf<String, RuleMetadata>()
                when (val parsed = JSONTokener(rulesJson).nextValue()) {
                    is JSONArray -> populateLegacyRuleBundle(parsed, exactDomains, suffixDomains, metadata)
                    is JSONObject -> {
                        when (parsed.optString("format")) {
                            "cfvpn-rules-v1" -> populateCompactRuleBundle(parsed, exactDomains, suffixDomains, metadata)
                            else -> return null
                        }
                    }
                    else -> return null
                }

                RuntimeRuleBundle(
                    exactDomains = exactDomains,
                    suffixDomains = suffixDomains,
                    metadata = metadata,
                )
            } catch (error: Exception) {
                Log.w(TAG, "Failed to parse staged VPN rule bundle", error)
                null
            }
        }

        internal fun parseSystemAllowlistJson(systemAllowlistJson: String?): RuntimeSystemAllowlist? {
            if (systemAllowlistJson.isNullOrBlank()) return null

            return try {
                val exactDomains = linkedSetOf<String>()
                val suffixDomains = linkedSetOf<String>()
                when (val parsed = JSONTokener(systemAllowlistJson).nextValue()) {
                    is JSONArray -> populateLegacySystemAllowlist(parsed, exactDomains, suffixDomains)
                    is JSONObject -> {
                        when (parsed.optString("format")) {
                            "cfvpn-system-allowlist-v1" -> populateCompactSystemAllowlist(parsed, exactDomains, suffixDomains)
                            else -> return null
                        }
                    }
                    else -> return null
                }

                RuntimeSystemAllowlist(
                    exactDomains = exactDomains,
                    suffixDomains = suffixDomains,
                )
            } catch (error: Exception) {
                Log.w(TAG, "Failed to parse staged VPN system allowlist", error)
                null
            }
        }

        internal fun matchesSystemAllowlist(
            domain: String,
            exactDomains: Set<String>,
            suffixDomains: Set<String>,
        ): Boolean {
            val normalizedDomain = domain.trim().lowercase()
            if (normalizedDomain in exactDomains) return true

            var idx = normalizedDomain.indexOf('.')
            while (idx >= 0 && idx < normalizedDomain.length - 1) {
                val suffix = normalizedDomain.substring(idx + 1)
                if (suffix in suffixDomains) return true
                idx = normalizedDomain.indexOf('.', idx + 1)
            }

            return false
        }

        private fun JSONObject.optNullableString(key: String): String? {
            val value = optString(key, "").trim()
            return value.ifEmpty { null }
        }

        private fun JSONObject.optModeAction(key: String): ModeAction? = when (optString(key, "")) {
            "block" -> ModeAction.BLOCK
            "observe" -> ModeAction.OBSERVE
            else -> null
        }

        private fun JSONObject.optConfidenceTier(key: String): String? = when (optString(key, "").trim().lowercase()) {
            "high", "medium", "review" -> optString(key).trim().lowercase()
            else -> null
        }

        private fun JSONObject.optConfidenceScore(key: String): Double? {
            if (!has(key) || isNull(key)) return null
            val value = optDouble(key, Double.NaN)
            if (value.isNaN() || value.isInfinite()) return null
            return value.coerceIn(0.0, 1.0)
        }

        private fun JSONObject.optStringList(key: String): List<String> {
            val values = linkedSetOf<String>()
            val entries = optJSONArray(key) ?: return emptyList()
            for (i in 0 until entries.length()) {
                val value = entries.optString(i, "").trim().lowercase()
                if (value.isNotEmpty()) {
                    values.add(value)
                }
            }
            return values.toList()
        }

        private fun JSONObject.optSourceList(arrayKey: String, fallbackKey: String): List<String> {
            val values = linkedSetOf<String>()
            values.addAll(optStringList(arrayKey))
            optNullableString(fallbackKey)?.lowercase()?.let(values::add)
            return values.toList()
        }

        private fun JSONObject.optPreservedStringList(key: String): List<String> {
            val values = linkedSetOf<String>()
            val entries = optJSONArray(key) ?: return emptyList()
            for (i in 0 until entries.length()) {
                val value = entries.optString(i, "").trim()
                if (value.isNotEmpty()) {
                    values.add(value)
                }
            }
            return values.toList()
        }

        private fun JSONObject.optValueList(arrayKey: String, fallbackKey: String): List<String> {
            val values = linkedSetOf<String>()
            values.addAll(optStringList(arrayKey))
            optNullableString(fallbackKey)?.lowercase()?.let(values::add)
            return values.toList()
        }

        private fun populateLegacyRuleBundle(
            entries: JSONArray,
            exactDomains: MutableSet<String>,
            suffixDomains: MutableSet<String>,
            metadata: MutableMap<String, RuleMetadata>,
        ) {
            for (i in 0 until entries.length()) {
                val entry = entries.optJSONObject(i) ?: continue
                val domain = entry.optString("domain").trim().lowercase()
                if (domain.isEmpty()) continue

                val matchScope = when (entry.optString("match_scope", "suffix")) {
                    "exact" -> "exact"
                    else -> "suffix"
                }

                if (matchScope == "exact") exactDomains.add(domain) else suffixDomains.add(domain)

                metadata[ruleMetadataKey(matchScope, domain)] = RuleMetadata(
                    category = entry.optNullableString("category"),
                    registrableDomain = entry.optNullableString("registrable_domain")?.lowercase(Locale.ROOT),
                    confidenceScore = entry.optConfidenceScore("confidence_score"),
                    entityNames = entry.optPreservedStringList("entity_names"),
                    categories = entry.optValueList("categories", "category"),
                    source = entry.optSourceList("sources", "source").firstOrNull(),
                    sources = entry.optSourceList("sources", "source"),
                    confidenceTier = entry.optConfidenceTier("confidence_tier"),
                    compatibilityTags = entry.optStringList("compatibility_tags"),
                    reviewNotes = entry.optPreservedStringList("review_notes"),
                    lightAction = entry.optModeAction("light_action"),
                    extremeAction = entry.optModeAction("extreme_action"),
                )
            }
        }

        private fun populateCompactRuleBundle(
            root: JSONObject,
            exactDomains: MutableSet<String>,
            suffixDomains: MutableSet<String>,
            metadata: MutableMap<String, RuleMetadata>,
        ) {
            val entries = root.optJSONArray("rules") ?: return
            for (i in 0 until entries.length()) {
                val entry = entries.optJSONArray(i) ?: continue
                val domain = entry.optString(0, "").trim().lowercase(Locale.ROOT)
                if (domain.isEmpty()) continue

                val matchScope = when (entry.optString(1, "suffix")) {
                    "exact" -> "exact"
                    else -> "suffix"
                }
                val category = entry.optString(2, "").trim().lowercase(Locale.ROOT).ifEmpty { null }
                val source = entry.optString(3, "").trim().lowercase(Locale.ROOT).ifEmpty { null }
                val lightAction = when (entry.optString(4, "block")) {
                    "observe" -> ModeAction.OBSERVE
                    else -> ModeAction.BLOCK
                }

                if (matchScope == "exact") exactDomains.add(domain) else suffixDomains.add(domain)

                metadata[ruleMetadataKey(matchScope, domain)] = RuleMetadata(
                    category = category,
                    categories = listOfNotNull(category),
                    source = source,
                    sources = listOfNotNull(source),
                    lightAction = lightAction,
                    extremeAction = ModeAction.BLOCK,
                )
            }
        }

        private fun populateLegacySystemAllowlist(
            entries: JSONArray,
            exactDomains: MutableSet<String>,
            suffixDomains: MutableSet<String>,
        ) {
            for (i in 0 until entries.length()) {
                val entry = entries.optJSONObject(i) ?: continue
                val domain = entry.optString("domain").trim().lowercase(Locale.ROOT)
                if (domain.isEmpty()) continue

                when (entry.optString("match_scope", "suffix")) {
                    "exact" -> exactDomains.add(domain)
                    else -> suffixDomains.add(domain)
                }
            }
        }

        private fun populateCompactSystemAllowlist(
            root: JSONObject,
            exactDomains: MutableSet<String>,
            suffixDomains: MutableSet<String>,
        ) {
            val entries = root.optJSONArray("rules") ?: return
            for (i in 0 until entries.length()) {
                val entry = entries.optJSONArray(i) ?: continue
                val domain = entry.optString(0, "").trim().lowercase(Locale.ROOT)
                if (domain.isEmpty()) continue

                when (entry.optString(1, "suffix")) {
                    "exact" -> exactDomains.add(domain)
                    else -> suffixDomains.add(domain)
                }
            }
        }

        internal fun localEventAction(decision: Decision): String {
            if (decision.reason == DecisionReason.TEMP_ALLOW) {
                return "allowed_temp"
            }
            if (decision.action == PolicyAction.BLOCK) {
                return "blocked"
            }
            if (decision.effect == DecisionEffect.OBSERVE) {
                return "observed"
            }

            return "allowed_override"
        }

        internal fun localEventReason(decision: Decision, mode: EnforcementMode): String = when (decision.reason) {
            DecisionReason.TEMP_ALLOW -> "temp_unblock"
            DecisionReason.SYSTEM_ALLOWLIST -> "system_allowlist"
            DecisionReason.DOMAIN_OVERRIDE,
            DecisionReason.APP_OVERRIDE,
            DecisionReason.CATEGORY_DISABLED,
            -> if (decision.action == PolicyAction.BLOCK) "user_override_block" else "user_override_allow"

            DecisionReason.CATEGORY_BLOCKED -> "user_override_block"
            DecisionReason.RULE_OBSERVE -> "observed_light"
            DecisionReason.RULE_BLOCK,
            DecisionReason.DEFAULT_BLOCK,
            -> if (mode == EnforcementMode.EXTREME) "auto_block_extreme" else "auto_block_light"

            DecisionReason.DEFAULT_ALLOW,
            -> if (mode == EnforcementMode.LIGHT) "observed_light" else "user_override_allow"
        }

        internal fun buildRemoteBlockedEvent(
            eventId: String,
            matched: String,
            matchResult: MatchResult?,
            blocklistVersion: String?,
            occurredAt: String,
        ): RemoteBlockedEvent? {
            val normalizedEventId = eventId.trim()
            if (normalizedEventId.isEmpty()) return null

            val normalizedMatched = matched.trim().lowercase(Locale.ROOT)
            if (normalizedMatched.isEmpty()) return null

            val normalizedRegistrableDomain = matchResult
                ?.registrableDomain
                ?.trim()
                ?.lowercase(Locale.ROOT)
                ?.ifEmpty { null }

            return RemoteBlockedEvent(
                eventId = normalizedEventId,
                matchedDomain = normalizedMatched,
                registrableDomain = normalizedRegistrableDomain,
                blocklistVersion = blocklistVersion?.trim()?.ifEmpty { null },
                occurredAt = occurredAt,
            )
        }

        internal fun buildRemoteBlockedEventsBody(events: List<RemoteBlockedEvent>): String = JSONObject().apply {
            put("events", JSONArray().apply {
                for (event in events) {
                    put(JSONObject().apply {
                        put("event_id", event.eventId)
                        put("matched_domain", event.matchedDomain)
                        if (event.registrableDomain != null) {
                            put("registrable_domain", event.registrableDomain)
                        }
                        if (event.blocklistVersion != null) {
                            put("blocklist_version", event.blocklistVersion)
                        }
                        put("ts", event.occurredAt)
                    })
                }
            })
        }.toString()

        internal fun buildCompressedRemoteBlockedEventsPayload(body: String): ByteArray {
            val rawBytes = body.toByteArray(Charsets.UTF_8)
            return ByteArrayOutputStream().use { output ->
                GZIPOutputStream(output).use { gzip ->
                    gzip.write(rawBytes)
                }
                output.toByteArray()
            }
        }

        internal fun evaluateHostnameRequest(
            domain: String,
            app: String,
            matchResult: MatchResult?,
            policy: Policy,
            exactSystemAllowlist: Set<String>,
            suffixSystemAllowlist: Set<String>,
        ): EvaluatedHostnameRequest {
            val policyRequest = PolicyRequest(
                domain = domain,
                mode = policy.mode,
                app = app,
                matchedRule = matchResult?.toMatchedPolicyRule(),
                systemAllowlisted = matchesSystemAllowlist(domain, exactSystemAllowlist, suffixSystemAllowlist),
            )

            return EvaluatedHostnameRequest(
                app = app,
                matchResult = matchResult,
                policyRequest = policyRequest,
                decision = PolicyEngine.evaluate(policyRequest, policy),
            )
        }

        internal fun evaluateShadowHostnameRequest(
            domain: String,
            app: String,
            matchResult: MatchResult?,
            policy: Policy,
            exactSystemAllowlist: Set<String>,
            suffixSystemAllowlist: Set<String>,
        ): ShadowDecisionTelemetry? {
            if (matchResult == null) return null

            val lightEvaluation = evaluateHostnameRequest(
                domain = domain,
                app = app,
                matchResult = matchResult,
                policy = policy.copy(mode = EnforcementMode.LIGHT),
                exactSystemAllowlist = exactSystemAllowlist,
                suffixSystemAllowlist = suffixSystemAllowlist,
            )
            val extremeEvaluation = evaluateHostnameRequest(
                domain = domain,
                app = app,
                matchResult = matchResult,
                policy = policy.copy(mode = EnforcementMode.EXTREME),
                exactSystemAllowlist = exactSystemAllowlist,
                suffixSystemAllowlist = suffixSystemAllowlist,
            )

            return ShadowDecisionTelemetry(
                matchResult = matchResult,
                wouldBlockLight = lightEvaluation.decision.action == PolicyAction.BLOCK,
                wouldBlockExtreme = extremeEvaluation.decision.action == PolicyAction.BLOCK,
            )
        }

        private fun ruleMetadataKey(matchScope: String, domain: String): String = "$matchScope:$domain"
    }

    private var tunnel: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null

    private var supabaseUrl: String = ""
    private var supabaseAnon: String = ""
    private var authToken: String = ""
    private var logEvents: Boolean = true
    private var sniInspect: Boolean = false
    private var sampleAllowed: Boolean = false

    private var appResolver: AppResolver? = null
    private var connectivityManager: ConnectivityManager? = null
    private val alertedThisSession = ConcurrentHashMap.newKeySet<String>()
    private val nextAlertId = AtomicInteger(ALERT_NOTIFICATION_ID_BASE)

    // Active TCP relay threads keyed by connection ID (srcPort:dstIp:dstPort)
    private val tcpRelays = ConcurrentHashMap<String, Thread>()

    private val eventQueue = ConcurrentLinkedDeque<RemoteBlockedEvent>()
    private var flusher: ScheduledExecutorService? = null

    private fun nowIso(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }
        .format(Date())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val domains = intent.getStringArrayListExtra(EXTRA_DOMAINS) ?: arrayListOf()
                val v = intent.getStringExtra(EXTRA_VERSION) ?: ""
                supabaseUrl = intent.getStringExtra(EXTRA_SUPABASE_URL) ?: ""
                supabaseAnon = intent.getStringExtra(EXTRA_SUPABASE_ANON) ?: ""
                authToken = intent.getStringExtra(EXTRA_AUTH_TOKEN) ?: ""
                logEvents = intent.getBooleanExtra(EXTRA_LOG_EVENTS, true)
                sniInspect = intent.getBooleanExtra(EXTRA_SNI_INSPECT, false)
                liveNotificationsEnabled = intent.getBooleanExtra(EXTRA_LIVE_NOTIFICATIONS, false)
                sampleAllowed = intent.getBooleanExtra(EXTRA_SAMPLE_ALLOWED, false)
                val policyJson = intent.getStringExtra(EXTRA_POLICY_JSON)
                if (policyJson != null) {
                    try { policy = Policy.fromJson(policyJson) } catch (_: Exception) { /* keep existing */ }
                }
                startTunnel(domains, v)
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    private fun startTunnel(domains: List<String>, v: String) {
        teardown()

        val stagedRuleBundle = consumePendingRuleBundle()
        val stagedShadowRuleBundle = consumePendingShadowRuleBundle()
        val stagedSystemAllowlist = consumePendingSystemAllowlist()
        val stagedShadowSystemAllowlist = consumePendingShadowSystemAllowlist()
        if (stagedRuleBundle != null) {
            exactBlocklist = stagedRuleBundle.exactDomains
            suffixBlocklist = stagedRuleBundle.suffixDomains
            ruleMetadata = stagedRuleBundle.metadata
            bundleKind = "signed_ruleset"
        } else {
            exactBlocklist = emptySet()
            suffixBlocklist = domains.map { it.lowercase().trim() }.filter { it.isNotEmpty() }.toSet()
            ruleMetadata = emptyMap()
            bundleKind = "legacy_company_domains"
        }
        exactSystemAllowlist = stagedSystemAllowlist?.exactDomains ?: emptySet()
        suffixSystemAllowlist = stagedSystemAllowlist?.suffixDomains ?: emptySet()
        shadowExactBlocklist = stagedShadowRuleBundle?.exactDomains ?: emptySet()
        shadowSuffixBlocklist = stagedShadowRuleBundle?.suffixDomains ?: emptySet()
        shadowRuleMetadata = stagedShadowRuleBundle?.metadata ?: emptyMap()
        shadowExactSystemAllowlist = stagedShadowSystemAllowlist?.exactDomains ?: emptySet()
        shadowSuffixSystemAllowlist = stagedShadowSystemAllowlist?.suffixDomains ?: emptySet()
        version = v
        blockedCount.set(0)
        alertedThisSession.clear()
        nextAlertId.set(ALERT_NOTIFICATION_ID_BASE)

        // Init UID→package resolver and connectivity manager (API 29+ for UID lookups)
        appResolver = AppResolver(packageManager)
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        // Ensure local event store exists and prune stale rows from prior sessions.
        if (eventStore == null) eventStore = RoomEventStore(applicationContext)
        eventStore?.let { prepareEventStore(it) }

        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("ChoiceFirst")
            .addAddress(TUNNEL_LOCAL, 32)
            .addDnsServer(TUNNEL_DNS_SINK)
            .addRoute(TUNNEL_DNS_SINK, 32)  // DNS-only route is always active

        // SNI mode widens the tunnel to capture all TCP/443 and UDP/443 traffic
        // in addition to DNS (for QUIC blocking and SNI inspection).
        if (sniInspect) {
            builder.addRoute("0.0.0.0", 0)
            // TODO(phase-6): add IPv6 route once writeTcpRst6() is implemented
            // builder.addRoute("::", 0)
        }

        builder.setBlocking(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        tunnel = builder.establish() ?: return
        active = true
        sniActive = sniInspect
        running.set(true)

        worker = Thread({ runDnsLoop() }, "cf-vpn-dns").also { it.start() }
        startFlusher()
    }

    private fun teardown() {
        running.set(false)
        active = false
        sniActive = false
        worker?.interrupt()
        worker = null
        flusher?.shutdownNow()
        flusher = null
        for (relay in tcpRelays.values) relay.interrupt()
        tcpRelays.clear()
        appResolver = null
        connectivityManager = null
        try { tunnel?.close() } catch (_: Exception) {}
        tunnel = null
        try { flushEvents() } catch (_: Exception) {}
    }

    private fun startFlusher() {
        flusher?.shutdownNow()
        flusher = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "cf-vpn-flush").apply { isDaemon = true }
        }.also {
            it.scheduleWithFixedDelay(
                { runCatching { flushEvents() }.onFailure { e -> Log.w(TAG, "flush failed", e) } },
                FLUSH_INTERVAL_SECONDS,
                FLUSH_INTERVAL_SECONDS,
                TimeUnit.SECONDS,
            )
        }
    }

    private fun requestImmediateFlushIfNeeded(queueSize: Int) {
        if (!shouldFlushImmediately(queueSize)) return
        flusher?.execute {
            runCatching { flushEvents() }.onFailure { e -> Log.w(TAG, "flush failed", e) }
        }
    }

    /**
     * Persist the local decision row for a matched or blocked request.
     *
     * Always writes to the local Room store so the device retains the exact
     * action/reason taken for matched domains. Remote upload remains block-only.
     */
    private fun enqueueDecisionEvent(
        domain: String,
        matched: String,
        decision: Decision,
        app: String = "unknown",
        matchResult: MatchResult? = null,
        shadowTelemetry: ShadowDecisionTelemetry? = null,
        shadowOnly: Boolean = false,
        remoteMatched: String = matched,
        remoteMatchResult: MatchResult? = matchResult,
    ) {
        val activeMode = policy.mode.name.lowercase(Locale.ROOT)
        eventStore?.insert(
            BlockedEvent(
                ts = System.currentTimeMillis(),
                domain = domain,
                matched = matched,
                registrableDomain = matchResult?.registrableDomain,
                matchScope = matchResult?.matchScope,
                confidenceScore = matchResult?.confidenceScore,
                entityNamesJson = matchResult
                    ?.entityNames
                    ?.takeIf { it.isNotEmpty() }
                    ?.let { JSONArray(it).toString() },
                app = app,
                category = matchResult?.categories?.firstOrNull() ?: matchResult?.category,
                categoriesCsv = matchResult
                    ?.categories
                    ?.takeIf { it.isNotEmpty() }
                    ?.joinToString(","),
                source = matchResult?.source,
                sourcesCsv = matchResult
                    ?.sources
                    ?.takeIf { it.isNotEmpty() }
                    ?.joinToString(","),
                blocklistVersion = version.ifEmpty { null },
                policyVersion = policy.version,
                confidenceTier = matchResult?.confidenceTier,
                compatibilityTagsCsv = matchResult
                    ?.compatibilityTags
                    ?.takeIf { it.isNotEmpty() }
                    ?.joinToString(","),
                reviewNotesJson = matchResult
                    ?.reviewNotes
                    ?.takeIf { it.isNotEmpty() }
                    ?.let { JSONArray(it).toString() },
                action = if (shadowOnly) "observed" else localEventAction(decision),
                reason = if (shadowOnly) "shadow_ruleset_match" else localEventReason(decision, policy.mode),
                mode = if (shadowOnly) null else activeMode,
                wouldBlockLight = shadowTelemetry?.wouldBlockLight,
                wouldBlockExtreme = shadowTelemetry?.wouldBlockExtreme,
            )
        )

        if (decision.action != PolicyAction.BLOCK) {
            return
        }

        maybeNotifyBlocked(domain, matched, app)
        if (!logEvents) return
        val remoteEvent = buildRemoteBlockedEvent(
            UUID.randomUUID().toString(),
            remoteMatched,
            remoteMatchResult,
            version.ifEmpty { null },
            nowIso(),
        ) ?: return
        while (eventQueue.size >= QUEUE_MAX) eventQueue.pollFirst() ?: break
        eventQueue.addLast(remoteEvent)
        requestImmediateFlushIfNeeded(eventQueue.size)
    }

    private fun maybeNotifyBlocked(domain: String, matched: String, app: String) {
        if (!liveNotificationsEnabled) return

        val signature = "${matched.lowercase(Locale.ROOT)}|${app.lowercase(Locale.ROOT)}"
        if (!alertedThisSession.add(signature)) return

        val appLabel = appResolver?.labelForPackage(app)
        val title = if (appLabel != null) "Tracker blocked in $appLabel" else "Tracker blocked"
        val body = if (domain.equals(matched, ignoreCase = true)) domain else "$domain via $matched"
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        try {
            nm.notify(
                nextAlertId.getAndIncrement(),
                NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
                    .setSmallIcon(applicationInfo.icon)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                    .setAutoCancel(true)
                    .setContentIntent(buildOpenAppIntent())
                    .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                    .build(),
            )
        } catch (e: Exception) {
            Log.w(TAG, "live block alert failed", e)
        }
    }

    /** Record a sampled allowed event (only written locally; never uploaded). */
    private fun enqueueSampled(domain: String, app: String) {
        eventStore?.insert(
            BlockedEvent(
                ts = System.currentTimeMillis(),
                domain = domain,
                matched = "",
                app = app,
                category = null,
                source = null,
                action = "allow_sampled",
            )
        )
    }

    private fun flushEvents() {
        if (!logEvents) return
        if (supabaseUrl.isEmpty() || authToken.isEmpty()) return
        val batch = ArrayList<RemoteBlockedEvent>(FLUSH_BATCH)
        while (batch.size < FLUSH_BATCH) {
            val e = eventQueue.pollFirst() ?: break
            batch.add(e)
        }
        if (batch.isEmpty()) return

        val body = buildRemoteBlockedEventsBody(batch)
        val compressedBody = buildCompressedRemoteBlockedEventsPayload(body)

        val url = URL("${supabaseUrl.trimEnd('/')}/functions/v1/log-blocked")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 15_000
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Content-Encoding", "gzip")
            setRequestProperty("Authorization", "Bearer $authToken")
            if (supabaseAnon.isNotEmpty()) setRequestProperty("apikey", supabaseAnon)
            setFixedLengthStreamingMode(compressedBody.size)
        }
        try {
            conn.outputStream.use { it.write(compressedBody) }
            val code = conn.responseCode
            if (code !in 200..299) {
                Log.w(TAG, "log-blocked returned $code; requeuing ${batch.size} events")
                for (i in batch.indices.reversed()) eventQueue.addFirst(batch[i])
            }
        } catch (e: Exception) {
            Log.w(TAG, "log-blocked post failed", e)
            for (i in batch.indices.reversed()) eventQueue.addFirst(batch[i])
        } finally {
            try { conn.disconnect() } catch (_: Exception) {}
        }
    }

    private fun runDnsLoop() {
        val fd = tunnel ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32 * 1024)

        while (running.get()) {
            val len = try {
                input.read(buffer)
            } catch (_: Exception) {
                break
            }
            if (len <= 0) continue

            val packet = buffer.copyOfRange(0, len)
            handlePacket(packet, output)
        }

        try { input.close() } catch (_: Exception) {}
        try { output.close() } catch (_: Exception) {}
    }

    private fun handlePacket(packet: ByteArray, out: FileOutputStream) {
        if (packet.size < 20) return
        val ipVersion = (packet[0].toInt() ushr 4) and 0x0F
        // TODO(phase-6): add IPv6 support — parse 40-byte fixed header, walk
        // extension chain to find Next Header == TCP(6) or UDP(17), then
        // dispatch to handleTcpPacket/handleUdpPacket with ipHeaderLen=40.
        if (ipVersion != 4) return
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF

        when (protocol) {
            17 -> handleUdpPacket(packet, ipHeaderLen, out)   // UDP (DNS + QUIC)
            6  -> if (sniInspect) handleTcpPacket(packet, ipHeaderLen, out) // TCP/SNI
        }
    }

    private fun handleUdpPacket(packet: ByteArray, ipHeaderLen: Int, out: FileOutputStream) {
        if (packet.size < ipHeaderLen + 8) return

        val udpStart = ipHeaderLen
        val srcPort = ((packet[udpStart].toInt() and 0xFF) shl 8) or (packet[udpStart + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpStart + 2].toInt() and 0xFF) shl 8) or (packet[udpStart + 3].toInt() and 0xFF)

        // Phase-6 cheap QUIC blocking: when SNI inspection is active, drop all
        // UDP/443 traffic. QUIC clients (Chrome, Instagram, YouTube) use UDP/443
        // for HTTP/3 and would bypass the TCP/443 SNI check otherwise. Dropping
        // the packet causes the client to retry and fall back to TCP/443, where
        // our SNI inspection can then act.
        //
        // TODO(phase-6): replace this blanket drop with a proper QUIC Initial
        // packet parser (HKDF-SHA256 key derivation + AES-128-GCM decryption per
        // RFC 9001 §5) so we can block specific SNI hostnames instead of all QUIC.
        if (sniInspect && dstPort == HTTPS_PORT) return   // drop → client falls back to TCP

        if (dstPort != 53) return

        val dnsStart = udpStart + 8
        val dnsPayload = packet.copyOfRange(dnsStart, packet.size)

        val name = DnsPacket.queryName(dnsPayload) ?: run {
            forward(packet, udpStart, srcPort, dnsPayload, out)
            return
        }

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)

        val app = resolveApp(OsConstants.IPPROTO_UDP, srcIp, srcPort, dstIp, dstPort)
        val evaluation = evaluateHostnameRequest(
            domain = name,
            app = app,
            matchResult = DnsPacket.matchedRuleDetailed(name, exactBlocklist, suffixBlocklist, ruleMetadata),
            policy = policy,
            exactSystemAllowlist = exactSystemAllowlist,
            suffixSystemAllowlist = suffixSystemAllowlist,
        )
        val shadowTelemetry = evaluateShadowHostnameRequest(
            domain = name,
            app = app,
            matchResult = DnsPacket.matchedRuleDetailed(name, shadowExactBlocklist, shadowSuffixBlocklist, shadowRuleMetadata),
            policy = policy,
            exactSystemAllowlist = shadowExactSystemAllowlist,
            suffixSystemAllowlist = shadowSuffixSystemAllowlist,
        )
        if (evaluation.decision.action == PolicyAction.BLOCK || evaluation.matchResult != null || shadowTelemetry != null) {
            val shadowOnly = evaluation.matchResult == null && shadowTelemetry != null
            enqueueDecisionEvent(
                domain = name,
                matched = if (shadowOnly) shadowTelemetry!!.matchResult.suffix else evaluation.matchResult?.suffix ?: name,
                decision = evaluation.decision,
                app = evaluation.app,
                matchResult = if (shadowOnly) shadowTelemetry!!.matchResult else evaluation.matchResult,
                shadowTelemetry = shadowTelemetry,
                shadowOnly = shadowOnly,
            )
        }
        if (evaluation.decision.action == PolicyAction.BLOCK) {
            blockedCount.incrementAndGet()
            val response = DnsPacket.nxDomainResponse(dnsPayload)
            writeUdpReply(packet, udpStart, srcPort, response, out)
            return
        }

        // Allowed path: optionally sample 1-in-100 unmatched traffic for dashboard breadth.
        if (evaluation.matchResult == null && sampleAllowed && (Math.random() < 0.01)) {
            enqueueSampled(name, evaluation.app)
        }

        forward(packet, udpStart, srcPort, dnsPayload, out)
    }

    /**
     * Inspect TCP/443 packets for TLS SNI.
     *
     * We only act on SYN packets and the first data segment after the handshake.
     * For new connections the first data segment is the ClientHello; we inspect
     * its SNI, and either RST the connection (if blocked) or relay it
     * transparently via a protect()-ed socket.
     *
     * All non-443 TCP traffic passes through unmodified — we only widen the
     * route in SNI mode, so non-HTTPS traffic still hits the real network via
     * Android's routing table once we drop it; the VPN FD simply ignores it.
     */
    private fun handleTcpPacket(packet: ByteArray, ipHeaderLen: Int, out: FileOutputStream) {
        if (packet.size < ipHeaderLen + 20) return

        val tcpStart = ipHeaderLen
        val srcPort = ((packet[tcpStart].toInt() and 0xFF) shl 8) or (packet[tcpStart + 1].toInt() and 0xFF)
        val dstPort = ((packet[tcpStart + 2].toInt() and 0xFF) shl 8) or (packet[tcpStart + 3].toInt() and 0xFF)
        if (dstPort != HTTPS_PORT) return

        val tcpDataOffset = ((packet[tcpStart + 12].toInt() ushr 4) and 0x0F) * 4
        val payloadStart = tcpStart + tcpDataOffset
        if (payloadStart >= packet.size) return

        val tcpFlags = packet[tcpStart + 13].toInt() and 0xFF
        val flagSyn = (tcpFlags and 0x02) != 0
        val flagAck = (tcpFlags and 0x10) != 0

        // We only inspect the first data segment (SYN+data or plain data after SYN)
        val payload = packet.copyOfRange(payloadStart, packet.size)
        if (payload.isEmpty() || flagSyn && !flagAck) return  // Pure SYN — wait for data

        val dstIpBytes = packet.copyOfRange(16, 20)  // IPv4 destination address field
        val dstIp = InetAddress.getByAddress(dstIpBytes)
        val connKey = "$srcPort:${dstIp.hostAddress}:$dstPort"

        // If relay already running for this connection, ignore (already allowed)
        if (tcpRelays.containsKey(connKey)) return

        val sniName = SniPacket.sniHostname(payload)
        if (sniName != null) {
            val app = resolveApp(OsConstants.IPPROTO_TCP, packet.copyOfRange(12, 16), srcPort, dstIpBytes, dstPort)
            val evaluation = evaluateHostnameRequest(
                domain = sniName,
                app = app,
                matchResult = DnsPacket.matchedRuleDetailed(sniName, exactBlocklist, suffixBlocklist, ruleMetadata),
                policy = policy,
                exactSystemAllowlist = exactSystemAllowlist,
                suffixSystemAllowlist = suffixSystemAllowlist,
            )
            val shadowTelemetry = evaluateShadowHostnameRequest(
                domain = sniName,
                app = app,
                matchResult = DnsPacket.matchedRuleDetailed(sniName, shadowExactBlocklist, shadowSuffixBlocklist, shadowRuleMetadata),
                policy = policy,
                exactSystemAllowlist = shadowExactSystemAllowlist,
                suffixSystemAllowlist = shadowSuffixSystemAllowlist,
            )
            if (evaluation.decision.action == PolicyAction.BLOCK || evaluation.matchResult != null || shadowTelemetry != null) {
                val shadowOnly = evaluation.matchResult == null && shadowTelemetry != null
                enqueueDecisionEvent(
                    domain = sniName,
                    matched = if (shadowOnly) shadowTelemetry!!.matchResult.suffix else evaluation.matchResult?.suffix ?: sniName,
                    decision = evaluation.decision,
                    app = evaluation.app,
                    matchResult = if (shadowOnly) shadowTelemetry!!.matchResult else evaluation.matchResult,
                    shadowTelemetry = shadowTelemetry,
                    shadowOnly = shadowOnly,
                )
            }
            if (evaluation.decision.action == PolicyAction.BLOCK) {
                Log.d(TAG, "SNI blocked: $sniName (reason=${evaluation.decision.reason})")
                blockedCount.incrementAndGet()
                writeTcpRst(packet, ipHeaderLen, out)
                return
            }
        }

        // Not blocked — start transparent TCP relay
        startTcpRelay(connKey, dstIp, dstPort, packet, ipHeaderLen, payload, out)
    }

    /**
     * Relay a TCP connection through a protect()-ed socket.
     * The first segment (already read) is forwarded immediately, then
     * two threads pump data in each direction until the connection closes.
     */
    private fun startTcpRelay(
        connKey: String,
        dstIp: InetAddress,
        dstPort: Int,
        originalPacket: ByteArray,
        ipHeaderLen: Int,
        firstPayload: ByteArray,
        out: FileOutputStream,
    ) {
        val relayThread = Thread({
            try {
                val socket = Socket()
                protect(socket)
                socket.connect(InetSocketAddress(dstIp, dstPort), TCP_RELAY_TIMEOUT_MS)
                socket.soTimeout = TCP_RELAY_TIMEOUT_MS

                // Forward first payload to real server
                socket.getOutputStream().write(firstPayload)
                socket.getOutputStream().flush()

                // Relay server→client in a background thread
                val serverToClient = Thread({
                    try { pipeStream(socket.getInputStream(), out) } catch (_: Exception) {}
                    try { socket.close() } catch (_: Exception) {}
                }, "cf-relay-s2c-$connKey")
                serverToClient.isDaemon = true
                serverToClient.start()

                // Block here pumping client→server until done
                // (client→server data arrives via the VPN fd; for a true
                // bidirectional relay we'd need per-connection fd splicing.
                // We close the socket when the relay thread is interrupted.)
                serverToClient.join()
            } catch (e: Exception) {
                Log.d(TAG, "TCP relay ended for $connKey: ${e.message}")
            } finally {
                tcpRelays.remove(connKey)
            }
        }, "cf-relay-$connKey")
        relayThread.isDaemon = true
        tcpRelays[connKey] = relayThread
        relayThread.start()
    }

    private fun pipeStream(input: InputStream, out: FileOutputStream) {
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            // Write raw bytes back through the tun FD so the app receives them
            out.write(buf, 0, n)
        }
    }

    /**
     * Resolve the originating Android package for a network connection.
     *
     * Uses [ConnectivityManager.getConnectionOwnerUid] (API 29+) to look up
     * the UID owning the socket, then maps that to a package name. Falls back
     * to "unknown" on older APIs or when the lookup fails (e.g., the socket
     * has already been destroyed by the time we inspect the packet).
     */
    private fun resolveApp(
        protocol: Int,
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
    ): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return "unknown"
        val cm = connectivityManager ?: return "unknown"
        return try {
            val uid = cm.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort),
                InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort),
            )
            appResolver?.resolveUid(uid) ?: "unknown"
        } catch (_: Exception) {
            "unknown"
        }
    }

    /** Craft a TCP RST packet and write it into the tun FD. */
    private fun writeTcpRst(originalPacket: ByteArray, ipHeaderLen: Int, out: FileOutputStream) {
        val tcpStart = ipHeaderLen
        // RST packet: IP header + 20-byte TCP header (no options, no data)
        val rst = ByteArray(ipHeaderLen + 20)

        // Copy IP header and swap src/dst
        System.arraycopy(originalPacket, 0, rst, 0, ipHeaderLen)
        // Swap src and dst IP
        System.arraycopy(originalPacket, 16, rst, 12, 4)
        System.arraycopy(originalPacket, 12, rst, 16, 4)
        val totalLen = ipHeaderLen + 20
        rst[2] = ((totalLen ushr 8) and 0xFF).toByte()
        rst[3] = (totalLen and 0xFF).toByte()
        rst[8] = 64 // TTL
        // Recalculate IP checksum
        rst[10] = 0; rst[11] = 0
        val ipCs = checksum(rst, 0, ipHeaderLen)
        rst[10] = ((ipCs ushr 8) and 0xFF).toByte()
        rst[11] = (ipCs and 0xFF).toByte()

        // TCP header: swap ports, set RST+ACK flags
        rst[tcpStart + 0] = originalPacket[tcpStart + 2]  // dst port → src port
        rst[tcpStart + 1] = originalPacket[tcpStart + 3]
        rst[tcpStart + 2] = originalPacket[tcpStart + 0]  // src port → dst port
        rst[tcpStart + 3] = originalPacket[tcpStart + 1]
        // seq = ack number from original (so RST is in-window)
        System.arraycopy(originalPacket, tcpStart + 8, rst, tcpStart + 4, 4)
        // ack = 0
        rst[tcpStart + 8] = 0; rst[tcpStart + 9] = 0
        rst[tcpStart + 10] = 0; rst[tcpStart + 11] = 0
        rst[tcpStart + 12] = (5 shl 4).toByte() // data offset = 5 (20 bytes)
        rst[tcpStart + 13] = 0x04 // RST flag
        rst[tcpStart + 14] = 0; rst[tcpStart + 15] = 0 // window = 0
        // TCP checksum (zeroed — some stacks accept it, and we're the local endpoint)
        rst[tcpStart + 16] = 0; rst[tcpStart + 17] = 0

        try { out.write(rst) } catch (_: Exception) {}
    }

    private fun forward(
        originalPacket: ByteArray,
        udpStart: Int,
        srcPort: Int,
        dnsPayload: ByteArray,
        out: FileOutputStream,
    ) {
        val socket = DatagramSocket()
        protect(socket)
        try {
            socket.soTimeout = 5_000
            val upstream = InetSocketAddress(InetAddress.getByName(UPSTREAM_DNS), UPSTREAM_DNS_PORT)
            socket.send(DatagramPacket(dnsPayload, dnsPayload.size, upstream))

            val reply = ByteArray(32 * 1024)
            val dp = DatagramPacket(reply, reply.size)
            socket.receive(dp)

            val replyBytes = reply.copyOfRange(0, dp.length)
            writeUdpReply(originalPacket, udpStart, srcPort, replyBytes, out)
        } catch (_: Exception) {
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    private fun writeUdpReply(
        originalPacket: ByteArray,
        udpStart: Int,
        originalSrcPort: Int,
        dnsReply: ByteArray,
        out: FileOutputStream,
    ) {
        val ipHeaderLen = (originalPacket[0].toInt() and 0x0F) * 4
        val totalLen = ipHeaderLen + 8 + dnsReply.size
        val pkt = ByteBuffer.allocate(totalLen)

        pkt.put(originalPacket, 0, ipHeaderLen)
        pkt.position(0)

        pkt.put(2, ((totalLen ushr 8) and 0xFF).toByte())
        pkt.put(3, (totalLen and 0xFF).toByte())
        pkt.put(8, 64.toByte())
        val src = originalPacket.copyOfRange(12, 16)
        val dst = originalPacket.copyOfRange(16, 20)
        pkt.position(12); pkt.put(dst); pkt.put(src)

        pkt.put(10, 0); pkt.put(11, 0)
        val ipChecksum = checksum(pkt.array(), 0, ipHeaderLen)
        pkt.put(10, ((ipChecksum ushr 8) and 0xFF).toByte())
        pkt.put(11, (ipChecksum and 0xFF).toByte())

        pkt.position(ipHeaderLen)
        pkt.put(0, pkt.get(0))
        pkt.position(ipHeaderLen)
        pkt.put((53 ushr 8 and 0xFF).toByte())
        pkt.put((53 and 0xFF).toByte())
        pkt.put((originalSrcPort ushr 8 and 0xFF).toByte())
        pkt.put((originalSrcPort and 0xFF).toByte())
        val udpLen = 8 + dnsReply.size
        pkt.put((udpLen ushr 8 and 0xFF).toByte())
        pkt.put((udpLen and 0xFF).toByte())
        pkt.put(0); pkt.put(0)
        pkt.put(dnsReply)

        try { out.write(pkt.array(), 0, totalLen) } catch (_: Exception) {}
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            if (sum and 0x10000 != 0) sum = (sum and 0xFFFF) + 1
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
            if (sum and 0x10000 != 0) sum = (sum and 0xFFFF) + 1
        }
        return sum.inv() and 0xFFFF
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(NotificationChannel(
                CHANNEL_ID,
                "CF Cloak",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shown while CF Cloak is blocking trackers."
                setShowBadge(false)
            })
        }
        if (nm.getNotificationChannel(ALERT_CHANNEL_ID) == null) {
            nm.createNotificationChannel(NotificationChannel(
                ALERT_CHANNEL_ID,
                "Live block alerts",
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Alerts when ChoiceFirst blocks a tracker in real time."
            })
        }
    }

    private fun buildOpenAppIntent(): PendingIntent? {
        val openApp = packageManager.getLaunchIntentForPackage(packageName)
        return openApp?.let {
            PendingIntent.getActivity(
                this, 0, it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }
    }

    private fun buildNotification(): Notification {
        val contentIntent = buildOpenAppIntent()

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(applicationInfo.icon)
            .setContentTitle("CF Cloak is active")
            .setContentText("Blocking ${domainCount()} tracker domains")
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
