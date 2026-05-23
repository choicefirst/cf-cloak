package app.choicefirst.eu.cloak

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.ActivityCallback
import com.getcapacitor.annotation.CapacitorPlugin
import java.io.ByteArrayInputStream
import java.util.Base64
import java.util.zip.GZIPInputStream
import org.json.JSONArray

/**
 * Capacitor bridge for CfVpnService.
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
@CapacitorPlugin(name = "Vpn")
class VpnPlugin : Plugin() {

    @PluginMethod
    fun prepare(call: PluginCall) {
        val intent = VpnService.prepare(context)
        if (intent == null) {
            call.resolve(JSObject().apply {
                put("consent_required", false)
                put("granted", true)
            })
            return
        }
        startActivityForResult(call, intent, "consentResult")
    }

    @ActivityCallback
    private fun consentResult(call: PluginCall, result: ActivityResult) {
        val granted = result.resultCode == Activity.RESULT_OK
        call.resolve(JSObject().apply {
            put("consent_required", true)
            put("granted", granted)
        })
    }

    @PluginMethod
    fun start(call: PluginCall) {
        val rulesJson = readJsonPayload(call, "rules_json", "rules_json_gzip_base64")
        val shadowRulesJson = readJsonPayload(call, "shadow_rules_json", "shadow_rules_json_gzip_base64")
        val systemAllowlistJson = readJsonPayload(call, "system_allowlist_json", "system_allowlist_json_gzip_base64")
        val shadowSystemAllowlistJson = readJsonPayload(call, "shadow_system_allowlist_json", "shadow_system_allowlist_json_gzip_base64")
        val domains = try {
            readDomains(call)
        } catch (error: Exception) {
            call.reject("invalid domains payload: ${error.message}")
            return
        }
        if (domains.isEmpty() && rulesJson == null && shadowRulesJson == null) {
            call.reject("domains array or staged rules payload required")
            return
        }
        val version = call.getString("version") ?: ""
        val supabaseUrl = call.getString("supabase_url") ?: ""
        val supabaseAnon = call.getString("supabase_anon_key") ?: ""
        val authToken = call.getString("auth_token") ?: ""
        val logEvents = call.getBoolean("log_events", true) ?: true
        val sniInspect = call.getBoolean("sni_inspect", false) ?: false
        val liveNotifications = call.getBoolean("live_notifications", false) ?: false

        CfVpnService.stageRuleBundleFromJson(rulesJson)
        CfVpnService.stageShadowRuleBundleFromJson(shadowRulesJson)
        CfVpnService.stageSystemAllowlistFromJson(systemAllowlistJson)
        CfVpnService.stageShadowSystemAllowlistFromJson(shadowSystemAllowlistJson)

        val intent = Intent(context, CfVpnService::class.java).apply {
            action = CfVpnService.ACTION_START
            putStringArrayListExtra(CfVpnService.EXTRA_DOMAINS, domains)
            putExtra(CfVpnService.EXTRA_VERSION, version)
            putExtra(CfVpnService.EXTRA_SUPABASE_URL, supabaseUrl)
            putExtra(CfVpnService.EXTRA_SUPABASE_ANON, supabaseAnon)
            putExtra(CfVpnService.EXTRA_AUTH_TOKEN, authToken)
            putExtra(CfVpnService.EXTRA_LOG_EVENTS, logEvents)
            putExtra(CfVpnService.EXTRA_SNI_INSPECT, sniInspect)
            putExtra(CfVpnService.EXTRA_LIVE_NOTIFICATIONS, liveNotifications)
        }
        ContextCompat.startForegroundService(context, intent)

        call.resolve(JSObject().apply { put("started", true) })
    }

    @PluginMethod
    fun stop(call: PluginCall) {
        val intent = Intent(context, CfVpnService::class.java).apply {
            action = CfVpnService.ACTION_STOP
        }
        context.startService(intent)
        call.resolve(JSObject().apply { put("stopped", true) })
    }

    @PluginMethod
    fun status(call: PluginCall) {
        call.resolve(JSObject().apply {
            put("active", CfVpnService.isActive())
            put("domain_count", CfVpnService.domainCount())
            put("blocked_session", CfVpnService.blockedInSession())
            put("version", CfVpnService.currentVersion())
            put("bundle_kind", CfVpnService.currentBundleKind())
            put("sni_inspect", CfVpnService.isSniActive())
        })
    }

    /**
    * Query local VPN events from the on-device Room DB.
     *
     * Args (all optional):
     *   since  — epoch millis lower bound (default: 0, i.e. all events)
     *   app    — filter to a specific package name
     *   limit  — max results (default: 500)
     */
    @PluginMethod
    fun getEvents(call: PluginCall) {
        val since = call.getLong("since") ?: 0L
        val app = call.getString("app")
        val limit = call.getInt("limit") ?: 500
        getBridge().execute {
            val store = CfVpnService.getEventStore()
            if (store == null) {
                call.resolve(JSObject().apply { put("events", JSArray()) })
                return@execute
            }
            try {
                val events = store.query(since, app, limit)
                val arr = JSArray()
                for (e in events) {
                    val entityNames = JSArray()
                    val entityNamesEntries = e.entityNamesJson?.let { runCatching { JSONArray(it) }.getOrNull() }
                    if (entityNamesEntries != null) {
                        for (i in 0 until entityNamesEntries.length()) {
                            val value = entityNamesEntries.optString(i, "").trim()
                            if (value.isNotEmpty()) {
                                entityNames.put(value)
                            }
                        }
                    }
                    val reviewNotes = JSArray()
                    val reviewNotesEntries = e.reviewNotesJson?.let { runCatching { JSONArray(it) }.getOrNull() }
                    if (reviewNotesEntries != null) {
                        for (i in 0 until reviewNotesEntries.length()) {
                            val value = reviewNotesEntries.optString(i, "").trim()
                            if (value.isNotEmpty()) {
                                reviewNotes.put(value)
                            }
                        }
                    }
                    val categories = JSArray()
                    e.categoriesCsv
                        ?.split(',')
                        ?.map { it.trim() }
                        ?.filter { it.isNotEmpty() }
                        ?.forEach { categories.put(it) }
                    val sources = JSArray()
                    e.sourcesCsv
                        ?.split(',')
                        ?.map { it.trim() }
                        ?.filter { it.isNotEmpty() }
                        ?.forEach { sources.put(it) }
                    val compatibilityTags = JSArray()
                    e.compatibilityTagsCsv
                        ?.split(',')
                        ?.map { it.trim() }
                        ?.filter { it.isNotEmpty() }
                        ?.forEach { compatibilityTags.put(it) }
                    arr.put(JSObject().apply {
                        put("id", e.id)
                        put("ts", e.ts)
                        put("domain", e.domain)
                        put("matched", e.matched)
                        put("registrable_domain", e.registrableDomain)
                        put("match_scope", e.matchScope)
                        put("entity_names", entityNames)
                        put("confidence_score", e.confidenceScore)
                        put("app", e.app)
                        put("category", e.category)
                        put("categories", categories)
                        put("source", e.source)
                        put("sources", sources)
                        put("blocklist_version", e.blocklistVersion)
                        put("policy_version", e.policyVersion)
                        put("confidence_tier", e.confidenceTier)
                        put("compatibility_tags", compatibilityTags)
                        put("review_notes", reviewNotes)
                        put("action", e.action)
                        put("reason", e.reason)
                        put("mode", e.mode)
                        put("would_block_light", e.wouldBlockLight)
                        put("would_block_extreme", e.wouldBlockExtreme)
                    })
                }
                call.resolve(JSObject().apply { put("events", arr) })
            } catch (ex: Exception) {
                call.reject("getEvents failed: ${ex.message}")
            }
        }
    }

    /** Delete all locally stored events. */
    @PluginMethod
    fun clearEvents(call: PluginCall) {
        CfVpnService.getEventStore()?.clear()
        call.resolve(JSObject().apply { put("cleared", true) })
    }

    /**
    * Aggregate local VPN event counts per day since [since] millis.
     * Optionally filter to a specific local action like `blocked`.
     */
    @PluginMethod
    fun getDailyStats(call: PluginCall) {
        val since = call.getLong("since") ?: 0L
        val action = call.getString("action")
        getBridge().execute {
            val store = CfVpnService.getEventStore()
            if (store == null) {
                call.resolve(JSObject().apply { put("stats", JSArray()) })
                return@execute
            }
            try {
                val stats = store.dailyStats(since, action)
                val arr = JSArray()
                for (s in stats) {
                    arr.put(JSObject().apply {
                        put("day_start_ts", s.dayStartTs)
                        put("action", s.action)
                        put("count", s.count)
                    })
                }
                call.resolve(JSObject().apply { put("stats", arr) })
            } catch (ex: Exception) {
                call.reject("getDailyStats failed: ${ex.message}")
            }
        }
    }

    /**
    * Aggregate local VPN event counts per app since [since] millis.
     * Returns an array sorted by count descending.
     */
    @PluginMethod
    fun getAppStats(call: PluginCall) {
        val since = call.getLong("since") ?: 0L
        getBridge().execute {
            val store = CfVpnService.getEventStore()
            if (store == null) {
                call.resolve(JSObject().apply { put("stats", JSArray()) })
                return@execute
            }
            try {
                val stats = store.appStats(since)
                val arr = JSArray()
                for (s in stats) {
                    arr.put(JSObject().apply {
                        put("app", s.app)
                        put("count", s.count)
                    })
                }
                call.resolve(JSObject().apply { put("stats", arr) })
            } catch (ex: Exception) {
                call.reject("getAppStats failed: ${ex.message}")
            }
        }
    }

    /**
     * Hot-swap the active policy without restarting the VPN service.
     *
     * The new policy is applied immediately to all subsequent DNS/SNI
     * decisions. The change is not persisted to disk — the caller is
     * responsible for re-sending the policy after a service restart.
     *
     * Args:
     *   policy — JSON-serialised [Policy] object.
     */
    @PluginMethod
    fun updatePolicy(call: PluginCall) {
        val policyJson = call.getString("policy") ?: run {
            call.reject("missing 'policy' field")
            return
        }
        try {
            CfVpnService.policy = Policy.fromJson(policyJson)
            call.resolve()
        } catch (ex: Exception) {
            call.reject("invalid policy JSON: ${ex.message}")
        }
    }

    @PluginMethod
    fun setLiveNotifications(call: PluginCall) {
        val enabled = call.getBoolean("enabled", false) ?: false
        CfVpnService.setLiveNotificationsEnabled(enabled)
        call.resolve()
    }

    private fun readDomains(call: PluginCall): ArrayList<String> {
        val compressedJson = call.getString("domains_json_gzip_base64")
        if (!compressedJson.isNullOrBlank()) {
            return parseStringArray(decodeGzipBase64(compressedJson))
        }

        val domainsArr = call.getArray("domains") ?: return arrayListOf()
        val domains = ArrayList<String>(domainsArr.length())
        for (i in 0 until domainsArr.length()) {
            domains.add(domainsArr.getString(i))
        }
        return domains
    }

    private fun readJsonPayload(call: PluginCall, rawKey: String, compressedKey: String): String? {
        val rawPayload = call.getString(rawKey)
        if (!rawPayload.isNullOrBlank()) {
            return rawPayload
        }

        val compressedPayload = call.getString(compressedKey)
        if (compressedPayload.isNullOrBlank()) {
            return null
        }

        return decodeGzipBase64(compressedPayload)
    }

    private fun parseStringArray(json: String): ArrayList<String> {
        val parsed = JSONArray(json)
        val values = ArrayList<String>(parsed.length())
        for (i in 0 until parsed.length()) {
            values.add(parsed.getString(i))
        }
        return values
    }

    private fun decodeGzipBase64(payload: String): String {
        val compressedBytes = Base64.getDecoder().decode(payload)
        return GZIPInputStream(ByteArrayInputStream(compressedBytes)).bufferedReader(Charsets.UTF_8).use { it.readText() }
    }
}
