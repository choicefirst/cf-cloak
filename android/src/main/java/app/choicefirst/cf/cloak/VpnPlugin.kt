package app.choicefirst.cf.cloak

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
        val domainsArr = call.getArray("domains")
        if (domainsArr == null) {
            call.reject("domains array required")
            return
        }
        val domains = ArrayList<String>(domainsArr.length())
        for (i in 0 until domainsArr.length()) {
            domains.add(domainsArr.getString(i))
        }
        val version = call.getString("version") ?: ""
        val supabaseUrl = call.getString("supabase_url") ?: ""
        val supabaseAnon = call.getString("supabase_anon_key") ?: ""
        val authToken = call.getString("auth_token") ?: ""
        val logEvents = call.getBoolean("log_events", true) ?: true
        val sniInspect = call.getBoolean("sni_inspect", false) ?: false

        val intent = Intent(context, CfVpnService::class.java).apply {
            action = CfVpnService.ACTION_START
            putStringArrayListExtra(CfVpnService.EXTRA_DOMAINS, domains)
            putExtra(CfVpnService.EXTRA_VERSION, version)
            putExtra(CfVpnService.EXTRA_SUPABASE_URL, supabaseUrl)
            putExtra(CfVpnService.EXTRA_SUPABASE_ANON, supabaseAnon)
            putExtra(CfVpnService.EXTRA_AUTH_TOKEN, authToken)
            putExtra(CfVpnService.EXTRA_LOG_EVENTS, logEvents)
            putExtra(CfVpnService.EXTRA_SNI_INSPECT, sniInspect)
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
            put("sni_inspect", CfVpnService.isSniActive())
        })
    }

    /**
     * Query local blocked events from the on-device Room DB.
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
                    arr.put(JSObject().apply {
                        put("id", e.id)
                        put("ts", e.ts)
                        put("domain", e.domain)
                        put("matched", e.matched)
                        put("app", e.app)
                        put("category", e.category)
                        put("source", e.source)
                        put("action", e.action)
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
     * Aggregate blocked + sampled counts per app since [since] millis.
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
}
