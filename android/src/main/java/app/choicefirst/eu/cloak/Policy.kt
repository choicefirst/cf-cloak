package app.choicefirst.eu.cloak

import org.json.JSONObject

/**
 * Blocking action returned by the policy evaluator.
 */
enum class PolicyAction { BLOCK, ALLOW }

/**
 * A temporary exception that allows a domain/suffix until the given
 * epoch-millisecond timestamp. Mirrors [cf-cloak/src/policy.ts TempAllow].
 */
data class TempAllow(
    val domain: String,
    val expiresAt: Long,
)

/**
 * Input to [PolicyEngine.evaluate]. All fields are optional except [domain].
 */
data class PolicyRequest(
    val domain: String,
    val category: String? = null,
    val app: String? = null,
    /** The blocklist suffix that matched this domain, or null if no match. */
    val matchedSuffix: String? = null,
)

/**
 * Reason codes returned alongside the [Decision]. Used for logging/analytics.
 */
enum class DecisionReason {
    TEMP_ALLOW,
    DOMAIN_OVERRIDE,
    APP_OVERRIDE,
    CATEGORY_DISABLED,
    CATEGORY_BLOCKED,
    DEFAULT_BLOCK,
    DEFAULT_ALLOW,
}

/**
 * The decision returned by [PolicyEngine.evaluate].
 */
data class Decision(
    val action: PolicyAction,
    val reason: DecisionReason,
)

/**
 * Policy configuration that controls blocking behaviour.
 *
 * Mirrors the TypeScript [Policy] interface in cf-cloak/src/policy.ts.
 * Construct via [Policy.fromJson] when receiving from the Capacitor bridge,
 * or use [Policy.DEFAULT] for the factory-default policy.
 */
data class Policy(
    val version: Int = 1,
    val defaultAction: PolicyAction = PolicyAction.BLOCK,
    /** category → true means blocking is active; false means opted-out. */
    val categoryEnabled: Map<String, Boolean> = emptyMap(),
    /** Android package name → forced action. */
    val appOverrides: Map<String, PolicyAction> = emptyMap(),
    /** Domain suffix → forced action. */
    val domainOverrides: Map<String, PolicyAction> = emptyMap(),
    val tempAllows: List<TempAllow> = emptyList(),
) {
    companion object {
        /** The default policy (block everything in the blocklist). */
        val DEFAULT = Policy()

        /**
         * Deserialise a [Policy] from a JSON string received via the
         * Capacitor bridge. Unknown keys are silently ignored; malformed values
         * fall back to their defaults.
         */
        fun fromJson(json: String): Policy {
            val obj = JSONObject(json)
            val version = obj.optInt("version", 1)

            val defaultAction = when (obj.optString("defaultAction", "block")) {
                "allow" -> PolicyAction.ALLOW
                else    -> PolicyAction.BLOCK
            }

            val categoryEnabled = mutableMapOf<String, Boolean>()
            obj.optJSONObject("categoryEnabled")?.let { ce ->
                ce.keys().forEach { k -> categoryEnabled[k] = ce.getBoolean(k) }
            }

            val appOverrides = mutableMapOf<String, PolicyAction>()
            obj.optJSONObject("appOverrides")?.let { ao ->
                ao.keys().forEach { k ->
                    appOverrides[k] = when (ao.getString(k)) {
                        "allow" -> PolicyAction.ALLOW
                        else    -> PolicyAction.BLOCK
                    }
                }
            }

            val domainOverrides = mutableMapOf<String, PolicyAction>()
            obj.optJSONObject("domainOverrides")?.let { dom ->
                dom.keys().forEach { k ->
                    domainOverrides[k] = when (dom.getString(k)) {
                        "allow" -> PolicyAction.ALLOW
                        else    -> PolicyAction.BLOCK
                    }
                }
            }

            val tempAllows = mutableListOf<TempAllow>()
            obj.optJSONArray("tempAllows")?.let { arr ->
                for (i in 0 until arr.length()) {
                    val ta = arr.getJSONObject(i)
                    tempAllows.add(
                        TempAllow(
                            domain = ta.getString("domain"),
                            expiresAt = ta.getLong("expiresAt"),
                        ),
                    )
                }
            }

            return Policy(version, defaultAction, categoryEnabled, appOverrides, domainOverrides, tempAllows)
        }
    }
}

/**
 * Pure policy evaluator — the Kotlin mirror of cf-cloak/src/policy.ts `evaluate()`.
 *
 * Priority order (highest → lowest):
 *  1. Temporary allows
 *  2. Domain overrides
 *  3. App overrides
 *  4. Category check (only when domain is in the blocklist)
 *  5. Default action (only when domain is in the blocklist)
 *  6. Not in blocklist → allow
 */
object PolicyEngine {

    fun evaluate(
        request: PolicyRequest,
        policy: Policy,
        now: Long = System.currentTimeMillis(),
    ): Decision {
        val domain = request.domain.lowercase()

        // ── 1. Temp allows ──────────────────────────────────────────────────
        for (ta in policy.tempAllows) {
            if (ta.expiresAt > now && domainMatchesSuffix(domain, ta.domain.lowercase())) {
                return Decision(PolicyAction.ALLOW, DecisionReason.TEMP_ALLOW)
            }
        }

        // ── 2. Domain overrides ─────────────────────────────────────────────
        for ((suffix, action) in policy.domainOverrides) {
            if (domainMatchesSuffix(domain, suffix.lowercase())) {
                return Decision(action, DecisionReason.DOMAIN_OVERRIDE)
            }
        }

        // ── 3. App overrides ────────────────────────────────────────────────
        request.app?.let { app ->
            val override = policy.appOverrides[app]
            if (override != null) {
                return Decision(override, DecisionReason.APP_OVERRIDE)
            }
        }

        // ── 4. Category + default (only applies when domain IS in blocklist) ─
        if (request.matchedSuffix != null) {
            request.category?.let { cat ->
                val enabled = policy.categoryEnabled[cat]
                if (enabled == false) return Decision(PolicyAction.ALLOW, DecisionReason.CATEGORY_DISABLED)
                if (enabled == true)  return Decision(PolicyAction.BLOCK, DecisionReason.CATEGORY_BLOCKED)
                // key absent → fall through to defaultAction
            }
            return Decision(
                policy.defaultAction,
                if (policy.defaultAction == PolicyAction.BLOCK) DecisionReason.DEFAULT_BLOCK
                else DecisionReason.DEFAULT_ALLOW,
            )
        }

        // ── 5. Domain not in blocklist → allow ──────────────────────────────
        return Decision(PolicyAction.ALLOW, DecisionReason.DEFAULT_ALLOW)
    }

    private fun domainMatchesSuffix(domain: String, suffix: String): Boolean =
        domain == suffix || domain.endsWith(".$suffix")
}
