package app.choicefirst.eu.cloak

import org.json.JSONObject

/**
 * Physical network action returned by the policy evaluator.
 */
enum class PolicyAction { BLOCK, ALLOW }

/**
 * User-visible effect of the decision.
 */
enum class DecisionEffect { BLOCK, ALLOW, OBSERVE }

/**
 * Automatic enforcement mode for canonical rule actions.
 */
enum class EnforcementMode { LIGHT, EXTREME }

/**
 * Mode-specific action attached to a canonical rule.
 */
enum class ModeAction { BLOCK, OBSERVE }

/**
 * A temporary exception that allows a domain/suffix until the given
 * epoch-millisecond timestamp. Mirrors [cf-cloak/src/policy.ts TempAllow].
 */
data class TempAllow(
    val domain: String,
    val expiresAt: Long,
)

data class MatchedPolicyRule(
    val domain: String,
    val confidenceScore: Double? = null,
    val entityNames: List<String> = emptyList(),
    val matchScope: String? = null,
    val registrableDomain: String? = null,
    val categories: List<String> = emptyList(),
    val confidenceTier: String? = null,
    val compatibilityTags: List<String> = emptyList(),
    val reviewNotes: List<String> = emptyList(),
    val lightAction: ModeAction? = null,
    val extremeAction: ModeAction? = null,
)

/**
 * Input to [PolicyEngine.evaluate]. All fields are optional except [domain].
 */
data class PolicyRequest(
    val domain: String,
    val mode: EnforcementMode? = null,
    val matchedRule: MatchedPolicyRule? = null,
    val category: String? = null,
    val app: String? = null,
    val systemAllowlisted: Boolean = false,
    /** The blocklist suffix that matched this domain, or null if no match. */
    val matchedSuffix: String? = null,
    /** Canonical Light-mode action for the matched rule, when available. */
    val lightAction: ModeAction? = null,
    /** Canonical Extreme-mode action for the matched rule, when available. */
    val extremeAction: ModeAction? = null,
)

/**
 * Reason codes returned alongside the [Decision]. Used for logging/analytics.
 */
enum class DecisionReason {
    TEMP_ALLOW,
    DOMAIN_OVERRIDE,
    SYSTEM_ALLOWLIST,
    APP_OVERRIDE,
    CATEGORY_DISABLED,
    CATEGORY_BLOCKED,
    RULE_OBSERVE,
    RULE_BLOCK,
    DEFAULT_BLOCK,
    DEFAULT_ALLOW,
}

/**
 * The decision returned by [PolicyEngine.evaluate].
 */
data class Decision(
    val action: PolicyAction,
    val effect: DecisionEffect,
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
    val version: Int = 2,
    val mode: EnforcementMode = EnforcementMode.LIGHT,
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
            val version = obj.optInt("version", 2)

            val mode = when (obj.optString("mode", "light")) {
                "extreme" -> EnforcementMode.EXTREME
                else       -> EnforcementMode.LIGHT
            }

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

            return Policy(version, mode, defaultAction, categoryEnabled, appOverrides, domainOverrides, tempAllows)
        }
    }
}

/**
 * Pure policy evaluator — the Kotlin mirror of cf-cloak/src/policy.ts `evaluate()`.
 *
 * Priority order (highest → lowest):
 *  1. Temporary allows
 *  2. Domain overrides
 *  3. System allowlist
 *  4. App overrides
 *  5. Category check (only when domain is in the blocklist)
 *  6. Canonical rule action (Light/Extreme observe or block)
 *  7. Default action (only when domain is in the blocklist)
 *  8. Not in blocklist → allow
 */
object PolicyEngine {

    fun evaluate(
        request: PolicyRequest,
        policy: Policy,
        now: Long = System.currentTimeMillis(),
    ): Decision {
        val domain = request.domain.lowercase()
        val mode = request.mode ?: policy.mode
        val matchedDomain = matchedDomain(request)
        val matchedCategory = matchedCategory(request)

        // ── 1. Temp allows ──────────────────────────────────────────────────
        for (ta in policy.tempAllows) {
            if (ta.expiresAt > now && domainMatchesSuffix(domain, ta.domain.lowercase())) {
                return Decision(PolicyAction.ALLOW, DecisionEffect.ALLOW, DecisionReason.TEMP_ALLOW)
            }
        }

        // ── 2. Domain overrides ─────────────────────────────────────────────
        val domainOverride = domainOverrideAction(domain, policy.domainOverrides)
        if (domainOverride != null) {
            return Decision(domainOverride, toEffect(domainOverride), DecisionReason.DOMAIN_OVERRIDE)
        }

        // ── 3. System allowlist ─────────────────────────────────────────────
        if (request.systemAllowlisted && matchedDomain != null) {
            return Decision(PolicyAction.ALLOW, DecisionEffect.ALLOW, DecisionReason.SYSTEM_ALLOWLIST)
        }

        // ── 4. App overrides ────────────────────────────────────────────────
        request.app?.let { app ->
            val override = policy.appOverrides[app]
            if (override != null) {
                return Decision(override, toEffect(override), DecisionReason.APP_OVERRIDE)
            }
        }

        // ── 5. Category + mode-aware rule action + default ──────────────────
        if (matchedDomain != null) {
            matchedCategory?.let { cat ->
                val enabled = policy.categoryEnabled[cat]
                if (enabled == false) return Decision(PolicyAction.ALLOW, DecisionEffect.ALLOW, DecisionReason.CATEGORY_DISABLED)
                if (enabled == true)  return Decision(PolicyAction.BLOCK, DecisionEffect.BLOCK, DecisionReason.CATEGORY_BLOCKED)
                // key absent → fall through to defaultAction
            }

            when (matchedRuleAction(request, mode)) {
                ModeAction.OBSERVE -> return Decision(PolicyAction.ALLOW, DecisionEffect.OBSERVE, DecisionReason.RULE_OBSERVE)
                ModeAction.BLOCK -> return Decision(PolicyAction.BLOCK, DecisionEffect.BLOCK, DecisionReason.RULE_BLOCK)
                null -> Unit
            }

            return Decision(
                policy.defaultAction,
                toEffect(policy.defaultAction),
                if (policy.defaultAction == PolicyAction.BLOCK) DecisionReason.DEFAULT_BLOCK
                else DecisionReason.DEFAULT_ALLOW,
            )
        }

        // ── 6. Domain not in blocklist → allow ──────────────────────────────
        return Decision(PolicyAction.ALLOW, DecisionEffect.ALLOW, DecisionReason.DEFAULT_ALLOW)
    }

    private fun matchedRuleAction(
        request: PolicyRequest,
        mode: EnforcementMode,
    ): ModeAction? = when (mode) {
        EnforcementMode.EXTREME -> request.matchedRule?.extremeAction ?: request.extremeAction
        EnforcementMode.LIGHT -> request.matchedRule?.lightAction ?: request.lightAction
    }

    private fun matchedDomain(request: PolicyRequest): String? =
        request.matchedRule?.domain ?: request.matchedSuffix

    private fun matchedCategory(request: PolicyRequest): String? =
        request.matchedRule?.categories?.firstOrNull() ?: request.category

    private fun domainOverrideAction(
        domain: String,
        overrides: Map<String, PolicyAction>,
    ): PolicyAction? {
        var bestAction: PolicyAction? = null
        var bestMatchLength = -1
        var bestMatchIsExact = false

        for ((rawCandidate, action) in overrides) {
            val candidate = rawCandidate.lowercase()
            if (!domainMatchesSuffix(domain, candidate)) {
                continue
            }

            val isExact = domain == candidate
            if (
                bestAction == null ||
                (isExact && !bestMatchIsExact) ||
                (isExact == bestMatchIsExact && candidate.length > bestMatchLength)
            ) {
                bestAction = action
                bestMatchLength = candidate.length
                bestMatchIsExact = isExact
            }
        }

        return bestAction
    }

    private fun toEffect(action: PolicyAction): DecisionEffect = when (action) {
        PolicyAction.BLOCK -> DecisionEffect.BLOCK
        PolicyAction.ALLOW -> DecisionEffect.ALLOW
    }

    private fun domainMatchesSuffix(domain: String, suffix: String): Boolean =
        domain == suffix || domain.endsWith(".$suffix")
}
