package app.choicefirst.eu.cloak

import android.content.pm.PackageManager
import java.util.concurrent.ConcurrentHashMap

/**
 * Maps Linux UIDs to Android package names.
 *
 * UIDs are stable for the lifetime of an installed app and are reused only
 * after an uninstall+reinstall cycle. A simple ConcurrentHashMap is safe here
 * because the number of distinct UIDs we ever see is bounded by the number of
 * installed apps (typically < 200), so unbounded growth is not a concern.
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
class AppResolver(private val pm: PackageManager) {

    private val cache = ConcurrentHashMap<Int, String>(64)
    private val labelCache = ConcurrentHashMap<String, String>(64)

    /**
     * Resolve a Linux UID to a package name.
     *
     * @return package name (e.g. "com.instagram.android"), a synthetic
     *         "uid:NNN" label if the UID has no owning package, or null
     *         for [android.os.Process.INVALID_UID].
     */
    fun resolveUid(uid: Int): String? {
        if (uid == android.os.Process.INVALID_UID) return null
        return cache.computeIfAbsent(uid) {
            pm.getNameForUid(it) ?: "uid:$it"
        }
    }

    /** Best-effort human label for a package name (e.g. "Chrome"). */
    fun labelForPackage(packageName: String): String? {
        if (packageName.isBlank() || packageName == "unknown" || packageName.startsWith("uid:")) return null
        return labelCache.computeIfAbsent(packageName) {
            try {
                val info = pm.getApplicationInfo(it, 0)
                pm.getApplicationLabel(info).toString()
            } catch (_: Exception) {
                it
            }
        }
    }
}
