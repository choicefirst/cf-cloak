package app.choicefirst.cf.cloak

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin

/**
 * InstalledAppsPlugin — returns the package identifiers of apps installed on
 * the device, so we can match them against the ChoiceFirst catalog and
 * auto-record user_services rows.
 *
 * Requires the `QUERY_ALL_PACKAGES` permission (Play Store policy requires
 * a declared justification: "The app enumerates installed apps to detect
 * which catalogued companies the user has accounts with, enabling the
 * core privacy-protection functionality of blocking trackers and
 * submitting data-deletion requests on the user's behalf."). If the
 * platform denies the permission the plugin returns an empty list —
 * callers should treat that as "no signal" rather than an error.
 *
 * This file is part of the cf-cloak open-source enforcement layer.
 * Licensed under AGPLv3. See the repository root for full terms.
 */
@CapacitorPlugin(name = "InstalledApps")
class InstalledAppsPlugin : Plugin() {

    @PluginMethod
    fun list(call: PluginCall) {
        val pm = context.packageManager
        val includeSystem = call.getBoolean("includeSystem", false) == true

        val packages: List<ApplicationInfo> = try {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        } catch (t: Throwable) {
            emptyList()
        }

        val arr = JSArray()
        for (info in packages) {
            val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystem && !includeSystem) continue

            val pkg = info.packageName ?: continue
            val label = try { pm.getApplicationLabel(info).toString() } catch (_: Throwable) { pkg }

            val firstInstall = try {
                pm.getPackageInfo(pkg, 0).firstInstallTime
            } catch (_: Throwable) { 0L }

            val obj = JSObject().apply {
                put("packageName", pkg)
                put("appName", label)
                put("firstInstallTime", firstInstall)
                put("isSystem", isSystem)
            }
            arr.put(obj)
        }

        call.resolve(JSObject().apply {
            put("packages", arr)
            put("count", arr.length())
        })
    }
}
