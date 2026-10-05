package com.irnetfree.vpn.core

import org.json.JSONObject

/**
 * "A newer IRNetFree is out" — the arithmetic of the Home card, testable off a
 * device. Android will not run a core an app downloads into its own storage
 * (W^X on app data since Android 10), so a newer core reaches a phone only
 * inside a newer APK: this is how the phone hears of one. The fetch is AppWork's.
 */
object UpdateCheck {
    const val EVERY_MS: Long = 24L * 3600 * 1000
    const val LATEST_URL = "https://api.github.com/repos/sadrazkh/Irnetfree_xray-client/releases/latest"
    private val VERSION = Regex("""(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.]+))?""")

    /** "v1.18.0" / "1.18.0-beta.1" → ([1, 18, 0], "beta.1"); "" for a release; null when unreadable. */
    fun parse(v: String): Pair<List<Int>, String>? {
        val m = VERSION.find(v.trim()) ?: return null
        val nums = (1..3).map { i: Int -> m.groupValues[i].toIntOrNull() ?: return null }
        return Pair(nums, m.groupValues[4])
    }

    /** Is [latest] newer than [current]? A release ranks above its own pre-releases; unreadable → false. */
    fun newer(latest: String, current: String): Boolean {
        val a = parse(latest) ?: return false
        val b = parse(current) ?: return false
        for (i in 0 until 3) if (a.first[i] != b.first[i]) return a.first[i] > b.first[i]
        if (a.second == b.second) return false
        if (a.second.isEmpty()) return true
        if (b.second.isEmpty()) return false
        return a.second > b.second
    }

    /**
     * Ask again a day after the last answer — at once when there never was one
     * (0: a fresh install, or every try so far failed), or when the clock went back.
     */
    fun due(lastCheck: Long, now: Long): Boolean = lastCheck <= 0L || now < lastCheck || now - lastCheck >= EVERY_MS

    /** The release's APK, else its page. */
    fun downloadUrl(release: JSONObject): String {
        val assets = release.optJSONArray("assets")
        if (assets != null) for (i in 0 until assets.length()) {
            val a = assets.optJSONObject(i) ?: continue
            if (a.optString("name").endsWith(".apk", ignoreCase = true)) {
                val url = a.optString("browser_download_url")
                if (url.isNotEmpty()) return url
            }
        }
        return release.optString("html_url")
    }
}
