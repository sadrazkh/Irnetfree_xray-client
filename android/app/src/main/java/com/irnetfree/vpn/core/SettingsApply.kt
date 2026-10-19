package com.irnetfree.vpn.core

/**
 * What a running connection was built from, and which of the user's changes
 * since then it does not carry yet — the desktop's settingsMeta.js
 * RECONNECT_KEYS. The core has no hot reload: a routing mode, a per-app list,
 * the DNS or the routing profile changed while connected waits for the next
 * connect. Saving it silently made the screen say "Bypass Iran" while the
 * tunnel still routed everything through the proxy; now the change is named on
 * screen beside a Reconnect.
 */
object SettingsApply {
    /** The settings a connect built its config from, and the routing profile it ran (null: not advanced routing). */
    data class Applied(val settings: AppSettings, val profile: RoutingProfile?)

    /** Per-app as the VPN sees it: off is off whatever the list holds; the list's order is nobody's business. */
    private fun perApp(s: AppSettings): Pair<String, List<String>> =
        if (s.perAppMode == "off") "off" to emptyList() else s.perAppMode to s.perApps.filter { p: String -> p.isNotBlank() }.distinct().sorted()

    /** Each setting baked into a running connection, by the name the screen gives it. */
    private val KEYS: List<Pair<String, (AppSettings) -> Any?>> = listOf(
        "Routing mode" to { s: AppSettings -> s.routingMode },
        "Block ads" to { s: AppSettings -> s.blockAds },
        "Sniffing" to { s: AppSettings -> s.enableSniffing },
        "Custom rules" to { s: AppSettings -> s.customRules },
        "Advanced routing" to { s: AppSettings -> s.advancedRouting },
        "Routing mode under the rules" to { s: AppSettings -> s.advancedUseMode },
        "Per-app routing" to { s: AppSettings -> perApp(s) },
        "DNS" to { s: AppSettings -> Triple(s.dnsManaged, s.dnsRemote, s.dnsDirect) },
        "IPv6" to { s: AppSettings -> s.ipv6 },
        "Log level" to { s: AppSettings -> s.logLevel },
        "Default core" to { s: AppSettings -> s.defaultEngine },
        "Local ports" to { s: AppSettings -> Pair(s.socksPort, s.httpPort) }
    )

    /**
     * The names of what changed since [applied] was connected: every key whose
     * value differs, then the routing profile when the connection ran one and it
     * was edited ([profileNow] — the store's copy of that profile now) or deleted.
     * Nothing applied (not connected): nothing pending.
     */
    fun pending(applied: Applied?, now: AppSettings, profileNow: RoutingProfile?): List<String> {
        if (applied == null) return emptyList()
        val out = ArrayList<String>()
        for ((name, read) in KEYS) if (read(applied.settings) != read(now)) out.add(name)
        val p = applied.profile
        if (p != null && profileNow != p) out.add(if (profileNow == null) "Routing profile (deleted)" else "Routing profile “${profileNow.name}”")
        return out
    }
}
