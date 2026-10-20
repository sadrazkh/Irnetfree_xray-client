package com.irnetfree.vpn.core

/**
 * What a running connection was built from, and which of the user's changes
 * since then it does not carry yet — the desktop's settingsMeta.js
 * RECONNECT_KEYS. The core has no hot reload: a routing mode, a per-app list,
 * the DNS, the Mux mode, the routing profile or a chain in use changed while
 * connected waits for the next connect. Saving it silently made the screen say
 * "Bypass Iran" while the tunnel still routed everything through the proxy;
 * now the change is named on screen beside a Reconnect.
 */
object SettingsApply {
    /**
     * What a connect built its config from: the settings; the routing profile
     * it ran (null: not advanced routing); Settings → Mux as it read it
     * (Store.muxMode — null: the mode could not change that config, see
     * [muxRead]); and the chains its plan dials, by chain id → their hops' ids
     * as the plan carried them ([chainsOf]).
     */
    data class Applied(
        val settings: AppSettings,
        val profile: RoutingProfile?,
        val muxMode: String? = null,
        val chains: Map<String, List<String>> = emptyMap()
    )

    /** A chain as the store holds it now: its name, and its hops' ids (Store.chainMembers). */
    data class ChainNow(val name: String, val hops: List<String>)

    /**
     * Per-app as the VPN sees it (TunnelSetup.perApp): off is off whatever the
     * list holds, and "only these apps" or "all except these" with no app in
     * the list is the whole device too — exactly off. The list's order is
     * nobody's business.
     */
    private fun perApp(s: AppSettings): Pair<String, List<String>> {
        val apps = s.perApps.filter { p: String -> p.isNotBlank() }.distinct().sorted()
        val on = (s.perAppMode == "allow" || s.perAppMode == "disallow") && apps.isNotEmpty()
        return if (on) s.perAppMode to apps else "off" to emptyList()
    }

    /*
     * Each setting baked into a running connection, by the name the screen
     * gives it. Not here: "Advanced routing" — the selection decides the plan
     * (Store.buildPlan builds a profile's plan whatever that switch says, and
     * every other plan builds without advanced rules) — and "Routing mode under
     * the rules" (advancedUseMode) — a profile's plan carries the profile's own
     * useMode, which wins over it (ConfigBuilder.buildAdvanced), and a change
     * there is a change of the profile, named below.
     */
    private val KEYS: List<Pair<String, (AppSettings) -> Any?>> = listOf(
        "Routing mode" to { s: AppSettings -> s.routingMode },
        "Block ads" to { s: AppSettings -> s.blockAds },
        "Sniffing" to { s: AppSettings -> s.enableSniffing },
        "Custom rules" to { s: AppSettings -> s.customRules },
        "Per-app routing" to { s: AppSettings -> perApp(s) },
        "DNS" to { s: AppSettings -> Triple(s.dnsManaged, s.dnsRemote, s.dnsDirect) },
        "IPv6" to { s: AppSettings -> s.ipv6 },
        "Log level" to { s: AppSettings -> s.logLevel },
        "Default core" to { s: AppSettings -> s.defaultEngine },
        "Local ports" to { s: AppSettings -> Pair(s.socksPort, s.httpPort) }
    )

    /**
     * Settings → Mux ([mode]) as a connect of [plan] on [engine] read it: null
     * when no mode could change that config — sing-box never muxes, a chain's
     * hops never carry mux, and a server that cannot carry it (Mux.eligible) or
     * is set to Mux on/off itself does not follow the app's mode (Mux.plan).
     */
    fun muxRead(mode: String, plan: ConnectionPlan, engine: String): String? {
        if (engine == EngineChoice.SINGBOX) return null
        val follows = Mux.targets(plan).any { s: ServerConfig -> Mux.eligible(s.outbound) && s.mux != Mux.ON && s.mux != Mux.OFF }
        return if (follows) Mux.modeOf(mode) else null
    }

    /**
     * The chains [plan] dials, by chain id → their hops' ids: a chain plan's
     * own (by its id), a pool's entries that are chains, and an advanced plan's
     * chain targets and the chain bases they ride on. A chain the plan does not
     * hold (gone before the connect) is not one it dials.
     */
    fun chainsOf(plan: ConnectionPlan): Map<String, List<String>> {
        val out = LinkedHashMap<String, List<String>>()
        fun fromTargets(targets: List<String>, byId: Map<String, List<ServerConfig>>) {
            for (t in targets) {
                if (!t.startsWith("chain:")) continue
                val id = t.substring(6)
                val hops = byId[id] ?: continue
                out[id] = hops.map { s: ServerConfig -> s.id }
            }
        }
        when (plan) {
            is ConnectionPlan.Single -> {}
            is ConnectionPlan.Chain -> { if (plan.id.isNotEmpty()) out[plan.id] = plan.members.map { s: ServerConfig -> s.id } }
            is ConnectionPlan.Pool -> fromTargets(listOf(plan.primary) + plan.entries.map { e: PoolEntry -> e.target }, plan.chainsById)
            is ConnectionPlan.Advanced -> fromTargets(
                RoutingProfiles.routes(plan).flatMap { r: Pair<String, String?> -> listOfNotNull(r.first, r.second) }, plan.chainsById)
        }
        return out
    }

    /**
     * The names of what changed since [applied] was connected: every key whose
     * value differs; the Mux mode ([muxNow], Store.muxMode) when the connect's
     * could matter; the routing profile when the connection ran one and it was
     * edited ([profileNow] — the store's copy of that profile now) or deleted;
     * and each chain the plan dials whose hops changed or that was deleted
     * ([chainNow]: the chain of that id now, null when there is none).
     * Nothing applied (not connected): nothing pending.
     */
    fun pending(
        applied: Applied?, now: AppSettings, profileNow: RoutingProfile?,
        muxNow: String, chainNow: (String) -> ChainNow?
    ): List<String> {
        if (applied == null) return emptyList()
        val out = ArrayList<String>()
        for ((name, read) in KEYS) if (read(applied.settings) != read(now)) out.add(name)
        val mux = applied.muxMode
        if (mux != null && Mux.modeOf(muxNow) != mux) out.add("Mux")
        val p = applied.profile
        if (p != null && profileNow != p) out.add(if (profileNow == null) "Routing profile (deleted)" else "Routing profile “${profileNow.name}”")
        for ((id, hops) in applied.chains) {
            val c = chainNow(id)
            if (c == null) out.add("Chain (deleted)")
            else if (c.hops != hops) out.add("Chain “${c.name}”")
        }
        return out
    }
}
