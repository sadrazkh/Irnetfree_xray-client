package com.irnetfree.vpn.core

/**
 * Port of src/main/engineChoice.js — which core runs a connection plan.
 *
 *  - single:   the server's own choice (edit screen), else the default engine
 *  - chain / pool / advanced: "xray-pattn" if the default is PattN or ANY server
 *    that takes part asks for it — PattN accepts everything the official core
 *    does plus plaintext VLESS/Trojan, so a chain with one plaintext hop must
 *    run on it. Otherwise the official core.
 *  - "sing-box" is a single-config engine only: it has no chain/pool translator,
 *    so a plan that is not a single server never resolves to it — nor does a
 *    group (Groups.kt) selected alone: it has no balancer. A group runs on
 *    PattN when one of its members asks for it, else on the official core.
 *
 * This is the app's decision, not the device's: whether the chosen core is
 * actually bundled for this ABI is a separate question, asked at connect time
 * (XrayPattnCore.available / SingboxCore.available), which falls back to the
 * in-process core and says so in the log.
 */
object EngineChoice {
    const val XRAY = "xray"
    const val PATTN = "xray-pattn"
    const val SINGBOX = "sing-box"

    /** Every server a plan can dial, duplicates allowed (engineChoice.planServers); a group stands for its members. */
    fun planServers(plan: ConnectionPlan?): List<ServerConfig> = planRecords(plan).flatMap { s: ServerConfig -> Groups.serversOf(s) }

    /** Every record a plan names — a group as its record — duplicates allowed. */
    private fun planRecords(plan: ConnectionPlan?): List<ServerConfig> = when (plan) {
        null -> emptyList()
        is ConnectionPlan.Single -> listOf(plan.server)
        is ConnectionPlan.Chain -> plan.members
        is ConnectionPlan.Pool -> targetsServers(plan.entries.map { it.target }, plan.serversById, plan.chainsById)
        // the bases a profile's targets ride on are dialled too (spec §2: planServers includes bases)
        is ConnectionPlan.Advanced ->
            targetsServers(plan.rules.map { it.target } + plan.def + RoutingProfiles.basesOf(plan), plan.serversById, plan.chainsById)
    }

    private fun targetsServers(
        targets: List<String?>,
        serversById: Map<String, ServerConfig>,
        chainsById: Map<String, List<ServerConfig>>
    ): List<ServerConfig> {
        val out = ArrayList<ServerConfig>()
        for (tg in targets) {
            if (tg.isNullOrEmpty() || tg == "direct" || tg == "block") continue
            if (tg.startsWith("chain:")) { chainsById[tg.substring(6)]?.let { out.addAll(it) }; continue }
            serversById[tg]?.let { out.add(it) }
        }
        return out
    }

    /**
     * A Hysteria2 server that asked for "allow insecure" and names no certificate
     * (engineChoice.js needsInsecureCore): the Xray cores have no way left to
     * accept an unverified certificate (allowInsecure is gone; CertPin's
     * trust-on-first-use is a TCP handshake, and Hysteria is QUIC) — sing-box
     * still has one. A self-signed certificate is how most of them are set up.
     */
    fun needsInsecureCore(server: ServerConfig?): Boolean {
        val st = server?.outbound?.optJSONObject("streamSettings") ?: return false
        val tls = st.optJSONObject("tlsSettings") ?: return false
        return st.optString("network") == "hysteria" && tls.optBoolean("allowInsecure") &&
            tls.optString("pinnedPeerCertSha256").isBlank() && tls.optString("verifyPeerCertByName").isBlank() &&
            server.certPin.isBlank()
    }

    /**
     * A MASQUE server (a JSON one too): only the Xray cores run it — sing-box
     * has no MASQUE and no WARP at all — whatever the record says (engineChoice.js isMasque).
     */
    fun isMasque(server: ServerConfig?): Boolean = Masque.isMasque(server)

    /** The core for this plan. `defaultEngine` is the app-wide setting. */
    fun chooseEngine(plan: ConnectionPlan?, defaultEngine: String = XRAY): String {
        val def = if (defaultEngine == PATTN) PATTN else XRAY
        // a group (Groups.kt) runs on an Xray core whatever its members ask: sing-box has no balancer
        val single: ServerConfig? = (plan as? ConnectionPlan.Single)?.server?.takeIf { s: ServerConfig -> !Groups.isGroupRecord(s) }
        if (single != null && isMasque(single)) return if (single.engine == PATTN) PATTN else def
        if (single != null) return single.engine?.takeIf { it.isNotBlank() }
            ?: if (needsInsecureCore(single)) SINGBOX else def
        return if (planServers(plan).any { it.engine == PATTN }) PATTN else def
    }

    /** Throwaway latency tests use an Xray-format core (buildTestConfig is Xray JSON). */
    fun testEngineFor(engineId: String?): String = if (engineId == PATTN) PATTN else XRAY

    /**
     * The core a throwaway test of [server] runs on: the one connecting to it
     * would use — its own choice, else Settings → Default core — never sing-box
     * (the desktop's testEngineFor(chooseEngine(plan, defaultEngine)), main.js).
     */
    fun testEngineFor(server: ServerConfig, defaultEngine: String = XRAY): String =
        testEngineFor(chooseEngine(ConnectionPlan.Single(server), defaultEngine))
}
