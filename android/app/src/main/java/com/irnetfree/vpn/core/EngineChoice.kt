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
 *    so a plan that is not a single server never resolves to it.
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

    /** Every server a plan can dial, duplicates allowed (engineChoice.planServers). */
    fun planServers(plan: ConnectionPlan?): List<ServerConfig> = when (plan) {
        null -> emptyList()
        is ConnectionPlan.Single -> listOf(plan.server)
        is ConnectionPlan.Chain -> plan.members
        is ConnectionPlan.Pool -> targetsServers(plan.entries.map { it.target }, plan.serversById, plan.chainsById)
        is ConnectionPlan.Advanced ->
            targetsServers(plan.rules.map { it.target } + plan.def, plan.serversById, plan.chainsById)
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

    /** The core for this plan. `defaultEngine` is the app-wide setting. */
    fun chooseEngine(plan: ConnectionPlan?, defaultEngine: String = XRAY): String {
        val def = if (defaultEngine == PATTN) PATTN else XRAY
        if (plan is ConnectionPlan.Single) return plan.server.engine?.takeIf { it.isNotBlank() } ?: def
        return if (planServers(plan).any { it.engine == PATTN }) PATTN else def
    }

    /** Throwaway latency tests use an Xray-format core (buildTestConfig is Xray JSON). */
    fun testEngineFor(engineId: String?): String = if (engineId == PATTN) PATTN else XRAY

    fun testEngineFor(server: ServerConfig, defaultEngine: String = XRAY): String = testEngineFor(server.engine)
}
