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
 *  - TUIC and AnyTLS are the other way round: sing-box or nothing
 *    ([isSingboxOnly]) — a single such server always runs on it, and one
 *    anywhere else is refused by the config path ([singboxOnlyInside]).
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

    /** The protocols no Xray core speaks: sing-box alone runs them. */
    val SINGBOX_ONLY: Set<String> = setOf("tuic", "anytls")

    /**
     * A TUIC or AnyTLS server: MASQUE turned around — sing-box runs it,
     * whatever the record or Settings → Default core says, and nothing else
     * can (engineChoice.js isSingboxOnly). sing-box runs one server on its
     * own, so such a server inside a chain, a group, a pool or a routing
     * profile cannot run at all: [singboxOnlyInside] names it, and the connect
     * refuses it rather than build an outbound the Xray core rejects.
     */
    fun isSingboxOnly(server: ServerConfig?): Boolean =
        server != null && (server.protocol in SINGBOX_ONLY || server.outbound.optString("protocol") in SINGBOX_ONLY)

    /** The protocol's name as the user knows it: "TUIC" / "AnyTLS" (the record's own protocol otherwise). */
    fun protocolName(server: ServerConfig): String {
        val p = server.outbound.optString("protocol").ifBlank { server.protocol }
        return when (p) {
            "tuic" -> "TUIC"
            "anytls" -> "AnyTLS"
            else -> p
        }
    }

    /**
     * The TUIC / AnyTLS servers [plan] would put where sing-box cannot go —
     * inside a chain, a group (a group selected alone too: it runs on Xray's
     * balancer), a pool or a routing profile — each once. Empty for a plan
     * of one plain server, whatever it is.
     */
    fun singboxOnlyInside(plan: ConnectionPlan?): List<ServerConfig> {
        val single = (plan as? ConnectionPlan.Single)?.server
        if (single != null && !Groups.isGroupRecord(single)) return emptyList()
        return planServers(plan).filter { s: ServerConfig -> isSingboxOnly(s) }.distinctBy { s: ServerConfig -> s.id }
    }

    /** "a TUIC server" / "an AnyTLS server", for a sentence about [server]. */
    fun serverKind(server: ServerConfig): String {
        val p = protocolName(server)
        val vowel = p.isNotEmpty() && p[0].lowercaseChar() in "aeiou"
        return (if (vowel) "an " else "a ") + p + " server"
    }

    /**
     * Why a TUIC / AnyTLS server cannot run, in words for the user — the line
     * a connect, a test or a config build refuses with (engineChoice.js
     * singboxOnlyError, its English):
     *  - [PLAN]:    it was put in a chain, a group, the pool or a routing profile;
     *  - [MISSING]: sing-box is not bundled for this device;
     *  - [PIN]:     its certificate is pinned, which sing-box cannot keep
     *               (SingboxConfig.isPinned) — and there is no Xray to fall back to;
     *  - [ENGINE]:  the connect was handed another core.
     */
    fun singboxOnlyError(server: ServerConfig, why: String): String {
        val name = server.name.ifBlank { protocolName(server) }
        val kind = serverKind(server)
        return when (why) {
            MISSING -> "\"$name\" is $kind: it runs only on the sing-box core, which is not bundled for this device (arm64 only)."
            PIN -> "\"$name\" is $kind with a pinned certificate (pcs, vcn or pinned on first use): sing-box, the only core it runs on, " +
                "could check it only by accepting any certificate — remove the pin in its edit sheet to connect."
            ENGINE -> "\"$name\" is $kind: it runs only on the sing-box core, and this connection is not on it."
            else -> "\"$name\" is $kind: it runs only on its own, on sing-box — not inside a chain, a group, the proxy pool or a routing profile."
        }
    }

    const val PLAN = "plan"
    const val MISSING = "missing"
    const val PIN = "pin"
    const val ENGINE = "engine"

    /** The core for this plan. `defaultEngine` is the app-wide setting. */
    fun chooseEngine(plan: ConnectionPlan?, defaultEngine: String = XRAY): String {
        val def = if (defaultEngine == PATTN) PATTN else XRAY
        // a group (Groups.kt) runs on an Xray core whatever its members ask: sing-box has no balancer
        val single: ServerConfig? = (plan as? ConnectionPlan.Single)?.server?.takeIf { s: ServerConfig -> !Groups.isGroupRecord(s) }
        if (single != null && isMasque(single)) return if (single.engine == PATTN) PATTN else def
        if (single != null && isSingboxOnly(single)) return SINGBOX
        if (single != null) return single.engine?.takeIf { it.isNotBlank() }
            ?: if (needsInsecureCore(single)) SINGBOX else def
        return if (planServers(plan).any { it.engine == PATTN }) PATTN else def
    }

    /** Throwaway latency tests use an Xray-format core (buildTestConfig is Xray JSON). */
    fun testEngineFor(engineId: String?): String = if (engineId == PATTN) PATTN else XRAY

    /**
     * The Xray-format core a throwaway test of [server] runs on: the one
     * connecting to it would use — its own choice, else Settings → Default
     * core (the desktop's testEngineFor(chooseEngine(plan, defaultEngine)),
     * main.js). A server whose connect runs on sing-box is measured on
     * sing-box itself when it is bundled (XrayTester.start); a TUIC / AnyTLS
     * one only there.
     */
    fun testEngineFor(server: ServerConfig, defaultEngine: String = XRAY): String =
        testEngineFor(chooseEngine(ConnectionPlan.Single(server), defaultEngine))
}
