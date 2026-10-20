package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * A change the running connection does not carry is named (the desktop's
 * settingsMeta.js): the routing mode and the per-app list above all — the two
 * the owner saw "not work" on Android because they waited, unsaid, for the
 * next connect — and the Mux mode and a chain in use; and nothing is named
 * that the running connection would not build differently.
 */
class SettingsApplyTest {
    private val base = AppSettings()
    private val prof = RoutingProfile("rp-1", "Work", rules = listOf(RouteRule("domain", "example.com", "direct")), def = "s1")

    /** pending() with the Mux mode and the chains as the store holds them now (defaults: Mux off, no chain). */
    private fun pending(
        applied: SettingsApply.Applied?, now: AppSettings, profileNow: RoutingProfile? = null,
        mux: String = Mux.OFF, chains: Map<String, SettingsApply.ChainNow> = emptyMap()
    ): List<String> = SettingsApply.pending(applied, now, profileNow, mux) { id: String -> chains[id] }

    /** A VLESS server; over WebSocket it can carry mux (Mux.eligible), over TCP it cannot. */
    private fun srv(id: String, network: String = "ws", mux: String = ""): ServerConfig {
        val user = JSONObject().put("id", "u-$id").put("encryption", "none")
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "$id.example").put("port", 443).put("users", JSONArray().put(user)))))
            .put("streamSettings", JSONObject().put("network", network).put("security", "tls"))
        return ServerConfig(id, id, "vless", "$id.example", 443, ob, mux = mux)
    }

    @Test fun nothingAppliedNothingPending() {
        assertEquals(emptyList<String>(), pending(null, base.copy(routingMode = "bypass-ir")))
    }

    @Test fun theSameSettingsNothingPending() {
        assertEquals(emptyList<String>(), pending(SettingsApply.Applied(base, null), base.copy()))
    }

    @Test fun routingModeAndPerAppAreNamed() {
        val applied = SettingsApply.Applied(base, null)
        assertEquals(listOf("Routing mode"), pending(applied, base.copy(routingMode = "bypass-ir")))
        assertEquals(listOf("Per-app routing"), pending(applied, base.copy(perAppMode = "disallow", perApps = listOf("org.telegram.messenger"))))
        assertEquals(listOf("Per-app routing"), pending(applied, base.copy(perAppMode = "allow", perApps = listOf("org.telegram.messenger"))))
        assertEquals(listOf("Routing mode", "Sniffing", "DNS"),
            pending(applied, base.copy(routingMode = "bypass-ir", enableSniffing = false, dnsRemote = listOf("https://dns.google/dns-query"))))
    }

    @Test fun perAppListOrderAndAnOffModeDoNotCount() {
        val on = base.copy(perAppMode = "allow", perApps = listOf("a.b", "c.d"))
        assertEquals(emptyList<String>(), pending(SettingsApply.Applied(on, null), on.copy(perApps = listOf("c.d", "a.b"))))
        val off = base.copy(perAppMode = "off", perApps = listOf("a.b"))
        assertEquals(emptyList<String>(), pending(SettingsApply.Applied(off, null), off.copy(perApps = listOf("x.y"))))
    }

    @Test fun aPerAppModeWithNoAppIsTheWholeDeviceLikeOff() {
        // TunnelSetup.perApp: "only these apps" with none left is the whole device, minus us — exactly off
        val applied = SettingsApply.Applied(base.copy(perAppMode = "off"), null)
        assertEquals(emptyList<String>(), pending(applied, base.copy(perAppMode = "allow", perApps = emptyList())))
        assertEquals(emptyList<String>(), pending(applied, base.copy(perAppMode = "allow", perApps = listOf(" ", ""))))
        assertEquals(emptyList<String>(), pending(applied, base.copy(perAppMode = "disallow", perApps = emptyList())))
        // ...and the first app picked is a change
        val empty = SettingsApply.Applied(base.copy(perAppMode = "allow", perApps = emptyList()), null)
        assertEquals(listOf("Per-app routing"), pending(empty, base.copy(perAppMode = "allow", perApps = listOf("a.b"))))
        assertEquals(emptyList<String>(), pending(empty, base.copy(perAppMode = "off")))
    }

    @Test fun theProfileInUseEditedOrDeleted() {
        val applied = SettingsApply.Applied(base, prof)
        assertEquals(emptyList<String>(), pending(applied, base, prof.copy()))
        assertEquals(listOf("Routing profile “Work”"), pending(applied, base, prof.copy(def = "direct")))
        assertEquals(listOf("Routing profile (deleted)"), pending(applied, base, null))
        // the profile's own "routing mode under these rules" is a change of the profile
        assertEquals(listOf("Routing profile “Work”"), pending(applied, base, prof.copy(useMode = true)))
    }

    @Test fun whatNoConnectionReadsIsNotNamed() {
        val applied = SettingsApply.Applied(base, null)
        assertEquals(emptyList<String>(), pending(applied, base.copy(autoConnect = true, autoUpdateInterval = 5, lang = "en", advancedMode = false)))
    }

    @Test fun theAdvancedRoutingSwitchAndTheSettingsUseModeAreNotNamed() {
        // the selection decides the plan (Store.buildPlan), and a profile's plan
        // carries the profile's own useMode over advancedUseMode (ConfigBuilder.buildAdvanced)
        val applied = SettingsApply.Applied(base.copy(advancedRouting = true, advancedUseMode = false), prof)
        assertEquals(emptyList<String>(), pending(applied, base.copy(advancedRouting = false, advancedUseMode = true), prof))
        assertEquals(emptyList<String>(), pending(SettingsApply.Applied(base, null), base.copy(advancedRouting = true)))
    }

    @Test fun theMuxModeIsNamedWhenTheConnectReadIt() {
        val applied = SettingsApply.Applied(base, null, muxMode = Mux.OFF)
        assertEquals(emptyList<String>(), pending(applied, base, mux = Mux.OFF))
        assertEquals(listOf("Mux"), pending(applied, base, mux = Mux.AUTO))
        assertEquals(listOf("Mux"), pending(SettingsApply.Applied(base, null, muxMode = Mux.ON), base, mux = Mux.OFF))
        // a connect whose config no mode could change: nothing to name
        assertEquals(emptyList<String>(), pending(SettingsApply.Applied(base, null, muxMode = null), base, mux = Mux.ON))
    }

    @Test fun muxRead_onlyWhereTheModeCouldChangeTheConfig() {
        val ws = srv("a")
        assertEquals(Mux.AUTO, SettingsApply.muxRead(Mux.AUTO, ConnectionPlan.Single(ws), EngineChoice.XRAY))
        assertEquals(Mux.OFF, SettingsApply.muxRead("", ConnectionPlan.Single(ws), EngineChoice.PATTN))
        // sing-box never muxes; a chain's hops never carry it
        assertNull(SettingsApply.muxRead(Mux.AUTO, ConnectionPlan.Single(ws), EngineChoice.SINGBOX))
        assertNull(SettingsApply.muxRead(Mux.AUTO, ConnectionPlan.Chain("c", listOf(ws, srv("b")), "c1"), EngineChoice.XRAY))
        // a server that cannot carry it, or is set to Mux on/off itself, does not follow the app's mode
        assertNull(SettingsApply.muxRead(Mux.AUTO, ConnectionPlan.Single(srv("t", network = "tcp")), EngineChoice.XRAY))
        assertNull(SettingsApply.muxRead(Mux.AUTO, ConnectionPlan.Single(srv("on", mux = Mux.ON)), EngineChoice.XRAY))
        assertNull(SettingsApply.muxRead(Mux.AUTO, ConnectionPlan.Single(srv("off", mux = Mux.OFF)), EngineChoice.XRAY))
    }

    @Test fun chainsOf_theChainsThePlanDials() {
        val a = srv("a"); val b = srv("b")
        assertEquals(emptyMap<String, List<String>>(), SettingsApply.chainsOf(ConnectionPlan.Single(a)))
        assertEquals(mapOf("c1" to listOf("a", "b")), SettingsApply.chainsOf(ConnectionPlan.Chain("C", listOf(a, b), "c1")))
        // a chain built without an id is not followed
        assertEquals(emptyMap<String, List<String>>(), SettingsApply.chainsOf(ConnectionPlan.Chain("C", listOf(a, b))))
        val chains = mapOf("c1" to listOf(a, b), "c2" to listOf(b, a), "c3" to listOf(a))
        val pool = ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "chain:c1", 60001, 60002, true), PoolEntry("p2", "Q", "a", 60003, 0, true),
            PoolEntry("p3", "R", "chain:gone", 60005, 0, true)), "chain:c1", mapOf("a" to a, "b" to b), chains)
        assertEquals(mapOf("c1" to listOf("a", "b")), SettingsApply.chainsOf(pool))
        // an advanced plan: its chain targets and the chain bases they ride on
        val adv = ConnectionPlan.Advanced(listOf(RouteRule("domain", "x.com", "a", via = "chain:c2")), "chain:c1", mapOf("a" to a, "b" to b), chains)
        assertEquals(mapOf("c2" to listOf("b", "a"), "c1" to listOf("a", "b")), SettingsApply.chainsOf(adv))
    }

    @Test fun aChainInUseEditedOrDeleted() {
        val applied = SettingsApply.Applied(base, null, chains = mapOf("c1" to listOf("a", "b")))
        assertEquals(emptyList<String>(), pending(applied, base, chains = mapOf("c1" to SettingsApply.ChainNow("Work", listOf("a", "b")))))
        // renamed only: the config is the same
        assertEquals(emptyList<String>(), pending(applied, base, chains = mapOf("c1" to SettingsApply.ChainNow("Home", listOf("a", "b")))))
        assertEquals(listOf("Chain “Work”"), pending(applied, base, chains = mapOf("c1" to SettingsApply.ChainNow("Work", listOf("a", "b", "c")))))
        assertEquals(listOf("Chain “Work”"), pending(applied, base, chains = mapOf("c1" to SettingsApply.ChainNow("Work", listOf("b", "a")))))
        assertEquals(listOf("Chain (deleted)"), pending(applied, base))
        // a chain the connection does not run is nobody's business
        assertEquals(emptyList<String>(), pending(SettingsApply.Applied(base, null), base, chains = mapOf("c9" to SettingsApply.ChainNow("X", listOf("a")))))
    }
}
