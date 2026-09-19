package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * EngineChoice against the desktop's own pins (tests/engineChoice.test.js),
 * assertion for assertion — the two clients must send the same plan to the same
 * core, or a chain the owner built on Windows runs on a different core on the
 * phone and fails where the desktop works.
 */
class EngineChoiceTest {
    private fun s(id: String, engine: String? = null) = ServerConfig(
        id = id, name = id, protocol = "vless", address = "x.example", port = 443,
        outbound = JSONObject().put("protocol", "vless"), engine = engine
    )

    private val a = s("a")
    private val b = s("b")
    private val p = s("p", "xray-pattn")
    private val sb = s("sb", "sing-box")
    private val byId = mapOf("a" to a, "b" to b, "p" to p, "sb" to sb)
    private val chains = mapOf("c1" to listOf(a, p), "c2" to listOf(a, b))

    private fun rule(target: String) = RouteRule("domain", "example.com", target)
    private fun entry(target: String) = PoolEntry("e-$target", target, target, 10810, 10811, true)

    @Test fun singleTakesTheServersOwnEngineElseTheDefault() {
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Single(p)))
        assertEquals("sing-box", EngineChoice.chooseEngine(ConnectionPlan.Single(sb)))
        assertEquals("xray", EngineChoice.chooseEngine(ConnectionPlan.Single(a)))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Single(a), "xray-pattn"))
    }

    @Test fun chainRunsOnPattnIfAnyHopWantsIt() {
        assertEquals("xray", EngineChoice.chooseEngine(ConnectionPlan.Chain("c", listOf(a, b))))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Chain("c", listOf(a, p))))
        // sing-box is a single-config engine: it has no chain translator, so a
        // chain with a sing-box hop still runs on the Xray-format core.
        assertEquals("xray", EngineChoice.chooseEngine(ConnectionPlan.Chain("c", listOf(a, sb))))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Chain("c", listOf(a, b)), "xray-pattn"))
    }

    @Test fun poolAndAdvancedLookThroughTheirTargets() {
        assertEquals("xray", EngineChoice.chooseEngine(
            ConnectionPlan.Pool(listOf(entry("a"), entry("chain:c2")), "a", byId, chains)))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(
            ConnectionPlan.Pool(listOf(entry("chain:c1")), "chain:c1", byId, chains)))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(
            ConnectionPlan.Advanced(listOf(rule("direct"), rule("a")), "p", byId, chains)))
        assertEquals("xray", EngineChoice.chooseEngine(
            ConnectionPlan.Advanced(listOf(rule("block")), "direct", byId, chains)))
    }

    @Test fun planServersListsEveryServerAPlanCanDial() {
        val ids = EngineChoice.planServers(
            ConnectionPlan.Advanced(listOf(rule("a")), "chain:c1", byId, chains)
        ).map { it.id }
        assertEquals(listOf("a", "a", "p"), ids)
    }

    @Test fun latencyTestsNeverRunOnSingbox() {
        assertEquals("xray", EngineChoice.testEngineFor("sing-box"))
        assertEquals("xray-pattn", EngineChoice.testEngineFor("xray-pattn"))
        assertEquals("xray", EngineChoice.testEngineFor(null))
    }

    @Test fun connectOnOpenIsOffUntilAskedForAndSurvivesARestart() {
        // A tunnel that starts by itself is the user's decision, so a store that
        // predates the setting must not suddenly begin connecting on launch.
        assertEquals(false, AppSettings.fromJson(JSONObject()).autoConnect)
        assertEquals(false, AppSettings.fromJson(JSONObject().put("socksPort", 10810)).autoConnect)
        val on = AppSettings.fromJson(AppSettings().copy(autoConnect = true).toJson())
        assertEquals(true, on.autoConnect)
        assertEquals(false, AppSettings.fromJson(on.copy(autoConnect = false).toJson()).autoConnect)
    }

    @Test fun theDefaultEngineSettingRoundTrips() {
        val fresh = AppSettings.fromJson(JSONObject())
        assertEquals("xray", fresh.defaultEngine)
        val back = AppSettings.fromJson(fresh.copy(defaultEngine = "xray-pattn").toJson())
        assertEquals("xray-pattn", back.defaultEngine)
        // A store written by an older APK has no such key at all.
        assertEquals("xray", AppSettings.fromJson(JSONObject().put("socksPort", 10810)).defaultEngine)
    }
}
