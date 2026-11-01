package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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

    /** A server whose outbound has [st] for its streamSettings (the phone's own rule: the desktop decides it at connect, xrayManager). */
    private fun withStream(id: String, st: JSONObject, engine: String? = null, protocol: String = "vless") = ServerConfig(
        id = id, name = id, protocol = protocol, address = "x.example", port = 443,
        outbound = JSONObject().put("protocol", protocol).put("streamSettings", st), engine = engine
    )
    private fun dial(v: String): JSONObject = JSONObject().put("network", "ws").put("sockopt", JSONObject().put("dialMode", v).put("tcpFastOpen", true))
    private fun tcpMask(type: String): JSONObject = JSONObject().put("finalmask", JSONObject().put("tcp", JSONArray().put(JSONObject().put("type", "fragment")).put(JSONObject().put("type", type))))

    @Test fun dialModeOrTheMergeMask_runOnTheBundledPattn_unlessTheServerNamesACoreOfItsOwn() {
        val oob = withStream("oob", dial("oob.0"))
        val merge = withStream("merge", tcpMask("merge"))
        assertTrue(EngineChoice.needsPattn(oob))
        assertTrue(EngineChoice.needsPattn(merge))
        for (none in listOf(a, withStream("e", dial("")), withStream("b", dial("  ")), withStream("f", tcpMask("fragment")),
            withStream("u", JSONObject().put("finalmask", JSONObject().put("udp", JSONArray().put(JSONObject().put("type", "merge"))))))) {
            assertFalse(none.id, EngineChoice.needsPattn(none))
        }
        assertFalse(EngineChoice.needsPattn(null))
        // alone: PattN, whatever Settings → Default core says
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Single(oob)))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Single(merge)))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Single(oob), "xray-pattn"))
        // a core of its own wins (sing-box asked for stays sing-box); "xray" is stored as none at all (ServerEditor.apply)
        assertEquals("sing-box", EngineChoice.chooseEngine(ConnectionPlan.Single(withStream("o2", dial("oob.0"), "sing-box"))))
        // the rules before it keep theirs: MASQUE on Xray unless it asks for PattN, TUIC on sing-box
        assertEquals("xray", EngineChoice.chooseEngine(ConnectionPlan.Single(withStream("m", dial("oob.0"), protocol = "masque"))))
        assertEquals("sing-box", EngineChoice.chooseEngine(ConnectionPlan.Single(withStream("t", dial("oob.0"), protocol = "tuic"))))
        // anywhere in a plan: a chain's hop, a pool's target, a profile's rule
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Chain("c", listOf(a, oob))))
        assertEquals("a hop that names its own core: as before", "xray",
            EngineChoice.chooseEngine(ConnectionPlan.Chain("c", listOf(a, withStream("o3", dial("oob.0"), "sing-box")))))
        val ids = mapOf("a" to a, "oob" to oob, "merge" to merge)
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Pool(listOf(entry("merge")), "a", ids, emptyMap())))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Advanced(listOf(rule("oob")), "a", ids, emptyMap())))
        assertEquals("xray", EngineChoice.chooseEngine(ConnectionPlan.Advanced(listOf(rule("a")), "direct", ids, emptyMap())))
        // and its latency test runs where it would connect
        assertEquals("xray-pattn", EngineChoice.testEngineFor(oob))
    }

    @Test fun latencyTestsNeverRunOnSingbox() {
        assertEquals("xray", EngineChoice.testEngineFor("sing-box"))
        assertEquals("xray-pattn", EngineChoice.testEngineFor("xray-pattn"))
        assertEquals("xray", EngineChoice.testEngineFor(null))
    }

    @Test fun aLatencyTestRunsOnTheCoreTheServerWouldConnectOn() {
        // Settings → Default core is honoured, as the desktop does with
        // testEngineFor(chooseEngine(plan, defaultEngine)) (main.js).
        assertEquals("xray-pattn", EngineChoice.testEngineFor(a, "xray-pattn"))
        assertEquals("xray", EngineChoice.testEngineFor(a))
        assertEquals("xray-pattn", EngineChoice.testEngineFor(p))
        // a server's own choice beats the default; sing-box tests on Xray
        assertEquals("xray", EngineChoice.testEngineFor(s("x", "xray"), "xray-pattn"))
        assertEquals("xray", EngineChoice.testEngineFor(sb, "xray-pattn"))
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
