package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mux, decided per server by a test (spec §4 of docs/superpowers/specs/2026-10-05-v1180-final-design.md, the
 * same rules as the desktop's src/main/mux.js): which outbounds may carry it, the object they get, how a server
 * is recognised again, how long a verdict holds, which servers a connect muxes or tests, and the test itself —
 * run here against fake cores, since the real ones need a phone.
 */
class MuxTest {
    private val day = 24L * 3600 * 1000
    private val now = 1_760_000_000_000L

    private fun stream(net: String, security: String = "tls", path: String = "/ws", host: String = "cdn.example", sni: String = "cdn.example"): JSONObject {
        val s = JSONObject().put("network", net).put("security", security)
        when (net) {
            "ws" -> s.put("wsSettings", JSONObject().put("path", path).put("headers", JSONObject().put("Host", host)))
            "httpupgrade" -> s.put("httpupgradeSettings", JSONObject().put("path", path).put("host", host))
            "grpc" -> s.put("grpcSettings", JSONObject().put("serviceName", "svc"))
            "xhttp" -> s.put("xhttpSettings", JSONObject().put("path", path).put("host", host).put("mode", "auto"))
            "h2" -> s.put("httpSettings", JSONObject().put("path", path).put("host", JSONArray().put(host)))
            else -> s.put("tcpSettings", JSONObject())
        }
        if (security == "tls") s.put("tlsSettings", JSONObject().put("serverName", sni).put("fingerprint", "chrome"))
        if (security == "reality") s.put("realitySettings", JSONObject().put("serverName", sni).put("publicKey", "pbk"))
        return s
    }

    private fun vless(
        id: String = "v", net: String = "ws", flow: String = "", security: String = "tls", path: String = "/ws",
        host: String = "cdn.example", sni: String = "cdn.example", uuid: String = "11111111-2222-3333-4444-555555555555",
        address: String = "cdn.example", port: Int = 443, name: String = id
    ): ServerConfig {
        val user = JSONObject().put("id", uuid).put("encryption", "none").put("flow", flow)
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", address).put("port", port).put("users", JSONArray().put(user)))))
            .put("streamSettings", stream(net, security, path, host, sni))
        return ServerConfig(id, name, "vless", address, port, ob)
    }

    private fun vmess(id: String = "m", net: String = "ws"): ServerConfig {
        val user = JSONObject().put("id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").put("alterId", 0).put("security", "auto")
        val ob = JSONObject().put("protocol", "vmess")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "m.example").put("port", 443).put("users", JSONArray().put(user)))))
            .put("streamSettings", stream(net))
        return ServerConfig(id, id, "vmess", "m.example", 443, ob)
    }

    private fun trojan(id: String = "t", net: String = "ws", password: String = "secret"): ServerConfig {
        val ob = JSONObject().put("protocol", "trojan")
            .put("settings", JSONObject().put("servers", JSONArray().put(JSONObject().put("address", "t.example").put("port", 443).put("password", password))))
            .put("streamSettings", stream(net))
        return ServerConfig(id, id, "trojan", "t.example", 443, ob)
    }

    private fun other(protocol: String): ServerConfig {
        val ob = JSONObject().put("protocol", protocol).put("settings", JSONObject()).put("streamSettings", stream("ws"))
        return ServerConfig(protocol, protocol, protocol, "o.example", 443, ob)
    }

    /* ---------------- which outbounds, and what they get ---------------- */

    @Test fun eligible_vlessWithoutFlowVmessAndTrojan_overWebSocketOrHttpUpgrade() {
        assertTrue(Mux.eligible(vless(net = "ws").outbound))
        assertTrue(Mux.eligible(vless(net = "httpupgrade").outbound))
        assertTrue(Mux.eligible(vless(net = "ws", security = "none").outbound))
        assertTrue(Mux.eligible(vmess(net = "ws").outbound))
        assertTrue(Mux.eligible(vmess(net = "httpupgrade").outbound))
        assertTrue(Mux.eligible(trojan(net = "ws").outbound))
        assertTrue(Mux.eligible(trojan(net = "httpupgrade").outbound))
    }

    @Test fun notEligible_visionGrpcXhttpH2RawAndTheOtherProtocols() {
        // Vision (any flow) is never touched
        assertFalse(Mux.eligible(vless(net = "ws", flow = "xtls-rprx-vision").outbound))
        assertFalse(Mux.eligible(vless(net = "tcp", flow = "xtls-rprx-vision", security = "reality").outbound))
        // gRPC, XHTTP and H2 multiplex already; raw and mKCP are not touched
        for (net in listOf("grpc", "xhttp", "h2", "tcp", "kcp")) {
            assertFalse(net, Mux.eligible(vless(net = net).outbound))
            assertFalse(net, Mux.eligible(vmess(net = net).outbound))
            assertFalse(net, Mux.eligible(trojan(net = net).outbound))
        }
        // Shadowsocks (even over a v2ray-plugin WebSocket), WireGuard, Hysteria, SOCKS, HTTP: never
        for (p in listOf("shadowsocks", "wireguard", "hysteria", "socks", "http")) assertFalse(p, Mux.eligible(other(p).outbound))
        // nothing to go by
        assertFalse(Mux.eligible(JSONObject()))
        assertFalse(Mux.eligible(JSONObject().put("protocol", "vless")))
        assertFalse(Mux.eligible(null))
        // the flat form of VLESS settings counts as well
        val flat = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("address", "a.example").put("port", 443).put("id", "u").put("flow", "xtls-rprx-vision"))
            .put("streamSettings", stream("ws"))
        assertFalse(Mux.eligible(flat))
        flat.getJSONObject("settings").put("flow", "")
        assertTrue(Mux.eligible(flat))
    }

    @Test fun theMuxObjectIsTheSpecs_andEveryReadIsItsOwnCopy() {
        assertEquals(Canon.of(JSONObject("""{"enabled":true,"concurrency":8,"xudpConcurrency":16,"xudpProxyUDP443":"skip"}""")), Canon.of(Mux.MUX))
        val one = Mux.MUX
        one.put("concurrency", 1)
        assertEquals(8, Mux.MUX.getInt("concurrency"))
    }

    /* ---------------- the same server, the next time ---------------- */

    @Test fun theFingerprintFollowsTheConnection_notTheNameOrTheId() {
        val base = Mux.fingerprint(vless())
        assertEquals(base, Mux.fingerprint(vless()))
        // a new name, or a new id from a refreshed subscription: the same server
        assertEquals(base, Mux.fingerprint(vless(id = "other-id", name = "Renamed")))
        val changed = listOf(
            vless(path = "/other"), vless(host = "other.example"), vless(sni = "other.example"), vless(port = 2053),
            vless(uuid = "99999999-2222-3333-4444-555555555555"), vless(address = "203.0.113.7"),
            vless(net = "httpupgrade"), vless(security = "none"))
        for (s in changed) assertNotEquals(base, Mux.fingerprint(s))
        assertNotEquals(Mux.fingerprint(trojan(password = "a")), Mux.fingerprint(trojan(password = "b")))
        assertTrue(base, Regex("^[0-9a-f]{32}$").matches(base))
    }

    @Test fun aVerdictHoldsSevenDaysWhenItWorked_threeWhenItDidNot() {
        assertEquals(7 * day, Mux.OK_TTL_MS)
        assertEquals(3 * day, Mux.UNSUPPORTED_TTL_MS)
        assertEquals(Mux.OK, Mux.freshVerdict(Mux.Probe(true, now), now))
        assertEquals(Mux.OK, Mux.freshVerdict(Mux.Probe(true, now - 7 * day + 1), now))
        assertNull(Mux.freshVerdict(Mux.Probe(true, now - 7 * day), now))
        assertEquals(Mux.UNSUPPORTED, Mux.freshVerdict(Mux.Probe(false, now - 3 * day + 1), now))
        assertNull(Mux.freshVerdict(Mux.Probe(false, now - 3 * day), now))
        // never tested, never stamped, or stamped by a clock that has since gone back: test again
        assertNull(Mux.freshVerdict(null, now))
        assertNull(Mux.freshVerdict(Mux.Probe(true, 0L), now))
        assertNull(Mux.freshVerdict(Mux.Probe(true, now + 60_000L), now))
    }

    @Test fun theVerdictTable() {
        assertEquals(Mux.OK, Mux.verdict(true, null))
        assertEquals(Mux.OK, Mux.verdict(true, false))
        assertEquals(Mux.UNSUPPORTED, Mux.verdict(false, true))
        assertEquals(Mux.UNKNOWN, Mux.verdict(false, false))
        assertEquals(Mux.UNKNOWN, Mux.verdict(false, null))
    }

    /* ---------------- plan: what a connect muxes, and what it tests ---------------- */

    @Test fun planOff_muxesNothingAndTestsNothing() {
        val p = Mux.plan(Mux.OFF, listOf(vless("a"), vmess("b")), emptyMap(), now)
        assertTrue(p.muxIds.isEmpty())
        assertTrue(p.toProbe.isEmpty())
    }

    @Test fun planOn_everyEligibleServer_noTest() {
        // a remembered "unsupported" does not matter here
        val cache = mapOf(Mux.fingerprint(vless("a")) to Mux.Probe(false, now))
        val p = Mux.plan(Mux.ON, listOf(vless("a"), vmess("b"), vless("v", flow = "xtls-rprx-vision"), vless("g", net = "grpc")), cache, now)
        assertEquals(setOf("a", "b"), p.muxIds)
        assertTrue(p.toProbe.isEmpty())
    }

    @Test fun planAuto_freshOksAreMuxed_theUntestedAreTested() {
        val ok = vless("ok", path = "/ok")
        val no = vless("no", path = "/no")
        val stale = vless("stale", path = "/stale")
        val fresh = vless("new", path = "/new")
        val cache = mapOf(
            Mux.fingerprint(ok) to Mux.Probe(true, now - day),
            Mux.fingerprint(no) to Mux.Probe(false, now - day),
            Mux.fingerprint(stale) to Mux.Probe(true, now - 8 * day))
        val p = Mux.plan(Mux.AUTO, listOf(ok, no, stale, fresh, vless("g", net = "grpc")), cache, now)
        assertEquals(setOf("ok"), p.muxIds)
        assertEquals(listOf("stale", "new"), p.toProbe.map { s: ServerConfig -> s.id })
        // the same server twice (imported twice) is tested once
        val twice = Mux.plan(Mux.AUTO, listOf(vless("x1", path = "/same"), vless("x2", path = "/same")), emptyMap(), now)
        assertEquals(listOf("x1"), twice.toProbe.map { s: ServerConfig -> s.id })
        // anything but on / off is auto, the default
        assertEquals(listOf("new"), Mux.plan("garbage", listOf(fresh), emptyMap(), now).toProbe.map { s: ServerConfig -> s.id })
        assertEquals(Mux.AUTO, Mux.modeOf(null))
        assertEquals(Mux.AUTO, Mux.modeOf(""))
        assertEquals(Mux.ON, Mux.modeOf(" On "))
        assertEquals(Mux.OFF, Mux.modeOf("off"))
    }

    @Test fun theServersAPlanDialsAsNonChainTargets() {
        val a = vless("a")
        val b = vmess("b")
        val c = trojan("c")
        assertEquals(listOf("a"), Mux.targets(ConnectionPlan.Single(a)).map { s: ServerConfig -> s.id })
        assertTrue(Mux.targets(ConnectionPlan.Chain("k", listOf(a, b))).isEmpty())
        val pool = ConnectionPlan.Pool(
            listOf(PoolEntry("p1", "P1", "b", 60001, 0, true), PoolEntry("p2", "P2", "chain:k", 60003, 0, true), PoolEntry("p3", "P3", "b", 60005, 0, true)),
            "b", mapOf("a" to a, "b" to b, "c" to c), mapOf("k" to listOf(a, c)))
        assertEquals(listOf("b"), Mux.targets(pool).map { s: ServerConfig -> s.id })
        // a literal "proxy" target is the first server, as the config builder resolves it
        val adv = ConnectionPlan.Advanced(
            listOf(RouteRule("domain", "x.com", "proxy"), RouteRule("domain", "y.com", "direct"), RouteRule("ip", "1.1.1.1", "c")),
            "block", mapOf("a" to a, "b" to b, "c" to c), emptyMap())
        assertEquals(listOf("a", "c"), Mux.targets(adv).map { s: ServerConfig -> s.id })
    }

    /* ---------------- the test, against fake cores ---------------- */

    /**
     * Two fake cores: what each request through the mux one and the plain one answers (ms, -1 = failed), how
     * long a request takes (one that would take longer than it is given times out), and the clock they move.
     */
    private class Cores(
        val mux: List<Long>, val plain: List<Long>,
        val muxStarts: Boolean = true, val plainStarts: Boolean = true,
        val requestMs: Long = 200L, val startMs: Long = 600L
    ) {
        var t = 0L
        val log = ArrayList<String>()
        val timeouts = ArrayList<Int>()
        private var nMux = 0
        private var nPlain = 0

        fun probe(budget: Long = Mux.PROBE_BUDGET_MS, wanted: () -> Boolean = { true }): String = Mux.probe<String>(
            start = { m: Boolean ->
                log.add(if (m) "start mux" else "start plain")
                t += startMs
                val starts = if (m) muxStarts else plainStarts
                if (starts) (if (m) "mux" else "plain") else null
            },
            request = { h: String, timeout: Int ->
                log.add("request $h")
                timeouts.add(timeout)
                val answer: Long = if (h == "mux") (mux.getOrNull(nMux++) ?: -1L) else (plain.getOrNull(nPlain++) ?: -1L)
                if (requestMs > timeout) { t += timeout; -1L } else { t += requestMs; answer }
            },
            stop = { h: String -> log.add("stop $h") },
            now = { t },
            wanted = wanted,
            budgetMs = budget
        )
    }

    @Test fun probe_twoAnswersThroughTheMuxCoreIsOk() {
        val c = Cores(mux = listOf(150L, 140L), plain = emptyList())
        assertEquals(Mux.OK, c.probe())
        assertEquals(listOf("start mux", "request mux", "request mux", "stop mux"), c.log)
    }

    @Test fun probe_muxFailsAndPlainWorksIsUnsupported() {
        val first = Cores(mux = listOf(-1L), plain = listOf(300L))
        assertEquals(Mux.UNSUPPORTED, first.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux", "start plain", "request plain", "stop plain"), first.log)
        // the second request through mux is the one that failed: still not a mux server
        val second = Cores(mux = listOf(150L, -1L), plain = listOf(300L))
        assertEquals(Mux.UNSUPPORTED, second.probe())
        assertEquals(listOf("start mux", "request mux", "request mux", "stop mux", "start plain", "request plain", "stop plain"), second.log)
    }

    @Test fun probe_bothFailIsUnknown_andEveryCoreStartedIsStopped() {
        val c = Cores(mux = listOf(-1L), plain = listOf(-1L))
        assertEquals(Mux.UNKNOWN, c.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux", "start plain", "request plain", "stop plain"), c.log)
        // a core that did not start says nothing about the server
        val noMux = Cores(mux = emptyList(), plain = listOf(300L), muxStarts = false)
        assertEquals(Mux.UNKNOWN, noMux.probe())
        assertEquals(listOf("start mux"), noMux.log)
        val noPlain = Cores(mux = listOf(-1L), plain = emptyList(), plainStarts = false)
        assertEquals(Mux.UNKNOWN, noPlain.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux", "start plain"), noPlain.log)
    }

    @Test fun probe_neverOutlastsItsBudget() {
        assertEquals(8_000L, Mux.PROBE_BUDGET_MS)
        // nothing ever answers: each request waits as long as it is given, and that is never past the budget
        val dead = Cores(mux = emptyList(), plain = emptyList(), requestMs = 60_000L)
        assertEquals(Mux.UNKNOWN, dead.probe())
        assertTrue("took ${dead.t} ms", dead.t <= Mux.PROBE_BUDGET_MS)
        assertEquals(listOf(5000, 1800), dead.timeouts)
        // a slow line that answers in 3 s through mux: both requests fit, the second in what is left
        val slow = Cores(mux = listOf(3000L, 3000L), plain = emptyList(), requestMs = 3_000L)
        assertEquals(Mux.OK, slow.probe())
        assertEquals(listOf(5000, 4400), slow.timeouts)
        // no time left for the control request: nothing is known
        val tight = Cores(mux = listOf(-1L), plain = listOf(300L), requestMs = 60_000L)
        assertEquals(Mux.UNKNOWN, tight.probe(budget = 3_000L))
        assertEquals(listOf("start mux", "request mux", "stop mux"), tight.log)
        assertTrue("took ${tight.t} ms", tight.t <= 3_000L)
    }

    @Test fun probe_aConnectOvertakenStartsNothingMore() {
        val c = Cores(mux = listOf(150L, 140L), plain = listOf(300L))
        assertEquals(Mux.UNKNOWN, c.probe(wanted = { false }))
        assertTrue(c.log.toString(), c.log.isEmpty())
        // overtaken after the first request through mux: no second one, no control
        val d = Cores(mux = listOf(150L, 140L), plain = listOf(300L))
        assertEquals(Mux.UNKNOWN, d.probe(wanted = { d.log.size < 2 }))
        assertEquals(listOf("start mux", "request mux", "stop mux"), d.log)
    }

    @Test fun probe_aRequestThatThrowsIsAFailure_andItsCoreIsStillStopped() {
        val stops = ArrayList<String>()
        val v = Mux.probe<String>(
            start = { m: Boolean -> if (m) "mux" else "plain" },
            request = { h: String, _: Int -> if (h == "mux") throw java.io.IOException("reset") else 100L },
            stop = { h: String -> stops.add(h) },
            now = { 0L }
        )
        assertEquals(Mux.UNSUPPORTED, v)
        assertEquals(listOf("mux", "plain"), stops)
    }

    /* ---------------- choose: the connect path's decision ---------------- */

    private class Seen {
        val probed = ArrayList<String>()
        val remembered = ArrayList<Pair<String, Mux.Probe>>()
        val lines = ArrayList<String>()
    }

    private fun choose(
        mode: String, plan: ConnectionPlan, cache: Map<String, Mux.Probe> = emptyMap(), answer: String = Mux.OK,
        wanted: () -> Boolean = { true }, seen: Seen = Seen()
    ): Mux.Pick = Mux.choose(
        mode = mode, connection = plan, cache = cache, now = { now },
        test = { s: ServerConfig -> seen.probed.add(s.id); answer },
        remember = { fp: String, p: Mux.Probe -> seen.remembered.add(Pair(fp, p)) },
        log = { line: String -> seen.lines.add(line) },
        wanted = wanted
    )

    @Test fun choose_autoTestsTheSelectedServer_andRemembersOkAndUnsupported() {
        val a = vless("a", name = "Germany WS")
        val fp = Mux.fingerprint(a)
        val ok = Seen()
        assertEquals(Mux.Pick(setOf("a"), listOf(fp)), choose(Mux.AUTO, ConnectionPlan.Single(a), answer = Mux.OK, seen = ok))
        assertEquals(listOf("a"), ok.probed)
        assertEquals(listOf(Pair(fp, Mux.Probe(true, now))), ok.remembered)
        assertEquals(listOf("Mux on for Germany WS (tested: works)"), ok.lines)

        val no = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), answer = Mux.UNSUPPORTED, seen = no))
        assertEquals(listOf(Pair(fp, Mux.Probe(false, now))), no.remembered)
        assertEquals(listOf("Mux off for Germany WS (this server does not accept it)"), no.lines)
    }

    @Test fun choose_unknownConnectsAsTodayAndIsNotRemembered() {
        val a = vless("a", name = "Germany WS")
        val seen = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), answer = Mux.UNKNOWN, seen = seen))
        assertEquals(listOf("a"), seen.probed)
        assertTrue(seen.remembered.isEmpty())
        assertEquals(listOf("Mux: Germany WS did not answer either way — connecting without it"), seen.lines)
    }

    @Test fun choose_aFreshVerdictIsUsedWithoutATest_aStaleOneIsTestedAgain() {
        val a = vless("a", name = "A")
        val fp = Mux.fingerprint(a)
        val fresh = Seen()
        assertEquals(Mux.Pick(setOf("a"), listOf(fp)), choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(fp to Mux.Probe(true, now - day)), seen = fresh))
        assertTrue(fresh.probed.isEmpty())
        assertTrue(fresh.remembered.isEmpty())
        assertEquals(listOf("Mux on for A (tested earlier: works)"), fresh.lines)

        val refused = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(fp to Mux.Probe(false, now - day)), seen = refused))
        assertTrue(refused.probed.isEmpty())
        assertEquals(listOf("Mux off for A (tested earlier: this server does not accept it)"), refused.lines)

        val stale = Seen()
        choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(fp to Mux.Probe(true, now - 8 * day)), answer = Mux.OK, seen = stale)
        assertEquals(listOf("a"), stale.probed)
    }

    @Test fun choose_onMuxesWithoutATest_offLeavesEverythingAsToday() {
        val a = vless("a", name = "A")
        val on = Seen()
        assertEquals(Mux.Pick(setOf("a"), emptyList()), choose(Mux.ON, ConnectionPlan.Single(a), seen = on))
        assertTrue(on.probed.isEmpty())
        assertEquals(listOf("Mux on for A (Settings → Mux: On)"), on.lines)

        val off = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.OFF, ConnectionPlan.Single(a), seen = off))
        assertTrue(off.probed.isEmpty())
        assertTrue(off.lines.isEmpty())
    }

    @Test fun choose_neverAChainsHops_norAnIneligibleServer() {
        val seen = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.ON, ConnectionPlan.Chain("c", listOf(vless("a"), vmess("b"))), seen = seen))
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Chain("c", listOf(vless("a"), vmess("b"))), seen = seen))
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(vless("g", net = "grpc")), seen = seen))
        assertEquals(Mux.Pick.NONE, choose(Mux.ON, ConnectionPlan.Single(vless("v", flow = "xtls-rprx-vision")), seen = seen))
        assertTrue(seen.probed.isEmpty())
        assertTrue(seen.lines.isEmpty())
    }

    @Test fun choose_aRoutingPlanUsesWhatItsServersWereTestedAs_andTestsNone() {
        val a = vless("a", name = "A", path = "/a")
        val b = vmess("b")
        val c = vless("c", name = "C", path = "/c")
        val plan = ConnectionPlan.Advanced(
            listOf(RouteRule("domain", "x.com", "a"), RouteRule("ip", "10.0.0.0/8", "chain:k"), RouteRule("domain", "y.com", "b")),
            "c", mapOf("a" to a, "b" to b, "c" to c), mapOf("k" to listOf(a, c)))
        val cache = mapOf(Mux.fingerprint(a) to Mux.Probe(true, now - day), Mux.fingerprint(b) to Mux.Probe(false, now - day))
        val seen = Seen()
        val pick = choose(Mux.AUTO, plan, cache, seen = seen)
        assertEquals(setOf("a"), pick.ids)
        assertEquals(listOf(Mux.fingerprint(a)), pick.forget)
        assertTrue(seen.probed.isEmpty())
        assertEquals(listOf(
            "Mux on for A (tested earlier: works)",
            "Mux off for b (tested earlier: this server does not accept it)",
            "Mux off for C (not tested yet — it is tested when you connect to it on its own)"), seen.lines)
        // On: every eligible one of them (the chain's hops are the builder's to leave alone)
        assertEquals(setOf("a", "b", "c"), choose(Mux.ON, plan).ids)
    }

    @Test fun choose_aConnectOvertakenWhileItTestedDecidesNothing() {
        val a = vless("a")
        val seen = Seen()
        // still wanted when the test starts, no longer once it has run
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), answer = Mux.OK, wanted = { seen.probed.isEmpty() }, seen = seen))
        assertEquals(listOf("a"), seen.probed)
        assertTrue(seen.lines.isEmpty())
    }

    /* ---------------- the stored verdicts ---------------- */

    @Test fun theStoredVerdicts_roundTrip_andKeepTheNewest500() {
        val m = mapOf("f1" to Mux.Probe(true, 1000L), "f2" to Mux.Probe(false, 2000L))
        assertEquals(m, Mux.probesFromJson(Mux.probesToJson(m)))
        // {fingerprint: {ok, at}}
        val o = JSONObject(Mux.probesToJson(m))
        assertTrue(o.getJSONObject("f1").getBoolean("ok"))
        assertEquals(2000L, o.getJSONObject("f2").getLong("at"))
        // anything unreadable is no verdict
        assertTrue(Mux.probesFromJson(null).isEmpty())
        assertTrue(Mux.probesFromJson("not json").isEmpty())
        assertEquals(setOf("good"), Mux.probesFromJson("""{"good":{"ok":true,"at":5},"bad":{"ok":true},"worse":7}""").keys)
        // at most 500: the oldest go first
        assertEquals(500, Mux.MAX_PROBES)
        val many = (1..520).associate { i: Int -> Pair("f$i", Mux.Probe(true, i.toLong())) }
        val kept = Mux.capped(many)
        assertEquals(500, kept.size)
        assertFalse(kept.containsKey("f20"))
        assertTrue(kept.containsKey("f21"))
        assertTrue(kept.containsKey("f520"))
        assertEquals(m, Mux.capped(m))
    }
}
