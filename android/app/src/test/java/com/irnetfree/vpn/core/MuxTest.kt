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
    private val hour = 3600L * 1000
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

    @Test fun aVerdictHoldsSevenDaysWhenItWorked_oneDayWhenItDidNot() {
        assertEquals(7 * day, Mux.OK_TTL_MS)
        assertEquals(day, Mux.UNSUPPORTED_TTL_MS)
        assertEquals(Mux.OK, Mux.freshVerdict(Mux.Probe(true, now), now))
        assertEquals(Mux.OK, Mux.freshVerdict(Mux.Probe(true, now - 7 * day + 1), now))
        assertNull(Mux.freshVerdict(Mux.Probe(true, now - 7 * day), now))
        assertEquals(Mux.UNSUPPORTED, Mux.freshVerdict(Mux.Probe(false, now - day + 1), now))
        assertNull(Mux.freshVerdict(Mux.Probe(false, now - day), now))
        // never tested, never stamped, stamped by a clock that has since gone back, or no verdict at all: none
        assertNull(Mux.freshVerdict(null, now))
        assertNull(Mux.freshVerdict(Mux.Probe(true, 0L), now))
        assertNull(Mux.freshVerdict(Mux.Probe(true, now + 60_000L), now))
        assertNull(Mux.freshVerdict(Mux.Probe(null, now, retryAfter = now + hour), now))
        // an unsupported a day old is tested again on the next connect
        val no = vless("no")
        val p = Mux.plan(Mux.AUTO, listOf(no), mapOf(Mux.fingerprint(no) to Mux.Probe(false, now - day)), now)
        assertEquals(listOf("no"), p.toProbe.map { s: ServerConfig -> s.id })
    }

    @Test fun anInconclusiveTestKeepsTheEarlierVerdict_andWaitsAnHour() {
        assertEquals(hour, Mux.RETRY_MS)
        // an expired ok, an ok marked for a recheck, an unsupported: kept as they are, retried in an hour
        val expiredOk = Mux.Probe(true, now - 8 * day)
        assertEquals(Mux.Probe(true, now - 8 * day, retryAfter = now + hour), Mux.record(expiredOk, Mux.UNKNOWN, now))
        val marked = Mux.Probe(true, now - day, recheck = true)
        assertEquals(Mux.Probe(true, now - day, recheck = true, retryAfter = now + hour), Mux.record(marked, Mux.UNKNOWN, now))
        val no = Mux.Probe(false, now - 2 * day)
        assertEquals(Mux.Probe(false, now - 2 * day, retryAfter = now + hour), Mux.record(no, Mux.UNKNOWN, now))
        // with no earlier verdict: an unknown of its own, retried in an hour
        assertEquals(Mux.Probe(null, now, retryAfter = now + hour), Mux.record(null, Mux.UNKNOWN, now))
        assertEquals(Mux.Probe(null, now, retryAfter = now + hour), Mux.record(Mux.Probe(null, now - 2 * hour, retryAfter = now - hour), Mux.UNKNOWN, now))
        // ok / unsupported replace whatever was there: the mark and the retry go
        assertEquals(Mux.Probe(true, now), Mux.record(marked.copy(retryAfter = now + 60_000L), Mux.OK, now))
        assertEquals(Mux.Probe(false, now), Mux.record(expiredOk, Mux.UNSUPPORTED, now))
        assertEquals(Mux.Probe(true, now), Mux.record(Mux.Probe(null, now - hour, retryAfter = now), Mux.OK, now))
    }

    @Test fun aDropMarksTheOkForARecheck_keptAsOk() {
        val ok = Mux.Probe(true, now - day)
        val cache = mapOf("a" to ok, "b" to Mux.Probe(false, now - hour), "c" to Mux.Probe(null, now, retryAfter = now + hour))
        val marked = Mux.markRecheck(cache, listOf("a", "b", "c", "gone"))
        assertEquals(ok.copy(recheck = true), marked["a"])
        // only an ok is marked; nothing else changes, nothing is added
        assertEquals(cache["b"], marked["b"])
        assertEquals(cache["c"], marked["c"])
        assertEquals(setOf("a", "b", "c"), marked.keys)
    }

    @Test fun theVerdictTable() {
        // the mux attempt's outcome is ok | timeout | failed; the control's is ok, not ok, or not run (null)
        assertEquals(Mux.OK, Mux.verdict(Mux.OK, null))
        assertEquals(Mux.OK, Mux.verdict(Mux.OK, false))
        assertEquals(Mux.UNSUPPORTED, Mux.verdict(Mux.FAILED, true))
        assertEquals(Mux.UNKNOWN, Mux.verdict(Mux.FAILED, false))
        assertEquals(Mux.UNKNOWN, Mux.verdict(Mux.FAILED, null))
        // a slow moment is not a refusal: a mux attempt that ran out of time says nothing, whatever the control says
        assertEquals(Mux.UNKNOWN, Mux.verdict(Mux.TIMEOUT, true))
        assertEquals(Mux.UNKNOWN, Mux.verdict(Mux.TIMEOUT, false))
        assertEquals(Mux.UNKNOWN, Mux.verdict(Mux.TIMEOUT, null))
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
            Mux.fingerprint(no) to Mux.Probe(false, now - hour),
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

    @Test fun planAuto_noTestBeforeItsRetryAfter() {
        val a = vless("a", path = "/a")
        val fp = Mux.fingerprint(a)
        // an inconclusive test and no earlier verdict: off, and not tested again before its hour is up
        val unknown = mapOf(fp to Mux.Probe(null, now - 10 * 60_000L, retryAfter = now + 50 * 60_000L))
        val p = Mux.plan(Mux.AUTO, listOf(a), unknown, now)
        assertTrue(p.muxIds.isEmpty())
        assertTrue(p.toProbe.isEmpty())
        assertEquals(listOf("a"), Mux.plan(Mux.AUTO, listOf(a), unknown, now + hour).toProbe.map { s: ServerConfig -> s.id })
        // an expired ok an inconclusive test kept: still on, and not tested before its hour is up
        val kept = mapOf(fp to Mux.Probe(true, now - 8 * day, retryAfter = now + 30 * 60_000L))
        val k = Mux.plan(Mux.AUTO, listOf(a), kept, now)
        assertEquals(setOf("a"), k.muxIds)
        assertTrue(k.toProbe.isEmpty())
        // once it is due: tested again, and on in the meantime only if still within its seven days
        val due = Mux.plan(Mux.AUTO, listOf(a), kept, now + hour)
        assertTrue(due.muxIds.isEmpty())
        assertEquals(listOf("a"), due.toProbe.map { s: ServerConfig -> s.id })
    }

    @Test fun planAuto_aRecheckIsOnAndTested_aRecoveryConnectUsesTheCacheAndTestsNothing() {
        val marked = vless("m", path = "/m")
        val expired = vless("e", path = "/e")
        val refused = vless("r", path = "/r")
        val untested = vless("u", path = "/u")
        val cache = mapOf(
            Mux.fingerprint(marked) to Mux.Probe(true, now - day, recheck = true),
            Mux.fingerprint(expired) to Mux.Probe(true, now - 30 * day),
            Mux.fingerprint(refused) to Mux.Probe(false, now - 5 * day))
        val servers = listOf(marked, expired, refused, untested)
        // the user's (or the boot's) connect: a recheck stays on and is tested; so are the expired and the untested
        val user = Mux.plan(Mux.AUTO, servers, cache, now)
        assertEquals(setOf("m"), user.muxIds)
        assertEquals(listOf("m", "e", "r", "u"), user.toProbe.map { s: ServerConfig -> s.id })
        // a reconnect of the service's own: the cached verdict, whatever its age, a recheck as ok — never a test
        val recovery = Mux.plan(Mux.AUTO, servers, cache, now, recovery = true)
        assertEquals(setOf("m", "e"), recovery.muxIds)
        assertTrue(recovery.toProbe.isEmpty())
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
     * long a request takes on each ([requestMs] through mux, [plainMs] without), and the clock they move. A
     * request that would take longer than it is given times out the way Diagnostics does: -1, once its time is up.
     */
    private class Cores(
        val mux: List<Long>, val plain: List<Long>,
        val muxStarts: Boolean = true, val plainStarts: Boolean = true,
        val requestMs: Long = 200L, val plainMs: Long = requestMs, val startMs: Long = 600L
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
                val takes = if (h == "mux") requestMs else plainMs
                if (takes > timeout) { t += timeout; -1L } else { t += takes; answer }
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

    @Test fun probe_muxFailedBeforeItsTimeAndPlainWorksIsUnsupported() {
        // refused / reset / closed: a -1 long before the request's time was up
        val first = Cores(mux = listOf(-1L), plain = listOf(300L))
        assertEquals(Mux.UNSUPPORTED, first.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux", "start plain", "request plain", "stop plain"), first.log)
        // the second request through mux is the one that failed: still not a mux server
        val second = Cores(mux = listOf(150L, -1L), plain = listOf(300L))
        assertEquals(Mux.UNSUPPORTED, second.probe())
        assertEquals(listOf("start mux", "request mux", "request mux", "stop mux", "start plain", "request plain", "stop plain"), second.log)
    }

    @Test fun probe_aMuxAttemptThatRanOutOfTimeIsUnknown_evenWhenTheControlWouldAnswer() {
        // The router's field case: a slow moment, not a refusal. Through mux the first request needs 6 s, more
        // than the 5 s it is given; a control without mux would answer in 0.3 s — and made it "unsupported",
        // remembered for three days. A timeout says nothing whatever the control says, so none is run.
        val slow = Cores(mux = listOf(6_000L, 150L), plain = listOf(300L), requestMs = 6_000L, plainMs = 300L)
        assertEquals(Mux.UNKNOWN, slow.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux"), slow.log)
        // the second request through mux running out of what is left of the budget: the same
        val late = Cores(mux = listOf(4_000L, 4_000L), plain = listOf(300L), requestMs = 4_000L, plainMs = 300L)
        assertEquals(Mux.UNKNOWN, late.probe())
        assertEquals(listOf("start mux", "request mux", "request mux", "stop mux"), late.log)
    }

    @Test fun probe_aMuxCoreThatCannotStartIsAFailure_soAnAnsweringControlMakesItUnsupported() {
        val c = Cores(mux = emptyList(), plain = listOf(300L), muxStarts = false)
        assertEquals(Mux.UNSUPPORTED, c.probe())
        assertEquals(listOf("start mux", "start plain", "request plain", "stop plain"), c.log)
        // a control that does not answer either: nothing is known
        val d = Cores(mux = emptyList(), plain = listOf(-1L), muxStarts = false)
        assertEquals(Mux.UNKNOWN, d.probe())
    }

    @Test fun probe_aMinusOneWithin150msOfItsTimeIsATimeout_anEarlierOneAFailure() {
        // The round trip says -1 for a refusal and for a timeout alike; the time it took against the time it was
        // given (5 s for the first request here) tells them apart.
        assertEquals(150L, Mux.TIMEOUT_SLACK_MS)
        val atItsTime = Cores(mux = listOf(-1L), plain = listOf(300L), requestMs = 4_900L, plainMs = 300L)
        assertEquals(Mux.UNKNOWN, atItsTime.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux"), atItsTime.log)
        val before = Cores(mux = listOf(-1L), plain = listOf(300L), requestMs = 4_800L, plainMs = 300L)
        assertEquals(Mux.UNSUPPORTED, before.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux", "start plain", "request plain", "stop plain"), before.log)
    }

    @Test fun probe_bothFailIsUnknown_andEveryCoreStartedIsStopped() {
        val c = Cores(mux = listOf(-1L), plain = listOf(-1L))
        assertEquals(Mux.UNKNOWN, c.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux", "start plain", "request plain", "stop plain"), c.log)
        // a control core that does not start: the control did not answer
        val noPlain = Cores(mux = listOf(-1L), plain = emptyList(), plainStarts = false)
        assertEquals(Mux.UNKNOWN, noPlain.probe())
        assertEquals(listOf("start mux", "request mux", "stop mux", "start plain"), noPlain.log)
    }

    @Test fun probe_neverOutlastsItsBudget() {
        assertEquals(8_000L, Mux.PROBE_BUDGET_MS)
        // nothing ever answers: the first request waits as long as it is given — a timeout, so nothing is known
        // and no control is run
        val dead = Cores(mux = emptyList(), plain = emptyList(), requestMs = 60_000L)
        assertEquals(Mux.UNKNOWN, dead.probe())
        assertEquals(listOf(5000), dead.timeouts)
        assertEquals(listOf("start mux", "request mux", "stop mux"), dead.log)
        assertTrue("took ${dead.t} ms", dead.t <= Mux.PROBE_BUDGET_MS)
        // a slow line that answers in 3 s through mux: both requests fit, the second in what is left
        val slow = Cores(mux = listOf(3000L, 3000L), plain = emptyList(), requestMs = 3_000L)
        assertEquals(Mux.OK, slow.probe())
        assertEquals(listOf(5000, 4400), slow.timeouts)
        // a refusal late in a small budget: no time left to start the control, so nothing is known
        val tight = Cores(mux = listOf(-1L), plain = listOf(300L), requestMs = 1_500L, plainMs = 300L)
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
        wanted: () -> Boolean = { true }, seen: Seen = Seen(), recovery: Boolean = false
    ): Mux.Pick = Mux.choose(
        mode = mode, connection = plan, cache = cache, now = { now },
        test = { s: ServerConfig -> seen.probed.add(s.id); answer },
        remember = { fp: String, p: Mux.Probe -> seen.remembered.add(Pair(fp, p)) },
        log = { line: String -> seen.lines.add(line) },
        wanted = wanted,
        recovery = recovery
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

    @Test fun choose_unknownConnectsAsToday_andIsNotTestedAgainForAnHour() {
        val a = vless("a", name = "Germany WS")
        val fp = Mux.fingerprint(a)
        val seen = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), answer = Mux.UNKNOWN, seen = seen))
        assertEquals(listOf("a"), seen.probed)
        assertEquals(listOf(Pair(fp, Mux.Probe(null, now, retryAfter = now + hour))), seen.remembered)
        assertEquals(listOf("Mux: Germany WS did not answer either way — connecting without it"), seen.lines)
        // the next connect within the hour does not test it
        val again = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(Pair(fp, Mux.Probe(null, now, retryAfter = now + hour))), seen = again))
        assertTrue(again.probed.isEmpty())
        assertEquals(listOf("Mux off for Germany WS (the last test had no clear answer — tested again within the hour)"), again.lines)
    }

    @Test fun choose_anExpiredOkTestedWithoutAClearAnswer_staysOn_andWaitsAnHour() {
        val a = vless("a", name = "A")
        val fp = Mux.fingerprint(a)
        val expired = Mux.Probe(true, now - 8 * day)
        val seen = Seen()
        assertEquals(Mux.Pick(setOf("a"), listOf(fp)), choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(fp to expired), answer = Mux.UNKNOWN, seen = seen))
        assertEquals(listOf("a"), seen.probed)
        assertEquals(listOf(Pair(fp, expired.copy(retryAfter = now + hour))), seen.remembered)
        assertEquals(listOf("Mux on for A (no clear answer this time — keeping the earlier result, tested again in an hour)"), seen.lines)
    }

    @Test fun choose_aReconnectOfTheServicesOwnNeverTests_andARecheckCountsAsOk() {
        val a = vless("a", name = "A")
        val fp = Mux.fingerprint(a)
        val marked = Mux.markRecheck(mapOf(fp to Mux.Probe(true, now - day)), listOf(fp))
        val seen = Seen()
        assertEquals(Mux.Pick(setOf("a"), listOf(fp)), choose(Mux.AUTO, ConnectionPlan.Single(a), marked, recovery = true, seen = seen))
        assertTrue(seen.probed.isEmpty())
        assertTrue(seen.remembered.isEmpty())
        assertEquals(listOf("Mux on for A (reconnecting, no test — tested earlier: works)"), seen.lines)
        // whatever the cache holds — an expired ok, nothing, an unsupported — a reconnect tests nothing
        val old = Seen()
        assertEquals(Mux.Pick(setOf("a"), listOf(fp)), choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(fp to Mux.Probe(true, now - 30 * day)), recovery = true, seen = old))
        val none = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), emptyMap(), recovery = true, seen = none))
        assertEquals(listOf("Mux off for A (reconnecting, no test — not tested yet)"), none.lines)
        val no = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(fp to Mux.Probe(false, now - 5 * day)), recovery = true, seen = no))
        assertTrue(old.probed.isEmpty())
        assertTrue(none.probed.isEmpty())
        assertTrue(no.probed.isEmpty())
    }

    @Test fun choose_theUsersNextConnectTestsARecheck_anInconclusiveOneKeepsMuxOn() {
        val a = vless("a", name = "A")
        val fp = Mux.fingerprint(a)
        val marked = Mux.markRecheck(mapOf(fp to Mux.Probe(true, now - day)), listOf(fp))
        // works: the mark goes
        val works = Seen()
        assertEquals(Mux.Pick(setOf("a"), listOf(fp)), choose(Mux.AUTO, ConnectionPlan.Single(a), marked, answer = Mux.OK, seen = works))
        assertEquals(listOf("a"), works.probed)
        assertEquals(listOf(Pair(fp, Mux.Probe(true, now))), works.remembered)
        // no clear answer: still on, still marked, not tested again for an hour
        val unclear = Seen()
        assertEquals(Mux.Pick(setOf("a"), listOf(fp)), choose(Mux.AUTO, ConnectionPlan.Single(a), marked, answer = Mux.UNKNOWN, seen = unclear))
        assertEquals(listOf(Pair(fp, Mux.Probe(true, now - day, recheck = true, retryAfter = now + hour))), unclear.remembered)
        // refused: off
        val refused = Seen()
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), marked, answer = Mux.UNSUPPORTED, seen = refused))
        assertEquals(listOf(Pair(fp, Mux.Probe(false, now))), refused.remembered)
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
        assertEquals(Mux.Pick.NONE, choose(Mux.AUTO, ConnectionPlan.Single(a), mapOf(fp to Mux.Probe(false, now - hour)), seen = refused))
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
        val cache = mapOf(Mux.fingerprint(a) to Mux.Probe(true, now - day), Mux.fingerprint(b) to Mux.Probe(false, now - hour))
        val seen = Seen()
        val pick = choose(Mux.AUTO, plan, cache, seen = seen)
        assertEquals(setOf("a"), pick.ids)
        assertEquals(listOf(Mux.fingerprint(a)), pick.onDrop)
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
        // {fingerprint: {ok, at}} — plus recheck and retryAfter when set, and an unknown with no ok at all
        val o = JSONObject(Mux.probesToJson(m))
        assertTrue(o.getJSONObject("f1").getBoolean("ok"))
        assertEquals(2000L, o.getJSONObject("f2").getLong("at"))
        assertFalse(o.getJSONObject("f1").has("recheck"))
        assertFalse(o.getJSONObject("f1").has("retryAfter"))
        val more = mapOf(
            "r" to Mux.Probe(true, 3000L, recheck = true),
            "k" to Mux.Probe(true, 4000L, recheck = true, retryAfter = 9000L),
            "u" to Mux.Probe(null, 5000L, retryAfter = 8000L))
        assertEquals(more, Mux.probesFromJson(Mux.probesToJson(more)))
        val u = JSONObject(Mux.probesToJson(more)).getJSONObject("u")
        assertFalse(u.has("ok"))
        assertEquals(8000L, u.getLong("retryAfter"))
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
