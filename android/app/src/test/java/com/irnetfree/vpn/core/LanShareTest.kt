package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * LAN sharing (LanShare): the setting itself — its defaults, its JSON, what it
 * refuses — and the inbounds it adds on the Xray format (the in-process core
 * and PattN take the same JSON) and on sing-box. The routing is the tunnel's
 * own: TunnelSetupLanTest checks that stripping LAN sharing off a config gives
 * back exactly the config without it, for every plan and both formats.
 */
class LanShareTest {
    private val session = LocalAuth("u1d2", "p9f8e7")
    private val share = LanShare(enabled = true, user = "irnf-ab12", pass = "k7p2m9x4q3w8")

    private fun vless(id: String): ServerConfig {
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "$id.example").put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", "u-$id").put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "ws").put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", "$id.example")))
        return ServerConfig(id, id, "vless", "$id.example", 443, ob)
    }
    private val a = vless("a")
    private val b = vless("b")
    private fun settings() = AppSettings(blockAds = false)
    private fun inbounds(c: JSONObject): List<JSONObject> { val arr = c.getJSONArray("inbounds"); return (0 until arr.length()).map { arr.getJSONObject(it) } }
    private fun inbound(c: JSONObject, tag: String): JSONObject = inbounds(c).first { it.getString("tag") == tag }
    private fun has(c: JSONObject, tag: String): Boolean = inbounds(c).any { it.getString("tag") == tag }
    private fun rules(c: JSONObject): List<JSONObject> { val a = c.getJSONObject("routing").getJSONArray("rules"); return (0 until a.length()).map { a.getJSONObject(it) } }
    private fun tags(r: JSONObject, key: String = "inboundTag"): List<String> = r.optJSONArray(key)?.let { t -> (0 until t.length()).map { t.getString(it) } } ?: emptyList()

    /* ---------------- the setting ---------------- */

    @Test fun offByDefault_onItsOwnPorts_withAPassword() {
        val d = LanShare()
        assertFalse(d.enabled)
        assertEquals(10810, d.socksPort); assertEquals(10811, d.httpPort)
        assertTrue(d.auth)
        // A store that never had it reads as the defaults.
        assertEquals(d, LanShare.fromJson(JSONObject()))
    }

    @Test fun roundTripsThroughJson() {
        for (v in listOf(LanShare(), share, share.copy(auth = false, socksPort = 20000, httpPort = 20001), share.copy(pass = "p@ss\"w:rd\\")))
            assertEquals(v, LanShare.fromJson(JSONObject(v.toJson().toString())))
    }

    @Test fun aHandEditedStoreFallsBackFieldByField() {
        val v = LanShare.fromJson(JSONObject().put("enabled", "yes").put("socksPort", "abc").put("httpPort", 20001).put("auth", JSONObject.NULL))
        assertFalse(v.enabled)
        assertEquals(10810, v.socksPort)
        assertEquals(20001, v.httpPort)
        assertTrue("a password unless it was turned off", v.auth)
    }

    @Test fun blankCredentialsAreGenerated_setOnesAreKept() {
        val g = LanShare().withCredentials()
        assertTrue(g.user, Regex("^irnf-[a-z2-9]{4}$").matches(g.user))
        assertTrue(g.pass, Regex("^[a-z2-9]{12}$").matches(g.pass))
        // typed by hand on a TV or a laptop: nothing to mistake for another character
        assertFalse(g.user + g.pass, (g.user.removePrefix("irnf-") + g.pass).any { it in "01ilo" })
        assertNull(LanShare.credentialProblem(g.user, g.pass))
        assertNotEquals(g.pass, LanShare().withCredentials().pass)
        assertEquals(share, share.withCredentials())
        val half = LanShare(user = "tv").withCredentials()
        assertEquals("tv", half.user); assertEquals(12, half.pass.length)
    }

    @Test fun portsAreCheckedAgainstTheRange_eachOther_theTunnel_andThePool() {
        val s = AppSettings()                       // 10808 / 10809 / api 10085
        val pool = listOf(PoolEntry("p1", "Work", "a", 20000, 20001, true))
        assertNull(share.problem(s, pool))
        assertNull(share.copy(socksPort = 1024, httpPort = 65535).problem(s, pool))
        assertEquals("The LAN SOCKS port must be between 1024 and 65535", share.copy(socksPort = 1023).problem(s, pool))
        assertEquals("The LAN HTTP port must be between 1024 and 65535", share.copy(httpPort = 65536).problem(s, pool))
        assertNotNull(share.copy(socksPort = 0).problem(s, pool))           // an emptied field
        assertEquals("The LAN SOCKS and HTTP ports must differ", share.copy(httpPort = 10810).problem(s, pool))
        assertEquals("Port 10808 is the tunnel's own SOCKS port", share.copy(socksPort = 10808).problem(s, pool))
        assertEquals("Port 10809 is the tunnel's own HTTP port", share.copy(httpPort = 10809).problem(s, pool))
        assertTrue(share.copy(httpPort = 10085).problem(s, pool)!!.contains("API"))
        assertEquals("Port 20001 belongs to the proxy pool (Work)", share.copy(httpPort = 20001).problem(s, pool))
        // The tunnel's own port moved onto the share's since it was set: the
        // connect leaves sharing out and says so (prepare → lanShareFor).
        assertEquals("Port 10810 is the tunnel's own SOCKS port", share.problem(s.copy(socksPort = 10810), pool))
    }

    @Test fun credentialsAreCheckedOnlyWhenAPasswordIsAskedFor() {
        val s = AppSettings()
        assertNotNull(share.copy(user = "").problem(s, emptyList()))
        assertNotNull(share.copy(pass = "").problem(s, emptyList()))
        assertNotNull(share.copy(pass = "two words").problem(s, emptyList()))
        assertNotNull(share.copy(pass = "رمز۱۲۳").problem(s, emptyList()))           // typed on another device's keyboard
        assertNotNull(share.copy(user = "x".repeat(65)).problem(s, emptyList()))
        // HTTP's Basic auth splits the pair on the first ":" — the password may hold one, the name not
        assertNotNull(share.copy(user = "a:b").problem(s, emptyList()))
        assertNull(share.copy(pass = "p@ss:w0rd!").problem(s, emptyList()))
        assertNull(share.copy(auth = false, user = "", pass = "").problem(s, emptyList()))
    }

    @Test fun theSameShareIsTheSamePortsAndTheSameCredentials() {
        assertTrue(LanShare.same(null, null))
        assertTrue("off is no share", LanShare.same(LanShare(), null))
        assertFalse(LanShare.same(share, null))
        assertTrue(LanShare.same(share, share.copy()))
        assertFalse(LanShare.same(share, share.copy(socksPort = 20000)))
        assertFalse(LanShare.same(share, share.copy(pass = "another")))
        assertFalse(LanShare.same(share, share.copy(auth = false)))
        assertTrue("no password asked: its value does not matter", LanShare.same(share.copy(auth = false), share.copy(auth = false, pass = "another")))
    }

    /* ---------------- Xray format: the in-process core and PattN ---------------- */

    @Test fun xray_theLanInboundsListenOnEveryInterfaceWithTheShareCredentials() {
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = session, lan = share)
        val socks = inbound(c, "lan-socks")
        assertEquals("socks", socks.getString("protocol"))
        assertEquals("0.0.0.0", socks.getString("listen")); assertEquals(10810, socks.getInt("port"))
        assertEquals("password", socks.getJSONObject("settings").getString("auth"))
        assertEquals("""[{"pass":"k7p2m9x4q3w8","user":"irnf-ab12"}]""", Canon.of(socks.getJSONObject("settings").getJSONArray("accounts")))
        assertTrue("UDP too, as the tunnel's", socks.getJSONObject("settings").getBoolean("udp"))
        val http = inbound(c, "lan-http")
        assertEquals("http", http.getString("protocol"))
        assertEquals("0.0.0.0", http.getString("listen")); assertEquals(10811, http.getInt("port"))
        assertEquals("""[{"pass":"k7p2m9x4q3w8","user":"irnf-ab12"}]""", Canon.of(http.getJSONObject("settings").getJSONArray("accounts")))
        // sniffed exactly as the tunnel's own traffic is
        assertEquals(Canon.of(inbound(c, "socks-in").getJSONObject("sniffing")), Canon.of(socks.getJSONObject("sniffing")))
    }

    @Test fun xray_theTunnelsOwnInboundsKeepLoopbackAndTheSessionCredentials() {
        val without = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = session)
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = session, lan = share)
        for (tag in listOf("socks-in", "http-in")) assertEquals(Canon.of(inbound(without, tag)), Canon.of(inbound(c, tag)))
        assertEquals("127.0.0.1", inbound(c, "socks-in").getString("listen"))
    }

    @Test fun xray_nothingFromTheLanReachesThePhonesLoopback_andThatIsTheOnlyRuleOfItsOwn() {
        for (plan in listOf<ConnectionPlan>(
            ConnectionPlan.Single(a),
            ConnectionPlan.Chain("c", listOf(a, b)),
            ConnectionPlan.Advanced(listOf(RouteRule("domain", "example.org", "b")), "a", mapOf("a" to a, "b" to b), emptyMap())
        )) {
            val s = settings().copy(routingMode = "bypass-ir")
            val without = ConfigBuilder.build(plan, s, geoAssets = true, inboundAuth = session)
            val c = ConfigBuilder.build(plan, s, geoAssets = true, inboundAuth = session, lan = share)
            val r = rules(c)
            assertEquals(Canon.of(JSONObject("""{"type":"field","inboundTag":["lan-socks","lan-http"],"ip":["127.0.0.0/8","0.0.0.0/8","::1/128"],"outboundTag":"block"}""")), Canon.of(r[0]))
            assertEquals(Canon.of(JSONObject("""{"type":"field","inboundTag":["lan-socks","lan-http"],"domain":["domain:localhost"],"outboundTag":"block"}""")), Canon.of(r[1]))
            // …then the tunnel's rules, every one, in order: the same routing, the same DNS plan
            assertEquals(rules(without).map { Canon.of(it) }, r.drop(2).map { Canon.of(it) })
            assertEquals(Canon.of(without.getJSONObject("dns")), Canon.of(c.getJSONObject("dns")))
            assertEquals(Canon.of(without.getJSONArray("outbounds")), Canon.of(c.getJSONArray("outbounds")))
            assertTrue((0 until c.getJSONArray("outbounds").length()).any { c.getJSONArray("outbounds").getJSONObject(it).getString("tag") == "block" })
        }
    }

    @Test fun xray_aPoolSendsTheLanWhereItSendsTheTunnel() {
        val plan = ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "b", 60001, 60002, true)), "a", mapOf("a" to a, "b" to b), emptyMap())
        val c = ConfigBuilder.build(plan, settings(), geoAssets = true, inboundAuth = session, lan = share)
        val std = rules(c).first { "socks-in" in tags(it) }
        assertEquals(listOf("socks-in", "http-in", "lan-socks", "lan-http"), tags(std))
        assertEquals("out-a", std.getString("outboundTag"))
        assertEquals("out-b", rules(c).first { "ps-p1" in tags(it) }.getString("outboundTag"))
        assertTrue(has(c, "ps-p1") && has(c, "ph-p1"))
    }

    @Test fun xray_noPasswordMeansNoauth() {
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = session, lan = share.copy(auth = false))
        assertEquals("noauth", inbound(c, "lan-socks").getJSONObject("settings").getString("auth"))
        assertFalse(inbound(c, "lan-http").getJSONObject("settings").has("accounts"))
        // the tunnel's own keep theirs
        assertEquals("password", inbound(c, "socks-in").getJSONObject("settings").getString("auth"))
    }

    @Test fun xray_offBuildsExactlyWhatItBuiltBefore() {
        val base = Canon.of(ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = session))
        assertEquals(base, Canon.of(ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = session, lan = null)))
        assertEquals(base, Canon.of(ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = session, lan = share.copy(enabled = false))))
    }

    @Test fun xray_aPortTheConfigAlreadyHoldsIsNeverWrittenTwice() {
        // prepare() refuses such a share; the builder still never writes a
        // config the core would reject whole
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, lan = share.copy(socksPort = 10808))
        assertFalse(has(c, "lan-socks")); assertTrue(has(c, "lan-http"))
        assertEquals(listOf("lan-http"), tags(rules(c)[0]))
        val pool = ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "b", 10810, 0, true)), "a", mapOf("a" to a, "b" to b), emptyMap())
        val p = ConfigBuilder.build(pool, settings(), geoAssets = true, lan = share)
        assertEquals(1, inbounds(p).count { it.getInt("port") == 10810 })
    }

    /* ---------------- sing-box ---------------- */

    @Test fun singbox_theLanInboundsAndTheLoopbackGuard() {
        val c = SingboxConfig.build(a, settings(), session, share)
        val socks = inbound(c, "lan-socks")
        assertEquals("socks", socks.getString("type"))
        assertEquals("0.0.0.0", socks.getString("listen")); assertEquals(10810, socks.getInt("listen_port"))
        assertEquals("""[{"password":"k7p2m9x4q3w8","username":"irnf-ab12"}]""", Canon.of(socks.getJSONArray("users")))
        val http = inbound(c, "lan-http")
        assertEquals("http", http.getString("type")); assertEquals(10811, http.getInt("listen_port"))
        assertEquals("""[{"password":"k7p2m9x4q3w8","username":"irnf-ab12"}]""", Canon.of(http.getJSONArray("users")))
        // the tunnel's route, which names no inbound, carries them as it is
        val route = c.getJSONObject("route")
        assertEquals("proxy", route.getString("final"))
        val r = route.getJSONArray("rules")
        assertEquals(2, r.length())
        for (i in 0 until 2) {
            assertEquals(listOf("lan-socks", "lan-http"), tags(r.getJSONObject(i), "inbound"))
            assertEquals("reject", r.getJSONObject(i).getString("action"))
        }
        assertEquals("""["127.0.0.0/8","0.0.0.0/8","::1/128"]""", Canon.of(r.getJSONObject(0).getJSONArray("ip_cidr")))
        // and the tunnel's own inbounds are untouched
        val without = SingboxConfig.build(a, settings(), session)
        assertEquals(Canon.of(inbound(without, "socks-in")), Canon.of(inbound(c, "socks-in")))
    }

    @Test fun singbox_noPasswordAndOff() {
        val open = SingboxConfig.build(a, settings(), session, share.copy(auth = false))
        assertFalse(inbound(open, "lan-socks").has("users")); assertFalse(inbound(open, "lan-http").has("users"))
        val without = SingboxConfig.build(a, settings(), session)
        assertFalse(without.getJSONObject("route").has("rules"))
        assertEquals(Canon.of(without), Canon.of(SingboxConfig.build(a, settings(), session, share.copy(enabled = false))))
    }

    /* ---------------- a connect builds the plan it was asked for ---------------- */

    @Test fun aPlanTakesItsOwnServersFresh_notWhateverIsSelectedByThen() {
        // prepare() learns certificate pins, then takes the records again from
        // the store. It used to rebuild from the store's CURRENT selection — a
        // server tapped in the list meanwhile was what got connected, under the
        // label of the one asked for. By id, it is the same plan, pins and all.
        val pinned = a.copy(certPin = "ab".repeat(32))
        val store = mapOf("a" to pinned, "b" to b)
        assertEquals(ConnectionPlan.Single(pinned), ConnectionPlan.Single(a).withRecords { id: String -> store[id] })
        // deleted meanwhile: the record it was asked with
        assertEquals(ConnectionPlan.Single(a), ConnectionPlan.Single(a).withRecords { _: String -> null })
        val chain = ConnectionPlan.Chain("c", listOf(a, b)).withRecords { id: String -> store[id] } as ConnectionPlan.Chain
        assertEquals("c", chain.name); assertEquals(listOf(pinned, b), chain.members)
        val entries = listOf(PoolEntry("p1", "P", "b", 60001, 60002, true))
        val pool = ConnectionPlan.Pool(entries, "a", mapOf("a" to a, "b" to b), mapOf("c1" to listOf(a, b))).withRecords { id: String -> store[id] } as ConnectionPlan.Pool
        assertEquals(entries, pool.entries); assertEquals("a", pool.primary)
        assertEquals(pinned, pool.serversById["a"]); assertEquals(listOf(pinned, b), pool.chainsById["c1"])
        val rulesIn = listOf(RouteRule("domain", "x.org", "a"))
        val adv = ConnectionPlan.Advanced(rulesIn, "b", mapOf("a" to a, "b" to b), emptyMap()).withRecords { id: String -> store[id] } as ConnectionPlan.Advanced
        assertEquals(rulesIn, adv.rules); assertEquals("b", adv.def); assertEquals(pinned, adv.serversById["a"])
    }
}
