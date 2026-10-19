package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Groups (v1.27.0) against the desktop's pins (tests/groups.test.js): the
 * stored group, the record a plan carries, a member at its own address
 * (AddressSwap), the expansion into members + balancer + rule + health check
 * wherever the plan puts a group, what the phone dials itself, the engine, the
 * selection and "+ clean IPs".
 */
class GroupsTest {
    private val uuid = "2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10"
    private fun srv(id: String, link: String): ServerConfig = LinkParser.parseLink(link).copy(id = id)
    private val cdn = srv("cdn", "vless://$uuid@cdn.example.com:443?type=ws&security=tls&path=%2Fw#CDN")
    private val de = srv("de", "vless://$uuid@de.example.net:8443?type=tcp&security=none#DE")
    private val nl = srv("nl", "trojan://pw@nl.example.net:443?security=tls&sni=nl.example.net#NL")
    private val byId: Map<String, ServerConfig> = mapOf("cdn" to cdn, "de" to de, "nl" to nl)
    private val settings = AppSettings(blockAds = false, enableSniffing = false)

    private fun wg(id: String, endpoint: String, dns: List<String> = emptyList()): ServerConfig {
        val ob = JSONObject().put("protocol", "wireguard").put("settings", JSONObject()
            .put("secretKey", "k").put("address", JSONArray().put("10.0.0.2/32")).put("mtu", 1420)
            .put("peers", JSONArray().put(JSONObject().put("publicKey", "p").put("endpoint", endpoint)
                .put("allowedIPs", JSONArray().put("0.0.0.0/0")))))
        val host = endpoint.substringBeforeLast(':')
        return ServerConfig(id, id, "wireguard", host, endpoint.substringAfterLast(':').toInt(), ob, dns = dns)
    }

    private fun group(id: String, members: List<Any>, strategy: String? = null): GroupConfig {
        val o = JSONObject().put("id", id).put("name", "G")
        if (strategy != null) o.put("strategy", strategy)
        val a = JSONArray()
        for (m in members) a.put(m)
        o.put("members", a)
        return Groups.normalizeGroup(o)!!
    }
    private fun groupOf(members: List<Any>, strategy: String? = null, servers: Map<String, ServerConfig> = byId): ServerConfig =
        Groups.groupRecord(group("grp-g", members, strategy), servers)!!
    private fun member(id: String, address: String? = null, port: Int? = null): JSONObject =
        JSONObject().put("id", id).apply { if (address != null) put("address", address); if (port != null) put("port", port) }

    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun tags(c: JSONObject): List<String> = outs(c).map { o: JSONObject -> o.optString("tag") }
    private fun find(c: JSONObject, tag: String): JSONObject? = outs(c).firstOrNull { o: JSONObject -> o.optString("tag") == tag }
    private fun rules(c: JSONObject): List<JSONObject> { val a = c.getJSONObject("routing").getJSONArray("rules"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun dialer(o: JSONObject?): String = o?.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: ""
    private fun same(expected: String, actual: Any?): Boolean {
        val e: Any = if (expected.trim().startsWith("[")) JSONArray(expected) else JSONObject(expected)
        return Canon.of(e) == Canon.of(actual)
    }
    private fun strs(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { i: Int -> a.getString(i) }

    /* ------------------------------ the stored group ------------------------------ */

    @Test fun normalizeGroup_ownFields_threeStrategies_membersAreServers() {
        val now = { 1792368000000L }
        val g = Groups.normalizeGroup(JSONObject(
            """{"id":"grp-a1","name":"  Fast  ","strategy":"leastPing","extra":1,
               "members":["de",{"id":"cdn","address":"[2606:4700::1]","port":"2053"},{"id":"grp-x"},{"id":""},{"id":"nl","address":"a b","port":99999},null]}"""), now)
        assertEquals(GroupConfig("grp-a1", "Fast", "leastPing",
            listOf(GroupMember("de"), GroupMember("cdn", "2606:4700::1", 2053), GroupMember("nl"))), g)
        assertEquals("roundRobin", Groups.normalizeGroup(JSONObject().put("strategy", "leastLoad"), now)!!.strategy)
        assertTrue(Regex("^grp-[0-9a-z]+[0-9a-f]{4}$").matches(Groups.normalizeGroup(JSONObject().put("id", "chain-1"), now)!!.id))
        assertEquals("Group", Groups.normalizeGroup(JSONObject(), now)!!.name)
        assertNull(Groups.normalizeGroup(null))
        assertNull(Groups.normalizeGroup("x"))
        val list = Groups.normalizeGroups(JSONArray("""[{"id":"grp-a"},{"id":"grp-a","name":"dup"},"x",{"id":"grp-b"}]"""))
        assertEquals(listOf("grp-a", "grp-b"), list.map { x: GroupConfig -> x.id })
        assertTrue(Groups.isGroupId("grp-a"))
        assertFalse(Groups.isGroupId("chain-a"))
        assertFalse(Groups.isGroupId(null))
    }

    @Test fun groupConfig_jsonRoundTrip() {
        val g = GroupConfig("grp-x1", "Two CDNs", "random",
            listOf(GroupMember("a"), GroupMember("b", "1.2.3.4", 2053), GroupMember("c", null, 8443), GroupMember("d", "2606:4700::1")))
        assertEquals(g, GroupConfig.fromJson(JSONObject(g.toJson().toString())))
        // what is not set is not written
        assertFalse(GroupMember("a").toJson().has("address"))
        assertFalse(GroupMember("a").toJson().has("port"))
        // a store list read back, normalized as it is saved
        val stored = JSONArray().put(g.toJson()).put(JSONObject().put("id", "grp-x1")).toString()
        assertEquals(listOf(g), Groups.normalizeGroups(JSONArray(stored)))
    }

    /* ------------------------------ the record ------------------------------ */

    @Test fun groupRecord_aLoopbackMarkedGroup_goneMemberSkipped_noneLeftNull_ownAddressKeepsId() {
        val rec = Groups.groupRecord(group("grp-1", listOf(member("cdn", "104.16.1.1"), member("cdn", "104.17.2.2", 2053), member("gone"))), byId)!!
        assertEquals("grp-1", rec.id)
        assertEquals("group", rec.protocol)
        assertEquals("loopback", rec.outbound.getString("protocol"))
        assertEquals(2, Groups.sizeOf(rec))
        val ms = Groups.serversOf(rec)
        assertEquals(listOf("cdn", "cdn"), ms.map { s: ServerConfig -> s.id })
        assertEquals(listOf("104.16.1.1", "104.17.2.2"), ms.map { s: ServerConfig -> s.address })
        assertEquals(listOf(443, 2053), ms.map { s: ServerConfig -> s.port })
        assertEquals("cdn.example.com", cdn.address)   // the stored server is untouched
        assertEquals("cdn.example.com", cdn.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"))
        assertTrue(Groups.isGroupRecord(rec))
        assertFalse(Groups.isGroupRecord(cdn))
        assertEquals(listOf(de), Groups.serversOf(de))
        assertEquals(emptyList<ServerConfig>(), Groups.serversOf(null))
        assertNull(Groups.groupRecord(group("grp-2", listOf("gone")), byId))
        // a group never holds a group
        val withGroup = byId + ("grp-1" to rec)
        assertNull(Groups.groupRecord(group("grp-3", listOf(member("grp-1"))), withGroup))
        assertEquals(listOf("grp-1"), Groups.groupRecordsById(listOf(group("grp-1", listOf("de")), group("grp-2", listOf("gone"))), byId).keys.toList())
        // the record is a copy: nothing in it is the stored server's own object
        assertEquals(0, Groups.serversOf(groupOf(listOf("de"))).count { s: ServerConfig -> s.outbound === de.outbound })
    }

    /* ------------------------------ AddressSwap ------------------------------ */

    @Test fun addressSwap_cleanIpWhereTheProtocolKeepsIt_sniAndHostFilled_realityUntouched_wireGuard_badPorts() {
        val out = AddressSwap.withTarget(cdn, "104.16.1.1", 2053)
        val node = out.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals(listOf<Any>("104.16.1.1", 2053, "104.16.1.1", 2053), listOf<Any>(out.address, out.port, node.getString("address"), node.getInt("port")))
        val st = out.outbound.getJSONObject("streamSettings")
        assertEquals("cdn.example.com", st.getJSONObject("tlsSettings").getString("serverName"))
        assertEquals("cdn.example.com", st.getJSONObject("wsSettings").getJSONObject("headers").getString("Host"))
        assertEquals("cdn.example.com", cdn.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"))
        assertEquals("", cdn.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("serverName"))
        // an SNI already set stays
        assertEquals("nl.example.net", AddressSwap.withTarget(nl, "1.2.3.4", null).outbound
            .getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("serverName"))
        assertEquals("1.2.3.4", AddressSwap.withTarget(nl, "1.2.3.4", null).outbound
            .getJSONObject("settings").getJSONArray("servers").getJSONObject(0).getString("address"))
        // REALITY's serverName is the camouflage site: never touched, no TLS block made
        val reality = srv("r", "vless://$uuid@r.example.net:443?type=tcp&security=reality&sni=www.microsoft.com&pbk=AAAA&fp=chrome#R")
        val r2 = AddressSwap.withTarget(reality, "5.6.7.8", null)
        assertEquals("www.microsoft.com", r2.outbound.getJSONObject("streamSettings").getJSONObject("realitySettings").getString("serverName"))
        assertFalse(r2.outbound.getJSONObject("streamSettings").has("tlsSettings"))
        // a WireGuard endpoint, a v6 one bracketed
        val w = wg("w", "engage.example.com:2408")
        val w2 = AddressSwap.withTarget(w, "2606:4700::1", null)
        assertEquals("[2606:4700::1]:2408", w2.outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        assertEquals("engage.example.com:2408", w.outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        // what it dials today
        assertEquals(AddressSwap.Dial("engage.example.com", 2408), AddressSwap.dialOf(w))
        assertEquals(AddressSwap.Dial("de.example.net", 8443), AddressSwap.dialOf(de))
        try { AddressSwap.withTarget(cdn, null, 70000); fail("a port outside 1–65535 is refused") }
        catch (e: AddressSwap.SwapError) { assertEquals("invalid", e.code) }
        val socks = ServerConfig("x", "x", "socks", "1.1.1.1", 1080, JSONObject().put("protocol", "socks").put("settings", JSONObject()))
        try { AddressSwap.withTarget(socks, "1.1.1.1", null); fail("socks cannot take another address") }
        catch (e: AddressSwap.SwapError) { assertEquals("unsupported", e.code) }
        assertNull(AddressSwap.toPort("0")); assertNull(AddressSwap.toPort(65536)); assertNull(AddressSwap.toPort("x"))
        assertEquals(2053, AddressSwap.toPort(" 2053 "))
    }

    @Test fun addressSwap_aJsonServerThatDialsThroughAProxyIsRefused_aFragmentHelperIsNot() {
        val main = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "j.example.net").put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", uuid).put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "tcp").put("sockopt", JSONObject().put("dialerProxy", "hop")))
        val frag = JSONObject().put("tag", "hop").put("protocol", "freedom").put("settings", JSONObject())
        val viaFrag = ServerConfig("j", "J", "vless", "j.example.net", 443, main, source = JsonImport.SOURCE,
            json = JSONObject().put("outbounds", JSONArray().put(JSONObject(main.toString()).put("tag", "proxy")).put(frag)), extraOutbounds = listOf(frag))
        val moved = AddressSwap.withTarget(viaFrag, "9.9.9.9", null)
        assertEquals("9.9.9.9", moved.address)
        // the config itself carries the same outbound, its tag kept
        val inJson = moved.json!!.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("proxy", inJson.getString("tag"))
        assertEquals("9.9.9.9", inJson.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"))
        val hop = JSONObject().put("tag", "hop").put("protocol", "vless").put("settings", JSONObject())
        val viaProxy = viaFrag.copy(extraOutbounds = listOf(hop))
        try { AddressSwap.withTarget(viaProxy, "9.9.9.9", null); fail("a JSON chain is refused") }
        catch (e: AddressSwap.SwapError) { assertEquals("json-chain", e.code) }
    }

    /* ------------------------------ the builder ------------------------------ */

    @Test fun selected_theLoopbackAsTheExit_membersTildeGm_balancerAndItsRuleFirst_oneObservatory() {
        val cfg = ConfigBuilder.build(ConnectionPlan.Single(groupOf(listOf("de", "nl"))), settings)
        assertTrue(same("""{"tag":"proxy","protocol":"loopback","settings":{"inboundTag":"proxy~in"}}""", find(cfg, "proxy")))
        assertEquals("vless", find(cfg, "proxy~gm0")!!.getString("protocol"))
        assertEquals("trojan", find(cfg, "proxy~gm1")!!.getString("protocol"))
        val routing = cfg.getJSONObject("routing")
        assertTrue(same("""[{"tag":"proxy~bal","selector":["proxy~gm"],"strategy":{"type":"roundRobin"},"fallbackTag":"proxy~gm0"}]""", routing.getJSONArray("balancers")))
        assertTrue(same("""{"type":"field","inboundTag":["proxy~in"],"balancerTag":"proxy~bal"}""", rules(cfg)[0]))
        assertTrue(same("""{"subjectSelector":["proxy~gm"],"probeUrl":"http://cp.cloudflare.com/","probeInterval":"30s","enableConcurrency":true}""", cfg.getJSONObject("observatory")))
        assertFalse("no marker left for the core", cfg.toString().contains("_group"))
        assertEquals("every outbound has a tag of its own", tags(cfg).size, tags(cfg).toSet().size)
        // the strategy as chosen
        val lp = ConfigBuilder.build(ConnectionPlan.Single(groupOf(listOf("de", "nl"), "leastPing")), settings)
        assertEquals("leastPing", lp.getJSONObject("routing").getJSONArray("balancers").getJSONObject(0).getJSONObject("strategy").getString("type"))
        // no group: no balancer, no observatory
        val plain = ConfigBuilder.build(ConnectionPlan.Single(de), settings)
        assertFalse(plain.getJSONObject("routing").has("balancers"))
        assertFalse(plain.has("observatory"))
    }

    private fun vnextAddress(o: JSONObject?): String =
        o!!.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")

    /** No outbound anywhere dials a loopback — nothing dials THROUGH a group. */
    private fun noneDialsALoopback(cfg: JSONObject): Boolean {
        val loops = outs(cfg).filter { o: JSONObject -> o.optString("protocol") == "loopback" }.map { o: JSONObject -> o.optString("tag") }.toSet()
        return outs(cfg).none { o: JSONObject -> dialer(o) in loops }
    }

    @Test fun aChainThroughAGroupIsAGroupOfWholeChains_hopsOutsideTheMemberPrefix_nothingDialsALoopback() {
        val g = groupOf(listOf("de", "nl"))
        // [G → CDN]: CDN reached through DE, or through NL
        var cfg = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(g, cdn)), settings)
        assertTrue(same("""{"tag":"proxy","protocol":"loopback","settings":{"inboundTag":"proxy~in"}}""", find(cfg, "proxy")))
        assertEquals("cdn.example.com", vnextAddress(find(cfg, "proxy~gm0")))
        assertEquals("proxy~gh0-h0", dialer(find(cfg, "proxy~gm0")))
        assertEquals("de.example.net", vnextAddress(find(cfg, "proxy~gh0-h0")))
        assertEquals("proxy~gh1-h0", dialer(find(cfg, "proxy~gm1")))
        assertEquals("trojan", find(cfg, "proxy~gh1-h0")!!.getString("protocol"))
        assertTrue(same("""[{"tag":"proxy~bal","selector":["proxy~gm"],"strategy":{"type":"roundRobin"},"fallbackTag":"proxy~gm0"}]""",
            cfg.getJSONObject("routing").getJSONArray("balancers")))
        assertEquals("proxy~bal", rules(cfg)[0].getString("balancerTag"))
        assertTrue(noneDialsALoopback(cfg))
        // [CDN → G]: CDN built ONCE, DE and NL each behind it
        cfg = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(cdn, g)), settings)
        assertEquals("cdn.example.com", vnextAddress(find(cfg, "proxy-h0")))
        assertEquals("the hop before the group dials by itself", "", dialer(find(cfg, "proxy-h0")))
        assertEquals("de.example.net", vnextAddress(find(cfg, "proxy~gm0")))
        assertEquals("proxy-h0", dialer(find(cfg, "proxy~gm0")))
        assertEquals("proxy-h0", dialer(find(cfg, "proxy~gm1")))
        assertEquals(1, outs(cfg).count { o: JSONObject ->
            o.optJSONObject("settings")?.optJSONArray("vnext")?.optJSONObject(0)?.optString("address") == "cdn.example.com"
        })
        assertTrue(noneDialsALoopback(cfg))
        // two groups: every combination
        val g2 = Groups.groupRecord(group("grp-2", listOf("cdn", "nl")), byId)!!
        cfg = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(g, g2)), settings)
        assertEquals(4, tags(cfg).count { t: String -> Regex("^proxy~gm\\d+$").matches(t) })
        assertTrue(noneDialsALoopback(cfg))
        assertEquals("every outbound has a tag of its own", tags(cfg).size, tags(cfg).toSet().size)
        assertFalse("no marker left for the core", cfg.toString().contains("_group"))
    }

    @Test fun aWireGuardInAChainWithAGroupIsOneOutbound_afterTheGroupItDialsTheLoopback_beforeItEveryMemberDialsIt() {
        val warp = wg("w", "162.159.192.1:2408")
        val ids = byId + ("w" to warp)
        val g = Groups.groupRecord(group("grp-c", listOf(member("cdn", "104.16.1.1"), member("cdn", "104.17.2.2"))), ids)!!
        fun wgs(cfg: JSONObject): List<JSONObject> = outs(cfg).filter { o: JSONObject -> o.optString("protocol") == "wireguard" }
        // [G → WARP]: the group's loopback at hop 0, the one WireGuard dialling it
        var cfg = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(g, warp)), settings)
        assertEquals(1, wgs(cfg).size)
        assertEquals("proxy", wgs(cfg)[0].getString("tag"))
        assertEquals("loopback", find(cfg, "proxy-h0")!!.getString("protocol"))
        assertEquals("proxy-h0", dialer(find(cfg, "proxy")))
        assertEquals(listOf("104.16.1.1", "104.17.2.2"), listOf("proxy-h0~gm0", "proxy-h0~gm1").map { t: String -> vnextAddress(find(cfg, t)) })
        assertEquals("proxy-h0~bal", rules(cfg)[0].getString("balancerTag"))
        // [G → DE → WARP]: the stretch [G → DE] varies, the WireGuard after it once
        cfg = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(g, de, warp)), settings)
        assertEquals(1, wgs(cfg).size)
        assertEquals("proxy-h1", dialer(find(cfg, "proxy")))
        assertEquals("loopback", find(cfg, "proxy-h1")!!.getString("protocol"))
        assertEquals("de.example.net", vnextAddress(find(cfg, "proxy-h1~gm0")))
        assertEquals("proxy-h1~gh0-h0", dialer(find(cfg, "proxy-h1~gm0")))
        // [WARP → G]: the WireGuard first, once; both members behind it
        val g2 = Groups.groupRecord(group("grp-d", listOf("de", "nl")), ids)!!
        cfg = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(warp, g2)), settings)
        assertEquals(1, wgs(cfg).size)
        assertEquals("proxy-h0", wgs(cfg)[0].getString("tag"))
        assertEquals(listOf("proxy-h0", "proxy-h0"), listOf("proxy~gm0", "proxy~gm1").map { t: String -> dialer(find(cfg, t)) })
        assertTrue(noneDialsALoopback(cfg))
    }

    @Test fun aChainThroughAGroupTargetedThroughAServerBase_eachVariantsFirstHopDialsTheBase() {
        val g = groupOf(listOf("de", "nl"))
        val plan = ConnectionPlan.Advanced(
            listOf(RouteRule("domain", "example.org", "chain:c1", via = "cdn")), "direct",
            byId + ("grp-g" to g), mapOf("c1" to listOf(g, nl)))
        val cfg = ConfigBuilder.build(plan, settings)
        assertEquals("loopback", find(cfg, "out-chain-c1@cdn")!!.getString("protocol"))
        assertEquals("base-cdn", dialer(find(cfg, "out-chain-c1@cdn~gh0-h0")))
        assertEquals("out-chain-c1@cdn~gh0-h0", dialer(find(cfg, "out-chain-c1@cdn~gm0")))
        assertTrue(noneDialsALoopback(cfg))
    }

    @Test fun inAdvancedRouting_aTargetIsItsOwnLoopback_asABaseEachTargetIsGroupThenTarget_aGroupGoneNoLongerExists() {
        val g = groupOf(listOf("de", "nl"))
        val plan = ConnectionPlan.Advanced(
            listOf(RouteRule("domain", "example.org", "grp-g"), RouteRule("domain", "example.com", "cdn", via = "grp-g")),
            "de", byId + ("grp-g" to g), emptyMap())
        val cfg = ConfigBuilder.build(plan, settings)
        val rule = rules(cfg).first { r: JSONObject -> strs(r.optJSONArray("domain")).contains("example.org") }
        assertEquals("out-grp-g", rule.getString("outboundTag"))
        assertEquals("loopback", find(cfg, "out-grp-g")!!.getString("protocol"))
        // the base registers nothing of its own; the target is a group of [DE → CDN], [NL → CDN]
        assertFalse(tags(cfg).any { t: String -> t.startsWith("base-") })
        assertEquals("loopback", find(cfg, "out-cdn@grp-g")!!.getString("protocol"))
        assertEquals("cdn.example.com", vnextAddress(find(cfg, "out-cdn@grp-g~gm0")))
        assertEquals("out-cdn@grp-g~gh0-h0", dialer(find(cfg, "out-cdn@grp-g~gm0")))
        assertEquals("de.example.net", vnextAddress(find(cfg, "out-cdn@grp-g~gh0-h0")))
        val bal = cfg.getJSONObject("routing").getJSONArray("balancers")
        assertEquals(listOf("out-cdn@grp-g~bal", "out-grp-g~bal"), (0 until bal.length()).map { i: Int -> bal.getJSONObject(i).getString("tag") }.sorted())
        assertEquals(listOf("out-cdn@grp-g~bal", "out-grp-g~bal"), rules(cfg).take(2).map { r: JSONObject -> r.optString("balancerTag") }.sorted())
        assertEquals(listOf("out-cdn@grp-g~gm", "out-grp-g~gm"), strs(cfg.getJSONObject("observatory").getJSONArray("subjectSelector")).sorted())
        assertTrue(noneDialsALoopback(cfg))
        // a chain base with a group in it registers nothing either: [G → NL] base, target CDN → [G → NL → CDN]
        val viaChain = ConnectionPlan.Advanced(listOf(RouteRule("domain", "example.com", "cdn", via = "chain:c2")), "direct",
            byId + ("grp-g" to g), mapOf("c2" to listOf(g, nl)))
        val c2 = ConfigBuilder.build(viaChain, settings)
        assertFalse(tags(c2).any { t: String -> t.startsWith("base-") })
        assertEquals("loopback", find(c2, "out-cdn@chain-c2")!!.getString("protocol"))
        // the variant [DE → NL → CDN]: CDN at the exit, behind the variant's NL, behind its DE
        assertEquals("cdn.example.com", vnextAddress(find(c2, "out-cdn@chain-c2~gm0")))
        assertEquals("out-cdn@chain-c2~gh0-h1", dialer(find(c2, "out-cdn@chain-c2~gm0")))
        assertEquals("trojan", find(c2, "out-cdn@chain-c2~gh0-h1")!!.getString("protocol"))
        assertEquals("out-cdn@chain-c2~gh0-h0", dialer(find(c2, "out-cdn@chain-c2~gh0-h1")))
        assertTrue(noneDialsALoopback(c2))
        // the default gone (a group whose servers are all gone has no record) → refused, as a deleted server is
        try {
            ConfigBuilder.build(plan.copy(def = "grp-gone"), settings)
            fail("a default that no longer exists is refused")
        } catch (e: IllegalStateException) {
            assertTrue(e.message!!.contains("no longer exists"))
        }
    }

    @Test fun inThePoolAndTheLatencyTest_expandedTheSameWay_theTestWithoutAHealthCheck() {
        val g = groupOf(listOf("de", "nl"))
        val pool = ConfigBuilder.build(ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "grp-g", 41090, 0, true)), "grp-g", byId + ("grp-g" to g), emptyMap()), settings)
        assertEquals("out-grp-g~bal", rules(pool)[0].getString("balancerTag"))
        assertNotNull(pool.optJSONObject("observatory"))
        val t = ConfigBuilder.buildTestConfig(g, 41095)
        assertTrue(same("""{"type":"field","inboundTag":["proxy~in"],"balancerTag":"proxy~bal"}""", rules(t)[0]))
        assertEquals("proxy", rules(t)[1].getString("outboundTag"))
        assertEquals("socks-in", rules(t)[1].getJSONArray("inboundTag").getString(0))
        assertFalse(t.has("observatory"))
        assertNotNull(find(t, "proxy~gm1"))
        // a server alone: the test config of before, no routing at all
        assertFalse(ConfigBuilder.buildTestConfig(de, 41096).has("routing"))
    }

    @Test fun aJsonMembersHelpersAreNamedOutsideTheBalancersPrefix() {
        val main = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "j.example.net").put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", uuid).put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "tcp").put("sockopt", JSONObject().put("dialerProxy", "frag")))
        val frag = JSONObject().put("tag", "frag").put("protocol", "freedom")
            .put("settings", JSONObject().put("fragment", JSONObject().put("packets", "tlshello").put("length", "100-200").put("interval", "10-20")))
        val json = ServerConfig("j", "J", "vless", "j.example.net", 443, main, source = JsonImport.SOURCE,
            json = JSONObject().put("outbounds", JSONArray().put(JSONObject(main.toString()).put("tag", "proxy")).put(frag)), extraOutbounds = listOf(frag))
        val g = Groups.groupRecord(group("grp-j", listOf("j", "de")), byId + ("j" to json))!!
        val cfg = ConfigBuilder.build(ConnectionPlan.Single(g), settings)
        assertEquals("proxy~gh0~frag", dialer(find(cfg, "proxy~gm0")))
        assertNotNull(find(cfg, "proxy~gh0~frag"))
        assertEquals("the prefix holds the two members only", 2, tags(cfg).count { t: String -> t.startsWith("proxy~gm") })
    }

    @Test fun whatThePhoneDialsItself_aGroupIsEnteredAtEachMember() {
        val w = wg("w", "vpn.corp.example:51820", dns = listOf("192.168.60.1"))
        val g = Groups.groupRecord(group("grp-e", listOf(member("cdn", "104.16.1.1"), "nl", "w")), byId + ("w" to w))!!
        assertEquals(listOf("104.16.1.1", "nl.example.net", "vpn.corp.example"), Groups.serversOf(g).map { s: ServerConfig -> s.address })
        assertEquals(listOf("vpn.corp.example"), ConfigBuilder.wgEndpointHosts(ConnectionPlan.Single(g)))
        assertEquals(listOf("192.168.60.1"), ConfigBuilder.wgResolverAddresses(ConnectionPlan.Single(g)))
        assertEquals(listOf("cdn", "nl", "w"), EngineChoice.planServers(ConnectionPlan.Single(g)).map { s: ServerConfig -> s.id })
        // a WireGuard member's endpoint name takes the address it was resolved to
        val cfg = ConfigBuilder.build(ConnectionPlan.Single(g), settings, wgEndpointIps = mapOf("vpn.corp.example" to "203.0.113.7"))
        assertEquals("203.0.113.7:51820", find(cfg, "proxy~gm2")!!.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        // in a pool or an advanced plan, a group among the records is flattened too
        val adv = ConnectionPlan.Advanced(listOf(RouteRule("domain", "x.example", "grp-e")), "direct", byId + ("grp-e" to g), emptyMap())
        assertTrue(ConfigBuilder.wgEndpointHosts(adv).contains("vpn.corp.example"))
        // a member that wants a pin is named among the plan's servers (the desktop's planServers)
        assertEquals(listOf("cdn", "nl", "w"), CertPin.planServers(ConnectionPlan.Single(g)).map { s: ServerConfig -> s.id })
    }

    @Test fun theEngine_aGroupRunsOnXray_pattnWhenAMemberAsks_neverSingBox() {
        val sb = de.copy(id = "sb", engine = "sing-box")
        val pn = nl.copy(id = "pn", engine = "xray-pattn")
        val all = byId + ("sb" to sb) + ("pn" to pn)
        assertEquals("xray", EngineChoice.chooseEngine(ConnectionPlan.Single(Groups.groupRecord(group("grp-s", listOf("sb", "de")), all)!!)))
        assertEquals("xray-pattn", EngineChoice.chooseEngine(ConnectionPlan.Single(Groups.groupRecord(group("grp-p", listOf("pn", "de")), all)!!)))
        assertEquals("a server alone as before", "sing-box", EngineChoice.chooseEngine(ConnectionPlan.Single(sb)))
        // the throwaway test of a group runs on an Xray core too
        assertEquals("xray", EngineChoice.testEngineFor(Groups.groupRecord(group("grp-s", listOf("sb", "de")), all)!!))
    }

    /* ------------------------------ selection, routing links ------------------------------ */

    @Test fun aGroupSelectionResolvesWhileTheGroupExists() {
        val servers = setOf("a"); val chains = emptySet<String>(); val profiles = emptySet<String>()
        assertTrue(Selection.resolves("grp-1", servers, chains, profiles, setOf("grp-1")))
        assertFalse(Selection.resolves("grp-1", servers, chains, profiles, emptySet()))
        assertEquals("grp-1", Selection.repair("grp-1", "a", listOf("a"), emptyList(), emptyList(), listOf("grp-1")))
        assertEquals("a", Selection.repair("grp-gone", "a", listOf("a"), emptyList(), emptyList(), listOf("grp-1")))
        assertEquals("grp-1", Selection.previousAfterPick("grp-1", "", "a", servers, chains, profiles, setOf("grp-1")))
    }

    @Test fun aRoutingLinkSaysAGroupDoesNotTravel() {
        val p = RoutingProfile("rp-x", "X", rules = listOf(RouteRule("domain", "example.org", "grp-1")), def = "de")
        try {
            RouteShare.profilePayload(p, listOf(de), emptyList()) { s: ServerConfig -> s.raw }
            fail("a group in a routing link is refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("group"))
        }
    }

    /* ------------------------------ + clean IPs ------------------------------ */

    @Test fun cleanIps_onePerLine_aBadLineFlaggedByNumber() {
        val r = Groups.parseCleanIps("104.16.1.1\n104.17.2.2:2053\n[2606:4700::1]:443\n2606:4700::2\nbad line\n\n1.2.3.4:99999\ncdn.example.com\r\n")
        assertEquals(listOf<Pair<String, Int?>>(
            Pair("104.16.1.1", null), Pair("104.17.2.2", 2053), Pair("2606:4700::1", 443), Pair("2606:4700::2", null), Pair("cdn.example.com", null)
        ), r.targets)
        assertEquals(listOf(5, 7), r.bad)
        assertEquals(listOf(1), Groups.parseCleanIps("999.1.1.1").bad)
        // why "+ clean IPs" cannot add them
        assertEquals("Pick the server these addresses are for", Groups.cleanIpProblem(null, r))
        assertTrue(Groups.cleanIpProblem(cdn, r)!!.startsWith("Lines 5, 7"))
        assertEquals("Paste at least one address", Groups.cleanIpProblem(cdn, Groups.parseCleanIps("\n\n")))
        assertNull(Groups.cleanIpProblem(cdn, Groups.parseCleanIps("104.16.1.1\n104.17.2.2:2053")))
        val socks = ServerConfig("x", "S", "socks", "1.1.1.1", 1080, JSONObject().put("protocol", "socks").put("settings", JSONObject()))
        assertTrue(Groups.cleanIpProblem(socks, Groups.parseCleanIps("1.2.3.4"))!!.contains("can't be dialled"))
        // a member's own address in words
        assertEquals("104.17.2.2:2053", Groups.memberAddress(GroupMember("cdn", "104.17.2.2", 2053)))
        assertEquals("[2606:4700::1]:443", Groups.memberAddress(GroupMember("cdn", "2606:4700::1", 443)))
        assertEquals("port 8443", Groups.memberAddress(GroupMember("cdn", null, 8443)))
        assertEquals("", Groups.memberAddress(GroupMember("cdn")))
    }
}
