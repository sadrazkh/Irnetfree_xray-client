package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ConfigBuilder against the desktop's pins (tests/configBuilder.test.js): rule
 * order, the DNS splice, the advanced exit, the WireGuard fixes, the pin.
 */
class ConfigBuilderTest {
    private fun vless(id: String, host: String, insecure: Boolean = false, pin: String = ""): ServerConfig {
        val tls = JSONObject().put("serverName", host).put("fingerprint", "chrome")
        if (insecure) tls.put("allowInsecure", true)
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", host).put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", "u-$id").put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "ws").put("security", "tls").put("tlsSettings", tls)
                .put("wsSettings", JSONObject().put("path", "/").put("headers", JSONObject().put("Host", host))))
        return ServerConfig(id, id, "vless", host, 443, ob, certPin = pin)
    }
    private fun wg(id: String, endpoint: String, allowed: List<String>, dns: List<String> = emptyList(), domains: List<String> = emptyList()): ServerConfig {
        val ob = JSONObject().put("protocol", "wireguard").put("settings", JSONObject()
            .put("secretKey", "k").put("address", JSONArray().put("10.13.13.2/24")).put("mtu", 1420)
            .put("peers", JSONArray().put(JSONObject().put("publicKey", "p").put("endpoint", endpoint).put("allowedIPs", JSONArray(allowed)))))
            .put("streamSettings", JSONObject().put("sockopt", JSONObject()))
        val hp = endpoint.substringBeforeLast(':')
        return ServerConfig(id, id, "wireguard", hp, 51820, ob, dns = dns, dnsDomains = domains)
    }
    private fun settings(over: (AppSettings) -> AppSettings = { it }) = over(AppSettings(blockAds = false, enableSniffing = false))
    private fun rules(c: JSONObject): List<JSONObject> { val a = c.getJSONObject("routing").getJSONArray("rules"); return (0 until a.length()).map { a.getJSONObject(it) } }
    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { a.getJSONObject(it) } }
    private fun tagged(c: JSONObject, tag: String) = outs(c).first { it.getString("tag") == tag }
    private fun ips(r: JSONObject): List<String> = r.optJSONArray("ip")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
    private fun domains(r: JSONObject): List<String> = r.optJSONArray("domain")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()

    private val a = vless("a", "a.example")
    private val corpWg = wg("wgcorp", "cobra.example:51820", listOf("192.168.0.0/16", "10.0.0.0/8"), listOf("192.168.60.1"), listOf("tes.systems"))
    private fun advanced(rules: List<RouteRule>, def: String, chains: Map<String, List<ServerConfig>> = mapOf("c1" to listOf(a, corpWg))) =
        ConnectionPlan.Advanced(rules, def, mapOf("a" to a, "wgcorp" to corpWg), chains)

    @Test fun singleGlobal_dnsRulesFirstThenPrivateThenCatchAll() {
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true)
        val r = rules(c)
        assertEquals("proxy", r[0].getString("outboundTag")); assertEquals("dns-internal", r[0].getJSONArray("inboundTag").getString(0))
        assertEquals("dns-out", r[1].getString("outboundTag")); assertEquals("53", r[1].getString("port"))
        assertTrue(ips(r[2]).contains("192.168.0.0/16")); assertEquals("direct", r[2].getString("outboundTag"))
        assertEquals("0-65535", r.last().getString("port")); assertEquals("proxy", r.last().getString("outboundTag"))
        assertEquals("IPOnDemand", c.getJSONObject("routing").getString("domainStrategy"))
        assertEquals("dns-internal", c.getJSONObject("dns").getString("tag"))
        assertEquals("dns-out", tagged(c, "dns-out").getString("tag"))
        assertEquals("UseIPv4", tagged(c, "direct").getJSONObject("settings").getString("domainStrategy"))
        assertFalse(c.getJSONObject("policy").getJSONObject("levels").getJSONObject("0").has("bufferSize"))
    }

    @Test fun bypassIr_customRulesSitBetweenGeoAndCatchAll() {
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings { it.copy(routingMode = "bypass-ir", customRules = listOf(RouteRule("domain", "mysite.ir", "proxy"))) }, geoAssets = true)
        val r = rules(c)
        val geo = r.indexOfFirst { domains(it).contains("geosite:category-ir") }
        val custom = r.indexOfFirst { domains(it).contains("mysite.ir") }
        assertTrue(geo > -1 && custom > geo)
        assertEquals("0-65535", r.last().getString("port"))
        // the in-country resolver came along, dialled direct on :53
        assertEquals("178.22.122.100", c.getJSONObject("dns").getJSONArray("servers").getJSONObject(0).getString("address"))
        assertEquals("direct", r[0].getString("outboundTag")); assertEquals("53", r[0].getString("port"))
    }

    @Test fun unmanagedDns_legacyShapeAndIpIfNonMatch() {
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings { it.copy(dnsManaged = false) }, geoAssets = true)
        assertFalse(c.getJSONObject("dns").has("tag"))
        assertEquals("IPIfNonMatch", c.getJSONObject("routing").getString("domainStrategy"))
        assertTrue(outs(c).none { it.getString("tag") == "dns-out" })
        assertTrue(ips(rules(c)[0]).contains("192.168.0.0/16"))
    }

    @Test fun advanced_userRulesBeforePrivateBypass_modeUnderThem_catchAllToDefault() {
        val c = ConfigBuilder.build(advanced(listOf(RouteRule("ip", "10.20.0.0/16", "chain:c1")), "a"),
            settings { it.copy(routingMode = "bypass-ir", advancedUseMode = true) }, geoAssets = true)
        val r = rules(c)
        val user = r.indexOfFirst { ips(it).contains("10.20.0.0/16") }
        val priv = r.indexOfFirst { ips(it).contains("192.168.0.0/16") }
        val site = r.indexOfFirst { domains(it).contains("geosite:category-ir") }
        val gip = r.indexOfFirst { ips(it).contains("geoip:ir") }
        assertTrue(user > -1 && priv > -1 && site > -1 && gip > -1)
        assertTrue(user < priv && priv < site && site < gip)
        assertEquals("out-a", r.last().getString("outboundTag"))
        // without advancedUseMode the mode is ignored, as before
        val off = ConfigBuilder.build(advanced(listOf(RouteRule("ip", "10.20.0.0/16", "chain:c1")), "a"), settings { it.copy(routingMode = "bypass-ir") }, geoAssets = true)
        assertFalse(rules(off).any { domains(it).contains("geosite:category-ir") })
    }

    @Test fun advanced_chainToCorporateWireGuardBringsItsResolverThroughTheChain() {
        val c = ConfigBuilder.build(advanced(listOf(RouteRule("ip", "192.168.0.0/16", "chain:c1")), "a"), settings(), geoAssets = true)
        val servers = c.getJSONObject("dns").getJSONArray("servers")
        val corp = servers.getJSONObject(servers.length() - 1)
        assertEquals("192.168.60.1", corp.getString("address"))
        assertEquals("""["domain:tes.systems"]""", corp.getJSONArray("domains").toString())
        assertTrue(corp.getBoolean("skipFallback"))
        assertEquals("""["192.168.0.0/16","10.0.0.0/8"]""", corp.getJSONArray("expectedIPs").toString())
        val r = rules(c)
        assertEquals("out-chain-c1", r[0].getString("outboundTag")); assertEquals(listOf("192.168.60.1"), ips(r[0]))
        assertEquals("out-a", r[1].getString("outboundTag"))   // the exit rule
        assertEquals("dns-out", r[2].getString("outboundTag"))
        // the chain's WireGuard dials through the hop and carries everything
        val w = tagged(c, "out-chain-c1")
        assertEquals("out-chain-c1-h0", w.getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
        assertEquals("""["0.0.0.0/0","::/0"]""", w.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getJSONArray("allowedIPs").toString())
        assertEquals("""["10.13.13.2/32"]""", w.getJSONObject("settings").getJSONArray("address").toString())
        assertFalse(c.getJSONObject("policy").getJSONObject("levels").getJSONObject("0").has("bufferSize"))
    }

    @Test fun advanced_blockDefaultResolverExitsThroughACarrier_notASplitTunnelWireGuard() {
        val c = ConfigBuilder.build(advanced(listOf(RouteRule("ip", "10.0.0.0/8", "wgcorp"), RouteRule("domain", "a.com", "a")), "block"), settings(), geoAssets = true)
        val exit = rules(c).first { it.has("inboundTag") && !it.has("ip") }
        assertEquals("out-a", exit.getString("outboundTag"))
        assertEquals("block", rules(c).last().getString("outboundTag"))
    }

    @Test fun wgEndpointHosts_andSubstitution() {
        val plan = advanced(listOf(RouteRule("ip", "10.0.0.0/8", "chain:c1")), "a")
        assertEquals(listOf("cobra.example"), ConfigBuilder.wgEndpointHosts(plan))
        assertEquals(listOf("192.168.60.1"), ConfigBuilder.wgResolverAddresses(plan))
        val c = ConfigBuilder.build(plan, settings(), geoAssets = true, wgEndpointIps = mapOf("cobra.example" to "51.222.52.23"))
        assertEquals("51.222.52.23:51820", tagged(c, "out-chain-c1").getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        val v6 = ConfigBuilder.build(plan, settings(), geoAssets = true, wgEndpointIps = mapOf("cobra.example" to "2001:db8::1"))
        assertEquals("[2001:db8::1]:51820", tagged(v6, "out-chain-c1").getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        assertTrue(ConfigBuilder.wgEndpointHosts(ConnectionPlan.Single(wg("x", "1.2.3.4:51820", listOf("0.0.0.0/0")))).isEmpty())
    }

    @Test fun allowInsecureIsNeverEmitted_aPinIs() {
        val insecure = vless("i", "i.example", insecure = true)
        val c = ConfigBuilder.build(ConnectionPlan.Single(insecure), settings(), geoAssets = true)
        val tls = tagged(c, "proxy").getJSONObject("streamSettings").getJSONObject("tlsSettings")
        assertFalse(tls.has("allowInsecure"))
        assertFalse(tls.has("pinnedPeerCertSha256"))
        val pinned = vless("p", "p.example", insecure = true, pin = "AB".repeat(32).lowercase())
        val d = ConfigBuilder.build(ConnectionPlan.Single(pinned), settings(), geoAssets = true)
        assertEquals("ab".repeat(32), tagged(d, "proxy").getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("pinnedPeerCertSha256"))
        // the stored record is untouched
        assertTrue(insecure.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings").getBoolean("allowInsecure"))
    }

    @Test fun pool_privateBypassThenPerInboundThenCatchAll_noInCountryResolver() {
        val plan = ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "a", 60001, 60002, true)), "a", mapOf("a" to a), emptyMap())
        val c = ConfigBuilder.build(plan, settings { it.copy(routingMode = "bypass-ir") }, geoAssets = true)
        val r = rules(c)
        assertEquals("out-a", r[0].getString("outboundTag"))          // the exit rule of the DNS plan
        assertEquals("dns-out", r[1].getString("outboundTag"))
        assertTrue(ips(r[2]).contains("192.168.0.0/16"))
        assertEquals("out-a", r.last().getString("outboundTag"))
        assertTrue(c.getJSONObject("dns").getJSONArray("servers").get(0) is String)   // no in-country resolver for a pool
    }

    @Test fun testConfigCarriesTheResolvedWireGuardEndpoint() {
        // A throwaway core that has to resolve a WireGuard endpoint itself can
        // panic (`close of closed channel`) and take the live tunnel's process
        // with it — the test config gets the address the tester resolved.
        val t = ConfigBuilder.buildTestConfig(corpWg, 39998, mapOf("cobra.example" to "51.222.52.23"))
        val peer = t.getJSONArray("outbounds").getJSONObject(0).getJSONObject("settings").getJSONArray("peers").getJSONObject(0)
        assertEquals("51.222.52.23:51820", peer.getString("endpoint"))
        // the stored record keeps its name
        assertEquals("cobra.example:51820", corpWg.outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
    }

    @Test fun testConfigKeepsItsMinimalShape() {
        val t = ConfigBuilder.buildTestConfig(vless("t", "t.example", insecure = true), 39999)
        assertNull(t.opt("dns"))
        assertFalse(t.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("tlsSettings").has("allowInsecure"))
    }

    /* ---------------- mux (Mux.kt, spec §4): only on the servers the connect chose ---------------- */

    private val muxCanon = Canon.of(JSONObject("""{"enabled":true,"concurrency":8,"xudpConcurrency":16,"xudpProxyUDP443":"skip"}"""))
    private fun withoutMux(c: JSONObject): String { for (o in outs(c)) o.remove("mux"); return Canon.of(c) }
    private fun pool() = ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "a", 60001, 60002, true)), "a", mapOf("a" to a), emptyMap())

    @Test fun mux_onlyOnTheOutboundsOfTheGivenServers() {
        val today = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true)
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, muxIds = setOf("a"))
        assertEquals(muxCanon, Canon.of(tagged(c, "proxy").getJSONObject("mux")))
        assertEquals("nothing but the mux key moved", Canon.of(today), withoutMux(c))
        assertFalse(tagged(ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, muxIds = setOf("b")), "proxy").has("mux"))
        // a pool's and an advanced plan's server targets — a literal "proxy" (the first server) too
        assertEquals(muxCanon, Canon.of(tagged(ConfigBuilder.build(pool(), settings(), geoAssets = true, muxIds = setOf("a")), "out-a").getJSONObject("mux")))
        val adv = ConfigBuilder.build(advanced(listOf(RouteRule("domain", "x.com", "proxy"), RouteRule("domain", "y.com", "a")), "a"), settings(), geoAssets = true, muxIds = setOf("a"))
        assertTrue(tagged(adv, "out-a").has("mux"))
        assertTrue(tagged(adv, "out-proxy").has("mux"))
    }

    @Test fun mux_neverOnAChainsHops_norOnAnOutboundThatCannotCarryIt() {
        val b = vless("b", "b.example")
        val chain = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(a, b)), settings(), geoAssets = true, muxIds = setOf("a", "b"))
        assertTrue(outs(chain).none { o: JSONObject -> o.has("mux") })
        val adv = ConfigBuilder.build(advanced(listOf(RouteRule("ip", "10.0.0.0/8", "chain:c1"), RouteRule("domain", "a.com", "a")), "wgcorp"),
            settings(), geoAssets = true, muxIds = setOf("a", "wgcorp"))
        assertTrue(tagged(adv, "out-a").has("mux"))
        assertFalse(tagged(adv, "out-chain-c1-h0").has("mux"))
        assertFalse(tagged(adv, "out-chain-c1").has("mux"))
        assertFalse(tagged(adv, "out-wgcorp").has("mux"))          // WireGuard
        val vision = vless("v", "v.example")
        vision.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).put("flow", "xtls-rprx-vision")
        assertFalse(tagged(ConfigBuilder.build(ConnectionPlan.Single(vision), settings(), geoAssets = true, muxIds = setOf("v")), "proxy").has("mux"))
        val grpc = vless("g", "g.example")
        grpc.outbound.getJSONObject("streamSettings").put("network", "grpc").remove("wsSettings")
        assertFalse(tagged(ConfigBuilder.build(ConnectionPlan.Single(grpc), settings(), geoAssets = true, muxIds = setOf("g")), "proxy").has("mux"))
    }

    @Test fun mux_noIdsIsTodaysConfig_everyPlan() {
        val plans = listOf<ConnectionPlan>(
            ConnectionPlan.Single(a),
            ConnectionPlan.Chain("c", listOf(a, corpWg)),
            pool(),
            advanced(listOf(RouteRule("ip", "10.0.0.0/8", "chain:c1"), RouteRule("domain", "x.com", "proxy")), "a"))
        for (p in plans) {
            val today = Canon.of(ConfigBuilder.build(p, settings(), geoAssets = true))
            assertEquals("$p", today, Canon.of(ConfigBuilder.build(p, settings(), geoAssets = true, muxIds = emptySet())))
            assertEquals("$p", today, Canon.of(ConfigBuilder.build(p, settings(), geoAssets = true, muxIds = setOf("not-in-this-plan"))))
        }
    }

    @Test fun mux_theTestConfigCarriesItOnlyWhenAskedTo() {
        val today = ConfigBuilder.buildTestConfig(a, 39990)
        assertFalse(today.getJSONArray("outbounds").getJSONObject(0).has("mux"))
        val m = ConfigBuilder.buildTestConfig(a, 39990, mux = true)
        assertEquals(muxCanon, Canon.of(m.getJSONArray("outbounds").getJSONObject(0).getJSONObject("mux")))
        m.getJSONArray("outbounds").getJSONObject(0).remove("mux")
        assertEquals(Canon.of(today), Canon.of(m))
        // an outbound that cannot carry it is tested as it is
        val wgTest = ConfigBuilder.buildTestConfig(corpWg, 39990, mapOf("cobra.example" to "51.222.52.23"), mux = true)
        assertFalse(wgTest.getJSONArray("outbounds").getJSONObject(0).has("mux"))
    }
}
